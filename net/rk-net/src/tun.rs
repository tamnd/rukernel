//! The TUN and TAP devices, as drivers/net/tun.c of Linux.
//!
//! A program opens `/dev/net/tun` and gives `TUNSETIFF` to make a device or to attach to one. A
//! TUN device carries IP packets, and a TAP device carries Ethernet frames. A frame that the
//! kernel sends on the device goes to a read of the file. A write of the file gives a frame that
//! the device receives. Without `IFF_NO_PI` each frame starts with a `struct tun_pi`, and with
//! `IFF_VNET_HDR` a `struct virtio_net_hdr` comes next.
//!
//! Each file that is attached to a device is a queue of the device. A device with
//! `IFF_MULTI_QUEUE` takes up to `MAX_TAP_QUEUES` files, and a frame that the kernel sends goes to
//! one queue by the hash of its flow, as `tun_automq_select_queue` of Linux. `TUNSETQUEUE` takes
//! a queue off the device (`IFF_DETACH_QUEUE`) and puts it back (`IFF_ATTACH_QUEUE`).
//! `TUNSETIFINDEX` gives the interface index of the next device that `TUNSETIFF` makes. The
//! device goes away when its last file closes, if it is not persistent, or when its namespace
//! stops.

use crate::buf::NetBuf;
use crate::dev::{self, Event, LinkKind, NetDevice, NetDriver};
use crate::ether::{EthHeader, HLEN, MacAddr};
use crate::ns::{self, NetNs};
use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::if_ether::{ETH_P_IP, ETH_P_IPV6};
use rk_abi::native::poll::{POLLERR, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM};
use rk_frame::sync::SpinLock;
use rk_vfs::cred::{self, cap};
use rk_vfs::device::{CharDevice, DeviceInfo, add_device, makedev, register_char};
use rk_vfs::inode::Result;
use rk_vfs::wait::{PollTable, WaitQueue};
use rk_vfs::{File, FileOps, UserMemory};

/// The kind of the device, for `IFLA_INFO_KIND`.
pub const KIND: &str = "tun";

/// The device number of `/dev/net/tun`: the misc major 10 and the minor `TUN_MINOR` 200.
pub const TUN_RDEV: u64 = makedev(10, 200);

/// The flags of `struct ifreq` for `TUNSETIFF`, `IFF_*` of <linux/if_tun.h>: a TUN device.
pub const IFF_TUN: u32 = 0x0001;
/// A TAP device.
pub const IFF_TAP: u32 = 0x0002;
/// The NAPI mode, which changes nothing here.
pub const IFF_NAPI: u32 = 0x0010;
/// The NAPI mode for fragments.
pub const IFF_NAPI_FRAGS: u32 = 0x0020;
/// The device has no carrier at the start, for `TUNGETFEATURES`.
pub const IFF_NO_CARRIER: u32 = 0x0040;
/// More than one queue: more than one file can attach to the device.
pub const IFF_MULTI_QUEUE: u32 = 0x0100;
/// `TUNSETQUEUE` puts the queue of the file back on its device.
pub const IFF_ATTACH_QUEUE: u32 = 0x0200;
/// `TUNSETQUEUE` takes the queue of the file off its device.
pub const IFF_DETACH_QUEUE: u32 = 0x0400;
/// The device stays when its file closes.
pub const IFF_PERSIST: u32 = 0x0800;
/// No `struct tun_pi` before the frames.
pub const IFF_NO_PI: u32 = 0x1000;
/// An old flag that changes nothing.
pub const IFF_ONE_QUEUE: u32 = 0x2000;
/// A `struct virtio_net_hdr` before the frames.
pub const IFF_VNET_HDR: u32 = 0x4000;
/// `TUNSETIFF` must make a new device.
pub const IFF_TUN_EXCL: u32 = 0x8000;

/// The flags that a file sets on its device, `TUN_FEATURES` of Linux.
const FEATURES: u32 =
    IFF_NO_PI | IFF_ONE_QUEUE | IFF_VNET_HDR | IFF_MULTI_QUEUE | IFF_NAPI | IFF_NAPI_FRAGS;

/// The ioctls of <linux/if_tun.h>.
const TUNSETNOCSUM: u32 = 0x4004_54c8;
const TUNSETDEBUG: u32 = 0x4004_54c9;
const TUNSETIFF: u32 = 0x4004_54ca;
const TUNSETPERSIST: u32 = 0x4004_54cb;
const TUNSETOWNER: u32 = 0x4004_54cc;
const TUNSETLINK: u32 = 0x4004_54cd;
const TUNSETGROUP: u32 = 0x4004_54ce;
const TUNGETFEATURES: u32 = 0x8004_54cf;
const TUNSETOFFLOAD: u32 = 0x4004_54d0;
const TUNSETTXFILTER: u32 = 0x4004_54d1;
const TUNGETIFF: u32 = 0x8004_54d2;
const TUNGETSNDBUF: u32 = 0x8004_54d3;
const TUNSETSNDBUF: u32 = 0x4004_54d4;
const TUNGETVNETHDRSZ: u32 = 0x8004_54d7;
const TUNSETVNETHDRSZ: u32 = 0x4004_54d8;
const TUNSETQUEUE: u32 = 0x4004_54d9;
const TUNSETIFINDEX: u32 = 0x4004_54da;
const TUNSETVNETLE: u32 = 0x4004_54dc;
const TUNGETVNETLE: u32 = 0x8004_54dd;
const TUNSETCARRIER: u32 = 0x4004_54e2;

/// The offloads of `TUNSETOFFLOAD`, `TUN_F_*`: checksum, TSO, ECN, UFO and USO.
const OFFLOADS: u32 = 0x7f;

/// The size of `struct ifreq`, and the offset of `ifr_flags` in it.
const IFREQ: usize = 40;
const IFR_FLAGS: usize = 16;
/// The size of a name in `struct ifreq`, `IFNAMSIZ`.
const IFNAMSIZ: usize = 16;

/// The size of `struct tun_pi`: the flags and the protocol.
const PI_LEN: usize = 4;
/// The flag of `struct tun_pi` for a frame that a read cut, `TUN_PKT_STRIP`.
const TUN_PKT_STRIP: u16 = 0x0001;
/// The size of `struct virtio_net_hdr`, the default and the smallest size of the header.
const VNET_HDR_LEN: u32 = 10;

/// The most frames that wait for a read, `TUN_READQ_SIZE` of Linux.
const READQ: usize = 500;
/// The most frames that a write puts before the next poll of the devices.
const BACKLOG: usize = 1000;
/// The largest MTU, `MAX_MTU` of tun.c.
const MAX_MTU: u32 = 65535;
/// The most queues of a device, `MAX_TAP_QUEUES` of Linux.
pub const MAX_TAP_QUEUES: usize = 256;

/// The settings of a device that the ioctls change.
struct Config {
    /// The `IFF_*` flags of <linux/if_tun.h>: the type, `IFF_PERSIST` and `FEATURES`.
    flags: u32,
    /// The user and the group that can attach, or `None` for each.
    owner: Option<u32>,
    group: Option<u32>,
    sndbuf: i32,
    vnet_hdr_sz: u32,
    vnet_le: bool,
    /// The carrier of `TUNSETCARRIER`.
    carrier: bool,
}

/// A queue of a device: the frames that the kernel sent for the reads of one file, as the
/// queue of `struct tun_file` of Linux.
pub(crate) struct Queue {
    pub(crate) out: SpinLock<VecDeque<NetBuf>>,
    /// The queue takes frames. A queue that `IFF_DETACH_QUEUE` took off the device does not.
    pub(crate) enabled: AtomicBool,
    wait: Arc<WaitQueue>,
    events: AtomicU64,
}

impl Queue {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            out: SpinLock::new(VecDeque::new()),
            enabled: AtomicBool::new(false),
            wait: Arc::new(WaitQueue::new()),
            events: AtomicU64::new(0),
        })
    }

    fn wake(&self) {
        self.events.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
    }
}

/// The driver of a TUN or TAP device.
pub struct Tun {
    mac: MacAddr,
    tap: bool,
    config: SpinLock<Config>,
    /// The queues of the files of the device, the enabled and the disabled ones, in the order of
    /// their attach, as `tfiles` and `disabled` of Linux.
    queues: SpinLock<Vec<Arc<Queue>>>,
    /// The device went away. A file of the device then gives `EBADFD`.
    gone: AtomicBool,
    /// The frames that the writes gave, for the poll of the device.
    input: SpinLock<VecDeque<NetBuf>>,
}

/// The TUN and TAP devices, to find the driver of a device.
static TUNS: SpinLock<Vec<(Weak<NetDevice>, Arc<Tun>)>> = SpinLock::new(Vec::new());

impl Tun {
    fn new(tap: bool, flags: u32) -> Arc<Self> {
        Arc::new(Self {
            mac: crate::veth::random_mac(),
            tap,
            config: SpinLock::new(Config {
                flags,
                owner: None,
                group: None,
                sndbuf: i32::MAX,
                vnet_hdr_sz: VNET_HDR_LEN,
                vnet_le: false,
                carrier: true,
            }),
            queues: SpinLock::new(Vec::new()),
            gone: AtomicBool::new(false),
            input: SpinLock::new(VecDeque::new()),
        })
    }

    fn multi_queue(&self) -> bool {
        self.config.lock().flags & IFF_MULTI_QUEUE != 0
    }

    /// Puts the queue `q` of a file on the device, as `tun_attach` of Linux. A device without
    /// `IFF_MULTI_QUEUE` takes one enabled queue, and a device takes at most `MAX_TAP_QUEUES`.
    fn attach(&self, q: &Arc<Queue>) -> Result<()> {
        let multi = self.multi_queue();
        let mut queues = self.queues.lock();
        let known = queues.iter().any(|x| Arc::ptr_eq(x, q));
        if !multi && queues.iter().any(|x| x.enabled.load(Ordering::Relaxed)) {
            return Err(Errno::EBUSY);
        }
        if !known && queues.len() >= MAX_TAP_QUEUES {
            return Err(Errno::E2BIG);
        }
        q.enabled.store(true, Ordering::Release);
        if !known {
            queues.push(q.clone());
        }
        Ok(())
    }

    /// Takes the queue `q` off the device, as `__tun_detach` of Linux. The frames of the queue go
    /// away. With `keep` the queue stays as a disabled queue, for `IFF_DETACH_QUEUE`. Gives the
    /// count of the queues that are left.
    fn detach(&self, q: &Arc<Queue>, keep: bool) -> usize {
        q.enabled.store(false, Ordering::Release);
        q.out.lock().clear();
        q.wake();
        let mut queues = self.queues.lock();
        if !keep {
            queues.retain(|x| !Arc::ptr_eq(x, q));
        }
        queues.len()
    }

    /// The enabled queue for `frame`: the hash of its flow selects one of them, as
    /// `tun_automq_select_queue` of Linux.
    fn select(&self, frame: &NetBuf) -> Option<Arc<Queue>> {
        let queues = self.queues.lock();
        let enabled = queues.iter().filter(|q| q.enabled.load(Ordering::Relaxed));
        let n = enabled.clone().count();
        if n == 0 {
            return None;
        }
        let i = if n == 1 { 0 } else { flow_hash(frame.data()) as usize % n };
        enabled.clone().nth(i).cloned()
    }

    /// The flags for `TUNGETIFF`, as `tun_flags` of Linux.
    fn flags(&self) -> u32 {
        let type_flag = if self.tap { IFF_TAP } else { IFF_TUN };
        (self.config.lock().flags & (FEATURES | IFF_PERSIST)) | type_flag
    }

    /// Tells if the current process cannot attach, as `tun_not_capable` of Linux.
    fn not_capable(&self) -> bool {
        let c = cred::current();
        let config = self.config.lock();
        let owner_ok = config.owner.is_none_or(|uid| uid == c.euid);
        let group_ok = config.group.is_none_or(|gid| c.in_group(gid));
        !(owner_ok && group_ok) && !c.capable(cap::NET_ADMIN)
    }
}

impl NetDriver for Tun {
    fn kind(&self) -> LinkKind {
        if self.tap { LinkKind::Ether } else { LinkKind::Tun }
    }

    fn mac(&self) -> MacAddr {
        if self.tap { self.mac } else { MacAddr::ZERO }
    }

    fn max_mtu(&self) -> u32 {
        MAX_MTU
    }

    fn link_kind(&self) -> Option<&'static str> {
        Some(KIND)
    }

    /// The carrier is on while a queue is enabled, as `tun_attach` and `__tun_detach` of Linux
    /// set it.
    fn link_up(&self) -> bool {
        self.queues.lock().iter().any(|q| q.enabled.load(Ordering::Relaxed))
            && self.config.lock().carrier
    }

    /// Puts the frame in the queue of the reads of one file, as `tun_net_xmit` of Linux. Without
    /// an enabled queue, or with a full queue, the frame goes away.
    fn transmit(&self, frame: NetBuf) -> Result<()> {
        let Some(queue) = self.select(&frame) else { return Ok(()) };
        {
            let mut q = queue.out.lock();
            if q.len() >= READQ {
                return Err(Errno::ENOBUFS);
            }
            q.push_back(frame);
        }
        queue.wake();
        Ok(())
    }

    fn poll(&self, budget: usize, deliver: &mut dyn FnMut(NetBuf)) -> usize {
        let mut n = 0;
        while n < budget {
            // The lock is not held while `deliver` runs, so `deliver` can send on the device.
            let Some(frame) = self.input.lock().pop_front() else { break };
            deliver(frame);
            n += 1;
        }
        n
    }
}

/// An open file of `/dev/net/tun`, as `struct tun_file` of Linux.
pub struct TunFile {
    /// The namespace of the process that opened the file. A new device goes in it.
    net: Arc<NetNs>,
    /// The interface index for the device that `TUNSETIFF` makes, from `TUNSETIFINDEX`. With 0
    /// the device gets a free index.
    pub(crate) ifindex: AtomicU32,
    /// The queue of the file. It is on the device of the file while it is enabled.
    pub(crate) queue: Arc<Queue>,
    /// The device of the file. The file is detached if this is set and the queue is not enabled.
    attached: SpinLock<Option<(Arc<Tun>, Arc<NetDevice>)>>,
}

impl TunFile {
    pub(crate) fn new(net: Arc<NetNs>) -> Self {
        Self { net, ifindex: AtomicU32::new(0), queue: Queue::new(), attached: SpinLock::new(None) }
    }

    /// The device of the file. Gives `EBADFD` if the file has none, or if `IFF_DETACH_QUEUE`
    /// took its queue off, as Linux.
    pub(crate) fn device(&self) -> Result<(Arc<Tun>, Arc<NetDevice>)> {
        let a = self.attached.lock().clone();
        match a {
            Some((tun, dev))
                if !tun.gone.load(Ordering::Relaxed)
                    && self.queue.enabled.load(Ordering::Relaxed) =>
            {
                Ok((tun, dev))
            }
            _ => Err(Errno::EBADFD),
        }
    }

    /// The device of a file that `IFF_DETACH_QUEUE` took off, as `tfile->detached` of Linux.
    fn detached(&self) -> Option<Arc<Tun>> {
        let a = self.attached.lock();
        let (tun, _) = a.as_ref()?;
        (!tun.gone.load(Ordering::Relaxed) && !self.queue.enabled.load(Ordering::Relaxed))
            .then(|| tun.clone())
    }

    /// Makes a device or attaches to one, as `tun_set_iff` of Linux. Gives the name.
    pub(crate) fn set_iff(&self, name: &str, flags: u32) -> Result<String> {
        let _in = ns::enter(&self.net);
        let tap = match flags & (IFF_TUN | IFF_TAP) {
            IFF_TUN => false,
            IFF_TAP => true,
            _ => return Err(Errno::EINVAL),
        };
        let detached = self.detached();
        let (tun, dev) = match (!name.is_empty()).then(|| dev::by_name(name)).flatten() {
            Some(dev) => {
                if flags & IFF_TUN_EXCL != 0 {
                    return Err(Errno::EBUSY);
                }
                let tun = find(&dev).ok_or(Errno::EINVAL)?;
                if tun.tap != tap {
                    return Err(Errno::EINVAL);
                }
                if (flags & IFF_MULTI_QUEUE != 0) != tun.multi_queue() {
                    return Err(Errno::EINVAL);
                }
                if tun.not_capable() {
                    return Err(Errno::EPERM);
                }
                // A detached file attaches again only to its own device.
                if detached.as_ref().is_some_and(|d| !Arc::ptr_eq(d, &tun)) {
                    return Err(Errno::EINVAL);
                }
                tun.attach(&self.queue)?;
                // Only the first queue sets the flags, as Linux.
                if tun.queues.lock().len() == 1 {
                    let mut c = tun.config.lock();
                    c.flags = (c.flags & !FEATURES) | (flags & FEATURES);
                }
                (tun, dev)
            }
            None => {
                if detached.is_some() {
                    return Err(Errno::EINVAL);
                }
                if !cred::current().capable(cap::NET_ADMIN) {
                    return Err(Errno::EPERM);
                }
                let pattern = match name {
                    "" if tap => "tap%d",
                    "" => "tun%d",
                    n => n,
                };
                let name = alloc_name(pattern)?;
                let tun = Tun::new(tap, flags & FEATURES);
                tun.attach(&self.queue)?;
                let ifindex = self.ifindex.load(Ordering::Relaxed);
                let dev = match dev::register_at(tun.clone(), Some(name.as_bytes()), ifindex) {
                    Ok(dev) => dev,
                    Err(e) => {
                        tun.detach(&self.queue, false);
                        return Err(e);
                    }
                };
                TUNS.lock().push((Arc::downgrade(&dev), tun.clone()));
                (tun, dev)
            }
        };
        let name = dev.name();
        *self.attached.lock() = Some((tun, dev));
        Ok(name)
    }

    /// Takes the queue of the file off its device or puts it back, as `tun_set_queue` of Linux.
    pub(crate) fn set_queue(&self, flags: u32) -> Result<()> {
        match flags {
            IFF_ATTACH_QUEUE => {
                let tun = self.detached().ok_or(Errno::EINVAL)?;
                if tun.not_capable() {
                    return Err(Errno::EPERM);
                }
                tun.attach(&self.queue)
            }
            IFF_DETACH_QUEUE => {
                let (tun, _) = self.device().map_err(|_| Errno::EINVAL)?;
                if !tun.multi_queue() {
                    return Err(Errno::EINVAL);
                }
                tun.detach(&self.queue, true);
                Ok(())
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// Takes the file off its device, as `tun_detach` of Linux. A device that is not persistent
    /// goes away with its last queue.
    fn detach(&self) {
        let Some((tun, dev)) = self.attached.lock().take() else { return };
        let left = tun.detach(&self.queue, false);
        if left == 0
            && tun.config.lock().flags & IFF_PERSIST == 0
            && !tun.gone.load(Ordering::Relaxed)
        {
            let _in = ns::enter_index(dev.net());
            dev::unregister(&dev);
        }
    }
}

impl Drop for TunFile {
    fn drop(&mut self) {
        self.detach();
    }
}

/// A hash of the flow of the frame `data` (an Ethernet frame) that is the same in the two
/// directions, as the symmetric flow hash of Linux. It uses the IP addresses, the protocol and
/// the ports of TCP, UDP and SCTP.
pub(crate) fn flow_hash(data: &[u8]) -> u32 {
    let ethertype = EthHeader::parse(data).map_or(0, |h| h.ethertype);
    let ip = data.get(HLEN..).unwrap_or(&[]);
    let (src, dst, proto, l4): (&[u8], &[u8], u8, &[u8]) = match ethertype {
        t if t == ETH_P_IP as u16 && ip.len() >= 20 => {
            let ihl = usize::from(ip[0] & 0xf) * 4;
            // A fragment after the first one has no ports.
            let frag = u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff != 0;
            let l4 = if frag { &[][..] } else { ip.get(ihl..).unwrap_or(&[]) };
            (&ip[12..16], &ip[16..20], ip[9], l4)
        }
        t if t == ETH_P_IPV6 as u16 && ip.len() >= 40 => {
            (&ip[8..24], &ip[24..40], ip[6], &ip[40..])
        }
        _ => return 0,
    };
    let ports = match proto {
        6 | 17 | 132 if l4.len() >= 4 => {
            let a = u32::from(u16::from_be_bytes([l4[0], l4[1]]));
            let b = u32::from(u16::from_be_bytes([l4[2], l4[3]]));
            a.min(b) << 16 | a.max(b)
        }
        _ => 0,
    };
    let (lo, hi) = if src <= dst { (src, dst) } else { (dst, src) };
    let mut h: u32 = 0x811c_9dc5;
    for &b in lo.iter().chain(hi).chain(&[proto]).chain(&ports.to_be_bytes()) {
        h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
    }
    h
}

/// The driver of the device `dev`, if it is a TUN or TAP device.
fn find(dev: &Arc<NetDevice>) -> Option<Arc<Tun>> {
    let list = TUNS.lock();
    list.iter().find(|(d, _)| core::ptr::eq(d.as_ptr(), Arc::as_ptr(dev))).map(|(_, t)| t.clone())
}

/// The name for a new device, as `dev_alloc_name` of Linux: `%d` becomes the lowest free
/// number.
fn alloc_name(pattern: &str) -> Result<String> {
    if pattern.len() >= IFNAMSIZ {
        return Err(Errno::EINVAL);
    }
    let Some((head, tail)) = pattern.split_once("%d") else {
        return Ok(String::from(pattern));
    };
    if tail.contains('%') {
        return Err(Errno::EINVAL);
    }
    (0..32768)
        .map(|n| format!("{head}{n}{tail}"))
        .find(|n| dev::by_name(n).is_none())
        .ok_or(Errno::ENFILE)
}

/// Reads an `int` argument of an ioctl.
fn read_int(mem: &dyn UserMemory, arg: usize) -> Result<i32> {
    let mut b = [0u8; 4];
    mem.read(arg, &mut b)?;
    Ok(i32::from_ne_bytes(b))
}

/// Writes an `int` result of an ioctl.
fn write_int(mem: &dyn UserMemory, arg: usize, v: i32) -> Result<usize> {
    mem.write(arg, &v.to_ne_bytes())?;
    Ok(0)
}

impl FileOps for TunFile {
    /// Gives one frame that the kernel sent, as `tun_do_read` of Linux. A short buffer gets the
    /// start of the frame.
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        let (tun, dev) = self.device()?;
        let queue = &self.queue;
        let frame = queue.wait.wait_interruptible(|| {
            if tun.gone.load(Ordering::Relaxed) || !queue.enabled.load(Ordering::Relaxed) {
                return Err(Errno::EBADFD);
            }
            if let Some(f) = queue.out.lock().pop_front() {
                return Ok(Some(f));
            }
            if file.nonblock() { Err(Errno::EAGAIN) } else { Ok(None) }
        })?;
        let data = frame.data();
        let ethertype = EthHeader::parse(data).map_or(0, |h| h.ethertype);
        let payload =
            if dev.kind() == LinkKind::Tun { &data[HLEN.min(data.len())..] } else { data };
        let (flags, vnet) = {
            let c = tun.config.lock();
            (c.flags, if c.flags & IFF_VNET_HDR != 0 { c.vnet_hdr_sz as usize } else { 0 })
        };
        let mut out = Vec::with_capacity(PI_LEN + vnet + payload.len());
        if flags & IFF_NO_PI == 0 {
            let total = PI_LEN + vnet + payload.len();
            let strip = if buf.len() < total { TUN_PKT_STRIP } else { 0 };
            out.extend_from_slice(&strip.to_ne_bytes());
            out.extend_from_slice(&ethertype.to_be_bytes());
        }
        // The header says no checksum and no segments: `VIRTIO_NET_HDR_GSO_NONE`.
        out.resize(out.len() + vnet, 0);
        out.extend_from_slice(payload);
        let n = out.len().min(buf.len());
        buf[..n].copy_from_slice(&out[..n]);
        Ok(n)
    }

    /// Gives a frame to the device, as `tun_get_user` of Linux. A TUN device without
    /// `struct tun_pi` takes the protocol from the version of the IP header.
    fn write(&self, _file: &File, buf: &[u8]) -> Result<usize> {
        let (tun, dev) = self.device()?;
        let (flags, vnet) = {
            let c = tun.config.lock();
            (c.flags, if c.flags & IFF_VNET_HDR != 0 { c.vnet_hdr_sz as usize } else { 0 })
        };
        let mut data = buf;
        let mut proto = None;
        if flags & IFF_NO_PI == 0 {
            if data.len() < PI_LEN {
                return Err(Errno::EINVAL);
            }
            proto = Some(u16::from_be_bytes([data[2], data[3]]));
            data = &data[PI_LEN..];
        }
        if vnet > 0 {
            if data.len() < vnet {
                return Err(Errno::EINVAL);
            }
            data = &data[vnet..];
        }
        // A device that is down drops the frame, as `netif_receive_skb` of Linux.
        if !dev.is_up() {
            return Ok(buf.len());
        }
        let frame = if tun.tap {
            if data.len() < HLEN {
                return Err(Errno::EINVAL);
            }
            NetBuf::from_slice(data)
        } else {
            let ethertype = match (proto, data.first().map(|b| b >> 4)) {
                (Some(p), _) => p,
                (None, Some(4)) => ETH_P_IP as u16,
                (None, Some(6)) => ETH_P_IPV6 as u16,
                _ => return Err(Errno::EINVAL),
            };
            let mut frame = NetBuf::new(HLEN, data.len());
            frame.put(data.len()).copy_from_slice(data);
            EthHeader { dst: MacAddr::ZERO, src: MacAddr::ZERO, ethertype }.push(&mut frame);
            frame
        };
        {
            let mut q = tun.input.lock();
            if q.len() >= BACKLOG {
                return Err(Errno::ENOBUFS);
            }
            q.push_back(frame);
        }
        drop(dev);
        dev::kick_rx();
        Ok(buf.len())
    }

    fn ioctl(&self, _file: &File, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        match cmd {
            TUNSETIFF => {
                {
                    let mut a = self.attached.lock();
                    match a.as_ref() {
                        // The device went away: the file can take a new one, as Linux.
                        Some((tun, _)) if tun.gone.load(Ordering::Relaxed) => *a = None,
                        Some(_) if self.queue.enabled.load(Ordering::Relaxed) => {
                            return Err(Errno::EEXIST);
                        }
                        _ => {}
                    }
                }
                let mut req = [0u8; IFREQ];
                mem.read(arg, &mut req)?;
                let len = req[..IFNAMSIZ].iter().position(|&b| b == 0).unwrap_or(IFNAMSIZ);
                let name = core::str::from_utf8(&req[..len]).map_err(|_| Errno::EINVAL)?;
                let flags = u32::from(u16::from_ne_bytes([req[IFR_FLAGS], req[IFR_FLAGS + 1]]));
                let name = self.set_iff(name, flags)?;
                let (tun, _) = self.device()?;
                req[..IFNAMSIZ].fill(0);
                req[..name.len()].copy_from_slice(name.as_bytes());
                req[IFR_FLAGS..IFR_FLAGS + 2].copy_from_slice(&(tun.flags() as u16).to_ne_bytes());
                mem.write(arg, &req)?;
                return Ok(0);
            }
            TUNGETFEATURES => {
                return write_int(mem, arg, (IFF_TUN | IFF_TAP | IFF_NO_CARRIER | FEATURES) as i32);
            }
            TUNSETQUEUE => {
                let mut req = [0u8; IFREQ];
                mem.read(arg, &mut req)?;
                let flags = u32::from(u16::from_ne_bytes([req[IFR_FLAGS], req[IFR_FLAGS + 1]]));
                self.set_queue(flags)?;
                return Ok(0);
            }
            TUNSETIFINDEX => {
                if self.device().is_ok() {
                    return Err(Errno::EPERM);
                }
                let v = read_int(mem, arg)?;
                if v < 0 {
                    return Err(Errno::EINVAL);
                }
                self.ifindex.store(v as u32, Ordering::Relaxed);
                return Ok(0);
            }
            _ => {}
        }
        let (tun, dev) = self.device()?;
        match cmd {
            TUNGETIFF => {
                let mut req = [0u8; IFREQ];
                let name = dev.name();
                req[..name.len()].copy_from_slice(name.as_bytes());
                req[IFR_FLAGS..IFR_FLAGS + 2].copy_from_slice(&(tun.flags() as u16).to_ne_bytes());
                mem.write(arg, &req)?;
                Ok(0)
            }
            TUNSETNOCSUM | TUNSETDEBUG => Ok(0),
            TUNSETPERSIST => {
                let mut c = tun.config.lock();
                if arg != 0 {
                    c.flags |= IFF_PERSIST;
                } else {
                    c.flags &= !IFF_PERSIST;
                }
                Ok(0)
            }
            TUNSETOWNER => {
                tun.config.lock().owner = (arg as u32 != u32::MAX).then_some(arg as u32);
                Ok(0)
            }
            TUNSETGROUP => {
                tun.config.lock().group = (arg as u32 != u32::MAX).then_some(arg as u32);
                Ok(0)
            }
            // The type of the link cannot change while the device is up.
            TUNSETLINK if dev.is_up() => Err(Errno::EBUSY),
            TUNSETLINK => Ok(0),
            TUNSETOFFLOAD if arg as u32 & !OFFLOADS != 0 => Err(Errno::EINVAL),
            TUNSETOFFLOAD => Ok(0),
            TUNSETTXFILTER if !tun.tap => Err(Errno::EINVAL),
            TUNSETTXFILTER => Ok(0),
            TUNGETSNDBUF => write_int(mem, arg, tun.config.lock().sndbuf),
            TUNSETSNDBUF => {
                let v = read_int(mem, arg)?;
                if v <= 0 {
                    return Err(Errno::EINVAL);
                }
                tun.config.lock().sndbuf = v;
                Ok(0)
            }
            TUNGETVNETHDRSZ => write_int(mem, arg, tun.config.lock().vnet_hdr_sz as i32),
            TUNSETVNETHDRSZ => {
                let v = read_int(mem, arg)?;
                if v < VNET_HDR_LEN as i32 {
                    return Err(Errno::EINVAL);
                }
                tun.config.lock().vnet_hdr_sz = v as u32;
                Ok(0)
            }
            TUNGETVNETLE => write_int(mem, arg, i32::from(tun.config.lock().vnet_le)),
            TUNSETVNETLE => {
                let v = read_int(mem, arg)?;
                tun.config.lock().vnet_le = v != 0;
                Ok(0)
            }
            TUNSETCARRIER => {
                let v = read_int(mem, arg)?;
                tun.config.lock().carrier = v != 0;
                Ok(0)
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// A file without a device gives `POLLERR`, as `tun_chr_poll` of Linux.
    fn poll(&self, _file: &File) -> u32 {
        if self.device().is_err() {
            return POLLERR;
        }
        let read = if self.queue.out.lock().is_empty() { 0 } else { POLLIN | POLLRDNORM };
        read | POLLOUT | POLLWRNORM
    }

    fn pollable(&self) -> bool {
        true
    }

    fn poll_wait(&self, _file: &File, table: &mut PollTable) {
        table.add(&self.queue.wait);
    }

    fn event_count(&self) -> u64 {
        self.queue.events.load(Ordering::Relaxed)
    }

    fn fdinfo(&self, _file: &File) -> Vec<u8> {
        let name = self.attached.lock().as_ref().map(|(_, d)| d.name()).unwrap_or_default();
        format!("iff:\t{name}\n").into_bytes()
    }
}

/// The character device `/dev/net/tun`.
struct TunDevice;

impl CharDevice for TunDevice {
    /// Opens a file without a device, as `tun_chr_open` of Linux.
    fn open(&self, _flags: u32) -> Result<Arc<dyn FileOps>> {
        Ok(Arc::new(TunFile::new(ns::current())))
    }
}

/// Marks the driver of a device that goes away, so that its files give `EBADFD`, as
/// `tun_detach_all` of Linux.
fn notifier(dev: &NetDevice, event: Event) {
    if event != Event::Unregister || dev.link_kind() != Some(KIND) {
        return;
    }
    let mut list = TUNS.lock();
    list.retain(|(d, tun)| {
        let same = core::ptr::eq(d.as_ptr(), dev);
        if same {
            tun.gone.store(true, Ordering::Relaxed);
            for q in core::mem::take(&mut *tun.queues.lock()) {
                q.enabled.store(false, Ordering::Relaxed);
                q.out.lock().clear();
                q.wake();
            }
        }
        !same && d.strong_count() > 0
    });
}

/// Adds `/dev/net/tun`. The kernel calls this one time at boot.
pub fn init() {
    register_char(TUN_RDEV, Arc::new(TunDevice));
    dev::add_notifier(notifier);
    add_device(DeviceInfo {
        name: String::from("net/tun"),
        class: "misc",
        rdev: TUN_RDEV,
        block: false,
        perm: 0o666,
    });
}

//! The packet sockets of the family `AF_PACKET`, as net/packet/af_packet.c of Linux.
//!
//! A packet socket sends whole link frames on one device. It also gives the ioctls of the
//! devices, for example `SIOCGIFINDEX`, as each socket of Linux does. Programs such as
//! `tst_ns_ifmove` of LTP make one only for these ioctls.
//!
//! A socket gets a copy of each frame that a device of its namespace receives, if the protocol
//! and the device match, as `packet_rcv` of Linux. A socket of `ETH_P_ALL` also gets the frames
//! that the devices send, as `dev_queue_xmit_nit` of Linux. A `SOCK_RAW` socket gets the link
//! header, and a `SOCK_DGRAM` socket gets the payload. A TUN device has no link header, thus its
//! frames have none for both types. A device on a terminal line, as a SLIP device, has no link
//! header too.
//!
//! When the device of a bound socket goes down, the socket gets the error `ENETDOWN` and no
//! frames, as `packet_notifier` of Linux. When the device goes away, the socket has no device,
//! and a send gives `ENXIO`.

use crate::buf::NetBuf;
use crate::consts::{MSG_DONTWAIT, MSG_OOB, MSG_PEEK, MSG_TRUNC, SOCK_DGRAM, SOCK_RAW};
use crate::dev::{self, Event, LinkKind, NetDevice};
use crate::ether::{EthHeader, HLEN, MacAddr};
use crate::options::Options;
use crate::{Message, PathOps, Received, Socket, next_ino, ns, wait_for};
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use rk_abi::Errno;
use rk_abi::native::if_ether::ETH_P_ALL;
use rk_abi::native::poll::{POLLERR, POLLIN, POLLOUT, POLLRDNORM, POLLWRBAND, POLLWRNORM};
use rk_abi::native::socket::{
    SO_ACCEPTCONN, SO_DOMAIN, SO_ERROR, SO_PROTOCOL, SO_TYPE, SOL_SOCKET,
};
use rk_frame::sync::SpinLock;
use rk_vfs::inode::Result;
use rk_vfs::wait::{PollTable, WaitQueue};

/// The family of the packet sockets, `AF_PACKET` of <linux/socket.h>.
pub const AF_PACKET: u32 = 17;

/// The size of `struct sockaddr_ll` of <linux/if_packet.h>.
const SOCKADDR_LL: usize = 20;

/// The level of the options of packet sockets, `SOL_PACKET` of <linux/socket.h>.
pub const SOL_PACKET: u32 = 263;
/// The options `PACKET_ADD_MEMBERSHIP` and `PACKET_DROP_MEMBERSHIP` of <linux/if_packet.h>.
const PACKET_ADD_MEMBERSHIP: u32 = 1;
const PACKET_DROP_MEMBERSHIP: u32 = 2;
/// The option `PACKET_VERSION` of <linux/if_packet.h>: the format of the mapped rings.
const PACKET_VERSION: u32 = 10;
/// The ring format `TPACKET_V1` of <linux/if_packet.h>, the default.
const TPACKET_V1: i32 = 0;

/// The types of a received frame, `PACKET_*` of <linux/if_packet.h>: to this host.
pub const PACKET_HOST: u8 = 0;
/// To all hosts.
pub const PACKET_BROADCAST: u8 = 1;
/// To a group of hosts.
pub const PACKET_MULTICAST: u8 = 2;
/// To another host.
pub const PACKET_OTHERHOST: u8 = 3;
/// A frame that this host sends.
pub const PACKET_OUTGOING: u8 = 4;

/// The memory that each queued frame uses in addition to its data, for the limit of
/// `SO_RCVBUF`, as the `truesize` of an `sk_buff` of Linux.
const FRAME_OVERHEAD: usize = 256;

/// The interface index of a socket whose device went away, `-1` of Linux. No device has it.
const GONE: u32 = u32::MAX;

/// The direction of a frame for `tap`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// The device received the frame.
    In,
    /// The device sends the frame. The packet socket with this inode number sent it, or 0.
    Out(u64),
}

/// A frame in the receive queue of a socket: the data and the address of the sender.
struct Queued {
    data: Vec<u8>,
    addr: [u8; SOCKADDR_LL],
}

/// The packet sockets of all namespaces, for `tap`.
static SOCKETS: SpinLock<Vec<Weak<PacketSocket>>> = SpinLock::new(Vec::new());
/// The count of packet sockets, so that `tap` does nothing when there is none.
static COUNT: AtomicUsize = AtomicUsize::new(0);

/// A packet socket.
pub struct PacketSocket {
    ino: u64,
    kind: u32,
    /// The protocol in network byte order, as the caller gave it.
    protocol: AtomicU32,
    /// The device of `bind`, or 0 for all devices, or `GONE`.
    ifindex: AtomicU32,
    /// The device of `bind` went down, thus the socket takes no frames, as a packet socket of
    /// Linux that is not `PACKET_SOCK_RUNNING`.
    stopped: AtomicBool,
    /// The error for the next receive or `SO_ERROR`, as `sk_err` of Linux, or 0.
    err: AtomicU32,
    options: SpinLock<Options>,
    wait: Arc<WaitQueue>,
    /// The index of the namespace of the socket. The socket holds its namespace, so the index
    /// does not change.
    net: usize,
    /// The received frames, and the memory that they use.
    queue: SpinLock<(VecDeque<Queued>, usize)>,
    events: AtomicU64,
}

impl Drop for PacketSocket {
    fn drop(&mut self) {
        COUNT.fetch_sub(1, Ordering::Relaxed);
    }
}

impl PacketSocket {
    /// Makes a packet socket, as `packet_create` of Linux. The caller checks `CAP_NET_RAW`.
    ///
    /// # Errors
    ///
    /// Gives `ESOCKTNOSUPPORT` for a type that is not `SOCK_RAW` or `SOCK_DGRAM`.
    pub fn new(kind: u32, protocol: u32) -> Result<Arc<Self>> {
        if kind != SOCK_RAW && kind != SOCK_DGRAM {
            return Err(Errno::ESOCKTNOSUPPORT);
        }
        let sock = Arc::new(Self {
            ino: next_ino(),
            kind,
            protocol: AtomicU32::new(protocol & 0xffff),
            ifindex: AtomicU32::new(0),
            stopped: AtomicBool::new(false),
            err: AtomicU32::new(0),
            options: SpinLock::new(Options::default()),
            wait: Arc::new(WaitQueue::new()),
            net: ns::current_index(),
            queue: SpinLock::new((VecDeque::new(), 0)),
            events: AtomicU64::new(0),
        });
        COUNT.fetch_add(1, Ordering::Relaxed);
        let mut list = SOCKETS.lock();
        list.retain(|w| w.strong_count() > 0);
        list.push(Arc::downgrade(&sock));
        Ok(sock)
    }

    /// Tells if the socket takes a frame of the protocol `ethertype` on `dev`.
    fn takes(&self, dev: &NetDevice, ethertype: u16, dir: Direction) -> bool {
        let protocol = u16::from_be(self.protocol() as u16);
        if protocol == 0 || self.net != dev.net() || self.stopped.load(Ordering::Relaxed) {
            return false;
        }
        let ifindex = self.ifindex.load(Ordering::Relaxed);
        if ifindex != 0 && ifindex != dev.ifindex() {
            return false;
        }
        match dir {
            Direction::In => u32::from(protocol) == ETH_P_ALL || protocol == ethertype,
            Direction::Out(skip) => u32::from(protocol) == ETH_P_ALL && skip != self.ino,
        }
    }

    /// Gives the pending error and clears it, as `sock_error` of Linux.
    fn take_error(&self) -> Result<()> {
        match self.err.swap(0, Ordering::Relaxed) {
            0 => Ok(()),
            e => Err(Errno::new(e as u16).unwrap_or(Errno::EIO)),
        }
    }

    /// Puts a copy of `frame` in the queue, as `packet_rcv` of Linux. A full queue drops it.
    fn queue(&self, dev: &NetDevice, frame: &[u8], h: &EthHeader, pkttype: u8) {
        let data = if self.kind == SOCK_DGRAM || !dev.kind().has_header() {
            &frame[HLEN..]
        } else {
            frame
        };
        let mut addr = [0u8; SOCKADDR_LL];
        addr[..2].copy_from_slice(&(AF_PACKET as u16).to_ne_bytes());
        addr[2..4].copy_from_slice(&h.ethertype.to_be_bytes());
        addr[4..8].copy_from_slice(&dev.ifindex().to_ne_bytes());
        addr[8..10].copy_from_slice(&dev.kind().arphrd().to_ne_bytes());
        addr[10] = pkttype;
        if dev.kind().has_header() {
            addr[11] = 6;
            addr[12..18].copy_from_slice(&h.src.0);
        }
        let size = data.len() + FRAME_OVERHEAD;
        let limit = self.options.lock().rcvbuf as usize;
        {
            let mut q = self.queue.lock();
            if q.1 + size > limit && !q.0.is_empty() {
                return;
            }
            q.0.push_back(Queued { data: data.to_vec(), addr });
            q.1 += size;
        }
        self.events.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
    }
}

/// Takes the change `event` of `dev` for the sockets that are bound to it, as `packet_notifier` of
/// Linux. A device that goes down gives `ENETDOWN` to each bound socket that takes frames, and the
/// socket takes no frames until the device is up again. A device that goes away leaves the
/// sockets without a device.
pub(crate) fn device_event(dev: &NetDevice, event: Event) {
    if COUNT.load(Ordering::Relaxed) == 0
        || !matches!(event, Event::Up | Event::Down | Event::Unregister)
    {
        return;
    }
    let list: Vec<Arc<PacketSocket>> = SOCKETS
        .lock()
        .iter()
        .filter_map(Weak::upgrade)
        .filter(|s| s.net == dev.net() && s.ifindex.load(Ordering::Relaxed) == dev.ifindex())
        .collect();
    for sock in list {
        if event == Event::Up {
            sock.stopped.store(false, Ordering::Relaxed);
            continue;
        }
        if !sock.stopped.swap(true, Ordering::Relaxed) && sock.protocol() != 0 {
            sock.err.store(u32::from(Errno::ENETDOWN.get()), Ordering::Relaxed);
        }
        if event == Event::Unregister {
            sock.ifindex.store(GONE, Ordering::Relaxed);
        }
        sock.events.fetch_add(1, Ordering::Relaxed);
        sock.wait.wake_all();
    }
}

/// Gives a copy of `frame` to each packet socket that takes it, as `__netif_receive_skb_core`
/// and `dev_queue_xmit_nit` of Linux. The device calls this for each frame that it receives or
/// sends.
pub fn tap(dev: &NetDevice, frame: &NetBuf, dir: Direction) {
    if COUNT.load(Ordering::Relaxed) == 0 {
        return;
    }
    let data = frame.data();
    let Some(h) = EthHeader::parse(data) else {
        return;
    };
    let list: Vec<Arc<PacketSocket>> = SOCKETS
        .lock()
        .iter()
        .filter_map(Weak::upgrade)
        .filter(|s| s.takes(dev, h.ethertype, dir))
        .collect();
    if list.is_empty() {
        return;
    }
    let pkttype = match dir {
        Direction::Out(_) => PACKET_OUTGOING,
        Direction::In if dev.kind() != LinkKind::Ether => PACKET_HOST,
        Direction::In if h.dst == dev.mac() => PACKET_HOST,
        Direction::In if h.dst.is_broadcast() => PACKET_BROADCAST,
        Direction::In if h.dst.is_multicast() => PACKET_MULTICAST,
        Direction::In => PACKET_OTHERHOST,
    };
    // The lock of the list is not held here, so a full queue or a wake cannot block it.
    for sock in list {
        sock.queue(dev, data, &h, pkttype);
    }
}

/// The fields of a `struct sockaddr_ll`: the protocol, the interface index and the address.
fn parse_addr(addr: &[u8]) -> Result<(u16, u32, MacAddr)> {
    if addr.len() < SOCKADDR_LL {
        return Err(Errno::EINVAL);
    }
    if u32::from(u16::from_ne_bytes([addr[0], addr[1]])) != AF_PACKET {
        return Err(Errno::EINVAL);
    }
    let protocol = u16::from_ne_bytes([addr[2], addr[3]]);
    let ifindex = u32::from_ne_bytes([addr[4], addr[5], addr[6], addr[7]]);
    let mut mac = [0; 6];
    mac.copy_from_slice(&addr[12..18]);
    Ok((protocol, ifindex, MacAddr(mac)))
}

impl Socket for PacketSocket {
    fn family(&self) -> u32 {
        AF_PACKET
    }

    fn kind(&self) -> u32 {
        self.kind
    }

    fn protocol(&self) -> u32 {
        self.protocol.load(Ordering::Relaxed)
    }

    fn ino(&self) -> u64 {
        self.ino
    }

    /// Binds the socket to one device, as `packet_bind` of Linux. Index 0 means all devices.
    fn bind(&self, _paths: &dyn PathOps, addr: &[u8]) -> Result<()> {
        let (protocol, ifindex, _) = parse_addr(addr)?;
        if ifindex != 0 && dev::by_index(ifindex).is_none() {
            return Err(Errno::ENODEV);
        }
        if protocol != 0 {
            self.protocol.store(u32::from(protocol), Ordering::Relaxed);
        }
        self.ifindex.store(ifindex, Ordering::Relaxed);
        self.stopped.store(false, Ordering::Relaxed);
        Ok(())
    }

    /// Sends one frame, as `packet_snd` of Linux. A `SOCK_RAW` socket gives the whole frame. A
    /// `SOCK_DGRAM` socket gives the payload, and the kernel adds the link header. A device
    /// without a link header takes the payload from both types.
    fn send(
        &self,
        _paths: &dyn PathOps,
        msg: Message,
        flags: u32,
        _nonblock: bool,
    ) -> Result<usize> {
        if flags & MSG_OOB != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let (protocol, ifindex, dst) = match msg.addr.as_deref() {
            Some(a) if !a.is_empty() => parse_addr(a)?,
            _ => (self.protocol() as u16, self.ifindex.load(Ordering::Relaxed), MacAddr::BROADCAST),
        };
        // No device gives `ENXIO`, as Linux.
        let dev = dev::by_index(ifindex).ok_or(Errno::ENXIO)?;
        let len = msg.data.len();
        let mut frame = NetBuf::new(HLEN, len);
        frame.put(len).copy_from_slice(&msg.data);
        if !dev.kind().has_header() {
            let h = EthHeader {
                dst: MacAddr::ZERO,
                src: MacAddr::ZERO,
                ethertype: u16::from_be(protocol),
            };
            h.push(&mut frame);
        } else if self.kind == SOCK_DGRAM {
            let h = EthHeader { dst, src: dev.mac(), ethertype: u16::from_be(protocol) };
            h.push(&mut frame);
        } else if len < HLEN {
            return Err(Errno::EINVAL);
        }
        dev.transmit_from(frame, self.ino)?;
        Ok(len)
    }

    /// Takes one frame from the queue, as `packet_recvmsg` of Linux. The address is the
    /// `struct sockaddr_ll` of the sender.
    fn recv(&self, len: usize, flags: u32, nonblock: bool) -> Result<Received> {
        if flags & MSG_OOB != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let nonblock = nonblock || flags & MSG_DONTWAIT != 0;
        let timeout = self.options.lock().rcvtimeo;
        let item = wait_for(&self.wait, timeout, || {
            // A pending error comes first, as `sock_error` in `__skb_try_recv_datagram`.
            self.take_error()?;
            let mut q = self.queue.lock();
            if flags & MSG_PEEK != 0 {
                if let Some(f) = q.0.front() {
                    return Ok(Some(Queued { data: f.data.clone(), addr: f.addr }));
                }
            } else if let Some(f) = q.0.pop_front() {
                q.1 = q.1.saturating_sub(f.data.len() + FRAME_OVERHEAD);
                return Ok(Some(f));
            }
            if nonblock { Err(Errno::EAGAIN) } else { Ok(None) }
        })?;
        let full = item.data.len();
        let mut data = item.data;
        data.truncate(len);
        Ok(Received {
            flags: if full > len { MSG_TRUNC } else { 0 },
            data,
            len: full,
            addr: Some(item.addr.to_vec()),
            ..Received::default()
        })
    }

    /// Gives the `struct sockaddr_ll` of the socket, as `packet_getname` of Linux.
    fn name(&self) -> Vec<u8> {
        let ifindex = self.ifindex.load(Ordering::Relaxed);
        let mut a = [0u8; SOCKADDR_LL];
        a[..2].copy_from_slice(&(AF_PACKET as u16).to_ne_bytes());
        a[2..4].copy_from_slice(&(self.protocol() as u16).to_ne_bytes());
        a[4..8].copy_from_slice(&ifindex.to_ne_bytes());
        if let Some(d) = dev::by_index(ifindex) {
            a[8..10].copy_from_slice(&d.kind().arphrd().to_ne_bytes());
            a[11] = 6;
            a[12..18].copy_from_slice(&d.mac().0);
        }
        a.to_vec()
    }

    fn get_option(&self, level: u32, name: u32) -> Result<Vec<u8>> {
        if level == SOL_PACKET {
            return match name {
                PACKET_VERSION => Ok(TPACKET_V1.to_ne_bytes().to_vec()),
                _ => Err(Errno::ENOPROTOOPT),
            };
        }
        if level != SOL_SOCKET {
            return Err(Errno::ENOPROTOOPT);
        }
        let int = |v: u32| (v as i32).to_ne_bytes().to_vec();
        Ok(match name {
            SO_TYPE => int(self.kind),
            SO_DOMAIN => int(AF_PACKET),
            SO_PROTOCOL => int(self.protocol()),
            SO_ERROR => int(self.err.swap(0, Ordering::Relaxed)),
            SO_ACCEPTCONN => int(0),
            _ => self.options.lock().get(name)?,
        })
    }

    fn set_option(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
        // A membership takes the frames of a group or all frames. Each device here gives all
        // frames that it gets to the sockets, thus the call only checks the device.
        if level == SOL_PACKET {
            return match name {
                PACKET_ADD_MEMBERSHIP | PACKET_DROP_MEMBERSHIP => {
                    let ifindex = value.get(..4).ok_or(Errno::EINVAL)?;
                    let ifindex =
                        u32::from_ne_bytes([ifindex[0], ifindex[1], ifindex[2], ifindex[3]]);
                    dev::by_index(ifindex).map(|_| ()).ok_or(Errno::ENODEV)
                }
                // rukernel has no mapped rings (`PACKET_RX_RING`), so only `TPACKET_V1`, the
                // format of a socket without a ring, is accepted. `TPACKET_V2` and `TPACKET_V3`
                // give `EINVAL`, as an unknown version gives in `packet_setsockopt` of Linux,
                // and a program such as setsockopt02 of LTP then knows that they are missing.
                PACKET_VERSION => {
                    let v: [u8; 4] = value.try_into().map_err(|_| Errno::EINVAL)?;
                    if i32::from_ne_bytes(v) == TPACKET_V1 { Ok(()) } else { Err(Errno::EINVAL) }
                }
                _ => Err(Errno::ENOPROTOOPT),
            };
        }
        if level != SOL_SOCKET {
            return Err(Errno::ENOPROTOOPT);
        }
        match name {
            SO_TYPE | SO_DOMAIN | SO_PROTOCOL | SO_ERROR | SO_ACCEPTCONN => Err(Errno::ENOPROTOOPT),
            _ => self.options.lock().set(name, value),
        }
    }

    fn poll(&self) -> u32 {
        let read = if self.queue.lock().0.is_empty() { 0 } else { POLLIN | POLLRDNORM };
        let err = if self.err.load(Ordering::Relaxed) != 0 { POLLERR } else { 0 };
        read | err | POLLOUT | POLLWRNORM | POLLWRBAND
    }

    fn poll_wait(&self, table: &mut PollTable) {
        table.add(&self.wait);
    }

    fn event_count(&self) -> u64 {
        self.events.load(Ordering::Relaxed)
    }

    /// The size of the first frame, as `packet_ioctl` of Linux for `SIOCINQ`.
    fn readable(&self) -> Result<usize> {
        Ok(self.queue.lock().0.front().map_or(0, |f| f.data.len()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

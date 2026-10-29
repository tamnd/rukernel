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
//!
//! A socket can have a mapped receive ring and a mapped transmit ring, as `PACKET_RX_RING` and
//! `PACKET_TX_RING` of Linux. The module `ring` has them.

use crate::buf::NetBuf;
use crate::consts::{MSG_DONTWAIT, MSG_OOB, MSG_PEEK, MSG_TRUNC, SOCK_DGRAM, SOCK_RAW};
use crate::dev::{self, Event, LinkKind, NetDevice};
use crate::ether::{EthHeader, HLEN, MacAddr};
use crate::options::{Options, hz, now};
use crate::{Message, PathOps, Received, Socket, SocketMap, next_ino, ns, wait_for};
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

mod ring;
#[cfg(test)]
mod tests;

use ring::{Packet, Req, Ring, Stats, TPACKET_V1, TPACKET_V2, TPACKET_V3};

/// The size of `struct sockaddr_ll` of <linux/if_packet.h>.
const SOCKADDR_LL: usize = 20;

/// The level of the options of packet sockets, `SOL_PACKET` of <linux/socket.h>.
pub const SOL_PACKET: u32 = 263;
/// The options `PACKET_ADD_MEMBERSHIP` and `PACKET_DROP_MEMBERSHIP` of <linux/if_packet.h>.
const PACKET_ADD_MEMBERSHIP: u32 = 1;
const PACKET_DROP_MEMBERSHIP: u32 = 2;
/// The options of the mapped rings of <linux/if_packet.h>.
const PACKET_RX_RING: u32 = 5;
const PACKET_STATISTICS: u32 = 6;
const PACKET_VERSION: u32 = 10;
const PACKET_HDRLEN: u32 = 11;
const PACKET_RESERVE: u32 = 12;
const PACKET_TX_RING: u32 = 13;
const PACKET_LOSS: u32 = 14;
const PACKET_TIMESTAMP: u32 = 17;

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

/// The options of the rings of a socket.
#[derive(Default)]
struct RingCfg {
    /// The format of the rings, `PACKET_VERSION`.
    version: i32,
    /// The free space before the link header in each frame, `PACKET_RESERVE`.
    reserve: u32,
    /// A transmit ring skips a bad frame, `PACKET_LOSS`.
    loss: bool,
    /// The value of `PACKET_TIMESTAMP`. The frames always have a software time stamp.
    tstamp: i32,
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
    /// The options of the rings. The lock comes before the locks of the rings.
    cfg: SpinLock<RingCfg>,
    /// The receive ring. Its lock comes before the lock of the transmit ring.
    rx: SpinLock<Option<Ring>>,
    /// The transmit ring.
    tx: SpinLock<Option<Ring>>,
    /// The counts of `PACKET_STATISTICS`.
    stats: Stats,
    /// Each mapping of the rings holds a clone, so the socket is mapped while the count is more
    /// than 1, as `po->mapped` of Linux.
    maps: Arc<()>,
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
            cfg: SpinLock::new(RingCfg::default()),
            rx: SpinLock::new(None),
            tx: SpinLock::new(None),
            stats: Stats::default(),
            maps: Arc::new(()),
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

    /// Puts a copy of `frame` in the queue, as `packet_rcv` of Linux. A full queue drops it. A
    /// socket with a receive ring puts the frame in the ring, as `tpacket_rcv` of Linux.
    fn queue(&self, dev: &NetDevice, frame: &[u8], h: &EthHeader, pkttype: u8) {
        let raw = self.kind == SOCK_RAW && dev.kind().has_header();
        let data = if !raw { &frame[HLEN..] } else { frame };
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
        {
            let mut rx = self.rx.lock();
            if let Some(ring) = rx.as_mut() {
                let p = Packet {
                    data,
                    maclen: if raw { HLEN } else { 0 },
                    dgram: self.kind == SOCK_DGRAM,
                    addr: &addr,
                };
                if !ring.receive(&p, &self.stats, now()) {
                    self.stats.drops.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                drop(rx);
                self.events.fetch_add(1, Ordering::Relaxed);
                self.wait.wake_all();
                return;
            }
        }
        let size = data.len() + FRAME_OVERHEAD;
        let limit = self.options.lock().rcvbuf as usize;
        {
            let mut q = self.queue.lock();
            if q.1 + size > limit && !q.0.is_empty() {
                self.stats.drops.fetch_add(1, Ordering::Relaxed);
                return;
            }
            q.0.push_back(Queued { data: data.to_vec(), addr });
            q.1 += size;
            self.stats.packets.fetch_add(1, Ordering::Relaxed);
        }
        self.events.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
    }

    /// Tells if a mapping of the rings exists.
    fn mapped(&self) -> bool {
        Arc::strong_count(&self.maps) > 1
    }

    /// Makes or removes a ring, as `packet_set_ring` of Linux.
    ///
    /// # Errors
    ///
    /// Gives `EBUSY` if the rings are mapped or the ring exists, and the errors of `Ring::new`.
    fn set_ring(&self, value: &[u8], tx: bool) -> Result<()> {
        let cfg = self.cfg.lock();
        let req = Req::parse(cfg.version, value)?;
        let mut rx = self.rx.lock();
        let mut txr = self.tx.lock();
        if self.mapped() {
            return Err(Errno::EBUSY);
        }
        let slot = if tx { &mut *txr } else { &mut *rx };
        if req.removes() {
            req.check_remove()?;
            *slot = None;
            return Ok(());
        }
        if slot.is_some() {
            return Err(Errno::EBUSY);
        }
        let ring = Ring::new(cfg.version, cfg.reserve, &req, tx, now(), hz())?;
        let timed = ring.deadline().is_some();
        *slot = Some(ring);
        if timed {
            retire::start();
        }
        Ok(())
    }

    /// Sends the frames of the transmit ring that the program asks to send, as `tpacket_snd` of
    /// Linux. Gives the count of bytes, or `None` if the socket has no transmit ring.
    fn send_ring(&self, ifindex: u32, protocol: u16, dst: MacAddr) -> Option<Result<usize>> {
        let loss = self.cfg.lock().loss;
        let mut tx = self.tx.lock();
        let ring = tx.as_mut()?;
        let Some(dev) = dev::by_index(ifindex) else { return Some(Err(Errno::ENXIO)) };
        if !dev.is_up() {
            return Some(Err(Errno::ENETDOWN));
        }
        // The largest packet: the frame without its header, and no more than the MTU with the
        // link header, as `tpacket_snd`.
        let raw = self.kind == SOCK_RAW && dev.kind().has_header();
        let max = ring.send_max().min(dev.mtu() as usize + if raw { HLEN } else { 0 } + 4);
        let mut total = 0usize;
        while let Some(next) = ring.take_send(max) {
            let (at, data) = match next {
                Ok(v) => v,
                Err((at, e)) => {
                    if loss {
                        ring.set_status(at, ring::TP_STATUS_AVAILABLE);
                        ring.advance();
                        continue;
                    }
                    ring.set_status(at, ring::TP_STATUS_WRONG_FORMAT);
                    return Some(Err(e));
                }
            };
            let len = data.len();
            let frame = match self.frame_for(&dev, data, protocol, dst) {
                Ok(f) => f,
                Err(e) => {
                    if loss {
                        ring.set_status(at, ring::TP_STATUS_AVAILABLE);
                        ring.advance();
                        continue;
                    }
                    ring.set_status(at, ring::TP_STATUS_WRONG_FORMAT);
                    return Some(Err(e));
                }
            };
            if let Err(e) = dev.transmit_from(frame, self.ino) {
                ring.set_status(at, ring::TP_STATUS_SEND_REQUEST);
                return Some(Err(e));
            }
            ring.set_status(at, ring::TP_STATUS_AVAILABLE);
            ring.advance();
            total += len;
        }
        Some(Ok(total))
    }

    /// Makes the frame that `dev` sends for `data`. A `SOCK_RAW` socket gives the whole frame. A
    /// `SOCK_DGRAM` socket gives the payload, and the kernel adds the link header. A device
    /// without a link header takes the payload from both types.
    fn frame_for(
        &self,
        dev: &NetDevice,
        data: Vec<u8>,
        protocol: u16,
        dst: MacAddr,
    ) -> Result<NetBuf> {
        let len = data.len();
        let mut frame = NetBuf::new(HLEN, len);
        frame.put(len).copy_from_slice(&data);
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
        Ok(frame)
    }

    /// Runs the retire timer of the receive ring. Gives the tick of the next run, or `None` if the
    /// ring has no timer.
    #[cfg_attr(
        not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))),
        allow(dead_code)
    )]
    fn retire(&self, now: u64) -> Option<u64> {
        let mut rx = self.rx.lock();
        let ring = rx.as_mut()?;
        let woke = ring.expire(&self.stats, now);
        let next = ring.deadline();
        drop(rx);
        if woke {
            self.events.fetch_add(1, Ordering::Relaxed);
            self.wait.wake_all();
        }
        next
    }
}

/// The retire timer of the `TPACKET_V3` receive rings, as `prb_retire_rx_blk_timer_expired` of
/// Linux. One kernel task runs the timers of all rings. It waits until the earliest deadline.
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod retire {
    use super::{PacketSocket, SOCKETS};
    use alloc::sync::{Arc, Weak};
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU64, Ordering};
    use rk_frame::sync::Once;
    use rk_frame::task::{TaskOptions, WaitQueue};

    /// The count of new rings. The task waits until it changes or a deadline comes.
    static EPOCH: AtomicU64 = AtomicU64::new(0);
    static WAKE: WaitQueue = WaitQueue::new();
    static STARTED: Once<()> = Once::new();

    /// Starts the task the first time that a ring has a timer, and tells it of a new ring.
    pub(super) fn start() {
        STARTED.call_once(|| {
            let _ = TaskOptions::new(run).spawn();
        });
        EPOCH.fetch_add(1, Ordering::Release);
        WAKE.wake_all();
    }

    fn run() {
        loop {
            let epoch = EPOCH.load(Ordering::Acquire);
            let now = rk_frame::time::ticks();
            let list: Vec<Arc<PacketSocket>> =
                SOCKETS.lock().iter().filter_map(Weak::upgrade).collect();
            let next = list.iter().filter_map(|s| s.retire(now)).min();
            drop(list);
            let changed = || (EPOCH.load(Ordering::Acquire) != epoch).then_some(());
            match next {
                Some(deadline) => {
                    WAKE.wait_until_timeout(deadline, changed);
                }
                None => WAKE.wait_until(changed),
            }
        }
    }
}

/// No task runs the retire timers on a machine without tasks.
#[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
mod retire {
    pub(super) fn start() {}
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

    /// Sends one frame, as `packet_snd` of Linux. `frame_for` makes the frame.
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
        // A socket with a transmit ring sends the frames of the ring, as `packet_sendmsg`.
        if let Some(r) = self.send_ring(ifindex, protocol, dst) {
            return r;
        }
        // No device gives `ENXIO`, as Linux.
        let dev = dev::by_index(ifindex).ok_or(Errno::ENXIO)?;
        let len = msg.data.len();
        let frame = self.frame_for(&dev, msg.data, protocol, dst)?;
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
            let int = |v: i32| v.to_ne_bytes().to_vec();
            let cfg = self.cfg.lock();
            return match name {
                PACKET_VERSION => Ok(int(cfg.version)),
                PACKET_RESERVE => Ok(int(cfg.reserve as i32)),
                PACKET_LOSS => Ok(int(i32::from(cfg.loss))),
                PACKET_TIMESTAMP => Ok(int(cfg.tstamp)),
                PACKET_STATISTICS => Ok(self.stats.take(cfg.version)),
                // `PACKET_HDRLEN` reads the version from the value, see `get_option_in`.
                PACKET_HDRLEN => Err(Errno::EINVAL),
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
                PACKET_RX_RING | PACKET_TX_RING => self.set_ring(value, name == PACKET_TX_RING),
                // The options of the rings, as `packet_setsockopt` of Linux. The value must be
                // an `int`, and a socket with a ring cannot change the format or the reserve.
                PACKET_VERSION | PACKET_RESERVE | PACKET_LOSS | PACKET_TIMESTAMP => {
                    let v: [u8; 4] = value.try_into().map_err(|_| Errno::EINVAL)?;
                    let v = i32::from_ne_bytes(v);
                    let mut cfg = self.cfg.lock();
                    if name == PACKET_TIMESTAMP {
                        cfg.tstamp = v;
                        return Ok(());
                    }
                    if self.rx.lock().is_some() || self.tx.lock().is_some() {
                        return Err(Errno::EBUSY);
                    }
                    match name {
                        PACKET_VERSION if matches!(v, TPACKET_V1 | TPACKET_V2 | TPACKET_V3) => {
                            cfg.version = v;
                        }
                        PACKET_VERSION => return Err(Errno::EINVAL),
                        // A negative `int` is more than `INT_MAX` as the `unsigned int` of Linux.
                        PACKET_RESERVE if v < 0 => return Err(Errno::EINVAL),
                        PACKET_RESERVE => cfg.reserve = v as u32,
                        _ => cfg.loss = v != 0,
                    }
                    Ok(())
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

    /// `PACKET_HDRLEN` reads an `int`, the version.
    fn option_input(&self, level: u32, name: u32) -> usize {
        if level == SOL_PACKET && name == PACKET_HDRLEN { 4 } else { 0 }
    }

    /// Gives the size of the frame header of a version for `PACKET_HDRLEN`, as
    /// `packet_getsockopt` of Linux.
    fn get_option_in(&self, level: u32, name: u32, input: &[u8]) -> Result<Vec<u8>> {
        if level != SOL_PACKET || name != PACKET_HDRLEN {
            return self.get_option(level, name);
        }
        let v: [u8; 4] =
            input.get(..4).ok_or(Errno::EINVAL)?.try_into().map_err(|_| Errno::EINVAL)?;
        let size = ring::header_size(i32::from_ne_bytes(v)).ok_or(Errno::EINVAL)?;
        Ok((size as i32).to_ne_bytes().to_vec())
    }

    /// Maps the receive ring and then the transmit ring, as `packet_mmap` of Linux. The mapping
    /// must start at 0 and have the size of the rings.
    fn mmap(&self, offset: u64, len: usize) -> Result<SocketMap> {
        if offset != 0 {
            return Err(Errno::EINVAL);
        }
        let rx = self.rx.lock();
        let tx = self.tx.lock();
        let pages: Vec<&ring::Page> =
            rx.iter().chain(tx.iter()).flat_map(|r| r.pages().iter()).collect();
        if pages.is_empty() || pages.len() * rk_frame::addr::PAGE_SIZE != len {
            return Err(Errno::EINVAL);
        }
        #[cfg(target_os = "none")]
        let frames: Vec<Arc<rk_frame::mm::Frame>> = pages.iter().map(|&p| p.clone()).collect();
        let hold: Arc<dyn Any + Send + Sync> = self.maps.clone();
        Ok(SocketMap {
            #[cfg(target_os = "none")]
            frames,
            pages: pages.len(),
            hold,
        })
    }

    fn poll(&self) -> u32 {
        let ring = self.rx.lock().as_ref().map(Ring::readable);
        let ready = match ring {
            Some(r) => r,
            None => !self.queue.lock().0.is_empty(),
        };
        let read = if ready { POLLIN | POLLRDNORM } else { 0 };
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

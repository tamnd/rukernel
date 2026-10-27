//! The datagram sockets of IPv4: UDP sockets, ICMP echo sockets and raw sockets, as
//! net/ipv4/udp.c, net/ipv4/ping.c and net/ipv4/raw.c of Linux.
//!
//! The three kinds share one type, because they differ only in the header that a send adds and
//! in the table that finds the socket for a received packet. A UDP socket has a port in
//! `UDP_PORTS`. An echo socket has an identifier in `PING_PORTS`, and a send puts it in the
//! echo request. A raw socket takes a copy of each packet of its protocol.

use crate::ipv4::{self, Addr, HLEN, Header, PROTO_ICMP, PROTO_UDP, UDP_HLEN, UdpHeader};
use crate::ports::{Binding, Ports};
use crate::stack::{self, Out, PING_PORTS, UDP_PORTS};
use crate::{checksum, sockaddr};
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::inet::{
    IP_HDRINCL, IP_MTU_DISCOVER, IP_MULTICAST_LOOP, IP_MULTICAST_TTL, IP_RECVERR, IP_TOS, IP_TTL,
    IPPROTO_ICMP, IPPROTO_IP, IPPROTO_RAW, IPPROTO_TCP, IPPROTO_UDP,
};
use rk_abi::native::poll::{
    POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP, POLLRDNORM, POLLWRBAND, POLLWRNORM,
};
use rk_abi::native::socket::{
    SO_ACCEPTCONN, SO_BINDTODEVICE, SO_BROADCAST, SO_COOKIE, SO_DOMAIN, SO_ERROR, SO_PROTOCOL,
    SO_REUSEADDR, SO_TYPE, SOL_SOCKET,
};
use rk_frame::sync::SpinLock;
use rk_net::consts::{
    AF_INET, ICMP_ECHO, ICMP_FILTER, MSG_DONTWAIT, MSG_ERRQUEUE, MSG_OOB, MSG_PEEK, MSG_TRUNC,
    SHUT_RD, SHUT_RDWR, SHUT_WR, SOCK_DGRAM, SOCK_RAW, SOCK_STREAM, SOL_RAW,
};
use rk_net::{Message, Options, PathOps, Received, Socket, wait_for};
use rk_vfs::inode::Result;
use rk_vfs::wait::{WaitQueue, poll_wake};

/// The kind of a datagram socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    /// A UDP socket.
    Udp,
    /// An ICMP echo socket, `SOCK_DGRAM` with `IPPROTO_ICMP`.
    Ping,
    /// A raw socket of an IP protocol.
    Raw(u8),
    /// A TCP socket, `SOCK_STREAM`. `new_socket` makes a `Stream` for it.
    Tcp,
}

/// The first protocol number that Linux does not have, `IPPROTO_MAX`.
const IPPROTO_MAX: u32 = 263;

/// Gives the kind of socket for the arguments `type` and `protocol` of `socket`, as
/// `inet_create` of Linux. The caller checks the permissions: a raw socket needs
/// `CAP_NET_RAW`, and an echo socket needs a group in `net.ipv4.ping_group_range`.
///
/// # Errors
///
/// Gives `EINVAL` for a protocol out of the range, `EPROTONOSUPPORT` for a protocol that the
/// type does not have, and `ESOCKTNOSUPPORT` for a type that IPv4 does not have.
pub fn classify(kind: u32, protocol: u32) -> Result<Proto> {
    if protocol >= IPPROTO_MAX {
        return Err(Errno::EINVAL);
    }
    match kind {
        SOCK_DGRAM => match protocol {
            0 | IPPROTO_UDP => Ok(Proto::Udp),
            IPPROTO_ICMP => Ok(Proto::Ping),
            _ => Err(Errno::EPROTONOSUPPORT),
        },
        SOCK_RAW => match u8::try_from(protocol) {
            Ok(p) if p != 0 => Ok(Proto::Raw(p)),
            _ => Err(Errno::EPROTONOSUPPORT),
        },
        SOCK_STREAM => match protocol {
            0 | IPPROTO_TCP => Ok(Proto::Tcp),
            _ => Err(Errno::EPROTONOSUPPORT),
        },
        _ => Err(Errno::ESOCKTNOSUPPORT),
    }
}

/// Makes a socket of the kind `proto`: a `Stream` for TCP and a `Dgram` for the others.
pub fn new_socket(proto: Proto) -> Arc<dyn Socket> {
    match proto {
        Proto::Tcp => crate::tcp::Stream::new(),
        _ => Dgram::new(proto),
    }
}

/// The bytes that a datagram in the receive queue costs more than its data, in place of the
/// `truesize` of a Linux packet buffer.
const OVERHEAD: usize = 256;

/// A received datagram.
struct Datagram {
    src: Addr,
    port: u16,
    data: Vec<u8>,
}

struct State {
    /// The local address, or `0.0.0.0`.
    local: Addr,
    /// The port or the echo identifier, or 0 if the socket has none yet.
    port: u16,
    /// The address came from `bind`, so `connect` does not change it.
    addr_locked: bool,
    /// The peer of `connect`.
    remote: Option<(Addr, u16)>,
    queue: VecDeque<Datagram>,
    /// The bytes that the queue costs.
    queued: usize,
    /// The error for `SO_ERROR` and the next call.
    error: Option<Errno>,
    options: Options,
    /// `IP_TTL`, or `None` for the default.
    ttl: Option<u8>,
    tos: u8,
    recverr: bool,
    hdrincl: bool,
    mtu_discover: i32,
    multicast_ttl: i32,
    multicast_loop: bool,
    /// `ICMP_FILTER`: a bit for each ICMP type to drop.
    filter: u32,
    shut_rd: bool,
    shut_wr: bool,
    closed: bool,
}

/// A datagram socket of IPv4.
pub struct Dgram {
    proto: Proto,
    ino: u64,
    state: SpinLock<State>,
    wait: WaitQueue,
    events: AtomicU64,
}

fn int(v: i32) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

fn int_of(value: &[u8]) -> Result<i32> {
    let Some(v) = value.first_chunk::<4>() else { return Err(Errno::EINVAL) };
    Ok(i32::from_ne_bytes(*v))
}

impl Dgram {
    /// Makes a socket of the kind `proto`. A `Dgram` of the kind `Proto::Tcp` takes no data.
    pub fn new(proto: Proto) -> Arc<Self> {
        let sock = Arc::new(Self {
            proto,
            ino: rk_net::next_ino(),
            state: SpinLock::new(State {
                local: ipv4::ANY,
                port: 0,
                addr_locked: false,
                remote: None,
                queue: VecDeque::new(),
                queued: 0,
                error: None,
                options: Options::default(),
                ttl: None,
                tos: 0,
                recverr: false,
                hdrincl: proto == Proto::Raw(IPPROTO_RAW as u8),
                mtu_discover: 0,
                multicast_ttl: 1,
                multicast_loop: true,
                filter: 0,
                shut_rd: false,
                shut_wr: false,
                closed: false,
            }),
            wait: WaitQueue::default(),
            events: AtomicU64::new(0),
        });
        stack::add_socket(sock.ino, &sock);
        sock
    }

    /// The kind of the socket.
    pub fn proto(&self) -> Proto {
        self.proto
    }

    fn ports(&self) -> Option<&'static SpinLock<Ports>> {
        match self.proto {
            Proto::Udp => Some(&UDP_PORTS),
            Proto::Ping => Some(&PING_PORTS),
            Proto::Raw(_) | Proto::Tcp => None,
        }
    }

    fn wake(&self) {
        self.events.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
        poll_wake();
    }

    /// The score of the socket for a packet from `src` and `sport`, or `None` if the socket
    /// has another peer. A socket with this peer wins over a socket without a peer.
    pub(crate) fn score(&self, src: Addr, sport: u16) -> Option<u32> {
        let s = self.state.lock();
        if s.closed {
            return None;
        }
        match s.remote {
            None => Some(0),
            Some((a, p)) if a == src && (p == sport || self.proto == Proto::Ping) => Some(2),
            Some(_) => None,
        }
    }

    /// Puts a datagram in the receive queue, as `__udp_queue_rcv_skb` of Linux. Gives `false`
    /// if the socket dropped it: a full receive buffer or a shut down socket.
    pub(crate) fn deliver(&self, src: Addr, port: u16, data: Vec<u8>) -> bool {
        let mut s = self.state.lock();
        if s.closed || s.shut_rd || s.queued > s.options.rcvbuf as usize {
            return false;
        }
        s.queued += data.len() + OVERHEAD;
        s.queue.push_back(Datagram { src, port, data });
        drop(s);
        self.wake();
        true
    }

    /// Gives a copy of a packet to a raw socket, as `raw_v4_input` of Linux. `packet` has the
    /// IPv4 header.
    pub(crate) fn deliver_raw(&self, h: &Header, packet: &[u8]) {
        {
            let s = self.state.lock();
            if s.local != ipv4::ANY && s.local != h.dst {
                return;
            }
            if s.remote.is_some_and(|(a, _)| a != h.src) {
                return;
            }
            if h.protocol == PROTO_ICMP
                && let Some(&t) = packet.get(h.hlen)
                && t < 32
                && s.filter & (1 << t) != 0
            {
                return;
            }
        }
        self.deliver(h.src, 0, packet.to_vec());
    }

    /// Records an error from an ICMP message about a packet to `dst`, as `udp_err` of Linux.
    /// Without `IP_RECVERR`, only a hard error on a connected socket counts.
    pub(crate) fn icmp_error(&self, err: Errno, hard: bool, dst: Addr) {
        let mut s = self.state.lock();
        let connected = s.remote.is_some_and(|(a, _)| a == dst);
        if !s.recverr && !(hard && connected) {
            return;
        }
        s.error = Some(err);
        drop(s);
        self.wake();
    }

    /// Gives the socket a port or an identifier if it has none, as `inet_autobind` of Linux.
    fn autobind(&self, s: &mut State) -> Result<()> {
        let Some(table) = self.ports() else { return Ok(()) };
        if s.port != 0 {
            return Ok(());
        }
        let reuse = s.options.get(SO_REUSEADDR).is_ok_and(|v| v != int(0));
        s.port = table.lock().bind(0, Binding { addr: s.local, reuse, id: self.ino })?;
        Ok(())
    }

    /// Checks that `dst` can take a packet from this socket, and gives the route.
    fn route_to(&self, s: &State, dst: Addr) -> Result<crate::route::Next> {
        let next = stack::route(dst)?;
        if next.broadcast && s.options.get(SO_BROADCAST).is_ok_and(|v| v == int(0)) {
            return Err(Errno::EACCES);
        }
        Ok(next)
    }

    fn out(&self, s: &State, src: Addr, dst: Addr, protocol: u8) -> Out {
        let ttl = if ipv4::is_multicast(dst) {
            s.multicast_ttl as u8
        } else {
            s.ttl.unwrap_or(ipv4::DEFAULT_TTL)
        };
        Out { src, dst, protocol, ttl, tos: s.tos }
    }

    /// Sends `data` to `dst` and `dport`. The caller holds the state.
    fn send_to(&self, s: &mut State, dst: Addr, dport: u16, data: &[u8]) -> Result<()> {
        // A destination of 0.0.0.0 is the local host, as `ip_route_output_key_hash` of Linux.
        let dst = if dst == ipv4::ANY { ipv4::LOOPBACK } else { dst };
        match self.proto {
            Proto::Udp => {
                if dport == 0 {
                    return Err(Errno::EINVAL);
                }
                if data.len() > ipv4::MAX_LEN - HLEN - UDP_HLEN {
                    return Err(Errno::EMSGSIZE);
                }
                let next = self.route_to(s, dst)?;
                self.autobind(s)?;
                let src = if s.local == ipv4::ANY { next.src } else { s.local };
                let len = (UDP_HLEN + data.len()) as u16;
                let mut d = Vec::with_capacity(usize::from(len));
                d.extend_from_slice(
                    &UdpHeader { src: s.port, dst: dport, len, check: 0 }.to_bytes(),
                );
                d.extend_from_slice(data);
                let check = checksum::udp(src, dst, &d);
                d[6..8].copy_from_slice(&check.to_be_bytes());
                stack::output(&next, &self.out(s, src, dst, PROTO_UDP), &d)
            }
            Proto::Ping => {
                // The message is an echo request with its ICMP header, as `ping_v4_sendmsg`.
                if data.len() < 8 || data[0] != ICMP_ECHO || data[1] != 0 {
                    return Err(Errno::EINVAL);
                }
                if data.len() > ipv4::MAX_LEN - HLEN {
                    return Err(Errno::EMSGSIZE);
                }
                let next = self.route_to(s, dst)?;
                self.autobind(s)?;
                let src = if s.local == ipv4::ANY { next.src } else { s.local };
                let mut d = data.to_vec();
                d[2..4].fill(0);
                d[4..6].copy_from_slice(&s.port.to_be_bytes());
                let sum = checksum::checksum(&d);
                d[2..4].copy_from_slice(&sum.to_be_bytes());
                stack::output(&next, &self.out(s, src, dst, PROTO_ICMP), &d)
            }
            Proto::Raw(protocol) => {
                if s.hdrincl {
                    return self.send_hdrincl(s, data);
                }
                if data.len() > ipv4::MAX_LEN - HLEN {
                    return Err(Errno::EMSGSIZE);
                }
                let next = self.route_to(s, dst)?;
                let src = if s.local == ipv4::ANY { next.src } else { s.local };
                stack::output(&next, &self.out(s, src, dst, protocol), data)
            }
            Proto::Tcp => Err(Errno::EOPNOTSUPP),
        }
    }

    /// Sends a packet that has its own IPv4 header, as `raw_send_hdrinc` of Linux. The kernel
    /// sets the total length, the checksum, and a zero source and identification.
    fn send_hdrincl(&self, s: &State, data: &[u8]) -> Result<()> {
        let h = Header::parse_loose(data).ok_or(Errno::EINVAL)?;
        if data.len() > ipv4::MAX_LEN {
            return Err(Errno::EMSGSIZE);
        }
        let next = self.route_to(s, h.dst)?;
        let mut p = data.to_vec();
        if h.src == ipv4::ANY {
            p[12..16].copy_from_slice(&next.src);
        }
        p[2..4].copy_from_slice(&(data.len() as u16).to_be_bytes());
        p[10..12].fill(0);
        let sum = checksum::checksum(&p[..h.hlen]);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        stack::output_raw(&next, &p)
    }

    fn take_error(&self) -> Result<()> {
        match self.state.lock().error.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn release_port(&self, s: &mut State) {
        if let Some(table) = self.ports()
            && s.port != 0
        {
            table.lock().unbind(s.port, self.ino);
        }
    }
}

impl Socket for Dgram {
    fn family(&self) -> u32 {
        AF_INET
    }

    fn kind(&self) -> u32 {
        match self.proto {
            Proto::Udp | Proto::Ping => SOCK_DGRAM,
            Proto::Raw(_) => SOCK_RAW,
            Proto::Tcp => SOCK_STREAM,
        }
    }

    fn protocol(&self) -> u32 {
        match self.proto {
            Proto::Udp => IPPROTO_UDP,
            Proto::Ping => IPPROTO_ICMP,
            Proto::Raw(p) => u32::from(p),
            Proto::Tcp => IPPROTO_TCP,
        }
    }

    fn ino(&self) -> u64 {
        self.ino
    }

    fn bind(&self, _paths: &dyn PathOps, addr: &[u8]) -> Result<()> {
        let (addr, port) = sockaddr::parse_bind(addr)?;
        let ok = {
            let routes = stack::ROUTES.lock();
            addr == ipv4::ANY
                || routes.is_local(addr)
                || (self.proto == Proto::Udp
                    && (routes.is_broadcast(addr) || ipv4::is_multicast(addr)))
        };
        if !ok {
            return Err(Errno::EADDRNOTAVAIL);
        }
        let mut s = self.state.lock();
        if s.port != 0 || (matches!(self.proto, Proto::Raw(_)) && s.addr_locked) {
            return Err(Errno::EINVAL);
        }
        if let Some(table) = self.ports() {
            let reuse = s.options.get(SO_REUSEADDR).is_ok_and(|v| v != int(0));
            s.port = table.lock().bind(port, Binding { addr, reuse, id: self.ino })?;
        }
        s.local = addr;
        s.addr_locked = addr != ipv4::ANY;
        Ok(())
    }

    fn connect(&self, _paths: &dyn PathOps, addr: &[u8], _nonblock: bool) -> Result<()> {
        let Some((dst, port)) = sockaddr::parse_connect(addr)? else {
            // `AF_UNSPEC` removes the peer, as `__udp_disconnect` of Linux.
            let mut s = self.state.lock();
            s.remote = None;
            if !s.addr_locked && s.local != ipv4::ANY {
                s.local = ipv4::ANY;
                if let Some(table) = self.ports() {
                    table.lock().set_addr(s.port, self.ino, ipv4::ANY);
                }
            }
            return Ok(());
        };
        let dst = if dst == ipv4::ANY { ipv4::LOOPBACK } else { dst };
        let mut s = self.state.lock();
        let next = self.route_to(&s, dst)?;
        self.autobind(&mut s)?;
        if s.local == ipv4::ANY {
            s.local = next.src;
            if let Some(table) = self.ports() {
                table.lock().set_addr(s.port, self.ino, next.src);
            }
        }
        s.remote = Some((dst, port));
        Ok(())
    }

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
        let to = match &msg.addr {
            Some(a) => sockaddr::parse_send(a)?,
            None => None,
        };
        self.take_error()?;
        {
            let mut s = self.state.lock();
            if s.shut_wr {
                return Err(Errno::EPIPE);
            }
            let (dst, port) = match to.or(s.remote) {
                Some(d) => d,
                None if matches!(self.proto, Proto::Raw(_)) && s.hdrincl => (ipv4::ANY, 0),
                None => return Err(Errno::EDESTADDRREQ),
            };
            self.send_to(&mut s, dst, port, &msg.data)?;
        }
        // The packet on the loopback device arrives now, as `netif_rx` and the softirq on the
        // return of Linux.
        stack::poll_now();
        Ok(msg.data.len())
    }

    fn recv(&self, len: usize, flags: u32, nonblock: bool) -> Result<Received> {
        if flags & MSG_OOB != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        if flags & MSG_ERRQUEUE != 0 {
            return Err(Errno::EAGAIN);
        }
        stack::poll();
        let nonblock = nonblock || flags & MSG_DONTWAIT != 0;
        let cond = || -> Result<Option<Received>> {
            let mut s = self.state.lock();
            if let Some(e) = s.error.take() {
                return Err(e);
            }
            let d = if flags & MSG_PEEK != 0 {
                s.queue.front().map(|d| (d.src, d.port, d.data.clone()))
            } else {
                let d = s.queue.pop_front();
                if let Some(d) = &d {
                    s.queued -= d.data.len() + OVERHEAD;
                }
                d.map(|d| (d.src, d.port, d.data))
            };
            if let Some((src, port, mut data)) = d {
                let full = data.len();
                data.truncate(len);
                let trunc = if full > len { MSG_TRUNC } else { 0 };
                return Ok(Some(Received {
                    data,
                    len: full,
                    addr: Some(sockaddr::make(src, port)),
                    flags: trunc,
                    ..Received::default()
                }));
            }
            if s.shut_rd {
                return Ok(Some(Received::default()));
            }
            if nonblock {
                return Err(Errno::EAGAIN);
            }
            Ok(None)
        };
        let timeout = self.state.lock().options.rcvtimeo;
        wait_for(&self.wait, timeout, cond)
    }

    fn shutdown(&self, how: u32) -> Result<()> {
        if how > SHUT_RDWR {
            return Err(Errno::EINVAL);
        }
        let connected = {
            let mut s = self.state.lock();
            s.shut_rd |= how == SHUT_RD || how == SHUT_RDWR;
            s.shut_wr |= how == SHUT_WR || how == SHUT_RDWR;
            s.remote.is_some()
        };
        self.wake();
        // Linux sets the flags and gives `ENOTCONN` for a socket without a peer.
        if connected { Ok(()) } else { Err(Errno::ENOTCONN) }
    }

    fn name(&self) -> Vec<u8> {
        let s = self.state.lock();
        sockaddr::make(s.local, if matches!(self.proto, Proto::Raw(_)) { 0 } else { s.port })
    }

    fn peer_name(&self) -> Result<Vec<u8>> {
        let s = self.state.lock();
        let (a, p) = s.remote.ok_or(Errno::ENOTCONN)?;
        Ok(sockaddr::make(a, p))
    }

    fn get_option(&self, level: u32, name: u32) -> Result<Vec<u8>> {
        let mut s = self.state.lock();
        match level {
            SOL_SOCKET => Ok(match name {
                SO_TYPE => int(self.kind() as i32),
                SO_DOMAIN => int(AF_INET as i32),
                SO_PROTOCOL => int(self.protocol() as i32),
                SO_ERROR => int(s.error.take().map_or(0, |e| i32::from(e.get()))),
                SO_ACCEPTCONN => int(0),
                SO_COOKIE => self.ino.to_ne_bytes().to_vec(),
                SO_BINDTODEVICE => Vec::new(),
                _ => s.options.get(name)?,
            }),
            IPPROTO_IP => Ok(match name {
                IP_TTL => int(i32::from(s.ttl.unwrap_or(ipv4::DEFAULT_TTL))),
                IP_TOS => int(i32::from(s.tos)),
                IP_RECVERR => int(i32::from(s.recverr)),
                IP_HDRINCL => int(i32::from(s.hdrincl)),
                IP_MTU_DISCOVER => int(s.mtu_discover),
                IP_MULTICAST_TTL => int(s.multicast_ttl),
                IP_MULTICAST_LOOP => int(i32::from(s.multicast_loop)),
                _ => return Err(Errno::ENOPROTOOPT),
            }),
            SOL_RAW if self.proto == Proto::Raw(PROTO_ICMP) && name == ICMP_FILTER => {
                Ok(s.filter.to_ne_bytes().to_vec())
            }
            SOL_RAW if matches!(self.proto, Proto::Raw(_)) => Err(Errno::EOPNOTSUPP),
            _ => Err(Errno::ENOPROTOOPT),
        }
    }

    fn set_option(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
        let mut s = self.state.lock();
        match level {
            SOL_SOCKET => match name {
                SO_TYPE | SO_DOMAIN | SO_PROTOCOL | SO_ERROR | SO_ACCEPTCONN | SO_COOKIE => {
                    return Err(Errno::ENOPROTOOPT);
                }
                SO_BINDTODEVICE => {
                    // Only the empty name, which removes the binding, is here.
                    if value.first().is_some_and(|&b| b != 0) {
                        return Err(Errno::ENODEV);
                    }
                }
                _ => s.options.set(name, value)?,
            },
            IPPROTO_IP => {
                let v = int_of(value)?;
                match name {
                    IP_TTL => {
                        s.ttl = match v {
                            -1 => None,
                            1..=255 => Some(v as u8),
                            _ => return Err(Errno::EINVAL),
                        };
                    }
                    IP_TOS => s.tos = v as u8,
                    IP_RECVERR => s.recverr = v != 0,
                    IP_HDRINCL if matches!(self.proto, Proto::Raw(_)) => s.hdrincl = v != 0,
                    IP_MTU_DISCOVER if (0..=5).contains(&v) => s.mtu_discover = v,
                    IP_MTU_DISCOVER => return Err(Errno::EINVAL),
                    IP_MULTICAST_TTL => {
                        s.multicast_ttl = match v {
                            -1 => 1,
                            0..=255 => v,
                            _ => return Err(Errno::EINVAL),
                        };
                    }
                    IP_MULTICAST_LOOP => s.multicast_loop = v != 0,
                    _ => return Err(Errno::ENOPROTOOPT),
                }
            }
            SOL_RAW if self.proto == Proto::Raw(PROTO_ICMP) && name == ICMP_FILTER => {
                // Linux copies at most 4 bytes over the old mask, as `raw_seticmpfilter`.
                let mut v = s.filter.to_ne_bytes();
                let n = value.len().min(4);
                v[..n].copy_from_slice(&value[..n]);
                s.filter = u32::from_ne_bytes(v);
            }
            SOL_RAW if matches!(self.proto, Proto::Raw(_)) => return Err(Errno::EOPNOTSUPP),
            _ => return Err(Errno::ENOPROTOOPT),
        }
        drop(s);
        self.wake();
        Ok(())
    }

    fn poll(&self) -> u32 {
        let s = self.state.lock();
        let mut mask = POLLOUT | POLLWRNORM | POLLWRBAND;
        if s.error.is_some() {
            mask |= POLLERR;
        }
        if !s.queue.is_empty() {
            mask |= POLLIN | POLLRDNORM;
        }
        if s.shut_rd {
            mask |= POLLRDHUP | POLLIN | POLLRDNORM;
        }
        if s.shut_rd && s.shut_wr {
            mask |= POLLHUP;
        }
        mask
    }

    fn event_count(&self) -> u64 {
        self.events.load(Ordering::Relaxed)
    }

    fn readable(&self) -> Result<usize> {
        // `FIONREAD` on a datagram socket gives the size of the next datagram, as Linux.
        Ok(self.state.lock().queue.front().map_or(0, |d| d.data.len()))
    }

    fn release(&self) {
        let mut s = self.state.lock();
        s.closed = true;
        self.release_port(&mut s);
        s.queue.clear();
        drop(s);
        stack::remove_socket(self.ino);
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

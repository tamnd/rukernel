//! The datagram sockets of IPv4 and IPv6: UDP sockets, ICMP echo sockets and raw sockets, as
//! net/ipv4/udp.c, net/ipv4/ping.c, net/ipv4/raw.c, net/ipv6/udp.c, net/ipv6/ping.c and
//! net/ipv6/raw.c of Linux.
//!
//! The three kinds share one type, because they differ only in the header that a send adds and
//! in the table that finds the socket for a received packet. A UDP socket has a port in
//! `UDP_PORTS`. An echo socket has an identifier in `PING_PORTS`, and a send puts it in the
//! echo request. A raw socket takes a copy of each packet of its protocol and its family.
//!
//! A socket keeps its addresses as `ip::Ip`: an IPv4 address is IPv4-mapped. An `AF_INET6` UDP
//! socket without `IPV6_V6ONLY` sends and takes IPv4 datagrams too, as on Linux.

use crate::ip::{self, Ip};
use crate::ipv4::{self, Addr, HLEN, Header, PROTO_ICMP, PROTO_UDP, UDP_HLEN, UdpHeader};
use crate::ipv6::{self, PROTO_ICMPV6};
use crate::ports::{Binding, Ports};
use crate::stack::{self, Out, PING_PORTS, UDP_PORTS};
use crate::stack6::{self, COUNTERS6, Out6};
use crate::{checksum, sockaddr};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::icmpv6::{ICMPV6_ECHO_REQUEST, ICMPV6_FILTER};
use rk_abi::native::in6::{
    IPV6_2292DSTOPTS, IPV6_2292HOPLIMIT, IPV6_2292HOPOPTS, IPV6_2292PKTINFO, IPV6_2292RTHDR,
    IPV6_ADDR_PREFERENCES, IPV6_AUTOFLOWLABEL, IPV6_CHECKSUM, IPV6_DONTFRAG, IPV6_FLOWINFO,
    IPV6_FLOWINFO_SEND, IPV6_FREEBIND, IPV6_HDRINCL, IPV6_HOPLIMIT, IPV6_MINHOPCOUNT, IPV6_MTU,
    IPV6_MTU_DISCOVER, IPV6_MULTICAST_ALL, IPV6_MULTICAST_HOPS, IPV6_MULTICAST_IF,
    IPV6_MULTICAST_LOOP, IPV6_PKTINFO, IPV6_PMTUDISC_OMIT, IPV6_RECVDSTOPTS, IPV6_RECVERR,
    IPV6_RECVERR_RFC4884, IPV6_RECVFRAGSIZE, IPV6_RECVHOPLIMIT, IPV6_RECVHOPOPTS,
    IPV6_RECVORIGDSTADDR, IPV6_RECVPATHMTU, IPV6_RECVPKTINFO, IPV6_RECVRTHDR, IPV6_RECVTCLASS,
    IPV6_ROUTER_ALERT_ISOLATE, IPV6_TCLASS, IPV6_TRANSPARENT, IPV6_UNICAST_HOPS, IPV6_UNICAST_IF,
    IPV6_V6ONLY,
};
use rk_abi::native::inet::{
    IP_HDRINCL, IP_MTU_DISCOVER, IP_MULTICAST_LOOP, IP_MULTICAST_TTL, IP_RECVERR, IP_TOS, IP_TTL,
    IPPROTO_ICMP, IPPROTO_IP, IPPROTO_IPV6, IPPROTO_RAW, IPPROTO_TCP, IPPROTO_UDP,
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
    AF_INET, AF_INET6, ICMP_ECHO, ICMP_FILTER, MSG_DONTWAIT, MSG_ERRQUEUE, MSG_OOB, MSG_PEEK,
    MSG_TRUNC, SHUT_RD, SHUT_RDWR, SHUT_WR, SOCK_DGRAM, SOCK_RAW, SOCK_STREAM, SOL_RAW,
};
use rk_net::{Message, Options, PathOps, Received, Socket, wait_for};
use rk_vfs::UserMemory;
use rk_vfs::inode::Result;
use rk_vfs::wait::{PollTable, WaitQueue};

/// The control messages of a received IPv6 datagram that the flags of `s` ask for, in the order
/// of `ip6_datagram_recv_ctl` of Linux.
fn control6(s: &State, i: &Info6) -> Vec<(u32, u32, Vec<u8>)> {
    let on = |name| s.flags6.get(&name).is_some_and(|&v| v != 0);
    let pktinfo = || {
        // `struct in6_pktinfo`: the address and the interface index.
        let mut v = i.dst.to_vec();
        v.extend_from_slice(&i.ifindex.to_ne_bytes());
        v
    };
    let mut out = Vec::new();
    if on(IPV6_RECVPKTINFO) {
        out.push((IPPROTO_IPV6, IPV6_PKTINFO, pktinfo()));
    }
    if on(IPV6_RECVHOPLIMIT) {
        out.push((IPPROTO_IPV6, IPV6_HOPLIMIT, i32::from(i.hops).to_ne_bytes().to_vec()));
    }
    if on(IPV6_RECVTCLASS) {
        out.push((IPPROTO_IPV6, IPV6_TCLASS, i32::from(i.tclass).to_ne_bytes().to_vec()));
    }
    if on(IPV6_2292PKTINFO) {
        out.push((IPPROTO_IPV6, IPV6_2292PKTINFO, pktinfo()));
    }
    if on(IPV6_2292HOPLIMIT) {
        out.push((IPPROTO_IPV6, IPV6_2292HOPLIMIT, i32::from(i.hops).to_ne_bytes().to_vec()));
    }
    out
}

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

/// Gives the kind of an `AF_INET6` socket for the arguments `type` and `protocol` of `socket`,
/// as `inet6_create` of Linux. `SOCK_DGRAM` with `IPPROTO_ICMPV6` is an echo socket. The
/// caller checks the permissions as for `classify`.
///
/// # Errors
///
/// Gives the errors of `classify`.
pub fn classify6(kind: u32, protocol: u32) -> Result<Proto> {
    match (kind, protocol) {
        (SOCK_DGRAM, SOL_ICMPV6) => Ok(Proto::Ping),
        (SOCK_DGRAM, IPPROTO_ICMP) => Err(Errno::EPROTONOSUPPORT),
        _ => classify(kind, protocol),
    }
}

/// Makes an `AF_INET6` socket of the kind `proto`.
pub fn new_socket6(proto: Proto) -> Arc<dyn Socket> {
    match proto {
        Proto::Tcp => crate::tcp::Stream::new6(),
        _ => Dgram::new6(proto),
    }
}

/// The level of the options of ICMPv6, `SOL_ICMPV6` of Linux. It is the protocol number, and
/// rk-abigen does not give `IPPROTO_ICMPV6`.
const SOL_ICMPV6: u32 = PROTO_ICMPV6 as u32;
/// The option `ICMP6_FILTER` of the level `SOL_ICMPV6`, `ICMPV6_FILTER` of Linux.
const ICMP6_FILTER: u32 = ICMPV6_FILTER;
/// The type of an ICMPv6 echo request.
const ECHO_REQUEST6: u8 = ICMPV6_ECHO_REQUEST as u8;

/// The bytes that a datagram in the receive queue costs more than its data, in place of the
/// `truesize` of a Linux packet buffer.
const OVERHEAD: usize = 256;

/// A received datagram.
struct Datagram {
    src: Ip,
    /// The interface of a link local source, for `sin6_scope_id`.
    scope: u32,
    port: u16,
    data: Vec<u8>,
    /// The IPv6 header of the datagram, for the control messages.
    info: Option<Info6>,
}

/// The fields of the IPv6 header of a received datagram that the control messages of
/// `IPV6_RECVPKTINFO`, `IPV6_RECVHOPLIMIT` and `IPV6_RECVTCLASS` give, as
/// `ip6_datagram_recv_ctl` of Linux.
#[derive(Clone, Copy)]
pub(crate) struct Info6 {
    /// The destination address.
    pub dst: Ip,
    /// The interface that took the packet.
    pub ifindex: u32,
    /// The hop limit.
    pub hops: u8,
    /// The traffic class.
    pub tclass: u8,
}

impl Info6 {
    /// The fields of `h`, a packet that came in on `ifindex`.
    pub(crate) fn of(h: &ipv6::Header, ifindex: u32) -> Self {
        Self { dst: h.dst, ifindex, hops: h.hops, tclass: h.tclass }
    }
}

struct State {
    /// The local address, or `0.0.0.0` or `::`.
    local: Ip,
    /// The port or the echo identifier, or 0 if the socket has none yet.
    port: u16,
    /// The address came from `bind`, so `connect` does not change it.
    addr_locked: bool,
    /// The peer of `connect`.
    remote: Option<(Ip, u16)>,
    /// The interface of the socket, from the scope ID of `bind` or `connect`, or 0.
    oif: u32,
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
    /// `IPV6_V6ONLY`: the socket takes no IPv4 packets.
    v6only: bool,
    /// `IPV6_UNICAST_HOPS`, or `None` for the default.
    hops: Option<u8>,
    /// `IPV6_MULTICAST_HOPS`.
    mc_hops: i32,
    /// `IPV6_TCLASS`.
    tclass: u8,
    /// `IPV6_CHECKSUM`: the offset of the checksum in a raw packet, or -1.
    checksum: i32,
    /// `IPV6_MTU`, or 0.
    mtu6: i32,
    /// `ICMP6_FILTER`: a bit for each ICMPv6 type to drop.
    filter6: [u32; 8],
    /// The other options of the level `IPPROTO_IPV6`, which change nothing in the stack.
    flags6: BTreeMap<u32, i32>,
    shut_rd: bool,
    shut_wr: bool,
    closed: bool,
}

/// A socket of /proc/net/udp, /proc/net/icmp or /proc/net/raw.
pub(crate) struct SockLine {
    /// The family of the socket.
    pub family: u32,
    /// The local address, and the port, the echo identifier or the protocol.
    pub local: (Ip, u16),
    /// The address and the port of the peer, or the wildcard and 0.
    pub remote: (Ip, u16),
    /// The socket has a peer: the state `TCP_ESTABLISHED`, else `TCP_CLOSE`.
    pub connected: bool,
    /// The bytes that the receive queue costs.
    pub rx_queue: usize,
    /// The owner.
    pub uid: u32,
    /// The inode number.
    pub ino: u64,
    /// The datagrams that the socket dropped.
    pub drops: u32,
}

/// A datagram socket of IPv4 or IPv6.
pub struct Dgram {
    /// `AF_INET` or `AF_INET6`.
    family: u32,
    proto: Proto,
    ino: u64,
    /// The owner, the file system user ID of the creator as `sk_uid` of Linux.
    uid: u32,
    /// The datagrams that the socket dropped, `sk_drops` of Linux.
    drops: AtomicU32,
    state: SpinLock<State>,
    wait: Arc<WaitQueue>,
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
        Self::make(AF_INET, proto)
    }

    /// Makes an `AF_INET6` socket of the kind `proto`. An echo socket takes only ICMPv6, as
    /// `ping_lookup` of Linux.
    pub fn new6(proto: Proto) -> Arc<Self> {
        Self::make(AF_INET6, proto)
    }

    fn make(family: u32, proto: Proto) -> Arc<Self> {
        let v6 = family == AF_INET6;
        let sock = Arc::new(Self {
            family,
            proto,
            ino: rk_net::next_ino(),
            uid: rk_vfs::cred::current().fsuid,
            drops: AtomicU32::new(0),
            state: SpinLock::new(State {
                local: if v6 { ip::ANY } else { ip::V4_ANY },
                port: 0,
                addr_locked: false,
                remote: None,
                oif: 0,
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
                v6only: v6 && proto == Proto::Ping,
                hops: None,
                mc_hops: 1,
                tclass: 0,
                checksum: -1,
                mtu6: 0,
                filter6: [0; 8],
                flags6: BTreeMap::new(),
                shut_rd: false,
                shut_wr: false,
                closed: false,
            }),
            wait: Arc::new(WaitQueue::new()),
            events: AtomicU64::new(0),
        });
        stack::add_socket(sock.ino, &sock);
        sock
    }

    /// The kind of the socket.
    pub fn proto(&self) -> Proto {
        self.proto
    }

    /// The family of the socket: `AF_INET` or `AF_INET6`.
    pub fn family(&self) -> u32 {
        self.family
    }

    /// The wildcard address of the family of the socket.
    fn any(&self) -> Ip {
        if self.family == AF_INET6 { ip::ANY } else { ip::V4_ANY }
    }

    /// The values for a line of /proc/net/udp, /proc/net/icmp or /proc/net/raw, or `None` if
    /// the socket is not in the table of its protocol: a closed socket, or a UDP or echo socket
    /// without a port.
    pub(crate) fn proc_line(&self) -> Option<SockLine> {
        let s = self.state.lock();
        let port = match self.proto {
            Proto::Raw(p) => u16::from(p),
            _ if s.port == 0 => return None,
            _ => s.port,
        };
        if s.closed {
            return None;
        }
        let remote = match (self.proto, s.remote) {
            (Proto::Raw(_), Some((a, _))) => (a, 0),
            (_, r) => r.unwrap_or((self.any(), 0)),
        };
        Some(SockLine {
            family: self.family,
            local: (s.local, port),
            remote,
            connected: s.remote.is_some(),
            rx_queue: s.queued,
            uid: self.uid,
            ino: self.ino,
            drops: self.drops.load(Ordering::Relaxed),
        })
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
    }

    /// The score of the socket for a packet from `src` and `sport`, or `None` if the socket
    /// has another peer. A socket with this peer wins over a socket without a peer.
    pub(crate) fn score(&self, src: &Ip, sport: u16) -> Option<u32> {
        let s = self.state.lock();
        if s.closed {
            return None;
        }
        match s.remote {
            None => Some(0),
            Some((a, p)) if a == *src && (p == sport || self.proto == Proto::Ping) => Some(2),
            Some(_) => None,
        }
    }

    /// Puts a datagram in the receive queue, as `__udp_queue_rcv_skb` of Linux. Gives `false`
    /// if the socket dropped it: a full receive buffer or a shut down socket.
    /// `scope` is the interface of a link local source, and `info` has the IPv6 header.
    pub(crate) fn deliver(
        &self,
        src: Ip,
        scope: u32,
        port: u16,
        data: Vec<u8>,
        info: Option<Info6>,
    ) -> bool {
        let mut s = self.state.lock();
        if s.closed || s.shut_rd || s.queued > s.options.rcvbuf as usize {
            self.drops.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        s.queued += data.len() + OVERHEAD;
        s.queue.push_back(Datagram { src, scope, port, data, info });
        drop(s);
        self.wake();
        true
    }

    /// Gives a copy of a packet to a raw socket, as `raw_v4_input` of Linux. `packet` has the
    /// IPv4 header.
    pub(crate) fn deliver_raw(&self, h: &Header, packet: &[u8]) {
        let (src, dst) = (ip::mapped(h.src), ip::mapped(h.dst));
        {
            let s = self.state.lock();
            if !ip::is_any(&s.local) && s.local != dst {
                return;
            }
            if s.remote.is_some_and(|(a, _)| a != src) {
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
        self.deliver(src, 0, 0, packet.to_vec(), None);
    }

    /// Gives a copy of an IPv6 packet to a raw socket, as `ipv6_raw_deliver` and
    /// `icmpv6_filter` of Linux. `payload` is the packet after the IPv6 headers, which is
    /// what an IPv6 raw socket reads. The packet came in on `ifindex`.
    pub(crate) fn deliver_raw6(&self, h: &ipv6::Header, ifindex: u32, payload: &[u8]) {
        let scope = stack6::scope_of(&h.src, ifindex);
        {
            let s = self.state.lock();
            if !ip::is_any(&s.local) && s.local != h.dst {
                return;
            }
            if s.remote.is_some_and(|(a, _)| a != h.src) {
                return;
            }
            if s.oif != 0 && scope != 0 && s.oif != scope {
                return;
            }
            if h.protocol == PROTO_ICMPV6
                && let Some(&t) = payload.first()
                && s.filter6[usize::from(t >> 5)] & (1 << (t & 31)) != 0
            {
                return;
            }
        }
        self.deliver(h.src, scope, 0, payload.to_vec(), Some(Info6::of(h, ifindex)));
    }

    /// Records an error from an ICMP message about a packet to `dst`, as `udp_err` of Linux.
    /// Without `IP_RECVERR`, only a hard error on a connected socket counts.
    pub(crate) fn icmp_error(&self, err: Errno, hard: bool, dst: Ip) {
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
        let b = Binding { addr: s.local, reuse, id: self.ino, v6only: s.v6only };
        s.port = table.lock().bind(0, b)?;
        Ok(())
    }

    /// The local IPv4 address, or `0.0.0.0`.
    fn local4(s: &State) -> Addr {
        ip::v4(&s.local).unwrap_or(ipv4::ANY)
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

    /// Sends `data` to `dst` and `dport`, and `scope` is the interface of a link local
    /// destination. The caller holds the state.
    fn send_to(&self, s: &mut State, dst: Ip, dport: u16, scope: u32, data: &[u8]) -> Result<()> {
        let Some(d4) = ip::v4(&dst) else {
            if self.family == AF_INET || ip::v4(&s.local).is_some_and(|a| a != ipv4::ANY) {
                return Err(Errno::ENETUNREACH);
            }
            // A destination of `::` is the local host, as `udpv6_sendmsg` of Linux.
            let dst = if dst == ip::ANY { ip::LOOPBACK } else { dst };
            return self.send6(s, dst, dport, scope, data);
        };
        if self.family == AF_INET6 {
            // Only UDP of IPv6 sends to an IPv4-mapped address, as `udpv6_sendmsg`.
            if self.proto != Proto::Udp {
                return Err(Errno::EINVAL);
            }
            if s.v6only || (ip::v4(&s.local).is_none() && s.local != ip::ANY) {
                return Err(Errno::ENETUNREACH);
            }
        }
        self.send4(s, d4, dport, data)
    }

    /// Sends `data` to the IPv4 address `dst` and `dport`.
    fn send4(&self, s: &mut State, dst: Addr, dport: u16, data: &[u8]) -> Result<()> {
        // A destination of 0.0.0.0 is the local host, as `ip_route_output_key_hash` of Linux.
        let dst = if dst == ipv4::ANY { ipv4::LOOPBACK } else { dst };
        let local = Self::local4(s);
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
                let src = if local == ipv4::ANY { next.src } else { local };
                let len = (UDP_HLEN + data.len()) as u16;
                let mut d = Vec::with_capacity(usize::from(len));
                d.extend_from_slice(
                    &UdpHeader { src: s.port, dst: dport, len, check: 0 }.to_bytes(),
                );
                d.extend_from_slice(data);
                let check = checksum::udp(src, dst, &d);
                d[6..8].copy_from_slice(&check.to_be_bytes());
                stack::output(&next, &self.out(s, src, dst, PROTO_UDP), &d)?;
                stack::count(&stack::COUNTERS.udp_out);
                Ok(())
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
                let src = if local == ipv4::ANY { next.src } else { local };
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
                let src = if local == ipv4::ANY { next.src } else { local };
                stack::output(&next, &self.out(s, src, dst, protocol), data)
            }
            Proto::Tcp => Err(Errno::EOPNOTSUPP),
        }
    }

    /// Sends `data` to the IPv6 address `dst` and `dport`, as `udpv6_sendmsg`,
    /// `ping_v6_sendmsg` and `rawv6_sendmsg` of Linux.
    fn send6(&self, s: &mut State, dst: Ip, dport: u16, scope: u32, data: &[u8]) -> Result<()> {
        let max = usize::from(u16::MAX);
        let oif = if scope != 0 { scope } else { s.oif };
        if let Proto::Raw(_) = self.proto
            && s.hdrincl
        {
            return self.send_hdrincl6(s, oif, data);
        }
        let next = stack6::route(&dst, oif)?;
        let src = if ip::is_any(&s.local) { next.src } else { s.local };
        let hops = if ipv6::is_multicast(&dst) {
            s.mc_hops as u8
        } else {
            s.hops.unwrap_or(ipv6::DEFAULT_HOPS)
        };
        let out = |next| Out6 { src, dst, next, hops, tclass: s.tclass };
        match self.proto {
            Proto::Udp => {
                if dport == 0 {
                    return Err(Errno::EINVAL);
                }
                if data.len() > max - UDP_HLEN {
                    return Err(Errno::EMSGSIZE);
                }
                let out = out(PROTO_UDP);
                self.autobind(s)?;
                let len = (UDP_HLEN + data.len()) as u16;
                let mut d = Vec::with_capacity(usize::from(len));
                d.extend_from_slice(
                    &UdpHeader { src: s.port, dst: dport, len, check: 0 }.to_bytes(),
                );
                d.extend_from_slice(data);
                // A checksum of 0 means none, so 0 goes out as 0xffff, as `udp_v6_send_skb`.
                let check = match checksum::upper(&src, &dst, PROTO_UDP, &d) {
                    0 => 0xffff,
                    c => c,
                };
                d[6..8].copy_from_slice(&check.to_be_bytes());
                stack6::output(&next, &out, &d)?;
                stack::count(&COUNTERS6.udp_out);
                Ok(())
            }
            Proto::Ping => {
                if data.len() < 8 || data[0] != ECHO_REQUEST6 || data[1] != 0 {
                    return Err(Errno::EINVAL);
                }
                if data.len() > max {
                    return Err(Errno::EMSGSIZE);
                }
                let out = out(PROTO_ICMPV6);
                self.autobind(s)?;
                let mut d = data.to_vec();
                d[2..4].fill(0);
                d[4..6].copy_from_slice(&s.port.to_be_bytes());
                let sum = checksum::upper(&src, &dst, PROTO_ICMPV6, &d);
                d[2..4].copy_from_slice(&sum.to_be_bytes());
                stack6::output(&next, &out, &d)
            }
            Proto::Raw(protocol) => {
                if data.len() > max {
                    return Err(Errno::EMSGSIZE);
                }
                let mut d = data.to_vec();
                // ICMPv6 always has its checksum at the offset 2, as `rawv6_init_sk`.
                let at = if protocol == PROTO_ICMPV6 { 2 } else { s.checksum };
                if let Ok(at) = usize::try_from(at) {
                    if at + 2 > d.len() {
                        return Err(Errno::EINVAL);
                    }
                    d[at..at + 2].fill(0);
                    let sum = checksum::upper(&src, &dst, protocol, &d);
                    d[at..at + 2].copy_from_slice(&sum.to_be_bytes());
                }
                stack6::output(&next, &out(protocol), &d)
            }
            Proto::Tcp => Err(Errno::EOPNOTSUPP),
        }
    }

    /// Sends a packet that has its own IPv6 header, as `rawv6_send_hdrinc` of Linux. The
    /// kernel sets a source of `::`.
    fn send_hdrincl6(&self, _s: &State, oif: u32, data: &[u8]) -> Result<()> {
        let h = ipv6::Header::parse_loose(data).ok_or(Errno::EINVAL)?;
        let next = stack6::route(&h.dst, oif)?;
        let mut p = data.to_vec();
        if h.src == ip::ANY {
            p[8..24].copy_from_slice(&next.src);
        }
        stack6::output_raw(&next, &p)
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

    /// An option of the level `IPPROTO_IPV6`, as `do_ipv6_getsockopt` and
    /// `do_rawv6_getsockopt` of Linux.
    fn get_option6(&self, s: &State, name: u32) -> Result<Vec<u8>> {
        let raw = matches!(self.proto, Proto::Raw(_));
        Ok(int(match name {
            IPV6_V6ONLY => i32::from(s.v6only),
            IPV6_UNICAST_HOPS => i32::from(s.hops.unwrap_or(ipv6::DEFAULT_HOPS)),
            IPV6_MULTICAST_HOPS => s.mc_hops,
            IPV6_MULTICAST_LOOP => i32::from(s.multicast_loop),
            IPV6_TCLASS => i32::from(s.tclass),
            IPV6_RECVERR => i32::from(s.recverr),
            IPV6_MTU_DISCOVER => s.mtu_discover,
            IPV6_HDRINCL if raw => i32::from(s.hdrincl),
            IPV6_CHECKSUM if self.proto == Proto::Raw(PROTO_ICMPV6) => 2,
            IPV6_CHECKSUM if raw => s.checksum,
            IPV6_MTU => {
                let (dst, _) = s.remote.ok_or(Errno::ENOTCONN)?;
                stack6::path(&dst, s.oif)?.mtu as i32
            }
            IPV6_MULTICAST_ALL | IPV6_AUTOFLOWLABEL => *s.flags6.get(&name).unwrap_or(&1),
            _ if Self::is_flag6(name) => *s.flags6.get(&name).unwrap_or(&0),
            _ => return Err(Errno::ENOPROTOOPT),
        }))
    }

    /// Tells if `name` is a flag of the level `IPPROTO_IPV6`. The stack keeps these flags, and
    /// uses only the flags of the control messages in `control6`.
    fn is_flag6(name: u32) -> bool {
        matches!(
            name,
            IPV6_RECVPKTINFO
                | IPV6_2292PKTINFO
                | IPV6_2292HOPLIMIT
                | IPV6_2292RTHDR
                | IPV6_2292HOPOPTS
                | IPV6_2292DSTOPTS
                | IPV6_RECVHOPLIMIT
                | IPV6_RECVTCLASS
                | IPV6_RECVRTHDR
                | IPV6_RECVHOPOPTS
                | IPV6_RECVDSTOPTS
                | IPV6_RECVPATHMTU
                | IPV6_RECVORIGDSTADDR
                | IPV6_RECVFRAGSIZE
                | IPV6_RECVERR_RFC4884
                | IPV6_DONTFRAG
                | IPV6_FREEBIND
                | IPV6_TRANSPARENT
                | IPV6_MULTICAST_ALL
                | IPV6_AUTOFLOWLABEL
                | IPV6_ADDR_PREFERENCES
                | IPV6_MINHOPCOUNT
                | IPV6_FLOWINFO
                | IPV6_FLOWINFO_SEND
                | IPV6_ROUTER_ALERT_ISOLATE
                | IPV6_UNICAST_IF
                | IPV6_MULTICAST_IF
        )
    }

    /// Sets an option of the level `IPPROTO_IPV6`, as `do_ipv6_setsockopt` and
    /// `do_rawv6_setsockopt` of Linux.
    fn set_option6(&self, s: &mut State, name: u32, value: &[u8]) -> Result<()> {
        let v = int_of(value)?;
        let raw = matches!(self.proto, Proto::Raw(_));
        let hops = |v: i32| if (-1..=255).contains(&v) { Ok(v) } else { Err(Errno::EINVAL) };
        match name {
            // A socket with a port or a raw socket keeps its family, as Linux.
            IPV6_V6ONLY if raw || s.port != 0 => return Err(Errno::EINVAL),
            IPV6_V6ONLY => s.v6only = v != 0,
            IPV6_UNICAST_HOPS => s.hops = u8::try_from(hops(v)?).ok(),
            IPV6_MULTICAST_HOPS => s.mc_hops = if hops(v)? == -1 { 1 } else { v },
            IPV6_MULTICAST_LOOP => s.multicast_loop = v != 0,
            IPV6_TCLASS if (-1..=255).contains(&v) => s.tclass = v.max(0) as u8,
            IPV6_TCLASS => return Err(Errno::EINVAL),
            IPV6_RECVERR => s.recverr = v != 0,
            IPV6_MTU_DISCOVER if (0..=IPV6_PMTUDISC_OMIT as i32).contains(&v) => {
                s.mtu_discover = v;
            }
            IPV6_MTU_DISCOVER => return Err(Errno::EINVAL),
            IPV6_MTU if v != 0 && v < ipv6::MIN_MTU as i32 => return Err(Errno::EINVAL),
            IPV6_MTU => s.mtu6 = v,
            IPV6_HDRINCL if raw => s.hdrincl = v != 0,
            // The checksum of ICMPv6 is always on, as `do_rawv6_setsockopt`.
            IPV6_CHECKSUM if self.proto == Proto::Raw(PROTO_ICMPV6) => {
                return Err(Errno::EINVAL);
            }
            IPV6_CHECKSUM if raw && v > 0 && v & 1 != 0 => return Err(Errno::EINVAL),
            IPV6_CHECKSUM if raw => s.checksum = v.max(-1),
            _ if Self::is_flag6(name) => {
                s.flags6.insert(name, v);
            }
            _ => return Err(Errno::ENOPROTOOPT),
        }
        Ok(())
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
        self.family
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
            Proto::Ping if self.family == AF_INET6 => SOL_ICMPV6,
            Proto::Ping => IPPROTO_ICMP,
            Proto::Raw(p) => u32::from(p),
            Proto::Tcp => IPPROTO_TCP,
        }
    }

    fn ino(&self) -> u64 {
        self.ino
    }

    fn bind(&self, _paths: &dyn PathOps, addr: &[u8]) -> Result<()> {
        let (addr, port, scope) = sockaddr::parse_bind_in(self.family, addr)?;
        let mut s = self.state.lock();
        let mut v6only = s.v6only;
        match ip::v4(&addr) {
            Some(a4) => {
                // An IPv6 socket binds to an IPv4 address only for UDP, as `__inet6_bind`.
                if self.family == AF_INET6 && (s.v6only || self.proto != Proto::Udp) {
                    return Err(if s.v6only { Errno::EINVAL } else { Errno::EADDRNOTAVAIL });
                }
                let ok = {
                    let routes = stack::ROUTES.lock();
                    a4 == ipv4::ANY
                        || routes.is_local(a4)
                        || (self.proto == Proto::Udp
                            && (routes.is_broadcast(a4) || ipv4::is_multicast(a4)))
                };
                if !ok {
                    return Err(Errno::EADDRNOTAVAIL);
                }
            }
            None if addr == ip::ANY => {}
            None => {
                let oif = if scope != 0 { scope } else { s.oif };
                // A link local address needs an interface.
                if ipv6::needs_scope(&addr) && oif == 0 {
                    return Err(Errno::EINVAL);
                }
                let ok = ipv6::is_multicast(&addr) && self.proto == Proto::Udp
                    || stack6::ROUTES6
                        .lock()
                        .addrs()
                        .iter()
                        .any(|a| a.addr == addr && (oif == 0 || a.ifindex == oif));
                if !ok {
                    return Err(Errno::EADDRNOTAVAIL);
                }
                if ipv6::needs_scope(&addr) {
                    s.oif = oif;
                }
                // A socket on an IPv6 address takes no IPv4 packets, as `__inet6_bind`.
                v6only = true;
            }
        }
        // A raw socket can bind again, as `raw_bind` and `rawv6_bind` of Linux.
        if s.port != 0 {
            return Err(Errno::EINVAL);
        }
        if let Some(table) = self.ports() {
            let reuse = s.options.get(SO_REUSEADDR).is_ok_and(|v| v != int(0));
            s.port = table.lock().bind(port, Binding { addr, reuse, id: self.ino, v6only })?;
        }
        s.v6only = v6only;
        s.local = addr;
        s.addr_locked = !ip::is_any(&addr);
        Ok(())
    }

    fn connect(&self, _paths: &dyn PathOps, addr: &[u8], _nonblock: bool) -> Result<()> {
        let Some((dst, port, scope)) = sockaddr::parse_connect_in(self.family, addr)? else {
            // `AF_UNSPEC` removes the peer, as `__udp_disconnect` of Linux.
            let mut s = self.state.lock();
            s.remote = None;
            if !s.addr_locked && !ip::is_any(&s.local) {
                s.local = self.any();
                if let Some(table) = self.ports() {
                    table.lock().set_addr(s.port, self.ino, s.local);
                }
            }
            return Ok(());
        };
        let mut s = self.state.lock();
        let (dst, src) = match ip::v4(&dst) {
            Some(d4) => {
                if self.family == AF_INET6 && (s.v6only || self.proto != Proto::Udp) {
                    return Err(Errno::ENETUNREACH);
                }
                let d4 = if d4 == ipv4::ANY { ipv4::LOOPBACK } else { d4 };
                (ip::mapped(d4), ip::mapped(self.route_to(&s, d4)?.src))
            }
            None => {
                let dst = if dst == ip::ANY { ip::LOOPBACK } else { dst };
                if ipv6::needs_scope(&dst) && scope != 0 {
                    s.oif = scope;
                }
                (dst, stack6::route(&dst, s.oif)?.src)
            }
        };
        self.autobind(&mut s)?;
        if ip::is_any(&s.local) {
            s.local = src;
            if let Some(table) = self.ports() {
                table.lock().set_addr(s.port, self.ino, src);
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
            Some(a) => sockaddr::parse_send_in(self.family, a)?,
            None => None,
        };
        self.take_error()?;
        {
            let mut s = self.state.lock();
            if s.shut_wr {
                return Err(Errno::EPIPE);
            }
            let (dst, port, scope) = match to.or(s.remote.map(|(a, p)| (a, p, 0))) {
                Some(d) => d,
                None if matches!(self.proto, Proto::Raw(_)) && s.hdrincl => (self.any(), 0, 0),
                None => return Err(Errno::EDESTADDRREQ),
            };
            self.send_to(&mut s, dst, port, scope, &msg.data)?;
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
                s.queue.front().map(|d| (d.src, d.scope, d.port, d.data.clone(), d.info))
            } else {
                let d = s.queue.pop_front();
                if let Some(d) = &d {
                    s.queued -= d.data.len() + OVERHEAD;
                }
                d.map(|d| (d.src, d.scope, d.port, d.data, d.info))
            };
            if let Some((src, scope, port, mut data, info)) = d {
                let full = data.len();
                data.truncate(len);
                let trunc = if full > len { MSG_TRUNC } else { 0 };
                return Ok(Some(Received {
                    data,
                    len: full,
                    addr: Some(sockaddr::make_in(self.family, &src, port, scope)),
                    flags: trunc,
                    control: info.map(|i| control6(&s, &i)).unwrap_or_default(),
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
        let port = if matches!(self.proto, Proto::Raw(_)) { 0 } else { s.port };
        sockaddr::make_in(self.family, &s.local, port, stack6::scope_of(&s.local, s.oif))
    }

    fn peer_name(&self) -> Result<Vec<u8>> {
        let s = self.state.lock();
        let (a, p) = s.remote.ok_or(Errno::ENOTCONN)?;
        Ok(sockaddr::make_in(self.family, &a, p, stack6::scope_of(&a, s.oif)))
    }

    fn get_option(&self, level: u32, name: u32) -> Result<Vec<u8>> {
        let mut s = self.state.lock();
        match level {
            SOL_SOCKET => Ok(match name {
                SO_TYPE => int(self.kind() as i32),
                SO_DOMAIN => int(self.family as i32),
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
            IPPROTO_IPV6 if self.family == AF_INET6 => self.get_option6(&s, name),
            SOL_RAW if self.family == AF_INET6 && name == IPV6_CHECKSUM => {
                self.get_option6(&s, name)
            }
            SOL_ICMPV6 if self.family == AF_INET6 && self.proto == Proto::Raw(PROTO_ICMPV6) => {
                if name != ICMP6_FILTER {
                    return Err(Errno::EINVAL);
                }
                Ok(s.filter6.iter().flat_map(|w| w.to_ne_bytes()).collect())
            }
            SOL_ICMPV6 if matches!(self.proto, Proto::Raw(_)) => Err(Errno::EOPNOTSUPP),
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
            IPPROTO_IPV6 if self.family == AF_INET6 => self.set_option6(&mut s, name, value)?,
            SOL_RAW if self.family == AF_INET6 && name == IPV6_CHECKSUM => {
                self.set_option6(&mut s, name, value)?;
            }
            SOL_ICMPV6 if self.family == AF_INET6 && self.proto == Proto::Raw(PROTO_ICMPV6) => {
                if name != ICMP6_FILTER {
                    return Err(Errno::ENOPROTOOPT);
                }
                // Linux copies at most 32 bytes over the old filter, as `rawv6_seticmpfilter`.
                let mut b: Vec<u8> = s.filter6.iter().flat_map(|w| w.to_ne_bytes()).collect();
                let n = value.len().min(32);
                b[..n].copy_from_slice(&value[..n]);
                for (w, c) in s.filter6.iter_mut().zip(b.as_chunks::<4>().0) {
                    *w = u32::from_ne_bytes(*c);
                }
            }
            SOL_ICMPV6 if matches!(self.proto, Proto::Raw(_)) => return Err(Errno::EOPNOTSUPP),
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

    fn poll_wait(&self, table: &mut PollTable) {
        table.add(&self.wait);
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

    fn ioctl(&self, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Option<Result<usize>> {
        crate::ioctl::inet_ioctl(cmd, arg, mem)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

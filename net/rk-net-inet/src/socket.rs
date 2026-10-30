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
    IPV6_ADD_MEMBERSHIP, IPV6_ADDR_PREFERENCES, IPV6_ADDRFORM, IPV6_AUTOFLOWLABEL, IPV6_CHECKSUM,
    IPV6_DONTFRAG, IPV6_DROP_MEMBERSHIP, IPV6_FLOWINFO, IPV6_FLOWINFO_SEND, IPV6_FREEBIND,
    IPV6_HDRINCL, IPV6_HOPLIMIT, IPV6_MINHOPCOUNT, IPV6_MTU, IPV6_MTU_DISCOVER, IPV6_MULTICAST_ALL,
    IPV6_MULTICAST_HOPS, IPV6_MULTICAST_IF, IPV6_MULTICAST_LOOP, IPV6_PKTINFO, IPV6_PMTUDISC_OMIT,
    IPV6_RECVDSTOPTS, IPV6_RECVERR, IPV6_RECVERR_RFC4884, IPV6_RECVFRAGSIZE, IPV6_RECVHOPLIMIT,
    IPV6_RECVHOPOPTS, IPV6_RECVORIGDSTADDR, IPV6_RECVPATHMTU, IPV6_RECVPKTINFO, IPV6_RECVRTHDR,
    IPV6_RECVTCLASS, IPV6_ROUTER_ALERT_ISOLATE, IPV6_RTHDR, IPV6_TCLASS, IPV6_TRANSPARENT,
    IPV6_UNICAST_HOPS, IPV6_UNICAST_IF, IPV6_V6ONLY,
};
use rk_abi::native::inet::{
    IP_ADD_MEMBERSHIP, IP_BIND_ADDRESS_NO_PORT, IP_DROP_MEMBERSHIP, IP_HDRINCL, IP_MTU_DISCOVER,
    IP_MULTICAST_ALL, IP_MULTICAST_IF, IP_MULTICAST_LOOP, IP_MULTICAST_TTL, IP_PKTINFO, IP_RECVERR,
    IP_RECVTOS, IP_RECVTTL, IP_TOS, IP_TTL, IPPROTO_ICMP, IPPROTO_IP, IPPROTO_IPV6, IPPROTO_RAW,
    IPPROTO_TCP, IPPROTO_UDP,
};
use rk_abi::native::poll::{
    POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP, POLLRDNORM, POLLWRBAND, POLLWRNORM,
};
use rk_abi::native::socket::{
    SO_ACCEPTCONN, SO_BINDTODEVICE, SO_BINDTOIFINDEX, SO_BROADCAST, SO_COOKIE, SO_DOMAIN, SO_ERROR,
    SO_PROTOCOL, SO_REUSEADDR, SO_TYPE, SOL_SOCKET,
};
use rk_frame::sync::SpinLock;
use rk_net::consts::{
    AF_INET, AF_INET6, ICMP_ECHO, ICMP_FILTER, MSG_DONTWAIT, MSG_ERRQUEUE, MSG_MORE, MSG_OOB,
    MSG_PEEK, MSG_TRUNC, SHUT_RD, SHUT_RDWR, SHUT_WR, SOCK_DGRAM, SOCK_RAW, SOCK_STREAM, SOL_RAW,
};
use rk_net::dev;
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

/// The control messages of a received IPv4 datagram that the flags of `s` ask for, in the order
/// of `ip_cmsg_recv_offset` in net/ipv4/ip_sockglue.c of Linux.
fn control4(s: &State, i: &Info6) -> Vec<(u32, u32, Vec<u8>)> {
    let mut out = Vec::new();
    if s.pktinfo {
        // `struct in_pktinfo`: the interface index, `ipi_spec_dst` and the destination, as
        // `ip_cmsg_recv_pktinfo`.
        let mut v = i.ifindex.to_ne_bytes().to_vec();
        v.extend_from_slice(&ip::v4(&i.spec).unwrap_or(ipv4::ANY));
        v.extend_from_slice(&ip::v4(&i.dst).unwrap_or(ipv4::ANY));
        out.push((IPPROTO_IP, IP_PKTINFO, v));
    }
    if s.recvttl {
        out.push((IPPROTO_IP, IP_TTL, i32::from(i.hops).to_ne_bytes().to_vec()));
    }
    if s.recvtos {
        // `ip_cmsg_recv_tos` gives one byte.
        out.push((IPPROTO_IP, IP_TOS, alloc::vec![i.tclass]));
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
    /// The IP header of the datagram, for the control messages.
    info: Option<Info6>,
}

/// The origins of an error of the error queue, `SO_EE_ORIGIN_ICMP` and `SO_EE_ORIGIN_ICMP6` of
/// <linux/errqueue.h>.
const SO_EE_ORIGIN_ICMP: u8 = 2;
const SO_EE_ORIGIN_ICMP6: u8 = 3;

/// An ICMP error about a datagram of the socket, as the `sock_exterr_skb` that `ip_icmp_error`
/// and `ipv6_icmp_error` of Linux put in the error queue.
pub(crate) struct IcmpError {
    /// The error, as `icmp_err_convert` of Linux.
    pub err: Errno,
    /// The error is hard: it counts on a connected socket without `IP_RECVERR`.
    pub hard: bool,
    /// The destination and the port of the datagram that failed.
    pub dst: Ip,
    pub port: u16,
    /// The type and the code of the ICMP message, and its information: the MTU or the pointer.
    pub kind: u8,
    pub code: u8,
    pub info: u32,
    /// The sender of the ICMP message, the offender of `SO_EE_OFFENDER`.
    pub from: Ip,
    /// The IP header of the ICMP message, for the control messages.
    pub pkt: Info6,
    /// The data of the datagram after its UDP or ICMP header.
    pub payload: Vec<u8>,
}

/// The fields of the IP header of a received datagram that the control messages give: for IPv6
/// `IPV6_RECVPKTINFO`, `IPV6_RECVHOPLIMIT` and `IPV6_RECVTCLASS`, as `ip6_datagram_recv_ctl` of
/// Linux, and for IPv4 `IP_PKTINFO`, `IP_RECVTTL` and `IP_RECVTOS`, as `ip_cmsg_recv_offset`.
#[derive(Clone, Copy)]
pub(crate) struct Info6 {
    /// The packet is IPv4, so the control messages are the ones of IPv4.
    pub v4: bool,
    /// The destination address.
    pub dst: Ip,
    /// The local address for a reply, `ipi_spec_dst` of `struct in_pktinfo`. IPv6 does not use
    /// it.
    pub spec: Ip,
    /// The interface that took the packet.
    pub ifindex: u32,
    /// The hop limit, or the TTL of IPv4.
    pub hops: u8,
    /// The traffic class, or the TOS of IPv4.
    pub tclass: u8,
}

impl Info6 {
    /// The fields of `h`, a packet that came in on `ifindex`.
    pub(crate) fn of(h: &ipv6::Header, ifindex: u32) -> Self {
        Self { v4: false, dst: h.dst, spec: h.dst, ifindex, hops: h.hops, tclass: h.tclass }
    }

    /// The fields of `h`, an IPv4 packet that came in on `ifindex`. `spec` is the local address
    /// for a reply.
    pub(crate) fn of4(h: &Header, ifindex: u32, spec: Addr) -> Self {
        let (dst, spec) = (ip::mapped(h.dst), ip::mapped(spec));
        Self { v4: true, dst, spec, ifindex, hops: h.ttl, tclass: h.tos }
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
    /// The error queue of `IP_RECVERR` and `IPV6_RECVERR`, `sk_error_queue` of Linux, and the
    /// bytes that it costs.
    errqueue: VecDeque<IcmpError>,
    errqueued: usize,
    options: Options,
    /// `IP_TTL`, or `None` for the default.
    ttl: Option<u8>,
    tos: u8,
    recverr: bool,
    /// `IP_PKTINFO`, `IP_RECVTTL` and `IP_RECVTOS`: the control messages of IPv4.
    pktinfo: bool,
    recvttl: bool,
    recvtos: bool,
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
    /// The interface index of `IPV6_PKTINFO`, `np->sticky_pktinfo.ipi6_ifindex` of Linux.
    sticky_ifindex: u32,
    shut_rd: bool,
    shut_wr: bool,
    closed: bool,
    /// The datagram of `MSG_MORE` that waits for more data: the address, the port and the
    /// scope of the first send, and the data, as `pending` of `struct udp_sock` of Linux.
    corked: Option<(Ip, u16, u32, Vec<u8>)>,
    /// `UDP_CORK`: each send adds its data to one datagram, as `MSG_MORE`.
    cork: bool,
    /// `IPV6_RTHDR`: the routing header that the program set. Each UDP and raw packet of IPv6
    /// gets it.
    rthdr: Option<Vec<u8>>,
    /// The multicast groups of IPv6 that the socket joined: the interface and the group, as
    /// `ipv6_mc_list` of Linux.
    groups6: Vec<(u32, Ip)>,
    /// The multicast groups of IPv4 that the socket joined, as `mc_list` of Linux.
    groups4: Vec<Membership>,
    /// The interface of `IP_MULTICAST_IF`, or 0.
    mc_index: u32,
    /// The source address of `IP_MULTICAST_IF`, or `0.0.0.0`.
    mc_addr: Addr,
    /// `IP_MULTICAST_ALL`: the socket takes the datagrams of each group of the host.
    mc_all: bool,
    /// `IP_BIND_ADDRESS_NO_PORT`: `bind` with the port 0 gives no port, and `connect` gives it.
    bind_no_port: bool,
}

/// A multicast group of IPv4 that a socket joined, `struct ip_mreqn` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Membership {
    /// The group.
    group: Addr,
    /// The address of the interface that the program gave, or `0.0.0.0`.
    addr: Addr,
    /// The interface.
    ifindex: u32,
}

/// The value of an option of the level `IPPROTO_IP` that is a number, as `do_ip_setsockopt` in
/// net/ipv4/ip_sockglue.c of Linux: an `int`, or one byte for a shorter value.
///
/// # Errors
///
/// Gives `EINVAL` for an empty value.
pub(crate) fn ip_int(value: &[u8]) -> Result<i32> {
    match value {
        [a, b, c, d, ..] => Ok(i32::from_ne_bytes([*a, *b, *c, *d])),
        [a, ..] => Ok(i32::from(*a)),
        [] => Err(Errno::EINVAL),
    }
}

/// The IPv4 address at `at` in `value`.
fn addr_at(value: &[u8], at: usize) -> Addr {
    let mut a = ipv4::ANY;
    a.copy_from_slice(&value[at..at + 4]);
    a
}

/// The group, the address and the interface of `struct ip_mreq` or `struct ip_mreqn` in
/// `value`, as `do_ip_setsockopt` of Linux.
///
/// # Errors
///
/// Gives `EINVAL` for a value that is shorter than `struct ip_mreq`.
fn mreqn(value: &[u8]) -> Result<Membership> {
    if value.len() < 8 {
        return Err(Errno::EINVAL);
    }
    let ifindex = match value.get(8..12) {
        Some(&[a, b, c, d]) => u32::from_ne_bytes([a, b, c, d]),
        _ => 0,
    };
    Ok(Membership { group: addr_at(value, 0), addr: addr_at(value, 4), ifindex })
}

/// The interface of a group, as `ip_mc_find_dev` in net/ipv4/igmp.c of Linux: the interface of
/// `m`, else the interface of the address of `m`, else the interface of the route to the group.
fn mc_find_dev(m: &Membership) -> Option<u32> {
    if m.ifindex != 0 {
        return dev::by_index(m.ifindex).map(|d| d.ifindex());
    }
    if m.addr != ipv4::ANY {
        return stack::dev_of_addr(m.addr);
    }
    stack::route(m.group).ok().map(|n| n.ifindex)
}

/// `UDP_CORK` of include/uapi/linux/udp.h.
const UDP_CORK: u32 = 1;
/// `MCAST_JOIN_GROUP` of include/uapi/linux/in.h.
const MCAST_JOIN_GROUP: u32 = 42;
/// `MCAST_LEAVE_GROUP` of include/uapi/linux/in.h.
const MCAST_LEAVE_GROUP: u32 = 45;
/// The size of `struct ipv6_mreq`.
const IPV6_MREQ_LEN: usize = 20;
/// The size of `struct group_req` on a 64-bit machine.
const GROUP_REQ_LEN: usize = 136;

/// The interface and the group of `struct ipv6_mreq` or `struct group_req` in `value`, for the
/// option `name`, as `do_ipv6_setsockopt` of Linux.
fn membership(name: u32, value: &[u8]) -> Result<(u32, Ip)> {
    if name == MCAST_JOIN_GROUP || name == MCAST_LEAVE_GROUP {
        if value.len() < GROUP_REQ_LEN {
            return Err(Errno::EINVAL);
        }
        let ifindex = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
        if u32::from(u16::from_ne_bytes([value[8], value[9]])) != AF_INET6 {
            return Err(Errno::EINVAL);
        }
        let group: Ip = value[16..32].try_into().map_err(|_| Errno::EINVAL)?;
        return Ok((ifindex, group));
    }
    if value.len() < IPV6_MREQ_LEN {
        return Err(Errno::EINVAL);
    }
    let group: Ip = value[..16].try_into().map_err(|_| Errno::EINVAL)?;
    let ifindex = i32::from_ne_bytes([value[16], value[17], value[18], value[19]]);
    Ok((u32::try_from(ifindex).unwrap_or(0), group))
}
/// `IPV6_SRCRT_TYPE_2` of include/uapi/linux/ipv6.h: the routing header of Mobile IPv6.
const SRCRT_TYPE_2: u8 = 2;
/// `IPV6_SRCRT_TYPE_4` of include/uapi/linux/ipv6.h: the segment routing header.
const SRCRT_TYPE_4: u8 = 4;

/// Checks a segment routing header of `len` bytes, as `seg6_validate_srh` in net/ipv6/seg6.c of
/// Linux: the length, the segment counts and the TLVs after the segments.
fn valid_srh(h: &[u8]) -> bool {
    let len = h.len();
    if h.len() < 8 || h[2] != SRCRT_TYPE_4 || (usize::from(h[1]) + 1) * 8 != len {
        return false;
    }
    let (left, first) = (usize::from(h[3]), usize::from(h[4]));
    if left > first || first + 1 > usize::from(h[1]) / 2 {
        return false;
    }
    let mut off = 8 + (first + 1) * 16;
    if off > len {
        return false;
    }
    // Each TLV has a type, a length and the data.
    while off < len {
        if len - off < 2 {
            return false;
        }
        off += 2 + usize::from(h[off + 1]);
        if off > len {
            return false;
        }
    }
    true
}

/// Checks the value of `IPV6_RTHDR`, as `ipv6_set_opt_hdr` in net/ipv6/ipv6_sockglue.c of
/// Linux. An empty value removes the header. Gives `None` for a header that is not correct.
fn rthdr_of(value: &[u8]) -> Option<Option<Vec<u8>>> {
    if value.is_empty() {
        return Some(None);
    }
    let len = value.len();
    if len < 2 || len & 7 != 0 || len > 8 * 255 || (usize::from(value[1]) + 1) * 8 > len {
        return None;
    }
    let ok = match value.get(2) {
        Some(&SRCRT_TYPE_2) => value[1] == 2 && value.get(3) == Some(&1),
        Some(&SRCRT_TYPE_4) => valid_srh(value),
        _ => false,
    };
    ok.then(|| Some(value.to_vec()))
}

/// Makes the routing header of a packet to `dst` from the header `rthdr` of `IPV6_RTHDR`, as
/// `ipv6_push_rthdr0` and `ipv6_push_rthdr4` in net/ipv6/exthdrs.c of Linux. The packet goes to
/// the next address of the header, and `dst`, the final destination, takes its place in the
/// header. Gives the header with the next header `next`, and the destination of the packet.
pub(crate) fn push_rthdr(rthdr: &[u8], dst: &Ip, next: u8) -> (Vec<u8>, Ip) {
    let addr = |i: usize| -> Ip {
        rthdr.get(8 + 16 * i..24 + 16 * i).and_then(|a| a.try_into().ok()).unwrap_or(*dst)
    };
    let mut h = rthdr.to_vec();
    h[0] = next;
    if rthdr[2] == SRCRT_TYPE_4 {
        // The segments are in the reverse order: segment 0 is the final destination, and the
        // packet goes to the segment "segments left".
        h[8..24].copy_from_slice(dst);
        (h, addr(usize::from(rthdr[3])))
    } else {
        // The packet goes to the first address. The other addresses move up one place, and the
        // final destination is the last address.
        let hops = usize::from(rthdr[1]) / 2;
        h.copy_within(24..8 + 16 * hops, 8);
        h[8 + 16 * (hops - 1)..8 + 16 * hops].copy_from_slice(dst);
        (h, addr(0))
    }
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
    /// `AF_INET` or `AF_INET6`. `IPV6_ADDRFORM` changes a UDP socket from `AF_INET6` to
    /// `AF_INET`.
    family: AtomicU32,
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
            family: AtomicU32::new(family),
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
                errqueue: VecDeque::new(),
                errqueued: 0,
                options: Options::default(),
                ttl: None,
                tos: 0,
                recverr: false,
                pktinfo: false,
                recvttl: false,
                recvtos: false,
                hdrincl: proto == Proto::Raw(IPPROTO_RAW as u8),
                mtu_discover: 0,
                multicast_ttl: 1,
                multicast_loop: true,
                filter: 0,
                v6only: v6 && proto == Proto::Ping,
                hops: None,
                mc_hops: 1,
                tclass: 0,
                // A raw ICMPv6 socket has its checksum at the offset 2, as `rawv6_init_sk`.
                checksum: if v6 && proto == Proto::Raw(PROTO_ICMPV6) { 2 } else { -1 },
                mtu6: 0,
                filter6: [0; 8],
                flags6: BTreeMap::new(),
                sticky_ifindex: 0,
                shut_rd: false,
                shut_wr: false,
                closed: false,
                corked: None,
                cork: false,
                rthdr: None,
                groups6: Vec::new(),
                groups4: Vec::new(),
                mc_index: 0,
                mc_addr: ipv4::ANY,
                mc_all: true,
                bind_no_port: false,
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
        self.af()
    }

    /// The family of the socket.
    fn af(&self) -> u32 {
        self.family.load(Ordering::Relaxed)
    }

    /// The wildcard address of the family of the socket.
    fn any(&self) -> Ip {
        if self.af() == AF_INET6 { ip::ANY } else { ip::V4_ANY }
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
            family: self.af(),
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

    /// The score of the socket for a packet from `src` and `sport` that came in on `dif`, or
    /// `None` if the socket has another peer or another device. A socket with this peer wins
    /// over a socket without a peer, and a socket on the device wins over a socket on no
    /// device, as `compute_score` in net/ipv4/udp.c of Linux.
    pub(crate) fn score(&self, src: &Ip, sport: u16, dif: u32) -> Option<u32> {
        let s = self.state.lock();
        if s.closed || !stack::dev_match(s.oif, dif) {
            return None;
        }
        let dev = if s.oif != 0 { 4 } else { 0 };
        match s.remote {
            None => Some(dev),
            Some((a, p)) if a == *src && (p == sport || self.proto == Proto::Ping) => Some(dev + 2),
            Some(_) => None,
        }
    }

    /// Tells if the socket takes a packet to `dst` that came in on `dif`, as `ip_mc_sf_allow`
    /// in net/ipv4/igmp.c of Linux: a packet that is not to a group, a group that the socket
    /// joined on the device, or any group with `IP_MULTICAST_ALL`.
    pub(crate) fn mc_allow(&self, dst: Addr, dif: u32) -> bool {
        let s = self.state.lock();
        !ipv4::is_multicast(dst)
            || s.mc_all
            || s.groups4.iter().any(|m| m.group == dst && (dif == 0 || m.ifindex == dif))
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
    /// IPv4 header, and it came in on `dif`. `info` is for the control messages.
    pub(crate) fn deliver_raw(&self, h: &Header, packet: &[u8], dif: u32, info: Info6) {
        let (src, dst) = (ip::mapped(h.src), ip::mapped(h.dst));
        {
            let s = self.state.lock();
            if !stack::dev_match(s.oif, dif) {
                return;
            }
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
        if !self.mc_allow(h.dst, dif) {
            return;
        }
        self.deliver(src, 0, 0, packet.to_vec(), Some(info));
    }

    /// Gives a copy of an IPv6 packet to a raw socket, as `ipv6_raw_deliver` and
    /// `icmpv6_filter` of Linux. `payload` is the packet after the IPv6 headers, which is
    /// what an IPv6 raw socket reads. The packet came in on `ifindex`, and `dif` is the device
    /// for `stack::dev_match`.
    pub(crate) fn deliver_raw6(&self, h: &ipv6::Header, ifindex: u32, payload: &[u8], dif: u32) {
        let scope = stack6::scope_of(&h.src, ifindex);
        {
            let s = self.state.lock();
            if !ip::is_any(&s.local) && s.local != h.dst {
                return;
            }
            if s.remote.is_some_and(|(a, _)| a != h.src) {
                return;
            }
            if !stack::dev_match(s.oif, dif) {
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

    /// Records an error from an ICMP message, as `__udp4_lib_err` and `__udp6_lib_err` of
    /// Linux. Without `IP_RECVERR`, only a hard error on a connected socket counts. With
    /// `IP_RECVERR`, the error also goes in the error queue, as `ip_icmp_error`. A full queue
    /// drops it, as `sock_queue_err_skb`.
    pub(crate) fn icmp_error(&self, e: IcmpError) {
        let mut s = self.state.lock();
        let err = e.err;
        if s.recverr {
            let size = e.payload.len() + OVERHEAD;
            if s.queued + s.errqueued + size < s.options.rcvbuf as usize {
                s.errqueued += size;
                s.errqueue.push_back(e);
            }
        } else {
            let connected = s.remote.is_some_and(|(a, _)| a == e.dst);
            if !(e.hard && connected) {
                return;
            }
        }
        s.error = Some(err);
        drop(s);
        self.wake();
    }

    /// Takes the first error of the error queue for `MSG_ERRQUEUE`, as `ip_recv_error` and
    /// `ipv6_recv_error` of Linux. The data is the data of the datagram that failed, the
    /// address is its destination, and the control messages of the ICMP packet come before the
    /// `struct sock_extended_err` and the offender. The pending error becomes the error of the
    /// next entry, as `sock_dequeue_err_skb`.
    fn recv_error(&self, len: usize) -> Result<Received> {
        let mut s = self.state.lock();
        let Some(e) = s.errqueue.pop_front() else { return Err(Errno::EAGAIN) };
        s.errqueued -= e.payload.len() + OVERHEAD;
        s.error = s.errqueue.front().map(|n| n.err);
        let af = self.af();
        let mut control = if e.pkt.v4 { control4(&s, &e.pkt) } else { control6(&s, &e.pkt) };
        drop(s);
        let mut ee = Vec::with_capacity(16 + 28);
        ee.extend_from_slice(&u32::from(e.err.get()).to_ne_bytes());
        ee.push(if e.pkt.v4 { SO_EE_ORIGIN_ICMP } else { SO_EE_ORIGIN_ICMP6 });
        ee.extend_from_slice(&[e.kind, e.code, 0]);
        ee.extend_from_slice(&e.info.to_ne_bytes());
        ee.extend_from_slice(&0u32.to_ne_bytes());
        ee.extend_from_slice(&sockaddr::make_in(af, &e.from, 0, 0));
        let (level, name) =
            if af == AF_INET6 { (IPPROTO_IPV6, IPV6_RECVERR) } else { (IPPROTO_IP, IP_RECVERR) };
        control.push((level, name, ee));
        let full = e.payload.len();
        let mut data = e.payload;
        data.truncate(len);
        Ok(Received {
            data,
            len: full,
            addr: Some(sockaddr::make_in(af, &e.dst, e.port, 0)),
            flags: MSG_ERRQUEUE | if full > len { MSG_TRUNC } else { 0 },
            control,
            ..Received::default()
        })
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
    /// A packet to a group goes through the interface of the socket or of `IP_MULTICAST_IF`,
    /// and its source is the local address or the address of `IP_MULTICAST_IF`, as
    /// `udp_sendmsg` of Linux.
    fn route_to(&self, s: &State, dst: Addr) -> Result<crate::route::Next> {
        let next = if ipv4::is_multicast(dst) {
            let oif = if s.oif != 0 { s.oif } else { s.mc_index };
            let local = Self::local4(s);
            stack::route_mc(dst, oif, if local == ipv4::ANY { s.mc_addr } else { local })?
        } else {
            stack::route_oif(dst, s.oif)?
        };
        if next.broadcast && s.options.get(SO_BROADCAST).is_ok_and(|v| v == int(0)) {
            return Err(Errno::EACCES);
        }
        Ok(next)
    }

    fn out(&self, s: &State, src: Addr, dst: Addr, protocol: u8) -> Out {
        let ttl = if ipv4::is_multicast(dst) {
            s.multicast_ttl as u8
        } else {
            s.ttl.unwrap_or_else(rk_net::sysctl::default_ttl)
        };
        // `IP_PMTUDISC_DO` and `IP_PMTUDISC_PROBE` forbid the fragments, as `ip_dont_fragment`
        // of Linux.
        let df = matches!(s.mtu_discover, 2 | 3);
        Out { src, dst, protocol, ttl, tos: s.tos, df, mc_loop: s.multicast_loop }
    }

    /// Reads `IPV6_PKTINFO` in the control messages of a send on an IPv6 socket, as
    /// `ip6_datagram_send_ctl` in net/ipv6/datagram.c of Linux. The interface index of the
    /// `struct in6_pktinfo` goes to `scope`, the interface of the packet. Gives the source
    /// address of the `struct in6_pktinfo`, or `::`. The other control messages do nothing, and
    /// a send to an IPv4-mapped `dst` reads none, as `udpv6_sendmsg`.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` for a short message, for an index that is not the interface of the
    /// destination or of `SO_BINDTODEVICE`, for a link local source without an interface, and
    /// for a source that is not local without `IPV6_FREEBIND` or `IPV6_TRANSPARENT`. Gives
    /// `ENODEV` for an interface that is not there.
    fn send_pktinfo6(
        &self,
        s: &State,
        dst: &Ip,
        control: &[(u32, u32, Vec<u8>)],
        scope: &mut u32,
    ) -> Result<Ip> {
        let mut saddr = ip::ANY;
        if self.af() != AF_INET6 || ip::v4(dst).is_some() {
            return Ok(saddr);
        }
        for (level, kind, data) in control {
            if *level != IPPROTO_IPV6 || *kind != IPV6_PKTINFO {
                continue;
            }
            let info = data.get(..20).ok_or(Errno::EINVAL)?;
            let ifindex = u32::from_ne_bytes([info[16], info[17], info[18], info[19]]);
            let mut oif = if *scope != 0 { *scope } else { s.oif };
            if ifindex != 0 {
                if oif != 0 && ifindex != oif {
                    return Err(Errno::EINVAL);
                }
                oif = ifindex;
                *scope = ifindex;
            }
            let mut addr = ip::ANY;
            addr.copy_from_slice(&info[..16]);
            if oif != 0 {
                dev::by_index(oif).ok_or(Errno::ENODEV)?;
            } else if ipv6::is_link_local(&addr) {
                return Err(Errno::EINVAL);
            }
            if addr != ip::ANY {
                // A link local source must be on the interface, as `ipv6_chk_addr_and_flags`.
                let strict = ipv6::is_link_local(&addr);
                let nonlocal = [IPV6_FREEBIND, IPV6_TRANSPARENT]
                    .iter()
                    .any(|o| s.flags6.get(o).is_some_and(|&v| v != 0));
                let local = stack6::ROUTES6
                    .lock()
                    .addrs()
                    .iter()
                    .any(|a| a.addr == addr && (!strict || a.ifindex == oif));
                if !nonlocal && !local {
                    return Err(Errno::EINVAL);
                }
                saddr = addr;
            }
        }
        Ok(saddr)
    }

    /// Sends `data` to `dst` and `dport`, and `scope` is the interface of a link local
    /// destination. `saddr` is the source of `IPV6_PKTINFO`, or `::`. The caller holds the state.
    fn send_to(
        &self,
        s: &mut State,
        dst: Ip,
        dport: u16,
        scope: u32,
        saddr: Ip,
        data: &[u8],
    ) -> Result<()> {
        let Some(d4) = ip::v4(&dst) else {
            if self.af() == AF_INET || ip::v4(&s.local).is_some_and(|a| a != ipv4::ANY) {
                return Err(Errno::ENETUNREACH);
            }
            // A destination of `::` is the local host, as `udpv6_sendmsg` of Linux.
            let dst = if dst == ip::ANY { ip::LOOPBACK } else { dst };
            return self.send6(s, dst, dport, scope, saddr, data);
        };
        if self.af() == AF_INET6 {
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
    fn send6(
        &self,
        s: &mut State,
        dst: Ip,
        dport: u16,
        scope: u32,
        saddr: Ip,
        data: &[u8],
    ) -> Result<()> {
        let max = usize::from(u16::MAX);
        let mut oif = if scope != 0 { scope } else { s.oif };
        // UDP sends on the interface of `IPV6_PKTINFO` if no other interface is set, as
        // `udpv6_sendmsg` of Linux.
        if oif == 0 && self.proto == Proto::Udp {
            oif = s.sticky_ifindex;
        }
        if let Proto::Raw(_) = self.proto
            && s.hdrincl
        {
            return self.send_hdrincl6(s, oif, data);
        }
        // A UDP or raw packet goes to the first address of the routing header, as
        // `fl6_update_dst`. The checksum uses the final destination.
        let (ext, first) = match (&s.rthdr, self.proto) {
            (Some(r), Proto::Udp) => push_rthdr(r, &dst, PROTO_UDP),
            (Some(r), Proto::Raw(p)) => push_rthdr(r, &dst, p),
            _ => (Vec::new(), dst),
        };
        let next = stack6::route(&first, oif)?;
        // The source of `IPV6_PKTINFO` comes before the local address, as `udpv6_sendmsg`.
        let src = if saddr != ip::ANY {
            saddr
        } else if ip::is_any(&s.local) {
            next.src
        } else {
            s.local
        };
        let hops = if ipv6::is_multicast(&dst) {
            s.mc_hops as u8
        } else {
            s.hops.unwrap_or(ipv6::DEFAULT_HOPS)
        };
        let tclass = s.tclass;
        // `IPV6_DONTFRAG`, `IPV6_PMTUDISC_DO` and `IPV6_PMTUDISC_PROBE` forbid the fragments,
        // as `ip6_sk_ignore_df` and `__ip6_append_data` of Linux.
        let dontfrag = s.flags6.get(&IPV6_DONTFRAG).is_some_and(|&v| v != 0)
            || matches!(s.mtu_discover, 2 | 3);
        let out = |next| Out6 { src, dst: first, next, hops, tclass, ext: ext.clone(), dontfrag };
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
                if let Ok(at) = usize::try_from(s.checksum) {
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
        if name == IPV6_RTHDR {
            return Ok(s.rthdr.clone().unwrap_or_default());
        }
        Ok(int(match name {
            IPV6_V6ONLY => i32::from(s.v6only),
            IPV6_UNICAST_HOPS => i32::from(s.hops.unwrap_or(ipv6::DEFAULT_HOPS)),
            IPV6_MULTICAST_HOPS => s.mc_hops,
            IPV6_MULTICAST_LOOP => i32::from(s.multicast_loop),
            IPV6_TCLASS => i32::from(s.tclass),
            IPV6_RECVERR => i32::from(s.recverr),
            IPV6_MTU_DISCOVER => s.mtu_discover,
            IPV6_HDRINCL if raw => i32::from(s.hdrincl),
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

    /// Changes a connected UDP socket of IPv6 with an IPv4 peer to an `AF_INET` socket, for
    /// `IPV6_ADDRFORM`, as `do_ipv6_setsockopt` in net/ipv6/ipv6_sockglue.c of Linux. The other
    /// kinds give `ENOPROTOOPT`.
    fn addrform(&self, s: &mut State) -> Result<()> {
        if self.proto != Proto::Udp {
            return Err(Errno::ENOPROTOOPT);
        }
        // A corked datagram of IPv6 waits, as `up->pending == AF_INET6`.
        if s.corked.as_ref().is_some_and(|c| ip::v4(&c.0).is_none()) {
            return Err(Errno::EBUSY);
        }
        let Some((peer, _)) = s.remote else { return Err(Errno::ENOTCONN) };
        if s.v6only || ip::v4(&peer).is_none() {
            return Err(Errno::EADDRNOTAVAIL);
        }
        // An IPv4 socket has no options of IPv6, as Linux frees `np->opt`.
        s.rthdr = None;
        self.family.store(AF_INET, Ordering::Relaxed);
        Ok(())
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
        if name == IPV6_RTHDR {
            s.rthdr = rthdr_of(value).ok_or(Errno::EINVAL)?;
            return Ok(());
        }
        // `struct in6_pktinfo`: the address and the interface index. The index must be the
        // device of `SO_BINDTODEVICE`, if the socket has one, as `sk_dev_equal_l3scope`.
        if name == IPV6_PKTINFO {
            let index = value.get(16..20).ok_or(Errno::EINVAL)?;
            let ifindex = u32::from_ne_bytes([index[0], index[1], index[2], index[3]]);
            if s.oif != 0 && ifindex != s.oif {
                return Err(Errno::EINVAL);
            }
            s.sticky_ifindex = ifindex;
            return Ok(());
        }
        if matches!(
            name,
            IPV6_ADD_MEMBERSHIP | IPV6_DROP_MEMBERSHIP | MCAST_JOIN_GROUP | MCAST_LEAVE_GROUP
        ) {
            let (ifindex, group) = membership(name, value)?;
            return if name == IPV6_ADD_MEMBERSHIP || name == MCAST_JOIN_GROUP {
                Self::join6(s, ifindex, &group)
            } else {
                Self::leave6(s, ifindex, &group)
            };
        }
        let v = int_of(value)?;
        let raw = matches!(self.proto, Proto::Raw(_));
        let hops = |v: i32| if (-1..=255).contains(&v) { Ok(v) } else { Err(Errno::EINVAL) };
        match name {
            IPV6_ADDRFORM if v != AF_INET as i32 => return Err(Errno::EINVAL),
            IPV6_ADDRFORM => self.addrform(s)?,
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
            // RFC 3542 does not allow `IPV6_CHECKSUM` at the level `IPPROTO_IPV6` on an ICMPv6
            // socket, as `do_rawv6_setsockopt`. The level `SOL_RAW` allows it.
            IPV6_CHECKSUM if self.proto == Proto::Raw(PROTO_ICMPV6) => {
                return Err(Errno::EINVAL);
            }
            IPV6_CHECKSUM if raw => Self::set_checksum6(s, v)?,
            _ if Self::is_flag6(name) => {
                s.flags6.insert(name, v);
            }
            _ => return Err(Errno::ENOPROTOOPT),
        }
        Ok(())
    }

    /// Sets the offset of the checksum of a raw IPv6 socket, or -1 for no checksum, as
    /// `do_rawv6_setsockopt` of Linux. An odd offset is not allowed.
    fn set_checksum6(s: &mut State, v: i32) -> Result<()> {
        if v > 0 && v & 1 != 0 {
            return Err(Errno::EINVAL);
        }
        s.checksum = v.max(-1);
        Ok(())
    }

    /// Joins a multicast group of IPv6, as `ipv6_sock_mc_join` of Linux.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` for an address that is not multicast, `EADDRINUSE` if the socket is in the
    /// group on the interface, and `ENODEV` for an interface that is not there.
    fn join6(s: &mut State, ifindex: u32, group: &Ip) -> Result<()> {
        if !ipv6::is_multicast(group) {
            return Err(Errno::EINVAL);
        }
        if s.groups6.iter().any(|(i, g)| (ifindex == 0 || *i == ifindex) && g == group) {
            return Err(Errno::EADDRINUSE);
        }
        let dev = crate::mcast6::sock_join(ifindex, group)?;
        s.groups6.push((dev, *group));
        Ok(())
    }

    /// Leaves a multicast group of IPv6, as `ipv6_sock_mc_drop` of Linux. The interface 0 takes
    /// the group on any interface.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` for an address that is not multicast, and `EADDRNOTAVAIL` if the socket is
    /// not in the group.
    fn leave6(s: &mut State, ifindex: u32, group: &Ip) -> Result<()> {
        if !ipv6::is_multicast(group) {
            return Err(Errno::EINVAL);
        }
        let at = s
            .groups6
            .iter()
            .position(|(i, g)| (ifindex == 0 || *i == ifindex) && g == group)
            .ok_or(Errno::EADDRNOTAVAIL)?;
        let (i, g) = s.groups6.remove(at);
        crate::mcast6::leave(i, &g);
        Ok(())
    }

    /// Sets an option of the level `IPPROTO_IP`, as `do_ip_setsockopt` in
    /// net/ipv4/ip_sockglue.c of Linux.
    fn set_option4(&self, s: &mut State, name: u32, value: &[u8]) -> Result<()> {
        match name {
            IP_MULTICAST_IF => return Self::set_mc_if(s, value),
            IP_ADD_MEMBERSHIP => return Self::join4(s, mreqn(value)?),
            IP_DROP_MEMBERSHIP => return Self::leave4(s, mreqn(value)?),
            MCAST_JOIN_GROUP | MCAST_LEAVE_GROUP => {
                // `struct group_req` with a `struct sockaddr_in` in `gr_group`.
                if value.len() < GROUP_REQ_LEN {
                    return Err(Errno::EINVAL);
                }
                if u32::from(u16::from_ne_bytes([value[8], value[9]])) != AF_INET {
                    return Err(Errno::EINVAL);
                }
                let ifindex = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                let m = Membership { group: addr_at(value, 12), addr: ipv4::ANY, ifindex };
                return if name == MCAST_JOIN_GROUP {
                    Self::join4(s, m)
                } else {
                    Self::leave4(s, m)
                };
            }
            _ => {}
        }
        let v = ip_int(value)?;
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
            IP_PKTINFO => s.pktinfo = v != 0,
            IP_RECVTTL => s.recvttl = v != 0,
            IP_RECVTOS => s.recvtos = v != 0,
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
            IP_MULTICAST_ALL => s.mc_all = v != 0,
            IP_BIND_ADDRESS_NO_PORT => s.bind_no_port = v != 0,
            _ => return Err(Errno::ENOPROTOOPT),
        }
        Ok(())
    }

    /// Sets `IP_MULTICAST_IF` from `struct in_addr`, `struct ip_mreq` or `struct ip_mreqn`, as
    /// `do_ip_setsockopt` of Linux. The address `0.0.0.0` without an interface removes the
    /// setting.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` for a short value or an interface that is not the device of the socket,
    /// and `EADDRNOTAVAIL` for an address or an interface that is not there.
    fn set_mc_if(s: &mut State, value: &[u8]) -> Result<()> {
        let (addr, ifindex) = match value.len() {
            0..4 => return Err(Errno::EINVAL),
            4..8 => (addr_at(value, 0), 0),
            _ => {
                let m = mreqn(value)?;
                (m.addr, m.ifindex)
            }
        };
        let ifindex = if ifindex == 0 {
            if addr == ipv4::ANY {
                s.mc_index = 0;
                s.mc_addr = ipv4::ANY;
                return Ok(());
            }
            stack::dev_of_addr(addr).ok_or(Errno::EADDRNOTAVAIL)?
        } else {
            dev::by_index(ifindex).ok_or(Errno::EADDRNOTAVAIL)?.ifindex()
        };
        if s.oif != 0 && ifindex != s.oif {
            return Err(Errno::EINVAL);
        }
        s.mc_index = ifindex;
        s.mc_addr = addr;
        Ok(())
    }

    /// Joins a multicast group of IPv4 on its interface, as `__ip_mc_join_group` in
    /// net/ipv4/igmp.c of Linux. The interface joins the group, as `ip_mc_inc_group`.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` for an address that is not multicast, `ENODEV` if no interface is found,
    /// `EADDRINUSE` if the socket is in the group on the interface, and `ENOBUFS` for more
    /// groups than `net.ipv4.igmp_max_memberships`.
    fn join4(s: &mut State, mut m: Membership) -> Result<()> {
        if !ipv4::is_multicast(m.group) {
            return Err(Errno::EINVAL);
        }
        m.ifindex = mc_find_dev(&m).ok_or(Errno::ENODEV)?;
        if s.groups4.iter().any(|g| g.group == m.group && g.ifindex == m.ifindex) {
            return Err(Errno::EADDRINUSE);
        }
        let max = rk_net::sysctl::ipv4("igmp_max_memberships");
        if i32::try_from(s.groups4.len()).unwrap_or(i32::MAX) >= max {
            return Err(Errno::ENOBUFS);
        }
        crate::igmp::join(m.ifindex, m.group);
        s.groups4.push(m);
        Ok(())
    }

    /// Leaves a multicast group of IPv4, as `ip_mc_leave_group` in net/ipv4/igmp.c of Linux.
    /// Without an interface, the address of the interface finds the group.
    ///
    /// # Errors
    ///
    /// Gives `ENODEV` if no interface is found for a request without an interface and an
    /// address, and `EADDRNOTAVAIL` if the socket is not in the group.
    fn leave4(s: &mut State, m: Membership) -> Result<()> {
        let dev = mc_find_dev(&m);
        if m.ifindex == 0 && m.addr == ipv4::ANY && dev.is_none() {
            return Err(Errno::ENODEV);
        }
        let ifindex = if m.ifindex != 0 { m.ifindex } else { dev.unwrap_or(0) };
        let at = s
            .groups4
            .iter()
            .position(|g| {
                g.group == m.group
                    && if ifindex != 0 {
                        g.ifindex == ifindex
                    } else {
                        m.addr == ipv4::ANY || g.addr == m.addr
                    }
            })
            .ok_or(Errno::EADDRNOTAVAIL)?;
        let g = s.groups4.remove(at);
        crate::igmp::leave(g.ifindex, g.group);
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
        self.af()
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
            Proto::Ping if self.af() == AF_INET6 => SOL_ICMPV6,
            Proto::Ping => IPPROTO_ICMP,
            Proto::Raw(p) => u32::from(p),
            Proto::Tcp => IPPROTO_TCP,
        }
    }

    fn ino(&self) -> u64 {
        self.ino
    }

    fn bind(&self, _paths: &dyn PathOps, addr: &[u8]) -> Result<()> {
        let (addr, port, scope) = sockaddr::parse_bind_in(self.af(), addr)?;
        let mut s = self.state.lock();
        let mut v6only = s.v6only;
        match ip::v4(&addr) {
            Some(a4) => {
                // An IPv6 socket binds to an IPv4 address only for UDP, as `__inet6_bind`.
                if self.af() == AF_INET6 && (s.v6only || self.proto != Proto::Udp) {
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
        // With `IP_BIND_ADDRESS_NO_PORT`, the port 0 waits for `connect` or the first send,
        // as `__inet_bind` of Linux.
        if let Some(table) = self.ports()
            && (port != 0 || !s.bind_no_port)
        {
            let reuse = s.options.get(SO_REUSEADDR).is_ok_and(|v| v != int(0));
            s.port = table.lock().bind(port, Binding { addr, reuse, id: self.ino, v6only })?;
        }
        s.v6only = v6only;
        s.local = addr;
        s.addr_locked = !ip::is_any(&addr);
        Ok(())
    }

    fn connect(&self, _paths: &dyn PathOps, addr: &[u8], _nonblock: bool) -> Result<()> {
        let Some((dst, port, scope)) = sockaddr::parse_connect_in(self.af(), addr)? else {
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
                if self.af() == AF_INET6 && (s.v6only || self.proto != Proto::Udp) {
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
            Some(a) => sockaddr::parse_send_in(self.af(), a)?,
            None => None,
        };
        self.take_error()?;
        {
            let mut s = self.state.lock();
            if s.shut_wr {
                return Err(Errno::EPIPE);
            }
            // A UDP send with `MSG_MORE` or `UDP_CORK` adds its data to one datagram, and the next send
            // without it sends the datagram to the address of the first send, as
            // `udp_sendmsg` of Linux.
            let more = flags & MSG_MORE != 0 || s.cork;
            if let Some((dst, port, scope, mut data)) = s.corked.take() {
                data.extend_from_slice(&msg.data);
                if more {
                    s.corked = Some((dst, port, scope, data));
                    return Ok(msg.data.len());
                }
                self.send_to(&mut s, dst, port, scope, ip::ANY, &data)?;
            } else {
                let (dst, port, mut scope) = match to.or(s.remote.map(|(a, p)| (a, p, 0))) {
                    Some(d) => d,
                    None if matches!(self.proto, Proto::Raw(_)) && s.hdrincl => (self.any(), 0, 0),
                    None => return Err(Errno::EDESTADDRREQ),
                };
                let saddr = self.send_pktinfo6(&s, &dst, &msg.control, &mut scope)?;
                // A corked datagram keeps the interface but not the source of `IPV6_PKTINFO`.
                if more && self.proto == Proto::Udp {
                    s.corked = Some((dst, port, scope, msg.data.clone()));
                    return Ok(msg.data.len());
                }
                self.send_to(&mut s, dst, port, scope, saddr, &msg.data)?;
            }
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
            return self.recv_error(len);
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
                    addr: Some(sockaddr::make_in(self.af(), &src, port, scope)),
                    flags: trunc,
                    control: info
                        .map(|i| if i.v4 { control4(&s, &i) } else { control6(&s, &i) })
                        .unwrap_or_default(),
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
        sockaddr::make_in(self.af(), &s.local, port, stack6::scope_of(&s.local, s.oif))
    }

    fn peer_name(&self) -> Result<Vec<u8>> {
        let s = self.state.lock();
        let (a, p) = s.remote.ok_or(Errno::ENOTCONN)?;
        Ok(sockaddr::make_in(self.af(), &a, p, stack6::scope_of(&a, s.oif)))
    }

    fn get_option(&self, level: u32, name: u32) -> Result<Vec<u8>> {
        let mut s = self.state.lock();
        match level {
            SOL_SOCKET => Ok(match name {
                SO_TYPE => int(self.kind() as i32),
                SO_DOMAIN => int(self.af() as i32),
                SO_PROTOCOL => int(self.protocol() as i32),
                SO_ERROR => int(s.error.take().map_or(0, |e| i32::from(e.get()))),
                SO_ACCEPTCONN => int(0),
                SO_COOKIE => self.ino.to_ne_bytes().to_vec(),
                SO_BINDTODEVICE | SO_BINDTOIFINDEX => stack::bound_device(s.oif, name),
                _ => s.options.get(name)?,
            }),
            IPPROTO_IP => Ok(match name {
                IP_TTL => int(i32::from(s.ttl.unwrap_or_else(rk_net::sysctl::default_ttl))),
                IP_TOS => int(i32::from(s.tos)),
                IP_RECVERR => int(i32::from(s.recverr)),
                IP_PKTINFO => int(i32::from(s.pktinfo)),
                IP_RECVTTL => int(i32::from(s.recvttl)),
                IP_RECVTOS => int(i32::from(s.recvtos)),
                IP_HDRINCL => int(i32::from(s.hdrincl)),
                IP_MTU_DISCOVER => int(s.mtu_discover),
                IP_MULTICAST_TTL => int(s.multicast_ttl),
                IP_MULTICAST_LOOP => int(i32::from(s.multicast_loop)),
                // `do_ip_getsockopt` gives the address, and at most 4 bytes.
                IP_MULTICAST_IF => s.mc_addr.to_vec(),
                IP_MULTICAST_ALL => int(i32::from(s.mc_all)),
                IP_BIND_ADDRESS_NO_PORT => int(i32::from(s.bind_no_port)),
                _ => return Err(Errno::ENOPROTOOPT),
            }),
            IPPROTO_IPV6 if self.af() == AF_INET6 => self.get_option6(&s, name),
            SOL_RAW if self.af() == AF_INET6 && name == IPV6_CHECKSUM => self.get_option6(&s, name),
            SOL_ICMPV6 if self.af() == AF_INET6 && self.proto == Proto::Raw(PROTO_ICMPV6) => {
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
            // An IPv4 socket gives the other levels to `ip_getsockopt` of Linux, which gives
            // `EOPNOTSUPP`. The level of the transport protocol and IPv6 give `ENOPROTOOPT`.
            IPPROTO_TCP if self.proto == Proto::Tcp => Err(Errno::ENOPROTOOPT),
            IPPROTO_UDP if self.proto == Proto::Udp && name == UDP_CORK => {
                Ok(int(i32::from(s.cork)))
            }
            IPPROTO_UDP if self.proto == Proto::Udp => Err(Errno::ENOPROTOOPT),
            _ if self.af() == AF_INET6 => Err(Errno::ENOPROTOOPT),
            _ => Err(Errno::EOPNOTSUPP),
        }
    }

    fn set_option(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
        let mut s = self.state.lock();
        match level {
            SOL_SOCKET => match name {
                SO_TYPE | SO_DOMAIN | SO_PROTOCOL | SO_ERROR | SO_ACCEPTCONN | SO_COOKIE => {
                    return Err(Errno::ENOPROTOOPT);
                }
                SO_BINDTODEVICE | SO_BINDTOIFINDEX => {
                    s.oif = stack::bind_device(s.oif, name, value)?;
                }
                _ => s.options.set(name, value)?,
            },
            IPPROTO_IP => self.set_option4(&mut s, name, value)?,
            IPPROTO_IPV6 if self.af() == AF_INET6 => self.set_option6(&mut s, name, value)?,
            IPPROTO_UDP if self.proto == Proto::Udp && name == UDP_CORK => {
                s.cork = int_of(value)? != 0;
                // The end of the cork sends the datagram that waits, as
                // `udp_lib_setsockopt` in net/ipv4/udp.c of Linux. An error goes nowhere.
                if !s.cork
                    && let Some((dst, port, scope, data)) = s.corked.take()
                {
                    let _ = self.send_to(&mut s, dst, port, scope, ip::ANY, &data);
                }
            }
            SOL_RAW if self.af() == AF_INET6 && name == IPV6_CHECKSUM => {
                if !matches!(self.proto, Proto::Raw(_)) {
                    return Err(Errno::ENOPROTOOPT);
                }
                Self::set_checksum6(&mut s, int_of(value)?)?;
            }
            SOL_ICMPV6 if self.af() == AF_INET6 && self.proto == Proto::Raw(PROTO_ICMPV6) => {
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
        if s.error.is_some() || !s.errqueue.is_empty() {
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
        let groups = core::mem::take(&mut s.groups6);
        let groups4 = core::mem::take(&mut s.groups4);
        drop(s);
        // The socket leaves its groups, as `ipv6_sock_mc_close` and `ip_mc_drop_socket` of
        // Linux.
        for (i, g) in &groups {
            crate::mcast6::leave(*i, g);
        }
        for m in &groups4 {
            crate::igmp::leave(m.ifindex, m.group);
        }
        stack::remove_socket(self.ino);
    }

    fn ioctl(&self, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Option<Result<usize>> {
        crate::ioctl::inet_ioctl(cmd, arg, mem)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

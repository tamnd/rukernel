//! The paths of the IPv6 packets: the input of IPv6, ICMPv6, neighbour discovery, the input of
//! UDP over IPv6, and the output of IPv6 through the neighbour table, as net/ipv6/ip6_input.c,
//! ip6_output.c, icmp.c, ndisc.c and udp.c of Linux.
//!
//! The stack has no fragments, no duplicate address detection and no multicast listener
//! discovery. An Ethernet device sends router solicitations when it goes up, and a router
//! advertisement gives the default route and the global address of the device (SLAAC).
//!
//! The locks are the same as in `stack`: the code holds at most one table lock at a time, and
//! the notifications of rtnetlink go out after the lock is free.

use crate::ip::{self, Ip};
use crate::ipv4::{PROTO_TCP, PROTO_UDP, UDP_HLEN, UdpHeader};
use crate::ipv6::{
    self, ALL_NODES, ALL_ROUTERS, Bad, HLEN, Header, NA_OVERRIDE, NA_SOLICITED, ND_OPT_PREFIX_INFO,
    ND_OPT_SOURCE_LL_ADDR, ND_OPT_TARGET_LL_ADDR, NDISC_NEIGHBOUR_ADVERTISEMENT,
    NDISC_NEIGHBOUR_SOLICITATION, NDISC_ROUTER_ADVERTISEMENT, NDISC_ROUTER_SOLICITATION, NEXT_NONE,
    PREFIX_AUTONOMOUS, PREFIX_ONLINK, PROTO_ICMPV6,
};
use crate::route::INFINITY;
use crate::route6::{Next6, PRIO_ADDRCONF, Route6, Table6};
use crate::socket::Info6;
use crate::stack::{self, PING_PORTS, UDP_PORTS, count, icmp_types, now_ms};
use crate::{addrconf, checksum, neigh};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::icmpv6::{
    ICMPV6_ADDR_UNREACH, ICMPV6_ADM_PROHIBITED, ICMPV6_DEST_UNREACH, ICMPV6_ECHO_REPLY,
    ICMPV6_ECHO_REQUEST, ICMPV6_NOROUTE, ICMPV6_NOT_NEIGHBOUR, ICMPV6_PARAMPROB, ICMPV6_PKT_TOOBIG,
    ICMPV6_POLICY_FAIL, ICMPV6_PORT_UNREACH, ICMPV6_REJECT_ROUTE, ICMPV6_TIME_EXCEED,
    ICMPV6_UNK_NEXTHDR,
};
use rk_abi::native::if_ether::ETH_P_IPV6;
use rk_abi::native::rtnetlink::RTPROT_RA;
use rk_frame::sync::SpinLock;
use rk_net::buf::{HEADROOM, NetBuf};
use rk_net::consts::AF_INET6;
use rk_net::dev::{self, LinkKind, NetDevice};
use rk_net::ether::{EthHeader, MacAddr};
use rk_net::ns::PerNet;
use rk_vfs::inode::Result;

/// The IPv6 addresses and routes.
pub(crate) static ROUTES6: PerNet<SpinLock<Table6>> = PerNet::new(|| SpinLock::new(Table6::new()));
/// The neighbour table of IPv6. A packet that waits has its IPv6 header and no link header.
static NEIGH6: PerNet<SpinLock<neigh::Table<NetBuf, Ip>>> =
    PerNet::new(|| SpinLock::new(neigh::Table::new()));
/// The devices that send router solicitations: the count that went out and the time of the
/// next one in milliseconds.
static SOLICIT: PerNet<SpinLock<BTreeMap<u32, (u32, u64)>>> =
    PerNet::new(|| SpinLock::new(BTreeMap::new()));
/// The time of the next check of the lifetimes of the addresses and routes.
static NEXT_EXPIRE: PerNet<AtomicU64> = PerNet::new(|| AtomicU64::new(0));

/// The count of router solicitations, `rtr_solicits` of Linux.
const RTR_SOLICITS: u32 = 3;
/// The time between two router solicitations, `rtr_solicit_interval` of Linux.
const RTR_SOLICIT_INTERVAL_MS: u64 = 4000;
/// The hop limit of the messages of neighbour discovery, as RFC 4861.
const ND_HOPS: u8 = 255;

const ECHO_REQUEST: u8 = ICMPV6_ECHO_REQUEST as u8;
const ECHO_REPLY: u8 = ICMPV6_ECHO_REPLY as u8;
const DEST_UNREACH: u8 = ICMPV6_DEST_UNREACH as u8;
const PKT_TOOBIG: u8 = ICMPV6_PKT_TOOBIG as u8;
const TIME_EXCEED: u8 = ICMPV6_TIME_EXCEED as u8;
const PARAMPROB: u8 = ICMPV6_PARAMPROB as u8;

/// The counters of IPv6, as the lines of /proc/net/snmp6.
pub(crate) struct Counters6 {
    /// The IPv6 packets that the stack received, `Ip6InReceives`.
    pub in_receives: AtomicU64,
    /// The packets with a bad header.
    pub in_hdr_errors: AtomicU64,
    /// The packets to an address that is not local. The stack does not forward.
    pub in_addr_errors: AtomicU64,
    /// The packets of a protocol without a handler or a raw socket.
    pub in_unknown_protos: AtomicU64,
    /// The packets shorter than their payload length.
    pub in_truncated: AtomicU64,
    /// The packets that went to a protocol or a raw socket.
    pub in_delivers: AtomicU64,
    /// The packets that the stack sent.
    pub out_requests: AtomicU64,
    /// The packets without a route.
    pub out_no_routes: AtomicU64,
    /// The fragments that the stack dropped, because it has no reassembly.
    pub reasm_fails: AtomicU64,
    /// The multicast packets that the stack received.
    pub in_mcast: AtomicU64,
    /// The multicast packets that the stack sent.
    pub out_mcast: AtomicU64,
    /// The bytes that the stack received.
    pub in_octets: AtomicU64,
    /// The bytes that the stack sent.
    pub out_octets: AtomicU64,
    /// The bytes of the received multicast packets.
    pub in_mcast_octets: AtomicU64,
    /// The bytes of the sent multicast packets.
    pub out_mcast_octets: AtomicU64,
    /// The packets that went to a device.
    pub out_transmits: AtomicU64,
    /// The ICMPv6 messages that the stack received.
    pub icmp_in: AtomicU64,
    /// The ICMPv6 messages that were too short or had a bad checksum.
    pub icmp_in_errors: AtomicU64,
    /// The ICMPv6 messages with a bad checksum.
    pub icmp_in_csum_errors: AtomicU64,
    /// The ICMPv6 messages that the stack sent.
    pub icmp_out: AtomicU64,
    /// The ICMPv6 messages that could not go out.
    pub icmp_out_errors: AtomicU64,
    /// The received ICMPv6 messages by type.
    pub icmp_in_type: Box<[AtomicU64]>,
    /// The sent ICMPv6 messages by type.
    pub icmp_out_type: Box<[AtomicU64]>,
    /// The datagrams that a UDP socket took.
    pub udp_in: AtomicU64,
    /// The datagrams to a port without a socket.
    pub udp_no_ports: AtomicU64,
    /// The datagrams with a bad checksum or length.
    pub udp_in_errors: AtomicU64,
    /// The datagrams that a full receive buffer dropped.
    pub udp_rcvbuf_errors: AtomicU64,
    /// The datagrams with a bad checksum.
    pub udp_in_csum_errors: AtomicU64,
    /// The datagrams that the UDP sockets sent.
    pub udp_out: AtomicU64,
}

impl rk_net::ns::Clear for Counters6 {
    fn clear(&self, _fresh: Self) {
        self.in_receives.store(0, Ordering::Relaxed);
        self.in_hdr_errors.store(0, Ordering::Relaxed);
        self.in_addr_errors.store(0, Ordering::Relaxed);
        self.in_unknown_protos.store(0, Ordering::Relaxed);
        self.in_truncated.store(0, Ordering::Relaxed);
        self.in_delivers.store(0, Ordering::Relaxed);
        self.out_requests.store(0, Ordering::Relaxed);
        self.out_no_routes.store(0, Ordering::Relaxed);
        self.reasm_fails.store(0, Ordering::Relaxed);
        self.in_mcast.store(0, Ordering::Relaxed);
        self.out_mcast.store(0, Ordering::Relaxed);
        self.in_octets.store(0, Ordering::Relaxed);
        self.out_octets.store(0, Ordering::Relaxed);
        self.in_mcast_octets.store(0, Ordering::Relaxed);
        self.out_mcast_octets.store(0, Ordering::Relaxed);
        self.out_transmits.store(0, Ordering::Relaxed);
        self.icmp_in.store(0, Ordering::Relaxed);
        self.icmp_in_errors.store(0, Ordering::Relaxed);
        self.icmp_in_csum_errors.store(0, Ordering::Relaxed);
        self.icmp_out.store(0, Ordering::Relaxed);
        self.icmp_out_errors.store(0, Ordering::Relaxed);
        for c in self.icmp_in_type.iter() {
            c.store(0, Ordering::Relaxed);
        }
        for c in self.icmp_out_type.iter() {
            c.store(0, Ordering::Relaxed);
        }
        self.udp_in.store(0, Ordering::Relaxed);
        self.udp_no_ports.store(0, Ordering::Relaxed);
        self.udp_in_errors.store(0, Ordering::Relaxed);
        self.udp_rcvbuf_errors.store(0, Ordering::Relaxed);
        self.udp_in_csum_errors.store(0, Ordering::Relaxed);
        self.udp_out.store(0, Ordering::Relaxed);
    }
}

/// The counters of IPv6.
pub(crate) static COUNTERS6: PerNet<Counters6> = PerNet::new(new_counters6);

/// The counters of a new namespace.
fn new_counters6() -> Counters6 {
    Counters6 {
        in_receives: AtomicU64::new(0),
        in_hdr_errors: AtomicU64::new(0),
        in_addr_errors: AtomicU64::new(0),
        in_unknown_protos: AtomicU64::new(0),
        in_truncated: AtomicU64::new(0),
        in_delivers: AtomicU64::new(0),
        out_requests: AtomicU64::new(0),
        out_no_routes: AtomicU64::new(0),
        reasm_fails: AtomicU64::new(0),
        in_mcast: AtomicU64::new(0),
        out_mcast: AtomicU64::new(0),
        in_octets: AtomicU64::new(0),
        out_octets: AtomicU64::new(0),
        in_mcast_octets: AtomicU64::new(0),
        out_mcast_octets: AtomicU64::new(0),
        out_transmits: AtomicU64::new(0),
        icmp_in: AtomicU64::new(0),
        icmp_in_errors: AtomicU64::new(0),
        icmp_in_csum_errors: AtomicU64::new(0),
        icmp_out: AtomicU64::new(0),
        icmp_out_errors: AtomicU64::new(0),
        icmp_in_type: icmp_types(),
        icmp_out_type: icmp_types(),
        udp_in: AtomicU64::new(0),
        udp_no_ports: AtomicU64::new(0),
        udp_in_errors: AtomicU64::new(0),
        udp_rcvbuf_errors: AtomicU64::new(0),
        udp_in_csum_errors: AtomicU64::new(0),
        udp_out: AtomicU64::new(0),
    }
}

fn add(c: &AtomicU64, n: usize) {
    c.fetch_add(n as u64, Ordering::Relaxed);
}

/// The scope ID of an address from the interface `ifindex`: the interface for a link local
/// address, else 0.
pub(crate) fn scope_of(a: &Ip, ifindex: u32) -> u32 {
    if ipv6::needs_scope(a) { ifindex } else { 0 }
}

/// Finds the route to `dst`, as `ip6_route_output` of Linux. `oif` is the interface of the
/// scope ID or of the socket, or 0.
pub(crate) fn route(dst: &Ip, oif: u32) -> Result<Next6> {
    let r = ROUTES6.lock().lookup(dst, oif);
    if r.is_err() {
        count(&COUNTERS6.out_no_routes);
    }
    r
}

/// Removes the neighbours of an interface, as `ndisc_ifdown` of Linux.
pub(crate) fn flush_neigh(ifindex: u32) {
    NEIGH6.lock().flush(ifindex);
}

/// The neighbours of IPv6, as `neighbours` of `stack`.
pub(crate) fn neighbours() -> Vec<neigh::Info<Ip>> {
    NEIGH6.lock().entries(now_ms())
}

/// The route and the source address of a packet of either family to `dst`, and the MTU of the
/// path. TCP uses this for both families.
pub(crate) struct Path {
    /// The source address. An IPv4 route gives an IPv4-mapped address.
    pub src: Ip,
    /// The MTU of the path.
    pub mtu: u32,
}

/// Finds the route of a packet of either family to `dst`.
pub(crate) fn path(dst: &Ip, oif: u32) -> Result<Path> {
    let mtu_of = |ifindex| dev::by_index(ifindex).map_or(0, |d| d.mtu());
    match ip::v4(dst) {
        Some(d) => {
            let n = stack::route(d)?;
            Ok(Path { src: ip::mapped(n.src), mtu: mtu_of(n.ifindex) })
        }
        None => {
            let n = route(dst, oif)?;
            let dev = mtu_of(n.ifindex);
            Ok(Path { src: n.src, mtu: if n.mtu != 0 { n.mtu.min(dev) } else { dev } })
        }
    }
}

/// Sends a packet of either family with the payload `payload`: IPv4 for two IPv4-mapped
/// addresses, else IPv6. `hops` is the time to live or the hop limit, and `tclass` the type of
/// service or the traffic class.
pub(crate) fn output_ip(out: &Out6, oif: u32, payload: &[u8]) -> Result<()> {
    match (ip::v4(&out.src), ip::v4(&out.dst)) {
        (Some(src), Some(dst)) => {
            let next = stack::route(dst)?;
            let o = stack::Out { src, dst, protocol: out.next, ttl: out.hops, tos: out.tclass };
            stack::output(&next, &o, payload)
        }
        (None, None) => output(&route(&out.dst, oif)?, out, payload),
        _ => Err(Errno::EAFNOSUPPORT),
    }
}

/// The things that an IPv6 packet needs to go out.
pub(crate) struct Out6 {
    /// The source address.
    pub src: Ip,
    /// The destination address.
    pub dst: Ip,
    /// The protocol of the payload.
    pub next: u8,
    /// The hop limit.
    pub hops: u8,
    /// The traffic class.
    pub tclass: u8,
    /// The routing header between the IPv6 header and the payload, or nothing. Its next header
    /// is `next`.
    pub ext: Vec<u8>,
}

/// Sends a packet with the payload `payload` on the route `next`, as `ip6_xmit` of Linux. The
/// packet does not get fragments: a packet larger than the MTU gives `EMSGSIZE`.
pub(crate) fn output(next: &Next6, out: &Out6, payload: &[u8]) -> Result<()> {
    let dev = dev::by_index(next.ifindex).ok_or(Errno::ENETUNREACH)?;
    let mtu = if next.mtu != 0 { next.mtu.min(dev.mtu()) } else { dev.mtu() };
    let len = out.ext.len() + payload.len();
    if len > usize::from(u16::MAX) || HLEN + len > mtu as usize {
        return Err(Errno::EMSGSIZE);
    }
    // The fixed header names the routing header, as `ipv6_push_nfrag_opts`.
    let first = if out.ext.is_empty() { out.next } else { ipv6::NEXT_ROUTING };
    let mut h = Header::new(out.src, out.dst, first, len);
    h.hops = out.hops;
    h.tclass = out.tclass;
    let mut buf = NetBuf::new(HEADROOM, HLEN + len);
    buf.extend_from_slice(&h.to_bytes());
    buf.extend_from_slice(&out.ext);
    buf.extend_from_slice(payload);
    if out.next == PROTO_ICMPV6 {
        count_icmp_out(payload);
    }
    count(&COUNTERS6.out_requests);
    transmit(&dev, next, buf)
}

/// Sends a packet that has its IPv6 header, for a raw socket with `IPV6_HDRINCL`.
pub(crate) fn output_raw(next: &Next6, packet: &[u8]) -> Result<()> {
    let dev = dev::by_index(next.ifindex).ok_or(Errno::ENETUNREACH)?;
    if packet.len() > dev.mtu() as usize {
        return Err(Errno::EMSGSIZE);
    }
    count(&COUNTERS6.out_requests);
    transmit(&dev, next, NetBuf::from_slice(packet))
}

/// Counts an ICMPv6 message that goes out, as `icmp6_msg_outstats` of Linux.
fn count_icmp_out(msg: &[u8]) {
    if let Some(&t) = msg.first() {
        count(&COUNTERS6.icmp_out);
        count(&COUNTERS6.icmp_out_type[usize::from(t)]);
    }
}

fn ether(dev: &NetDevice, dst: MacAddr) -> EthHeader {
    EthHeader { dst, src: dev.mac(), ethertype: ETH_P_IPV6 as u16 }
}

/// Gives a packet to the link: the loopback device, a multicast group, or a neighbour.
fn transmit(dev: &NetDevice, next: &Next6, mut buf: NetBuf) -> Result<()> {
    count(&COUNTERS6.out_transmits);
    add(&COUNTERS6.out_octets, buf.len());
    if dev.kind() == LinkKind::Loopback {
        ether(dev, MacAddr::ZERO).push(&mut buf);
        return dev.transmit(buf);
    }
    let dst: Ip = buf.data().get(24..40).and_then(|d| d.try_into().ok()).unwrap_or(next.hop);
    if ipv6::is_multicast(&dst) {
        count(&COUNTERS6.out_mcast);
        add(&COUNTERS6.out_mcast_octets, buf.len());
        ether(dev, ipv6::multicast_mac(&dst)).push(&mut buf);
        return dev.transmit(buf);
    }
    let key = (dev.ifindex(), next.hop);
    let r = NEIGH6.lock().resolve(key, now_ms(), buf);
    match r {
        neigh::Resolve::Send { mut packet, mac, probe } => {
            if probe {
                solicit(dev, &next.hop);
            }
            ether(dev, mac).push(&mut packet);
            dev.transmit(packet)
        }
        neigh::Resolve::Wait { probe } => {
            if probe {
                solicit(dev, &next.hop);
            }
            Ok(())
        }
    }
}

/// Sends a message of neighbour discovery from `src` to `dst` at the link address `mac`, with
/// the hop limit 255. The function computes the checksum.
fn send_ndisc(dev: &NetDevice, src: &Ip, dst: &Ip, mac: MacAddr, mut msg: Vec<u8>) {
    let sum = checksum::upper(src, dst, PROTO_ICMPV6, &msg);
    msg[2..4].copy_from_slice(&sum.to_be_bytes());
    let mut h = Header::new(*src, *dst, PROTO_ICMPV6, msg.len());
    h.hops = ND_HOPS;
    let mut buf = NetBuf::new(HEADROOM, HLEN + msg.len());
    buf.extend_from_slice(&h.to_bytes());
    buf.extend_from_slice(&msg);
    count_icmp_out(&msg);
    count(&COUNTERS6.out_requests);
    count(&COUNTERS6.out_transmits);
    ether(dev, mac).push(&mut buf);
    // A lost message is like a lost frame: the timers send it again.
    let _ = dev.transmit(buf);
}

/// The option of the link address `kind` of a message of neighbour discovery, as
/// `ndisc_parse_options` of Linux.
fn link_option(mut opts: &[u8], kind: u8) -> Option<MacAddr> {
    while opts.len() >= 8 {
        let len = usize::from(opts[1]) * 8;
        if len == 0 || len > opts.len() {
            return None;
        }
        if opts[0] == kind {
            return Some(MacAddr(opts[2..8].try_into().ok()?));
        }
        opts = &opts[len..];
    }
    None
}

/// Adds the option `kind` with the link address of `dev` to `msg`.
fn put_link_option(msg: &mut Vec<u8>, kind: u8, dev: &NetDevice) {
    msg.extend_from_slice(&[kind, 1]);
    msg.extend_from_slice(&dev.mac().0);
}

/// Sends a neighbour solicitation for `target` on `dev`, as `ndisc_solicit` of Linux.
fn solicit(dev: &NetDevice, target: &Ip) {
    let Some(src) = ROUTES6.lock().select_src(target, dev.ifindex()) else { return };
    let dst = ipv6::solicited_node(target);
    let mut msg = Vec::with_capacity(32);
    msg.extend_from_slice(&[NDISC_NEIGHBOUR_SOLICITATION, 0, 0, 0, 0, 0, 0, 0]);
    msg.extend_from_slice(target);
    put_link_option(&mut msg, ND_OPT_SOURCE_LL_ADDR, dev);
    send_ndisc(dev, &src, &dst, ipv6::multicast_mac(&dst), msg);
}

/// Sends a router solicitation on `dev`, as `ndisc_send_rs` of Linux. Without a link local
/// address the source is `::` and the message has no link address.
fn send_rs(dev: &NetDevice) {
    let ifindex = dev.ifindex();
    let src = ROUTES6
        .lock()
        .addrs_of(ifindex)
        .find(|a| ipv6::is_link_local(&a.addr))
        .map_or(ip::ANY, |a| a.addr);
    let mut msg = Vec::with_capacity(16);
    msg.extend_from_slice(&[NDISC_ROUTER_SOLICITATION, 0, 0, 0, 0, 0, 0, 0]);
    if src != ip::ANY {
        put_link_option(&mut msg, ND_OPT_SOURCE_LL_ADDR, dev);
    }
    send_ndisc(dev, &src, &ALL_ROUTERS, ipv6::multicast_mac(&ALL_ROUTERS), msg);
}

/// Starts the router solicitations of a device that went up, as `addrconf_dad_completed` of
/// Linux. The first one goes out at the next poll.
pub(crate) fn start_solicit(ifindex: u32) {
    SOLICIT.lock().insert(ifindex, (0, now_ms()));
}

/// Stops the router solicitations of a device.
pub(crate) fn stop_solicit(ifindex: u32) {
    SOLICIT.lock().remove(&ifindex);
}

/// Records the link address of a neighbour and sends the packets that waited for it.
fn learn(dev: &NetDevice, addr: &Ip, mac: MacAddr, create: bool) {
    let waiting = NEIGH6.lock().update((dev.ifindex(), *addr), mac, now_ms(), create);
    for mut packet in waiting {
        ether(dev, mac).push(&mut packet);
        let _ = dev.transmit(packet);
    }
}

/// Takes an IPv6 packet, as `ipv6_rcv` and `ip6_input` of Linux. The stack does not forward,
/// and it drops the fragments.
pub(crate) fn input(dev: &NetDevice, mut frame: NetBuf) {
    count(&COUNTERS6.in_receives);
    add(&COUNTERS6.in_octets, frame.len());
    let h = match Header::parse(frame.data()) {
        Ok(h) => h,
        Err(Bad::Fragment) => return count(&COUNTERS6.reasm_fails),
        Err(Bad::Length) => return count(&COUNTERS6.in_truncated),
        Err(Bad::Header) => return count(&COUNTERS6.in_hdr_errors),
    };
    frame.trim(HLEN + usize::from(h.payload_len));
    let ifindex = dev.ifindex();
    let loopback = dev.kind() == LinkKind::Loopback;
    // A multicast source is not valid, and `::1` from a real link is a martian, as `ipv6_rcv`.
    if ipv6::is_multicast(&h.src) || (!loopback && (h.src == ip::LOOPBACK || h.dst == ip::LOOPBACK))
    {
        return count(&COUNTERS6.in_addr_errors);
    }
    let mcast = ipv6::is_multicast(&h.dst);
    let ours = {
        let t = ROUTES6.lock();
        if mcast { loopback || t.takes_multicast(ifindex, &h.dst) } else { t.is_local(&h.dst) }
    };
    if !ours {
        return count(&COUNTERS6.in_addr_errors);
    }
    if mcast {
        count(&COUNTERS6.in_mcast);
        add(&COUNTERS6.in_mcast_octets, frame.len());
    }
    let packet = frame.data();
    let payload = &packet[h.l4..];
    let raw = stack::raw_sockets(AF_INET6, h.protocol);
    for sock in &raw {
        sock.deliver_raw6(&h, ifindex, payload);
    }
    let known = matches!(h.protocol, PROTO_ICMPV6 | PROTO_UDP | PROTO_TCP | NEXT_NONE);
    if known || !raw.is_empty() {
        count(&COUNTERS6.in_delivers);
    } else {
        count(&COUNTERS6.in_unknown_protos);
    }
    match h.protocol {
        PROTO_ICMPV6 => icmp_input(dev, &h, payload, mcast),
        PROTO_UDP => udp_input(&h, ifindex, packet, mcast),
        PROTO_TCP => crate::tcp::input(h.src, h.dst, payload, mcast),
        NEXT_NONE => {}
        _ if raw.is_empty() => {
            icmp_error(&h, ifindex, packet, PARAMPROB, ICMPV6_UNK_NEXTHDR as u8, h.nh as u32);
        }
        _ => {}
    }
}

/// The error of an ICMPv6 error message, as `icmpv6_err_convert` of Linux, and tells if the
/// error is hard. A soft error goes only to a socket with `IPV6_RECVERR`.
fn icmp_errno(kind: u8, code: u8) -> (Errno, bool) {
    match (kind, u32::from(code)) {
        (DEST_UNREACH, ICMPV6_NOROUTE) => (Errno::ENETUNREACH, false),
        (DEST_UNREACH, ICMPV6_ADM_PROHIBITED | ICMPV6_POLICY_FAIL | ICMPV6_REJECT_ROUTE) => {
            (Errno::EACCES, true)
        }
        (DEST_UNREACH, ICMPV6_NOT_NEIGHBOUR | ICMPV6_ADDR_UNREACH) => (Errno::EHOSTUNREACH, false),
        (DEST_UNREACH, ICMPV6_PORT_UNREACH) => (Errno::ECONNREFUSED, true),
        (PKT_TOOBIG, _) => (Errno::EMSGSIZE, false),
        (PARAMPROB, _) => (Errno::EPROTO, true),
        _ => (Errno::EHOSTUNREACH, false),
    }
}

/// Takes an ICMPv6 message, as `icmpv6_rcv` of Linux.
fn icmp_input(dev: &NetDevice, h: &Header, msg: &[u8], mcast: bool) {
    count(&COUNTERS6.icmp_in);
    if msg.len() < 4 {
        return count(&COUNTERS6.icmp_in_errors);
    }
    if checksum::upper(&h.src, &h.dst, PROTO_ICMPV6, msg) != 0 {
        count(&COUNTERS6.icmp_in_csum_errors);
        return count(&COUNTERS6.icmp_in_errors);
    }
    count(&COUNTERS6.icmp_in_type[usize::from(msg[0])]);
    let ifindex = dev.ifindex();
    match msg[0] {
        ECHO_REQUEST if msg.len() >= 8 => {
            // A reply to a multicast request comes from an address of the device, as
            // `icmpv6_echo_reply`.
            let src = if mcast { ROUTES6.lock().select_src(&h.src, ifindex) } else { Some(h.dst) };
            let Some(src) = src else { return };
            let mut reply = msg.to_vec();
            reply[0] = ECHO_REPLY;
            send_icmp(&src, &h.src, ifindex, reply);
        }
        ECHO_REPLY if msg.len() >= 8 => {
            let id = u16::from_be_bytes([msg[4], msg[5]]);
            if let Some(sock) = stack::find_socket(&PING_PORTS, id, h.dst, h.src, 0) {
                let info = Some(Info6::of(h, ifindex));
                sock.deliver(h.src, scope_of(&h.src, ifindex), 0, msg.to_vec(), info);
            }
        }
        DEST_UNREACH | PKT_TOOBIG | TIME_EXCEED | PARAMPROB if msg.len() >= 8 => {
            error_input(msg[0], msg[1], &msg[8..]);
        }
        NDISC_NEIGHBOUR_SOLICITATION => ndisc_ns(dev, h, msg),
        NDISC_NEIGHBOUR_ADVERTISEMENT => ndisc_na(dev, h, msg),
        NDISC_ROUTER_ADVERTISEMENT => ndisc_ra(dev, h, msg),
        _ => {}
    }
}

/// Gives the error of an ICMPv6 error message to the socket of the packet in it, as
/// `__udp6_lib_err` and `ping_err` of Linux. `inner` is the start of the packet that failed.
fn error_input(kind: u8, code: u8, inner: &[u8]) {
    let Some(ih) = Header::parse_loose(inner) else { return };
    let Some(l4) = inner.get(ih.l4..ih.l4 + 8) else { return };
    let (err, hard) = icmp_errno(kind, code);
    let sock = match ih.protocol {
        PROTO_UDP => {
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            stack::find_socket(&UDP_PORTS, sport, ih.src, ih.dst, dport)
        }
        PROTO_ICMPV6 if l4[0] == ECHO_REQUEST => {
            let id = u16::from_be_bytes([l4[4], l4[5]]);
            stack::find_socket(&PING_PORTS, id, ih.src, ih.dst, 0)
        }
        _ => None,
    };
    if let Some(sock) = sock {
        sock.icmp_error(err, hard, ih.dst);
    }
}

/// Sends an ICMPv6 message from `src` to `dst`, and computes its checksum.
fn send_icmp(src: &Ip, dst: &Ip, ifindex: u32, mut msg: Vec<u8>) {
    let Ok(next) = route(dst, scope_of(dst, ifindex)) else {
        return count(&COUNTERS6.icmp_out_errors);
    };
    msg[2..4].fill(0);
    let sum = checksum::upper(src, dst, PROTO_ICMPV6, &msg);
    msg[2..4].copy_from_slice(&sum.to_be_bytes());
    let out = Out6 {
        src: *src,
        dst: *dst,
        next: PROTO_ICMPV6,
        hops: ipv6::DEFAULT_HOPS,
        tclass: 0,
        ext: Vec::new(),
    };
    // An ICMPv6 message that the stack makes is not for a socket, and a lost one is not an
    // error.
    if output(&next, &out, &msg).is_err() {
        count(&COUNTERS6.icmp_out_errors);
    }
}

/// Sends an ICMPv6 error about the packet `packet` with the header `h`, as `icmp6_send` of
/// Linux. The message fits in the minimum MTU of 1280 bytes. The stack sends no error about a
/// multicast packet or about an ICMPv6 error.
pub(crate) fn icmp_error(h: &Header, ifindex: u32, packet: &[u8], kind: u8, code: u8, info: u32) {
    if h.protocol == PROTO_ICMPV6 && packet.get(h.l4).is_some_and(|&t| t < ECHO_REQUEST) {
        return;
    }
    if ipv6::is_multicast(&h.dst) || h.src == ip::ANY || ipv6::is_multicast(&h.src) {
        return;
    }
    let data = &packet[..packet.len().min(ipv6::MIN_MTU - HLEN - 8)];
    let mut msg = Vec::with_capacity(8 + data.len());
    msg.extend_from_slice(&[kind, code, 0, 0]);
    msg.extend_from_slice(&info.to_be_bytes());
    msg.extend_from_slice(data);
    send_icmp(&h.dst, &h.src, ifindex, msg);
}

/// Takes a neighbour solicitation, as `ndisc_recv_ns` of Linux: it learns the address of the
/// sender and answers for a local address.
fn ndisc_ns(dev: &NetDevice, h: &Header, msg: &[u8]) {
    if h.hops != ND_HOPS || msg.len() < 24 || msg[1] != 0 {
        return;
    }
    let Ok(target) = <Ip>::try_from(&msg[8..24]) else { return };
    if ipv6::is_multicast(&target) {
        return;
    }
    let ifindex = dev.ifindex();
    let ours = ROUTES6.lock().addrs_of(ifindex).any(|a| a.addr == target);
    let slla = link_option(&msg[24..], ND_OPT_SOURCE_LL_ADDR);
    // A probe of duplicate address detection has the source `::` and no link address.
    let dad = h.src == ip::ANY;
    if dad && slla.is_some() {
        return;
    }
    if let Some(mac) = slla {
        learn(dev, &h.src, mac, ours);
    }
    if !ours {
        return;
    }
    let (dst, flags) =
        if dad { (ALL_NODES, NA_OVERRIDE) } else { (h.src, NA_SOLICITED | NA_OVERRIDE) };
    let mac = if dad {
        Some(ipv6::multicast_mac(&ALL_NODES))
    } else {
        slla.or_else(|| NEIGH6.lock().lookup((ifindex, h.src)))
    };
    let Some(mac) = mac else { return };
    let mut na = Vec::with_capacity(32);
    na.extend_from_slice(&[NDISC_NEIGHBOUR_ADVERTISEMENT, 0, 0, 0, flags, 0, 0, 0]);
    na.extend_from_slice(&target);
    put_link_option(&mut na, ND_OPT_TARGET_LL_ADDR, dev);
    send_ndisc(dev, &target, &dst, mac, na);
}

/// Takes a neighbour advertisement, as `ndisc_recv_na` of Linux: it gives the link address to
/// an entry that waits.
fn ndisc_na(dev: &NetDevice, h: &Header, msg: &[u8]) {
    if h.hops != ND_HOPS || msg.len() < 24 || msg[1] != 0 {
        return;
    }
    let Ok(target) = <Ip>::try_from(&msg[8..24]) else { return };
    if ipv6::is_multicast(&target) {
        return;
    }
    if let Some(mac) = link_option(&msg[24..], ND_OPT_TARGET_LL_ADDR) {
        learn(dev, &target, mac, false);
    }
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// The time in milliseconds when a lifetime of `secs` seconds from `now` ends, or `None` for
/// the infinite lifetime.
fn expiry(now: u64, secs: u32) -> Option<u64> {
    (secs != INFINITY).then(|| now + u64::from(secs) * 1000)
}

/// Takes a router advertisement, as `ndisc_router_discovery` and `addrconf_prefix_rcv` of
/// Linux: the default route through the router, the routes of the prefixes on the link, and
/// an address of each prefix for SLAAC.
fn ndisc_ra(dev: &NetDevice, h: &Header, msg: &[u8]) {
    if h.hops != ND_HOPS
        || msg.len() < 16
        || msg[1] != 0
        || !ipv6::is_link_local(&h.src)
        || dev.kind() == LinkKind::Loopback
    {
        return;
    }
    let ifindex = dev.ifindex();
    stop_solicit(ifindex);
    let now = now_ms();
    let opts = &msg[16..];
    if let Some(mac) = link_option(opts, ND_OPT_SOURCE_LL_ADDR) {
        learn(dev, &h.src, mac, true);
    }
    let lifetime = u16::from_be_bytes([msg[6], msg[7]]);
    let mut r = Route6::new(ip::ANY, 0, Some(h.src), ifindex);
    r.protocol = RTPROT_RA as u8;
    r.addrconf = true;
    r.expires = Some(now + u64::from(lifetime) * 1000);
    addrconf::ra_route(r, lifetime == 0);
    let mut rest = opts;
    while rest.len() >= 8 {
        let len = usize::from(rest[1]) * 8;
        if len == 0 || len > rest.len() {
            break;
        }
        let o = &rest[..len];
        rest = &rest[len..];
        if o[0] != ND_OPT_PREFIX_INFO || o.len() < 32 {
            continue;
        }
        let (plen, flags) = (o[2], o[3]);
        let (valid, preferred) = (be32(&o[4..8]), be32(&o[8..12]));
        let Ok(prefix) = <Ip>::try_from(&o[16..32]) else { continue };
        if plen > 128 || preferred > valid {
            continue;
        }
        let prefix = ipv6::prefix(&prefix, plen);
        if ipv6::is_link_local(&prefix) || ipv6::is_multicast(&prefix) {
            continue;
        }
        // The route of the prefix comes first, so that the address does not add a route of its
        // own without a lifetime.
        if flags & PREFIX_ONLINK != 0 {
            let mut p = Route6::new(prefix, plen, None, ifindex);
            p.priority = PRIO_ADDRCONF;
            p.addrconf = true;
            p.expires = expiry(now, valid);
            addrconf::ra_route(p, valid == 0);
        }
        if flags & PREFIX_AUTONOMOUS != 0 && plen == 64 && valid != 0 {
            let addr = ipv6::with_id(&prefix, ipv6::eui64(dev.mac()));
            addrconf::slaac(ifindex, addr, plen, valid, preferred);
        }
    }
}

/// Takes a UDP datagram over IPv6, as `udpv6_rcv` of Linux. `packet` has the IPv6 header.
/// IPv6 needs the checksum of UDP.
fn udp_input(h: &Header, ifindex: u32, packet: &[u8], mcast: bool) {
    let d = &packet[h.l4..];
    let Some(u) = UdpHeader::parse(d) else { return count(&COUNTERS6.udp_in_errors) };
    let d = &d[..usize::from(u.len)];
    if u.check == 0 || checksum::upper(&h.src, &h.dst, PROTO_UDP, d) != 0 {
        count(&COUNTERS6.udp_in_csum_errors);
        return count(&COUNTERS6.udp_in_errors);
    }
    let Some(sock) = stack::find_socket(&UDP_PORTS, u.dst, h.dst, h.src, u.src) else {
        count(&COUNTERS6.udp_no_ports);
        if !mcast {
            let code = ICMPV6_PORT_UNREACH as u8;
            icmp_error(h, ifindex, packet, DEST_UNREACH, code, 0);
        }
        return;
    };
    let info = Some(Info6::of(h, ifindex));
    if sock.deliver(h.src, scope_of(&h.src, ifindex), u.src, d[UDP_HLEN..].to_vec(), info) {
        count(&COUNTERS6.udp_in);
    } else {
        count(&COUNTERS6.udp_rcvbuf_errors);
    }
}

/// Runs the timers of IPv6: the neighbour solicitations, the router solicitations and the
/// lifetimes of the addresses and the routes. The poll of the stack calls this.
pub(crate) fn tick() {
    let now = now_ms();
    let probes = {
        let mut neigh = NEIGH6.lock();
        if neigh.is_empty() { Vec::new() } else { neigh.tick(now) }
    };
    for (ifindex, addr) in probes {
        if let Some(d) = dev::by_index(ifindex) {
            solicit(&d, &addr);
        }
    }
    let due: Vec<u32> = {
        let mut s = SOLICIT.lock();
        let mut due = Vec::new();
        s.retain(|&ifindex, (sent, next)| {
            if *next > now {
                return true;
            }
            *sent += 1;
            *next = now + RTR_SOLICIT_INTERVAL_MS;
            due.push(ifindex);
            *sent < RTR_SOLICITS
        });
        due
    };
    for ifindex in due {
        if let Some(d) = dev::by_index(ifindex).filter(|d| d.is_up()) {
            send_rs(&d);
        }
    }
    // The lifetimes count in seconds, thus one check each second is enough.
    if NEXT_EXPIRE.load(Ordering::Relaxed) <= now {
        NEXT_EXPIRE.store(now + 1000, Ordering::Relaxed);
        addrconf::expire(now);
    }
}

/// Clears the tables of IPv6 of a namespace that stops.
pub(crate) fn ns_exit() {
    ROUTES6.reset();
    NEIGH6.reset();
    SOLICIT.reset();
    NEXT_EXPIRE.reset();
    COUNTERS6.reset();
}

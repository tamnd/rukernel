//! The paths of the IPv6 packets: the input of IPv6, ICMPv6, neighbour discovery, the input of
//! UDP over IPv6, and the output of IPv6 through the neighbour table, as net/ipv6/ip6_input.c,
//! ip6_output.c, icmp.c, ndisc.c and udp.c of Linux.
//!
//! A packet larger than the MTU goes out in fragments, and the input puts the fragments
//! together, as net/ipv6/ip6_output.c and reassembly.c of Linux. An Ethernet device sends router solicitations when it goes up,
//! and a router advertisement gives the default route and the global address of the device
//! (SLAAC). A new address goes through duplicate address detection, and the device sends an
//! MLD report when it joins the solicited node group of the address. `mcast6` has the groups and
//! the answers to the queries of MLD.
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
use crate::socket::{IcmpError, Info6};
use crate::stack::{self, PING_PORTS, UDP_PORTS, count, icmp_types, now_ms};
use crate::{addrconf, checksum, frag, mcast6, neigh};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::icmpv6::{
    ICMPV6_ADDR_UNREACH, ICMPV6_ADM_PROHIBITED, ICMPV6_DEST_UNREACH, ICMPV6_ECHO_REPLY,
    ICMPV6_ECHO_REQUEST, ICMPV6_EXC_HOPLIMIT, ICMPV6_HDR_FIELD, ICMPV6_NOROUTE,
    ICMPV6_NOT_NEIGHBOUR, ICMPV6_PARAMPROB, ICMPV6_PKT_TOOBIG, ICMPV6_POLICY_FAIL,
    ICMPV6_PORT_UNREACH, ICMPV6_REJECT_ROUTE, ICMPV6_TIME_EXCEED, ICMPV6_UNK_NEXTHDR,
};
use rk_abi::native::if_addr::{IFA_F_OPTIMISTIC, IFA_F_TENTATIVE};
use rk_abi::native::if_ether::ETH_P_IPV6;
use rk_abi::native::inet::{IPPROTO_IPIP, IPPROTO_IPV6};
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
/// The key of a queue of the reassembly: the source, the destination and the identification,
/// as `struct frag_v6_compare_key` of Linux.
type FragKey = (Ip, Ip, u32);
/// The queues of the reassembly of IPv6.
static FRAGS6: PerNet<SpinLock<frag::Reasm<FragKey>>> =
    PerNet::new(|| SpinLock::new(frag::Reasm::new()));
/// The identification of the next packet in fragments, as `ipv6_select_ident` of Linux.
static FRAG_ID: AtomicU32 = AtomicU32::new(1);
/// The time of the next check of the lifetimes of the addresses and routes.
static NEXT_EXPIRE: PerNet<AtomicU64> = PerNet::new(|| AtomicU64::new(0));
/// The addresses in duplicate address detection.
static DAD: PerNet<SpinLock<Vec<Dad>>> = PerNet::new(|| SpinLock::new(Vec::new()));

/// An address in duplicate address detection: the interface, the address, the probes that are
/// left to send and the time of the next step in milliseconds.
struct Dad {
    ifindex: u32,
    addr: Ip,
    probes: u32,
    next: u64,
}

/// The time between two probes, `RETRANS_TIMER` of Linux, in milliseconds.
const RETRANS_TIMER_MS: u64 = 1000;
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
/// The code of a parameter problem in a field of a header.
const HDR_FIELD: u8 = ICMPV6_HDR_FIELD as u8;
/// The code of a time exceeded message for the hop limit.
const EXC_HOPLIMIT: u8 = ICMPV6_EXC_HOPLIMIT as u8;

/// The counters of IPv6, as the lines of /proc/net/snmp6.
pub(crate) struct Counters6 {
    /// The IPv6 packets that the stack received, `Ip6InReceives`.
    pub in_receives: AtomicU64,
    /// The packets with a bad header.
    pub in_hdr_errors: AtomicU64,
    /// The packets to an address that is not local, when the host does not forward.
    pub in_addr_errors: AtomicU64,
    /// The packets that the host forwarded, `Ip6OutForwDatagrams`.
    pub out_forw_datagrams: AtomicU64,
    /// The packets that were too large to forward, `Ip6InTooBigErrors`.
    pub in_too_big_errors: AtomicU64,
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
    /// The failures of the reassembly: a bad fragment or a full table.
    pub reasm_fails: AtomicU64,
    /// The queues of the reassembly that timed out.
    pub reasm_timeout: AtomicU64,
    /// The fragments that went to the reassembly.
    pub reasm_reqds: AtomicU64,
    /// The packets that the reassembly completed.
    pub reasm_oks: AtomicU64,
    /// The packets that the stack sent in fragments.
    pub frag_oks: AtomicU64,
    /// The fragments that the stack made.
    pub frag_creates: AtomicU64,
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
        self.out_forw_datagrams.store(0, Ordering::Relaxed);
        self.in_too_big_errors.store(0, Ordering::Relaxed);
        self.in_unknown_protos.store(0, Ordering::Relaxed);
        self.in_truncated.store(0, Ordering::Relaxed);
        self.in_delivers.store(0, Ordering::Relaxed);
        self.out_requests.store(0, Ordering::Relaxed);
        self.out_no_routes.store(0, Ordering::Relaxed);
        self.reasm_fails.store(0, Ordering::Relaxed);
        self.reasm_timeout.store(0, Ordering::Relaxed);
        self.reasm_reqds.store(0, Ordering::Relaxed);
        self.reasm_oks.store(0, Ordering::Relaxed);
        self.frag_oks.store(0, Ordering::Relaxed);
        self.frag_creates.store(0, Ordering::Relaxed);
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
        out_forw_datagrams: AtomicU64::new(0),
        in_too_big_errors: AtomicU64::new(0),
        in_unknown_protos: AtomicU64::new(0),
        in_truncated: AtomicU64::new(0),
        in_delivers: AtomicU64::new(0),
        out_requests: AtomicU64::new(0),
        out_no_routes: AtomicU64::new(0),
        reasm_fails: AtomicU64::new(0),
        reasm_timeout: AtomicU64::new(0),
        reasm_reqds: AtomicU64::new(0),
        reasm_oks: AtomicU64::new(0),
        frag_oks: AtomicU64::new(0),
        frag_creates: AtomicU64::new(0),
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
    NEIGH6.lock().flush(ifindex, now_ms());
    neigh_notify();
}

/// Sends the changes of the neighbour table to `RTNLGRP_NEIGH`, as `neigh_update_notify` of
/// Linux. The caller does not hold the lock of the table.
fn neigh_notify() {
    let changes = NEIGH6.lock().take_changes();
    for c in changes {
        crate::rtnl::notify_neigh(AF_INET6, c);
    }
}

/// Adds or changes a neighbour of IPv6 for `RTM_NEWNEIGH`, as `neigh_add` of Linux, and sends
/// the packets that waited for it.
///
/// # Errors
///
/// Gives the error of `neigh::Table::add`.
pub(crate) fn neigh_add(
    dev: &NetDevice,
    addr: &Ip,
    mac: Option<MacAddr>,
    nud: neigh::Nud,
    flags: u32,
) -> Result<()> {
    let key = (dev.ifindex(), *addr);
    let (waiting, mac) = {
        let mut t = NEIGH6.lock();
        let waiting = t.add(key, mac, nud, now_ms(), flags)?;
        (waiting, t.lookup(key).unwrap_or(MacAddr::ZERO))
    };
    neigh_notify();
    for mut packet in waiting {
        ether(dev, mac).push(&mut packet);
        let _ = dev.transmit(packet);
    }
    Ok(())
}

/// Removes a neighbour of IPv6 for `RTM_DELNEIGH`, as `neigh_delete` of Linux. Gives `false`
/// if there is no entry.
pub(crate) fn neigh_del(ifindex: u32, addr: &Ip) -> bool {
    let found = NEIGH6.lock().remove((ifindex, *addr), now_ms());
    neigh_notify();
    found
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
            let n = stack::route_oif(d, oif)?;
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
            let next = stack::route_oif(dst, oif)?;
            let o = stack::Out {
                src,
                dst,
                protocol: out.next,
                ttl: out.hops,
                tos: out.tclass,
                df: out.dontfrag,
                mc_loop: true,
            };
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
    /// The packet cannot go out in fragments: `IPV6_DONTFRAG`, or `IPV6_PMTUDISC_DO` and
    /// `IPV6_PMTUDISC_PROBE`. A packet larger than the MTU then gives `EMSGSIZE`.
    pub dontfrag: bool,
}

/// Sends a packet with the payload `payload` on the route `next`, as `ip6_xmit` and
/// `ip6_fragment` of Linux. A packet larger than the MTU goes out in fragments, or gives
/// `EMSGSIZE` if `out.dontfrag` is set.
pub(crate) fn output(next: &Next6, out: &Out6, payload: &[u8]) -> Result<()> {
    let dev = dev::by_index(next.ifindex).ok_or(Errno::ENETUNREACH)?;
    let mtu = if next.mtu != 0 { next.mtu.min(dev.mtu()) } else { dev.mtu() } as usize;
    let len = out.ext.len() + payload.len();
    if len > usize::from(u16::MAX) || (out.dontfrag && HLEN + len > mtu) {
        return Err(Errno::EMSGSIZE);
    }
    // The fixed header names the routing header, as `ipv6_push_nfrag_opts`.
    let first = if out.ext.is_empty() { out.next } else { ipv6::NEXT_ROUTING };
    if out.next == PROTO_ICMPV6 {
        count_icmp_out(payload);
    }
    count(&COUNTERS6.out_requests);
    let header = |next: u8, len: usize| {
        let mut h = Header::new(out.src, out.dst, next, len);
        h.hops = out.hops;
        h.tclass = out.tclass;
        h.to_bytes()
    };
    if HLEN + len <= mtu {
        let mut buf = NetBuf::new(HEADROOM, HLEN + len);
        buf.extend_from_slice(&header(first, len));
        buf.extend_from_slice(&out.ext);
        buf.extend_from_slice(payload);
        return transmit(&dev, next, buf);
    }
    // The fragment header goes after the routing header, which is in each fragment. The next
    // header of the routing header becomes the fragment header.
    let mut ext = out.ext.clone();
    let first = match ext.first_mut() {
        Some(n) => {
            *n = ipv6::NEXT_FRAGMENT;
            first
        }
        None => ipv6::NEXT_FRAGMENT,
    };
    let room = mtu.saturating_sub(HLEN + ext.len() + ipv6::FRAG_HLEN);
    let id = FRAG_ID.fetch_add(1, Ordering::Relaxed);
    for (offset, n) in frag::split(payload.len(), room) {
        let more = offset + n < payload.len();
        let f = ipv6::Frag { at: 0, nh: 0, next: out.next, offset, more, id };
        let plen = ext.len() + ipv6::FRAG_HLEN + n;
        let mut buf = NetBuf::new(HEADROOM, HLEN + plen);
        buf.extend_from_slice(&header(first, plen));
        buf.extend_from_slice(&ext);
        buf.extend_from_slice(&f.to_bytes());
        buf.extend_from_slice(&payload[offset..offset + n]);
        count(&COUNTERS6.frag_creates);
        transmit(&dev, next, buf)?;
    }
    count(&COUNTERS6.frag_oks);
    Ok(())
}

/// Puts the fragment `packet` in its queue, as `ipv6_frag_rcv` in net/ipv6/reassembly.c of
/// Linux. Gives the whole packet when the queue is complete. `packet` ends at the end of the
/// payload.
fn reassemble(packet: &[u8]) -> Option<NetBuf> {
    count(&COUNTERS6.reasm_reqds);
    let Some(f) = ipv6::Frag::find(packet) else {
        count(&COUNTERS6.in_hdr_errors);
        return None;
    };
    let src: Ip = packet[8..24].try_into().unwrap_or_default();
    let dst: Ip = packet[24..40].try_into().unwrap_or_default();
    // The headers before the fragment header stay. The field that named the fragment header
    // names the next header of the fragment, as `ip6_frag_reasm`.
    let mut head = packet[..f.at].to_vec();
    head[f.nh] = f.next;
    let data = &packet[f.at + ipv6::FRAG_HLEN..];
    let r = FRAGS6.lock().add((src, dst, f.id), f.offset, f.more, &head, data, now_ms());
    match r {
        frag::Add::Wait => None,
        frag::Add::Fail => {
            count(&COUNTERS6.reasm_fails);
            None
        }
        frag::Add::Done(mut head, data) => {
            let len = head.len() - HLEN + data.len();
            if len > usize::from(u16::MAX) {
                count(&COUNTERS6.reasm_fails);
                return None;
            }
            count(&COUNTERS6.reasm_oks);
            head[4..6].copy_from_slice(&(len as u16).to_be_bytes());
            let mut buf = NetBuf::new(HEADROOM, head.len() + data.len());
            buf.extend_from_slice(&head);
            buf.extend_from_slice(&data);
            Some(buf)
        }
    }
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
pub(crate) fn count_icmp_out(msg: &[u8]) {
    if let Some(&t) = msg.first() {
        count(&COUNTERS6.icmp_out);
        count(&COUNTERS6.icmp_out_type[usize::from(t)]);
    }
}

fn ether(dev: &NetDevice, dst: MacAddr) -> EthHeader {
    EthHeader { dst, src: dev.mac(), ethertype: ETH_P_IPV6 as u16 }
}

/// Gives a packet to the link: the loopback device, a multicast group, or a neighbour.
pub(crate) fn transmit(dev: &NetDevice, next: &Next6, mut buf: NetBuf) -> Result<()> {
    count(&COUNTERS6.out_transmits);
    add(&COUNTERS6.out_octets, buf.len());
    // A TUN device and a line device have no link header and no neighbours, as the loopback
    // device.
    if matches!(dev.kind(), LinkKind::Loopback | LinkKind::Tun | LinkKind::Line { .. }) {
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
    let Some(src) = ROUTES6.lock().select_src_strict(target, dev.ifindex()) else { return };
    let dst = ipv6::solicited_node(target);
    let mut msg = Vec::with_capacity(32);
    msg.extend_from_slice(&[NDISC_NEIGHBOUR_SOLICITATION, 0, 0, 0, 0, 0, 0, 0]);
    msg.extend_from_slice(target);
    put_link_option(&mut msg, ND_OPT_SOURCE_LL_ADDR, dev);
    send_ndisc(dev, &src, &dst, ipv6::multicast_mac(&dst), msg);
}

/// Sends a probe of duplicate address detection for `target`, as `addrconf_dad_work` of Linux:
/// a neighbour solicitation from `::` to the solicited node group, without a link address.
fn send_dad(dev: &NetDevice, target: &Ip) {
    let dst = ipv6::solicited_node(target);
    let mut msg = Vec::with_capacity(24);
    msg.extend_from_slice(&[NDISC_NEIGHBOUR_SOLICITATION, 0, 0, 0, 0, 0, 0, 0]);
    msg.extend_from_slice(target);
    send_ndisc(dev, &ip::ANY, &dst, ipv6::multicast_mac(&dst), msg);
}

/// Starts the duplicate address detection of `addr` on `ifindex`, as `addrconf_dad_kick` of
/// Linux. The first probe goes out after a random delay below `router_solicitation_delay`, or
/// at the next poll for an `optimistic` address. A detection that runs for the address goes on.
pub(crate) fn start_dad(ifindex: u32, addr: Ip, optimistic: bool) {
    let conf = |name| {
        rk_net::sysctl::conf(
            rk_net::sysctl::Family::Ipv6,
            rk_net::sysctl::Scope::Dev(ifindex),
            name,
        )
    };
    let probes = conf("dad_transmits");
    // The value is in seconds. Linux takes a delay below 1 jiffy, which is 0, for 0.
    let delay = if optimistic {
        0
    } else {
        mcast6::random_below(u64::try_from(conf("router_solicitation_delay")).unwrap_or(0) * 1000)
    };
    let mut d = DAD.lock();
    if d.iter().any(|x| x.ifindex == ifindex && x.addr == addr) {
        return;
    }
    d.push(Dad { ifindex, addr, probes: probes.max(1) as u32, next: now_ms() + delay });
}

/// Tells if `addr` on `ifindex` is in duplicate address detection, and stops the detection
/// as a failure if it is, as `addrconf_dad_failure` of Linux.
fn dad_conflict(ifindex: u32, addr: &Ip) -> bool {
    let found = {
        let mut d = DAD.lock();
        let before = d.len();
        d.retain(|x| !(x.ifindex == ifindex && x.addr == *addr));
        d.len() != before
    };
    if found {
        addrconf::dad_done(ifindex, addr, true);
    }
    found
}

/// Gives a packet to a multicast group `dst` on `dev`, as `ip6_finish_output2` of Linux.
pub(crate) fn transmit_mcast(dev: &NetDevice, dst: &Ip, mut buf: NetBuf) -> Result<()> {
    count(&COUNTERS6.out_transmits);
    add(&COUNTERS6.out_octets, buf.len());
    let mac = if dev.kind() == LinkKind::Ether { ipv6::multicast_mac(dst) } else { MacAddr::ZERO };
    ether(dev, mac).push(&mut buf);
    dev.transmit(buf)
}

/// Joins the solicited node group of the address `addr` on `dev`, as `addrconf_join_solict` of
/// Linux, and sends the MLD report. The loopback device sends no report.
pub(crate) fn join(dev: &NetDevice, addr: &Ip) {
    if ipv6::is_multicast(addr) {
        return;
    }
    mcast6::report_change(dev, &ipv6::solicited_node(addr), true);
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
    neigh_notify();
    for mut packet in waiting {
        ether(dev, mac).push(&mut packet);
        let _ = dev.transmit(packet);
    }
}

/// Takes an IPv6 packet, as `ipv6_rcv` and `ip6_input` of Linux. A packet for another host goes
/// to `forward::forward6`. The fragments of a packet for the host go to `reassemble`. `host`
/// tells that the frame came to the link address of the device, `PACKET_HOST` of Linux.
pub(crate) fn input(dev: &NetDevice, frame: NetBuf, host: bool) {
    count(&COUNTERS6.in_receives);
    add(&COUNTERS6.in_octets, frame.len());
    let Some(frame) = crate::forward::forward6(dev, frame, host) else { return };
    let (h, mut frame) = match Header::parse(frame.data()) {
        Ok(h) => (h, frame),
        Err(Bad::Fragment) => {
            let end = HLEN + usize::from(u16::from_be_bytes([frame.data()[4], frame.data()[5]]));
            let Some(whole) = reassemble(&frame.data()[..end]) else { return };
            // A packet with a second fragment header is not valid.
            match Header::parse(whole.data()) {
                Ok(h) => (h, whole),
                Err(_) => return count(&COUNTERS6.reasm_fails),
            }
        }
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
    let ours = ours || (mcast && mcast6::joined(ifindex, &h.dst));
    if !ours {
        return count(&COUNTERS6.in_addr_errors);
    }
    if mcast {
        count(&COUNTERS6.in_mcast);
        add(&COUNTERS6.in_mcast_octets, frame.len());
    }
    let Some(h) = rthdr_input(dev, &mut frame, h) else { return };
    let packet = frame.data();
    let payload = &packet[h.l4..];
    let dif = stack::dif_of(dev);
    let raw = stack::raw_sockets(AF_INET6, h.protocol);
    for sock in &raw {
        sock.deliver_raw6(&h, ifindex, payload, dif);
    }
    let known = matches!(h.protocol, PROTO_ICMPV6 | PROTO_UDP | PROTO_TCP | NEXT_NONE);
    if known || !raw.is_empty() {
        count(&COUNTERS6.in_delivers);
    } else {
        count(&COUNTERS6.in_unknown_protos);
    }
    match h.protocol {
        PROTO_ICMPV6 => icmp_input(dev, &h, payload, mcast),
        PROTO_UDP => udp_input(&h, ifindex, packet, mcast, dif),
        PROTO_TCP => crate::tcp::input(h.src, h.dst, payload, mcast, dif),
        NEXT_NONE => {}
        _ if raw.is_empty() => {
            icmp_error(&h, ifindex, packet, PARAMPROB, ICMPV6_UNK_NEXTHDR as u8, h.nh as u32);
        }
        _ => {}
    }
}

/// `IPV6_SRCRT_TYPE_2` of include/uapi/linux/ipv6.h: the routing header of Mobile IPv6.
const SRCRT_TYPE_2: u8 = 2;
/// `IPV6_SRCRT_TYPE_3` of include/uapi/linux/ipv6.h: the routing header of RPL.
const SRCRT_TYPE_3: u8 = 3;
/// `IPV6_SRCRT_TYPE_4` of include/uapi/linux/ipv6.h: the segment routing header.
const SRCRT_TYPE_4: u8 = 4;

/// Processes the routing header of a packet for this host, as `ipv6_rthdr_rcv` and
/// `ipv6_srh_rcv` in net/ipv6/exthdrs.c of Linux. Gives the header of the packet for the upper
/// layer, or `None` when the packet is dropped or goes to the input again after its
/// encapsulation is removed.
///
/// A segment routing header with segments left goes to its next segment: the header and the
/// destination of the packet change. When the next segment is an address of the host, the
/// processing continues with one hop less, as for the loopback route of Linux. Else the packet
/// is dropped, because the stack does not forward. Linux takes a segment routing header only
/// when `seg6_enabled` of `all` and of the device are on. There is no RPL and no Mobile IPv6
/// home address, so a header of type 3, and a header of type 2 with an address, are dropped.
fn rthdr_input(dev: &NetDevice, frame: &mut NetBuf, mut h: Header) -> Option<Header> {
    let Some(at) = h.routing_header(frame.data()) else { return Some(h) };
    let (hdr_errors, addr_errors) = (&COUNTERS6.in_hdr_errors, &COUNTERS6.in_addr_errors);
    let Some(&[_, hdrlen, kind, _]) = frame.data().get(at..at + 4) else {
        count(hdr_errors);
        return None;
    };
    let len = (usize::from(hdrlen) + 1) * 8;
    if frame.len() < at + len {
        count(hdr_errors);
        return None;
    }
    if ipv6::is_multicast(&h.dst) {
        count(addr_errors);
        return None;
    }
    let ifindex = dev.ifindex();
    let conf = |name| {
        use rk_net::sysctl::{Family, Scope, conf};
        conf(Family::Ipv6, Scope::All, name).min(conf(Family::Ipv6, Scope::Dev(ifindex), name))
    };
    // The number of addresses in the header.
    let n = hdrlen / 2;
    match kind {
        SRCRT_TYPE_4 if conf("seg6_enabled") == 0 => None,
        SRCRT_TYPE_4 => loop {
            let left = frame.data()[at + 3];
            if left == 0 {
                let next = frame.data()[at];
                if u32::from(next) == IPPROTO_IPV6 || u32::from(next) == IPPROTO_IPIP {
                    // The packet in the header goes to the input of its protocol, as
                    // `netif_rx` of the inner packet.
                    let inner = NetBuf::from_slice(&frame.data()[at + len..]);
                    if u32::from(next) == IPPROTO_IPV6 {
                        input(dev, inner, false);
                    } else {
                        stack::ip_input(dev, inner, false);
                    }
                    return None;
                }
                return Some(h);
            }
            if left >= n {
                count(hdr_errors);
                let packet = frame.data();
                icmp_error(&h, ifindex, packet, PARAMPROB, HDR_FIELD, (at + 3) as u32);
                return None;
            }
            let seg = at + 8 + 16 * usize::from(left - 1);
            let data = frame.data_mut();
            data[at + 3] = left - 1;
            data.copy_within(seg..seg + 16, 24);
            h.dst = data[24..40].try_into().unwrap_or_default();
            if !ROUTES6.lock().is_local(&h.dst) {
                count(addr_errors);
                return None;
            }
            if h.hops <= 1 {
                count(hdr_errors);
                icmp_error(&h, ifindex, frame.data(), TIME_EXCEED, EXC_HOPLIMIT, 0);
                return None;
            }
            h.hops -= 1;
            frame.data_mut()[7] = h.hops;
        },
        SRCRT_TYPE_3 => None,
        // A type 2 header that this host did not process itself is dropped.
        SRCRT_TYPE_2 if frame.data()[at + 3] == 0 => {
            count(addr_errors);
            None
        }
        _ if frame.data()[at + 3] == 0 => Some(h),
        SRCRT_TYPE_2 if conf("accept_source_route") >= 0 => {
            count(if hdrlen != 2 || frame.data()[at + 3] != 1 { hdr_errors } else { addr_errors });
            None
        }
        _ => {
            count(hdr_errors);
            icmp_error(&h, ifindex, frame.data(), PARAMPROB, HDR_FIELD, (at + 2) as u32);
            None
        }
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
            if let Some(sock) =
                stack::find_socket(&PING_PORTS, id, h.dst, h.src, 0, stack::dif_of(dev))
            {
                let info = Some(Info6::of(h, ifindex));
                sock.deliver(h.src, scope_of(&h.src, ifindex), 0, msg.to_vec(), info);
            }
        }
        DEST_UNREACH | PKT_TOOBIG | TIME_EXCEED | PARAMPROB if msg.len() >= 8 => {
            error_input(msg, h.src, Info6::of(h, ifindex));
        }
        NDISC_NEIGHBOUR_SOLICITATION => ndisc_ns(dev, h, msg),
        NDISC_NEIGHBOUR_ADVERTISEMENT => ndisc_na(dev, h, msg),
        NDISC_ROUTER_ADVERTISEMENT => ndisc_ra(dev, h, msg),
        mcast6::MLD_QUERY => mcast6::query_input(dev, h, msg),
        _ => {}
    }
}

/// Gives the error of the ICMPv6 error message `msg` from `from` to the socket of the packet in
/// it, as `__udp6_lib_err` and `ping_err` of Linux. `pkt` has the IPv6 header of the message.
/// The error queue gets the data after the UDP header, or the echo request, and the
/// information of the message: the MTU or the pointer, as `ipv6_icmp_error`.
fn error_input(msg: &[u8], from: Ip, pkt: Info6) {
    let (kind, code, inner) = (msg[0], msg[1], &msg[8..]);
    let Some(ih) = Header::parse_loose(inner) else { return };
    let Some(l4) = inner.get(ih.l4..ih.l4 + 8) else { return };
    let (err, hard) = icmp_errno(kind, code);
    let (sock, port, payload) = match ih.protocol {
        PROTO_UDP => {
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            let sock = stack::find_socket(&UDP_PORTS, sport, ih.src, ih.dst, dport, 0);
            (sock, dport, &inner[ih.l4 + 8..])
        }
        PROTO_ICMPV6 if l4[0] == ECHO_REQUEST => {
            let id = u16::from_be_bytes([l4[4], l4[5]]);
            (stack::find_socket(&PING_PORTS, id, ih.src, ih.dst, 0, 0), 0, &inner[ih.l4..])
        }
        _ => return,
    };
    let info = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
    if let Some(sock) = sock {
        let (dst, payload) = (ih.dst, payload.to_vec());
        sock.icmp_error(IcmpError { err, hard, dst, port, kind, code, info, from, pkt, payload });
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
        dontfrag: false,
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
    // The error about a packet that the host forwards comes from an address of the host.
    let src = if ROUTES6.lock().is_local(&h.dst) {
        h.dst
    } else {
        match crate::forward::error_src6(&h.src, ifindex) {
            Some(s) => s,
            None => return count(&COUNTERS6.icmp_out_errors),
        }
    };
    send_icmp(&src, &h.src, ifindex, msg);
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
    let (ours, tentative, optimistic) = {
        let t = ROUTES6.lock();
        let a = t.addrs_of(ifindex).find(|a| a.addr == target);
        let flag = |f| a.is_some_and(|a| a.flags & f != 0);
        (a.is_some(), flag(IFA_F_TENTATIVE), flag(IFA_F_OPTIMISTIC))
    };
    let slla = link_option(&msg[24..], ND_OPT_SOURCE_LL_ADDR);
    // A probe of duplicate address detection has the source `::` and no link address.
    let dad = h.src == ip::ANY;
    if dad && slla.is_some() {
        return;
    }
    // A tentative address answers nothing. A probe of another node for it is a conflict, as
    // `ndisc_recv_ns` of Linux. An optimistic address answers a solicitation that is not a probe,
    // without the override flag, as RFC 4429 asks.
    if tentative && (dad || !optimistic) {
        if dad {
            dad_conflict(ifindex, &target);
        }
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
    let flags = if optimistic { flags & !NA_OVERRIDE } else { flags };
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
    // Another node has the address that is in detection, as `ndisc_recv_na` of Linux.
    if dad_conflict(dev.ifindex(), &target) {
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
fn udp_input(h: &Header, ifindex: u32, packet: &[u8], mcast: bool, dif: u32) {
    let d = &packet[h.l4..];
    let Some(u) = UdpHeader::parse(d) else { return count(&COUNTERS6.udp_in_errors) };
    let d = &d[..usize::from(u.len)];
    if u.check == 0 || checksum::upper(&h.src, &h.dst, PROTO_UDP, d) != 0 {
        count(&COUNTERS6.udp_in_csum_errors);
        return count(&COUNTERS6.udp_in_errors);
    }
    let Some(sock) = stack::find_socket(&UDP_PORTS, u.dst, h.dst, h.src, u.src, dif) else {
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
    neigh_notify();
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
    dad_tick(now);
    mcast6::tick(now);
    {
        let mut f = FRAGS6.lock();
        if !f.is_empty() {
            let n = f.expire(now);
            add(&COUNTERS6.reasm_timeout, n);
            add(&COUNTERS6.reasm_fails, n);
        }
    }
    // The lifetimes count in seconds, thus one check each second is enough.
    if NEXT_EXPIRE.load(Ordering::Relaxed) <= now {
        NEXT_EXPIRE.store(now + 1000, Ordering::Relaxed);
        addrconf::expire(now);
    }
}

/// Sends the probes of duplicate address detection that are due, and ends the detections
/// without an answer, as `addrconf_dad_work` of Linux.
fn dad_tick(now: u64) {
    let (probes, done) = {
        let mut d = DAD.lock();
        if d.is_empty() {
            return;
        }
        let (mut probes, mut done) = (Vec::new(), Vec::new());
        d.retain_mut(|x| {
            if x.next > now {
                return true;
            }
            if x.probes == 0 {
                done.push((x.ifindex, x.addr));
                return false;
            }
            x.probes -= 1;
            x.next = now + RETRANS_TIMER_MS;
            probes.push((x.ifindex, x.addr));
            true
        });
        (probes, done)
    };
    for (ifindex, addr) in probes {
        match dev::by_index(ifindex).filter(|d| d.is_up()) {
            Some(d) => send_dad(&d, &addr),
            None => DAD.lock().retain(|x| !(x.ifindex == ifindex && x.addr == addr)),
        }
    }
    for (ifindex, addr) in done {
        addrconf::dad_done(ifindex, &addr, false);
    }
}

/// Clears the tables of IPv6 of a namespace that stops.
pub(crate) fn ns_exit() {
    ROUTES6.reset();
    NEIGH6.reset();
    SOLICIT.reset();
    NEXT_EXPIRE.reset();
    DAD.reset();
    FRAGS6.reset();
    COUNTERS6.reset();
    mcast6::ns_exit();
    addrconf::ns_exit();
}

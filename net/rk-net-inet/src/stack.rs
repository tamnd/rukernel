//! The global state of the stack and the paths of the packets: the input of the frames, ARP,
//! IPv4, ICMP and the input of UDP, and the output of IPv4 through the neighbour table. The
//! module `stack6` has the paths of IPv6.
//!
//! Each table has its own lock, and the code holds at most one of them at a time. No lock is
//! held while a device sends a frame or while a socket takes a datagram.

use crate::ip::{self, Ip};
use crate::ipv4::{
    self, Addr, Bad, HLEN, Header, PROTO_ICMP, PROTO_TCP, PROTO_UDP, UDP_HLEN, UdpHeader,
};
use crate::ports::{self, Ports};
use crate::socket::{Dgram, Proto};
use crate::{checksum, neigh, route};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::if_ether::{ETH_P_ARP, ETH_P_IP, ETH_P_IPV6};
use rk_frame::sync::SpinLock;
use rk_net::arp::ArpPacket;
use rk_net::buf::{HEADROOM, NetBuf};
use rk_net::consts::AF_INET;
use rk_net::consts::{
    ARPOP_REPLY, ARPOP_REQUEST, ICMP_DEST_UNREACH, ICMP_ECHO, ICMP_ECHOREPLY, ICMP_FRAG_NEEDED,
    ICMP_HOST_UNREACH, ICMP_NET_UNREACH, ICMP_PARAMETERPROB, ICMP_PORT_UNREACH, ICMP_PROT_UNREACH,
    ICMP_TIME_EXCEEDED,
};
use rk_net::dev::{self, LinkKind, NetDevice};
use rk_net::ether::{EthHeader, MacAddr};
use rk_net::ns::PerNet;
use rk_vfs::inode::Result;

/// The addresses and the routes.
pub(crate) static ROUTES: PerNet<SpinLock<route::Table>> =
    PerNet::new(|| SpinLock::new(route::Table::new()));
/// The neighbour table. A packet that waits has its IPv4 header and no link header.
static NEIGH: PerNet<SpinLock<neigh::Table<NetBuf>>> =
    PerNet::new(|| SpinLock::new(neigh::Table::new()));
/// The ports of the UDP sockets.
pub(crate) static UDP_PORTS: PerNet<SpinLock<Ports>> =
    PerNet::new(|| SpinLock::new(Ports::new(ports::EPHEMERAL)));
/// The identifiers of the ICMP echo sockets, as `ping_table` of Linux.
pub(crate) static PING_PORTS: PerNet<SpinLock<Ports>> =
    PerNet::new(|| SpinLock::new(Ports::new(1..=u16::MAX)));
/// The open sockets, by their ID.
static SOCKETS: PerNet<SpinLock<BTreeMap<u64, Weak<Dgram>>>> =
    PerNet::new(|| SpinLock::new(BTreeMap::new()));
/// The identification of the next packet.
static IP_ID: AtomicU16 = AtomicU16::new(1);

/// The counters of the stack, as the lines of /proc/net/snmp.
pub struct Counters {
    /// The IPv4 packets that the stack received.
    pub ip_in: AtomicU64,
    /// The IPv4 packets with a bad header.
    pub ip_in_hdr_errors: AtomicU64,
    /// The fragments that the stack dropped, because it has no reassembly.
    pub ip_reasm_fails: AtomicU64,
    /// The packets to an address that is not local. The stack does not forward.
    pub ip_in_addr_errors: AtomicU64,
    /// The IPv4 packets that went to a protocol or a raw socket.
    pub ip_in_delivers: AtomicU64,
    /// The IPv4 packets of a protocol without a handler or a raw socket.
    pub ip_in_unknown_protos: AtomicU64,
    /// The IPv4 packets that the stack sent.
    pub ip_out: AtomicU64,
    /// The datagrams that a UDP socket took.
    pub udp_in: AtomicU64,
    /// The datagrams to a port without a socket.
    pub udp_no_ports: AtomicU64,
    /// The datagrams with a bad checksum or length.
    pub udp_in_errors: AtomicU64,
    /// The datagrams that a full receive buffer dropped.
    pub udp_rcvbuf_errors: AtomicU64,
    /// The datagrams with a bad checksum. `udp_in_errors` counts them too.
    pub udp_in_csum_errors: AtomicU64,
    /// The datagrams that the UDP sockets sent.
    pub udp_out: AtomicU64,
    /// The ICMP messages that the stack received.
    pub icmp_in: AtomicU64,
    /// The ICMP messages that were too short or had a bad checksum.
    pub icmp_in_errors: AtomicU64,
    /// The ICMP messages with a bad checksum. `icmp_in_errors` counts them too.
    pub icmp_in_csum_errors: AtomicU64,
    /// The ICMP messages that the stack sent.
    pub icmp_out: AtomicU64,
    /// The received ICMP messages by type, as `icmpmsg_statistics` of Linux.
    pub icmp_in_type: Box<[AtomicU64]>,
    /// The sent ICMP messages by type.
    pub icmp_out_type: Box<[AtomicU64]>,
    /// The connections that went to SYN-SENT.
    pub tcp_active_opens: AtomicU64,
    /// The connections that went from SYN-RECEIVED to an open state.
    pub tcp_passive_opens: AtomicU64,
    /// The connections that went from SYN-SENT or SYN-RECEIVED to CLOSED.
    pub tcp_attempt_fails: AtomicU64,
    /// The connections that went from ESTABLISHED or CLOSE-WAIT to CLOSED.
    pub tcp_estab_resets: AtomicU64,
    /// The TCP segments that the stack received.
    pub tcp_in_segs: AtomicU64,
    /// The TCP segments that the stack sent.
    pub tcp_out_segs: AtomicU64,
    /// The TCP segments that went out again.
    pub tcp_retrans_segs: AtomicU64,
    /// The TCP segments with a bad header or checksum.
    pub tcp_in_errs: AtomicU64,
    /// The TCP segments with a bad checksum. `tcp_in_errs` counts them too.
    pub tcp_in_csum_errors: AtomicU64,
    /// The TCP segments with RST that the stack sent.
    pub tcp_out_rsts: AtomicU64,
}

impl rk_net::ns::Clear for Counters {
    fn clear(&self, _fresh: Self) {
        self.ip_in.store(0, Ordering::Relaxed);
        self.ip_in_hdr_errors.store(0, Ordering::Relaxed);
        self.ip_reasm_fails.store(0, Ordering::Relaxed);
        self.ip_in_addr_errors.store(0, Ordering::Relaxed);
        self.ip_in_delivers.store(0, Ordering::Relaxed);
        self.ip_in_unknown_protos.store(0, Ordering::Relaxed);
        self.ip_out.store(0, Ordering::Relaxed);
        self.udp_in.store(0, Ordering::Relaxed);
        self.udp_no_ports.store(0, Ordering::Relaxed);
        self.udp_in_errors.store(0, Ordering::Relaxed);
        self.udp_rcvbuf_errors.store(0, Ordering::Relaxed);
        self.udp_in_csum_errors.store(0, Ordering::Relaxed);
        self.udp_out.store(0, Ordering::Relaxed);
        self.icmp_in.store(0, Ordering::Relaxed);
        self.icmp_in_errors.store(0, Ordering::Relaxed);
        self.icmp_in_csum_errors.store(0, Ordering::Relaxed);
        self.icmp_out.store(0, Ordering::Relaxed);
        for c in self.icmp_in_type.iter() {
            c.store(0, Ordering::Relaxed);
        }
        for c in self.icmp_out_type.iter() {
            c.store(0, Ordering::Relaxed);
        }
        self.tcp_active_opens.store(0, Ordering::Relaxed);
        self.tcp_passive_opens.store(0, Ordering::Relaxed);
        self.tcp_attempt_fails.store(0, Ordering::Relaxed);
        self.tcp_estab_resets.store(0, Ordering::Relaxed);
        self.tcp_in_segs.store(0, Ordering::Relaxed);
        self.tcp_out_segs.store(0, Ordering::Relaxed);
        self.tcp_retrans_segs.store(0, Ordering::Relaxed);
        self.tcp_in_errs.store(0, Ordering::Relaxed);
        self.tcp_in_csum_errors.store(0, Ordering::Relaxed);
        self.tcp_out_rsts.store(0, Ordering::Relaxed);
    }
}

/// The counters.
pub static COUNTERS: PerNet<Counters> = PerNet::new(new_counters);

/// A counter for each of the 256 types of ICMP. The counters are on the heap, so that a new
/// namespace does not make 4 KiB of them on the small stack of the kernel.
pub(crate) fn icmp_types() -> Box<[AtomicU64]> {
    (0..256).map(|_| AtomicU64::new(0)).collect()
}

/// The counters of a new namespace.
fn new_counters() -> Counters {
    Counters {
        ip_in: AtomicU64::new(0),
        ip_in_hdr_errors: AtomicU64::new(0),
        ip_reasm_fails: AtomicU64::new(0),
        ip_in_delivers: AtomicU64::new(0),
        ip_in_unknown_protos: AtomicU64::new(0),
        ip_in_addr_errors: AtomicU64::new(0),
        ip_out: AtomicU64::new(0),
        udp_in: AtomicU64::new(0),
        udp_no_ports: AtomicU64::new(0),
        udp_in_errors: AtomicU64::new(0),
        udp_rcvbuf_errors: AtomicU64::new(0),
        udp_in_csum_errors: AtomicU64::new(0),
        udp_out: AtomicU64::new(0),
        icmp_in: AtomicU64::new(0),
        icmp_in_errors: AtomicU64::new(0),
        icmp_in_csum_errors: AtomicU64::new(0),
        icmp_out: AtomicU64::new(0),
        icmp_in_type: icmp_types(),
        icmp_out_type: icmp_types(),
        tcp_active_opens: AtomicU64::new(0),
        tcp_passive_opens: AtomicU64::new(0),
        tcp_attempt_fails: AtomicU64::new(0),
        tcp_estab_resets: AtomicU64::new(0),
        tcp_in_segs: AtomicU64::new(0),
        tcp_out_segs: AtomicU64::new(0),
        tcp_retrans_segs: AtomicU64::new(0),
        tcp_in_errs: AtomicU64::new(0),
        tcp_in_csum_errors: AtomicU64::new(0),
        tcp_out_rsts: AtomicU64::new(0),
    }
}

/// Adds one to the counter `c`.
pub(crate) fn count(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

/// The time since boot in milliseconds, for the neighbour table. The host has no timer.
pub(crate) fn now_ms() -> u64 {
    #[cfg(target_os = "none")]
    {
        rk_frame::time::nanos() / 1_000_000
    }
    #[cfg(not(target_os = "none"))]
    {
        0
    }
}

/// Adds a socket to the table of the open sockets.
pub(crate) fn add_socket(id: u64, sock: &Arc<Dgram>) {
    SOCKETS.lock().insert(id, Arc::downgrade(sock));
}

/// Removes a socket from the table of the open sockets.
pub(crate) fn remove_socket(id: u64) {
    SOCKETS.lock().remove(&id);
}

/// The open datagram sockets, by their inode number.
pub(crate) fn dgram_sockets() -> Vec<Arc<Dgram>> {
    SOCKETS.lock().values().filter_map(Weak::upgrade).collect()
}

fn socket(id: u64) -> Option<Arc<Dgram>> {
    SOCKETS.lock().get(&id)?.upgrade()
}

/// The raw sockets of the family `family` and the protocol `protocol`.
pub(crate) fn raw_sockets(family: u32, protocol: u8) -> Vec<Arc<Dgram>> {
    let all: Vec<Arc<Dgram>> = SOCKETS.lock().values().filter_map(Weak::upgrade).collect();
    all.into_iter().filter(|s| s.family() == family && s.proto() == Proto::Raw(protocol)).collect()
}

/// The UDP socket that `id`, `src` and `sport` name in the ports table `table`: a socket on
/// the port `port` for `dst`, with no peer or the peer `src` and `sport`. The addresses of an
/// IPv4 packet are IPv4-mapped.
pub(crate) fn find_socket(
    table: &SpinLock<Ports>,
    port: u16,
    dst: Ip,
    src: Ip,
    sport: u16,
) -> Option<Arc<Dgram>> {
    let found = table.lock().find(port, dst);
    // A socket with the peer `src` wins over a socket without a peer, as the score of
    // `compute_score` in net/ipv4/udp.c.
    let mut best: Option<(u32, Arc<Dgram>)> = None;
    for b in found {
        let Some(sock) = socket(b.id) else { continue };
        let Some(score) = sock.score(&src, sport) else { continue };
        let score = score + u32::from(!ip::is_any(&b.addr));
        if best.as_ref().is_none_or(|(s, _)| score > *s) {
            best = Some((score, sock));
        }
    }
    best.map(|(_, s)| s)
}

/// Finds the route to `dst`, as `ip_route_output_key` of Linux.
pub(crate) fn route(dst: Addr) -> Result<route::Next> {
    ROUTES.lock().lookup(dst)
}

/// Removes the neighbours of an interface, as `arp_ifdown` of Linux.
pub(crate) fn flush_neigh(ifindex: u32) {
    NEIGH.lock().flush(ifindex);
}

/// The neighbours: the interface, the address, the hardware address if the entry is valid,
/// the probes and the times since the confirmation, the use and the update in milliseconds.
pub(crate) fn neighbours() -> Vec<neigh::Info> {
    NEIGH.lock().entries(now_ms())
}

/// The Ethernet multicast address of an IPv4 multicast address, as `ip_eth_mc_map` of Linux.
fn multicast_mac(a: Addr) -> MacAddr {
    MacAddr([0x01, 0x00, 0x5e, a[1] & 0x7f, a[2], a[3]])
}

/// The things that a packet needs to go out.
pub(crate) struct Out {
    /// The source address.
    pub src: Addr,
    /// The destination address.
    pub dst: Addr,
    /// The protocol.
    pub protocol: u8,
    /// The time to live.
    pub ttl: u8,
    /// The type of service.
    pub tos: u8,
}

/// Sends a packet with the payload `payload` on the route `next`, as `ip_queue_xmit` of Linux.
/// The packet does not get fragments: a packet larger than the MTU gives `EMSGSIZE`.
pub(crate) fn output(next: &route::Next, out: &Out, payload: &[u8]) -> Result<()> {
    let dev = dev::by_index(next.ifindex).ok_or(Errno::ENETUNREACH)?;
    if HLEN + payload.len() > dev.mtu() as usize {
        return Err(Errno::EMSGSIZE);
    }
    let mut header = Header::new(out.src, out.dst, out.protocol, payload.len());
    header.ttl = out.ttl;
    header.tos = out.tos;
    header.id = IP_ID.fetch_add(1, Ordering::Relaxed);
    let mut buf = NetBuf::new(HEADROOM, HLEN + payload.len());
    buf.extend_from_slice(&header.to_bytes());
    buf.extend_from_slice(payload);
    if out.protocol == PROTO_ICMP {
        count_icmp_out(payload);
    }
    transmit(&dev, next, buf)
}

/// Counts an ICMP message that goes out, as `icmp_out_count` of Linux.
fn count_icmp_out(msg: &[u8]) {
    if let Some(&t) = msg.first() {
        count(&COUNTERS.icmp_out);
        count(&COUNTERS.icmp_out_type[usize::from(t)]);
    }
}

/// Sends a packet that has its IPv4 header, for a raw socket with `IP_HDRINCL`.
pub(crate) fn output_raw(next: &route::Next, packet: &[u8]) -> Result<()> {
    let dev = dev::by_index(next.ifindex).ok_or(Errno::ENETUNREACH)?;
    if packet.len() > dev.mtu() as usize {
        return Err(Errno::EMSGSIZE);
    }
    if let Some(h) = Header::parse_loose(packet)
        && h.protocol == PROTO_ICMP
    {
        count_icmp_out(packet.get(h.hlen..).unwrap_or_default());
    }
    transmit(&dev, next, NetBuf::from_slice(packet))
}

/// Gives a packet to the link: the loopback device, a broadcast, or a neighbour.
fn transmit(dev: &NetDevice, next: &route::Next, mut buf: NetBuf) -> Result<()> {
    count(&COUNTERS.ip_out);
    let mac = dev.mac();
    let ether = |dst| EthHeader { dst, src: mac, ethertype: ETH_P_IP as u16 };
    // A TUN device has no link header and no neighbours, as the loopback device.
    if matches!(dev.kind(), LinkKind::Loopback | LinkKind::Tun) {
        ether(MacAddr::ZERO).push(&mut buf);
        return dev.transmit(buf);
    }
    let dst = Header::parse_loose(buf.data()).map_or(next.hop, |h| h.dst);
    if next.broadcast || dst == ipv4::BROADCAST {
        ether(MacAddr::BROADCAST).push(&mut buf);
        return dev.transmit(buf);
    }
    if ipv4::is_multicast(dst) {
        ether(multicast_mac(dst)).push(&mut buf);
        return dev.transmit(buf);
    }
    let key = (dev.ifindex(), next.hop);
    let r = NEIGH.lock().resolve(key, now_ms(), buf);
    match r {
        neigh::Resolve::Send { mut packet, mac: to, probe } => {
            if probe {
                solicit(dev, next.hop);
            }
            ether(to).push(&mut packet);
            dev.transmit(packet)
        }
        neigh::Resolve::Wait { probe } => {
            if probe {
                solicit(dev, next.hop);
            }
            Ok(())
        }
    }
}

/// Sends an ARP request for `target` on `dev`, as `arp_solicit` of Linux.
fn solicit(dev: &NetDevice, target: Addr) {
    let Some(src) = ROUTES.lock().addr_of(dev.ifindex()) else { return };
    let frame = ArpPacket::request(dev.mac(), src, target).to_frame(MacAddr::BROADCAST);
    // A lost request is like a lost frame: the timer of the table sends it again.
    let _ = dev.transmit(frame);
}

/// Takes a frame from a device, as `__netif_receive_skb` of Linux: the type of the Ethernet
/// header gives the protocol.
pub fn receive(dev: &NetDevice, mut frame: NetBuf) {
    let Some(eth) = EthHeader::pull(&mut frame) else { return };
    if eth.dst != dev.mac() && !eth.dst.is_multicast() {
        return;
    }
    frame.protocol = eth.ethertype;
    match u32::from(eth.ethertype) {
        ETH_P_ARP => arp_input(dev, frame.data()),
        ETH_P_IP => ip_input(dev, frame),
        ETH_P_IPV6 => crate::stack6::input(dev, frame),
        _ => {}
    }
}

/// Takes an ARP packet, as `arp_process` of Linux: it learns the address of the sender, sends
/// the packets that waited for it, and answers a request for a local address.
fn arp_input(dev: &NetDevice, data: &[u8]) {
    let Some(p) = ArpPacket::parse(data) else { return };
    if p.op != ARPOP_REQUEST && p.op != ARPOP_REPLY {
        return;
    }
    if ipv4::is_multicast(p.target_ip) || ipv4::is_loopback(p.target_ip) {
        return;
    }
    let ours = { ROUTES.lock().is_local(p.target_ip) };
    // A probe for duplicate addresses has the sender 0.0.0.0, and it does not go in the table.
    if p.sender_ip != ipv4::ANY && !p.sender_mac.is_multicast() {
        let key = (dev.ifindex(), p.sender_ip);
        let waiting = NEIGH.lock().update(key, p.sender_mac, now_ms(), ours);
        for mut packet in waiting {
            EthHeader { dst: p.sender_mac, src: dev.mac(), ethertype: ETH_P_IP as u16 }
                .push(&mut packet);
            let _ = dev.transmit(packet);
        }
    }
    if p.op == ARPOP_REQUEST && ours {
        let reply = ArpPacket {
            op: ARPOP_REPLY,
            sender_mac: dev.mac(),
            sender_ip: p.target_ip,
            target_mac: p.sender_mac,
            target_ip: p.sender_ip,
        };
        let _ = dev.transmit(reply.to_frame(p.sender_mac));
    }
}

/// Takes an IPv4 packet, as `ip_rcv` and `ip_local_deliver` of Linux. The stack does not
/// forward, and it drops the fragments.
fn ip_input(dev: &NetDevice, mut frame: NetBuf) {
    count(&COUNTERS.ip_in);
    let h = match Header::parse(frame.data()) {
        Ok(h) => h,
        Err(Bad::Fragment) => return count(&COUNTERS.ip_reasm_fails),
        Err(_) => return count(&COUNTERS.ip_in_hdr_errors),
    };
    frame.trim(usize::from(h.total_len));
    let loopback = dev.kind() == LinkKind::Loopback;
    // An address of 127.0.0.0/8 from a real link is a martian, as `ip_route_input_slow`.
    if !loopback && (ipv4::is_loopback(h.src) || ipv4::is_loopback(h.dst)) {
        return count(&COUNTERS.ip_in_addr_errors);
    }
    let (local, broadcast) = {
        let routes = ROUTES.lock();
        (routes.is_local(h.dst), routes.is_broadcast(h.dst))
    };
    if !local && !broadcast {
        return count(&COUNTERS.ip_in_addr_errors);
    }
    let raw = raw_sockets(AF_INET, h.protocol);
    for sock in &raw {
        sock.deliver_raw(&h, frame.data());
    }
    let packet = frame.data();
    let payload = &packet[h.hlen..];
    // `ip_protocol_deliver_rcu` counts a packet with a handler or a raw socket as delivered.
    let known = matches!(h.protocol, PROTO_ICMP | PROTO_UDP | PROTO_TCP);
    if known || !raw.is_empty() {
        count(&COUNTERS.ip_in_delivers);
    } else {
        count(&COUNTERS.ip_in_unknown_protos);
    }
    match h.protocol {
        PROTO_ICMP => icmp_input(&h, payload, broadcast),
        PROTO_UDP => udp_input(&h, packet, broadcast),
        PROTO_TCP => crate::tcp::input(ip::mapped(h.src), ip::mapped(h.dst), payload, broadcast),
        _ if raw.is_empty() && !broadcast => {
            icmp_error(&h, packet, ICMP_DEST_UNREACH, ICMP_PROT_UNREACH);
        }
        _ => {}
    }
}

/// The error of an ICMP error message, as `icmp_err_convert` of Linux, and tells if the error
/// is hard. A soft error goes only to a socket with `IP_RECVERR`.
fn icmp_errno(kind: u8, code: u8) -> (Errno, bool) {
    match (kind, code) {
        (ICMP_DEST_UNREACH, ICMP_NET_UNREACH) => (Errno::ENETUNREACH, false),
        (ICMP_DEST_UNREACH, ICMP_HOST_UNREACH) => (Errno::EHOSTUNREACH, false),
        (ICMP_DEST_UNREACH, ICMP_PROT_UNREACH) => (Errno::ENOPROTOOPT, true),
        (ICMP_DEST_UNREACH, ICMP_PORT_UNREACH) => (Errno::ECONNREFUSED, true),
        (ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED) => (Errno::EMSGSIZE, false),
        (ICMP_DEST_UNREACH, _) => (Errno::EHOSTUNREACH, true),
        (ICMP_PARAMETERPROB, _) => (Errno::EPROTO, true),
        _ => (Errno::EHOSTUNREACH, false),
    }
}

/// Takes an ICMP message, as `icmp_rcv` of Linux.
fn icmp_input(h: &Header, msg: &[u8], broadcast: bool) {
    count(&COUNTERS.icmp_in);
    if msg.len() < 8 {
        return count(&COUNTERS.icmp_in_errors);
    }
    if checksum::checksum(msg) != 0 {
        count(&COUNTERS.icmp_in_csum_errors);
        return count(&COUNTERS.icmp_in_errors);
    }
    count(&COUNTERS.icmp_in_type[usize::from(msg[0])]);
    match msg[0] {
        // `icmp_echo` of Linux ignores a request for `net.ipv4.icmp_echo_ignore_all`. The stack
        // ignores each request to a broadcast address, as the default of
        // `net.ipv4.icmp_echo_ignore_broadcasts`.
        ICMP_ECHO if !broadcast && rk_net::sysctl::ipv4("icmp_echo_ignore_all") == 0 => {
            let mut reply = msg.to_vec();
            reply[0] = ICMP_ECHOREPLY;
            reply[2..4].fill(0);
            let sum = checksum::checksum(&reply);
            reply[2..4].copy_from_slice(&sum.to_be_bytes());
            send_icmp(h.dst, h.src, h.tos, &reply);
        }
        ICMP_ECHOREPLY => {
            let id = u16::from_be_bytes([msg[4], msg[5]]);
            if let Some(sock) =
                find_socket(&PING_PORTS, id, ip::mapped(h.dst), ip::mapped(h.src), 0)
            {
                sock.deliver(ip::mapped(h.src), 0, 0, msg.to_vec(), None);
            }
        }
        ICMP_DEST_UNREACH | ICMP_TIME_EXCEEDED | ICMP_PARAMETERPROB => {
            icmp_unreach(msg[0], msg[1], &msg[8..]);
        }
        _ => {}
    }
}

/// Gives the error of an ICMP error message to the socket of the packet in it, as `udp_err`
/// and `ping_err` of Linux. `inner` is the start of the packet that failed.
fn icmp_unreach(kind: u8, code: u8, inner: &[u8]) {
    let Some(ih) = Header::parse_loose(inner) else { return };
    let Some(l4) = inner.get(ih.hlen..ih.hlen + 8) else { return };
    let (err, hard) = icmp_errno(kind, code);
    let sock = match ih.protocol {
        PROTO_UDP => {
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            find_socket(&UDP_PORTS, sport, ip::mapped(ih.src), ip::mapped(ih.dst), dport)
        }
        PROTO_ICMP if l4[0] == ICMP_ECHO => {
            let id = u16::from_be_bytes([l4[4], l4[5]]);
            find_socket(&PING_PORTS, id, ip::mapped(ih.src), ip::mapped(ih.dst), 0)
        }
        _ => None,
    };
    if let Some(sock) = sock {
        sock.icmp_error(err, hard, ip::mapped(ih.dst));
    }
}

/// Sends an ICMP message from `src` to `dst`.
fn send_icmp(src: Addr, dst: Addr, tos: u8, msg: &[u8]) {
    let Ok(next) = route(dst) else { return };
    let out = Out { src, dst, protocol: PROTO_ICMP, ttl: rk_net::sysctl::default_ttl(), tos };
    // An ICMP message that the stack makes is not for a socket, and a lost one is not an error.
    let _ = output(&next, &out, msg);
}

/// The most bytes of the failed packet in an ICMP error. The full message is at most 576 bytes,
/// as `icmp_send` of Linux.
const ICMP_ERROR_DATA: usize = 576 - HLEN - 8;

/// Sends an ICMP error about the packet `packet` with the header `h`, as `icmp_send` of Linux.
/// The stack sends no error about a broadcast or about an ICMP error.
pub(crate) fn icmp_error(h: &Header, packet: &[u8], kind: u8, code: u8) {
    if let Some(&t) = packet.get(h.hlen)
        && h.protocol == PROTO_ICMP
        && t != ICMP_ECHO
        && t != ICMP_ECHOREPLY
    {
        return;
    }
    if h.src == ipv4::ANY || ipv4::is_multicast(h.src) || h.src == ipv4::BROADCAST {
        return;
    }
    let local = ROUTES.lock().is_local(h.dst);
    if !local {
        return;
    }
    let data = &packet[..packet.len().min(ICMP_ERROR_DATA)];
    let mut msg = Vec::with_capacity(8 + data.len());
    msg.extend_from_slice(&[kind, code, 0, 0, 0, 0, 0, 0]);
    msg.extend_from_slice(data);
    let sum = checksum::checksum(&msg);
    msg[2..4].copy_from_slice(&sum.to_be_bytes());
    send_icmp(h.dst, h.src, h.tos, &msg);
}

/// Takes a UDP datagram, as `udp_rcv` of Linux. `packet` has the IPv4 header.
fn udp_input(h: &Header, packet: &[u8], broadcast: bool) {
    let d = &packet[h.hlen..];
    let Some(u) = UdpHeader::parse(d) else { return count(&COUNTERS.udp_in_errors) };
    let d = &d[..usize::from(u.len)];
    if u.check != 0
        && checksum::fold(checksum::add(checksum::pseudo(h.src, h.dst, PROTO_UDP, u.len), d)) != 0
    {
        count(&COUNTERS.udp_in_csum_errors);
        return count(&COUNTERS.udp_in_errors);
    }
    let found = find_socket(&UDP_PORTS, u.dst, ip::mapped(h.dst), ip::mapped(h.src), u.src);
    let Some(sock) = found else {
        count(&COUNTERS.udp_no_ports);
        if !broadcast {
            icmp_error(h, packet, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH);
        }
        return;
    };
    if sock.deliver(ip::mapped(h.src), 0, u.src, d[UDP_HLEN..].to_vec(), None) {
        count(&COUNTERS.udp_in);
    } else {
        count(&COUNTERS.udp_rcvbuf_errors);
    }
}

/// Tells that a poll runs, so that a send in the poll does not start a second poll.
static POLLING: AtomicBool = AtomicBool::new(false);

/// The most frames of one device in one round of `poll`.
const BUDGET: usize = 64;
/// The most rounds of one `poll`.
const ROUNDS: usize = 16;

/// The time of the end of the last poll of the bottom half and the time that it took, in
/// nanoseconds.
#[cfg(target_os = "none")]
static LAST_POLL: SpinLock<(u64, u64)> = SpinLock::new((0, 0));

/// Takes the received frames of each device and runs the timers of the neighbour table, as the
/// `NET_RX` softirq of Linux. The bottom half of the kernel calls this. If a poll runs on another
/// CPU, this call does nothing.
///
/// The bottom half runs after each interrupt. When the host is slow, a poll can take longer than
/// one tick of the clock, and then a task gets no time between two polls. So a poll does not start
/// until the time after the last poll is as long as the time of the last poll, and the poll takes
/// at most half of the time of the CPU. Linux moves such work to `ksoftirqd`.
pub fn poll() {
    #[cfg(target_os = "none")]
    let start = {
        let start = rk_frame::time::nanos();
        let (end, took) = *LAST_POLL.lock();
        if start.saturating_sub(end) < took {
            return;
        }
        start
    };
    if POLLING.swap(true, Ordering::Acquire) {
        return;
    }
    poll_locked();
    #[cfg(target_os = "none")]
    {
        let end = rk_frame::time::nanos();
        *LAST_POLL.lock() = (end, end.saturating_sub(start));
    }
}

/// Polls as `poll`, but waits for a poll on another CPU to end first. A send calls this, so
/// that a packet on the loopback device arrives before the send returns. A poll does not block
/// and does not send on a socket, so the wait is short.
pub(crate) fn poll_now() {
    while POLLING.swap(true, Ordering::Acquire) {
        core::hint::spin_loop();
    }
    poll_locked();
}

/// The time of the next run of the timers of the namespaces other than the first one.
static NEXT_TIMERS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The shortest time between two runs of the timers of the other namespaces, in milliseconds.
/// Each run of the timers of a namespace costs time. When the poll takes longer than one tick of
/// the clock, a task can get no time to run, because the poll runs after each interrupt.
const TIMER_INTERVAL_MS: u64 = 10;

fn poll_locked() {
    // A device gives its frames to the stack of its namespace.
    let devices = dev::all_devices();
    for _ in 0..ROUNDS {
        let mut n = 0;
        for d in devices.iter().filter(|d| d.is_up()) {
            let _in = rk_net::ns::enter_index(d.net());
            n += d.poll(BUDGET, &mut |d, frame| receive(d, frame));
        }
        if n == 0 {
            break;
        }
    }
    // The timers of the first namespace run at each poll, as before. The timers of the other
    // namespaces run at most one time in each interval.
    {
        let _in = rk_net::ns::enter_index(0);
        timers();
    }
    let now = now_ms();
    if rk_net::ns::count() > 1 && NEXT_TIMERS.load(Ordering::Relaxed) <= now {
        NEXT_TIMERS.store(now + TIMER_INTERVAL_MS, Ordering::Relaxed);
        for index in rk_net::ns::indices().into_iter().skip(1) {
            let _in = rk_net::ns::enter_index(index);
            timers();
        }
    }
    POLLING.store(false, Ordering::Release);
}

/// Runs the timers of TCP, of the neighbour tables and of IPv6 in the current namespace.
fn timers() {
    crate::tcp::tick();
    let probes = {
        let mut neigh = NEIGH.lock();
        if neigh.is_empty() { Vec::new() } else { neigh.tick(now_ms()) }
    };
    for (ifindex, addr) in probes {
        if let Some(d) = dev::by_index(ifindex) {
            solicit(&d, addr);
        }
    }
    crate::stack6::tick();
}

/// Clears the tables of IPv4 of a namespace that stops.
pub(crate) fn ns_exit() {
    ROUTES.reset();
    NEIGH.reset();
    UDP_PORTS.reset();
    PING_PORTS.reset();
    SOCKETS.reset();
    COUNTERS.reset();
}

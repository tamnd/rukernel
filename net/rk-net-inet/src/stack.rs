//! The global state of the stack and the paths of the packets: the input of the frames, ARP,
//! IPv4, ICMP and the input of UDP, and the output of IPv4 through the neighbour table.
//!
//! Each table has its own lock, and the code holds at most one of them at a time. No lock is
//! held while a device sends a frame or while a socket takes a datagram.

use crate::ipv4::{self, Addr, Bad, HLEN, Header, PROTO_ICMP, PROTO_UDP, UDP_HLEN, UdpHeader};
use crate::ports::{self, Ports};
use crate::socket::{Dgram, Proto};
use crate::{checksum, neigh, route};
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::if_ether::{ETH_P_ARP, ETH_P_IP};
use rk_frame::sync::SpinLock;
use rk_net::arp::ArpPacket;
use rk_net::buf::{HEADROOM, NetBuf};
use rk_net::consts::{
    ARPOP_REPLY, ARPOP_REQUEST, ICMP_DEST_UNREACH, ICMP_ECHO, ICMP_ECHOREPLY, ICMP_FRAG_NEEDED,
    ICMP_HOST_UNREACH, ICMP_NET_UNREACH, ICMP_PARAMETERPROB, ICMP_PORT_UNREACH, ICMP_PROT_UNREACH,
    ICMP_TIME_EXCEEDED,
};
use rk_net::dev::{self, LinkKind, NetDevice};
use rk_net::ether::{EthHeader, MacAddr};
use rk_vfs::inode::Result;

/// The addresses and the routes.
pub(crate) static ROUTES: SpinLock<route::Table> = SpinLock::new(route::Table::new());
/// The neighbour table. A packet that waits has its IPv4 header and no link header.
static NEIGH: SpinLock<neigh::Table<NetBuf>> = SpinLock::new(neigh::Table::new());
/// The ports of the UDP sockets.
pub(crate) static UDP_PORTS: SpinLock<Ports> = SpinLock::new(Ports::new(ports::EPHEMERAL));
/// The identifiers of the ICMP echo sockets, as `ping_table` of Linux.
pub(crate) static PING_PORTS: SpinLock<Ports> = SpinLock::new(Ports::new(1..=u16::MAX));
/// The open sockets, by their ID.
static SOCKETS: SpinLock<BTreeMap<u64, Weak<Dgram>>> = SpinLock::new(BTreeMap::new());
/// The identification of the next packet.
static IP_ID: AtomicU16 = AtomicU16::new(1);

/// The counters of the stack, as the `Ip`, `Icmp` and `Udp` lines of /proc/net/snmp.
#[derive(Default)]
pub struct Counters {
    /// The IPv4 packets that the stack received.
    pub ip_in: AtomicU64,
    /// The IPv4 packets with a bad header.
    pub ip_in_hdr_errors: AtomicU64,
    /// The fragments that the stack dropped, because it has no reassembly.
    pub ip_reasm_fails: AtomicU64,
    /// The packets to an address that is not local. The stack does not forward.
    pub ip_in_addr_errors: AtomicU64,
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
}

/// The counters.
pub static COUNTERS: Counters = Counters {
    ip_in: AtomicU64::new(0),
    ip_in_hdr_errors: AtomicU64::new(0),
    ip_reasm_fails: AtomicU64::new(0),
    ip_in_addr_errors: AtomicU64::new(0),
    ip_out: AtomicU64::new(0),
    udp_in: AtomicU64::new(0),
    udp_no_ports: AtomicU64::new(0),
    udp_in_errors: AtomicU64::new(0),
    udp_rcvbuf_errors: AtomicU64::new(0),
};

fn count(c: &AtomicU64) {
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

fn socket(id: u64) -> Option<Arc<Dgram>> {
    SOCKETS.lock().get(&id)?.upgrade()
}

/// The raw sockets of the protocol `protocol`.
fn raw_sockets(protocol: u8) -> Vec<Arc<Dgram>> {
    let all: Vec<Arc<Dgram>> = SOCKETS.lock().values().filter_map(Weak::upgrade).collect();
    all.into_iter().filter(|s| s.proto() == Proto::Raw(protocol)).collect()
}

/// The UDP socket that `id`, `src` and `sport` name in the ports table `table`: a socket on
/// the port `port` for `dst`, with no peer or the peer `src` and `sport`.
fn find_socket(
    table: &SpinLock<Ports>,
    port: u16,
    dst: Addr,
    src: Addr,
    sport: u16,
) -> Option<Arc<Dgram>> {
    let found = table.lock().find(port, dst);
    // A socket with the peer `src` wins over a socket without a peer, as the score of
    // `compute_score` in net/ipv4/udp.c.
    let mut best: Option<(u32, Arc<Dgram>)> = None;
    for b in found {
        let Some(sock) = socket(b.id) else { continue };
        let Some(score) = sock.score(src, sport) else { continue };
        let score = score + u32::from(b.addr != ipv4::ANY);
        if best.as_ref().is_none_or(|(s, _)| score > *s) {
            best = Some((score, sock));
        }
    }
    best.map(|(_, s)| s)
}

/// Sets the address of an interface, as `ip addr add`. The loopback device gets all of its
/// subnet as local addresses.
pub fn add_addr(ifindex: u32, addr: Addr, prefix: u8) -> Result<()> {
    let dev = dev::by_index(ifindex).ok_or(Errno::ENODEV)?;
    if prefix > 32 {
        return Err(Errno::EINVAL);
    }
    let loopback = dev.kind() == LinkKind::Loopback;
    ROUTES.lock().add_addr(route::IfAddr { ifindex, addr, prefix, loopback });
    Ok(())
}

/// Adds a route, as `ip route add`. A gateway must be in a connected subnet.
pub fn add_route(dst: Addr, prefix: u8, gateway: Option<Addr>, ifindex: u32) -> Result<()> {
    if prefix > 32 || dev::by_index(ifindex).is_none() {
        return Err(Errno::EINVAL);
    }
    let mut routes = ROUTES.lock();
    if let Some(gw) = gateway {
        let on_link = routes
            .addrs()
            .iter()
            .any(|a| a.ifindex == ifindex && ipv4::same_net(a.addr, gw, a.prefix));
        if !on_link {
            return Err(Errno::ENETUNREACH);
        }
    }
    routes.add_route(route::Route { dst, prefix, gateway, ifindex });
    Ok(())
}

/// Finds the route to `dst`. Gives `ENETUNREACH` if no route matches.
pub(crate) fn route(dst: Addr) -> Result<route::Next> {
    ROUTES.lock().lookup(dst).ok_or(Errno::ENETUNREACH)
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
    transmit(&dev, next, buf)
}

/// Sends a packet that has its IPv4 header, for a raw socket with `IP_HDRINCL`.
pub(crate) fn output_raw(next: &route::Next, packet: &[u8]) -> Result<()> {
    let dev = dev::by_index(next.ifindex).ok_or(Errno::ENETUNREACH)?;
    if packet.len() > dev.mtu() as usize {
        return Err(Errno::EMSGSIZE);
    }
    transmit(&dev, next, NetBuf::from_slice(packet))
}

/// Gives a packet to the link: the loopback device, a broadcast, or a neighbour.
fn transmit(dev: &NetDevice, next: &route::Next, mut buf: NetBuf) -> Result<()> {
    count(&COUNTERS.ip_out);
    let mac = dev.mac();
    let ether = |dst| EthHeader { dst, src: mac, ethertype: ETH_P_IP as u16 };
    if dev.kind() == LinkKind::Loopback {
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
    let ours = {
        let routes = ROUTES.lock();
        routes.addrs().iter().any(|a| !a.loopback && a.addr == p.target_ip)
    };
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
    let raw = raw_sockets(h.protocol);
    for sock in &raw {
        sock.deliver_raw(&h, frame.data());
    }
    let packet = frame.data();
    let payload = &packet[h.hlen..];
    match h.protocol {
        PROTO_ICMP => icmp_input(&h, payload, broadcast),
        PROTO_UDP => udp_input(&h, packet, broadcast),
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
    if msg.len() < 8 || checksum::checksum(msg) != 0 {
        return;
    }
    match msg[0] {
        // Linux ignores an echo request to a broadcast address by default, as
        // `net.ipv4.icmp_echo_ignore_broadcasts`.
        ICMP_ECHO if !broadcast => {
            let mut reply = msg.to_vec();
            reply[0] = ICMP_ECHOREPLY;
            reply[2..4].fill(0);
            let sum = checksum::checksum(&reply);
            reply[2..4].copy_from_slice(&sum.to_be_bytes());
            send_icmp(h.dst, h.src, h.tos, &reply);
        }
        ICMP_ECHOREPLY => {
            let id = u16::from_be_bytes([msg[4], msg[5]]);
            if let Some(sock) = find_socket(&PING_PORTS, id, h.dst, h.src, 0) {
                sock.deliver(h.src, 0, msg.to_vec());
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
            find_socket(&UDP_PORTS, sport, ih.src, ih.dst, dport)
        }
        PROTO_ICMP if l4[0] == ICMP_ECHO => {
            let id = u16::from_be_bytes([l4[4], l4[5]]);
            find_socket(&PING_PORTS, id, ih.src, ih.dst, 0)
        }
        _ => None,
    };
    if let Some(sock) = sock {
        sock.icmp_error(err, hard, ih.dst);
    }
}

/// Sends an ICMP message from `src` to `dst`.
fn send_icmp(src: Addr, dst: Addr, tos: u8, msg: &[u8]) {
    let Ok(next) = route(dst) else { return };
    let out = Out { src, dst, protocol: PROTO_ICMP, ttl: ipv4::DEFAULT_TTL, tos };
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
        return count(&COUNTERS.udp_in_errors);
    }
    let Some(sock) = find_socket(&UDP_PORTS, u.dst, h.dst, h.src, u.src) else {
        count(&COUNTERS.udp_no_ports);
        if !broadcast {
            icmp_error(h, packet, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH);
        }
        return;
    };
    if sock.deliver(h.src, u.src, d[UDP_HLEN..].to_vec()) {
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

/// Takes the received frames of each device and runs the timers of the neighbour table, as the
/// `NET_RX` softirq of Linux. The bottom half of the kernel calls this. If a poll runs on another
/// CPU, this call does nothing.
pub fn poll() {
    if POLLING.swap(true, Ordering::Acquire) {
        return;
    }
    poll_locked();
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

fn poll_locked() {
    let devices = dev::devices();
    for _ in 0..ROUNDS {
        let mut n = 0;
        for d in devices.iter().filter(|d| d.is_up()) {
            n += d.poll(BUDGET, &mut |d, frame| receive(d, frame));
        }
        if n == 0 {
            break;
        }
    }
    let probes = {
        let mut neigh = NEIGH.lock();
        if neigh.is_empty() { Vec::new() } else { neigh.tick(now_ms()) }
    };
    for (ifindex, addr) in probes {
        if let Some(d) = dev::by_index(ifindex) {
            solicit(&d, addr);
        }
    }
    POLLING.store(false, Ordering::Release);
}

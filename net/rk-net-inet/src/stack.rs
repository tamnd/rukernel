//! The global state of the stack and the paths of the packets: the input of the frames, ARP,
//! IPv4, ICMP and the input of UDP, and the output of IPv4 through the neighbour table. The
//! module `stack6` has the paths of IPv6.
//!
//! Each table has its own lock, and the code holds at most one of them at a time. No lock is
//! held while a device sends a frame or while a socket takes a datagram.

use crate::ip::{self, Ip};
use crate::ipv4::{
    self, Addr, HLEN, Header, PROTO_ICMP, PROTO_TCP, PROTO_UDP, UDP_HLEN, UdpHeader,
};
use crate::ports::{self, Ports};
use crate::socket::{Dgram, Proto};
use crate::{checksum, frag, igmp, neigh, route};
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::if_ether::{ETH_P_ARP, ETH_P_IP, ETH_P_IPV6};
use rk_abi::native::rtnetlink::RT_SCOPE_LINK;
use rk_abi::native::socket::SO_BINDTOIFINDEX;
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
/// The proxy entries of ARP, as the `phash_buckets` of `arp_tbl` of Linux.
static PNEIGH: PerNet<SpinLock<neigh::Proxy>> = PerNet::new(|| SpinLock::new(neigh::Proxy::new()));
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
/// The key of a queue of the reassembly: the source, the destination, the identification and
/// the protocol, as `struct frag_v4_compare_key` of Linux.
type FragKey = (Addr, Addr, u16, u8);
/// The queues of the reassembly of IPv4.
static FRAGS: PerNet<SpinLock<frag::Reasm<FragKey>>> =
    PerNet::new(|| SpinLock::new(frag::Reasm::new()));

/// The counters of the stack, as the lines of /proc/net/snmp.
pub struct Counters {
    /// The IPv4 packets that the stack received.
    pub ip_in: AtomicU64,
    /// The IPv4 packets with a bad header.
    pub ip_in_hdr_errors: AtomicU64,
    /// The failures of the reassembly: a bad fragment or a full table.
    pub ip_reasm_fails: AtomicU64,
    /// The queues of the reassembly that timed out.
    pub ip_reasm_timeout: AtomicU64,
    /// The fragments that went to the reassembly.
    pub ip_reasm_reqds: AtomicU64,
    /// The packets that the reassembly completed.
    pub ip_reasm_oks: AtomicU64,
    /// The packets that the stack sent in fragments.
    pub ip_frag_oks: AtomicU64,
    /// The fragments that the stack made.
    pub ip_frag_creates: AtomicU64,
    /// The packets to an address that is not local, when the device does not forward.
    pub ip_in_addr_errors: AtomicU64,
    /// The packets that the stack forwarded, as `IPSTATS_MIB_OUTFORWDATAGRAMS` of Linux.
    pub ip_forw_datagrams: AtomicU64,
    /// The packets that needed fragments and had the flag "do not fragment".
    pub ip_frag_fails: AtomicU64,
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
        self.ip_reasm_timeout.store(0, Ordering::Relaxed);
        self.ip_reasm_reqds.store(0, Ordering::Relaxed);
        self.ip_reasm_oks.store(0, Ordering::Relaxed);
        self.ip_frag_oks.store(0, Ordering::Relaxed);
        self.ip_frag_creates.store(0, Ordering::Relaxed);
        self.ip_in_addr_errors.store(0, Ordering::Relaxed);
        self.ip_forw_datagrams.store(0, Ordering::Relaxed);
        self.ip_frag_fails.store(0, Ordering::Relaxed);
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
        ip_reasm_timeout: AtomicU64::new(0),
        ip_reasm_reqds: AtomicU64::new(0),
        ip_reasm_oks: AtomicU64::new(0),
        ip_frag_oks: AtomicU64::new(0),
        ip_frag_creates: AtomicU64::new(0),
        ip_in_delivers: AtomicU64::new(0),
        ip_in_unknown_protos: AtomicU64::new(0),
        ip_in_addr_errors: AtomicU64::new(0),
        ip_forw_datagrams: AtomicU64::new(0),
        ip_frag_fails: AtomicU64::new(0),
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

/// Tells if a socket bound to the device `bound` takes a packet that came in on the device
/// `dif`, as `inet_sk_bound_dev_eq` of Linux. `bound` is 0 for a socket without a device. `dif`
/// is 0 for a packet of the loopback device, which every socket takes, as the `rt_iif` of a
/// local route of Linux.
pub(crate) fn dev_match(bound: u32, dif: u32) -> bool {
    bound == 0 || dif == 0 || bound == dif
}

/// The device of a received packet for `dev_match`: the interface, or 0 for the loopback
/// device.
pub(crate) fn dif_of(dev: &NetDevice) -> u32 {
    if dev.kind() == LinkKind::Loopback { 0 } else { dev.ifindex() }
}

/// Gives the new device of a socket for `SO_BINDTODEVICE` or `SO_BINDTOIFINDEX` with the value
/// `value`, as `sock_setbindtodevice` and `sock_bindtoindex_locked` in net/core/sock.c of Linux.
/// `bound` is the device of the socket now. An empty name or the index 0 removes the binding.
///
/// # Errors
///
/// Gives `EPERM` if the socket has a device and the process does not have `CAP_NET_RAW`,
/// `EINVAL` for a short or negative index, and `ENODEV` for a device that is not there.
pub(crate) fn bind_device(bound: u32, name: u32, value: &[u8]) -> Result<u32> {
    let ifindex = if name == SO_BINDTOIFINDEX {
        let raw: [u8; 4] = value.get(..4).and_then(|v| v.try_into().ok()).ok_or(Errno::EINVAL)?;
        let i = i32::from_ne_bytes(raw);
        if i < 0 {
            return Err(Errno::EINVAL);
        }
        let i = i as u32;
        if i != 0 && dev::by_index(i).is_none() {
            return Err(Errno::ENODEV);
        }
        i
    } else {
        // Linux takes at most `IFNAMSIZ - 1` bytes, and the name ends at the first zero.
        let v = &value[..value.len().min(rk_net::consts::IFNAMSIZ - 1)];
        let v = &v[..v.iter().position(|&b| b == 0).unwrap_or(v.len())];
        if v.is_empty() {
            0
        } else {
            let name = core::str::from_utf8(v).map_err(|_| Errno::ENODEV)?;
            dev::by_name(name).ok_or(Errno::ENODEV)?.ifindex()
        }
    };
    if bound != 0 && !rk_net::ioctl::net_raw() {
        return Err(Errno::EPERM);
    }
    Ok(ifindex)
}

/// The value of `SO_BINDTODEVICE` or `SO_BINDTOIFINDEX` for a socket on the device `bound`, as
/// `sock_getbindtodevice` of Linux: the name with its zero, or no bytes if the socket has no
/// device.
pub(crate) fn bound_device(bound: u32, name: u32) -> Vec<u8> {
    if name == SO_BINDTOIFINDEX {
        return (bound as i32).to_ne_bytes().to_vec();
    }
    match dev::by_index(bound).filter(|_| bound != 0) {
        Some(d) => {
            let mut v = d.name().as_bytes().to_vec();
            v.push(0);
            v
        }
        None => Vec::new(),
    }
}

/// The UDP socket that `id`, `src` and `sport` name in the ports table `table`: a socket on
/// the port `port` for `dst`, with no peer or the peer `src` and `sport`, and bound to no device
/// or to `dif`. The addresses of an IPv4 packet are IPv4-mapped.
pub(crate) fn find_socket(
    table: &SpinLock<Ports>,
    port: u16,
    dst: Ip,
    src: Ip,
    sport: u16,
    dif: u32,
) -> Option<Arc<Dgram>> {
    let found = table.lock().find(port, dst);
    // A socket with the peer `src` wins over a socket without a peer, as the score of
    // `compute_score` in net/ipv4/udp.c.
    let mut best: Option<(u32, Arc<Dgram>)> = None;
    for b in found {
        let Some(sock) = socket(b.id) else { continue };
        let Some(score) = sock.score(&src, sport, dif) else { continue };
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

/// Finds the route to `dst` through the interface `oif`, or through any interface if `oif` is
/// 0, as `ip_route_output_key` of Linux with `flowi4_oif`.
pub(crate) fn route_oif(dst: Addr, oif: u32) -> Result<route::Next> {
    ROUTES.lock().lookup_route(dst, oif).map(|(n, _)| n)
}

/// The interface of the local address `a`, as `__ip_dev_find` of Linux.
pub(crate) fn dev_of_addr(a: Addr) -> Option<u32> {
    ROUTES.lock().addrs().iter().find(|x| x.local == a).map(|x| x.ifindex)
}

/// Finds the route of a multicast packet to `dst` from `src` through `oif`, as
/// `ip_route_output_key_hash_rcu` of Linux. Without an interface, the interface of the source
/// address sends the packet. A packet with an interface goes out on it without a route. A
/// packet without an interface and a source address takes the route to `dst`.
///
/// # Errors
///
/// Gives `ENETUNREACH` for a source address that is not local or a group without a route, and
/// `ENODEV` for an interface that is not there.
pub(crate) fn route_mc(dst: Addr, oif: u32, src: Addr) -> Result<route::Next> {
    let oif = match (oif, src) {
        (0, ipv4::ANY) => return route_oif(dst, 0),
        (0, s) => dev_of_addr(s).ok_or(Errno::ENETUNREACH)?,
        (o, _) => o,
    };
    if dev::by_index(oif).is_none() {
        return Err(Errno::ENODEV);
    }
    let src = if src == ipv4::ANY {
        ROUTES.lock().select_addr(oif, ipv4::ANY, RT_SCOPE_LINK as u8).unwrap_or(ipv4::ANY)
    } else {
        src
    };
    Ok(route::Next { ifindex: oif, hop: dst, src, local: false, broadcast: false })
}

/// Removes the neighbours and the proxy entries of an interface, as `arp_ifdown` of Linux.
pub(crate) fn flush_neigh(ifindex: u32) {
    NEIGH.lock().flush(ifindex, now_ms());
    PNEIGH.lock().flush(ifindex);
    neigh_notify();
}

/// Sends the changes of the neighbour table to `RTNLGRP_NEIGH`, as `neigh_update_notify` of
/// Linux. The caller does not hold the lock of the table.
fn neigh_notify() {
    let changes = NEIGH.lock().take_changes();
    for c in changes {
        let c = match c {
            neigh::Change::New(n) => neigh::Change::New(n.map(ip::mapped)),
            neigh::Change::Del(n) => neigh::Change::Del(n.map(ip::mapped)),
        };
        crate::rtnl::notify_neigh(AF_INET, c);
    }
}

/// Adds or changes a neighbour for `RTM_NEWNEIGH` and `SIOCSARP`, as `neigh_add` of Linux,
/// and sends the packets that waited for it. `flags` are the netlink flags.
///
/// # Errors
///
/// Gives the error of `neigh::Table::add`.
pub(crate) fn neigh_add(
    dev: &NetDevice,
    addr: Addr,
    mac: Option<MacAddr>,
    nud: neigh::Nud,
    flags: u32,
) -> Result<()> {
    let key = (dev.ifindex(), addr);
    let (waiting, mac) = {
        let mut t = NEIGH.lock();
        let waiting = t.add(key, mac, nud, now_ms(), flags)?;
        (waiting, t.lookup(key).unwrap_or(MacAddr::ZERO))
    };
    neigh_notify();
    for mut packet in waiting {
        EthHeader { dst: mac, src: dev.mac(), ethertype: ETH_P_IP as u16 }.push(&mut packet);
        let _ = dev.transmit(packet);
    }
    Ok(())
}

/// Removes a neighbour for `RTM_DELNEIGH` and `SIOCDARP`, as `neigh_delete` of Linux. Gives
/// `false` if there is no entry.
pub(crate) fn neigh_del(ifindex: u32, addr: Addr) -> bool {
    let found = NEIGH.lock().remove((ifindex, addr), now_ms());
    neigh_notify();
    found
}

/// Adds a proxy entry of ARP for `addr` on the interface `ifindex`, or on each interface if it
/// is 0, as `pneigh_create` of Linux. An entry that is there gets the flags `flags`.
pub(crate) fn pneigh_add(addr: Addr, ifindex: u32, flags: u8) {
    PNEIGH.lock().add(addr, ifindex, flags);
}

/// Removes a proxy entry of ARP, as `pneigh_delete` of Linux. Gives `false` if there is no
/// entry with that address and interface.
pub(crate) fn pneigh_del(addr: Addr, ifindex: u32) -> bool {
    PNEIGH.lock().remove(addr, ifindex)
}

/// The proxy entries of ARP.
pub(crate) fn proxies() -> Vec<neigh::ProxyInfo> {
    PNEIGH.lock().entries()
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
    /// The packet must not get fragments, as `IP_PMTUDISC_DO` of Linux.
    pub df: bool,
    /// A packet to a multicast group of the device comes back to the host too, as
    /// `IP_MULTICAST_LOOP` of Linux.
    pub mc_loop: bool,
}

/// Sends a packet with the payload `payload` on the route `next`, as `ip_queue_xmit` of Linux.
/// A packet that fits in the MTU has the flag "do not fragment". A larger packet goes out in
/// fragments, as `ip_do_fragment` in net/ipv4/ip_output.c, or gives `EMSGSIZE` if `out.df` is
/// set.
pub(crate) fn output(next: &route::Next, out: &Out, payload: &[u8]) -> Result<()> {
    let dev = dev::by_index(next.ifindex).ok_or(Errno::ENETUNREACH)?;
    let mtu = dev.mtu() as usize;
    if HLEN + payload.len() > ipv4::MAX_LEN || (out.df && HLEN + payload.len() > mtu) {
        return Err(Errno::EMSGSIZE);
    }
    let mut header = Header::new(out.src, out.dst, out.protocol, payload.len());
    header.ttl = out.ttl;
    header.tos = out.tos;
    header.id = IP_ID.fetch_add(1, Ordering::Relaxed);
    if out.protocol == PROTO_ICMP {
        count_icmp_out(payload);
    }
    if ipv4::is_multicast(out.dst) {
        if out.mc_loop {
            loop_back(&dev, &header, payload);
        }
        // A packet with the time to live 0 stays on the host, as `ip_mc_output` of Linux.
        if out.ttl == 0 {
            return Ok(());
        }
    }
    if HLEN + payload.len() <= mtu {
        let mut buf = NetBuf::new(HEADROOM, HLEN + payload.len());
        buf.extend_from_slice(&header.to_bytes());
        buf.extend_from_slice(payload);
        return transmit(&dev, next, buf);
    }
    let parts = frag::split(payload.len(), mtu.saturating_sub(HLEN));
    let last = parts.len() - 1;
    for (i, (offset, len)) in parts.into_iter().enumerate() {
        let mut h = header;
        h.total_len = (HLEN + len) as u16;
        h.frag = (offset / 8) as u16 | if i < last { ipv4::MF } else { 0 };
        let mut buf = NetBuf::new(HEADROOM, HLEN + len);
        buf.extend_from_slice(&h.to_bytes());
        buf.extend_from_slice(&payload[offset..offset + len]);
        count(&COUNTERS.ip_frag_creates);
        transmit(&dev, next, buf)?;
    }
    count(&COUNTERS.ip_frag_oks);
    Ok(())
}

/// The multicast packets that the host sends to its own groups, with the device that sent
/// them, as the queue of `dev_loopback_xmit` of Linux. The poll takes them as packets that came
/// in on the device. The queue is not in the namespace, because the poll takes it for each
/// namespace.
static LOOPED: SpinLock<VecDeque<(Arc<NetDevice>, NetBuf)>> = SpinLock::new(VecDeque::new());

/// Puts a copy of a multicast packet in `LOOPED` if the device `dev` is in the group, as
/// `ip_mc_output` of Linux. The loopback device takes its own packets already.
fn loop_back(dev: &Arc<NetDevice>, header: &Header, payload: &[u8]) {
    if dev.kind() == LinkKind::Loopback || !igmp::joined(dev.ifindex(), header.dst) {
        return;
    }
    let mut buf = NetBuf::new(HEADROOM, HLEN + payload.len());
    buf.extend_from_slice(&header.to_bytes());
    buf.extend_from_slice(payload);
    LOOPED.lock().push_back((dev.clone(), buf));
}

/// Takes the packets of `LOOPED`. Gives their count.
fn poll_looped() -> usize {
    let looped: Vec<(Arc<NetDevice>, NetBuf)> = LOOPED.lock().drain(..).collect();
    let n = looped.len();
    for (d, frame) in looped {
        let _in = rk_net::ns::enter_index(d.net());
        ip_input(&d, frame, false);
    }
    n
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

/// Gives a packet that the host makes to the link, and counts it.
fn transmit(dev: &NetDevice, next: &route::Next, buf: NetBuf) -> Result<()> {
    count(&COUNTERS.ip_out);
    xmit(dev, next, buf)
}

/// Gives a packet to the link: the loopback device, a broadcast, or a neighbour, as
/// `ip_finish_output2` of Linux.
pub(crate) fn xmit(dev: &NetDevice, next: &route::Next, mut buf: NetBuf) -> Result<()> {
    let mac = dev.mac();
    let ether = |dst| EthHeader { dst, src: mac, ethertype: ETH_P_IP as u16 };
    // A TUN device and a line device have no link header and no neighbours, as the loopback
    // device.
    if matches!(dev.kind(), LinkKind::Loopback | LinkKind::Tun | LinkKind::Line { .. }) {
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
        // A frame to a link multicast or broadcast address is not `PACKET_HOST`, and the stack
        // does not forward it.
        ETH_P_IP => ip_input(dev, frame, !eth.dst.is_multicast()),
        ETH_P_IPV6 => crate::stack6::input(dev, frame, !eth.dst.is_multicast()),
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
    let proxied = !ours && p.op == ARPOP_REQUEST && proxy_arp(dev, &p);
    // A probe for duplicate addresses has the sender 0.0.0.0, and it does not go in the table.
    if p.sender_ip != ipv4::ANY && !p.sender_mac.is_multicast() {
        let key = (dev.ifindex(), p.sender_ip);
        // A request that the host answers makes an entry of the sender, as `neigh_event_ns`.
        let waiting = NEIGH.lock().update(key, p.sender_mac, now_ms(), ours || proxied);
        neigh_notify();
        for mut packet in waiting {
            EthHeader { dst: p.sender_mac, src: dev.mac(), ethertype: ETH_P_IP as u16 }
                .push(&mut packet);
            let _ = dev.transmit(packet);
        }
    }
    if p.op == ARPOP_REQUEST && (ours || proxied) {
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

/// Tells if the host answers the ARP request `p` for an address of another host, as the
/// `IN_DEV_FORWARD` case of `arp_process` in net/ipv4/arp.c of Linux. The interface must
/// forward, the target must have a unicast route through another interface, and `proxy_arp`
/// of the interface or a proxy entry must allow it. Linux waits `proxy_delay` before the reply
/// to a broadcast request. This stack answers at once.
fn proxy_arp(dev: &NetDevice, p: &ArpPacket) -> bool {
    use rk_net::sysctl::{Family, Scope, conf};
    let ifindex = dev.ifindex();
    // `ip_route_input_noref` with the sender as the source: a sender 0.0.0.0 is a martian.
    if p.sender_ip == ipv4::ANY
        || ipv4::is_multicast(p.sender_ip)
        || p.target_ip == ipv4::ANY
        || p.target_ip == ipv4::BROADCAST
        || conf(Family::Ipv4, Scope::Dev(ifindex), "forwarding") == 0
    {
        return false;
    }
    let Ok((next, kind)) = ROUTES.lock().lookup_input(p.target_ip) else { return false };
    if u32::from(kind) != rk_abi::native::rtnetlink::RTN_UNICAST
        || next.broadcast
        || next.ifindex == ifindex
    {
        return false;
    }
    let orconf = |name| {
        conf(Family::Ipv4, Scope::All, name) != 0
            || conf(Family::Ipv4, Scope::Dev(ifindex), name) != 0
    };
    let medium = |i| conf(Family::Ipv4, Scope::Dev(i), "medium_id");
    crate::forward::fwd_proxy(orconf("proxy_arp"), medium(ifindex), medium(next.ifindex))
        || PNEIGH.lock().lookup(p.target_ip, ifindex)
}

/// Takes an IPv4 packet, as `ip_rcv` and `ip_local_deliver` of Linux. It takes a packet to a
/// local address, to a broadcast address, or to a multicast group of the device, and it puts
/// the fragments together first. It forwards a packet to another host if the device forwards.
/// `host` tells that the frame came to the link address of the device, `PACKET_HOST` of Linux.
pub(crate) fn ip_input(dev: &NetDevice, mut frame: NetBuf, host: bool) {
    count(&COUNTERS.ip_in);
    let Ok(h) = Header::parse(frame.data()) else {
        return count(&COUNTERS.ip_in_hdr_errors);
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
    // A multicast packet goes to the groups of the device, as `ip_route_input_mc`. A packet
    // that the host sends to a group comes back on the loopback device.
    let mcast = ipv4::is_multicast(h.dst) && (loopback || igmp::joined(dev.ifindex(), h.dst));
    if !local && !broadcast && !mcast {
        if !loopback && !ipv4::is_multicast(h.dst) && crate::forward::forward4(dev, &h, frame, host)
        {
            return;
        }
        return count(&COUNTERS.ip_in_addr_errors);
    }
    let (h, frame) = if h.is_fragment() {
        match reassemble(&h, frame.data()) {
            Some(x) => x,
            None => return,
        }
    } else {
        (h, frame)
    };
    let dif = dif_of(dev);
    let raw = raw_sockets(AF_INET, h.protocol);
    for sock in &raw {
        sock.deliver_raw(&h, frame.data(), dif);
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
    let broadcast = broadcast || mcast;
    match h.protocol {
        PROTO_ICMP => icmp_input(dev, &h, payload, broadcast),
        PROTO_UDP => udp_input(&h, packet, broadcast, dif),
        PROTO_TCP => {
            crate::tcp::input(ip::mapped(h.src), ip::mapped(h.dst), payload, broadcast, dif);
        }
        _ if raw.is_empty() && !broadcast => {
            icmp_error(&h, packet, ICMP_DEST_UNREACH, ICMP_PROT_UNREACH);
        }
        _ => {}
    }
}

/// Puts the fragment `packet` with the header `h` in its queue, as `ip_defrag` and
/// `ip_frag_reasm` of Linux. Gives the full packet when the last missing fragment comes. The
/// full packet has the header of the first fragment.
fn reassemble(h: &Header, packet: &[u8]) -> Option<(Header, NetBuf)> {
    count(&COUNTERS.ip_reasm_reqds);
    let key = (h.src, h.dst, h.id, h.protocol);
    let more = h.frag & ipv4::MF != 0;
    let (head, data) = packet.split_at(h.hlen);
    let r = FRAGS.lock().add(key, h.frag_offset(), more, head, data, now_ms());
    let (mut head, data) = match r {
        frag::Add::Wait => return None,
        frag::Add::Fail => {
            count(&COUNTERS.ip_reasm_fails);
            return None;
        }
        frag::Add::Done(head, data) => (head, data),
    };
    let len = head.len() + data.len();
    if len > ipv4::MAX_LEN {
        count(&COUNTERS.ip_reasm_fails);
        return None;
    }
    head[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    head[6..8].fill(0);
    head[10..12].fill(0);
    let sum = checksum::checksum(&head);
    head[10..12].copy_from_slice(&sum.to_be_bytes());
    let mut buf = NetBuf::new(HEADROOM, len);
    buf.extend_from_slice(&head);
    buf.extend_from_slice(&data);
    let h = Header::parse(buf.data()).ok()?;
    count(&COUNTERS.ip_reasm_oks);
    Some((h, buf))
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

/// Takes an ICMP message, as `icmp_rcv` of Linux. `broadcast` tells that the packet went to a
/// broadcast address or to a multicast group.
fn icmp_input(dev: &NetDevice, h: &Header, msg: &[u8], broadcast: bool) {
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
        // `icmp_echo` of Linux ignores a request for `net.ipv4.icmp_echo_ignore_all`, and
        // `icmp_rcv` ignores a request to a broadcast address or a multicast group for
        // `net.ipv4.icmp_echo_ignore_broadcasts`.
        ICMP_ECHO
            if rk_net::sysctl::ipv4("icmp_echo_ignore_all") == 0
                && (!broadcast || rk_net::sysctl::ipv4("icmp_echo_ignore_broadcasts") == 0) =>
        {
            // The reply to a broadcast or a multicast request comes from an address of the
            // device, as `fib_compute_spec_dst` of Linux.
            let src = if broadcast {
                let scope = rk_abi::native::rtnetlink::RT_SCOPE_UNIVERSE as u8;
                match ROUTES.lock().select_addr(dev.ifindex(), h.src, scope) {
                    Some(a) => a,
                    None => return,
                }
            } else {
                h.dst
            };
            let mut reply = msg.to_vec();
            reply[0] = ICMP_ECHOREPLY;
            reply[2..4].fill(0);
            let sum = checksum::checksum(&reply);
            reply[2..4].copy_from_slice(&sum.to_be_bytes());
            send_icmp(src, h.src, h.tos, &reply);
        }
        ICMP_ECHOREPLY => {
            let id = u16::from_be_bytes([msg[4], msg[5]]);
            let (dst, src) = (ip::mapped(h.dst), ip::mapped(h.src));
            if let Some(sock) = find_socket(&PING_PORTS, id, dst, src, 0, dif_of(dev)) {
                sock.deliver(ip::mapped(h.src), 0, 0, msg.to_vec(), None);
            }
        }
        ICMP_DEST_UNREACH | ICMP_TIME_EXCEEDED | ICMP_PARAMETERPROB => {
            icmp_unreach(msg[0], msg[1], &msg[8..], dif_of(dev));
        }
        _ => {}
    }
}

/// Gives the error of an ICMP error message to the socket of the packet in it, as `udp_err`
/// and `ping_err` of Linux. `inner` is the start of the packet that failed, and the message
/// came in on `dif`.
fn icmp_unreach(kind: u8, code: u8, inner: &[u8], dif: u32) {
    let Some(ih) = Header::parse_loose(inner) else { return };
    let Some(l4) = inner.get(ih.hlen..ih.hlen + 8) else { return };
    let (err, hard) = icmp_errno(kind, code);
    let sock = match ih.protocol {
        PROTO_UDP => {
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            find_socket(&UDP_PORTS, sport, ip::mapped(ih.src), ip::mapped(ih.dst), dport, dif)
        }
        PROTO_ICMP if l4[0] == ICMP_ECHO => {
            let id = u16::from_be_bytes([l4[4], l4[5]]);
            find_socket(&PING_PORTS, id, ip::mapped(ih.src), ip::mapped(ih.dst), 0, dif)
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
    let ttl = rk_net::sysctl::default_ttl();
    // A large reply goes out in fragments, as the socket of `icmp_reply` with
    // `IP_PMTUDISC_DONT`.
    let out = Out { src, dst, protocol: PROTO_ICMP, ttl, tos, df: false, mc_loop: false };
    // An ICMP message that the stack makes is not for a socket, and a lost one is not an error.
    let _ = output(&next, &out, msg);
}

/// The most bytes of the failed packet in an ICMP error. The full message is at most 576 bytes,
/// as `icmp_send` of Linux.
const ICMP_ERROR_DATA: usize = 576 - HLEN - 8;

/// Sends an ICMP error about the packet `packet` with the header `h`, as `icmp_send` of Linux.
/// The stack sends no error about a broadcast or about an ICMP error.
pub(crate) fn icmp_error(h: &Header, packet: &[u8], kind: u8, code: u8) {
    icmp_send(h, packet, kind, code, 0);
}

/// Sends an ICMP error as `icmp_error`, with `info` in the bytes 4 to 8 of the message: the
/// MTU of `ICMP_FRAG_NEEDED` or the gateway of `ICMP_REDIRECT`. The error about a packet that
/// the host forwards comes from the address of the route to the sender, as `__icmp_send` of
/// Linux with `icmp_errors_use_inbound_ifaddr` 0. The stack sends no error about a fragment
/// that is not the first one.
pub(crate) fn icmp_send(h: &Header, packet: &[u8], kind: u8, code: u8, info: u32) {
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
    if h.frag_offset() != 0 || h.dst == ipv4::ANY || ipv4::is_multicast(h.dst) {
        return;
    }
    let (local, broadcast) = {
        let routes = ROUTES.lock();
        (routes.is_local(h.dst), routes.is_broadcast(h.dst))
    };
    if broadcast {
        return;
    }
    let src = if local {
        h.dst
    } else {
        match route(h.src) {
            Ok(n) => n.src,
            Err(_) => return,
        }
    };
    let data = &packet[..packet.len().min(ICMP_ERROR_DATA)];
    let mut msg = Vec::with_capacity(8 + data.len());
    msg.extend_from_slice(&[kind, code, 0, 0]);
    msg.extend_from_slice(&info.to_be_bytes());
    msg.extend_from_slice(data);
    let sum = checksum::checksum(&msg);
    msg[2..4].copy_from_slice(&sum.to_be_bytes());
    send_icmp(src, h.src, h.tos, &msg);
}

/// Takes a UDP datagram, as `udp_rcv` of Linux. `packet` has the IPv4 header, and it came in
/// on `dif`.
fn udp_input(h: &Header, packet: &[u8], broadcast: bool, dif: u32) {
    let d = &packet[h.hlen..];
    let Some(u) = UdpHeader::parse(d) else { return count(&COUNTERS.udp_in_errors) };
    let d = &d[..usize::from(u.len)];
    if u.check != 0
        && checksum::fold(checksum::add(checksum::pseudo(h.src, h.dst, PROTO_UDP, u.len), d)) != 0
    {
        count(&COUNTERS.udp_in_csum_errors);
        return count(&COUNTERS.udp_in_errors);
    }
    let (dst, src) = (ip::mapped(h.dst), ip::mapped(h.src));
    if broadcast {
        return udp_mcast_input(h, &d[UDP_HLEN..], u.src, u.dst, dif);
    }
    let found = find_socket(&UDP_PORTS, u.dst, dst, src, u.src, dif);
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

/// Gives a UDP datagram to a broadcast address or a multicast group to each socket that takes
/// it, as `__udp4_lib_mcast_deliver` of Linux. A socket takes a datagram to a group if it is in
/// the group on the device or if it has `IP_MULTICAST_ALL`, as `ip_mc_sf_allow`.
fn udp_mcast_input(h: &Header, data: &[u8], sport: u16, dport: u16, dif: u32) {
    let (dst, src) = (ip::mapped(h.dst), ip::mapped(h.src));
    let found = UDP_PORTS.lock().find(dport, dst);
    let socks: Vec<Arc<Dgram>> = found
        .iter()
        .filter_map(|b| socket(b.id))
        .filter(|s| s.score(&src, sport, dif).is_some() && s.mc_allow(h.dst, dif))
        .collect();
    if socks.is_empty() {
        return count(&COUNTERS.udp_no_ports);
    }
    for sock in socks {
        if sock.deliver(src, 0, sport, data.to_vec(), None) {
            count(&COUNTERS.udp_in);
        } else {
            count(&COUNTERS.udp_rcvbuf_errors);
        }
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
        rk_frame::sync::wait_hint();
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
        n += poll_looped();
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
    neigh_notify();
    for (ifindex, addr) in probes {
        if let Some(d) = dev::by_index(ifindex) {
            solicit(&d, addr);
        }
    }
    let expired = {
        let mut frags = FRAGS.lock();
        if frags.is_empty() { 0 } else { frags.expire(now_ms()) }
    };
    for _ in 0..expired {
        count(&COUNTERS.ip_reasm_timeout);
        count(&COUNTERS.ip_reasm_fails);
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
    FRAGS.reset();
    PNEIGH.reset();
    COUNTERS.reset();
}

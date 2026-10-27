//! The IPv4 files of /proc/net: `route` as `fib_route_seq_show` in net/ipv4/fib_trie.c, `arp`
//! as `arp_seq_show` in net/ipv4/arp.c, `snmp` and `netstat` as net/ipv4/proc.c, and the socket
//! tables `tcp`, `udp`, `raw` and `icmp` as net/ipv4/tcp_ipv4.c, udp.c, raw.c and ping.c.
//!
//! The IPv6 files: `if_inet6` as `if6_seq_show` in net/ipv6/addrconf.c, `ipv6_route` as
//! `ipv6_route_native_seq_show` in net/ipv6/ip6_fib.c, `snmp6` as net/ipv6/proc.c, and the
//! socket tables `tcp6`, `udp6`, `raw6` and `icmp6`. A table of IPv4 has only the `AF_INET`
//! sockets, and a table of IPv6 only the `AF_INET6` sockets, as Linux.

use crate::ip::Ip;
use crate::neigh::Nud;
use crate::route::{RTAX_ADVMSS, RTAX_RTT, RTAX_WINDOW};
use crate::socket::{Proto, SockLine};
use crate::stack::{self, COUNTERS, ROUTES};
use crate::stack6::{COUNTERS6, ROUTES6};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use rk_abi::native::rtnetlink::{
    RT_TABLE_MAIN, RTN_BLACKHOLE, RTN_BROADCAST, RTN_LOCAL, RTN_MULTICAST, RTN_PROHIBIT,
    RTN_UNREACHABLE,
};
use rk_net::consts::{AF_INET, AF_INET6, ATF_COM, RTF_GATEWAY, RTF_HOST, RTF_REJECT, RTF_UP};
use rk_net::dev;
use rk_net::ether::MacAddr;

/// Adds the files to /proc/net.
pub(crate) fn init() {
    rk_net::procfs::register("route", show_route);
    rk_net::procfs::register("arp", show_arp);
    rk_net::procfs::register("snmp", show_snmp);
    rk_net::procfs::register("netstat", show_netstat);
    rk_net::procfs::register("tcp", show_tcp);
    rk_net::procfs::register("udp", show_udp);
    rk_net::procfs::register("raw", show_raw);
    rk_net::procfs::register("icmp", show_icmp);
    rk_net::procfs::register("if_inet6", show_if_inet6);
    rk_net::procfs::register("ipv6_route", show_ipv6_route);
    rk_net::procfs::register("snmp6", show_snmp6);
    rk_net::procfs::register("tcp6", show_tcp6);
    rk_net::procfs::register("udp6", show_udp6);
    rk_net::procfs::register("raw6", show_raw6);
    rk_net::procfs::register("icmp6", show_icmp6);
}

/// The text of a pointer of `%pK`, as Linux shows it with `kernel.kptr_restrict`.
const POINTER: &str = "0000000000000000";

/// A time in milliseconds in the unit of `clock_t`, as `jiffies_to_clock_t` of Linux.
fn clock_t(ms: u64) -> u64 {
    ms / (1000 / USER_HZ)
}

/// The ticks of `clock_t` in one second, `USER_HZ` of Linux.
const USER_HZ: u64 = 100;

/// The width of a line of /proc/net/tcp without its newline, `TMPSZ - 1` of Linux.
const TCP_WIDTH: usize = 149;

/// The text of /proc/net/tcp, as `tcp4_seq_show` of Linux.
pub(crate) fn show_tcp() -> String {
    let header = format!(
        "{:<w$}\n",
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  \
         timeout inode",
        w = TCP_WIDTH
    );
    show_tcp_family(AF_INET, header)
}

/// The text of /proc/net/tcp6, as `tcp6_seq_show` of Linux. The lines have no padding.
pub(crate) fn show_tcp6() -> String {
    show_tcp_family(AF_INET6, format!("  sl  {SOCK6_HEADER} timeout inode\n"))
}

/// The text of /proc/net/tcp or /proc/net/tcp6: the sockets of the family `family`.
fn show_tcp_family(family: u32, mut out: String) -> String {
    let lines = crate::tcp::proc_lines();
    for (i, l) in lines.iter().filter(|l| l.family == family).enumerate() {
        let addrs = format!(
            "{i:4}: {}:{:04X} {}:{:04X} {:02X}",
            addr_hex(family, &l.local.0),
            l.local.1,
            addr_hex(family, &l.remote.0),
            l.remote.1,
            l.state
        );
        let line = match &l.info {
            // A listening socket, with the values of a new socket: the initial RTO of one
            // second, a window of 10 segments and no queue of TCP Fast Open.
            None => format!(
                "{addrs} {:08X}:{:08X} 00:00000000 00000000 {:5} {:8} {} 1 {POINTER} {} 0 0 10 0",
                0,
                l.accept_queue,
                l.uid,
                0,
                l.ino,
                clock_t(u64::from(crate::tcp::conn::RTO_INIT)),
            ),
            // A connection that waits for its last ACK is a request of Linux, without an inode.
            Some(c) if l.state == 3 => format!(
                "{addrs} {:08X}:{:08X} {:02X}:{:08X} {:08X} {:5} {:8} {} {} {POINTER}",
                0,
                0,
                1,
                clock_t(c.timer_left),
                c.retransmits,
                l.uid,
                0,
                0,
                0,
            ),
            Some(c) if l.state == 6 => format!(
                "{addrs} {:08X}:{:08X} {:02X}:{:08X} {:08X} {:5} {:8} {} {} {POINTER}",
                0,
                0,
                3,
                clock_t(c.timer_left),
                0,
                0,
                0,
                0,
                1,
            ),
            Some(c) => {
                let ssthresh = if c.ssthresh >= crate::tcp::cc::INFINITE_SSTHRESH {
                    -1
                } else {
                    i64::from(c.ssthresh)
                };
                format!(
                    "{addrs} {:08X}:{:08X} {:02X}:{:08X} {:08X} {:5} {:8} {} 1 {POINTER} {} {} {} \
                     {} {}",
                    c.tx_queue,
                    c.rx_queue,
                    c.timer as u8,
                    clock_t(c.timer_left),
                    c.retransmits,
                    l.uid,
                    c.probes,
                    l.ino,
                    clock_t(u64::from(c.rto)),
                    clock_t(u64::from(c.ato)),
                    c.quick << 1,
                    c.cwnd,
                    ssthresh,
                )
            }
        };
        if family == AF_INET {
            out.push_str(&format!("{line:<w$}\n", w = TCP_WIDTH));
        } else {
            out.push_str(&format!("{line}\n"));
        }
    }
    out
}

/// The header of the IPv6 socket tables after the column `sl`, up to the column `uid`.
const SOCK6_HEADER: &str = "local_address                         remote_address                        \
                            st tx_queue rx_queue tr tm->when retrnsmt   uid ";

/// An address of a socket in the form of a socket table: `%08X` of the IPv4 address, or four
/// times `%08X` of the IPv6 address, each on a `__be32` as Linux.
fn addr_hex(family: u32, a: &Ip) -> String {
    if family == AF_INET {
        return format!("{:08X}", hex(crate::ip::v4(a).unwrap_or([0; 4])));
    }
    a.as_chunks::<4>().0.iter().map(|w| format!("{:08X}", hex(*w))).collect()
}

/// The width of a line of /proc/net/udp and /proc/net/icmp without its newline.
const UDP_WIDTH: usize = 127;

/// The buckets of the table of the UDP ports, `UDP_HTABLE_SIZE_MIN` of Linux. The bucket of a
/// socket is the first number of its line.
const UDP_BUCKETS: u16 = 256;
/// The buckets of the table of the echo sockets, `PING_HTABLE_SIZE` of Linux.
const PING_BUCKETS: u16 = 64;

/// The datagram sockets of the kind `kind`, with their bucket in the table of Linux, in the
/// order of the buckets.
fn dgram_lines(family: u32, kind: fn(Proto) -> bool, buckets: u16) -> Vec<(u16, SockLine)> {
    let mut lines: Vec<(u16, SockLine)> = stack::dgram_sockets()
        .iter()
        .filter(|s| s.family() == family && kind(s.proto()))
        .filter_map(|s| s.proc_line())
        .map(|l| (l.local.1 % buckets, l))
        .collect();
    lines.sort_by_key(|(b, l)| (*b, l.ino));
    lines
}

/// A line of a datagram socket, as `udp4_format_sock` and `raw_sock_seq_show` of Linux,
/// without the bucket. The state is `TCP_ESTABLISHED` for a socket with a peer, else
/// `TCP_CLOSE`. A send does not wait in a queue, so `tx_queue` is 0.
fn dgram_line(l: &SockLine) -> String {
    format!(
        "{}:{:04X} {}:{:04X} {:02X} {:08X}:{:08X} 00:00000000 00000000 {:5} {:8} {} 2 \
         {POINTER} {}",
        addr_hex(l.family, &l.local.0),
        l.local.1,
        addr_hex(l.family, &l.remote.0),
        l.remote.1,
        if l.connected { 1 } else { 7 },
        0,
        l.rx_queue,
        l.uid,
        0,
        l.ino,
        l.drops
    )
}

/// The header of /proc/net/udp, /proc/net/icmp and /proc/net/raw after the column `sl`.
const DGRAM_HEADER: &str = "local_address rem_address   st tx_queue rx_queue tr tm->when \
                            retrnsmt   uid  timeout inode ref pointer drops";

/// The text of /proc/net/udp or /proc/net/icmp, as `udp4_seq_show` and `ping_v4_seq_show` of
/// Linux.
fn show_udp_like(sl: &str, kind: fn(Proto) -> bool, buckets: u16) -> String {
    let mut out = format!("{:<w$}\n", format!("{sl}{DGRAM_HEADER}"), w = UDP_WIDTH);
    for (b, l) in dgram_lines(AF_INET, kind, buckets) {
        out.push_str(&format!("{:<w$}\n", format!("{b:5}: {}", dgram_line(&l)), w = UDP_WIDTH));
    }
    out
}

/// The text of /proc/net/udp.
pub(crate) fn show_udp() -> String {
    show_udp_like("   sl  ", |p| p == Proto::Udp, UDP_BUCKETS)
}

/// The text of /proc/net/icmp: the ICMP echo sockets.
pub(crate) fn show_icmp() -> String {
    show_udp_like("  sl  ", |p| p == Proto::Ping, PING_BUCKETS)
}

/// The text of /proc/net/raw, as `raw_seq_show` of Linux. The bucket is the protocol, and the
/// lines have no padding.
pub(crate) fn show_raw() -> String {
    let mut out = format!("  sl  {DGRAM_HEADER}\n");
    for (b, l) in dgram_lines(AF_INET, |p| matches!(p, Proto::Raw(_)), 256) {
        out.push_str(&format!("{b:4}: {}\n", dgram_line(&l)));
    }
    out
}

/// The text of a datagram table of IPv6, as `ip6_dgram_sock_seq_show` of Linux.
fn show_dgram6(kind: fn(Proto) -> bool, buckets: u16) -> String {
    let mut out = format!("  sl  {SOCK6_HEADER} timeout inode ref pointer drops\n");
    for (b, l) in dgram_lines(AF_INET6, kind, buckets) {
        out.push_str(&format!("{b:5}: {}\n", dgram_line(&l)));
    }
    out
}

/// The text of /proc/net/udp6.
pub(crate) fn show_udp6() -> String {
    show_dgram6(|p| p == Proto::Udp, UDP_BUCKETS)
}

/// The text of /proc/net/raw6.
pub(crate) fn show_raw6() -> String {
    show_dgram6(|p| matches!(p, Proto::Raw(_)), 256)
}

/// The text of /proc/net/icmp6: the ICMPv6 echo sockets.
pub(crate) fn show_icmp6() -> String {
    show_dgram6(|p| p == Proto::Ping, PING_BUCKETS)
}

/// An IPv6 address as 32 hex digits, as `%pi6` of Linux.
fn hex6(a: &Ip) -> String {
    a.iter().map(|b| format!("{b:02x}")).collect()
}

/// The text of /proc/net/if_inet6: the address, the interface index, the prefix length, the
/// scope, the flags and the interface name.
pub(crate) fn show_if_inet6() -> String {
    let mut out = String::new();
    for a in ROUTES6.lock().addrs() {
        out.push_str(&format!(
            "{} {:02x} {:02x} {:02x} {:02x} {:>8}\n",
            hex6(&a.addr),
            a.ifindex,
            a.prefix,
            crate::ipv6::scope(&a.addr),
            a.flags & 0xff,
            dev_name(a.ifindex)
        ));
    }
    out
}

/// The flags of /proc/net/ipv6_route from include/uapi/linux/ipv6_route.h, which rk-abigen does
/// not give: `RTF_DEFAULT`, `RTF_ADDRCONF`, `RTF_PREFIX_RT`, `RTF_NONEXTHOP` and
/// `RTF_EXPIRES`.
const RTF_DEFAULT: u32 = 0x0001_0000;
const RTF_ADDRCONF: u32 = 0x0004_0000;
const RTF_PREFIX_RT: u32 = 0x0008_0000;
const RTF_NONEXTHOP: u32 = 0x0020_0000;
const RTF_EXPIRES: u32 = 0x0040_0000;

/// The text of /proc/net/ipv6_route: the routes of all tables, as
/// `ipv6_route_native_seq_show`. The reference count and the use count are 0, and a reject
/// route has the device `lo`.
pub(crate) fn show_ipv6_route() -> String {
    let mut out = String::new();
    for r in ROUTES6.lock().routes() {
        let mut flags = RTF_UP;
        if r.gateway.is_some() {
            flags |= RTF_GATEWAY;
        }
        if r.prefix == 128 {
            flags |= RTF_HOST;
        }
        if r.kind == RTN_UNREACHABLE as u8
            || r.kind == RTN_PROHIBIT as u8
            || r.kind == RTN_BLACKHOLE as u8
        {
            flags |= RTF_REJECT;
        }
        if r.addrconf {
            flags |= RTF_ADDRCONF | if r.gateway.is_some() { RTF_DEFAULT } else { RTF_PREFIX_RT };
        }
        if r.expires.is_some() {
            flags |= RTF_EXPIRES;
        }
        if r.kind == RTN_LOCAL as u8 {
            flags |= RTF_NONEXTHOP;
        }
        let dev = if flags & RTF_REJECT != 0 { String::from("lo") } else { dev_name(r.ifindex) };
        out.push_str(&format!(
            "{} {:02x} {} 00 {} {:08x} {:08x} {:08x} {:08x} {:>8}\n",
            hex6(&r.dst),
            r.prefix,
            hex6(&crate::ip::ANY),
            hex6(&r.gateway.unwrap_or(crate::ip::ANY)),
            r.priority,
            0,
            0,
            flags,
            dev
        ));
    }
    out
}

/// The names of the ICMPv6 types of /proc/net/snmp6, `icmp6type2name` of Linux.
const ICMP6_NAMES: [(usize, &str); 15] = [
    (1, "DestUnreachs"),
    (2, "PktTooBigs"),
    (3, "TimeExcds"),
    (4, "ParmProblems"),
    (128, "Echos"),
    (129, "EchoReplies"),
    (130, "GroupMembQueries"),
    (131, "GroupMembResponses"),
    (132, "GroupMembReductions"),
    (133, "RouterSolicits"),
    (134, "RouterAdvertisements"),
    (135, "NeighborSolicits"),
    (136, "NeighborAdvertisements"),
    (137, "Redirects"),
    (143, "MLDv2Reports"),
];

/// The text of /proc/net/snmp6, as `snmp6_seq_show` of Linux: one counter on each line. The
/// stack keeps only some of the counters, and the others are 0.
pub(crate) fn show_snmp6() -> String {
    let c = |a: &core::sync::atomic::AtomicU64| a.load(Ordering::Relaxed);
    let k = &COUNTERS6;
    let mut out = String::new();
    let mut line = |name: &str, v: u64| out.push_str(&format!("{name:<32}\t{v}\n"));
    let ip = [
        ("InReceives", c(&k.in_receives)),
        ("InHdrErrors", c(&k.in_hdr_errors)),
        ("InTooBigErrors", 0),
        ("InNoRoutes", 0),
        ("InAddrErrors", c(&k.in_addr_errors)),
        ("InUnknownProtos", c(&k.in_unknown_protos)),
        ("InTruncatedPkts", c(&k.in_truncated)),
        ("InDiscards", 0),
        ("InDelivers", c(&k.in_delivers)),
        ("OutForwDatagrams", 0),
        ("OutRequests", c(&k.out_requests)),
        ("OutDiscards", 0),
        ("OutNoRoutes", c(&k.out_no_routes)),
        ("ReasmTimeout", 0),
        ("ReasmReqds", 0),
        ("ReasmOKs", 0),
        ("ReasmFails", c(&k.reasm_fails)),
        ("FragOKs", 0),
        ("FragFails", 0),
        ("FragCreates", 0),
        ("InMcastPkts", c(&k.in_mcast)),
        ("OutMcastPkts", c(&k.out_mcast)),
        ("InOctets", c(&k.in_octets)),
        ("OutOctets", c(&k.out_octets)),
        ("InMcastOctets", c(&k.in_mcast_octets)),
        ("OutMcastOctets", c(&k.out_mcast_octets)),
        ("InBcastOctets", 0),
        ("OutBcastOctets", 0),
        ("InNoECTPkts", c(&k.in_receives)),
        ("InECT1Pkts", 0),
        ("InECT0Pkts", 0),
        ("InCEPkts", 0),
        ("OutTransmits", c(&k.out_transmits)),
    ];
    for (n, v) in ip {
        line(&format!("Ip6{n}"), v);
    }
    let icmp = [
        ("InMsgs", c(&k.icmp_in)),
        ("InErrors", c(&k.icmp_in_errors)),
        ("OutMsgs", c(&k.icmp_out)),
        ("OutErrors", c(&k.icmp_out_errors)),
        ("InCsumErrors", c(&k.icmp_in_csum_errors)),
        ("OutRateLimitHost", 0),
    ];
    for (n, v) in icmp {
        line(&format!("Icmp6{n}"), v);
    }
    for (dir, types) in [("In", &k.icmp_in_type), ("Out", &k.icmp_out_type)] {
        for (t, n) in ICMP6_NAMES {
            line(&format!("Icmp6{dir}{n}"), c(&types[t]));
        }
    }
    for (dir, types) in [("In", &k.icmp_in_type), ("Out", &k.icmp_out_type)] {
        for (t, v) in types.iter().enumerate() {
            let v = c(v);
            if v != 0 {
                line(&format!("Icmp6{dir}Type{t}"), v);
            }
        }
    }
    let udp = [
        ("InDatagrams", c(&k.udp_in)),
        ("NoPorts", c(&k.udp_no_ports)),
        ("InErrors", c(&k.udp_in_errors)),
        ("OutDatagrams", c(&k.udp_out)),
        ("RcvbufErrors", c(&k.udp_rcvbuf_errors)),
        ("SndbufErrors", 0),
        ("InCsumErrors", c(&k.udp_in_csum_errors)),
        ("IgnoredMulti", 0),
        ("MemErrors", 0),
    ];
    for (n, v) in udp {
        line(&format!("Udp6{n}"), v);
    }
    for (n, _) in udp {
        line(&format!("UdpLite6{n}"), 0);
    }
    out
}

/// The width of a line of /proc/net/route without its newline. Linux pads each line with spaces.
const ROUTE_WIDTH: usize = 127;

/// The name of an interface, or `*` for none.
fn dev_name(ifindex: u32) -> String {
    dev::by_index(ifindex).map_or_else(|| String::from("*"), |d| d.name())
}

/// An address in the form of `%08X` on a `__be32` of Linux: the bytes in the order of memory.
fn hex(a: [u8; 4]) -> u32 {
    u32::from_le_bytes(a)
}

/// The text of /proc/net/route: the routes of the main table, without the broadcast and
/// multicast routes. MTU, window and IRTT come from the metrics of the route.
pub(crate) fn show_route() -> String {
    let mut out = format!(
        "{:<w$}\n",
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT",
        w = ROUTE_WIDTH
    );
    let routes = ROUTES.lock().routes().to_vec();
    for r in routes.iter().filter(|r| r.table == RT_TABLE_MAIN) {
        let kind = u32::from(r.kind);
        if kind == RTN_BROADCAST || kind == RTN_MULTICAST {
            continue;
        }
        let mask = crate::ipv4::mask(r.prefix).to_be_bytes();
        let mut flags =
            if kind == RTN_UNREACHABLE || kind == RTN_PROHIBIT { RTF_REJECT } else { 0 };
        if r.gateway.is_some() {
            flags |= RTF_GATEWAY;
        }
        if r.prefix == 32 {
            flags |= RTF_HOST;
        }
        flags |= RTF_UP;
        let metric = |ty: u16| r.metrics[usize::from(ty - 1)];
        let advmss = metric(RTAX_ADVMSS);
        let line = format!(
            "{}\t{:08X}\t{:08X}\t{:04X}\t0\t0\t{}\t{:08X}\t{}\t{}\t{}",
            dev_name(r.ifindex),
            hex(r.dst),
            hex(r.gateway.unwrap_or_default()),
            flags,
            r.priority as i32,
            hex(mask),
            if advmss != 0 { advmss + 40 } else { 0 },
            metric(RTAX_WINDOW),
            metric(RTAX_RTT) >> 3,
        );
        out.push_str(&format!("{line:<w$}\n", w = ROUTE_WIDTH));
    }
    out
}

/// The text of /proc/net/arp.
pub(crate) fn show_arp() -> String {
    let mut out = String::from(
        "IP address       HW type     Flags       HW address            Mask     Device\n",
    );
    for n in stack::neighbours() {
        let Some(d) = dev::by_index(n.ifindex) else { continue };
        let [a, b, c, e] = n.addr;
        let ip = format!("{a}.{b}.{c}.{e}");
        let flags = if n.state == Nud::Incomplete { 0 } else { ATF_COM };
        let mac = format!("{}", n.mac.unwrap_or(MacAddr::ZERO));
        out.push_str(&format!(
            "{ip:<16} 0x{:<10x}0x{flags:<10x}{mac:<17}     {:<8} {}\n",
            d.kind().arphrd(),
            "*",
            d.name()
        ));
    }
    out
}

/// Adds a line of names and a line of values with the prefix `name`, as `snmp_seq_show_*`.
fn table(out: &mut String, name: &str, fields: &[(&str, i64)]) {
    out.push_str(name);
    out.push(':');
    for (f, _) in fields {
        out.push(' ');
        out.push_str(f);
    }
    out.push('\n');
    out.push_str(name);
    out.push(':');
    for (_, v) in fields {
        out.push_str(&format!(" {v}"));
    }
    out.push('\n');
}

/// Adds the `IcmpMsg` lines, as `icmpmsg_put` of Linux: the types with a count that is not 0,
/// at most 16 in a line.
fn icmp_msg(out: &mut String) {
    let k = &COUNTERS;
    let counts = k.icmp_in_type.iter().chain(&k.icmp_out_type).enumerate();
    let found: Vec<(String, i64)> = counts
        .map(|(i, a)| (i, a.load(Ordering::Relaxed) as i64))
        .filter(|(_, v)| *v != 0)
        .map(|(i, v)| {
            let dir = if i >= 256 { "Out" } else { "In" };
            (format!("{dir}Type{}", i % 256), v)
        })
        .collect();
    for chunk in found.chunks(16) {
        let fields: Vec<(&str, i64)> = chunk.iter().map(|(n, v)| (n.as_str(), *v)).collect();
        table(out, "IcmpMsg", &fields);
    }
}

/// The fields of the `TcpExt` line of /proc/net/netstat, as `snmp4_net_list` of Linux.
const TCP_EXT: &[&str] = &[
    "SyncookiesSent",
    "SyncookiesRecv",
    "SyncookiesFailed",
    "EmbryonicRsts",
    "PruneCalled",
    "RcvPruned",
    "OfoPruned",
    "OutOfWindowIcmps",
    "LockDroppedIcmps",
    "ArpFilter",
    "TW",
    "TWRecycled",
    "TWKilled",
    "PAWSActive",
    "PAWSEstab",
    "DelayedACKs",
    "DelayedACKLocked",
    "DelayedACKLost",
    "ListenOverflows",
    "ListenDrops",
    "TCPHPHits",
    "TCPPureAcks",
    "TCPHPAcks",
    "TCPRenoRecovery",
    "TCPSackRecovery",
    "TCPSACKReneging",
    "TCPSACKReorder",
    "TCPRenoReorder",
    "TCPTSReorder",
    "TCPFullUndo",
    "TCPPartialUndo",
    "TCPDSACKUndo",
    "TCPLossUndo",
    "TCPLostRetransmit",
    "TCPRenoFailures",
    "TCPSackFailures",
    "TCPLossFailures",
    "TCPFastRetrans",
    "TCPSlowStartRetrans",
    "TCPTimeouts",
    "TCPLossProbes",
    "TCPLossProbeRecovery",
    "TCPRenoRecoveryFail",
    "TCPSackRecoveryFail",
    "TCPRcvCollapsed",
    "TCPBacklogCoalesce",
    "TCPDSACKOldSent",
    "TCPDSACKOfoSent",
    "TCPDSACKRecv",
    "TCPDSACKOfoRecv",
    "TCPAbortOnData",
    "TCPAbortOnClose",
    "TCPAbortOnMemory",
    "TCPAbortOnTimeout",
    "TCPAbortOnLinger",
    "TCPAbortFailed",
    "TCPMemoryPressures",
    "TCPMemoryPressuresChrono",
    "TCPSACKDiscard",
    "TCPDSACKIgnoredOld",
    "TCPDSACKIgnoredNoUndo",
    "TCPSpuriousRTOs",
    "TCPMD5NotFound",
    "TCPMD5Unexpected",
    "TCPMD5Failure",
    "TCPSackShifted",
    "TCPSackMerged",
    "TCPSackShiftFallback",
    "TCPBacklogDrop",
    "PFMemallocDrop",
    "TCPMinTTLDrop",
    "TCPDeferAcceptDrop",
    "IPReversePathFilter",
    "TCPTimeWaitOverflow",
    "TCPReqQFullDoCookies",
    "TCPReqQFullDrop",
    "TCPRetransFail",
    "TCPRcvCoalesce",
    "TCPOFOQueue",
    "TCPOFODrop",
    "TCPOFOMerge",
    "TCPChallengeACK",
    "TCPSYNChallenge",
    "TCPFastOpenActive",
    "TCPFastOpenActiveFail",
    "TCPFastOpenPassive",
    "TCPFastOpenPassiveFail",
    "TCPFastOpenListenOverflow",
    "TCPFastOpenCookieReqd",
    "TCPFastOpenBlackhole",
    "TCPSpuriousRtxHostQueues",
    "BusyPollRxPackets",
    "TCPAutoCorking",
    "TCPFromZeroWindowAdv",
    "TCPToZeroWindowAdv",
    "TCPWantZeroWindowAdv",
    "TCPSynRetrans",
    "TCPOrigDataSent",
    "TCPHystartTrainDetect",
    "TCPHystartTrainCwnd",
    "TCPHystartDelayDetect",
    "TCPHystartDelayCwnd",
    "TCPACKSkippedSynRecv",
    "TCPACKSkippedPAWS",
    "TCPACKSkippedSeq",
    "TCPACKSkippedFinWait2",
    "TCPACKSkippedTimeWait",
    "TCPACKSkippedChallenge",
    "TCPWinProbe",
    "TCPKeepAlive",
    "TCPMTUPFail",
    "TCPMTUPSuccess",
    "TCPDelivered",
    "TCPDeliveredCE",
    "TCPAckCompressed",
    "TCPZeroWindowDrop",
    "TCPRcvQDrop",
    "TCPWqueueTooBig",
    "TCPFastOpenPassiveAltKey",
    "TcpTimeoutRehash",
    "TcpDuplicateDataRehash",
    "TCPDSACKRecvSegs",
    "TCPDSACKIgnoredDubious",
    "TCPMigrateReqSuccess",
    "TCPMigrateReqFailure",
    "TCPPLBRehash",
    "TCPAORequired",
    "TCPAOBad",
    "TCPAOKeyNotFound",
    "TCPAOGood",
    "TCPAODroppedIcmps",
];

/// The fields of the `IpExt` line of /proc/net/netstat, as `snmp4_ipextstats_list` of Linux.
const IP_EXT: &[&str] = &[
    "InNoRoutes",
    "InTruncatedPkts",
    "InMcastPkts",
    "OutMcastPkts",
    "InBcastPkts",
    "OutBcastPkts",
    "InOctets",
    "OutOctets",
    "InMcastOctets",
    "OutMcastOctets",
    "InBcastOctets",
    "OutBcastOctets",
    "InCsumErrors",
    "InNoECTPkts",
    "InECT1Pkts",
    "InECT0Pkts",
    "InCEPkts",
    "ReasmOverlaps",
];

/// The text of /proc/net/netstat, as `netstat_seq_show` of Linux. The stack does not keep these
/// counters, so they are 0. rukernel has no MPTCP, so the file has no `MPTcpExt` line.
pub(crate) fn show_netstat() -> String {
    let mut out = String::new();
    let fields: Vec<(&str, i64)> = TCP_EXT.iter().map(|&n| (n, 0)).collect();
    table(&mut out, "TcpExt", &fields);
    let fields: Vec<(&str, i64)> = IP_EXT.iter().map(|&n| (n, 0)).collect();
    table(&mut out, "IpExt", &fields);
    out
}

/// The text of /proc/net/snmp. The stack keeps only some of the counters, and the others are 0.
/// `Forwarding` is 2 because the stack does not forward, and the TCP constants are the values
/// of Linux: the RTO algorithm 1 (other), 200 ms and 120 s, and no limit of connections.
pub(crate) fn show_snmp() -> String {
    let c = |a: &core::sync::atomic::AtomicU64| a.load(Ordering::Relaxed) as i64;
    let k = &COUNTERS;
    let mut out = String::new();
    table(
        &mut out,
        "Ip",
        &[
            ("Forwarding", 2),
            ("DefaultTTL", i64::from(crate::ipv4::DEFAULT_TTL)),
            ("InReceives", c(&k.ip_in)),
            ("InHdrErrors", c(&k.ip_in_hdr_errors)),
            ("InAddrErrors", c(&k.ip_in_addr_errors)),
            ("ForwDatagrams", 0),
            ("InUnknownProtos", c(&k.ip_in_unknown_protos)),
            ("InDiscards", 0),
            ("InDelivers", c(&k.ip_in_delivers)),
            ("OutRequests", c(&k.ip_out)),
            ("OutDiscards", 0),
            ("OutNoRoutes", 0),
            ("ReasmTimeout", 0),
            ("ReasmReqds", 0),
            ("ReasmOKs", 0),
            ("ReasmFails", c(&k.ip_reasm_fails)),
            ("FragOKs", 0),
            ("FragFails", 0),
            ("FragCreates", 0),
            ("OutTransmits", c(&k.ip_out)),
        ],
    );
    // The types of the `Icmp` line, as `icmpmibmap` of Linux.
    let types = [
        ("DestUnreachs", 3),
        ("TimeExcds", 11),
        ("ParmProbs", 12),
        ("SrcQuenchs", 4),
        ("Redirects", 5),
        ("Echos", 8),
        ("EchoReps", 0),
        ("Timestamps", 13),
        ("TimestampReps", 14),
        ("AddrMasks", 17),
        ("AddrMaskReps", 18),
    ];
    let mut icmp: Vec<(String, i64)> = Vec::from([
        (String::from("InMsgs"), c(&k.icmp_in)),
        (String::from("InErrors"), c(&k.icmp_in_errors)),
        (String::from("InCsumErrors"), c(&k.icmp_in_csum_errors)),
    ]);
    icmp.extend(types.iter().map(|(n, t)| (format!("In{n}"), c(&k.icmp_in_type[*t]))));
    for n in ["OutMsgs", "OutErrors", "OutRateLimitGlobal", "OutRateLimitHost"] {
        let v = if n == "OutMsgs" { c(&k.icmp_out) } else { 0 };
        icmp.push((String::from(n), v));
    }
    icmp.extend(types.iter().map(|(n, t)| (format!("Out{n}"), c(&k.icmp_out_type[*t]))));
    let icmp: Vec<(&str, i64)> = icmp.iter().map(|(n, v)| (n.as_str(), *v)).collect();
    table(&mut out, "Icmp", &icmp);
    icmp_msg(&mut out);
    table(
        &mut out,
        "Tcp",
        &[
            ("RtoAlgorithm", 1),
            ("RtoMin", 200),
            ("RtoMax", 120_000),
            ("MaxConn", -1),
            ("ActiveOpens", c(&k.tcp_active_opens)),
            ("PassiveOpens", c(&k.tcp_passive_opens)),
            ("AttemptFails", c(&k.tcp_attempt_fails)),
            ("EstabResets", c(&k.tcp_estab_resets)),
            ("CurrEstab", crate::tcp::curr_estab() as i64),
            ("InSegs", c(&k.tcp_in_segs)),
            ("OutSegs", c(&k.tcp_out_segs)),
            ("RetransSegs", c(&k.tcp_retrans_segs)),
            ("InErrs", c(&k.tcp_in_errs)),
            ("OutRsts", c(&k.tcp_out_rsts)),
            ("InCsumErrors", c(&k.tcp_in_csum_errors)),
        ],
    );
    let udp = |v: [i64; 6]| {
        [
            ("InDatagrams", v[0]),
            ("NoPorts", v[1]),
            ("InErrors", v[2]),
            ("OutDatagrams", v[3]),
            ("RcvbufErrors", v[4]),
            ("SndbufErrors", 0),
            ("InCsumErrors", v[5]),
            ("IgnoredMulti", 0),
            ("MemErrors", 0),
        ]
    };
    let u = udp([
        c(&k.udp_in),
        c(&k.udp_no_ports),
        c(&k.udp_in_errors),
        c(&k.udp_out),
        c(&k.udp_rcvbuf_errors),
        c(&k.udp_in_csum_errors),
    ]);
    table(&mut out, "Udp", &u);
    table(&mut out, "UdpLite", &udp([0; 6]));
    out
}

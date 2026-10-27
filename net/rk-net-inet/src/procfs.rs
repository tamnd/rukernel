//! The IPv4 files of /proc/net: `route` as `fib_route_seq_show` in net/ipv4/fib_trie.c, `arp`
//! as `arp_seq_show` in net/ipv4/arp.c, and `snmp` as `snmp_seq_show` in net/ipv4/proc.c.

use crate::neigh::Nud;
use crate::stack::{self, COUNTERS, ROUTES};
use alloc::format;
use alloc::string::String;
use core::sync::atomic::Ordering;
use rk_abi::native::rtnetlink::{
    RT_TABLE_MAIN, RTN_BROADCAST, RTN_MULTICAST, RTN_PROHIBIT, RTN_UNREACHABLE,
};
use rk_net::consts::{ATF_COM, RTF_GATEWAY, RTF_HOST, RTF_REJECT, RTF_UP};
use rk_net::dev;
use rk_net::ether::MacAddr;

/// Adds the files to /proc/net.
pub(crate) fn init() {
    rk_net::procfs::register("route", show_route);
    rk_net::procfs::register("arp", show_arp);
    rk_net::procfs::register("snmp", show_snmp);
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
/// multicast routes. The kernel does not keep the metrics, so MTU, window and IRTT are 0.
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
        let line = format!(
            "{}\t{:08X}\t{:08X}\t{:04X}\t0\t0\t{}\t{:08X}\t0\t0\t0",
            dev_name(r.ifindex),
            hex(r.dst),
            hex(r.gateway.unwrap_or_default()),
            flags,
            r.priority as i32,
            hex(mask),
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
            ("InUnknownProtos", 0),
            ("InDiscards", 0),
            ("InDelivers", 0),
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
    let icmp = [
        "InMsgs",
        "InErrors",
        "InCsumErrors",
        "InDestUnreachs",
        "InTimeExcds",
        "InParmProbs",
        "InSrcQuenchs",
        "InRedirects",
        "InEchos",
        "InEchoReps",
        "InTimestamps",
        "InTimestampReps",
        "InAddrMasks",
        "InAddrMaskReps",
        "OutMsgs",
        "OutErrors",
        "OutRateLimitGlobal",
        "OutRateLimitHost",
        "OutDestUnreachs",
        "OutTimeExcds",
        "OutParmProbs",
        "OutSrcQuenchs",
        "OutRedirects",
        "OutEchos",
        "OutEchoReps",
        "OutTimestamps",
        "OutTimestampReps",
        "OutAddrMasks",
        "OutAddrMaskReps",
    ];
    let icmp: alloc::vec::Vec<(&str, i64)> = icmp.iter().map(|&n| (n, 0)).collect();
    table(&mut out, "Icmp", &icmp);
    table(
        &mut out,
        "Tcp",
        &[
            ("RtoAlgorithm", 1),
            ("RtoMin", 200),
            ("RtoMax", 120_000),
            ("MaxConn", -1),
            ("ActiveOpens", 0),
            ("PassiveOpens", 0),
            ("AttemptFails", 0),
            ("EstabResets", 0),
            ("CurrEstab", 0),
            ("InSegs", 0),
            ("OutSegs", 0),
            ("RetransSegs", 0),
            ("InErrs", 0),
            ("OutRsts", 0),
            ("InCsumErrors", 0),
        ],
    );
    let udp = |in_: i64, no_ports: i64, errors: i64, rcvbuf: i64| {
        [
            ("InDatagrams", in_),
            ("NoPorts", no_ports),
            ("InErrors", errors),
            ("OutDatagrams", 0),
            ("RcvbufErrors", rcvbuf),
            ("SndbufErrors", 0),
            ("InCsumErrors", 0),
            ("IgnoredMulti", 0),
            ("MemErrors", 0),
        ]
    };
    let u = udp(c(&k.udp_in), c(&k.udp_no_ports), c(&k.udp_in_errors), c(&k.udp_rcvbuf_errors));
    table(&mut out, "Udp", &u);
    table(&mut out, "UdpLite", &udp(0, 0, 0, 0));
    out
}

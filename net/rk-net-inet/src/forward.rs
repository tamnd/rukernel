//! The forwarding of IPv4 and IPv6 packets, as net/ipv4/ip_forward.c, the input routes of
//! net/ipv4/route.c and `ip6_forward` in net/ipv6/ip6_output.c of Linux.
//!
//! A packet to an address of another host goes to the next hop of its route when the device
//! forwards: `net.ipv4.conf.IFACE.forwarding` for IPv4 and `net.ipv6.conf.all.forwarding` for
//! IPv6. The host decreases the time to live or the hop limit, and it sends an ICMP error when
//! the time to live ends, when there is no route, and when the packet is too large for a packet
//! that must not get fragments. An IPv4 packet that can get fragments goes out in fragments.
//! The host sends an ICMP redirect when the packet goes out on the device that it came in on.
//!
//! The pure parts are `verdict`, `fwd_proxy` and `neigh::Redirects`, for the host tests.

use crate::ip::{self, Ip};
use crate::ipv4::{self, DF, HLEN, Header, MF, OFFSET_MASK};
use crate::neigh::Redirects;
use crate::stack::{self, COUNTERS, ROUTES, count, now_ms};
use crate::stack6::{self, COUNTERS6, ROUTES6};
use crate::{frag, ipv6, route};
use rk_abi::Errno;
use rk_abi::native::icmpv6::{
    ICMPV6_ADM_PROHIBITED, ICMPV6_DEST_UNREACH, ICMPV6_EXC_HOPLIMIT, ICMPV6_NOROUTE,
    ICMPV6_NOT_NEIGHBOUR, ICMPV6_PKT_TOOBIG, ICMPV6_TIME_EXCEED,
};
use rk_abi::native::rtnetlink::RTN_UNICAST;
use rk_frame::sync::SpinLock;
use rk_net::buf::{HEADROOM, NetBuf};
use rk_net::consts::{
    ICMP_DEST_UNREACH, ICMP_EXC_TTL, ICMP_FRAG_NEEDED, ICMP_HOST_UNREACH, ICMP_NET_UNREACH,
    ICMP_PKT_FILTERED, ICMP_REDIR_HOST, ICMP_REDIRECT, ICMP_TIME_EXCEEDED,
};
use rk_net::dev::{self, LinkKind, NetDevice};
use rk_net::ns::PerNet;
use rk_net::sysctl::{Family, Scope, conf};

/// The limits of the ICMP redirects, by the source of the packet, as the `inet_peer` entries of
/// Linux.
static REDIRECTS: PerNet<SpinLock<Redirects>> = PerNet::new(|| SpinLock::new(Redirects::new()));

/// What the host does with a packet that it forwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The time to live ends: an ICMP time exceeded message goes back.
    TimeExceeded,
    /// The packet is too large and must not get fragments: an ICMP message with the MTU goes
    /// back.
    FragNeeded(u32),
    /// The packet goes out.
    Send,
    /// The packet goes out in fragments.
    Fragment,
}

/// The verdict for an IPv4 packet with the time to live `ttl` and the length `len`, and the
/// flag "do not fragment" `df`, on a route with the MTU `mtu`, as the checks of `ip_forward` in
/// net/ipv4/ip_forward.c of Linux.
pub fn verdict(ttl: u8, len: usize, df: bool, mtu: usize) -> Verdict {
    if ttl <= 1 {
        Verdict::TimeExceeded
    } else if len <= mtu {
        Verdict::Send
    } else if df {
        Verdict::FragNeeded(mtu as u32)
    } else {
        Verdict::Fragment
    }
}

/// Tells if the host answers an ARP request for a host behind another device with its own
/// address, as `arp_fwd_proxy` in net/ipv4/arp.c of Linux. `proxy_arp` is the value of the
/// device or of `all`, and the medium IDs are the values of the input and the output device. A
/// medium ID 0 tells that each device is a different medium, and -1 stops the proxy.
pub fn fwd_proxy(proxy_arp: bool, in_medium: i32, out_medium: i32) -> bool {
    if !proxy_arp {
        return false;
    }
    match in_medium {
        0 => true,
        -1 => false,
        m => out_medium != m && out_medium != -1,
    }
}

/// The value of a configuration of IPv4 of `all` or of the device, as the `IN_DEV_ORCONF`
/// macro of include/linux/inetdevice.h.
fn orconf(ifindex: u32, name: &str) -> bool {
    conf(Family::Ipv4, Scope::All, name) != 0 || conf(Family::Ipv4, Scope::Dev(ifindex), name) != 0
}

/// Forwards the IPv4 packet `frame` with the header `h` that came in on `dev`, as
/// `ip_route_input_slow`, `ip_error` and `ip_forward` of Linux. `host` tells that the frame
/// came to the link address of the device. Gives `false` if the device does not forward, and
/// the caller counts the packet as an address error. The packet does not go through the
/// reassembly.
pub(crate) fn forward4(dev: &NetDevice, h: &Header, mut frame: NetBuf, host: bool) -> bool {
    let ifindex = dev.ifindex();
    if conf(Family::Ipv4, Scope::Dev(ifindex), "forwarding") == 0 || !host {
        return false;
    }
    // A martian source or destination, as the checks of `ip_route_input_slow`.
    if ipv4::is_multicast(h.src) || h.src == ipv4::BROADCAST || h.src[0] == 0 || h.dst[0] == 0 {
        return true;
    }
    let r = {
        let t = ROUTES.lock();
        // A local source from another host is a martian, as `fib_validate_source`.
        if t.is_local(h.src) {
            return true;
        }
        t.lookup_input(h.dst)
    };
    let next = match r {
        Ok((n, kind)) if u32::from(kind) == RTN_UNICAST && !n.broadcast => n,
        Ok(_) => return true,
        Err(e) => {
            // `ip_error`: a route without a next hop gives an ICMP error.
            let code = match e {
                Errno::ENETUNREACH => ICMP_NET_UNREACH,
                Errno::EHOSTUNREACH => ICMP_HOST_UNREACH,
                Errno::EACCES => ICMP_PKT_FILTERED,
                _ => return true,
            };
            stack::icmp_send(h, frame.data(), ICMP_DEST_UNREACH, code, 0);
            return true;
        }
    };
    let Some(out) = dev::by_index(next.ifindex) else { return true };
    if out.kind() == LinkKind::Loopback {
        return true;
    }
    let mtu = out.mtu() as usize;
    let v = verdict(h.ttl, usize::from(h.total_len), h.frag & DF != 0, mtu);
    match v {
        Verdict::TimeExceeded => {
            count(&COUNTERS.ip_in_hdr_errors);
            stack::icmp_send(h, frame.data(), ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
            return true;
        }
        Verdict::FragNeeded(m) => {
            count(&COUNTERS.ip_frag_fails);
            stack::icmp_send(h, frame.data(), ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, m);
            return true;
        }
        Verdict::Send | Verdict::Fragment => {}
    }
    ipv4::decrease_ttl(&mut frame.data_mut()[..HLEN]);
    if next.ifindex == ifindex && redirect(dev, h, &next) && REDIRECTS.lock().allow(h.src, now_ms())
    {
        stack::icmp_send(
            h,
            frame.data(),
            ICMP_REDIRECT,
            ICMP_REDIR_HOST,
            u32::from_be_bytes(next.hop),
        );
    }
    count(&COUNTERS.ip_forw_datagrams);
    // A lost packet is like a lost frame.
    if v == Verdict::Send {
        let _ = stack::xmit(&out, &next, frame);
    } else {
        fragment(&out, &next, h, frame.data(), mtu);
    }
    true
}

/// Tells if a packet that goes out on the device that it came in on gives a redirect to its
/// sender, as `__mkroute_input` of Linux: `send_redirects` is on, the sender is on the link of
/// the device, and the link is shared or the sender and the gateway are in a subnet of the
/// device.
fn redirect(dev: &NetDevice, h: &Header, next: &route::Next) -> bool {
    let ifindex = dev.ifindex();
    if !orconf(ifindex, "send_redirects") {
        return false;
    }
    let t = ROUTES.lock();
    // `__fib_validate_source` gives 1 when the route back to the sender has no gateway.
    let onlink = t.lookup_input(h.src).is_ok_and(|(n, _)| n.ifindex == ifindex && n.hop == h.src);
    if !onlink {
        return false;
    }
    if orconf(ifindex, "shared_media") {
        return true;
    }
    // `inet_addr_onlink`.
    let gw = (next.hop != h.dst).then_some(next.hop);
    t.addrs_of(ifindex).any(|a| a.contains(h.src) && gw.is_none_or(|g| a.contains(g)))
}

/// Sends a forwarded packet in fragments that fit in `mtu`, as the slow path of
/// `ip_do_fragment` in net/ipv4/ip_output.c of Linux. The first fragment has all the options
/// and the next fragments have only the options that have the copy flag. A fragment of a
/// fragment keeps the offset and the flag "more fragments" of the packet.
fn fragment(out: &NetDevice, next: &route::Next, h: &Header, packet: &[u8], mtu: usize) {
    let (head, data) = packet.split_at(h.hlen);
    let mut later = head.to_vec();
    ipv4::options_fragment(&mut later[HLEN..]);
    let base = h.frag & OFFSET_MASK;
    let more = h.frag & MF;
    let parts = frag::split(data.len(), mtu.saturating_sub(h.hlen));
    let last = parts.len() - 1;
    for (i, (offset, len)) in parts.into_iter().enumerate() {
        let mut hd = if i == 0 { head.to_vec() } else { later.clone() };
        hd[2..4].copy_from_slice(&((h.hlen + len) as u16).to_be_bytes());
        let flags = if i < last { MF } else { more };
        let field = (base + (offset / 8) as u16) | flags;
        hd[6..8].copy_from_slice(&field.to_be_bytes());
        ipv4::set_checksum(&mut hd);
        let mut buf = NetBuf::new(HEADROOM, h.hlen + len);
        buf.extend_from_slice(&hd);
        buf.extend_from_slice(&data[offset..offset + len]);
        count(&COUNTERS.ip_frag_creates);
        if stack::xmit(out, next, buf).is_err() {
            count(&COUNTERS.ip_frag_fails);
            return;
        }
    }
    count(&COUNTERS.ip_frag_oks);
}

/// Forwards the IPv6 packet `frame` that came in on `dev`, as `ip6_route_input` and
/// `ip6_forward` of Linux. Gives the frame back if the host does not forward it: the packet is
/// for the host, `net.ipv6.conf.all.forwarding` is off, the frame did not come to the link
/// address of the device, or the header is not valid. The input takes such a frame as before.
///
/// The packet does not go through the reassembly, and it does not get fragments. The host
/// sends no redirect and does not proxy neighbour discovery.
pub(crate) fn forward6(dev: &NetDevice, mut frame: NetBuf, host: bool) -> Option<NetBuf> {
    let ifindex = dev.ifindex();
    let Some(fh) = ipv6::Header::fixed(frame.data()) else { return Some(frame) };
    let end = ipv6::HLEN + usize::from(fh.payload_len);
    if !host
        || end > frame.len()
        || dev.kind() == LinkKind::Loopback
        || ipv6::is_multicast(&fh.dst)
        || ipv6::is_multicast(&fh.src)
        || fh.dst == ip::ANY
        || fh.dst == ip::LOOPBACK
        || fh.src == ip::LOOPBACK
        || conf(Family::Ipv6, Scope::All, "forwarding") == 0
    {
        return Some(frame);
    }
    let r = {
        let t = ROUTES6.lock();
        if t.is_local(&fh.dst) {
            return Some(frame);
        }
        // A link local destination does not leave its link.
        if ipv6::is_link_local(&fh.dst) {
            return Some(frame);
        }
        t.lookup(&fh.dst, 0)
    };
    frame.trim(end);
    // The headers of the packet for the ICMPv6 errors. A fragment has only the fixed header.
    let h = ipv6::Header::parse_loose(frame.data()).unwrap_or(fh);
    let error = |frame: &NetBuf, kind: u32, code: u32, info: u32| {
        stack6::icmp_error(&h, ifindex, frame.data(), kind as u8, code as u8, info);
    };
    let next = match r {
        Ok(n) => n,
        Err(e) => {
            // `ip6_pkt_discard` and `ip6_pkt_prohibit`.
            match e {
                Errno::ENETUNREACH => error(&frame, ICMPV6_DEST_UNREACH, ICMPV6_NOROUTE, 0),
                Errno::EACCES => error(&frame, ICMPV6_DEST_UNREACH, ICMPV6_ADM_PROHIBITED, 0),
                _ => {}
            }
            return None;
        }
    };
    if fh.hops <= 1 {
        error(&frame, ICMPV6_TIME_EXCEED, ICMPV6_EXC_HOPLIMIT, 0);
        count(&COUNTERS6.in_hdr_errors);
        return None;
    }
    // The checks of the source in `ip6_forward` are "security critical".
    if fh.src == ip::ANY {
        count(&COUNTERS6.in_addr_errors);
        return None;
    }
    if ipv6::is_link_local(&fh.src) {
        error(&frame, ICMPV6_DEST_UNREACH, ICMPV6_NOT_NEIGHBOUR, 0);
        count(&COUNTERS6.in_addr_errors);
        return None;
    }
    let out = dev::by_index(next.ifindex)?;
    if out.kind() == LinkKind::Loopback {
        return None;
    }
    let mtu = if next.mtu != 0 { next.mtu } else { out.mtu() };
    let mtu = mtu.max(ipv6::MIN_MTU as u32);
    if frame.len() > mtu as usize {
        error(&frame, ICMPV6_PKT_TOOBIG, 0, mtu);
        count(&COUNTERS6.in_too_big_errors);
        return None;
    }
    frame.data_mut()[7] -= 1;
    count(&COUNTERS6.out_forw_datagrams);
    let _ = stack6::transmit(&out, &next, frame);
    None
}

/// The source of an ICMPv6 error about a packet that the host forwards: the address of the
/// route back to the sender, as the source address selection of `icmp6_send` of Linux.
pub(crate) fn error_src6(dst: &Ip, ifindex: u32) -> Option<Ip> {
    stack6::route(dst, stack6::scope_of(dst, ifindex)).ok().map(|n| n.src)
}

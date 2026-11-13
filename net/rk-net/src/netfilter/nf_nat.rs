//! NAT, as net/netfilter/nf_nat_core.c, nf_nat_proto.c and nf_nat_masquerade.c of Linux.
//!
//! A rule of NAT runs on the first packet of a connection. It picks the new source or the new
//! destination of the connection and changes the reply tuple, before the connection goes in the
//! table: a reply then has the tuple that the changed packets make. Each packet of the
//! connection then gets the change at the hooks of NAT: the destination at
//! `NF_INET_PRE_ROUTING` and `NF_INET_LOCAL_OUT`, the source at `NF_INET_POST_ROUTING` and
//! `NF_INET_LOCAL_IN`, and the change back on the replies. The checksums of the IP header and of
//! the transport header get the change of each address and port, as RFC 1624. An ICMP error for
//! a connection with NAT gets the change in the packet in it too.
//!
//! The confirm of a connection sets up the NAT that no rule set up (`IPS_NAT_DONE_MASK`), so
//! the rules do not run for the next packets, as `nf_nat_alloc_null_binding`. That binding
//! does not look for a free port. A connection of masquerade stays when the address of its
//! device goes away.

use super::nf_conntrack::{
    IP_CT_DIR_ORIGINAL, IP_CT_DIR_REPLY, IP_CT_IS_REPLY, IP_CT_NEW, IP_CT_RELATED,
    IP_CT_RELATED_REPLY, IPS_DST_NAT, IPS_DST_NAT_DONE, IPS_NAT_MASK, IPS_SRC_NAT,
    IPS_SRC_NAT_DONE, NfConn, NfConntrackTuple, nf_conntrack_tuple_taken,
};
use super::{
    NF_ACCEPT, NF_DROP, NF_INET_LOCAL_IN, NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING,
    NF_INET_PRE_ROUTING, NF_IP_PRI_NAT_DST, NF_IP_PRI_NAT_SRC, NFPROTO_IPV4, NFPROTO_IPV6,
    NfHookFn, NfHookOps, NfHookState, nf_pktinfo,
};
use crate::buf::NetBuf;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use rk_frame::sync::SpinLock;

/// The change of the source.
pub const NF_NAT_MANIP_SRC: u8 = 0;
/// The change of the destination.
pub const NF_NAT_MANIP_DST: u8 = 1;

/// The range has addresses, as the flags `NF_NAT_RANGE_*` of Linux.
pub const NF_NAT_RANGE_MAP_IPS: u32 = 1 << 0;
/// The range has ports.
pub const NF_NAT_RANGE_PROTO_SPECIFIED: u32 = 1 << 1;
/// A random port of the range.
pub const NF_NAT_RANGE_PROTO_RANDOM: u32 = 1 << 2;
/// The same address of the range for a source, whatever the destination.
pub const NF_NAT_RANGE_PERSISTENT: u32 = 1 << 3;
/// A random port of the range for each connection.
pub const NF_NAT_RANGE_PROTO_RANDOM_FULLY: u32 = 1 << 4;
/// The port is an offset from a base, which this NAT does not do.
pub const NF_NAT_RANGE_PROTO_OFFSET: u32 = 1 << 5;
/// A map of a prefix to a prefix. The bits of the address that are not in the prefix stay.
pub const NF_NAT_RANGE_NETMAP: u32 = 1 << 6;
/// The flags that are known.
pub const NF_NAT_RANGE_MASK: u32 = (1 << 7) - 1;
const NF_NAT_RANGE_PROTO_RANDOM_ALL: u32 =
    NF_NAT_RANGE_PROTO_RANDOM | NF_NAT_RANGE_PROTO_RANDOM_FULLY;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_DCCP: u8 = 33;
const IPPROTO_ICMPV6: u8 = 58;
const IPPROTO_SCTP: u8 = 132;
const IPPROTO_UDPLITE: u8 = 136;

/// A range of addresses and ports, as `struct nf_nat_range2` of Linux. An IPv4 address is in
/// the first 4 bytes. The ports are in the byte order of the CPU.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NfNatRange {
    /// The `NF_NAT_RANGE_*` flags.
    pub flags: u32,
    /// The first address.
    pub min_addr: [u8; 16],
    /// The last address.
    pub max_addr: [u8; 16],
    /// The first port or ID.
    pub min_proto: u16,
    /// The last port or ID.
    pub max_proto: u16,
}

/// The change of the hook `hook`, as `HOOK2MANIP` of Linux.
pub fn hook2manip(hook: u8) -> u8 {
    if hook == NF_INET_POST_ROUTING || hook == NF_INET_LOCAL_IN {
        NF_NAT_MANIP_SRC
    } else {
        NF_NAT_MANIP_DST
    }
}

fn done_bit(mtype: u8) -> u32 {
    if mtype == NF_NAT_MANIP_SRC { IPS_SRC_NAT_DONE } else { IPS_DST_NAT_DONE }
}

/// Tells if the change `mtype` of the connection is set up, as `nf_nat_initialized` of Linux.
pub fn nf_nat_initialized(ct: &NfConn, mtype: u8) -> bool {
    ct.status() & done_bit(mtype) != 0
}

fn alen(l3num: u8) -> usize {
    if l3num == NFPROTO_IPV4 { 4 } else { 16 }
}

fn has_ports(protonum: u8) -> bool {
    matches!(protonum, IPPROTO_TCP | IPPROTO_UDP | IPPROTO_UDPLITE | IPPROTO_DCCP | IPPROTO_SCTP)
}

fn is_icmp(t: &NfConntrackTuple) -> bool {
    matches!((t.l3num, t.protonum), (NFPROTO_IPV4, IPPROTO_ICMP) | (NFPROTO_IPV6, IPPROTO_ICMPV6))
}

/// The address and the port (or the ID of an ICMP echo) that the change `mtype` sets.
fn key(t: &NfConntrackTuple, mtype: u8) -> ([u8; 16], u16) {
    if mtype == NF_NAT_MANIP_SRC || is_icmp(t) {
        (if mtype == NF_NAT_MANIP_SRC { t.src } else { t.dst }, t.src_u)
    } else {
        (t.dst, t.dst_u)
    }
}

fn set_port(t: &mut NfConntrackTuple, mtype: u8, port: u16) {
    if mtype == NF_NAT_MANIP_SRC || is_icmp(t) {
        t.src_u = port;
    } else {
        t.dst_u = port;
    }
}

/// An address as a number, for a range.
fn addr_num(a: &[u8; 16], len: usize) -> u128 {
    a[..len].iter().fold(0u128, |n, &b| n << 8 | u128::from(b))
}

fn num_addr(mut n: u128, len: usize) -> [u8; 16] {
    let mut a = [0u8; 16];
    for i in (0..len).rev() {
        a[i] = n as u8;
        n >>= 8;
    }
    a
}

/// Tells if the tuple is in the range for the change `mtype`, as `nf_in_range` of Linux.
fn in_range(t: &NfConntrackTuple, r: &NfNatRange, mtype: u8) -> bool {
    let (addr, port) = key(t, mtype);
    let len = alen(t.l3num);
    if r.flags & NF_NAT_RANGE_MAP_IPS != 0 {
        let a = addr_num(&addr, len);
        if a < addr_num(&r.min_addr, len) || a > addr_num(&r.max_addr, len) {
            return false;
        }
    }
    r.flags & NF_NAT_RANGE_PROTO_SPECIFIED == 0
        || !(has_ports(t.protonum) || is_icmp(t))
        || (r.min_proto..=r.max_proto).contains(&port)
}

/// Tells if a connection other than `ct` uses the tuple `t`, as `nf_nat_used_tuple` of Linux:
/// the reply of `t` is in the table.
fn used_tuple(t: &NfConntrackTuple, ct: &NfConn) -> bool {
    t.invert().is_some_and(|reply| nf_conntrack_tuple_taken(&reply, ct))
}

/// A pseudo-random number, for the ports of a range.
fn random() -> u32 {
    static STATE: AtomicU32 = AtomicU32::new(0x9e37_79b9);
    let mut s = STATE.load(Ordering::Relaxed);
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    STATE.store(s, Ordering::Relaxed);
    s
}

/// A hash of the addresses of `t`, so a source gets the same address of a range each time, as
/// the `jhash2` of `find_best_ips_proto` of Linux.
fn hash_addrs(t: &NfConntrackTuple, persistent: bool) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut add = |b: &[u8]| {
        for &x in b {
            h = (h ^ u64::from(x)).wrapping_mul(0x0100_0000_01b3);
        }
    };
    let len = alen(t.l3num);
    add(&t.src[..len]);
    if !persistent {
        add(&t.dst[..len]);
    }
    h
}

/// Picks the address of the range, as `find_best_ips_proto` of Linux.
fn find_best_ips(t: &mut NfConntrackTuple, r: &NfNatRange, mtype: u8) {
    if r.flags & NF_NAT_RANGE_MAP_IPS == 0 {
        return;
    }
    let len = alen(t.l3num);
    let (min, max) = (addr_num(&r.min_addr, len), addr_num(&r.max_addr, len));
    let a = if min >= max {
        r.min_addr
    } else {
        let dist = max - min + 1;
        let h = u128::from(hash_addrs(t, r.flags & NF_NAT_RANGE_PERSISTENT != 0));
        num_addr(min + h % dist, len)
    };
    if mtype == NF_NAT_MANIP_SRC {
        t.src = a;
    } else {
        t.dst = a;
    }
}

/// Picks a port (or the ID of an ICMP echo) that no other connection uses, as
/// `nf_nat_l4proto_unique_tuple` of Linux.
fn unique_port(t: &mut NfConntrackTuple, r: &NfNatRange, mtype: u8, ct: &NfConn) {
    let (_, port) = key(t, mtype);
    let (min, size) = if is_icmp(t) {
        if r.flags & NF_NAT_RANGE_PROTO_SPECIFIED == 0 {
            (0u32, 65536u32)
        } else {
            let (lo, hi) = (r.min_proto.min(r.max_proto), r.min_proto.max(r.max_proto));
            (u32::from(lo), u32::from(hi - lo) + 1)
        }
    } else if has_ports(t.protonum) {
        if r.flags & NF_NAT_RANGE_PROTO_SPECIFIED == 0 {
            // The change of the destination keeps the port of the service.
            if mtype == NF_NAT_MANIP_DST {
                return;
            }
            // The ports below 1024 stay below 1024, as the loose rule of Linux.
            match port {
                0..512 => (1, 511),
                512..1024 => (600, 1024 - 600),
                _ => (1024, 65536 - 1024),
            }
        } else {
            let (lo, hi) = (r.min_proto.min(r.max_proto), r.min_proto.max(r.max_proto));
            (u32::from(lo), u32::from(hi - lo) + 1)
        }
    } else {
        return;
    };
    let mut off = if r.flags & NF_NAT_RANGE_PROTO_RANDOM_ALL != 0 || mtype != NF_NAT_MANIP_DST {
        random()
    } else {
        0
    };
    let mut attempts = size.min(128);
    loop {
        for _ in 0..attempts {
            set_port(t, mtype, (min + off % size) as u16);
            if !used_tuple(t, ct) {
                return;
            }
            off = off.wrapping_add(1);
        }
        if attempts >= size || attempts < 16 {
            return;
        }
        attempts /= 2;
        off = random();
    }
}

/// The tuple of the connection after the change, with a port that no other connection uses,
/// as `get_unique_tuple` of Linux. `orig` is the tuple of the original direction after the
/// changes that are there.
fn get_unique_tuple(
    orig: &NfConntrackTuple,
    r: &NfNatRange,
    ct: &NfConn,
    mtype: u8,
) -> NfConntrackTuple {
    // A source in the range stays, if no other connection has the tuple.
    if mtype == NF_NAT_MANIP_SRC
        && r.flags & NF_NAT_RANGE_PROTO_RANDOM_ALL == 0
        && in_range(orig, r, mtype)
        && !used_tuple(orig, ct)
    {
        return *orig;
    }
    let mut t = *orig;
    find_best_ips(&mut t, r, mtype);
    if r.flags & NF_NAT_RANGE_PROTO_RANDOM_ALL == 0 {
        if r.flags & NF_NAT_RANGE_PROTO_SPECIFIED != 0 {
            let (_, port) = key(&t, mtype);
            let fixed = !(has_ports(t.protonum) || is_icmp(&t));
            if r.flags & NF_NAT_RANGE_PROTO_OFFSET == 0
                && (fixed || (r.min_proto..=r.max_proto).contains(&port))
                && (r.min_proto == r.max_proto || !used_tuple(&t, ct))
            {
                return t;
            }
        } else if !used_tuple(&t, ct) {
            return t;
        }
    }
    unique_port(&mut t, r, mtype, ct);
    t
}

/// Sets up the change `mtype` of a new connection with the range `r`, as `nf_nat_setup_info` of
/// Linux. Gives the verdict for the packet.
pub fn nf_nat_setup_info(ct: &NfConn, r: &NfNatRange, mtype: u8) -> u32 {
    if ct.is_confirmed() || nf_nat_initialized(ct, mtype) {
        return NF_DROP;
    }
    // The original tuple after the changes that are there: the inverse of the reply.
    let Some(curr) = ct.tuple(IP_CT_DIR_REPLY).invert() else { return NF_DROP };
    let new = get_unique_tuple(&curr, r, ct, mtype);
    if new != curr {
        let Some(reply) = new.invert() else { return NF_DROP };
        ct.alter_reply(reply);
        ct.set_status(if mtype == NF_NAT_MANIP_SRC { IPS_SRC_NAT } else { IPS_DST_NAT });
    }
    ct.set_status(done_bit(mtype));
    NF_ACCEPT
}

/// Changes `sum`, a checksum of words that has `old`, for `new` in place of `old`, as
/// `inet_proto_csum_replace*` of Linux and RFC 1624.
fn csum_replace(sum: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut s = u32::from(!sum);
    for w in old.as_chunks::<2>().0 {
        s += u32::from(!u16::from_be_bytes(*w));
    }
    for w in new.as_chunks::<2>().0 {
        s += u32::from(u16::from_be_bytes(*w));
    }
    csum_fold(s)
}

/// The sum of the 16-bit words of `d`, with an odd last byte as the high byte of a word.
pub(super) fn csum_add(mut s: u32, d: &[u8]) -> u32 {
    let (words, rest) = d.as_chunks::<2>();
    for w in words {
        s = s.wrapping_add(u32::from(u16::from_be_bytes(*w)));
        if s > 0xffff_0000 {
            s = (s & 0xffff) + (s >> 16);
        }
    }
    if let [b] = rest {
        s += u32::from(*b) << 8;
    }
    s
}

/// Folds a sum of words to the checksum of RFC 1071.
pub(super) fn csum_fold(mut s: u32) -> u16 {
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

fn get16(d: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([d[at], d[at + 1]])
}

fn put16(d: &mut [u8], at: usize, v: u16) {
    d[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

/// Changes the checksum at `at` for a new address of the pseudo header, as `nf_csum_update`.
fn csum_addr(d: &mut [u8], at: usize, old: &[u8], new: &[u8]) {
    let s = csum_replace(get16(d, at), old, new);
    put16(d, at, s);
}

/// The CRC32c of SCTP, as `sctp_compute_cksum` of Linux, with the checksum field as 0.
pub(super) fn sctp_crc(d: &[u8]) -> u32 {
    let mut crc = !0u32;
    for (i, &b) in d.iter().enumerate() {
        let b = if (8..12).contains(&i) { 0 } else { b };
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { crc >> 1 ^ 0x82f6_3b78 } else { crc >> 1 };
        }
    }
    !crc
}

/// Changes the port or the ID of the transport header at `hdroff` and its checksum for the new
/// address too, as `l4proto_manip_pkt` of Linux. `end` is the end of the IP packet. A header in
/// an ICMP error can have only its first 8 bytes, and then its checksum stays.
#[allow(clippy::too_many_arguments)]
fn l4_manip(
    d: &mut [u8],
    l3num: u8,
    protonum: u8,
    hdroff: usize,
    end: usize,
    old_addr: &[u8],
    t: &NfConntrackTuple,
    mtype: u8,
) -> bool {
    let len = end.saturating_sub(hdroff);
    let new_addr = if mtype == NF_NAT_MANIP_SRC { &t.src } else { &t.dst };
    let new_addr = &new_addr[..old_addr.len()];
    let (_, port) = key(t, mtype);
    let port_at = hdroff + if mtype == NF_NAT_MANIP_SRC { 0 } else { 2 };
    match protonum {
        IPPROTO_TCP | IPPROTO_DCCP | IPPROTO_UDP | IPPROTO_UDPLITE | IPPROTO_SCTP => {
            if len < 8 {
                return false;
            }
            let old_port = get16(d, port_at);
            put16(d, port_at, port);
            let (full, csum) = match protonum {
                IPPROTO_TCP => (20, 16),
                IPPROTO_DCCP => (12, 6),
                IPPROTO_SCTP => (12, 8),
                _ => (8, 6),
            };
            if len < full {
                return true;
            }
            if protonum == IPPROTO_SCTP {
                let crc = sctp_crc(&d[hdroff..end]);
                d[hdroff + 8..hdroff + 12].copy_from_slice(&crc.to_le_bytes());
                return true;
            }
            let at = hdroff + csum;
            // A UDP datagram of IPv4 with no checksum keeps none.
            if protonum == IPPROTO_UDP && l3num == NFPROTO_IPV4 && get16(d, at) == 0 {
                return true;
            }
            csum_addr(d, at, old_addr, new_addr);
            csum_addr(d, at, &old_port.to_be_bytes(), &port.to_be_bytes());
            if matches!(protonum, IPPROTO_UDP | IPPROTO_UDPLITE) && get16(d, at) == 0 {
                put16(d, at, 0xffff);
            }
        }
        IPPROTO_ICMP if l3num == NFPROTO_IPV4 => {
            if len < 8 {
                return false;
            }
            // Only the messages with an ID: echo, timestamp, information and address mask.
            if matches!(d[hdroff], 0 | 8 | 13 | 14 | 15 | 16 | 17 | 18) {
                let old = get16(d, hdroff + 4);
                put16(d, hdroff + 4, t.src_u);
                csum_addr(d, hdroff + 2, &old.to_be_bytes(), &t.src_u.to_be_bytes());
            }
        }
        IPPROTO_ICMPV6 if l3num == NFPROTO_IPV6 => {
            if len < 8 {
                return false;
            }
            csum_addr(d, hdroff + 2, old_addr, new_addr);
            if matches!(d[hdroff], 128 | 129) {
                let old = get16(d, hdroff + 4);
                put16(d, hdroff + 4, t.src_u);
                csum_addr(d, hdroff + 2, &old.to_be_bytes(), &t.src_u.to_be_bytes());
            }
        }
        _ => {}
    }
    true
}

/// Changes the source or the destination of the IP packet at `iphdroff` of `d` to the one of
/// `t`, as `nf_nat_ipv4_manip_pkt` and `nf_nat_ipv6_manip_pkt` of Linux. `protonum` is the
/// protocol of the transport header to change.
fn manip_pkt(d: &mut [u8], iphdroff: usize, t: &NfConntrackTuple, mtype: u8, protonum: u8) -> bool {
    let ip = &d[iphdroff..];
    let (hdroff, end, at) = match t.l3num {
        NFPROTO_IPV4 => {
            if ip.len() < 20 {
                return false;
            }
            let ihl = usize::from(ip[0] & 0xf) * 4;
            let total = usize::from(get16(ip, 2)).min(ip.len());
            let at = if mtype == NF_NAT_MANIP_SRC { 12 } else { 16 };
            (iphdroff + ihl, iphdroff + total.max(ihl), iphdroff + at)
        }
        NFPROTO_IPV6 => {
            if ip.len() < 40 {
                return false;
            }
            let Some(thoff) = nf_pktinfo(NFPROTO_IPV6, ip).thoff else { return false };
            let total = (40 + usize::from(get16(ip, 4))).min(ip.len());
            let at = if mtype == NF_NAT_MANIP_SRC { 8 } else { 24 };
            (iphdroff + thoff, iphdroff + total.max(thoff), iphdroff + at)
        }
        _ => return false,
    };
    let n = alen(t.l3num);
    let mut old = [0u8; 16];
    old[..n].copy_from_slice(&d[at..at + n]);
    // A fragment that is not the first has no transport header.
    let frag = t.l3num == NFPROTO_IPV4 && get16(d, iphdroff + 6) & 0x1fff != 0;
    if !frag && !l4_manip(d, t.l3num, protonum, hdroff, end, &old[..n], t, mtype) {
        return false;
    }
    let new = if mtype == NF_NAT_MANIP_SRC { t.src } else { t.dst };
    d[at..at + n].copy_from_slice(&new[..n]);
    if t.l3num == NFPROTO_IPV4 {
        csum_addr(d, iphdroff + 10, &old[..4], &new[..4]);
    }
    true
}

fn ctdir(ctinfo: u8) -> usize {
    if ctinfo >= IP_CT_IS_REPLY { IP_CT_DIR_REPLY } else { IP_CT_DIR_ORIGINAL }
}

/// The bit of the status that tells if the packets of the direction of `ctinfo` get the change
/// `mtype`.
fn statusbit(mtype: u8, ctinfo: u8) -> u32 {
    let bit = if mtype == NF_NAT_MANIP_SRC { IPS_SRC_NAT } else { IPS_DST_NAT };
    if ctdir(ctinfo) == IP_CT_DIR_REPLY { bit ^ IPS_NAT_MASK } else { bit }
}

/// Changes a packet of a connection at the hook `hook`, as `nf_nat_packet` of Linux.
pub fn nf_nat_packet(ct: &NfConn, ctinfo: u8, hook: u8, skb: &mut NetBuf) -> u32 {
    let mtype = hook2manip(hook);
    if ct.status() & statusbit(mtype, ctinfo) == 0 {
        return NF_ACCEPT;
    }
    // The packet gets the address and the port of the inverse of the other direction.
    let Some(target) = ct.tuple(1 - ctdir(ctinfo)).invert() else { return NF_DROP };
    if manip_pkt(skb.data_mut(), 0, &target, mtype, target.protonum) { NF_ACCEPT } else { NF_DROP }
}

/// Changes an ICMP error for a connection with NAT and the packet in it, as
/// `nf_nat_icmp_reply_translation` and `nf_nat_icmpv6_reply_translation` of Linux. The packet
/// in the error went the other way, so it gets the other change.
fn icmp_reply_translation(ct: &NfConn, ctinfo: u8, hook: u8, skb: &mut NetBuf, pf: u8) -> bool {
    let mtype = hook2manip(hook);
    let d = skb.data_mut();
    let Some(thoff) = nf_pktinfo(pf, d).thoff else { return false };
    if d.len() < thoff + 8 {
        return false;
    }
    // A redirect for a connection with NAT would make the ends talk past the NAT.
    if pf == NFPROTO_IPV4 && d[thoff] == 5 && ct.status() & IPS_NAT_MASK != 0 {
        return false;
    }
    if ct.status() & statusbit(mtype, ctinfo) == 0 {
        return true;
    }
    let dir = ctdir(ctinfo);
    let other = ct.tuple(1 - dir);
    if !manip_pkt(d, thoff + 8, &other, 1 - mtype, other.protonum) {
        return false;
    }
    let Some(mut target) = other.invert() else { return false };
    target.protonum = if pf == NFPROTO_IPV4 { IPPROTO_ICMP } else { IPPROTO_ICMPV6 };
    let end = match pf {
        NFPROTO_IPV4 => usize::from(get16(d, 2)),
        _ => 40 + usize::from(get16(d, 4)),
    }
    .min(d.len());
    // The checksum of the ICMP message, with the pseudo header of ICMPv6. The change of the
    // outer header then changes it as for any packet.
    d[thoff + 2..thoff + 4].fill(0);
    let mut sum = csum_add(0, &d[thoff..end]);
    if pf == NFPROTO_IPV6 {
        sum = csum_add(sum, &d[8..40]);
        sum = csum_add(sum, &((end - thoff) as u32).to_be_bytes());
        sum = csum_add(sum, &[0, 0, 0, IPPROTO_ICMPV6]);
    }
    let c = csum_fold(sum);
    put16(d, thoff + 2, c);
    manip_pkt(d, 0, &target, mtype, target.protonum)
}

/// Tells if the packet is an ICMP error.
fn is_icmp_error(pf: u8, d: &[u8]) -> bool {
    let p = nf_pktinfo(pf, d);
    let Some(t) = p.thoff.and_then(|o| d.get(o)) else { return false };
    match (pf, p.l4proto) {
        (NFPROTO_IPV4, IPPROTO_ICMP) => matches!(t, 3 | 4 | 5 | 11 | 12),
        (NFPROTO_IPV6, IPPROTO_ICMPV6) => *t < 128,
        _ => false,
    }
}

/// The work of a hook of NAT, as `nf_nat_inet_fn` of Linux. `chain` runs the rules of the chain
/// of NAT on the first packet of a connection; a rule sets up the change with
/// `nf_nat_setup_info`. Then the packet gets the change of its connection.
pub fn nf_nat_inet_fn(
    skb: &mut NetBuf,
    state: &NfHookState,
    chain: impl FnOnce(&mut NetBuf) -> u32,
) -> u32 {
    let Some((ct, ctinfo)) = skb.nfct.get().map(|(c, i)| (c.clone(), i)) else {
        return NF_ACCEPT;
    };
    let mtype = hook2manip(state.hook);
    match ctinfo {
        IP_CT_RELATED | IP_CT_RELATED_REPLY | IP_CT_NEW => {
            if ctinfo != IP_CT_NEW && is_icmp_error(state.pf, skb.data()) {
                return if icmp_reply_translation(&ct, ctinfo, state.hook, skb, state.pf) {
                    NF_ACCEPT
                } else {
                    NF_DROP
                };
            }
            if !nf_nat_initialized(&ct, mtype) {
                let v = chain(skb);
                if v != NF_ACCEPT {
                    return v;
                }
            }
        }
        _ => {}
    }
    nf_nat_packet(&ct, ctinfo, state.hook, skb)
}

/// The hook of NAT at each of the four hooks, as `nf_nat_ipv4_ops` of Linux: a packet of a
/// connection gets the change of its connection at each hook, also at a hook with no chain of
/// NAT, as the reply of a connection with DNAT at `NF_INET_LOCAL_IN`. A chain of NAT at the
/// hook runs its rules and makes the change too; the second change is the same, so it changes
/// nothing.
struct NatHook;

impl NfHookFn for NatHook {
    fn hook(&self, skb: &mut NetBuf, state: &NfHookState) -> u32 {
        nf_nat_inet_fn(skb, state, |_| NF_ACCEPT)
    }
}

/// The hooks of NAT of the family `pf`. Connection tracking registers them with its hooks.
pub(super) fn nf_nat_ops(pf: u8) -> Vec<NfHookOps> {
    let h: Arc<dyn NfHookFn> = Arc::new(NatHook);
    [
        (NF_INET_PRE_ROUTING, NF_IP_PRI_NAT_DST),
        (NF_INET_LOCAL_OUT, NF_IP_PRI_NAT_DST),
        (NF_INET_POST_ROUTING, NF_IP_PRI_NAT_SRC),
        (NF_INET_LOCAL_IN, NF_IP_PRI_NAT_SRC),
    ]
    .into_iter()
    .map(|(hooknum, priority)| NfHookOps { hook: h.clone(), pf, hooknum, priority })
    .collect()
}

/// The function that gives the source address of a packet of the family `pf` that goes out on
/// the device `ifindex` to `dst`, for masquerade. The stack of IPv4 and IPv6 registers it, as
/// `inet_select_addr` and `ipv6_dev_get_saddr` of Linux.
pub type NfNatSrcFn = fn(pf: u8, ifindex: u32, dst: &[u8; 16]) -> Option<[u8; 16]>;

static SRC_FN: SpinLock<Option<NfNatSrcFn>> = SpinLock::new(None);

/// Registers the function that gives the source address for masquerade.
pub fn nf_nat_set_src_fn(f: NfNatSrcFn) {
    *SRC_FN.lock() = Some(f);
}

/// Sets up masquerade for a new connection: the source becomes the address of the device that
/// the packet goes out on, as `nf_nat_masquerade_ipv4` and `nf_nat_masquerade_ipv6` of Linux.
pub fn nf_nat_masquerade(ct: &NfConn, r: &NfNatRange, state: &NfHookState, d: &[u8]) -> u32 {
    let orig = ct.tuple(IP_CT_DIR_ORIGINAL);
    // A packet of the host with the source 0.0.0.0 is not for masquerade.
    if state.pf == NFPROTO_IPV4 && orig.src[..4] == [0; 4] {
        return NF_ACCEPT;
    }
    let mut dst = [0u8; 16];
    match state.pf {
        NFPROTO_IPV4 if d.len() >= 20 => dst[..4].copy_from_slice(&d[16..20]),
        NFPROTO_IPV6 if d.len() >= 40 => dst.copy_from_slice(&d[24..40]),
        _ => return NF_DROP,
    }
    let f = *SRC_FN.lock();
    let Some(src) = f.and_then(|f| f(state.pf, state.out_dev, &dst)) else { return NF_DROP };
    let range = NfNatRange {
        flags: r.flags | NF_NAT_RANGE_MAP_IPS,
        min_addr: src,
        max_addr: src,
        min_proto: r.min_proto,
        max_proto: r.max_proto,
    };
    nf_nat_setup_info(ct, &range, NF_NAT_MANIP_SRC)
}

/// Sets up redirect for a new connection: the destination becomes the host, as
/// `nf_nat_redirect_ipv4` and `nf_nat_redirect_ipv6` of Linux. A packet of the host goes to
/// the loopback address; a packet that comes in goes to an address of its device, and a device
/// with no address drops it.
pub fn nf_nat_redirect(ct: &NfConn, r: &NfNatRange, state: &NfHookState, d: &[u8]) -> u32 {
    let v6 = state.pf == NFPROTO_IPV6;
    let mut newdst = [0u8; 16];
    if state.hook == NF_INET_LOCAL_OUT {
        if v6 {
            newdst[15] = 1;
        } else {
            newdst[..4].copy_from_slice(&[127, 0, 0, 1]);
        }
    } else {
        // The address of the device for the sender of the packet.
        let mut from = [0u8; 16];
        match state.pf {
            NFPROTO_IPV4 if d.len() >= 20 => from[..4].copy_from_slice(&d[12..16]),
            NFPROTO_IPV6 if d.len() >= 40 => from.copy_from_slice(&d[8..24]),
            _ => return NF_DROP,
        }
        let f = *SRC_FN.lock();
        match f.and_then(|f| f(state.pf, state.in_dev, &from)) {
            Some(a) => newdst = a,
            None => return NF_DROP,
        }
    }
    let range = NfNatRange {
        flags: r.flags | NF_NAT_RANGE_MAP_IPS,
        min_addr: newdst,
        max_addr: newdst,
        min_proto: r.min_proto,
        max_proto: r.max_proto,
    };
    nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netfilter::nf_conntrack::tests::{SERIAL, fresh, ip4, state, udp};
    use crate::netfilter::nf_conntrack::{
        IP_CT_ESTABLISHED_REPLY, nf_conntrack_confirm, nf_conntrack_in,
    };
    use alloc::vec;

    const A: [u8; 4] = [10, 7, 0, 1];
    const A2: [u8; 4] = [10, 7, 0, 3];
    const B: [u8; 4] = [10, 7, 0, 2];
    const C: [u8; 4] = [10, 7, 0, 4];
    const N: [u8; 4] = [192, 0, 2, 1];

    fn addr(a: [u8; 4]) -> [u8; 16] {
        let mut x = [0u8; 16];
        x[..4].copy_from_slice(&a);
        x
    }

    fn range(a: [u8; 4], ports: Option<u16>) -> NfNatRange {
        let mut r = NfNatRange {
            flags: NF_NAT_RANGE_MAP_IPS,
            min_addr: addr(a),
            max_addr: addr(a),
            ..NfNatRange::default()
        };
        if let Some(p) = ports {
            r.flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
            (r.min_proto, r.max_proto) = (p, p);
        }
        r
    }

    /// The checksum of the transport header at `off` of the IPv4 packet `p`.
    fn l4_sum(p: &[u8], off: usize) -> u16 {
        let end = usize::from(get16(p, 2));
        let mut s = csum_add(0, &p[off..end]);
        if p[9] != IPPROTO_ICMP {
            s = csum_add(s, &p[12..20]);
            s = csum_add(s, &[0, p[9]]);
            s = csum_add(s, &((end - off) as u16).to_be_bytes());
        }
        csum_fold(s)
    }

    fn csum_at(proto: u8) -> usize {
        match proto {
            IPPROTO_TCP => 16,
            IPPROTO_UDP => 6,
            _ => 2,
        }
    }

    /// Fills in the checksums of the IPv4 packet `p`.
    fn fill(p: &mut [u8]) {
        p[10..12].fill(0);
        let c = csum_fold(csum_add(0, &p[..20]));
        put16(p, 10, c);
        let at = 20 + csum_at(p[9]);
        p[at..at + 2].fill(0);
        let c = l4_sum(p, 20);
        put16(p, at, c);
    }

    /// Tells if the checksums of the IPv4 packet `p` are right.
    fn sums_ok(p: &[u8]) -> bool {
        csum_fold(csum_add(0, &p[..20])) == 0 && l4_sum(p, 20) == 0
    }

    fn pkt(proto: u8, src: [u8; 4], dst: [u8; 4], mut l4: Vec<u8>) -> NetBuf {
        if proto == IPPROTO_UDP {
            l4.extend_from_slice(b"nat");
            let len = l4.len() as u16;
            l4[4..6].copy_from_slice(&len.to_be_bytes());
        }
        let mut b = ip4(proto, src, dst, &l4);
        fill(b.data_mut());
        b
    }

    fn tcp(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8) -> Vec<u8> {
        let mut h = vec![0u8; 20];
        h[0..2].copy_from_slice(&sport.to_be_bytes());
        h[2..4].copy_from_slice(&dport.to_be_bytes());
        h[4..8].copy_from_slice(&seq.to_be_bytes());
        h[8..12].copy_from_slice(&ack.to_be_bytes());
        h[12] = 0x50;
        h[13] = flags;
        h[14..16].copy_from_slice(&8192u16.to_be_bytes());
        h
    }

    fn src(b: &NetBuf) -> ([u8; 4], u16) {
        let d = b.data();
        (d[12..16].try_into().unwrap(), get16(d, 20))
    }

    fn dst(b: &NetBuf) -> ([u8; 4], u16) {
        let d = b.data();
        (d[16..20].try_into().unwrap(), get16(d, 22))
    }

    /// Runs a hook of NAT with a chain that sets up `r`, or that must not run.
    fn nat(b: &mut NetBuf, hook: u8, r: Option<(NfNatRange, u8)>) -> u32 {
        nf_nat_inet_fn(b, &state(hook), |b| {
            let (r, mtype) = r.expect("the chain runs only for a new connection");
            nf_nat_setup_info(b.nfct.get().unwrap().0, &r, mtype)
        })
    }

    #[test]
    fn snat_changes_the_source_the_replies_and_an_icmp_error() {
        let _s = SERIAL.lock();
        fresh(40_000);
        let mut p = pkt(IPPROTO_UDP, A, B, udp(4000, 53));
        assert_eq!(nf_conntrack_in(&mut p, &state(NF_INET_LOCAL_OUT)), NF_ACCEPT);
        // The change of the destination at NF_INET_LOCAL_OUT finds no rule, so none.
        assert_eq!(nat(&mut p, NF_INET_LOCAL_OUT, Some((NfNatRange::default(), 1))), NF_ACCEPT);
        let r = range(N, Some(5000));
        assert_eq!(nat(&mut p, NF_INET_POST_ROUTING, Some((r, NF_NAT_MANIP_SRC))), NF_ACCEPT);
        assert_eq!(nf_conntrack_confirm(&mut p), NF_ACCEPT);
        assert_eq!((src(&p), dst(&p)), ((N, 5000), (B, 53)));
        assert!(sums_ok(p.data()));
        let ct = p.nfct.get().unwrap().0.clone();
        assert!(ct.status() & IPS_SRC_NAT != 0 && ct.status() & IPS_DST_NAT == 0);
        assert_eq!(ct.tuple(IP_CT_DIR_REPLY).dst[..4], N);
        // The next packet gets the change with no rule.
        let mut q = pkt(IPPROTO_UDP, A, B, udp(4000, 53));
        nf_conntrack_in(&mut q, &state(NF_INET_LOCAL_OUT));
        assert_eq!(nat(&mut q, NF_INET_LOCAL_OUT, None), NF_ACCEPT);
        assert_eq!(nat(&mut q, NF_INET_POST_ROUTING, None), NF_ACCEPT);
        assert_eq!(src(&q), (N, 5000));
        assert!(sums_ok(q.data()));
        // The reply goes back to A.
        let mut r = pkt(IPPROTO_UDP, B, N, udp(53, 5000));
        nf_conntrack_in(&mut r, &state(NF_INET_PRE_ROUTING));
        assert_eq!(r.nfct.get().unwrap().1, IP_CT_ESTABLISHED_REPLY);
        assert_eq!(nat(&mut r, NF_INET_PRE_ROUTING, None), NF_ACCEPT);
        assert_eq!(nat(&mut r, NF_INET_LOCAL_IN, None), NF_ACCEPT);
        assert_eq!((src(&r), dst(&r)), ((B, 53), (A, 4000)));
        assert!(sums_ok(r.data()));
        // A port unreachable for the changed packet goes to A, with A in the packet in it.
        let mut err = vec![3, 3, 0, 0, 0, 0, 0, 0];
        err.extend_from_slice(q.data());
        let mut e = pkt(IPPROTO_ICMP, B, N, err);
        nf_conntrack_in(&mut e, &state(NF_INET_PRE_ROUTING));
        assert_eq!(nat(&mut e, NF_INET_PRE_ROUTING, None), NF_ACCEPT);
        let d = e.data();
        assert_eq!((&d[12..16], &d[16..20]), (&B[..], &A[..]));
        assert!(sums_ok(d));
        let inner = &d[28..];
        assert_eq!((&inner[12..16], get16(inner, 20)), (&A[..], 4000));
        assert!(sums_ok(inner));
    }

    #[test]
    fn dnat_changes_the_destination_and_the_source_of_the_replies() {
        let _s = SERIAL.lock();
        fresh(50_000);
        let mut p = pkt(IPPROTO_TCP, A, B, tcp(4001, 80, 1000, 0, 0x02));
        assert_eq!(nf_conntrack_in(&mut p, &state(NF_INET_LOCAL_OUT)), NF_ACCEPT);
        let r = range(C, Some(8080));
        assert_eq!(nat(&mut p, NF_INET_LOCAL_OUT, Some((r, NF_NAT_MANIP_DST))), NF_ACCEPT);
        assert_eq!(nat(&mut p, NF_INET_POST_ROUTING, Some((NfNatRange::default(), 0))), NF_ACCEPT);
        assert_eq!(nf_conntrack_confirm(&mut p), NF_ACCEPT);
        assert_eq!((src(&p), dst(&p)), ((A, 4001), (C, 8080)));
        assert!(sums_ok(p.data()));
        let ct = p.nfct.get().unwrap().0.clone();
        assert!(ct.status() & IPS_DST_NAT != 0 && ct.status() & IPS_SRC_NAT == 0);
        let mut r = pkt(IPPROTO_TCP, C, A, tcp(8080, 4001, 5000, 1001, 0x12));
        assert_eq!(nf_conntrack_in(&mut r, &state(NF_INET_PRE_ROUTING)), NF_ACCEPT);
        assert!(core::ptr::eq(&**r.nfct.get().unwrap().0, &*ct));
        assert_eq!(nat(&mut r, NF_INET_PRE_ROUTING, None), NF_ACCEPT);
        assert_eq!(dst(&r), (A, 4001));
        assert_eq!(nat(&mut r, NF_INET_LOCAL_IN, None), NF_ACCEPT);
        assert_eq!((src(&r), dst(&r)), ((B, 80), (A, 4001)));
        assert!(sums_ok(r.data()));
    }

    #[test]
    fn a_source_in_use_gets_another_port() {
        let _s = SERIAL.lock();
        fresh(60_000);
        let mut ports = Vec::new();
        for a in [A, A2] {
            let mut p = pkt(IPPROTO_UDP, a, B, udp(4000, 53));
            nf_conntrack_in(&mut p, &state(NF_INET_LOCAL_OUT));
            let r = range(N, None);
            assert_eq!(nat(&mut p, NF_INET_POST_ROUTING, Some((r, NF_NAT_MANIP_SRC))), NF_ACCEPT);
            assert_eq!(nf_conntrack_confirm(&mut p), NF_ACCEPT);
            assert_eq!(src(&p).0, N);
            assert!(sums_ok(p.data()));
            ports.push(src(&p).1);
        }
        assert_eq!(ports[0], 4000);
        assert!(ports[1] != 4000 && ports[1] >= 1024, "{ports:?}");
    }

    #[test]
    fn masquerade_takes_the_address_of_the_device() {
        let _s = SERIAL.lock();
        fresh(70_000);
        nf_nat_set_src_fn(|pf, ifindex, dst| {
            (pf == NFPROTO_IPV4 && ifindex == 3 && dst[..4] == B).then(|| addr([192, 0, 2, 9]))
        });
        let mut st = state(NF_INET_POST_ROUTING);
        st.out_dev = 3;
        let mut p = pkt(IPPROTO_UDP, A, B, udp(4002, 53));
        nf_conntrack_in(&mut p, &state(NF_INET_LOCAL_OUT));
        let ct = p.nfct.get().unwrap().0.clone();
        assert_eq!(nf_nat_masquerade(&ct, &NfNatRange::default(), &st, p.data()), NF_ACCEPT);
        assert_eq!(nf_nat_packet(&ct, IP_CT_NEW, NF_INET_POST_ROUTING, &mut p), NF_ACCEPT);
        assert_eq!(src(&p), ([192, 0, 2, 9], 4002));
        assert!(sums_ok(p.data()));
        // A device with no address drops the packet.
        let mut q = pkt(IPPROTO_UDP, A, B, udp(4003, 53));
        nf_conntrack_in(&mut q, &state(NF_INET_LOCAL_OUT));
        st.out_dev = 4;
        let ct = q.nfct.get().unwrap().0.clone();
        assert_eq!(nf_nat_masquerade(&ct, &NfNatRange::default(), &st, q.data()), NF_DROP);
    }

    #[test]
    fn redirect_sends_the_packet_to_the_host() {
        let _s = SERIAL.lock();
        fresh(80_000);
        nf_nat_set_src_fn(|pf, ifindex, from| {
            (pf == NFPROTO_IPV4 && ifindex == 2 && from[..4] == N).then(|| addr(C))
        });
        // `redirect to :8080` at prerouting: the address of the device that the packet came in
        // on, and the port.
        let mut st = state(NF_INET_PRE_ROUTING);
        st.in_dev = 2;
        let mut p = pkt(IPPROTO_UDP, N, B, udp(4005, 80));
        nf_conntrack_in(&mut p, &st);
        let ct = p.nfct.get().unwrap().0.clone();
        let r = NfNatRange {
            flags: NF_NAT_RANGE_PROTO_SPECIFIED,
            min_proto: 8080,
            max_proto: 8080,
            ..NfNatRange::default()
        };
        assert_eq!(nf_nat_redirect(&ct, &r, &st, p.data()), NF_ACCEPT);
        assert_eq!(nf_nat_packet(&ct, IP_CT_NEW, NF_INET_PRE_ROUTING, &mut p), NF_ACCEPT);
        assert_eq!(dst(&p), (C, 8080));
        assert!(sums_ok(p.data()));
        // A packet of the host goes to 127.0.0.1, and a device with no address drops.
        let mut q = pkt(IPPROTO_UDP, A, B, udp(4006, 80));
        let out = state(NF_INET_LOCAL_OUT);
        nf_conntrack_in(&mut q, &out);
        let ct = q.nfct.get().unwrap().0.clone();
        assert_eq!(nf_nat_redirect(&ct, &NfNatRange::default(), &out, q.data()), NF_ACCEPT);
        assert_eq!(nf_nat_packet(&ct, IP_CT_NEW, NF_INET_LOCAL_OUT, &mut q), NF_ACCEPT);
        assert_eq!(dst(&q), ([127, 0, 0, 1], 80));
        let mut z = pkt(IPPROTO_UDP, A, B, udp(4007, 80));
        nf_conntrack_in(&mut z, &st);
        let ct = z.nfct.get().unwrap().0.clone();
        assert_eq!(nf_nat_redirect(&ct, &NfNatRange::default(), &st, z.data()), NF_DROP);
    }

    #[test]
    fn a_udp_datagram_with_no_checksum_keeps_none() {
        let mut p = pkt(IPPROTO_UDP, A, B, udp(4004, 53));
        p.data_mut()[26..28].fill(0);
        let mut t =
            NfConntrackTuple { l3num: NFPROTO_IPV4, protonum: IPPROTO_UDP, ..Default::default() };
        t.src = addr(N);
        t.src_u = 6000;
        assert!(manip_pkt(p.data_mut(), 0, &t, NF_NAT_MANIP_SRC, IPPROTO_UDP));
        assert_eq!(src(&p), (N, 6000));
        assert_eq!(get16(p.data(), 26), 0);
        assert_eq!(csum_fold(csum_add(0, &p.data()[..20])), 0);
    }
}

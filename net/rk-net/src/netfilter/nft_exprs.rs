//! The expressions `byteorder`, `range`, `limit`, `log` and `reject` of nf_tables, as
//! nft_byteorder.c, nft_range.c, nft_limit.c, nft_log.c, nf_log_syslog.c, nft_reject.c,
//! nft_reject_ipv4.c, nft_reject_ipv6.c and nft_reject_inet.c of Linux.

use super::{NFT_BREAK, NftRegs, be32, be64, len_attr, nft_parse_register, nft_value};
use crate::buf::NetBuf;
use crate::netfilter::nf_reject::{NfReject, nf_send_reject};
use crate::netfilter::{NFPROTO_INET, NFPROTO_IPV4, NFPROTO_IPV6, NfHookState};
use crate::netlink::msg::Attrs;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::{self, Write};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::inode::Result;

// `NFTA_BYTEORDER_*` and `enum nft_byteorder_ops`.
const NFTA_BYTEORDER_SREG: u32 = 1;
const NFTA_BYTEORDER_DREG: u32 = 2;
const NFTA_BYTEORDER_OP: u32 = 3;
const NFTA_BYTEORDER_LEN: u32 = 4;
const NFTA_BYTEORDER_SIZE: u32 = 5;
const NFT_BYTEORDER_NTOH: u32 = 0;
const NFT_BYTEORDER_HTON: u32 = 1;

// `NFTA_RANGE_*` and `enum nft_range_ops`.
const NFTA_RANGE_SREG: u32 = 1;
const NFTA_RANGE_OP: u32 = 2;
const NFTA_RANGE_FROM_DATA: u32 = 3;
const NFTA_RANGE_TO_DATA: u32 = 4;
const NFT_RANGE_EQ: u32 = 0;
const NFT_RANGE_NEQ: u32 = 1;

// `NFTA_LIMIT_*`, `enum nft_limit_type` and `enum nft_limit_flags`.
const NFTA_LIMIT_RATE: u32 = 1;
const NFTA_LIMIT_UNIT: u32 = 2;
const NFTA_LIMIT_BURST: u32 = 3;
const NFTA_LIMIT_TYPE: u32 = 4;
const NFTA_LIMIT_FLAGS: u32 = 5;
const NFT_LIMIT_PKTS: u32 = 0;
const NFT_LIMIT_PKT_BYTES: u32 = 1;
const NFT_LIMIT_F_INV: u32 = 1;
/// The burst of a limit of packets with no burst, `NFT_LIMIT_PKT_BURST_DEFAULT`.
const NFT_LIMIT_PKT_BURST_DEFAULT: u32 = 5;
const NSEC_PER_SEC: u64 = 1_000_000_000;

// `NFTA_LOG_*`, the levels and the flags of nf_log.
const NFTA_LOG_GROUP: u32 = 1;
const NFTA_LOG_PREFIX: u32 = 2;
const NFTA_LOG_LEVEL: u32 = 5;
const NFTA_LOG_FLAGS: u32 = 6;
/// `LOGLEVEL_WARNING`, the level of a `log` with no level.
const NFT_LOGLEVEL_WARNING: u32 = 4;
/// `NFT_LOGLEVEL_AUDIT`, the level that sends the packet to the audit log.
const NFT_LOGLEVEL_AUDIT: u32 = 8;
/// `NF_LOG_TCPSEQ`: the sequence numbers of TCP.
const NF_LOG_TCPSEQ: u32 = 0x01;
/// `NF_LOG_MASK`, the flags that `log` takes.
const NF_LOG_MASK: u32 = 0x2f;
/// `NF_LOG_PREFIXLEN`: a prefix has fewer bytes.
const NF_LOG_PREFIXLEN: usize = 128;

// `NFTA_REJECT_*`, `enum nft_reject_types` and `enum nft_reject_inet_code`.
const NFTA_REJECT_TYPE: u32 = 1;
const NFTA_REJECT_ICMP_CODE: u32 = 2;
const NFT_REJECT_ICMP_UNREACH: u32 = 0;
const NFT_REJECT_TCP_RST: u32 = 1;
const NFT_REJECT_ICMPX_UNREACH: u32 = 2;
const NFT_REJECT_ICMPX_MAX: u8 = 3;
/// The ICMP codes of the codes of `NFT_REJECT_ICMPX_UNREACH`, as `icmp_code_v4` of Linux:
/// no route, port, host and administratively prohibited.
const ICMPX_V4: [u8; 4] = [0, 3, 1, 13];
/// The ICMPv6 codes of the codes of `NFT_REJECT_ICMPX_UNREACH`, as `icmp_code_v6` of Linux.
const ICMPX_V6: [u8; 4] = [0, 4, 3, 1];

/// `byteorder`, as nft_byteorder.c.
#[derive(Clone, Debug)]
pub(crate) struct NftByteorder {
    sreg: usize,
    dreg: usize,
    hton: bool,
    len: usize,
    size: usize,
}

/// Reads a `byteorder`, as `nft_byteorder_init` of Linux.
pub(super) fn nft_byteorder_init(data: &[u8]) -> Result<NftByteorder> {
    let a = Attrs::parse(data, 5);
    let (Some(op), Some(size)) = (be32(&a, NFTA_BYTEORDER_OP)?, be32(&a, NFTA_BYTEORDER_SIZE)?)
    else {
        return Err(Errno::EINVAL);
    };
    if !a.has(NFTA_BYTEORDER_SREG) || !a.has(NFTA_BYTEORDER_DREG) {
        return Err(Errno::EINVAL);
    }
    let hton = match op {
        NFT_BYTEORDER_NTOH => false,
        NFT_BYTEORDER_HTON => true,
        _ => return Err(Errno::EINVAL),
    };
    if !matches!(size, 2 | 4 | 8) {
        return Err(Errno::EINVAL);
    }
    let len = len_attr(&a, NFTA_BYTEORDER_LEN)?;
    if len > usize::from(u8::MAX) {
        return Err(Errno::ERANGE);
    }
    if len % size as usize != 0 {
        return Err(Errno::EINVAL);
    }
    let sreg = nft_parse_register(&a, NFTA_BYTEORDER_SREG, len)?;
    let dreg = nft_parse_register(&a, NFTA_BYTEORDER_DREG, len)?;
    Ok(NftByteorder { sreg, dreg, hton, len, size: size as usize })
}

/// Turns the words of a register to or from the order of the network, as
/// `nft_byteorder_eval` of Linux.
pub(super) fn nft_byteorder_eval(e: &NftByteorder, regs: &mut NftRegs) {
    let mut v = [0u8; super::NFT_REGS_LEN];
    v[..e.len].copy_from_slice(&regs.data[e.sreg..e.sreg + e.len]);
    for w in v[..e.len].chunks_exact_mut(e.size) {
        // The order of the network is big endian: a change to it and back are the same
        // change of the bytes of the host.
        match w.len() {
            2 => {
                let x = u16::from_ne_bytes([w[0], w[1]]);
                w.copy_from_slice(&if e.hton { x.to_be() } else { u16::from_be(x) }.to_ne_bytes());
            }
            4 => {
                let x = u32::from_ne_bytes([w[0], w[1], w[2], w[3]]);
                w.copy_from_slice(&if e.hton { x.to_be() } else { u32::from_be(x) }.to_ne_bytes());
            }
            _ => {
                let mut b = [0u8; 8];
                b.copy_from_slice(w);
                let x = u64::from_ne_bytes(b);
                w.copy_from_slice(&if e.hton { x.to_be() } else { u64::from_be(x) }.to_ne_bytes());
            }
        }
    }
    regs.store(e.dreg, &v[..e.len]);
}

/// `range`, as nft_range.c.
#[derive(Clone, Debug)]
pub(crate) struct NftRange {
    sreg: usize,
    neq: bool,
    from: Vec<u8>,
    to: Vec<u8>,
}

/// Reads a `range`, as `nft_range_init` of Linux.
pub(super) fn nft_range_init(data: &[u8]) -> Result<NftRange> {
    let a = Attrs::parse(data, 4);
    let (Some(f), Some(t)) = (a.get(NFTA_RANGE_FROM_DATA), a.get(NFTA_RANGE_TO_DATA)) else {
        return Err(Errno::EINVAL);
    };
    if !a.has(NFTA_RANGE_SREG) || !a.has(NFTA_RANGE_OP) {
        return Err(Errno::EINVAL);
    }
    let (from, to) = (nft_value(f)?, nft_value(t)?);
    if from.len() != to.len() {
        return Err(Errno::EINVAL);
    }
    let sreg = nft_parse_register(&a, NFTA_RANGE_SREG, from.len())?;
    let neq = match be32(&a, NFTA_RANGE_OP)? {
        Some(NFT_RANGE_EQ) => false,
        Some(NFT_RANGE_NEQ) => true,
        _ => return Err(Errno::EINVAL),
    };
    Ok(NftRange { sreg, neq, from, to })
}

/// Ends the rule when the register is not in the range, or is in it for `NFT_RANGE_NEQ`, as
/// `nft_range_eval` of Linux.
pub(super) fn nft_range_eval(e: &NftRange, regs: &mut NftRegs) {
    let v = &regs.data[e.sreg..e.sreg + e.from.len()];
    let inside = e.from.as_slice() <= v && v <= e.to.as_slice();
    if inside == e.neq {
        regs.verdict = NFT_BREAK;
    }
}

/// `limit`, as nft_limit.c: a bucket of tokens in nanoseconds. A packet takes the time that
/// the rate gives it, or the time of its bytes.
pub(crate) struct NftLimit {
    rate: u64,
    nsecs: u64,
    bytes: bool,
    invert: bool,
    tokens_max: u64,
    /// The tokens, and the time when the bucket last changed.
    bucket: SpinLock<(u64, u64)>,
}

impl fmt::Debug for NftLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NftLimit").field("rate", &self.rate).field("nsecs", &self.nsecs).finish()
    }
}

/// The nanoseconds of the clock since boot. A unit test sets the time.
#[cfg(not(test))]
fn now_ns() -> u64 {
    #[cfg(target_os = "none")]
    {
        rk_frame::time::clock_ns()
    }
    #[cfg(not(target_os = "none"))]
    {
        0
    }
}

#[cfg(test)]
pub(super) static TEST_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
fn now_ns() -> u64 {
    TEST_NS.load(core::sync::atomic::Ordering::Relaxed)
}

/// Reads a `limit`, as `nft_limit_init` and the `select_ops` of nft_limit.c of Linux.
pub(super) fn nft_limit_init(data: &[u8]) -> Result<Arc<NftLimit>> {
    let a = Attrs::parse(data, 6);
    let bytes = match be32(&a, NFTA_LIMIT_TYPE)?.unwrap_or(NFT_LIMIT_PKTS) {
        NFT_LIMIT_PKTS => false,
        NFT_LIMIT_PKT_BYTES => true,
        _ => return Err(Errno::EOPNOTSUPP),
    };
    let (Some(rate), Some(unit)) = (be64(&a, NFTA_LIMIT_RATE)?, be64(&a, NFTA_LIMIT_UNIT)?) else {
        return Err(Errno::EINVAL);
    };
    if rate == 0 {
        return Err(Errno::EINVAL);
    }
    let nsecs = unit.checked_mul(NSEC_PER_SEC).ok_or(Errno::EOVERFLOW)?;
    let mut burst = u64::from(be32(&a, NFTA_LIMIT_BURST)?.unwrap_or(0));
    if !bytes && burst == 0 {
        burst = u64::from(NFT_LIMIT_PKT_BURST_DEFAULT);
    }
    rate.checked_add(burst).ok_or(Errno::EOVERFLOW)?;
    let tokens = if bytes {
        nsecs.checked_mul(burst).ok_or(Errno::EOVERFLOW)? / rate
    } else {
        (nsecs / rate).checked_mul(burst).ok_or(Errno::EOVERFLOW)?
    };
    let flags = be32(&a, NFTA_LIMIT_FLAGS)?.unwrap_or(0);
    if flags & !NFT_LIMIT_F_INV != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(Arc::new(NftLimit {
        rate,
        nsecs,
        bytes,
        invert: flags & NFT_LIMIT_F_INV != 0,
        tokens_max: tokens,
        bucket: SpinLock::new((tokens, now_ns())),
    }))
}

/// Takes the cost of the packet from the bucket, as `nft_limit_eval` of Linux. A packet over
/// the limit ends the rule, or a packet under it with `NFT_LIMIT_F_INV`.
pub(super) fn nft_limit_eval(l: &NftLimit, regs: &mut NftRegs, skb: &NetBuf) {
    let cost = if l.bytes {
        (u128::from(l.nsecs) * skb.len() as u128 / u128::from(l.rate)) as u64
    } else {
        l.nsecs / l.rate
    };
    let now = now_ns();
    let over = {
        let mut b = l.bucket.lock();
        let tokens = b.0.saturating_add(now.saturating_sub(b.1)).min(l.tokens_max);
        b.1 = now;
        match tokens.checked_sub(cost) {
            Some(left) => {
                b.0 = left;
                false
            }
            None => {
                b.0 = tokens;
                true
            }
        }
    };
    if over != l.invert {
        regs.verdict = NFT_BREAK;
    }
}

/// `reject`, as nft_reject.c and its forms for each family.
#[derive(Clone, Debug)]
pub(crate) struct NftReject {
    ty: u32,
    code: u8,
}

/// Reads a `reject` of a table of the family `family`, as `nft_reject_init` of Linux. A table
/// of the family ARP has no `reject`.
pub(super) fn nft_reject_init(family: u8, data: &[u8]) -> Result<NftReject> {
    if !matches!(family, NFPROTO_IPV4 | NFPROTO_IPV6 | NFPROTO_INET) {
        return Err(Errno::EOPNOTSUPP);
    }
    let a = Attrs::parse(data, 2);
    let Some(ty) = be32(&a, NFTA_REJECT_TYPE)? else { return Err(Errno::EINVAL) };
    let code = match ty {
        NFT_REJECT_ICMP_UNREACH | NFT_REJECT_ICMPX_UNREACH => {
            let Some(code) = a.u8(NFTA_REJECT_ICMP_CODE)? else { return Err(Errno::EINVAL) };
            if ty == NFT_REJECT_ICMPX_UNREACH && code > NFT_REJECT_ICMPX_MAX {
                return Err(Errno::EINVAL);
            }
            code
        }
        NFT_REJECT_TCP_RST => 0,
        _ => return Err(Errno::EINVAL),
    };
    Ok(NftReject { ty, code })
}

/// Sends the answer of `reject` and drops the packet, as `nft_reject_inet_eval` and the eval
/// of the other families of Linux. `NFT_REJECT_ICMPX_UNREACH` takes the code of the family of
/// the packet.
pub(super) fn nft_reject_eval(e: &NftReject, skb: &NetBuf, state: &NfHookState) -> u32 {
    let v6 = state.pf == NFPROTO_IPV6;
    let how = match e.ty {
        NFT_REJECT_TCP_RST => Some(NfReject::TcpReset),
        NFT_REJECT_ICMP_UNREACH => Some(NfReject::Unreach(e.code)),
        NFT_REJECT_ICMPX_UNREACH => {
            let map = if v6 { &ICMPX_V6 } else { &ICMPX_V4 };
            Some(NfReject::Unreach(map[usize::from(e.code)]))
        }
        _ => None,
    };
    if let Some(how) = how {
        nf_send_reject(state.pf, state.hook, state.in_dev, skb.data(), how);
    }
    super::NF_DROP
}

/// `log` to the kernel log, as nft_log.c with `NF_LOG_TYPE_LOG`.
#[derive(Clone, Debug)]
pub(crate) struct NftLog {
    prefix: Vec<u8>,
    level: u16,
    flags: u32,
}

impl NftLog {
    /// A `log` to the kernel log with a prefix, a level and the flags of nf_log, as the target
    /// `LOG` of xtables makes it in `log_tg` of xt_LOG.c of Linux.
    pub(crate) fn new(prefix: &[u8], level: u8, flags: u8) -> NftLog {
        NftLog {
            prefix: prefix.to_vec(),
            level: level.into(),
            flags: u32::from(flags) & NF_LOG_MASK,
        }
    }
}

/// Reads a `log`, as `nft_log_init` of Linux. A group sends the packets to nfnetlink_log,
/// which is not here, and gives `ENOENT` as a logger that Linux cannot load.
pub(super) fn nft_log_init(data: &[u8]) -> Result<NftLog> {
    let a = Attrs::parse(data, 6);
    let prefix = match a.get(NFTA_LOG_PREFIX) {
        Some(p) => {
            let p = p.split(|&c| c == 0).next().unwrap_or(p);
            if p.len() >= NF_LOG_PREFIXLEN {
                return Err(Errno::ERANGE);
            }
            p.to_vec()
        }
        None => Vec::new(),
    };
    if a.has(NFTA_LOG_GROUP) {
        if a.has(NFTA_LOG_LEVEL) || a.has(NFTA_LOG_FLAGS) {
            return Err(Errno::EINVAL);
        }
        return Err(Errno::ENOENT);
    }
    let level = be32(&a, NFTA_LOG_LEVEL)?.unwrap_or(NFT_LOGLEVEL_WARNING);
    if level > NFT_LOGLEVEL_AUDIT {
        return Err(Errno::EINVAL);
    }
    if level == NFT_LOGLEVEL_AUDIT {
        // The audit log is not here.
        return Err(Errno::EOPNOTSUPP);
    }
    let flags = be32(&a, NFTA_LOG_FLAGS)?.unwrap_or(0);
    if flags & !NF_LOG_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    Ok(NftLog { prefix, level: level as u16, flags })
}

/// A line of the kernel log.
struct Line(Vec<u8>);

impl Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// The name of the device `ifindex`, or nothing for 0.
fn dev_name(ifindex: u32) -> alloc::string::String {
    if ifindex == 0 {
        return alloc::string::String::new();
    }
    crate::dev::by_index(ifindex).map(|d| d.name()).unwrap_or_default()
}

/// Writes the line of the packet, as `nf_log_ip_packet`, `nf_log_ip6_packet`,
/// `dump_ipv4_packet` and `dump_ipv6_packet` of nf_log_syslog.c of Linux, with no MAC
/// address and no options.
pub(crate) fn nft_log_line(l: &NftLog, skb: &NetBuf, state: &NfHookState) -> Vec<u8> {
    let mut w = Line(l.prefix.clone());
    let _ = write!(w, "IN={} OUT={} ", dev_name(state.in_dev), dev_name(state.out_dev));
    let d = skb.data();
    let (proto, l4) = if state.pf == NFPROTO_IPV6 {
        let Some(h) = d.get(..40) else {
            w.0.extend_from_slice(b"TRUNCATED");
            return w.0;
        };
        let addr = |a: &[u8]| {
            let mut s = alloc::string::String::new();
            for (i, p) in a.chunks(2).enumerate() {
                let _ = write!(s, "{}{:02x}{:02x}", if i > 0 { ":" } else { "" }, p[0], p[1]);
            }
            s
        };
        let tc = (u32::from(h[0] & 0xf) << 4) | u32::from(h[1] >> 4);
        let flow = u32::from_be_bytes([0, h[1] & 0xf, h[2], h[3]]);
        let _ = write!(
            w,
            "SRC={} DST={} LEN={} TC={} HOPLIMIT={} FLOWLBL={} ",
            addr(&h[8..24]),
            addr(&h[24..40]),
            usize::from(u16::from_be_bytes([h[4], h[5]])) + 40,
            tc,
            h[7],
            flow
        );
        let pkt = crate::netfilter::nf_pktinfo(state.pf, d);
        match pkt.thoff {
            Some(off) => (pkt.l4proto, d.get(off..)),
            None => (h[6], None),
        }
    } else {
        let Some(h) = d.get(..20) else {
            w.0.extend_from_slice(b"TRUNCATED");
            return w.0;
        };
        let frag = u16::from_be_bytes([h[6], h[7]]);
        let _ = write!(
            w,
            "SRC={}.{}.{}.{} DST={}.{}.{}.{} LEN={} TOS=0x{:02X} PREC=0x{:02X} TTL={} ID={} ",
            h[12],
            h[13],
            h[14],
            h[15],
            h[16],
            h[17],
            h[18],
            h[19],
            u16::from_be_bytes([h[2], h[3]]),
            h[1] & 0x1e,
            h[1] & 0xe0,
            h[8],
            u16::from_be_bytes([h[4], h[5]])
        );
        for (bit, name) in [(0x8000, "CE "), (0x4000, "DF "), (0x2000, "MF ")] {
            if frag & bit != 0 {
                w.0.extend_from_slice(name.as_bytes());
            }
        }
        if frag & 0x1fff != 0 {
            let _ = write!(w, "FRAG:{} ", frag & 0x1fff);
            (h[9], None)
        } else {
            (h[9], d.get(usize::from(h[0] & 0xf) * 4..))
        }
    };
    let word = |b: &[u8], at: usize| u16::from_be_bytes([b[at], b[at + 1]]);
    match proto {
        6 => {
            w.0.extend_from_slice(b"PROTO=TCP ");
            match l4.filter(|t| t.len() >= 20) {
                None => {
                    let n = l4.map_or(0, <[u8]>::len);
                    let _ = write!(w, "INCOMPLETE [{n} bytes] ");
                }
                Some(t) => {
                    let _ = write!(w, "SPT={} DPT={} ", word(t, 0), word(t, 2));
                    if l.flags & NF_LOG_TCPSEQ != 0 {
                        let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
                        let ack = u32::from_be_bytes([t[8], t[9], t[10], t[11]]);
                        let _ = write!(w, "SEQ={seq} ACK={ack} ");
                    }
                    let _ = write!(w, "WINDOW={} RES=0x{:02x} ", word(t, 14), (t[12] & 0x0f) << 2);
                    let names = ["FIN ", "SYN ", "RST ", "PSH ", "ACK ", "URG ", "ECE ", "CWR "];
                    for i in (0..8).rev() {
                        if t[13] & 1 << i != 0 {
                            w.0.extend_from_slice(names[i].as_bytes());
                        }
                    }
                    let _ = write!(w, "URGP={} ", word(t, 18));
                }
            }
        }
        17 | 136 => {
            let name = if proto == 17 { "UDP" } else { "UDPLITE" };
            let _ = write!(w, "PROTO={name} ");
            match l4.filter(|u| u.len() >= 8) {
                None => {
                    let n = l4.map_or(0, <[u8]>::len);
                    let _ = write!(w, "INCOMPLETE [{n} bytes] ");
                }
                Some(u) => {
                    let _ = write!(w, "SPT={} DPT={} LEN={} ", word(u, 0), word(u, 2), word(u, 4));
                }
            }
        }
        1 | 58 => {
            let _ = write!(w, "PROTO={} ", if proto == 1 { "ICMP" } else { "ICMPv6" });
            match l4.filter(|i| i.len() >= 4) {
                None => {
                    let n = l4.map_or(0, <[u8]>::len);
                    let _ = write!(w, "INCOMPLETE [{n} bytes] ");
                }
                Some(i) => {
                    let _ = write!(w, "TYPE={} CODE={} ", i[0], i[1]);
                    // The echo requests and the echo replies.
                    if matches!((proto, i[0]), (1, 0 | 8) | (58, 128 | 129)) && i.len() >= 8 {
                        let _ = write!(w, "ID={} SEQ={} ", word(i, 4), word(i, 6));
                    }
                }
            }
        }
        p => {
            let _ = write!(w, "PROTO={p} ");
        }
    }
    w.0
}

/// Writes the packet to the kernel log at the level of the expression, as `nft_log_eval`.
pub(crate) fn nft_log_eval(l: &NftLog, skb: &NetBuf, state: &NfHookState) {
    let line = nft_log_line(l, skb, state);
    rk_frame::console::log_emit(l.level, &line);
}

#[cfg(test)]
mod tests {
    use super::super::{NFT_CONTINUE, NFT_REG_SIZE};
    use super::*;
    use crate::netfilter::{NF_INET_LOCAL_OUT, NFPROTO_IPV4};
    use crate::netlink::msg::{Builder, HDRLEN};
    use core::sync::atomic::Ordering;

    const R1: u32 = 1;

    fn regs() -> NftRegs {
        NftRegs { verdict: NFT_CONTINUE, chain: 0, data: [0; super::super::NFT_REGS_LEN] }
    }

    /// The attributes of an expression: each is a type and its bytes.
    fn attrs(list: &[(u16, &[u8])]) -> Vec<u8> {
        let mut b = Builder::new(0, 0, 0, 0);
        for (ty, v) in list {
            b.put(*ty, v);
        }
        b.finish()[HDRLEN..].to_vec()
    }

    /// `NFTA_DATA_VALUE` in a nest.
    fn value(v: &[u8]) -> Vec<u8> {
        attrs(&[(1, v)])
    }

    #[test]
    fn byteorder_turns_each_word() {
        let be = |v: u32| v.to_be_bytes();
        let b = nft_byteorder_init(&attrs(&[
            (1, &be(R1)),
            (2, &be(R1)),
            (3, &be(NFT_BYTEORDER_NTOH)),
            (4, &be(4)),
            (5, &be(2)),
        ]))
        .unwrap();
        let mut r = regs();
        r.data[NFT_REG_SIZE..NFT_REG_SIZE + 4].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        nft_byteorder_eval(&b, &mut r);
        let at = &r.data[NFT_REG_SIZE..NFT_REG_SIZE + 4];
        assert_eq!(u16::from_ne_bytes([at[0], at[1]]), 0x1234);
        assert_eq!(u16::from_ne_bytes([at[2], at[3]]), 0x5678);
        let b = nft_byteorder_init(&attrs(&[
            (1, &be(R1)),
            (2, &be(R1)),
            (3, &be(NFT_BYTEORDER_HTON)),
            (4, &be(8)),
            (5, &be(8)),
        ]))
        .unwrap();
        r.data[NFT_REG_SIZE..NFT_REG_SIZE + 8].copy_from_slice(&7u64.to_ne_bytes());
        nft_byteorder_eval(&b, &mut r);
        assert_eq!(r.data[NFT_REG_SIZE..NFT_REG_SIZE + 8], 7u64.to_be_bytes());
        // A size that is not 2, 4 or 8, and a length that is not a number of words.
        let bad = |size: u32, len: u32| {
            nft_byteorder_init(&attrs(&[
                (1, &be(R1)),
                (2, &be(R1)),
                (3, &be(0)),
                (4, &be(len)),
                (5, &be(size)),
            ]))
            .unwrap_err()
        };
        assert_eq!(bad(3, 6), Errno::EINVAL);
        assert_eq!(bad(4, 6), Errno::EINVAL);
    }

    #[test]
    fn range_matches_from_the_first_to_the_last_value() {
        let be = |v: u32| v.to_be_bytes();
        let range = |op: u32| {
            nft_range_init(&attrs(&[
                (1, &be(R1)),
                (2, &be(op)),
                (3, &value(&10u16.to_be_bytes())),
                (4, &value(&20u16.to_be_bytes())),
            ]))
            .unwrap()
        };
        let run = |e: &NftRange, port: u16| {
            let mut r = regs();
            r.data[NFT_REG_SIZE..NFT_REG_SIZE + 2].copy_from_slice(&port.to_be_bytes());
            nft_range_eval(e, &mut r);
            r.verdict == NFT_CONTINUE
        };
        let (eq, neq) = (range(NFT_RANGE_EQ), range(NFT_RANGE_NEQ));
        let m: Vec<bool> = [9, 10, 15, 20, 21].iter().map(|&p| run(&eq, p)).collect();
        assert_eq!(m, [false, true, true, true, false]);
        let m: Vec<bool> = [9, 10, 20, 21].iter().map(|&p| run(&neq, p)).collect();
        assert_eq!(m, [true, false, false, true]);
        let short = nft_range_init(&attrs(&[
            (1, &be(R1)),
            (2, &be(0)),
            (3, &value(&[1])),
            (4, &value(&[1, 2])),
        ]));
        assert_eq!(short.unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn limit_lets_the_burst_through_and_then_the_rate() {
        TEST_NS.store(1_000_000_000, Ordering::Relaxed);
        // limit rate 2/second burst 3 packets.
        let l = nft_limit_init(&attrs(&[
            (1, &2u64.to_be_bytes()),
            (2, &1u64.to_be_bytes()),
            (3, &3u32.to_be_bytes()),
        ]))
        .unwrap();
        let skb = NetBuf::from_slice(&[0; 100]);
        let pass = |l: &NftLimit| {
            let mut r = regs();
            nft_limit_eval(l, &mut r, &skb);
            r.verdict == NFT_CONTINUE
        };
        let first: Vec<bool> = (0..4).map(|_| pass(&l)).collect();
        assert_eq!(first, [true, true, true, false]);
        // Half a second gives one packet.
        TEST_NS.fetch_add(500_000_000, Ordering::Relaxed);
        assert_eq!((pass(&l), pass(&l)), (true, false));
        // A long wait fills the bucket to the burst, no more.
        TEST_NS.fetch_add(100 * NSEC_PER_SEC, Ordering::Relaxed);
        let again: Vec<bool> = (0..4).map(|_| pass(&l)).collect();
        assert_eq!(again, [true, true, true, false]);

        // limit rate over 200 bytes/second burst 100 bytes: the packets under it end the rule.
        let l = nft_limit_init(&attrs(&[
            (1, &200u64.to_be_bytes()),
            (2, &1u64.to_be_bytes()),
            (3, &100u32.to_be_bytes()),
            (4, &NFT_LIMIT_PKT_BYTES.to_be_bytes()),
            (5, &NFT_LIMIT_F_INV.to_be_bytes()),
        ]))
        .unwrap();
        assert_eq!((pass(&l), pass(&l)), (false, true));
        assert_eq!(
            nft_limit_init(&attrs(&[(1, &0u64.to_be_bytes()), (2, &1u64.to_be_bytes())]))
                .unwrap_err(),
            Errno::EINVAL
        );
        let huge = attrs(&[(1, &1u64.to_be_bytes()), (2, &u64::MAX.to_be_bytes())]);
        assert_eq!(nft_limit_init(&huge).unwrap_err(), Errno::EOVERFLOW);
    }

    #[test]
    fn log_writes_the_line_of_nf_log() {
        let l =
            nft_log_init(&attrs(&[(2, b"drop: \0"), (6, &NF_LOG_TCPSEQ.to_be_bytes())])).unwrap();
        assert_eq!(l.level, 4);
        let mut p = [0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[4..6].copy_from_slice(&7u16.to_be_bytes());
        p[6] = 0x40;
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p[20..22].copy_from_slice(&1000u16.to_be_bytes());
        p[22..24].copy_from_slice(&22u16.to_be_bytes());
        p[27] = 5;
        p[32] = 0x50;
        p[33] = 0x12;
        p[34..36].copy_from_slice(&512u16.to_be_bytes());
        let s = NfHookState { hook: NF_INET_LOCAL_OUT, pf: NFPROTO_IPV4, in_dev: 0, out_dev: 0 };
        let line = nft_log_line(&l, &NetBuf::from_slice(&p), &s);
        assert_eq!(
            core::str::from_utf8(&line).unwrap(),
            "drop: IN= OUT= SRC=10.0.0.1 DST=10.0.0.2 LEN=40 TOS=0x00 PREC=0x00 TTL=64 ID=7 DF \
             PROTO=TCP SPT=1000 DPT=22 SEQ=5 ACK=0 WINDOW=512 RES=0x00 ACK SYN URGP=0 "
        );
        let mut u = [0u8; 48];
        u[0] = 0x60;
        u[4..6].copy_from_slice(&8u16.to_be_bytes());
        u[6] = 17;
        u[7] = 255;
        u[23] = 1;
        u[39] = 1;
        u[40..42].copy_from_slice(&53u16.to_be_bytes());
        u[42..44].copy_from_slice(&5353u16.to_be_bytes());
        u[44..46].copy_from_slice(&8u16.to_be_bytes());
        let s = NfHookState { pf: NFPROTO_IPV6, ..s };
        let line = nft_log_line(&nft_log_init(&[]).unwrap(), &NetBuf::from_slice(&u), &s);
        let one = "0000:0000:0000:0000:0000:0000:0000:0001";
        assert_eq!(
            core::str::from_utf8(&line).unwrap(),
            alloc::format!(
                "IN= OUT= SRC={one} DST={one} LEN=48 TC=0 HOPLIMIT=255 FLOWLBL=0 PROTO=UDP \
                 SPT=53 DPT=5353 LEN=8 "
            )
        );
        // A group is nfnetlink_log, which is not here, and a level over the audit level.
        assert_eq!(nft_log_init(&attrs(&[(1, &0u16.to_be_bytes())])).unwrap_err(), Errno::ENOENT);
        assert_eq!(nft_log_init(&attrs(&[(5, &9u32.to_be_bytes())])).unwrap_err(), Errno::EINVAL);
        assert_eq!(
            nft_log_init(&attrs(&[(6, &0x40u32.to_be_bytes())])).unwrap_err(),
            Errno::EINVAL
        );
    }

    #[test]
    fn reject_sends_the_answer_of_the_family_and_drops() {
        use crate::netfilter::nf_reject::nf_reject_set_fn;
        static SENT: SpinLock<Vec<(u8, NfReject)>> = SpinLock::new(Vec::new());
        nf_reject_set_fn(|pf, _, _, _, how| SENT.lock().push((pf, how)));
        let be = |v: u32| v.to_be_bytes();
        let icmpx = nft_reject_init(NFPROTO_INET, &attrs(&[(1, &be(2)), (2, &[1])])).unwrap();
        let rst = nft_reject_init(NFPROTO_IPV4, &attrs(&[(1, &be(1))])).unwrap();
        let skb = NetBuf::from_slice(&[0x45; 20]);
        let mut s =
            NfHookState { hook: NF_INET_LOCAL_OUT, pf: NFPROTO_IPV4, in_dev: 0, out_dev: 1 };
        assert_eq!(nft_reject_eval(&icmpx, &skb, &s), super::super::NF_DROP);
        s.pf = NFPROTO_IPV6;
        nft_reject_eval(&icmpx, &skb, &s);
        nft_reject_eval(&rst, &skb, &s);
        assert_eq!(
            *SENT.lock(),
            [
                (NFPROTO_IPV4, NfReject::Unreach(3)),
                (NFPROTO_IPV6, NfReject::Unreach(4)),
                (NFPROTO_IPV6, NfReject::TcpReset)
            ]
        );
        // An ICMP type needs a code, an icmpx code is at most 3, and ARP has no reject.
        assert_eq!(
            nft_reject_init(NFPROTO_IPV4, &attrs(&[(1, &be(0))])).unwrap_err(),
            Errno::EINVAL
        );
        let big = attrs(&[(1, &be(2)), (2, &[4])]);
        assert_eq!(nft_reject_init(NFPROTO_INET, &big).unwrap_err(), Errno::EINVAL);
        assert_eq!(nft_reject_init(3, &attrs(&[(1, &be(1))])).unwrap_err(), Errno::EOPNOTSUPP);
        // No reject at the hook postrouting.
        let e = super::super::NftExpr::Reject(rst);
        let (mask, nat) = super::super::nft_expr_hooks(&e).unwrap();
        assert!(!nat && mask & 1 << crate::netfilter::NF_INET_POST_ROUTING == 0);
    }
}

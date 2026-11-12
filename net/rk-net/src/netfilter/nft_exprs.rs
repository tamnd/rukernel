//! The expressions `byteorder`, `range`, `limit`, `log`, `reject`, `numgen` and `hash` of
//! nf_tables, as nft_byteorder.c, nft_range.c, nft_limit.c, nft_log.c, nf_log_syslog.c,
//! nft_reject.c, nft_reject_ipv4.c, nft_reject_ipv6.c, nft_reject_inet.c, nft_numgen.c and
//! nft_hash.c of Linux, and `payload` that writes the packet and `queue`, as nft_payload.c and
//! nft_queue.c of Linux.

use super::{
    NFT_BREAK, NFT_PAYLOAD_NETWORK_HEADER, NFT_PAYLOAD_TRANSPORT_HEADER, NFTA_PAYLOAD_LEN,
    NFTA_PAYLOAD_OFFSET, NFTA_PAYLOAD_SREG, NftRegs, be32, be64, len_attr, nft_parse_register,
    nft_value,
};
use crate::buf::NetBuf;
use crate::netfilter::nf_nat::{csum_add, csum_fold, sctp_crc};
use crate::netfilter::nf_reject::{NfReject, nf_send_reject};
use crate::netfilter::{
    NF_VERDICT_FLAG_QUEUE_BYPASS, NFPROTO_INET, NFPROTO_IPV4, NFPROTO_IPV6, NfHookState, NfPktinfo,
    nf_queue_nr,
};
use crate::netlink::msg::Attrs;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
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

// `NFTA_NG_*` and `enum nft_ng_types`.
const NFTA_NG_DREG: u32 = 1;
const NFTA_NG_MODULUS: u32 = 2;
const NFTA_NG_TYPE: u32 = 3;
const NFTA_NG_OFFSET: u32 = 4;
const NFT_NG_INCREMENTAL: u32 = 0;
const NFT_NG_RANDOM: u32 = 1;

// `NFTA_HASH_*` and `enum nft_hash_types`.
const NFTA_HASH_SREG: u32 = 1;
const NFTA_HASH_DREG: u32 = 2;
const NFTA_HASH_LEN: u32 = 3;
const NFTA_HASH_MODULUS: u32 = 4;
const NFTA_HASH_SEED: u32 = 5;
const NFTA_HASH_OFFSET: u32 = 6;
const NFTA_HASH_TYPE: u32 = 7;
const NFT_HASH_JENKINS: u32 = 0;
const NFT_HASH_SYM: u32 = 1;

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

/// A pseudo-random number, as `get_random_u32` and `prandom_u32_state` for `numgen random`,
/// `meta random` and the seed of `jhash`. The first call takes a seed from the CPU.
pub(super) fn nft_prandom() -> u32 {
    static STATE: AtomicU64 = AtomicU64::new(0);
    let mut s = STATE.load(Ordering::Relaxed);
    if s == 0 {
        s = rk_frame::arch::random_seed() | 1;
    }
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    STATE.store(s, Ordering::Relaxed);
    (s >> 32) as u32
}

/// The real time in nanoseconds, as `ktime_get_real_ns` of Linux. The host has no clock.
pub(super) fn nft_realtime_ns() -> u64 {
    #[cfg(target_os = "none")]
    let ns = rk_frame::time::realtime_ns();
    #[cfg(not(target_os = "none"))]
    let ns = 0;
    ns
}

/// Puts `v` in the range from 0 to `n` less 1, as `reciprocal_scale` of Linux.
fn reciprocal_scale(v: u32, n: u32) -> u32 {
    ((u64::from(v) * u64::from(n)) >> 32) as u32
}

/// The hash of `key` with the seed `initval`, as `jhash` of Linux (lookup3.c of Bob Jenkins).
pub(super) fn jhash(key: &[u8], initval: u32) -> u32 {
    let init = 0xdead_beef_u32.wrapping_add(key.len() as u32).wrapping_add(initval);
    let (mut a, mut b, mut c) = (init, init, init);
    let word = |k: &[u8]| {
        let mut w = [0u8; 4];
        w[..k.len()].copy_from_slice(k);
        u32::from_le_bytes(w)
    };
    // The words of the loop are in the order of the CPU, as `__get_unaligned_cpu32`.
    let cpu = |k: &[u8]| u32::from_ne_bytes([k[0], k[1], k[2], k[3]]);
    let mut k = key;
    while k.len() > 12 {
        a = a.wrapping_add(cpu(&k[0..4]));
        b = b.wrapping_add(cpu(&k[4..8]));
        c = c.wrapping_add(cpu(&k[8..12]));
        // `__jhash_mix`.
        a = a.wrapping_sub(c) ^ c.rotate_left(4);
        c = c.wrapping_add(b);
        b = b.wrapping_sub(a) ^ a.rotate_left(6);
        a = a.wrapping_add(c);
        c = c.wrapping_sub(b) ^ b.rotate_left(8);
        b = b.wrapping_add(a);
        a = a.wrapping_sub(c) ^ c.rotate_left(16);
        c = c.wrapping_add(b);
        b = b.wrapping_sub(a) ^ a.rotate_left(19);
        a = a.wrapping_add(c);
        c = c.wrapping_sub(b) ^ b.rotate_left(4);
        b = b.wrapping_add(a);
        k = &k[12..];
    }
    if k.is_empty() {
        return c;
    }
    // The last bytes, in the order of a little-endian word, as the `switch` of `jhash`.
    a = a.wrapping_add(word(&k[..k.len().min(4)]));
    if k.len() > 4 {
        b = b.wrapping_add(word(&k[4..k.len().min(8)]));
    }
    if k.len() > 8 {
        c = c.wrapping_add(word(&k[8..]));
    }
    // `__jhash_final`.
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(14));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(11));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(25));
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(16));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(4));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(14));
    c ^= b;
    c.wrapping_sub(b.rotate_left(24))
}

/// Checks the modulus and the offset of `numgen` and `hash`, as `nft_ng_inc_init` and
/// `nft_jhash_init` of Linux: the last number must not go over `u32::MAX`.
fn nft_modulus_check(modulus: u32, offset: u32) -> Result<()> {
    if modulus == 0 {
        return Err(Errno::ERANGE);
    }
    offset.checked_add(modulus - 1).map(|_| ()).ok_or(Errno::EOVERFLOW)
}

/// `numgen`, as nft_numgen.c: a number from 0 to the modulus less 1, plus the offset.
#[derive(Clone, Debug)]
pub(crate) struct NftNumgen {
    dreg: usize,
    modulus: u32,
    offset: u32,
    /// The last number of `NFT_NG_INCREMENTAL`, or `None` for `NFT_NG_RANDOM`.
    counter: Option<Arc<AtomicU32>>,
}

/// Reads a `numgen`, as `nft_ng_select_ops`, `nft_ng_inc_init` and `nft_ng_random_init` of
/// Linux.
pub(super) fn nft_numgen_init(data: &[u8]) -> Result<NftNumgen> {
    let a = Attrs::parse(data, 6);
    let (Some(modulus), Some(ty)) = (be32(&a, NFTA_NG_MODULUS)?, be32(&a, NFTA_NG_TYPE)?) else {
        return Err(Errno::EINVAL);
    };
    if !a.has(NFTA_NG_DREG) || !matches!(ty, NFT_NG_INCREMENTAL | NFT_NG_RANDOM) {
        return Err(Errno::EINVAL);
    }
    let offset = be32(&a, NFTA_NG_OFFSET)?.unwrap_or(0);
    nft_modulus_check(modulus, offset)?;
    let dreg = nft_parse_register(&a, NFTA_NG_DREG, 4)?;
    // The first number of `NFT_NG_INCREMENTAL` is 0.
    let counter = (ty == NFT_NG_INCREMENTAL).then(|| Arc::new(AtomicU32::new(modulus - 1)));
    Ok(NftNumgen { dreg, modulus, offset, counter })
}

/// Puts the next number in the register, as `nft_ng_inc_eval` and `nft_ng_random_eval`.
pub(super) fn nft_numgen_eval(e: &NftNumgen, regs: &mut NftRegs) {
    let n = match &e.counter {
        Some(c) => {
            let next = |o: u32| if o + 1 < e.modulus { o + 1 } else { 0 };
            let old = c
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |o| Some(next(o)))
                .unwrap_or_else(|o| o);
            next(old)
        }
        None => reciprocal_scale(nft_prandom(), e.modulus),
    };
    regs.store(e.dreg, &(n + e.offset).to_ne_bytes());
}

/// `hash`, as nft_hash.c: a hash of a register, or a hash of the flow that is the same in the
/// two directions, from 0 to the modulus less 1, plus the offset.
#[derive(Clone, Debug)]
pub(crate) struct NftHash {
    /// The register and the length of the data of `NFT_HASH_JENKINS`, or `None` for
    /// `NFT_HASH_SYM`.
    src: Option<(usize, usize)>,
    dreg: usize,
    modulus: u32,
    offset: u32,
    seed: u32,
}

/// Reads a `hash`, as `nft_hash_select_ops`, `nft_jhash_init` and `nft_symhash_init` of Linux.
/// A `jhash` with no seed gets a random seed.
pub(super) fn nft_hash_init(data: &[u8]) -> Result<NftHash> {
    let a = Attrs::parse(data, 9);
    let sym = match be32(&a, NFTA_HASH_TYPE)? {
        None | Some(NFT_HASH_JENKINS) => false,
        Some(NFT_HASH_SYM) => true,
        Some(_) => return Err(Errno::EOPNOTSUPP),
    };
    let Some(modulus) = be32(&a, NFTA_HASH_MODULUS)? else { return Err(Errno::EINVAL) };
    if !a.has(NFTA_HASH_DREG) || (!sym && !(a.has(NFTA_HASH_SREG) && a.has(NFTA_HASH_LEN))) {
        return Err(Errno::EINVAL);
    }
    let offset = be32(&a, NFTA_HASH_OFFSET)?.unwrap_or(0);
    let mut src = None;
    let mut seed = nft_hashrnd();
    if !sym {
        let len = match be32(&a, NFTA_HASH_LEN)? {
            Some(l @ 1..=255) => l as usize,
            _ => return Err(Errno::ERANGE),
        };
        src = Some((nft_parse_register(&a, NFTA_HASH_SREG, len)?, len));
        seed = be32(&a, NFTA_HASH_SEED)?.unwrap_or_else(nft_prandom);
    }
    nft_modulus_check(modulus, offset)?;
    let dreg = nft_parse_register(&a, NFTA_HASH_DREG, 4)?;
    Ok(NftHash { src, dreg, modulus, offset, seed })
}

/// The seed of the hashes of the flows, as `hashrnd` of flow_dissector.c of Linux. It is the
/// same for all of the boot.
fn nft_hashrnd() -> u32 {
    static SEED: AtomicU32 = AtomicU32::new(0);
    let s = SEED.load(Ordering::Relaxed);
    if s != 0 {
        return s;
    }
    let _ = SEED.compare_exchange(0, nft_prandom() | 1, Ordering::Relaxed, Ordering::Relaxed);
    SEED.load(Ordering::Relaxed)
}

/// The hash of the flow of the packet `d` of the family `pf`, as `__skb_get_hash_symmetric`
/// of Linux: the addresses, the ports and the protocol, in an order that does not change with
/// the direction. The hash is not 0.
fn nft_symhash(d: &[u8], pf: u8, pkt: &NfPktinfo, seed: u32) -> u32 {
    let (at, alen) = if pf == NFPROTO_IPV6 { (8, 16) } else { (12, 4) };
    let (Some(s), Some(t)) = (d.get(at..at + alen), d.get(at + alen..at + 2 * alen)) else {
        return 0;
    };
    // TCP, UDP, DCCP, SCTP and UDP-Lite have the ports in the first 4 bytes.
    let ports = match (pkt.thoff, pkt.l4proto) {
        (Some(off), 6 | 17 | 33 | 132 | 136) => d.get(off..off + 4),
        _ => None,
    };
    let (sp, tp) = ports.map_or(([0u8; 2], [0u8; 2]), |p| ([p[0], p[1]], [p[2], p[3]]));
    let (lo, hi) = if (t, tp) < (s, sp) { ((t, tp), (s, sp)) } else { ((s, sp), (t, tp)) };
    let mut key = [0u8; 37];
    key[..alen].copy_from_slice(lo.0);
    key[alen..2 * alen].copy_from_slice(hi.0);
    key[2 * alen..2 * alen + 2].copy_from_slice(&lo.1);
    key[2 * alen + 2..2 * alen + 4].copy_from_slice(&hi.1);
    key[2 * alen + 4] = pkt.l4proto;
    match jhash(&key[..2 * alen + 5], seed) {
        0 => 1,
        h => h,
    }
}

/// Puts the hash in the register, as `nft_jhash_eval` and `nft_symhash_eval` of Linux.
pub(super) fn nft_hash_eval(
    e: &NftHash,
    regs: &mut NftRegs,
    skb: &NetBuf,
    pf: u8,
    pkt: &NfPktinfo,
) {
    let h = match e.src {
        Some((sreg, len)) => jhash(&regs.data[sreg..sreg + len], e.seed),
        None => nft_symhash(skb.data(), pf, pkt, e.seed),
    };
    regs.store(e.dreg, &(reciprocal_scale(h, e.modulus) + e.offset).to_ne_bytes());
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
    fn jhash_gives_the_values_of_linux() {
        let d: Vec<u8> = (0..40u8).map(|i| i.wrapping_mul(7) + 1).collect();
        let want = [
            (0, 0xf0e2_1567),
            (1, 0x4015_8784),
            (3, 0xd8f0_e5df),
            (4, 0xf7e6_ac94),
            (5, 0x236b_f5cd),
            (8, 0xdc12_b871),
            (12, 0xe8f4_c145),
            (13, 0xa2fb_e119),
            (24, 0x56fa_96df),
            (25, 0xe5fc_355e),
            (40, 0x9d69_5eda),
        ];
        for (len, h) in want {
            assert_eq!(jhash(&d[..len], 0x1234_5678), h, "{len}");
        }
        assert_eq!(jhash(&[10, 0, 0, 1], 0), 0x2fa5_f781);
    }

    #[test]
    fn numgen_counts_up_to_the_modulus_and_adds_the_offset() {
        let be = |v: u32| v.to_be_bytes();
        let ng = |ty: u32, modulus: u32, offset: u32| {
            nft_numgen_init(&attrs(&[
                (NFTA_NG_DREG as u16, &be(R1)),
                (NFTA_NG_MODULUS as u16, &be(modulus)),
                (NFTA_NG_TYPE as u16, &be(ty)),
                (NFTA_NG_OFFSET as u16, &be(offset)),
            ]))
        };
        let n = ng(NFT_NG_INCREMENTAL, 3, 10).unwrap();
        let mut r = regs();
        let mut got = Vec::new();
        for _ in 0..5 {
            nft_numgen_eval(&n, &mut r);
            got.push(u32::from_ne_bytes(
                r.data[NFT_REG_SIZE..NFT_REG_SIZE + 4].try_into().unwrap(),
            ));
        }
        assert_eq!(got, [10, 11, 12, 10, 11]);
        // A copy of the rule goes on from the same number.
        nft_numgen_eval(&n.clone(), &mut r);
        assert_eq!(r.data[NFT_REG_SIZE..NFT_REG_SIZE + 4], 12u32.to_ne_bytes());
        let n = ng(NFT_NG_RANDOM, 4, 0).unwrap();
        for _ in 0..20 {
            nft_numgen_eval(&n, &mut r);
            assert!(
                u32::from_ne_bytes(r.data[NFT_REG_SIZE..NFT_REG_SIZE + 4].try_into().unwrap()) < 4
            );
        }
        assert_eq!(ng(NFT_NG_INCREMENTAL, 0, 0).unwrap_err(), Errno::ERANGE);
        assert_eq!(ng(NFT_NG_INCREMENTAL, 2, u32::MAX).unwrap_err(), Errno::EOVERFLOW);
        assert_eq!(ng(2, 2, 0).unwrap_err(), Errno::EINVAL);
        let no_type = attrs(&[(NFTA_NG_DREG as u16, &be(R1)), (NFTA_NG_MODULUS as u16, &be(2))]);
        assert_eq!(nft_numgen_init(&no_type).unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn hash_puts_a_register_or_the_flow_in_the_modulus() {
        let be = |v: u32| v.to_be_bytes();
        // jhash ip saddr mod 10 seed 0x0 offset 100.
        let h = nft_hash_init(&attrs(&[
            (NFTA_HASH_SREG as u16, &be(R1)),
            (NFTA_HASH_DREG as u16, &be(R1)),
            (NFTA_HASH_LEN as u16, &be(4)),
            (NFTA_HASH_MODULUS as u16, &be(10)),
            (NFTA_HASH_SEED as u16, &be(0)),
            (NFTA_HASH_OFFSET as u16, &be(100)),
            (NFTA_HASH_TYPE as u16, &be(NFT_HASH_JENKINS)),
        ]))
        .unwrap();
        let mut r = regs();
        r.data[NFT_REG_SIZE..NFT_REG_SIZE + 4].copy_from_slice(&[10, 0, 0, 1]);
        let skb = NetBuf::from_slice(&[0x45; 28]);
        let pkt = NfPktinfo { thoff: None, l4proto: 0 };
        nft_hash_eval(&h, &mut r, &skb, NFPROTO_IPV4, &pkt);
        let want = reciprocal_scale(0x2fa5_f781, 10) + 100;
        assert_eq!(r.data[NFT_REG_SIZE..NFT_REG_SIZE + 4], want.to_ne_bytes());
        // symhash mod 1000: the two directions of a flow get the same number.
        let sym = nft_hash_init(&attrs(&[
            (NFTA_HASH_DREG as u16, &be(R1)),
            (NFTA_HASH_MODULUS as u16, &be(1000)),
            (NFTA_HASH_TYPE as u16, &be(NFT_HASH_SYM)),
        ]))
        .unwrap();
        let udp = |s: [u8; 4], d: [u8; 4], sp: u16, dp: u16| {
            let mut p = [0u8; 28];
            p[0] = 0x45;
            p[9] = 17;
            p[12..16].copy_from_slice(&s);
            p[16..20].copy_from_slice(&d);
            p[20..22].copy_from_slice(&sp.to_be_bytes());
            p[22..24].copy_from_slice(&dp.to_be_bytes());
            NetBuf::from_slice(&p)
        };
        let pkt = NfPktinfo { thoff: Some(20), l4proto: 17 };
        let mut get = |b: &NetBuf| {
            nft_hash_eval(&sym, &mut r, b, NFPROTO_IPV4, &pkt);
            u32::from_ne_bytes(r.data[NFT_REG_SIZE..NFT_REG_SIZE + 4].try_into().unwrap())
        };
        let a = get(&udp([10, 0, 0, 1], [10, 0, 0, 2], 1000, 53));
        assert_eq!(a, get(&udp([10, 0, 0, 2], [10, 0, 0, 1], 53, 1000)));
        assert!(a < 1000);
        let bad = |list: &[(u16, &[u8])]| nft_hash_init(&attrs(list)).unwrap_err();
        let len = |l: u32| {
            bad(&[
                (NFTA_HASH_SREG as u16, &be(R1)),
                (NFTA_HASH_DREG as u16, &be(R1)),
                (NFTA_HASH_LEN as u16, &be(l)),
                (NFTA_HASH_MODULUS as u16, &be(10)),
            ])
        };
        assert_eq!(len(0), Errno::ERANGE);
        assert_eq!(len(256), Errno::ERANGE);
        assert_eq!(
            bad(&[(NFTA_HASH_DREG as u16, &be(R1)), (NFTA_HASH_MODULUS as u16, &be(10))]),
            Errno::EINVAL
        );
        assert_eq!(bad(&[(NFTA_HASH_TYPE as u16, &be(2))]), Errno::EOPNOTSUPP);
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

// `NFTA_PAYLOAD_CSUM_*`, `enum nft_payload_csum_types` and `enum nft_payload_csum_flags`.
const NFTA_PAYLOAD_CSUM_TYPE: u32 = 6;
const NFTA_PAYLOAD_CSUM_OFFSET: u32 = 7;
const NFTA_PAYLOAD_CSUM_FLAGS: u32 = 8;
pub(super) const NFT_PAYLOAD_CSUM_NONE: u32 = 0;
pub(super) const NFT_PAYLOAD_CSUM_INET: u32 = 1;
pub(super) const NFT_PAYLOAD_CSUM_SCTP: u32 = 2;
const NFT_PAYLOAD_L4CSUM_PSEUDOHDR: u32 = 1;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;
const IPPROTO_SCTP: u8 = 132;
const IPPROTO_UDPLITE: u8 = 136;

/// `payload` that writes a register to the packet, as `nft_payload_set` of Linux.
#[derive(Clone, Debug)]
pub(crate) struct NftPayloadSet {
    pub(super) base: u32,
    pub(super) offset: usize,
    pub(super) len: usize,
    pub(super) sreg: usize,
    pub(super) csum_type: u32,
    pub(super) csum_offset: usize,
    /// `NFT_PAYLOAD_L4CSUM_PSEUDOHDR`: the bytes are in the pseudo header of the checksum of
    /// the transport header too.
    pub(super) l4csum: bool,
}

/// Reads `payload` with `NFTA_PAYLOAD_SREG`, as `nft_payload_set_init` of Linux. `base` is a
/// base that the packet can have.
pub(super) fn nft_payload_set_init(a: &Attrs<'_>, base: u32) -> Result<NftPayloadSet> {
    let Some(offset) = be32(a, NFTA_PAYLOAD_OFFSET)? else { return Err(Errno::EINVAL) };
    if offset > u32::from(u8::MAX) {
        return Err(Errno::ERANGE);
    }
    let len = len_attr(a, NFTA_PAYLOAD_LEN)?;
    let csum_type = be32(a, NFTA_PAYLOAD_CSUM_TYPE)?.unwrap_or(NFT_PAYLOAD_CSUM_NONE);
    let csum_offset = match be32(a, NFTA_PAYLOAD_CSUM_OFFSET)? {
        Some(o) if o > u32::from(u8::MAX) => return Err(Errno::ERANGE),
        o => o.unwrap_or(0) as usize,
    };
    let flags = be32(a, NFTA_PAYLOAD_CSUM_FLAGS)?.unwrap_or(0);
    if flags & !NFT_PAYLOAD_L4CSUM_PSEUDOHDR != 0 {
        return Err(Errno::EINVAL);
    }
    match csum_type {
        NFT_PAYLOAD_CSUM_NONE | NFT_PAYLOAD_CSUM_INET => {}
        // The checksum of SCTP is at offset 8 of its header.
        NFT_PAYLOAD_CSUM_SCTP if base == NFT_PAYLOAD_TRANSPORT_HEADER && csum_offset == 8 => {}
        NFT_PAYLOAD_CSUM_SCTP => return Err(Errno::EINVAL),
        _ => return Err(Errno::EOPNOTSUPP),
    }
    let sreg = nft_parse_register(a, NFTA_PAYLOAD_SREG, len)?;
    Ok(NftPayloadSet {
        base,
        offset: offset as usize,
        len,
        sreg,
        csum_type,
        csum_offset,
        l4csum: flags != 0,
    })
}

/// Writes the register of `p` to the packet and changes the checksums, as
/// `nft_payload_set_eval` of Linux. A write that the packet cannot take ends the rule.
pub(super) fn nft_payload_set_eval(
    p: &NftPayloadSet,
    regs: &mut NftRegs,
    skb: &mut NetBuf,
    pkt: &NfPktinfo,
) {
    let src = &regs.data[p.sreg..p.sreg + p.len];
    if nft_payload_set(skb, pkt, src, p).is_none() {
        regs.verdict = NFT_BREAK;
    }
}

fn nft_payload_set(skb: &mut NetBuf, pkt: &NfPktinfo, src: &[u8], p: &NftPayloadSet) -> Option<()> {
    let start = match p.base {
        NFT_PAYLOAD_NETWORK_HEADER => 0,
        NFT_PAYLOAD_TRANSPORT_HEADER => pkt.thoff?,
        // The packet has no link layer header at the hooks of IPv4 and IPv6.
        _ => return None,
    };
    let at = start + p.offset;
    let end = at + src.len();
    let d = skb.data_mut();
    if end > d.len() {
        return None;
    }
    if p.csum_type == NFT_PAYLOAD_CSUM_INET || p.l4csum {
        let fsum = csum_add(0, &d[at..end]);
        let tsum = csum_add(0, src);
        if p.csum_type == NFT_PAYLOAD_CSUM_INET {
            nft_csum_replace(d, start + p.csum_offset, fsum, tsum)?;
        }
        // A packet with no checksum of the transport header keeps none, as
        // `nft_payload_l4csum_update` of Linux.
        if p.l4csum
            && let Some(l4) = nft_payload_l4csum_offset(pkt, d)
        {
            nft_csum_replace(d, l4, fsum, tsum)?;
        }
    }
    d[at..end].copy_from_slice(src);
    if p.csum_type == NFT_PAYLOAD_CSUM_SCTP && pkt.l4proto == IPPROTO_SCTP {
        let t = pkt.thoff?;
        let ip_end = nft_ip_end(d).min(d.len());
        if ip_end < t + 12 {
            return None;
        }
        let crc = sctp_crc(&d[t..ip_end]);
        d[t + 8..t + 12].copy_from_slice(&crc.to_le_bytes());
    }
    Some(())
}

/// Changes the checksum at `at` of `d` for the bytes of the sum `tsum` in place of the bytes
/// of the sum `fsum`, as `nft_csum_replace` of Linux.
fn nft_csum_replace(d: &mut [u8], at: usize, fsum: u32, tsum: u32) -> Option<()> {
    let w = d.get_mut(at..at + 2)?;
    let old = u16::from_be_bytes([w[0], w[1]]);
    // `csum_fold` gives the complement of the sum.
    let s = u32::from(!old) + u32::from(csum_fold(fsum)) + u32::from(!csum_fold(tsum));
    let sum = match csum_fold(s) {
        0 => 0xffff,
        s => s,
    };
    w.copy_from_slice(&sum.to_be_bytes());
    Some(())
}

/// The offset of the checksum of the transport header that has the pseudo header, as
/// `nft_payload_l4csum_offset` of Linux. A UDP datagram with no checksum has none.
fn nft_payload_l4csum_offset(pkt: &NfPktinfo, d: &[u8]) -> Option<usize> {
    let t = pkt.thoff?;
    let at = match pkt.l4proto {
        IPPROTO_TCP => 16,
        IPPROTO_UDP => {
            if d.get(t + 6..t + 8)? == [0, 0] {
                return None;
            }
            6
        }
        IPPROTO_UDPLITE => 6,
        IPPROTO_ICMPV6 => 2,
        _ => return None,
    };
    Some(t + at)
}

/// The end of the IP packet `d`, from the length in its header.
fn nft_ip_end(d: &[u8]) -> usize {
    match d.first().map(|b| b >> 4) {
        Some(4) if d.len() >= 4 => usize::from(u16::from_be_bytes([d[2], d[3]])),
        Some(6) if d.len() >= 6 => 40 + usize::from(u16::from_be_bytes([d[4], d[5]])),
        _ => d.len(),
    }
}

// `NFTA_QUEUE_*` and `NFT_QUEUE_FLAG_*`.
const NFTA_QUEUE_NUM: u32 = 1;
const NFTA_QUEUE_TOTAL: u32 = 2;
const NFTA_QUEUE_FLAGS: u32 = 3;
const NFTA_QUEUE_SREG_QNUM: u32 = 4;
const NFT_QUEUE_FLAG_BYPASS: u16 = 0x01;
const NFT_QUEUE_FLAG_CPU_FANOUT: u16 = 0x02;
const NFT_QUEUE_FLAG_MASK: u16 = 0x03;

fn be16_attr(a: &Attrs<'_>, ty: u32) -> Result<Option<u16>> {
    match a.get(ty) {
        None => Ok(None),
        Some(&[x, y]) => Ok(Some(u16::from_be_bytes([x, y]))),
        Some(_) => Err(Errno::EINVAL),
    }
}

/// `queue`, as nft_queue.c of Linux: the queue `num`, or the queue in the register `sreg`.
#[derive(Clone, Debug)]
pub(crate) struct NftQueue {
    num: u16,
    sreg: Option<usize>,
    bypass: bool,
}

/// Reads `queue`, as `nft_queue_select_ops`, `nft_queue_init` and `nft_queue_sreg_init` of
/// Linux.
pub(super) fn nft_queue_init(data: &[u8]) -> Result<NftQueue> {
    let a = Attrs::parse(data, 4);
    let flags = be16_attr(&a, NFTA_QUEUE_FLAGS)?.unwrap_or(0);
    if flags & !NFT_QUEUE_FLAG_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    let bypass = flags & NFT_QUEUE_FLAG_BYPASS != 0;
    match (a.has(NFTA_QUEUE_NUM), a.has(NFTA_QUEUE_SREG_QNUM)) {
        (true, true) | (false, false) => Err(Errno::EINVAL),
        (true, false) => {
            let num = be16_attr(&a, NFTA_QUEUE_NUM)?.unwrap_or(0);
            let total = be16_attr(&a, NFTA_QUEUE_TOTAL)?.unwrap_or(1);
            if total == 0 {
                return Err(Errno::EINVAL);
            }
            if u32::from(total) - 1 + u32::from(num) > u32::from(u16::MAX) {
                return Err(Errno::ERANGE);
            }
            Ok(NftQueue { num, sreg: None, bypass })
        }
        (false, true) => {
            let sreg = nft_parse_register(&a, NFTA_QUEUE_SREG_QNUM, 4)?;
            if flags & NFT_QUEUE_FLAG_CPU_FANOUT != 0 {
                return Err(Errno::EOPNOTSUPP);
            }
            Ok(NftQueue { num: 0, sreg: Some(sreg), bypass })
        }
    }
}

/// Gives the packet to its queue, as `nft_queue_eval` and `nft_queue_sreg_eval` of Linux. A
/// spread of the packets over more than one queue is not here: the first queue gets them.
pub(super) fn nft_queue_eval(q: &NftQueue, regs: &mut NftRegs) {
    let num = match q.sreg {
        Some(r) => {
            let w = &regs.data[r..r + 4];
            u32::from_ne_bytes([w[0], w[1], w[2], w[3]]) as u16
        }
        None => q.num,
    };
    let bypass = if q.bypass { NF_VERDICT_FLAG_QUEUE_BYPASS } else { 0 };
    regs.verdict = nf_queue_nr(num) | bypass;
}

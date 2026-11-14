//! The expression `exthdr` of nf_tables, as nft_exthdr.c of Linux: the extension headers of
//! IPv6, the options of IPv4, TCP and DCCP, and the chunks of SCTP. It reads a field of a
//! header or tells that the header is there, and for TCP it also writes a field of an option
//! (`tcp option maxseg size set 1360`) or removes an option (`reset tcp option sack-perm`).

use super::{NFT_BREAK, NftRegs, be32, nft_parse_register};
use crate::buf::NetBuf;
use crate::netfilter::nf_nat::csum_add;
use crate::netfilter::{NF_DROP, NFPROTO_IPV4, NFPROTO_IPV6, NfHookState, NfPktinfo};
use crate::netlink::msg::Attrs;
use rk_abi::Errno;
use rk_vfs::inode::Result;

// `NFTA_EXTHDR_*`, `enum nft_exthdr_op` and `enum nft_exthdr_flags`.
const NFTA_EXTHDR_DREG: u32 = 1;
const NFTA_EXTHDR_TYPE: u32 = 2;
const NFTA_EXTHDR_OFFSET: u32 = 3;
const NFTA_EXTHDR_LEN: u32 = 4;
const NFTA_EXTHDR_FLAGS: u32 = 5;
const NFTA_EXTHDR_OP: u32 = 6;
const NFTA_EXTHDR_SREG: u32 = 7;
const NFT_EXTHDR_OP_IPV6: u32 = 0;
const NFT_EXTHDR_OP_TCPOPT: u32 = 1;
const NFT_EXTHDR_OP_IPV4: u32 = 2;
const NFT_EXTHDR_OP_SCTP: u32 = 3;
const NFT_EXTHDR_OP_DCCP: u32 = 4;
const NFT_EXTHDR_F_PRESENT: u32 = 1 << 0;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_DCCP: u8 = 33;
const IPPROTO_SCTP: u8 = 132;

// The options of IPv4 that `exthdr` finds, `IPOPT_*`.
const IPOPT_END: u8 = 0;
const IPOPT_NOOP: u8 = 1;
const IPOPT_RR: u8 = 7;
const IPOPT_TIMESTAMP: u8 = 68;
const IPOPT_LSRR: u8 = 131;
const IPOPT_CIPSO: u8 = 134;
const IPOPT_RA: u8 = 148;
const IPOPT_SSRR: u8 = 137;
const IPOPT_TS_PRESPEC: u8 = 3;

// The options of TCP, `TCPOPT_*`.
const TCPOPT_NOP: u8 = 1;
const TCPOPT_MSS: u8 = 2;

/// `IP6_MAX_EXT_HDRS_CNT` of Linux.
const IP6_MAX_EXT_HDRS_CNT: usize = 32;
/// `DCCPO_MAX_RESERVED` of Linux: the options of DCCP up to it have 1 byte.
const DCCPO_MAX_RESERVED: u8 = 31;

/// What the expression does with the header, as the `nft_expr_ops` of nft_exthdr.c.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// Reads the field to the register `dreg`, or tells that the header is there.
    Get,
    /// Writes the register `sreg` to the field of a TCP option, as `nft_exthdr_tcp_set_eval`.
    Set,
    /// Removes a TCP option, as `nft_exthdr_tcp_strip_eval`.
    Strip,
}

/// `exthdr`, as `struct nft_exthdr` of Linux. `reg` is `dreg` for `Get`, `sreg` for `Set`.
#[derive(Clone, Debug)]
pub(crate) struct NftExthdr {
    kind: Kind,
    op: u32,
    ty: u8,
    offset: usize,
    len: usize,
    flags: u32,
    reg: usize,
}

/// Reads a 32-bit attribute that must be at most 255, as `nft_parse_u32_check` with `U8_MAX`.
fn u8_attr(a: &Attrs<'_>, ty: u32) -> Result<Option<u32>> {
    match be32(a, ty)? {
        Some(v) if v > 255 => Err(Errno::ERANGE),
        v => Ok(v),
    }
}

/// Reads an `exthdr` expression of a table of the family `family`, as `nft_exthdr_select_ops`,
/// `nft_exthdr_init`, `nft_exthdr_tcp_set_init`, `nft_exthdr_tcp_strip_init`,
/// `nft_exthdr_ipv4_init` and `nft_exthdr_dccp_init` of Linux.
pub(super) fn nft_exthdr_init(family: u8, data: &[u8]) -> Result<NftExthdr> {
    let a = Attrs::parse(data, NFTA_EXTHDR_SREG as u16);
    let (dreg, sreg) = (a.has(NFTA_EXTHDR_DREG), a.has(NFTA_EXTHDR_SREG));
    let kind = match u8_attr(&a, NFTA_EXTHDR_OP)? {
        // With no operation, `exthdr` is of IPv6.
        None => Kind::Get,
        Some(_) if dreg && sreg => return Err(Errno::EOPNOTSUPP),
        Some(NFT_EXTHDR_OP_TCPOPT) if sreg => Kind::Set,
        Some(NFT_EXTHDR_OP_TCPOPT) if !dreg => Kind::Strip,
        Some(NFT_EXTHDR_OP_IPV4) if family == NFPROTO_IPV6 => return Err(Errno::EOPNOTSUPP),
        Some(
            NFT_EXTHDR_OP_TCPOPT | NFT_EXTHDR_OP_IPV6 | NFT_EXTHDR_OP_IPV4 | NFT_EXTHDR_OP_SCTP
            | NFT_EXTHDR_OP_DCCP,
        ) if dreg => Kind::Get,
        Some(_) => return Err(Errno::EOPNOTSUPP),
    };
    let op = u8_attr(&a, NFTA_EXTHDR_OP)?.unwrap_or(NFT_EXTHDR_OP_IPV6);
    // `NLA_U8`.
    let ty = a.get(NFTA_EXTHDR_TYPE).and_then(|t| t.first().copied());
    if kind == Kind::Strip {
        if a.has(NFTA_EXTHDR_FLAGS) || a.has(NFTA_EXTHDR_OFFSET) || a.has(NFTA_EXTHDR_LEN) {
            return Err(Errno::EINVAL);
        }
        let Some(ty) = ty else { return Err(Errno::EINVAL) };
        return Ok(NftExthdr { kind, op, ty, offset: 0, len: 0, flags: 0, reg: 0 });
    }
    let (Some(ty), true, true) = (ty, a.has(NFTA_EXTHDR_OFFSET), a.has(NFTA_EXTHDR_LEN)) else {
        return Err(Errno::EINVAL);
    };
    let offset = u8_attr(&a, NFTA_EXTHDR_OFFSET)?.unwrap_or(0) as usize;
    let len = u8_attr(&a, NFTA_EXTHDR_LEN)?.unwrap_or(0) as usize;
    if kind == Kind::Set {
        if a.has(NFTA_EXTHDR_FLAGS) {
            return Err(Errno::EINVAL);
        }
        // The kind and the length of the option cannot change, and a write is of 2 or 4 bytes.
        if offset < 2 || !matches!(len, 2 | 4) {
            return Err(Errno::EOPNOTSUPP);
        }
        let reg = nft_parse_register(&a, NFTA_EXTHDR_SREG, len)?;
        return Ok(NftExthdr { kind, op, ty, offset, len, flags: 0, reg });
    }
    let flags = u8_attr(&a, NFTA_EXTHDR_FLAGS)?.unwrap_or(0);
    if flags & !NFT_EXTHDR_F_PRESENT != 0 {
        return Err(Errno::EINVAL);
    }
    let present = flags & NFT_EXTHDR_F_PRESENT != 0;
    if present && len != 1 {
        return Err(Errno::EINVAL);
    }
    let reg = nft_parse_register(&a, NFTA_EXTHDR_DREG, len)?;
    match op {
        NFT_EXTHDR_OP_IPV4 if !matches!(ty, IPOPT_SSRR | IPOPT_LSRR | IPOPT_RR | IPOPT_RA) => {
            return Err(Errno::EOPNOTSUPP);
        }
        // DCCP only tells that an option is there.
        NFT_EXTHDR_OP_DCCP if !present => return Err(Errno::EOPNOTSUPP),
        _ => {}
    }
    Ok(NftExthdr { kind, op, ty, offset, len, flags, reg })
}

impl NftExthdr {
    fn present(&self) -> bool {
        self.flags & NFT_EXTHDR_F_PRESENT != 0
    }

    /// Puts the field at `at` of `d` in the register, or ends the rule if the packet is short,
    /// as `nft_skb_copy_to_reg` of Linux.
    fn copy(&self, regs: &mut NftRegs, d: &[u8], at: usize) {
        match d.get(at..at + self.len) {
            Some(v) => regs.store(self.reg, v),
            None => regs.verdict = NFT_BREAK,
        }
    }
}

/// Runs `exthdr` on the packet `skb`, as the `eval` functions of nft_exthdr.c of Linux.
pub(super) fn nft_exthdr_eval(
    e: &NftExthdr,
    regs: &mut NftRegs,
    skb: &mut NetBuf,
    state: &NfHookState,
    pkt: &NfPktinfo,
) {
    match (e.kind, e.op) {
        (Kind::Set, _) => nft_exthdr_tcp_set_eval(e, regs, skb, pkt),
        (Kind::Strip, _) => nft_exthdr_tcp_strip_eval(e, regs, skb, pkt),
        (_, NFT_EXTHDR_OP_IPV6) => {
            let d = skb.data();
            if state.pf != NFPROTO_IPV6 {
                regs.verdict = NFT_BREAK;
                return;
            }
            let found = ipv6_find_hdr(d, e.ty);
            if e.present() {
                return regs.store(e.reg, &[u8::from(found.is_some())]);
            }
            match found {
                Some(at) => e.copy(regs, d, at + e.offset),
                None => regs.verdict = NFT_BREAK,
            }
        }
        (_, NFT_EXTHDR_OP_IPV4) => {
            let d = skb.data();
            if state.pf != NFPROTO_IPV4 {
                regs.verdict = NFT_BREAK;
                return;
            }
            let found = ipv4_find_option(d, e.ty);
            if e.present() {
                return regs.store(e.reg, &[u8::from(found.is_some())]);
            }
            match found {
                Some(at) => e.copy(regs, d, at + e.offset),
                None => regs.verdict = NFT_BREAK,
            }
        }
        (_, NFT_EXTHDR_OP_TCPOPT) => nft_exthdr_tcp_eval(e, regs, skb.data(), pkt),
        (_, NFT_EXTHDR_OP_SCTP) => nft_exthdr_sctp_eval(e, regs, skb.data(), pkt),
        _ => nft_exthdr_dccp_eval(e, regs, skb.data(), pkt),
    }
}

/// The offset of the header `target` of the IPv6 packet `d`, as `ipv6_find_hdr` of Linux.
/// `None` if the packet does not have it, or if its headers are wrong.
fn ipv6_find_hdr(d: &[u8], target: u8) -> Option<usize> {
    // As `ipv6_ext_hdr` of Linux: hop by hop, routing, fragment, ESP, AH, none, destination
    // options and mobility.
    let ext = |h: u8| matches!(h, 0 | 43 | 44 | 50 | 51 | 59 | 60 | 135);
    let mut next = *d.get(6)?;
    let mut start = 40;
    for cnt in 0.. {
        let found = next == target;
        if !ext(next) || next == 59 {
            return found.then_some(start);
        }
        if cnt >= IP6_MAX_EXT_HDRS_CNT {
            return None;
        }
        let hp = d.get(start..start + 2)?;
        let hdrlen = match next {
            44 => {
                let off = u16::from_be_bytes(d.get(start + 2..start + 4)?.try_into().ok()?);
                // A fragment that is not the first has the fragment header and no other.
                if off & !0x7 != 0 {
                    return found.then_some(start);
                }
                8
            }
            51 => (usize::from(hp[1]) + 2) * 4,
            _ => (usize::from(hp[1]) + 1) * 8,
        };
        if found {
            return Some(start);
        }
        if d.len().saturating_sub(start) < hdrlen {
            return None;
        }
        next = hp[0];
        start += hdrlen;
    }
    None
}

/// The offset of the option `target` of the IPv4 packet `d`, as `ipv4_find_option` and
/// `__ip_options_compile` of Linux. `None` if the packet does not have it, or if its options
/// are wrong.
fn ipv4_find_option(d: &[u8], target: u8) -> Option<usize> {
    let ihl = usize::from(d.first()? & 0xf) * 4;
    let opts = d.get(20..ihl)?;
    let (mut srr, mut strict, mut rr, mut ts, mut ra, mut cipso) = (0, false, 0, 0, 0, 0);
    let mut at = 0;
    while at < opts.len() {
        let o = &opts[at..];
        match o[0] {
            IPOPT_END => break,
            IPOPT_NOOP => {
                at += 1;
                continue;
            }
            _ => {}
        }
        let optlen = usize::from(*o.get(1)?);
        if optlen < 2 || optlen > o.len() {
            return None;
        }
        let o = &o[..optlen];
        let ptr = o.get(2).copied();
        let hdr_at = 20 + at;
        match o[0] {
            IPOPT_SSRR | IPOPT_LSRR => {
                let ptr = ptr?;
                // The checks of a route that does not come from a packet.
                if ptr < 4 || srr != 0 || ptr != 4 || optlen < 7 || (optlen - 3) & 3 != 0 {
                    return None;
                }
                strict = o[0] == IPOPT_SSRR;
                srr = hdr_at;
            }
            IPOPT_RR => {
                let ptr = usize::from(ptr?);
                if rr != 0 || ptr < 4 || (ptr <= optlen && ptr + 3 > optlen) {
                    return None;
                }
                rr = hdr_at;
            }
            IPOPT_TIMESTAMP => {
                if ts != 0 || optlen < 4 {
                    return None;
                }
                let (ptr, fl) = (usize::from(o[2]), o[3]);
                if ptr < 5 {
                    return None;
                }
                if ptr <= optlen {
                    // An address and a time stamp in each slot, or a time stamp.
                    let need = if matches!(fl & 0xf, 1 | IPOPT_TS_PRESPEC) { 7 } else { 3 };
                    if ptr + need > optlen {
                        return None;
                    }
                } else if fl & 0xf != IPOPT_TS_PRESPEC && fl >> 4 == 15 {
                    // The overflow counter is full.
                    return None;
                }
                ts = hdr_at;
            }
            IPOPT_RA => {
                if optlen < 4 {
                    return None;
                }
                if o[2] == 0 && o[3] == 0 {
                    ra = hdr_at;
                }
            }
            IPOPT_CIPSO => {
                if cipso != 0 {
                    return None;
                }
                cipso = hdr_at;
            }
            _ => {}
        }
        at += optlen;
    }
    let found = match target {
        IPOPT_SSRR | IPOPT_LSRR => srr != 0 && strict == (target == IPOPT_SSRR),
        IPOPT_RR => rr != 0,
        _ => ra != 0,
    };
    found.then_some(match target {
        IPOPT_SSRR | IPOPT_LSRR => srr,
        IPOPT_RR => rr,
        _ => ra,
    })
}

/// The length of the TCP option at `i` of `opt`: 1 for an option with no length, as `optlen`
/// of nft_exthdr.c.
fn optlen(opt: &[u8], i: usize) -> usize {
    match opt.get(i + 1) {
        Some(&l) if opt[i] > TCPOPT_NOP && l != 0 => usize::from(l),
        _ => 1,
    }
}

/// The offset and the length of the TCP header of the packet, as `nft_tcp_header_pointer` of
/// Linux. A fragment that is not the first has none.
fn tcp_header(d: &[u8], pkt: &NfPktinfo) -> Option<(usize, usize)> {
    if pkt.l4proto != IPPROTO_TCP {
        return None;
    }
    let t = pkt.thoff?;
    let hl = usize::from(*d.get(t + 12)? >> 4) * 4;
    if hl < 20 || t + hl > d.len() {
        return None;
    }
    Some((t, hl))
}

/// Finds the TCP option `ty` in the header `tcph`: its offset, and its length.
fn tcp_find_option(tcph: &[u8], ty: u8) -> Option<(usize, usize)> {
    let mut i = 20;
    while i + 1 < tcph.len() {
        let optl = optlen(tcph, i);
        if tcph[i] == ty {
            return Some((i, optl));
        }
        i += optl;
    }
    None
}

/// `nft_exthdr_tcp_eval` of Linux.
fn nft_exthdr_tcp_eval(e: &NftExthdr, regs: &mut NftRegs, d: &[u8], pkt: &NfPktinfo) {
    let found = tcp_header(d, pkt).and_then(|(t, hl)| {
        let tcph = &d[t..t + hl];
        let (i, optl) = tcp_find_option(tcph, e.ty)?;
        // An option that is too long for the header, or a field out of the option.
        (i + optl <= hl && e.len + e.offset <= optl).then_some(t + i + e.offset)
    });
    match found {
        Some(_) if e.present() => regs.store(e.reg, &[1]),
        Some(at) => regs.store(e.reg, &d[at..at + e.len]),
        None if e.present() => regs.store(e.reg, &[0]),
        None => regs.verdict = NFT_BREAK,
    }
}

/// Changes the TCP checksum of the header at `t` of `d` after a change of its options, with
/// `fsum` the sum of the header before the change.
fn tcp_csum_update(d: &mut [u8], t: usize, hl: usize, fsum: u32) {
    let tsum = csum_add(0, &d[t..t + hl]);
    let _ = super::nft_exprs::nft_csum_replace(d, t + 16, fsum, tsum);
}

/// `nft_exthdr_tcp_set_eval` of Linux. A larger MSS can stall the connection, and it does not
/// change the option.
fn nft_exthdr_tcp_set_eval(e: &NftExthdr, regs: &mut NftRegs, skb: &mut NetBuf, pkt: &NfPktinfo) {
    let Some((t, hl)) = tcp_header(skb.data(), pkt) else {
        regs.verdict = NFT_BREAK;
        return;
    };
    let d = skb.data_mut();
    let Some((i, optl)) = tcp_find_option(&d[t..t + hl], e.ty) else { return };
    if i + optl > hl || e.len + e.offset > optl {
        regs.verdict = NFT_BREAK;
        return;
    }
    let at = t + i + e.offset;
    let new = &regs.data[e.reg..e.reg + e.len];
    let old = &d[at..at + e.len];
    if old == new || (e.len == 2 && e.ty == TCPOPT_MSS && old <= new) {
        return;
    }
    let fsum = csum_add(0, &d[t..t + hl]);
    d[at..at + e.len].copy_from_slice(new);
    tcp_csum_update(d, t, hl, fsum);
}

/// `nft_exthdr_tcp_strip_eval` of Linux: the option becomes `NOP`s. An option that is not
/// there lets the rule go on, so that a rule can remove more options.
fn nft_exthdr_tcp_strip_eval(e: &NftExthdr, regs: &mut NftRegs, skb: &mut NetBuf, pkt: &NfPktinfo) {
    let Some((t, hl)) = tcp_header(skb.data(), pkt) else {
        regs.verdict = NFT_BREAK;
        return;
    };
    let d = skb.data_mut();
    let Some((i, optl)) = tcp_find_option(&d[t..t + hl], e.ty) else { return };
    if i + optl > hl {
        // It cannot remove the option, and it drops the packet.
        regs.verdict = NF_DROP;
        return;
    }
    let fsum = csum_add(0, &d[t..t + hl]);
    d[t + i..t + i + optl].fill(TCPOPT_NOP);
    tcp_csum_update(d, t, hl, fsum);
}

/// `nft_exthdr_sctp_eval` of Linux.
fn nft_exthdr_sctp_eval(e: &NftExthdr, regs: &mut NftRegs, d: &[u8], pkt: &NfPktinfo) {
    let found = (|| {
        if pkt.l4proto != IPPROTO_SCTP {
            return None;
        }
        let mut at = pkt.thoff? + 12;
        loop {
            let ch = d.get(at..at + 4)?;
            let len = usize::from(u16::from_be_bytes([ch[2], ch[3]]));
            if len == 0 {
                return None;
            }
            if ch[0] == e.ty {
                if e.present() {
                    return Some(None);
                }
                if e.offset + e.len > len || at + len > d.len() {
                    return None;
                }
                return Some(Some(at + e.offset));
            }
            at += len.next_multiple_of(4);
            if at >= d.len() {
                return None;
            }
        }
    })();
    match found {
        Some(None) => regs.store(e.reg, &[1]),
        Some(Some(at)) => e.copy(regs, d, at),
        None if e.present() => regs.store(e.reg, &[0]),
        None => regs.verdict = NFT_BREAK,
    }
}

/// The length of the header of DCCP after the generic header, as `dccp_packet_hdr_len` of
/// Linux.
fn dccp_packet_hdr_len(ty: u8) -> usize {
    match ty {
        // `DCCP_PKT_DATA`.
        2 => 0,
        // `DCCP_PKT_ACK`, `DATAACK`, `CLOSEREQ`, `CLOSE`, `SYNC` and `SYNCACK`: the ack bits.
        3 | 4 | 5 | 6 | 8 | 9 => 8,
        // `DCCP_PKT_REQUEST`: the service code.
        0 => 4,
        // `DCCP_PKT_RESPONSE` and `DCCP_PKT_RESET`.
        _ => 12,
    }
}

/// `nft_exthdr_dccp_eval` of Linux: it tells that the option is there.
fn nft_exthdr_dccp_eval(e: &NftExthdr, regs: &mut NftRegs, d: &[u8], pkt: &NfPktinfo) {
    let found = (|| {
        if pkt.l4proto != IPPROTO_DCCP {
            return None;
        }
        let t = pkt.thoff?;
        let dh = d.get(t..t + 12)?;
        let dataoff = usize::from(dh[4]) * 4;
        // The type and the extended sequence numbers, as `__dccp_hdr_len`.
        let (ty, x) = ((dh[8] >> 1) & 0xf, dh[8] & 1 != 0);
        let optoff = 12 + if x { 4 } else { 0 } + dccp_packet_hdr_len(ty);
        if dataoff <= optoff {
            return None;
        }
        let opts = d.get(t + optoff..t + dataoff)?;
        let mut i = 0;
        while i < opts.len() {
            let ty = opts[i];
            if ty == e.ty {
                return Some(());
            }
            if ty <= DCCPO_MAX_RESERVED {
                i += 1;
                continue;
            }
            let len = usize::from(*opts.get(i + 1)?);
            if len < 2 {
                return None;
            }
            i += len;
        }
        None
    })();
    regs.store(e.reg, &[u8::from(found.is_some())]);
}

#[cfg(test)]
mod tests {
    use super::super::{NFT_CONTINUE, NFT_REG_SIZE, NFT_REGS_LEN};
    use super::*;
    use crate::netfilter::{NF_INET_FORWARD, NFPROTO_INET, nf_pktinfo};
    use crate::netlink::msg::{Builder, HDRLEN};
    use alloc::vec;
    use alloc::vec::Vec;

    /// An `exthdr` with the operation `op` and the attributes of `attrs`.
    fn exthdr(family: u8, op: Option<u32>, attrs: &[(u32, &[u8])]) -> Result<NftExthdr> {
        let mut b = Builder::new(0, 0, 0, 0);
        if let Some(op) = op {
            b.put(NFTA_EXTHDR_OP as u16, &op.to_be_bytes());
        }
        for (ty, v) in attrs {
            b.put(*ty as u16, v);
        }
        nft_exthdr_init(family, &b.finish()[HDRLEN..])
    }

    fn get(op: u32, ty: u8, offset: u32, len: u32, flags: u32) -> NftExthdr {
        let reg = 1u32.to_be_bytes();
        let (o, l, f) = (offset.to_be_bytes(), len.to_be_bytes(), flags.to_be_bytes());
        let attrs: [(u32, &[u8]); 5] = [
            (NFTA_EXTHDR_DREG, &reg),
            (NFTA_EXTHDR_TYPE, &[ty]),
            (NFTA_EXTHDR_OFFSET, &o),
            (NFTA_EXTHDR_LEN, &l),
            (NFTA_EXTHDR_FLAGS, &f),
        ];
        exthdr(NFPROTO_IPV4, Some(op), &attrs).unwrap()
    }

    fn regs() -> NftRegs {
        let mut r = NftRegs { verdict: NFT_CONTINUE, chain: 0, data: [0; NFT_REGS_LEN] };
        r.data[NFT_REG_SIZE..2 * NFT_REG_SIZE].fill(0xaa);
        r
    }

    fn run(e: &NftExthdr, pf: u8, p: &[u8]) -> (u32, [u8; 4], Vec<u8>) {
        let st = NfHookState { hook: NF_INET_FORWARD, pf, in_dev: 1, out_dev: 2 };
        let mut skb = NetBuf::from_slice(p);
        let pkt = nf_pktinfo(pf, skb.data());
        let mut r = regs();
        r.data[2 * NFT_REG_SIZE..2 * NFT_REG_SIZE + 4].copy_from_slice(&[0x05, 0x50, 0, 0]);
        nft_exthdr_eval(e, &mut r, &mut skb, &st, &pkt);
        let v = r.data[NFT_REG_SIZE..NFT_REG_SIZE + 4].try_into().unwrap();
        (r.verdict, v, skb.data().to_vec())
    }

    /// A TCP SYN over IPv4 with the options MSS 1460, SACK permitted and window scale 7, and
    /// a right checksum.
    fn tcp_syn() -> Vec<u8> {
        let mut p = vec![0u8; 20 + 32];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&52u16.to_be_bytes());
        p[8] = 64;
        p[9] = IPPROTO_TCP;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let t = &mut p[20..];
        t[12] = 8 << 4;
        t[13] = 0x02;
        t[20..32].copy_from_slice(&[2, 4, 0x05, 0xb4, 4, 2, 1, 3, 3, 7, 1, 1]);
        tcp_csum(&mut p);
        p
    }

    /// Puts the TCP checksum with the pseudo header in the IPv4 packet `p`.
    fn tcp_csum(p: &mut [u8]) {
        p[36..38].fill(0);
        let len = (p.len() - 20) as u16;
        let mut s = csum_add(0, &p[12..20]);
        s = csum_add(s, &[0, IPPROTO_TCP]);
        s = csum_add(s, &len.to_be_bytes());
        s = csum_add(s, &p[20..]);
        let c = crate::netfilter::nf_nat::csum_fold(s);
        p[36..38].copy_from_slice(&c.to_be_bytes());
    }

    #[test]
    fn exthdr_takes_the_attributes_of_linux() {
        let reg = 1u32.to_be_bytes();
        let one = 1u32.to_be_bytes();
        let two = 2u32.to_be_bytes();
        let big = 256u32.to_be_bytes();
        let ipv6 = |attrs: &[(u32, &[u8])]| exthdr(NFPROTO_IPV6, None, attrs);
        let base: [(u32, &[u8]); 4] = [
            (NFTA_EXTHDR_DREG, &reg),
            (NFTA_EXTHDR_TYPE, &[44]),
            (NFTA_EXTHDR_OFFSET, &two),
            (NFTA_EXTHDR_LEN, &two),
        ];
        // `frag frag-off`: IPv6 with no operation.
        let e = ipv6(&base).unwrap();
        assert_eq!((e.op, e.kind, e.reg, e.offset, e.len), (0, Kind::Get, NFT_REG_SIZE, 2, 2));
        assert_eq!(ipv6(&base[..3]).unwrap_err(), Errno::EINVAL);
        let mut long = base;
        long[3] = (NFTA_EXTHDR_LEN, &big);
        assert_eq!(ipv6(&long).unwrap_err(), Errno::ERANGE);
        // `exists` has 1 byte.
        let mut p = base.to_vec();
        p.push((NFTA_EXTHDR_FLAGS, &one));
        assert_eq!(ipv6(&p).unwrap_err(), Errno::EINVAL);
        p[3] = (NFTA_EXTHDR_LEN, &one);
        assert!(ipv6(&p).unwrap().present());
        p[4] = (NFTA_EXTHDR_FLAGS, &two);
        assert_eq!(ipv6(&p).unwrap_err(), Errno::EINVAL);
        // The options of IPv4: not in a table of IPv6, and only the routes and `ra`.
        let ipv4 = |family, ty: u8| {
            let attrs: [(u32, &[u8]); 4] = [
                (NFTA_EXTHDR_DREG, &reg),
                (NFTA_EXTHDR_TYPE, &[ty]),
                (NFTA_EXTHDR_OFFSET, &two),
                (NFTA_EXTHDR_LEN, &two),
            ];
            exthdr(family, Some(NFT_EXTHDR_OP_IPV4), &attrs)
        };
        assert!(ipv4(NFPROTO_IPV4, IPOPT_RA).is_ok());
        assert_eq!(ipv4(NFPROTO_IPV6, IPOPT_RA).unwrap_err(), Errno::EOPNOTSUPP);
        assert_eq!(ipv4(NFPROTO_IPV4, IPOPT_TIMESTAMP).unwrap_err(), Errno::EOPNOTSUPP);
        // `tcp option maxseg size set`: 2 or 4 bytes, after the kind and the length.
        let set = |offset: u32, len: u32, extra: Option<(u32, &[u8])>| {
            let (o, l) = (offset.to_be_bytes(), len.to_be_bytes());
            let mut attrs: Vec<(u32, &[u8])> = vec![
                (NFTA_EXTHDR_SREG, &reg),
                (NFTA_EXTHDR_TYPE, &[TCPOPT_MSS]),
                (NFTA_EXTHDR_OFFSET, &o),
                (NFTA_EXTHDR_LEN, &l),
            ];
            attrs.extend(extra);
            exthdr(NFPROTO_INET, Some(NFT_EXTHDR_OP_TCPOPT), &attrs).map(|e| e.kind)
        };
        assert_eq!(set(2, 2, None), Ok(Kind::Set));
        assert_eq!(set(1, 2, None), Err(Errno::EOPNOTSUPP));
        assert_eq!(set(2, 3, None), Err(Errno::EOPNOTSUPP));
        assert_eq!(set(2, 2, Some((NFTA_EXTHDR_FLAGS, &one))), Err(Errno::EINVAL));
        assert_eq!(set(2, 2, Some((NFTA_EXTHDR_DREG, &reg))), Err(Errno::EOPNOTSUPP));
        // `reset tcp option sack-perm` has only the type.
        let strip = |attrs: &[(u32, &[u8])]| {
            exthdr(NFPROTO_INET, Some(NFT_EXTHDR_OP_TCPOPT), attrs).map(|e| e.kind)
        };
        assert_eq!(strip(&[(NFTA_EXTHDR_TYPE, &[4])]), Ok(Kind::Strip));
        assert_eq!(strip(&[]), Err(Errno::EINVAL));
        assert_eq!(strip(&[(NFTA_EXTHDR_TYPE, &[4]), (NFTA_EXTHDR_LEN, &one)]), Err(Errno::EINVAL));
        // The operations that need a destination register, and the ones that Linux does not
        // have.
        assert_eq!(
            exthdr(NFPROTO_INET, Some(NFT_EXTHDR_OP_SCTP), &[(NFTA_EXTHDR_TYPE, &[1])])
                .unwrap_err(),
            Errno::EOPNOTSUPP
        );
        assert_eq!(exthdr(NFPROTO_INET, Some(5), &base).unwrap_err(), Errno::EOPNOTSUPP);
        let dccp = |flags: u32| {
            let f = flags.to_be_bytes();
            let mut attrs = base.to_vec();
            attrs[3] = (NFTA_EXTHDR_LEN, &one);
            attrs.push((NFTA_EXTHDR_FLAGS, &f));
            exthdr(NFPROTO_INET, Some(NFT_EXTHDR_OP_DCCP), &attrs).map(|e| e.kind)
        };
        assert_eq!(dccp(1), Ok(Kind::Get));
        assert_eq!(dccp(0), Err(Errno::EOPNOTSUPP));
    }

    #[test]
    fn exthdr_reads_and_writes_the_tcp_options() {
        let p = tcp_syn();
        // `tcp option maxseg size`.
        let e = get(NFT_EXTHDR_OP_TCPOPT, TCPOPT_MSS, 2, 2, 0);
        assert_eq!(run(&e, NFPROTO_IPV4, &p).0, NFT_CONTINUE);
        assert_eq!(run(&e, NFPROTO_IPV4, &p).1, [0x05, 0xb4, 0, 0]);
        // `tcp option window exists`, and an option that is not there.
        let e = get(NFT_EXTHDR_OP_TCPOPT, 3, 0, 1, NFT_EXTHDR_F_PRESENT);
        assert_eq!(run(&e, NFPROTO_IPV4, &p).1, [1, 0, 0, 0]);
        let e = get(NFT_EXTHDR_OP_TCPOPT, 8, 0, 1, NFT_EXTHDR_F_PRESENT);
        assert_eq!(run(&e, NFPROTO_IPV4, &p).1, [0, 0, 0, 0]);
        let e = get(NFT_EXTHDR_OP_TCPOPT, 8, 2, 4, 0);
        assert_eq!(run(&e, NFPROTO_IPV4, &p).0, NFT_BREAK);
        // A field after the end of the option ends the rule.
        let e = get(NFT_EXTHDR_OP_TCPOPT, TCPOPT_MSS, 2, 4, 0);
        assert_eq!(run(&e, NFPROTO_IPV4, &p).0, NFT_BREAK);

        // `tcp option maxseg size set 1360`: the register has 0x0550 in the byte order of the
        // network, and the checksum stays right.
        let set = NftExthdr {
            kind: Kind::Set,
            op: NFT_EXTHDR_OP_TCPOPT,
            ty: TCPOPT_MSS,
            offset: 2,
            len: 2,
            flags: 0,
            reg: 2 * NFT_REG_SIZE,
        };
        let (v, _, out) = run(&set, NFPROTO_IPV4, &p);
        assert_eq!((v, &out[42..44]), (NFT_CONTINUE, &[0x05, 0x50][..]));
        let mut want = out.clone();
        tcp_csum(&mut want);
        assert_eq!(out, want);
        // It does not make the MSS larger.
        let mut small = p.clone();
        small[42..44].copy_from_slice(&[0x02, 0x00]);
        tcp_csum(&mut small);
        assert_eq!(run(&set, NFPROTO_IPV4, &small).2, small);

        // `reset tcp option sack-perm`: the option becomes 2 `NOP`s.
        let strip = NftExthdr { kind: Kind::Strip, ty: 4, offset: 0, len: 0, reg: 0, ..set };
        let (v, _, out) = run(&strip, NFPROTO_IPV4, &p);
        assert_eq!((v, &out[44..46]), (NFT_CONTINUE, &[1, 1][..]));
        let mut want = out.clone();
        tcp_csum(&mut want);
        assert_eq!(out, want);
        // A UDP packet has no TCP options.
        let mut udp = p.clone();
        udp[9] = 17;
        assert_eq!(run(&strip, NFPROTO_IPV4, &udp).0, NFT_BREAK);
    }

    #[test]
    fn exthdr_finds_the_headers_of_ipv6_and_the_options_of_ipv4() {
        // IPv6 with a hop by hop header of 8 bytes, then a fragment header, then UDP.
        let mut p = vec![0u8; 40 + 8 + 8 + 8];
        p[0] = 0x60;
        p[6] = 0;
        p[40] = 44;
        p[48] = 17;
        p[50..52].copy_from_slice(&0x0009u16.to_be_bytes());
        p[52..56].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        // `frag id`: 4 bytes at 4 of the fragment header.
        let e = get(NFT_EXTHDR_OP_IPV6, 44, 4, 4, 0);
        assert_eq!(run(&e, NFPROTO_IPV6, &p).1, [0x12, 0x34, 0x56, 0x78]);
        // `exthdr hbh exists` and `exthdr rt exists`.
        let e = get(NFT_EXTHDR_OP_IPV6, 0, 0, 1, NFT_EXTHDR_F_PRESENT);
        assert_eq!(run(&e, NFPROTO_IPV6, &p).1, [1, 0, 0, 0]);
        let e = get(NFT_EXTHDR_OP_IPV6, 43, 0, 1, NFT_EXTHDR_F_PRESENT);
        assert_eq!(run(&e, NFPROTO_IPV6, &p).1, [0, 0, 0, 0]);
        let e = get(NFT_EXTHDR_OP_IPV6, 43, 2, 1, 0);
        assert_eq!(run(&e, NFPROTO_IPV6, &p).0, NFT_BREAK);
        // In an IPv4 packet, an IPv6 header is not there and ends the rule.
        let e = get(NFT_EXTHDR_OP_IPV6, 0, 0, 1, NFT_EXTHDR_F_PRESENT);
        assert_eq!(run(&e, NFPROTO_IPV4, &tcp_syn()).0, NFT_BREAK);

        // IPv4 with a NOP and the router alert option.
        let mut p = tcp_syn();
        p.splice(20..20, [IPOPT_NOOP, IPOPT_RA, 4, 0, 0, IPOPT_END, 0, 0]);
        p[0] = 0x47;
        // `ip option ra value`: 2 bytes at 2 of the option.
        let e = get(NFT_EXTHDR_OP_IPV4, IPOPT_RA, 2, 2, 0);
        assert_eq!(run(&e, NFPROTO_IPV4, &p).0, NFT_CONTINUE);
        assert_eq!(ipv4_find_option(&p, IPOPT_RA), Some(21));
        let e = get(NFT_EXTHDR_OP_IPV4, IPOPT_RR, 0, 1, NFT_EXTHDR_F_PRESENT);
        assert_eq!(run(&e, NFPROTO_IPV4, &p).1, [0, 0, 0, 0]);
        // An option longer than the header makes all the options wrong.
        p[22] = 40;
        assert_eq!(ipv4_find_option(&p, IPOPT_RA), None);
    }

    #[test]
    fn exthdr_finds_the_chunks_of_sctp() {
        // IPv4, the common header of SCTP, then an INIT chunk of 20 bytes.
        let mut p = vec![0u8; 20 + 12 + 20];
        p[0] = 0x45;
        p[9] = IPPROTO_SCTP;
        p[32] = 1;
        p[34..36].copy_from_slice(&20u16.to_be_bytes());
        p[36..40].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        // `sctp chunk init init-tag`.
        let e = get(NFT_EXTHDR_OP_SCTP, 1, 4, 4, 0);
        assert_eq!(run(&e, NFPROTO_IPV4, &p).1, [0xde, 0xad, 0xbe, 0xef]);
        let e = get(NFT_EXTHDR_OP_SCTP, 0, 0, 1, NFT_EXTHDR_F_PRESENT);
        assert_eq!(run(&e, NFPROTO_IPV4, &p).1, [0, 0, 0, 0]);
        let e = get(NFT_EXTHDR_OP_SCTP, 1, 0, 1, NFT_EXTHDR_F_PRESENT);
        assert_eq!(run(&e, NFPROTO_IPV4, &p).1, [1, 0, 0, 0]);
        let e = get(NFT_EXTHDR_OP_SCTP, 0, 4, 4, 0);
        assert_eq!(run(&e, NFPROTO_IPV4, &p).0, NFT_BREAK);
    }
}

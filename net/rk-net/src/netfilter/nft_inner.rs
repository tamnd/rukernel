//! The expression `inner` of nf_tables, as nft_inner.c of Linux: a `payload` or a `meta` of the
//! packet in a tunnel, for example `vxlan ip saddr`, `geneve tcp dport` or `gre ip daddr`.

use super::{
    ETH_P_IP, ETH_P_IPV6, NFT_BREAK, NFT_META_L4PROTO, NFT_META_PROTOCOL, NFT_PAYLOAD_LL_HEADER,
    NFT_PAYLOAD_NETWORK_HEADER, NFT_PAYLOAD_TRANSPORT_HEADER, NFTA_EXPR_DATA, NFTA_EXPR_MAX,
    NFTA_EXPR_NAME, NFTA_META_DREG, NFTA_META_KEY, NFTA_PAYLOAD_BASE, NFTA_PAYLOAD_DREG,
    NFTA_PAYLOAD_LEN, NFTA_PAYLOAD_OFFSET, NftRegs, be32, nft_expr_type_known, nft_parse_register,
};
use crate::netfilter::{NFPROTO_IPV4, NFPROTO_IPV6, NfPktinfo, nf_pktinfo};
use crate::netlink::msg::Attrs;
use rk_abi::Errno;
use rk_vfs::inode::Result;

// `NFTA_INNER_*`.
const NFTA_INNER_NUM: u32 = 1;
const NFTA_INNER_TYPE: u32 = 2;
const NFTA_INNER_FLAGS: u32 = 3;
const NFTA_INNER_HDRSIZE: u32 = 4;
const NFTA_INNER_EXPR: u32 = 5;
const NFTA_INNER_MAX: u16 = 5;
/// `NFT_INNER_GENEVE` of `enum nft_inner_type`.
const NFT_INNER_GENEVE: u32 = 2;
// `enum nft_inner_flags`.
const NFT_INNER_HDRSIZE: u32 = 1 << 0;
const NFT_INNER_LL: u32 = 1 << 1;
const NFT_INNER_NH: u32 = 1 << 2;
const NFT_INNER_TH: u32 = 1 << 3;
const NFT_INNER_MASK: u32 = NFT_INNER_HDRSIZE | NFT_INNER_LL | NFT_INNER_NH | NFT_INNER_TH;
/// `NFT_PAYLOAD_TUN_HEADER`: the header of the tunnel.
const NFT_PAYLOAD_TUN_HEADER: u32 = 4;
const IPPROTO_IPIP: u8 = 4;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_GRE: u8 = 47;
const ETH_P_8021Q: u16 = 0x8100;
// The bits of the flags of GRE, `GRE_*` of net/gre.h.
const GRE_CSUM: u16 = 0x8000;
const GRE_ROUTING: u16 = 0x4000;
const GRE_KEY: u16 = 0x2000;
const GRE_SEQ: u16 = 0x1000;
const GRE_VERSION: u16 = 0x0007;

/// The expression in the tunnel, as `NFT_INNER_EXPR_PAYLOAD` and `NFT_INNER_EXPR_META`.
#[derive(Clone, Debug)]
enum NftInnerExpr {
    Payload { base: u32, offset: usize, len: usize, dreg: usize },
    Meta { key: u32, dreg: usize },
}

/// `inner`, as `struct nft_inner` of Linux.
#[derive(Clone, Debug)]
pub(crate) struct NftInner {
    flags: u32,
    hdrsize: usize,
    ty: u32,
    expr: NftInnerExpr,
}

/// Reads an `inner` expression, as `nft_inner_init` of Linux.
pub(super) fn nft_inner_init(data: &[u8]) -> Result<NftInner> {
    let a = Attrs::parse(data, NFTA_INNER_MAX);
    let (Some(flags), Some(num), Some(hdrsize), Some(ty), Some(e)) = (
        be32(&a, NFTA_INNER_FLAGS)?,
        be32(&a, NFTA_INNER_NUM)?,
        be32(&a, NFTA_INNER_HDRSIZE)?,
        be32(&a, NFTA_INNER_TYPE)?,
        a.get(NFTA_INNER_EXPR),
    ) else {
        return Err(Errno::EINVAL);
    };
    // `NLA_POLICY_MASK` of the policy.
    if flags & !NFT_INNER_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    if num != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if ty > u32::from(u8::MAX) {
        return Err(Errno::EINVAL);
    }
    if flags & NFT_INNER_HDRSIZE != 0 && (hdrsize == 0 || hdrsize > 64) {
        return Err(Errno::EOPNOTSUPP);
    }
    let expr = nft_inner_expr_init(e)?;
    Ok(NftInner { flags, hdrsize: hdrsize as usize, ty, expr })
}

/// Reads the expression in the tunnel, as `nft_expr_inner_parse` of Linux and the `init` of
/// `inner_ops` of `payload` and `meta`. An expression of another type gives `EOPNOTSUPP`, and
/// one that the kernel does not have gives `ENOENT`.
fn nft_inner_expr_init(nla: &[u8]) -> Result<NftInnerExpr> {
    let tb = Attrs::parse(nla, NFTA_EXPR_MAX);
    let (Some(name), Some(data)) = (tb.str(NFTA_EXPR_NAME), tb.get(NFTA_EXPR_DATA)) else {
        return Err(Errno::EINVAL);
    };
    match name {
        // As `nft_payload_inner_init`.
        b"payload" => {
            let a = Attrs::parse(data, 8);
            let (Some(base), Some(offset), Some(len)) = (
                be32(&a, NFTA_PAYLOAD_BASE)?,
                be32(&a, NFTA_PAYLOAD_OFFSET)?,
                be32(&a, NFTA_PAYLOAD_LEN)?,
            ) else {
                return Err(Errno::EINVAL);
            };
            if !a.has(NFTA_PAYLOAD_DREG) {
                return Err(Errno::EINVAL);
            }
            if !matches!(
                base,
                NFT_PAYLOAD_TUN_HEADER
                    | NFT_PAYLOAD_LL_HEADER
                    | NFT_PAYLOAD_NETWORK_HEADER
                    | NFT_PAYLOAD_TRANSPORT_HEADER
            ) {
                return Err(Errno::EOPNOTSUPP);
            }
            // `nft_parse_u32_check` with `U16_MAX`.
            if offset > u32::from(u16::MAX) {
                return Err(Errno::ERANGE);
            }
            let len = len as usize;
            let dreg = nft_parse_register(&a, NFTA_PAYLOAD_DREG, len)?;
            Ok(NftInnerExpr::Payload { base, offset: offset as usize, len, dreg })
        }
        // As `nft_meta_inner_init`.
        b"meta" => {
            let a = Attrs::parse(data, 3);
            let Some(key) = be32(&a, NFTA_META_KEY)? else { return Err(Errno::EINVAL) };
            if !a.has(NFTA_META_DREG) {
                return Err(Errno::EINVAL);
            }
            let len = match key {
                NFT_META_PROTOCOL => 2,
                NFT_META_L4PROTO => 4,
                _ => return Err(Errno::EOPNOTSUPP),
            };
            let dreg = nft_parse_register(&a, NFTA_META_DREG, len)?;
            Ok(NftInnerExpr::Meta { key, dreg })
        }
        n if nft_expr_type_known(n) => Err(Errno::EOPNOTSUPP),
        _ => Err(Errno::ENOENT),
    }
}

/// The headers of the packet in the tunnel, as `struct nft_inner_tun_ctx` of Linux: the
/// offsets of the headers that the packet has.
#[derive(Default, Debug, PartialEq)]
struct NftInnerTunCtx {
    tunoff: Option<usize>,
    lloff: Option<usize>,
    nhoff: Option<usize>,
    thoff: Option<usize>,
    llproto: u16,
    l4proto: u8,
}

/// The offset of the data after the transport header of the packet `d`, as
/// `__nft_payload_inner_offset` of Linux: after UDP, TCP or GRE, or the header of IP in IP.
fn nft_inner_offset(d: &[u8], pkt: &NfPktinfo) -> Option<usize> {
    let thoff = pkt.thoff?;
    match pkt.l4proto {
        IPPROTO_UDP => Some(thoff + 8),
        IPPROTO_TCP => Some(thoff + usize::from(d.get(thoff + 12)? >> 4) * 4),
        IPPROTO_GRE => {
            let h = d.get(thoff..thoff + 4)?;
            let flags = u16::from_be_bytes([h[0], h[1]]);
            // Only the version 0 of GRE, with no routing.
            if flags & GRE_VERSION != 0 || flags & GRE_ROUTING != 0 {
                return None;
            }
            let mut off = 4;
            for (bit, len) in [(GRE_CSUM, 4), (GRE_KEY, 4), (GRE_SEQ, 4)] {
                if flags & bit != 0 {
                    off += len;
                }
            }
            Some(thoff + off)
        }
        IPPROTO_IPIP => Some(thoff),
        _ => None,
    }
}

/// Finds the headers of the packet in the tunnel of `d`, as `nft_inner_parse` of Linux.
/// `inneroff` is the offset of the data after the transport header of `d`.
fn nft_inner_parse(
    i: &NftInner,
    d: &[u8],
    pkt: &NfPktinfo,
    inneroff: usize,
) -> Option<NftInnerTunCtx> {
    let mut ctx = NftInnerTunCtx::default();
    let mut off = inneroff;
    // As `nft_inner_parse_tunhdr`.
    if i.flags & NFT_INNER_HDRSIZE != 0 {
        match pkt.l4proto {
            IPPROTO_GRE => ctx.tunoff = pkt.thoff,
            IPPROTO_UDP => {
                ctx.tunoff = Some(off);
                off += i.hdrsize;
                if i.ty == NFT_INNER_GENEVE {
                    // The length of the options of GENEVE, in words of 4 bytes.
                    off += usize::from(d.get(inneroff)? & 0x3f) * 4;
                }
            }
            _ => return None,
        }
    }
    if i.flags & (NFT_INNER_LL | NFT_INNER_NH) != 0 {
        nft_inner_parse_l2l3(i, d, &mut ctx, off)?;
    } else if i.flags & NFT_INNER_TH != 0 {
        ctx.thoff = Some(off);
    }
    Some(ctx)
}

/// Finds the link layer, network and transport headers of the packet in the tunnel, at `off`
/// of `d`, as `nft_inner_parse_l2l3` of Linux.
fn nft_inner_parse_l2l3(
    i: &NftInner,
    d: &[u8],
    ctx: &mut NftInnerTunCtx,
    mut off: usize,
) -> Option<()> {
    let be16 = |at: usize| d.get(at..at + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    let llproto = if i.flags & NFT_INNER_LL != 0 {
        // An Ethernet header, maybe with a VLAN tag.
        let (llproto, proto, hdrsize) = match be16(off + 12)? {
            p @ (ETH_P_IP | ETH_P_IPV6) => (p, p, 14),
            ETH_P_8021Q => (ETH_P_8021Q, be16(off + 16)?, 18),
            _ => return None,
        };
        ctx.lloff = Some(off);
        ctx.llproto = llproto;
        off += hdrsize;
        proto
    } else {
        let p = match d.get(off)? >> 4 {
            4 => ETH_P_IP,
            6 => ETH_P_IPV6,
            _ => return None,
        };
        ctx.llproto = p;
        p
    };
    let h = d.get(off..)?;
    let pf = match llproto {
        ETH_P_IP => {
            if h.len() < 20 || h[0] >> 4 != 4 || h[0] & 0xf < 5 {
                return None;
            }
            NFPROTO_IPV4
        }
        ETH_P_IPV6 => {
            if h.len() < 40 || h[0] >> 4 != 6 {
                return None;
            }
            NFPROTO_IPV6
        }
        _ => return None,
    };
    ctx.nhoff = Some(off);
    let p = nf_pktinfo(pf, h);
    // A header of IPv6 that ends before the transport header gives no headers at all, as
    // `ipv6_find_hdr` of Linux; a fragment that is not the first has no transport header.
    if pf == NFPROTO_IPV6 && p.thoff.is_none() && p.l4proto == 0 {
        return None;
    }
    if let Some(t) = p.thoff {
        ctx.thoff = Some(off + t);
        ctx.l4proto = p.l4proto;
    }
    Some(())
}

/// Runs `inner` on the packet `d`, as `nft_inner_eval` of Linux: the `payload` or the `meta`
/// of the packet in the tunnel. A packet with no tunnel, or with no header that the expression
/// needs, ends the rule.
///
/// Linux keeps the headers that it found for the packet in a variable of the CPU, so that the
/// next `inner` of the rule does not look for them again. Here each `inner` looks for them:
/// the result is the same.
pub(super) fn nft_inner_eval(i: &NftInner, regs: &mut NftRegs, d: &[u8], pkt: &NfPktinfo) {
    let ctx = nft_inner_offset(d, pkt).and_then(|off| nft_inner_parse(i, d, pkt, off));
    let ok = ctx.is_some_and(|ctx| match i.expr {
        // As `nft_payload_inner_eval`.
        NftInnerExpr::Payload { base, offset, len, dreg } => {
            let start = match base {
                NFT_PAYLOAD_TUN_HEADER => ctx.tunoff,
                NFT_PAYLOAD_LL_HEADER => ctx.lloff,
                NFT_PAYLOAD_NETWORK_HEADER => ctx.nhoff,
                _ => ctx.thoff,
            };
            match start.and_then(|s| d.get(s + offset..s + offset + len)) {
                Some(v) => {
                    regs.store(dreg, v);
                    true
                }
                None => false,
            }
        }
        // As `nft_meta_inner_eval`.
        NftInnerExpr::Meta { key: NFT_META_PROTOCOL, dreg } => {
            regs.store(dreg, &ctx.llproto.to_be_bytes());
            true
        }
        NftInnerExpr::Meta { dreg, .. } => {
            if ctx.thoff.is_none() {
                return false;
            }
            regs.store(dreg, &[ctx.l4proto]);
            true
        }
    });
    if !ok {
        regs.verdict = NFT_BREAK;
    }
}

#[cfg(test)]
mod tests {
    use super::super::{NFT_CONTINUE, NFT_REGS_LEN};
    use super::*;
    use crate::netlink::msg::{Builder, HDRLEN};
    use alloc::vec;
    use alloc::vec::Vec;

    /// The attributes of `inner` with the expression `name` of the attributes `data`.
    fn inner(flags: u32, num: u32, hdrsize: u32, name: &[u8], data: &[(u32, u32)]) -> Vec<u8> {
        let mut b = Builder::new(0, 0, 0, 0);
        b.put(NFTA_INNER_NUM as u16, &num.to_be_bytes())
            .put(NFTA_INNER_TYPE as u16, &1u32.to_be_bytes())
            .put(NFTA_INNER_FLAGS as u16, &flags.to_be_bytes())
            .put(NFTA_INNER_HDRSIZE as u16, &hdrsize.to_be_bytes());
        let e = b.nest(NFTA_INNER_EXPR as u16);
        let mut n = name.to_vec();
        n.push(0);
        b.put(NFTA_EXPR_NAME as u16, &n);
        let d = b.nest(NFTA_EXPR_DATA as u16);
        for (ty, v) in data {
            b.put(*ty as u16, &v.to_be_bytes());
        }
        b.end_nest(d);
        b.end_nest(e);
        b.finish()[HDRLEN..].to_vec()
    }

    /// `vxlan ip saddr`, as nft gives it: the source address of the IPv4 header in the tunnel.
    fn vxlan_payload(base: u32, offset: u32, len: u32) -> Vec<u8> {
        let p = [
            (NFTA_PAYLOAD_DREG, 1),
            (NFTA_PAYLOAD_BASE, base),
            (NFTA_PAYLOAD_OFFSET, offset),
            (NFTA_PAYLOAD_LEN, len),
        ];
        inner(NFT_INNER_HDRSIZE | NFT_INNER_LL | NFT_INNER_NH | NFT_INNER_TH, 0, 8, b"payload", &p)
    }

    /// An IPv4 UDP packet to the port of VXLAN, with an Ethernet frame of an IPv4 TCP packet.
    fn vxlan_packet() -> Vec<u8> {
        let mut p = vec![0u8; 20 + 8 + 8 + 14 + 20 + 20];
        p[0] = 0x45;
        p[9] = IPPROTO_UDP;
        p[22..24].copy_from_slice(&4789u16.to_be_bytes());
        p[28] = 0x08;
        p[36 + 12..36 + 14].copy_from_slice(&ETH_P_IP.to_be_bytes());
        let ip = 36 + 14;
        p[ip] = 0x45;
        p[ip + 9] = IPPROTO_TCP;
        p[ip + 12..ip + 16].copy_from_slice(&[1, 1, 1, 1]);
        p[ip + 16..ip + 20].copy_from_slice(&[2, 2, 2, 2]);
        p[ip + 20 + 2..ip + 20 + 4].copy_from_slice(&22u16.to_be_bytes());
        p
    }

    fn eval(i: &NftInner, p: &[u8]) -> NftRegs {
        let mut regs = NftRegs { verdict: NFT_CONTINUE, chain: 0, data: [0; NFT_REGS_LEN] };
        nft_inner_eval(i, &mut regs, p, &nf_pktinfo(NFPROTO_IPV4, p));
        regs
    }

    #[test]
    fn the_attributes_of_inner_are_checked_as_on_linux() {
        let ok = vxlan_payload(NFT_PAYLOAD_NETWORK_HEADER, 12, 4);
        assert!(nft_inner_init(&ok).is_ok());
        let p = [(NFTA_PAYLOAD_DREG, 1), (NFTA_PAYLOAD_BASE, 1), (NFTA_PAYLOAD_OFFSET, 12)];
        let short = [(NFTA_PAYLOAD_LEN, 4)];
        let e = |d: &[u8]| nft_inner_init(d).unwrap_err();
        let all = [p.as_slice(), short.as_slice()].concat();
        assert_eq!(e(&inner(1 << 4, 0, 8, b"payload", &all)), Errno::EINVAL);
        assert_eq!(e(&inner(NFT_INNER_HDRSIZE, 1, 8, b"payload", &all)), Errno::EOPNOTSUPP);
        assert_eq!(e(&inner(NFT_INNER_HDRSIZE, 0, 65, b"payload", &all)), Errno::EOPNOTSUPP);
        assert_eq!(e(&inner(NFT_INNER_HDRSIZE, 0, 8, b"payload", &p)), Errno::EINVAL);
        assert_eq!(e(&vxlan_payload(3, 0, 4)), Errno::EOPNOTSUPP);
        assert_eq!(e(&vxlan_payload(1, 1 << 16, 4)), Errno::ERANGE);
        // Only `payload` and `meta` go in a tunnel.
        assert_eq!(e(&inner(0, 0, 0, b"counter", &[])), Errno::EOPNOTSUPP);
        assert_eq!(e(&inner(0, 0, 0, b"nosuch", &[])), Errno::ENOENT);
        let mark = [(NFTA_META_DREG, 1), (NFTA_META_KEY, 3)];
        assert_eq!(e(&inner(0, 0, 0, b"meta", &mark)), Errno::EOPNOTSUPP);
    }

    #[test]
    fn inner_reads_the_headers_of_the_packet_in_a_vxlan_tunnel() {
        let p = vxlan_packet();
        let saddr = nft_inner_init(&vxlan_payload(NFT_PAYLOAD_NETWORK_HEADER, 12, 4)).unwrap();
        let regs = eval(&saddr, &p);
        assert_eq!((regs.verdict, &regs.data[16..20]), (NFT_CONTINUE, &[1, 1, 1, 1][..]));
        let dport = nft_inner_init(&vxlan_payload(NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2)).unwrap();
        assert_eq!(&eval(&dport, &p).data[16..18], &22u16.to_be_bytes());
        let flags = NFT_INNER_HDRSIZE | NFT_INNER_LL | NFT_INNER_NH | NFT_INNER_TH;
        let l4 = [(NFTA_META_DREG, 1), (NFTA_META_KEY, NFT_META_L4PROTO)];
        let l4 = nft_inner_init(&inner(flags, 0, 8, b"meta", &l4)).unwrap();
        assert_eq!(&eval(&l4, &p).data[16..20], &[IPPROTO_TCP, 0, 0, 0]);
        // A packet with no tunnel, or with a header that is too short, ends the rule.
        let mut tcp = p.clone();
        tcp[9] = 1;
        assert_eq!(eval(&saddr, &tcp).verdict, NFT_BREAK);
        assert_eq!(eval(&saddr, &p[..36 + 14 + 10]).verdict, NFT_BREAK);
    }
}

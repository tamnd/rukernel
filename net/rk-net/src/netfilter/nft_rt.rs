//! The expression `rt` of nf_tables, as nft_rt.c of Linux: the next hop, the TCP MSS of the
//! path, the realm and the IPsec state of the route of the packet.
//!
//! A packet of rukernel does not keep its route, the `dst` of Linux. The stack of IPv4 and IPv6
//! registers a lookup with `nft_rt_set_fn`, and `rt` looks up the route of the packet again.
//! Before the routing decision (`prerouting` and `ingress`) the packet has no route, as in
//! Linux.

use super::nft_fib::NftFibFlow;
use super::{NFT_BREAK, NftRegs, be32, nft_parse_register};
use crate::netfilter::{
    NF_INET_FORWARD, NF_INET_INGRESS, NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING, NF_INET_PRE_ROUTING,
    NFPROTO_INET, NFPROTO_IPV4, NFPROTO_IPV6, NfHookState,
};
use crate::netlink::msg::Attrs;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::inode::Result;

// `NFTA_RT_*` and `enum nft_rt_keys`.
const NFTA_RT_DREG: u32 = 1;
const NFTA_RT_KEY: u32 = 2;
const NFT_RT_CLASSID: u32 = 0;
const NFT_RT_NEXTHOP4: u32 = 1;
const NFT_RT_NEXTHOP6: u32 = 2;
const NFT_RT_TCPMSS: u32 = 3;
const NFT_RT_XFRM: u32 = 4;

/// `TCP_MSS_DEFAULT` of Linux.
const TCP_MSS_DEFAULT: u16 = 536;

/// The route of a flow of the family `pf`: the address of the next hop (the gateway, or the
/// destination) and the MTU of the path (the metric `mtu` of the route, or the MTU of its
/// device). `None` if there is no route.
pub type NftRtRouteFn = fn(pf: u8, fl: &NftFibFlow) -> Option<([u8; 16], u32)>;

static RT_FN: SpinLock<Option<NftRtRouteFn>> = SpinLock::new(None);

/// Registers the route lookup of `rt`.
pub fn nft_rt_set_fn(route: NftRtRouteFn) {
    *RT_FN.lock() = Some(route);
}

/// `rt`, as `struct nft_rt` of Linux.
#[derive(Clone, Debug)]
pub(crate) struct NftRt {
    key: u32,
    dreg: usize,
}

/// Reads an `rt` expression of a table of the family `family`, as `nft_rt_get_init` and the
/// family check of `nft_rt_validate` of Linux.
pub(super) fn nft_rt_init(family: u8, data: &[u8]) -> Result<NftRt> {
    let a = Attrs::parse(data, NFTA_RT_KEY as u16);
    let (Some(key), true) = (be32(&a, NFTA_RT_KEY)?, a.has(NFTA_RT_DREG)) else {
        return Err(Errno::EINVAL);
    };
    let len = match key {
        NFT_RT_CLASSID | NFT_RT_NEXTHOP4 => 4,
        NFT_RT_NEXTHOP6 => 16,
        NFT_RT_TCPMSS => 2,
        NFT_RT_XFRM => 1,
        _ => return Err(Errno::EOPNOTSUPP),
    };
    let dreg = nft_parse_register(&a, NFTA_RT_DREG, len)?;
    if !matches!(family, NFPROTO_IPV4 | NFPROTO_IPV6 | NFPROTO_INET) {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(NftRt { key, dreg })
}

impl NftRt {
    /// The hooks of a base chain that can have the expression, as `nft_rt_validate` of Linux:
    /// the MSS needs the output route.
    pub(super) fn hooks(&self) -> Option<u32> {
        (self.key == NFT_RT_TCPMSS)
            .then_some(1 << NF_INET_FORWARD | 1 << NF_INET_LOCAL_OUT | 1 << NF_INET_POST_ROUTING)
    }
}

/// The flow of the route of the packet `d` to `dst`, as the route that the stack took for it.
fn flow(d: &[u8], v6: bool, dst: &[u8], mark: u32, state: &NfHookState) -> NftFibFlow {
    let mut fl = NftFibFlow { mark, ..NftFibFlow::default() };
    fl.dst[..dst.len()].copy_from_slice(dst);
    // A packet that came in has the input route; a packet of the host the output route.
    if state.hook != NF_INET_LOCAL_OUT {
        fl.iif = state.in_dev;
    }
    if v6 {
        let mut s = [0u8; 16];
        s.copy_from_slice(&d[8..24]);
        fl.src = Some(s);
        fl.flowlabel = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) & 0x000f_ffff;
        fl.proto = d[6];
    } else {
        let mut s = [0u8; 16];
        s[..4].copy_from_slice(&d[12..16]);
        fl.src = Some(s);
        fl.tos = d[1] & 0xfc;
        fl.proto = d[9];
    }
    fl
}

/// Runs `rt` on the packet `d` with the mark `mark`, as `nft_rt_get_eval` of Linux.
pub(super) fn nft_rt_eval(r: &NftRt, regs: &mut NftRegs, d: &[u8], mark: u32, state: &NfHookState) {
    let v6 = match state.pf {
        NFPROTO_IPV4 if d.len() >= 20 => false,
        NFPROTO_IPV6 if d.len() >= 40 => true,
        _ => {
            regs.verdict = NFT_BREAK;
            return;
        }
    };
    let route = *RT_FN.lock();
    // As `skb_valid_dst`: no route before the routing decision.
    let (Some(route), false) =
        (route, state.hook == NF_INET_PRE_ROUTING || state.hook == NF_INET_INGRESS)
    else {
        regs.verdict = NFT_BREAK;
        return;
    };
    let (saddr, daddr) = if v6 { (&d[8..24], &d[24..40]) } else { (&d[12..16], &d[16..20]) };
    let Some((hop, mtu)) = route(state.pf, &flow(d, v6, daddr, mark, state)) else {
        regs.verdict = NFT_BREAK;
        return;
    };
    match r.key {
        // The routes of rukernel have no realm.
        NFT_RT_CLASSID => regs.store(r.dreg, &0u32.to_ne_bytes()),
        NFT_RT_NEXTHOP4 if !v6 => regs.store(r.dreg, &hop[..4]),
        NFT_RT_NEXTHOP6 if v6 => regs.store(r.dreg, &hop),
        NFT_RT_TCPMSS => {
            // As `get_tcpmss`: the smaller MTU of the route of the packet and of the route back
            // to its source, less the headers.
            let back =
                NftFibFlow { dst: flow(d, v6, saddr, 0, state).dst, ..NftFibFlow::default() };
            let mtu = route(state.pf, &back).map_or(mtu, |(_, m)| mtu.min(m));
            let minlen = if v6 { 40 + 20 } else { 20 + 20 };
            let mss =
                if mtu <= minlen || mtu > 0xffff { TCP_MSS_DEFAULT } else { (mtu - minlen) as u16 };
            regs.store(r.dreg, &mss.to_ne_bytes());
        }
        // rukernel has no IPsec, and no route has a transform.
        NFT_RT_XFRM => regs.store(r.dreg, &[0]),
        // `rt ip nexthop` of a packet of IPv6 and the other way.
        _ => regs.verdict = NFT_BREAK,
    }
}

#[cfg(test)]
mod tests {
    use super::super::{NFT_CONTINUE, NFT_REG_SIZE, NFT_REGS_LEN};
    use super::*;
    use crate::netfilter::{NF_INET_LOCAL_IN, NFPROTO_ARP};
    use crate::netlink::msg::{Builder, HDRLEN};

    fn rt(family: u8, key: u32) -> Result<NftRt> {
        let mut b = Builder::new(0, 0, 0, 0);
        b.put(NFTA_RT_DREG as u16, &1u32.to_be_bytes());
        b.put(NFTA_RT_KEY as u16, &key.to_be_bytes());
        nft_rt_init(family, &b.finish()[HDRLEN..])
    }

    #[test]
    fn rt_takes_the_keys_of_linux() {
        assert_eq!(rt(NFPROTO_INET, NFT_RT_NEXTHOP6).unwrap().dreg, NFT_REG_SIZE);
        assert_eq!(rt(NFPROTO_IPV4, NFT_RT_CLASSID).unwrap().hooks(), None);
        let mss = 1 << NF_INET_FORWARD | 1 << NF_INET_LOCAL_OUT | 1 << NF_INET_POST_ROUTING;
        assert_eq!(rt(NFPROTO_IPV6, NFT_RT_TCPMSS).unwrap().hooks(), Some(mss));
        assert_eq!(rt(NFPROTO_IPV4, 5).unwrap_err(), Errno::EOPNOTSUPP);
        assert_eq!(rt(NFPROTO_ARP, NFT_RT_XFRM).unwrap_err(), Errno::EOPNOTSUPP);
        let mut b = Builder::new(0, 0, 0, 0);
        b.put(NFTA_RT_KEY as u16, &NFT_RT_XFRM.to_be_bytes());
        assert_eq!(nft_rt_init(NFPROTO_IPV4, &b.finish()[HDRLEN..]).unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn rt_gives_the_next_hop_and_the_mss() {
        // 10.0.0.0/8 goes through the gateway 192.168.1.1 with an MTU of 1400; the rest is on
        // the link with an MTU of 1500.
        fn route(_: u8, fl: &NftFibFlow) -> Option<([u8; 16], u32)> {
            let mut hop = fl.dst;
            if fl.dst[0] == 10 {
                hop[..4].copy_from_slice(&[192, 168, 1, 1]);
                return Some((hop, 1400));
            }
            Some((hop, 1500))
        }
        nft_rt_set_fn(route);
        let mut ip = [0u8; 20];
        ip[0] = 0x45;
        ip[12..16].copy_from_slice(&[172, 16, 0, 1]);
        ip[16..20].copy_from_slice(&[10, 1, 2, 3]);
        let run = |r: &NftRt, hook| {
            let st = NfHookState { hook, pf: NFPROTO_IPV4, in_dev: 2, out_dev: 3 };
            let mut regs = NftRegs { verdict: NFT_CONTINUE, chain: 0, data: [0; NFT_REGS_LEN] };
            regs.data[16..32].fill(0xaa);
            nft_rt_eval(r, &mut regs, &ip, 0, &st);
            (regs.verdict, u32::from_ne_bytes(regs.data[16..20].try_into().unwrap()))
        };
        let hop = rt(NFPROTO_IPV4, NFT_RT_NEXTHOP4).unwrap();
        let want = u32::from_ne_bytes([192, 168, 1, 1]);
        assert_eq!(run(&hop, NF_INET_POST_ROUTING), (NFT_CONTINUE, want));
        // No route before the routing decision.
        assert_eq!(run(&hop, NF_INET_PRE_ROUTING).0, NFT_BREAK);
        // `rt ip6 nexthop` of an IPv4 packet.
        assert_eq!(run(&rt(NFPROTO_INET, NFT_RT_NEXTHOP6).unwrap(), NF_INET_LOCAL_IN).0, NFT_BREAK);
        // `rt mtu`: 1400 less 40.
        let mss = rt(NFPROTO_IPV4, NFT_RT_TCPMSS).unwrap();
        assert_eq!(run(&mss, NF_INET_FORWARD), (NFT_CONTINUE, u32::from(1360u16)));
        let x = rt(NFPROTO_IPV4, NFT_RT_XFRM).unwrap();
        assert_eq!(run(&x, NF_INET_FORWARD), (NFT_CONTINUE, 0));
    }
}

//! The expression `xfrm` of nf_tables, as nft_xfrm.c of Linux: a key of the IPsec state of the
//! packet, for example `ipsec in reqid` or `ipsec out ip daddr`.
//!
//! rukernel has no IPsec, so a packet that comes in has no security path and a route has no
//! transform. The expression gives no result (`NFT_BREAK`), as on Linux for a packet that IPsec
//! did not touch. The checks of the attributes and of the hooks are the same as on Linux, so
//! that a rule set with `ipsec` loads.

use super::{NFT_BREAK, NftRegs, be32, nft_parse_register};
use crate::netfilter::{
    NF_INET_FORWARD, NF_INET_LOCAL_IN, NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING,
    NF_INET_PRE_ROUTING, NFPROTO_INET, NFPROTO_IPV4, NFPROTO_IPV6,
};
use crate::netlink::msg::Attrs;
use rk_abi::Errno;
use rk_vfs::inode::Result;

// `NFTA_XFRM_*`, `enum nft_xfrm_keys` and `XFRM_POLICY_*`.
const NFTA_XFRM_DREG: u32 = 1;
const NFTA_XFRM_KEY: u32 = 2;
const NFTA_XFRM_DIR: u32 = 3;
const NFTA_XFRM_SPNUM: u32 = 4;
const NFT_XFRM_KEY_DADDR_IP4: u32 = 1;
const NFT_XFRM_KEY_DADDR_IP6: u32 = 2;
const NFT_XFRM_KEY_SADDR_IP4: u32 = 3;
const NFT_XFRM_KEY_SADDR_IP6: u32 = 4;
const NFT_XFRM_KEY_REQID: u32 = 5;
const NFT_XFRM_KEY_SPI: u32 = 6;
const XFRM_POLICY_IN: u8 = 0;
const XFRM_POLICY_OUT: u8 = 1;
/// `XFRM_MAX_DEPTH` of Linux: the most transforms on a packet.
const XFRM_MAX_DEPTH: u32 = 6;

/// `xfrm`, as `struct nft_xfrm` of Linux.
#[derive(Clone, Debug)]
pub(crate) struct NftXfrm {
    dir: u8,
}

/// Reads a 32-bit attribute that must be at most 255, as `NLA_POLICY_MAX(NLA_BE32, 255)`.
fn u8_attr(a: &Attrs<'_>, ty: u32) -> Result<Option<u32>> {
    match be32(a, ty)? {
        Some(v) if v > 255 => Err(Errno::ERANGE),
        v => Ok(v),
    }
}

/// Reads an `xfrm` expression of a table of the family `family`, as `nft_xfrm_policy` and
/// `nft_xfrm_get_init` of Linux.
pub(super) fn nft_xfrm_init(family: u8, data: &[u8]) -> Result<NftXfrm> {
    let a = Attrs::parse(data, NFTA_XFRM_SPNUM as u16);
    let key = u8_attr(&a, NFTA_XFRM_KEY)?;
    let spnum = u8_attr(&a, NFTA_XFRM_SPNUM)?.unwrap_or(0);
    let dir = match a.get(NFTA_XFRM_DIR) {
        // `NLA_U8`: an attribute with no byte is too short.
        Some([]) => return Err(Errno::ERANGE),
        Some(d) => Some(d[0]),
        None => None,
    };
    let (Some(key), Some(dir), true) = (key, dir, a.has(NFTA_XFRM_DREG)) else {
        return Err(Errno::EINVAL);
    };
    if !matches!(family, NFPROTO_IPV4 | NFPROTO_IPV6 | NFPROTO_INET) {
        return Err(Errno::EOPNOTSUPP);
    }
    let len = match key {
        NFT_XFRM_KEY_REQID | NFT_XFRM_KEY_SPI => 4,
        NFT_XFRM_KEY_DADDR_IP4 | NFT_XFRM_KEY_SADDR_IP4 => 4,
        NFT_XFRM_KEY_DADDR_IP6 | NFT_XFRM_KEY_SADDR_IP6 => 16,
        _ => return Err(Errno::EINVAL),
    };
    if !matches!(dir, XFRM_POLICY_IN | XFRM_POLICY_OUT) {
        return Err(Errno::EINVAL);
    }
    if spnum >= XFRM_MAX_DEPTH {
        return Err(Errno::ERANGE);
    }
    nft_parse_register(&a, NFTA_XFRM_DREG, len)?;
    Ok(NftXfrm { dir })
}

impl NftXfrm {
    /// The hooks of a base chain that can have the expression, as `nft_xfrm_validate` of Linux:
    /// the input state is there after the input of IPsec, the output state after the routing.
    pub(super) fn hooks(&self) -> u32 {
        let both = 1 << NF_INET_FORWARD;
        if self.dir == XFRM_POLICY_IN {
            both | 1 << NF_INET_LOCAL_IN | 1 << NF_INET_PRE_ROUTING
        } else {
            both | 1 << NF_INET_LOCAL_OUT | 1 << NF_INET_POST_ROUTING
        }
    }
}

/// Runs `xfrm`, as `nft_xfrm_get_eval` of Linux. No packet has a security path and no route
/// has a transform, so there is no state at any `spnum`.
pub(super) fn nft_xfrm_eval(_x: &NftXfrm, regs: &mut NftRegs) {
    regs.verdict = NFT_BREAK;
}

#[cfg(test)]
mod tests {
    use super::super::NFT_CONTINUE;
    use super::super::NFT_REGS_LEN;
    use super::*;
    use crate::netfilter::NFPROTO_ARP;
    use crate::netlink::msg::{Builder, HDRLEN};

    fn xfrm(family: u8, key: u32, dir: &[u8], spnum: Option<u32>) -> Result<NftXfrm> {
        let mut b = Builder::new(0, 0, 0, 0);
        b.put(NFTA_XFRM_DREG as u16, &1u32.to_be_bytes());
        b.put(NFTA_XFRM_KEY as u16, &key.to_be_bytes());
        b.put(NFTA_XFRM_DIR as u16, dir);
        if let Some(n) = spnum {
            b.put(NFTA_XFRM_SPNUM as u16, &n.to_be_bytes());
        }
        nft_xfrm_init(family, &b.finish()[HDRLEN..])
    }

    #[test]
    fn xfrm_takes_the_attributes_of_linux() {
        let input = 1 << NF_INET_FORWARD | 1 << NF_INET_LOCAL_IN | 1 << NF_INET_PRE_ROUTING;
        let output = 1 << NF_INET_FORWARD | 1 << NF_INET_LOCAL_OUT | 1 << NF_INET_POST_ROUTING;
        assert_eq!(xfrm(NFPROTO_INET, NFT_XFRM_KEY_REQID, &[0], None).unwrap().hooks(), input);
        assert_eq!(
            xfrm(NFPROTO_IPV6, NFT_XFRM_KEY_SADDR_IP6, &[1], Some(5)).unwrap().hooks(),
            output
        );
        assert_eq!(xfrm(NFPROTO_ARP, NFT_XFRM_KEY_SPI, &[0], None).unwrap_err(), Errno::EOPNOTSUPP);
        assert_eq!(xfrm(NFPROTO_IPV4, 7, &[0], None).unwrap_err(), Errno::EINVAL);
        assert_eq!(xfrm(NFPROTO_IPV4, 256, &[0], None).unwrap_err(), Errno::ERANGE);
        assert_eq!(xfrm(NFPROTO_IPV4, NFT_XFRM_KEY_SPI, &[2], None).unwrap_err(), Errno::EINVAL);
        assert_eq!(xfrm(NFPROTO_IPV4, NFT_XFRM_KEY_SPI, &[], None).unwrap_err(), Errno::ERANGE);
        let deep = xfrm(NFPROTO_IPV4, NFT_XFRM_KEY_SPI, &[0], Some(XFRM_MAX_DEPTH));
        assert_eq!(deep.unwrap_err(), Errno::ERANGE);
        // No register, or no direction.
        let mut b = Builder::new(0, 0, 0, 0);
        b.put(NFTA_XFRM_KEY as u16, &NFT_XFRM_KEY_SPI.to_be_bytes());
        b.put(NFTA_XFRM_DIR as u16, &[0]);
        assert_eq!(nft_xfrm_init(NFPROTO_IPV4, &b.finish()[HDRLEN..]).unwrap_err(), Errno::EINVAL);
        let mut b = Builder::new(0, 0, 0, 0);
        b.put(NFTA_XFRM_DREG as u16, &1u32.to_be_bytes());
        b.put(NFTA_XFRM_KEY as u16, &NFT_XFRM_KEY_SPI.to_be_bytes());
        assert_eq!(nft_xfrm_init(NFPROTO_IPV4, &b.finish()[HDRLEN..]).unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn xfrm_gives_no_result_with_no_ipsec() {
        let x = xfrm(NFPROTO_IPV4, NFT_XFRM_KEY_DADDR_IP4, &[1], None).unwrap();
        let mut regs = NftRegs { verdict: NFT_CONTINUE, chain: 0, data: [0; NFT_REGS_LEN] };
        nft_xfrm_eval(&x, &mut regs);
        assert_eq!(regs.verdict, NFT_BREAK);
    }
}

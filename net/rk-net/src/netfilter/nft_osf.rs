//! The expression `osf` of nf_tables, as nft_osf.c of Linux: the genre of the system that sent
//! a TCP SYN, from the fingerprints of nfnetlink_osf, for example `osf name "Linux"` or
//! `osf version "Linux:4.19"`.

use super::{NFT_BREAK, NftRegs, nft_parse_register};
use crate::netfilter::nfnetlink_osf::nf_osf_find;
use crate::netfilter::{
    NF_INET_FORWARD, NF_INET_LOCAL_IN, NF_INET_PRE_ROUTING, NFPROTO_INET, NFPROTO_IPV4,
    NFPROTO_IPV6, NfHookState, NfPktinfo,
};
use crate::netlink::msg::Attrs;
use rk_abi::Errno;
use rk_vfs::inode::Result;

// `NFTA_OSF_*` and `NFT_OSF_F_VERSION`.
const NFTA_OSF_DREG: u32 = 1;
const NFTA_OSF_TTL: u32 = 2;
const NFTA_OSF_FLAGS: u32 = 3;
const NFTA_OSF_MAX: u16 = 3;
const NFT_OSF_F_VERSION: u32 = 1 << 0;
/// The size of the register of the genre, `NFT_OSF_MAXGENRELEN`.
const NFT_OSF_MAXGENRELEN: usize = 16;
const IPPROTO_TCP: u8 = 6;

/// `osf`, as `struct nft_osf` of Linux, with the family of the table for the check of
/// `nft_osf_validate`.
#[derive(Clone, Debug)]
pub(crate) struct NftOsf {
    dreg: usize,
    ttl: u8,
    flags: u32,
    family: u8,
}

/// Reads an `osf` expression of a table of the family `family`, as `nft_osf_init` of Linux.
pub(super) fn nft_osf_init(family: u8, data: &[u8]) -> Result<NftOsf> {
    let a = Attrs::parse(data, NFTA_OSF_MAX);
    // `NLA_U8` and `NLA_U32` of the policy: a short attribute gives `ERANGE`.
    let ttl = match a.get(NFTA_OSF_TTL) {
        Some([]) => return Err(Errno::ERANGE),
        Some(t) => Some(t[0]),
        None => None,
    };
    let flags = match a.get(NFTA_OSF_FLAGS) {
        Some(f) => Some(u32::from_be_bytes(*f.first_chunk::<4>().ok_or(Errno::ERANGE)?)),
        None => None,
    };
    if !a.has(NFTA_OSF_DREG) {
        return Err(Errno::EINVAL);
    }
    let ttl = ttl.unwrap_or(0);
    if ttl > 2 {
        return Err(Errno::EINVAL);
    }
    let flags = match flags {
        Some(NFT_OSF_F_VERSION) | None => flags.unwrap_or(0),
        Some(_) => return Err(Errno::EINVAL),
    };
    let dreg = nft_parse_register(&a, NFTA_OSF_DREG, NFT_OSF_MAXGENRELEN)?;
    Ok(NftOsf { dreg, ttl, flags, family })
}

impl NftOsf {
    /// The hooks of a base chain that can have the expression, as `nft_osf_validate` of Linux:
    /// the SYNs that come in. A table of an other family has no hook for it, so that a base
    /// chain with it gives `EOPNOTSUPP`.
    pub(super) fn hooks(&self) -> u32 {
        if matches!(self.family, NFPROTO_IPV4 | NFPROTO_IPV6 | NFPROTO_INET) {
            1 << NF_INET_LOCAL_IN | 1 << NF_INET_PRE_ROUTING | 1 << NF_INET_FORWARD
        } else {
            0
        }
    }
}

/// Runs `osf`, as `nft_osf_eval` of Linux: the genre of the first fingerprint that the TCP SYN
/// `d` matches, with its version for `NFT_OSF_F_VERSION`, or `unknown`. A packet that is not a
/// TCP SYN gives no result.
///
/// nf_osf.c reads the header of IPv4 of all packets; for an IPv6 packet it reads its header as
/// one of IPv4. Here an IPv6 packet gives no result.
pub(super) fn nft_osf_eval(
    o: &NftOsf,
    regs: &mut NftRegs,
    d: &[u8],
    state: &NfHookState,
    pkt: &NfPktinfo,
) {
    if pkt.l4proto != IPPROTO_TCP || state.pf != NFPROTO_IPV4 {
        regs.verdict = NFT_BREAK;
        return;
    }
    let ihl = usize::from(d.first().map_or(0, |b| b & 0xf)) * 4;
    let Some(tcp) = d.get(ihl..ihl + 20) else {
        regs.verdict = NFT_BREAK;
        return;
    };
    if tcp[13] & 0x02 == 0 {
        regs.verdict = NFT_BREAK;
        return;
    }
    let mut name = [0u8; NFT_OSF_MAXGENRELEN];
    let s = match nf_osf_find(d, o.ttl, state.in_dev) {
        None => b"unknown".to_vec(),
        Some((genre, version)) if o.flags & NFT_OSF_F_VERSION != 0 => {
            [&genre[..], b":", &version[..]].concat()
        }
        Some((genre, _)) => genre,
    };
    // `strscpy_pad` and `snprintf`: the string is cut to leave a NUL.
    let n = s.len().min(NFT_OSF_MAXGENRELEN - 1);
    name[..n].copy_from_slice(&s[..n]);
    regs.store(o.dreg, &name);
}

#[cfg(test)]
mod tests {
    use super::super::{NFT_CONTINUE, NFT_REGS_LEN};
    use super::*;
    use crate::netfilter::{NF_INET_LOCAL_OUT, NFPROTO_NETDEV};
    use crate::netlink::msg::{Builder, HDRLEN};

    fn osf(family: u8, ttl: Option<&[u8]>, flags: Option<u32>) -> Result<NftOsf> {
        let mut b = Builder::new(0, 0, 0, 0);
        b.put(NFTA_OSF_DREG as u16, &1u32.to_be_bytes());
        if let Some(t) = ttl {
            b.put(NFTA_OSF_TTL as u16, t);
        }
        if let Some(f) = flags {
            b.put(NFTA_OSF_FLAGS as u16, &f.to_be_bytes());
        }
        nft_osf_init(family, &b.finish()[HDRLEN..])
    }

    #[test]
    fn the_attributes_of_osf_are_checked_as_on_linux() {
        assert!(osf(NFPROTO_INET, Some(&[2]), Some(NFT_OSF_F_VERSION)).is_ok());
        assert_eq!(osf(NFPROTO_INET, Some(&[3]), None).unwrap_err(), Errno::EINVAL);
        assert_eq!(osf(NFPROTO_INET, Some(&[]), None).unwrap_err(), Errno::ERANGE);
        assert_eq!(osf(NFPROTO_INET, None, Some(2)).unwrap_err(), Errno::EINVAL);
        assert_eq!(osf(NFPROTO_INET, None, Some(0)).unwrap_err(), Errno::EINVAL);
        let mut b = Builder::new(0, 0, 0, 0);
        b.put(NFTA_OSF_TTL as u16, &[0]);
        assert_eq!(nft_osf_init(NFPROTO_IPV4, &b.finish()[HDRLEN..]).unwrap_err(), Errno::EINVAL);
        // The hooks of the SYNs that come in, and none for a table of netdev.
        let h = osf(NFPROTO_IPV4, None, None).unwrap().hooks();
        assert_ne!(h & 1 << NF_INET_PRE_ROUTING, 0);
        assert_eq!(h & 1 << NF_INET_LOCAL_OUT, 0);
        assert_eq!(osf(NFPROTO_NETDEV, None, None).unwrap().hooks(), 0);
    }

    #[test]
    fn a_syn_with_no_fingerprint_is_unknown() {
        let o = osf(NFPROTO_IPV4, None, None).unwrap();
        let mut p = [0u8; 40];
        p[0] = 0x45;
        p[2] = 40;
        p[9] = IPPROTO_TCP;
        p[32] = 5 << 4;
        p[33] = 0x02;
        let state = NfHookState { hook: NF_INET_LOCAL_IN, pf: NFPROTO_IPV4, in_dev: 1, out_dev: 0 };
        let pkt = NfPktinfo { thoff: Some(20), l4proto: IPPROTO_TCP };
        let mut regs = NftRegs { verdict: NFT_CONTINUE, chain: 0, data: [0xff; NFT_REGS_LEN] };
        nft_osf_eval(&o, &mut regs, &p, &state, &pkt);
        assert_eq!(regs.verdict, NFT_CONTINUE);
        assert_eq!(&regs.data[o.dreg..o.dreg + 16], b"unknown\0\0\0\0\0\0\0\0\0");
        // An ACK.
        p[33] = 0x10;
        nft_osf_eval(&o, &mut regs, &p, &state, &pkt);
        assert_eq!(regs.verdict, NFT_BREAK);
    }
}

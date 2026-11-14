//! The expression `fib` of nf_tables, as nft_fib.c, nft_fib_ipv4.c, nft_fib_ipv6.c and
//! nft_fib_inet.c of Linux: the type of an address of the packet, or the output device of the
//! route to it.
//!
//! The stack of IPv4 and IPv6 does the lookups: it registers them with `nft_fib_set_fns`, as
//! the masquerade of nf_nat.rs, so that rk-net does not depend on the routes.

use super::{NFT_BREAK, NftRegs, be32, nft_parse_register};
use crate::consts::{IFF_LOOPBACK, IFNAMSIZ};
use crate::netfilter::{
    NF_INET_FORWARD, NF_INET_INGRESS, NF_INET_LOCAL_IN, NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING,
    NF_INET_PRE_ROUTING, NFPROTO_INET, NFPROTO_IPV4, NFPROTO_IPV6, NFPROTO_NETDEV, NfHookState,
};
use crate::netlink::msg::Attrs;
use rk_abi::Errno;
use rk_abi::native::rtnetlink::RTN_LOCAL;
use rk_frame::sync::SpinLock;
use rk_vfs::inode::Result;

// `NFTA_FIB_*`, `enum nft_fib_result` and `enum nft_fib_flags`.
const NFTA_FIB_DREG: u32 = 1;
const NFTA_FIB_RESULT: u32 = 2;
const NFTA_FIB_FLAGS: u32 = 3;
const NFT_FIB_RESULT_OIF: u32 = 1;
const NFT_FIB_RESULT_OIFNAME: u32 = 2;
const NFT_FIB_RESULT_ADDRTYPE: u32 = 3;
const NFTA_FIB_F_SADDR: u32 = 1 << 0;
const NFTA_FIB_F_DADDR: u32 = 1 << 1;
const NFTA_FIB_F_MARK: u32 = 1 << 2;
const NFTA_FIB_F_IIF: u32 = 1 << 3;
const NFTA_FIB_F_OIF: u32 = 1 << 4;
const NFTA_FIB_F_PRESENT: u32 = 1 << 5;
const NFTA_FIB_F_ALL: u32 = (1 << 6) - 1;

/// A route lookup of `fib`, as the `struct flowi4` and `struct flowi6` of nft_fib_ipv4.c and
/// nft_fib_ipv6.c of Linux. An address of IPv4 has 4 bytes, the rest are 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NftFibFlow {
    /// The destination of the lookup.
    pub dst: [u8; 16],
    /// The source of the lookup, or `None`.
    pub src: Option<[u8; 16]>,
    /// The input interface, or 0 for the loopback device: a lookup as for a packet of the host.
    pub iif: u32,
    /// The output interface for an IPv6 link-local destination, or 0.
    pub oif: u32,
    /// The firewall mark.
    pub mark: u32,
    /// The type of service of IPv4, with no ECN bits.
    pub tos: u8,
    /// The transport protocol.
    pub proto: u8,
    /// The IPv6 flow label, in the byte order of the network.
    pub flowlabel: u32,
}

/// The lookup of the route of a flow of the family `pf`: the type of the route (`RTN_*`) and
/// its output interface. `None` if there is no route or the route rejects.
pub type NftFibRouteFn = fn(pf: u8, fl: &NftFibFlow) -> Option<(u32, u32)>;

/// The type of the address `addr` of the family `pf` (`RTN_*`), as `inet_dev_addr_type` of
/// Linux for IPv4 and `__nft_fib6_eval_type` for IPv6. `dev` is the device of the address, or
/// 0 for any. `fl` is the lookup for IPv6.
pub type NftFibTypeFn = fn(pf: u8, dev: u32, fl: &NftFibFlow) -> u32;

static FIB_FNS: SpinLock<Option<(NftFibRouteFn, NftFibTypeFn)>> = SpinLock::new(None);

/// Registers the lookups of `fib`.
pub fn nft_fib_set_fns(route: NftFibRouteFn, addr_type: NftFibTypeFn) {
    *FIB_FNS.lock() = Some((route, addr_type));
}

/// `fib`, as `struct nft_fib` of Linux.
#[derive(Clone, Debug)]
pub(crate) struct NftFib {
    dreg: usize,
    result: u32,
    flags: u32,
}

/// Reads a `fib` expression of a table of the family `family`, as `nft_fib_init` of Linux. The
/// families `ip`, `ip6`, `inet` and `netdev` have `fib`.
pub(super) fn nft_fib_init(family: u8, data: &[u8]) -> Result<NftFib> {
    if !matches!(family, NFPROTO_IPV4 | NFPROTO_IPV6 | NFPROTO_INET | NFPROTO_NETDEV) {
        return Err(Errno::ENOENT);
    }
    let a = Attrs::parse(data, NFTA_FIB_FLAGS as u16);
    let (Some(_), Some(result), Some(flags)) =
        (be32(&a, NFTA_FIB_DREG)?, be32(&a, NFTA_FIB_RESULT)?, be32(&a, NFTA_FIB_FLAGS)?)
    else {
        return Err(Errno::EINVAL);
    };
    // As `NLA_POLICY_MASK` of `nft_fib_policy`.
    if flags & !NFTA_FIB_F_ALL != 0 {
        return Err(Errno::EINVAL);
    }
    let both = |m: u32| flags & m == m;
    if flags == 0
        || both(NFTA_FIB_F_SADDR | NFTA_FIB_F_DADDR)
        || both(NFTA_FIB_F_IIF | NFTA_FIB_F_OIF)
        || flags & (NFTA_FIB_F_SADDR | NFTA_FIB_F_DADDR) == 0
    {
        return Err(Errno::EINVAL);
    }
    let len = match result {
        NFT_FIB_RESULT_OIF | NFT_FIB_RESULT_OIFNAME if flags & NFTA_FIB_F_OIF != 0 => {
            return Err(Errno::EINVAL);
        }
        NFT_FIB_RESULT_OIF => 4,
        NFT_FIB_RESULT_OIFNAME => IFNAMSIZ,
        NFT_FIB_RESULT_ADDRTYPE => 4,
        // `nft_fib4_select_ops` and the others.
        _ => return Err(Errno::EOPNOTSUPP),
    };
    let dreg = nft_parse_register(&a, NFTA_FIB_DREG, len)?;
    Ok(NftFib { dreg, result, flags })
}

impl NftFib {
    /// The hooks of a base chain that can have the expression, as `nft_fib_validate` of Linux.
    pub(super) fn hooks(&self) -> u32 {
        let iif = self.flags & NFTA_FIB_F_IIF != 0;
        match self.result {
            NFT_FIB_RESULT_OIF | NFT_FIB_RESULT_OIFNAME if iif => {
                1 << NF_INET_PRE_ROUTING | 1 << NF_INET_LOCAL_IN | 1 << NF_INET_FORWARD
            }
            NFT_FIB_RESULT_OIF | NFT_FIB_RESULT_OIFNAME => 1 << NF_INET_PRE_ROUTING,
            _ if iif => 1 << NF_INET_PRE_ROUTING | 1 << NF_INET_LOCAL_IN | 1 << NF_INET_FORWARD,
            _ if self.flags & NFTA_FIB_F_OIF != 0 => {
                1 << NF_INET_LOCAL_OUT | 1 << NF_INET_POST_ROUTING | 1 << NF_INET_FORWARD
            }
            _ => {
                1 << NF_INET_LOCAL_IN
                    | 1 << NF_INET_LOCAL_OUT
                    | 1 << NF_INET_FORWARD
                    | 1 << NF_INET_PRE_ROUTING
                    | 1 << NF_INET_POST_ROUTING
            }
        }
    }

    /// Puts the device `ifindex` (0 for none) in the register, as `nft_fib_store_result` of
    /// Linux.
    fn store_result(&self, regs: &mut NftRegs, ifindex: u32) {
        if self.flags & NFTA_FIB_F_PRESENT != 0 {
            return regs.store(self.dreg, &[u8::from(ifindex != 0)]);
        }
        if self.result == NFT_FIB_RESULT_OIF {
            return regs.store(self.dreg, &ifindex.to_ne_bytes());
        }
        let mut name = [0u8; IFNAMSIZ];
        if let Some(d) = (ifindex != 0).then(|| crate::dev::by_index(ifindex)).flatten() {
            let n = d.name();
            let len = n.len().min(IFNAMSIZ - 1);
            name[..len].copy_from_slice(&n.as_bytes()[..len]);
        }
        regs.store(self.dreg, &name);
    }
}

/// The device `ifindex` is a loopback device, as `nft_fib_is_loopback` of Linux.
fn is_loopback(ifindex: u32) -> bool {
    ifindex != 0 && crate::dev::by_index(ifindex).is_some_and(|d| d.flags() & IFF_LOOPBACK != 0)
}

/// The source address of a lookup of IPv4, as `get_saddr` of nft_fib_ipv4.c of Linux: none for
/// a multicast, broadcast or zero address.
fn get_saddr(a: &[u8]) -> Option<[u8; 16]> {
    if a[0] >= 224 || a == [0; 4] {
        return None;
    }
    let mut s = [0u8; 16];
    s[..4].copy_from_slice(a);
    Some(s)
}

/// Runs `fib` on the packet `d` with the mark `mark` and the transport protocol `proto`, as
/// `nft_fib4_eval`, `nft_fib4_eval_type`, `nft_fib6_eval`, `nft_fib6_eval_type` and
/// `nft_fib_inet_eval` of Linux.
pub(super) fn nft_fib_eval(
    f: &NftFib,
    regs: &mut NftRegs,
    d: &[u8],
    mark: u32,
    proto: u8,
    state: &NfHookState,
) {
    let v6 = match state.pf {
        NFPROTO_IPV4 if d.len() >= 20 => false,
        NFPROTO_IPV6 if d.len() >= 40 => true,
        _ => {
            regs.verdict = NFT_BREAK;
            return;
        }
    };
    let (saddr, daddr) = if v6 { (&d[8..24], &d[24..40]) } else { (&d[12..16], &d[16..20]) };
    let dev = if f.flags & NFTA_FIB_F_IIF != 0 {
        state.in_dev
    } else if f.flags & NFTA_FIB_F_OIF != 0 {
        state.out_dev
    } else {
        0
    };
    let mut fl = NftFibFlow { proto, ..NftFibFlow::default() };
    let (dst, src) = if f.flags & NFTA_FIB_F_DADDR != 0 {
        (daddr, saddr)
    } else {
        if state.hook == NF_INET_FORWARD && f.flags & NFTA_FIB_F_IIF != 0 {
            fl.iif = state.out_dev;
        }
        (saddr, daddr)
    };
    fl.dst[..dst.len()].copy_from_slice(dst);
    if v6 {
        let mut s = [0u8; 16];
        s.copy_from_slice(src);
        fl.src = Some(s);
        fl.flowlabel = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) & 0x000f_ffff;
        // A link-local destination is on the device, as `nft_fib6_flowi_init`.
        if dst[0] == 0xfe && dst[1] & 0xc0 == 0x80 {
            fl.oif = if dev != 0 { dev } else { state.in_dev };
        }
    } else {
        fl.src = get_saddr(src);
        fl.tos = d[1] & 0xfc;
    }
    if f.flags & NFTA_FIB_F_MARK != 0 {
        fl.mark = mark;
    }
    let fns = *FIB_FNS.lock();
    if f.result == NFT_FIB_RESULT_ADDRTYPE {
        // IPv4 looks only at the address, as `inet_dev_addr_type`.
        if !v6 {
            fl = NftFibFlow { dst: fl.dst, ..NftFibFlow::default() };
        }
        let t = fns.map_or(0, |(_, addr_type)| addr_type(state.pf, dev, &fl));
        return regs.store(f.dreg, &t.to_ne_bytes());
    }
    // A packet that comes in from a loopback device goes there.
    if (state.hook == NF_INET_PRE_ROUTING || (v6 && state.hook == NF_INET_INGRESS))
        && is_loopback(state.in_dev)
    {
        return f.store_result(regs, state.in_dev);
    }
    if v6 {
        // An ICMPv6 packet from :: to a link-local address, as `nft_fib_v6_skip_icmpv6`.
        if state.hook == NF_INET_PRE_ROUTING
            && proto == 58
            && saddr == [0; 16]
            && daddr[0] == 0xfe
            && daddr[1] & 0xc0 == 0x80
        {
            return f.store_result(regs, state.in_dev);
        }
    } else if saddr == [0; 4] && (daddr == [255; 4] || daddr[..3] == [224, 0, 0]) {
        // DHCP and the local multicast from 0.0.0.0 go on the device of the packet.
        return f.store_result(regs, state.in_dev);
    }
    regs.store(f.dreg, &0u32.to_ne_bytes());
    let Some((ty, ifindex)) = fns.and_then(|(route, _)| route(state.pf, &fl)) else { return };
    if ty == RTN_LOCAL {
        return;
    }
    // The route must go out on the device of the packet if the expression names one.
    if dev != 0 && ifindex != dev {
        return;
    }
    f.store_result(regs, ifindex);
}

#[cfg(test)]
mod tests {
    use super::super::{NFT_CONTINUE, NFT_REG_SIZE, NFT_REGS_LEN};
    use super::*;
    use crate::netfilter::NFPROTO_ARP;
    use crate::netlink::msg::{Builder, HDRLEN};
    use rk_abi::native::rtnetlink::{RTN_MULTICAST, RTN_UNICAST};

    fn fib(family: u8, result: u32, flags: u32) -> Result<NftFib> {
        let mut b = Builder::new(0, 0, 0, 0);
        b.put(NFTA_FIB_DREG as u16, &1u32.to_be_bytes());
        b.put(NFTA_FIB_RESULT as u16, &result.to_be_bytes());
        b.put(NFTA_FIB_FLAGS as u16, &flags.to_be_bytes());
        nft_fib_init(family, &b.finish()[HDRLEN..])
    }

    #[test]
    fn fib_takes_the_flags_of_linux() {
        let (s, d, iif, oif) = (NFTA_FIB_F_SADDR, NFTA_FIB_F_DADDR, NFTA_FIB_F_IIF, NFTA_FIB_F_OIF);
        let oif_r = NFT_FIB_RESULT_OIF;
        // `fib saddr . iif oif missing`, as firewalld has.
        let f = fib(NFPROTO_INET, oif_r, s | iif).unwrap();
        let hooks = 1 << NF_INET_PRE_ROUTING | 1 << NF_INET_LOCAL_IN | 1 << NF_INET_FORWARD;
        assert_eq!((f.dreg, f.hooks()), (NFT_REG_SIZE, hooks));
        assert_eq!(fib(NFPROTO_IPV4, NFT_FIB_RESULT_ADDRTYPE, d).unwrap().hooks(), 0x1f);
        for flags in [0, s | d, s | iif | oif, iif, 1 << 6] {
            assert_eq!(fib(NFPROTO_IPV4, oif_r, flags).unwrap_err(), Errno::EINVAL, "{flags}");
        }
        assert_eq!(fib(NFPROTO_IPV6, NFT_FIB_RESULT_OIFNAME, d | oif).unwrap_err(), Errno::EINVAL);
        assert_eq!(fib(NFPROTO_IPV4, 4, d).unwrap_err(), Errno::EOPNOTSUPP);
        assert_eq!(fib(NFPROTO_ARP, oif_r, d).unwrap_err(), Errno::ENOENT);
    }

    #[test]
    fn fib_gives_the_device_of_the_route_and_the_type_of_the_address() {
        // A route to 10.0.0.0/8 goes out on 3. 224.0.0.0/4 is multicast.
        fn route(_: u8, fl: &NftFibFlow) -> Option<(u32, u32)> {
            (fl.dst[0] == 10 && fl.iif == 0).then_some((RTN_UNICAST, 3))
        }
        fn addr_type(_: u8, _: u32, fl: &NftFibFlow) -> u32 {
            if fl.dst[0] >= 224 { RTN_MULTICAST } else { RTN_UNICAST }
        }
        nft_fib_set_fns(route, addr_type);
        let mut ip = [0u8; 20];
        ip[0] = 0x45;
        ip[12..16].copy_from_slice(&[10, 1, 2, 3]);
        ip[16..20].copy_from_slice(&[224, 0, 1, 1]);
        // At the input hook, with no check for a loopback device.
        let st =
            |in_dev| NfHookState { hook: NF_INET_LOCAL_IN, pf: NFPROTO_IPV4, in_dev, out_dev: 0 };
        let run = |f: &NftFib, in_dev| {
            let mut regs = NftRegs { verdict: NFT_CONTINUE, chain: 0, data: [0; NFT_REGS_LEN] };
            regs.data[16..32].fill(0xaa);
            nft_fib_eval(f, &mut regs, &ip, 0, 17, &st(in_dev));
            (regs.verdict, u32::from_ne_bytes(regs.data[16..20].try_into().unwrap()))
        };
        // `fib saddr . iif oif`: the route back to the source goes out on the device the packet
        // came in on, or the result is 0.
        let f = fib(NFPROTO_IPV4, NFT_FIB_RESULT_OIF, NFTA_FIB_F_SADDR | NFTA_FIB_F_IIF).unwrap();
        assert_eq!(run(&f, 3), (NFT_CONTINUE, 3));
        assert_eq!(run(&f, 4), (NFT_CONTINUE, 0));
        let p = NFTA_FIB_F_SADDR | NFTA_FIB_F_IIF | NFTA_FIB_F_PRESENT;
        let f = fib(NFPROTO_IPV4, NFT_FIB_RESULT_OIF, p).unwrap();
        assert_eq!((run(&f, 3).1, run(&f, 4).1), (1, 0));
        // `fib daddr type`.
        let f = fib(NFPROTO_IPV4, NFT_FIB_RESULT_ADDRTYPE, NFTA_FIB_F_DADDR).unwrap();
        assert_eq!(run(&f, 3), (NFT_CONTINUE, RTN_MULTICAST));
        // A packet with no full header ends the rule.
        let mut regs = NftRegs { verdict: NFT_CONTINUE, chain: 0, data: [0; NFT_REGS_LEN] };
        nft_fib_eval(&f, &mut regs, &ip[..10], 0, 17, &st(3));
        assert_eq!(regs.verdict, NFT_BREAK);
    }
}

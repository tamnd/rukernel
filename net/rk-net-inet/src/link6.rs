//! The IPv6 data of the links: the dump of `RTM_GETLINK` for `AF_INET6`, as
//! `inet6_dump_ifinfo` and `inet6_fill_ifinfo` of net/ipv6/addrconf.c of Linux. `ip token`
//! reads the token of each link from it.
//!
//! Each message has `IFLA_PROTINFO` with the flags, the times, the `net.ipv6.conf` values of
//! the device, the token and the mode of the address generator. The kernel keeps no IPv6
//! counters for each device, thus the messages have no `IFLA_INET6_STATS` and no
//! `IFLA_INET6_ICMP6STATS`. A token cannot be set, thus the token is always `::`.
//!
//! `IFLA_AF_SPEC` of each link has the same attributes for `AF_INET6`, as `inet6_fill_link_af`
//! of Linux. `RTM_SETLINK` sets the mode of the address generator with
//! `IFLA_INET6_ADDR_GEN_MODE` in it, as `inet6_set_link_af` of Linux. systemd-networkd sets the
//! mode `IN6_ADDR_GEN_MODE_NONE` so that the kernel makes no link local address.

use crate::addrconf::{ADDR_GEN_MODE_RANDOM, ADDR_GEN_MODE_STABLE_PRIVACY};
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::if_link::{
    IFLA_ADDRESS, IFLA_IFNAME, IFLA_LINK, IFLA_MTU, IFLA_OPERSTATE, IFLA_PROTINFO,
};
use rk_abi::native::netlink::NLM_F_MULTI;
use rk_abi::native::rtnetlink::{RTM_GETLINK, RTM_NEWLINK};
use rk_net::consts::{AF_INET6, IF_OPER_UNKNOWN, IF_OPER_UP};
use rk_net::dev::{self, LinkKind, NetDevice};
use rk_net::netlink::link::IFINFO_LEN;
use rk_net::netlink::msg::{Attrs, Builder};
use rk_net::netlink::{self, Request};
use rk_net::sysctl::{self, Family, Scope};
use rk_vfs::inode::Result;

/// The attributes in `IFLA_PROTINFO`, `IFLA_INET6_*` of <linux/if_link.h>. They are in an enum
/// without a name that rk-abigen does not read, thus they are here by hand.
const IFLA_INET6_FLAGS: u16 = 1;
const IFLA_INET6_CONF: u16 = 2;
const IFLA_INET6_CACHEINFO: u16 = 5;
const IFLA_INET6_TOKEN: u16 = 7;
const IFLA_INET6_ADDR_GEN_MODE: u16 = 8;
const IFLA_INET6_MAX: u16 = 9;

/// The modes of the address generator, `IN6_ADDR_GEN_MODE_*` of <linux/if_link.h>.
const IN6_ADDR_GEN_MODE_EUI64: u8 = 0;
const IN6_ADDR_GEN_MODE_RANDOM: u8 = 3;

/// The flag of a device that is ready for IPv6, `IF_READY` of <net/if_inet6.h>.
const IF_READY: u32 = 0x8000_0000;

/// The largest packet that the reassembly makes, `IPV6_MAXPLEN` of Linux.
const IPV6_MAXPLEN: u32 = 65535;

/// The smallest MTU of IPv6, `IPV6_MIN_MTU` of Linux. A device with a smaller MTU has no IPv6.
const IPV6_MIN_MTU: u32 = 1280;

/// The values of `IFLA_INET6_CONF` in the order of `DEVCONF_*` of <linux/ipv6.h>, as
/// `ipv6_store_devconf` of Linux. Each entry is the name of the value in `net.ipv6.conf` and the
/// factor from the unit of the file to the unit of the attribute: Linux gives the intervals in
/// milliseconds. An entry without a name is a value that the kernel does not have, with the
/// default value of Linux. `stable_secret` is 0, as in Linux.
const DEVCONF: &[(Option<&str>, i32)] = &[
    (Some("forwarding"), 1),
    (Some("hop_limit"), 1),
    (Some("mtu"), 1),
    (Some("accept_ra"), 1),
    (Some("accept_redirects"), 1),
    (Some("autoconf"), 1),
    (Some("dad_transmits"), 1),
    (Some("router_solicitations"), 1),
    (Some("router_solicitation_interval"), 1000),
    (Some("router_solicitation_delay"), 1000),
    (Some("use_tempaddr"), 1),
    (Some("temp_valid_lft"), 1),
    (Some("temp_prefered_lft"), 1),
    (Some("regen_max_retry"), 1),
    (Some("max_desync_factor"), 1),
    (Some("max_addresses"), 1),
    (Some("force_mld_version"), 1),
    (Some("accept_ra_defrtr"), 1),
    (Some("accept_ra_pinfo"), 1),
    (Some("accept_ra_rtr_pref"), 1),
    (Some("router_probe_interval"), 1000),
    (Some("accept_ra_rt_info_max_plen"), 1),
    (Some("proxy_ndp"), 1),
    (Some("optimistic_dad"), 1),
    (Some("accept_source_route"), 1),
    (Some("mc_forwarding"), 1),
    (Some("disable_ipv6"), 1),
    (Some("accept_dad"), 1),
    (Some("force_tllao"), 1),
    (Some("ndisc_notify"), 1),
    (Some("mldv1_unsolicited_report_interval"), 1),
    (Some("mldv2_unsolicited_report_interval"), 1),
    (Some("suppress_frag_ndisc"), 1),
    (Some("accept_ra_from_local"), 1),
    (Some("use_optimistic"), 1),
    (Some("accept_ra_mtu"), 1),
    // `stable_secret`.
    (None, 0),
    // `use_oif_addrs_only`.
    (None, 0),
    (Some("accept_ra_min_hop_limit"), 1),
    // `ignore_routes_with_linkdown`.
    (None, 0),
    (Some("drop_unicast_in_l2_multicast"), 1),
    (Some("drop_unsolicited_na"), 1),
    (Some("keep_addr_on_down"), 1),
    (Some("router_solicitation_max_interval"), 1000),
    (Some("seg6_enabled"), 1),
    // `seg6_require_hmac`.
    (None, 0),
    (Some("enhanced_dad"), 1),
    (Some("addr_gen_mode"), 1),
    (Some("disable_policy"), 1),
    (Some("accept_ra_rt_info_min_plen"), 1),
    (Some("ndisc_tclass"), 1),
    // `rpl_seg_enabled`.
    (None, 0),
    // `ra_defrtr_metric`, `IP6_RT_PRIO_USER`.
    (None, 1024),
    // `ioam6_enabled`.
    (None, 0),
    // `ioam6_id` and `ioam6_id_wide`, `IOAM6_DEFAULT_IF_ID` and `IOAM6_DEFAULT_IF_ID_WIDE`.
    (None, 0xffff),
    (None, -1),
    // `ndisc_evict_nocarrier`.
    (None, 1),
    // `accept_untracked_na`.
    (None, 0),
    // `accept_ra_min_lft`.
    (None, 0),
];

/// Registers the dump. The IPv6 stack calls this at boot.
pub(crate) fn init() {
    netlink::register(AF_INET6 as u8, RTM_GETLINK, None, Some(dump), false);
}

/// Tells if the device has IPv6, as `__in6_dev_get` of Linux gives an `inet6_dev`: Linux
/// removes it from a device with an MTU below `IPV6_MIN_MTU`.
fn has_ipv6(d: &NetDevice) -> bool {
    d.mtu() >= IPV6_MIN_MTU
}

/// The value `name` of `net.ipv6.conf` of the device.
fn conf(d: &NetDevice, name: &str) -> i32 {
    sysctl::conf(Family::Ipv6, Scope::Dev(d.ifindex()), name)
}

/// The mode of the address generator of the device. A TUN device has no hardware address, so
/// its mode is `IN6_ADDR_GEN_MODE_RANDOM` when it is `IN6_ADDR_GEN_MODE_EUI64`, as
/// `addrconf_dev_config` of Linux sets it for `ARPHRD_NONE`.
fn addr_gen_mode(d: &NetDevice) -> u8 {
    let mode = conf(d, "addr_gen_mode") as u8;
    if d.kind() == LinkKind::Tun && mode == IN6_ADDR_GEN_MODE_EUI64 {
        IN6_ADDR_GEN_MODE_RANDOM
    } else {
        mode
    }
}

/// Builds the message of a device, as `inet6_fill_ifinfo` of Linux.
fn fill(d: &NetDevice, portid: u32, seq: u32, flags: u32) -> Vec<u8> {
    let mut h = [0; IFINFO_LEN];
    h[0] = AF_INET6 as u8;
    h[2..4].copy_from_slice(&d.kind().arphrd().to_ne_bytes());
    h[4..8].copy_from_slice(&d.ifindex().to_ne_bytes());
    h[8..12].copy_from_slice(&d.flags().to_ne_bytes());
    let mut b = Builder::new(RTM_NEWLINK as u16, flags as u16, seq, portid);
    b.fixed(&h);
    b.str(IFLA_IFNAME as u16, &d.name());
    // A device without a hardware address has no `IFLA_ADDRESS`, as a `dev->addr_len` of 0.
    if d.kind().has_header() {
        b.put(IFLA_ADDRESS as u16, &d.mac().0);
    }
    b.u32(IFLA_MTU as u16, d.mtu());
    // The other end of a pair, as `dev_get_iflink` of Linux.
    if let Some(peer) = d.peer() {
        b.u32(IFLA_LINK as u16, peer.ifindex());
    }
    b.u8(IFLA_OPERSTATE as u16, d.operstate());
    let info = b.nest(IFLA_PROTINFO as u16);
    fill_attrs(d, &mut b);
    b.end_nest(info);
    b.finish()
}

/// Adds the attributes in `IFLA_PROTINFO`, as `inet6_fill_ifla6_attrs` of Linux.
fn fill_attrs(d: &NetDevice, b: &mut Builder) {
    // Linux sets `IF_READY` when the device goes up with its link, as `addrconf_link_ready`.
    let ready = d.is_up() && matches!(d.operstate(), IF_OPER_UP | IF_OPER_UNKNOWN);
    b.u32(IFLA_INET6_FLAGS, if ready { IF_READY } else { 0 });
    // `struct ifla_cacheinfo`: the largest packet of the reassembly, the time of the last
    // change, which the kernel does not keep, and the times of the neighbour discovery.
    let mut ci = [0; 16];
    ci[0..4].copy_from_slice(&IPV6_MAXPLEN.to_ne_bytes());
    ci[8..12].copy_from_slice(&(crate::neigh::REACHABLE_MS as u32).to_ne_bytes());
    ci[12..16].copy_from_slice(&(crate::neigh::RETRANS_MS as u32).to_ne_bytes());
    b.put(IFLA_INET6_CACHEINFO, &ci);
    let conf: Vec<u8> = DEVCONF
        .iter()
        .map(|&(name, f)| name.map_or(f, |n| conf(d, n).saturating_mul(f)))
        .flat_map(i32::to_ne_bytes)
        .collect();
    b.put(IFLA_INET6_CONF, &conf);
    b.put(IFLA_INET6_TOKEN, &[0; 16]);
    b.u8(IFLA_INET6_ADDR_GEN_MODE, addr_gen_mode(d));
}

/// Adds the attributes of IPv6 to `IFLA_AF_SPEC` of a link, as `inet6_fill_link_af` of Linux. A
/// device without IPv6 has none.
pub(crate) fn fill_link_af(d: &NetDevice, b: &mut Builder) -> bool {
    if !has_ipv6(d) {
        return false;
    }
    fill_attrs(d, b);
    true
}

/// Checks the attributes of `AF_INET6` in `IFLA_AF_SPEC` of `RTM_SETLINK`, as
/// `inet6_validate_link_af` of Linux. The request must have a token or a mode, and the mode must
/// be one of Linux. `IN6_ADDR_GEN_MODE_STABLE_PRIVACY` needs `stable_secret`, which the kernel
/// does not have. A token cannot be set, so it gives `EOPNOTSUPP`.
pub(crate) fn check_link_af(d: &NetDevice, data: &[u8]) -> Result<()> {
    if !has_ipv6(d) {
        return Err(Errno::EAFNOSUPPORT);
    }
    let a = Attrs::parse(data, IFLA_INET6_MAX);
    let mode = a.u8(u32::from(IFLA_INET6_ADDR_GEN_MODE))?;
    let token = a.get(u32::from(IFLA_INET6_TOKEN));
    if token.is_some_and(|t| t.len() > 16) {
        return Err(Errno::ERANGE);
    }
    match (token, mode.map(i32::from)) {
        (None, None) => Err(Errno::EINVAL),
        (Some(_), _) => Err(Errno::EOPNOTSUPP),
        (None, Some(m)) if m > ADDR_GEN_MODE_RANDOM || m == ADDR_GEN_MODE_STABLE_PRIVACY => {
            Err(Errno::EINVAL)
        }
        (None, Some(_)) => Ok(()),
    }
}

/// Applies the attributes of `AF_INET6` in `IFLA_AF_SPEC` after `check_link_af`, as
/// `inet6_set_link_af` of Linux. It stores the mode and makes no address: the mode counts at the
/// next time the device goes up.
pub(crate) fn set_link_af(d: &NetDevice, data: &[u8]) -> Result<()> {
    let a = Attrs::parse(data, IFLA_INET6_MAX);
    if let Some(m) = a.u8(u32::from(IFLA_INET6_ADDR_GEN_MODE))? {
        sysctl::store_conf(Family::Ipv6, Scope::Dev(d.ifindex()), "addr_gen_mode", i32::from(m))?;
    }
    Ok(())
}

/// Checks the request of a dump with the strict checks, as `inet6_valid_dump_ifinfo` of Linux:
/// a whole `struct ifinfomsg` with only the family, and no attribute after it.
fn check_dump(req: &Request<'_>) -> Result<()> {
    let p = req.payload();
    if p.len() < IFINFO_LEN {
        return Err(req.error("ipv6: Invalid header for link dump request", Errno::EINVAL));
    }
    if p.len() > IFINFO_LEN {
        return Err(req.error("ipv6: Invalid data after header", Errno::EINVAL));
    }
    if p[1..4] != [0; 3] || p[4..IFINFO_LEN] != [0; IFINFO_LEN - 4] {
        return Err(req.error("ipv6: Invalid values in header for dump request", Errno::EINVAL));
    }
    Ok(())
}

/// The dump of `RTM_GETLINK` for `AF_INET6`, as `inet6_dump_ifinfo` of Linux.
fn dump(req: &Request<'_>) -> Result<Vec<Vec<u8>>> {
    if req.strict {
        check_dump(req)?;
    }
    Ok(dev::devices()
        .iter()
        .filter(|d| has_ipv6(d))
        .map(|d| fill(d, req.portid, req.hdr.seq, NLM_F_MULTI))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_conf_has_each_value_of_linux() {
        // `DEVCONF_ACCEPT_RA_MIN_LFT` is the last one, 58.
        assert_eq!(DEVCONF.len(), 59);
        assert_eq!(DEVCONF[47].0, Some("addr_gen_mode"));
    }

    /// systemd-networkd sets the mode of the address generator with `RTM_SETLINK`, as
    /// `inet6_validate_link_af` and `inet6_set_link_af` of Linux.
    #[test]
    fn a_link_takes_the_mode_of_the_address_generator() {
        dev::init();
        let d = rk_net::dummy::create(Some(b"agm1"), None).unwrap();
        let attr = |ty: u16, data: &[u8]| {
            let mut b = Builder::new(0, 0, 0, 0);
            b.put(ty, data);
            b.finish()[16..].to_vec()
        };
        let mode = |m: u8| attr(IFLA_INET6_ADDR_GEN_MODE, &[m]);
        assert_eq!(check_link_af(&d, &[]), Err(Errno::EINVAL));
        assert_eq!(check_link_af(&d, &attr(IFLA_INET6_FLAGS, &[0; 4])), Err(Errno::EINVAL));
        assert_eq!(check_link_af(&d, &attr(IFLA_INET6_ADDR_GEN_MODE, &[])), Err(Errno::ERANGE));
        assert_eq!(check_link_af(&d, &attr(IFLA_INET6_TOKEN, &[0; 16])), Err(Errno::EOPNOTSUPP));
        assert_eq!(check_link_af(&d, &mode(2)), Err(Errno::EINVAL));
        assert_eq!(check_link_af(&d, &mode(4)), Err(Errno::EINVAL));
        for m in [0, 1, 3] {
            assert_eq!(check_link_af(&d, &mode(m)), Ok(()));
        }
        set_link_af(&d, &mode(1)).unwrap();
        assert_eq!(addr_gen_mode(&d), 1);
        let mut b = Builder::new(0, 0, 0, 0);
        assert!(fill_link_af(&d, &mut b));
        let m = b.finish();
        let info = Attrs::parse(&m[16..], IFLA_INET6_MAX);
        assert_eq!(info.u8(u32::from(IFLA_INET6_ADDR_GEN_MODE)).unwrap(), Some(1));
        dev::unregister(&d);
    }

    #[test]
    fn the_message_of_the_loopback_device_has_the_token() {
        dev::init();
        let lo = dev::by_name("lo").unwrap();
        let m = fill(&lo, 7, 3, NLM_F_MULTI);
        let p = &m[16..];
        assert_eq!(p[0], AF_INET6 as u8);
        assert_eq!(u32::from_ne_bytes(p[4..8].try_into().unwrap()), lo.ifindex());
        let a = Attrs::parse(&p[IFINFO_LEN..], IFLA_OPERSTATE as u16);
        assert_eq!(a.str(IFLA_IFNAME), Some(&b"lo"[..]));
        assert_eq!(a.u32(IFLA_MTU).unwrap(), Some(lo.mtu()));
        let info = Attrs::parse(a.get(IFLA_PROTINFO).unwrap(), IFLA_INET6_ADDR_GEN_MODE);
        assert_eq!(info.get(u32::from(IFLA_INET6_TOKEN)), Some(&[0u8; 16][..]));
        assert_eq!(info.u8(u32::from(IFLA_INET6_ADDR_GEN_MODE)).unwrap(), Some(0));
        let conf = info.get(u32::from(IFLA_INET6_CONF)).unwrap();
        assert_eq!(conf.len(), 4 * DEVCONF.len());
        // `DEVCONF_HOPLIMIT` and `DEVCONF_RTR_SOLICIT_INTERVAL`, which is in milliseconds.
        assert_eq!(i32::from_ne_bytes(conf[4..8].try_into().unwrap()), 64);
        assert_eq!(i32::from_ne_bytes(conf[32..36].try_into().unwrap()), 4000);
    }
}

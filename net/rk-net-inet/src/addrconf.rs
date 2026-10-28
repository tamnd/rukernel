//! The IPv6 addresses and routes of the interfaces and their rtnetlink messages, as
//! net/ipv6/addrconf.c and the netlink parts of net/ipv6/route.c of Linux.
//!
//! The loopback device gets `::1/128`, and each Ethernet device gets a link local address from
//! its MAC address when it goes up. A router advertisement adds the default route, the routes
//! of the prefixes and the addresses of SLAAC.
//!
//! A new address on an Ethernet device is tentative while the duplicate address detection of
//! RFC 4862 runs, as `addrconf_dad_begin` of Linux. The device joins the solicited node group of
//! the address and sends an MLD report for it. Then it sends `dad_transmits` neighbour
//! solicitations from `::`, one each second. If no other node answers, the address is no longer
//! tentative. An answer, or a probe of another node for the same address, marks the address
//! `dadfailed`. A tentative address is not a source address.
//!
//! Each change takes the lock of the table for a short time. The notifications go out after the
//! lock is free, as in `fib`.

use crate::fib::{self, IFADDR_LEN, RTMSG_LEN, now_cs};
use crate::ip::{self, Ip};
use crate::ipv6;
use crate::route::{INFINITY, RTAX_MAX};
use crate::route6::{Addr6, Changes6, Match6, PRIO_USER, Route6};
use crate::stack;
use crate::stack6::{self, ROUTES6};
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::if_addr::{
    IFA_ADDRESS, IFA_CACHEINFO, IFA_F_DADFAILED, IFA_F_DEPRECATED, IFA_F_HOMEADDRESS,
    IFA_F_MANAGETEMPADDR, IFA_F_MCAUTOJOIN, IFA_F_NODAD, IFA_F_NOPREFIXROUTE, IFA_F_OPTIMISTIC,
    IFA_F_PERMANENT, IFA_F_TENTATIVE, IFA_FLAGS, IFA_LOCAL, IFA_MC_USERS, IFA_PROTO,
    IFA_RT_PRIORITY, IFA_TARGET_NETNSID,
};
use rk_abi::native::netlink::{NLM_F_CREATE, NLM_F_DUMP_FILTERED, NLM_F_EXCL, NLM_F_MULTI};
use rk_abi::native::rtnetlink::{
    RT_SCOPE_UNIVERSE, RT_TABLE_COMPAT, RT_TABLE_MAIN, RTA_CACHEINFO, RTA_DEL_REASON, RTA_DPORT,
    RTA_DST, RTA_EXPIRES, RTA_GATEWAY, RTA_IIF, RTA_IP_PROTO, RTA_MARK, RTA_METRICS, RTA_OIF,
    RTA_PREF, RTA_PREFSRC, RTA_PRIORITY, RTA_SPORT, RTA_SRC, RTA_TABLE, RTA_UID, RTM_DELADDR,
    RTM_DELROUTE, RTM_F_CLONED, RTM_F_FIB_MATCH, RTM_F_NOTIFY, RTM_F_PREFIX, RTM_GETADDR,
    RTM_GETROUTE, RTM_NEWADDR, RTM_NEWROUTE, RTN_BLACKHOLE, RTN_LOCAL, RTN_PROHIBIT, RTN_UNICAST,
    RTN_UNREACHABLE, RTNLGRP_IPV6_IFADDR, RTNLGRP_IPV6_ROUTE, RTPROT_BOOT,
};
use rk_net::consts::{AF_INET6, IFF_NOARP};
use rk_net::dev::{self, Event, LinkKind, NetDevice};
use rk_net::netlink::msg::{Attrs, Builder, attrs};
use rk_net::netlink::{self, Origin, Request};
use rk_net::sysctl::{Family, Scope};
use rk_vfs::inode::Result;

/// The last attribute of an address, `IFA_MAX` of Linux.
const IFA_MAX: u16 = IFA_MC_USERS as u16;
/// The last attribute of a route, `RTA_MAX` of Linux.
const RTA_MAX: u16 = RTA_DEL_REASON as u16;
/// The size of `struct ifa_cacheinfo`.
const CACHEINFO_LEN: usize = 16;
/// The size of `struct rta_cacheinfo`.
const RTA_CACHEINFO_LEN: usize = 32;
/// The flags of an address that a program can set, as `inet6_rtm_newaddr` of Linux.
const USER_FLAGS: u32 = IFA_F_NODAD
    | IFA_F_HOMEADDRESS
    | IFA_F_MANAGETEMPADDR
    | IFA_F_NOPREFIXROUTE
    | IFA_F_MCAUTOJOIN
    | IFA_F_OPTIMISTIC;

fn u32_at(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).map_or(0, |v| u32::from_ne_bytes([v[0], v[1], v[2], v[3]]))
}

/// Registers the handlers of IPv6 in rtnetlink. The stack calls this one time at boot.
pub(crate) fn init() {
    let inet6 = AF_INET6 as u8;
    netlink::register(inet6, RTM_NEWADDR, Some(newaddr), None, false);
    netlink::register(inet6, RTM_DELADDR, Some(deladdr), None, false);
    netlink::register(inet6, RTM_GETADDR, None, Some(dump_addrs), true);
    netlink::register(inet6, RTM_NEWROUTE, Some(newroute), None, false);
    netlink::register(inet6, RTM_DELROUTE, Some(delroute), None, false);
    netlink::register(inet6, RTM_GETROUTE, Some(getroute), Some(dump_routes), true);
}

/// The preferred and the valid lifetimes that are left, as `inet6_fill_ifaddr` of Linux.
fn lifetimes(a: &Addr6) -> (u32, u32) {
    if a.flags & IFA_F_PERMANENT != 0 || a.valid == INFINITY {
        return (a.preferred, a.valid);
    }
    let gone = (now_cs().saturating_sub(a.tstamp) / 100) as u32;
    let preferred =
        if a.preferred == INFINITY { INFINITY } else { a.preferred.saturating_sub(gone) };
    (preferred, a.valid.saturating_sub(gone))
}

/// Builds the message of an address, as `inet6_fill_ifaddr` of Linux.
pub(crate) fn fill_addr(a: &Addr6, ty: u32, portid: u32, seq: u32, flags: u32) -> Vec<u8> {
    let mut b = Builder::new(ty as u16, flags as u16, seq, portid);
    let mut h = [0u8; IFADDR_LEN];
    h[0] = AF_INET6 as u8;
    h[1] = a.prefix;
    h[2] = a.flags as u8;
    h[3] = ipv6::rt_scope(&a.addr);
    h[4..8].copy_from_slice(&a.ifindex.to_ne_bytes());
    b.fixed(&h);
    b.put(IFA_ADDRESS as u16, &a.addr);
    if a.rt_priority != 0 {
        b.u32(IFA_RT_PRIORITY as u16, a.rt_priority);
    }
    let (preferred, valid) = lifetimes(a);
    let mut ci = [0u8; CACHEINFO_LEN];
    ci[0..4].copy_from_slice(&preferred.to_ne_bytes());
    ci[4..8].copy_from_slice(&valid.to_ne_bytes());
    ci[8..12].copy_from_slice(&(a.cstamp as u32).to_ne_bytes());
    ci[12..16].copy_from_slice(&(a.tstamp as u32).to_ne_bytes());
    b.put(IFA_CACHEINFO as u16, &ci);
    b.u32(IFA_FLAGS as u16, a.flags);
    if a.proto != 0 {
        b.u8(IFA_PROTO as u16, a.proto);
    }
    b.finish()
}

/// Tells if `r` is the route of a prefix of a router advertisement, `RTF_PREFIX_RT` of Linux.
pub(crate) fn is_prefix_route(r: &Route6) -> bool {
    r.addrconf && r.gateway.is_none()
}

/// Builds the message of a route, as `rt6_fill_node` of Linux.
pub(crate) fn fill_route(r: &Route6, ty: u32, portid: u32, seq: u32, flags: u32) -> Vec<u8> {
    let mut b = Builder::new(ty as u16, flags as u16, seq, portid);
    let mut h = [0u8; RTMSG_LEN];
    h[0] = AF_INET6 as u8;
    h[1] = r.prefix;
    h[4] = if r.table < 256 { r.table as u8 } else { RT_TABLE_COMPAT as u8 };
    h[5] = r.protocol;
    h[6] = RT_SCOPE_UNIVERSE as u8;
    h[7] = r.kind;
    let rflags = if is_prefix_route(r) { RTM_F_PREFIX } else { 0 };
    h[8..12].copy_from_slice(&rflags.to_ne_bytes());
    b.fixed(&h);
    b.u32(RTA_TABLE as u16, r.table);
    if r.prefix != 0 {
        b.put(RTA_DST as u16, &r.dst);
    }
    if let Some(s) = r.prefsrc {
        b.put(RTA_PREFSRC as u16, &s);
    }
    fib::put_metrics(&mut b, &r.metrics);
    if let Some(gw) = r.gateway {
        b.put(RTA_GATEWAY as u16, &gw);
    }
    if r.ifindex != 0 {
        b.u32(RTA_OIF as u16, r.ifindex);
    }
    b.u32(RTA_PRIORITY as u16, r.priority);
    put_cacheinfo(&mut b, r.expires);
    // The preference of the route: medium.
    b.u8(RTA_PREF as u16, 0);
    b.finish()
}

/// Adds `RTA_CACHEINFO` with the time to the expiry in hundredths of a second, as
/// `rtnl_put_cacheinfo` of Linux.
fn put_cacheinfo(b: &mut Builder, expires: Option<u64>) {
    let mut ci = [0u8; RTA_CACHEINFO_LEN];
    if let Some(t) = expires {
        let left = (t.saturating_sub(stack::now_ms()) / 10).min(i32::MAX as u64) as u32;
        ci[8..12].copy_from_slice(&left.to_ne_bytes());
    }
    b.put(RTA_CACHEINFO as u16, &ci);
}

/// Sends the notification of an address to `RTNLGRP_IPV6_IFADDR`, as `inet6_ifa_notify`.
fn notify_addr(a: &Addr6, ty: u32, origin: Origin) {
    if netlink::has_listeners(RTNLGRP_IPV6_IFADDR) || origin.echo {
        let m = fill_addr(a, ty, origin.portid, origin.seq, 0);
        netlink::notify(RTNLGRP_IPV6_IFADDR, m, origin);
    }
}

/// Sends the notification of a route to `RTNLGRP_IPV6_ROUTE`, as `inet6_rt_notify`.
fn notify_route(r: &Route6, ty: u32, origin: Origin, flags: u32) {
    if netlink::has_listeners(RTNLGRP_IPV6_ROUTE) || origin.echo {
        let m = fill_route(r, ty, origin.portid, origin.seq, flags);
        netlink::notify(RTNLGRP_IPV6_ROUTE, m, origin);
    }
}

/// Sends the notifications of the routes that a change of an address or a device made.
fn notify_changes(c: &Changes6) {
    for r in &c.removed {
        notify_route(r, RTM_DELROUTE, Origin::KERNEL, 0);
    }
    for r in &c.added {
        notify_route(r, RTM_NEWROUTE, Origin::KERNEL, NLM_F_CREATE | NLM_F_EXCL);
    }
}

/// Adds an address with its routes, as `ipv6_add_addr` and `addrconf_prefix_route` of Linux.
///
/// # Errors
///
/// Gives `ENODEV` for an interface that is not there, and the errors of `Table6::insert_addr`.
pub(crate) fn add_addr(mut a: Addr6, origin: Origin) -> Result<()> {
    if dev::by_index(a.ifindex).is_none() {
        return Err(Errno::ENODEV);
    }
    // `ipv6_add_addr` of Linux gives `EACCES` when `disable_ipv6` is set on the device.
    if rk_net::sysctl::ipv6_disabled(a.ifindex) {
        return Err(Errno::EACCES);
    }
    let now = now_cs();
    a.tstamp = now;
    a.cstamp = now;
    let dev = dev::by_index(a.ifindex);
    let dad = dev.as_ref().is_some_and(|d| needs_dad(d, &a));
    if dad {
        a.flags |= IFA_F_TENTATIVE;
    }
    let changes = ROUTES6.lock().insert_addr(a.clone())?;
    notify_addr(&a, RTM_NEWADDR, origin);
    notify_changes(&changes);
    // A device that is down starts the detection when it goes up.
    if let Some(d) = dev.filter(|d| d.is_up()) {
        stack6::join(&d, &a.addr);
        if dad {
            stack6::start_dad(a.ifindex, a.addr);
        }
    }
    Ok(())
}

/// Tells if the address `a` on `d` needs duplicate address detection, as `addrconf_dad_begin`
/// of Linux: not on the loopback device, a TUN device or a device with `IFF_NOARP`, not with
/// `IFA_F_NODAD`, and only with `accept_dad` and `dad_transmits` above 0.
fn needs_dad(d: &NetDevice, a: &Addr6) -> bool {
    let ifindex = d.ifindex();
    let conf = |scope, name| rk_net::sysctl::conf(Family::Ipv6, scope, name);
    let accept = conf(Scope::All, "accept_dad").max(conf(Scope::Dev(ifindex), "accept_dad"));
    d.kind() == LinkKind::Ether
        && d.flags() & IFF_NOARP == 0
        && a.flags & IFA_F_NODAD == 0
        && accept > 0
        && conf(Scope::Dev(ifindex), "dad_transmits") > 0
}

/// Ends the detection of `addr` on `ifindex`, as `addrconf_dad_completed` of Linux. With
/// `failed` the address stays tentative and gets `IFA_F_DADFAILED`, as `addrconf_dad_failure`.
pub(crate) fn dad_done(ifindex: u32, addr: &Ip, failed: bool) {
    update_addr(
        ifindex,
        |a| {
            if a.addr != *addr || a.flags & IFA_F_TENTATIVE == 0 {
                return false;
            }
            if failed {
                a.flags |= IFA_F_DADFAILED;
            } else {
                a.flags &= !IFA_F_TENTATIVE;
            }
            true
        },
        Origin::KERNEL,
    );
}

/// Changes an address that is there and sends its notification. `f` changes the address and
/// gives `false` if it is not the address to change.
fn update_addr(ifindex: u32, mut f: impl FnMut(&mut Addr6) -> bool, origin: Origin) -> bool {
    let a = {
        let mut t = ROUTES6.lock();
        let Some(a) = t
            .addrs_mut()
            .iter_mut()
            .filter(|a| a.ifindex == ifindex)
            .find_map(|a| f(a).then_some(a))
        else {
            return false;
        };
        a.tstamp = now_cs();
        a.clone()
    };
    notify_addr(&a, RTM_NEWADDR, origin);
    true
}

/// Removes the first address of an interface that `pred` takes, with its routes, as
/// `ipv6_del_addr` of Linux.
///
/// # Errors
///
/// Gives `EADDRNOTAVAIL` if no address matches.
fn del_addr(ifindex: u32, pred: impl Fn(&Addr6) -> bool, origin: Origin) -> Result<()> {
    let (a, changes) = ROUTES6.lock().remove_addr(ifindex, pred)?;
    notify_addr(&a, RTM_DELADDR, origin);
    notify_changes(&changes);
    if !ROUTES6.lock().has_addr(ifindex) {
        stack6::flush_neigh(ifindex);
    }
    Ok(())
}

/// Adds, changes or removes a route of a router advertisement, as `rt6_add_dflt_router` and
/// `rt6_add_route_info` of Linux. With `delete` the route goes away.
pub(crate) fn ra_route(r: Route6, delete: bool) {
    if delete {
        let m = Match6 {
            table: r.table,
            dst: r.dst,
            prefix: r.prefix,
            gateway: r.gateway,
            ifindex: Some(r.ifindex),
            priority: Some(r.priority),
            protocol: None,
        };
        let gone = ROUTES6.lock().delete_route(&m);
        if let Ok(r) = gone {
            notify_route(&r, RTM_DELROUTE, Origin::KERNEL, 0);
        }
        return;
    }
    let added = ROUTES6.lock().update_route(r);
    if let Some(r) = added {
        notify_route(&r, RTM_NEWROUTE, Origin::KERNEL, NLM_F_CREATE | NLM_F_EXCL);
    }
}

/// Adds or renews an address of SLAAC, as `addrconf_prefix_rcv_add_addr` of Linux. The
/// lifetimes are in seconds.
pub(crate) fn slaac(ifindex: u32, addr: Ip, prefix: u8, valid: u32, preferred: u32) {
    let set = |a: &mut Addr6| {
        a.valid = valid;
        a.preferred = preferred;
        a.flags &= !(IFA_F_PERMANENT | IFA_F_DEPRECATED);
        if preferred == 0 {
            a.flags |= IFA_F_DEPRECATED;
        }
    };
    if update_addr(
        ifindex,
        |a| {
            if a.addr != addr {
                return false;
            }
            set(a);
            true
        },
        Origin::KERNEL,
    ) {
        return;
    }
    let mut a = Addr6::new(ifindex, addr, prefix);
    set(&mut a);
    // The address can be there on another device, which is not an error of the router.
    let _ = add_addr(a, Origin::KERNEL);
}

/// Removes the addresses and the routes whose lifetime is over, as `addrconf_verify` and
/// `fib6_gc` of Linux.
pub(crate) fn expire(now_ms: u64) {
    let (gone, changes) = {
        let mut t = ROUTES6.lock();
        if !t.has_timers() {
            return;
        }
        t.expire(now_ms)
    };
    for a in &gone {
        notify_addr(a, RTM_DELADDR, Origin::KERNEL);
    }
    notify_changes(&changes);
}

/// Takes the changes of the devices, as `addrconf_notify` of Linux.
pub(crate) fn event(d: &NetDevice, e: Event) {
    let ifindex = d.ifindex();
    match e {
        // `addrconf_notify` of Linux does nothing for a device with `disable_ipv6`.
        Event::Up if rk_net::sysctl::ipv6_disabled(ifindex) => {}
        Event::Up => {
            let loopback = d.kind() == LinkKind::Loopback;
            if loopback {
                ROUTES6.lock().set_loopback(ifindex);
                // The address can be there from an earlier time.
                let _ = add_addr(Addr6::new(ifindex, ip::LOOPBACK, 128), Origin::KERNEL);
            }
            let ll = ipv6::link_local(ipv6::eui64(d.mac()));
            let added = d.kind() == LinkKind::Ether
                && add_addr(Addr6::new(ifindex, ll, 64), Origin::KERNEL).is_ok();
            let changes = ROUTES6.lock().link_up(ifindex, loopback);
            notify_changes(&changes);
            if d.kind() == LinkKind::Ether {
                stack6::start_solicit(ifindex);
            }
            // The addresses that came while the device was down start their detection now. The
            // new link local address started it in `add_addr`.
            let waiting: Vec<(Ip, bool)> = ROUTES6
                .lock()
                .addrs_of(ifindex)
                .filter(|a| !(added && a.addr == ll))
                .map(|a| (a.addr, a.flags & (IFA_F_TENTATIVE | IFA_F_DADFAILED) == IFA_F_TENTATIVE))
                .collect();
            for (addr, dad) in waiting {
                stack6::join(d, &addr);
                if dad {
                    stack6::start_dad(ifindex, addr);
                }
            }
        }
        Event::Down => {
            let (gone, changes) = ROUTES6.lock().link_down(ifindex);
            for a in &gone {
                notify_addr(a, RTM_DELADDR, Origin::KERNEL);
            }
            notify_changes(&changes);
            stack6::flush_neigh(ifindex);
            stack6::stop_solicit(ifindex);
        }
        // The device is down before it goes, so it has no address or route.
        Event::Flags(_) | Event::Mtu | Event::Name | Event::Register | Event::Unregister => {}
    }
}

/// Checks the attributes of an address against `ifa_ipv6_policy` of Linux.
/// Takes a write of `net.ipv6.conf.DEV.disable_ipv6`, as `dev_disable_change` of Linux. The
/// device loses its addresses and routes when IPv6 goes off, and it gets them again when IPv6
/// comes on and the device is up.
pub(crate) fn sysctl_hook(f: Family, scope: Scope, name: &'static str, value: i32) {
    let (Family::Ipv6, Scope::Dev(ifindex), "disable_ipv6") = (f, scope, name) else { return };
    let Some(d) = dev::by_index(ifindex) else { return };
    if value != 0 {
        event(&d, Event::Down);
    } else if d.is_up() {
        event(&d, Event::Up);
    }
}

fn check_addr_policy(a: &Attrs<'_>) -> Result<()> {
    for ty in [IFA_LOCAL, IFA_ADDRESS] {
        a.addr6(ty)?;
    }
    for ty in [IFA_FLAGS, IFA_RT_PRIORITY, IFA_TARGET_NETNSID] {
        a.u32(ty)?;
    }
    a.u8(IFA_PROTO)?;
    if a.get(IFA_CACHEINFO).is_some_and(|c| c.len() < CACHEINFO_LEN) {
        return Err(Errno::ERANGE);
    }
    Ok(())
}

/// The address of a request, as `extract_addr` of Linux: `IFA_LOCAL`, else `IFA_ADDRESS`.
fn request_addr(a: &Attrs<'_>) -> Result<Option<Ip>> {
    Ok(a.addr6(IFA_LOCAL)?.or(a.addr6(IFA_ADDRESS)?))
}

/// `RTM_NEWADDR`, as `inet6_rtm_newaddr` of Linux.
fn newaddr(req: &Request<'_>) -> Result<()> {
    let (h, a) = req.parse(IFADDR_LEN, IFA_MAX)?;
    check_addr_policy(&a)?;
    let Some(addr) = request_addr(&a)? else { return Err(Errno::EINVAL) };
    let prefix = h[1];
    if prefix > 128 {
        return Err(Errno::EINVAL);
    }
    let ifindex = u32_at(h, 4);
    dev::by_index(ifindex).ok_or(Errno::ENODEV)?;
    let flags = a.u32(IFA_FLAGS)?.unwrap_or(u32::from(h[2])) & USER_FLAGS;
    let (mut valid, mut preferred) = (INFINITY, INFINITY);
    if let Some(ci) = a.get(IFA_CACHEINFO) {
        preferred = u32_at(ci, 0);
        valid = u32_at(ci, 4);
        if valid == 0 || preferred > valid {
            return Err(Errno::EINVAL);
        }
    }
    let rt_priority = a.u32(IFA_RT_PRIORITY)?.unwrap_or(0);
    let proto = a.u8(IFA_PROTO)?.unwrap_or(0);
    // `inet6_addr_add` makes an address with the infinite lifetime permanent.
    // The state of the detection stays, as Linux keeps it on a change.
    let set = |x: &mut Addr6| {
        x.flags = flags | (x.flags & (IFA_F_TENTATIVE | IFA_F_DADFAILED));
        if valid == INFINITY {
            x.flags |= IFA_F_PERMANENT;
        }
        if preferred == 0 {
            x.flags |= IFA_F_DEPRECATED;
        }
        x.valid = valid;
        x.preferred = preferred;
        x.rt_priority = rt_priority;
        x.proto = proto;
    };
    let origin = req.origin();
    let exists = ROUTES6.lock().addrs_of(ifindex).any(|x| x.addr == addr);
    if !exists {
        let mut x = Addr6::new(ifindex, addr, prefix);
        set(&mut x);
        return add_addr(x, origin);
    }
    let rflags = u32::from(req.hdr.flags);
    if rflags & NLM_F_EXCL != 0 || rflags & rk_abi::native::netlink::NLM_F_REPLACE == 0 {
        return Err(Errno::EEXIST);
    }
    update_addr(
        ifindex,
        |x| {
            if x.addr != addr {
                return false;
            }
            set(x);
            true
        },
        origin,
    );
    Ok(())
}

/// `RTM_DELADDR`, as `inet6_rtm_deladdr` of Linux: the address with the prefix length of the
/// request goes away.
fn deladdr(req: &Request<'_>) -> Result<()> {
    let (h, a) = req.parse(IFADDR_LEN, IFA_MAX)?;
    check_addr_policy(&a)?;
    let Some(addr) = request_addr(&a)? else { return Err(Errno::EINVAL) };
    let ifindex = u32_at(h, 4);
    dev::by_index(ifindex).ok_or(Errno::ENODEV)?;
    let prefix = h[1];
    del_addr(ifindex, |o| o.addr == addr && o.prefix == prefix, req.origin())
}

/// The dump of `RTM_GETADDR`, as `inet6_dump_ifaddr` of Linux.
fn dump_addrs(req: &Request<'_>) -> Result<Vec<Vec<u8>>> {
    let mut ifindex = 0;
    let mut flags = NLM_F_MULTI;
    if req.strict {
        let (h, _) = req.parse(IFADDR_LEN, IFA_MAX)?;
        if h[1] != 0 || h[2] != 0 || h[3] != 0 {
            return Err(Errno::EINVAL);
        }
        for (ty, _) in attrs(&req.payload()[IFADDR_LEN..]) {
            if u32::from(ty) != IFA_TARGET_NETNSID {
                return Err(Errno::EINVAL);
            }
        }
        ifindex = u32_at(h, 4);
        if ifindex != 0 {
            dev::by_index(ifindex).ok_or(Errno::ENODEV)?;
            req.set_filtered();
            flags |= NLM_F_DUMP_FILTERED;
        }
    }
    let t = ROUTES6.lock();
    Ok(t.addrs()
        .iter()
        .filter(|a| ifindex == 0 || a.ifindex == ifindex)
        .map(|a| fill_addr(a, RTM_NEWADDR, req.portid, req.hdr.seq, flags))
        .collect())
}

/// A route of a request, as `rtm_to_fib6_config` of Linux.
fn to_route(req: &Request<'_>) -> Result<Route6> {
    let (h, a) = req.parse(RTMSG_LEN, RTA_MAX)?;
    for ty in [RTA_DST, RTA_SRC, RTA_GATEWAY, RTA_PREFSRC] {
        a.addr6(ty)?;
    }
    for ty in [RTA_OIF, RTA_PRIORITY, RTA_TABLE, RTA_EXPIRES] {
        a.u32(ty)?;
    }
    let prefix = h[1];
    // The kernel has no routes by source, as Linux without `CONFIG_IPV6_SUBTREES`.
    if prefix > 128 || h[2] != 0 {
        return Err(Errno::EINVAL);
    }
    let mut table = a.u32(RTA_TABLE)?.unwrap_or(u32::from(h[4]));
    if table == 0 {
        table = RT_TABLE_MAIN;
    }
    let dst = ipv6::prefix(&a.addr6(RTA_DST)?.unwrap_or(ip::ANY), prefix);
    let mut r = Route6::new(dst, prefix, None, a.u32(RTA_OIF)?.unwrap_or(0));
    r.table = table;
    r.protocol = if h[5] != 0 { h[5] } else { RTPROT_BOOT as u8 };
    r.kind = h[7];
    r.gateway = a.addr6(RTA_GATEWAY)?.filter(|g| *g != ip::ANY);
    r.prefsrc = a.addr6(RTA_PREFSRC)?.filter(|s| *s != ip::ANY);
    r.priority = a.u32(RTA_PRIORITY)?.filter(|p| *p != 0).unwrap_or(PRIO_USER);
    if let Some(m) = a.get(RTA_METRICS) {
        r.metrics = crate::rtnl::to_metrics(m)?;
    } else {
        r.metrics = [0; RTAX_MAX as usize];
    }
    if let Some(secs) = a.u32(RTA_EXPIRES)?
        && secs != 0
        && secs != INFINITY
    {
        r.expires = Some(stack::now_ms() + u64::from(secs) * 1000);
    }
    Ok(r)
}

/// Checks the next hop of a new route and sets its interface, as `ip6_route_info_create` and
/// `ip6_validate_gw` of Linux.
fn check_route(r: &mut Route6) -> Result<()> {
    match u32::from(r.kind) {
        RTN_UNICAST | RTN_LOCAL => {}
        // A route that rejects has no next hop.
        RTN_UNREACHABLE | RTN_PROHIBIT | RTN_BLACKHOLE => {
            r.gateway = None;
            return Ok(());
        }
        _ => return Err(Errno::EINVAL),
    }
    let t = ROUTES6.lock();
    if let Some(gw) = r.gateway {
        if t.is_local(&gw) || ipv6::is_multicast(&gw) {
            return Err(Errno::EINVAL);
        }
        if r.ifindex == 0 {
            // A link local gateway needs a device. Another gateway must be on a link.
            if ipv6::is_link_local(&gw) {
                return Err(Errno::EINVAL);
            }
            let (next, route) = t.lookup_route(&gw, 0).map_err(|_| Errno::EHOSTUNREACH)?;
            if route.is_some_and(|x| x.gateway.is_some()) {
                return Err(Errno::EHOSTUNREACH);
            }
            r.ifindex = next.ifindex;
        }
    }
    if let Some(src) = r.prefsrc
        && !t.is_local(&src)
    {
        return Err(Errno::EINVAL);
    }
    drop(t);
    let d = dev::by_index(r.ifindex).ok_or(Errno::ENODEV)?;
    if !d.is_up() {
        return Err(Errno::ENETDOWN);
    }
    Ok(())
}

/// `RTM_NEWROUTE`, as `inet6_rtm_newroute` of Linux.
fn newroute(req: &Request<'_>) -> Result<()> {
    let mut r = to_route(req)?;
    check_route(&mut r)?;
    let flags = u32::from(req.hdr.flags);
    ROUTES6.lock().insert_route(r.clone(), flags)?;
    notify_route(&r, RTM_NEWROUTE, req.origin(), flags & (NLM_F_CREATE | NLM_F_EXCL));
    Ok(())
}

/// `RTM_DELROUTE`, as `inet6_rtm_delroute` and `ip6_route_del` of Linux.
fn delroute(req: &Request<'_>) -> Result<()> {
    let (h, a) = req.parse(RTMSG_LEN, RTA_MAX)?;
    let r = to_route(req)?;
    let m = Match6 {
        table: r.table,
        dst: r.dst,
        prefix: r.prefix,
        gateway: r.gateway,
        ifindex: (r.ifindex != 0).then_some(r.ifindex),
        priority: a.u32(RTA_PRIORITY)?.filter(|p| *p != 0),
        protocol: (h[5] != 0).then_some(h[5]),
    };
    let gone = ROUTES6.lock().delete_route(&m)?;
    notify_route(&gone, RTM_DELROUTE, req.origin(), 0);
    Ok(())
}

/// `RTM_GETROUTE` for one destination, as `inet6_rtm_getroute` of Linux with the checks of
/// `inet6_rtm_valid_getroute_req`.
fn getroute(req: &Request<'_>) -> Result<()> {
    let (h, a) = req.parse(RTMSG_LEN, RTA_MAX)?;
    let rflags = u32_at(h, 8);
    if req.strict {
        let len_ok = |l: u8| l == 0 || l == 128;
        if !len_ok(h[1]) || !len_ok(h[2]) || h[3] != 0 || h[4] != 0 || h[5] != 0 || h[6] != 0 {
            return Err(Errno::EINVAL);
        }
        if h[7] != 0 || rflags & !RTM_F_FIB_MATCH != 0 {
            return Err(Errno::EINVAL);
        }
        let allowed = [
            RTA_SRC,
            RTA_DST,
            RTA_IIF,
            RTA_OIF,
            RTA_MARK,
            RTA_UID,
            RTA_SPORT,
            RTA_DPORT,
            RTA_IP_PROTO,
        ];
        for (ty, _) in attrs(&req.payload()[RTMSG_LEN..]) {
            if !allowed.contains(&u32::from(ty)) {
                return Err(Errno::EINVAL);
            }
        }
    }
    for ty in [RTA_SRC, RTA_DST] {
        a.addr6(ty)?;
    }
    for ty in [RTA_IIF, RTA_OIF, RTA_MARK, RTA_UID] {
        a.u32(ty)?;
    }
    if a.u32(RTA_IIF)?.unwrap_or(0) != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let src = a.addr6(RTA_SRC)?.unwrap_or(ip::ANY);
    let dst = a.addr6(RTA_DST)?.unwrap_or(ip::ANY);
    let oif = a.u32(RTA_OIF)?.unwrap_or(0);
    if oif != 0 {
        dev::by_index(oif).ok_or(Errno::ENODEV)?;
    }
    let uid = a.u32(RTA_UID)?.unwrap_or_else(|| rk_vfs::cred::current().uid);
    let mark = a.u32(RTA_MARK)?.unwrap_or(0);
    let t = ROUTES6.lock();
    // A lookup of `::` goes to the loopback address, as `ip6_route_output`.
    let to = if dst == ip::ANY { ip::LOOPBACK } else { dst };
    let (next, route) = t.lookup_route(&to, oif)?;
    if rflags & RTM_F_FIB_MATCH != 0 {
        let r = route.ok_or(Errno::ENETUNREACH)?;
        let m = fill_route(r, RTM_NEWROUTE, req.portid, req.hdr.seq, 0);
        drop(t);
        req.reply(m);
        return Ok(());
    }
    let kind = if next.local { RTN_LOCAL } else { RTN_UNICAST };
    let (table, protocol, priority) =
        route.map_or((RT_TABLE_MAIN, 0, 0), |r| (r.table, r.protocol, r.priority));
    let metrics = route.map(|r| r.metrics);
    let expires = route.and_then(|r| r.expires);
    drop(t);
    let mut b = Builder::new(RTM_NEWROUTE as u16, 0, req.hdr.seq, req.portid);
    let mut rh = [0u8; RTMSG_LEN];
    rh[0] = AF_INET6 as u8;
    rh[1] = 128;
    rh[2] = if src != ip::ANY { 128 } else { 0 };
    rh[4] = if table < 256 { table as u8 } else { RT_TABLE_COMPAT as u8 };
    rh[5] = protocol;
    rh[6] = RT_SCOPE_UNIVERSE as u8;
    rh[7] = kind as u8;
    let cflags = rflags & RTM_F_NOTIFY;
    rh[8..12].copy_from_slice(&cflags.to_ne_bytes());
    b.fixed(&rh);
    b.u32(RTA_TABLE as u16, table);
    b.put(RTA_DST as u16, &to);
    if src != ip::ANY {
        b.put(RTA_SRC as u16, &src);
    } else {
        b.put(RTA_PREFSRC as u16, &next.src);
    }
    if let Some(m) = &metrics {
        fib::put_metrics(&mut b, m);
    }
    if !next.local && next.hop != to {
        b.put(RTA_GATEWAY as u16, &next.hop);
    }
    b.u32(RTA_OIF as u16, next.ifindex);
    b.u32(RTA_PRIORITY as u16, priority);
    put_cacheinfo(&mut b, expires);
    b.u8(RTA_PREF as u16, 0);
    if mark != 0 {
        b.u32(RTA_MARK as u16, mark);
    }
    b.u32(RTA_UID as u16, uid);
    req.reply(b.finish());
    Ok(())
}

/// The dump of `RTM_GETROUTE`, as `inet6_dump_fib` of Linux with the checks of
/// `ip_valid_fib_dump_req`.
fn dump_routes(req: &Request<'_>) -> Result<Vec<Vec<u8>>> {
    let (mut table, mut protocol, mut kind, mut oif, mut rflags) = (0, 0, 0, 0, 0);
    let p = req.payload();
    if req.strict {
        let (h, a) = req.parse(RTMSG_LEN, RTA_MAX)?;
        if h[1] != 0 || h[2] != 0 || h[3] != 0 || h[6] != 0 {
            return Err(Errno::EINVAL);
        }
        rflags = u32_at(h, 8);
        if rflags & !(RTM_F_CLONED | RTM_F_PREFIX) != 0 {
            return Err(Errno::EINVAL);
        }
        protocol = h[5];
        kind = h[7];
        table = u32::from(h[4]);
        for (ty, _) in attrs(&p[RTMSG_LEN..]) {
            match u32::from(ty) {
                RTA_TABLE => table = a.u32(RTA_TABLE)?.unwrap_or(0),
                RTA_OIF => {
                    oif = a.u32(RTA_OIF)?.unwrap_or(0);
                    dev::by_index(oif).ok_or(Errno::ENODEV)?;
                }
                _ => return Err(Errno::EINVAL),
            }
        }
    } else if p.len() >= RTMSG_LEN {
        rflags = u32_at(p, 8) & (RTM_F_CLONED | RTM_F_PREFIX);
    }
    let filtered = rflags != 0 || protocol != 0 || kind != 0 || table != 0 || oif != 0;
    let mut flags = NLM_F_MULTI;
    if req.strict && filtered {
        req.set_filtered();
        flags |= NLM_F_DUMP_FILTERED;
    }
    // The kernel has no cache of the routes.
    if rflags & RTM_F_CLONED != 0 {
        return Ok(Vec::new());
    }
    let t = ROUTES6.lock();
    if table != 0 && !t.has_table(table) {
        return if p.first() == Some(&(AF_INET6 as u8)) {
            Err(Errno::ENOENT)
        } else {
            Ok(Vec::new())
        };
    }
    Ok(t.routes()
        .iter()
        .filter(|r| table == 0 || r.table == table)
        .filter(|r| protocol == 0 || r.protocol == protocol)
        .filter(|r| kind == 0 || r.kind == kind)
        .filter(|r| oif == 0 || r.ifindex == oif)
        .filter(|r| rflags & RTM_F_PREFIX == 0 || is_prefix_route(r))
        .map(|r| fill_route(r, RTM_NEWROUTE, req.portid, req.hdr.seq, flags))
        .collect())
}

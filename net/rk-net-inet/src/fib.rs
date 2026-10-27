//! The changes of the addresses and the routes, and their netlink messages, as the parts of
//! net/ipv4/devinet.c and net/ipv4/fib_frontend.c of Linux that the ioctls, netlink and the
//! device events share.
//!
//! Each change takes the lock of the route table for a short time. The notifications go out
//! after the lock is free, because a socket that gets a message takes its own lock.

use crate::ipv4::{self, Addr};
use crate::route::{Changes, IfAddr, Link, Match, Route};
use crate::stack::{self, ROUTES};
use alloc::string::String;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::if_addr::{
    IFA_ADDRESS, IFA_BROADCAST, IFA_CACHEINFO, IFA_F_PERMANENT, IFA_FLAGS, IFA_LABEL, IFA_LOCAL,
    IFA_PROTO, IFA_RT_PRIORITY,
};
use rk_abi::native::netlink::{NLM_F_CREATE, NLM_F_EXCL};
use rk_abi::native::rtnetlink::{
    RT_SCOPE_HOST, RT_SCOPE_LINK, RT_SCOPE_NOWHERE, RT_SCOPE_UNIVERSE, RT_TABLE_COMPAT, RTA_DST,
    RTA_GATEWAY, RTA_OIF, RTA_PREFSRC, RTA_PRIORITY, RTA_TABLE, RTM_DELADDR, RTM_DELROUTE,
    RTM_NEWADDR, RTM_NEWROUTE, RTN_ANYCAST, RTN_BLACKHOLE, RTN_BROADCAST, RTN_LOCAL, RTN_MULTICAST,
    RTN_NAT, RTN_PROHIBIT, RTN_THROW, RTN_UNICAST, RTN_UNREACHABLE, RTN_XRESOLVE,
    RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV4_ROUTE,
};
use rk_net::consts::{AF_INET, IFNAMSIZ};
use rk_net::dev::{self, Event, LinkKind, NetDevice};
use rk_net::netlink::msg::Builder;
use rk_net::netlink::{self, Origin};
use rk_vfs::inode::Result;

/// The size of `struct ifaddrmsg`.
pub const IFADDR_LEN: usize = 8;
/// The size of `struct rtmsg`.
pub const RTMSG_LEN: usize = 12;

/// The time since boot in hundredths of a second, as the stamps of an address. The host has no
/// timer.
pub(crate) fn now_cs() -> u64 {
    stack::now_ms() / 10
}

/// The state of the interface `ifindex` for the routes of its addresses.
pub(crate) fn link(ifindex: u32) -> Link {
    let d = dev::by_index(ifindex);
    Link {
        ifindex,
        up: d.as_ref().is_some_and(|d| d.is_up()),
        loopback: d.is_some_and(|d| d.kind() == LinkKind::Loopback),
    }
}

/// Builds the message of an address, as `inet_fill_ifaddr` of Linux.
pub fn fill_addr(a: &IfAddr, ty: u32, portid: u32, seq: u32, flags: u32) -> Vec<u8> {
    let mut b = Builder::new(ty as u16, flags as u16, seq, portid);
    let mut h = [0u8; IFADDR_LEN];
    h[0] = AF_INET as u8;
    h[1] = a.prefix;
    h[2] = a.flags as u8;
    h[3] = a.scope;
    h[4..8].copy_from_slice(&a.ifindex.to_ne_bytes());
    b.fixed(&h);
    if a.address != ipv4::ANY {
        b.put(IFA_ADDRESS as u16, &a.address);
    }
    if a.local != ipv4::ANY {
        b.put(IFA_LOCAL as u16, &a.local);
    }
    if a.broadcast != ipv4::ANY {
        b.put(IFA_BROADCAST as u16, &a.broadcast);
    }
    if !a.label.is_empty() {
        b.str(IFA_LABEL as u16, &a.label);
    }
    if a.proto != 0 {
        b.u8(IFA_PROTO as u16, a.proto);
    }
    b.u32(IFA_FLAGS as u16, a.flags);
    if a.rt_priority != 0 {
        b.u32(IFA_RT_PRIORITY as u16, a.rt_priority);
    }
    let (preferred, valid) = lifetimes(a);
    let mut ci = [0u8; 16];
    ci[0..4].copy_from_slice(&preferred.to_ne_bytes());
    ci[4..8].copy_from_slice(&valid.to_ne_bytes());
    ci[8..12].copy_from_slice(&(a.cstamp as u32).to_ne_bytes());
    ci[12..16].copy_from_slice(&(a.tstamp as u32).to_ne_bytes());
    b.put(IFA_CACHEINFO as u16, &ci);
    b.finish()
}

/// The preferred and the valid lifetimes that are left, as `inet_fill_ifaddr` of Linux.
fn lifetimes(a: &IfAddr) -> (u32, u32) {
    use crate::route::INFINITY;
    if a.flags & IFA_F_PERMANENT != 0 {
        return (INFINITY, INFINITY);
    }
    let (mut preferred, mut valid) = (a.preferred, a.valid);
    if preferred != INFINITY {
        let gone = (now_cs().saturating_sub(a.tstamp) / 100) as u32;
        preferred = preferred.saturating_sub(gone);
        if valid != INFINITY {
            valid = valid.saturating_sub(gone);
        }
    }
    (preferred, valid)
}

/// Builds the message of a route, as `fib_dump_info` of Linux.
pub fn fill_route(r: &Route, ty: u32, portid: u32, seq: u32, flags: u32) -> Vec<u8> {
    let mut b = Builder::new(ty as u16, flags as u16, seq, portid);
    let mut h = [0u8; RTMSG_LEN];
    h[0] = AF_INET as u8;
    h[1] = r.prefix;
    h[3] = r.tos;
    h[4] = if r.table < 256 { r.table as u8 } else { RT_TABLE_COMPAT as u8 };
    h[5] = r.protocol;
    h[6] = r.scope;
    h[7] = r.kind;
    h[8..12].copy_from_slice(&r.flags.to_ne_bytes());
    b.fixed(&h);
    b.u32(RTA_TABLE as u16, r.table);
    if r.prefix != 0 {
        b.put(RTA_DST as u16, &r.dst);
    }
    if r.priority != 0 {
        b.u32(RTA_PRIORITY as u16, r.priority);
    }
    if let Some(s) = r.prefsrc {
        b.put(RTA_PREFSRC as u16, &s);
    }
    if let Some(gw) = r.gateway {
        b.put(RTA_GATEWAY as u16, &gw);
    }
    if r.ifindex != 0 {
        b.u32(RTA_OIF as u16, r.ifindex);
    }
    b.finish()
}

/// Sends the notification of an address to `RTNLGRP_IPV4_IFADDR`, as `rtmsg_ifa` of Linux.
fn notify_addr(a: &IfAddr, ty: u32, origin: Origin) {
    if netlink::has_listeners(RTNLGRP_IPV4_IFADDR) || origin.echo {
        let m = fill_addr(a, ty, origin.portid, origin.seq, 0);
        netlink::notify(RTNLGRP_IPV4_IFADDR, m, origin);
    }
}

/// Sends the notification of a route to `RTNLGRP_IPV4_ROUTE`, as `rtmsg_fib` of Linux.
fn notify_route(r: &Route, ty: u32, origin: Origin, flags: u32) {
    if netlink::has_listeners(RTNLGRP_IPV4_ROUTE) || origin.echo {
        let m = fill_route(r, ty, origin.portid, origin.seq, flags);
        netlink::notify(RTNLGRP_IPV4_ROUTE, m, origin);
    }
}

/// Sends the notifications of the routes of the kernel, as `fib_magic` does with each change.
fn notify_changes(c: &Changes) {
    for r in &c.removed {
        notify_route(r, RTM_DELROUTE, Origin::KERNEL, 0);
    }
    for r in &c.added {
        notify_route(r, RTM_NEWROUTE, Origin::KERNEL, NLM_F_CREATE | NLM_F_EXCL);
    }
}

/// Adds an address and its routes, as `__inet_insert_ifa` and `fib_add_ifaddr` of Linux.
///
/// # Errors
///
/// Gives `ENODEV` for an interface that is not there, and the errors of
/// `route::Table::insert_addr`.
pub fn add_addr(mut a: IfAddr, origin: Origin) -> Result<()> {
    if dev::by_index(a.ifindex).is_none() {
        return Err(Errno::ENODEV);
    }
    let now = now_cs();
    a.tstamp = now;
    if a.cstamp == 0 {
        a.cstamp = now;
    }
    let (a, changes) = {
        let mut t = ROUTES.lock();
        t.insert_addr(a.clone())?;
        let a = t
            .addrs_of(a.ifindex)
            .find(|o| o.local == a.local && o.prefix == a.prefix && o.address == a.address)
            .cloned()
            .unwrap_or(a);
        let changes = t.sync_link(link(a.ifindex));
        (a, changes)
    };
    notify_addr(&a, RTM_NEWADDR, origin);
    notify_changes(&changes);
    Ok(())
}

/// Changes an address that is there and sends its notification. `f` changes the address and
/// gives `false` if it is not the address to change.
pub fn update_addr(ifindex: u32, mut f: impl FnMut(&mut IfAddr) -> bool, origin: Origin) -> bool {
    let (a, changes) = {
        let mut t = ROUTES.lock();
        let Some(a) = t
            .addrs_mut()
            .iter_mut()
            .filter(|a| a.ifindex == ifindex)
            .find_map(|a| f(a).then_some(a))
        else {
            return false;
        };
        a.tstamp = now_cs();
        let a = a.clone();
        (a, t.sync_link(link(ifindex)))
    };
    notify_addr(&a, RTM_NEWADDR, origin);
    notify_changes(&changes);
    true
}

/// Removes the first address of an interface that `pred` takes, and its routes, as
/// `__inet_del_ifa` and `fib_del_ifaddr` of Linux.
///
/// # Errors
///
/// Gives `EADDRNOTAVAIL` if no address matches.
pub fn del_addr(ifindex: u32, pred: impl Fn(&IfAddr) -> bool, origin: Origin) -> Result<IfAddr> {
    let (removed, changes) = {
        let mut t = ROUTES.lock();
        let i = t
            .addrs()
            .iter()
            .position(|a| a.ifindex == ifindex && pred(a))
            .ok_or(Errno::EADDRNOTAVAIL)?;
        let removed = t.remove_addr(i);
        (removed, t.sync_link(link(ifindex)))
    };
    let n = removed.len();
    for (i, a) in removed.iter().enumerate() {
        // The secondary addresses go out without the origin of the request, as Linux does.
        notify_addr(a, RTM_DELADDR, if i + 1 == n { origin } else { Origin::KERNEL });
    }
    notify_changes(&changes);
    // An interface without addresses loses its neighbours, as `fib_disable_ip` of Linux.
    if ROUTES.lock().addrs_of(ifindex).next().is_none() {
        stack::flush_neigh(ifindex);
    }
    Ok(removed.into_iter().next_back().unwrap_or_else(|| IfAddr::new(ifindex, [0; 4], 0, "")))
}

/// Adds a route, as `fib_table_insert` of Linux, and sends its notification.
///
/// # Errors
///
/// Gives the errors of `route::Table::insert_route`.
pub fn add_route(r: Route, flags: u32, origin: Origin) -> Result<()> {
    let notify = ROUTES.lock().insert_route(r.clone(), flags)?;
    if let Some(nlflags) = notify {
        notify_route(&r, RTM_NEWROUTE, origin, nlflags);
    }
    Ok(())
}

/// Removes a route, as `fib_table_delete` of Linux, and sends its notification.
///
/// # Errors
///
/// Gives `ESRCH` if no route matches.
pub fn del_route(m: &Match, origin: Origin) -> Result<()> {
    let r = ROUTES.lock().delete_route(m)?;
    notify_route(&r, RTM_DELROUTE, origin, 0);
    Ok(())
}

/// The smallest scope of each type of route, as `fib_props` of Linux.
fn min_scope(kind: u32) -> u32 {
    match kind {
        RTN_LOCAL => RT_SCOPE_HOST,
        RTN_BROADCAST | RTN_ANYCAST => RT_SCOPE_LINK,
        RTN_NAT | RTN_XRESOLVE => RT_SCOPE_NOWHERE,
        _ => RT_SCOPE_UNIVERSE,
    }
}

/// Checks a new route and sets the interface of its next hop, as `fib_create_info` of Linux.
///
/// # Errors
///
/// Gives `EINVAL` for a type or a scope that is not valid, for a gateway or a device on a route
/// without a next hop, and for a preferred source that is not local. Gives the errors of
/// `route::Table::check_nexthop` too.
pub fn check_route(r: &mut Route) -> Result<()> {
    let kind = u32::from(r.kind);
    // `RTN_XRESOLVE` is the last type, `RTN_MAX` of Linux.
    if kind > RTN_XRESOLVE || min_scope(kind) > u32::from(r.scope) {
        return Err(Errno::EINVAL);
    }
    let t = ROUTES.lock();
    if matches!(kind, RTN_UNREACHABLE | RTN_PROHIBIT | RTN_BLACKHOLE | RTN_THROW) {
        // A route without a next hop takes no gateway and no device.
        if r.gateway.is_some() || r.ifindex != 0 {
            return Err(Errno::EINVAL);
        }
    } else {
        if !matches!(kind, RTN_UNICAST | RTN_LOCAL | RTN_BROADCAST | RTN_ANYCAST | RTN_MULTICAST)
            || u32::from(r.scope) > RT_SCOPE_HOST
        {
            return Err(Errno::EINVAL);
        }
        r.ifindex = t.check_nexthop(r, |i| dev::by_index(i).map(|d| d.is_up()))?;
    }
    if let Some(src) = r.prefsrc {
        // `fib_valid_prefsrc`: a `local` route to its own address is valid before the address.
        let own = kind == RTN_LOCAL && r.dst != ipv4::ANY && r.dst == src;
        if !own && !t.is_local(src) {
            return Err(Errno::EINVAL);
        }
    }
    Ok(())
}

/// The new label of an address after a change of the name of its device, as
/// `inetdev_changename` of Linux. The first address takes the name. The others keep the part
/// from the colon, or get `:n`.
fn new_label(name: &str, old: &str, n: usize) -> String {
    let mut label = String::from(name);
    if n == 0 {
        return label;
    }
    let suffix = match old.find(':') {
        Some(i) => String::from(&old[i..]),
        None => alloc::format!(":{n}"),
    };
    if suffix.len() + name.len() < IFNAMSIZ {
        label.push_str(&suffix);
    } else {
        label.truncate(IFNAMSIZ - suffix.len() - 1);
        label.push_str(&suffix);
    }
    label
}

/// Takes the changes of the devices, as `inetdev_event` and `fib_netdev_event` of Linux.
pub(crate) fn event(d: &NetDevice, e: Event) {
    let ifindex = d.ifindex();
    match e {
        Event::Up => {
            if d.kind() == LinkKind::Loopback {
                ROUTES.lock().set_loopback(ifindex);
                let mut a = IfAddr::new(ifindex, ipv4::LOOPBACK, 8, &d.name());
                a.scope = RT_SCOPE_HOST as u8;
                // The address can be there from an earlier time.
                let _ = add_addr(a, Origin::KERNEL);
            }
            let changes = ROUTES.lock().sync_link(link(ifindex));
            notify_changes(&changes);
        }
        Event::Down => {
            ROUTES.lock().link_down(ifindex);
            stack::flush_neigh(ifindex);
        }
        Event::Name => {
            let name = d.name();
            let mut n = 0;
            let changed: Vec<IfAddr> = {
                let mut t = ROUTES.lock();
                t.addrs_mut()
                    .iter_mut()
                    .filter(|a| a.ifindex == ifindex)
                    .map(|a| {
                        a.label = new_label(&name, &a.label, n);
                        n += 1;
                        a.clone()
                    })
                    .collect()
            };
            for a in &changed {
                notify_addr(a, RTM_NEWADDR, Origin::KERNEL);
            }
        }
        Event::Flags(_) | Event::Mtu => {}
    }
}

/// The IPv4 addresses of a device for `SIOCGIFCONF`: the label and the local address.
pub(crate) fn ifconf(ifindex: u32) -> Vec<(String, [u8; 4])> {
    ROUTES.lock().addrs_of(ifindex).map(|a| (a.label.clone(), a.local)).collect()
}

/// The values of `IFLA_INET_CONF`, from `enum IPV4_DEVCONF_*` of
/// include/uapi/linux/ip.h. rk-abigen does not read that header, thus they are here by hand.
const DEVCONF_MAX: usize = 33;
const DEVCONF_ACCEPT_REDIRECTS: usize = 4;
const DEVCONF_SECURE_REDIRECTS: usize = 5;
const DEVCONF_SEND_REDIRECTS: usize = 6;
const DEVCONF_SHARED_MEDIA: usize = 7;
const DEVCONF_ACCEPT_SOURCE_ROUTE: usize = 9;
const DEVCONF_NOXFRM: usize = 15;
const DEVCONF_NOPOLICY: usize = 16;
const DEVCONF_IGMPV2_UNSOLICITED_REPORT_INTERVAL: usize = 27;
const DEVCONF_IGMPV3_UNSOLICITED_REPORT_INTERVAL: usize = 28;
const DEVCONF_ARP_EVICT_NOCARRIER: usize = 33;

/// The attribute `IFLA_INET_CONF` of `enum IFLA_INET_*` of include/uapi/linux/if_link.h.
/// rk-abigen does not read the enum, thus it is here by hand.
const IFLA_INET_CONF: u16 = 1;

/// Adds the attributes of IPv4 to `IFLA_AF_SPEC` of a link, as `inet_fill_link_af` of Linux:
/// the configuration of the device, with the defaults of `ipv4_devconf_dflt`.
pub(crate) fn fill_link_af(d: &NetDevice, b: &mut Builder) -> bool {
    let mut conf = [0u32; DEVCONF_MAX];
    for (i, v) in [
        (DEVCONF_ACCEPT_REDIRECTS, 1),
        (DEVCONF_SECURE_REDIRECTS, 1),
        (DEVCONF_SEND_REDIRECTS, 1),
        (DEVCONF_SHARED_MEDIA, 1),
        (DEVCONF_ACCEPT_SOURCE_ROUTE, 1),
        (DEVCONF_IGMPV2_UNSOLICITED_REPORT_INTERVAL, 10000),
        (DEVCONF_IGMPV3_UNSOLICITED_REPORT_INTERVAL, 1000),
        (DEVCONF_ARP_EVICT_NOCARRIER, 1),
    ] {
        conf[i - 1] = v;
    }
    if d.kind() == LinkKind::Loopback {
        conf[DEVCONF_NOXFRM - 1] = 1;
        conf[DEVCONF_NOPOLICY - 1] = 1;
    }
    let mut data = Vec::with_capacity(DEVCONF_MAX * 4);
    for v in conf {
        data.extend_from_slice(&v.to_ne_bytes());
    }
    b.put(IFLA_INET_CONF, &data);
    true
}

/// Sets the address of an interface, as the parts of `ip=` and `ifconfig`: the address with
/// its subnet and broadcast address, and the routes.
///
/// # Errors
///
/// Gives `ENODEV` for an interface that is not there, `EINVAL` for a prefix longer than 32
/// bits, and the errors of `add_addr`.
pub fn set_addr(ifindex: u32, addr: Addr, prefix: u8) -> Result<()> {
    let d = dev::by_index(ifindex).ok_or(Errno::ENODEV)?;
    if prefix > 32 {
        return Err(Errno::EINVAL);
    }
    let mut a = IfAddr::new(ifindex, addr, prefix, &d.name());
    if d.flags() & rk_net::consts::IFF_BROADCAST != 0 {
        a.broadcast = a.default_broadcast();
    }
    if d.kind() == LinkKind::Loopback && ipv4::is_loopback(addr) {
        a.scope = RT_SCOPE_HOST as u8;
    }
    add_addr(a, Origin::KERNEL)
}

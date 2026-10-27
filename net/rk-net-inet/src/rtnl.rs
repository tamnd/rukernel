//! The rtnetlink messages of IPv4: the addresses, the routes and the neighbours, as the netlink
//! parts of net/ipv4/devinet.c, net/ipv4/fib_frontend.c and net/core/neighbour.c of Linux.

use crate::fib::{self, IFADDR_LEN, RTMSG_LEN};
use crate::ipv4;
use crate::neigh::Nud;
use crate::route::{
    INFINITY, IfAddr, Match, Metrics, RTAX_ADVMSS, RTAX_CC_ALGO, RTAX_FEATURE_MASK, RTAX_FEATURES,
    RTAX_HOPLIMIT, RTAX_MAX, RTAX_MTU, Route,
};
use crate::stack::{self, ROUTES};
use alloc::string::String;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::if_addr::{
    IFA_ADDRESS, IFA_BROADCAST, IFA_CACHEINFO, IFA_F_DEPRECATED, IFA_F_PERMANENT, IFA_FLAGS,
    IFA_LABEL, IFA_LOCAL, IFA_MC_USERS, IFA_PROTO, IFA_RT_PRIORITY, IFA_TARGET_NETNSID,
};
use rk_abi::native::neighbour::{
    NDA_CACHEINFO, NDA_DST, NDA_IFINDEX, NDA_LLADDR, NDA_MASTER, NDA_NDM_FLAGS_MASK, NDA_PROBES,
    NTF_PROXY, NUD_INCOMPLETE, NUD_REACHABLE, NUD_STALE,
};
use rk_abi::native::netlink::{NLM_F_DUMP_FILTERED, NLM_F_EXCL, NLM_F_MULTI, NLM_F_REPLACE};
use rk_abi::native::rtnetlink::{
    RT_SCOPE_NOWHERE, RT_SCOPE_UNIVERSE, RT_TABLE_COMPAT, RT_TABLE_MAIN, RTA_CACHEINFO,
    RTA_DEL_REASON, RTA_DPORT, RTA_DST, RTA_GATEWAY, RTA_IIF, RTA_IP_PROTO, RTA_MARK, RTA_METRICS,
    RTA_OIF, RTA_PREFSRC, RTA_PRIORITY, RTA_SPORT, RTA_SRC, RTA_TABLE, RTA_UID, RTM_DELADDR,
    RTM_DELROUTE, RTM_F_CLONED, RTM_F_FIB_MATCH, RTM_F_LOOKUP_TABLE, RTM_F_NOTIFY, RTM_F_PREFIX,
    RTM_GETADDR, RTM_GETNEIGH, RTM_GETROUTE, RTM_NEWADDR, RTM_NEWNEIGH, RTM_NEWROUTE,
    RTN_BROADCAST, RTN_LOCAL, RTN_UNICAST,
};
use rk_net::consts::{AF_INET, IFNAMSIZ};
use rk_net::dev;
use rk_net::netlink::msg::{Attrs, Builder, attrs};
use rk_net::netlink::{self, Request};
use rk_vfs::inode::Result;

/// The last attribute of an address, `IFA_MAX` of Linux. rk-abigen does not give the `MAX`
/// values of the enums.
const IFA_MAX: u16 = IFA_MC_USERS as u16;
/// The last attribute of a route, `RTA_MAX` of Linux.
const RTA_MAX: u16 = RTA_DEL_REASON as u16;
/// The last attribute of a neighbour, `NDA_MAX` of Linux.
const NDA_MAX: u16 = NDA_NDM_FLAGS_MASK as u16;
/// The size of `struct ndmsg`.
const NDMSG_LEN: usize = 12;
/// The size of `struct ifa_cacheinfo`.
const CACHEINFO_LEN: usize = 16;
/// The size of `struct rta_cacheinfo`.
const RTA_CACHEINFO_LEN: usize = 32;
/// The flag of a route to a local address, `RTCF_LOCAL` of include/uapi/linux/in_route.h.
/// rk-abigen does not read this header, so the value is written by hand.
const RTCF_LOCAL: u32 = 0x8000_0000;
/// The flag of a route to a broadcast address, `RTCF_BROADCAST` of in_route.h.
const RTCF_BROADCAST: u32 = 0x1000_0000;
/// The bits of the type of service that a lookup uses, `INET_DSCP_MASK` of Linux.
const DSCP_MASK: u8 = 0xfc;

fn u32_at(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).map_or(0, |v| u32::from_ne_bytes([v[0], v[1], v[2], v[3]]))
}

/// Registers the handlers of IPv4. The stack calls this one time at boot.
pub(crate) fn init() {
    let inet = AF_INET as u8;
    netlink::register(inet, RTM_NEWADDR, Some(newaddr), None, false);
    netlink::register(inet, RTM_DELADDR, Some(deladdr), None, false);
    netlink::register(inet, RTM_GETADDR, None, Some(dump_addrs), true);
    netlink::register(inet, RTM_NEWROUTE, Some(newroute), None, false);
    netlink::register(inet, RTM_DELROUTE, Some(delroute), None, false);
    netlink::register(inet, RTM_GETROUTE, Some(getroute), Some(dump_routes), true);
    netlink::register(0, RTM_GETNEIGH, None, Some(dump_neigh), false);
}

/// Checks the attributes of an address against `ifa_ipv4_policy` of Linux.
fn check_addr_policy(a: &Attrs<'_>) -> Result<()> {
    for ty in [IFA_LOCAL, IFA_ADDRESS, IFA_BROADCAST] {
        a.addr4(ty)?;
    }
    for ty in [IFA_FLAGS, IFA_RT_PRIORITY, IFA_TARGET_NETNSID] {
        a.u32(ty)?;
    }
    a.u8(IFA_PROTO)?;
    if a.str(IFA_LABEL).is_some_and(|l| l.len() >= IFNAMSIZ) {
        return Err(Errno::ERANGE);
    }
    if a.get(IFA_CACHEINFO).is_some_and(|c| c.len() < CACHEINFO_LEN) {
        return Err(Errno::ERANGE);
    }
    Ok(())
}

/// Sets the lifetimes of an address, as `set_ifa_lifetime` of Linux.
fn set_lifetime(a: &mut IfAddr, valid: u32, preferred: u32) {
    a.flags &= !(IFA_F_PERMANENT | IFA_F_DEPRECATED);
    if valid == INFINITY {
        a.flags |= IFA_F_PERMANENT;
    }
    a.valid = valid;
    if preferred == 0 {
        a.flags |= IFA_F_DEPRECATED;
    }
    a.preferred = preferred;
}

/// `RTM_NEWADDR`, as `inet_rtm_newaddr` of Linux.
fn newaddr(req: &Request<'_>) -> Result<()> {
    let (h, a) = req.parse(IFADDR_LEN, IFA_MAX)?;
    check_addr_policy(&a)?;
    let prefix = h[1];
    let Some(local) = a.addr4(IFA_LOCAL)? else { return Err(Errno::EINVAL) };
    if prefix > 32 {
        return Err(Errno::EINVAL);
    }
    let ifindex = u32_at(h, 4);
    let d = dev::by_index(ifindex).ok_or(Errno::ENODEV)?;
    let label = match a.str(IFA_LABEL) {
        Some(l) => String::from_utf8_lossy(l).into_owned(),
        None => d.name(),
    };
    let mut ifa = IfAddr::new(ifindex, local, prefix, &label);
    ifa.address = a.addr4(IFA_ADDRESS)?.unwrap_or(local);
    ifa.broadcast = a.addr4(IFA_BROADCAST)?.unwrap_or(ipv4::ANY);
    ifa.flags = a.u32(IFA_FLAGS)?.unwrap_or(u32::from(h[2]));
    ifa.scope = h[3];
    ifa.rt_priority = a.u32(IFA_RT_PRIORITY)?.unwrap_or(0);
    ifa.proto = a.u8(IFA_PROTO)?.unwrap_or(0);
    let (mut valid, mut preferred) = (INFINITY, INFINITY);
    if let Some(ci) = a.get(IFA_CACHEINFO) {
        preferred = u32_at(ci, 0);
        valid = u32_at(ci, 4);
        if valid == 0 || preferred > valid {
            return Err(Errno::EINVAL);
        }
    }
    set_lifetime(&mut ifa, valid, preferred);
    let origin = req.origin();
    // `find_matching_ifa`: the same subnet and the same local address.
    let same =
        |o: &IfAddr| o.prefix == ifa.prefix && o.contains(ifa.address) && o.local == ifa.local;
    let exists = ROUTES.lock().addrs_of(ifindex).any(same);
    if !exists {
        // `__inet_insert_ifa` takes an address 0.0.0.0 and does nothing.
        if local == ipv4::ANY {
            return Ok(());
        }
        return fib::add_addr(ifa, origin);
    }
    let flags = u32::from(req.hdr.flags);
    if flags & NLM_F_EXCL != 0 || flags & NLM_F_REPLACE == 0 {
        return Err(Errno::EEXIST);
    }
    fib::update_addr(
        ifindex,
        |o| {
            if !same(o) {
                return false;
            }
            o.rt_priority = ifa.rt_priority;
            o.proto = ifa.proto;
            set_lifetime(o, valid, preferred);
            true
        },
        origin,
    );
    Ok(())
}

/// `RTM_DELADDR`, as `inet_rtm_deladdr` of Linux: the first address that matches the local
/// address, the label and the subnet of the request goes away.
fn deladdr(req: &Request<'_>) -> Result<()> {
    let (h, a) = req.parse(IFADDR_LEN, IFA_MAX)?;
    check_addr_policy(&a)?;
    let ifindex = u32_at(h, 4);
    dev::by_index(ifindex).ok_or(Errno::ENODEV)?;
    let local = a.addr4(IFA_LOCAL)?;
    let label = a.str(IFA_LABEL);
    let address = a.addr4(IFA_ADDRESS)?;
    let prefix = h[1];
    fib::del_addr(
        ifindex,
        |o| {
            local.is_none_or(|l| l == o.local)
                && label.is_none_or(|l| l == o.label.as_bytes())
                && address.is_none_or(|x| prefix == o.prefix && o.contains(x))
        },
        req.origin(),
    )?;
    Ok(())
}

/// The dump of `RTM_GETADDR`, as `inet_dump_ifaddr` of Linux.
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
    let t = ROUTES.lock();
    Ok(t.addrs()
        .iter()
        .filter(|a| ifindex == 0 || a.ifindex == ifindex)
        .map(|a| fib::fill_addr(a, RTM_NEWADDR, req.portid, req.hdr.seq, flags))
        .collect())
}

/// The metrics of an `RTA_METRICS` attribute, as `ip_metrics_convert` of Linux. The kernel
/// has no choice of the congestion control for each route, so it skips `RTAX_CC_ALGO`.
fn to_metrics(b: &[u8]) -> Result<Metrics> {
    let mut m = [0; RTAX_MAX as usize];
    for (ty, v) in attrs(b) {
        if ty == 0 || ty == RTAX_CC_ALGO {
            continue;
        }
        if ty > RTAX_MAX || v.len() != 4 {
            return Err(Errno::EINVAL);
        }
        let mut v = u32_at(v, 0);
        match ty {
            RTAX_ADVMSS => v = v.min(65535 - 40),
            RTAX_MTU => v = v.min(65535 - 15),
            RTAX_HOPLIMIT => v = v.min(255),
            RTAX_FEATURES if v & !RTAX_FEATURE_MASK != 0 => return Err(Errno::EINVAL),
            _ => {}
        }
        m[usize::from(ty - 1)] = v;
    }
    Ok(m)
}

/// A route of a request, as `rtm_to_fib_config` of Linux. Gives the route with its table.
fn to_route(req: &Request<'_>) -> Result<Route> {
    let (h, a) = req.parse(RTMSG_LEN, RTA_MAX)?;
    for ty in [RTA_DST, RTA_GATEWAY, RTA_PREFSRC] {
        a.addr4(ty)?;
    }
    for ty in [RTA_OIF, RTA_PRIORITY, RTA_TABLE] {
        a.u32(ty)?;
    }
    let mut table = a.u32(RTA_TABLE)?.unwrap_or(u32::from(h[4]));
    if table == 0 {
        table = RT_TABLE_MAIN;
    }
    let prefix = h[1];
    let dst = a.addr4(RTA_DST)?.unwrap_or(ipv4::ANY);
    // `fib_table_insert` and `fib_table_delete` take no bits after the prefix.
    if prefix > 32 || ipv4::prefix(dst, prefix) != dst {
        return Err(Errno::EINVAL);
    }
    Ok(Route {
        table,
        dst,
        prefix,
        tos: h[3],
        priority: a.u32(RTA_PRIORITY)?.unwrap_or(0),
        kind: h[7],
        scope: h[6],
        protocol: h[5],
        prefsrc: a.addr4(RTA_PREFSRC)?.filter(|s| *s != ipv4::ANY),
        gateway: a.addr4(RTA_GATEWAY)?.filter(|g| *g != ipv4::ANY),
        ifindex: a.u32(RTA_OIF)?.unwrap_or(0),
        flags: u32_at(h, 8),
        metrics: a.get(RTA_METRICS).map_or(Ok([0; RTAX_MAX as usize]), to_metrics)?,
    })
}

/// `RTM_NEWROUTE`, as `inet_rtm_newroute` of Linux.
fn newroute(req: &Request<'_>) -> Result<()> {
    let mut r = to_route(req)?;
    fib::check_route(&mut r)?;
    fib::add_route(r, u32::from(req.hdr.flags), req.origin())
}

/// `RTM_DELROUTE`, as `inet_rtm_delroute` of Linux.
fn delroute(req: &Request<'_>) -> Result<()> {
    let r = to_route(req)?;
    let nonzero = |v: u8| (v != 0).then_some(v);
    let m = Match {
        table: r.table,
        dst: r.dst,
        prefix: r.prefix,
        tos: r.tos,
        kind: nonzero(r.kind),
        scope: (r.scope != RT_SCOPE_NOWHERE as u8).then_some(r.scope),
        protocol: nonzero(r.protocol),
        prefsrc: r.prefsrc,
        gateway: r.gateway,
        ifindex: (r.ifindex != 0).then_some(r.ifindex),
        priority: (r.priority != 0).then_some(r.priority),
    };
    fib::del_route(&m, req.origin())
}

/// `RTM_GETROUTE` for one destination, as `inet_rtm_getroute` and `rt_fill_info` of Linux,
/// with the checks of `inet_rtm_valid_getroute_req`. The kernel does not forward, so a request
/// with an input interface gets `EOPNOTSUPP`.
fn getroute(req: &Request<'_>) -> Result<()> {
    let (h, a) = req.parse(RTMSG_LEN, RTA_MAX)?;
    let rflags = u32_at(h, 8);
    if req.strict {
        let len_ok = |l: u8| l == 0 || l == 32;
        if !len_ok(h[1]) || !len_ok(h[2]) || h[4] != 0 || h[5] != 0 || h[6] != 0 || h[7] != 0 {
            return Err(Errno::EINVAL);
        }
        if rflags & !(RTM_F_NOTIFY | RTM_F_LOOKUP_TABLE | RTM_F_FIB_MATCH) != 0 {
            return Err(Errno::EINVAL);
        }
        let allowed = [
            RTA_IIF,
            RTA_OIF,
            RTA_SRC,
            RTA_DST,
            RTA_IP_PROTO,
            RTA_SPORT,
            RTA_DPORT,
            RTA_MARK,
            RTA_UID,
        ];
        for (ty, _) in attrs(&req.payload()[RTMSG_LEN..]) {
            if !allowed.contains(&u32::from(ty)) {
                return Err(Errno::EINVAL);
            }
        }
    }
    for ty in [RTA_SRC, RTA_DST] {
        a.addr4(ty)?;
    }
    for ty in [RTA_IIF, RTA_OIF, RTA_MARK, RTA_UID] {
        a.u32(ty)?;
    }
    if a.u32(RTA_IIF)?.unwrap_or(0) != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let src = a.addr4(RTA_SRC)?.unwrap_or(ipv4::ANY);
    let dst = a.addr4(RTA_DST)?.unwrap_or(ipv4::ANY);
    let oif = a.u32(RTA_OIF)?.unwrap_or(0);
    if oif != 0 {
        dev::by_index(oif).ok_or(Errno::ENODEV)?;
    }
    let uid = a.u32(RTA_UID)?.unwrap_or_else(|| rk_vfs::cred::current().uid);
    let mark = a.u32(RTA_MARK)?.unwrap_or(0);
    let t = ROUTES.lock();
    if src != ipv4::ANY && !t.is_local(src) {
        return Err(Errno::EINVAL);
    }
    // A lookup of 0.0.0.0 goes to the loopback address, as `ip_route_output_key_hash_rcu`.
    let to = if dst == ipv4::ANY { [127, 0, 0, 1] } else { dst };
    let (next, route) = t.lookup_route(to, oif)?;
    if rflags & RTM_F_FIB_MATCH != 0 {
        let r = route.ok_or(Errno::EHOSTUNREACH)?;
        let m = fib::fill_route(r, RTM_NEWROUTE, req.portid, req.hdr.seq, 0);
        drop(t);
        req.reply(m);
        return Ok(());
    }
    let kind = if next.local {
        RTN_LOCAL
    } else if next.broadcast {
        RTN_BROADCAST
    } else {
        RTN_UNICAST
    };
    let table =
        if rflags & RTM_F_LOOKUP_TABLE != 0 { route.map_or(0, |r| r.table) } else { RT_TABLE_MAIN };
    let mut cflags = RTM_F_CLONED | (rflags & RTM_F_NOTIFY);
    if next.local {
        cflags |= RTCF_LOCAL;
    }
    if next.broadcast {
        cflags |= RTCF_BROADCAST | RTCF_LOCAL;
    }
    let mut b = Builder::new(RTM_NEWROUTE as u16, 0, req.hdr.seq, req.portid);
    let mut rh = [0u8; RTMSG_LEN];
    rh[0] = AF_INET as u8;
    rh[1] = 32;
    rh[2] = if src != ipv4::ANY { 32 } else { 0 };
    rh[3] = h[3] & DSCP_MASK;
    rh[4] = if table < 256 { table as u8 } else { RT_TABLE_COMPAT as u8 };
    rh[6] = RT_SCOPE_UNIVERSE as u8;
    rh[7] = kind as u8;
    rh[8..12].copy_from_slice(&cflags.to_ne_bytes());
    b.fixed(&rh);
    b.u32(RTA_TABLE as u16, table);
    b.put(RTA_DST as u16, &dst);
    if src != ipv4::ANY {
        b.put(RTA_SRC as u16, &src);
    }
    b.u32(RTA_OIF as u16, next.ifindex);
    let prefsrc = if src != ipv4::ANY { src } else { next.src };
    if prefsrc != src {
        b.put(RTA_PREFSRC as u16, &prefsrc);
    }
    if !next.local && next.hop != to {
        b.put(RTA_GATEWAY as u16, &next.hop);
    }
    if let Some(r) = route {
        fib::put_metrics(&mut b, &r.metrics);
    }
    drop(t);
    if mark != 0 {
        b.u32(RTA_MARK as u16, mark);
    }
    b.u32(RTA_UID as u16, uid);
    // The cache entry is new: one user, no age, no expiry and no error.
    let mut ci = [0u8; RTA_CACHEINFO_LEN];
    ci[0..4].copy_from_slice(&1u32.to_ne_bytes());
    b.put(RTA_CACHEINFO as u16, &ci);
    req.reply(b.finish());
    Ok(())
}

/// The dump of `RTM_GETROUTE`, as `inet_dump_fib` of Linux with the checks of
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
    // IPv4 has no routes with a prefix flag, and the cache of the routes is empty.
    if rflags != 0 {
        return Ok(Vec::new());
    }
    let t = ROUTES.lock();
    if table != 0 && !t.has_table(table) {
        // A dump of all of the families skips a table that is not there.
        return if p.first() == Some(&(AF_INET as u8)) {
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
        .map(|r| fib::fill_route(r, RTM_NEWROUTE, req.portid, req.hdr.seq, flags))
        .collect())
}

/// The dump of `RTM_GETNEIGH`, as `neigh_dump_info` of Linux with the table of ARP.
fn dump_neigh(req: &Request<'_>) -> Result<Vec<Vec<u8>>> {
    let p = req.payload();
    let family = p.first().copied().unwrap_or(0);
    let mut ifindex = 0;
    let mut flags = NLM_F_MULTI;
    let mut proxy = false;
    if req.strict {
        let (h, a) = req.parse(NDMSG_LEN, NDA_MAX)?;
        if h[1] != 0 || h[2] != 0 || h[3] != 0 || h[8] != 0 || h[9] != 0 || h[11] != 0 {
            return Err(Errno::EINVAL);
        }
        if u32::from(h[10]) & !NTF_PROXY != 0 {
            return Err(Errno::EINVAL);
        }
        proxy = u32::from(h[10]) == NTF_PROXY;
        for (ty, _) in attrs(&p[NDMSG_LEN..]) {
            match u32::from(ty) {
                NDA_IFINDEX => ifindex = a.u32(NDA_IFINDEX)?.unwrap_or(0),
                NDA_MASTER => {
                    a.u32(NDA_MASTER)?;
                }
                _ => return Err(Errno::EINVAL),
            }
        }
        if a.has(NDA_IFINDEX) || a.has(NDA_MASTER) {
            req.set_filtered();
            flags |= NLM_F_DUMP_FILTERED;
        }
        // No device has a master, thus a filter on the master takes no entries.
        if a.has(NDA_MASTER) {
            return Ok(Vec::new());
        }
    } else if p.len() >= NDMSG_LEN {
        proxy = u32::from(p[10]) == NTF_PROXY;
    }
    if proxy || (family != 0 && family != AF_INET as u8) {
        return Ok(Vec::new());
    }
    Ok(stack::neighbours()
        .iter()
        .filter(|n| ifindex == 0 || n.ifindex == ifindex)
        .map(|n| {
            let mut b = Builder::new(RTM_NEWNEIGH as u16, flags as u16, req.hdr.seq, req.portid);
            let state = match n.state {
                Nud::Incomplete => NUD_INCOMPLETE,
                Nud::Reachable => NUD_REACHABLE,
                Nud::Stale => NUD_STALE,
            };
            let mut h = [0u8; NDMSG_LEN];
            h[0] = AF_INET as u8;
            h[4..8].copy_from_slice(&n.ifindex.to_ne_bytes());
            h[8..10].copy_from_slice(&(state as u16).to_ne_bytes());
            h[11] = RTN_UNICAST as u8;
            b.fixed(&h);
            b.put(NDA_DST as u16, &n.addr);
            if let Some(mac) = n.mac {
                b.put(NDA_LLADDR as u16, &mac.0);
            }
            b.u32(NDA_PROBES as u16, n.probes);
            // `struct nda_cacheinfo` in hundredths of a second, `clock_t` of `USER_HZ`.
            let mut ci = [0u8; 16];
            for (i, ms) in [n.confirmed, n.used, n.updated].into_iter().enumerate() {
                ci[i * 4..i * 4 + 4].copy_from_slice(&((ms / 10) as u32).to_ne_bytes());
            }
            b.put(NDA_CACHEINFO as u16, &ci);
            b.finish()
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(ty: u16, v: &[u8]) -> Vec<u8> {
        let mut b = Vec::from(((4 + v.len()) as u16).to_ne_bytes());
        b.extend_from_slice(&ty.to_ne_bytes());
        b.extend_from_slice(v);
        b
    }

    #[test]
    fn metrics_have_the_limits_of_linux() {
        let mut b = attr(RTAX_ADVMSS, &100_000u32.to_ne_bytes());
        b.extend(attr(RTAX_HOPLIMIT, &300u32.to_ne_bytes()));
        b.extend(attr(crate::route::RTAX_WINDOW, &8192u32.to_ne_bytes()));
        let m = to_metrics(&b).unwrap();
        assert_eq!(m[usize::from(RTAX_ADVMSS - 1)], 65535 - 40);
        assert_eq!(m[usize::from(RTAX_HOPLIMIT - 1)], 255);
        assert_eq!(m[usize::from(crate::route::RTAX_WINDOW - 1)], 8192);
        assert_eq!(to_metrics(&attr(RTAX_MAX + 1, &[0; 4])), Err(Errno::EINVAL));
        assert_eq!(to_metrics(&attr(RTAX_MTU, &[0; 2])), Err(Errno::EINVAL));
        assert_eq!(to_metrics(&attr(RTAX_FEATURES, &0x20u32.to_ne_bytes())), Err(Errno::EINVAL));
    }

    #[test]
    fn a_route_without_metrics_has_no_attribute() {
        let mut r = Route::new([10, 9, 0, 0], 16, Some([10, 0, 2, 2]), 2);
        let plain = fib::fill_route(&r, RTM_NEWROUTE, 0, 0, 0);
        r.metrics[usize::from(RTAX_ADVMSS - 1)] = 1360;
        let with = fib::fill_route(&r, RTM_NEWROUTE, 0, 0, 0);
        // The attribute has a header of 4 bytes and one metric of 8 bytes.
        assert_eq!(with.len(), plain.len() + 12);
    }
}

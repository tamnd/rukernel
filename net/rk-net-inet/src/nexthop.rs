//! The nexthop objects, as net/ipv4/nexthop.c of Linux.
//!
//! A nexthop object is a next hop with an ID: a gateway and a device, a blackhole, a next hop
//! of a bridge (`fdb`), or a group of other nexthops with weights. A route of IPv4 or IPv6 can
//! point to a nexthop with `RTA_NH_ID` in place of its own gateway and device. `ip nexthop`
//! changes and shows the nexthops with `RTM_NEWNEXTHOP`, `RTM_DELNEXTHOP` and
//! `RTM_GETNEXTHOP`.
//!
//! A route keeps a copy of the gateway and the device of the first path of its nexthop, for the
//! lookups. A change of the nexthop changes the copies. The messages of a route get the
//! nexthop from the table, as the compat mode of Linux: `RTA_NH_ID`, then the gateway and the
//! device or `RTA_MULTIPATH`.
//!
//! The limits: a packet through a group takes the first path, without a hash. Resilient
//! groups, encapsulations and IPv4 routes through an IPv6 nexthop give `EOPNOTSUPP`. The
//! packet counts of a group are 0. A loss of the carrier does not remove the nexthops of the
//! device. A dump with `NHA_MASTER` gives no nexthops, because the kernel has no master
//! devices.
//!
//! The lock of the nexthops comes after the lock of the IPv4 or the IPv6 routes. A function
//! that holds the lock of the nexthops never takes the lock of the routes.

use crate::addrconf;
use crate::fib;
use crate::ip::{self, Ip};
use crate::ipv4::{self, Addr};
use crate::ipv6;
use crate::route::Route;
use crate::route6::Route6;
use crate::stack::ROUTES;
use crate::stack6::ROUTES6;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::netlink::{NLA_F_NESTED, NLM_F_CREATE, NLM_F_MULTI, NLM_F_REPLACE};
use rk_abi::native::rtnetlink::{
    RT_SCOPE_HOST, RT_SCOPE_LINK, RTM_DELNEXTHOP, RTM_DELROUTE, RTM_GETNEXTHOP, RTM_NEWNEXTHOP,
    RTM_NEWROUTE, RTN_BLACKHOLE, RTN_PROHIBIT, RTN_THROW, RTN_UNREACHABLE, RTNH_F_DEAD,
    RTNH_F_LINKDOWN, RTNH_F_OFFLOAD, RTNH_F_ONLINK, RTNH_F_TRAP, RTNLGRP_NEXTHOP,
};
use rk_frame::sync::SpinLock;
use rk_net::consts::{AF_INET, AF_INET6, AF_UNSPEC};
use rk_net::dev::{self, Event, LinkKind, NetDevice};
use rk_net::netlink::msg::{Attrs, Builder};
use rk_net::netlink::policy::{self, Check, Kind as Pt, Policy};
use rk_net::netlink::{self, Origin, Request};
use rk_net::ns::PerNet;
use rk_vfs::inode::Result;

// The attributes of a nexthop, `NHA_*` of <linux/nexthop.h>. rk-abigen does not take this
// header yet, so the values are written by hand.
/// The ID of the nexthop.
const NHA_ID: u32 = 1;
/// The members of a group, an array of `struct nexthop_grp`.
const NHA_GROUP: u32 = 2;
/// The type of a group, `NEXTHOP_GRP_TYPE_*`.
const NHA_GROUP_TYPE: u32 = 3;
/// A flag: the nexthop drops the packets.
const NHA_BLACKHOLE: u32 = 4;
/// The device.
const NHA_OIF: u32 = 5;
/// The gateway.
const NHA_GATEWAY: u32 = 6;
/// The type of the encapsulation.
const NHA_ENCAP_TYPE: u32 = 7;
/// The encapsulation.
const NHA_ENCAP: u32 = 8;
/// A flag of a dump: only the groups.
const NHA_GROUPS: u32 = 9;
/// The master device of a dump.
const NHA_MASTER: u32 = 10;
/// A flag: the nexthop is for the forwarding database of a bridge.
const NHA_FDB: u32 = 11;
/// The parameters of a resilient group.
const NHA_RES_GROUP: u32 = 12;
/// The flags of an operation, `NHA_OP_FLAG_*`.
const NHA_OP_FLAGS: u32 = 14;
/// The packet counts of the members of a group.
const NHA_GROUP_STATS: u32 = 15;
/// Tells if a group counts the packets of the hardware.
const NHA_HW_STATS_ENABLE: u32 = 16;
/// Tells if the hardware counts the packets of a group.
const NHA_HW_STATS_USED: u32 = 17;
/// The UDP port of the destination of an `fdb` nexthop.
const NHA_DST_PORT: u32 = 18;
/// The last attribute, `NHA_MAX`.
const NHA_MAX: u32 = NHA_DST_PORT;
/// A member in `NHA_GROUP_STATS`.
const NHA_GROUP_STATS_ENTRY: u16 = 1;
/// The ID of the member.
const NHA_GROUP_STATS_ENTRY_ID: u16 = 1;
/// The count of the packets through the member.
const NHA_GROUP_STATS_ENTRY_PACKETS: u16 = 2;
/// The count of the packets of the hardware through the member.
const NHA_GROUP_STATS_ENTRY_PACKETS_HW: u16 = 3;
/// A flag of `NHA_OP_FLAGS`: give the packet counts of a group.
const NHA_OP_FLAG_DUMP_STATS: u32 = 1;
/// A flag of `NHA_OP_FLAGS`: give the packet counts of the hardware too.
const NHA_OP_FLAG_DUMP_HW_STATS: u32 = 2;
/// The flags of a request, `NHA_OP_FLAGS_DUMP_ALL`.
const NHA_OP_FLAGS_DUMP_ALL: u64 = 3;
/// A flag of a reply: the reserved fields of `NHA_GROUP` are 0.
const NHA_OP_FLAG_RESP_GRP_RESVD_0: u32 = 1 << 31;
/// A group with the hash of the flow, `NEXTHOP_GRP_TYPE_MPATH`.
const NEXTHOP_GRP_TYPE_MPATH: u16 = 0;
/// A resilient group, `NEXTHOP_GRP_TYPE_RES`.
const NEXTHOP_GRP_TYPE_RES: u16 = 1;
/// The last encapsulation type, `LWTUNNEL_ENCAP_MAX`.
const LWTUNNEL_ENCAP_MAX: u16 = 10;
/// The size of `struct nhmsg`.
const NHMSG_LEN: usize = 8;
/// The size of `struct nexthop_grp`.
const GRP_LEN: usize = 8;
/// The interface index of the loopback device of each namespace.
const LOOPBACK_IFINDEX: u32 = 1;
/// The flags of a path in a route message, as `fib_nexthop_info` of Linux.
const PATH_FLAGS: u32 =
    RTNH_F_DEAD | RTNH_F_LINKDOWN | RTNH_F_ONLINK | RTNH_F_OFFLOAD | RTNH_F_TRAP;

/// The policy of `RTM_NEWNEXTHOP`, `rtm_nh_policy_new` of Linux.
static NEW_POLICY: [Policy; 19] = {
    let mut p = [Policy::NONE; 19];
    p[NHA_ID as usize] = Policy::of(Pt::U32);
    p[NHA_GROUP as usize] = Policy::of(Pt::Binary);
    p[NHA_GROUP_TYPE as usize] = Policy::of(Pt::U16);
    p[NHA_BLACKHOLE as usize] = Policy::of(Pt::Flag);
    p[NHA_OIF as usize] = Policy::of(Pt::U32);
    p[NHA_GATEWAY as usize] = Policy::of(Pt::Binary);
    p[NHA_ENCAP_TYPE as usize] = Policy::of(Pt::U16);
    p[NHA_ENCAP as usize] = Policy::of(Pt::Nested);
    p[NHA_FDB as usize] = Policy::of(Pt::Flag);
    p[NHA_DST_PORT as usize] = Policy::of(Pt::Be16).check(Check::Min(1));
    p[NHA_RES_GROUP as usize] = Policy::of(Pt::Nested);
    p[NHA_HW_STATS_ENABLE as usize] = Policy::of(Pt::U32).check(Check::Max(1));
    p
};

/// The policy of `RTM_GETNEXTHOP`, `rtm_nh_policy_get` of Linux.
static GET_POLICY: [Policy; 15] = {
    let mut p = [Policy::NONE; 15];
    p[NHA_ID as usize] = Policy::of(Pt::U32);
    p[NHA_OP_FLAGS as usize] = Policy::of(Pt::U32).check(Check::Mask(NHA_OP_FLAGS_DUMP_ALL));
    p
};

/// The policy of `RTM_DELNEXTHOP`, `rtm_nh_policy_del` of Linux.
static DEL_POLICY: [Policy; 2] = {
    let mut p = [Policy::NONE; 2];
    p[NHA_ID as usize] = Policy::of(Pt::U32);
    p
};

/// The policy of a dump, `rtm_nh_policy_dump` of Linux.
static DUMP_POLICY: [Policy; 15] = {
    let mut p = [Policy::NONE; 15];
    p[NHA_OIF as usize] = Policy::of(Pt::U32);
    p[NHA_GROUPS as usize] = Policy::of(Pt::Flag);
    p[NHA_MASTER as usize] = Policy::of(Pt::U32);
    p[NHA_FDB as usize] = Policy::of(Pt::Flag);
    p[NHA_OP_FLAGS as usize] = Policy::of(Pt::U32).check(Check::Mask(NHA_OP_FLAGS_DUMP_ALL));
    p
};

/// The gateway of a nexthop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Gateway {
    /// No gateway: the destination is on the link.
    None,
    /// An IPv4 gateway.
    V4(Addr),
    /// An IPv6 gateway.
    V6(Ip),
}

/// A nexthop that is not a group, as `struct nh_info` of Linux.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Info {
    /// The family, `AF_INET` or `AF_INET6`.
    family: u8,
    /// The device, the loopback device for a blackhole, or 0 for an `fdb` nexthop.
    ifindex: u32,
    gateway: Gateway,
    /// The scope of the next hop.
    scope: u8,
    blackhole: bool,
    fdb: bool,
    /// The UDP port of an `fdb` nexthop, in the network order, or 0.
    dst_port: [u8; 2],
}

/// A group of nexthops, as `struct nh_group` of Linux.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Group {
    /// The members and their weights, from 1 to 65536 less 1.
    members: Vec<(u32, u32)>,
    fdb: bool,
    /// Tells if the group counts the packets of the hardware.
    hw_stats: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    Single(Info),
    Group(Group),
}

/// A nexthop object, as `struct nexthop` of Linux.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Nexthop {
    id: u32,
    protocol: u8,
    /// The flags `RTNH_F_*`.
    flags: u32,
    kind: Kind,
}

impl Nexthop {
    fn info(&self) -> Option<&Info> {
        match &self.kind {
            Kind::Single(i) => Some(i),
            Kind::Group(_) => None,
        }
    }

    fn group(&self) -> Option<&Group> {
        match &self.kind {
            Kind::Single(_) => None,
            Kind::Group(g) => Some(g),
        }
    }

    fn is_fdb(&self) -> bool {
        match &self.kind {
            Kind::Single(i) => i.fdb,
            Kind::Group(g) => g.fdb,
        }
    }

    fn is_blackhole(&self) -> bool {
        self.info().is_some_and(|i| i.blackhole)
    }
}

/// The nexthops of a namespace.
pub(crate) struct Table {
    map: BTreeMap<u32, Nexthop>,
    /// The last ID that the kernel gave, `last_id_allocated` of Linux.
    last_id: u32,
}

impl Table {
    const fn new() -> Self {
        Self { map: BTreeMap::new(), last_id: 0 }
    }

    /// The groups with the member `id`, as the `grp_list` of Linux.
    fn parents(&self, id: u32) -> Vec<u32> {
        self.map
            .values()
            .filter(|n| n.group().is_some_and(|g| g.members.iter().any(|m| m.0 == id)))
            .map(|n| n.id)
            .collect()
    }

    /// The first member of a group, or the nexthop itself.
    fn first<'a>(&'a self, nh: &'a Nexthop) -> Option<&'a Info> {
        match &nh.kind {
            Kind::Single(i) => Some(i),
            Kind::Group(g) => g.members.first().and_then(|m| self.map.get(&m.0)?.info()),
        }
    }

    /// Tells if a group has an IPv4 member, `has_v4` of Linux.
    fn has_v4(&self, g: &Group) -> bool {
        g.members.iter().any(|m| {
            self.map.get(&m.0).and_then(Nexthop::info).is_some_and(|i| i.family == AF_INET as u8)
        })
    }

    /// The paths of a nexthop for a route message.
    fn paths(&self, nh: &Nexthop) -> Vec<Path> {
        let path = |n: &Nexthop, weight: u32| {
            n.info().map(|i| Path {
                gateway: i.gateway,
                ifindex: i.ifindex,
                flags: (n.flags & PATH_FLAGS) as u8,
                weight,
            })
        };
        match &nh.kind {
            Kind::Single(_) => path(nh, 1).into_iter().collect(),
            Kind::Group(g) => {
                g.members.iter().filter_map(|m| path(self.map.get(&m.0)?, m.1)).collect()
            }
        }
    }

    /// The next free ID after the last one, as `nh_find_unused_id` of Linux, or 0.
    fn unused_id(&mut self) -> u32 {
        let start = self.last_id;
        loop {
            self.last_id = self.last_id.wrapping_add(1);
            if self.last_id == start {
                return 0;
            }
            if !self.map.contains_key(&self.last_id) {
                return self.last_id;
            }
        }
    }
}

/// The nexthops of each namespace.
pub(crate) static NEXTHOPS: PerNet<SpinLock<Table>> = PerNet::new(|| SpinLock::new(Table::new()));

/// A path of a route through a nexthop, for the route messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Path {
    pub gateway: Gateway,
    pub ifindex: u32,
    /// The flags `RTNH_F_*` of the path.
    pub flags: u8,
    /// The weight, from 1.
    pub weight: u32,
}

/// The nexthop of a route for its messages, as the compat mode of Linux.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Compat {
    /// The nexthop drops the packets: the route shows the type `blackhole`.
    pub blackhole: bool,
    /// The nexthop is a group.
    pub group: bool,
    pub paths: Vec<Path>,
}

/// The nexthop `id` of a route for its messages, or `None` if it is not there.
pub(crate) fn compat(id: u32) -> Option<Compat> {
    let t = NEXTHOPS.lock();
    let nh = t.map.get(&id)?;
    Some(Compat { blackhole: nh.is_blackhole(), group: nh.group().is_some(), paths: t.paths(nh) })
}

/// Adds the paths of a route as `RTA_MULTIPATH`, as `nexthop_mpath_fill_node` of Linux: a
/// `struct rtnexthop` and the gateway for each path. An IPv6 gateway of an IPv4 route is an
/// `RTA_VIA`.
pub(crate) fn put_multipath(b: &mut Builder, paths: &[Path], family: u32) {
    let mut m = Vec::new();
    for p in paths {
        let at = m.len();
        m.extend_from_slice(&[0, 0, p.flags, (p.weight - 1) as u8]);
        m.extend_from_slice(&p.ifindex.to_ne_bytes());
        match p.gateway {
            Gateway::None => {}
            Gateway::V4(a) => put_raw(&mut m, rk_abi::native::rtnetlink::RTA_GATEWAY as u16, &a),
            Gateway::V6(a) if family == AF_INET6 => {
                put_raw(&mut m, rk_abi::native::rtnetlink::RTA_GATEWAY as u16, &a);
            }
            Gateway::V6(a) => {
                let mut via = Vec::from((AF_INET6 as u16).to_ne_bytes());
                via.extend_from_slice(&a);
                put_raw(&mut m, rk_abi::native::rtnetlink::RTA_VIA as u16, &via);
            }
        }
        let len = (m.len() - at) as u16;
        m[at..at + 2].copy_from_slice(&len.to_ne_bytes());
    }
    b.put(rk_abi::native::rtnetlink::RTA_MULTIPATH as u16, &m);
}

/// Adds the gateway and the device of one path, as `fib_nexthop_info` of Linux.
pub(crate) fn put_path(b: &mut Builder, p: &Path, family: u32) {
    use rk_abi::native::rtnetlink::{RTA_GATEWAY, RTA_OIF, RTA_VIA};
    match p.gateway {
        Gateway::None => {}
        Gateway::V4(a) => {
            b.put(RTA_GATEWAY as u16, &a);
        }
        Gateway::V6(a) if family == AF_INET6 => {
            b.put(RTA_GATEWAY as u16, &a);
        }
        Gateway::V6(a) => {
            let mut via = Vec::from((AF_INET6 as u16).to_ne_bytes());
            via.extend_from_slice(&a);
            b.put(RTA_VIA as u16, &via);
        }
    }
    if p.ifindex != 0 {
        b.u32(RTA_OIF as u16, p.ifindex);
    }
}

/// Adds an attribute without a builder.
fn put_raw(m: &mut Vec<u8>, ty: u16, data: &[u8]) {
    m.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
    m.extend_from_slice(&ty.to_ne_bytes());
    m.extend_from_slice(data);
    m.resize(m.len().next_multiple_of(4), 0);
}

/// Copies the first path of the nexthop of an IPv4 route to the route, for the lookups. Gives
/// `None` if the nexthop is not there.
fn apply4(t: &Table, r: &mut Route) -> Option<()> {
    let nh = t.map.get(&r.nhid)?;
    let i = t.first(nh)?;
    r.gateway = match i.gateway {
        Gateway::V4(a) => Some(a),
        _ => None,
    };
    r.ifindex = i.ifindex;
    r.blackhole = nh.is_blackhole();
    Some(())
}

/// Copies the first path of the nexthop of an IPv6 route to the route.
fn apply6(t: &Table, r: &mut Route6) -> Option<()> {
    let nh = t.map.get(&r.nhid)?;
    let i = t.first(nh)?;
    r.gateway = match i.gateway {
        Gateway::V6(a) => Some(a),
        _ => None,
    };
    r.ifindex = i.ifindex;
    r.blackhole = nh.is_blackhole();
    Some(())
}

/// Copies the nexthop of a new IPv4 route again, under the lock of the routes, for
/// `fib::add_route`.
///
/// # Errors
///
/// Gives `EINVAL` if the nexthop went away.
pub(crate) fn refresh4(r: &mut Route) -> Result<()> {
    apply4(&NEXTHOPS.lock(), r).ok_or(Errno::EINVAL)
}

/// Copies the nexthop of a new IPv6 route again, under the lock of the routes.
///
/// # Errors
///
/// Gives `EINVAL` if the nexthop went away.
pub(crate) fn refresh6(r: &mut Route6) -> Result<()> {
    apply6(&NEXTHOPS.lock(), r).ok_or(Errno::EINVAL)
}

/// Checks that the nexthop of a route is there, as `fib_create_info`, `inet_rtm_delroute` and
/// the IPv6 functions of Linux.
///
/// # Errors
///
/// Gives `EINVAL` with "Nexthop id does not exist".
pub(crate) fn exists(req: &Request<'_>, id: u32) -> Result<()> {
    if NEXTHOPS.lock().map.contains_key(&id) {
        Ok(())
    } else {
        Err(req.error("Nexthop id does not exist", Errno::EINVAL))
    }
}

/// Tells if a route of the type `kind` rejects the packets, `fib_props[].error` of Linux.
fn rejects(kind: u8) -> bool {
    matches!(u32::from(kind), RTN_UNREACHABLE | RTN_PROHIBIT | RTN_BLACKHOLE | RTN_THROW)
}

/// Checks the nexthop of a new IPv4 route with the scope `scope`, as `fib_check_nexthop` of
/// Linux.
fn check_nexthop4(t: &Table, nh: &Nexthop, scope: u8) -> core::result::Result<(), &'static str> {
    if nh.is_fdb() {
        return Err("Route cannot point to a fdb nexthop");
    }
    if nh.group().is_some() && scope == RT_SCOPE_HOST as u8 {
        return Err("Route with host scope can not have multiple nexthops");
    }
    // All of the members of a group have the same scope, as `nexthop_check_scope` of Linux.
    let Some(i) = t.first(nh) else { return Ok(()) };
    let flags = match &nh.kind {
        Kind::Single(_) => nh.flags,
        Kind::Group(g) => g.members.first().and_then(|m| t.map.get(&m.0)).map_or(0, |n| n.flags),
    };
    if scope == RT_SCOPE_HOST as u8 && i.gateway != Gateway::None {
        return Err("Route with host scope can not have a gateway");
    }
    if flags & RTNH_F_ONLINK != 0 && scope >= RT_SCOPE_LINK as u8 {
        return Err("Scope mismatch with nexthop");
    }
    Ok(())
}

/// Checks the nexthop of a new IPv6 route, as `fib6_check_nexthop` of Linux.
fn check_nexthop6(t: &Table, nh: &Nexthop) -> core::result::Result<(), &'static str> {
    let v4 = match &nh.kind {
        Kind::Single(i) => i.family == AF_INET as u8,
        Kind::Group(g) => t.has_v4(g),
    };
    if v4 {
        return Err("IPv6 routes can not use an IPv4 nexthop");
    }
    if nh.is_fdb() {
        return Err("Route cannot point to a fdb nexthop");
    }
    Ok(())
}

/// Checks the nexthop of a new IPv4 route and copies its first path to the route, as the
/// nexthop part of `fib_create_info` of Linux. The route has passed `fib::check_route`.
///
/// # Errors
///
/// Gives `EINVAL` with the message of Linux for a nexthop that the route can not use, and
/// `EOPNOTSUPP` for an IPv6 gateway.
pub(crate) fn check_route4(req: &Request<'_>, r: &mut Route) -> Result<()> {
    let t = NEXTHOPS.lock();
    let nh =
        t.map.get(&r.nhid).ok_or_else(|| req.error("Nexthop id does not exist", Errno::EINVAL))?;
    if !rejects(r.kind) {
        check_nexthop4(&t, nh, r.scope).map_err(|m| req.error(m, Errno::EINVAL))?;
    }
    if t.paths(nh).iter().any(|p| matches!(p.gateway, Gateway::V6(_))) {
        return Err(
            req.error("IPv4 routes through IPv6 gateways are not supported", Errno::EOPNOTSUPP)
        );
    }
    apply4(&t, r);
    Ok(())
}

/// Checks the nexthop of a new IPv6 route and copies its first path to the route, as the
/// nexthop part of `ip6_route_info_create` of Linux.
///
/// # Errors
///
/// Gives `EINVAL` with the message of Linux for a nexthop that the route can not use.
pub(crate) fn check_route6(req: &Request<'_>, r: &mut Route6) -> Result<()> {
    let t = NEXTHOPS.lock();
    let nh =
        t.map.get(&r.nhid).ok_or_else(|| req.error("Nexthop id does not exist", Errno::EINVAL))?;
    check_nexthop6(&t, nh).map_err(|m| req.error(m, Errno::EINVAL))?;
    apply6(&t, r);
    Ok(())
}

/// Registers the handlers of the nexthop messages.
pub(crate) fn init() {
    let unspec = AF_UNSPEC as u8;
    netlink::register(unspec, RTM_NEWNEXTHOP, Some(newnexthop), None, false);
    netlink::register(unspec, RTM_DELNEXTHOP, Some(delnexthop), None, false);
    netlink::register(unspec, RTM_GETNEXTHOP, Some(getnexthop), Some(dump), false);
}

/// Clears the nexthops of a namespace that stops.
pub(crate) fn ns_exit() {
    NEXTHOPS.reset();
}

/// Builds the message of a nexthop, as `nh_fill_node` of Linux.
fn fill(nh: &Nexthop, ty: u32, seq: u32, pid: u32, flags: u32, op: u32) -> Vec<u8> {
    let mut b = Builder::new(ty as u16, flags as u16, seq, pid);
    let mut h = [0u8; NHMSG_LEN];
    h[2] = nh.protocol;
    h[4..8].copy_from_slice(&nh.flags.to_ne_bytes());
    if let Kind::Single(i) = &nh.kind {
        h[0] = i.family;
        if !i.blackhole {
            h[1] = i.scope;
        }
    }
    b.fixed(&h);
    b.u32(NHA_ID as u16, nh.id);
    match &nh.kind {
        Kind::Group(g) => {
            if g.fdb {
                b.put(NHA_FDB as u16, &[]);
            }
            b.u16(NHA_GROUP_TYPE as u16, NEXTHOP_GRP_TYPE_MPATH);
            let mut a = Vec::with_capacity(g.members.len() * GRP_LEN);
            for &(id, w) in &g.members {
                let w = w - 1;
                a.extend_from_slice(&id.to_ne_bytes());
                a.extend_from_slice(&[w as u8, (w >> 8) as u8, 0, 0]);
            }
            b.put(NHA_GROUP as u16, &a);
            if op & NHA_OP_FLAG_DUMP_STATS != 0 {
                b.u32(NHA_HW_STATS_ENABLE as u16, u32::from(g.hw_stats));
                if op & NHA_OP_FLAG_DUMP_HW_STATS != 0 && g.hw_stats {
                    b.u32(NHA_HW_STATS_USED as u16, 0);
                }
                let stats = b.nest(NHA_GROUP_STATS as u16 | NLA_F_NESTED as u16);
                for &(id, _) in &g.members {
                    let e = b.nest(NHA_GROUP_STATS_ENTRY | NLA_F_NESTED as u16);
                    b.u32(NHA_GROUP_STATS_ENTRY_ID, id);
                    b.uint(NHA_GROUP_STATS_ENTRY_PACKETS, 0);
                    if op & NHA_OP_FLAG_DUMP_HW_STATS != 0 {
                        b.uint(NHA_GROUP_STATS_ENTRY_PACKETS_HW, 0);
                    }
                    b.end_nest(e);
                }
                b.end_nest(stats);
            }
            b.u32(NHA_OP_FLAGS as u16, NHA_OP_FLAG_RESP_GRP_RESVD_0);
        }
        Kind::Single(i) => {
            if i.blackhole {
                b.put(NHA_BLACKHOLE as u16, &[]);
            } else {
                if i.fdb {
                    b.put(NHA_FDB as u16, &[]);
                    if i.dst_port != [0; 2] {
                        b.put(NHA_DST_PORT as u16, &i.dst_port);
                    }
                } else if i.ifindex != 0 {
                    b.u32(NHA_OIF as u16, i.ifindex);
                }
                match i.gateway {
                    Gateway::None => {}
                    Gateway::V4(a) => {
                        b.put(NHA_GATEWAY as u16, &a);
                    }
                    Gateway::V6(a) => {
                        b.put(NHA_GATEWAY as u16, &a);
                    }
                }
            }
        }
    }
    b.finish()
}

/// The request of `RTM_NEWNEXTHOP`, as `struct nh_config` of Linux.
#[derive(Default)]
struct Config {
    id: u32,
    family: u8,
    protocol: u8,
    flags: u32,
    /// The members of a group and their weights.
    group: Option<Vec<(u32, u32)>>,
    fdb: bool,
    hw_stats: bool,
    blackhole: bool,
    oif: Option<u32>,
    gateway: Option<Gateway>,
    dst_port: [u8; 2],
}

/// A `u16` attribute.
fn u16_of(a: &Attrs<'_>, ty: u32) -> Option<u16> {
    a.get(ty).filter(|d| d.len() >= 2).map(|d| u16::from_ne_bytes([d[0], d[1]]))
}

/// Checks the attribute `NHA_GROUP`, as `nh_check_attr_group` of Linux, and gives the members.
fn check_group(
    a: &Attrs<'_>,
    g: &[u8],
    ty: u16,
) -> core::result::Result<Vec<(u32, u32)>, &'static str> {
    if g.is_empty() || g.len() % GRP_LEN != 0 {
        return Err("Invalid length for nexthop group attribute");
    }
    let mut members: Vec<(u32, u32)> = Vec::new();
    for e in g.chunks_exact(GRP_LEN) {
        if e[6] != 0 || e[7] != 0 {
            return Err("Reserved field in nexthop_grp must be 0");
        }
        // `nexthop_grp_weight` of Linux gives a `u16`: 65536 is 0.
        let w = ((u16::from(e[5]) << 8) | u16::from(e[4])).wrapping_add(1);
        if w == 0 {
            return Err("Invalid value for weight");
        }
        members.push((u32::from_ne_bytes([e[0], e[1], e[2], e[3]]), u32::from(w)));
    }
    for (i, m) in members.iter().enumerate() {
        if members[i + 1..].iter().any(|o| o.0 == m.0) {
            return Err("Nexthop id can not be used twice in a group");
        }
    }
    for t in NHA_GROUP_TYPE + 1..=NHA_MAX {
        if !a.has(t) {
            continue;
        }
        match t {
            NHA_HW_STATS_ENABLE | NHA_FDB => continue,
            NHA_RES_GROUP if ty == NEXTHOP_GRP_TYPE_RES => continue,
            _ => return Err("No other attributes can be set in nexthop groups"),
        }
    }
    Ok(members)
}

/// Parses `RTM_NEWNEXTHOP`, as `rtm_to_nh_config` of Linux.
fn to_config(req: &Request<'_>, h: &[u8], a: &Attrs<'_>) -> Result<Config> {
    let inval = |text| req.error(text, Errno::EINVAL);
    let (family, scope, protocol, resvd) = (h[0], h[1], h[2], h[3]);
    let flags = u32::from_ne_bytes([h[4], h[5], h[6], h[7]]);
    if resvd != 0 || scope != 0 {
        return Err(inval("Invalid values in ancillary header"));
    }
    if flags & !RTNH_F_ONLINK != 0 {
        return Err(inval("Invalid nexthop flags in ancillary header"));
    }
    match u32::from(family) {
        AF_INET | AF_INET6 => {}
        AF_UNSPEC if a.has(NHA_GROUP) => {}
        _ => return Err(inval("Invalid address family")),
    }
    let mut c = Config { family, protocol, flags, ..Config::default() };
    c.id = a.u32(NHA_ID)?.unwrap_or(0);
    if a.has(NHA_FDB) {
        if [NHA_OIF, NHA_BLACKHOLE, NHA_ENCAP, NHA_ENCAP_TYPE].iter().any(|t| a.has(*t)) {
            return Err(inval("Fdb attribute can not be used with encap, oif or blackhole"));
        }
        if flags != 0 {
            return Err(inval("Unsupported nexthop flags in ancillary header"));
        }
        c.fdb = true;
    }
    if let Some(p) = a.get(NHA_DST_PORT) {
        if !a.has(NHA_FDB) || !a.has(NHA_GATEWAY) {
            return Err(inval(
                "Destination port can only be set on fdb nexthops that have a gateway",
            ));
        }
        c.dst_port = [p[0], p[1]];
    }
    if let Some(g) = a.get(NHA_GROUP) {
        if u32::from(family) != AF_UNSPEC {
            return Err(inval("Invalid family for group"));
        }
        let ty = u16_of(a, NHA_GROUP_TYPE).unwrap_or(NEXTHOP_GRP_TYPE_MPATH);
        if ty > NEXTHOP_GRP_TYPE_RES {
            return Err(inval("Invalid group type"));
        }
        c.group = Some(check_group(a, g, ty).map_err(inval)?);
        if ty == NEXTHOP_GRP_TYPE_RES {
            return Err(req.error("Resilient nexthop groups are not supported", Errno::EOPNOTSUPP));
        }
        c.hw_stats = a.u32(NHA_HW_STATS_ENABLE)?.unwrap_or(0) != 0;
        return Ok(c);
    }
    if a.has(NHA_BLACKHOLE) {
        if [NHA_GATEWAY, NHA_OIF, NHA_ENCAP, NHA_ENCAP_TYPE, NHA_FDB].iter().any(|t| a.has(*t)) {
            return Err(inval(
                "Blackhole attribute can not be used with gateway, oif, encap or fdb",
            ));
        }
        c.blackhole = true;
        return Ok(c);
    }
    if !c.fdb && !a.has(NHA_OIF) {
        return Err(inval("Device attribute required for non-blackhole and non-fdb nexthops"));
    }
    c.oif = a.u32(NHA_OIF)?;
    if let Some(gw) = a.get(NHA_GATEWAY) {
        c.gateway = Some(match u32::from(family) {
            AF_INET if gw.len() == 4 => {
                let g = [gw[0], gw[1], gw[2], gw[3]];
                if g == ipv4::ANY { Gateway::None } else { Gateway::V4(g) }
            }
            AF_INET6 if gw.len() == 16 => {
                let mut g = ip::ANY;
                g.copy_from_slice(gw);
                if g == ip::ANY { Gateway::None } else { Gateway::V6(g) }
            }
            AF_INET | AF_INET6 => return Err(inval("Invalid gateway")),
            _ => return Err(inval("Unknown address family for gateway")),
        });
    } else if flags & RTNH_F_ONLINK != 0 {
        return Err(inval("ONLINK flag can not be set for nexthop without a gateway"));
    }
    if a.has(NHA_ENCAP) {
        let Some(ty) = u16_of(a, NHA_ENCAP_TYPE) else {
            return Err(inval("LWT encapsulation type is missing"));
        };
        // `lwtunnel_valid_encap_type` of Linux. The kernel has no encapsulations.
        if ty == 0 || ty > LWTUNNEL_ENCAP_MAX {
            return Err(inval("Unknown LWT encapsulation type"));
        }
        return Err(req.error("LWT encapsulation type not supported", Errno::EOPNOTSUPP));
    } else if a.has(NHA_ENCAP_TYPE) {
        return Err(inval("LWT encapsulation attribute is missing"));
    }
    if a.has(NHA_HW_STATS_ENABLE) {
        return Err(inval("Cannot enable nexthop hardware statistics for non-group nexthops"));
    }
    Ok(c)
}

/// The checks of `RTM_NEWNEXTHOP` with the tables, as `rtm_to_nh_config_rtnl` of Linux.
fn check_config(req: &Request<'_>, c: &Config) -> Result<()> {
    let inval = |text| req.error(text, Errno::EINVAL);
    if let Some(members) = &c.group {
        let t = NEXTHOPS.lock();
        let mut fdb_family = 0u8;
        for m in members {
            let nh = t.map.get(&m.0).ok_or_else(|| inval("Invalid nexthop id"))?;
            // `valid_group_nh`: the groups are all of the hash type.
            let Some(i) = nh.info() else {
                return Err(inval("Hash-threshold group can not be a nexthop within a group"));
            };
            if i.blackhole && members.len() > 1 {
                return Err(inval(
                    "Blackhole nexthop can not be used in a group with more than 1 path",
                ));
            }
            if c.fdb {
                if !i.fdb {
                    return Err(inval("FDB nexthop group can only have fdb nexthops"));
                }
                if fdb_family == 0 {
                    fdb_family = i.family;
                } else if fdb_family != i.family {
                    return Err(inval("FDB nexthop group cannot have mixed family nexthops"));
                }
            }
            if !c.fdb && i.fdb {
                return Err(inval("Non FDB nexthop group cannot have fdb nexthops"));
            }
        }
    }
    if let Some(oif) = c.oif {
        let d = (oif != 0).then(|| dev::by_index(oif)).flatten();
        let Some(d) = d else {
            return Err(inval("Invalid device index"));
        };
        if !d.is_up() {
            return Err(req.error("Nexthop device is not up", Errno::ENETDOWN));
        }
        if !d.carrier() {
            return Err(req.error("Carrier for nexthop device is down", Errno::ENETDOWN));
        }
    }
    Ok(())
}

/// The state of a device: `None` if it is not there, else if it is up.
fn dev_up(ifindex: u32) -> Option<bool> {
    dev::by_index(ifindex).map(|d| d.is_up())
}

/// Makes the IPv4 next hop of a new nexthop, as `nh_create_ipv4` and `fib_check_nh` of Linux.
fn create4(req: &Request<'_>, c: &Config, info: &mut Info) -> Result<()> {
    let oif = if c.blackhole { LOOPBACK_IFINDEX } else { c.oif.unwrap_or(0) };
    match info.gateway {
        Gateway::V4(gw) => {
            let onlink = c.flags & RTNH_F_ONLINK != 0;
            let (ifindex, scope) = ROUTES
                .lock()
                .check_nh_gateway(gw, oif, onlink, dev_up)
                .map_err(|(m, e)| match m {
                    Some(m) => req.error(m, e),
                    None => e,
                })?;
            info.ifindex = ifindex;
            info.scope = scope;
        }
        _ => {
            // `fib_check_nh_nongw` of Linux.
            if c.flags & RTNH_F_ONLINK != 0 {
                return Err(req.error(
                    "Invalid flags for nexthop - PERVASIVE and ONLINK can not be set",
                    Errno::EINVAL,
                ));
            }
            match dev_up(oif) {
                None => return Err(Errno::ENODEV),
                Some(false) => {
                    return Err(req.error("Device for nexthop is not up", Errno::ENETDOWN));
                }
                Some(true) => {}
            }
            info.ifindex = oif;
            info.scope = RT_SCOPE_HOST as u8;
        }
    }
    Ok(())
}

/// Makes the IPv6 next hop of a new nexthop, as `nh_create_ipv6`, `fib6_nh_init` and
/// `ip6_validate_gw` of Linux.
fn create6(req: &Request<'_>, c: &Config, info: &mut Info) -> Result<()> {
    let inval = |text| req.error(text, Errno::EINVAL);
    let oif = if c.blackhole { LOOPBACK_IFINDEX } else { c.oif.unwrap_or(0) };
    let d = dev::by_index(oif).ok_or(Errno::ENODEV)?;
    if c.flags & RTNH_F_ONLINK != 0 && !d.is_up() {
        return Err(req.error("Nexthop device is not up", Errno::ENETDOWN));
    }
    info.ifindex = oif;
    // A next hop through the loopback device rejects the packets, as `fib6_is_reject`.
    if d.kind() == LinkKind::Loopback {
        return Ok(());
    }
    if let Gateway::V6(gw) = info.gateway {
        let t = ROUTES6.lock();
        if t.is_local(&gw) {
            return Err(inval("Gateway can not be a local address"));
        }
        if !ipv6::is_link_local(&gw) {
            if ipv6::is_multicast(&gw) {
                return Err(inval("Invalid gateway address"));
            }
            if c.flags & RTNH_F_ONLINK != 0 {
                // `ip6_route_check_nh_onlink`: a route to the gateway other than the default
                // route must go through the device.
                if let Ok((_, Some(r))) = t.lookup_route(&gw, 0)
                    && r.prefix != 0
                    && (u32::from(r.kind) != rk_abi::native::rtnetlink::RTN_UNICAST
                        || r.ifindex != oif)
                {
                    return Err(inval("Nexthop has invalid gateway or device mismatch"));
                }
            } else {
                // `ip6_route_check_nh`: the gateway must be on the link of the device.
                match t.lookup_route(&gw, oif) {
                    Ok((n, r)) if n.ifindex == oif && r.is_none_or(|r| r.gateway.is_none()) => {}
                    _ => return Err(Errno::EHOSTUNREACH),
                }
            }
        }
    }
    if !d.is_up() {
        return Err(req.error("Nexthop device is not up", Errno::ENETDOWN));
    }
    Ok(())
}

/// Makes a new nexthop, as `nexthop_create` and `nexthop_create_group` of Linux.
fn create(req: &Request<'_>, c: &Config) -> Result<Nexthop> {
    if let Some(members) = &c.group {
        let g = Group { members: members.clone(), fdb: c.fdb, hw_stats: c.hw_stats };
        return Ok(Nexthop { id: c.id, protocol: c.protocol, flags: 0, kind: Kind::Group(g) });
    }
    let mut info = Info {
        family: c.family,
        ifindex: 0,
        gateway: c.gateway.unwrap_or(Gateway::None),
        scope: RT_SCOPE_LINK as u8,
        blackhole: c.blackhole,
        fdb: c.fdb,
        dst_port: c.dst_port,
    };
    if !c.fdb {
        if u32::from(c.family) == AF_INET {
            create4(req, c, &mut info)?;
        } else {
            create6(req, c, &mut info)?;
        }
    }
    Ok(Nexthop { id: c.id, protocol: c.protocol, flags: c.flags, kind: Kind::Single(info) })
}

/// The routes of each nexthop: the scopes of the IPv4 routes, and if an IPv6 route uses it.
fn route_use(ids: &[u32]) -> BTreeMap<u32, (Vec<u8>, bool)> {
    let mut m: BTreeMap<u32, (Vec<u8>, bool)> =
        ids.iter().map(|&id| (id, (Vec::new(), false))).collect();
    for r in ROUTES.lock().nh_routes(ids) {
        if let Some(e) = m.get_mut(&r.nhid) {
            e.0.push(r.scope);
        }
    }
    let t6 = ROUTES6.lock();
    for (&id, e) in m.iter_mut() {
        e.1 = t6.uses_nh(&[id]);
    }
    m
}

/// Checks a replacement of `old` by `new`, as `replace_nexthop`, `replace_nexthop_single` and
/// `replace_nexthop_grp` of Linux.
fn check_replace(
    req: &Request<'_>,
    t: &Table,
    old: &Nexthop,
    new: &Nexthop,
    parents: &[u32],
    uses: &BTreeMap<u32, (Vec<u8>, bool)>,
) -> Result<()> {
    let inval = |text| req.error(text, Errno::EINVAL);
    let check = |id: u32| -> Result<()> {
        let (scopes, v6) = uses.get(&id).map_or((&[][..], false), |u| (&u.0[..], u.1));
        for &s in scopes {
            check_nexthop4(t, new, s).map_err(inval)?;
        }
        if v6 {
            check_nexthop6(t, new).map_err(inval)?;
        }
        Ok(())
    };
    check(old.id)?;
    for &p in parents {
        let paths = t.map.get(&p).and_then(Nexthop::group).map_or(0, |g| g.members.len());
        if new.is_blackhole() && paths > 1 {
            return Err(inval(
                "Blackhole nexthop can not be a member of a group with more than one path",
            ));
        }
        check(p)?;
    }
    match (&old.kind, &new.kind) {
        (Kind::Group(_), Kind::Single(_)) => {
            Err(inval("Can not replace a nexthop group with a nexthop."))
        }
        (Kind::Single(_), Kind::Group(_)) => {
            Err(inval("Can not replace a nexthop with a nexthop group."))
        }
        (Kind::Single(o), Kind::Single(n)) if !parents.is_empty() && o.fdb != n.fdb => {
            Err(inval("Cannot change nexthop FDB status while in a group"))
        }
        _ => Ok(()),
    }
}

/// Sends a message of a nexthop to `RTNLGRP_NEXTHOP`, as `nexthop_notify` of Linux.
fn notify(m: Vec<u8>, origin: Origin) {
    netlink::notify(RTNLGRP_NEXTHOP, m, origin);
}

/// `RTM_NEWNEXTHOP`, as `rtm_new_nexthop`, `nexthop_add` and `insert_nexthop` of Linux.
fn newnexthop(req: &Request<'_>) -> Result<()> {
    let (h, a) = policy::parse(req, NHMSG_LEN, &NEW_POLICY, policy::STRICT)?;
    let mut c = to_config(req, h, &a)?;
    check_config(req, &c)?;
    let nlflags = u32::from(req.hdr.flags);
    let replace = nlflags & NLM_F_REPLACE != 0;
    if replace && c.id == 0 {
        return Err(req.error("Replace requires nexthop id", Errno::EINVAL));
    }
    if c.id == 0 {
        c.id = NEXTHOPS.lock().unused_id();
        if c.id == 0 {
            return Err(req.error("No unused id", Errno::EINVAL));
        }
    }
    let new = create(req, &c)?;
    let (old, parents) = {
        let t = NEXTHOPS.lock();
        (t.map.get(&c.id).cloned(), t.parents(c.id))
    };
    let origin = req.origin();
    let (seq, pid) = (req.hdr.seq, req.portid);
    let Some(old) = old else {
        if replace && nlflags & NLM_F_CREATE == 0 {
            return Err(
                req.error("Replace specified without create and no entry exists", Errno::ENOENT)
            );
        }
        let m = {
            let mut t = NEXTHOPS.lock();
            if t.map.contains_key(&c.id) {
                return Err(Errno::EEXIST);
            }
            t.map.insert(c.id, new.clone());
            fill(&new, RTM_NEWNEXTHOP, seq, pid, nlflags, 0)
        };
        notify(m, origin);
        return Ok(());
    };
    if !replace {
        return Err(Errno::EEXIST);
    }
    let mut ids = alloc::vec![c.id];
    ids.extend_from_slice(&parents);
    let uses = route_use(&ids);
    let m = {
        let mut t = NEXTHOPS.lock();
        check_replace(req, &t, &old, &new, &parents, &uses)?;
        t.map.insert(c.id, new.clone());
        fill(&new, RTM_NEWNEXTHOP, seq, pid, nlflags, 0)
    };
    notify(m, origin);
    replace_notify(&ids, origin);
    Ok(())
}

/// Copies the changed nexthops `ids` to their routes, and sends the notifications of the
/// routes with `NLM_F_REPLACE`, as `nexthop_replace_notify` of Linux: the IPv4 and then the
/// IPv6 routes of each nexthop in turn.
fn replace_notify(ids: &[u32], origin: Origin) {
    let changed4 = {
        let mut rt = ROUTES.lock();
        let t = NEXTHOPS.lock();
        rt.update_nh_routes(|r| ids.contains(&r.nhid).then(|| apply4(&t, r).is_some()))
    };
    let (changed6, _) = {
        let mut rt = ROUTES6.lock();
        let t = NEXTHOPS.lock();
        rt.update_nh_routes(|r| ids.contains(&r.nhid).then(|| apply6(&t, r).is_some()))
    };
    for id in ids {
        for r in changed4.iter().filter(|r| r.nhid == *id) {
            fib::notify_route(r, RTM_NEWROUTE, origin, NLM_F_REPLACE);
        }
        for r in changed6.iter().filter(|r| r.nhid == *id) {
            addrconf::notify_route(r, RTM_NEWROUTE, origin, NLM_F_REPLACE);
        }
    }
}

/// A step of the removal of nexthops, in the order of Linux.
enum Step {
    /// A message of a nexthop.
    Msg(Vec<u8>),
    /// The routes of a nexthop go away.
    Routes(u32),
}

/// Removes the nexthop `id` from the table, as `remove_nexthop` of Linux, and gives the steps
/// after it. With `info` (the flags, sequence number and port of the request) the messages go
/// out.
fn plan_remove(t: &mut Table, id: u32, info: Option<(u32, u32, u32)>, steps: &mut Vec<Step>) {
    let Some(nh) = t.map.remove(&id) else { return };
    if let Some((flags, seq, pid)) = info {
        steps.push(Step::Msg(fill(&nh, RTM_DELNEXTHOP, seq, pid, flags, 0)));
    }
    steps.push(Step::Routes(id));
    if nh.group().is_some() {
        return;
    }
    // `remove_nexthop_from_groups`: a group without members goes away too.
    for p in t.parents(id) {
        let last = t.map.get(&p).and_then(Nexthop::group).is_some_and(|g| g.members.len() == 1);
        if last {
            plan_remove(t, p, info, steps);
            continue;
        }
        if let Some(Kind::Group(g)) = t.map.get_mut(&p).map(|n| &mut n.kind) {
            g.members.retain(|m| m.0 != id);
        }
        if let Some((flags, seq, pid)) = info
            && let Some(n) = t.map.get(&p)
        {
            steps.push(Step::Msg(fill(n, RTM_NEWNEXTHOP, seq, pid, flags, 0)));
        }
    }
}

/// Runs the steps of a removal. The IPv4 routes go away without a notification, as
/// `fib_flush`, and the IPv6 routes with one, as `ip6_del_rt`. The routes through the groups
/// that lost a member get the new first path.
fn run_steps(steps: Vec<Step>, origin: Origin) {
    for s in steps {
        match s {
            Step::Msg(m) => notify(m, origin),
            Step::Routes(id) => {
                ROUTES.lock().update_nh_routes(|r| (r.nhid == id).then_some(false));
                let (_, gone) =
                    ROUTES6.lock().update_nh_routes(|r| (r.nhid == id).then_some(false));
                for r in &gone {
                    addrconf::notify_route(r, RTM_DELROUTE, Origin::KERNEL, 0);
                }
            }
        }
    }
    {
        let mut rt = ROUTES.lock();
        let t = NEXTHOPS.lock();
        rt.update_nh_routes(|r| {
            let old = (r.gateway, r.ifindex, r.blackhole);
            apply4(&t, r)?;
            (old != (r.gateway, r.ifindex, r.blackhole)).then_some(true)
        });
    }
    let mut rt = ROUTES6.lock();
    let t = NEXTHOPS.lock();
    rt.update_nh_routes(|r| {
        let old = (r.gateway, r.ifindex, r.blackhole);
        apply6(&t, r)?;
        (old != (r.gateway, r.ifindex, r.blackhole)).then_some(true)
    });
}

/// The ID of a get or a delete, as `nh_valid_get_del_req` of Linux.
fn get_del_id(req: &Request<'_>, h: &[u8], a: &Attrs<'_>) -> Result<u32> {
    if h[1..8].iter().any(|&b| b != 0) {
        return Err(req.error("Invalid values in header", Errno::EINVAL));
    }
    let Some(id) = a.u32(NHA_ID)? else {
        return Err(req.error("Nexthop id is missing", Errno::EINVAL));
    };
    if id == 0 {
        return Err(req.error("Invalid nexthop id", Errno::EINVAL));
    }
    Ok(id)
}

/// `RTM_DELNEXTHOP`, as `rtm_del_nexthop` of Linux.
fn delnexthop(req: &Request<'_>) -> Result<()> {
    let (h, a) = policy::parse(req, NHMSG_LEN, &DEL_POLICY, policy::STRICT)?;
    let id = get_del_id(req, h, &a)?;
    let info = (u32::from(req.hdr.flags), req.hdr.seq, req.portid);
    let mut steps = Vec::new();
    {
        let mut t = NEXTHOPS.lock();
        if !t.map.contains_key(&id) {
            return Err(Errno::ENOENT);
        }
        plan_remove(&mut t, id, Some(info), &mut steps);
    }
    run_steps(steps, req.origin());
    Ok(())
}

/// `RTM_GETNEXTHOP` for one nexthop, as `rtm_get_nexthop` of Linux.
fn getnexthop(req: &Request<'_>) -> Result<()> {
    let (h, a) = policy::parse(req, NHMSG_LEN, &GET_POLICY, policy::STRICT)?;
    let id = get_del_id(req, h, &a)?;
    let op = a.u32(NHA_OP_FLAGS)?.unwrap_or(0);
    let m = {
        let t = NEXTHOPS.lock();
        let nh = t.map.get(&id).ok_or(Errno::ENOENT)?;
        fill(nh, RTM_NEWNEXTHOP, req.hdr.seq, req.portid, 0, op)
    };
    req.reply(m);
    Ok(())
}

/// A dump of the nexthops, as `rtm_dump_nexthop`, `nh_valid_dump_req` and `nh_dump_filtered`
/// of Linux.
fn dump(req: &Request<'_>) -> Result<Vec<Vec<u8>>> {
    let (h, a) = policy::parse(req, NHMSG_LEN, &DUMP_POLICY, policy::STRICT)?;
    let op = a.u32(NHA_OP_FLAGS)?.unwrap_or(0);
    let dev_idx = a.u32(NHA_OIF)?.unwrap_or(0);
    if dev_idx > i32::MAX as u32 {
        return Err(req.error("Invalid device index", Errno::EINVAL));
    }
    let master = a.u32(NHA_MASTER)?.unwrap_or(0);
    if master > i32::MAX as u32 {
        return Err(req.error("Invalid master device index", Errno::EINVAL));
    }
    let groups = a.has(NHA_GROUPS);
    if h[1..8].iter().any(|&b| b != 0) {
        return Err(req.error("Invalid values in header for nexthop dump request", Errno::EINVAL));
    }
    let family = h[0];
    let t = NEXTHOPS.lock();
    let skip = |nh: &Nexthop| {
        if groups && nh.group().is_none() {
            return true;
        }
        if dev_idx == 0 && master == 0 && family == 0 {
            return false;
        }
        let Some(i) = nh.info() else { return true };
        (family != 0 && i.family != family)
            || (dev_idx != 0 && (i.ifindex != dev_idx || i.fdb))
            // The kernel has no master devices.
            || master != 0
    };
    Ok(t.map
        .values()
        .filter(|nh| !skip(nh))
        .map(|nh| fill(nh, RTM_NEWNEXTHOP, req.hdr.seq, req.portid, NLM_F_MULTI, op))
        .collect())
}

/// Takes the changes of the devices, as `nh_netdev_event` and `nexthop_flush_dev` of Linux.
/// A device that goes down or away loses its nexthops, without messages. A blackhole stays
/// when the loopback device goes down.
pub(crate) fn event(d: &NetDevice, e: Event) {
    let down = match e {
        Event::Down => true,
        Event::Unregister => false,
        _ => return,
    };
    let ifindex = d.ifindex();
    let mut steps = Vec::new();
    {
        let mut t = NEXTHOPS.lock();
        let ids: Vec<u32> = t
            .map
            .values()
            .filter_map(|n| {
                let i = n.info()?;
                (i.ifindex == ifindex && !i.fdb && !(i.blackhole && down)).then_some(n.id)
            })
            .collect();
        for id in ids {
            plan_remove(&mut t, id, None, &mut steps);
        }
    }
    if !steps.is_empty() {
        run_steps(steps, Origin::KERNEL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use rk_net::netlink::msg::attrs;

    fn single(id: u32, ifindex: u32, gateway: Gateway) -> Nexthop {
        let info = Info {
            family: AF_INET as u8,
            ifindex,
            gateway,
            scope: RT_SCOPE_LINK as u8,
            blackhole: false,
            fdb: false,
            dst_port: [0; 2],
        };
        Nexthop { id, protocol: 3, flags: 0, kind: Kind::Single(info) }
    }

    fn group(id: u32, members: &[(u32, u32)]) -> Nexthop {
        let g = Group { members: members.to_vec(), fdb: false, hw_stats: false };
        Nexthop { id, protocol: 3, flags: 0, kind: Kind::Group(g) }
    }

    fn table(list: &[Nexthop]) -> Table {
        let mut t = Table::new();
        for n in list {
            t.map.insert(n.id, n.clone());
        }
        t
    }

    #[test]
    fn a_single_nexthop_has_the_format_of_linux() {
        let n = single(7, 2, Gateway::V4([10, 0, 2, 2]));
        let m = fill(&n, RTM_NEWNEXTHOP, 9, 5, 0, 0);
        assert_eq!(&m[16..24], &[AF_INET as u8, RT_SCOPE_LINK as u8, 3, 0, 0, 0, 0, 0]);
        let got: Vec<(u16, Vec<u8>)> = attrs(&m[24..]).map(|(t, d)| (t, d.to_vec())).collect();
        assert_eq!(
            got,
            [
                (NHA_ID as u16, 7u32.to_ne_bytes().to_vec()),
                (NHA_OIF as u16, 2u32.to_ne_bytes().to_vec()),
                (NHA_GATEWAY as u16, vec![10, 0, 2, 2]),
            ]
        );
    }

    #[test]
    fn a_group_has_the_weights_less_one_and_the_reserved_flag() {
        let t = table(&[
            single(1, 2, Gateway::None),
            single(2, 2, Gateway::None),
            group(10, &[(1, 1), (2, 300)]),
        ]);
        let m = fill(&t.map[&10], RTM_NEWNEXTHOP, 0, 0, 0, 0);
        assert_eq!(&m[16..24], &[0, 0, 3, 0, 0, 0, 0, 0]);
        let got: Vec<(u16, Vec<u8>)> = attrs(&m[24..]).map(|(t, d)| (t, d.to_vec())).collect();
        let mut grp = Vec::from(1u32.to_ne_bytes());
        grp.extend_from_slice(&[0, 0, 0, 0]);
        grp.extend_from_slice(&2u32.to_ne_bytes());
        grp.extend_from_slice(&[43, 1, 0, 0]);
        assert_eq!(
            got,
            [
                (NHA_ID as u16, 10u32.to_ne_bytes().to_vec()),
                (NHA_GROUP_TYPE as u16, 0u16.to_ne_bytes().to_vec()),
                (NHA_GROUP as u16, grp),
                (NHA_OP_FLAGS as u16, NHA_OP_FLAG_RESP_GRP_RESVD_0.to_ne_bytes().to_vec()),
            ]
        );
    }

    #[test]
    fn the_stats_of_a_group_are_nested() {
        let t = table(&[single(1, 2, Gateway::None), group(10, &[(1, 1)])]);
        let m = fill(&t.map[&10], RTM_NEWNEXTHOP, 0, 0, 0, NHA_OP_FLAG_DUMP_STATS);
        let types: Vec<u16> = attrs(&m[24..]).map(|(t, _)| t).collect();
        // The iterator takes away the flags, so look at the raw types for NLA_F_NESTED.
        let mut raw = Vec::new();
        let mut at = 24;
        while at + 4 <= m.len() {
            let len = u16::from_ne_bytes([m[at], m[at + 1]]) as usize;
            raw.push(u16::from_ne_bytes([m[at + 2], m[at + 3]]));
            at += len.div_ceil(4) * 4;
        }
        assert!(raw.contains(&(NHA_GROUP_STATS as u16 | NLA_F_NESTED as u16)));
        let nested = NHA_GROUP_STATS as u16;
        assert_eq!(
            types,
            [
                NHA_ID as u16,
                NHA_GROUP_TYPE as u16,
                NHA_GROUP as u16,
                NHA_HW_STATS_ENABLE as u16,
                nested,
                NHA_OP_FLAGS as u16
            ]
        );
    }

    #[test]
    fn the_group_attribute_has_the_checks_of_linux() {
        let a = Attrs::parse(&[], NHA_MAX as u16);
        let e = |id: u32, w: u8, r: u8| {
            let mut v = Vec::from(id.to_ne_bytes());
            v.extend_from_slice(&[w, 0, r, 0]);
            v
        };
        assert_eq!(check_group(&a, &[], 0), Err("Invalid length for nexthop group attribute"));
        assert_eq!(check_group(&a, &[0; 4], 0), Err("Invalid length for nexthop group attribute"));
        assert_eq!(check_group(&a, &e(1, 0, 1), 0), Err("Reserved field in nexthop_grp must be 0"));
        let mut two = e(1, 0, 0);
        two.extend(e(1, 4, 0));
        assert_eq!(check_group(&a, &two, 0), Err("Nexthop id can not be used twice in a group"));
        let mut ok = e(1, 0, 0);
        ok.extend(e(2, 4, 0));
        assert_eq!(check_group(&a, &ok, 0), Ok(vec![(1, 1), (2, 5)]));
    }

    #[test]
    fn a_new_id_skips_the_ids_in_use_and_wraps() {
        let mut t = table(&[single(1, 2, Gateway::None), single(2, 2, Gateway::None)]);
        assert_eq!(t.unused_id(), 3);
        t.last_id = u32::MAX;
        assert_eq!(t.unused_id(), 0);
        assert_eq!(t.unused_id(), 3);
    }

    #[test]
    fn the_last_member_takes_its_group_away() {
        let mut t = table(&[
            single(1, 2, Gateway::None),
            single(2, 3, Gateway::None),
            group(10, &[(1, 1)]),
            group(11, &[(1, 1), (2, 1)]),
        ]);
        let mut steps = Vec::new();
        plan_remove(&mut t, 1, Some((0, 0, 0)), &mut steps);
        assert_eq!(t.map.keys().copied().collect::<Vec<_>>(), [2, 11]);
        assert_eq!(t.map[&11].group().map(|g| g.members.clone()), Some(vec![(2, 1)]));
        let kinds: Vec<&str> = steps
            .iter()
            .map(|s| match s {
                Step::Msg(m) if m[4] == RTM_DELNEXTHOP as u8 => "del",
                Step::Msg(_) => "new",
                Step::Routes(_) => "routes",
            })
            .collect();
        assert_eq!(kinds, ["del", "routes", "del", "routes", "new"]);
    }

    #[test]
    fn a_route_checks_the_scope_of_its_nexthop() {
        let gw = single(1, 2, Gateway::V4([10, 0, 2, 2]));
        let mut onlink = single(2, 2, Gateway::V4([10, 0, 2, 2]));
        onlink.flags = RTNH_F_ONLINK;
        let g = group(10, &[(1, 1)]);
        let t = table(&[gw.clone(), onlink.clone(), g.clone()]);
        let host = RT_SCOPE_HOST as u8;
        assert_eq!(
            check_nexthop4(&t, &gw, host),
            Err("Route with host scope can not have a gateway")
        );
        assert_eq!(
            check_nexthop4(&t, &g, host),
            Err("Route with host scope can not have multiple nexthops")
        );
        assert_eq!(
            check_nexthop4(&t, &onlink, RT_SCOPE_LINK as u8),
            Err("Scope mismatch with nexthop")
        );
        assert_eq!(check_nexthop4(&t, &onlink, 0), Ok(()));
        assert_eq!(check_nexthop6(&t, &gw), Err("IPv6 routes can not use an IPv4 nexthop"));
        assert_eq!(check_nexthop6(&t, &g), Err("IPv6 routes can not use an IPv4 nexthop"));
    }

    #[test]
    fn a_multipath_attribute_has_a_rtnexthop_for_each_path() {
        let mut b = Builder::new(0, 0, 0, 0);
        let p = |gw, ifindex, weight| Path { gateway: gw, ifindex, flags: 0, weight };
        put_multipath(
            &mut b,
            &[p(Gateway::V4([10, 0, 2, 2]), 2, 1), p(Gateway::None, 3, 4)],
            AF_INET,
        );
        let m = b.finish();
        let (ty, d) = attrs(&m[16..]).next().unwrap();
        assert_eq!(u32::from(ty), rk_abi::native::rtnetlink::RTA_MULTIPATH);
        let mut want = vec![16, 0, 0, 0, 2, 0, 0, 0, 8, 0, 5, 0, 10, 0, 2, 2];
        want.extend_from_slice(&[8, 0, 0, 3, 3, 0, 0, 0]);
        assert_eq!(d, &want[..]);
    }
}

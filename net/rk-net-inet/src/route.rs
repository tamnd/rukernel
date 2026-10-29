//! The addresses of the interfaces and the route tables, as net/ipv4/devinet.c and
//! net/ipv4/fib_*.c of Linux, with a sorted list in place of a trie.
//!
//! Each interface has a list of addresses in the order of Linux: the primary addresses first,
//! by scope, then the secondary addresses. An address adds the routes of `fib_add_ifaddr`: a
//! `local` route for the address and, when the interface is up, the route of its subnet and the
//! `broadcast` routes. A packet to a `local` route goes through the loopback device.
//!
//! The routes of each table are in the order of a dump of Linux: by destination, then the
//! longer prefix first, then by the type of service and the priority. A lookup looks in the
//! table `local` and then in the table `main`, as the default rules of Linux.

use crate::ipv4::{self, Addr};
use alloc::string::String;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::if_addr::{IFA_F_NOPREFIXROUTE, IFA_F_PERMANENT, IFA_F_SECONDARY};
use rk_abi::native::netlink::{NLM_F_APPEND, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE};
use rk_abi::native::rtnetlink::{
    RT_SCOPE_HOST, RT_SCOPE_LINK, RT_SCOPE_NOWHERE, RT_SCOPE_UNIVERSE, RT_TABLE_LOCAL,
    RT_TABLE_MAIN, RTN_BLACKHOLE, RTN_BROADCAST, RTN_LOCAL, RTN_PROHIBIT, RTN_THROW, RTN_UNICAST,
    RTN_UNREACHABLE, RTNH_F_ONLINK, RTPROT_BOOT, RTPROT_KERNEL,
};
use rk_vfs::inode::Result;

/// A lifetime without an end, `INFINITY_LIFE_TIME` of Linux.
pub const INFINITY: u32 = u32::MAX;

// The metrics of a route, the `RTAX_*` enum of include/uapi/linux/rtnetlink.h. rk-abigen does
// not give the values of this enum, so they are written by hand.
/// The metric of the MTU of the path, `RTAX_MTU`.
pub const RTAX_MTU: u16 = 2;
/// The metric of the window, `RTAX_WINDOW`.
pub const RTAX_WINDOW: u16 = 3;
/// The metric of the round trip time, `RTAX_RTT`, in units of 1/8 ms.
pub const RTAX_RTT: u16 = 4;
/// The metric of the advertised MSS, `RTAX_ADVMSS`.
pub const RTAX_ADVMSS: u16 = 8;
/// The metric of the hop limit, `RTAX_HOPLIMIT`.
pub const RTAX_HOPLIMIT: u16 = 10;
/// The metric of the features, `RTAX_FEATURES`.
pub const RTAX_FEATURES: u16 = 12;
/// The metric of the congestion control, `RTAX_CC_ALGO`. Its value is a name.
pub const RTAX_CC_ALGO: u16 = 16;
/// The last metric, `RTAX_MAX`.
pub const RTAX_MAX: u16 = 17;
/// The features of `RTAX_FEATURES` that a route can have, `RTAX_FEATURE_MASK` of Linux.
pub const RTAX_FEATURE_MASK: u32 = 0x1f;

/// The metrics of a route, as `fib_metrics` of Linux: the value of `RTAX_n` is at `n - 1`, and
/// 0 means no value.
pub type Metrics = [u32; RTAX_MAX as usize];

/// An address of an interface, as `struct in_ifaddr` of Linux.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfAddr {
    /// The interface index.
    pub ifindex: u32,
    /// The local address, `ifa_local`.
    pub local: Addr,
    /// The address of the subnet or of the peer, `ifa_address`. It is the local address on a
    /// link that is not point to point.
    pub address: Addr,
    /// The length of the prefix of the subnet.
    pub prefix: u8,
    /// The broadcast address, or `0.0.0.0` for none.
    pub broadcast: Addr,
    /// The label, as `eth0` or `eth0:1`.
    pub label: String,
    /// The scope, `RT_SCOPE_*`.
    pub scope: u8,
    /// The flags, `IFA_F_*`.
    pub flags: u32,
    /// The protocol that added the address, `IFAPROT_*`.
    pub proto: u8,
    /// The priority of the route of the subnet.
    pub rt_priority: u32,
    /// The valid lifetime in seconds.
    pub valid: u32,
    /// The preferred lifetime in seconds.
    pub preferred: u32,
    /// The time of the creation, in hundredths of a second since boot.
    pub cstamp: u64,
    /// The time of the last change, in hundredths of a second since boot.
    pub tstamp: u64,
}

impl IfAddr {
    /// A permanent address with the subnet of `prefix` and no broadcast address.
    pub fn new(ifindex: u32, local: Addr, prefix: u8, label: &str) -> Self {
        Self {
            ifindex,
            local,
            address: local,
            prefix,
            broadcast: ipv4::ANY,
            label: String::from(label),
            scope: RT_SCOPE_UNIVERSE as u8,
            flags: IFA_F_PERMANENT,
            proto: 0,
            rt_priority: 0,
            valid: INFINITY,
            preferred: INFINITY,
            cstamp: 0,
            tstamp: 0,
        }
    }

    /// The netmask as a number.
    pub fn mask(&self) -> u32 {
        ipv4::mask(self.prefix)
    }

    /// The netmask.
    pub fn netmask(&self) -> Addr {
        self.mask().to_be_bytes()
    }

    /// The address of the subnet.
    pub fn subnet(&self) -> Addr {
        (u32::from_be_bytes(self.address) & self.mask()).to_be_bytes()
    }

    /// Tells if the address is a secondary address.
    pub fn is_secondary(&self) -> bool {
        self.flags & IFA_F_SECONDARY != 0
    }

    /// Tells if `a` is in the subnet, as `inet_ifa_match` of Linux.
    pub fn contains(&self, a: Addr) -> bool {
        ipv4::same_net(self.address, a, self.prefix)
    }

    /// The broadcast address that Linux sets for a new address on a link with broadcast: the
    /// subnet with all of the host bits set. A prefix of 31 or 32 bits has none.
    pub fn default_broadcast(&self) -> Addr {
        if self.prefix >= 31 {
            return ipv4::ANY;
        }
        (u32::from_be_bytes(self.local) | !self.mask()).to_be_bytes()
    }
}

/// A route, as a `struct fib_alias` and its `struct fib_info` of Linux.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    /// The table, `RT_TABLE_*`.
    pub table: u32,
    /// The destination subnet.
    pub dst: Addr,
    /// The length of the prefix of the destination.
    pub prefix: u8,
    /// The type of service.
    pub tos: u8,
    /// The priority, the metric of `ip route`. A lower value wins.
    pub priority: u32,
    /// The type, `RTN_*`.
    pub kind: u8,
    /// The scope, `RT_SCOPE_*`.
    pub scope: u8,
    /// The protocol that added the route, `RTPROT_*`.
    pub protocol: u8,
    /// The preferred source address.
    pub prefsrc: Option<Addr>,
    /// The gateway, or `None` for a subnet on the link.
    pub gateway: Option<Addr>,
    /// The interface index, or 0 for a route without a device.
    pub ifindex: u32,
    /// The flags of the next hop, `RTNH_F_*`.
    pub flags: u32,
    /// The metrics.
    pub metrics: Metrics,
}

impl Route {
    /// A route of the table `main` that the administrator adds.
    pub fn new(dst: Addr, prefix: u8, gateway: Option<Addr>, ifindex: u32) -> Self {
        let scope = if gateway.is_some() { RT_SCOPE_UNIVERSE } else { RT_SCOPE_LINK };
        Self {
            table: RT_TABLE_MAIN,
            dst: ipv4::prefix(dst, prefix),
            prefix,
            tos: 0,
            priority: 0,
            kind: RTN_UNICAST as u8,
            scope: scope as u8,
            protocol: RTPROT_BOOT as u8,
            prefsrc: None,
            gateway,
            ifindex,
            flags: 0,
            metrics: [0; RTAX_MAX as usize],
        }
    }

    /// The key of the order of a dump.
    fn order(&self) -> (u32, u32, u8, u8, u32) {
        (self.table, u32::from_be_bytes(self.dst), 32 - self.prefix, !self.tos, self.priority)
    }

    /// Tells if the route has the same key as `o`, as the check of `fib_table_insert`.
    fn same_key(&self, o: &Route) -> bool {
        self.order() == o.order()
    }

    /// The error of a route without a next hop, as `fib_props` of Linux.
    fn error(&self) -> Option<Errno> {
        match u32::from(self.kind) {
            RTN_UNREACHABLE => Some(Errno::EHOSTUNREACH),
            RTN_BLACKHOLE => Some(Errno::EINVAL),
            RTN_PROHIBIT => Some(Errno::EACCES),
            RTN_THROW => Some(Errno::EAGAIN),
            _ => None,
        }
    }
}

/// The fields that select a route to delete, as the checks of `fib_table_delete` of Linux. A
/// field that is `None` matches each route.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Match {
    /// The table.
    pub table: u32,
    /// The destination.
    pub dst: Addr,
    /// The length of the prefix.
    pub prefix: u8,
    /// The type of service.
    pub tos: u8,
    /// The type.
    pub kind: Option<u8>,
    /// The scope.
    pub scope: Option<u8>,
    /// The protocol.
    pub protocol: Option<u8>,
    /// The preferred source address.
    pub prefsrc: Option<Addr>,
    /// The gateway.
    pub gateway: Option<Addr>,
    /// The interface.
    pub ifindex: Option<u32>,
    /// The priority.
    pub priority: Option<u32>,
}

impl Match {
    fn matches(&self, r: &Route) -> bool {
        let opt = |want: Option<u8>, have: u8| want.is_none_or(|w| w == have);
        r.table == self.table
            && r.dst == self.dst
            && r.prefix == self.prefix
            && r.tos == self.tos
            && opt(self.kind, r.kind)
            && opt(self.scope, r.scope)
            && opt(self.protocol, r.protocol)
            && (self.prefsrc.is_none() || self.prefsrc == r.prefsrc)
            && (self.gateway.is_none() || self.gateway == r.gateway)
            && self.ifindex.is_none_or(|i| i == r.ifindex)
            && self.priority.is_none_or(|p| p == r.priority)
    }
}

/// The result of a lookup: where a packet goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Next {
    /// The interface index.
    pub ifindex: u32,
    /// The address of the next hop: the gateway or the destination.
    pub hop: Addr,
    /// The source address for a packet on this route.
    pub src: Addr,
    /// Tells if the destination is a local address.
    pub local: bool,
    /// Tells if the destination is a broadcast address.
    pub broadcast: bool,
}

/// The state of an interface that the routes of its addresses need.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    /// The interface index.
    pub ifindex: u32,
    /// The interface is up.
    pub up: bool,
    /// The interface is the loopback device.
    pub loopback: bool,
}

/// The changes to the routes that an operation made, for the notifications.
#[derive(Debug, Default)]
pub struct Changes {
    /// The routes that the operation added.
    pub added: Vec<Route>,
    /// The routes that the operation removed.
    pub removed: Vec<Route>,
}

/// The addresses and the routes.
#[derive(Default)]
pub struct Table {
    addrs: Vec<IfAddr>,
    routes: Vec<Route>,
    /// The tables that exist. Linux makes a table at the first route in it.
    tables: Vec<u32>,
    /// The interface index of the loopback device.
    loopback: u32,
}

impl Table {
    /// An empty table.
    pub const fn new() -> Self {
        Self { addrs: Vec::new(), routes: Vec::new(), tables: Vec::new(), loopback: 0 }
    }

    /// Sets the loopback device, which takes the packets to the local addresses.
    pub fn set_loopback(&mut self, ifindex: u32) {
        self.loopback = ifindex;
    }

    /// The addresses, by interface.
    pub fn addrs(&self) -> &[IfAddr] {
        &self.addrs
    }

    /// The addresses, for a change that keeps their order and their subnets: the label, the
    /// lifetimes or the priority.
    pub fn addrs_mut(&mut self) -> &mut [IfAddr] {
        &mut self.addrs
    }

    /// The addresses of an interface, in the order of Linux.
    pub fn addrs_of(&self, ifindex: u32) -> impl Iterator<Item = &IfAddr> {
        self.addrs.iter().filter(move |a| a.ifindex == ifindex)
    }

    /// The routes, in the order of a dump.
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// Tells if the table `id` exists.
    pub fn has_table(&self, id: u32) -> bool {
        id == RT_TABLE_MAIN || id == RT_TABLE_LOCAL || self.tables.contains(&id)
    }

    /// The first primary address of an interface, as `inet_select_addr` with a scope that
    /// takes each address.
    pub fn addr_of(&self, ifindex: u32) -> Option<Addr> {
        self.addrs_of(ifindex).find(|a| !a.is_secondary()).map(|a| a.local)
    }

    /// Adds an address, as `__inet_insert_ifa` of Linux. An address in the subnet of another
    /// address is secondary. A primary address goes after the last primary address with a
    /// smaller or equal scope, and a secondary address goes at the end. The caller adds the
    /// routes with `sync_link`.
    ///
    /// # Errors
    ///
    /// Gives `EEXIST` for an address that is there, and `EINVAL` for an address in the subnet
    /// of another address with another scope.
    pub fn insert_addr(&mut self, mut a: IfAddr) -> Result<()> {
        a.flags &= !IFA_F_SECONDARY;
        let mut at = None;
        let mut last_primary = None;
        for (i, o) in self.addrs.iter().enumerate() {
            if o.ifindex != a.ifindex {
                if at.is_none() && o.ifindex > a.ifindex {
                    at = Some(i);
                }
                continue;
            }
            if last_primary.is_none() {
                last_primary = Some(i);
            }
            if !o.is_secondary() && o.scope <= a.scope {
                last_primary = Some(i + 1);
            }
            if a.prefix == o.prefix && o.contains(a.address) {
                if a.local == o.local {
                    return Err(Errno::EEXIST);
                }
                if a.scope != o.scope {
                    return Err(Errno::EINVAL);
                }
                a.flags |= IFA_F_SECONDARY;
            }
        }
        let end = self
            .addrs
            .iter()
            .rposition(|o| o.ifindex == a.ifindex)
            .map(|i| i + 1)
            .or(at)
            .unwrap_or(self.addrs.len());
        let pos = if a.is_secondary() { end } else { last_primary.unwrap_or(end) };
        self.addrs.insert(pos, a);
        Ok(())
    }

    /// Removes the address at `index` of `addrs`, as `__inet_del_ifa` of Linux without the
    /// promotion of a secondary address. A primary address takes its secondary addresses with
    /// it. Gives the removed addresses: the secondary addresses first. The caller removes the
    /// routes with `sync_link`.
    pub fn remove_addr(&mut self, index: usize) -> Vec<IfAddr> {
        let a = self.addrs.remove(index);
        let mut out = Vec::new();
        if !a.is_secondary() {
            let mut i = 0;
            while i < self.addrs.len() {
                let o = &self.addrs[i];
                if o.ifindex == a.ifindex
                    && o.is_secondary()
                    && o.prefix == a.prefix
                    && a.contains(o.address)
                {
                    out.push(self.addrs.remove(i));
                } else {
                    i += 1;
                }
            }
        }
        out.push(a);
        out
    }

    /// Removes the addresses of an interface, without a change to the routes.
    pub fn remove_iface(&mut self, ifindex: u32) {
        self.addrs.retain(|a| a.ifindex != ifindex);
        self.routes.retain(|r| r.ifindex != ifindex);
    }

    /// The routes that the addresses of an interface need, as `fib_add_ifaddr` of Linux.
    fn kernel_routes(&self, link: Link) -> Vec<Route> {
        let mut out = Vec::new();
        for a in self.addrs_of(link.ifindex) {
            // A secondary address uses the primary address of its subnet as the source.
            let prim = if a.is_secondary() {
                match self
                    .addrs_of(link.ifindex)
                    .find(|p| !p.is_secondary() && p.prefix == a.prefix && p.contains(a.address))
                {
                    Some(p) => p.local,
                    None => continue,
                }
            } else {
                a.local
            };
            let magic = |kind: u32, dst: Addr, prefix: u8, priority: u32| Route {
                table: if kind == RTN_UNICAST { RT_TABLE_MAIN } else { RT_TABLE_LOCAL },
                dst,
                prefix,
                tos: 0,
                priority,
                kind: kind as u8,
                scope: if kind == RTN_LOCAL { RT_SCOPE_HOST } else { RT_SCOPE_LINK } as u8,
                protocol: RTPROT_KERNEL as u8,
                prefsrc: Some(prim),
                gateway: None,
                ifindex: link.ifindex,
                flags: 0,
                metrics: [0; RTAX_MAX as usize],
            };
            out.push(magic(RTN_LOCAL, a.local, 32, 0));
            if !link.up {
                continue;
            }
            if a.broadcast != ipv4::ANY && a.broadcast != ipv4::BROADCAST {
                out.push(magic(RTN_BROADCAST, a.broadcast, 32, 0));
            }
            let prefix = ipv4::prefix(a.address, a.prefix);
            if prefix[0] != 0 && !a.is_secondary() && (prefix != a.address || a.prefix < 32) {
                if a.flags & IFA_F_NOPREFIXROUTE == 0 {
                    let kind = if link.loopback { RTN_LOCAL } else { RTN_UNICAST };
                    out.push(magic(kind, prefix, a.prefix, a.rt_priority));
                }
                if a.prefix < 31 {
                    let bcast = (u32::from_be_bytes(prefix) | !a.mask()).to_be_bytes();
                    out.push(magic(RTN_BROADCAST, bcast, 32, 0));
                }
            }
        }
        out
    }

    /// Makes the routes of the kernel for an interface match its addresses, as
    /// `fib_add_ifaddr` and `fib_del_ifaddr` of Linux. A route of the kernel that no address
    /// needs goes away, and so does a route with a preferred source that is not a local
    /// address now. An interface without addresses loses all of its routes, as
    /// `fib_disable_ip`.
    pub fn sync_link(&mut self, link: Link) -> Changes {
        let want = self.kernel_routes(link);
        let mut c = Changes::default();
        let no_addrs = self.addrs_of(link.ifindex).next().is_none();
        let locals: Vec<Addr> = self.addrs.iter().map(|a| a.local).collect();
        let mut i = 0;
        while i < self.routes.len() {
            let r = &self.routes[i];
            let stale_kernel =
                r.ifindex == link.ifindex && r.protocol == RTPROT_KERNEL as u8 && !want.contains(r);
            let stale_src = r.prefsrc.is_some_and(|s| !locals.contains(&s));
            if stale_kernel || stale_src || (no_addrs && r.ifindex == link.ifindex) {
                let r = self.routes.remove(i);
                // Linux sends no notification for a flush of the routes of a device.
                if stale_kernel || !no_addrs {
                    c.removed.push(r);
                }
            } else {
                i += 1;
            }
        }
        for r in want {
            if !self.routes.contains(&r) {
                self.place(r.clone(), false);
                c.added.push(r);
            }
        }
        c
    }

    /// Removes the routes of an interface that goes down, as `fib_sync_down_dev` of Linux
    /// without force: the routes with the scope `host` stay. Linux sends no notification.
    pub fn link_down(&mut self, ifindex: u32) {
        self.routes.retain(|r| r.ifindex != ifindex || r.scope == RT_SCOPE_HOST as u8);
    }

    /// Puts a route at its place in the order. A new route goes before the routes with the
    /// same key, or after them with `append`.
    fn place(&mut self, r: Route, append: bool) -> usize {
        let key = r.order();
        let pos = if append {
            self.routes.partition_point(|o| o.order() <= key)
        } else {
            self.routes.partition_point(|o| o.order() < key)
        };
        if !self.has_table(r.table) {
            self.tables.push(r.table);
        }
        self.routes.insert(pos, r);
        pos
    }

    /// Adds a route, as `fib_table_insert` of Linux. `flags` has the flags `NLM_F_*` of the
    /// request. Gives the flags of the notification of the new route, or `None` if the table
    /// did not change.
    ///
    /// # Errors
    ///
    /// Gives `EEXIST` for a route with the same key and `NLM_F_EXCL`, or for the same route,
    /// and `ENOENT` for a new route without `NLM_F_CREATE`.
    pub fn insert_route(&mut self, r: Route, flags: u32) -> Result<Option<u32>> {
        let mut notify = NLM_F_EXCL;
        if let Some(first) = self.routes.iter().position(|o| o.same_key(&r)) {
            notify = 0;
            if flags & NLM_F_EXCL != 0 {
                return Err(Errno::EEXIST);
            }
            let same =
                self.routes[first..].iter().take_while(|o| o.same_key(&r)).position(|o| *o == r);
            if flags & NLM_F_REPLACE != 0 {
                return match same {
                    Some(0) => Ok(None),
                    Some(_) => Err(Errno::EEXIST),
                    None => {
                        self.routes[first] = r;
                        Ok(Some(NLM_F_REPLACE))
                    }
                };
            }
            if same.is_some() {
                return Err(Errno::EEXIST);
            }
            notify |= flags & NLM_F_APPEND;
        }
        if flags & NLM_F_CREATE == 0 {
            return Err(Errno::ENOENT);
        }
        self.place(r, flags & NLM_F_APPEND != 0);
        Ok(Some(notify | NLM_F_CREATE))
    }

    /// Removes the first route that `m` matches, as `fib_table_delete` of Linux.
    ///
    /// # Errors
    ///
    /// Gives `ESRCH` if the table is not there or if no route matches.
    pub fn delete_route(&mut self, m: &Match) -> Result<Route> {
        if !self.has_table(m.table) {
            return Err(Errno::ESRCH);
        }
        let i = self.routes.iter().position(|r| m.matches(r)).ok_or(Errno::ESRCH)?;
        Ok(self.routes.remove(i))
    }

    /// The best route to `dst` in one table, with at least the scope `scope`, and through the
    /// interface `oif` if it is not 0, as `fib_table_lookup` of Linux.
    fn table_lookup(&self, table: u32, dst: Addr, scope: u8, oif: u32) -> Option<&Route> {
        // The routes with a longer prefix come first in the order, thus the best route is the
        // first match with the longest prefix.
        self.routes
            .iter()
            .filter(|r| r.table == table && ipv4::same_net(r.dst, dst, r.prefix))
            .filter(|r| r.scope >= scope && (oif == 0 || r.ifindex == oif))
            .min_by_key(|r| (32 - r.prefix, r.priority))
    }

    /// The best route to `dst` in the tables `local` and `main`, as `fib_lookup` of Linux.
    fn fib_lookup(&self, dst: Addr, scope: u8, oif: u32) -> Option<&Route> {
        self.table_lookup(RT_TABLE_LOCAL, dst, scope, oif)
            .or_else(|| self.table_lookup(RT_TABLE_MAIN, dst, scope, oif))
    }

    /// The type of the address `a`, as `inet_addr_type` of Linux: `RTN_LOCAL`, `RTN_BROADCAST`,
    /// `RTN_UNICAST` or another type of the route.
    pub fn addr_type(&self, a: Addr) -> u32 {
        if a == ipv4::ANY || a == ipv4::BROADCAST {
            return RTN_BROADCAST;
        }
        if ipv4::is_multicast(a) {
            return rk_abi::native::rtnetlink::RTN_MULTICAST;
        }
        self.table_lookup(RT_TABLE_LOCAL, a, 0, 0).map_or(RTN_UNICAST, |r| u32::from(r.kind))
    }

    /// Tells if `a` is a local address.
    pub fn is_local(&self, a: Addr) -> bool {
        self.addr_type(a) == RTN_LOCAL
    }

    /// Tells if `a` is a broadcast address: `255.255.255.255` or a `broadcast` route.
    pub fn is_broadcast(&self, a: Addr) -> bool {
        a == ipv4::BROADCAST
            || self
                .table_lookup(RT_TABLE_LOCAL, a, 0, 0)
                .is_some_and(|r| u32::from(r.kind) == RTN_BROADCAST)
    }

    /// The source address for a packet through `ifindex` to `dst`, as `inet_select_addr` of
    /// Linux: a primary address of the interface in the subnet of `dst`, else its first
    /// primary address with a scope that is small enough, else such an address of another
    /// interface.
    pub fn select_addr(&self, ifindex: u32, dst: Addr, scope: u8) -> Option<Addr> {
        let ok = |a: &&IfAddr| !a.is_secondary() && a.scope <= scope;
        let mine = || self.addrs_of(ifindex).filter(ok);
        if let Some(a) = mine().find(|a| dst != ipv4::ANY && a.contains(dst)) {
            return Some(a.local);
        }
        if let Some(a) = mine().next() {
            return Some(a.local);
        }
        self.addrs.iter().filter(ok).find(|a| a.scope != RT_SCOPE_LINK as u8).map(|a| a.local)
    }

    /// Checks the next hop of a new route and gives its interface and scope, as `fib_check_nh`
    /// of Linux. `up` tells if an interface is up, and gives `None` for an interface that is
    /// not there.
    ///
    /// # Errors
    ///
    /// Gives `ENODEV` for an interface that is not there, `ENETDOWN` for an interface that is
    /// down, `ENETUNREACH` for a gateway without a route, and `EINVAL` for a gateway that is
    /// not a unicast or local address.
    pub fn check_nexthop(&self, r: &Route, up: impl Fn(u32) -> Option<bool>) -> Result<u32> {
        if r.scope == RT_SCOPE_HOST as u8 {
            if r.gateway.is_some() {
                return Err(Errno::EINVAL);
            }
            up(r.ifindex).ok_or(Errno::ENODEV)?;
            return Ok(r.ifindex);
        }
        let Some(gw) = r.gateway else {
            if r.flags & RTNH_F_ONLINK != 0 {
                return Err(Errno::EINVAL);
            }
            return match up(r.ifindex) {
                None => Err(Errno::ENODEV),
                Some(false) => Err(Errno::ENETDOWN),
                Some(true) => Ok(r.ifindex),
            };
        };
        if r.flags & RTNH_F_ONLINK != 0 {
            if r.scope >= RT_SCOPE_LINK as u8 {
                return Err(Errno::EINVAL);
            }
            match up(r.ifindex) {
                None => return Err(Errno::ENODEV),
                Some(false) => return Err(Errno::ENETDOWN),
                Some(true) => {}
            }
            if self.addr_type(gw) != RTN_UNICAST {
                return Err(Errno::EINVAL);
            }
            return Ok(r.ifindex);
        }
        let scope = (r.scope + 1).max(RT_SCOPE_LINK as u8);
        let mut found = None;
        if r.table != RT_TABLE_MAIN {
            found = self.table_lookup(r.table, gw, scope, r.ifindex);
        }
        let found =
            found.or_else(|| self.fib_lookup(gw, scope, r.ifindex)).ok_or(Errno::ENETUNREACH)?;
        let kind = u32::from(found.kind);
        if kind != RTN_UNICAST && kind != RTN_LOCAL {
            return Err(Errno::EINVAL);
        }
        match up(found.ifindex) {
            Some(true) => Ok(found.ifindex),
            Some(false) => Err(Errno::ENETDOWN),
            None => Err(Errno::EINVAL),
        }
    }

    /// Finds the route to `dst`, as `ip_route_output_key` of Linux. A local address goes to
    /// the loopback device.
    ///
    /// # Errors
    ///
    /// Gives `ENETUNREACH` if no route matches, and the error of a route of the type
    /// `unreachable`, `prohibit` or `blackhole`.
    pub fn lookup(&self, dst: Addr) -> Result<Next> {
        self.lookup_route(dst, 0).map(|(n, _)| n)
    }

    /// Finds the route to `dst` through the interface `oif` if it is not 0, as `lookup`. Gives
    /// the route of the table too, or `None` for a destination on the link of `oif` without a
    /// route, as the `make_route` case of `ip_route_output_key_hash_rcu` of Linux.
    ///
    /// # Errors
    ///
    /// As `lookup`.
    pub fn lookup_route(&self, dst: Addr, oif: u32) -> Result<(Next, Option<&Route>)> {
        let Some(r) = self.fib_lookup(dst, RT_SCOPE_UNIVERSE as u8, oif) else {
            if oif == 0 {
                return Err(Errno::ENETUNREACH);
            }
            let src = self.select_addr(oif, ipv4::ANY, RT_SCOPE_LINK as u8).unwrap_or(ipv4::ANY);
            let next = Next { ifindex: oif, hop: dst, src, local: false, broadcast: false };
            return Ok((next, None));
        };
        if let Some(e) = r.error() {
            return Err(e);
        }
        let kind = u32::from(r.kind);
        if kind == RTN_LOCAL {
            let ifindex = if self.loopback != 0 { self.loopback } else { r.ifindex };
            let src = r.prefsrc.unwrap_or(dst);
            return Ok((Next { ifindex, hop: dst, src, local: true, broadcast: false }, Some(r)));
        }
        let hop = r.gateway.unwrap_or(dst);
        let src = match r.prefsrc {
            Some(s) => s,
            None => {
                // The address of the next hop, as `fib_info_update_nhc_saddr` of Linux.
                self.select_addr(r.ifindex, r.gateway.unwrap_or(ipv4::ANY), r.scope)
                    .ok_or(Errno::ENETUNREACH)?
            }
        };
        let broadcast = kind == RTN_BROADCAST || self.is_broadcast(dst);
        Ok((Next { ifindex: r.ifindex, hop, src, local: false, broadcast }, Some(r)))
    }

    /// Finds the route of a received packet to `dst`, as `ip_route_input_slow` of Linux. The
    /// route needs no source address. Gives the next hop and the type of the route, `RTN_*`.
    /// The source of the `Next` is the preferred source, or `0.0.0.0`.
    ///
    /// # Errors
    ///
    /// Gives `ENETUNREACH` if no route matches, and the error of a route of the type
    /// `unreachable`, `prohibit` or `blackhole`.
    pub fn lookup_input(&self, dst: Addr) -> Result<(Next, u8)> {
        let r = self.fib_lookup(dst, RT_SCOPE_UNIVERSE as u8, 0).ok_or(Errno::ENETUNREACH)?;
        if let Some(e) = r.error() {
            return Err(e);
        }
        let kind = u32::from(r.kind);
        let next = Next {
            ifindex: r.ifindex,
            hop: r.gateway.unwrap_or(dst),
            src: r.prefsrc.unwrap_or(ipv4::ANY),
            local: kind == RTN_LOCAL,
            broadcast: kind == RTN_BROADCAST || self.is_broadcast(dst),
        };
        Ok((next, r.kind))
    }

    /// The scope `nowhere`, for a `Match` that takes each scope.
    pub const SCOPE_ANY: u8 = RT_SCOPE_NOWHERE as u8;
}

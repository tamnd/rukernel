//! The IPv6 addresses of the interfaces and the IPv6 route table, as the tables of
//! net/ipv6/addrconf.c and net/ipv6/route.c of Linux with a list in place of the tree of
//! `fib6`.
//!
//! An address has a route to itself in the table `local` and a route to its prefix in the table
//! `main`. A lookup finds a local address first, then the longest prefix of the table `main`,
//! then the route with the smallest metric. The choice of the source address follows the rules
//! of RFC 6724 that matter for a host: the same address, the scope, the interface and the
//! longest common prefix.

use crate::ip::{self, Ip};
use crate::ipv6;
use crate::route::{INFINITY, Metrics, RTAX_MAX};
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::if_addr::{IFA_F_NOPREFIXROUTE, IFA_F_PERMANENT, IFA_F_TENTATIVE};
use rk_abi::native::netlink::{NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE};
use rk_abi::native::rtnetlink::{
    RT_TABLE_LOCAL, RT_TABLE_MAIN, RTN_BLACKHOLE, RTN_LOCAL, RTN_MULTICAST, RTN_PROHIBIT,
    RTN_UNICAST, RTN_UNREACHABLE, RTPROT_KERNEL,
};
use rk_vfs::inode::Result;

/// The metric of a route of the kernel to a prefix, `IP6_RT_PRIO_ADDRCONF` of Linux.
pub const PRIO_ADDRCONF: u32 = 256;
/// The metric of a route of a program without `RTA_PRIORITY`, `IP6_RT_PRIO_USER` of Linux.
pub const PRIO_USER: u32 = 1024;

/// An IPv6 address of an interface, as `struct inet6_ifaddr` of Linux.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Addr6 {
    /// The interface index.
    pub ifindex: u32,
    /// The address.
    pub addr: Ip,
    /// The length of the prefix.
    pub prefix: u8,
    /// The flags `IFA_F_*`.
    pub flags: u32,
    /// The valid lifetime in seconds, or `INFINITY`.
    pub valid: u32,
    /// The preferred lifetime in seconds, or `INFINITY`.
    pub preferred: u32,
    /// The time of the creation in hundredths of a second since boot.
    pub cstamp: u64,
    /// The time of the last change.
    pub tstamp: u64,
    /// The protocol that added the address, `IFA_PROTO`.
    pub proto: u8,
    /// The metric of the route to the prefix, `IFA_RT_PRIORITY`.
    pub rt_priority: u32,
}

impl Addr6 {
    /// A permanent address.
    pub fn new(ifindex: u32, addr: Ip, prefix: u8) -> Self {
        Self {
            ifindex,
            addr,
            prefix,
            flags: IFA_F_PERMANENT,
            valid: INFINITY,
            preferred: INFINITY,
            cstamp: 0,
            tstamp: 0,
            proto: 0,
            rt_priority: 0,
        }
    }
}

/// An IPv6 route, as `struct fib6_info` of Linux.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route6 {
    /// The table: `RT_TABLE_MAIN` or `RT_TABLE_LOCAL`, or another table of a program.
    pub table: u32,
    /// The destination prefix.
    pub dst: Ip,
    /// The length of the prefix.
    pub prefix: u8,
    /// The next hop, or `None` for a route to the link.
    pub gateway: Option<Ip>,
    /// The output interface.
    pub ifindex: u32,
    /// The metric.
    pub priority: u32,
    /// The protocol that added the route, `RTPROT_*`.
    pub protocol: u8,
    /// The type `RTN_*`.
    pub kind: u8,
    /// The preferred source address.
    pub prefsrc: Option<Ip>,
    /// The time in milliseconds since boot when the route goes away, for a route of a router
    /// advertisement.
    pub expires: Option<u64>,
    /// The flags `RTF_ADDRCONF` and `RTF_PREFIX_RT` of a route of a router advertisement, for
    /// /proc/net/ipv6_route.
    pub addrconf: bool,
    /// The metrics `RTAX_*`.
    pub metrics: Metrics,
}

impl Route6 {
    /// A unicast route of the table `main`.
    pub fn new(dst: Ip, prefix: u8, gateway: Option<Ip>, ifindex: u32) -> Self {
        Self {
            table: RT_TABLE_MAIN,
            dst,
            prefix,
            gateway,
            ifindex,
            priority: PRIO_USER,
            protocol: RTPROT_KERNEL as u8,
            kind: RTN_UNICAST as u8,
            prefsrc: None,
            expires: None,
            addrconf: false,
            metrics: [0; RTAX_MAX as usize],
        }
    }

    /// The route to the address `a` in the table `local`.
    fn local(a: &Addr6, lo: u32) -> Self {
        let mut r = Self::new(a.addr, 128, None, if lo != 0 { lo } else { a.ifindex });
        r.table = RT_TABLE_LOCAL;
        r.kind = RTN_LOCAL as u8;
        r.priority = 0;
        // The route keeps the interface of the address, as `ip -6 route show table local`.
        r.ifindex = a.ifindex;
        r
    }

    /// Tells if `r` is the same route: the same table, destination, metric, gateway and
    /// interface.
    fn same(&self, r: &Route6) -> bool {
        self.table == r.table
            && self.dst == r.dst
            && self.prefix == r.prefix
            && self.priority == r.priority
            && self.gateway == r.gateway
            && self.ifindex == r.ifindex
    }
}

/// The selectors of `RTM_DELROUTE`. A field with `None` takes each value.
#[derive(Clone, Debug, Default)]
pub struct Match6 {
    /// The table.
    pub table: u32,
    /// The destination.
    pub dst: Ip,
    /// The length of the prefix.
    pub prefix: u8,
    /// The gateway.
    pub gateway: Option<Ip>,
    /// The interface.
    pub ifindex: Option<u32>,
    /// The metric.
    pub priority: Option<u32>,
    /// The protocol.
    pub protocol: Option<u8>,
}

/// The result of a lookup: where a packet goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Next6 {
    /// The output interface.
    pub ifindex: u32,
    /// The neighbour: the gateway, or the destination.
    pub hop: Ip,
    /// The source address.
    pub src: Ip,
    /// The destination is a local address.
    pub local: bool,
    /// The metric `RTAX_MTU` of the route, or 0.
    pub mtu: u32,
}

/// The changes of the routes that a change of an address or a device makes, for the
/// notifications.
#[derive(Clone, Debug, Default)]
pub struct Changes6 {
    /// The routes that went away.
    pub removed: Vec<Route6>,
    /// The new routes.
    pub added: Vec<Route6>,
}

/// The IPv6 addresses and routes.
pub struct Table6 {
    addrs: Vec<Addr6>,
    routes: Vec<Route6>,
    /// The index of the loopback device, or 0.
    loopback: u32,
}

impl Default for Table6 {
    fn default() -> Self {
        Self::new()
    }
}

/// The scope of RFC 4291 of `a` for the choice of a source address: 1 for the interface, 2 for
/// the link, 5 for the site and 14 for the world.
fn scope_rank(a: &Ip) -> u8 {
    if ipv6::is_multicast(a) {
        return a[1] & 0xf;
    }
    match ipv6::scope(a) {
        ipv6::SCOPE_HOST => 1,
        ipv6::SCOPE_LINK => 2,
        ipv6::SCOPE_SITE => 5,
        _ => 14,
    }
}

/// The length of the common prefix of `a` and `b` in bits.
fn common(a: &Ip, b: &Ip) -> u32 {
    let mut n = 0;
    for (x, y) in a.iter().zip(b) {
        let d = x ^ y;
        if d != 0 {
            return n + d.leading_zeros();
        }
        n += 8;
    }
    n
}

impl Table6 {
    /// An empty table.
    pub const fn new() -> Self {
        Self { addrs: Vec::new(), routes: Vec::new(), loopback: 0 }
    }

    /// Records the index of the loopback device. A packet to a local address goes on it.
    pub fn set_loopback(&mut self, ifindex: u32) {
        self.loopback = ifindex;
    }

    /// The addresses.
    pub fn addrs(&self) -> &[Addr6] {
        &self.addrs
    }

    /// The addresses, to change their lifetimes.
    pub fn addrs_mut(&mut self) -> &mut [Addr6] {
        &mut self.addrs
    }

    /// The addresses of an interface.
    pub fn addrs_of(&self, ifindex: u32) -> impl Iterator<Item = &Addr6> {
        self.addrs.iter().filter(move |a| a.ifindex == ifindex)
    }

    /// The routes.
    pub fn routes(&self) -> &[Route6] {
        &self.routes
    }

    /// Tells if the table `table` has a route.
    pub fn has_table(&self, table: u32) -> bool {
        self.routes.iter().any(|r| r.table == table)
    }

    /// Tells if `a` is an address of an interface.
    pub fn is_local(&self, a: &Ip) -> bool {
        self.addrs.iter().any(|x| x.addr == *a)
    }

    /// Tells if the interface `ifindex` takes a packet to the multicast address `a`: the groups
    /// of all of the nodes and the solicited node groups of its addresses, as the groups that
    /// `ipv6_dev_mc_inc` joins in Linux.
    pub fn takes_multicast(&self, ifindex: u32, a: &Ip) -> bool {
        *a == ipv6::ALL_NODES
            || *a == ipv6::ALL_NODES_IF
            || self.addrs_of(ifindex).any(|x| ipv6::solicited_node(&x.addr) == *a)
    }

    /// Adds a route if it is not there, and records it in `c`.
    fn add_kernel_route(&mut self, r: Route6, c: &mut Changes6) {
        if !self.routes.iter().any(|o| o.same(&r)) {
            self.routes.push(r.clone());
            c.added.push(r);
        }
    }

    /// Adds an address with its local route and the route to its prefix, as `ipv6_add_addr` and
    /// `addrconf_prefix_route` of Linux.
    ///
    /// # Errors
    ///
    /// Gives `EEXIST` if the interface has the address, and `EINVAL` for a prefix longer than
    /// 128 bits or the address `::`.
    pub fn insert_addr(&mut self, a: Addr6) -> Result<Changes6> {
        if a.prefix > 128 || a.addr == ip::ANY || ipv6::is_multicast(&a.addr) {
            return Err(Errno::EINVAL);
        }
        if self.addrs_of(a.ifindex).any(|o| o.addr == a.addr) {
            return Err(Errno::EEXIST);
        }
        let mut c = Changes6::default();
        self.add_kernel_route(Route6::local(&a, self.loopback), &mut c);
        if a.flags & IFA_F_NOPREFIXROUTE == 0 {
            let mut r = Route6::new(ipv6::prefix(&a.addr, a.prefix), a.prefix, None, a.ifindex);
            r.priority = if a.rt_priority != 0 { a.rt_priority } else { PRIO_ADDRCONF };
            self.add_kernel_route(r, &mut c);
        }
        self.addrs.push(a);
        Ok(c)
    }

    /// Removes the first address of `ifindex` that `pred` takes, with its local route and the
    /// route to its prefix if no other address has the prefix, as `ipv6_del_addr` of Linux.
    ///
    /// # Errors
    ///
    /// Gives `EADDRNOTAVAIL` if no address matches.
    pub fn remove_addr(
        &mut self,
        ifindex: u32,
        pred: impl Fn(&Addr6) -> bool,
    ) -> Result<(Addr6, Changes6)> {
        let i = self
            .addrs
            .iter()
            .position(|a| a.ifindex == ifindex && pred(a))
            .ok_or(Errno::EADDRNOTAVAIL)?;
        let a = self.addrs.remove(i);
        let mut c = Changes6::default();
        let net = ipv6::prefix(&a.addr, a.prefix);
        let shared = self
            .addrs_of(ifindex)
            .any(|o| o.prefix == a.prefix && ipv6::prefix(&o.addr, o.prefix) == net);
        let local_shared = self.is_local(&a.addr);
        self.routes.retain(|r| {
            let local = r.kind == RTN_LOCAL as u8 && r.dst == a.addr && r.ifindex == ifindex;
            let prefix = !shared
                && r.kind == RTN_UNICAST as u8
                && r.table == RT_TABLE_MAIN
                && r.protocol == RTPROT_KERNEL as u8
                && r.gateway.is_none()
                && r.ifindex == ifindex
                && r.dst == net
                && r.prefix == a.prefix
                && !r.addrconf;
            let gone = (local && !local_shared) || prefix;
            if gone {
                c.removed.push(r.clone());
            }
            !gone
        });
        Ok((a, c))
    }

    /// Adds the routes of an interface that went up: the multicast route `ff00::/8` in the
    /// table `local`, as `addrconf_add_mroute` of Linux.
    pub fn link_up(&mut self, ifindex: u32, loopback: bool) -> Changes6 {
        let mut c = Changes6::default();
        if !loopback {
            let mut m = [0; 16];
            m[0] = 0xff;
            let mut r = Route6::new(m, 8, None, ifindex);
            r.table = RT_TABLE_LOCAL;
            r.kind = RTN_MULTICAST as u8;
            r.priority = PRIO_ADDRCONF;
            self.add_kernel_route(r, &mut c);
        }
        c
    }

    /// Removes the addresses and the routes of an interface that went down, as `addrconf_ifdown`
    /// of Linux without `keep_addr_on_down`.
    pub fn link_down(&mut self, ifindex: u32) -> (Vec<Addr6>, Changes6) {
        let (gone, kept): (Vec<Addr6>, Vec<Addr6>) =
            core::mem::take(&mut self.addrs).into_iter().partition(|a| a.ifindex == ifindex);
        self.addrs = kept;
        let mut c = Changes6::default();
        self.routes.retain(|r| {
            if r.ifindex == ifindex {
                c.removed.push(r.clone());
                return false;
            }
            true
        });
        (gone, c)
    }

    /// Adds a route of a program, as `ip6_route_add` of Linux.
    ///
    /// # Errors
    ///
    /// Gives `EEXIST` for a route that is there with `NLM_F_EXCL` or without `NLM_F_CREATE`
    /// and `NLM_F_REPLACE`, and `ENOENT` for `NLM_F_REPLACE` without such a route and without
    /// `NLM_F_CREATE`.
    pub fn insert_route(&mut self, r: Route6, flags: u32) -> Result<()> {
        if let Some(i) = self.routes.iter().position(|o| o.same(&r)) {
            if flags & NLM_F_EXCL != 0 || flags & NLM_F_REPLACE == 0 {
                return Err(Errno::EEXIST);
            }
            self.routes[i] = r;
            return Ok(());
        }
        if flags & NLM_F_REPLACE != 0 && flags & NLM_F_CREATE == 0 {
            return Err(Errno::ENOENT);
        }
        self.routes.push(r);
        Ok(())
    }

    /// Adds or changes a route of a router advertisement, and gives it if it is new.
    pub fn update_route(&mut self, r: Route6) -> Option<Route6> {
        match self.routes.iter_mut().find(|o| o.same(&r)) {
            Some(o) => {
                o.expires = r.expires;
                None
            }
            None => {
                self.routes.push(r.clone());
                Some(r)
            }
        }
    }

    /// Removes the first route that `m` takes, as `ip6_route_del` of Linux.
    ///
    /// # Errors
    ///
    /// Gives `ESRCH` if no route matches.
    pub fn delete_route(&mut self, m: &Match6) -> Result<Route6> {
        let i = self
            .routes
            .iter()
            .position(|r| {
                r.table == m.table
                    && r.dst == m.dst
                    && r.prefix == m.prefix
                    && m.gateway.is_none_or(|g| r.gateway == Some(g))
                    && m.ifindex.is_none_or(|i| r.ifindex == i)
                    && m.priority.is_none_or(|p| r.priority == p)
                    && m.protocol.is_none_or(|p| r.protocol == p)
            })
            .ok_or(Errno::ESRCH)?;
        Ok(self.routes.remove(i))
    }

    /// Removes the routes and the addresses whose time is over at `now`, in milliseconds for the
    /// routes and in hundredths of a second for the addresses.
    pub fn expire(&mut self, now_ms: u64) -> (Vec<Addr6>, Changes6) {
        let mut c = Changes6::default();
        self.routes.retain(|r| {
            if r.expires.is_some_and(|t| t <= now_ms) {
                c.removed.push(r.clone());
                return false;
            }
            true
        });
        let now_s = now_ms / 1000;
        let (gone, kept): (Vec<Addr6>, Vec<Addr6>) = core::mem::take(&mut self.addrs)
            .into_iter()
            .partition(|a| a.valid != INFINITY && a.tstamp / 100 + u64::from(a.valid) <= now_s);
        self.addrs = kept;
        for a in &gone {
            let lo = self.loopback;
            let local = Route6::local(a, lo);
            self.routes.retain(|r| {
                if r.same(&local) {
                    c.removed.push(r.clone());
                    return false;
                }
                true
            });
        }
        (gone, c)
    }

    /// Tells if the table has a route or an address with a time limit.
    pub fn has_timers(&self) -> bool {
        self.routes.iter().any(|r| r.expires.is_some())
            || self.addrs.iter().any(|a| a.valid != INFINITY)
    }

    /// The best source address for `dst` on the interface `ifindex`, as `ipv6_dev_get_saddr` of
    /// Linux with the rules of RFC 6724 that matter for a host.
    pub fn select_src(&self, dst: &Ip, ifindex: u32) -> Option<Ip> {
        let want = scope_rank(dst);
        self.addrs
            .iter()
            .filter(|a| a.flags & IFA_F_TENTATIVE == 0)
            // A link local address is good only on its own link.
            .filter(|a| !(ipv6::is_link_local(&a.addr) && a.ifindex != ifindex))
            .filter(|a| a.addr != ip::LOOPBACK || *dst == ip::LOOPBACK)
            .max_by_key(|a| {
                let s = scope_rank(&a.addr);
                (
                    a.addr == *dst,
                    // Rule 2: a scope that is large enough, then the smallest of those.
                    s >= want,
                    if s >= want { u8::MAX - s } else { s },
                    a.ifindex == ifindex,
                    common(&a.addr, dst),
                )
            })
            .map(|a| a.addr)
    }

    /// Finds the route to `dst`, as `ip6_route_output` of Linux. `oif` is the interface of the
    /// socket or of the scope ID, or 0.
    ///
    /// # Errors
    ///
    /// Gives `ENETUNREACH` if no route matches, and `EADDRNOTAVAIL` if the interface has no
    /// source address.
    pub fn lookup(&self, dst: &Ip, oif: u32) -> Result<Next6> {
        self.lookup_route(dst, oif).map(|(n, _)| n)
    }

    /// Finds the route to `dst` as `lookup`, and gives the route of the table too.
    ///
    /// # Errors
    ///
    /// Gives the errors of `lookup`.
    pub fn lookup_route(&self, dst: &Ip, oif: u32) -> Result<(Next6, Option<&Route6>)> {
        if let Some(a) = self.addrs.iter().find(|a| a.addr == *dst) {
            let ifindex = if self.loopback != 0 { self.loopback } else { a.ifindex };
            let next = Next6 { ifindex, hop: *dst, src: *dst, local: true, mtu: 0 };
            let route = self.routes.iter().find(|r| r.same(&Route6::local(a, self.loopback)));
            return Ok((next, route));
        }
        let route = self
            .routes
            .iter()
            .filter(|r| {
                let table_ok = r.table == RT_TABLE_MAIN
                    || (r.table == RT_TABLE_LOCAL && r.kind == RTN_MULTICAST as u8);
                table_ok
                    && matches!(
                        u32::from(r.kind),
                        RTN_UNICAST
                            | RTN_MULTICAST
                            | RTN_UNREACHABLE
                            | RTN_PROHIBIT
                            | RTN_BLACKHOLE
                    )
                    && (oif == 0 || r.ifindex == oif)
                    && ipv6::same_net(&r.dst, dst, r.prefix)
            })
            .max_by_key(|r| (r.prefix, u32::MAX - r.priority));
        // A route that rejects gives the error of `ip6_rt_type_to_error` of Linux.
        match route.map(|r| u32::from(r.kind)) {
            Some(RTN_UNREACHABLE) => return Err(Errno::ENETUNREACH),
            Some(RTN_PROHIBIT) => return Err(Errno::EACCES),
            Some(RTN_BLACKHOLE) => return Err(Errno::EINVAL),
            _ => {}
        }
        let (ifindex, hop, mtu) = match route {
            Some(r) => (r.ifindex, r.gateway.unwrap_or(*dst), r.metrics[1]),
            // A link local destination with an interface needs no route.
            None if oif != 0 && ipv6::needs_scope(dst) => (oif, *dst, 0),
            None => return Err(Errno::ENETUNREACH),
        };
        let src = match route.and_then(|r| r.prefsrc) {
            Some(s) => s,
            None => self.select_src(dst, ifindex).ok_or(Errno::EADDRNOTAVAIL)?,
        };
        Ok((Next6 { ifindex, hop, src, local: false, mtu }, route))
    }

    /// Tells if the interface `ifindex` has the link local address `a` or has an address.
    pub fn has_addr(&self, ifindex: u32) -> bool {
        self.addrs_of(ifindex).next().is_some()
    }
}

//! The addresses of the interfaces and the route table, as the `local` and `main` tables of
//! net/ipv4/fib_*.c of Linux, with a list in place of a trie.
//!
//! An address on an interface adds a connected route to its subnet. The address and, on the
//! loopback interface, the whole subnet are local: a packet to a local address goes through the
//! loopback device, as Linux does it.

use crate::ipv4::{self, Addr};
use alloc::vec::Vec;

/// An address of an interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IfAddr {
    /// The interface index.
    pub ifindex: u32,
    /// The address.
    pub addr: Addr,
    /// The length of the prefix of the subnet.
    pub prefix: u8,
    /// Tells if the interface is the loopback device.
    pub loopback: bool,
}

impl IfAddr {
    /// The broadcast address of the subnet. A prefix of 31 or 32 bits has none.
    pub fn broadcast(&self) -> Option<Addr> {
        if self.prefix >= 31 {
            return None;
        }
        Some((u32::from_be_bytes(self.addr) | !ipv4::mask(self.prefix)).to_be_bytes())
    }
}

/// A route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    /// The destination subnet.
    pub dst: Addr,
    /// The length of the prefix of the destination.
    pub prefix: u8,
    /// The gateway, or `None` for a subnet on the link.
    pub gateway: Option<Addr>,
    /// The interface index.
    pub ifindex: u32,
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

/// The addresses and the routes.
#[derive(Default)]
pub struct Table {
    addrs: Vec<IfAddr>,
    routes: Vec<Route>,
}

impl Table {
    /// An empty table.
    pub const fn new() -> Self {
        Self { addrs: Vec::new(), routes: Vec::new() }
    }

    /// Adds an address and the connected route of its subnet, as `fib_add_ifaddr` of Linux.
    pub fn add_addr(&mut self, a: IfAddr) {
        if self.addrs.contains(&a) {
            return;
        }
        self.addrs.push(a);
        let dst = (u32::from_be_bytes(a.addr) & ipv4::mask(a.prefix)).to_be_bytes();
        self.add_route(Route { dst, prefix: a.prefix, gateway: None, ifindex: a.ifindex });
    }

    /// Adds a route. A route with the same destination and prefix takes the place of the old
    /// one.
    pub fn add_route(&mut self, r: Route) {
        let dst = (u32::from_be_bytes(r.dst) & ipv4::mask(r.prefix)).to_be_bytes();
        let r = Route { dst, ..r };
        self.routes.retain(|o| (o.dst, o.prefix) != (r.dst, r.prefix));
        self.routes.push(r);
    }

    /// Removes the addresses and the routes of an interface.
    pub fn remove_iface(&mut self, ifindex: u32) {
        self.addrs.retain(|a| a.ifindex != ifindex);
        self.routes.retain(|r| r.ifindex != ifindex);
    }

    /// The addresses.
    pub fn addrs(&self) -> &[IfAddr] {
        &self.addrs
    }

    /// The routes.
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// The first address of an interface.
    pub fn addr_of(&self, ifindex: u32) -> Option<Addr> {
        self.addrs.iter().find(|a| a.ifindex == ifindex).map(|a| a.addr)
    }

    /// Tells if `a` is a local address: an address of an interface, or an address in the subnet
    /// of the loopback interface.
    pub fn is_local(&self, a: Addr) -> bool {
        self.addrs
            .iter()
            .any(|i| i.addr == a || (i.loopback && ipv4::same_net(i.addr, a, i.prefix)))
    }

    /// Tells if `a` is a broadcast address: `255.255.255.255` or the broadcast address of a
    /// subnet.
    pub fn is_broadcast(&self, a: Addr) -> bool {
        a == ipv4::BROADCAST || self.addrs.iter().any(|i| i.broadcast() == Some(a))
    }

    /// The interface index of the loopback device, if it has an address.
    fn loopback(&self) -> Option<&IfAddr> {
        self.addrs.iter().find(|a| a.loopback)
    }

    /// Finds the route to `dst`, as `ip_route_output_key` of Linux. A local address goes to the
    /// loopback device. Else the longest prefix wins. Gives `None` if no route matches.
    pub fn lookup(&self, dst: Addr) -> Option<Next> {
        if self.is_local(dst) {
            let lo = self.loopback()?;
            return Some(Next {
                ifindex: lo.ifindex,
                hop: dst,
                src: dst,
                local: true,
                broadcast: false,
            });
        }
        let r = self
            .routes
            .iter()
            .filter(|r| ipv4::same_net(r.dst, dst, r.prefix))
            .max_by_key(|r| r.prefix)?;
        let hop = r.gateway.unwrap_or(dst);
        // The source is the address of the interface in the subnet of the next hop, else the
        // first address of the interface, as `inet_select_addr` of Linux.
        let mine = self.addrs.iter().filter(|a| a.ifindex == r.ifindex);
        let src = mine
            .clone()
            .find(|a| ipv4::same_net(a.addr, hop, a.prefix))
            .or_else(|| mine.clone().next())?
            .addr;
        let broadcast = self.is_broadcast(dst);
        Some(Next { ifindex: r.ifindex, hop, src, local: false, broadcast })
    }
}

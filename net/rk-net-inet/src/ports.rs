//! The table of the bound ports of one protocol, as the hash tables of `udp_lib_get_port` in
//! net/ipv4/udp.c of Linux.
//!
//! Two sockets can have the same port if their addresses do not overlap, or if both set
//! `SO_REUSEADDR`. The address `0.0.0.0` overlaps each IPv4 address, and `::` overlaps each
//! address unless the socket has `IPV6_V6ONLY`. The table has one key for both families: an
//! IPv4 address is an IPv4-mapped address.

use crate::ip::{self, Ip};
use crate::ipv4::Addr;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ops::RangeInclusive;
use rk_abi::Errno;

/// The range of the ephemeral ports, `net.ipv4.ip_local_port_range` of Linux.
pub const EPHEMERAL: RangeInclusive<u16> = 32768..=60999;

/// A socket on a port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The local address, `::` or `0.0.0.0` for each address.
    pub addr: Ip,
    /// Tells if the socket set `SO_REUSEADDR`.
    pub reuse: bool,
    /// The ID of the socket.
    pub id: u64,
    /// The socket takes only IPv6 packets, `IPV6_V6ONLY`.
    pub v6only: bool,
}

impl Binding {
    /// The binding of an IPv4 socket to `addr`.
    pub fn v4(addr: Addr, reuse: bool, id: u64) -> Self {
        Self { addr: ip::mapped(addr), reuse, id, v6only: false }
    }
}

/// The bound ports.
pub struct Ports {
    ports: BTreeMap<u16, Vec<Binding>>,
    range: RangeInclusive<u16>,
    /// The next port that the search for a free port tries first.
    hint: u16,
}

impl Ports {
    /// An empty table that gives free ports from `range`.
    pub const fn new(range: RangeInclusive<u16>) -> Self {
        let hint = *range.start();
        Self { ports: BTreeMap::new(), range, hint }
    }

    /// Tells if `b` can bind the port `port`.
    fn free(&self, port: u16, b: &Binding) -> bool {
        self.ports.get(&port).is_none_or(|list| {
            list.iter()
                .filter(|o| o.id != b.id)
                .all(|o| !ip::overlap(&o.addr, o.v6only, &b.addr, b.v6only) || (o.reuse && b.reuse))
        })
    }

    /// Binds `b` to `port`, or to a free port of the range if `port` is 0. Gives the port.
    ///
    /// # Errors
    ///
    /// Gives `EADDRINUSE` if the port is in use, or if no port of the range is free.
    pub fn bind(&mut self, port: u16, b: Binding) -> Result<u16, Errno> {
        let port = if port != 0 {
            if !self.free(port, &b) {
                return Err(Errno::EADDRINUSE);
            }
            port
        } else {
            self.pick(&b)?
        };
        self.ports.entry(port).or_default().push(b);
        Ok(port)
    }

    /// Finds a free port for `b`. The search starts at the hint and goes around the range, and
    /// the hint moves past the port, so that a new socket does not get the port of a socket
    /// that closed a moment before.
    fn pick(&mut self, b: &Binding) -> Result<u16, Errno> {
        let (lo, hi) = (*self.range.start(), *self.range.end());
        let count = u32::from(hi - lo) + 1;
        for i in 0..count {
            let port = lo + ((u32::from(self.hint - lo) + i) % count) as u16;
            if self.free(port, b) {
                self.hint = if port == hi { lo } else { port + 1 };
                return Ok(port);
            }
        }
        Err(Errno::EADDRINUSE)
    }

    /// Tells if `b` can have `port`, beside the binding of `b.id` itself. A TCP socket checks
    /// this before `listen`.
    pub fn is_free(&self, port: u16, b: &Binding) -> bool {
        self.free(port, b)
    }

    /// Adds `b` to `port` without the check, for a TCP connection that a listening socket made.
    pub fn add(&mut self, port: u16, b: Binding) {
        self.ports.entry(port).or_default().push(b);
    }

    /// Changes the flag `reuse` of the socket `id` on `port`. A listening TCP socket clears it,
    /// so that no other socket binds the port.
    pub fn set_reuse(&mut self, port: u16, id: u64, reuse: bool) {
        if let Some(b) = self.ports.get_mut(&port).and_then(|l| l.iter_mut().find(|b| b.id == id)) {
            b.reuse = reuse;
        }
    }

    /// Changes the address of the socket `id` on `port`, for `connect` on a socket that has the
    /// address `0.0.0.0` or `::`.
    pub fn set_addr(&mut self, port: u16, id: u64, addr: Ip) {
        if let Some(b) = self.ports.get_mut(&port).and_then(|l| l.iter_mut().find(|b| b.id == id)) {
            b.addr = addr;
        }
    }

    /// Removes the socket `id` from `port`.
    pub fn unbind(&mut self, port: u16, id: u64) {
        if let Some(list) = self.ports.get_mut(&port) {
            list.retain(|b| b.id != id);
            if list.is_empty() {
                self.ports.remove(&port);
            }
        }
    }

    /// The sockets on `port` that take a packet to `dst`: the sockets with the address `dst`
    /// and the sockets with a wildcard address. The first have priority.
    pub fn find(&self, port: u16, dst: Ip) -> Vec<Binding> {
        let mut found: Vec<Binding> = self
            .ports
            .get(&port)
            .map(|l| l.iter().filter(|b| ip::takes(&b.addr, b.v6only, &dst)).copied().collect())
            .unwrap_or_default();
        found.sort_by_key(|b| ip::is_any(&b.addr));
        found
    }
}

//! The neighbour table of IPv4 and IPv6 over Ethernet, as net/core/neighbour.c, net/ipv4/arp.c
//! and net/ipv6/ndisc.c of Linux, with fewer states. The type `A` of the address is `Addr` for
//! ARP and `Ip` for neighbour discovery.
//!
//! An entry is `Incomplete` while the table waits for an ARP reply. It keeps the packets to
//! that address until the reply comes. The table sends a request each `RETRANS_MS`, at most
//! `MAX_PROBES` times, and then it drops the entry and its packets. A reply makes the entry
//! `Reachable` for `REACHABLE_MS`. After that time the table still uses the address, but it
//! sends a new request at the next use, as the `STALE` state of Linux. An entry that nobody
//! uses for `GC_MS` goes away.
//!
//! The administrator adds, changes and removes entries with `set` and `remove`, as `neigh_add`
//! and `neigh_delete` of Linux. A `Permanent` or `Noarp` entry does not change by ARP and does
//! not go away by itself.
//!
//! The table records each change of an entry in `changes`, and the caller sends them to
//! `RTNLGRP_NEIGH`, as `neigh_update_notify` and `__neigh_notify` of Linux.
//!
//! The table does not send frames itself. Each call gives the work to the caller, and the
//! caller gives the time in milliseconds. Thus the host tests can run the table.

use crate::ipv4::Addr;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::netlink::{NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE};
use rk_net::ether::MacAddr;

/// The time between two requests, `retrans_time` of Linux.
pub const RETRANS_MS: u64 = 1000;
/// The count of requests before the table drops an entry, `mcast_solicit` of Linux.
pub const MAX_PROBES: u32 = 3;
/// The time that a reply is good for, `base_reachable_time` of Linux.
pub const REACHABLE_MS: u64 = 30_000;
/// The time after the last use that an entry goes away, `gc_staletime` of Linux.
pub const GC_MS: u64 = 60_000;
/// The most packets that wait for one address. Linux counts bytes with `unres_qlen_bytes`.
pub const QUEUE_LEN: usize = 8;

/// The key of an entry: the interface index and the address.
pub type Key<A = Addr> = (u32, A);

enum State<P> {
    Incomplete {
        queue: VecDeque<P>,
        probes: u32,
        next: u64,
    },
    /// `stale` is set by the administrator, as `NUD_STALE`, until the next probe.
    Reachable {
        mac: MacAddr,
        confirmed: u64,
        stale: bool,
    },
    /// An entry of the administrator that never changes by itself: `Permanent` or `Noarp`.
    Static {
        mac: MacAddr,
        nud: Nud,
    },
}

struct Entry<P> {
    state: State<P>,
    used: u64,
    updated: u64,
}

/// The state of an entry, `NUD_*` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nud {
    /// The table waits for a reply, `NUD_INCOMPLETE`.
    Incomplete,
    /// A reply came in the last `REACHABLE_MS`, `NUD_REACHABLE`.
    Reachable,
    /// The reply is older than `REACHABLE_MS`, `NUD_STALE`.
    Stale,
    /// The administrator set the address, and it does not change, `NUD_PERMANENT`.
    Permanent,
    /// The address needs no resolution, `NUD_NOARP`.
    Noarp,
}

/// An entry of the table, for a dump of `RTM_GETNEIGH` and for /proc/net/arp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info<A = Addr> {
    /// The interface index.
    pub ifindex: u32,
    /// The address.
    pub addr: A,
    /// The hardware address, if the table knows it.
    pub mac: Option<MacAddr>,
    /// The state.
    pub state: Nud,
    /// The count of requests without a reply.
    pub probes: u32,
    /// The time since the last reply, in milliseconds.
    pub confirmed: u64,
    /// The time since the last use, in milliseconds.
    pub used: u64,
    /// The time since the last change, in milliseconds.
    pub updated: u64,
}

impl<A> Info<A> {
    /// The entry with the address that `f` gives, as an IPv4 address in an IPv6 one.
    pub fn map<B>(self, f: impl FnOnce(A) -> B) -> Info<B> {
        Info {
            ifindex: self.ifindex,
            addr: f(self.addr),
            mac: self.mac,
            state: self.state,
            probes: self.probes,
            confirmed: self.confirmed,
            used: self.used,
            updated: self.updated,
        }
    }
}

/// What the caller must do after `resolve`.
#[derive(Debug, PartialEq, Eq)]
pub enum Resolve<P> {
    /// Send the packet to the address `mac`. If `probe` is true, the address is old, and the
    /// caller also sends an ARP request for it.
    Send {
        /// The packet.
        packet: P,
        /// The hardware address.
        mac: MacAddr,
        /// Send a request too.
        probe: bool,
    },
    /// The packet waits. If `probe` is true, send an ARP request for the address now.
    Wait {
        /// Send a request now.
        probe: bool,
    },
}

/// A change of an entry, for the netlink message of the change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change<A = Addr> {
    /// The entry is new or it has a new state or a new address, `RTM_NEWNEIGH`.
    New(Info<A>),
    /// The entry went away, `RTM_DELNEIGH`.
    Del(Info<A>),
}

/// The neighbour table. `P` is the type of a packet that waits, and `A` the type of an address.
pub struct Table<P, A = Addr> {
    entries: BTreeMap<Key<A>, Entry<P>>,
    /// The packets that the table dropped: a full queue, or no reply.
    pub dropped: u64,
    /// The changes that the caller did not send yet.
    changes: Vec<Change<A>>,
}

/// The entry `key` at the time `now`.
fn info<P, A: Copy>(&(ifindex, addr): &Key<A>, e: &Entry<P>, now: u64) -> Info<A> {
    let ago = |t: u64| now.saturating_sub(t);
    let (mac, state, probes, confirmed) = match &e.state {
        State::Incomplete { probes, .. } => (None, Nud::Incomplete, *probes, e.updated),
        State::Reachable { mac, confirmed, stale } => {
            let state =
                if !*stale && ago(*confirmed) < REACHABLE_MS { Nud::Reachable } else { Nud::Stale };
            (Some(*mac), state, 0, *confirmed)
        }
        State::Static { mac, nud } => (Some(*mac), *nud, 0, e.updated),
    };
    Info {
        ifindex,
        addr,
        mac,
        state,
        probes,
        confirmed: ago(confirmed),
        used: ago(e.used),
        updated: ago(e.updated),
    }
}

impl<P, A: Copy + Ord> Default for Table<P, A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P, A: Copy + Ord> Table<P, A> {
    /// An empty table.
    pub const fn new() -> Self {
        Self { entries: BTreeMap::new(), dropped: 0, changes: Vec::new() }
    }

    /// Takes the changes since the last call, for `RTM_NEWNEIGH` and `RTM_DELNEIGH`.
    pub fn take_changes(&mut self) -> Vec<Change<A>> {
        core::mem::take(&mut self.changes)
    }

    /// Records a new state of `key` if the state or the address is not `old`, as
    /// `__neigh_update` of Linux that sends a notification only for a change.
    fn changed(&mut self, key: Key<A>, old: Option<(Nud, Option<MacAddr>)>, now: u64) {
        if let Some(e) = self.entries.get(&key) {
            let new = info(&key, e, now);
            if old != Some((new.state, new.mac)) {
                self.changes.push(Change::New(new));
            }
        }
    }

    /// The state and the address of `key`, to find a change.
    fn state_of(&self, key: Key<A>, now: u64) -> Option<(Nud, Option<MacAddr>)> {
        self.entries.get(&key).map(|e| {
            let i = info(&key, e, now);
            (i.state, i.mac)
        })
    }

    /// Finds the hardware address of `key` for `packet`, as `neigh_resolve_output` of Linux.
    /// A known address gives `Resolve::Send`. An entry that is older than `REACHABLE_MS` gives
    /// the address too, with a request. An unknown address makes an `Incomplete` entry that
    /// keeps the packet.
    pub fn resolve(&mut self, key: Key<A>, now: u64, packet: P) -> Resolve<P> {
        let entry = self.entries.entry(key).or_insert_with(|| Entry {
            state: State::Incomplete { queue: VecDeque::new(), probes: 0, next: now },
            used: now,
            updated: now,
        });
        entry.used = now;
        match &mut entry.state {
            State::Reachable { mac, confirmed, stale } => {
                let probe = *stale || now.saturating_sub(*confirmed) >= REACHABLE_MS;
                if probe {
                    // Send one request each `RETRANS_MS` until a reply comes.
                    *confirmed = now.saturating_sub(REACHABLE_MS - RETRANS_MS);
                    *stale = false;
                }
                Resolve::Send { packet, mac: *mac, probe }
            }
            State::Static { mac, .. } => Resolve::Send { packet, mac: *mac, probe: false },
            State::Incomplete { queue, probes, next } => {
                if queue.len() >= QUEUE_LEN {
                    queue.pop_front();
                    self.dropped += 1;
                }
                queue.push_back(packet);
                let probe = *probes == 0;
                if probe {
                    *probes = 1;
                    *next = now + RETRANS_MS;
                }
                Resolve::Wait { probe }
            }
        }
    }

    /// The hardware address of `key`, if the table knows it.
    pub fn lookup(&self, key: Key<A>) -> Option<MacAddr> {
        match self.entries.get(&key)?.state {
            State::Reachable { mac, .. } | State::Static { mac, .. } => Some(mac),
            State::Incomplete { .. } => None,
        }
    }

    /// Tells if the table has an entry for `key`.
    pub fn contains(&self, key: Key<A>) -> bool {
        self.entries.contains_key(&key)
    }

    /// Adds or changes an entry for the administrator, as `neigh_add` and `__neigh_update` of
    /// Linux with `NEIGH_UPDATE_F_ADMIN`. Without `mac`, the entry keeps its old address. If
    /// `replace` is false, a different old address stays, as an update without
    /// `NEIGH_UPDATE_F_OVERRIDE`. Gives the packets that waited for the address, or `None` if
    /// the state is not valid or the entry has no address.
    pub fn set(
        &mut self,
        key: Key<A>,
        mac: Option<MacAddr>,
        nud: Nud,
        now: u64,
        replace: bool,
    ) -> Option<Vec<P>> {
        let old = self.lookup(key);
        let mac = match (mac, old) {
            (Some(_), Some(o)) if !replace => o,
            (Some(m), _) => m,
            (None, Some(o)) => o,
            (None, None) => return None,
        };
        let before = self.state_of(key, now);
        let state = match nud {
            Nud::Permanent | Nud::Noarp => State::Static { mac, nud },
            Nud::Reachable => State::Reachable { mac, confirmed: now, stale: false },
            Nud::Stale => State::Reachable { mac, confirmed: now, stale: true },
            Nud::Incomplete => return None,
        };
        let waiting = match self.entries.get_mut(&key) {
            Some(entry) => {
                entry.updated = now;
                match core::mem::replace(&mut entry.state, state) {
                    State::Incomplete { queue, .. } => queue.into(),
                    _ => Vec::new(),
                }
            }
            None => {
                self.entries.insert(key, Entry { state, used: now, updated: now });
                Vec::new()
            }
        };
        self.changed(key, before, now);
        Some(waiting)
    }

    /// Adds or changes an entry for `RTM_NEWNEIGH` with the netlink flags `flags`, as
    /// `neigh_add` of Linux: `NLM_F_EXCL` refuses an entry that exists, a new entry needs
    /// `NLM_F_CREATE`, and `NLM_F_REPLACE` changes the address of an entry.
    ///
    /// # Errors
    ///
    /// Gives `EEXIST`, `ENOENT`, or `EINVAL` if the entry has no address.
    pub fn add(
        &mut self,
        key: Key<A>,
        mac: Option<MacAddr>,
        nud: Nud,
        now: u64,
        flags: u32,
    ) -> Result<Vec<P>, Errno> {
        let exists = self.contains(key);
        if exists && flags & NLM_F_EXCL != 0 {
            return Err(Errno::EEXIST);
        }
        if !exists && flags & NLM_F_CREATE == 0 {
            return Err(Errno::ENOENT);
        }
        let replace = !exists || flags & NLM_F_REPLACE != 0;
        self.set(key, mac, nud, now, replace).ok_or(Errno::EINVAL)
    }

    /// Removes the entry `key` and drops the packets that wait for it, as `neigh_delete` of
    /// Linux. Gives `false` if there is no entry.
    pub fn remove(&mut self, key: Key<A>, now: u64) -> bool {
        match self.entries.remove(&key) {
            Some(e) => {
                self.changes.push(Change::Del(info(&key, &e, now)));
                if let State::Incomplete { queue, .. } = e.state {
                    self.dropped += queue.len() as u64;
                }
                true
            }
            None => false,
        }
    }

    /// Records that `key` has the address `mac`, from an ARP packet, as `neigh_update` of
    /// Linux. If `create` is false, only an entry that exists changes. Gives the packets that
    /// waited for the address, for the caller to send.
    pub fn update(&mut self, key: Key<A>, mac: MacAddr, now: u64, create: bool) -> Vec<P> {
        let reachable = State::Reachable { mac, confirmed: now, stale: false };
        let before = self.state_of(key, now);
        let waiting = match self.entries.get_mut(&key) {
            // ARP does not change an entry of the administrator, as `__neigh_update` gives
            // `EPERM` for `NUD_PERMANENT` and `NUD_NOARP` without `NEIGH_UPDATE_F_ADMIN`.
            Some(Entry { state: State::Static { .. }, .. }) => Vec::new(),
            Some(entry) => {
                entry.updated = now;
                match core::mem::replace(&mut entry.state, reachable) {
                    State::Incomplete { queue, .. } => queue.into(),
                    _ => Vec::new(),
                }
            }
            None => {
                if create {
                    self.entries.insert(key, Entry { state: reachable, used: now, updated: now });
                }
                Vec::new()
            }
        };
        self.changed(key, before, now);
        waiting
    }

    /// Runs the timers, as `neigh_timer_handler` of Linux. Gives the keys that need a new
    /// request. An entry with `MAX_PROBES` requests and no reply goes away with its packets,
    /// and an entry that nobody used for `GC_MS` goes away too.
    pub fn tick(&mut self, now: u64) -> Vec<Key<A>> {
        let mut probes = Vec::new();
        let mut dropped = 0;
        let mut gone = Vec::new();
        self.entries.retain(|key, entry| {
            let keep = match &mut entry.state {
                State::Incomplete { queue, probes: n, next } => {
                    if now < *next {
                        return true;
                    }
                    if *n >= MAX_PROBES {
                        dropped += queue.len() as u64;
                        false
                    } else {
                        *n += 1;
                        *next = now + RETRANS_MS;
                        probes.push(*key);
                        true
                    }
                }
                State::Reachable { .. } => now.saturating_sub(entry.used) < GC_MS,
                State::Static { .. } => true,
            };
            if !keep {
                gone.push(Change::Del(info(key, entry, now)));
            }
            keep
        });
        self.dropped += dropped;
        self.changes.extend(gone);
        probes
    }

    /// Tells if the table has work for `tick`: an entry that waits for a reply.
    pub fn pending(&self) -> bool {
        self.entries.values().any(|e| matches!(e.state, State::Incomplete { .. }))
    }

    /// Removes the entries of an interface.
    pub fn flush(&mut self, ifindex: u32, now: u64) {
        let mut gone = Vec::new();
        self.entries.retain(|key, e| {
            if key.0 == ifindex {
                gone.push(Change::Del(info(key, e, now)));
            }
            key.0 != ifindex
        });
        self.changes.extend(gone);
    }

    /// The entries at the time `now`, by interface and address.
    pub fn entries(&self, now: u64) -> Vec<Info<A>> {
        self.entries.iter().map(|(key, e)| info(key, e, now)).collect()
    }

    /// The count of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Tells if the table has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// An entry of the proxy table, for a dump of `RTM_GETNEIGH` with `NTF_PROXY`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProxyInfo<A = Addr> {
    /// The address.
    pub addr: A,
    /// The interface index, or 0 for an entry of each interface.
    pub ifindex: u32,
    /// The flags `NTF_*` of the request that made the entry.
    pub flags: u8,
}

impl<A> ProxyInfo<A> {
    /// The entry with the address that `f` gives.
    pub fn map<B>(self, f: impl FnOnce(A) -> B) -> ProxyInfo<B> {
        ProxyInfo { addr: f(self.addr), ifindex: self.ifindex, flags: self.flags }
    }
}

/// The proxy entries of a neighbour table, as `struct pneigh_entry` and `pneigh_lookup`,
/// `pneigh_create` and `pneigh_delete` in net/core/neighbour.c of Linux. The host answers the
/// requests for the address of an entry with its own link address. An entry with the
/// interface 0 is for each interface.
pub struct Proxy<A = Addr> {
    entries: BTreeMap<(A, u32), u8>,
}

impl<A: Copy + Ord> Default for Proxy<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Copy + Ord> Proxy<A> {
    /// An empty table.
    pub const fn new() -> Self {
        Self { entries: BTreeMap::new() }
    }

    /// Adds the entry of `addr` on `ifindex`, or sets the flags of the entry that is there, as
    /// `pneigh_create` of Linux.
    pub fn add(&mut self, addr: A, ifindex: u32, flags: u8) {
        self.entries.insert((addr, ifindex), flags);
    }

    /// Removes the entry of `addr` on `ifindex`, as `pneigh_delete` of Linux. Gives `false` if
    /// there is no entry. The interface must be the same, 0 included.
    pub fn remove(&mut self, addr: A, ifindex: u32) -> bool {
        self.entries.remove(&(addr, ifindex)).is_some()
    }

    /// Tells if an entry of `addr` is for `ifindex`: an entry on the interface or an entry for
    /// each interface, as `pneigh_lookup` of Linux.
    pub fn lookup(&self, addr: A, ifindex: u32) -> bool {
        self.entries.contains_key(&(addr, ifindex)) || self.entries.contains_key(&(addr, 0))
    }

    /// Removes the entries of an interface, as `pneigh_ifdown` of Linux.
    pub fn flush(&mut self, ifindex: u32) {
        self.entries.retain(|k, _| k.1 != ifindex);
    }

    /// The entries, by address and interface.
    pub fn entries(&self) -> Vec<ProxyInfo<A>> {
        self.entries
            .iter()
            .map(|(&(addr, ifindex), &flags)| ProxyInfo { addr, ifindex, flags })
            .collect()
    }

    /// Tells if the table has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The time between two redirects to one host at the start, in milliseconds, as
/// `ip_rt_redirect_load` of Linux (`HZ / 50`). The time doubles after each redirect.
pub const REDIRECT_LOAD_MS: u64 = 20;
/// The most redirects to one host without a pause, `ip_rt_redirect_number` of Linux.
pub const REDIRECT_NUMBER: u32 = 9;
/// The pause after which the count of redirects to a host starts again,
/// `ip_rt_redirect_silence` of Linux.
pub const REDIRECT_SILENCE_MS: u64 = REDIRECT_LOAD_MS << (REDIRECT_NUMBER + 1);
/// The most hosts in the redirect table. A full table starts again empty.
const REDIRECT_HOSTS: usize = 1024;

/// The limit of the ICMP redirects to each host, as the `n_redirects` and `rate_last` fields of
/// `struct inet_peer` and `ip_rt_send_redirect` in net/ipv4/route.c of Linux.
pub struct Redirects<A = Addr> {
    peers: BTreeMap<A, (u32, Option<u64>)>,
}

impl<A: Copy + Ord> Default for Redirects<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Copy + Ord> Redirects<A> {
    /// An empty table.
    pub const fn new() -> Self {
        Self { peers: BTreeMap::new() }
    }

    /// Tells if the host can send a redirect to `host` at the time `now`, and records it. The
    /// first redirect goes at once, and each next one waits two times longer. After
    /// `REDIRECT_NUMBER` redirects, the host sends no more until the host gets no redirect for
    /// `REDIRECT_SILENCE_MS`.
    pub fn allow(&mut self, host: A, now: u64) -> bool {
        if self.peers.len() >= REDIRECT_HOSTS && !self.peers.contains_key(&host) {
            self.peers.clear();
        }
        let (n, last) = self.peers.entry(host).or_insert((0, None));
        if last.is_none_or(|l| now > l + REDIRECT_SILENCE_MS) {
            *n = 0;
        }
        if *n >= REDIRECT_NUMBER {
            *last = Some(now);
            return false;
        }
        if *n == 0 || last.is_some_and(|l| now > l + (REDIRECT_LOAD_MS << *n)) {
            *last = Some(now);
            *n += 1;
            return true;
        }
        false
    }
}

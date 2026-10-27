//! The neighbour table of IPv4 over Ethernet, as net/core/neighbour.c and net/ipv4/arp.c of
//! Linux, with fewer states.
//!
//! An entry is `Incomplete` while the table waits for an ARP reply. It keeps the packets to
//! that address until the reply comes. The table sends a request each `RETRANS_MS`, at most
//! `MAX_PROBES` times, and then it drops the entry and its packets. A reply makes the entry
//! `Reachable` for `REACHABLE_MS`. After that time the table still uses the address, but it
//! sends a new request at the next use, as the `STALE` state of Linux. An entry that nobody
//! uses for `GC_MS` goes away.
//!
//! The table does not send frames itself. Each call gives the work to the caller, and the
//! caller gives the time in milliseconds. Thus the host tests can run the table.

use crate::ipv4::Addr;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
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
pub type Key = (u32, Addr);

enum State<P> {
    Incomplete { queue: VecDeque<P>, probes: u32, next: u64 },
    Reachable { mac: MacAddr, confirmed: u64 },
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
}

/// An entry of the table, for a dump of `RTM_GETNEIGH` and for /proc/net/arp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    /// The interface index.
    pub ifindex: u32,
    /// The address.
    pub addr: Addr,
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

/// The neighbour table. `P` is the type of a packet that waits.
pub struct Table<P> {
    entries: BTreeMap<Key, Entry<P>>,
    /// The packets that the table dropped: a full queue, or no reply.
    pub dropped: u64,
}

impl<P> Default for Table<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P> Table<P> {
    /// An empty table.
    pub const fn new() -> Self {
        Self { entries: BTreeMap::new(), dropped: 0 }
    }

    /// Finds the hardware address of `key` for `packet`, as `neigh_resolve_output` of Linux.
    /// A known address gives `Resolve::Send`. An entry that is older than `REACHABLE_MS` gives
    /// the address too, with a request. An unknown address makes an `Incomplete` entry that
    /// keeps the packet.
    pub fn resolve(&mut self, key: Key, now: u64, packet: P) -> Resolve<P> {
        let entry = self.entries.entry(key).or_insert_with(|| Entry {
            state: State::Incomplete { queue: VecDeque::new(), probes: 0, next: now },
            used: now,
            updated: now,
        });
        entry.used = now;
        match &mut entry.state {
            State::Reachable { mac, confirmed } => {
                let stale = now.saturating_sub(*confirmed) >= REACHABLE_MS;
                if stale {
                    // Send one request each `RETRANS_MS` until a reply comes.
                    *confirmed = now.saturating_sub(REACHABLE_MS - RETRANS_MS);
                }
                Resolve::Send { packet, mac: *mac, probe: stale }
            }
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
    pub fn lookup(&self, key: Key) -> Option<MacAddr> {
        match self.entries.get(&key)?.state {
            State::Reachable { mac, .. } => Some(mac),
            State::Incomplete { .. } => None,
        }
    }

    /// Records that `key` has the address `mac`, from an ARP packet, as `neigh_update` of
    /// Linux. If `create` is false, only an entry that exists changes. Gives the packets that
    /// waited for the address, for the caller to send.
    pub fn update(&mut self, key: Key, mac: MacAddr, now: u64, create: bool) -> Vec<P> {
        let reachable = State::Reachable { mac, confirmed: now };
        match self.entries.get_mut(&key) {
            Some(entry) => {
                entry.updated = now;
                match core::mem::replace(&mut entry.state, reachable) {
                    State::Incomplete { queue, .. } => queue.into(),
                    State::Reachable { .. } => Vec::new(),
                }
            }
            None => {
                if create {
                    self.entries.insert(key, Entry { state: reachable, used: now, updated: now });
                }
                Vec::new()
            }
        }
    }

    /// Runs the timers, as `neigh_timer_handler` of Linux. Gives the keys that need a new
    /// request. An entry with `MAX_PROBES` requests and no reply goes away with its packets,
    /// and an entry that nobody used for `GC_MS` goes away too.
    pub fn tick(&mut self, now: u64) -> Vec<Key> {
        let mut probes = Vec::new();
        let mut dropped = 0;
        self.entries.retain(|key, entry| match &mut entry.state {
            State::Incomplete { queue, probes: n, next } => {
                if now < *next {
                    return true;
                }
                if *n >= MAX_PROBES {
                    dropped += queue.len() as u64;
                    return false;
                }
                *n += 1;
                *next = now + RETRANS_MS;
                probes.push(*key);
                true
            }
            State::Reachable { .. } => now.saturating_sub(entry.used) < GC_MS,
        });
        self.dropped += dropped;
        probes
    }

    /// Tells if the table has work for `tick`: an entry that waits for a reply.
    pub fn pending(&self) -> bool {
        self.entries.values().any(|e| matches!(e.state, State::Incomplete { .. }))
    }

    /// Removes the entries of an interface.
    pub fn flush(&mut self, ifindex: u32) {
        self.entries.retain(|(i, _), _| *i != ifindex);
    }

    /// The entries at the time `now`, by interface and address.
    pub fn entries(&self, now: u64) -> Vec<Info> {
        let ago = |t: u64| now.saturating_sub(t);
        self.entries
            .iter()
            .map(|(&(ifindex, addr), e)| {
                let (mac, state, probes, confirmed) = match &e.state {
                    State::Incomplete { probes, .. } => (None, Nud::Incomplete, *probes, e.updated),
                    State::Reachable { mac, confirmed } => {
                        let state = if ago(*confirmed) < REACHABLE_MS {
                            Nud::Reachable
                        } else {
                            Nud::Stale
                        };
                        (Some(*mac), state, 0, *confirmed)
                    }
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
            })
            .collect()
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

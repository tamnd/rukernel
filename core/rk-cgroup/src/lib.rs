//! The cgroup v2 hierarchy of rukernel, its controllers and pressure stall information.
//!
//! A cgroup is a node of one tree. Each process is in one cgroup, and its children start in the
//! same cgroup. The root has the ID `ROOT`. A cgroup gives a controller to its children when the
//! name of the controller is in its `cgroup.subtree_control`. A cgroup that is not the root and
//! that gives domain controllers to its children cannot have processes: the rule of no internal
//! processes of Linux.
//!
//! A cgroup of the type `threaded` is in the threaded subtree of its thread root, the nearest
//! domain cgroup above it. The threads of one process can be in different cgroups of this
//! subtree, and only the threaded controllers (`cpu`, `cpuset` and `pids`) work in it. The rules
//! are those of the thread mode of Linux.
//!
//! The controllers:
//!
//! - `pids` counts the threads of each subtree and refuses a new thread past `pids.max`.
//! - `memory` counts the anonymous pages and the page cache of each subtree. A charge past
//!   `memory.max` first takes back clean page cache, and then fails. The caller then kills a
//!   process of the cgroup, as the OOM killer of the cgroup in Linux. `memory.min` and
//!   `memory.low` protect the page cache of a cgroup from this reclaim.
//! - `cpu` counts the CPU time of each subtree. `cpu.max` gives a quota of time in each period.
//!   A thread of a cgroup that used its quota waits until the next period. `cpu.weight` changes
//!   the weight of the threads of the cgroup in the fair class.
//! - `cpuset` limits the CPUs of the threads of the cgroup.
//! - `io` counts the I/O of each subtree on each device. `io.max` limits it, and `io.weight`
//!   shares the time of a device between the cgroups that use it.
//!
//! `Hierarchy` has all the state, and it is pure, so the tests on the host examine it. The
//! functions at the end of this file keep one `Hierarchy` for the kernel, with a lock. The file
//! system `cgroup2` in rk-fs-cgroup shows it, and rk-proc, rk-mm and rk-sched call the charge
//! functions.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod io;
pub mod psi;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use rk_abi::Errno;
use rk_frame::sync::{Once, SpinLock};

/// The ID of a cgroup. IDs are not used again, so an old ID never names a new cgroup.
pub type CgId = u32;

/// The ID of the root cgroup.
pub const ROOT: CgId = 1;

/// The size of a page, the unit of the memory controller.
pub const PAGE_SIZE: u64 = 4096;

/// The bit of the cpuset controller.
pub const CPUSET: u8 = 1 << 0;
/// The bit of the cpu controller.
pub const CPU: u8 = 1 << 1;
/// The bit of the memory controller.
pub const MEMORY: u8 = 1 << 2;
/// The bit of the pids controller.
pub const PIDS: u8 = 1 << 3;
/// The bit of the io controller.
pub const IO: u8 = 1 << 4;
/// The bits of all controllers.
pub const ALL: u8 = CPUSET | CPU | IO | MEMORY | PIDS;
/// The bits of the threaded controllers, `cgrp_dfl_threaded_ss_mask` of Linux. Only these
/// controllers work in a threaded subtree. The others are domain controllers.
pub const THREADED: u8 = CPUSET | CPU | PIDS;

/// The controllers in the order of Linux, with their names.
pub const CONTROLLERS: [(u8, &str); 5] =
    [(CPUSET, "cpuset"), (CPU, "cpu"), (IO, "io"), (MEMORY, "memory"), (PIDS, "pids")];

/// The value `max`: no limit.
pub const MAX: u64 = u64::MAX;

/// The default weight of `cpu.weight`.
pub const WEIGHT_DEFAULT: u32 = 100;

/// The default period of `cpu.max` in microseconds.
pub const PERIOD_DEFAULT_US: u64 = 100_000;

/// The unit of the factor of `weight_factor`: the factor 1.
pub const WEIGHT_UNIT: u64 = 1 << 16;

/// The index of each count of `memory.events`.
const EV_LOW: usize = 0;
const EV_HIGH: usize = 1;
const EV_MAX: usize = 2;
const EV_OOM: usize = 3;
const EV_OOM_KILL: usize = 4;
const EV_OOM_GROUP_KILL: usize = 5;
/// The number of counts of `memory.events`.
const NR_EV: usize = 6;

/// The pages that a cgroup over `memory.high` charges before its threads wait the full delay,
/// `MEMCG_CHARGE_BATCH` of Linux.
const HIGH_BATCH: u64 = 64;
/// The longest wait for `memory.high` in nanoseconds, `MEMCG_MAX_HIGH_DELAY_JIFFIES` of Linux.
const HIGH_DELAY_MAX: u64 = 2_000_000_000;
/// The shortest wait for `memory.high` in nanoseconds. A shorter wait does not happen, as in
/// Linux, where the wait must be longer than `HZ / 100`.
const HIGH_DELAY_MIN: u64 = 10_000_000;

/// The weight of each nice value from -20 to 19 in the fair class: `sched_prio_to_weight` of
/// Linux. `cpu.weight.nice` uses it.
const NICE_WEIGHTS: [u64; 40] = [
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100, 4904,
    3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172, 137, 110, 87,
    70, 56, 45, 36, 29, 23, 18, 15,
];

/// The values of the memory controller of one cgroup. The sizes are in bytes.
#[derive(Clone, Debug)]
pub struct Memory {
    /// The bytes that the subtree uses now.
    pub current: u64,
    /// The largest value of `current`.
    pub peak: u64,
    /// `memory.min`.
    pub min: u64,
    /// `memory.low`.
    pub low: u64,
    /// `memory.high`.
    pub high: u64,
    /// `memory.max`.
    pub max: u64,
    /// `memory.swap.max`. rukernel has no swap, so the value has no effect: no page of a
    /// cgroup goes to swap with any value.
    pub swap_max: u64,
    /// The bytes of the page cache that the subtree uses, a part of `current`.
    pub file: u64,
    /// The bytes of the page cache that this cgroup uses, without the subtree.
    pub file_local: u64,
    /// `memory.oom.group`.
    pub oom_group: bool,
    /// The counts of `memory.events`, with the events of the subtree.
    pub events: [u64; NR_EV],
    /// The counts of `memory.events.local`, with the events of this cgroup only.
    pub events_local: [u64; NR_EV],
    /// The bytes that the subtree charged while the use was over `memory.high`. The next
    /// return of a thread to user mode waits for them, and sets the count to 0.
    pub over_high: u64,
}

impl Default for Memory {
    fn default() -> Self {
        Self {
            current: 0,
            peak: 0,
            min: 0,
            low: 0,
            high: MAX,
            max: MAX,
            swap_max: MAX,
            file: 0,
            file_local: 0,
            oom_group: false,
            events: [0; NR_EV],
            events_local: [0; NR_EV],
            over_high: 0,
        }
    }
}

/// The values of the cpu controller of one cgroup. The times are in nanoseconds.
#[derive(Clone, Debug)]
pub struct Cpu {
    /// `cpu.weight`, from 1 to 10000.
    pub weight: u32,
    /// The quota of `cpu.max` in each period, or `None` for `max`.
    pub quota: Option<u64>,
    /// The period of `cpu.max`.
    pub period: u64,
    /// The CPU time of the subtree.
    pub usage: u64,
    /// The periods in which the cgroup ran.
    pub nr_periods: u64,
    /// The times that the cgroup used its quota.
    pub nr_throttled: u64,
    /// The time that the cgroup waited for a new period.
    pub throttled: u64,
    /// The time that is left of the quota in this period. It is below 0 if the cgroup ran past
    /// its quota, and the next period pays for the difference.
    runtime: i64,
    /// The start of this period.
    period_start: u64,
    /// The cgroup ran in this period.
    used: bool,
    /// The cgroup used its quota at this time, and it waits for a new period.
    throttled_since: Option<u64>,
}

impl Default for Cpu {
    fn default() -> Self {
        Self {
            weight: WEIGHT_DEFAULT,
            quota: None,
            period: PERIOD_DEFAULT_US * 1000,
            usage: 0,
            nr_periods: 0,
            nr_throttled: 0,
            throttled: 0,
            runtime: 0,
            period_start: 0,
            used: false,
            throttled_since: None,
        }
    }
}

impl Cpu {
    /// Starts the periods that ended before `now`, and gives the quota of each one, as
    /// `do_sched_cfs_period_timer` of Linux.
    fn refill(&mut self, now: u64) {
        let Some(quota) = self.quota else { return };
        let end = self.period_start + self.period;
        if now < end {
            return;
        }
        let n = (now - self.period_start) / self.period;
        if self.used {
            self.nr_periods += 1;
        }
        self.used = false;
        self.period_start += n * self.period;
        let quota = i64::try_from(quota).unwrap_or(i64::MAX);
        let n = i64::try_from(n).unwrap_or(i64::MAX);
        self.runtime = self.runtime.min(0).saturating_add(quota.saturating_mul(n)).min(quota);
        if self.runtime > 0
            && let Some(since) = self.throttled_since.take()
        {
            self.throttled += end.saturating_sub(since);
        }
    }

    /// Adds `ns` of CPU time at the time `now`.
    fn charge(&mut self, ns: u64, now: u64) {
        self.usage += ns;
        if self.quota.is_none() {
            return;
        }
        self.refill(now);
        self.used = true;
        self.runtime = self.runtime.saturating_sub(i64::try_from(ns).unwrap_or(i64::MAX));
        if self.runtime <= 0 && self.throttled_since.is_none() {
            self.nr_throttled += 1;
            self.throttled_since = Some(now);
        }
    }

    /// The end of the period, if the cgroup used its quota and must wait.
    fn throttled_until(&mut self, now: u64) -> Option<u64> {
        self.quota?;
        self.refill(now);
        (self.runtime <= 0).then_some(self.period_start + self.period)
    }

    /// Sets the quota and the period of `cpu.max`. A new period starts now.
    fn set_max(&mut self, quota: Option<u64>, period: u64, now: u64) {
        self.quota = quota;
        self.period = period;
        self.period_start = now;
        self.runtime = quota.map_or(0, |q| i64::try_from(q).unwrap_or(i64::MAX));
        if let Some(since) = self.throttled_since.take() {
            self.throttled += now.saturating_sub(since);
        }
    }
}

/// The values of the cpuset controller of one cgroup.
#[derive(Clone, Copy, Debug, Default)]
pub struct Cpuset {
    /// `cpuset.cpus`, one bit for each CPU. 0 means the CPUs of the parent.
    pub cpus: u64,
    /// `cpuset.mems`, one bit for each memory node. 0 means the nodes of the parent.
    pub mems: u64,
}

/// A cgroup.
#[derive(Clone, Debug)]
struct Node {
    /// The parent, or 0 for the root.
    parent: CgId,
    /// The domain of the cgroup, `dom_cgrp` of Linux: the cgroup itself, or the thread root of
    /// the threaded subtree for a threaded cgroup.
    dom: CgId,
    /// The children of the type `threaded`.
    nr_threaded_children: u32,
    name: Vec<u8>,
    children: BTreeMap<Vec<u8>, CgId>,
    /// The depth from the root: 0 for the root.
    depth: u32,
    /// The cgroup was removed. It stays while memory is charged to it.
    dead: bool,
    subtree_control: u8,
    max_depth: u32,
    max_descendants: u32,
    /// The cgroups below this one that are not removed.
    nr_descendants: u32,
    /// The processes in this cgroup, without the subtree.
    nr_procs: u32,
    /// The children whose subtree has a task, as `nr_populated_domain_children` and
    /// `nr_populated_threaded_children` of Linux together.
    nr_populated_children: u32,
    /// `cgroup.freeze`: the freeze of this cgroup. The threads of the subtree freeze.
    freeze: bool,
    /// The threads of this cgroup, without the subtree, that wait in the freezer.
    nr_frozen: u64,
    /// The value of `frozen` of `cgroup.events` at the last change.
    ev_frozen: bool,
    /// The count of the changes of `cgroup.events`, for `poll`.
    ev_seq: u64,
    /// The count of the changes of `memory.events` and `pids.events`, for `poll`.
    files_seq: u64,
    /// The threads of the subtree: `pids.current`.
    pids: u64,
    pids_max: u64,
    pids_peak: u64,
    /// `pids.events`: the forks that the limit of this cgroup refused.
    pids_events_max: u64,
    mem: Memory,
    cpu: Cpu,
    cpuset: Cpuset,
    io: io::Io,
    psi: psi::Psi,
}

impl Node {
    fn new(parent: CgId, dom: CgId, name: &[u8], depth: u32, now: u64) -> Self {
        Self {
            parent,
            dom,
            nr_threaded_children: 0,
            name: name.to_vec(),
            children: BTreeMap::new(),
            depth,
            dead: false,
            subtree_control: 0,
            max_depth: u32::MAX,
            max_descendants: u32::MAX,
            nr_descendants: 0,
            nr_procs: 0,
            nr_populated_children: 0,
            freeze: false,
            nr_frozen: 0,
            ev_frozen: false,
            ev_seq: 1,
            files_seq: 1,
            pids: 0,
            pids_max: MAX,
            pids_peak: 0,
            pids_events_max: 0,
            mem: Memory::default(),
            cpu: Cpu { period_start: now, ..Cpu::default() },
            cpuset: Cpuset::default(),
            io: io::Io::default(),
            psi: psi::Psi::new(now, parent == 0),
        }
    }
}

/// A file of a cgroup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileInfo {
    /// The name.
    pub name: &'static str,
    /// The controller of the file, or 0 for a file of the core.
    pub ctrl: u8,
    /// The root has the file.
    pub root: bool,
    /// A cgroup that is not the root has the file.
    pub child: bool,
    /// The permission bits.
    pub perm: u32,
}

const fn file(name: &'static str, ctrl: u8, root: bool, child: bool, perm: u32) -> FileInfo {
    FileInfo { name, ctrl, root, child, perm }
}

/// The files of a cgroup, as Linux names them.
pub const FILES: [FileInfo; 50] = [
    file("cgroup.controllers", 0, true, true, 0o444),
    file("cgroup.events", 0, false, true, 0o444),
    file("cgroup.freeze", 0, false, true, 0o644),
    file("cgroup.kill", 0, false, true, 0o200),
    file("cgroup.max.depth", 0, true, true, 0o644),
    file("cgroup.max.descendants", 0, true, true, 0o644),
    file("cgroup.procs", 0, true, true, 0o644),
    file("cgroup.stat", 0, true, true, 0o444),
    file("cgroup.subtree_control", 0, true, true, 0o644),
    file("cgroup.threads", 0, true, true, 0o644),
    file("cgroup.type", 0, false, true, 0o644),
    file("cpu.pressure", 0, true, true, 0o644),
    file("cpu.stat", 0, true, true, 0o444),
    file("io.pressure", 0, true, true, 0o644),
    file("memory.pressure", 0, true, true, 0o644),
    file("cpu.max", CPU, false, true, 0o644),
    file("cpu.max.burst", CPU, false, true, 0o644),
    file("cpu.weight", CPU, false, true, 0o644),
    file("cpu.weight.nice", CPU, false, true, 0o644),
    file("cpuset.cpus", CPUSET, false, true, 0o644),
    file("cpuset.cpus.effective", CPUSET, true, true, 0o444),
    file("cpuset.cpus.exclusive", CPUSET, false, true, 0o644),
    file("cpuset.cpus.partition", CPUSET, false, true, 0o644),
    file("cpuset.mems", CPUSET, false, true, 0o644),
    file("cpuset.mems.effective", CPUSET, true, true, 0o444),
    file("io.max", IO, false, true, 0o644),
    file("io.stat", IO, true, true, 0o444),
    file("io.weight", IO, false, true, 0o644),
    file("memory.current", MEMORY, false, true, 0o444),
    file("memory.events", MEMORY, false, true, 0o444),
    file("memory.events.local", MEMORY, false, true, 0o444),
    file("memory.high", MEMORY, false, true, 0o644),
    file("memory.low", MEMORY, false, true, 0o644),
    file("memory.max", MEMORY, false, true, 0o644),
    file("memory.min", MEMORY, false, true, 0o644),
    file("memory.numa_stat", MEMORY, true, true, 0o444),
    file("memory.oom.group", MEMORY, false, true, 0o644),
    file("memory.peak", MEMORY, false, true, 0o644),
    file("memory.reclaim", MEMORY, true, true, 0o200),
    file("memory.stat", MEMORY, true, true, 0o444),
    file("memory.swap.current", MEMORY, false, true, 0o444),
    file("memory.swap.events", MEMORY, false, true, 0o444),
    file("memory.swap.high", MEMORY, false, true, 0o644),
    file("memory.swap.max", MEMORY, false, true, 0o644),
    file("memory.swap.peak", MEMORY, false, true, 0o644),
    file("memory.zswap.current", MEMORY, false, true, 0o444),
    file("memory.zswap.max", MEMORY, false, true, 0o644),
    file("pids.current", PIDS, false, true, 0o444),
    file("pids.events", PIDS, false, true, 0o444),
    file("pids.max", PIDS, false, true, 0o644),
];

/// The files of the pids controller that come after the others: `pids.peak`.
const PIDS_PEAK: FileInfo = file("pids.peak", PIDS, false, true, 0o444);

/// What the caller must do after a write of a file, because the hierarchy cannot do it alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Nothing.
    None,
    /// `cgroup.kill`: send `SIGKILL` to each process of the subtree.
    Kill,
    /// `cgroup.freeze` changed: wake the threads of the subtree that wait while it is frozen.
    Freeze,
    /// `memory.max` is below `memory.current`: kill processes of the subtree until the use is
    /// below the limit.
    MemoryOver,
    /// `cpuset.cpus` changed: set the CPUs of the threads of the subtree again.
    Cpuset,
    /// `memory.high`, `io.max` or `cpu.max` changed: wake the threads that wait for these
    /// limits, so that they wait again with the new limits.
    Throttle,
}

/// The names of the controllers in `mask`, with a space between two names and a new line at the
/// end, as `cgroup.controllers` shows them.
pub fn controller_names(mask: u8) -> String {
    let names: Vec<&str> =
        CONTROLLERS.iter().filter(|(bit, _)| mask & bit != 0).map(|&(_, n)| n).collect();
    let mut out = names.join(" ");
    out.push('\n');
    out
}

/// The text of the value of a file without the new line and the zero bytes at the end.
fn text(data: &[u8]) -> Result<&str, Errno> {
    let s = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
    Ok(s.trim_matches(|c: char| c.is_ascii_whitespace() || c == '\0'))
}

/// Parses `max` or a number.
pub fn parse_max(data: &[u8]) -> Result<u64, Errno> {
    match text(data)? {
        "max" => Ok(MAX),
        s => s.parse().map_err(|_| Errno::EINVAL),
    }
}

/// Parses `max` or a size in bytes, with the suffix `K`, `M`, `G` or `T` as `memparse` of Linux.
/// The size is rounded down to a page.
pub fn parse_bytes(data: &[u8]) -> Result<u64, Errno> {
    let s = text(data)?;
    if s == "max" {
        return Ok(MAX);
    }
    let (num, shift) = match s.as_bytes().last() {
        Some(b'k' | b'K') => (&s[..s.len() - 1], 10),
        Some(b'm' | b'M') => (&s[..s.len() - 1], 20),
        Some(b'g' | b'G') => (&s[..s.len() - 1], 30),
        Some(b't' | b'T') => (&s[..s.len() - 1], 40),
        _ => (s, 0),
    };
    let n: u64 = num.parse().map_err(|_| Errno::EINVAL)?;
    let bytes = n.checked_shl(shift).filter(|v| v >> shift == n).unwrap_or(MAX);
    Ok(if bytes == MAX { MAX } else { bytes / PAGE_SIZE * PAGE_SIZE })
}

/// Formats `max` or a number, with a new line.
fn show_max(v: u64) -> String {
    if v == MAX { String::from("max\n") } else { format!("{v}\n") }
}

/// Parses a list of CPUs or memory nodes, as `0-3,5`, to one bit for each one. An empty list is
/// 0.
///
/// # Errors
///
/// Gives `EINVAL` for a list that is not valid, or a number past 63.
pub fn parse_list(data: &[u8]) -> Result<u64, Errno> {
    let s = text(data)?;
    let mut mask = 0u64;
    for part in s.split(',').filter(|p| !p.is_empty()) {
        let (a, b) = match part.split_once('-') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => (part.trim(), part.trim()),
        };
        let a: u32 = a.parse().map_err(|_| Errno::EINVAL)?;
        let b: u32 = b.parse().map_err(|_| Errno::EINVAL)?;
        if a > b || b > 63 {
            return Err(Errno::EINVAL);
        }
        for i in a..=b {
            mask |= 1 << i;
        }
    }
    Ok(mask)
}

/// Formats one bit for each CPU or memory node as a list, as `0-3,5`, with a new line.
pub fn show_list(mask: u64) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut i = 0;
    while i < 64 {
        if mask & (1 << i) == 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i + 1 < 64 && mask & (1 << (i + 1)) != 0 {
            i += 1;
        }
        parts.push(if start == i { format!("{i}") } else { format!("{start}-{i}") });
        i += 1;
    }
    let mut out = parts.join(",");
    out.push('\n');
    out
}

/// All cgroups, with the cgroup namespaces.
pub struct Hierarchy {
    nodes: BTreeMap<CgId, Node>,
    next: CgId,
    /// The CPUs of the machine, for the root cpuset.
    online_cpus: u64,
    /// The root cgroup of each cgroup namespace. The namespace 0 is the first one, with the
    /// root `ROOT`.
    namespaces: BTreeMap<u32, CgId>,
    next_ns: u32,
    /// A change can change `cgroup.events`, and `refresh_events` must look again.
    dirty: bool,
    /// A file that `poll` watches changed since the last `take_notify`.
    notify: bool,
    /// The cgroups with `cgroup.freeze` 1.
    nr_freeze: u32,
    /// A cgroup can have pages that it charged over `memory.high`, for `high_delay`.
    any_over_high: bool,
    /// A cgroup had a quota in `cpu.max`. The value stays true after the quota goes away, so
    /// it only tells that `throttled_until` must look.
    any_quota: bool,
    /// The share of each device for `io.weight`.
    io_shares: BTreeMap<u64, io::Share>,
}

impl Hierarchy {
    /// Makes a hierarchy with the root only, at the time `now` in nanoseconds. `online_cpus` has
    /// one bit for each CPU of the machine.
    pub fn new(now: u64, online_cpus: u64) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(ROOT, Node::new(0, ROOT, b"", 0, now));
        let mut namespaces = BTreeMap::new();
        namespaces.insert(0, ROOT);
        Self {
            nodes,
            next: ROOT + 1,
            online_cpus,
            namespaces,
            next_ns: 1,
            dirty: false,
            notify: false,
            nr_freeze: 0,
            any_over_high: false,
            any_quota: false,
            io_shares: BTreeMap::new(),
        }
    }

    /// Sets the CPUs of the machine, when the CPUs start.
    pub fn set_online_cpus(&mut self, mask: u64) {
        self.online_cpus = mask;
    }

    fn node(&self, id: CgId) -> Result<&Node, Errno> {
        self.nodes.get(&id).ok_or(Errno::ENOENT)
    }

    fn node_mut(&mut self, id: CgId) -> Result<&mut Node, Errno> {
        self.nodes.get_mut(&id).ok_or(Errno::ENOENT)
    }

    /// Tells if the cgroup `id` exists and is not removed.
    pub fn exists(&self, id: CgId) -> bool {
        self.nodes.get(&id).is_some_and(|n| !n.dead)
    }

    /// The parent of `id`, or `None` for the root and for an ID that does not exist.
    pub fn parent(&self, id: CgId) -> Option<CgId> {
        self.nodes.get(&id).map(|n| n.parent).filter(|&p| p != 0)
    }

    /// The IDs from `id` up to the root, with both.
    fn path_ids(&self, id: CgId) -> Vec<CgId> {
        let mut out = Vec::new();
        let mut at = id;
        while let Some(n) = self.nodes.get(&at) {
            out.push(at);
            at = n.parent;
        }
        out
    }

    /// The children of `id`, by name.
    pub fn children(&self, id: CgId) -> Vec<(Vec<u8>, CgId)> {
        self.nodes
            .get(&id)
            .map(|n| n.children.iter().map(|(k, &v)| (k.clone(), v)).collect())
            .unwrap_or_default()
    }

    /// The child `name` of `id`.
    pub fn lookup(&self, id: CgId, name: &[u8]) -> Option<CgId> {
        self.nodes.get(&id)?.children.get(name).copied()
    }

    /// The depth of `id`: 0 for the root.
    pub fn depth(&self, id: CgId) -> u32 {
        self.nodes.get(&id).map_or(0, |n| n.depth)
    }

    /// Tells if `id` is `ancestor` or a cgroup below it.
    pub fn is_descendant(&self, id: CgId, ancestor: CgId) -> bool {
        self.path_ids(id).contains(&ancestor)
    }

    /// The path of `id` from the root, as `/a/b`. The root is `/`.
    pub fn path(&self, id: CgId) -> Vec<u8> {
        self.path_from(id, ROOT)
    }

    /// The path of `id` as a process in the namespace with the root `root` sees it, as
    /// `/proc/PID/cgroup` of Linux shows it. A cgroup outside the namespace has `/..` for each
    /// step up from `root`.
    pub fn path_from(&self, id: CgId, root: CgId) -> Vec<u8> {
        let ids = self.path_ids(id);
        let roots = self.path_ids(root);
        // The deepest common ancestor.
        let common = ids.iter().copied().find(|i| roots.contains(i)).unwrap_or(ROOT);
        let mut out = Vec::new();
        for &r in &roots {
            if r == common {
                break;
            }
            out.extend_from_slice(b"/..");
        }
        for &i in ids.iter().take_while(|&&i| i != common).collect::<Vec<_>>().iter().rev() {
            out.push(b'/');
            out.extend_from_slice(&self.nodes[i].name);
        }
        if out.is_empty() {
            out.push(b'/');
        }
        out
    }

    /// The controllers that `id` can use: all for the root, and the `cgroup.subtree_control`
    /// of the parent for another cgroup. A threaded cgroup gets only the threaded controllers,
    /// as `cgroup_control` of Linux.
    pub fn controllers(&self, id: CgId) -> u8 {
        match self.parent(id) {
            None => ALL,
            Some(p) => {
                let mask = self.nodes.get(&p).map_or(0, |n| n.subtree_control);
                if self.is_threaded(id) { mask & THREADED } else { mask }
            }
        }
    }

    /// Tells if the controller `ctrl` works in `id`: `id` is not the root, and its parent gives
    /// the controller to it.
    pub fn on(&self, id: CgId, ctrl: u8) -> bool {
        self.parent(id).is_some() && self.controllers(id) & ctrl != 0
    }

    /// The `cgroup.subtree_control` of `id`.
    pub fn subtree_control(&self, id: CgId) -> u8 {
        self.nodes.get(&id).map_or(0, |n| n.subtree_control)
    }

    /// The files of `id`.
    pub fn files(&self, id: CgId) -> Vec<FileInfo> {
        let root = self.parent(id).is_none();
        let avail = self.controllers(id);
        FILES
            .iter()
            .chain(core::iter::once(&PIDS_PEAK))
            .filter(|f| if root { f.root } else { f.child })
            .filter(|f| f.ctrl == 0 || root || avail & f.ctrl != 0)
            // The root has the files of a controller only if the controller exists.
            .copied()
            .collect()
    }

    /// The file `name` of `id`.
    pub fn file(&self, id: CgId, name: &[u8]) -> Option<FileInfo> {
        self.files(id).into_iter().find(|f| f.name.as_bytes() == name)
    }

    /// Makes the cgroup `name` in `parent`.
    ///
    /// # Errors
    ///
    /// `ENOENT` if `parent` does not exist, `EEXIST` if the name is in use, `EINVAL` for a name
    /// that is not valid, and `EAGAIN` if `cgroup.max.depth` or `cgroup.max.descendants` of a
    /// cgroup above does not allow the new cgroup.
    pub fn mkdir(&mut self, parent: CgId, name: &[u8], now: u64) -> Result<CgId, Errno> {
        if name.is_empty() || name.contains(&b'/') || name == b"." || name == b".." {
            return Err(Errno::EINVAL);
        }
        let p = self.node(parent)?;
        if p.dead {
            return Err(Errno::ENOENT);
        }
        if p.children.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        let depth = p.depth + 1;
        for a in self.path_ids(parent) {
            let n = &self.nodes[&a];
            if depth - n.depth > n.max_depth || n.nr_descendants >= n.max_descendants {
                return Err(Errno::EAGAIN);
            }
        }
        let id = self.next;
        self.next += 1;
        // A new cgroup is a domain, also below a threaded cgroup, where it is not valid.
        let mut node = Node::new(parent, id, name, depth, now);
        node.cpu.period_start = now;
        self.nodes.insert(id, node);
        for a in self.path_ids(parent) {
            if let Some(n) = self.nodes.get_mut(&a) {
                n.nr_descendants += 1;
            }
        }
        self.node_mut(parent)?.children.insert(name.to_vec(), id);
        self.empty_changed();
        Ok(id)
    }

    /// Removes the cgroup `name` of `parent`, and gives its ID.
    ///
    /// # Errors
    ///
    /// `ENOENT` if it does not exist, and `EBUSY` if it has children or processes.
    pub fn rmdir(&mut self, parent: CgId, name: &[u8]) -> Result<CgId, Errno> {
        let id = self.lookup(parent, name).ok_or(Errno::ENOENT)?;
        let n = self.node(id)?;
        if !n.children.is_empty() || n.nr_procs > 0 || n.pids > 0 {
            return Err(Errno::EBUSY);
        }
        let keep = n.mem.current > 0;
        if n.freeze {
            self.nr_freeze -= 1;
        }
        let threaded = self.is_threaded(id);
        let p = self.node_mut(parent)?;
        p.children.remove(name);
        if threaded {
            p.nr_threaded_children -= 1;
        }
        for a in self.path_ids(parent) {
            if let Some(n) = self.nodes.get_mut(&a) {
                n.nr_descendants = n.nr_descendants.saturating_sub(1);
            }
        }
        if keep {
            let n = self.node_mut(id)?;
            n.dead = true;
            n.freeze = false;
        } else {
            self.nodes.remove(&id);
        }
        self.empty_changed();
        Ok(id)
    }

    /// Tells if the subtree of `id` has a process or a thread, the `populated` value of
    /// `cgroup.events`.
    pub fn populated(&self, id: CgId) -> bool {
        self.nodes.get(&id).is_some_and(|n| n.nr_populated_children > 0) || self.has_tasks(id)
    }

    /// The threads of `id` without the threads of its subtree.
    fn own_threads(&self, id: CgId) -> u64 {
        let Some(n) = self.nodes.get(&id) else { return 0 };
        let below: u64 = n.children.values().map(|&c| self.pids(c)).sum();
        n.pids.saturating_sub(below)
    }

    /// Tells if `id` itself has a process or a thread, `cgroup_has_tasks` of Linux.
    fn has_tasks(&self, id: CgId) -> bool {
        self.nodes.get(&id).is_some_and(|n| n.nr_procs > 0) || self.own_threads(id) > 0
    }

    /// The domain of `id`: `id` itself, or the thread root for a threaded cgroup.
    pub fn dom(&self, id: CgId) -> CgId {
        self.nodes.get(&id).map_or(id, |n| n.dom)
    }

    /// Tells if `id` has the type `threaded`, `cgroup_is_threaded` of Linux.
    pub fn is_threaded(&self, id: CgId) -> bool {
        self.dom(id) != id
    }

    /// Tells if `id` can have processes and give domain controllers to its children at the same
    /// time, `cgroup_is_mixable` of Linux: only the root can.
    fn is_mixable(&self, id: CgId) -> bool {
        self.parent(id).is_none()
    }

    /// Tells if `id` can be the root of a threaded subtree, `cgroup_can_be_thread_root` of Linux.
    fn can_be_thread_root(&self, id: CgId) -> bool {
        if self.is_mixable(id) {
            return true;
        }
        let Some(n) = self.nodes.get(&id) else { return false };
        if self.is_threaded(id) || n.subtree_control & !THREADED != 0 {
            return false;
        }
        // A populated domain child, `nr_populated_domain_children` of Linux.
        !n.children.values().any(|&c| !self.is_threaded(c) && self.populated(c))
    }

    /// Tells if `id` is the root of a threaded subtree, `cgroup_is_thread_root` of Linux.
    fn is_thread_root(&self, id: CgId) -> bool {
        let Some(n) = self.nodes.get(&id) else { return false };
        if self.is_threaded(id) {
            return false;
        }
        n.nr_threaded_children > 0 || (self.has_tasks(id) && n.subtree_control & THREADED != 0)
    }

    /// Tells if `id` is a valid domain, `cgroup_is_valid_domain` of Linux: it is not threaded,
    /// and no cgroup above it is threaded or a thread root that is not the root.
    fn is_valid_domain(&self, id: CgId) -> bool {
        if self.is_threaded(id) {
            return false;
        }
        let mut at = id;
        while let Some(p) = self.parent(at) {
            if (!self.is_mixable(p) && self.is_thread_root(p)) || self.is_threaded(p) {
                return false;
            }
            at = p;
        }
        true
    }

    /// The text of `cgroup.type` of `id`, as `cgroup_type_show` of Linux.
    fn type_name(&self, id: CgId) -> &'static str {
        if self.is_threaded(id) {
            "threaded"
        } else if !self.is_valid_domain(id) {
            "domain invalid"
        } else if self.is_thread_root(id) {
            "domain threaded"
        } else {
            "domain"
        }
    }

    /// Makes `id` a threaded cgroup in the threaded subtree of its parent, for a write of
    /// `threaded` to `cgroup.type`, as `cgroup_enable_threaded` of Linux.
    ///
    /// # Errors
    ///
    /// `EOPNOTSUPP` if `id` has a process or a thread in its subtree, gives domain controllers
    /// to its children, or its parent cannot be in a threaded subtree.
    fn enable_threaded(&mut self, id: CgId) -> Result<(), Errno> {
        if self.is_threaded(id) {
            return Ok(());
        }
        let parent = self.parent(id).ok_or(Errno::ENOENT)?;
        if self.populated(id) || self.subtree_control(id) & !THREADED != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let dom = self.dom(parent);
        if !self.is_valid_domain(dom) || !self.can_be_thread_root(dom) {
            return Err(Errno::EOPNOTSUPP);
        }
        // The threaded cgroups below `id` join the subtree of `dom` too. A child that is not
        // threaded stays a domain, and it is not valid.
        let mut stack = alloc::vec![id];
        while let Some(at) = stack.pop() {
            if at != id && !self.is_threaded(at) {
                continue;
            }
            let n = self.node_mut(at)?;
            n.dom = dom;
            stack.extend(n.children.values().copied());
        }
        self.node_mut(parent)?.nr_threaded_children += 1;
        self.dirty = true;
        Ok(())
    }

    /// Tells if `id` or a cgroup above it has `cgroup.freeze` 1, so the threads of `id` must
    /// freeze, as `CGRP_FREEZE` of Linux.
    pub fn frozen(&self, id: CgId) -> bool {
        self.nr_freeze > 0 && self.path_ids(id).iter().any(|i| self.nodes[i].freeze)
    }

    /// Tells if `id` is frozen: it must freeze, and each thread of its subtree waits in the
    /// freezer. This is the `frozen` value of `cgroup.events`, as `CGRP_FROZEN` of Linux.
    pub fn events_frozen(&mut self, id: CgId) -> bool {
        self.refresh_events();
        self.nodes.get(&id).is_some_and(|n| n.ev_frozen)
    }

    /// Tells if a cgroup has `cgroup.freeze` 1.
    pub fn any_freeze(&self) -> bool {
        self.nr_freeze > 0
    }

    /// Counts a thread of `id` that starts (`on` true) or stops waiting in the freezer.
    pub fn thread_frozen(&mut self, id: CgId, on: bool) {
        if let Some(n) = self.nodes.get_mut(&id) {
            n.nr_frozen = if on { n.nr_frozen + 1 } else { n.nr_frozen.saturating_sub(1) };
            self.dirty = true;
        }
    }

    /// Computes `frozen` of `cgroup.events` again for each cgroup after a change, as
    /// `cgroup_update_frozen` of Linux. A cgroup whose value changes counts a change for `poll`.
    /// `populated` changes at once in `update_populated`.
    pub fn refresh_events(&mut self) {
        if !self.dirty {
            return;
        }
        self.dirty = false;
        // A child has a larger ID than its parent, so the order of the IDs goes down the tree,
        // and the reverse order goes up.
        let ids: Vec<CgId> =
            self.nodes.iter().filter(|(_, n)| !n.dead).map(|(&id, _)| id).collect();
        let mut freezing: BTreeMap<CgId, bool> = BTreeMap::new();
        for &id in &ids {
            let n = &self.nodes[&id];
            let up = freezing.get(&n.parent).copied().unwrap_or(false);
            freezing.insert(id, n.freeze || up);
        }
        // For each cgroup: each child is frozen, and the threads of the children.
        let mut below: BTreeMap<CgId, (bool, u64)> = BTreeMap::new();
        for &id in ids.iter().rev() {
            let (children_frozen, child_pids) = below.remove(&id).unwrap_or((true, 0));
            let n = &self.nodes[&id];
            let own = n.pids.saturating_sub(child_pids);
            let frozen = freezing[&id] && n.nr_frozen >= own && children_frozen;
            let (parent, pids) = (n.parent, n.pids);
            let p = below.entry(parent).or_insert((true, 0));
            p.0 &= frozen;
            p.1 += pids;
            let Some(n) = self.nodes.get_mut(&id) else { continue };
            if n.ev_frozen != frozen {
                n.ev_frozen = frozen;
                n.ev_seq += 1;
                self.notify = true;
            }
        }
    }

    /// Tells if a file that `poll` watches changed since the last call.
    pub fn take_notify(&mut self) -> bool {
        core::mem::take(&mut self.notify)
    }

    /// The count of the changes of the file `name` of `id`, for `poll`, or `None` for a file
    /// without events. `cgroup.events`, `memory.events`, `memory.events.local` and
    /// `pids.events` have events, as the files of Linux that `cgroup_file_notify` tells.
    pub fn event_seq(&mut self, id: CgId, name: &str) -> Option<u64> {
        self.refresh_events();
        let n = self.nodes.get(&id)?;
        match name {
            "cgroup.events" => Some(n.ev_seq),
            "memory.events" | "memory.events.local" | "pids.events" => Some(n.files_seq),
            _ => None,
        }
    }

    /// The removed cgroups below `id` that still have charges.
    fn nr_dying(&self, id: CgId) -> usize {
        self.nodes.iter().filter(|&(&i, n)| n.dead && i != id && self.is_descendant(i, id)).count()
    }

    /// Checks that a process or a thread can move to `id`, as `cgroup_migrate_vet_dst` of
    /// Linux.
    ///
    /// # Errors
    ///
    /// `ENOENT` if `id` does not exist, `EOPNOTSUPP` if the domain of `id` is not valid, and
    /// `EBUSY` if `id` is not the root and gives controllers to its children: the rule of no
    /// internal processes. A cgroup that can be a thread root can have processes when it gives
    /// only threaded controllers to its children.
    pub fn can_attach(&self, id: CgId) -> Result<(), Errno> {
        let n = self.node(id)?;
        if n.dead {
            return Err(Errno::ENOENT);
        }
        if !self.is_valid_domain(self.dom(id)) {
            return Err(Errno::EOPNOTSUPP);
        }
        if self.is_mixable(id) || self.can_be_thread_root(id) || self.is_threaded(id) {
            return Ok(());
        }
        if n.subtree_control != 0 {
            return Err(Errno::EBUSY);
        }
        Ok(())
    }

    /// Checks that a thread can move alone from `from` to `to`, for a write of
    /// `cgroup.threads`, as `cgroup_attach_permissions` of Linux.
    ///
    /// # Errors
    ///
    /// The errors of `can_attach`, and `EOPNOTSUPP` if the two cgroups are not in one domain:
    /// a thread can leave the cgroup of its process only in a threaded subtree.
    pub fn can_attach_thread(&self, from: CgId, to: CgId) -> Result<(), Errno> {
        self.can_attach(to)?;
        if self.dom(from) != self.dom(to) {
            return Err(Errno::EOPNOTSUPP);
        }
        Ok(())
    }

    /// Adds a new process to `id`. The caller charged its thread with `charge_pids`.
    pub fn add_process(&mut self, id: CgId) {
        let had = self.has_tasks(id);
        if let Some(n) = self.nodes.get_mut(&id) {
            n.nr_procs += 1;
            self.tasks_changed(id, had);
        }
    }

    /// Removes a process that ended from `id`.
    pub fn remove_process(&mut self, id: CgId) {
        let had = self.has_tasks(id);
        if let Some(n) = self.nodes.get_mut(&id) {
            n.nr_procs = n.nr_procs.saturating_sub(1);
            self.tasks_changed(id, had);
        }
    }

    /// Moves a process with `threads` threads from `from` to `to`. The charges of memory stay
    /// with `from`, as in Linux.
    ///
    /// # Errors
    ///
    /// The errors of `can_attach`.
    pub fn migrate(&mut self, from: CgId, to: CgId, threads: u64) -> Result<(), Errno> {
        let threads: Vec<CgId> = (0..threads).map(|_| from).collect();
        self.migrate_process(from, to, &threads)
    }

    /// Moves a process from `from`, the cgroup of its leader thread, to `to`. `threads` has the
    /// cgroup of each thread of the process: in a threaded subtree, the threads can be in
    /// different cgroups. All the threads go to `to`.
    ///
    /// # Errors
    ///
    /// The errors of `can_attach`.
    pub fn migrate_process(&mut self, from: CgId, to: CgId, threads: &[CgId]) -> Result<(), Errno> {
        self.can_attach(to)?;
        for &t in threads {
            self.move_thread(t, to);
        }
        if from != to {
            self.remove_process(from);
            self.add_process(to);
        }
        Ok(())
    }

    /// Moves one thread from `from` to `to`, without the checks. The caller moves the process
    /// with `move_leader` if the thread is its leader.
    pub fn move_thread(&mut self, from: CgId, to: CgId) {
        if from != to {
            self.uncharge_pids(from, 1);
            self.force_charge_pids(to, 1);
        }
    }

    /// Moves the count of a process from `from` to `to`, after a move of its leader thread.
    pub fn move_leader(&mut self, from: CgId, to: CgId) {
        if from != to {
            self.remove_process(from);
            self.add_process(to);
        }
    }

    /// Adds `n` threads to `id` and the cgroups above it, past the limits, as a move does.
    fn force_charge_pids(&mut self, id: CgId, n: u64) {
        let had = self.has_tasks(id);
        for a in self.path_ids(id) {
            if let Some(node) = self.nodes.get_mut(&a) {
                node.pids += n;
                node.pids_peak = node.pids_peak.max(node.pids);
            }
        }
        self.tasks_changed(id, had);
    }

    /// Adds `n` new threads to `id` and the cgroups above it, as `pids_try_charge` of Linux.
    ///
    /// # Errors
    ///
    /// `EAGAIN` if the threads pass the `pids.max` of a cgroup of the path. That cgroup counts
    /// the event in `pids.events`.
    pub fn charge_pids(&mut self, id: CgId, n: u64) -> Result<(), Errno> {
        let path = self.path_ids(id);
        for &a in &path {
            let on = self.on(a, PIDS);
            let Some(node) = self.nodes.get_mut(&a) else { continue };
            if on && node.pids_max != MAX && node.pids + n > node.pids_max {
                node.pids_events_max += 1;
                node.files_seq += 1;
                self.notify = true;
                return Err(Errno::EAGAIN);
            }
        }
        self.force_charge_pids(id, n);
        Ok(())
    }

    /// Removes `n` threads that ended from `id` and the cgroups above it.
    pub fn uncharge_pids(&mut self, id: CgId, n: u64) {
        let had = self.has_tasks(id);
        for a in self.path_ids(id) {
            if let Some(node) = self.nodes.get_mut(&a) {
                node.pids = node.pids.saturating_sub(n);
            }
        }
        self.tasks_changed(id, had);
    }

    /// Updates `cgroup.events` after a change of the tasks of `id`. When `id` gets its first
    /// task or loses its last one, `update_populated` changes `populated`. The cgroups above
    /// `id` keep their own tasks, as their counts and the counts of their children change
    /// together. `frozen` can change only when a cgroup is frozen, and only then
    /// `refresh_events` must go over each cgroup.
    fn tasks_changed(&mut self, id: CgId, had_tasks: bool) {
        let has = self.has_tasks(id);
        if has != had_tasks {
            self.update_populated(id, had_tasks);
        }
        if self.nr_freeze > 0 {
            self.dirty = true;
        }
    }

    /// Changes `populated` of `id` and of the cgroups above it after `id` got its first task
    /// or lost its last one, as `cgroup_update_populated` in kernel/cgroup/cgroup.c of Linux.
    /// `had_tasks` tells if `id` had tasks before. The walk goes up while the value of a cgroup
    /// changes, so an exit does not look at the other cgroups.
    fn update_populated(&mut self, id: CgId, had_tasks: bool) {
        let mut at = id;
        let mut was = had_tasks || self.nodes.get(&id).is_some_and(|n| n.nr_populated_children > 0);
        loop {
            let now = self.populated(at);
            if now == was {
                return;
            }
            let Some(n) = self.nodes.get_mut(&at) else { return };
            n.ev_seq += 1;
            self.notify = true;
            let parent = n.parent;
            if parent == 0 {
                return;
            }
            was = self.populated(parent);
            let Some(p) = self.nodes.get_mut(&parent) else { return };
            if now {
                p.nr_populated_children += 1;
            } else {
                p.nr_populated_children = p.nr_populated_children.saturating_sub(1);
            }
            at = parent;
        }
    }

    /// Marks `cgroup.events` for `refresh_events` after `mkdir` or `rmdir`. The cgroup has no
    /// task, so `populated` does not change. Without a frozen cgroup, `frozen` is 0 in each
    /// cgroup, and a new cgroup starts with the right values.
    fn empty_changed(&mut self) {
        if self.nr_freeze > 0 {
            self.dirty = true;
        }
    }

    /// The threads of the subtree of `id`: `pids.current`.
    pub fn pids(&self, id: CgId) -> u64 {
        self.nodes.get(&id).map_or(0, |n| n.pids)
    }

    /// Charges `bytes` of memory to `id` and the cgroups above it.
    ///
    /// # Errors
    ///
    /// Gives the cgroup whose `memory.max` the charge passes. That cgroup and the cgroups above
    /// it count a `max` event, and the caller must free memory or kill a process.
    pub fn charge_memory(&mut self, id: CgId, bytes: u64) -> Result<(), CgId> {
        let path = self.path_ids(id);
        for &a in &path {
            let on = self.on(a, MEMORY);
            let n = &self.nodes[&a];
            if on && n.mem.max != MAX && n.mem.current + bytes > n.mem.max {
                self.memory_event(a, EV_MAX);
                return Err(a);
            }
        }
        for &a in &path {
            let on = self.on(a, MEMORY);
            let Some(n) = self.nodes.get_mut(&a) else { continue };
            n.mem.current += bytes;
            n.mem.peak = n.mem.peak.max(n.mem.current);
            let high = on && n.mem.high != MAX && n.mem.current > n.mem.high;
            if high {
                n.mem.over_high += bytes;
                self.any_over_high = true;
                self.memory_event(a, EV_HIGH);
            }
        }
        Ok(())
    }

    /// Removes a charge of `bytes` from `id` and the cgroups above it. A removed cgroup goes
    /// away when it has no charge left.
    pub fn uncharge_memory(&mut self, id: CgId, bytes: u64) {
        self.uncharge(id, bytes, false);
    }

    /// Charges `bytes` of the page cache to `id` and the cgroups above it. The charge does not
    /// fail: the page is in the cache already. Gives the highest cgroup whose `memory.max` the
    /// use now passes, and the caller then takes pages back from it with `reclaim_plan`.
    pub fn charge_file(&mut self, id: CgId, bytes: u64) -> Option<CgId> {
        let mut over = None;
        if let Some(n) = self.nodes.get_mut(&id) {
            n.mem.file_local += bytes;
        }
        for a in self.path_ids(id) {
            let on = self.on(a, MEMORY);
            let Some(n) = self.nodes.get_mut(&a) else { continue };
            n.mem.current += bytes;
            n.mem.file += bytes;
            n.mem.peak = n.mem.peak.max(n.mem.current);
            if on && n.mem.max != MAX && n.mem.current > n.mem.max {
                over = Some(a);
            }
            if on && n.mem.high != MAX && n.mem.current > n.mem.high {
                n.mem.over_high += bytes;
                self.any_over_high = true;
                self.memory_event(a, EV_HIGH);
            }
        }
        over
    }

    /// Removes a charge of `bytes` of the page cache from `id` and the cgroups above it.
    pub fn uncharge_file(&mut self, id: CgId, bytes: u64) {
        self.uncharge(id, bytes, true);
    }

    /// Removes a charge of `bytes`, of the page cache if `file`, from `id` and the cgroups
    /// above it. A removed cgroup goes away when it has no charge left.
    fn uncharge(&mut self, id: CgId, bytes: u64, file: bool) {
        if file && let Some(n) = self.nodes.get_mut(&id) {
            n.mem.file_local = n.mem.file_local.saturating_sub(bytes);
        }
        for a in self.path_ids(id) {
            let Some(n) = self.nodes.get_mut(&a) else { continue };
            n.mem.current = n.mem.current.saturating_sub(bytes);
            if file {
                n.mem.file = n.mem.file.saturating_sub(bytes);
            }
            if n.dead && n.mem.current == 0 && n.children.is_empty() {
                self.nodes.remove(&a);
            }
        }
    }

    /// The effective `memory.min` and `memory.low` of each cgroup below `root` that uses
    /// memory, for a reclaim in `root`, as `mem_cgroup_calculate_protection` of Linux. A child
    /// of `root` has its own values. A cgroup lower down gets its part of the effective value
    /// of its parent: if the protected use of the children, `min(current, memory.min)`, is
    /// above the effective value of the parent, each child gets the part of its protected use.
    /// `root` itself has no protection. The removed cgroups count with their parent.
    fn protection(&self, root: CgId) -> BTreeMap<CgId, (u64, u64)> {
        // The cgroups below `root`, with the removed ones, by their parent.
        let mut below: BTreeMap<CgId, Vec<CgId>> = BTreeMap::new();
        for (&id, n) in &self.nodes {
            if id != root && n.mem.current > 0 && self.is_descendant(id, root) {
                below.entry(n.parent).or_default().push(id);
            }
        }
        let mut out = BTreeMap::new();
        out.insert(root, (0, 0));
        let mut todo = alloc::vec![root];
        while let Some(parent) = todo.pop() {
            let Some(kids) = below.get(&parent) else { continue };
            let (pmin, plow) = out[&parent];
            let used = |id: CgId, f: fn(&Memory) -> u64| {
                let n = &self.nodes[&id];
                if self.on(id, MEMORY) { n.mem.current.min(f(&n.mem)) } else { 0 }
            };
            let sum_min: u64 = kids.iter().map(|&k| used(k, |m| m.min)).sum();
            let sum_low: u64 = kids.iter().map(|&k| used(k, |m| m.low)).sum();
            for &k in kids {
                let n = &self.nodes[&k];
                let prot = if !self.on(k, MEMORY) {
                    (0, 0)
                } else if parent == root {
                    (n.mem.min, n.mem.low)
                } else {
                    let part = |own: u64, sum: u64, parent_e: u64| {
                        if sum > parent_e {
                            (u128::from(own) * u128::from(parent_e) / u128::from(sum)) as u64
                        } else {
                            own
                        }
                    };
                    (
                        part(used(k, |m| m.min), sum_min, pmin),
                        part(used(k, |m| m.low), sum_low, plow),
                    )
                };
                out.insert(k, prot);
                todo.push(k);
            }
        }
        out
    }

    /// Plans the reclaim of `want` bytes of the page cache in the subtree of `root`, as
    /// `try_to_free_mem_cgroup_pages` of Linux. Gives the cgroups and the bytes of their own
    /// page cache to take. A cgroup keeps its effective `memory.low`, and its effective
    /// `memory.min`. If that is not enough for `want`, a second pass goes below the effective
    /// `memory.low`, and each cgroup at or below it counts a `low` event. The plan takes from
    /// each cgroup in proportion to what it can give.
    pub fn reclaim_plan(&mut self, root: CgId, want: u64) -> Vec<(CgId, u64)> {
        let prot = self.protection(root);
        let free = |h: &Self, low_pass: bool| -> Vec<(CgId, u64)> {
            prot.iter()
                .filter_map(|(&id, &(emin, elow))| {
                    let m = &h.nodes[&id].mem;
                    let keep = if low_pass { emin } else { emin.max(elow) };
                    let n = m.file_local.min(m.current.saturating_sub(keep));
                    (n > 0).then_some((id, n))
                })
                .collect()
        };
        let mut plan = free(self, false);
        if plan.iter().map(|p| p.1).sum::<u64>() < want {
            // `mem_cgroup_below_low` of Linux: a cgroup with an effective `memory.low` that
            // its use does not pass.
            let low: Vec<CgId> = prot
                .iter()
                .filter(|(id, (_, elow))| *elow > 0 && self.nodes[id].mem.current <= *elow)
                .map(|(&id, _)| id)
                .collect();
            for id in low {
                self.memory_event(id, EV_LOW);
            }
            plan = free(self, true);
        }
        let total: u64 = plan.iter().map(|p| p.1).sum();
        if total > want {
            for p in &mut plan {
                p.1 = (u128::from(p.1) * u128::from(want)).div_ceil(u128::from(total)) as u64;
            }
        }
        plan.retain(|p| p.1 > 0);
        plan
    }

    /// Counts the event `ev` of `memory.events` in `id` and the cgroups above it, and of
    /// `memory.events.local` in `id`.
    fn memory_event(&mut self, id: CgId, ev: usize) {
        if let Some(n) = self.nodes.get_mut(&id) {
            n.mem.events_local[ev] += 1;
        }
        for a in self.path_ids(id) {
            if let Some(n) = self.nodes.get_mut(&a) {
                n.mem.events[ev] += 1;
                n.files_seq += 1;
            }
        }
        self.notify = true;
    }

    /// Counts an OOM in `id`: a charge failed, and the caller looks for a process to kill.
    pub fn count_oom(&mut self, id: CgId) {
        self.memory_event(id, EV_OOM);
    }

    /// Counts an OOM kill in `id`.
    pub fn count_oom_kill(&mut self, id: CgId) {
        self.memory_event(id, EV_OOM_KILL);
    }

    /// Counts a kill of the whole group `id` for `memory.oom.group`.
    pub fn count_oom_group_kill(&mut self, id: CgId) {
        self.memory_event(id, EV_OOM_GROUP_KILL);
    }

    /// The cgroup that an OOM kill of a process of `victim` must kill as a whole, as
    /// `mem_cgroup_get_oom_group` of Linux: the highest cgroup with `memory.oom.group` 1 from
    /// `victim` up to `domain`, the cgroup whose limit the charge passed. `domain` is the root
    /// for an OOM of the system. Gives `None` if no such cgroup has `memory.oom.group` 1.
    pub fn oom_group(&self, victim: CgId, domain: CgId) -> Option<CgId> {
        let path = self.path_ids(victim);
        // The path goes from `victim` up to the root. A group above `domain` does not count.
        let end = path.iter().position(|&a| a == domain)?;
        path[..=end]
            .iter()
            .rev()
            .copied()
            .find(|&a| self.on(a, MEMORY) && self.nodes.get(&a).is_some_and(|n| n.mem.oom_group))
    }

    /// The time in nanoseconds that a thread of `id` must wait because its cgroup or a cgroup
    /// above it uses more than `memory.high`, as `mem_cgroup_handle_over_high` of Linux. The
    /// wait grows with the square of the part of the use over the limit and with the pages that
    /// the cgroup charged while over it. Sets the count of these pages to 0.
    pub fn high_delay(&mut self, id: CgId) -> u64 {
        if !self.any_over_high {
            return 0;
        }
        let (mut overage, mut pages) = (0u64, 0u64);
        for a in self.path_ids(id) {
            let on = self.on(a, MEMORY);
            let Some(n) = self.nodes.get_mut(&a) else { continue };
            let charged = core::mem::take(&mut n.mem.over_high);
            if !on || n.mem.high == MAX || n.mem.current <= n.mem.high || n.mem.high == 0 {
                continue;
            }
            // The part over the limit in units of 2^-20, `calculate_overage` of Linux.
            let over = ((n.mem.current - n.mem.high) << 20) / n.mem.high;
            overage = overage.max(over);
            pages = pages.max(charged / PAGE_SIZE);
        }
        self.any_over_high = self.nodes.values().any(|n| n.mem.over_high > 0);
        // `calculate_high_delay` of Linux, in nanoseconds instead of jiffies. Linux handles the
        // pages in batches of `HIGH_BATCH`, and the limit is for one batch. Here a thread can
        // come back after each page, so the limit is for a batch and the wait is for the part of
        // a batch.
        let delay = (u128::from(overage) * u128::from(overage) * 1_000_000_000) >> 34;
        let delay = delay.min(u128::from(HIGH_DELAY_MAX)) * u128::from(pages);
        let delay = u64::try_from(delay / u128::from(HIGH_BATCH)).unwrap_or(HIGH_DELAY_MAX);
        if delay <= HIGH_DELAY_MIN { 0 } else { delay.min(HIGH_DELAY_MAX) }
    }

    /// Charges `bytes` bytes in `ios` bios of the kind `op` of the device `dev` to `id` and to
    /// each cgroup above it, at the time `now`. The device took `ns` nanoseconds for them. Gives
    /// the time in nanoseconds that the task waits to keep the use under `io.max` of these
    /// cgroups and in the part of the device that `io.weight` gives.
    pub fn charge_io(&mut self, id: CgId, dev: u64, op: io::Op, io: (u64, u64), now: u64) -> u64 {
        self.charge_io_timed(id, dev, op, io, now, 0)
    }

    /// `charge_io` with the time `ns` that the device took.
    pub fn charge_io_timed(
        &mut self,
        id: CgId,
        dev: u64,
        op: io::Op,
        (bytes, ios): (u64, u64),
        now: u64,
        ns: u64,
    ) -> u64 {
        let mut delay = 0;
        for a in self.path_ids(id) {
            let limit = self.on(a, IO);
            if let Some(n) = self.nodes.get_mut(&a) {
                delay = delay.max(n.io.charge(dev, op, bytes, ios, now, limit));
            }
        }
        let share = self.io_share(id, dev, now);
        let s = self.io_shares.entry(dev).or_default();
        delay.max(s.charge(id, bytes, ns, share, now))
    }

    /// The part of the device `dev` that `id` gets now by `io.weight`, in units of
    /// `io::SHARE_UNIT`. At each level of the path, a cgroup with the io controller gets its
    /// weight divided by the sum of the weights of its siblings that are active on the device,
    /// with itself.
    pub fn io_share(&mut self, id: CgId, dev: u64, now: u64) -> u64 {
        let active = self.io_shares.get_mut(&dev).map(|s| s.active(now)).unwrap_or_default();
        let mut part = u128::from(io::SHARE_UNIT);
        for a in self.path_ids(id).into_iter().rev() {
            let Some(p) = self.parent(a).filter(|_| self.on(a, IO)) else { continue };
            let mut sum = 0u128;
            for &s in self.nodes[&p].children.values() {
                if s == a || (self.on(s, IO) && active.iter().any(|&x| self.is_descendant(x, s))) {
                    sum += u128::from(self.nodes[&s].io.weight_of(dev));
                }
            }
            part = part * u128::from(self.nodes[&a].io.weight_of(dev)) / sum.max(1);
        }
        u64::try_from(part).unwrap_or(io::SHARE_UNIT)
    }

    /// The memory of `id`.
    pub fn memory(&self, id: CgId) -> Option<&Memory> {
        self.nodes.get(&id).map(|n| &n.mem)
    }

    /// Tells if the use of `id` is over its `memory.max`, and gives the bytes over the limit.
    pub fn memory_over(&self, id: CgId) -> u64 {
        match self.nodes.get(&id) {
            Some(n) if n.mem.max != MAX && self.on(id, MEMORY) => {
                n.mem.current.saturating_sub(n.mem.max)
            }
            _ => 0,
        }
    }

    /// Adds `ns` of CPU time of a thread of `id` at the time `now` to `id` and the cgroups above
    /// it, and to their quotas.
    pub fn charge_cpu(&mut self, id: CgId, ns: u64, now: u64) {
        // The scheduler calls this often, so the walk up the tree does not make a `Vec`.
        let mut at = id;
        while let Some(parent) = self.nodes.get(&at).map(|n| n.parent) {
            let on = self.on(at, CPU);
            if let Some(n) = self.nodes.get_mut(&at) {
                if on {
                    n.cpu.charge(ns, now);
                } else {
                    n.cpu.usage += ns;
                }
            }
            at = parent;
        }
    }

    /// The time until which a thread of `id` must wait, because `id` or a cgroup above it used
    /// its quota of `cpu.max`. `None` if the thread can run.
    pub fn throttled_until(&mut self, id: CgId, now: u64) -> Option<u64> {
        if !self.any_quota {
            return None;
        }
        let mut until = None;
        for a in self.path_ids(id) {
            if !self.on(a, CPU) {
                continue;
            }
            let Some(n) = self.nodes.get_mut(&a) else { continue };
            if let Some(t) = n.cpu.throttled_until(now) {
                until = Some(until.map_or(t, |u: u64| u.max(t)));
            }
        }
        until
    }

    /// The factor of the weight of a thread of `id` in the fair class, in units of
    /// `WEIGHT_UNIT`.
    ///
    /// Linux schedules a group as one entity with the weight of `cpu.weight`, and the threads of
    /// the group share the time of the group. This hierarchy gives each thread the product of
    /// `cpu.weight / 100` of the cgroups of its path that use the cpu controller, divided by the
    /// threads of the highest of those cgroups. With one level of cgroups the shares are as in
    /// Linux. A thread that sleeps still counts, so a group with sleeping threads gets less. The
    /// root cgroup has no `cpu.weight`, so a thread of the root keeps its weight, as in Linux.
    pub fn weight_factor(&self, id: CgId) -> u64 {
        if id == ROOT {
            return WEIGHT_UNIT;
        }
        let path: Vec<CgId> =
            self.path_ids(id).into_iter().rev().filter(|&a| a != ROOT && self.on(a, CPU)).collect();
        let Some(&top) = path.first() else { return WEIGHT_UNIT };
        let mut f = u128::from(WEIGHT_UNIT);
        for a in &path {
            f = f * u128::from(self.nodes[a].cpu.weight) / u128::from(WEIGHT_DEFAULT);
        }
        f /= u128::from(self.pids(top).max(1));
        u64::try_from(f.max(1)).unwrap_or(u64::MAX)
    }

    /// The CPUs that the threads of `id` can use: `cpuset.cpus.effective`.
    pub fn effective_cpus(&self, id: CgId) -> u64 {
        let mut mask = self.online_cpus;
        for a in self.path_ids(id).into_iter().rev() {
            let own = self.nodes[&a].cpuset.cpus;
            if self.on(a, CPUSET) && own != 0 && own & mask != 0 {
                mask &= own;
            }
        }
        mask
    }

    /// The memory nodes of `id`: `cpuset.mems.effective`. The machine has the node 0 only.
    pub fn effective_mems(&self, id: CgId) -> u64 {
        let mut mask = 1;
        for a in self.path_ids(id).into_iter().rev() {
            let own = self.nodes[&a].cpuset.mems;
            if self.on(a, CPUSET) && own != 0 && own & mask != 0 {
                mask &= own;
            }
        }
        mask
    }

    /// Changes the counts of the pressure of `id` and of the cgroups above it with `f` at the
    /// time `now`.
    pub fn psi_change(&mut self, id: CgId, now: u64, f: impl Fn(&mut psi::Counts)) {
        // The scheduler calls this at each task switch, so the walk up the tree does not make a
        // `Vec`, as in `charge_cpu`.
        let mut at = id;
        while let Some(n) = self.nodes.get_mut(&at) {
            n.psi.change(now, &f);
            at = n.parent;
        }
    }

    /// The text of the pressure file of `resource` of `id` at the time `now`.
    pub fn psi_show(&mut self, id: CgId, resource: usize, now: u64) -> Result<String, Errno> {
        Ok(self.node_mut(id)?.psi.show(now, resource))
    }

    /// The total stall time of `resource` in `id` up to `now`, in nanoseconds.
    pub fn psi_total(&mut self, id: CgId, resource: usize, full: bool, now: u64) -> u64 {
        self.nodes.get_mut(&id).map_or(0, |n| n.psi.total(now, resource, full))
    }

    /// The pressure counts of `id`.
    pub fn psi_counts(&self, id: CgId) -> psi::Counts {
        self.nodes.get(&id).map_or_else(psi::Counts::default, |n| n.psi.counts())
    }

    /// Makes a cgroup namespace with the root `root`, and gives its number.
    pub fn new_namespace(&mut self, root: CgId) -> u32 {
        let ns = self.next_ns;
        self.next_ns += 1;
        self.namespaces.insert(ns, root);
        ns
    }

    /// The root of the cgroup namespace `ns`. A namespace that does not exist has the root of
    /// the system.
    pub fn namespace_root(&self, ns: u32) -> CgId {
        self.namespaces.get(&ns).copied().unwrap_or(ROOT)
    }

    /// Reads the file `name` of `id` at the time `now`. `cgroup.procs` and `cgroup.threads` need
    /// the processes, so rk-fs-cgroup reads them.
    ///
    /// # Errors
    ///
    /// `ENOENT` if `id` does not have the file, and `EINVAL` for a file that only takes writes.
    pub fn read(&mut self, id: CgId, name: &str, now: u64) -> Result<String, Errno> {
        if self.file(id, name.as_bytes()).is_none() {
            return Err(Errno::ENOENT);
        }
        let root = self.parent(id).is_none();
        let avail = self.controllers(id);
        let cpu_on = self.on(id, CPU);
        let populated = self.populated(id);
        let frozen = self.events_frozen(id);
        // The count goes over each cgroup, so only cgroup.stat counts.
        let dying = if name == "cgroup.stat" { self.nr_dying(id) } else { 0 };
        let cpus = self.effective_cpus(id);
        let mems = self.effective_mems(id);
        let type_name = self.type_name(id);
        let n = self.node_mut(id)?;
        if let Some(r) = name.strip_suffix(".pressure") {
            let r = psi::NAMES.iter().position(|&x| x == r).ok_or(Errno::ENOENT)?;
            return Ok(n.psi.show(now, r));
        }
        let events = |e: &[u64; NR_EV]| {
            format!(
                "low {}\nhigh {}\nmax {}\noom {}\noom_kill {}\noom_group_kill {}\n",
                e[EV_LOW], e[EV_HIGH], e[EV_MAX], e[EV_OOM], e[EV_OOM_KILL], e[EV_OOM_GROUP_KILL]
            )
        };
        let out = match name {
            "cgroup.controllers" => controller_names(avail),
            "cgroup.subtree_control" => controller_names(n.subtree_control),
            "cgroup.events" => {
                format!("populated {}\nfrozen {}\n", u8::from(populated), u8::from(frozen))
            }
            "cgroup.type" => format!("{type_name}\n"),
            "cgroup.freeze" => format!("{}\n", u8::from(n.freeze)),
            "cgroup.max.depth" => {
                show_max(if n.max_depth == u32::MAX { MAX } else { u64::from(n.max_depth) })
            }
            "cgroup.max.descendants" => show_max(if n.max_descendants == u32::MAX {
                MAX
            } else {
                u64::from(n.max_descendants)
            }),
            "cgroup.stat" => {
                format!("nr_descendants {}\nnr_dying_descendants {dying}\n", n.nr_descendants)
            }
            "cpu.stat" => {
                n.cpu.refill(now);
                let us = n.cpu.usage / 1000;
                let mut out = format!("usage_usec {us}\nuser_usec {us}\nsystem_usec 0\n");
                if cpu_on {
                    let mut throttled = n.cpu.throttled;
                    if let Some(since) = n.cpu.throttled_since {
                        throttled += now.saturating_sub(since);
                    }
                    out.push_str(&format!(
                        "nr_periods {}\nnr_throttled {}\nthrottled_usec {}\nnr_bursts 0\n\
                         burst_usec 0\n",
                        n.cpu.nr_periods,
                        n.cpu.nr_throttled,
                        throttled / 1000
                    ));
                }
                out
            }
            "cpu.weight" => format!("{}\n", n.cpu.weight),
            "cpu.weight.nice" => format!("{}\n", nice_of_weight(n.cpu.weight)),
            "cpu.max" => match n.cpu.quota {
                Some(q) => format!("{} {}\n", q / 1000, n.cpu.period / 1000),
                None => format!("max {}\n", n.cpu.period / 1000),
            },
            "cpu.max.burst" => String::from("0\n"),
            "cpuset.cpus" => show_list(n.cpuset.cpus),
            "cpuset.mems" => show_list(n.cpuset.mems),
            "cpuset.cpus.effective" => show_list(cpus),
            "cpuset.mems.effective" => show_list(mems),
            "cpuset.cpus.exclusive" => String::from("\n"),
            "cpuset.cpus.partition" => String::from(if root { "root\n" } else { "member\n" }),
            "io.stat" => n.io.show_stat(),
            "io.max" => n.io.show_max(),
            "io.weight" => n.io.show_weight(),
            "memory.current" => format!("{}\n", n.mem.current),
            "memory.peak" => format!("{}\n", n.mem.peak),
            "memory.min" => show_max(n.mem.min),
            "memory.low" => show_max(n.mem.low),
            "memory.high" => show_max(n.mem.high),
            "memory.max" => show_max(n.mem.max),
            "memory.oom.group" => format!("{}\n", u8::from(n.mem.oom_group)),
            "memory.events" => events(&n.mem.events),
            "memory.events.local" => events(&n.mem.events_local),
            "memory.stat" => memory_stat(&n.mem),
            "memory.numa_stat" => {
                let anon = n.mem.current.saturating_sub(n.mem.file);
                format!("anon N0={anon}\nfile N0={}\n", n.mem.file)
            }
            "memory.swap.current" | "memory.swap.peak" | "memory.zswap.current" => {
                String::from("0\n")
            }
            "memory.swap.max" => show_max(n.mem.swap_max),
            "memory.swap.high" | "memory.zswap.max" => String::from("max\n"),
            "memory.swap.events" => String::from("high 0\nmax 0\nfail 0\n"),
            "pids.current" => format!("{}\n", n.pids),
            "pids.peak" => format!("{}\n", n.pids_peak),
            "pids.max" => show_max(n.pids_max),
            "pids.events" => format!("max {}\n", n.pids_events_max),
            _ => return Err(Errno::EINVAL),
        };
        Ok(out)
    }

    /// Writes `data` to the file `name` of `id` at the time `now`, and tells what the caller
    /// must do then. `cgroup.procs` and `cgroup.threads` need the processes, so rk-fs-cgroup
    /// writes them.
    ///
    /// # Errors
    ///
    /// `ENOENT` if `id` does not have the file, `EACCES` for a file that only takes reads,
    /// `EINVAL` for a value that is not valid, `ERANGE` for a weight out of range, and `EBUSY` for
    /// a change of `cgroup.subtree_control` that the rules do not allow.
    pub fn write(&mut self, id: CgId, name: &str, data: &[u8], now: u64) -> Result<Effect, Errno> {
        let info = self.file(id, name.as_bytes()).ok_or(Errno::ENOENT)?;
        if info.perm & 0o200 == 0 {
            return Err(Errno::EACCES);
        }
        match name {
            "cgroup.subtree_control" => {
                return self.set_subtree_control(id, data).map(|()| Effect::None);
            }
            "cgroup.kill" => {
                return match text(data)? {
                    "1" => Ok(Effect::Kill),
                    _ => Err(Errno::ERANGE),
                };
            }
            // Only `threaded` is a valid write, as `cgroup_type_write` of Linux.
            "cgroup.type" => {
                return match text(data)? {
                    "threaded" => self.enable_threaded(id).map(|()| Effect::None),
                    _ => Err(Errno::EINVAL),
                };
            }
            _ => {}
        }
        let n = self.node_mut(id)?;
        let effect = match name {
            "cgroup.freeze" => {
                let freeze = match text(data)? {
                    "0" => false,
                    "1" => true,
                    _ => return Err(Errno::ERANGE),
                };
                if freeze == n.freeze {
                    return Ok(Effect::None);
                }
                n.freeze = freeze;
                if freeze {
                    self.nr_freeze += 1;
                } else {
                    self.nr_freeze -= 1;
                }
                self.dirty = true;
                return Ok(Effect::Freeze);
            }
            "cgroup.max.depth" => {
                n.max_depth = u32::try_from(parse_max(data)?).unwrap_or(u32::MAX);
                Effect::None
            }
            "cgroup.max.descendants" => {
                n.max_descendants = u32::try_from(parse_max(data)?).unwrap_or(u32::MAX);
                Effect::None
            }
            "cpu.weight" => {
                let w = parse_max(data)?;
                if !(1..=10_000).contains(&w) {
                    return Err(Errno::ERANGE);
                }
                n.cpu.weight = w as u32;
                Effect::None
            }
            "cpu.weight.nice" => {
                let nice: i32 = text(data)?.parse().map_err(|_| Errno::EINVAL)?;
                if !(-20..=19).contains(&nice) {
                    return Err(Errno::ERANGE);
                }
                n.cpu.weight = weight_of_nice(nice);
                Effect::None
            }
            "cpu.max" => {
                let s = text(data)?;
                let mut words = s.split_ascii_whitespace();
                let quota = match words.next() {
                    Some("max") => None,
                    Some(w) => Some(w.parse::<u64>().map_err(|_| Errno::EINVAL)?),
                    None => return Err(Errno::EINVAL),
                };
                let period = match words.next() {
                    Some(w) => w.parse::<u64>().map_err(|_| Errno::EINVAL)?,
                    None => n.cpu.period / 1000,
                };
                if words.next().is_some()
                    || !(1000..=1_000_000).contains(&period)
                    || quota.is_some_and(|q| !(1000..=u64::MAX / 1000).contains(&q))
                {
                    return Err(Errno::EINVAL);
                }
                n.cpu.set_max(quota.map(|q| q * 1000), period * 1000, now);
                self.any_quota |= quota.is_some();
                Effect::Throttle
            }
            "cpu.max.burst" => {
                if parse_max(data)? != 0 {
                    return Err(Errno::EINVAL);
                }
                Effect::None
            }
            "cpuset.cpus" => {
                n.cpuset.cpus = parse_list(data)?;
                Effect::Cpuset
            }
            "cpuset.mems" => {
                let mems = parse_list(data)?;
                if mems & !1 != 0 {
                    return Err(Errno::EINVAL);
                }
                n.cpuset.mems = mems;
                Effect::None
            }
            "cpuset.cpus.exclusive" => {
                if parse_list(data)? != 0 {
                    return Err(Errno::EINVAL);
                }
                Effect::None
            }
            "cpuset.cpus.partition" => match text(data)? {
                "member" => Effect::None,
                _ => return Err(Errno::EINVAL),
            },
            "io.max" => {
                n.io.write_max(text(data)?)?;
                Effect::Throttle
            }
            "io.weight" => {
                n.io.write_weight(text(data)?)?;
                Effect::None
            }
            "memory.min" => {
                n.mem.min = parse_bytes(data)?;
                Effect::None
            }
            "memory.low" => {
                n.mem.low = parse_bytes(data)?;
                Effect::None
            }
            "memory.high" => {
                n.mem.high = parse_bytes(data)?;
                Effect::Throttle
            }
            "memory.max" => {
                n.mem.max = parse_bytes(data)?;
                if n.mem.current > n.mem.max { Effect::MemoryOver } else { Effect::None }
            }
            "memory.swap.max" => {
                n.mem.swap_max = parse_bytes(data)?;
                Effect::None
            }
            "memory.swap.high" | "memory.zswap.max" => {
                parse_bytes(data)?;
                Effect::None
            }
            "memory.peak" | "memory.swap.peak" => {
                n.mem.peak = n.mem.current;
                Effect::None
            }
            "memory.oom.group" => {
                n.mem.oom_group = match text(data)? {
                    "0" => false,
                    "1" => true,
                    _ => return Err(Errno::EINVAL),
                };
                Effect::None
            }
            // rukernel has no reclaim, so no memory comes back.
            "memory.reclaim" => {
                parse_bytes(data)?;
                return Err(Errno::EAGAIN);
            }
            "pids.max" => {
                n.pids_max = parse_max(data)?;
                Effect::None
            }
            _ => return Err(Errno::EINVAL),
        };
        Ok(effect)
    }

    /// Changes `cgroup.subtree_control` of `id` with a list as `+cpu -memory`, as
    /// `cgroup_subtree_control_write` of Linux.
    fn set_subtree_control(&mut self, id: CgId, data: &[u8]) -> Result<(), Errno> {
        let (mut enable, mut disable) = (0u8, 0u8);
        for word in text(data)?.split_ascii_whitespace() {
            let (on, name) = match word.as_bytes().first() {
                Some(b'+') => (true, &word[1..]),
                Some(b'-') => (false, &word[1..]),
                _ => return Err(Errno::EINVAL),
            };
            let bit = CONTROLLERS
                .iter()
                .find(|(_, n)| *n == name)
                .map(|&(b, _)| b)
                .ok_or(Errno::EINVAL)?;
            if on {
                enable |= bit;
                disable &= !bit;
            } else {
                disable |= bit;
                enable &= !bit;
            }
        }
        let avail = self.controllers(id);
        if enable & !avail != 0 {
            return Err(Errno::ENOENT);
        }
        let n = self.node(id)?;
        let enable = enable & !n.subtree_control;
        let disable = disable & n.subtree_control;
        self.vet_enable(id, enable)?;
        let n = self.node(id)?;
        // A controller that a child gives to its own children stays.
        for &c in n.children.values() {
            if self.subtree_control(c) & disable != 0 {
                return Err(Errno::EBUSY);
            }
        }
        let n = self.node_mut(id)?;
        n.subtree_control = (n.subtree_control | enable) & !disable;
        Ok(())
    }

    /// Checks that `id` can give the controllers `enable` to its children, as
    /// `cgroup_vet_subtree_control_enable` of Linux. A cgroup that is not the root and that has
    /// processes cannot give domain controllers to its children. A threaded subtree has only
    /// threaded controllers.
    fn vet_enable(&self, id: CgId, enable: u8) -> Result<(), Errno> {
        if enable == 0 {
            return Ok(());
        }
        if !self.is_valid_domain(self.dom(id)) {
            return Err(Errno::EOPNOTSUPP);
        }
        if self.is_mixable(id) {
            return Ok(());
        }
        if enable & !THREADED != 0 {
            if self.is_thread_root(id) || self.is_threaded(id) {
                return Err(Errno::EOPNOTSUPP);
            }
        } else if self.can_be_thread_root(id) || self.is_threaded(id) {
            return Ok(());
        }
        if self.has_tasks(id) {
            return Err(Errno::EBUSY);
        }
        Ok(())
    }

    /// The text of `/proc/cgroups`: each controller, its hierarchy, its number of cgroups, and
    /// if it is enabled. The hierarchy of cgroup v2 has the number 0.
    pub fn proc_cgroups(&self) -> String {
        let live = self.nodes.values().filter(|n| !n.dead).count();
        let mut out = String::from("#subsys_name\thierarchy\tnum_cgroups\tenabled\n");
        for (_, name) in CONTROLLERS {
            out.push_str(&format!("{name}\t0\t{live}\t1\n"));
        }
        out
    }
}

/// The weight of `cpu.weight` for a nice value, as `cpu_weight_nice_write_s64` of Linux.
fn weight_of_nice(nice: i32) -> u32 {
    let w = NICE_WEIGHTS[(nice + 20) as usize];
    // The scale of Linux: weight 1024 is `cpu.weight` 100.
    ((w * 100 + 512) / 1024).clamp(1, 10_000) as u32
}

/// The nice value that is closest to `cpu.weight` `w`, as `cpu_weight_nice_read_s64` of Linux.
fn nice_of_weight(w: u32) -> i32 {
    let w = u64::from(w) * 1024 / 100;
    let mut best = 0;
    let mut diff = u64::MAX;
    for (i, &x) in NICE_WEIGHTS.iter().enumerate() {
        let d = x.abs_diff(w);
        if d < diff {
            diff = d;
            best = i as i32 - 20;
        }
    }
    best
}

/// The text of `memory.stat`. The memory that rukernel charges is the anonymous memory of the
/// processes and the page cache.
fn memory_stat(m: &Memory) -> String {
    let anon = m.current.saturating_sub(m.file);
    let mut out = String::new();
    for (name, v) in [
        ("anon", anon),
        ("file", m.file),
        ("kernel", 0),
        ("kernel_stack", 0),
        ("pagetables", 0),
        ("sec_pagetables", 0),
        ("percpu", 0),
        ("sock", 0),
        ("vmalloc", 0),
        ("shmem", 0),
        ("file_mapped", 0),
        ("file_dirty", 0),
        ("file_writeback", 0),
        ("swapcached", 0),
        ("anon_thp", 0),
        ("file_thp", 0),
        ("shmem_thp", 0),
        ("inactive_anon", 0),
        ("active_anon", anon),
        ("inactive_file", m.file),
        ("active_file", 0),
        ("unevictable", 0),
        ("slab_reclaimable", 0),
        ("slab_unreclaimable", 0),
        ("slab", 0),
        ("workingset_refault_anon", 0),
        ("workingset_refault_file", 0),
        ("pgscan", 0),
        ("pgsteal", 0),
        ("pgfault", 0),
        ("pgmajfault", 0),
    ] {
        out.push_str(&format!("{name} {v}\n"));
    }
    out
}

/// The hierarchy of the kernel. It is made at the first use.
static HIERARCHY: SpinLock<Option<Hierarchy>> = SpinLock::new(None);

/// A cgroup has `cgroup.freeze` 1. The check of a signal looks at it first, so that the
/// check does not take the lock of the hierarchy when no cgroup freezes.
static ANY_FREEZE: AtomicBool = AtomicBool::new(false);

/// A cgroup charged pages over its `memory.high`. The return to user mode looks at it first.
static ANY_OVER_HIGH: AtomicBool = AtomicBool::new(false);

/// A cgroup had a quota in `cpu.max`. The return to user mode looks at it first, so that it does
/// not take the lock of the hierarchy when no cgroup has a quota.
static ANY_QUOTA: AtomicBool = AtomicBool::new(false);

/// The function that wakes the tasks in `poll`, after a change of a file with events.
static NOTIFY: SpinLock<Option<fn()>> = SpinLock::new(None);

/// Sets the function that wakes the tasks in `poll` after a change of `cgroup.events` or of
/// another file with events. rk-fs-cgroup sets it.
pub fn set_notify(f: fn()) {
    *NOTIFY.lock() = Some(f);
}

/// Calls `f` with the hierarchy of the kernel. After a change of a file with events, this wakes
/// the tasks in `poll`, without the lock of the hierarchy.
pub fn with<R>(f: impl FnOnce(&mut Hierarchy) -> R) -> R {
    let (r, notify) = {
        let mut h = HIERARCHY.lock();
        let h = h.get_or_insert_with(|| Hierarchy::new(now(), 1));
        let r = f(h);
        h.refresh_events();
        ANY_FREEZE.store(h.any_freeze(), Ordering::Relaxed);
        ANY_OVER_HIGH.store(h.any_over_high, Ordering::Relaxed);
        ANY_QUOTA.store(h.any_quota, Ordering::Relaxed);
        (r, h.take_notify())
    };
    if notify && let Some(f) = *NOTIFY.lock() {
        f();
    }
    r
}

/// The time now in nanoseconds since boot. The host has no clock of the kernel, so the time is
/// 0 there.
pub fn now() -> u64 {
    #[cfg(target_os = "none")]
    let t = rk_frame::time::nanos();
    #[cfg(not(target_os = "none"))]
    let t = 0;
    t
}

/// Sets the CPUs of the machine. The kernel calls this when the CPUs run.
pub fn set_online_cpus(count: usize) {
    let mask = if count >= 64 { u64::MAX } else { (1u64 << count) - 1 };
    with(|h| h.set_online_cpus(mask));
}

/// Charges a new thread to `id`. See `Hierarchy::charge_pids`.
///
/// # Errors
///
/// `EAGAIN` past a `pids.max`.
pub fn charge_thread(id: CgId) -> Result<(), Errno> {
    with(|h| h.charge_pids(id, 1))
}

/// Removes a thread that ended from `id`.
pub fn uncharge_thread(id: CgId) {
    with(|h| h.uncharge_pids(id, 1));
}

/// The function that drops the clean page cache of a cgroup: it gets the cgroup and the bytes,
/// and gives the bytes that it dropped. The block layer gives it.
pub type ReclaimFn = fn(CgId, u64) -> u64;

/// The hook of [`set_reclaim`].
static RECLAIM: Once<ReclaimFn> = Once::new();

/// The bytes that a reclaim for a charge takes at least, as `SWAP_CLUSTER_MAX` of Linux.
const RECLAIM_BATCH: u64 = 64 * PAGE_SIZE;

/// Sets the function that drops the page cache of a cgroup. The kernel calls this once.
pub fn set_reclaim(f: ReclaimFn) {
    RECLAIM.call_once(|| f);
}

/// Takes back `want` bytes of the page cache in the subtree of `root`, as
/// `try_to_free_mem_cgroup_pages` of Linux. See `Hierarchy::reclaim_plan`. Gives the bytes that
/// were dropped. The caller must not hold the lock of a page cache.
pub fn reclaim(root: CgId, want: u64) -> u64 {
    let Some(drop) = RECLAIM.get() else { return 0 };
    let plan = with(|h| h.reclaim_plan(root, want));
    plan.into_iter().map(|(id, bytes)| drop(id, bytes)).sum()
}

/// Charges a page of memory to `id`. A charge past a `memory.max` first takes back page cache
/// of that cgroup.
///
/// # Errors
///
/// Gives the cgroup whose limit the charge passes.
pub fn charge_page(id: CgId) -> Result<(), CgId> {
    if id == 0 {
        return Ok(());
    }
    let mut tries = 0;
    loop {
        match with(|h| h.charge_memory(id, PAGE_SIZE)) {
            Ok(()) => return Ok(()),
            Err(over) if tries < 8 && reclaim(over, RECLAIM_BATCH) > 0 => tries += 1,
            Err(over) => return Err(over),
        }
    }
}

/// Charges `bytes` of the page cache to `id`. The page cache calls this with its lock, so the
/// charge does not take pages back. See [`balance_file`].
pub fn charge_file(id: CgId, bytes: u64) {
    if id != 0 {
        with(|h| h.charge_file(id, bytes));
    }
}

/// Removes a charge of `bytes` of the page cache from `id`.
pub fn uncharge_file(id: CgId, bytes: u64) {
    if id != 0 {
        with(|h| h.uncharge_file(id, bytes));
    }
}

/// Takes back page cache until the cgroups above `id` are not over `memory.max`, after a charge
/// of the page cache. The page cache calls this without its lock.
pub fn balance_file(id: CgId) {
    if id == 0 {
        return;
    }
    for _ in 0..64 {
        let over = with(|h| {
            h.path_ids(id).into_iter().rev().find_map(|a| {
                let m = &h.nodes.get(&a)?.mem;
                (h.on(a, MEMORY) && m.max != MAX && m.current > m.max)
                    .then(|| (a, m.current - m.max))
            })
        });
        let Some((cg, excess)) = over else { return };
        if reclaim(cg, excess.max(RECLAIM_BATCH)) == 0 {
            return;
        }
    }
}

/// Charges `n` pages of memory to `id` at one time, as for a huge page.
///
/// # Errors
///
/// Gives the cgroup whose limit the charge passes. Then no page is charged.
pub fn charge_pages(id: CgId, n: usize) -> Result<(), CgId> {
    if id == 0 {
        return Ok(());
    }
    with(|h| h.charge_memory(id, PAGE_SIZE * n as u64))
}

/// Removes the charge of a page from `id`. rk-frame calls this when a charged frame is free.
pub fn uncharge_page(id: CgId) {
    if id != 0 {
        with(|h| h.uncharge_memory(id, PAGE_SIZE));
    }
}

/// Adds `ns` of CPU time of a thread to `id`. The scheduler calls this.
pub fn charge_cpu(id: CgId, ns: u64) {
    if id != 0 {
        let now = now();
        with(|h| h.charge_cpu(id, ns, now));
    }
}

/// The time in nanoseconds that a thread of `id` waits for `memory.high`. See
/// `Hierarchy::high_delay`.
pub fn high_delay(id: CgId) -> u64 {
    if id == 0 || !ANY_OVER_HIGH.load(Ordering::Relaxed) {
        return 0;
    }
    with(|h| h.high_delay(id))
}

/// Charges an I/O of `bytes` in `ios` bios that took the device `ns` nanoseconds to `id`. See
/// `Hierarchy::charge_io`. Gives the delay of `io.max` and `io.weight` in nanoseconds.
pub fn charge_io(id: CgId, dev: u64, op: io::Op, (bytes, ios): (u64, u64), ns: u64) -> u64 {
    if id == 0 {
        return 0;
    }
    let now = now();
    with(|h| h.charge_io_timed(id, dev, op, (bytes, ios), now, ns))
}

/// The time in nanoseconds until which a thread of `id` waits for its quota.
pub fn throttled_until(id: CgId) -> Option<u64> {
    if !ANY_QUOTA.load(Ordering::Relaxed) {
        return None;
    }
    let now = now();
    with(|h| h.throttled_until(id, now))
}

/// The factor of the weight of a thread of `id`, in units of `WEIGHT_UNIT`.
pub fn weight_factor(id: CgId) -> u64 {
    with(|h| h.weight_factor(id))
}

/// Tells if `id` or a cgroup above it has `cgroup.freeze` 1, so its threads must freeze.
pub fn frozen(id: CgId) -> bool {
    ANY_FREEZE.load(Ordering::Relaxed) && with(|h| h.frozen(id))
}

/// Tells if a cgroup has `cgroup.freeze` 1, charged pages over its `memory.high`, or had a quota
/// in `cpu.max`. If not, `frozen`, `high_delay` and `throttled_until` give no wait.
pub fn any_limit() -> bool {
    ANY_FREEZE.load(Ordering::Relaxed)
        || ANY_OVER_HIGH.load(Ordering::Relaxed)
        || ANY_QUOTA.load(Ordering::Relaxed)
}

/// Changes the pressure counts of `id` with `f`.
pub fn psi_change(id: CgId, f: impl Fn(&mut psi::Counts)) {
    if id != 0 {
        let now = now();
        with(|h| h.psi_change(id, now, f));
    }
}

#[cfg(test)]
mod tests;

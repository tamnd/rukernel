//! The counters of each cgroup that the hot paths change without the lock of the tree.
//!
//! A charge of memory or of a thread changes a count in the cgroup and in each cgroup above it.
//! Linux does this with the atomic counters of mm/page_counter.c and the `pids_try_charge` of
//! kernel/cgroup/pids.c: each counter has a pointer to the counter of the parent, and a charge
//! adds to each counter and takes the charge back if a limit refuses it. Only a change of the tree
//! (`mkdir`, `rmdir`, a move of a task) takes `cgroup_mutex` or `css_set_lock`. This module does
//! the same. Each cgroup has a [`Counters`] with atomic counts, a pointer to the counters of its
//! parent, and a lock for the CPU time and for the pressure of the cgroup. The tree keeps the
//! counters of each cgroup in a map that a charge reads with a read lock, as the IDR of cgroups in
//! Linux that a lookup reads under RCU.

use crate::{CPU, CgId, Cpu, MAX, MEMORY, NR_EV, PIDS, ROOT, WEIGHT_DEFAULT, WEIGHT_UNIT, psi};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use rk_frame::sync::{RwLock, SpinLock};

/// The state that the hot paths and the tree share.
pub(crate) struct Shared {
    /// The counters of each cgroup by ID, with the removed cgroups that still have charges.
    pub(crate) map: RwLock<BTreeMap<CgId, Arc<Counters>>>,
    /// A file that `poll` watches changed since the last `take_notify`.
    pub(crate) notify: AtomicBool,
    /// A cgroup can have pages that it charged over `memory.high`, for `high_delay`.
    pub(crate) any_over_high: AtomicBool,
}

impl Shared {
    pub(crate) fn new() -> Self {
        Self {
            map: RwLock::new(BTreeMap::new()),
            notify: AtomicBool::new(false),
            any_over_high: AtomicBool::new(false),
        }
    }
}

/// The counts of the memory controller of one cgroup that a charge changes. The sizes are in
/// bytes.
#[derive(Default)]
pub(crate) struct MemCounters {
    /// The bytes that the subtree uses now: `memory.current`.
    pub(crate) current: AtomicU64,
    /// The largest value of `current`: `memory.peak`.
    pub(crate) peak: AtomicU64,
    /// The largest value of `current` after the last write of `memory.peak`, as
    /// `local_watermark` of the page counter of Linux. An open file of `memory.peak` that had a
    /// write shows this value.
    pub(crate) local_peak: AtomicU64,
    /// `memory.high`.
    pub(crate) high: AtomicU64,
    /// `memory.max`.
    pub(crate) max: AtomicU64,
    /// The bytes of the page cache that the subtree uses, a part of `current`.
    pub(crate) file: AtomicU64,
    /// The bytes of the page cache that this cgroup uses, without the subtree.
    pub(crate) file_local: AtomicU64,
    /// The bytes that the subtree charged while the use was over `memory.high`.
    pub(crate) over_high: AtomicU64,
    /// The counts of `memory.events`, with the events of the subtree.
    pub(crate) events: [AtomicU64; NR_EV],
    /// The counts of `memory.events.local`.
    pub(crate) events_local: [AtomicU64; NR_EV],
    /// `pgscan_kswapd` and `pgscan_direct` of `memory.stat`: the pages of the subtree that the
    /// reclaim looked at.
    pub(crate) scan: [AtomicU64; 2],
    /// `pgsteal_kswapd` and `pgsteal_direct` of `memory.stat`: the pages of the subtree that the
    /// reclaim freed.
    pub(crate) steal: [AtomicU64; 2],
    /// The bytes of the subtree in swap areas: `memory.swap.current`.
    pub(crate) swap: AtomicU64,
    /// The largest value of `swap`: `memory.swap.peak`.
    pub(crate) swap_peak: AtomicU64,
    /// The largest value of `swap` after the last write of `memory.swap.peak`.
    pub(crate) swap_local_peak: AtomicU64,
    /// `memory.swap.max`.
    pub(crate) swap_max: AtomicU64,
    /// The counts `max` and `fail` of `memory.swap.events`.
    pub(crate) swap_events: [AtomicU64; 2],
    /// `pswpout` and `pswpin` of `memory.stat`: the pages of the subtree that went to swap and
    /// that came back.
    pub(crate) pswp: [AtomicU64; 2],
}

impl MemCounters {
    /// Tells if memory or swap is charged to the cgroup, so that a removed cgroup must stay, as
    /// the swap entries of Linux keep the ID of their memory cgroup.
    pub(crate) fn charged(&self) -> bool {
        self.current.load(Ordering::SeqCst) > 0 || self.swap.load(Ordering::SeqCst) > 0
    }
}

/// The counts of the pids controller of one cgroup.
#[derive(Default)]
pub(crate) struct PidsCounters {
    /// The threads of the subtree: `pids.current`.
    pub(crate) current: AtomicU64,
    /// The threads of this cgroup, without the subtree.
    pub(crate) local: AtomicU64,
    /// `pids.max`.
    pub(crate) max: AtomicU64,
    /// `pids.peak`.
    pub(crate) peak: AtomicU64,
    /// `pids.events`: the forks that the limit of this cgroup refused.
    pub(crate) events_max: AtomicU64,
}

/// The counters of one cgroup.
pub(crate) struct Counters {
    /// The ID of the cgroup.
    pub(crate) id: CgId,
    /// The counters of the parent, or `None` for the root. The parent of a cgroup does not
    /// change, so a charge follows these pointers with no lock.
    pub(crate) parent: Option<Arc<Counters>>,
    /// The controllers that work in this cgroup, as `Hierarchy::on` gives them. The tree sets
    /// them again after each change of `cgroup.subtree_control` or `cgroup.type`.
    pub(crate) ctrl: AtomicU8,
    /// The cgroup was removed. It stays while memory is charged to it.
    pub(crate) dead: AtomicBool,
    pub(crate) mem: MemCounters,
    pub(crate) pids: PidsCounters,
    /// The processes in this cgroup, without the subtree.
    pub(crate) nr_procs: AtomicU32,
    /// The count of the changes of `memory.events` and `pids.events`, for `poll`.
    pub(crate) files_seq: AtomicU64,
    /// `cpu.weight`.
    pub(crate) weight: AtomicU32,
    /// The sum of `cpu.weight` of the children that use the cpu controller and have a task in
    /// their subtree. The tree sets it when `populated` of a child, a `cpu.weight` or the
    /// controllers change, so the scheduler can read the weights of a level with no lock.
    pub(crate) child_weight: AtomicU64,
    /// The CPU time and the quota of `cpu.max`.
    pub(crate) cpu: SpinLock<Cpu>,
    /// The pressure of the subtree.
    pub(crate) psi: SpinLock<psi::Psi>,
}

/// The result of a charge: the flags that the caller must look at after it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Changed {
    /// The cgroup got its first thread or lost its last one, so `populated` can change.
    pub(crate) tasks: bool,
    /// A removed cgroup of the path has no charge now, and the tree can let it go.
    pub(crate) reap: bool,
}

/// Subtracts `n` from `a`, with 0 as the lowest value. Gives the new value.
fn sub_sat(a: &AtomicU64, n: u64) -> u64 {
    let old = a
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| Some(v.saturating_sub(n)))
        .unwrap_or_default();
    old.saturating_sub(n)
}

impl Counters {
    /// Makes the counters of a new cgroup `id` below `parent` at the time `now`.
    pub(crate) fn new(id: CgId, parent: Option<Arc<Counters>>, now: u64) -> Self {
        let root = parent.is_none();
        let c = Self {
            id,
            parent,
            ctrl: AtomicU8::new(0),
            dead: AtomicBool::new(false),
            mem: MemCounters::default(),
            pids: PidsCounters::default(),
            nr_procs: AtomicU32::new(0),
            files_seq: AtomicU64::new(1),
            weight: AtomicU32::new(WEIGHT_DEFAULT),
            child_weight: AtomicU64::new(0),
            cpu: SpinLock::new(Cpu { period_start: now, ..Cpu::default() }),
            psi: SpinLock::new(psi::Psi::new(now, root)),
        };
        c.mem.high.store(MAX, Ordering::Relaxed);
        c.mem.max.store(MAX, Ordering::Relaxed);
        c.mem.swap_max.store(MAX, Ordering::Relaxed);
        c.pids.max.store(MAX, Ordering::Relaxed);
        c
    }

    /// The counters from this cgroup up to the root, with both.
    pub(crate) fn path(&self) -> impl Iterator<Item = &Counters> {
        core::iter::successors(Some(self), |c| c.parent.as_deref())
    }

    /// Tells if the controller `ctrl` works in this cgroup.
    pub(crate) fn on(&self, ctrl: u8) -> bool {
        self.ctrl.load(Ordering::Relaxed) & ctrl != 0
    }

    /// Tells if the cgroup has a process or a thread of its own, `cgroup_has_tasks` of Linux.
    pub(crate) fn has_tasks(&self) -> bool {
        self.nr_procs.load(Ordering::SeqCst) > 0 || self.pids.local.load(Ordering::SeqCst) > 0
    }

    /// Counts the event `ev` of `memory.events` in this cgroup and the cgroups above it, and of
    /// `memory.events.local` in this cgroup.
    pub(crate) fn memory_event(&self, ev: usize, sh: &Shared) {
        self.mem.events_local[ev].fetch_add(1, Ordering::Relaxed);
        for c in self.path() {
            c.mem.events[ev].fetch_add(1, Ordering::Relaxed);
            c.files_seq.fetch_add(1, Ordering::Relaxed);
        }
        sh.notify.store(true, Ordering::SeqCst);
    }

    /// Counts a reclaim that looked at `scanned` pages of this cgroup and freed `stolen` of them,
    /// in this cgroup and the cgroups above it, as `count_memcg_events` of Linux with the
    /// hierarchical counts of `memory.stat`. Index 0 is for `kswapd`, 1 for a direct reclaim.
    pub(crate) fn count_reclaim(&self, i: usize, scanned: u64, stolen: u64) {
        for c in self.path() {
            c.mem.scan[i].fetch_add(scanned, Ordering::Relaxed);
            c.mem.steal[i].fetch_add(stolen, Ordering::Relaxed);
        }
    }

    /// Charges `bytes` of swap to this cgroup and the cgroups above it, as
    /// `__mem_cgroup_try_charge_swap` of Linux.
    ///
    /// # Errors
    ///
    /// Gives `Err` if the charge passes the `memory.swap.max` of a cgroup of the path. That
    /// cgroup and the cgroups above it count a `max` and a `fail` event of `memory.swap.events`.
    pub(crate) fn try_charge_swap(&self, bytes: u64, sh: &Shared) -> Result<(), ()> {
        for c in self.path() {
            let new = c.mem.swap.fetch_add(bytes, Ordering::SeqCst) + bytes;
            let max = c.mem.swap_max.load(Ordering::Relaxed);
            if c.on(MEMORY) && max != MAX && new > max {
                for b in self.path() {
                    b.mem.swap.fetch_sub(bytes, Ordering::SeqCst);
                    if core::ptr::eq(b, c) {
                        break;
                    }
                }
                c.swap_event(0, sh);
                c.swap_event(1, sh);
                return Err(());
            }
        }
        for c in self.path() {
            let swap = c.mem.swap.load(Ordering::Relaxed);
            c.mem.swap_peak.fetch_max(swap, Ordering::Relaxed);
            c.mem.swap_local_peak.fetch_max(swap, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Removes a charge of `bytes` of swap from this cgroup and the cgroups above it. `reap` of
    /// the result tells that a removed cgroup has no charge now.
    pub(crate) fn uncharge_swap(&self, bytes: u64) -> Changed {
        let mut out = Changed::default();
        for c in self.path() {
            sub_sat(&c.mem.swap, bytes);
            if c.dead.load(Ordering::SeqCst) && !c.mem.charged() {
                out.reap = true;
            }
        }
        out
    }

    /// Counts the event `ev` of `memory.swap.events`, 0 for `max` and 1 for `fail`, in this
    /// cgroup and the cgroups above it.
    pub(crate) fn swap_event(&self, ev: usize, sh: &Shared) {
        for c in self.path() {
            c.mem.swap_events[ev].fetch_add(1, Ordering::Relaxed);
            c.files_seq.fetch_add(1, Ordering::Relaxed);
        }
        sh.notify.store(true, Ordering::SeqCst);
    }

    /// Counts `n` pages of this cgroup that went to swap if `out`, else that came back, in this
    /// cgroup and the cgroups above it.
    pub(crate) fn count_swap(&self, out: bool, n: u64) {
        for c in self.path() {
            c.mem.pswp[usize::from(!out)].fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Counts the bytes that `c` charged over its `memory.high`, after a charge that made its
    /// use `current`.
    fn over_high(c: &Counters, bytes: u64, current: u64, sh: &Shared) {
        let high = c.mem.high.load(Ordering::Relaxed);
        if c.on(MEMORY) && high != MAX && current > high {
            c.mem.over_high.fetch_add(bytes, Ordering::SeqCst);
            sh.any_over_high.store(true, Ordering::SeqCst);
            c.memory_event(crate::EV_HIGH, sh);
        }
    }

    /// Charges `bytes` of memory to this cgroup and the cgroups above it, as
    /// `page_counter_try_charge` of Linux: each counter gets the charge first, and a counter that
    /// passes its `memory.max` takes it back with the counters below it.
    ///
    /// # Errors
    ///
    /// Gives the cgroup whose `memory.max` the charge passes. That cgroup and the cgroups above
    /// it count a `max` event.
    pub(crate) fn try_charge_memory(&self, bytes: u64, sh: &Shared) -> Result<(), CgId> {
        for c in self.path() {
            let new = c.mem.current.fetch_add(bytes, Ordering::SeqCst) + bytes;
            let max = c.mem.max.load(Ordering::Relaxed);
            if c.on(MEMORY) && max != MAX && new > max {
                for b in self.path() {
                    b.mem.current.fetch_sub(bytes, Ordering::SeqCst);
                    if core::ptr::eq(b, c) {
                        break;
                    }
                }
                c.memory_event(crate::EV_MAX, sh);
                return Err(c.id);
            }
        }
        for c in self.path() {
            let current = c.mem.current.load(Ordering::Relaxed);
            c.mem.peak.fetch_max(current, Ordering::Relaxed);
            c.mem.local_peak.fetch_max(current, Ordering::Relaxed);
            Self::over_high(c, bytes, current, sh);
        }
        Ok(())
    }

    /// Charges `bytes` of the page cache to this cgroup and the cgroups above it. The charge does
    /// not fail. Gives the highest cgroup whose `memory.max` the use now passes.
    pub(crate) fn charge_file(&self, bytes: u64, sh: &Shared) -> Option<CgId> {
        self.mem.file_local.fetch_add(bytes, Ordering::Relaxed);
        let mut over = None;
        for c in self.path() {
            let current = c.mem.current.fetch_add(bytes, Ordering::SeqCst) + bytes;
            c.mem.file.fetch_add(bytes, Ordering::Relaxed);
            c.mem.peak.fetch_max(current, Ordering::Relaxed);
            c.mem.local_peak.fetch_max(current, Ordering::Relaxed);
            let max = c.mem.max.load(Ordering::Relaxed);
            if c.on(MEMORY) && max != MAX && current > max {
                over = Some(c.id);
            }
            Self::over_high(c, bytes, current, sh);
        }
        over
    }

    /// Removes a charge of `bytes`, of the page cache if `file`, from this cgroup and the cgroups
    /// above it. `reap` of the result tells that a removed cgroup has no charge now.
    pub(crate) fn uncharge_memory(&self, bytes: u64, file: bool) -> Changed {
        if file {
            sub_sat(&self.mem.file_local, bytes);
        }
        let mut out = Changed::default();
        for c in self.path() {
            let left = sub_sat(&c.mem.current, bytes);
            if file {
                sub_sat(&c.mem.file, bytes);
            }
            // `rmdir` sets `dead` and then reads `current`, and this reads them in the other
            // order, so one of the two sees the cgroup with no charge.
            if left == 0 && c.dead.load(Ordering::SeqCst) && !c.mem.charged() {
                out.reap = true;
            }
        }
        out
    }

    /// Adds `n` new threads to this cgroup and the cgroups above it, as `pids_try_charge` of
    /// Linux.
    ///
    /// # Errors
    ///
    /// Gives `Err` if the threads pass the `pids.max` of a cgroup of the path. That cgroup counts
    /// the event in `pids.events`.
    pub(crate) fn try_charge_pids(&self, n: u64, sh: &Shared) -> Result<Changed, ()> {
        for c in self.path() {
            let new = c.pids.current.fetch_add(n, Ordering::SeqCst) + n;
            let max = c.pids.max.load(Ordering::Relaxed);
            if c.on(PIDS) && max != MAX && new > max {
                for b in self.path() {
                    b.pids.current.fetch_sub(n, Ordering::SeqCst);
                    if core::ptr::eq(b, c) {
                        break;
                    }
                }
                c.pids.events_max.fetch_add(1, Ordering::Relaxed);
                c.files_seq.fetch_add(1, Ordering::Relaxed);
                sh.notify.store(true, Ordering::SeqCst);
                return Err(());
            }
        }
        for c in self.path() {
            c.pids.peak.fetch_max(c.pids.current.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        Ok(self.add_local(n))
    }

    /// Adds `n` threads to this cgroup and the cgroups above it, past the limits, as a move
    /// does.
    pub(crate) fn force_charge_pids(&self, n: u64) -> Changed {
        for c in self.path() {
            let new = c.pids.current.fetch_add(n, Ordering::SeqCst) + n;
            c.pids.peak.fetch_max(new, Ordering::Relaxed);
        }
        self.add_local(n)
    }

    /// Adds `n` threads to the threads of this cgroup without the subtree.
    fn add_local(&self, n: u64) -> Changed {
        let old = self.pids.local.fetch_add(n, Ordering::SeqCst);
        Changed { tasks: old == 0 && n > 0, reap: false }
    }

    /// Removes `n` threads that ended or moved from this cgroup and the cgroups above it.
    pub(crate) fn uncharge_pids(&self, n: u64) -> Changed {
        for c in self.path() {
            sub_sat(&c.pids.current, n);
        }
        let old = self.pids.local.load(Ordering::SeqCst);
        let left = sub_sat(&self.pids.local, n);
        Changed { tasks: old > 0 && left == 0, reap: false }
    }

    /// Adds a process to this cgroup (`add` true) or removes one.
    pub(crate) fn count_process(&self, add: bool) -> Changed {
        let old = if add {
            self.nr_procs.fetch_add(1, Ordering::SeqCst)
        } else {
            self.nr_procs
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| Some(v.saturating_sub(1)))
                .unwrap_or_default()
        };
        Changed { tasks: if add { old == 0 } else { old == 1 }, reap: false }
    }

    /// Adds `ns` of CPU time at the time `now` to this cgroup and the cgroups above it, and to
    /// their quotas. Each cgroup takes the lock of its own time.
    pub(crate) fn charge_cpu(&self, ns: u64, now: u64) {
        for c in self.path() {
            let on = c.on(CPU);
            let mut cpu = c.cpu.lock();
            if on {
                cpu.charge(ns, now);
            } else {
                cpu.usage += ns;
            }
        }
    }

    /// Changes the counts of the pressure of this cgroup and of the cgroups above it with `f` at
    /// the time `now`. Each cgroup takes the lock of its own pressure, as each group of Linux
    /// has its own counts.
    pub(crate) fn psi_change(&self, now: u64, f: &impl Fn(&mut psi::Counts)) {
        for c in self.path() {
            c.psi.lock().change(now, f);
        }
    }

    /// The time until which a thread of this cgroup must wait, because this cgroup or a cgroup
    /// above it used its quota of `cpu.max`. `None` if the thread can run.
    pub(crate) fn throttled_until(&self, now: u64) -> Option<u64> {
        let mut until = None;
        for c in self.path().filter(|c| c.on(CPU)) {
            if let Some(t) = c.cpu.lock().throttled_until(now) {
                until = Some(until.map_or(t, |u: u64| u.max(t)));
            }
        }
        until
    }

    /// The factor of the weight of a thread of this cgroup in the fair class, in units of
    /// `WEIGHT_UNIT`. See `Hierarchy::weight_factor`.
    pub(crate) fn weight_factor(&self) -> u64 {
        // From the top down, as the product rounds down at each step.
        let mut path: Vec<&Counters> = self.path().filter(|c| c.id != ROOT && c.on(CPU)).collect();
        path.reverse();
        let Some(top) = path.first() else { return WEIGHT_UNIT };
        let weight = |c: &Counters| u128::from(c.weight.load(Ordering::Relaxed));
        let default = u128::from(WEIGHT_DEFAULT);
        let mut f = u128::from(WEIGHT_UNIT) * weight(top) / default;
        for (i, c) in path.iter().enumerate() {
            // The entities of the group: its threads with the weight of nice 0, and its children
            // with threads. Without such children the group schedules each thread of its
            // subtree, as the children then do not use the cpu controller or have no thread.
            let children = u128::from(c.child_weight.load(Ordering::Relaxed));
            let threads = if children > 0 { &c.pids.local } else { &c.pids.current };
            let threads = u128::from(threads.load(Ordering::Relaxed));
            // The next group of the path, or the thread itself.
            let next = path.get(i + 1).map_or(default, |n| weight(n));
            f = f * next / (threads * default + children).max(next);
        }
        u64::try_from(f.max(1)).unwrap_or(u64::MAX)
    }
}

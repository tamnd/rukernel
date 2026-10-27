//! The choice of a CPU for a task and the first load balancer, per spec/06-scheduler.md section
//! 6.3.
//!
//! This first version has no scheduling domains: each CPU is as near as each other CPU. A task
//! that wakes goes to an idle CPU if one is free, as `select_idle_sibling` of Linux does, and
//! else to the CPU where it ran last. A CPU that becomes idle pulls a task from the busiest queue,
//! as `sched_balance_newidle` of Linux does, and a busy CPU evens out the queues at intervals, as
//! `sched_balance_rq` does. The load of a queue is its number of tasks. Linux uses the PELT load.

/// The load of the run queue of one CPU.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Load {
    /// The number of tasks that wait in the queue.
    pub queued: usize,
    /// Tells if a task of the fair class runs on the CPU.
    pub running: bool,
}

impl Load {
    /// The number of tasks of the CPU, as `nr_running` of Linux.
    pub fn nr(&self) -> usize {
        self.queued + usize::from(self.running)
    }

    /// Tells if the CPU has no task.
    pub fn is_idle(&self) -> bool {
        self.nr() == 0
    }
}

/// The time between two periodic balances of a busy CPU, in nanoseconds.
pub const BALANCE_INTERVAL: u64 = 4_000_000;

/// Tells if the mask `allowed` has the CPU `cpu`.
pub fn allows(allowed: u64, cpu: usize) -> bool {
    cpu < 64 && allowed >> cpu & 1 != 0
}

/// Chooses the CPU for a task that wakes or is new, as `select_task_rq_fair` of Linux does.
/// `prev` is the CPU where the task ran last, `this` is the CPU that wakes the task, `allowed` is
/// the affinity mask of the task and `loads` has one entry for each CPU that runs.
///
/// An idle CPU comes first: the CPU that wakes the task, then the last CPU of the task, for its
/// cache, then the CPU with the lowest number. The CPU that wakes the task is idle when the bottom
/// half of its idle loop wakes the task, and then it runs the task at once, with no interrupt to
/// another CPU. If no allowed CPU is idle, a task that wakes stays on its
/// last CPU, and a new task goes to the CPU with the fewest tasks. If the mask has no CPU that
/// runs, the task goes to its last CPU, as `select_fallback_rq` of Linux gives a CPU.
pub fn select_cpu(prev: usize, this: usize, allowed: u64, loads: &[Load], new: bool) -> usize {
    let ok = |c: usize| c < loads.len() && allows(allowed, c);
    let order = || [this, prev].into_iter().chain(0..loads.len());
    if let Some(c) = order().find(|&c| ok(c) && loads[c].is_idle()) {
        return c;
    }
    if !new && ok(prev) {
        return prev;
    }
    match order().filter(|&c| ok(c)).min_by_key(|&c| loads[c].nr()) {
        Some(c) => c,
        None if prev < loads.len() => prev,
        None => this,
    }
}

/// The CPU from which the CPU `this` pulls a task, as `sched_balance_find_src_rq` of Linux finds
/// it. The CPUs in the mask `skip` do not count. A CPU counts if it has a task that waits and has
/// at least two tasks more than `this`, so that the move of one task makes the loads more equal.
/// An idle CPU can also pull from a CPU that has a task in its queue but runs no task yet. That
/// CPU can be slow to wake up, and the task then runs at once on `this`. Of those CPUs, the CPU
/// with the most tasks comes first, and then the CPU with the lowest number.
pub fn busiest(this: usize, loads: &[Load], skip: u64) -> Option<usize> {
    let own = loads.get(this)?;
    let floor = own.nr() + 2;
    let counts = |l: &Load| l.queued > 0 && (l.nr() >= floor || (own.is_idle() && !l.running));
    (0..loads.len())
        .filter(|&c| c != this && !allows(skip, c))
        .filter(|&c| counts(&loads[c]))
        .max_by_key(|&c| (loads[c].nr(), core::cmp::Reverse(c)))
}

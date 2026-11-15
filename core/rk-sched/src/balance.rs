//! The choice of a CPU for a task and the first load balancer, per spec/06-scheduler.md section
//! 6.3.
//!
//! This first version has no scheduling domains: each CPU is as near as each other CPU. A task
//! that wakes goes to an idle CPU if one is free, as `select_idle_sibling` of Linux does, and
//! else to the CPU where it ran last. A CPU that becomes idle pulls a task from the busiest queue,
//! as `sched_balance_newidle` of Linux does, and a busy CPU evens out the queues at intervals, as
//! `sched_balance_rq` does. An idle CPU looks at the number of tasks of a queue, and a busy CPU
//! looks at the sum of the weights of its tasks, as Linux does with `migrate_task` and
//! `migrate_load`. Linux uses the PELT load, and this balancer uses the weights of now.

/// The load of the run queue of one CPU.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Load {
    /// The number of tasks that wait in the queue.
    pub queued: usize,
    /// Tells if a task of the fair class runs on the CPU.
    pub running: bool,
    /// The sum of the weights of the tasks that wait and of the task that runs, as the load of a
    /// queue in Linux. The weights include the part of `cpu.weight` of the cgroups.
    pub weight: u64,
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
/// it. The CPUs in the mask `skip` do not count. A CPU counts only if it has a task that waits.
///
/// An idle CPU counts the tasks, as Linux does when the local group has spare capacity: a CPU
/// counts if it has at least two tasks, so that the move of one task makes the loads more equal.
/// An idle CPU can also pull from a CPU that has a task in its queue but runs no task yet. That
/// CPU can be slow to wake up, and the task then runs at once on `this`. Of those CPUs, the CPU
/// with the most tasks comes first, and then the CPU with the lowest number.
///
/// A busy CPU compares the weights, as Linux does when both groups are busy: a CPU counts if its
/// weight is more than the weight of `this`, and `movable` then tells which task can move. Of
/// those CPUs, the CPU with the most weight comes first, and then the CPU with the lowest number.
pub fn busiest(this: usize, loads: &[Load], skip: u64) -> Option<usize> {
    let own = loads.get(this)?;
    let idle = own.is_idle();
    let counts = |l: &Load| {
        l.queued > 0 && if idle { l.nr() >= 2 || !l.running } else { l.weight > own.weight }
    };
    let key = |l: &Load| if idle { u64::try_from(l.nr()).unwrap_or(u64::MAX) } else { l.weight };
    (0..loads.len())
        .filter(|&c| c != this && !allows(skip, c))
        .filter(|&c| counts(&loads[c]))
        .max_by_key(|&c| (key(&loads[c]), core::cmp::Reverse(c)))
}

/// Tells if a task with the weight `weight` that waits on the CPU with the load `src` can move to
/// the CPU with the load `own`, after `busiest` chose `src`. Each task can move to an idle CPU. To
/// a busy CPU, a task moves only if the loads after the move are not further apart and the load of
/// `src` stays at least the load of `own`, as `detach_tasks` of Linux moves a task only if its
/// load is not more than the imbalance, half the difference. With equal weights, this is a
/// difference of at least two tasks.
pub fn movable(own: &Load, src: &Load, weight: u64) -> bool {
    own.is_idle() || weight.saturating_mul(2) <= src.weight.saturating_sub(own.weight)
}

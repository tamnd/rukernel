//! The scheduler of rukernel.
//!
//! The fair class uses EEVDF, as Linux does since 6.6, per spec/06-scheduler.md section 6.2. Each
//! task has a virtual run time, which grows by the real run time times `NICE_0_WEIGHT / weight`.
//! A task is eligible when its virtual run time is not more than the weighted average of the
//! queue. Of the eligible tasks, the task with the earliest virtual deadline runs next. The
//! deadline is the virtual run time at the start of a slice plus the slice in virtual time. A task
//! that sleeps keeps its lag, the distance from the average, and gets it back when it wakes.
//!
//! Each CPU has its own queue. The queue keeps its tasks in a tree keyed by the deadline, with the
//! minimum virtual run time of each subtree, as Linux does, so that the pick takes O(log n) time.
//! The weights come from `sched_prio_to_weight` of Linux. A task that wakes goes to an idle CPU or
//! to the CPU where it ran last, and the load balancer moves tasks from busy queues to idle CPUs.
//!
//! `Eevdf` and the functions of `balance` are pure, so the tests on the host examine them. `Fair`
//! gives them to rk-frame as the `Scheduler` of the kernel tasks.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod balance;
mod tree;

use tree::Tree;

/// The weight of a task with nice 0.
pub const NICE_0_WEIGHT: u64 = 1024;

/// The base slice of a task in nanoseconds: `sysctl_sched_base_slice` of Linux.
pub const BASE_SLICE: u64 = 3_000_000;

/// The weight of a task with the `SCHED_IDLE` policy. Linux names it `WEIGHT_IDLEPRIO`.
pub const WEIGHT_IDLE: u64 = 3;

/// The weight of each nice value from -20 to 19: `sched_prio_to_weight` of Linux. Each step of
/// nice changes the share of a task by about 10 percent.
pub const WEIGHTS: [u64; 40] = [
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100, 4904,
    3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172, 137, 110, 87,
    70, 56, 45, 36, 29, 23, 18, 15,
];

/// The weight of the nice value `nice`. A value out of the range -20 to 19 counts as the nearest
/// value in the range.
pub fn weight_of(nice: i32) -> u64 {
    WEIGHTS[(nice.clamp(-20, 19) + 20) as usize]
}

/// The scheduling values of a task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entity {
    /// The virtual run time in nanoseconds.
    pub vruntime: u64,
    /// The virtual deadline in nanoseconds.
    pub deadline: u64,
    /// The weight, from the nice value.
    pub weight: u64,
    /// The lag when the task went to sleep: the average virtual run time minus the virtual run
    /// time of the task.
    pub lag: i64,
}

impl Default for Entity {
    fn default() -> Self {
        Self { vruntime: 0, deadline: 0, weight: NICE_0_WEIGHT, lag: 0 }
    }
}

impl Entity {
    /// Converts `ns` of real time to the virtual time of this task.
    fn virt(&self, ns: u64) -> u64 {
        (u128::from(ns) * u128::from(NICE_0_WEIGHT) / u128::from(self.weight.max(1))) as u64
    }

    /// The slice of the task in virtual time.
    fn vslice(&self) -> u64 {
        self.virt(BASE_SLICE)
    }

    /// Adds `ns` of run time to the task. When the task used its slice, it gets a new deadline.
    /// Gives `true` if the task used its slice.
    pub fn charge(&mut self, ns: u64) -> bool {
        self.vruntime = self.vruntime.saturating_add(self.virt(ns));
        if self.vruntime >= self.deadline {
            self.deadline = self.vruntime + self.vslice();
            return true;
        }
        false
    }
}

/// A queue of tasks that EEVDF orders. `T` is the handle of a task.
///
/// The queue keeps the sums of the average, as `avg_vruntime` of Linux does, so the average and
/// the test of eligibility take O(1) time. The tasks are in a tree, so `push` and `pick` take
/// O(log n) time.
#[derive(Debug)]
pub struct Eevdf<T> {
    /// The tasks, keyed by the deadline and the order in which they came into the queue.
    tasks: Tree<T>,
    /// A virtual time that does not go back. It is the base of the average, so that the sums do
    /// not overflow, and it is the average when the queue is empty and no task runs.
    min_vruntime: u64,
    /// The sum of `weight * (vruntime - min_vruntime)` of the queue.
    key: i128,
    /// The sum of the weights of the queue.
    load: i128,
    /// The lowest virtual run time of the queue, or a lower value.
    lowest: Option<u64>,
    /// The order number of the next task that comes into the queue.
    seq: u64,
}

impl<T> Eevdf<T> {
    /// Makes an empty queue.
    pub const fn new() -> Self {
        Self { tasks: Tree::new(), min_vruntime: 0, key: 0, load: 0, lowest: None, seq: 0 }
    }

    /// The number of tasks in the queue.
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Tells if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.tasks.len() == 0
    }

    /// The part of `e` in the sum of the keys.
    fn key_of(&self, e: &Entity) -> i128 {
        i128::from(e.weight) * (i128::from(e.vruntime) - i128::from(self.min_vruntime))
    }

    /// The tasks of the queue and the task `curr` that runs, as the sum of `weight * (vruntime -
    /// min_vruntime)` and the sum of the weights.
    fn sums(&self, curr: Option<&Entity>) -> (i128, i128) {
        match curr {
            Some(c) => (self.key + self.key_of(c), self.load + i128::from(c.weight)),
            None => (self.key, self.load),
        }
    }

    /// The weighted average of the virtual run time of the queue and of `curr`.
    pub fn avg_vruntime(&self, curr: Option<&Entity>) -> u64 {
        let (key, load) = self.sums(curr);
        if load == 0 {
            return self.min_vruntime;
        }
        (i128::from(self.min_vruntime) + key.div_euclid(load)).max(0) as u64
    }

    /// Moves `min_vruntime` forward to `v`, if `v` is larger, and moves the sum of the keys with
    /// it.
    fn advance_min(&mut self, v: u64) {
        if v > self.min_vruntime {
            self.key -= self.load * i128::from(v - self.min_vruntime);
            self.min_vruntime = v;
        }
    }

    /// Moves `min_vruntime` forward to the lowest virtual run time of the queue and of `curr`.
    pub fn update_min(&mut self, curr: Option<&Entity>) {
        let lowest = match (self.lowest, curr.map(|e| e.vruntime)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if let Some(lowest) = lowest {
            self.advance_min(lowest);
        }
    }

    /// Keeps the lag of `e`, a task that goes to sleep, as `update_entity_lag` of Linux. The lag
    /// is at most the slice of the task, or one tick if that is more.
    pub fn save_lag(&self, e: &mut Entity, tick_ns: u64) {
        e.lag = lag_of(e, self.avg_vruntime(None), tick_ns);
    }

    /// Places `e`, a task that wakes or is new, in the virtual time of the queue, as
    /// `place_entity` of Linux. A task that wakes gets back its lag. The lag grows by the weight
    /// of the task over the weight of the queue, so that the average does not move when the task
    /// joins. A new task starts at the average with half a slice to its deadline.
    pub fn place(&self, e: &mut Entity, curr: Option<&Entity>, new: bool) {
        let avg = i128::from(self.avg_vruntime(curr));
        let mut lag = if new { 0 } else { i128::from(e.lag) };
        let (_, load) = self.sums(curr);
        if load > 0 && lag != 0 {
            lag = lag * (load + i128::from(e.weight)) / load;
        }
        e.vruntime = (avg - lag).max(0) as u64;
        let vslice = e.vslice();
        e.deadline = e.vruntime + if new { vslice / 2 } else { vslice };
        e.lag = 0;
    }

    /// Adds a task.
    pub fn push(&mut self, task: T, e: Entity) {
        self.key += self.key_of(&e);
        self.load += i128::from(e.weight);
        self.lowest = Some(self.lowest.map_or(e.vruntime, |l| l.min(e.vruntime)));
        self.tasks.insert(task, e, self.seq);
        self.seq += 1;
    }

    /// Removes the next task to run: the eligible task with the earliest deadline. `curr` is the
    /// task that runs now, which counts in the average. Of two tasks with the same deadline, the
    /// task that came first runs first.
    pub fn pick(&mut self, curr: Option<&Entity>) -> Option<(T, Entity)> {
        let (key, load) = self.sums(curr);
        // A task is eligible if `(vruntime - min_vruntime) * load <= key`, as
        // `vruntime_eligible` of Linux tests. For a load that is not 0, this is the same as a
        // virtual run time that is not more than this limit.
        let limit = (load > 0).then(|| i128::from(self.min_vruntime) + key.div_euclid(load));
        let low = self.tasks.min_vruntime()?;
        // The rounding of the average can leave no task eligible. Then the task with the lowest
        // virtual run time runs.
        let (task, e) = self.tasks.pick(|v| limit.is_none_or(|l| i128::from(v) <= l))?;
        self.remove_sums(&e);
        self.advance_min(low);
        self.lowest = if self.is_empty() { None } else { Some(low) };
        Some((task, e))
    }

    /// Takes the part of `e`, a task that leaves the queue, out of the sums.
    fn remove_sums(&mut self, e: &Entity) {
        self.key -= self.key_of(e);
        self.load -= i128::from(e.weight);
    }

    /// Removes a task for which `ok` gives `true`, so that it moves to the queue of another CPU,
    /// as `detach_tasks` of the Linux load balancer does. Of those tasks, the task with the latest
    /// deadline moves, because it waits longest here. The entity of the task has its lag, against
    /// the average of this queue and of `curr`, so that `place` on the other queue keeps it. This
    /// can take O(n) time.
    pub fn steal(
        &mut self,
        curr: Option<&Entity>,
        tick_ns: u64,
        mut ok: impl FnMut(&T) -> bool,
    ) -> Option<(T, Entity)> {
        // The task is in the queue, so the average counts it, as `update_entity_lag` of Linux.
        let avg = self.avg_vruntime(curr);
        let (task, mut e) = self.tasks.remove_last(|t, _| ok(t))?;
        self.remove_sums(&e);
        if self.is_empty() {
            self.lowest = None;
        }
        e.lag = lag_of(&e, avg, tick_ns);
        Some((task, e))
    }

    /// Checks the tree of the queue, for the tests. Gives its height.
    #[cfg(test)]
    fn check(&self) -> u8 {
        self.tasks.check()
    }
}

/// The lag of `e` against the average `avg`, as `update_entity_lag` of Linux computes it. The lag
/// is at most the slice of the task, or one tick if that is more.
fn lag_of(e: &Entity, avg: u64, tick_ns: u64) -> i64 {
    let limit = i128::from(e.virt(BASE_SLICE.max(tick_ns)));
    let lag = i128::from(avg) - i128::from(e.vruntime);
    lag.clamp(-limit, limit) as i64
}

impl<T> Default for Eevdf<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod glue {
    use super::balance::{self, BALANCE_INTERVAL, Load};
    use super::{Eevdf, Entity, WEIGHT_IDLE, weight_of};
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::any::Any;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use rk_frame::cpu::{self, MAX_CPUS};
    use rk_frame::sync::SpinLock;
    use rk_frame::task::{Enqueue, Scheduler, Task};

    /// The time of one timer tick in nanoseconds.
    const TICK_NS: u64 = 1_000_000_000 / rk_frame::time::HZ;

    /// The values of the fair class for one task.
    struct TaskData {
        entity: SpinLock<Entity>,
        /// The time in nanoseconds when the task came on the CPU, or when it was last charged.
        exec_start: SpinLock<u64>,
        /// The CPU of the queue of the task, or the CPU where the task ran last.
        cpu: AtomicUsize,
        /// The CPUs that the task can use, one bit for each CPU.
        affinity: AtomicU64,
    }

    fn data(task: &Task) -> &TaskData {
        task.sched_data().downcast_ref::<TaskData>().expect("the data of the fair class")
    }

    /// Adds the run time since the last charge to `task`. Gives `true` if the task used its
    /// slice, and the entity after the charge.
    fn charge(task: &Task) -> (bool, Entity) {
        let now = rk_frame::time::nanos();
        let d = data(task);
        let mut start = d.exec_start.lock();
        let ran = now.saturating_sub(*start);
        *start = now;
        let mut e = d.entity.lock();
        (e.charge(ran), *e)
    }

    /// The run queue of one CPU.
    struct Rq {
        queue: Eevdf<Arc<Task>>,
        /// The number and the entity of the task that runs on the CPU. The entity is a copy from
        /// the last charge, as `curr` of Linux is current from the last `update_curr`.
        curr: Option<(u64, Entity)>,
        /// The time of the next periodic balance, in nanoseconds.
        next_balance: u64,
    }

    impl Rq {
        const fn new() -> Self {
            Self { queue: Eevdf::new(), curr: None, next_balance: 0 }
        }

        fn load(&self) -> Load {
            Load { queued: self.queue.len(), running: self.curr.is_some() }
        }

        /// The entity of the task that runs, if it is not the task `id`.
        fn curr_except(&self, id: u64) -> Option<Entity> {
            self.curr.filter(|&(c, _)| c != id).map(|(_, e)| e)
        }
    }

    /// The fair class with EEVDF and a run queue for each CPU.
    ///
    /// The kernel lock of rk-frame lets only one CPU at a time run this code. Each method takes
    /// the lock of one queue at a time, so the locks have no order.
    pub struct Fair {
        rqs: [SpinLock<Rq>; MAX_CPUS],
    }

    impl Fair {
        /// Makes a scheduler with empty queues.
        pub const fn new() -> Self {
            Self { rqs: [const { SpinLock::new(Rq::new()) }; MAX_CPUS] }
        }

        /// The number of CPUs that run.
        fn cpus() -> usize {
            cpu::count().clamp(1, MAX_CPUS)
        }

        /// The number of tasks that wait to run, on all CPUs.
        pub fn len(&self) -> usize {
            self.rqs[..Self::cpus()].iter().map(|rq| rq.lock().queue.len()).sum()
        }

        /// Tells if no task waits to run.
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }

        /// The loads of the CPUs. The first `cpus()` entries count.
        fn loads(&self) -> [Load; MAX_CPUS] {
            let mut loads = [Load::default(); MAX_CPUS];
            for (load, rq) in loads.iter_mut().zip(&self.rqs[..Self::cpus()]) {
                *load = rq.lock().load();
            }
            loads
        }

        /// Chooses the CPU for `task`, as `balance::select_cpu`.
        fn select(&self, task: &Task, prev: usize, new: bool) -> usize {
            let loads = self.loads();
            let allowed = data(task).affinity.load(Ordering::Relaxed);
            balance::select_cpu(prev, cpu::id(), allowed, &loads[..Self::cpus()], new)
        }

        /// Adds `task` with the entity `e` to the queue of `cpu`. If `place` is `Some(new)`, the
        /// task is first placed in the virtual time of the queue.
        fn push(&self, cpu: usize, task: Arc<Task>, mut e: Entity, place: Option<bool>) {
            data(&task).cpu.store(cpu, Ordering::Relaxed);
            let mut rq = self.rqs[cpu].lock();
            if let Some(new) = place {
                let curr = rq.curr_except(task.id());
                rq.queue.place(&mut e, curr.as_ref(), new);
            }
            rq.queue.push(task, e);
        }

        /// Removes a task for which `ok` gives `true` from the queue of `cpu`. The entity has
        /// the lag of the task.
        fn steal(
            &self,
            cpu: usize,
            ok: impl FnMut(&Arc<Task>) -> bool,
        ) -> Option<(Arc<Task>, Entity)> {
            let mut rq = self.rqs[cpu].lock();
            let curr = rq.curr.map(|(_, e)| e);
            rq.queue.steal(curr.as_ref(), TICK_NS, ok)
        }

        /// Pulls one task to the queue of `this` from the busiest queue that has a task that can
        /// run on `this`, as `sched_balance_rq` of Linux. Gives `true` if a task moved.
        fn balance(&self, this: usize) -> bool {
            let loads = self.loads();
            let mut skip = 0;
            while let Some(src) = balance::busiest(this, &loads[..Self::cpus()], skip) {
                let ok =
                    |t: &Arc<Task>| balance::allows(data(t).affinity.load(Ordering::Relaxed), this);
                if let Some((task, e)) = self.steal(src, ok) {
                    self.push(this, task, e, Some(false));
                    return true;
                }
                skip |= 1 << src;
            }
            false
        }
    }

    impl Default for Fair {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Scheduler for Fair {
        fn new_data(&self) -> Box<dyn Any + Send + Sync> {
            Box::new(TaskData {
                entity: SpinLock::new(Entity::default()),
                exec_start: SpinLock::new(0),
                cpu: AtomicUsize::new(cpu::id()),
                affinity: AtomicU64::new(u64::MAX),
            })
        }

        fn enqueue(&self, task: Arc<Task>, why: Enqueue) -> usize {
            let this = cpu::id();
            let d = data(&task);
            let mut e = *d.entity.lock();
            if why == Enqueue::Yield {
                if balance::allows(d.affinity.load(Ordering::Relaxed), this) {
                    self.push(this, task, e, None);
                    return this;
                }
                // The affinity mask does not allow this CPU any more, so the task moves. It keeps
                // its lag against the queue of this CPU.
                self.rqs[this].lock().queue.save_lag(&mut e, TICK_NS);
            }
            let cpu = self.select(&task, d.cpu.load(Ordering::Relaxed), why == Enqueue::New);
            // A task that wakes has the lag of its sleep, from `put_prev` on the CPU where it ran.
            self.push(cpu, task, e, Some(why == Enqueue::New));
            cpu
        }

        fn dequeue(&self) -> Option<Arc<Task>> {
            let this = cpu::id();
            let curr = Task::current();
            let running = !curr.is_idle() && !curr.is_blocked() && !curr.is_exited();
            let curr = running.then(|| *data(&curr).entity.lock());
            let empty = {
                let mut rq = self.rqs[this].lock();
                rq.curr = None;
                rq.queue.is_empty()
            };
            // The CPU becomes idle, so it pulls a task from the busiest queue, as
            // `sched_balance_newidle` of Linux.
            if empty {
                self.balance(this);
            }
            let (task, e) = self.rqs[this].lock().queue.pick(curr.as_ref())?;
            let mut entity = data(&task).entity.lock();
            // `set_nice` can change the weight while the task is in the queue.
            *entity = Entity { weight: entity.weight, ..e };
            drop(entity);
            Some(task)
        }

        fn put_prev(&self, task: &Task, sleeping: bool) {
            charge(task);
            let mut e = data(task).entity.lock();
            let mut rq = self.rqs[cpu::id()].lock();
            rq.queue.update_min(Some(&e));
            if sleeping {
                rq.queue.save_lag(&mut e, TICK_NS);
            }
            rq.curr = None;
        }

        fn set_next(&self, task: &Task) {
            let this = cpu::id();
            let d = data(task);
            *d.exec_start.lock() = rk_frame::time::nanos();
            d.cpu.store(this, Ordering::Relaxed);
            let e = *d.entity.lock();
            self.rqs[this].lock().curr = Some((task.id(), e));
        }

        fn should_yield(&self, task: &Task, _ran: u64) -> bool {
            let this = cpu::id();
            let (used, e) = charge(task);
            let now = rk_frame::time::nanos();
            let due = {
                let mut rq = self.rqs[this].lock();
                rq.curr = Some((task.id(), e));
                let due = now >= rq.next_balance;
                if due {
                    rq.next_balance = now + BALANCE_INTERVAL;
                }
                due
            };
            // The periodic balance on the tick, as `sched_balance_trigger` of Linux.
            if due {
                self.balance(this);
            }
            // A task that its affinity mask does not allow on this CPU gives the CPU, and
            // `enqueue` moves it to a CPU of the mask.
            if !balance::allows(data(task).affinity.load(Ordering::Relaxed), this) {
                return true;
            }
            used && !self.rqs[this].lock().queue.is_empty()
        }

        fn set_nice(&self, task: &Task, nice: i32, idle: bool) {
            data(task).entity.lock().weight = if idle { WEIGHT_IDLE } else { weight_of(nice) };
        }

        fn set_affinity(&self, task: &Task, mask: u64) -> Option<usize> {
            let d = data(task);
            d.affinity.store(mask, Ordering::Relaxed);
            let cpu = d.cpu.load(Ordering::Relaxed);
            if balance::allows(mask, cpu) {
                return None;
            }
            // A task in the queue of a CPU that the mask does not allow moves now. A task that
            // runs moves at its next `should_yield`.
            let (t, e) = self.steal(cpu, |t| t.id() == task.id())?;
            let to = self.select(task, cpu, false);
            self.push(to, t, e, Some(false));
            Some(to)
        }
    }

    static SCHEDULER: Fair = Fair::new();

    /// Gives the fair class to rk-frame. The kernel calls this one time at boot.
    pub fn init() {
        rk_frame::task::inject_scheduler(&SCHEDULER);
    }
}

#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub use glue::{Fair, init};

#[cfg(test)]
mod tests;

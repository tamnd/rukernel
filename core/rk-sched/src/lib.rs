//! The scheduler of rukernel.
//!
//! The fair class uses EEVDF, as Linux does since 6.6, per spec/06-scheduler.md section 6.2. Each
//! task has a virtual run time, which grows by the real run time times `NICE_0_WEIGHT / weight`.
//! A task is eligible when its virtual run time is not more than the weighted average of the
//! queue. Of the eligible tasks, the task with the earliest virtual deadline runs next. The
//! deadline is the virtual run time at the start of a slice plus the slice in virtual time. A task
//! that sleeps keeps its lag, the distance from the average, and gets it back when it wakes.
//!
//! This first version keeps one queue for all CPUs and finds the next task with a scan of the
//! queue. Linux uses a tree with the minimum virtual run time of each subtree, so that the pick
//! takes O(log n) time. The weights come from `sched_prio_to_weight` of Linux.
//!
//! `Eevdf` is a pure type, so the tests on the host examine it. `Fair` gives it to rk-frame as the
//! `Scheduler` of the kernel tasks.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

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
/// the test of eligibility take O(1) time. Only `pick` scans the queue.
#[derive(Debug)]
pub struct Eevdf<T> {
    /// The tasks, with the order in which they came into the queue.
    tasks: Vec<(T, Entity, u64)>,
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
        Self { tasks: Vec::new(), min_vruntime: 0, key: 0, load: 0, lowest: None, seq: 0 }
    }

    /// The number of tasks in the queue.
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Tells if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
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
        let limit = i128::from(e.virt(BASE_SLICE.max(tick_ns)));
        let lag = i128::from(self.avg_vruntime(None)) - i128::from(e.vruntime);
        e.lag = lag.clamp(-limit, limit) as i64;
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
        self.tasks.push((task, e, self.seq));
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
        let mut best: Option<usize> = None;
        let mut lowest: Option<usize> = None;
        for (i, (_, e, seq)) in self.tasks.iter().enumerate() {
            let order = |j: usize| self.tasks[j].2;
            if lowest.is_none_or(|l| (e.vruntime, *seq) < (self.tasks[l].1.vruntime, order(l))) {
                lowest = Some(i);
            }
            if limit.is_some_and(|l| i128::from(e.vruntime) > l) {
                continue;
            }
            if best.is_none_or(|b| (e.deadline, *seq) < (self.tasks[b].1.deadline, order(b))) {
                best = Some(i);
            }
        }
        // The rounding of the average can leave no task eligible. Then the task with the lowest
        // virtual run time runs.
        let best = best.or(lowest)?;
        let low = self.tasks[lowest?].1.vruntime;
        let (task, e, _) = self.tasks.swap_remove(best);
        self.key -= self.key_of(&e);
        self.load -= i128::from(e.weight);
        self.advance_min(low);
        self.lowest = if self.tasks.is_empty() { None } else { Some(low) };
        Some((task, e))
    }
}

impl<T> Default for Eevdf<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod glue {
    use super::{Eevdf, Entity, WEIGHT_IDLE, weight_of};
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::any::Any;
    use rk_frame::sync::SpinLock;
    use rk_frame::task::{Enqueue, Scheduler, Task};

    /// The values of the fair class for one task.
    struct TaskData {
        entity: SpinLock<Entity>,
        /// The time in nanoseconds when the task came on the CPU, or when it was last charged.
        exec_start: SpinLock<u64>,
    }

    fn data(task: &Task) -> &TaskData {
        task.sched_data().downcast_ref::<TaskData>().expect("the data of the fair class")
    }

    /// Adds the run time since the last charge to `task`. Gives `true` if the task used its
    /// slice.
    fn charge(task: &Task) -> bool {
        let now = rk_frame::time::nanos();
        let d = data(task);
        let mut start = d.exec_start.lock();
        let ran = now.saturating_sub(*start);
        *start = now;
        d.entity.lock().charge(ran)
    }

    /// The entity of the task on this CPU, if it runs and is not `task`.
    fn current_entity(task: &Task) -> Option<Entity> {
        let curr = Task::current();
        (curr.id() != task.id() && !curr.is_idle() && !curr.is_blocked() && !curr.is_exited())
            .then(|| *data(&curr).entity.lock())
    }

    /// The fair class with EEVDF.
    pub struct Fair {
        queue: SpinLock<Eevdf<Arc<Task>>>,
    }

    impl Fair {
        /// Makes a scheduler with an empty queue.
        pub const fn new() -> Self {
            Self { queue: SpinLock::new(Eevdf::new()) }
        }

        /// The number of tasks that wait to run.
        pub fn len(&self) -> usize {
            self.queue.lock().len()
        }

        /// Tells if no task waits to run.
        pub fn is_empty(&self) -> bool {
            self.queue.lock().is_empty()
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
            })
        }

        fn enqueue(&self, task: Arc<Task>, why: Enqueue) {
            let curr = if why == Enqueue::Yield { None } else { current_entity(&task) };
            let mut e = *data(&task).entity.lock();
            let mut queue = self.queue.lock();
            if why != Enqueue::Yield {
                queue.place(&mut e, curr.as_ref(), why == Enqueue::New);
            }
            queue.push(task, e);
        }

        fn dequeue(&self) -> Option<Arc<Task>> {
            let curr = Task::current();
            let running = !curr.is_idle() && !curr.is_blocked() && !curr.is_exited();
            let curr = running.then(|| *data(&curr).entity.lock());
            let (task, e) = self.queue.lock().pick(curr.as_ref())?;
            let mut entity = data(&task).entity.lock();
            // `set_nice` can change the weight while the task is in the queue.
            *entity = Entity { weight: entity.weight, ..e };
            drop(entity);
            Some(task)
        }

        fn put_prev(&self, task: &Task, sleeping: bool) {
            charge(task);
            let mut e = data(task).entity.lock();
            let mut queue = self.queue.lock();
            queue.update_min(Some(&e));
            if sleeping {
                queue.save_lag(&mut e, 1_000_000_000 / rk_frame::time::HZ);
            }
        }

        fn set_next(&self, task: &Task) {
            *data(task).exec_start.lock() = rk_frame::time::nanos();
        }

        fn should_yield(&self, task: &Task, _ran: u64) -> bool {
            charge(task) && !self.queue.lock().is_empty()
        }

        fn set_nice(&self, task: &Task, nice: i32, idle: bool) {
            data(task).entity.lock().weight = if idle { WEIGHT_IDLE } else { weight_of(nice) };
        }
    }

    static SCHEDULER: Fair = Fair::new();

    /// Gives the fair class to rk-frame. The kernel calls this one time at boot.
    pub fn init() {
        rk_frame::task::inject_scheduler(&SCHEDULER);
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub use glue::{Fair, init};

#[cfg(test)]
mod tests;

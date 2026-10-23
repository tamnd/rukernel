//! The scheduler of rukernel.
//!
//! In R1 the scheduler is a round robin queue on one CPU, per spec/22-milestones.md. Each task
//! that can run is in the queue one time, and the task at the front runs next. A task that yields
//! goes to the back. EEVDF and SMP come in R2, per spec/06-scheduler.md.
//!
//! The queue is a pure type, so the tests on the host examine it. `RoundRobin` gives it to rk-frame
//! as the `Scheduler` of the kernel tasks.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::VecDeque;

/// A first in, first out queue of tasks.
#[derive(Debug)]
pub struct RunQueue<T> {
    tasks: VecDeque<T>,
}

impl<T> RunQueue<T> {
    /// Makes an empty queue.
    pub const fn new() -> Self {
        Self { tasks: VecDeque::new() }
    }

    /// Adds a task at the back.
    pub fn push(&mut self, task: T) {
        self.tasks.push_back(task);
    }

    /// Removes the task at the front.
    pub fn pop(&mut self) -> Option<T> {
        self.tasks.pop_front()
    }

    /// The number of tasks in the queue.
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Tells if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
}

impl<T> Default for RunQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod glue {
    use super::RunQueue;
    use alloc::sync::Arc;
    use rk_frame::sync::SpinLock;
    use rk_frame::task::{Scheduler, Task};

    /// The round robin scheduler of the kernel tasks.
    pub struct RoundRobin {
        queue: SpinLock<RunQueue<Arc<Task>>>,
    }

    impl RoundRobin {
        /// Makes a scheduler with an empty queue.
        pub const fn new() -> Self {
            Self { queue: SpinLock::new(RunQueue::new()) }
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

    impl Default for RoundRobin {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Scheduler for RoundRobin {
        fn enqueue(&self, task: Arc<Task>) {
            self.queue.lock().push(task);
        }

        fn dequeue(&self) -> Option<Arc<Task>> {
            self.queue.lock().pop()
        }
    }

    static SCHEDULER: RoundRobin = RoundRobin::new();

    /// Gives the round robin scheduler to rk-frame. The kernel calls this one time at boot.
    pub fn init() {
        rk_frame::task::inject_scheduler(&SCHEDULER);
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub use glue::{RoundRobin, init};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tasks_run_in_turn() {
        let mut q = RunQueue::new();
        q.push(1);
        q.push(2);
        q.push(3);
        assert_eq!(q.pop(), Some(1));
        q.push(1);
        assert_eq!(q.len(), 3);
        assert_eq!([q.pop(), q.pop(), q.pop(), q.pop()], [Some(2), Some(3), Some(1), None]);
        assert!(q.is_empty());
    }
}

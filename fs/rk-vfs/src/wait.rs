//! The waits of the file operations.
//!
//! A read of a pipe or a terminal waits until data comes, and a signal can stop the wait. Each
//! file has its own queue. `poll`, `select` and `epoll_wait` put the task in the queue of each file
//! that they test, with a `PollTable`, as `poll_wait` of Linux does. So a new event of a file wakes
//! only the tasks that wait for that file. A file that adds no queue has no events that change, as
//! a regular file. A wait with no queue stops only at its deadline or at a signal, because a signal
//! wakes the task directly. The process layer gives the check of the signals with
//! `set_interrupt_check`. The queue blocks the task on the kernel of x86-64. On the other targets
//! of R1 and on the host there are no tasks, so the queue tests the condition again in a loop.

use crate::inode::Result;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

/// A queue of tasks that wait for a change of a file.
pub struct WaitQueue {
    #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
    inner: rk_frame::task::WaitQueue,
}

impl WaitQueue {
    /// Makes an empty queue.
    pub const fn new() -> Self {
        Self {
            #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
            inner: rk_frame::task::WaitQueue::new(),
        }
    }

    /// Blocks the current task until `cond` gives a value, and gives the value.
    pub fn wait_until<R>(&self, cond: impl FnMut() -> Option<R>) -> R {
        #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            self.inner.wait_until(cond)
        }
        #[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
        {
            let mut cond = cond;
            loop {
                if let Some(value) = cond() {
                    return value;
                }
                core::hint::spin_loop();
            }
        }
    }

    /// Blocks the current task until `cond` gives a value or the tick count is at `deadline`.
    /// Gives `None` at the deadline. On the host there is no clock, so `cond` is tested one time.
    pub fn wait_until_timeout<R>(
        &self,
        deadline: u64,
        cond: impl FnMut() -> Option<R>,
    ) -> Option<R> {
        #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            self.inner.wait_until_timeout(deadline, cond)
        }
        #[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
        {
            let _ = deadline;
            let mut cond = cond;
            cond()
        }
    }

    /// Blocks the current task until `cond` gives a value, or a signal comes. Gives
    /// `ERESTARTSYS` for a signal, so that the system call layer can start the call again.
    ///
    /// # Errors
    ///
    /// Gives the error of `cond`, or `ERESTARTSYS`.
    pub fn wait_interruptible<R>(&self, mut cond: impl FnMut() -> Result<Option<R>>) -> Result<R> {
        self.wait_until(|| match cond() {
            Ok(Some(value)) => Some(Ok(value)),
            Err(e) => Some(Err(e)),
            Ok(None) if interrupted() => Some(Err(Errno::ERESTARTSYS)),
            Ok(None) => None,
        })
    }

    /// Wakes each task that waits.
    pub fn wake_all(&self) {
        #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
        self.inner.wake_all();
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// The queues that a wait of `poll`, `select` or `epoll_wait` blocks in, as `poll_table` of Linux.
/// The `poll_wait` operation of each file adds the queues that its events wake.
#[derive(Default)]
pub struct PollTable {
    queues: Vec<QueueRef>,
}

/// A queue in a `PollTable`. The table holds the queue of a file, so the queue lives while the
/// task is in it, also if the file closes.
enum QueueRef {
    Shared(Arc<WaitQueue>),
    Static(&'static WaitQueue),
}

impl QueueRef {
    fn get(&self) -> &WaitQueue {
        match self {
            Self::Shared(q) => q,
            Self::Static(q) => q,
        }
    }
}

impl PollTable {
    /// Makes an empty table.
    pub const fn new() -> Self {
        Self { queues: Vec::new() }
    }

    fn push(&mut self, queue: &WaitQueue, make: impl FnOnce() -> QueueRef) {
        if !self.queues.iter().any(|q| core::ptr::eq(q.get(), queue)) {
            self.queues.push(make());
        }
    }

    /// Adds a queue of a file. A queue that the table has already is not added again.
    pub fn add(&mut self, queue: &Arc<WaitQueue>) {
        self.push(queue, || QueueRef::Shared(queue.clone()));
    }

    /// Adds a queue that lives for each time, as the queue of a device.
    pub fn add_static(&mut self, queue: &'static WaitQueue) {
        self.push(queue, || QueueRef::Static(queue));
    }

    /// The number of queues in the table.
    pub fn len(&self) -> usize {
        self.queues.len()
    }

    /// Tells if the table has no queue.
    pub fn is_empty(&self) -> bool {
        self.queues.is_empty()
    }
}

/// Blocks the current task until `scan` gives a value, or the tick count is at `deadline`, and
/// gives the value. Gives `None` at the deadline. A deadline of `u64::MAX` is no deadline.
///
/// `scan` tests the files. When it gets a table, it adds the queues of each file that it tests.
/// The task blocks in each queue of the table, so a new event of one of the files wakes it, as
/// `do_poll` of Linux. With an empty table, only the deadline or a signal wakes the task. On the
/// host there is no clock, so `scan` is tested one time.
pub fn poll_wait_until<R>(
    deadline: u64,
    mut scan: impl FnMut(Option<&mut PollTable>) -> Option<R>,
) -> Option<R> {
    #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
    loop {
        let mut table = PollTable::new();
        if let Some(value) = scan(Some(&mut table)) {
            return Some(value);
        }
        if rk_frame::time::ticks() >= deadline {
            return None;
        }
        let queues: Vec<&rk_frame::task::WaitQueue> =
            table.queues.iter().map(|q| &q.get().inner).collect();
        if let Some(value) = rk_frame::task::wait_any(&queues, deadline, || scan(None)) {
            return Some(value);
        }
    }
    #[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
    {
        let _ = deadline;
        scan(None)
    }
}

/// The check of the process layer: it tells if a signal must stop the wait of the current task.
static INTERRUPTED: SpinLock<Option<fn() -> bool>> = SpinLock::new(None);

/// Sets the function that tells if a signal must stop the wait of the current task.
pub fn set_interrupt_check(f: fn() -> bool) {
    *INTERRUPTED.lock() = Some(f);
}

/// Tells if a signal must stop the wait of the current task.
pub fn interrupted() -> bool {
    let check = *INTERRUPTED.lock();
    check.is_some_and(|f| f())
}

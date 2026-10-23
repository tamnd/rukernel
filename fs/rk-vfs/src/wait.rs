//! The waits of the file operations.
//!
//! A read of a pipe or a terminal waits until data comes, and a signal can stop the wait. The
//! process layer gives the check of the signals with `set_interrupt_check`. The queue blocks the
//! task on the kernel of x86-64. On the other targets of R1 and on the host there are no tasks, so
//! the queue tests the condition again in a loop.

use crate::inode::Result;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

/// A queue of tasks that wait for a change of a file.
pub struct WaitQueue {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    inner: rk_frame::task::WaitQueue,
}

impl WaitQueue {
    /// Makes an empty queue.
    pub const fn new() -> Self {
        Self {
            #[cfg(all(target_os = "none", target_arch = "x86_64"))]
            inner: rk_frame::task::WaitQueue::new(),
        }
    }

    /// Blocks the current task until `cond` gives a value, and gives the value.
    pub fn wait_until<R>(&self, cond: impl FnMut() -> Option<R>) -> R {
        #[cfg(all(target_os = "none", target_arch = "x86_64"))]
        {
            self.inner.wait_until(cond)
        }
        #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
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
        #[cfg(all(target_os = "none", target_arch = "x86_64"))]
        self.inner.wake_all();
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
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

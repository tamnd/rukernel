//! Event files: `eventfd` and `eventfd2`.
//!
//! An event file holds a 64-bit counter. A write adds to the counter, and a read takes the
//! counter and sets it to 0. With `EFD_SEMAPHORE` a read takes 1. A read of a counter of 0 and
//! a write that makes the counter larger than `u64::MAX - 1` wait. This is the model of
//! fs/eventfd.c of Linux.

use crate::cx::{Cx, SysResult};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::eventfd::{EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE};
use rk_abi::native::open::O_RDWR;
use rk_frame::sync::SpinLock;
use rk_vfs::file::{File, FileOps, events};
use rk_vfs::inode::Result;
use rk_vfs::wait::{PollTable, WaitQueue};

/// The largest value of the counter.
const MAX: u64 = u64::MAX - 1;

/// The operations of an event file.
struct EventFd {
    count: SpinLock<u64>,
    semaphore: bool,
    wait: Arc<WaitQueue>,
    /// The count of the changes of the counter, for an edge triggered epoll entry.
    events: AtomicU64,
}

impl EventFd {
    fn wake(&self) {
        self.events.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
    }
}

impl FileOps for EventFd {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < 8 {
            return Err(Errno::EINVAL);
        }
        let nonblock = file.nonblock();
        let value = self.wait.wait_interruptible(|| {
            let mut count = self.count.lock();
            if *count == 0 {
                return if nonblock { Err(Errno::EAGAIN) } else { Ok(None) };
            }
            let take = if self.semaphore { 1 } else { *count };
            *count -= take;
            Ok(Some(take))
        })?;
        self.wake();
        buf[..8].copy_from_slice(&value.to_ne_bytes());
        Ok(8)
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize> {
        if buf.len() < 8 {
            return Err(Errno::EINVAL);
        }
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&buf[..8]);
        let value = u64::from_ne_bytes(raw);
        if value == u64::MAX {
            return Err(Errno::EINVAL);
        }
        let nonblock = file.flags().nonblock();
        self.wait.wait_interruptible(|| {
            let mut count = self.count.lock();
            if MAX - *count < value {
                return if nonblock { Err(Errno::EAGAIN) } else { Ok(None) };
            }
            *count += value;
            Ok(Some(()))
        })?;
        if value != 0 {
            self.wake();
        }
        Ok(8)
    }

    fn poll_wait(&self, _file: &File, table: &mut PollTable) {
        table.add(&self.wait);
    }

    fn poll(&self, _file: &File) -> u32 {
        let count = *self.count.lock();
        let mut ev = 0;
        if count > 0 {
            ev |= events::POLLIN;
        }
        if count == u64::MAX {
            ev |= events::POLLERR;
        }
        if count < MAX {
            ev |= events::POLLOUT;
        }
        ev
    }

    fn pollable(&self) -> bool {
        true
    }

    fn event_count(&self) -> u64 {
        self.events.load(Ordering::Relaxed)
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

/// Adds 1 to the counter of the event file `file` for the kernel, as `eventfd_signal_mask` in
/// fs/eventfd.c of Linux. The add does not wait: the counter stops at `u64::MAX`, and then a poll
/// gives `POLLERR`. Another file gets a write of 1.
pub(crate) fn signal(file: &File) {
    let Some(efd) = file.ops().as_any().and_then(|a| a.downcast_ref::<EventFd>()) else {
        let _ = file.write(&1u64.to_ne_bytes());
        return;
    };
    {
        let mut count = efd.count.lock();
        if *count < u64::MAX {
            *count += 1;
        }
    }
    efd.wake();
}

pub(crate) fn eventfd2(cx: &Cx<'_>, count: u64, flags: u64) -> SysResult {
    let flags = u32::try_from(flags).map_err(|_| Errno::EINVAL)?;
    if flags & !(EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE) != 0 {
        return Err(Errno::EINVAL);
    }
    let ops = EventFd {
        count: SpinLock::new(u64::from(count as u32)),
        semaphore: flags & EFD_SEMAPHORE != 0,
        wait: Arc::new(WaitQueue::new()),
        events: AtomicU64::new(0),
    };
    let file = File::with_ops(Arc::new(ops), None, O_RDWR | (flags & EFD_NONBLOCK));
    Ok(cx.files()?.lock().insert(file, flags & EFD_CLOEXEC != 0)? as u64)
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn eventfd(cx: &Cx<'_>, count: u64) -> SysResult {
    eventfd2(cx, count, 0)
}

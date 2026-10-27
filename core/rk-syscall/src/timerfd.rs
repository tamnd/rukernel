//! Timer files: `timerfd_create`, `timerfd_settime` and `timerfd_gettime`.
//!
//! A timer file has a timer of rk-proc. When the time of the timer is over, the timer adds the
//! count of intervals that are over to the file. A read takes the count. This is the model of
//! fs/timerfd.c of Linux.

use crate::cx::{Cx, SysResult};
use crate::info::{timespec, timespec_ns};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::open::O_RDWR;
use rk_abi::native::time::{
    CLOCK_BOOTTIME, CLOCK_BOOTTIME_ALARM, CLOCK_MONOTONIC, CLOCK_REALTIME, CLOCK_REALTIME_ALARM,
};
use rk_abi::native::timerfd::{
    TFD_CLOEXEC, TFD_IOC_SET_TICKS, TFD_NONBLOCK, TFD_TIMER_ABSTIME, TFD_TIMER_CANCEL_ON_SET,
};
use rk_abi::native::types::KernelItimerspec;
use rk_frame::sync::SpinLock;
use rk_proc::signal::SigInfo;
use rk_proc::timer::{Clock, Expire, Target, Timer};
use rk_vfs::file::{File, FileOps, UserMemory, events};
use rk_vfs::inode::Result;
use rk_vfs::wait::{WaitQueue, poll_wake};

/// The count of the expirations that no read took yet.
struct Ticks {
    count: SpinLock<u64>,
    wait: WaitQueue,
    /// The count of the expirations, for an edge triggered epoll entry.
    events: AtomicU64,
    /// The timer has an absolute time of `CLOCK_REALTIME` and `TFD_TIMER_CANCEL_ON_SET`.
    might_cancel: AtomicBool,
    /// The real time changed after `timerfd_settime` with `TFD_TIMER_CANCEL_ON_SET`. The next
    /// read gives `ECANCELED`.
    canceled: AtomicBool,
}

/// The timer files that have `TFD_TIMER_CANCEL_ON_SET`.
static CANCEL_LIST: SpinLock<Vec<Weak<Ticks>>> = SpinLock::new(Vec::new());

/// Tells each timer file with `TFD_TIMER_CANCEL_ON_SET` that the real time changed, as
/// `timerfd_clock_was_set` of Linux does. The file becomes readable, and the read gives
/// `ECANCELED`.
pub(crate) fn clock_was_set() {
    let list: Vec<Arc<Ticks>> = {
        let mut list = CANCEL_LIST.lock();
        list.retain(|t| t.strong_count() > 0);
        list.iter().filter_map(Weak::upgrade).collect()
    };
    for ticks in list {
        if ticks.might_cancel.load(Ordering::Relaxed)
            && !ticks.canceled.swap(true, Ordering::Relaxed)
        {
            {
                let mut c = ticks.count.lock();
                *c = c.saturating_add(1);
            }
            ticks.wake();
        }
    }
}

impl Ticks {
    fn wake(&self) {
        self.events.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
        poll_wake();
    }
}

impl Expire for Ticks {
    fn expire(&self, count: u64) {
        {
            let mut c = self.count.lock();
            *c = c.saturating_add(count);
        }
        self.wake();
    }
}

/// The operations of a timer file.
struct TimerFd {
    timer: Arc<Timer>,
    ticks: Arc<Ticks>,
}

impl Drop for TimerFd {
    fn drop(&mut self) {
        self.timer.arm(0, 0);
    }
}

impl FileOps for TimerFd {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < 8 {
            return Err(Errno::EINVAL);
        }
        let nonblock = file.flags().nonblock();
        let value = self.ticks.wait.wait_interruptible(|| {
            let mut count = self.ticks.count.lock();
            if self.ticks.canceled.swap(false, Ordering::Relaxed) {
                *count = 0;
                return Err(Errno::ECANCELED);
            }
            match *count {
                0 if nonblock => Err(Errno::EAGAIN),
                0 => Ok(None),
                n => {
                    *count = 0;
                    Ok(Some(n))
                }
            }
        })?;
        buf[..8].copy_from_slice(&value.to_ne_bytes());
        Ok(8)
    }

    fn ioctl(&self, _file: &File, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        if cmd != TFD_IOC_SET_TICKS {
            return Err(Errno::ENOTTY);
        }
        let mut raw = [0u8; 8];
        mem.read(arg, &mut raw)?;
        let value = u64::from_ne_bytes(raw);
        if value == 0 {
            return Err(Errno::EINVAL);
        }
        *self.ticks.count.lock() = value;
        self.ticks.wake();
        Ok(0)
    }

    fn poll(&self, _file: &File) -> u32 {
        if *self.ticks.count.lock() > 0 { events::POLLIN } else { 0 }
    }

    fn pollable(&self) -> bool {
        true
    }

    fn event_count(&self) -> u64 {
        self.ticks.events.load(Ordering::Relaxed)
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

pub(crate) fn timerfd_create(cx: &Cx<'_>, clock: u64, flags: u64) -> SysResult {
    let flags = u32::try_from(flags).map_err(|_| Errno::EINVAL)?;
    if flags & !(TFD_CLOEXEC | TFD_NONBLOCK) != 0 {
        return Err(Errno::EINVAL);
    }
    // The timer counts the time since boot. A timer of the real time changes an absolute time to
    // the time since boot.
    match clock as u32 {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME | CLOCK_REALTIME_ALARM
        | CLOCK_BOOTTIME_ALARM => {}
        _ => return Err(Errno::EINVAL),
    }
    let ticks = Arc::new(Ticks {
        count: SpinLock::new(0),
        wait: WaitQueue::new(),
        events: AtomicU64::new(0),
        might_cancel: AtomicBool::new(false),
        canceled: AtomicBool::new(false),
    });
    let weak: Weak<dyn Expire> = Arc::downgrade(&ticks) as Weak<dyn Expire>;
    let timer = if matches!(clock as u32, CLOCK_REALTIME | CLOCK_REALTIME_ALARM) {
        Timer::new_realtime(Target::Notify(weak), SigInfo::new(0, 0, 0))
    } else {
        Timer::new(Clock::Boot, Target::Notify(weak), SigInfo::new(0, 0, 0))
    };
    let file =
        File::with_ops(Arc::new(TimerFd { timer, ticks }), None, O_RDWR | (flags & TFD_NONBLOCK));
    Ok(cx.files()?.lock().insert(file, flags & TFD_CLOEXEC != 0)? as u64)
}

/// Gives the timer file `fd`.
fn timer_file(cx: &Cx<'_>, fd: u64) -> core::result::Result<Arc<File>, Errno> {
    let file = cx.file(fd)?;
    if file.ops().as_any().and_then(|a| a.downcast_ref::<TimerFd>()).is_none() {
        return Err(Errno::EINVAL);
    }
    Ok(file)
}

fn ops(file: &File) -> &TimerFd {
    file.ops().as_any().and_then(|a| a.downcast_ref::<TimerFd>()).expect("a timer file")
}

fn itimerspec((value, interval): (u64, u64)) -> KernelItimerspec {
    KernelItimerspec { it_interval: timespec(interval), it_value: timespec(value) }
}

pub(crate) fn timerfd_settime(cx: &Cx<'_>, fd: u64, flags: u64, new: u64, old: u64) -> SysResult {
    let flags = u32::try_from(flags).map_err(|_| Errno::EINVAL)?;
    if flags & !(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET) != 0 {
        return Err(Errno::EINVAL);
    }
    let new: KernelItimerspec = cx.read_val(new)?;
    let value = timespec_ns(&new.it_value)?;
    let interval = timespec_ns(&new.it_interval)?;
    let file = timer_file(cx, fd)?;
    let tfd = ops(&file);
    let expires = if value == 0 {
        0
    } else if flags & TFD_TIMER_ABSTIME != 0 {
        // A time in the past fires the timer at once.
        if tfd.timer.is_realtime() {
            crate::info::boot_ns(CLOCK_REALTIME, value).max(1)
        } else {
            value.max(1)
        }
    } else {
        tfd.timer.now().saturating_add(value)
    };
    let abs = flags & TFD_TIMER_ABSTIME != 0;
    let cancel = abs && flags & TFD_TIMER_CANCEL_ON_SET != 0 && tfd.timer.is_realtime();
    {
        let mut list = CANCEL_LIST.lock();
        list.retain(|t| {
            t.strong_count() > 0 && !core::ptr::eq(t.as_ptr(), Arc::as_ptr(&tfd.ticks))
        });
        if cancel {
            list.push(Arc::downgrade(&tfd.ticks));
        }
    }
    tfd.ticks.might_cancel.store(cancel, Ordering::Relaxed);
    tfd.ticks.canceled.store(false, Ordering::Relaxed);
    *tfd.ticks.count.lock() = 0;
    let prev = tfd.timer.arm_abs(expires, interval, abs);
    cx.write_opt(old, &itimerspec(prev))?;
    Ok(0)
}

pub(crate) fn timerfd_gettime(cx: &Cx<'_>, fd: u64, value: u64) -> SysResult {
    let file = timer_file(cx, fd)?;
    cx.write_val(value, &itimerspec(ops(&file).timer.get()))?;
    Ok(0)
}

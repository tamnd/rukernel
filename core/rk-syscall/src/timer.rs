//! The timer system calls: `alarm`, `setitimer`, `getitimer` and the POSIX timers.
//!
//! rk-proc keeps the timers and fires them. This module reads and checks the arguments, as
//! kernel/time/itimer.c and kernel/time/posix-timers.c of Linux do.

use crate::cx::{Cx, SysResult};
use crate::info::{NSEC_PER_SEC, timespec, timespec_ns};
use alloc::sync::Arc;
use rk_abi::Errno;
use rk_abi::native::signal::SIGALRM;
use rk_abi::native::time::{
    CLOCK_BOOTTIME, CLOCK_BOOTTIME_ALARM, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID,
    CLOCK_REALTIME, CLOCK_REALTIME_ALARM, CLOCK_TAI, CLOCK_THREAD_CPUTIME_ID, ITIMER_PROF,
    ITIMER_REAL, ITIMER_VIRTUAL, TIMER_ABSTIME,
};
use rk_abi::native::types::{KernelItimerspec, KernelOldItimerval, KernelOldTimeval};
use rk_proc::signal::{NSIG, SI_KERNEL, SI_TIMER, SigInfo};
use rk_proc::timer::{Clock, Target, Timer};
use rk_proc::{Pid, Process};
use zerocopy::FromZeros;

/// The `sigev_notify` values from include/uapi/asm-generic/siginfo.h.
const SIGEV_SIGNAL: u32 = 0;
const SIGEV_NONE: u32 = 1;
const SIGEV_THREAD: u32 = 2;
const SIGEV_THREAD_ID: u32 = 4;
/// The size of `struct sigevent`, and the offsets of its fields.
const SIGEVENT_SIZE: usize = 64;
const SIGEV_SIGNO: usize = 8;
const SIGEV_NOTIFY: usize = 12;
const SIGEV_TID: usize = 16;

const NSEC_PER_USEC: u64 = 1000;

/// The signal of each interval timer: `SIGALRM`, `SIGVTALRM` and `SIGPROF`.
const ITIMER_SIGNALS: [u32; 3] =
    [SIGALRM, rk_abi::native::signal::SIGVTALRM, rk_abi::native::signal::SIGPROF];

fn timeval_ns(tv: &KernelOldTimeval) -> Result<u64, Errno> {
    if tv.tv_sec < 0 || !(0..1_000_000).contains(&tv.tv_usec) {
        return Err(Errno::EINVAL);
    }
    Ok((tv.tv_sec as u64)
        .saturating_mul(NSEC_PER_SEC)
        .saturating_add(tv.tv_usec as u64 * NSEC_PER_USEC))
}

pub(crate) fn timeval(ns: u64) -> KernelOldTimeval {
    KernelOldTimeval {
        tv_sec: (ns / NSEC_PER_SEC) as i64,
        tv_usec: (ns % NSEC_PER_SEC).div_ceil(NSEC_PER_USEC) as i64,
    }
}

/// The interval timer `which` of `process`. `ITIMER_VIRTUAL` and `ITIMER_PROF` count the CPU
/// time of the process. The system time is 0, so the two count the same time.
fn itimer(process: &Arc<Process>, which: u64) -> Result<Arc<Timer>, Errno> {
    let which = match which as u32 {
        w @ (ITIMER_REAL | ITIMER_VIRTUAL | ITIMER_PROF) => w as usize,
        _ => return Err(Errno::EINVAL),
    };
    let make = || {
        let info = SigInfo::new(ITIMER_SIGNALS[which], SI_KERNEL, 0);
        let clock = if which == ITIMER_REAL as usize {
            Clock::Boot
        } else {
            Clock::ProcessCpu(Arc::downgrade(process))
        };
        Timer::new(clock, Target::Process(Arc::downgrade(process)), info)
    };
    Ok(process.timers().itimer(which, make))
}

fn itimerval((value, interval): (u64, u64)) -> KernelOldItimerval {
    KernelOldItimerval { it_interval: timeval(interval), it_value: timeval(value) }
}

pub(crate) fn getitimer(cx: &Cx<'_>, which: u64, value: u64) -> SysResult {
    let timer = itimer(cx.process(), which)?;
    cx.write_val(value, &itimerval(timer.get()))?;
    Ok(0)
}

pub(crate) fn setitimer(cx: &Cx<'_>, which: u64, new: u64, old: u64) -> SysResult {
    let timer = itimer(cx.process(), which)?;
    // A null value turns the timer off, as Linux still permits.
    let new = if new == 0 { KernelOldItimerval::new_zeroed() } else { cx.read_val(new)? };
    let value = timeval_ns(&new.it_value)?;
    let interval = timeval_ns(&new.it_interval)?;
    let expires = if value == 0 { 0 } else { timer.now().saturating_add(value) };
    let prev = timer.arm(expires, interval);
    cx.write_opt(old, &itimerval(prev))?;
    Ok(0)
}

pub(crate) fn alarm(cx: &Cx<'_>, seconds: u64) -> SysResult {
    let timer = itimer(cx.process(), u64::from(ITIMER_REAL))?;
    let seconds = seconds & u64::from(u32::MAX);
    let expires = if seconds == 0 { 0 } else { timer.now().saturating_add(seconds * NSEC_PER_SEC) };
    let (left, _) = timer.arm(expires, 0);
    // The rest rounds to the nearest second, and a rest of less than one second gives 1, as
    // `alarm_setitimer` of Linux does.
    let tv = timeval(left);
    let mut rest = tv.tv_sec as u64;
    if (rest == 0 && tv.tv_usec != 0) || tv.tv_usec >= 500_000 {
        rest += 1;
    }
    Ok(rest)
}

pub(crate) fn timer_create(cx: &Cx<'_>, clock: u64, sevp: u64, idp: u64) -> SysResult {
    let process = cx.process();
    let realtime = crate::info::is_realtime(clock as u32);
    let clock = match clock as u32 {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME | CLOCK_TAI => Clock::Boot,
        CLOCK_PROCESS_CPUTIME_ID => Clock::ProcessCpu(Arc::downgrade(process)),
        CLOCK_THREAD_CPUTIME_ID => Clock::ThreadCpu(Arc::downgrade(cx.thread)),
        // The alarm clocks need a real time clock that can wake the machine.
        CLOCK_REALTIME_ALARM | CLOCK_BOOTTIME_ALARM => return Err(Errno::EOPNOTSUPP),
        _ => return Err(Errno::EINVAL),
    };
    let (notify, signo, value, tid) = if sevp == 0 {
        (SIGEV_SIGNAL, SIGALRM, None, 0)
    } else {
        let b = cx.read_bytes(sevp, SIGEVENT_SIZE)?;
        let word = |off: usize| u32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]);
        let mut v = [0u8; 8];
        v.copy_from_slice(&b[0..8]);
        (word(SIGEV_NOTIFY), word(SIGEV_SIGNO), Some(u64::from_ne_bytes(v)), word(SIGEV_TID))
    };
    let target = match notify {
        SIGEV_NONE => Target::None,
        SIGEV_SIGNAL => Target::Process(Arc::downgrade(process)),
        n if n == SIGEV_SIGNAL | SIGEV_THREAD_ID => {
            let thread = rk_proc::find_thread(tid as Pid)
                .filter(|t| Arc::ptr_eq(t.process(), process))
                .ok_or(Errno::EINVAL)?;
            Target::Thread(Arc::downgrade(&thread))
        }
        // The C library makes a thread for `SIGEV_THREAD` and gives `SIGEV_THREAD_ID` to the
        // kernel, so the kernel does not take it.
        SIGEV_THREAD | _ => return Err(Errno::EINVAL),
    };
    if notify != SIGEV_NONE && (signo == 0 || signo > NSIG) {
        return Err(Errno::EINVAL);
    }
    let id = process
        .timers()
        .add(|id| {
            let mut info = SigInfo::new(signo, SI_TIMER, id as u32);
            info.value = value.unwrap_or(id as u64);
            if realtime {
                Timer::new_realtime(target, info)
            } else {
                Timer::new(clock, target, info)
            }
        })
        .ok_or(Errno::EAGAIN)?;
    if let Err(e) = cx.write_val(idp, &id) {
        process.timers().remove(id);
        return Err(e);
    }
    Ok(0)
}

fn posix_timer(cx: &Cx<'_>, id: u64) -> Result<Arc<Timer>, Errno> {
    let id = i32::try_from(id as i64).map_err(|_| Errno::EINVAL)?;
    cx.process().timers().get(id).ok_or(Errno::EINVAL)
}

fn itimerspec((value, interval): (u64, u64)) -> KernelItimerspec {
    KernelItimerspec { it_interval: timespec(interval), it_value: timespec(value) }
}

pub(crate) fn timer_settime(cx: &Cx<'_>, id: u64, flags: u64, new: u64, old: u64) -> SysResult {
    let timer = posix_timer(cx, id)?;
    if new == 0 {
        return Err(Errno::EINVAL);
    }
    let new: KernelItimerspec = cx.read_val(new)?;
    let value = timespec_ns(&new.it_value)?;
    let interval = timespec_ns(&new.it_interval)?;
    let now = timer.now();
    let expires = if value == 0 {
        0
    } else if flags as u32 & TIMER_ABSTIME != 0 {
        // A time in the past fires the timer at once.
        if timer.is_realtime() {
            crate::info::boot_ns(CLOCK_REALTIME, value).max(1)
        } else {
            value.max(1)
        }
    } else {
        now.saturating_add(value)
    };
    let prev = timer.arm(expires, interval);
    cx.write_opt(old, &itimerspec(prev))?;
    Ok(0)
}

pub(crate) fn timer_gettime(cx: &Cx<'_>, id: u64, value: u64) -> SysResult {
    let timer = posix_timer(cx, id)?;
    cx.write_val(value, &itimerspec(timer.get()))?;
    Ok(0)
}

pub(crate) fn timer_getoverrun(cx: &Cx<'_>, id: u64) -> SysResult {
    let timer = posix_timer(cx, id)?;
    Ok(timer.overrun() as u64)
}

pub(crate) fn timer_delete(cx: &Cx<'_>, id: u64) -> SysResult {
    let id = i32::try_from(id as i64).map_err(|_| Errno::EINVAL)?;
    if !cx.process().timers().remove(id) {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}

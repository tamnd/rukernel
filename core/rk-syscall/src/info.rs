//! The system calls of time, limits and system information.

use crate::cx::{Cx, SysResult};
use rk_abi::Errno;
use rk_abi::native::random::{GRND_INSECURE, GRND_NONBLOCK, GRND_RANDOM};
use rk_abi::native::syscalls as nr;
use rk_abi::native::time::{
    CLOCK_BOOTTIME, CLOCK_MONOTONIC, CLOCK_MONOTONIC_COARSE, CLOCK_MONOTONIC_RAW,
    CLOCK_PROCESS_CPUTIME_ID, CLOCK_REALTIME, CLOCK_REALTIME_COARSE, CLOCK_TAI,
    CLOCK_THREAD_CPUTIME_ID, TIMER_ABSTIME,
};
use rk_abi::native::types::{
    KernelOldTimeval, KernelTimespec, NewUtsname, Rlimit64, Rusage, Sysinfo,
};
use rk_frame::time::{HZ, ticks};
use rk_proc::Restart;
use rk_proc::exec::USER_HZ;
use rk_proc::limits::{Limit, NR_OPEN, RLIM_NLIMITS, RLIMIT_NOFILE};
use zerocopy::FromZeros;

pub(crate) const NSEC_PER_SEC: u64 = 1_000_000_000;

/// The most bytes of one `getrandom`. Linux names it `MAX_RW_COUNT`.
const MAX_RANDOM: usize = 0x7fff_f000;

/// The nanoseconds since boot, from the timer tick.
pub(crate) fn uptime_ns() -> u64 {
    ticks().saturating_mul(NSEC_PER_SEC / HZ)
}

/// The time of `CLOCK_REALTIME`. R1 has no real time clock, so the time starts at the epoch at
/// boot.
pub(crate) fn realtime() -> rk_vfs::inode::Timespec {
    let ns = uptime_ns();
    rk_vfs::inode::Timespec { sec: (ns / NSEC_PER_SEC) as i64, nsec: (ns % NSEC_PER_SEC) as u32 }
}

/// Gives the nanoseconds of a `timespec`. Gives `EINVAL` if a field is out of range.
pub(crate) fn timespec_ns(ts: &KernelTimespec) -> Result<u64, Errno> {
    if ts.tv_sec < 0 || !(0..NSEC_PER_SEC as i64).contains(&ts.tv_nsec) {
        return Err(Errno::EINVAL);
    }
    Ok((ts.tv_sec as u64).saturating_mul(NSEC_PER_SEC).saturating_add(ts.tv_nsec as u64))
}

/// The timer tick when `ns` nanoseconds from now are over.
pub(crate) fn deadline_after(ns: u64) -> u64 {
    uptime_ns().saturating_add(ns).div_ceil(NSEC_PER_SEC / HZ)
}

pub(crate) fn timespec(ns: u64) -> KernelTimespec {
    KernelTimespec { tv_sec: (ns / NSEC_PER_SEC) as i64, tv_nsec: (ns % NSEC_PER_SEC) as i64 }
}

/// Gives the time of `clock` in nanoseconds.
fn clock_ns(clock: u32) -> Result<u64, Errno> {
    match clock {
        CLOCK_REALTIME
        | CLOCK_REALTIME_COARSE
        | CLOCK_TAI
        | CLOCK_MONOTONIC
        | CLOCK_MONOTONIC_RAW
        | CLOCK_MONOTONIC_COARSE
        | CLOCK_BOOTTIME => Ok(uptime_ns()),
        // R1 does not count the CPU time of each thread, so the CPU clocks give the time since
        // boot. The time never goes back, as POSIX tells.
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => Ok(uptime_ns()),
        _ => Err(Errno::EINVAL),
    }
}

pub(crate) fn clock_gettime(cx: &Cx<'_>, clock: u64, tp: u64) -> SysResult {
    let ns = clock_ns(clock as u32)?;
    cx.write_val(tp, &timespec(ns))?;
    Ok(0)
}

pub(crate) fn clock_getres(cx: &Cx<'_>, clock: u64, tp: u64) -> SysResult {
    clock_ns(clock as u32)?;
    cx.write_opt(tp, &timespec(NSEC_PER_SEC / HZ))?;
    Ok(0)
}

pub(crate) fn gettimeofday(cx: &Cx<'_>, tv: u64, tz: u64) -> SysResult {
    let ns = uptime_ns();
    let v = KernelOldTimeval {
        tv_sec: (ns / NSEC_PER_SEC) as i64,
        tv_usec: (ns % NSEC_PER_SEC / 1000) as i64,
    };
    cx.write_opt(tv, &v)?;
    cx.write_opt(tz, &[0i32; 2])?;
    Ok(0)
}

pub(crate) fn time(cx: &Cx<'_>, tloc: u64) -> SysResult {
    let sec = uptime_ns() / NSEC_PER_SEC;
    cx.write_opt(tloc, &sec)?;
    Ok(sec)
}

/// Waits until the tick count is at `deadline`, or a signal comes. Gives `true` if a signal
/// comes first.
fn sleep_until(thread: &rk_proc::Thread, deadline: u64) -> bool {
    let queue = rk_frame::task::WaitQueue::new();
    queue.wait_until_timeout(deadline, || thread.signal_pending().then_some(())).is_some()
}

pub(crate) fn clock_nanosleep(
    cx: &Cx<'_>,
    clock: u64,
    flags: u64,
    req: u64,
    rem: u64,
) -> SysResult {
    let clock = clock as u32;
    if matches!(clock, CLOCK_THREAD_CPUTIME_ID) {
        return Err(Errno::EINVAL);
    }
    let now = clock_ns(clock)?;
    let ts: KernelTimespec = cx.read_val(req)?;
    let want = timespec_ns(&ts)?;
    if flags as u32 & TIMER_ABSTIME != 0 {
        // The end does not change, so the call can start again with the same arguments.
        if sleep_until(cx.thread, want.div_ceil(NSEC_PER_SEC / HZ)) {
            return Err(Errno::ERESTARTNOHAND);
        }
        return Ok(0);
    }
    sleep_relative(cx, now.saturating_add(want), rem)
}

/// Sleeps until `end` in nanoseconds since boot, for a relative `clock_nanosleep`. If a signal
/// comes first, it writes the rest of the time to `rem`, and keeps the end for
/// `restart_syscall`, as `hrtimer_nanosleep` of Linux does.
fn sleep_relative(cx: &Cx<'_>, end: u64, rem: u64) -> SysResult {
    if !sleep_until(cx.thread, end.div_ceil(NSEC_PER_SEC / HZ)) {
        return Ok(0);
    }
    cx.write_opt(rem, &timespec(end.saturating_sub(uptime_ns())))?;
    cx.thread.set_restart(Some(Restart { call: nr::CLOCK_NANOSLEEP, args: [end, rem, 0] }));
    Err(Errno::ERESTART_RESTARTBLOCK)
}

/// Continues the call that a signal without a handler or a stop interrupted. If there is no
/// such call, it gives `EINTR`, as `do_no_restart_syscall` of Linux does.
pub(crate) fn restart_syscall(cx: &Cx<'_>) -> SysResult {
    match cx.thread.take_restart() {
        Some(Restart { call, args: [end, rem, _] }) if call == nr::CLOCK_NANOSLEEP => {
            sleep_relative(cx, end, rem)
        }
        _ => Err(Errno::EINTR),
    }
}

fn utsname_field(s: &[u8]) -> [u8; 65] {
    let mut f = [0u8; 65];
    let n = s.len().min(64);
    f[..n].copy_from_slice(&s[..n]);
    f
}

pub(crate) fn uname(cx: &Cx<'_>, buf: u64) -> SysResult {
    let u = NewUtsname {
        sysname: utsname_field(b"Linux"),
        nodename: utsname_field(b"rukernel"),
        release: utsname_field(crate::UNAME_RELEASE.as_bytes()),
        version: utsname_field(crate::UNAME_VERSION.as_bytes()),
        machine: utsname_field(rk_frame::arch::UNAME_MACHINE.as_bytes()),
        domainname: utsname_field(b"(none)"),
    };
    cx.write_val(buf, &u)?;
    Ok(0)
}

pub(crate) fn prlimit64(cx: &Cx<'_>, pid: u64, resource: u64, new: u64, old: u64) -> SysResult {
    let resource =
        usize::try_from(resource).ok().filter(|&r| r < RLIM_NLIMITS).ok_or(Errno::EINVAL)?;
    let process = match pid as i32 {
        0 => cx.thread.process().clone(),
        p => rk_proc::find_process(p as u32).ok_or(Errno::ESRCH)?,
    };
    let new = if new == 0 {
        None
    } else {
        let n: Rlimit64 = cx.read_val(new)?;
        if n.rlim_cur > n.rlim_max {
            return Err(Errno::EINVAL);
        }
        if resource == RLIMIT_NOFILE && n.rlim_max > NR_OPEN {
            return Err(Errno::EPERM);
        }
        Some(Limit { cur: n.rlim_cur, max: n.rlim_max })
    };
    let l = process.limit(resource);
    cx.write_opt(old, &Rlimit64 { rlim_cur: l.cur, rlim_max: l.max })?;
    if let Some(n) = new {
        // Each process runs as root with `CAP_SYS_RESOURCE` in R1, so it can raise the hard limit
        // up to the limits above.
        process.set_limit(resource, n);
    }
    Ok(0)
}

pub(crate) fn getrusage(cx: &Cx<'_>, who: u64, buf: u64) -> SysResult {
    // `RUSAGE_SELF`, `RUSAGE_CHILDREN` and `RUSAGE_THREAD`.
    if !matches!(who as i32, 0 | -1 | 1) {
        return Err(Errno::EINVAL);
    }
    cx.write_val(buf, &Rusage::new_zeroed())?;
    Ok(0)
}

pub(crate) fn times(cx: &Cx<'_>, buf: u64) -> SysResult {
    cx.write_opt(buf, &[0u64; 4])?;
    Ok(ticks() * USER_HZ / HZ)
}

pub(crate) fn sysinfo(cx: &Cx<'_>, buf: u64) -> SysResult {
    let frames = rk_frame::mm::frame_stats();
    let mut s = Sysinfo::new_zeroed();
    s.uptime = (uptime_ns() / NSEC_PER_SEC) as i64;
    s.totalram = frames.total as u64;
    s.freeram = frames.free as u64;
    s.procs = rk_proc::processes().len().min(u16::MAX as usize) as u16;
    s.mem_unit = rk_mm::PAGE_SIZE as u32;
    cx.write_val(buf, &s)?;
    Ok(0)
}

pub(crate) fn getresid(cx: &Cx<'_>, r: u64, e: u64, s: u64) -> SysResult {
    cx.write_val(r, &0u32)?;
    cx.write_val(e, &0u32)?;
    cx.write_val(s, &0u32)?;
    Ok(0)
}

pub(crate) fn getrandom(cx: &Cx<'_>, buf: u64, len: u64, flags: u64) -> SysResult {
    let flags = flags as u32;
    if flags & !(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE) != 0
        || flags & (GRND_RANDOM | GRND_INSECURE) == GRND_RANDOM | GRND_INSECURE
    {
        return Err(Errno::EINVAL);
    }
    let len = (len as usize).min(MAX_RANDOM);
    let mut chunk = [0u8; 256];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(chunk.len());
        rk_drv_mem::get_random_bytes(&mut chunk[..n]);
        if let Err(e) = cx.write_bytes(buf + done as u64, &chunk[..n]) {
            if done == 0 {
                return Err(e);
            }
            break;
        }
        done += n;
    }
    Ok(done as u64)
}

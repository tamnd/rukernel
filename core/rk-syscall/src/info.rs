//! The system calls of time, limits and system information.

use crate::cx::{Cx, SysResult};
use rk_abi::Errno;
use rk_abi::native::random::{GRND_INSECURE, GRND_NONBLOCK, GRND_RANDOM};
use rk_abi::native::time::{
    CLOCK_BOOTTIME, CLOCK_MONOTONIC, CLOCK_MONOTONIC_COARSE, CLOCK_MONOTONIC_RAW,
    CLOCK_PROCESS_CPUTIME_ID, CLOCK_REALTIME, CLOCK_REALTIME_COARSE, CLOCK_TAI,
    CLOCK_THREAD_CPUTIME_ID, TIMER_ABSTIME,
};
use rk_abi::native::types::{
    KernelOldTimeval, KernelTimespec, NewUtsname, Rlimit64, Rusage, Sysinfo,
};
use rk_frame::time::{HZ, ticks};
use rk_proc::exec::USER_HZ;
use zerocopy::FromZeros;

const NSEC_PER_SEC: u64 = 1_000_000_000;

/// The resources of `prlimit64`. Linux has 16.
const RLIM_NLIMITS: u64 = 16;
const RLIMIT_STACK: u64 = 3;
const RLIMIT_NPROC: u64 = 6;
const RLIMIT_NOFILE: u64 = 7;
const RLIM_INFINITY: u64 = u64::MAX;

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

fn timespec(ns: u64) -> KernelTimespec {
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

/// Waits until the tick count is at `deadline`, or the thread must stop. Gives `true` if the
/// thread must stop first.
fn sleep_until(thread: &rk_proc::Thread, deadline: u64) -> bool {
    loop {
        if thread.is_killed() {
            return true;
        }
        if ticks() >= deadline {
            return false;
        }
        rk_frame::task::yield_now();
        if ticks() < deadline {
            // No other task ran or the tick did not come yet. The CPU waits for the next
            // interrupt, which is at most one tick.
            rk_frame::irq::wait();
            rk_frame::irq::disable();
        }
    }
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
    if ts.tv_sec < 0 || !(0..NSEC_PER_SEC as i64).contains(&ts.tv_nsec) {
        return Err(Errno::EINVAL);
    }
    let want = (ts.tv_sec as u64).saturating_mul(NSEC_PER_SEC).saturating_add(ts.tv_nsec as u64);
    let end = if flags as u32 & TIMER_ABSTIME != 0 { want } else { now.saturating_add(want) };
    let tick_ns = NSEC_PER_SEC / HZ;
    let deadline = end.div_ceil(tick_ns);
    if sleep_until(cx.thread, deadline) {
        if flags as u32 & TIMER_ABSTIME == 0 {
            cx.write_opt(rem, &timespec(end.saturating_sub(uptime_ns())))?;
        }
        return Err(Errno::EINTR);
    }
    Ok(0)
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

/// The limit of `resource`. R1 has no limits, so each value is the default of Linux.
fn limit(resource: u64) -> Rlimit64 {
    let (cur, max) = match resource {
        RLIMIT_STACK => (rk_mm::STACK_SIZE as u64, RLIM_INFINITY),
        RLIMIT_NPROC => (u64::from(rk_proc::PID_MAX), u64::from(rk_proc::PID_MAX)),
        RLIMIT_NOFILE => (rk_vfs::fdtable::NR_OPEN_DEFAULT as u64, 4096),
        _ => (RLIM_INFINITY, RLIM_INFINITY),
    };
    Rlimit64 { rlim_cur: cur, rlim_max: max }
}

pub(crate) fn prlimit64(cx: &Cx<'_>, pid: u64, resource: u64, new: u64, old: u64) -> SysResult {
    if resource >= RLIM_NLIMITS {
        return Err(Errno::EINVAL);
    }
    if pid as i32 != 0 && rk_proc::find_process(pid as u32).is_none() {
        return Err(Errno::ESRCH);
    }
    if new != 0 {
        let n: Rlimit64 = cx.read_val(new)?;
        if n.rlim_cur > n.rlim_max {
            return Err(Errno::EINVAL);
        }
    }
    cx.write_opt(old, &limit(resource))?;
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

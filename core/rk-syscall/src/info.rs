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

/// The nanoseconds since boot.
pub(crate) fn uptime_ns() -> u64 {
    rk_frame::time::clock_ns()
}

/// The nanoseconds of `CLOCK_REALTIME`. The real time clock of the machine gives the time at boot.
pub(crate) fn realtime_ns() -> u64 {
    rk_frame::time::realtime_ns()
}

/// Gives `true` if `clock` follows the real time, as `CLOCK_REALTIME` does.
pub(crate) fn is_realtime(clock: u32) -> bool {
    matches!(clock, CLOCK_REALTIME | CLOCK_REALTIME_COARSE | CLOCK_TAI)
}

/// Gives the time since boot of the absolute time `ns` of `clock`. The timers of the kernel use
/// the time since boot.
pub(crate) fn boot_ns(clock: u32, ns: u64) -> u64 {
    if is_realtime(clock) { ns.saturating_sub(rk_frame::time::realtime_offset_ns()) } else { ns }
}

/// The time of `CLOCK_REALTIME`.
pub(crate) fn realtime() -> rk_vfs::inode::Timespec {
    let ns = realtime_ns();
    rk_vfs::inode::Timespec { sec: (ns / NSEC_PER_SEC) as i64, nsec: (ns % NSEC_PER_SEC) as u32 }
}

/// Gives the nanoseconds of a `timespec`. Gives `EINVAL` if a field is out of range.
pub(crate) fn timespec_ns(ts: &KernelTimespec) -> Result<u64, Errno> {
    if ts.tv_sec < 0 || !(0..NSEC_PER_SEC as i64).contains(&ts.tv_nsec) {
        return Err(Errno::EINVAL);
    }
    Ok((ts.tv_sec as u64).saturating_mul(NSEC_PER_SEC).saturating_add(ts.tv_nsec as u64))
}

/// The timer tick when `ns` nanoseconds from now are over. A time of 0 gives the current tick, so
/// a call with no timeout does not wait for the next tick.
pub(crate) fn deadline_after(ns: u64) -> u64 {
    if ns == 0 {
        return ticks();
    }
    uptime_ns().saturating_add(ns).div_ceil(NSEC_PER_SEC / HZ)
}

pub(crate) fn timespec(ns: u64) -> KernelTimespec {
    KernelTimespec { tv_sec: (ns / NSEC_PER_SEC) as i64, tv_nsec: (ns % NSEC_PER_SEC) as i64 }
}

/// The nanoseconds of `ticks` timer ticks.
pub(crate) fn ticks_ns(ticks: u64) -> u64 {
    ticks.saturating_mul(NSEC_PER_SEC / HZ)
}

/// The ticks of `USER_HZ` of `ticks` timer ticks, for `times` and `/proc/PID/stat`.
pub(crate) fn user_hz(ticks: u64) -> u64 {
    ticks * USER_HZ / HZ
}

/// Gives the time of `clock` in nanoseconds, for the calls of `thread`.
fn clock_ns(thread: &rk_proc::Thread, clock: u32) -> Result<u64, Errno> {
    match clock {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE | CLOCK_TAI => Ok(realtime_ns()),
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_MONOTONIC_COARSE | CLOCK_BOOTTIME => {
            Ok(uptime_ns())
        }
        CLOCK_PROCESS_CPUTIME_ID => Ok(ticks_ns(thread.process().user_ticks())),
        CLOCK_THREAD_CPUTIME_ID => Ok(ticks_ns(thread.user_ticks())),
        c if (c as i32) < 0 => cpu_clock_ns(thread, c as i32),
        _ => Err(Errno::EINVAL),
    }
}

/// Gives the time of the CPU clock `clock` of another thread or process, as
/// `clock_getcpuclockid` and `pthread_getcpuclockid` make it. The clock is `!id << 3`, with 4 for
/// a thread clock, and the kind of time in the low 2 bits. The kernel counts only the user time,
/// so each kind gives the same time.
fn cpu_clock_ns(thread: &rk_proc::Thread, clock: i32) -> Result<u64, Errno> {
    const PERTHREAD: i32 = 4;
    const KIND: i32 = 3;
    if clock & KIND == KIND {
        return Err(Errno::EINVAL);
    }
    let id = !(clock >> 3);
    if clock & PERTHREAD != 0 {
        let ticks = match id {
            0 => thread.user_ticks(),
            id => {
                let t = rk_proc::find_thread(id as u32).ok_or(Errno::EINVAL)?;
                // A thread clock is only for the threads of the same process.
                if !alloc::sync::Arc::ptr_eq(t.process(), thread.process()) {
                    return Err(Errno::EINVAL);
                }
                t.user_ticks()
            }
        };
        return Ok(ticks_ns(ticks));
    }
    let process = match id {
        0 => thread.process().clone(),
        id => rk_proc::find_process(id as u32).ok_or(Errno::EINVAL)?,
    };
    Ok(ticks_ns(process.user_ticks()))
}

pub(crate) fn clock_gettime(cx: &Cx<'_>, clock: u64, tp: u64) -> SysResult {
    let ns = clock_ns(cx.thread, clock as u32)?;
    cx.write_val(tp, &timespec(ns))?;
    Ok(0)
}

pub(crate) fn clock_getres(cx: &Cx<'_>, clock: u64, tp: u64) -> SysResult {
    clock_ns(cx.thread, clock as u32)?;
    cx.write_opt(tp, &timespec(NSEC_PER_SEC / HZ))?;
    Ok(0)
}

pub(crate) fn gettimeofday(cx: &Cx<'_>, tv: u64, tz: u64) -> SysResult {
    let ns = realtime_ns();
    let v = KernelOldTimeval {
        tv_sec: (ns / NSEC_PER_SEC) as i64,
        tv_usec: (ns % NSEC_PER_SEC / 1000) as i64,
    };
    cx.write_opt(tv, &v)?;
    cx.write_opt(tz, &[0i32; 2])?;
    Ok(0)
}

pub(crate) fn time(cx: &Cx<'_>, tloc: u64) -> SysResult {
    let sec = realtime_ns() / NSEC_PER_SEC;
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
    // A thread clock cannot wait, as in Linux. rukernel does not wait on the CPU clock of another
    // process yet.
    if matches!(clock, CLOCK_THREAD_CPUTIME_ID) || (clock as i32) < 0 {
        return Err(Errno::EINVAL);
    }
    let now = clock_ns(cx.thread, clock)?;
    let ts: KernelTimespec = cx.read_val(req)?;
    let mut want = timespec_ns(&ts)?;
    if clock == CLOCK_PROCESS_CPUTIME_ID {
        // The timers do not follow the CPU time yet, so the sleep waits for the rest of the
        // time on the clock since boot.
        if flags as u32 & TIMER_ABSTIME != 0 {
            want = want.saturating_sub(now);
        }
        return sleep_relative(cx, uptime_ns().saturating_add(want), rem);
    }
    if flags as u32 & TIMER_ABSTIME != 0 {
        // The end does not change, so the call can start again with the same arguments.
        let end = boot_ns(clock, want);
        if sleep_until(cx.thread, end.div_ceil(NSEC_PER_SEC / HZ)) {
            return Err(Errno::ERESTARTNOHAND);
        }
        return Ok(0);
    }
    sleep_relative(cx, uptime_ns().saturating_add(want), rem)
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
    let ticks = match who as i32 {
        0 => cx.process().user_ticks(),
        -1 => cx.process().child_ticks(),
        1 => cx.thread.user_ticks(),
        _ => return Err(Errno::EINVAL),
    };
    cx.write_val(buf, &rusage(ticks))?;
    Ok(0)
}

/// The `struct rusage` of `ticks` timer ticks of user CPU time. The kernel does not count the
/// other values yet.
pub(crate) fn rusage(ticks: u64) -> Rusage {
    let mut r = Rusage::new_zeroed();
    r.ru_utime = crate::timer::timeval(ticks_ns(ticks));
    r
}

pub(crate) fn times(cx: &Cx<'_>, buf: u64) -> SysResult {
    let process = cx.process();
    // `tms_utime`, `tms_stime`, `tms_cutime` and `tms_cstime`.
    let tms = [user_hz(process.user_ticks()), 0, user_hz(process.child_ticks()), 0];
    cx.write_opt(buf, &tms)?;
    Ok(user_hz(ticks()))
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

/// The versions of the header of `capget` and `capset`. Version 1 has one set of 32 bits, and
/// versions 2 and 3 have two sets.
const LINUX_CAPABILITY_VERSION_1: u32 = 0x1998_0330;
const LINUX_CAPABILITY_VERSION_2: u32 = 0x2007_1026;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// The highest capability of Linux, `CAP_CHECKPOINT_RESTORE`.
const CAP_LAST_CAP: u32 = 40;

/// Reads the header of `capget` and `capset`, and gives the number of 32-bit sets of the
/// version and the process ID. An unknown version writes version 3 into the header, as
/// `cap_validate_magic` of Linux does.
fn cap_header(cx: &Cx<'_>, header: u64) -> Result<(usize, i32), Errno> {
    let [version, pid]: [u32; 2] = cx.read_val(header)?;
    let sets = match version {
        LINUX_CAPABILITY_VERSION_1 => 1,
        LINUX_CAPABILITY_VERSION_2 | LINUX_CAPABILITY_VERSION_3 => 2,
        _ => {
            cx.write_val(header, &LINUX_CAPABILITY_VERSION_3)?;
            return Err(Errno::EINVAL);
        }
    };
    Ok((sets, pid as i32))
}

/// `capget`. rukernel has no credentials: each process runs as root with all the capabilities
/// in its effective and permitted sets, and none in its inheritable set.
pub(crate) fn capget(cx: &Cx<'_>, header: u64, data: u64) -> SysResult {
    let (sets, pid) = match cap_header(cx, header) {
        Err(Errno::EINVAL) if data == 0 => return Ok(0),
        r => r?,
    };
    if data == 0 {
        return Ok(0);
    }
    if pid < 0 {
        return Err(Errno::EINVAL);
    }
    if pid > 0 && rk_proc::find_thread(pid as rk_proc::Pid).is_none() {
        return Err(Errno::ESRCH);
    }
    let all = (1u64 << (CAP_LAST_CAP + 1)) - 1;
    let mut out = [0u32; 6];
    for (i, set) in out.chunks_mut(3).take(sets).enumerate() {
        let bits = (all >> (32 * i)) as u32;
        set.copy_from_slice(&[bits, bits, 0]);
    }
    let bytes: alloc::vec::Vec<u8> = out[..3 * sets].iter().flat_map(|w| w.to_ne_bytes()).collect();
    cx.write_bytes(data, &bytes)?;
    Ok(0)
}

/// `capset`. rukernel has no credentials, so the call only checks its arguments.
pub(crate) fn capset(cx: &Cx<'_>, header: u64, data: u64) -> SysResult {
    let (sets, pid) = cap_header(cx, header)?;
    if pid != 0 && pid as u32 != cx.process().pid() {
        return Err(Errno::EPERM);
    }
    cx.read_bytes(data, 12 * sets)?;
    Ok(0)
}

//! The system calls of time, limits and system information.

use crate::cx::{Cx, SysResult};
use alloc::sync::Arc;
use alloc::vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::random::{GRND_INSECURE, GRND_NONBLOCK, GRND_RANDOM};
use rk_abi::native::syscalls as nr;
use rk_abi::native::time::{
    CLOCK_BOOTTIME, CLOCK_MONOTONIC, CLOCK_MONOTONIC_COARSE, CLOCK_MONOTONIC_RAW,
    CLOCK_PROCESS_CPUTIME_ID, CLOCK_REALTIME, CLOCK_REALTIME_COARSE, CLOCK_TAI,
    CLOCK_THREAD_CPUTIME_ID, TIMER_ABSTIME,
};
use rk_abi::native::types::{
    KernelOldTimeval, KernelTimespec, KernelTimex, NewUtsname, Rlimit64, Rusage, Sysinfo,
};
use rk_frame::sync::SpinLock;
use rk_frame::time::{HZ, ticks};
use rk_proc::Restart;
use rk_proc::exec::USER_HZ;
use rk_proc::limits::{Limit, NR_OPEN, RLIM_NLIMITS, RLIMIT_NOFILE};
use rk_vfs::cred::cap;
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
    if !is_realtime(clock) {
        return ns;
    }
    // The offset wraps: a clock set to a time before the time since boot makes it less than 0.
    let offset = rk_frame::time::realtime_offset_ns() as i64;
    (i128::from(ns) - i128::from(offset)).clamp(0, i128::from(u64::MAX)) as u64
}

/// The count of the clock sets. A sleep to an absolute time of `CLOCK_REALTIME` waits until it
/// changes, and then computes its end again.
static CLOCK_SETS: AtomicU64 = AtomicU64::new(0);
/// The threads that sleep to an absolute time of `CLOCK_REALTIME`.
static CLOCK_SET_WAIT: rk_frame::task::WaitQueue = rk_frame::task::WaitQueue::new();
/// The time zone of `settimeofday`: the minutes west of Greenwich in the high half and the type
/// of the daylight saving time in the low half.
static TIMEZONE: AtomicU64 = AtomicU64::new(0);
/// The largest second of a clock set, `TIME_SETTOD_SEC_MAX`: `KTIME_SEC_MAX` less 30 years of
/// time since boot.
const SETTOD_SEC_MAX: i64 = i64::MAX / NSEC_PER_SEC as i64 - 30 * 365 * 86400;

/// Sets `CLOCK_REALTIME` to `ns`, as `do_settimeofday64` of Linux does. The absolute timers of the
/// real time move, the timer files with `TFD_TIMER_CANCEL_ON_SET` see the change, and the sleeps
/// to an absolute real time compute their end again.
fn set_realtime(ns: u64) {
    let delta = rk_frame::time::set_realtime_ns(ns) as i64;
    rk_proc::timer::clock_was_set(delta);
    crate::timerfd::clock_was_set();
    CLOCK_SETS.fetch_add(1, Ordering::Release);
    CLOCK_SET_WAIT.wake_all();
}

/// Checks the time of a clock set and the permission of the caller, as `do_sys_settimeofday64` of
/// Linux does, and sets the clock.
fn settime(cx: &Cx<'_>, ts: &KernelTimespec) -> Result<(), Errno> {
    if !(0..SETTOD_SEC_MAX).contains(&ts.tv_sec) || !(0..NSEC_PER_SEC as i64).contains(&ts.tv_nsec)
    {
        return Err(Errno::EINVAL);
    }
    if !cx.process().cred().capable(cap::SYS_TIME) {
        return Err(Errno::EPERM);
    }
    set_realtime(timespec_ns(ts)?);
    Ok(())
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
    let zone = TIMEZONE.load(Ordering::Relaxed);
    cx.write_opt(tz, &[(zone >> 32) as i32, zone as i32])?;
    Ok(0)
}

pub(crate) fn clock_settime(cx: &Cx<'_>, clock: u64, tp: u64) -> SysResult {
    // Only `CLOCK_REALTIME` can be set. A CPU clock of another thread or process gives `EPERM`
    // after its checks, as `posix_cpu_clock_set` does.
    let clock = clock as u32;
    let cpu = (clock as i32) < 0;
    if cpu {
        cpu_clock_ns(cx.thread, clock as i32)?;
    } else if clock != CLOCK_REALTIME {
        return Err(Errno::EINVAL);
    }
    let ts: KernelTimespec = cx.read_val(tp)?;
    if cpu {
        return Err(Errno::EPERM);
    }
    settime(cx, &ts)?;
    Ok(0)
}

pub(crate) fn settimeofday(cx: &Cx<'_>, tv: u64, tz: u64) -> SysResult {
    let ts = if tv == 0 {
        None
    } else {
        let v: KernelOldTimeval = cx.read_val(tv)?;
        if !(0..=1_000_000).contains(&v.tv_usec) {
            return Err(Errno::EINVAL);
        }
        Some(KernelTimespec { tv_sec: v.tv_sec, tv_nsec: v.tv_usec * 1000 })
    };
    let zone = if tz == 0 { None } else { Some(cx.read_val::<[i32; 2]>(tz)?) };
    if let Some(ts) = &ts
        && (!(0..SETTOD_SEC_MAX).contains(&ts.tv_sec) || ts.tv_nsec >= NSEC_PER_SEC as i64)
    {
        return Err(Errno::EINVAL);
    }
    if !cx.process().cred().capable(cap::SYS_TIME) {
        return Err(Errno::EPERM);
    }
    if let Some([west, dst]) = zone {
        if !(-15 * 60..=15 * 60).contains(&west) {
            return Err(Errno::EINVAL);
        }
        TIMEZONE.store((u64::from(west as u32) << 32) | u64::from(dst as u32), Ordering::Relaxed);
    }
    if let Some(ts) = ts {
        settime(cx, &ts)?;
    }
    Ok(0)
}

/// The NTP state of the kernel.
static NTP: SpinLock<rk_proc::ntp::Ntp> = SpinLock::new(rk_proc::ntp::Ntp::new());

/// Does `adjtimex` on the `struct timex` at `buf`, as `do_adjtimex` of Linux does.
fn do_adjtimex(cx: &Cx<'_>, buf: u64) -> SysResult {
    let mut tx: KernelTimex = cx.read_val(buf)?;
    rk_proc::ntp::validate(&tx, cx.process().cred().capable(cap::SYS_TIME))?;
    if let Some(step) = rk_proc::ntp::set_offset_ns(&tx) {
        let now = i128::from(realtime_ns()) + i128::from(step);
        let max = i128::from(SETTOD_SEC_MAX) * i128::from(NSEC_PER_SEC);
        if !(0..max).contains(&now) {
            return Err(Errno::EINVAL);
        }
        set_realtime(now as u64);
    }
    let state = NTP.lock().adjtimex(&mut tx, realtime_ns());
    cx.write_val(buf, &tx)?;
    Ok(state as u64)
}

pub(crate) fn adjtimex(cx: &Cx<'_>, buf: u64) -> SysResult {
    do_adjtimex(cx, buf)
}

pub(crate) fn clock_adjtime(cx: &Cx<'_>, clock: u64, buf: u64) -> SysResult {
    // Only `CLOCK_REALTIME` has an NTP state. The other clocks that exist give `EOPNOTSUPP`.
    match clock as u32 {
        CLOCK_REALTIME => do_adjtimex(cx, buf),
        c if (c as i32) < 0 => {
            cpu_clock_ns(cx.thread, c as i32)?;
            Err(Errno::EOPNOTSUPP)
        }
        c => {
            clock_ns(cx.thread, c)?;
            Err(Errno::EOPNOTSUPP)
        }
    }
}

#[cfg(target_arch = "x86_64")]
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
    // A thread clock cannot wait, as in Linux: `clock_thread` in kernel/time/posix-cpu-timers.c
    // has no `nsleep`, so kernel/time/posix-timers.c gives `EOPNOTSUPP`, and `posix_cpu_nsleep`
    // gives `EINVAL` for the clock ID of a thread. rukernel does not wait on the CPU clock of
    // another process yet.
    if clock == CLOCK_THREAD_CPUTIME_ID {
        return Err(Errno::EOPNOTSUPP);
    }
    if (clock as i32) < 0 {
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
        // The end does not change, so the call can start again with the same arguments. A clock
        // set moves the end of a sleep to a time of the real time, so the sleep computes it
        // again after each clock set.
        loop {
            let sets = CLOCK_SETS.load(Ordering::Acquire);
            let end = boot_ns(clock, want).div_ceil(NSEC_PER_SEC / HZ);
            let woke = CLOCK_SET_WAIT.wait_until_timeout(end, || {
                if cx.thread.signal_pending() {
                    Some(true)
                } else if is_realtime(clock) && CLOCK_SETS.load(Ordering::Acquire) != sets {
                    Some(false)
                } else {
                    None
                }
            });
            match woke {
                Some(true) => return Err(Errno::ERESTARTNOHAND),
                Some(false) => continue,
                None => return Ok(0),
            }
        }
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

/// The `UNAME26` flag of the personality, from include/uapi/linux/personality.h.
const UNAME26: u32 = 0x002_0000;

/// The release that `uname` gives. With `UNAME26`, the release is `2.6.x` with x = 60 + the
/// second number of the version, as `override_release` in kernel/sys.c of Linux.
fn release(personality: u32) -> alloc::vec::Vec<u8> {
    let real = crate::UNAME_RELEASE;
    if personality & UNAME26 == 0 {
        return real.as_bytes().to_vec();
    }
    let mut dots = 0;
    let rest = real
        .find(|c: char| {
            if c == '.' {
                dots += 1;
            }
            dots >= 3 || !(c.is_ascii_digit() || c == '.')
        })
        .map_or("", |i| &real[i..]);
    let minor: u32 = real.split('.').nth(1).and_then(|m| m.parse().ok()).unwrap_or(0);
    alloc::format!("2.6.{}{rest}", minor + 60).into_bytes()
}

/// The magic numbers and the commands of `reboot`, from include/uapi/linux/reboot.h.
const LINUX_REBOOT_MAGIC1: u32 = 0xfee1_dead;
const LINUX_REBOOT_MAGIC2: u32 = 672_274_793;
const LINUX_REBOOT_MAGIC2A: u32 = 85_072_278;
const LINUX_REBOOT_MAGIC2B: u32 = 369_367_448;
const LINUX_REBOOT_MAGIC2C: u32 = 537_993_216;
const LINUX_REBOOT_CMD_RESTART: u32 = 0x0123_4567;
const LINUX_REBOOT_CMD_HALT: u32 = 0xcdef_0123;
const LINUX_REBOOT_CMD_CAD_ON: u32 = 0x89ab_cdef;
const LINUX_REBOOT_CMD_CAD_OFF: u32 = 0;
const LINUX_REBOOT_CMD_POWER_OFF: u32 = 0x4321_fedc;
const LINUX_REBOOT_CMD_RESTART2: u32 = 0xa1b2_c3d4;

/// Tells if Ctrl-Alt-Del restarts the machine at once, as `C_A_D` of Linux. rukernel has no
/// keyboard handler for it yet, so only `reboot` reads and writes it.
static CTRL_ALT_DEL: AtomicBool = AtomicBool::new(true);

/// `reboot`, as kernel/reboot.c of Linux. The permission comes first, then the magic numbers,
/// then the command. rukernel cannot restart the machine, so a restart stops it, as a halt and
/// a power off do.
pub(crate) fn reboot(cx: &Cx<'_>, magic1: u64, magic2: u64, cmd: u64) -> SysResult {
    if !cx.process().cred().capable(cap::SYS_BOOT) {
        return Err(Errno::EPERM);
    }
    let magic2 = magic2 as u32;
    if magic1 as u32 != LINUX_REBOOT_MAGIC1
        || ![LINUX_REBOOT_MAGIC2, LINUX_REBOOT_MAGIC2A, LINUX_REBOOT_MAGIC2B, LINUX_REBOOT_MAGIC2C]
            .contains(&magic2)
    {
        return Err(Errno::EINVAL);
    }
    match cmd as u32 {
        LINUX_REBOOT_CMD_CAD_ON => CTRL_ALT_DEL.store(true, Ordering::Relaxed),
        LINUX_REBOOT_CMD_CAD_OFF => {
            CTRL_ALT_DEL.store(false, Ordering::Relaxed);
        }
        LINUX_REBOOT_CMD_RESTART
        | LINUX_REBOOT_CMD_RESTART2
        | LINUX_REBOOT_CMD_HALT
        | LINUX_REBOOT_CMD_POWER_OFF => rk_frame::arch::qemu_exit(0),
        _ => return Err(Errno::EINVAL),
    }
    Ok(0)
}

/// `personality`, as kernel/exec_domain.c of Linux: sets the personality, except for
/// `0xffffffff`, and gives the old one. Linux does not examine the value.
pub(crate) fn personality(cx: &Cx<'_>, value: u64) -> SysResult {
    let process = cx.process();
    let old = process.personality();
    if value as u32 != 0xffff_ffff {
        process.set_personality(value as u32);
    }
    Ok(u64::from(old))
}

pub(crate) fn uname(cx: &Cx<'_>, buf: u64) -> SysResult {
    let u = NewUtsname {
        sysname: utsname_field(b"Linux"),
        nodename: rk_proc::uts::hostname(),
        release: utsname_field(&release(cx.process().personality())),
        version: utsname_field(crate::UNAME_VERSION.as_bytes()),
        machine: utsname_field(rk_frame::arch::UNAME_MACHINE.as_bytes()),
        domainname: rk_proc::uts::domainname(),
    };
    cx.write_val(buf, &u)?;
    Ok(0)
}

/// Reads the new name of `sethostname` or `setdomainname`, as Linux does: the permission comes
/// first, then the length, then the copy.
fn read_uts_name(cx: &Cx<'_>, name: u64, len: u64) -> Result<alloc::vec::Vec<u8>, Errno> {
    if !cx.process().cred().capable(cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    let len = len as i32;
    if !(0..=rk_proc::uts::NAME_MAX as i32).contains(&len) {
        return Err(Errno::EINVAL);
    }
    cx.read_bytes(name, len as usize)
}

pub(crate) fn sethostname(cx: &Cx<'_>, name: u64, len: u64) -> SysResult {
    let name = read_uts_name(cx, name, len)?;
    rk_proc::uts::set_hostname(&name);
    Ok(0)
}

pub(crate) fn setdomainname(cx: &Cx<'_>, name: u64, len: u64) -> SysResult {
    let name = read_uts_name(cx, name, len)?;
    rk_proc::uts::set_domainname(&name);
    Ok(0)
}

/// `syslog(2)`, the call under `klogctl(3)` and `dmesg`. Linux has it in kernel/printk/printk.c.
/// The kernel has no console log level, so the actions that change it do nothing.
pub(crate) fn syslog(cx: &Cx<'_>, action: u64, buf: u64, len: u64) -> SysResult {
    use rk_frame::console;
    const CLOSE: i32 = 0;
    const OPEN: i32 = 1;
    const READ: i32 = 2;
    const READ_ALL: i32 = 3;
    const READ_CLEAR: i32 = 4;
    const CLEAR: i32 = 5;
    const CONSOLE_OFF: i32 = 6;
    const CONSOLE_ON: i32 = 7;
    const CONSOLE_LEVEL: i32 = 8;
    const SIZE_UNREAD: i32 = 9;
    const SIZE_BUFFER: i32 = 10;
    let action = action as i32;
    // Only the full read and the size are open to each process, as `syslog_action_restricted`
    // of Linux with `dmesg_restrict` at 0.
    if action != READ_ALL && action != SIZE_BUFFER {
        let cred = cx.process().cred();
        if !cred.capable(cap::SYSLOG) && !cred.capable(cap::SYS_ADMIN) {
            return Err(Errno::EPERM);
        }
    }
    match action {
        CLOSE | OPEN | CONSOLE_OFF | CONSOLE_ON => Ok(0),
        READ | READ_ALL | READ_CLEAR => {
            if buf == 0 || (len as i32) < 0 {
                return Err(Errno::EINVAL);
            }
            let mut out = vec![0u8; (len as usize).min(console::LOG_SIZE)];
            let n = if action == READ {
                console::log_read(&mut out)
            } else {
                console::log_read_all(&mut out)
            };
            cx.write_bytes(buf, &out[..n])?;
            if action == READ_CLEAR {
                console::log_clear();
            }
            Ok(n as u64)
        }
        CLEAR => {
            console::log_clear();
            Ok(0)
        }
        CONSOLE_LEVEL if (1..=8).contains(&(len as i32)) => Ok(0),
        SIZE_UNREAD => Ok(console::log_unread() as u64),
        SIZE_BUFFER => Ok(console::LOG_SIZE as u64),
        _ => Err(Errno::EINVAL),
    }
}

pub(crate) fn prlimit64(cx: &Cx<'_>, pid: u64, resource: u64, new: u64, old: u64) -> SysResult {
    let resource =
        usize::try_from(resource).ok().filter(|&r| r < RLIM_NLIMITS).ok_or(Errno::EINVAL)?;
    let process = match pid as i32 {
        0 => cx.thread.process().clone(),
        p => rk_proc::find_process(p as u32).ok_or(Errno::ESRCH)?,
    };
    let cred = cx.process().cred();
    // Another process must have the IDs of the caller, as `check_prlimit_permission` of Linux.
    if !Arc::ptr_eq(&process, cx.process())
        && !cred.same_ids(&process.cred())
        && !cred.capable(cap::SYS_RESOURCE)
    {
        return Err(Errno::EPERM);
    }
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
    // Only a process with `CAP_SYS_RESOURCE` can raise the hard limit.
    if new.is_some_and(|n| n.max > l.max) && !cred.capable(cap::SYS_RESOURCE) {
        return Err(Errno::EPERM);
    }
    cx.write_opt(old, &Rlimit64 { rlim_cur: l.cur, rlim_max: l.max })?;
    if let Some(n) = new {
        process.set_limit(resource, n);
    }
    Ok(0)
}

pub(crate) fn getrusage(cx: &Cx<'_>, who: u64, buf: u64) -> SysResult {
    // `RUSAGE_SELF`, `RUSAGE_CHILDREN` and `RUSAGE_THREAD`.
    let process = cx.process();
    let (ticks, maxrss) = match who as i32 {
        0 => (process.user_ticks(), process.maxrss_kb()),
        -1 => (process.child_ticks(), process.child_maxrss_kb()),
        1 => (cx.thread.user_ticks(), process.maxrss_kb()),
        _ => return Err(Errno::EINVAL),
    };
    let mut r = rusage(ticks);
    r.ru_maxrss = maxrss as i64;
    cx.write_val(buf, &r)?;
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
    s.totalswap = rk_vfs::swap::total_pages();
    s.freeswap = s.totalswap;
    s.procs = rk_proc::processes().len().min(u16::MAX as usize) as u16;
    s.mem_unit = rk_mm::PAGE_SIZE as u32;
    cx.write_val(buf, &s)?;
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

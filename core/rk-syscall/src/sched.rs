//! The scheduling calls: `getpriority`, `setpriority`, the `sched_*` calls and `getcpu`.
//!
//! The checks and the errors are as in kernel/sys.c and kernel/sched/syscalls.c of Linux. The
//! scheduler of rukernel has only the fair class, so a real time policy and `SCHED_DEADLINE` only
//! give the thread the largest share of the CPU.

use crate::cx::{Cx, SysResult};
use crate::info::timespec;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::resource::{PRIO_PGRP, PRIO_PROCESS, PRIO_USER};
use rk_abi::native::sched::{
    SCHED_BATCH, SCHED_DEADLINE, SCHED_FIFO, SCHED_FLAG_ALL, SCHED_FLAG_KEEP_PARAMS,
    SCHED_FLAG_KEEP_POLICY, SCHED_FLAG_RESET_ON_FORK, SCHED_FLAG_UTIL_CLAMP, SCHED_IDLE,
    SCHED_NORMAL, SCHED_RESET_ON_FORK, SCHED_RR,
};
use rk_abi::native::types::SchedAttr;
use rk_proc::sched::SchedParams;
use rk_proc::{Thread, find_thread, processes};
use zerocopy::{FromZeros, IntoBytes};

/// The count of the CPUs. rukernel runs on one CPU.
const NR_CPUS: u32 = 1;

/// The bits of the CPUs that are online.
const ONLINE: u64 = (1 << NR_CPUS) - 1;

/// The size of a CPU mask in bytes. Linux names it `cpumask_size()`.
const MASK_SIZE: usize = 8;

/// The smallest and the largest nice value.
const MIN_NICE: i32 = -20;
const MAX_NICE: i32 = 19;

/// The largest real time priority. Linux names it `MAX_RT_PRIO - 1`.
const MAX_RT_PRIO: u32 = 99;

/// The size of the first version of `struct sched_attr`, and of the current version.
const ATTR_SIZE_VER0: u32 = 48;
const ATTR_SIZE: u32 = size_of::<SchedAttr>() as u32;

/// A flag of the scheduler governor of Linux. `sched_setattr` accepts it.
const SCHED_FLAG_SUGOV: u64 = 0x1000_0000;

/// The time slice of `SCHED_RR`: 100 milliseconds. Linux names it `RR_TIMESLICE`.
const RR_TIMESLICE: u64 = 100_000_000;

/// The time slice of the fair class, `BASE_SLICE` of rk-sched.
const FAIR_SLICE: u64 = 3_000_000;

/// The smallest and the largest period of `SCHED_DEADLINE`, in nanoseconds. These are the
/// default values of `sched_deadline_period_min_us` and `sched_deadline_period_max_us`.
const DL_PERIOD_MIN: u64 = 100_000;
const DL_PERIOD_MAX: u64 = (1 << 22) * 1000;

/// The policy argument that keeps the policy of the thread. Linux names it `SETPARAM_POLICY`.
const KEEP_POLICY: i64 = -1;

/// Gives the thread `pid`, or the calling thread for 0. The affinity calls of Linux give
/// `ESRCH` for a negative `pid`.
fn affinity_target(cx: &Cx<'_>, pid: u64) -> Result<Arc<Thread>, Errno> {
    match pid as i32 {
        0 => Ok(cx.thread.clone()),
        p if p > 0 => find_thread(p as u32).ok_or(Errno::ESRCH),
        _ => Err(Errno::ESRCH),
    }
}

/// Gives the thread `pid`, or the calling thread for 0.
fn target(cx: &Cx<'_>, pid: u64) -> Result<Arc<Thread>, Errno> {
    match pid as i32 {
        p if p < 0 => Err(Errno::EINVAL),
        0 => Ok(cx.thread.clone()),
        p => find_thread(p as u32).ok_or(Errno::ESRCH),
    }
}

/// Gives the threads that `which` and `who` of `getpriority` and `setpriority` select.
fn prio_targets(cx: &Cx<'_>, which: u64, who: u64) -> Result<Vec<Arc<Thread>>, Errno> {
    let who = who as i32;
    match which as i32 {
        PRIO_PROCESS => Ok(match who {
            0 => alloc::vec![cx.thread.clone()],
            w if w > 0 => find_thread(w as u32).into_iter().collect(),
            _ => Vec::new(),
        }),
        PRIO_PGRP => {
            let pgid = if who == 0 { cx.process().pgid() } else { who as u32 };
            Ok(processes()
                .into_iter()
                .filter(|p| p.pgid() == pgid)
                .flat_map(|p| p.threads())
                .collect())
        }
        // Each process of rukernel has the user ID 0.
        PRIO_USER if who == 0 => Ok(processes().into_iter().flat_map(|p| p.threads()).collect()),
        PRIO_USER => Ok(Vec::new()),
        _ => Err(Errno::EINVAL),
    }
}

/// `getpriority`: gives `20 - nice` of the thread with the smallest nice value.
pub(crate) fn getpriority(cx: &Cx<'_>, which: u64, who: u64) -> SysResult {
    let threads = prio_targets(cx, which, who)?;
    let nice = threads.iter().map(|t| t.sched().nice).min().ok_or(Errno::ESRCH)?;
    Ok((20 - nice) as u64)
}

/// `setpriority`: sets the nice value of each thread that `which` and `who` select.
pub(crate) fn setpriority(cx: &Cx<'_>, which: u64, who: u64, nice: u64) -> SysResult {
    let nice = (nice as i32).clamp(MIN_NICE, MAX_NICE);
    let threads = prio_targets(cx, which, who)?;
    if threads.is_empty() {
        return Err(Errno::ESRCH);
    }
    for thread in threads {
        thread.set_sched(SchedParams { nice, ..thread.sched() });
    }
    Ok(0)
}

/// Tells if `policy` is a policy that rukernel knows.
fn valid_policy(policy: u64) -> bool {
    matches!(
        policy,
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE | SCHED_FIFO | SCHED_RR | SCHED_DEADLINE
    )
}

/// Tells if the values of `SCHED_DEADLINE` are correct, as `__checkparam_dl` of Linux does.
fn valid_deadline(attr: &SchedAttr) -> bool {
    if attr.sched_deadline == 0 || attr.sched_runtime < 1 << 10 {
        return false;
    }
    if (attr.sched_deadline | attr.sched_period) & (1 << 63) != 0 {
        return false;
    }
    let period = if attr.sched_period == 0 { attr.sched_deadline } else { attr.sched_period };
    if period < attr.sched_deadline || attr.sched_deadline < attr.sched_runtime {
        return false;
    }
    (DL_PERIOD_MIN..=DL_PERIOD_MAX).contains(&period)
}

/// Sets the policy and its values from `attr`, as `__sched_setscheduler` of Linux does.
/// `policy` is `KEEP_POLICY` to keep the policy of the thread.
fn set_scheduler(thread: &Thread, policy: i64, attr: &SchedAttr) -> Result<(), Errno> {
    let old = thread.sched();
    let (policy, reset_on_fork) = if policy == KEEP_POLICY {
        (u64::from(old.policy), old.reset_on_fork)
    } else {
        let policy = policy as u64;
        if !valid_policy(policy) {
            return Err(Errno::EINVAL);
        }
        (policy, attr.sched_flags & SCHED_FLAG_RESET_ON_FORK != 0)
    };
    if attr.sched_flags & !(SCHED_FLAG_ALL | SCHED_FLAG_SUGOV) != 0 {
        return Err(Errno::EINVAL);
    }
    let rt = matches!(policy, SCHED_FIFO | SCHED_RR);
    if attr.sched_priority > MAX_RT_PRIO || rt != (attr.sched_priority != 0) {
        return Err(Errno::EINVAL);
    }
    if policy == SCHED_DEADLINE && !valid_deadline(attr) {
        return Err(Errno::EINVAL);
    }
    // rukernel has no utilization clamps. Linux without `CONFIG_UCLAMP_TASK` gives this error.
    if attr.sched_flags & SCHED_FLAG_UTIL_CLAMP != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let mut new = SchedParams {
        policy: policy as u32,
        priority: attr.sched_priority,
        reset_on_fork,
        runtime: 0,
        deadline: 0,
        period: 0,
        ..old
    };
    if policy == SCHED_DEADLINE {
        new.runtime = attr.sched_runtime;
        new.deadline = attr.sched_deadline;
        new.period = if attr.sched_period == 0 { attr.sched_deadline } else { attr.sched_period };
    } else if !rt {
        new.nice = attr.sched_nice;
    }
    thread.set_sched(new);
    Ok(())
}

/// The `struct sched_attr` of the values of `thread`, as `get_params` of Linux makes it.
fn get_attr(thread: &Thread) -> SchedAttr {
    let p = thread.sched();
    let mut attr = SchedAttr::new_zeroed();
    attr.sched_policy = p.policy;
    if p.reset_on_fork {
        attr.sched_flags |= SCHED_FLAG_RESET_ON_FORK;
    }
    if p.is_deadline() {
        attr.sched_runtime = p.runtime;
        attr.sched_deadline = p.deadline;
        attr.sched_period = p.period;
    } else if p.is_rt() {
        attr.sched_priority = p.priority;
    } else {
        attr.sched_nice = p.nice;
        attr.sched_runtime = FAIR_SLICE;
    }
    attr
}

/// `sched_setscheduler` and `sched_setparam`: the old interface, with `struct sched_param`.
fn setscheduler(cx: &Cx<'_>, pid: u64, policy: i64, param: u64) -> SysResult {
    if param == 0 || (pid as i32) < 0 {
        return Err(Errno::EINVAL);
    }
    let priority: i32 = cx.read_val(param)?;
    let thread = target(cx, pid)?;
    let mut attr = get_attr(&thread);
    attr.sched_priority = priority as u32;
    attr.sched_nice = thread.sched().nice;
    attr.sched_flags = 0;
    let policy = if policy == KEEP_POLICY {
        policy
    } else {
        if policy as u64 & SCHED_RESET_ON_FORK != 0 {
            attr.sched_flags = SCHED_FLAG_RESET_ON_FORK;
        }
        policy & !(SCHED_RESET_ON_FORK as i64)
    };
    // The old interface cannot give the values of `SCHED_DEADLINE`, so `valid_deadline` fails.
    attr.sched_runtime = 0;
    attr.sched_deadline = 0;
    attr.sched_period = 0;
    set_scheduler(&thread, policy, &attr)?;
    Ok(0)
}

pub(crate) fn sched_setscheduler(cx: &Cx<'_>, pid: u64, policy: u64, param: u64) -> SysResult {
    let policy = i64::from(policy as i32);
    if policy < 0 {
        return Err(Errno::EINVAL);
    }
    setscheduler(cx, pid, policy, param)
}

pub(crate) fn sched_setparam(cx: &Cx<'_>, pid: u64, param: u64) -> SysResult {
    setscheduler(cx, pid, KEEP_POLICY, param)
}

pub(crate) fn sched_getscheduler(cx: &Cx<'_>, pid: u64) -> SysResult {
    let p = target(cx, pid)?.sched();
    let flag = if p.reset_on_fork { SCHED_RESET_ON_FORK } else { 0 };
    Ok(u64::from(p.policy) | flag)
}

pub(crate) fn sched_getparam(cx: &Cx<'_>, pid: u64, param: u64) -> SysResult {
    if param == 0 || (pid as i32) < 0 {
        return Err(Errno::EINVAL);
    }
    let p = target(cx, pid)?.sched();
    let priority: i32 = if p.is_rt() { p.priority as i32 } else { 0 };
    cx.write_val(param, &priority)?;
    Ok(0)
}

/// Reads the `struct sched_attr` at `addr`, as `sched_copy_attr` of Linux does.
fn read_attr(cx: &Cx<'_>, addr: u64) -> Result<SchedAttr, Errno> {
    let mut size: u32 = cx.read_val(addr)?;
    if size == 0 {
        size = ATTR_SIZE_VER0;
    }
    if size < ATTR_SIZE_VER0 || size as usize > rk_proc::PAGE_SIZE {
        cx.write_val(addr, &ATTR_SIZE)?;
        return Err(Errno::E2BIG);
    }
    // A newer program can give a larger structure. The bytes that rukernel does not know must
    // be 0.
    if size > ATTR_SIZE {
        let rest = cx.read_bytes(addr + u64::from(ATTR_SIZE), (size - ATTR_SIZE) as usize)?;
        if rest.iter().any(|&b| b != 0) {
            cx.write_val(addr, &ATTR_SIZE)?;
            return Err(Errno::E2BIG);
        }
    }
    let mut attr = SchedAttr::new_zeroed();
    let len = size.min(ATTR_SIZE) as usize;
    let bytes = cx.read_bytes(addr, len)?;
    attr.as_mut_bytes()[..len].copy_from_slice(&bytes);
    if attr.sched_flags & SCHED_FLAG_UTIL_CLAMP != 0 && size < ATTR_SIZE {
        return Err(Errno::EINVAL);
    }
    attr.size = size;
    attr.sched_nice = attr.sched_nice.clamp(MIN_NICE, MAX_NICE);
    Ok(attr)
}

pub(crate) fn sched_setattr(cx: &Cx<'_>, pid: u64, uattr: u64, flags: u64) -> SysResult {
    if uattr == 0 || (pid as i32) < 0 || flags as u32 != 0 {
        return Err(Errno::EINVAL);
    }
    let mut attr = read_attr(cx, uattr)?;
    if (attr.sched_policy as i32) < 0 {
        return Err(Errno::EINVAL);
    }
    let policy = if attr.sched_flags & SCHED_FLAG_KEEP_POLICY != 0 {
        KEEP_POLICY
    } else {
        i64::from(attr.sched_policy)
    };
    let thread = target(cx, pid)?;
    if attr.sched_flags & SCHED_FLAG_KEEP_PARAMS != 0 {
        let now = get_attr(&thread);
        attr.sched_nice = now.sched_nice;
        attr.sched_priority = now.sched_priority;
        attr.sched_runtime = now.sched_runtime;
        attr.sched_deadline = now.sched_deadline;
        attr.sched_period = now.sched_period;
    }
    set_scheduler(&thread, policy, &attr)?;
    Ok(0)
}

pub(crate) fn sched_getattr(cx: &Cx<'_>, pid: u64, uattr: u64, size: u64, flags: u64) -> SysResult {
    let size = size as u32;
    if uattr == 0
        || (pid as i32) < 0
        || size as usize > rk_proc::PAGE_SIZE
        || size < ATTR_SIZE_VER0
        || flags as u32 != 0
    {
        return Err(Errno::EINVAL);
    }
    let mut attr = get_attr(&*target(cx, pid)?);
    let size = size.min(ATTR_SIZE);
    attr.size = size;
    cx.write_bytes(uattr, &attr.as_bytes()[..size as usize])?;
    Ok(0)
}

pub(crate) fn sched_get_priority_max(policy: u64) -> SysResult {
    match policy as i32 as i64 as u64 {
        SCHED_FIFO | SCHED_RR => Ok(u64::from(MAX_RT_PRIO)),
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE => Ok(0),
        _ => Err(Errno::EINVAL),
    }
}

pub(crate) fn sched_get_priority_min(policy: u64) -> SysResult {
    match policy as i32 as i64 as u64 {
        SCHED_FIFO | SCHED_RR => Ok(1),
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE => Ok(0),
        _ => Err(Errno::EINVAL),
    }
}

/// `sched_rr_get_interval`: the time slice of `SCHED_RR` is 100 milliseconds. The other policies
/// give 0, as Linux gives for a fair slice that is shorter than one timer tick.
pub(crate) fn sched_rr_get_interval(cx: &Cx<'_>, pid: u64, interval: u64) -> SysResult {
    let p = target(cx, pid)?.sched();
    let slice = if u64::from(p.policy) == SCHED_RR { RR_TIMESLICE } else { 0 };
    cx.write_val(interval, &timespec(slice))?;
    Ok(0)
}

pub(crate) fn sched_setaffinity(cx: &Cx<'_>, pid: u64, len: u64, mask: u64) -> SysResult {
    let len = (len as usize).min(MASK_SIZE);
    let mut raw = [0u8; MASK_SIZE];
    raw[..len].copy_from_slice(&cx.read_bytes(mask, len)?);
    let thread = affinity_target(cx, pid)?;
    let affinity = u64::from_ne_bytes(raw) & ONLINE;
    if affinity == 0 {
        return Err(Errno::EINVAL);
    }
    thread.set_sched(SchedParams { affinity, ..thread.sched() });
    Ok(0)
}

pub(crate) fn sched_getaffinity(cx: &Cx<'_>, pid: u64, len: u64, mask: u64) -> SysResult {
    let len = len as u32;
    if u64::from(len) * 8 < u64::from(NR_CPUS) || len as usize % size_of::<u64>() != 0 {
        return Err(Errno::EINVAL);
    }
    let affinity = affinity_target(cx, pid)?.sched().affinity & ONLINE;
    cx.write_bytes(mask, &affinity.to_ne_bytes())?;
    Ok(MASK_SIZE as u64)
}

/// `getcpu`: rukernel runs on CPU 0 of node 0.
pub(crate) fn getcpu(cx: &Cx<'_>, cpu: u64, node: u64) -> SysResult {
    cx.write_opt(cpu, &0u32)?;
    cx.write_opt(node, &0u32)?;
    Ok(0)
}

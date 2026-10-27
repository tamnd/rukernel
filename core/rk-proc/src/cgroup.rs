//! The processes in the cgroups: the move of a process, the kill of a subtree, the freezer and
//! the OOM killer of a memory cgroup. rk-cgroup keeps the hierarchy and the counts, and this
//! module changes the processes and the threads.

use crate::process::{Process, Thread, kill_group, processes};
use crate::wait::WaitStatus;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::signal::SIGKILL;
use rk_cgroup::CgId;
use rk_frame::task::WaitQueue;

/// The threads of a frozen cgroup wait here until it thaws.
static THAW: WaitQueue = WaitQueue::new();

/// The threads of a cgroup without CPU quota wait here until the next period.
static THROTTLE: WaitQueue = WaitQueue::new();

/// The length of a timer tick in nanoseconds.
const TICK_NS: u64 = 1_000_000_000 / rk_frame::time::HZ;

/// Moves `process` with all its threads to the cgroup `to`, for a write of `cgroup.procs`.
///
/// # Errors
///
/// `ESRCH` for a process that ended, and the errors of `Hierarchy::migrate`.
pub fn migrate(process: &Process, to: CgId) -> Result<(), Errno> {
    let threads = process.move_cgroup(to)?;
    if let Some(vm) = process.vm() {
        vm.set_memcg(process.memcg());
    }
    for t in &threads {
        if let Some(task) = t.task() {
            rk_frame::task::set_group(&task, to);
        }
        t.set_sched(t.sched());
    }
    // A thread that waits in a frozen cgroup checks the state of its new cgroup.
    THAW.wake_all();
    Ok(())
}

/// The processes in the cgroup `id` and the cgroups below it.
pub fn processes_in(id: CgId) -> Vec<Arc<Process>> {
    // `is_zombie` takes the lock of the state of the process, and the lock order is the state
    // first and then the hierarchy. Thus the check of the state is before `with`.
    let live: Vec<Arc<Process>> = processes().into_iter().filter(|p| !p.is_zombie()).collect();
    rk_cgroup::with(|h| live.into_iter().filter(|p| h.is_descendant(p.cgroup(), id)).collect())
}

/// The processes in the cgroup `id` only, for `cgroup.procs`.
pub fn processes_of(id: CgId) -> Vec<Arc<Process>> {
    processes().into_iter().filter(|p| !p.is_zombie() && p.cgroup() == id).collect()
}

/// Sends `SIGKILL` to each process in the subtree of `id`, for `cgroup.kill`.
pub fn kill_subtree(id: CgId) {
    for p in processes_in(id) {
        kill_group(&p, WaitStatus::signaled(SIGKILL, false));
    }
}

/// Wakes the threads that wait in a frozen cgroup, after a write of `cgroup.freeze`.
pub fn thaw() {
    THAW.wake_all();
}

/// Keeps `thread` waiting while its cgroup is frozen, as the freezer of Linux. A kill ends the
/// wait.
pub fn wait_frozen(thread: &Thread) {
    let process = thread.process();
    if !rk_cgroup::frozen(process.cgroup()) {
        return;
    }
    THAW.wait_until(|| (thread.is_killed() || !rk_cgroup::frozen(process.cgroup())).then_some(()));
}

/// Keeps `thread` waiting while its cgroup has used its CPU quota for this period, as the
/// throttle of `cpu.max`. The thread counts as a task that can run in the pressure of the CPU
/// while it waits, as a throttled task of Linux. A kill ends the wait.
pub fn wait_throttled(thread: &Thread) {
    let cg = thread.process().cgroup();
    let Some(until) = rk_cgroup::throttled_until(cg) else { return };
    let now = rk_frame::time::nanos();
    let ticks = until.saturating_sub(now).div_ceil(TICK_NS).max(1);
    let deadline = rk_frame::time::ticks() + ticks;
    rk_cgroup::psi_change(cg, |c| c.runnable += 1);
    THROTTLE.wait_until_timeout(deadline, || thread.is_killed().then_some(()));
    rk_cgroup::psi_change(cg, |c| c.runnable = c.runnable.saturating_sub(1));
}

/// The size of a process in pages, for the choice of the OOM killer.
fn size(process: &Process) -> usize {
    process.vm().map_or(0, |vm| vm.resident_pages(0, rk_frame::vm::USER_END))
}

/// Kills the largest process in the subtree of the memory cgroup `id`, as
/// `mem_cgroup_out_of_memory` of Linux. Gives the process, or `None` if the subtree has no
/// process that the kill can free.
pub fn oom_kill(id: CgId) -> Option<Arc<Process>> {
    let victim = processes_in(id)
        .into_iter()
        .filter(|p| p.group_exit().is_none() && p.oom_score_adj() > -1000)
        .max_by_key(|p| size(p))?;
    rk_frame::println!(
        "Memory cgroup out of memory: Killed process {} ({})",
        victim.pid(),
        core::str::from_utf8(&victim.comm()).unwrap_or("?")
    );
    rk_cgroup::with(|h| h.count_oom_kill(id));
    kill_group(&victim, WaitStatus::signaled(SIGKILL, false));
    Some(victim)
}

/// Handles a page fault of `thread` that did not get a page. If the memory cgroup of the
/// process is at its limit, the OOM killer of the cgroup kills a process and the thread waits
/// for its end, so that the fault can try again. Gives `true` if the fault can try again, and
/// `false` if the memory of the system is short.
pub fn memcg_oom(thread: &Thread) -> bool {
    let process = thread.process();
    let memcg = process.memcg();
    if memcg == 0 {
        return false;
    }
    // A test charge finds the cgroup whose limit blocks the page.
    let blocking = match rk_cgroup::charge_page(memcg) {
        Ok(()) => {
            rk_cgroup::uncharge_page(memcg);
            // A page was freed since the fault, so the fault can try again.
            return true;
        }
        Err(id) => id,
    };
    let cg = process.cgroup();
    rk_cgroup::with(|h| h.count_oom(blocking));
    rk_cgroup::psi_change(cg, |c| c.memstall += 1);
    let victim = oom_kill(blocking);
    if let Some(victim) = &victim
        && !Arc::ptr_eq(victim, process)
    {
        // The memory of the victim is free when its address space goes. Wait for that, but not
        // for ever, and stop if this thread gets a kill.
        let deadline = rk_frame::time::ticks() + rk_frame::time::HZ;
        THROTTLE.wait_until_timeout(deadline, || {
            (thread.is_killed() || victim.vm().is_none()).then_some(())
        });
    }
    rk_cgroup::psi_change(cg, |c| c.memstall = c.memstall.saturating_sub(1));
    victim.is_some()
}

/// Kills processes in the subtree of `id` until its memory use is below `memory.max`, after a
/// write of the limit.
pub fn reclaim_over_limit(id: CgId) {
    for _ in 0..64 {
        if rk_cgroup::with(|h| h.memory_over(id)) == 0 {
            return;
        }
        rk_cgroup::with(|h| h.count_oom(id));
        let Some(victim) = oom_kill(id) else { return };
        let deadline = rk_frame::time::ticks() + rk_frame::time::HZ;
        THROTTLE.wait_until_timeout(deadline, || victim.vm().is_none().then_some(()));
    }
}

/// Sets the CPUs of each thread in the subtree of `id` again, after a write of `cpuset.cpus`.
pub fn update_cpus(id: CgId) {
    for p in processes_in(id) {
        for t in p.threads() {
            t.set_sched(t.sched());
        }
    }
}

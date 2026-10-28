//! The processes in the cgroups: the move of a process, the kill of a subtree, the freezer, the
//! wait of `memory.high`, and the OOM killers of a memory cgroup and of the system. rk-cgroup keeps the hierarchy and the counts, and this
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

/// The free frames under which the memory of the system is short, for the OOM killers. A fault
/// of a process fails under the reserve of rk-mm or under `vm.min_free_kbytes`, so the memory is
/// short at that point. The margin covers the frames that the kernel takes between the fault and
/// the check.
fn system_reserve() -> usize {
    let total = rk_frame::mm::frame_stats().total;
    rk_mm::USER_RESERVE.max(rk_mm::tunables::reserve_pages(total)) + 16
}

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
    // A thread that waits in a frozen cgroup checks the state of its new cgroup, and a thread
    // that moves to a frozen cgroup stops its wait to freeze, as `cgroup_freezer_migrate_task`
    // of Linux.
    THAW.wake_all();
    if rk_cgroup::frozen(to) {
        for t in &threads {
            t.wake();
        }
    }
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

/// Tells the threads of the subtree of `id` that `cgroup.freeze` changed, as
/// `cgroup_freeze_task` of Linux. The threads that wait in the freezer check the state again.
/// Each other thread stops its wait as for a signal, and goes to the freezer before it returns
/// to user mode. A system call that a freeze stops starts again after the thaw.
pub fn freeze_changed(id: CgId) {
    THAW.wake_all();
    if !rk_cgroup::frozen(id) {
        return;
    }
    for p in processes_in(id) {
        for t in p.threads() {
            t.wake();
        }
    }
}

/// Keeps `thread` waiting while its cgroup is frozen, as the freezer of Linux
/// (`do_freezer_trap`). The thread counts as frozen in its cgroup while it waits, so that
/// `cgroup.events` tells when the whole cgroup is frozen. A kill ends the wait.
pub fn wait_frozen(thread: &Thread) {
    let process = thread.process();
    let mut cg = process.cgroup();
    while !thread.is_killed() && rk_cgroup::frozen(cg) {
        rk_cgroup::with(|h| h.thread_frozen(cg, true));
        THAW.wait_until(|| {
            (thread.is_killed() || process.cgroup() != cg || !rk_cgroup::frozen(cg)).then_some(())
        });
        rk_cgroup::with(|h| h.thread_frozen(cg, false));
        cg = process.cgroup();
    }
}

/// Keeps `thread` waiting while its cgroup has used its CPU quota for this period, as the
/// throttle of `cpu.max`. The thread counts as a task that can run in the pressure of the CPU
/// while it waits, as a throttled task of Linux. A kill ends the wait.
pub fn wait_throttled(thread: &Thread) {
    let cg = thread.process().cgroup();
    wait_over_high(thread, cg);
    wait_io(thread, cg);
    let Some(until) = rk_cgroup::throttled_until(cg) else { return };
    let now = rk_frame::time::nanos();
    let ticks = until.saturating_sub(now).div_ceil(TICK_NS).max(1);
    let deadline = rk_frame::time::ticks() + ticks;
    rk_cgroup::psi_change(cg, |c| c.runnable += 1);
    THROTTLE.wait_until_timeout(deadline, || thread.is_killed().then_some(()));
    rk_cgroup::psi_change(cg, |c| c.runnable = c.runnable.saturating_sub(1));
}

/// Keeps `thread` waiting when its cgroup charged pages over `memory.high`, as
/// `mem_cgroup_handle_over_high` of Linux. The wait counts as a memory stall in the pressure.
/// rukernel does not take pages back from a cgroup, so this wait is the only effect of the
/// limit. A kill ends the wait.
fn wait_over_high(thread: &Thread, cg: CgId) {
    let delay = rk_cgroup::high_delay(thread.process().memcg());
    if delay == 0 {
        return;
    }
    let deadline = rk_frame::time::ticks() + delay.div_ceil(TICK_NS);
    rk_cgroup::psi_change(cg, |c| c.memstall += 1);
    THROTTLE.wait_until_timeout(deadline, || thread.is_killed().then_some(()));
    rk_cgroup::psi_change(cg, |c| c.memstall = c.memstall.saturating_sub(1));
}

/// Charges an I/O of the current thread to its cgroup, for `io.stat`. Kernel work goes to the
/// root. The delay of `io.max` waits until the thread goes back to user mode, so the thread does
/// not wait with the locks of a file system. The block layer calls this after each batch.
pub fn io_account(dev: u64, write: bool, bytes: u64, ios: u64) {
    let thread = crate::current_thread();
    let cg = thread.as_ref().map_or(rk_cgroup::ROOT, |t| t.process().cgroup());
    let delay = rk_cgroup::charge_io(cg, dev, write, bytes, ios);
    if let Some(t) = thread.filter(|_| delay > 0) {
        t.add_io_delay(delay);
    }
}

/// Keeps `thread` waiting for the delay of `io.max`, as the throttle of blk-throttle of Linux.
/// The wait counts as an I/O stall in the pressure. A kill ends the wait.
fn wait_io(thread: &Thread, cg: CgId) {
    let delay = thread.take_io_delay();
    if delay == 0 {
        return;
    }
    let deadline = rk_frame::time::ticks() + delay.div_ceil(TICK_NS);
    rk_cgroup::psi_change(cg, |c| c.iowait += 1);
    THROTTLE.wait_until_timeout(deadline, || thread.is_killed().then_some(()));
    rk_cgroup::psi_change(cg, |c| c.iowait = c.iowait.saturating_sub(1));
}

/// The size of a process in pages, for the choice of the OOM killer.
fn size(process: &Process) -> usize {
    process.vm().map_or(0, |vm| vm.page_count())
}

/// Kills the largest process in the subtree of the memory cgroup `id`, as
/// `mem_cgroup_out_of_memory` of Linux. Gives the process, or `None` if the subtree has no
/// process that the kill can free.
pub fn oom_kill(id: CgId) -> Option<Arc<Process>> {
    let victim = processes_in(id)
        .into_iter()
        .filter(|p| p.group_exit().is_none() && p.oom_score_adj() > -1000)
        .max_by_key(|p| size(p))?;
    kill_victim(&victim, id, "Memory cgroup out of memory");
    Some(victim)
}

/// Kills `victim` for an OOM of the memory cgroup `domain`, the root for an OOM of the system.
/// If a cgroup of the victim up to `domain` has `memory.oom.group` 1, the kill takes each
/// process of the highest such cgroup, as `mem_cgroup_get_oom_group` of Linux.
fn kill_victim(victim: &Arc<Process>, domain: CgId, why: &str) {
    rk_frame::println!(
        "{why}: Killed process {} ({})",
        victim.pid(),
        core::str::from_utf8(&victim.comm()).unwrap_or("?")
    );
    let group = rk_cgroup::with(|h| {
        h.count_oom_kill(victim.cgroup());
        h.oom_group(victim.cgroup(), domain)
    });
    kill_group(victim, WaitStatus::signaled(SIGKILL, false));
    let Some(group) = group else { return };
    rk_cgroup::with(|h| h.count_oom_group_kill(group));
    for p in processes_in(group) {
        if !Arc::ptr_eq(&p, victim) && p.oom_score_adj() > -1000 && p.group_exit().is_none() {
            rk_cgroup::with(|h| h.count_oom_kill(p.cgroup()));
            kill_group(&p, WaitStatus::signaled(SIGKILL, false));
        }
    }
}

/// Handles a page fault of `thread` that did not get a page because the memory of the system
/// is short, as `out_of_memory` of Linux. The OOM killer kills the process with the most
/// points: its resident pages, plus `oom_score_adj` thousandths of the memory of the system.
/// It does not kill init or a process with `oom_score_adj` -1000. The thread then waits for
/// the end of the victim, so that the fault can try again. Gives `false` if no process can go.
pub fn system_oom(thread: &Thread) -> bool {
    // A fault that a memory cgroup refused, with free memory in the system, is not for this
    // killer.
    if rk_frame::mm::frame_stats().free > system_reserve() {
        return false;
    }
    // A victim that is still on its way out frees its memory soon: wait for it, as Linux does
    // for a task with `TIF_MEMDIE`.
    let all: Vec<Arc<Process>> =
        processes().into_iter().filter(|p| !p.is_zombie() && p.vm().is_some()).collect();
    let dying =
        all.iter().find(|p| p.group_exit().is_some() && !Arc::ptr_eq(p, thread.process())).cloned();
    let victim = match dying {
        Some(p) => p,
        None => {
            let total = rk_frame::mm::frame_stats().total as i64;
            let Some(victim) = all
                .iter()
                .filter(|p| p.pid() != 1 && p.oom_score_adj() > -1000)
                .max_by_key(|p| size(p) as i64 + i64::from(p.oom_score_adj()) * total / 1000)
                .cloned()
            else {
                return false;
            };
            kill_victim(&victim, rk_cgroup::ROOT, "Out of memory");
            victim
        }
    };
    if Arc::ptr_eq(&victim, thread.process()) {
        // The thread ends at its return to user mode.
        return true;
    }
    let cg = thread.process().cgroup();
    rk_cgroup::psi_change(cg, |c| c.memstall += 1);
    let deadline = rk_frame::time::ticks() + rk_frame::time::HZ;
    THROTTLE.wait_until_timeout(deadline, || {
        (thread.is_killed() || victim.vm().is_none()).then_some(())
    });
    rk_cgroup::psi_change(cg, |c| c.memstall = c.memstall.saturating_sub(1));
    true
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
            // The cgroup has room. If the system has free memory, a page was freed since the
            // fault, so the fault can try again. If not, the OOM killer of the system must act.
            return rk_frame::mm::frame_stats().free > system_reserve();
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

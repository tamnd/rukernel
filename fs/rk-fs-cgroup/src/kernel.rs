//! The processes of the cgroups, from rk-proc.

use crate::PsiTrigger;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_cgroup::{CgId, Effect};
use rk_proc::signal::SigInfo;
use rk_proc::timer::{Clock, Expire, Target, Timer};

/// The timer of a pressure trigger.
pub(crate) type TriggerTimer = Arc<Timer>;

/// Starts a timer that checks `trigger` after each `period` nanoseconds.
pub(crate) fn start_timer(trigger: &Arc<PsiTrigger>, period: u64) -> TriggerTimer {
    let weak: Weak<dyn Expire> = Arc::downgrade(trigger) as Weak<dyn Expire>;
    let timer = Timer::new(Clock::Boot, Target::Notify(weak), SigInfo::new(0, 0, 0));
    timer.arm(rk_cgroup::now() + period, period);
    timer
}

/// Stops the timer of a trigger.
pub(crate) fn stop_timer(timer: &TriggerTimer) {
    timer.arm(0, 0);
}

impl Expire for PsiTrigger {
    fn expire(&self, _count: u64) {
        self.check();
    }
}

/// The cgroup namespace of the caller, and its root cgroup.
pub(crate) fn namespace() -> (u32, CgId) {
    let ns = rk_proc::current_thread().map_or(0, |t| t.process().cgroup_ns());
    (ns, rk_cgroup::with(|h| h.namespace_root(ns)))
}

/// The IDs of the processes in the cgroup `id`, for `cgroup.procs`.
pub(crate) fn processes(id: CgId) -> Vec<u32> {
    rk_proc::cgroup::processes_of(id).iter().map(|p| p.pid()).collect()
}

/// The IDs of the threads in the cgroup `id`, for `cgroup.threads`.
pub(crate) fn threads(id: CgId) -> Vec<u32> {
    let mut out: Vec<u32> = rk_proc::cgroup::processes_of(id)
        .iter()
        .flat_map(|p| p.threads().into_iter().map(|t| t.tid()))
        .collect();
    out.sort_unstable();
    out
}

/// Moves the process `pid`, or the caller for 0, to the cgroup `id`. `check` gets the cgroup of
/// the process and gives an error if the move is not allowed.
pub(crate) fn move_process(
    id: CgId,
    pid: u32,
    check: &dyn Fn(CgId) -> Result<(), Errno>,
) -> Result<(), Errno> {
    let process = if pid == 0 {
        rk_proc::current_thread().ok_or(Errno::ESRCH)?.process().clone()
    } else {
        rk_proc::find_process(pid).ok_or(Errno::ESRCH)?
    };
    check(process.cgroup())?;
    rk_proc::cgroup::migrate(&process, id)
}

/// Moves the thread `tid` to the cgroup `id`. The cgroups here are all of the type `domain`,
/// so a thread cannot leave its process, as in Linux. `check` gets the cgroup of the thread and
/// gives an error if the move is not allowed.
pub(crate) fn move_thread(
    id: CgId,
    tid: u32,
    check: &dyn Fn(CgId) -> Result<(), Errno>,
) -> Result<(), Errno> {
    let thread = if tid == 0 {
        rk_proc::current_thread().ok_or(Errno::ESRCH)?
    } else {
        rk_proc::find_thread(tid).ok_or(Errno::ESRCH)?
    };
    check(thread.process().cgroup())?;
    if thread.process().cgroup() == id { Ok(()) } else { Err(Errno::EOPNOTSUPP) }
}

/// Tells if the block device `dev` exists.
pub(crate) fn block_exists(dev: u64) -> bool {
    rk_vfs::blockdev::block_sectors(dev).is_some()
}

/// Does what `effect` of a write of the cgroup `id` asks for.
pub(crate) fn apply(id: CgId, effect: Effect) {
    match effect {
        Effect::None => {}
        Effect::Kill => rk_proc::cgroup::kill_subtree(id),
        Effect::Freeze => rk_proc::cgroup::freeze_changed(id),
        Effect::MemoryOver => rk_proc::cgroup::reclaim_over_limit(id),
        Effect::Cpuset => rk_proc::cgroup::update_cpus(id),
    }
}

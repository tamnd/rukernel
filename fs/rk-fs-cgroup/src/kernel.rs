//! The processes of the cgroups, from rk-proc.

use alloc::vec::Vec;
use rk_abi::Errno;
use rk_cgroup::{CgId, Effect};

/// The root of the cgroup namespace of the caller.
pub(crate) fn namespace_root() -> CgId {
    let ns = rk_proc::current_thread().map_or(0, |t| t.process().cgroup_ns());
    rk_cgroup::with(|h| h.namespace_root(ns))
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

/// Moves the process `pid`, or the caller for 0, to the cgroup `id`.
pub(crate) fn move_process(id: CgId, pid: u32) -> Result<(), Errno> {
    let process = if pid == 0 {
        rk_proc::current_thread().ok_or(Errno::ESRCH)?.process().clone()
    } else {
        rk_proc::find_process(pid).ok_or(Errno::ESRCH)?
    };
    rk_proc::cgroup::migrate(&process, id)
}

/// Moves the thread `tid` to the cgroup `id`. The cgroups here are all of the type `domain`,
/// so a thread cannot leave its process, as in Linux.
pub(crate) fn move_thread(id: CgId, tid: u32) -> Result<(), Errno> {
    let thread = if tid == 0 {
        rk_proc::current_thread().ok_or(Errno::ESRCH)?
    } else {
        rk_proc::find_thread(tid).ok_or(Errno::ESRCH)?
    };
    if thread.process().cgroup() == id { Ok(()) } else { Err(Errno::EOPNOTSUPP) }
}

/// Does what `effect` of a write of the cgroup `id` asks for.
pub(crate) fn apply(id: CgId, effect: Effect) {
    match effect {
        Effect::None => {}
        Effect::Kill => rk_proc::cgroup::kill_subtree(id),
        Effect::Freeze => rk_proc::cgroup::thaw(),
        Effect::MemoryOver => rk_proc::cgroup::reclaim_over_limit(id),
        Effect::Cpuset => rk_proc::cgroup::update_cpus(id),
    }
}

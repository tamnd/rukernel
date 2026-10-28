//! The processes of the cgroups on the host, where rk-proc has no processes. The tests use it.

use crate::PsiTrigger;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_cgroup::{CgId, Effect, ROOT};

/// The cgroup namespace of the caller and its root: the initial namespace and the root of the
/// system.
pub(crate) fn namespace() -> (u32, CgId) {
    (0, ROOT)
}

/// The IDs of the processes in a cgroup: none on the host.
pub(crate) fn processes(_id: CgId) -> Vec<u32> {
    Vec::new()
}

/// The IDs of the threads in a cgroup: none on the host.
pub(crate) fn threads(_id: CgId) -> Vec<u32> {
    Vec::new()
}

/// Moves a process: the host has no process, so this gives `ESRCH`.
pub(crate) fn move_process(
    _id: CgId,
    _pid: u32,
    _check: &dyn Fn(CgId) -> Result<(), Errno>,
) -> Result<(), Errno> {
    Err(Errno::ESRCH)
}

/// Moves a thread: the host has no thread, so this gives `ESRCH`.
pub(crate) fn move_thread(
    _id: CgId,
    _tid: u32,
    _check: &dyn Fn(CgId) -> Result<(), Errno>,
) -> Result<(), Errno> {
    Err(Errno::ESRCH)
}

/// Tells if a block device exists: the host takes each device.
pub(crate) fn block_exists(_dev: u64) -> bool {
    true
}

/// Does what a write asks for: nothing on the host.
pub(crate) fn apply(_id: CgId, _effect: Effect) {}

/// The timer of a pressure trigger: the host has no timers, so the trigger checks only at
/// `poll`.
pub(crate) type TriggerTimer = ();

/// Starts the timer of a trigger: nothing on the host.
pub(crate) fn start_timer(_trigger: &Arc<PsiTrigger>, _period: u64) -> TriggerTimer {}

/// Stops the timer of a trigger: nothing on the host.
pub(crate) fn stop_timer(_timer: &TriggerTimer) {}

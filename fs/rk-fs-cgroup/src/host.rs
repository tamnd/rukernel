//! The processes of the cgroups on the host, where rk-proc has no processes. The tests use it.

use alloc::vec::Vec;
use rk_abi::Errno;
use rk_cgroup::{CgId, Effect, ROOT};

/// The root of the cgroup namespace of the caller: the root of the system.
pub(crate) fn namespace_root() -> CgId {
    ROOT
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
pub(crate) fn move_process(_id: CgId, _pid: u32) -> Result<(), Errno> {
    Err(Errno::ESRCH)
}

/// Moves a thread: the host has no thread, so this gives `ESRCH`.
pub(crate) fn move_thread(_id: CgId, _tid: u32) -> Result<(), Errno> {
    Err(Errno::ESRCH)
}

/// Does what a write asks for: nothing on the host.
pub(crate) fn apply(_id: CgId, _effect: Effect) {}

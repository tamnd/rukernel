//! Process file descriptors: `pidfd_open`, `pidfd_send_signal` and `pidfd_getfd`.
//!
//! A process file descriptor refers to one process, and the ID of the process cannot go to a
//! new process while the descriptor is open. `poll` gives `POLLIN` when the process ended. This
//! is the model of kernel/pid.c and kernel/fork.c of Linux.

use crate::cx::{Cx, SysResult};
use alloc::sync::Arc;
use core::any::Any;
use rk_abi::Errno;
use rk_abi::native::open::{O_EXCL, O_NONBLOCK, O_RDWR};
use rk_proc::signal::{NSIG, SI_USER, SIGINFO_SIZE, SigInfo};
use rk_proc::{Pid, Process};
use rk_vfs::file::{File, FileOps, events};

/// `PIDFD_NONBLOCK`: a wait for the process does not block.
const PIDFD_NONBLOCK: u32 = O_NONBLOCK;
/// `PIDFD_THREAD`: the descriptor refers to a thread. rukernel gives the process of the thread.
const PIDFD_THREAD: u32 = O_EXCL;

/// The operations of a process file descriptor.
struct PidFd {
    process: Arc<Process>,
}

impl FileOps for PidFd {
    fn pollable(&self) -> bool {
        true
    }

    fn poll(&self, _file: &File) -> u32 {
        if self.process.is_zombie() { events::POLLIN } else { 0 }
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

/// Makes a process file descriptor for `process`, for `pidfd_open` and `CLONE_PIDFD`. The
/// descriptor has `FD_CLOEXEC`, as in Linux.
///
/// # Errors
///
/// Gives `EMFILE` if the table is full.
pub(crate) fn open(cx: &Cx<'_>, process: Arc<Process>, flags: u32) -> Result<i32, Errno> {
    let file = File::with_ops(Arc::new(PidFd { process }), None, O_RDWR | flags);
    cx.files()?.lock().insert(file, true)
}

/// Gives the process of the process file descriptor `fd`.
///
/// # Errors
///
/// Gives `EBADF` if `fd` is not open, or if it is not a process file descriptor.
pub(crate) fn process_of(cx: &Cx<'_>, fd: u64) -> Result<Arc<Process>, Errno> {
    let file = cx.file(fd)?;
    let pidfd = file.ops().as_any().and_then(|a| a.downcast_ref::<PidFd>()).ok_or(Errno::EBADF)?;
    Ok(pidfd.process.clone())
}

pub(crate) fn pidfd_open(cx: &Cx<'_>, pid: u64, flags: u64) -> SysResult {
    let flags = u32::try_from(flags).map_err(|_| Errno::EINVAL)?;
    let pid = pid as i32;
    if flags & !(PIDFD_NONBLOCK | PIDFD_THREAD) != 0 || pid <= 0 {
        return Err(Errno::EINVAL);
    }
    let process = match rk_proc::find_process(pid as Pid) {
        Some(p) => p,
        // The ID of a thread that is not the leader gives `ENOENT`, as in Linux.
        None => match rk_proc::find_thread(pid as Pid) {
            Some(t) if flags & PIDFD_THREAD != 0 => t.process().clone(),
            Some(_) => return Err(Errno::ENOENT),
            None => return Err(Errno::ESRCH),
        },
    };
    Ok(open(cx, process, flags & PIDFD_NONBLOCK)? as u64)
}

pub(crate) fn pidfd_send_signal(
    cx: &Cx<'_>,
    fd: u64,
    sig: u64,
    uinfo: u64,
    flags: u64,
) -> SysResult {
    if flags != 0 || sig > u64::from(NSIG) {
        return Err(Errno::EINVAL);
    }
    let process = process_of(cx, fd)?;
    if process.is_zombie() {
        return Err(Errno::ESRCH);
    }
    let info = if uinfo == 0 {
        let mut info = SigInfo::new(sig as u32, SI_USER, cx.process().pid());
        info.uid = cx.process().cred().uid;
        info
    } else {
        let b = cx.read_bytes(uinfo, SIGINFO_SIZE)?;
        let mut raw = [0u8; SIGINFO_SIZE];
        raw.copy_from_slice(&b);
        let mut info = SigInfo::from_bytes(&raw);
        // As `rt_sigqueueinfo`: only the kernel sends a signal with a code of 0 or more to
        // another process.
        if info.signo != sig as u32 {
            return Err(Errno::EINVAL);
        }
        if info.code >= 0 && !Arc::ptr_eq(&process, cx.process()) {
            return Err(Errno::EPERM);
        }
        info.signo = sig as u32;
        info
    };
    if sig != 0 {
        rk_proc::send_signal(&process, info);
    }
    Ok(0)
}

pub(crate) fn pidfd_getfd(cx: &Cx<'_>, fd: u64, target: u64, flags: u64) -> SysResult {
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    let process = process_of(cx, fd)?;
    let files = process.files().ok_or(Errno::ESRCH)?;
    let file = files.lock().file(target as i32)?;
    Ok(cx.files()?.lock().insert(file, true)? as u64)
}

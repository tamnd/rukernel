//! Signal files: `signalfd` and `signalfd4`.
//!
//! A signal file takes the pending signals of a set from the thread that reads it, and gives each
//! signal as a `struct signalfd_siginfo`. The program blocks the signals of the set, so their
//! actions do not apply. This is the model of fs/signalfd.c of Linux.

use crate::cx::{Cx, SysResult};
use alloc::sync::Arc;
use core::any::Any;
use rk_abi::Errno;
use rk_abi::native::open::O_RDWR;
use rk_abi::native::signal::{SIGCHLD, SIGSYS};
use rk_abi::native::signalfd::{SFD_CLOEXEC, SFD_NONBLOCK};
use rk_abi::native::types::SignalfdSiginfo;
use rk_frame::sync::SpinLock;
use rk_proc::signal::{SI_TIMER, SYS_SECCOMP, SigInfo, SigSet};
use rk_vfs::file::{File, FileOps, events};
use rk_vfs::inode::Result;
use rk_vfs::wait::POLL_WAIT;
use zerocopy::{FromZeros, IntoBytes};

/// The size of `struct signalfd_siginfo`.
const SIZE: usize = 128;

/// The operations of a signal file.
struct SignalFd {
    mask: SpinLock<SigSet>,
}

impl SignalFd {
    fn mask(&self) -> SigSet {
        *self.mask.lock()
    }
}

/// Gives `info` as a `struct signalfd_siginfo`, as `signalfd_copyinfo` of Linux does.
fn siginfo(info: &SigInfo) -> SignalfdSiginfo {
    let mut s = SignalfdSiginfo::new_zeroed();
    s.ssi_signo = info.signo;
    s.ssi_errno = info.errno;
    s.ssi_code = info.code;
    if info.code == SI_TIMER {
        // The timer keeps its ID in `pid` and the overrun count in `uid`.
        s.ssi_tid = info.pid;
        s.ssi_overrun = info.uid;
    } else if info.signo == SIGSYS && info.code == SYS_SECCOMP {
        s.ssi_call_addr = info.addr;
        s.ssi_syscall = info.status;
        s.ssi_arch = info.uid;
    } else {
        s.ssi_pid = info.pid;
        s.ssi_uid = info.uid;
        s.ssi_addr = info.addr;
        if info.signo == SIGCHLD {
            s.ssi_status = info.status;
        }
    }
    s.ssi_ptr = info.value;
    s.ssi_int = info.value as i32;
    s
}

impl FileOps for SignalFd {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        let count = buf.len() / SIZE;
        if count == 0 {
            return Err(Errno::EINVAL);
        }
        let thread = rk_proc::current_thread().ok_or(Errno::EINVAL)?;
        let mask = self.mask();
        let nonblock = file.flags().nonblock();
        let first = POLL_WAIT.wait_interruptible(|| match thread.take_signal(mask) {
            Some(info) => Ok(Some(info)),
            None if nonblock => Err(Errno::EAGAIN),
            None => Ok(None),
        })?;
        buf[..SIZE].copy_from_slice(siginfo(&first).as_bytes());
        let mut n = 1;
        while n < count {
            let Some(info) = thread.take_signal(mask) else { break };
            buf[n * SIZE..(n + 1) * SIZE].copy_from_slice(siginfo(&info).as_bytes());
            n += 1;
        }
        Ok(n * SIZE)
    }

    fn poll(&self, _file: &File) -> u32 {
        let ready = rk_proc::current_thread()
            .is_some_and(|t| !SigSet(t.pending().0 & self.mask().0).is_empty());
        if ready { events::POLLIN } else { 0 }
    }

    fn pollable(&self) -> bool {
        true
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

pub(crate) fn signalfd4(cx: &Cx<'_>, fd: u64, mask: u64, size: u64, flags: u64) -> SysResult {
    let flags = u32::try_from(flags).map_err(|_| Errno::EINVAL)?;
    if flags & !(SFD_CLOEXEC | SFD_NONBLOCK) != 0 || size != 8 {
        return Err(Errno::EINVAL);
    }
    let set: u64 = cx.read_val(mask)?;
    let set = SigSet(set).without(SigSet::UNBLOCKABLE);
    let fd = fd as i32;
    if fd != -1 {
        let file = cx.file(fd as u64)?;
        let sfd =
            file.ops().as_any().and_then(|a| a.downcast_ref::<SignalFd>()).ok_or(Errno::EINVAL)?;
        *sfd.mask.lock() = set;
        rk_vfs::wait::poll_wake();
        return Ok(fd as u64);
    }
    let ops = SignalFd { mask: SpinLock::new(set) };
    let file = File::with_ops(Arc::new(ops), None, O_RDWR | (flags & SFD_NONBLOCK));
    Ok(cx.files()?.lock().insert(file, flags & SFD_CLOEXEC != 0)? as u64)
}

pub(crate) fn signalfd(cx: &Cx<'_>, fd: u64, mask: u64, size: u64) -> SysResult {
    signalfd4(cx, fd, mask, size, 0)
}

//! Yama, as security/yama/yama_lsm.c of Linux.
//!
//! Yama limits `PTRACE_ATTACH` with the value of `kernel.yama.ptrace_scope`:
//!
//! - 0: the usual checks of `ptrace` only.
//! - 1: a process can attach only to its descendants, to a process that named it (or any
//!   process) with `prctl(PR_SET_PTRACER)`, or with `CAP_SYS_PTRACE`.
//! - 2: a process can attach only with `CAP_SYS_PTRACE`.
//! - 3: no process can attach. The value cannot change after that.

use crate::process::{Process, current_thread, find_process, find_process_by_vpid, find_thread};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::cred::{self, Cred, cap};
use rk_vfs::inode::Result;
use rk_vfs::security::{BlobSizes, LsmId, LsmInfo, Order, SecurityHooks, Task, id};

/// `PR_SET_PTRACER` of include/uapi/linux/prctl.h.
pub const PR_SET_PTRACER: u32 = 0x5961_6d61;
/// `PR_SET_PTRACER_ANY`: any process can attach.
pub const PR_SET_PTRACER_ANY: u64 = u64::MAX;

/// `YAMA_SCOPE_RELATIONAL`, the default value.
const SCOPE_RELATIONAL: u32 = 1;
/// `YAMA_SCOPE_CAPABILITY`.
const SCOPE_CAPABILITY: u32 = 2;
/// `YAMA_SCOPE_NO_ATTACH`, the largest value.
const SCOPE_NO_ATTACH: u32 = 3;

/// The `PTRACE_MODE_ATTACH` bit of the mode of the `ptrace_access_check` hook.
const PTRACE_MODE_ATTACH: u32 = 0x02;

/// The value of `kernel.yama.ptrace_scope`.
static PTRACE_SCOPE: AtomicU32 = AtomicU32::new(SCOPE_RELATIONAL);

/// The exceptions of `PR_SET_PTRACER`: the tracee, and the tracer or `None` for any process, as
/// `struct ptrace_relation` of Linux. An entry with a process that went away has no effect.
type Relation = (Weak<Process>, Option<Weak<Process>>);

static RELATIONS: SpinLock<Vec<Relation>> = SpinLock::new(Vec::new());

/// The value of `kernel.yama.ptrace_scope`.
pub fn ptrace_scope() -> u32 {
    PTRACE_SCOPE.load(Ordering::Relaxed)
}

/// Writes `kernel.yama.ptrace_scope`, as `yama_dointvec_minmax` of Linux.
///
/// # Errors
///
/// Gives `EPERM` if the caller has no `CAP_SYS_PTRACE`, and `EINVAL` for a value out of the
/// range. After the value 3, the range is 3 only.
pub fn set_ptrace_scope(value: i64) -> Result<()> {
    if !cred::current().capable(cap::SYS_PTRACE) {
        return Err(Errno::EPERM);
    }
    let min = if ptrace_scope() == SCOPE_NO_ATTACH { SCOPE_NO_ATTACH } else { 0 };
    let value = u32::try_from(value).map_err(|_| Errno::EINVAL)?;
    if !(min..=SCOPE_NO_ATTACH).contains(&value) {
        return Err(Errno::EINVAL);
    }
    PTRACE_SCOPE.store(value, Ordering::Relaxed);
    Ok(())
}

/// Tells if Yama is an active module.
pub fn active() -> bool {
    rk_vfs::security::modules().iter().any(|m| m.info.id.id == id::YAMA)
}

/// The process of the task with the ID `pid`.
fn process_of(pid: u32) -> Option<Arc<Process>> {
    find_thread(pid).map(|t| t.process().clone()).or_else(|| find_process(pid))
}

/// Tells if `child` is `parent` or one of its descendants, as `task_is_descendant` of Linux.
fn is_descendant(parent: &Process, child: &Arc<Process>) -> bool {
    let mut walker = Some(child.clone());
    while let Some(w) = walker {
        if core::ptr::eq(Arc::as_ptr(&w), parent) {
            return true;
        }
        walker = w.parent();
    }
    false
}

/// Tells if `tracee` named `tracer` or any process with `PR_SET_PTRACER`, as
/// `ptracer_exception_found` of Linux.
fn exception_found(tracer: &Arc<Process>, tracee: &Process) -> bool {
    let relations = RELATIONS.lock();
    let Some((_, allowed)) =
        relations.iter().find(|(t, _)| core::ptr::eq(t.as_ptr(), tracee) && t.strong_count() > 0)
    else {
        return false;
    };
    match allowed {
        None => true,
        Some(p) => p.upgrade().is_some_and(|p| is_descendant(&p, tracer)),
    }
}

/// Sets the exception of the current process, as `yama_ptracer_add` and `yama_ptracer_del` of
/// Linux. `tracer` is `None` for any process. `del` removes the exception.
fn set_exception(tracee: &Arc<Process>, tracer: Option<&Arc<Process>>, del: bool) {
    let mut relations = RELATIONS.lock();
    relations.retain(|(t, p)| {
        t.strong_count() > 0
            && p.as_ref().is_none_or(|p| p.strong_count() > 0)
            && !core::ptr::eq(t.as_ptr(), Arc::as_ptr(tracee))
    });
    if !del {
        relations.push((Arc::downgrade(tracee), tracer.map(Arc::downgrade)));
    }
}

/// The hooks of Yama.
pub struct Yama;

impl SecurityHooks for Yama {
    /// `yama_ptrace_access_check`.
    fn ptrace_access_check(&self, cred: &Cred, child: &Task<'_>, mode: u32) -> Result<()> {
        if mode & PTRACE_MODE_ATTACH == 0 {
            return Ok(());
        }
        let allowed = match ptrace_scope() {
            SCOPE_RELATIONAL => {
                let me = current_thread().map(|t| t.process().clone());
                match (me, process_of(child.pid)) {
                    (Some(me), Some(target)) => {
                        is_descendant(&me, &target)
                            || exception_found(&me, &target)
                            || cred.ns_capable(&child.cred.user_ns, cap::SYS_PTRACE)
                    }
                    _ => false,
                }
            }
            SCOPE_CAPABILITY => cred.ns_capable(&child.cred.user_ns, cap::SYS_PTRACE),
            SCOPE_NO_ATTACH => false,
            _ => true,
        };
        if allowed { Ok(()) } else { Err(Errno::EPERM) }
    }

    /// `yama_ptrace_traceme`.
    fn ptrace_traceme(&self, parent: &Task<'_>) -> Result<()> {
        let allowed = match ptrace_scope() {
            SCOPE_CAPABILITY => parent.cred.ns_capable(&cred::current().user_ns, cap::SYS_PTRACE),
            SCOPE_NO_ATTACH => false,
            _ => true,
        };
        if allowed { Ok(()) } else { Err(Errno::EPERM) }
    }

    /// `yama_task_prctl`: `PR_SET_PTRACER` with 0 removes the exception, with
    /// `PR_SET_PTRACER_ANY` lets any process attach, and with a process ID lets that process and
    /// its ancestors attach. The exception is for the process, not for the thread.
    fn task_prctl(&self, option: u32, args: [u64; 4]) -> Option<Result<u64>> {
        if option != PR_SET_PTRACER {
            return None;
        }
        let me = current_thread()?.process().clone();
        let arg = args[0];
        if arg == 0 {
            set_exception(&me, None, true);
        } else if arg == PR_SET_PTRACER_ANY || arg as i32 == -1 {
            set_exception(&me, None, false);
        } else {
            let tracer = u32::try_from(arg).ok().and_then(|nr| find_process_by_vpid(&me, nr));
            let Some(tracer) = tracer else {
                return Some(Err(Errno::EINVAL));
            };
            set_exception(&me, Some(&tracer), false);
        }
        Some(Ok(0))
    }
}

/// Yama, `yama` in /sys/kernel/security/lsm.
pub static LSM: LsmInfo = LsmInfo {
    id: LsmId { name: "yama", id: id::YAMA },
    order: Order::Mutable,
    flags: 0,
    blobs: BlobSizes::NONE,
    hooks: &Yama,
};

//! `seccomp`, the `seccomp` options of `prctl`, and the check of each system call.
//!
//! A thread in the strict mode can call only `read`, `write`, `exit` and `rt_sigreturn`. A thread
//! in the filter mode runs its filters at each system call, after the stop of the tracer at the
//! entry, and the action of the filters tells what happens to the call. This is the model of
//! kernel/seccomp.c of Linux.

use crate::cx::{Cx, SysResult};
use crate::run::Entry;
use alloc::sync::Arc;
use rk_abi::Errno;
use rk_abi::native::signal::{SIGKILL, SIGSYS};
use rk_abi::native::syscalls as nr;
use rk_frame::user::UserContext;
use rk_proc::bpf::{self, INSN_SIZE};
use rk_proc::ptrace::{self, NO_SYSCALL, PTRACE_EVENT_SECCOMP};
use rk_proc::seccomp::{
    Filter, SECCOMP_MODE_DISABLED, SECCOMP_MODE_FILTER, SECCOMP_MODE_STRICT,
    SECCOMP_RET_ACTION_FULL, SECCOMP_RET_ALLOW, SECCOMP_RET_DATA, SECCOMP_RET_ERRNO,
    SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_KILL_THREAD, SECCOMP_RET_LOG, SECCOMP_RET_TRACE,
    SECCOMP_RET_TRAP, SECCOMP_RET_USER_NOTIF, run_filters,
};
use rk_proc::signal::SigInfo;
use rk_proc::{Thread, WaitStatus};

/// The operations of `seccomp`.
const SECCOMP_SET_MODE_STRICT: u64 = 0;
const SECCOMP_SET_MODE_FILTER: u64 = 1;
const SECCOMP_GET_ACTION_AVAIL: u64 = 2;
const SECCOMP_GET_NOTIF_SIZES: u64 = 3;

/// The flags of `SECCOMP_SET_MODE_FILTER`.
const SECCOMP_FILTER_FLAG_TSYNC: u64 = 1 << 0;
const SECCOMP_FILTER_FLAG_LOG: u64 = 1 << 1;
const SECCOMP_FILTER_FLAG_SPEC_ALLOW: u64 = 1 << 2;

/// The flags that rukernel accepts.
const FILTER_FLAGS: u64 =
    SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_LOG | SECCOMP_FILTER_FLAG_SPEC_ALLOW;

/// The options of `prctl`.
pub(crate) const PR_GET_SECCOMP: u64 = 21;
pub(crate) const PR_SET_SECCOMP: u64 = 22;
pub(crate) const PR_SET_NO_NEW_PRIVS: u64 = 38;
pub(crate) const PR_GET_NO_NEW_PRIVS: u64 = 39;

/// `AUDIT_ARCH_X86_64`: the architecture in `seccomp_data`.
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

/// The highest error number that `SECCOMP_RET_ERRNO` gives.
const MAX_ERRNO: u32 = 4095;

/// The sizes of the structures of the notifications of `seccomp`.
const SECCOMP_NOTIF_SIZE: u16 = 80;
const SECCOMP_NOTIF_RESP_SIZE: u16 = 24;

/// Checks the system call `number` of `thread` against its `seccomp` mode. Gives the number to
/// run, `NO_SYSCALL` if the call must not run, or the exit of the thread or of its group.
pub(crate) fn check(thread: &Arc<Thread>, regs: &mut UserContext, number: u64) -> Entry {
    match thread.seccomp_mode() {
        SECCOMP_MODE_DISABLED => Entry::Run(number),
        _ if thread.seccomp_suspended() => Entry::Run(number),
        SECCOMP_MODE_STRICT => {
            let allowed = [nr::READ, nr::WRITE, nr::EXIT, nr::RT_SIGRETURN];
            if allowed.iter().any(|&n| u64::from(n) == number) {
                Entry::Run(number)
            } else {
                Entry::ThreadExit(WaitStatus::signaled(SIGKILL, false))
            }
        }
        _ => filter(thread, regs, number, false),
    }
}

/// Runs the filters of `thread` on the system call `number` and does the action, as
/// `__seccomp_filter` of Linux does. `recheck` is true for the second run after a stop of
/// `SECCOMP_RET_TRACE`, and then `SECCOMP_RET_TRACE` lets the call run.
fn filter(thread: &Arc<Thread>, regs: &mut UserContext, number: u64, recheck: bool) -> Entry {
    let Some(chain) = thread.seccomp().filter else { return Entry::Run(number) };
    let nr = number as i32;
    let ip = regs.regs().rip;
    let data = bpf::seccomp_data(nr, AUDIT_ARCH_X86_64, ip, regs.syscall_args());
    let (ret, _matched) = run_filters(&chain, &data);
    let action = ret & SECCOMP_RET_ACTION_FULL;
    let value = ret & SECCOMP_RET_DATA;
    match action {
        SECCOMP_RET_ERRNO => {
            regs.set_syscall_return(-i64::from(value.min(MAX_ERRNO)) as u64);
            Entry::Run(NO_SYSCALL)
        }
        SECCOMP_RET_TRAP => {
            // The return value is the number of the call again, as `syscall_rollback` of Linux
            // makes it, and the handler of `SIGSYS` sees it.
            regs.set_syscall_return(number);
            thread.force_signal(SigInfo::seccomp(nr, AUDIT_ARCH_X86_64, ip, value as i32));
            Entry::Run(NO_SYSCALL)
        }
        SECCOMP_RET_TRACE => {
            if recheck {
                return Entry::Run(number);
            }
            // Without a tracer that asked for the event, the call gives `ENOSYS`.
            if !thread.trace_event_enabled(PTRACE_EVENT_SECCOMP) {
                return Entry::Run(NO_SYSCALL);
            }
            let resumed =
                ptrace::event(thread, regs, number, PTRACE_EVENT_SECCOMP, u64::from(value));
            if thread.is_killed() {
                return Entry::GroupExit;
            }
            // The tracer can change the call, or skip it with -1.
            let number = resumed.map_or(number, |r| r.orig_rax);
            if (number as i64) < 0 {
                return Entry::Run(NO_SYSCALL);
            }
            filter(thread, regs, number, true)
        }
        // rukernel has no listener for the notifications yet, thus the call gives `ENOSYS`.
        SECCOMP_RET_USER_NOTIF => Entry::Run(NO_SYSCALL),
        SECCOMP_RET_LOG | SECCOMP_RET_ALLOW => Entry::Run(number),
        SECCOMP_RET_KILL_THREAD if thread.process().threads().len() > 1 => {
            Entry::ThreadExit(WaitStatus::signaled(SIGSYS, false))
        }
        _ => {
            // `SECCOMP_RET_KILL_PROCESS`, an unknown action, and `SECCOMP_RET_KILL_THREAD` in the
            // last thread end the process with `SIGSYS`. The handler of the signal does not run,
            // and the tracer does not see the signal.
            regs.set_syscall_return(number);
            let process = thread.process();
            rk_proc::kill_group(process, process.fatal_status(SIGSYS));
            Entry::GroupExit
        }
    }
}

/// Reads the program of a `struct sock_fprog` at `addr` and checks it.
fn read_prog(cx: &Cx<'_>, addr: u64) -> Result<alloc::vec::Vec<bpf::Insn>, Errno> {
    let raw = cx.read_bytes(addr, 16)?;
    let len = usize::from(u16::from_ne_bytes([raw[0], raw[1]]));
    let mut ptr = [0u8; 8];
    ptr.copy_from_slice(&raw[8..16]);
    if len == 0 || len > bpf::BPF_MAXINSNS {
        return Err(Errno::EINVAL);
    }
    let prog = bpf::from_bytes(&cx.read_bytes(u64::from_ne_bytes(ptr), len * INSN_SIZE)?);
    bpf::check(&prog)?;
    Ok(prog)
}

/// `SECCOMP_SET_MODE_FILTER`: adds a filter to the chain of the thread. All processes of rukernel
/// run as root, thus the thread does not need the no_new_privs bit.
fn set_mode_filter(cx: &Cx<'_>, flags: u64, uprog: u64) -> SysResult {
    if flags & !FILTER_FLAGS != 0 {
        return Err(Errno::EINVAL);
    }
    let prog = read_prog(cx, uprog)?;
    let filter = Filter::new(prog, flags & SECCOMP_FILTER_FLAG_LOG != 0);
    cx.thread.attach_seccomp_filter(filter)?;
    Ok(0)
}

/// Tells if `action` is an action that the kernel knows, for `SECCOMP_GET_ACTION_AVAIL`.
fn action_avail(action: u32) -> bool {
    matches!(
        action,
        SECCOMP_RET_KILL_PROCESS
            | SECCOMP_RET_KILL_THREAD
            | SECCOMP_RET_TRAP
            | SECCOMP_RET_ERRNO
            | SECCOMP_RET_USER_NOTIF
            | SECCOMP_RET_TRACE
            | SECCOMP_RET_LOG
            | SECCOMP_RET_ALLOW
    )
}

pub(crate) fn seccomp(cx: &Cx<'_>, op: u64, flags: u64, uargs: u64) -> SysResult {
    match op {
        SECCOMP_SET_MODE_STRICT => {
            if flags != 0 || uargs != 0 {
                return Err(Errno::EINVAL);
            }
            cx.thread.set_seccomp_strict()?;
            Ok(0)
        }
        SECCOMP_SET_MODE_FILTER => set_mode_filter(cx, flags, uargs),
        SECCOMP_GET_ACTION_AVAIL => {
            if flags != 0 {
                return Err(Errno::EINVAL);
            }
            let action: u32 = cx.read_val(uargs)?;
            if action_avail(action) { Ok(0) } else { Err(Errno::EOPNOTSUPP) }
        }
        SECCOMP_GET_NOTIF_SIZES => {
            if flags != 0 {
                return Err(Errno::EINVAL);
            }
            let sizes =
                [SECCOMP_NOTIF_SIZE, SECCOMP_NOTIF_RESP_SIZE, bpf::SECCOMP_DATA_SIZE as u16];
            cx.write_val(uargs, &sizes)?;
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

/// The `seccomp` options of `prctl`.
pub(crate) fn prctl(cx: &Cx<'_>, option: u64, args: [u64; 4]) -> SysResult {
    match option {
        PR_GET_SECCOMP => Ok(u64::from(cx.thread.seccomp_mode())),
        PR_SET_SECCOMP => match u32::try_from(args[0]) {
            Ok(SECCOMP_MODE_STRICT) => seccomp(cx, SECCOMP_SET_MODE_STRICT, 0, 0),
            Ok(SECCOMP_MODE_FILTER) => seccomp(cx, SECCOMP_SET_MODE_FILTER, 0, args[1]),
            _ => Err(Errno::EINVAL),
        },
        PR_SET_NO_NEW_PRIVS => {
            if args[0] != 1 || args[1..].iter().any(|&a| a != 0) {
                return Err(Errno::EINVAL);
            }
            cx.thread.set_no_new_privs();
            Ok(0)
        }
        PR_GET_NO_NEW_PRIVS => {
            if args.iter().any(|&a| a != 0) {
                return Err(Errno::EINVAL);
            }
            Ok(u64::from(cx.thread.no_new_privs()))
        }
        _ => Err(Errno::EINVAL),
    }
}

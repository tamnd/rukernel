//! The system calls of processes: `clone`, `execve`, `exit`, `wait4`, `kill` and the IDs.

use crate::cx::{Cx, SysResult};
use crate::run::{random16, start_thread};
use rk_abi::Errno;
use rk_abi::native::sched::{
    CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID, CLONE_FILES, CLONE_FS, CLONE_PARENT_SETTID,
    CLONE_SETTLS, CLONE_SIGHAND, CLONE_THREAD, CLONE_VFORK, CLONE_VM,
};
use rk_abi::native::signal::{
    SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK, SIGCHLD, SIGCONT, SIGKILL, SIGSTOP, SIGTSTP, SIGTTIN,
    SIGTTOU, SIGURG, SIGWINCH,
};
use rk_abi::native::wait::{WCONTINUED, WNOHANG, WUNTRACED};
use rk_frame::task::yield_now;
use rk_proc::exec::{ExecArgs, exec};
use rk_proc::{ForkShare, Pid, Process, WaitStatus, WaitTarget};

/// The number of signals. Linux names it `_NSIG`.
const NSIG: u64 = 64;

/// The `option` values of `prctl` that R1 has.
const PR_SET_PDEATHSIG: u64 = 1;
const PR_GET_PDEATHSIG: u64 = 2;
const PR_GET_DUMPABLE: u64 = 3;
const PR_SET_DUMPABLE: u64 = 4;
const PR_SET_NAME: u64 = 15;
const PR_GET_NAME: u64 = 16;

/// The `code` values of `arch_prctl`, from arch/x86/include/uapi/asm/prctl.h.
const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;

pub(crate) fn sched_yield() -> SysResult {
    yield_now();
    Ok(0)
}

/// Checks the arguments of `rt_sigaction` and gives a zero old action. The signal state comes
/// with the signal delivery of R1, issue #57.
pub(crate) fn rt_sigaction(cx: &Cx<'_>, sig: u64, act: u64, oact: u64, size: u64) -> SysResult {
    if size != 8 || sig == 0 || sig > NSIG {
        return Err(Errno::EINVAL);
    }
    if act != 0 && (sig == u64::from(SIGKILL) || sig == u64::from(SIGSTOP)) {
        return Err(Errno::EINVAL);
    }
    if act != 0 {
        cx.read_bytes(act, 32)?;
    }
    cx.write_opt(oact, &[0u64; 4])?;
    Ok(0)
}

/// Checks the arguments of `rt_sigprocmask` and gives an empty old mask.
pub(crate) fn rt_sigprocmask(cx: &Cx<'_>, how: u64, set: u64, oset: u64, size: u64) -> SysResult {
    if size != 8 {
        return Err(Errno::EINVAL);
    }
    if set != 0 {
        if !matches!(how as u32, SIG_BLOCK | SIG_UNBLOCK | SIG_SETMASK) {
            return Err(Errno::EINVAL);
        }
        cx.read_val::<u64>(set)?;
    }
    cx.write_opt(oset, &0u64)?;
    Ok(0)
}

pub(crate) fn clone(
    cx: &Cx<'_>,
    flags: u64,
    stack: u64,
    ptid: u64,
    ctid: u64,
    tls: u64,
) -> SysResult {
    if flags & CLONE_THREAD != 0 && flags & CLONE_SIGHAND == 0 {
        return Err(Errno::EINVAL);
    }
    if flags & CLONE_SIGHAND != 0 && flags & CLONE_VM == 0 {
        return Err(Errno::EINVAL);
    }
    let thread = if flags & CLONE_THREAD != 0 {
        rk_proc::new_thread(cx.thread)?
    } else {
        // R1 has no wait for `CLONE_VFORK`, so the child gets a copy of the memory and the parent
        // continues at once. A child that calls only `execve` or `_exit` sees no change.
        let share = ForkShare {
            vm: flags & CLONE_VM != 0 && flags & CLONE_VFORK == 0,
            files: flags & CLONE_FILES != 0,
            fs: flags & CLONE_FS != 0,
        };
        rk_proc::fork(cx.thread, share)?
    };
    let tid = thread.tid();
    let mut regs = *cx.regs;
    regs.set_syscall_return(0);
    if stack != 0 {
        regs.regs_mut().rsp = stack;
    }
    if flags & CLONE_SETTLS != 0 {
        regs.set_fs_base(tls);
    }
    if flags & CLONE_PARENT_SETTID != 0 {
        cx.write_val(ptid, &tid)?;
    }
    if flags & CLONE_CHILD_SETTID != 0
        && let Some(vm) = thread.process().vm()
    {
        vm.write(ctid as usize, &tid.to_ne_bytes())?;
    }
    if flags & CLONE_CHILD_CLEARTID != 0 {
        thread.set_clear_child_tid(ctid as usize);
    }
    if let Err(e) = start_thread(thread.clone(), regs) {
        rk_proc::exit_thread(&thread, WaitStatus::exited(0));
        return Err(e);
    }
    Ok(u64::from(tid))
}

pub(crate) fn fork(cx: &Cx<'_>) -> SysResult {
    clone(cx, u64::from(SIGCHLD), 0, 0, 0, 0)
}

pub(crate) fn vfork(cx: &Cx<'_>) -> SysResult {
    clone(cx, CLONE_VM | CLONE_VFORK | u64::from(SIGCHLD), 0, 0, 0, 0)
}

pub(crate) fn execve(cx: &mut Cx<'_>, path: u64, argv: u64, envp: u64) -> SysResult {
    let path = cx.read_path(path)?;
    let mut total = 0;
    let argv = cx.read_strings(argv, &mut total)?;
    let envp = cx.read_strings(envp, &mut total)?;
    let image = exec(cx.thread, ExecArgs { path, argv, envp }, random16())?;
    *cx.regs = rk_frame::user::UserContext::new(
        rk_frame::addr::VirtAddr::new(image.entry),
        rk_frame::addr::VirtAddr::new(image.sp),
    );
    Ok(0)
}

pub(crate) fn exit(cx: &mut Cx<'_>, code: u64) -> SysResult {
    cx.exit = Some(WaitStatus::exited(code as i32 & 0xff));
    Ok(0)
}

pub(crate) fn exit_group(cx: &mut Cx<'_>, code: u64) -> SysResult {
    let status = WaitStatus::exited(code as i32 & 0xff);
    rk_proc::exit_group(cx.thread, status);
    cx.exit = Some(status);
    Ok(0)
}

pub(crate) fn wait4(cx: &Cx<'_>, pid: u64, status: u64, options: u64, rusage: u64) -> SysResult {
    let options = options as u32;
    if options & !(WNOHANG | WUNTRACED | WCONTINUED | 0xe000_0000) != 0 {
        return Err(Errno::EINVAL);
    }
    let pid = pid as i32;
    let target = match pid {
        -1 => WaitTarget::Any,
        0 => WaitTarget::Pgid(cx.process().pgid()),
        p if p > 0 => WaitTarget::Pid(p as Pid),
        i32::MIN => return Err(Errno::ESRCH),
        p => WaitTarget::Pgid(p.unsigned_abs()),
    };
    let thread = cx.thread.clone();
    let found = rk_proc::wait_child(cx.process(), target, options & WNOHANG != 0, true, || {
        thread.is_killed()
    })?;
    let Some((child, code)) = found else { return Ok(0) };
    cx.write_opt(status, &code.0)?;
    cx.write_opt(rusage, &<rk_abi::native::types::Rusage as zerocopy::FromZeros>::new_zeroed())?;
    Ok(u64::from(child))
}

/// Tells if the default action of `sig` ends the process. R1 has no stopped state, so a stop
/// signal has no effect.
fn ends_process(sig: u32) -> bool {
    !matches!(
        sig,
        0 | SIGCHLD | SIGCONT | SIGURG | SIGWINCH | SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU
    )
}

/// Sends `sig` to `process`. R1 has no signal handlers, so a signal does its default action.
fn signal_process(process: &Process, sig: u32) {
    if ends_process(sig) {
        rk_proc::kill_group(process, WaitStatus::signaled(sig, false));
    }
}

/// Sends `sig` to each process in the group `pgid`. Gives `ESRCH` if the group is empty.
pub(crate) fn signal_group(pgid: Pid, sig: u32) -> Result<(), Errno> {
    let members: alloc::vec::Vec<_> =
        rk_proc::processes().into_iter().filter(|p| p.pgid() == pgid && !p.is_zombie()).collect();
    if members.is_empty() {
        return Err(Errno::ESRCH);
    }
    for p in members {
        signal_process(&p, sig);
    }
    Ok(())
}

pub(crate) fn kill(cx: &Cx<'_>, pid: u64, sig: u64) -> SysResult {
    if sig > NSIG {
        return Err(Errno::EINVAL);
    }
    let sig = sig as u32;
    let pid = pid as i32;
    match pid {
        0 => signal_group(cx.process().pgid(), sig)?,
        -1 => {
            for p in rk_proc::processes() {
                if p.pid() != rk_proc::INIT_PID && p.pid() != cx.process().pid() {
                    signal_process(&p, sig);
                }
            }
        }
        p if p > 0 => {
            let target = rk_proc::find_process(p as Pid)
                .or_else(|| rk_proc::find_thread(p as Pid).map(|t| t.process().clone()))
                .ok_or(Errno::ESRCH)?;
            signal_process(&target, sig);
        }
        i32::MIN => return Err(Errno::ESRCH),
        p => signal_group(p.unsigned_abs(), sig)?,
    }
    Ok(0)
}

pub(crate) fn setpgid(cx: &Cx<'_>, pid: u64, pgid: u64) -> SysResult {
    let pid = pid as i32;
    let pgid = pgid as i32;
    if pgid < 0 {
        return Err(Errno::EINVAL);
    }
    let me = cx.process();
    let target = if pid == 0 || pid as Pid == me.pid() {
        me.clone()
    } else {
        me.children().into_iter().find(|c| c.pid() == pid as Pid).ok_or(Errno::ESRCH)?
    };
    if target.sid() != me.sid() {
        return Err(Errno::EPERM);
    }
    if target.sid() == target.pid() {
        return Err(Errno::EPERM);
    }
    let pgid = if pgid == 0 { target.pid() } else { pgid as Pid };
    if pgid != target.pid()
        && !rk_proc::processes().iter().any(|p| p.pgid() == pgid && p.sid() == me.sid())
    {
        return Err(Errno::EPERM);
    }
    target.set_pgid(pgid);
    Ok(0)
}

fn find(cx: &Cx<'_>, pid: u64) -> Result<alloc::sync::Arc<Process>, Errno> {
    if pid as i32 == 0 {
        return Ok(cx.process().clone());
    }
    rk_proc::find_process(pid as Pid).ok_or(Errno::ESRCH)
}

pub(crate) fn getpgid(cx: &Cx<'_>, pid: u64) -> SysResult {
    Ok(u64::from(find(cx, pid)?.pgid()))
}

pub(crate) fn getsid(cx: &Cx<'_>, pid: u64) -> SysResult {
    Ok(u64::from(find(cx, pid)?.sid()))
}

pub(crate) fn prctl(cx: &Cx<'_>, option: u64, arg2: u64) -> SysResult {
    match option {
        PR_SET_NAME => {
            let name = cx.vm()?.read_cstr(arg2 as usize, 16).or_else(|e| {
                if e == Errno::ENAMETOOLONG { cx.read_bytes(arg2, 15) } else { Err(e) }
            })?;
            cx.process().set_comm(&name);
            Ok(0)
        }
        PR_GET_NAME => {
            let mut name = [0u8; 16];
            let comm = cx.process().comm();
            let n = comm.len().min(15);
            name[..n].copy_from_slice(&comm[..n]);
            cx.write_bytes(arg2, &name)?;
            Ok(0)
        }
        PR_SET_PDEATHSIG => {
            if arg2 > NSIG {
                return Err(Errno::EINVAL);
            }
            Ok(0)
        }
        PR_GET_PDEATHSIG => {
            cx.write_val(arg2, &0i32)?;
            Ok(0)
        }
        PR_GET_DUMPABLE => Ok(1),
        PR_SET_DUMPABLE => {
            if arg2 > 1 {
                return Err(Errno::EINVAL);
            }
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

pub(crate) fn arch_prctl(cx: &mut Cx<'_>, code: u64, addr: u64) -> SysResult {
    match code {
        ARCH_SET_FS => {
            if addr >= rk_frame::user::USER_END as u64 {
                return Err(Errno::EPERM);
            }
            cx.regs.set_fs_base(addr);
            Ok(0)
        }
        ARCH_GET_FS => {
            let base = cx.regs.fs_base();
            cx.write_val(addr, &base)?;
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

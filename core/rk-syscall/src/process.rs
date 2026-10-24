//! The system calls of processes: `clone`, `execve`, `exit`, `wait4` and the IDs.

use crate::cx::{Cx, SysResult};
use crate::run::{random16, start_thread};
use rk_abi::Errno;
use rk_abi::native::sched::{
    CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID, CLONE_FILES, CLONE_FS, CLONE_PARENT,
    CLONE_PARENT_SETTID, CLONE_SETTLS, CLONE_SIGHAND, CLONE_THREAD, CLONE_VFORK, CLONE_VM,
};
use rk_abi::native::signal::SIGCHLD;
use rk_abi::native::wait::{WCONTINUED, WNOHANG, WUNTRACED};
use rk_frame::task::yield_now;
use rk_proc::exec::{ExecArgs, exec};
use rk_proc::{ForkShare, Pid, Process, VforkDone, WaitStatus, WaitTarget};

/// The number of signals. Linux names it `_NSIG`.
const NSIG: u64 = 64;

/// The bits of the `clone` flags that hold the exit signal.
const CSIGNAL: u64 = 0xff;

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
        let share = ForkShare {
            vm: flags & CLONE_VM != 0,
            files: flags & CLONE_FILES != 0,
            fs: flags & CLONE_FS != 0,
            exit_signal: (flags & CSIGNAL) as u32,
            parent: flags & CLONE_PARENT != 0,
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
    let vfork = (flags & CLONE_VFORK != 0).then(VforkDone::new);
    if let Some(done) = &vfork {
        thread.set_vfork_done(done.clone());
    }
    if let Err(e) = start_thread(thread.clone(), regs) {
        rk_proc::exit_thread(&thread, WaitStatus::exited(0));
        return Err(e);
    }
    if let Some(done) = vfork {
        done.wait();
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
    // The new program has no robust list. The locks in the list of the old program are dead.
    let image =
        exec(cx.thread, ExecArgs { path, argv, envp }, random16(), crate::futex::exit_robust_list)?;
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
        thread.signal_pending()
    })?;
    let Some((child, code)) = found else { return Ok(0) };
    cx.write_opt(status, &code.0)?;
    cx.write_opt(rusage, &<rk_abi::native::types::Rusage as zerocopy::FromZeros>::new_zeroed())?;
    Ok(u64::from(child))
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

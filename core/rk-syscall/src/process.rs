//! The system calls of processes: `clone`, `execve`, `exit`, `wait4` and the IDs.

use crate::cx::{Cx, SysResult};
use crate::run::{random16, start_thread};
use alloc::sync::Arc;
use rk_abi::Errno;
use rk_abi::native::sched::{
    CLONE_ARGS_SIZE_VER0, CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID, CLONE_CLEAR_SIGHAND,
    CLONE_DETACHED, CLONE_FILES, CLONE_FS, CLONE_INTO_CGROUP, CLONE_NEWCGROUP, CLONE_NEWIPC,
    CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWTIME, CLONE_NEWUSER, CLONE_NEWUTS,
    CLONE_PARENT, CLONE_PARENT_SETTID, CLONE_PIDFD, CLONE_PTRACE, CLONE_SETTLS, CLONE_SIGHAND,
    CLONE_SYSVSEM, CLONE_THREAD, CLONE_UNTRACED, CLONE_VFORK, CLONE_VM,
};
use rk_abi::native::signal::SIGCHLD;
use rk_abi::native::types::CloneArgs;
use rk_abi::native::wait::{
    P_ALL, P_PGID, P_PID, P_PIDFD, WCONTINUED, WEXITED, WNOHANG, WNOWAIT, WSTOPPED, WUNTRACED,
};
use rk_frame::sync::SpinLock;
use rk_frame::task::yield_now;
use rk_proc::exec::{ExecArgs, exec};
use rk_proc::ptrace::{
    self, PTRACE_EVENT_CLONE, PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK, PTRACE_EVENT_VFORK_DONE,
};
use rk_proc::signal::{CLD_TRAPPED, SigInfo};
use rk_proc::{
    ForkShare, Pid, Process, VforkDone, WaitOptions, WaitResult, WaitStatus, WaitTarget,
};
use zerocopy::FromZeros;

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

/// The flags of `unshare` that make a new namespace. rukernel has no namespaces, thus they give
/// `EINVAL`, as Linux without `CONFIG_NAMESPACES` gives.
const CLONE_NEW_ANY: u64 = CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET
    | CLONE_NEWTIME;

/// `unshare`: the process gets its own copy of the parts that it shares, as kernel/fork.c of
/// Linux does.
pub(crate) fn unshare(cx: &Cx<'_>, flags: u64) -> SysResult {
    let known = CLONE_THREAD
        | CLONE_FS
        | CLONE_FILES
        | CLONE_SIGHAND
        | CLONE_VM
        | CLONE_SYSVSEM
        | CLONE_NEW_ANY;
    if flags & !known != 0 || flags & CLONE_NEW_ANY != 0 {
        return Err(Errno::EINVAL);
    }
    let process = cx.process();
    // A process with more than one thread cannot leave its group, its handlers or its memory.
    if flags & (CLONE_THREAD | CLONE_SIGHAND | CLONE_VM) != 0 && process.threads().len() > 1 {
        return Err(Errno::EINVAL);
    }
    if flags & CLONE_FILES != 0 {
        let table = cx.files()?.lock().clone();
        process.set_files(Arc::new(SpinLock::new(table)));
    }
    if flags & CLONE_FS != 0
        && let Some(fs) = process.fs()
    {
        let context = fs.lock().clone();
        process.set_fs(Arc::new(SpinLock::new(context)));
    }
    Ok(0)
}

pub(crate) fn sched_yield() -> SysResult {
    yield_now();
    Ok(0)
}

pub(crate) fn clone(
    cx: &mut Cx<'_>,
    flags: u64,
    stack: u64,
    ptid: u64,
    ctid: u64,
    tls: u64,
) -> SysResult {
    let args = CloneArgs {
        flags: flags & !CSIGNAL,
        exit_signal: flags & CSIGNAL,
        stack,
        parent_tid: ptid,
        child_tid: ctid,
        tls,
        // `clone` writes the process file descriptor at the place of the parent TID.
        pidfd: ptid,
        ..CloneArgs::new_zeroed()
    };
    // The two values go to the same place, so `clone` cannot have both.
    if flags & CLONE_PIDFD != 0 && flags & CLONE_PARENT_SETTID != 0 {
        return Err(Errno::EINVAL);
    }
    // `clone` takes the low 32 bits of the flags. The bits above are only for `clone3`.
    do_clone(cx, &CloneArgs { flags: args.flags & 0xffff_ffff, ..args }, stack)
}

/// The largest `struct clone_args` that `clone3` reads. Linux gives `E2BIG` for a larger one.
const CLONE_ARGS_MAX: u64 = 4096;

/// `clone3`, as `copy_clone_args_from_user` and `clone3_args_valid` of Linux check it. The stack
/// of `clone3` is the lowest address and a size, and the new thread starts at the top. The cgroup
/// and `set_tid` are not in R2, so they give `EINVAL`.
pub(crate) fn clone3(cx: &mut Cx<'_>, uargs: u64, size: u64) -> SysResult {
    if size > CLONE_ARGS_MAX {
        return Err(Errno::E2BIG);
    }
    if size < CLONE_ARGS_SIZE_VER0 {
        return Err(Errno::EINVAL);
    }
    let known = size_of::<CloneArgs>();
    let mut bytes = alloc::vec![0u8; (size as usize).max(known)];
    cx.vm()?.read(uargs as usize, &mut bytes[..size as usize])?;
    if bytes[known..].iter().any(|&b| b != 0) {
        return Err(Errno::E2BIG);
    }
    let args = <CloneArgs as zerocopy::FromBytes>::read_from_bytes(&bytes[..known])
        .map_err(|_| Errno::EINVAL)?;
    let flags = args.flags;
    let unsupported = CLONE_INTO_CGROUP;
    if flags & (CLONE_DETACHED | CSIGNAL | unsupported) != 0
        || flags & !(0xffff_ffff | CLONE_CLEAR_SIGHAND) != 0
        || args.set_tid != 0
        || args.set_tid_size != 0
        || args.exit_signal >= NSIG
        || (flags & CLONE_SIGHAND != 0 && flags & CLONE_CLEAR_SIGHAND != 0)
        || (flags & (CLONE_THREAD | CLONE_PARENT) != 0 && args.exit_signal != 0)
        || ((args.stack == 0) != (args.stack_size == 0))
    {
        return Err(Errno::EINVAL);
    }
    let top = if args.stack == 0 {
        0
    } else {
        args.stack.checked_add(args.stack_size).ok_or(Errno::EINVAL)?
    };
    do_clone(cx, &args, top)
}

/// Makes a new thread or process for `clone` and `clone3`. `stack` is the stack pointer of the
/// new thread, or 0 for the stack pointer of the caller. A tracer that asked for the event of the
/// call traces the new thread too.
fn do_clone(cx: &mut Cx<'_>, args: &CloneArgs, stack: u64) -> SysResult {
    let flags = args.flags;
    if flags & CLONE_THREAD != 0 && flags & CLONE_SIGHAND == 0 {
        return Err(Errno::EINVAL);
    }
    if flags & CLONE_SIGHAND != 0 && flags & CLONE_VM == 0 {
        return Err(Errno::EINVAL);
    }
    if flags & CLONE_PIDFD != 0 && flags & (CLONE_THREAD | CLONE_DETACHED) != 0 {
        return Err(Errno::EINVAL);
    }
    let thread = if flags & CLONE_THREAD != 0 {
        rk_proc::new_thread(cx.thread)?
    } else {
        let share = ForkShare {
            vm: flags & CLONE_VM != 0,
            files: flags & CLONE_FILES != 0,
            fs: flags & CLONE_FS != 0,
            exit_signal: args.exit_signal as u32,
            parent: flags & CLONE_PARENT != 0,
        };
        rk_proc::fork(cx.thread, share)?
    };
    if flags & CLONE_CLEAR_SIGHAND != 0 {
        // A handler goes back to the default action, and an ignored signal stays ignored.
        thread.process().reset_actions();
    }
    let tid = thread.tid();
    let mut regs = *cx.regs;
    regs.set_syscall_return(0);
    if stack != 0 {
        regs.regs_mut().rsp = stack;
    }
    if flags & CLONE_SETTLS != 0 {
        regs.set_fs_base(args.tls);
    }
    if flags & CLONE_PARENT_SETTID != 0 {
        cx.write_val(args.parent_tid, &tid)?;
    }
    if flags & CLONE_PIDFD != 0 {
        let fd = crate::pidfd::open(cx, thread.process().clone(), 0)?;
        cx.write_val(args.pidfd, &fd)?;
    }
    if flags & CLONE_CHILD_SETTID != 0
        && let Some(vm) = thread.process().vm()
    {
        vm.write(args.child_tid as usize, &tid.to_ne_bytes())?;
    }
    if flags & CLONE_CHILD_CLEARTID != 0 {
        thread.set_clear_child_tid(args.child_tid as usize);
    }
    let vfork = (flags & CLONE_VFORK != 0).then(VforkDone::new);
    if let Some(done) = &vfork {
        thread.set_vfork_done(done.clone());
    }
    let event = if flags & CLONE_VFORK != 0 {
        PTRACE_EVENT_VFORK
    } else if args.exit_signal != u64::from(SIGCHLD) {
        PTRACE_EVENT_CLONE
    } else {
        PTRACE_EVENT_FORK
    };
    let traced = flags & CLONE_UNTRACED == 0
        && (cx.thread.trace_event_enabled(event)
            || (flags & CLONE_PTRACE != 0 && cx.thread.is_traced()));
    if traced {
        ptrace::attach_child(cx.thread, &thread);
    }
    if let Err(e) = start_thread(thread.clone(), regs) {
        rk_proc::exit_thread(&thread, WaitStatus::exited(0));
        return Err(e);
    }
    ptrace::event(cx.thread, cx.regs, cx.number, event, u64::from(tid));
    if let Some(done) = vfork {
        done.wait();
        ptrace::event(cx.thread, cx.regs, cx.number, PTRACE_EVENT_VFORK_DONE, u64::from(tid));
    }
    Ok(u64::from(tid))
}

pub(crate) fn fork(cx: &mut Cx<'_>) -> SysResult {
    clone(cx, u64::from(SIGCHLD), 0, 0, 0, 0)
}

pub(crate) fn vfork(cx: &mut Cx<'_>) -> SysResult {
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
    cx.regs.set_syscall_return(0);
    // rukernel keeps the thread ID in `execve`, so the old ID is the ID of the thread.
    ptrace::exec_event(cx.thread, cx.regs, cx.number, cx.thread.tid());
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

/// The flags `__WNOTHREAD`, `__WALL` and `__WCLONE` of the waits. `__WALL` and `__WCLONE` apply
/// to the traced threads. rukernel has one wait queue for each process, so `__WNOTHREAD` changes
/// nothing.
const WAIT_LINUX_FLAGS: u32 = 0xe000_0000;
const WALL: u32 = 0x4000_0000;
const WCLONE: u32 = 0x8000_0000;

/// Waits for a child with `options`, for `wait4` and `waitid`.
fn wait_child(cx: &Cx<'_>, target: WaitTarget, options: u32) -> Result<Option<WaitResult>, Errno> {
    let options = WaitOptions {
        exited: options & WEXITED != 0,
        stopped: options & WSTOPPED != 0,
        continued: options & WCONTINUED != 0,
        nohang: options & WNOHANG != 0,
        nowait: options & WNOWAIT != 0,
        all: options & WALL != 0,
        clone: options & WCLONE != 0,
    };
    let thread = cx.thread.clone();
    rk_proc::wait_child(cx.process(), target, options, || thread.signal_pending())
}

pub(crate) fn wait4(cx: &Cx<'_>, pid: u64, status: u64, options: u64, rusage: u64) -> SysResult {
    let options = options as u32;
    if options & !(WNOHANG | WUNTRACED | WCONTINUED | WAIT_LINUX_FLAGS) != 0 {
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
    let found = wait_child(cx, target, options | WEXITED)?;
    let Some(r) = found else { return Ok(0) };
    cx.write_opt(status, &r.status.0)?;
    cx.write_opt(rusage, &crate::info::rusage(r.ticks))?;
    Ok(u64::from(r.pid))
}

/// The fields of `siginfo_t` that `waitid` writes: `si_signo`, `si_errno`, `si_code`, `si_pid`,
/// `si_uid` and `si_status`.
const WAITID_INFO_SIZE: usize = 28;

pub(crate) fn waitid(
    cx: &Cx<'_>,
    idtype: u64,
    id: u64,
    infop: u64,
    options: u64,
    rusage: u64,
) -> SysResult {
    let options = options as u32;
    if options & !(WNOHANG | WNOWAIT | WEXITED | WSTOPPED | WCONTINUED | WAIT_LINUX_FLAGS) != 0
        || options & (WEXITED | WSTOPPED | WCONTINUED) == 0
    {
        return Err(Errno::EINVAL);
    }
    let id = id as i32;
    let target = match idtype as u32 {
        P_ALL => WaitTarget::Any,
        P_PID if id > 0 => WaitTarget::Pid(id as Pid),
        P_PGID if id == 0 => WaitTarget::Pgid(cx.process().pgid()),
        P_PGID if id > 0 => WaitTarget::Pgid(id as Pid),
        P_PIDFD => WaitTarget::Pid(crate::pidfd::process_of(cx, id as u32 as u64)?.pid()),
        _ => return Err(Errno::EINVAL),
    };
    // With `WNOHANG` and no child that changed, the fields are 0, as in Linux.
    let mut info = SigInfo::default();
    let mut ticks = 0;
    if let Some(r) = wait_child(cx, target, options)? {
        let (code, value) = r.status.child_code();
        info = SigInfo::new(SIGCHLD, code, r.pid);
        info.status = value;
        if r.trapped {
            // The status of a stop of `ptrace` holds the event above the signal.
            info.code = CLD_TRAPPED;
            info.status = (r.status.0 >> 8) & 0xffff;
        }
        ticks = r.ticks;
    }
    if infop != 0 {
        cx.write_bytes(infop, &info.to_bytes()[..WAITID_INFO_SIZE])?;
    }
    cx.write_opt(rusage, &crate::info::rusage(ticks))?;
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

pub(crate) fn prctl(cx: &Cx<'_>, option: u64, args: [u64; 4]) -> SysResult {
    let arg2 = args[0];
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
        _ => crate::cred::prctl(cx, option, args)
            .unwrap_or_else(|| crate::seccomp::prctl(cx, option, args)),
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

/// The `type` values of `kcmp`, from include/uapi/linux/kcmp.h.
const KCMP_FILE: u64 = 0;
const KCMP_VM: u64 = 1;
const KCMP_FILES: u64 = 2;
const KCMP_FS: u64 = 3;
const KCMP_SIGHAND: u64 = 4;

/// Gives the result of `kcmp` for two kernel objects: 0 if they are the same object, else 1 or
/// 2 in an order of the objects.
fn kcmp_order<T: ?Sized>(a: *const T, b: *const T) -> u64 {
    let (a, b) = (a.cast::<u8>() as usize, b.cast::<u8>() as usize);
    match a.cmp(&b) {
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Less => 1,
        core::cmp::Ordering::Greater => 2,
    }
}

/// `kcmp`: tells if two processes share a kernel object. rukernel has no credentials, so each
/// process can examine each other process.
pub(crate) fn kcmp(pid1: u64, pid2: u64, kind: u64, idx1: u64, idx2: u64) -> SysResult {
    let find = |pid: u64| {
        rk_proc::find_thread(pid as Pid)
            .map(|t| t.process().clone())
            .filter(|p| !p.is_zombie())
            .ok_or(Errno::ESRCH)
    };
    let (p1, p2) = (find(pid1)?, find(pid2)?);
    match kind {
        KCMP_FILE => {
            let file = |p: &Process, fd: u64| -> Result<_, Errno> {
                p.files().ok_or(Errno::EBADF)?.lock().file(fd as i32)
            };
            let (f1, f2) = (file(&p1, idx1)?, file(&p2, idx2)?);
            Ok(kcmp_order(Arc::as_ptr(&f1), Arc::as_ptr(&f2)))
        }
        KCMP_VM => {
            let (v1, v2) = (p1.vm().ok_or(Errno::ESRCH)?, p2.vm().ok_or(Errno::ESRCH)?);
            Ok(kcmp_order(Arc::as_ptr(&v1), Arc::as_ptr(&v2)))
        }
        KCMP_FILES => {
            let (f1, f2) = (p1.files().ok_or(Errno::ESRCH)?, p2.files().ok_or(Errno::ESRCH)?);
            Ok(kcmp_order(Arc::as_ptr(&f1), Arc::as_ptr(&f2)))
        }
        KCMP_FS => {
            let (f1, f2) = (p1.fs().ok_or(Errno::ESRCH)?, p2.fs().ok_or(Errno::ESRCH)?);
            Ok(kcmp_order(Arc::as_ptr(&f1), Arc::as_ptr(&f2)))
        }
        // The signal actions belong to the process, so two processes do not share them.
        KCMP_SIGHAND => Ok(kcmp_order(Arc::as_ptr(&p1), Arc::as_ptr(&p2))),
        _ => Err(Errno::EINVAL),
    }
}

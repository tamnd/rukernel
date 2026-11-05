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
use rk_proc::pid_namespace::{self, PidNamespace};
use rk_proc::ptrace::{
    self, PTRACE_EVENT_CLONE, PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK, PTRACE_EVENT_VFORK_DONE,
};
use rk_proc::signal::{CLD_TRAPPED, SigInfo};
use rk_proc::timens::TimeNs;
use rk_proc::{
    ForkShare, Pid, Process, VforkDone, WaitOptions, WaitResult, WaitStatus, WaitTarget,
};
use rk_vfs::cred::Cred;
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
/// The other `option` values, from include/uapi/linux/prctl.h of Linux.
const PR_GET_TSC: u64 = 25;
const PR_SET_TSC: u64 = 26;
const PR_SET_TIMERSLACK: u64 = 29;
const PR_GET_TIMERSLACK: u64 = 30;
const PR_SET_THP_DISABLE: u64 = 41;
const PR_GET_THP_DISABLE: u64 = 42;
const PR_GET_SPECULATION_CTRL: u64 = 52;
const PR_SET_SPECULATION_CTRL: u64 = 53;
/// The `PR_SET_TSC` values: `rdtsc` works, or it gives `SIGSEGV`.
const PR_TSC_ENABLE: u64 = 1;
const PR_TSC_SIGSEGV: u64 = 2;
/// The speculation features that `PR_GET_SPECULATION_CTRL` knows: `PR_SPEC_STORE_BYPASS`,
/// `PR_SPEC_INDIRECT_BRANCH` and `PR_SPEC_L1D_FLUSH`.
const PR_SPEC_L1D_FLUSH: u64 = 2;
/// `PR_SPEC_NOT_AFFECTED` and `PR_SPEC_ENABLE`.
const PR_SPEC_NOT_AFFECTED: u64 = 0;
const PR_SPEC_ENABLE: u64 = 1 << 1;

/// The `code` values of `arch_prctl`, from arch/x86/include/uapi/asm/prctl.h.
#[cfg(target_arch = "x86_64")]
const ARCH_SET_FS: u64 = 0x1002;
#[cfg(target_arch = "x86_64")]
const ARCH_GET_FS: u64 = 0x1003;
#[cfg(target_arch = "x86_64")]
const ARCH_GET_CPUID: u64 = 0x1011;
#[cfg(target_arch = "x86_64")]
const ARCH_SET_CPUID: u64 = 0x1012;

/// The credentials in a new user namespace for `CLONE_NEWUSER`, as `create_user_ns` of Linux,
/// or `None` without the flag.
///
/// # Errors
///
/// Gives the errors of [`rk_vfs::user_ns::create`].
fn new_user_ns(process: &Process, flags: u64) -> Result<Option<Cred>, Errno> {
    if flags & CLONE_NEWUSER == 0 {
        return Ok(None);
    }
    rk_vfs::user_ns::create(&process.cred()).map(Some)
}

/// Makes a new PID namespace for the children of `thread`, for `CLONE_NEWPID`, as `copy_pid_ns`
/// of Linux. It needs `CAP_SYS_ADMIN` in the user namespace of `cred`, the credentials that the
/// process has after the call.
///
/// # Errors
///
/// Gives `EPERM` without `CAP_SYS_ADMIN`, `EINVAL` if the children of the thread go in another
/// namespace already after `unshare` or `setns`, and `ENOSPC` if the namespace is too deep.
fn new_pid_ns(thread: &rk_proc::Thread, cred: &Cred) -> Result<Arc<PidNamespace>, Errno> {
    may_new_pid_ns(thread, cred)?;
    pid_namespace::create_pid_namespace(thread.pid_ns_for_children().as_ref())
}

/// Checks that `thread` can make a new PID namespace for its children. See `new_pid_ns`.
fn may_new_pid_ns(thread: &rk_proc::Thread, cred: &Cred) -> Result<(), Errno> {
    if !cred.has_cap(rk_vfs::cred::cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    let children = thread.pid_ns_for_children();
    if !pid_namespace::same(children.as_ref(), thread.process().pid_ns()) {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// Checks that a process with the credentials `cred` can make a new UTS, IPC or time namespace,
/// as `create_new_namespaces` of kernel/nsproxy.c of Linux. It needs `CAP_SYS_ADMIN` in its user
/// namespace.
fn may_new_ns(cred: &Cred, flags: u64) -> Result<(), Errno> {
    if flags & (CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWTIME) != 0
        && !cred.has_cap(rk_vfs::cred::cap::SYS_ADMIN)
    {
        return Err(Errno::EPERM);
    }
    Ok(())
}

/// Puts `thread` in a new UTS namespace with a copy of the names, and in a new IPC namespace
/// with no objects, as `flags` asks, as `copy_utsname` and `copy_ipcs` of Linux.
fn new_uts_ipc_ns(thread: &rk_proc::Thread, flags: u64) {
    if flags & CLONE_NEWUTS != 0 {
        thread.set_uts_ns(thread.uts_ns().copy());
    }
    if flags & CLONE_NEWIPC != 0 {
        thread.set_ipc_ns(rk_proc::ns::new_ipc());
    }
}

/// Makes a new time namespace for the children of `thread` for `CLONE_NEWTIME`, with the offsets
/// of the namespace of its children now, as `copy_time_ns` of Linux.
fn new_time_ns(thread: &rk_proc::Thread, flags: u64) -> Result<Option<Arc<TimeNs>>, Errno> {
    if flags & CLONE_NEWTIME == 0 {
        return Ok(None);
    }
    rk_proc::timens::new(&thread.time_ns_for_children()).map(Some)
}

/// Makes a new network namespace for `CLONE_NEWNET`, as `copy_net_ns` of Linux. It needs
/// `CAP_SYS_ADMIN` in the user namespace of `cred`.
fn new_net_ns(cred: &Cred) -> Result<Arc<rk_net::ns::NetNs>, Errno> {
    if !cred.has_cap(rk_vfs::cred::cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    rk_net::ns::new_in(cred.user_ns.clone())
}

/// `unshare`: the process gets its own copy of the parts that it shares, as kernel/fork.c of
/// Linux does.
pub(crate) fn unshare(cx: &Cx<'_>, flags: u64) -> SysResult {
    let known = CLONE_THREAD
        | CLONE_FS
        | CLONE_FILES
        | CLONE_SIGHAND
        | CLONE_VM
        | CLONE_SYSVSEM
        | CLONE_NEWNS
        | CLONE_NEWCGROUP
        | CLONE_NEWNET
        | CLONE_NEWUTS
        | CLONE_NEWIPC
        | CLONE_NEWTIME
        | CLONE_NEWPID
        | CLONE_NEWUSER;
    if flags & !known != 0 {
        return Err(Errno::EINVAL);
    }
    let process = cx.process();
    let mut flags = flags;
    // A new user namespace is for the whole process, and the process leaves its shared file
    // system context, as `check_unshare_flags` of Linux.
    if flags & CLONE_NEWUSER != 0 {
        flags |= CLONE_THREAD | CLONE_FS;
        if process.threads().len() > 1 {
            return Err(Errno::EINVAL);
        }
    }
    // The checks of the other namespaces use the credentials in the new user namespace.
    let old_cred = process.cred();
    let new_cred = new_user_ns(process, flags)?;
    let cred = new_cred.as_ref().unwrap_or(&*old_cred);
    // A new mount name space needs `CAP_SYS_ADMIN`, and the process leaves its shared file
    // system context too, as `unshare_fs` of Linux.
    if flags & CLONE_NEWNS != 0 {
        if !cred.has_cap(rk_vfs::cred::cap::SYS_ADMIN) {
            return Err(Errno::EPERM);
        }
        flags |= CLONE_FS;
    }
    may_new_ns(cred, flags)?;
    // A new IPC namespace leaves the semaphore undo list too, as `ksys_unshare` of Linux.
    if flags & CLONE_NEWIPC != 0 {
        flags |= CLONE_SYSVSEM;
    }
    // The copy of the descriptor table comes before the other changes, so that an `EMFILE` of
    // `fs.nr_open` changes nothing, as `unshare_fd` in `ksys_unshare` of Linux.
    let files = if flags & CLONE_FILES != 0 { Some(cx.files()?.lock().try_clone()?) } else { None };
    let time = new_time_ns(cx.thread, flags)?;
    // The caller stays in its PID namespace, and its new children go in the new one.
    let pid_ns = if flags & CLONE_NEWPID != 0 { Some(new_pid_ns(cx.thread, cred)?) } else { None };
    if flags & CLONE_NEWCGROUP != 0 {
        new_cgroup_ns(process, cred)?;
    }
    // A process with more than one thread cannot leave its group, its handlers or its memory.
    if flags & (CLONE_THREAD | CLONE_SIGHAND | CLONE_VM) != 0 && process.threads().len() > 1 {
        return Err(Errno::EINVAL);
    }
    // `CLONE_SYSVSEM` does the changes of the undo list as an exit does, as `exit_sem`. The
    // threads of a process share the list, so the last user does the changes.
    if flags & CLONE_SYSVSEM != 0 && process.threads().len() <= 1 {
        crate::sem::exit(process.pid() as i32);
    }
    new_uts_ipc_ns(cx.thread, flags);
    // The caller stays in its time namespace, and its new children go in the new one.
    if let Some(ns) = time {
        cx.thread.set_time_ns_for_children(ns);
    }
    if let Some(ns) = pid_ns {
        cx.thread.set_pid_ns_for_children(Some(ns));
    }
    // Only the caller gets the new namespace, as `switch_task_namespaces` of Linux.
    if flags & CLONE_NEWNET != 0 {
        cx.thread.set_net_ns(new_net_ns(cred)?);
    }
    if let Some(c) = new_cred {
        process.set_cred(c);
    }
    if let Some(table) = files {
        process.set_files(Arc::new(SpinLock::new(table)));
    }
    if flags & CLONE_FS != 0
        && let Some(fs) = process.fs()
    {
        let mut context = fs.lock().clone();
        if flags & CLONE_NEWNS != 0 {
            context.unshare_namespace();
        }
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
    do_clone(cx, &CloneArgs { flags: args.flags & 0xffff_ffff, ..args }, stack, &Default::default())
}

/// The largest `struct clone_args` that `clone3` reads. Linux gives `E2BIG` for a larger one.
const CLONE_ARGS_MAX: u64 = 4096;

/// Puts `process` in a new cgroup namespace with its cgroup as the root, for `CLONE_NEWCGROUP`.
///
/// # Errors
///
/// `EPERM` without `CAP_SYS_ADMIN` in the user namespace of `cred`.
fn new_cgroup_ns(process: &Process, cred: &Cred) -> Result<(), Errno> {
    if !cred.has_cap(rk_vfs::cred::cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    let root = process.cgroup();
    let ns = rk_cgroup::with(|h| h.new_namespace(root));
    process.set_cgroup_ns(ns);
    Ok(())
}

/// Puts the calling thread in the network namespace `ns`, as `netns_install` of Linux. The other
/// threads of the process keep their namespace.
///
/// # Errors
///
/// `EPERM` without `CAP_SYS_ADMIN`.
fn join_net_ns(cx: &Cx<'_>, ns: Arc<rk_net::ns::NetNs>) -> Result<(), Errno> {
    if !cx.process().cred().capable(rk_vfs::cred::cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    cx.thread.set_net_ns(ns);
    Ok(())
}

/// Puts the calling thread in the UTS namespace `ns`, as `utsns_install` of kernel/utsname.c
/// of Linux.
///
/// # Errors
///
/// `EPERM` without `CAP_SYS_ADMIN`.
fn join_uts_ns(cx: &Cx<'_>, ns: Arc<rk_proc::uts::UtsNs>) -> Result<(), Errno> {
    if !cx.process().cred().capable(rk_vfs::cred::cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    cx.thread.set_uts_ns(ns);
    Ok(())
}

/// Puts the calling thread in the IPC namespace `ns`, as `ipcns_install` of ipc/namespace.c of
/// Linux. The process leaves the semaphore undo list of the old namespace, as `exit_sem`.
///
/// # Errors
///
/// `EPERM` without `CAP_SYS_ADMIN`.
fn join_ipc_ns(cx: &Cx<'_>, ns: Arc<rk_proc::ns::IpcNs>) -> Result<(), Errno> {
    if !cx.process().cred().capable(rk_vfs::cred::cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    if cx.process().threads().len() <= 1 {
        crate::sem::exit(cx.process().pid() as i32);
    }
    cx.thread.set_ipc_ns(ns);
    Ok(())
}

/// Puts the calling thread and its new children in the time namespace `ns`, as `timens_install`
/// of kernel/time/namespace.c of Linux.
///
/// # Errors
///
/// `EUSERS` if the process has more than one thread, and `EPERM` without `CAP_SYS_ADMIN`.
fn join_time_ns(cx: &Cx<'_>, ns: Arc<TimeNs>) -> Result<(), Errno> {
    if cx.process().threads().len() > 1 {
        return Err(Errno::EUSERS);
    }
    if !cx.process().cred().capable(rk_vfs::cred::cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    cx.thread.enter_time_ns(ns, true)
}

/// Puts `process` in the cgroup namespace `ns`, as `cgroupns_install` of Linux.
///
/// # Errors
///
/// `EPERM` without `CAP_SYS_ADMIN`.
fn join_cgroup_ns(process: &Process, ns: u32) -> Result<(), Errno> {
    if !process.cred().capable(rk_vfs::cred::cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    process.set_cgroup_ns(ns);
    Ok(())
}

/// `setns`: joins the namespace of a file of `/proc/PID/ns`, or the namespaces of the process of
/// a process file descriptor, as `setns` of `kernel/nsproxy.c` of Linux.
///
/// A process can change its cgroup, network, UTS and IPC namespaces, and its mount namespace
/// through a file. The other kinds that `unshare` cannot make are the same for each process, so a
/// join changes nothing, but it needs `CAP_SYS_ADMIN` as in Linux. A mount namespace through a
/// process file descriptor gives `EINVAL`.
pub(crate) fn setns(cx: &Cx<'_>, fd: u64, nstype: u64) -> SysResult {
    let file = cx.file(fd)?;
    let process = cx.process();
    if let Some((kind, id)) = file.inode().and_then(rk_vfs::nsfs::ns_of) {
        if nstype != 0 && nstype != kind.clone_flag() {
            return Err(Errno::EINVAL);
        }
        match kind {
            rk_vfs::nsfs::NsKind::Cgroup => join_cgroup_ns(process, id)?,
            // The file keeps the namespace, so the search finds it.
            rk_vfs::nsfs::NsKind::Net => {
                join_net_ns(cx, rk_net::ns::by_id(id).ok_or(Errno::EINVAL)?)?;
            }
            rk_vfs::nsfs::NsKind::Uts => {
                join_uts_ns(cx, rk_proc::uts::by_id(id).ok_or(Errno::EINVAL)?)?;
            }
            rk_vfs::nsfs::NsKind::Ipc => {
                join_ipc_ns(cx, rk_proc::ns::ipc_by_id(id).ok_or(Errno::EINVAL)?)?;
            }
            rk_vfs::nsfs::NsKind::Time => {
                join_time_ns(cx, rk_proc::timens::by_id(id).ok_or(Errno::EINVAL)?)?;
            }
            rk_vfs::nsfs::NsKind::Pid => {
                let ns = pid_namespace::by_id(id).ok_or(Errno::EINVAL)?;
                may_join_pid_ns(cx, ns.as_ref())?;
                cx.thread.set_pid_ns_for_children(ns);
            }
            kind => crate::ns::install(cx, process, kind, id)?,
        }
        return Ok(0);
    }
    let Ok(target) = crate::pidfd::process_of(cx, fd) else {
        return Err(Errno::EINVAL);
    };
    let all = CLONE_NEWNS
        | CLONE_NEWCGROUP
        | CLONE_NEWNET
        | CLONE_NEWTIME
        | CLONE_NEWPID
        | CLONE_NEWUTS
        | CLONE_NEWIPC
        | CLONE_NEWUSER;
    if nstype == 0 || nstype & !all != 0 {
        return Err(Errno::EINVAL);
    }
    if nstype & CLONE_NEWNS != 0 {
        return Err(Errno::EINVAL);
    }
    if target.is_zombie() {
        return Err(Errno::ESRCH);
    }
    // A join needs `CAP_SYS_ADMIN`, as `validate_nsset` of Linux, and an error changes nothing.
    if nstype & !CLONE_NEWUSER != 0 && !process.cred().capable(rk_vfs::cred::cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    // The user namespace comes first, as `validate_nsset` of Linux.
    if nstype & CLONE_NEWUSER != 0 {
        let ns = target.cred().user_ns.clone();
        if ns != process.cred().user_ns {
            crate::ns::join_user_ns(cx, process, ns)?;
        }
    }
    if nstype & CLONE_NEWPID != 0 {
        may_join_pid_ns(cx, target.pid_ns())?;
    }
    if nstype & CLONE_NEWCGROUP != 0 {
        join_cgroup_ns(process, target.cgroup_ns())?;
    }
    if nstype & CLONE_NEWNET != 0 {
        join_net_ns(cx, target.net_ns())?;
    }
    if nstype & CLONE_NEWUTS != 0 {
        join_uts_ns(cx, target.uts_ns())?;
    }
    if nstype & CLONE_NEWIPC != 0 {
        join_ipc_ns(cx, target.ipc_ns())?;
    }
    if nstype & CLONE_NEWTIME != 0 {
        join_time_ns(cx, target.time_ns())?;
    }
    if nstype & CLONE_NEWPID != 0 {
        cx.thread.set_pid_ns_for_children(target.pid_ns().cloned());
    }
    Ok(0)
}

/// Checks that the caller can put its new children in the PID namespace `ns`, as
/// `pidns_install` of Linux: `ns` is the namespace of the caller or a descendant of it.
///
/// # Errors
///
/// Gives `EPERM` without `CAP_SYS_ADMIN`, and `EINVAL` for another namespace.
fn may_join_pid_ns(cx: &Cx<'_>, ns: Option<&Arc<PidNamespace>>) -> Result<(), Errno> {
    if !cx.process().cred().capable(rk_vfs::cred::cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    if !pid_namespace::is_descendant(ns, cx.process().pid_ns()) {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// The cgroup of the directory that `fd` opens, for `CLONE_INTO_CGROUP`.
///
/// # Errors
///
/// `EBADF` for a descriptor that is not open, and `EINVAL` if it is not a directory of cgroup2.
fn cgroup_of_fd(cx: &Cx<'_>, fd: u64) -> Result<u32, Errno> {
    let fd = i32::try_from(fd).map_err(|_| Errno::EBADF)?;
    let file = cx.file(fd as u64)?;
    file.inode().and_then(rk_fs_cgroup::cgroup_of).ok_or(Errno::EINVAL)
}

/// `clone3`, as `copy_clone_args_from_user` and `clone3_args_valid` of Linux check it. The stack
/// of `clone3` is the lowest address and a size, and the new thread starts at the top.
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
    // `CLONE_NEWTIME` has a bit of `CSIGNAL`, and only `clone3` takes it, as
    // `clone3_args_valid` of Linux.
    if flags & (CLONE_DETACHED | (CSIGNAL & !CLONE_NEWTIME)) != 0
        || flags & !(0xffff_ffff | CLONE_CLEAR_SIGHAND | CLONE_INTO_CGROUP) != 0
        || (flags & CLONE_INTO_CGROUP != 0 && flags & CLONE_THREAD != 0)
        || args.set_tid_size > u64::from(pid_namespace::MAX_PID_NS_LEVEL)
        || (args.set_tid == 0) != (args.set_tid_size == 0)
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
    // The IDs of `set_tid`, from the namespace of the child up, as `copy_clone_args_from_user`.
    // A valid ID is at least 1, so a 0 in the list gives `EINVAL`.
    let mut set_tid: rk_proc::SetTid = Default::default();
    if args.set_tid_size != 0 {
        let n = args.set_tid_size as usize;
        let mut raw = alloc::vec![0u8; n * 4];
        cx.vm()?.read(args.set_tid as usize, &mut raw)?;
        for (i, b) in raw.chunks_exact(4).enumerate() {
            let tid = i32::from_ne_bytes([b[0], b[1], b[2], b[3]]);
            set_tid[i] = u32::try_from(tid).ok().filter(|&t| t >= 1).ok_or(Errno::EINVAL)?;
        }
        // The caller needs `CAP_CHECKPOINT_RESTORE` or `CAP_SYS_ADMIN`, as
        // `checkpoint_restore_ns_capable` in `alloc_pid` of Linux.
        let cred = cx.process().cred();
        if !cred.capable(rk_vfs::cred::cap::CHECKPOINT_RESTORE)
            && !cred.capable(rk_vfs::cred::cap::SYS_ADMIN)
        {
            return Err(Errno::EPERM);
        }
    }
    do_clone(cx, &args, top, &set_tid)
}

/// Makes a new thread or process for `clone` and `clone3`. `stack` is the stack pointer of the
/// new thread, or 0 for the stack pointer of the caller. A tracer that asked for the event of the
/// call traces the new thread too.
fn do_clone(cx: &mut Cx<'_>, args: &CloneArgs, stack: u64, set_tid: &rk_proc::SetTid) -> SysResult {
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
    // A new user namespace is for a new process with its own file system context, as
    // `copy_process` of Linux.
    if flags & CLONE_NEWUSER != 0 && flags & (CLONE_THREAD | CLONE_FS) != 0 {
        return Err(Errno::EINVAL);
    }
    // A new thread stays in the PID namespace of its process, as `copy_process` of Linux checks.
    if flags & CLONE_THREAD != 0
        && (flags & CLONE_NEWPID != 0
            || !pid_namespace::same(
                cx.thread.pid_ns_for_children().as_ref(),
                cx.process().pid_ns(),
            ))
    {
        return Err(Errno::EINVAL);
    }
    // The checks of the other namespaces use the credentials of the child in its new user
    // namespace, as `copy_creds` comes before `copy_namespaces` in Linux.
    let old_cred = cx.process().cred();
    let new_cred = new_user_ns(cx.process(), flags)?;
    let cred = new_cred.as_ref().unwrap_or(&*old_cred);
    // `fork` makes the namespace.
    if flags & CLONE_NEWPID != 0 {
        may_new_pid_ns(cx.thread, cred)?;
    }
    // A new IPC namespace cannot share the semaphore undo list, as `copy_process` of Linux.
    if flags & (CLONE_NEWIPC | CLONE_SYSVSEM) == CLONE_NEWIPC | CLONE_SYSVSEM {
        return Err(Errno::EINVAL);
    }
    may_new_ns(cred, flags)?;
    if flags & CLONE_NEWCGROUP != 0 && !cred.has_cap(rk_vfs::cred::cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    let cgroup =
        if flags & CLONE_INTO_CGROUP != 0 { Some(cgroup_of_fd(cx, args.cgroup)?) } else { None };
    // A new mount name space cannot share the file system context. The threads of a process
    // share one name space in rukernel.
    if flags & CLONE_NEWNS != 0 {
        if flags & (CLONE_FS | CLONE_THREAD) != 0 {
            return Err(Errno::EINVAL);
        }
        if !cred.has_cap(rk_vfs::cred::cap::SYS_ADMIN) {
            return Err(Errno::EPERM);
        }
    }
    // A new thread can have its own network namespace, as on Linux.
    let net = if flags & CLONE_NEWNET != 0 { Some(new_net_ns(cred)?) } else { None };
    let time = new_time_ns(cx.thread, flags)?;
    // The task blob of the child starts as a copy of the blob of the parent, and the security
    // modules can deny the new task, as `security_task_alloc` in `copy_process` of Linux. The
    // child has no ID yet.
    let blob = rk_vfs::security::Blob::task();
    blob.copy_from(cx.thread.security());
    let task = rk_vfs::security::Task { pid: 0, cred: &cx.process().cred(), security: Some(&blob) };
    rk_vfs::security::task_alloc(&task, flags)?;
    let thread = if flags & CLONE_THREAD != 0 {
        rk_proc::new_thread_with(cx.thread, set_tid)?
    } else {
        let share = ForkShare {
            vm: flags & CLONE_VM != 0,
            files: flags & CLONE_FILES != 0,
            fs: flags & CLONE_FS != 0,
            exit_signal: args.exit_signal as u32,
            parent: flags & CLONE_PARENT != 0,
            cgroup,
            new_pid_ns: flags & CLONE_NEWPID != 0,
            set_tid: *set_tid,
        };
        rk_proc::fork(cx.thread, share)?
    };
    if let Some(c) = new_cred {
        thread.process().set_cred(c);
    }
    thread.security().copy_from(&blob);
    if flags & CLONE_NEWNS != 0
        && let Some(fs) = thread.process().fs()
    {
        fs.lock().unshare_namespace();
    }
    if let Some(net) = net {
        thread.set_net_ns(net);
    }
    new_uts_ipc_ns(&thread, flags);
    if flags & CLONE_NEWCGROUP != 0 {
        let process = thread.process();
        let ns = rk_cgroup::with(|h| h.new_namespace(process.cgroup()));
        process.set_cgroup_ns(ns);
    }
    if flags & CLONE_CLEAR_SIGHAND != 0 {
        // A handler goes back to the default action, and an ignored signal stays ignored.
        thread.process().reset_actions();
    }
    // The caller gets the ID in its namespace, and the child writes its ID in its own namespace,
    // as `schedule_tail` of Linux.
    let tid = cx.vnr(thread.tid());
    let child_tid = rk_proc::pid_vnr(thread.process(), thread.tid());
    let mut regs = *cx.regs;
    regs.set_syscall_return(0);
    if stack != 0 {
        regs.set_sp(stack);
    }
    if flags & CLONE_SETTLS != 0 {
        regs.set_tls(args.tls);
    }
    // An error here ends the new thread before it runs, so that no child stays that never
    // ends. A process file descriptor that the caller cannot get closes again, as
    // `copy_process` in kernel/fork.c of Linux, which installs the descriptor after the write.
    let setup = |cx: &mut Cx<'_>| -> Result<(), Errno> {
        if let Some(ns) = time {
            thread.set_time_ns_for_children(ns);
        }
        // A new process goes in the time namespace of the children of the caller, as
        // `timens_on_fork` of Linux. A child that shares the memory stays in the namespace of
        // the caller until it runs a program.
        if flags & CLONE_VM == 0 && thread.time_ns_changes() {
            thread.enter_time_ns(thread.time_ns_for_children(), false)?;
        }
        if flags & CLONE_PARENT_SETTID != 0 {
            cx.write_val(args.parent_tid, &tid)?;
        }
        if flags & CLONE_PIDFD != 0 {
            let fd = crate::pidfd::open(cx, thread.process().clone(), 0)?;
            if let Err(e) = cx.write_val(args.pidfd, &fd) {
                let _ = cx.files()?.lock().remove(fd);
                return Err(e);
            }
        }
        if flags & CLONE_CHILD_SETTID != 0
            && let Some(vm) = thread.process().vm()
        {
            vm.write(args.child_tid as usize, &child_tid.to_ne_bytes())?;
        }
        Ok(())
    };
    if let Err(e) = setup(cx) {
        rk_proc::exit_thread(&thread, WaitStatus::exited(0));
        return Err(e);
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

#[cfg(target_arch = "x86_64")]
pub(crate) fn fork(cx: &mut Cx<'_>) -> SysResult {
    clone(cx, u64::from(SIGCHLD), 0, 0, 0, 0)
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn vfork(cx: &mut Cx<'_>) -> SysResult {
    clone(cx, CLONE_VM | CLONE_VFORK | u64::from(SIGCHLD), 0, 0, 0, 0)
}

pub(crate) fn execve(cx: &mut Cx<'_>, path: u64, argv: u64, envp: u64) -> SysResult {
    let path = cx.read_path(path)?;
    let mut total = 0;
    let argv = cx.read_strings(argv, &mut total)?;
    let envp = cx.read_strings(envp, &mut total)?;
    // The new program has no robust list. The locks in the list of the old program are dead.
    let image = exec(
        cx.thread,
        ExecArgs::new(path, argv, envp),
        random16(),
        crate::futex::exit_robust_list,
    )?;
    *cx.regs = rk_frame::user::UserContext::new(
        rk_frame::addr::VirtAddr::new(image.entry),
        rk_frame::addr::VirtAddr::new(image.sp),
    );
    cx.regs.set_syscall_return(0);
    // rukernel keeps the thread ID in `execve`, so the old ID is the ID of the thread.
    ptrace::exec_event(cx.thread, cx.regs, cx.number, cx.thread.tid());
    Ok(0)
}

/// `execveat`, as `do_execveat_common` of Linux. The path starts at `dirfd`, `AT_EMPTY_PATH`
/// runs the file of `dirfd` and `AT_SYMLINK_NOFOLLOW` gives `ELOOP` for a symbolic link.
pub(crate) fn execveat(
    cx: &mut Cx<'_>,
    dirfd: u64,
    path: u64,
    argv: u64,
    envp: u64,
    flags: u64,
) -> SysResult {
    use rk_abi::native::at::{AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW};
    let flags = u32::try_from(flags).map_err(|_| Errno::EINVAL)?;
    if flags & !(AT_EMPTY_PATH as u32 | AT_SYMLINK_NOFOLLOW as u32) != 0 {
        return Err(Errno::EINVAL);
    }
    let path = cx.read_path_opt(path, flags & AT_EMPTY_PATH as u32 != 0)?;
    let cwd = dirfd as i32 == rk_abi::native::at::AT_FDCWD;
    let start = if path.is_empty() && cwd {
        Some(cx.fs()?.cwd().clone())
    } else if path.first() == Some(&b'/') || cwd {
        None
    } else {
        let file = cx.file(dirfd)?;
        let at = file.location().ok_or(Errno::EACCES)?.clone();
        if !path.is_empty() && !at.inode().metadata().is_dir() {
            return Err(Errno::ENOTDIR);
        }
        Some(at)
    };
    let mut total = 0;
    let argv = cx.read_strings(argv, &mut total)?;
    let envp = cx.read_strings(envp, &mut total)?;
    let mut args = ExecArgs::new(path, argv, envp);
    args.start = start;
    args.follow = flags & AT_SYMLINK_NOFOLLOW as u32 == 0;
    let image = exec(cx.thread, args, random16(), crate::futex::exit_robust_list)?;
    *cx.regs = rk_frame::user::UserContext::new(
        rk_frame::addr::VirtAddr::new(image.entry),
        rk_frame::addr::VirtAddr::new(image.sp),
    );
    cx.regs.set_syscall_return(0);
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
        p if p > 0 => WaitTarget::Pid(global(cx, p)),
        i32::MIN => return Err(Errno::ESRCH),
        p => WaitTarget::Pgid(global(cx, -p)),
    };
    let found = wait_child(cx, target, options | WEXITED)?;
    let Some(r) = found else { return Ok(0) };
    cx.write_opt(status, &r.status.0)?;
    cx.write_opt(rusage, &crate::info::rusage(r.ticks, r.sys_ticks))?;
    Ok(u64::from(cx.vnr(r.pid)))
}

/// The global ID of the ID `nr` of the PID namespace of the caller, or 0, which no child has,
/// if the namespace has no such ID, as `find_get_pid` in `kernel_wait4` of Linux.
fn global(cx: &Cx<'_>, nr: i32) -> Pid {
    cx.find_vpid(nr as u64).unwrap_or(0)
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
    // A wait on a process file descriptor with `O_NONBLOCK` does not wait. It gives `EAGAIN` if
    // no child changed, as `kernel_waitid` in kernel/exit.c of Linux.
    let mut nonblock = false;
    let target = match idtype as u32 {
        P_ALL => WaitTarget::Any,
        P_PID if id > 0 => WaitTarget::Pid(global(cx, id)),
        P_PGID if id == 0 => WaitTarget::Pgid(cx.process().pgid()),
        P_PGID if id > 0 => WaitTarget::Pgid(global(cx, id)),
        P_PIDFD => {
            let fd = id as u32 as u64;
            let pid = crate::pidfd::process_of(cx, fd)?.pid();
            nonblock = options & WNOHANG == 0 && cx.file(fd)?.flags().nonblock();
            WaitTarget::Pid(pid)
        }
        _ => return Err(Errno::EINVAL),
    };
    // With `WNOHANG` and no child that changed, the fields are 0, as in Linux.
    let mut info = SigInfo::default();
    let mut ticks = (0, 0);
    let options = if nonblock { options | WNOHANG } else { options };
    let result = wait_child(cx, target, options)?;
    if result.is_none() && nonblock {
        return Err(Errno::EAGAIN);
    }
    if let Some(r) = result {
        let (code, value) = r.status.child_code();
        info = SigInfo::new(SIGCHLD, code, cx.vnr(r.pid));
        info.uid = r.uid;
        info.status = value;
        if r.trapped {
            // The status of a stop of `ptrace` holds the event above the signal.
            info.code = CLD_TRAPPED;
            info.status = (r.status.0 >> 8) & 0xffff;
        }
        ticks = (r.ticks, r.sys_ticks);
    }
    if infop != 0 {
        cx.write_bytes(infop, &info.to_bytes()[..WAITID_INFO_SIZE])?;
    }
    cx.write_opt(rusage, &crate::info::rusage(ticks.0, ticks.1))?;
    Ok(0)
}

pub(crate) fn setpgid(cx: &Cx<'_>, pid: u64, pgid: u64) -> SysResult {
    let pid = pid as i32;
    let pgid = pgid as i32;
    if pgid < 0 {
        return Err(Errno::EINVAL);
    }
    let me = cx.process();
    // The checks and the change are one step, as `setpgid` in kernel/sys.c of Linux does with
    // `tasklist_lock`.
    let _tasks = rk_proc::tasklist_write();
    let target = if pid == 0 || cx.find_vpid(pid as u64) == Some(me.pid()) {
        me.clone()
    } else {
        let pid = cx.find_vpid(pid as u64).ok_or(Errno::ESRCH)?;
        me.children().into_iter().find(|c| c.pid() == pid).ok_or(Errno::ESRCH)?
    };
    if target.sid() != me.sid() {
        return Err(Errno::EPERM);
    }
    // A child that ran `execve` keeps its group, as `PF_FORKNOEXEC` in kernel/sys.c of Linux.
    if !Arc::ptr_eq(&target, me) && target.did_exec() {
        return Err(Errno::EACCES);
    }
    if target.sid() == target.pid() {
        return Err(Errno::EPERM);
    }
    let pgid =
        if pgid == 0 { target.pid() } else { cx.find_vpid(pgid as u64).ok_or(Errno::EPERM)? };
    if pgid != target.pid()
        && !rk_proc::processes().iter().any(|p| p.pgid() == pgid && p.sid() == me.sid())
    {
        return Err(Errno::EPERM);
    }
    rk_vfs::security::task_setpgid(&lsm_process(&target, &target.cred()), pgid)?;
    target.set_pgid(pgid);
    Ok(0)
}

fn find(cx: &Cx<'_>, pid: u64) -> Result<alloc::sync::Arc<Process>, Errno> {
    if pid as i32 == 0 {
        return Ok(cx.process().clone());
    }
    cx.find_process_by_vpid(pid).ok_or(Errno::ESRCH)
}

/// `getpgid`. A group outside the PID namespace of the caller gives 0, as `pid_vnr` of Linux.
pub(crate) fn getpgid(cx: &Cx<'_>, pid: u64) -> SysResult {
    let p = find(cx, pid)?;
    if pid as i32 != 0 {
        rk_vfs::security::task_getpgid(&lsm_process(&p, &p.cred()))?;
    }
    Ok(u64::from(cx.vnr(p.pgid())))
}

/// `getsid`. A session outside the PID namespace of the caller gives 0.
pub(crate) fn getsid(cx: &Cx<'_>, pid: u64) -> SysResult {
    let p = find(cx, pid)?;
    if pid as i32 != 0 {
        rk_vfs::security::task_getsid(&lsm_process(&p, &p.cred()))?;
    }
    Ok(u64::from(cx.vnr(p.sid())))
}

/// The view of the process `p` with the credentials `cred` for the hooks of the security
/// modules.
fn lsm_process<'a>(p: &Process, cred: &'a rk_vfs::cred::Cred) -> rk_vfs::security::Task<'a> {
    rk_vfs::security::Task { pid: p.pid(), cred, security: None }
}

pub(crate) fn prctl(cx: &mut Cx<'_>, option: u64, args: [u64; 4]) -> SysResult {
    let arg2 = args[0];
    let [_, arg3, arg4, arg5] = args;
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
            cx.process().set_pdeath_signal(arg2 as u32);
            Ok(0)
        }
        PR_GET_PDEATHSIG => {
            cx.write_val(arg2, &(cx.process().pdeath_signal() as i32))?;
            Ok(0)
        }
        // As `SET_TSC_CTL` and `GET_TSC_CTL` in arch/x86/kernel/process.c of Linux. The flag
        // belongs to the thread, and a child of `fork` gets it with the registers.
        PR_GET_TSC if cfg!(target_arch = "x86_64") => {
            let value = if cx.regs.no_tsc() { PR_TSC_SIGSEGV } else { PR_TSC_ENABLE };
            cx.write_val(arg2, &(value as i32))?;
            Ok(0)
        }
        PR_SET_TSC if cfg!(target_arch = "x86_64") => match arg2 {
            PR_TSC_ENABLE | PR_TSC_SIGSEGV => {
                cx.regs.set_no_tsc(arg2 == PR_TSC_SIGSEGV);
                Ok(0)
            }
            _ => Err(Errno::EINVAL),
        },
        // As kernel/sys.c of Linux: 0 sets the default slack again.
        PR_SET_TIMERSLACK => {
            cx.thread.set_timer_slack(arg2);
            Ok(0)
        }
        PR_GET_TIMERSLACK => Ok(cx.thread.timer_slack()),
        PR_GET_THP_DISABLE => {
            if arg2 != 0 || arg3 != 0 || arg4 != 0 || arg5 != 0 {
                return Err(Errno::EINVAL);
            }
            Ok(u64::from(cx.process().thp_disable()))
        }
        PR_SET_THP_DISABLE => {
            if arg3 != 0 || arg4 != 0 || arg5 != 0 {
                return Err(Errno::EINVAL);
            }
            cx.process().set_thp_disable(arg2 != 0);
            Ok(0)
        }
        // As arch/x86/kernel/cpu/bugs.c of Linux on a CPU that is not affected: each known
        // feature is `PR_SPEC_NOT_AFFECTED`, and only `PR_SPEC_ENABLE` can be set.
        PR_GET_SPECULATION_CTRL => {
            if arg3 != 0 || arg4 != 0 || arg5 != 0 {
                return Err(Errno::EINVAL);
            }
            if arg2 > PR_SPEC_L1D_FLUSH {
                return Err(Errno::ENODEV);
            }
            Ok(PR_SPEC_NOT_AFFECTED)
        }
        PR_SET_SPECULATION_CTRL => {
            if arg4 != 0 || arg5 != 0 {
                return Err(Errno::EINVAL);
            }
            if arg2 > PR_SPEC_L1D_FLUSH {
                return Err(Errno::ENODEV);
            }
            if arg3 == PR_SPEC_ENABLE { Ok(0) } else { Err(Errno::ENXIO) }
        }
        // The `dumpable` value of the process, as `prctl_set_dumpable` in kernel/sys.c of Linux.
        // A user can set only `SUID_DUMP_DISABLE` and `SUID_DUMP_USER`.
        PR_GET_DUMPABLE => Ok(u64::from(cx.process().dumpable())),
        PR_SET_DUMPABLE => {
            if arg2 > 1 {
                return Err(Errno::EINVAL);
            }
            cx.process().set_dumpable(arg2 as u8);
            Ok(0)
        }
        _ => {
            let cx = &*cx;
            crate::cred::prctl(cx, option, args)
                .or_else(|| crate::ksm::prctl(cx, option, args))
                .unwrap_or_else(|| crate::seccomp::prctl(cx, option, args))
        }
    }
}

#[cfg(target_arch = "x86_64")]
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
        // rukernel does not use CPUID faulting, so CPUID is always on, as
        // arch/x86/kernel/process.c of Linux on a CPU without `X86_FEATURE_CPUID_FAULT`.
        ARCH_GET_CPUID => Ok(1),
        ARCH_SET_CPUID => Err(Errno::ENODEV),
        _ => Err(Errno::EINVAL),
    }
}

/// The number of I/O ports, as `IO_BITMAP_BITS` in arch/x86/include/asm/processor.h of Linux.
#[cfg(target_arch = "x86_64")]
const IO_BITMAP_BITS: u64 = 65536;

/// `ioperm`, as `ksys_ioperm` in arch/x86/kernel/ioport.c of Linux. The checks are those of
/// Linux, but the kernel keeps no I/O bitmap: an `in` or `out` instruction still gives `SIGSEGV`.
#[cfg(target_arch = "x86_64")]
pub(crate) fn ioperm(cx: &Cx<'_>, from: u64, num: u64, turn_on: u64) -> SysResult {
    let end = from.checked_add(num).ok_or(Errno::EINVAL)?;
    if end <= from || end > IO_BITMAP_BITS {
        return Err(Errno::EINVAL);
    }
    if turn_on != 0 && !cx.process().cred().capable(rk_vfs::cred::cap::SYS_RAWIO) {
        return Err(Errno::EPERM);
    }
    Ok(0)
}

/// `iopl`, as `SYSCALL_DEFINE1(iopl)` in arch/x86/kernel/ioport.c of Linux. A higher level
/// needs `CAP_SYS_RAWIO`. As in Linux, the level is not put in RFLAGS. The kernel keeps no I/O
/// bitmap, so the level does not let the user code use the ports.
#[cfg(target_arch = "x86_64")]
pub(crate) fn iopl(cx: &Cx<'_>, level: u64) -> SysResult {
    if level > 3 {
        return Err(Errno::EINVAL);
    }
    let level = level as u32;
    if level > cx.thread.iopl() && !cx.process().cred().capable(rk_vfs::cred::cap::SYS_RAWIO) {
        return Err(Errno::EPERM);
    }
    cx.thread.set_iopl(level);
    Ok(0)
}

/// The `type` values of `kcmp`, from include/uapi/linux/kcmp.h.
const KCMP_FILE: u64 = 0;
const KCMP_VM: u64 = 1;
const KCMP_FILES: u64 = 2;
const KCMP_FS: u64 = 3;
const KCMP_SIGHAND: u64 = 4;
const KCMP_IO: u64 = 5;
const KCMP_SYSVSEM: u64 = 6;

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
    let me = rk_proc::current_thread().ok_or(Errno::ESRCH)?;
    let find = |pid: u64| {
        rk_proc::find_task_by_vpid(me.process(), pid as Pid)
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
        // rukernel keeps no I/O context, so each task has the null context of Linux.
        KCMP_IO => Ok(0),
        // Each process has its own undo list, or none, as a null `undo_list` of Linux.
        KCMP_SYSVSEM => {
            match (crate::sem::has_undo(p1.pid() as i32), crate::sem::has_undo(p2.pid() as i32)) {
                (false, false) => Ok(0),
                _ if Arc::ptr_eq(&p1, &p2) => Ok(0),
                _ => Ok(kcmp_order(Arc::as_ptr(&p1), Arc::as_ptr(&p2))),
            }
        }
        _ => Err(Errno::EINVAL),
    }
}

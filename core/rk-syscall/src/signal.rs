//! The signal system calls, and the delivery of a signal to a user thread.
//!
//! Before the task goes back to user mode, it takes the next signal that the thread does not
//! block. For a handler, the kernel writes the `rt_sigframe` of the architecture on the user stack
//! and starts the handler. The handler returns to the restorer of the C library, which calls
//! `rt_sigreturn`. That call reads the saved registers back from the frame. The frame is in the
//! module `frame`, one file for each architecture, as in arch/*/kernel/signal.c of Linux.

#[cfg(target_arch = "aarch64")]
#[path = "signal/aarch64.rs"]
mod frame;
#[cfg(target_arch = "x86_64")]
#[path = "signal/x86_64.rs"]
mod frame;

pub(crate) use frame::rt_sigreturn;

use crate::cx::{Cx, SysResult};
use alloc::sync::Arc;
use rk_abi::Errno;
use rk_abi::native::signal::{
    MINSIGSTKSZ, SA_NODEFER, SA_RESTART, SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK, SIGCONT, SIGKILL,
    SIGSEGV, SIGSTOP, SIGTRAP,
};
use rk_abi::native::syscalls as nr;
use rk_abi::native::types::{KernelTimespec, Sigaltstack};
use rk_frame::user::UserContext;
use rk_proc::ptrace::{self, NO_SYSCALL, PTRACE_EVENT_STOP, StopKind};
use rk_proc::signal::{
    AltStack, NSIG, SI_TKILL, SI_USER, SIGINFO_SIZE, SS_AUTODISARM, SS_DISABLE, SS_ONSTACK,
    SigAction, SigInfo, SigSet,
};
use rk_proc::{Delivery, Pid, Process, Thread, WaitStatus};
use zerocopy::FromZeros;

/// The size of a signal set in the system calls. Linux names it `sizeof(sigset_t)`.
const SIGSET_SIZE: u64 = 8;

fn put(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_ne_bytes());
}

fn get(b: &[u8], off: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[off..off + 8]);
    u64::from_ne_bytes(w)
}

/// Changes the registers of a system call that gave a restart code, when no handler runs: the
/// call starts again. After `ERESTART_RESTARTBLOCK`, the thread calls `restart_syscall`, which
/// continues the call from the state that it kept.
fn restart_without_handler(regs: &mut UserContext, e: Errno, number: u64) {
    let number =
        if e == Errno::ERESTART_RESTARTBLOCK { u64::from(nr::RESTART_SYSCALL) } else { number };
    regs.restart_syscall(number);
}

/// Changes the registers of a system call that gave a restart code, before a handler runs, as
/// `handle_signal` of Linux does. `ERESTARTSYS` starts again only with `SA_RESTART`.
fn restart_with_handler(regs: &mut UserContext, e: Errno, number: u64, flags: u64) {
    let again = e == Errno::ERESTARTNOINTR
        || (e == Errno::ERESTARTSYS && flags & u64::from(SA_RESTART) != 0);
    if again {
        regs.restart_syscall(number);
    } else {
        regs.set_syscall_return(Errno::EINTR.to_syscall_return() as u64);
    }
}

/// Delivers the next signal of `thread` before the return to user mode. `syscall` is the number
/// of the system call that the thread made, if the return is from one that can restart. Gives
/// the status of the thread if the signal ends the process. While the process is stopped, the
/// thread waits here. A traced thread stops for its tracer here.
pub(crate) fn deliver(
    thread: &Arc<Thread>,
    regs: &mut UserContext,
    mut syscall: Option<u64>,
) -> Option<WaitStatus> {
    let delivery = loop {
        thread.wait_while_stopped();
        if thread.is_killed() {
            return None;
        }
        let delivery = if thread.is_traced() {
            match traced_signal(thread, regs, &mut syscall) {
                Some(delivery) => delivery,
                None => continue,
            }
        } else {
            thread.dequeue_signal()
        };
        match delivery {
            Some(Delivery::Stop(sig)) => rk_proc::stop_group(thread, sig),
            delivery => break delivery,
        }
    };
    // The tracer can change the return value and `orig_rax`, so the check comes after the stops.
    let restart = syscall.and_then(|number| {
        let e = Errno::from_syscall_return(regs.syscall_return() as isize)?;
        e.is_restart().then_some((e, number))
    });
    match delivery {
        // The loop above takes each stop, so `Stop` does not come here.
        None | Some(Delivery::Stop(_)) => {
            if let Some((e, number)) = restart {
                restart_without_handler(regs, e, number);
            }
            if let Some(mask) = thread.take_saved_mask() {
                thread.set_blocked(mask);
            }
            None
        }
        Some(Delivery::Fatal(status)) => {
            rk_proc::exit_group(thread, status);
            Some(thread.process().group_exit().unwrap_or(status))
        }
        Some(Delivery::Handler(info, action)) => {
            if let Some((e, number)) = restart {
                restart_with_handler(regs, e, number, action.flags);
            }
            let blocked = thread.blocked();
            let mask = thread.take_saved_mask().unwrap_or(blocked);
            if frame::setup_frame(thread, regs, &info, &action, mask).is_err() {
                // The frame does not fit, so the thread cannot run the handler. Linux sends
                // `SIGSEGV` with the default action then.
                let status = thread.process().fatal_status(SIGSEGV);
                rk_proc::exit_group(thread, status);
                return Some(thread.process().group_exit().unwrap_or(status));
            }
            let mut blocked = SigSet(blocked.0 | action.mask);
            if action.flags & u64::from(SA_NODEFER) == 0 {
                blocked.add(info.signo);
            }
            thread.set_blocked(blocked);
            None
        }
    }
}

/// Takes the next stop or signal of the traced `thread`, as `get_signal` and `ptrace_signal` of
/// Linux do: first a group stop, then a `PTRACE_INTERRUPT`, and then the next signal, which the
/// tracer sees before its action applies. `syscall` is the system call of the thread, which the
/// tracer can change with `orig_rax`. Gives the delivery of the signal, `Some(None)` if no signal
/// is pending, or `None` if the loop must look again.
fn traced_signal(
    thread: &Arc<Thread>,
    regs: &mut UserContext,
    syscall: &mut Option<u64>,
) -> Option<Option<Delivery>> {
    let orig = syscall.unwrap_or(NO_SYSCALL);
    let mut update = |orig_rax: u64| {
        if syscall.is_some() {
            *syscall = (orig_rax != NO_SYSCALL).then_some(orig_rax);
        }
    };
    if let Some(sig) = thread.take_group_stop() {
        if let Some(r) = ptrace::stop(thread, regs, orig, StopKind::Group, sig, None) {
            update(r.orig_rax);
        }
        return None;
    }
    if thread.take_interrupt() {
        let kind = StopKind::Event(PTRACE_EVENT_STOP);
        // The stop gives the signal of the group stop while the process is stopped, as
        // `do_jobctl_trap` of Linux does.
        let sig = thread.process().stop_signal().unwrap_or(SIGTRAP);
        if let Some(r) = ptrace::stop(thread, regs, orig, kind, sig, None) {
            update(r.orig_rax);
        }
        return None;
    }
    let Some(mut info) = thread.next_signal() else { return Some(None) };
    let tracer = thread.tracer_pid();
    let Some(r) = ptrace::stop(thread, regs, orig, StopKind::Signal, info.signo, Some(info)) else {
        // The tracer went away, so the signal has the usual delivery.
        if !thread.is_killed() {
            thread.requeue_signal(info);
        }
        return None;
    };
    update(r.orig_rax);
    if r.sig == 0 {
        return None;
    }
    if let Some(new) = r.info {
        info = new;
    }
    if r.sig != info.signo {
        info = SigInfo::new(r.sig, SI_USER, tracer);
    }
    if thread.blocked().contains(info.signo) {
        thread.requeue_signal(info);
        return None;
    }
    // An action that discards the signal makes the loop look again.
    thread.signal_delivery(info).map(Some)
}

/// Checks a new alternate stack and sets it, as `do_sigaltstack` of Linux does. `rsp` is the
/// user stack pointer.
fn set_altstack(thread: &Thread, new: AltStack, rsp: u64) -> Result<(), Errno> {
    if thread.altstack().contains(rsp) {
        return Err(Errno::EPERM);
    }
    let mode = new.flags & !SS_AUTODISARM;
    if mode != 0 && mode != SS_DISABLE && mode != SS_ONSTACK {
        return Err(Errno::EINVAL);
    }
    let stack = if mode == SS_DISABLE {
        AltStack::default()
    } else if new.size < u64::from(MINSIGSTKSZ) {
        return Err(Errno::ENOMEM);
    } else {
        AltStack { sp: new.sp, size: new.size, flags: new.flags & SS_AUTODISARM }
    };
    thread.set_altstack(stack);
    Ok(())
}

pub(crate) fn sigaltstack(cx: &Cx<'_>, ss: u64, old_ss: u64) -> SysResult {
    let rsp = cx.regs.sp();
    let old = cx.thread.altstack();
    if ss != 0 {
        let n: Sigaltstack = cx.read_val(ss)?;
        let new = AltStack { sp: n.ss_sp, size: n.ss_size, flags: n.ss_flags as u32 };
        set_altstack(cx.thread, new, rsp)?;
    }
    if old_ss != 0 {
        let mut o = Sigaltstack::new_zeroed();
        o.ss_sp = old.sp;
        o.ss_size = old.size;
        o.ss_flags = old.flags_at(rsp) as i32;
        cx.write_val(old_ss, &o)?;
    }
    Ok(0)
}

pub(crate) fn rt_sigaction(cx: &Cx<'_>, sig: u64, act: u64, oact: u64, size: u64) -> SysResult {
    if size != SIGSET_SIZE || sig == 0 || sig > u64::from(NSIG) {
        return Err(Errno::EINVAL);
    }
    let sig = sig as u32;
    let new = if act == 0 {
        None
    } else {
        if sig == SIGKILL || sig == SIGSTOP {
            return Err(Errno::EINVAL);
        }
        let mut a: SigAction = cx.read_val(act)?;
        a.mask &= !SigSet::UNBLOCKABLE.0;
        Some(a)
    };
    let old = match new {
        Some(a) => cx.process().set_action(sig, a),
        None => cx.process().action(sig),
    };
    cx.write_opt(oact, &old)?;
    Ok(0)
}

pub(crate) fn rt_sigprocmask(cx: &Cx<'_>, how: u64, set: u64, oset: u64, size: u64) -> SysResult {
    if size != SIGSET_SIZE {
        return Err(Errno::EINVAL);
    }
    let old = cx.thread.blocked();
    if set != 0 {
        let new: u64 = cx.read_val(set)?;
        let mask = match how as u32 {
            SIG_BLOCK => old.0 | new,
            SIG_UNBLOCK => old.0 & !new,
            SIG_SETMASK => new,
            _ => return Err(Errno::EINVAL),
        };
        cx.thread.set_blocked(SigSet(mask));
    }
    cx.write_opt(oset, &old.0)?;
    Ok(0)
}

pub(crate) fn rt_sigpending(cx: &Cx<'_>, set: u64, size: u64) -> SysResult {
    if size > SIGSET_SIZE {
        return Err(Errno::EINVAL);
    }
    let pending = cx.thread.pending().0 & cx.thread.blocked().0;
    cx.write_bytes(set, &pending.to_ne_bytes()[..size as usize])?;
    Ok(0)
}

/// Waits until a signal that the thread does not block is pending.
fn wait_for_signal(thread: &Thread) {
    let queue = rk_frame::task::WaitQueue::new();
    queue.wait_until(|| thread.signal_pending().then_some(()));
}

pub(crate) fn rt_sigsuspend(cx: &Cx<'_>, mask: u64, size: u64) -> SysResult {
    if size != SIGSET_SIZE {
        return Err(Errno::EINVAL);
    }
    let mask: u64 = cx.read_val(mask)?;
    let old = cx.thread.blocked();
    cx.thread.set_blocked(SigSet(mask));
    cx.thread.set_saved_mask(old);
    wait_for_signal(cx.thread);
    Err(Errno::ERESTARTNOHAND)
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn pause(cx: &Cx<'_>) -> SysResult {
    wait_for_signal(cx.thread);
    Err(Errno::ERESTARTNOHAND)
}

/// Sends `info` to each process in the group `pgid`. Gives `ESRCH` if the group is empty.
pub(crate) fn signal_group(pgid: Pid, info: SigInfo) -> Result<(), Errno> {
    let members: alloc::vec::Vec<Arc<Process>> =
        rk_proc::processes().into_iter().filter(|p| p.pgid() == pgid && !p.is_zombie()).collect();
    if members.is_empty() {
        return Err(Errno::ESRCH);
    }
    for p in members {
        rk_proc::send_signal(&p, info);
    }
    Ok(())
}

/// Checks that the caller can send `sig` to `target`, as `check_kill_permission` of Linux. A
/// process in the same session can always send `SIGCONT`.
fn may_signal(cx: &Cx<'_>, target: &Process, sig: u32) -> Result<(), Errno> {
    let me = cx.process();
    if me.cred().may_kill(&target.cred()) || (sig == SIGCONT && me.sid() == target.sid()) {
        Ok(())
    } else {
        Err(Errno::EPERM)
    }
}

/// Sends `info` to each process in the group `pgid` that the caller can signal, as
/// `__kill_pgrp_info` of Linux. Gives `ESRCH` if the group is empty, and `EPERM` if the caller
/// can signal no process of it.
fn kill_group(cx: &Cx<'_>, pgid: Pid, info: SigInfo) -> Result<(), Errno> {
    let members: alloc::vec::Vec<Arc<Process>> =
        rk_proc::processes().into_iter().filter(|p| p.pgid() == pgid && !p.is_zombie()).collect();
    let mut result = Err(Errno::ESRCH);
    for p in members {
        match may_signal(cx, &p, info.signo) {
            Ok(()) => {
                rk_proc::send_signal(&p, info);
                result = Ok(());
            }
            Err(e) if result.is_err() => result = Err(e),
            Err(_) => {}
        }
    }
    result
}

pub(crate) fn kill(cx: &Cx<'_>, pid: u64, sig: u64) -> SysResult {
    if sig > u64::from(NSIG) {
        return Err(Errno::EINVAL);
    }
    let me = cx.process();
    let mut info = SigInfo::new(sig as u32, SI_USER, me.pid());
    info.uid = me.cred().uid;
    match pid as i32 {
        0 => kill_group(cx, me.pgid(), info)?,
        -1 => {
            // A process that the caller cannot signal does not count, as in Linux.
            let mut count = 0;
            for p in rk_proc::processes() {
                if p.pid() != rk_proc::INIT_PID
                    && p.pid() != me.pid()
                    && !p.is_zombie()
                    && may_signal(cx, &p, info.signo).is_ok()
                {
                    rk_proc::send_signal(&p, info);
                    count += 1;
                }
            }
            if count == 0 {
                return Err(Errno::ESRCH);
            }
        }
        p if p > 0 => {
            let target = rk_proc::find_process(p as Pid)
                .or_else(|| rk_proc::find_thread(p as Pid).map(|t| t.process().clone()))
                .ok_or(Errno::ESRCH)?;
            may_signal(cx, &target, info.signo)?;
            rk_proc::send_signal(&target, info);
        }
        i32::MIN => return Err(Errno::ESRCH),
        p => kill_group(cx, p.unsigned_abs(), info)?,
    }
    Ok(0)
}

/// Sends `sig` to the thread `tid`. If `tgid` is given, the thread must be in that process.
fn signal_thread(cx: &Cx<'_>, tgid: Option<u64>, tid: u64, sig: u64) -> SysResult {
    if tid as i32 <= 0 || tgid.is_some_and(|g| g as i32 <= 0) {
        return Err(Errno::EINVAL);
    }
    if sig > u64::from(NSIG) {
        return Err(Errno::EINVAL);
    }
    let thread = rk_proc::find_thread(tid as Pid).ok_or(Errno::ESRCH)?;
    if tgid.is_some_and(|g| thread.process().pid() != g as Pid) {
        return Err(Errno::ESRCH);
    }
    may_signal(cx, thread.process(), sig as u32)?;
    if sig != 0 {
        let mut info = SigInfo::new(sig as u32, SI_TKILL, cx.process().pid());
        info.uid = cx.process().cred().uid;
        thread.send_signal(info);
    }
    Ok(0)
}

pub(crate) fn tkill(cx: &Cx<'_>, tid: u64, sig: u64) -> SysResult {
    signal_thread(cx, None, tid, sig)
}

pub(crate) fn tgkill(cx: &Cx<'_>, tgid: u64, tid: u64, sig: u64) -> SysResult {
    signal_thread(cx, Some(tgid), tid, sig)
}

pub(crate) fn rt_sigtimedwait(
    cx: &Cx<'_>,
    set: u64,
    uinfo: u64,
    timeout: u64,
    size: u64,
) -> SysResult {
    if size != SIGSET_SIZE {
        return Err(Errno::EINVAL);
    }
    let set: u64 = cx.read_val(set)?;
    let set = SigSet(set).without(SigSet::UNBLOCKABLE);
    let deadline = if timeout == 0 {
        None
    } else {
        let ts: KernelTimespec = cx.read_val(timeout)?;
        Some(crate::info::deadline_after(crate::info::timespec_ns(&ts)?))
    };
    let thread = cx.thread;
    let mut info = thread.take_signal(set);
    if info.is_none() && deadline != Some(rk_frame::time::ticks()) {
        // The signals of `set` wake the thread while it waits, as if it did not block them.
        thread.set_waiting(set);
        let queue = rk_frame::task::WaitQueue::new();
        let cond = || match thread.take_signal(set) {
            Some(i) => Some(Some(i)),
            None => thread.signal_pending().then_some(None),
        };
        info = match deadline {
            Some(d) => queue.wait_until_timeout(d, cond).flatten(),
            None => queue.wait_until(cond),
        };
        thread.set_waiting(SigSet::EMPTY);
        // A signal can come after the wait and before the end of the wait set.
        if info.is_none() {
            info = thread.take_signal(set);
        }
        if info.is_none() && thread.signal_pending() {
            return Err(Errno::EINTR);
        }
    }
    let info = info.ok_or(Errno::EAGAIN)?;
    if uinfo != 0 {
        cx.write_bytes(uinfo, &info.to_bytes())?;
    }
    Ok(u64::from(info.signo))
}

/// Reads the `siginfo_t` of `rt_sigqueueinfo` and `rt_tgsigqueueinfo`. A program can send a
/// signal with a code that tells that the kernel or `kill` sent it only to itself, as
/// `do_rt_sigqueueinfo` of Linux tells.
fn queue_info(cx: &Cx<'_>, target: Pid, sig: u64, uinfo: u64) -> Result<SigInfo, Errno> {
    if sig > u64::from(NSIG) {
        return Err(Errno::EINVAL);
    }
    let b = cx.read_bytes(uinfo, SIGINFO_SIZE)?;
    let mut raw = [0u8; SIGINFO_SIZE];
    raw.copy_from_slice(&b);
    let mut info = SigInfo::from_bytes(&raw);
    if (info.code >= 0 || info.code == SI_TKILL) && target != cx.process().pid() {
        return Err(Errno::EPERM);
    }
    info.signo = sig as u32;
    Ok(info)
}

pub(crate) fn rt_sigqueueinfo(cx: &Cx<'_>, tgid: u64, sig: u64, uinfo: u64) -> SysResult {
    let info = queue_info(cx, tgid as Pid, sig, uinfo)?;
    // Linux finds the process from any of its thread IDs, as `kill` does.
    let target = rk_proc::find_process(tgid as Pid)
        .or_else(|| rk_proc::find_thread(tgid as Pid).map(|t| t.process().clone()))
        .filter(|p| tgid as i32 > 0 && !p.is_zombie())
        .ok_or(Errno::ESRCH)?;
    may_signal(cx, &target, sig as u32)?;
    if sig != 0 {
        rk_proc::send_signal(&target, info);
    }
    Ok(0)
}

pub(crate) fn rt_tgsigqueueinfo(
    cx: &Cx<'_>,
    tgid: u64,
    tid: u64,
    sig: u64,
    uinfo: u64,
) -> SysResult {
    if tid as i32 <= 0 || tgid as i32 <= 0 {
        return Err(Errno::EINVAL);
    }
    let info = queue_info(cx, tgid as Pid, sig, uinfo)?;
    let thread = rk_proc::find_thread(tid as Pid)
        .filter(|t| t.process().pid() == tgid as Pid)
        .ok_or(Errno::ESRCH)?;
    may_signal(cx, thread.process(), sig as u32)?;
    if sig != 0 {
        thread.send_signal(info);
    }
    Ok(0)
}

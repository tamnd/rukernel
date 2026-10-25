//! The signal system calls, and the delivery of a signal to a user thread.
//!
//! Before the task goes back to user mode, it takes the next signal that the thread does not
//! block. For a handler, the kernel writes the `rt_sigframe` of the x86-64 ABI on the user stack
//! and starts the handler. The handler returns to the restorer of the C library, which calls
//! `rt_sigreturn`. That call reads the saved registers back from the frame. This is the method of
//! arch/x86/kernel/signal.c and signal_64.c.

use crate::cx::{Cx, SysResult};
use alloc::sync::Arc;
use alloc::vec;
use rk_abi::Errno;
use rk_abi::native::signal::{
    MINSIGSTKSZ, SA_NODEFER, SA_ONSTACK, SA_RESTART, SA_RESTORER, SIG_BLOCK, SIG_SETMASK,
    SIG_UNBLOCK, SIGCONT, SIGKILL, SIGSEGV, SIGSTOP, SIGTRAP,
};
use rk_abi::native::syscalls as nr;
use rk_abi::native::types::{KernelTimespec, Sigaltstack};
use rk_frame::user::{FpuState, UserContext};
use rk_proc::ptrace::{self, NO_SYSCALL, PTRACE_EVENT_STOP, StopKind};
use rk_proc::signal::{
    AltStack, NSIG, SI_KERNEL, SI_TKILL, SI_USER, SIGINFO_SIZE, SS_AUTODISARM, SS_DISABLE,
    SS_ONSTACK, SigAction, SigInfo, SigSet,
};
use rk_proc::{Delivery, Pid, Process, Thread, WaitStatus};
use zerocopy::FromZeros;

/// The size of a signal set in the system calls. Linux names it `sizeof(sigset_t)`.
const SIGSET_SIZE: u64 = 8;

/// The length of the `syscall` instruction.
const SYSCALL_INSN_LEN: u64 = 2;

/// The bytes below the stack pointer that a leaf function can use. The frame goes below them.
const RED_ZONE: u64 = 128;
/// The size of `struct ucontext`: the flags, the link, the stack, the `sigcontext` and the mask.
const UCONTEXT_SIZE: usize = 304;
/// The size of `struct rt_sigframe`: the return address, the `ucontext` and the `siginfo`.
const FRAME_SIZE: u64 = 8 + UCONTEXT_SIZE as u64 + SIGINFO_SIZE as u64;
/// The offsets in `struct ucontext`.
const UC_STACK: usize = 16;
const UC_MCONTEXT: usize = 40;
const UC_SIGMASK: usize = 296;
/// The `uc_flags` of a 64 bit frame: the frame holds SS, and `rt_sigreturn` loads it as it is.
const UC_FLAGS: u64 = 0x2 | 0x4;
/// The user code and stack selectors, as the GDT of rk-frame has them.
const USER_CS: u16 = 0x33;
const USER_SS: u16 = 0x2b;

/// The flags that `rt_sigreturn` takes from the frame: AC, OF, DF, TF, SF, ZF, AF, PF, CF and RF.
/// Linux names this set `FIX_EFLAGS`.
const FIX_EFLAGS: u64 = 0x0005_0dd5;
/// The flags that the kernel clears for a handler: DF, TF and RF.
const HANDLER_CLEAR: u64 = (1 << 10) | (1 << 8) | (1 << 16);

fn put(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_ne_bytes());
}

fn get(b: &[u8], off: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[off..off + 8]);
    u64::from_ne_bytes(w)
}

/// Writes the `sigcontext` of `regs` in `b`. The order is the order of `struct sigcontext_64`:
/// r8 to r15, rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, rip, eflags, the selectors, err, trapno,
/// oldmask, cr2 and the address of the FPU state.
fn put_sigcontext(b: &mut [u8], regs: &UserContext, mask: SigSet, fpstate: u64) {
    let r = regs.regs();
    let words = [
        r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15, r.rdi, r.rsi, r.rbp, r.rbx, r.rdx,
        r.rax, r.rcx, r.rsp, r.rip, r.rflags,
    ];
    for (i, w) in words.iter().enumerate() {
        put(b, i * 8, *w);
    }
    b[144..146].copy_from_slice(&USER_CS.to_ne_bytes());
    b[150..152].copy_from_slice(&USER_SS.to_ne_bytes());
    put(b, 168, mask.0);
    put(b, 184, fpstate);
}

/// Reads the registers of a `sigcontext` into `regs`. Gives the address of the FPU state.
fn get_sigcontext(b: &[u8], regs: &mut UserContext) -> u64 {
    let r = regs.regs_mut();
    let dst = [
        &mut r.r8, &mut r.r9, &mut r.r10, &mut r.r11, &mut r.r12, &mut r.r13, &mut r.r14,
        &mut r.r15, &mut r.rdi, &mut r.rsi, &mut r.rbp, &mut r.rbx, &mut r.rdx, &mut r.rax,
        &mut r.rcx, &mut r.rsp, &mut r.rip,
    ];
    for (i, d) in dst.into_iter().enumerate() {
        *d = get(b, i * 8);
    }
    r.rflags = (r.rflags & !FIX_EFLAGS) | (get(b, 136) & FIX_EFLAGS);
    get(b, 184)
}

/// Writes the frame of `info` on the user stack and sets the registers for the handler. The
/// frame holds the registers of `regs`, the FPU state and `mask`, the mask that `rt_sigreturn`
/// puts back.
fn setup_frame(
    thread: &Thread,
    regs: &mut UserContext,
    info: &SigInfo,
    action: &SigAction,
    mask: SigSet,
) -> Result<(), Errno> {
    if action.flags & u64::from(SA_RESTORER) == 0 {
        return Err(Errno::EFAULT);
    }
    let vm = thread.process().vm().ok_or(Errno::EFAULT)?;
    let user_sp = regs.regs().rsp;
    let alt = thread.altstack();
    let mut sp = user_sp.wrapping_sub(RED_ZONE);
    if action.flags & u64::from(SA_ONSTACK) != 0 && alt.size != 0 && !alt.contains(user_sp) {
        sp = alt.sp + alt.size;
    }
    let fpstate = sp.wrapping_sub(FpuState::SIZE as u64) & !63;
    let frame = (fpstate.wrapping_sub(FRAME_SIZE) & !15).wrapping_sub(8);

    let mut fp = *regs.fpu().as_bytes();
    // The bytes after 464 are free for software. With no XSAVE data, they stay 0.
    fp[464..].fill(0);
    vm.write(fpstate as usize, &fp)?;

    let mut b = vec![0u8; FRAME_SIZE as usize];
    put(&mut b, 0, action.restorer);
    let uc = &mut b[8..8 + UCONTEXT_SIZE];
    put(uc, 0, UC_FLAGS);
    put(uc, UC_STACK, alt.sp);
    uc[UC_STACK + 8..UC_STACK + 12].copy_from_slice(&alt.flags_at(user_sp).to_ne_bytes());
    put(uc, UC_STACK + 16, alt.size);
    put_sigcontext(&mut uc[UC_MCONTEXT..UC_SIGMASK], regs, mask, fpstate);
    put(uc, UC_SIGMASK, mask.0);
    b[8 + UCONTEXT_SIZE..].copy_from_slice(&info.to_bytes());
    vm.write(frame as usize, &b)?;

    if alt.flags & SS_AUTODISARM != 0 {
        thread.set_altstack(AltStack::default());
    }
    let r = regs.regs_mut();
    r.rdi = u64::from(info.signo);
    r.rsi = frame + 8 + UCONTEXT_SIZE as u64;
    r.rdx = frame + 8;
    r.rax = 0;
    r.rsp = frame;
    r.rip = action.handler;
    r.rflags &= !HANDLER_CLEAR;
    // The handler starts with a clean FPU, as `fpu__clear_user_states` of Linux gives it.
    regs.set_fpu(FpuState::default());
    Ok(())
}

/// Changes the registers of a system call that gave a restart code, when no handler runs: the
/// call starts again. After `ERESTART_RESTARTBLOCK`, the thread calls `restart_syscall`, which
/// continues the call from the state that it kept.
fn restart_without_handler(regs: &mut UserContext, e: Errno, number: u64) {
    let r = regs.regs_mut();
    r.rax = if e == Errno::ERESTART_RESTARTBLOCK { u64::from(nr::RESTART_SYSCALL) } else { number };
    r.rip -= SYSCALL_INSN_LEN;
}

/// Changes the registers of a system call that gave a restart code, before a handler runs, as
/// `handle_signal` of Linux does. `ERESTARTSYS` starts again only with `SA_RESTART`.
fn restart_with_handler(regs: &mut UserContext, e: Errno, number: u64, flags: u64) {
    let again = e == Errno::ERESTARTNOINTR
        || (e == Errno::ERESTARTSYS && flags & u64::from(SA_RESTART) != 0);
    if again {
        let r = regs.regs_mut();
        r.rax = number;
        r.rip -= SYSCALL_INSN_LEN;
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
        let e = Errno::from_syscall_return(regs.regs().rax as isize)?;
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
            if setup_frame(thread, regs, &info, &action, mask).is_err() {
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

pub(crate) fn rt_sigreturn(cx: &mut Cx<'_>) -> SysResult {
    let uc = cx.regs.regs().rsp;
    let Ok(b) = cx.read_bytes(uc, UCONTEXT_SIZE) else {
        cx.thread.force_signal(SigInfo::new(SIGSEGV, SI_KERNEL, 0));
        return Ok(0);
    };
    let mut regs = *cx.regs;
    let fpstate = get_sigcontext(&b[UC_MCONTEXT..UC_SIGMASK], &mut regs);
    let fpu = if fpstate == 0 {
        FpuState::default()
    } else {
        match cx.read_bytes(fpstate, FpuState::SIZE) {
            Ok(fp) => {
                let mut a = [0u8; FpuState::SIZE];
                a.copy_from_slice(&fp);
                FpuState::from_bytes(&a)
            }
            Err(_) => {
                cx.thread.force_signal(SigInfo::new(SIGSEGV, SI_KERNEL, 0));
                return Ok(0);
            }
        }
    };
    regs.set_fpu(fpu);
    *cx.regs = regs;
    cx.thread.set_blocked(SigSet(get(&b, UC_SIGMASK)));
    // The call that the handler interrupted does not continue, as in Linux.
    cx.thread.set_restart(None);
    let flags =
        u32::from_ne_bytes([b[UC_STACK + 8], b[UC_STACK + 9], b[UC_STACK + 10], b[UC_STACK + 11]]);
    let stack = AltStack { sp: get(&b, UC_STACK), size: get(&b, UC_STACK + 16), flags };
    let _ = set_altstack(cx.thread, stack, cx.regs.regs().rsp);
    Ok(cx.regs.regs().rax)
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
    let rsp = cx.regs.regs().rsp;
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
    let info = SigInfo::new(sig as u32, SI_USER, me.pid());
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
        thread.send_signal(SigInfo::new(sig as u32, SI_TKILL, cx.process().pid()));
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

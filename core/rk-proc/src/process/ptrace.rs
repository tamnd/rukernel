//! The tracing of threads, for `ptrace`.
//!
//! A tracer is a process, and a tracee is a thread. A tracee stops at the events that the tracer
//! asks for: a signal, the entry to a system call and the return from it, a `fork`, an `execve`
//! or the exit. While the tracee is stopped, its registers are here, and the tracer reads and
//! changes them. The tracee loads them again when the tracer lets it continue. The tracer gets the
//! stops of its tracees with `wait4`, as it gets the changes of its children. This is the model of
//! kernel/ptrace.c and of `ptrace_stop` in kernel/signal.c of Linux.

use super::{Pid, Process, State, Thread, kill_group, send_signal};
use crate::signal::{CLD_TRAPPED, SigInfo};
use crate::wait::{WaitOptions, WaitResult, WaitStatus, WaitTarget};
use alloc::sync::{Arc, Weak};
use rk_abi::Errno;
use rk_abi::native::signal::{SA_NOCLDSTOP, SIGCHLD, SIGKILL, SIGSTOP, SIGTRAP};
use rk_frame::task::WaitQueue;
use rk_frame::user::UserContext;

/// The `ptrace` events, from include/uapi/linux/ptrace.h.
pub const PTRACE_EVENT_FORK: u32 = 1;
/// The tracee called `vfork`.
pub const PTRACE_EVENT_VFORK: u32 = 2;
/// The tracee called `clone`.
pub const PTRACE_EVENT_CLONE: u32 = 3;
/// The tracee called `execve`.
pub const PTRACE_EVENT_EXEC: u32 = 4;
/// The child of `vfork` called `execve` or ended.
pub const PTRACE_EVENT_VFORK_DONE: u32 = 5;
/// The tracee ends.
pub const PTRACE_EVENT_EXIT: u32 = 6;
/// The stop for `SECCOMP_RET_TRACE`.
pub const PTRACE_EVENT_SECCOMP: u32 = 7;
/// The stop of `PTRACE_INTERRUPT`, and the group stop of a tracee of `PTRACE_SEIZE`.
pub const PTRACE_EVENT_STOP: u32 = 128;

/// The options of `PTRACE_SETOPTIONS`.
pub const PTRACE_O_TRACESYSGOOD: u32 = 1;
/// Stop at `fork` and trace the child.
pub const PTRACE_O_TRACEFORK: u32 = 1 << PTRACE_EVENT_FORK;
/// Stop at `vfork` and trace the child.
pub const PTRACE_O_TRACEVFORK: u32 = 1 << PTRACE_EVENT_VFORK;
/// Stop at `clone` and trace the child.
pub const PTRACE_O_TRACECLONE: u32 = 1 << PTRACE_EVENT_CLONE;
/// Stop at `execve`.
pub const PTRACE_O_TRACEEXEC: u32 = 1 << PTRACE_EVENT_EXEC;
/// Stop when the child of `vfork` lets the parent continue.
pub const PTRACE_O_TRACEVFORKDONE: u32 = 1 << PTRACE_EVENT_VFORK_DONE;
/// Stop at the exit.
pub const PTRACE_O_TRACEEXIT: u32 = 1 << PTRACE_EVENT_EXIT;
/// Stop at a `SECCOMP_RET_TRACE` filter. rukernel has no seccomp yet.
pub const PTRACE_O_TRACESECCOMP: u32 = 1 << PTRACE_EVENT_SECCOMP;
/// Send `SIGKILL` to the tracee when the tracer ends.
pub const PTRACE_O_EXITKILL: u32 = 1 << 20;
/// Do not run the seccomp filters of the tracee.
pub const PTRACE_O_SUSPEND_SECCOMP: u32 = 1 << 21;
/// Each option that `PTRACE_SETOPTIONS` accepts.
pub const PTRACE_O_MASK: u32 = 0xff | PTRACE_O_EXITKILL | PTRACE_O_SUSPEND_SECCOMP;

/// The event message of a stop at the entry to a system call and at the return from it.
const EVENTMSG_SYSCALL_ENTRY: u64 = 1;
const EVENTMSG_SYSCALL_EXIT: u64 = 2;

/// The trap flag of RFLAGS. The CPU stops after one instruction when it is set.
const RFLAGS_TF: u64 = 1 << 8;

/// The value of `orig_rax` when the tracee is not in a system call.
pub const NO_SYSCALL: u64 = u64::MAX;

/// What stopped a tracee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopKind {
    /// A signal, before its delivery.
    Signal,
    /// The stop of the thread group.
    Group,
    /// The entry to a system call.
    SyscallEntry,
    /// The return from a system call.
    SyscallExit,
    /// A `PTRACE_EVENT_*` event.
    Event(u32),
}

/// The state of a stopped tracee.
#[derive(Clone, Copy, Debug)]
pub struct Stop {
    /// What stopped the tracee.
    pub kind: StopKind,
    /// The registers. The tracee loads them again when it continues.
    pub regs: UserContext,
    /// The value of `orig_rax`: the number of the system call, or `NO_SYSCALL`.
    pub orig_rax: u64,
    /// The signal information, for `PTRACE_GETSIGINFO`. A group stop of a tracee of
    /// `PTRACE_ATTACH` has none.
    pub info: Option<SigInfo>,
    /// The status that the wait of the tracer gives.
    status: WaitStatus,
    /// The wait of the tracer took the stop.
    reported: bool,
    /// The signal that the tracer gave when it let the tracee continue, or `None` while the tracee
    /// stays stopped.
    resume: Option<u32>,
    /// `PTRACE_LISTEN`: the tracee stays stopped until the group continues.
    listening: bool,
}

/// The tracing state of a thread.
#[derive(Debug)]
pub struct Ptrace {
    tracer: Weak<Process>,
    /// The tracer used `PTRACE_SEIZE`.
    seized: bool,
    /// The `PTRACE_O_*` options.
    pub options: u32,
    /// The message of the last event, for `PTRACE_GETEVENTMSG`.
    pub message: u64,
    /// `PTRACE_SYSCALL`: stop at the entry to each system call and at the return from it.
    syscall: bool,
    /// `PTRACE_SINGLESTEP`: stop after one instruction.
    step: bool,
    /// The kernel set the trap flag for a single step. The user program did not set it.
    forced_tf: bool,
    /// `PTRACE_INTERRUPT`: stop with `PTRACE_EVENT_STOP` at the next return to user mode.
    interrupt: bool,
    /// The tracer detached while the tracee was stopped. The tracee drops the state when it
    /// continues.
    detached: bool,
    /// The stop, while the tracee is stopped.
    stop: Option<Stop>,
    /// The status of a thread that ended and is not the leader of its process, until the wait of
    /// the tracer takes it.
    exit: Option<WaitStatus>,
    /// The debug registers DR0 to DR7 that the tracer wrote. rukernel keeps them for
    /// `PTRACE_PEEKUSR`, but does not load them into the CPU.
    pub debugreg: [u64; 8],
}

impl Ptrace {
    fn new(tracer: &Arc<Process>, seized: bool, options: u32) -> Self {
        Self {
            tracer: Arc::downgrade(tracer),
            seized,
            options,
            message: 0,
            syscall: false,
            step: false,
            forced_tf: false,
            interrupt: false,
            detached: false,
            stop: None,
            exit: None,
            debugreg: [0; 8],
        }
    }

    /// The flags of the stopped tracee as the tracer sees them. The trap flag that the kernel set
    /// for a single step is not there, as `get_flags` of Linux gives it.
    pub fn flags(&self, stop: &Stop) -> u64 {
        let flags = stop.regs.regs().rflags;
        if self.forced_tf { flags & !RFLAGS_TF } else { flags }
    }

    /// Sets the flags of the stopped tracee, as `set_flags` of Linux does. Only the bits of
    /// `mask` change. A trap flag from the tracer is its own, and the trap flag of a single step
    /// stays.
    pub fn set_flags(&mut self, stop: &mut Stop, value: u64, mask: u64) {
        let mut value = value & mask;
        if value & RFLAGS_TF != 0 {
            self.forced_tf = false;
        } else if self.forced_tf {
            value |= RFLAGS_TF;
        }
        let r = stop.regs.regs_mut();
        r.rflags = (r.rflags & !mask) | value;
    }

    /// Clears the trap flag in the registers of `stop` if the kernel set it for a single step.
    fn clear_forced_tf(&mut self, stop: &mut Stop) {
        if self.forced_tf {
            stop.regs.regs_mut().rflags &= !RFLAGS_TF;
            self.forced_tf = false;
        }
    }
}

/// What the tracer gave to the tracee when it let the tracee continue.
#[derive(Clone, Copy, Debug)]
pub struct Resumed {
    /// The signal to deliver, or 0.
    pub sig: u32,
    /// The signal information, which `PTRACE_SETSIGINFO` can change.
    pub info: Option<SigInfo>,
    /// The value of `orig_rax`, which the tracer can change.
    pub orig_rax: u64,
}

/// How the tracer lets a stopped tracee continue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resume {
    /// `PTRACE_CONT`.
    Cont,
    /// `PTRACE_SYSCALL`.
    Syscall,
    /// `PTRACE_SINGLESTEP`.
    Step,
    /// `PTRACE_LISTEN`: the tracee stays in the group stop, and the tracer can wait for it again.
    Listen,
    /// `PTRACE_DETACH`.
    Detach,
}

impl Thread {
    /// Tells if a tracer traces the thread.
    pub fn is_traced(&self) -> bool {
        self.ptrace.lock().as_ref().is_some_and(|p| !p.detached)
    }

    /// The process ID of the tracer, or 0, for `/proc/PID/status`.
    pub fn tracer_pid(&self) -> Pid {
        let pt = self.ptrace.lock();
        pt.as_ref().filter(|p| !p.detached).and_then(|p| p.tracer.upgrade()).map_or(0, |t| t.pid)
    }

    /// Tells if the thread is in a stop of `ptrace`.
    pub fn is_trace_stopped(&self) -> bool {
        self.ptrace.lock().as_ref().is_some_and(|p| p.stop.is_some_and(|s| s.resume.is_none()))
    }

    /// Takes the request of `PTRACE_INTERRUPT`.
    pub fn take_interrupt(&self) -> bool {
        self.ptrace.lock().as_mut().is_some_and(|p| core::mem::take(&mut p.interrupt))
    }

    /// Tells if a request of `PTRACE_INTERRUPT` waits.
    pub(super) fn interrupt_pending(&self) -> bool {
        self.ptrace.lock().as_ref().is_some_and(|p| p.interrupt)
    }

    /// Tells if the tracer asked for the stops at the system calls.
    pub fn syscall_traced(&self) -> bool {
        self.ptrace.lock().as_ref().is_some_and(|p| p.syscall)
    }

    /// Tells if the tracer asked for a single step.
    pub fn single_stepping(&self) -> bool {
        self.ptrace.lock().as_ref().is_some_and(|p| p.step)
    }

    /// Tells if the tracer set `PTRACE_O_SUSPEND_SECCOMP`: the `seccomp` mode of the thread does
    /// not check its system calls.
    pub fn seccomp_suspended(&self) -> bool {
        self.ptrace.lock().as_ref().is_some_and(|p| p.options & PTRACE_O_SUSPEND_SECCOMP != 0)
    }

    /// Tells if the tracer asked for the stop at `event`.
    pub fn trace_event_enabled(&self, event: u32) -> bool {
        self.ptrace.lock().as_ref().is_some_and(|p| p.options & (1 << event) != 0)
    }
}

/// Makes `tracer` the tracer of `thread`, for `PTRACE_ATTACH`, `PTRACE_SEIZE` and
/// `PTRACE_TRACEME`. A thread of a stopped process stops for its new tracer.
///
/// # Errors
///
/// Gives `EPERM` if the thread is in the process of the tracer or has a tracer already.
pub fn attach(
    tracer: &Arc<Process>,
    thread: &Arc<Thread>,
    seized: bool,
    options: u32,
) -> Result<(), Errno> {
    if Arc::ptr_eq(tracer, &thread.process) {
        return Err(Errno::EPERM);
    }
    {
        let mut guard = thread.ptrace.lock();
        let mut new = Ptrace::new(tracer, seized, options);
        match guard.as_mut() {
            Some(pt) if !pt.detached => return Err(Errno::EPERM),
            // The tracee did not run yet after the detach, so it takes its last stop from here.
            Some(pt) => new.stop = pt.stop.take(),
            None => {}
        }
        *guard = Some(new);
    }
    tracer.state.lock().tracees.push(thread.clone());
    if thread.process.is_stopped() {
        let sig = thread.process.stop_signal().unwrap_or(SIGSTOP);
        thread.group_stop.store(sig, core::sync::atomic::Ordering::Release);
        thread.wake();
        // As JOBCTL_TRAPPING of Linux: the next request of the tracer finds the tracee stopped.
        tracer.child_wait.wait_until(|| {
            (thread.is_trace_stopped()
                || thread.is_killed()
                || !thread.is_traced()
                || !thread.process.is_stopped())
            .then_some(())
        });
    }
    Ok(())
}

/// Makes the parent of the process of `thread` its tracer, for `PTRACE_TRACEME`.
///
/// # Errors
///
/// Gives `EPERM` if the thread has a tracer already or the process has no parent.
pub fn trace_me(thread: &Arc<Thread>) -> Result<(), Errno> {
    let parent = thread.process.parent().ok_or(Errno::EPERM)?;
    attach(&parent, thread, false, 0)
}

/// Makes the tracer of `parent` the tracer of its new child `child`, for a `fork`, `vfork` or
/// `clone` that the tracer traces. The child stops before its first instruction: with
/// `SIGSTOP`, or with `PTRACE_EVENT_STOP` for a tracer of `PTRACE_SEIZE`.
pub fn attach_child(parent: &Thread, child: &Arc<Thread>) {
    let Some((tracer, seized, options)) = parent
        .ptrace
        .lock()
        .as_ref()
        .and_then(|p| Some((p.tracer.upgrade()?, p.seized, p.options)))
    else {
        return;
    };
    let mut pt = Ptrace::new(&tracer, seized, options);
    pt.interrupt = seized;
    *child.ptrace.lock() = Some(pt);
    tracer.state.lock().tracees.push(child.clone());
    if !seized {
        child.requeue_signal(SigInfo::new(SIGSTOP, crate::signal::SI_USER, 0));
    }
}

/// Gives the tracee `tid` of `tracer`.
fn tracee(tracer: &Process, tid: Pid) -> Option<Arc<Thread>> {
    tracer.state.lock().tracees.iter().find(|t| t.tid == tid).cloned()
}

/// Runs `f` on the tracing state and the stop of the stopped tracee `tid` of `tracer`.
///
/// # Errors
///
/// Gives `ESRCH` if `tid` is not a tracee of `tracer` or is not stopped, else the error of `f`.
pub fn with_stopped<R>(
    tracer: &Process,
    tid: Pid,
    f: impl FnOnce(&mut Ptrace, &mut Stop) -> Result<R, Errno>,
) -> Result<R, Errno> {
    let thread = tracee(tracer, tid).ok_or(Errno::ESRCH)?;
    let mut guard = thread.ptrace.lock();
    let pt = guard.as_mut().filter(|p| !p.detached).ok_or(Errno::ESRCH)?;
    let mut stop = match pt.stop {
        Some(s) if s.resume.is_none() && !s.listening => s,
        _ => return Err(Errno::ESRCH),
    };
    let r = f(pt, &mut stop);
    pt.stop = Some(stop);
    r
}

/// Gives the tracee `tid` of `tracer` if it is stopped, for the access to its memory.
///
/// # Errors
///
/// Gives `ESRCH` if `tid` is not a stopped tracee of `tracer`.
pub fn stopped_tracee(tracer: &Process, tid: Pid) -> Result<Arc<Thread>, Errno> {
    with_stopped(tracer, tid, |_, _| Ok(()))?;
    tracee(tracer, tid).ok_or(Errno::ESRCH)
}

/// Lets the stopped tracee `tid` of `tracer` continue as `how` tells, with the signal `sig`.
///
/// # Errors
///
/// Gives `ESRCH` if `tid` is not a stopped tracee of `tracer`, and `EIO` for `PTRACE_LISTEN` on
/// a stop that is not a `PTRACE_EVENT_STOP` of a tracee of `PTRACE_SEIZE`.
pub fn resume(tracer: &Process, tid: Pid, how: Resume, sig: u32) -> Result<(), Errno> {
    with_stopped(tracer, tid, |pt, stop| {
        if how == Resume::Listen {
            if !pt.seized || stop.status.0 >> 16 != PTRACE_EVENT_STOP as i32 {
                return Err(Errno::EIO);
            }
            // A request of `PTRACE_INTERRUPT` or a `SIGCONT` came during the stop, so the tracee
            // stops again at once, as with `JOBCTL_TRAP_NOTIFY` of Linux.
            if pt.interrupt {
                stop.resume = Some(0);
            } else {
                stop.listening = true;
                return Ok(());
            }
        } else {
            pt.syscall = how == Resume::Syscall;
            pt.step = how == Resume::Step;
            if how == Resume::Step {
                if stop.regs.regs().rflags & RFLAGS_TF == 0 {
                    stop.regs.regs_mut().rflags |= RFLAGS_TF;
                    pt.forced_tf = true;
                }
            } else {
                pt.clear_forced_tf(stop);
            }
            pt.detached = how == Resume::Detach;
            stop.resume = Some(sig);
        }
        Ok(())
    })?;
    if let Some(thread) = tracee(tracer, tid) {
        if how == Resume::Detach {
            tracer.state.lock().tracees.retain(|t| !Arc::ptr_eq(t, &thread));
        }
        thread.wake();
    }
    Ok(())
}

/// Asks the tracee `tid` of `tracer` to stop with `PTRACE_EVENT_STOP`, for `PTRACE_INTERRUPT`.
///
/// # Errors
///
/// Gives `ESRCH` if `tid` is not a tracee of `tracer`, and `EIO` if the tracer did not use
/// `PTRACE_SEIZE`.
pub fn interrupt(tracer: &Process, tid: Pid) -> Result<(), Errno> {
    let thread = tracee(tracer, tid).ok_or(Errno::ESRCH)?;
    {
        let mut guard = thread.ptrace.lock();
        let pt = guard.as_mut().filter(|p| !p.detached).ok_or(Errno::ESRCH)?;
        if !pt.seized {
            return Err(Errno::EIO);
        }
        pt.interrupt = true;
        // A tracee of `PTRACE_LISTEN` stops again at once.
        if let Some(stop) = pt.stop.as_mut().filter(|s| s.listening) {
            stop.listening = false;
            stop.resume = Some(0);
        }
    }
    thread.wake();
    Ok(())
}

/// Sends `SIGKILL` to the process of the tracee `tid` of `tracer`, for `PTRACE_KILL`.
///
/// # Errors
///
/// Gives `ESRCH` if `tid` is not a tracee of `tracer`.
pub fn kill(tracer: &Process, tid: Pid) -> Result<(), Errno> {
    let thread = tracee(tracer, tid).ok_or(Errno::ESRCH)?;
    kill_group(&thread.process, WaitStatus::signaled(SIGKILL, false));
    Ok(())
}

/// Stops the traced `thread` as `kind` tells, and waits until the tracer lets it continue. `sig`
/// is the signal of the status that the tracer gets, `regs` are the registers of the thread, and
/// `orig_rax` is the number of its system call or `NO_SYSCALL`. Gives what the tracer gave, or
/// `None` if the thread has no tracer or the group exits.
pub fn stop(
    thread: &Thread,
    regs: &mut UserContext,
    orig_rax: u64,
    kind: StopKind,
    sig: u32,
    info: Option<SigInfo>,
) -> Option<Resumed> {
    let tracer = {
        let mut guard = thread.ptrace.lock();
        let pt = guard.as_mut().filter(|p| !p.detached)?;
        let Some(tracer) = pt.tracer.upgrade() else {
            *guard = None;
            return None;
        };
        if thread.is_killed() {
            return None;
        }
        let sysgood = if pt.options & PTRACE_O_TRACESYSGOOD != 0 { 0x80 } else { 0 };
        // The signal information of a stop that is not a signal has the ID of the tracee, as
        // `ptrace_do_notify` of Linux gives it.
        let tid = thread.tid;
        let (status, info) = match kind {
            StopKind::Signal => (WaitStatus::stopped(sig), info),
            StopKind::Group if pt.seized => {
                let code = (PTRACE_EVENT_STOP << 8 | sig) as i32;
                (WaitStatus::trapped(sig, PTRACE_EVENT_STOP), Some(SigInfo::new(sig, code, tid)))
            }
            StopKind::Group => (WaitStatus::stopped(sig), None),
            StopKind::SyscallEntry | StopKind::SyscallExit => {
                pt.message = if kind == StopKind::SyscallEntry {
                    EVENTMSG_SYSCALL_ENTRY
                } else {
                    EVENTMSG_SYSCALL_EXIT
                };
                let code = SIGTRAP | sysgood;
                (WaitStatus::stopped(code), Some(SigInfo::new(SIGTRAP, code as i32, tid)))
            }
            StopKind::Event(event) => {
                let code = (event << 8 | SIGTRAP) as i32;
                (WaitStatus::trapped(SIGTRAP, event), Some(SigInfo::new(SIGTRAP, code, tid)))
            }
        };
        pt.stop = Some(Stop {
            kind,
            regs: *regs,
            orig_rax,
            info,
            status,
            reported: false,
            resume: None,
            listening: false,
        });
        tracer
    };
    notify_tracer(&tracer, thread.tid, CLD_TRAPPED, (sig & 0x7f) as i32);
    let queue = WaitQueue::new();
    queue.wait_until(|| {
        if thread.is_killed() {
            return Some(());
        }
        let pt = thread.ptrace.lock();
        match pt.as_ref().and_then(|p| p.stop) {
            Some(s) if s.resume.is_none() => None,
            _ => Some(()),
        }
    });
    let stop = {
        let mut guard = thread.ptrace.lock();
        let pt = guard.as_mut()?;
        let stop = pt.stop.take();
        if pt.detached {
            *guard = None;
        }
        stop
    };
    if thread.is_killed() {
        return None;
    }
    let stop = stop?;
    *regs = stop.regs;
    Some(Resumed { sig: stop.resume.unwrap_or(0), info: stop.info, orig_rax: stop.orig_rax })
}

/// Stops the traced `thread` at the event `event` with the message `message`, if the tracer
/// asked for the event. Gives what the tracer gave, or `None` if the thread did not stop.
pub fn event(
    thread: &Thread,
    regs: &mut UserContext,
    orig_rax: u64,
    event: u32,
    message: u64,
) -> Option<Resumed> {
    {
        let mut guard = thread.ptrace.lock();
        match guard.as_mut() {
            Some(pt) if pt.options & (1 << event) != 0 => pt.message = message,
            _ => return None,
        }
    }
    stop(thread, regs, orig_rax, StopKind::Event(event), SIGTRAP, None)
}

/// The stop of a traced thread after `execve`. `old_tid` was the thread ID before the call.
/// Without `PTRACE_O_TRACEEXEC`, a tracee of `PTRACE_ATTACH` gets `SIGTRAP`, as in Linux.
pub fn exec_event(thread: &Arc<Thread>, regs: &mut UserContext, orig_rax: u64, old_tid: Pid) {
    let (enabled, seized) = match thread.ptrace.lock().as_ref().filter(|p| !p.detached) {
        Some(p) => (p.options & PTRACE_O_TRACEEXEC != 0, p.seized),
        None => return,
    };
    if enabled {
        event(thread, regs, orig_rax, PTRACE_EVENT_EXEC, u64::from(old_tid));
    } else if !seized {
        thread.send_signal(SigInfo::new(SIGTRAP, crate::signal::SI_USER, 0));
    }
}

/// Sends `SIGCHLD` with `code` and `status` about the tracee `tid` to `tracer`, unless the tracer
/// set `SA_NOCLDSTOP` for a stop, and wakes the waits of the tracer.
fn notify_tracer(tracer: &Process, tid: Pid, code: i32, status: i32) {
    if code != CLD_TRAPPED || tracer.action(SIGCHLD).flags & u64::from(SA_NOCLDSTOP) == 0 {
        let mut info = SigInfo::new(SIGCHLD, code, tid);
        info.status = status;
        send_signal(tracer, info);
    }
    tracer.child_wait.wake_all();
}

/// Tells the tracer that the traced `thread` ended with `status`, if the thread is not the leader
/// of its process. The tracer then takes the status with a wait. The exit of the leader goes to
/// the tracer when the process ends.
pub(super) fn thread_exited(thread: &Thread, status: WaitStatus) {
    let tracer = {
        let mut guard = thread.ptrace.lock();
        let Some(pt) = guard.as_mut().filter(|p| !p.detached) else { return };
        let tracer = pt.tracer.upgrade();
        if thread.tid == thread.process.pid {
            *thread.process.leader_tracer.lock() = pt.tracer.clone();
            return;
        }
        pt.stop = None;
        pt.exit = Some(status);
        tracer
    };
    if let Some(tracer) = tracer {
        let (code, value) = status.child_code();
        notify_tracer(&tracer, thread.tid, code, value);
    }
}

/// Tells the tracer of the leader of `process` that the process ended with `status`, if the
/// tracer is not the parent. The parent gets the exit signal in the usual way.
pub(super) fn process_exited(process: &Process, parent: Option<&Arc<Process>>, status: WaitStatus) {
    let Some(tracer) = process.leader_tracer.lock().upgrade() else { return };
    if parent.is_some_and(|p| Arc::ptr_eq(p, &tracer)) {
        return;
    }
    let (code, value) = status.child_code();
    notify_tracer(&tracer, process.pid, code, value);
}

/// Detaches each tracee of `tracer`, because the tracer ends. A tracee of `PTRACE_O_EXITKILL`
/// gets `SIGKILL`.
pub(super) fn release_tracees(tracer: &Process) {
    let tracees = core::mem::take(&mut tracer.state.lock().tracees);
    for t in tracees {
        let kill = {
            let mut guard = t.ptrace.lock();
            match guard.as_mut() {
                Some(pt) if !pt.detached => {
                    let kill = pt.options & PTRACE_O_EXITKILL != 0;
                    if let Some(mut stop) = pt.stop {
                        pt.clear_forced_tf(&mut stop);
                        stop.resume = Some(0);
                        pt.stop = Some(stop);
                        pt.detached = true;
                    } else {
                        *guard = None;
                    }
                    kill
                }
                _ => false,
            }
        };
        if kill {
            kill_group(&t.process, WaitStatus::signaled(SIGKILL, false));
        }
        t.wake();
    }
}

/// Lets each tracee in `threads` that waits in `PTRACE_LISTEN` stop again, because the group
/// continued.
pub(super) fn group_continued(threads: &[Arc<Thread>]) {
    for t in threads {
        let woke = {
            let mut guard = t.ptrace.lock();
            match guard.as_mut() {
                Some(pt) => match pt.stop.as_mut().filter(|s| s.resume.is_none()) {
                    Some(stop) if stop.listening => {
                        stop.listening = false;
                        stop.resume = Some(0);
                        pt.interrupt = true;
                        true
                    }
                    // A tracee of `PTRACE_SEIZE` stops again when the tracer lets it continue,
                    // to tell the tracer about the continue.
                    Some(_) => {
                        pt.interrupt |= pt.seized;
                        false
                    }
                    None => false,
                },
                None => false,
            }
        };
        if woke {
            t.wake();
        }
    }
}

/// Tells if the wait `options` takes `thread`: a thread that is not the leader of its process is
/// a clone child for `__WCLONE`, as `eligible_child` of Linux tells.
fn eligible(thread: &Thread, options: WaitOptions) -> bool {
    let clone = thread.tid != thread.process.pid || thread.process.exit_signal != SIGCHLD;
    options.all || clone == options.clone
}

/// What the wait of a tracer found in its tracees.
pub(super) enum Found {
    /// No tracee matches the target.
    None,
    /// A tracee matches, but it has no change for the wait.
    Waiting,
    /// A tracee changed.
    Report(WaitResult),
}

/// Looks for a change of a tracee of `process` that matches `target`, for the wait of the
/// tracer. `s` is the state of `process`. A tracee that ended goes away from the list, unless
/// `options.nowait` is set. The zombie of a child of `process` stays for the loop over the
/// children, which reaps it.
pub(super) fn wait_tracee(
    process: &Process,
    s: &mut State,
    target: WaitTarget,
    options: WaitOptions,
) -> Found {
    let mut found = Found::None;
    let mut i = 0;
    while i < s.tracees.len() {
        let t = s.tracees[i].clone();
        i += 1;
        let matches = match target {
            WaitTarget::Any => true,
            WaitTarget::Pid(pid) => t.tid == pid,
            WaitTarget::Pgid(pgid) => t.process.pgid() == pgid,
        };
        if !matches || !eligible(&t, options) {
            continue;
        }
        if matches!(found, Found::None) {
            found = Found::Waiting;
        }
        let leader = t.tid == t.process.pid;
        let mut guard = t.ptrace.lock();
        let Some(pt) = guard.as_mut() else { continue };
        if let Some(status) = pt.exit {
            if !options.exited {
                continue;
            }
            if !options.nowait {
                drop(guard);
                s.tracees.remove(i - 1);
            }
            return Found::Report(WaitResult {
                pid: t.tid,
                uid: t.process.cred().uid,
                status,
                ticks: t.user_ticks(),
                trapped: false,
            });
        }
        if leader {
            let zombie = t.process.state.lock().zombie;
            if let Some(status) = zombie {
                let parent = t.process.state.lock().parent.upgrade();
                if parent.is_some_and(|p| core::ptr::eq(&*p, process)) || !options.exited {
                    continue;
                }
                if !options.nowait {
                    drop(guard);
                    s.tracees.remove(i - 1);
                }
                let ticks = t.process.user_ticks() + t.process.child_ticks();
                let uid = t.process.cred().uid;
                return Found::Report(WaitResult {
                    pid: t.tid,
                    uid,
                    status,
                    ticks,
                    trapped: false,
                });
            }
        }
        if let Some(stop) = pt.stop.as_mut().filter(|s| s.resume.is_none() && !s.reported) {
            if !options.nowait {
                stop.reported = true;
            }
            let status = stop.status;
            drop(guard);
            return Found::Report(WaitResult {
                pid: t.tid,
                uid: t.process.cred().uid,
                status,
                ticks: t.user_ticks(),
                trapped: true,
            });
        }
    }
    found
}

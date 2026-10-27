//! The task of a user thread: it enters user mode and handles the reason of each return.

use crate::cx::Cx;
use crate::table;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::signal::{SIGBUS, SIGFPE, SIGILL, SIGSEGV, SIGTRAP};
use rk_abi::native::syscalls as nr;
use rk_frame::addr::VirtAddr;
use rk_frame::println;
use rk_frame::task::{TaskOptions, should_yield, yield_now};
use rk_frame::time::ticks;
use rk_frame::user::{ExceptionKind, FaultAccess, ReturnReason, UserContext, UserException};
use rk_mm::Access;
use rk_proc::exec::{ExecArgs, exec};
use rk_proc::ptrace::{self, NO_SYSCALL, PTRACE_EVENT_EXIT, StopKind};
use rk_proc::signal::{
    BUS_ADRALN, BUS_ADRERR, FPE_INTDIV, ILL_ILLOPN, SEGV_ACCERR, SEGV_MAPERR, SI_KERNEL, SIG_DFL,
    SIG_IGN, SigInfo, TRAP_BRKPT, TRAP_TRACE,
};
use rk_proc::{SyscallInfo, Thread, WaitStatus};
use rk_vfs::FsContext;

/// The number of system calls since boot.
static COUNT: AtomicU64 = AtomicU64::new(0);

/// Gives the number of system calls since boot.
pub fn count() -> u64 {
    COUNT.load(Ordering::Relaxed)
}

/// Gives 16 random bytes for `AT_RANDOM`.
pub(crate) fn random16() -> [u8; 16] {
    let mut r = [0u8; 16];
    rk_drv_mem::get_random_bytes(&mut r);
    r
}

/// Starts a task that runs `thread` from the registers `regs`.
///
/// # Errors
///
/// Gives `ENOMEM` if no memory is free for the kernel stack.
pub(crate) fn start_thread(thread: Arc<Thread>, regs: UserContext) -> Result<(), Errno> {
    let run_thread = thread.clone();
    let sched = thread.sched();
    let (nice, idle) = sched.share();
    let task = TaskOptions::new(move || run(run_thread, regs))
        .data(thread.clone())
        .nice(nice, idle)
        .affinity(sched.affinity)
        .spawn()
        .ok_or(Errno::ENOMEM)?;
    thread.set_task(&task);
    Ok(())
}

/// Makes init from the program at `path` and starts it. The console is its standard input,
/// output and error, as `console_on_rootfs` of Linux makes it.
///
/// # Errors
///
/// Gives the error of `execve`, or `ENOMEM`.
pub fn spawn_init(
    fs: FsContext,
    path: &[u8],
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
) -> Result<(), Errno> {
    let console = fs.open(&fs.root().clone(), b"/dev/console", rk_abi::native::open::O_RDWR, 0);
    let thread = rk_proc::create_init(fs)?;
    let process = thread.process().clone();
    if let (Ok(console), Some(files)) = (console, process.files()) {
        let mut files = files.lock();
        for _ in 0..3 {
            files.insert(console.clone(), false)?;
        }
    }
    let image = exec(&thread, ExecArgs { path: path.to_vec(), argv, envp }, random16(), |_| {})?;
    rk_drv_tty::set_console_session(process.pid(), process.pgid());
    start_thread(thread, UserContext::new(VirtAddr::new(image.entry), VirtAddr::new(image.sp)))
}

/// Gives the signal of a user exception at `ip`, as the trap handlers of
/// arch/x86/kernel/traps.c and arch/arm64/kernel/traps.c give it.
fn exception_signal(e: &UserException, ip: u64) -> SigInfo {
    match e.kind() {
        ExceptionKind::DivideError => SigInfo::fault(SIGFPE, FPE_INTDIV, ip),
        ExceptionKind::FloatingPoint => SigInfo::fault(SIGFPE, SI_KERNEL, ip),
        // The trap flag gives the debug exception after one instruction.
        ExceptionKind::SingleStep => SigInfo::fault(SIGTRAP, TRAP_TRACE, ip),
        ExceptionKind::Breakpoint => SigInfo::fault(SIGTRAP, SI_KERNEL, 0),
        ExceptionKind::IllegalInstruction => SigInfo::fault(SIGILL, ILL_ILLOPN, ip),
        ExceptionKind::Alignment { addr } => SigInfo::fault(SIGBUS, BUS_ADRALN, addr),
        ExceptionKind::PageFault { addr, present, .. } => {
            SigInfo::fault(SIGSEGV, if present { SEGV_ACCERR } else { SEGV_MAPERR }, addr)
        }
        ExceptionKind::Other => SigInfo::fault(SIGSEGV, SI_KERNEL, 0),
    }
}

/// Sends the signal of a user exception to the thread. If the signal ends the process, the
/// kernel log tells where the fault was. A tracer sees the signal first, so the log does not
/// tell about a traced thread.
fn fault(thread: &Arc<Thread>, regs: &UserContext, e: &UserException, info: SigInfo) {
    let sig = info.signo;
    let process = thread.process();
    let action = process.action(sig);
    let fatal =
        action.handler == SIG_DFL || action.handler == SIG_IGN || thread.blocked().contains(sig);
    if fatal && !thread.is_traced() {
        println!(
            "{}[{}]: signal {sig} at ip {:#x} addr {:#x} error {:#x}",
            core::str::from_utf8(&process.comm()).unwrap_or("?"),
            thread.tid(),
            regs.pc(),
            e.addr,
            e.error
        );
    }
    thread.force_signal(info);
}

/// Handles a page fault of the thread. Gives the signal if the memory manager did not repair it:
/// `SIGBUS` for a page that has no data, else `SIGSEGV`.
fn page_fault(
    thread: &Thread,
    e: &UserException,
    addr: u64,
    access: FaultAccess,
) -> Option<SigInfo> {
    let segv = || Some(exception_signal(e, 0));
    let Some(vm) = thread.process().vm() else { return segv() };
    let access = match access {
        FaultAccess::Exec => Access::Exec,
        FaultAccess::Write => Access::Write,
        FaultAccess::Read => Access::Read,
    };
    match vm.handle_fault(addr as usize, access) {
        Ok(()) => None,
        Err(Errno::EFAULT | Errno::ENOMEM) => segv(),
        Err(_) => Some(SigInfo::fault(SIGBUS, BUS_ADRERR, addr)),
    }
}

/// Runs the user thread until it ends.
fn run(thread: Arc<Thread>, mut regs: UserContext) {
    let status = 'run: {
        // A new traced thread stops for its tracer before its first instruction.
        if let Some(status) = crate::signal::deliver(&thread, &mut regs, None) {
            break 'run status;
        }
        run_loop(&thread, &mut regs)
    };
    // The tracer can ask for a stop before the exit, with `PTRACE_O_TRACEEXIT`.
    ptrace::event(&thread, &mut regs, NO_SYSCALL, PTRACE_EVENT_EXIT, status.0 as u32 as u64);
    crate::futex::exit_robust_list(&thread);
    crate::futex::exit_clear_tid(&thread);
    // The last thread of a process does the changes that `SEM_UNDO` recorded.
    let process = thread.process();
    if process.threads().len() <= 1 {
        crate::sem::exit(process.pid() as i32);
    }
    rk_proc::exit_thread(&thread, status);
}

/// Runs the user code of the thread and handles each return to the kernel, until the thread
/// ends. Gives the status of the thread.
fn run_loop(thread: &Arc<Thread>, regs: &mut UserContext) -> WaitStatus {
    loop {
        let process = thread.process();
        if thread.is_killed() {
            break process.group_exit().unwrap_or(WaitStatus::exited(0));
        }
        let Some(vm) = process.vm() else { break WaitStatus::exited(0) };
        vm.activate();
        drop(vm);
        // The number of a system call that can start again after a signal. `rt_sigreturn` puts
        // back the registers of the frame, so its return value is not a restart code.
        let mut syscall = None;
        let start = ticks();
        let reason = regs.execute();
        let user = ticks() - start;
        if user != 0 {
            thread.add_user_ticks(user);
            rk_proc::timer::check_cpu_timers(&thread);
        }
        match reason {
            ReturnReason::Syscall => {
                COUNT.fetch_add(1, Ordering::Relaxed);
                let (number, run) = match syscall_entry(thread, regs) {
                    Entry::Run(number) => (number, number != NO_SYSCALL),
                    Entry::Skip(number) => (number, false),
                    Entry::GroupExit => continue,
                    Entry::ThreadExit(status) => break status,
                };
                if run {
                    let mut cx = Cx { thread, regs, exit: None, number };
                    table::dispatch(&mut cx);
                    if let Some(status) = cx.exit {
                        break status;
                    }
                }
                syscall_exit(thread, regs, number);
                if number != u64::from(nr::RT_SIGRETURN) && number != NO_SYSCALL {
                    syscall = Some(number);
                }
            }
            ReturnReason::Interrupt => {}
            ReturnReason::Exception(e) => {
                let info = match e.kind() {
                    ExceptionKind::PageFault { addr, access, .. } => {
                        page_fault(thread, &e, addr, access)
                    }
                    _ => Some(exception_signal(&e, regs.pc())),
                };
                if let Some(info) = info {
                    fault(thread, regs, &e, info);
                }
            }
        }
        if should_yield() {
            yield_now();
        }
        if let Some(status) = crate::signal::deliver(thread, regs, syscall) {
            break status;
        }
    }
}

/// What the entry to a system call gives.
pub(crate) enum Entry {
    /// Run the system call with this number, or skip it if the number is `NO_SYSCALL`.
    Run(u64),
    /// Skip the system call with this number. The return register has the return value, and a
    /// signal can start the call again if the value is a restart code.
    Skip(u64),
    /// The group exits.
    GroupExit,
    /// The thread exits with this status, for `seccomp`.
    ThreadExit(WaitStatus),
}

/// Starts a system call: the return register gets `-ENOSYS` as `set_entry_return` tells, and a
/// tracer of `PTRACE_SYSCALL` sees the entry and can change the number. Then the `seccomp` mode of
/// the thread checks the call, as `syscall_trace_enter` of Linux does.
fn syscall_entry(thread: &Arc<Thread>, regs: &mut UserContext) -> Entry {
    let mut number = regs.syscall_number();
    thread.set_syscall_info(SyscallInfo {
        nr: number as i64,
        args: regs.syscall_args(),
        sp: regs.sp(),
        pc: regs.pc(),
    });
    regs.set_entry_return(Errno::ENOSYS.to_syscall_return() as u64);
    if thread.syscall_traced() {
        let r = ptrace::stop(thread, regs, number, StopKind::SyscallEntry, SIGTRAP, None);
        if thread.is_killed() {
            return Entry::GroupExit;
        }
        number = r.map_or(number, |r| r.orig_rax);
    }
    crate::seccomp::check(thread, regs, number)
}

/// Ends a system call: a tracer of `PTRACE_SYSCALL` sees the return. A thread in a single step
/// gets `SIGTRAP` instead, because the trap flag stops it only after the next instruction, as
/// `syscall_exit_work` of Linux does.
fn syscall_exit(thread: &Arc<Thread>, regs: &mut UserContext, number: u64) {
    thread.set_syscall_info(SyscallInfo {
        nr: -1,
        sp: regs.sp(),
        pc: regs.pc(),
        ..SyscallInfo::default()
    });
    if thread.single_stepping() {
        thread.send_signal(SigInfo::fault(SIGTRAP, TRAP_BRKPT, regs.pc()));
    } else if thread.syscall_traced() {
        ptrace::stop(thread, regs, number, StopKind::SyscallExit, SIGTRAP, None);
    }
}

/// Connects the system calls to the other parts of the kernel: the clock of the VFS time stamps,
/// the credentials of the VFS checks and the signals of the console. The boot code calls this one time, before `spawn_init`.
pub fn init() {
    rk_vfs::ipc::set_sysvipc(crate::msg::sysvipc);
    crate::mqueue::register();
    rk_vfs::inode::set_clock(crate::info::realtime);
    rk_vfs::cred::set_current(|| rk_proc::current_thread().map(|t| t.process().cred()));
    rk_drv_tty::set_signal_handler(|pgrp, sig| {
        let _ = crate::signal::signal_group(pgrp, SigInfo::new(sig, SI_KERNEL, 0));
    });
    rk_net::set_cred_source(crate::net::current_cred);
    rk_vfs::wait::set_interrupt_check(|| {
        rk_proc::current_thread().is_some_and(|t| t.signal_pending())
    });
    rk_vfs::loopdev::set_file_lookup(|fd| {
        let files = rk_proc::current_thread().and_then(|t| t.process().files());
        files.ok_or(Errno::EBADF)?.lock().file(fd)
    });
}

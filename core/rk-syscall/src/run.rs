//! The task of a user thread: it enters user mode and handles the reason of each return.

use crate::cx::Cx;
use crate::table;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::signal::{SIGBUS, SIGFPE, SIGILL, SIGSEGV, SIGTRAP};
use rk_frame::addr::VirtAddr;
use rk_frame::println;
use rk_frame::task::{TaskOptions, should_yield, yield_now};
use rk_frame::user::{ReturnReason, UserContext, UserException};
use rk_mm::Access;
use rk_proc::exec::{ExecArgs, exec};
use rk_proc::{Thread, WaitStatus};
use rk_vfs::FsContext;

/// The number of system calls since boot.
static COUNT: AtomicU64 = AtomicU64::new(0);

/// Gives the number of system calls since boot.
pub fn count() -> u64 {
    COUNT.load(Ordering::Relaxed)
}

/// The vectors of the x86-64 exceptions that a user program can cause.
const DIVIDE_ERROR: u8 = 0;
const DEBUG: u8 = 1;
const BREAKPOINT: u8 = 3;
const INVALID_OPCODE: u8 = 6;
const GENERAL_PROTECTION: u8 = 13;
const PAGE_FAULT: u8 = 14;
const X87_FLOATING_POINT: u8 = 16;
const ALIGNMENT_CHECK: u8 = 17;
const SIMD_FLOATING_POINT: u8 = 19;

/// The bits of the error code of a page fault.
const PF_WRITE: u64 = 1 << 1;
const PF_INSTR: u64 = 1 << 4;

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
    let task = TaskOptions::new(move || run(run_thread, regs))
        .data(thread.clone())
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
    let image = exec(&thread, ExecArgs { path: path.to_vec(), argv, envp }, random16())?;
    rk_drv_tty::set_console_session(process.pid(), process.pgid());
    start_thread(thread, UserContext::new(VirtAddr::new(image.entry), VirtAddr::new(image.sp)))
}

/// Gives the signal of a user exception, as the trap handlers of arch/x86/kernel/traps.c give it.
fn exception_signal(e: &UserException) -> u32 {
    match e.vector {
        DIVIDE_ERROR | X87_FLOATING_POINT | SIMD_FLOATING_POINT => SIGFPE,
        DEBUG | BREAKPOINT => SIGTRAP,
        INVALID_OPCODE => SIGILL,
        ALIGNMENT_CHECK => SIGBUS,
        GENERAL_PROTECTION | PAGE_FAULT => SIGSEGV,
        _ => SIGSEGV,
    }
}

/// Handles a page fault of the thread. Gives `false` if the memory manager did not repair it.
fn page_fault(thread: &Thread, e: &UserException) -> bool {
    let Some(vm) = thread.process().vm() else { return false };
    let access = if e.error & PF_INSTR != 0 {
        Access::Exec
    } else if e.error & PF_WRITE != 0 {
        Access::Write
    } else {
        Access::Read
    };
    vm.handle_fault(e.addr as usize, access).is_ok()
}

/// The length of the `syscall` instruction.
const SYSCALL_INSN_LEN: u64 = 2;

/// Handles a system call that a signal stopped with a restart number. No signal handler runs in
/// R1, so the call starts again: the instruction pointer goes back to the `syscall` instruction,
/// as `handle_signal` of arch/x86/kernel/signal.c does it. `restart_syscall` is not there yet, so
/// `ERESTART_RESTARTBLOCK` gives `EINTR`.
fn restart_syscall(regs: &mut UserContext, number: u64) {
    let Some(e) = Errno::from_syscall_return(regs.regs().rax as isize) else { return };
    if !e.is_restart() {
        return;
    }
    if e == Errno::ERESTART_RESTARTBLOCK {
        regs.set_syscall_return(Errno::EINTR.to_syscall_return() as u64);
        return;
    }
    let r = regs.regs_mut();
    r.rax = number;
    r.rip -= SYSCALL_INSN_LEN;
}

/// Runs the user thread until it ends.
fn run(thread: Arc<Thread>, mut regs: UserContext) {
    let status = loop {
        let process = thread.process();
        if thread.is_killed() {
            break process.group_exit().unwrap_or(WaitStatus::exited(0));
        }
        let Some(vm) = process.vm() else { break WaitStatus::exited(0) };
        vm.activate();
        drop(vm);
        match regs.execute() {
            ReturnReason::Syscall => {
                COUNT.fetch_add(1, Ordering::Relaxed);
                let number = regs.syscall_number();
                let mut cx = Cx { thread: &thread, regs: &mut regs, exit: None };
                table::dispatch(&mut cx);
                if let Some(status) = cx.exit {
                    break status;
                }
                restart_syscall(&mut regs, number);
            }
            ReturnReason::Interrupt => {}
            ReturnReason::Exception(e) => {
                if e.vector == PAGE_FAULT && page_fault(&thread, &e) {
                    continue;
                }
                let sig = exception_signal(&e);
                println!(
                    "{}[{}]: signal {sig} at ip {:#x} addr {:#x} error {:#x}",
                    core::str::from_utf8(&process.comm()).unwrap_or("?"),
                    thread.tid(),
                    regs.regs().rip,
                    e.addr,
                    e.error
                );
                let status = WaitStatus::signaled(sig, false);
                rk_proc::exit_group(&thread, status);
                break status;
            }
        }
        if should_yield() {
            yield_now();
        }
    };
    let clear = thread.clear_child_tid();
    if clear != 0
        && let Some(vm) = thread.process().vm()
    {
        let _ = vm.write(clear, &0u32.to_ne_bytes());
    }
    rk_proc::exit_thread(&thread, status);
}

/// Connects the system calls to the other parts of the kernel: the clock of the VFS time stamps
/// and the signals of the console. The boot code calls this one time, before `spawn_init`.
pub fn init() {
    rk_vfs::inode::set_clock(crate::info::realtime);
    rk_drv_tty::set_signal_handler(|pgrp, sig| {
        let _ = crate::process::signal_group(pgrp, sig);
    });
    rk_vfs::wait::set_interrupt_check(|| rk_proc::current_thread().is_some_and(|t| t.is_killed()));
}

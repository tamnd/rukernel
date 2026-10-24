//! The system calls of rukernel.
//!
//! Each user thread runs in a kernel task. The task enters user mode, and the system calls, the
//! interrupts and the exceptions of the thread come back to the task, as in OSTD, per
//! spec/03-architecture.md. The task calls the handler of the system call from the table, then
//! enters user mode again. A page fault goes to the memory manager. A fault that the memory
//! manager does not repair sends the signal of the fault. Before each return to user mode, the task
//! delivers the next signal that the thread does not block.
//!
//! The handlers check the arguments as Linux does and give the same errors. The tables of
//! numbers and types come from rk-abi. A number with no handler gives `ENOSYS`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

/// The release that `uname` gives, per spec/17-upstream-tracking.md section 17.4.
pub const UNAME_RELEASE: &str = "7.3.0-rukernel";

/// The version that `uname` gives.
pub const UNAME_VERSION: &str = "#1 SMP PREEMPT_DYNAMIC rukernel";

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod cx;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod fs;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod futex;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod info;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod mm;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod mount;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod pidfd;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod poll;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod process;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod ptrace;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod run;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod signal;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod table;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod timer;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub use run::{count, init, spawn_init};

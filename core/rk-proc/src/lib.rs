//! The processes of rukernel.
//!
//! A process has an address space, a descriptor table, a file system context and threads, per
//! spec/05-processes-signals-exec.md. This crate keeps the processes and their IDs, runs a new program with
//! `exec` and the ELF loader, and does `fork`, `exit`, `wait` and the signal queues. rk-syscall
//! runs each thread in a kernel task and calls this crate from the system calls.
//!
//! The ELF headers, the `#!` line, the initial stack, the wait status and the signal sets are pure
//! code, so the tests on the host examine them. The rest runs in the kernel only.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod bpf;
pub mod elf;
pub mod limits;
pub mod sched;
pub mod script;
pub mod signal;
pub mod stack;
pub mod wait;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod exec;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod process;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod timer;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod vdso;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub use process::{
    COMM_LEN, Delivery, ForkShare, INIT_PID, PID_MAX, Pid, Process, Restart, SharedFiles, SharedFs,
    SyscallInfo, Thread, VforkDone, create_init, current_thread, exit_group, exit_thread,
    find_process, find_thread, fork, kill_group, new_thread, processes, send_signal, stop_group,
    user_ticks, wait_child, wait_for_init,
};
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub use process::{ptrace, seccomp};
pub use wait::{WaitOptions, WaitResult, WaitStatus, WaitTarget};

/// The size of a page.
pub const PAGE_SIZE: usize = rk_mm::PAGE_SIZE;

#[cfg(test)]
mod tests;

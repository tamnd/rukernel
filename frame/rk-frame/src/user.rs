//! User mode: user pages and the entry to user code.
//!
//! A `UserContext` holds the user registers. `execute` runs the user code until it makes a system
//! call, takes an exception or is interrupted, and then gives the reason. The kernel handles the
//! reason and calls `execute` again. This is the model of OSTD, per spec/03-architecture.md.
//!
//! Only x86-64 has user mode in R0. arm64 gets it in R4 and riscv64 in R8.

use crate::addr::{PAGE_SIZE, VirtAddr};
use crate::arch::imp::{paging, user};
use crate::mm::Frame;

pub use user::UserRegs;

/// The end of the user half of the address space. Each user address is below it.
pub const USER_END: usize = paging::USER_END;

/// Why `UserContext::execute` returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnReason {
    /// The user code made a system call.
    Syscall,
    /// An interrupt came while the user code ran. The kernel handled it.
    Interrupt,
    /// The user code caused an exception.
    Exception(UserException),
}

/// An exception in user mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserException {
    /// The vector of the exception.
    pub vector: u8,
    /// The error code that the CPU gave, or 0.
    pub error: u64,
    /// The address of a page fault, or 0.
    pub addr: u64,
}

/// The registers of one user thread.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserContext {
    regs: UserRegs,
}

impl UserContext {
    /// Makes a context that starts at `entry` with the stack pointer `stack`. The other registers
    /// are 0.
    pub fn new(entry: VirtAddr, stack: VirtAddr) -> Self {
        let regs =
            UserRegs { rip: entry.get() as u64, rsp: stack.get() as u64, ..UserRegs::default() };
        Self { regs }
    }

    /// The registers.
    pub fn regs(&self) -> &UserRegs {
        &self.regs
    }

    /// The registers, to change them.
    pub fn regs_mut(&mut self) -> &mut UserRegs {
        &mut self.regs
    }

    /// Runs the user code until it comes back to the kernel, and gives the reason. The registers
    /// then have the values of the user code at that time. After a system call, the instruction
    /// pointer is after the `syscall` instruction.
    pub fn execute(&mut self) -> ReturnReason {
        match user::enter(&mut self.regs) {
            user::Return::Syscall => ReturnReason::Syscall,
            user::Return::Interrupt => ReturnReason::Interrupt,
            user::Return::Exception { vector, error, cr2 } => {
                ReturnReason::Exception(UserException { vector, error, addr: cr2 })
            }
        }
    }

    /// The system call number.
    pub fn syscall_number(&self) -> u64 {
        self.regs.rax
    }

    /// The six system call arguments, in the order of the Linux ABI.
    pub fn syscall_args(&self) -> [u64; 6] {
        let r = &self.regs;
        [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9]
    }

    /// Sets the return value of the system call.
    pub fn set_syscall_return(&mut self, value: u64) {
        self.regs.rax = value;
    }
}

/// A user page could not be mapped.
#[derive(Debug)]
pub struct MapError {
    /// The frame that was not mapped.
    pub frame: Frame,
}

/// Maps `frame` at the user address `addr`. The frame stays mapped for all of the run time.
///
/// In R0 there is one address space, and nothing removes a user page. Each process gets its own
/// address space in R1.
///
/// # Errors
///
/// Gives the frame back if `addr` is not page aligned, is not in the user half, is mapped
/// already, or if no frame is free for a page table.
pub fn map_page(
    addr: VirtAddr,
    frame: Frame,
    writable: bool,
    executable: bool,
) -> Result<(), MapError> {
    let a = addr.get();
    if !a.is_multiple_of(PAGE_SIZE) || a >= USER_END {
        return Err(MapError { frame });
    }
    if paging::map_user_page(a, frame.addr().get(), writable, executable).is_err() {
        return Err(MapError { frame });
    }
    // The page tables own the frame now.
    core::mem::forget(frame);
    Ok(())
}

//! User mode: the entry to user code.
//!
//! A `UserContext` holds the user registers. `execute` runs the user code until it makes a system
//! call, takes an exception or is interrupted, and then gives the reason. The kernel handles the
//! reason and calls `execute` again. This is the model of OSTD, per spec/03-architecture.md.
//!
//! The user code runs in the address space that is active. The kernel activates the `VmSpace` of
//! the process before it calls `execute`.
//!
//! Only x86-64 has user mode in R0. arm64 gets it in R4 and riscv64 in R8.

use crate::addr::VirtAddr;
use crate::arch::imp::{paging, user};

pub use user::{FpuState, UserRegs};

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

/// The registers of one user thread: the general registers, the x87 and SSE state, and the FS
/// base, which holds the thread pointer on x86-64.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserContext {
    regs: UserRegs,
    fpu: FpuState,
    fs_base: u64,
}

impl UserContext {
    /// Makes a context that starts at `entry` with the stack pointer `stack`. The other registers
    /// are 0.
    pub fn new(entry: VirtAddr, stack: VirtAddr) -> Self {
        let regs =
            UserRegs { rip: entry.get() as u64, rsp: stack.get() as u64, ..UserRegs::default() };
        Self { regs, ..Self::default() }
    }

    /// The registers.
    pub fn regs(&self) -> &UserRegs {
        &self.regs
    }

    /// The registers, to change them.
    pub fn regs_mut(&mut self) -> &mut UserRegs {
        &mut self.regs
    }

    /// The x87 and SSE state.
    pub fn fpu(&self) -> &FpuState {
        &self.fpu
    }

    /// Sets the x87 and SSE state, for a signal handler and `rt_sigreturn`.
    pub fn set_fpu(&mut self, fpu: FpuState) {
        self.fpu = fpu;
    }

    /// The FS base. `arch_prctl(ARCH_GET_FS)` gives it.
    pub fn fs_base(&self) -> u64 {
        self.fs_base
    }

    /// Sets the FS base, for `arch_prctl(ARCH_SET_FS)`. The kernel loads it at the next entry to
    /// user mode. A value that is not canonical makes the entry load 0.
    pub fn set_fs_base(&mut self, value: u64) {
        self.fs_base = value;
    }

    /// Runs the user code until it comes back to the kernel, and gives the reason. The registers
    /// then have the values of the user code at that time. After a system call, the instruction
    /// pointer is after the `syscall` instruction.
    pub fn execute(&mut self) -> ReturnReason {
        match user::enter(&mut self.regs, &mut self.fpu, self.fs_base) {
            user::Return::Syscall => ReturnReason::Syscall,
            user::Return::Interrupt => {
                crate::task::run_bottom_half();
                ReturnReason::Interrupt
            }
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

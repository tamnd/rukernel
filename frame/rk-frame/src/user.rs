//! User mode: the entry to user code.
//!
//! A `UserContext` holds the user registers. `execute` runs the user code until it makes a system
//! call, takes an exception or is interrupted, and then gives the reason. The kernel handles the
//! reason and calls `execute` again. This is the model of OSTD, per spec/03-architecture.md.
//!
//! The user code runs in the address space that is active. The kernel activates the `VmSpace` of
//! the process before it calls `execute`.
//!
//! x86-64 and arm64 have user mode. riscv64 gets it in R8. The accessors of `UserContext` hide
//! the registers of the architecture, so the kernel crates need no arch cfg.

use crate::addr::VirtAddr;
use crate::arch::imp::{paging, user};

pub use user::{FpuState, UserRegs};

/// The end of the user half of the address space. Each user address is below it.
pub const USER_END: usize = paging::USER_END;

/// The bit of the flags register that makes the CPU stop after one user instruction: the trap
/// flag TF on x86-64, and the software step bit SS of PSTATE on arm64.
pub const STEP_FLAG: u64 = user::STEP_FLAG;

/// The `AUDIT_ARCH_*` value of the architecture, from include/uapi/linux/audit.h, for
/// `seccomp_data` and `ptrace`.
pub const AUDIT_ARCH: u32 = user::AUDIT_ARCH;

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

/// The access that caused a page fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultAccess {
    /// A read of data.
    Read,
    /// A write of data.
    Write,
    /// An instruction fetch.
    Exec,
}

/// The kind of a user exception, the same on each architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExceptionKind {
    /// A page fault at `addr`. `present` tells that the page is mapped, so the access is not
    /// allowed.
    PageFault {
        /// The address of the access.
        addr: u64,
        /// The kind of access.
        access: FaultAccess,
        /// The page is mapped.
        present: bool,
    },
    /// An integer division by zero, or an overflow of a division.
    DivideError,
    /// An exception of the floating point unit.
    FloatingPoint,
    /// A single step trap.
    SingleStep,
    /// A breakpoint instruction.
    Breakpoint,
    /// An instruction that the CPU does not know, or that user mode cannot use.
    IllegalInstruction,
    /// An access that is not aligned.
    Alignment {
        /// The address of the access, or 0 if the CPU does not give it.
        addr: u64,
    },
    /// Another exception, for example a general protection fault.
    Other,
}

impl UserException {
    /// The kind of the exception.
    pub fn kind(&self) -> ExceptionKind {
        user::classify(self.vector, self.error, self.addr)
    }
}

/// The registers of one user thread: the general registers, the FP and SIMD state, and the thread
/// pointer. The thread pointer is the FS base on x86-64 and TPIDR_EL0 on arm64.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserContext {
    regs: UserRegs,
    fpu: FpuState,
    tls: u64,
    no_tsc: bool,
}

impl UserContext {
    /// Makes a context that starts at `entry` with the stack pointer `stack`. The other registers
    /// are 0.
    pub fn new(entry: VirtAddr, stack: VirtAddr) -> Self {
        let mut context = Self::default();
        context.set_pc(entry.get() as u64);
        context.set_sp(stack.get() as u64);
        context
    }

    /// The registers.
    pub fn regs(&self) -> &UserRegs {
        &self.regs
    }

    /// The registers, to change them.
    pub fn regs_mut(&mut self) -> &mut UserRegs {
        &mut self.regs
    }

    /// The FP and SIMD state: the x87 and SSE state on x86-64, v0 to v31, FPSR and FPCR on arm64.
    pub fn fpu(&self) -> &FpuState {
        &self.fpu
    }

    /// Sets the FP and SIMD state, for a signal handler and `rt_sigreturn`.
    pub fn set_fpu(&mut self, fpu: FpuState) {
        self.fpu = fpu;
    }

    /// The thread pointer: the FS base on x86-64, which `arch_prctl(ARCH_GET_FS)` gives, and
    /// TPIDR_EL0 on arm64.
    pub fn tls(&self) -> u64 {
        self.tls
    }

    /// Sets the thread pointer, for `arch_prctl(ARCH_SET_FS)` or the `CLONE_SETTLS` flag. The
    /// kernel loads it at the next entry to user mode. On x86-64, a value that is not canonical
    /// makes the entry load 0.
    pub fn set_tls(&mut self, value: u64) {
        self.tls = value;
    }

    /// Tells if `rdtsc` and `rdtscp` fault in the user code, as `TIF_NOTSC` of Linux.
    pub fn no_tsc(&self) -> bool {
        self.no_tsc
    }

    /// Makes `rdtsc` and `rdtscp` fault in the user code, or not, for `prctl(PR_SET_TSC)`. On
    /// x86-64 the kernel sets CR4.TSD while this user code runs, as `disable_TSC` in
    /// arch/x86/kernel/process.c of Linux. arm64 has no such instruction, so the flag does nothing
    /// there.
    pub fn set_no_tsc(&mut self, value: bool) {
        self.no_tsc = value;
    }

    /// The FS base. `arch_prctl(ARCH_GET_FS)` gives it.
    #[cfg(target_arch = "x86_64")]
    pub fn fs_base(&self) -> u64 {
        self.tls
    }

    /// Sets the FS base, for `arch_prctl(ARCH_SET_FS)`.
    #[cfg(target_arch = "x86_64")]
    pub fn set_fs_base(&mut self, value: u64) {
        self.tls = value;
    }

    /// The flags register: RFLAGS on x86-64, PSTATE on arm64. `ptrace` shows it to the tracer.
    pub fn flags(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        return self.regs.rflags;
        #[cfg(target_arch = "aarch64")]
        return self.regs.pstate;
    }

    /// Sets the flags register. The entry to user mode clears the bits that user code cannot
    /// have.
    pub fn set_flags(&mut self, value: u64) {
        #[cfg(target_arch = "x86_64")]
        {
            self.regs.rflags = value;
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.regs.pstate = value;
        }
    }

    /// The address of the next user instruction.
    pub fn pc(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        return self.regs.rip;
        #[cfg(target_arch = "aarch64")]
        return self.regs.pc;
    }

    /// Sets the address of the next user instruction.
    pub fn set_pc(&mut self, value: u64) {
        #[cfg(target_arch = "x86_64")]
        {
            self.regs.rip = value;
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.regs.pc = value;
        }
    }

    /// The user stack pointer.
    pub fn sp(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        return self.regs.rsp;
        #[cfg(target_arch = "aarch64")]
        return self.regs.sp;
    }

    /// Sets the user stack pointer.
    pub fn set_sp(&mut self, value: u64) {
        #[cfg(target_arch = "x86_64")]
        {
            self.regs.rsp = value;
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.regs.sp = value;
        }
    }

    /// Runs the user code until it comes back to the kernel, and gives the reason. The registers
    /// then have the values of the user code at that time. After a system call, the instruction
    /// pointer is after the `syscall` instruction.
    pub fn execute(&mut self) -> ReturnReason {
        self.execute_timed().0
    }

    /// Runs the user code as `execute` does, and also gives the nanoseconds in user mode. The
    /// time does not include the wait for the kernel lock and the bottom half after the return,
    /// because they are kernel work: on a machine with many CPUs, the wait for the lock can be
    /// long.
    pub fn execute_timed(&mut self) -> (ReturnReason, u64) {
        // User code runs without the kernel lock, so the other CPUs can run kernel code.
        crate::task::kernel_unlock();
        let start = crate::time::nanos();
        #[cfg(target_arch = "x86_64")]
        let reason = user::enter(&mut self.regs, &mut self.fpu, self.tls, self.no_tsc);
        #[cfg(target_arch = "aarch64")]
        let reason = user::enter(&mut self.regs, &mut self.fpu, &mut self.tls);
        let ns = crate::time::nanos().saturating_sub(start);
        crate::task::kernel_lock();
        let reason = match reason {
            user::Return::Syscall => ReturnReason::Syscall,
            user::Return::Interrupt => {
                crate::task::run_bottom_half();
                ReturnReason::Interrupt
            }
            user::Return::Exception { vector, error, cr2 } => {
                ReturnReason::Exception(UserException { vector, error, addr: cr2 })
            }
        };
        (reason, ns)
    }

    /// The system call number: rax on x86-64, x8 on arm64.
    pub fn syscall_number(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        return self.regs.rax;
        #[cfg(target_arch = "aarch64")]
        return self.regs.syscall_number();
    }

    /// The six system call arguments, in the order of the Linux ABI.
    pub fn syscall_args(&self) -> [u64; 6] {
        #[cfg(target_arch = "x86_64")]
        {
            let r = &self.regs;
            [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9]
        }
        #[cfg(target_arch = "aarch64")]
        self.regs.syscall_args()
    }

    /// The return value of the last system call, or the value that `set_syscall_return` set.
    pub fn syscall_return(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        return self.regs.rax;
        #[cfg(target_arch = "aarch64")]
        return self.regs.syscall_return();
    }

    /// Sets the return register at the entry to a system call to `value`, before a tracer sees
    /// the registers, as the entry code of Linux does. x86-64 puts it in RAX. On arm64, x0 keeps
    /// the first argument for the tracer, and only the call with the number -1 gets `value`.
    pub fn set_entry_return(&mut self, value: u64) {
        #[cfg(target_arch = "x86_64")]
        {
            self.regs.rax = value;
        }
        #[cfg(target_arch = "aarch64")]
        if self.regs.syscall_number() == u64::MAX {
            self.regs.set_syscall_return(value);
        }
    }

    /// Sets the return value of the system call.
    pub fn set_syscall_return(&mut self, value: u64) {
        #[cfg(target_arch = "x86_64")]
        {
            self.regs.rax = value;
        }
        #[cfg(target_arch = "aarch64")]
        self.regs.set_syscall_return(value);
    }

    /// Makes the thread make the system call `number` again when it goes back to user mode, with
    /// the same arguments. The kernel calls this after a system call that a signal stopped.
    pub fn restart_syscall(&mut self, number: u64) {
        #[cfg(target_arch = "x86_64")]
        {
            // The `syscall` instruction is two bytes long.
            self.regs.rax = number;
            self.regs.rip = self.regs.rip.wrapping_sub(2);
        }
        #[cfg(target_arch = "aarch64")]
        self.regs.restart_syscall(number);
    }
}

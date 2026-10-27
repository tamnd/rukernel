//! The entry to user mode and the return from it.
//!
//! `enter` saves the registers that the kernel must keep, loads the user registers, the FP and
//! SIMD state and TPIDR_EL0, and goes to EL0 with `eret`. The CPU comes back to EL1 on an `svc`
//! instruction, on another exception or on an interrupt. The vectors of EL0 in trap.rs save the
//! registers in a `TrapFrame` as for EL1, and `trap` copies them to the `UserRegs` and `FpuState`
//! values of `enter`. Then `rk_user_return` loads the kernel stack pointer that `enter` saved, so
//! `enter` returns to its caller. This is the method of the `UserContext` type of OSTD, as on
//! x86-64.
//!
//! The saved values are in the `Local` value of the CPU, which TPIDR_EL1 gives.

use super::cpu;
use super::trap::TrapFrame;
use core::sync::atomic::Ordering;

/// The user registers, in the order of `struct user_pt_regs` of Linux, with the `orig_x0` of
/// `struct pt_regs` after them. An `svc` instruction gives the return value in x0, so `orig_x0`
/// keeps the first argument for a restart of the call.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserRegs {
    /// The general registers x0 to x30.
    pub x: [u64; 31],
    /// The stack pointer, SP_EL0.
    pub sp: u64,
    /// The program counter.
    pub pc: u64,
    /// The flags NZCV and the other PSTATE bits of EL0.
    pub pstate: u64,
    /// x0 at the entry to the last system call.
    pub orig_x0: u64,
}

/// The FP and SIMD state of a user thread, in the format of `struct user_fpsimd_state` of Linux:
/// the 32 registers v0 to v31, FPSR and FPCR.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FpuState([u8; 528]);

impl Default for FpuState {
    /// The state of a new program: all registers 0, and the default rounding mode.
    fn default() -> Self {
        Self([0; 528])
    }
}

/// The bits of FPSR and FPCR that exist in Armv8.0. The other bits are reserved.
const FPSR_VALID: u32 = 0xf800_009f;
const FPCR_VALID: u32 = 0x07ff_9f00;

impl FpuState {
    /// The size of the state.
    pub const SIZE: usize = 528;

    /// The state as bytes, for the signal frame.
    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }

    /// Makes a state from bytes, for `rt_sigreturn`. The reserved bits of FPSR and FPCR are
    /// cleared.
    pub fn from_bytes(bytes: &[u8; Self::SIZE]) -> Self {
        let mut s = *bytes;
        let word = |s: &[u8; Self::SIZE], at: usize| {
            u32::from_le_bytes([s[at], s[at + 1], s[at + 2], s[at + 3]])
        };
        let fpsr = word(&s, 512) & FPSR_VALID;
        let fpcr = word(&s, 516) & FPCR_VALID;
        s[512..516].copy_from_slice(&fpsr.to_le_bytes());
        s[516..520].copy_from_slice(&fpcr.to_le_bytes());
        s[520..].fill(0);
        Self(s)
    }
}

impl UserRegs {
    /// The system call number: x8.
    pub(crate) fn syscall_number(&self) -> u64 {
        self.x[8]
    }

    /// The six system call arguments: `orig_x0` and x1 to x5.
    pub(crate) fn syscall_args(&self) -> [u64; 6] {
        [self.orig_x0, self.x[1], self.x[2], self.x[3], self.x[4], self.x[5]]
    }

    /// The return value of the system call: x0.
    pub(crate) fn syscall_return(&self) -> u64 {
        self.x[0]
    }

    /// Sets the return value of the system call.
    pub(crate) fn set_syscall_return(&mut self, value: u64) {
        self.x[0] = value;
    }

    /// Makes the thread make the system call `number` again: x0 gets its first argument back, x8
    /// gets `number` and the PC goes back to the `svc` instruction.
    pub(crate) fn restart_syscall(&mut self, number: u64) {
        self.x[0] = self.orig_x0;
        self.x[8] = number;
        self.pc = self.pc.wrapping_sub(4);
    }
}

/// The way that the CPU came back from user mode, as `rk_user_return` gets it in x0.
pub(crate) const RETURN_SYSCALL: u64 = 0;
pub(crate) const RETURN_INTERRUPT: u64 = 1;
pub(crate) const RETURN_EXCEPTION: u64 = 2;

/// The size of the frame that `rk_user_enter` stores: x19 to x30 and d8 to d15.
const SAVE_FRAME: usize = 20 * 8;

// The offsets in `UserRegs`: x0 at 0 to x30 at 240, sp 248, pc 256 and pstate 264. The offsets in
// `FpuState`: v0 at 0 to v31 at 496, FPSR 512 and FPCR 516.
core::arch::global_asm!(
    r#"
    .section .text.rk_user, "ax"
    .global rk_user_enter
rk_user_enter:                      // x0: UserRegs, x1: FpuState, x2: TPIDR_EL0
    sub     sp, sp, #{save}
    stp     x19, x20, [sp, #0]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x28, [sp, #64]
    stp     x29, x30, [sp, #80]
    stp     d8, d9, [sp, #96]
    stp     d10, d11, [sp, #112]
    stp     d12, d13, [sp, #128]
    stp     d14, d15, [sp, #144]
    mrs     x3, tpidr_el1
    mov     x4, sp
    str     x4, [x3, #{kernel_sp}]
    str     x0, [x3, #{user_regs}]
    msr     tpidr_el0, x2
    ldp     q0, q1, [x1, #0]
    ldp     q2, q3, [x1, #32]
    ldp     q4, q5, [x1, #64]
    ldp     q6, q7, [x1, #96]
    ldp     q8, q9, [x1, #128]
    ldp     q10, q11, [x1, #160]
    ldp     q12, q13, [x1, #192]
    ldp     q14, q15, [x1, #224]
    ldp     q16, q17, [x1, #256]
    ldp     q18, q19, [x1, #288]
    ldp     q20, q21, [x1, #320]
    ldp     q22, q23, [x1, #352]
    ldp     q24, q25, [x1, #384]
    ldp     q26, q27, [x1, #416]
    ldp     q28, q29, [x1, #448]
    ldp     q30, q31, [x1, #480]
    add     x4, x1, #512
    ldp     w4, w5, [x4]
    msr     fpsr, x4
    msr     fpcr, x5
    ldp     x4, x5, [x0, #248]
    msr     sp_el0, x4
    msr     elr_el1, x5
    ldr     x4, [x0, #264]
    msr     spsr_el1, x4
    ldp     x2, x3, [x0, #16]
    ldp     x4, x5, [x0, #32]
    ldp     x6, x7, [x0, #48]
    ldp     x8, x9, [x0, #64]
    ldp     x10, x11, [x0, #80]
    ldp     x12, x13, [x0, #96]
    ldp     x14, x15, [x0, #112]
    ldp     x16, x17, [x0, #128]
    ldp     x18, x19, [x0, #144]
    ldp     x20, x21, [x0, #160]
    ldp     x22, x23, [x0, #176]
    ldp     x24, x25, [x0, #192]
    ldp     x26, x27, [x0, #208]
    ldp     x28, x29, [x0, #224]
    ldr     x30, [x0, #240]
    ldp     x0, x1, [x0, #0]
    eret
    // No speculation past the `eret`, as Linux does.
    dsb     nsh
    isb

    .global rk_user_return
rk_user_return:                     // x0: the way back, one of the RETURN_ values
    mrs     x3, tpidr_el1
    ldr     x4, [x3, #{kernel_sp}]
    mov     sp, x4
    ldp     x19, x20, [sp, #0]
    ldp     x21, x22, [sp, #16]
    ldp     x23, x24, [sp, #32]
    ldp     x25, x26, [sp, #48]
    ldp     x27, x28, [sp, #64]
    ldp     x29, x30, [sp, #80]
    ldp     d8, d9, [sp, #96]
    ldp     d10, d11, [sp, #112]
    ldp     d12, d13, [sp, #128]
    ldp     d14, d15, [sp, #144]
    add     sp, sp, #{save}
    ret
"#,
    save = const SAVE_FRAME,
    kernel_sp = const cpu::KERNEL_SP,
    user_regs = const cpu::USER_REGS,
);

unsafe extern "C" {
    fn rk_user_enter(regs: *mut UserRegs, fpu: *const FpuState, tls: u64) -> u64;
    fn rk_user_return(how: u64) -> !;
}

/// The software step bit of PSTATE. With MDSCR_EL1.SS set, the CPU takes a software step
/// exception after one user instruction.
pub(crate) const STEP_FLAG: u64 = 1 << 21;

/// `AUDIT_ARCH_AARCH64`.
pub(crate) const AUDIT_ARCH: u32 = 0xc000_00b7;

/// The PSTATE bits that user code can set: N, Z, C and V, and the software step bit for `ptrace`.
/// The other bits are 0, so the CPU returns to EL0 with SP_EL0, in AArch64, and with no exception
/// masked.
const USER_PSTATE: u64 = 0xf000_0000 | STEP_FLAG;

/// The software step enable bit of MDSCR_EL1.
const MDSCR_SS: u64 = 1 << 0;

/// Turns the software step of user code on or off, as `user_enable_single_step` of Linux does.
/// The kernel does not set MDSCR_EL1.KDE, so the kernel code itself does not step.
fn set_step(on: bool) {
    let mdscr: u64;
    // SAFETY: reading MDSCR_EL1 has no side effect.
    unsafe { core::arch::asm!("mrs {}, mdscr_el1", out(reg) mdscr, options(nomem, nostack)) };
    let new = if on { mdscr | MDSCR_SS } else { mdscr & !MDSCR_SS };
    if new != mdscr {
        // SAFETY: MDSCR_EL1.SS changes only the debug exceptions of EL0, because KDE is 0. The
        // `isb` makes the change take effect before the `eret`.
        unsafe {
            core::arch::asm!("msr mdscr_el1, {}", "isb", in(reg) new, options(nomem, nostack))
        };
    }
}

/// Unlocks the OS lock of the debug registers, so that a software step exception can come, as
/// `clear_os_lock` of Linux does. Each CPU calls this one time at boot.
pub(crate) fn init_cpu() {
    // SAFETY: writing 0 to OSLAR_EL1 unlocks the debug registers. No debug event is enabled yet.
    unsafe { core::arch::asm!("msr oslar_el1, xzr", "isb", options(nomem, nostack)) };
}

/// The exception classes of ESR_EL1 for exceptions from EL0.
pub(crate) const EC_UNKNOWN: u8 = 0x00;
pub(crate) const EC_SVC64: u8 = 0x15;
pub(crate) const EC_IABT_LOW: u8 = 0x20;
pub(crate) const EC_PC_ALIGN: u8 = 0x22;
pub(crate) const EC_DABT_LOW: u8 = 0x24;
pub(crate) const EC_SP_ALIGN: u8 = 0x26;
pub(crate) const EC_FP_EXC64: u8 = 0x2c;
pub(crate) const EC_SOFTSTP_LOW: u8 = 0x32;
pub(crate) const EC_BRK64: u8 = 0x3c;

/// How the CPU came back from user mode.
pub(crate) enum Return {
    Syscall,
    Interrupt,
    Exception { vector: u8, error: u64, cr2: u64 },
}

/// Gives the kind of a user exception from the exception class, the ESR and the FAR.
pub(crate) fn classify(ec: u8, esr: u64, far: u64) -> crate::user::ExceptionKind {
    use crate::user::{ExceptionKind, FaultAccess};
    match ec {
        EC_IABT_LOW | EC_DABT_LOW => {
            // The fault status code: translation faults are 0b0001xx, access flag faults are
            // 0b0010xx and permission faults are 0b0011xx.
            let status = esr & 0x3f;
            let present = matches!(status >> 2, 0b0010 | 0b0011);
            // WnR tells a write. A cache maintenance instruction (CM) reads, as in Linux.
            let write = ec == EC_DABT_LOW && esr & (1 << 6) != 0 && esr & (1 << 8) == 0;
            let access = if ec == EC_IABT_LOW {
                FaultAccess::Exec
            } else if write {
                FaultAccess::Write
            } else {
                FaultAccess::Read
            };
            if matches!(status >> 2, 0b0001..=0b0011) {
                ExceptionKind::PageFault { addr: far, access, present }
            } else if status == 0b10_0001 {
                ExceptionKind::Alignment { addr: far }
            } else {
                ExceptionKind::Other
            }
        }
        EC_PC_ALIGN | EC_SP_ALIGN => ExceptionKind::Alignment { addr: far },
        EC_FP_EXC64 => ExceptionKind::FloatingPoint,
        EC_SOFTSTP_LOW => ExceptionKind::SingleStep,
        EC_BRK64 => ExceptionKind::Breakpoint,
        EC_UNKNOWN => ExceptionKind::IllegalInstruction,
        _ => ExceptionKind::Other,
    }
}

/// Runs user code with the registers `regs`, the FP and SIMD state `fpu` and the thread pointer
/// `tls`, until it comes back to the kernel. When this function returns, `regs`, `fpu` and `tls`
/// have the user values at that time. User code can write TPIDR_EL0, so `tls` can change.
pub(crate) fn enter(regs: &mut UserRegs, fpu: &mut FpuState, tls: &mut u64) -> Return {
    regs.pstate &= USER_PSTATE;
    let was_enabled = super::irq::enabled();
    super::irq::disable();
    set_step(regs.pstate & STEP_FLAG != 0);
    let local = cpu::local();
    local.user_fpu.store(core::ptr::from_mut(fpu) as u64, Ordering::Relaxed);
    // SAFETY: the user registers go to EL0 with the PSTATE bits of EL0 only, so the user code can
    // touch only the pages of TTBR0 that allow EL0. Each path back to the kernel saves the user
    // registers in `regs` and `fpu` and returns here with the registers of the kernel as they
    // were. `regs` and `fpu` live until the call returns, and no other reference to them exists
    // in that time.
    let how = unsafe { rk_user_enter(regs, fpu, *tls) };
    let value: u64;
    // SAFETY: reading TPIDR_EL0 has no side effect. The kernel does not write it, so it has the
    // value of the user code.
    unsafe { core::arch::asm!("mrs {}, tpidr_el0", out(reg) value, options(nomem, nostack)) };
    *tls = value;
    if was_enabled {
        super::irq::enable();
    }
    match how {
        RETURN_SYSCALL => Return::Syscall,
        RETURN_INTERRUPT => Return::Interrupt,
        _ => {
            let e = &local.exception;
            let esr = e[0].load(Ordering::Relaxed);
            Return::Exception {
                vector: (esr >> 26 & 0x3f) as u8,
                error: esr,
                cr2: e[1].load(Ordering::Relaxed),
            }
        }
    }
}

/// Handles a trap from EL0. The trap handler calls this for the vectors of EL0. Each trap goes
/// back to the caller of `enter`.
pub(crate) fn trap(frame: &TrapFrame, esr: u64, far: u64, irq: bool) -> ! {
    let local = cpu::local();
    let regs = local.user_regs.load(Ordering::Relaxed) as *mut UserRegs;
    let fpu = local.user_fpu.load(Ordering::Relaxed) as *mut FpuState;
    let ec = (esr >> 26 & 0x3f) as u8;
    let syscall = !irq && ec == EC_SVC64;
    let mut saved = UserRegs {
        x: frame.x,
        sp: read_sp_el0(),
        pc: frame.elr,
        pstate: frame.spsr,
        orig_x0: frame.x[0],
    };
    if !syscall {
        // SAFETY: as below. `orig_x0` keeps the value of the last system call.
        saved.orig_x0 = unsafe { (*regs).orig_x0 };
    }
    let mut state = [0u8; FpuState::SIZE];
    for (i, q) in frame.q.iter().enumerate() {
        state[i * 16..i * 16 + 16].copy_from_slice(&q.to_le_bytes());
    }
    state[512..516].copy_from_slice(&(frame.fpsr as u32).to_le_bytes());
    state[516..520].copy_from_slice(&(frame.fpcr as u32).to_le_bytes());
    // SAFETY: user code runs only in `enter`, and `enter` stores the addresses of its `UserRegs`
    // and `FpuState` values before it goes to user mode. They live until `enter` returns.
    unsafe { regs.write(saved) };
    // SAFETY: as above.
    unsafe { fpu.write(FpuState(state)) };
    let how = if irq {
        super::interrupt();
        RETURN_INTERRUPT
    } else if syscall {
        RETURN_SYSCALL
    } else {
        local.exception[0].store(esr, Ordering::Relaxed);
        local.exception[1].store(far, Ordering::Relaxed);
        RETURN_EXCEPTION
    };
    // SAFETY: the trap came from EL0, so the code of `enter` waits for the return, and its stack
    // pointer is in the `Local` value of the CPU. The trap frame is on the same stack, below that
    // stack pointer, and nothing in it must be dropped, so it is correct to leave it.
    unsafe { rk_user_return(how) }
}

fn read_sp_el0() -> u64 {
    let value: u64;
    // SAFETY: reading SP_EL0 at EL1 with SP_EL1 in use has no side effect.
    unsafe { core::arch::asm!("mrs {}, sp_el0", out(reg) value, options(nomem, nostack)) };
    value
}

//! The entry to user mode and the return from it.
//!
//! `enter` saves the registers that the kernel must keep, loads the user registers and goes to
//! user mode with `iretq`. The CPU comes back to the kernel on a `syscall` instruction, on an
//! exception or on an interrupt. Each path saves the user registers in the `UserRegs` value and
//! jumps to `rk_user_return`. That code loads the kernel stack pointer that `enter` saved, so
//! `enter` returns to its caller. This is the method of the `UserContext` type of OSTD.
//!
//! The return to user mode is `sysretq` when the registers allow it, as in Linux: RCX has the
//! user RIP, R11 has the user RFLAGS, the RIP is canonical and below the last user page, and the
//! trap flag is clear. This is the usual case after a system call. Each other return is `iretq`,
//! for example after an interrupt, an exception or a signal frame. `sysretq` loads RIP from RCX in
//! kernel mode, and the Intel CPUs make a general protection fault in kernel mode if that value is
//! not canonical, so the check of the RIP comes first.
//!
//! The kernel does not use the x87 and SSE registers. When the registers of the CPU have the FPU
//! state of the thread already, `enter` sets CR0.TS before it goes to user mode. If the user code
//! does not use the FPU, the state does not change, and `fxsave` is not needed after the return.
//! The first FPU instruction makes a device not available exception (`#NM`). `trap` then clears
//! CR0.TS, and the instruction runs again. CR0.TS is set only when the registers have the state of
//! the same thread, so the user code cannot see the state of another thread, also with
//! speculation (the LazyFP problem of the old lazy FPU code of Linux).
//!
//! The saved values are in the `Local` value of the CPU, at `%gs:` addresses.

use super::cpu;
use super::gdt::{KERNEL_CS, KERNEL_DS, USER_CS, USER_DS, USER32_CS};
use super::trap::{DEVICE_NOT_AVAILABLE, NMI, TrapFrame};
use core::sync::atomic::{AtomicU64, Ordering};

/// The user registers, in the order that the entry code reads and writes them.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct UserRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

/// The x87, MMX and SSE state of a user thread, in the `fxsave` format.
///
/// `tag` tells if the registers of a CPU still have this state. Each `fxsave` gives the state a
/// new tag, and the CPU keeps the tag of its last `fxsave`. When the two tags are the same, the
/// entry to user mode does not need `fxrstor`. A state that the kernel makes or changes has the
/// tag 0, which no CPU has. Only `enter` writes the bytes with a tag that is not 0, so a state with
/// a tag that is not 0 is the state of that `fxsave` or of an `fxrstor`. The tags are not in the
/// bytes, so user code cannot see or change them.
///
/// `eager` is the number of the next entries that save the state with no check. A thread that
/// uses the FPU after a lazy entry gets this count, so it does not get an `#NM` exception on
/// each entry, as the `fpu_counter` of the old Linux code.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug)]
pub struct FpuState {
    bytes: [u8; 512],
    tag: u64,
    eager: u32,
}

impl PartialEq for FpuState {
    /// Two states are the same if they have the same bytes. The tag is not a part of the state.
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for FpuState {}

impl Default for FpuState {
    /// The state after `fninit`, with the MXCSR value that Linux gives a new program: all SSE
    /// exceptions are masked.
    fn default() -> Self {
        let mut s = [0; 512];
        s[0..2].copy_from_slice(&0x037f_u16.to_le_bytes()); // FCW
        s[24..28].copy_from_slice(&0x1f80_u32.to_le_bytes()); // MXCSR
        s[28..32].copy_from_slice(&0xffbf_u32.to_le_bytes()); // MXCSR_MASK, as the CPU gives it
        Self { bytes: s, tag: 0, eager: 0 }
    }
}

/// The bits of MXCSR that `fxrstor` accepts on each x86-64 CPU. A reserved bit set makes it
/// fault.
const MXCSR_VALID: u32 = 0xffbf;

impl FpuState {
    /// The size of the `fxsave` area.
    pub const SIZE: usize = 512;

    /// The state in the `fxsave` format, for the signal frame.
    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.bytes
    }

    /// Makes a state from bytes in the `fxsave` format, for `rt_sigreturn`. The reserved bits of
    /// MXCSR are cleared, so the bytes from user memory cannot make `fxrstor` fault.
    pub fn from_bytes(bytes: &[u8; Self::SIZE]) -> Self {
        let mut s = *bytes;
        let mxcsr = u32::from_le_bytes([s[24], s[25], s[26], s[27]]) & MXCSR_VALID;
        s[24..28].copy_from_slice(&mxcsr.to_le_bytes());
        Self { bytes: s, tag: 0, eager: 0 }
    }
}

/// The way that the CPU came back from user mode, as `rk_user_return` gets it in RAX.
pub(crate) const RETURN_SYSCALL: u64 = 0;
pub(crate) const RETURN_INTERRUPT: u64 = 1;
pub(crate) const RETURN_EXCEPTION: u64 = 2;

// The offsets in `UserRegs`: rax 0, rbx 8, rcx 16, rdx 24, rsi 32, rdi 40, rbp 48, rsp 56, r8 64
// to r15 120, rip 128 and rflags 136.
core::arch::global_asm!(
    r#"
    .section .text.rk_user, "ax"
    .global rk_user_enter
rk_user_enter:                      # rdi: the UserRegs value, rsi: 1 for sysretq, 0 for iretq
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp, %gs:{kernel_rsp}
    movq %rdi, %gs:{user_regs}
    testq %rsi, %rsi
    jnz 2f
    pushq ${user_ds}                # the iretq frame: ss, rsp, rflags, cs, rip
    pushq 56(%rdi)
    pushq 136(%rdi)
    pushq ${user_cs}
    pushq 128(%rdi)
    movq 0(%rdi), %rax
    movq 8(%rdi), %rbx
    movq 16(%rdi), %rcx
    movq 24(%rdi), %rdx
    movq 32(%rdi), %rsi
    movq 48(%rdi), %rbp
    movq 64(%rdi), %r8
    movq 72(%rdi), %r9
    movq 80(%rdi), %r10
    movq 88(%rdi), %r11
    movq 96(%rdi), %r12
    movq 104(%rdi), %r13
    movq 112(%rdi), %r14
    movq 120(%rdi), %r15
    movq 40(%rdi), %rdi
    swapgs
    iretq

2:  # The sysretq path. RCX and R11 have the user RIP and RFLAGS already. An interrupt from user
    # mode loads a null SS. The AMD CPUs keep the attributes of that SS after sysretq, and a later
    # change to 32 bit code would then fail, so a null SS becomes the kernel SS first, as in Linux.
    movl %ss, %eax
    testl %eax, %eax
    jnz 3f
    movl ${kernel_ds}, %eax
    movl %eax, %ss
3:  movq 0(%rdi), %rax
    movq 8(%rdi), %rbx
    movq 16(%rdi), %rcx
    movq 24(%rdi), %rdx
    movq 32(%rdi), %rsi
    movq 48(%rdi), %rbp
    movq 64(%rdi), %r8
    movq 72(%rdi), %r9
    movq 80(%rdi), %r10
    movq 88(%rdi), %r11
    movq 96(%rdi), %r12
    movq 104(%rdi), %r13
    movq 112(%rdi), %r14
    movq 120(%rdi), %r15
    movq 56(%rdi), %rsp             # interrupts are off, and the NMI has its own stack
    movq 40(%rdi), %rdi
    swapgs
    sysretq

    .global rk_syscall_entry
rk_syscall_entry:                   # rcx: the user rip, r11: the user rflags
    swapgs
    movq %rsp, %gs:{user_rsp}
    movq %gs:{user_regs}, %rsp
    movq %rax, 0(%rsp)
    movq %rbx, 8(%rsp)
    movq %rcx, 16(%rsp)
    movq %rdx, 24(%rsp)
    movq %rsi, 32(%rsp)
    movq %rdi, 40(%rsp)
    movq %rbp, 48(%rsp)
    movq %r8, 64(%rsp)
    movq %r9, 72(%rsp)
    movq %r10, 80(%rsp)
    movq %r11, 88(%rsp)
    movq %r12, 96(%rsp)
    movq %r13, 104(%rsp)
    movq %r14, 112(%rsp)
    movq %r15, 120(%rsp)
    movq %rcx, 128(%rsp)
    movq %r11, 136(%rsp)
    movq %gs:{user_rsp}, %rax
    movq %rax, 56(%rsp)
    movl ${syscall}, %edi
    # Fall through to rk_user_return.

    .global rk_user_return
rk_user_return:                     # rdi: the way back, one of the RETURN_ values
    movq %gs:{kernel_rsp}, %rsp
    movq %rdi, %rax
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    ret
"#,
    user_ds = const USER_DS,
    user_cs = const USER_CS,
    kernel_ds = const KERNEL_DS,
    syscall = const RETURN_SYSCALL,
    kernel_rsp = const cpu::KERNEL_RSP,
    user_regs = const cpu::USER_REGS,
    user_rsp = const cpu::USER_RSP,
    options(att_syntax)
);

unsafe extern "C" {
    fn rk_user_enter(regs: *mut UserRegs, sysret: u64) -> u64;
    fn rk_syscall_entry();
    fn rk_user_return(how: u64) -> !;
}

const IA32_EFER: u32 = 0xc000_0080;
const IA32_STAR: u32 = 0xc000_0081;
const IA32_LSTAR: u32 = 0xc000_0082;
const IA32_FMASK: u32 = 0xc000_0084;
const IA32_FS_BASE: u32 = 0xc000_0100;
/// EFER.SCE: the CPU accepts the `syscall` instruction.
const EFER_SCE: u64 = 1 << 0;

/// The flags that user code can set: CF, PF, AF, ZF, SF, TF, DF, OF, AC and ID.
const USER_FLAGS: u64 = 0x0024_0dd5;
/// IF, and bit 1, which is always set.
const FIXED_FLAGS: u64 = 0x202;
/// The flags that `syscall` clears: TF, IF, DF, IOPL, NT and AC, as in Linux.
const SYSCALL_MASK: u64 = 0x0004_7700;

/// The end of the lower half. An address at or above it is not canonical in user mode.
const LOWER_HALF_END: u64 = 1 << 47;
/// The end of the user RIP values that `sysretq` takes: the last page of the lower half is not
/// used, as `TASK_SIZE_MAX` of Linux, so the address after a `syscall` instruction there is still
/// canonical.
const SYSRET_RIP_END: u64 = LOWER_HALF_END - 4096;
/// The resume flag of RFLAGS.
const RESUME_FLAG: u64 = 1 << 16;

/// The last tag of an `fxsave` or an `fxrstor`. See `FpuState`.
static FPU_TAG: AtomicU64 = AtomicU64::new(0);

/// The number of entries that save the FPU state with no check, after a thread used the FPU in a
/// lazy entry. See `FpuState`.
const EAGER_ENTRIES: u32 = 16;

/// Gives a new FPU tag. See `FpuState`.
fn new_fpu_tag() -> u64 {
    FPU_TAG.fetch_add(1, Ordering::Relaxed) + 1
}

fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: the caller gives an MSR that each x86-64 CPU has. `rdmsr` does not touch memory.
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags))
    };
    (u64::from(hi) << 32) | u64::from(lo)
}

fn wrmsr(msr: u32, value: u64) {
    // SAFETY: the callers in this module write the syscall MSRs with the values that the entry
    // code needs. `wrmsr` does not touch memory.
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") msr, in("eax") value as u32, in("edx") (value >> 32) as u32, options(nomem, nostack, preserves_flags))
    };
}

/// CR0.MP: `wait` and `fwait` examine CR0.TS.
const CR0_MP: u64 = 1 << 1;
/// CR0.EM: the CPU has no x87 unit. It must be clear for SSE.
const CR0_EM: u64 = 1 << 2;
/// CR0.TS: the next x87, MMX or SSE instruction makes an `#NM` exception.
const CR0_TS: u64 = 1 << 3;
/// CR4.OSFXSR: the kernel uses `fxsave` and `fxrstor`, so the SSE instructions work.
const CR4_OSFXSR: u64 = 1 << 9;
/// CR4.OSXMMEXCPT: the kernel handles the SIMD floating point exception.
const CR4_OSXMMEXCPT: u64 = 1 << 10;
/// CR4.TSD: `rdtsc` and `rdtscp` fault outside ring 0.
const CR4_TSD: u64 = 1 << 2;

/// Sets or clears CR4.TSD, as `cr4_toggle_bits_irqsoff(X86_CR4_TSD)` in arch/x86/kernel/process.c
/// of Linux. CR4 is read and written only when the bit changes. The CPU keeps the value of the bit
/// in its `Local` value, as Linux keeps a copy of CR4 in `cpu_tlbstate`.
fn set_tsd(on: bool) {
    let local = cpu::local();
    if local.tsd.load(Ordering::Relaxed) == on {
        return;
    }
    local.tsd.store(on, Ordering::Relaxed);
    let cr4: u64;
    // SAFETY: reading CR4 has no side effect.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags))
    };
    let cr4 = if on { cr4 | CR4_TSD } else { cr4 & !CR4_TSD };
    // SAFETY: CR4.TSD changes only how `rdtsc` and `rdtscp` run outside ring 0. The kernel runs in
    // ring 0, so it is not affected.
    unsafe {
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags))
    };
}

/// Sets or clears CR0.TS. CR0 is written only when the bit changes. The CPU keeps the value of
/// the bit in its `Local` value.
fn set_ts(on: bool) {
    let local = cpu::local();
    if local.ts.load(Ordering::Relaxed) == on {
        return;
    }
    local.ts.store(on, Ordering::Relaxed);
    if on {
        let cr0: u64;
        // SAFETY: reading CR0 has no side effect.
        unsafe {
            core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags))
        };
        // SAFETY: CR0.TS changes only how the CPU runs x87, MMX and SSE instructions. The kernel
        // code has none, and `enter` clears the bit before its `fxrstor` and `fxsave`.
        unsafe {
            core::arch::asm!("mov cr0, {}", in(reg) cr0 | CR0_TS, options(nomem, nostack, preserves_flags))
        };
    } else {
        // SAFETY: `clts` clears only CR0.TS.
        unsafe { core::arch::asm!("clts", options(nomem, nostack, preserves_flags)) };
    }
}

/// Lets user code use x87, MMX and SSE. CR4.OSXSAVE stays clear, so CPUID tells user code that
/// AVX is not available, and the `fxsave` state is complete. The kernel itself does not use these
/// registers, because the target has no SSE.
fn enable_sse() {
    let (mut cr0, mut cr4): (u64, u64);
    // SAFETY: reading CR0 and CR4 has no side effect.
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags))
    };
    // SAFETY: as above.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags))
    };
    cr0 = (cr0 & !(CR0_EM | CR0_TS)) | CR0_MP;
    cr4 |= CR4_OSFXSR | CR4_OSXMMEXCPT;
    let local = cpu::local();
    local.tsd.store(cr4 & CR4_TSD != 0, Ordering::Relaxed);
    local.ts.store(false, Ordering::Relaxed);
    // The registers of the CPU have no user state yet.
    local.fpu_tag.store(0, Ordering::Relaxed);
    // SAFETY: these bits change only how the CPU runs x87 and SSE instructions. The kernel code
    // has none, and each x86-64 CPU has SSE2.
    unsafe {
        core::arch::asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack, preserves_flags))
    };
    // SAFETY: as above.
    unsafe {
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags))
    };
}

/// Sets up the `syscall` instruction and SSE. `sysret` would take the user code segment at
/// STAR[63:48] plus 16, and the user stack segment at STAR[63:48] plus 8.
pub(crate) fn init() {
    enable_sse();
    wrmsr(IA32_STAR, (u64::from(USER32_CS) << 48) | (u64::from(KERNEL_CS) << 32));
    wrmsr(IA32_LSTAR, rk_syscall_entry as *const () as u64);
    wrmsr(IA32_FMASK, SYSCALL_MASK);
    wrmsr(IA32_EFER, rdmsr(IA32_EFER) | EFER_SCE);
}

/// The trap flag of RFLAGS.
pub(crate) const STEP_FLAG: u64 = 1 << 8;

/// `AUDIT_ARCH_X86_64`.
pub(crate) const AUDIT_ARCH: u32 = 0xc000_003e;

/// How the CPU came back from user mode.
pub(crate) enum Return {
    Syscall,
    Interrupt,
    Exception { vector: u8, error: u64, cr2: u64 },
}

/// Gives the kind of a user exception from the vector, the error code and CR2.
pub(crate) fn classify(vector: u8, error: u64, cr2: u64) -> crate::user::ExceptionKind {
    use super::trap::{BREAKPOINT, DEBUG, DIVIDE_ERROR, INVALID_OPCODE, PAGE_FAULT};
    use crate::user::{ExceptionKind, FaultAccess};
    /// The vectors of the x87 error, the alignment check and the SIMD error.
    const X87_ERROR: u8 = 16;
    const ALIGNMENT_CHECK: u8 = 17;
    const SIMD_ERROR: u8 = 19;
    match vector {
        PAGE_FAULT => {
            // The error code bits: P (bit 0), W/R (bit 1) and I/D (bit 4).
            let access = if error & 0x10 != 0 {
                FaultAccess::Exec
            } else if error & 0x2 != 0 {
                FaultAccess::Write
            } else {
                FaultAccess::Read
            };
            ExceptionKind::PageFault { addr: cr2, access, present: error & 1 != 0 }
        }
        DIVIDE_ERROR => ExceptionKind::DivideError,
        X87_ERROR | SIMD_ERROR => ExceptionKind::FloatingPoint,
        DEBUG => ExceptionKind::SingleStep,
        BREAKPOINT => ExceptionKind::Breakpoint,
        INVALID_OPCODE => ExceptionKind::IllegalInstruction,
        ALIGNMENT_CHECK => ExceptionKind::Alignment { addr: 0 },
        _ => ExceptionKind::Other,
    }
}

/// Runs user code with the registers `regs`, the FPU state `fpu` and the FS base `fs_base`, until
/// it comes back to the kernel. When this function returns, `regs` and `fpu` have the user values
/// at that time. User code cannot change the FS base, because CR4.FSGSBASE is clear. If `no_tsc`
/// is true, `rdtsc` and `rdtscp` cause a general protection fault in the user code.
pub(crate) fn enter(regs: &mut UserRegs, fpu: &mut FpuState, fs_base: u64, no_tsc: bool) -> Return {
    if regs.rip >= LOWER_HALF_END {
        // `iretq` to this address would fault in kernel mode. User code that jumps there gets a
        // general protection fault, so the result is the same.
        return Return::Exception { vector: super::trap::GENERAL_PROTECTION, error: 0, cr2: 0 };
    }
    regs.rflags = (regs.rflags & USER_FLAGS) | FIXED_FLAGS;
    // The conditions of `sysretq`, as `syscall_return_slowpath` of Linux checks them: `sysretq`
    // loads RIP from RCX and RFLAGS from R11, and a trap flag would stop at the wrong place.
    let sysret = regs.rcx == regs.rip
        && regs.r11 == regs.rflags
        && regs.rip < SYSRET_RIP_END
        && regs.rflags & (STEP_FLAG | RESUME_FLAG) == 0;
    let was_enabled = super::irq::enabled();
    super::irq::disable();
    let local = cpu::local();
    // A value that is not canonical makes `wrmsr` fault. The user gets a value of 0 then, as an
    // access through it would fault. Only `enter` writes the MSR, so it keeps the last value.
    let fs_base = if fs_base < LOWER_HALF_END { fs_base } else { 0 };
    if local.fs_base.load(Ordering::Relaxed) != fs_base {
        wrmsr(IA32_FS_BASE, fs_base);
        local.fs_base.store(fs_base, Ordering::Relaxed);
    }
    set_tsd(no_tsc);
    // The kernel does not use the FPU registers, so they still have the state of the last
    // `fxsave` or `fxrstor` of this CPU. If that is the state of `fpu`, the `fxrstor` is not
    // needed.
    if fpu.tag == 0 || local.fpu_tag.load(Ordering::Relaxed) != fpu.tag {
        set_ts(false);
        // SAFETY: `fpu` is a valid `fxsave` area of 512 bytes, aligned to 16. Its MXCSR has no
        // reserved bit set, because only `fxsave`, `FpuState::default` and
        // `FpuState::from_bytes` write it. CR0.TS is clear.
        unsafe {
            core::arch::asm!("fxrstor64 [{}]", in(reg) fpu.bytes.as_ptr(), options(nostack, readonly, preserves_flags))
        };
        if fpu.tag == 0 {
            fpu.tag = new_fpu_tag();
        }
        local.fpu_tag.store(fpu.tag, Ordering::Relaxed);
    }
    // The registers have the state of `fpu` now. In a lazy entry, CR0.TS stays set until the user
    // code uses the FPU.
    let lazy = fpu.eager == 0;
    if !lazy {
        fpu.eager -= 1;
    }
    set_ts(lazy);
    // SAFETY: the user registers go to user mode with the user selectors and IOPL 0, so the user
    // code can touch only the user pages. Each path back to the kernel saves the user registers in
    // `regs` and returns here with the registers of the kernel as they were. `regs` lives until
    // the call returns, and no other reference to it exists in that time. With `sysret`, RCX and
    // R11 have the RIP and the RFLAGS, and the RIP is canonical.
    let how = unsafe { rk_user_enter(regs, u64::from(sysret)) };
    // If CR0.TS is still set, the user code did not use the FPU, and `fpu` has the state of the
    // registers.
    if !local.ts.load(Ordering::Relaxed) {
        // SAFETY: `fpu` is a writable area of 512 bytes, aligned to 16, and no other reference to
        // it exists in this call. CR0.TS is clear.
        unsafe {
            core::arch::asm!("fxsave64 [{}]", in(reg) fpu.bytes.as_mut_ptr(), options(nostack, preserves_flags))
        };
        let tag = new_fpu_tag();
        fpu.tag = tag;
        local.fpu_tag.store(tag, Ordering::Relaxed);
        if lazy {
            fpu.eager = EAGER_ENTRIES;
        }
    }
    if was_enabled {
        super::irq::enable();
    }
    match how {
        RETURN_SYSCALL => Return::Syscall,
        RETURN_INTERRUPT => Return::Interrupt,
        _ => {
            let e = &cpu::local().exception;
            Return::Exception {
                vector: e[0].load(Ordering::Relaxed) as u8,
                error: e[1].load(Ordering::Relaxed),
                cr2: e[2].load(Ordering::Relaxed),
            }
        }
    }
}

/// Handles a trap from user mode. The trap handler calls this when CS of the frame is a user
/// selector. A non maskable interrupt, an interrupt from another CPU and the `#NM` exception of a
/// lazy entry return to the user code. Each other trap goes back to the caller of `enter`.
pub(crate) fn trap(frame: &TrapFrame, cr2: u64) {
    let vector = frame.vector as u8;
    if vector == NMI {
        return;
    }
    if vector == DEVICE_NOT_AVAILABLE && cpu::local().ts.load(Ordering::Relaxed) {
        // The registers have the state of the thread, so the FPU instruction can run again.
        set_ts(false);
        return;
    }
    if super::smp::is_ipi(vector) {
        super::interrupt(vector);
        return;
    }
    let local = cpu::local();
    let regs = local.user_regs.load(Ordering::Relaxed) as *mut UserRegs;
    let saved = UserRegs {
        rax: frame.rax,
        rbx: frame.rbx,
        rcx: frame.rcx,
        rdx: frame.rdx,
        rsi: frame.rsi,
        rdi: frame.rdi,
        rbp: frame.rbp,
        rsp: frame.rsp,
        r8: frame.r8,
        r9: frame.r9,
        r10: frame.r10,
        r11: frame.r11,
        r12: frame.r12,
        r13: frame.r13,
        r14: frame.r14,
        r15: frame.r15,
        rip: frame.rip,
        rflags: frame.rflags,
    };
    // SAFETY: user code runs only in `enter`, and `enter` stores the address of its `UserRegs`
    // value before it goes to user mode. That value lives until `enter` returns.
    unsafe { regs.write(saved) };
    let how = if vector >= super::trap::FIRST_IRQ_VECTOR {
        super::interrupt(vector);
        RETURN_INTERRUPT
    } else {
        local.exception[0].store(u64::from(vector), Ordering::Relaxed);
        local.exception[1].store(frame.error, Ordering::Relaxed);
        local.exception[2].store(cr2, Ordering::Relaxed);
        RETURN_EXCEPTION
    };
    // SAFETY: the trap came from user mode, so the code of `enter` waits for the return, and its
    // stack pointer is in the `Local` value of the CPU. The trap entry code made the swapgs, so GS is the
    // kernel GS. The frames of the trap handler are on the entry stack, and nothing in them must
    // be dropped, so it is correct to leave them.
    unsafe { rk_user_return(how) }
}

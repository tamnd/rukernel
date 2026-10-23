//! The entry to user mode and the return from it.
//!
//! `enter` saves the registers that the kernel must keep, loads the user registers and goes to
//! user mode with `iretq`. The CPU comes back to the kernel on a `syscall` instruction, on an
//! exception or on an interrupt. Each path saves the user registers in the `UserRegs` value and
//! jumps to `rk_user_return`. That code loads the kernel stack pointer that `enter` saved, so
//! `enter` returns to its caller. This is the method of the `UserContext` type of OSTD.
//!
//! The kernel does not use `sysret`. The return to user mode is always `iretq`, so a user RIP that
//! is not canonical cannot make a fault in kernel mode.
//!
//! In R0 there is one CPU, so the saved values are in static variables. They become per CPU in R2.

use super::gdt::{KERNEL_CS, USER_CS, USER_DS, USER32_CS};
use super::trap::{NMI, TrapFrame};
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

/// The way that the CPU came back from user mode, as `rk_user_return` gets it in RAX.
pub(crate) const RETURN_SYSCALL: u64 = 0;
pub(crate) const RETURN_INTERRUPT: u64 = 1;
pub(crate) const RETURN_EXCEPTION: u64 = 2;

/// The kernel stack pointer of `enter`, after it pushes the registers that it must keep.
#[unsafe(no_mangle)]
static RK_KERNEL_RSP: AtomicU64 = AtomicU64::new(0);
/// The address of the `UserRegs` value of the running user code.
#[unsafe(no_mangle)]
static RK_USER_REGS: AtomicU64 = AtomicU64::new(0);
/// The user stack pointer at a `syscall` instruction, until the entry code saves it.
#[unsafe(no_mangle)]
static RK_USER_RSP: AtomicU64 = AtomicU64::new(0);

/// The vector, the error code and CR2 of the last exception in user mode.
static EXCEPTION: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

// The offsets in `UserRegs`: rax 0, rbx 8, rcx 16, rdx 24, rsi 32, rdi 40, rbp 48, rsp 56, r8 64
// to r15 120, rip 128 and rflags 136.
core::arch::global_asm!(
    r#"
    .section .text.rk_user, "ax"
    .global rk_user_enter
rk_user_enter:                      # rdi: the UserRegs value
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp, RK_KERNEL_RSP(%rip)
    movq %rdi, RK_USER_REGS(%rip)
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

    .global rk_syscall_entry
rk_syscall_entry:                   # rcx: the user rip, r11: the user rflags
    swapgs
    movq %rsp, RK_USER_RSP(%rip)
    movq RK_USER_REGS(%rip), %rsp
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
    movq RK_USER_RSP(%rip), %rax
    movq %rax, 56(%rsp)
    movl ${syscall}, %edi
    # Fall through to rk_user_return.

    .global rk_user_return
rk_user_return:                     # rdi: the way back, one of the RETURN_ values
    movq RK_KERNEL_RSP(%rip), %rsp
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
    syscall = const RETURN_SYSCALL,
    options(att_syntax)
);

unsafe extern "C" {
    fn rk_user_enter(regs: *mut UserRegs) -> u64;
    fn rk_syscall_entry();
    fn rk_user_return(how: u64) -> !;
}

const IA32_EFER: u32 = 0xc000_0080;
const IA32_STAR: u32 = 0xc000_0081;
const IA32_LSTAR: u32 = 0xc000_0082;
const IA32_FMASK: u32 = 0xc000_0084;
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

/// Sets up the `syscall` instruction. `sysret` would take the user code segment at STAR[63:48]
/// plus 16, and the user stack segment at STAR[63:48] plus 8.
pub(crate) fn init() {
    wrmsr(IA32_STAR, (u64::from(USER32_CS) << 48) | (u64::from(KERNEL_CS) << 32));
    wrmsr(IA32_LSTAR, rk_syscall_entry as *const () as u64);
    wrmsr(IA32_FMASK, SYSCALL_MASK);
    wrmsr(IA32_EFER, rdmsr(IA32_EFER) | EFER_SCE);
}

/// How the CPU came back from user mode.
pub(crate) enum Return {
    Syscall,
    Interrupt,
    Exception { vector: u8, error: u64, cr2: u64 },
}

/// Runs user code with the registers `regs` until it comes back to the kernel. When this function
/// returns, `regs` has the user registers at that time.
pub(crate) fn enter(regs: &mut UserRegs) -> Return {
    if regs.rip >= LOWER_HALF_END {
        // `iretq` to this address would fault in kernel mode. User code that jumps there gets a
        // general protection fault, so the result is the same.
        return Return::Exception { vector: super::trap::GENERAL_PROTECTION, error: 0, cr2: 0 };
    }
    regs.rflags = (regs.rflags & USER_FLAGS) | FIXED_FLAGS;
    let was_enabled = super::irq::enabled();
    super::irq::disable();
    // SAFETY: the user registers go to user mode with the user selectors and IOPL 0, so the user
    // code can touch only the user pages. Each path back to the kernel saves the user registers in
    // `regs` and returns here with the registers of the kernel as they were. `regs` lives until
    // the call returns, and no other reference to it exists in that time.
    let how = unsafe { rk_user_enter(regs) };
    if was_enabled {
        super::irq::enable();
    }
    match how {
        RETURN_SYSCALL => Return::Syscall,
        RETURN_INTERRUPT => Return::Interrupt,
        _ => Return::Exception {
            vector: EXCEPTION[0].load(Ordering::Relaxed) as u8,
            error: EXCEPTION[1].load(Ordering::Relaxed),
            cr2: EXCEPTION[2].load(Ordering::Relaxed),
        },
    }
}

/// Handles a trap from user mode. The trap handler calls this when CS of the frame is a user
/// selector. A non maskable interrupt returns to the user code. Each other trap goes back to the
/// caller of `enter`.
pub(crate) fn trap(frame: &TrapFrame, cr2: u64) {
    let vector = frame.vector as u8;
    if vector == NMI {
        return;
    }
    let regs = RK_USER_REGS.load(Ordering::Relaxed) as *mut UserRegs;
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
        EXCEPTION[0].store(u64::from(vector), Ordering::Relaxed);
        EXCEPTION[1].store(frame.error, Ordering::Relaxed);
        EXCEPTION[2].store(cr2, Ordering::Relaxed);
        RETURN_EXCEPTION
    };
    // SAFETY: the trap came from user mode, so the code of `enter` waits for the return, and its
    // stack pointer is in `RK_KERNEL_RSP`. The trap entry code made the swapgs, so GS is the
    // kernel GS. The frames of the trap handler are on the entry stack, and nothing in them must
    // be dropped, so it is correct to leave them.
    unsafe { rk_user_return(how) }
}

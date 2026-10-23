//! The interrupt descriptor table and the trap entry code.
//!
//! Each of the 256 vectors has a small stub. The stub pushes an error code of 0 when the CPU does
//! not push one, and then the vector number. All stubs jump to one common entry. The common entry
//! saves the general registers in a `TrapFrame` and calls `rk_frame_x86_64_trap`.
//!
//! Each stub is 16 bytes long, so the address of a stub is the address of the first stub plus 16
//! times the vector.

use super::gdt::{IST_DOUBLE_FAULT, IST_MACHINE_CHECK, IST_NMI, KERNEL_CS};
use super::trap::{BREAKPOINT, DOUBLE_FAULT, MACHINE_CHECK, NMI, OVERFLOW};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

// The CPU pushes an error code for vectors 8, 10 to 14, 17, 21, 29 and 30.
core::arch::global_asm!(
    r#"
    .section .text.rk_trap_stubs, "ax"
    .balign 16
    .global rk_trap_stubs
rk_trap_stubs:
    .set rk_vector, 0
    .rept 256
    .balign 16
    .if (rk_vector == 8) || (rk_vector >= 10 && rk_vector <= 14) || (rk_vector == 17) || (rk_vector == 21) || (rk_vector == 29) || (rk_vector == 30)
    .else
    pushq $0
    .endif
    pushq $rk_vector
    jmp rk_trap_common
    .set rk_vector, rk_vector + 1
    .endr

    .section .text.rk_trap_common, "ax"
rk_trap_common:
    testb $3, 24(%rsp)              # CS of the interrupted code: swapgs if it was user mode
    jz 1f
    swapgs
1:
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp, %rdi
    cld
    call rk_frame_x86_64_trap
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    addq $16, %rsp                  # the vector and the error code
    testb $3, 8(%rsp)
    jz 2f
    swapgs
2:
    iretq
"#,
    options(att_syntax)
);

unsafe extern "C" {
    static rk_trap_stubs: [u8; 256 * 16];
}

/// One gate descriptor.
#[derive(Clone, Copy)]
#[repr(C)]
struct Gate {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl Gate {
    const EMPTY: Self = Self {
        offset_low: 0,
        selector: 0,
        ist: 0,
        attr: 0,
        offset_mid: 0,
        offset_high: 0,
        reserved: 0,
    };

    /// A present 64 bit interrupt gate. `dpl` 3 lets user code use `int` for this vector.
    fn interrupt(handler: u64, ist: u8, dpl: u8) -> Self {
        Self {
            offset_low: handler as u16,
            selector: KERNEL_CS,
            ist,
            attr: 0x8e | (dpl << 5),
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }
}

#[repr(C, align(16))]
struct Idt(UnsafeCell<[Gate; 256]>);

// SAFETY: only `init` writes the table, one time, before the CPU loads it. The `LOADED` flag makes
// sure of this.
unsafe impl Sync for Idt {}

static IDT: Idt = Idt(UnsafeCell::new([Gate::EMPTY; 256]));
static LOADED: AtomicBool = AtomicBool::new(false);

#[repr(C, packed)]
struct Pointer {
    limit: u16,
    base: u64,
}

/// Fills the IDT and loads it.
pub(crate) fn init() {
    if LOADED.swap(true, Ordering::AcqRel) {
        return;
    }
    let stubs = (&raw const rk_trap_stubs) as u64;
    let mut gates = [Gate::EMPTY; 256];
    for (vector, gate) in gates.iter_mut().enumerate() {
        let ist = match vector as u8 {
            DOUBLE_FAULT => IST_DOUBLE_FAULT,
            NMI => IST_NMI,
            MACHINE_CHECK => IST_MACHINE_CHECK,
            _ => 0,
        };
        // Linux lets user code use int3 and into.
        let dpl = if matches!(vector as u8, BREAKPOINT | OVERFLOW) { 3 } else { 0 };
        *gate = Gate::interrupt(stubs + 16 * vector as u64, ist, dpl);
    }
    // SAFETY: `LOADED` makes sure that this code runs one time, before the CPU loads the table.
    unsafe { IDT.0.get().write(gates) };
    let ptr = Pointer { limit: (size_of::<[Gate; 256]>() - 1) as u16, base: IDT.0.get() as u64 };
    // SAFETY: the table is static and each gate points to a stub in `rk_trap_stubs`.
    unsafe { core::arch::asm!("lidt [{}]", in(reg) &raw const ptr, options(readonly, nostack)) };
}

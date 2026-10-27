//! The exception vectors and the trap handler of arm64.
//!
//! The vector table has 16 entries, per the Arm ARM section D1.10.2: four kinds (synchronous,
//! IRQ, FIQ and SError) for each of four sources (EL1 with SP_EL0, EL1 with SP_EL1, EL0 in
//! AArch64 and EL0 in AArch32). The kernel runs with SP_EL1, so its exceptions come to the second
//! group. Each entry saves x0 and x1 and goes to the common entry, which saves the other general
//! registers, the FP and SIMD registers and the exception registers in a `TrapFrame`, and calls
//! `rk_frame_aarch64_trap`. The kernel code uses the SIMD registers, so an interrupt must keep
//! them.

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

/// The size of a `TrapFrame`.
const FRAME_SIZE: usize = 800;

/// The registers that the entry code saves.
#[repr(C)]
pub(crate) struct TrapFrame {
    x: [u64; 31],
    elr: u64,
    spsr: u64,
    /// The index of the vector table entry.
    kind: u64,
    fpsr: u64,
    fpcr: u64,
    q: [u128; 32],
}

const _: () = assert!(size_of::<TrapFrame>() == FRAME_SIZE);

/// The entries of the vector table for EL1 with SP_EL1.
const EL1_SYNC: u64 = 4;
const EL1_IRQ: u64 = 5;

/// The exception classes of ESR_EL1 that the handler knows.
const EC_IABT_EL1: u64 = 0x21;
const EC_DABT_EL1: u64 = 0x25;
const EC_BRK: u64 = 0x3c;

core::arch::global_asm!(
    r#"
    .section .text.rk_vectors, "ax"
    .balign 2048
    .global rk_aarch64_vectors
rk_aarch64_vectors:
    .irp kind, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    .balign 128
    sub     sp, sp, #{frame}
    stp     x0, x1, [sp]
    mov     x0, #\kind
    b       rk_aarch64_trap_entry
    .endr

rk_aarch64_trap_entry:
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]
    stp     x8, x9, [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    mrs     x1, elr_el1
    stp     x30, x1, [sp, #240]
    mrs     x1, spsr_el1
    stp     x1, x0, [sp, #256]
    mrs     x1, fpsr
    mrs     x2, fpcr
    stp     x1, x2, [sp, #272]
    add     x1, sp, #288
    stp     q0, q1, [x1, #0]
    stp     q2, q3, [x1, #32]
    stp     q4, q5, [x1, #64]
    stp     q6, q7, [x1, #96]
    stp     q8, q9, [x1, #128]
    stp     q10, q11, [x1, #160]
    stp     q12, q13, [x1, #192]
    stp     q14, q15, [x1, #224]
    stp     q16, q17, [x1, #256]
    stp     q18, q19, [x1, #288]
    stp     q20, q21, [x1, #320]
    stp     q22, q23, [x1, #352]
    stp     q24, q25, [x1, #384]
    stp     q26, q27, [x1, #416]
    stp     q28, q29, [x1, #448]
    stp     q30, q31, [x1, #480]
    mov     x0, sp
    bl      rk_frame_aarch64_trap
    add     x1, sp, #288
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
    ldp     x1, x2, [sp, #272]
    msr     fpsr, x1
    msr     fpcr, x2
    ldr     x1, [sp, #256]
    msr     spsr_el1, x1
    ldp     x30, x1, [sp, #240]
    msr     elr_el1, x1
    ldp     x2, x3, [sp, #16]
    ldp     x4, x5, [sp, #32]
    ldp     x6, x7, [sp, #48]
    ldp     x8, x9, [sp, #64]
    ldp     x10, x11, [sp, #80]
    ldp     x12, x13, [sp, #96]
    ldp     x14, x15, [sp, #112]
    ldp     x16, x17, [sp, #128]
    ldp     x18, x19, [sp, #144]
    ldp     x20, x21, [sp, #160]
    ldp     x22, x23, [sp, #176]
    ldp     x24, x25, [sp, #192]
    ldp     x26, x27, [sp, #208]
    ldp     x28, x29, [sp, #224]
    ldp     x0, x1, [sp]
    add     sp, sp, #{frame}
    eret
"#,
    frame = const FRAME_SIZE,
);

/// The names of the vector table entries, for the oops message.
const KINDS: [&str; 16] = [
    "synchronous exception from EL1t",
    "IRQ from EL1t",
    "FIQ from EL1t",
    "SError from EL1t",
    "synchronous exception",
    "IRQ",
    "FIQ",
    "SError",
    "synchronous exception from EL0",
    "IRQ from EL0",
    "FIQ from EL0",
    "SError from EL0",
    "synchronous exception from AArch32 EL0",
    "IRQ from AArch32 EL0",
    "FIQ from AArch32 EL0",
    "SError from AArch32 EL0",
];

impl fmt::Display for TrapFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sp = core::ptr::from_ref(self) as usize + FRAME_SIZE;
        writeln!(f, "pc : {:#018x}", self.elr)?;
        writeln!(f, "lr : {:#018x}", self.x[30])?;
        writeln!(f, "sp : {sp:#018x} pstate: {:08x}", self.spsr)?;
        for i in (0..30).step_by(2).rev() {
            writeln!(f, "x{:<2}: {:016x} x{:<2}: {:016x}", i + 1, self.x[i + 1], i, self.x[i])?;
        }
        Ok(())
    }
}

pub(crate) static BREAKPOINTS: AtomicU64 = AtomicU64::new(0);
pub(crate) static PAGE_FAULTS: AtomicU64 = AtomicU64::new(0);
pub(crate) static FIXUPS: AtomicU64 = AtomicU64::new(0);

/// One entry of the exception table: an instruction that can fault, and the address where the
/// code continues after a fault.
#[repr(C)]
struct ExTableEntry {
    insn: u64,
    fixup: u64,
}

unsafe extern "C" {
    static __start___ex_table: ExTableEntry;
    static __stop___ex_table: ExTableEntry;
}

/// Gives the fixup address for a faulting instruction, if the exception table has one.
fn search_exception_table(pc: u64) -> Option<u64> {
    let start = &raw const __start___ex_table;
    let stop = &raw const __stop___ex_table;
    // The linker script puts all `__ex_table` sections between the two symbols, and each entry is
    // two quads that the assembler wrote. The table is read only.
    let len = (stop as usize - start as usize) / size_of::<ExTableEntry>();
    // SAFETY: as above, `len` entries are between the two symbols.
    let table = unsafe { core::slice::from_raw_parts(start, len) };
    table.iter().find(|e| e.insn == pc).map(|e| e.fixup)
}

fn read_esr() -> u64 {
    let value: u64;
    // SAFETY: reading ESR_EL1 has no side effect.
    unsafe { core::arch::asm!("mrs {}, esr_el1", out(reg) value, options(nomem, nostack)) };
    value
}

fn read_far() -> u64 {
    let value: u64;
    // SAFETY: reading FAR_EL1 has no side effect.
    unsafe { core::arch::asm!("mrs {}, far_el1", out(reg) value, options(nomem, nostack)) };
    value
}

/// The common trap handler. The entry code calls it with interrupts off.
#[unsafe(no_mangle)]
extern "C" fn rk_frame_aarch64_trap(frame: *mut TrapFrame) {
    // SAFETY: the entry code gives a pointer to the frame on the current stack. No other reference
    // to the frame exists while this function runs.
    let frame = unsafe { &mut *frame };
    match frame.kind {
        EL1_IRQ => super::interrupt(),
        EL1_SYNC => sync(frame),
        _ => oops(frame, read_esr()),
    }
}

/// Handles a synchronous exception of the kernel.
fn sync(frame: &mut TrapFrame) {
    let esr = read_esr();
    match esr >> 26 & 0x3f {
        EC_BRK => {
            BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
            frame.elr += 4;
            return;
        }
        EC_DABT_EL1 | EC_IABT_EL1 => {
            PAGE_FAULTS.fetch_add(1, Ordering::Relaxed);
            if let Some(fixup) = search_exception_table(frame.elr) {
                FIXUPS.fetch_add(1, Ordering::Relaxed);
                frame.elr = fixup;
                return;
            }
            crate::console::_print_panic(format_args!(
                "Unable to handle kernel paging request at virtual address {:016x}\n",
                read_far()
            ));
        }
        _ => {}
    }
    oops(frame, esr);
}

/// Prints the exception and the registers, as the oops message of Linux, and panics.
fn oops(frame: &TrapFrame, esr: u64) -> ! {
    let kind = KINDS.get(frame.kind as usize).copied().unwrap_or("exception");
    crate::console::_print_panic(format_args!(
        "Internal error: Oops: {kind}, ESR {esr:#010x}, FAR {:#018x}\n{frame}",
        read_far()
    ));
    panic!("{kind} in kernel mode");
}

/// Stops at a breakpoint. The trap handler counts it and returns.
pub(crate) fn breakpoint() {
    // SAFETY: `brk` traps to the handler, which steps over it and changes no register.
    unsafe { core::arch::asm!("brk #0", options(nomem, nostack)) };
}

/// Reads 8 bytes at `addr`. A fault gives `None` and does not panic.
#[inline(never)]
pub(crate) fn probe_read_u64(addr: usize) -> Option<u64> {
    let value: u64;
    let failed: u64;
    // SAFETY: the exception table entry sends a fault at the load to the fixup code, which sets
    // `failed`. A successful load reads a plain integer, and the caller gets a copy. The load does
    // not change memory.
    unsafe {
        core::arch::asm!(
            "2: ldr {value}, [{addr}]",
            "mov {failed}, #0",
            "3:",
            ".pushsection __ex_table, \"a\"",
            ".balign 8",
            ".quad 2b, 4f",
            ".popsection",
            ".pushsection .text.rk_fixup, \"ax\"",
            "4: mov {failed}, #1",
            "mov {value}, #0",
            "b 3b",
            ".popsection",
            addr = in(reg) addr,
            value = out(reg) value,
            failed = out(reg) failed,
            options(readonly, nostack),
        );
    }
    if failed == 0 { Some(value) } else { None }
}

/// Tells if a write to `addr` is allowed, with an exclusive load and store of the same value. The
/// value does not change. A fault gives `false`.
#[inline(never)]
pub(crate) fn probe_writable(addr: usize) -> bool {
    let failed: u64;
    // SAFETY: the exception table entries send a fault at the load or the store to the fixup code.
    // The caller gives an aligned address in the kernel image, which is normal memory. The store
    // writes the value that the load read, and the exclusive pair fails and tries again if another
    // access came between them, so no other access sees a change.
    unsafe {
        core::arch::asm!(
            "2: ldxr {tmp}, [{addr}]",
            "5: stxr {status:w}, {tmp}, [{addr}]",
            "cbnz {status:w}, 2b",
            "mov {failed}, #0",
            "3:",
            ".pushsection __ex_table, \"a\"",
            ".balign 8",
            ".quad 2b, 4f",
            ".quad 5b, 4f",
            ".popsection",
            ".pushsection .text.rk_fixup, \"ax\"",
            "4: mov {failed}, #1",
            "b 3b",
            ".popsection",
            addr = in(reg) addr,
            tmp = out(reg) _,
            status = out(reg) _,
            failed = out(reg) failed,
            options(nostack),
        );
    }
    failed == 0
}

/// The virtual address range of the kernel image.
pub(crate) fn kernel_image() -> (usize, usize) {
    super::paging::kernel_image()
}

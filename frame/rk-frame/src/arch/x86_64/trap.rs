//! The trap handler.
//!
//! The entry code in `idt.rs` calls `rk_frame_x86_64_trap` for each exception and interrupt. An
//! exception in the kernel that has an entry in the exception table continues at the fixup
//! address of the entry. This is the method of Linux, and the user copy functions use it later.
//! Each other exception in the kernel is a bug, and the kernel panics. A trap from user mode goes
//! to `user::trap`.

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

pub(crate) const DIVIDE_ERROR: u8 = 0;
pub(crate) const DEBUG: u8 = 1;
pub(crate) const NMI: u8 = 2;
pub(crate) const BREAKPOINT: u8 = 3;
pub(crate) const OVERFLOW: u8 = 4;
pub(crate) const INVALID_OPCODE: u8 = 6;
pub(crate) const DOUBLE_FAULT: u8 = 8;
pub(crate) const GENERAL_PROTECTION: u8 = 13;
pub(crate) const PAGE_FAULT: u8 = 14;
pub(crate) const MACHINE_CHECK: u8 = 18;

/// The first vector that a device or the local APIC uses.
pub(crate) const FIRST_IRQ_VECTOR: u8 = 32;

/// The registers of the interrupted code, in the order that the entry code pushes them.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct TrapFrame {
    pub(crate) r15: u64,
    pub(crate) r14: u64,
    pub(crate) r13: u64,
    pub(crate) r12: u64,
    pub(crate) r11: u64,
    pub(crate) r10: u64,
    pub(crate) r9: u64,
    pub(crate) r8: u64,
    pub(crate) rbp: u64,
    pub(crate) rdi: u64,
    pub(crate) rsi: u64,
    pub(crate) rdx: u64,
    pub(crate) rcx: u64,
    pub(crate) rbx: u64,
    pub(crate) rax: u64,
    pub(crate) vector: u64,
    pub(crate) error: u64,
    pub(crate) rip: u64,
    pub(crate) cs: u64,
    pub(crate) rflags: u64,
    pub(crate) rsp: u64,
    pub(crate) ss: u64,
}

impl fmt::Display for TrapFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "RIP: {:04x}:{:#018x} RFLAGS: {:#010x}", self.cs, self.rip, self.rflags)?;
        writeln!(f, "RSP: {:04x}:{:#018x} ERR: {:#x}", self.ss, self.rsp, self.error)?;
        writeln!(f, "RAX: {:#018x} RBX: {:#018x} RCX: {:#018x}", self.rax, self.rbx, self.rcx)?;
        writeln!(f, "RDX: {:#018x} RSI: {:#018x} RDI: {:#018x}", self.rdx, self.rsi, self.rdi)?;
        writeln!(f, "RBP: {:#018x} R08: {:#018x} R09: {:#018x}", self.rbp, self.r8, self.r9)?;
        writeln!(f, "R10: {:#018x} R11: {:#018x} R12: {:#018x}", self.r10, self.r11, self.r12)?;
        write!(f, "R13: {:#018x} R14: {:#018x} R15: {:#018x}", self.r13, self.r14, self.r15)
    }
}

/// The name of an exception vector, as the Linux oops message gives it.
fn name(vector: u8) -> &'static str {
    match vector {
        DIVIDE_ERROR => "divide error",
        DEBUG => "debug",
        NMI => "NMI",
        BREAKPOINT => "int3",
        OVERFLOW => "overflow",
        5 => "bounds",
        INVALID_OPCODE => "invalid opcode",
        7 => "device not available",
        DOUBLE_FAULT => "double fault",
        10 => "invalid TSS",
        11 => "segment not present",
        12 => "stack segment",
        GENERAL_PROTECTION => "general protection fault",
        PAGE_FAULT => "page fault",
        16 => "coprocessor error",
        17 => "alignment check",
        MACHINE_CHECK => "machine check",
        19 => "SIMD exception",
        20 => "virtualization exception",
        21 => "control protection fault",
        _ => "exception",
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
fn search_exception_table(rip: u64) -> Option<u64> {
    let start = &raw const __start___ex_table;
    let stop = &raw const __stop___ex_table;
    // SAFETY: the linker script puts all `__ex_table` sections between the two symbols, and each
    // entry is two quads that the assembler wrote. The table is read only.
    let table = unsafe { core::slice::from_raw_parts(start, stop.offset_from_unsigned(start)) };
    table.iter().find(|e| e.insn == rip).map(|e| e.fixup)
}

fn read_cr2() -> u64 {
    let value: u64;
    // SAFETY: reading CR2 has no side effect.
    unsafe {
        core::arch::asm!("mov {}, cr2", out(reg) value, options(nomem, nostack, preserves_flags))
    };
    value
}

/// The common trap handler. The entry code calls it with interrupts off.
#[unsafe(no_mangle)]
extern "C" fn rk_frame_x86_64_trap(frame: *mut TrapFrame) {
    // SAFETY: the entry code gives a pointer to the frame on the current stack. No other reference
    // to the frame exists while this function runs.
    let frame = unsafe { &mut *frame };
    let vector = frame.vector as u8;
    if frame.cs & 3 == 3 {
        let cr2 = if vector == PAGE_FAULT { read_cr2() } else { 0 };
        super::user::trap(frame, cr2);
        return;
    }
    if vector >= FIRST_IRQ_VECTOR {
        super::interrupt(vector);
        return;
    }
    match vector {
        BREAKPOINT => {
            BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        PAGE_FAULT => {
            PAGE_FAULTS.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
    let from_kernel = frame.cs & 3 == 0;
    if from_kernel
        && matches!(vector, PAGE_FAULT | GENERAL_PROTECTION)
        && let Some(fixup) = search_exception_table(frame.rip)
    {
        FIXUPS.fetch_add(1, Ordering::Relaxed);
        frame.rip = fixup;
        return;
    }
    if vector == PAGE_FAULT {
        crate::console::_print_panic(format_args!(
            "BUG: unable to handle page fault for address {:#018x}\n",
            read_cr2()
        ));
    }
    crate::console::_print_panic(format_args!(
        "Oops: {} [#{}] {:#06x}\n{frame}\n",
        name(vector),
        vector,
        frame.error
    ));
    panic!("{} in {} mode", name(vector), if from_kernel { "kernel" } else { "user" });
}

/// Stops at a breakpoint. The trap handler counts it and returns.
pub(crate) fn breakpoint() {
    // SAFETY: int3 traps to the breakpoint handler, which returns at once and changes no register.
    unsafe { core::arch::asm!("int3", options(nomem, nostack)) };
}

/// Reads 8 bytes at `addr`. A fault gives `None` and does not panic.
#[inline(never)]
pub(crate) fn probe_read_u64(addr: usize) -> Option<u64> {
    let value: u64;
    let failed: u32;
    // SAFETY: the exception table entry sends a page fault or a general protection fault at the
    // load to the fixup code, which sets `failed`. A successful load reads a plain integer, and
    // the caller gets a copy. The load does not change memory.
    unsafe {
        core::arch::asm!(
            "2: mov {value}, qword ptr [{addr}]",
            "xor {failed:e}, {failed:e}",
            "3:",
            ".pushsection __ex_table, \"a\"",
            ".balign 8",
            ".quad 2b, 4f",
            ".popsection",
            ".pushsection .text.rk_fixup, \"ax\"",
            "4: mov {failed:e}, 1",
            "xor {value:e}, {value:e}",
            "jmp 3b",
            ".popsection",
            addr = in(reg) addr,
            value = out(reg) value,
            failed = out(reg) failed,
            options(readonly, nostack),
        );
    }
    if failed == 0 { Some(value) } else { None }
}

/// Tells if a write to `addr` is allowed, with a locked OR of 0. The OR does not change the value.
/// A fault gives `false`.
#[inline(never)]
pub(crate) fn probe_writable(addr: usize) -> bool {
    let failed: u32;
    // SAFETY: the exception table entry sends a fault at the OR to the fixup code. The caller
    // gives an address in the kernel image, which is normal memory. A locked OR of 0 is atomic and
    // leaves the value as it was, so no other access sees a change.
    unsafe {
        core::arch::asm!(
            "2: lock or qword ptr [{addr}], 0",
            "xor {failed:e}, {failed:e}",
            "3:",
            ".pushsection __ex_table, \"a\"",
            ".balign 8",
            ".quad 2b, 4f",
            ".popsection",
            ".pushsection .text.rk_fixup, \"ax\"",
            "4: mov {failed:e}, 1",
            "jmp 3b",
            ".popsection",
            addr = in(reg) addr,
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

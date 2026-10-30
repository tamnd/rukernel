//! The arm64 code of the frame.
//!
//! The kernel boots from a Linux arm64 `Image` on the QEMU `virt` machine. It runs at EL1 with the
//! MMU on. The console is the PL011 UART, the interrupt controller is a GICv2 or a GICv3, and the
//! tick comes from the virtual timer of the generic timer. The device tree gives the addresses,
//! and the addresses of QEMU `virt` are the fallback. The virtio devices are on virtio-mmio or on
//! the PCI bus of the generic ECAM host, and their SPIs, or the LPIs of their MSI-X messages through
//! the GICv3 ITS, wake the drivers. User programs get a vDSO
//! with the time calls and `__kernel_rt_sigreturn`.

pub(crate) mod boot;
pub(crate) mod cpu;
pub(crate) mod gic;
pub(crate) mod its;
pub(crate) mod paging;
pub(crate) mod pl011;
pub(crate) mod smp;
pub(crate) mod task;
pub(crate) mod timer;
pub(crate) mod trap;
pub(crate) mod user;

use core::sync::atomic::{AtomicBool, Ordering};

/// Handles an interrupt from the GIC. The trap handler calls this with interrupts off.
fn interrupt() {
    let iar = gic::ack();
    let id = gic::intid(iar);
    if id == timer::intid() {
        timer::tick();
        gic::eoi(iar);
    } else if id == smp::SGI_CALL {
        smp::poll();
        gic::eoi(iar);
    } else if id == smp::SGI_RESCHEDULE || its::handle(id) {
        gic::eoi(iar);
    } else if gic::is_device(id) {
        gic::device_interrupt(id);
        gic::eoi(iar);
    } else if id >= gic::SPURIOUS {
        // A spurious interrupt has no end of interrupt.
    } else {
        crate::console::_print_panic(format_args!("rk-frame: unexpected interrupt {id}\n"));
        gic::eoi(iar);
    }
}

/// Tells if PSCI calls use `smc`. Else they use `hvc`, as on QEMU `virt` without EL3.
pub(crate) static PSCI_SMC: AtomicBool = AtomicBool::new(false);

/// Sets the PSCI call method, from the `/psci` node of the device tree.
fn set_psci_smc(smc: bool) {
    PSCI_SMC.store(smc, Ordering::Relaxed);
}

/// The PSCI function that turns the machine off.
const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;

/// The early console that the architecture independent code writes to: the PL011 UART.
pub(crate) mod console {
    pub(crate) use super::pl011::{try_read, write_bytes, write_raw};
}

/// Stops this CPU with interrupts off. The CPU does not continue.
pub fn halt_forever() -> ! {
    loop {
        // SAFETY: masking the exceptions and `wfi` change no memory. With the exceptions masked,
        // the CPU stays here.
        unsafe { core::arch::asm!("msr daifset, #0xf", "wfi", options(nomem, nostack)) };
    }
}

/// Stops the virtual machine through PSCI `SYSTEM_OFF`. QEMU then exits with the status 0, so the
/// code does not get to the host. The boot test reads the result from the console. If the call
/// returns, the CPU stops.
pub fn qemu_exit(_code: u32) -> ! {
    // The PSCI call turns the machine off. If the firmware has no PSCI, the call returns an error
    // in x0, and the code stops the CPU.
    if PSCI_SMC.load(Ordering::Relaxed) {
        // SAFETY: as above. The call changes only x0.
        unsafe {
            core::arch::asm!("smc #0", inout("x0") PSCI_SYSTEM_OFF => _, options(nomem, nostack));
        }
    } else {
        // SAFETY: as above.
        unsafe {
            core::arch::asm!("hvc #0", inout("x0") PSCI_SYSTEM_OFF => _, options(nomem, nostack));
        }
    }
    halt_forever()
}

/// Gives 64 bits for a random seed, from the `RNDR` register if the CPU has `FEAT_RNG`, else from
/// the counter of the generic timer.
pub fn random_seed() -> u64 {
    let isar0: u64;
    // SAFETY: reading ID_AA64ISAR0_EL1 has no side effect.
    unsafe {
        core::arch::asm!("mrs {}, id_aa64isar0_el1", out(reg) isar0, options(nomem, nostack))
    };
    if isar0 >> 60 != 0 {
        for _ in 0..10 {
            let value: u64;
            let ok: u64;
            // SAFETY: the CPU has FEAT_RNG, so RNDR exists. A read sets NZCV, and `cset` reads it.
            unsafe {
                core::arch::asm!(
                    "mrs {v}, s3_3_c2_c4_0",
                    "cset {ok}, ne",
                    v = out(reg) value,
                    ok = out(reg) ok,
                    options(nomem, nostack),
                );
            }
            if ok != 0 {
                return value;
            }
        }
    }
    let count: u64;
    // SAFETY: reading CNTVCT_EL0 has no side effect.
    unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) count, options(nomem, nostack)) };
    count.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

/// Copies of memory that user code can write at the same time, such as the frames of user pages.
/// The assembly copies 16 bytes with each `ldp` and `stp`, then the rest with one word and single
/// bytes. The compiler does not know the instructions, so it cannot assume that the memory does
/// not change. QEMU emulates each instruction alone, so a copy of pairs of words is about 16 times
/// faster there than a copy of bytes. The MMU allows accesses that are not aligned to normal
/// memory, because SCTLR_EL1.A is clear.
pub(crate) mod mem {
    /// Copies `len` bytes from `src` to `dst`.
    ///
    /// # Safety
    ///
    /// The two ranges must be valid kernel memory, and they must not overlap.
    pub(crate) unsafe fn copy(dst: *mut u8, src: *const u8, len: usize) {
        // SAFETY: the caller gives two valid ranges of `len` bytes. The loops stop at the end of
        // the ranges: `pairs` blocks of 16 bytes, then one word if bit 3 of `rest` is set, then the
        // bytes of the low 3 bits of `rest`.
        unsafe {
            core::arch::asm!(
                "cbz {pairs}, 2f",
                "1: ldp {a}, {b}, [{src}], #16",
                "stp {a}, {b}, [{dst}], #16",
                "subs {pairs}, {pairs}, #1",
                "b.ne 1b",
                "2: tbz {rest}, #3, 3f",
                "ldr {a}, [{src}], #8",
                "str {a}, [{dst}], #8",
                "3: and {rest}, {rest}, #7",
                "cbz {rest}, 5f",
                "4: ldrb {a:w}, [{src}], #1",
                "strb {a:w}, [{dst}], #1",
                "subs {rest}, {rest}, #1",
                "b.ne 4b",
                "5:",
                pairs = inout(reg) len / 16 => _,
                rest = inout(reg) len % 16 => _,
                src = inout(reg) src => _,
                dst = inout(reg) dst => _,
                a = out(reg) _,
                b = out(reg) _,
                options(nostack),
            );
        }
    }

    /// Copies the page of 4 KiB at `src` to the page at `dst`, for copy on write. Each step of
    /// the loop copies 128 bytes with the SIMD registers, so the loop has about a third of the
    /// instructions of `copy`. This matters most on QEMU without KVM, where the time of a copy
    /// follows the number of instructions.
    ///
    /// # Safety
    ///
    /// The two pages must be valid kernel memory, 16 byte aligned, and they must not overlap.
    pub(crate) unsafe fn copy_page(dst: *mut u8, src: *const u8) {
        // SAFETY: the caller gives two valid pages. The loop runs 32 times, and each step reads
        // and writes 128 bytes. The trap entry keeps the SIMD registers of user code, and the
        // compiler keeps the ones that this function changes.
        unsafe {
            core::arch::asm!(
                "1: ldp q0, q1, [{src}]",
                "ldp q2, q3, [{src}, #32]",
                "ldp q4, q5, [{src}, #64]",
                "ldp q6, q7, [{src}, #96]",
                "add {src}, {src}, #128",
                "stp q0, q1, [{dst}]",
                "stp q2, q3, [{dst}, #32]",
                "stp q4, q5, [{dst}, #64]",
                "stp q6, q7, [{dst}, #96]",
                "add {dst}, {dst}, #128",
                "subs {n}, {n}, #1",
                "b.ne 1b",
                n = inout(reg) 4096usize / 128 => _,
                src = inout(reg) src => _,
                dst = inout(reg) dst => _,
                out("v0") _,
                out("v1") _,
                out("v2") _,
                out("v3") _,
                out("v4") _,
                out("v5") _,
                out("v6") _,
                out("v7") _,
                options(nostack),
            );
        }
    }

    /// Writes `len` zero bytes at `dst`.
    ///
    /// # Safety
    ///
    /// The range must be valid kernel memory.
    pub(crate) unsafe fn zero(dst: *mut u8, len: usize) {
        // As in `copy`, an `stp` of the zero register writes 16 bytes, then the rest is one word
        // and single bytes.
        // SAFETY: as for `copy`.
        unsafe {
            core::arch::asm!(
                "cbz {pairs}, 2f",
                "1: stp xzr, xzr, [{dst}], #16",
                "subs {pairs}, {pairs}, #1",
                "b.ne 1b",
                "2: tbz {rest}, #3, 3f",
                "str xzr, [{dst}], #8",
                "3: and {rest}, {rest}, #7",
                "cbz {rest}, 5f",
                "4: strb wzr, [{dst}], #1",
                "subs {rest}, {rest}, #1",
                "b.ne 4b",
                "5:",
                pairs = inout(reg) len / 16 => _,
                rest = inout(reg) len % 16 => _,
                dst = inout(reg) dst => _,
                options(nostack),
            );
        }
    }
}

// The `memcpy` and `memset` of the kernel, which the compiler calls for copies and fills of
// slices and of large values. The functions of compiler_builtins are weak, so these replace them,
// as the assembly functions of arch/arm64/lib of Linux replace the generic ones. The target has
// `strict-align`, so the `memcpy` of compiler_builtins reads single bytes and joins them with
// shifts when the source and the destination have a different alignment: about 25 instructions
// for 8 bytes. Its `memset` writes 8 bytes in each step. A TCP segment starts 40 bytes after the
// start of the packet, so most copies of the network stack were of the slow type, and on QEMU
// without KVM they were a large part of the time of the TCP stream on loopback (#465). x86-64
// uses `rep movsb` and `rep stosb`. These functions read and write 64 bytes with 4 `ldp` and 4
// `stp` in each step, then the rest with smaller accesses. The kernel runs with the MMU on and
// SCTLR_EL1.A clear, and the copies are only of normal memory (IoMem uses volatile accesses), so
// accesses that are not aligned are allowed.
core::arch::global_asm!(
    r#"
    .section .text.memcpy, "ax"
    .global memcpy
    .type memcpy, %function
    .balign 16
memcpy:                             // x0: dst, x1: src, x2: len. Gives dst in x0.
    mov     x3, x0
    cmp     x2, #64
    b.lo    2f
1:  ldp     x4, x5, [x1]
    ldp     x6, x7, [x1, #16]
    ldp     x8, x9, [x1, #32]
    ldp     x10, x11, [x1, #48]
    add     x1, x1, #64
    sub     x2, x2, #64
    stp     x4, x5, [x3]
    stp     x6, x7, [x3, #16]
    stp     x8, x9, [x3, #32]
    stp     x10, x11, [x3, #48]
    add     x3, x3, #64
    cmp     x2, #64
    b.hs    1b
2:  tbz     x2, #5, 3f
    ldp     x4, x5, [x1]
    ldp     x6, x7, [x1, #16]
    add     x1, x1, #32
    stp     x4, x5, [x3]
    stp     x6, x7, [x3, #16]
    add     x3, x3, #32
3:  tbz     x2, #4, 4f
    ldp     x4, x5, [x1], #16
    stp     x4, x5, [x3], #16
4:  tbz     x2, #3, 5f
    ldr     x4, [x1], #8
    str     x4, [x3], #8
5:  tbz     x2, #2, 6f
    ldr     w4, [x1], #4
    str     w4, [x3], #4
6:  tbz     x2, #1, 7f
    ldrh    w4, [x1], #2
    strh    w4, [x3], #2
7:  tbz     x2, #0, 8f
    ldrb    w4, [x1]
    strb    w4, [x3]
8:  ret
    .size memcpy, . - memcpy

    .section .text.memset, "ax"
    .global memset
    .type memset, %function
    .balign 16
memset:                             // x0: dst, w1: the byte, x2: len. Gives dst in x0.
    and     x1, x1, #0xff
    mov     x4, #0x0101010101010101
    mul     x4, x1, x4
    mov     x3, x0
    cmp     x2, #64
    b.lo    2f
1:  stp     x4, x4, [x3]
    stp     x4, x4, [x3, #16]
    stp     x4, x4, [x3, #32]
    stp     x4, x4, [x3, #48]
    add     x3, x3, #64
    sub     x2, x2, #64
    cmp     x2, #64
    b.hs    1b
2:  tbz     x2, #5, 3f
    stp     x4, x4, [x3]
    stp     x4, x4, [x3, #16]
    add     x3, x3, #32
3:  tbz     x2, #4, 4f
    stp     x4, x4, [x3], #16
4:  tbz     x2, #3, 5f
    str     x4, [x3], #8
5:  tbz     x2, #2, 6f
    str     w4, [x3], #4
6:  tbz     x2, #1, 7f
    strh    w4, [x3], #2
7:  tbz     x2, #0, 8f
    strb    w4, [x3]
8:  ret
    .size memset, . - memset
    .text
"#
);

/// Interrupt control on this CPU. The handlers use only atomic values and the GIC, so an
/// interrupt cannot stop on a lock that the interrupted code holds.
pub(crate) mod irq {
    /// Lets this CPU take interrupts.
    pub(crate) fn enable() {
        // SAFETY: the vector table is set, and the handlers take no locks.
        unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack)) };
    }

    /// Stops this CPU from taking interrupts.
    pub(crate) fn disable() {
        // SAFETY: this changes only the IRQ mask.
        unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack)) };
    }

    /// Tells if this CPU takes interrupts.
    pub(crate) fn enabled() -> bool {
        let daif: u64;
        // SAFETY: reading DAIF has no side effect.
        unsafe { core::arch::asm!("mrs {}, daif", out(reg) daif, options(nomem, nostack)) };
        daif & (1 << 7) == 0
    }

    /// Waits for the next interrupt, then lets this CPU take it. A pending interrupt wakes `wfi`
    /// also when it is masked, so no interrupt is lost between the check and the wait.
    pub(crate) fn wait() {
        // SAFETY: as for `enable`. `wfi` changes no memory.
        unsafe { core::arch::asm!("wfi", "msr daifclr, #2", options(nomem, nostack)) };
    }
}

/// The real time clock: a PL031, at the address that the device tree gives, else at the address
/// of QEMU `virt`.
pub(crate) mod rtc {
    use super::paging::MMIO_BASE;
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// The virtual address of the data register, which counts the seconds since the epoch.
    static RTCDR: AtomicUsize = AtomicUsize::new(MMIO_BASE + 0x0901_0000);

    /// Uses the PL031 at the virtual address `base`, from the device tree.
    pub(crate) fn set_base(base: usize) {
        RTCDR.store(base, Ordering::Relaxed);
    }

    /// Gives the seconds since the epoch.
    pub(crate) fn read() -> Option<u64> {
        let addr = RTCDR.load(Ordering::Relaxed);
        // SAFETY: the page tables map the PL031 registers as device memory at this address: the
        // boot window of `MMIO_BASE` or a mapping of `paging::map_device`. The read has no side
        // effect.
        let secs = unsafe { (addr as *const u32).read_volatile() };
        (secs != 0).then_some(u64::from(secs))
    }
}

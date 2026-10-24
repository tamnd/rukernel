//! The local APIC, the legacy PIC and the timer.
//!
//! The kernel uses the local APIC in x2APIC mode when the CPU has it, and in xAPIC mode if not.
//! The legacy 8259 PIC is moved to vectors 0x20 to 0x2f and masked, so it sends no interrupts.
//!
//! The timer of the local APIC runs in periodic mode at `HZ` interrupts each second. Its frequency
//! is not known, so the boot code measures it against channel 2 of the PIT, as Linux does. The
//! vector numbers are the vector numbers of Linux, per arch/x86/include/asm/irq_vectors.h.

use super::io::Port;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// The timer interrupts each second. This is the default `CONFIG_HZ` of Linux on x86-64.
pub(crate) const HZ: u64 = 250;

/// The vector of the local APIC timer. Linux names it `LOCAL_TIMER_VECTOR`.
pub(crate) const TIMER_VECTOR: u8 = 0xec;
/// The vector of an APIC error. Linux names it `ERROR_APIC_VECTOR`.
pub(crate) const ERROR_VECTOR: u8 = 0xfe;
/// The spurious interrupt vector. Linux names it `SPURIOUS_APIC_VECTOR`.
pub(crate) const SPURIOUS_VECTOR: u8 = 0xff;

const IA32_APIC_BASE: u32 = 0x1b;
const APIC_BASE_X2APIC: u64 = 1 << 10;
const APIC_BASE_ENABLE: u64 = 1 << 11;
const APIC_BASE_ADDR: u64 = 0x000f_ffff_ffff_f000;

// The register offsets of the xAPIC. The MSR of the same register in x2APIC mode is
// `0x800 + offset / 16`.
const REG_TPR: u32 = 0x80;
const REG_EOI: u32 = 0xb0;
const REG_SVR: u32 = 0xf0;
const REG_LVT_TIMER: u32 = 0x320;
const REG_LVT_ERROR: u32 = 0x370;
const REG_TIMER_INIT: u32 = 0x380;
const REG_TIMER_CURRENT: u32 = 0x390;
const REG_TIMER_DIVIDE: u32 = 0x3e0;

const SVR_ENABLE: u32 = 1 << 8;
const LVT_MASKED: u32 = 1 << 16;
const LVT_PERIODIC: u32 = 1 << 17;
/// Divide the bus clock by 16.
const DIVIDE_BY_16: u32 = 0b0011;

/// The frequency of the PIT input clock, in Hz.
const PIT_HZ: u64 = 1_193_182;
/// The time of the calibration, in milliseconds.
const CALIBRATE_MS: u64 = 10;

/// The local APIC is in x2APIC mode.
static X2APIC: AtomicBool = AtomicBool::new(false);
/// The virtual address of the xAPIC registers, in xAPIC mode.
static XAPIC_BASE: AtomicUsize = AtomicUsize::new(0);
/// The timer interrupts since boot.
pub(crate) static TICKS: AtomicU64 = AtomicU64::new(0);
/// The frequency of the APIC timer after the divider, in Hz.
pub(crate) static TIMER_HZ: AtomicU64 = AtomicU64::new(0);

fn read_msr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: the callers read only MSRs that each x86-64 CPU with an APIC has. `rdmsr` does not
    // touch memory.
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
    }
    u64::from(hi) << 32 | u64::from(lo)
}

fn write_msr(msr: u32, value: u64) {
    // SAFETY: the callers write only the APIC MSRs, with values that keep the APIC in a mode that
    // this module knows. `wrmsr` does not touch memory.
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") msr, in("eax") value as u32, in("edx") (value >> 32) as u32, options(nomem, nostack, preserves_flags));
    }
}

fn read(reg: u32) -> u32 {
    if X2APIC.load(Ordering::Relaxed) {
        read_msr(0x800 + reg / 16) as u32
    } else {
        let addr = XAPIC_BASE.load(Ordering::Relaxed) + reg as usize;
        // SAFETY: `init` maps the xAPIC page at `XAPIC_BASE` before it sets up the registers, and
        // `reg` is a register offset inside that page.
        unsafe { (addr as *const u32).read_volatile() }
    }
}

fn write(reg: u32, value: u32) {
    if X2APIC.load(Ordering::Relaxed) {
        write_msr(0x800 + reg / 16, u64::from(value));
    } else {
        let addr = XAPIC_BASE.load(Ordering::Relaxed) + reg as usize;
        // SAFETY: as for `read`.
        unsafe { (addr as *mut u32).write_volatile(value) };
    }
}

/// Tells the local APIC that the handler of the current interrupt is done.
pub(crate) fn eoi() {
    write(REG_EOI, 0);
}

fn has_x2apic() -> bool {
    // CPUID leaf 1, ECX bit 21.
    let ecx: u32;
    // SAFETY: `cpuid` only writes the four registers. LLVM uses rbx, so the code keeps it.
    unsafe {
        core::arch::asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "mov rbx, {tmp:r}",
            tmp = out(reg) _,
            inout("eax") 1u32 => _,
            inout("ecx") 0u32 => ecx,
            out("edx") _,
            options(nomem, nostack, preserves_flags),
        );
    }
    ecx & (1 << 21) != 0
}

/// Moves the legacy PIC to vectors 0x20 to 0x2f, away from the exception vectors, and masks all of
/// its lines.
fn disable_pic() {
    // SAFETY: ports 0x20, 0x21, 0xa0 and 0xa1 are the two 8259 PICs, which this module owns.
    let (cmd1, data1, cmd2, data2) =
        unsafe { (Port::new(0x20), Port::new(0x21), Port::new(0xa0), Port::new(0xa1)) };
    cmd1.write(0x11); // ICW1: start the init sequence, ICW4 follows
    cmd2.write(0x11);
    data1.write(0x20); // ICW2: the first vector
    data2.write(0x28);
    data1.write(0x04); // ICW3: the second PIC is on line 2
    data2.write(0x02);
    data1.write(0x01); // ICW4: 8086 mode
    data2.write(0x01);
    data1.write(0xff); // mask all lines
    data2.write(0xff);
}

/// Measures the APIC timer against PIT channel 2, and gives the timer ticks in `CALIBRATE_MS`.
fn calibrate() -> u64 {
    // SAFETY: port 0x61 is the PIT gate and speaker control, and ports 0x42 and 0x43 are PIT
    // channel 2 and the PIT mode register. This module owns them, and the speaker stays off.
    let (gate, ch2, mode) = unsafe { (Port::new(0x61), Port::new(0x42), Port::new(0x43)) };
    let latch = (PIT_HZ * CALIBRATE_MS / 1000) as u16;
    // Gate on, speaker off.
    gate.write((gate.read() & !0x02) | 0x01);
    // Channel 2, low byte then high byte, mode 0, binary.
    mode.write(0xb0);
    ch2.write(latch as u8);
    write(REG_TIMER_DIVIDE, DIVIDE_BY_16);
    write(REG_LVT_TIMER, LVT_MASKED | u32::from(TIMER_VECTOR));
    ch2.write((latch >> 8) as u8);
    write(REG_TIMER_INIT, u32::MAX);
    // Bit 5 of port 0x61 is the output of channel 2. In mode 0 it goes high when the count is 0.
    while gate.read() & 0x20 == 0 {
        core::hint::spin_loop();
    }
    let elapsed = u32::MAX - read(REG_TIMER_CURRENT);
    write(REG_TIMER_INIT, 0);
    u64::from(elapsed)
}

/// Sets up the local APIC of the boot CPU and starts the timer. Interrupts stay off. The kernel
/// page tables must be in use, because the xAPIC registers need a mapping.
pub(crate) fn init() {
    disable_pic();
    let base = read_msr(IA32_APIC_BASE);
    if has_x2apic() {
        write_msr(IA32_APIC_BASE, base | APIC_BASE_ENABLE | APIC_BASE_X2APIC);
        X2APIC.store(true, Ordering::Relaxed);
    } else {
        write_msr(IA32_APIC_BASE, base | APIC_BASE_ENABLE);
        let virt = crate::mm::frame::vmap_mmio(base & APIC_BASE_ADDR)
            .unwrap_or_else(|| panic!("no mapping for the local APIC"));
        XAPIC_BASE.store(virt, Ordering::Relaxed);
    }
    write(REG_TPR, 0);
    write(REG_LVT_ERROR, u32::from(ERROR_VECTOR));
    write(REG_SVR, SVR_ENABLE | u32::from(SPURIOUS_VECTOR));

    let per_ms = (calibrate() / CALIBRATE_MS).max(1);
    TIMER_HZ.store(per_ms * 1000, Ordering::Relaxed);
    let period = (per_ms * 1000 / HZ).clamp(1, u64::from(u32::MAX)) as u32;
    write(REG_TIMER_DIVIDE, DIVIDE_BY_16);
    write(REG_LVT_TIMER, LVT_PERIODIC | u32::from(TIMER_VECTOR));
    write(REG_TIMER_INIT, period);
}

/// Handles an interrupt from the local APIC. Gives `false` for a vector that is not an APIC
/// vector.
pub(crate) fn handle(vector: u8) -> bool {
    match vector {
        TIMER_VECTOR => {
            TICKS.fetch_add(1, Ordering::Relaxed);
            crate::vdso::tick();
            eoi();
        }
        ERROR_VECTOR => {
            // A write to the error status register latches the errors, per the Intel SDM.
            write(0x280, 0);
            let esr = read(0x280);
            crate::console::_print_panic(format_args!("rk-frame: APIC error {esr:#x}\n"));
            eoi();
        }
        // A spurious interrupt has no EOI, per the Intel SDM.
        SPURIOUS_VECTOR => {}
        _ => return false,
    }
    true
}

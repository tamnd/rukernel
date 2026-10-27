//! The local APIC, the legacy PIC and the timer.
//!
//! The kernel uses the local APIC in x2APIC mode when the CPU has it, and in xAPIC mode if not.
//! The legacy 8259 PIC is moved to vectors 0x20 to 0x2f and masked, so it sends no interrupts.
//!
//! The timer of the local APIC runs in periodic mode at `HZ` interrupts each second. Its frequency
//! is not known, so the boot code measures it against channel 2 of the PIT, as Linux does. Each
//! CPU has a timer, so that user code on each CPU comes back to the kernel at the end of its time
//! slice. Only the timer of the boot CPU counts the ticks. The
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
const REG_ID: u32 = 0x20;
const REG_TPR: u32 = 0x80;
const REG_EOI: u32 = 0xb0;
const REG_SVR: u32 = 0xf0;
const REG_ICR_LOW: u32 = 0x300;
const REG_ICR_HIGH: u32 = 0x310;
const REG_LVT_TIMER: u32 = 0x320;
const REG_LVT_ERROR: u32 = 0x370;
const REG_TIMER_INIT: u32 = 0x380;
const REG_TIMER_CURRENT: u32 = 0x390;
const REG_TIMER_DIVIDE: u32 = 0x3e0;

const SVR_ENABLE: u32 = 1 << 8;
const LVT_MASKED: u32 = 1 << 16;
const LVT_PERIODIC: u32 = 1 << 17;
/// The delivery status bit of the ICR in xAPIC mode: the APIC did not send the last IPI yet.
const ICR_PENDING: u32 = 1 << 12;
/// Divide the bus clock by 16.
const DIVIDE_BY_16: u32 = 0b0011;

/// The frequency of the PIT input clock, in Hz.
const PIT_HZ: u64 = 1_193_182;
/// The time of the calibration, in milliseconds.
const CALIBRATE_MS: u64 = 10;
/// The measures of the calibration. The calibration keeps the shortest.
const CALIBRATE_TRIES: u32 = 8;

/// The local APIC is in x2APIC mode.
static X2APIC: AtomicBool = AtomicBool::new(false);
/// The virtual address of the xAPIC registers, in xAPIC mode.
static XAPIC_BASE: AtomicUsize = AtomicUsize::new(0);
/// The timer interrupts since boot.
pub(crate) static TICKS: AtomicU64 = AtomicU64::new(0);
/// The frequency of the APIC timer after the divider, in Hz.
pub(crate) static TIMER_HZ: AtomicU64 = AtomicU64::new(0);
/// The initial count of the timer for one tick.
static PERIOD: AtomicU64 = AtomicU64::new(0);
/// The frequency of the time stamp counter in Hz, or 0 before the calibration.
static TSC_HZ: AtomicU64 = AtomicU64::new(0);
/// The time stamp counter at the calibration, which is the time 0 of `nanos`.
static TSC_BASE: AtomicU64 = AtomicU64::new(0);
/// The nanoseconds of one cycle of the time stamp counter, times 2^32, or 0 before the
/// calibration.
static TSC_MULT: AtomicU64 = AtomicU64::new(0);
/// The time stamp counter at the last tick.
static TICK_TSC: AtomicU64 = AtomicU64::new(0);

/// Reads the time stamp counter.
fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: `rdtsc` writes only EAX and EDX.
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)) };
    (u64::from(hi) << 32) | u64::from(lo)
}

/// The nanoseconds since the calibration of the timer, from the time stamp counter. Before the
/// calibration it gives the time of the tick count.
pub(crate) fn nanos() -> u64 {
    let hz = TSC_HZ.load(Ordering::Relaxed);
    if hz == 0 {
        return TICKS.load(Ordering::Relaxed) * (1_000_000_000 / HZ);
    }
    let delta = rdtsc().saturating_sub(TSC_BASE.load(Ordering::Relaxed));
    (u128::from(delta) * 1_000_000_000 / u128::from(hz)) as u64
}

/// The nanoseconds of the clock since boot. The value is the time of the tick count, plus the time
/// of the time stamp counter since the last tick. The second part is always less than one tick,
/// so the clock does not go back at a tick, and a deadline in ticks comes at the time that the
/// clock shows. The vDSO calculates the same value from its data page.
pub(crate) fn clock_ns() -> u64 {
    loop {
        let ticks = TICKS.load(Ordering::Acquire);
        let base = TICK_TSC.load(Ordering::Acquire);
        let now = rdtsc();
        if TICKS.load(Ordering::Acquire) == ticks {
            return clock(ticks, now.saturating_sub(base), TSC_MULT.load(Ordering::Relaxed));
        }
    }
}

/// The clock value from the tick count, the cycles of the time stamp counter since the last tick
/// and `TSC_MULT`.
fn clock(ticks: u64, cycles: u64, mult: u64) -> u64 {
    let tick_ns = 1_000_000_000 / HZ;
    let part = ((u128::from(cycles) * u128::from(mult)) >> 32).min(u128::from(tick_ns - 1));
    ticks * tick_ns + part as u64
}

/// The ticks at a timer interrupt, and the new time stamp counter of the last tick. `last` is the
/// counter of the last tick, `now` is the counter now and `period` is the cycles of one tick, or 0
/// before the calibration.
///
/// The kernel runs with interrupts off, so the interrupt of a tick can wait, and the APIC keeps
/// only one interrupt of the timer. The ticks of that time are lost, and a kernel that is busy
/// sees a clock that is too slow and timeouts that do not come. Thus the tick count adds each
/// period that passed, as `tick_do_update_jiffies64` of Linux does. The counter of the last tick
/// moves by whole periods, but not past `now`, so a timer that is a little faster than the counter
/// does not move it into the future.
fn advance(last: u64, now: u64, period: u64) -> (u64, u64) {
    if period == 0 {
        return (1, now);
    }
    let ticks = (now.saturating_sub(last) / period).max(1);
    (ticks, last.saturating_add(ticks * period).min(now))
}

/// The time stamp counter at the last tick and `TSC_MULT`, for the data page of the vDSO.
pub(crate) fn tsc_state() -> (u64, u64) {
    (TICK_TSC.load(Ordering::Relaxed), TSC_MULT.load(Ordering::Relaxed))
}

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

/// Measures the APIC timer and the time stamp counter against PIT channel 2. Gives the timer
/// ticks in `CALIBRATE_MS`, and sets `TSC_HZ`.
///
/// A host that stops the virtual CPU during a measure makes the measure too long, and a time stamp
/// counter that seems too fast makes the clock and the tick count slow. Under QEMU without KVM on
/// a busy host, one measure gave 4.5 times the true frequency. Thus the calibration measures
/// `CALIBRATE_TRIES` times and keeps the measure with the fewest cycles, as
/// `pit_hpet_ptimer_calibrate_cpu` of Linux keeps the lowest of its tries.
fn calibrate() -> u64 {
    let (mut cycles, mut elapsed) = measure();
    for _ in 1..CALIBRATE_TRIES {
        let (c, e) = measure();
        if c < cycles {
            (cycles, elapsed) = (c, e);
        }
    }
    let now = rdtsc();
    let hz = (cycles * 1000 / CALIBRATE_MS).max(1);
    TSC_HZ.store(hz, Ordering::Relaxed);
    TSC_BASE.store(now, Ordering::Relaxed);
    TICK_TSC.store(now, Ordering::Relaxed);
    TSC_MULT.store(((1_000_000_000u128 << 32) / u128::from(hz)) as u64, Ordering::Relaxed);
    elapsed
}

/// Measures `CALIBRATE_MS` once against PIT channel 2. Gives the cycles of the time stamp counter
/// and the ticks of the APIC timer in that time.
fn measure() -> (u64, u64) {
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
    write(REG_TIMER_INIT, u32::MAX);
    let tsc = rdtsc();
    // The high byte starts the count. The APIC timer and the time stamp counter start first, so a
    // stop of the CPU at any point makes the measure longer and never shorter.
    ch2.write((latch >> 8) as u8);
    // Bit 5 of port 0x61 is the output of channel 2. In mode 0 it goes high when the count is 0.
    while gate.read() & 0x20 == 0 {
        core::hint::spin_loop();
    }
    let elapsed = u32::MAX - read(REG_TIMER_CURRENT);
    let now = rdtsc();
    write(REG_TIMER_INIT, 0);
    (now.saturating_sub(tsc), u64::from(elapsed))
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
    enable();
    let per_ms = (calibrate() / CALIBRATE_MS).max(1);
    TIMER_HZ.store(per_ms * 1000, Ordering::Relaxed);
    PERIOD.store((per_ms * 1000 / HZ).clamp(1, u64::from(u32::MAX)), Ordering::Relaxed);
    start_timer();
}

/// Sets up the local APIC of a CPU that is not the boot CPU, in the mode of the boot CPU, and
/// starts its timer. The xAPIC registers of each CPU are at the same address.
pub(crate) fn init_secondary() {
    let base = read_msr(IA32_APIC_BASE) | APIC_BASE_ENABLE;
    let mode = if X2APIC.load(Ordering::Relaxed) { APIC_BASE_X2APIC } else { 0 };
    write_msr(IA32_APIC_BASE, base | mode);
    enable();
    start_timer();
}

/// Lets the local APIC take interrupts of each priority and report errors.
fn enable() {
    write(REG_TPR, 0);
    write(REG_LVT_ERROR, u32::from(ERROR_VECTOR));
    write(REG_SVR, SVR_ENABLE | u32::from(SPURIOUS_VECTOR));
}

/// Starts the timer in periodic mode at `HZ` interrupts each second.
fn start_timer() {
    write(REG_TIMER_DIVIDE, DIVIDE_BY_16);
    write(REG_LVT_TIMER, LVT_PERIODIC | u32::from(TIMER_VECTOR));
    write(REG_TIMER_INIT, PERIOD.load(Ordering::Relaxed) as u32);
}

/// The local APIC ID of this CPU.
pub(crate) fn id() -> u32 {
    if X2APIC.load(Ordering::Relaxed) { read_msr(0x802) as u32 } else { read(REG_ID) >> 24 }
}

/// Sends an interrupt to the CPU with the local APIC ID `dest`. `command` is the low half of the
/// ICR: the vector, the delivery mode and the level.
pub(crate) fn send_ipi(dest: u32, command: u32) {
    if X2APIC.load(Ordering::Relaxed) {
        write_msr(0x800 + REG_ICR_LOW / 16, u64::from(dest) << 32 | u64::from(command));
    } else {
        write(REG_ICR_HIGH, dest << 24);
        write(REG_ICR_LOW, command);
        while read(REG_ICR_LOW) & ICR_PENDING != 0 {
            core::hint::spin_loop();
        }
    }
}

/// Handles an interrupt from the local APIC. Gives `false` for a vector that is not an APIC
/// vector.
pub(crate) fn handle(vector: u8) -> bool {
    match vector {
        TIMER_VECTOR => {
            if super::cpu::id() == 0 {
                let period = TSC_HZ.load(Ordering::Relaxed) / HZ;
                let (ticks, base) = advance(TICK_TSC.load(Ordering::Relaxed), rdtsc(), period);
                // `clock_ns` reads the tick count before and after the time stamp counter of the
                // tick, so the counter must change first.
                TICK_TSC.store(base, Ordering::Release);
                TICKS.fetch_add(ticks, Ordering::Release);
                crate::vdso::tick();
            }
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

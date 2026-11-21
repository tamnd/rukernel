//! The generic timer: the clock and the timer tick.
//!
//! The kernel uses the virtual timer of EL1, as Linux does in a guest. The virtual counter gives
//! the clock, and the timer interrupts `HZ` times each second. User code can read the virtual
//! counter, so the vDSO calculates the clock from it.

use crate::clocksource;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// The timer interrupts each second.
pub(crate) const HZ: u64 = 250;
const NS_PER_TICK: u64 = 1_000_000_000 / HZ;

/// The interrupt of the virtual timer. It is PPI 11 on QEMU virt, and the `timer` node of the
/// device tree can change it.
static INTID: AtomicU32 = AtomicU32::new(27);

/// Uses the interrupt `intid` for the timer, from the device tree.
pub(crate) fn set_intid(intid: u32) {
    INTID.store(intid, Ordering::Relaxed);
}

/// The interrupt of the virtual timer.
pub(crate) fn intid() -> u32 {
    INTID.load(Ordering::Relaxed)
}

/// The frequency of the counter in Hz.
pub(crate) static TIMER_HZ: AtomicU64 = AtomicU64::new(0);
/// The counter at boot, the time 0 of the clock.
static BOOT_COUNT: AtomicU64 = AtomicU64::new(0);
/// The multiplier of the counter, see `clocksource::mult`. The clock and the vDSO use it. It is 0
/// before `init`.
static COUNTER_MULT: AtomicU64 = AtomicU64::new(0);

fn counter() -> u64 {
    let value: u64;
    // SAFETY: the ISB orders the read after the code before it. Reading the counter has no side
    // effect.
    unsafe {
        core::arch::asm!("isb", "mrs {}, cntvct_el0", out(reg) value, options(nomem, nostack));
    }
    value
}

fn frequency() -> u64 {
    let value: u64;
    // SAFETY: reading CNTFRQ_EL0 has no side effect.
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) value, options(nomem, nostack)) };
    value
}

/// Sets the timer of this CPU to interrupt at the start of the next tick, at an absolute value of
/// the counter, as Linux arms a clockevent device in oneshot mode. A late interrupt thus does not
/// make the next tick late.
fn arm() {
    let mult = COUNTER_MULT.load(Ordering::Relaxed);
    let boot = BOOT_COUNT.load(Ordering::Relaxed);
    let next = clocksource::next_tick(counter().wrapping_sub(boot), mult, NS_PER_TICK);
    // SAFETY: the timer registers of EL1 change only the timer. The control value 1 turns the
    // timer on with its interrupt not masked.
    unsafe {
        core::arch::asm!(
            "msr cntv_cval_el0, {cval}",
            "msr cntv_ctl_el0, {ctl}",
            "isb",
            cval = in(reg) boot.wrapping_add(next),
            ctl = in(reg) 1u64,
            options(nomem, nostack),
        );
    }
}

/// Starts the tick. The boot CPU calls this one time, after `gic::init`.
pub(crate) fn init() {
    let freq = frequency();
    TIMER_HZ.store(freq, Ordering::Relaxed);
    BOOT_COUNT.store(counter(), Ordering::Relaxed);
    COUNTER_MULT.store(clocksource::mult(freq), Ordering::Release);
    init_cpu();
}

/// The bit of CNTKCTL_EL1 that lets user code read the virtual counter.
const CNTKCTL_EL0VCTEN: u64 = 1 << 1;

/// Starts the timer of this CPU. Each CPU has its own timer and its own PPI. User code on the CPU
/// can read the virtual counter, for the vDSO, as on Linux.
pub(crate) fn init_cpu() {
    // SAFETY: CNTKCTL_EL1 controls only the access of EL0 to the timer. The value lets EL0 read
    // the virtual counter and nothing more.
    unsafe {
        core::arch::asm!("msr cntkctl_el1, {}", "isb", in(reg) CNTKCTL_EL0VCTEN, options(nomem, nostack));
    }
    let freq = TIMER_HZ.load(Ordering::Relaxed);
    if freq == 0 {
        return;
    }
    super::gic::enable(intid());
    arm();
}

/// Handles the timer interrupt. Each CPU gets one and arms its timer for the next tick. The clock
/// and the tick count come from the counter, so the interrupt does not change them.
pub(crate) fn tick() {
    arm();
}

/// The nanoseconds since boot, from the counter. This is the clocksource of Linux: the counter
/// since boot times `COUNTER_MULT`, shifted right. The value does not depend on the timer
/// interrupts, so a late tick does not make the clock slow. The vDSO calculates the same value
/// from its data page. It is 0 before `init`.
pub(crate) fn clock_ns() -> u64 {
    let mult = COUNTER_MULT.load(Ordering::Acquire);
    clocksource::cycles_to_ns(counter().saturating_sub(BOOT_COUNT.load(Ordering::Relaxed)), mult)
}

/// The nanoseconds since boot, for the scheduler. It is the same as `clock_ns`.
pub(crate) fn nanos() -> u64 {
    clock_ns()
}

/// The timer ticks since boot, the `jiffies` value of Linux, from the clock. A tick that comes
/// late is not lost, and a deadline in ticks is not before the time on the clock.
pub(crate) fn ticks() -> u64 {
    clock_ns() / NS_PER_TICK
}

/// The clock state for the data page of the vDSO: the nanoseconds at the base, the counter at the
/// base, `COUNTER_MULT` and the most nanoseconds that the counter adds to the base. The base is
/// boot, and the counter part has no limit.
pub(crate) fn counter_state() -> (u64, u64, u64, u64) {
    (0, BOOT_COUNT.load(Ordering::Relaxed), COUNTER_MULT.load(Ordering::Relaxed), u64::MAX)
}

//! The generic timer: the clock and the timer tick.
//!
//! The kernel uses the virtual timer of EL1, as Linux does in a guest. The virtual counter gives
//! the clock, and the timer interrupts `HZ` times each second.

use core::sync::atomic::{AtomicU64, Ordering};

/// The timer interrupts each second.
pub(crate) const HZ: u64 = 250;
const NS_PER_TICK: u64 = 1_000_000_000 / HZ;

/// The interrupt of the virtual timer: PPI 11.
// TODO: read it from the `timer` node of the device tree.
pub(crate) const INTID: u32 = 27;

/// The timer interrupts since boot.
pub(crate) static TICKS: AtomicU64 = AtomicU64::new(0);
/// The frequency of the counter in Hz.
pub(crate) static TIMER_HZ: AtomicU64 = AtomicU64::new(0);
/// The counter at the last tick.
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
/// The counter at boot.
static BOOT_COUNT: AtomicU64 = AtomicU64::new(0);

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

/// Sets the timer to interrupt after one tick.
fn arm(freq: u64) {
    // SAFETY: the timer registers of EL1 change only the timer. The control value 1 turns the
    // timer on with its interrupt not masked.
    unsafe {
        core::arch::asm!(
            "msr cntv_tval_el0, {tval}",
            "msr cntv_ctl_el0, {ctl}",
            "isb",
            tval = in(reg) freq / HZ,
            ctl = in(reg) 1u64,
            options(nomem, nostack),
        );
    }
}

/// Starts the tick. The boot CPU calls this one time, after `gic::init`.
pub(crate) fn init() {
    let freq = frequency();
    TIMER_HZ.store(freq, Ordering::Relaxed);
    let now = counter();
    BOOT_COUNT.store(now, Ordering::Relaxed);
    TICK_COUNT.store(now, Ordering::Relaxed);
    if freq == 0 {
        return;
    }
    super::gic::enable(INTID);
    arm(freq);
}

/// Handles the timer interrupt.
pub(crate) fn tick() {
    TICK_COUNT.store(counter(), Ordering::Release);
    TICKS.fetch_add(1, Ordering::Release);
    arm(TIMER_HZ.load(Ordering::Relaxed));
}

fn to_ns(count: u64, freq: u64) -> u64 {
    (u128::from(count) * 1_000_000_000 / u128::from(freq)) as u64
}

/// The nanoseconds since boot, from the counter.
pub(crate) fn nanos() -> u64 {
    let freq = TIMER_HZ.load(Ordering::Relaxed);
    if freq == 0 {
        return TICKS.load(Ordering::Relaxed) * NS_PER_TICK;
    }
    to_ns(counter().saturating_sub(BOOT_COUNT.load(Ordering::Relaxed)), freq)
}

/// The nanoseconds of the clock since boot. The value is in the same tick as the tick count, so a
/// deadline in ticks is not before the time on the clock.
pub(crate) fn clock_ns() -> u64 {
    let freq = TIMER_HZ.load(Ordering::Relaxed);
    loop {
        let ticks = TICKS.load(Ordering::Acquire);
        let base = TICK_COUNT.load(Ordering::Acquire);
        let now = counter();
        if TICKS.load(Ordering::Acquire) == ticks {
            let part = if freq == 0 { 0 } else { to_ns(now.saturating_sub(base), freq) };
            return ticks * NS_PER_TICK + part.min(NS_PER_TICK - 1);
        }
    }
}

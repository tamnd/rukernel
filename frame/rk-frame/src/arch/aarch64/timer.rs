//! The generic timer: the clock and the timer tick.
//!
//! The kernel uses the virtual timer of EL1, as Linux does in a guest. The virtual counter gives
//! the clock, and the timer interrupts `HZ` times each second. User code can read the virtual
//! counter, so the vDSO calculates the clock from it.

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

/// The timer interrupts since boot.
pub(crate) static TICKS: AtomicU64 = AtomicU64::new(0);
/// The frequency of the counter in Hz.
pub(crate) static TIMER_HZ: AtomicU64 = AtomicU64::new(0);
/// The counter at the last tick.
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
/// The counter at boot.
static BOOT_COUNT: AtomicU64 = AtomicU64::new(0);
/// The nanoseconds of one cycle of the counter, times 2^32. The clock and the vDSO use it.
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
    if freq != 0 {
        COUNTER_MULT
            .store(((1_000_000_000u128 << 32) / u128::from(freq)) as u64, Ordering::Relaxed);
    }
    let now = counter();
    BOOT_COUNT.store(now, Ordering::Relaxed);
    TICK_COUNT.store(now, Ordering::Relaxed);
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
    arm(freq);
}

/// Handles the timer interrupt. Each CPU gets one, and the boot CPU counts the ticks.
pub(crate) fn tick() {
    if super::cpu::id() == 0 {
        // `clock_ns` reads the tick count before and after the counter of the tick, so the counter
        // must change first.
        TICK_COUNT.store(counter(), Ordering::Release);
        TICKS.fetch_add(1, Ordering::Release);
        crate::vdso::tick();
    }
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
/// deadline in ticks is not before the time on the clock. The vDSO calculates the same value from
/// its data page.
pub(crate) fn clock_ns() -> u64 {
    let mult = COUNTER_MULT.load(Ordering::Relaxed);
    loop {
        let ticks = TICKS.load(Ordering::Acquire);
        let base = TICK_COUNT.load(Ordering::Acquire);
        let now = counter();
        if TICKS.load(Ordering::Acquire) == ticks {
            let cycles = u128::from(now.saturating_sub(base));
            let part = ((cycles * u128::from(mult)) >> 32).min(u128::from(NS_PER_TICK - 1));
            return ticks * NS_PER_TICK + part as u64;
        }
    }
}

/// The counter at the last tick and `COUNTER_MULT`, for the data page of the vDSO.
pub(crate) fn counter_state() -> (u64, u64) {
    (TICK_COUNT.load(Ordering::Relaxed), COUNTER_MULT.load(Ordering::Relaxed))
}

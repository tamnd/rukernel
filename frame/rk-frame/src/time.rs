//! The timer tick.
//!
//! The timer interrupts `HZ` times each second on the boot CPU. The tick count is the `jiffies`
//! value of Linux, but it starts at 0.

use crate::arch::imp;
use crate::sync::Once;
use core::sync::atomic::{AtomicU64, Ordering};

/// The timer interrupts each second.
pub const HZ: u64 = imp::timer::HZ;

/// The timer interrupts since boot.
pub fn ticks() -> u64 {
    imp::timer::TICKS.load(Ordering::Relaxed)
}

/// The nanoseconds since boot. On x86-64 the time stamp counter gives them, so they change
/// between two ticks. The scheduler measures the run time of a task with them.
pub fn nanos() -> u64 {
    imp::timer::nanos()
}

/// The nanoseconds of the clock since boot. The value changes between two ticks, but it is in the
/// same tick as `ticks`, so a deadline in ticks is not before the time on the clock. The clocks of
/// the system calls and of the vDSO use it.
pub fn clock_ns() -> u64 {
    imp::timer::clock_ns()
}

/// The difference between `CLOCK_REALTIME` and the clock since boot, in nanoseconds. The value
/// wraps, because a clock set can move the real time to before the time since boot.
static OFFSET: AtomicU64 = AtomicU64::new(0);

/// The nanoseconds of `CLOCK_REALTIME` at boot, as a wrapping offset to `clock_ns`. The first call
/// reads the real time clock. The time is 0, the epoch, if the machine has no real time clock or
/// the clock is not valid. `set_realtime_ns` changes the value.
pub fn realtime_offset_ns() -> u64 {
    static INIT: Once<()> = Once::new();
    INIT.call_once(|| {
        let offset = imp::rtc::read()
            .map_or(0, |sec| sec.saturating_mul(1_000_000_000).saturating_sub(clock_ns()));
        OFFSET.store(offset, Ordering::Relaxed);
    });
    OFFSET.load(Ordering::Relaxed)
}

/// The nanoseconds of `CLOCK_REALTIME`: the clock since boot plus the time at boot.
pub fn realtime_ns() -> u64 {
    clock_ns().wrapping_add(realtime_offset_ns())
}

/// Sets `CLOCK_REALTIME` to `ns` nanoseconds after the epoch. The clock since boot does not change.
/// The vDSO shows the new time immediately. Gives the change of the offset, as a wrapping value.
pub fn set_realtime_ns(ns: u64) -> u64 {
    let old = realtime_offset_ns();
    let offset = ns.wrapping_sub(clock_ns());
    OFFSET.store(offset, Ordering::Relaxed);
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    crate::vdso::set_realtime_offset(offset);
    offset.wrapping_sub(old)
}

/// The frequency of the timer hardware in Hz, as the boot code measured it. It is 0 if there is no
/// timer.
pub fn timer_frequency() -> u64 {
    imp::timer::TIMER_HZ.load(Ordering::Relaxed)
}

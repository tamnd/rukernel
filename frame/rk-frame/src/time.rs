//! The timer tick.
//!
//! The timer interrupts `HZ` times each second on the boot CPU. The tick count is the `jiffies`
//! value of Linux, but it starts at 0.

use crate::arch::imp;
use crate::sync::Once;
use core::sync::atomic::Ordering;

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

/// The nanoseconds of `CLOCK_REALTIME` at boot. The first call reads the real time clock. The
/// time is 0, the epoch, if the machine has no real time clock or the clock is not valid.
pub fn realtime_offset_ns() -> u64 {
    static OFFSET: Once<u64> = Once::new();
    *OFFSET.call_once(|| {
        imp::rtc::read()
            .map_or(0, |sec| sec.saturating_mul(1_000_000_000).saturating_sub(clock_ns()))
    })
}

/// The nanoseconds of `CLOCK_REALTIME`: the clock since boot plus the time at boot.
pub fn realtime_ns() -> u64 {
    clock_ns().saturating_add(realtime_offset_ns())
}

/// The frequency of the timer hardware in Hz, as the boot code measured it. It is 0 if there is no
/// timer.
pub fn timer_frequency() -> u64 {
    imp::timer::TIMER_HZ.load(Ordering::Relaxed)
}

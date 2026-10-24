//! The timer tick.
//!
//! The timer interrupts `HZ` times each second on the boot CPU. The tick count is the `jiffies`
//! value of Linux, but it starts at 0.

use crate::arch::imp;
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

/// The frequency of the timer hardware in Hz, as the boot code measured it. It is 0 if there is no
/// timer.
pub fn timer_frequency() -> u64 {
    imp::timer::TIMER_HZ.load(Ordering::Relaxed)
}

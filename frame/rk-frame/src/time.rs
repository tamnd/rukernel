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

/// The frequency of the timer hardware in Hz, as the boot code measured it. It is 0 if there is no
/// timer.
pub fn timer_frequency() -> u64 {
    imp::timer::TIMER_HZ.load(Ordering::Relaxed)
}

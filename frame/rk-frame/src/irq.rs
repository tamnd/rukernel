//! Interrupt control on the current CPU.

use crate::arch::imp;

/// Lets this CPU take interrupts.
pub fn enable() {
    imp::irq::enable();
}

/// Stops this CPU from taking interrupts.
pub fn disable() {
    imp::irq::disable();
}

/// Tells if this CPU takes interrupts.
pub fn enabled() -> bool {
    imp::irq::enabled()
}

/// Lets this CPU take interrupts and waits for the next one. Interrupts stay on after the wait.
pub fn wait() {
    imp::irq::wait();
}

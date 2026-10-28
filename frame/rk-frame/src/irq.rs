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

/// The interrupt line of a device: an SPI of the GIC on arm64. The handler of the line turns the
/// line off and keeps a flag that the line came, because a handler takes no lock and cannot reach
/// the device. The driver tests the flag with `take`, tells the device that the interrupt is
/// handled, and turns the line on again with `unmask`. Between the two, a level triggered line
/// does not come again and again. x86-64 has no lines yet, so its drivers poll.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line {
    intid: u32,
}

impl Line {
    /// Makes the line of the interrupt number `intid`, and turns it on. The line goes to the boot
    /// CPU until a `wait` on another CPU. Gives `None` if the number is not a device interrupt.
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn new(intid: u32, edge: bool) -> Option<Self> {
        imp::gic::enable_device(intid, edge).then_some(Self { intid })
    }

    /// The interrupt number.
    pub fn number(self) -> u32 {
        self.intid
    }

    /// Tells if the line came since the last `take`, and clears the flag. The line stays off
    /// until `unmask`.
    pub fn take(self) -> bool {
        #[cfg(target_arch = "aarch64")]
        return imp::gic::take_device(self.intid);
        #[cfg(not(target_arch = "aarch64"))]
        false
    }

    /// Turns the line on again, after the driver told the device that the interrupt is handled.
    pub fn unmask(self) {
        #[cfg(target_arch = "aarch64")]
        imp::gic::unmask_device(self.intid);
    }

    /// Waits on this CPU until the line comes, or until another interrupt comes. The line goes to
    /// this CPU first. If the line came already and is off, or if this CPU does not take
    /// interrupts, the call does not wait. The caller tests its condition and calls this in a
    /// loop, and calls `take` and `unmask` when the line came.
    pub fn wait(self) {
        #[cfg(target_arch = "aarch64")]
        {
            if !enabled() {
                core::hint::spin_loop();
                return;
            }
            imp::gic::route_here(self.intid);
            disable();
            // With interrupts off, the line cannot come between the test and `wait`. A line that
            // is pending wakes `wait`, and `wait` turns interrupts on, so the handler runs.
            if imp::gic::fired(self.intid) {
                enable();
            } else {
                wait();
            }
        }
        #[cfg(not(target_arch = "aarch64"))]
        core::hint::spin_loop();
    }
}

//! Interrupt control on the current CPU.

use crate::arch::imp;
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
use alloc::vec::Vec;

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

/// The interrupt line of a device: an SPI of the GIC or the LPI of an MSI-X table entry on arm64,
/// and the vector of an MSI-X table entry on x86-64. The handler of the line turns the line off
/// and keeps a flag that the line came, because a handler takes no lock and cannot reach the
/// device. The driver tests the flag with `take`, tells the device that the interrupt is handled,
/// and turns the line on again with `unmask`. Between the two, a level triggered line does not come again and again.
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

    /// Makes a line for each MSI-X table entry at the virtual addresses `entries` of the function
    /// with the device ID `device` of the GICv3 ITS, each with a free LPI, and turns them on. The
    /// event ID of each entry is its index in `entries`. The lines go to the boot CPU until a
    /// `wait` on another CPU. Gives `None` if the machine has no ITS, or if not enough LPIs are
    /// free.
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn msix(entries: &[usize], device: u32) -> Option<Vec<Self>> {
        let mut lpis = alloc::vec![0; entries.len()];
        imp::its::alloc(entries, device, &mut lpis)
            .then(|| lpis.into_iter().map(|intid| Self { intid }).collect())
    }

    /// Gives back the lines `lines` of the function with the device ID `device`, which one
    /// `msix` gave.
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn free_msix(lines: &[Self], device: u32) {
        let lpis: Vec<u32> = lines.iter().map(|l| l.intid).collect();
        imp::its::free(&lpis, device);
    }

    /// Makes a line for each MSI-X table entry at the virtual addresses `entries`, each with a
    /// free vector, and turns them on. The lines go to the boot CPU until a `wait` on another
    /// CPU. Gives `None` if not enough vectors are free.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn msix(entries: &[usize]) -> Option<Vec<Self>> {
        let mut vectors = alloc::vec![0; entries.len()];
        imp::msi::alloc(entries, &mut vectors)
            .then(|| vectors.into_iter().map(|v| Self { intid: u32::from(v) }).collect())
    }

    /// Gives back the lines `lines`, which one `msix` gave.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn free_msix(lines: &[Self]) {
        let vectors: Vec<u8> = lines.iter().map(|l| l.intid as u8).collect();
        imp::msi::free(&vectors);
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
        #[cfg(target_arch = "x86_64")]
        return imp::msi::take(self.intid as u8);
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        false
    }

    /// Turns the line on again, after the driver told the device that the interrupt is handled.
    pub fn unmask(self) {
        #[cfg(target_arch = "aarch64")]
        imp::gic::unmask_device(self.intid);
        #[cfg(target_arch = "x86_64")]
        imp::msi::unmask(self.intid as u8);
    }

    /// Waits on this CPU until the line comes, or until another interrupt comes. The line goes to
    /// this CPU first. If the line came already and is off, or if this CPU does not take
    /// interrupts, the call does not wait. The caller tests its condition and calls this in a
    /// loop, and calls `take` and `unmask` when the line came.
    pub fn wait(self) {
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        {
            if !enabled() {
                crate::sync::wait_hint();
                return;
            }
            #[cfg(target_arch = "aarch64")]
            let fired = || imp::gic::fired(self.intid);
            #[cfg(target_arch = "x86_64")]
            let fired = || imp::msi::fired(self.intid as u8);
            #[cfg(target_arch = "aarch64")]
            imp::gic::route_here(self.intid);
            #[cfg(target_arch = "x86_64")]
            imp::msi::route_here(self.intid as u8);
            disable();
            // With interrupts off, the line cannot come between the test and `wait`. A line that
            // is pending wakes `wait`, and `wait` turns interrupts on, so the handler runs.
            if fired() {
                enable();
            } else {
                wait();
            }
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        core::hint::spin_loop();
    }
}

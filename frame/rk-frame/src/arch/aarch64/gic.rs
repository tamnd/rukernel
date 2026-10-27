//! The GICv2 interrupt controller.
//!
//! The kernel uses the distributor and the CPU interface of the boot CPU. Only the timer
//! interrupt is on now. GICv3 and the interrupts of the devices come later.

use super::paging::MMIO_BASE;

/// The distributor and the CPU interface of QEMU virt, in the device window of the boot page
/// tables.
// TODO: read the addresses and the version from the `interrupt-controller` node.
const GICD: usize = MMIO_BASE + 0x0800_0000;
const GICC: usize = MMIO_BASE + 0x0801_0000;

const GICD_CTLR: usize = 0x000;
const GICD_ISENABLER: usize = 0x100;
const GICD_IPRIORITYR: usize = 0x400;
const GICC_CTLR: usize = 0x000;
const GICC_PMR: usize = 0x004;
const GICC_IAR: usize = 0x00c;
const GICC_EOIR: usize = 0x010;

/// The interrupt numbers 1020 to 1023 are special. 1023 tells that no interrupt is pending.
pub(crate) const SPURIOUS: u32 = 1020;

/// The priority of each interrupt that the kernel enables. A lower value is a higher priority.
const PRIORITY: u8 = 0xa0;

fn read(addr: usize) -> u32 {
    // SAFETY: the boot page tables map the GIC registers as device memory, and rk-frame owns the
    // GIC. The registers have no effect on memory.
    unsafe { (addr as *const u32).read_volatile() }
}

fn write(addr: usize, value: u32) {
    // SAFETY: as for `read`.
    unsafe { (addr as *mut u32).write_volatile(value) };
}

/// Turns on the distributor and the CPU interface of the boot CPU.
pub(crate) fn init() {
    write(GICD + GICD_CTLR, 1);
    // All priorities below the mask go to the CPU.
    write(GICC + GICC_PMR, 0xf0);
    write(GICC + GICC_CTLR, 1);
}

/// Lets the interrupt `intid` come to the CPU.
pub(crate) fn enable(intid: u32) {
    let intid = intid as usize;
    // SAFETY: as for `read`. The priority registers allow byte accesses.
    unsafe { ((GICD + GICD_IPRIORITYR + intid) as *mut u8).write_volatile(PRIORITY) };
    write(GICD + GICD_ISENABLER + intid / 32 * 4, 1 << (intid % 32));
}

/// Takes the pending interrupt with the highest priority. Gives the value for `eoi`. Its low 10
/// bits are the interrupt number.
pub(crate) fn ack() -> u32 {
    read(GICC + GICC_IAR)
}

/// Tells the GIC that the handler of an interrupt from `ack` is done.
pub(crate) fn eoi(iar: u32) {
    write(GICC + GICC_EOIR, iar);
}

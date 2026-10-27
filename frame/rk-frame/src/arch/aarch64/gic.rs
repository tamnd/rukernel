//! The GICv2 interrupt controller.
//!
//! The boot CPU turns on the distributor, and each CPU turns on its own CPU interface. The timer
//! interrupt and the SGIs between CPUs are on now. GICv3 and the interrupts of the devices come
//! later.

use super::paging::MMIO_BASE;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

/// The virtual addresses of the distributor and of the CPU interface. They start as the GIC of
/// QEMU virt, in the device window of the boot page tables. The device tree can change them.
static GICD_BASE: AtomicUsize = AtomicUsize::new(MMIO_BASE + 0x0800_0000);
static GICC_BASE: AtomicUsize = AtomicUsize::new(MMIO_BASE + 0x0801_0000);

/// Uses the distributor and the CPU interface at these virtual addresses, from the device tree.
pub(crate) fn set_base(gicd: usize, gicc: usize) {
    GICD_BASE.store(gicd, Ordering::Relaxed);
    GICC_BASE.store(gicc, Ordering::Relaxed);
}

fn gicd() -> usize {
    GICD_BASE.load(Ordering::Relaxed)
}

fn gicc() -> usize {
    GICC_BASE.load(Ordering::Relaxed)
}

const GICD_CTLR: usize = 0x000;
const GICD_ISENABLER: usize = 0x100;
const GICD_IPRIORITYR: usize = 0x400;
const GICD_ITARGETSR: usize = 0x800;
const GICD_SGIR: usize = 0xf00;
const GICC_CTLR: usize = 0x000;
const GICC_PMR: usize = 0x004;
const GICC_IAR: usize = 0x00c;
const GICC_EOIR: usize = 0x010;

/// The interrupt numbers 1020 to 1023 are special. 1023 tells that no interrupt is pending.
pub(crate) const SPURIOUS: u32 = 1020;

/// The priority of each interrupt that the kernel enables. A lower value is a higher priority.
const PRIORITY: u8 = 0xa0;

fn read(addr: usize) -> u32 {
    // SAFETY: the page tables map the GIC registers as device memory, and rk-frame owns the
    // GIC. The registers have no effect on memory.
    unsafe { (addr as *const u32).read_volatile() }
}

fn write(addr: usize, value: u32) {
    // SAFETY: as for `read`.
    unsafe { (addr as *mut u32).write_volatile(value) };
}

/// The most CPUs that a GICv2 has.
pub(crate) const MAX_CPUS: usize = 8;

/// The bit of the CPU interface of each CPU, for the target list of an SGI.
static TARGETS: [AtomicU8; MAX_CPUS] = [const { AtomicU8::new(0) }; MAX_CPUS];

/// Turns on the distributor and the CPU interface of the boot CPU.
pub(crate) fn init() {
    write(gicd() + GICD_CTLR, 1);
    init_cpu();
}

/// Turns on the CPU interface of this CPU and the SGIs between CPUs. The registers of the SGIs and
/// the PPIs are banked, so each CPU does this.
pub(crate) fn init_cpu() {
    // The first target register is banked. Each of its bytes gives the bit of this CPU.
    let target = read(gicd() + GICD_ITARGETSR) as u8;
    if let Some(slot) = TARGETS.get(super::cpu::id()) {
        slot.store(target, Ordering::Relaxed);
    }
    enable(super::smp::SGI_CALL);
    enable(super::smp::SGI_RESCHEDULE);
    // All priorities below the mask go to the CPU.
    write(gicc() + GICC_PMR, 0xf0);
    write(gicc() + GICC_CTLR, 1);
}

/// Sends the SGI `sgi` to the CPU `id`.
pub(crate) fn send_sgi(id: usize, sgi: u32) {
    let target = TARGETS.get(id).map_or(0, |t| t.load(Ordering::Relaxed));
    // The stores to memory before the SGI must be visible to the CPU that takes it.
    // SAFETY: the barrier changes no memory.
    unsafe { core::arch::asm!("dsb ishst", options(nostack, preserves_flags)) };
    write(gicd() + GICD_SGIR, u32::from(target) << 16 | sgi);
}

/// Lets the interrupt `intid` come to the CPU.
pub(crate) fn enable(intid: u32) {
    let intid = intid as usize;
    // SAFETY: as for `read`. The priority registers allow byte accesses.
    unsafe { ((gicd() + GICD_IPRIORITYR + intid) as *mut u8).write_volatile(PRIORITY) };
    write(gicd() + GICD_ISENABLER + intid / 32 * 4, 1 << (intid % 32));
}

/// Takes the pending interrupt with the highest priority. Gives the value for `eoi`. Its low 10
/// bits are the interrupt number.
pub(crate) fn ack() -> u32 {
    read(gicc() + GICC_IAR)
}

/// Tells the GIC that the handler of an interrupt from `ack` is done.
pub(crate) fn eoi(iar: u32) {
    write(gicc() + GICC_EOIR, iar);
}

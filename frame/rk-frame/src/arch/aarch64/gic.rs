//! The GICv2 and GICv3 interrupt controllers.
//!
//! The boot CPU turns on the distributor, and each CPU turns on its own CPU interface. The timer
//! interrupt and the SGIs between CPUs are on. A driver turns on the SPI of its device through
//! `irq::Line`. The handler of a device SPI turns the SPI off and keeps a flag, and the driver
//! turns the SPI on again after it told the device that the interrupt is handled.
//!
//! A GICv2 has a memory mapped CPU interface. A GICv3 has a redistributor for each CPU, in a
//! region of memory, and a CPU interface of system registers, as drivers/irqchip/irq-gic-v3.c of
//! Linux. The device tree tells which GIC the machine has. Without a device tree, the kernel uses
//! the GICv2 of QEMU `virt`. The LPIs of a GICv3 come from its ITS, which its.rs drives.

use super::paging::MMIO_BASE;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// The virtual addresses of the distributor and of the GICv2 CPU interface. They start as the GIC
/// of QEMU virt, in the device window of the boot page tables. The device tree can change them.
static GICD_BASE: AtomicUsize = AtomicUsize::new(MMIO_BASE + 0x0800_0000);
static GICC_BASE: AtomicUsize = AtomicUsize::new(MMIO_BASE + 0x0801_0000);

/// The GIC is a GICv3. Then `GICR_BASE` and `GICR_LEN` give the redistributor region, and
/// `GICR_PHYS` its physical address.
static V3: AtomicBool = AtomicBool::new(false);
static GICR_BASE: AtomicUsize = AtomicUsize::new(0);
static GICR_LEN: AtomicUsize = AtomicUsize::new(0);
static GICR_PHYS: AtomicU64 = AtomicU64::new(0);

/// Uses the GICv2 distributor and CPU interface at these virtual addresses, from the device tree.
pub(crate) fn set_base(gicd: usize, gicc: usize) {
    GICD_BASE.store(gicd, Ordering::Relaxed);
    GICC_BASE.store(gicc, Ordering::Relaxed);
}

/// Uses the GICv3 distributor and the redistributor region of `len` bytes at these virtual
/// addresses, from the device tree. `gicr_phys` is the physical address of the region.
pub(crate) fn set_base_v3(gicd: usize, gicr: usize, len: usize, gicr_phys: u64) {
    GICD_BASE.store(gicd, Ordering::Relaxed);
    GICR_BASE.store(gicr, Ordering::Relaxed);
    GICR_PHYS.store(gicr_phys, Ordering::Relaxed);
    GICR_LEN.store(len, Ordering::Relaxed);
    V3.store(true, Ordering::Relaxed);
}

fn gicd() -> usize {
    GICD_BASE.load(Ordering::Relaxed)
}

fn gicc() -> usize {
    GICC_BASE.load(Ordering::Relaxed)
}

pub(crate) fn v3() -> bool {
    V3.load(Ordering::Relaxed)
}

const GICD_CTLR: usize = 0x000;
const GICD_TYPER: usize = 0x004;
const GICD_IGROUPR: usize = 0x080;
const GICD_ISENABLER: usize = 0x100;
const GICD_ICENABLER: usize = 0x180;
const GICD_IPRIORITYR: usize = 0x400;
const GICD_ITARGETSR: usize = 0x800;
const GICD_ICFGR: usize = 0xc00;
const GICD_SGIR: usize = 0xf00;
const GICD_IROUTER: usize = 0x6000;
const GICC_CTLR: usize = 0x000;
const GICC_PMR: usize = 0x004;
const GICC_IAR: usize = 0x00c;
const GICC_EOIR: usize = 0x010;

/// The bits of `GICD_CTLR` of a GICv3 with one security state: group 1 on, affinity routing on,
/// and the write in progress.
const GICD_CTLR_ENABLE_G1A: u32 = 1 << 1;
const GICD_CTLR_ARE_NS: u32 = 1 << 4;
const GICD_CTLR_RWP: u32 = 1 << 31;

/// The registers of a GICv3 redistributor. Each redistributor has two 64 KiB frames: the frame
/// of the controls, then the frame of the SGIs and the PPIs.
const GICR_TYPER: usize = 0x0008;
const GICR_WAKER: usize = 0x0014;
const GICR_SGI: usize = 0x1_0000;
const GICR_FRAME: usize = 0x2_0000;
/// The bit of `GICR_TYPER` on the last redistributor of the region, and the bit that tells that
/// the redistributor also has the two frames of the virtual LPIs.
const GICR_TYPER_LAST: u64 = 1 << 4;
const GICR_TYPER_VLPIS: u64 = 1 << 1;
const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

/// The interrupt numbers 1020 to 1023 are special. 1023 tells that no interrupt is pending.
pub(crate) const SPURIOUS: u32 = 1020;

/// The priority of each interrupt that the kernel enables. A lower value is a higher priority.
pub(crate) const PRIORITY: u8 = 0xa0;

/// The priority mask of each CPU. All priorities below the mask go to the CPU.
const PRIORITY_MASK: u64 = 0xf0;

pub(crate) fn read(addr: usize) -> u32 {
    // SAFETY: the page tables map the GIC registers as device memory, and rk-frame owns the
    // GIC. The registers have no effect on memory.
    unsafe { (addr as *const u32).read_volatile() }
}

pub(crate) fn read64(addr: usize) -> u64 {
    // SAFETY: as for `read`.
    unsafe { (addr as *const u64).read_volatile() }
}

pub(crate) fn write(addr: usize, value: u32) {
    // SAFETY: as for `read`.
    unsafe { (addr as *mut u32).write_volatile(value) };
}

pub(crate) fn write64(addr: usize, value: u64) {
    // SAFETY: as for `read`.
    unsafe { (addr as *mut u64).write_volatile(value) };
}

fn write_u8(addr: usize, value: u8) {
    // SAFETY: as for `read`. The priority registers allow byte accesses.
    unsafe { (addr as *mut u8).write_volatile(value) };
}

/// The most CPUs that a GICv2 has.
const MAX_CPUS_V2: usize = 8;

/// The most CPUs that the GIC can send SGIs to.
pub(crate) fn max_cpus() -> usize {
    if v3() { super::cpu::MAX_CPUS } else { MAX_CPUS_V2 }
}

/// The target of an SGI to each CPU. On a GICv2 it is the bit of the CPU interface of the CPU. On
/// a GICv3 it is the MPIDR affinity of the CPU.
static TARGETS: [AtomicU64; super::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; super::cpu::MAX_CPUS];

/// The virtual address of the redistributor of each CPU of a GICv3.
static REDISTRIBUTORS: [AtomicUsize; super::cpu::MAX_CPUS] =
    [const { AtomicUsize::new(0) }; super::cpu::MAX_CPUS];

/// Writes the system register of the GICv3 CPU interface with the encoding `$reg`.
macro_rules! msr {
    ($reg:literal, $value:expr) => {
        // SAFETY: the GICv3 CPU interface registers change only the interrupts of this CPU. The
        // `isb` makes the change take effect before the next instruction.
        unsafe {
            core::arch::asm!(
                concat!("msr ", $reg, ", {}"),
                "isb",
                in(reg) $value,
                options(nostack, preserves_flags)
            )
        }
    };
}

/// Reads the system register of the GICv3 CPU interface with the encoding `$reg`.
macro_rules! mrs {
    ($reg:literal) => {{
        let value: u64;
        // SAFETY: as for `msr!`. A read of the acknowledge register takes the interrupt, which is
        // the purpose of the read.
        unsafe {
            core::arch::asm!(
                concat!("mrs {}, ", $reg),
                out(reg) value,
                options(nostack, preserves_flags)
            )
        };
        value
    }};
}

/// Turns on the distributor and the CPU interface of the boot CPU.
pub(crate) fn init() {
    if v3() {
        write(gicd() + GICD_CTLR, GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_G1A);
        while read(gicd() + GICD_CTLR) & GICD_CTLR_RWP != 0 {
            core::hint::spin_loop();
        }
    } else {
        write(gicd() + GICD_CTLR, 1);
    }
    init_cpu();
}

/// Turns on the CPU interface of this CPU and the SGIs between CPUs. The registers of the SGIs and
/// the PPIs are banked, so each CPU does this.
pub(crate) fn init_cpu() {
    if v3() {
        init_cpu_v3();
    } else {
        // The first target register is banked. Each of its bytes gives the bit of this CPU.
        let target = read(gicd() + GICD_ITARGETSR) as u8;
        if let Some(slot) = TARGETS.get(super::cpu::id()) {
            slot.store(u64::from(target), Ordering::Relaxed);
        }
    }
    enable(super::smp::SGI_CALL);
    enable(super::smp::SGI_RESCHEDULE);
    if v3() {
        // ICC_PMR_EL1 and ICC_IGRPEN1_EL1.
        msr!("s3_0_c4_c6_0", PRIORITY_MASK);
        msr!("s3_0_c12_c12_7", 1u64);
    } else {
        write(gicc() + GICC_PMR, PRIORITY_MASK as u32);
        write(gicc() + GICC_CTLR, 1);
    }
}

/// The affinity of an MPIDR in the format of `GICR_TYPER` bits 63 to 32: Aff3, Aff2, Aff1, Aff0.
fn affinity(mpidr: u64) -> u64 {
    (mpidr & 0xff_ffff) | ((mpidr >> 32 & 0xff) << 24)
}

/// Finds the redistributor of this CPU, wakes it, and puts the SGIs and the PPIs in group 1.
fn init_cpu_v3() {
    let mpidr = super::cpu::read_mpidr();
    let id = super::cpu::id();
    let (base, len) = (GICR_BASE.load(Ordering::Relaxed), GICR_LEN.load(Ordering::Relaxed));
    let mut at = 0;
    let mut found = None;
    while at + GICR_FRAME <= len {
        let typer = read64(base + at + GICR_TYPER);
        if typer >> 32 == affinity(mpidr) {
            found = Some(base + at);
            break;
        }
        if typer & GICR_TYPER_LAST != 0 {
            break;
        }
        at += if typer & GICR_TYPER_VLPIS != 0 { 2 * GICR_FRAME } else { GICR_FRAME };
    }
    let Some(rd) = found else {
        crate::console::_print_panic(format_args!(
            "rk-frame: no GICv3 redistributor for MPIDR {mpidr:#x}\n"
        ));
        return;
    };
    if let (Some(r), Some(t)) = (REDISTRIBUTORS.get(id), TARGETS.get(id)) {
        r.store(rd, Ordering::Relaxed);
        t.store(mpidr, Ordering::Relaxed);
    }
    let waker = read(rd + GICR_WAKER);
    write(rd + GICR_WAKER, waker & !GICR_WAKER_PROCESSOR_SLEEP);
    while read(rd + GICR_WAKER) & GICR_WAKER_CHILDREN_ASLEEP != 0 {
        core::hint::spin_loop();
    }
    write(rd + GICR_SGI + GICD_IGROUPR, u32::MAX);
    // ICC_SRE_EL1: use the system registers.
    let sre = mrs!("s3_0_c12_c12_5");
    msr!("s3_0_c12_c12_5", sre | 1);
    super::its::init_cpu(id);
}

/// The redistributor of this CPU.
fn redistributor() -> usize {
    REDISTRIBUTORS.get(super::cpu::id()).map_or(0, |r| r.load(Ordering::Relaxed))
}

/// The virtual and the physical address of the redistributor of the CPU `id`, or `None` if the
/// CPU did not start or the GIC is not a GICv3.
pub(crate) fn redistributor_of(id: usize) -> Option<(usize, u64)> {
    let rd = REDISTRIBUTORS.get(id)?.load(Ordering::Relaxed);
    let at = rd.checked_sub(GICR_BASE.load(Ordering::Relaxed))?;
    (rd != 0).then(|| (rd, GICR_PHYS.load(Ordering::Relaxed) + at as u64))
}

/// The `GICD_TYPER` register: the number of interrupt ID bits and the support of LPIs.
pub(crate) fn typer() -> u32 {
    read(gicd() + GICD_TYPER)
}

/// Sends the SGI `sgi` to the CPU `id`.
pub(crate) fn send_sgi(id: usize, sgi: u32) {
    let target = TARGETS.get(id).map_or(0, |t| t.load(Ordering::Relaxed));
    // The stores to memory before the SGI must be visible to the CPU that takes it.
    // SAFETY: the barrier changes no memory.
    unsafe { core::arch::asm!("dsb ishst", options(nostack, preserves_flags)) };
    if v3() {
        // ICC_SGI1R_EL1: the target list holds Aff0 of the target, with Aff1, Aff2 and Aff3.
        let (aff0, aff1) = (target & 0xf, target >> 8 & 0xff);
        let (aff2, aff3) = (target >> 16 & 0xff, target >> 32 & 0xff);
        let value = 1 << aff0 | aff1 << 16 | u64::from(sgi & 0xf) << 24 | aff2 << 32 | aff3 << 48;
        msr!("s3_0_c12_c11_5", value);
    } else {
        write(gicd() + GICD_SGIR, (target as u32) << 16 | sgi);
    }
}

/// Lets the interrupt `intid` come to the CPU. An SGI or a PPI comes to this CPU only.
pub(crate) fn enable(intid: u32) {
    let n = intid as usize;
    let bit = 1 << (n % 32);
    if v3() && n < 32 {
        let sgi = redistributor() + GICR_SGI;
        write_u8(sgi + GICD_IPRIORITYR + n, PRIORITY);
        write(sgi + GICD_ISENABLER, bit);
        return;
    }
    if v3() {
        // An SPI is in group 1 and goes to the boot CPU.
        let group = gicd() + GICD_IGROUPR + n / 32 * 4;
        write(group, read(group) | bit);
        // GICD_IROUTER has the affinity fields at the places of MPIDR.
        let boot = TARGETS.first().map_or(0, |t| t.load(Ordering::Relaxed));
        write64(gicd() + GICD_IROUTER + n * 8, boot & 0xff_00ff_ffff);
    }
    write_u8(gicd() + GICD_IPRIORITYR + n, PRIORITY);
    write(gicd() + GICD_ISENABLER + n / 32 * 4, bit);
}

/// Takes the pending interrupt with the highest priority. Gives the value for `eoi`. `intid`
/// gives the interrupt number from it.
pub(crate) fn ack() -> u32 {
    if v3() {
        // ICC_IAR1_EL1.
        mrs!("s3_0_c12_c12_0") as u32
    } else {
        read(gicc() + GICC_IAR)
    }
}

/// The interrupt number of a value from `ack`: 24 bits on a GICv3, for the LPIs, and 10 bits on
/// a GICv2.
pub(crate) fn intid(iar: u32) -> u32 {
    if v3() { iar & 0xff_ffff } else { iar & 0x3ff }
}

/// Tells the GIC that the handler of an interrupt from `ack` is done.
pub(crate) fn eoi(iar: u32) {
    if v3() {
        // ICC_EOIR1_EL1.
        msr!("s3_0_c12_c12_1", u64::from(iar));
    } else {
        write(gicc() + GICC_EOIR, iar);
    }
}

/// The first SPI, and the end of the interrupt numbers that `irq::Line` takes.
const FIRST_SPI: u32 = 32;
const END_SPI: u32 = SPURIOUS;

/// A bit for each interrupt number below 1024: the SPIs that are device lines, and the lines that
/// came since the last `take_device`.
static DEVICE: [AtomicU32; 32] = [const { AtomicU32::new(0) }; 32];
static FIRED: [AtomicU32; 32] = [const { AtomicU32::new(0) }; 32];

fn bit(intid: u32) -> (&'static AtomicU32, &'static AtomicU32, u32) {
    let n = intid as usize;
    (&DEVICE[n / 32 % 32], &FIRED[n / 32 % 32], 1 << (n % 32))
}

/// Makes the SPI `intid` a device line with the trigger of the device tree and turns it on. Gives
/// `false` if `intid` is not an SPI.
pub(crate) fn enable_device(intid: u32, edge: bool) -> bool {
    if !(FIRST_SPI..END_SPI).contains(&intid) {
        return false;
    }
    let (device, _, b) = bit(intid);
    let n = intid as usize;
    // The trigger can change only while the SPI is off. Bit 1 of the two bits of each SPI is the
    // edge trigger.
    write(gicd() + GICD_ICENABLER + n / 32 * 4, b);
    let cfg = gicd() + GICD_ICFGR + n / 16 * 4;
    let shift = n % 16 * 2 + 1;
    let value = read(cfg) & !(1 << shift);
    write(cfg, value | u32::from(edge) << shift);
    if !v3() {
        // A GICv2 sends an SPI to the CPU interfaces of its target byte, and the byte is 0 at
        // the reset. `enable` sets the target of a GICv3.
        let boot = TARGETS.first().map_or(0, |t| t.load(Ordering::Relaxed));
        write_u8(gicd() + GICD_ITARGETSR + n, boot as u8);
    }
    device.fetch_or(b, Ordering::Relaxed);
    enable(intid);
    true
}

/// Tells if the SPI `intid` is a device line.
pub(crate) fn is_device(intid: u32) -> bool {
    let (device, _, b) = bit(intid);
    (FIRST_SPI..END_SPI).contains(&intid) && device.load(Ordering::Relaxed) & b != 0
}

/// The handler of a device line: turns the SPI off and sets its flag. It takes no lock.
pub(crate) fn device_interrupt(intid: u32) {
    let (_, fired, b) = bit(intid);
    write(gicd() + GICD_ICENABLER + intid as usize / 32 * 4, b);
    fired.fetch_or(b, Ordering::AcqRel);
}

/// Tells if the device line `intid` came since the last `take_device`.
pub(crate) fn fired(intid: u32) -> bool {
    if intid >= super::its::FIRST_LPI {
        return super::its::fired(intid);
    }
    let (_, fired, b) = bit(intid);
    fired.load(Ordering::Acquire) & b != 0
}

/// Tells if the device line `intid` came since the last call, and clears the flag.
pub(crate) fn take_device(intid: u32) -> bool {
    if intid >= super::its::FIRST_LPI {
        return super::its::take(intid);
    }
    let (_, fired, b) = bit(intid);
    fired.fetch_and(!b, Ordering::AcqRel) & b != 0
}

/// Turns the device line `intid` on again.
pub(crate) fn unmask_device(intid: u32) {
    if intid >= super::its::FIRST_LPI {
        super::its::unmask(intid);
    } else if is_device(intid) {
        write(gicd() + GICD_ISENABLER + intid as usize / 32 * 4, 1 << (intid % 32));
    }
}

/// Sends the device line `intid` to this CPU.
pub(crate) fn route_here(intid: u32) {
    if intid >= super::its::FIRST_LPI {
        super::its::route_here(intid);
        return;
    }
    if !is_device(intid) {
        return;
    }
    let n = intid as usize;
    let target = TARGETS.get(super::cpu::id()).map_or(0, |t| t.load(Ordering::Relaxed));
    if v3() {
        write64(gicd() + GICD_IROUTER + n * 8, target & 0xff_00ff_ffff);
    } else {
        write_u8(gicd() + GICD_ITARGETSR + n, target as u8);
    }
}

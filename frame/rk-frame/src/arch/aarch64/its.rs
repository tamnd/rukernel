//! The GICv3 ITS, which turns the MSI-X messages of PCI functions into LPIs, per the GICv3
//! Architecture Specification (IHI 0069) chapters 5 and 6, as drivers/irqchip/irq-gic-v3-its.c of
//! Linux.
//!
//! A function writes the event ID of an MSI-X table entry to the `GITS_TRANSLATER` register of the
//! ITS. The ITS gets the device ID of the function from the requester ID of the write. Its tables
//! map the device ID and the event ID to an LPI and to a collection, and each collection is the
//! redistributor of one CPU. Each line gets one LPI from `FIRST_LPI`. The lines of one function
//! share one interrupt translation table, and the event ID of each line is the index of its MSI-X
//! table entry, as `its_msi_prepare` and `its_irq_domain_alloc` of Linux. The handler masks the MSI-X table entry and sets the flag of the line, as the handler
//! of x86-64 in msi.rs does. A message that comes while the entry is masked stays pending in the
//! function, and the function sends it when the driver unmasks the entry.
//!
//! The first `alloc` sets up the LPIs and the ITS: the property table of the LPIs, a pending
//! table for each redistributor, the command queue, the tables of the devices and of the
//! collections, and one collection for each CPU. A CPU that starts later turns on its LPIs and
//! its collection in `init_cpu`. The tables are never given back.
//!
//! Each table is in normal memory with the write back cache, and inner shareable, as the CPUs
//! use it. A GIC that has only memory without cache for its tables is not supported.

use super::gic;
use crate::sync::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// The first LPI, and the interrupt number of the first line.
pub(crate) const FIRST_LPI: u32 = 8192;
/// The number of lines.
const LINES: usize = 32;
/// The number of interrupt ID bits that the property and the pending tables cover: the LPIs
/// below 16384. 14 bits is the least that a GICv3 with LPIs takes.
const ID_BITS: u32 = 14;

/// The size of an entry of the MSI-X table.
pub(crate) const ENTRY_SIZE: usize = 16;
/// The fields of an entry of the MSI-X table.
const ENTRY_ADDR_LOW: usize = 0;
const ENTRY_ADDR_HIGH: usize = 4;
const ENTRY_DATA: usize = 8;
const ENTRY_CONTROL: usize = 12;
/// The bit of the vector control field that masks the entry.
const CONTROL_MASKED: u32 = 1;

/// The registers of the ITS.
const GITS_CTLR: usize = 0x0000;
const GITS_TYPER: usize = 0x0008;
const GITS_CBASER: usize = 0x0080;
const GITS_CWRITER: usize = 0x0088;
const GITS_CREADR: usize = 0x0090;
const GITS_BASER: usize = 0x0100;
/// The register that the functions write their messages to, in the second frame of the ITS.
const GITS_TRANSLATER: u64 = 0x1_0040;
const GITS_CTLR_ENABLED: u32 = 1;
const GITS_CTLR_QUIESCENT: u32 = 1 << 31;
/// The bit of `GITS_TYPER` that tells that a collection names its redistributor by the physical
/// address. Else it names it by the processor number of `GICR_TYPER`.
const GITS_TYPER_PTA: u64 = 1 << 19;
/// The bit of `GITS_CREADR` that tells that the ITS stopped at a command with an error.
const GITS_CREADR_STALLED: u64 = 1;

/// The registers of a redistributor for the LPIs.
const GICR_CTLR: usize = 0x0000;
const GICR_TYPER: usize = 0x0008;
const GICR_PROPBASER: usize = 0x0070;
const GICR_PENDBASER: usize = 0x0078;
const GICR_CTLR_ENABLE_LPIS: u32 = 1;
const GICR_TYPER_PLPIS: u64 = 1;
/// The bit of `GICD_TYPER` that tells that the GIC has LPIs, and the field of its ID bits.
const GICD_TYPER_LPIS: u32 = 1 << 17;

/// The fields of the base registers of the tables: inner shareable, and the write back cache
/// with read and write allocation.
const SHAREABLE_INNER: u64 = 1 << 10;
const CACHE_WAWB: u64 = 7;
/// The inner cache field of `GICR_PROPBASER` and `GICR_PENDBASER`, and of `GITS_CBASER` and
/// `GITS_BASER<n>`.
const CACHE_SHIFT_RD: u32 = 7;
const CACHE_SHIFT_ITS: u32 = 59;
const BASER_VALID: u64 = 1 << 63;
/// The table types of `GITS_BASER<n>`.
const BASER_DEVICES: u64 = 1;
const BASER_COLLECTIONS: u64 = 4;
/// The most pages of 4 KiB that the size field of `GITS_BASER<n>` gives.
const BASER_MAX_PAGES: usize = 256;

/// The command numbers.
const CMD_MOVI: u64 = 0x01;
const CMD_SYNC: u64 = 0x05;
const CMD_MAPD: u64 = 0x08;
const CMD_MAPC: u64 = 0x09;
const CMD_MAPTI: u64 = 0x0a;
/// The size of a command, and of the command queue: one page.
const CMD_SIZE: usize = 32;
const QUEUE_SIZE: usize = 4096;

/// The page size and its order for `alloc_table_run`.
const PAGE: usize = 4096;

/// The virtual and the physical address of the ITS, from the device tree, or 0.
static ITS_BASE: AtomicUsize = AtomicUsize::new(0);
static ITS_PHYS: AtomicU64 = AtomicU64::new(0);

/// The virtual address of the MSI-X table entry of each line, or 0 for a free line.
static ENTRY: [AtomicUsize; LINES] = [const { AtomicUsize::new(0) }; LINES];
/// The device ID of each line, and its event ID.
static DEVICE: [AtomicU32; LINES] = [const { AtomicU32::new(0) }; LINES];
static EVENT: [AtomicU32; LINES] = [const { AtomicU32::new(0) }; LINES];
/// The CPU that the collection of each line is.
static TARGET: [AtomicUsize; LINES] = [const { AtomicUsize::new(0) }; LINES];
/// A bit for each line that came since the last `take`.
static FIRED: AtomicU32 = AtomicU32::new(0);
/// The ITS is set up. `alloc` reads it without the lock.
static READY: AtomicBool = AtomicBool::new(false);

/// The state that the commands change. The lock keeps one command sequence at a time.
struct Its {
    /// The setup failed, so `alloc` gives `None` without a new try.
    failed: bool,
    /// The physical address of the command queue, and the offset of the next command.
    queue: u64,
    write: usize,
    /// The physical address of the property table of the LPIs.
    prop: u64,
    /// A collection names its redistributor by the physical address.
    pta: bool,
    /// The size of an entry of the interrupt translation table of a device.
    itt_entry: usize,
    /// The device IDs that the device table holds.
    devices: u32,
    /// A bit for each CPU with its LPIs on and its collection mapped.
    cpus: u64,
}

static ITS: SpinLock<Its> = SpinLock::new(Its {
    failed: false,
    queue: 0,
    write: 0,
    prop: 0,
    pta: false,
    itt_entry: 0,
    devices: 0,
    cpus: 0,
});

/// Uses the ITS at the virtual address `virt` and the physical address `phys`, from the device
/// tree.
pub(crate) fn set_base(virt: usize, phys: u64) {
    ITS_PHYS.store(phys, Ordering::Relaxed);
    ITS_BASE.store(virt, Ordering::Release);
}

fn its() -> usize {
    ITS_BASE.load(Ordering::Acquire)
}

/// The virtual address of the frame at the physical address `phys`, in the direct map.
fn virt(phys: u64) -> usize {
    super::paging::phys_to_virt(phys)
}

/// Makes the stores to memory visible to the GIC before the next access to its registers.
fn barrier() {
    // SAFETY: the barrier changes no memory.
    unsafe { core::arch::asm!("dsb sy", options(nostack, preserves_flags)) };
}

fn line(intid: u32) -> Option<usize> {
    let n = intid.checked_sub(FIRST_LPI)? as usize;
    (n < LINES).then_some(n)
}

/// Writes the field at `offset` of the MSI-X table entry at the virtual address `entry`.
fn write_entry(entry: usize, offset: usize, value: u32) {
    // SAFETY: `entry` is an entry of an MSI-X table that `pci::map_registers` mapped as device
    // memory for all of the run time, and it is not RAM. The offset is in the entry and aligned.
    unsafe { ((entry + offset) as *mut u32).write_volatile(value) };
}

impl Its {
    /// Sets up the LPIs and the ITS. Gives `false` if the GIC has no LPIs or the ITS does not
    /// take its tables.
    fn init(&mut self) -> bool {
        let base = its();
        let typer = gic::typer();
        if !gic::v3() || base == 0 || typer & GICD_TYPER_LPIS == 0 || (typer >> 19 & 0x1f) + 1 < 14
        {
            return false;
        }
        // The property table has a byte for each LPI: the priority, and bit 0 turns the LPI on.
        // All lines are on, and the masks of the MSI-X entries stop them.
        let prop_len = (1 << ID_BITS) - FIRST_LPI as usize;
        let Some(prop) = crate::mm::frame::alloc_table_run((prop_len / PAGE).trailing_zeros())
        else {
            return false;
        };
        for n in 0..LINES {
            // SAFETY: the table is a run of frames that this module owns, in the direct map.
            unsafe { ((virt(prop) + n) as *mut u8).write_volatile(gic::PRIORITY | 1) };
        }
        self.prop = prop;

        // The ITS must be off and quiet while its tables change.
        gic::write(base + GITS_CTLR, gic::read(base + GITS_CTLR) & !GITS_CTLR_ENABLED);
        let mut spins = 0u32;
        while gic::read(base + GITS_CTLR) & GITS_CTLR_QUIESCENT == 0 {
            spins += 1;
            if spins > 1_000_000 {
                return false;
            }
            core::hint::spin_loop();
        }
        let its_typer = gic::read64(base + GITS_TYPER);
        self.pta = its_typer & GITS_TYPER_PTA != 0;
        self.itt_entry = (its_typer >> 4 & 0xf) as usize + 1;
        let dev_bits = (its_typer >> 13 & 0x1f) as u32 + 1;

        let Some(queue) = crate::mm::frame::alloc_table_frame() else { return false };
        self.queue = queue;
        self.write = 0;
        let cache = CACHE_WAWB << CACHE_SHIFT_ITS;
        gic::write64(base + GITS_CBASER, BASER_VALID | cache | queue | SHAREABLE_INNER);
        gic::write64(base + GITS_CWRITER, 0);

        // The device table holds the device IDs of the functions that the scan of the PCI bus
        // found.
        let wanted = (u64::from(crate::pci::max_device_id()) + 1).min(1 << dev_bits);
        for n in 0..8 {
            let reg = base + GITS_BASER + n * 8;
            let value = gic::read64(reg);
            let kind = value >> 56 & 7;
            let entry = (value >> 48 & 0x1f) as usize + 1;
            let ids = match kind {
                BASER_DEVICES => wanted as usize,
                BASER_COLLECTIONS => super::cpu::MAX_CPUS,
                _ => continue,
            };
            let pages = (ids * entry).div_ceil(PAGE).clamp(1, BASER_MAX_PAGES).next_power_of_two();
            let pages = pages.min(BASER_MAX_PAGES);
            let Some(table) = crate::mm::frame::alloc_table_run(pages.trailing_zeros()) else {
                return false;
            };
            // The page size field 0 selects pages of 4 KiB.
            let keep = value & (0x7 << 56 | 0x1f << 48);
            let new = BASER_VALID | cache | keep | table | SHAREABLE_INNER | (pages as u64 - 1);
            gic::write64(reg, new);
            let back = gic::read64(reg);
            if back & BASER_VALID == 0 || back >> 8 & 3 != 0 {
                crate::println!("aarch64: the GICv3 ITS does not take the table of type {kind}");
                return false;
            }
            if kind == BASER_DEVICES {
                self.devices = (pages * PAGE / entry) as u32;
            }
        }
        barrier();
        gic::write(base + GITS_CTLR, GITS_CTLR_ENABLED);
        for id in 0..super::cpu::MAX_CPUS {
            self.add_cpu(id);
        }
        true
    }

    /// Turns on the LPIs of the redistributor of the CPU `id`, and maps the collection `id` to
    /// it. Does nothing for a CPU that did not start, or that has them already.
    fn add_cpu(&mut self, id: usize) {
        let Some((rd, rd_phys)) = gic::redistributor_of(id) else { return };
        if id >= 64 || self.cpus & 1 << id != 0 {
            return;
        }
        let typer = gic::read64(rd + GICR_TYPER);
        if typer & GICR_TYPER_PLPIS == 0 || gic::read(rd + GICR_CTLR) & GICR_CTLR_ENABLE_LPIS != 0 {
            crate::println!("aarch64: the GICv3 redistributor of CPU {id} cannot take LPIs");
            return;
        }
        // The pending table has a bit for each interrupt ID, and it is 64 KiB aligned.
        let Some(pending) = crate::mm::frame::alloc_table_run(4) else { return };
        let cache = CACHE_WAWB << CACHE_SHIFT_RD;
        let prop = self.prop | cache | SHAREABLE_INNER | u64::from(ID_BITS - 1);
        gic::write64(rd + GICR_PROPBASER, prop);
        gic::write64(rd + GICR_PENDBASER, pending | cache | SHAREABLE_INNER);
        barrier();
        gic::write(rd + GICR_CTLR, gic::read(rd + GICR_CTLR) | GICR_CTLR_ENABLE_LPIS);
        let target = self.target(rd_phys, typer);
        if self.run(&[[CMD_MAPC, 0, 1 << 63 | target | id as u64, 0], [CMD_SYNC, 0, target, 0]]) {
            self.cpus |= 1 << id;
        }
    }

    /// The target field of a command for the redistributor at `rd_phys` with the `GICR_TYPER`
    /// value `typer`: its physical address, or its processor number, in bits 51 to 16.
    fn target(&self, rd_phys: u64, typer: u64) -> u64 {
        if self.pta { rd_phys & 0xf_ffff_ffff_0000 } else { (typer >> 8 & 0xffff) << 16 }
    }

    /// The target field of the redistributor of the CPU `id`.
    fn target_of(&self, id: usize) -> Option<u64> {
        let (rd, rd_phys) = gic::redistributor_of(id)?;
        Some(self.target(rd_phys, gic::read64(rd + GICR_TYPER)))
    }

    /// Puts the commands in the queue and waits until the ITS did them. Gives `false` if the ITS
    /// stopped at an error, or did not take the commands in time.
    fn run(&mut self, cmds: &[[u64; 4]]) -> bool {
        let base = its();
        for cmd in cmds {
            let at = virt(self.queue) + self.write;
            for (i, word) in cmd.iter().enumerate() {
                // SAFETY: the queue is a frame that this module owns, in the direct map, and the
                // ITS reads only the commands before `GITS_CWRITER`.
                unsafe { ((at + i * 8) as *mut u64).write_volatile(*word) };
            }
            self.write = (self.write + CMD_SIZE) % QUEUE_SIZE;
        }
        barrier();
        gic::write64(base + GITS_CWRITER, self.write as u64);
        let mut spins = 0u32;
        loop {
            let read = gic::read64(base + GITS_CREADR);
            if read & GITS_CREADR_STALLED != 0 {
                crate::println!("aarch64: the GICv3 ITS stopped at a command");
                return false;
            }
            if read as usize & (QUEUE_SIZE - 1) & !(CMD_SIZE - 1) == self.write {
                return true;
            }
            spins += 1;
            if spins > 10_000_000 {
                crate::println!("aarch64: the GICv3 ITS does not take its commands");
                return false;
            }
            core::hint::spin_loop();
        }
    }
}

/// Turns on the LPIs and the collection of the CPU `id` that just started, if the ITS is set up.
pub(crate) fn init_cpu(id: usize) {
    if READY.load(Ordering::Acquire) {
        ITS.lock().add_cpu(id);
    }
}

/// Takes a free line for each entry of `entries`. Gives `false` and takes none if not enough
/// lines are free.
fn reserve(entries: &[usize], lines: &mut [usize]) -> bool {
    for (k, &entry) in entries.iter().enumerate() {
        let free = ENTRY.iter().position(|e| {
            e.compare_exchange(0, entry, Ordering::AcqRel, Ordering::Relaxed).is_ok()
        });
        match free {
            Some(n) => lines[k] = n,
            None => {
                lines[..k].iter().for_each(|&n| ENTRY[n].store(0, Ordering::Release));
                return false;
            }
        }
    }
    true
}

/// The number of event ID bits of an interrupt translation table for `events` events: at least 1,
/// as the size field of `MAPD` is the number of bits less one.
fn event_bits(events: usize) -> u32 {
    events.next_power_of_two().trailing_zeros().max(1)
}

/// Sets up the MSI-X table entries at the virtual addresses `entries` of the function with the
/// device ID `device`, each with a free LPI to the boot CPU and the event ID of its index in
/// `entries`, and unmasks them. Writes the LPI of each entry to `lpis`. Gives `false` if there is
/// no ITS, if the device table does not hold the device ID, or if not enough LPIs are free. Then no
/// entry has an LPI.
pub(crate) fn alloc(entries: &[usize], device: u32, lpis: &mut [u32]) -> bool {
    let mut its = ITS.lock();
    if its.failed || entries.is_empty() || entries.len() > LINES || lpis.len() < entries.len() {
        return false;
    }
    if !READY.load(Ordering::Acquire) {
        if !its.init() {
            its.failed = true;
            return false;
        }
        READY.store(true, Ordering::Release);
    }
    if device >= its.devices || its.cpus & 1 == 0 {
        return false;
    }
    let mut lines = [0usize; LINES];
    let lines = &mut lines[..entries.len()];
    if !reserve(entries, lines) {
        return false;
    }
    let free = |lines: &[usize]| lines.iter().for_each(|&n| ENTRY[n].store(0, Ordering::Release));
    // The interrupt translation table of the device holds an event ID for each entry, and it is
    // 256 bytes aligned.
    let bits = event_bits(entries.len());
    let itt = crate::mm::frame::alloc_table_frame().filter(|_| its.itt_entry << bits <= PAGE);
    let target = its.target_of(0);
    let (Some(itt), Some(target)) = (itt, target) else {
        free(lines);
        return false;
    };
    let doorbell = ITS_PHYS.load(Ordering::Relaxed) + GITS_TRANSLATER;
    let dev = u64::from(device) << 32;
    let mut cmds = [[0u64; 4]; LINES + 2];
    // The size field is the number of event ID bits less one.
    cmds[0] = [CMD_MAPD | dev, u64::from(bits - 1), 1 << 63 | itt, 0];
    for (event, (&entry, &n)) in entries.iter().zip(lines.iter()).enumerate() {
        let lpi = FIRST_LPI + n as u32;
        DEVICE[n].store(device, Ordering::Relaxed);
        EVENT[n].store(event as u32, Ordering::Relaxed);
        TARGET[n].store(0, Ordering::Relaxed);
        write_entry(entry, ENTRY_CONTROL, CONTROL_MASKED);
        write_entry(entry, ENTRY_ADDR_LOW, doorbell as u32);
        write_entry(entry, ENTRY_ADDR_HIGH, (doorbell >> 32) as u32);
        write_entry(entry, ENTRY_DATA, event as u32);
        cmds[event + 1] = [CMD_MAPTI | dev, u64::from(lpi) << 32 | event as u64, 0, 0];
        lpis[event] = lpi;
    }
    cmds[entries.len() + 1] = [CMD_SYNC, 0, target, 0];
    if !its.run(&cmds[..entries.len() + 2]) {
        free(lines);
        return false;
    }
    entries.iter().for_each(|&entry| write_entry(entry, ENTRY_CONTROL, 0));
    true
}

/// Gives back the lines `lpis` of the function with the device ID `device`, which one `alloc`
/// gave. Masks their MSI-X table entries and unmaps the device with `MAPD`, as
/// `its_irq_domain_free` of Linux. The interrupt translation table is not given back.
pub(crate) fn free(lpis: &[u32], device: u32) {
    let mut its = ITS.lock();
    for &lpi in lpis {
        let Some(n) = line(lpi) else { continue };
        let entry = ENTRY[n].load(Ordering::Acquire);
        if entry != 0 {
            write_entry(entry, ENTRY_CONTROL, CONTROL_MASKED);
        }
        ENTRY[n].store(0, Ordering::Release);
        FIRED.fetch_and(!(1 << n), Ordering::AcqRel);
    }
    if let Some(target) = its.target_of(0) {
        its.run(&[[CMD_MAPD | u64::from(device) << 32, 0, 0, 0], [CMD_SYNC, 0, target, 0]]);
    }
}

/// The handler of a device line: masks the entry and sets the flag of the line. It takes no lock.
/// Gives `false` for another interrupt.
pub(crate) fn handle(intid: u32) -> bool {
    let Some(n) = line(intid) else { return false };
    let entry = ENTRY[n].load(Ordering::Acquire);
    if entry == 0 {
        return false;
    }
    write_entry(entry, ENTRY_CONTROL, CONTROL_MASKED);
    FIRED.fetch_or(1 << n, Ordering::AcqRel);
    true
}

/// Tells if the line `intid` came since the last `take`.
pub(crate) fn fired(intid: u32) -> bool {
    line(intid).is_some_and(|n| FIRED.load(Ordering::Acquire) & 1 << n != 0)
}

/// Tells if the line `intid` came since the last `take`, and clears the flag.
pub(crate) fn take(intid: u32) -> bool {
    line(intid).is_some_and(|n| FIRED.fetch_and(!(1 << n), Ordering::AcqRel) & 1 << n != 0)
}

/// Unmasks the entry of the line `intid`.
pub(crate) fn unmask(intid: u32) {
    if let Some(n) = line(intid) {
        let entry = ENTRY[n].load(Ordering::Acquire);
        if entry != 0 {
            write_entry(entry, ENTRY_CONTROL, 0);
        }
    }
}

/// Sends the line `intid` to this CPU with the command MOVI. The entry is masked while the line
/// moves, and it stays masked if the line came, until `unmask`.
pub(crate) fn route_here(intid: u32) {
    let Some(n) = line(intid) else { return };
    let entry = ENTRY[n].load(Ordering::Acquire);
    let id = super::cpu::id();
    if entry == 0 || TARGET[n].load(Ordering::Relaxed) == id {
        return;
    }
    let mut its = ITS.lock();
    if id >= 64 || its.cpus & 1 << id == 0 {
        return;
    }
    let Some(target) = its.target_of(id) else { return };
    write_entry(entry, ENTRY_CONTROL, CONTROL_MASKED);
    let dev = u64::from(DEVICE[n].load(Ordering::Relaxed)) << 32;
    let event = u64::from(EVENT[n].load(Ordering::Relaxed));
    if its.run(&[[CMD_MOVI | dev, event, id as u64, 0], [CMD_SYNC, 0, target, 0]]) {
        TARGET[n].store(id, Ordering::Relaxed);
    }
    drop(its);
    if FIRED.load(Ordering::Acquire) & 1 << n == 0 {
        write_entry(entry, ENTRY_CONTROL, 0);
    }
}

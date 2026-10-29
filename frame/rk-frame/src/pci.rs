//! The PCI bus: the configuration space of each function and the memory registers of its BARs.
//!
//! On x86-64, rk-frame reads the configuration space through the legacy ports 0xCF8 and 0xCFC, and
//! the firmware assigned the BARs. On arm64, it reads the ECAM of the generic PCI host of the
//! device tree. No firmware runs before a kernel that QEMU loads with `-kernel`, so the scan
//! assigns the memory BARs and the I/O BARs of each function from the windows of the host, as
//! `pci_assign_unassigned_resources` of Linux. The scan also gives a bus number to each PCI bridge
//! and scans the bus behind it, as `pci_scan_bridge` of Linux in drivers/pci/probe.c. The memory
//! windows and the I/O window of a bridge hold the BARs of all functions behind it, as
//! `pbus_size_mem`, `pbus_size_io` and `pci_setup_bridge` of Linux in drivers/pci/setup-bus.c.
//!
//! A driver gets a `PciDevice` from `devices` and reads its configuration space. It can turn on
//! the memory decoding and the bus master bit, and map a range of a memory BAR as an `IoMem`. It
//! cannot write other registers of the configuration space, because a BAR that moves onto RAM
//! breaks the memory safety of the kernel. On arm64 it gets the interrupt line of the INTx pin of
//! the function from the `interrupt-map` of the host, with the pin swizzled through each bridge.
//! It can turn on MSI-X and get a line for each of the first entries of the MSI-X table: on x86-64
//! through the local APIC, and on arm64 through the GICv3 ITS. On arm64 it can map an I/O BAR,
//! because the CPU sees the I/O space of the host as memory.
//!
//! A device with the bus master bit can write each physical address. rukernel has no IOMMU
//! driver yet, so the kernel trusts the device and the driver to give the device only the
//! addresses of the frames that the driver owns. AUDITED.md records this.

#[cfg(target_arch = "x86_64")]
use crate::addr::PAGE_SIZE;
use crate::boot::MemoryKind;
use crate::pci_window as window;
use crate::sync::{Once, SpinLock};
use alloc::vec::Vec;

pub use crate::iomem::IoMem;
pub use crate::irq::Line;

/// The lock of the configuration space. It keeps the two accesses of one read through the ports
/// together, and the steps of a BAR size probe.
static CONFIG: SpinLock<()> = SpinLock::new(());

/// The configuration space through the ports 0xCF8 and 0xCFC.
#[cfg(target_arch = "x86_64")]
mod config {
    use super::PciAddress;
    use crate::arch::imp::io::Port;

    // SAFETY: 0xCF8 and 0xCFC are the configuration ports of the PCI host bridge. Only this
    // module uses them, and a read or a write of the configuration space does not touch memory.
    const ADDRESS: Port = unsafe { Port::new(0xcf8) };
    // SAFETY: as for `ADDRESS`.
    const DATA: Port = unsafe { Port::new(0xcfc) };

    /// The number of buses that the scan reads.
    pub(super) fn buses() -> usize {
        256
    }

    fn select(a: PciAddress, offset: u8) {
        ADDRESS.write_u32(
            (1 << 31)
                | (u32::from(a.bus) << 16)
                | (u32::from(a.device) << 11)
                | (u32::from(a.function) << 8)
                | u32::from(offset & 0xfc),
        );
    }

    /// Reads the register at `offset`. The caller holds `CONFIG`.
    pub(super) fn read_u32(a: PciAddress, offset: u8) -> u32 {
        select(a, offset);
        DATA.read_u32()
    }

    /// Writes the register at `offset`. The caller holds `CONFIG`.
    pub(super) fn write_u32(a: PciAddress, offset: u8, value: u32) {
        select(a, offset);
        DATA.write_u32(value);
    }

    /// Writes the low 16 bits of the register at `offset`. The caller holds `CONFIG`.
    pub(super) fn write_u16(a: PciAddress, offset: u8, value: u16) {
        select(a, offset);
        DATA.write_u16(value);
    }
}

/// The configuration space through the ECAM of the generic PCI host: 4 KiB for each function, at
/// the bus, the device and the function in bits 20, 15 and 12 of the offset.
#[cfg(target_arch = "aarch64")]
mod config {
    use super::PciAddress;
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// The virtual address of the ECAM, or 0 if there is no PCI host, and its number of buses.
    static ECAM: AtomicUsize = AtomicUsize::new(0);
    static BUSES: AtomicUsize = AtomicUsize::new(0);

    /// Uses the ECAM of `len` bytes at the virtual address `virt`. The boot path maps it as device
    /// memory for all of the run time.
    pub(crate) fn set(virt: usize, len: usize) {
        BUSES.store((len >> 20).min(256), Ordering::Relaxed);
        ECAM.store(virt, Ordering::Release);
    }

    /// The number of buses that the scan reads.
    pub(super) fn buses() -> usize {
        BUSES.load(Ordering::Relaxed)
    }

    fn register(a: PciAddress, offset: u8) -> Option<usize> {
        let base = ECAM.load(Ordering::Acquire);
        (base != 0 && usize::from(a.bus) < buses()).then(|| {
            base + (usize::from(a.bus) << 20)
                + (usize::from(a.device & 31) << 15)
                + (usize::from(a.function & 7) << 12)
                + usize::from(offset)
        })
    }

    /// Reads the register at `offset`. A function that is not there gives all ones.
    pub(super) fn read_u32(a: PciAddress, offset: u8) -> u32 {
        match register(a, offset & 0xfc) {
            // SAFETY: the register is in the ECAM, which the boot path maps as device memory, and
            // it is aligned. A read of the configuration space does not touch memory.
            Some(r) => unsafe { (r as *const u32).read_volatile() },
            None => u32::MAX,
        }
    }

    /// Writes the register at `offset`.
    pub(super) fn write_u32(a: PciAddress, offset: u8, value: u32) {
        if let Some(r) = register(a, offset & 0xfc) {
            // SAFETY: as for `read_u32`. The callers do not move a BAR onto RAM.
            unsafe { (r as *mut u32).write_volatile(value) };
        }
    }

    /// Writes the low 16 bits of the register at `offset`.
    pub(super) fn write_u16(a: PciAddress, offset: u8, value: u16) {
        if let Some(r) = register(a, offset & 0xfc) {
            // SAFETY: as for `write_u32`.
            unsafe { (r as *mut u16).write_volatile(value) };
        }
    }
}

#[cfg(target_arch = "aarch64")]
pub(crate) use host::set as set_host;

/// The memory windows and the INTx interrupts of the generic PCI host of arm64.
#[cfg(target_arch = "aarch64")]
mod host {
    use super::{CONFIG, PciAddress, PciDevice};
    use crate::fdt::{MAX_PCI_INTX, PciIntx, Platform};
    use crate::println;
    use crate::sync::SpinLock;
    use alloc::vec::Vec;

    use super::window::{self, Window};

    struct Host {
        mem: Window,
        mem64: Window,
        /// The free part of the I/O window, in PCI addresses, and the CPU address of PCI address 0.
        io: Window,
        io_cpu: u64,
        intx_mask: (u32, u32),
        intx: [PciIntx; MAX_PCI_INTX],
        intx_count: usize,
        /// The `msi-map` of the host, as in `Platform::pci_msi_map`.
        msi_map: Option<(u32, u32, u32)>,
    }

    static HOST: SpinLock<Host> = SpinLock::new(Host {
        mem: Window::EMPTY,
        mem64: Window::EMPTY,
        io: Window::EMPTY,
        io_cpu: 0,
        intx_mask: (0, 0),
        intx: [PciIntx { addr: 0, pin: 0, irq: crate::fdt::Irq { intid: 0, edge: false } };
            MAX_PCI_INTX],
        intx_count: 0,
        msi_map: None,
    });

    /// Uses the PCI host of the device tree, with its ECAM at the virtual address `ecam`.
    pub(crate) fn set(p: &Platform, ecam: usize, len: usize) {
        let mut h = HOST.lock();
        h.mem = Window::new(p.pci_mem);
        h.mem64 = Window::new(p.pci_mem64);
        if let Some((cpu, pci, len)) = p.pci_io {
            // The I/O BARs start at 0x1000, above the ports of ISA devices, as `PCIBIOS_MIN_IO` of
            // Linux on arm64.
            let start = pci.max(window::MIN_IO);
            let len = (pci + len).saturating_sub(start);
            h.io = Window::new(Some((start, len)));
            h.io_cpu = cpu.wrapping_sub(pci);
        }
        h.intx_mask = p.pci_intx_mask;
        h.intx = p.pci_intx;
        h.intx_count = p.pci_intx_count;
        h.msi_map = p.pci_msi_map;
        drop(h);
        super::config::set(ecam, len);
    }

    /// Gives an address for a memory BAR of `size` bytes: in the 32 bit window, or for a 64 bit
    /// BAR in the 64 bit window if the 32 bit window is full. Behind a bridge, the 64 bit window
    /// is only for a prefetchable BAR, because only the prefetchable window of a bridge has 64
    /// bits.
    fn alloc(size: u64, high: bool) -> Option<u64> {
        let mut h = HOST.lock();
        h.mem.take(size, 1 << 32).or_else(|| if high { h.mem64.take(size, u64::MAX) } else { None })
    }

    /// Gives the CPU address of the `len` bytes at the PCI address `bus` of the I/O space, or
    /// `None` if the range is not in the I/O window of the host.
    pub(super) fn io_cpu(bus: u64, len: u64) -> Option<u64> {
        let h = HOST.lock();
        let end = bus.checked_add(len)?;
        (bus >= window::MIN_IO && end <= h.io.end).then(|| h.io_cpu.wrapping_add(bus))
    }

    /// Gives the device ID of the ITS for the requester ID `rid`, from the `msi-map` of the host.
    /// Gives `None` if the map does not have the ID.
    pub(super) fn msi_device_id(rid: u16) -> Option<u32> {
        match HOST.lock().msi_map {
            Some((base, id, len)) => {
                let at = u32::from(rid).checked_sub(base).filter(|&at| at < len)?;
                id.checked_add(at)
            }
            None => Some(u32::from(rid)),
        }
    }

    /// Gives an address to each memory BAR and each I/O BAR of the function `a`: six BARs for a
    /// header of type 0, and two for a bridge. The decoding is off while the BARs change, and stays
    /// as it was after.
    pub(super) fn assign(a: PciAddress) {
        let _guard = CONFIG.lock();
        let read = |offset| super::config::read_u32(a, offset);
        let write = |offset, value| super::config::write_u32(a, offset, value);
        let bars = match read(0x0c) >> 16 & 0x7f {
            0 => 6,
            1 => 2,
            _ => return,
        };
        let command = read(super::COMMAND) as u16;
        let off = command & !(super::COMMAND_MEMORY | super::COMMAND_IO);
        super::config::write_u16(a, super::COMMAND, off);
        let mut bar = 0;
        while bar < bars {
            let offset = super::BAR0 + bar * 4;
            let low = read(offset);
            let wide = low & 1 == 0 && (low >> 1) & 3 == 2 && bar < bars - 1;
            let prefetch = low & 1 << 3 != 0;
            bar += if wide { 2 } else { 1 };
            if low & 1 != 0 {
                write(offset, u32::MAX);
                let mask = read(offset);
                let size = window::io_bar_size(mask);
                // A function that decodes only 16 bits of the address gives 0 in the upper half.
                let limit = if mask >> 16 == 0 { 1 << 16 } else { 1 << 32 };
                let base = if size == 0 { None } else { HOST.lock().io.take(size, limit) };
                if base.is_none() && size != 0 {
                    println!("pci: no address for the I/O BAR {} of {a:?}", bar - 1);
                }
                write(offset, base.unwrap_or(0) as u32);
                continue;
            }
            write(offset, u32::MAX);
            let mask_low = read(offset) & !0xf;
            let mask_high = if wide {
                write(offset + 4, u32::MAX);
                read(offset + 4)
            } else {
                u32::MAX
            };
            let size = (!((u64::from(mask_high) << 32) | u64::from(mask_low))).wrapping_add(1);
            let high = wide && (a.bus == 0 || prefetch);
            let base = if mask_low == 0 && !wide { None } else { alloc(size, high) };
            let base = base.unwrap_or_else(|| {
                if size != 0 && mask_low != 0 {
                    println!("pci: no address for BAR {} of {a:?}", bar - 1);
                }
                0
            });
            write(offset, base as u32);
            if wide {
                write(offset + 4, (base >> 32) as u32);
            }
        }
        super::config::write_u16(a, super::COMMAND, command);
    }

    /// Gives the interrupt line of the INTx pin of `dev`, from the `interrupt-map` of the host.
    /// The pin of a function behind a bridge goes to the pin of the bridge, as
    /// `pci_swizzle_interrupt_pin` of Linux: INTA of device 1 goes to INTB, and so on. The bridge
    /// on bus 0 and the pin after the swizzle select the entry of the map.
    pub(super) fn irq(dev: &PciDevice) -> Option<super::Line> {
        let mut pin = u32::from(dev.read_config_u8(0x3d));
        if !(1..=4).contains(&pin) {
            return None;
        }
        let mut a = dev.address();
        let mut parent = dev.parent;
        while let Some(bridge) = parent {
            pin = (pin - 1 + u32::from(a.device)) % 4 + 1;
            a = bridge;
            parent = super::devices().iter().find(|d| d.address == bridge)?.parent;
        }
        if a.bus != 0 {
            return None;
        }
        let addr = u32::from(a.device) << 11 | u32::from(a.function) << 8;
        let h = HOST.lock();
        let (addr_mask, pin_mask) = h.intx_mask;
        let e = h.intx[..h.intx_count]
            .iter()
            .find(|e| e.addr == addr & addr_mask && e.pin == pin & pin_mask)
            .copied()?;
        drop(h);
        super::Line::new(e.irq.intid, e.irq.edge)
    }

    /// The registers of the header of a bridge: the bus numbers, the I/O window, the memory
    /// window, and the prefetchable window with the upper halves of its base and limit.
    const BRIDGE_BUSES: u8 = 0x18;
    const BRIDGE_IO: u8 = 0x1c;
    const BRIDGE_MEMORY: u8 = 0x20;
    const BRIDGE_PREFETCH: u8 = 0x24;
    const BRIDGE_PREFETCH_BASE_HIGH: u8 = 0x28;
    const BRIDGE_PREFETCH_LIMIT_HIGH: u8 = 0x2c;
    const BRIDGE_IO_HIGH: u8 = 0x30;

    /// Scans the bus `bus` behind the bridge `parent`, or the root bus 0, and adds each function
    /// to `found`. It assigns the BARs of each function. Each bridge gets the bus number `next`,
    /// and the scan continues on the bus behind it first. Gives the highest bus number behind
    /// `bus`.
    pub(super) fn scan_bus(
        bus: u8,
        parent: Option<PciAddress>,
        found: &mut Vec<PciDevice>,
        next: &mut usize,
    ) -> u8 {
        let mut last = bus;
        for device in 0..32u8 {
            for function in 0..8u8 {
                let address = PciAddress { bus, device, function };
                let Some(dev) = super::probe(address, parent) else {
                    if function == 0 {
                        break;
                    }
                    continue;
                };
                assign(address);
                let header = address.read_u32(0x0c) >> 16;
                found.push(dev);
                if header & 0x7f == 1 {
                    last = last.max(scan_bridge(address, found, next));
                }
                // Bit 7 of the header type tells that the device has more than one function.
                if function == 0 && header & 0x80 == 0 {
                    break;
                }
            }
        }
        last
    }

    /// Gives the bridge `a` the bus number `next`, scans the bus behind it, and opens its memory
    /// windows and its I/O window over the BARs of the functions behind it, as
    /// `pci_scan_bridge_extend`, `pbus_size_io` and `pci_setup_bridge` of Linux. Gives the highest
    /// bus number behind the bridge.
    fn scan_bridge(a: PciAddress, found: &mut Vec<PciDevice>, next: &mut usize) -> u8 {
        let Ok(secondary) = u8::try_from(*next) else { return a.bus };
        if *next >= super::config::buses() {
            println!("pci: no bus number for the bridge {a:?}");
            return a.bus;
        }
        *next += 1;
        // The latency timer of the secondary bus is in the high byte.
        let latency = a.read_u32(BRIDGE_BUSES) & 0xff00_0000;
        let buses = |subordinate: u8| {
            latency | u32::from(subordinate) << 16 | u32::from(secondary) << 8 | u32::from(a.bus)
        };
        // The subordinate bus is 255 during the scan, so the configuration cycles of each bus
        // behind the bridge go through it.
        a.write_u32(BRIDGE_BUSES, buses(u8::MAX));
        // Each window of the bridge starts at a multiple of its granule, and the BARs behind the
        // bridge come next. The end of the window is the next multiple of the granule after them.
        let align = |h: &mut Host| {
            let mem = h.mem.align(window::MEMORY_GRANULE);
            let mem64 = h.mem64.align(window::MEMORY_GRANULE);
            (mem, mem64, h.io.align(window::IO_GRANULE))
        };
        let (mem, mem64, io) = align(&mut HOST.lock());
        let last = scan_bus(secondary, Some(a), found, next);
        a.write_u32(BRIDGE_BUSES, buses(last));
        let (mem_end, mem64_end, io_end) = align(&mut HOST.lock());
        // The upper half of the I/O window is 0xFFFF while the lower half changes, so that the
        // window does not open at a wrong address, as `pci_setup_bridge_io` of Linux.
        let (io_low, io_high) = window::io_registers(io, io_end);
        a.write_u32(BRIDGE_IO_HIGH, 0xffff);
        a.write_u16(BRIDGE_IO, io_low);
        a.write_u32(BRIDGE_IO_HIGH, io_high);
        a.write_u32(BRIDGE_MEMORY, window::memory_register(mem, mem_end));
        a.write_u32(BRIDGE_PREFETCH, window::memory_register(mem64, mem64_end));
        let (base_high, limit_high) = if mem64_end > mem64 {
            ((mem64 >> 32) as u32, ((mem64_end - 1) >> 32) as u32)
        } else {
            (0, 0)
        };
        a.write_u32(BRIDGE_PREFETCH_BASE_HIGH, base_high);
        a.write_u32(BRIDGE_PREFETCH_LIMIT_HIGH, limit_high);
        // The bridge forwards the memory cycles and the I/O cycles to the bus behind it, and the
        // DMA of the functions behind it to the host.
        let command = a.read_u32(super::COMMAND) as u16;
        let on = super::COMMAND_MEMORY | super::COMMAND_BUS_MASTER;
        a.write_command(command | on | if io_end > io { super::COMMAND_IO } else { 0 });
        last
    }
}

/// The command register and its bits.
const COMMAND: u8 = 0x04;
const COMMAND_IO: u16 = 1 << 0;
const COMMAND_MEMORY: u16 = 1 << 1;
const COMMAND_BUS_MASTER: u16 = 1 << 2;
/// The bit of the command register that turns off the INTx pin.
const COMMAND_INTX_DISABLE: u16 = 1 << 10;
/// The capability ID of MSI-X, and the bits of its message control register in the upper half of
/// the first register of the capability.
const CAP_MSIX: u8 = 0x11;
const MSIX_ENABLE: u32 = 1 << 31;
/// The field of the message control register that gives the size of the MSI-X table less one.
const MSIX_TABLE_SIZE: u32 = 0x7ff << 16;
const MSIX_FUNCTION_MASK: u32 = 1 << 30;
/// The bit of the status register that tells that the function has a capability list.
const STATUS_CAP_LIST: u32 = 1 << 20;
const CAP_POINTER: u8 = 0x34;
const BAR0: u8 = 0x10;

/// The bus, the device and the function of a PCI function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PciAddress {
    /// The bus number.
    pub bus: u8,
    /// The device number, 0 to 31.
    pub device: u8,
    /// The function number, 0 to 7.
    pub function: u8,
}

impl PciAddress {
    fn read_u32(self, offset: u8) -> u32 {
        let _guard = CONFIG.lock();
        config::read_u32(self, offset)
    }

    fn write_u32(self, offset: u8, value: u32) {
        let _guard = CONFIG.lock();
        config::write_u32(self, offset, value);
    }

    #[cfg(target_arch = "aarch64")]
    fn write_u16(self, offset: u8, value: u16) {
        let _guard = CONFIG.lock();
        config::write_u16(self, offset, value);
    }

    fn write_command(self, value: u16) {
        let _guard = CONFIG.lock();
        // The status register is in the upper half, and a write of 1 clears its bits.
        config::write_u16(self, COMMAND, value);
    }
}

/// One function on the PCI bus.
#[derive(Clone, Copy, Debug)]
pub struct PciDevice {
    address: PciAddress,
    vendor: u16,
    device: u16,
    class: u32,
    /// The bridge on the bus above the function, or `None` on bus 0.
    #[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
    parent: Option<PciAddress>,
}

/// The PCI functions that the scan at the first call found.
static DEVICES: Once<Vec<PciDevice>> = Once::new();

/// Gives each function on the PCI bus, in the order of the bus, the device and the function.
pub fn devices() -> &'static [PciDevice] {
    DEVICES.call_once(scan)
}

/// Reads the IDs and the class of the function at `a`, behind the bridge `parent`. A function
/// that is not there gives the vendor ID 0xFFFF, and then the result is `None`.
fn probe(a: PciAddress, parent: Option<PciAddress>) -> Option<PciDevice> {
    let id = a.read_u32(0);
    if id & 0xffff == 0xffff {
        return None;
    }
    let class = a.read_u32(0x08) >> 8;
    Some(PciDevice { address: a, vendor: id as u16, device: (id >> 16) as u16, class, parent })
}

/// Reads the vendor ID of each function of each bus, with the bus numbers that the firmware gave
/// to the bridges.
#[cfg(not(target_arch = "aarch64"))]
fn scan() -> Vec<PciDevice> {
    let mut found = Vec::new();
    for bus in (0..config::buses()).filter_map(|b| u8::try_from(b).ok()) {
        for device in 0..32u8 {
            for function in 0..8u8 {
                let address = PciAddress { bus, device, function };
                let Some(dev) = probe(address, None) else {
                    if function == 0 {
                        break;
                    }
                    continue;
                };
                found.push(dev);
                // Bit 7 of the header type tells that the device has more than one function.
                if function == 0 && address.read_u32(0x0c) & (0x80 << 16) == 0 {
                    break;
                }
            }
        }
    }
    found
}

/// Scans bus 0 and the buses behind its bridges. No firmware gave the bus numbers, so the scan
/// gives them, and it assigns the memory BARs of each function that it finds.
#[cfg(target_arch = "aarch64")]
fn scan() -> Vec<PciDevice> {
    let mut found = Vec::new();
    if config::buses() > 0 {
        host::scan_bus(0, None, &mut found, &mut 1);
    }
    found
}

impl PciDevice {
    /// The bus, the device and the function.
    pub fn address(&self) -> PciAddress {
        self.address
    }

    /// The vendor ID.
    pub fn vendor_id(&self) -> u16 {
        self.vendor
    }

    /// The device ID.
    pub fn device_id(&self) -> u16 {
        self.device
    }

    /// The class code, the subclass and the programming interface, as 24 bits.
    pub fn class(&self) -> u32 {
        self.class
    }

    /// Reads the 32 bit register at `offset` of the configuration space. The two low bits of
    /// `offset` are ignored.
    pub fn read_config(&self, offset: u8) -> u32 {
        self.address.read_u32(offset)
    }

    /// Reads the byte at `offset` of the configuration space.
    pub fn read_config_u8(&self, offset: u8) -> u8 {
        (self.read_config(offset) >> ((offset & 3) * 8)) as u8
    }

    /// Gives the ID and the offset of each capability in the list of the function.
    pub fn capabilities(&self) -> Vec<(u8, u8)> {
        let mut caps = Vec::new();
        if self.read_config(COMMAND) & STATUS_CAP_LIST == 0 {
            return caps;
        }
        let mut offset = self.read_config_u8(CAP_POINTER) & 0xfc;
        // A list with a loop stops after the 48 capabilities that fit in the space.
        while offset >= 0x40 && caps.len() < 48 {
            let header = self.read_config(offset);
            caps.push((header as u8, offset));
            offset = (header >> 8) as u8 & 0xfc;
        }
        caps
    }

    /// Turns on the interrupt line of the INTx pin of the function, and gives it. Gives `None` if
    /// the function has no pin, or if the kernel has no line for the pin: on x86-64 and behind a
    /// bridge.
    pub fn irq(&self) -> Option<Line> {
        #[cfg(target_arch = "aarch64")]
        return host::irq(self);
        #[cfg(not(target_arch = "aarch64"))]
        None
    }

    /// The requester ID of the function: the bus, the device and the function in 16 bits. A
    /// message of the function to the GICv3 ITS has it.
    pub fn requester_id(&self) -> u16 {
        let a = self.address;
        u16::from(a.bus) << 8 | u16::from(a.device & 31) << 3 | u16::from(a.function & 7)
    }

    /// The number of entries of the MSI-X table of the function, and the offset of its MSI-X
    /// capability. Gives `None` if the function has no MSI-X capability.
    fn msix_cap(&self) -> Option<(usize, u8)> {
        let (_, at) = self.capabilities().into_iter().find(|(id, _)| *id == CAP_MSIX)?;
        Some((((self.read_config(at) & MSIX_TABLE_SIZE) >> 16) as usize + 1, at))
    }

    /// The number of entries of the MSI-X table of the function, or 0 if the function has no
    /// MSI-X capability.
    pub fn msix_table_size(&self) -> usize {
        self.msix_cap().map_or(0, |(n, _)| n)
    }

    /// Turns on MSI-X for the function with a line for each of the first `n` entries of its
    /// MSI-X table, and gives the lines in the order of the entries, as `pci_alloc_irq_vectors`
    /// of Linux. The INTx pin of the function is off after this. Gives `None` if `n` is 0, if the
    /// function has no MSI-X capability or a table of less than `n` entries, if its table is not
    /// in a memory BAR, if not enough vectors are free, and on arm64 if the machine has no GICv3
    /// ITS. Then MSI-X stays as it was.
    pub fn msix_vectors(&self, n: usize) -> Option<Vec<Line>> {
        let (size, at) = self.msix_cap()?;
        if n == 0 || n > size {
            return None;
        }
        let table = self.read_config(at + 4);
        let len = n * MSIX_ENTRY_SIZE;
        let table = self.map_bar((table & 7) as u8, u64::from(table & !7), len)?;
        let entries: Vec<usize> = (0..n).map(|k| table.base() + k * MSIX_ENTRY_SIZE).collect();
        #[cfg(target_arch = "x86_64")]
        let lines = Line::msix(&entries)?;
        #[cfg(target_arch = "aarch64")]
        let lines = Line::msix(&entries, host::msi_device_id(self.requester_id())?)?;
        let control = self.read_config(at);
        self.address.write_u32(at, (control | MSIX_ENABLE) & !MSIX_FUNCTION_MASK);
        let command = self.read_config(COMMAND) as u16;
        self.address.write_command(command | COMMAND_INTX_DISABLE);
        Some(lines)
    }

    /// Gives back the lines that `msix_vectors` gave, turns off MSI-X and turns on the INTx pin of
    /// the function again, as `pci_free_irq_vectors` of Linux.
    pub fn msix_free(&self, lines: &[Line]) {
        let Some((_, at)) = self.msix_cap() else { return };
        let control = self.read_config(at);
        self.address.write_u32(at, control & !MSIX_ENABLE);
        #[cfg(target_arch = "x86_64")]
        Line::free_msix(lines);
        #[cfg(target_arch = "aarch64")]
        if let Some(device) = host::msi_device_id(self.requester_id()) {
            Line::free_msix(lines, device);
        }
        let command = self.read_config(COMMAND) as u16;
        self.address.write_command(command & !COMMAND_INTX_DISABLE);
    }

    /// Turns on the memory decoding and the bus master bit, so that the device answers to its
    /// memory registers and can do DMA. If an I/O BAR of the function has an address, it also
    /// turns on the I/O decoding, as `pci_enable_resources` of Linux.
    pub fn enable(&self) {
        let command = self.read_config(COMMAND) as u16;
        let mut io = false;
        let mut bar = 0;
        while bar < 6 {
            let low = self.read_config(BAR0 + bar * 4);
            io |= low & 1 != 0 && low & !3 != 0;
            // The upper half of a 64 bit memory BAR is not a BAR.
            bar += if low & 7 == 4 { 2 } else { 1 };
        }
        let on = COMMAND_MEMORY | COMMAND_BUS_MASTER | if io { COMMAND_IO } else { 0 };
        self.address.write_command(command | on);
    }

    /// Gives the PCI address and the size of the I/O BAR `bar`, or `None` for a memory BAR or an
    /// I/O BAR without an address.
    fn io_bar(&self, bar: u8) -> Option<(u64, u64)> {
        if bar > 5 {
            return None;
        }
        let offset = BAR0 + bar * 4;
        let low = self.read_config(offset);
        if low & 1 == 0 || low & !3 == 0 {
            return None;
        }
        // The I/O decoding is off during the size probe.
        let command = self.read_config(COMMAND) as u16;
        self.address.write_command(command & !COMMAND_IO);
        self.address.write_u32(offset, u32::MAX);
        let mask = self.read_config(offset);
        self.address.write_u32(offset, low);
        self.address.write_command(command);
        let size = window::io_bar_size(mask);
        (size != 0).then_some((u64::from(low & !3), size))
    }

    /// Maps `len` bytes at `offset` in the I/O BAR `bar`. On arm64 the CPU sees the I/O space of
    /// the host as memory, as `pci_iomap` of Linux. Gives `None` if the range is not in the BAR,
    /// if no virtual address is free, and on x86-64, where the I/O space is the I/O ports.
    pub fn map_io_bar(&self, bar: u8, offset: u64, len: usize) -> Option<IoMem> {
        let (base, size) = self.io_bar(bar)?;
        if len == 0 || offset.checked_add(len as u64)? > size {
            return None;
        }
        #[cfg(target_arch = "aarch64")]
        return map_registers(host::io_cpu(base + offset, len as u64)?, len);
        #[cfg(not(target_arch = "aarch64"))]
        {
            let _ = base;
            None
        }
    }

    /// Gives the physical address and the size of the memory BAR `bar`, or `None` for an I/O
    /// BAR, a BAR without an address, or the upper half of a 64 bit BAR.
    fn memory_bar(&self, bar: u8) -> Option<(u64, u64)> {
        if bar > 5 {
            return None;
        }
        let offset = BAR0 + bar * 4;
        let low = self.read_config(offset);
        if low & 1 != 0 {
            return None;
        }
        let wide = (low >> 1) & 3 == 2;
        if wide && bar == 5 {
            return None;
        }
        let high = if wide { self.read_config(offset + 4) } else { 0 };
        // The size probe writes all ones and reads the mask back. The memory decoding is off
        // during the probe, so that the device does not answer at the probe address.
        let command = self.read_config(COMMAND) as u16;
        self.address.write_command(command & !COMMAND_MEMORY);
        self.address.write_u32(offset, u32::MAX);
        let mask_low = self.read_config(offset);
        self.address.write_u32(offset, low);
        let mask_high = if wide {
            self.address.write_u32(offset + 4, u32::MAX);
            let m = self.read_config(offset + 4);
            self.address.write_u32(offset + 4, high);
            m
        } else {
            u32::MAX
        };
        self.address.write_command(command);
        let mask = (u64::from(mask_high) << 32) | u64::from(mask_low & !0xf);
        let size = (!mask).wrapping_add(1);
        let base = (u64::from(high) << 32) | u64::from(low & !0xf);
        (base != 0 && size != 0).then_some((base, size))
    }

    /// Maps `len` bytes at `offset` in the memory BAR `bar`. Gives `None` if the range is not in
    /// the BAR, if the BAR is on RAM, or if no virtual address is free.
    pub fn map_bar(&self, bar: u8, offset: u64, len: usize) -> Option<IoMem> {
        let (base, size) = self.memory_bar(bar)?;
        let end = offset.checked_add(len as u64)?;
        if len == 0 || end > size {
            return None;
        }
        let bar_end = base.checked_add(size)?;
        let ram = crate::boot::info()?.memory().iter().filter(|r| {
            matches!(
                r.kind,
                MemoryKind::Usable
                    | MemoryKind::AcpiReclaimable
                    | MemoryKind::AcpiNvs
                    | MemoryKind::Persistent
            )
        });
        if base < 1 << 20
            || ram.into_iter().any(|r| base < r.start.get() + r.len && r.start.get() < bar_end)
        {
            return None;
        }
        map_registers(base + offset, len)
    }
}

/// The highest device ID of the GICv3 ITS of the functions that the scan found.
#[cfg(target_arch = "aarch64")]
pub(crate) fn max_device_id() -> u32 {
    devices().iter().filter_map(|d| host::msi_device_id(d.requester_id())).max().unwrap_or(0)
}

/// The size of an entry of the MSI-X table.
#[cfg(target_arch = "x86_64")]
const MSIX_ENTRY_SIZE: usize = crate::arch::imp::msi::ENTRY_SIZE;
#[cfg(target_arch = "aarch64")]
const MSIX_ENTRY_SIZE: usize = crate::arch::imp::its::ENTRY_SIZE;

/// Maps `len` bytes of device registers at the physical address `start`. The caller checked that
/// the range is not RAM.
#[cfg(target_arch = "x86_64")]
fn map_registers(start: u64, len: usize) -> Option<IoMem> {
    let page = start & !(PAGE_SIZE as u64 - 1);
    let in_page = (start - page) as usize;
    let pages = (in_page + len).div_ceil(PAGE_SIZE);
    let virt = crate::mm::frame::vmap_mmio_pages(page, pages)?;
    // SAFETY: the pages map the registers of the BAR without cache, and they are not RAM.
    Some(unsafe { IoMem::new(virt + in_page, len) })
}

/// Maps `len` bytes of device registers at the physical address `start`. The BARs are in the
/// windows of the ECAM host, below 512 GiB, so the device window at `MMIO_BASE` maps them.
#[cfg(target_arch = "aarch64")]
fn map_registers(start: u64, len: usize) -> Option<IoMem> {
    let info = crate::boot::info()?;
    let virt = crate::arch::imp::paging::map_device(start, len as u64, info)?;
    // SAFETY: `map_device` maps the range as device memory for all of the run time, and the
    // caller checked that the range is not RAM.
    Some(unsafe { IoMem::new(virt, len) })
}

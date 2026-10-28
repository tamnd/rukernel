//! The PCI bus: the configuration space of each function and the memory registers of its BARs.
//!
//! rk-frame reads the configuration space through the legacy ports 0xCF8 and 0xCFC. A driver gets
//! a `PciDevice` from `devices` and reads its configuration space. It can turn on the memory
//! decoding and the bus master bit, and map a range of a memory BAR as an `IoMem`. It cannot
//! write other registers of the configuration space, because a BAR that moves onto RAM breaks
//! the memory safety of the kernel.
//!
//! A device with the bus master bit can write each physical address. rukernel has no IOMMU
//! driver yet, so the kernel trusts the device and the driver to give the device only the
//! addresses of the frames that the driver owns. AUDITED.md records this.

use crate::addr::PAGE_SIZE;
use crate::arch::imp::io::Port;
use crate::boot::MemoryKind;
use crate::sync::{Once, SpinLock};
use alloc::vec::Vec;

pub use crate::iomem::IoMem;

/// The address register and the data register of the configuration space. The lock keeps the
/// two accesses of one read together.
static CONFIG: SpinLock<()> = SpinLock::new(());

// SAFETY: 0xCF8 and 0xCFC are the configuration ports of the PCI host bridge. Only this module
// uses them, and a read or a write of the configuration space does not touch memory.
const ADDRESS: Port = unsafe { Port::new(0xcf8) };
// SAFETY: as for `ADDRESS`.
const DATA: Port = unsafe { Port::new(0xcfc) };

/// The command register and its bits.
const COMMAND: u8 = 0x04;
const COMMAND_MEMORY: u16 = 1 << 1;
const COMMAND_BUS_MASTER: u16 = 1 << 2;
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
    fn config_address(self, offset: u8) -> u32 {
        (1 << 31)
            | (u32::from(self.bus) << 16)
            | (u32::from(self.device) << 11)
            | (u32::from(self.function) << 8)
            | u32::from(offset & 0xfc)
    }

    fn read_u32(self, offset: u8) -> u32 {
        let _guard = CONFIG.lock();
        ADDRESS.write_u32(self.config_address(offset));
        DATA.read_u32()
    }

    fn write_u32(self, offset: u8, value: u32) {
        let _guard = CONFIG.lock();
        ADDRESS.write_u32(self.config_address(offset));
        DATA.write_u32(value);
    }

    fn write_command(self, value: u16) {
        let _guard = CONFIG.lock();
        ADDRESS.write_u32(self.config_address(COMMAND));
        // The status register is in the upper half, and a write of 1 clears its bits.
        DATA.write_u16(value);
    }
}

/// One function on the PCI bus.
#[derive(Clone, Copy, Debug)]
pub struct PciDevice {
    address: PciAddress,
    vendor: u16,
    device: u16,
    class: u32,
}

/// The PCI functions that the scan at the first call found.
static DEVICES: Once<Vec<PciDevice>> = Once::new();

/// Gives each function on the PCI bus, in the order of the bus, the device and the function.
pub fn devices() -> &'static [PciDevice] {
    DEVICES.call_once(scan)
}

/// Reads the vendor ID of each function of each bus. A bus without a function gives 0xFFFF.
fn scan() -> Vec<PciDevice> {
    let mut found = Vec::new();
    for bus in 0..=255u8 {
        for device in 0..32u8 {
            for function in 0..8u8 {
                let address = PciAddress { bus, device, function };
                let id = address.read_u32(0);
                if id & 0xffff == 0xffff {
                    if function == 0 {
                        break;
                    }
                    continue;
                }
                let class = address.read_u32(0x08) >> 8;
                found.push(PciDevice {
                    address,
                    vendor: id as u16,
                    device: (id >> 16) as u16,
                    class,
                });
                // Bit 7 of the header type tells that the device has more than one function.
                if function == 0 && address.read_u32(0x0c) & (0x80 << 16) == 0 {
                    break;
                }
            }
        }
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

    /// Turns on the memory decoding and the bus master bit, so that the device answers to its
    /// memory registers and can do DMA.
    pub fn enable(&self) {
        let command = self.read_config(COMMAND) as u16;
        self.address.write_command(command | COMMAND_MEMORY | COMMAND_BUS_MASTER);
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
        let start = base + offset;
        let page = start & !(PAGE_SIZE as u64 - 1);
        let in_page = (start - page) as usize;
        let pages = (in_page + len).div_ceil(PAGE_SIZE);
        let virt = crate::mm::frame::vmap_mmio_pages(page, pages)?;
        // SAFETY: the pages map the registers of the BAR without cache, and they are not RAM.
        Some(unsafe { IoMem::new(virt + in_page, len) })
    }
}

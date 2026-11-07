//! The devices on the buses, for `/sys/bus`, `/sys/devices` and `/sys/module`: the PCI
//! functions, the platform devices of the device tree, and the virtio devices on them.
//!
//! The drivers give the lists when they start. sysfs reads them, as drivers/pci/pci-sysfs.c,
//! drivers/base/platform.c and drivers/virtio/virtio.c of Linux show them.
//!
//! A disk of a virtio device has its directory in the directory of the virtio device, as
//! `/devices/pci0000:00/0000:00:02.0/virtio1/block/vda`. [`set_block_parent`] gives the virtio
//! device of a disk.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use rk_frame::sync::SpinLock;

/// One function on the PCI bus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PciFunction {
    /// The bus number.
    pub bus: u8,
    /// The device number.
    pub slot: u8,
    /// The function number.
    pub function: u8,
    /// The vendor ID.
    pub vendor: u16,
    /// The device ID.
    pub device: u16,
    /// The class code, the subclass and the programming interface.
    pub class: u32,
    /// The revision ID.
    pub revision: u8,
    /// The subsystem vendor ID.
    pub subsystem_vendor: u16,
    /// The subsystem ID.
    pub subsystem_device: u16,
    /// The interrupt line of the configuration space.
    pub irq: u8,
    /// The name of the driver of the function, as `virtio-pci`.
    pub driver: Option<&'static str>,
}

impl PciFunction {
    /// The name of the function, as `pci_name` of Linux: `0000:00:01.0`.
    #[must_use]
    pub fn name(&self) -> String {
        format!("0000:{:02x}:{:02x}.{:x}", self.bus, self.slot, self.function)
    }

    /// The modalias of the function, as `pci_uevent` of Linux.
    #[must_use]
    pub fn modalias(&self) -> String {
        format!(
            "pci:v{:08X}d{:08X}sv{:08X}sd{:08X}bc{:02X}sc{:02X}i{:02X}",
            self.vendor,
            self.device,
            self.subsystem_vendor,
            self.subsystem_device,
            (self.class >> 16) as u8,
            (self.class >> 8) as u8,
            self.class as u8
        )
    }

    /// The variables of the event of the function, as `dev_uevent` and `pci_uevent` of Linux.
    #[must_use]
    pub fn uevent(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(d) = self.driver {
            out.push(format!("DRIVER={d}"));
        }
        out.push(format!("PCI_CLASS={:X}", self.class));
        out.push(format!("PCI_ID={:04X}:{:04X}", self.vendor, self.device));
        out.push(format!(
            "PCI_SUBSYS_ID={:04X}:{:04X}",
            self.subsystem_vendor, self.subsystem_device
        ));
        out.push(format!("PCI_SLOT_NAME={}", self.name()));
        out.push(format!("MODALIAS={}", self.modalias()));
        out
    }
}

/// A platform device of the device tree: a virtio MMIO transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformDevice {
    /// The physical address of the registers.
    pub phys: u64,
    /// The name of the node of the device tree, as `virtio_mmio`.
    pub node: &'static str,
    /// The first string of the property `compatible`, as `virtio,mmio`.
    pub compatible: &'static str,
    /// The name of the driver of the device, as `virtio-mmio`.
    pub driver: Option<&'static str>,
}

impl PlatformDevice {
    /// The name of the device, as `of_device_make_bus_id` of Linux: `a000000.virtio_mmio`.
    #[must_use]
    pub fn name(&self) -> String {
        format!("{:x}.{}", self.phys, self.node)
    }

    /// The modalias of the device, as `of_modalias` of Linux.
    #[must_use]
    pub fn modalias(&self) -> String {
        format!("of:N{}T(null)C{}", self.node, self.compatible)
    }

    /// The variables of the event of the device, as `of_device_uevent` of Linux.
    #[must_use]
    pub fn uevent(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(d) = self.driver {
            out.push(format!("DRIVER={d}"));
        }
        out.push(format!("OF_NAME={}", self.node));
        out.push(format!("OF_FULLNAME=/{}@{:x}", self.node, self.phys));
        out.push(format!("OF_COMPATIBLE_0={}", self.compatible));
        out.push(String::from("OF_COMPATIBLE_N=1"));
        out.push(format!("MODALIAS={}", self.modalias()));
        out
    }
}

/// The transport of a virtio device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// A PCI function: the bus, the device and the function.
    Pci(u8, u8, u8),
    /// A virtio MMIO device at a physical address.
    Mmio(u64),
}

/// A device on the virtio bus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtioDevice {
    /// The number of the device on the bus: `virtio0` has 0.
    pub index: u32,
    /// The transport of the device.
    pub transport: Transport,
    /// The virtio device ID, as 1 for a network device.
    pub device: u32,
    /// The vendor ID.
    pub vendor: u32,
    /// The name of the driver of the device, as `virtio_net`.
    pub driver: Option<&'static str>,
}

impl VirtioDevice {
    /// The name of the device: `virtio0`.
    #[must_use]
    pub fn name(&self) -> String {
        format!("virtio{}", self.index)
    }

    /// The modalias of the device, as `virtio_uevent` of Linux.
    #[must_use]
    pub fn modalias(&self) -> String {
        format!("virtio:d{:08X}v{:08X}", self.device, self.vendor)
    }

    /// The variables of the event of the device.
    #[must_use]
    pub fn uevent(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(d) = self.driver {
            out.push(format!("DRIVER={d}"));
        }
        out.push(format!("MODALIAS={}", self.modalias()));
        out
    }
}

/// The devices of each bus.
struct Buses {
    pci: Vec<PciFunction>,
    platform: Vec<PlatformDevice>,
    virtio: Vec<VirtioDevice>,
    /// The number of the block device and the number of its virtio device, for each disk of a
    /// virtio device.
    disks: Vec<(u64, u32)>,
}

static BUSES: SpinLock<Buses> = SpinLock::new(Buses {
    pci: Vec::new(),
    platform: Vec::new(),
    virtio: Vec::new(),
    disks: Vec::new(),
});

/// Adds a function on the PCI bus. A function with the same name is changed.
pub fn add_pci(f: PciFunction) {
    let mut b = BUSES.lock();
    b.pci.retain(|g| g.name() != f.name());
    b.pci.push(f);
    b.pci.sort_by_key(|g| (g.bus, g.slot, g.function));
}

/// Adds a platform device. A device with the same name is changed.
pub fn add_platform(d: PlatformDevice) {
    let mut b = BUSES.lock();
    b.platform.retain(|g| g.name() != d.name());
    b.platform.push(d);
    b.platform.sort_by_key(|g| g.phys);
}

/// Adds a device on the virtio bus. A device with the same number is changed.
pub fn add_virtio(d: VirtioDevice) {
    let mut b = BUSES.lock();
    b.virtio.retain(|g| g.index != d.index);
    b.virtio.push(d);
    b.virtio.sort_by_key(|g| g.index);
}

/// Puts the block device with the number `rdev` below the virtio device with the number `index`.
/// The driver calls it before it adds the disk, so the event of the disk has the path of Linux.
pub fn set_block_parent(rdev: u64, index: u32) {
    let mut b = BUSES.lock();
    b.disks.retain(|&(r, _)| r != rdev);
    b.disks.push((rdev, index));
}

/// The path of the directory of the virtio device of the block device `rdev` below `/sys`, if
/// the disk is on a virtio device.
#[must_use]
pub fn block_parent(rdev: u64) -> Option<String> {
    let b = BUSES.lock();
    let &(_, index) = b.disks.iter().find(|&&(r, _)| r == rdev)?;
    let d = b.virtio.iter().find(|d| d.index == index)?.clone();
    drop(b);
    Some(virtio_path(&d))
}

/// The path of the directory of the virtio device with the name `name` below `/sys`, as
/// `/devices/pci0000:00/0000:00:03.0/virtio2`.
#[must_use]
pub fn virtio_named(name: &str) -> Option<String> {
    let d = virtio().into_iter().find(|d| d.name() == name)?;
    Some(virtio_path(&d))
}

/// The path of the directory of the virtio device `d` below `/sys`.
#[must_use]
pub fn virtio_path(d: &VirtioDevice) -> String {
    format!("{}/{}", transport_path(d.transport), d.name())
}

/// The functions on the PCI bus, in the order of the bus.
#[must_use]
pub fn pci() -> Vec<PciFunction> {
    BUSES.lock().pci.clone()
}

/// The platform devices, in the order of their addresses.
#[must_use]
pub fn platform() -> Vec<PlatformDevice> {
    BUSES.lock().platform.clone()
}

/// The devices on the virtio bus, in the order of their numbers.
#[must_use]
pub fn virtio() -> Vec<VirtioDevice> {
    BUSES.lock().virtio.clone()
}

/// The name of the directory of the root bus of PCI below `/sys/devices`. All functions are in
/// it, also the ones behind a bridge, where Linux puts them in the directory of the bridge.
pub const PCI_ROOT: &str = "pci0000:00";

/// The path of the directory of the transport `t` below `/sys`, as
/// `/devices/pci0000:00/0000:00:01.0`.
#[must_use]
pub fn transport_path(t: Transport) -> String {
    match t {
        Transport::Pci(bus, slot, function) => {
            format!("/devices/{PCI_ROOT}/0000:{bus:02x}:{slot:02x}.{function:x}")
        }
        Transport::Mmio(phys) => {
            let node =
                platform().into_iter().find(|d| d.phys == phys).map_or("virtio_mmio", |d| d.node);
            format!("/devices/platform/{phys:x}.{node}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_function_has_the_names_of_linux() {
        let f = PciFunction {
            bus: 0,
            slot: 2,
            function: 0,
            vendor: 0x1af4,
            device: 0x1000,
            class: 0x02_0000,
            revision: 0,
            subsystem_vendor: 0x1af4,
            subsystem_device: 1,
            irq: 11,
            driver: Some("virtio-pci"),
        };
        assert_eq!(f.name(), "0000:00:02.0");
        assert_eq!(f.modalias(), "pci:v00001AF4d00001000sv00001AF4sd00000001bc02sc00i00");
        assert_eq!(
            f.uevent(),
            [
                "DRIVER=virtio-pci",
                "PCI_CLASS=20000",
                "PCI_ID=1AF4:1000",
                "PCI_SUBSYS_ID=1AF4:0001",
                "PCI_SLOT_NAME=0000:00:02.0",
                "MODALIAS=pci:v00001AF4d00001000sv00001AF4sd00000001bc02sc00i00",
            ]
        );
        let v = VirtioDevice {
            index: 0,
            transport: Transport::Pci(0, 2, 0),
            device: 1,
            vendor: 0x1af4,
            driver: Some("virtio_net"),
        };
        assert_eq!(v.modalias(), "virtio:d00000001v00001AF4");
        assert_eq!(transport_path(v.transport), "/devices/pci0000:00/0000:00:02.0");
        assert_eq!(virtio_path(&v), "/devices/pci0000:00/0000:00:02.0/virtio0");
        let p = PlatformDevice {
            phys: 0xa00_0000,
            node: "virtio_mmio",
            compatible: "virtio,mmio",
            driver: Some("virtio-mmio"),
        };
        assert_eq!(p.name(), "a000000.virtio_mmio");
        assert_eq!(p.modalias(), "of:Nvirtio_mmioT(null)Cvirtio,mmio");
    }

    #[test]
    fn a_disk_is_below_its_virtio_device() {
        add_virtio(VirtioDevice {
            index: 41,
            transport: Transport::Pci(0, 9, 0),
            device: 2,
            vendor: 0x1af4,
            driver: Some("virtio_blk"),
        });
        set_block_parent(0xfe_0000_00f0, 41);
        assert_eq!(
            block_parent(0xfe_0000_00f0).as_deref(),
            Some("/devices/pci0000:00/0000:00:09.0/virtio41")
        );
        assert_eq!(
            virtio_named("virtio41").as_deref(),
            Some("/devices/pci0000:00/0000:00:09.0/virtio41")
        );
        assert_eq!(block_parent(0xfe_0000_00e0), None);
    }
}

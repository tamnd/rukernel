//! The virtio drivers of rukernel.
//!
//! A virtio device on PCI is a function of the vendor 0x1AF4. The driver uses the modern PCI
//! transport of virtio 1.0: the capabilities of the function give the BAR ranges of the common
//! configuration, the notification registers, the ISR status and the configuration of the device.
//! On arm64 the device tree also gives the virtio MMIO devices, and the driver uses the modern MMIO
//! transport for them. Each queue is a split virtqueue in three frames: the descriptor table, the
//! available ring and the used ring.
//!
//! A request of virtio-blk waits for the device in a loop that reads the used ring. The kernel
//! does not preempt a task in the kernel, so the queue of a disk does one request at a time under
//! a lock. virtio-net keeps many buffers in its queues, and the network device layer polls the
//! device for received frames when the interrupt of the device came. The interrupt wakes the wait
//! of virtio-blk and an idle CPU. On arm64 it is an SPI of the GIC for the INTx line of a PCI
//! device and for the line of an MMIO device, and an LPI of the GICv3 ITS for an MSI-X vector. On
//! x86-64 it is an MSI-X vector. A PCI device with MSI-X gets a vector for its configuration and a
//! vector for each queue, or else one shared vector, as Linux. A device without an interrupt is
//! polled.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

// The queue code uses the ring layout only on the kernel target. On the host, only the tests use it.
#[cfg_attr(
    not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))),
    allow(dead_code)
)]
mod ring;
// The same for the MSI-X vectors of the PCI transport.
#[cfg_attr(
    not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))),
    allow(dead_code)
)]
mod vectors;
// The same for the header of virtio-net.
#[cfg_attr(
    not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))),
    allow(dead_code)
)]
mod net_hdr;

#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod blk;
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
mod mmio;
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod net;
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod pci;
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod queue;
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod transport;

/// The PCI vendor ID of virtio devices.
pub const VIRTIO_VENDOR: u16 = 0x1af4;

/// The virtio device IDs of a network device and of a block device, from section 5 of the virtio
/// 1.2 specification.
pub const DEVICE_NET: u32 = 1;
/// The virtio device ID of a block device.
pub const DEVICE_BLK: u32 = 2;

/// The major number of virtio-blk disks. Linux gives the number at run time, and 254 is the
/// number that a usual system gets.
pub const VIRTBLK_MAJOR: u32 = 254;

/// The drivers that `init` started, for the names of the devices.
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
#[derive(Default)]
struct Probe {
    disks: u32,
    nics: u32,
}

#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
impl Probe {
    /// Starts the driver for the device with the virtio device ID `id` on the transport `t`.
    /// `bus` is the number of the device among all virtio devices, and `place` tells where the
    /// device is, from the kind of its interrupt. `bus_info` is the name of the device on its
    /// bus, as `virtio_bus_name` of Linux gives it. `on` is the transport, for sysfs.
    fn add(
        &mut self,
        id: u32,
        t: transport::Transport,
        bus: u32,
        bus_info: alloc::string::String,
        place: impl Fn(&str) -> alloc::string::String,
        on: rk_vfs::bus::Transport,
    ) {
        let driver = match id {
            DEVICE_BLK => blk::probe(t, self.disks).map(|(name, kind)| {
                rk_frame::println!("virtio: {name} on {}", place(&kind));
                self.disks += 1;
                "virtio_blk"
            }),
            DEVICE_NET => net::probe(t, self.nics, bus, bus_info).map(|(nic, kind)| {
                let place = place(&kind);
                rk_frame::println!("virtio: {} on {place}, MAC {}", nic.name(), nic.mac());
                self.nics += 1;
                "virtio_net"
            }),
            _ => None,
        };
        rk_vfs::bus::add_virtio(rk_vfs::bus::VirtioDevice {
            index: bus,
            transport: on,
            device: id,
            vendor: u32::from(VIRTIO_VENDOR),
            driver,
        });
    }
}

#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
impl Probe {
    /// Starts a driver for each virtio device on the PCI bus. `bus` is the number of the first
    /// device among all virtio devices, and the call gives the number after the last device.
    fn pci(&mut self, mut bus: u32) -> u32 {
        for dev in rk_frame::pci::devices() {
            let a = dev.address();
            let mut driver = None;
            if dev.vendor_id() == VIRTIO_VENDOR {
                let this = bus;
                bus += 1;
                if let Some(id) = pci::device_type(dev)
                    && matches!(id, DEVICE_BLK | DEVICE_NET)
                    && let Some(t) = pci::PciTransport::new(dev)
                {
                    let place = |kind: &str| alloc::format!("PCI {:?} with {kind}", dev.address());
                    let bus_info =
                        alloc::format!("{:04x}:{:02x}:{:02x}.{:x}", 0, a.bus, a.device, a.function);
                    let on = rk_vfs::bus::Transport::Pci(a.bus, a.device, a.function);
                    self.add(id, transport::Transport::Pci(t), this, bus_info, place, on);
                    driver = Some("virtio-pci");
                }
            }
            let subsystem = dev.read_config(0x2c);
            rk_vfs::bus::add_pci(rk_vfs::bus::PciFunction {
                bus: a.bus,
                slot: a.device,
                function: a.function,
                vendor: dev.vendor_id(),
                device: dev.device_id(),
                class: dev.class(),
                revision: dev.read_config_u8(0x08),
                subsystem_vendor: subsystem as u16,
                subsystem_device: (subsystem >> 16) as u16,
                irq: dev.read_config_u8(0x3c),
                driver,
            });
        }
        bus
    }
}

/// Finds the virtio devices on the PCI bus and starts a driver for each device that rukernel
/// knows. A disk gets the name `vda`, `vdb` and so on, in the order of the bus. A network device
/// gets the name `eth0`, `eth1` and so on from the network device layer, so the kernel calls
/// `rk_net::dev::init` first to give the loopback device the first index.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub fn init() {
    Probe::default().pci(0);
}

/// Finds the virtio MMIO devices of the device tree and starts a driver for each device that
/// rukernel knows, as `init` on x86-64 does for the PCI bus. The devices are in the order of the
/// device tree, as Linux finds them. Then the call does the same for the virtio devices on the PCI
/// bus of the ECAM host, and the names continue after the MMIO devices.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub fn init() {
    let mut probe = Probe::default();
    let mut bus = 0u32;
    for dev in rk_frame::iomem::virtio_mmio_devices() {
        // Each node of the device tree is a platform device. The driver takes the ones that have
        // a device, as `virtio_mmio_probe` of Linux.
        let mut platform = rk_vfs::bus::PlatformDevice {
            phys: dev.phys(),
            node: "virtio_mmio",
            compatible: "virtio,mmio",
            driver: None,
        };
        let Some(regs) = dev.map() else {
            rk_vfs::bus::add_platform(platform);
            continue;
        };
        // A transport without a device does not get its line.
        let Some((id, t)) = mmio::MmioTransport::new(regs, dev.phys(), || dev.irq()) else {
            rk_vfs::bus::add_platform(platform);
            continue;
        };
        platform.driver = Some("virtio-mmio");
        rk_vfs::bus::add_platform(platform);
        if matches!(id, DEVICE_BLK | DEVICE_NET) {
            let place = |_: &str| alloc::format!("MMIO {:#x}", dev.phys());
            let bus_info = alloc::format!("{:x}.virtio_mmio", dev.phys());
            let on = rk_vfs::bus::Transport::Mmio(dev.phys());
            probe.add(id, transport::Transport::Mmio(t), bus, bus_info, place, on);
        }
        bus += 1;
    }
    probe.pci(bus);
}

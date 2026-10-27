//! The virtio drivers of rukernel.
//!
//! On x86-64 a virtio device is a PCI function of the vendor 0x1AF4. The driver uses the modern
//! PCI transport of virtio 1.0: the capabilities of the function give the BAR ranges of the common
//! configuration, the notification registers and the configuration of the device. On arm64 the
//! device tree gives the virtio MMIO devices, and the driver uses the modern MMIO transport. Each
//! queue is a split virtqueue in three frames: the descriptor table, the available ring and the
//! used ring.
//!
//! The drivers do not use interrupts yet. A request of virtio-blk waits for the device in a loop
//! that reads the used ring. The kernel does not preempt a task in the kernel, so the queue of a
//! disk does one request at a time under a lock. virtio-net keeps many buffers in its queues, and
//! the network device layer polls the device for received frames.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

// The queue code uses the ring layout only on the kernel target. On the host, only the tests use it.
#[cfg_attr(
    not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))),
    allow(dead_code)
)]
mod ring;
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
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
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
    /// device is.
    fn add(&mut self, id: u32, t: transport::Transport, bus: u32, place: core::fmt::Arguments<'_>) {
        match id {
            DEVICE_BLK => {
                if let Some(name) = blk::probe(t, self.disks) {
                    rk_frame::println!("virtio: {name} on {place}");
                    self.disks += 1;
                }
            }
            DEVICE_NET => {
                if let Some(nic) = net::probe(t, self.nics, bus) {
                    rk_frame::println!("virtio: {} on {place}, MAC {}", nic.name(), nic.mac());
                    self.nics += 1;
                }
            }
            _ => {}
        }
    }
}

/// Finds the virtio devices on the PCI bus and starts a driver for each device that rukernel
/// knows. A disk gets the name `vda`, `vdb` and so on, in the order of the bus. A network device
/// gets the name `eth0`, `eth1` and so on from the network device layer, so the kernel calls
/// `rk_net::dev::init` first to give the loopback device the first index.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub fn init() {
    let mut probe = Probe::default();
    let virtio = rk_frame::pci::devices().iter().filter(|d| d.vendor_id() == VIRTIO_VENDOR);
    for (bus, dev) in (0u32..).zip(virtio) {
        let Some(id) = pci::device_type(dev) else { continue };
        if !matches!(id, DEVICE_BLK | DEVICE_NET) {
            continue;
        }
        if let Some(t) = pci::PciTransport::new(dev) {
            probe.add(
                id,
                transport::Transport::Pci(t),
                bus,
                format_args!("PCI {:?}", dev.address()),
            );
        }
    }
}

/// Finds the virtio MMIO devices of the device tree and starts a driver for each device that
/// rukernel knows, as `init` on x86-64 does for the PCI bus. The devices are in the order of the
/// device tree, as Linux finds them.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub fn init() {
    let mut probe = Probe::default();
    let mut bus = 0u32;
    for dev in rk_frame::iomem::virtio_mmio_devices() {
        let Some((id, t)) = dev.map().and_then(|regs| mmio::MmioTransport::new(regs, dev.phys()))
        else {
            continue;
        };
        if matches!(id, DEVICE_BLK | DEVICE_NET) {
            probe.add(
                id,
                transport::Transport::Mmio(t),
                bus,
                format_args!("MMIO {:#x}", dev.phys()),
            );
        }
        bus += 1;
    }
}

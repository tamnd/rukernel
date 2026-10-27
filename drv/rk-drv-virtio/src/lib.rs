//! The virtio drivers of rukernel.
//!
//! A virtio device is a PCI function of the vendor 0x1AF4. The driver uses the modern PCI
//! transport of virtio 1.0: the capabilities of the function give the BAR ranges of the common
//! configuration, the notification registers and the configuration of the device. Each queue is
//! a split virtqueue in three frames: the descriptor table, the available ring and the used ring.
//!
//! The drivers do not use interrupts yet. A request of virtio-blk waits for the device in a loop
//! that reads the used ring. The kernel does not preempt a task in the kernel, so the queue of a
//! disk does one request at a time under a lock. virtio-net keeps many buffers in its queues, and
//! the network device layer polls the device for received frames.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

// The queue code uses the ring layout only on the kernel target. On the host, only the tests use it.
#[cfg_attr(not(all(target_os = "none", target_arch = "x86_64")), allow(dead_code))]
mod ring;
// The same for the header of virtio-net.
#[cfg_attr(not(all(target_os = "none", target_arch = "x86_64")), allow(dead_code))]
mod net_hdr;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod blk;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod net;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod pci;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod queue;

/// The PCI vendor ID of virtio devices.
pub const VIRTIO_VENDOR: u16 = 0x1af4;

/// The major number of virtio-blk disks. Linux gives the number at run time, and 254 is the
/// number that a usual system gets.
pub const VIRTBLK_MAJOR: u32 = 254;

/// Finds the virtio devices on the PCI bus and starts a driver for each device that rukernel
/// knows. A disk gets the name `vda`, `vdb` and so on, in the order of the bus. A network device
/// gets the name `eth0`, `eth1` and so on from the network device layer, so the kernel calls
/// `rk_net::dev::init` first to give the loopback device the first index.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub fn init() {
    let (mut disks, mut nics) = (0u32, 0u32);
    for dev in rk_frame::pci::devices().iter().filter(|d| d.vendor_id() == VIRTIO_VENDOR) {
        if blk::is_blk(dev) {
            if let Some(name) = blk::probe(dev, disks) {
                rk_frame::println!("virtio: {name} on PCI {:?}", dev.address());
                disks += 1;
            }
        } else if net::is_net(dev) {
            if let Some(nic) = net::probe(dev, nics) {
                rk_frame::println!(
                    "virtio: {} on PCI {:?}, MAC {}",
                    nic.name(),
                    dev.address(),
                    nic.mac()
                );
                nics += 1;
            }
        }
    }
}

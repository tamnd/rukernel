//! The virtio drivers of rukernel.
//!
//! A virtio device is a PCI function of the vendor 0x1AF4. The driver uses the modern PCI
//! transport of virtio 1.0: the capabilities of the function give the BAR ranges of the common
//! configuration, the notification registers and the configuration of the device. Each queue is
//! a split virtqueue in three frames: the descriptor table, the available ring and the used ring.
//!
//! The drivers do not use interrupts yet. A request waits for the device in a loop that reads
//! the used ring. The kernel does not preempt a task in the kernel, so the queue of a device
//! does one request at a time under a lock.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

// The queue code uses the ring layout only on the kernel target. On the host, only the tests use it.
#[cfg_attr(not(all(target_os = "none", target_arch = "x86_64")), allow(dead_code))]
mod ring;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod blk;
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
/// knows. A disk gets the name `vda`, `vdb` and so on, in the order of the bus.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub fn init() {
    let mut disks = 0u32;
    for dev in rk_frame::pci::devices().iter().filter(|d| d.vendor_id() == VIRTIO_VENDOR) {
        if blk::is_blk(dev) {
            if let Some(name) = blk::probe(dev, disks) {
                rk_frame::println!("virtio: {name} on PCI {:?}", dev.address());
                disks += 1;
            }
        }
    }
}

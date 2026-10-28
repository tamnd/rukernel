//! The modern virtio PCI transport, from section 4.1 of the virtio 1.2 specification.

use crate::transport::{QueueAddrs, status};
use rk_frame::pci::{IoMem, PciDevice};

/// The capability ID of the vendor specific capabilities that virtio uses.
const CAP_VENDOR: u8 = 0x09;
const CFG_COMMON: u8 = 1;
const CFG_NOTIFY: u8 = 2;
const CFG_DEVICE: u8 = 4;

/// The registers of the common configuration.
mod common {
    pub(crate) const DEVICE_FEATURE_SELECT: usize = 0x00;
    pub(crate) const DEVICE_FEATURE: usize = 0x04;
    pub(crate) const DRIVER_FEATURE_SELECT: usize = 0x08;
    pub(crate) const DRIVER_FEATURE: usize = 0x0c;
    pub(crate) const MSIX_CONFIG: usize = 0x10;
    pub(crate) const DEVICE_STATUS: usize = 0x14;
    pub(crate) const QUEUE_SELECT: usize = 0x16;
    pub(crate) const QUEUE_SIZE: usize = 0x18;
    pub(crate) const QUEUE_MSIX_VECTOR: usize = 0x1a;
    pub(crate) const QUEUE_ENABLE: usize = 0x1c;
    pub(crate) const QUEUE_NOTIFY_OFF: usize = 0x1e;
    pub(crate) const QUEUE_DESC: usize = 0x20;
    pub(crate) const QUEUE_DRIVER: usize = 0x28;
    pub(crate) const QUEUE_DEVICE: usize = 0x30;
    /// The size of the common configuration.
    pub(crate) const LEN: usize = 0x38;
}

/// The PCI device ID of a transitional virtio-net device and of a transitional virtio-blk device.
/// A modern device has the ID 0x1040 plus the virtio device ID.
const DEVICE_TRANSITIONAL_NET: u16 = 0x1000;
const DEVICE_TRANSITIONAL_BLK: u16 = 0x1001;
const DEVICE_MODERN_BASE: u16 = 0x1040;

/// Gives the virtio device ID of the PCI function, or `None` if it is not a virtio device.
pub(crate) fn device_type(dev: &PciDevice) -> Option<u32> {
    if dev.vendor_id() != crate::VIRTIO_VENDOR {
        return None;
    }
    match dev.device_id() {
        DEVICE_TRANSITIONAL_NET => Some(crate::DEVICE_NET),
        DEVICE_TRANSITIONAL_BLK => Some(crate::DEVICE_BLK),
        id => id.checked_sub(DEVICE_MODERN_BASE).filter(|&n| n < 0x40).map(u32::from),
    }
}

/// The value of an MSI-X vector register for no vector.
const NO_VECTOR: u16 = 0xffff;

/// The place of a configuration structure: a range of a BAR.
#[derive(Clone, Copy)]
struct Place {
    bar: u8,
    offset: u32,
    len: u32,
}

/// A virtio device on the PCI bus, after the reset.
pub(crate) struct PciTransport {
    common: IoMem,
    notify: IoMem,
    notify_multiplier: u32,
    device: IoMem,
}

impl PciTransport {
    /// Finds the configuration structures of the device, maps them and resets the device. Gives
    /// `None` if the device does not have the modern transport.
    pub(crate) fn new(dev: &PciDevice) -> Option<Self> {
        let (mut common, mut notify, mut device) = (None, None, None);
        let mut notify_multiplier = 0;
        for (id, at) in dev.capabilities() {
            if id != CAP_VENDOR {
                continue;
            }
            let cfg_type = dev.read_config_u8(at + 3);
            let place = Place {
                bar: dev.read_config_u8(at + 4),
                offset: dev.read_config(at + 8),
                len: dev.read_config(at + 12),
            };
            // The first structure of each type is the one to use.
            match cfg_type {
                CFG_COMMON if common.is_none() => common = Some(place),
                CFG_NOTIFY if notify.is_none() => {
                    notify = Some(place);
                    notify_multiplier = dev.read_config(at + 16);
                }
                CFG_DEVICE if device.is_none() => device = Some(place),
                _ => {}
            }
        }
        let map = |p: Place| dev.map_bar(p.bar, u64::from(p.offset), p.len as usize);
        let common = map(common?)?;
        if common.len() < common::LEN {
            return None;
        }
        dev.enable();
        let t = Self { common, notify: map(notify?)?, notify_multiplier, device: map(device?)? };
        t.common.write_u8(common::DEVICE_STATUS, 0);
        // The device gives 0 when the reset is done.
        while t.common.read_u8(common::DEVICE_STATUS) != 0 {
            core::hint::spin_loop();
        }
        t.common.write_u16(common::MSIX_CONFIG, NO_VECTOR);
        t.set_status(status::ACKNOWLEDGE | status::DRIVER);
        Some(t)
    }

    /// Reads the device status.
    pub(crate) fn status(&self) -> u8 {
        self.common.read_u8(common::DEVICE_STATUS)
    }

    /// Writes the device status.
    pub(crate) fn set_status(&self, value: u8) {
        self.common.write_u8(common::DEVICE_STATUS, value);
    }

    /// Reads the half `half` of the features of the device: bits 0 to 31 or bits 32 to 63.
    pub(crate) fn device_features(&self, half: u32) -> u32 {
        self.common.write_u32(common::DEVICE_FEATURE_SELECT, half);
        self.common.read_u32(common::DEVICE_FEATURE)
    }

    /// Writes the half `half` of the features of the driver.
    pub(crate) fn set_driver_features(&self, half: u32, value: u32) {
        self.common.write_u32(common::DRIVER_FEATURE_SELECT, half);
        self.common.write_u32(common::DRIVER_FEATURE, value);
    }

    /// Gives the largest size of the queue `index`, or 0 if the queue is not there.
    pub(crate) fn queue_max(&self, index: u16) -> u16 {
        self.common.write_u16(common::QUEUE_SELECT, index);
        self.common.read_u16(common::QUEUE_SIZE)
    }

    /// Gives the queue `index` to the device, and gives the offset of its notification register.
    pub(crate) fn enable_queue(&self, index: u16, size: u16, addrs: &QueueAddrs) -> Option<usize> {
        let c = &self.common;
        c.write_u16(common::QUEUE_SELECT, index);
        c.write_u16(common::QUEUE_SIZE, size);
        c.write_u16(common::QUEUE_MSIX_VECTOR, NO_VECTOR);
        for (reg, addr) in [
            (common::QUEUE_DESC, addrs.desc),
            (common::QUEUE_DRIVER, addrs.avail),
            (common::QUEUE_DEVICE, addrs.used),
        ] {
            c.write_u32(reg, addr as u32);
            c.write_u32(reg + 4, (addr >> 32) as u32);
        }
        let notify_off = usize::from(c.read_u16(common::QUEUE_NOTIFY_OFF));
        let at = notify_off.checked_mul(self.notify_multiplier as usize)?;
        if at.checked_add(2)? > self.notify.len() {
            return None;
        }
        c.write_u16(common::QUEUE_ENABLE, 1);
        Some(at)
    }

    /// Tells the device that the queue `index` has new buffers. `at` is the offset that
    /// `enable_queue` gave.
    pub(crate) fn notify(&self, at: usize, index: u16) {
        self.notify.write_u16(at, index);
    }

    /// Reads the byte at `offset` of the configuration of the device.
    pub(crate) fn device_u8(&self, offset: usize) -> u8 {
        self.device.read_u8(offset)
    }

    /// Reads the 16 bit field at `offset` of the configuration of the device.
    pub(crate) fn device_u16(&self, offset: usize) -> u16 {
        self.device.read_u16(offset)
    }

    /// Reads the 32 bit field at `offset` of the configuration of the device.
    pub(crate) fn device_u32(&self, offset: usize) -> u32 {
        self.device.read_u32(offset)
    }
}

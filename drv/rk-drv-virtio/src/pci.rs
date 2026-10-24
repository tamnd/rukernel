//! The modern virtio PCI transport, from section 4.1 of the virtio 1.2 specification.

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

/// The bits of the device status.
pub(crate) mod status {
    pub(crate) const ACKNOWLEDGE: u8 = 1;
    pub(crate) const DRIVER: u8 = 2;
    pub(crate) const DRIVER_OK: u8 = 4;
    pub(crate) const FEATURES_OK: u8 = 8;
    pub(crate) const FAILED: u8 = 0x80;
}

/// The feature bit that tells that the device is a virtio 1.0 device.
pub(crate) const F_VERSION_1: u64 = 1 << 32;

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
pub(crate) struct Transport {
    common: IoMem,
    notify: IoMem,
    notify_multiplier: u32,
    device: IoMem,
}

/// The physical addresses of the three parts of a queue.
pub(crate) struct QueueAddrs {
    pub(crate) desc: u64,
    pub(crate) avail: u64,
    pub(crate) used: u64,
}

impl Transport {
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
        t.add_status(status::ACKNOWLEDGE | status::DRIVER);
        Some(t)
    }

    /// Sets the bits `bits` in the device status.
    pub(crate) fn add_status(&self, bits: u8) {
        let s = self.common.read_u8(common::DEVICE_STATUS);
        self.common.write_u8(common::DEVICE_STATUS, s | bits);
    }

    /// Tells the device that the driver failed.
    pub(crate) fn fail(&self) {
        self.add_status(status::FAILED);
    }

    /// Takes the features of `wanted` that the device has. Gives the features, or `None` if the
    /// device does not take them or does not have `F_VERSION_1`.
    pub(crate) fn negotiate(&self, wanted: u64) -> Option<u64> {
        let mut offered = 0u64;
        for half in 0..2u32 {
            self.common.write_u32(common::DEVICE_FEATURE_SELECT, half);
            offered |= u64::from(self.common.read_u32(common::DEVICE_FEATURE)) << (32 * half);
        }
        let features = offered & (wanted | F_VERSION_1);
        if features & F_VERSION_1 == 0 {
            return None;
        }
        for half in 0..2u32 {
            self.common.write_u32(common::DRIVER_FEATURE_SELECT, half);
            self.common.write_u32(common::DRIVER_FEATURE, (features >> (32 * half)) as u32);
        }
        self.add_status(status::FEATURES_OK);
        (self.common.read_u8(common::DEVICE_STATUS) & status::FEATURES_OK != 0).then_some(features)
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

    /// Reads the 32 bit field at `offset` of the configuration of the device.
    pub(crate) fn device_u32(&self, offset: usize) -> u32 {
        self.device.read_u32(offset)
    }

    /// Reads the 64 bit field at `offset` of the configuration of the device, as two 32 bit
    /// reads.
    pub(crate) fn device_u64(&self, offset: usize) -> u64 {
        u64::from(self.device_u32(offset)) | (u64::from(self.device_u32(offset + 4)) << 32)
    }
}

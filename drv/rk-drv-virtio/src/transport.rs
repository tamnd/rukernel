//! The transport of a virtio device: the modern PCI transport on x86-64, and the MMIO transport
//! of the device tree on arm64. The drivers use the device through `Transport`, which does the
//! steps that are the same on each transport, such as the feature negotiation.

#[cfg(target_arch = "aarch64")]
use crate::mmio::MmioTransport;
#[cfg(target_arch = "x86_64")]
use crate::pci::PciTransport;

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

/// The physical addresses of the three parts of a queue.
pub(crate) struct QueueAddrs {
    pub(crate) desc: u64,
    pub(crate) avail: u64,
    pub(crate) used: u64,
}

/// A virtio device after the reset, on one of the transports.
pub(crate) enum Transport {
    /// A device on the PCI bus.
    #[cfg(target_arch = "x86_64")]
    Pci(PciTransport),
    /// A device on the MMIO transport.
    #[cfg(target_arch = "aarch64")]
    Mmio(MmioTransport),
}

/// Calls the method of the transport of `$t`.
macro_rules! each {
    ($t:expr, $x:ident => $e:expr) => {
        match $t {
            #[cfg(target_arch = "x86_64")]
            Transport::Pci($x) => $e,
            #[cfg(target_arch = "aarch64")]
            Transport::Mmio($x) => $e,
        }
    };
}

impl Transport {
    /// Sets the bits `bits` in the device status.
    pub(crate) fn add_status(&self, bits: u8) {
        each!(self, t => t.set_status(t.status() | bits));
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
            offered |= u64::from(each!(self, t => t.device_features(half))) << (32 * half);
        }
        let features = offered & (wanted | F_VERSION_1);
        if features & F_VERSION_1 == 0 {
            return None;
        }
        for half in 0..2u32 {
            let value = (features >> (32 * half)) as u32;
            each!(self, t => t.set_driver_features(half, value));
        }
        self.add_status(status::FEATURES_OK);
        let ok = each!(self, t => t.status()) & status::FEATURES_OK != 0;
        ok.then_some(features)
    }

    /// Gives the largest size of the queue `index`, or 0 if the queue is not there.
    pub(crate) fn queue_max(&self, index: u16) -> u16 {
        each!(self, t => t.queue_max(index))
    }

    /// Gives the queue `index` to the device, and gives the offset of its notification register.
    pub(crate) fn enable_queue(&self, index: u16, size: u16, addrs: &QueueAddrs) -> Option<usize> {
        each!(self, t => t.enable_queue(index, size, addrs))
    }

    /// Tells the device that the queue `index` has new buffers. `at` is the offset that
    /// `enable_queue` gave.
    pub(crate) fn notify(&self, at: usize, index: u16) {
        each!(self, t => t.notify(at, index));
    }

    /// Reads the byte at `offset` of the configuration of the device.
    pub(crate) fn device_u8(&self, offset: usize) -> u8 {
        each!(self, t => t.device_u8(offset))
    }

    /// Reads the 16 bit field at `offset` of the configuration of the device.
    pub(crate) fn device_u16(&self, offset: usize) -> u16 {
        each!(self, t => t.device_u16(offset))
    }

    /// Reads the 32 bit field at `offset` of the configuration of the device.
    pub(crate) fn device_u32(&self, offset: usize) -> u32 {
        each!(self, t => t.device_u32(offset))
    }

    /// Reads the 64 bit field at `offset` of the configuration of the device, as two 32 bit
    /// reads.
    pub(crate) fn device_u64(&self, offset: usize) -> u64 {
        u64::from(self.device_u32(offset)) | (u64::from(self.device_u32(offset + 4)) << 32)
    }
}

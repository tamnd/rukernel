//! The virtio MMIO transport, from section 4.2 of the virtio 1.2 specification. The device tree of
//! arm64 gives the devices. The driver takes only the modern interface, version 2. QEMU gives
//! version 2 with `-global virtio-mmio.force-legacy=false`.

use crate::transport::{QueueAddrs, status};
use rk_frame::iomem::IoMem;
use rk_frame::irq::Line;

/// The registers.
const MAGIC_VALUE: usize = 0x000;
const VERSION: usize = 0x004;
const DEVICE_ID: usize = 0x008;
const DEVICE_FEATURES: usize = 0x010;
const DEVICE_FEATURES_SEL: usize = 0x014;
const DRIVER_FEATURES: usize = 0x020;
const DRIVER_FEATURES_SEL: usize = 0x024;
const QUEUE_SEL: usize = 0x030;
const QUEUE_NUM_MAX: usize = 0x034;
const QUEUE_NUM: usize = 0x038;
const QUEUE_READY: usize = 0x044;
const QUEUE_NOTIFY: usize = 0x050;
const INTERRUPT_STATUS: usize = 0x060;
const INTERRUPT_ACK: usize = 0x064;
const STATUS: usize = 0x070;
const QUEUE_DESC: usize = 0x080;
const QUEUE_DRIVER: usize = 0x090;
const QUEUE_DEVICE: usize = 0x0a0;
const CONFIG: usize = 0x100;

/// The value of `MAGIC_VALUE`: "virt" in little endian.
const MAGIC: u32 = 0x7472_6976;
/// The version of the modern interface.
const VERSION_MODERN: u32 = 2;

/// A virtio device on the MMIO transport, after the reset.
pub(crate) struct MmioTransport {
    regs: IoMem,
    irq: Option<Line>,
}

impl MmioTransport {
    /// Checks the registers `regs` and resets the device. `irq` turns on the interrupt line of
    /// the device, and the call uses it only when a device is there. Gives the virtio device ID
    /// and the transport, or `None` if there is no device at the registers or the device is a
    /// legacy device.
    pub(crate) fn new(
        regs: IoMem,
        phys: u64,
        irq: impl FnOnce() -> Option<Line>,
    ) -> Option<(u32, Self)> {
        if regs.len() <= CONFIG || regs.read_u32(MAGIC_VALUE) != MAGIC {
            return None;
        }
        // A transport without a device gives the device ID 0.
        let id = regs.read_u32(DEVICE_ID);
        if id == 0 {
            return None;
        }
        let version = regs.read_u32(VERSION);
        if version != VERSION_MODERN {
            rk_frame::println!("virtio: device {id} at {phys:#x} has version {version}, not 2");
            return None;
        }
        let t = Self { regs, irq: irq() };
        t.set_status(0);
        // The device gives 0 when the reset is done.
        while t.status() != 0 {
            core::hint::spin_loop();
        }
        t.set_status(status::ACKNOWLEDGE | status::DRIVER);
        Some((id, t))
    }

    /// Reads the device status.
    pub(crate) fn status(&self) -> u8 {
        self.regs.read_u32(STATUS) as u8
    }

    /// Writes the device status.
    pub(crate) fn set_status(&self, value: u8) {
        self.regs.write_u32(STATUS, u32::from(value));
    }

    /// Reads the half `half` of the features of the device: bits 0 to 31 or bits 32 to 63.
    pub(crate) fn device_features(&self, half: u32) -> u32 {
        self.regs.write_u32(DEVICE_FEATURES_SEL, half);
        self.regs.read_u32(DEVICE_FEATURES)
    }

    /// Writes the half `half` of the features of the driver.
    pub(crate) fn set_driver_features(&self, half: u32, value: u32) {
        self.regs.write_u32(DRIVER_FEATURES_SEL, half);
        self.regs.write_u32(DRIVER_FEATURES, value);
    }

    /// Gives the largest size of the queue `index`, or 0 if the queue is not there or is in use.
    pub(crate) fn queue_max(&self, index: u16) -> u16 {
        self.regs.write_u32(QUEUE_SEL, u32::from(index));
        if self.regs.read_u32(QUEUE_READY) != 0 {
            return 0;
        }
        u16::try_from(self.regs.read_u32(QUEUE_NUM_MAX)).unwrap_or(u16::MAX)
    }

    /// Gives the queue `index` to the device. The MMIO transport has one notification register
    /// for all queues, so the offset is 0.
    pub(crate) fn enable_queue(&self, index: u16, size: u16, addrs: &QueueAddrs) -> Option<usize> {
        let r = &self.regs;
        r.write_u32(QUEUE_SEL, u32::from(index));
        r.write_u32(QUEUE_NUM, u32::from(size));
        for (reg, addr) in
            [(QUEUE_DESC, addrs.desc), (QUEUE_DRIVER, addrs.avail), (QUEUE_DEVICE, addrs.used)]
        {
            r.write_u32(reg, addr as u32);
            r.write_u32(reg + 4, (addr >> 32) as u32);
        }
        r.write_u32(QUEUE_READY, 1);
        Some(0)
    }

    /// Tells the device that the queue `index` has new buffers.
    pub(crate) fn notify(&self, _at: usize, index: u16) {
        self.regs.write_u32(QUEUE_NOTIFY, u32::from(index));
    }

    /// The interrupt line of the device.
    pub(crate) fn irq(&self) -> Option<Line> {
        self.irq
    }

    /// Tells the device that the driver saw its interrupt. The device then lowers the line.
    pub(crate) fn ack_interrupt(&self) {
        let pending = self.regs.read_u32(INTERRUPT_STATUS);
        if pending != 0 {
            self.regs.write_u32(INTERRUPT_ACK, pending);
        }
    }

    /// Reads the byte at `offset` of the configuration of the device.
    pub(crate) fn device_u8(&self, offset: usize) -> u8 {
        self.regs.read_u8(CONFIG + offset)
    }

    /// Reads the 16 bit field at `offset` of the configuration of the device.
    pub(crate) fn device_u16(&self, offset: usize) -> u16 {
        self.regs.read_u16(CONFIG + offset)
    }

    /// Reads the 32 bit field at `offset` of the configuration of the device.
    pub(crate) fn device_u32(&self, offset: usize) -> u32 {
        self.regs.read_u32(CONFIG + offset)
    }
}

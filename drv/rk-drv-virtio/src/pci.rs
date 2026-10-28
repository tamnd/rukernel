//! The modern virtio PCI transport, from section 4.1 of the virtio 1.2 specification.

use crate::transport::{QueueAddrs, status};
use crate::vectors::{self, Mode, NO_VECTOR};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use rk_frame::pci::{IoMem, Line, PciDevice};

/// The capability ID of the vendor specific capabilities that virtio uses.
const CAP_VENDOR: u8 = 0x09;
const CFG_COMMON: u8 = 1;
const CFG_NOTIFY: u8 = 2;
const CFG_ISR: u8 = 3;
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

/// The size of the legacy registers in the I/O BAR 0 of a transitional device, and the offset of
/// the device status there, from section 4.1.4.8 of the virtio 1.2 specification.
const LEGACY_LEN: usize = 20;
const LEGACY_STATUS: usize = 18;

/// The place of a configuration structure: a range of a BAR.
#[derive(Clone, Copy)]
struct Place {
    bar: u8,
    offset: u32,
    len: u32,
}

/// A virtio device on the PCI bus, after the reset.
pub(crate) struct PciTransport {
    dev: PciDevice,
    common: IoMem,
    notify: IoMem,
    notify_multiplier: u32,
    device: IoMem,
    /// The ISR status byte, for the INTx line.
    isr: Option<IoMem>,
    /// The interrupt lines, after `find_queues`.
    irq: Irq,
    /// The device status in the legacy registers of the I/O BAR 0 was the same as in the common
    /// configuration.
    legacy_io: bool,
}

/// The interrupt of a device on the PCI bus.
enum Irq {
    /// No line, so the driver polls.
    None,
    /// The INTx line. A read of the ISR status byte lowers it.
    Intx(IoMem, Line),
    /// The MSI-X lines in the order of the vectors, and the number of queues that have a vector.
    /// Each message is an edge, so the driver does not read the ISR status byte.
    Msix(Mode, Vec<Line>, u16),
}

impl PciTransport {
    /// Finds the configuration structures of the device, maps them and resets the device. Gives
    /// `None` if the device does not have the modern transport.
    pub(crate) fn new(dev: &PciDevice) -> Option<Self> {
        let (mut common, mut notify, mut device, mut isr) = (None, None, None, None);
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
                CFG_ISR if isr.is_none() => isr = Some(place),
                _ => {}
            }
        }
        let map = |p: Place| dev.map_bar(p.bar, u64::from(p.offset), p.len as usize);
        let common = map(common?)?;
        if common.len() < common::LEN {
            return None;
        }
        dev.enable();
        let (notify, device, isr) = (map(notify?)?, map(device?)?, isr.and_then(map));
        let mut t = Self {
            dev: *dev,
            common,
            notify,
            notify_multiplier,
            device,
            isr,
            irq: Irq::None,
            legacy_io: false,
        };
        t.common.write_u8(common::DEVICE_STATUS, 0);
        // The device gives 0 when the reset is done.
        while t.common.read_u8(common::DEVICE_STATUS) != 0 {
            core::hint::spin_loop();
        }
        t.common.write_u16(common::MSIX_CONFIG, NO_VECTOR);
        t.set_status(status::ACKNOWLEDGE | status::DRIVER);
        // A transitional device also has the legacy registers in its I/O BAR 0, with the same
        // device status. The log tells when a read through the I/O BAR gives it, so the I/O
        // window of the host and of each bridge on the path works.
        t.legacy_io = dev
            .map_io_bar(0, 0, LEGACY_LEN)
            .is_some_and(|io| io.read_u8(LEGACY_STATUS) == t.status());
        Some(t)
    }

    /// Gives the interrupt lines to the device for its configuration and for the queues 0 to
    /// `queues - 1`, as `vp_find_vqs` of Linux: a MSI-X vector for each queue, else one shared
    /// MSI-X vector, else the INTx line with the ISR status byte, else no line. The driver calls
    /// this after the feature negotiation and before it makes the queues.
    pub(crate) fn find_queues(&mut self, queues: u16) {
        for mode in vectors::modes(queues, self.dev.msix_table_size()) {
            let Some(lines) = self.dev.msix_vectors(mode.count(queues)) else { continue };
            if self.set_vectors(mode, queues) {
                self.irq = Irq::Msix(mode, lines, queues);
                return;
            }
            self.dev.msix_free(&lines);
        }
        self.irq = match self.isr.take().zip(self.dev.irq()) {
            Some((isr, line)) => Irq::Intx(isr, line),
            None => Irq::None,
        };
    }

    /// Writes the vectors of `mode` to the vector registers of the configuration and of the
    /// queues. Gives `false`, with no vector in the registers, if the device does not take one:
    /// the device then gives `NO_VECTOR` back, as `vp_setup_vq` of Linux tests.
    fn set_vectors(&self, mode: Mode, queues: u16) -> bool {
        let c = &self.common;
        let mut ok = {
            c.write_u16(common::MSIX_CONFIG, mode.config_vector());
            c.read_u16(common::MSIX_CONFIG) == mode.config_vector()
        };
        for index in 0..queues {
            if !ok {
                break;
            }
            let vector = mode.queue_vector(index, queues);
            c.write_u16(common::QUEUE_SELECT, index);
            c.write_u16(common::QUEUE_MSIX_VECTOR, vector);
            ok = c.read_u16(common::QUEUE_MSIX_VECTOR) == vector;
        }
        if !ok {
            c.write_u16(common::MSIX_CONFIG, NO_VECTOR);
            for index in 0..queues {
                c.write_u16(common::QUEUE_SELECT, index);
                c.write_u16(common::QUEUE_MSIX_VECTOR, NO_VECTOR);
            }
        }
        ok
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
        let vector = match &self.irq {
            Irq::Msix(mode, _, queues) => mode.queue_vector(index, *queues),
            _ => NO_VECTOR,
        };
        c.write_u16(common::QUEUE_MSIX_VECTOR, vector);
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

    /// The interrupt line of the queue `index`, or `None` if the driver must poll.
    pub(crate) fn line(&self, index: u16) -> Option<Line> {
        match &self.irq {
            Irq::Intx(_, line) => Some(*line),
            Irq::Msix(mode, lines, queues) => lines.get(mode.queue_line(index, *queues)?).copied(),
            Irq::None => None,
        }
    }

    /// Handles each line of the device that came: for the INTx line, reads the ISR status byte,
    /// so that the device lowers the line, and turns the line on again. Gives `true` if a line
    /// came.
    pub(crate) fn handle_interrupt(&self) -> bool {
        match &self.irq {
            Irq::Intx(isr, line) => {
                if !line.take() {
                    return false;
                }
                isr.read_u8(0);
                line.unmask();
                true
            }
            Irq::Msix(_, lines, _) => lines.iter().fold(false, |came, line| {
                if !line.take() {
                    return came;
                }
                line.unmask();
                true
            }),
            Irq::None => false,
        }
    }

    /// The kind of the interrupt of the device, for the log: the MSI-X vectors, INTx, or none,
    /// and the legacy I/O BAR if a read through it worked.
    pub(crate) fn irq_kind(&self) -> String {
        let kind = match &self.irq {
            Irq::Msix(_, lines, _) if lines.len() == 1 => String::from("1 MSI-X vector"),
            Irq::Msix(_, lines, _) => format!("{} MSI-X vectors", lines.len()),
            Irq::Intx(..) => String::from("INTx"),
            Irq::None => String::from("no interrupt"),
        };
        if self.legacy_io { format!("{kind} and the legacy I/O BAR") } else { kind }
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

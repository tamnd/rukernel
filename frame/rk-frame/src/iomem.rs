//! Ranges of device registers that are mapped in the kernel, and on arm64 the virtio MMIO devices
//! of the device tree.
//!
//! A driver gets an `IoMem` from a PCI BAR or from a device of the device tree. Each access is
//! volatile and checks that it is in the range.

/// A range of device registers that is mapped in the kernel. The mapping stays for all of the
/// run time. Each access is volatile and checks that it is in the range.
#[derive(Debug)]
pub struct IoMem {
    virt: usize,
    len: usize,
}

macro_rules! io_access {
    ($read:ident, $write:ident, $t:ty) => {
        /// Reads the register at `offset`.
        ///
        /// # Panics
        ///
        /// If the register is not in the range or is not aligned.
        pub fn $read(&self, offset: usize) -> $t {
            let p = self.ptr::<$t>(offset);
            // SAFETY: `ptr` checks that the register is in the mapped range and aligned. The range
            // is device memory that is mapped without cache, and no Rust reference to it exists.
            unsafe { p.read_volatile() }
        }

        /// Writes the register at `offset`.
        ///
        /// # Panics
        ///
        /// If the register is not in the range or is not aligned.
        pub fn $write(&self, offset: usize, value: $t) {
            let p = self.ptr::<$t>(offset);
            // SAFETY: as for the read. The range is not RAM, so the write does not change memory
            // that the kernel uses.
            unsafe { p.write_volatile(value) }
        }
    };
}

impl IoMem {
    /// Makes the range of `len` bytes at the kernel virtual address `virt`.
    ///
    /// # Safety
    ///
    /// The range is device registers that are mapped without cache for all of the run time, and
    /// it is not RAM.
    pub(crate) unsafe fn new(virt: usize, len: usize) -> Self {
        Self { virt, len }
    }

    /// The length of the range in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Tells if the range is empty. A mapped range is never empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The kernel virtual address of the range.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn base(&self) -> usize {
        self.virt
    }

    fn ptr<T>(&self, offset: usize) -> *mut T {
        let size = size_of::<T>();
        assert!(
            offset.checked_add(size).is_some_and(|end| end <= self.len),
            "{size} bytes at {offset} are outside the registers"
        );
        let addr = self.virt + offset;
        assert!(addr.is_multiple_of(size), "the register at {offset} is not aligned");
        addr as *mut T
    }

    io_access!(read_u8, write_u8, u8);
    io_access!(read_u16, write_u16, u16);
    io_access!(read_u32, write_u32, u32);
    io_access!(read_u64, write_u64, u64);
}

#[cfg(target_arch = "aarch64")]
pub use virtio_mmio::{MmioDevice, virtio_mmio_devices};

/// The virtio MMIO devices of the device tree.
#[cfg(target_arch = "aarch64")]
pub(crate) mod virtio_mmio {
    use super::IoMem;
    use crate::fdt::{Irq, MAX_VIRTIO_MMIO};
    use crate::irq::Line;
    use crate::sync::SpinLock;
    use alloc::vec::Vec;

    /// The physical address, the size and the interrupt of each device, and the number of
    /// devices. The boot path sets them from the device tree.
    type List = [(u64, u64, Option<Irq>); MAX_VIRTIO_MMIO];
    static DEVICES: SpinLock<(List, usize)> = SpinLock::new(([(0, 0, None); MAX_VIRTIO_MMIO], 0));

    /// Keeps the devices `list` of the device tree.
    pub(crate) fn set(list: &[(u64, u64, Option<Irq>)]) {
        let mut d = DEVICES.lock();
        let n = list.len().min(MAX_VIRTIO_MMIO);
        d.0[..n].copy_from_slice(&list[..n]);
        d.1 = n;
    }

    /// A virtio MMIO device of the device tree: a range of registers and an interrupt.
    #[derive(Clone, Copy, Debug)]
    pub struct MmioDevice {
        phys: u64,
        len: u64,
        irq: Option<Irq>,
    }

    /// Gives the virtio MMIO devices, in the order of the device tree.
    pub fn virtio_mmio_devices() -> Vec<MmioDevice> {
        let d = DEVICES.lock();
        d.0[..d.1].iter().map(|&(phys, len, irq)| MmioDevice { phys, len, irq }).collect()
    }

    impl MmioDevice {
        /// The physical address of the registers.
        pub fn phys(&self) -> u64 {
            self.phys
        }

        /// Turns on the interrupt line of the device, and gives it. Gives `None` if the device
        /// tree gives no SPI for the device.
        pub fn irq(&self) -> Option<Line> {
            self.irq.and_then(|i| Line::new(i.intid, i.edge))
        }

        /// Maps the registers. Gives `None` if the range is on RAM or the kernel cannot map it.
        pub fn map(&self) -> Option<IoMem> {
            let len = usize::try_from(self.len).ok().filter(|&l| l > 0)?;
            let info = crate::boot::info()?;
            let virt = crate::arch::imp::paging::map_device(self.phys, self.len, info)?;
            // SAFETY: `map_device` maps the range as device memory for all of the run time, and
            // it does not map a range that holds RAM.
            Some(unsafe { IoMem::new(virt, len) })
        }
    }
}

//! Device numbers and the table of character devices.
//!
//! A device file is an inode with the type `S_IFCHR` or `S_IFBLK` and a device number. `open` of
//! the file asks the driver of the number for the operations of the open file. A driver adds its
//! number to the table with `register_char`.

use crate::file::FileOps;
use crate::inode::Result;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

/// Makes a device number from the major and the minor number, in the encoding of Linux that
/// `st_rdev` uses.
pub const fn makedev(major: u32, minor: u32) -> u64 {
    let (major, minor) = (major as u64, minor as u64);
    (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12) | ((major & !0xfff) << 32)
}

/// The major number of a device number.
pub const fn major(dev: u64) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as u32
}

/// The minor number of a device number.
pub const fn minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32
}

/// The driver of a character device.
pub trait CharDevice: Send + Sync {
    /// Gives the operations of a new open file of the device.
    fn open(&self, flags: u32) -> Result<Arc<dyn FileOps>>;
}

static CHAR_DEVICES: SpinLock<BTreeMap<u64, Arc<dyn CharDevice>>> = SpinLock::new(BTreeMap::new());

/// Adds the driver of the character device `rdev`. A second driver for the same number takes
/// the place of the first.
pub fn register_char(rdev: u64, device: Arc<dyn CharDevice>) {
    CHAR_DEVICES.lock().insert(rdev, device);
}

/// Opens the character device `rdev`. Gives `ENXIO` if no driver has the number, as Linux.
pub fn open_char(rdev: u64, flags: u32) -> Result<Arc<dyn FileOps>> {
    let device = CHAR_DEVICES.lock().get(&rdev).cloned().ok_or(Errno::ENXIO)?;
    device.open(flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_numbers() {
        assert_eq!(makedev(5, 1), 0x501);
        assert_eq!(makedev(4, 64), 0x440);
        let big = makedev(0x1234, 0x56789);
        assert_eq!((major(big), minor(big)), (0x1234, 0x56789));
    }
}

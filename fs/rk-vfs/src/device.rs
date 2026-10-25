//! Device numbers and the table of character devices.
//!
//! A device file is an inode with the type `S_IFCHR` or `S_IFBLK` and a device number. `open` of
//! the file asks the driver of the number for the operations of the open file. A driver adds its
//! number to the table with `register_char`.
//!
//! The kernel also keeps a list of the devices with their names, as the device model of Linux
//! does. devtmpfs makes a device file for each one, and sysfs shows each one.

use crate::file::FileOps;
use crate::inode::Result;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
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

/// A device in the list of devices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    /// The name of the device file in `/dev`, for example `vda` or `null`.
    pub name: String,
    /// The class of the device in sysfs, for example `block`, `mem` or `tty`.
    pub class: &'static str,
    /// The device number.
    pub rdev: u64,
    /// Tells if the device is a block device. Else it is a character device.
    pub block: bool,
    /// The permission bits of the device file.
    pub perm: u32,
}

static DEVICES: SpinLock<Vec<DeviceInfo>> = SpinLock::new(Vec::new());

/// Adds a device to the list of devices. A device with the same type and number takes the place
/// of the old one.
pub fn add_device(info: DeviceInfo) {
    let mut devices = DEVICES.lock();
    devices.retain(|d| d.block != info.block || d.rdev != info.rdev);
    devices.push(info);
}

/// Gives the list of devices, in the order that they were added.
pub fn devices() -> Vec<DeviceInfo> {
    DEVICES.lock().clone()
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

    #[test]
    fn a_device_with_the_same_number_takes_the_place_of_the_old_one() {
        let info = |name: &str, block| DeviceInfo {
            name: String::from(name),
            class: "test",
            rdev: makedev(250, 1),
            block,
            perm: 0o600,
        };
        add_device(info("one", false));
        add_device(info("disk", true));
        add_device(info("two", false));
        let names: Vec<String> =
            devices().into_iter().filter(|d| d.class == "test").map(|d| d.name).collect();
        assert_eq!(names, ["disk", "two"]);
    }
}

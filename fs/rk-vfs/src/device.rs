//! Device numbers and the table of character devices.
//!
//! A device file is an inode with the type `S_IFCHR` or `S_IFBLK` and a device number. `open` of
//! the file asks the driver of the number for the operations of the open file. A driver adds its
//! number to the table with `register_char`.
//!
//! The kernel also keeps a list of the devices with their names, as the device model of Linux
//! does. devtmpfs makes a device file for each one, and sysfs shows each one.

use crate::dentry::Location;
use crate::file::FileOps;
use crate::inode::Result;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::{Once, SpinLock};

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

    /// Gives the operations of a new open file of the device file at `at`. A driver that must
    /// know the device file, as the pseudo terminals of devpts, uses it. The default calls
    /// [`CharDevice::open`].
    fn open_at(&self, at: &Location, flags: u32) -> Result<Arc<dyn FileOps>> {
        let _ = at;
        self.open(flags)
    }
}

static CHAR_DEVICES: SpinLock<BTreeMap<u64, Arc<dyn CharDevice>>> = SpinLock::new(BTreeMap::new());

/// The drivers of all the minor numbers of a major number, by the major number.
static CHAR_MAJORS: SpinLock<BTreeMap<u32, Arc<dyn CharDevice>>> = SpinLock::new(BTreeMap::new());

/// Adds the driver of the character device `rdev`. A second driver for the same number takes
/// the place of the first.
pub fn register_char(rdev: u64, device: Arc<dyn CharDevice>) {
    CHAR_DEVICES.lock().insert(rdev, device);
}

/// Removes the driver of the character device `rdev`. A later open of the number gives `ENXIO`.
pub fn unregister_char(rdev: u64) {
    CHAR_DEVICES.lock().remove(&rdev);
}

/// Adds the driver of each minor number of the major number `major`, as a `cdev` of Linux with
/// the full range of minor numbers. A driver of one device number comes first.
pub fn register_char_major(major: u32, device: Arc<dyn CharDevice>) {
    CHAR_MAJORS.lock().insert(major, device);
}

/// The driver of the character device `rdev`.
fn char_driver(rdev: u64) -> Result<Arc<dyn CharDevice>> {
    if let Some(device) = CHAR_DEVICES.lock().get(&rdev).cloned() {
        return Ok(device);
    }
    CHAR_MAJORS.lock().get(&major(rdev)).cloned().ok_or(Errno::ENXIO)
}

/// Opens the character device `rdev`. Gives `ENXIO` if no driver has the number, as Linux.
pub fn open_char(rdev: u64, flags: u32) -> Result<Arc<dyn FileOps>> {
    char_driver(rdev)?.open(flags)
}

/// Opens the character device `rdev` through its device file at `at`. Gives `ENXIO` if no driver
/// has the number.
pub fn open_char_at(rdev: u64, at: &Location, flags: u32) -> Result<Arc<dyn FileOps>> {
    char_driver(rdev)?.open_at(at, flags)
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

/// Adds a device to the list of devices, and sends the event `add`. A device with the same type
/// and number takes the place of the old one.
pub fn add_device(info: DeviceInfo) {
    insert(info.clone());
    crate::uevent::device(&info, crate::uevent::Action::Add, &[]);
}

/// Adds a device to the list of devices with no event.
fn insert(info: DeviceInfo) {
    let mut devices = DEVICES.lock();
    devices.retain(|d| d.block != info.block || d.rdev != info.rdev);
    devices.push(info);
}

/// Gives the list of devices, in the order that they were added.
pub fn devices() -> Vec<DeviceInfo> {
    DEVICES.lock().clone()
}

/// A change in the list of devices, for the hook of [`set_node_hook`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeChange {
    /// A driver added the device.
    Add,
    /// A driver removed the device.
    Remove,
}

/// The types of a device and the accesses of the device controller, `DEVCG_DEV_*` and
/// `DEVCG_ACC_*` of Linux.
pub mod devcg {
    /// A block device.
    pub const DEV_BLOCK: u32 = 1;
    /// A character device.
    pub const DEV_CHAR: u32 = 2;
    /// `mknod`.
    pub const ACC_MKNOD: u32 = 1;
    /// A read.
    pub const ACC_READ: u32 = 2;
    /// A write.
    pub const ACC_WRITE: u32 = 4;
}

/// The check of the device controller: the type, the major and minor numbers and the access.
type DevcgroupCheck = fn(u32, u32, u32, u32) -> Result<()>;

static DEVCGROUP: Once<DevcgroupCheck> = Once::new();

/// Sets the check of the device controller of the cgroup of the current task, the device
/// programs of cgroup2. Only the first call has an effect.
pub fn set_devcgroup_check(check: DevcgroupCheck) {
    DEVCGROUP.call_once(|| check);
}

/// `devcgroup_check_permission` of Linux: gives `EPERM` if the device controller refuses the
/// access `access` of the type of [`devcg`] to the device `rdev`.
pub fn devcgroup_check_permission(dev_type: u32, rdev: u64, access: u32) -> Result<()> {
    match DEVCGROUP.get() {
        Some(check) => check(dev_type, major(rdev), minor(rdev), access),
        None => Ok(()),
    }
}

/// `devcgroup_inode_permission` of Linux, for the open of a device file with the access mask
/// `mask` of `MAY_*`.
pub fn devcgroup_inode_permission(block: bool, rdev: u64, mask: u32) -> Result<()> {
    use crate::cred::may;
    let mut access = 0;
    if mask & may::WRITE != 0 {
        access |= devcg::ACC_WRITE;
    }
    if mask & may::READ != 0 {
        access |= devcg::ACC_READ;
    }
    if access == 0 {
        return Ok(());
    }
    let dev_type = if block { devcg::DEV_BLOCK } else { devcg::DEV_CHAR };
    devcgroup_check_permission(dev_type, rdev, access)
}

/// `devcgroup_inode_mknod` of Linux, for `mknod` of a device file. The whiteout device 0:0 needs
/// no check.
pub fn devcgroup_inode_mknod(block: bool, rdev: u64) -> Result<()> {
    if !block && rdev == 0 {
        return Ok(());
    }
    let dev_type = if block { devcg::DEV_BLOCK } else { devcg::DEV_CHAR };
    devcgroup_check_permission(dev_type, rdev, devcg::ACC_MKNOD)
}

static NODE_HOOK: Once<fn(&DeviceInfo, NodeChange)> = Once::new();

/// Sets the function that makes and removes the device files of the devices that a driver adds
/// or removes after the boot, as devtmpfs of Linux does. Only the first call has an effect.
pub fn set_node_hook(hook: fn(&DeviceInfo, NodeChange)) {
    NODE_HOOK.call_once(|| hook);
}

/// Adds a device to the list after the boot, makes its device file with the hook of
/// [`set_node_hook`], and sends the event `add`. The device file is there before the event, as
/// `device_add` of Linux does.
pub fn add_device_node(info: DeviceInfo) {
    insert(info.clone());
    if let Some(hook) = NODE_HOOK.get() {
        hook(&info, NodeChange::Add);
    }
    crate::uevent::device(&info, crate::uevent::Action::Add, &[]);
}

/// Removes the device `rdev` of the type `block` from the list, removes its device file with the
/// hook of [`set_node_hook`], and sends the event `remove`.
pub fn remove_device(block: bool, rdev: u64) {
    let gone: Vec<DeviceInfo> = {
        let mut devices = DEVICES.lock();
        let gone = devices.iter().filter(|d| d.block == block && d.rdev == rdev).cloned().collect();
        devices.retain(|d| d.block != block || d.rdev != rdev);
        gone
    };
    if let Some(hook) = NODE_HOOK.get() {
        for d in &gone {
            hook(d, NodeChange::Remove);
        }
    }
    for d in &gone {
        crate::uevent::device(d, crate::uevent::Action::Remove, &[]);
    }
}

/// The names of the major numbers, as `register_blkdev` and `register_chrdev` of Linux keep them.
static MAJORS: SpinLock<Vec<(bool, u32, &'static str)>> = SpinLock::new(Vec::new());

/// Gives the major number `major` the name `name` in `/proc/devices`. `block` tells if the number
/// is for block devices.
pub fn register_major(block: bool, major: u32, name: &'static str) {
    let mut majors = MAJORS.lock();
    if !majors.contains(&(block, major, name)) {
        majors.push((block, major, name));
    }
}

/// Gives the text of `/proc/devices`: the character majors, and then the block majors.
pub fn proc_devices() -> String {
    let mut majors = MAJORS.lock().clone();
    majors.sort_by_key(|&(block, major, _)| (block, major));
    let mut out = String::from("Character devices:\n");
    for &(_, major, name) in majors.iter().filter(|m| !m.0) {
        out.push_str(&alloc::format!("{major:3} {name}\n"));
    }
    out.push_str("\nBlock devices:\n");
    for &(_, major, name) in majors.iter().filter(|m| m.0) {
        out.push_str(&alloc::format!("{major:3} {name}\n"));
    }
    out
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
        remove_device(true, makedev(250, 1));
        let names: Vec<String> =
            devices().into_iter().filter(|d| d.class == "test").map(|d| d.name).collect();
        assert_eq!(names, ["two"]);
    }

    #[test]
    fn proc_devices_has_the_character_majors_and_then_the_block_majors() {
        register_major(true, 251, "testblk");
        register_major(false, 250, "testchr");
        register_major(false, 250, "testchr");
        let text = proc_devices();
        let (chars, blocks) = text.split_once("\nBlock devices:\n").unwrap();
        assert!(chars.starts_with("Character devices:\n"));
        assert_eq!(chars.matches("250 testchr\n").count(), 1);
        assert!(blocks.contains("251 testblk\n"));
    }
}

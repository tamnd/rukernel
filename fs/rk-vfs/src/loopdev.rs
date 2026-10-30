//! The loop device: a block device over a file, from drivers/block/loop.c of Linux.
//!
//! `/dev/loop-control` adds, removes and finds the loop devices. Each `/dev/loopN` is a block
//! device. `LOOP_CONFIGURE` or `LOOP_SET_FD` gives the device an open file. Then the sector `s` of
//! the device is at the byte `offset + 512 * s` of the file. The size of the device is the size of
//! the file after the offset, but not more than the size limit. A read past the end of the file
//! gives zeros.
//!
//! `LOOP_CLR_FD` sets the flag `LO_FLAGS_AUTOCLEAR`. At the last close of a device with this flag,
//! the device writes its dirty pages to the file and lets the file go, as Linux does. The boot
//! adds `loop0` to `loop7`, as `CONFIG_BLK_DEV_LOOP_MIN_COUNT` of Linux.

use crate::blockdev::{self, BlockDevice, BlockOps, SECTOR_SIZE};
use crate::device::{self, CharDevice, DeviceInfo, major, makedev, minor};
use crate::file::{File, FileOps, UserMemory};
use crate::inode::{Result, mode};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::open::O_DIRECT;
use rk_block::cache::PAGE_SIZE;
use rk_frame::sync::{Once, SpinLock};

/// The major number of the loop devices.
pub const LOOP_MAJOR: u32 = 7;
/// The major number of the misc devices, which has `/dev/loop-control`.
pub const MISC_MAJOR: u32 = 10;
/// The minor number of `/dev/loop-control`.
pub const LOOP_CTRL_MINOR: u32 = 237;
/// The number of loop devices that the boot adds.
pub const MIN_COUNT: u32 = 8;
/// The limit of the index of a loop device: the minor numbers have 20 bits.
const MAX_INDEX: u32 = 1 << 20;
/// The layout of the old `struct loop_info` of `LOOP_SET_STATUS` and `LOOP_GET_STATUS`. Its
/// `lo_device` and `lo_rdevice` have the type `__kernel_old_dev_t`, which is an `unsigned long`
/// on x86_64 and an `unsigned int` on the other architectures. The values are the offsets of
/// `lo_number`, `lo_device`, `lo_inode`, `lo_rdevice`, `lo_offset`, `lo_encrypt_type`,
/// `lo_encrypt_key_size`, `lo_flags` and `lo_name`, and the size of the structure.
#[cfg(target_arch = "x86_64")]
mod old {
    pub(super) const DEV_SIZE: usize = 8;
    pub(super) const AT: [usize; 9] = [0, 8, 16, 24, 32, 36, 40, 44, 48];
    pub(super) const SIZE: usize = 168;
}
#[cfg(not(target_arch = "x86_64"))]
mod old {
    pub(super) const DEV_SIZE: usize = 4;
    pub(super) const AT: [usize; 9] = [0, 4, 8, 16, 20, 24, 28, 32, 36];
    pub(super) const SIZE: usize = 160;
}

/// The size of the file name in `struct loop_info64`.
pub const LO_NAME_SIZE: usize = 64;
/// The largest key size in `struct loop_info64`.
const LO_KEY_SIZE: u32 = 32;
/// The size of `struct loop_info64`.
const INFO64_SIZE: usize = 232;
/// The size of `struct loop_config`.
const CONFIG_SIZE: usize = 304;

/// The `ioctl` commands of the loop devices and of `/dev/loop-control`, from `<linux/loop.h>`.
pub mod ioctl {
    /// Gives the device the file of a descriptor.
    pub const LOOP_SET_FD: u32 = 0x4c00;
    /// Lets the file go at the last close.
    pub const LOOP_CLR_FD: u32 = 0x4c01;
    /// Sets the status from a `struct loop_info`.
    pub const LOOP_SET_STATUS: u32 = 0x4c02;
    /// Gives the status as a `struct loop_info`.
    pub const LOOP_GET_STATUS: u32 = 0x4c03;
    /// Sets the status from a `struct loop_info64`.
    pub const LOOP_SET_STATUS64: u32 = 0x4c04;
    /// Gives the status as a `struct loop_info64`.
    pub const LOOP_GET_STATUS64: u32 = 0x4c05;
    /// Changes the file of a read only device.
    pub const LOOP_CHANGE_FD: u32 = 0x4c06;
    /// Reads the size of the file again.
    pub const LOOP_SET_CAPACITY: u32 = 0x4c07;
    /// Sets or clears the direct I/O mode.
    pub const LOOP_SET_DIRECT_IO: u32 = 0x4c08;
    /// Sets the logical block size.
    pub const LOOP_SET_BLOCK_SIZE: u32 = 0x4c09;
    /// Gives the device a file and its status from a `struct loop_config`.
    pub const LOOP_CONFIGURE: u32 = 0x4c0a;
    /// Adds a loop device.
    pub const LOOP_CTL_ADD: u32 = 0x4c80;
    /// Removes a loop device.
    pub const LOOP_CTL_REMOVE: u32 = 0x4c81;
    /// Gives the first loop device that has no file.
    pub const LOOP_CTL_GET_FREE: u32 = 0x4c82;
}

/// The flags of a loop device, from `<linux/loop.h>`.
pub mod flags {
    /// The device does not accept writes.
    pub const LO_FLAGS_READ_ONLY: u32 = 1;
    /// The device lets its file go at the last close.
    pub const LO_FLAGS_AUTOCLEAR: u32 = 4;
    /// The kernel reads the partition table of the device.
    pub const LO_FLAGS_PARTSCAN: u32 = 8;
    /// The device reads and writes the file with direct I/O.
    pub const LO_FLAGS_DIRECT_IO: u32 = 16;
    /// The flags that `LOOP_SET_STATUS64` can set.
    pub const SET_STATUS_SETTABLE: u32 = LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN;
    /// The flags that `LOOP_SET_STATUS64` can clear.
    pub const SET_STATUS_CLEARABLE: u32 = LO_FLAGS_AUTOCLEAR;
    /// The flags that `LOOP_CONFIGURE` accepts.
    pub const CONFIGURE_SETTABLE: u32 =
        LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN | LO_FLAGS_DIRECT_IO;
}

use flags::*;
use ioctl::*;

/// A function that gives the open file of a descriptor of the current process.
pub type FileLookup = fn(i32) -> Result<Arc<File>>;

static FILE_LOOKUP: Once<FileLookup> = Once::new();

/// Gives the loop devices the function that gives the open file of a descriptor of the current
/// process, for `LOOP_SET_FD` and `LOOP_CONFIGURE`. Only the first call has an effect.
pub fn set_file_lookup(f: FileLookup) {
    FILE_LOOKUP.call_once(|| f);
}

fn lookup(fd: i32) -> Result<Arc<File>> {
    FILE_LOOKUP.get().ok_or(Errno::EBADF).and_then(|f| f(fd))
}

/// The loop devices by their index.
static LOOPS: SpinLock<BTreeMap<u32, Arc<LoopDevice>>> = SpinLock::new(BTreeMap::new());

/// Adds `/dev/loop-control` and the devices `loop0` to `loop7`, and the names of their major
/// numbers.
pub fn init() {
    device::register_major(true, LOOP_MAJOR, "loop");
    device::register_major(false, MISC_MAJOR, "misc");
    let rdev = makedev(MISC_MAJOR, LOOP_CTRL_MINOR);
    device::register_char(rdev, Arc::new(Control));
    device::add_device(DeviceInfo {
        name: String::from("loop-control"),
        class: "misc",
        rdev,
        block: false,
        perm: 0o660,
    });
    for i in 0..MIN_COUNT {
        let _ = add(Some(i));
    }
}

/// `struct loop_info64` of `<linux/loop.h>`, without the fields that Linux does not use.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Info64 {
    device: u64,
    inode: u64,
    rdevice: u64,
    offset: u64,
    sizelimit: u64,
    number: u32,
    encrypt_type: u32,
    encrypt_key_size: u32,
    flags: u32,
    file_name: [u8; LO_NAME_SIZE],
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_ne_bytes(v)
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    let mut v = [0u8; 4];
    v.copy_from_slice(&b[at..at + 4]);
    u32::from_ne_bytes(v)
}

impl Info64 {
    fn empty() -> Self {
        Self {
            device: 0,
            inode: 0,
            rdevice: 0,
            offset: 0,
            sizelimit: 0,
            number: 0,
            encrypt_type: 0,
            encrypt_key_size: 0,
            flags: 0,
            file_name: [0; LO_NAME_SIZE],
        }
    }

    /// Reads the structure from its bytes.
    fn parse(b: &[u8]) -> Self {
        let mut file_name = [0u8; LO_NAME_SIZE];
        file_name.copy_from_slice(&b[56..56 + LO_NAME_SIZE]);
        Self {
            device: u64_at(b, 0),
            inode: u64_at(b, 8),
            rdevice: u64_at(b, 16),
            offset: u64_at(b, 24),
            sizelimit: u64_at(b, 32),
            number: u32_at(b, 40),
            encrypt_type: u32_at(b, 44),
            encrypt_key_size: u32_at(b, 48),
            flags: u32_at(b, 52),
            file_name,
        }
    }

    /// Gives the bytes of the structure. The crypt name, the key and `lo_init` are zero.
    fn bytes(&self) -> [u8; INFO64_SIZE] {
        let mut b = [0u8; INFO64_SIZE];
        b[0..8].copy_from_slice(&self.device.to_ne_bytes());
        b[8..16].copy_from_slice(&self.inode.to_ne_bytes());
        b[16..24].copy_from_slice(&self.rdevice.to_ne_bytes());
        b[24..32].copy_from_slice(&self.offset.to_ne_bytes());
        b[32..40].copy_from_slice(&self.sizelimit.to_ne_bytes());
        b[40..44].copy_from_slice(&self.number.to_ne_bytes());
        b[44..48].copy_from_slice(&self.encrypt_type.to_ne_bytes());
        b[48..52].copy_from_slice(&self.encrypt_key_size.to_ne_bytes());
        b[52..56].copy_from_slice(&self.flags.to_ne_bytes());
        b[56..56 + LO_NAME_SIZE].copy_from_slice(&self.file_name);
        b
    }

    /// Reads the old `struct loop_info`, as `loop_info64_from_old` of Linux. The offset is an
    /// `int`, and the size limit is 0.
    fn parse_old(b: &[u8]) -> Self {
        let [_, _, _, _, offset, encrypt_type, key_size, flags, name] = old::AT;
        let mut info = Self::empty();
        info.offset = i64::from(u32_at(b, offset) as i32) as u64;
        info.encrypt_type = u32_at(b, encrypt_type);
        info.encrypt_key_size = u32_at(b, key_size);
        info.flags = u32_at(b, flags);
        info.file_name.copy_from_slice(&b[name..name + LO_NAME_SIZE]);
        info
    }

    /// Gives the bytes of the old `struct loop_info`, as `loop_info64_to_old` of Linux. A value
    /// that does not fit gives `EOVERFLOW`.
    fn bytes_old(&self) -> Result<[u8; old::SIZE]> {
        let [number, device, inode, rdevice, offset, encrypt_type, key_size, flags, name] = old::AT;
        let dev_fits = |v: u64| old::DEV_SIZE == 8 || v <= u64::from(u32::MAX);
        if !dev_fits(self.device) || !dev_fits(self.rdevice) || self.offset > i32::MAX as u64 {
            return Err(Errno::EOVERFLOW);
        }
        let mut b = [0u8; old::SIZE];
        let mut put = |at: usize, v: &[u8]| b[at..at + v.len()].copy_from_slice(v);
        put(number, &self.number.to_ne_bytes());
        put(device, &self.device.to_ne_bytes()[..old::DEV_SIZE]);
        put(inode, &self.inode.to_ne_bytes());
        put(rdevice, &self.rdevice.to_ne_bytes()[..old::DEV_SIZE]);
        put(offset, &(self.offset as u32).to_ne_bytes());
        put(encrypt_type, &self.encrypt_type.to_ne_bytes());
        put(key_size, &self.encrypt_key_size.to_ne_bytes());
        put(flags, &self.flags.to_ne_bytes());
        put(name, &self.file_name);
        Ok(b)
    }

    /// Checks the fields that a caller sets, as `loop_set_status_from_info` of Linux.
    fn check(&self) -> Result<()> {
        // Linux removed the encryption, so only `LO_CRYPT_NONE` stays.
        if self.encrypt_key_size > LO_KEY_SIZE || self.encrypt_type != 0 {
            return Err(Errno::EINVAL);
        }
        if self.offset > i64::MAX as u64 || self.sizelimit > i64::MAX as u64 {
            return Err(Errno::EOVERFLOW);
        }
        Ok(())
    }

    /// The file name, with a zero at the end as Linux keeps it.
    fn name(&self) -> [u8; LO_NAME_SIZE] {
        let mut name = self.file_name;
        name[LO_NAME_SIZE - 1] = 0;
        name
    }
}

/// The size of a device in sectors, for a file of `size` bytes, as `lo_calculate_size` of
/// Linux.
fn sectors_of(size: u64, offset: u64, sizelimit: u64) -> u64 {
    let mut bytes = size.saturating_sub(offset);
    if sizelimit > 0 && sizelimit < bytes {
        bytes = sizelimit;
    }
    bytes / SECTOR_SIZE as u64
}

/// The size of the file of a device in bytes. A block device gives the size of the device.
fn file_size(file: &File) -> u64 {
    match file.metadata() {
        Ok(m) if m.mode & mode::S_IFMT == mode::S_IFBLK => file.ops().end().unwrap_or(0),
        Ok(m) => m.size,
        Err(_) => 0,
    }
}

/// Tells if `size` is a correct logical block size: a power of two from 512 to the page size.
fn valid_block_size(size: u64) -> bool {
    size.is_power_of_two() && (SECTOR_SIZE as u64..=PAGE_SIZE as u64).contains(&size)
}

/// The file of a loop device and its status.
struct Backing {
    file: Arc<File>,
    offset: u64,
    sizelimit: u64,
    flags: u32,
    file_name: [u8; LO_NAME_SIZE],
    block_size: u32,
    /// The size of the device in sectors.
    sectors: u64,
}

struct Inner {
    backing: Option<Backing>,
    /// The device lets its file go at the last close, and does not take a new open. It is the
    /// state `Lo_rundown` of Linux.
    rundown: bool,
}

/// One loop device.
struct LoopDevice {
    number: u32,
    rdev: u64,
    inner: SpinLock<Inner>,
}

impl LoopDevice {
    fn new(number: u32) -> Self {
        Self {
            number,
            rdev: makedev(LOOP_MAJOR, number),
            inner: SpinLock::new(Inner { backing: None, rundown: false }),
        }
    }

    /// Tells if the device has no file, the state `Lo_unbound` of Linux.
    fn unbound(&self) -> bool {
        let inner = self.inner.lock();
        inner.backing.is_none() && !inner.rundown
    }

    /// The file and the position in it of the sector `sector`.
    fn target(&self, sector: u64) -> Result<(Arc<File>, u64)> {
        let inner = self.inner.lock();
        let b = inner.backing.as_ref().ok_or(Errno::EIO)?;
        Ok((b.file.clone(), b.offset + sector * SECTOR_SIZE as u64))
    }

    /// The file of the device, or `ENXIO` if the device has no file.
    fn file(&self) -> Result<Arc<File>> {
        let inner = self.inner.lock();
        inner.backing.as_ref().map(|b| b.file.clone()).ok_or(Errno::ENXIO)
    }

    /// Calls `f` with the status of the device. Gives `ENXIO` if the device has no file.
    fn with<T>(&self, f: impl FnOnce(&mut Backing) -> T) -> Result<T> {
        let mut inner = self.inner.lock();
        if inner.rundown {
            return Err(Errno::ENXIO);
        }
        inner.backing.as_mut().map(f).ok_or(Errno::ENXIO)
    }

    /// Sets the size of the device to `sectors`. A change of the size first writes the dirty
    /// pages of the device and drops its cache, because the cache keeps the size of each folio.
    fn resize(&self, sectors: u64) -> Result<()> {
        if self.with(|b| b.sectors)? == sectors {
            return Ok(());
        }
        if let Some(cache) = blockdev::block_cache(self.rdev) {
            cache.write_back(0, u64::MAX)?;
            cache.forget(0, u64::MAX);
        }
        self.with(|b| b.sectors = sectors)
    }

    /// Gives the device the file of `config`, as `loop_configure` of Linux. `dev` is the open
    /// device.
    fn configure(&self, dev: &File, fd: i32, block_size: u32, info: &Info64) -> Result<()> {
        let file = lookup(fd)?;
        if !self.unbound() {
            return Err(Errno::EBUSY);
        }
        self.validate(&file)?;
        if info.flags & !CONFIGURE_SETTABLE != 0 {
            return Err(Errno::EINVAL);
        }
        info.check()?;
        let block_size = match block_size {
            0 => SECTOR_SIZE as u32,
            n if valid_block_size(u64::from(n)) => n,
            _ => return Err(Errno::EINVAL),
        };
        let mut flags = info.flags;
        if !file.flags().writable() || !dev.flags().writable() {
            flags |= LO_FLAGS_READ_ONLY;
        }
        if file.flags().0 & O_DIRECT != 0 {
            flags |= LO_FLAGS_DIRECT_IO;
        }
        // Linux writes the dirty data of the file first, for a change to direct I/O.
        let _ = file.sync();
        let sectors = sectors_of(file_size(&file), info.offset, info.sizelimit);
        if let Some(cache) = blockdev::block_cache(self.rdev) {
            cache.forget(0, u64::MAX);
        }
        let mut inner = self.inner.lock();
        if inner.backing.is_some() || inner.rundown {
            return Err(Errno::EBUSY);
        }
        inner.backing = Some(Backing {
            file,
            offset: info.offset,
            sizelimit: info.sizelimit,
            flags,
            file_name: info.name(),
            block_size,
            sectors,
        });
        Ok(())
    }

    /// Checks the file of a new configuration, as `loop_validate_file` of Linux. The file must
    /// be a regular file or a block device. A chain of loop devices must not come back to this
    /// device.
    fn validate(&self, file: &Arc<File>) -> Result<()> {
        let mut f = file.clone();
        loop {
            let meta = f.metadata()?;
            match meta.mode & mode::S_IFMT {
                mode::S_IFREG => return Ok(()),
                mode::S_IFBLK if major(meta.rdev) == LOOP_MAJOR => {
                    if meta.rdev == self.rdev {
                        return Err(Errno::EBADF);
                    }
                    let next = find(minor(meta.rdev)).ok_or(Errno::EINVAL)?;
                    f = next.file().map_err(|_| Errno::EINVAL)?;
                }
                mode::S_IFBLK => return Ok(()),
                _ => return Err(Errno::EINVAL),
            }
        }
    }

    /// Marks the device so that it lets its file go at the last close, as `loop_clr_fd` of
    /// Linux. If the caller has the only open, the device takes no new open.
    fn clear_fd(&self) -> Result<()> {
        let openers = blockdev::block_openers(self.rdev);
        let mut inner = self.inner.lock();
        if inner.rundown {
            return Err(Errno::ENXIO);
        }
        let b = inner.backing.as_mut().ok_or(Errno::ENXIO)?;
        b.flags |= LO_FLAGS_AUTOCLEAR;
        if openers == 1 {
            inner.rundown = true;
        }
        Ok(())
    }

    /// Writes the dirty pages of the device to the file, drops the cache and lets the file go,
    /// as `__loop_clr_fd` of Linux.
    fn detach(&self) {
        if let Some(cache) = blockdev::block_cache(self.rdev) {
            let _ = cache.sync();
            cache.forget(0, u64::MAX);
        }
        let backing = {
            let mut inner = self.inner.lock();
            inner.rundown = false;
            inner.backing.take()
        };
        drop(backing);
    }

    /// Sets the status, as `loop_set_status` of Linux.
    fn set_status(&self, info: &Info64) -> Result<()> {
        let (file, changed) = self
            .with(|b| (b.file.clone(), b.offset != info.offset || b.sizelimit != info.sizelimit))?;
        if changed && let Some(cache) = blockdev::block_cache(self.rdev) {
            cache.sync()?;
            cache.forget(0, u64::MAX);
        }
        info.check()?;
        let sectors = sectors_of(file_size(&file), info.offset, info.sizelimit);
        self.with(|b| {
            b.offset = info.offset;
            b.sizelimit = info.sizelimit;
            b.file_name = info.name();
            b.flags = (b.flags & !SET_STATUS_CLEARABLE) | (info.flags & SET_STATUS_SETTABLE);
            if changed {
                b.sectors = sectors;
            }
        })
    }

    /// Gives the status, as `loop_get_status` of Linux.
    fn status(&self) -> Result<Info64> {
        let (mut info, file) = self.with(|b| {
            let mut info = Info64::empty();
            info.number = self.number;
            info.offset = b.offset;
            info.sizelimit = b.sizelimit;
            info.flags = b.flags;
            info.file_name = b.file_name;
            (info, b.file.clone())
        })?;
        let meta = file.metadata()?;
        info.device = meta.dev;
        info.inode = meta.ino;
        info.rdevice = meta.rdev;
        Ok(info)
    }

    /// The files of `/sys/block/loopN/loop`, if the device has a file.
    fn sysfs_files(&self) -> Option<Vec<(&'static str, String)>> {
        let inner = self.inner.lock();
        let b = inner.backing.as_ref()?;
        let path = match b.file.location() {
            Some(at) => at.absolute_path(),
            None => b.file_name.iter().copied().take_while(|&c| c != 0).collect(),
        };
        let bit = |flag: u32| String::from(if b.flags & flag != 0 { "1\n" } else { "0\n" });
        Some(alloc::vec![
            ("autoclear", bit(LO_FLAGS_AUTOCLEAR)),
            ("backing_file", format!("{}\n", String::from_utf8_lossy(&path))),
            ("dio", bit(LO_FLAGS_DIRECT_IO)),
            ("offset", format!("{}\n", b.offset)),
            ("partscan", bit(LO_FLAGS_PARTSCAN)),
            ("sizelimit", format!("{}\n", b.sizelimit)),
        ])
    }
}

impl BlockDevice for LoopDevice {
    fn sectors(&self) -> u64 {
        self.inner.lock().backing.as_ref().map_or(0, |b| b.sectors)
    }

    fn read_only(&self) -> bool {
        self.inner.lock().backing.as_ref().is_some_and(|b| b.flags & LO_FLAGS_READ_ONLY != 0)
    }

    /// Reads the file. The part of `buf` past the end of the file gets zeros, as Linux.
    fn read(&self, sector: u64, buf: &mut [u8]) -> Result<()> {
        let (file, pos) = self.target(sector)?;
        let mut done = 0;
        while done < buf.len() {
            let n = file.ops().read_at(&file, pos + done as u64, &mut buf[done..])?;
            if n == 0 {
                break;
            }
            done += n;
        }
        buf[done..].fill(0);
        Ok(())
    }

    /// Writes the file. A short write gives `EIO`, as Linux.
    fn write(&self, sector: u64, buf: &[u8]) -> Result<()> {
        let (file, pos) = self.target(sector)?;
        let mut done = 0;
        while done < buf.len() {
            let n = file.ops().write_at(&file, pos + done as u64, &buf[done..])?;
            if n == 0 {
                return Err(Errno::EIO);
            }
            done += n;
        }
        Ok(())
    }

    /// Makes the file durable, as `lo_req_flush` of Linux.
    fn flush(&self) -> Result<()> {
        match self.file() {
            Ok(file) => file.sync(),
            Err(_) => Ok(()),
        }
    }
}

impl BlockOps for LoopDevice {
    /// A device that lets its file go does not take a new open, as `lo_open` of Linux.
    fn open(&self) -> Result<()> {
        if self.inner.lock().rundown { Err(Errno::ENXIO) } else { Ok(()) }
    }

    /// At the last close, a device with `LO_FLAGS_AUTOCLEAR` lets its file go, as `lo_release`
    /// of Linux.
    fn release(&self) {
        let clear = {
            let mut inner = self.inner.lock();
            if inner.backing.as_ref().is_some_and(|b| b.flags & LO_FLAGS_AUTOCLEAR != 0) {
                inner.rundown = true;
            }
            inner.rundown
        };
        if clear {
            self.detach();
        }
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        // The commands that change the device need a device open for writing, or
        // `CAP_SYS_ADMIN`.
        let may_change = || {
            if file.flags().writable()
                || crate::cred::current().capable(crate::cred::cap::SYS_ADMIN)
            {
                Ok(())
            } else {
                Err(Errno::EPERM)
            }
        };
        match cmd {
            LOOP_SET_FD => self.configure(file, arg as i32, 0, &Info64::empty()).map(|()| 0),
            LOOP_CONFIGURE => {
                let mut b = [0u8; CONFIG_SIZE];
                mem.read(arg, &mut b)?;
                let info = Info64::parse(&b[8..8 + INFO64_SIZE]);
                self.configure(file, u32_at(&b, 0) as i32, u32_at(&b, 4), &info).map(|()| 0)
            }
            LOOP_CHANGE_FD => Err(Errno::EOPNOTSUPP),
            LOOP_CLR_FD => self.clear_fd().map(|()| 0),
            LOOP_SET_STATUS64 => {
                may_change()?;
                let mut b = [0u8; INFO64_SIZE];
                mem.read(arg, &mut b)?;
                self.set_status(&Info64::parse(&b)).map(|()| 0)
            }
            // The old structure, as `loop_set_status_old` and `loop_get_status_old` of Linux.
            LOOP_SET_STATUS => {
                may_change()?;
                let mut b = [0u8; old::SIZE];
                mem.read(arg, &mut b)?;
                self.set_status(&Info64::parse_old(&b)).map(|()| 0)
            }
            LOOP_GET_STATUS => {
                if arg == 0 {
                    return Err(Errno::EINVAL);
                }
                mem.write(arg, &self.status()?.bytes_old()?)?;
                Ok(0)
            }
            LOOP_GET_STATUS64 => {
                if arg == 0 {
                    return Err(Errno::EINVAL);
                }
                let info = self.status()?;
                mem.write(arg, &info.bytes())?;
                Ok(0)
            }
            LOOP_SET_CAPACITY => {
                may_change()?;
                let file = self.file()?;
                let (offset, sizelimit) = self.with(|b| (b.offset, b.sizelimit))?;
                self.resize(sectors_of(file_size(&file), offset, sizelimit)).map(|()| 0)
            }
            LOOP_SET_DIRECT_IO => {
                may_change()?;
                self.with(|b| {
                    if arg != 0 {
                        b.flags |= LO_FLAGS_DIRECT_IO;
                    } else {
                        b.flags &= !LO_FLAGS_DIRECT_IO;
                    }
                })
                .map(|()| 0)
            }
            LOOP_SET_BLOCK_SIZE => {
                may_change()?;
                if !valid_block_size(arg as u64) {
                    // Linux gives `ENXIO` before the check of the size for a device with no file.
                    self.with(|_| ())?;
                    return Err(Errno::EINVAL);
                }
                self.with(|b| b.block_size = arg as u32).map(|()| 0)
            }
            _ => Err(Errno::ENOTTY),
        }
    }
}

/// Gives the loop device of index `index`.
fn find(index: u32) -> Option<Arc<LoopDevice>> {
    LOOPS.lock().get(&index).cloned()
}

/// Adds the loop device `index`, or the first free index for `None`, as `loop_add` of Linux.
/// Gives the index.
fn add(index: Option<u32>) -> Result<u32> {
    let dev = {
        let mut loops = LOOPS.lock();
        let n = match index {
            Some(i) if i >= MAX_INDEX => return Err(Errno::EINVAL),
            Some(i) if loops.contains_key(&i) => return Err(Errno::EEXIST),
            Some(i) => i,
            None => (0..MAX_INDEX).find(|i| !loops.contains_key(i)).ok_or(Errno::ENOSPC)?,
        };
        let dev = Arc::new(LoopDevice::new(n));
        loops.insert(n, dev.clone());
        dev
    };
    let name = format!("loop{}", dev.number);
    blockdev::register_block_ops(dev.rdev, &name, dev.clone(), dev.clone());
    Ok(dev.number)
}

/// Removes the loop device `index`, as `loop_control_remove` of Linux.
fn remove(index: u32) -> Result<()> {
    let dev = find(index).ok_or(Errno::ENODEV)?;
    if !dev.unbound() {
        return Err(Errno::EBUSY);
    }
    blockdev::unregister_block(dev.rdev)?;
    LOOPS.lock().remove(&index);
    Ok(())
}

/// Gives the first loop device with no file, or adds one, as `loop_control_get_free` of Linux.
fn get_free() -> Result<u32> {
    let loops: Vec<Arc<LoopDevice>> = LOOPS.lock().values().cloned().collect();
    match loops.iter().find(|l| l.unbound()) {
        Some(l) => Ok(l.number),
        None => add(None),
    }
}

/// Gives the files of `/sys/block/loopN/loop` of the block device `rdev`: the name and the text
/// of each. Gives `None` if `rdev` is not a loop device with a file.
pub fn sysfs_files(rdev: u64) -> Option<Vec<(&'static str, String)>> {
    if major(rdev) != LOOP_MAJOR {
        return None;
    }
    find(minor(rdev))?.sysfs_files()
}

/// The driver of `/dev/loop-control`.
struct Control;

impl CharDevice for Control {
    fn open(&self, _flags: u32) -> Result<Arc<dyn FileOps>> {
        Ok(Arc::new(Control))
    }
}

impl FileOps for Control {
    fn ioctl(&self, _file: &File, cmd: u32, arg: usize, _mem: &dyn UserMemory) -> Result<usize> {
        // The argument is an `int` index.
        let index = u32::try_from(arg as i32);
        let n = match cmd {
            LOOP_CTL_ADD => add(index.ok())?,
            LOOP_CTL_REMOVE => {
                remove(index.map_err(|_| Errno::EINVAL)?)?;
                0
            }
            LOOP_CTL_GET_FREE => get_free()?,
            _ => return Err(Errno::ENOSYS),
        };
        Ok(n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inode::Metadata;
    use rk_abi::native::open::{O_RDONLY, O_RDWR};

    /// A file in memory.
    struct MemFile(SpinLock<Vec<u8>>);

    impl FileOps for MemFile {
        fn read_at(&self, _file: &File, offset: u64, buf: &mut [u8]) -> Result<usize> {
            let data = self.0.lock();
            let start = (offset as usize).min(data.len());
            let n = buf.len().min(data.len() - start);
            buf[..n].copy_from_slice(&data[start..start + n]);
            Ok(n)
        }

        fn write_at(&self, _file: &File, offset: u64, buf: &[u8]) -> Result<usize> {
            let mut data = self.0.lock();
            let end = offset as usize + buf.len();
            if end > data.len() {
                data.resize(end, 0);
            }
            data[offset as usize..end].copy_from_slice(buf);
            Ok(buf.len())
        }

        fn metadata(&self) -> Option<Metadata> {
            let size = self.0.lock().len() as u64;
            Some(Metadata {
                mode: mode::S_IFREG | 0o644,
                size,
                ino: 42,
                dev: 9,
                ..Metadata::default()
            })
        }
    }

    /// The files of the test descriptors.
    static FDS: SpinLock<BTreeMap<i32, Arc<File>>> = SpinLock::new(BTreeMap::new());

    fn test_lookup(fd: i32) -> Result<Arc<File>> {
        FDS.lock().get(&fd).cloned().ok_or(Errno::EBADF)
    }

    /// The memory of a process, from the address 0.
    struct Mem(SpinLock<Vec<u8>>);

    impl UserMemory for Mem {
        fn read(&self, addr: usize, buf: &mut [u8]) -> Result<()> {
            buf.copy_from_slice(&self.0.lock()[addr..addr + buf.len()]);
            Ok(())
        }

        fn write(&self, addr: usize, buf: &[u8]) -> Result<()> {
            self.0.lock()[addr..addr + buf.len()].copy_from_slice(buf);
            Ok(())
        }
    }

    /// Adds a loop device and a file of `size` bytes with the descriptor `fd`, which has the
    /// byte `i % 251` at the offset `i`.
    fn setup(index: u32, fd: i32, size: usize, flags: u32) -> (Arc<MemFile>, u64) {
        set_file_lookup(test_lookup);
        let data = (0..size).map(|i| (i % 251) as u8).collect();
        let mem = Arc::new(MemFile(SpinLock::new(data)));
        FDS.lock().insert(fd, File::with_ops(mem.clone(), None, flags));
        assert_eq!(add(Some(index)), Ok(index));
        (mem, makedev(LOOP_MAJOR, index))
    }

    fn config(fd: i32, offset: u64, sizelimit: u64, flags: u32) -> Vec<u8> {
        let mut info = Info64::empty();
        info.offset = offset;
        info.sizelimit = sizelimit;
        info.flags = flags;
        info.file_name[..4].copy_from_slice(b"file");
        let mut b = alloc::vec![0u8; CONFIG_SIZE];
        b[0..4].copy_from_slice(&(fd as u32).to_ne_bytes());
        b[8..8 + INFO64_SIZE].copy_from_slice(&info.bytes());
        b
    }

    #[test]
    fn the_size_comes_from_the_file_the_offset_and_the_limit() {
        assert_eq!(sectors_of(4096, 0, 0), 8);
        assert_eq!(sectors_of(4096, 1024, 0), 6);
        assert_eq!(sectors_of(4096, 1024, 1024), 2);
        assert_eq!(sectors_of(4096, 8192, 0), 0);
        assert_eq!(sectors_of(1000, 0, 0), 1);
        assert!(valid_block_size(4096) && !valid_block_size(256) && !valid_block_size(1536));
    }

    #[test]
    fn loop_info64_has_the_layout_of_linux() {
        let mut info = Info64::empty();
        info.offset = 0x1122;
        info.number = 3;
        info.flags = LO_FLAGS_AUTOCLEAR;
        info.file_name[0] = b'x';
        let b = info.bytes();
        assert_eq!(u64_at(&b, 24), 0x1122);
        assert_eq!(u32_at(&b, 40), 3);
        assert_eq!(u32_at(&b, 52), LO_FLAGS_AUTOCLEAR);
        assert_eq!(b[56], b'x');
        assert_eq!(Info64::parse(&b), info);
        info.encrypt_type = 1;
        assert_eq!(info.check(), Err(Errno::EINVAL));
        info.encrypt_type = 0;
        info.sizelimit = u64::MAX;
        assert_eq!(info.check(), Err(Errno::EOVERFLOW));
    }

    #[test]
    fn the_old_loop_info_sets_and_gives_the_status() {
        let (_, rdev) = setup(902, 902, 8192, O_RDWR);
        let dev = File::with_ops(blockdev::open_block(rdev, O_RDWR).unwrap(), None, O_RDWR);
        let user = Mem(SpinLock::new(alloc::vec![0u8; old::SIZE]));
        // The device has no file yet.
        assert_eq!(dev.ioctl(LOOP_SET_STATUS, 0, &user), Err(Errno::ENXIO));
        assert_eq!(dev.ioctl(LOOP_GET_STATUS, 0, &user), Err(Errno::EINVAL));
        dev.ioctl(LOOP_SET_FD, 902, &user).unwrap();
        // `tst_attach_device` of LTP sets the name with the old structure.
        let mut b = [0u8; old::SIZE];
        b[old::AT[4]..old::AT[4] + 4].copy_from_slice(&512u32.to_ne_bytes());
        b[old::AT[7]..old::AT[7] + 4].copy_from_slice(&LO_FLAGS_AUTOCLEAR.to_ne_bytes());
        b[old::AT[8]..old::AT[8] + 4].copy_from_slice(b"swap");
        user.0.lock().copy_from_slice(&b);
        dev.ioctl(LOOP_SET_STATUS, 0, &user).unwrap();
        assert_eq!(dev.ops().end(), Some(8192 - 512));
        // The structure goes at the address 8, because the address 0 gives `EINVAL`.
        *user.0.lock() = alloc::vec![0u8; 8 + old::SIZE];
        dev.ioctl(LOOP_GET_STATUS, 8, &user).unwrap();
        let got = user.0.lock()[8..].to_vec();
        assert_eq!(u32_at(&got, old::AT[0]), 902);
        assert_eq!(u64_at(&got, old::AT[2]), 42);
        assert_eq!(u32_at(&got, old::AT[4]), 512);
        assert_eq!(u32_at(&got, old::AT[7]), LO_FLAGS_AUTOCLEAR);
        assert_eq!(&got[old::AT[8]..old::AT[8] + 5], b"swap\0");
        dev.ioctl(LOOP_CLR_FD, 0, &user).unwrap();
        drop(dev);
        assert!(sysfs_files(rdev).is_none());
        Control
            .ioctl(&File::with_ops(Arc::new(Control), None, O_RDWR), LOOP_CTL_REMOVE, 902, &user)
            .unwrap();
    }

    #[test]
    fn a_loop_device_reads_and_writes_its_file_at_the_offset() {
        let (mem, rdev) = setup(900, 900, 8192, O_RDWR);
        let dev = File::with_ops(blockdev::open_block(rdev, O_RDWR).unwrap(), None, O_RDWR);
        assert_eq!(dev.ops().end(), Some(0));
        let user = Mem(SpinLock::new(config(900, 1024, 4096, 0)));
        dev.ioctl(LOOP_CONFIGURE, 0, &user).unwrap();
        assert_eq!(dev.ioctl(LOOP_CONFIGURE, 0, &user), Err(Errno::EBUSY));
        assert_eq!(dev.ops().end(), Some(4096));
        let mut buf = [0u8; 4];
        dev.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, [1024 % 251, 1025 % 251, 1026 % 251, 1027 % 251].map(|x| x as u8));
        dev.write_at(512, b"abcd").unwrap();
        dev.sync().unwrap();
        assert_eq!(&mem.0.lock()[1536..1540], b"abcd");

        user.0.lock().resize(CONFIG_SIZE + INFO64_SIZE, 0);
        dev.ioctl(LOOP_GET_STATUS64, CONFIG_SIZE, &user).unwrap();
        let info = Info64::parse(&user.0.lock()[CONFIG_SIZE..]);
        assert_eq!((info.number, info.offset, info.sizelimit), (900, 1024, 4096));
        assert_eq!((info.device, info.inode), (9, 42));
        assert_eq!(&info.file_name[..5], b"file\0");
        let files = sysfs_files(rdev).unwrap();
        assert!(files.contains(&("offset", String::from("1024\n"))));
        assert!(files.contains(&("backing_file", String::from("file\n"))));

        // The file grows, and `LOOP_SET_CAPACITY` reads its size again.
        mem.0.lock().resize(16384, 0);
        dev.ioctl(LOOP_SET_CAPACITY, 0, &user).unwrap();
        assert_eq!(dev.ops().end(), Some(4096));
        let mut info = info.clone();
        info.sizelimit = 0;
        user.0.lock()[CONFIG_SIZE..].copy_from_slice(&info.bytes());
        dev.ioctl(LOOP_SET_STATUS64, CONFIG_SIZE, &user).unwrap();
        assert_eq!(dev.ops().end(), Some(16384 - 1024));
        dev.ioctl(LOOP_SET_BLOCK_SIZE, 4096, &user).unwrap();
        assert_eq!(dev.ioctl(LOOP_SET_BLOCK_SIZE, 3000, &user), Err(Errno::EINVAL));
        dev.ioctl(LOOP_SET_DIRECT_IO, 1, &user).unwrap();
        assert!(sysfs_files(rdev).unwrap().contains(&("dio", String::from("1\n"))));

        // The file goes at the last close after `LOOP_CLR_FD`.
        assert_eq!(Control.ioctl(&dev, LOOP_CTL_REMOVE, 900, &user), Err(Errno::EBUSY));
        dev.ioctl(LOOP_CLR_FD, 0, &user).unwrap();
        assert!(blockdev::open_block(rdev, O_RDWR).is_err());
        drop(dev);
        assert!(sysfs_files(rdev).is_none());
        assert_eq!(blockdev::block_sectors(rdev), Some(0));
        Control
            .ioctl(&File::with_ops(Arc::new(Control), None, O_RDWR), LOOP_CTL_REMOVE, 900, &user)
            .unwrap();
        assert!(blockdev::block_sectors(rdev).is_none());
    }

    #[test]
    fn autoclear_lets_the_file_go_at_the_last_close() {
        let (_, rdev) = setup(901, 901, 4096, O_RDONLY);
        let dev = File::with_ops(blockdev::open_block(rdev, O_RDWR).unwrap(), None, O_RDWR);
        let user = Mem(SpinLock::new(config(901, 0, 0, LO_FLAGS_AUTOCLEAR)));
        dev.ioctl(LOOP_CONFIGURE, 0, &user).unwrap();
        // A file open for reading only makes a read only device.
        assert_eq!(dev.write_at(0, b"x"), Err(Errno::EPERM));
        let mount = blockdev::mount_block(rdev).unwrap();
        drop(dev);
        assert_eq!(blockdev::block_sectors(rdev), Some(8));
        drop(mount);
        assert_eq!(blockdev::block_sectors(rdev), Some(0));
        let user = Mem(SpinLock::new(config(901, 0, 0, 0x100)));
        let dev = File::with_ops(blockdev::open_block(rdev, O_RDWR).unwrap(), None, O_RDWR);
        assert_eq!(dev.ioctl(LOOP_CONFIGURE, 0, &user), Err(Errno::EINVAL));
        assert_eq!(dev.ioctl(LOOP_SET_FD, 5555, &user), Err(Errno::EBADF));
        assert_eq!(dev.ioctl(LOOP_CLR_FD, 0, &user), Err(Errno::ENXIO));
    }

    #[test]
    fn the_control_device_adds_and_finds_devices() {
        let ctl = File::with_ops(Arc::new(Control), None, O_RDWR);
        let user = Mem(SpinLock::new(Vec::new()));
        assert_eq!(ctl.ioctl(LOOP_CTL_ADD, 910, &user), Ok(910));
        assert_eq!(ctl.ioctl(LOOP_CTL_ADD, 910, &user), Err(Errno::EEXIST));
        assert_eq!(ctl.ioctl(LOOP_CTL_REMOVE, 911, &user), Err(Errno::ENODEV));
        assert_eq!(ctl.ioctl(LOOP_CTL_REMOVE, usize::MAX, &user), Err(Errno::EINVAL));
        assert_eq!(ctl.ioctl(0x4c83, 0, &user), Err(Errno::ENOSYS));
        let free = ctl.ioctl(LOOP_CTL_GET_FREE, 0, &user).unwrap() as u32;
        assert!(find(free).is_some());
        assert_eq!(ctl.ioctl(LOOP_CTL_REMOVE, 910, &user), Ok(0));
        assert!(find(910).is_none());
    }
}

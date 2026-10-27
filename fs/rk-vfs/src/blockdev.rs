//! Block devices and their device files.
//!
//! A driver gives a `BlockDevice`, which reads and writes whole sectors of 512 bytes, and the
//! block layer puts a queue in front of it. Each device has a page cache over its queue. An open
//! file of the device reads and writes at each byte offset through the cache. A file with
//! `O_DIRECT` goes to the queue. It first writes the dirty pages of its range to the disk, and a
//! write then drops the cached pages of its range. A part of a sector is read, changed and written
//! again.

use crate::file::{BatchIo, File, FileOps, UserMemory};
use crate::inode::Result;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::open::{O_DIRECT, O_EXCL};
use rk_block::cache::{PAGE_SIZE, PageCache};
use rk_block::{Bio, Op, Queue};
use rk_frame::sync::SpinLock;

pub use rk_block::{BlockDevice, SECTOR_SIZE};

/// The `ioctl` commands of block devices, from `<linux/fs.h>`.
pub mod ioctl {
    /// Makes the device read only, from an `int` that is not 0, or writable again.
    pub const BLKROSET: u32 = 0x125d;
    /// Gives 1 if the device is read only.
    pub const BLKROGET: u32 = 0x125e;
    /// Gives the size in sectors, as an `unsigned long`.
    pub const BLKGETSIZE: u32 = 0x1260;
    /// Writes the cached data of the device to the device.
    pub const BLKFLSBUF: u32 = 0x1261;
    /// Gives the logical sector size, as an `int`.
    pub const BLKSSZGET: u32 = 0x1268;
    /// Gives the minimum I/O size, as an `unsigned int`.
    pub const BLKIOMIN: u32 = 0x1278;
    /// Gives the optimal I/O size, as an `unsigned int`.
    pub const BLKIOOPT: u32 = 0x1279;
    /// Gives the alignment offset, as an `int`.
    pub const BLKALIGNOFF: u32 = 0x127a;
    /// Gives the physical sector size, as an `unsigned int`.
    pub const BLKPBSZGET: u32 = 0x127b;
    /// Gives the block size of the device, as an `int`.
    pub const BLKBSZGET: u32 = 0x8008_1270;
    /// Sets the block size of the device, from an `int`.
    pub const BLKBSZSET: u32 = 0x4008_1271;
    /// Gives the size in bytes, as a `u64`.
    pub const BLKGETSIZE64: u32 = 0x8008_1272;
    /// Gives the sequence number of the disk, as a `u64`.
    pub const BLKGETDISKSEQ: u32 = 0x8008_1280;
}

/// The page cache of a block device.
pub type DiskCache = PageCache<Arc<Queue>>;

pub use rk_block::cache::without_wait;

/// A block device with its name in /dev.
struct Entry {
    name: String,
    cache: Arc<DiskCache>,
    /// The count of mounts that use the device.
    mounts: u32,
    /// Tells if a file has the device open with `O_EXCL`.
    exclusive: bool,
    /// The count of open files and mounts of the device, as `disk_openers` of Linux.
    opens: u32,
    /// The driver calls of the device, if the driver has them.
    ops: Option<Arc<dyn BlockOps>>,
}

/// The calls of a block driver at an open, at the last close and for its own `ioctl` commands,
/// as `block_device_operations` of Linux. A mount is an open too.
pub trait BlockOps: Send + Sync {
    /// Accepts or refuses a new open of the device.
    ///
    /// # Errors
    ///
    /// Gives the error of the driver.
    fn open(&self) -> Result<()> {
        Ok(())
    }

    /// Tells the driver that the last open file or mount of the device closed.
    fn release(&self) {}

    /// Does an `ioctl` command that the block layer does not know. `file` is the open device.
    ///
    /// # Errors
    ///
    /// Gives `ENOTTY` for an unknown command, or the error of the command.
    fn ioctl(&self, _file: &File, _cmd: u32, _arg: usize, _mem: &dyn UserMemory) -> Result<usize> {
        Err(Errno::ENOTTY)
    }
}

/// One open file or mount of a block device. The count of opens goes down when the value drops,
/// and the driver gets `release` at the last close.
struct Opener {
    rdev: u64,
}

impl Opener {
    /// Asks the driver of `rdev` for a new open, and counts it.
    fn new(rdev: u64) -> Result<Self> {
        let ops = BLOCK_DEVICES.lock().get(&rdev).ok_or(Errno::ENXIO)?.ops.clone();
        if let Some(ops) = ops {
            ops.open()?;
        }
        BLOCK_DEVICES.lock().get_mut(&rdev).ok_or(Errno::ENXIO)?.opens += 1;
        Ok(Self { rdev })
    }
}

impl Drop for Opener {
    fn drop(&mut self) {
        let ops = {
            let mut devices = BLOCK_DEVICES.lock();
            let Some(e) = devices.get_mut(&self.rdev) else { return };
            e.opens = e.opens.saturating_sub(1);
            if e.opens > 0 {
                return;
            }
            e.ops.clone()
        };
        if let Some(ops) = ops {
            ops.release();
        }
    }
}

/// The holder of an exclusive claim of a block device, as the holder of `bdev_open` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Holder {
    /// A mount of a file system. Two mounts of one device can share it.
    Mount,
    /// A file that has the device open with `O_EXCL`. No other holder can share it.
    File,
}

/// An exclusive claim of a block device. The claim ends when the value drops.
#[derive(Debug)]
pub struct Claim {
    rdev: u64,
    holder: Holder,
}

impl Drop for Claim {
    fn drop(&mut self) {
        if let Some(e) = BLOCK_DEVICES.lock().get_mut(&self.rdev) {
            match self.holder {
                Holder::Mount => e.mounts = e.mounts.saturating_sub(1),
                Holder::File => e.exclusive = false,
            }
        }
    }
}

/// Claims the block device `rdev` for `holder`. A mount and an open with `O_EXCL` exclude each
/// other, so that mkfs, fsck and resize2fs see that a disk is mounted.
///
/// # Errors
///
/// Gives `ENXIO` if no driver has the number, and `EBUSY` if another holder has the device.
pub fn claim_block(rdev: u64, holder: Holder) -> Result<Claim> {
    let mut devices = BLOCK_DEVICES.lock();
    let e = devices.get_mut(&rdev).ok_or(Errno::ENXIO)?;
    if e.exclusive || (holder == Holder::File && e.mounts > 0) {
        return Err(Errno::EBUSY);
    }
    match holder {
        Holder::Mount => e.mounts += 1,
        Holder::File => e.exclusive = true,
    }
    Ok(Claim { rdev, holder })
}

static BLOCK_DEVICES: SpinLock<BTreeMap<u64, Entry>> = SpinLock::new(BTreeMap::new());

/// Adds the block device `rdev` with the name `name`, for example `vda`, and puts it in the list
/// of devices.
pub fn register_block(rdev: u64, name: &str, device: Arc<dyn BlockDevice>) {
    insert_block(rdev, name, device, None);
    crate::device::add_device(block_info(rdev, name));
}

/// Adds the block device `rdev` as `register_block` does, with the driver calls `ops`. The driver
/// can add the device after the boot: the hook of `device::set_node_hook` makes its device file.
pub fn register_block_ops(
    rdev: u64,
    name: &str,
    device: Arc<dyn BlockDevice>,
    ops: Arc<dyn BlockOps>,
) {
    insert_block(rdev, name, device, Some(ops));
    crate::device::add_device_node(block_info(rdev, name));
}

fn insert_block(
    rdev: u64,
    name: &str,
    device: Arc<dyn BlockDevice>,
    ops: Option<Arc<dyn BlockOps>>,
) {
    let cache = Arc::new(PageCache::new(Arc::new(Queue::new(device))));
    let entry =
        Entry { name: String::from(name), cache, mounts: 0, exclusive: false, opens: 0, ops };
    BLOCK_DEVICES.lock().insert(rdev, entry);
}

fn block_info(rdev: u64, name: &str) -> crate::device::DeviceInfo {
    crate::device::DeviceInfo {
        name: String::from(name),
        class: "block",
        rdev,
        block: true,
        perm: 0o660,
    }
}

/// Removes the block device `rdev` and its device file, as `del_gendisk` of Linux.
///
/// # Errors
///
/// Gives `ENXIO` if no driver has the number, and `EBUSY` if a file or a mount has the device
/// open.
pub fn unregister_block(rdev: u64) -> Result<()> {
    {
        let mut devices = BLOCK_DEVICES.lock();
        let e = devices.get(&rdev).ok_or(Errno::ENXIO)?;
        if e.opens > 0 || e.mounts > 0 || e.exclusive {
            return Err(Errno::EBUSY);
        }
        devices.remove(&rdev);
    }
    crate::device::remove_device(true, rdev);
    Ok(())
}

/// Gives the count of open files and mounts of the block device `rdev`.
pub fn block_openers(rdev: u64) -> u32 {
    BLOCK_DEVICES.lock().get(&rdev).map_or(0, |e| e.opens)
}

/// Gives the size of the block device `rdev` in sectors of 512 bytes.
pub fn block_sectors(rdev: u64) -> Option<u64> {
    block_queue(rdev).map(|q| q.sectors())
}

/// Gives the queue of the block device `rdev`.
pub fn block_queue(rdev: u64) -> Option<Arc<Queue>> {
    BLOCK_DEVICES.lock().get(&rdev).map(|e| e.cache.store().clone())
}

/// Tells if the block device `rdev` does not accept writes, as `bdev_read_only` of Linux. A
/// number without a driver gives false.
pub fn block_read_only(rdev: u64) -> bool {
    block_queue(rdev).is_some_and(|q| q.read_only())
}

/// Gives the page cache of the block device `rdev`.
pub fn block_cache(rdev: u64) -> Option<Arc<DiskCache>> {
    BLOCK_DEVICES.lock().get(&rdev).map(|e| e.cache.clone())
}

/// The page cache of a block device that a file system has mounted. The device stays claimed
/// until the file system drops it.
pub struct MountedDisk {
    /// The page cache of the device.
    pub cache: Arc<DiskCache>,
    _claim: Claim,
    _opener: Opener,
}

/// Claims the block device `rdev` for a mount, and gives its page cache.
///
/// # Errors
///
/// Gives `ENXIO` if no driver has the number, and `EBUSY` if a file has the device open with
/// `O_EXCL`.
pub fn mount_block(rdev: u64) -> Result<MountedDisk> {
    let cache = block_cache(rdev).ok_or(Errno::ENXIO)?;
    let opener = Opener::new(rdev)?;
    Ok(MountedDisk { cache, _claim: claim_block(rdev, Holder::Mount)?, _opener: opener })
}

/// Writes the dirty pages of each block device to the disk, and makes them durable, for `sync`.
///
/// # Errors
///
/// Gives the first error of a device. The other devices are written all the same.
pub fn sync_all() -> Result<()> {
    let caches: Vec<Arc<DiskCache>> =
        BLOCK_DEVICES.lock().values().map(|e| e.cache.clone()).collect();
    let mut result = Ok(());
    for cache in caches {
        result = result.and(cache.sync());
    }
    result
}

/// Removes the clean pages of each block device from the cache, for `/proc/sys/vm/drop_caches`.
/// The dirty pages stay in the cache.
pub fn drop_clean_all() {
    let caches: Vec<Arc<DiskCache>> =
        BLOCK_DEVICES.lock().values().map(|e| e.cache.clone()).collect();
    for cache in caches {
        cache.drop_clean();
    }
}

/// Gives the name and the device number of each block device.
pub fn block_devices() -> Vec<(String, u64)> {
    BLOCK_DEVICES.lock().iter().map(|(rdev, e)| (e.name.clone(), *rdev)).collect()
}

/// Opens the block device `rdev`. With `O_EXCL` the file claims the device until it closes.
/// Gives `ENXIO` if no driver has the number, and `EBUSY` for `O_EXCL` if the device is mounted
/// or open with `O_EXCL`, as Linux.
pub fn open_block(rdev: u64, flags: u32) -> Result<Arc<dyn FileOps>> {
    let cache = block_cache(rdev).ok_or(Errno::ENXIO)?;
    let ops = BLOCK_DEVICES.lock().get(&rdev).and_then(|e| e.ops.clone());
    let opener = Opener::new(rdev)?;
    let claim = if flags & O_EXCL != 0 { Some(claim_block(rdev, Holder::File)?) } else { None };
    let queue = cache.store().clone();
    Ok(Arc::new(BlockFile { queue, cache, ops, _claim: claim, _opener: Some(opener) }))
}

/// The operations of an open block device.
struct BlockFile {
    queue: Arc<Queue>,
    cache: Arc<DiskCache>,
    /// The driver calls of the device.
    ops: Option<Arc<dyn BlockOps>>,
    /// The claim of a file with `O_EXCL`.
    _claim: Option<Claim>,
    /// The count of this open. It drops after the claim.
    _opener: Option<Opener>,
}

/// Tells if `file` goes to the queue without the cache.
fn direct(file: &File) -> bool {
    file.flags().0 & O_DIRECT != 0
}

impl BlockFile {
    fn size(&self) -> u64 {
        self.queue.sectors() * SECTOR_SIZE as u64
    }

    fn read_file(&self, file: &File, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if !direct(file) {
            return self.cache.read(offset, buf);
        }
        self.cache.write_back(offset, buf.len() as u64)?;
        self.read_bytes(offset, buf)
    }

    fn write_file(&self, file: &File, offset: u64, buf: &[u8]) -> Result<usize> {
        if self.queue.read_only() {
            return Err(Errno::EPERM);
        }
        if !direct(file) {
            return self.cache.write(offset, buf);
        }
        self.cache.write_back(offset, buf.len() as u64)?;
        let r = self.write_bytes(offset, buf);
        self.cache.forget(offset, buf.len() as u64);
        r
    }

    /// The sectors from `first` that hold `len` bytes at `offset` in the sector.
    fn span(offset: u64, len: usize) -> (u64, usize) {
        let first = offset / SECTOR_SIZE as u64;
        let end = (offset + len as u64).div_ceil(SECTOR_SIZE as u64);
        (first, (end - first) as usize)
    }

    fn read_bytes(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let size = self.size();
        if offset >= size || buf.is_empty() {
            return Ok(0);
        }
        let len = buf.len().min((size - offset) as usize);
        let (first, count) = Self::span(offset, len);
        let mut sectors = vec![0u8; count * SECTOR_SIZE];
        self.queue.read(first, &mut sectors)?;
        let start = (offset - first * SECTOR_SIZE as u64) as usize;
        buf[..len].copy_from_slice(&sectors[start..start + len]);
        Ok(len)
    }

    fn write_bytes(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        if self.queue.read_only() {
            return Err(Errno::EPERM);
        }
        let size = self.size();
        if offset >= size {
            return if buf.is_empty() { Ok(0) } else { Err(Errno::ENOSPC) };
        }
        let len = buf.len().min((size - offset) as usize);
        if len == 0 {
            return Ok(0);
        }
        let (first, count) = Self::span(offset, len);
        let start = (offset - first * SECTOR_SIZE as u64) as usize;
        let mut sectors = vec![0u8; count * SECTOR_SIZE];
        // A write of part of a sector keeps the other bytes of the sector.
        if start != 0 || !len.is_multiple_of(SECTOR_SIZE) {
            self.queue.read(first, &mut sectors)?;
        }
        sectors[start..start + len].copy_from_slice(&buf[..len]);
        self.queue.write(first, &sectors)?;
        Ok(len)
    }

    /// Gives the bio of a batch entry, if the entry is for whole sectors on the device.
    fn bio(&self, io: &BatchIo) -> Option<Bio> {
        let sector_size = SECTOR_SIZE as u64;
        let len = io.buf.len() as u64;
        if !io.offset.is_multiple_of(sector_size) || !len.is_multiple_of(sector_size) || len == 0 {
            return None;
        }
        if io.offset.checked_add(len).is_none_or(|end| end > self.size()) {
            return None;
        }
        let op = if io.write { Op::Write } else { Op::Read };
        let data = if io.write { io.buf.clone() } else { vec![0u8; io.buf.len()] };
        Some(Bio::new(op, io.offset / sector_size, data))
    }

    fn put(mem: &dyn UserMemory, arg: usize, bytes: &[u8]) -> Result<usize> {
        mem.write(arg, bytes)?;
        Ok(0)
    }
}

impl FileOps for BlockFile {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        let n = self.read_file(file, file.pos(), buf)?;
        file.set_pos(file.pos() + n as u64);
        Ok(n)
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize> {
        let n = self.write_file(file, file.pos(), buf)?;
        file.set_pos(file.pos() + n as u64);
        Ok(n)
    }

    fn read_at(&self, file: &File, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.read_file(file, offset, buf)
    }

    fn write_at(&self, file: &File, offset: u64, buf: &[u8]) -> Result<usize> {
        self.write_file(file, offset, buf)
    }

    fn seekable(&self) -> bool {
        true
    }

    /// Without `O_DIRECT`, each entry goes to the cache. With `O_DIRECT`, the entries for whole
    /// sectors go to the queue as one batch, so that near entries merge. The other entries go
    /// one at a time.
    fn rw_batch(&self, file: &File, ios: &mut [BatchIo]) {
        if !direct(file) {
            for io in ios {
                io.result = if io.write {
                    self.write_file(file, io.offset, &io.buf)
                } else {
                    self.read_file(file, io.offset, &mut io.buf)
                };
            }
            return;
        }
        let first = ios.iter().map(|io| io.offset).min().unwrap_or(0);
        let end = ios.iter().map(|io| io.offset.saturating_add(io.buf.len() as u64)).max();
        if let Err(e) = self.cache.write_back(first, end.unwrap_or(0).saturating_sub(first)) {
            for io in ios {
                io.result = Err(e);
            }
            return;
        }
        let mut bios = Vec::new();
        let mut owners = Vec::new();
        for (i, io) in ios.iter_mut().enumerate() {
            if let Some(bio) = self.bio(io) {
                bios.push(bio);
                owners.push(i);
            } else if io.write {
                io.result = self.write_bytes(io.offset, &io.buf);
            } else {
                io.result = self.read_bytes(io.offset, &mut io.buf);
            }
        }
        self.queue.submit(&mut bios);
        for (bio, i) in bios.into_iter().zip(owners) {
            let io = &mut ios[i];
            io.result = bio.result.map(|()| io.buf.len());
            if !io.write && io.result.is_ok() {
                io.buf = bio.data;
            }
        }
        for io in ios.iter().filter(|io| io.write) {
            self.cache.forget(io.offset, io.buf.len() as u64);
        }
    }

    fn end(&self) -> Option<u64> {
        Some(self.size())
    }

    fn sync(&self) -> Result<()> {
        self.cache.sync()
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        match cmd {
            ioctl::BLKGETSIZE64 => Self::put(mem, arg, &self.size().to_ne_bytes()),
            ioctl::BLKGETSIZE => Self::put(mem, arg, &self.queue.sectors().to_ne_bytes()),
            ioctl::BLKSSZGET | ioctl::BLKPBSZGET | ioctl::BLKIOMIN => {
                Self::put(mem, arg, &(SECTOR_SIZE as u32).to_ne_bytes())
            }
            ioctl::BLKIOOPT | ioctl::BLKALIGNOFF => Self::put(mem, arg, &0u32.to_ne_bytes()),
            ioctl::BLKBSZGET => Self::put(mem, arg, &(PAGE_SIZE as u32).to_ne_bytes()),
            ioctl::BLKBSZSET => {
                // The cache keeps whole pages, so the block size changes nothing. Linux takes a
                // power of two from the sector size to the page size.
                let mut b = [0u8; 4];
                mem.read(arg, &mut b)?;
                let size = u32::from_ne_bytes(b) as usize;
                if size.is_power_of_two() && (SECTOR_SIZE..=PAGE_SIZE).contains(&size) {
                    Ok(0)
                } else {
                    Err(Errno::EINVAL)
                }
            }
            ioctl::BLKGETDISKSEQ => Self::put(mem, arg, &1u64.to_ne_bytes()),
            ioctl::BLKROSET => {
                // As `blkdev_roset` of Linux, it needs `CAP_SYS_ADMIN`.
                if !crate::cred::current().capable(crate::cred::cap::SYS_ADMIN) {
                    return Err(Errno::EACCES);
                }
                let mut b = [0u8; 4];
                mem.read(arg, &mut b)?;
                self.queue.set_read_only(i32::from_ne_bytes(b) != 0);
                Ok(0)
            }
            ioctl::BLKROGET => {
                Self::put(mem, arg, &i32::from(self.queue.read_only()).to_ne_bytes())
            }
            ioctl::BLKFLSBUF => {
                self.cache.sync()?;
                self.cache.drop_clean();
                Ok(0)
            }
            _ => self.ops.as_ref().map_or(Err(Errno::ENOTTY), |ops| ops.ioctl(file, cmd, arg, mem)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A device in memory.
    struct Ram(SpinLock<Vec<u8>>);

    impl BlockDevice for Ram {
        fn sectors(&self) -> u64 {
            (self.0.lock().len() / SECTOR_SIZE) as u64
        }

        fn read(&self, sector: u64, buf: &mut [u8]) -> Result<()> {
            let at = sector as usize * SECTOR_SIZE;
            buf.copy_from_slice(&self.0.lock()[at..at + buf.len()]);
            Ok(())
        }

        fn write(&self, sector: u64, buf: &[u8]) -> Result<()> {
            let at = sector as usize * SECTOR_SIZE;
            self.0.lock()[at..at + buf.len()].copy_from_slice(buf);
            Ok(())
        }
    }

    fn file() -> (Arc<Ram>, BlockFile) {
        let ram = Arc::new(Ram(SpinLock::new(vec![7u8; 4 * SECTOR_SIZE])));
        let queue = Arc::new(Queue::new(ram.clone()));
        (
            ram,
            BlockFile {
                queue: queue.clone(),
                cache: Arc::new(PageCache::new(queue)),
                ops: None,
                _claim: None,
                _opener: None,
            },
        )
    }

    #[test]
    fn a_mount_and_an_exclusive_open_exclude_each_other() {
        let rdev = 0xfe_0f00;
        register_block(rdev, "claimtest", Arc::new(Ram(SpinLock::new(vec![0u8; SECTOR_SIZE]))));
        let mount = claim_block(rdev, Holder::Mount).unwrap();
        let again = claim_block(rdev, Holder::Mount).unwrap();
        assert_eq!(open_block(rdev, O_EXCL).err(), Some(Errno::EBUSY));
        assert!(open_block(rdev, 0).is_ok());
        drop((mount, again));
        let file = open_block(rdev, O_EXCL).unwrap();
        assert_eq!(claim_block(rdev, Holder::Mount).err(), Some(Errno::EBUSY));
        assert_eq!(open_block(rdev, O_EXCL).err(), Some(Errno::EBUSY));
        drop(file);
        assert!(claim_block(rdev, Holder::Mount).is_ok());
        assert!(!block_read_only(rdev));
        block_queue(rdev).unwrap().set_read_only(true);
        assert!(block_read_only(rdev));
        assert!(!block_read_only(1));
        assert_eq!(claim_block(1, Holder::Mount).err(), Some(Errno::ENXIO));
    }

    /// Counts the calls of the driver.
    struct Counter(SpinLock<(u32, u32)>);

    impl BlockOps for Counter {
        fn open(&self) -> Result<()> {
            self.0.lock().0 += 1;
            Ok(())
        }

        fn release(&self) {
            self.0.lock().1 += 1;
        }
    }

    #[test]
    fn the_driver_gets_release_at_the_last_close_only() {
        let rdev = 0xfe_0f01;
        let ops = Arc::new(Counter(SpinLock::new((0, 0))));
        let ram = Arc::new(Ram(SpinLock::new(vec![0u8; SECTOR_SIZE])));
        register_block_ops(rdev, "opstest", ram, ops.clone());
        let one = open_block(rdev, 0).unwrap();
        let mount = mount_block(rdev).unwrap();
        assert_eq!(block_openers(rdev), 2);
        assert_eq!(unregister_block(rdev), Err(Errno::EBUSY));
        drop(one);
        assert_eq!(*ops.0.lock(), (2, 0));
        drop(mount);
        assert_eq!(*ops.0.lock(), (2, 1));
        assert_eq!(block_openers(rdev), 0);
        assert_eq!(unregister_block(rdev), Ok(()));
        assert!(block_cache(rdev).is_none());
        assert_eq!(unregister_block(rdev), Err(Errno::ENXIO));
    }

    #[test]
    fn a_write_of_part_of_a_sector_keeps_the_other_bytes() {
        let (ram, f) = file();
        assert_eq!(f.write_bytes(510, &[1, 2, 3, 4]).unwrap(), 4);
        let disk = ram.0.lock();
        assert_eq!(&disk[508..516], &[7, 7, 1, 2, 3, 4, 7, 7]);
    }

    #[test]
    fn a_read_stops_at_the_end_of_the_device() {
        let (_, f) = file();
        let mut buf = [0u8; 100];
        assert_eq!(f.read_bytes(4 * 512 - 10, &mut buf).unwrap(), 10);
        assert_eq!(f.read_bytes(4 * 512, &mut buf).unwrap(), 0);
        assert_eq!(f.write_bytes(4 * 512, &buf), Err(Errno::ENOSPC));
    }
}

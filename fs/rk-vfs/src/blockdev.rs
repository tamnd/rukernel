//! Block devices and their device files.
//!
//! A driver gives a `BlockDevice`, which reads and writes whole sectors of 512 bytes, and the
//! block layer puts a queue in front of it. An open file of the device reads and writes at each
//! byte offset. A part of a sector is read, changed and written again. There is no page cache
//! yet, so each call goes to the queue.

use crate::file::{BatchIo, File, FileOps, UserMemory};
use crate::inode::Result;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_block::{Bio, Op, Queue};
use rk_frame::sync::SpinLock;

pub use rk_block::{BlockDevice, SECTOR_SIZE};

/// The `ioctl` commands of block devices, from `<linux/fs.h>`.
pub mod ioctl {
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
    /// Gives the physical sector size, as an `unsigned int`.
    pub const BLKPBSZGET: u32 = 0x127b;
    /// Gives the size in bytes, as a `u64`.
    pub const BLKGETSIZE64: u32 = 0x8008_1272;
}

/// A block device with its name in /dev.
struct Entry {
    name: String,
    queue: Arc<Queue>,
}

static BLOCK_DEVICES: SpinLock<BTreeMap<u64, Entry>> = SpinLock::new(BTreeMap::new());

/// Adds the block device `rdev` with the name `name`, for example `vda`.
pub fn register_block(rdev: u64, name: &str, device: Arc<dyn BlockDevice>) {
    let queue = Arc::new(Queue::new(device));
    BLOCK_DEVICES.lock().insert(rdev, Entry { name: String::from(name), queue });
}

/// Gives the queue of the block device `rdev`.
pub fn block_queue(rdev: u64) -> Option<Arc<Queue>> {
    BLOCK_DEVICES.lock().get(&rdev).map(|e| e.queue.clone())
}

/// Gives the name and the device number of each block device.
pub fn block_devices() -> Vec<(String, u64)> {
    BLOCK_DEVICES.lock().iter().map(|(rdev, e)| (e.name.clone(), *rdev)).collect()
}

/// Opens the block device `rdev`. Gives `ENXIO` if no driver has the number, as Linux.
pub fn open_block(rdev: u64, _flags: u32) -> Result<Arc<dyn FileOps>> {
    let queue = block_queue(rdev).ok_or(Errno::ENXIO)?;
    Ok(Arc::new(BlockFile { queue }))
}

/// The operations of an open block device.
struct BlockFile {
    queue: Arc<Queue>,
}

impl BlockFile {
    fn size(&self) -> u64 {
        self.queue.sectors() * SECTOR_SIZE as u64
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
        let n = self.read_bytes(file.pos(), buf)?;
        file.set_pos(file.pos() + n as u64);
        Ok(n)
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize> {
        let n = self.write_bytes(file.pos(), buf)?;
        file.set_pos(file.pos() + n as u64);
        Ok(n)
    }

    fn read_at(&self, _file: &File, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.read_bytes(offset, buf)
    }

    fn write_at(&self, _file: &File, offset: u64, buf: &[u8]) -> Result<usize> {
        self.write_bytes(offset, buf)
    }

    fn seekable(&self) -> bool {
        true
    }

    /// The entries for whole sectors go to the queue as one batch, so that near entries merge.
    /// The other entries go one at a time.
    fn rw_batch(&self, _file: &File, ios: &mut [BatchIo]) {
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
    }

    fn end(&self) -> Option<u64> {
        Some(self.size())
    }

    fn sync(&self) -> Result<()> {
        self.queue.flush()
    }

    fn ioctl(&self, _file: &File, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        match cmd {
            ioctl::BLKGETSIZE64 => Self::put(mem, arg, &self.size().to_ne_bytes()),
            ioctl::BLKGETSIZE => Self::put(mem, arg, &self.queue.sectors().to_ne_bytes()),
            ioctl::BLKSSZGET | ioctl::BLKPBSZGET | ioctl::BLKIOMIN => {
                Self::put(mem, arg, &(SECTOR_SIZE as u32).to_ne_bytes())
            }
            ioctl::BLKIOOPT => Self::put(mem, arg, &0u32.to_ne_bytes()),
            ioctl::BLKROGET => {
                Self::put(mem, arg, &i32::from(self.queue.read_only()).to_ne_bytes())
            }
            ioctl::BLKFLSBUF => self.queue.flush().map(|()| 0),
            _ => Err(Errno::ENOTTY),
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
        (ram.clone(), BlockFile { queue: Arc::new(Queue::new(ram)) })
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

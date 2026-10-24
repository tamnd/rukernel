//! Block devices and their device files.
//!
//! A driver gives a `BlockDevice`, which reads and writes whole sectors of 512 bytes. An open
//! file of the device reads and writes at each byte offset. A part of a sector is read, changed
//! and written again. There is no page cache yet, so each call goes to the driver.

use crate::file::{File, FileOps, UserMemory};
use crate::inode::Result;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

/// The size of a sector, the unit of the block layer.
pub const SECTOR_SIZE: usize = 512;

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

/// The driver of a block device.
pub trait BlockDevice: Send + Sync {
    /// The number of sectors.
    fn sectors(&self) -> u64;

    /// Tells if the device does not accept writes.
    fn read_only(&self) -> bool {
        false
    }

    /// Reads the sectors from `sector` to `buf`. The length of `buf` is a multiple of
    /// `SECTOR_SIZE`, and the sectors are on the device.
    fn read(&self, sector: u64, buf: &mut [u8]) -> Result<()>;

    /// Writes `buf` to the sectors from `sector`, with the same rules as `read`.
    fn write(&self, sector: u64, buf: &[u8]) -> Result<()>;

    /// Makes the data of the completed writes durable.
    fn flush(&self) -> Result<()> {
        Ok(())
    }
}

/// A block device with its name in /dev.
struct Entry {
    name: String,
    device: Arc<dyn BlockDevice>,
}

static BLOCK_DEVICES: SpinLock<BTreeMap<u64, Entry>> = SpinLock::new(BTreeMap::new());

/// Adds the block device `rdev` with the name `name`, for example `vda`.
pub fn register_block(rdev: u64, name: &str, device: Arc<dyn BlockDevice>) {
    BLOCK_DEVICES.lock().insert(rdev, Entry { name: String::from(name), device });
}

/// Gives the name and the device number of each block device.
pub fn block_devices() -> Vec<(String, u64)> {
    BLOCK_DEVICES.lock().iter().map(|(rdev, e)| (e.name.clone(), *rdev)).collect()
}

/// Opens the block device `rdev`. Gives `ENXIO` if no driver has the number, as Linux.
pub fn open_block(rdev: u64, _flags: u32) -> Result<Arc<dyn FileOps>> {
    let device = BLOCK_DEVICES.lock().get(&rdev).map(|e| e.device.clone()).ok_or(Errno::ENXIO)?;
    Ok(Arc::new(BlockFile { device }))
}

/// The operations of an open block device.
struct BlockFile {
    device: Arc<dyn BlockDevice>,
}

impl BlockFile {
    fn size(&self) -> u64 {
        self.device.sectors() * SECTOR_SIZE as u64
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
        self.device.read(first, &mut sectors)?;
        let start = (offset - first * SECTOR_SIZE as u64) as usize;
        buf[..len].copy_from_slice(&sectors[start..start + len]);
        Ok(len)
    }

    fn write_bytes(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        if self.device.read_only() {
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
            self.device.read(first, &mut sectors)?;
        }
        sectors[start..start + len].copy_from_slice(&buf[..len]);
        self.device.write(first, &sectors)?;
        Ok(len)
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

    fn end(&self) -> Option<u64> {
        Some(self.size())
    }

    fn sync(&self) -> Result<()> {
        self.device.flush()
    }

    fn ioctl(&self, _file: &File, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        match cmd {
            ioctl::BLKGETSIZE64 => Self::put(mem, arg, &self.size().to_ne_bytes()),
            ioctl::BLKGETSIZE => Self::put(mem, arg, &self.device.sectors().to_ne_bytes()),
            ioctl::BLKSSZGET | ioctl::BLKPBSZGET | ioctl::BLKIOMIN => {
                Self::put(mem, arg, &(SECTOR_SIZE as u32).to_ne_bytes())
            }
            ioctl::BLKIOOPT => Self::put(mem, arg, &0u32.to_ne_bytes()),
            ioctl::BLKROGET => {
                Self::put(mem, arg, &i32::from(self.device.read_only()).to_ne_bytes())
            }
            ioctl::BLKFLSBUF => self.device.flush().map(|()| 0),
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
        (ram.clone(), BlockFile { device: ram })
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

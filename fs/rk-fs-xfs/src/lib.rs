//! XFS, a file system for large disks that Linux has.
//!
//! The driver can only read. It reads the superblock, the inodes, the extent lists and the extent
//! trees of the files, the short form directories in the inodes, and the data blocks of the
//! directories in the block, leaf and node formats. A lookup reads the entries one by one, and it
//! does not use the hash index of the directory. It reads version 4 and version 5 file systems.
//! The checksums are not checked, and the log is not replayed, so a disk that Linux did not
//! unmount can show old data. The extended attributes and the files on a realtime device are not
//! read.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod dir;
mod node;
#[cfg(test)]
mod tests;

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::fstype::{FsType, MountArgs};
use rk_vfs::inode::FsStat;
use rk_vfs::{InodeRef, Result};

pub use node::Node;

/// The magic number of XFS, `XFS_SUPER_MAGIC`. The superblock starts with it, and `statfs` gives
/// it.
pub const XFS_MAGIC: u64 = 0x5846_5342;

/// The file system type for `mount -t xfs`.
pub const FS_TYPES: [FsType; 1] = [FsType { name: "xfs", nodev: false, make: mount }];

/// The features of a version 5 file system that the driver can read, `XFS_SB_FEAT_INCOMPAT_*`:
/// the file types in the directories, the sparse inode chunks, the metadata UUID, the large time
/// stamps, the large extent counters, the exchange of ranges, and the parent pointers.
const INCOMPAT_KNOWN: u32 = 0x1 | 0x2 | 0x4 | 0x8 | 0x20 | 0x40 | 0x80;
/// The feature of a version 5 file system that tells that the file system needs `xfs_repair`.
const INCOMPAT_NEEDSREPAIR: u32 = 0x10;
/// The feature of a version 5 file system for the file types in the directories.
const INCOMPAT_FTYPE: u32 = 0x1;
/// The bit of `sb_features2` of a version 4 file system for the file types in the directories.
const FEATURES2_FTYPE: u32 = 0x200;
/// The bit of `sb_versionnum` for the directories of version 2. The driver reads only these.
const VERSION_DIRV2: u16 = 0x2000;

/// Gives the big endian number of 2 bytes at `at`, or 0 past the end of `b`.
pub(crate) fn be16(b: &[u8], at: usize) -> u16 {
    b.get(at..at + 2).and_then(|s| s.try_into().ok()).map_or(0, u16::from_be_bytes)
}

/// Gives the big endian number of 4 bytes at `at`, or 0 past the end of `b`.
pub(crate) fn be32(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).and_then(|s| s.try_into().ok()).map_or(0, u32::from_be_bytes)
}

/// Gives the big endian number of 8 bytes at `at`, or 0 past the end of `b`.
pub(crate) fn be64(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8).and_then(|s| s.try_into().ok()).map_or(0, u64::from_be_bytes)
}

/// The disk under a file system.
pub trait Disk: Send + Sync {
    /// Reads `buf.len()` bytes at `offset`.
    ///
    /// # Errors
    ///
    /// Gives the error of the disk, or `EIO` past the end.
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<()>;
}

impl Disk for Arc<rk_vfs::blockdev::DiskCache> {
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        match rk_vfs::blockdev::DiskCache::read(self, offset, buf)? {
            n if n == buf.len() => Ok(()),
            _ => Err(Errno::EIO),
        }
    }
}

/// Mounts the XFS file system on the block device of `args`.
///
/// # Errors
///
/// Gives `ENOTBLK` without a device, `ENXIO` if the device has no driver, `EROFS` for a read and
/// write mount, `EINVAL` if the device does not have XFS, and `EOPNOTSUPP` for a feature that
/// the driver does not support.
pub fn mount(args: &MountArgs<'_>) -> Result<InodeRef> {
    let dev = args.dev.ok_or(Errno::ENOTBLK)?;
    if !args.read_only {
        return Err(Errno::EROFS);
    }
    let cache = rk_vfs::blockdev::block_cache(dev).ok_or(Errno::ENXIO)?;
    let fs = Fs::open(dev, alloc::boxed::Box::new(cache))?;
    Ok(fs.root()?)
}

/// The fields of the superblock that the driver uses.
pub(crate) struct Superblock {
    /// The size of a block in bytes.
    pub(crate) block_size: u64,
    /// The number of blocks of the data device.
    dblocks: u64,
    /// The first block of the log, or 0 for a log on another device.
    logstart: u64,
    /// The number of blocks of the log.
    logblocks: u64,
    /// The inode number of the root directory.
    rootino: u64,
    /// The number of blocks in an allocation group.
    agblocks: u64,
    /// The number of allocation groups.
    agcount: u64,
    /// The size of an inode in bytes.
    pub(crate) inode_size: usize,
    /// The base 2 log of the number of inodes in a block.
    inopblog: u32,
    /// The base 2 log of `agblocks`, rounded up.
    agblklog: u32,
    /// The base 2 log of the number of blocks in a directory block.
    pub(crate) dirblklog: u32,
    /// The number of inodes, and of free inodes.
    icount: u64,
    ifree: u64,
    /// The number of free blocks.
    fdblocks: u64,
    /// The file system is version 5, with the checksums and the headers of version 5.
    pub(crate) v5: bool,
    /// The directory entries have the type of the file.
    pub(crate) ftype: bool,
}

impl Superblock {
    /// Reads the superblock in the first sector `b`.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` for a disk without XFS, `EOPNOTSUPP` for a feature that the driver does not
    /// support, and `EUCLEAN` for values that are not possible, or for a file system that needs
    /// `xfs_repair`.
    fn parse(b: &[u8]) -> Result<Self> {
        if u64::from(be32(b, 0)) != XFS_MAGIC {
            return Err(Errno::EINVAL);
        }
        let versionnum = be16(b, 100);
        let v5 = match versionnum & 0xf {
            4 => false,
            5 => true,
            _ => return Err(Errno::EOPNOTSUPP),
        };
        if versionnum & VERSION_DIRV2 == 0 && !v5 {
            return Err(Errno::EOPNOTSUPP);
        }
        let incompat = be32(b, 216);
        if v5 && incompat & INCOMPAT_NEEDSREPAIR != 0 {
            return Err(Errno::EUCLEAN);
        }
        if v5 && incompat & !INCOMPAT_KNOWN != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let ftype =
            if v5 { incompat & INCOMPAT_FTYPE != 0 } else { be32(b, 200) & FEATURES2_FTYPE != 0 };
        let block_size = be32(b, 4);
        let blocklog = u32::from(b[120]);
        let inode_size = be16(b, 104);
        let inodelog = u32::from(b[122]);
        let inopblog = u32::from(b[123]);
        let agblklog = u32::from(b[124]);
        let dirblklog = u32::from(b[192]);
        let agblocks = be32(b, 84);
        let sb = Self {
            block_size: u64::from(block_size),
            dblocks: be64(b, 8),
            logstart: be64(b, 48),
            logblocks: u64::from(be32(b, 96)),
            rootino: be64(b, 56),
            agblocks: u64::from(agblocks),
            agcount: u64::from(be32(b, 88)),
            inode_size: usize::from(inode_size),
            inopblog,
            agblklog,
            dirblklog,
            icount: be64(b, 128),
            ifree: be64(b, 136),
            fdblocks: be64(b, 144),
            v5,
            ftype,
        };
        let sane = (9..=16).contains(&blocklog)
            && block_size == 1 << blocklog
            && (8..=11).contains(&inodelog)
            && u32::from(inode_size) == 1 << inodelog
            && inopblog + inodelog == blocklog
            && agblocks > 0
            && agblklog < 32
            && u64::from(agblocks) <= 1 << agblklog
            && sb.agcount > 0
            && blocklog + dirblklog <= 16;
        if !sane {
            return Err(Errno::EUCLEAN);
        }
        Ok(sb)
    }
}

/// One mounted XFS file system.
pub struct Fs {
    disk: alloc::boxed::Box<dyn Disk>,
    dev: u64,
    pub(crate) sb: Superblock,
    /// The inodes in memory, so that two lookups of one file give one inode.
    inodes: SpinLock<BTreeMap<u64, Weak<Node>>>,
    this: Weak<Fs>,
}

impl Fs {
    /// Reads the superblock of `disk`, which has the device number `dev`.
    ///
    /// # Errors
    ///
    /// Gives the error of the disk, `EINVAL` for a disk without XFS, `EOPNOTSUPP` for a feature
    /// that the driver does not support, and `EUCLEAN` for a bad superblock.
    pub fn open(dev: u64, disk: alloc::boxed::Box<dyn Disk>) -> Result<Arc<Self>> {
        let mut b = vec![0u8; 512];
        disk.read(0, &mut b)?;
        let sb = Superblock::parse(&b)?;
        Ok(Arc::new_cyclic(|this| Self {
            disk,
            dev,
            sb,
            inodes: SpinLock::new(BTreeMap::new()),
            this: this.clone(),
        }))
    }

    /// Gives the root directory.
    ///
    /// # Errors
    ///
    /// Gives the error of the disk, or `EUCLEAN` for a bad inode.
    pub fn root(&self) -> Result<Arc<Node>> {
        self.inode(self.sb.rootino)
    }

    /// Gives the inode `ino`.
    ///
    /// # Errors
    ///
    /// Gives the error of the disk, or `EUCLEAN` for a bad inode number or a bad inode.
    pub fn inode(&self, ino: u64) -> Result<Arc<Node>> {
        if let Some(node) = self.inodes.lock().get(&ino).and_then(Weak::upgrade) {
            return Ok(node);
        }
        let fs = self.this.upgrade().ok_or(Errno::EIO)?;
        let mut raw = vec![0u8; self.sb.inode_size];
        self.disk.read(self.inode_at(ino)?, &mut raw)?;
        let node = Node::new(fs, ino, raw)?;
        let mut inodes = self.inodes.lock();
        if let Some(old) = inodes.get(&ino).and_then(Weak::upgrade) {
            return Ok(old);
        }
        inodes.retain(|_, n| n.strong_count() > 0);
        inodes.insert(ino, Arc::downgrade(&node));
        Ok(node)
    }

    /// Gives the offset on the disk of the inode `ino`. The inode number has the allocation
    /// group, the block in the group, and the inode in the block.
    fn inode_at(&self, ino: u64) -> Result<u64> {
        let sb = &self.sb;
        let agino_bits = sb.agblklog + sb.inopblog;
        let agno = ino >> agino_bits;
        let agbno = (ino & ((1 << agino_bits) - 1)) >> sb.inopblog;
        let index = ino & ((1 << sb.inopblog) - 1);
        if ino == 0 || agno >= sb.agcount || agbno >= sb.agblocks {
            return Err(Errno::EUCLEAN);
        }
        Ok((agno * sb.agblocks + agbno) * sb.block_size + index * sb.inode_size as u64)
    }

    /// Gives the offset on the disk of the block `fsb`, a block number that has the allocation
    /// group in its high bits.
    pub(crate) fn block_at(&self, fsb: u64) -> Result<u64> {
        let sb = &self.sb;
        let agno = fsb >> sb.agblklog;
        let agbno = fsb & ((1 << sb.agblklog) - 1);
        if agno >= sb.agcount || agbno >= sb.agblocks {
            return Err(Errno::EUCLEAN);
        }
        Ok((agno * sb.agblocks + agbno) * sb.block_size)
    }

    /// Reads `buf.len()` bytes at `offset` of the disk.
    pub(crate) fn read(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.disk.read(offset, buf)
    }

    /// The counts for `statfs`. An internal log is not in the blocks for data.
    fn stat(&self) -> FsStat {
        let sb = &self.sb;
        let log = if sb.logstart != 0 { sb.logblocks } else { 0 };
        FsStat {
            bsize: sb.block_size,
            blocks: sb.dblocks.saturating_sub(log),
            bfree: sb.fdblocks,
            bavail: sb.fdblocks,
            files: sb.icount,
            ffree: sb.ifree,
        }
    }
}

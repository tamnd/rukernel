//! ext4, the file system of Linux on disks.
//!
//! The driver reads the disk through the page cache of the block device. It reads the
//! superblock, the group descriptors, the inode tables, the extent trees and the block maps of
//! the files, and the directories. A directory with an htree index is read as a list, because
//! the index blocks look like empty entries. The checksums are not checked.
//!
//! This version mounts the disk read only. A change gives `EROFS`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod layout;
mod node;
#[cfg(test)]
mod tests;

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use layout::{GroupDesc, RawInode, Superblock};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::fstype::{FsType, MountArgs};
use rk_vfs::{InodeRef, Result};

pub use node::Node;

/// The magic number of ext4 for `statfs`, `EXT4_SUPER_MAGIC`.
pub const EXT4_MAGIC: u64 = 0xef53;

/// The file system types for `mount -t ext4`, `ext3` and `ext2`. One driver reads all three.
pub const FS_TYPES: [FsType; 3] = [
    FsType { name: "ext4", nodev: false, make: mount },
    FsType { name: "ext3", nodev: false, make: mount },
    FsType { name: "ext2", nodev: false, make: mount },
];

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

/// Mounts the ext4 file system on the block device of `args`.
///
/// # Errors
///
/// Gives `ENXIO` if the device has no driver, `EINVAL` if the device does not have ext4, and
/// `EOPNOTSUPP` for a feature that the driver does not support.
pub fn mount(args: &MountArgs<'_>) -> Result<InodeRef> {
    let dev = args.dev.ok_or(Errno::ENOTBLK)?;
    let cache = rk_vfs::blockdev::block_cache(dev).ok_or(Errno::ENXIO)?;
    let fs = Fs::open(dev, alloc::boxed::Box::new(cache))?;
    Ok(fs.root()?)
}

/// One mounted ext4 file system.
pub struct Fs {
    disk: alloc::boxed::Box<dyn Disk>,
    dev: u64,
    sb: Superblock,
    groups: Vec<GroupDesc>,
    /// The inodes in memory, so that two lookups of one file give one inode.
    inodes: SpinLock<BTreeMap<u32, Weak<Node>>>,
    this: Weak<Fs>,
}

impl Fs {
    /// Reads the superblock and the group descriptors of `disk`, which has the device number
    /// `dev`.
    ///
    /// # Errors
    ///
    /// Gives the error of the disk, `EINVAL` for a disk without ext4, and `EOPNOTSUPP` for a
    /// feature that the driver does not support.
    pub fn open(dev: u64, disk: alloc::boxed::Box<dyn Disk>) -> Result<Arc<Self>> {
        let mut b = vec![0u8; layout::SUPERBLOCK_SIZE];
        disk.read(layout::SUPERBLOCK_AT, &mut b)?;
        let sb = Superblock::parse(&b)?;
        if sb.incompat & layout::incompat::META_BG != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let count = sb.groups() as usize;
        let size = usize::from(sb.desc_size);
        let mut table = vec![0u8; count * size];
        let at = (u64::from(sb.first_data_block) + 1) * sb.block_size;
        disk.read(at, &mut table)?;
        let groups = table.chunks(size).map(|d| GroupDesc::parse(d, sb.desc_size)).collect();
        Ok(Arc::new_cyclic(|this| Self {
            disk,
            dev,
            sb,
            groups,
            inodes: SpinLock::new(BTreeMap::new()),
            this: this.clone(),
        }))
    }

    /// The superblock.
    pub fn superblock(&self) -> &Superblock {
        &self.sb
    }

    /// The root directory.
    ///
    /// # Errors
    ///
    /// Gives the error of the disk.
    pub fn root(&self) -> Result<Arc<Node>> {
        self.inode(layout::ROOT_INO)
    }

    /// Reads `buf.len()` bytes at `offset` of the disk.
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.disk.read(offset, buf)
    }

    /// Reads the block `block`.
    fn read_block(&self, block: u64) -> Result<Vec<u8>> {
        if block >= self.sb.blocks_count {
            return Err(Errno::EIO);
        }
        let mut buf = vec![0u8; self.sb.block_size as usize];
        self.read(block * self.sb.block_size, &mut buf)?;
        Ok(buf)
    }

    /// Reads the inode `ino` from the inode table.
    fn read_inode(&self, ino: u32) -> Result<RawInode> {
        if ino == 0 || ino > self.sb.inodes_count {
            return Err(Errno::EIO);
        }
        let index = ino - 1;
        let group =
            self.groups.get((index / self.sb.inodes_per_group) as usize).ok_or(Errno::EIO)?;
        let size = u64::from(self.sb.inode_size);
        let at = group.inode_table * self.sb.block_size
            + u64::from(index % self.sb.inodes_per_group) * size;
        let mut buf = vec![0u8; size as usize];
        self.read(at, &mut buf)?;
        Ok(RawInode(buf))
    }

    /// Gives the inode `ino`, from memory if it is there.
    ///
    /// # Errors
    ///
    /// Gives the error of the disk.
    pub fn inode(&self, ino: u32) -> Result<Arc<Node>> {
        let mut inodes = self.inodes.lock();
        if let Some(node) = inodes.get(&ino).and_then(Weak::upgrade) {
            return Ok(node);
        }
        let fs = self.this.upgrade().ok_or(Errno::EIO)?;
        let node = Node::new(fs, ino, self.read_inode(ino)?);
        inodes.retain(|_, n| n.strong_count() > 0);
        inodes.insert(ino, Arc::downgrade(&node));
        Ok(node)
    }
}

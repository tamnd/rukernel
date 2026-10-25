//! ext4, the file system of Linux on disks.
//!
//! The driver reads and writes the disk through the page cache of the block device. It reads the
//! superblock, the group descriptors, the inode tables, the extent trees and the block maps of
//! the files, and the directories. A directory with an htree index is read as a list, because
//! the index blocks look like empty entries. The checksums are not checked on a read.
//!
//! A read and write mount changes the bitmaps, the group descriptors, the inodes, the extent trees
//! and the directories, and it writes the checksums of `metadata_csum` or `uninit_bg`. Each change
//! goes to the page cache at once, under one lock for the file system, so `sync` makes the disk
//! consistent. The driver does not write the journal yet, but at mount it replays a journal that
//! Linux or e2fsprogs left with transactions. A new entry in a directory with an htree
//! index first changes the directory into a list. A file with a block map can change in its
//! blocks, but it cannot get new blocks.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod alloc_blocks;
pub mod crc;
mod dir;
mod extent;
mod journal;
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
use rk_frame::sync::{SpinLock, SpinLockGuard};
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

    /// Writes `buf` at `offset`.
    ///
    /// # Errors
    ///
    /// Gives the error of the disk, or `EIO` past the end.
    fn write(&self, offset: u64, buf: &[u8]) -> Result<()>;
}

impl Disk for Arc<rk_vfs::blockdev::DiskCache> {
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        match rk_vfs::blockdev::DiskCache::read(self, offset, buf)? {
            n if n == buf.len() => Ok(()),
            _ => Err(Errno::EIO),
        }
    }

    fn write(&self, offset: u64, buf: &[u8]) -> Result<()> {
        match rk_vfs::blockdev::DiskCache::write(self, offset, buf)? {
            n if n == buf.len() => Ok(()),
            _ => Err(Errno::EIO),
        }
    }
}

/// Mounts the ext4 file system on the block device of `args`.
///
/// # Errors
///
/// Gives `ENXIO` if the device has no driver, `EINVAL` if the device does not have ext4,
/// `EOPNOTSUPP` for a feature that the driver does not support, and `EROFS` for a read and write
/// mount of a disk that the driver can only read.
pub fn mount(args: &MountArgs<'_>) -> Result<InodeRef> {
    let dev = args.dev.ok_or(Errno::ENOTBLK)?;
    let cache = rk_vfs::blockdev::block_cache(dev).ok_or(Errno::ENXIO)?;
    let fs = Fs::open(dev, alloc::boxed::Box::new(cache), args.read_only)?;
    Ok(fs.root()?)
}

/// The metadata that a change of the file system changes, under the lock of the file system.
pub(crate) struct Meta {
    /// The 1024 bytes of the superblock.
    sb: Vec<u8>,
    /// The group descriptors as the disk has them.
    descs: Vec<Vec<u8>>,
    /// The generation of the next new inode.
    generation: u32,
}

/// A change of the file system. It holds the lock of the file system. When it ends, it frees the
/// inodes that have no link and that no one uses.
pub(crate) struct Tx<'a> {
    fs: &'a Fs,
    meta: SpinLockGuard<'a, Meta>,
}

impl Drop for Tx<'_> {
    fn drop(&mut self) {
        loop {
            let Some(ino) = self.fs.orphans.lock().pop() else { break };
            // The inode stays in use on an error, and fsck finds it.
            let _ = self.release(ino);
        }
    }
}

/// One mounted ext4 file system.
pub struct Fs {
    disk: alloc::boxed::Box<dyn Disk>,
    dev: u64,
    sb: Superblock,
    groups: Vec<GroupDesc>,
    /// The file system can change.
    writable: bool,
    /// The seed of the crc32c checksums, for `metadata_csum`.
    csum_seed: u32,
    meta: SpinLock<Meta>,
    /// The inodes without a link that no one uses, to free.
    orphans: SpinLock<Vec<u32>>,
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
    /// Gives the error of the disk, `EINVAL` for a disk without ext4, `EOPNOTSUPP` for a feature
    /// that the driver does not support, `EUCLEAN` for a bad journal, and `EROFS` if `read_only`
    /// is false and the driver can only read the disk. A journal with transactions is replayed
    /// first.
    pub fn open(dev: u64, disk: alloc::boxed::Box<dyn Disk>, read_only: bool) -> Result<Arc<Self>> {
        let fs = Self::load(dev, disk, read_only)?;
        if fs.sb.incompat & layout::incompat::RECOVER == 0 {
            return Ok(fs);
        }
        // As Linux, a read only mount also replays the journal.
        fs.recover()?;
        let fs = Arc::try_unwrap(fs).map_err(|_| Errno::EIO)?;
        Self::load(dev, fs.disk, read_only)
    }

    fn load(dev: u64, disk: alloc::boxed::Box<dyn Disk>, read_only: bool) -> Result<Arc<Self>> {
        let mut b = vec![0u8; layout::SUPERBLOCK_SIZE];
        disk.read(layout::SUPERBLOCK_AT, &mut b)?;
        let sb = Superblock::parse(&b)?;
        if sb.incompat & layout::incompat::META_BG != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let can_write = sb.ro_compat & !layout::ro_compat::WRITABLE == 0
            && sb.incompat & layout::incompat::MMP == 0
            && sb.incompat & layout::incompat::EXTENTS != 0
            && sb.block_size <= 4096;
        if !read_only && !can_write {
            return Err(Errno::EROFS);
        }
        let csum_seed = if sb.incompat & layout::incompat::CSUM_SEED != 0 {
            sb.checksum_seed
        } else {
            crc::crc32c(!0, &sb.uuid)
        };
        let count = sb.groups() as usize;
        let size = usize::from(sb.desc_size);
        let mut table = vec![0u8; count * size];
        let at = (u64::from(sb.first_data_block) + 1) * sb.block_size;
        disk.read(at, &mut table)?;
        let groups = table.chunks(size).map(|d| GroupDesc::parse(d, sb.desc_size)).collect();
        let descs = table.chunks(size).map(<[u8]>::to_vec).collect();
        let generation = crc::crc32c(csum_seed, &rk_vfs::now().nsec.to_le_bytes());
        Ok(Arc::new_cyclic(|this| Self {
            disk,
            dev,
            sb,
            groups,
            writable: !read_only,
            csum_seed,
            meta: SpinLock::new(Meta { sb: b, descs, generation }),
            orphans: SpinLock::new(Vec::new()),
            inodes: SpinLock::new(BTreeMap::new()),
            this: this.clone(),
        }))
    }

    /// Starts a change of the file system.
    ///
    /// # Errors
    ///
    /// Gives `EROFS` for a read only mount.
    pub(crate) fn tx(&self) -> Result<Tx<'_>> {
        if !self.writable {
            return Err(Errno::EROFS);
        }
        Ok(Tx { fs: self, meta: self.meta.lock() })
    }

    /// Tells if the metadata has crc32c checksums.
    fn metadata_csum(&self) -> bool {
        self.sb.ro_compat & layout::ro_compat::METADATA_CSUM != 0
    }

    /// The seed of the checksums of the blocks of the inode `ino`.
    fn inode_seed(&self, ino: u32, raw: &RawInode) -> u32 {
        let seed = crc::crc32c(self.csum_seed, &ino.to_le_bytes());
        crc::crc32c(seed, &raw.generation().to_le_bytes())
    }

    /// Writes `buf` at `offset` of the disk.
    fn write(&self, offset: u64, buf: &[u8]) -> Result<()> {
        self.disk.write(offset, buf)
    }

    /// The offset of the inode `ino` on the disk.
    fn inode_at(&self, ino: u32) -> Result<u64> {
        if ino == 0 || ino > self.sb.inodes_count {
            return Err(Errno::EIO);
        }
        let index = ino - 1;
        let group =
            self.groups.get((index / self.sb.inodes_per_group) as usize).ok_or(Errno::EIO)?;
        let size = u64::from(self.sb.inode_size);
        Ok(group.inode_table * self.sb.block_size
            + u64::from(index % self.sb.inodes_per_group) * size)
    }

    /// Writes the inode `ino`, with its checksum.
    fn write_inode(&self, ino: u32, raw: &mut RawInode) -> Result<()> {
        if self.metadata_csum() {
            let has_hi = raw.0.len() > 128 && raw.extra_size() >= 4;
            layout::put16(&mut raw.0, 0x7c, 0);
            if has_hi {
                layout::put16(&mut raw.0, 0x82, 0);
            }
            let seed = self.inode_seed(ino, raw);
            let csum = crc::crc32c(seed, &raw.0);
            layout::put16(&mut raw.0, 0x7c, csum as u16);
            if has_hi {
                layout::put16(&mut raw.0, 0x82, (csum >> 16) as u16);
            }
        }
        self.write(self.inode_at(ino)?, &raw.0)
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

    /// Adds the new inode `ino` to the inodes in memory.
    fn new_node(&self, ino: u32, raw: RawInode) -> Result<Arc<Node>> {
        let fs = self.this.upgrade().ok_or(Errno::EIO)?;
        let node = Node::new(fs, ino, raw);
        let mut inodes = self.inodes.lock();
        inodes.retain(|_, n| n.strong_count() > 0);
        inodes.insert(ino, Arc::downgrade(&node));
        Ok(node)
    }

    /// Adds the inode `ino` without links to the inodes to free, and frees them if no change
    /// runs. Else the change frees them when it ends.
    fn orphan(&self, ino: u32) {
        self.orphans.lock().push(ino);
        if let Some(meta) = self.meta.try_lock() {
            drop(Tx { fs: self, meta });
        }
    }
}

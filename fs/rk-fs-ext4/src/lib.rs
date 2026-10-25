//! ext4, the file system of Linux on disks.
//!
//! The driver reads and writes the disk through the page cache of the block device. It reads the
//! superblock, the group descriptors, the inode tables, the extent trees and the block maps of
//! the files, and the directories. A directory with an htree index is read as a list, because
//! the index blocks look like empty entries. The checksums are not checked on a read.
//!
//! A read and write mount changes the bitmaps, the group descriptors, the inodes, the extent trees
//! and the directories, and it writes the checksums of `metadata_csum` or `uninit_bg`. With a
//! journal, the metadata blocks of each change go to the journal first, and then to their places,
//! as `data=writeback` of Linux. The data of a regular file goes to its blocks at once. At mount
//! the driver replays a journal that Linux, e2fsprogs or a crash left with transactions, and at
//! unmount it leaves the journal empty. A new entry in a directory with an htree index first
//! changes the directory into a list. A file with a block map can change in its blocks, but it
//! cannot get new blocks.

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

    /// Writes the data from `offset` up to `offset + len` that is in a cache to the disk.
    ///
    /// # Errors
    ///
    /// Gives the error of the disk.
    fn write_back(&self, _offset: u64, _len: u64) -> Result<()> {
        Ok(())
    }

    /// Makes the data that the disk has durable. The writes before it reach the disk before the
    /// writes after it.
    ///
    /// # Errors
    ///
    /// Gives the error of the disk.
    fn flush(&self) -> Result<()> {
        Ok(())
    }
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

    fn write_back(&self, offset: u64, len: u64) -> Result<()> {
        rk_vfs::blockdev::DiskCache::write_back(self, offset, len)
    }

    fn flush(&self) -> Result<()> {
        rk_vfs::blockdev::DiskCache::flush(self)
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
        self.fs.commit();
    }
}

impl Drop for Fs {
    fn drop(&mut self) {
        // On an error the journal stays, and the next mount replays it.
        let _ = self.finish();
    }
}

/// One mounted ext4 file system.
pub struct Fs {
    disk: Arc<dyn Disk>,
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
    /// The journal, for a read and write mount of a file system with a journal.
    log: Option<SpinLock<journal::Log>>,
    /// The metadata blocks that the running change wrote, which go to the journal when the
    /// change ends.
    pending: SpinLock<BTreeMap<u64, Vec<u8>>>,
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
        let disk: Arc<dyn Disk> = Arc::from(disk);
        let mut fs = Self::load(dev, disk.clone(), read_only)?;
        if fs.sb.incompat & layout::incompat::RECOVER != 0 {
            // As Linux, a read only mount also replays the journal.
            fs.recover()?;
            drop(fs);
            fs = Self::load(dev, disk, read_only)?;
        }
        if fs.log.is_some() {
            fs.mark_recover(true)?;
        }
        Ok(fs)
    }

    fn load(dev: u64, disk: Arc<dyn Disk>, read_only: bool) -> Result<Arc<Self>> {
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
        // A disk with a journal to replay changes only after the replay.
        let writable = !read_only && sb.incompat & layout::incompat::RECOVER == 0;
        let journal = writable && sb.compat & layout::compat::HAS_JOURNAL != 0;
        if journal && (sb.incompat & layout::incompat::JOURNAL_DEV != 0 || sb.journal_inum == 0) {
            return Err(Errno::EROFS);
        }
        let mut fs = Self {
            disk,
            dev,
            sb,
            groups,
            writable,
            csum_seed,
            meta: SpinLock::new(Meta { sb: b, descs, generation }),
            orphans: SpinLock::new(Vec::new()),
            log: None,
            pending: SpinLock::new(BTreeMap::new()),
            inodes: SpinLock::new(BTreeMap::new()),
            this: Weak::new(),
        };
        if journal {
            fs.log = Some(SpinLock::new(journal::Log::open(&fs, fs.sb.journal_inum)?));
        }
        Ok(Arc::new_cyclic(|this| {
            fs.this = this.clone();
            fs
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

    /// Writes the metadata `buf` at `offset` of the disk. With a journal, the blocks wait in
    /// memory until the change ends.
    fn write(&self, offset: u64, buf: &[u8]) -> Result<()> {
        let Some(log) = &self.log else { return self.disk.write(offset, buf) };
        let bs = self.sb.block_size;
        let mut done = 0;
        while done < buf.len() {
            let at = offset + done as u64;
            let (block, in_block) = (at / bs, (at % bs) as usize);
            let n = (bs as usize - in_block).min(buf.len() - done);
            log.lock().used_again(block);
            let mut data = match self.pending.lock().remove(&block) {
                Some(data) => data,
                None if n == bs as usize => vec![0u8; n],
                None => {
                    let mut data = vec![0u8; bs as usize];
                    self.disk.read(block * bs, &mut data)?;
                    data
                }
            };
            data[in_block..in_block + n].copy_from_slice(&buf[done..done + n]);
            self.pending.lock().insert(block, data);
            done += n;
        }
        Ok(())
    }

    /// Writes `buf` at `offset` of the disk at once, for the data of a file and for the
    /// journal.
    fn write_direct(&self, offset: u64, buf: &[u8]) -> Result<()> {
        self.disk.write(offset, buf)
    }

    /// Writes the data of the file `raw` at `offset`. The data of a regular file does not go to
    /// the journal, as `data=writeback` of Linux.
    fn write_file(&self, raw: &RawInode, offset: u64, buf: &[u8]) -> Result<()> {
        if u32::from(raw.mode()) & 0o170000 == 0o100000 {
            self.write_direct(offset, buf)
        } else {
            self.write(offset, buf)
        }
    }

    /// Ends a change: the blocks that it wrote go to the journal and then to their places. If
    /// the journal cannot take them, they go to their places at once.
    fn commit(&self) {
        let Some(log) = &self.log else { return };
        let blocks = self.pending.lock().clone();
        let mut log = log.lock();
        if log.commit(self, &blocks).is_err() {
            for (&block, data) in &blocks {
                let _ = self.write_direct(block * self.sb.block_size, data);
            }
        }
        drop(log);
        self.pending.lock().clear();
    }

    /// Notes that the blocks from `start` up to `start + count` are free, so their metadata
    /// does not go to the disk, and the journal revokes its copies of them.
    fn freed(&self, start: u64, count: u64) {
        if let Some(log) = &self.log {
            let mut pending = self.pending.lock();
            for block in start..start + count {
                pending.remove(&block);
            }
            drop(pending);
            log.lock().freed(start, count);
        }
    }

    /// Sets or clears `needs_recovery` in the superblock, and makes it durable.
    fn mark_recover(&self, on: bool) -> Result<()> {
        let mut meta = self.meta.lock();
        let b = &mut meta.sb;
        let mut incompat = layout::u32_at(b, 0x60) & !layout::incompat::RECOVER;
        if on {
            incompat |= layout::incompat::RECOVER;
        }
        layout::put32(b, 0x60, incompat);
        if self.metadata_csum() {
            let csum = crc::crc32c(!0, &b[..layout::sb::CHECKSUM]);
            layout::put32(b, layout::sb::CHECKSUM, csum);
        }
        self.disk.write(layout::SUPERBLOCK_AT, b)?;
        self.disk.write_back(layout::SUPERBLOCK_AT, b.len() as u64)?;
        self.disk.flush()
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

    /// Reads `buf.len()` bytes at `offset` of the disk, with the blocks that the running change
    /// wrote.
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.disk.read(offset, buf)?;
        let pending = self.pending.lock();
        if pending.is_empty() || buf.is_empty() {
            return Ok(());
        }
        let bs = self.sb.block_size;
        let end = offset + buf.len() as u64;
        for (&block, data) in pending.range(offset / bs..end.div_ceil(bs)) {
            let from = (block * bs).max(offset);
            let to = ((block + 1) * bs).min(end);
            buf[(from - offset) as usize..(to - offset) as usize]
                .copy_from_slice(&data[(from - block * bs) as usize..(to - block * bs) as usize]);
        }
        Ok(())
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

    /// Ends the use of the journal at unmount: the log becomes empty and `needs_recovery` is
    /// cleared.
    fn finish(&self) -> Result<()> {
        let Some(log) = &self.log else { return Ok(()) };
        log.lock().checkpoint(self)?;
        self.mark_recover(false)
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

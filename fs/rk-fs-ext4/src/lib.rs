//! ext4, the file system of Linux on disks.
//!
//! The driver reads and writes the disk through the page cache of the block device. It reads the
//! superblock, the group descriptors, the inode tables, the extent trees and the block maps of
//! the files, and the directories. A directory with an htree index is read as a list, because
//! the index blocks look like empty entries. The checksums are not checked on a read.
//!
//! A read and write mount changes the bitmaps, the group descriptors, the inodes, the extent trees
//! and the directories, and it writes the checksums of `metadata_csum` or `uninit_bg`. With a
//! journal, the metadata blocks of the changes go to the journal first, and then to their places,
//! as `data=writeback` of Linux. A commit collects the changes of up to 5 seconds, and `fsync`
//! commits at once. An inode without links that a process still uses is on the list of orphans,
//! so a mount after a crash frees it. The data of a regular file goes to its blocks at once. At mount
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
mod indirect;
mod journal;
pub mod layout;
mod node;
#[cfg(test)]
mod tests;
mod xattr;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use layout::{GroupDesc, RawInode, Superblock, gd, u16_at, u32_at};
use rk_abi::Errno;
use rk_frame::sync::{SpinLock, SpinLockGuard};
use rk_vfs::fstype::{FsType, MountArgs};
use rk_vfs::{InodeRef, Result};

/// The longest time that a change waits for its commit, as the `commit=5` default of Linux.
const COMMIT_SECS: i64 = 5;

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
    // The last of `minixdf` and `bsddf` sets how `statfs` counts the blocks.
    for option in args.data.split(|&c| c == b',') {
        match option {
            b"minixdf" => fs.minix_df.store(true, Ordering::Relaxed),
            b"bsddf" => fs.minix_df.store(false, Ordering::Relaxed),
            _ => {}
        }
    }
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
        self.fs.commit(false);
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
    /// The metadata blocks that the changes since the last commit wrote, which go to the
    /// journal in the next commit.
    pending: SpinLock<BTreeMap<u64, Vec<u8>>>,
    /// The blocks that the changes since the last commit freed. They are not used again before
    /// the commit, because after a crash the old metadata still uses them.
    busy: SpinLock<BTreeSet<u64>>,
    /// The time of the last commit, in seconds.
    committed: SpinLock<i64>,
    /// The inodes in memory, so that two lookups of one file give one inode.
    inodes: SpinLock<BTreeMap<u32, Weak<Node>>>,
    /// The mount option `minixdf`: `statfs` counts the blocks of the metadata in the count of
    /// blocks.
    minix_df: AtomicBool,
    /// `FS_IOC_GOINGDOWN` stopped the file system. Nothing goes to the disk again.
    shut: AtomicBool,
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
        if fs.writable && layout::u32_at(&fs.meta.lock().sb, layout::sb::LAST_ORPHAN) != 0 {
            // As Linux, the mount goes on if an orphan cannot be freed.
            let _ = fs.tx()?.clean_orphans();
        }
        Ok(fs)
    }

    fn load(dev: u64, disk: Arc<dyn Disk>, read_only: bool) -> Result<Arc<Self>> {
        let mut b = vec![0u8; layout::SUPERBLOCK_SIZE];
        disk.read(layout::SUPERBLOCK_AT, &mut b)?;
        let sb = Superblock::parse(&b)?;
        // Linux does not mount a block size larger than the page size.
        if sb.block_size > 4096 {
            return Err(Errno::EINVAL);
        }
        let can_write = sb.ro_compat & !layout::ro_compat::WRITABLE == 0
            && sb.incompat & layout::incompat::MMP == 0;
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
        for (nr, block) in table.chunks_mut(sb.block_size as usize).enumerate() {
            disk.read(sb.desc_block(nr as u64) * sb.block_size, block)?;
        }
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
            busy: SpinLock::new(BTreeSet::new()),
            committed: SpinLock::new(rk_vfs::now().sec),
            inodes: SpinLock::new(BTreeMap::new()),
            minix_df: AtomicBool::new(false),
            shut: AtomicBool::new(false),
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
    /// Gives `EROFS` for a read only mount, and `EIO` after a shutdown.
    pub(crate) fn tx(&self) -> Result<Tx<'_>> {
        if !self.writable {
            return Err(Errno::EROFS);
        }
        let meta = self.meta.lock();
        self.check_shut()?;
        Ok(Tx { fs: self, meta })
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

    /// Writes the blocks of the changes since the last commit to the journal, and then to their
    /// places. As Linux, a commit collects the changes of up to `COMMIT_SECS` seconds, or until
    /// the transaction is a quarter of the log. `force` commits at once. If the journal cannot
    /// take the blocks, they go to their places at once.
    fn commit(&self, force: bool) {
        let Some(log) = &self.log else { return };
        if self.shut.load(Ordering::Relaxed) {
            return;
        }
        let now = rk_vfs::now().sec;
        let mut log = log.lock();
        let blocks = {
            let pending = self.pending.lock();
            let due = now.saturating_sub(*self.committed.lock()) >= COMMIT_SECS;
            if !force && !due && !log.full(pending.len()) {
                return;
            }
            pending.clone()
        };
        if log.commit(self, &blocks).is_err() {
            for (&block, data) in &blocks {
                let _ = self.write_direct(block * self.sb.block_size, data);
            }
        }
        drop(log);
        self.pending.lock().clear();
        self.busy.lock().clear();
        *self.committed.lock() = now;
    }

    /// Makes all the changes durable, for `fsync` and `sync`.
    pub(crate) fn sync(&self) -> Result<()> {
        self.check_shut()?;
        if !self.writable {
            return Ok(());
        }
        // The lock waits for a running change, so the commit has only whole changes.
        let meta = self.meta.lock();
        self.commit(true);
        drop(meta);
        self.disk.write_back(0, u64::MAX)?;
        self.disk.flush()
    }

    /// The counts of the file system for `statfs`, as `ext4_statfs` of Linux gives them. The
    /// blocks of the metadata and of the journal are not in the count of blocks, except with
    /// `minixdf`.
    pub(crate) fn stat(&self) -> rk_vfs::inode::FsStat {
        let sb = &self.sb;
        let meta = self.meta.lock();
        let field = |d: &[u8], at: usize| {
            let hi = if d.len() >= 64 { u64::from(u16_at(d, at + gd::HI)) << 16 } else { 0 };
            u64::from(u16_at(d, at)) | hi
        };
        let bfree: u64 = meta.descs.iter().map(|d| field(d, gd::FREE_BLOCKS)).sum();
        let ffree: u64 = meta.descs.iter().map(|d| field(d, gd::FREE_INODES)).sum();
        let mut reserved = u64::from(u32_at(&meta.sb, layout::sb::R_BLOCKS));
        if sb.incompat & layout::incompat::BIT64 != 0 {
            reserved |= u64::from(u32_at(&meta.sb, layout::sb::R_BLOCKS_HI)) << 32;
        }
        drop(meta);
        let groups = sb.groups();
        let base: u64 = (0..groups).map(|g| sb.base_meta_blocks(g)).sum();
        let mut overhead =
            u64::from(sb.first_data_block) + base + u64::from(groups) * (2 + sb.itable_blocks());
        if sb.journal_inum != 0
            && let Ok(raw) = self.read_inode(sb.journal_inum)
        {
            overhead += raw.size() / sb.block_size;
        }
        if self.minix_df.load(Ordering::Relaxed) {
            overhead = 0;
        }
        rk_vfs::inode::FsStat {
            bsize: sb.block_size,
            blocks: sb.blocks_count.saturating_sub(overhead),
            bfree,
            bavail: bfree.saturating_sub(reserved),
            files: u64::from(sb.inodes_count),
            ffree,
        }
    }

    /// Tells if the block `block` was freed since the last commit.
    pub(crate) fn is_busy(&self, block: u64) -> bool {
        self.log.is_some() && self.busy.lock().contains(&block)
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
            self.busy.lock().extend(start..start + count);
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
        // After a shutdown the disk stays as a crash leaves it, and the next mount replays the
        // journal.
        if self.shut.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.commit(true);
        log.lock().checkpoint(self)?;
        self.mark_recover(false)
    }

    /// Gives `EIO` after a shutdown.
    pub(crate) fn check_shut(&self) -> Result<()> {
        if self.shut.load(Ordering::Relaxed) { Err(Errno::EIO) } else { Ok(()) }
    }

    /// Stops the file system for `FS_IOC_GOINGDOWN`. After it, a change, a read of the data of a
    /// file, and `fsync` give `EIO`, and nothing goes to the disk again. `DEFAULT` and
    /// `LOGFLUSH` first make the changes durable, and `NOLOGFLUSH` loses the changes since the
    /// last commit.
    pub(crate) fn shutdown(&self, flags: u32) -> Result<()> {
        use rk_vfs::inode::shutdown::{DEFAULT, LOGFLUSH, NOLOGFLUSH};
        if !matches!(flags, DEFAULT | LOGFLUSH | NOLOGFLUSH) {
            return Err(Errno::EINVAL);
        }
        if self.shut.load(Ordering::Relaxed) {
            return Ok(());
        }
        if flags != NOLOGFLUSH {
            // As Linux, an error of the disk does not stop the shutdown.
            let _ = self.sync();
        }
        // The lock waits for a running change, so it does not go to the disk after this.
        let meta = self.meta.lock();
        self.shut.store(true, Ordering::Relaxed);
        drop(meta);
        Ok(())
    }

    /// Writes the transactions of the journal to their places and empties the journal, for
    /// `EXT4_IOC_CHECKPOINT`. `ZEROOUT` then writes zeros to the blocks of the log. A mount
    /// without a journal gives `ENODEV`, and `DISCARD` gives `EOPNOTSUPP`, as the disk does not
    /// discard.
    pub(crate) fn checkpoint(&self, flags: u32) -> Result<()> {
        use rk_vfs::inode::checkpoint::{DISCARD, DRY_RUN, ZEROOUT};
        if flags & !(DISCARD | ZEROOUT | DRY_RUN) != 0
            || flags & (DISCARD | ZEROOUT) == DISCARD | ZEROOUT
        {
            return Err(Errno::EINVAL);
        }
        let Some(log) = &self.log else { return Err(Errno::ENODEV) };
        if flags & DISCARD != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        if flags & DRY_RUN != 0 {
            return Ok(());
        }
        // The lock waits for a running change, so the commit has only whole changes.
        let meta = self.meta.lock();
        self.check_shut()?;
        self.commit(true);
        let mut log = log.lock();
        log.checkpoint(self)?;
        if flags & ZEROOUT != 0 {
            log.erase(self)?;
        }
        drop(log);
        drop(meta);
        Ok(())
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

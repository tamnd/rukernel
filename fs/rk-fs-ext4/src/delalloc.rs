//! The delayed allocation of the data of regular files, as `delalloc` of Linux.
//!
//! A buffered write to a hole of a file with an extent tree does not get blocks. Its data stays
//! in memory, and the file system keeps free blocks for it. `stat` counts the kept blocks in the
//! blocks of the file, `statfs` does not count them as free, and `FS_IOC_FIEMAP` gives them as
//! extents with `FIEMAP_EXTENT_DELALLOC`. The blocks are allocated and the data goes to the disk
//! at the writeback: `fsync`, `sync`, a freeze, the unmount, or when the kept data is too large.
//! A change of the extents of a file, as `fallocate`, first writes back the data of the file.

use crate::layout::{RawInode, flags};
use crate::{Fs, Tx};
use alloc::collections::BTreeMap;
use alloc::sync::Weak;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use rk_abi::Errno;
use rk_vfs::Result;
use rk_vfs::inode::FiemapExtent;

/// The most bytes of data that wait for the writeback in one file system.
const MAX_BYTES: u64 = 8 << 20;
/// The most free blocks that a delayed write cannot keep, as `s_resv_clusters` of Linux. Then the
/// extent trees can get blocks at the writeback.
const MAX_POOL: u64 = 4096;

/// The data of the files that waits for the writeback.
#[derive(Default)]
pub(crate) struct Delayed {
    /// The blocks of data of each inode, by the inode and the block of the file.
    files: BTreeMap<u32, BTreeMap<u64, Vec<u8>>>,
    /// The number of blocks in `files`, which the file system keeps free.
    pub(crate) count: u64,
    /// The blocks of the file that the writeback now writes. These are not kept free, so the
    /// writeback can allocate them.
    flushing: u64,
}

/// Gives the runs of the blocks of `file` as (first block, number of blocks).
fn runs(file: &BTreeMap<u64, Vec<u8>>) -> Vec<(u64, u64)> {
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for &lblock in file.keys() {
        match runs.last_mut() {
            Some((first, n)) if *first + *n == lblock => *n += 1,
            _ => runs.push((lblock, 1)),
        }
    }
    runs
}

impl Fs {
    /// Tells if a write to a hole of a regular file waits for the writeback.
    pub(crate) fn delalloc(&self) -> bool {
        self.delalloc.load(Ordering::Relaxed)
    }

    /// Turns the delayed allocation on or off, for the mount options `delalloc` and
    /// `nodelalloc`. The kept blocks are not clusters, so a file system with `bigalloc` does
    /// not use the delayed allocation.
    pub(crate) fn set_delalloc(&self, on: bool) {
        let on = on && self.writable && self.sb.cluster_ratio() == 1;
        self.delalloc.store(on, Ordering::Relaxed);
    }

    /// The number of blocks of all the files that wait for the writeback.
    pub(crate) fn delayed_count(&self) -> u64 {
        self.delayed.lock().count
    }

    /// The blocks that the delayed writes keep free, and that other allocations cannot use.
    pub(crate) fn kept_blocks(&self) -> u64 {
        let d = self.delayed.lock();
        d.count - d.flushing
    }

    /// The number of blocks of the inode `ino` that wait for the writeback.
    pub(crate) fn delayed_blocks(&self, ino: u32) -> u64 {
        self.delayed.lock().files.get(&ino).map_or(0, |f| f.len() as u64)
    }

    /// Gives a copy of the blocks of the inode `ino` that wait for the writeback and that have a
    /// byte from `offset` up to `offset + len`.
    pub(crate) fn delayed_data(&self, ino: u32, offset: u64, len: u64) -> Vec<(u64, Vec<u8>)> {
        let d = self.delayed.lock();
        let Some(file) = d.files.get(&ino) else { return Vec::new() };
        let bs = self.sb.block_size;
        let last = offset.saturating_add(len).div_ceil(bs);
        file.range(offset / bs..last).map(|(&l, data)| (l, data.clone())).collect()
    }

    /// Gives the runs of blocks of the inode `ino` that wait for the writeback as extents for
    /// `FS_IOC_FIEMAP`, from the byte `start` up to `end`. As Linux, they have no place on the
    /// disk.
    pub(crate) fn delayed_extents(&self, ino: u32, start: u64, end: u64) -> Vec<FiemapExtent> {
        let d = self.delayed.lock();
        let Some(file) = d.files.get(&ino) else { return Vec::new() };
        let bs = self.sb.block_size;
        runs(file)
            .into_iter()
            .filter(|&(first, n)| first * bs < end && (first + n) * bs > start)
            .map(|(first, n)| {
                let skip = (start / bs).saturating_sub(first);
                FiemapExtent {
                    logical: (first + skip) * bs,
                    physical: 0,
                    length: (n - skip) * bs,
                    unwritten: false,
                    inline: false,
                    delalloc: true,
                }
            })
            .collect()
    }

    /// Tells if a block of the inode `ino` from the byte `start` up to `end` waits for the
    /// writeback.
    pub(crate) fn has_delayed(&self, ino: u32, start: u64, end: u64) -> bool {
        let bs = self.sb.block_size;
        let d = self.delayed.lock();
        d.files.get(&ino).is_some_and(|f| f.range(start / bs..end.div_ceil(bs)).next().is_some())
    }

    /// Writes `buf` at `offset` of the regular file of `node` without new blocks, if the range
    /// has only holes. Gives `None` if the write must allocate its blocks now: the delayed
    /// allocation is off, the file has a block map or inline data, a block of the range has an
    /// extent, or the file system does not have the free blocks to keep.
    pub(crate) fn delay_write(
        &self,
        node: &crate::Node,
        offset: u64,
        buf: &[u8],
    ) -> Result<Option<usize>> {
        if !self.delalloc() {
            return Ok(None);
        }
        let bs = self.sb.block_size;
        let Some(end) = offset.checked_add(buf.len() as u64) else { return Ok(None) };
        if end.div_ceil(bs) > u64::from(u32::MAX) {
            return Ok(None);
        }
        if self.delayed.lock().count * bs >= MAX_BYTES {
            self.flush_all()?;
        }
        let mut tx = self.tx()?;
        let mut raw = node.raw();
        if raw.flags() & flags::EXTENTS == 0 || raw.flags() & flags::INLINE_DATA != 0 {
            return Ok(None);
        }
        let (first, last) = (offset / bs, (end - 1) / bs);
        let (extents, _) = self.extents(&raw)?;
        if extents.iter().any(|e| u64::from(e.lblock) <= last && e.end() > first) {
            return Ok(None);
        }
        let mut d = self.delayed.lock();
        let new = match d.files.get(&node.ino) {
            Some(file) => (first..=last).filter(|l| !file.contains_key(l)).count() as u64,
            None => last - first + 1,
        };
        let free = tx.free_count();
        let pool = (self.blocks_count() / 50).min(MAX_POOL);
        if new > 0 && free < d.count + new + pool {
            // Near a full disk, the write allocates its blocks now and gives the right error.
            drop(d);
            drop(tx);
            self.flush_all()?;
            return Ok(None);
        }
        let file = d.files.entry(node.ino).or_default();
        let mut pos = offset;
        while pos < end {
            let in_block = (pos % bs) as usize;
            let n = (bs as usize - in_block).min((end - pos) as usize);
            let at = (pos - offset) as usize;
            let block = file.entry(pos / bs).or_insert_with(|| vec![0u8; bs as usize]);
            block[in_block..in_block + n].copy_from_slice(&buf[at..at + n]);
            pos += n as u64;
        }
        d.count += new;
        drop(d);
        if end > raw.size() {
            raw.set_size(end);
        }
        crate::node::touch(&mut raw, true);
        tx.save(node, &mut raw)?;
        Ok(Some(buf.len()))
    }

    /// Allocates the blocks of the data of the inode `ino` that waits for the writeback, and
    /// writes the data to them. The data leaves the memory also after an error, as Linux.
    ///
    /// # Errors
    ///
    /// Gives `ENOSPC` if the file system has no free block, or the error of the disk.
    pub(crate) fn flush_delayed(&self, ino: u32) -> Result<()> {
        if self.delayed_blocks(ino) == 0 {
            return Ok(());
        }
        let result = self.retry_commit(|| self.write_delayed(ino));
        let mut d = self.delayed.lock();
        if let Some(file) = d.files.remove(&ino) {
            d.count -= file.len() as u64;
        }
        result
    }

    /// Writes back the data of all the files that waits for the writeback.
    ///
    /// # Errors
    ///
    /// Gives the first error. The data of the other files is written all the same.
    pub(crate) fn flush_all(&self) -> Result<()> {
        let inos: Vec<u32> = self.delayed.lock().files.keys().copied().collect();
        let mut result = Ok(());
        for ino in inos {
            result = result.and(self.flush_delayed(ino));
        }
        result
    }

    /// Allocates the blocks of the inode `ino` that wait for the writeback, writes their data,
    /// and saves the inode. The data stays in memory, so a read during the writeback finds it.
    fn write_delayed(&self, ino: u32) -> Result<()> {
        let node = self.inodes.lock().get(&ino).and_then(Weak::upgrade);
        let mut tx = self.tx()?;
        let Some(file) = self.delayed.lock().files.get(&ino).cloned() else { return Ok(()) };
        let mut raw = match &node {
            Some(node) => node.raw(),
            None => self.read_inode(ino)?,
        };
        self.delayed.lock().flushing = file.len() as u64;
        let result = tx.put_delayed(ino, &mut raw, &file);
        self.delayed.lock().flushing = 0;
        match &node {
            Some(node) => tx.save(node, &mut raw)?,
            None => self.write_inode(ino, &mut raw)?,
        }
        result
    }
}

impl Tx<'_> {
    /// The free blocks in the group descriptors.
    pub(crate) fn free_count(&self) -> u64 {
        (0..self.fs.group_count())
            .map(|g| u64::from(self.desc_get(g, crate::layout::gd::FREE_BLOCKS)))
            .sum()
    }

    /// Allocates the blocks of `file`, the data of the inode `ino` that waited for the writeback,
    /// and writes the data up to the size of the file.
    fn put_delayed(
        &mut self,
        ino: u32,
        raw: &mut RawInode,
        file: &BTreeMap<u64, Vec<u8>>,
    ) -> Result<()> {
        let bs = self.fs.sb.block_size;
        for (first, n) in runs(file) {
            let size = raw.size();
            let start = first * bs;
            if start >= size {
                break;
            }
            let data: Vec<u8> = file.range(first..first + n).flat_map(|(_, b)| b.clone()).collect();
            let len = (n * bs).min(size - start) as usize;
            if self.put_data(ino, raw, start, &data[..len])? < len {
                return Err(Errno::ENOSPC);
            }
        }
        Ok(())
    }

    /// Removes the blocks of the inode `ino` that wait for the writeback past the new size
    /// `size`, and makes the bytes past `size` in its last block zeros, for a truncate.
    pub(crate) fn cut_delayed(&mut self, ino: u32, size: u64) {
        let bs = self.fs.sb.block_size;
        let mut d = self.fs.delayed.lock();
        let Some(file) = d.files.get_mut(&ino) else { return };
        let gone = file.split_off(&size.div_ceil(bs)).len() as u64;
        if let Some(block) = file.get_mut(&(size / bs)) {
            block[(size % bs) as usize..].fill(0);
        }
        if file.is_empty() {
            d.files.remove(&ino);
        }
        d.count -= gone;
    }

    /// Removes all the blocks of the inode `ino` that wait for the writeback, for the release of
    /// the inode.
    pub(crate) fn drop_delayed(&mut self, ino: u32) {
        let mut d = self.fs.delayed.lock();
        if let Some(file) = d.files.remove(&ino) {
            d.count -= file.len() as u64;
        }
    }
}

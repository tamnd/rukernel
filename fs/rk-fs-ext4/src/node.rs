//! The inodes of ext4: the attributes, the map from the blocks of a file to the blocks of the
//! disk, the data, and the changes of the files and the directories.

use crate::extent::{self, Extent};
use crate::layout::{self, EXTENT_INIT_MAX, EXTENT_MAGIC, RawInode, flags, u16_at, u32_at};
use crate::{EXT4_MAGIC, Fs, Tx, xattr};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::inode::{FiemapExtent, mode};
use rk_vfs::xattr::{XATTR_CREATE, XATTR_REPLACE};
use rk_vfs::{DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, Timespec, now};

use extent::MAX_DEPTH;

/// The longest name in a directory.
const NAME_MAX: usize = 255;
/// The most hard links of a file.
const LINK_MAX: u16 = 65000;

/// An inode of ext4.
pub struct Node {
    fs: Arc<Fs>,
    pub(crate) ino: u32,
    raw: SpinLock<RawInode>,
}

/// Gives the time stamp of the seconds and the nanoseconds of `t`.
fn timespec((sec, nsec): (i64, u32)) -> Timespec {
    Timespec { sec, nsec: nsec.min(999_999_999) }
}

/// The type of a file from the file type of a directory entry, as `EXT4_FT_*`.
pub(crate) fn entry_type(t: u8) -> Option<FileType> {
    Some(match t {
        1 => FileType::Regular,
        2 => FileType::Directory,
        3 => FileType::CharDevice,
        4 => FileType::BlockDevice,
        5 => FileType::Fifo,
        6 => FileType::Socket,
        7 => FileType::Symlink,
        _ => return None,
    })
}

/// The file type of a directory entry for `kind`, as `EXT4_FT_*`.
pub(crate) fn entry_code(kind: FileType) -> u8 {
    match kind {
        FileType::Regular => 1,
        FileType::Directory => 2,
        FileType::CharDevice => 3,
        FileType::BlockDevice => 4,
        FileType::Fifo => 5,
        FileType::Socket => 6,
        FileType::Symlink => 7,
    }
}

fn kind_of(raw: &RawInode) -> FileType {
    FileType::from_mode(u32::from(raw.mode())).unwrap_or(FileType::Regular)
}

/// Tells if the symbolic link has its target in `i_block`.
fn fast_symlink(raw: &RawInode) -> bool {
    kind_of(raw) == FileType::Symlink
        && raw.size() < 60
        && raw.flags() & (flags::EXTENTS | flags::INLINE_DATA) == 0
}

/// Sets the change time, and the modification time if `modify` is true, to now.
fn touch(raw: &mut RawInode, modify: bool) {
    let t = now();
    raw.set_time(0xc, 0x84, t.sec, t.nsec);
    if modify {
        raw.set_time(0x10, 0x88, t.sec, t.nsec);
    }
}

impl Fs {
    /// Gives the block of the disk that has the block `lblock` of the file, and tells if the
    /// block has data. A hole gives `None`.
    pub(crate) fn map(&self, raw: &RawInode, lblock: u64) -> Result<Option<(u64, bool)>> {
        if raw.flags() & flags::EXTENTS != 0 {
            let lblock = u32::try_from(lblock).map_err(|_| Errno::EFBIG)?;
            self.map_extent(raw, lblock)
        } else {
            Ok(self.map_indirect(raw, lblock)?.map(|b| (b, true)))
        }
    }

    /// Finds `lblock` in the extent tree.
    fn map_extent(&self, raw: &RawInode, lblock: u32) -> Result<Option<(u64, bool)>> {
        let mut node = raw.block().to_vec();
        for _ in 0..=MAX_DEPTH {
            if node.len() < 12 || u16_at(&node, 0) != EXTENT_MAGIC {
                return Err(Errno::EUCLEAN);
            }
            let entries = usize::from(u16_at(&node, 2));
            if 12 + entries * 12 > node.len() {
                return Err(Errno::EUCLEAN);
            }
            let entry = |i: usize| &node[12 + i * 12..24 + i * 12];
            if u16_at(&node, 6) == 0 {
                for e in (0..entries).map(entry) {
                    let first = u32_at(e, 0);
                    let raw_len = u16_at(e, 4);
                    let (len, init) = if raw_len > EXTENT_INIT_MAX {
                        (raw_len - EXTENT_INIT_MAX, false)
                    } else {
                        (raw_len, true)
                    };
                    if lblock >= first && lblock - first < u32::from(len) {
                        let start = u64::from(u16_at(e, 6)) << 32 | u64::from(u32_at(e, 8));
                        return Ok(Some((start + u64::from(lblock - first), init)));
                    }
                }
                return Ok(None);
            }
            // The last index that starts at or before `lblock`.
            let Some(e) = (0..entries).map(entry).take_while(|e| u32_at(e, 0) <= lblock).last()
            else {
                return Ok(None);
            };
            let leaf = u64::from(u32_at(e, 4)) | u64::from(u16_at(e, 8)) << 32;
            node = self.read_block(leaf)?;
        }
        Err(Errno::EUCLEAN)
    }

    /// Finds `lblock` in the block map of ext2 and ext3: 12 direct blocks, then a single, a
    /// double and a triple indirect block.
    fn map_indirect(&self, raw: &RawInode, lblock: u64) -> Result<Option<u64>> {
        let per = self.sb.block_size / 4;
        let root = raw.block();
        let (mut block, mut index, mut levels) = if lblock < 12 {
            return Ok(Some(u64::from(u32_at(root, lblock as usize * 4))).filter(|&b| b != 0));
        } else if lblock - 12 < per {
            (u32_at(root, 12 * 4), lblock - 12, 1)
        } else if lblock - 12 - per < per * per {
            (u32_at(root, 13 * 4), lblock - 12 - per, 2)
        } else if lblock - 12 - per - per * per < per * per * per {
            (u32_at(root, 14 * 4), lblock - 12 - per - per * per, 3)
        } else {
            return Err(Errno::EFBIG);
        };
        while levels > 0 {
            if block == 0 {
                return Ok(None);
            }
            levels -= 1;
            let span = per.pow(levels);
            let data = self.read_block(u64::from(block))?;
            block = u32_at(&data, (index / span) as usize * 4);
            index %= span;
        }
        Ok(Some(u64::from(block)).filter(|&b| b != 0))
    }

    /// Reads the block map of the file into runs of blocks that follow each other on the disk,
    /// and the indirect blocks of the map.
    pub(crate) fn block_map(&self, raw: &RawInode) -> Result<(Vec<Extent>, Vec<u64>)> {
        let per = self.sb.block_size / 4;
        let root = raw.block();
        let mut runs = Vec::new();
        let mut tree = Vec::new();
        let mut lblock = 0;
        for (i, level) in [(0..12, 0), (12..13, 1), (13..14, 2), (14..15, 3)]
            .into_iter()
            .flat_map(|(r, l)| r.map(move |i| (i, l)))
        {
            let block = u64::from(u32_at(root, i * 4));
            self.walk_map(block, level, lblock, &mut runs, &mut tree)?;
            lblock += per.pow(level);
        }
        Ok((runs, tree))
    }

    /// Adds the blocks under `block`, a block of the level `level` of the map that maps from
    /// the block `lblock` of the file, to `runs` and `tree`.
    fn walk_map(
        &self,
        block: u64,
        level: u32,
        lblock: u64,
        runs: &mut Vec<Extent>,
        tree: &mut Vec<u64>,
    ) -> Result<()> {
        if block == 0 {
            return Ok(());
        }
        if level > 0 {
            tree.push(block);
            let span = (self.sb.block_size / 4).pow(level - 1);
            let data = self.read_block(block)?;
            for i in 0..data.len() / 4 {
                let next = u64::from(u32_at(&data, i * 4));
                self.walk_map(next, level - 1, lblock + i as u64 * span, runs, tree)?;
            }
            return Ok(());
        }
        let lblock = u32::try_from(lblock).map_err(|_| Errno::EFBIG)?;
        match runs.last_mut() {
            Some(r)
                if r.end() == u64::from(lblock)
                    && r.start + u64::from(r.len) == block
                    && r.len < u32::from(EXTENT_INIT_MAX) =>
            {
                r.len += 1
            }
            _ => runs.push(Extent { lblock, len: 1, start: block, init: true }),
        }
        Ok(())
    }

    /// Reads the data of the file at `offset`, up to the size of the file.
    pub(crate) fn read_data(&self, raw: &RawInode, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.check_shut()?;
        if raw.flags() & flags::INLINE_DATA != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let size = raw.size();
        if offset >= size {
            return Ok(0);
        }
        let len = buf.len().min((size - offset) as usize);
        let bs = self.sb.block_size;
        let mut done = 0;
        while done < len {
            let at = offset + done as u64;
            let in_block = (at % bs) as usize;
            let n = (bs as usize - in_block).min(len - done);
            let out = &mut buf[done..done + n];
            match self.map(raw, at / bs)? {
                Some((block, true)) => {
                    if block >= self.blocks_count() {
                        return Err(Errno::EUCLEAN);
                    }
                    self.read(block * bs + in_block as u64, out)?;
                }
                _ => out.fill(0),
            }
            done += n;
        }
        Ok(len)
    }
}

impl Tx<'_> {
    /// Writes the inode of `node` and keeps `raw` as its inode in memory. An inode that loses
    /// its last link goes on the list of orphans.
    pub(crate) fn save(&mut self, node: &Node, mut raw: RawInode) -> Result<()> {
        if raw.links() == 0 && node.raw.lock().links() != 0 {
            self.add_orphan(node.ino, &mut raw)?;
        }
        self.fs.write_inode(node.ino, &mut raw)?;
        *node.raw.lock() = raw;
        Ok(())
    }

    /// Writes `buf` at `offset` of the file `ino`, and gives new blocks to the holes. The size
    /// grows if the data goes past it.
    pub(crate) fn write_data(
        &mut self,
        ino: u32,
        raw: &mut RawInode,
        offset: u64,
        buf: &[u8],
    ) -> Result<usize> {
        let fs = self.fs;
        let bs = fs.sb.block_size;
        let end = offset.checked_add(buf.len() as u64).ok_or(Errno::EFBIG)?;
        if end.div_ceil(bs) > u64::from(u32::MAX) {
            return Err(Errno::EFBIG);
        }
        let is_map = raw.flags() & flags::EXTENTS == 0;
        let (mut extents, tree) = if !is_map { fs.extents(raw)? } else { (Vec::new(), Vec::new()) };
        let mut changed = false;
        let mut pos = offset;
        let mut result = Ok(());
        while pos < end {
            let lblock = pos / bs;
            let in_block = (pos % bs) as usize;
            let n = (bs as usize - in_block).min((end - pos) as usize);
            let data = &buf[(pos - offset) as usize..(pos - offset) as usize + n];
            let found = if raw.flags() & flags::EXTENTS != 0 {
                extent::find(&extents, lblock)
                    .map(|e| (e.start + (lblock - u64::from(e.lblock)), e.init))
            } else {
                fs.map(raw, lblock)?
            };
            match found {
                Some((block, true)) => {
                    if let Err(e) = fs.write_file(raw, block * bs + in_block as u64, data) {
                        result = Err(e);
                        break;
                    }
                }
                Some((block, false)) => {
                    let mut full = vec![0u8; bs as usize];
                    full[in_block..in_block + n].copy_from_slice(data);
                    if let Err(e) = fs.write_file(raw, block * bs, &full) {
                        result = Err(e);
                        break;
                    }
                    extent::put(
                        &mut extents,
                        Extent { lblock: lblock as u32, len: 1, start: block, init: true },
                    );
                    changed = true;
                }
                None => {
                    let last = end.div_ceil(bs);
                    let (next, goal) = if is_map {
                        let mut next = lblock + 1;
                        while next < last && fs.map(raw, next)?.is_none() {
                            next += 1;
                        }
                        let before = match lblock.checked_sub(1) {
                            Some(l) => fs.map(raw, l)?.map(|(b, _)| b + 1),
                            None => None,
                        };
                        (next, before.unwrap_or_else(|| fs.goal(ino)))
                    } else {
                        let next = extents
                            .iter()
                            .map(|e| u64::from(e.lblock))
                            .find(|&l| l > lblock)
                            .unwrap_or(last);
                        let goal = extents
                            .iter()
                            .rev()
                            .find(|e| u64::from(e.lblock) < lblock)
                            .map_or_else(
                                || fs.goal(ino),
                                |e| e.start + (lblock - u64::from(e.lblock)),
                            );
                        (next, goal)
                    };
                    let want = (next.min(last) - lblock).min(u64::from(EXTENT_INIT_MAX)) as u32;
                    let (start, got) = match self.alloc_blocks(goal, want) {
                        Ok(run) => run,
                        Err(e) => {
                            result = Err(e);
                            break;
                        }
                    };
                    if is_map && let Err(e) = self.map_blocks(raw, lblock, start, u64::from(got)) {
                        // The entries that the map got before the error stay, and fsck finds
                        // them. As Linux, the indirect blocks come before the data blocks.
                        self.free_blocks(start, u64::from(got))?;
                        result = Err(e);
                        break;
                    }
                    let zero = vec![0u8; bs as usize];
                    let partial_first = in_block != 0;
                    let partial_last = (lblock + u64::from(got)) * bs > end;
                    if partial_first {
                        fs.write_file(raw, start * bs, &zero)?;
                    }
                    if partial_last && (got > 1 || !partial_first) {
                        fs.write_file(raw, (start + u64::from(got) - 1) * bs, &zero)?;
                    }
                    if !is_map {
                        extent::put(
                            &mut extents,
                            Extent { lblock: lblock as u32, len: got, start, init: true },
                        );
                        changed = true;
                    }
                    raw.set_blocks(raw.blocks() + u64::from(got) * (bs / 512));
                    continue;
                }
            }
            pos += n as u64;
        }
        if changed {
            self.build_tree(ino, raw, &extents, tree)?;
        }
        if pos > raw.size() {
            raw.set_size(pos);
        }
        if pos > offset {
            touch(raw, true);
            return Ok((pos - offset) as usize);
        }
        result.map(|()| 0)
    }

    /// Changes the size of the file `ino`. The bytes past the size in its last block become
    /// zeros. A truncate down or to the same size frees the blocks past the size, also the blocks
    /// that `fallocate` gave with `FALLOC_FL_KEEP_SIZE`, as Linux. A truncate up keeps them.
    pub(crate) fn truncate(&mut self, ino: u32, raw: &mut RawInode, size: u64) -> Result<()> {
        let fs = self.fs;
        let bs = fs.sb.block_size;
        let old = raw.size();
        if size <= old && raw.flags() & flags::EXTENTS == 0 {
            let freed = self.cut_map(raw, size.div_ceil(bs))?;
            raw.set_blocks(raw.blocks().saturating_sub(freed * (bs / 512)));
        } else if size <= old {
            let (mut extents, tree) = fs.extents(raw)?;
            let last = size.div_ceil(bs);
            if size == old && extents.iter().all(|e| e.end() <= last) {
                return Ok(());
            }
            let freed = extent::cut(&mut extents, last);
            let mut count = 0;
            for (start, len) in freed {
                self.free_blocks(start, len)?;
                count += len;
            }
            raw.set_blocks(raw.blocks().saturating_sub(count * (bs / 512)));
            self.build_tree(ino, raw, &extents, tree)?;
        }
        let at = size.min(old);
        if size != old
            && !at.is_multiple_of(bs)
            && let Some((block, true)) = fs.map(raw, at / bs)?
        {
            let zero = vec![0u8; (bs - at % bs) as usize];
            fs.write_file(raw, block * bs + at % bs, &zero)?;
        }
        raw.set_size(size);
        Ok(())
    }

    /// Gives blocks to the holes of the blocks `first..last` of the file, as extents that are
    /// not initialized, so they read as zeros. Gives `true` if the list changed. On an error the
    /// list keeps the blocks that it got.
    fn preallocate(
        &mut self,
        ino: u32,
        raw: &mut RawInode,
        extents: &mut Vec<Extent>,
        first: u64,
        last: u64,
    ) -> (bool, Result<()>) {
        let bs = self.fs.sb.block_size;
        let mut changed = false;
        let mut lblock = first;
        while lblock < last {
            if let Some(e) = extent::find(extents, lblock) {
                lblock = e.end();
                continue;
            }
            let next =
                extents.iter().map(|e| u64::from(e.lblock)).find(|&l| l > lblock).unwrap_or(last);
            let want = (next.min(last) - lblock).min(u64::from(EXTENT_INIT_MAX - 1)) as u32;
            let goal = extents
                .iter()
                .rev()
                .find(|e| u64::from(e.lblock) < lblock)
                .map_or_else(|| self.fs.goal(ino), |e| e.start + (lblock - u64::from(e.lblock)));
            let (start, got) = match self.alloc_blocks(goal, want) {
                Ok(run) => run,
                Err(e) => return (changed, Err(e)),
            };
            extent::put(extents, Extent { lblock: lblock as u32, len: got, start, init: false });
            raw.set_blocks(raw.blocks() + u64::from(got) * (bs / 512));
            changed = true;
            lblock += u64::from(got);
        }
        (changed, Ok(()))
    }

    /// Writes zeros on the bytes `from..to` of one block of the file, if the block has data.
    fn zero_part(&self, raw: &RawInode, from: u64, to: u64) -> Result<()> {
        let bs = self.fs.sb.block_size;
        if from < to
            && let Some((block, true)) = self.fs.map(raw, from / bs)?
        {
            let zero = vec![0u8; (to - from) as usize];
            self.fs.write_file(raw, block * bs + from % bs, &zero)?;
        }
        Ok(())
    }

    /// `FALLOC_FL_COLLAPSE_RANGE` or `FALLOC_FL_INSERT_RANGE` of the file `ino`. A collapse frees
    /// the blocks of the range and moves the blocks after it down. An insert moves the blocks from
    /// `offset` up and leaves a hole. Each one changes the size by `len`. The checks are the
    /// checks of Linux, in its order.
    fn shift_range(
        &mut self,
        ino: u32,
        raw: &mut RawInode,
        collapse: bool,
        offset: u64,
        len: u64,
    ) -> Result<()> {
        let fs = self.fs;
        let bs = fs.sb.block_size;
        if raw.flags() & flags::EXTENTS == 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        if !(offset | len).is_multiple_of(bs) {
            return Err(Errno::EINVAL);
        }
        let size = raw.size();
        let (first, count) = (offset / bs, len / bs);
        let (mut extents, tree) = fs.extents(raw)?;
        if collapse {
            if offset.saturating_add(len) >= size {
                return Err(Errno::EINVAL);
            }
            let mut freed = 0;
            for (start, n) in extent::remove(&mut extents, first, first + count) {
                self.free_blocks(start, n)?;
                freed += n;
            }
            raw.set_blocks(raw.blocks().saturating_sub(freed * (bs / 512)));
            extents = extent::shift(&extents, first + count, -(count as i64));
            raw.set_size(size - len);
        } else {
            let last = extents.last().map_or(0, Extent::end);
            if size.saturating_add(len).div_ceil(bs) > u64::from(u32::MAX)
                || last.saturating_add(count) > u64::from(u32::MAX)
            {
                return Err(Errno::EFBIG);
            }
            if offset >= size {
                return Err(Errno::EINVAL);
            }
            extents = extent::shift(&extents, first, count as i64);
            raw.set_size(size + len);
        }
        self.build_tree(ino, raw, &extents, tree)?;
        touch(raw, true);
        Ok(())
    }

    /// `fallocate` of the file `ino`. A new block is an extent that is not initialized. A hole
    /// frees the full blocks of the range, and the parts of blocks at its ends become zeros.
    pub(crate) fn fallocate(
        &mut self,
        ino: u32,
        raw: &mut RawInode,
        mode: u32,
        offset: u64,
        len: u64,
    ) -> Result<()> {
        use rk_vfs::inode::falloc::{
            COLLAPSE_RANGE, INSERT_RANGE, KEEP_SIZE, PUNCH_HOLE, ZERO_RANGE,
        };
        if mode & (COLLAPSE_RANGE | INSERT_RANGE) != 0 {
            return self.shift_range(ino, raw, mode & COLLAPSE_RANGE != 0, offset, len);
        }
        let fs = self.fs;
        let bs = fs.sb.block_size;
        let end = offset.checked_add(len).ok_or(Errno::EFBIG)?;
        if end.div_ceil(bs) > u64::from(u32::MAX) {
            return Err(Errno::EFBIG);
        }
        if mode & !(KEEP_SIZE | PUNCH_HOLE | ZERO_RANGE) != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        if raw.flags() & flags::EXTENTS == 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let clear = mode & (PUNCH_HOLE | ZERO_RANGE) != 0;
        if clear {
            // The ends of the range in blocks that the range does not fill.
            let (first_full, last_full) = (offset.div_ceil(bs), end / bs);
            if first_full > last_full {
                self.zero_part(raw, offset, end)?;
            } else {
                self.zero_part(raw, offset, first_full * bs)?;
                self.zero_part(raw, last_full * bs, end)?;
            }
            if first_full < last_full {
                let (mut extents, tree) = fs.extents(raw)?;
                let freed = extent::remove(&mut extents, first_full, last_full);
                if !freed.is_empty() {
                    let mut count = 0;
                    for (start, n) in freed {
                        self.free_blocks(start, n)?;
                        count += n;
                    }
                    raw.set_blocks(raw.blocks().saturating_sub(count * (bs / 512)));
                    self.build_tree(ino, raw, &extents, tree)?;
                }
            }
        }
        if mode & PUNCH_HOLE == 0 {
            let (mut extents, tree) = fs.extents(raw)?;
            let (changed, result) =
                self.preallocate(ino, raw, &mut extents, offset / bs, end.div_ceil(bs));
            if changed {
                self.build_tree(ino, raw, &extents, tree)?;
            }
            result?;
            if mode & KEEP_SIZE == 0 && end > raw.size() {
                raw.set_size(end);
                touch(raw, true);
                return Ok(());
            }
        }
        touch(raw, clear);
        Ok(())
    }

    /// Frees the inode `ino`, which has no link and which no one uses, and its blocks.
    pub(crate) fn release(&mut self, ino: u32) -> Result<()> {
        let fs = self.fs;
        let mut raw = fs.read_inode(ino)?;
        if raw.links() != 0 {
            return Ok(());
        }
        self.remove_orphan(ino, &raw)?;
        let kind = kind_of(&raw);
        let has_blocks =
            matches!(kind, FileType::Regular | FileType::Directory | FileType::Symlink)
                && !fast_symlink(&raw);
        if has_blocks && raw.flags() & flags::EXTENTS != 0 {
            let (extents, tree) = fs.extents(&raw)?;
            for e in extents {
                self.free_blocks(e.start, u64::from(e.len))?;
            }
            for b in tree {
                self.free_blocks(b, 1)?;
            }
            Tx::empty_tree(&mut raw);
        } else if has_blocks {
            let root = raw.block().to_vec();
            for (i, level) in [(0..12, 0), (12..13, 1), (13..14, 2), (14..15, 3)]
                .into_iter()
                .flat_map(|(r, l)| r.map(move |i| (i, l)))
            {
                self.free_map(u64::from(u32_at(&root, i * 4)), level)?;
            }
            raw.block_mut().fill(0);
        }
        let acl = raw.file_acl();
        if acl != 0 {
            self.put_xattr_block(acl)?;
            raw.set_file_acl(0);
        }
        let t = now();
        layout::put32(&mut raw.0, 0x14, t.sec as u32);
        raw.set_size(0);
        raw.set_blocks(0);
        fs.write_inode(ino, &mut raw)?;
        self.free_inode(ino, kind == FileType::Directory)
    }

    /// Puts the inode `ino` first on the list of orphans, as `ext4_orphan_add`. The list is in
    /// `s_last_orphan` and in the `i_dtime` of each orphan. After a crash, the mount or fsck frees
    /// the orphans.
    fn add_orphan(&mut self, ino: u32, raw: &mut RawInode) -> Result<()> {
        let head = u32_at(&self.meta.sb, layout::sb::LAST_ORPHAN);
        layout::put32(&mut raw.0, 0x14, head);
        layout::put32(&mut self.meta.sb, layout::sb::LAST_ORPHAN, ino);
        self.write_sb(0, 0)
    }

    /// Removes the inode `ino` with `raw` from the list of orphans, as `ext4_orphan_del`.
    pub(crate) fn remove_orphan(&mut self, ino: u32, raw: &RawInode) -> Result<()> {
        let fs = self.fs;
        let next = u32_at(&raw.0, 0x14);
        let mut at = u32_at(&self.meta.sb, layout::sb::LAST_ORPHAN);
        if at == ino {
            layout::put32(&mut self.meta.sb, layout::sb::LAST_ORPHAN, next);
            return self.write_sb(0, 0);
        }
        // A list with a loop or a bad inode ends after one step for each inode.
        for _ in 0..fs.inodes_count() {
            if at == 0 || at > fs.inodes_count() {
                break;
            }
            let node = fs.inodes.lock().get(&at).and_then(alloc::sync::Weak::upgrade);
            let mut prev = match &node {
                Some(node) => node.raw(),
                None => fs.read_inode(at)?,
            };
            if u32_at(&prev.0, 0x14) == ino {
                layout::put32(&mut prev.0, 0x14, next);
                fs.write_inode(at, &mut prev)?;
                if let Some(node) = node {
                    *node.raw.lock() = prev;
                }
                return Ok(());
            }
            at = u32_at(&prev.0, 0x14);
        }
        Ok(())
    }

    /// Frees the orphans that a crash left, at mount, as `ext4_orphan_cleanup`. An orphan that
    /// has links again leaves the list. A reserved inode, an inode past the end, or an inode
    /// that is not in use ends the list, and the driver does not change it, as Linux.
    pub(crate) fn clean_orphans(&mut self) -> Result<()> {
        let fs = self.fs;
        for _ in 0..fs.inodes_count() {
            let ino = u32_at(&self.meta.sb, layout::sb::LAST_ORPHAN);
            if ino == 0 {
                break;
            }
            if ino < fs.sb.first_ino || ino > fs.inodes_count() || !self.inode_in_use(ino)? {
                layout::put32(&mut self.meta.sb, layout::sb::LAST_ORPHAN, 0);
                return self.write_sb(0, 0);
            }
            let mut raw = fs.read_inode(ino)?;
            if raw.links() == 0 {
                self.release(ino)?;
            } else {
                self.remove_orphan(ino, &raw)?;
                layout::put32(&mut raw.0, 0x14, 0);
                fs.write_inode(ino, &mut raw)?;
            }
        }
        Ok(())
    }

    /// Moves the file `ino` from a block map to an extent tree, as `chattr +e`. The tree uses
    /// the indirect blocks of the map first.
    fn migrate_to_extents(&mut self, ino: u32, raw: &mut RawInode) -> Result<()> {
        let (runs, map) = self.fs.block_map(raw)?;
        raw.set_flags(raw.flags() | flags::EXTENTS);
        Tx::empty_tree(raw);
        self.build_tree(ino, raw, &runs, map)
    }

    /// Moves the file from an extent tree to a block map, as `chattr -e`. As Linux, the tree
    /// must be only the root, with at most one extent that has data and fits in the 12 direct
    /// blocks. Other files give `EOPNOTSUPP`.
    fn migrate_to_block_map(raw: &mut RawInode) -> Result<()> {
        if u16_at(raw.block(), 0) != EXTENT_MAGIC {
            return Err(Errno::EUCLEAN);
        }
        if u16_at(raw.block(), 6) != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let mut entries = [0u32; 12];
        let mut extents = (0..usize::from(u16_at(raw.block(), 2))).map(|i| {
            let e = &raw.block()[12 + i * 12..24 + i * 12];
            (u32_at(e, 0), u16_at(e, 4), u64::from(u16_at(e, 6)) << 32 | u64::from(u32_at(e, 8)))
        });
        if let Some((lblock, len, start)) = extents.next() {
            let (lblock, len) = (lblock as usize, usize::from(len));
            if len > usize::from(EXTENT_INIT_MAX)
                || lblock + len > entries.len()
                || start + len as u64 > u64::from(u32::MAX)
            {
                return Err(Errno::EOPNOTSUPP);
            }
            for (i, entry) in entries[lblock..lblock + len].iter_mut().enumerate() {
                *entry = (start + i as u64) as u32;
            }
        }
        if extents.next().is_some() {
            return Err(Errno::EOPNOTSUPP);
        }
        let root = raw.block_mut();
        root.fill(0);
        for (i, entry) in entries.iter().enumerate() {
            layout::put32(root, i * 4, *entry);
        }
        raw.set_flags(raw.flags() & !flags::EXTENTS);
        Ok(())
    }

    /// Makes a new inode of the type `kind` near the directory `dir`, and writes it.
    fn new_inode(&mut self, dir: u32, kind: FileType, perm: u32) -> Result<(u32, RawInode)> {
        let fs = self.fs;
        let is_dir = kind == FileType::Directory;
        let ino = self.alloc_inode(dir, is_dir)?;
        let size = usize::from(fs.sb.inode_size);
        let mut raw = RawInode(vec![0u8; size]);
        if size > 128 {
            let extra = fs.sb.want_extra_isize.max(32).min(size as u16 - 128);
            layout::put16(&mut raw.0, 0x80, extra);
        }
        raw.set_mode((kind.mode_bits() | (perm & mode::PERM_MASK)) as u16);
        raw.set_links(if is_dir { 2 } else { 1 });
        layout::put32(&mut raw.0, 0x64, self.next_generation());
        let t = now();
        raw.set_time(0x8, 0x8c, t.sec, t.nsec);
        touch(&mut raw, true);
        if raw.extra_size() >= 0x98 - 128 {
            raw.set_time(0x90, 0x94, t.sec, t.nsec);
        }
        // A disk without the `extents` feature keeps the new files in a block map.
        if matches!(kind, FileType::Regular | FileType::Directory | FileType::Symlink)
            && fs.sb.incompat & layout::incompat::EXTENTS != 0
        {
            raw.set_flags(flags::EXTENTS);
            Tx::empty_tree(&mut raw);
        }
        fs.write_inode(ino, &mut raw)?;
        Ok((ino, raw))
    }
}

impl Fs {
    /// The first block of the group of the inode `ino`, where its data goes first.
    pub(crate) fn goal(&self, ino: u32) -> u64 {
        let group = u64::from((ino - 1) / self.sb.inodes_per_group);
        u64::from(self.sb.first_data_block) + group * u64::from(self.sb.blocks_per_group)
    }
}

impl Node {
    pub(crate) fn new(fs: Arc<Fs>, ino: u32, raw: RawInode) -> Arc<Self> {
        Arc::new(Self { fs, ino, raw: SpinLock::new(raw) })
    }

    /// A copy of the inode.
    pub(crate) fn raw(&self) -> RawInode {
        self.raw.lock().clone()
    }

    pub(crate) fn kind(&self) -> FileType {
        kind_of(&self.raw.lock())
    }

    fn is_dir(&self) -> bool {
        self.kind() == FileType::Directory
    }

    /// The device of a device file, from `i_block`, as `old_decode_dev` and `new_decode_dev` of
    /// Linux.
    fn rdev(raw: &RawInode) -> u64 {
        let b = raw.block();
        let (old, new) = (u32_at(b, 0), u32_at(b, 4));
        if old != 0 {
            rk_vfs::device::makedev((old >> 8) & 0xff, old & 0xff)
        } else {
            rk_vfs::device::makedev((new & 0xfff00) >> 8, (new & 0xff) | ((new >> 12) & 0xfff00))
        }
    }

    /// Gives the ext4 inode of `inode`, which must be in this file system.
    fn same_fs<'a>(&self, inode: &'a InodeRef) -> Result<&'a Node> {
        let any: &dyn Any = &**inode;
        let node = any.downcast_ref::<Node>().ok_or(Errno::EXDEV)?;
        if !Arc::ptr_eq(&node.fs, &self.fs) {
            return Err(Errno::EXDEV);
        }
        Ok(node)
    }

    /// Checks that this inode is a directory, and that `name` can be a new entry in it.
    fn check_new(&self, name: &[u8]) -> Result<()> {
        if !self.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        if name.len() > NAME_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        if self.fs.find_entry(&self.raw(), name)?.is_some() {
            return Err(Errno::EEXIST);
        }
        Ok(())
    }

    /// Adds `delta` to the links of this inode, and sets its change time.
    fn add_links(&self, tx: &mut Tx<'_>, delta: i32) -> Result<()> {
        let mut raw = self.raw();
        raw.set_links(raw.links().saturating_add_signed(delta as i16));
        touch(&mut raw, false);
        tx.save(self, raw)
    }

    /// Sets the times of a directory after a change of its entries.
    fn touch_dir(&self, tx: &mut Tx<'_>) -> Result<()> {
        let mut raw = self.raw();
        touch(&mut raw, true);
        tx.save(self, raw)
    }

    /// Adds the new inode `ino` with `raw` as `name`. If the entry cannot be added, the inode
    /// loses its links, and the end of the change frees it.
    fn attach(&self, tx: &mut Tx<'_>, name: &[u8], ino: u32, raw: RawInode) -> Result<Arc<Node>> {
        let kind = kind_of(&raw);
        let node = self.fs.new_node(ino, raw)?;
        if let Err(e) = tx.add_entry(self, name, ino, kind) {
            let mut raw = node.raw();
            raw.set_links(0);
            tx.save(&node, raw)?;
            return Err(e);
        }
        if kind == FileType::Directory {
            self.add_links(tx, 1)?;
        }
        self.touch_dir(tx)?;
        Ok(node)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if self.fs.writable && self.raw.lock().links() == 0 {
            self.fs.orphan(self.ino);
        }
    }
}

impl Inode for Node {
    fn sync(&self) -> Result<()> {
        self.fs.sync()
    }

    fn shutdown(&self, flags: u32) -> Result<()> {
        self.fs.shutdown(flags)
    }

    fn checkpoint(&self, flags: u32) -> Result<()> {
        self.fs.checkpoint(flags)
    }

    fn resize(&self, blocks: u64) -> Result<()> {
        self.fs.resize(blocks)
    }

    fn metadata(&self) -> Metadata {
        let raw = self.raw();
        let kind = kind_of(&raw);
        let bs = self.fs.sb.block_size;
        let blocks = if raw.flags() & flags::HUGE_FILE != 0 {
            raw.blocks() * (bs / 512)
        } else {
            raw.blocks()
        };
        let rdev = match kind {
            FileType::CharDevice | FileType::BlockDevice => Self::rdev(&raw),
            _ => 0,
        };
        Metadata {
            dev: self.fs.dev,
            ino: u64::from(self.ino),
            mode: u32::from(raw.mode()),
            nlink: u32::from(raw.links()),
            uid: raw.uid(),
            gid: raw.gid(),
            rdev,
            size: raw.size(),
            blksize: bs as u32,
            blocks,
            atime: timespec(raw.time(0x8, 0x8c)),
            mtime: timespec(raw.time(0x10, 0x88)),
            ctime: timespec(raw.time(0xc, 0x84)),
        }
    }

    fn set_attr(&self, attr: &SetAttr) -> Result<()> {
        let mut tx = self.fs.tx()?;
        let mut raw = self.raw();
        if let Some(size) = attr.size {
            match kind_of(&raw) {
                FileType::Regular => {}
                FileType::Directory => return Err(Errno::EISDIR),
                _ => return Err(Errno::EINVAL),
            }
            if size.div_ceil(self.fs.sb.block_size) > u64::from(u32::MAX) {
                return Err(Errno::EFBIG);
            }
            let result = tx.truncate(self.ino, &mut raw, size);
            touch(&mut raw, true);
            tx.save(self, raw.clone())?;
            result?;
        }
        if let Some(m) = attr.mode {
            raw.set_mode(
                ((u32::from(raw.mode()) & !mode::PERM_MASK) | (m & mode::PERM_MASK)) as u16,
            );
        }
        if let Some(uid) = attr.uid {
            raw.set_uid(uid);
        }
        if let Some(gid) = attr.gid {
            raw.set_gid(gid);
        }
        if let Some(t) = attr.atime {
            raw.set_time(0x8, 0x8c, t.sec, t.nsec);
        }
        if let Some(t) = attr.mtime {
            raw.set_time(0x10, 0x88, t.sec, t.nsec);
        }
        touch(&mut raw, false);
        tx.save(self, raw)
    }

    fn set_atime(&self, time: Timespec) -> Result<()> {
        let mut tx = self.fs.tx()?;
        let mut raw = self.raw();
        raw.set_time(0x8, 0x8c, time.sec, time.nsec);
        tx.save(self, raw)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        match self.kind() {
            FileType::Regular => self.fs.read_data(&self.raw(), offset, buf),
            FileType::Directory => Err(Errno::EISDIR),
            _ => Err(Errno::EINVAL),
        }
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        match self.kind() {
            FileType::Regular => {}
            FileType::Directory => return Err(Errno::EISDIR),
            _ => return Err(Errno::EINVAL),
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let mut tx = self.fs.tx()?;
        let mut raw = self.raw();
        let result = tx.write_data(self.ino, &mut raw, offset, buf);
        tx.save(self, raw)?;
        result
    }

    fn attr_flags(&self) -> Result<u32> {
        Ok(self.raw().flags() & flags::USER_VISIBLE)
    }

    fn set_attr_flags(&self, new: u32) -> Result<()> {
        let mut tx = self.fs.tx()?;
        let mut raw = self.raw();
        let old = raw.flags();
        let changed = (old ^ new) & flags::USER_MODIFIABLE;
        // The driver has no names that ignore the case.
        if changed & flags::CASEFOLD != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        if changed & flags::EXTENTS != 0 {
            if !matches!(self.kind(), FileType::Regular | FileType::Directory) {
                return Err(Errno::EINVAL);
            }
            // As Linux, a disk without the `extents` feature has no extent trees.
            if new & flags::EXTENTS != 0 && self.fs.sb.incompat & layout::incompat::EXTENTS == 0 {
                return Err(Errno::EINVAL);
            }
            if new & flags::EXTENTS != 0 {
                tx.migrate_to_extents(self.ino, &mut raw)?;
            } else {
                Tx::migrate_to_block_map(&mut raw)?;
            }
        }
        raw.set_flags((old & !flags::USER_MODIFIABLE) | (new & flags::USER_MODIFIABLE));
        touch(&mut raw, false);
        tx.save(self, raw)
    }

    fn fiemap(&self, start: u64, len: u64) -> Result<Vec<FiemapExtent>> {
        let raw = self.raw();
        let bs = self.fs.sb.block_size;
        let end = start.saturating_add(len);
        let extents = if raw.flags() & flags::EXTENTS != 0 {
            self.fs.extents(&raw)?.0
        } else {
            self.fs.block_map(&raw)?.0
        };
        Ok(extents
            .iter()
            .filter(|e| u64::from(e.lblock) * bs < end && e.end() * bs > start)
            .map(|e| {
                // The first extent starts at `start`, as the iomap of Linux maps from there.
                let skip = (start / bs).saturating_sub(u64::from(e.lblock));
                FiemapExtent {
                    logical: (u64::from(e.lblock) + skip) * bs,
                    physical: (e.start + skip) * bs,
                    length: (u64::from(e.len) - skip) * bs,
                    unwritten: !e.init,
                }
            })
            .collect())
    }

    fn fallocate(&self, mode: u32, offset: u64, len: u64) -> Result<()> {
        if self.kind() != FileType::Regular {
            return Err(Errno::ENODEV);
        }
        let mut tx = self.fs.tx()?;
        let mut raw = self.raw();
        let result = tx.fallocate(self.ino, &mut raw, mode, offset, len);
        tx.save(self, raw)?;
        result
    }

    fn lookup(&self, name: &[u8]) -> Result<InodeRef> {
        if !self.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let slot = self.fs.find_entry(&self.raw(), name)?.ok_or(Errno::ENOENT)?;
        Ok(self.fs.inode(slot.ino)?)
    }

    fn create(&self, name: &[u8], kind: FileType, perm: u32, rdev: u64) -> Result<InodeRef> {
        let mut tx = self.fs.tx()?;
        self.check_new(name)?;
        if self.raw().links() >= LINK_MAX && kind == FileType::Directory {
            return Err(Errno::EMLINK);
        }
        let (ino, mut raw) = tx.new_inode(self.ino, kind, perm)?;
        match kind {
            FileType::Directory => {
                let block = self.fs.new_dir_block(ino, &raw, self.ino);
                let written = tx.write_data(ino, &mut raw, 0, &block);
                if written.is_err() {
                    raw.set_links(0);
                }
                self.fs.write_inode(ino, &mut raw)?;
                if let Err(e) = written {
                    drop(self.fs.new_node(ino, raw)?);
                    return Err(e);
                }
            }
            FileType::CharDevice | FileType::BlockDevice => {
                let (major, minor) = (rk_vfs::device::major(rdev), rk_vfs::device::minor(rdev));
                let b = raw.block_mut();
                if major < 256 && minor < 256 {
                    b[..4].copy_from_slice(&((major << 8) | minor).to_le_bytes());
                } else {
                    let new = (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12);
                    b[4..8].copy_from_slice(&new.to_le_bytes());
                }
                self.fs.write_inode(ino, &mut raw)?;
            }
            _ => {}
        }
        Ok(self.attach(&mut tx, name, ino, raw)?)
    }

    fn symlink(&self, name: &[u8], target: &[u8]) -> Result<InodeRef> {
        if target.is_empty() {
            return Err(Errno::ENOENT);
        }
        if target.len() >= self.fs.sb.block_size as usize {
            return Err(Errno::ENAMETOOLONG);
        }
        let mut tx = self.fs.tx()?;
        self.check_new(name)?;
        let (ino, mut raw) = tx.new_inode(self.ino, FileType::Symlink, 0o777)?;
        if target.len() < 60 {
            raw.set_flags(0);
            let b = raw.block_mut();
            b.fill(0);
            b[..target.len()].copy_from_slice(target);
            raw.set_size(target.len() as u64);
            self.fs.write_inode(ino, &mut raw)?;
        } else {
            let written = tx.write_data(ino, &mut raw, 0, target);
            if written.is_err() {
                raw.set_links(0);
            }
            self.fs.write_inode(ino, &mut raw)?;
            if let Err(e) = written {
                drop(self.fs.new_node(ino, raw)?);
                return Err(e);
            }
        }
        Ok(self.attach(&mut tx, name, ino, raw)?)
    }

    fn link(&self, name: &[u8], inode: &InodeRef) -> Result<()> {
        let target = self.same_fs(inode)?;
        let mut tx = self.fs.tx()?;
        self.check_new(name)?;
        if target.is_dir() {
            return Err(Errno::EPERM);
        }
        let links = target.raw().links();
        if links == 0 {
            return Err(Errno::ENOENT);
        }
        if links >= LINK_MAX {
            return Err(Errno::EMLINK);
        }
        tx.add_entry(self, name, target.ino, target.kind())?;
        target.add_links(&mut tx, 1)?;
        self.touch_dir(&mut tx)
    }

    fn unlink(&self, name: &[u8]) -> Result<()> {
        let mut tx = self.fs.tx()?;
        if !self.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let slot = self.fs.find_entry(&self.raw(), name)?.ok_or(Errno::ENOENT)?;
        let node = self.fs.inode(slot.ino)?;
        if node.is_dir() {
            return Err(Errno::EISDIR);
        }
        tx.remove_entry(self, name)?;
        self.touch_dir(&mut tx)?;
        node.add_links(&mut tx, -1)
    }

    fn rmdir(&self, name: &[u8]) -> Result<()> {
        let mut tx = self.fs.tx()?;
        if !self.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        if name == b"." {
            return Err(Errno::EINVAL);
        }
        if name == b".." {
            return Err(Errno::ENOTEMPTY);
        }
        let slot = self.fs.find_entry(&self.raw(), name)?.ok_or(Errno::ENOENT)?;
        let node = self.fs.inode(slot.ino)?;
        if !node.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        if !self.fs.is_empty_dir(&node.raw())? {
            return Err(Errno::ENOTEMPTY);
        }
        tx.remove_entry(self, name)?;
        let mut raw = node.raw();
        raw.set_links(0);
        touch(&mut raw, false);
        tx.save(&node, raw)?;
        self.add_links(&mut tx, -1)?;
        self.touch_dir(&mut tx)
    }

    fn rename(&self, old: &[u8], new_dir: &InodeRef, new: &[u8]) -> Result<()> {
        let to = self.same_fs(new_dir)?;
        let mut tx = self.fs.tx()?;
        if !self.is_dir() || !to.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        if new.len() > NAME_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        let slot = self.fs.find_entry(&self.raw(), old)?.ok_or(Errno::ENOENT)?;
        let node = self.fs.inode(slot.ino)?;
        let moving_dir = node.is_dir();
        let moves = self.ino != to.ino;
        if let Some(there) = self.fs.find_entry(&to.raw(), new)? {
            if there.ino == slot.ino {
                return Ok(());
            }
            let victim = self.fs.inode(there.ino)?;
            if victim.is_dir() {
                if !moving_dir {
                    return Err(Errno::EISDIR);
                }
                if !self.fs.is_empty_dir(&victim.raw())? {
                    return Err(Errno::ENOTEMPTY);
                }
            } else if moving_dir {
                return Err(Errno::ENOTDIR);
            }
            tx.remove_entry(to, new)?;
            if victim.is_dir() {
                let mut raw = victim.raw();
                raw.set_links(0);
                touch(&mut raw, false);
                tx.save(&victim, raw)?;
                to.add_links(&mut tx, -1)?;
            } else {
                victim.add_links(&mut tx, -1)?;
            }
        } else if moving_dir && moves && to.raw().links() >= LINK_MAX {
            return Err(Errno::EMLINK);
        }
        tx.add_entry(to, new, node.ino, node.kind())?;
        tx.remove_entry(self, old)?;
        if moving_dir && moves {
            tx.set_parent(&node, to.ino)?;
            self.add_links(&mut tx, -1)?;
            to.add_links(&mut tx, 1)?;
        }
        let mut raw = node.raw();
        touch(&mut raw, false);
        tx.save(&node, raw)?;
        self.touch_dir(&mut tx)?;
        if moves {
            to.touch_dir(&mut tx)?;
        }
        Ok(())
    }

    fn read_link(&self) -> Result<Vec<u8>> {
        let raw = self.raw();
        if kind_of(&raw) != FileType::Symlink {
            return Err(Errno::EINVAL);
        }
        let size = usize::try_from(raw.size()).map_err(|_| Errno::EUCLEAN)?;
        // A short target is in `i_block`, and the inode has no block.
        if fast_symlink(&raw) {
            return Ok(raw.block()[..size].to_vec());
        }
        if size > self.fs.sb.block_size as usize {
            return Err(Errno::EUCLEAN);
        }
        let mut target = vec![0u8; size];
        let n = self.fs.read_data(&raw, 0, &mut target)?;
        target.truncate(n);
        Ok(target)
    }

    fn read_dir(&self, pos: u64) -> Result<Option<(DirEntry, u64)>> {
        if !self.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        self.fs.entry_at(&self.raw(), pos)
    }

    fn get_xattr(&self, name: &[u8]) -> Result<Vec<u8>> {
        let key = xattr::key(name)?;
        let value = self.fs.xattrs(&self.raw())?.remove(&key).ok_or(Errno::ENODATA)?;
        if xattr::is_acl(&key) { xattr::acl_from_disk(&value) } else { Ok(value) }
    }

    fn set_xattr(&self, name: &[u8], value: &[u8], flags: u32) -> Result<()> {
        let key = xattr::key(name)?;
        let mut tx = self.fs.tx()?;
        let mut raw = self.raw();
        let mut attrs = self.fs.xattrs(&raw)?;
        let old = attrs.contains_key(&key);
        if flags & XATTR_CREATE != 0 && old {
            return Err(Errno::EEXIST);
        }
        if flags & XATTR_REPLACE != 0 && !old {
            return Err(Errno::ENODATA);
        }
        let value = if xattr::is_acl(&key) { xattr::acl_to_disk(value)? } else { value.to_vec() };
        attrs.insert(key, value);
        tx.write_xattrs(self.ino, &mut raw, &attrs)?;
        touch(&mut raw, false);
        tx.save(self, raw)
    }

    fn list_xattr(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.fs.xattrs(&self.raw())?.keys().filter_map(xattr::name).collect())
    }

    fn remove_xattr(&self, name: &[u8]) -> Result<()> {
        let key = xattr::key(name)?;
        let mut tx = self.fs.tx()?;
        let mut raw = self.raw();
        let mut attrs = self.fs.xattrs(&raw)?;
        attrs.remove(&key).ok_or(Errno::ENODATA)?;
        tx.write_xattrs(self.ino, &mut raw, &attrs)?;
        touch(&mut raw, false);
        tx.save(self, raw)
    }

    fn fs_id(&self) -> u64 {
        self.fs.dev
    }

    fn fs_magic(&self) -> u64 {
        EXT4_MAGIC
    }

    fn fs_stat(&self) -> Option<rk_vfs::inode::FsStat> {
        Some(self.fs.stat())
    }
}

//! The extent trees. A change reads the extents of the file into a list, changes the list, and
//! builds the tree again. The new tree uses the blocks of the old tree first.

use crate::layout::{EXTENT_INIT_MAX, EXTENT_MAGIC, RawInode, put16, put32, u16_at, u32_at};
use crate::{Fs, Tx, crc};
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::Result;

/// The deepest extent tree, as `EXT4_MAX_EXTENT_DEPTH` of Linux.
pub(crate) const MAX_DEPTH: u16 = 5;
/// The number of entries in the root of the tree, in `i_block`.
const ROOT_ENTRIES: usize = 4;

/// A run of blocks of a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Extent {
    /// The first block of the file.
    pub lblock: u32,
    /// The number of blocks.
    pub len: u32,
    /// The first block of the disk.
    pub start: u64,
    /// The blocks have data. An extent that is not initialized reads as zeros.
    pub init: bool,
}

impl Extent {
    pub(crate) fn end(&self) -> u64 {
        u64::from(self.lblock) + u64::from(self.len)
    }

    fn max_len(init: bool) -> u32 {
        if init { u32::from(EXTENT_INIT_MAX) } else { u32::from(EXTENT_INIT_MAX) - 1 }
    }
}

/// Writes the header of a node of the tree.
fn header(node: &mut [u8], entries: usize, max: usize, depth: u16) {
    put16(node, 0, EXTENT_MAGIC);
    put16(node, 2, entries as u16);
    put16(node, 4, max as u16);
    put16(node, 6, depth);
    put32(node, 8, 0);
}

impl Fs {
    /// Reads the extents of the file into a list, and the blocks of its tree.
    pub(crate) fn extents(&self, raw: &RawInode) -> Result<(Vec<Extent>, Vec<u64>)> {
        let mut extents = Vec::new();
        let mut tree = Vec::new();
        self.walk(raw.block(), MAX_DEPTH + 1, &mut extents, &mut tree)?;
        Ok((extents, tree))
    }

    fn walk(
        &self,
        node: &[u8],
        left: u16,
        extents: &mut Vec<Extent>,
        tree: &mut Vec<u64>,
    ) -> Result<()> {
        if left == 0 || node.len() < 12 || u16_at(node, 0) != EXTENT_MAGIC {
            return Err(Errno::EUCLEAN);
        }
        let entries = usize::from(u16_at(node, 2));
        if 12 + entries * 12 > node.len() {
            return Err(Errno::EUCLEAN);
        }
        for i in 0..entries {
            let e = &node[12 + i * 12..24 + i * 12];
            if u16_at(node, 6) == 0 {
                let raw_len = u16_at(e, 4);
                let (len, init) = if raw_len > EXTENT_INIT_MAX {
                    (raw_len - EXTENT_INIT_MAX, false)
                } else {
                    (raw_len, true)
                };
                let start = u64::from(u16_at(e, 6)) << 32 | u64::from(u32_at(e, 8));
                extents.push(Extent { lblock: u32_at(e, 0), len: u32::from(len), start, init });
            } else {
                let leaf = u64::from(u32_at(e, 4)) | u64::from(u16_at(e, 8)) << 32;
                tree.push(leaf);
                let child = self.read_block(leaf)?;
                self.walk(&child, left - 1, extents, tree)?;
            }
        }
        Ok(())
    }
}

/// Finds the extent that has the block `lblock`.
pub(crate) fn find(extents: &[Extent], lblock: u64) -> Option<&Extent> {
    extents.iter().find(|e| u64::from(e.lblock) <= lblock && lblock < e.end())
}

/// Maps the blocks of `new` in the list. The blocks of the list that `new` covers leave the
/// list, and the caller frees them if it must. The extents that touch join.
pub(crate) fn put(extents: &mut Vec<Extent>, new: Extent) {
    let mut out = Vec::with_capacity(extents.len() + 2);
    for &e in extents.iter() {
        if e.end() <= u64::from(new.lblock) || u64::from(e.lblock) >= new.end() {
            out.push(e);
            continue;
        }
        if e.lblock < new.lblock {
            out.push(Extent { len: new.lblock - e.lblock, ..e });
        }
        if e.end() > new.end() {
            let skip = (new.end() - u64::from(e.lblock)) as u32;
            out.push(Extent {
                lblock: e.lblock + skip,
                len: e.len - skip,
                start: e.start + u64::from(skip),
                init: e.init,
            });
        }
    }
    out.push(new);
    out.sort_by_key(|e| e.lblock);
    extents.clear();
    for e in out {
        if let Some(last) = extents.last_mut()
            && last.end() == u64::from(e.lblock)
            && last.start + u64::from(last.len) == e.start
            && last.init == e.init
            && last.len + e.len <= Extent::max_len(e.init)
        {
            last.len += e.len;
            continue;
        }
        extents.push(e);
    }
}

/// Removes the blocks from `lblock` to the end of the file from the list. Gives the runs of
/// blocks of the disk that left the list.
pub(crate) fn cut(extents: &mut Vec<Extent>, lblock: u64) -> Vec<(u64, u64)> {
    remove(extents, lblock, u64::MAX)
}

/// Removes the blocks `first..last` of the file from the list. An extent that has blocks on
/// each side of the range becomes two extents. Gives the runs of blocks of the disk that left
/// the list.
pub(crate) fn remove(extents: &mut Vec<Extent>, first: u64, last: u64) -> Vec<(u64, u64)> {
    let mut freed = Vec::new();
    let mut out = Vec::with_capacity(extents.len() + 1);
    for &e in extents.iter() {
        let (from, to) = (u64::from(e.lblock).max(first), e.end().min(last));
        if from >= to {
            out.push(e);
            continue;
        }
        let skip = from - u64::from(e.lblock);
        freed.push((e.start + skip, to - from));
        if skip > 0 {
            out.push(Extent { len: skip as u32, ..e });
        }
        if e.end() > to {
            let keep = to - u64::from(e.lblock);
            out.push(Extent {
                lblock: (u64::from(e.lblock) + keep) as u32,
                len: (e.end() - to) as u32,
                start: e.start + keep,
                init: e.init,
            });
        }
    }
    *extents = out;
    freed
}

/// Moves the blocks from `lblock` to the end of the file by `by` blocks, for
/// `FALLOC_FL_COLLAPSE_RANGE` and `FALLOC_FL_INSERT_RANGE`. An extent that has blocks on each
/// side of `lblock` becomes two extents first. The caller makes sure that no extent moves below
/// block 0 or onto another extent, and that the last block stays below 2^32.
pub(crate) fn shift(extents: &[Extent], lblock: u64, by: i64) -> Vec<Extent> {
    let mut out = Vec::with_capacity(extents.len() + 1);
    for &e in extents.iter() {
        if u64::from(e.lblock) < lblock && lblock < e.end() {
            let keep = (lblock - u64::from(e.lblock)) as u32;
            out.push(Extent { len: keep, ..e });
            out.push(Extent {
                lblock: e.lblock + keep,
                len: e.len - keep,
                start: e.start + u64::from(keep),
                init: e.init,
            });
        } else {
            out.push(e);
        }
    }
    for e in &mut out {
        if u64::from(e.lblock) >= lblock {
            e.lblock = (i64::from(e.lblock) + by) as u32;
        }
    }
    out
}

impl Tx<'_> {
    /// Builds the extent tree of the inode `ino` from `extents`. `old` has the blocks of the old
    /// tree. The count of blocks of the inode changes with the count of blocks of the tree.
    pub(crate) fn build_tree(
        &mut self,
        ino: u32,
        raw: &mut RawInode,
        extents: &[Extent],
        old: Vec<u64>,
    ) -> Result<()> {
        let fs = self.fs;
        let bs = fs.sb.block_size as usize;
        let per = (bs - 12) / 12;
        let mut entries: Vec<(u32, [u8; 12])> = Vec::with_capacity(extents.len());
        for e in extents {
            let mut b = [0u8; 12];
            put32(&mut b, 0, e.lblock);
            put16(
                &mut b,
                4,
                if e.init { e.len as u16 } else { (e.len + u32::from(EXTENT_INIT_MAX)) as u16 },
            );
            put16(&mut b, 6, (e.start >> 32) as u16);
            put32(&mut b, 8, e.start as u32);
            entries.push((e.lblock, b));
        }
        let mut need = 0;
        let mut n = entries.len();
        while n > ROOT_ENTRIES {
            n = n.div_ceil(per);
            need += n;
        }
        let had = old.len() as u64;
        let mut pool = old;
        let goal = extents.first().map_or(0, |e| e.start.saturating_sub(1));
        while pool.len() < need {
            let (b, _) = self.alloc_blocks(goal, 1)?;
            pool.push(b);
        }
        let spare = pool.split_off(need);
        for &b in &spare {
            self.free_blocks(b, 1)?;
        }
        let seed = fs.inode_seed(ino, raw);
        let mut depth = 0;
        let mut blocks = pool.into_iter();
        while entries.len() > ROOT_ENTRIES {
            let mut up = Vec::new();
            for chunk in entries.chunks(per) {
                let block = blocks.next().ok_or(Errno::EIO)?;
                let mut node = vec![0u8; bs];
                header(&mut node, chunk.len(), per, depth);
                for (i, (_, e)) in chunk.iter().enumerate() {
                    node[12 + i * 12..24 + i * 12].copy_from_slice(e);
                }
                if fs.metadata_csum() {
                    let tail = 12 + per * 12;
                    let csum = crc::crc32c(seed, &node[..tail]);
                    put32(&mut node, tail, csum);
                }
                fs.write(block * bs as u64, &node)?;
                let mut index = [0u8; 12];
                put32(&mut index, 0, chunk[0].0);
                put32(&mut index, 4, block as u32);
                put16(&mut index, 8, (block >> 32) as u16);
                up.push((chunk[0].0, index));
            }
            entries = up;
            depth += 1;
        }
        let root = raw.block_mut();
        root.fill(0);
        header(root, entries.len(), ROOT_ENTRIES, depth);
        for (i, (_, e)) in entries.iter().enumerate() {
            root[12 + i * 12..24 + i * 12].copy_from_slice(e);
        }
        // i_blocks counts the old tree blocks already, so only the difference changes it.
        let sectors = fs.sb.block_size / 512;
        let blocks = raw.blocks() + need as u64 * sectors;
        raw.set_blocks(blocks.saturating_sub(had * sectors));
        Ok(())
    }

    /// Makes an empty extent tree in `i_block`.
    pub(crate) fn empty_tree(raw: &mut RawInode) {
        let root = raw.block_mut();
        root.fill(0);
        header(root, 0, ROOT_ENTRIES, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(lblock: u32, len: u32, start: u64) -> Extent {
        Extent { lblock, len, start, init: true }
    }

    #[test]
    fn put_joins_and_splits() {
        let mut list = vec![ext(0, 4, 100)];
        put(&mut list, ext(4, 2, 104));
        assert_eq!(list, [ext(0, 6, 100)]);
        put(&mut list, Extent { lblock: 2, len: 1, start: 102, init: false });
        assert_eq!(
            list,
            [ext(0, 2, 100), Extent { lblock: 2, len: 1, start: 102, init: false }, ext(3, 3, 103)]
        );
        put(&mut list, ext(2, 1, 102));
        assert_eq!(list, [ext(0, 6, 100)]);
        put(&mut list, ext(10, 1, 500));
        assert_eq!(list, [ext(0, 6, 100), ext(10, 1, 500)]);
    }

    #[test]
    fn remove_splits_an_extent() {
        let mut list = vec![ext(0, 10, 100), ext(20, 5, 200)];
        assert_eq!(remove(&mut list, 3, 22), [(103, 7), (200, 2)]);
        assert_eq!(list, [ext(0, 3, 100), ext(22, 3, 202)]);
        assert_eq!(remove(&mut list, 1, 2), [(101, 1)]);
        assert_eq!(list, [ext(0, 1, 100), ext(2, 1, 102), ext(22, 3, 202)]);
        assert!(remove(&mut list, 5, 20).is_empty());
    }

    #[test]
    fn cut_frees_the_end() {
        let mut list = vec![ext(0, 6, 100), ext(10, 2, 500)];
        assert_eq!(cut(&mut list, 4), [(104, 2), (500, 2)]);
        assert_eq!(list, [ext(0, 4, 100)]);
        assert_eq!(cut(&mut list, 0), [(100, 4)]);
        assert!(list.is_empty());
    }
}

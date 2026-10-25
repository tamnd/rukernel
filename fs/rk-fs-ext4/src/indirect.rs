//! The changes of the block map of ext2 and ext3: 12 direct blocks, then a single, a double and
//! a triple indirect block. A disk without the `extents` feature keeps all its files in a map.

use crate::Tx;
use crate::layout::{RawInode, put32, u32_at};
use rk_abi::Errno;
use rk_vfs::Result;

/// Gives the entry of `i_block` for the block `lblock` of a file, and the indexes in the
/// indirect blocks under it, the first index first. Gives `EFBIG` past the triple indirect block.
fn path(per: u64, lblock: u64) -> Result<(usize, [u64; 3], usize)> {
    if lblock < 12 {
        return Ok((lblock as usize, [0; 3], 0));
    }
    let mut l = lblock - 12;
    if l < per {
        return Ok((12, [l, 0, 0], 1));
    }
    l -= per;
    if l < per * per {
        return Ok((13, [l / per, l % per, 0], 2));
    }
    l -= per * per;
    if l < per * per * per {
        return Ok((14, [l / (per * per), l / per % per, l % per], 3));
    }
    Err(Errno::EFBIG)
}

impl Tx<'_> {
    /// Gives a new indirect block near `goal`, filled with zeros. The count of blocks of the
    /// inode grows by one block.
    fn new_indirect(&mut self, raw: &mut RawInode, goal: u64) -> Result<u32> {
        let fs = self.fs;
        let (block, _) = self.alloc_blocks(goal, 1)?;
        let Ok(entry) = u32::try_from(block) else {
            self.free_blocks(block, 1)?;
            return Err(Errno::EFBIG);
        };
        fs.write(block * fs.sb.block_size, &alloc::vec![0u8; fs.sb.block_size as usize])?;
        raw.set_blocks(raw.blocks() + fs.sb.block_size / 512);
        Ok(entry)
    }

    /// Finds the block of the map that has the entry of `lblock`, and makes the indirect blocks
    /// on the way that are not there yet, near `goal`. Gives the block, or `None` for `i_block`,
    /// the index of the entry in it, and the count of entries from that index to its end.
    fn leaf(
        &mut self,
        raw: &mut RawInode,
        lblock: u64,
        goal: u64,
    ) -> Result<(Option<u64>, usize, u64)> {
        let fs = self.fs;
        let per = fs.sb.block_size / 4;
        let (slot, index, levels) = path(per, lblock)?;
        if levels == 0 {
            return Ok((None, slot, 12 - slot as u64));
        }
        let mut block = u32_at(raw.block(), slot * 4);
        if block == 0 {
            block = self.new_indirect(raw, goal)?;
            put32(raw.block_mut(), slot * 4, block);
        }
        for &i in &index[..levels - 1] {
            let mut data = fs.read_block(u64::from(block))?;
            let mut next = u32_at(&data, i as usize * 4);
            if next == 0 {
                next = self.new_indirect(raw, goal)?;
                put32(&mut data, i as usize * 4, next);
                fs.write(u64::from(block) * fs.sb.block_size, &data)?;
            }
            block = next;
        }
        let last = index[levels - 1];
        Ok((Some(u64::from(block)), last as usize, per - last))
    }

    /// Maps the blocks `lblock..lblock + count` of the file to the blocks of the disk from
    /// `start`. The entries must be holes. Each block of the map changes once.
    pub(crate) fn map_blocks(
        &mut self,
        raw: &mut RawInode,
        lblock: u64,
        start: u64,
        count: u64,
    ) -> Result<()> {
        let fs = self.fs;
        if start + count > u64::from(u32::MAX) + 1 {
            return Err(Errno::EFBIG);
        }
        let mut done = 0;
        while done < count {
            let (leaf, at, room) = self.leaf(raw, lblock + done, start + done)?;
            let n = room.min(count - done);
            let put = |entries: &mut [u8]| {
                for i in 0..n {
                    put32(entries, (at + i as usize) * 4, (start + done + i) as u32);
                }
            };
            match leaf {
                None => put(raw.block_mut()),
                Some(block) => {
                    let mut data = fs.read_block(block)?;
                    put(&mut data);
                    fs.write(block * fs.sb.block_size, &data)?;
                }
            }
            done += n;
        }
        Ok(())
    }

    /// Frees the blocks of the map from the block `last` of the file to the end, and the
    /// indirect blocks that then map nothing, as `ext4_ind_truncate`. Gives the count of blocks
    /// that it freed.
    pub(crate) fn cut_map(&mut self, raw: &mut RawInode, last: u64) -> Result<u64> {
        let per = self.fs.sb.block_size / 4;
        let mut freed = 0;
        let mut lblock = 0;
        // The entries 0 to 11 map data blocks, 12 to 14 map indirect blocks of the levels 1 to 3.
        for slot in 0..15usize {
            let level = slot.saturating_sub(11) as u32;
            let span = per.pow(level);
            let entry = u64::from(u32_at(raw.block(), slot * 4));
            if lblock >= last {
                freed += self.free_map(entry, level)?;
                put32(raw.block_mut(), slot * 4, 0);
            } else if level > 0 && lblock + span > last && entry != 0 {
                freed += self.cut_indirect(entry, level, lblock, last)?;
            }
            lblock += span;
        }
        Ok(freed)
    }

    /// Frees the blocks under the indirect block `block` of the level `level` that map from the
    /// block `last` of the file on. `lblock` is the first block of the file that `block` maps.
    fn cut_indirect(&mut self, block: u64, level: u32, lblock: u64, last: u64) -> Result<u64> {
        let fs = self.fs;
        let span = (fs.sb.block_size / 4).pow(level - 1);
        let mut data = fs.read_block(block)?;
        let mut freed = 0;
        let mut changed = false;
        for i in 0..data.len() / 4 {
            let first = lblock + i as u64 * span;
            let entry = u64::from(u32_at(&data, i * 4));
            if entry == 0 || first + span <= last {
                continue;
            }
            if first >= last {
                freed += self.free_map(entry, level - 1)?;
                put32(&mut data, i * 4, 0);
                changed = true;
            } else {
                freed += self.cut_indirect(entry, level - 1, first, last)?;
            }
        }
        if changed {
            fs.write(block * fs.sb.block_size, &data)?;
        }
        Ok(freed)
    }

    /// Frees the block `block` of a block map, and the blocks under it for an indirect block of
    /// the level `level`. Gives the count of blocks that it freed.
    pub(crate) fn free_map(&mut self, block: u64, level: u32) -> Result<u64> {
        if block == 0 {
            return Ok(0);
        }
        let mut freed = 1;
        if level > 0 {
            let data = self.fs.read_block(block)?;
            for i in 0..data.len() / 4 {
                freed += self.free_map(u64::from(u32_at(&data, i * 4)), level - 1)?;
            }
        }
        self.free_blocks(block, 1)?;
        Ok(freed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_finds_the_level_of_each_block() {
        assert_eq!(path(256, 11).unwrap(), (11, [0; 3], 0));
        assert_eq!(path(256, 12).unwrap(), (12, [0, 0, 0], 1));
        assert_eq!(path(256, 267).unwrap(), (12, [255, 0, 0], 1));
        assert_eq!(path(256, 268).unwrap(), (13, [0, 0, 0], 2));
        assert_eq!(path(256, 268 + 256 + 3).unwrap(), (13, [1, 3, 0], 2));
        let triple = 12 + 256 + 256 * 256;
        assert_eq!(path(256, triple).unwrap(), (14, [0, 0, 0], 3));
        assert_eq!(path(256, triple + 256 * 256 + 257).unwrap(), (14, [1, 1, 1], 3));
        assert_eq!(path(256, triple + 256 * 256 * 256), Err(Errno::EFBIG));
    }
}

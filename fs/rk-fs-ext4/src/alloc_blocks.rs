//! The allocation of blocks and inodes: the bitmaps, the counts of the group descriptors and of
//! the superblock, and their checksums.

use crate::extent::Extent;
use crate::layout::{self, bg, gd, put16, put32, u16_at, u32_at};
use crate::{Tx, crc};
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::Result;

/// Sets the bits from `from` to the end of `bitmap`, as `ext4_mark_bitmap_end`.
pub(crate) fn mark_end(bitmap: &mut [u8], from: usize) {
    for bit in from..bitmap.len() * 8 {
        bitmap[bit / 8] |= 1 << (bit % 8);
    }
}

pub(crate) fn test_bit(bitmap: &[u8], bit: usize) -> bool {
    bitmap[bit / 8] & (1 << (bit % 8)) != 0
}

pub(crate) fn set_bit(bitmap: &mut [u8], bit: usize, on: bool) {
    if on {
        bitmap[bit / 8] |= 1 << (bit % 8);
    } else {
        bitmap[bit / 8] &= !(1 << (bit % 8));
    }
}

impl Tx<'_> {
    /// Gives the field `at` of the descriptor of the group `group`, with its high half.
    pub(crate) fn desc_get(&self, group: u32, at: usize) -> u32 {
        let d = &self.meta.descs[group as usize];
        let hi = if d.len() >= 64 { u32::from(u16_at(d, at + gd::HI)) << 16 } else { 0 };
        u32::from(u16_at(d, at)) | hi
    }

    /// Changes the field `at` of the descriptor of the group `group`, with its high half.
    pub(crate) fn desc_set(&mut self, group: u32, at: usize, v: u32) {
        let d = &mut self.meta.descs[group as usize];
        put16(d, at, v as u16);
        if d.len() >= 64 {
            put16(d, at + gd::HI, (v >> 16) as u16);
        }
    }

    fn desc_flags(&self, group: u32) -> u16 {
        u16_at(&self.meta.descs[group as usize], gd::FLAGS)
    }

    fn set_desc_flags(&mut self, group: u32, flags: u16) {
        put16(&mut self.meta.descs[group as usize], gd::FLAGS, flags);
    }

    /// Writes the descriptor of the group `group`, with its checksum.
    pub(crate) fn write_desc(&mut self, group: u32) -> Result<()> {
        let fs = self.fs;
        let size = usize::from(fs.sb.desc_size);
        let d = &mut self.meta.descs[group as usize];
        let le = group.to_le_bytes();
        if fs.metadata_csum() {
            put16(d, gd::CHECKSUM, 0);
            let csum = crc::crc32c(crc::crc32c(fs.csum_seed, &le), d);
            put16(d, gd::CHECKSUM, csum as u16);
        } else if fs.sb.ro_compat & layout::ro_compat::GDT_CSUM != 0 {
            let mut crc = crc::crc16(crc::crc16(!0, &fs.sb.uuid), &le);
            crc = crc::crc16(crc, &d[..gd::CHECKSUM]);
            if fs.sb.incompat & layout::incompat::BIT64 != 0 && size > gd::CHECKSUM + 2 {
                crc = crc::crc16(crc, &d[gd::CHECKSUM + 2..size]);
            }
            put16(d, gd::CHECKSUM, crc);
        }
        let per_block = fs.sb.descs_per_block();
        let at = fs.sb.desc_block(u64::from(group) / per_block) * fs.sb.block_size
            + (u64::from(group) % per_block) * size as u64;
        fs.write(at, &self.meta.descs[group as usize])
    }

    /// Adds `delta` to the free blocks and `inodes` to the free inodes of the superblock, and
    /// writes the superblock with its checksum.
    pub(crate) fn write_sb(&mut self, blocks: i64, inodes: i64) -> Result<()> {
        let fs = self.fs;
        let b = &mut self.meta.sb;
        let bit64 = fs.sb.incompat & layout::incompat::BIT64 != 0;
        let mut free = u64::from(u32_at(b, layout::sb::FREE_BLOCKS));
        if bit64 {
            free |= u64::from(u32_at(b, layout::sb::FREE_BLOCKS_HI)) << 32;
        }
        let free = free.saturating_add_signed(blocks);
        put32(b, layout::sb::FREE_BLOCKS, free as u32);
        if bit64 {
            put32(b, layout::sb::FREE_BLOCKS_HI, (free >> 32) as u32);
        }
        let free = u32_at(b, layout::sb::FREE_INODES).saturating_add_signed(inodes as i32);
        put32(b, layout::sb::FREE_INODES, free);
        if fs.metadata_csum() {
            let csum = crc::crc32c(!0, &b[..layout::sb::CHECKSUM]);
            put32(b, layout::sb::CHECKSUM, csum);
        }
        fs.write(layout::SUPERBLOCK_AT, b)
    }

    /// Gives the block bitmap of the group `group`. A bitmap that is not on the disk is made from
    /// the layout, as `ext4_init_block_bitmap`. Each bit is one cluster.
    pub(crate) fn block_bitmap(&self, group: u32) -> Result<Vec<u8>> {
        self.fs.block_bitmap_of(group, self.desc_flags(group))
    }

    /// Gives the inode bitmap of the group `group`.
    fn inode_bitmap(&self, group: u32) -> Result<Vec<u8>> {
        let fs = self.fs;
        if self.desc_flags(group) & bg::INODE_UNINIT == 0 {
            return fs.read_block(fs.group(group)?.inode_bitmap);
        }
        let mut bitmap = vec![0u8; fs.sb.block_size as usize];
        mark_end(&mut bitmap, fs.sb.inodes_per_group as usize);
        Ok(bitmap)
    }

    /// Writes the block bitmap of the group `group` and sets its checksum in the descriptor.
    pub(crate) fn write_block_bitmap(&mut self, group: u32, bitmap: &[u8]) -> Result<()> {
        let fs = self.fs;
        fs.write(fs.group(group)?.block_bitmap * fs.sb.block_size, bitmap)?;
        let flags = self.desc_flags(group) & !bg::BLOCK_UNINIT;
        self.set_desc_flags(group, flags);
        if fs.metadata_csum() {
            let len = fs.sb.clusters_per_group as usize / 8;
            let csum = crc::crc32c(fs.csum_seed, &bitmap[..len]);
            self.desc_set(group, gd::BLOCK_BITMAP_CSUM, csum);
        }
        Ok(())
    }

    /// Writes the inode bitmap of the group `group` and sets its checksum in the descriptor.
    pub(crate) fn write_inode_bitmap(&mut self, group: u32, bitmap: &[u8]) -> Result<()> {
        let fs = self.fs;
        fs.write(fs.group(group)?.inode_bitmap * fs.sb.block_size, bitmap)?;
        let flags = self.desc_flags(group) & !bg::INODE_UNINIT;
        self.set_desc_flags(group, flags);
        if fs.metadata_csum() {
            let csum = crc::crc32c(fs.csum_seed, &bitmap[..fs.sb.inodes_per_group as usize / 8]);
            self.desc_set(group, gd::INODE_BITMAP_CSUM, csum);
        }
        Ok(())
    }

    /// Allocates up to `want` blocks in a row, at `goal` or after it if it can. Gives the first
    /// block and the number of blocks. With `bigalloc` it allocates whole clusters: the first
    /// block is the first block of a cluster, and the number of blocks is a number of clusters.
    /// The blocks that the delayed writes keep are not used.
    ///
    /// # Errors
    ///
    /// Gives `ENOSPC` if the file system has no free block.
    pub(crate) fn alloc_blocks(&mut self, goal: u64, want: u32) -> Result<(u64, u32)> {
        let kept = self.fs.kept_blocks();
        let want = if kept == 0 {
            want
        } else {
            let free = self.free_count();
            if free <= kept {
                return Err(Errno::ENOSPC);
            }
            want.min(u32::try_from(free - kept).unwrap_or(u32::MAX))
        };
        let sb = &self.fs.sb;
        let (first, bpg) = (u64::from(sb.first_data_block), u64::from(sb.blocks_per_group));
        let bits = sb.cluster_bits;
        let want = want.div_ceil(1 << bits).max(1);
        let goal = goal.clamp(first, self.fs.blocks_count() - 1);
        let groups = self.fs.group_count();
        let goal_group = ((goal - first) / bpg) as u32;
        for i in 0..=groups {
            let group = (goal_group + i) % groups;
            if self.desc_get(group, gd::FREE_BLOCKS) == 0 {
                continue;
            }
            let mut bitmap = self.block_bitmap(group)?;
            let size = self.fs.clusters_in_group(group) as usize;
            let from = if i == 0 { (((goal - first) % bpg) >> bits) as usize } else { 0 };
            let base = first + u64::from(group) * bpg;
            let free = |bitmap: &[u8], c: usize| {
                !test_bit(bitmap, c) && !self.fs.is_busy(base + ((c as u64) << bits))
            };
            let Some(bit) = (from..size).find(|&c| free(&bitmap, c)) else { continue };
            let mut got = 0;
            while got < want as usize && bit + got < size && free(&bitmap, bit + got) {
                set_bit(&mut bitmap, bit + got, true);
                got += 1;
            }
            self.write_block_bitmap(group, &bitmap)?;
            let free = self.desc_get(group, gd::FREE_BLOCKS).saturating_sub(got as u32);
            self.desc_set(group, gd::FREE_BLOCKS, free);
            self.write_desc(group)?;
            self.write_sb(-((got as i64) << bits), 0)?;
            return Ok((base + ((bit as u64) << bits), (got as u32) << bits));
        }
        Err(Errno::ENOSPC)
    }

    /// Allocates up to `want` blocks in a row as [`Tx::alloc_blocks`], but if the free run at
    /// `goal` is too short, it first looks for a free run of all `want` blocks after `goal`, as
    /// the mballoc of Linux does. So the blocks of `fallocate` are in one extent if the file
    /// system has such a run.
    ///
    /// # Errors
    ///
    /// Gives `ENOSPC` if the file system has no free block.
    pub(crate) fn alloc_run(&mut self, goal: u64, want: u32) -> Result<(u64, u32)> {
        let sb = &self.fs.sb;
        let (first, bpg) = (u64::from(sb.first_data_block), u64::from(sb.blocks_per_group));
        let goal = goal.clamp(first, self.fs.blocks_count() - 1);
        let groups = self.fs.group_count();
        let goal_group = ((goal - first) / bpg) as u32;
        for i in 0..groups {
            let group = (goal_group + i) % groups;
            let size = self.fs.blocks_in_group(group) as usize;
            let need = (want as usize).min(size);
            if (self.desc_get(group, gd::FREE_BLOCKS) as usize) < need {
                continue;
            }
            let bitmap = self.block_bitmap(group)?;
            let base = first + u64::from(group) * bpg;
            let free = |b: usize| !test_bit(&bitmap, b) && !self.fs.is_busy(base + b as u64);
            let from = if i == 0 { ((goal - first) % bpg) as usize } else { 0 };
            let mut run = 0;
            for b in from..size {
                run = if free(b) { run + 1 } else { 0 };
                if run == need {
                    return self.alloc_blocks(base + (b + 1 - run) as u64, want);
                }
            }
        }
        self.alloc_blocks(goal, want)
    }

    /// Frees `count` blocks from `start`. With `bigalloc` it frees each cluster that has one of
    /// the blocks.
    ///
    /// # Errors
    ///
    /// Gives the error of the disk, or `EUCLEAN` for a block outside the file system.
    pub(crate) fn free_blocks(&mut self, start: u64, count: u64) -> Result<()> {
        if count == 0 {
            return Ok(());
        }
        let sb = &self.fs.sb;
        let (first, bpg) = (u64::from(sb.first_data_block), u64::from(sb.blocks_per_group));
        let bits = sb.cluster_bits;
        if start < first || start + count > self.fs.blocks_count() {
            return Err(Errno::EUCLEAN);
        }
        // The range grows to whole clusters. A group has whole clusters.
        let ratio = sb.cluster_ratio();
        let end = first + (start + count - first).next_multiple_of(ratio);
        let mut start = first + (start - first) / ratio * ratio;
        let mut count = end - start;
        while count > 0 {
            let group = ((start - first) / bpg) as u32;
            let bit = ((start - first) % bpg) as usize;
            let n = count.min(bpg - bit as u64) as usize;
            let mut bitmap = self.block_bitmap(group)?;
            let mut freed = 0;
            for c in bit >> bits..(bit + n) >> bits {
                if test_bit(&bitmap, c) {
                    set_bit(&mut bitmap, c, false);
                    freed += 1;
                }
            }
            self.write_block_bitmap(group, &bitmap)?;
            let free = self.desc_get(group, gd::FREE_BLOCKS) + freed;
            self.desc_set(group, gd::FREE_BLOCKS, free);
            self.write_desc(group)?;
            self.write_sb(i64::from(freed) << bits, 0)?;
            self.fs.freed(start, n as u64);
            start += n as u64;
            count -= n as u64;
        }
        Ok(())
    }

    /// Gives blocks of the disk to the blocks from `lblock` of a file with the extents
    /// `extents`, up to `want` blocks, near `goal`. Gives the first block, the number of blocks
    /// and the number of sectors that the file gets for `i_blocks`.
    ///
    /// With `bigalloc` a cluster of the disk has the blocks of one cluster of the file, at the
    /// same places, as `ext4_ext_map_blocks` of Linux. If a block of the cluster of the file at
    /// `lblock` has a block of the disk, the blocks come from that cluster and nothing is
    /// allocated. Else the new clusters stop before the next cluster of the file that has blocks.
    ///
    /// # Errors
    ///
    /// Gives `ENOSPC` if the file system has no free block.
    pub(crate) fn alloc_data(
        &mut self,
        extents: &[Extent],
        lblock: u64,
        want: u32,
        goal: u64,
    ) -> Result<(u64, u32, u64)> {
        let fs = self.fs;
        let ratio = fs.sb.cluster_ratio();
        let sectors = fs.sb.block_size / 512;
        if ratio == 1 {
            let (start, got) = self.alloc_blocks(goal, want)?;
            return Ok((start, got, u64::from(got) * sectors));
        }
        let (first, offset) = (lblock / ratio * ratio, lblock % ratio);
        let left = (first + ratio - lblock) as u32;
        if let Some(e) =
            extents.iter().find(|e| u64::from(e.lblock) < first + ratio && e.end() > first)
        {
            let at = u64::from(e.lblock).max(first);
            let block = e.start + (at - u64::from(e.lblock));
            return Ok((block - block % ratio + offset, want.min(left), 0));
        }
        let mut want = u64::from(want);
        if let Some(next) = extents.iter().map(|e| u64::from(e.lblock)).find(|&l| l > lblock) {
            want = want.min(next / ratio * ratio - lblock);
        }
        let (start, got) = self.alloc_blocks(goal, (offset + want) as u32)?;
        let used = want.min(u64::from(got) - offset) as u32;
        Ok((start + offset, used, u64::from(got) * sectors))
    }

    /// Frees the runs `freed` of blocks of the disk that left a file, which now has the extents
    /// `kept`. Gives the number of sectors that the file loses from `i_blocks`. With `bigalloc` a
    /// cluster is freed only if no block of `kept` is in it, as the partial clusters of
    /// `ext4_ext_remove_space` of Linux.
    ///
    /// # Errors
    ///
    /// Gives the error of the disk.
    pub(crate) fn free_data(&mut self, kept: &[Extent], freed: &[(u64, u64)]) -> Result<u64> {
        let fs = self.fs;
        let ratio = fs.sb.cluster_ratio();
        let sectors = fs.sb.block_size / 512;
        if ratio == 1 {
            let mut count = 0;
            for &(start, n) in freed {
                self.free_blocks(start, n)?;
                count += n;
            }
            return Ok(count * sectors);
        }
        let in_use = |c: u64| {
            kept.iter().any(|e| e.start < (c + 1) * ratio && e.start + u64::from(e.len) > c * ratio)
        };
        let mut clusters: Vec<u64> = Vec::new();
        for &(start, n) in freed.iter().filter(|&&(_, n)| n > 0) {
            let (first, last) = (start / ratio, (start + n - 1) / ratio);
            clusters.extend((first..=last).filter(|&c| (c != first && c != last) || !in_use(c)));
        }
        clusters.sort_unstable();
        clusters.dedup();
        for &c in &clusters {
            self.free_blocks(c * ratio, ratio)?;
        }
        Ok(clusters.len() as u64 * ratio * sectors)
    }

    /// Allocates an inode, in the group of `near` if it can. `dir` tells if the inode is for a
    /// directory.
    ///
    /// # Errors
    ///
    /// Gives `ENOSPC` if the file system has no free inode.
    pub(crate) fn alloc_inode(&mut self, near: u32, dir: bool) -> Result<u32> {
        let sb = &self.fs.sb;
        let (groups, ipg, first_ino) = (self.fs.group_count(), sb.inodes_per_group, sb.first_ino);
        let csum =
            sb.ro_compat & (layout::ro_compat::GDT_CSUM | layout::ro_compat::METADATA_CSUM) != 0;
        let start = near.saturating_sub(1) / ipg;
        for i in 0..groups {
            let group = (start + i) % groups;
            if self.desc_get(group, gd::FREE_INODES) == 0 {
                continue;
            }
            let mut bitmap = self.inode_bitmap(group)?;
            let used = |b: usize| test_bit(&bitmap, b) || group * ipg + b as u32 + 1 < first_ino;
            let Some(bit) = (0..ipg as usize).find(|&b| !used(b)) else { continue };
            set_bit(&mut bitmap, bit, true);
            // A group with a block bitmap that is not on the disk gets it now, as Linux.
            if self.desc_flags(group) & bg::BLOCK_UNINIT != 0 {
                let blocks = self.block_bitmap(group)?;
                self.write_block_bitmap(group, &blocks)?;
            }
            self.write_inode_bitmap(group, &bitmap)?;
            let free = self.desc_get(group, gd::FREE_INODES).saturating_sub(1);
            self.desc_set(group, gd::FREE_INODES, free);
            if dir {
                let dirs = self.desc_get(group, gd::USED_DIRS) + 1;
                self.desc_set(group, gd::USED_DIRS, dirs);
            }
            if csum {
                let unused = self.desc_get(group, gd::ITABLE_UNUSED);
                if bit as u32 + 1 > ipg - unused {
                    self.desc_set(group, gd::ITABLE_UNUSED, ipg - bit as u32 - 1);
                }
            }
            self.write_desc(group)?;
            self.write_sb(0, -1)?;
            return Ok(group * ipg + bit as u32 + 1);
        }
        Err(Errno::ENOSPC)
    }

    /// Frees the inode `ino`. `dir` tells if the inode was a directory.
    ///
    /// # Errors
    ///
    /// Gives the error of the disk.
    pub(crate) fn free_inode(&mut self, ino: u32, dir: bool) -> Result<()> {
        let ipg = self.fs.sb.inodes_per_group;
        let (group, bit) = ((ino - 1) / ipg, ((ino - 1) % ipg) as usize);
        let mut bitmap = self.inode_bitmap(group)?;
        if !test_bit(&bitmap, bit) {
            return Err(Errno::EUCLEAN);
        }
        set_bit(&mut bitmap, bit, false);
        self.write_inode_bitmap(group, &bitmap)?;
        let free = self.desc_get(group, gd::FREE_INODES) + 1;
        self.desc_set(group, gd::FREE_INODES, free);
        if dir {
            let dirs = self.desc_get(group, gd::USED_DIRS).saturating_sub(1);
            self.desc_set(group, gd::USED_DIRS, dirs);
        }
        self.write_desc(group)?;
        self.write_sb(0, 1)
    }

    /// Tells if the bitmap has the inode `ino` in use.
    pub(crate) fn inode_in_use(&self, ino: u32) -> Result<bool> {
        let ipg = self.fs.sb.inodes_per_group;
        let bitmap = self.inode_bitmap((ino - 1) / ipg)?;
        Ok(test_bit(&bitmap, ((ino - 1) % ipg) as usize))
    }

    /// Takes a generation for a new inode.
    pub(crate) fn next_generation(&mut self) -> u32 {
        let g = self.meta.generation;
        self.meta.generation = g.wrapping_add(1);
        g
    }
}

impl crate::Fs {
    /// Gives the block bitmap of the group `group`, which has the flags `flags` in its
    /// descriptor. The caller holds the lock of the metadata. A bitmap that is not on the disk is
    /// made from the layout, as `ext4_init_block_bitmap`. Each bit is one cluster.
    pub(crate) fn block_bitmap_of(&self, group: u32, flags: u16) -> Result<Vec<u8>> {
        let desc = self.group(group)?;
        if flags & bg::BLOCK_UNINIT == 0 {
            return self.read_block(desc.block_bitmap);
        }
        let sb = &self.sb;
        let mut bitmap = vec![0u8; sb.block_size as usize];
        let start = sb.group_start(group);
        // The group 0 can start before the superblock, with `bigalloc` and blocks of 1 KiB.
        let lead = if group == 0 { sb.sb_block().saturating_sub(start) } else { 0 };
        for bit in 0..lead + sb.base_meta_blocks(group) {
            set_bit(&mut bitmap, (bit >> sb.cluster_bits) as usize, true);
        }
        let end = start + u64::from(self.blocks_in_group(group));
        let own = [
            (desc.block_bitmap, 1),
            (desc.inode_bitmap, 1),
            (desc.inode_table, sb.itable_blocks()),
        ];
        for (first, count) in own {
            for b in (first..first + count).filter(|b| (start..end).contains(b)) {
                set_bit(&mut bitmap, ((b - start) >> sb.cluster_bits) as usize, true);
            }
        }
        mark_end(&mut bitmap, self.clusters_in_group(group) as usize);
        Ok(bitmap)
    }
}

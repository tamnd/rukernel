//! The online resize of a mounted file system, as `EXT4_IOC_RESIZE_FS` of Linux. A resize makes
//! the last group longer and adds new groups at the end. When the new descriptors need more
//! blocks, the reserved descriptor blocks become descriptor blocks, as `add_new_gdb`. When no
//! reserved block is left, the file system changes to `meta_bg`, as `ext4_convert_meta_bg`, and
//! each new meta block group keeps its descriptor block in its first group.

use crate::alloc_blocks::{mark_end, set_bit};
use crate::layout::{
    self, GroupDesc, Superblock, bg, compat, gd, incompat, put16, put32, ro_compat, u32_at,
};
use crate::{Fs, Tx, crc};
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use rk_abi::Errno;
use rk_vfs::Result;

/// The number of blocks of zeros in one write to a new inode table.
const ZERO_CHUNK: u64 = 64;

/// The free blocks that a new last group must have after its metadata, as Linux. A shorter last
/// group is left out.
const MIN_DATA: u64 = 50;

/// The index of the doubly indirect block in `i_block`, `EXT4_DIND_BLOCK`. The resize inode
/// keeps the reserved descriptor blocks in it.
const DIND: usize = 13;

impl Fs {
    /// Grows the file system to `count` blocks, for `EXT4_IOC_RESIZE_FS`.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` for a smaller size, a size past the end of the device or a bad resize
    /// inode, `EFBIG` for a size that the disk cannot address, `EOPNOTSUPP` for too many inodes
    /// or a disk with `sparse_super2`, and `EROFS` for a read only mount.
    pub(crate) fn resize(&self, count: u64) -> Result<()> {
        self.tx()?.grow(count)
    }
}

/// The number of the reserved descriptor blocks that the resize inode keeps.
fn reserved(layout: &Superblock) -> u64 {
    if layout.compat & compat::RESIZE_INODE != 0 {
        u64::from(layout.reserved_gdt_blocks)
    } else {
        0
    }
}

/// The layout after a resize from `old` groups to `groups` groups, as the resize makes it.
fn plan(layout: &Superblock, old: u32, groups: u32) -> Superblock {
    let mut next = layout.clone();
    let per = layout.descs_per_block();
    let (have, need) = (u64::from(old).div_ceil(per), u64::from(groups).div_ceil(per));
    if layout.incompat & incompat::META_BG == 0 && need > have {
        let reserved = reserved(layout);
        if need > have + reserved {
            next.compat &= !compat::RESIZE_INODE;
            next.incompat |= incompat::META_BG;
            next.first_meta_bg = (have + reserved) as u32;
            if reserved > 0 {
                next.reserved_gdt_blocks = 0;
            }
        } else {
            next.reserved_gdt_blocks -= (need - have) as u16;
        }
    }
    next.blocks_count = layout.group_start(groups);
    next
}

impl Tx<'_> {
    fn grow(&mut self, mut count: u64) -> Result<()> {
        let fs = self.fs;
        let sb = &fs.sb;
        let old = fs.blocks_count();
        if count < old {
            return Err(Errno::EINVAL);
        }
        if count == old {
            return Ok(());
        }
        let bit64 = sb.incompat & incompat::BIT64 != 0;
        if !bit64 && count > u64::from(u32::MAX) {
            return Err(Errno::EFBIG);
        }
        if sb.compat & compat::SPARSE_SUPER2 != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        // A disk cannot have both `resize_inode` and `meta_bg`, as `ext4_resize_fs`.
        let layout = fs.layout();
        if layout.compat & compat::RESIZE_INODE != 0 && layout.incompat & incompat::META_BG != 0 {
            return Err(Errno::EINVAL);
        }
        let bs = sb.block_size;
        let mut probe = vec![0u8; bs as usize];
        fs.disk.read((count - 1) * bs, &mut probe).map_err(|_| Errno::EINVAL)?;
        // With `bigalloc` the new size becomes whole clusters, as Linux.
        let bits = sb.cluster_bits;
        count = count >> bits << bits;
        if count <= old {
            return Ok(());
        }
        let old_groups = fs.group_count();
        let mut groups = sb.groups_for(count);
        if groups > old_groups {
            let last = groups - 1;
            let after = plan(&layout, old_groups, groups);
            let need = after.base_meta_blocks(last) + 2 + sb.itable_blocks() + MIN_DATA;
            if u64::from(sb.group_size(last, count)) < need {
                groups = last;
                count = sb.group_start(groups);
            }
        }
        if count <= old {
            return Ok(());
        }
        if u64::from(groups) * u64::from(sb.inodes_per_group) > u64::from(u32::MAX) {
            return Err(Errno::EOPNOTSUPP);
        }

        // When the reserved descriptor blocks are not sufficient, the resize first fills them,
        // then changes the file system to `meta_bg`, and then adds the other groups, as
        // `ext4_resize_fs`.
        let per = layout.descs_per_block();
        let have = u64::from(old_groups).div_ceil(per);
        let need = u64::from(groups).div_ceil(per);
        if layout.incompat & incompat::META_BG == 0 && need > have + reserved(&layout) {
            let full = ((have + reserved(&layout)) * per) as u32;
            self.add(layout.group_start(full))?;
            self.convert_meta_bg()?;
        }
        self.add(count)
    }

    /// Makes the last group longer and adds the groups up to `count` blocks. The layout must
    /// have the descriptor blocks for these groups, or reserved blocks for them.
    fn add(&mut self, count: u64) -> Result<()> {
        let fs = self.fs;
        let sb = &fs.sb;
        let old = fs.blocks_count();
        if count <= old {
            return Ok(());
        }
        let bs = sb.block_size;
        let bits = sb.cluster_bits;
        let bit64 = sb.incompat & incompat::BIT64 != 0;
        let old_groups = fs.group_count();
        let groups = sb.groups_for(count);
        let itable = sb.itable_blocks();
        let ipg = sb.inodes_per_group;
        let mut layout = fs.layout();
        let per = layout.descs_per_block();
        let meta_bg = layout.incompat & incompat::META_BG != 0;
        let (have, need) = (u64::from(old_groups).div_ceil(per), u64::from(groups).div_ceil(per));
        if !meta_bg && need > have + reserved(&layout) {
            return Err(Errno::EINVAL);
        }
        let left = if meta_bg { 0 } else { reserved(&layout) - (need - have) };
        let backups = (1..groups).filter(|&g| sb.has_super(g)).count();
        if left > 0 && backups * 4 > bs as usize {
            return Err(Errno::EOPNOTSUPP);
        }

        // Each new descriptor block starts with zeros. Without `meta_bg` it is the next
        // reserved block. With `meta_bg` it is in the first group of its meta block group.
        if !meta_bg && need > have {
            for nr in have..need {
                self.take_reserved(nr)?;
            }
            layout.reserved_gdt_blocks = left as u16;
            put16(&mut self.meta.sb, layout::sb::RESERVED_GDT_BLOCKS, left as u16);
        }
        layout.blocks_count = count;
        let zero = vec![0u8; bs as usize];
        for nr in have..need {
            fs.write(layout.desc_block(nr) * bs, &zero)?;
        }
        *fs.layout.lock() = layout.clone();

        // The last group gets the blocks up to the new end, or up to the end of the group.
        let last = old_groups - 1;
        let (was, now) = (fs.clusters_in_group(last), sb.group_clusters(last, count));
        let mut free_clusters = u64::from(now - was);
        let mut used_clusters = 0;
        if now > was {
            let mut bitmap = self.block_bitmap(last)?;
            for bit in was as usize..now as usize {
                set_bit(&mut bitmap, bit, false);
            }
            self.write_block_bitmap(last, &bitmap)?;
            let free = self.desc_get(last, gd::FREE_BLOCKS) + (now - was);
            self.desc_set(last, gd::FREE_BLOCKS, free);
            self.write_desc(last)?;
        }

        // Each new group keeps its bitmaps and its inode table after its copy of the
        // superblock and of the descriptors. With checksums of the descriptors the inode table
        // is not zeroed, as Linux without `noinit_itable`. The counts of unused inodes tell
        // fsck that the table has no inode in use.
        let csum = sb.ro_compat & (ro_compat::GDT_CSUM | ro_compat::METADATA_CSUM) != 0;
        let zeros = if csum { Vec::new() } else { vec![0u8; (ZERO_CHUNK * bs) as usize] };
        for group in old_groups..groups {
            let start = sb.group_start(group);
            let at = start + layout.base_meta_blocks(group);
            let desc = GroupDesc { block_bitmap: at, inode_bitmap: at + 1, inode_table: at + 2 };
            let used = (at + 2 + itable - start).div_ceil(sb.cluster_ratio());
            let clusters = u64::from(sb.group_clusters(group, count));
            let mut block = desc.inode_table;
            while !csum && block < desc.inode_table + itable {
                let n = ZERO_CHUNK.min(desc.inode_table + itable - block);
                fs.write_direct(block * bs, &zeros[..(n * bs) as usize])?;
                block += n;
            }
            let mut raw = vec![0u8; usize::from(sb.desc_size)];
            for (field, value) in [(0, desc.block_bitmap), (4, desc.inode_bitmap), (8, at + 2)] {
                put32(&mut raw, field, value as u32);
                if raw.len() >= 64 {
                    put32(&mut raw, field + 0x20, (value >> 32) as u32);
                }
            }
            if !csum {
                put16(&mut raw, gd::FLAGS, bg::ITABLE_ZEROED);
            }
            self.meta.descs.push(raw);
            fs.groups.lock().push(desc);
            self.desc_set(group, gd::FREE_BLOCKS, (clusters - used) as u32);
            self.desc_set(group, gd::FREE_INODES, ipg);
            if csum {
                self.desc_set(group, gd::ITABLE_UNUSED, ipg);
            }
            let mut bitmap = vec![0u8; bs as usize];
            for bit in 0..used as usize {
                set_bit(&mut bitmap, bit, true);
            }
            mark_end(&mut bitmap, clusters as usize);
            self.write_block_bitmap(group, &bitmap)?;
            let mut bitmap = vec![0u8; bs as usize];
            mark_end(&mut bitmap, ipg as usize);
            self.write_inode_bitmap(group, &bitmap)?;
            self.write_desc(group)?;
            free_clusters += clusters - used;
            used_clusters += used;
        }

        // The resize inode maps the reserved descriptor blocks of each group with a copy. Each
        // reserved block of group 0 is an indirect block with the copies of that block, as
        // `reserve_backup_gdb`.
        if left > 0 {
            let primary = layout.sb_block() + 1 + need;
            let mut added = 0;
            for group in (old_groups..groups).filter(|&g| sb.has_super(g)) {
                let index = (1..group).filter(|&g| sb.has_super(g)).count();
                let offset = u64::from(group) * u64::from(sb.blocks_per_group);
                for block in primary..primary + left {
                    let mut ind = fs.read_block(block)?;
                    put32(&mut ind, index * 4, (block + offset) as u32);
                    fs.write(block * bs, &ind)?;
                }
                added += left;
            }
            if added > 0 {
                let mut raw = fs.read_inode(layout::RESIZE_INO)?;
                raw.set_blocks(raw.blocks() + added * fs.cluster_sectors());
                fs.write_inode(layout::RESIZE_INO, &mut raw)?;
            }
        }

        // The reserved blocks keep their part of the file system.
        let b = &mut self.meta.sb;
        let mut r_blocks = u64::from(u32_at(b, layout::sb::R_BLOCKS));
        if bit64 {
            r_blocks |= u64::from(u32_at(b, layout::sb::R_BLOCKS_HI)) << 32;
        }
        let r_blocks = (u128::from(r_blocks) * u128::from(count) / u128::from(old)) as u64;
        put32(b, layout::sb::R_BLOCKS, r_blocks as u32);
        put32(b, layout::sb::BLOCKS_COUNT, count as u32);
        if bit64 {
            put32(b, layout::sb::R_BLOCKS_HI, (r_blocks >> 32) as u32);
            put32(b, layout::sb::BLOCKS_COUNT_HI, (count >> 32) as u32);
        }
        put32(b, layout::sb::INODES_COUNT, groups * ipg);
        // With `bigalloc` a count of the clusters of the metadata from mkfs gets the new
        // metadata, as `ext4_add_overhead`.
        let overhead = u32_at(b, layout::sb::OVERHEAD_CLUSTERS);
        if bits != 0 && overhead != 0 {
            put32(b, layout::sb::OVERHEAD_CLUSTERS, overhead + used_clusters as u32);
        }
        fs.blocks.store(count, Ordering::Relaxed);
        self.write_sb((free_clusters << bits) as i64, i64::from((groups - old_groups) * ipg))?;
        self.write_backups(groups)
    }

    /// Makes the reserved block after the descriptor block `nr - 1` the descriptor block `nr`,
    /// as `add_new_gdb`. The resize inode does not keep the block and its copies after this.
    /// The copies become copies of the descriptor block.
    fn take_reserved(&mut self, nr: u64) -> Result<()> {
        let fs = self.fs;
        let bs = fs.sb.block_size;
        let primary = fs.sb.sb_block() + 1 + nr;
        let mut raw = fs.read_inode(layout::RESIZE_INO)?;
        let dind = u64::from(u32_at(raw.block(), DIND * 4));
        if dind == 0 {
            return Err(Errno::EINVAL);
        }
        let mut map = fs.read_block(dind)?;
        let at = (nr % (bs / 4)) as usize * 4;
        if u64::from(u32_at(&map, at)) != primary {
            return Err(Errno::EINVAL);
        }
        put32(&mut map, at, 0);
        fs.write(dind * bs, &map)?;
        let copies = fs.read_block(primary)?.chunks(4).filter(|e| u32_at(e, 0) != 0).count();
        let sectors = (copies as u64 + 1) * fs.cluster_sectors();
        raw.set_blocks(raw.blocks().saturating_sub(sectors));
        fs.write_inode(layout::RESIZE_INO, &mut raw)
    }

    /// Changes the file system to `meta_bg` when the reserved descriptor blocks are all in use,
    /// as `ext4_convert_meta_bg`. The present descriptor blocks stay after the superblock, and
    /// the resize inode frees its last block.
    fn convert_meta_bg(&mut self) -> Result<()> {
        let fs = self.fs;
        let mut layout = fs.layout();
        if layout.compat & compat::RESIZE_INODE != 0 {
            if layout.reserved_gdt_blocks != 0 {
                return Err(Errno::EINVAL);
            }
            let mut raw = fs.read_inode(layout::RESIZE_INO)?;
            let dind = u64::from(u32_at(raw.block(), DIND * 4));
            raw.block_mut()[DIND * 4..DIND * 4 + 4].fill(0);
            raw.set_blocks(0);
            fs.write_inode(layout::RESIZE_INO, &mut raw)?;
            if dind != 0 {
                self.free_blocks(dind, 1)?;
            }
        }
        layout.compat &= !compat::RESIZE_INODE;
        layout.incompat |= incompat::META_BG;
        layout.first_meta_bg = layout.gdt_blocks() as u32;
        let b = &mut self.meta.sb;
        let features = u32_at(b, layout::sb::FEATURE_COMPAT) & !compat::RESIZE_INODE;
        put32(b, layout::sb::FEATURE_COMPAT, features);
        let features = u32_at(b, layout::sb::FEATURE_INCOMPAT) | incompat::META_BG;
        put32(b, layout::sb::FEATURE_INCOMPAT, features);
        put32(b, layout::sb::FIRST_META_BG, layout.first_meta_bg);
        *fs.layout.lock() = layout;
        self.write_sb(0, 0)
    }

    /// Writes the copies of the superblock and of the descriptors in each group that has them.
    /// The descriptor blocks before `first_meta_bg` have a copy in each group with a copy of
    /// the superblock. Each later block has a copy in the second and in the last group of its
    /// meta block group, as `update_backups`.
    fn write_backups(&mut self, groups: u32) -> Result<()> {
        let fs = self.fs;
        let layout = fs.layout();
        let bs = layout.block_size;
        let per = layout.descs_per_block() as usize;
        let meta_bg = layout.incompat & incompat::META_BG != 0;
        let blocks = layout.gdt_blocks();
        let flat = if meta_bg { u64::from(layout.first_meta_bg) } else { blocks };
        let block_of = |descs: &[Vec<u8>], nr: usize| {
            let mut data: Vec<u8> = descs[nr * per..descs.len().min((nr + 1) * per)].concat();
            data.resize(bs as usize, 0);
            data
        };
        let mut table: Vec<u8> =
            self.meta.descs[..groups.min(flat as u32 * per as u32) as usize].concat();
        table.resize((flat * bs) as usize, 0);
        let mut copy = self.meta.sb.clone();
        for group in (1..groups).filter(|&g| layout.has_super(g)) {
            let start = layout.group_start(group);
            put16(&mut copy, layout::sb::BLOCK_GROUP_NR, group as u16);
            if fs.metadata_csum() {
                let csum = crc::crc32c(!0, &copy[..layout::sb::CHECKSUM]);
                put32(&mut copy, layout::sb::CHECKSUM, csum);
            }
            fs.write(start * bs, &copy)?;
            if (u64::from(group) / per as u64) < flat {
                fs.write((start + 1) * bs, &table)?;
            }
        }
        for nr in flat..blocks {
            let first = nr as u32 * per as u32;
            let data = block_of(&self.meta.descs, nr as usize);
            for group in [first + 1, first + per as u32 - 1].into_iter().filter(|&g| g < groups) {
                let at = layout.group_start(group) + u64::from(layout.has_super(group));
                fs.write(at * bs, &data)?;
            }
        }
        Ok(())
    }
}

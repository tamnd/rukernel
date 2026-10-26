//! The map of the space of a mounted file system, as `FS_IOC_GETFSMAP` and `ext4_getfsmap` of
//! Linux.

use crate::Fs;
use crate::alloc_blocks::test_bit;
use crate::layout::{gd, incompat, u16_at};
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::Result;
use rk_vfs::inode::{FsmapRecord, fsmap_owner};

/// The special owners of ext4, from `fs/ext4/fsmap.h` of Linux. The XFS owners have the type
/// `X`, so that `xfs_io` knows their names.
pub(crate) mod owner {
    /// `EXT4_FMR_OWN_FS`: the superblock.
    pub(crate) const FS: u64 = ((b'X' as u64) << 32) | 1;
    /// `EXT4_FMR_OWN_INODES`: the inode tables.
    pub(crate) const INODES: u64 = ((b'X' as u64) << 32) | 5;
    /// `EXT4_FMR_OWN_GDT`: the group descriptors.
    pub(crate) const GDT: u64 = ((b'f' as u64) << 32) | 1;
    /// `EXT4_FMR_OWN_RESV_GDT`: the blocks that the group descriptors keep for a resize.
    pub(crate) const RESV_GDT: u64 = ((b'f' as u64) << 32) | 2;
    /// `EXT4_FMR_OWN_BLKBM`: the block bitmaps.
    pub(crate) const BLKBM: u64 = ((b'f' as u64) << 32) | 3;
    /// `EXT4_FMR_OWN_INOBM`: the inode bitmaps.
    pub(crate) const INOBM: u64 = ((b'f' as u64) << 32) | 4;
}

/// An area of blocks: the first block, the number of blocks and the owner.
type Area = (u64, u64, u64);

impl Fs {
    /// Gives the map of the space, as the `Inode::fsmap` of the VFS. The metadata at fixed
    /// places has its special owner, the runs of free blocks have `FMR_OWN_FREE`, and the other
    /// blocks have `FMR_OWN_UNKNOWN`, as Linux. A block that a change freed since the last
    /// commit is not free yet, as in the buddy bitmap of Linux. The groups before the group of
    /// the byte `from` are not read.
    ///
    /// # Errors
    ///
    /// Gives the error of the disk.
    pub(crate) fn fsmap(&self, from: u64) -> Result<Vec<FsmapRecord>> {
        let bs = self.sb.block_size;
        let first_data = u64::from(self.sb.first_data_block);
        let per_group = u64::from(self.sb.blocks_per_group);
        let end = self.blocks_count();
        let groups = self.group_count();
        let first_group = ((from / bs).max(first_data) - first_data) / per_group;
        let first_group = u32::try_from(first_group).unwrap_or(u32::MAX).min(groups);
        let start = self.sb.group_start(first_group).min(end);
        let mut areas = self.fixed_metadata()?;
        areas.extend(self.free_runs(first_group)?);
        areas.sort_unstable_by_key(|a| a.0);
        // The gaps between the areas have an owner that the map does not give.
        let mut map = Vec::new();
        let mut at = start;
        for (first, count, owner) in areas {
            let last = first + count;
            if count == 0 || last <= at {
                continue;
            }
            if first > at {
                map.push((at, first - at, fsmap_owner::UNKNOWN));
            }
            // An area that starts before `start` stays whole. A later area does not overlap the
            // area before it.
            let first = if at == start { first } else { first.max(at) };
            map.push((first, last - first, owner));
            at = last;
        }
        if at < end {
            map.push((at, end - at, fsmap_owner::UNKNOWN));
        }
        Ok(map
            .into_iter()
            .map(|(first, count, owner)| FsmapRecord {
                physical: first * bs,
                length: count * bs,
                owner,
            })
            .collect())
    }

    /// Gives the metadata at fixed places in order, with the next areas of one owner as one
    /// area, as `ext4_getfsmap_find_fixed_metadata` of Linux.
    fn fixed_metadata(&self) -> Result<Vec<Area>> {
        let sb = &self.layout();
        let groups = self.group_count();
        let meta_bg = sb.incompat & incompat::META_BG != 0;
        let per_block = sb.descs_per_block();
        let gdt_blocks = (u64::from(groups) * u64::from(sb.desc_size)).div_ceil(sb.block_size);
        let mut areas = Vec::new();
        for group in 0..groups {
            let desc = self.group(group)?;
            let mut at = sb.group_start(group);
            let has_super = sb.has_super(group);
            if has_super {
                areas.push((at, 1, owner::FS));
                at += 1;
            }
            // The blocks of the group descriptors, as `ext4_bg_num_gdb` of Linux.
            let nr = u64::from(group) / per_block;
            let in_meta_bg = meta_bg && nr >= u64::from(sb.first_meta_bg);
            let gdt = if in_meta_bg {
                let index = u64::from(group) % per_block;
                u64::from(index <= 1 || index == per_block - 1)
            } else if !has_super {
                0
            } else if meta_bg {
                u64::from(sb.first_meta_bg)
            } else {
                gdt_blocks
            };
            if gdt > 0 {
                areas.push((at, gdt, owner::GDT));
                at += gdt;
                let reserved = u64::from(sb.reserved_gdt_blocks);
                if !in_meta_bg && reserved > 0 {
                    areas.push((at, reserved, owner::RESV_GDT));
                }
            }
            areas.push((desc.block_bitmap, 1, owner::BLKBM));
            areas.push((desc.inode_bitmap, 1, owner::INOBM));
            areas.push((desc.inode_table, sb.itable_blocks(), owner::INODES));
        }
        areas.sort_unstable_by_key(|a| a.0);
        Ok(merge(areas))
    }

    /// Gives the runs of free blocks from the group `first_group` to the end, in order. A run
    /// can continue in the next group.
    fn free_runs(&self, first_group: u32) -> Result<Vec<Area>> {
        let mut runs = Vec::new();
        for group in first_group..self.group_count() {
            let base = self.sb.group_start(group);
            // Each bit of the bitmap is one cluster.
            let bits = self.sb.cluster_bits;
            let size = u64::from(self.clusters_in_group(group));
            // The lock stops an allocation in the group while the bitmap is read. A read only
            // or frozen file system also gives its map, so this is not a change.
            let meta = self.meta.lock();
            let desc = meta.descs.get(group as usize).ok_or(Errno::EIO)?;
            let flags = u16_at(desc, gd::FLAGS);
            let bitmap = self.block_bitmap_of(group, flags)?;
            if bitmap.len() * 8 < size as usize {
                return Err(Errno::EUCLEAN);
            }
            let mut run: Option<u64> = None;
            for bit in 0..=size {
                let free = bit < size
                    && !test_bit(&bitmap, bit as usize)
                    && !self.is_busy(base + (bit << bits));
                match (free, run) {
                    (true, None) => run = Some(bit),
                    (false, Some(first)) => {
                        run = None;
                        let (at, count) = (first << bits, (bit - first) << bits);
                        let count = count.min(self.blocks_count().saturating_sub(base + at));
                        runs.push((base + at, count, fsmap_owner::FREE));
                    }
                    _ => {}
                }
            }
            drop(meta);
        }
        Ok(merge(runs))
    }
}

/// Makes each two areas in order that touch and have one owner into one area.
fn merge(areas: Vec<Area>) -> Vec<Area> {
    let mut out: Vec<Area> = Vec::with_capacity(areas.len());
    for (first, count, owner) in areas {
        match out.last_mut() {
            Some(prev) if prev.2 == owner && prev.0 + prev.1 == first => prev.1 += count,
            _ => out.push((first, count, owner)),
        }
    }
    out
}

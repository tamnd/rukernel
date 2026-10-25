//! The online resize of a mounted file system, as `EXT4_IOC_RESIZE_FS` of Linux. A resize makes
//! the last group longer and adds new groups at the end. The descriptors of the new groups must
//! fit in the blocks of descriptors that the disk has.

use crate::alloc_blocks::{mark_end, set_bit};
use crate::layout::{self, GroupDesc, bg, compat, gd, incompat, put16, put32, ro_compat, u32_at};
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

impl Fs {
    /// Grows the file system to `count` blocks, for `EXT4_IOC_RESIZE_FS`.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` for a smaller size or a size past the end of the device, `EFBIG` for a
    /// size that the disk cannot address, `EOPNOTSUPP` if the new descriptors need more blocks
    /// or the disk has `meta_bg` or `sparse_super2`, and `EROFS` for a read only mount.
    pub(crate) fn resize(&self, count: u64) -> Result<()> {
        self.tx()?.grow(count)
    }
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
        if sb.incompat & incompat::META_BG != 0 || sb.compat & compat::SPARSE_SUPER2 != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let bs = sb.block_size;
        let mut probe = vec![0u8; bs as usize];
        fs.disk.read((count - 1) * bs, &mut probe).map_err(|_| Errno::EINVAL)?;
        let old_groups = fs.group_count();
        let mut groups = sb.groups_for(count);
        let itable = sb.itable_blocks();
        if groups > old_groups {
            let last = groups - 1;
            let need = sb.base_meta_blocks(last) + 2 + itable + MIN_DATA;
            if u64::from(sb.group_size(last, count)) < need {
                groups = last;
                count = sb.group_start(groups);
            }
        }
        if count <= old {
            return Ok(());
        }
        let ipg = sb.inodes_per_group;
        if (u64::from(groups) * u64::from(sb.desc_size)).div_ceil(bs) > sb.gdt_blocks()
            || u64::from(groups) * u64::from(ipg) > u64::from(u32::MAX)
        {
            return Err(Errno::EOPNOTSUPP);
        }
        let reserved = u64::from(sb.reserved_gdt_blocks);
        let resize_inode = sb.compat & compat::RESIZE_INODE != 0 && reserved > 0;
        let backups = (1..groups).filter(|&g| sb.has_super(g)).count();
        if resize_inode && backups * 4 > bs as usize {
            return Err(Errno::EOPNOTSUPP);
        }

        // The last group gets the blocks up to the new end, or up to the end of the group.
        let last = old_groups - 1;
        let (was, now) = (fs.blocks_in_group(last), sb.group_size(last, count));
        let mut free_blocks = u64::from(now - was);
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
        // superblock and of the descriptors.
        let csum = sb.ro_compat & (ro_compat::GDT_CSUM | ro_compat::METADATA_CSUM) != 0;
        let zeros = vec![0u8; (ZERO_CHUNK * bs) as usize];
        for group in old_groups..groups {
            let start = sb.group_start(group);
            let size = u64::from(sb.group_size(group, count));
            let at = start + sb.base_meta_blocks(group);
            let desc = GroupDesc { block_bitmap: at, inode_bitmap: at + 1, inode_table: at + 2 };
            let used = at + 2 + itable - start;
            let mut block = desc.inode_table;
            while block < desc.inode_table + itable {
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
            if csum {
                put16(&mut raw, gd::FLAGS, bg::ITABLE_ZEROED);
            }
            self.meta.descs.push(raw);
            fs.groups.lock().push(desc);
            self.desc_set(group, gd::FREE_BLOCKS, (size - used) as u32);
            self.desc_set(group, gd::FREE_INODES, ipg);
            if csum {
                self.desc_set(group, gd::ITABLE_UNUSED, ipg);
            }
            let mut bitmap = vec![0u8; bs as usize];
            for bit in 0..used as usize {
                set_bit(&mut bitmap, bit, true);
            }
            mark_end(&mut bitmap, size as usize);
            self.write_block_bitmap(group, &bitmap)?;
            let mut bitmap = vec![0u8; bs as usize];
            mark_end(&mut bitmap, ipg as usize);
            self.write_inode_bitmap(group, &bitmap)?;
            self.write_desc(group)?;
            free_blocks += size - used;
        }

        // The resize inode maps the reserved descriptor blocks of each group with a copy. Each
        // reserved block of group 0 is an indirect block with the copies of that block.
        if resize_inode {
            let primary = u64::from(sb.first_data_block) + 1 + sb.gdt_blocks();
            let mut added = 0;
            for group in (old_groups..groups).filter(|&g| sb.has_super(g)) {
                let index = (1..group).filter(|&g| sb.has_super(g)).count();
                for block in primary..primary + reserved {
                    let mut ind = fs.read_block(block)?;
                    put32(&mut ind, index * 4, (block + sb.group_start(group)) as u32);
                    fs.write(block * bs, &ind)?;
                }
                added += reserved;
            }
            if added > 0 {
                let mut raw = fs.read_inode(layout::RESIZE_INO)?;
                raw.set_blocks(raw.blocks() + added * (bs / 512));
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
        fs.blocks.store(count, Ordering::Relaxed);
        self.write_sb(free_blocks as i64, i64::from((groups - old_groups) * ipg))?;
        self.write_backups(groups)
    }

    /// Writes the copies of the superblock and of the descriptors in each group that has them.
    fn write_backups(&mut self, groups: u32) -> Result<()> {
        let fs = self.fs;
        let sb = &fs.sb;
        let bs = sb.block_size;
        let mut table: Vec<u8> = self.meta.descs.concat();
        table.resize((sb.gdt_blocks() * bs) as usize, 0);
        let mut copy = self.meta.sb.clone();
        for group in (1..groups).filter(|&g| sb.has_super(g)) {
            let start = sb.group_start(group);
            put16(&mut copy, layout::sb::BLOCK_GROUP_NR, group as u16);
            if fs.metadata_csum() {
                let csum = crc::crc32c(!0, &copy[..layout::sb::CHECKSUM]);
                put32(&mut copy, layout::sb::CHECKSUM, csum);
            }
            fs.write(start * bs, &copy)?;
            fs.write((start + 1) * bs, &table)?;
        }
        Ok(())
    }
}

//! The structures of ext4 on the disk, from fs/ext4/ext4.h of Linux and the ext4 disk layout
//! document. All the numbers are little endian.

use alloc::vec::Vec;
use rk_abi::Errno;

/// The magic number of the superblock, `EXT4_SUPER_MAGIC`.
pub const MAGIC: u16 = 0xef53;
/// The offset of the superblock on the disk.
pub const SUPERBLOCK_AT: u64 = 1024;
/// The size of the superblock.
pub const SUPERBLOCK_SIZE: usize = 1024;
/// The inode of the root directory.
pub const ROOT_INO: u32 = 2;
/// The inode that keeps the reserved blocks for more group descriptors.
pub const RESIZE_INO: u32 = 7;

/// The incompatible features. A kernel that does not know one of them must not mount the disk.
pub mod incompat {
    /// A directory entry has the type of its file.
    pub const FILETYPE: u32 = 0x2;
    /// The journal must be replayed.
    pub const RECOVER: u32 = 0x4;
    /// The journal is on another device.
    pub const JOURNAL_DEV: u32 = 0x8;
    /// The group descriptors are in meta groups.
    pub const META_BG: u32 = 0x10;
    /// The files use extent trees.
    pub const EXTENTS: u32 = 0x40;
    /// The block numbers have 64 bits.
    pub const BIT64: u32 = 0x80;
    /// Multiple mount protection.
    pub const MMP: u32 = 0x100;
    /// The bitmaps and the inode tables of a flex group are together.
    pub const FLEX_BG: u32 = 0x200;
    /// The checksum seed is in the superblock.
    pub const CSUM_SEED: u32 = 0x2000;
    /// A directory can have more than 2 GiB of entries, or an htree of 3 levels.
    pub const LARGEDIR: u32 = 0x4000;
    /// The features that this driver supports.
    pub const SUPPORTED: u32 =
        FILETYPE | RECOVER | META_BG | EXTENTS | BIT64 | MMP | FLEX_BG | CSUM_SEED | LARGEDIR;
}

/// The features that are compatible for a read only mount. A kernel that does not know one of
/// them can mount the disk read only.
pub mod ro_compat {
    /// Only some groups have a copy of the superblock.
    pub const SPARSE_SUPER: u32 = 0x1;
    /// A file can be larger than 2 GiB.
    pub const LARGE_FILE: u32 = 0x2;
    /// The `blocks` field of an inode can count blocks of the file system.
    pub const HUGE_FILE: u32 = 0x8;
    /// The group descriptors have a crc16 checksum.
    pub const GDT_CSUM: u32 = 0x10;
    /// A directory can have more than 65000 subdirectories.
    pub const DIR_NLINK: u32 = 0x20;
    /// The inodes have extra fields after the first 128 bytes.
    pub const EXTRA_ISIZE: u32 = 0x40;
    /// The metadata has crc32c checksums.
    pub const METADATA_CSUM: u32 = 0x400;
    /// The orphan file has inodes in it.
    pub const ORPHAN_PRESENT: u32 = 0x1_0000;
    /// The features that this driver can change.
    pub const WRITABLE: u32 =
        SPARSE_SUPER | LARGE_FILE | HUGE_FILE | GDT_CSUM | DIR_NLINK | EXTRA_ISIZE | METADATA_CSUM;
}

/// The compatible features.
pub mod compat {
    /// The file system has a journal.
    pub const HAS_JOURNAL: u32 = 0x4;
    /// The inode [`RESIZE_INO`] keeps the reserved blocks for more group descriptors.
    pub const RESIZE_INODE: u32 = 0x10;
    /// A large directory can have an htree index, `dir_index`.
    pub const DIR_INDEX: u32 = 0x20;
    /// Only up to two groups past group 0 have a copy of the superblock.
    pub const SPARSE_SUPER2: u32 = 0x200;
}

/// The flags of a group descriptor.
pub mod bg {
    /// The inode bitmap is not on the disk. It has no inode in use.
    pub const INODE_UNINIT: u16 = 0x1;
    /// The block bitmap is not on the disk. The driver makes it from the layout.
    pub const BLOCK_UNINIT: u16 = 0x2;
    /// The inode table has only zeros.
    pub const ITABLE_ZEROED: u16 = 0x4;
}

/// The offsets of the fields of the superblock that the driver changes.
pub mod sb {
    /// The number of inodes.
    pub const INODES_COUNT: usize = 0x0;
    /// The low 32 bits of the number of blocks.
    pub const BLOCKS_COUNT: usize = 0x4;
    /// The high 32 bits of the number of blocks.
    pub const BLOCKS_COUNT_HI: usize = 0x150;
    /// The group of this copy of the superblock.
    pub const BLOCK_GROUP_NR: usize = 0x5a;
    /// The low 32 bits of the number of blocks for the superuser only.
    pub const R_BLOCKS: usize = 0x8;
    /// The high 32 bits of the number of blocks for the superuser only.
    pub const R_BLOCKS_HI: usize = 0x154;
    /// The low 32 bits of the number of free blocks.
    pub const FREE_BLOCKS: usize = 0xc;
    /// The high 32 bits of the number of free blocks.
    pub const FREE_BLOCKS_HI: usize = 0x158;
    /// The number of free inodes.
    pub const FREE_INODES: usize = 0x10;
    /// The first inode of the list of orphans, as `s_last_orphan`.
    pub const LAST_ORPHAN: usize = 0xe8;
    /// The label of the file system, `s_volume_name`. A label shorter than the field ends with
    /// a zero byte.
    pub const VOLUME_NAME: usize = 0x78;
    /// The length of the label field, `EXT4_LABEL_MAX`.
    pub const VOLUME_NAME_LEN: usize = 16;
    /// The checksum of the superblock.
    pub const CHECKSUM: usize = 0x3fc;
}

/// The offsets of the fields of a group descriptor that the driver changes. A field with a
/// high half has the high half at `HI` past the low half, if the descriptor has 64 bytes.
pub mod gd {
    /// The number of free blocks.
    pub const FREE_BLOCKS: usize = 0xc;
    /// The number of free inodes.
    pub const FREE_INODES: usize = 0xe;
    /// The number of directories.
    pub const USED_DIRS: usize = 0x10;
    /// The flags.
    pub const FLAGS: usize = 0x12;
    /// The checksum of the block bitmap.
    pub const BLOCK_BITMAP_CSUM: usize = 0x18;
    /// The checksum of the inode bitmap.
    pub const INODE_BITMAP_CSUM: usize = 0x1a;
    /// The number of inodes at the end of the inode table that were never used.
    pub const ITABLE_UNUSED: usize = 0x1c;
    /// The checksum of the descriptor.
    pub const CHECKSUM: usize = 0x1e;
    /// The distance from a low half to its high half.
    pub const HI: usize = 0x20;
}

/// The flags of an inode.
pub mod flags {
    /// The directory has an htree index.
    pub const INDEX: u32 = 0x1000;
    /// The file uses an extent tree.
    pub const EXTENTS: u32 = 0x8_0000;
    /// The `blocks` field counts blocks of the file system and not sectors.
    pub const HUGE_FILE: u32 = 0x4_0000;
    /// The data is in the inode.
    pub const INLINE_DATA: u32 = 0x1000_0000;
    /// The names of the directory do not depend on the case of the letters.
    pub const CASEFOLD: u32 = 0x4000_0000;
    /// The flags that `FS_IOC_GETFLAGS` shows, as `EXT4_FL_USER_VISIBLE` of Linux.
    pub const USER_VISIBLE: u32 = 0x725B_DFFF;
    /// The flags that `FS_IOC_SETFLAGS` can change, as `EXT4_FL_USER_MODIFIABLE` of Linux.
    pub const USER_MODIFIABLE: u32 = 0x624B_C0FF;
    /// The file uses direct access to the memory of the device.
    pub const DAX: u32 = 0x0200_0000;
    /// The data goes to the journal.
    pub const JOURNAL_DATA: u32 = 0x4000;
    /// The file is encrypted.
    pub const ENCRYPT: u32 = 0x800;
    /// The file has fs-verity.
    pub const VERITY: u32 = 0x10_0000;
    /// The flags that a file cannot have together with [`DAX`], as `EXT4_DAX_MUT_EXCL` of Linux.
    pub const DAX_MUT_EXCL: u32 = VERITY | ENCRYPT | JOURNAL_DATA | INLINE_DATA;
    /// The flags that a new inode gets from its directory, as `EXT4_FL_INHERITED` of Linux
    /// without `EXT4_CASEFOLD_FL`, because the driver has no names that ignore the case.
    pub const INHERITED: u32 = 0x2201_C4CF;
    /// The flags of a directory that a regular file cannot have, from `EXT4_REG_FLMASK` of Linux.
    pub const DIR_ONLY: u32 = 0x6003_0000;
    /// The inherited flags that a file that is not a directory or a regular file can have, as
    /// `EXT4_OTHER_FLMASK` of Linux.
    pub const OTHER: u32 = 0xC0;
}

/// Gives the `u16` at `at`.
pub fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

/// Writes the `u16` `v` at `at`.
pub fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

/// Writes the `u32` `v` at `at`.
pub fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// Gives the `u32` at `at`.
pub fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// The fields of the superblock that the driver uses.
#[derive(Clone, Debug)]
pub struct Superblock {
    /// The number of inodes.
    pub inodes_count: u32,
    /// The number of blocks.
    pub blocks_count: u64,
    /// The number of free blocks.
    pub free_blocks: u64,
    /// The number of free inodes.
    pub free_inodes: u32,
    /// The first block of the group 0: 1 for blocks of 1 KiB, else 0.
    pub first_data_block: u32,
    /// The size of a block in bytes.
    pub block_size: u64,
    /// The number of blocks in a group.
    pub blocks_per_group: u32,
    /// The number of inodes in a group.
    pub inodes_per_group: u32,
    /// The size of an inode in the inode table.
    pub inode_size: u16,
    /// The compatible features.
    pub compat: u32,
    /// The incompatible features.
    pub incompat: u32,
    /// The features that are compatible for a read only mount.
    pub ro_compat: u32,
    /// The size of a group descriptor.
    pub desc_size: u16,
    /// The length of the longest name.
    pub name_max: usize,
    /// The first inode that is not reserved.
    pub first_ino: u32,
    /// The number of blocks after the group descriptors that are kept for a larger file system.
    pub reserved_gdt_blocks: u16,
    /// The size of the extra fields that each inode must have, `s_min_extra_isize`.
    pub min_extra_isize: u16,
    /// The size of the extra fields of a new inode.
    pub want_extra_isize: u16,
    /// The UUID of the file system.
    pub uuid: [u8; 16],
    /// The seed of the crc32c checksums, if the superblock has it.
    pub checksum_seed: u32,
    /// The inode of the journal, or 0.
    pub journal_inum: u32,
    /// The first meta block group, if the disk has `meta_bg`.
    pub first_meta_bg: u32,
    /// The seed of the hash of the names in an htree index, `s_hash_seed`.
    pub hash_seed: [u32; 4],
    /// The hash of a new htree index, `s_def_hash_version`.
    pub def_hash_version: u8,
    /// The flags of the superblock, `s_flags`.
    pub flags: u32,
}

/// The flags of the superblock.
pub mod sb_flags {
    /// The hash of the names reads the bytes as unsigned numbers.
    pub const UNSIGNED_HASH: u32 = 0x2;
}

impl Superblock {
    /// Reads the superblock from its 1024 bytes.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` if the magic number is wrong or a field is not valid, and `EOPNOTSUPP` if
    /// the disk has a feature that the driver does not know.
    pub fn parse(b: &[u8]) -> Result<Self, Errno> {
        if b.len() < SUPERBLOCK_SIZE || u16_at(b, 0x38) != MAGIC {
            return Err(Errno::EINVAL);
        }
        let log = u32_at(b, 0x18);
        if log > 6 {
            return Err(Errno::EINVAL);
        }
        let incompat = u32_at(b, 0x60);
        if incompat & !incompat::SUPPORTED != 0 || incompat & incompat::JOURNAL_DEV != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let rev = u32_at(b, 0x4c);
        let bit64 = incompat & incompat::BIT64 != 0;
        let hi = |at: usize| if bit64 { u64::from(u32_at(b, at)) << 32 } else { 0 };
        let sb = Self {
            inodes_count: u32_at(b, 0),
            blocks_count: u64::from(u32_at(b, 0x4)) | hi(0x150),
            free_blocks: u64::from(u32_at(b, 0xc)) | hi(0x158),
            free_inodes: u32_at(b, 0x10),
            first_data_block: u32_at(b, 0x14),
            block_size: 1024 << log,
            blocks_per_group: u32_at(b, 0x20),
            inodes_per_group: u32_at(b, 0x28),
            inode_size: if rev == 0 { 128 } else { u16_at(b, 0x58) },
            compat: u32_at(b, 0x5c),
            incompat,
            ro_compat: u32_at(b, 0x64),
            desc_size: if bit64 { u16_at(b, 0xfe) } else { 32 },
            name_max: 255,
            first_ino: if rev == 0 { 11 } else { u32_at(b, 0x54) },
            reserved_gdt_blocks: u16_at(b, 0xce),
            min_extra_isize: u16_at(b, 0x15c),
            want_extra_isize: u16_at(b, 0x15e),
            uuid: b[0x68..0x78].try_into().map_err(|_| Errno::EINVAL)?,
            checksum_seed: u32_at(b, 0x270),
            journal_inum: u32_at(b, 0xe0),
            first_meta_bg: u32_at(b, 0x104),
            hash_seed: [u32_at(b, 0xec), u32_at(b, 0xf0), u32_at(b, 0xf4), u32_at(b, 0xf8)],
            def_hash_version: b[0xfc],
            flags: u32_at(b, 0x160),
        };
        if sb.blocks_per_group == 0
            || sb.inodes_per_group == 0
            || sb.inode_size < 128
            || !sb.inode_size.is_power_of_two()
            || u64::from(sb.inode_size) > sb.block_size
            || sb.desc_size < 32
            || !sb.desc_size.is_power_of_two()
        {
            return Err(Errno::EINVAL);
        }
        Ok(sb)
    }

    /// The number of block groups.
    pub fn groups(&self) -> u32 {
        self.groups_for(self.blocks_count)
    }

    /// The number of block groups of a file system with `blocks` blocks.
    pub fn groups_for(&self, blocks: u64) -> u32 {
        let blocks = blocks - u64::from(self.first_data_block);
        blocks.div_ceil(u64::from(self.blocks_per_group)) as u32
    }

    /// The first block of the group `group`.
    pub fn group_start(&self, group: u32) -> u64 {
        u64::from(self.first_data_block) + u64::from(group) * u64::from(self.blocks_per_group)
    }

    /// Tells if the group `group` has a copy of the superblock and of the group descriptors.
    pub fn has_super(&self, group: u32) -> bool {
        if self.ro_compat & ro_compat::SPARSE_SUPER == 0 || group <= 1 {
            return true;
        }
        [3, 5, 7].iter().any(|&p| {
            let mut n = group;
            while n.is_multiple_of(p) {
                n /= p;
            }
            n == 1
        })
    }

    /// The number of blocks of the group descriptors.
    pub fn gdt_blocks(&self) -> u64 {
        (u64::from(self.groups()) * u64::from(self.desc_size)).div_ceil(self.block_size)
    }

    /// The number of group descriptors in one block. With `meta_bg`, this is also the number of
    /// groups in a meta block group.
    pub fn descs_per_block(&self) -> u64 {
        self.block_size / u64::from(self.desc_size)
    }

    /// Tells if the descriptor block `nr` is in a meta block group, as `meta_bg` puts it.
    fn in_meta_bg(&self, nr: u64) -> bool {
        self.incompat & incompat::META_BG != 0 && nr >= u64::from(self.first_meta_bg)
    }

    /// The block that holds the descriptor block `nr`, as `descriptor_loc` of Linux. Without
    /// `meta_bg` the descriptors follow the superblock. With `meta_bg` each meta block group has
    /// its block of descriptors in its first group, after the superblock if the group has one.
    pub fn desc_block(&self, nr: u64) -> u64 {
        let first = u64::from(self.first_data_block);
        if !self.in_meta_bg(nr) {
            return first + 1 + nr;
        }
        let group = nr * self.descs_per_block();
        let mut has_super = u64::from(self.has_super(group as u32));
        if self.block_size == 1024 && nr == 0 && first == 0 {
            has_super += 1;
        }
        first + group * u64::from(self.blocks_per_group) + has_super
    }

    /// The number of blocks at the start of the group `group` for the superblock and the group
    /// descriptors, as `ext4_num_base_meta_blocks` of Linux.
    pub fn base_meta_blocks(&self, group: u32) -> u64 {
        let has_super = self.has_super(group);
        let nr = u64::from(group) / self.descs_per_block();
        if !self.in_meta_bg(nr) {
            if !has_super {
                return 0;
            }
            let gdt = if self.incompat & incompat::META_BG != 0 {
                u64::from(self.first_meta_bg)
            } else {
                self.gdt_blocks()
            };
            return 1 + gdt + u64::from(self.reserved_gdt_blocks);
        }
        // The first, the second and the last group of a meta block group have a copy of its
        // descriptor block.
        let first = nr * self.descs_per_block();
        let at = u64::from(group) - first;
        let copy = at <= 1 || at == self.descs_per_block() - 1;
        u64::from(has_super) + u64::from(copy)
    }

    /// The number of blocks of the inode table of one group.
    pub fn itable_blocks(&self) -> u64 {
        (u64::from(self.inodes_per_group) * u64::from(self.inode_size)).div_ceil(self.block_size)
    }

    /// The number of blocks in the group `group`. The last group can be shorter.
    pub fn blocks_in_group(&self, group: u32) -> u32 {
        self.group_size(group, self.blocks_count)
    }

    /// The number of blocks in the group `group` of a file system with `blocks` blocks.
    pub fn group_size(&self, group: u32, blocks: u64) -> u32 {
        (blocks - self.group_start(group)).min(u64::from(self.blocks_per_group)) as u32
    }
}

/// The fields of a group descriptor that the driver uses.
#[derive(Clone, Copy, Debug, Default)]
pub struct GroupDesc {
    /// The block of the block bitmap.
    pub block_bitmap: u64,
    /// The block of the inode bitmap.
    pub inode_bitmap: u64,
    /// The first block of the inode table.
    pub inode_table: u64,
}

impl GroupDesc {
    /// Reads a group descriptor of `size` bytes.
    pub fn parse(b: &[u8], size: u16) -> Self {
        let hi = |at: usize| if size >= 64 { u64::from(u32_at(b, at)) << 32 } else { 0 };
        Self {
            block_bitmap: u64::from(u32_at(b, 0)) | hi(0x20),
            inode_bitmap: u64::from(u32_at(b, 0x4)) | hi(0x24),
            inode_table: u64::from(u32_at(b, 0x8)) | hi(0x28),
        }
    }
}

/// The last second that an inode with the epoch bits can keep, `EXT4_EXTRA_TIMESTAMP_MAX`.
pub const EXTRA_TIMESTAMP_MAX: i64 = (1 << 34) - 1 + i32::MIN as i64;

/// An inode as the inode table has it.
#[derive(Clone, Debug)]
pub struct RawInode(pub Vec<u8>);

impl RawInode {
    /// The type and the permission bits.
    pub fn mode(&self) -> u16 {
        u16_at(&self.0, 0)
    }

    /// The owner.
    pub fn uid(&self) -> u32 {
        u32::from(u16_at(&self.0, 0x2)) | u32::from(u16_at(&self.0, 0x78)) << 16
    }

    /// The group.
    pub fn gid(&self) -> u32 {
        u32::from(u16_at(&self.0, 0x18)) | u32::from(u16_at(&self.0, 0x7a)) << 16
    }

    /// The size in bytes.
    pub fn size(&self) -> u64 {
        u64::from(u32_at(&self.0, 0x4)) | u64::from(u32_at(&self.0, 0x6c)) << 32
    }

    /// The number of hard links.
    pub fn links(&self) -> u16 {
        u16_at(&self.0, 0x1a)
    }

    /// The flags.
    pub fn flags(&self) -> u32 {
        u32_at(&self.0, 0x20)
    }

    /// The 60 bytes of `i_block`: the root of the extent tree, the block map, or the target of a
    /// short symbolic link.
    pub fn block(&self) -> &[u8] {
        &self.0[0x28..0x28 + 60]
    }

    /// The number of blocks, in sectors of 512 bytes, or in blocks with `HUGE_FILE`.
    pub fn blocks(&self) -> u64 {
        u64::from(u32_at(&self.0, 0x1c)) | u64::from(u16_at(&self.0, 0x74)) << 32
    }

    /// The generation, for NFS and for the checksums.
    pub fn generation(&self) -> u32 {
        u32_at(&self.0, 0x64)
    }

    /// Changes the type and the permission bits.
    pub fn set_mode(&mut self, mode: u16) {
        put16(&mut self.0, 0, mode);
    }

    /// Changes the owner.
    pub fn set_uid(&mut self, uid: u32) {
        put16(&mut self.0, 0x2, uid as u16);
        put16(&mut self.0, 0x78, (uid >> 16) as u16);
    }

    /// Changes the group.
    pub fn set_gid(&mut self, gid: u32) {
        put16(&mut self.0, 0x18, gid as u16);
        put16(&mut self.0, 0x7a, (gid >> 16) as u16);
    }

    /// Changes the size.
    pub fn set_size(&mut self, size: u64) {
        put32(&mut self.0, 0x4, size as u32);
        put32(&mut self.0, 0x6c, (size >> 32) as u32);
    }

    /// Changes the number of hard links.
    pub fn set_links(&mut self, links: u16) {
        put16(&mut self.0, 0x1a, links);
    }

    /// Changes the flags.
    pub fn set_flags(&mut self, flags: u32) {
        put32(&mut self.0, 0x20, flags);
    }

    /// Changes the number of blocks, in sectors of 512 bytes.
    pub fn set_blocks(&mut self, blocks: u64) {
        put32(&mut self.0, 0x1c, blocks as u32);
        put16(&mut self.0, 0x74, (blocks >> 32) as u16);
    }

    /// The 60 bytes of `i_block` to change.
    pub fn block_mut(&mut self) -> &mut [u8] {
        &mut self.0[0x28..0x28 + 60]
    }

    /// Changes the time at `at` and, if the inode has them, the nanoseconds and the epoch bits at
    /// `extra`. A time out of the range of the inode becomes the nearest time in the range, as
    /// `timestamp_truncate` of Linux: the epoch bits give times until the year 2446.
    pub fn set_time(&mut self, at: usize, extra: usize, sec: i64, nsec: u32) {
        let has_extra = self.extra_size() >= extra + 4 - 128;
        let max = if has_extra { EXTRA_TIMESTAMP_MAX } else { i64::from(i32::MAX) };
        let sec = sec.clamp(i64::from(i32::MIN), max);
        put32(&mut self.0, at, sec as u32);
        if has_extra {
            let epoch = ((sec - i64::from(sec as i32)) >> 32) as u32 & 3;
            put32(&mut self.0, extra, nsec << 2 | epoch);
        }
    }

    /// The size of the fields after the first 128 bytes.
    pub fn extra_size(&self) -> usize {
        if self.0.len() > 128 { usize::from(u16_at(&self.0, 0x80)) } else { 0 }
    }

    /// The time at `at` in the first 128 bytes, with the nanoseconds and the epoch bits at
    /// `extra` after them if the inode has them.
    pub fn time(&self, at: usize, extra: usize) -> (i64, u32) {
        let sec = i64::from(u32_at(&self.0, at) as i32);
        if self.extra_size() < extra + 4 - 128 {
            return (sec, 0);
        }
        let x = u32_at(&self.0, extra);
        (sec + (i64::from(x & 3) << 32), x >> 2)
    }
}

/// The magic number of an extent tree node.
pub const EXTENT_MAGIC: u16 = 0xf30a;

/// The length of an extent above which the extent is not initialized, and reads give zeros.
pub const EXTENT_INIT_MAX: u16 = 32768;

#[cfg(test)]
mod tests {
    use super::*;

    /// A superblock of 4096 blocks of 4 KiB, with 64 byte descriptors and 256 blocks in a group.
    fn meta_sb(first_meta_bg: u32) -> Superblock {
        let mut b = alloc::vec![0u8; SUPERBLOCK_SIZE];
        b[0x38..0x3a].copy_from_slice(&MAGIC.to_le_bytes());
        b[0x04..0x08].copy_from_slice(&(128u32 * 256).to_le_bytes());
        b[0x18..0x1c].copy_from_slice(&2u32.to_le_bytes());
        b[0x20..0x24].copy_from_slice(&256u32.to_le_bytes());
        b[0x28..0x2c].copy_from_slice(&16u32.to_le_bytes());
        b[0x4c..0x50].copy_from_slice(&1u32.to_le_bytes());
        b[0x58..0x5a].copy_from_slice(&256u16.to_le_bytes());
        b[0x64..0x68].copy_from_slice(&ro_compat::SPARSE_SUPER.to_le_bytes());
        let incompat = incompat::META_BG | incompat::EXTENTS | incompat::BIT64;
        b[0x60..0x64].copy_from_slice(&incompat.to_le_bytes());
        b[0xfe..0x100].copy_from_slice(&64u16.to_le_bytes());
        b[0x104..0x108].copy_from_slice(&first_meta_bg.to_le_bytes());
        Superblock::parse(&b).unwrap()
    }

    #[test]
    fn meta_bg_puts_each_descriptor_block_in_its_meta_group() {
        let sb = meta_sb(0);
        assert_eq!(sb.descs_per_block(), 64);
        // The group 0 has the superblock, the group 64 has none.
        assert_eq!(sb.desc_block(0), 1);
        assert_eq!(sb.desc_block(1), 64 * 256);
        assert_eq!(sb.base_meta_blocks(0), 2);
        assert_eq!(sb.base_meta_blocks(1), 2);
        assert_eq!(sb.base_meta_blocks(2), 0);
        assert_eq!(sb.base_meta_blocks(3), 1);
        assert_eq!(sb.base_meta_blocks(63), 1);
        assert_eq!(sb.base_meta_blocks(64), 1);
        assert_eq!(sb.base_meta_blocks(65), 1);
        assert_eq!(sb.base_meta_blocks(81), 1);
        assert_eq!(sb.base_meta_blocks(127), 1);
    }

    #[test]
    fn the_descriptor_blocks_before_the_first_meta_group_follow_the_superblock() {
        let sb = meta_sb(1);
        assert_eq!(sb.desc_block(0), 1);
        assert_eq!(sb.desc_block(1), 64 * 256);
        assert_eq!(sb.base_meta_blocks(0), 2);
        assert_eq!(sb.base_meta_blocks(3), 2);
        assert_eq!(sb.base_meta_blocks(2), 0);
        assert_eq!(sb.base_meta_blocks(64), 1);
    }

    #[test]
    fn set_time_keeps_the_time_in_the_range_of_the_inode() {
        let mut raw = RawInode(alloc::vec![0u8; 256]);
        raw.0[0x80] = 32;
        for sec in [i64::from(i32::MIN), 0, EXTRA_TIMESTAMP_MAX / 2, EXTRA_TIMESTAMP_MAX] {
            raw.set_time(0x10, 0x88, sec, 5);
            assert_eq!(raw.time(0x10, 0x88), (sec, 5));
        }
        raw.set_time(0x10, 0x88, EXTRA_TIMESTAMP_MAX + 1, 0);
        assert_eq!(raw.time(0x10, 0x88).0, EXTRA_TIMESTAMP_MAX);
        raw.set_time(0x10, 0x88, i64::from(i32::MIN) - 1, 0);
        assert_eq!(raw.time(0x10, 0x88).0, i64::from(i32::MIN));
        let mut small = RawInode(alloc::vec![0u8; 128]);
        small.set_time(0x10, 0x88, EXTRA_TIMESTAMP_MAX, 0);
        assert_eq!(small.time(0x10, 0x88).0, i64::from(i32::MAX));
    }
}

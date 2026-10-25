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
}

/// Gives the `u16` at `at`.
pub fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
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
        let blocks = self.blocks_count - u64::from(self.first_data_block);
        blocks.div_ceil(u64::from(self.blocks_per_group)) as u32
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

    /// The size of the fields after the first 128 bytes.
    fn extra_size(&self) -> usize {
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

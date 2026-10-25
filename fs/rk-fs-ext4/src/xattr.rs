//! The extended attributes of ext4, as fs/ext4/xattr.c of Linux.
//!
//! An inode keeps its attributes after its extra fields, if the inode is larger than 128 bytes,
//! and in one block that `i_file_acl` gives. Each place has a list of entries, which ends with 4
//! zero bytes, and the values are at the end of the place. An entry has the index of the prefix
//! of the name, for example 1 for `user.`, and the rest of the name. A change writes all the
//! attributes again: the attributes that fit go in the inode, in the order of their names, and
//! the others go in the block. A block that other inodes share, which Linux makes, is copied
//! before a change. A value in its own inode, the `ea_inode` feature, is not supported, so the
//! driver does not mount such a disk.

use crate::layout::{RawInode, put16, put32, u16_at, u32_at};
use crate::{Fs, Tx, crc};
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::Result;
use rk_vfs::acl::{Acl, Entry, UNDEFINED_ID, tag};

/// The magic number of the attributes of an inode and of an attribute block.
const MAGIC: u32 = 0xea02_0000;
/// The size of the header of an attribute block.
const BLOCK_HEADER: usize = 32;
/// The offset of the reference count in the header of a block.
const REFCOUNT: usize = 4;
/// The offset of the checksum in the header of a block.
const CHECKSUM: usize = 16;
/// The size of an entry without its name.
const ENTRY: usize = 16;

/// The prefixes of the names with their indexes, as `ext4_xattr_handler_map`. The ACL names have
/// no rest, so they come before `system.`.
const PREFIXES: [(u8, &[u8]); 6] = [
    (2, b"system.posix_acl_access"),
    (3, b"system.posix_acl_default"),
    (1, b"user."),
    (4, b"trusted."),
    (6, b"security."),
    (7, b"system."),
];

/// The name of an attribute on the disk: the index of the prefix and the rest of the name.
pub(crate) type Key = (u8, Vec<u8>);

/// The attributes of an inode.
pub(crate) type Attrs = BTreeMap<Key, Vec<u8>>;

/// Gives the key of the full name `name`. A name with an unknown prefix gives `EOPNOTSUPP`.
pub(crate) fn key(name: &[u8]) -> Result<Key> {
    for (index, prefix) in PREFIXES {
        if index == 2 || index == 3 {
            if name == prefix {
                return Ok((index, Vec::new()));
            }
        } else if let Some(rest) = name.strip_prefix(prefix) {
            if rest.len() > 255 {
                return Err(Errno::ERANGE);
            }
            return Ok((index, rest.to_vec()));
        }
    }
    Err(Errno::EOPNOTSUPP)
}

/// Gives the full name of `key`, or `None` for an unknown index.
pub(crate) fn name(key: &Key) -> Option<Vec<u8>> {
    let (_, prefix) = PREFIXES.iter().find(|(i, _)| *i == key.0)?;
    let mut name = prefix.to_vec();
    name.extend_from_slice(&key.1);
    Some(name)
}

/// The version of an ACL on the disk, `EXT4_ACL_VERSION`.
const ACL_VERSION: u32 = 1;

/// The key is the key of an ACL.
pub(crate) fn is_acl(key: &Key) -> bool {
    key.0 == 2 || key.0 == 3
}

/// Changes the value of an ACL from the format of the system calls to the format on the disk,
/// as `ext4_acl_to_disk`. The disk keeps the ID only in the entries of a named user and a named
/// group, and an entry without an ID has 4 bytes.
pub(crate) fn acl_to_disk(value: &[u8]) -> Result<Vec<u8>> {
    let acl = Acl::from_xattr(value)?.ok_or(Errno::EINVAL)?;
    let mut out = ACL_VERSION.to_le_bytes().to_vec();
    for e in &acl.0 {
        out.extend_from_slice(&e.tag.to_le_bytes());
        out.extend_from_slice(&e.perm.to_le_bytes());
        if matches!(e.tag, tag::USER | tag::GROUP) {
            out.extend_from_slice(&e.id.to_le_bytes());
        }
    }
    Ok(out)
}

/// Changes the value of an ACL from the format on the disk to the format of the system calls,
/// as `ext4_acl_from_disk`. A damaged value gives `EIO`.
pub(crate) fn acl_from_disk(disk: &[u8]) -> Result<Vec<u8>> {
    if disk.len() < 4 || u32_at(disk, 0) != ACL_VERSION {
        return Err(Errno::EIO);
    }
    let mut entries = Vec::new();
    let mut at = 4;
    while at < disk.len() {
        if at + 4 > disk.len() {
            return Err(Errno::EIO);
        }
        let (tag, perm) = (u16_at(disk, at), u16_at(disk, at + 2));
        let id = match tag {
            tag::USER | tag::GROUP if at + 8 <= disk.len() => {
                at += 8;
                u32_at(disk, at - 4)
            }
            tag::USER_OBJ | tag::GROUP_OBJ | tag::MASK | tag::OTHER => {
                at += 4;
                UNDEFINED_ID
            }
            _ => return Err(Errno::EIO),
        };
        entries.push(Entry { tag, perm, id });
    }
    Ok(Acl(entries).to_xattr())
}

fn pad(n: usize) -> usize {
    (n + 3) & !3
}

/// The size of the entry of a name of `len` bytes.
fn entry_size(len: usize) -> usize {
    pad(ENTRY + len)
}

/// The hash of an entry, as `ext4_xattr_hash_entry`.
fn hash_entry(name: &[u8], value: &[u8]) -> u32 {
    let mut hash = 0u32;
    for &c in name {
        hash = (hash << 5) ^ (hash >> 27) ^ u32::from(c);
    }
    let mut padded = value.to_vec();
    padded.resize(pad(value.len()), 0);
    for word in padded.chunks(4) {
        hash = (hash << 16) ^ (hash >> 16) ^ u32_at(word, 0);
    }
    hash
}

/// Reads the entries of `area` from `first`. The values are at their offsets from `base`.
fn parse(area: &[u8], first: usize, base: usize, out: &mut Attrs) -> Result<()> {
    let mut at = first;
    loop {
        if at + 4 > area.len() {
            return Err(Errno::EUCLEAN);
        }
        if u32_at(area, at) == 0 {
            return Ok(());
        }
        if at + ENTRY > area.len() {
            return Err(Errno::EUCLEAN);
        }
        let len = usize::from(area[at]);
        let index = area[at + 1];
        let offs = usize::from(u16_at(area, at + 2));
        let inum = u32_at(area, at + 4);
        let size = u32_at(area, at + 8) as usize;
        let name = area.get(at + ENTRY..at + ENTRY + len).ok_or(Errno::EUCLEAN)?;
        if inum != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let value = area.get(base + offs..base + offs + size).ok_or(Errno::EUCLEAN)?;
        out.insert((index, name.to_vec()), value.to_vec());
        at += entry_size(len);
    }
}

/// Tells if the attributes `list` fit in `len` bytes with the entries from `first`.
fn fits(list: &[(&Key, &Vec<u8>)], first: usize, len: usize) -> bool {
    let entries: usize = list.iter().map(|(k, _)| entry_size(k.1.len())).sum();
    let values: usize = list.iter().map(|(_, v)| pad(v.len())).sum();
    first + entries + 4 + values <= len
}

/// Writes the attributes `list` in `area`, which is zero, with the entries from `first`. The
/// offsets of the values are from `base`. The values go from the end of the area down.
fn write_entries(area: &mut [u8], first: usize, base: usize, list: &[(&Key, &Vec<u8>)]) {
    let mut at = first;
    let mut end = area.len();
    for (key, value) in list {
        let offs = if value.is_empty() {
            0
        } else {
            end -= pad(value.len());
            area[end..end + value.len()].copy_from_slice(value);
            end - base
        };
        area[at] = key.1.len() as u8;
        area[at + 1] = key.0;
        put16(area, at + 2, offs as u16);
        put32(area, at + 8, value.len() as u32);
        put32(area, at + 12, hash_entry(&key.1, value));
        area[at + ENTRY..at + ENTRY + key.1.len()].copy_from_slice(&key.1);
        at += entry_size(key.1.len());
    }
}

/// The offset in the inode where its attributes start, or `None` if the inode has no room for
/// them.
fn ibody_start(raw: &RawInode) -> Option<usize> {
    let start = 128 + raw.extra_size();
    (raw.0.len() > 128 && start.is_multiple_of(4) && start + 8 <= raw.0.len()).then_some(start)
}

impl RawInode {
    /// The block of the extended attributes, or 0.
    pub(crate) fn file_acl(&self) -> u64 {
        u64::from(u32_at(&self.0, 0x68)) | u64::from(u16_at(&self.0, 0x76)) << 32
    }

    /// Changes the block of the extended attributes.
    pub(crate) fn set_file_acl(&mut self, block: u64) {
        put32(&mut self.0, 0x68, block as u32);
        put16(&mut self.0, 0x76, (block >> 32) as u16);
    }
}

impl Fs {
    /// Reads the extended attributes of the inode `raw`.
    pub(crate) fn xattrs(&self, raw: &RawInode) -> Result<Attrs> {
        let mut out = Attrs::new();
        if let Some(start) = ibody_start(raw)
            && u32_at(&raw.0, start) == MAGIC
        {
            parse(&raw.0[start..], 4, 4, &mut out)?;
        }
        let block = raw.file_acl();
        if block != 0 {
            let data = self.read_block(block)?;
            if u32_at(&data, 0) != MAGIC || u32_at(&data, 8) != 1 {
                return Err(Errno::EUCLEAN);
            }
            parse(&data, BLOCK_HEADER, 0, &mut out)?;
        }
        Ok(out)
    }

    /// Writes the attribute block `data` at `block`, with its checksum.
    fn write_xattr_block(&self, block: u64, data: &mut [u8]) -> Result<()> {
        if self.metadata_csum() {
            put32(data, CHECKSUM, 0);
            let csum = crc::crc32c(self.csum_seed, &block.to_le_bytes());
            put32(data, CHECKSUM, crc::crc32c(csum, data));
        }
        self.write(block * self.sb.block_size, data)
    }
}

impl Tx<'_> {
    /// Removes the use of the attribute block `block` by one inode. The last use frees the
    /// block.
    pub(crate) fn put_xattr_block(&mut self, block: u64) -> Result<()> {
        let fs = self.fs;
        let mut data = fs.read_block(block)?;
        let refs = u32_at(&data, REFCOUNT);
        if u32_at(&data, 0) != MAGIC || refs <= 1 {
            return self.free_blocks(block, 1);
        }
        put32(&mut data, REFCOUNT, refs - 1);
        fs.write_xattr_block(block, &mut data)
    }

    /// Writes `attrs` as the extended attributes of the inode `ino` with `raw`. The caller saves
    /// the inode. Gives `ENOSPC` if the attributes do not fit in the inode and one block.
    pub(crate) fn write_xattrs(
        &mut self,
        ino: u32,
        raw: &mut RawInode,
        attrs: &Attrs,
    ) -> Result<()> {
        let fs = self.fs;
        let bs = fs.sb.block_size as usize;
        let start = ibody_start(raw);
        let room = start.map_or(0, |s| raw.0.len() - s);
        let mut inside = Vec::new();
        let mut outside = Vec::new();
        for attr in attrs {
            inside.push(attr);
            if start.is_none() || !fits(&inside, 4, room) {
                inside.pop();
                outside.push(attr);
            }
        }
        if !fits(&outside, BLOCK_HEADER, bs) {
            return Err(Errno::ENOSPC);
        }
        if let Some(start) = start {
            let area = &mut raw.0[start..];
            area.fill(0);
            if !inside.is_empty() {
                put32(area, 0, MAGIC);
                write_entries(area, 4, 4, &inside);
            }
        }
        let old = raw.file_acl();
        let sectors = (bs / 512) as u64;
        if outside.is_empty() {
            if old != 0 {
                self.put_xattr_block(old)?;
                raw.set_file_acl(0);
                raw.set_blocks(raw.blocks().saturating_sub(sectors));
            }
            return Ok(());
        }
        let shared = old != 0 && u32_at(&fs.read_block(old)?, REFCOUNT) > 1;
        let block = if old == 0 || shared {
            let (block, _) = self.alloc_blocks(fs.goal(ino), 1)?;
            if shared {
                self.put_xattr_block(old)?;
            } else {
                raw.set_blocks(raw.blocks() + sectors);
            }
            block
        } else {
            old
        };
        let mut data = vec![0u8; bs];
        put32(&mut data, 0, MAGIC);
        put32(&mut data, REFCOUNT, 1);
        put32(&mut data, 8, 1);
        // The entries of a block are in the order of `ext4_xattr_find_entry`: the index, the
        // length of the name, and the name.
        outside.sort_by(|a, b| (a.0.0, a.0.1.len(), &a.0.1).cmp(&(b.0.0, b.0.1.len(), &b.0.1)));
        write_entries(&mut data, BLOCK_HEADER, 0, &outside);
        // The hash of the block, as `ext4_xattr_rehash`.
        let mut hash = 0u32;
        let mut at = BLOCK_HEADER;
        while u32_at(&data, at) != 0 {
            hash = (hash << 16) ^ (hash >> 16) ^ u32_at(&data, at + 12);
            at += entry_size(usize::from(data[at]));
        }
        put32(&mut data, 12, hash);
        fs.write_xattr_block(block, &mut data)?;
        raw.set_file_acl(block);
        Ok(())
    }
}

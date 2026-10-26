//! The extended attributes of ext4, as fs/ext4/xattr.c of Linux.
//!
//! An inode keeps its attributes after its extra fields, if the inode is larger than 128 bytes,
//! and in one block that `i_file_acl` gives. Each place has a list of entries, which ends with 4
//! zero bytes, and the values are at the end of the place. An entry has the index of the prefix
//! of the name, for example 1 for `user.`, and the rest of the name. A change writes all the
//! attributes again: the attributes that fit go in the inode, in the order of their names, and
//! the others go in the block. A block that other inodes share, which Linux makes, is copied
//! before a change.
//!
//! With the `ea_inode` feature, a large value is in the data of an inode of its own, and the
//! entry has the number of that inode. The value inode keeps the hash of the value in its access
//! time, and the count of the references to it in its change time and in `i_version`. The count
//! of blocks of the inode with the attribute also counts the blocks of the value, as the quota of
//! Linux does.

use crate::layout::{self, RawInode, flags, put16, put32, u16_at, u32_at};
use crate::{Fs, Tx, crc};
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::Result;
use rk_vfs::acl::{Acl, Entry, UNDEFINED_ID, tag};
use rk_vfs::inode::FiemapExtent;

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
/// A value is in an inode of its own if its padded size is more than the block size less this
/// gap, as `EXT4_XATTR_MIN_LARGE_EA_SIZE`: the header of a block, an entry with a name of 3
/// bytes, and the 4 zero bytes at the end of the entries.
const LARGE_GAP: usize = BLOCK_HEADER + 20 + 4;

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
/// as `ext4_acl_from_disk` and `ext4_get_acl`. An ACL with no entries gives `ENODATA`, as a file
/// without an ACL. A damaged value gives `EINVAL`.
pub(crate) fn acl_from_disk(disk: &[u8]) -> Result<Vec<u8>> {
    if disk.len() < 4 || u32_at(disk, 0) != ACL_VERSION {
        return Err(Errno::EINVAL);
    }
    if disk.len() == 4 {
        return Err(Errno::ENODATA);
    }
    let mut entries = Vec::new();
    let mut at = 4;
    while at < disk.len() {
        if at + 4 > disk.len() {
            return Err(Errno::EINVAL);
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
            _ => return Err(Errno::EINVAL),
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

/// Where an entry keeps its value.
enum Stored {
    /// The value is in the area of the entry.
    Here(Vec<u8>),
    /// The value is in the inode, with the size, as the `ea_inode` feature.
    Inode(u32, usize),
}

/// The entries of an area, in the order of the area.
type Entries = Vec<(Key, Stored)>;

/// An attribute to write: the key, the value, and the inode of the value. The inode is `None`
/// for a value in the entry, and 0 for a value that needs a new inode.
struct Slot<'a> {
    key: &'a Key,
    value: &'a [u8],
    inode: Option<u32>,
}

impl Slot<'_> {
    /// The bytes of the value in the area.
    fn value_size(&self) -> usize {
        if self.inode.is_some() { 0 } else { pad(self.value.len()) }
    }
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
fn parse(area: &[u8], first: usize, base: usize, out: &mut Entries) -> Result<()> {
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
        let stored = if inum != 0 {
            Stored::Inode(inum, size)
        } else {
            Stored::Here(area.get(base + offs..base + offs + size).ok_or(Errno::EUCLEAN)?.to_vec())
        };
        out.push(((index, name.to_vec()), stored));
        at += entry_size(len);
    }
}

/// Tells if the attributes `list` fit in `len` bytes with the entries from `first`.
fn fits(list: &[&Slot<'_>], first: usize, len: usize) -> bool {
    let entries: usize = list.iter().map(|s| entry_size(s.key.1.len())).sum();
    let values: usize = list.iter().map(|s| s.value_size()).sum();
    first + entries + 4 + values <= len
}

/// Writes the attributes `list` in `area`, which is zero, with the entries from `first`. The
/// offsets of the values are from `base`. The values go from the end of the area down. The
/// hash of a value in an inode is `seed` with the value, as `ext4_xattr_inode_hash`, and the
/// hash of the entry uses it in place of the value.
fn write_entries(area: &mut [u8], first: usize, base: usize, list: &[&Slot<'_>], seed: u32) {
    let mut at = first;
    let mut end = area.len();
    for slot in list {
        let (key, value) = (slot.key, slot.value);
        let offs = if value.is_empty() || slot.inode.is_some() {
            0
        } else {
            end -= pad(value.len());
            area[end..end + value.len()].copy_from_slice(value);
            end - base
        };
        let hash = match slot.inode {
            Some(inum) => {
                put32(area, at + 4, inum);
                hash_entry(&key.1, &crc::crc32c(seed, value).to_le_bytes())
            }
            None => hash_entry(&key.1, value),
        };
        area[at] = key.1.len() as u8;
        area[at + 1] = key.0;
        put16(area, at + 2, offs as u16);
        put32(area, at + 8, value.len() as u32);
        put32(area, at + 12, hash);
        area[at + ENTRY..at + ENTRY + key.1.len()].copy_from_slice(&key.1);
        at += entry_size(key.1.len());
    }
}

/// The count of the references to the value inode `raw`, as `ext4_xattr_inode_get_ref`.
fn ea_refs(raw: &RawInode) -> u64 {
    u64::from(u32_at(&raw.0, 0xc)) << 32 | u64::from(u32_at(&raw.0, 0x24))
}

/// Sets the count of the references to the value inode `raw`, as `ext4_xattr_inode_set_ref`.
fn set_ea_refs(raw: &mut RawInode, refs: u64) {
    raw.set_time(0xc, 0x84, (refs >> 32) as i64, 0);
    put32(&mut raw.0, 0x24, refs as u32);
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
    /// Tells if a value can be in an inode of its own.
    fn ea_inode(&self) -> bool {
        self.sb.incompat & layout::incompat::EA_INODE != 0
    }

    /// The count of 512-byte sectors that a value of `len` bytes in an inode adds to the inode
    /// with the attribute, as `ext4_xattr_inode_alloc_quota`.
    fn ea_sectors(&self, len: usize) -> u64 {
        let bs = self.sb.block_size;
        (len as u64).div_ceil(bs) * (bs / 512)
    }

    /// Reads the entries of the extended attributes of the inode `raw`: the entries in the inode,
    /// and the entries in the block.
    fn xattr_entries(&self, raw: &RawInode) -> Result<(Entries, Entries)> {
        let (mut inside, mut outside) = (Entries::new(), Entries::new());
        if let Some(start) = ibody_start(raw)
            && u32_at(&raw.0, start) == MAGIC
        {
            parse(&raw.0[start..], 4, 4, &mut inside)?;
        }
        let block = raw.file_acl();
        if block != 0 {
            let data = self.read_block(block)?;
            if u32_at(&data, 0) != MAGIC || u32_at(&data, 8) != 1 {
                return Err(Errno::EUCLEAN);
            }
            parse(&data, BLOCK_HEADER, 0, &mut outside)?;
        }
        let in_inode = inside.iter().chain(&outside).any(|(_, s)| matches!(s, Stored::Inode(..)));
        if in_inode && !self.ea_inode() {
            return Err(Errno::EUCLEAN);
        }
        Ok((inside, outside))
    }

    /// Reads the extended attributes of the inode `raw`.
    pub(crate) fn xattrs(&self, raw: &RawInode) -> Result<Attrs> {
        let (inside, outside) = self.xattr_entries(raw)?;
        let mut out = Attrs::new();
        for (key, stored) in inside.into_iter().chain(outside) {
            let value = match stored {
                Stored::Here(value) => value,
                Stored::Inode(inum, size) => self.ea_value(inum, size)?,
            };
            out.insert(key, value);
        }
        Ok(out)
    }

    /// Reads the value of `size` bytes in the inode `inum`, as `ext4_xattr_inode_get`. An inode
    /// without `EXT4_EA_INODE_FL` or with another size gives `EUCLEAN`.
    fn ea_value(&self, inum: u32, size: usize) -> Result<Vec<u8>> {
        if inum < self.sb.first_ino || inum > self.inodes_count() {
            return Err(Errno::EUCLEAN);
        }
        let raw = self.read_inode(inum)?;
        if raw.flags() & flags::EA_INODE == 0 || raw.size() != size as u64 {
            return Err(Errno::EUCLEAN);
        }
        let mut value = vec![0u8; size];
        if self.read_data(&raw, 0, &mut value)? != size {
            return Err(Errno::EUCLEAN);
        }
        Ok(value)
    }

    /// Gives the extent of the extended attributes of the inode `ino` with `raw`, as
    /// `ext4_iomap_xattr_fiemap`. Attributes in the inode give the area after the extra fields,
    /// and else the attribute block gives one block. As Linux, the address of the area is from
    /// the start of the block of the inode, without the offset of the inode in that block.
    pub(crate) fn xattr_extent(&self, ino: u32, raw: &RawInode) -> Result<Option<FiemapExtent>> {
        let bs = self.sb.block_size;
        if let Some(start) = ibody_start(raw)
            && u32_at(&raw.0, start) == MAGIC
        {
            let block = self.inode_at(ino)? / bs;
            return Ok(Some(FiemapExtent {
                logical: 0,
                physical: block * bs + start as u64,
                length: (raw.0.len() - start) as u64,
                unwritten: false,
                inline: true,
                delalloc: false,
            }));
        }
        let block = raw.file_acl();
        Ok((block != 0).then_some(FiemapExtent {
            logical: 0,
            physical: block * bs,
            length: bs,
            unwritten: false,
            inline: false,
            delalloc: false,
        }))
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
    /// block, and removes the references of its entries to their value inodes.
    fn put_xattr_block(&mut self, block: u64) -> Result<()> {
        let fs = self.fs;
        let mut data = fs.read_block(block)?;
        let refs = u32_at(&data, REFCOUNT);
        if u32_at(&data, 0) != MAGIC || refs <= 1 {
            if fs.ea_inode() && u32_at(&data, 0) == MAGIC {
                let mut entries = Entries::new();
                parse(&data, BLOCK_HEADER, 0, &mut entries)?;
                for (_, stored) in entries {
                    if let Stored::Inode(inum, _) = stored {
                        self.change_ea_refs(inum, -1)?;
                    }
                }
            }
            return self.free_blocks(block, 1);
        }
        put32(&mut data, REFCOUNT, refs - 1);
        fs.write_xattr_block(block, &mut data)
    }

    /// Makes the extra fields of the inode `ino` with `raw` larger, as
    /// `ext4_expand_extra_isize_ea`. The attributes that then do not fit in the inode go to its
    /// block. If the block has no room for them, the size `s_min_extra_isize` is tried. The
    /// caller saves the inode. Gives `ENOSPC` and keeps `raw` if no size fits.
    pub(crate) fn expand_extra_isize(&mut self, ino: u32, raw: &mut RawInode) -> Result<()> {
        let fs = self.fs;
        let attrs = fs.xattrs(raw)?;
        let old = raw.extra_size();
        for new in [fs.want_extra_isize(), usize::from(fs.sb.min_extra_isize)] {
            if new <= old || !new.is_multiple_of(4) || 128 + new > raw.0.len() {
                continue;
            }
            let mut next = raw.clone();
            next.0[128 + old..128 + new].fill(0);
            put16(&mut next.0, 0x80, new as u16);
            match self.rewrite_xattrs(ino, raw, &mut next, &attrs) {
                Ok(()) => {
                    *raw = next;
                    return Ok(());
                }
                Err(Errno::ENOSPC) => {}
                Err(e) => return Err(e),
            }
        }
        Err(Errno::ENOSPC)
    }

    /// Writes `attrs` as the extended attributes of the inode `ino` with `raw`. The caller saves
    /// the inode. Gives `ENOSPC` if the attributes do not fit in the inode and one block.
    ///
    /// With the `ea_inode` feature, a large value goes to an inode of its own, as
    /// `ext4_xattr_set_handle`. If the attributes do not fit, the largest value in the block
    /// also goes to an inode of its own, until they fit. A value that has an inode and does not
    /// change keeps its inode.
    pub(crate) fn write_xattrs(
        &mut self,
        ino: u32,
        raw: &mut RawInode,
        attrs: &Attrs,
    ) -> Result<()> {
        let old = raw.clone();
        self.rewrite_xattrs(ino, &old, raw, attrs)
    }

    /// Writes `attrs` as the extended attributes of the inode `ino` with `raw`, as
    /// [`Tx::write_xattrs`]. The attributes before the change are in `before`.
    fn rewrite_xattrs(
        &mut self,
        ino: u32,
        before: &RawInode,
        raw: &mut RawInode,
        attrs: &Attrs,
    ) -> Result<()> {
        let fs = self.fs;
        let bs = fs.sb.block_size as usize;
        let (old_inside, old_outside) = fs.xattr_entries(before)?;
        let old = before.file_acl();
        let shared = old != 0 && u32_at(&fs.read_block(old)?, REFCOUNT) > 1;
        let mut slots = Vec::new();
        for (key, value) in attrs {
            let kept = old_inside.iter().chain(&old_outside).find_map(|(k, s)| match s {
                Stored::Inode(inum, size) if k == key && *size == value.len() => Some(*inum),
                _ => None,
            });
            let inode = match kept {
                Some(inum) if fs.ea_value(inum, value.len())? == *value => Some(inum),
                _ if fs.ea_inode() && pad(value.len()) > bs - LARGE_GAP => Some(0),
                _ => None,
            };
            slots.push(Slot { key, value, inode });
        }
        let start = ibody_start(raw);
        let room = start.map_or(0, |s| raw.0.len() - s);
        let outside_at = loop {
            let mut inside = Vec::new();
            let mut outside = Vec::new();
            for (i, slot) in slots.iter().enumerate() {
                inside.push(slot);
                if start.is_none() || !fits(&inside, 4, room) {
                    inside.pop();
                    outside.push(i);
                }
            }
            let list: Vec<_> = outside.iter().map(|&i| &slots[i]).collect();
            if fits(&list, BLOCK_HEADER, bs) {
                break outside;
            }
            let largest = outside
                .iter()
                .copied()
                .filter(|&i| slots[i].inode.is_none() && !slots[i].value.is_empty())
                .max_by_key(|&i| slots[i].value.len());
            match largest {
                Some(i) if fs.ea_inode() => slots[i].inode = Some(0),
                _ => return Err(Errno::ENOSPC),
            }
        };
        let mut made = Vec::new();
        for slot in &mut slots {
            if slot.inode == Some(0) {
                match self.make_ea_inode(ino, raw, slot.value) {
                    Ok(inum) => {
                        slot.inode = Some(inum);
                        made.push(inum);
                    }
                    Err(e) => {
                        for inum in made {
                            self.change_ea_refs(inum, 0)?;
                        }
                        return Err(e);
                    }
                }
            }
        }
        let result = self.write_slots(ino, raw, &slots, &outside_at, shared);
        // A change of the references frees a value inode without references.
        let mut refs = BTreeMap::<u32, i64>::new();
        if result.is_ok() {
            for slot in &slots {
                if let Some(inum) = slot.inode {
                    *refs.entry(inum).or_default() += 1;
                }
            }
            // The entries of a shared block stay, so their references stay.
            let gone = old_inside.iter().chain(old_outside.iter().filter(|_| !shared));
            for (_, stored) in gone {
                if let Stored::Inode(inum, _) = stored {
                    *refs.entry(*inum).or_default() -= 1;
                }
            }
            let old_sectors: u64 = old_inside
                .iter()
                .chain(&old_outside)
                .filter_map(|(_, s)| match s {
                    Stored::Inode(_, size) => Some(fs.ea_sectors(*size)),
                    Stored::Here(_) => None,
                })
                .sum();
            let new_sectors: u64 = slots
                .iter()
                .filter(|s| s.inode.is_some())
                .map(|s| fs.ea_sectors(s.value.len()))
                .sum();
            raw.set_blocks((raw.blocks() + new_sectors).saturating_sub(old_sectors));
        }
        for inum in made {
            refs.entry(inum).or_default();
        }
        for (inum, delta) in refs {
            self.change_ea_refs(inum, delta)?;
        }
        result
    }

    /// Writes the attributes `slots` of the inode `ino` with `raw`: the attributes at the
    /// indexes `outside` go to the block, and the others go in the inode. `shared` tells if the
    /// old block has other inodes.
    fn write_slots(
        &mut self,
        ino: u32,
        raw: &mut RawInode,
        slots: &[Slot<'_>],
        outside: &[usize],
        shared: bool,
    ) -> Result<()> {
        let fs = self.fs;
        let bs = fs.sb.block_size as usize;
        let inside: Vec<_> = slots
            .iter()
            .enumerate()
            .filter(|(i, _)| !outside.contains(i))
            .map(|(_, s)| s)
            .collect();
        let mut outside: Vec<_> = outside.iter().map(|&i| &slots[i]).collect();
        if let Some(start) = ibody_start(raw) {
            let area = &mut raw.0[start..];
            area.fill(0);
            if !inside.is_empty() {
                put32(area, 0, MAGIC);
                write_entries(area, 4, 4, &inside, fs.csum_seed);
            }
        }
        let old = raw.file_acl();
        // With `bigalloc` the block has a cluster.
        let sectors = fs.cluster_sectors();
        if outside.is_empty() {
            if old != 0 {
                // The references of the entries of a block that only this inode has are
                // removed by the caller.
                if shared {
                    self.put_xattr_block(old)?
                } else {
                    self.free_blocks(old, 1)?
                }
                raw.set_file_acl(0);
                raw.set_blocks(raw.blocks().saturating_sub(sectors));
            }
            return Ok(());
        }
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
        outside.sort_by(|a, b| {
            (a.key.0, a.key.1.len(), &a.key.1).cmp(&(b.key.0, b.key.1.len(), &b.key.1))
        });
        write_entries(&mut data, BLOCK_HEADER, 0, &outside, fs.csum_seed);
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

    /// Removes the extended attributes of the inode `raw`, which is freed: the references of
    /// the entries in the inode to their value inodes, and the use of the block.
    pub(crate) fn release_xattrs(&mut self, raw: &mut RawInode) -> Result<()> {
        let fs = self.fs;
        if fs.ea_inode()
            && let Some(start) = ibody_start(raw)
            && u32_at(&raw.0, start) == MAGIC
        {
            let mut entries = Entries::new();
            parse(&raw.0[start..], 4, 4, &mut entries)?;
            for (_, stored) in entries {
                if let Stored::Inode(inum, _) = stored {
                    self.change_ea_refs(inum, -1)?;
                }
            }
        }
        let block = raw.file_acl();
        if block != 0 {
            self.put_xattr_block(block)?;
            raw.set_file_acl(0);
        }
        Ok(())
    }

    /// Adds `delta` to the count of the references to the value inode `inum`, as
    /// `ext4_xattr_inode_update_ref`. A count of 0 frees the inode.
    fn change_ea_refs(&mut self, inum: u32, delta: i64) -> Result<()> {
        let fs = self.fs;
        if inum < fs.sb.first_ino || inum > fs.inodes_count() {
            return Err(Errno::EUCLEAN);
        }
        let mut raw = fs.read_inode(inum)?;
        if raw.flags() & flags::EA_INODE == 0 {
            return Err(Errno::EUCLEAN);
        }
        let refs = ea_refs(&raw).saturating_add_signed(delta);
        if delta == 0 && refs != 0 {
            return Ok(());
        }
        if refs == 0 {
            raw.set_links(0);
            fs.write_inode(inum, &mut raw)?;
            return self.release(inum);
        }
        set_ea_refs(&mut raw, refs);
        fs.write_inode(inum, &mut raw)
    }

    /// Makes a new value inode with `value` for the inode `ino` with `raw`, as
    /// `ext4_xattr_inode_create`. The new inode has no reference.
    fn make_ea_inode(&mut self, ino: u32, raw: &RawInode, value: &[u8]) -> Result<u32> {
        let fs = self.fs;
        let inum = self.alloc_inode(ino, false)?;
        let size = usize::from(fs.sb.inode_size);
        let mut new = RawInode(vec![0u8; size]);
        if size > 128 {
            put16(&mut new.0, 0x80, fs.want_extra_isize().min(size - 128) as u16);
        }
        new.set_mode(0o100600);
        new.set_uid(raw.uid());
        new.set_gid(raw.gid());
        new.set_links(1);
        put32(&mut new.0, 0x64, self.next_generation());
        let t = rk_vfs::now();
        new.set_time(0x10, 0x88, t.sec, t.nsec);
        if new.extra_size() >= 0x98 - 128 {
            new.set_time(0x90, 0x94, t.sec, t.nsec);
        }
        new.set_flags(flags::EA_INODE);
        if fs.sb.incompat & layout::incompat::EXTENTS != 0 {
            new.set_flags(flags::EA_INODE | flags::EXTENTS);
            Tx::empty_tree(&mut new);
        }
        let written = self.write_data(inum, &mut new, 0, value);
        // The access time keeps the hash of the value.
        new.set_time(0x8, 0x8c, i64::from(crc::crc32c(fs.csum_seed, value)), 0);
        set_ea_refs(&mut new, 0);
        fs.write_inode(inum, &mut new)?;
        match written {
            Ok(n) if n == value.len() => Ok(inum),
            result => {
                self.change_ea_refs(inum, 0)?;
                Err(result.err().unwrap_or(Errno::ENOSPC))
            }
        }
    }
}

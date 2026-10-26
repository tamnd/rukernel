//! The directories. An entry has the inode, the length of the record, the length of the name,
//! the type of the file and the name. The records of a block fill the block. With
//! `metadata_csum`, each block ends with a record of 12 bytes that has the checksum.
//!
//! A directory of one block that becomes full gets an htree index if the file system has
//! `dir_index`, as Linux. The `htree` module finds and adds the entries of an indexed directory.
//! Without `dir_index`, a new entry in a directory with an index first changes the index blocks
//! into empty blocks and clears the `INDEX` flag, so the directory is a list. `readdir` gives
//! the entries in the order of the blocks, also with an index.

use crate::layout::{self, RawInode, flags, put16, put32, u16_at, u32_at};
use crate::node::{Node, entry_code, entry_type};
use crate::{Fs, Tx, crc};
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::{DirEntry, FileType, Result};

/// The length of the checksum record at the end of a block.
const TAIL: usize = 12;
/// The file type of the checksum record.
const TAIL_TYPE: u8 = 0xde;

/// The length of a record for a name of `len` bytes.
pub(crate) fn rec_len(len: usize) -> usize {
    (8 + len).next_multiple_of(4)
}

/// Finds the entry `name` in the block `lblock` of a directory, which has the data `data`.
pub(crate) fn search_block(data: &[u8], lblock: u64, name: &[u8]) -> Result<Option<Slot>> {
    let mut at = 0;
    let mut prev = None;
    while at + 8 <= data.len() {
        let rec = usize::from(u16_at(data, at + 4));
        let name_len = usize::from(data[at + 6]);
        if rec < 8 || at + rec > data.len() || at + 8 + name_len > data.len() {
            return Err(Errno::EUCLEAN);
        }
        let ino = u32_at(data, at);
        if ino != 0 && &data[at + 8..at + 8 + name_len] == name {
            return Ok(Some(Slot { lblock, at, prev, ino }));
        }
        prev = Some(at);
        at += rec;
    }
    Ok(None)
}

/// An entry that a search found.
pub(crate) struct Slot {
    /// The block of the directory.
    lblock: u64,
    /// The offset of the record in the block.
    at: usize,
    /// The offset of the record before it in the block.
    prev: Option<usize>,
    /// The inode of the entry.
    pub ino: u32,
}

impl Fs {
    /// The length of the checksum record of a block of a directory.
    pub(crate) fn tail(&self) -> usize {
        if self.metadata_csum() { TAIL } else { 0 }
    }

    /// Reads the block `lblock` of a directory. Gives the block of the disk and the data.
    pub(crate) fn dir_block(&self, raw: &RawInode, lblock: u64) -> Result<(u64, Vec<u8>)> {
        let Some((block, true)) = self.map(raw, lblock)? else { return Err(Errno::EUCLEAN) };
        Ok((block, self.read_block(block)?))
    }

    /// Gives the entry at the byte `pos` of the directory, or the next entry after it that has
    /// an inode, and the position after the entry.
    pub(crate) fn entry_at(&self, raw: &RawInode, mut pos: u64) -> Result<Option<(DirEntry, u64)>> {
        let size = raw.size();
        let bs = self.sb.block_size;
        let mut block: Option<(u64, Vec<u8>)> = None;
        while pos < size {
            let lblock = pos / bs;
            if block.as_ref().is_none_or(|(l, _)| *l != lblock) {
                let mut data = vec![0u8; bs as usize];
                self.read_data(raw, lblock * bs, &mut data)?;
                block = Some((lblock, data));
            }
            let Some((_, data)) = &block else { return Err(Errno::EIO) };
            let at = (pos % bs) as usize;
            if at + 8 > data.len() {
                return Err(Errno::EUCLEAN);
            }
            let ino = u32_at(data, at);
            let rec = u64::from(u16_at(data, at + 4));
            let name_len = usize::from(data[at + 6]);
            if rec < 8 || at as u64 + rec > bs || at + 8 + name_len > data.len() {
                return Err(Errno::EUCLEAN);
            }
            pos += rec;
            if ino == 0 || name_len == 0 {
                continue;
            }
            let name = data[at + 8..at + 8 + name_len].to_vec();
            let kind = match entry_type(data[at + 7]) {
                Some(kind) if self.sb.incompat & layout::incompat::FILETYPE != 0 => kind,
                _ => self.inode(ino)?.kind(),
            };
            return Ok(Some((DirEntry { ino: u64::from(ino), kind, name }, pos)));
        }
        Ok(None)
    }

    /// Finds the entry `name` in a directory. A directory with a valid index uses the index,
    /// except for `.` and `..`, which are in the block 0.
    pub(crate) fn find_entry(&self, raw: &RawInode, name: &[u8]) -> Result<Option<Slot>> {
        if self.is_dx(raw)
            && name != b"."
            && name != b".."
            && let Some(found) = self.dx_find(raw, name)?
        {
            return Ok(found);
        }
        let bs = self.sb.block_size;
        for lblock in 0..raw.size() / bs {
            let mut data = vec![0u8; bs as usize];
            self.read_data(raw, lblock * bs, &mut data)?;
            if let Some(slot) = search_block(&data, lblock, name)? {
                return Ok(Some(slot));
            }
        }
        Ok(None)
    }

    /// Tells if a directory has only `.` and `..`.
    pub(crate) fn is_empty_dir(&self, raw: &RawInode) -> Result<bool> {
        let mut pos = 0;
        while let Some((entry, next)) = self.entry_at(raw, pos)? {
            if entry.name != b"." && entry.name != b".." {
                return Ok(false);
            }
            pos = next;
        }
        Ok(true)
    }

    /// Writes the checksum record at the end of the block `data` of the directory `ino`.
    pub(crate) fn seal(&self, ino: u32, raw: &RawInode, data: &mut [u8]) {
        if !self.metadata_csum() {
            return;
        }
        let at = data.len() - TAIL;
        put32(data, at, 0);
        put16(data, at + 4, TAIL as u16);
        data[at + 6] = 0;
        data[at + 7] = TAIL_TYPE;
        let csum = crc::crc32c(self.inode_seed(ino, raw), &data[..at]);
        put32(data, at + 8, csum);
    }

    /// Writes the record of `name` at `at` of `data`.
    fn put_entry(
        &self,
        data: &mut [u8],
        at: usize,
        rec: usize,
        ino: u32,
        name: &[u8],
        kind: FileType,
    ) {
        put32(data, at, ino);
        put16(data, at + 4, rec as u16);
        data[at + 6] = name.len() as u8;
        data[at + 7] =
            if self.sb.incompat & layout::incompat::FILETYPE != 0 { entry_code(kind) } else { 0 };
        data[at + 8..at + 8 + name.len()].copy_from_slice(name);
    }

    /// Adds the record of `name` to the block `data` of a directory, in the first record with
    /// room, as `ext4_find_dest_de`. Gives false if the block has no room.
    pub(crate) fn put_in_block(
        &self,
        data: &mut [u8],
        name: &[u8],
        ino: u32,
        kind: FileType,
    ) -> Result<bool> {
        let usable = data.len() - self.tail();
        let need = rec_len(name.len());
        let mut at = 0;
        while at < usable {
            let rec = usize::from(u16_at(data, at + 4));
            if rec < 8 || at + rec > usable {
                return Err(Errno::EUCLEAN);
            }
            let used = if u32_at(data, at) != 0 { rec_len(usize::from(data[at + 6])) } else { 0 };
            if rec >= used + need {
                if used == 0 {
                    self.put_entry(data, at, rec, ino, name, kind);
                } else {
                    put16(data, at + 4, used as u16);
                    self.put_entry(data, at + used, rec - used, ino, name, kind);
                }
                return Ok(true);
            }
            at += rec;
        }
        Ok(false)
    }

    /// Gives the first block of a new directory `ino` with the parent `parent`.
    pub(crate) fn new_dir_block(&self, ino: u32, raw: &RawInode, parent: u32) -> Vec<u8> {
        let bs = self.sb.block_size as usize;
        let mut data = vec![0u8; bs];
        self.put_entry(&mut data, 0, 12, ino, b".", FileType::Directory);
        self.put_entry(&mut data, 12, bs - self.tail() - 12, parent, b"..", FileType::Directory);
        self.seal(ino, raw, &mut data);
        data
    }
}

impl Tx<'_> {
    /// Changes the directory `dir` from an htree to a list.
    fn unindex(&mut self, dir: &Node, raw: &mut RawInode) -> Result<()> {
        if raw.flags() & flags::INDEX == 0 {
            return Ok(());
        }
        let fs = self.fs;
        let bs = fs.sb.block_size as usize;
        let tail = fs.tail();
        for lblock in 0..raw.size() / bs as u64 {
            let (block, mut data) = fs.dir_block(raw, lblock)?;
            let at = if lblock == 0 { 12 } else { 0 };
            // The root has `.` and a `..` that covers the rest of the block. The other index
            // blocks have one empty record that covers all of the block.
            if usize::from(u16_at(&data, at + 4)) != bs - at
                || (lblock != 0 && u32_at(&data, 0) != 0)
            {
                continue;
            }
            if tail != 0 {
                put16(&mut data, at + 4, (bs - at - tail) as u16);
                fs.seal(dir.ino, raw, &mut data);
            }
            fs.write(block * bs as u64, &data)?;
        }
        raw.set_flags(raw.flags() & !flags::INDEX);
        Ok(())
    }

    /// Adds the entry `name` for the inode `ino` to the directory `dir`, as `ext4_add_entry`.
    pub(crate) fn add_entry(
        &mut self,
        dir: &Node,
        name: &[u8],
        ino: u32,
        kind: FileType,
    ) -> Result<()> {
        let mut raw = dir.raw();
        let result = self.add_entry_to(dir, &mut raw, name, ino, kind);
        self.save(dir, &mut raw)?;
        result
    }

    /// Adds the entry `name` to the directory `dir`, which has the inode `raw`. An indexed
    /// directory adds it with its index. A list adds it to the first block with room, or to a
    /// new block. A directory of one full block gets an index first.
    fn add_entry_to(
        &mut self,
        dir: &Node,
        raw: &mut RawInode,
        name: &[u8],
        ino: u32,
        kind: FileType,
    ) -> Result<()> {
        let fs = self.fs;
        // A directory with an index that is not valid becomes a list, and it stays a list.
        let mut fallback = false;
        if raw.flags() & flags::INDEX != 0 {
            if fs.dir_index() && self.dx_add(dir, raw, name, ino, kind)? {
                return Ok(());
            }
            self.unindex(dir, raw)?;
            fallback = true;
        }
        let bs = fs.sb.block_size as usize;
        let blocks = raw.size() / bs as u64;
        for lblock in 0..blocks {
            let (block, mut data) = fs.dir_block(raw, lblock)?;
            if fs.put_in_block(&mut data, name, ino, kind)? {
                fs.seal(dir.ino, raw, &mut data);
                return fs.write(block * bs as u64, &data);
            }
            if blocks == 1
                && !fallback
                && fs.dir_index()
                && self.make_indexed(dir, raw, (block, data), (name, ino, kind))?
            {
                return Ok(());
            }
        }
        let mut data = vec![0u8; bs];
        fs.put_entry(&mut data, 0, bs - fs.tail(), ino, name, kind);
        fs.seal(dir.ino, raw, &mut data);
        let size = raw.size();
        self.write_data(dir.ino, raw, size, &data).map(drop)
    }

    /// Removes the entry `name` from the directory `dir`. Gives the inode of the entry.
    pub(crate) fn remove_entry(&mut self, dir: &Node, name: &[u8]) -> Result<u32> {
        let fs = self.fs;
        let raw = dir.raw();
        let slot = fs.find_entry(&raw, name)?.ok_or(Errno::ENOENT)?;
        let (block, mut data) = fs.dir_block(&raw, slot.lblock)?;
        let rec = usize::from(u16_at(&data, slot.at + 4));
        // As `ext4_generic_delete_entry` of Linux, the removed record gets zeros, so the name
        // does not stay on the disk. A first record keeps its length.
        match slot.prev {
            Some(prev) => {
                let joined = u16_at(&data, prev + 4) + rec as u16;
                put16(&mut data, prev + 4, joined);
                data[slot.at..slot.at + rec].fill(0);
            }
            None => {
                put32(&mut data, slot.at, 0);
                data[slot.at + 6..slot.at + rec].fill(0);
            }
        }
        fs.seal(dir.ino, &raw, &mut data);
        fs.write(block * fs.sb.block_size, &data)?;
        Ok(slot.ino)
    }

    /// Points the existing entry `name` of the directory `dir` to the inode `ino` of the type
    /// `kind`. The name and the hash of the entry do not change.
    pub(crate) fn set_entry(
        &mut self,
        dir: &Node,
        name: &[u8],
        ino: u32,
        kind: FileType,
    ) -> Result<()> {
        let fs = self.fs;
        let raw = dir.raw();
        let slot = fs.find_entry(&raw, name)?.ok_or(Errno::ENOENT)?;
        let (block, mut data) = fs.dir_block(&raw, slot.lblock)?;
        put32(&mut data, slot.at, ino);
        if fs.sb.incompat & layout::incompat::FILETYPE != 0 {
            data[slot.at + 7] = entry_code(kind);
        }
        fs.seal(dir.ino, &raw, &mut data);
        fs.write(block * fs.sb.block_size, &data)
    }

    /// Changes the inode of `..` in the directory `dir` to `parent`.
    pub(crate) fn set_parent(&mut self, dir: &Node, parent: u32) -> Result<()> {
        let fs = self.fs;
        let raw = dir.raw();
        let (block, mut data) = fs.dir_block(&raw, 0)?;
        let at = usize::from(u16_at(&data, 4));
        if at + 10 > data.len() || data[at + 6] != 2 || &data[at + 8..at + 10] != b".." {
            return Err(Errno::EUCLEAN);
        }
        put32(&mut data, at, parent);
        fs.seal(dir.ino, &raw, &mut data);
        fs.write(block * fs.sb.block_size, &data)
    }
}

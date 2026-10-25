//! The directories of XFS. A small directory is a list in the inode, the short form. A larger
//! directory has data blocks with the entries below `LEAF_OFFSET`, and a hash index above it,
//! which the driver does not use.

use crate::node::{FMT_LOCAL, Node};
use crate::{be16, be32, be64};
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::{DirEntry, FileType, Result};

/// The offset of the leaf blocks in a directory, `XFS_DIR2_LEAF_OFFSET`. The data blocks are
/// below it.
const LEAF_OFFSET: u64 = 1 << 35;
/// The magic numbers of a data block of version 5, in a directory with one block and in a larger
/// directory, and the size of their header.
const DATA_BLOCK_V5: u32 = 0x5844_4233;
const DATA_V5: u32 = 0x5844_4433;
const HEADER_V5: usize = 64;
/// The magic numbers and the size of the header of version 4.
const DATA_BLOCK_V4: u32 = 0x5844_3242;
const DATA_V4: u32 = 0x5844_3244;
const HEADER_V4: usize = 16;
/// The tag of an unused space in a data block.
const FREE_TAG: u16 = 0xffff;
/// The type of a directory in an entry, `XFS_DIR3_FT_DIR`.
const FT_DIR: u8 = 2;

/// An entry of a directory as the disk has it.
struct Entry {
    ino: u64,
    name: Vec<u8>,
    /// The type of the file, if the directory keeps it.
    ftype: Option<u8>,
}

/// The type of a file from the type in a directory entry, `XFS_DIR3_FT_*`.
fn entry_type(t: u8) -> Option<FileType> {
    Some(match t {
        1 => FileType::Regular,
        2 => FileType::Directory,
        3 => FileType::CharDevice,
        4 => FileType::BlockDevice,
        5 => FileType::Fifo,
        6 => FileType::Socket,
        7 => FileType::Symlink,
        _ => return None,
    })
}

/// Gives the inode number of `size` bytes at `at`.
fn ino_at(b: &[u8], at: usize, size: usize) -> Result<u64> {
    match size {
        4 if at + 4 <= b.len() => Ok(u64::from(be32(b, at))),
        8 if at + 8 <= b.len() => Ok(be64(b, at)),
        _ => Err(Errno::EUCLEAN),
    }
}

impl Node {
    /// Gives the entry at `pos` of the directory and the position of the next entry, or `None`
    /// at the end.
    pub(crate) fn entry_at(&self, pos: u64) -> Result<Option<(DirEntry, u64)>> {
        let Some((e, next)) = self.raw_entry_at(pos)? else { return Ok(None) };
        let kind = match e.ftype.and_then(entry_type) {
            Some(kind) => kind,
            None => self.fs.inode(e.ino)?.kind(),
        };
        Ok(Some((DirEntry { ino: e.ino, kind, name: e.name }, next)))
    }

    /// Finds the inode number of `name` in the directory.
    pub(crate) fn find(&self, name: &[u8]) -> Result<Option<u64>> {
        let mut pos = 0;
        while let Some((e, next)) = self.raw_entry_at(pos)? {
            if e.name == name {
                return Ok(Some(e.ino));
            }
            pos = next;
        }
        Ok(None)
    }

    fn raw_entry_at(&self, pos: u64) -> Result<Option<(Entry, u64)>> {
        if self.format() == FMT_LOCAL { self.short_entry(pos) } else { self.block_entry(pos) }
    }

    /// Gives the entry at `pos` of a short form directory. The short form does not keep `.` and
    /// `..`, so position 0 is `.`, position 1 is `..`, and position k + 2 is entry k.
    fn short_entry(&self, pos: u64) -> Result<Option<(Entry, u64)>> {
        let size = usize::try_from(self.size()).map_err(|_| Errno::EUCLEAN)?;
        let f = self.fork().get(..size).ok_or(Errno::EUCLEAN)?;
        let count = u64::from(*f.first().ok_or(Errno::EUCLEAN)?);
        let isize = if f.get(1).copied().unwrap_or(0) != 0 { 8 } else { 4 };
        let parent = ino_at(f, 2, isize)?;
        let dir = Some(FT_DIR);
        match pos {
            0 => return Ok(Some((Entry { ino: self.ino, name: b".".to_vec(), ftype: dir }, 1))),
            1 => return Ok(Some((Entry { ino: parent, name: b"..".to_vec(), ftype: dir }, 2))),
            _ if pos - 2 >= count => return Ok(None),
            _ => {}
        }
        let mut at = 2 + isize;
        for k in 0..count {
            let len = usize::from(*f.get(at).ok_or(Errno::EUCLEAN)?);
            let name = f.get(at + 3..at + 3 + len).ok_or(Errno::EUCLEAN)?;
            at += 3 + len;
            let ftype = if self.fs.sb.ftype {
                at += 1;
                Some(*f.get(at - 1).ok_or(Errno::EUCLEAN)?)
            } else {
                None
            };
            let ino = ino_at(f, at, isize)?;
            at += isize;
            if len == 0 {
                return Err(Errno::EUCLEAN);
            }
            if k == pos - 2 {
                return Ok(Some((Entry { ino, name: name.to_vec(), ftype }, pos + 1)));
            }
        }
        Ok(None)
    }

    /// Reads the directory block `dblock`, which can be more than one block of the file system.
    fn read_dir_block(&self, dblock: u64) -> Result<Vec<u8>> {
        let sb = &self.fs.sb;
        let bs = sb.block_size as usize;
        let per = 1u64 << sb.dirblklog;
        let mut b = vec![0u8; bs << sb.dirblklog];
        for (i, chunk) in b.chunks_exact_mut(bs).enumerate() {
            let lblock = dblock * per + i as u64;
            let e = self.extent_from(lblock).filter(|e| e.off <= lblock).ok_or(Errno::EUCLEAN)?;
            self.fs.read(self.fs.block_at(e.block + (lblock - e.off))?, chunk)?;
        }
        Ok(b)
    }

    /// Gives the entry at `pos` of a directory with data blocks. The position is the offset of
    /// the entry in the data blocks.
    fn block_entry(&self, mut pos: u64) -> Result<Option<(Entry, u64)>> {
        let sb = &self.fs.sb;
        let dbs = sb.block_size << sb.dirblklog;
        let per = 1u64 << sb.dirblklog;
        let header = if sb.v5 { HEADER_V5 } else { HEADER_V4 };
        while pos < LEAF_OFFSET {
            // The data block that has `pos`, or the next data block after a hole.
            let Some(e) = self.extent_from(pos / dbs * per) else { return Ok(None) };
            let dblock = (pos / dbs).max(e.off / per);
            if dblock * dbs >= LEAF_OFFSET {
                return Ok(None);
            }
            if dblock != pos / dbs {
                pos = dblock * dbs;
            }
            let b = self.read_dir_block(dblock)?;
            let end = match be32(&b, 0) {
                DATA_BLOCK_V5 | DATA_BLOCK_V4 => {
                    // A directory with one block has the hash index at the end of the block.
                    let leaves = be32(&b, b.len() - 8) as usize;
                    b.len().checked_sub(8 + leaves * 8).ok_or(Errno::EUCLEAN)?
                }
                DATA_V5 | DATA_V4 => b.len(),
                _ => return Err(Errno::EUCLEAN),
            };
            let mut at = ((pos % dbs) as usize).max(header);
            while at < end {
                if be16(&b, at) == FREE_TAG {
                    let len = usize::from(be16(&b, at + 2));
                    if len < 8 || len % 8 != 0 {
                        return Err(Errno::EUCLEAN);
                    }
                    at += len;
                    continue;
                }
                let ino = be64(&b, at);
                let len = usize::from(*b.get(at + 8).ok_or(Errno::EUCLEAN)?);
                let name = b.get(at + 9..at + 9 + len).ok_or(Errno::EUCLEAN)?.to_vec();
                let ftype =
                    if sb.ftype { Some(*b.get(at + 9 + len).ok_or(Errno::EUCLEAN)?) } else { None };
                let next = at + (9 + len + usize::from(sb.ftype) + 2).next_multiple_of(8);
                if len == 0 || next > end {
                    return Err(Errno::EUCLEAN);
                }
                return Ok(Some((Entry { ino, name, ftype }, dblock * dbs + next as u64)));
            }
            pos = (dblock + 1) * dbs;
        }
        Ok(None)
    }
}

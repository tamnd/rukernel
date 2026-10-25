//! The inodes of ext4: the attributes, the map from the blocks of a file to the blocks of the
//! disk, and the directories.

use crate::layout::{self, EXTENT_INIT_MAX, EXTENT_MAGIC, RawInode, flags, u16_at, u32_at};
use crate::{EXT4_MAGIC, Fs};
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::inode::mode;
use rk_vfs::{DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, Timespec};

/// The deepest extent tree, as `EXT4_MAX_EXTENT_DEPTH` of Linux.
const MAX_DEPTH: u16 = 5;

/// An inode of ext4.
pub struct Node {
    fs: Arc<Fs>,
    ino: u32,
    raw: RawInode,
}

/// Gives the time stamp of the seconds and the nanoseconds of `t`.
fn timespec((sec, nsec): (i64, u32)) -> Timespec {
    Timespec { sec, nsec: nsec.min(999_999_999) }
}

/// The type of a file from the file type of a directory entry, as `EXT4_FT_*`.
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

impl Node {
    pub(crate) fn new(fs: Arc<Fs>, ino: u32, raw: RawInode) -> Arc<Self> {
        Arc::new(Self { fs, ino, raw })
    }

    fn block_size(&self) -> u64 {
        self.fs.sb.block_size
    }

    fn is_dir(&self) -> bool {
        u32::from(self.raw.mode()) & mode::S_IFMT == mode::S_IFDIR
    }

    /// Gives the block of the disk that has the block `lblock` of the file, and tells if the
    /// block has data. A hole gives `None`.
    fn map(&self, lblock: u64) -> Result<Option<(u64, bool)>> {
        if self.raw.flags() & flags::EXTENTS != 0 {
            let lblock = u32::try_from(lblock).map_err(|_| Errno::EFBIG)?;
            self.map_extent(lblock)
        } else {
            Ok(self.map_indirect(lblock)?.map(|b| (b, true)))
        }
    }

    /// Finds `lblock` in the extent tree.
    fn map_extent(&self, lblock: u32) -> Result<Option<(u64, bool)>> {
        let mut node = self.raw.block().to_vec();
        for _ in 0..=MAX_DEPTH {
            if node.len() < 12 || u16_at(&node, 0) != EXTENT_MAGIC {
                return Err(Errno::EUCLEAN);
            }
            let entries = usize::from(u16_at(&node, 2));
            if 12 + entries * 12 > node.len() {
                return Err(Errno::EUCLEAN);
            }
            let entry = |i: usize| &node[12 + i * 12..24 + i * 12];
            if u16_at(&node, 6) == 0 {
                for e in (0..entries).map(entry) {
                    let first = u32_at(e, 0);
                    let raw_len = u16_at(e, 4);
                    let (len, init) = if raw_len > EXTENT_INIT_MAX {
                        (raw_len - EXTENT_INIT_MAX, false)
                    } else {
                        (raw_len, true)
                    };
                    if lblock >= first && lblock - first < u32::from(len) {
                        let start = u64::from(u16_at(e, 6)) << 32 | u64::from(u32_at(e, 8));
                        return Ok(Some((start + u64::from(lblock - first), init)));
                    }
                }
                return Ok(None);
            }
            // The last index that starts at or before `lblock`.
            let Some(e) = (0..entries).map(entry).take_while(|e| u32_at(e, 0) <= lblock).last()
            else {
                return Ok(None);
            };
            let leaf = u64::from(u32_at(e, 4)) | u64::from(u16_at(e, 8)) << 32;
            node = self.fs.read_block(leaf)?;
        }
        Err(Errno::EUCLEAN)
    }

    /// Finds `lblock` in the block map of ext2 and ext3: 12 direct blocks, then a single, a
    /// double and a triple indirect block.
    fn map_indirect(&self, lblock: u64) -> Result<Option<u64>> {
        let per = self.block_size() / 4;
        let root = self.raw.block();
        let (mut block, mut index, mut levels) = if lblock < 12 {
            return Ok(Some(u64::from(u32_at(root, lblock as usize * 4))).filter(|&b| b != 0));
        } else if lblock - 12 < per {
            (u32_at(root, 12 * 4), lblock - 12, 1)
        } else if lblock - 12 - per < per * per {
            (u32_at(root, 13 * 4), lblock - 12 - per, 2)
        } else if lblock - 12 - per - per * per < per * per * per {
            (u32_at(root, 14 * 4), lblock - 12 - per - per * per, 3)
        } else {
            return Err(Errno::EFBIG);
        };
        while levels > 0 {
            if block == 0 {
                return Ok(None);
            }
            levels -= 1;
            let span = per.pow(levels);
            let data = self.fs.read_block(u64::from(block))?;
            block = u32_at(&data, (index / span) as usize * 4);
            index %= span;
        }
        Ok(Some(u64::from(block)).filter(|&b| b != 0))
    }

    /// Reads the data of the file at `offset`, up to the size of the file.
    fn read_data(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if self.raw.flags() & flags::INLINE_DATA != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let size = self.raw.size();
        if offset >= size {
            return Ok(0);
        }
        let len = buf.len().min((size - offset) as usize);
        let bs = self.block_size();
        let mut done = 0;
        while done < len {
            let at = offset + done as u64;
            let in_block = (at % bs) as usize;
            let n = (bs as usize - in_block).min(len - done);
            let out = &mut buf[done..done + n];
            match self.map(at / bs)? {
                Some((block, true)) => {
                    if block >= self.fs.sb.blocks_count {
                        return Err(Errno::EUCLEAN);
                    }
                    self.fs.read(block * bs + in_block as u64, out)?;
                }
                _ => out.fill(0),
            }
            done += n;
        }
        Ok(len)
    }

    /// Gives the entry at the byte `pos` of the directory, or the next entry after it that has
    /// an inode, and the position after the entry.
    fn entry_at(&self, mut pos: u64) -> Result<Option<(DirEntry, u64)>> {
        let size = self.raw.size();
        let bs = self.block_size();
        let mut block: Option<(u64, Vec<u8>)> = None;
        while pos < size {
            let lblock = pos / bs;
            if block.as_ref().is_none_or(|(l, _)| *l != lblock) {
                let mut data = alloc::vec![0u8; bs as usize];
                self.read_data(lblock * bs, &mut data)?;
                block = Some((lblock, data));
            }
            let Some((_, data)) = &block else { return Err(Errno::EIO) };
            let at = (pos % bs) as usize;
            if at + 8 > data.len() {
                return Err(Errno::EUCLEAN);
            }
            let ino = u32_at(data, at);
            let rec_len = u64::from(u16_at(data, at + 4));
            let name_len = usize::from(data[at + 6]);
            if rec_len < 8 || at as u64 + rec_len > bs || at + 8 + name_len > data.len() {
                return Err(Errno::EUCLEAN);
            }
            pos += rec_len;
            if ino == 0 || name_len == 0 {
                continue;
            }
            let name = data[at + 8..at + 8 + name_len].to_vec();
            let kind = match entry_type(data[at + 7]) {
                Some(kind) if self.fs.sb.incompat & layout::incompat::FILETYPE != 0 => kind,
                _ => self.fs.inode(ino)?.kind(),
            };
            return Ok(Some((DirEntry { ino: u64::from(ino), kind, name }, pos)));
        }
        Ok(None)
    }

    fn kind(&self) -> FileType {
        FileType::from_mode(u32::from(self.raw.mode())).unwrap_or(FileType::Regular)
    }

    /// The device of a device file, from `i_block`, as `old_decode_dev` and `new_decode_dev` of
    /// Linux.
    fn rdev(&self) -> u64 {
        let b = self.raw.block();
        let (old, new) = (u32_at(b, 0), u32_at(b, 4));
        if old != 0 {
            rk_vfs::device::makedev((old >> 8) & 0xff, old & 0xff)
        } else {
            rk_vfs::device::makedev((new & 0xfff00) >> 8, (new & 0xff) | ((new >> 12) & 0xfff00))
        }
    }

    fn read_only<T>(&self) -> Result<T> {
        if self.is_dir() { Err(Errno::EROFS) } else { Err(Errno::ENOTDIR) }
    }
}

impl Inode for Node {
    fn metadata(&self) -> Metadata {
        let raw = &self.raw;
        let kind = self.kind();
        let blocks = if raw.flags() & flags::HUGE_FILE != 0 {
            raw.blocks() * (self.block_size() / 512)
        } else {
            raw.blocks()
        };
        let rdev = match kind {
            FileType::CharDevice | FileType::BlockDevice => self.rdev(),
            _ => 0,
        };
        Metadata {
            dev: self.fs.dev,
            ino: u64::from(self.ino),
            mode: u32::from(raw.mode()),
            nlink: u32::from(raw.links()),
            uid: raw.uid(),
            gid: raw.gid(),
            rdev,
            size: raw.size(),
            blksize: self.block_size() as u32,
            blocks,
            atime: timespec(raw.time(0x8, 0x8c)),
            mtime: timespec(raw.time(0x10, 0x88)),
            ctime: timespec(raw.time(0xc, 0x84)),
        }
    }

    fn set_attr(&self, _attr: &SetAttr) -> Result<()> {
        Err(Errno::EROFS)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        match self.kind() {
            FileType::Regular => self.read_data(offset, buf),
            FileType::Directory => Err(Errno::EISDIR),
            _ => Err(Errno::EINVAL),
        }
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> Result<usize> {
        Err(Errno::EROFS)
    }

    fn lookup(&self, name: &[u8]) -> Result<InodeRef> {
        if !self.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let mut pos = 0;
        while let Some((entry, next)) = self.entry_at(pos)? {
            if entry.name == name {
                let ino = u32::try_from(entry.ino).map_err(|_| Errno::EUCLEAN)?;
                return Ok(self.fs.inode(ino)?);
            }
            pos = next;
        }
        Err(Errno::ENOENT)
    }

    fn create(&self, _name: &[u8], _kind: FileType, _perm: u32, _rdev: u64) -> Result<InodeRef> {
        self.read_only()
    }

    fn symlink(&self, _name: &[u8], _target: &[u8]) -> Result<InodeRef> {
        self.read_only()
    }

    fn link(&self, _name: &[u8], _inode: &InodeRef) -> Result<()> {
        self.read_only()
    }

    fn unlink(&self, _name: &[u8]) -> Result<()> {
        self.read_only()
    }

    fn rmdir(&self, _name: &[u8]) -> Result<()> {
        self.read_only()
    }

    fn rename(&self, _old: &[u8], _new_dir: &InodeRef, _new: &[u8]) -> Result<()> {
        self.read_only()
    }

    fn read_link(&self) -> Result<Vec<u8>> {
        if self.kind() != FileType::Symlink {
            return Err(Errno::EINVAL);
        }
        let size = usize::try_from(self.raw.size()).map_err(|_| Errno::EUCLEAN)?;
        // A short target is in `i_block`, and the inode has no block.
        if size < 60 && self.raw.flags() & (flags::EXTENTS | flags::INLINE_DATA) == 0 {
            return Ok(self.raw.block()[..size].to_vec());
        }
        if size > self.block_size() as usize {
            return Err(Errno::EUCLEAN);
        }
        let mut target = alloc::vec![0u8; size];
        let n = self.read_data(0, &mut target)?;
        target.truncate(n);
        Ok(target)
    }

    fn read_dir(&self, pos: u64) -> Result<Option<(DirEntry, u64)>> {
        if !self.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        self.entry_at(pos)
    }

    fn fs_id(&self) -> u64 {
        self.fs.dev
    }

    fn fs_magic(&self) -> u64 {
        EXT4_MAGIC
    }
}

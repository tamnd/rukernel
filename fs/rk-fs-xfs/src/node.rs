//! The inodes of XFS: the attributes, the map from the blocks of a file to the blocks of the disk,
//! and the data.

use crate::{Fs, XFS_MAGIC, be16, be32, be64};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::{DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, Timespec};

/// The magic number of an inode, `XFS_DINODE_MAGIC`.
const INODE_MAGIC: u16 = 0x494e;
/// The formats of a fork, `XFS_DINODE_FMT_*`: a device number, data in the inode, a list of
/// extents, and a tree of extents.
pub(crate) const FMT_DEV: u8 = 0;
pub(crate) const FMT_LOCAL: u8 = 1;
const FMT_EXTENTS: u8 = 2;
const FMT_BTREE: u8 = 3;
/// The flag of an inode for a file on the realtime device, `XFS_DIFLAG_REALTIME`.
const FLAG_REALTIME: u16 = 0x1;
/// The flags of a version 3 inode for the large time stamps and the large extent counters,
/// `XFS_DIFLAG2_BIGTIME` and `XFS_DIFLAG2_NREXT64`.
const FLAG2_BIGTIME: u64 = 0x8;
const FLAG2_NREXT64: u64 = 0x10;
/// The seconds from 1901-12-13 to 1970-01-01, which a large time stamp adds.
const BIGTIME_OFFSET: i64 = 1 << 31;
/// The magic numbers of a block of an extent tree, of version 5 and of version 4.
const BMAP_MAGIC_V5: u32 = 0x424d_4133;
const BMAP_MAGIC_V4: u32 = 0x424d_4150;
/// The most levels of an extent tree.
const BMAP_MAX_LEVELS: u16 = 9;
/// The magic number of a block of a symbolic link of version 5, and the size of its header.
const SYMLINK_MAGIC: u32 = 0x5853_4c4d;
const SYMLINK_HEADER: usize = 56;
/// The longest target of a symbolic link.
const SYMLINK_MAX: usize = 1024;

/// A range of blocks of a file on the disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Extent {
    /// The first block in the file.
    pub(crate) off: u64,
    /// The first block on the disk, with the allocation group in its high bits.
    pub(crate) block: u64,
    /// The number of blocks.
    pub(crate) len: u64,
    /// The blocks have no data yet, and read as zeros.
    pub(crate) unwritten: bool,
}

impl Extent {
    /// Reads an extent record of 16 bytes.
    fn parse(r: &[u8]) -> Self {
        let (l0, l1) = (be64(r, 0), be64(r, 8));
        Self {
            off: (l0 & !(1 << 63)) >> 9,
            block: (l0 & 0x1ff) << 43 | l1 >> 21,
            len: l1 & 0x1f_ffff,
            unwritten: l0 >> 63 != 0,
        }
    }
}

/// An inode of XFS.
pub struct Node {
    pub(crate) fs: Arc<Fs>,
    pub(crate) ino: u64,
    /// The inode as the disk has it.
    raw: Vec<u8>,
    /// The size of the core of the inode, before the data fork.
    core: usize,
    /// The extents of the data fork, in the order of the file, for a fork with extents.
    pub(crate) extents: Vec<Extent>,
}

/// Gives the time stamp at `at` of the inode `raw`.
fn timestamp(raw: &[u8], at: usize, bigtime: bool) -> Timespec {
    if bigtime {
        let t = be64(raw, at);
        let sec = (t / 1_000_000_000) as i64 - BIGTIME_OFFSET;
        Timespec { sec, nsec: (t % 1_000_000_000) as u32 }
    } else {
        let sec = i64::from(be32(raw, at) as i32);
        Timespec { sec, nsec: be32(raw, at + 4).min(999_999_999) }
    }
}

impl Node {
    /// Reads the inode `ino` from `raw`, and the extents of its data fork.
    ///
    /// # Errors
    ///
    /// Gives `EUCLEAN` for a bad inode, and the error of the disk.
    pub(crate) fn new(fs: Arc<Fs>, ino: u64, raw: Vec<u8>) -> Result<Arc<Self>> {
        if be16(&raw, 0) != INODE_MAGIC {
            return Err(Errno::EUCLEAN);
        }
        let core = match raw[4] {
            1 | 2 => 100,
            3 if be64(&raw, 152) == ino => 176,
            _ => return Err(Errno::EUCLEAN),
        };
        let mut node = Self { fs, ino, raw, core, extents: Vec::new() };
        if node.fork().is_empty() {
            return Err(Errno::EUCLEAN);
        }
        node.extents = match node.format() {
            FMT_EXTENTS => node.list_extents()?,
            FMT_BTREE => node.tree_extents()?,
            _ => Vec::new(),
        };
        Ok(Arc::new(node))
    }

    /// The type and the permission bits.
    fn mode(&self) -> u16 {
        be16(&self.raw, 2)
    }

    /// The type of the file.
    pub(crate) fn kind(&self) -> FileType {
        FileType::from_mode(u32::from(self.mode())).unwrap_or(FileType::Regular)
    }

    /// The format of the data fork.
    pub(crate) fn format(&self) -> u8 {
        self.raw[5]
    }

    /// The size of the file in bytes.
    pub(crate) fn size(&self) -> u64 {
        be64(&self.raw, 56)
    }

    fn flags2(&self) -> u64 {
        if self.core == 176 { be64(&self.raw, 120) } else { 0 }
    }

    /// The data fork. The attribute fork follows it if the inode has one.
    pub(crate) fn fork(&self) -> &[u8] {
        let forkoff = usize::from(self.raw[82]) * 8;
        let end = if forkoff != 0 { self.core + forkoff } else { self.raw.len() };
        self.raw.get(self.core..end).unwrap_or(&[])
    }

    /// The number of extents of the data fork.
    fn extent_count(&self) -> u64 {
        if self.flags2() & FLAG2_NREXT64 != 0 {
            be64(&self.raw, 24)
        } else {
            u64::from(be32(&self.raw, 76))
        }
    }

    /// Reads the extents of a fork in the extent format.
    fn list_extents(&self) -> Result<Vec<Extent>> {
        let count = usize::try_from(self.extent_count()).map_err(|_| Errno::EUCLEAN)?;
        let fork = self.fork();
        if count > fork.len() / 16 {
            return Err(Errno::EUCLEAN);
        }
        Ok(fork.as_chunks::<16>().0.iter().take(count).map(|r| Extent::parse(r)).collect())
    }

    /// Reads the extents of a fork in the tree format. The root of the tree is in the fork, and
    /// the other nodes are in blocks.
    fn tree_extents(&self) -> Result<Vec<Extent>> {
        let fork = self.fork();
        let level = be16(fork, 0);
        let count = usize::from(be16(fork, 2));
        let max = fork.len().saturating_sub(4) / 16;
        if level == 0 || level > BMAP_MAX_LEVELS || count > max {
            return Err(Errno::EUCLEAN);
        }
        let mut out = Vec::new();
        for i in 0..count {
            self.walk(be64(fork, 4 + max * 8 + i * 8), level - 1, &mut out)?;
        }
        if out.len() as u64 != self.extent_count() {
            return Err(Errno::EUCLEAN);
        }
        Ok(out)
    }

    /// Adds the extents of the tree block `fsb` at the level `level` to `out`.
    fn walk(&self, fsb: u64, level: u16, out: &mut Vec<Extent>) -> Result<()> {
        let fs = &self.fs;
        let bs = fs.sb.block_size as usize;
        let mut b = vec![0u8; bs];
        fs.read(fs.block_at(fsb)?, &mut b)?;
        let (magic, header) = if fs.sb.v5 { (BMAP_MAGIC_V5, 72) } else { (BMAP_MAGIC_V4, 24) };
        let count = usize::from(be16(&b, 6));
        if be32(&b, 0) != magic || be16(&b, 4) != level || count > (bs - header) / 16 {
            return Err(Errno::EUCLEAN);
        }
        if out.len() + count > self.extent_count() as usize {
            return Err(Errno::EUCLEAN);
        }
        if level == 0 {
            out.extend(
                b[header..].as_chunks::<16>().0.iter().take(count).map(|r| Extent::parse(r)),
            );
            return Ok(());
        }
        let max = (bs - header) / 16;
        for i in 0..count {
            self.walk(be64(&b, header + max * 8 + i * 8), level - 1, out)?;
        }
        Ok(())
    }

    /// Gives the extent that has the block `lblock` of the file, or the first extent after it.
    pub(crate) fn extent_from(&self, lblock: u64) -> Option<&Extent> {
        let i = self.extents.partition_point(|e| e.off + e.len <= lblock);
        self.extents.get(i)
    }

    /// Reads the data of the file at `offset`. A hole and an unwritten extent read as zeros.
    pub(crate) fn read_data(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if be16(&self.raw, 90) & FLAG_REALTIME != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let size = self.size();
        if offset >= size {
            return Ok(0);
        }
        let len = buf.len().min((size - offset) as usize);
        let bs = self.fs.sb.block_size;
        let mut done = 0;
        while done < len {
            let pos = offset + done as u64;
            let lblock = pos / bs;
            let want = len - done;
            let n = match self.extent_from(lblock) {
                Some(e) if e.off <= lblock => {
                    let n = want.min(((e.off + e.len) * bs - pos) as usize);
                    if e.unwritten {
                        buf[done..done + n].fill(0);
                    } else {
                        let at = self.fs.block_at(e.block + (lblock - e.off))? + pos % bs;
                        self.fs.read(at, &mut buf[done..done + n])?;
                    }
                    n
                }
                next => {
                    let end = next.map_or(u64::MAX, |e| e.off.saturating_mul(bs));
                    let n = want.min((end - pos).try_into().unwrap_or(usize::MAX));
                    buf[done..done + n].fill(0);
                    n
                }
            };
            done += n;
        }
        Ok(len)
    }

    /// The device number of a device file. XFS keeps it in the encoding of System V.
    fn rdev(&self) -> u64 {
        let dev = be32(self.fork(), 0);
        rk_vfs::device::makedev(dev >> 18, dev & 0x3_ffff)
    }

    /// The target of a symbolic link that is in blocks. Each block of version 5 has a header.
    fn remote_link(&self, size: usize) -> Result<Vec<u8>> {
        if !self.fs.sb.v5 {
            let mut target = vec![0u8; size];
            let n = self.read_data(0, &mut target)?;
            target.truncate(n);
            return Ok(target);
        }
        let bs = self.fs.sb.block_size as usize;
        let mut target = Vec::with_capacity(size);
        let mut b = vec![0u8; bs];
        let mut lblock = 0;
        while target.len() < size {
            let e = self.extent_from(lblock).filter(|e| e.off <= lblock).ok_or(Errno::EUCLEAN)?;
            self.fs.read(self.fs.block_at(e.block + (lblock - e.off))?, &mut b)?;
            let n = (size - target.len()).min(bs - SYMLINK_HEADER);
            if be32(&b, 0) != SYMLINK_MAGIC || be32(&b, 8) as usize != n {
                return Err(Errno::EUCLEAN);
            }
            target.extend_from_slice(&b[SYMLINK_HEADER..SYMLINK_HEADER + n]);
            lblock += 1;
        }
        Ok(target)
    }
}

impl Inode for Node {
    fn metadata(&self) -> Metadata {
        let raw = &self.raw;
        let bigtime = self.flags2() & FLAG2_BIGTIME != 0;
        let rdev = match self.kind() {
            FileType::CharDevice | FileType::BlockDevice if self.format() == FMT_DEV => self.rdev(),
            _ => 0,
        };
        let nlink = if raw[4] == 1 { u32::from(be16(raw, 6)) } else { be32(raw, 16) };
        Metadata {
            dev: self.fs.dev,
            ino: self.ino,
            mode: u32::from(self.mode()),
            nlink,
            uid: be32(raw, 8),
            gid: be32(raw, 12),
            rdev,
            size: self.size(),
            blksize: self.fs.sb.block_size as u32,
            blocks: be64(raw, 64) * (self.fs.sb.block_size / 512),
            atime: timestamp(raw, 32, bigtime),
            mtime: timestamp(raw, 40, bigtime),
            ctime: timestamp(raw, 48, bigtime),
            // Only a version 3 inode keeps the creation time.
            btime: (raw[4] >= 3).then(|| timestamp(raw, 144, bigtime)),
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
        if self.kind() != FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        let ino = self.find(name)?.ok_or(Errno::ENOENT)?;
        Ok(self.fs.inode(ino)?)
    }

    fn create(&self, _name: &[u8], _kind: FileType, _perm: u32, _rdev: u64) -> Result<InodeRef> {
        Err(Errno::EROFS)
    }

    fn symlink(&self, _name: &[u8], _target: &[u8]) -> Result<InodeRef> {
        Err(Errno::EROFS)
    }

    fn link(&self, _name: &[u8], _inode: &InodeRef) -> Result<()> {
        Err(Errno::EROFS)
    }

    fn unlink(&self, _name: &[u8]) -> Result<()> {
        Err(Errno::EROFS)
    }

    fn rmdir(&self, _name: &[u8]) -> Result<()> {
        Err(Errno::EROFS)
    }

    fn rename(&self, _old: &[u8], _new_dir: &InodeRef, _new: &[u8]) -> Result<()> {
        Err(Errno::EROFS)
    }

    /// The driver only reads, so the file system cannot become writable.
    fn set_read_only(&self, read_only: bool) -> Result<()> {
        if read_only { Ok(()) } else { Err(Errno::EROFS) }
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn read_link(&self) -> Result<Vec<u8>> {
        if self.kind() != FileType::Symlink {
            return Err(Errno::EINVAL);
        }
        let size = usize::try_from(self.size()).map_err(|_| Errno::EUCLEAN)?;
        if size == 0 || size > SYMLINK_MAX {
            return Err(Errno::EUCLEAN);
        }
        if self.format() == FMT_LOCAL {
            return Ok(self.fork().get(..size).ok_or(Errno::EUCLEAN)?.to_vec());
        }
        self.remote_link(size)
    }

    fn read_dir(&self, pos: u64) -> Result<Option<(DirEntry, u64)>> {
        if self.kind() != FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        self.entry_at(pos)
    }

    fn fs_id(&self) -> u64 {
        self.fs.dev
    }

    fn fs_magic(&self) -> u64 {
        XFS_MAGIC
    }

    fn fs_stat(&self) -> Option<rk_vfs::inode::FsStat> {
        Some(self.fs.stat())
    }
}

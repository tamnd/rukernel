//! Open files.
//!
//! A `File` is an open file description of POSIX: the object that `open` makes and that `dup` and
//! `fork` share. It has the status flags and the file position. The `FileOps` of the file do the
//! work. A regular file and a directory use the operations of their inode. A device, a pipe and a
//! socket give their own operations.

use crate::dentry::Location;
use crate::inode::{
    FileType, InodeRef, Metadata, Result, SetAttr, check_immutable, check_set_attr, mode,
};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use rk_abi::Errno;
use rk_abi::native::mount;
use rk_abi::native::open as o;
use rk_frame::sync::SpinLock;

/// The access to the memory of the process that made a call. An `ioctl` reads and writes its
/// argument through it.
pub trait UserMemory {
    /// Reads `buf.len()` bytes at `addr`.
    fn read(&self, addr: usize, buf: &mut [u8]) -> Result<()>;
    /// Writes `buf` at `addr`.
    fn write(&self, addr: usize, buf: &[u8]) -> Result<()>;
}

/// The events of `poll`.
pub mod events {
    pub use rk_abi::native::poll::{POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT, POLLPRI};
}

/// One read or write of a batch. For a write, `buf` has the data. For a read, `buf` has the
/// length to read, and the read fills it. `result` is the number of bytes.
#[derive(Debug)]
pub struct BatchIo {
    /// The entry is a write.
    pub write: bool,
    /// The offset in the file.
    pub offset: u64,
    /// The data.
    pub buf: Vec<u8>,
    /// The result, after the batch.
    pub result: Result<usize>,
}

/// The operations of an open file. The default of each operation gives the error of Linux for a
/// file that does not have it.
pub trait FileOps: Send + Sync {
    /// Reads at the position of the file and moves the position.
    fn read(&self, _file: &File, _buf: &mut [u8]) -> Result<usize> {
        Err(Errno::EINVAL)
    }

    /// Writes at the position of the file, or at the end with `O_APPEND`, and moves the position.
    fn write(&self, _file: &File, _buf: &[u8]) -> Result<usize> {
        Err(Errno::EINVAL)
    }

    /// Reads at `offset`, for `pread64`. The position does not change.
    fn read_at(&self, _file: &File, _offset: u64, _buf: &mut [u8]) -> Result<usize> {
        Err(Errno::ESPIPE)
    }

    /// Writes at `offset`, for `pwrite64`. The position does not change.
    fn write_at(&self, _file: &File, _offset: u64, _buf: &[u8]) -> Result<usize> {
        Err(Errno::ESPIPE)
    }

    /// Tells if `lseek` can move the position.
    fn seekable(&self) -> bool {
        false
    }

    /// Moves the position for `lseek`, for a file that gives its own meaning to the position, as
    /// `/dev/kmsg`. `None` uses the `lseek` of the VFS.
    fn llseek(&self, _file: &File, _offset: i64, _whence: Whence) -> Option<Result<u64>> {
        None
    }

    /// Runs an `ioctl` command.
    fn ioctl(&self, _file: &File, _cmd: u32, _arg: usize, _mem: &dyn UserMemory) -> Result<usize> {
        Err(Errno::ENOTTY)
    }

    /// The end of the file for `lseek` with `SEEK_END`, for a file whose size is not the size
    /// of its inode, as a block device.
    fn end(&self) -> Option<u64> {
        None
    }

    /// Writes the data of the file to its device, for `fsync`.
    fn sync(&self) -> Result<()> {
        Ok(())
    }

    /// Does a batch of reads and writes at offsets, for `io_submit`. A file that can do the
    /// entries together, as a block device, does them together. Each entry is done one at a time
    /// with `read_at` and `write_at` by default.
    fn rw_batch(&self, file: &File, ios: &mut [BatchIo]) {
        for io in ios {
            io.result = if io.write {
                self.write_at(file, io.offset, &io.buf)
            } else {
                self.read_at(file, io.offset, &mut io.buf)
            };
        }
    }

    /// The events of `poll` that are true now.
    fn poll(&self, _file: &File) -> u32 {
        events::POLLIN | events::POLLOUT
    }

    /// Tells if the file has its own `poll`. Only such a file can go in an epoll set. A file
    /// without it is always ready, as a file of Linux without the `poll` operation.
    fn pollable(&self) -> bool {
        false
    }

    /// A count that goes up at each new event of the file, for an edge triggered epoll entry.
    /// An entry sees an edge when the count changes, also if the events stay the same. A file
    /// without the count gives 0, and an entry then sees an edge only when a new event is true.
    fn event_count(&self) -> u64 {
        0
    }

    /// The attributes, for `fstat` of a file that has no inode.
    fn metadata(&self) -> Option<Metadata> {
        None
    }

    /// The operations as `Any`, for a caller that must know the type of the file, for example
    /// the system calls of a process file descriptor.
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        None
    }

    /// The lines of `/proc/PID/fdinfo` after the common lines, as `show_fdinfo` of Linux.
    fn fdinfo(&self, _file: &File) -> Vec<u8> {
        Vec::new()
    }
}

/// The access mode and the status flags of an open file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenFlags(pub u32);

impl OpenFlags {
    /// The flags that `fcntl(F_SETFL)` can change.
    pub const SETFL_MASK: u32 = o::O_APPEND | o::O_NONBLOCK | o::O_DIRECT | o::O_NOATIME;

    /// Tells if the file can be read.
    pub fn readable(self) -> bool {
        matches!(self.0 & o::O_ACCMODE, o::O_RDONLY | o::O_RDWR) && !self.is_path()
    }

    /// Tells if the file can be written.
    pub fn writable(self) -> bool {
        matches!(self.0 & o::O_ACCMODE, o::O_WRONLY | o::O_RDWR) && !self.is_path()
    }

    /// `O_PATH`: the file is only a place in the tree.
    pub fn is_path(self) -> bool {
        self.0 & o::O_PATH != 0
    }

    /// `O_APPEND`.
    pub fn append(self) -> bool {
        self.0 & o::O_APPEND != 0
    }

    /// `O_NONBLOCK`.
    pub fn nonblock(self) -> bool {
        self.0 & o::O_NONBLOCK != 0
    }

    /// `O_DSYNC`, which `O_SYNC` also has.
    pub fn dsync(self) -> bool {
        self.0 & o::O_DSYNC != 0
    }
}

/// An open file description.
pub struct File {
    ops: Arc<dyn FileOps>,
    location: Option<Location>,
    inode: Option<InodeRef>,
    flags: AtomicU32,
    pos: SpinLock<u64>,
    /// The file took an OFD lock or a `flock` lock, so its drop must release them.
    locked: AtomicBool,
    /// The file is a regular file that can write, and the mount counts it as a writer, as
    /// `FMODE_WRITER` of Linux.
    writer: bool,
}

impl Drop for File {
    fn drop(&mut self) {
        if self.locked.load(Ordering::Relaxed) {
            crate::lock::close_file(self);
        }
        // The last close, as `fsnotify_close` in `__fput` of Linux.
        let flags = self.flags();
        if !flags.is_path() {
            crate::notify::close(self.location.as_ref(), self.inode.as_ref(), flags.writable());
        }
        if self.writer
            && let Some(location) = &self.location
        {
            location.mount.remove_writer();
        }
    }
}

impl core::fmt::Debug for File {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("File").field("flags", &self.flags()).finish_non_exhaustive()
    }
}

/// The operations of a regular file and a directory: the inode does the work.
struct InodeFile;

impl FileOps for InodeFile {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        let inode = file.inode.as_ref().ok_or(Errno::EINVAL)?;
        if inode.metadata().is_dir() {
            return Err(Errno::EISDIR);
        }
        let mut pos = file.pos.lock();
        crate::mapped::sync(inode, *pos, pos.saturating_add(buf.len() as u64))?;
        let n = inode.read_at(*pos, buf)?;
        *pos += n as u64;
        drop(pos);
        file.accessed();
        Ok(n)
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize> {
        let inode = file.inode.as_ref().ok_or(Errno::EINVAL)?;
        crate::swap::check(&**inode)?;
        check_immutable(&**inode)?;
        let mut pos = file.pos.lock();
        if file.flags().append() {
            *pos = inode.metadata().size;
        }
        crate::mapped::extend(inode, pos.saturating_add(buf.len() as u64));
        let n = inode.write_at(*pos, buf)?;
        crate::mapped::wrote(inode, *pos, &buf[..n]);
        *pos += n as u64;
        Ok(n)
    }

    fn read_at(&self, file: &File, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let inode = file.inode.as_ref().ok_or(Errno::EINVAL)?;
        if inode.metadata().is_dir() {
            return Err(Errno::EISDIR);
        }
        crate::mapped::sync(inode, offset, offset.saturating_add(buf.len() as u64))?;
        let n = inode.read_at(offset, buf)?;
        file.accessed();
        Ok(n)
    }

    fn write_at(&self, file: &File, offset: u64, buf: &[u8]) -> Result<usize> {
        let inode = file.inode.as_ref().ok_or(Errno::EINVAL)?;
        crate::swap::check(&**inode)?;
        check_immutable(&**inode)?;
        crate::mapped::extend(inode, offset.saturating_add(buf.len() as u64));
        let n = inode.write_at(offset, buf)?;
        crate::mapped::wrote(inode, offset, &buf[..n]);
        Ok(n)
    }

    fn seekable(&self) -> bool {
        true
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        let inode = file.inode.as_ref().ok_or(Errno::ENOTTY)?;
        match cmd {
            fiemap::FS_IOC_FIEMAP => fiemap::ioctl(inode, arg, mem),
            fsmap::FS_IOC_GETFSMAP => fsmap::ioctl(inode, arg, mem),
            FS_IOC_GETFLAGS | FS_IOC32_GETFLAGS => {
                mem.write(arg, &inode.attr_flags()?.to_ne_bytes())?;
                Ok(0)
            }
            FS_IOC_SETFLAGS | FS_IOC32_SETFLAGS => {
                let mut b = [0u8; 4];
                mem.read(arg, &mut b)?;
                file.want_write()?;
                inode.set_attr_flags(u32::from_ne_bytes(b))?;
                Ok(0)
            }
            FIBMAP => {
                let mut b = [0u8; 4];
                mem.read(arg, &mut b)?;
                let block = i32::from_ne_bytes(b);
                if block < 0 {
                    return Err(Errno::EINVAL);
                }
                let bs = u64::from(inode.metadata().blksize);
                let at = block as u64 * bs;
                let mut extents = inode.fiemap(at, 1).map_err(|_| Errno::EINVAL)?;
                // A block that waits for the writeback first gets its place, as `ext4_bmap` of
                // Linux.
                if extents.first().is_some_and(|e| e.delalloc) {
                    inode.sync()?;
                    extents = inode.fiemap(at, 1).map_err(|_| Errno::EINVAL)?;
                }
                // A hole and an extent that is not initialized give 0, as Linux.
                let phys = match extents.first() {
                    Some(e) if !e.unwritten && e.logical <= at => {
                        (e.physical + at - e.logical) / bs
                    }
                    _ => 0,
                };
                let phys = i32::try_from(phys).map_err(|_| Errno::ERANGE)?;
                mem.write(arg, &phys.to_ne_bytes())?;
                Ok(0)
            }
            FIGETBSZ => {
                let bs = inode.metadata().blksize as i32;
                mem.write(arg, &bs.to_ne_bytes())?;
                Ok(0)
            }
            FS_IOC_GOINGDOWN => {
                let mut b = [0u8; 4];
                mem.read(arg, &mut b)?;
                inode.shutdown(u32::from_ne_bytes(b))?;
                Ok(0)
            }
            EXT4_IOC_CHECKPOINT => {
                let mut b = [0u8; 4];
                mem.read(arg, &mut b)?;
                inode.checkpoint(u32::from_ne_bytes(b))?;
                Ok(0)
            }
            EXT4_IOC_RESIZE_FS => {
                let mut b = [0u8; 8];
                mem.read(arg, &mut b)?;
                file.want_write()?;
                inode.resize(u64::from_ne_bytes(b))?;
                Ok(0)
            }
            FITRIM => {
                // `struct fstrim_range`: the start, the length and the least length of a run.
                let mut range = [0u64; 3];
                for (i, v) in range.iter_mut().enumerate() {
                    let mut b = [0u8; 8];
                    mem.read(arg + i * 8, &mut b)?;
                    *v = u64::from_ne_bytes(b);
                }
                let [start, len, minlen] = range;
                let trimmed = inode.trim(start, len, minlen)?;
                mem.write(arg + 8, &trimmed.to_ne_bytes())?;
                Ok(0)
            }
            FS_IOC_GETFSLABEL => {
                let mut b = [0u8; FSLABEL_MAX];
                let label = inode.label()?;
                let n = label.len().min(FSLABEL_MAX - 1);
                b[..n].copy_from_slice(&label[..n]);
                mem.write(arg, &b)?;
                Ok(0)
            }
            FS_IOC_SETFSLABEL => {
                if !crate::cred::current().capable(crate::cred::cap::SYS_ADMIN) {
                    return Err(Errno::EPERM);
                }
                let mut b = [0u8; FSLABEL_MAX];
                mem.read(arg, &mut b)?;
                let len = b.iter().position(|&c| c == 0).unwrap_or(FSLABEL_MAX);
                file.want_write()?;
                inode.set_label(&b[..len])?;
                Ok(0)
            }
            FIFREEZE => inode.freeze(true).map(|()| 0),
            FITHAW => inode.freeze(false).map(|()| 0),
            fsx::FS_IOC_FSGETXATTR => fsx::get(&**inode, arg, mem),
            fsx::FS_IOC_FSSETXATTR => {
                file.want_write()?;
                fsx::set(&**inode, arg, mem)
            }
            _ => Err(Errno::ENOTTY),
        }
    }
}

/// `_IOWR('f', 15, struct move_extent)`. Swaps the blocks of two ext4 files, for online
/// defragmentation.
pub const EXT4_IOC_MOVE_EXT: u32 = 0xc028_660f;
/// `_IO(0, 1)`. Gives the block of the disk of a block of the file.
const FIBMAP: u32 = 1;
/// `_IO(0, 2)`. Gives the block size.
const FIGETBSZ: u32 = 2;
/// `_IOR('X', 125, __u32)`. Stops the file system, as `EXT4_IOC_SHUTDOWN` and
/// `XFS_IOC_GOINGDOWN`.
const FS_IOC_GOINGDOWN: u32 = 0x8004_587d;
/// `_IOW('f', 43, __u32)`. Empties the journal of ext4.
const EXT4_IOC_CHECKPOINT: u32 = 0x4004_662b;
/// `_IOW('f', 16, __u64)`. Grows a mounted ext4 file system to a number of blocks.
const EXT4_IOC_RESIZE_FS: u32 = 0x4008_6610;
/// `_IOWR('X', 121, struct fstrim_range)`. Discards the free blocks of a file system. The
/// caller needs `CAP_SYS_ADMIN`.
pub const FITRIM: u32 = 0xc018_5879;
/// The size of the label buffer of the label ioctls, `FSLABEL_MAX`.
const FSLABEL_MAX: usize = 256;
/// `_IOR(0x94, 49, char[FSLABEL_MAX])`. Gives the label of a file system.
const FS_IOC_GETFSLABEL: u32 = 0x8100_9431;
/// `_IOW(0x94, 50, char[FSLABEL_MAX])`. Changes the label of a file system. The caller needs
/// `CAP_SYS_ADMIN`.
const FS_IOC_SETFSLABEL: u32 = 0x4100_9432;
/// `_IOWR('X', 119, int)`. Stops the changes of a file system until `FITHAW`. The caller needs
/// `CAP_SYS_ADMIN`.
pub const FIFREEZE: u32 = 0xc004_5877;
/// `_IOWR('X', 120, int)`. Starts the changes of a frozen file system again. The caller needs
/// `CAP_SYS_ADMIN`.
pub const FITHAW: u32 = 0xc004_5878;
/// `_IOR('f', 1, long)`. The kernel reads and writes an `int`, as Linux.
const FS_IOC_GETFLAGS: u32 = 0x8008_6601;
/// `_IOW('f', 2, long)`.
const FS_IOC_SETFLAGS: u32 = 0x4008_6602;
/// `_IOR('f', 1, int)`, the command of a 32-bit program.
const FS_IOC32_GETFLAGS: u32 = 0x8004_6601;
/// `_IOW('f', 2, int)`.
const FS_IOC32_SETFLAGS: u32 = 0x4004_6602;

/// `FS_IOC_FSGETXATTR` and `FS_IOC_FSSETXATTR`, from `<linux/fs.h>`. They give and change the
/// inode flags as the `FS_XFLAG_*` flags of XFS.
mod fsx {
    use super::UserMemory;
    use crate::inode::{Inode, Result, iflags};
    use rk_abi::Errno;

    /// `_IOR('X', 31, struct fsxattr)`.
    pub(super) const FS_IOC_FSGETXATTR: u32 = 0x801c_581f;
    /// `_IOW('X', 32, struct fsxattr)`.
    pub(super) const FS_IOC_FSSETXATTR: u32 = 0x401c_5820;
    /// The size of `struct fsxattr`.
    const SIZE: usize = 28;
    /// `FS_PROJINHERIT_FL`.
    const PROJINHERIT: u32 = 0x2000_0000;
    /// The pairs of an inode flag and its `FS_XFLAG_*` flag.
    const MAP: [(u32, u32); 7] = [
        (iflags::IMMUTABLE, 0x8),
        (iflags::APPEND, 0x10),
        (iflags::SYNC, 0x20),
        (iflags::NOATIME, 0x40),
        (iflags::NODUMP, 0x80),
        (PROJINHERIT, 0x200),
        (iflags::DAX, 0x8000),
    ];

    /// Writes the `struct fsxattr` of `inode` at `arg`.
    pub(super) fn get(inode: &dyn Inode, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        let flags = inode.attr_flags()?;
        let xflags = MAP.iter().filter(|(f, _)| flags & f != 0).fold(0, |x, (_, b)| x | b);
        let mut buf = [0u8; SIZE];
        buf[..4].copy_from_slice(&u32::to_ne_bytes(xflags));
        mem.write(arg, &buf)?;
        Ok(0)
    }

    /// Reads a `struct fsxattr` at `arg` and sets the flags of `inode` from it.
    pub(super) fn set(inode: &dyn Inode, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        let mut buf = [0u8; SIZE];
        mem.read(arg, &mut buf)?;
        let word = |i: usize| u32::from_ne_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        let (xflags, extsize, projid, cowextsize) = (word(0), word(4), word(12), word(16));
        if MAP.iter().fold(xflags, |x, (_, b)| x & !b) != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        // No file system here has project quotas or extent size hints.
        if projid != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        if extsize != 0 || cowextsize != 0 {
            return Err(Errno::EINVAL);
        }
        // The flags that `FS_XFLAG_*` cannot give stay as they are, as Linux.
        let common = MAP.iter().fold(0, |f, (i, _)| f | i);
        let new = MAP.iter().filter(|(_, b)| xflags & b != 0).fold(0, |f, (i, _)| f | i);
        inode.set_attr_flags((inode.attr_flags()? & !common) | new)?;
        Ok(0)
    }
}

/// `FS_IOC_FIEMAP`, from `<linux/fiemap.h>`.
mod fiemap {
    use super::UserMemory;
    use crate::inode::{FileType, InodeRef, Result};
    use rk_abi::Errno;

    /// `_IOWR('f', 11, struct fiemap)`.
    pub(super) const FS_IOC_FIEMAP: u32 = 0xc020_660b;
    /// The size of `struct fiemap`, the header.
    const HEADER: usize = 32;
    /// The size of `struct fiemap_extent`.
    const EXTENT: usize = 56;
    /// `FIEMAP_FLAG_SYNC`: the file is synced first.
    const FLAG_SYNC: u32 = 0x1;
    /// `FIEMAP_FLAG_XATTR`: the extents of the extended attributes are given.
    const FLAG_XATTR: u32 = 0x2;
    /// `FIEMAP_MAX_EXTENTS`.
    const MAX_EXTENTS: u32 = u32::MAX / EXTENT as u32;
    /// `FIEMAP_EXTENT_LAST`.
    const EXTENT_LAST: u32 = 0x1;
    /// `FIEMAP_EXTENT_UNKNOWN`: the place of the data on the disk is not known.
    const EXTENT_UNKNOWN: u32 = 0x2;
    /// `FIEMAP_EXTENT_DELALLOC`: the data waits for the writeback to get its blocks.
    const EXTENT_DELALLOC: u32 = 0x4;
    /// `FIEMAP_EXTENT_NOT_ALIGNED`.
    const EXTENT_NOT_ALIGNED: u32 = 0x100;
    /// `FIEMAP_EXTENT_DATA_INLINE`.
    const EXTENT_DATA_INLINE: u32 = 0x200;
    /// `FIEMAP_EXTENT_UNWRITTEN`.
    const EXTENT_UNWRITTEN: u32 = 0x800;

    /// Fills the `struct fiemap` at `arg` with the extents of `inode`, as `ioctl_fiemap` of
    /// Linux.
    pub(super) fn ioctl(inode: &InodeRef, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        let mut head = [0u8; HEADER];
        mem.read(arg, &mut head)?;
        let u64_at = |o: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&head[o..o + 8]);
            u64::from_ne_bytes(b)
        };
        let u32_at =
            |o: usize| u32::from_ne_bytes([head[o], head[o + 1], head[o + 2], head[o + 3]]);
        let (start, len, flags, count) = (u64_at(0), u64_at(8), u32_at(16), u32_at(24));
        if count > MAX_EXTENTS {
            return Err(Errno::EINVAL);
        }
        let known = FLAG_SYNC | FLAG_XATTR;
        if flags & !known != 0 {
            // Linux gives back the flags that it does not know.
            mem.write(arg + 16, &(flags & !known).to_ne_bytes())?;
            return Err(Errno::EBADR);
        }
        if len == 0 {
            return Err(Errno::EINVAL);
        }
        if inode.metadata().file_type() != Some(FileType::Regular) {
            return Err(Errno::EOPNOTSUPP);
        }
        if flags & FLAG_SYNC != 0 {
            inode.sync()?;
        }
        let extents = if flags & FLAG_XATTR != 0 {
            // As the iomap of Linux, a `start` past the end of the extent gives no extent.
            inode.fiemap_xattr()?.filter(|e| start < e.length).into_iter().collect()
        } else {
            inode.fiemap(start, len.min(u64::MAX - start))?
        };
        let mapped = if count == 0 { extents.len() } else { extents.len().min(count as usize) };
        for (i, e) in extents.iter().take(count as usize).enumerate() {
            let mut raw = [0u8; EXTENT];
            raw[0..8].copy_from_slice(&e.logical.to_ne_bytes());
            raw[8..16].copy_from_slice(&e.physical.to_ne_bytes());
            raw[16..24].copy_from_slice(&e.length.to_ne_bytes());
            let mut f = if e.unwritten { EXTENT_UNWRITTEN } else { 0 };
            if e.delalloc {
                f |= EXTENT_DELALLOC | EXTENT_UNKNOWN;
            }
            if e.inline {
                f |= EXTENT_DATA_INLINE | EXTENT_NOT_ALIGNED;
            }
            if i + 1 == extents.len() {
                f |= EXTENT_LAST;
            }
            raw[40..44].copy_from_slice(&f.to_ne_bytes());
            mem.write(arg + HEADER + i * EXTENT, &raw)?;
        }
        mem.write(arg + 20, &(mapped as u32).to_ne_bytes())?;
        Ok(0)
    }
}

/// `FS_IOC_GETFSMAP`, from `<linux/fsmap.h>`, as `ext4_ioc_getfsmap` and `ext4_getfsmap` of
/// Linux. The file system has one device and gives no file offsets.
mod fsmap {
    use super::UserMemory;
    use crate::device::{major, minor};
    use crate::inode::{FsmapRecord, InodeRef, Result, fsmap_owner};
    use alloc::vec::Vec;
    use rk_abi::Errno;

    /// `_IOWR('X', 59, struct fsmap_head)`.
    pub(super) const FS_IOC_GETFSMAP: u32 = 0xc0c0_583b;
    /// The size of `struct fsmap_head` with its two keys.
    const HEADER: usize = 192;
    /// The offset of the first key in `struct fsmap_head`.
    const KEYS: usize = 64;
    /// The size of `struct fsmap`.
    const RECORD: usize = 64;
    /// `FMH_OF_DEV_T`: `fmr_device` is a device number.
    const OF_DEV_T: u32 = 0x1;
    /// `FMR_OF_SPECIAL_OWNER`: `fmr_owner` is a special owner and not an inode.
    const OF_SPECIAL_OWNER: u32 = 0x10;
    /// `FMR_OF_LAST`: the record is the last one.
    const OF_LAST: u32 = 0x20;

    /// A key of the search, from a `struct fsmap`.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(super) struct Key {
        pub(super) device: u32,
        pub(super) physical: u64,
        pub(super) owner: u64,
        pub(super) offset: u64,
        pub(super) length: u64,
        /// The reserved fields are not all zero.
        pub(super) reserved: bool,
    }

    impl Key {
        /// Reads a key from the 64 bytes of a `struct fsmap`.
        pub(super) fn parse(b: &[u8]) -> Self {
            let u64_at = |o: usize| {
                let mut v = [0u8; 8];
                v.copy_from_slice(&b[o..o + 8]);
                u64::from_ne_bytes(v)
            };
            Self {
                device: u32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
                physical: u64_at(8),
                owner: u64_at(16),
                offset: u64_at(24),
                length: u64_at(32),
                reserved: b[40..RECORD].iter().any(|&c| c != 0),
            }
        }
    }

    /// Gives the device number of `dev` as a 32-bit `dev_t`, as `new_encode_dev` of Linux.
    fn encode(dev: u64) -> u32 {
        let (major, minor) = (major(dev), minor(dev));
        (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
    }

    /// Fills the `struct fsmap_head` at `arg` with the map of the space of the file system of
    /// `inode`.
    pub(super) fn ioctl(inode: &InodeRef, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        let mut head = [0u8; HEADER];
        mem.read(arg, &mut head)?;
        let u32_at =
            |o: usize| u32::from_ne_bytes([head[o], head[o + 1], head[o + 2], head[o + 3]]);
        let (iflags, count) = (u32_at(0), u32_at(8));
        let low = Key::parse(&head[KEYS..KEYS + RECORD]);
        let high = Key::parse(&head[KEYS + RECORD..HEADER]);
        if head[16..KEYS].iter().any(|&c| c != 0) || low.reserved || high.reserved {
            return Err(Errno::EINVAL);
        }
        // The map gives no file offsets, so only the offsets of all zeros or all ones are valid.
        if low.offset != 0 || (high.offset != 0 && high.offset != u64::MAX) {
            return Err(Errno::EINVAL);
        }
        // No input flags are defined.
        if iflags != 0 {
            return Err(Errno::EINVAL);
        }
        let meta = inode.metadata();
        let dev = encode(meta.dev);
        if [low.device, high.device].iter().any(|&d| d != 0 && d != u32::MAX && d != dev) {
            return Err(Errno::EINVAL);
        }
        let bits = meta.blksize.max(1).trailing_zeros();
        let records = records(inode, dev, bits, &low, &high)?;
        let entries = if count == 0 {
            u32::try_from(records.len()).unwrap_or(u32::MAX)
        } else {
            let n = records.len().min(count as usize);
            for (i, r) in records.iter().take(n).enumerate() {
                let mut flags = OF_SPECIAL_OWNER;
                if i + 1 == records.len() {
                    flags |= OF_LAST;
                }
                let mut raw = [0u8; RECORD];
                raw[0..4].copy_from_slice(&dev.to_ne_bytes());
                raw[4..8].copy_from_slice(&flags.to_ne_bytes());
                raw[8..16].copy_from_slice(&r.physical.to_ne_bytes());
                raw[16..24].copy_from_slice(&r.owner.to_ne_bytes());
                raw[32..40].copy_from_slice(&r.length.to_ne_bytes());
                mem.write(arg + HEADER + i * RECORD, &raw)?;
            }
            n as u32
        };
        mem.write(arg + 4, &OF_DEV_T.to_ne_bytes())?;
        mem.write(arg + 12, &entries.to_ne_bytes())?;
        Ok(0)
    }

    /// Gives the records between the keys for the device `dev`, with blocks of `1 << bits`
    /// bytes.
    fn records(
        inode: &InodeRef,
        dev: u32,
        bits: u32,
        low: &Key,
        high: &Key,
    ) -> Result<Vec<FsmapRecord>> {
        // The search starts after the low key, which can be the last record of the call before.
        let first = (low.physical >> bits).saturating_add(low.length >> bits);
        let last = high.physical >> bits;
        if (low.device, first, 0) >= (high.device, last, high.owner) {
            return Err(Errno::EINVAL);
        }
        if low.device > dev || high.device < dev {
            return Ok(Vec::new());
        }
        let first = if dev > low.device { 0 } else { first };
        let last = if dev == high.device { last } else { u64::MAX };
        let map = inode.fsmap(first.checked_shl(bits).unwrap_or(u64::MAX))?;
        Ok(select(&map, bits, first, last))
    }

    /// Gives the records of `map` that have blocks from `first` to `last`, as bytes. A free or
    /// unknown area is cut at `first` and at `last`, as Linux.
    pub(super) fn select(
        map: &[FsmapRecord],
        bits: u32,
        first: u64,
        last: u64,
    ) -> Vec<FsmapRecord> {
        let Some(end) = map.last().map(|r| (r.physical + r.length) >> bits) else {
            return Vec::new();
        };
        let last = last.min(end.saturating_sub(1));
        if first >= end || last < first {
            return Vec::new();
        }
        let mut out = Vec::new();
        for r in map {
            let (mut start, mut stop) = (r.physical >> bits, (r.physical + r.length) >> bits);
            if stop <= first || start > last {
                continue;
            }
            if r.owner == fsmap_owner::FREE || r.owner == fsmap_owner::UNKNOWN {
                start = start.max(first);
                stop = stop.min(last + 1);
            }
            out.push(FsmapRecord {
                physical: start << bits,
                length: (stop - start) << bits,
                owner: r.owner,
            });
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn rec(physical: u64, length: u64, owner: u64) -> FsmapRecord {
            FsmapRecord { physical: physical * 1024, length: length * 1024, owner }
        }

        /// A map of 20 blocks of 1 KiB: metadata, free space, a file and free space.
        fn map() -> Vec<FsmapRecord> {
            let meta = (u64::from(b'X') << 32) | 1;
            [rec(1, 4, meta), rec(5, 5, fsmap_owner::FREE), rec(10, 3, fsmap_owner::UNKNOWN)]
                .into_iter()
                .chain([rec(13, 7, fsmap_owner::FREE)])
                .collect()
        }

        #[test]
        fn all_the_map_is_selected_without_keys() {
            assert_eq!(select(&map(), 10, 0, u64::MAX), map());
        }

        #[test]
        fn the_keys_cut_the_free_and_unknown_areas() {
            let meta = (u64::from(b'X') << 32) | 1;
            let got = select(&map(), 10, 3, 11);
            let want =
                [rec(1, 4, meta), rec(5, 5, fsmap_owner::FREE), rec(10, 2, fsmap_owner::UNKNOWN)];
            assert_eq!(got, want);
            assert_eq!(select(&map(), 10, 7, 15)[0], rec(7, 3, fsmap_owner::FREE));
            assert_eq!(select(&map(), 10, 7, 15)[2], rec(13, 3, fsmap_owner::FREE));
        }

        #[test]
        fn a_low_key_at_the_end_gives_no_records() {
            assert!(select(&map(), 10, 20, u64::MAX).is_empty());
            assert!(select(&[], 10, 0, u64::MAX).is_empty());
            assert!(select(&map(), 10, 6, 5).is_empty());
        }

        #[test]
        fn a_key_is_read_from_its_bytes() {
            let mut b = [0u8; RECORD];
            b[0..4].copy_from_slice(&7u32.to_ne_bytes());
            b[8..16].copy_from_slice(&4096u64.to_ne_bytes());
            b[32..40].copy_from_slice(&1024u64.to_ne_bytes());
            let key = Key::parse(&b);
            assert_eq!(
                (key.device, key.physical, key.length, key.reserved),
                (7, 4096, 1024, false)
            );
            b[56] = 1;
            assert!(Key::parse(&b).reserved);
        }

        #[test]
        fn the_device_has_the_encoding_of_linux() {
            assert_eq!(encode(crate::device::makedev(8, 3)), 0x803);
            assert_eq!(encode(crate::device::makedev(259, 0x123)), 0x1_0323 | (0x100 << 12));
        }
    }
}

/// The `whence` of `lseek`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Whence {
    /// `SEEK_SET`.
    Set,
    /// `SEEK_CUR`.
    Current,
    /// `SEEK_END`.
    End,
    /// `SEEK_DATA`, the next data at or after the offset.
    Data,
    /// `SEEK_HOLE`, the next hole at or after the offset.
    Hole,
}

impl Whence {
    /// Gives the value of the `whence` argument, or `None` if it is not known.
    pub fn from_raw(whence: u32) -> Option<Self> {
        Some(match whence {
            0 => Self::Set,
            1 => Self::Current,
            2 => Self::End,
            3 => Self::Data,
            4 => Self::Hole,
            _ => return None,
        })
    }
}

impl File {
    /// Opens the inode at `location` with the operations of the inode. The caller examined the
    /// access mode. A device file must use `with_ops`.
    pub fn open_inode(location: Location, flags: u32) -> Arc<Self> {
        let inode = location.inode().clone();
        Self::new(Arc::new(InodeFile), Some(location), Some(inode), flags)
    }

    /// Opens a file with its own operations. `location` is the place in the tree, if the file
    /// has one.
    pub fn with_ops(ops: Arc<dyn FileOps>, location: Option<Location>, flags: u32) -> Arc<Self> {
        let inode = location.as_ref().map(|l| l.inode().clone());
        Self::new(ops, location, inode, flags)
    }

    fn new(
        ops: Arc<dyn FileOps>,
        location: Option<Location>,
        inode: Option<InodeRef>,
        flags: u32,
    ) -> Arc<Self> {
        // The flags of the call only, as Linux keeps them. `O_CLOEXEC` is a flag of the
        // descriptor.
        let keep = !(o::O_CREAT | o::O_EXCL | o::O_NOCTTY | o::O_TRUNC | o::O_CLOEXEC);
        // A device file and a pipe do not change the file system, as `special_file` of Linux.
        let writer = OpenFlags(flags).writable()
            && inode.as_ref().is_some_and(|i| i.metadata().file_type() == Some(FileType::Regular));
        let writer = match &location {
            Some(location) if writer => {
                location.mount.add_writer();
                true
            }
            _ => false,
        };
        Arc::new(Self {
            ops,
            location,
            inode,
            flags: AtomicU32::new(flags & keep),
            pos: SpinLock::new(0),
            locked: AtomicBool::new(false),
            writer,
        })
    }

    /// Checks that a change of the file can start, as `mnt_want_write_file` of Linux. A file
    /// that the mount counts as a writer can always change. A file without a mount can change.
    ///
    /// # Errors
    ///
    /// Gives `EROFS` if the mount of the file or its file system is read only.
    pub fn want_write(&self) -> Result<()> {
        match &self.location {
            Some(location) if !self.writer => location.mount.want_write(),
            _ => Ok(()),
        }
    }

    /// The access mode and the status flags.
    pub fn flags(&self) -> OpenFlags {
        OpenFlags(self.flags.load(Ordering::Relaxed))
    }

    /// Changes the status flags, for `fcntl(F_SETFL)`. The other flags do not change.
    pub fn set_status_flags(&self, flags: u32) {
        let mask = OpenFlags::SETFL_MASK;
        let _ = self.flags.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
            Some((old & !mask) | (flags & mask))
        });
    }

    /// Records that the file took a lock, so its drop releases the lock.
    pub(crate) fn mark_locked(&self) {
        self.locked.store(true, Ordering::Relaxed);
    }

    /// The place of the file in the tree.
    pub fn location(&self) -> Option<&Location> {
        self.location.as_ref()
    }

    /// The inode, if the file has one.
    pub fn inode(&self) -> Option<&InodeRef> {
        self.inode.as_ref()
    }

    /// The operations of the file, for a caller that knows the type of the file.
    pub fn ops(&self) -> &Arc<dyn FileOps> {
        &self.ops
    }

    /// The position.
    pub fn pos(&self) -> u64 {
        *self.pos.lock()
    }

    /// Sets the position, for a `FileOps` that keeps a position of its own kind.
    pub fn set_pos(&self, pos: u64) {
        *self.pos.lock() = pos;
    }

    /// `read`.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if !self.flags().readable() {
            return Err(Errno::EBADF);
        }
        let n = self.ops.read(self, buf)?;
        self.notify_access(n);
        Ok(n)
    }

    /// The event of a read of `n` bytes, as `fsnotify_access` in `vfs_read` of Linux.
    fn notify_access(&self, n: usize) {
        if n > 0 {
            crate::notify::access(self.location.as_ref(), self.inode.as_ref());
        }
    }

    /// The event of a write of `n` bytes, as `fsnotify_modify` in `vfs_write` of Linux.
    fn notify_modify(&self, n: usize) {
        if n > 0 {
            crate::notify::modify(self.location.as_ref(), self.inode.as_ref());
        }
    }

    /// Clears the set-user-ID and set-group-ID bits of a regular file before a write, as
    /// `file_remove_privs` of Linux. A process with `CAP_FSETID` keeps them.
    fn remove_privs(&self) -> Result<()> {
        let Some(inode) = &self.inode else {
            return Ok(());
        };
        let meta = inode.metadata();
        if meta.mode & (mode::S_ISUID | mode::S_ISGID) == 0 {
            return Ok(());
        }
        match crate::cred::current().write_kill(&meta) {
            Some(perm) => inode.set_attr(&SetAttr { mode: Some(perm), ..SetAttr::default() }),
            None => Ok(()),
        }
    }

    /// `write`.
    pub fn write(&self, buf: &[u8]) -> Result<usize> {
        if !self.flags().writable() {
            return Err(Errno::EBADF);
        }
        self.remove_privs()?;
        let n = self.ops.write(self, buf)?;
        self.notify_modify(n);
        Ok(n)
    }

    /// `pread64`.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if !self.flags().readable() {
            return Err(Errno::EBADF);
        }
        let n = self.ops.read_at(self, offset, buf)?;
        self.notify_access(n);
        Ok(n)
    }

    /// `pwrite64`.
    pub fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        if !self.flags().writable() {
            return Err(Errno::EBADF);
        }
        self.remove_privs()?;
        let n = self.ops.write_at(self, offset, buf)?;
        self.notify_modify(n);
        Ok(n)
    }

    /// `lseek`. Gives the new position.
    pub fn seek(&self, offset: i64, whence: Whence) -> Result<u64> {
        if self.flags().is_path() {
            return Err(Errno::EBADF);
        }
        if let Some(result) = self.ops.llseek(self, offset, whence) {
            return result;
        }
        if !self.ops.seekable() {
            return Err(Errno::ESPIPE);
        }
        let end = || match self.ops.end() {
            Some(end) => Ok(end),
            None => self.metadata().map(|m| m.size),
        };
        let mut pos = self.pos.lock();
        let new = match whence {
            Whence::Set => 0u64.checked_add_signed(offset),
            Whence::Current => pos.checked_add_signed(offset),
            Whence::End => end()?.checked_add_signed(offset),
            Whence::Data | Whence::Hole => {
                let size = end()?;
                let at = u64::try_from(offset).map_err(|_| Errno::ENXIO)?;
                if at >= size {
                    return Err(Errno::ENXIO);
                }
                Some(self.seek_extent(at, size, whence == Whence::Data)?)
            }
        };
        let new = new.ok_or(Errno::EINVAL)?;
        if new > i64::MAX as u64 {
            return Err(Errno::EINVAL);
        }
        *pos = new;
        Ok(new)
    }

    /// Gives the next data or the next hole at or after `at`, for an offset before `size`. The
    /// extents of the inode give the holes. An unwritten extent is a hole. Without the extents,
    /// as the generic code of Linux, all the file is data and the end is the only hole.
    fn seek_extent(&self, at: u64, size: u64, data: bool) -> Result<u64> {
        let extents = match self.inode.as_ref().map(|i| i.fiemap(at, u64::MAX - at)) {
            Some(Ok(extents)) => extents,
            None | Some(Err(Errno::EOPNOTSUPP)) => return Ok(if data { at } else { size }),
            Some(Err(e)) => return Err(e),
        };
        let mut written = extents.iter().filter(|e| !e.unwritten);
        if data {
            let next = written.find(|e| e.logical + e.length > at).map(|e| e.logical.max(at));
            return next.filter(|&next| next < size).ok_or(Errno::ENXIO);
        }
        let mut pos = at;
        for e in written {
            if e.logical > pos {
                break;
            }
            pos = pos.max(e.logical + e.length);
        }
        Ok(pos.min(size))
    }

    /// `fsync` and `fdatasync`. The inode makes its changes durable, and then the file.
    pub fn sync(&self) -> Result<()> {
        if let Some(inode) = &self.inode {
            inode.sync()?;
        }
        self.ops.sync()
    }

    /// Makes a write durable before it returns when the file has `O_DSYNC` or `O_SYNC`, or the
    /// inode has the flag `S_SYNC`, as `generic_write_sync` of Linux. The new data and the new
    /// size go to the journal, so a crash after the write keeps them.
    pub fn write_sync(&self) -> Result<()> {
        let flag = self.inode.as_ref().map_or(0, |i| i.attr_flags().unwrap_or(0));
        if self.flags().dsync() || flag & crate::inode::iflags::SYNC != 0 {
            self.sync()?;
        }
        Ok(())
    }

    /// Does a batch of reads and writes at offsets. An entry gets `EBADF` if the file is not open
    /// for it.
    pub fn rw_batch(&self, ios: &mut [BatchIo]) {
        let (readable, writable) = (self.flags().readable(), self.flags().writable());
        let mut ok = Vec::with_capacity(ios.len());
        for io in ios.iter_mut() {
            let allowed = if io.write { writable } else { readable };
            if !allowed {
                io.result = Err(Errno::EBADF);
            }
            ok.push(allowed);
        }
        if ok.iter().all(|&a| a) {
            self.ops.rw_batch(self, ios);
        } else {
            for (io, allowed) in ios.iter_mut().zip(ok) {
                if allowed {
                    self.ops.rw_batch(self, core::slice::from_mut(io));
                }
            }
        }
    }

    /// `ioctl`.
    pub fn ioctl(&self, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        if self.flags().is_path() {
            return Err(Errno::EBADF);
        }
        self.ops.ioctl(self, cmd, arg, mem)
    }

    /// The events of `poll` that are true now.
    pub fn poll(&self) -> u32 {
        self.ops.poll(self)
    }

    /// Tells if the file has its own `poll`, for `epoll_ctl`.
    pub fn pollable(&self) -> bool {
        self.ops.pollable()
    }

    /// The count of the events of the file, for an edge triggered epoll entry.
    pub fn event_count(&self) -> u64 {
        self.ops.event_count()
    }

    /// The lines of `/proc/PID/fdinfo` that the type of the file adds.
    pub fn fdinfo(&self) -> Vec<u8> {
        self.ops.fdinfo(self)
    }

    /// The attributes, for `fstat`.
    pub fn metadata(&self) -> Result<Metadata> {
        match (&self.inode, self.ops.metadata()) {
            (_, Some(m)) => Ok(m),
            (Some(inode), None) => Ok(inode.metadata()),
            (None, None) => Err(Errno::EBADF),
        }
    }

    /// `ftruncate`.
    pub fn truncate(&self, size: u64) -> Result<()> {
        let inode = self.inode.as_ref().ok_or(Errno::EINVAL)?;
        if !self.flags().writable() || inode.metadata().file_type() != Some(FileType::Regular) {
            return Err(Errno::EINVAL);
        }
        let mode = crate::cred::current().write_kill(&inode.metadata());
        let attr = SetAttr { size: Some(size), mode, ..SetAttr::default() };
        check_set_attr(&**inode, &attr)?;
        crate::mapped::extend(inode, size);
        inode.set_attr(&attr)?;
        crate::mapped::changed(inode, size, u64::MAX);
        crate::notify::change(self.location.as_ref(), inode, &attr);
        Ok(())
    }

    /// `fallocate`. The caller checked the mode, the offset and the length.
    pub fn fallocate(&self, mode: u32, offset: u64, len: u64) -> Result<()> {
        if !self.flags().writable() {
            return Err(Errno::EBADF);
        }
        let inode = self.inode.as_ref().ok_or(Errno::ENODEV)?;
        // An append-only file only takes new blocks, as `vfs_fallocate` of Linux.
        check_immutable(&**inode)?;
        crate::swap::check(&**inode)?;
        if mode & !crate::inode::falloc::KEEP_SIZE != 0 {
            crate::inode::check_fixed(&**inode)?;
        }
        match inode.metadata().file_type() {
            Some(FileType::Regular) => {
                self.remove_privs()?;
                if mode & crate::inode::falloc::KEEP_SIZE == 0 {
                    crate::mapped::extend(inode, offset.saturating_add(len));
                }
                inode.fallocate(mode, offset, len)?;
                // A collapse or an insert moves the data after the range.
                crate::mapped::changed(inode, offset, u64::MAX);
                Ok(())
            }
            Some(FileType::Fifo) => Err(Errno::ESPIPE),
            Some(FileType::Directory) => Err(Errno::EISDIR),
            _ => Err(Errno::ENODEV),
        }
    }

    /// `EXT4_IOC_MOVE_EXT` on this file with `donor` as the donor file. Gives the number of
    /// blocks that moved. The checks are those of `ext4_ioctl` of Linux, in its order.
    pub fn move_extents(
        &self,
        donor: &File,
        orig_start: u64,
        donor_start: u64,
        len: u64,
    ) -> Result<u64> {
        let inode = self.inode.as_ref().ok_or(Errno::ENOTTY)?;
        if !self.flags().readable() || !self.flags().writable() || !donor.flags().writable() {
            return Err(Errno::EBADF);
        }
        let other = donor.inode.as_ref().ok_or(Errno::EXDEV)?;
        if other.fs_id() != inode.fs_id() {
            return Err(Errno::EXDEV);
        }
        crate::swap::check(&**inode)?;
        crate::swap::check(&**other)?;
        // The pages that a mapping changed go to the blocks before the blocks swap.
        crate::mapped::sync(inode, 0, u64::MAX)?;
        crate::mapped::sync(other, 0, u64::MAX)?;
        let moved = inode.move_extents(other, orig_start, donor_start, len)?;
        // The donor has the old data of this file now.
        crate::mapped::changed(other, 0, u64::MAX);
        Ok(moved)
    }

    /// Fills `buf` with `struct linux_dirent64` records from the position of the directory, for
    /// `getdents64`. Gives the number of bytes. A record that does not fit stays for the next
    /// call. Gives `EINVAL` if the first record does not fit.
    pub fn read_dir(&self, buf: &mut [u8]) -> Result<usize> {
        let inode = self.inode.as_ref().ok_or(Errno::ENOTDIR)?;
        if self.flags().is_path() {
            return Err(Errno::EBADF);
        }
        let mut pos = self.pos.lock();
        let mut used = 0;
        while let Some((entry, next)) = inode.read_dir(*pos)? {
            // d_ino, d_off, d_reclen, d_type, the name and its zero byte, padded to 8 bytes.
            let len = (19 + entry.name.len() + 1).next_multiple_of(8);
            if used + len > buf.len() {
                if used == 0 {
                    return Err(Errno::EINVAL);
                }
                break;
            }
            let rec = &mut buf[used..used + len];
            rec.fill(0);
            rec[0..8].copy_from_slice(&entry.ino.to_ne_bytes());
            rec[8..16].copy_from_slice(&next.to_ne_bytes());
            rec[16..18].copy_from_slice(&(len as u16).to_ne_bytes());
            rec[18] = entry.kind.dirent_type();
            rec[19..19 + entry.name.len()].copy_from_slice(&entry.name);
            used += len;
            *pos = next;
        }
        drop(pos);
        self.accessed();
        // As `iterate_dir` of Linux.
        crate::notify::access(self.location.as_ref(), self.inode.as_ref());
        Ok(used)
    }

    /// Updates the access time after a read, with the rules of `atime_needs_update` of Linux.
    /// A noatime mount, a nodiratime mount for a directory, a read only mount, a read only file
    /// system and `O_NOATIME` keep the time. A relatime mount, the default, updates the time only if it is not after
    /// the modification time or the change time, or if it is one day old. An error is ignored,
    /// as Linux does.
    fn accessed(&self) {
        const DAY: i64 = 24 * 60 * 60;
        let (Some(location), Some(inode)) = (self.location(), self.inode()) else {
            return;
        };
        if self.flags.load(Ordering::Relaxed) & o::O_NOATIME != 0 {
            return;
        }
        let flags = location.mount.flags() as u32;
        let meta = inode.metadata();
        if flags & mount::MS_NOATIME != 0
            || location.mount.is_read_only()
            || (meta.is_dir() && flags & mount::MS_NODIRATIME != 0)
        {
            return;
        }
        let now = crate::inode::now();
        if flags & mount::MS_STRICTATIME == 0
            && meta.atime > meta.mtime
            && meta.atime > meta.ctime
            && now.sec - meta.atime.sec < DAY
        {
            return;
        }
        if meta.atime != now {
            let _ = inode.set_atime(now);
        }
    }
}

/// Reads all of a file from its start, for the ELF loader and for tests.
pub fn read_all(inode: &InodeRef) -> Result<Vec<u8>> {
    let size = inode.metadata().size as usize;
    let mut data = alloc::vec![0; size];
    let mut done = 0;
    while done < size {
        let n = inode.read_at(done as u64, &mut data[done..])?;
        if n == 0 {
            break;
        }
        done += n;
    }
    data.truncate(done);
    Ok(data)
}

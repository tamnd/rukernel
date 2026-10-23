//! Open files.
//!
//! A `File` is an open file description of POSIX: the object that `open` makes and that `dup` and
//! `fork` share. It has the status flags and the file position. The `FileOps` of the file do the
//! work. A regular file and a directory use the operations of their inode. A device, a pipe and a
//! socket give their own operations.

use crate::dentry::Location;
use crate::inode::{FileType, InodeRef, Metadata, Result, SetAttr};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use rk_abi::Errno;
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

    /// Runs an `ioctl` command.
    fn ioctl(&self, _file: &File, _cmd: u32, _arg: usize, _mem: &dyn UserMemory) -> Result<usize> {
        Err(Errno::ENOTTY)
    }

    /// The events of `poll` that are true now.
    fn poll(&self, _file: &File) -> u32 {
        events::POLLIN | events::POLLOUT
    }

    /// The attributes, for `fstat` of a file that has no inode.
    fn metadata(&self) -> Option<Metadata> {
        None
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
}

/// An open file description.
pub struct File {
    ops: Arc<dyn FileOps>,
    location: Option<Location>,
    inode: Option<InodeRef>,
    flags: AtomicU32,
    pos: SpinLock<u64>,
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
        let n = inode.read_at(*pos, buf)?;
        *pos += n as u64;
        Ok(n)
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize> {
        let inode = file.inode.as_ref().ok_or(Errno::EINVAL)?;
        let mut pos = file.pos.lock();
        if file.flags().append() {
            *pos = inode.metadata().size;
        }
        let n = inode.write_at(*pos, buf)?;
        *pos += n as u64;
        Ok(n)
    }

    fn read_at(&self, file: &File, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let inode = file.inode.as_ref().ok_or(Errno::EINVAL)?;
        if inode.metadata().is_dir() {
            return Err(Errno::EISDIR);
        }
        inode.read_at(offset, buf)
    }

    fn write_at(&self, file: &File, offset: u64, buf: &[u8]) -> Result<usize> {
        let inode = file.inode.as_ref().ok_or(Errno::EINVAL)?;
        inode.write_at(offset, buf)
    }

    fn seekable(&self) -> bool {
        true
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
}

impl Whence {
    /// Gives the value of the `whence` argument. `SEEK_DATA` and `SEEK_HOLE` are not supported
    /// yet, so they give `None`.
    pub fn from_raw(whence: u32) -> Option<Self> {
        Some(match whence {
            0 => Self::Set,
            1 => Self::Current,
            2 => Self::End,
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
        Arc::new(Self {
            ops,
            location,
            inode,
            flags: AtomicU32::new(flags & keep),
            pos: SpinLock::new(0),
        })
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
        self.ops.read(self, buf)
    }

    /// `write`.
    pub fn write(&self, buf: &[u8]) -> Result<usize> {
        if !self.flags().writable() {
            return Err(Errno::EBADF);
        }
        self.ops.write(self, buf)
    }

    /// `pread64`.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if !self.flags().readable() {
            return Err(Errno::EBADF);
        }
        self.ops.read_at(self, offset, buf)
    }

    /// `pwrite64`.
    pub fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        if !self.flags().writable() {
            return Err(Errno::EBADF);
        }
        self.ops.write_at(self, offset, buf)
    }

    /// `lseek`. Gives the new position.
    pub fn seek(&self, offset: i64, whence: Whence) -> Result<u64> {
        if self.flags().is_path() {
            return Err(Errno::EBADF);
        }
        if !self.ops.seekable() {
            return Err(Errno::ESPIPE);
        }
        let mut pos = self.pos.lock();
        let base = match whence {
            Whence::Set => 0,
            Whence::Current => *pos,
            Whence::End => self.metadata()?.size,
        };
        let new = base.checked_add_signed(offset).ok_or(Errno::EINVAL)?;
        if new > i64::MAX as u64 {
            return Err(Errno::EINVAL);
        }
        *pos = new;
        Ok(new)
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
        inode.set_attr(&SetAttr { size: Some(size), ..SetAttr::default() })
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
        Ok(used)
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

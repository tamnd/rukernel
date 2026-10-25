//! Inodes: the objects of a file system.
//!
//! An `Inode` is a file, a directory, a symbolic link or a special file of one file system. Linux
//! splits the operations into `inode_operations` and `file_operations`. Here the `Inode` trait has
//! the operations on the name space and the data of a regular file. A device, a pipe or a socket
//! gives its own `FileOps` when it is opened.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_frame::sync::Once;

/// The result of a VFS operation.
pub type Result<T> = core::result::Result<T, Errno>;

/// A shared reference to an inode.
pub type InodeRef = Arc<dyn Inode>;

/// The mode bits of `st_mode`. They are the same on each architecture.
pub mod mode {
    pub use rk_abi::native::stat::{
        S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK, S_ISGID, S_ISUID,
        S_ISVTX,
    };

    /// The permission bits and the set ID and sticky bits.
    pub const PERM_MASK: u32 = 0o7777;
}

/// The type of a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    /// A regular file.
    Regular,
    /// A directory.
    Directory,
    /// A symbolic link.
    Symlink,
    /// A character device.
    CharDevice,
    /// A block device.
    BlockDevice,
    /// A named pipe.
    Fifo,
    /// A socket.
    Socket,
}

impl FileType {
    /// Gives the type of the `S_IFMT` bits of `mode`.
    pub fn from_mode(mode: u32) -> Option<Self> {
        Some(match mode & mode::S_IFMT {
            mode::S_IFREG => Self::Regular,
            mode::S_IFDIR => Self::Directory,
            mode::S_IFLNK => Self::Symlink,
            mode::S_IFCHR => Self::CharDevice,
            mode::S_IFBLK => Self::BlockDevice,
            mode::S_IFIFO => Self::Fifo,
            mode::S_IFSOCK => Self::Socket,
            _ => return None,
        })
    }

    /// The `S_IFMT` bits of the type.
    pub fn mode_bits(self) -> u32 {
        match self {
            Self::Regular => mode::S_IFREG,
            Self::Directory => mode::S_IFDIR,
            Self::Symlink => mode::S_IFLNK,
            Self::CharDevice => mode::S_IFCHR,
            Self::BlockDevice => mode::S_IFBLK,
            Self::Fifo => mode::S_IFIFO,
            Self::Socket => mode::S_IFSOCK,
        }
    }

    /// The `d_type` of `getdents64`: `DT_REG`, `DT_DIR` and the others.
    pub fn dirent_type(self) -> u8 {
        (self.mode_bits() >> 12) as u8
    }
}

/// A time stamp of an inode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timespec {
    /// The seconds since the epoch.
    pub sec: i64,
    /// The nanoseconds, below 1,000,000,000.
    pub nsec: u32,
}

static CLOCK: Once<fn() -> Timespec> = Once::new();

/// Gives the VFS the clock of the time stamps. Only the first call has an effect. Before the
/// call, each time stamp is zero.
pub fn set_clock(clock: fn() -> Timespec) {
    CLOCK.call_once(|| clock);
}

/// The time for a new time stamp.
pub fn now() -> Timespec {
    CLOCK.get().map_or(Timespec::default(), |clock| clock())
}

/// The attributes of an inode, as `stat` gives them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Metadata {
    /// The device of the file system.
    pub dev: u64,
    /// The inode number.
    pub ino: u64,
    /// The type and the permission bits.
    pub mode: u32,
    /// The number of hard links.
    pub nlink: u32,
    /// The owner.
    pub uid: u32,
    /// The group.
    pub gid: u32,
    /// The device that a device file is for.
    pub rdev: u64,
    /// The size in bytes.
    pub size: u64,
    /// The preferred block size for I/O.
    pub blksize: u32,
    /// The number of 512 byte blocks that the file uses.
    pub blocks: u64,
    /// The time of the last access.
    pub atime: Timespec,
    /// The time of the last change of the data.
    pub mtime: Timespec,
    /// The time of the last change of the inode.
    pub ctime: Timespec,
}

impl Metadata {
    /// The type of the file.
    pub fn file_type(&self) -> Option<FileType> {
        FileType::from_mode(self.mode)
    }

    /// Tells if the file is a directory.
    pub fn is_dir(&self) -> bool {
        self.mode & mode::S_IFMT == mode::S_IFDIR
    }
}

/// The counts of a file system, as `statfs` gives them. The counts of blocks are in units of
/// `bsize` bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FsStat {
    /// The size of a block in bytes.
    pub bsize: u64,
    /// The number of blocks for data.
    pub blocks: u64,
    /// The number of free blocks.
    pub bfree: u64,
    /// The number of free blocks that a user without privileges can use.
    pub bavail: u64,
    /// The number of inodes.
    pub files: u64,
    /// The number of free inodes.
    pub ffree: u64,
}

/// A change of the attributes, as `chmod`, `chown`, `truncate` and `utimensat` give it. A field
/// with `None` does not change.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SetAttr {
    /// The new permission bits.
    pub mode: Option<u32>,
    /// The new owner.
    pub uid: Option<u32>,
    /// The new group.
    pub gid: Option<u32>,
    /// The new size.
    pub size: Option<u64>,
    /// The new access time.
    pub atime: Option<Timespec>,
    /// The new modification time.
    pub mtime: Option<Timespec>,
    /// The caller gave a time that is not the time now, as `ATTR_TIMES_SET` of Linux. An
    /// append-only file refuses it.
    pub explicit_times: bool,
}

/// One entry of a directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// The inode number.
    pub ino: u64,
    /// The type of the file.
    pub kind: FileType,
    /// The name.
    pub name: Vec<u8>,
}

/// Gives a new device number for a file system that has no device, as `get_anon_bdev` of Linux.
/// The major number is 0.
pub fn anon_dev() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// An object of a file system.
///
/// The VFS examines the arguments that are the same for each file system before it calls an
/// operation. A name is never empty, `.` or `..`, and has no `/`. `create` and `link` are called
/// only for a name that is not in the directory. `unlink` is called for a file that is not a
/// directory and `rmdir` for a directory. The default of each operation gives the error of
/// Linux for an inode that does not have the operation.
pub trait Inode: Any + Send + Sync {
    /// The attributes.
    fn metadata(&self) -> Metadata;

    /// Changes the attributes. A change of the size is for a regular file only.
    fn set_attr(&self, attr: &SetAttr) -> Result<()>;

    /// Sets the access time after a read, and does not change the change time, as
    /// `touch_atime` of Linux. The default does nothing, for a file system that keeps no access
    /// time.
    fn set_atime(&self, _time: Timespec) -> Result<()> {
        Ok(())
    }

    /// Reads the data of a regular file at `offset`. Gives the number of bytes read, which is 0
    /// at the end of the file.
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize> {
        Err(Errno::EINVAL)
    }

    /// Writes the data of a regular file at `offset`, and makes the file larger if it is
    /// necessary. Gives the number of bytes written.
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> Result<usize> {
        Err(Errno::EINVAL)
    }

    /// Changes the space of a regular file in `offset..offset + len`, for `fallocate`. `mode` has
    /// the `FALLOC_FL_*` bits of [`falloc`], and the caller checked them. The default gives
    /// `EOPNOTSUPP`.
    fn fallocate(&self, _mode: u32, _offset: u64, _len: u64) -> Result<()> {
        Err(Errno::EOPNOTSUPP)
    }

    /// Gives the extents of a regular file that have bytes in `start..start + len`, in order,
    /// for `FS_IOC_FIEMAP`. The default gives `EOPNOTSUPP`.
    fn fiemap(&self, _start: u64, _len: u64) -> Result<Vec<FiemapExtent>> {
        Err(Errno::EOPNOTSUPP)
    }

    /// Gives the inode flags of [`iflags`], for `FS_IOC_GETFLAGS`. The default gives `ENOTTY`, as
    /// Linux gives for a file system that does not have the ioctl.
    fn attr_flags(&self) -> Result<u32> {
        Err(Errno::ENOTTY)
    }

    /// Sets the inode flags of [`iflags`], for `FS_IOC_SETFLAGS`. A file system gives
    /// `EOPNOTSUPP` for a flag that it does not keep. The default gives `ENOTTY`.
    fn set_attr_flags(&self, _flags: u32) -> Result<()> {
        Err(Errno::ENOTTY)
    }

    /// Makes the changes of the inode durable, for `fsync`. A file system that keeps all its
    /// changes in one journal can make all of them durable. The default does nothing.
    fn sync(&self) -> Result<()> {
        Ok(())
    }

    /// Finds the inode of `name` in this directory.
    fn lookup(&self, _name: &[u8]) -> Result<InodeRef> {
        Err(Errno::ENOTDIR)
    }

    /// Makes a new file of the type `kind` with the permission bits `perm`. `rdev` is for a
    /// device file. A symbolic link is made with `symlink`.
    fn create(&self, _name: &[u8], _kind: FileType, _perm: u32, _rdev: u64) -> Result<InodeRef> {
        Err(Errno::ENOTDIR)
    }

    /// Makes a symbolic link to `target`.
    fn symlink(&self, _name: &[u8], _target: &[u8]) -> Result<InodeRef> {
        Err(Errno::ENOTDIR)
    }

    /// Adds a hard link to `inode`, which is not a directory and is in the same file system.
    fn link(&self, _name: &[u8], _inode: &InodeRef) -> Result<()> {
        Err(Errno::ENOTDIR)
    }

    /// Removes the name of a file that is not a directory.
    fn unlink(&self, _name: &[u8]) -> Result<()> {
        Err(Errno::ENOTDIR)
    }

    /// Removes an empty directory. Gives `ENOTEMPTY` if the directory has entries.
    fn rmdir(&self, _name: &[u8]) -> Result<()> {
        Err(Errno::ENOTDIR)
    }

    /// Moves `old` of this directory to `new` of `new_dir`, which is in the same file system. The
    /// VFS examined the types: if `new` exists, it is a directory only if `old` is a directory.
    /// The file system replaces `new`, and gives `ENOTEMPTY` for a directory with entries.
    fn rename(&self, _old: &[u8], _new_dir: &InodeRef, _new: &[u8]) -> Result<()> {
        Err(Errno::ENOTDIR)
    }

    /// The target of a symbolic link.
    fn read_link(&self) -> Result<Vec<u8>> {
        Err(Errno::EINVAL)
    }

    /// The target of a symbolic link for a walk that follows it. A link of `/proc/PID/fd` to a
    /// file that cannot open again gives an error here, as the magic links of Linux.
    fn follow_link(&self) -> Result<Vec<u8>> {
        self.read_link()
    }

    /// Gives the entry at the position `pos` of a directory and the position of the next entry,
    /// or `None` at the end. Position 0 is the first entry. The entries `.` and `..` are first.
    fn read_dir(&self, _pos: u64) -> Result<Option<(DirEntry, u64)>> {
        Err(Errno::ENOTDIR)
    }

    /// Gives the value of the extended attribute `name`, which has its namespace prefix, for
    /// example `user.color`. Gives `ENODATA` if the inode does not have the attribute. The
    /// default is for a file system that keeps no extended attributes.
    fn get_xattr(&self, _name: &[u8]) -> Result<Vec<u8>> {
        Err(Errno::ENODATA)
    }

    /// Sets the extended attribute `name` to `value`. `flags` is 0, `XATTR_CREATE` or
    /// `XATTR_REPLACE`. `XATTR_CREATE` gives `EEXIST` if the attribute exists, and
    /// `XATTR_REPLACE` gives `ENODATA` if it does not exist.
    fn set_xattr(&self, _name: &[u8], _value: &[u8], _flags: u32) -> Result<()> {
        Err(Errno::EOPNOTSUPP)
    }

    /// Gives the names of the extended attributes of the inode.
    fn list_xattr(&self) -> Result<Vec<Vec<u8>>> {
        Ok(Vec::new())
    }

    /// Removes the extended attribute `name`. Gives `ENODATA` if the inode does not have it.
    fn remove_xattr(&self, _name: &[u8]) -> Result<()> {
        Err(Errno::ENODATA)
    }

    /// The device of the file system, for a rename or a link across file systems.
    fn fs_id(&self) -> u64 {
        self.metadata().dev
    }

    /// The counts of the file system, for `statfs`. `None` gives counts of 0, as for a file
    /// system without a size.
    fn fs_stat(&self) -> Option<FsStat> {
        None
    }

    /// The magic number of the file system, as `f_type` of `statfs` gives it. The values are in
    /// `<linux/magic.h>`.
    fn fs_magic(&self) -> u64 {
        0
    }
}

/// One extent of a file for `FS_IOC_FIEMAP`, in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FiemapExtent {
    /// The offset in the file.
    pub logical: u64,
    /// The offset on the disk.
    pub physical: u64,
    /// The length.
    pub length: u64,
    /// The extent has blocks that are not written, and it reads as zeros.
    pub unwritten: bool,
}

/// The inode flags of `FS_IOC_GETFLAGS` and `FS_IOC_SETFLAGS`, from `<linux/fs.h>`. `chattr`
/// and `lsattr` use them.
pub mod iflags {
    /// The changes of the file are written at once.
    pub const SYNC: u32 = 0x08;
    /// The file cannot change, and no name can change to or from it.
    pub const IMMUTABLE: u32 = 0x10;
    /// The file can only get data at its end.
    pub const APPEND: u32 = 0x20;
    /// `dump` does not save the file.
    pub const NODUMP: u32 = 0x40;
    /// A read does not change the access time.
    pub const NOATIME: u32 = 0x80;
}

/// Gives the inode flags of `inode`, or 0 if its file system does not keep them.
fn flags_of(inode: &dyn Inode) -> u32 {
    inode.attr_flags().unwrap_or(0)
}

/// Gives `EPERM` if `inode` is immutable, for a change of the data, the attributes or the names
/// of a directory.
///
/// # Errors
///
/// Gives `EPERM` if the inode has [`iflags::IMMUTABLE`].
pub fn check_immutable(inode: &dyn Inode) -> Result<()> {
    if flags_of(inode) & iflags::IMMUTABLE != 0 { Err(Errno::EPERM) } else { Ok(()) }
}

/// Gives `EPERM` if `inode` is immutable or append-only, for a change that an append-only file
/// also refuses: an unlink, a rename, a link, a truncate, or a change of the owner, the mode or
/// an extended attribute.
///
/// # Errors
///
/// Gives `EPERM` if the inode has [`iflags::IMMUTABLE`] or [`iflags::APPEND`].
pub fn check_fixed(inode: &dyn Inode) -> Result<()> {
    if flags_of(inode) & (iflags::IMMUTABLE | iflags::APPEND) != 0 {
        Err(Errno::EPERM)
    } else {
        Ok(())
    }
}

/// The checks of the inode flags for a change of attributes, as `notify_change` of Linux. An
/// immutable file refuses all changes. An append-only file only takes a change of the times.
///
/// # Errors
///
/// Gives `EPERM` if the flags refuse the change.
pub fn check_set_attr(inode: &dyn Inode, attr: &SetAttr) -> Result<()> {
    let flags = flags_of(inode);
    let fixed = attr.size.is_some()
        || attr.mode.is_some()
        || attr.uid.is_some()
        || attr.gid.is_some()
        || attr.explicit_times;
    if flags & iflags::IMMUTABLE != 0 || (flags & iflags::APPEND != 0 && fixed) {
        return Err(Errno::EPERM);
    }
    Ok(())
}

/// The modes of `fallocate`, from `<linux/falloc.h>`.
pub mod falloc {
    /// The size of the file does not change.
    pub const KEEP_SIZE: u32 = 0x01;
    /// Frees the blocks of the range. The range reads as zeros after.
    pub const PUNCH_HOLE: u32 = 0x02;
    /// Removes the range, and the data after it moves down.
    pub const COLLAPSE_RANGE: u32 = 0x08;
    /// The range reads as zeros, and has blocks.
    pub const ZERO_RANGE: u32 = 0x10;
    /// Adds a hole at the range, and the data after it moves up.
    pub const INSERT_RANGE: u32 = 0x20;
    /// Gives the file its own copy of the blocks that it shares.
    pub const UNSHARE_RANGE: u32 = 0x40;
}

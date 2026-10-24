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

    /// The device of the file system, for a rename or a link across file systems.
    fn fs_id(&self) -> u64 {
        self.metadata().dev
    }

    /// The magic number of the file system, as `f_type` of `statfs` gives it. The values are in
    /// `<linux/magic.h>`.
    fn fs_magic(&self) -> u64 {
        0
    }
}

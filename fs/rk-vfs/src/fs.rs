//! The file system context of a process and the operations on names.
//!
//! An `FsContext` is the `fs_struct` of Linux: the name space, the root, the current directory and
//! the umask of a process. Its methods are the VFS part of the system calls on names: `openat`,
//! `mkdirat`, `unlinkat`, `renameat2` and the others. The caller gives the start of a relative
//! path, which is the current directory or the directory of a descriptor.
//!
//! In R1 each process runs as root, so the VFS does not examine the permission bits yet.

use crate::dentry::{Location, MountNamespace, MountSource};
use crate::device;
use crate::file::File;
use crate::inode::{FileType, InodeRef, Result, SetAttr, mode};
use crate::path::{Parent, Walk};
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::open as o;

/// The flags of `renameat2`.
pub mod rename_flags {
    pub use rk_abi::native::at::{AT_RENAME_EXCHANGE, AT_RENAME_NOREPLACE, AT_RENAME_WHITEOUT};
}

/// The name space, the root, the current directory and the umask of a process.
#[derive(Clone)]
pub struct FsContext {
    ns: Arc<MountNamespace>,
    root: Location,
    cwd: Location,
    umask: u32,
}

impl core::fmt::Debug for FsContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FsContext").field("umask", &self.umask).finish_non_exhaustive()
    }
}

/// Tells if a lookup error means that the name is not in the directory.
fn absent<T>(r: &Result<T>) -> bool {
    matches!(r, Err(e) if *e == Errno::ENOENT)
}

impl FsContext {
    /// Makes the context of the first process: the root of `ns` is its root and its current
    /// directory. The umask is 022, as Linux gives to init.
    pub fn new(ns: Arc<MountNamespace>) -> Self {
        let root = ns.root();
        Self { ns, cwd: root.clone(), root, umask: 0o022 }
    }

    /// The mount name space.
    pub fn namespace(&self) -> &Arc<MountNamespace> {
        &self.ns
    }

    /// The root of the process.
    pub fn root(&self) -> &Location {
        &self.root
    }

    /// The current directory.
    pub fn cwd(&self) -> &Location {
        &self.cwd
    }

    /// The umask.
    pub fn umask(&self) -> u32 {
        self.umask
    }

    /// Sets the umask and gives the old umask.
    pub fn set_umask(&mut self, umask: u32) -> u32 {
        core::mem::replace(&mut self.umask, umask & 0o777)
    }

    fn walk(&self) -> Walk<'_> {
        Walk::new(&self.ns, &self.root)
    }

    /// Gives the location of `path`, from `start` for a relative path.
    pub fn resolve(&self, start: &Location, path: &[u8], follow: bool) -> Result<Location> {
        self.walk().resolve(start, path, follow)
    }

    fn parent(&self, start: &Location, path: &[u8]) -> Result<Parent> {
        self.walk().resolve_parent(start, path)
    }

    /// `chdir`.
    pub fn chdir(&mut self, start: &Location, path: &[u8]) -> Result<()> {
        let at = self.resolve(start, path, true)?;
        self.set_cwd(at)
    }

    /// `fchdir`, and the end of `chdir`.
    pub fn set_cwd(&mut self, at: Location) -> Result<()> {
        if !at.inode().metadata().is_dir() {
            return Err(Errno::ENOTDIR);
        }
        self.cwd = at;
        Ok(())
    }

    /// `chroot`.
    pub fn chroot(&mut self, start: &Location, path: &[u8]) -> Result<()> {
        let at = self.resolve(start, path, true)?;
        if !at.inode().metadata().is_dir() {
            return Err(Errno::ENOTDIR);
        }
        self.root = at;
        Ok(())
    }

    /// `getcwd`.
    pub fn getcwd(&self) -> Result<Vec<u8>> {
        self.walk().path_of(&self.cwd)
    }

    /// The absolute path of `at`, for `/proc/self/fd` and the other places that show a path.
    pub fn path_of(&self, at: &Location) -> Result<Vec<u8>> {
        self.walk().path_of(at)
    }

    /// `openat`. `perm` is the mode of a new file.
    pub fn open(&self, start: &Location, path: &[u8], flags: u32, perm: u32) -> Result<Arc<File>> {
        if flags & o::O_TMPFILE == o::O_TMPFILE {
            return Err(Errno::EOPNOTSUPP);
        }
        let follow = flags & o::O_NOFOLLOW == 0;
        let at = if flags & o::O_CREAT != 0 {
            let parent = self.parent(start, path)?;
            if parent.trailing_slash {
                return Err(Errno::EISDIR);
            }
            match self.child(&parent) {
                Ok(_) if flags & o::O_EXCL != 0 => return Err(Errno::EEXIST),
                Ok(at) if follow && is_type(at.inode(), FileType::Symlink) => {
                    self.resolve(&parent.dir, &parent.name, true)?
                }
                Ok(at) => at,
                Err(e) if e == Errno::ENOENT && !parent.is_dot() => {
                    let perm = perm & mode::PERM_MASK & !self.umask;
                    let inode =
                        parent.dir.inode().create(&parent.name, FileType::Regular, perm, 0)?;
                    let dentry = parent.dir.dentry.add_child(&parent.name, inode);
                    Location { mount: parent.dir.mount.clone(), dentry }
                }
                Err(e) => return Err(e),
            }
        } else {
            self.resolve(start, path, follow)?
        };
        self.open_at(at, flags)
    }

    /// Opens the inode at `at`, after the walk.
    pub fn open_at(&self, at: Location, flags: u32) -> Result<Arc<File>> {
        let meta = at.inode().metadata();
        let kind = meta.file_type().ok_or(Errno::EIO)?;
        if flags & o::O_PATH != 0 {
            let flags = flags & (o::O_PATH | o::O_DIRECTORY | o::O_NOFOLLOW | o::O_CLOEXEC);
            if flags & o::O_DIRECTORY != 0 && kind != FileType::Directory {
                return Err(Errno::ENOTDIR);
            }
            return Ok(File::open_inode(at, flags));
        }
        if kind == FileType::Symlink {
            return Err(Errno::ELOOP);
        }
        if flags & o::O_DIRECTORY != 0 && kind != FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        let write = matches!(flags & o::O_ACCMODE, o::O_WRONLY | o::O_RDWR);
        match kind {
            FileType::Directory if write || flags & o::O_CREAT != 0 => Err(Errno::EISDIR),
            FileType::Regular | FileType::Directory => {
                if kind == FileType::Regular && write && flags & o::O_TRUNC != 0 {
                    at.inode().set_attr(&SetAttr { size: Some(0), ..SetAttr::default() })?;
                }
                Ok(File::open_inode(at, flags))
            }
            FileType::CharDevice => {
                let ops = device::open_char(meta.rdev, flags)?;
                Ok(File::with_ops(ops, Some(at), flags))
            }
            FileType::BlockDevice => {
                let ops = crate::blockdev::open_block(meta.rdev, flags)?;
                Ok(File::with_ops(ops, Some(at), flags))
            }
            FileType::Fifo => {
                let ops = crate::pipe::open_fifo(meta.dev, meta.ino, flags)?;
                Ok(File::with_ops(ops, Some(at), flags))
            }
            FileType::Socket => Err(Errno::ENXIO),
            FileType::Symlink => Err(Errno::ELOOP),
        }
    }

    /// The location of the last component of a walk. It must exist.
    fn child(&self, parent: &Parent) -> Result<Location> {
        match &parent.name[..] {
            b"." => Ok(parent.dir.clone()),
            b".." => Ok(self.walk().up(&parent.dir)),
            _ => self.resolve(&parent.dir, &parent.name, false),
        }
    }

    /// Tells if the last component of a walk exists. A dangling link exists.
    fn exists(&self, parent: &Parent) -> Result<bool> {
        let r = self.child(parent);
        if absent(&r) { Ok(false) } else { r.map(|_| true) }
    }

    /// Makes a new inode for `mkdirat`, `mknodat` and `symlinkat`.
    fn make(
        &self,
        start: &Location,
        path: &[u8],
        f: impl FnOnce(&InodeRef, &[u8]) -> Result<InodeRef>,
    ) -> Result<Location> {
        let parent = self.parent(start, path)?;
        if parent.is_dot() || self.exists(&parent)? {
            return Err(Errno::EEXIST);
        }
        let inode = f(parent.dir.inode(), &parent.name)?;
        let dentry = parent.dir.dentry.add_child(&parent.name, inode);
        Ok(Location { mount: parent.dir.mount, dentry })
    }

    /// `mkdirat`.
    pub fn mkdir(&self, start: &Location, path: &[u8], perm: u32) -> Result<Location> {
        let perm = perm & 0o1777 & !self.umask;
        self.make(start, path, |dir, name| dir.create(name, FileType::Directory, perm, 0))
    }

    /// `mknodat`. A mode with no file type makes a regular file.
    pub fn mknod(&self, start: &Location, path: &[u8], mode: u32, rdev: u64) -> Result<Location> {
        let kind = if mode & mode::S_IFMT == 0 {
            FileType::Regular
        } else {
            FileType::from_mode(mode).ok_or(Errno::EINVAL)?
        };
        if matches!(kind, FileType::Directory | FileType::Symlink) {
            return Err(Errno::EINVAL);
        }
        let perm = mode & mode::PERM_MASK & !self.umask;
        self.make(start, path, |dir, name| dir.create(name, kind, perm, rdev))
    }

    /// `symlinkat`.
    pub fn symlink(&self, target: &[u8], start: &Location, path: &[u8]) -> Result<Location> {
        if target.is_empty() {
            return Err(Errno::ENOENT);
        }
        self.make(start, path, |dir, name| dir.symlink(name, target))
    }

    /// `linkat`. `old` is the location of the file, after the walk of the old path.
    pub fn link(&self, old: &Location, start: &Location, path: &[u8]) -> Result<()> {
        if old.inode().metadata().is_dir() {
            return Err(Errno::EPERM);
        }
        let parent = self.parent(start, path)?;
        if parent.is_dot() || self.exists(&parent)? {
            return Err(Errno::EEXIST);
        }
        if !Arc::ptr_eq(&parent.dir.mount, &old.mount) {
            return Err(Errno::EXDEV);
        }
        parent.dir.inode().link(&parent.name, old.inode())?;
        parent.dir.dentry.add_child(&parent.name, old.inode().clone());
        Ok(())
    }

    /// `unlinkat`, without and with `AT_REMOVEDIR`.
    pub fn remove(&self, start: &Location, path: &[u8], dir: bool) -> Result<()> {
        let parent = self.parent(start, path)?;
        match &parent.name[..] {
            b"." if dir => return Err(Errno::EINVAL),
            b".." if dir => return Err(Errno::ENOTEMPTY),
            b"." | b".." => return Err(Errno::EISDIR),
            _ => {}
        }
        if parent.trailing_slash && !dir {
            // Linux examines the type for the error: a file with a slash is `ENOTDIR`.
            let at = self.child(&parent)?;
            return Err(if is_type(at.inode(), FileType::Directory) {
                Errno::EISDIR
            } else {
                Errno::ENOTDIR
            });
        }
        let at = self.child(&parent)?;
        let is_dir = is_type(at.inode(), FileType::Directory);
        if dir {
            if !is_dir {
                return Err(Errno::ENOTDIR);
            }
            if at.is_mount_root() || self.ns.mounted_on(&at).is_some() {
                return Err(Errno::EBUSY);
            }
            parent.dir.inode().rmdir(&parent.name)?;
        } else {
            if is_dir {
                return Err(Errno::EISDIR);
            }
            parent.dir.inode().unlink(&parent.name)?;
        }
        parent.dir.dentry.forget_child(&parent.name);
        Ok(())
    }

    /// `renameat2`.
    pub fn rename(
        &self,
        old_start: &Location,
        old_path: &[u8],
        new_start: &Location,
        new_path: &[u8],
        flags: u32,
    ) -> Result<()> {
        use rename_flags::{AT_RENAME_EXCHANGE, AT_RENAME_NOREPLACE, AT_RENAME_WHITEOUT};
        let known = (AT_RENAME_NOREPLACE | AT_RENAME_EXCHANGE | AT_RENAME_WHITEOUT) as u32;
        if flags & !known != 0 {
            return Err(Errno::EINVAL);
        }
        if flags & (AT_RENAME_EXCHANGE | AT_RENAME_WHITEOUT) as u32 != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let old = self.parent(old_start, old_path)?;
        let new = self.parent(new_start, new_path)?;
        if old.is_dot() || new.is_dot() {
            return Err(Errno::EBUSY);
        }
        let from = self.child(&old)?;
        if !Arc::ptr_eq(&old.dir.mount, &new.dir.mount) {
            return Err(Errno::EXDEV);
        }
        let from_dir = is_type(from.inode(), FileType::Directory);
        if (old.trailing_slash || new.trailing_slash) && !from_dir {
            return Err(Errno::ENOTDIR);
        }
        let to = self.child(&new);
        if !absent(&to) {
            let to = to?;
            if flags & AT_RENAME_NOREPLACE as u32 != 0 {
                return Err(Errno::EEXIST);
            }
            if Arc::ptr_eq(from.inode(), to.inode()) {
                return Ok(());
            }
            let to_dir = is_type(to.inode(), FileType::Directory);
            if from_dir && !to_dir {
                return Err(Errno::ENOTDIR);
            }
            if !from_dir && to_dir {
                return Err(Errno::EISDIR);
            }
            if to.is_mount_root() || self.ns.mounted_on(&to).is_some() {
                return Err(Errno::EBUSY);
            }
        }
        if from.is_mount_root() || self.ns.mounted_on(&from).is_some() {
            return Err(Errno::EBUSY);
        }
        if from_dir && new.dir.dentry.is_under(&from.dentry) {
            return Err(Errno::EINVAL);
        }
        old.dir.inode().rename(&old.name, new.dir.inode(), &new.name)?;
        old.dir.dentry.move_child(&old.name, &new.dir.dentry, &new.name);
        Ok(())
    }

    /// `readlinkat`.
    pub fn read_link(&self, start: &Location, path: &[u8]) -> Result<Vec<u8>> {
        let at = self.resolve(start, path, false)?;
        at.inode().read_link()
    }

    /// Mounts the file system with the root `root` on the directory `path`.
    pub fn mount(
        &self,
        root: InodeRef,
        start: &Location,
        path: &[u8],
        source: MountSource,
    ) -> Result<()> {
        let at = self.resolve(start, path, true)?;
        self.ns.mount(root, &at, source).map(drop)
    }
}

fn is_type(inode: &InodeRef, kind: FileType) -> bool {
    inode.metadata().file_type() == Some(kind)
}

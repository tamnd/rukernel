//! The file system context of a process and the operations on names.
//!
//! An `FsContext` is the `fs_struct` of Linux: the name space, the root, the current directory and
//! the umask of a process. Its methods are the VFS part of the system calls on names: `openat`,
//! `mkdirat`, `unlinkat`, `renameat2` and the others. The caller gives the start of a relative
//! path, which is the current directory or the directory of a descriptor.
//!
//! The context holds the credentials of the process, and the operations check the permission bits
//! with them, as `inode_permission` of Linux. A copy of the context of a process holds its
//! credentials at the time of the copy.

use crate::acl;
use crate::cred::{Cred, cap, may};
use crate::dentry::{Location, MountNamespace, MountSource};
use crate::device;
use crate::file::File;
use crate::inode::{
    FileType, InodeRef, Result, SetAttr, check_fixed, check_immutable, iflags, mode,
};
use crate::path::{Parent, Walk};
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::open as o;

/// The flags of `renameat2`.
pub mod rename_flags {
    pub use rk_abi::native::at::{AT_RENAME_EXCHANGE, AT_RENAME_NOREPLACE, AT_RENAME_WHITEOUT};
}

/// The name space, the root, the current directory, the umask and the credentials of a process.
#[derive(Clone)]
pub struct FsContext {
    ns: Arc<MountNamespace>,
    root: Location,
    cwd: Location,
    umask: u32,
    cred: Arc<Cred>,
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
        Self { ns, cwd: root.clone(), root, umask: 0o022, cred: Arc::new(Cred::root()) }
    }

    /// The credentials that the checks use.
    pub fn cred(&self) -> &Arc<Cred> {
        &self.cred
    }

    /// Sets the credentials that the checks use.
    pub fn set_cred(&mut self, cred: Arc<Cred>) {
        self.cred = cred;
    }

    /// Checks the access `mask` (the bits of [`may`]) to the file at `at`.
    ///
    /// # Errors
    ///
    /// Gives `EACCES` if the access is not allowed.
    pub fn permission(&self, at: &Location, mask: u32) -> Result<()> {
        self.cred.inode_permission(&**at.inode(), mask)
    }

    /// Checks that the process can make its current directory or its root at `at`: it must be a
    /// directory that the process can search.
    ///
    /// # Errors
    ///
    /// Gives `ENOTDIR` or `EACCES`.
    pub fn check_dir(&self, at: &Location) -> Result<()> {
        if !at.inode().metadata().is_dir() {
            return Err(Errno::ENOTDIR);
        }
        self.cred.inode_permission(&**at.inode(), may::EXEC)
    }

    /// Checks that the process can add or remove a name in the directory `dir`.
    fn may_change(&self, dir: &Location) -> Result<()> {
        self.permission(dir, may::WRITE | may::EXEC)
    }

    /// Gives the new inode `inode` in the directory `dir` the owner and the group of the
    /// process, as `inode_init_owner` of Linux.
    fn init_owner(&self, dir: &Location, inode: &InodeRef) -> Result<()> {
        let meta = inode.metadata();
        let kind = meta.file_type().ok_or(Errno::EIO)?;
        let perm = meta.mode & 0o7777;
        let (uid, gid, new) = self.cred.new_owner(&dir.inode().metadata(), kind, perm);
        if (uid, gid, new) == (meta.uid, meta.gid, perm) {
            return Ok(());
        }
        let attr = SetAttr {
            uid: (uid != meta.uid).then_some(uid),
            gid: (gid != meta.gid).then_some(gid),
            mode: (new != perm).then_some(new),
            ..SetAttr::default()
        };
        inode.set_attr(&attr)
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
        Walk::new(&self.ns, &self.root, &self.cred)
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
        self.check_dir(&at)?;
        self.cwd = at;
        Ok(())
    }

    /// Puts the context in a copy of its mount name space, for `CLONE_NEWNS`. The root and the
    /// current directory go to the copies of their mounts.
    pub fn unshare_namespace(&mut self) {
        let ns = self.ns.copy(&mut [&mut self.root, &mut self.cwd]);
        self.ns = ns;
    }

    /// `chroot`.
    pub fn chroot(&mut self, start: &Location, path: &[u8]) -> Result<()> {
        let at = self.resolve(start, path, true)?;
        self.check_dir(&at)?;
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
        let mut created = false;
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
                    self.may_change(&parent.dir)?;
                    check_immutable(&**parent.dir.inode())?;
                    let dir = parent.dir.inode();
                    let perm = self.cred.strip_sgid(
                        &dir.metadata(),
                        FileType::Regular,
                        perm & mode::PERM_MASK,
                    );
                    let (perm, acls) = acl::create(&**dir, FileType::Regular, perm, self.umask);
                    let inode = dir.create(&parent.name, FileType::Regular, perm, 0)?;
                    self.init_owner(&parent.dir, &inode)?;
                    if let Some(acls) = acls {
                        acls.apply(&*inode)?;
                    }
                    created = true;
                    let dentry = parent.dir.dentry.add_child(&parent.name, inode);
                    Location { mount: parent.dir.mount.clone(), dentry }
                }
                Err(e) => return Err(e),
            }
        } else {
            self.resolve(start, path, follow)?
        };
        self.open_inode(at, flags, created)
    }

    /// Opens the inode at `at`, after the walk.
    pub fn open_at(&self, at: Location, flags: u32) -> Result<Arc<File>> {
        self.open_inode(at, flags, false)
    }

    /// Opens the inode at `at`. An open that made the file does not check the permission bits,
    /// so that `open` with `O_CREAT` and the mode 0 gives a descriptor that can write.
    fn open_inode(&self, at: Location, flags: u32, created: bool) -> Result<Arc<File>> {
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
        // The checks of the inode flags of `may_open` of Linux.
        if matches!(kind, FileType::Regular | FileType::Directory) {
            let iflags = at.inode().attr_flags().unwrap_or(0);
            if write && iflags & iflags::IMMUTABLE != 0 {
                return Err(Errno::EPERM);
            }
            let trunc = flags & o::O_TRUNC != 0;
            if iflags & iflags::APPEND != 0 && ((write && flags & o::O_APPEND == 0) || trunc) {
                return Err(Errno::EPERM);
            }
        }
        if kind == FileType::Directory && (write || flags & o::O_CREAT != 0) {
            return Err(Errno::EISDIR);
        }
        if !created {
            self.cred.inode_permission(&**at.inode(), open_mask(flags))?;
        }
        if flags & o::O_NOATIME != 0 && !self.cred.owns(&meta) {
            return Err(Errno::EPERM);
        }
        match kind {
            FileType::Regular | FileType::Directory => {
                if kind == FileType::Regular && write && flags & o::O_TRUNC != 0 {
                    at.inode().set_attr(&SetAttr { size: Some(0), ..SetAttr::default() })?;
                    crate::mapped::changed(at.inode(), 0, u64::MAX);
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
                // A pipe that a link of `/proc/PID/fd` gives has no name.
                if let Some(ops) = crate::pipe::open_pipe_inode(&**at.inode(), flags) {
                    return Ok(File::with_ops(ops?, None, flags));
                }
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

    /// Makes a new inode of the type `kind` for `mkdirat`, `mknodat` and `symlinkat`. `f` gets
    /// the directory, the name and the permission bits after the umask or the default ACL of the
    /// directory masks `perm`.
    fn make(
        &self,
        start: &Location,
        path: &[u8],
        kind: FileType,
        perm: u32,
        f: impl FnOnce(&InodeRef, &[u8], u32) -> Result<InodeRef>,
    ) -> Result<Location> {
        let parent = self.parent(start, path)?;
        if parent.is_dot() || self.exists(&parent)? {
            return Err(Errno::EEXIST);
        }
        self.may_change(&parent.dir)?;
        check_immutable(&**parent.dir.inode())?;
        let dir = parent.dir.inode();
        let perm = self.cred.strip_sgid(&dir.metadata(), kind, perm);
        let (perm, acls) = acl::create(&**dir, kind, perm, self.umask);
        let inode = f(parent.dir.inode(), &parent.name, perm)?;
        self.init_owner(&parent.dir, &inode)?;
        if let Some(acls) = acls {
            acls.apply(&*inode)?;
        }
        let dentry = parent.dir.dentry.add_child(&parent.name, inode);
        Ok(Location { mount: parent.dir.mount, dentry })
    }

    /// `mkdirat`.
    pub fn mkdir(&self, start: &Location, path: &[u8], perm: u32) -> Result<Location> {
        self.make(start, path, FileType::Directory, perm & 0o1777, |dir, name, perm| {
            dir.create(name, FileType::Directory, perm, 0)
        })
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
        self.make(start, path, kind, mode & mode::PERM_MASK, |dir, name, perm| {
            if matches!(kind, FileType::CharDevice | FileType::BlockDevice)
                && !self.cred.capable(cap::MKNOD)
            {
                return Err(Errno::EPERM);
            }
            dir.create(name, kind, perm, rdev)
        })
    }

    /// `symlinkat`.
    pub fn symlink(&self, target: &[u8], start: &Location, path: &[u8]) -> Result<Location> {
        if target.is_empty() {
            return Err(Errno::ENOENT);
        }
        self.make(start, path, FileType::Symlink, 0o777, |dir, name, _| dir.symlink(name, target))
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
        self.may_change(&parent.dir)?;
        check_immutable(&**parent.dir.inode())?;
        check_fixed(&**old.inode())?;
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
        // The checks of `may_delete` of Linux.
        self.may_change(&parent.dir)?;
        check_fixed(&**parent.dir.inode())?;
        self.cred.check_sticky(&parent.dir.inode().metadata(), &at.inode().metadata())?;
        check_fixed(&**at.inode())?;
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
        let exchange = flags & AT_RENAME_EXCHANGE as u32 != 0;
        if exchange && flags & (AT_RENAME_NOREPLACE | AT_RENAME_WHITEOUT) as u32 != 0 {
            return Err(Errno::EINVAL);
        }
        if flags & AT_RENAME_WHITEOUT as u32 != 0 {
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
        if exchange {
            return self.exchange(&old, &new, &from);
        }
        if (old.trailing_slash || new.trailing_slash) && !from_dir {
            return Err(Errno::ENOTDIR);
        }
        let to = self.child(&new);
        let to = if absent(&to) { None } else { Some(to?) };
        if let Some(to) = &to {
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
            if to.is_mount_root() || self.ns.mounted_on(to).is_some() {
                return Err(Errno::EBUSY);
            }
        }
        if from.is_mount_root() || self.ns.mounted_on(&from).is_some() {
            return Err(Errno::EBUSY);
        }
        if from_dir && new.dir.dentry.is_under(&from.dentry) {
            return Err(Errno::EINVAL);
        }
        // The checks of `may_delete` and `may_create` of Linux. A directory that moves to a new
        // parent must be writable, because its `..` changes.
        self.may_change(&old.dir)?;
        check_fixed(&**old.dir.inode())?;
        self.cred.check_sticky(&old.dir.inode().metadata(), &from.inode().metadata())?;
        check_fixed(&**from.inode())?;
        self.may_change(&new.dir)?;
        check_immutable(&**new.dir.inode())?;
        if let Some(to) = &to {
            check_fixed(&**new.dir.inode())?;
            self.cred.check_sticky(&new.dir.inode().metadata(), &to.inode().metadata())?;
            check_fixed(&**to.inode())?;
        }
        if from_dir && !Arc::ptr_eq(old.dir.inode(), new.dir.inode()) {
            self.permission(&from, may::WRITE)?;
        }
        old.dir.inode().rename(&old.name, new.dir.inode(), &new.name)?;
        old.dir.dentry.move_child(&old.name, &new.dir.dentry, &new.name);
        Ok(())
    }

    /// The part of `renameat2` for `RENAME_EXCHANGE`, which exchanges `from`, the child of `old`,
    /// and the child of `new`. The caller examined the flags and the mounts of the parents.
    fn exchange(&self, old: &Parent, new: &Parent, from: &Location) -> Result<()> {
        let to = self.child(new)?;
        let from_dir = is_type(from.inode(), FileType::Directory);
        let to_dir = is_type(to.inode(), FileType::Directory);
        if (old.trailing_slash && !from_dir) || (new.trailing_slash && !to_dir) {
            return Err(Errno::ENOTDIR);
        }
        if Arc::ptr_eq(from.inode(), to.inode()) {
            return Ok(());
        }
        for at in [from, &to] {
            if at.is_mount_root() || self.ns.mounted_on(at).is_some() {
                return Err(Errno::EBUSY);
            }
        }
        if from_dir && new.dir.dentry.is_under(&from.dentry) {
            return Err(Errno::EINVAL);
        }
        if to_dir && old.dir.dentry.is_under(&to.dentry) {
            return Err(Errno::EINVAL);
        }
        // Each name is deleted from its directory and made in the other, as `may_delete` and
        // `may_create` of Linux examine for an exchange.
        for (dir, child) in [(&old.dir, from), (&new.dir, &to)] {
            self.may_change(dir)?;
            check_fixed(&**dir.inode())?;
            self.cred.check_sticky(&dir.inode().metadata(), &child.inode().metadata())?;
            check_fixed(&**child.inode())?;
        }
        if !Arc::ptr_eq(old.dir.inode(), new.dir.inode()) {
            if from_dir {
                self.permission(from, may::WRITE)?;
            }
            if to_dir {
                self.permission(&to, may::WRITE)?;
            }
        }
        old.dir.inode().exchange(&old.name, new.dir.inode(), &new.name)?;
        old.dir.dentry.exchange_child(&old.name, &new.dir.dentry, &new.name);
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

/// The access that an open with `flags` needs, as `ACC_MODE` of Linux. `O_TRUNC` needs write.
fn open_mask(flags: u32) -> u32 {
    let mask = match flags & o::O_ACCMODE {
        o::O_RDONLY => may::READ,
        o::O_WRONLY => may::WRITE,
        _ => may::READ | may::WRITE,
    };
    if flags & o::O_TRUNC != 0 { mask | may::WRITE } else { mask }
}

fn is_type(inode: &InodeRef, kind: FileType) -> bool {
    inode.metadata().file_type() == Some(kind)
}

//! tmpfs: a file system in memory.
//!
//! Each inode keeps its data in kernel memory, and the data goes away with the last reference to
//! the inode. The kernel unpacks the initramfs into a tmpfs and uses it as the root file system in
//! R1, per spec/22-milestones.md. Linux has the same design in mm/shmem.c.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::inode::mode;
use rk_vfs::xattr::Xattrs;
use rk_vfs::{DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, Timespec, now};

/// The largest file, as `MAX_LFS_FILESIZE` of Linux on a 64 bit CPU.
const MAX_FILE_SIZE: u64 = i64::MAX as u64;

/// The block size that `stat` gives.
const BLOCK_SIZE: u32 = 4096;

/// One tmpfs.
struct Fs {
    dev: u64,
    next_ino: AtomicU64,
}

/// The attributes of a node.
struct Attrs {
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u64,
    atime: Timespec,
    mtime: Timespec,
    ctime: Timespec,
}

enum Data {
    File(Vec<u8>),
    Dir { entries: BTreeMap<Vec<u8>, Arc<Node>>, parent: Weak<Node> },
    Symlink(Vec<u8>),
    Special,
}

/// An inode of tmpfs.
struct Node {
    fs: Arc<Fs>,
    ino: u64,
    this: Weak<Node>,
    attrs: SpinLock<Attrs>,
    data: SpinLock<Data>,
    xattrs: SpinLock<Xattrs>,
}

/// The magic number of tmpfs, `TMPFS_MAGIC` of `<linux/magic.h>`.
pub const TMPFS_MAGIC: u64 = 0x0102_1994;

/// The file system type for `mount -t tmpfs`.
pub const FS_TYPE: rk_vfs::fstype::FsType =
    rk_vfs::fstype::FsType { name: "tmpfs", nodev: true, make: mount };

/// Makes a new tmpfs for `mount(2)`. The option `mode=` gives the permission bits of the root in
/// octal. The default is 1777, as Linux gives.
pub fn mount(args: &rk_vfs::fstype::MountArgs<'_>) -> Result<InodeRef> {
    let perm = match rk_vfs::fstype::option(args.data, b"mode") {
        Some(v) => parse_octal(v).ok_or(Errno::EINVAL)?,
        None => 0o1777,
    };
    Ok(new(perm))
}

/// The file system type for `mount -t devtmpfs`.
pub const DEVTMPFS: rk_vfs::fstype::FsType =
    rk_vfs::fstype::FsType { name: "devtmpfs", nodev: true, make: mount_devtmpfs };

/// Gives the root of devtmpfs for `mount(2)`. devtmpfs is one tmpfs that each mount shows, as in
/// Linux. Each mount makes the device files of the new devices in the list of devices, so a
/// device file that a user removed comes back at the next mount. The options have no effect.
fn mount_devtmpfs(_args: &rk_vfs::fstype::MountArgs<'_>) -> Result<InodeRef> {
    static ROOT: rk_frame::sync::Once<InodeRef> = rk_frame::sync::Once::new();
    let root = ROOT.call_once(|| new(0o755)).clone();
    for d in rk_vfs::device::devices() {
        let kind = if d.block { FileType::BlockDevice } else { FileType::CharDevice };
        match root.create(d.name.as_bytes(), kind, d.perm, d.rdev) {
            Ok(_) | Err(Errno::EEXIST) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(root)
}

fn parse_octal(v: &[u8]) -> Option<u32> {
    if v.is_empty() || v.len() > 6 {
        return None;
    }
    v.iter().try_fold(0u32, |n, &b| (b'0'..=b'7').contains(&b).then(|| n * 8 + u32::from(b - b'0')))
}

/// Makes a new tmpfs and gives its root directory, with the permission bits `perm`.
pub fn new(perm: u32) -> InodeRef {
    let fs = Arc::new(Fs { dev: rk_vfs::anon_dev(), next_ino: AtomicU64::new(1) });
    let root = Node::new(&fs, mode::S_IFDIR | (perm & mode::PERM_MASK), 0, Weak::new());
    root.attrs.lock().nlink = 2;
    root
}

impl Node {
    fn new(fs: &Arc<Fs>, mode: u32, rdev: u64, parent: Weak<Node>) -> Arc<Node> {
        let t = now();
        let data = match FileType::from_mode(mode) {
            Some(FileType::Regular) => Data::File(Vec::new()),
            Some(FileType::Directory) => Data::Dir { entries: BTreeMap::new(), parent },
            Some(FileType::Symlink) => Data::Symlink(Vec::new()),
            _ => Data::Special,
        };
        let nlink = if matches!(data, Data::Dir { .. }) { 2 } else { 1 };
        Arc::new_cyclic(|this| Node {
            fs: fs.clone(),
            ino: fs.next_ino.fetch_add(1, Ordering::Relaxed),
            this: this.clone(),
            attrs: SpinLock::new(Attrs {
                mode,
                nlink,
                uid: 0,
                gid: 0,
                rdev,
                atime: t,
                mtime: t,
                ctime: t,
            }),
            data: SpinLock::new(data),
            xattrs: SpinLock::new(Xattrs::new()),
        })
    }

    fn is_dir(&self) -> bool {
        self.attrs.lock().mode & mode::S_IFMT == mode::S_IFDIR
    }

    fn touch(&self) {
        let t = now();
        let mut a = self.attrs.lock();
        a.mtime = t;
        a.ctime = t;
    }

    fn add_links(&self, n: i32) {
        let mut a = self.attrs.lock();
        a.nlink = a.nlink.saturating_add_signed(n);
        a.ctime = now();
    }

    /// Gives the node of `inode` if it is a node of this file system.
    fn same_fs(&self, inode: &InodeRef) -> Result<Arc<Node>> {
        let any: &dyn Any = &**inode;
        let node = any.downcast_ref::<Node>().ok_or(Errno::EXDEV)?;
        if !Arc::ptr_eq(&node.fs, &self.fs) {
            return Err(Errno::EXDEV);
        }
        node.this.upgrade().ok_or(Errno::ENOENT)
    }

    /// Adds `child` as `name`. The caller knows that `name` is not in the directory.
    fn insert(&self, name: &[u8], child: Arc<Node>) -> Result<()> {
        let child_is_dir = child.is_dir();
        match &mut *self.data.lock() {
            Data::Dir { entries, .. } => {
                if entries.contains_key(name) {
                    return Err(Errno::EEXIST);
                }
                entries.insert(name.to_vec(), child);
            }
            _ => return Err(Errno::ENOTDIR),
        }
        if child_is_dir {
            self.add_links(1);
        }
        self.touch();
        Ok(())
    }

    fn get(&self, name: &[u8]) -> Result<Arc<Node>> {
        match &*self.data.lock() {
            Data::Dir { entries, .. } => entries.get(name).cloned().ok_or(Errno::ENOENT),
            _ => Err(Errno::ENOTDIR),
        }
    }

    fn take(&self, name: &[u8]) -> Result<Arc<Node>> {
        match &mut *self.data.lock() {
            Data::Dir { entries, .. } => entries.remove(name).ok_or(Errno::ENOENT),
            _ => Err(Errno::ENOTDIR),
        }
    }

    fn is_empty_dir(&self) -> bool {
        matches!(&*self.data.lock(), Data::Dir { entries, .. } if entries.is_empty())
    }

    fn set_parent(&self, parent: &Arc<Node>) {
        if let Data::Dir { parent: p, .. } = &mut *self.data.lock() {
            *p = Arc::downgrade(parent);
        }
    }
}

impl Inode for Node {
    fn metadata(&self) -> Metadata {
        let size = match &*self.data.lock() {
            Data::File(d) | Data::Symlink(d) => d.len() as u64,
            Data::Dir { .. } => u64::from(BLOCK_SIZE),
            Data::Special => 0,
        };
        let a = self.attrs.lock();
        Metadata {
            dev: self.fs.dev,
            ino: self.ino,
            mode: a.mode,
            nlink: a.nlink,
            uid: a.uid,
            gid: a.gid,
            rdev: a.rdev,
            size,
            blksize: BLOCK_SIZE,
            blocks: size.div_ceil(512),
            atime: a.atime,
            mtime: a.mtime,
            ctime: a.ctime,
        }
    }

    fn set_attr(&self, attr: &SetAttr) -> Result<()> {
        if let Some(size) = attr.size {
            if size > MAX_FILE_SIZE {
                return Err(Errno::EFBIG);
            }
            match &mut *self.data.lock() {
                Data::File(d) => d.resize(usize::try_from(size).map_err(|_| Errno::EFBIG)?, 0),
                Data::Dir { .. } => return Err(Errno::EISDIR),
                _ => return Err(Errno::EINVAL),
            }
            self.touch();
        }
        let mut a = self.attrs.lock();
        if let Some(perm) = attr.mode {
            a.mode = (a.mode & mode::S_IFMT) | (perm & mode::PERM_MASK);
        }
        if let Some(uid) = attr.uid {
            a.uid = uid;
        }
        if let Some(gid) = attr.gid {
            a.gid = gid;
        }
        if let Some(t) = attr.atime {
            a.atime = t;
        }
        if let Some(t) = attr.mtime {
            a.mtime = t;
        }
        a.ctime = now();
        Ok(())
    }

    fn set_atime(&self, time: Timespec) -> Result<()> {
        self.attrs.lock().atime = time;
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        match &*self.data.lock() {
            Data::File(d) => {
                let start = usize::try_from(offset).unwrap_or(usize::MAX).min(d.len());
                let n = buf.len().min(d.len() - start);
                buf[..n].copy_from_slice(&d[start..start + n]);
                Ok(n)
            }
            Data::Dir { .. } => Err(Errno::EISDIR),
            _ => Err(Errno::EINVAL),
        }
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        let end = offset.checked_add(buf.len() as u64).ok_or(Errno::EFBIG)?;
        if end > MAX_FILE_SIZE {
            return Err(Errno::EFBIG);
        }
        let start = usize::try_from(offset).map_err(|_| Errno::EFBIG)?;
        let end = usize::try_from(end).map_err(|_| Errno::EFBIG)?;
        match &mut *self.data.lock() {
            Data::File(d) => {
                if d.len() < end {
                    d.try_reserve(end - d.len()).map_err(|_| Errno::ENOSPC)?;
                    d.resize(end, 0);
                }
                d[start..end].copy_from_slice(buf);
            }
            Data::Dir { .. } => return Err(Errno::EISDIR),
            _ => return Err(Errno::EINVAL),
        }
        self.touch();
        Ok(buf.len())
    }

    fn lookup(&self, name: &[u8]) -> Result<InodeRef> {
        Ok(self.get(name)?)
    }

    fn create(&self, name: &[u8], kind: FileType, perm: u32, rdev: u64) -> Result<InodeRef> {
        if kind == FileType::Symlink {
            return Err(Errno::EINVAL);
        }
        let parent = if kind == FileType::Directory { self.this.clone() } else { Weak::new() };
        let mode = kind.mode_bits() | (perm & mode::PERM_MASK);
        let child = Node::new(&self.fs, mode, rdev, parent);
        self.insert(name, child.clone())?;
        Ok(child)
    }

    fn symlink(&self, name: &[u8], target: &[u8]) -> Result<InodeRef> {
        let child = Node::new(&self.fs, mode::S_IFLNK | 0o777, 0, Weak::new());
        *child.data.lock() = Data::Symlink(target.to_vec());
        self.insert(name, child.clone())?;
        Ok(child)
    }

    fn link(&self, name: &[u8], inode: &InodeRef) -> Result<()> {
        let node = self.same_fs(inode)?;
        if node.is_dir() {
            return Err(Errno::EPERM);
        }
        self.insert(name, node.clone())?;
        node.add_links(1);
        Ok(())
    }

    fn unlink(&self, name: &[u8]) -> Result<()> {
        let node = self.get(name)?;
        if node.is_dir() {
            return Err(Errno::EISDIR);
        }
        self.take(name)?;
        node.add_links(-1);
        self.touch();
        Ok(())
    }

    fn rmdir(&self, name: &[u8]) -> Result<()> {
        let node = self.get(name)?;
        if !node.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        if !node.is_empty_dir() {
            return Err(Errno::ENOTEMPTY);
        }
        self.take(name)?;
        node.add_links(-2);
        self.add_links(-1);
        self.touch();
        Ok(())
    }

    fn rename(&self, old: &[u8], new_dir: &InodeRef, new: &[u8]) -> Result<()> {
        let target_dir = self.same_fs(new_dir)?;
        let node = self.get(old)?;
        let moving_dir = node.is_dir();
        if let Ok(replaced) = target_dir.get(new) {
            if replaced.is_dir() {
                if !replaced.is_empty_dir() {
                    return Err(Errno::ENOTEMPTY);
                }
                target_dir.take(new)?;
                replaced.add_links(-2);
                target_dir.add_links(-1);
            } else {
                target_dir.take(new)?;
                replaced.add_links(-1);
            }
        }
        self.take(old)?;
        if moving_dir {
            self.add_links(-1);
            node.set_parent(&target_dir);
        }
        self.touch();
        target_dir.insert(new, node.clone())?;
        node.attrs.lock().ctime = now();
        Ok(())
    }

    fn read_link(&self) -> Result<Vec<u8>> {
        match &*self.data.lock() {
            Data::Symlink(target) => Ok(target.clone()),
            _ => Err(Errno::EINVAL),
        }
    }

    fn read_dir(&self, pos: u64) -> Result<Option<(DirEntry, u64)>> {
        let data = self.data.lock();
        let Data::Dir { entries, parent } = &*data else { return Err(Errno::ENOTDIR) };
        let entry = match pos {
            0 => DirEntry { ino: self.ino, kind: FileType::Directory, name: b".".to_vec() },
            1 => {
                let ino = parent.upgrade().map_or(self.ino, |p| p.ino);
                DirEntry { ino, kind: FileType::Directory, name: b"..".to_vec() }
            }
            _ => {
                let index = usize::try_from(pos - 2).unwrap_or(usize::MAX);
                let Some((name, node)) = entries.iter().nth(index) else { return Ok(None) };
                let kind = FileType::from_mode(node.attrs.lock().mode).unwrap_or(FileType::Regular);
                DirEntry { ino: node.ino, kind, name: name.clone() }
            }
        };
        Ok(Some((entry, pos + 1)))
    }

    fn fs_id(&self) -> u64 {
        self.fs.dev
    }

    fn get_xattr(&self, name: &[u8]) -> Result<Vec<u8>> {
        self.xattrs.lock().get(name)
    }

    fn set_xattr(&self, name: &[u8], value: &[u8], flags: u32) -> Result<()> {
        self.xattrs.lock().set(name, value, flags)?;
        self.attrs.lock().ctime = now();
        Ok(())
    }

    fn list_xattr(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.xattrs.lock().names())
    }

    fn remove_xattr(&self, name: &[u8]) -> Result<()> {
        self.xattrs.lock().remove(name)?;
        self.attrs.lock().ctime = now();
        Ok(())
    }

    fn fs_magic(&self) -> u64 {
        TMPFS_MAGIC
    }
}

#[cfg(test)]
mod tests;

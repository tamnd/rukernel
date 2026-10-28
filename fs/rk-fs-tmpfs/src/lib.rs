//! tmpfs: a file system in memory.
//!
//! Each inode keeps its data in kernel memory, and the data goes away with the last reference to
//! the inode. The kernel unpacks the initramfs into a tmpfs and uses it as the root file system in
//! R1, per spec/22-milestones.md. Linux has the same design in mm/shmem.c.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod pages;

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::fcntl::{
    F_SEAL_EXEC, F_SEAL_FUTURE_WRITE, F_SEAL_GROW, F_SEAL_SEAL, F_SEAL_SHRINK, F_SEAL_WRITE,
};
use rk_frame::sync::SpinLock;
use rk_vfs::inode::{fileid, mode};
use rk_vfs::xattr::Xattrs;
use rk_vfs::{DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, Timespec, now};

use pages::{PAGE, Pages, Space};

/// The largest file, as `MAX_LFS_FILESIZE` of Linux on a 64 bit CPU.
const MAX_FILE_SIZE: u64 = i64::MAX as u64;

/// The block size that `stat` gives.
const BLOCK_SIZE: u32 = 4096;

/// One tmpfs.
struct Fs {
    dev: u64,
    next_ino: AtomicU64,
    /// The nodes in use, by inode number, for `open_by_handle_at`. A node leaves the map when
    /// it goes away.
    nodes: SpinLock<BTreeMap<u64, Weak<Node>>>,
    /// The file system is read only, after a mount with `MS_RDONLY` or a read only remount. A
    /// change gives `EROFS`.
    read_only: AtomicBool,
    /// The pages of the regular files, and the limit of the option `size=`.
    space: Space,
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
    /// The time when the node was made.
    btime: Timespec,
    /// The inode flags of `FS_IOC_SETFLAGS`.
    flags: u32,
}

enum Data {
    File(Pages),
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
    /// The seals of `fcntl(F_ADD_SEALS)`. A new node has `F_SEAL_SEAL`, so only `memfd_create`
    /// with `MFD_ALLOW_SEALING` gives a file that can take seals, as `shmem_get_inode` of Linux.
    seals: AtomicU32,
}

/// The seals that stop a change of the data.
const SEALS_WRITE: u32 = (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) as u32;

/// The magic number of tmpfs, `TMPFS_MAGIC` of `<linux/magic.h>`.
pub const TMPFS_MAGIC: u64 = 0x0102_1994;

/// The file system type for `mount -t tmpfs`.
pub const FS_TYPE: rk_vfs::fstype::FsType =
    rk_vfs::fstype::FsType { name: "tmpfs", nodev: true, make: mount };

/// Makes a new tmpfs for `mount(2)`. The option `mode=` gives the permission bits of the root in
/// octal. The default is 1777, as Linux gives. The option `size=` gives the largest size of the
/// data, in bytes with an optional suffix `k`, `m` or `g`, and `nr_blocks=` gives it in pages. A
/// write past it gives `ENOSPC`. A size in percent of the memory has no limit. A mount with
/// `MS_RDONLY` makes an empty file system that is read only, as Linux.
pub fn mount(args: &rk_vfs::fstype::MountArgs<'_>) -> Result<InodeRef> {
    let perm = match rk_vfs::fstype::option(args.data, b"mode") {
        Some(v) => parse_octal(v).ok_or(Errno::EINVAL)?,
        None => 0o1777,
    };
    let max = match (
        rk_vfs::fstype::option(args.data, b"size"),
        rk_vfs::fstype::option(args.data, b"nr_blocks"),
    ) {
        (Some(v), _) if v.ends_with(b"%") => u64::MAX,
        (Some(v), _) => parse_size(v).ok_or(Errno::EINVAL)?.div_ceil(PAGE),
        (None, Some(v)) => parse_size(v).ok_or(Errno::EINVAL)?,
        (None, None) => u64::MAX,
    };
    let root = make(perm, max);
    root.set_read_only(args.read_only)?;
    Ok(root)
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
        // A name with a directory, as `net/tun`, gets its directories first.
        let (dir, name) = match d.name.rsplit_once('/') {
            Some((dirs, name)) => (make_dirs(&root, dirs)?, name),
            None => (root.clone(), d.name.as_str()),
        };
        // A read only remount of devtmpfs stops the new device files.
        match dir.create(name.as_bytes(), kind, d.perm, d.rdev) {
            Ok(_) | Err(Errno::EEXIST | Errno::EROFS) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(root)
}

/// Makes the directories `path` below `root` if they are not there, and gives the last one.
fn make_dirs(root: &InodeRef, path: &str) -> Result<InodeRef> {
    let mut dir = root.clone();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        dir = match dir.create(part.as_bytes(), FileType::Directory, 0o755, 0) {
            Ok(d) => d,
            Err(Errno::EEXIST | Errno::EROFS) => dir.lookup(part.as_bytes())?,
            Err(e) => return Err(e),
        };
    }
    Ok(dir)
}

/// Parses a number with an optional suffix `k`, `m`, `g`, `t`, `p` or `e`, as `memparse` of
/// Linux.
fn parse_size(v: &[u8]) -> Option<u64> {
    let digits = v.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let n = v[..digits]
        .iter()
        .try_fold(0u64, |n, &b| n.checked_mul(10)?.checked_add(u64::from(b - b'0')))?;
    let shift = match &v[digits..] {
        b"" => 0,
        b"k" | b"K" => 10,
        b"m" | b"M" => 20,
        b"g" | b"G" => 30,
        b"t" | b"T" => 40,
        b"p" | b"P" => 50,
        b"e" | b"E" => 60,
        _ => return None,
    };
    n.checked_mul(1 << shift)
}

fn parse_octal(v: &[u8]) -> Option<u32> {
    if v.is_empty() || v.len() > 6 {
        return None;
    }
    v.iter().try_fold(0u32, |n, &b| (b'0'..=b'7').contains(&b).then(|| n * 8 + u32::from(b - b'0')))
}

/// Makes a new tmpfs and gives its root directory, with the permission bits `perm`.
pub fn new(perm: u32) -> InodeRef {
    make(perm, u64::MAX)
}

/// Makes a new tmpfs with the permission bits `perm` on the root, and at most `max` pages of data.
fn make(perm: u32, max: u64) -> Arc<Node> {
    let fs = Arc::new(Fs {
        dev: rk_vfs::anon_dev(),
        next_ino: AtomicU64::new(1),
        nodes: SpinLock::new(BTreeMap::new()),
        read_only: AtomicBool::new(false),
        space: Space::new(max),
    });
    let root = Node::new(&fs, mode::S_IFDIR | (perm & mode::PERM_MASK), 0, Weak::new());
    root.attrs.lock().nlink = 2;
    root
}

impl Node {
    fn new(fs: &Arc<Fs>, mode: u32, rdev: u64, parent: Weak<Node>) -> Arc<Node> {
        let t = now();
        let data = match FileType::from_mode(mode) {
            Some(FileType::Regular) => Data::File(Pages::default()),
            Some(FileType::Directory) => Data::Dir { entries: BTreeMap::new(), parent },
            Some(FileType::Symlink) => Data::Symlink(Vec::new()),
            _ => Data::Special,
        };
        let nlink = if matches!(data, Data::Dir { .. }) { 2 } else { 1 };
        let ino = fs.next_ino.fetch_add(1, Ordering::Relaxed);
        let node = Arc::new_cyclic(|this| Node {
            fs: fs.clone(),
            ino,
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
                btime: t,
                flags: 0,
            }),
            data: SpinLock::new(data),
            xattrs: SpinLock::new(Xattrs::new()),
            seals: AtomicU32::new(F_SEAL_SEAL as u32),
        });
        fs.nodes.lock().insert(ino, Arc::downgrade(&node));
        node
    }

    /// Gives `EROFS` if the file system is read only.
    fn check_rw(&self) -> Result<()> {
        if self.fs.read_only.load(Ordering::Acquire) { Err(Errno::EROFS) } else { Ok(()) }
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

    /// Points the existing entry `name` to `child`, without a change of the link counts.
    fn replace(&self, name: &[u8], child: Arc<Node>) -> Result<()> {
        match &mut *self.data.lock() {
            Data::Dir { entries, .. } => {
                *entries.get_mut(name).ok_or(Errno::ENOENT)? = child;
                Ok(())
            }
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

    /// Moves `old` of this directory to `new` of `new_dir`, for `rename`. With `whiteout`, a
    /// whiteout with this owner takes the place of `old`, as `shmem_whiteout` of Linux.
    fn move_entry(
        &self,
        old: &[u8],
        new_dir: &InodeRef,
        new: &[u8],
        whiteout: Option<(u32, u32)>,
    ) -> Result<()> {
        self.check_rw()?;
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
        if let Some((uid, gid)) = whiteout {
            let wh = Node::new(&self.fs, mode::S_IFCHR, 0, Weak::new());
            {
                let mut a = wh.attrs.lock();
                a.uid = uid;
                a.gid = gid;
            }
            self.insert(old, wh)?;
        }
        if moving_dir {
            self.add_links(-1);
            node.set_parent(&target_dir);
        }
        self.touch();
        target_dir.insert(new, node.clone())?;
        node.attrs.lock().ctime = now();
        Ok(())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.fs.nodes.lock().remove(&self.ino);
        if let Data::File(d) = &mut *self.data.lock() {
            d.free(&self.fs.space);
        }
    }
}

impl Inode for Node {
    fn metadata(&self) -> Metadata {
        let (size, blocks) = match &*self.data.lock() {
            Data::File(d) => (d.len(), d.count() * (PAGE / 512)),
            Data::Symlink(d) => (d.len() as u64, (d.len() as u64).div_ceil(512)),
            Data::Dir { .. } => (u64::from(BLOCK_SIZE), u64::from(BLOCK_SIZE) / 512),
            Data::Special => (0, 0),
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
            blocks,
            atime: a.atime,
            mtime: a.mtime,
            ctime: a.ctime,
            btime: Some(a.btime),
        }
    }

    fn set_attr(&self, attr: &SetAttr) -> Result<()> {
        self.check_rw()?;
        // The checks of the seals in `shmem_setattr` of Linux.
        let seals = self.seals.load(Ordering::Acquire);
        if let Some(perm) = attr.mode
            && seals & F_SEAL_EXEC as u32 != 0
            && (self.attrs.lock().mode ^ perm) & 0o111 != 0
        {
            return Err(Errno::EPERM);
        }
        if let Some(size) = attr.size {
            if size > MAX_FILE_SIZE {
                return Err(Errno::EFBIG);
            }
            match &mut *self.data.lock() {
                Data::File(d) => {
                    let old = d.len();
                    if (size < old && seals & F_SEAL_SHRINK as u32 != 0)
                        || (size > old && seals & F_SEAL_GROW as u32 != 0)
                    {
                        return Err(Errno::EPERM);
                    }
                    d.set_len(&self.fs.space, size);
                }
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
        // A read only file system keeps the access times, as `atime_needs_update` of Linux.
        if !self.fs.read_only.load(Ordering::Acquire) {
            self.attrs.lock().atime = time;
        }
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        match &*self.data.lock() {
            Data::File(d) => Ok(d.read(offset, buf)),
            Data::Dir { .. } => Err(Errno::EISDIR),
            _ => Err(Errno::EINVAL),
        }
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        self.check_rw()?;
        let end = offset.checked_add(buf.len() as u64).ok_or(Errno::EFBIG)?;
        if end > MAX_FILE_SIZE {
            return Err(Errno::EFBIG);
        }
        let n = match &mut *self.data.lock() {
            Data::File(d) => {
                // The checks of the seals in `shmem_write_begin` of Linux.
                let seals = self.seals.load(Ordering::Acquire);
                if seals & SEALS_WRITE != 0 || (seals & F_SEAL_GROW as u32 != 0 && end > d.len()) {
                    return Err(Errno::EPERM);
                }
                d.write(&self.fs.space, offset, buf)?
            }
            Data::Dir { .. } => return Err(Errno::EISDIR),
            _ => return Err(Errno::EINVAL),
        };
        self.touch();
        Ok(n)
    }

    fn attr_flags(&self) -> Result<u32> {
        Ok(self.attrs.lock().flags)
    }

    fn statx_attributes_mask(&self) -> u32 {
        // tmpfs has no compressed flag, as `shmem_getattr` of Linux.
        use rk_vfs::inode::iflags::{APPEND, IMMUTABLE, NODUMP};
        APPEND | IMMUTABLE | NODUMP
    }

    fn set_attr_flags(&self, flags: u32) -> Result<()> {
        self.check_rw()?;
        use rk_vfs::inode::iflags::{APPEND, IMMUTABLE, NOATIME, NODUMP};
        // tmpfs keeps only these flags, as `SHMEM_FL_USER_MODIFIABLE` of Linux.
        if flags & !(IMMUTABLE | APPEND | NODUMP | NOATIME) != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let mut attrs = self.attrs.lock();
        attrs.flags = flags;
        attrs.ctime = now();
        Ok(())
    }

    fn fallocate(&self, mode: u32, offset: u64, len: u64) -> Result<()> {
        self.check_rw()?;
        use rk_vfs::inode::falloc::{KEEP_SIZE, PUNCH_HOLE};
        let end = offset.checked_add(len).ok_or(Errno::EFBIG)?;
        if end > MAX_FILE_SIZE {
            return Err(Errno::EFBIG);
        }
        // tmpfs has no other mode, as `shmem_fallocate` of Linux.
        if mode & !(KEEP_SIZE | PUNCH_HOLE) != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let start = offset;
        match &mut *self.data.lock() {
            Data::File(d) => {
                // The checks of the seals in `shmem_fallocate` of Linux.
                let seals = self.seals.load(Ordering::Acquire);
                if mode & PUNCH_HOLE != 0 {
                    if seals & SEALS_WRITE != 0 {
                        return Err(Errno::EPERM);
                    }
                } else if seals & F_SEAL_GROW as u32 != 0 && end > d.len() {
                    return Err(Errno::EPERM);
                }
                if mode & PUNCH_HOLE != 0 {
                    d.clear(&self.fs.space, start, end);
                } else {
                    d.allocate(&self.fs.space, start, end)?;
                    if mode & KEEP_SIZE == 0 && d.len() < end {
                        d.set_len(&self.fs.space, end);
                    }
                }
            }
            Data::Dir { .. } => return Err(Errno::EISDIR),
            _ => return Err(Errno::ENODEV),
        }
        self.touch();
        Ok(())
    }

    fn lookup(&self, name: &[u8]) -> Result<InodeRef> {
        Ok(self.get(name)?)
    }

    fn create(&self, name: &[u8], kind: FileType, perm: u32, rdev: u64) -> Result<InodeRef> {
        self.check_rw()?;
        if kind == FileType::Symlink {
            return Err(Errno::EINVAL);
        }
        let parent = if kind == FileType::Directory { self.this.clone() } else { Weak::new() };
        let mode = kind.mode_bits() | (perm & mode::PERM_MASK);
        let child = Node::new(&self.fs, mode, rdev, parent);
        self.insert(name, child.clone())?;
        Ok(child)
    }

    fn tmpfile(&self, perm: u32) -> Result<InodeRef> {
        self.check_rw()?;
        if !self.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let child = Node::new(&self.fs, mode::S_IFREG | (perm & mode::PERM_MASK), 0, Weak::new());
        child.attrs.lock().nlink = 0;
        Ok(child)
    }

    fn symlink(&self, name: &[u8], target: &[u8]) -> Result<InodeRef> {
        self.check_rw()?;
        let child = Node::new(&self.fs, mode::S_IFLNK | 0o777, 0, Weak::new());
        *child.data.lock() = Data::Symlink(target.to_vec());
        self.insert(name, child.clone())?;
        Ok(child)
    }

    fn link(&self, name: &[u8], inode: &InodeRef) -> Result<()> {
        self.check_rw()?;
        let node = self.same_fs(inode)?;
        if node.is_dir() {
            return Err(Errno::EPERM);
        }
        self.insert(name, node.clone())?;
        node.add_links(1);
        Ok(())
    }

    fn unlink(&self, name: &[u8]) -> Result<()> {
        self.check_rw()?;
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
        self.check_rw()?;
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
        self.move_entry(old, new_dir, new, None)
    }

    fn rename_whiteout(
        &self,
        old: &[u8],
        new_dir: &InodeRef,
        new: &[u8],
        owner: (u32, u32),
    ) -> Result<()> {
        self.move_entry(old, new_dir, new, Some(owner))
    }

    fn exchange(&self, old: &[u8], new_dir: &InodeRef, new: &[u8]) -> Result<()> {
        self.check_rw()?;
        let target_dir = self.same_fs(new_dir)?;
        let this = self.this.upgrade().ok_or(Errno::ENOENT)?;
        let first = self.get(old)?;
        let second = target_dir.get(new)?;
        if Arc::ptr_eq(&first, &second) {
            return Ok(());
        }
        self.replace(old, second.clone())?;
        target_dir.replace(new, first.clone())?;
        if !Arc::ptr_eq(&this, &target_dir) {
            if first.is_dir() {
                first.set_parent(&target_dir);
                target_dir.add_links(1);
                self.add_links(-1);
            }
            if second.is_dir() {
                second.set_parent(&this);
                self.add_links(1);
                target_dir.add_links(-1);
            }
            target_dir.touch();
        }
        self.touch();
        let t = now();
        first.attrs.lock().ctime = t;
        second.attrs.lock().ctime = t;
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

    fn seek_hole_data(&self, at: u64, data: bool) -> Result<u64> {
        match &*self.data.lock() {
            Data::File(d) => d.seek(at, data).ok_or(Errno::ENXIO),
            _ => Err(Errno::EOPNOTSUPP),
        }
    }

    /// The counts of a tmpfs with the option `size=`. Without a limit, the counts are 0, as for a
    /// file system with no blocks.
    fn fs_stat(&self) -> Option<rk_vfs::inode::FsStat> {
        let max = self.fs.space.max();
        (max != u64::MAX).then(|| {
            let free = max.saturating_sub(self.fs.space.used());
            rk_vfs::inode::FsStat {
                bsize: PAGE,
                blocks: max,
                bfree: free,
                bavail: free,
                files: 0,
                ffree: 0,
            }
        })
    }

    fn seals(&self) -> Option<u32> {
        matches!(*self.data.lock(), Data::File(_)).then(|| self.seals.load(Ordering::Acquire))
    }

    fn set_seals(&self, seals: u32) -> Result<()> {
        if !matches!(*self.data.lock(), Data::File(_)) {
            return Err(Errno::EINVAL);
        }
        self.seals.store(seals, Ordering::Release);
        Ok(())
    }

    /// Makes the file system read only or writable again, for a remount, as `shmem_reconfigure`
    /// of Linux. The data stays in memory, so there is nothing to write back.
    fn set_read_only(&self, read_only: bool) -> Result<()> {
        self.fs.read_only.store(read_only, Ordering::Release);
        Ok(())
    }

    fn is_read_only(&self) -> bool {
        self.fs.read_only.load(Ordering::Acquire)
    }

    /// tmpfs has POSIX ACLs, as Linux with `CONFIG_TMPFS_POSIX_ACL`.
    fn posix_acl(&self) -> bool {
        true
    }

    fn get_xattr(&self, name: &[u8]) -> Result<Vec<u8>> {
        self.xattrs.lock().get(name)
    }

    fn set_xattr(&self, name: &[u8], value: &[u8], flags: u32) -> Result<()> {
        self.check_rw()?;
        self.xattrs.lock().set(name, value, flags)?;
        self.attrs.lock().ctime = now();
        Ok(())
    }

    fn list_xattr(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.xattrs.lock().names())
    }

    fn remove_xattr(&self, name: &[u8]) -> Result<()> {
        self.check_rw()?;
        self.xattrs.lock().remove(name)?;
        self.attrs.lock().ctime = now();
        Ok(())
    }

    /// The handle has the generation, which is always 0, and the inode number in two words, as
    /// `shmem_encode_fh` of Linux. An inode number is not used again, so the generation is not
    /// necessary.
    fn file_handle(&self) -> Option<(i32, Vec<u32>)> {
        Some((fileid::INO32_GEN, alloc::vec![0, self.ino as u32, (self.ino >> 32) as u32]))
    }

    /// Finds a node that is in use, as `shmem_fh_to_dentry` of Linux.
    fn inode_by_handle(&self, ty: i32, fid: &[u32]) -> Result<InodeRef> {
        let &[0, low, high, ..] = fid else { return Err(Errno::ESTALE) };
        if ty != fileid::INO32_GEN {
            return Err(Errno::ESTALE);
        }
        let ino = u64::from(high) << 32 | u64::from(low);
        let node = self.fs.nodes.lock().get(&ino).and_then(Weak::upgrade);
        Ok(node.ok_or(Errno::ESTALE)?)
    }

    fn fs_magic(&self) -> u64 {
        TMPFS_MAGIC
    }
}

#[cfg(test)]
mod tests;

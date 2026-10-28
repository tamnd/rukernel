//! hugetlbfs: a file system whose files keep their data in the huge pages of the pool.
//!
//! A mapping of a file of hugetlbfs gets pages of 2 MiB from the pool of `vm.nr_hugepages`, as
//! fs/hugetlbfs/inode.c of Linux. The pages stay with the file until a truncate, a punch of a hole
//! or the end of the file. A file has no `write`: a process writes the data through a mapping.
//! `read`, `ftruncate` to a multiple of 2 MiB and `fallocate` work as on Linux.
//!
//! The kernel also keeps one private hugetlbfs for `memfd_create(MFD_HUGETLB)`, as the
//! `hugetlbfs_vfsmount` of Linux.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
mod host;

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
pub use host::HugeFile;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub use rk_mm::hugetlb::HugeFile;
use rk_mm::hugetlb::{HPAGE_SIZE, Subpool};
use rk_vfs::inode::{FsStat, mode};
use rk_vfs::{DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, Timespec, now};

/// The magic number of hugetlbfs, `HUGETLBFS_MAGIC` of `<linux/magic.h>`.
pub const HUGETLBFS_MAGIC: u64 = 0x9584_58f6;

/// The size of a huge page as a `u64`.
const HPAGE: u64 = HPAGE_SIZE as u64;

/// The largest file, as `MAX_LFS_FILESIZE` of Linux on a 64 bit CPU.
const MAX_FILE_SIZE: u64 = i64::MAX as u64;

/// The block size of a directory, as `stat` gives it.
const DIR_SIZE: u64 = 4096;

/// The options of a mount, as `struct hugetlbfs_fs_context` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// The permission bits of the root.
    pub mode: u32,
    /// The owner of the root.
    pub uid: u32,
    /// The group of the root.
    pub gid: u32,
    /// The most huge pages that the files can have, from `size=`.
    pub max_pages: Option<u64>,
    /// The huge pages that the mount reserves, from `min_size=`.
    pub min_pages: Option<u64>,
    /// The most inodes, from `nr_inodes=`.
    pub max_inodes: Option<u64>,
}

impl Default for Options {
    fn default() -> Self {
        Self { mode: 0o755, uid: 0, gid: 0, max_pages: None, min_pages: None, max_inodes: None }
    }
}

/// Reads a number with an optional suffix `K`, `M`, `G`, `T`, `P` or `E`, as `memparse` of Linux.
fn memparse(v: &[u8]) -> Option<u64> {
    let digits = v.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let n: u64 = core::str::from_utf8(&v[..digits]).ok()?.parse().ok()?;
    let shift = match &v[digits..] {
        [] => 0,
        [b'k' | b'K'] => 10,
        [b'm' | b'M'] => 20,
        [b'g' | b'G'] => 30,
        [b't' | b'T'] => 40,
        [b'p' | b'P'] => 50,
        [b'e' | b'E'] => 60,
        _ => return None,
    };
    n.checked_mul(1 << shift)
}

/// Reads a size of `size=` or `min_size=`: bytes, or a percent of the pool with `%`. Gives the
/// number of huge pages, rounded down as Linux does.
fn parse_size(v: &[u8], pool: u64) -> Option<u64> {
    match v.strip_suffix(b"%") {
        Some(pct) => {
            let pct: u64 = core::str::from_utf8(pct).ok()?.parse().ok()?;
            Some(pool.checked_mul(pct)? / 100)
        }
        None => Some(memparse(v)? / HPAGE),
    }
}

fn parse_u32(v: &[u8]) -> Option<u32> {
    core::str::from_utf8(v).ok()?.parse().ok()
}

fn parse_octal(v: &[u8]) -> Option<u32> {
    if v.is_empty() || v.len() > 6 {
        return None;
    }
    v.iter().try_fold(0u32, |n, &b| (b'0'..=b'7').contains(&b).then(|| n * 8 + u32::from(b - b'0')))
}

/// Reads the options of a mount, as `hugetlbfs_parse_param` of Linux. `pool` is the number of
/// pages of the pool, for a size in percent. A value that is not valid, or a page size that is
/// not 2 MiB, gives `EINVAL`. An unknown option has no effect.
///
/// # Errors
///
/// `EINVAL` for a bad value.
pub fn parse_options(data: &[u8], pool: u64) -> Result<Options> {
    let mut o = Options::default();
    for opt in data.split(|&b| b == b',').filter(|o| !o.is_empty()) {
        let (key, value) = match opt.iter().position(|&b| b == b'=') {
            Some(i) => (&opt[..i], &opt[i + 1..]),
            None => (opt, &b""[..]),
        };
        match key {
            b"mode" => o.mode = parse_octal(value).ok_or(Errno::EINVAL)? & 0o1777,
            b"uid" => o.uid = parse_u32(value).ok_or(Errno::EINVAL)?,
            b"gid" => o.gid = parse_u32(value).ok_or(Errno::EINVAL)?,
            b"size" => o.max_pages = Some(parse_size(value, pool).ok_or(Errno::EINVAL)?),
            b"min_size" => o.min_pages = Some(parse_size(value, pool).ok_or(Errno::EINVAL)?),
            b"nr_inodes" => o.max_inodes = Some(memparse(value).ok_or(Errno::EINVAL)?),
            b"pagesize" if memparse(value) != Some(HPAGE) => return Err(Errno::EINVAL),
            _ => {}
        }
    }
    if let (Some(max), Some(min)) = (o.max_pages, o.min_pages)
        && min > max
    {
        return Err(Errno::EINVAL);
    }
    Ok(o)
}

/// One hugetlbfs.
struct Fs {
    dev: u64,
    next_ino: AtomicU64,
    opts: Options,
    /// The pages of the files, for `size=` and `min_size=`. Each file has it too, so the
    /// reservations of `min_size=` stay until the last file goes.
    subpool: Arc<Subpool>,
    /// The nodes in use, by inode number.
    nodes: SpinLock<BTreeMap<u64, Weak<Node>>>,
    read_only: AtomicBool,
}

struct Attrs {
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u64,
    atime: Timespec,
    mtime: Timespec,
    ctime: Timespec,
    btime: Timespec,
}

enum Data {
    File(Arc<HugeFile>),
    Dir { entries: BTreeMap<Vec<u8>, Arc<Node>>, parent: Weak<Node> },
    Symlink(Vec<u8>),
    Special,
}

/// An inode of hugetlbfs.
struct Node {
    fs: Arc<Fs>,
    ino: u64,
    this: Weak<Node>,
    attrs: SpinLock<Attrs>,
    data: SpinLock<Data>,
}

/// The file system type for `mount -t hugetlbfs`.
pub const FS_TYPE: rk_vfs::fstype::FsType =
    rk_vfs::fstype::FsType { name: "hugetlbfs", nodev: true, make: mount };

/// Makes a new hugetlbfs for `mount(2)`. `min_size=` reserves its pages at once, and the mount
/// fails with `ENOMEM` if the pool does not have them, as on Linux.
///
/// # Errors
///
/// `EINVAL` for a bad option and `ENOMEM` for a reservation that fails.
pub fn mount(args: &rk_vfs::fstype::MountArgs<'_>) -> Result<InodeRef> {
    let pool = rk_mm::hugetlb::counts().total as u64;
    let opts = parse_options(args.data, pool)?;
    let root = new(opts)?;
    root.set_read_only(args.read_only)?;
    Ok(root)
}

/// Makes a new hugetlbfs with the options `opts` and gives its root directory.
///
/// # Errors
///
/// `ENOMEM` if the pool does not have the pages of `min_size=`.
pub fn new(opts: Options) -> Result<InodeRef> {
    Ok(new_with(opts, Subpool::new(opts.max_pages, opts.min_pages)?))
}

/// Makes a new hugetlbfs with the options `opts` and the pages `subpool` of its files.
fn new_with(opts: Options, subpool: Arc<Subpool>) -> InodeRef {
    let fs = Arc::new(Fs {
        dev: rk_vfs::anon_dev(),
        next_ino: AtomicU64::new(1),
        opts,
        subpool,
        nodes: SpinLock::new(BTreeMap::new()),
        read_only: AtomicBool::new(false),
    });
    let root = Node::new(&fs, mode::S_IFDIR | (opts.mode & mode::PERM_MASK), 0, Weak::new());
    {
        let mut a = root.attrs.lock();
        a.uid = opts.uid;
        a.gid = opts.gid;
    }
    root
}

/// Gives the huge pages of `inode` if it is a regular file of hugetlbfs. A mapping of the file
/// uses them.
pub fn huge_file(inode: &InodeRef) -> Option<Arc<HugeFile>> {
    let any: &dyn Any = &**inode;
    any.downcast_ref::<Node>()?.file()
}

/// The private hugetlbfs of the kernel, for `memfd_create(MFD_HUGETLB)`.
pub fn internal() -> InodeRef {
    static ROOT: rk_frame::sync::Once<InodeRef> = rk_frame::sync::Once::new();
    let make = || new_with(Options { mode: 0o1777, ..Options::default() }, Subpool::unlimited());
    ROOT.call_once(make).clone()
}

impl Node {
    fn new(fs: &Arc<Fs>, mode: u32, rdev: u64, parent: Weak<Node>) -> Arc<Node> {
        let t = now();
        let ino = fs.next_ino.fetch_add(1, Ordering::Relaxed);
        let data = match FileType::from_mode(mode) {
            Some(FileType::Regular) => {
                let subpool = Some(fs.subpool.clone());
                Data::File(HugeFile::new_in(fs.dev, ino, Vec::new(), 0, subpool))
            }
            Some(FileType::Directory) => Data::Dir { entries: BTreeMap::new(), parent },
            Some(FileType::Symlink) => Data::Symlink(Vec::new()),
            _ => Data::Special,
        };
        let nlink = if matches!(data, Data::Dir { .. }) { 2 } else { 1 };
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
            }),
            data: SpinLock::new(data),
        });
        fs.nodes.lock().insert(ino, Arc::downgrade(&node));
        node
    }

    /// Gives `ENOSPC` if the file system has `nr_inodes` inodes.
    fn check_inodes(&self) -> Result<()> {
        let count = self.fs.nodes.lock().len() as u64;
        match self.fs.opts.max_inodes {
            Some(max) if count >= max => Err(Errno::ENOSPC),
            _ => Ok(()),
        }
    }

    fn check_rw(&self) -> Result<()> {
        if self.fs.read_only.load(Ordering::Acquire) { Err(Errno::EROFS) } else { Ok(()) }
    }

    fn file(&self) -> Option<Arc<HugeFile>> {
        match &*self.data.lock() {
            Data::File(f) => Some(f.clone()),
            _ => None,
        }
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

    fn same_fs(&self, inode: &InodeRef) -> Result<Arc<Node>> {
        let any: &dyn Any = &**inode;
        let node = any.downcast_ref::<Node>().ok_or(Errno::EXDEV)?;
        if !Arc::ptr_eq(&node.fs, &self.fs) {
            return Err(Errno::EXDEV);
        }
        node.this.upgrade().ok_or(Errno::ENOENT)
    }

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

    /// Makes a new node in this directory, with the owner of the caller.
    fn make(&self, mode: u32, rdev: u64) -> Result<Arc<Node>> {
        self.check_rw()?;
        self.check_inodes()?;
        let parent =
            if mode & mode::S_IFMT == mode::S_IFDIR { self.this.clone() } else { Weak::new() };
        Ok(Node::new(&self.fs, mode, rdev, parent))
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.fs.nodes.lock().remove(&self.ino);
    }
}

impl Inode for Node {
    fn metadata(&self) -> Metadata {
        let (size, pages) = match &*self.data.lock() {
            Data::File(f) => (f.size(), f.page_count() as u64),
            Data::Symlink(d) => (d.len() as u64, 0),
            Data::Dir { .. } => (DIR_SIZE, 0),
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
            blksize: HPAGE_SIZE as u32,
            blocks: pages * (HPAGE / 512),
            atime: a.atime,
            mtime: a.mtime,
            ctime: a.ctime,
            btime: Some(a.btime),
        }
    }

    /// A new size must be a multiple of 2 MiB, as `hugetlbfs_setattr` of Linux. A smaller size
    /// frees the pages after the end.
    fn set_attr(&self, attr: &SetAttr) -> Result<()> {
        self.check_rw()?;
        if let Some(size) = attr.size {
            if size > MAX_FILE_SIZE {
                return Err(Errno::EFBIG);
            }
            match &*self.data.lock() {
                Data::File(f) => {
                    if size % HPAGE != 0 {
                        return Err(Errno::EINVAL);
                    }
                    f.set_size(size);
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
        if !self.fs.read_only.load(Ordering::Acquire) {
            self.attrs.lock().atime = time;
        }
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        match &*self.data.lock() {
            Data::File(f) => Ok(f.read(offset, buf)),
            Data::Dir { .. } => Err(Errno::EISDIR),
            _ => Err(Errno::EINVAL),
        }
    }

    /// A file of hugetlbfs has no `write`, as on Linux.
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> Result<usize> {
        match &*self.data.lock() {
            Data::Dir { .. } => Err(Errno::EISDIR),
            _ => Err(Errno::EINVAL),
        }
    }

    /// Gives pages to a range, or frees them with `FALLOC_FL_PUNCH_HOLE`, as
    /// `hugetlbfs_fallocate` of Linux. A hole frees the whole huge pages in the range, and the
    /// parts of huge pages at its ends become zeros.
    fn fallocate(&self, mode: u32, offset: u64, len: u64) -> Result<()> {
        self.check_rw()?;
        use rk_vfs::inode::falloc::{KEEP_SIZE, PUNCH_HOLE};
        if mode & !(KEEP_SIZE | PUNCH_HOLE) != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let end = offset.checked_add(len).ok_or(Errno::EFBIG)?;
        if end > MAX_FILE_SIZE {
            return Err(Errno::EFBIG);
        }
        let file = match &*self.data.lock() {
            Data::File(f) => f.clone(),
            Data::Dir { .. } => return Err(Errno::EISDIR),
            _ => return Err(Errno::ENODEV),
        };
        if mode & PUNCH_HOLE != 0 {
            let first = offset.next_multiple_of(HPAGE);
            let last = end / HPAGE * HPAGE;
            if first < last {
                file.zero(offset, first - offset);
                file.zero(last, end - last);
                file.punch(first / HPAGE, last / HPAGE);
            } else {
                file.zero(offset, len);
            }
        } else {
            // `size=` of the mount limits the new pages, and the pages before the first one that
            // it does not allow stay, as on Linux.
            file.allocate(offset / HPAGE, end.div_ceil(HPAGE))?;
            if mode & KEEP_SIZE == 0 && file.size() < end {
                file.grow_to(end);
            }
        }
        self.touch();
        Ok(())
    }

    fn lookup(&self, name: &[u8]) -> Result<InodeRef> {
        Ok(self.get(name)?)
    }

    fn create(&self, name: &[u8], kind: FileType, perm: u32, rdev: u64) -> Result<InodeRef> {
        if kind == FileType::Symlink {
            return Err(Errno::EINVAL);
        }
        let child = self.make(kind.mode_bits() | (perm & mode::PERM_MASK), rdev)?;
        self.insert(name, child.clone())?;
        Ok(child)
    }

    fn tmpfile(&self, perm: u32) -> Result<InodeRef> {
        if !self.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let child = self.make(mode::S_IFREG | (perm & mode::PERM_MASK), 0)?;
        child.attrs.lock().nlink = 0;
        Ok(child)
    }

    fn symlink(&self, name: &[u8], target: &[u8]) -> Result<InodeRef> {
        let child = self.make(mode::S_IFLNK | 0o777, 0)?;
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

    fn set_read_only(&self, read_only: bool) -> Result<()> {
        self.fs.read_only.store(read_only, Ordering::Release);
        Ok(())
    }

    fn is_read_only(&self) -> bool {
        self.fs.read_only.load(Ordering::Acquire)
    }

    /// The counts of `hugetlbfs_statfs` of Linux: the blocks are huge pages, and a mount without
    /// `size=` gives 0 blocks, and a mount without `nr_inodes=` gives -1 inodes. The used blocks
    /// are the pages and the reservations of the files.
    fn fs_stat(&self) -> Option<FsStat> {
        let mut st = FsStat { bsize: HPAGE, ..FsStat::default() };
        if let Some(max) = self.fs.opts.max_pages {
            st.blocks = max;
            st.bfree = max.saturating_sub(self.fs.subpool.counts().used);
            st.bavail = st.bfree;
        }
        match self.fs.opts.max_inodes {
            Some(max) => {
                st.files = max;
                st.ffree = max.saturating_sub(self.fs.nodes.lock().len() as u64);
            }
            None => (st.files, st.ffree) = (u64::MAX, u64::MAX),
        }
        Some(st)
    }

    fn fs_magic(&self) -> u64 {
        HUGETLBFS_MAGIC
    }
}

#[cfg(test)]
mod tests;

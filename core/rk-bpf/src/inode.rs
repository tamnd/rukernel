//! bpffs, the file system of the pinned BPF objects, kernel/bpf/inode.c of Linux.
//!
//! `BPF_OBJ_PIN` puts a map, a program or a link in a file of bpffs, and the object stays after
//! the last file descriptor closes. `BPF_OBJ_GET` gives a new file descriptor for the object of a
//! file. An `unlink` of the file drops the reference of the pin. bpffs also has directories and
//! symbolic links. A name with a dot is not valid, and an `open` of a pinned object gives `EIO`,
//! as in Linux.

use crate::link::BpfLink;
use crate::map::BpfMap;
use crate::prog::BpfProg;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::file::FileOps;
use rk_vfs::inode::{FsStat, mode};
use rk_vfs::{DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, Timespec, now};

/// The magic number of bpffs, `BPF_FS_MAGIC` of `<linux/magic.h>`.
pub const BPF_FS_MAGIC: u64 = 0xcafe_4a11;

/// The default mode of the root, `S_IRWXUGO | S_ISVTX` as in `bpf_init_fs_context` of Linux.
const DEFAULT_MODE: u32 = 0o1777;

/// An object that a file of bpffs pins, `enum bpf_type` of Linux.
#[derive(Clone)]
pub enum BpfObj {
    /// A program, `BPF_TYPE_PROG`.
    Prog(Arc<BpfProg>),
    /// A map, `BPF_TYPE_MAP`.
    Map(Arc<BpfMap>),
    /// A link, `BPF_TYPE_LINK`.
    Link(Arc<BpfLink>),
}

/// The options of a mount, `struct bpf_mount_opts` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// The permission bits of the root.
    pub mode: u32,
    /// The owner of the root.
    pub uid: u32,
    /// The group of the root.
    pub gid: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self { mode: DEFAULT_MODE, uid: 0, gid: 0 }
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

/// Reads the options of a mount, as `bpf_parse_param` of Linux. A bad value gives `EINVAL`. An
/// unknown option has no effect, because bpffs always ignored them.
///
/// # Errors
///
/// `EINVAL` for a bad value.
pub fn parse_options(data: &[u8]) -> Result<Options> {
    let mut o = Options::default();
    for opt in data.split(|&b| b == b',').filter(|o| !o.is_empty()) {
        let (key, value) = match opt.iter().position(|&b| b == b'=') {
            Some(i) => (&opt[..i], &opt[i + 1..]),
            None => (opt, &b""[..]),
        };
        match key {
            b"mode" => o.mode = parse_octal(value).ok_or(Errno::EINVAL)? & 0o7777,
            b"uid" => o.uid = parse_u32(value).ok_or(Errno::EINVAL)?,
            b"gid" => o.gid = parse_u32(value).ok_or(Errno::EINVAL)?,
            _ => {}
        }
    }
    Ok(o)
}

/// One bpffs.
struct Fs {
    dev: u64,
    next_ino: AtomicU64,
    opts: Options,
    read_only: AtomicBool,
}

struct Attrs {
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    atime: Timespec,
    mtime: Timespec,
    ctime: Timespec,
}

enum Data {
    Dir { entries: BTreeMap<Vec<u8>, Arc<Node>>, parent: Weak<Node> },
    Symlink(Vec<u8>),
    Obj(BpfObj),
}

/// An inode of bpffs.
struct Node {
    fs: Arc<Fs>,
    ino: u64,
    this: Weak<Node>,
    attrs: SpinLock<Attrs>,
    data: SpinLock<Data>,
}

impl Drop for Node {
    /// The inode is freed, `bpf_free_inode` of Linux.
    fn drop(&mut self) {
        if let Data::Obj(BpfObj::Map(map)) = &*self.data.lock() {
            map.put_uref();
        }
    }
}

/// The file system type for `mount -t bpf`.
pub const FS_TYPE: rk_vfs::fstype::FsType =
    rk_vfs::fstype::FsType { name: "bpf", nodev: true, make: mount };

/// Makes a new bpffs for `mount(2)`, as `bpf_fill_super` of Linux.
///
/// # Errors
///
/// `EINVAL` for a bad option.
pub fn mount(args: &rk_vfs::fstype::MountArgs<'_>) -> Result<InodeRef> {
    let root = new(parse_options(args.data)?);
    root.set_read_only(args.read_only)?;
    Ok(root)
}

/// Makes a new bpffs with the options `opts` and gives its root directory.
pub fn new(opts: Options) -> InodeRef {
    let fs = Arc::new(Fs {
        dev: rk_vfs::anon_dev(),
        next_ino: AtomicU64::new(1),
        opts,
        read_only: AtomicBool::new(false),
    });
    let root = Node::new(
        &fs,
        mode::S_IFDIR | (opts.mode & 0o7777),
        Data::Dir { entries: BTreeMap::new(), parent: Weak::new() },
    );
    {
        let mut a = root.attrs.lock();
        a.uid = opts.uid;
        a.gid = opts.gid;
    }
    root
}

fn node_of(inode: &InodeRef) -> Option<&Node> {
    let any: &dyn Any = &**inode;
    any.downcast_ref::<Node>()
}

/// Makes the file `name` in the directory `dir` that pins `obj`, as `bpf_mkobj_ops` of Linux.
/// `perm` has the permission bits after the umask. A directory that is not on bpffs gives
/// `EPERM`, as `bpf_obj_do_pin` of Linux.
///
/// # Errors
///
/// `EPERM` for a directory that is not on bpffs, and the errors of a new name.
pub fn bpf_mkobj(dir: &InodeRef, name: &[u8], perm: u32, obj: BpfObj) -> Result<InodeRef> {
    let dir = node_of(dir).ok_or(Errno::EPERM)?;
    dir.check_rw()?;
    check_name(name)?;
    if let BpfObj::Map(map) = &obj {
        // A pin counts in `usercnt` until the inode is freed, as `bpf_any_get` of Linux.
        map.inc_uref();
    }
    let child = Node::new(&dir.fs, mode::S_IFREG | (perm & mode::PERM_MASK), Data::Obj(obj));
    dir.insert(name, child.clone())?;
    Ok(child)
}

/// Gives the object that the file `inode` pins, as `bpf_inode_type` of Linux. A file that does
/// not pin an object gives `EACCES`.
///
/// # Errors
///
/// `EACCES` for an inode that is not a pinned object.
pub fn bpf_obj_of(inode: &InodeRef) -> Result<BpfObj> {
    match &*node_of(inode).ok_or(Errno::EACCES)?.data.lock() {
        Data::Obj(obj) => Ok(obj.clone()),
        _ => Err(Errno::EACCES),
    }
}

/// Tells if `inode` is on bpffs.
pub fn is_bpffs(inode: &InodeRef) -> bool {
    node_of(inode).is_some()
}

/// A name with a dot gives `EPERM`, as `bpf_lookup` of Linux. The dots are for the names of
/// the kernel, as the files of a BPF iterator.
fn check_name(name: &[u8]) -> Result<()> {
    if name.contains(&b'.') { Err(Errno::EPERM) } else { Ok(()) }
}

impl Node {
    fn new(fs: &Arc<Fs>, mode: u32, data: Data) -> Arc<Node> {
        let t = now();
        let ino = fs.next_ino.fetch_add(1, Ordering::Relaxed);
        let nlink = if matches!(data, Data::Dir { .. }) { 2 } else { 1 };
        Arc::new_cyclic(|this| Node {
            fs: fs.clone(),
            ino,
            this: this.clone(),
            attrs: SpinLock::new(Attrs {
                mode,
                nlink,
                uid: 0,
                gid: 0,
                atime: t,
                mtime: t,
                ctime: t,
            }),
            data: SpinLock::new(data),
        })
    }

    fn check_rw(&self) -> Result<()> {
        if self.fs.read_only.load(Ordering::Acquire) { Err(Errno::EROFS) } else { Ok(()) }
    }

    fn is_dir(&self) -> bool {
        matches!(&*self.data.lock(), Data::Dir { .. })
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
        let node = node_of(inode).ok_or(Errno::EXDEV)?;
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
}

impl Inode for Node {
    fn metadata(&self) -> Metadata {
        let size = match &*self.data.lock() {
            Data::Symlink(d) => d.len() as u64,
            _ => 0,
        };
        let a = self.attrs.lock();
        Metadata {
            dev: self.fs.dev,
            ino: self.ino,
            mode: a.mode,
            nlink: a.nlink,
            uid: a.uid,
            gid: a.gid,
            rdev: 0,
            size,
            blksize: 4096,
            blocks: 0,
            atime: a.atime,
            mtime: a.mtime,
            ctime: a.ctime,
            btime: None,
        }
    }

    fn set_attr(&self, attr: &SetAttr) -> Result<()> {
        self.check_rw()?;
        if attr.size.is_some() {
            return Err(if self.is_dir() { Errno::EISDIR } else { Errno::EINVAL });
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

    fn lookup(&self, name: &[u8]) -> Result<InodeRef> {
        check_name(name)?;
        Ok(self.get(name)?)
    }

    /// bpffs makes only directories with `mkdir`, as `bpf_mkdir` of Linux. It has no `mknod`
    /// and no `create`.
    fn create(&self, name: &[u8], kind: FileType, perm: u32, _rdev: u64) -> Result<InodeRef> {
        if kind != FileType::Directory {
            return Err(Errno::EPERM);
        }
        self.check_rw()?;
        check_name(name)?;
        let child = Node::new(
            &self.fs,
            mode::S_IFDIR | (perm & mode::PERM_MASK),
            Data::Dir { entries: BTreeMap::new(), parent: self.this.clone() },
        );
        self.insert(name, child.clone())?;
        Ok(child)
    }

    fn symlink(&self, name: &[u8], target: &[u8]) -> Result<InodeRef> {
        self.check_rw()?;
        check_name(name)?;
        let child = Node::new(&self.fs, mode::S_IFLNK | 0o777, Data::Symlink(target.to_vec()));
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
        check_name(new)?;
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

    /// An `open` of a pinned object gives `EIO`, as `bpffs_obj_open` of Linux.
    fn open_file(&self, _flags: u32) -> Option<Result<Arc<dyn FileOps>>> {
        match &*self.data.lock() {
            Data::Obj(_) => Some(Err(Errno::EIO)),
            _ => None,
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

    /// The counts of `simple_statfs` of Linux: no blocks and no inodes.
    fn fs_stat(&self) -> Option<FsStat> {
        Some(FsStat { bsize: 4096, ..FsStat::default() })
    }

    fn fs_magic(&self) -> u64 {
        BPF_FS_MAGIC
    }

    /// The options of `bpf_show_options` of Linux: the values that are not the default.
    fn fs_options(&self) -> Vec<u8> {
        let o = self.fs.opts;
        let mut s = Vec::new();
        if o.uid != 0 {
            s.extend_from_slice(format!(",uid={}", o.uid).as_bytes());
        }
        if o.gid != 0 {
            s.extend_from_slice(format!(",gid={}", o.gid).as_bytes());
        }
        if o.mode != DEFAULT_MODE {
            s.extend_from_slice(format!(",mode={:o}", o.mode).as_bytes());
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::map::{MapAttr, map_alloc};
    use crate::uapi::map_type::BPF_MAP_TYPE_ARRAY;

    fn array_map() -> Arc<BpfMap> {
        let attr = MapAttr {
            map_type: BPF_MAP_TYPE_ARRAY,
            key_size: 4,
            value_size: 8,
            max_entries: 1,
            ..MapAttr::default()
        };
        let ops = map_alloc(&attr, 1, u64::MAX).unwrap();
        Arc::new(BpfMap::new(&attr, [0; 16], 1, ops))
    }

    #[test]
    fn the_root_has_the_default_mode_and_the_magic() {
        let root = new(Options::default());
        assert_eq!(root.metadata().mode, mode::S_IFDIR | 0o1777);
        assert_eq!(root.fs_magic(), BPF_FS_MAGIC);
        assert!(root.fs_options().is_empty());
        let root = new(parse_options(b"mode=700,uid=5,gid=6").unwrap());
        assert_eq!(root.metadata().mode, mode::S_IFDIR | 0o700);
        assert_eq!((root.metadata().uid, root.metadata().gid), (5, 6));
        assert_eq!(root.fs_options(), b",uid=5,gid=6,mode=700");
        assert_eq!(parse_options(b"mode=9").err(), Some(Errno::EINVAL));
    }

    #[test]
    fn a_pin_keeps_the_map_until_unlink() {
        let root = new(Options::default());
        let map = array_map();
        let file = bpf_mkobj(&root, b"m", 0o600, BpfObj::Map(map.clone())).unwrap();
        assert_eq!(file.metadata().mode, mode::S_IFREG | 0o600);
        let found = root.lookup(b"m").unwrap();
        assert!(matches!(bpf_obj_of(&found), Ok(BpfObj::Map(m)) if Arc::ptr_eq(&m, &map)));
        assert!(matches!(found.open_file(0), Some(Err(Errno::EIO))));
        assert_eq!(
            bpf_mkobj(&root, b"m", 0o600, BpfObj::Map(map.clone())).err(),
            Some(Errno::EEXIST)
        );
        root.unlink(b"m").unwrap();
        assert_eq!(root.lookup(b"m").err(), Some(Errno::ENOENT));
        drop((file, found));
        assert_eq!(Arc::strong_count(&map), 1);
    }

    #[test]
    fn directories_and_names_follow_linux() {
        let root = new(Options::default());
        let dir = root.create(b"d", FileType::Directory, 0o755, 0).unwrap();
        assert_eq!(bpf_obj_of(&dir).err(), Some(Errno::EACCES));
        assert_eq!(root.create(b"f", FileType::Regular, 0o644, 0).err(), Some(Errno::EPERM));
        assert_eq!(root.lookup(b"a.b").err(), Some(Errno::EPERM));
        assert_eq!(
            bpf_mkobj(&dir, b"a.b", 0o600, BpfObj::Map(array_map())).err(),
            Some(Errno::EPERM)
        );
        bpf_mkobj(&dir, b"m", 0o600, BpfObj::Map(array_map())).unwrap();
        assert_eq!(root.rmdir(b"d").err(), Some(Errno::ENOTEMPTY));
        root.rename(b"d", &root, b"e").unwrap();
        assert!(bpf_obj_of(&root.lookup(b"e").unwrap().lookup(b"m").unwrap()).is_ok());
        root.symlink(b"l", b"e/m").unwrap();
        assert_eq!(root.lookup(b"l").unwrap().read_link().unwrap(), b"e/m");
    }
}

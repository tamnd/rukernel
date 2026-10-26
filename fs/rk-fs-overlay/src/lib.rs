//! overlayfs: a file system that joins directories of other file systems.
//!
//! A mount has one or more lower directories, which it does not change, and an upper directory,
//! which takes all the changes. A name in the upper directory hides the same name in the lower
//! directories, and the entries of two directories with the same name are joined. The first
//! change of a file of a lower directory copies the file to the upper directory. A removal of a
//! name that a lower directory has makes a whiteout, a character device 0:0, in the upper
//! directory. A directory with the extended attribute `trusted.overlay.opaque` set to `y` hides
//! the lower directories. Linux has the same design in fs/overlayfs.
//!
//! A mount without an upper directory does not accept changes. A rename of a directory that is
//! in a lower directory gives `EXDEV`, as Linux without the `redirect_dir` feature, and `mv`
//! then copies the directory.
//!
//! The extended attributes of overlayfs have the prefix `trusted.overlay.`, or `user.overlay.`
//! with the option `userxattr`. A user cannot see them through the mount. A user attribute with
//! the prefix gets `overlay.` after the prefix in the layer, as the escapes of Linux, so an
//! overlay can be a lower layer of another overlay.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, Ordering};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::fstype::{FsType, MountArgs};
use rk_vfs::inode::{FsStat, check_immutable, iflags, mode};
use rk_vfs::{DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, Timespec, acl};

/// The magic number of overlayfs, `OVERLAYFS_SUPER_MAGIC` of `<linux/magic.h>`.
pub const OVERLAYFS_SUPER_MAGIC: u64 = 0x794c_7630;

/// The file system type for `mount -t overlay`.
pub const FS_TYPE: FsType = FsType { name: "overlay", nodev: true, make: mount };

/// The prefix of the extended attributes of overlayfs.
const TRUSTED: &[u8] = b"trusted.overlay.";
/// The prefix of the extended attributes of overlayfs with the option `userxattr`.
const USER: &[u8] = b"user.overlay.";
/// The part after the prefix of an attribute of a user that has the prefix of overlayfs.
const ESCAPE: &[u8] = b"overlay.";
/// The attribute that makes a directory opaque with the value `y`. The value `x` tells that the
/// directory can have whiteouts that are regular files with [`WHITEOUT`].
const OPAQUE: &[u8] = b"opaque";
/// The attribute that makes a regular file of size 0 a whiteout.
const WHITEOUT: &[u8] = b"whiteout";
/// The attribute that keeps the immutable and append-only flags of an upper file, as the
/// letters `i` and `a`. The upper inode does not get these flags, so the mount can still change
/// it.
const PROTATTR: &[u8] = b"protattr";
/// The inode flags that the attribute [`PROTATTR`] keeps.
const PROT_FLAGS: u32 = iflags::IMMUTABLE | iflags::APPEND;
/// The inode flags that a copy up gives to the upper inode.
const COPY_FLAGS: u32 = iflags::SYNC | iflags::NOATIME;
/// The name of the directory that overlayfs makes in the work directory.
const WORK: &[u8] = b"work";
/// The bytes that a copy up moves in one step.
const CHUNK: usize = 64 * 1024;

/// One mount of overlayfs.
struct Fs {
    /// The device of the mount, for the directories.
    dev: u64,
    /// Tells if the mount accepts changes. A mount without an upper directory does not, and a
    /// mount that cannot make its work directory does not, as Linux.
    writable: bool,
    /// Tells if the mount is read only now: it does not accept changes, or a remount made it
    /// read only.
    read_only: AtomicBool,
    /// The prefix of the extended attributes of overlayfs: [`TRUSTED`] or [`USER`].
    prefix: &'static [u8],
    /// The options of the mount for `/proc/PID/mountinfo`.
    options: Vec<u8>,
}

impl Fs {
    /// Gives the extended attribute `name` of overlayfs, with the prefix of the mount.
    fn xattr(&self, name: &[u8]) -> Vec<u8> {
        [self.prefix, name].concat()
    }

    /// Tells if `name` is an attribute of overlayfs, which a user cannot see through the mount,
    /// as `ovl_is_private_xattr` of Linux.
    fn is_private(&self, name: &[u8]) -> bool {
        name.strip_prefix(self.prefix).is_some_and(|rest| !rest.starts_with(ESCAPE))
    }

    /// Gives the name in the layer of the attribute `name` of a user: the name with `overlay.`
    /// after the prefix of overlayfs, or the same name.
    fn escape(&self, name: &[u8]) -> Vec<u8> {
        match name.strip_prefix(self.prefix) {
            Some(rest) => [self.prefix, ESCAPE, rest].concat(),
            None => name.to_vec(),
        }
    }

    /// Gives the name that a user sees for the attribute `name` of a layer, or `None` for an
    /// attribute of overlayfs.
    fn unescape(&self, name: &[u8]) -> Option<Vec<u8>> {
        let Some(rest) = name.strip_prefix(self.prefix) else { return Some(name.to_vec()) };
        let rest = rest.strip_prefix(ESCAPE)?;
        Some([self.prefix, rest].concat())
    }

    /// Tells if the directory `inode` hides the lower directories.
    fn is_opaque(&self, inode: &InodeRef) -> bool {
        inode.get_xattr(&self.xattr(OPAQUE)).is_ok_and(|v| v == b"y")
    }

    /// Tells if the directory `dir` can have whiteouts that are regular files.
    fn has_xwhiteouts(&self, dir: &InodeRef) -> bool {
        dir.get_xattr(&self.xattr(OPAQUE)).is_ok_and(|v| v == b"x")
    }

    /// Tells if `inode` in the directory `dir` is a whiteout: a character device 0:0, or a
    /// regular file of size 0 with the attribute [`WHITEOUT`] in a directory that can have such
    /// whiteouts, as `ovl_path_is_whiteout` of Linux.
    fn is_whiteout_in(&self, dir: &InodeRef, inode: &InodeRef) -> bool {
        if is_whiteout(inode) {
            return true;
        }
        let m = inode.metadata();
        m.file_type() == Some(FileType::Regular)
            && m.size == 0
            && inode.get_xattr(&self.xattr(WHITEOUT)).is_ok()
            && self.has_xwhiteouts(dir)
    }

    /// Tells if the entry `entry` of the directory `dir` is a whiteout.
    fn entry_is_whiteout(&self, dir: &InodeRef, entry: &DirEntry) -> bool {
        let maybe = match entry.kind {
            FileType::CharDevice => true,
            FileType::Regular => self.has_xwhiteouts(dir),
            _ => false,
        };
        maybe && dir.lookup(&entry.name).is_ok_and(|i| self.is_whiteout_in(dir, &i))
    }

    /// Gives the flags of [`PROT_FLAGS`] that the upper inode `upper` keeps in [`PROTATTR`].
    fn prot_flags(&self, upper: &InodeRef) -> u32 {
        let value = upper.get_xattr(&self.xattr(PROTATTR)).unwrap_or_default();
        value.iter().fold(0, |flags, &b| match b {
            b'a' => flags | iflags::APPEND,
            b'i' => flags | iflags::IMMUTABLE,
            _ => flags,
        })
    }

    /// Keeps the flags of [`PROT_FLAGS`] in `flags` in the attribute [`PROTATTR`] of the upper
    /// inode `upper`, as `ovl_set_protattr` of Linux. No flag removes the attribute.
    fn set_prot_flags(&self, upper: &InodeRef, flags: u32) -> Result<()> {
        let mut value = Vec::new();
        if flags & iflags::APPEND != 0 {
            value.push(b'a');
        }
        if flags & iflags::IMMUTABLE != 0 {
            value.push(b'i');
        }
        let name = self.xattr(PROTATTR);
        if !value.is_empty() {
            return upper.set_xattr(&name, &value, 0);
        }
        match upper.remove_xattr(&name) {
            Ok(()) | Err(Errno::ENODATA) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// The options of a mount.
#[derive(Debug, Default, PartialEq, Eq)]
struct Options {
    /// The lower directories, the top layer first.
    lowers: Vec<Vec<u8>>,
    upper: Option<Vec<u8>>,
    work: Option<Vec<u8>>,
    /// The option `userxattr`: the attributes of overlayfs have the prefix [`USER`].
    userxattr: bool,
}

impl Options {
    /// Reads the data string of `mount(2)`. A comma separates the options and a colon separates
    /// the lower directories. A backslash before a comma or a colon makes it a part of the path,
    /// as `ovl_parse_monolithic` of Linux. Linux ignores other options, such as `index=off`,
    /// when it does not have the feature, and so does this file system.
    fn parse(data: &[u8]) -> Result<Options> {
        let mut out = Options::default();
        let mut lowerdir = None;
        for opt in split_escaped(data, b',') {
            let (key, value) = match opt.iter().position(|&b| b == b'=') {
                Some(i) => (&opt[..i], Some(&opt[i + 1..])),
                None => (opt, None),
            };
            match (key, value) {
                (b"lowerdir", Some(v)) => lowerdir = Some(v),
                (b"upperdir", Some(v)) => out.upper = Some(unescape(v)),
                (b"workdir", Some(v)) => out.work = Some(unescape(v)),
                (b"userxattr", None) => out.userxattr = true,
                _ => {}
            }
        }
        for path in split_escaped(lowerdir.ok_or(Errno::EINVAL)?, b':') {
            if path.is_empty() {
                return Err(Errno::EINVAL);
            }
            out.lowers.push(unescape(path));
        }
        Ok(out)
    }

    /// Gives the options for `/proc/PID/mountinfo`, as `ovl_show_options` of Linux.
    fn show(&self) -> Vec<u8> {
        let mut out = Vec::from(&b",lowerdir="[..]);
        for (i, path) in self.lowers.iter().enumerate() {
            if i > 0 {
                out.push(b':');
            }
            show_escaped(&mut out, path, b":");
        }
        if let (Some(upper), Some(work)) = (&self.upper, &self.work) {
            out.extend_from_slice(b",upperdir=");
            show_escaped(&mut out, upper, b"");
            out.extend_from_slice(b",workdir=");
            show_escaped(&mut out, work, b"");
        }
        if self.userxattr {
            out.extend_from_slice(b",userxattr");
        }
        out
    }
}

/// Splits `data` at each `sep` that has no backslash before it. The parts keep the backslashes.
fn split_escaped(data: &[u8], sep: u8) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let (mut start, mut i) = (0, 0);
    while i < data.len() {
        if data[i] == b'\\' {
            i += 2;
            continue;
        }
        if data[i] == sep {
            out.push(&data[start..i]);
            start = i + 1;
        }
        i += 1;
    }
    out.push(&data[start..]);
    out
}

/// Removes the backslashes of `s` that make the next byte a part of the path, as
/// `ovl_unescape` of Linux.
fn unescape(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.iter();
    while let Some(&b) = bytes.next() {
        if b == b'\\' {
            match bytes.next() {
                Some(&next) => out.push(next),
                None => break,
            }
        } else {
            out.push(b);
        }
    }
    out
}

/// Writes the path `s` for an option of `/proc/PID/mountinfo`. A byte of `extra`, a comma, an
/// equal sign, a space, a tab, a new line and a backslash become an octal escape, as
/// `seq_show_option` of Linux does.
fn show_escaped(out: &mut Vec<u8>, s: &[u8], extra: &[u8]) {
    for &b in s {
        if b",= \t\n\\".contains(&b) || extra.contains(&b) {
            out.extend_from_slice(alloc::format!("\\{b:03o}").as_bytes());
        } else {
            out.push(b);
        }
    }
}

/// An inode of overlayfs: one name with its inodes in the layers.
struct Node {
    fs: Arc<Fs>,
    this: Weak<Node>,
    /// The directory of the node and the name in it. The root has no parent.
    place: SpinLock<(Option<Arc<Node>>, Vec<u8>)>,
    /// The inode in the upper directory, after a copy up or for a new file.
    upper: SpinLock<Option<InodeRef>>,
    /// The inode that the node had first: the upper inode, or else the top lower inode.
    first: InodeRef,
    /// The inodes in the lower directories that the node shows, the top layer first. A file that
    /// is not a directory has one at most.
    lowers: Vec<InodeRef>,
    /// The nodes that a lookup in this directory gave, so a name keeps one node while it is in
    /// use.
    children: SpinLock<BTreeMap<Vec<u8>, Weak<Node>>>,
    /// The joined entries of the directory, which `read_dir` makes again at position 0.
    entries: SpinLock<Vec<DirEntry>>,
}

/// Makes a new overlayfs for `mount(2)`. The options are `lowerdir=`, with the directories
/// separated by `:` and the top layer first, `upperdir=`, `workdir=` and `userxattr`. The upper
/// directory needs the work directory, as in Linux. The mount makes the directory `work` in the
/// work directory. If it cannot, the mount does not accept changes, as Linux.
pub fn mount(args: &MountArgs<'_>) -> Result<InodeRef> {
    let opts = Options::parse(args.data)?;
    let mut lowers = Vec::new();
    for path in &opts.lowers {
        lowers.push(dir(args, path)?);
    }
    let (upper, writable) = match (&opts.upper, &opts.work) {
        (Some(upper), Some(work)) => {
            let upper = dir(args, upper)?;
            let work = dir(args, work)?;
            // Linux refuses an upper directory on overlayfs, because overlayfs cannot keep
            // its whiteouts and attributes there.
            if upper.fs_id() != work.fs_id() || upper.fs_magic() == OVERLAYFS_SUPER_MAGIC {
                return Err(Errno::EINVAL);
            }
            let writable = make_work(&work).is_ok();
            (Some(upper), writable)
        }
        (None, _) => (None, false),
        (Some(_), None) => return Err(Errno::EINVAL),
    };
    let prefix = if opts.userxattr { USER } else { TRUSTED };
    let read_only = AtomicBool::new(!writable || args.read_only);
    let fs = Fs { dev: rk_vfs::anon_dev(), writable, read_only, prefix, options: opts.show() };
    Node::new(&Arc::new(fs), None, Vec::new(), upper, lowers)
        .ok_or(Errno::EINVAL)
        .map(|n| n as InodeRef)
}

/// Makes the directory `work` in the work directory `work_dir`, with the mode 0 and with no ACL,
/// as `ovl_workdir_create` of Linux. It first removes an old `work`.
fn make_work(work_dir: &InodeRef) -> Result<()> {
    // The VFS checks the flags for a change through a system call. The mount changes the work
    // directory directly, so it checks the flags here.
    check_immutable(&**work_dir)?;
    match work_dir.lookup(WORK) {
        Ok(old) => remove_tree(work_dir, WORK, &old, 0)?,
        Err(Errno::ENOENT) => {}
        Err(e) => return Err(e),
    }
    let work = work_dir.create(WORK, FileType::Directory, 0, 0)?;
    for name in [acl::DEFAULT, acl::ACCESS] {
        match work.remove_xattr(name) {
            Ok(()) | Err(Errno::ENODATA | Errno::EOPNOTSUPP) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Removes `name`, which is `inode`, from `dir`, with its entries. As `ovl_workdir_cleanup` of
/// Linux, it does not go deeper than two levels below `work`, and then gives `EINVAL`.
fn remove_tree(dir: &InodeRef, name: &[u8], inode: &InodeRef, level: u32) -> Result<()> {
    if !inode.metadata().is_dir() {
        return dir.unlink(name);
    }
    if level > 2 {
        return Err(Errno::EINVAL);
    }
    for entry in real_entries(inode)? {
        let child = inode.lookup(&entry.name)?;
        remove_tree(inode, &entry.name, &child, level + 1)?;
    }
    dir.rmdir(name)
}

/// Finds the directory at `path` for an option.
fn dir(args: &MountArgs<'_>, path: &[u8]) -> Result<InodeRef> {
    let inode = args.lookup(path)?;
    if !inode.metadata().is_dir() {
        return Err(Errno::ENOTDIR);
    }
    Ok(inode)
}

/// Makes a new overlayfs of the directories `lowers`, the top layer first, and `upper`, and
/// gives its root. Gives `EINVAL` if there is no directory. The mount does not use a work
/// directory and has no options for `/proc/PID/mountinfo`.
pub fn new(lowers: Vec<InodeRef>, upper: Option<InodeRef>) -> Result<InodeRef> {
    let fs = Arc::new(Fs {
        dev: rk_vfs::anon_dev(),
        writable: upper.is_some(),
        read_only: AtomicBool::new(upper.is_none()),
        prefix: TRUSTED,
        options: Vec::new(),
    });
    Ok(Node::new(&fs, None, Vec::new(), upper, lowers).ok_or(Errno::EINVAL)?)
}

/// Tells if `inode` is a whiteout: a character device with the device number 0:0.
fn is_whiteout(inode: &InodeRef) -> bool {
    let m = inode.metadata();
    m.file_type() == Some(FileType::CharDevice) && m.rdev == 0
}

/// Gives each entry of the directory `inode` but `.` and `..`.
fn real_entries(inode: &InodeRef) -> Result<Vec<DirEntry>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some((entry, next)) = inode.read_dir(pos)? {
        if entry.name != b"." && entry.name != b".." {
            out.push(entry);
        }
        pos = next;
    }
    Ok(out)
}

impl Node {
    fn new(
        fs: &Arc<Fs>,
        parent: Option<Arc<Node>>,
        name: Vec<u8>,
        upper: Option<InodeRef>,
        lowers: Vec<InodeRef>,
    ) -> Option<Arc<Node>> {
        let first = upper.clone().or_else(|| lowers.first().cloned())?;
        Some(Arc::new_cyclic(|this| Node {
            fs: fs.clone(),
            first,
            this: this.clone(),
            place: SpinLock::new((parent, name)),
            upper: SpinLock::new(upper),
            lowers,
            children: SpinLock::new(BTreeMap::new()),
            entries: SpinLock::new(Vec::new()),
        }))
    }

    /// Gives the reference to this node. A node is alive while a caller uses it.
    fn arc(&self) -> Result<Arc<Node>> {
        self.this.upgrade().ok_or(Errno::ENOENT)
    }

    fn upper(&self) -> Option<InodeRef> {
        self.upper.lock().clone()
    }

    /// The inode that gives the data and the attributes: the upper inode, or else the top lower
    /// inode.
    fn real(&self) -> InodeRef {
        self.upper().unwrap_or_else(|| self.first.clone())
    }

    fn is_dir(&self) -> bool {
        self.real().metadata().is_dir()
    }

    /// Gives the node of `inode` if it is a node of this mount.
    fn same_fs(&self, inode: &InodeRef) -> Result<Arc<Node>> {
        let any: &dyn Any = &**inode;
        let node = any.downcast_ref::<Node>().ok_or(Errno::EXDEV)?;
        if !Arc::ptr_eq(&node.fs, &self.fs) {
            return Err(Errno::EXDEV);
        }
        node.arc()
    }

    /// Gives `EROFS` if the mount has no upper directory.
    fn check_writable(&self) -> Result<()> {
        if self.fs.writable { Ok(()) } else { Err(Errno::EROFS) }
    }

    /// Finds `name` in the layers of this directory, and gives a new node for it.
    fn find(&self, name: &[u8]) -> Result<Arc<Node>> {
        let mut upper = None;
        let mut lowers = Vec::new();
        // A directory joins the directories below it until a layer has a file that is not a
        // directory, a whiteout or an opaque directory.
        let mut more = true;
        if let Some(dir) = self.upper() {
            match dir.lookup(name) {
                Ok(i) if self.fs.is_whiteout_in(&dir, &i) => return Err(Errno::ENOENT),
                Ok(i) => {
                    more = i.metadata().is_dir() && !self.fs.is_opaque(&i);
                    upper = Some(i);
                }
                Err(Errno::ENOENT) => {}
                Err(e) => return Err(e),
            }
            more = more && !self.fs.is_opaque(&dir);
        }
        for dir in &self.lowers {
            if !more {
                break;
            }
            match dir.lookup(name) {
                Ok(i) if self.fs.is_whiteout_in(dir, &i) => break,
                Ok(i) => {
                    let is_dir = i.metadata().is_dir();
                    let found = upper.is_some() || !lowers.is_empty();
                    if found && !is_dir {
                        break;
                    }
                    more = is_dir && !self.fs.is_opaque(&i);
                    lowers.push(i);
                }
                Err(Errno::ENOENT) => {}
                Err(e) => return Err(e),
            }
        }
        if upper.is_none() && lowers.is_empty() {
            return Err(Errno::ENOENT);
        }
        Node::new(&self.fs, Some(self.arc()?), name.to_vec(), upper, lowers).ok_or(Errno::ENOENT)
    }

    /// Gives the node of `name`, from the nodes in use if one has the name.
    fn child(&self, name: &[u8]) -> Result<Arc<Node>> {
        if let Some(node) = self.children.lock().get(name).and_then(Weak::upgrade) {
            return Ok(node);
        }
        let node = self.find(name)?;
        let mut children = self.children.lock();
        if let Some(old) = children.get(name).and_then(Weak::upgrade) {
            return Ok(old);
        }
        children.retain(|_, w| w.strong_count() > 0);
        children.insert(name.to_vec(), Arc::downgrade(&node));
        Ok(node)
    }

    /// Forgets the node of `name` after a change of the directory.
    fn forget(&self, name: &[u8]) {
        self.children.lock().remove(name);
    }

    /// Tells if a lower directory of this directory shows `name`. A removal of such a name needs
    /// a whiteout.
    fn lower_has(&self, name: &[u8]) -> bool {
        for dir in &self.lowers {
            match dir.lookup(name) {
                Ok(i) => return !self.fs.is_whiteout_in(dir, &i),
                Err(_) => continue,
            }
        }
        false
    }

    /// Copies the file to the upper directory if it is not there, with its parents, and gives
    /// the upper inode.
    fn copy_up(&self) -> Result<InodeRef> {
        if let Some(upper) = self.upper() {
            return Ok(upper);
        }
        self.check_writable()?;
        let (parent, name) = self.place.lock().clone();
        // The root always has an upper inode on a writable mount.
        let dir = parent.ok_or(Errno::EROFS)?.copy_up()?;
        let lower = self.lowers.first().ok_or(Errno::ENOENT)?;
        let mut slot = self.upper.lock();
        if let Some(upper) = slot.clone() {
            return Ok(upper);
        }
        match dir.lookup(&name) {
            Ok(i) if is_whiteout(&i) => dir.unlink(&name)?,
            Ok(i) => {
                *slot = Some(i.clone());
                return Ok(i);
            }
            Err(Errno::ENOENT) => {}
            Err(e) => return Err(e),
        }
        let m = lower.metadata();
        let perm = m.mode & mode::PERM_MASK;
        let kind = m.file_type().ok_or(Errno::EIO)?;
        let upper = match kind {
            FileType::Symlink => dir.symlink(&name, &lower.read_link()?)?,
            FileType::Regular => {
                let file = dir.create(&name, kind, perm, 0)?;
                copy_data(lower, &file, m.size)?;
                file
            }
            _ => dir.create(&name, kind, perm, m.rdev)?,
        };
        for attr in lower.list_xattr()? {
            if self.fs.is_private(&attr) {
                continue;
            }
            if let Ok(value) = lower.get_xattr(&attr) {
                upper.set_xattr(&attr, &value, 0)?;
            }
        }
        let mode = (kind != FileType::Symlink).then_some(perm);
        upper.set_attr(&SetAttr {
            mode,
            uid: Some(m.uid),
            gid: Some(m.gid),
            size: None,
            atime: Some(m.atime),
            mtime: Some(m.mtime),
            explicit_times: true,
        })?;
        self.copy_flags(lower, &upper)?;
        *slot = Some(upper.clone());
        Ok(upper)
    }

    /// Gives the inode flags of `lower` to the new upper inode `upper`, as `ovl_copy_fileattr` of
    /// Linux. The upper inode gets the flags of [`COPY_FLAGS`]. The attribute [`PROTATTR`] keeps
    /// the flags of [`PROT_FLAGS`].
    fn copy_flags(&self, lower: &InodeRef, upper: &InodeRef) -> Result<()> {
        // A file system without inode flags has nothing to copy.
        let Ok(flags) = lower.attr_flags() else { return Ok(()) };
        if flags & PROT_FLAGS != 0 {
            self.fs.set_prot_flags(upper, flags)?;
        }
        if flags & COPY_FLAGS == 0 {
            return Ok(());
        }
        let real = upper.attr_flags().unwrap_or(0);
        match upper.set_attr_flags((real & !COPY_FLAGS) | (flags & COPY_FLAGS)) {
            Ok(()) | Err(Errno::EOPNOTSUPP | Errno::ENOTTY) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Gives the joined entries of the directory but `.` and `..`, in the order of the names.
    fn joined(&self) -> Result<Vec<DirEntry>> {
        // `None` is a name that a whiteout hides.
        let mut names: BTreeMap<Vec<u8>, Option<DirEntry>> = BTreeMap::new();
        let mut more = true;
        if let Some(dir) = self.upper() {
            for entry in real_entries(&dir)? {
                let hidden = self.fs.entry_is_whiteout(&dir, &entry);
                names.insert(entry.name.clone(), (!hidden).then_some(entry));
            }
            more = !self.fs.is_opaque(&dir);
        }
        if more {
            for dir in &self.lowers {
                for entry in real_entries(dir)? {
                    if names.contains_key(&entry.name) {
                        continue;
                    }
                    let hidden = self.fs.entry_is_whiteout(dir, &entry);
                    names.insert(entry.name.clone(), (!hidden).then_some(entry));
                }
            }
        }
        Ok(names.into_values().flatten().collect())
    }

    /// Removes the whiteouts of the upper directory `dir` before a removal of the directory.
    fn remove_whiteouts(&self, dir: &InodeRef) -> Result<()> {
        for entry in real_entries(dir)? {
            if self.fs.entry_is_whiteout(dir, &entry) {
                dir.unlink(&entry.name)?;
            }
        }
        Ok(())
    }

    /// Prepares the upper directory for a new name: copies the directory up and removes a
    /// whiteout of the name. Gives the upper directory and tells if it removed a whiteout.
    fn prepare_new(&self, name: &[u8]) -> Result<(InodeRef, bool)> {
        self.check_writable()?;
        let dir = self.copy_up()?;
        let whiteout = match dir.lookup(name) {
            Ok(i) if is_whiteout(&i) => {
                dir.unlink(name)?;
                true
            }
            _ => false,
        };
        Ok((dir, whiteout))
    }

    /// Adds a node for the new upper inode `inode` of `name`.
    fn added(&self, name: &[u8], inode: InodeRef) -> Result<InodeRef> {
        let parent = Some(self.arc()?);
        let node = Node::new(&self.fs, parent, name.to_vec(), Some(inode), Vec::new())
            .ok_or(Errno::EIO)?;
        self.children.lock().insert(name.to_vec(), Arc::downgrade(&node));
        Ok(node)
    }

    /// Makes a whiteout of `name` in the upper directory `dir` if a lower directory shows the
    /// name.
    fn white_out(&self, dir: &InodeRef, name: &[u8]) -> Result<()> {
        if self.lower_has(name) {
            dir.create(name, FileType::CharDevice, 0, 0)?;
        }
        Ok(())
    }

    /// Checks that the directory node `node` has no entries in the joined view.
    fn check_empty(node: &Node) -> Result<()> {
        if node.joined()?.is_empty() { Ok(()) } else { Err(Errno::ENOTEMPTY) }
    }
}

/// Copies `size` bytes of the regular file `from` to `to`.
fn copy_data(from: &InodeRef, to: &InodeRef, size: u64) -> Result<()> {
    let mut buf = vec![0u8; CHUNK];
    let mut pos = 0u64;
    while pos < size {
        let n = from.read_at(pos, &mut buf)?;
        if n == 0 {
            break;
        }
        let mut done = 0;
        while done < n {
            done += to.write_at(pos + done as u64, &buf[done..n])?;
        }
        pos += n as u64;
    }
    Ok(())
}

impl Inode for Node {
    fn metadata(&self) -> Metadata {
        let mut m = self.real().metadata();
        // A directory joins layers, so it has the device of the mount. Another file shows the
        // device and the inode number of its layer, as Linux without the `xino` feature.
        // A copy up does not change the device and the inode number, as Linux, so a lock on
        // the file stays the same lock.
        if m.is_dir() {
            m.dev = self.fs.dev;
        } else {
            let first = self.first.metadata();
            m.dev = first.dev;
            m.ino = first.ino;
        }
        m
    }

    fn set_attr(&self, attr: &SetAttr) -> Result<()> {
        self.check_writable()?;
        self.copy_up()?.set_attr(attr)
    }

    fn set_atime(&self, time: Timespec) -> Result<()> {
        // An access does not copy a file up.
        match self.upper() {
            Some(upper) => upper.set_atime(time),
            None => Ok(()),
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.real().read_at(offset, buf)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        self.check_writable()?;
        self.copy_up()?.write_at(offset, buf)
    }

    fn fiemap(&self, start: u64, len: u64) -> Result<Vec<rk_vfs::inode::FiemapExtent>> {
        self.real().fiemap(start, len)
    }

    fn fiemap_xattr(&self) -> Result<Option<rk_vfs::inode::FiemapExtent>> {
        self.real().fiemap_xattr()
    }

    fn attr_flags(&self) -> Result<u32> {
        match self.upper() {
            // The upper inode keeps the immutable and append-only flags in an attribute.
            Some(upper) => {
                let prot = self.fs.prot_flags(&upper);
                Ok(upper.attr_flags().unwrap_or(0) & !PROT_FLAGS | prot)
            }
            None => self.first.attr_flags(),
        }
    }

    fn set_attr_flags(&self, flags: u32) -> Result<()> {
        self.check_writable()?;
        let upper = self.copy_up()?;
        self.fs.set_prot_flags(&upper, flags)?;
        upper.set_attr_flags(flags & !PROT_FLAGS)
    }

    fn fallocate(&self, mode: u32, offset: u64, len: u64) -> Result<()> {
        self.check_writable()?;
        self.copy_up()?.fallocate(mode, offset, len)
    }

    fn sync(&self) -> Result<()> {
        match self.upper() {
            Some(upper) => upper.sync(),
            None => Ok(()),
        }
    }

    fn lookup(&self, name: &[u8]) -> Result<InodeRef> {
        if !self.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        Ok(self.child(name)?)
    }

    fn create(&self, name: &[u8], kind: FileType, perm: u32, rdev: u64) -> Result<InodeRef> {
        let (dir, whiteout) = self.prepare_new(name)?;
        let inode = dir.create(name, kind, perm, rdev)?;
        // A new directory over a removed directory must not show the old entries.
        if kind == FileType::Directory && (whiteout || self.lower_has(name)) {
            inode.set_xattr(&self.fs.xattr(OPAQUE), b"y", 0)?;
        }
        self.added(name, inode)
    }

    fn symlink(&self, name: &[u8], target: &[u8]) -> Result<InodeRef> {
        let (dir, _) = self.prepare_new(name)?;
        let inode = dir.symlink(name, target)?;
        self.added(name, inode)
    }

    fn link(&self, name: &[u8], inode: &InodeRef) -> Result<()> {
        let node = self.same_fs(inode)?;
        self.check_writable()?;
        let target = node.copy_up()?;
        let (dir, _) = self.prepare_new(name)?;
        dir.link(name, &target)
    }

    fn unlink(&self, name: &[u8]) -> Result<()> {
        self.check_writable()?;
        let node = self.child(name)?;
        if node.is_dir() {
            return Err(Errno::EISDIR);
        }
        let dir = self.copy_up()?;
        if node.upper().is_some() {
            dir.unlink(name)?;
        }
        self.white_out(&dir, name)?;
        self.forget(name);
        Ok(())
    }

    fn rmdir(&self, name: &[u8]) -> Result<()> {
        self.check_writable()?;
        let node = self.child(name)?;
        if !node.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        Node::check_empty(&node)?;
        let dir = self.copy_up()?;
        if let Some(upper) = node.upper() {
            self.remove_whiteouts(&upper)?;
            dir.rmdir(name)?;
        }
        self.white_out(&dir, name)?;
        self.forget(name);
        Ok(())
    }

    fn rename(&self, old: &[u8], new_dir: &InodeRef, new: &[u8]) -> Result<()> {
        let to = self.same_fs(new_dir)?;
        self.check_writable()?;
        let node = self.child(old)?;
        let moving_dir = node.is_dir();
        if moving_dir && !node.lowers.is_empty() {
            return Err(Errno::EXDEV);
        }
        let src = node.copy_up()?;
        let from_dir = self.copy_up()?;
        let to_dir = to.copy_up()?;
        match to.child(new) {
            Ok(target) if target.is_dir() => {
                Node::check_empty(&target)?;
                if let Some(upper) = target.upper() {
                    self.remove_whiteouts(&upper)?;
                }
            }
            Ok(_) | Err(Errno::ENOENT) => {}
            Err(e) => return Err(e),
        }
        if let Ok(i) = to_dir.lookup(new)
            && is_whiteout(&i)
        {
            to_dir.unlink(new)?;
        }
        from_dir.rename(old, &to_dir, new)?;
        if moving_dir && to.lower_has(new) {
            src.set_xattr(&self.fs.xattr(OPAQUE), b"y", 0)?;
        }
        self.white_out(&from_dir, old)?;
        self.forget(old);
        to.forget(new);
        *node.place.lock() = (Some(to.clone()), new.to_vec());
        to.children.lock().insert(new.to_vec(), Arc::downgrade(&node));
        Ok(())
    }

    fn read_link(&self) -> Result<Vec<u8>> {
        self.real().read_link()
    }

    fn read_dir(&self, pos: u64) -> Result<Option<(DirEntry, u64)>> {
        if !self.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let mut entries = self.entries.lock();
        if pos == 0 {
            let ino = self.metadata().ino;
            let parent = self.place.lock().0.clone();
            let up = parent.map_or(ino, |p| p.metadata().ino);
            let mut list = vec![
                DirEntry { ino, kind: FileType::Directory, name: b".".to_vec() },
                DirEntry { ino: up, kind: FileType::Directory, name: b"..".to_vec() },
            ];
            list.extend(self.joined()?);
            *entries = list;
        }
        let index = usize::try_from(pos).unwrap_or(usize::MAX);
        Ok(entries.get(index).map(|e| (e.clone(), pos + 1)))
    }

    fn get_xattr(&self, name: &[u8]) -> Result<Vec<u8>> {
        self.real().get_xattr(&self.fs.escape(name))
    }

    fn set_xattr(&self, name: &[u8], value: &[u8], flags: u32) -> Result<()> {
        self.check_writable()?;
        let name = self.fs.escape(name);
        self.copy_up()?.set_xattr(&name, value, flags)
    }

    fn list_xattr(&self) -> Result<Vec<Vec<u8>>> {
        let names = self.real().list_xattr()?;
        Ok(names.iter().filter_map(|n| self.fs.unescape(n)).collect())
    }

    fn remove_xattr(&self, name: &[u8]) -> Result<()> {
        self.check_writable()?;
        let name = self.fs.escape(name);
        self.real().get_xattr(&name)?;
        self.copy_up()?.remove_xattr(&name)
    }

    fn fs_id(&self) -> u64 {
        self.fs.dev
    }

    fn fs_stat(&self) -> Option<FsStat> {
        let mut root = self.arc().ok()?;
        loop {
            let parent = root.place.lock().0.clone();
            match parent {
                Some(p) => root = p,
                None => break,
            }
        }
        root.real().fs_stat()
    }

    fn fs_magic(&self) -> u64 {
        OVERLAYFS_SUPER_MAGIC
    }

    fn set_read_only(&self, read_only: bool) -> Result<()> {
        // A mount without an upper directory or without a work directory stays read only, as
        // `ovl_reconfigure` of Linux.
        if !read_only && !self.fs.writable {
            return Err(Errno::EROFS);
        }
        self.fs.read_only.store(read_only, Ordering::Relaxed);
        Ok(())
    }

    fn is_read_only(&self) -> bool {
        self.fs.read_only.load(Ordering::Relaxed)
    }

    fn fs_options(&self) -> Vec<u8> {
        self.fs.options.clone()
    }
}

#[cfg(test)]
mod tests;

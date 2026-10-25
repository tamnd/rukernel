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

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::fstype::{FsType, MountArgs, option};
use rk_vfs::inode::{FsStat, mode};
use rk_vfs::{DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, Timespec};

/// The magic number of overlayfs, `OVERLAYFS_SUPER_MAGIC` of `<linux/magic.h>`.
pub const OVERLAYFS_SUPER_MAGIC: u64 = 0x794c_7630;

/// The file system type for `mount -t overlay`.
pub const FS_TYPE: FsType = FsType { name: "overlay", nodev: true, make: mount };

/// The extended attribute that makes a directory of the upper directory opaque.
const OPAQUE: &[u8] = b"trusted.overlay.opaque";
/// The prefix of the extended attributes that overlayfs keeps for itself. A user cannot see them
/// or change them through the mount.
const PRIVATE: &[u8] = b"trusted.overlay.";
/// The bytes that a copy up moves in one step.
const CHUNK: usize = 64 * 1024;

/// One mount of overlayfs.
struct Fs {
    /// The device of the mount, for the directories.
    dev: u64,
    /// Tells if the mount has an upper directory.
    writable: bool,
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
/// separated by `:` and the top layer first, `upperdir=` and `workdir=`. The upper directory
/// needs the work directory, as in Linux, but this file system does not use it.
pub fn mount(args: &MountArgs<'_>) -> Result<InodeRef> {
    let lowerdir = option(args.data, b"lowerdir").ok_or(Errno::EINVAL)?;
    let mut lowers = Vec::new();
    for path in lowerdir.split(|&b| b == b':') {
        if path.is_empty() {
            return Err(Errno::EINVAL);
        }
        lowers.push(dir(args, path)?);
    }
    let upper = match (option(args.data, b"upperdir"), option(args.data, b"workdir")) {
        (Some(upper), Some(work)) => {
            let upper = dir(args, upper)?;
            let work = dir(args, work)?;
            if upper.fs_id() != work.fs_id() {
                return Err(Errno::EINVAL);
            }
            Some(upper)
        }
        (None, _) => None,
        (Some(_), None) => return Err(Errno::EINVAL),
    };
    new(lowers, upper)
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
/// gives its root. Gives `EINVAL` if there is no directory.
pub fn new(lowers: Vec<InodeRef>, upper: Option<InodeRef>) -> Result<InodeRef> {
    let fs = Arc::new(Fs { dev: rk_vfs::anon_dev(), writable: upper.is_some() });
    Ok(Node::new(&fs, None, Vec::new(), upper, lowers).ok_or(Errno::EINVAL)?)
}

/// Tells if `inode` is a whiteout: a character device with the device number 0:0.
fn is_whiteout(inode: &InodeRef) -> bool {
    let m = inode.metadata();
    m.file_type() == Some(FileType::CharDevice) && m.rdev == 0
}

/// Tells if the directory `inode` hides the lower directories.
fn is_opaque(inode: &InodeRef) -> bool {
    inode.get_xattr(OPAQUE).is_ok_and(|v| v == b"y")
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

/// Tells if the entry `entry` of the directory `dir` is a whiteout.
fn entry_is_whiteout(dir: &InodeRef, entry: &DirEntry) -> bool {
    entry.kind == FileType::CharDevice && dir.lookup(&entry.name).is_ok_and(|i| is_whiteout(&i))
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
                Ok(i) if is_whiteout(&i) => return Err(Errno::ENOENT),
                Ok(i) => {
                    more = i.metadata().is_dir() && !is_opaque(&i);
                    upper = Some(i);
                }
                Err(Errno::ENOENT) => {}
                Err(e) => return Err(e),
            }
            more = more && !is_opaque(&dir);
        }
        for dir in &self.lowers {
            if !more {
                break;
            }
            match dir.lookup(name) {
                Ok(i) if is_whiteout(&i) => break,
                Ok(i) => {
                    let is_dir = i.metadata().is_dir();
                    let found = upper.is_some() || !lowers.is_empty();
                    if found && !is_dir {
                        break;
                    }
                    more = is_dir && !is_opaque(&i);
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
                Ok(i) => return !is_whiteout(&i),
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
            if attr.starts_with(PRIVATE) {
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
        })?;
        *slot = Some(upper.clone());
        Ok(upper)
    }

    /// Gives the joined entries of the directory but `.` and `..`, in the order of the names.
    fn joined(&self) -> Result<Vec<DirEntry>> {
        // `None` is a name that a whiteout hides.
        let mut names: BTreeMap<Vec<u8>, Option<DirEntry>> = BTreeMap::new();
        let mut more = true;
        if let Some(dir) = self.upper() {
            for entry in real_entries(&dir)? {
                let hidden = entry_is_whiteout(&dir, &entry);
                names.insert(entry.name.clone(), (!hidden).then_some(entry));
            }
            more = !is_opaque(&dir);
        }
        if more {
            for dir in &self.lowers {
                for entry in real_entries(dir)? {
                    if names.contains_key(&entry.name) {
                        continue;
                    }
                    let hidden = entry_is_whiteout(dir, &entry);
                    names.insert(entry.name.clone(), (!hidden).then_some(entry));
                }
            }
        }
        Ok(names.into_values().flatten().collect())
    }

    /// Removes the whiteouts of the upper directory `dir` before a removal of the directory.
    fn remove_whiteouts(dir: &InodeRef) -> Result<()> {
        for entry in real_entries(dir)? {
            if entry_is_whiteout(dir, &entry) {
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
        if m.is_dir() {
            m.dev = self.fs.dev;
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
            inode.set_xattr(OPAQUE, b"y", 0)?;
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
            Node::remove_whiteouts(&upper)?;
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
                    Node::remove_whiteouts(&upper)?;
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
            src.set_xattr(OPAQUE, b"y", 0)?;
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
        if name.starts_with(PRIVATE) {
            return Err(Errno::ENODATA);
        }
        self.real().get_xattr(name)
    }

    fn set_xattr(&self, name: &[u8], value: &[u8], flags: u32) -> Result<()> {
        self.check_writable()?;
        if name.starts_with(PRIVATE) {
            return Err(Errno::EPERM);
        }
        self.copy_up()?.set_xattr(name, value, flags)
    }

    fn list_xattr(&self) -> Result<Vec<Vec<u8>>> {
        let mut names = self.real().list_xattr()?;
        names.retain(|n| !n.starts_with(PRIVATE));
        Ok(names)
    }

    fn remove_xattr(&self, name: &[u8]) -> Result<()> {
        self.check_writable()?;
        if name.starts_with(PRIVATE) {
            return Err(Errno::ENODATA);
        }
        self.real().get_xattr(name)?;
        self.copy_up()?.remove_xattr(name)
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
}

#[cfg(test)]
mod tests;

//! The notification of file system events, as fs/notify/fsnotify.c of Linux.
//!
//! A group, for example an inotify instance, puts marks on inodes. A mark has the events that the
//! group wants. The VFS calls the hooks of this module at the places where Linux calls the
//! functions of include/linux/fsnotify.h: an open, a read, a write, a close, a change of the
//! attributes, a create, a remove, a rename and an unmount. A hook gives the event to each mark of
//! the inode, and to each mark of the parent directory that wants the events of its children.
//!
//! The marks do not depend on inotify: dnotify and fanotify are other groups. An inotify mark and
//! a dnotify mark are on an inode. A fanotify mark can also be on a mount or on a file system,
//! and fanotify gets the events of an open file with their path, as `FSNOTIFY_EVENT_PATH` of
//! Linux. A global count of the marks lets each hook return at once when no group has a mark,
//! which is the usual case.
//!
//! The constants are the `FS_*` values of include/linux/fsnotify_backend.h, which are the same as
//! the `IN_*` values of include/uapi/linux/inotify.h.

pub mod dnotify;
pub mod fanotify;
pub mod inotify;
pub mod queue;

use crate::dentry::{Dentry, Location, Mount};
use crate::inode::{InodeRef, Result, SetAttr};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use rk_frame::sync::SpinLock;

/// The bits of an event and of a mark.
pub mod mask {
    /// The file was read.
    pub const ACCESS: u32 = 0x1;
    /// The file was written.
    pub const MODIFY: u32 = 0x2;
    /// The attributes changed.
    pub const ATTRIB: u32 = 0x4;
    /// A file that was open for a write was closed.
    pub const CLOSE_WRITE: u32 = 0x8;
    /// A file that was not open for a write was closed.
    pub const CLOSE_NOWRITE: u32 = 0x10;
    /// The file was opened.
    pub const OPEN: u32 = 0x20;
    /// A file moved out of the directory.
    pub const MOVED_FROM: u32 = 0x40;
    /// A file moved into the directory.
    pub const MOVED_TO: u32 = 0x80;
    /// A file was made in the directory.
    pub const CREATE: u32 = 0x100;
    /// A file was removed from the directory.
    pub const DELETE: u32 = 0x200;
    /// The watched file was removed.
    pub const DELETE_SELF: u32 = 0x400;
    /// The watched file moved.
    pub const MOVE_SELF: u32 = 0x800;
    /// The file was opened to run it, `FS_OPEN_EXEC`.
    pub const OPEN_EXEC: u32 = 0x1000;
    /// The file system of the file was unmounted.
    pub const UNMOUNT: u32 = 0x2000;
    /// The queue of the group overflowed.
    pub const Q_OVERFLOW: u32 = 0x4000;
    /// The mark went away, `IN_IGNORED`.
    pub const IGNORED: u32 = 0x8000;
    /// A permission event before an open, `FS_OPEN_PERM`.
    pub const OPEN_PERM: u32 = 0x1_0000;
    /// A permission event before a read, `FS_ACCESS_PERM`.
    pub const ACCESS_PERM: u32 = 0x2_0000;
    /// A permission event before an open to run the file, `FS_OPEN_EXEC_PERM`.
    pub const OPEN_EXEC_PERM: u32 = 0x4_0000;
    /// The permission events.
    pub const PERM_EVENTS: u32 = OPEN_PERM | ACCESS_PERM | OPEN_EXEC_PERM;
    /// Only the events after the child is unlinked, `IN_EXCL_UNLINK`: a mark with it does not
    /// get the events of a file that has no name.
    pub const EXCL_UNLINK: u32 = 0x0400_0000;
    /// The mark of a directory wants the events of its children.
    pub const EVENT_ON_CHILD: u32 = 0x0800_0000;
    /// A file moved in its directory, `FS_RENAME`. Only dnotify uses it here.
    pub const RENAME: u32 = 0x1000_0000;
    /// The dnotify entry stays after its first event, `FS_DN_MULTISHOT`.
    pub const DN_MULTISHOT: u32 = 0x2000_0000;
    /// The subject of the event is a directory.
    pub const ISDIR: u32 = 0x4000_0000;
    /// The mark goes away after its first event, `IN_ONESHOT`.
    pub const ONESHOT: u32 = 0x8000_0000;
    /// All the events that a group can ask for, `IN_ALL_EVENTS`.
    pub const ALL_EVENTS: u32 = 0xfff;
    /// The events of a file that the mark of its parent also gets, with the name of the file,
    /// as `FS_EVENTS_POSS_ON_CHILD` of Linux.
    pub const ON_CHILD: u32 = ACCESS | MODIFY | ATTRIB | CLOSE_WRITE | CLOSE_NOWRITE | OPEN;
}

/// A group of marks: the receiver of the events, as `struct fsnotify_group` of Linux.
pub trait Group: Send + Sync {
    /// Takes the event `mask` for `mark`. `name` is the name of the child for an event that the
    /// mark of a directory gets, and `cookie` joins the two events of a rename. As
    /// `handle_inode_event` of Linux.
    fn handle_event(&self, mark: &Arc<Mark>, mask: u32, name: Option<&[u8]>, cookie: u32);

    /// The mark goes away, as `freeing_mark` of Linux. inotify queues `IN_IGNORED` here.
    fn freeing_mark(&self, mark: &Arc<Mark>);

    /// Tells if the group gets the events of an open file with their path, as fanotify. Such a
    /// group gets its events from `handle_path` and not from `handle_event`.
    fn wants_paths(&self) -> bool {
        false
    }

    /// The order of the group for the events of a path: a group with a higher value gets the
    /// event first, as the priority of a fanotify class in Linux.
    fn priority(&self) -> u32 {
        0
    }

    /// Takes the event `mask` of the file at `at`. `marks` are the marks of the group that the
    /// event found. An error of a permission event stops the operation, as
    /// `fanotify_handle_event` of Linux.
    ///
    /// # Errors
    ///
    /// Gives the error of the answer to a permission event.
    fn handle_path(&self, at: &Location, mask: u32, marks: &[(Found, Arc<Mark>)]) -> Result<()> {
        let _ = (at, mask, marks);
        Ok(())
    }
}

/// The object of a mark, as the connector types of Linux.
#[derive(Clone)]
pub enum Object {
    /// An inode.
    Inode(InodeRef),
    /// A mount.
    Mount(Arc<Mount>),
    /// A file system, by its ID.
    Fs(u64),
}

impl Object {
    fn key(&self) -> (u8, usize) {
        match self {
            Self::Inode(inode) => (0, key(inode)),
            Self::Mount(mount) => (1, Arc::as_ptr(mount) as usize),
            Self::Fs(id) => (2, *id as usize),
        }
    }

    /// Tells if `self` and `other` are the same object.
    pub fn same(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}

/// The place of a mark that an event of a path found, as the iterator types of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Found {
    /// The mark is on the inode of the file.
    Inode,
    /// The mark is on the parent directory of the file.
    Parent,
    /// The mark is on the mount of the file.
    Mount,
    /// The mark is on the file system of the file.
    Fs,
}

/// A mark of a group on an object, as `struct fsnotify_mark` of Linux.
pub struct Mark {
    group: Arc<dyn Group>,
    object: Object,
    mask: AtomicU32,
    ignore: AtomicU32,
    flags: AtomicU32,
    id: i32,
    alive: AtomicBool,
}

impl Mark {
    /// The events and the flags that the mark wants.
    pub fn mask(&self) -> u32 {
        self.mask.load(Ordering::Relaxed)
    }

    /// Changes the events and the flags.
    pub fn set_mask(&self, mask: u32) {
        self.mask.store(mask, Ordering::Relaxed);
    }

    /// The number that the group gave the mark, the watch descriptor of inotify.
    pub fn id(&self) -> i32 {
        self.id
    }

    /// The events that the mark ignores, the ignore mask of fanotify.
    pub fn ignore(&self) -> u32 {
        self.ignore.load(Ordering::Relaxed)
    }

    /// Changes the events that the mark ignores.
    pub fn set_ignore(&self, ignore: u32) {
        self.ignore.store(ignore, Ordering::Relaxed);
    }

    /// The flags of the group for the mark, as `FSNOTIFY_MARK_FLAG_*` of Linux.
    pub fn flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }

    /// Changes the flags of the group for the mark.
    pub fn set_flags(&self, flags: u32) {
        self.flags.store(flags, Ordering::Relaxed);
    }

    /// The inode of the mark, if the mark is on an inode.
    pub fn inode(&self) -> Option<&InodeRef> {
        match &self.object {
            Object::Inode(inode) => Some(inode),
            _ => None,
        }
    }

    /// The object of the mark.
    pub fn object(&self) -> &Object {
        &self.object
    }

    /// Tells if the mark is still on its inode.
    pub fn alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }
}

/// The marks of each object, by the kind and the address of the object. A mark holds its inode
/// or its mount, so the address stays the same while the object has marks.
static MARKS: SpinLock<MarkMap> = SpinLock::new(BTreeMap::new());

/// A map from the kind and the address of an object to the marks of the object.
type MarkMap = BTreeMap<(u8, usize), Vec<Arc<Mark>>>;

/// The number of marks, so that a hook returns at once when there are none.
static COUNT: AtomicUsize = AtomicUsize::new(0);

/// The number of marks of the groups that get the events of a path.
static PATH_COUNT: AtomicUsize = AtomicUsize::new(0);

/// The cookie of the last rename, as `fsnotify_get_cookie` of Linux.
static COOKIE: AtomicU32 = AtomicU32::new(0);

fn key(inode: &InodeRef) -> usize {
    Arc::as_ptr(inode).cast::<()>() as usize
}

fn none() -> bool {
    COUNT.load(Ordering::Acquire) == 0
}

/// Puts a new mark of `group` on `inode` with the events `mask` and the number `id`, as
/// `fsnotify_add_inode_mark` of Linux.
pub fn add_mark(group: Arc<dyn Group>, inode: &InodeRef, mask: u32, id: i32) -> Arc<Mark> {
    add_object_mark(group, Object::Inode(inode.clone()), mask, id)
}

/// Puts a new mark of `group` on `object` with the events `mask` and the number `id`, as
/// `fsnotify_add_mark` of Linux.
pub fn add_object_mark(group: Arc<dyn Group>, object: Object, mask: u32, id: i32) -> Arc<Mark> {
    let paths = group.wants_paths();
    let k = object.key();
    let mark = Arc::new(Mark {
        group,
        object,
        mask: AtomicU32::new(mask),
        ignore: AtomicU32::new(0),
        flags: AtomicU32::new(0),
        id,
        alive: AtomicBool::new(true),
    });
    MARKS.lock().entry(k).or_default().push(mark.clone());
    COUNT.fetch_add(1, Ordering::AcqRel);
    if paths {
        PATH_COUNT.fetch_add(1, Ordering::AcqRel);
    }
    mark
}

/// The marks on `object`.
pub fn object_marks(object: &Object) -> Vec<Arc<Mark>> {
    MARKS.lock().get(&object.key()).cloned().unwrap_or_default()
}

/// Removes `mark` from its inode and tells its group, as `fsnotify_destroy_mark` of Linux. The
/// second call for a mark does nothing.
pub fn destroy_mark(mark: &Arc<Mark>) {
    if !mark.alive.swap(false, Ordering::AcqRel) {
        return;
    }
    {
        let mut marks = MARKS.lock();
        let k = mark.object.key();
        if let Some(list) = marks.get_mut(&k) {
            list.retain(|m| !Arc::ptr_eq(m, mark));
            if list.is_empty() {
                marks.remove(&k);
            }
        }
    }
    COUNT.fetch_sub(1, Ordering::AcqRel);
    if mark.group.wants_paths() {
        PATH_COUNT.fetch_sub(1, Ordering::AcqRel);
    }
    mark.group.freeing_mark(mark);
}

/// The marks of `inode`. The lock is free when the groups get the events, so a group can remove
/// a mark.
fn marks_of(inode: &InodeRef) -> Vec<Arc<Mark>> {
    MARKS.lock().get(&(0, key(inode))).cloned().unwrap_or_default()
}

/// Gives the event `mask` of the file at `at` to the groups that get the events of a path, as
/// `fsnotify` of Linux with `FSNOTIFY_EVENT_PATH`. Each group gets its marks on the inode, on the
/// parent, on the mount and on the file system together, so it can join their masks.
fn path_event(at: &Location, mask: u32) -> Result<()> {
    if PATH_COUNT.load(Ordering::Acquire) == 0 {
        return Ok(());
    }
    let inode = at.inode();
    let mut found: Vec<(Found, Arc<Mark>)> = Vec::new();
    {
        let marks = MARKS.lock();
        let mut add = |kind: Found, k: (u8, usize)| {
            for m in marks.get(&k).into_iter().flatten() {
                if m.group.wants_paths() {
                    found.push((kind, m.clone()));
                }
            }
        };
        add(Found::Inode, (0, key(inode)));
        if let Some(parent) = at.dentry.parent()
            && !Arc::ptr_eq(&parent, &at.dentry)
        {
            add(Found::Parent, (0, key(parent.inode())));
        }
        add(Found::Mount, (1, Arc::as_ptr(&at.mount) as usize));
        add(Found::Fs, (2, inode.fs_id() as usize));
    }
    let mask = mask | dir_bit(inode);
    found.sort_by_key(|(_, m)| core::cmp::Reverse(m.group.priority()));
    while let Some((_, first)) = found.first() {
        let group = first.group.clone();
        let (mine, rest): (Vec<_>, Vec<_>) =
            found.into_iter().partition(|(_, m)| Arc::ptr_eq(&m.group, &group));
        found = rest;
        group.handle_path(at, mask, &mine)?;
    }
    Ok(())
}

/// Gives the event to the marks of `to`. `child` is the dentry of the subject for an event
/// that the mark of the parent gets, and `data` is the dentry of the subject, for
/// `IN_EXCL_UNLINK`. As `send_to_group` of Linux.
fn send(
    to: &InodeRef,
    mask: u32,
    name: Option<&[u8]>,
    cookie: u32,
    on_child: bool,
    data: Option<&Dentry>,
) {
    for mark in marks_of(to) {
        if mark.group.wants_paths() {
            continue;
        }
        let wants = mark.mask();
        if on_child && wants & mask::EVENT_ON_CHILD == 0 {
            continue;
        }
        if wants & mask & !(mask::ISDIR | mask::EVENT_ON_CHILD) == 0 {
            continue;
        }
        // As `inotify_handle_inode_event` of Linux, for each group.
        if wants & mask::EXCL_UNLINK != 0 && data.is_some_and(Dentry::unlinked) {
            continue;
        }
        mark.group.handle_event(&mark, mask, name, cookie);
    }
}

fn dir_bit(inode: &InodeRef) -> u32 {
    if inode.metadata().is_dir() { mask::ISDIR } else { 0 }
}

/// An event of the file of `dentry`: the parent gets it with the name if it wants the events of
/// its children, then the file gets it, as `fsnotify_parent` and `fsnotify_dentry` of Linux.
pub fn dentry_event(dentry: &Dentry, mask: u32) {
    if none() {
        return;
    }
    let inode = dentry.inode();
    let mask = mask | dir_bit(inode);
    if mask & mask::ON_CHILD != 0
        && let Some(parent) = dentry.parent()
        && !core::ptr::eq(&*parent, dentry)
    {
        let name = dentry.name();
        send(parent.inode(), mask, Some(&name), 0, true, Some(dentry));
    }
    send(inode, mask, None, 0, false, Some(dentry));
}

/// An event of `inode` only, as `fsnotify_inode` of Linux.
pub fn inode_event(inode: &InodeRef, mask: u32) {
    if none() {
        return;
    }
    send(inode, mask | dir_bit(inode), None, 0, false, None);
}

/// An event of the directory `dir` about its child `name`, as `fsnotify_name` of Linux.
pub fn name_event(dir: &InodeRef, mask: u32, name: &[u8], cookie: u32) {
    if none() {
        return;
    }
    send(dir, mask, Some(name), cookie, false, None);
}

/// An event of an open file: the parent and the file get it, or the inode only if the file has
/// no place in the tree.
fn file_event(location: Option<&Location>, inode: Option<&InodeRef>, mask: u32) {
    if none() {
        return;
    }
    match (location, inode) {
        (Some(at), _) => dentry_event(&at.dentry, mask),
        (None, Some(inode)) => inode_event(inode, mask),
        (None, None) => {}
    }
}

/// The events of an open file: an access, a modification, an open and a close. Only these
/// events have the path that fanotify needs.
fn open_file_event(location: Option<&Location>, inode: Option<&InodeRef>, mask: u32) {
    if none() {
        return;
    }
    match (location, inode) {
        (Some(at), _) => {
            dentry_event(&at.dentry, mask);
            let _ = path_event(at, mask);
        }
        (None, Some(inode)) => inode_event(inode, mask),
        (None, None) => {}
    }
}

/// The permission events before an open of the file at `at`, as `fsnotify_open_perm` of Linux.
/// `exec` tells that the open is to run the file.
///
/// # Errors
///
/// Gives `EPERM` or the error of the answer if a group denies the open.
pub fn open_perm(at: &Location, exec: bool) -> Result<()> {
    if none() {
        return Ok(());
    }
    if exec {
        path_event(at, mask::OPEN_EXEC_PERM)?;
    }
    path_event(at, mask::OPEN_PERM)
}

/// The permission event before a read of the file at `at`, as `fsnotify_file_area_perm` of
/// Linux.
///
/// # Errors
///
/// Gives `EPERM` or the error of the answer if a group denies the read.
pub fn access_perm(at: &Location) -> Result<()> {
    if none() {
        return Ok(());
    }
    path_event(at, mask::ACCESS_PERM)
}

/// A read of a file, as `fsnotify_access` of Linux.
pub fn access(location: Option<&Location>, inode: Option<&InodeRef>) {
    open_file_event(location, inode, mask::ACCESS);
}

/// A write of a file, as `fsnotify_modify` of Linux.
pub fn modify(location: Option<&Location>, inode: Option<&InodeRef>) {
    open_file_event(location, inode, mask::MODIFY);
}

/// An open of a file, as `fsnotify_open` of Linux. A file of `O_PATH` has no events. `exec` tells
/// that the open is to run the file.
pub fn open(at: &Location, exec: bool) {
    let m = if exec { mask::OPEN | mask::OPEN_EXEC } else { mask::OPEN };
    open_file_event(Some(at), None, m);
}

/// The last close of a file, as `fsnotify_close` of Linux.
pub fn close(location: Option<&Location>, inode: Option<&InodeRef>, write: bool) {
    let mask = if write { mask::CLOSE_WRITE } else { mask::CLOSE_NOWRITE };
    open_file_event(location, inode, mask);
}

/// The events of a change of the attributes, as `fsnotify_change` of Linux: the owner and the
/// mode give `IN_ATTRIB`, the size gives `IN_MODIFY`, and the times give `IN_ATTRIB` for both,
/// `IN_ACCESS` for the access time and `IN_MODIFY` for the modification time.
pub fn attr_mask(attr: &SetAttr) -> u32 {
    let mut m = 0;
    if attr.uid.is_some() || attr.gid.is_some() || attr.mode.is_some() {
        m |= mask::ATTRIB;
    }
    if attr.size.is_some() {
        m |= mask::MODIFY;
    }
    match (attr.atime.is_some(), attr.mtime.is_some()) {
        (true, true) => m |= mask::ATTRIB,
        (true, false) => m |= mask::ACCESS,
        (false, true) => m |= mask::MODIFY,
        (false, false) => {}
    }
    m
}

/// A change of the attributes of the file at `location`, or of `inode` if the file has no place.
pub fn change(location: Option<&Location>, inode: &InodeRef, attr: &SetAttr) {
    if none() {
        return;
    }
    let m = attr_mask(attr);
    if m != 0 {
        file_event(location, Some(inode), m);
    }
}

/// A change of an extended attribute, as `fsnotify_xattr` of Linux.
pub fn xattr(location: Option<&Location>, inode: &InodeRef) {
    file_event(location, Some(inode), mask::ATTRIB);
}

/// A new file `child` in the directory `dir`, as `fsnotify_create` and `fsnotify_mkdir` of Linux.
pub fn create(dir: &InodeRef, child: &Dentry) {
    if none() {
        return;
    }
    let m = mask::CREATE | dir_bit(child.inode());
    name_event(dir, m, &child.name(), 0);
}

/// A new link `name` of `inode` in the directory `dir`, as `fsnotify_link` of Linux.
pub fn link(dir: &InodeRef, name: &[u8], inode: &InodeRef) {
    inode_event(inode, mask::ATTRIB);
    name_event(dir, mask::CREATE, name, 0);
}

/// The file `inode` has no link and no name, as `fsnotify_inoderemove` of Linux: its marks get
/// `IN_DELETE_SELF` and go away. Linux removes the marks when it frees the inode. Here they go at
/// the removal of the last link, so that a mark does not keep the inode.
pub fn delete_self(inode: &InodeRef) {
    if none() {
        return;
    }
    inode_event(inode, mask::DELETE_SELF);
    for mark in marks_of(inode) {
        destroy_mark(&mark);
    }
}

/// The removal of the name `name` of `inode` from the directory `dir`, as `vfs_unlink` and
/// `vfs_rmdir` of Linux with `fsnotify_link_count`, `d_delete` and `fsnotify_delete`.
pub fn remove(dir: &InodeRef, name: &[u8], inode: &InodeRef, is_dir: bool) {
    if none() {
        return;
    }
    if !is_dir {
        inode_event(inode, mask::ATTRIB);
    }
    if is_dir || inode.metadata().nlink == 0 {
        delete_self(inode);
    }
    let m = mask::DELETE | if is_dir { mask::ISDIR } else { 0 };
    name_event(dir, m, name, 0);
}

/// A rename of `moved` from `old_name` in `old_dir` to `new_name` in `new_dir`, as
/// `fsnotify_move` of Linux. `target` is the file that the rename replaced. The two events of the
/// directories have the same cookie.
pub fn rename(
    old_dir: &InodeRef,
    old_name: &[u8],
    new_dir: &InodeRef,
    new_name: &[u8],
    moved: &InodeRef,
    target: Option<&InodeRef>,
) {
    if none() {
        return;
    }
    let cookie = COOKIE.fetch_add(1, Ordering::Relaxed).wrapping_add(1).max(1);
    let isdir = dir_bit(moved);
    // The event with the two names. Only dnotify takes it, and only for a move in one
    // directory, as `fsnotify_handle_event` of Linux.
    if Arc::ptr_eq(old_dir, new_dir) {
        name_event(old_dir, mask::RENAME | isdir, old_name, 0);
    }
    name_event(old_dir, mask::MOVED_FROM | isdir, old_name, cookie);
    name_event(new_dir, mask::MOVED_TO | isdir, new_name, cookie);
    if let Some(target) = target {
        inode_event(target, mask::ATTRIB);
        if target.metadata().is_dir() || target.metadata().nlink == 0 {
            delete_self(target);
        }
    }
    inode_event(moved, mask::MOVE_SELF);
}

/// The unmount of the file system `fs_id`: each mark of its inodes gets `IN_UNMOUNT` and goes
/// away, and the marks on the file system go away, as `fsnotify_sb_delete` of Linux.
pub fn unmount(fs_id: u64) {
    if none() {
        return;
    }
    let marks: Vec<Arc<Mark>> = MARKS.lock().values().flatten().cloned().collect();
    let mut gone = Vec::new();
    for mark in marks {
        let on_fs = match &mark.object {
            Object::Inode(inode) => inode.fs_id() == fs_id,
            Object::Mount(_) => false,
            Object::Fs(id) => *id == fs_id,
        };
        if on_fs {
            gone.push(mark);
        }
    }
    for mark in &gone {
        if mark.alive() {
            mark.group.handle_event(mark, mask::UNMOUNT, None, 0);
        }
    }
    for mark in &gone {
        destroy_mark(mark);
    }
}

/// The number of marks on all inodes.
pub fn mark_count() -> usize {
    COUNT.load(Ordering::Relaxed)
}

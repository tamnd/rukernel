//! Dentries, mounts and locations.
//!
//! A `Dentry` is a name of an inode in its parent directory. The dentries of a file system make a
//! tree that the VFS keeps while a process uses a name, so `getcwd` and `..` work after a rename.
//! A `Mount` puts the root of a file system on a dentry of another mount. A `Location` is a mount
//! and a dentry in it, as `struct path` of Linux.
//!
//! A mount can be shared, a slave, private or unbindable, as the shared subtrees of Linux. The
//! shared mounts of a peer group send their mount and unmount events to each other, and to the
//! mounts that are slaves of the group.

use crate::inode::{InodeRef, Result};
use crate::wait::WaitQueue;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use rk_abi::Errno;
use rk_abi::native::mount::{
    MOUNT_ATTR__ATIME, MOUNT_ATTR_IDMAP, MOUNT_ATTR_NOATIME, MOUNT_ATTR_NODEV,
    MOUNT_ATTR_NODIRATIME, MOUNT_ATTR_NOEXEC, MOUNT_ATTR_NOSUID, MOUNT_ATTR_NOSYMFOLLOW,
    MOUNT_ATTR_RDONLY, MOUNT_ATTR_RELATIME, MOUNT_ATTR_STRICTATIME, MS_NOATIME, MS_NODEV,
    MS_NODIRATIME, MS_NOEXEC, MS_NOSUID, MS_NOSYMFOLLOW, MS_PRIVATE, MS_RDONLY, MS_RELATIME,
    MS_SHARED, MS_SLAVE, MS_STRICTATIME, MS_UNBINDABLE,
};
use rk_frame::sync::SpinLock;

/// A name of an inode.
pub struct Dentry {
    name: SpinLock<Vec<u8>>,
    parent: SpinLock<Option<Arc<Dentry>>>,
    inode: InodeRef,
    /// The children that a lookup found. A child that no one uses goes away.
    children: SpinLock<BTreeMap<Vec<u8>, Weak<Dentry>>>,
    /// The inode has no link, and `linkat` can give it one, as `I_LINKABLE` of Linux. It is
    /// for a file of `O_TMPFILE` without `O_EXCL`.
    linkable: AtomicBool,
    /// The name was removed, as `d_unlinked` of Linux, for `IN_EXCL_UNLINK`.
    unlinked: AtomicBool,
    /// The lock of the names in the directory, as `i_rwsem` of Linux. A create, a link, an
    /// unlink, a rmdir and a rename hold it while they examine the names and change them.
    lock: DirLock,
    /// `rmdir` or a rename removed the directory, as `S_DEAD` of Linux. It changes with `lock`
    /// held, and no new name goes in the directory after it.
    dead: AtomicBool,
    /// The count of the changes of `children`. It changes with the lock of `children` held. A
    /// lookup that did not find a child in the cache adds the inode that the file system gave
    /// only if no change came in the meantime, as the `d_seq` checks of fs/dcache.c of Linux.
    seq: AtomicU64,
}

/// A lock that a task can hold while it blocks, as `inode_lock` of a directory in Linux. The
/// operations of a file system can wait for a block device with the lock held, so it is not a
/// spin lock.
pub struct DirLock {
    held: AtomicBool,
    queue: WaitQueue,
}

impl DirLock {
    /// Makes an unlocked lock.
    pub const fn new() -> Self {
        Self { held: AtomicBool::new(false), queue: WaitQueue::new() }
    }

    /// Takes the lock. The task waits while another task holds it.
    pub fn lock(&self) -> DirGuard<'_> {
        // `wait_until` puts the task in the queue before it tests the condition again, so the
        // wake of an unlock is not lost.
        self.queue.wait_until(|| {
            self.held
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .ok()
                .map(drop)
        });
        DirGuard { lock: self }
    }
}

impl Default for DirLock {
    fn default() -> Self {
        Self::new()
    }
}

/// The guard of a [`DirLock`]. The drop releases the lock.
pub struct DirGuard<'a> {
    lock: &'a DirLock,
}

impl Drop for DirGuard<'_> {
    fn drop(&mut self) {
        self.lock.held.store(false, Ordering::Release);
        self.lock.queue.wake_all();
    }
}

impl core::fmt::Debug for Dentry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = self.name();
        f.debug_struct("Dentry")
            .field("name", &alloc::string::String::from_utf8_lossy(&name))
            .finish()
    }
}

impl Dentry {
    /// Makes the root dentry of a file system.
    pub fn new_root(inode: InodeRef) -> Arc<Self> {
        Arc::new(Self {
            name: SpinLock::new(Vec::from(&b"/"[..])),
            parent: SpinLock::new(None),
            inode,
            children: SpinLock::new(BTreeMap::new()),
            linkable: AtomicBool::new(false),
            unlinked: AtomicBool::new(false),
            lock: DirLock::new(),
            dead: AtomicBool::new(false),
            seq: AtomicU64::new(0),
        })
    }

    /// The inode.
    pub fn inode(&self) -> &InodeRef {
        &self.inode
    }

    /// The name in the parent directory. The root has the name `/`.
    pub fn name(&self) -> Vec<u8> {
        self.name.lock().clone()
    }

    /// The parent, or `None` for the root of a file system.
    pub fn parent(&self) -> Option<Arc<Dentry>> {
        self.parent.lock().clone()
    }

    /// Finds the child `name`. The dentry is the same while someone uses it.
    ///
    /// The lookup does not hold the lock of the directory. A create, an unlink or a rename on
    /// another CPU can change the name while the file system looks for it, so the lookup adds
    /// the inode to the cache only if no change of the cache came in the meantime. Else it looks
    /// again. Thus the cache keeps no name that an unlink removed, and two lookups give the same
    /// dentry, as `d_alloc_parallel` in fs/dcache.c of Linux.
    pub fn lookup(self: &Arc<Self>, name: &[u8]) -> Result<Arc<Dentry>> {
        loop {
            let seq = {
                let children = self.children.lock();
                if let Some(child) = children.get(name).and_then(Weak::upgrade) {
                    return Ok(child);
                }
                self.seq.load(Ordering::Relaxed)
            };
            let inode = self.inode.lookup(name)?;
            let mut children = self.children.lock();
            if let Some(child) = children.get(name).and_then(Weak::upgrade) {
                return Ok(child);
            }
            if self.seq.load(Ordering::Relaxed) == seq {
                let child = self.new_child(name, inode);
                children.retain(|_, c| c.strong_count() > 0);
                children.insert(name.to_vec(), Arc::downgrade(&child));
                return Ok(child);
            }
        }
    }

    /// Adds the dentry of a new inode `name`, after a create in this directory. If a lookup
    /// added a dentry of the same inode already, that dentry stays.
    pub fn add_child(self: &Arc<Self>, name: &[u8], inode: InodeRef) -> Arc<Dentry> {
        let mut children = self.children.lock();
        if let Some(child) = children.get(name).and_then(Weak::upgrade)
            && Arc::ptr_eq(&child.inode, &inode)
        {
            return child;
        }
        let child = self.new_child(name, inode);
        children.retain(|_, c| c.strong_count() > 0);
        children.insert(name.to_vec(), Arc::downgrade(&child));
        self.seq.fetch_add(1, Ordering::Relaxed);
        child
    }

    /// Makes a dentry for the child `name` with the inode `inode`.
    fn new_child(self: &Arc<Self>, name: &[u8], inode: InodeRef) -> Arc<Dentry> {
        Arc::new(Self {
            name: SpinLock::new(name.to_vec()),
            parent: SpinLock::new(Some(self.clone())),
            inode,
            children: SpinLock::new(BTreeMap::new()),
            linkable: AtomicBool::new(false),
            unlinked: AtomicBool::new(false),
            lock: DirLock::new(),
            dead: AtomicBool::new(false),
            seq: AtomicU64::new(0),
        })
    }

    /// Takes the lock of the names of the directory, as `inode_lock` of Linux.
    pub fn lock(&self) -> DirGuard<'_> {
        self.lock.lock()
    }

    /// Tells if `rmdir` or a rename removed the directory, as `IS_DEADDIR` of Linux. A new name
    /// cannot go in it.
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    /// Records that the directory was removed. The caller holds the lock of the directory.
    pub(crate) fn set_dead(&self) {
        self.dead.store(true, Ordering::Release);
    }

    /// Makes the dentry of the new inode `inode` that has no name in this directory, for
    /// `O_TMPFILE`. The name is `#` and the inode number, as `d_tmpfile` of Linux. The dentry is
    /// not in the cache, so no lookup finds it. `open_by_handle_at` also uses it for an inode
    /// that it found without a path.
    pub fn tmp_child(self: &Arc<Self>, inode: InodeRef, linkable: bool) -> Arc<Dentry> {
        let name = alloc::format!("#{}", inode.metadata().ino);
        Arc::new(Self {
            name: SpinLock::new(name.into_bytes()),
            parent: SpinLock::new(Some(self.clone())),
            inode,
            children: SpinLock::new(BTreeMap::new()),
            linkable: AtomicBool::new(linkable),
            unlinked: AtomicBool::new(false),
            lock: DirLock::new(),
            dead: AtomicBool::new(false),
            seq: AtomicU64::new(0),
        })
    }

    /// Tells if `linkat` can give a link to the inode, which has no link.
    pub fn linkable(&self) -> bool {
        self.linkable.load(Ordering::Relaxed)
    }

    /// Ends the right of `linkat` to give a link to the inode, after the first link.
    pub(crate) fn clear_linkable(&self) {
        self.linkable.store(false, Ordering::Relaxed);
    }

    /// Tells if the name of the dentry was removed.
    pub fn unlinked(&self) -> bool {
        self.unlinked.load(Ordering::Relaxed)
    }

    /// Records that the name of the dentry was removed, after an unlink, a rmdir or a rename
    /// that replaced it.
    pub(crate) fn set_unlinked(&self) {
        self.unlinked.store(true, Ordering::Relaxed);
    }

    /// Removes the child `name` from the cache, after an unlink or a rmdir.
    pub fn forget_child(&self, name: &[u8]) {
        let mut children = self.children.lock();
        children.remove(name);
        self.seq.fetch_add(1, Ordering::Relaxed);
    }

    /// Moves the cached child `old` of this dentry to the name `new` of `new_parent`, after a
    /// rename.
    pub fn move_child(self: &Arc<Self>, old: &[u8], new_parent: &Arc<Dentry>, new: &[u8]) {
        let moved = self.take_child(old);
        new_parent.take_child(new);
        if let Some(child) = moved {
            *child.name.lock() = new.to_vec();
            *child.parent.lock() = Some(new_parent.clone());
            new_parent.put_child(new, &child);
        }
    }

    /// Removes the cached child `name` and gives it, for a rename.
    fn take_child(&self, name: &[u8]) -> Option<Arc<Dentry>> {
        let mut children = self.children.lock();
        self.seq.fetch_add(1, Ordering::Relaxed);
        children.remove(name).and_then(|c| c.upgrade())
    }

    /// Puts `child` in the cache with the name `name`, for a rename.
    fn put_child(&self, name: &[u8], child: &Arc<Dentry>) {
        let mut children = self.children.lock();
        self.seq.fetch_add(1, Ordering::Relaxed);
        children.insert(name.to_vec(), Arc::downgrade(child));
    }

    /// Exchanges the cached children `old` of `self` and `new` of `new_parent`, after a
    /// `RENAME_EXCHANGE`.
    pub fn exchange_child(self: &Arc<Self>, old: &[u8], new_parent: &Arc<Dentry>, new: &[u8]) {
        let first = self.take_child(old);
        let second = new_parent.take_child(new);
        if let Some(child) = first {
            *child.name.lock() = new.to_vec();
            *child.parent.lock() = Some(new_parent.clone());
            new_parent.put_child(new, &child);
        }
        if let Some(child) = second {
            *child.name.lock() = old.to_vec();
            *child.parent.lock() = Some(self.clone());
            self.put_child(old, &child);
        }
    }

    /// The path of the dentry from the root of its file system, as `show_path` of Linux shows
    /// the root of a mount. The root gives `/`.
    pub fn fs_path(self: &Arc<Self>) -> Vec<u8> {
        let mut path = Vec::new();
        let mut d = self.clone();
        while let Some(up) = d.parent() {
            let mut part = Vec::from(&b"/"[..]);
            part.extend_from_slice(&d.name());
            path.splice(0..0, part);
            d = up;
        }
        if path.is_empty() {
            path.push(b'/');
        }
        path
    }

    /// Tells if `self` is `other` or a descendant of `other`.
    pub fn is_under(self: &Arc<Self>, other: &Arc<Dentry>) -> bool {
        let mut at = Some(self.clone());
        while let Some(d) = at {
            if Arc::ptr_eq(&d, other) {
                return true;
            }
            at = d.parent();
        }
        false
    }
}

/// The source, the type and the flags of a mount, as `/proc/self/mounts` shows them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountSource {
    /// The source argument of `mount(2)`, for example a device or `none`.
    pub source: Vec<u8>,
    /// The name of the file system type.
    pub fstype: &'static str,
    /// The flags of the mount: `MS_RDONLY`, `MS_NOSUID`, `MS_NODEV`, `MS_NOEXEC` and the
    /// others.
    pub flags: u64,
}

impl MountSource {
    /// The source of the root of the initramfs, which Linux names `rootfs`.
    pub fn rootfs() -> Self {
        Self { source: Vec::from(&b"rootfs"[..]), fstype: "rootfs", flags: 0 }
    }
}

/// The propagation of a mount, as the peer group and the master of a mount of Linux.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Propagation {
    /// The peer group of a shared mount, or 0 if the mount is not shared.
    pub group: u64,
    /// The peer group that sends its events to the mount, or 0 if the mount is not a slave.
    pub master: u64,
    /// The mount cannot be the source of a bind mount.
    pub unbindable: bool,
}

/// A change of the propagation of a mount, as `MS_SHARED`, `MS_SLAVE`, `MS_PRIVATE` and
/// `MS_UNBINDABLE` of `mount(2)` give.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PropagationType {
    /// The mount sends its events to its peers and receives their events.
    Shared,
    /// The mount receives the events of its old peer group or master, and sends no events.
    Slave,
    /// The mount sends and receives no events.
    Private,
    /// The mount is private and cannot be the source of a bind mount.
    Unbindable,
}

/// A change of the flags and of the propagation of mounts, as `struct mount_attr` of
/// `mount_setattr` gives it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MountAttr {
    /// The flags to clear: `MS_RDONLY`, `MS_NOATIME` and the others.
    pub clear: u64,
    /// The flags to set. They apply after `clear`.
    pub set: u64,
    /// The new propagation, or `None` to keep the propagation.
    pub propagation: Option<PropagationType>,
}

/// The `MOUNT_ATTR_*` flags that are bits, and their `MS_*` flags. The atime flags are a value in
/// `MOUNT_ATTR__ATIME`.
const ATTR_BITS: [(u32, u32); 6] = [
    (MOUNT_ATTR_RDONLY, MS_RDONLY),
    (MOUNT_ATTR_NOSUID, MS_NOSUID),
    (MOUNT_ATTR_NODEV, MS_NODEV),
    (MOUNT_ATTR_NOEXEC, MS_NOEXEC),
    (MOUNT_ATTR_NODIRATIME, MS_NODIRATIME),
    (MOUNT_ATTR_NOSYMFOLLOW, MS_NOSYMFOLLOW),
];

/// Gives the `MS_*` flags of the bits of `attr`, as `attr_flags_to_mnt_flags` of Linux.
fn bit_flags(attr: u64) -> u64 {
    let flags = ATTR_BITS.iter().filter(|(a, _)| attr & u64::from(*a) != 0);
    flags.fold(0, |all, (_, ms)| all | u64::from(*ms))
}

impl MountAttr {
    /// Gives the change of the `attr_set`, `attr_clr` and `propagation` fields of
    /// `struct mount_attr`, as `build_mount_kattr` of Linux. Gives `EINVAL` for an unknown flag
    /// and for more than one propagation type.
    ///
    /// The atime flags are a value and not bits. Thus an atime value in `set` needs all of
    /// `MOUNT_ATTR__ATIME` in `clear`. `MOUNT_ATTR_IDMAP` is a known flag, but it is not in the
    /// result.
    pub fn from_user(set: u64, clear: u64, propagation: u64) -> Result<Self> {
        let propagation = match u32::try_from(propagation).map_err(|_| Errno::EINVAL)? {
            0 => None,
            MS_SHARED => Some(PropagationType::Shared),
            MS_SLAVE => Some(PropagationType::Slave),
            MS_PRIVATE => Some(PropagationType::Private),
            MS_UNBINDABLE => Some(PropagationType::Unbindable),
            _ => return Err(Errno::EINVAL),
        };
        let known =
            ATTR_BITS.iter().fold(MOUNT_ATTR__ATIME | MOUNT_ATTR_IDMAP, |all, (a, _)| all | a);
        if (set | clear) & !u64::from(known) != 0 {
            return Err(Errno::EINVAL);
        }
        let atime = u64::from(MOUNT_ATTR__ATIME);
        let mut attr = Self { clear: bit_flags(clear), set: bit_flags(set), propagation };
        if clear & atime != 0 {
            if clear & atime != atime {
                return Err(Errno::EINVAL);
            }
            // The mount keeps `MS_STRICTATIME`, so a change of the atime value clears it too.
            attr.clear |= u64::from(MS_RELATIME | MS_NOATIME | MS_STRICTATIME);
            attr.set |= u64::from(match (set & atime) as u32 {
                MOUNT_ATTR_RELATIME => MS_RELATIME,
                MOUNT_ATTR_NOATIME => MS_NOATIME,
                MOUNT_ATTR_STRICTATIME => MS_STRICTATIME,
                _ => return Err(Errno::EINVAL),
            });
        } else if set & atime != 0 {
            return Err(Errno::EINVAL);
        }
        Ok(attr)
    }
}

/// A mounted file system.
pub struct Mount {
    id: u64,
    root: Arc<Dentry>,
    /// The place of the mount, or `None` for the root mount of a name space and for a mount that
    /// `fsmount` or `open_tree` made and that is not attached yet.
    mountpoint: SpinLock<Option<Location>>,
    source: SpinLock<MountSource>,
    propagation: SpinLock<Propagation>,
    /// The name space of the mount. It is empty for a mount that is not attached.
    ns: SpinLock<Weak<MountNamespace>>,
    /// The number of the open files of the mount that can write, as `mnt_writers` of Linux. A
    /// mount with writers cannot become read only.
    writers: AtomicUsize,
    /// The number of the open files of the mount. A mount with open files is busy for `umount2`.
    opens: AtomicUsize,
    /// The number of walks that went into the mount. `MNT_EXPIRE` uses it.
    entries: AtomicU64,
    /// The mark of `MNT_EXPIRE`, as `mnt_expiry_mark` of Linux: 0 for no mark, or 1 more than
    /// the value of `entries` at the time of the mark.
    expiry: AtomicU64,
}

impl core::fmt::Debug for Mount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mount").field("id", &self.id).finish_non_exhaustive()
    }
}

impl Mount {
    fn new(root: Arc<Dentry>, source: MountSource) -> Arc<Self> {
        Arc::new(Self {
            id: NEXT_MOUNT_ID.fetch_add(1, Ordering::Relaxed),
            root,
            mountpoint: SpinLock::new(None),
            source: SpinLock::new(source),
            propagation: SpinLock::new(Propagation::default()),
            ns: SpinLock::new(Weak::new()),
            writers: AtomicUsize::new(0),
            opens: AtomicUsize::new(0),
            entries: AtomicU64::new(0),
            expiry: AtomicU64::new(0),
        })
    }

    /// The mount ID, as `/proc/self/mountinfo` shows it.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The unique mount ID of `statx` with `STATX_MNT_ID_UNIQUE`, `statmount` and `listmount`,
    /// as `mnt_id_unique` of Linux.
    pub fn unique_id(&self) -> u64 {
        UNIQUE_ID_OFFSET + self.id
    }

    /// The mount that the mount is on, or `None` for the root mount of a name space and for a
    /// mount that is not attached.
    pub fn parent(&self) -> Option<Arc<Mount>> {
        self.mountpoint().map(|p| p.mount)
    }

    /// The root dentry of the file system.
    pub fn root(&self) -> &Arc<Dentry> {
        &self.root
    }

    /// The place of the mount.
    pub fn mountpoint(&self) -> Option<Location> {
        self.mountpoint.lock().clone()
    }

    /// The source, the type and the flags.
    pub fn source(&self) -> MountSource {
        self.source.lock().clone()
    }

    /// The flags: `MS_RDONLY`, `MS_NOATIME` and the others.
    pub fn flags(&self) -> u64 {
        self.source.lock().flags
    }

    /// Sets the flags, for `MS_REMOUNT` and `mount_setattr`. A mount becomes read only only if
    /// it has no open file that can write, as `mnt_make_readonly` of Linux.
    ///
    /// # Errors
    ///
    /// Gives `EBUSY` if `flags` has `MS_RDONLY`, the mount is writable and a file of the mount
    /// is open for a write.
    pub fn set_flags(&self, flags: u64) -> Result<()> {
        let mut source = self.source.lock();
        if !self.can_set_flags(source.flags, flags) {
            return Err(Errno::EBUSY);
        }
        source.flags = flags;
        Ok(())
    }

    /// Tells if the flags can change from `old` to `new`.
    fn can_set_flags(&self, old: u64, new: u64) -> bool {
        let ro = u64::from(MS_RDONLY);
        old & ro != 0 || new & ro == 0 || !self.has_writers()
    }

    /// Tells if the mount is read only, as `__mnt_is_readonly` of Linux. The mount has
    /// `MS_RDONLY`, or its file system is read only.
    pub fn is_read_only(&self) -> bool {
        self.flags() & u64::from(MS_RDONLY) != 0 || self.root.inode().is_read_only()
    }

    /// Checks that a change of the files of the mount can start, as `mnt_want_write` of Linux.
    /// The VFS calls it before each change of a name, of the data or of the attributes of a
    /// file. A file that is open for a write does not call it again, because the mount cannot
    /// become read only while the file is open.
    ///
    /// # Errors
    ///
    /// Gives `EROFS` if the mount or its file system is read only.
    pub fn want_write(&self) -> Result<()> {
        if self.is_read_only() { Err(Errno::EROFS) } else { Ok(()) }
    }

    /// Tells if a file of the mount is open for a write.
    pub fn has_writers(&self) -> bool {
        self.writers.load(Ordering::Acquire) != 0
    }

    /// Counts a new open file of the mount that can write.
    pub(crate) fn add_writer(&self) {
        self.writers.fetch_add(1, Ordering::AcqRel);
    }

    /// Stops the count of an open file of the mount that can write, after its close.
    pub(crate) fn remove_writer(&self) {
        self.writers.fetch_sub(1, Ordering::AcqRel);
    }

    /// Counts an open file of the mount.
    pub(crate) fn add_open(&self) {
        self.opens.fetch_add(1, Ordering::AcqRel);
    }

    /// Stops the count of an open file of the mount, after its close.
    pub(crate) fn remove_open(&self) {
        self.opens.fetch_sub(1, Ordering::AcqRel);
    }

    /// The number of the open files of the mount.
    pub fn open_files(&self) -> usize {
        self.opens.load(Ordering::Acquire)
    }

    /// Records that a walk went into the mount. This clears the mark of `MNT_EXPIRE`.
    pub(crate) fn enter(&self) {
        self.entries.fetch_add(1, Ordering::AcqRel);
    }

    /// Marks the mount for `MNT_EXPIRE`. Tells if the mount had the mark and only the walk of
    /// the caller went into the mount after the mark, so the mount can go.
    pub fn expire(&self) -> bool {
        let now = self.entries.load(Ordering::Acquire);
        let mark = self.expiry.swap(now + 1, Ordering::AcqRel);
        mark != 0 && now <= mark
    }

    /// The propagation of the mount.
    pub fn propagation(&self) -> Propagation {
        *self.propagation.lock()
    }

    fn set_propagation(&self, p: Propagation) {
        *self.propagation.lock() = p;
    }

    /// Changes the propagation to `ty`, as `change_mnt_propagation` of Linux.
    fn change_propagation(self: &Arc<Self>, ty: PropagationType) {
        let mut p = self.propagation();
        if ty == PropagationType::Shared {
            if p.group == 0 {
                p.group = new_group();
            }
            p.unbindable = false;
            self.set_propagation(p);
            return;
        }
        // The mount leaves its peer group, as `do_make_slave` of Linux. If the group has other
        // peers, the mount becomes their slave. Else the slaves of the group go to the master of
        // the mount.
        if p.group != 0 {
            let all = attached();
            let peers =
                all.iter().any(|m| !Arc::ptr_eq(m, self) && m.propagation().group == p.group);
            if peers {
                p.master = p.group;
            } else {
                for m in all.iter().filter(|m| m.propagation().master == p.group) {
                    let mut q = m.propagation();
                    q.master = p.master;
                    m.set_propagation(q);
                }
            }
            p.group = 0;
        }
        match ty {
            PropagationType::Private => (p.master, p.unbindable) = (0, false),
            PropagationType::Unbindable => (p.master, p.unbindable) = (0, true),
            _ => {}
        }
        self.set_propagation(p);
    }

    fn namespace(&self) -> Option<Arc<MountNamespace>> {
        self.ns.lock().upgrade()
    }

    /// Tells if the mount was never in a name space, as a mount that `fsmount` or `open_tree`
    /// with `OPEN_TREE_CLONE` made and that `move_mount` did not attach yet.
    pub fn is_detached(&self) -> bool {
        self.mountpoint().is_none() && self.namespace().is_none()
    }
}

/// The unique mount IDs start after this value, as `MNT_UNIQUE_ID_OFFSET` of Linux. rukernel
/// does not use a mount ID again, so the unique ID of a mount is its ID plus this value.
pub const UNIQUE_ID_OFFSET: u64 = 1 << 31;

/// The mounts of each name space, for the propagation between name spaces.
static ATTACHED: SpinLock<Vec<Weak<Mount>>> = SpinLock::new(Vec::new());

static NEXT_GROUP: AtomicU64 = AtomicU64::new(1);

fn new_group() -> u64 {
    NEXT_GROUP.fetch_add(1, Ordering::Relaxed)
}

/// Tells if a mount of the file system of `root` has a file that is open for a write. A
/// remount that makes the file system read only gives `EBUSY` then, as
/// `sb_prepare_remount_readonly` of Linux.
pub fn fs_has_writers(root: &InodeRef) -> bool {
    let id = root.fs_id();
    attached().iter().any(|m| m.has_writers() && m.root.inode().fs_id() == id)
}

/// The mounts that are in a name space.
fn attached() -> Vec<Arc<Mount>> {
    let mut all = ATTACHED.lock();
    all.retain(|m| m.strong_count() > 0);
    all.iter().filter_map(Weak::upgrade).collect()
}

/// The mounts that receive the events of `from`, which is shared, with the propagation of the
/// copy of a new mount on each of them, as `propagate_mnt` of Linux. A copy on a peer of `from`
/// is in the peer group `group`. A copy on a slave is a slave of the group of the copies that its
/// master gets. A copy on a peer group that is a slave goes in a new peer group, if `copies` is
/// true.
fn receivers(from: &Arc<Mount>, group: u64, copies: bool) -> Vec<(Arc<Mount>, Propagation)> {
    let all = attached();
    let mut out = Vec::new();
    let start = from.propagation().group;
    if start == 0 {
        return out;
    }
    let mut seen = BTreeSet::from([start]);
    let mut todo = alloc::vec![(start, group, 0)];
    while let Some((g, copy_group, copy_master)) = todo.pop() {
        for m in &all {
            let p = m.propagation();
            if p.group == g {
                if !Arc::ptr_eq(m, from) {
                    let copy =
                        Propagation { group: copy_group, master: copy_master, unbindable: false };
                    out.push((m.clone(), copy));
                }
            } else if p.master == g {
                if p.group == 0 {
                    let copy = Propagation { group: 0, master: copy_group, unbindable: false };
                    out.push((m.clone(), copy));
                } else if seen.insert(p.group) {
                    let next = if copies { new_group() } else { 0 };
                    todo.push((p.group, next, copy_group));
                }
            }
        }
    }
    out
}

/// A mount and a dentry in it.
#[derive(Clone, Debug)]
pub struct Location {
    /// The mount.
    pub mount: Arc<Mount>,
    /// The dentry.
    pub dentry: Arc<Dentry>,
}

impl Location {
    /// Makes a location for `inode` in a mount of its own, outside each name space. It is for
    /// a file without a name, as a pipe, which the internal mounts of Linux hold.
    pub fn detached(inode: InodeRef) -> Self {
        let mount = Mount::new(Dentry::new_root(inode), MountSource::rootfs());
        Location { dentry: mount.root.clone(), mount }
    }

    /// The inode.
    pub fn inode(&self) -> &InodeRef {
        self.dentry.inode()
    }

    /// Tells if both locations are the same.
    pub fn same(&self, other: &Location) -> bool {
        Arc::ptr_eq(&self.mount, &other.mount) && Arc::ptr_eq(&self.dentry, &other.dentry)
    }

    /// Tells if the location is `root` or under it in the tree of the mounts, as
    /// `is_path_reachable` of Linux.
    pub fn is_reachable_from(&self, root: &Location) -> bool {
        let mut at = self.clone();
        while !Arc::ptr_eq(&at.mount, &root.mount) {
            match at.mount.mountpoint() {
                Some(up) => at = up,
                None => return false,
            }
        }
        at.dentry.is_under(&root.dentry)
    }

    /// The top mount on the sibling `name` of the location, as `path_pts` of Linux finds `pts`
    /// next to `/dev/ptmx`. Gives `None` if the sibling is not there or has no mount on it.
    pub fn sibling_mount(&self, name: &[u8]) -> Option<Location> {
        let ns = self.mount.namespace()?;
        let dentry = self.dentry.parent()?.lookup(name).ok()?;
        let mut at = Location { mount: self.mount.clone(), dentry };
        let mut found = false;
        while let Some(mount) = ns.mounted_on(&at) {
            at = Location { dentry: mount.root.clone(), mount };
            found = true;
        }
        found.then_some(at)
    }

    /// Tells if the location is the root of its mount.
    pub fn is_mount_root(&self) -> bool {
        Arc::ptr_eq(&self.dentry, &self.mount.root)
    }

    /// The path from the root of the name space, through the mount points. It is for the
    /// places that show a file to a person, as `/proc/PID/maps`. `FsContext::path_of` gives the
    /// path from the root of a process.
    pub fn absolute_path(&self) -> Vec<u8> {
        let mut parts = Vec::new();
        let mut at = self.clone();
        loop {
            if at.is_mount_root() {
                match at.mount.mountpoint() {
                    Some(up) => at = up,
                    None => break,
                }
                continue;
            }
            parts.push(at.dentry.name());
            let Some(parent) = at.dentry.parent() else { break };
            at.dentry = parent;
        }
        if parts.is_empty() {
            return Vec::from(&b"/"[..]);
        }
        let mut path = Vec::new();
        for part in parts.iter().rev() {
            path.push(b'/');
            path.extend_from_slice(part);
        }
        path
    }
}

/// The mounts that a group of processes sees, as a mount name space of Linux.
pub struct MountNamespace {
    root: Arc<Mount>,
    mounts: SpinLock<Vec<Arc<Mount>>>,
    me: Weak<MountNamespace>,
    /// The count of the changes of the mounts, as `event` of `struct mnt_namespace` of Linux.
    event: AtomicU64,
}

/// The waits of `poll` on `/proc/PID/mounts` wait here for a change of the mounts of a name
/// space, as `poll` of `struct mnt_namespace` of Linux. One queue serves each name space.
static NS_POLL: WaitQueue = WaitQueue::new();

static NEXT_MOUNT_ID: AtomicU64 = AtomicU64::new(1);

impl MountNamespace {
    /// Makes a name space with the root `root`. The root mount has the source `rootfs`.
    pub fn new(root: InodeRef) -> Arc<Self> {
        let mount = Mount::new(Dentry::new_root(root), MountSource::rootfs());
        let ns = Arc::new_cyclic(|me| Self {
            root: mount.clone(),
            mounts: SpinLock::new(Vec::from([mount.clone()])),
            me: me.clone(),
            event: AtomicU64::new(0),
        });
        *mount.ns.lock() = ns.me.clone();
        ATTACHED.lock().push(Arc::downgrade(&mount));
        ns
    }

    /// Makes a copy of the name space with a copy of each mount, for `CLONE_NEWNS`, as
    /// `copy_mnt_ns` of Linux. A copy has the propagation of its mount, so a copy of a shared
    /// mount is a peer of the mount. `locations` go to the same places in the copy.
    pub fn copy(&self, locations: &mut [&mut Location]) -> Arc<Self> {
        let old = self.mounts();
        let new: Vec<Arc<Mount>> = old
            .iter()
            .map(|m| {
                let copy = Mount::new(m.root.clone(), m.source());
                copy.set_propagation(m.propagation());
                copy
            })
            .collect();
        let find = |m: &Arc<Mount>| old.iter().position(|o| Arc::ptr_eq(o, m)).map(|i| &new[i]);
        for (m, copy) in old.iter().zip(&new) {
            if let Some(place) = m.mountpoint() {
                let mount = find(&place.mount).cloned().unwrap_or(place.mount);
                *copy.mountpoint.lock() = Some(Location { mount, dentry: place.dentry });
            }
        }
        let root = find(&self.root)
            .cloned()
            .unwrap_or_else(|| Mount::new(self.root.root.clone(), self.root.source()));
        for at in locations {
            if let Some(mount) = find(&at.mount) {
                at.mount = mount.clone();
            }
        }
        let ns = Arc::new_cyclic(|me| Self {
            root,
            mounts: SpinLock::new(new.clone()),
            me: me.clone(),
            event: AtomicU64::new(0),
        });
        let mut all = ATTACHED.lock();
        for m in &new {
            *m.ns.lock() = ns.me.clone();
            all.push(Arc::downgrade(m));
        }
        ns
    }

    /// The root of the name space.
    pub fn root(&self) -> Location {
        Location { mount: self.root.clone(), dentry: self.root.root.clone() }
    }

    /// Mounts the file system with the root `root` on the directory `at`.
    pub fn mount(&self, root: InodeRef, at: &Location, source: MountSource) -> Result<Arc<Mount>> {
        if !root.metadata().is_dir() {
            return Err(Errno::ENOTDIR);
        }
        self.mount_dentry(Dentry::new_root(root), at, source)
    }

    /// Mounts the tree at `from` on `at`, for `MS_BIND`. The new mount has the source of the
    /// mount of `from`. A file can be mounted on a file, and a directory on a directory. Gives
    /// `EINVAL` if the mount of `from` is unbindable.
    ///
    /// The new mount is a peer of a shared source, and a slave of the master of a slave source,
    /// as the shared subtrees of Linux.
    pub fn bind(&self, from: &Location, at: &Location) -> Result<Arc<Mount>> {
        let mount = Self::clone_tree(from)?;
        self.attach(&mount, at)?;
        Ok(mount)
    }

    fn mount_dentry(
        &self,
        root: Arc<Dentry>,
        at: &Location,
        source: MountSource,
    ) -> Result<Arc<Mount>> {
        let mount = Self::detached(root, source);
        self.attach(&mount, at)?;
        Ok(mount)
    }

    /// Makes a mount of the tree at `root` that is not in a name space, for `fsmount` and
    /// `open_tree`. `attach` puts it in a name space.
    pub fn detached(root: Arc<Dentry>, source: MountSource) -> Arc<Mount> {
        Mount::new(root, source)
    }

    /// Makes a mount of the tree at `from` that is not in a name space, for `MS_BIND` and for
    /// `open_tree` with `OPEN_TREE_CLONE`. The new mount has the source and the propagation of the
    /// mount of `from`, as `clone_mnt` of Linux. Gives `EINVAL` if the mount of `from` is
    /// unbindable.
    pub fn clone_tree(from: &Location) -> Result<Arc<Mount>> {
        let p = from.mount.propagation();
        if p.unbindable {
            return Err(Errno::EINVAL);
        }
        let mount = Self::detached(from.dentry.clone(), from.mount.source());
        mount.set_propagation(p);
        Ok(mount)
    }

    /// Tells if `mount` is in the name space.
    pub fn contains(&self, mount: &Arc<Mount>) -> bool {
        self.mounts.lock().iter().any(|m| Arc::ptr_eq(m, mount))
    }

    /// Puts the mount `mount`, which is not in a name space, on `at`. A file can be mounted on a
    /// file, and a directory on a directory. Gives `EINVAL` if the mount is in a name space.
    ///
    /// If the mount of `at` is shared, the mount becomes shared, and each mount that receives
    /// the events of the mount of `at` gets a copy of the mount at the same place.
    pub fn attach(&self, mount: &Arc<Mount>, at: &Location) -> Result<()> {
        if mount.root.inode().metadata().is_dir() != at.inode().metadata().is_dir() {
            return Err(Errno::ENOTDIR);
        }
        if mount.mountpoint().is_some() || self.contains(mount) {
            return Err(Errno::EINVAL);
        }
        let mut p = mount.propagation();
        let shared = at.mount.propagation().group != 0;
        if shared && p.group == 0 {
            p.group = new_group();
            mount.set_propagation(p);
        }
        let targets = if shared { receivers(&at.mount, p.group, true) } else { Vec::new() };
        self.attach_one(mount, at);
        for (m, copy_p) in targets {
            let Some(ns) = m.namespace() else { continue };
            if !at.dentry.is_under(&m.root) {
                continue;
            }
            let copy = Mount::new(mount.root.clone(), mount.source());
            copy.set_propagation(copy_p);
            ns.attach_one(&copy, &Location { mount: m, dentry: at.dentry.clone() });
        }
        Ok(())
    }

    fn attach_one(&self, mount: &Arc<Mount>, at: &Location) {
        *mount.mountpoint.lock() = Some(at.clone());
        *mount.ns.lock() = self.me.clone();
        self.mounts.lock().push(mount.clone());
        ATTACHED.lock().push(Arc::downgrade(mount));
        self.touch();
    }

    /// Counts a change of the mounts and wakes the waits of `poll`, as `touch_mnt_namespace` of
    /// Linux.
    fn touch(&self) {
        self.event.fetch_add(1, Ordering::Relaxed);
        NS_POLL.wake_all();
    }

    /// The count of the changes of the mounts. A file of `/proc/PID/mounts` has an event of
    /// `POLLPRI` when the count changes, as `mounts_poll` of Linux.
    pub fn event(&self) -> u64 {
        self.event.load(Ordering::Relaxed)
    }

    /// The queue that a change of the mounts of a name space wakes.
    pub fn poll_queue() -> &'static WaitQueue {
        &NS_POLL
    }

    /// Changes the propagation of the mount of `at` to `ty`, and of each mount under it if
    /// `recursive` is true. Gives `EINVAL` if `at` is not the root of a mount of the name space.
    pub fn set_propagation(
        &self,
        at: &Location,
        ty: PropagationType,
        recursive: bool,
    ) -> Result<()> {
        if !at.is_mount_root() || !self.contains(&at.mount) {
            return Err(Errno::EINVAL);
        }
        for m in &self.tree(&at.mount, recursive) {
            m.change_propagation(ty);
        }
        Ok(())
    }

    /// Changes the flags and the propagation of the mount of `at`, and of each mount under it
    /// if `recursive` is true, for `mount_setattr`. As `do_mount_setattr` of Linux, the mount
    /// can be in the name space or be a detached mount. Gives `EINVAL` if `at` is not the root
    /// of the mount, or if the mount is in another name space. Gives `EBUSY` if a mount that
    /// becomes read only has a file that is open for a write.
    pub fn set_attr(&self, at: &Location, attr: MountAttr, recursive: bool) -> Result<()> {
        if !at.is_mount_root() || !(self.contains(&at.mount) || at.mount.is_detached()) {
            return Err(Errno::EINVAL);
        }
        let tree = self.tree(&at.mount, recursive);
        // No mount changes if one of them cannot become read only, as Linux.
        for m in &tree {
            if !m.can_set_flags(m.flags(), (m.flags() & !attr.clear) | attr.set) {
                return Err(Errno::EBUSY);
            }
        }
        for m in &tree {
            m.set_flags((m.flags() & !attr.clear) | attr.set)?;
            if let Some(ty) = attr.propagation {
                m.change_propagation(ty);
            }
        }
        Ok(())
    }

    /// Gives `mount`, and each mount of the name space under it if `recursive` is true.
    fn tree(&self, mount: &Arc<Mount>, recursive: bool) -> Vec<Arc<Mount>> {
        let mut tree = Vec::from([mount.clone()]);
        if recursive {
            for m in self.mounts() {
                let mut up = m.mountpoint().map(|p| p.mount);
                while let Some(u) = up {
                    if Arc::ptr_eq(&u, mount) {
                        tree.push(m.clone());
                        break;
                    }
                    up = u.mountpoint().map(|p| p.mount);
                }
            }
        }
        tree
    }

    /// Moves the mount of `from` to `at`, for `MS_MOVE` and `move_mount`. `from` is the root of
    /// a mount in the name space. Gives `EINVAL` for the root mount of the name space, and
    /// `ELOOP` if `at` is in the tree of the mount.
    pub fn move_to(&self, from: &Location, at: &Location) -> Result<()> {
        let mount = &from.mount;
        if !from.is_mount_root() || mount.mountpoint().is_none() || !self.contains(mount) {
            return Err(Errno::EINVAL);
        }
        if mount.root.inode().metadata().is_dir() != at.inode().metadata().is_dir() {
            return Err(Errno::ENOTDIR);
        }
        // The new place cannot be in the mount or in a mount on it.
        let mut below = Some(at.mount.clone());
        while let Some(m) = below {
            if Arc::ptr_eq(&m, mount) {
                return Err(Errno::ELOOP);
            }
            below = m.mountpoint().map(|p| p.mount);
        }
        let mut mounts = self.mounts.lock();
        *mount.mountpoint.lock() = Some(at.clone());
        // The last mount on a place hides the others, so the moved mount goes to the end.
        mounts.retain(|m| !Arc::ptr_eq(m, mount));
        mounts.push(mount.clone());
        drop(mounts);
        self.touch();
        Ok(())
    }

    /// Puts the mount of `from` below the top mount of `to`, for `MOVE_MOUNT_BENEATH`. The mount
    /// of `from` goes on the place of the top mount, and the top mount goes on the root of the
    /// mount of `from`. Gives `EINVAL` if `from` or `to` is not the root of a mount, or if the
    /// top mount is the root mount of the name space.
    pub fn move_beneath(&self, from: &Location, to: &Location) -> Result<()> {
        let (mount, top) = (&from.mount, &to.mount);
        if !from.is_mount_root() || !to.is_mount_root() || Arc::ptr_eq(mount, top) {
            return Err(Errno::EINVAL);
        }
        let Some(place) = top.mountpoint() else {
            return Err(Errno::EINVAL);
        };
        if !self.contains(top) {
            return Err(Errno::EINVAL);
        }
        if mount.root.inode().metadata().is_dir() != top.root.inode().metadata().is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let mut below = Some(place.mount.clone());
        while let Some(m) = below {
            if Arc::ptr_eq(&m, mount) {
                return Err(Errno::ELOOP);
            }
            below = m.mountpoint().map(|p| p.mount);
        }
        let mut mounts = self.mounts.lock();
        mounts.retain(|m| !Arc::ptr_eq(m, mount));
        let index = mounts.iter().position(|m| Arc::ptr_eq(m, top)).ok_or(Errno::EINVAL)?;
        *mount.mountpoint.lock() = Some(place);
        *top.mountpoint.lock() =
            Some(Location { mount: mount.clone(), dentry: mount.root.clone() });
        mounts.insert(index, mount.clone());
        drop(mounts);
        self.touch();
        Ok(())
    }

    /// Removes the mount on `at`, which is the root of the mount. Gives `EBUSY` if another mount
    /// is on the mount, and `EINVAL` if `at` is not the root of a mount.
    ///
    /// If the parent mount is shared, each mount that receives its events loses the copy of the
    /// mount at the same place, if no mount is on the copy, as `propagate_umount` of Linux.
    pub fn unmount(&self, at: &Location) -> Result<()> {
        let Some(place) = at.mount.mountpoint().filter(|_| at.is_mount_root()) else {
            return Err(Errno::EINVAL);
        };
        if !self.remove(&at.mount) {
            return Err(Errno::EBUSY);
        }
        for (m, _) in receivers(&place.mount, 0, false) {
            let Some(ns) = m.namespace() else { continue };
            let on = Location { mount: m, dentry: place.dentry.clone() };
            if let Some(copy) = ns.mounted_on(&on)
                && Arc::ptr_eq(&copy.root, &at.mount.root)
            {
                ns.remove(&copy);
            }
        }
        // The last mount of the file system went, as `fsnotify_sb_delete` of Linux.
        let root = at.mount.root().inode();
        let id = root.fs_id();
        if !attached().iter().any(|m| m.root.inode().fs_id() == id) {
            crate::notify::unmount(id);
        }
        Ok(())
    }

    /// Removes `mount` from the name space, if no mount is on it. Tells if it removed it.
    fn remove(&self, mount: &Arc<Mount>) -> bool {
        {
            let mut mounts = self.mounts.lock();
            let busy =
                mounts.iter().any(|m| m.mountpoint().is_some_and(|p| Arc::ptr_eq(&p.mount, mount)));
            if busy {
                return false;
            }
            mounts.retain(|m| !Arc::ptr_eq(m, mount));
        }
        self.touch();
        mount.change_propagation(PropagationType::Private);
        *mount.ns.lock() = Weak::new();
        ATTACHED.lock().retain(|m| !core::ptr::eq(m.as_ptr(), Arc::as_ptr(mount)));
        true
    }

    /// Makes the mount of `new` the root mount of the process and puts the mount of `root`,
    /// the old root, on `old`, for `pivot_root`, as `path_pivot_root` of Linux. `root` is the
    /// root of the process. The caller changes the root and the current directory of the
    /// processes that use `root`.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` if a mount is not in the name space, if the mount of `old`, the parent of
    /// the mount of `new` or the parent of the mount of `root` is shared, if `root` or `new` is
    /// not the root of a mount that is on another mount, or if `new` is not under `root` or
    /// `old` is not under `new`. Gives `ENOENT` if `new` was removed, and `EBUSY` if `new` or
    /// `old` is on the mount of `root`.
    pub fn pivot_root(&self, new: &Location, old: &Location, root: &Location) -> Result<()> {
        let (new_mnt, root_mnt, old_mnt) = (&new.mount, &root.mount, &old.mount);
        if !self.contains(root_mnt) || !self.contains(new_mnt) {
            return Err(Errno::EINVAL);
        }
        let shared = |m: Option<Arc<Mount>>| m.is_some_and(|m| m.propagation().group != 0);
        if shared(Some(old_mnt.clone())) || shared(new_mnt.parent()) || shared(root_mnt.parent()) {
            return Err(Errno::EINVAL);
        }
        if new.dentry.unlinked() {
            return Err(Errno::ENOENT);
        }
        if Arc::ptr_eq(new_mnt, root_mnt) || Arc::ptr_eq(old_mnt, root_mnt) {
            return Err(Errno::EBUSY);
        }
        // The root mount of the name space has no parent. Linux 7.3 puts the initramfs on
        // nullfs, so its root has a parent. Here the root mount cannot move yet.
        let Some(root_place) = root_mnt.mountpoint().filter(|_| root.is_mount_root()) else {
            return Err(Errno::EINVAL);
        };
        if !new.is_mount_root() || new_mnt.mountpoint().is_none() {
            return Err(Errno::EINVAL);
        }
        if !old.is_reachable_from(new) || !new.is_reachable_from(root) {
            return Err(Errno::EINVAL);
        }
        let mut mounts = self.mounts.lock();
        *new_mnt.mountpoint.lock() = Some(root_place);
        *root_mnt.mountpoint.lock() = Some(old.clone());
        // The last mount on a place hides the others, so both mounts go to the end.
        mounts.retain(|m| !Arc::ptr_eq(m, new_mnt) && !Arc::ptr_eq(m, root_mnt));
        mounts.push(new_mnt.clone());
        mounts.push(root_mnt.clone());
        drop(mounts);
        self.touch();
        Ok(())
    }

    /// The peer group of the name space that sends its events to the slave `mount`, and that
    /// has a peer under `root`, as `get_dominating_id` of Linux. Gives 0 if there is none.
    pub fn propagate_from(&self, mount: &Arc<Mount>, root: &Location) -> u64 {
        let all = attached();
        let mut group = mount.propagation().master;
        let mut seen = BTreeSet::new();
        while group != 0 && seen.insert(group) {
            let peers: Vec<&Arc<Mount>> =
                all.iter().filter(|m| m.propagation().group == group).collect();
            let under = |m: &&Arc<Mount>| {
                let at = Location { mount: (*m).clone(), dentry: m.root.clone() };
                self.contains(m) && at.is_reachable_from(root)
            };
            if peers.iter().any(under) {
                return group;
            }
            group = peers.iter().map(|m| m.propagation().master).find(|&g| g != 0).unwrap_or(0);
        }
        0
    }

    /// The mount of the name space with the unique ID `id`, as `lookup_mnt_in_ns` of Linux.
    pub fn find_unique(&self, id: u64) -> Option<Arc<Mount>> {
        self.mounts.lock().iter().find(|m| m.unique_id() == id).cloned()
    }

    /// The last mount on `at`, if a mount is on it.
    pub fn mounted_on(&self, at: &Location) -> Option<Arc<Mount>> {
        self.mounts
            .lock()
            .iter()
            .rev()
            .find(|m| m.mountpoint().is_some_and(|p| p.same(at)))
            .cloned()
    }

    /// The mounts in the order that they were made.
    pub fn mounts(&self) -> Vec<Arc<Mount>> {
        self.mounts.lock().clone()
    }
}

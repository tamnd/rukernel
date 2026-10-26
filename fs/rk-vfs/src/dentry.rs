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
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
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
    pub fn lookup(self: &Arc<Self>, name: &[u8]) -> Result<Arc<Dentry>> {
        if let Some(child) = self.children.lock().get(name).and_then(Weak::upgrade) {
            return Ok(child);
        }
        let inode = self.inode.lookup(name)?;
        Ok(self.add_child(name, inode))
    }

    /// Adds the dentry of a new inode `name`, after a create in this directory.
    pub fn add_child(self: &Arc<Self>, name: &[u8], inode: InodeRef) -> Arc<Dentry> {
        let child = Arc::new(Self {
            name: SpinLock::new(name.to_vec()),
            parent: SpinLock::new(Some(self.clone())),
            inode,
            children: SpinLock::new(BTreeMap::new()),
        });
        let mut children = self.children.lock();
        children.retain(|_, c| c.strong_count() > 0);
        children.insert(name.to_vec(), Arc::downgrade(&child));
        child
    }

    /// Removes the child `name` from the cache, after an unlink or a rmdir.
    pub fn forget_child(&self, name: &[u8]) {
        self.children.lock().remove(name);
    }

    /// Moves the cached child `old` of this dentry to the name `new` of `new_parent`, after a
    /// rename.
    pub fn move_child(self: &Arc<Self>, old: &[u8], new_parent: &Arc<Dentry>, new: &[u8]) {
        let moved = self.children.lock().remove(old).and_then(|c| c.upgrade());
        new_parent.children.lock().remove(new);
        if let Some(child) = moved {
            *child.name.lock() = new.to_vec();
            *child.parent.lock() = Some(new_parent.clone());
            new_parent.children.lock().insert(new.to_vec(), Arc::downgrade(&child));
        }
    }

    /// Exchanges the cached children `old` of `self` and `new` of `new_parent`, after a
    /// `RENAME_EXCHANGE`.
    pub fn exchange_child(self: &Arc<Self>, old: &[u8], new_parent: &Arc<Dentry>, new: &[u8]) {
        let first = self.children.lock().remove(old).and_then(|c| c.upgrade());
        let second = new_parent.children.lock().remove(new).and_then(|c| c.upgrade());
        if let Some(child) = first {
            *child.name.lock() = new.to_vec();
            *child.parent.lock() = Some(new_parent.clone());
            new_parent.children.lock().insert(new.to_vec(), Arc::downgrade(&child));
        }
        if let Some(child) = second {
            *child.name.lock() = old.to_vec();
            *child.parent.lock() = Some(self.clone());
            self.children.lock().insert(old.to_vec(), Arc::downgrade(&child));
        }
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
        })
    }

    /// The mount ID, as `/proc/self/mountinfo` shows it.
    pub fn id(&self) -> u64 {
        self.id
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

    /// Sets the flags, for `MS_REMOUNT`.
    pub fn set_flags(&self, flags: u64) {
        self.source.lock().flags = flags;
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

/// The mounts of each name space, for the propagation between name spaces.
static ATTACHED: SpinLock<Vec<Weak<Mount>>> = SpinLock::new(Vec::new());

static NEXT_GROUP: AtomicU64 = AtomicU64::new(1);

fn new_group() -> u64 {
    NEXT_GROUP.fetch_add(1, Ordering::Relaxed)
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
}

static NEXT_MOUNT_ID: AtomicU64 = AtomicU64::new(1);

impl MountNamespace {
    /// Makes a name space with the root `root`. The root mount has the source `rootfs`.
    pub fn new(root: InodeRef) -> Arc<Self> {
        let mount = Mount::new(Dentry::new_root(root), MountSource::rootfs());
        let ns = Arc::new_cyclic(|me| Self {
            root: mount.clone(),
            mounts: SpinLock::new(Vec::from([mount.clone()])),
            me: me.clone(),
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
        let ns =
            Arc::new_cyclic(|me| Self { root, mounts: SpinLock::new(new.clone()), me: me.clone() });
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
    /// of the mount, or if the mount is in another name space.
    pub fn set_attr(&self, at: &Location, attr: MountAttr, recursive: bool) -> Result<()> {
        if !at.is_mount_root() || !(self.contains(&at.mount) || at.mount.is_detached()) {
            return Err(Errno::EINVAL);
        }
        for m in &self.tree(&at.mount, recursive) {
            m.set_flags((m.flags() & !attr.clear) | attr.set);
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
        mount.change_propagation(PropagationType::Private);
        *mount.ns.lock() = Weak::new();
        ATTACHED.lock().retain(|m| !core::ptr::eq(m.as_ptr(), Arc::as_ptr(mount)));
        true
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

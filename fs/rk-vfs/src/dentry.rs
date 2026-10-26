//! Dentries, mounts and locations.
//!
//! A `Dentry` is a name of an inode in its parent directory. The dentries of a file system make a
//! tree that the VFS keeps while a process uses a name, so `getcwd` and `..` work after a rename.
//! A `Mount` puts the root of a file system on a dentry of another mount. A `Location` is a mount
//! and a dentry in it, as `struct path` of Linux.

use crate::inode::{InodeRef, Result};
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
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

/// A mounted file system.
pub struct Mount {
    id: u64,
    root: Arc<Dentry>,
    /// The place of the mount, or `None` for the root mount of a name space and for a mount that
    /// `fsmount` or `open_tree` made and that is not attached yet.
    mountpoint: SpinLock<Option<Location>>,
    source: SpinLock<MountSource>,
}

impl core::fmt::Debug for Mount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mount").field("id", &self.id).finish_non_exhaustive()
    }
}

impl Mount {
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
        let mount = Arc::new(Mount {
            id: NEXT_MOUNT_ID.fetch_add(1, Ordering::Relaxed),
            root: Dentry::new_root(inode),
            mountpoint: SpinLock::new(None),
            source: SpinLock::new(MountSource::rootfs()),
        });
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
}

static NEXT_MOUNT_ID: AtomicU64 = AtomicU64::new(1);

impl MountNamespace {
    /// Makes a name space with the root `root`. The root mount has the source `rootfs`.
    pub fn new(root: InodeRef) -> Arc<Self> {
        let mount = Arc::new(Mount {
            id: NEXT_MOUNT_ID.fetch_add(1, Ordering::Relaxed),
            root: Dentry::new_root(root),
            mountpoint: SpinLock::new(None),
            source: SpinLock::new(MountSource::rootfs()),
        });
        Arc::new(Self { root: mount.clone(), mounts: SpinLock::new(Vec::from([mount])) })
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
    /// mount of `from`. A file can be mounted on a file, and a directory on a directory.
    pub fn bind(&self, from: &Location, at: &Location) -> Result<Arc<Mount>> {
        self.mount_dentry(from.dentry.clone(), at, from.mount.source())
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
        Arc::new(Mount {
            id: NEXT_MOUNT_ID.fetch_add(1, Ordering::Relaxed),
            root,
            mountpoint: SpinLock::new(None),
            source: SpinLock::new(source),
        })
    }

    /// Makes a mount of the tree at `from` that is not in a name space, for `open_tree` with
    /// `OPEN_TREE_CLONE`. The new mount has the source of the mount of `from`.
    pub fn clone_tree(from: &Location) -> Arc<Mount> {
        Self::detached(from.dentry.clone(), from.mount.source())
    }

    /// Tells if `mount` is in the name space.
    pub fn contains(&self, mount: &Arc<Mount>) -> bool {
        self.mounts.lock().iter().any(|m| Arc::ptr_eq(m, mount))
    }

    /// Puts the mount `mount`, which is not in a name space, on `at`. A file can be mounted on a
    /// file, and a directory on a directory. Gives `EINVAL` if the mount is in a name space.
    pub fn attach(&self, mount: &Arc<Mount>, at: &Location) -> Result<()> {
        if mount.root.inode().metadata().is_dir() != at.inode().metadata().is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let mut mounts = self.mounts.lock();
        if mount.mountpoint().is_some() || mounts.iter().any(|m| Arc::ptr_eq(m, mount)) {
            return Err(Errno::EINVAL);
        }
        *mount.mountpoint.lock() = Some(at.clone());
        mounts.push(mount.clone());
        Ok(())
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
    pub fn unmount(&self, at: &Location) -> Result<()> {
        if !at.is_mount_root() || at.mount.mountpoint().is_none() {
            return Err(Errno::EINVAL);
        }
        let mut mounts = self.mounts.lock();
        let busy =
            mounts.iter().any(|m| m.mountpoint().is_some_and(|p| Arc::ptr_eq(&p.mount, &at.mount)));
        if busy {
            return Err(Errno::EBUSY);
        }
        mounts.retain(|m| !Arc::ptr_eq(m, &at.mount));
        Ok(())
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

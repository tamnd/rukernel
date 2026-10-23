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
    /// The place of the mount, or `None` for the root mount of a name space.
    mountpoint: Option<Location>,
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
    pub fn mountpoint(&self) -> Option<&Location> {
        self.mountpoint.as_ref()
    }

    /// The source, the type and the flags.
    pub fn source(&self) -> MountSource {
        self.source.lock().clone()
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
            mountpoint: None,
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
        if root.inode().metadata().is_dir() != at.inode().metadata().is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let mount = Arc::new(Mount {
            id: NEXT_MOUNT_ID.fetch_add(1, Ordering::Relaxed),
            root,
            mountpoint: Some(at.clone()),
            source: SpinLock::new(source),
        });
        self.mounts.lock().push(mount.clone());
        Ok(mount)
    }

    /// Removes the mount on `at`, which is the root of the mount. Gives `EBUSY` if another mount
    /// is on the mount, and `EINVAL` if `at` is not the root of a mount.
    pub fn unmount(&self, at: &Location) -> Result<()> {
        if !at.is_mount_root() || at.mount.mountpoint.is_none() {
            return Err(Errno::EINVAL);
        }
        let mut mounts = self.mounts.lock();
        let busy = mounts
            .iter()
            .any(|m| m.mountpoint.as_ref().is_some_and(|p| Arc::ptr_eq(&p.mount, &at.mount)));
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
            .find(|m| m.mountpoint.as_ref().is_some_and(|p| p.same(at)))
            .cloned()
    }

    /// The mounts in the order that they were made.
    pub fn mounts(&self) -> Vec<Arc<Mount>> {
        self.mounts.lock().clone()
    }
}

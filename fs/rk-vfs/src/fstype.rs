//! The file system types that `mount` can make, as `register_filesystem` of Linux.
//!
//! The kernel registers each type at boot. `mount(2)` finds the type by its name and calls its
//! constructor, and `/proc/filesystems` shows the list.

use crate::inode::{Inode, InodeRef, Result};
use alloc::sync::Weak;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

/// A file system type.
#[derive(Clone, Copy, Debug)]
pub struct FsType {
    /// The name that `mount -t` gives, for example `tmpfs`.
    pub name: &'static str,
    /// Tells if the file system has no block device. `/proc/filesystems` shows `nodev` for it.
    pub nodev: bool,
    /// Makes a new instance and gives its root directory.
    pub make: fn(&MountArgs<'_>) -> Result<InodeRef>,
}

/// Finds the inode of a path, from the current directory of the caller of `mount(2)`.
pub type LookupFn<'a> = &'a dyn Fn(&[u8]) -> Result<InodeRef>;

/// The arguments of `mount(2)` for the constructor of a file system type.
#[derive(Clone, Copy)]
pub struct MountArgs<'a> {
    /// The data string, which holds the options of the file system.
    pub data: &'a [u8],
    /// The block device of the source, for a type that is not `nodev`.
    pub dev: Option<u64>,
    /// `MS_RDONLY`: the file system does not accept changes.
    pub read_only: bool,
    /// Finds a path of the options, for a file system that uses other directories, as the
    /// layers of overlayfs. `None` gives `ENOENT` for each path.
    pub lookup: Option<LookupFn<'a>>,
}

impl MountArgs<'_> {
    /// Finds the inode of the path `path` of an option.
    pub fn lookup(&self, path: &[u8]) -> Result<InodeRef> {
        self.lookup.ok_or(Errno::ENOENT)?(path)
    }
}

impl core::fmt::Debug for MountArgs<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MountArgs")
            .field("data", &self.data)
            .field("dev", &self.dev)
            .field("read_only", &self.read_only)
            .finish_non_exhaustive()
    }
}

static TYPES: SpinLock<Vec<FsType>> = SpinLock::new(Vec::new());

/// Adds a file system type. A second type with the same name replaces the first.
pub fn register(fs: FsType) {
    let mut types = TYPES.lock();
    types.retain(|t| t.name != fs.name);
    types.push(fs);
}

/// Finds the file system type with the name `name`.
pub fn find(name: &[u8]) -> Option<FsType> {
    TYPES.lock().iter().find(|t| t.name.as_bytes() == name).copied()
}

/// The registered types, in the order of registration.
pub fn types() -> Vec<FsType> {
    TYPES.lock().clone()
}

/// A file system on a block device that a mount made, as a super block of Linux.
struct Super {
    name: &'static str,
    dev: u64,
    read_only: bool,
    root: Weak<dyn Inode>,
}

static SUPERS: SpinLock<Vec<Super>> = SpinLock::new(Vec::new());

/// Gives the root of a file system of the type `ty` for `args`. If `mounted` is true and a mount
/// made a file system of the type on the same device, the root of that file system is the result,
/// as `sget_fc` of Linux. Two mounts of a device then show the same files. Gives `EBUSY` if the
/// file system has another read only state than `args`.
///
/// # Errors
///
/// Gives the error of the constructor of the type.
pub fn get_tree(ty: FsType, args: &MountArgs<'_>, mounted: bool) -> Result<InodeRef> {
    let Some(dev) = args.dev.filter(|_| !ty.nodev) else {
        return (ty.make)(args);
    };
    {
        let mut supers = SUPERS.lock();
        supers.retain(|s| s.root.strong_count() > 0);
        if mounted
            && let Some(s) = supers.iter().find(|s| s.name == ty.name && s.dev == dev)
            && let Some(root) = s.root.upgrade()
        {
            return if s.read_only == args.read_only { Ok(root) } else { Err(Errno::EBUSY) };
        }
    }
    let root = (ty.make)(args)?;
    let mut supers = SUPERS.lock();
    supers.retain(|s| !(s.name == ty.name && s.dev == dev));
    let read_only = args.read_only;
    supers.push(Super { name: ty.name, dev, read_only, root: alloc::sync::Arc::downgrade(&root) });
    Ok(root)
}

/// Records that a remount made the file system of the type `name` on the device `dev` read only
/// or writable, so that a new mount of the device checks the new state.
pub fn set_read_only(name: &str, dev: u64, read_only: bool) {
    let mut supers = SUPERS.lock();
    for s in supers.iter_mut().filter(|s| s.name == name && s.dev == dev) {
        s.read_only = read_only;
    }
}

/// Gives the value of the option `key=value` in the comma separated data string of `mount(2)`.
pub fn option<'a>(data: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    data.split(|&b| b == b',').find_map(|opt| {
        let (k, v) = opt.split_at(opt.iter().position(|&b| b == b'=')?);
        (k == key).then_some(&v[1..])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_are_found_by_key() {
        assert_eq!(option(b"size=10m,mode=1777", b"mode"), Some(&b"1777"[..]));
        assert_eq!(option(b"size=10m,mode=1777", b"size"), Some(&b"10m"[..]));
        assert_eq!(option(b"ro,mode", b"mode"), None);
        assert_eq!(option(b"", b"mode"), None);
    }
}

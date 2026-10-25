//! The file system types that `mount` can make, as `register_filesystem` of Linux.
//!
//! The kernel registers each type at boot. `mount(2)` finds the type by its name and calls its
//! constructor, and `/proc/filesystems` shows the list.

use crate::inode::{InodeRef, Result};
use alloc::vec::Vec;
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
        self.lookup.ok_or(rk_abi::Errno::ENOENT)?(path)
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

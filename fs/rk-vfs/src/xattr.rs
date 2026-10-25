//! The extended attributes of an inode: the flags of `setxattr`, and a map of attributes for a
//! file system that keeps them in memory.

use crate::inode::Result;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use rk_abi::Errno;

/// `XATTR_CREATE` of `<linux/xattr.h>`: `setxattr` fails if the attribute exists.
pub const XATTR_CREATE: u32 = 1;
/// `XATTR_REPLACE` of `<linux/xattr.h>`: `setxattr` fails if the attribute does not exist.
pub const XATTR_REPLACE: u32 = 2;

/// The extended attributes of one inode, by name.
#[derive(Clone, Debug, Default)]
pub struct Xattrs(BTreeMap<Vec<u8>, Vec<u8>>);

impl Xattrs {
    /// Makes a map with no attributes.
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Gives the value of `name`, or `ENODATA`.
    pub fn get(&self, name: &[u8]) -> Result<Vec<u8>> {
        self.0.get(name).cloned().ok_or(Errno::ENODATA)
    }

    /// Sets `name` to `value` with the flags of `setxattr`.
    pub fn set(&mut self, name: &[u8], value: &[u8], flags: u32) -> Result<()> {
        let exists = self.0.contains_key(name);
        if flags & XATTR_CREATE != 0 && exists {
            return Err(Errno::EEXIST);
        }
        if flags & XATTR_REPLACE != 0 && !exists {
            return Err(Errno::ENODATA);
        }
        self.0.insert(name.to_vec(), value.to_vec());
        Ok(())
    }

    /// Gives the names, in the order of the bytes.
    pub fn names(&self) -> Vec<Vec<u8>> {
        self.0.keys().cloned().collect()
    }

    /// Removes `name`, or gives `ENODATA`.
    pub fn remove(&mut self, name: &[u8]) -> Result<()> {
        self.0.remove(name).map(|_| ()).ok_or(Errno::ENODATA)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flags_of_setxattr() {
        let mut x = Xattrs::new();
        assert_eq!(x.set(b"user.a", b"1", XATTR_REPLACE), Err(Errno::ENODATA));
        x.set(b"user.a", b"1", XATTR_CREATE).unwrap();
        assert_eq!(x.set(b"user.a", b"2", XATTR_CREATE), Err(Errno::EEXIST));
        x.set(b"user.a", b"2", XATTR_REPLACE).unwrap();
        x.set(b"trusted.b", b"", 0).unwrap();
        assert_eq!(x.get(b"user.a").unwrap(), b"2");
        assert_eq!(x.names(), [&b"trusted.b"[..], b"user.a"]);
        x.remove(b"user.a").unwrap();
        assert_eq!(x.remove(b"user.a"), Err(Errno::ENODATA));
        assert_eq!(x.get(b"user.a"), Err(Errno::ENODATA));
    }
}

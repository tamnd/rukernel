//! securityfs: the file system of the security modules, as security/inode.c of Linux. The init
//! system mounts it on `/sys/kernel/security`.
//!
//! The file `lsm` gives the names of the active modules. A module adds its own files with
//! [`create_file`], as `securityfs_create_file` of Linux. A file has a path below the root, and
//! the directories of the path are made from the paths of the files. There is one instance:
//! each mount shows the same files.

use super::lsm_names;
use crate::fstype::{FsType, MountArgs};
use crate::inode::{DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, mode};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::{Once, SpinLock};

/// The magic number of securityfs, `SECURITYFS_MAGIC` of `<linux/magic.h>`.
pub const SECURITYFS_MAGIC: u64 = 0x7363_6673;

/// The type of securityfs for `mount -t securityfs`.
pub const FS_TYPE: FsType = FsType { name: "securityfs", nodev: true, make: mount };

/// A file of securityfs.
#[derive(Clone, Copy)]
pub struct FileDef {
    /// The path below the root, for example `apparmor/profiles`.
    pub path: &'static str,
    /// The permission bits.
    pub perm: u32,
    /// Gives the text of the file.
    pub read: fn() -> Vec<u8>,
    /// Takes a write of the whole text, or `None` for a file that takes no write.
    pub write: Option<fn(&[u8]) -> Result<usize>>,
}

/// The text of `lsm`: the names of the active modules in order, with no new line, as
/// `lsm_read` of Linux.
fn lsm_text() -> Vec<u8> {
    lsm_names().into_bytes()
}

/// The file `lsm`, which securityfs always has.
const LSM: FileDef = FileDef { path: "lsm", perm: 0o444, read: lsm_text, write: None };

/// The files that the modules added.
static FILES: SpinLock<Vec<FileDef>> = SpinLock::new(Vec::new());

/// Adds the file `def`, as `securityfs_create_file` of Linux. A file with the same path is
/// replaced.
pub fn create_file(def: FileDef) {
    let mut files = FILES.lock();
    files.retain(|f| f.path != def.path);
    files.push(def);
}

/// Removes the file with the path `path`, as `securityfs_remove` of Linux.
pub fn remove(path: &str) {
    FILES.lock().retain(|f| f.path != path);
}

/// All the files.
fn files() -> Vec<FileDef> {
    let mut all = Vec::from([LSM]);
    all.extend(FILES.lock().iter().copied());
    all
}

/// The device of securityfs.
fn dev() -> u64 {
    static DEV: Once<u64> = Once::new();
    *DEV.call_once(crate::inode::anon_dev)
}

/// The inode number of the path `path`. The root has 1, and another path has a hash of the
/// path, so a path keeps its number.
fn ino(path: &str) -> u64 {
    if path.is_empty() {
        return 1;
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in path.as_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    (h >> 1) | 2
}

/// An inode of securityfs: a directory or a file, by its path. The root has the empty path.
struct Node {
    path: String,
}

impl Node {
    /// The file with the path of this node, or `None` for a directory.
    fn file(&self) -> Option<FileDef> {
        files().into_iter().find(|f| f.path == self.path)
    }

    /// The names of the entries of this directory and tells if each one is a directory, in the
    /// order of the files.
    fn children(&self) -> Vec<(String, bool)> {
        let mut out: Vec<(String, bool)> = Vec::new();
        for f in files() {
            let rest = if self.path.is_empty() {
                Some(f.path)
            } else {
                f.path.strip_prefix(self.path.as_str()).and_then(|r| r.strip_prefix('/'))
            };
            let Some(rest) = rest else { continue };
            let (name, dir) = match rest.split_once('/') {
                Some((name, _)) => (name, true),
                None => (rest, false),
            };
            if !out.iter().any(|(n, _)| n == name) {
                out.push((String::from(name), dir));
            }
        }
        out
    }

    fn child_path(&self, name: &str) -> String {
        if self.path.is_empty() {
            String::from(name)
        } else {
            alloc::format!("{}/{name}", self.path)
        }
    }
}

impl Inode for Node {
    fn metadata(&self) -> Metadata {
        let (kind, perm, nlink) = match self.file() {
            Some(f) => (mode::S_IFREG, f.perm, 1),
            None => (mode::S_IFDIR, 0o755, 2),
        };
        Metadata {
            dev: dev(),
            ino: ino(&self.path),
            mode: kind | perm,
            nlink,
            ..Metadata::default()
        }
    }

    fn set_attr(&self, _attr: &SetAttr) -> Result<()> {
        Err(Errno::EPERM)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let f = self.file().ok_or(Errno::EISDIR)?;
        let text = (f.read)();
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(text.len());
        let n = buf.len().min(text.len() - start);
        buf[..n].copy_from_slice(&text[start..start + n]);
        Ok(n)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        let f = self.file().ok_or(Errno::EISDIR)?;
        let write = f.write.ok_or(Errno::EINVAL)?;
        if offset != 0 {
            return Err(Errno::EINVAL);
        }
        write(buf)
    }

    fn lookup(&self, name: &[u8]) -> Result<InodeRef> {
        if self.file().is_some() {
            return Err(Errno::ENOTDIR);
        }
        let name = core::str::from_utf8(name).map_err(|_| Errno::ENOENT)?;
        if !self.children().iter().any(|(n, _)| n == name) {
            return Err(Errno::ENOENT);
        }
        Ok(Arc::new(Self { path: self.child_path(name) }))
    }

    fn read_dir(&self, pos: u64) -> Result<Option<(DirEntry, u64)>> {
        if self.file().is_some() {
            return Err(Errno::ENOTDIR);
        }
        let entry = match pos {
            0 => DirEntry { ino: ino(&self.path), kind: FileType::Directory, name: b".".to_vec() },
            1 => DirEntry { ino: 1, kind: FileType::Directory, name: b"..".to_vec() },
            _ => {
                let children = self.children();
                let Some((name, dir)) = usize::try_from(pos - 2).ok().and_then(|i| children.get(i))
                else {
                    return Ok(None);
                };
                let kind = if *dir { FileType::Directory } else { FileType::Regular };
                DirEntry { ino: ino(&self.child_path(name)), kind, name: name.as_bytes().to_vec() }
            }
        };
        Ok(Some((entry, pos + 1)))
    }

    fn fs_id(&self) -> u64 {
        dev()
    }

    fn fs_magic(&self) -> u64 {
        SECURITYFS_MAGIC
    }
}

/// Gives the root of securityfs. Each mount shows the same files, as `get_tree_single` of Linux.
fn mount(_args: &MountArgs<'_>) -> Result<InodeRef> {
    static ROOT: Once<InodeRef> = Once::new();
    Ok(ROOT.call_once(|| Arc::new(Node { path: String::new() })).clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(inode: &InodeRef) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let n = inode.read_at(0, &mut buf).unwrap();
        buf[..n].to_vec()
    }

    fn names(dir: &InodeRef) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut pos = 0;
        while let Some((e, next)) = dir.read_dir(pos).unwrap() {
            out.push(e.name);
            pos = next;
        }
        out
    }

    fn hello() -> Vec<u8> {
        b"hello\n".to_vec()
    }

    #[test]
    fn the_root_has_lsm_and_the_files_of_the_modules() {
        let root =
            mount(&MountArgs { data: b"", dev: None, read_only: false, lookup: None }).unwrap();
        assert_eq!(root.fs_magic(), SECURITYFS_MAGIC);
        assert!(root.metadata().is_dir());
        let lsm = root.lookup(b"lsm").unwrap();
        assert_eq!(lsm.metadata().mode, mode::S_IFREG | 0o444);
        assert_eq!(read(&lsm), b"capability");
        assert_eq!(lsm.write_at(0, b"x"), Err(Errno::EINVAL));
        create_file(FileDef { path: "test/a/hello", perm: 0o400, read: hello, write: None });
        assert_eq!(names(&root), [&b"."[..], b"..", b"lsm", b"test"]);
        let a = root.lookup(b"test").unwrap().lookup(b"a").unwrap();
        assert!(a.metadata().is_dir());
        assert_eq!(read(&a.lookup(b"hello").unwrap()), b"hello\n");
        assert_eq!(root.lookup(b"nothing").err(), Some(Errno::ENOENT));
        remove("test/a/hello");
        assert_eq!(names(&root), [&b"."[..], b"..", b"lsm"]);
    }
}

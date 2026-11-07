//! securityfs: the file system of the security modules, as security/inode.c of Linux. The init
//! system mounts it on `/sys/kernel/security`.
//!
//! The file `lsm` gives the names of the active modules. A module adds its own files with
//! [`create_file`], as `securityfs_create_file` of Linux. A file has a path below the root, and
//! the directories of the path are made from the paths of the files. There is one instance:
//! each mount shows the same files.
//!
//! A module whose files change, as the profiles of AppArmor, adds a [`Tree`] with [`add_tree`].
//! The tree gives its entries when a process looks at them. A file of a tree takes each write
//! whole, in one call.

use super::lsm_names;
use crate::file::{File, FileOps};
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

/// An entry of a [`Tree`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    /// A directory.
    Dir,
    /// A regular file with its permission bits.
    File(u32),
    /// A symbolic link with its permission bits and its target.
    Link(u32, Vec<u8>),
}

/// A directory of securityfs whose entries a module makes when a process looks at them, as the
/// tree of AppArmor in Linux, whose directories come and go with the profiles. A path of the
/// tree is below its top directory, and the top directory has the empty path.
pub trait Tree: Send + Sync {
    /// The entry at `path`, or `None` if there is no such entry.
    fn entry(&self, path: &str) -> Option<Entry>;

    /// The names and the entries of the directory at `path`, in order.
    fn list(&self, path: &str) -> Vec<(String, Entry)>;

    /// Checks an open of the file at `path` with the flags `flags`.
    ///
    /// # Errors
    ///
    /// Gives the error of the module, for example `EACCES`. The default allows the open.
    fn open(&self, _path: &str, _flags: u32) -> Result<()> {
        Ok(())
    }

    /// Gives the text of the file at `path`. An open file reads the text of its first read.
    ///
    /// # Errors
    ///
    /// Gives the error of the module, for example `EACCES`.
    fn read(&self, path: &str) -> Result<Vec<u8>>;

    /// Takes the whole write `data` at `offset` to the file at `path`. Gives the count that it
    /// took.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` by default, for a file that takes no write.
    fn write(&self, _path: &str, _offset: u64, _data: &[u8]) -> Result<usize> {
        Err(Errno::EINVAL)
    }
}

/// The trees, each with the name of its top directory in the root.
static TREES: SpinLock<Vec<(&'static str, &'static dyn Tree)>> = SpinLock::new(Vec::new());

/// Adds the tree `tree` as the directory `name` of the root, as `securityfs_create_dir` of Linux
/// with the files below it. A tree with the same name is replaced.
pub fn add_tree(name: &'static str, tree: &'static dyn Tree) {
    let mut trees = TREES.lock();
    trees.retain(|t| t.0 != name);
    trees.push((name, tree));
}

/// Removes the tree with the name `name`.
pub fn remove_tree(name: &str) {
    TREES.lock().retain(|t| t.0 != name);
}

/// The tree that has `path`, and the path below the top of the tree.
fn tree_of(path: &str) -> Option<(&'static dyn Tree, &str)> {
    let (top, rest) = path.split_once('/').unwrap_or((path, ""));
    TREES.lock().iter().find(|t| t.0 == top).map(|t| (t.1, rest))
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
        if self.path.is_empty() {
            out.extend(TREES.lock().iter().map(|t| (String::from(t.0), true)));
        }
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

    /// The tree of this node, the path in the tree and the entry there. An entry that went
    /// away is a file that no process can read, as a dentry of Linux that a module removed.
    fn tree_entry(&self) -> Option<(&'static dyn Tree, &str, Entry)> {
        let (tree, rest) = tree_of(&self.path)?;
        Some((tree, rest, tree.entry(rest).unwrap_or(Entry::File(0))))
    }
}

/// An open file of a [`Tree`]. It keeps the text of its first read, as a `seq_file` of Linux.
struct TreeFile {
    tree: &'static dyn Tree,
    path: String,
    text: SpinLock<Option<Arc<Vec<u8>>>>,
}

impl TreeFile {
    fn text(&self) -> Result<Arc<Vec<u8>>> {
        let mut text = self.text.lock();
        if let Some(t) = &*text {
            return Ok(t.clone());
        }
        let t = Arc::new(self.tree.read(&self.path)?);
        *text = Some(t.clone());
        Ok(t)
    }
}

/// Copies the part of `text` at `offset` to `buf`.
fn copy_at(text: &[u8], offset: u64, buf: &mut [u8]) -> usize {
    let start = usize::try_from(offset).unwrap_or(usize::MAX).min(text.len());
    let n = buf.len().min(text.len() - start);
    buf[..n].copy_from_slice(&text[start..start + n]);
    n
}

impl FileOps for TreeFile {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        let n = self.read_at(file, file.pos(), buf)?;
        file.set_pos(file.pos() + n as u64);
        Ok(n)
    }

    fn read_at(&self, _file: &File, offset: u64, buf: &mut [u8]) -> Result<usize> {
        Ok(copy_at(&self.text()?, offset, buf))
    }

    // A write does not move the position, as the files of AppArmor in Linux.
    fn write(&self, file: &File, buf: &[u8]) -> Result<usize> {
        self.tree.write(&self.path, file.pos(), buf)
    }

    fn write_at(&self, _file: &File, offset: u64, buf: &[u8]) -> Result<usize> {
        self.tree.write(&self.path, offset, buf)
    }

    fn seekable(&self) -> bool {
        true
    }

    fn whole_write(&self) -> bool {
        true
    }
}

impl Inode for Node {
    fn metadata(&self) -> Metadata {
        let (kind, perm, nlink, size) = match (self.tree_entry(), self.file()) {
            (Some((_, _, Entry::Dir)), _) | (None, None) => (mode::S_IFDIR, 0o755, 2, 0),
            (Some((_, _, Entry::File(perm))), _) => (mode::S_IFREG, perm, 1, 0),
            (Some((_, _, Entry::Link(perm, to))), _) => (mode::S_IFLNK, perm, 1, to.len() as u64),
            (None, Some(f)) => (mode::S_IFREG, f.perm, 1, 0),
        };
        Metadata {
            dev: dev(),
            ino: ino(&self.path),
            mode: kind | perm,
            nlink,
            size,
            ..Metadata::default()
        }
    }

    fn set_attr(&self, attr: &SetAttr) -> Result<()> {
        // The truncate of an open with `O_TRUNC` has no effect on a file of a tree, as
        // `simple_setattr` of Linux on a file with no pages.
        let truncate = SetAttr { size: attr.size, ..SetAttr::default() };
        match self.tree_entry() {
            Some((_, _, Entry::File(_))) if *attr == truncate => Ok(()),
            _ => Err(Errno::EPERM),
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if let Some((tree, rest, entry)) = self.tree_entry() {
            let Entry::File(_) = entry else { return Err(Errno::EISDIR) };
            return Ok(copy_at(&tree.read(rest)?, offset, buf));
        }
        let f = self.file().ok_or(Errno::EISDIR)?;
        Ok(copy_at(&(f.read)(), offset, buf))
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        if let Some((tree, rest, entry)) = self.tree_entry() {
            let Entry::File(_) = entry else { return Err(Errno::EISDIR) };
            return tree.write(rest, offset, buf);
        }
        let f = self.file().ok_or(Errno::EISDIR)?;
        let write = f.write.ok_or(Errno::EINVAL)?;
        if offset != 0 {
            return Err(Errno::EINVAL);
        }
        write(buf)
    }

    fn read_link(&self) -> Result<Vec<u8>> {
        match self.tree_entry() {
            Some((_, _, Entry::Link(_, to))) => Ok(to),
            _ => Err(Errno::EINVAL),
        }
    }

    fn open_file(&self, flags: u32) -> Option<Result<Arc<dyn FileOps>>> {
        let (tree, rest, Entry::File(_)) = self.tree_entry()? else { return None };
        if let Err(e) = tree.open(rest, flags) {
            return Some(Err(e));
        }
        let path = String::from(rest);
        Some(Ok(Arc::new(TreeFile { tree, path, text: SpinLock::new(None) })))
    }

    fn lookup(&self, name: &[u8]) -> Result<InodeRef> {
        let name = core::str::from_utf8(name).map_err(|_| Errno::ENOENT)?;
        if let Some((tree, rest, entry)) = self.tree_entry() {
            if entry != Entry::Dir {
                return Err(Errno::ENOTDIR);
            }
            let child =
                if rest.is_empty() { String::from(name) } else { alloc::format!("{rest}/{name}") };
            if name.contains('/') || tree.entry(&child).is_none() {
                return Err(Errno::ENOENT);
            }
            return Ok(Arc::new(Self { path: self.child_path(name) }));
        }
        if self.file().is_some() {
            return Err(Errno::ENOTDIR);
        }
        if !self.children().iter().any(|(n, _)| n == name) {
            return Err(Errno::ENOENT);
        }
        Ok(Arc::new(Self { path: self.child_path(name) }))
    }

    fn read_dir(&self, pos: u64) -> Result<Option<(DirEntry, u64)>> {
        let tree = self.tree_entry();
        if matches!(tree, Some((_, _, ref e)) if *e != Entry::Dir)
            || (tree.is_none() && self.file().is_some())
        {
            return Err(Errno::ENOTDIR);
        }
        let entry = match pos {
            0 => DirEntry { ino: ino(&self.path), kind: FileType::Directory, name: b".".to_vec() },
            1 => DirEntry { ino: 1, kind: FileType::Directory, name: b"..".to_vec() },
            _ => {
                let children: Vec<(String, FileType)> = match tree {
                    Some((tree, rest, _)) => tree
                        .list(rest)
                        .into_iter()
                        .map(|(name, e)| {
                            let kind = match e {
                                Entry::Dir => FileType::Directory,
                                Entry::File(_) => FileType::Regular,
                                Entry::Link(..) => FileType::Symlink,
                            };
                            (name, kind)
                        })
                        .collect(),
                    None => self
                        .children()
                        .into_iter()
                        .map(|(name, dir)| {
                            (name, if dir { FileType::Directory } else { FileType::Regular })
                        })
                        .collect(),
                };
                let Some((name, kind)) =
                    usize::try_from(pos - 2).ok().and_then(|i| children.get(i))
                else {
                    return Ok(None);
                };
                DirEntry {
                    ino: ino(&self.child_path(name)),
                    kind: *kind,
                    name: name.as_bytes().to_vec(),
                }
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
        a_tree_gives_its_entries_and_takes_a_whole_write();
    }

    /// A tree with the directory `d`, the file `d/f` that keeps the last write, and the link
    /// `l` to `d`.
    struct Demo(SpinLock<Vec<u8>>);

    impl Tree for Demo {
        fn entry(&self, path: &str) -> Option<Entry> {
            match path {
                "" | "d" => Some(Entry::Dir),
                "d/f" => Some(Entry::File(0o640)),
                "l" => Some(Entry::Link(0o777, b"d".to_vec())),
                _ => None,
            }
        }

        fn list(&self, path: &str) -> Vec<(String, Entry)> {
            ["d", "l", "d/f"]
                .into_iter()
                .filter_map(|p| {
                    let name = match path {
                        "" => p.strip_prefix(""),
                        dir => p.strip_prefix(dir).and_then(|r| r.strip_prefix('/')),
                    }?;
                    if name.contains('/') {
                        None
                    } else {
                        Some((String::from(name), self.entry(p)?))
                    }
                })
                .collect()
        }

        fn read(&self, _path: &str) -> Result<Vec<u8>> {
            Ok(self.0.lock().clone())
        }

        fn write(&self, _path: &str, offset: u64, data: &[u8]) -> Result<usize> {
            if offset != 0 {
                return Err(Errno::ESPIPE);
            }
            *self.0.lock() = data.to_vec();
            Ok(data.len())
        }
    }

    static DEMO: Demo = Demo(SpinLock::new(Vec::new()));

    /// A part of the test below, which runs after the files, as the root is shared.
    fn a_tree_gives_its_entries_and_takes_a_whole_write() {
        let root =
            mount(&MountArgs { data: b"", dev: None, read_only: false, lookup: None }).unwrap();
        add_tree("demo", &DEMO);
        let demo = root.lookup(b"demo").unwrap();
        assert!(demo.metadata().is_dir());
        assert_eq!(names(&demo), [&b"."[..], b"..", b"d", b"l"]);
        let l = demo.lookup(b"l").unwrap();
        assert_eq!(l.metadata().mode, mode::S_IFLNK | 0o777);
        assert_eq!(l.read_link().unwrap(), b"d");
        let d = demo.lookup(b"d").unwrap();
        assert_eq!(names(&d), [&b"."[..], b"..", b"f"]);
        let f = d.lookup(b"f").unwrap();
        assert_eq!(f.metadata().mode, mode::S_IFREG | 0o640);
        assert_eq!(f.lookup(b"x").err(), Some(Errno::ENOTDIR));
        assert_eq!(demo.lookup(b"x").err(), Some(Errno::ENOENT));
        let ops = f.open_file(0).unwrap().unwrap();
        assert!(ops.whole_write());
        assert_eq!(f.write_at(0, b"policy"), Ok(6));
        assert_eq!(f.write_at(1, b"x"), Err(Errno::ESPIPE));
        assert_eq!(read(&f), b"policy");
        let truncate = SetAttr { size: Some(0), ..SetAttr::default() };
        assert_eq!(f.set_attr(&truncate), Ok(()));
        assert_eq!(d.set_attr(&truncate), Err(Errno::EPERM));
        remove_tree("demo");
        assert_eq!(root.lookup(b"demo").err(), Some(Errno::ENOENT));
    }
}

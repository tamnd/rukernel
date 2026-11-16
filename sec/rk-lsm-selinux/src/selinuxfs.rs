//! selinuxfs, the file system of SELinux, as security/selinux/selinuxfs.c of Linux. The init
//! system mounts it on `/sys/fs/selinux`.
//!
//! `load_policy` writes the binary policy to `load`, and `setenforce` writes 0 or 1 to
//! `enforce`. The other files give the state of the module and of the policy. There is one
//! instance: each mount shows the same files. The inode numbers are those of Linux, so that
//! the files keep their numbers from one mount to the next.

use crate::{deny_unknown, enforcing, policy, policydb, reject_unknown};
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use rk_abi::Errno;
use rk_frame::sync::Once;
use rk_vfs::file::{File, FileOps};
use rk_vfs::fstype::{FsType, MountArgs};
use rk_vfs::inode::{DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, mode};

/// The magic number of selinuxfs, `SELINUX_MAGIC` of `<linux/magic.h>`.
pub const SELINUX_MAGIC: u64 = 0xf97c_ff8c;

/// The type of selinuxfs for `mount -t selinuxfs`.
pub const FS_TYPE: FsType = FsType { name: "selinuxfs", nodev: true, make: mount };

/// The inode number of the directory `policy_capabilities`. Linux gives the numbers after
/// `SEL_INO_NEXT` (22) to the directories in the order of `sel_fill_super`: `booleans`,
/// `null`, `avc`, `ss`, `initial_contexts`, `class` and `policy_capabilities`.
const POLICYCAP_DIR_INO: u64 = 28;

/// The bit of the inode numbers of the files of `policy_capabilities`,
/// `SEL_POLICYCAP_INO_OFFSET` of Linux.
const POLICYCAP_INO_OFFSET: u64 = 0x0800_0000;

/// The largest write to a file other than `load`, `PAGE_SIZE` of Linux.
const PAGE_SIZE: usize = 4096;

/// Takes a write of the whole text of a file and gives the number of bytes that it used.
type WriteFn = fn(&[u8]) -> Result<usize>;

/// A file of the root.
#[derive(Clone, Copy)]
struct FileDef {
    /// The name.
    name: &'static str,
    /// The inode number, from `enum sel_inos` of Linux.
    ino: u64,
    /// The permission bits.
    perm: u32,
    /// Gives the text of the file, or `None` for a file that a process cannot read.
    read: Option<fn() -> Result<Vec<u8>>>,
    /// Takes a write of the whole text, or `None` for a file that takes no write.
    write: Option<WriteFn>,
}

/// The files of the root, in the order of `selinux_files` of Linux.
const FILES: [FileDef; 9] = [
    FileDef { name: "load", ino: 3, perm: 0o600, read: None, write: Some(write_load) },
    FileDef {
        name: "enforce",
        ino: 4,
        perm: 0o644,
        read: Some(read_enforce),
        write: Some(write_enforce),
    },
    FileDef { name: "policyvers", ino: 10, perm: 0o444, read: Some(read_policyvers), write: None },
    FileDef { name: "mls", ino: 12, perm: 0o444, read: Some(read_mls), write: None },
    FileDef {
        name: "checkreqprot",
        ino: 15,
        perm: 0o644,
        read: Some(read_checkreqprot),
        write: Some(write_checkreqprot),
    },
    FileDef { name: "reject_unknown", ino: 17, perm: 0o444, read: Some(read_reject), write: None },
    FileDef { name: "deny_unknown", ino: 18, perm: 0o444, read: Some(read_deny), write: None },
    FileDef { name: "status", ino: 19, perm: 0o444, read: Some(read_status), write: None },
    FileDef { name: "policy", ino: 20, perm: 0o444, read: Some(read_policy), write: None },
];

/// Formats a number as `"%d"`, with no new line, as most files of selinuxfs.
fn number(v: impl core::fmt::Display) -> Result<Vec<u8>> {
    Ok(format!("{v}").into_bytes())
}

fn read_enforce() -> Result<Vec<u8>> {
    number(u8::from(enforcing()))
}

fn read_policyvers() -> Result<Vec<u8>> {
    number(policydb::VERSION_MAX)
}

fn read_mls() -> Result<Vec<u8>> {
    number(u8::from(crate::mls_enabled()))
}

fn read_checkreqprot() -> Result<Vec<u8>> {
    number(0)
}

fn read_reject() -> Result<Vec<u8>> {
    number(u8::from(reject_unknown()))
}

fn read_deny() -> Result<Vec<u8>> {
    number(u8::from(deny_unknown()))
}

fn read_status() -> Result<Vec<u8>> {
    Ok(crate::status().to_vec())
}

/// Gives the binary policy, as `sel_open_policy` of Linux, which fails before the first load.
fn read_policy() -> Result<Vec<u8>> {
    policy().map(|p| p.data.clone()).ok_or(Errno::EINVAL)
}

/// Loads a policy, as `sel_write_load` of Linux.
fn write_load(data: &[u8]) -> Result<usize> {
    if data.is_empty() {
        return Err(Errno::EINVAL);
    }
    crate::load_policy(data).inspect_err(|_| {
        rk_frame::println!("SELinux: failed to load policy");
    })?;
    Ok(data.len())
}

/// Parses a number as `sscanf("%d")`: spaces, a sign and decimal digits, and the text after
/// the digits does not count.
fn scan_int(data: &[u8]) -> Option<i64> {
    let text = core::str::from_utf8(data).ok()?.trim_start();
    let (neg, text) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let end = text.bytes().position(|b| !b.is_ascii_digit()).unwrap_or(text.len());
    let v: i64 = text[..end].parse().ok()?;
    Some(if neg { -v } else { v })
}

/// Changes the mode, as `sel_write_enforce` of Linux.
fn write_enforce(data: &[u8]) -> Result<usize> {
    if data.len() >= PAGE_SIZE {
        return Err(Errno::ENOMEM);
    }
    let v = scan_int(data).ok_or(Errno::EINVAL)?;
    crate::set_enforcing(v != 0);
    Ok(data.len())
}

/// Takes a write to `checkreqprot` and does nothing, as Linux, which no longer supports a
/// change of this value.
fn write_checkreqprot(data: &[u8]) -> Result<usize> {
    static TOLD: AtomicBool = AtomicBool::new(false);
    if !TOLD.swap(true, Ordering::Relaxed) {
        let (pid, comm) = crate::current();
        rk_frame::println!(
            "SELinux: {} ({pid}) wrote to checkreqprot. This is no longer supported.",
            alloc::string::String::from_utf8_lossy(&comm)
        );
    }
    Ok(data.len())
}

/// The device of selinuxfs.
fn dev() -> u64 {
    static DEV: Once<u64> = Once::new();
    *DEV.call_once(rk_vfs::inode::anon_dev)
}

/// An inode of selinuxfs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Node {
    /// The root.
    Root,
    /// A file of the root, by its index in [`FILES`].
    File(usize),
    /// The directory `policy_capabilities`.
    CapDir,
    /// A file of `policy_capabilities`, by the number of the capability.
    Cap(usize),
}

impl Node {
    /// The inode number.
    fn ino(self) -> u64 {
        match self {
            Self::Root => 1,
            Self::File(i) => FILES[i].ino,
            Self::CapDir => POLICYCAP_DIR_INO,
            Self::Cap(i) => i as u64 | POLICYCAP_INO_OFFSET,
        }
    }

    /// The entries of this directory.
    fn children(self) -> Vec<(&'static str, Self)> {
        match self {
            Self::Root => FILES
                .iter()
                .enumerate()
                .map(|(i, f)| (f.name, Self::File(i)))
                .chain([("policy_capabilities", Self::CapDir)])
                .collect(),
            Self::CapDir => {
                crate::POLICYCAP_NAMES.iter().enumerate().map(|(i, &n)| (n, Self::Cap(i))).collect()
            }
            _ => Vec::new(),
        }
    }

    fn is_dir(self) -> bool {
        matches!(self, Self::Root | Self::CapDir)
    }

    /// The text of this file.
    fn text(self) -> Result<Vec<u8>> {
        match self {
            Self::File(i) => FILES[i].read.ok_or(Errno::EINVAL)?(),
            Self::Cap(i) => number(u8::from(policy().is_some_and(|p| p.db.policycap(i as u32)))),
            _ => Err(Errno::EISDIR),
        }
    }

    /// Takes the whole write `data` at `offset`. The files of selinuxfs take no partial write.
    fn write(self, offset: u64, data: &[u8]) -> Result<usize> {
        let write = match self {
            Self::File(i) => FILES[i].write.ok_or(Errno::EINVAL)?,
            Self::Cap(_) => return Err(Errno::EINVAL),
            _ => return Err(Errno::EISDIR),
        };
        if offset != 0 {
            return Err(Errno::EINVAL);
        }
        write(data)
    }
}

/// Copies the part of `text` at `offset` to `buf`.
fn copy_at(text: &[u8], offset: u64, buf: &mut [u8]) -> usize {
    let start = usize::try_from(offset).unwrap_or(usize::MAX).min(text.len());
    let n = buf.len().min(text.len() - start);
    buf[..n].copy_from_slice(&text[start..start + n]);
    n
}

/// An open file of selinuxfs. A write does not move the position, as Linux.
struct SelFile(Node);

impl FileOps for SelFile {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        let n = self.read_at(file, file.pos(), buf)?;
        file.set_pos(file.pos() + n as u64);
        Ok(n)
    }

    fn read_at(&self, _file: &File, offset: u64, buf: &mut [u8]) -> Result<usize> {
        Ok(copy_at(&self.0.text()?, offset, buf))
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize> {
        self.0.write(file.pos(), buf)
    }

    fn write_at(&self, _file: &File, offset: u64, buf: &[u8]) -> Result<usize> {
        self.0.write(offset, buf)
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
        let (kind, perm, nlink) = match *self {
            Self::Root | Self::CapDir => (mode::S_IFDIR, 0o755, 2),
            Self::File(i) => (mode::S_IFREG, FILES[i].perm, 1),
            Self::Cap(_) => (mode::S_IFREG, 0o444, 1),
        };
        // `status` has the size of its structure, and `policy` the size of the policy, as
        // the inodes of Linux after an open.
        let size = match *self {
            Self::File(i) if FILES[i].name == "status" => 20,
            Self::File(i) if FILES[i].name == "policy" => {
                policy().map_or(0, |p| p.data.len() as u64)
            }
            _ => 0,
        };
        Metadata {
            dev: dev(),
            ino: self.ino(),
            mode: kind | perm,
            nlink,
            size,
            ..Metadata::default()
        }
    }

    fn set_attr(&self, attr: &SetAttr) -> Result<()> {
        // The truncate of an open with `O_TRUNC` has no effect, as `simple_setattr` of Linux on
        // a file with no pages.
        let truncate = SetAttr { size: attr.size, ..SetAttr::default() };
        if !self.is_dir() && *attr == truncate {
            return Ok(());
        }
        Err(Errno::EPERM)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        Ok(copy_at(&self.text()?, offset, buf))
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        self.write(offset, buf)
    }

    fn open_file(&self, _flags: u32) -> Option<Result<Arc<dyn FileOps>>> {
        if self.is_dir() {
            return None;
        }
        Some(Ok(Arc::new(SelFile(*self))))
    }

    fn lookup(&self, name: &[u8]) -> Result<InodeRef> {
        if !self.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let node = self.children().into_iter().find(|(n, _)| n.as_bytes() == name);
        Ok(Arc::new(node.ok_or(Errno::ENOENT)?.1))
    }

    fn read_dir(&self, pos: u64) -> Result<Option<(DirEntry, u64)>> {
        if !self.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let entry = match pos {
            0 => DirEntry { ino: self.ino(), kind: FileType::Directory, name: b".".to_vec() },
            1 => DirEntry { ino: 1, kind: FileType::Directory, name: b"..".to_vec() },
            _ => {
                let children = self.children();
                let Some(&(name, node)) =
                    usize::try_from(pos - 2).ok().and_then(|i| children.get(i))
                else {
                    return Ok(None);
                };
                let kind = if node.is_dir() { FileType::Directory } else { FileType::Regular };
                DirEntry { ino: node.ino(), kind, name: name.as_bytes().to_vec() }
            }
        };
        Ok(Some((entry, pos + 1)))
    }

    fn fs_id(&self) -> u64 {
        dev()
    }

    fn fs_magic(&self) -> u64 {
        SELINUX_MAGIC
    }
}

/// Gives the root of selinuxfs. Each mount shows the same files, as `get_tree_single` of Linux.
fn mount(_args: &MountArgs<'_>) -> Result<InodeRef> {
    static ROOT: Once<InodeRef> = Once::new();
    Ok(ROOT.call_once(|| Arc::new(Node::Root)).clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(inode: &InodeRef) -> Result<Vec<u8>> {
        let mut buf = alloc::vec![0u8; 1 << 16];
        let n = inode.read_at(0, &mut buf)?;
        Ok(buf[..n].to_vec())
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

    fn args() -> MountArgs<'static> {
        MountArgs { data: b"", dev: None, read_only: false, lookup: None }
    }

    #[test]
    fn the_root_has_the_files_of_linux() {
        let root = mount(&args()).unwrap();
        assert_eq!(root.fs_magic(), SELINUX_MAGIC);
        assert!(root.metadata().is_dir());
        let all = names(&root);
        assert_eq!(all.len(), 2 + FILES.len() + 1);
        assert_eq!(&all[2..4], [&b"load"[..], b"enforce"]);
        let load = root.lookup(b"load").unwrap();
        assert_eq!(load.metadata().mode, mode::S_IFREG | 0o600);
        assert_eq!(load.metadata().ino, 3);
        assert_eq!(read(&load), Err(Errno::EINVAL));
        let vers = root.lookup(b"policyvers").unwrap();
        assert_eq!(read(&vers).unwrap(), b"35");
        assert_eq!(vers.write_at(0, b"1"), Err(Errno::EINVAL));
        assert_eq!(root.lookup(b"nothing").err(), Some(Errno::ENOENT));
        let status = root.lookup(b"status").unwrap();
        assert_eq!(status.metadata().size, 20);
        assert_eq!(read(&status).unwrap().len(), 20);
        let check = root.lookup(b"checkreqprot").unwrap();
        assert_eq!(read(&check).unwrap(), b"0");
        let caps = root.lookup(b"policy_capabilities").unwrap();
        assert_eq!(names(&caps).len(), 2 + crate::POLICYCAP_NAMES.len());
        let open_perms = caps.lookup(b"open_perms").unwrap();
        assert_eq!(open_perms.metadata().ino, 1 | POLICYCAP_INO_OFFSET);
        assert_eq!(open_perms.lookup(b"x").err(), Some(Errno::ENOTDIR));
        assert!(root.lookup(b"enforce").unwrap().open_file(0).unwrap().unwrap().whole_write());
        assert_eq!(scan_int(b" -12abc"), Some(-12));
        assert_eq!(scan_int(b"x"), None);
    }

    #[test]
    fn a_load_through_the_file_sets_the_policy() {
        let root = mount(&args()).unwrap();
        let load = root.lookup(b"load").unwrap();
        assert_eq!(load.write_at(0, b""), Err(Errno::EINVAL));
        assert_eq!(load.write_at(0, b"not a policy"), Err(Errno::EINVAL));
        let data = include_bytes!("../tests/rk_test.33.bin");
        assert_eq!(load.write_at(1, data), Err(Errno::EINVAL));
        assert_eq!(load.write_at(0, data), Ok(data.len()));
        assert_eq!(read(&root.lookup(b"mls").unwrap()).unwrap(), b"1");
        assert_eq!(read(&root.lookup(b"deny_unknown").unwrap()).unwrap(), b"1");
        assert_eq!(read(&root.lookup(b"reject_unknown").unwrap()).unwrap(), b"0");
        let pol = root.lookup(b"policy").unwrap();
        assert!(pol.metadata().size > 0);
        let caps = root.lookup(b"policy_capabilities").unwrap();
        assert_eq!(read(&caps.lookup(b"open_perms").unwrap()).unwrap(), b"1");
        assert_eq!(read(&caps.lookup(b"cgroup_seclabel").unwrap()).unwrap(), b"0");
        let enforce = root.lookup(b"enforce").unwrap();
        assert_eq!(enforce.write_at(0, b"x"), Err(Errno::EINVAL));
        assert_eq!(enforce.write_at(0, &[b'1'; PAGE_SIZE]), Err(Errno::ENOMEM));
    }
}

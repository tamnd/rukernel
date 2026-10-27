//! cgroup2: the file system of the cgroup hierarchy, for `mount -t cgroup2`.
//!
//! rk-cgroup keeps the hierarchy and the values of the files. This crate shows the hierarchy as
//! directories, and each cgroup has the files of its controllers. `mkdir` makes a cgroup and
//! `rmdir` removes it. A write of `cgroup.procs` moves a process, and the writes of the other
//! files go to rk-cgroup. Each `write` is one command, as in Linux, so the offset has no effect.
//!
//! A mount shows the hierarchy from the root of the cgroup namespace of the process that mounts
//! it. All the mounts show the same cgroups.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
#[path = "kernel.rs"]
mod procs;
#[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[path = "host.rs"]
mod procs;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_cgroup::{CgId, FILES, psi::Trigger};
use rk_frame::sync::Once;
use rk_vfs::fstype::{FsType, MountArgs};
use rk_vfs::inode::mode;
use rk_vfs::{DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, now};

/// The magic number of cgroup2, `CGROUP2_SUPER_MAGIC` of `<linux/magic.h>`.
pub const CGROUP2_MAGIC: u64 = 0x6367_7270;

/// The file system type of cgroup2, for `mount -t cgroup2`.
pub const FS_TYPE: FsType = FsType { name: "cgroup2", nodev: true, make: mount };

/// The block size that `stat` gives for a file.
const BLOCK_SIZE: u32 = 4096;

/// The bits of the inode number below the ID of the cgroup. The number of a directory has 0
/// there, and the number of a file has its place in the list of files plus 1.
const INO_SHIFT: u32 = 8;

/// Makes the root of a mount: the root of the cgroup namespace of the caller. cgroup2 takes the
/// options `nsdelegate` and others, but they have no effect here.
fn mount(_args: &MountArgs<'_>) -> Result<InodeRef> {
    Ok(Arc::new(Node { id: procs::namespace_root(), file: None }))
}

/// The device of cgroup2. All the mounts show the same files, so they have one device.
fn dev() -> u64 {
    static DEV: Once<u64> = Once::new();
    *DEV.call_once(rk_vfs::anon_dev)
}

/// Gives the cgroup of a directory of cgroup2, for `CLONE_INTO_CGROUP`. Gives `None` for
/// another inode, or for a cgroup that was removed.
pub fn cgroup_of(inode: &InodeRef) -> Option<CgId> {
    if inode.fs_magic() != CGROUP2_MAGIC {
        return None;
    }
    let m = inode.metadata();
    if m.mode & mode::S_IFMT != mode::S_IFDIR {
        return None;
    }
    let id = CgId::try_from(m.ino >> INO_SHIFT).ok()?;
    rk_cgroup::with(|h| h.exists(id)).then_some(id)
}

/// The place of the file `name` in the list of files, plus 1. 0 is for the directory.
fn file_index(name: &str) -> u64 {
    FILES.iter().position(|f| f.name == name).unwrap_or(FILES.len()) as u64 + 1
}

/// An inode of cgroup2: the directory of the cgroup `id`, or its file `file`.
struct Node {
    id: CgId,
    file: Option<&'static str>,
}

impl Node {
    /// The inode number of the cgroup `id`, or of its file `file`.
    fn ino(id: CgId, file: Option<&str>) -> u64 {
        u64::from(id) << INO_SHIFT | file.map_or(0, file_index)
    }

    /// Gives an error if the cgroup was removed. A file that is open after `rmdir` gives
    /// `ENODEV`, as in Linux.
    fn live(&self) -> Result<()> {
        if rk_cgroup::with(|h| h.exists(self.id)) { Ok(()) } else { Err(Errno::ENODEV) }
    }

    /// The text of the file `name`.
    fn text(&self, name: &str) -> Result<String> {
        self.live()?;
        match name {
            "cgroup.procs" => Ok(lines(&procs::processes(self.id))),
            "cgroup.threads" => Ok(lines(&procs::threads(self.id))),
            _ => {
                let t = rk_cgroup::now();
                rk_cgroup::with(|h| h.read(self.id, name, t))
            }
        }
    }

    /// Does the write of `data` to the file `name`.
    fn command(&self, name: &str, data: &[u8]) -> Result<()> {
        self.live()?;
        match name {
            "cgroup.procs" => procs::move_process(self.id, parse_id(data)?),
            "cgroup.threads" => procs::move_thread(self.id, parse_id(data)?),
            _ if name.ends_with(".pressure") => {
                // A trigger needs `poll` on the open file, and the files of this crate cannot
                // keep a state for each open file yet.
                Trigger::parse(data)?;
                Err(Errno::EOPNOTSUPP)
            }
            _ => {
                let t = rk_cgroup::now();
                let effect = rk_cgroup::with(|h| h.write(self.id, name, data, t))?;
                procs::apply(self.id, effect);
                Ok(())
            }
        }
    }

    /// The entries of the directory, without `.` and `..`.
    fn entries(&self) -> Result<Vec<(Vec<u8>, Option<CgId>)>> {
        rk_cgroup::with(|h| {
            if !h.exists(self.id) {
                return Err(Errno::ENOENT);
            }
            let mut out: Vec<(Vec<u8>, Option<CgId>)> =
                h.children(self.id).into_iter().map(|(n, c)| (n, Some(c))).collect();
            out.extend(h.files(self.id).iter().map(|f| (f.name.as_bytes().to_vec(), None)));
            Ok(out)
        })
    }
}

/// The text of a list of IDs: one ID on each line.
fn lines(ids: &[u32]) -> String {
    ids.iter().map(|id| format!("{id}\n")).collect()
}

/// Reads a process or thread ID from a write of `cgroup.procs` or `cgroup.threads`.
fn parse_id(data: &[u8]) -> Result<u32> {
    let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
    text.trim_matches(|c: char| c.is_ascii_whitespace() || c == '\0')
        .parse()
        .map_err(|_| Errno::EINVAL)
}

impl Inode for Node {
    fn metadata(&self) -> Metadata {
        let (kind, perm, nlink) = match self.file {
            None => (mode::S_IFDIR, 0o755, 2),
            Some(name) => {
                let perm =
                    rk_cgroup::with(|h| h.file(self.id, name.as_bytes())).map_or(0o444, |f| f.perm);
                (mode::S_IFREG, perm, 1)
            }
        };
        let t = now();
        Metadata {
            dev: dev(),
            ino: Self::ino(self.id, self.file),
            mode: kind | perm,
            nlink,
            blksize: BLOCK_SIZE,
            atime: t,
            mtime: t,
            ctime: t,
            ..Metadata::default()
        }
    }

    fn set_attr(&self, _attr: &SetAttr) -> Result<()> {
        // `O_TRUNC` sets the size to 0, and the files have no size. A change of the owner or the
        // mode is for the delegation of Linux, which this kernel does not check.
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let Some(name) = self.file else { return Err(Errno::EISDIR) };
        let text = self.text(name)?;
        let text = text.as_bytes();
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(text.len());
        let n = buf.len().min(text.len() - start);
        buf[..n].copy_from_slice(&text[start..start + n]);
        Ok(n)
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize> {
        let Some(name) = self.file else { return Err(Errno::EISDIR) };
        self.command(name, buf)?;
        Ok(buf.len())
    }

    fn lookup(&self, name: &[u8]) -> Result<InodeRef> {
        if self.file.is_some() {
            return Err(Errno::ENOTDIR);
        }
        rk_cgroup::with(|h| {
            if let Some(id) = h.lookup(self.id, name) {
                return Ok(Arc::new(Node { id, file: None }) as InodeRef);
            }
            let f = h.file(self.id, name).ok_or(Errno::ENOENT)?;
            Ok(Arc::new(Node { id: self.id, file: Some(f.name) }) as InodeRef)
        })
    }

    fn create(&self, name: &[u8], kind: FileType, _perm: u32, _rdev: u64) -> Result<InodeRef> {
        if self.file.is_some() {
            return Err(Errno::ENOTDIR);
        }
        if kind != FileType::Directory {
            return Err(Errno::EPERM);
        }
        let t = rk_cgroup::now();
        let id = rk_cgroup::with(|h| h.mkdir(self.id, name, t))?;
        Ok(Arc::new(Node { id, file: None }))
    }

    fn symlink(&self, _: &[u8], _: &[u8]) -> Result<InodeRef> {
        Err(Errno::EPERM)
    }

    fn link(&self, _: &[u8], _: &InodeRef) -> Result<()> {
        Err(Errno::EPERM)
    }

    fn unlink(&self, _: &[u8]) -> Result<()> {
        Err(Errno::EPERM)
    }

    fn rmdir(&self, name: &[u8]) -> Result<()> {
        if self.file.is_some() {
            return Err(Errno::ENOTDIR);
        }
        rk_cgroup::with(|h| {
            if h.lookup(self.id, name).is_none() && h.file(self.id, name).is_some() {
                return Err(Errno::ENOTDIR);
            }
            h.rmdir(self.id, name).map(|_| ())
        })
    }

    fn rename(&self, _: &[u8], _: &InodeRef, _: &[u8]) -> Result<()> {
        Err(Errno::EPERM)
    }

    fn read_dir(&self, pos: u64) -> Result<Option<(DirEntry, u64)>> {
        if self.file.is_some() {
            return Err(Errno::ENOTDIR);
        }
        let entry = match pos {
            0 => DirEntry {
                ino: Self::ino(self.id, None),
                kind: FileType::Directory,
                name: b".".to_vec(),
            },
            1 => {
                let parent = rk_cgroup::with(|h| h.parent(self.id)).unwrap_or(self.id);
                DirEntry {
                    ino: Self::ino(parent, None),
                    kind: FileType::Directory,
                    name: b"..".to_vec(),
                }
            }
            _ => {
                let entries = self.entries()?;
                let Some((name, child)) = entries.into_iter().nth((pos - 2) as usize) else {
                    return Ok(None);
                };
                match child {
                    Some(id) => {
                        DirEntry { ino: Self::ino(id, None), kind: FileType::Directory, name }
                    }
                    None => {
                        let ino = Self::ino(self.id, core::str::from_utf8(&name).ok());
                        DirEntry { ino, kind: FileType::Regular, name }
                    }
                }
            }
        };
        Ok(Some((entry, pos + 1)))
    }

    fn fs_magic(&self) -> u64 {
        CGROUP2_MAGIC
    }
}

#[cfg(test)]
mod tests;

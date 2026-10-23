//! The initramfs: a cpio archive in the `newc` format, as init/initramfs.c of Linux reads it.
//!
//! Each entry has a header of 110 ASCII bytes, the name with a zero byte, and the data. The
//! header, the name and the data each start at a multiple of 4 bytes. The entry `TRAILER!!!`
//! ends the archive. An entry with more than one link and the same inode number as an earlier
//! entry is a hard link to it. The last entry of such a group has the data.

use crate::dentry::Location;
use crate::fs::FsContext;
use crate::inode::{FileType, Result, SetAttr, Timespec, mode};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use rk_abi::Errno;

const MAGIC: &[u8] = b"070701";
const MAGIC_CRC: &[u8] = b"070702";
const HEADER_LEN: usize = 110;
const TRAILER: &[u8] = b"TRAILER!!!";

/// One entry of the archive.
#[derive(Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    /// The inode number in the archive.
    pub ino: u32,
    /// The type and the permission bits.
    pub mode: u32,
    /// The owner.
    pub uid: u32,
    /// The group.
    pub gid: u32,
    /// The number of links.
    pub nlink: u32,
    /// The modification time in seconds.
    pub mtime: u32,
    /// The device of the archive, with `ino` the identity of a hard link.
    pub dev: (u32, u32),
    /// The device that a device file is for.
    pub rdev: (u32, u32),
    /// The path, without the zero byte.
    pub name: &'a [u8],
    /// The data of a file, or the target of a symbolic link.
    pub data: &'a [u8],
}

fn hex(field: &[u8]) -> Result<u32> {
    let mut value = 0u32;
    for &b in field {
        let digit = (b as char).to_digit(16).ok_or(Errno::EINVAL)?;
        value = (value << 4) | digit;
    }
    Ok(value)
}

fn align4(n: usize) -> usize {
    n.next_multiple_of(4)
}

/// Reads the entries of an archive. The iterator stops after the trailer or at the first error.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    done: bool,
}

impl<'a> Reader<'a> {
    /// Reads `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0, done: false }
    }

    fn next_entry(&mut self) -> Result<Option<Entry<'a>>> {
        // Linux skips zero bytes between archives, so an image can be more than one archive.
        while self.data.get(self.pos) == Some(&0) {
            self.pos += 1;
        }
        if self.pos >= self.data.len() {
            return Ok(None);
        }
        let h = self.data.get(self.pos..self.pos + HEADER_LEN).ok_or(Errno::EINVAL)?;
        if &h[..6] != MAGIC && &h[..6] != MAGIC_CRC {
            return Err(Errno::EINVAL);
        }
        let field = |i: usize| hex(&h[6 + i * 8..14 + i * 8]);
        let name_len = field(11)? as usize;
        let file_size = field(6)? as usize;
        let name_start = self.pos + HEADER_LEN;
        let name = self.data.get(name_start..name_start + name_len).ok_or(Errno::EINVAL)?;
        let name = name.strip_suffix(b"\0").ok_or(Errno::EINVAL)?;
        let data_start = align4(name_start + name_len);
        let data = self.data.get(data_start..data_start + file_size).ok_or(Errno::EINVAL)?;
        self.pos = align4(data_start + file_size);
        if name == TRAILER {
            // The next archive, if there is one, starts after the trailer.
            return self.next_entry();
        }
        Ok(Some(Entry {
            ino: field(0)?,
            mode: field(1)?,
            uid: field(2)?,
            gid: field(3)?,
            nlink: field(4)?,
            mtime: field(5)?,
            dev: (field(7)?, field(8)?),
            rdev: (field(9)?, field(10)?),
            name,
            data,
        }))
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = Result<Entry<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let r = self.next_entry().transpose();
        if !matches!(r, Some(Ok(_))) {
            self.done = true;
        }
        r
    }
}

/// Unpacks the archive `data` into the root of `fs`. An entry that exists is replaced, except a
/// directory, which only gets the new attributes. The function stops at the first error.
pub fn unpack(fs: &FsContext, data: &[u8]) -> Result<usize> {
    let root = fs.root().clone();
    let mut links: BTreeMap<(u32, u32, u32), Location> = BTreeMap::new();
    let mut count = 0;
    for entry in Reader::new(data) {
        let e = entry?;
        let path: Vec<u8> = match e.name {
            b"." | b"./" => continue,
            name => name.strip_prefix(b"./").unwrap_or(name).to_vec(),
        };
        let kind = FileType::from_mode(e.mode).ok_or(Errno::EINVAL)?;
        let perm = e.mode & mode::PERM_MASK;
        let key = (e.dev.0, e.dev.1, e.ino);
        if kind != FileType::Directory {
            // Linux removes the old file before it makes the new one.
            let _ = fs.remove(&root, &path, false);
        }
        if kind != FileType::Directory
            && e.nlink > 1
            && let Some(first) = links.get(&key)
        {
            fs.link(first, &root, &path)?;
            if !e.data.is_empty() {
                let at = fs.resolve(&root, &path, false)?;
                at.inode().write_at(0, e.data)?;
            }
            count += 1;
            continue;
        }
        let at = match kind {
            FileType::Directory => match fs.resolve(&root, &path, false) {
                Ok(at) if at.inode().metadata().is_dir() => at,
                _ => fs.mkdir(&root, &path, perm)?,
            },
            FileType::Symlink => fs.symlink(e.data, &root, &path)?,
            FileType::Regular => {
                let at = fs.mknod(&root, &path, mode::S_IFREG | perm, 0)?;
                let mut done = 0;
                while done < e.data.len() {
                    done += at.inode().write_at(done as u64, &e.data[done..])?;
                }
                at
            }
            _ => {
                let rdev = crate::device::makedev(e.rdev.0, e.rdev.1);
                fs.mknod(&root, &path, kind.mode_bits() | perm, rdev)?
            }
        };
        if kind != FileType::Symlink {
            let time = Timespec { sec: i64::from(e.mtime), nsec: 0 };
            // The umask does not apply to the archive, as in Linux.
            at.inode().set_attr(&SetAttr {
                mode: Some(perm),
                uid: Some(e.uid),
                gid: Some(e.gid),
                mtime: Some(time),
                ..SetAttr::default()
            })?;
        }
        if e.nlink > 1 && kind != FileType::Directory {
            links.insert(key, at);
        }
        count += 1;
    }
    Ok(count)
}

/// Writes an archive, for tests and for the tools that make an initramfs.
#[derive(Default)]
pub struct Writer {
    out: Vec<u8>,
    ino: u32,
}

impl Writer {
    /// Makes an empty archive.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an entry with one link.
    pub fn add(&mut self, name: &[u8], mode: u32, data: &[u8]) {
        self.ino += 1;
        let ino = self.ino;
        self.add_raw(ino, name, mode, 1, (0, 0), data);
    }

    /// Adds an entry with all fields that matter to `unpack`.
    pub fn add_raw(
        &mut self,
        ino: u32,
        name: &[u8],
        mode: u32,
        nlink: u32,
        rdev: (u32, u32),
        data: &[u8],
    ) {
        use core::fmt::Write as _;
        let fields = [
            ino,
            mode,
            0,
            0,
            nlink,
            0,
            data.len() as u32,
            0,
            0,
            rdev.0,
            rdev.1,
            name.len() as u32 + 1,
            0,
        ];
        let mut header = alloc::string::String::from("070701");
        for f in fields {
            let _ = write!(header, "{f:08x}");
        }
        self.out.extend_from_slice(header.as_bytes());
        self.out.extend_from_slice(name);
        self.out.push(0);
        self.pad();
        self.out.extend_from_slice(data);
        self.pad();
    }

    fn pad(&mut self) {
        while !self.out.len().is_multiple_of(4) {
            self.out.push(0);
        }
    }

    /// Adds the trailer and gives the archive.
    pub fn finish(mut self) -> Vec<u8> {
        self.add_raw(0, TRAILER, 0, 1, (0, 0), &[]);
        self.out
    }
}

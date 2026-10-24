//! The kinds of inode of procfs: a file that makes its text at each read, a file that reads and
//! writes at an offset, a symbolic link that finds its target at each read, and a directory that
//! makes its list at each read.
//!
//! The text of a file is new at each `read`, so a read at an offset sees the text of that moment.
//! Linux keeps the text of an open file in a `seq_file` buffer. The programs that R1 runs read a
//! proc file in one call, or do not depend on the difference.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::Once;
use rk_vfs::inode::mode;
use rk_vfs::{DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, now};

use crate::PROC_SUPER_MAGIC;

/// Makes the text of a file or the target of a link.
pub(crate) type ReadFn = Box<dyn Fn() -> Result<Vec<u8>> + Send + Sync>;
/// Takes the bytes of a write.
pub(crate) type WriteFn = Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync>;
/// Makes the entries of a directory.
pub(crate) type ListFn = Box<dyn Fn() -> Result<Vec<(Vec<u8>, InodeRef)>> + Send + Sync>;
/// Reads at an offset into a buffer, and gives the number of bytes.
pub(crate) type ReadAtFn = Box<dyn Fn(u64, &mut [u8]) -> Result<usize> + Send + Sync>;
/// Writes a buffer at an offset, and gives the number of bytes.
pub(crate) type WriteAtFn = Box<dyn Fn(u64, &[u8]) -> Result<usize> + Send + Sync>;
/// Finds one entry of a directory, without the full list.
pub(crate) type FindFn = Box<dyn Fn(&[u8]) -> Result<InodeRef> + Send + Sync>;

/// The block size that `stat` gives for a proc file, as Linux gives.
const BLOCK_SIZE: u32 = 1024;

enum Kind {
    File {
        read: ReadFn,
        write: Option<WriteFn>,
    },
    /// A file that reads and writes at an offset, as `/proc/PID/mem`.
    Data {
        read: ReadAtFn,
        write: WriteAtFn,
    },
    /// A symbolic link. The error is for a walk that follows the link.
    Link(ReadFn, Option<Errno>),
    Dir {
        parent: u64,
        list: ListFn,
        find: Option<FindFn>,
    },
}

/// An inode of procfs.
pub(crate) struct Node {
    ino: u64,
    perm: u32,
    kind: Kind,
}

/// The device of procfs. Each mount of procfs shows the same files, so they have one device.
fn dev() -> u64 {
    static DEV: Once<u64> = Once::new();
    *DEV.call_once(rk_vfs::anon_dev)
}

/// The inode number of the file with the path `path` in procfs. The number is a hash of the
/// path, so the inode of one path keeps its number when the kernel makes it again.
pub(crate) fn ino(path: &[u8]) -> u64 {
    if path == b"/" {
        return 1;
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in path {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    // Keep the numbers positive in a signed 64 bit value, and away from 1.
    (h >> 1) | 2
}

/// Makes a file that only gives text.
pub(crate) fn file(
    path: &[u8],
    read: impl Fn() -> Result<Vec<u8>> + Send + Sync + 'static,
) -> InodeRef {
    Arc::new(Node {
        ino: ino(path),
        perm: 0o444,
        kind: Kind::File { read: Box::new(read), write: None },
    })
}

/// Makes a file that gives text and takes writes.
pub(crate) fn rw_file(
    path: &[u8],
    read: impl Fn() -> Result<Vec<u8>> + Send + Sync + 'static,
    write: impl Fn(&[u8]) -> Result<()> + Send + Sync + 'static,
) -> InodeRef {
    let kind = Kind::File { read: Box::new(read), write: Some(Box::new(write)) };
    Arc::new(Node { ino: ino(path), perm: 0o644, kind })
}

/// Makes a file that reads and writes at an offset, with the permission bits `perm`.
pub(crate) fn data_file(
    path: &[u8],
    perm: u32,
    read: impl Fn(u64, &mut [u8]) -> Result<usize> + Send + Sync + 'static,
    write: impl Fn(u64, &[u8]) -> Result<usize> + Send + Sync + 'static,
) -> InodeRef {
    let kind = Kind::Data { read: Box::new(read), write: Box::new(write) };
    Arc::new(Node { ino: ino(path), perm, kind })
}

/// Makes a symbolic link with the permission bits `perm`.
pub(crate) fn link(
    path: &[u8],
    perm: u32,
    target: impl Fn() -> Result<Vec<u8>> + Send + Sync + 'static,
) -> InodeRef {
    Arc::new(Node { ino: ino(path), perm, kind: Kind::Link(Box::new(target), None) })
}

/// Makes a symbolic link that a walk cannot follow: the walk gives `error`.
pub(crate) fn dead_link(
    path: &[u8],
    perm: u32,
    target: impl Fn() -> Result<Vec<u8>> + Send + Sync + 'static,
    error: Errno,
) -> InodeRef {
    Arc::new(Node { ino: ino(path), perm, kind: Kind::Link(Box::new(target), Some(error)) })
}

/// Makes a directory. `parent` is the path of the parent directory, for `..`. `find` finds one
/// entry. Without it, a lookup makes the full list.
pub(crate) fn dir(
    path: &[u8],
    parent: &[u8],
    perm: u32,
    list: impl Fn() -> Result<Vec<(Vec<u8>, InodeRef)>> + Send + Sync + 'static,
    find: Option<FindFn>,
) -> InodeRef {
    let kind = Kind::Dir { parent: ino(parent), list: Box::new(list), find };
    Arc::new(Node { ino: ino(path), perm, kind })
}

/// Joins a directory path and a name.
pub(crate) fn join(dir: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = dir.to_vec();
    if path.last() != Some(&b'/') {
        path.push(b'/');
    }
    path.extend_from_slice(name);
    path
}

impl Inode for Node {
    fn metadata(&self) -> Metadata {
        let (kind, nlink) = match self.kind {
            Kind::File { .. } | Kind::Data { .. } => (mode::S_IFREG, 1),
            Kind::Link(..) => (mode::S_IFLNK, 1),
            Kind::Dir { .. } => (mode::S_IFDIR, 2),
        };
        let t = now();
        Metadata {
            dev: dev(),
            ino: self.ino,
            mode: kind | self.perm,
            nlink,
            blksize: BLOCK_SIZE,
            atime: t,
            mtime: t,
            ctime: t,
            ..Metadata::default()
        }
    }

    fn set_attr(&self, attr: &SetAttr) -> Result<()> {
        // `O_TRUNC` on a proc file has no effect, as on Linux. The owner and the mode stay.
        if attr.mode.is_some() || attr.uid.is_some() || attr.gid.is_some() {
            return Err(Errno::EPERM);
        }
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if let Kind::Data { read, .. } = &self.kind {
            return read(offset, buf);
        }
        let Kind::File { read, .. } = &self.kind else {
            return Err(if matches!(self.kind, Kind::Dir { .. }) {
                Errno::EISDIR
            } else {
                Errno::EINVAL
            });
        };
        let text = read()?;
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(text.len());
        let n = buf.len().min(text.len() - start);
        buf[..n].copy_from_slice(&text[start..start + n]);
        Ok(n)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        match &self.kind {
            Kind::Data { write, .. } => write(offset, buf),
            Kind::File { write: Some(write), .. } => {
                write(buf)?;
                Ok(buf.len())
            }
            Kind::File { write: None, .. } => Err(Errno::EIO),
            _ => Err(Errno::EINVAL),
        }
    }

    fn lookup(&self, name: &[u8]) -> Result<InodeRef> {
        let Kind::Dir { list, find, .. } = &self.kind else {
            return Err(Errno::ENOTDIR);
        };
        if let Some(find) = find {
            return find(name);
        }
        list()?.into_iter().find(|(n, _)| n == name).map(|(_, i)| i).ok_or(Errno::ENOENT)
    }

    fn create(&self, _: &[u8], _: FileType, _: u32, _: u64) -> Result<InodeRef> {
        self.no_change()
    }

    fn symlink(&self, _: &[u8], _: &[u8]) -> Result<InodeRef> {
        self.no_change()
    }

    fn link(&self, _: &[u8], _: &InodeRef) -> Result<()> {
        self.no_change()
    }

    fn unlink(&self, _: &[u8]) -> Result<()> {
        self.no_change()
    }

    fn rmdir(&self, _: &[u8]) -> Result<()> {
        self.no_change()
    }

    fn rename(&self, _: &[u8], _: &InodeRef, _: &[u8]) -> Result<()> {
        self.no_change()
    }

    fn read_link(&self) -> Result<Vec<u8>> {
        match &self.kind {
            Kind::Link(target, _) => target(),
            _ => Err(Errno::EINVAL),
        }
    }

    fn follow_link(&self) -> Result<Vec<u8>> {
        match &self.kind {
            Kind::Link(_, Some(e)) => Err(*e),
            _ => self.read_link(),
        }
    }

    fn read_dir(&self, pos: u64) -> Result<Option<(DirEntry, u64)>> {
        let Kind::Dir { parent, list, .. } = &self.kind else {
            return Err(Errno::ENOTDIR);
        };
        let entry = match pos {
            0 => DirEntry { ino: self.ino, kind: FileType::Directory, name: b".".to_vec() },
            1 => DirEntry { ino: *parent, kind: FileType::Directory, name: b"..".to_vec() },
            _ => {
                let Some((name, inode)) = list()?.into_iter().nth((pos - 2) as usize) else {
                    return Ok(None);
                };
                let meta = inode.metadata();
                let kind = meta.file_type().unwrap_or(FileType::Regular);
                DirEntry { ino: meta.ino, kind, name }
            }
        };
        Ok(Some((entry, pos + 1)))
    }

    fn fs_magic(&self) -> u64 {
        PROC_SUPER_MAGIC
    }
}

impl Node {
    /// A directory of procfs does not take new names, and a file is not a directory.
    fn no_change<T>(&self) -> Result<T> {
        Err(if matches!(self.kind, Kind::Dir { .. }) { Errno::EPERM } else { Errno::ENOTDIR })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::sync::atomic::{AtomicU64, Ordering};

    static VALUE: AtomicU64 = AtomicU64::new(5);

    fn tree() -> InodeRef {
        dir(
            b"/",
            b"/",
            0o555,
            || {
                Ok(vec![
                    (b"text".to_vec(), file(b"/text", || Ok(b"hello\n".to_vec()))),
                    (
                        b"value".to_vec(),
                        rw_file(
                            b"/value",
                            || {
                                Ok(alloc::format!("{}\n", VALUE.load(Ordering::Relaxed))
                                    .into_bytes())
                            },
                            |data| {
                                let v = crate::text::parse_number(data).ok_or(Errno::EINVAL)?;
                                VALUE.store(v as u64, Ordering::Relaxed);
                                Ok(())
                            },
                        ),
                    ),
                    (b"self".to_vec(), link(b"/self", 0o777, || Ok(b"1".to_vec()))),
                    (
                        b"data".to_vec(),
                        data_file(
                            b"/data",
                            0o600,
                            |offset, buf| {
                                buf.fill(offset as u8);
                                Ok(buf.len())
                            },
                            |offset, _| Ok(offset as usize),
                        ),
                    ),
                ])
            },
            None,
        )
    }

    #[test]
    fn a_file_reads_at_an_offset() {
        let text = tree().lookup(b"text").unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(text.read_at(0, &mut buf).unwrap(), 4);
        assert_eq!(&buf, b"hell");
        assert_eq!(text.read_at(4, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], b"o\n");
        assert_eq!(text.read_at(99, &mut buf).unwrap(), 0);
        assert_eq!(text.write_at(0, b"x").unwrap_err(), Errno::EIO);
        assert_eq!(text.metadata().mode, mode::S_IFREG | 0o444);
        assert_eq!(text.fs_magic(), PROC_SUPER_MAGIC);
        assert_eq!(text.lookup(b"x").err(), Some(Errno::ENOTDIR));
    }

    #[test]
    fn a_write_changes_the_value() {
        let value = tree().lookup(b"value").unwrap();
        assert_eq!(value.write_at(0, b"42\n").unwrap(), 3);
        let mut buf = [0u8; 8];
        assert_eq!(value.read_at(0, &mut buf).unwrap(), 3);
        assert_eq!(&buf[..3], b"42\n");
        assert_eq!(value.write_at(0, b"x").unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn a_data_file_reads_and_writes_at_the_offset() {
        let data = tree().lookup(b"data").unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(data.read_at(9, &mut buf).unwrap(), 2);
        assert_eq!(buf, [9, 9]);
        assert_eq!(data.write_at(7, b"x").unwrap(), 7);
        assert_eq!(data.metadata().mode, mode::S_IFREG | 0o600);
    }

    #[test]
    fn a_directory_lists_its_entries() {
        let root = tree();
        let names: Vec<Vec<u8>> =
            (0..).map_while(|pos| root.read_dir(pos).unwrap()).map(|(e, _)| e.name).collect();
        assert_eq!(names, [&b"."[..], b"..", b"text", b"value", b"self", b"data"]);
        assert_eq!(root.metadata().ino, 1);
        assert_eq!(root.lookup(b"nothing").err(), Some(Errno::ENOENT));
        assert_eq!(root.lookup(b"self").unwrap().read_link().unwrap(), b"1");
        assert_eq!(root.unlink(b"text").unwrap_err(), Errno::EPERM);
        assert_eq!(ino(b"/text"), ino(b"/text"));
        assert_ne!(ino(b"/text"), ino(b"/value"));
        assert_eq!(join(b"/1", b"stat"), b"/1/stat");
    }

    #[test]
    fn a_dead_link_gives_its_error_to_a_walk() {
        let node = dead_link(b"/fd/3", 0o700, || Ok(b"socket:[7]".to_vec()), Errno::ENXIO);
        assert_eq!(node.read_link().unwrap(), b"socket:[7]");
        assert_eq!(node.follow_link().err(), Some(Errno::ENXIO));
        let node = link(b"/fd/4", 0o700, || Ok(b"/tmp".to_vec()));
        assert_eq!(node.follow_link().unwrap(), b"/tmp");
    }
}

//! The kinds of inode of procfs: a file that makes its text at each read, a file that reads and
//! writes at an offset, a symbolic link that finds its target at each read, and a directory that
//! makes its list at each read.
//!
//! A read at offset 0 makes the text of a file again. A read at a larger offset uses the text of
//! the last read at offset 0, until a read gets to the end of the text, as the `seq_file` buffer
//! of Linux. A program that reads a long file, as `/proc/PID/maps` with many areas, in small parts
//! then takes a time that grows with the size and not with the square of the size.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use rk_abi::Errno;
use rk_frame::sync::{Once, SpinLock};
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

/// Makes the operations of an open file, for a file that keeps a state for each open file.
pub(crate) type OpenFn = Box<dyn Fn() -> Option<Arc<dyn rk_vfs::file::FileOps>> + Send + Sync>;

/// Gives the owner and the group of a file.
pub(crate) type OwnerFn = Box<dyn Fn() -> (u32, u32) + Send + Sync>;

/// Gives the place that a walk goes to at a magic link.
pub(crate) type JumpFn = Box<dyn Fn() -> Result<rk_vfs::Location> + Send + Sync>;

/// The block size that `stat` gives for a proc file, as Linux gives.
const BLOCK_SIZE: u32 = 1024;

enum Kind {
    File {
        read: ReadFn,
        write: Option<WriteFn>,
        /// The text of the last read at offset 0, while a reader has not got to its end.
        text: SpinLock<Option<Arc<Vec<u8>>>>,
        /// The operations of an open file. Without them, the file uses the inode.
        open: Option<OpenFn>,
    },
    /// A file that reads and writes at an offset, as `/proc/PID/mem`.
    Data {
        read: ReadAtFn,
        write: WriteAtFn,
    },
    /// A symbolic link, and what a walk does at it.
    Link(ReadFn, Follow),
    Dir {
        parent: u64,
        list: ListFn,
        find: Option<FindFn>,
    },
}

/// What a walk does at a symbolic link.
enum Follow {
    /// The walk reads the target as a path.
    Path,
    /// The walk gives the error.
    Error(Errno),
    /// The walk goes to the place, as at a magic link of Linux.
    Jump(JumpFn),
}

/// An inode of procfs.
pub(crate) struct Node {
    ino: u64,
    perm: u32,
    kind: Kind,
    /// The owner and the group. Without it, root owns the file.
    owner: Once<OwnerFn>,
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
        kind: Kind::File {
            read: Box::new(read),
            write: None,
            text: SpinLock::new(None),
            open: None,
        },
        owner: Once::new(),
    })
}

/// Makes a file that gives text and takes writes.
pub(crate) fn rw_file(
    path: &[u8],
    read: impl Fn() -> Result<Vec<u8>> + Send + Sync + 'static,
    write: impl Fn(&[u8]) -> Result<()> + Send + Sync + 'static,
) -> InodeRef {
    let kind = Kind::File {
        read: Box::new(read),
        write: Some(Box::new(write)),
        text: SpinLock::new(None),
        open: None,
    };
    Arc::new(Node { ino: ino(path), perm: 0o644, kind, owner: Once::new() })
}

/// Makes a file with the permission bits `perm` whose open files have the operations that
/// `open` makes. `read` gives the text for a read of the inode without an open file.
#[cfg_attr(test, expect(dead_code, reason = "only the pressure files of the kernel use it"))]
pub(crate) fn ops_file(
    path: &[u8],
    perm: u32,
    read: impl Fn() -> Result<Vec<u8>> + Send + Sync + 'static,
    open: impl Fn() -> Option<Arc<dyn rk_vfs::file::FileOps>> + Send + Sync + 'static,
) -> InodeRef {
    let kind = Kind::File {
        read: Box::new(read),
        write: None,
        text: SpinLock::new(None),
        open: Some(Box::new(open)),
    };
    Arc::new(Node { ino: ino(path), perm, kind, owner: Once::new() })
}

/// Makes a file that reads and writes at an offset, with the permission bits `perm`.
pub(crate) fn data_file(
    path: &[u8],
    perm: u32,
    read: impl Fn(u64, &mut [u8]) -> Result<usize> + Send + Sync + 'static,
    write: impl Fn(u64, &[u8]) -> Result<usize> + Send + Sync + 'static,
) -> InodeRef {
    let kind = Kind::Data { read: Box::new(read), write: Box::new(write) };
    Arc::new(Node { ino: ino(path), perm, kind, owner: Once::new() })
}

/// Makes a symbolic link with the permission bits `perm`.
pub(crate) fn link(
    path: &[u8],
    perm: u32,
    target: impl Fn() -> Result<Vec<u8>> + Send + Sync + 'static,
) -> InodeRef {
    Arc::new(Node {
        ino: ino(path),
        perm,
        kind: Kind::Link(Box::new(target), Follow::Path),
        owner: Once::new(),
    })
}

/// Makes a symbolic link that a walk cannot follow: the walk gives `error`.
pub(crate) fn dead_link(
    path: &[u8],
    perm: u32,
    target: impl Fn() -> Result<Vec<u8>> + Send + Sync + 'static,
    error: Errno,
) -> InodeRef {
    Arc::new(Node {
        ino: ino(path),
        perm,
        kind: Kind::Link(Box::new(target), Follow::Error(error)),
        owner: Once::new(),
    })
}

/// Makes a magic link: a walk that follows it goes to the place that `jump` gives and does not
/// read the target as a path.
pub(crate) fn jump_link(
    path: &[u8],
    perm: u32,
    target: impl Fn() -> Result<Vec<u8>> + Send + Sync + 'static,
    jump: impl Fn() -> Result<rk_vfs::Location> + Send + Sync + 'static,
) -> InodeRef {
    let follow = Follow::Jump(Box::new(jump));
    Arc::new(Node {
        ino: ino(path),
        perm,
        kind: Kind::Link(Box::new(target), follow),
        owner: Once::new(),
    })
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
    Arc::new(Node { ino: ino(path), perm, kind, owner: Once::new() })
}

/// Gives `node` the owner and the group that `owner` gives at each `stat`, as the files of a
/// process in Linux have the effective ids of the process. The owner of a node is set one time.
pub(crate) fn set_owner(node: &InodeRef, owner: impl Fn() -> (u32, u32) + Send + Sync + 'static) {
    let any: &dyn Any = &**node;
    if let Some(node) = any.downcast_ref::<Node>() {
        node.owner.call_once(|| Box::new(owner));
    }
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
        let (uid, gid) = self.owner.get().map_or((0, 0), |f| f());
        Metadata {
            dev: dev(),
            ino: self.ino,
            mode: kind | self.perm,
            nlink,
            uid,
            gid,
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
        let Kind::File { read, text: kept, .. } = &self.kind else {
            return Err(if matches!(self.kind, Kind::Dir { .. }) {
                Errno::EISDIR
            } else {
                Errno::EINVAL
            });
        };
        let last = if offset == 0 { None } else { kept.lock().clone() };
        let text = match last {
            Some(text) => text,
            None => Arc::new(read()?),
        };
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(text.len());
        let n = buf.len().min(text.len() - start);
        buf[..n].copy_from_slice(&text[start..start + n]);
        // Keep the text for the next part, or let it go at the end.
        *kept.lock() = (start + n < text.len()).then_some(text);
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

    fn open_file(&self, _flags: u32) -> Option<Result<Arc<dyn rk_vfs::file::FileOps>>> {
        let Kind::File { open: Some(open), .. } = &self.kind else { return None };
        open().map(Ok)
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
            Kind::Link(_, Follow::Error(e)) => Err(*e),
            _ => self.read_link(),
        }
    }

    fn magic_link(&self) -> Option<Result<rk_vfs::Location>> {
        match &self.kind {
            Kind::Link(_, Follow::Jump(jump)) => Some(jump()),
            _ => None,
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
    fn a_read_in_parts_sees_the_text_of_the_first_part() {
        use core::sync::atomic::{AtomicU8, Ordering};
        let calls = Arc::new(AtomicU8::new(0));
        let c = calls.clone();
        let node = file(b"/count", move || {
            let n = c.fetch_add(1, Ordering::Relaxed);
            Ok(alloc::vec![b'0' + n; 4])
        });
        let mut buf = [0u8; 2];
        assert_eq!(node.read_at(0, &mut buf).unwrap(), 2);
        assert_eq!(&buf, b"00");
        // The second part comes from the same text, and the end lets the text go.
        assert_eq!(node.read_at(2, &mut buf).unwrap(), 2);
        assert_eq!(&buf, b"00");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(node.read_at(0, &mut buf).unwrap(), 2);
        assert_eq!(&buf, b"11");
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
    fn a_file_has_the_owner_that_it_gets() {
        let text = file(b"/text", || Ok(Vec::new()));
        assert_eq!((text.metadata().uid, text.metadata().gid), (0, 0));
        set_owner(&text, || (1000, 100));
        set_owner(&text, || (2000, 200));
        assert_eq!((text.metadata().uid, text.metadata().gid), (1000, 100));
    }

    #[test]
    fn a_dead_link_gives_its_error_to_a_walk() {
        let node = dead_link(b"/fd/3", 0o700, || Ok(b"socket:[7]".to_vec()), Errno::ENXIO);
        assert_eq!(node.read_link().unwrap(), b"socket:[7]");
        assert_eq!(node.follow_link().err(), Some(Errno::ENXIO));
        let node = link(b"/fd/4", 0o700, || Ok(b"/tmp".to_vec()));
        assert_eq!(node.follow_link().unwrap(), b"/tmp");
        assert!(node.magic_link().is_none());
        let node = jump_link(b"/fd/5", 0o700, || Ok(b"pipe:[2]".to_vec()), || Err(Errno::ENOENT));
        assert_eq!(node.read_link().unwrap(), b"pipe:[2]");
        assert_eq!(node.magic_link().map(|j| j.err()), Some(Some(Errno::ENOENT)));
    }
}

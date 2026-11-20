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
use rk_vfs::cred::{Cred, may};
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
    /// Tells that the inode is gone, for `Inode::stale`. Without it, the inode stays.
    gone: Once<GoneFn>,
    /// The check of an access, for `Inode::permission`. Without it, the VFS checks the mode.
    access: Once<AccessFn>,
    /// The check of an access before the other checks, for `Inode::permission`, as
    /// `proc_pid_permission` of Linux for `hidepid`. If it allows the access, `access` or the
    /// mode decide.
    check: Once<CheckFn>,
}

/// The function that checks an access to an inode of procfs, with the caller and the mask.
type CheckFn = Box<dyn Fn(&Cred, u32) -> Result<()> + Send + Sync>;

/// The function that tells that an inode of procfs is gone.
type GoneFn = Box<dyn Fn() -> bool + Send + Sync>;

/// The function that checks an access to an inode of procfs: the credentials and the bits of
/// `may`.
type AccessFn = Box<dyn Fn(&Cred, u32) -> Result<()> + Send + Sync>;

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

/// Makes the node of the path `path` with the permission bits `perm`.
fn new_node(path: &[u8], perm: u32, kind: Kind) -> InodeRef {
    let (owner, gone, access, check) = (Once::new(), Once::new(), Once::new(), Once::new());
    Arc::new(Node { ino: ino(path), perm, kind, owner, gone, access, check })
}

/// Makes a file that only gives text.
pub(crate) fn file(
    path: &[u8],
    read: impl Fn() -> Result<Vec<u8>> + Send + Sync + 'static,
) -> InodeRef {
    let kind =
        Kind::File { read: Box::new(read), write: None, text: SpinLock::new(None), open: None };
    new_node(path, 0o444, kind)
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
    new_node(path, 0o644, kind)
}

/// Makes a file with the permission bits `perm` whose open files have the operations that
/// `open` makes. `read` gives the text for a read of the inode without an open file.
#[cfg_attr(test, expect(dead_code, reason = "only the files of the kernel module use it"))]
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
    new_node(path, perm, kind)
}

/// Makes a file of /proc/sys with the permission bits `perm`. It gives text, takes writes if
/// `write` is there, and its open files have the operations that `open` makes.
#[cfg_attr(test, expect(dead_code, reason = "only the files of the kernel module use it"))]
pub(crate) fn sysctl_file(
    path: &[u8],
    perm: u32,
    read: impl Fn() -> Result<Vec<u8>> + Send + Sync + 'static,
    write: Option<WriteFn>,
    open: impl Fn() -> Option<Arc<dyn rk_vfs::file::FileOps>> + Send + Sync + 'static,
) -> InodeRef {
    let kind = Kind::File {
        read: Box::new(read),
        write,
        text: SpinLock::new(None),
        open: Some(Box::new(open)),
    };
    new_node(path, perm, kind)
}

/// Makes a file that reads and writes at an offset, with the permission bits `perm`.
pub(crate) fn data_file(
    path: &[u8],
    perm: u32,
    read: impl Fn(u64, &mut [u8]) -> Result<usize> + Send + Sync + 'static,
    write: impl Fn(u64, &[u8]) -> Result<usize> + Send + Sync + 'static,
) -> InodeRef {
    let kind = Kind::Data { read: Box::new(read), write: Box::new(write) };
    new_node(path, perm, kind)
}

/// Makes a symbolic link with the permission bits `perm`.
pub(crate) fn link(
    path: &[u8],
    perm: u32,
    target: impl Fn() -> Result<Vec<u8>> + Send + Sync + 'static,
) -> InodeRef {
    new_node(path, perm, Kind::Link(Box::new(target), Follow::Path))
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
    new_node(path, perm, Kind::Link(Box::new(target), follow))
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
    new_node(path, perm, kind)
}

/// The entries that a directory with a fixed table of names makes: all of them for a list, or
/// only the entry `want` for a lookup.
pub(crate) struct Entries<'a> {
    want: Option<&'a [u8]>,
    out: Vec<(Vec<u8>, InodeRef)>,
}

impl<'a> Entries<'a> {
    pub(crate) fn new(want: Option<&'a [u8]>) -> Self {
        Self { want, out: Vec::new() }
    }

    /// Adds the entry `name`. `make` makes its inode only if the entry is in the result.
    pub(crate) fn add(&mut self, name: &[u8], make: impl FnOnce() -> InodeRef) {
        if self.want.is_none_or(|want| want == name) {
            self.out.push((name.to_vec(), make()));
        }
    }

    pub(crate) fn into_vec(self) -> Vec<(Vec<u8>, InodeRef)> {
        self.out
    }
}

/// Makes a directory with a fixed table of names, as the directories of a process in Linux.
/// `make(None)` gives all entries, for the list. A lookup calls `make(Some(name))`, which makes
/// only the inode of `name`, as `proc_pident_lookup` in fs/proc/base.c of Linux.
pub(crate) fn table_dir(
    path: &[u8],
    parent: &[u8],
    perm: u32,
    make: impl Fn(Option<&[u8]>) -> Result<Vec<(Vec<u8>, InodeRef)>> + Send + Sync + 'static,
) -> InodeRef {
    let make = Arc::new(make);
    let one = make.clone();
    let find: FindFn = Box::new(move |name: &[u8]| {
        one(Some(name))?.into_iter().find(|(n, _)| n == name).map(|(_, i)| i).ok_or(Errno::ENOENT)
    });
    dir(path, parent, perm, move || make(None), Some(find))
}

/// Gives `node` the owner and the group that `owner` gives at each `stat`, as the files of a
/// process in Linux have the effective ids of the process. The owner of a node is set one time.
pub(crate) fn set_owner(node: &InodeRef, owner: impl Fn() -> (u32, u32) + Send + Sync + 'static) {
    let any: &dyn Any = &**node;
    if let Some(node) = any.downcast_ref::<Node>() {
        node.owner.call_once(|| Box::new(owner));
    }
}

/// Makes `node` stale when `gone` gives `true`, so that a lookup makes the inode again. The
/// function is set one time.
pub(crate) fn set_gone(node: &InodeRef, gone: impl Fn() -> bool + Send + Sync + 'static) {
    let any: &dyn Any = &**node;
    if let Some(node) = any.downcast_ref::<Node>() {
        node.gone.call_once(|| Box::new(gone));
    }
}

/// Gives `node` the check `access` in place of the check of the mode. The function is set one
/// time.
pub(crate) fn set_access(
    node: &InodeRef,
    access: impl Fn(&Cred, u32) -> Result<()> + Send + Sync + 'static,
) {
    let any: &dyn Any = &**node;
    if let Some(node) = any.downcast_ref::<Node>() {
        node.access.call_once(|| Box::new(access));
    }
}

/// Checks the access `mask` of `cred` to a file of /proc/sys/net with the permission bits
/// `perm`, as `proc_sys_permission` and `net_ctl_permissions` of Linux. If `net_admin`, the
/// process has `CAP_NET_ADMIN` in the network namespace, and it has the access of the owner,
/// root. The other bits then are the same as the owner bits. Root, the effective user ID 0, has
/// the owner bits, and a member of the group 0 the group bits. `CAP_DAC_OVERRIDE` does not
/// apply, as `test_perm` of Linux.
///
/// # Errors
///
/// Gives `EACCES` if the access is not allowed.
pub(crate) fn net_sysctl_access(perm: u32, net_admin: bool, cred: &Cred, mask: u32) -> Result<()> {
    let mut perm = perm & 0o777;
    if net_admin {
        let owner = perm >> 6;
        perm = owner << 6 | owner << 3 | owner;
    }
    if cred.euid == 0 {
        perm >>= 6;
    } else if cred.egid == 0 || cred.groups.binary_search(&0).is_ok() {
        perm >>= 3;
    }
    if mask & (may::READ | may::WRITE | may::EXEC) & !perm == 0 {
        Ok(())
    } else {
        Err(Errno::EACCES)
    }
}

/// Gives `node` a check of each access before the check of the mode bits, as the `permission`
/// operation of an inode in Linux. The check is set one time.
pub(crate) fn set_check(
    node: &InodeRef,
    check: impl Fn(&Cred, u32) -> Result<()> + Send + Sync + 'static,
) {
    let any: &dyn Any = &**node;
    if let Some(node) = any.downcast_ref::<Node>() {
        node.check.call_once(|| Box::new(check));
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

    fn stale(&self) -> bool {
        self.gone.get().is_some_and(|gone| gone())
    }

    fn permission(&self, cred: &Cred, mask: u32) -> Option<Result<()>> {
        if let Some(Err(e)) = self.check.get().map(|check| check(cred, mask)) {
            return Some(Err(e));
        }
        self.access.get().map(|access| access(cred, mask))
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
    fn a_net_sysctl_file_takes_a_write_of_a_network_administrator() {
        static ADMIN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(true);
        let node = rw_file(b"/sys/net/ipv6/conf/all/accept_ra", || Ok(b"1\n".to_vec()), |_| Ok(()));
        let mut user = Cred::root();
        (user.euid, user.fsuid, user.egid, user.fsgid, user.cap_effective) =
            (998, 998, 998, 998, 0);
        // The mode 0644 alone lets the user only read.
        assert_eq!(user.inode_permission(&*node, may::READ), Ok(()));
        assert_eq!(user.inode_permission(&*node, may::WRITE), Err(Errno::EACCES));
        set_access(&node, |cred, mask| {
            net_sysctl_access(0o644, ADMIN.load(Ordering::Relaxed), cred, mask)
        });
        assert_eq!(user.inode_permission(&*node, may::READ | may::WRITE), Ok(()));
        assert_eq!(user.inode_permission(&*node, may::EXEC), Err(Errno::EACCES));
        ADMIN.store(false, Ordering::Relaxed);
        assert_eq!(user.inode_permission(&*node, may::READ), Ok(()));
        assert_eq!(user.inode_permission(&*node, may::WRITE), Err(Errno::EACCES));
        // CAP_DAC_OVERRIDE does not apply. Root has the owner bits with no capability.
        user.cap_effective = rk_vfs::cred::cap::ALL;
        assert_eq!(user.inode_permission(&*node, may::WRITE), Err(Errno::EACCES));
        let mut root = Cred::root();
        root.cap_effective = 0;
        assert_eq!(root.inode_permission(&*node, may::READ | may::WRITE), Ok(()));
        // A file that takes no write stays read only for root and for an administrator.
        assert_eq!(net_sysctl_access(0o444, true, &user, may::WRITE), Err(Errno::EACCES));
        assert_eq!(net_sysctl_access(0o444, true, &root, may::WRITE), Err(Errno::EACCES));
        assert_eq!(net_sysctl_access(0o444, false, &user, may::READ), Ok(()));
        // The group 0 has the group bits.
        user.egid = 0;
        assert_eq!(net_sysctl_access(0o640, false, &user, may::READ), Ok(()));
        assert_eq!(net_sysctl_access(0o604, false, &user, may::READ), Err(Errno::EACCES));
    }

    #[test]
    fn a_magic_link_goes_to_its_place_and_a_link_reads_its_target() {
        let node = link(b"/fd/4", 0o700, || Ok(b"/tmp".to_vec()));
        assert_eq!(node.follow_link().unwrap(), b"/tmp");
        assert!(node.magic_link().is_none());
        let node = jump_link(b"/fd/5", 0o700, || Ok(b"pipe:[2]".to_vec()), || Err(Errno::ENOENT));
        assert_eq!(node.read_link().unwrap(), b"pipe:[2]");
        assert_eq!(node.magic_link().map(|j| j.err()), Some(Some(Errno::ENOENT)));
    }

    #[test]
    fn a_lookup_in_a_table_makes_only_the_entry_of_the_name() {
        use core::sync::atomic::AtomicUsize;
        let made = Arc::new(AtomicUsize::new(0));
        let m = made.clone();
        let node = table_dir(b"/7", b"/", 0o555, move |want| {
            let mut out = Entries::new(want);
            for name in [&b"stat"[..], b"status", b"fd"] {
                out.add(name, || {
                    m.fetch_add(1, Ordering::Relaxed);
                    file(&join(b"/7", name), || Ok(Vec::new()))
                });
            }
            Ok(out.into_vec())
        });
        let status = node.lookup(b"status").unwrap();
        assert_eq!(status.metadata().ino, ino(b"/7/status"));
        assert_eq!(made.load(Ordering::Relaxed), 1);
        assert_eq!(node.lookup(b"environ").err(), Some(Errno::ENOENT));
        assert_eq!(made.load(Ordering::Relaxed), 1);
        // The list still has all of the entries, in the order of the table.
        let mut names = Vec::new();
        let mut pos = 2;
        while let Some((entry, next)) = node.read_dir(pos).unwrap() {
            names.push(entry.name);
            pos = next;
        }
        assert_eq!(names, [&b"stat"[..], b"status", b"fd"]);
    }
}

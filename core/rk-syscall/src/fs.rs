//! The system calls of files, descriptors and paths.

use crate::cx::{Cx, PATH_MAX, SysResult, UserMem};
use alloc::vec;
use rk_abi::Errno;
use rk_abi::native::at::{
    AT_EACCESS, AT_EMPTY_PATH, AT_REMOVEDIR, AT_SYMLINK_FOLLOW, AT_SYMLINK_NOFOLLOW,
};
use rk_abi::native::fcntl::{
    F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_GETFL, F_GETLK, F_GETPIPE_SZ, F_OFD_GETLK, F_OFD_SETLK,
    F_OFD_SETLKW, F_RDLCK, F_SETFD, F_SETFL, F_SETLK, F_SETLKW, F_SETPIPE_SZ, F_UNLCK, F_WRLCK,
    FD_CLOEXEC,
};
use rk_abi::native::ioctls::{FIOCLEX, FIONBIO, FIONCLEX};
use rk_abi::native::mount::{
    MS_MANDLOCK, MS_NOATIME, MS_NODEV, MS_NODIRATIME, MS_NOEXEC, MS_NOSUID, MS_NOSYMFOLLOW,
    MS_RDONLY, MS_RELATIME, MS_SYNCHRONOUS,
};
use rk_abi::native::open::{O_APPEND, O_CLOEXEC, O_NONBLOCK};
use rk_abi::native::signal::{SIGPIPE, SIGXFSZ};
use rk_abi::native::stat::{STATX_BASIC_STATS, STATX_BTIME, STATX_MNT_ID};
use rk_abi::native::types::{Iovec, KernelFsidT, Stat, Statfs, Statx, StatxTimestamp};
use rk_proc::signal::{SI_USER, SigInfo};
use rk_vfs::device::{major, minor};
use rk_vfs::inode::{Metadata, SetAttr, Timespec};
use rk_vfs::lock::{self, LockKind, Owner, RecordLock};
use rk_vfs::{File, Location, Whence};
use zerocopy::FromZeros;

/// The most bytes of one `read` or `write`. Linux names it `MAX_RW_COUNT`.
const MAX_RW_COUNT: usize = 0x7fff_f000;
/// The most bytes that the kernel copies in one step.
const CHUNK: usize = 64 * 1024;
/// The most entries of `readv` and `writev`. Linux names it `UIO_MAXIOV`.
const UIO_MAXIOV: u64 = 1024;
/// The magic number of tmpfs, for `statfs`.
const TMPFS_MAGIC: i64 = 0x0102_1994;

fn stat_of(m: &Metadata) -> Stat {
    Stat {
        st_dev: m.dev,
        st_ino: m.ino,
        st_nlink: u64::from(m.nlink),
        st_mode: m.mode,
        st_uid: m.uid,
        st_gid: m.gid,
        __pad0: 0,
        st_rdev: m.rdev,
        st_size: m.size as i64,
        st_blksize: i64::from(m.blksize),
        st_blocks: m.blocks as i64,
        st_atime: m.atime.sec as u64,
        st_atime_nsec: u64::from(m.atime.nsec),
        st_mtime: m.mtime.sec as u64,
        st_mtime_nsec: u64::from(m.mtime.nsec),
        st_ctime: m.ctime.sec as u64,
        st_ctime_nsec: u64::from(m.ctime.nsec),
        __unused: [0; 3],
    }
}

fn statx_time(t: Timespec) -> StatxTimestamp {
    StatxTimestamp { tv_sec: t.sec, tv_nsec: t.nsec, __reserved: 0 }
}

/// Reads up to `count` bytes with `f` to user memory at `buf`. A regular file reads in steps
/// until the count or the end of the file. Another file reads one time.
pub(crate) fn read_with(
    cx: &Cx<'_>,
    file: &File,
    buf: u64,
    count: u64,
    mut f: impl FnMut(u64, &mut [u8]) -> Result<usize, Errno>,
) -> SysResult {
    let count = (count as usize).min(MAX_RW_COUNT);
    let vm = cx.vm()?;
    let regular = file.inode().is_some();
    let mut chunk = vec![0u8; count.min(CHUNK)];
    let mut done = 0usize;
    while done < count {
        let n = (count - done).min(chunk.len());
        let got = match f(done as u64, &mut chunk[..n]) {
            Ok(got) => got,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        vm.write(buf as usize + done, &chunk[..got])?;
        done += got;
        if got < n || !regular {
            break;
        }
    }
    Ok(done as u64)
}

/// Writes up to `count` bytes from user memory at `buf` with `f`.
pub(crate) fn write_with(
    cx: &Cx<'_>,
    buf: u64,
    count: u64,
    mut f: impl FnMut(u64, &[u8]) -> Result<usize, Errno>,
) -> SysResult {
    let count = (count as usize).min(MAX_RW_COUNT);
    let vm = cx.vm()?;
    let mut chunk = vec![0u8; count.min(CHUNK)];
    let mut done = 0usize;
    while done < count {
        let n = (count - done).min(chunk.len());
        if let Err(e) = vm.read(buf as usize + done, &mut chunk[..n]) {
            if done == 0 {
                return Err(e);
            }
            break;
        }
        let put = match f(done as u64, &chunk[..n]) {
            Ok(put) => put,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        done += put;
        if put < n {
            break;
        }
    }
    Ok(done as u64)
}

pub(crate) fn read(cx: &Cx<'_>, fd: u64, buf: u64, count: u64) -> SysResult {
    let file = cx.file(fd)?;
    if let Some(sock) = rk_net::socket_of(&file) {
        return crate::net::read_socket(
            cx,
            &file,
            &*sock,
            &[Iovec { iov_base: buf, iov_len: count }],
        );
    }
    read_with(cx, &file, buf, count, |_, b| file.read(b))
}

pub(crate) fn write(cx: &Cx<'_>, fd: u64, buf: u64, count: u64) -> SysResult {
    let file = cx.file(fd)?;
    if !file.flags().writable() {
        return Err(Errno::EBADF);
    }
    if let Some(sock) = rk_net::socket_of(&file) {
        return crate::net::write_socket(
            cx,
            &file,
            &*sock,
            &[Iovec { iov_base: buf, iov_len: count }],
        );
    }
    let count = fsize_count(cx, &file, write_pos(&file), count)?;
    sigpipe(cx, write_with(cx, buf, count, |_, b| file.write(b)))
}

/// Gives the bytes of a write of `count` bytes at `pos` that `RLIMIT_FSIZE` lets a regular file
/// take, as `generic_write_check_limits` of Linux. A write that starts at or after the limit sends
/// `SIGXFSZ` and gives `EFBIG`.
fn fsize_count(cx: &Cx<'_>, file: &File, pos: u64, count: u64) -> Result<u64, Errno> {
    let limit = cx.process().limit(rk_proc::limits::RLIMIT_FSIZE).cur;
    if limit == rk_proc::limits::RLIM_INFINITY || count == 0 || !is_regular(file) {
        return Ok(count);
    }
    if pos >= limit {
        return Err(xfsz(cx));
    }
    Ok(count.min(limit - pos))
}

/// Checks a new size of a regular file against `RLIMIT_FSIZE`, as `inode_newsize_ok` of Linux. Only
/// a size that makes the file larger can go above the limit.
fn fsize_check(cx: &Cx<'_>, meta: &Metadata, size: u64) -> Result<(), Errno> {
    let limit = cx.process().limit(rk_proc::limits::RLIMIT_FSIZE).cur;
    if size > meta.size && size > limit && meta.file_type() == Some(rk_vfs::FileType::Regular) {
        return Err(xfsz(cx));
    }
    Ok(())
}

/// Sends `SIGXFSZ` to the thread and gives `EFBIG`.
fn xfsz(cx: &Cx<'_>) -> Errno {
    let pid = cx.process().pid();
    cx.thread.send_signal(SigInfo::new(SIGXFSZ, SI_USER, pid));
    Errno::EFBIG
}

fn is_regular(file: &File) -> bool {
    file.metadata().is_ok_and(|m| m.file_type() == Some(rk_vfs::FileType::Regular))
}

/// The position of the next `write` of `file`.
fn write_pos(file: &File) -> u64 {
    if file.flags().append() { file.metadata().map_or(0, |m| m.size) } else { file.pos() }
}

/// Sends `SIGPIPE` to the thread when a write gives `EPIPE`, as `pipe_write` of Linux does.
pub(crate) fn sigpipe(cx: &Cx<'_>, r: SysResult) -> SysResult {
    if r == Err(Errno::EPIPE) {
        let pid = cx.process().pid();
        cx.thread.send_signal(SigInfo::new(SIGPIPE, SI_USER, pid));
    }
    r
}

pub(crate) fn pread(cx: &Cx<'_>, fd: u64, buf: u64, count: u64, offset: u64) -> SysResult {
    if (offset as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    let file = cx.file(fd)?;
    if !file.ops().seekable() {
        return Err(Errno::ESPIPE);
    }
    read_with(cx, &file, buf, count, |done, b| file.read_at(offset + done, b))
}

pub(crate) fn pwrite(cx: &Cx<'_>, fd: u64, buf: u64, count: u64, offset: u64) -> SysResult {
    if (offset as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    let file = cx.file(fd)?;
    if !file.ops().seekable() {
        return Err(Errno::ESPIPE);
    }
    let count = fsize_count(cx, &file, offset, count)?;
    write_with(cx, buf, count, |done, b| file.write_at(offset + done, b))
}

pub(crate) fn read_iovecs(
    cx: &Cx<'_>,
    iov: u64,
    count: u64,
) -> Result<alloc::vec::Vec<Iovec>, Errno> {
    if count > UIO_MAXIOV {
        return Err(Errno::EINVAL);
    }
    let mut out = alloc::vec::Vec::with_capacity(count as usize);
    let mut total: u64 = 0;
    for i in 0..count {
        let v: Iovec = cx.read_val(iov + i * 16)?;
        if (v.iov_len as i64) < 0 {
            return Err(Errno::EINVAL);
        }
        total = total.saturating_add(v.iov_len);
        out.push(v);
    }
    if total > i64::MAX as u64 {
        return Err(Errno::EINVAL);
    }
    Ok(out)
}

pub(crate) fn readv(cx: &Cx<'_>, fd: u64, iov: u64, count: u64) -> SysResult {
    let file = cx.file(fd)?;
    if let Some(sock) = rk_net::socket_of(&file) {
        return crate::net::read_socket(cx, &file, &*sock, &read_iovecs(cx, iov, count)?);
    }
    let mut done = 0;
    for v in read_iovecs(cx, iov, count)? {
        if v.iov_len == 0 {
            continue;
        }
        let n = match read_with(cx, &file, v.iov_base, v.iov_len, |_, b| file.read(b)) {
            Ok(n) => n,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        done += n;
        if n < v.iov_len {
            break;
        }
    }
    Ok(done)
}

/// The flags of `preadv2` and `pwritev2`, as `RWF_*` of linux/fs.h.
mod rwf {
    pub(super) const HIPRI: u64 = 0x1;
    pub(super) const DSYNC: u64 = 0x2;
    pub(super) const SYNC: u64 = 0x4;
    pub(super) const NOWAIT: u64 = 0x8;
    pub(super) const APPEND: u64 = 0x10;
    pub(super) const NOAPPEND: u64 = 0x20;
    pub(super) const ATOMIC: u64 = 0x40;
    pub(super) const DONTCACHE: u64 = 0x80;
    /// The flags that Linux knows, as `RWF_SUPPORTED`.
    pub(super) const KNOWN: u64 =
        HIPRI | DSYNC | SYNC | NOWAIT | APPEND | NOAPPEND | ATOMIC | DONTCACHE;
}

/// `preadv`. A 64-bit kernel takes the full offset from the low register, as `pos_from_hilo` of
/// Linux. An offset of -1 gives `EINVAL`, as each negative offset.
pub(crate) fn preadv(cx: &Cx<'_>, fd: u64, iov: u64, count: u64, offset: u64) -> SysResult {
    if (offset as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    preadv2(cx, fd, iov, count, offset, 0)
}

/// `pwritev`, with the offset of `preadv`.
pub(crate) fn pwritev(cx: &Cx<'_>, fd: u64, iov: u64, count: u64, offset: u64) -> SysResult {
    if (offset as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    pwritev2(cx, fd, iov, count, offset, 0)
}

/// `preadv` and `preadv2`. An offset of -1 for `preadv2` reads at the position of the file, as
/// `readv`. The flags only change the speed, so the read does not use them.
pub(crate) fn preadv2(
    cx: &Cx<'_>,
    fd: u64,
    iov: u64,
    count: u64,
    offset: u64,
    flags: u64,
) -> SysResult {
    // The checks of `do_preadv`, `vfs_readv` and `kiocb_set_rw_flags` of Linux, in its order.
    if offset as i64 == -1 {
        check_rw_flags(flags, false)?;
        return readv(cx, fd, iov, count);
    }
    if (offset as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    let file = cx.file(fd)?;
    if !file.ops().seekable() {
        return Err(Errno::ESPIPE);
    }
    check_rw_flags(flags, false)?;
    let mut done = 0;
    for v in read_iovecs(cx, iov, count)? {
        if v.iov_len == 0 {
            continue;
        }
        let at = offset + done;
        let n = match read_with(cx, &file, v.iov_base, v.iov_len, |d, b| file.read_at(at + d, b)) {
            Ok(n) => n,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        done += n;
        if n < v.iov_len {
            break;
        }
    }
    Ok(done)
}

/// `pwritev` and `pwritev2`. An offset of -1 for `pwritev2` writes at the position of the file,
/// as `writev`. `RWF_APPEND` writes at the end, and `RWF_DSYNC` and `RWF_SYNC` sync the file
/// after the write.
pub(crate) fn pwritev2(
    cx: &Cx<'_>,
    fd: u64,
    iov: u64,
    count: u64,
    offset: u64,
    flags: u64,
) -> SysResult {
    if (offset as i64) < -1 {
        return Err(Errno::EINVAL);
    }
    let file = cx.file(fd)?;
    let done = if offset as i64 == -1 {
        check_rw_flags(flags, true)?;
        writev(cx, fd, iov, count)?
    } else {
        if !file.ops().seekable() {
            return Err(Errno::ESPIPE);
        }
        if !file.flags().writable() {
            return Err(Errno::EBADF);
        }
        check_rw_flags(flags, true)?;
        let mut offset = offset;
        if flags & rwf::APPEND != 0 {
            offset = file.metadata()?.size;
        }
        let iovs = read_iovecs(cx, iov, count)?;
        let total = iovs.iter().map(|v| v.iov_len).sum();
        let room = fsize_count(cx, &file, offset, total)?;
        let mut done = 0;
        for v in iovs {
            let len = v.iov_len.min(room - done);
            if len == 0 {
                continue;
            }
            let at = offset + done;
            let n = match write_with(cx, v.iov_base, len, |d, b| file.write_at(at + d, b)) {
                Ok(n) => n,
                Err(e) if done == 0 => return sigpipe(cx, Err(e)),
                Err(_) => break,
            };
            done += n;
            if n < len {
                break;
            }
        }
        done
    };
    if flags & (rwf::DSYNC | rwf::SYNC) != 0 && done > 0 {
        file.sync()?;
    }
    Ok(done)
}

/// Checks the flags of `preadv2` or `pwritev2`, as `kiocb_set_rw_flags` of Linux. The file
/// systems of rukernel have no atomic writes and no uncached I/O.
fn check_rw_flags(flags: u64, write: bool) -> Result<(), Errno> {
    if flags & !rwf::KNOWN != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if flags & rwf::ATOMIC != 0 {
        return Err(if write { Errno::EOPNOTSUPP } else { Errno::EINVAL });
    }
    if flags & rwf::DONTCACHE != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(())
}

pub(crate) fn writev(cx: &Cx<'_>, fd: u64, iov: u64, count: u64) -> SysResult {
    let file = cx.file(fd)?;
    if !file.flags().writable() {
        return Err(Errno::EBADF);
    }
    if let Some(sock) = rk_net::socket_of(&file) {
        return crate::net::write_socket(cx, &file, &*sock, &read_iovecs(cx, iov, count)?);
    }
    let iovs = read_iovecs(cx, iov, count)?;
    let total = iovs.iter().map(|v| v.iov_len).sum();
    let room = fsize_count(cx, &file, write_pos(&file), total)?;
    let mut done = 0;
    for v in iovs {
        let len = v.iov_len.min(room - done);
        if len == 0 {
            continue;
        }
        let n = match write_with(cx, v.iov_base, len, |_, b| file.write(b)) {
            Ok(n) => n,
            Err(e) if done == 0 => return sigpipe(cx, Err(e)),
            Err(_) => break,
        };
        done += n;
        if n < len {
            break;
        }
    }
    Ok(done)
}

pub(crate) fn openat(cx: &Cx<'_>, dirfd: u64, path: u64, flags: u64, mode: u64) -> SysResult {
    let path = cx.read_path(path)?;
    let fs = cx.fs()?;
    let start = cx.dir_start(&fs, dirfd, &path)?;
    let flags = flags as u32;
    let file = fs.open(&start, &path, flags, mode as u32)?;
    let fd = cx.files()?.lock().insert(file, flags & O_CLOEXEC != 0)?;
    Ok(fd as u64)
}

pub(crate) fn close(cx: &Cx<'_>, fd: u64) -> SysResult {
    let entry = cx.files()?.lock().remove(fd as i32)?;
    drop(entry);
    Ok(0)
}

pub(crate) fn lseek(cx: &Cx<'_>, fd: u64, offset: u64, whence: u64) -> SysResult {
    let file = cx.file(fd)?;
    let whence = Whence::from_raw(whence as u32).ok_or(Errno::EINVAL)?;
    file.seek(offset as i64, whence)
}

pub(crate) fn fstat(cx: &Cx<'_>, fd: u64, buf: u64) -> SysResult {
    let meta = cx.file(fd)?.metadata()?;
    cx.write_val(buf, &stat_of(&meta))?;
    Ok(0)
}

/// Finds the file of a `*at` call with `AT_EMPTY_PATH` and `AT_SYMLINK_NOFOLLOW`, and gives its
/// attributes.
fn lookup_meta(cx: &Cx<'_>, dirfd: u64, path: u64, flags: u32) -> Result<Metadata, Errno> {
    Ok(lookup(cx, dirfd, path, flags)?.0)
}

/// Gives the metadata of the file of `stat` and `statx`, its inode if it has one, and the ID of
/// its mount, or 0 for a file without a mount.
fn lookup(
    cx: &Cx<'_>,
    dirfd: u64,
    path: u64,
    flags: u32,
) -> Result<(Metadata, Option<rk_vfs::InodeRef>, u64), Errno> {
    let empty_ok = flags & AT_EMPTY_PATH as u32 != 0;
    let path = cx.read_path_opt(path, empty_ok)?;
    if path.is_empty() {
        if dirfd as i32 == rk_abi::native::at::AT_FDCWD {
            let fs = cx.fs()?;
            let inode = fs.cwd().inode().clone();
            return Ok((inode.metadata(), Some(inode), fs.cwd().mount.id()));
        }
        let file = cx.file(dirfd)?;
        let id = file.location().map_or(0, |at| at.mount.id());
        return Ok((file.metadata()?, file.inode().cloned(), id));
    }
    let fs = cx.fs()?;
    let start = cx.dir_start(&fs, dirfd, &path)?;
    let follow = flags & AT_SYMLINK_NOFOLLOW as u32 == 0;
    let at = fs.resolve(&start, &path, follow)?;
    let inode = at.inode().clone();
    Ok((inode.metadata(), Some(inode), at.mount.id()))
}

pub(crate) fn fstatat(cx: &Cx<'_>, dirfd: u64, path: u64, buf: u64, flags: u64) -> SysResult {
    let meta = lookup_meta(cx, dirfd, path, flags as u32)?;
    cx.write_val(buf, &stat_of(&meta))?;
    Ok(0)
}

pub(crate) fn statx(
    cx: &Cx<'_>,
    dirfd: u64,
    path: u64,
    flags: u64,
    _mask: u64,
    buf: u64,
) -> SysResult {
    let (meta, inode, mnt_id) = lookup(cx, dirfd, path, flags as u32)?;
    let mut s = Statx::new_zeroed();
    s.stx_mask = STATX_BASIC_STATS | STATX_MNT_ID;
    s.stx_mnt_id = mnt_id;
    // The `STATX_ATTR_*` bits of these flags are the bits of the inode flags.
    if let Some(Ok(f)) = inode.map(|i| i.attr_flags()) {
        let known =
            STATX_ATTR_COMPRESSED | STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND | STATX_ATTR_NODUMP;
        s.stx_attributes = u64::from(f) & known;
        s.stx_attributes_mask = known;
    }
    s.stx_blksize = meta.blksize;
    s.stx_nlink = meta.nlink;
    s.stx_uid = meta.uid;
    s.stx_gid = meta.gid;
    s.stx_mode = meta.mode as u16;
    s.stx_ino = meta.ino;
    s.stx_size = meta.size;
    s.stx_blocks = meta.blocks;
    s.stx_atime = statx_time(meta.atime);
    s.stx_ctime = statx_time(meta.ctime);
    s.stx_mtime = statx_time(meta.mtime);
    if let Some(btime) = meta.btime {
        s.stx_mask |= STATX_BTIME;
        s.stx_btime = statx_time(btime);
    }
    s.stx_rdev_major = major(meta.rdev);
    s.stx_rdev_minor = minor(meta.rdev);
    s.stx_dev_major = major(meta.dev);
    s.stx_dev_minor = minor(meta.dev);
    cx.write_val(buf, &s)?;
    Ok(0)
}

/// The `STATX_ATTR_*` bits of `stx_attributes`, from `<linux/stat.h>`.
const STATX_ATTR_COMPRESSED: u64 = 0x4;
const STATX_ATTR_IMMUTABLE: u64 = 0x10;
const STATX_ATTR_APPEND: u64 = 0x20;
const STATX_ATTR_NODUMP: u64 = 0x40;

/// The bits of `f_flags` of `statfs`, as `ST_*` of Linux. `ST_VALID` tells that the field is
/// set.
const ST_VALID: i64 = 0x20;
const ST_RELATIME: i64 = 0x1000;
const ST_NOSYMFOLLOW: i64 = 0x2000;

/// The `f_flags` field of `statfs` for a mount with the flags `flags`. The `ST_*` bits are the
/// `MS_*` bits, except for `ST_RELATIME` and `ST_NOSYMFOLLOW`.
fn statfs_flags(flags: u64) -> i64 {
    let flags = flags as u32;
    let same = MS_RDONLY
        | MS_NOSUID
        | MS_NODEV
        | MS_NOEXEC
        | MS_SYNCHRONOUS
        | MS_MANDLOCK
        | MS_NOATIME
        | MS_NODIRATIME;
    let mut out = i64::from(flags & same) | ST_VALID;
    if flags & MS_RELATIME != 0 {
        out |= ST_RELATIME;
    }
    if flags & MS_NOSYMFOLLOW != 0 {
        out |= ST_NOSYMFOLLOW;
    }
    out
}

fn statfs_of(meta: &Metadata, inode: Option<&rk_vfs::InodeRef>, flags: i64) -> Statfs {
    let magic = inode.map_or(0, |i| i.fs_magic());
    let mut s = Statfs::new_zeroed();
    s.f_type = if magic == 0 { TMPFS_MAGIC } else { magic as i64 };
    s.f_bsize = rk_mm::PAGE_SIZE as i64;
    s.f_frsize = rk_mm::PAGE_SIZE as i64;
    if let Some(st) = inode.and_then(|i| i.fs_stat()) {
        s.f_bsize = st.bsize as i64;
        s.f_frsize = st.bsize as i64;
        s.f_blocks = st.blocks as i64;
        s.f_bfree = st.bfree as i64;
        s.f_bavail = st.bavail as i64;
        s.f_files = st.files as i64;
        s.f_ffree = st.ffree as i64;
    }
    s.f_namelen = 255;
    s.f_fsid = KernelFsidT { val: [meta.dev as i32, (meta.dev >> 32) as i32] };
    s.f_flags = flags;
    s
}

pub(crate) fn statfs(cx: &Cx<'_>, path: u64, buf: u64) -> SysResult {
    let path = cx.read_path(path)?;
    let fs = cx.fs()?;
    let at = fs.resolve(fs.cwd(), &path, true)?;
    let flags = statfs_flags(at.mount.source().flags);
    cx.write_val(buf, &statfs_of(&at.inode().metadata(), Some(at.inode()), flags))?;
    Ok(0)
}

pub(crate) fn fstatfs(cx: &Cx<'_>, fd: u64, buf: u64) -> SysResult {
    let file = cx.file(fd)?;
    let at = file.location();
    let flags = at.map_or(ST_VALID, |at| statfs_flags(at.mount.source().flags));
    cx.write_val(buf, &statfs_of(&file.metadata()?, at.map(Location::inode), flags))?;
    Ok(0)
}

pub(crate) fn getdents64(cx: &Cx<'_>, fd: u64, buf: u64, count: u64) -> SysResult {
    let file = cx.file(fd)?;
    let mut data = vec![0u8; (count as usize).min(CHUNK)];
    let n = file.read_dir(&mut data)?;
    cx.write_bytes(buf, &data[..n])?;
    Ok(n as u64)
}

pub(crate) fn ioctl(cx: &Cx<'_>, fd: u64, cmd: u64, arg: u64) -> SysResult {
    let cmd = cmd as u32;
    match cmd {
        FIOCLEX | FIONCLEX => {
            cx.files()?.lock().set_cloexec(fd as i32, cmd == FIOCLEX)?;
            return Ok(0);
        }
        FIONBIO => {
            let file = cx.file(fd)?;
            let on: i32 = cx.read_val(arg)?;
            let flags = file.flags().0;
            file.set_status_flags(if on != 0 { flags | O_NONBLOCK } else { flags & !O_NONBLOCK });
            return Ok(0);
        }
        _ => {}
    }
    let file = cx.file(fd)?;
    use rk_vfs::file::{FIFREEZE, FITHAW, FITRIM};
    if matches!(cmd, FITRIM | FIFREEZE | FITHAW)
        && !cx.process().cred().capable(rk_vfs::cred::cap::SYS_ADMIN)
    {
        return Err(Errno::EPERM);
    }
    if let Some(notify) = crate::seccomp::listener_of(&file) {
        return crate::seccomp::listener_ioctl(cx, &notify, cmd, arg);
    }
    let vm = cx.vm()?;
    Ok(file.ioctl(cmd, arg as usize, &UserMem(&vm))? as u64)
}

fn dup_from(cx: &Cx<'_>, fd: u64, min: u64, cloexec: bool) -> SysResult {
    let files = cx.files()?;
    let mut table = files.lock();
    let file = table.file(fd as i32)?;
    let min = usize::try_from(min as i32).map_err(|_| Errno::EINVAL)?;
    Ok(table.insert_from(min, file, cloexec)? as u64)
}

pub(crate) fn dup(cx: &Cx<'_>, fd: u64) -> SysResult {
    dup_from(cx, fd, 0, false)
}

pub(crate) fn dup2(cx: &Cx<'_>, old: u64, new: u64) -> SysResult {
    if old as i32 == new as i32 {
        cx.file(old)?;
        return Ok(new);
    }
    dup3(cx, old, new, 0)
}

pub(crate) fn dup3(cx: &Cx<'_>, old: u64, new: u64, flags: u64) -> SysResult {
    let flags = flags as u32;
    if flags & !O_CLOEXEC != 0 || old as i32 == new as i32 {
        return Err(Errno::EINVAL);
    }
    let files = cx.files()?;
    let replaced = {
        let mut table = files.lock();
        let file = table.file(old as i32)?;
        table.set(new as i32, file, flags & O_CLOEXEC != 0)?
    };
    drop(replaced);
    Ok(new & 0xffff_ffff)
}

pub(crate) fn fcntl(cx: &Cx<'_>, fd: u64, cmd: u64, arg: u64) -> SysResult {
    let cmd = cmd as i32;
    match cmd {
        F_DUPFD => dup_from(cx, fd, arg, false),
        F_DUPFD_CLOEXEC => dup_from(cx, fd, arg, true),
        F_GETFD => {
            let files = cx.files()?;
            let table = files.lock();
            Ok(if table.get(fd as i32)?.cloexec { FD_CLOEXEC as u64 } else { 0 })
        }
        F_SETFD => {
            cx.files()?.lock().set_cloexec(fd as i32, arg as i32 & FD_CLOEXEC != 0)?;
            Ok(0)
        }
        F_GETFL => Ok(u64::from(cx.file(fd)?.flags().0)),
        F_SETFL => {
            let file = cx.file(fd)?;
            // Only `O_APPEND` and `O_NONBLOCK` change in R1. Linux also changes `O_ASYNC`,
            // `O_DIRECT` and `O_NOATIME`.
            // An append-only file keeps `O_APPEND`, as `setfl` of Linux.
            if arg as u32 & O_APPEND == 0
                && let Some(inode) = file.inode()
                && inode.attr_flags().unwrap_or(0) & rk_vfs::inode::iflags::APPEND != 0
            {
                return Err(Errno::EPERM);
            }
            let keep = file.flags().0 & !(O_APPEND | O_NONBLOCK);
            file.set_status_flags(keep | (arg as u32 & (O_APPEND | O_NONBLOCK)));
            Ok(0)
        }
        F_GETPIPE_SZ => Ok(rk_vfs::pipe::pipe_size(&*cx.file(fd)?)? as u64),
        F_SETPIPE_SZ => {
            let size = usize::try_from(arg as u32).map_err(|_| Errno::EINVAL)?;
            Ok(rk_vfs::pipe::set_pipe_size(&*cx.file(fd)?, size)? as u64)
        }
        F_GETLK | F_SETLK | F_SETLKW | F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW => {
            record_lock(cx, fd, cmd, arg)
        }
        _ => Err(Errno::EINVAL),
    }
}

/// The size of `struct flock`.
const FLOCK_SIZE: usize = 32;

/// The record lock commands of `fcntl`. The argument points to a `struct flock`: `l_type` at 0,
/// `l_whence` at 2, `l_start` at 8, `l_len` at 16 and `l_pid` at 24.
fn record_lock(cx: &Cx<'_>, fd: u64, cmd: i32, arg: u64) -> SysResult {
    let (file, table) = {
        let files = cx.files()?;
        let table = files.lock();
        (table.file(fd as i32)?, table.owner())
    };
    let raw = cx.read_bytes(arg, FLOCK_SIZE)?;
    let mut buf = [0u8; FLOCK_SIZE];
    buf.copy_from_slice(&raw);
    let i16_at = |o: usize| i16::from_ne_bytes([buf[o], buf[o + 1]]);
    let i64_at = |o: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&buf[o..o + 8]);
        i64::from_ne_bytes(b)
    };
    let ofd = matches!(cmd, F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW);
    if ofd && i32::from_ne_bytes([buf[24], buf[25], buf[26], buf[27]]) != 0 {
        return Err(Errno::EINVAL);
    }
    let kind = match i32::from(i16_at(0)) {
        F_RDLCK => Some(LockKind::Read),
        F_WRLCK => Some(LockKind::Write),
        F_UNLCK => None,
        _ => return Err(Errno::EINVAL),
    };
    let base = match i16_at(2) {
        0 => 0,
        1 => i64::try_from(file.pos()).map_err(|_| Errno::EOVERFLOW)?,
        2 => i64::try_from(file.metadata()?.size).map_err(|_| Errno::EOVERFLOW)?,
        _ => return Err(Errno::EINVAL),
    };
    let start = base.checked_add(i64_at(8)).ok_or(Errno::EOVERFLOW)?;
    let len = i64_at(16);
    // A length of 0 locks to the end of the file, and a negative length locks the bytes before
    // the start.
    let (first, end) = match len {
        0 => (start, u64::MAX),
        1.. => (start, start.checked_add(len - 1).ok_or(Errno::EOVERFLOW)? as u64),
        _ => (start.checked_add(len).ok_or(Errno::EINVAL)?, start.wrapping_sub(1) as u64),
    };
    let first = u64::try_from(first).map_err(|_| Errno::EINVAL)?;
    let (owner, pid) = if ofd {
        (Owner::File(lock::file_id(&file)), -1)
    } else {
        (Owner::Posix(table), cx.process().pid() as i32)
    };
    let request = RecordLock { owner, kind: LockKind::Read, start: first, end, pid };
    if matches!(cmd, F_GETLK | F_OFD_GETLK) {
        let kind = kind.ok_or(Errno::EINVAL)?;
        let found = lock::test(&file, &RecordLock { kind, ..request })?;
        let Some(holder) = found else {
            // No lock conflicts, so only `l_type` changes.
            cx.write_bytes(arg, &(F_UNLCK as i16).to_ne_bytes())?;
            return Ok(0);
        };
        let held = if holder.kind == LockKind::Write { F_WRLCK } else { F_RDLCK };
        let len = if holder.end == u64::MAX { 0 } else { holder.end - holder.start + 1 };
        buf[0..2].copy_from_slice(&(held as i16).to_ne_bytes());
        buf[2..4].copy_from_slice(&0i16.to_ne_bytes());
        buf[8..16].copy_from_slice(&(holder.start as i64).to_ne_bytes());
        buf[16..24].copy_from_slice(&(len as i64).to_ne_bytes());
        buf[24..28].copy_from_slice(&holder.pid.to_ne_bytes());
        cx.write_bytes(arg, &buf)?;
        return Ok(0);
    }
    let mode = file.flags();
    match kind {
        Some(LockKind::Read) if !mode.readable() => return Err(Errno::EBADF),
        Some(LockKind::Write) if !mode.writable() => return Err(Errno::EBADF),
        _ => {}
    }
    lock::set(&file, request, kind, matches!(cmd, F_SETLKW | F_OFD_SETLKW))?;
    Ok(0)
}

/// The operations of `flock`, from `<sys/file.h>`.
const LOCK_SH: u32 = 1;
const LOCK_EX: u32 = 2;
const LOCK_NB: u32 = 4;
const LOCK_UN: u32 = 8;

pub(crate) fn flock(cx: &Cx<'_>, fd: u64, op: u64) -> SysResult {
    let file = cx.file(fd)?;
    let op = op as u32;
    let kind = match op & !LOCK_NB {
        LOCK_SH => Some(LockKind::Read),
        LOCK_EX => Some(LockKind::Write),
        LOCK_UN => None,
        _ => return Err(Errno::EINVAL),
    };
    lock::flock(&file, kind, op & LOCK_NB == 0)?;
    Ok(0)
}

pub(crate) fn getcwd(cx: &Cx<'_>, buf: u64, size: u64) -> SysResult {
    let mut path = cx.fs()?.getcwd()?;
    path.push(0);
    if path.len() as u64 > size {
        return Err(Errno::ERANGE);
    }
    cx.write_bytes(buf, &path)?;
    Ok(path.len() as u64)
}

pub(crate) fn chdir(cx: &Cx<'_>, path: u64) -> SysResult {
    let path = cx.read_path(path)?;
    let fs = cx.fs()?;
    let at = fs.resolve(fs.cwd(), &path, true)?;
    fs.check_dir(&at)?;
    cx.fs_shared()?.lock().set_cwd(at)?;
    Ok(0)
}

pub(crate) fn fchdir(cx: &Cx<'_>, fd: u64) -> SysResult {
    let at = cx.file(fd)?.location().ok_or(Errno::ENOTDIR)?.clone();
    cx.fs()?.check_dir(&at)?;
    cx.fs_shared()?.lock().set_cwd(at)?;
    Ok(0)
}

pub(crate) fn mkdirat(cx: &Cx<'_>, dirfd: u64, path: u64, mode: u64) -> SysResult {
    let path = cx.read_path(path)?;
    let fs = cx.fs()?;
    let start = cx.dir_start(&fs, dirfd, &path)?;
    fs.mkdir(&start, &path, mode as u32)?;
    Ok(0)
}

pub(crate) fn mknodat(cx: &Cx<'_>, dirfd: u64, path: u64, mode: u64, dev: u64) -> SysResult {
    let path = cx.read_path(path)?;
    let fs = cx.fs()?;
    let start = cx.dir_start(&fs, dirfd, &path)?;
    fs.mknod(&start, &path, mode as u32, dev)?;
    Ok(0)
}

pub(crate) fn unlinkat(cx: &Cx<'_>, dirfd: u64, path: u64, flags: u64) -> SysResult {
    let flags = flags as u32;
    if flags & !(AT_REMOVEDIR as u32) != 0 {
        return Err(Errno::EINVAL);
    }
    let path = cx.read_path(path)?;
    let fs = cx.fs()?;
    let start = cx.dir_start(&fs, dirfd, &path)?;
    fs.remove(&start, &path, flags & AT_REMOVEDIR as u32 != 0)?;
    Ok(0)
}

pub(crate) fn renameat2(
    cx: &Cx<'_>,
    olddir: u64,
    old: u64,
    newdir: u64,
    new: u64,
    flags: u64,
) -> SysResult {
    let old = cx.read_path(old)?;
    let new = cx.read_path(new)?;
    let fs = cx.fs()?;
    let old_start = cx.dir_start(&fs, olddir, &old)?;
    let new_start = cx.dir_start(&fs, newdir, &new)?;
    fs.rename(&old_start, &old, &new_start, &new, flags as u32)?;
    Ok(0)
}

pub(crate) fn linkat(
    cx: &Cx<'_>,
    olddir: u64,
    old: u64,
    newdir: u64,
    new: u64,
    flags: u64,
) -> SysResult {
    let flags = flags as u32;
    if flags & !(AT_SYMLINK_FOLLOW as u32 | AT_EMPTY_PATH as u32) != 0 {
        return Err(Errno::EINVAL);
    }
    let old = cx.read_path_opt(old, flags & AT_EMPTY_PATH as u32 != 0)?;
    let new = cx.read_path(new)?;
    let fs = cx.fs()?;
    let target: Location = if old.is_empty() {
        cx.file(olddir)?.location().ok_or(Errno::ENOENT)?.clone()
    } else {
        let start = cx.dir_start(&fs, olddir, &old)?;
        fs.resolve(&start, &old, flags & AT_SYMLINK_FOLLOW as u32 != 0)?
    };
    let start = cx.dir_start(&fs, newdir, &new)?;
    fs.link(&target, &start, &new)?;
    Ok(0)
}

pub(crate) fn symlinkat(cx: &Cx<'_>, target: u64, newdir: u64, path: u64) -> SysResult {
    let target = cx.read_path(target)?;
    let path = cx.read_path(path)?;
    let fs = cx.fs()?;
    let start = cx.dir_start(&fs, newdir, &path)?;
    fs.symlink(&target, &start, &path)?;
    Ok(0)
}

pub(crate) fn readlinkat(cx: &Cx<'_>, dirfd: u64, path: u64, buf: u64, size: u64) -> SysResult {
    if (size as i64) <= 0 {
        return Err(Errno::EINVAL);
    }
    let path = cx.read_path(path)?;
    let fs = cx.fs()?;
    let start = cx.dir_start(&fs, dirfd, &path)?;
    let target = fs.read_link(&start, &path)?;
    let n = target.len().min(size as usize).min(PATH_MAX);
    cx.write_bytes(buf, &target[..n])?;
    Ok(n as u64)
}

/// The kind of a change of attributes, for the checks that depend on the call.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Change {
    /// `chmod` and `utimensat` with a time that is not now.
    Plain,
    /// `chown`, which clears the set-user-ID bit.
    Owner,
    /// `utimensat` that sets both times to now. The owner or a process that can write the file
    /// can do it.
    Touch,
}

/// Checks and makes the change `attr` of the attributes of `inode`, as `notify_change` of
/// Linux.
fn change_attr(cx: &Cx<'_>, inode: &rk_vfs::InodeRef, attr: &SetAttr, change: Change) -> SysResult {
    rk_vfs::inode::check_set_attr(&**inode, attr)?;
    let cred = cx.process().cred();
    let meta = inode.metadata();
    if change == Change::Touch && !cred.owns(&meta) {
        cred.inode_permission(&**inode, rk_vfs::cred::may::WRITE)?;
    }
    let mut attr = *attr;
    cred.setattr_prepare(&meta, &mut attr)?;
    if change == Change::Owner {
        cred.chown_kill(&meta, &mut attr);
    }
    inode.set_attr(&attr)?;
    if let Some(mode) = attr.mode {
        rk_vfs::acl::chmod(&**inode, mode)?;
    }
    Ok(0)
}

fn set_attr_at(
    cx: &Cx<'_>,
    dirfd: u64,
    path: u64,
    follow: bool,
    attr: &SetAttr,
    change: Change,
) -> SysResult {
    let path = cx.read_path(path)?;
    let fs = cx.fs()?;
    let start = cx.dir_start(&fs, dirfd, &path)?;
    let at = fs.resolve(&start, &path, follow)?;
    change_attr(cx, at.inode(), attr, change)
}

fn set_attr_fd(cx: &Cx<'_>, fd: u64, attr: &SetAttr, change: Change) -> SysResult {
    let file = cx.file(fd)?;
    let inode = file.inode().ok_or(Errno::EBADF)?;
    change_attr(cx, inode, attr, change)
}

pub(crate) fn fchmodat(cx: &Cx<'_>, dirfd: u64, path: u64, mode: u64) -> SysResult {
    let attr = SetAttr { mode: Some(mode as u32 & 0o7777), ..SetAttr::default() };
    set_attr_at(cx, dirfd, path, true, &attr, Change::Plain)
}

pub(crate) fn fchmod(cx: &Cx<'_>, fd: u64, mode: u64) -> SysResult {
    let attr = SetAttr { mode: Some(mode as u32 & 0o7777), ..SetAttr::default() };
    set_attr_fd(cx, fd, &attr, Change::Plain)
}

/// The owner of `chown`: -1 keeps the value.
fn owner(id: u64) -> Option<u32> {
    if id as u32 == u32::MAX { None } else { Some(id as u32) }
}

pub(crate) fn fchownat(
    cx: &Cx<'_>,
    dirfd: u64,
    path: u64,
    uid: u64,
    gid: u64,
    flags: u64,
) -> SysResult {
    let attr = SetAttr { uid: owner(uid), gid: owner(gid), ..SetAttr::default() };
    let follow = flags as u32 & AT_SYMLINK_NOFOLLOW as u32 == 0;
    set_attr_at(cx, dirfd, path, follow, &attr, Change::Owner)
}

pub(crate) fn fchown(cx: &Cx<'_>, fd: u64, uid: u64, gid: u64) -> SysResult {
    let attr = SetAttr { uid: owner(uid), gid: owner(gid), ..SetAttr::default() };
    set_attr_fd(cx, fd, &attr, Change::Owner)
}

pub(crate) fn umask(cx: &Cx<'_>, mask: u64) -> SysResult {
    Ok(u64::from(cx.fs_shared()?.lock().set_umask(mask as u32 & 0o777)))
}

pub(crate) fn faccessat(cx: &Cx<'_>, dirfd: u64, path: u64, mode: u64, flags: u64) -> SysResult {
    if mode & !7 != 0 {
        return Err(Errno::EINVAL);
    }
    let flags = flags as u32;
    if flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) as u32 != 0 {
        return Err(Errno::EINVAL);
    }
    let (meta, inode, _) = lookup(cx, dirfd, path, flags)?;
    if mode == 0 {
        return Ok(0);
    }
    // Without `AT_EACCESS`, the check uses the real IDs, as `access_override_creds` of Linux.
    let cred = cx.process().cred();
    let cred = if flags & AT_EACCESS as u32 == 0 { cred.for_access() } else { (*cred).clone() };
    match inode {
        Some(inode) => cred.inode_permission(&*inode, mode as u32)?,
        None => cred.permission(&meta, mode as u32)?,
    }
    Ok(0)
}

pub(crate) fn truncate(cx: &Cx<'_>, path: u64, size: u64) -> SysResult {
    if (size as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    let path = cx.read_path(path)?;
    let fs = cx.fs()?;
    let at = fs.resolve(fs.cwd(), &path, true)?;
    if at.inode().metadata().is_dir() {
        return Err(Errno::EISDIR);
    }
    fs.permission(&at, rk_vfs::cred::may::WRITE)?;
    fsize_check(cx, &at.inode().metadata(), size)?;
    let mode = fs.cred().write_kill(&at.inode().metadata());
    let attr = SetAttr { size: Some(size), mode, ..SetAttr::default() };
    rk_vfs::inode::check_set_attr(&**at.inode(), &attr)?;
    at.inode().set_attr(&attr)?;
    rk_vfs::mapped::changed(at.inode(), size, u64::MAX);
    Ok(0)
}

pub(crate) fn ftruncate(cx: &Cx<'_>, fd: u64, size: u64) -> SysResult {
    if (size as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    let file = cx.file(fd)?;
    if let Ok(meta) = file.metadata()
        && file.flags().writable()
    {
        fsize_check(cx, &meta, size)?;
    }
    file.truncate(size)?;
    Ok(0)
}

/// Writes back a range of a file. The page cache has no partial write back, so a request with flags
/// syncs all the file. The checks are those of `ksys_sync_file_range` of Linux, in its order.
pub(crate) fn sync_file_range(
    cx: &Cx<'_>,
    fd: u64,
    offset: u64,
    nbytes: u64,
    flags: u64,
) -> SysResult {
    const ALL: u64 = 1 | 2 | 4; // WAIT_BEFORE, WRITE and WAIT_AFTER.
    let (offset, nbytes) = (offset as i64, nbytes as i64);
    if flags & !ALL != 0 || offset < 0 || nbytes < 0 || offset.checked_add(nbytes).is_none() {
        return Err(Errno::EINVAL);
    }
    let file = cx.file(fd)?;
    use rk_vfs::FileType::{BlockDevice, Directory, Regular, Symlink};
    let kind = file.metadata()?.file_type();
    if !matches!(kind, Some(Regular | Directory | BlockDevice | Symlink)) {
        return Err(Errno::ESPIPE);
    }
    if flags != 0 {
        file.sync()?;
    }
    Ok(0)
}

pub(crate) fn fallocate(cx: &Cx<'_>, fd: u64, mode: u64, offset: u64, len: u64) -> SysResult {
    use rk_vfs::inode::falloc::*;
    let mode = mode as u32;
    let (offset, len) = (offset as i64, len as i64);
    // The checks of `vfs_fallocate` of Linux, in its order.
    if offset < 0 || len <= 0 {
        return Err(Errno::EINVAL);
    }
    let all = KEEP_SIZE | PUNCH_HOLE | COLLAPSE_RANGE | ZERO_RANGE | INSERT_RANGE | UNSHARE_RANGE;
    if mode & !all != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    match mode & !KEEP_SIZE {
        0 | ZERO_RANGE | UNSHARE_RANGE => {}
        PUNCH_HOLE if mode & KEEP_SIZE != 0 => {}
        COLLAPSE_RANGE | INSERT_RANGE if mode & KEEP_SIZE == 0 => {}
        COLLAPSE_RANGE | INSERT_RANGE => return Err(Errno::EINVAL),
        _ => return Err(Errno::EOPNOTSUPP),
    }
    let end = offset.checked_add(len).ok_or(Errno::EFBIG)?;
    let file = cx.file(fd)?;
    // A change that can make the file larger checks `RLIMIT_FSIZE`, as ext4 and XFS of Linux do.
    if mode & KEEP_SIZE == 0 && matches!(mode, 0 | ZERO_RANGE) && file.flags().writable() {
        fsize_check(cx, &file.metadata()?, end as u64)?;
    }
    file.fallocate(mode, offset as u64, (end - offset) as u64)?;
    Ok(0)
}

/// `UTIME_NOW` and `UTIME_OMIT` of `utimensat`.
const UTIME_NOW: i64 = (1 << 30) - 1;
const UTIME_OMIT: i64 = (1 << 30) - 2;

pub(crate) fn utimensat(cx: &Cx<'_>, dirfd: u64, path: u64, times: u64, flags: u64) -> SysResult {
    let now = rk_vfs::inode::now();
    let mut explicit_times = false;
    let (atime, mtime) = if times == 0 {
        (Some(now), Some(now))
    } else {
        let t: [rk_abi::native::types::KernelTimespec; 2] = cx.read_val(times)?;
        let mut conv = |ts: rk_abi::native::types::KernelTimespec| match ts.tv_nsec {
            UTIME_NOW => Ok(Some(now)),
            UTIME_OMIT => Ok(None),
            n if (0..1_000_000_000).contains(&n) => {
                explicit_times = true;
                Ok(Some(Timespec { sec: ts.tv_sec, nsec: n as u32 }))
            }
            _ => Err(Errno::EINVAL),
        };
        (conv(t[0])?, conv(t[1])?)
    };
    // Both times now is a touch, which the owner or a process that can write the file can do.
    let change = if atime == Some(now) && mtime == Some(now) && !explicit_times {
        Change::Touch
    } else {
        Change::Plain
    };
    let attr = SetAttr { atime, mtime, explicit_times, ..SetAttr::default() };
    if path == 0 {
        return set_attr_fd(cx, dirfd, &attr, change);
    }
    let follow = flags as u32 & AT_SYMLINK_NOFOLLOW as u32 == 0;
    let path_bytes = cx.read_path_opt(path, flags as u32 & AT_EMPTY_PATH as u32 != 0)?;
    if path_bytes.is_empty() {
        return set_attr_fd(cx, dirfd, &attr, change);
    }
    set_attr_at(cx, dirfd, path, follow, &attr, change)
}

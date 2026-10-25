//! The system calls of files, descriptors and paths.

use crate::cx::{Cx, PATH_MAX, SysResult, UserMem};
use alloc::vec;
use rk_abi::Errno;
use rk_abi::native::at::{AT_EMPTY_PATH, AT_REMOVEDIR, AT_SYMLINK_FOLLOW, AT_SYMLINK_NOFOLLOW};
use rk_abi::native::fcntl::{
    F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_GETFL, F_GETLK, F_GETPIPE_SZ, F_OFD_GETLK, F_OFD_SETLK,
    F_OFD_SETLKW, F_SETFD, F_SETFL, F_SETLK, F_SETLKW, F_SETPIPE_SZ, FD_CLOEXEC,
};
use rk_abi::native::ioctls::{FIOCLEX, FIONBIO, FIONCLEX};
use rk_abi::native::open::{O_APPEND, O_CLOEXEC, O_NONBLOCK};
use rk_abi::native::signal::SIGPIPE;
use rk_abi::native::stat::{STATX_BASIC_STATS, STATX_MNT_ID};
use rk_abi::native::types::{Iovec, KernelFsidT, Stat, Statfs, Statx, StatxTimestamp};
use rk_proc::signal::{SI_USER, SigInfo};
use rk_vfs::device::{major, minor};
use rk_vfs::inode::{Metadata, SetAttr, Timespec};
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
    sigpipe(cx, write_with(cx, buf, count, |_, b| file.write(b)))
}

/// Sends `SIGPIPE` to the thread when a write gives `EPIPE`, as `pipe_write` of Linux does.
fn sigpipe(cx: &Cx<'_>, r: SysResult) -> SysResult {
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

pub(crate) fn writev(cx: &Cx<'_>, fd: u64, iov: u64, count: u64) -> SysResult {
    let file = cx.file(fd)?;
    if !file.flags().writable() {
        return Err(Errno::EBADF);
    }
    if let Some(sock) = rk_net::socket_of(&file) {
        return crate::net::write_socket(cx, &file, &*sock, &read_iovecs(cx, iov, count)?);
    }
    let mut done = 0;
    for v in read_iovecs(cx, iov, count)? {
        if v.iov_len == 0 {
            continue;
        }
        let n = match write_with(cx, v.iov_base, v.iov_len, |_, b| file.write(b)) {
            Ok(n) => n,
            Err(e) if done == 0 => return sigpipe(cx, Err(e)),
            Err(_) => break,
        };
        done += n;
        if n < v.iov_len {
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
    let empty_ok = flags & AT_EMPTY_PATH as u32 != 0;
    let path = cx.read_path_opt(path, empty_ok)?;
    if path.is_empty() {
        if dirfd as i32 == rk_abi::native::at::AT_FDCWD {
            return Ok(cx.fs()?.cwd().inode().metadata());
        }
        return cx.file(dirfd)?.metadata();
    }
    let fs = cx.fs()?;
    let start = cx.dir_start(&fs, dirfd, &path)?;
    let follow = flags & AT_SYMLINK_NOFOLLOW as u32 == 0;
    Ok(fs.resolve(&start, &path, follow)?.inode().metadata())
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
    let meta = lookup_meta(cx, dirfd, path, flags as u32)?;
    let mut s = Statx::new_zeroed();
    s.stx_mask = STATX_BASIC_STATS | STATX_MNT_ID;
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
    s.stx_rdev_major = major(meta.rdev);
    s.stx_rdev_minor = minor(meta.rdev);
    s.stx_dev_major = major(meta.dev);
    s.stx_dev_minor = minor(meta.dev);
    cx.write_val(buf, &s)?;
    Ok(0)
}

fn statfs_of(meta: &Metadata, magic: u64) -> Statfs {
    let mut s = Statfs::new_zeroed();
    s.f_type = if magic == 0 { TMPFS_MAGIC } else { magic as i64 };
    s.f_bsize = rk_mm::PAGE_SIZE as i64;
    s.f_frsize = rk_mm::PAGE_SIZE as i64;
    s.f_namelen = 255;
    s.f_fsid = KernelFsidT { val: [meta.dev as i32, (meta.dev >> 32) as i32] };
    s
}

pub(crate) fn statfs(cx: &Cx<'_>, path: u64, buf: u64) -> SysResult {
    let path = cx.read_path(path)?;
    let fs = cx.fs()?;
    let inode = fs.resolve(fs.cwd(), &path, true)?.inode().clone();
    cx.write_val(buf, &statfs_of(&inode.metadata(), inode.fs_magic()))?;
    Ok(0)
}

pub(crate) fn fstatfs(cx: &Cx<'_>, fd: u64, buf: u64) -> SysResult {
    let file = cx.file(fd)?;
    let magic = file.location().map_or(0, |at| at.inode().fs_magic());
    cx.write_val(buf, &statfs_of(&file.metadata()?, magic))?;
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
            let keep = file.flags().0 & !(O_APPEND | O_NONBLOCK);
            file.set_status_flags(keep | (arg as u32 & (O_APPEND | O_NONBLOCK)));
            Ok(0)
        }
        F_GETPIPE_SZ => Ok(rk_vfs::pipe::pipe_size(&*cx.file(fd)?)? as u64),
        F_SETPIPE_SZ => {
            let size = usize::try_from(arg as u32).map_err(|_| Errno::EINVAL)?;
            Ok(rk_vfs::pipe::set_pipe_size(&*cx.file(fd)?, size)? as u64)
        }
        // A process has no other process that shares its files in R1, so each lock succeeds.
        F_GETLK | F_SETLK | F_SETLKW | F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW => {
            cx.file(fd)?;
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
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
    let shared = cx.fs_shared()?;
    let fs = shared.lock().clone();
    let at = fs.resolve(fs.cwd(), &path, true)?;
    shared.lock().set_cwd(at)?;
    Ok(0)
}

pub(crate) fn fchdir(cx: &Cx<'_>, fd: u64) -> SysResult {
    let at = cx.file(fd)?.location().ok_or(Errno::ENOTDIR)?.clone();
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

fn set_attr_at(cx: &Cx<'_>, dirfd: u64, path: u64, follow: bool, attr: &SetAttr) -> SysResult {
    let path = cx.read_path(path)?;
    let fs = cx.fs()?;
    let start = cx.dir_start(&fs, dirfd, &path)?;
    fs.resolve(&start, &path, follow)?.inode().set_attr(attr)?;
    Ok(0)
}

fn set_attr_fd(cx: &Cx<'_>, fd: u64, attr: &SetAttr) -> SysResult {
    let file = cx.file(fd)?;
    file.inode().ok_or(Errno::EBADF)?.set_attr(attr)?;
    Ok(0)
}

pub(crate) fn fchmodat(cx: &Cx<'_>, dirfd: u64, path: u64, mode: u64) -> SysResult {
    let attr = SetAttr { mode: Some(mode as u32 & 0o7777), ..SetAttr::default() };
    set_attr_at(cx, dirfd, path, true, &attr)
}

pub(crate) fn fchmod(cx: &Cx<'_>, fd: u64, mode: u64) -> SysResult {
    set_attr_fd(cx, fd, &SetAttr { mode: Some(mode as u32 & 0o7777), ..SetAttr::default() })
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
    set_attr_at(cx, dirfd, path, follow, &attr)
}

/// The extended attribute calls on the path `path`. No file system keeps extended attributes
/// yet. A list is empty, a read or a removal gives `ENODATA`, and a change gives `EOPNOTSUPP`.
/// The file must be there. The caller gives the error, or `None` for a list.
pub(crate) fn path_xattr(cx: &Cx<'_>, path: u64, follow: bool, error: Option<Errno>) -> SysResult {
    let flags = if follow { 0 } else { AT_SYMLINK_NOFOLLOW as u32 };
    lookup_meta(cx, rk_abi::native::at::AT_FDCWD as i64 as u64, path, flags)?;
    error.map_or(Ok(0), Err)
}

/// The extended attribute calls on the file `fd`, as `path_xattr`.
pub(crate) fn fd_xattr(cx: &Cx<'_>, fd: u64, error: Option<Errno>) -> SysResult {
    cx.file(fd)?;
    error.map_or(Ok(0), Err)
}

pub(crate) fn fchown(cx: &Cx<'_>, fd: u64, uid: u64, gid: u64) -> SysResult {
    set_attr_fd(cx, fd, &SetAttr { uid: owner(uid), gid: owner(gid), ..SetAttr::default() })
}

pub(crate) fn umask(cx: &Cx<'_>, mask: u64) -> SysResult {
    Ok(u64::from(cx.fs_shared()?.lock().set_umask(mask as u32 & 0o777)))
}

pub(crate) fn faccessat(cx: &Cx<'_>, dirfd: u64, path: u64, mode: u64, flags: u64) -> SysResult {
    if mode & !7 != 0 {
        return Err(Errno::EINVAL);
    }
    let meta = lookup_meta(cx, dirfd, path, flags as u32)?;
    // The caller is root in R1. Root can read and write each file, and can run a file that has
    // an execute bit or is a directory.
    if mode & 1 != 0 && meta.mode & 0o111 == 0 && !meta.is_dir() {
        return Err(Errno::EACCES);
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
    at.inode().set_attr(&SetAttr { size: Some(size), ..SetAttr::default() })?;
    Ok(0)
}

pub(crate) fn ftruncate(cx: &Cx<'_>, fd: u64, size: u64) -> SysResult {
    if (size as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    cx.file(fd)?.truncate(size)?;
    Ok(0)
}

/// `UTIME_NOW` and `UTIME_OMIT` of `utimensat`.
const UTIME_NOW: i64 = (1 << 30) - 1;
const UTIME_OMIT: i64 = (1 << 30) - 2;

pub(crate) fn utimensat(cx: &Cx<'_>, dirfd: u64, path: u64, times: u64, flags: u64) -> SysResult {
    let now = rk_vfs::inode::now();
    let (atime, mtime) = if times == 0 {
        (Some(now), Some(now))
    } else {
        let t: [rk_abi::native::types::KernelTimespec; 2] = cx.read_val(times)?;
        let conv = |ts: rk_abi::native::types::KernelTimespec| match ts.tv_nsec {
            UTIME_NOW => Ok(Some(now)),
            UTIME_OMIT => Ok(None),
            n if (0..1_000_000_000).contains(&n) => {
                Ok(Some(Timespec { sec: ts.tv_sec, nsec: n as u32 }))
            }
            _ => Err(Errno::EINVAL),
        };
        (conv(t[0])?, conv(t[1])?)
    };
    let attr = SetAttr { atime, mtime, ..SetAttr::default() };
    if path == 0 {
        return set_attr_fd(cx, dirfd, &attr);
    }
    let follow = flags as u32 & AT_SYMLINK_NOFOLLOW as u32 == 0;
    let path_bytes = cx.read_path_opt(path, flags as u32 & AT_EMPTY_PATH as u32 != 0)?;
    if path_bytes.is_empty() {
        return set_attr_fd(cx, dirfd, &attr);
    }
    set_attr_at(cx, dirfd, path, follow, &attr)
}

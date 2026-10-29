//! The system calls that copy data from one file to another in the kernel: `sendfile`, `splice`
//! and `copy_file_range`, and the `fadvise64` call.
//!
//! Each call copies through a buffer in the kernel. Linux moves pages of the page cache, but the
//! result that a program sees is the same.

use crate::cx::{Cx, SysResult};
use alloc::vec;
use rk_abi::Errno;
use rk_vfs::File;
use rk_vfs::inode::FileType;
use rk_vfs::pipe::{PIPE_BUF, pipe_size, pipe_space, put_to_pipe, take_from_pipe};

/// The most bytes of one call. Linux names it `MAX_RW_COUNT`.
const MAX_RW_COUNT: usize = 0x7fff_f000;
/// The most bytes that the kernel copies in one step.
const CHUNK: usize = 64 * 1024;
/// The flags of `splice` that Linux knows: `SPLICE_F_MOVE`, `SPLICE_F_NONBLOCK`, `SPLICE_F_MORE`
/// and `SPLICE_F_GIFT`.
const SPLICE_F_ALL: u64 = 0xf;
/// The `SPLICE_F_NONBLOCK` flag: a pipe that is not ready gives `EAGAIN`.
const SPLICE_F_NONBLOCK: u64 = 0x2;
/// The `O_NONBLOCK` flag of a file, which Linux adds as `SPLICE_F_NONBLOCK` for `tee`.
fn nonblock(flags: u64, files: &[&File]) -> bool {
    flags & SPLICE_F_NONBLOCK != 0 || files.iter().any(|f| f.flags().nonblock())
}
/// The largest advice of `fadvise64`: `POSIX_FADV_NOREUSE`.
const POSIX_FADV_NOREUSE: u64 = 5;

/// Tells if `file` is one end of a pipe.
fn is_pipe(file: &File) -> bool {
    pipe_size(file).is_ok()
}

/// Tells if `file` has the splice operations of Linux (`splice_read` and `splice_write`). A file
/// in the tree other than a directory, a pipe and a socket have them. A directory and a file of
/// an anonymous inode, as an eventfd, an epoll, a signalfd, a timerfd, a pidfd or an inotify
/// file, have neither, so `splice` gives `EINVAL` before it waits for the pipe, as
/// `warn_unsupported` in fs/splice.c of Linux.
fn can_splice(file: &File) -> bool {
    let kind = file.metadata().ok().and_then(|m| m.file_type());
    if kind == Some(FileType::Directory) {
        return false;
    }
    file.location().is_some() || is_pipe(file) || kind == Some(FileType::Socket)
}

/// Reads the offset at the user pointer `addr`. A null pointer gives `None`, and the copy then
/// uses the position of the file. A negative offset gives `EINVAL`.
fn offset_at(cx: &Cx<'_>, addr: u64) -> Result<Option<u64>, Errno> {
    if addr == 0 {
        return Ok(None);
    }
    let off: i64 = cx.read_val(addr)?;
    if off < 0 {
        return Err(Errno::EINVAL);
    }
    Ok(Some(off as u64))
}

/// Copies up to `count` bytes from `input` to `output`. An offset reads or writes at that place
/// and does not move the position of the file. Without an offset, the copy uses the position.
/// A file that is not regular reads one time, as `read` does. Gives the count of bytes that the
/// copy wrote. An error after some bytes stops the copy and gives the count.
fn copy(
    input: &File,
    in_off: Option<u64>,
    output: &File,
    out_off: Option<u64>,
    count: usize,
) -> Result<usize, Errno> {
    let count = count.min(MAX_RW_COUNT);
    let regular = input.inode().is_some();
    let mut chunk = vec![0u8; count.min(CHUNK)];
    let mut done = 0usize;
    while done < count {
        let mut n = (count - done).min(chunk.len());
        // A copy into a pipe writes what fits, as Linux. A full pipe waits for space only before
        // the first byte: a write of up to `PIPE_BUF` bytes waits until all of it fits.
        if let Ok(space) = pipe_space(output) {
            match space {
                0 if done > 0 => break,
                0 => n = n.min(PIPE_BUF),
                _ => n = n.min(space),
            }
        }
        let read = match in_off {
            Some(off) => input.read_at(off + done as u64, &mut chunk[..n]),
            None => input.read(&mut chunk[..n]),
        };
        let got = match read {
            Ok(got) => got,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        if got == 0 {
            break;
        }
        let mut put = 0usize;
        while put < got {
            let write = match out_off {
                Some(off) => output.write_at(off + (done + put) as u64, &chunk[put..got]),
                None => output.write(&chunk[put..got]),
            };
            match write {
                Ok(0) => break,
                Ok(w) => put += w,
                Err(e) if done + put == 0 => return Err(e),
                Err(_) => break,
            }
        }
        done += put;
        if put < got || got < n || !regular {
            break;
        }
    }
    Ok(done)
}

/// Writes `off + done` back to the user pointer `addr`, if the call has an offset there.
fn update_offset(cx: &Cx<'_>, addr: u64, off: Option<u64>, done: usize) -> Result<(), Errno> {
    if let Some(off) = off {
        cx.write_val(addr, &((off + done as u64) as i64))?;
    }
    Ok(())
}

/// Sends `SIGPIPE` for a write to a pipe with no read end, as `write` does.
fn sigpipe(cx: &Cx<'_>, r: Result<usize, Errno>) -> SysResult {
    crate::fs::sigpipe(cx, r.map(|n| n as u64))
}

pub(crate) fn sendfile(cx: &Cx<'_>, out_fd: u64, in_fd: u64, offset: u64, count: u64) -> SysResult {
    let input = cx.file(in_fd)?;
    let output = cx.file(out_fd)?;
    if !input.flags().readable() || !output.flags().writable() {
        return Err(Errno::EBADF);
    }
    // Linux reads the input through the page cache, so the input must be a file that can seek.
    if !input.ops().seekable() {
        return Err(Errno::EINVAL);
    }
    if output.flags().append() {
        return Err(Errno::EINVAL);
    }
    let off = offset_at(cx, offset)?;
    let done = copy(&input, off, &output, None, count as usize);
    if let Ok(n) = done {
        update_offset(cx, offset, off, n)?;
    }
    sigpipe(cx, done)
}

pub(crate) fn splice(
    cx: &Cx<'_>,
    in_fd: u64,
    in_off: u64,
    out_fd: u64,
    out_off: u64,
    len: u64,
    flags: u64,
) -> SysResult {
    if flags & !SPLICE_F_ALL != 0 {
        return Err(Errno::EINVAL);
    }
    let input = cx.file(in_fd)?;
    let output = cx.file(out_fd)?;
    if !input.flags().readable() || !output.flags().writable() {
        return Err(Errno::EBADF);
    }
    let (in_pipe, out_pipe) = (is_pipe(&input), is_pipe(&output));
    if !in_pipe && !out_pipe {
        return Err(Errno::EINVAL);
    }
    // A pipe has no offset.
    if (in_pipe && in_off != 0) || (out_pipe && out_off != 0) {
        return Err(Errno::ESPIPE);
    }
    if output.flags().append() {
        return Err(Errno::EINVAL);
    }
    let in_pos = offset_at(cx, in_off)?;
    let out_pos = offset_at(cx, out_off)?;
    if (in_pos.is_some() && !input.ops().seekable())
        || (out_pos.is_some() && !output.ops().seekable())
    {
        return Err(Errno::ESPIPE);
    }
    // A splice from a pipe needs `splice_write` of the output, as `do_splice_from`, also for a
    // length of 0. A splice to a pipe needs `splice_read` of the input after the check of the
    // length, as `vfs_splice_read`.
    if in_pipe && !out_pipe && !can_splice(&output) {
        return Err(Errno::EINVAL);
    }
    if len == 0 {
        return Ok(0);
    }
    if out_pipe && !in_pipe && !can_splice(&input) {
        return Err(Errno::EINVAL);
    }
    let done = copy(&input, in_pos, &output, out_pos, len as usize);
    if let Ok(n) = done {
        update_offset(cx, in_off, in_pos, n)?;
        update_offset(cx, out_off, out_pos, n)?;
    }
    sigpipe(cx, done)
}

/// `tee`, as fs/splice.c of Linux: copies data from one pipe to another and leaves it in the
/// first pipe.
pub(crate) fn tee(cx: &Cx<'_>, in_fd: u64, out_fd: u64, len: u64, flags: u64) -> SysResult {
    if flags & !SPLICE_F_ALL != 0 {
        return Err(Errno::EINVAL);
    }
    let input = cx.file(in_fd)?;
    let output = cx.file(out_fd)?;
    if !input.flags().readable() || !output.flags().writable() {
        return Err(Errno::EBADF);
    }
    if len == 0 {
        return Ok(0);
    }
    let nb = nonblock(flags, &[&input, &output]);
    let len = (len as usize).min(MAX_RW_COUNT);
    sigpipe(cx, rk_vfs::pipe::tee(&input, &output, len, nb))
}

/// `vmsplice`, as fs/splice.c of Linux. For a file that writes, the call copies user memory into
/// the pipe. Else it copies data of the pipe to user memory. A pipe that is not ready waits,
/// except with `SPLICE_F_NONBLOCK` or `O_NONBLOCK`.
pub(crate) fn vmsplice(cx: &Cx<'_>, fd: u64, iov: u64, nr_segs: u64, flags: u64) -> SysResult {
    if flags & !SPLICE_F_ALL != 0 {
        return Err(Errno::EINVAL);
    }
    let file = cx.file(fd)?;
    let (readable, writable) = (file.flags().readable(), file.flags().writable());
    if !readable && !writable {
        return Err(Errno::EBADF);
    }
    let iovecs = crate::fs::read_iovecs(cx, iov, nr_segs)?;
    let total: u64 = iovecs.iter().map(|v| v.iov_len).sum();
    if total == 0 {
        return Ok(0);
    }
    let size = pipe_size(&file)?;
    let nb = nonblock(flags, &[&file]);
    let want = (total as usize).min(size).min(MAX_RW_COUNT);
    if writable {
        // Read only what the pipe can hold. A bad address after some bytes stops the copy.
        let mut data = vec![];
        for v in &iovecs {
            let n = (v.iov_len as usize).min(want - data.len());
            match cx.read_bytes(v.iov_base, n) {
                Ok(b) => data.extend_from_slice(&b),
                Err(e) if data.is_empty() => return Err(e),
                Err(_) => break,
            }
            if data.len() == want {
                break;
            }
        }
        return sigpipe(cx, put_to_pipe(&file, &data, nb));
    }
    let data = take_from_pipe(&file, want, nb)?;
    let mut done = 0;
    for v in &iovecs {
        if done == data.len() {
            break;
        }
        let n = (v.iov_len as usize).min(data.len() - done);
        if let Err(e) = cx.write_bytes(v.iov_base, &data[done..done + n]) {
            if done == 0 {
                return Err(e);
            }
            break;
        }
        done += n;
    }
    Ok(done as u64)
}

pub(crate) fn copy_file_range(
    cx: &Cx<'_>,
    in_fd: u64,
    in_off: u64,
    out_fd: u64,
    out_off: u64,
    len: u64,
    flags: u64,
) -> SysResult {
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    let input = cx.file(in_fd)?;
    let output = cx.file(out_fd)?;
    // The checks of `generic_file_rw_checks` of Linux, in its order: the types of the files come
    // before their modes.
    let in_meta = input.metadata()?;
    let out_meta = output.metadata()?;
    if in_meta.is_dir() || out_meta.is_dir() {
        return Err(Errno::EISDIR);
    }
    let regular =
        |m: &rk_vfs::inode::Metadata| m.file_type() == Some(rk_vfs::inode::FileType::Regular);
    if !regular(&in_meta) || !regular(&out_meta) {
        return Err(Errno::EINVAL);
    }
    if !input.flags().readable() || !output.flags().writable() || output.flags().append() {
        return Err(Errno::EBADF);
    }
    // `generic_copy_file_checks` of Linux: an active swap area is not copied from or to.
    for file in [&input, &output] {
        if let Some(inode) = file.inode() {
            rk_vfs::swap::check(&**inode)?;
        }
    }
    let in_pos = offset_at(cx, in_off)?;
    let out_pos = offset_at(cx, out_off)?;
    let in_start = in_pos.unwrap_or_else(|| input.pos());
    let out_start = out_pos.unwrap_or_else(|| output.pos());
    // `generic_copy_file_checks` of Linux: the offsets must not wrap. Then the copy stops at the
    // end of the input, and a start at the largest file size gives `EFBIG`.
    if in_start.checked_add(len).is_none() || out_start.checked_add(len).is_none() {
        return Err(Errno::EOVERFLOW);
    }
    let max = i64::MAX as u64;
    let len = len.min(in_meta.size.saturating_sub(in_start));
    if out_start >= max {
        return Err(Errno::EFBIG);
    }
    let len = len.min(max - out_start);
    if in_start.checked_add(len).is_none_or(|e| e > max) {
        return Err(Errno::EOVERFLOW);
    }
    // The two ranges of one file must not overlap.
    if in_meta.dev == out_meta.dev
        && in_meta.ino == out_meta.ino
        && in_start < out_start + len
        && out_start < in_start + len
    {
        return Err(Errno::EINVAL);
    }
    if len == 0 {
        return Ok(0);
    }
    let n = copy(&input, Some(in_start), &output, Some(out_start), len as usize)?;
    match in_pos {
        Some(_) => update_offset(cx, in_off, in_pos, n)?,
        None => input.set_pos(in_start + n as u64),
    }
    match out_pos {
        Some(_) => update_offset(cx, out_off, out_pos, n)?,
        None => output.set_pos(out_start + n as u64),
    }
    Ok(n as u64)
}

/// `fadvise64`. The kernel keeps no page cache policy, so a valid advice does nothing.
pub(crate) fn fadvise64(cx: &Cx<'_>, fd: u64, _offset: u64, len: u64, advice: u64) -> SysResult {
    let file = cx.file(fd)?;
    if is_pipe(&file) {
        return Err(Errno::ESPIPE);
    }
    if advice > POSIX_FADV_NOREUSE || (len as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}

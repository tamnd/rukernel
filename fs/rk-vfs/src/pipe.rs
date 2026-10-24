//! Pipes: a buffer in memory with a read end and a write end, as fs/pipe.c of Linux has them.
//!
//! A read waits until data comes or each write end is closed. A write of up to `PIPE_BUF` bytes
//! is atomic: it waits until the buffer has space for all of it. A write to a pipe that has no
//! read end gives `EPIPE`, and the system call layer sends `SIGPIPE`.

use crate::file::{File, FileOps, UserMemory, events};
use crate::inode::{Metadata, Result};
use crate::wait::{WaitQueue, poll_wake};
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::ioctls::FIONREAD;
use rk_abi::native::stat::S_IFIFO;
use rk_frame::sync::SpinLock;

/// The size of a write that is atomic. Linux names it `PIPE_BUF`.
pub const PIPE_BUF: usize = 4096;

/// The capacity of a pipe, the default of Linux: 16 pages.
pub const PIPE_SIZE: usize = 65536;

struct State {
    buf: VecDeque<u8>,
    /// The capacity in bytes. `F_SETPIPE_SZ` changes it.
    size: usize,
    readers: usize,
    writers: usize,
}

/// The buffer that the two ends share.
struct Pipe {
    state: SpinLock<State>,
    /// The readers and the writers wait here.
    wait: WaitQueue,
    ino: u64,
    /// The count of the events for the read end: data came or each write end closed.
    read_events: AtomicU64,
    /// The count of the events for the write end: space came or each read end closed.
    write_events: AtomicU64,
}

impl Pipe {
    /// Wakes the waiters. `readers` tells if the event is for the read end or the write end.
    fn wake(&self, readers: bool) {
        let count = if readers { &self.read_events } else { &self.write_events };
        count.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
        poll_wake();
    }
}

/// One end of a pipe. Each end is the operations of one open file. When the file closes, the
/// end goes away.
struct PipeEnd {
    pipe: Arc<Pipe>,
    write: bool,
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        {
            let mut s = self.pipe.state.lock();
            if self.write {
                s.writers -= 1;
            } else {
                s.readers -= 1;
            }
        }
        self.pipe.wake(self.write);
    }
}

/// The device of the pipe file system.
fn pipe_dev() -> u64 {
    static DEV: AtomicU64 = AtomicU64::new(0);
    let dev = DEV.load(Ordering::Relaxed);
    if dev != 0 {
        return dev;
    }
    let new = crate::inode::anon_dev();
    match DEV.compare_exchange(0, new, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => new,
        Err(old) => old,
    }
}

impl FileOps for PipeEnd {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        if self.write {
            return Err(Errno::EBADF);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let nonblock = file.flags().nonblock();
        let n = self.pipe.wait.wait_interruptible(|| {
            let mut s = self.pipe.state.lock();
            if !s.buf.is_empty() {
                let n = buf.len().min(s.buf.len());
                for (d, b) in buf.iter_mut().zip(s.buf.drain(..n)) {
                    *d = b;
                }
                return Ok(Some(n));
            }
            if s.writers == 0 {
                return Ok(Some(0));
            }
            if nonblock { Err(Errno::EAGAIN) } else { Ok(None) }
        })?;
        if n > 0 {
            self.pipe.wake(false);
        }
        Ok(n)
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize> {
        if !self.write {
            return Err(Errno::EBADF);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let nonblock = file.flags().nonblock();
        let mut done = 0;
        while done < buf.len() {
            let rest = &buf[done..];
            let r = self.pipe.wait.wait_interruptible(|| {
                let mut s = self.pipe.state.lock();
                if s.readers == 0 {
                    return Err(Errno::EPIPE);
                }
                let space = s.size.saturating_sub(s.buf.len());
                // A small write goes in one piece, so it waits for space for all of it.
                let need = if rest.len() <= PIPE_BUF { rest.len() } else { 1 };
                if space >= need {
                    let n = rest.len().min(space);
                    s.buf.extend(&rest[..n]);
                    return Ok(Some(n));
                }
                if nonblock { Err(Errno::EAGAIN) } else { Ok(None) }
            });
            match r {
                Ok(n) => {
                    done += n;
                    self.pipe.wake(true);
                }
                Err(e) if done == 0 => return Err(e),
                Err(_) => break,
            }
        }
        Ok(done)
    }

    fn ioctl(&self, _file: &File, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        match cmd {
            FIONREAD => {
                let n = self.pipe.state.lock().buf.len() as i32;
                mem.write(arg, &n.to_ne_bytes())?;
                Ok(0)
            }
            _ => Err(Errno::ENOTTY),
        }
    }

    fn pollable(&self) -> bool {
        true
    }

    fn event_count(&self) -> u64 {
        let count = if self.write { &self.pipe.write_events } else { &self.pipe.read_events };
        count.load(Ordering::Relaxed)
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }

    fn poll(&self, _file: &File) -> u32 {
        let s = self.pipe.state.lock();
        if self.write {
            let mut ev = 0;
            if s.size.saturating_sub(s.buf.len()) >= PIPE_BUF.min(s.size) {
                ev |= events::POLLOUT;
            }
            if s.readers == 0 {
                ev |= events::POLLERR;
            }
            ev
        } else {
            let mut ev = 0;
            if !s.buf.is_empty() {
                ev |= events::POLLIN;
            }
            if s.writers == 0 {
                ev |= events::POLLHUP;
            }
            ev
        }
    }

    fn metadata(&self) -> Option<Metadata> {
        Some(Metadata {
            dev: pipe_dev(),
            ino: self.pipe.ino,
            mode: S_IFIFO | 0o600,
            nlink: 1,
            blksize: PIPE_BUF as u32,
            ..Metadata::default()
        })
    }
}

/// The largest capacity of a pipe, the default of `/proc/sys/fs/pipe-max-size` of Linux.
pub const PIPE_MAX_SIZE: usize = 1 << 20;

const PAGE_SIZE: usize = 4096;

fn end_of(file: &File) -> Result<&PipeEnd> {
    file.ops().as_any().and_then(|a| a.downcast_ref::<PipeEnd>()).ok_or(Errno::EBADF)
}

/// The capacity of the pipe of `file`, for `F_GETPIPE_SZ`.
///
/// # Errors
///
/// Gives `EBADF` if the file is not a pipe.
pub fn pipe_size(file: &File) -> Result<usize> {
    Ok(end_of(file)?.pipe.state.lock().size)
}

/// Sets the capacity of the pipe of `file`, for `F_SETPIPE_SZ`. The size goes up to a power of
/// two count of pages, as `round_pipe_size` of Linux does. Gives the new capacity.
///
/// # Errors
///
/// Gives `EBADF` if the file is not a pipe, `EINVAL` for a size that is too large, `EPERM` for
/// a size above `PIPE_MAX_SIZE`, and `EBUSY` if the pipe holds more data than the new capacity.
pub fn set_pipe_size(file: &File, size: usize) -> Result<usize> {
    let end = end_of(file)?;
    if size > (1 << 31) {
        return Err(Errno::EINVAL);
    }
    let size = size.max(PAGE_SIZE).div_ceil(PAGE_SIZE).next_power_of_two() * PAGE_SIZE;
    if size > PIPE_MAX_SIZE {
        return Err(Errno::EPERM);
    }
    {
        let mut s = end.pipe.state.lock();
        if s.buf.len() > size {
            return Err(Errno::EBUSY);
        }
        s.size = size;
    }
    end.pipe.wake(false);
    Ok(size)
}

/// Makes a pipe, and gives the read end and the write end. `flags` holds `O_NONBLOCK` for both
/// files.
pub fn pipe(flags: u32) -> (Arc<File>, Arc<File>) {
    use rk_abi::native::open::{O_RDONLY, O_WRONLY};
    static NEXT_INO: AtomicU64 = AtomicU64::new(1);
    let pipe = Arc::new(Pipe {
        state: SpinLock::new(State {
            buf: VecDeque::new(),
            size: PIPE_SIZE,
            readers: 1,
            writers: 1,
        }),
        wait: WaitQueue::new(),
        ino: NEXT_INO.fetch_add(1, Ordering::Relaxed),
        read_events: AtomicU64::new(0),
        write_events: AtomicU64::new(0),
    });
    let r = Arc::new(PipeEnd { pipe: pipe.clone(), write: false });
    let w = Arc::new(PipeEnd { pipe, write: true });
    (File::with_ops(r, None, O_RDONLY | flags), File::with_ops(w, None, O_WRONLY | flags))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rk_abi::native::open::O_NONBLOCK;

    #[test]
    fn data_goes_from_the_write_end_to_the_read_end() {
        let (r, w) = pipe(O_NONBLOCK);
        assert_eq!(r.read(&mut [0u8; 4]).unwrap_err(), Errno::EAGAIN);
        assert_eq!(w.write(b"abcde").unwrap(), 5);
        assert_eq!(r.poll(), events::POLLIN);
        assert_eq!(w.poll(), events::POLLOUT);
        let mut buf = [0u8; 3];
        assert_eq!(r.read(&mut buf).unwrap(), 3);
        assert_eq!(&buf, b"abc");
        let mut buf = [0u8; 8];
        assert_eq!(r.read(&mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], b"de");
        assert_eq!(w.read(&mut buf).unwrap_err(), Errno::EBADF);
        assert_eq!(r.write(b"x").unwrap_err(), Errno::EBADF);
        let meta = r.metadata().unwrap();
        assert_eq!(meta.mode & 0o170000, S_IFIFO);
    }

    #[test]
    fn a_full_pipe_takes_part_of_a_large_write() {
        let (r, w) = pipe(O_NONBLOCK);
        let big = alloc::vec![7u8; PIPE_SIZE + 100];
        assert_eq!(w.write(&big).unwrap(), PIPE_SIZE);
        assert_eq!(w.poll(), 0);
        assert_eq!(w.write(b"x").unwrap_err(), Errno::EAGAIN);
        let mut buf = alloc::vec![0u8; PIPE_BUF - 1];
        assert_eq!(r.read(&mut buf).unwrap(), PIPE_BUF - 1);
        // A small write waits for space for all of its bytes.
        assert_eq!(w.write(&[1u8; PIPE_BUF]).unwrap_err(), Errno::EAGAIN);
        drop(r);
        assert_eq!(w.write(b"x").unwrap_err(), Errno::EPIPE);
        assert_eq!(w.poll(), events::POLLERR);
    }

    #[test]
    fn a_closed_write_end_gives_end_of_file() {
        let (r, w) = pipe(0);
        w.write(b"ab").unwrap();
        drop(w);
        assert_eq!(r.poll(), events::POLLIN | events::POLLHUP);
        let mut buf = [0u8; 4];
        assert_eq!(r.read(&mut buf).unwrap(), 2);
        assert_eq!(r.read(&mut buf).unwrap(), 0);
        assert_eq!(r.poll(), events::POLLHUP);
    }
}

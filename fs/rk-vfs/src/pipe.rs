//! Pipes: a buffer in memory with a read end and a write end, as fs/pipe.c of Linux has them.
//!
//! A read waits until data comes or each write end is closed. A write of up to `PIPE_BUF` bytes
//! is atomic: it waits until the buffer has space for all of it. A write to a pipe that has no
//! read end gives `EPIPE`, and the system call layer sends `SIGPIPE`.
//!
//! A named pipe, or FIFO, is a pipe that a file of the type `S_IFIFO` names. Each open of the
//! file gives an end of one pipe, which lives while one end is open. An open for reading waits
//! for a writer, and an open for writing waits for a reader, as `fifo_open` of Linux.

use crate::file::{File, FileOps, UserMemory, events};
use crate::inode::{Inode, InodeRef, Metadata, Result, SetAttr};
use crate::wait::{PollTable, WaitQueue};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
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
    /// The count of the opens of each type, so an open that waits sees an open and a close
    /// that came before it ran again.
    reader_opens: u64,
    writer_opens: u64,
}

/// The buffer that the two ends share.
struct Pipe {
    state: SpinLock<State>,
    /// The readers and the writers wait here.
    wait: Arc<WaitQueue>,
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
    }
}

/// One end of a pipe. Each end is the operations of one open file. When the file closes, the
/// end goes away. An open of a FIFO with `O_RDWR` gives an end that reads and writes.
struct PipeEnd {
    pipe: Arc<Pipe>,
    read: bool,
    write: bool,
    /// The end is of a FIFO, so `fstat` gives the attributes of the file of the FIFO.
    named: bool,
}

impl PipeEnd {
    /// Makes an end and counts it in the pipe.
    fn new(pipe: Arc<Pipe>, read: bool, write: bool, named: bool) -> Self {
        {
            let mut s = pipe.state.lock();
            if read {
                s.readers += 1;
                s.reader_opens += 1;
            }
            if write {
                s.writers += 1;
                s.writer_opens += 1;
            }
        }
        if named {
            pipe.wake(true);
            pipe.wake(false);
        }
        Self { pipe, read, write, named }
    }
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        {
            let mut s = self.pipe.state.lock();
            if self.read {
                s.readers -= 1;
            }
            if self.write {
                s.writers -= 1;
            }
        }
        if self.read {
            self.pipe.wake(false);
        }
        if self.write {
            self.pipe.wake(true);
        }
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
        if !self.read {
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
        let mut n = 0u64;
        if self.read {
            n = n.wrapping_add(self.pipe.read_events.load(Ordering::Relaxed));
        }
        if self.write {
            n = n.wrapping_add(self.pipe.write_events.load(Ordering::Relaxed));
        }
        n
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }

    fn poll_wait(&self, _file: &File, table: &mut PollTable) {
        table.add(&self.pipe.wait);
    }

    fn poll(&self, _file: &File) -> u32 {
        let s = self.pipe.state.lock();
        let mut ev = 0;
        if self.write {
            if s.size.saturating_sub(s.buf.len()) >= PIPE_BUF.min(s.size) {
                ev |= events::POLLOUT;
            }
            if s.readers == 0 {
                ev |= events::POLLERR;
            }
        }
        if self.read {
            if !s.buf.is_empty() {
                ev |= events::POLLIN;
            }
            if s.writers == 0 {
                ev |= events::POLLHUP;
            }
        }
        ev
    }

    fn metadata(&self) -> Option<Metadata> {
        if self.named {
            return None;
        }
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

/// The free space in the pipe of `file`. `splice` and `sendfile` write only this much, so a copy
/// into a full pipe does not wait for all of its data to go in.
///
/// # Errors
///
/// Gives `EBADF` if the file is not a pipe.
pub fn pipe_space(file: &File) -> Result<usize> {
    let s = end_of(file)?.pipe.state.lock();
    Ok(s.size.saturating_sub(s.buf.len()))
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
    let pipe = new_pipe();
    let r = Arc::new(PipeEnd::new(pipe.clone(), true, false, false));
    let w = Arc::new(PipeEnd::new(pipe, false, true, false));
    (File::with_ops(r, None, O_RDONLY | flags), File::with_ops(w, None, O_WRONLY | flags))
}

/// Makes a pipe with no ends.
fn new_pipe() -> Arc<Pipe> {
    static NEXT_INO: AtomicU64 = AtomicU64::new(1);
    Arc::new(Pipe {
        state: SpinLock::new(State {
            buf: VecDeque::new(),
            size: PIPE_SIZE,
            readers: 0,
            writers: 0,
            reader_opens: 0,
            writer_opens: 0,
        }),
        wait: Arc::new(WaitQueue::new()),
        ino: NEXT_INO.fetch_add(1, Ordering::Relaxed),
        read_events: AtomicU64::new(0),
        write_events: AtomicU64::new(0),
    })
}

/// The pipes of the FIFOs that have an open end, by the device and the inode number of the file.
static FIFOS: SpinLock<BTreeMap<(u64, u64), Weak<Pipe>>> = SpinLock::new(BTreeMap::new());

/// Opens the FIFO with the device `dev` and the inode number `ino`, with the access mode and
/// `O_NONBLOCK` in `flags`. An open for reading waits for a writer, and an open for writing waits
/// for a reader, unless `O_NONBLOCK` is set. An open with `O_RDWR` does not wait.
///
/// # Errors
///
/// Gives `ENXIO` for an open for writing with `O_NONBLOCK` when the FIFO has no reader, and
/// `ERESTARTSYS` if a signal stops the wait.
pub fn open_fifo(dev: u64, ino: u64, flags: u32) -> Result<Arc<dyn FileOps>> {
    let pipe = {
        let mut fifos = FIFOS.lock();
        fifos.retain(|_, p| p.strong_count() > 0);
        match fifos.get(&(dev, ino)).and_then(Weak::upgrade) {
            Some(pipe) => pipe,
            None => {
                let pipe = new_pipe();
                fifos.insert((dev, ino), Arc::downgrade(&pipe));
                pipe
            }
        }
    };
    open_end(pipe, flags, true)
}

/// Opens a new end of `pipe`, with the access mode and `O_NONBLOCK` in `flags`, as `fifo_open`
/// of Linux. `named` is for an end of a FIFO. An open of a pipe without a name does not wait
/// and does not give `ENXIO`, because the other end can be closed already.
fn open_end(pipe: Arc<Pipe>, flags: u32, named: bool) -> Result<Arc<dyn FileOps>> {
    use rk_abi::native::open::{O_ACCMODE, O_NONBLOCK, O_RDWR, O_WRONLY};
    let nonblock = flags & O_NONBLOCK != 0;
    let (read, write) = match flags & O_ACCMODE {
        O_RDWR => (true, true),
        O_WRONLY => (false, true),
        _ => (true, false),
    };
    if named && write && !read && nonblock && pipe.state.lock().readers == 0 {
        return Err(Errno::ENXIO);
    }
    let (readers, writers) = {
        let s = pipe.state.lock();
        (s.reader_opens, s.writer_opens)
    };
    let end = PipeEnd::new(pipe.clone(), read, write, named);
    if named && !nonblock && read != write {
        pipe.wait.wait_interruptible(|| {
            let s = pipe.state.lock();
            let ready = if read {
                s.writers > 0 || s.writer_opens != writers
            } else {
                s.readers > 0 || s.reader_opens != readers
            };
            Ok(ready.then_some(()))
        })?;
    }
    Ok(Arc::new(end))
}

/// The inode of an open pipe, which a walk reaches through a link of `/proc/PID/fd`. An open of
/// it gives a new end of the same pipe, as an open of the inode of pipefs does on Linux.
struct PipeInode {
    pipe: Weak<Pipe>,
    ino: u64,
    uid: u32,
    gid: u32,
}

impl Inode for PipeInode {
    fn metadata(&self) -> Metadata {
        Metadata {
            dev: pipe_dev(),
            ino: self.ino,
            mode: S_IFIFO | 0o600,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            blksize: PIPE_BUF as u32,
            ..Metadata::default()
        }
    }

    fn set_attr(&self, _attr: &SetAttr) -> Result<()> {
        Err(Errno::EPERM)
    }
}

/// The inode of the pipe of `file`, or `None` if the file is not a pipe. The inode belongs to the
/// current file system user, who made the pipe or can see its descriptor.
pub fn pipe_inode(file: &File) -> Option<InodeRef> {
    let end = end_of(file).ok()?;
    let cred = crate::cred::current();
    Some(Arc::new(PipeInode {
        pipe: Arc::downgrade(&end.pipe),
        ino: end.pipe.ino,
        uid: cred.fsuid,
        gid: cred.fsgid,
    }))
}

/// Opens a new end of the pipe of `inode`, if it is an inode that `pipe_inode` made.
///
/// # Errors
///
/// Gives `ENOENT` if each end of the pipe is closed, and the errors of `open_fifo`.
pub(crate) fn open_pipe_inode(inode: &dyn Inode, flags: u32) -> Option<Result<Arc<dyn FileOps>>> {
    let any: &dyn core::any::Any = inode;
    let p = any.downcast_ref::<PipeInode>()?;
    Some(p.pipe.upgrade().ok_or(Errno::ENOENT).and_then(|pipe| open_end(pipe, flags, false)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rk_abi::native::open::O_NONBLOCK;

    #[test]
    fn an_open_of_the_inode_of_a_pipe_gives_an_end_of_the_same_pipe() {
        use rk_abi::native::open::{O_RDONLY, O_WRONLY};
        let (r, w) = pipe(0);
        let inode = pipe_inode(&r).unwrap();
        assert_eq!(inode.metadata().ino, r.metadata().unwrap().ino);
        assert_eq!(w.write(b"ab").unwrap(), 2);
        drop(w);
        // The write end is closed, and the open does not wait for a writer.
        let again = File::with_ops(open_pipe_inode(&*inode, O_RDONLY).unwrap().unwrap(), None, 0);
        let mut buf = [0u8; 4];
        assert_eq!(again.read(&mut buf).unwrap(), 2);
        assert_eq!(again.read(&mut buf).unwrap(), 0);
        drop(r);
        drop(again);
        assert_eq!(open_pipe_inode(&*inode, O_WRONLY).unwrap().err(), Some(Errno::ENOENT));
    }

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
    fn a_fifo_shares_one_pipe_between_its_opens() {
        use rk_abi::native::open::{O_RDONLY, O_RDWR, O_WRONLY};
        assert_eq!(open_fifo(9, 1, O_WRONLY | O_NONBLOCK).err(), Some(Errno::ENXIO));
        let r = File::with_ops(open_fifo(9, 1, O_RDONLY | O_NONBLOCK).unwrap(), None, O_RDONLY);
        let w = File::with_ops(open_fifo(9, 1, O_WRONLY | O_NONBLOCK).unwrap(), None, O_WRONLY);
        assert_eq!(w.write(b"abc").unwrap(), 3);
        let mut buf = [0u8; 4];
        assert_eq!(r.read(&mut buf).unwrap(), 3);
        assert!(w.metadata().is_err());
        let rw = File::with_ops(open_fifo(9, 2, O_RDWR).unwrap(), None, O_RDWR);
        assert_eq!(rw.write(b"x").unwrap(), 1);
        assert_eq!(rw.poll(), events::POLLIN | events::POLLOUT);
        assert_eq!(rw.read(&mut buf).unwrap(), 1);
        drop((r, w, rw));
        assert!(FIFOS.lock().values().all(|p| p.strong_count() == 0));
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

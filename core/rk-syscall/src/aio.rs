//! The asynchronous I/O of Linux: `io_setup`, `io_destroy`, `io_submit`, `io_cancel`,
//! `io_getevents` and `io_pgetevents`, from fs/aio.c.
//!
//! A context holds the events of the requests that are done. Its ID is the address of a page
//! that `io_setup` maps in the process, as in Linux. In Linux the page is the start of a ring of
//! events that user space can read. Here the page has zeros, so the magic number of the ring is
//! not there, and libaio reads the events with `io_getevents`.
//!
//! `io_submit` does each request before it returns. The reads and the writes of one file that
//! come one after the other in a call go to the file as one batch, so that the block layer can
//! merge and sort them. A request is never in progress after `io_submit`, so `io_cancel` finds
//! no request.

use crate::cx::{Cx, SysResult};
use crate::poll::{restore_mask, set_temp_mask, timespec_deadline, wait_events};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::types::Iovec;
use rk_frame::sync::SpinLock;
use rk_mm::{AddressSpace, MmapRequest, PAGE_SIZE, Prot};
use rk_vfs::File;
use rk_vfs::file::BatchIo;
use rk_vfs::wait::{PollTable, WaitQueue};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// The commands of a request.
const IOCB_CMD_PREAD: u16 = 0;
const IOCB_CMD_PWRITE: u16 = 1;
const IOCB_CMD_FSYNC: u16 = 2;
const IOCB_CMD_FDSYNC: u16 = 3;
const IOCB_CMD_PREADV: u16 = 7;
const IOCB_CMD_PWRITEV: u16 = 8;

/// The flags of a request: write to the event file `aio_resfd` when the request is done, and
/// use the priority `aio_reqprio`.
const IOCB_FLAG_RESFD: u32 = 1;
const IOCB_FLAG_IOPRIO: u32 = 2;

/// The most events of all the contexts. Linux names it `aio-max-nr`.
const AIO_MAX_NR: u64 = 65536;
/// The largest request that goes in a batch. A larger request goes alone, in parts.
const BATCH_MAX: usize = 1 << 20;

/// A request as user space gives it: `struct iocb`.
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct Iocb {
    aio_data: u64,
    aio_key: u32,
    aio_rw_flags: i32,
    aio_lio_opcode: u16,
    aio_reqprio: i16,
    aio_fildes: u32,
    aio_buf: u64,
    aio_nbytes: u64,
    aio_offset: i64,
    aio_reserved2: u64,
    aio_flags: u32,
    aio_resfd: u32,
}

/// An event of a request that is done: `struct io_event`.
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct IoEvent {
    data: u64,
    obj: u64,
    res: i64,
    res2: i64,
}

/// A context of `io_setup`.
struct Context {
    /// The address space of the process that made the context.
    owner: Weak<AddressSpace>,
    /// The most events that can wait.
    nr: u64,
    events: SpinLock<VecDeque<IoEvent>>,
    /// `io_getevents` waits here for new events, as `kioctx.wait` of Linux.
    wait: Arc<WaitQueue>,
}

/// The contexts by ID.
static CONTEXTS: SpinLock<BTreeMap<u64, Arc<Context>>> = SpinLock::new(BTreeMap::new());

/// Gives the context `id` of the process.
fn context(cx: &Cx<'_>, id: u64) -> Result<Arc<Context>, Errno> {
    let vm = cx.vm()?;
    CONTEXTS
        .lock()
        .get(&id)
        .filter(|c| c.owner.as_ptr() == Arc::as_ptr(&vm))
        .cloned()
        .ok_or(Errno::EINVAL)
}

pub(crate) fn io_setup(cx: &Cx<'_>, nr: u64, idp: u64) -> SysResult {
    let old: u64 = cx.read_val(idp)?;
    let nr = nr as u32;
    if old != 0 || nr == 0 || u64::from(nr) > AIO_MAX_NR {
        return Err(Errno::EINVAL);
    }
    let vm = cx.vm()?;
    let mut contexts = CONTEXTS.lock();
    contexts.retain(|_, c| c.owner.strong_count() > 0);
    if contexts.values().map(|c| c.nr).sum::<u64>() + u64::from(nr) > AIO_MAX_NR {
        return Err(Errno::EAGAIN);
    }
    let prot = Prot::from_bits(3).ok_or(Errno::EINVAL)?;
    let id = vm.mmap(MmapRequest::anon(PAGE_SIZE, prot))? as u64;
    if let Err(e) = cx.write_val(idp, &id) {
        let _ = vm.munmap(id as usize, PAGE_SIZE);
        return Err(e);
    }
    let ctx = Context {
        owner: Arc::downgrade(&vm),
        nr: u64::from(nr),
        events: SpinLock::new(VecDeque::new()),
        wait: Arc::new(WaitQueue::new()),
    };
    contexts.insert(id, Arc::new(ctx));
    Ok(0)
}

pub(crate) fn io_destroy(cx: &Cx<'_>, id: u64) -> SysResult {
    context(cx, id)?;
    CONTEXTS.lock().remove(&id);
    let _ = cx.vm()?.munmap(id as usize, PAGE_SIZE);
    Ok(0)
}

pub(crate) fn io_cancel(cx: &Cx<'_>, id: u64, _iocb: u64, _result: u64) -> SysResult {
    context(cx, id)?;
    Err(Errno::EINVAL)
}

/// What a request does.
enum Work {
    /// A read or a write of a file. `iov` has the user buffers.
    Rw {
        file: Arc<File>,
        write: bool,
        offset: u64,
        iov: Vec<Iovec>,
    },
    Sync {
        file: Arc<File>,
    },
}

/// A request that `io_submit` read.
struct Item {
    obj: u64,
    iocb: Iocb,
    work: Work,
    /// The event file of `IOCB_FLAG_RESFD`.
    resfd: Option<Arc<File>>,
}

impl Item {
    fn len(&self) -> usize {
        match &self.work {
            Work::Rw { iov, .. } => iov.iter().map(|v| v.iov_len as usize).sum(),
            Work::Sync { .. } => 0,
        }
    }
}

/// Reads and checks the request at `obj`.
fn read_item(cx: &Cx<'_>, obj: u64) -> Result<Item, Errno> {
    let iocb: Iocb = cx.read_val(obj)?;
    if iocb.aio_reserved2 != 0 || iocb.aio_flags & !(IOCB_FLAG_RESFD | IOCB_FLAG_IOPRIO) != 0 {
        return Err(Errno::EINVAL);
    }
    let file = cx.file(u64::from(iocb.aio_fildes))?;
    let resfd = if iocb.aio_flags & IOCB_FLAG_RESFD != 0 {
        Some(cx.file(u64::from(iocb.aio_resfd))?)
    } else {
        None
    };
    let rw = |write: bool, iov: Vec<Iovec>| {
        let allowed = if write { file.flags().writable() } else { file.flags().readable() };
        if !allowed {
            return Err(Errno::EBADF);
        }
        if iocb.aio_offset < 0 {
            return Err(Errno::EINVAL);
        }
        Ok(Work::Rw { file: file.clone(), write, offset: iocb.aio_offset as u64, iov })
    };
    let one =
        || vec![Iovec { iov_base: iocb.aio_buf, iov_len: iocb.aio_nbytes.min(i64::MAX as u64) }];
    let work = match iocb.aio_lio_opcode {
        IOCB_CMD_PREAD => rw(false, one())?,
        IOCB_CMD_PWRITE => rw(true, one())?,
        IOCB_CMD_PREADV => rw(false, crate::fs::read_iovecs(cx, iocb.aio_buf, iocb.aio_nbytes)?)?,
        IOCB_CMD_PWRITEV => rw(true, crate::fs::read_iovecs(cx, iocb.aio_buf, iocb.aio_nbytes)?)?,
        IOCB_CMD_FSYNC | IOCB_CMD_FDSYNC => Work::Sync { file },
        _ => return Err(Errno::EINVAL),
    };
    Ok(Item { obj, iocb, work, resfd })
}

/// Copies the user buffers of `iov` to one buffer.
fn gather(cx: &Cx<'_>, iov: &[Iovec]) -> Result<Vec<u8>, Errno> {
    let mut buf = Vec::new();
    for v in iov {
        buf.extend_from_slice(&cx.read_bytes(v.iov_base, v.iov_len as usize)?);
    }
    Ok(buf)
}

/// Copies `data` to the user buffers of `iov`.
fn scatter(cx: &Cx<'_>, iov: &[Iovec], data: &[u8]) -> Result<(), Errno> {
    let mut at = 0;
    for v in iov {
        let n = (v.iov_len as usize).min(data.len() - at);
        cx.write_bytes(v.iov_base, &data[at..at + n])?;
        at += n;
        if at == data.len() {
            break;
        }
    }
    Ok(())
}

/// Does a large read or write alone, in parts, as `preadv` and `pwritev` do.
fn run_large(cx: &Cx<'_>, file: &File, write: bool, offset: u64, iov: &[Iovec]) -> SysResult {
    let mut done = 0u64;
    for v in iov.iter().filter(|v| v.iov_len != 0) {
        let at = offset + done;
        let r = if write {
            crate::fs::write_with(cx, v.iov_base, v.iov_len, |d, b| file.write_at(at + d, b))
        } else {
            crate::fs::read_with(cx, file, v.iov_base, v.iov_len, |d, b| file.read_at(at + d, b))
        };
        let n = match r {
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

/// Does the requests of `items` and gives the result of each. The small reads and writes of one
/// file that come one after the other go as one batch.
fn run(cx: &Cx<'_>, items: &[Item]) -> Vec<SysResult> {
    let mut results = Vec::with_capacity(items.len());
    let mut i = 0;
    while i < items.len() {
        let small = |item: &Item| matches!(item.work, Work::Rw { .. }) && item.len() <= BATCH_MAX;
        let item = &items[i];
        match &item.work {
            Work::Sync { file } => {
                results.push(file.sync().map(|()| 0));
                i += 1;
            }
            Work::Rw { file, write, offset, iov } if !small(item) => {
                let r = run_large(cx, file, *write, *offset, iov);
                results.push(if *write { crate::fs::write_sync(file, r) } else { r });
                i += 1;
            }
            Work::Rw { file, .. } => {
                let same = |it: &Item| match &it.work {
                    Work::Rw { file: f, .. } => small(it) && Arc::ptr_eq(f, file),
                    Work::Sync { .. } => false,
                };
                let end = i + items[i..].iter().take_while(|it| same(it)).count();
                let group = &items[i..end];
                let mut ios = Vec::with_capacity(group.len());
                let mut copied = Vec::with_capacity(group.len());
                for it in group {
                    let Work::Rw { write, offset, iov, .. } = &it.work else { unreachable!() };
                    let (buf, ok) = if *write {
                        match gather(cx, iov) {
                            Ok(buf) => (buf, Ok(())),
                            Err(e) => (Vec::new(), Err(e)),
                        }
                    } else {
                        (vec![0u8; it.len()], Ok(()))
                    };
                    ios.push(BatchIo { write: *write, offset: *offset, buf, result: Ok(0) });
                    copied.push(ok);
                }
                // An entry whose data cannot be read does not go to the file.
                let mut todo: Vec<BatchIo> = Vec::new();
                let mut place = Vec::new();
                for (k, (io, ok)) in ios.into_iter().zip(&copied).enumerate() {
                    if ok.is_ok() {
                        place.push(k);
                        todo.push(io);
                    }
                }
                file.rw_batch(&mut todo);
                let mut out: Vec<SysResult> = copied.iter().map(|ok| ok.map(|()| 0)).collect();
                for (io, k) in todo.into_iter().zip(place) {
                    let Work::Rw { iov, .. } = &group[k].work else { unreachable!() };
                    out[k] = match io.result {
                        Ok(n) if !io.write => scatter(cx, iov, &io.buf[..n]).map(|()| n as u64),
                        Ok(n) => crate::fs::write_sync(file, Ok(n as u64)),
                        Err(e) => Err(e),
                    };
                }
                results.extend(out);
                i = end;
            }
        }
    }
    results
}

pub(crate) fn io_submit(cx: &Cx<'_>, id: u64, nr: u64, iocbpp: u64) -> SysResult {
    let ctx = context(cx, id)?;
    if (nr as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    let nr = nr.min(ctx.nr);
    let room = ctx.nr.saturating_sub(ctx.events.lock().len() as u64);
    let mut items = Vec::new();
    let mut error = None;
    for k in 0..nr {
        if k >= room {
            error = Some(Errno::EAGAIN);
            break;
        }
        let item = cx.read_val::<u64>(iocbpp + k * 8).and_then(|obj| read_item(cx, obj));
        match item {
            Ok(item) => items.push(item),
            Err(e) => {
                error = Some(e);
                break;
            }
        }
    }
    let results = run(cx, &items);
    for (item, r) in items.iter().zip(results) {
        let res = match r {
            Ok(n) => n as i64,
            Err(e) => -i64::from(e.get()),
        };
        ctx.events.lock().push_back(IoEvent {
            data: item.iocb.aio_data,
            obj: item.obj,
            res,
            res2: 0,
        });
        if let Some(efd) = &item.resfd {
            crate::eventfd::signal(efd);
        }
    }
    ctx.wait.wake_all();
    match (items.len(), error) {
        (0, Some(e)) => Err(e),
        (n, _) => Ok(n as u64),
    }
}

fn getevents(cx: &Cx<'_>, id: u64, min_nr: u64, nr: u64, events: u64, timeout: u64) -> SysResult {
    let ctx = context(cx, id)?;
    let (min_nr, nr) = (min_nr as i64, nr as i64);
    if min_nr < 0 || nr < 0 || min_nr > nr {
        return Err(Errno::EINVAL);
    }
    let deadline = timespec_deadline(cx, timeout)?;
    let grab = |need: i64| {
        let mut q = ctx.events.lock();
        if (q.len() as i64) < need {
            return None;
        }
        let n = (nr as usize).min(q.len());
        Some(q.drain(..n).collect::<Vec<_>>())
    };
    let scan = |table: Option<&mut PollTable>| {
        if let Some(table) = table {
            table.add(&ctx.wait);
        }
        Ok(grab(min_nr))
    };
    let list = match wait_events(cx, deadline, scan) {
        Ok(Some(list)) => list,
        Ok(None) => grab(0).unwrap_or_default(),
        Err(Errno::ERESTARTNOHAND) => match grab(1) {
            Some(list) => list,
            None => return Err(Errno::EINTR),
        },
        Err(e) => return Err(e),
    };
    for (k, e) in list.iter().enumerate() {
        cx.write_val(events + k as u64 * 32, e)?;
    }
    Ok(list.len() as u64)
}

pub(crate) fn io_getevents(
    cx: &Cx<'_>,
    id: u64,
    min_nr: u64,
    nr: u64,
    events: u64,
    timeout: u64,
) -> SysResult {
    getevents(cx, id, min_nr, nr, events, timeout)
}

/// The signal argument of `io_pgetevents`: `struct __aio_sigset`.
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct AioSigset {
    sigmask: u64,
    sigsetsize: u64,
}

pub(crate) fn io_pgetevents(cx: &Cx<'_>, a: &[u64; 6]) -> SysResult {
    let sig = if a[5] == 0 { None } else { Some(cx.read_val::<AioSigset>(a[5])?) };
    let old = match sig {
        Some(s) => set_temp_mask(cx, s.sigmask, s.sigsetsize)?,
        None => None,
    };
    let r = getevents(cx, a[0], a[1], a[2], a[3], a[4]);
    // As for `ppoll`, the mask comes back after the handler of the signal that stopped the wait.
    let stopped = if r == Err(Errno::EINTR) { Err(Errno::ERESTARTNOHAND) } else { r };
    restore_mask(cx, old, &stopped);
    r
}

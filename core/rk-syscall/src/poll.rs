//! The system calls that wait for the events of more than one file: `poll`, `ppoll`, `select` and
//! `pselect6`, and `pipe` and `pipe2`.
//!
//! A wait scans each file with its `poll` operation. If no file is ready, the task waits in the
//! queue of each file until a file has a new event, a signal comes or the time is over. Then it
//! scans again, as `do_poll` and `do_select` of fs/select.c do.

use crate::cx::{Cx, SysResult};
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::open::{O_CLOEXEC, O_NONBLOCK};
use rk_abi::native::poll::{POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT, POLLPRI};
#[cfg(target_arch = "x86_64")]
use rk_abi::native::types::KernelOldTimeval;
use rk_abi::native::types::KernelTimespec;
use rk_frame::time::{HZ, ticks};
use rk_proc::signal::SigSet;
use rk_vfs::wait::{PollTable, poll_wait_until};

const NSEC_PER_SEC: u64 = 1_000_000_000;
const TICK_NS: u64 = NSEC_PER_SEC / HZ;

/// The events that make a file ready for `select`, as fs/select.c has them.
const SELECT_IN: u32 = POLLIN | POLLHUP | POLLERR;
const SELECT_OUT: u32 = POLLOUT | POLLERR;
const SELECT_EX: u32 = POLLPRI;

/// The tick count when `ns` nanoseconds from now are over.
pub(crate) fn deadline_after(ns: u64) -> u64 {
    crate::info::deadline_after(ns)
}

/// The nanoseconds until `deadline`, or 0.
fn left(deadline: u64) -> u64 {
    deadline.saturating_mul(TICK_NS).saturating_sub(crate::info::uptime_ns())
}

/// Scans with `scan` until it gives a value, the deadline comes or a signal comes. `scan` gives
/// `None` if no file is ready. When `scan` gets a table, it adds the queues of each file that it
/// tests with `File::poll_wait`. Gives `None` at the deadline.
///
/// # Errors
///
/// Gives the error of `scan`, or `ERESTARTNOHAND` for a signal.
pub(crate) fn wait_events<R>(
    cx: &Cx<'_>,
    deadline: Option<u64>,
    mut scan: impl FnMut(Option<&mut PollTable>) -> Result<Option<R>, Errno>,
) -> Result<Option<R>, Errno> {
    if deadline.is_some_and(|d| d <= ticks()) {
        return scan(None);
    }
    let thread = cx.thread;
    poll_wait_until(deadline.unwrap_or(u64::MAX), |table| match scan(table) {
        Ok(Some(r)) => Some(Ok(Some(r))),
        Err(e) => Some(Err(e)),
        Ok(None) if thread.signal_pending() => Some(Err(Errno::ERESTARTNOHAND)),
        Ok(None) => None,
    })
    .unwrap_or(Ok(None))
}

/// Sets the signal mask of `ppoll` or `pselect6`, and gives the old mask.
pub(crate) fn set_temp_mask(cx: &Cx<'_>, mask: u64, size: u64) -> Result<Option<SigSet>, Errno> {
    if mask == 0 {
        return Ok(None);
    }
    if size != 8 {
        return Err(Errno::EINVAL);
    }
    let new: u64 = cx.read_val(mask)?;
    let old = cx.thread.blocked();
    cx.thread.set_blocked(SigSet(new));
    Ok(Some(old))
}

/// Puts back the mask of `set_temp_mask`. If a signal stopped the call, the mask comes back after
/// the handler starts, so the signal of the temporary mask runs its handler.
pub(crate) fn restore_mask(cx: &Cx<'_>, old: Option<SigSet>, r: &SysResult) {
    if let Some(old) = old {
        if *r == Err(Errno::ERESTARTNOHAND) {
            cx.thread.set_saved_mask(old);
        } else {
            cx.thread.set_blocked(old);
        }
    }
}

/// Reads a `timespec` timeout and gives its deadline.
pub(crate) fn timespec_deadline(cx: &Cx<'_>, tsp: u64) -> Result<Option<u64>, Errno> {
    if tsp == 0 {
        return Ok(None);
    }
    let ts: KernelTimespec = cx.read_val(tsp)?;
    if ts.tv_sec < 0 || !(0..NSEC_PER_SEC as i64).contains(&ts.tv_nsec) {
        return Err(Errno::EINVAL);
    }
    let ns = (ts.tv_sec as u64).saturating_mul(NSEC_PER_SEC).saturating_add(ts.tv_nsec as u64);
    Ok(Some(deadline_after(ns)))
}

/// Writes the time that is left back to a `timespec`, as `poll_select_finish` does.
fn write_timespec_left(cx: &Cx<'_>, tsp: u64, deadline: Option<u64>) {
    if let (Some(d), true) = (deadline, tsp != 0) {
        let ns = left(d);
        let ts = KernelTimespec {
            tv_sec: (ns / NSEC_PER_SEC) as i64,
            tv_nsec: (ns % NSEC_PER_SEC) as i64,
        };
        let _ = cx.write_val(tsp, &ts);
    }
}

/// One entry of a `pollfd` array.
#[derive(Clone, Copy)]
struct PollFd {
    fd: i32,
    events: u32,
}

/// The events of `file` that `poll` reports for `events`. `POLLERR` and `POLLHUP` are always
/// reported. Adds the queues of the file to `table`.
fn poll_file(cx: &Cx<'_>, fd: i32, events: u32, table: Option<&mut PollTable>) -> u32 {
    match cx.files().and_then(|f| f.lock().file(fd)) {
        Ok(file) => {
            if let Some(table) = table {
                file.poll_wait(table);
            }
            file.poll() & (events | POLLERR | POLLHUP)
        }
        Err(_) => POLLNVAL,
    }
}

/// The soft `RLIMIT_NOFILE` of the process, the most descriptors that `poll` and `select` take.
fn nofile(cx: &Cx<'_>) -> usize {
    let limit = cx.process().limit(rk_proc::limits::RLIMIT_NOFILE).cur;
    usize::try_from(limit).unwrap_or(usize::MAX)
}

fn do_poll(cx: &Cx<'_>, fds: u64, nfds: u64, deadline: Option<u64>) -> SysResult {
    if nfds > nofile(cx) as u64 {
        return Err(Errno::EINVAL);
    }
    let raw = cx.read_bytes(fds, nfds as usize * 8)?;
    let entries: Vec<PollFd> = raw
        .chunks_exact(8)
        .map(|c| PollFd {
            fd: i32::from_ne_bytes([c[0], c[1], c[2], c[3]]),
            events: u32::from(u16::from_ne_bytes([c[4], c[5]])),
        })
        .collect();
    let scan = |mut table: Option<&mut PollTable>| {
        let revents: Vec<u32> = entries
            .iter()
            .map(|e| if e.fd < 0 { 0 } else { poll_file(cx, e.fd, e.events, table.as_deref_mut()) })
            .collect();
        let ready = revents.iter().filter(|&&r| r != 0).count();
        Ok((ready > 0).then_some(revents))
    };
    let revents = wait_events(cx, deadline, scan)?.unwrap_or_else(|| vec![0; entries.len()]);
    for (i, r) in revents.iter().enumerate() {
        cx.write_val(fds + i as u64 * 8 + 6, &(*r as u16))?;
    }
    Ok(revents.iter().filter(|&&r| r != 0).count() as u64)
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn poll(cx: &Cx<'_>, fds: u64, nfds: u64, timeout: u64) -> SysResult {
    let ms = timeout as i32;
    let deadline = (ms >= 0).then(|| deadline_after(ms as u64 * 1_000_000));
    match do_poll(cx, fds, nfds, deadline) {
        // Linux starts a `poll` with a timeout again through `restart_syscall`. rukernel does not
        // have it yet, so the call gives `EINTR`.
        Err(Errno::ERESTARTNOHAND) if deadline.is_some() => Err(Errno::EINTR),
        r => r,
    }
}

pub(crate) fn ppoll(cx: &Cx<'_>, fds: u64, nfds: u64, tsp: u64, mask: u64, size: u64) -> SysResult {
    let deadline = timespec_deadline(cx, tsp)?;
    let old = set_temp_mask(cx, mask, size)?;
    let r = do_poll(cx, fds, nfds, deadline);
    restore_mask(cx, old, &r);
    write_timespec_left(cx, tsp, deadline);
    r
}

/// The three sets of `select`, one bit for each descriptor.
struct FdSets {
    words: usize,
    sets: [Option<Vec<u64>>; 3],
}

fn read_set(cx: &Cx<'_>, addr: u64, words: usize) -> Result<Option<Vec<u64>>, Errno> {
    if addr == 0 {
        return Ok(None);
    }
    let raw = cx.read_bytes(addr, words * 8)?;
    Ok(Some(raw.as_chunks::<8>().0.iter().map(|c| u64::from_ne_bytes(*c)).collect()))
}

fn write_set(cx: &Cx<'_>, addr: u64, set: &[u64]) -> Result<(), Errno> {
    if addr == 0 {
        return Ok(());
    }
    let bytes: Vec<u8> = set.iter().flat_map(|w| w.to_ne_bytes()).collect();
    cx.write_bytes(addr, &bytes)
}

fn do_select(cx: &Cx<'_>, nfds: u64, ptrs: [u64; 3], deadline: Option<u64>) -> SysResult {
    let n = nfds as i32;
    if n < 0 {
        return Err(Errno::EINVAL);
    }
    let n = (n as usize).min(nofile(cx));
    let words = n.div_ceil(64);
    let sets = FdSets {
        words,
        sets: [
            read_set(cx, ptrs[0], words)?,
            read_set(cx, ptrs[1], words)?,
            read_set(cx, ptrs[2], words)?,
        ],
    };
    let want = [SELECT_IN, SELECT_OUT, SELECT_EX];
    let scan = |mut table: Option<&mut PollTable>| {
        let mut out = [vec![0u64; sets.words], vec![0u64; sets.words], vec![0u64; sets.words]];
        let mut count = 0u64;
        for fd in 0..n {
            let (w, bit) = (fd / 64, 1u64 << (fd % 64));
            let asked: Vec<usize> = (0..3)
                .filter(|&k| sets.sets[k].as_ref().is_some_and(|s| s[w] & bit != 0))
                .collect();
            if asked.is_empty() {
                continue;
            }
            let file = cx.files()?.lock().file(fd as i32)?;
            if let Some(table) = table.as_deref_mut() {
                file.poll_wait(table);
            }
            let ev = file.poll();
            for k in asked {
                if ev & want[k] != 0 {
                    out[k][w] |= bit;
                    count += 1;
                }
            }
        }
        Ok((count > 0).then_some((out, count)))
    };
    let (out, count) = match wait_events(cx, deadline, scan)? {
        Some(r) => r,
        None => ([vec![0; words], vec![0; words], vec![0; words]], 0),
    };
    for k in 0..3 {
        write_set(cx, ptrs[k], &out[k])?;
    }
    Ok(count)
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn select(cx: &Cx<'_>, nfds: u64, inp: u64, outp: u64, exp: u64, tvp: u64) -> SysResult {
    let deadline = if tvp == 0 {
        None
    } else {
        let tv: KernelOldTimeval = cx.read_val(tvp)?;
        if tv.tv_sec < 0 || !(0..1_000_000).contains(&tv.tv_usec) {
            return Err(Errno::EINVAL);
        }
        let ns = (tv.tv_sec as u64).saturating_mul(NSEC_PER_SEC) + tv.tv_usec as u64 * 1000;
        Some(deadline_after(ns))
    };
    let r = do_select(cx, nfds, [inp, outp, exp], deadline);
    if let Some(d) = deadline {
        let ns = left(d);
        let tv = KernelOldTimeval {
            tv_sec: (ns / NSEC_PER_SEC) as i64,
            tv_usec: (ns % NSEC_PER_SEC / 1000) as i64,
        };
        let _ = cx.write_val(tvp, &tv);
    }
    r
}

pub(crate) fn pselect6(
    cx: &Cx<'_>,
    nfds: u64,
    inp: u64,
    outp: u64,
    exp: u64,
    tsp: u64,
    sig: u64,
) -> SysResult {
    let deadline = timespec_deadline(cx, tsp)?;
    // The last argument points to a pointer to the mask and the size of the mask.
    let (mask, size) = if sig == 0 {
        (0, 0)
    } else {
        let pair: [u64; 2] = cx.read_val(sig)?;
        (pair[0], pair[1])
    };
    let old = set_temp_mask(cx, mask, size)?;
    let r = do_select(cx, nfds, [inp, outp, exp], deadline);
    restore_mask(cx, old, &r);
    write_timespec_left(cx, tsp, deadline);
    r
}

pub(crate) fn pipe2(cx: &Cx<'_>, fds: u64, flags: u64) -> SysResult {
    let flags = flags as u32;
    if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
        return Err(Errno::EINVAL);
    }
    let (r, w) = rk_vfs::pipe::pipe(flags & O_NONBLOCK);
    let cloexec = flags & O_CLOEXEC != 0;
    let files = cx.files()?;
    let (rfd, wfd) = {
        let mut table = files.lock();
        let rfd = table.insert(r, cloexec)?;
        match table.insert(w, cloexec) {
            Ok(wfd) => (rfd, wfd),
            Err(e) => {
                let _ = table.remove(rfd);
                return Err(e);
            }
        }
    };
    if let Err(e) = cx.write_val(fds, &[rfd, wfd]) {
        let mut table = files.lock();
        let entries = (table.remove(rfd), table.remove(wfd));
        drop(table);
        drop(entries);
        return Err(e);
    }
    Ok(0)
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn pipe(cx: &Cx<'_>, fds: u64) -> SysResult {
    pipe2(cx, fds, 0)
}

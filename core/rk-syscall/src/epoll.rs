//! Epoll: `epoll_create`, `epoll_create1`, `epoll_ctl`, `epoll_wait`, `epoll_pwait` and
//! `epoll_pwait2`.
//!
//! An epoll file holds a set of entries. Each entry is one open file and the events that the
//! program wants. A wait scans the entries with the `poll` operation of each file, as `poll`
//! does, and waits in the queue of each file of the set if no entry is ready. Linux puts an entry
//! on a ready list when its file wakes the entry. rukernel has no such callback, so an entry with
//! `EPOLLET` keeps the last events and the event count of its file, and it sees an edge when a
//! new event is true or the count changes. An entry that a wait gave goes to the end of the set,
//! so that each ready entry comes in turn. This is the model of fs/eventpoll.c of Linux.

use crate::cx::{Cx, SysResult};
use crate::poll::{deadline_after, restore_mask, set_temp_mask, timespec_deadline, wait_events};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use rk_abi::Errno;
use rk_abi::native::eventpoll::{
    EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD, EPOLLERR, EPOLLET, EPOLLEXCLUSIVE,
    EPOLLHUP, EPOLLIN, EPOLLONESHOT, EPOLLOUT, EPOLLRDNORM, EPOLLWAKEUP,
};
use rk_abi::native::open::O_RDWR;
use rk_abi::native::types::EpollEvent;
use rk_frame::sync::SpinLock;
use rk_vfs::file::{File, FileOps};
use rk_vfs::wait::{PollTable, WaitQueue};
use zerocopy::FromZeros;

/// Makes an `epoll_event`. The padding of the struct is not the same on each architecture.
fn epoll_event(events: u32, data: u64) -> EpollEvent {
    let mut e = EpollEvent::new_zeroed();
    e.events = events;
    e.data = data;
    e
}

/// The most levels of epoll files in epoll files, as `EP_MAX_NESTS` of Linux.
const MAX_NESTS: usize = 4;

/// The most events of one wait, as `EP_MAX_EVENTS` of Linux.
const MAX_EVENTS: usize = i32::MAX as usize / size_of::<EpollEvent>();

/// The events that an entry with `EPOLLEXCLUSIVE` can have.
const EXCLUSIVE_OK: u32 =
    EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLWAKEUP | EPOLLET | EPOLLEXCLUSIVE;

/// The flags of an entry. They are not events.
const FLAGS: u32 = EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE | EPOLLWAKEUP;

/// One entry of an epoll set.
struct Item {
    /// The file. The entry does not keep the file open. When the file closes, the entry goes
    /// away, as `eventpoll_release` of Linux does.
    file: Weak<File>,
    fd: i32,
    /// The events and the flags. `EPOLLERR` and `EPOLLHUP` are always in it.
    events: u32,
    data: u64,
    /// An entry with `EPOLLONESHOT` that a wait gave. `EPOLL_CTL_MOD` sets it again.
    disabled: bool,
    /// The events at the last scan, for `EPOLLET`.
    last: u32,
    /// The event count of the file at the last scan, for `EPOLLET`.
    count: u64,
    /// An edge that a wait did not give yet, for `EPOLLET`.
    edge: bool,
    /// The event count of the file at the last event that this entry took, for
    /// `EPOLLEXCLUSIVE`.
    wake: Option<u64>,
}

/// The last event count of each file that an entry with `EPOLLEXCLUSIVE` took.
static WAKES: SpinLock<Vec<(Weak<File>, u64)>> = SpinLock::new(Vec::new());

impl Item {
    fn same(&self, file: &Arc<File>, fd: i32) -> bool {
        self.fd == fd && core::ptr::eq(self.file.as_ptr(), Arc::as_ptr(file))
    }

    /// The events of the file that the entry wants now.
    fn ready(file: &File, events: u32) -> u32 {
        file.poll() & (events & !FLAGS)
    }

    /// Tells if this entry with `EPOLLEXCLUSIVE` has the last event of its file. The first
    /// entry that sees a new event takes it, so one event wakes one waiter, as the exclusive
    /// wake of Linux does. A file without an event count wakes each entry.
    fn take_wake(&mut self, file: &Arc<File>) -> bool {
        let count = file.event_count();
        if count == 0 || self.wake == Some(count) {
            return true;
        }
        let mut wakes = WAKES.lock();
        wakes.retain(|(f, _)| f.strong_count() > 0);
        let key = Arc::as_ptr(file);
        match wakes.iter_mut().find(|(f, _)| core::ptr::eq(f.as_ptr(), key)) {
            Some((_, taken)) if *taken >= count => return false,
            Some((_, taken)) => *taken = count,
            None => wakes.push((Arc::downgrade(file), count)),
        }
        self.wake = Some(count);
        true
    }

    /// Tells if the entry is ready, and does not change it. The `poll` of an epoll file uses
    /// this.
    fn peek(&self, file: &File) -> bool {
        if self.disabled {
            return false;
        }
        let now = Self::ready(file, self.events);
        if self.events & EPOLLET == 0 {
            return now != 0;
        }
        now != 0 && (self.edge || now & !self.last != 0 || file.event_count() != self.count)
    }

    /// Scans the entry, and gives the events to report.
    fn scan(&mut self, file: &Arc<File>) -> Option<u32> {
        if self.disabled {
            return None;
        }
        let mut now = Self::ready(file, self.events);
        if now != 0 && self.events & EPOLLEXCLUSIVE != 0 && !self.take_wake(file) {
            now = 0;
        }
        if self.events & EPOLLET != 0 {
            let count = file.event_count();
            if now & !self.last != 0 || count != self.count {
                self.edge = true;
            }
            self.last = now;
            self.count = count;
            if now == 0 || !self.edge {
                self.edge = false;
                return None;
            }
            self.edge = false;
        } else if now == 0 {
            return None;
        }
        if self.events & EPOLLONESHOT != 0 {
            self.disabled = true;
        }
        Some(now)
    }
}

/// The operations of an epoll file.
struct Epoll {
    items: SpinLock<Vec<Item>>,
    /// The epoll files that hold this one, for the check of the levels.
    parents: SpinLock<Vec<Weak<File>>>,
    /// The queue that a change of the set wakes.
    wait: Arc<WaitQueue>,
}

impl Epoll {
    /// Gives the ready entries, at most `max`. An entry that the wait gives goes to the end of
    /// the set. Adds the queue of the set and the queues of the files that it tests to `table`.
    fn collect(&self, max: usize, mut table: Option<&mut PollTable>) -> Vec<EpollEvent> {
        if let Some(table) = table.as_deref_mut() {
            table.add(&self.wait);
        }
        let mut out = Vec::new();
        let mut items = self.items.lock();
        items.retain(|i| i.file.strong_count() > 0);
        let mut given = Vec::new();
        for (n, item) in items.iter_mut().enumerate() {
            if out.len() == max {
                break;
            }
            let Some(file) = item.file.upgrade() else { continue };
            if let Some(table) = table.as_deref_mut() {
                file.poll_wait(table);
            }
            if let Some(events) = item.scan(&file) {
                out.push(epoll_event(events, item.data));
                given.push(n);
            }
        }
        let mut moved = Vec::with_capacity(given.len());
        for n in given.into_iter().rev() {
            moved.push(items.remove(n));
        }
        items.extend(moved.into_iter().rev());
        out
    }

    /// The epoll files in this set.
    fn children(&self) -> Vec<Arc<File>> {
        self.items.lock().iter().filter_map(|i| i.file.upgrade()).filter(|f| is_epoll(f)).collect()
    }

    /// The most levels of epoll files under this one.
    fn depth_down(&self) -> usize {
        self.children()
            .iter()
            .map(|c| 1 + epoll_of(c).map_or(0, Epoll::depth_down))
            .max()
            .unwrap_or(0)
    }

    /// The most levels of epoll files over this one.
    fn depth_up(&self) -> usize {
        let parents: Vec<Arc<File>> =
            self.parents.lock().iter().filter_map(Weak::upgrade).collect();
        parents.iter().map(|p| 1 + epoll_of(p).map_or(0, Epoll::depth_up)).max().unwrap_or(0)
    }

    /// Tells if `target` is this file or an epoll file under it.
    fn reaches(&self, me: &File, target: &File) -> bool {
        if core::ptr::eq(me, target) {
            return true;
        }
        self.children().iter().any(|c| epoll_of(c).is_some_and(|e| e.reaches(c, target)))
    }
}

impl FileOps for Epoll {
    fn poll(&self, _file: &File) -> u32 {
        let items = self.items.lock();
        let ready = items.iter().any(|i| i.file.upgrade().is_some_and(|f| i.peek(&f)));
        if ready { EPOLLIN | EPOLLRDNORM } else { 0 }
    }

    fn pollable(&self) -> bool {
        true
    }

    fn poll_wait(&self, _file: &File, table: &mut PollTable) {
        table.add(&self.wait);
        let files: Vec<Arc<File>> =
            self.items.lock().iter().filter_map(|i| i.file.upgrade()).collect();
        for file in files {
            file.poll_wait(table);
        }
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

fn epoll_of(file: &File) -> Option<&Epoll> {
    file.ops().as_any()?.downcast_ref::<Epoll>()
}

fn is_epoll(file: &File) -> bool {
    epoll_of(file).is_some()
}

pub(crate) fn epoll_create1(cx: &Cx<'_>, flags: u64) -> SysResult {
    let flags = u32::try_from(flags).map_err(|_| Errno::EINVAL)?;
    if flags & !EPOLL_CLOEXEC != 0 {
        return Err(Errno::EINVAL);
    }
    let ops = Epoll {
        items: SpinLock::new(Vec::new()),
        parents: SpinLock::new(Vec::new()),
        wait: Arc::new(WaitQueue::new()),
    };
    let file = File::with_ops(Arc::new(ops), None, O_RDWR);
    Ok(cx.files()?.lock().insert(file, flags & EPOLL_CLOEXEC != 0)? as u64)
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn epoll_create(cx: &Cx<'_>, size: u64) -> SysResult {
    if size as i32 <= 0 {
        return Err(Errno::EINVAL);
    }
    epoll_create1(cx, 0)
}

/// Gives the epoll file `epfd`.
fn epoll_file(cx: &Cx<'_>, epfd: u64) -> core::result::Result<Arc<File>, Errno> {
    let file = cx.file(epfd)?;
    if file.flags().is_path() {
        return Err(Errno::EBADF);
    }
    if !is_epoll(&file) {
        return Err(Errno::EINVAL);
    }
    Ok(file)
}

pub(crate) fn epoll_ctl(cx: &Cx<'_>, epfd: u64, op: u64, fd: u64, event: u64) -> SysResult {
    let op = op as u32;
    let has_event = op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD;
    let wanted: EpollEvent = if has_event { cx.read_val(event)? } else { epoll_event(0, 0) };
    let ep_file = cx.file(epfd)?;
    let file = cx.file(fd)?;
    if ep_file.flags().is_path() || file.flags().is_path() {
        return Err(Errno::EBADF);
    }
    if !file.pollable() {
        return Err(Errno::EPERM);
    }
    let ep = epoll_of(&ep_file).ok_or(Errno::EINVAL)?;
    if Arc::ptr_eq(&ep_file, &file) {
        return Err(Errno::EINVAL);
    }
    let fd = fd as i32;
    let mut events = wanted.events;
    if events & EPOLLEXCLUSIVE != 0 {
        if op == EPOLL_CTL_MOD
            || (op == EPOLL_CTL_ADD && (is_epoll(&file) || events & !EXCLUSIVE_OK != 0))
        {
            return Err(Errno::EINVAL);
        }
    }
    events |= EPOLLERR | EPOLLHUP;
    match op {
        EPOLL_CTL_ADD => {
            if ep.items.lock().iter().any(|i| i.same(&file, fd)) {
                return Err(Errno::EEXIST);
            }
            if let Some(child) = epoll_of(&file) {
                if child.reaches(&file, &ep_file) {
                    return Err(Errno::ELOOP);
                }
                if child.depth_down() + 1 + ep.depth_up() > MAX_NESTS {
                    return Err(Errno::EINVAL);
                }
                child.parents.lock().push(Arc::downgrade(&ep_file));
            }
            ep.items.lock().push(Item {
                file: Arc::downgrade(&file),
                fd,
                events,
                data: wanted.data,
                disabled: false,
                last: 0,
                count: file.event_count(),
                edge: false,
                // A file that is ready now gives its event to the new entry.
                wake: Some(file.event_count()),
            });
        }
        EPOLL_CTL_MOD => {
            let mut items = ep.items.lock();
            let item = items.iter_mut().find(|i| i.same(&file, fd)).ok_or(Errno::ENOENT)?;
            if item.events & EPOLLEXCLUSIVE != 0 {
                return Err(Errno::EINVAL);
            }
            item.events = events;
            item.data = wanted.data;
            item.disabled = false;
            // The new events are true again for an edge triggered entry, as `ep_modify` polls
            // the file again.
            item.last = 0;
            item.count = file.event_count();
        }
        EPOLL_CTL_DEL => {
            let mut items = ep.items.lock();
            let n = items.iter().position(|i| i.same(&file, fd)).ok_or(Errno::ENOENT)?;
            items.remove(n);
            drop(items);
            if let Some(child) = epoll_of(&file) {
                child.parents.lock().retain(|p| !core::ptr::eq(p.as_ptr(), Arc::as_ptr(&ep_file)));
            }
        }
        _ => return Err(Errno::EINVAL),
    }
    ep.wait.wake_all();
    Ok(0)
}

/// The wait of `epoll_wait`, `epoll_pwait` and `epoll_pwait2`.
fn do_wait(cx: &Cx<'_>, epfd: u64, events: u64, max: u64, deadline: Option<u64>) -> SysResult {
    let max = max as i32;
    if max <= 0 || max as usize > MAX_EVENTS {
        return Err(Errno::EINVAL);
    }
    let file = epoll_file(cx, epfd)?;
    let ep = epoll_of(&file).ok_or(Errno::EINVAL)?;
    let max = max as usize;
    let scan = |table: Option<&mut PollTable>| {
        let out = ep.collect(max, table);
        Ok((!out.is_empty()).then_some(out))
    };
    let out = wait_events(cx, deadline, scan)?.unwrap_or_default();
    for (n, ev) in out.iter().enumerate() {
        cx.write_val(events + (n * size_of::<EpollEvent>()) as u64, ev)?;
    }
    Ok(out.len() as u64)
}

/// The deadline of a timeout in milliseconds. A negative timeout waits with no end.
fn ms_deadline(timeout: u64) -> Option<u64> {
    let ms = timeout as i32;
    (ms >= 0).then(|| deadline_after(ms as u64 * 1_000_000))
}

/// Gives `EINTR` for a signal. Linux does not start an epoll wait again.
fn no_restart(r: SysResult) -> SysResult {
    match r {
        Err(Errno::ERESTARTNOHAND) => Err(Errno::EINTR),
        r => r,
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn epoll_wait(cx: &Cx<'_>, epfd: u64, events: u64, max: u64, timeout: u64) -> SysResult {
    no_restart(do_wait(cx, epfd, events, max, ms_deadline(timeout)))
}

/// `epoll_pwait` and `epoll_pwait2`: the wait with a temporary signal mask.
fn pwait(
    cx: &Cx<'_>,
    epfd: u64,
    events: u64,
    max: u64,
    deadline: Option<u64>,
    mask: u64,
    size: u64,
) -> SysResult {
    let old = set_temp_mask(cx, mask, size)?;
    let r = do_wait(cx, epfd, events, max, deadline);
    restore_mask(cx, old, &r);
    no_restart(r)
}

pub(crate) fn epoll_pwait(
    cx: &Cx<'_>,
    epfd: u64,
    events: u64,
    max: u64,
    timeout: u64,
    mask: u64,
    size: u64,
) -> SysResult {
    pwait(cx, epfd, events, max, ms_deadline(timeout), mask, size)
}

pub(crate) fn epoll_pwait2(
    cx: &Cx<'_>,
    epfd: u64,
    events: u64,
    max: u64,
    timeout: u64,
    mask: u64,
    size: u64,
) -> SysResult {
    let deadline = timespec_deadline(cx, timeout)?;
    pwait(cx, epfd, events, max, deadline, mask, size)
}

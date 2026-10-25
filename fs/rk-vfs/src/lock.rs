//! Advisory file locks: the record locks of `fcntl` and the locks of `flock`.
//!
//! A record lock locks a range of bytes. A POSIX lock (`F_SETLK`) belongs to a descriptor table,
//! and a close of any descriptor of the file in that table releases it, as Linux. An OFD lock
//! (`F_OFD_SETLK`) belongs to an open file description, and goes away when the last descriptor of
//! the description closes. The two kinds share one list, so they conflict with each other. A
//! `flock` lock locks all the file, belongs to an open file description, and does not conflict
//! with the record locks. The locks are only advisory: a read or a write does not examine them.

use crate::file::File;
use crate::inode::Result;
use crate::wait::WaitQueue;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

/// The kind of a lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockKind {
    /// A shared lock, `F_RDLCK` or `LOCK_SH`.
    Read,
    /// An exclusive lock, `F_WRLCK` or `LOCK_EX`.
    Write,
}

/// The owner of a record lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Owner {
    /// A POSIX lock: the address of the descriptor table.
    Posix(usize),
    /// An OFD lock: the address of the open file description.
    File(usize),
}

/// A record lock on the bytes `start..=end`. An `end` of `u64::MAX` is the end of the file, also
/// when the file grows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordLock {
    /// The owner.
    pub owner: Owner,
    /// The kind.
    pub kind: LockKind,
    /// The first byte.
    pub start: u64,
    /// The last byte.
    pub end: u64,
    /// The process that took the lock, for `F_GETLK`. An OFD lock has -1, as Linux.
    pub pid: i32,
}

impl RecordLock {
    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start <= end && start <= self.end
    }

    fn conflicts(&self, other: &RecordLock) -> bool {
        self.owner != other.owner
            && self.overlaps(other.start, other.end)
            && (self.kind == LockKind::Write || other.kind == LockKind::Write)
    }
}

/// The locks of one file.
#[derive(Default)]
struct FileLocks {
    records: Vec<RecordLock>,
    /// The `flock` locks: the address of the open file description and the kind.
    flocks: Vec<(usize, LockKind)>,
}

/// The file of a lock: the device and the inode number.
type Key = (u64, u64);

/// The locks of each file that has a lock.
static LOCKS: SpinLock<BTreeMap<Key, FileLocks>> = SpinLock::new(BTreeMap::new());
/// For each POSIX owner that waits for a lock, the owner of the lock that it waits for. It finds
/// a wait that never ends.
static WAITING: SpinLock<BTreeMap<usize, usize>> = SpinLock::new(BTreeMap::new());
/// The tasks that wait for a lock. Each release wakes all of them.
static LOCK_WAIT: WaitQueue = WaitQueue::new();

fn key(file: &File) -> Result<Key> {
    let inode = file.inode().ok_or(Errno::EBADF)?;
    let m = inode.metadata();
    Ok((m.dev, m.ino))
}

/// Gives the address of `file`, which identifies an open file description.
pub fn file_id(file: &File) -> usize {
    core::ptr::from_ref(file) as usize
}

/// Gives the first lock of another owner that conflicts with `lock`, for `F_GETLK`.
///
/// # Errors
///
/// Gives `EBADF` if the file has no inode.
pub fn test(file: &File, lock: &RecordLock) -> Result<Option<RecordLock>> {
    let key = key(file)?;
    let locks = LOCKS.lock();
    Ok(locks.get(&key).and_then(|l| l.records.iter().find(|r| r.conflicts(lock)).copied()))
}

/// Sets the record lock `lock`, or removes the locks of its owner in its range if `kind` is
/// `None`. With `wait`, the call waits for the locks of the other owners that conflict.
///
/// # Errors
///
/// Gives `EAGAIN` if another owner has a lock that conflicts and `wait` is false, `EDEADLK` if
/// the wait would never end, and `ERESTARTSYS` if a signal stops the wait.
pub fn set(file: &File, lock: RecordLock, kind: Option<LockKind>, wait: bool) -> Result<()> {
    let key = key(file)?;
    if kind.is_some() {
        file.mark_locked();
    }
    let attempt = || -> Result<Option<()>> {
        let mut locks = LOCKS.lock();
        let Some(kind) = kind else {
            if let Some(l) = locks.get_mut(&key) {
                remove_range(&mut l.records, lock.owner, lock.start, lock.end);
                clean(&mut locks, key);
                LOCK_WAIT.wake_all();
            }
            return Ok(Some(()));
        };
        let new = RecordLock { kind, ..lock };
        let entry = locks.entry(key).or_default();
        if let Some(holder) = entry.records.iter().find(|r| r.conflicts(&new)) {
            if !wait {
                return Err(Errno::EAGAIN);
            }
            if let (Owner::Posix(me), Owner::Posix(them)) = (new.owner, holder.owner) {
                let mut waiting = WAITING.lock();
                if deadlock(&waiting, me, them) {
                    waiting.remove(&me);
                    return Err(Errno::EDEADLK);
                }
                waiting.insert(me, them);
            }
            return Ok(None);
        }
        if let Owner::Posix(me) = new.owner {
            WAITING.lock().remove(&me);
        }
        remove_range(&mut entry.records, new.owner, new.start, new.end);
        entry.records.push(new);
        merge(&mut entry.records, new.owner);
        // A lock that changes from write to read lets the readers that wait go on.
        LOCK_WAIT.wake_all();
        Ok(Some(()))
    };
    let result = LOCK_WAIT.wait_interruptible(attempt);
    if result.is_err()
        && let Owner::Posix(me) = lock.owner
    {
        WAITING.lock().remove(&me);
    }
    result
}

/// Tells if a wait of `me` for `them` makes a cycle of POSIX owners that wait for each other.
fn deadlock(waiting: &BTreeMap<usize, usize>, me: usize, mut them: usize) -> bool {
    for _ in 0..=waiting.len() {
        if them == me {
            return true;
        }
        match waiting.get(&them) {
            Some(&next) => them = next,
            None => return false,
        }
    }
    false
}

/// Removes the bytes `start..=end` from the locks of `owner`. A lock that has bytes on each side
/// of the range becomes two locks.
fn remove_range(records: &mut Vec<RecordLock>, owner: Owner, start: u64, end: u64) {
    let mut kept = Vec::with_capacity(records.len() + 1);
    for r in records.drain(..) {
        if r.owner != owner || !r.overlaps(start, end) {
            kept.push(r);
            continue;
        }
        if r.start < start {
            kept.push(RecordLock { end: start - 1, ..r });
        }
        if r.end > end {
            kept.push(RecordLock { start: end + 1, ..r });
        }
    }
    *records = kept;
}

/// Joins the locks of `owner` of the same kind that touch or overlap, as Linux does.
fn merge(records: &mut Vec<RecordLock>, owner: Owner) {
    let (mut mine, mut rest): (Vec<_>, Vec<_>) = records.drain(..).partition(|r| r.owner == owner);
    mine.sort_by_key(|r| r.start);
    let mut joined: Vec<RecordLock> = Vec::with_capacity(mine.len());
    for r in mine {
        match joined.last_mut() {
            Some(last) if last.kind == r.kind && last.end.saturating_add(1) >= r.start => {
                last.end = last.end.max(r.end);
            }
            _ => joined.push(r),
        }
    }
    rest.extend(joined);
    *records = rest;
}

fn clean(locks: &mut BTreeMap<Key, FileLocks>, key: Key) {
    if locks.get(&key).is_some_and(|l| l.records.is_empty() && l.flocks.is_empty()) {
        locks.remove(&key);
    }
}

/// `flock`: sets a lock of `kind` on all the file for the open file description, or removes it
/// if `kind` is `None`. A change of the kind removes the old lock first, so another process can
/// take the file between the two steps, as on Linux.
///
/// # Errors
///
/// Gives `EWOULDBLOCK` if another description has a lock that conflicts and `wait` is false, and
/// `ERESTARTSYS` if a signal stops the wait.
pub fn flock(file: &File, kind: Option<LockKind>, wait: bool) -> Result<()> {
    let key = key(file)?;
    let id = file_id(file);
    {
        let mut locks = LOCKS.lock();
        if let Some(l) = locks.get_mut(&key) {
            if kind.is_some() && l.flocks.iter().any(|&(o, k)| o == id && Some(k) == kind) {
                return Ok(());
            }
            let before = l.flocks.len();
            l.flocks.retain(|&(o, _)| o != id);
            if l.flocks.len() != before {
                LOCK_WAIT.wake_all();
            }
            clean(&mut locks, key);
        }
    }
    let Some(kind) = kind else { return Ok(()) };
    file.mark_locked();
    LOCK_WAIT.wait_interruptible(|| {
        let mut locks = LOCKS.lock();
        let entry = locks.entry(key).or_default();
        let busy = entry
            .flocks
            .iter()
            .any(|&(o, k)| o != id && (k == LockKind::Write || kind == LockKind::Write));
        if !busy {
            entry.flocks.push((id, kind));
            return Ok(Some(()));
        }
        clean(&mut locks, key);
        if wait { Ok(None) } else { Err(Errno::EWOULDBLOCK) }
    })
}

/// Releases the POSIX locks of the descriptor table `owner` on the file of `file`, because the
/// table closed a descriptor of the file.
pub fn close_posix(file: &File, owner: usize) {
    if LOCKS.lock().is_empty() {
        return;
    }
    let Ok(key) = key(file) else { return };
    let mut locks = LOCKS.lock();
    if let Some(l) = locks.get_mut(&key) {
        let before = l.records.len();
        l.records.retain(|r| r.owner != Owner::Posix(owner));
        if l.records.len() != before {
            LOCK_WAIT.wake_all();
        }
        clean(&mut locks, key);
    }
}

/// Releases the OFD locks and the `flock` lock of the open file description `file`, because its
/// last descriptor closed.
pub(crate) fn close_file(file: &File) {
    let Ok(key) = key(file) else { return };
    let id = file_id(file);
    let mut locks = LOCKS.lock();
    if let Some(l) = locks.get_mut(&key) {
        l.records.retain(|r| r.owner != Owner::File(id));
        l.flocks.retain(|&(o, _)| o != id);
        clean(&mut locks, key);
        LOCK_WAIT.wake_all();
    }
}

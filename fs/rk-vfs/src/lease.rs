//! File leases of `fcntl(F_SETLEASE)`, as the lease part of fs/locks.c of Linux.
//!
//! A lease belongs to an open file description. Each inode has a list of leases. A read lease
//! lets other files read the file. A write lease lets no other file open the file. An `open` or a
//! `truncate` that conflicts with a lease breaks it, as `__break_lease` of Linux: the holder gets
//! its signal (`SIGIO` or the signal of `F_SETSIG`), and the caller waits until the holder
//! releases or downgrades the lease with `F_SETLEASE`. After `fs.lease-break-time` seconds, the
//! kernel does the change itself.

use crate::file::{File, inode_key};
use crate::inode::{InodeRef, Result};
use crate::lock::LockKind;
use crate::wait::WaitQueue;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use rk_abi::Errno;
use rk_abi::native::fcntl::{F_RDLCK, F_UNLCK, F_WRLCK};
use rk_abi::native::open as o;
use rk_frame::sync::SpinLock;

/// `fs.lease-break-time`: the seconds that a holder has to release or downgrade its lease, as
/// `lease_break_time` of Linux. With 0 the breaker waits until the holder does the change.
pub static BREAK_TIME: AtomicU32 = AtomicU32::new(45);

/// `fs.leases-enable`: with 0, `F_SETLEASE` does not give new leases, as `leases_enable` of
/// Linux.
pub static ENABLE: AtomicU32 = AtomicU32::new(1);

/// One lease, as `struct file_lease` of Linux.
struct Lease {
    /// The address of the open file description.
    id: usize,
    file: Weak<File>,
    /// The descriptor of `F_SETLEASE`, for the `si_fd` of the signal.
    fd: i32,
    kind: LockKind,
    /// An open for a write breaks the lease, as `FL_UNLOCK_PENDING` of Linux.
    unlock_pending: bool,
    /// An open for a read breaks the write lease, as `FL_DOWNGRADE_PENDING` of Linux.
    downgrade_pending: bool,
    /// The tick at which the kernel removes the lease. 0 is no time.
    break_time: u64,
    /// The tick at which the kernel downgrades the lease. 0 is no time.
    downgrade_time: u64,
}

impl Lease {
    /// The type that the lease has after the break, as `target_leasetype` of Linux.
    fn target(&self) -> i32 {
        if self.unlock_pending {
            F_UNLCK
        } else if self.downgrade_pending || self.kind == LockKind::Read {
            F_RDLCK
        } else {
            F_WRLCK
        }
    }

    /// Tells if the lease conflicts with an open for a write (`want_write`) or a read, as
    /// `leases_conflict` of Linux.
    fn conflicts(&self, want_write: bool) -> bool {
        want_write || self.kind == LockKind::Write
    }
}

/// The leases of each inode that has a lease. The key is the address of the inode.
static LEASES: SpinLock<BTreeMap<usize, Vec<Lease>>> = SpinLock::new(BTreeMap::new());

/// The tasks that wait for the break of a lease. Each change of a lease wakes all of them.
static LEASE_WAIT: WaitQueue = WaitQueue::new();

/// The tick count. On the host there is no clock, and the count stays at 0.
fn ticks() -> u64 {
    #[cfg(target_os = "none")]
    {
        rk_frame::time::ticks()
    }
    #[cfg(not(target_os = "none"))]
    {
        0
    }
}

/// The ticks of one second.
#[cfg(target_os = "none")]
const HZ: u64 = rk_frame::time::HZ;
#[cfg(not(target_os = "none"))]
const HZ: u64 = 100;

/// Tells if the tick `then` is past, as `past_time` of Linux. 0 is never past.
fn past(then: u64, now: u64) -> bool {
    then != 0 && now >= then
}

/// Changes the lease at `i` to `kind`, or removes it if `kind` is `None`, as `lease_modify` of
/// Linux. A removed lease adds its file to `gone`, so that the caller clears the owner of the
/// file after it releases the list.
fn modify(list: &mut Vec<Lease>, i: usize, kind: Option<LockKind>, gone: &mut Vec<Arc<File>>) {
    match kind {
        Some(kind) => {
            let lease = &mut list[i];
            lease.kind = kind;
            // As `lease_clear_pending` of Linux.
            if kind == LockKind::Read {
                lease.downgrade_pending = false;
            }
        }
        None => {
            let lease = list.remove(i);
            if let Some(file) = lease.file.upgrade() {
                gone.push(file);
            }
        }
    }
    LEASE_WAIT.wake_all();
}

/// Does the changes of the breaks that are past their time, as `time_out_leases` of Linux.
fn time_out(list: &mut Vec<Lease>, gone: &mut Vec<Arc<File>>) {
    let now = ticks();
    let mut i = 0;
    while i < list.len() {
        if past(list[i].downgrade_time, now) {
            modify(list, i, Some(LockKind::Read), gone);
        }
        if past(list[i].break_time, now) {
            modify(list, i, None, gone);
            continue;
        }
        i += 1;
    }
}

/// Clears the owner and the signal of each file whose lease went away, as `f_delown` in
/// `lease_modify` of Linux.
fn clear_owners(gone: &[Arc<File>]) {
    for file in gone {
        file.set_owner(0);
        file.set_signum(0);
    }
}

/// Tells if a file that is open for a write or a read conflicts with a new lease of `kind` on
/// `file`, as `check_conflicting_open` of Linux. Only `file` can have the inode open for a write
/// lease.
fn conflicting_open(file: &File, inode: &InodeRef, kind: LockKind) -> bool {
    let (writers, readers) = crate::file::open_counts(inode);
    match kind {
        LockKind::Read => writers != 0,
        LockKind::Write => {
            let (own_write, own_read) = file.open_counts_as();
            crate::file::check_write_access(&**inode).is_err()
                || writers != usize::from(own_write)
                || readers != usize::from(own_read)
        }
    }
}

/// `F_SETLEASE`: sets the lease `kind` of the open file `file`, or removes it if `kind` is
/// `None`, as `generic_setlease` of Linux. `fd` is the descriptor that gets the signal of a
/// break. The caller checked the owner of the file and its type.
///
/// # Errors
///
/// Gives `EAGAIN` if an open file or a lease of another file conflicts, or if `kind` is `None`
/// and the file has no lease. Gives `EINVAL` for a new lease if `fs.leases-enable` is 0.
pub fn set(file: &Arc<File>, fd: i32, kind: Option<LockKind>) -> Result<()> {
    let inode = file.inode().ok_or(Errno::EBADF)?;
    let key = inode_key(inode);
    let id = crate::lock::file_id(file);
    let mut gone = Vec::new();
    let result = {
        let mut leases = LEASES.lock();
        let list = leases.entry(key).or_default();
        time_out(list, &mut gone);
        let result = set_in(list, file, inode, id, fd, kind, &mut gone);
        if list.is_empty() {
            leases.remove(&key);
        }
        result
    };
    clear_owners(&gone);
    result
}

/// The part of `set` that holds the list of the inode.
fn set_in(
    list: &mut Vec<Lease>,
    file: &Arc<File>,
    inode: &InodeRef,
    id: usize,
    fd: i32,
    kind: Option<LockKind>,
    gone: &mut Vec<Arc<File>>,
) -> Result<()> {
    let mine = list.iter().position(|l| l.id == id);
    let Some(kind) = kind else {
        // As `generic_delete_lease` of Linux.
        let i = mine.ok_or(Errno::EAGAIN)?;
        modify(list, i, None, gone);
        return Ok(());
    };
    // As `generic_add_lease` of Linux.
    if conflicting_open(file, inode, kind) {
        return Err(Errno::EAGAIN);
    }
    for lease in list.iter().filter(|l| l.id != id) {
        // No write lease if another file has a lease, and no new lease while an open for a
        // write waits.
        if kind == LockKind::Write || lease.unlock_pending {
            return Err(Errno::EAGAIN);
        }
    }
    if let Some(i) = mine {
        list[i].fd = fd;
        modify(list, i, Some(kind), gone);
        return Ok(());
    }
    if ENABLE.load(Ordering::Relaxed) == 0 {
        return Err(Errno::EINVAL);
    }
    file.mark_locked();
    list.push(Lease {
        id,
        file: Arc::downgrade(file),
        fd,
        kind,
        unlock_pending: false,
        downgrade_pending: false,
        break_time: 0,
        downgrade_time: 0,
    });
    Ok(())
}

/// `F_GETLEASE`: the lease of `file`, or the type that it has after a break, as
/// `fcntl_getlease` of Linux. Gives `F_RDLCK`, `F_WRLCK` or `F_UNLCK`.
pub fn get(file: &File) -> i32 {
    let Some(inode) = file.inode() else { return F_UNLCK };
    let key = inode_key(inode);
    let id = crate::lock::file_id(file);
    let mut gone = Vec::new();
    let kind = {
        let mut leases = LEASES.lock();
        let Some(list) = leases.get_mut(&key) else { return F_UNLCK };
        time_out(list, &mut gone);
        let kind = list.iter().find(|l| l.id == id).map_or(F_UNLCK, Lease::target);
        if list.is_empty() {
            leases.remove(&key);
        }
        kind
    };
    clear_owners(&gone);
    kind
}

/// Breaks the leases of `inode` that conflict with an open with the flags `flags`, as
/// `__break_lease` of Linux. An open for a write breaks all the leases, and an open for a read
/// breaks the write leases. Each holder gets its signal. The call then waits until no lease
/// conflicts, or `EWOULDBLOCK` comes at once with `O_NONBLOCK`. A `truncate` calls this with
/// `O_WRONLY`.
///
/// # Errors
///
/// Gives `EWOULDBLOCK` with `O_NONBLOCK` if a lease conflicts, and `ERESTARTSYS` if a signal
/// stops the wait.
pub fn break_lease(inode: &InodeRef, flags: u32) -> Result<()> {
    let key = inode_key(inode);
    let want_write = flags & o::O_ACCMODE != o::O_RDONLY;
    let mut signals: Vec<(Arc<File>, i32)> = Vec::new();
    let mut gone = Vec::new();
    {
        let mut leases = LEASES.lock();
        let Some(list) = leases.get_mut(&key) else { return Ok(()) };
        time_out(list, &mut gone);
        if list.iter().any(|l| l.conflicts(want_write)) {
            let secs = u64::from(BREAK_TIME.load(Ordering::Relaxed));
            let time = if secs > 0 { ticks() + secs * HZ } else { 0 };
            for lease in list.iter_mut().filter(|l| l.conflicts(want_write)) {
                if want_write {
                    if lease.unlock_pending {
                        continue;
                    }
                    lease.unlock_pending = true;
                    lease.break_time = time;
                } else {
                    if lease.unlock_pending || lease.downgrade_pending {
                        continue;
                    }
                    lease.downgrade_pending = true;
                    lease.downgrade_time = time;
                }
                if let Some(file) = lease.file.upgrade() {
                    signals.push((file, lease.fd));
                }
            }
        }
        if list.is_empty() {
            leases.remove(&key);
        }
    }
    clear_owners(&gone);
    // As `lease_break_callback` of Linux.
    for (file, fd) in &signals {
        crate::notify::dnotify::sigio(file, *fd, crate::file::poll_code::POLL_MSG);
    }
    drop(signals);
    drop(gone);
    loop {
        // The first time of a pending change of a lease that conflicts.
        let deadline = {
            let mut gone = Vec::new();
            let deadline = {
                let mut leases = LEASES.lock();
                let Some(list) = leases.get_mut(&key) else { return Ok(()) };
                time_out(list, &mut gone);
                let deadline = list
                    .iter()
                    .filter(|l| l.conflicts(want_write))
                    .map(|l| if l.unlock_pending { l.break_time } else { l.downgrade_time })
                    .map(|t| if t == 0 { u64::MAX } else { t })
                    .min();
                if list.is_empty() {
                    leases.remove(&key);
                }
                deadline
            };
            clear_owners(&gone);
            match deadline {
                None => return Ok(()),
                Some(_) if flags & o::O_NONBLOCK != 0 => return Err(Errno::EWOULDBLOCK),
                Some(d) => d,
            }
        };
        let cond = || {
            let leases = LEASES.lock();
            let conflict =
                leases.get(&key).is_some_and(|l| l.iter().any(|l| l.conflicts(want_write)));
            if !conflict {
                Some(Ok(()))
            } else if crate::wait::interrupted() {
                Some(Err(Errno::ERESTARTSYS))
            } else {
                None
            }
        };
        let done = if deadline == u64::MAX {
            Some(LEASE_WAIT.wait_until(cond))
        } else {
            LEASE_WAIT.wait_until_timeout(deadline, cond)
        };
        if let Some(result) = done {
            return result;
        }
    }
}

/// Removes the lease of the open file description `file`, because it closes, as
/// `locks_remove_lease` of Linux.
pub(crate) fn close_file(file: &File) {
    let Some(inode) = file.inode() else { return };
    let key = inode_key(inode);
    let id = crate::lock::file_id(file);
    let mut leases = LEASES.lock();
    if let Some(list) = leases.get_mut(&key) {
        let before = list.len();
        list.retain(|l| l.id != id);
        if list.len() != before {
            LEASE_WAIT.wake_all();
        }
        if list.is_empty() {
            leases.remove(&key);
        }
    }
}

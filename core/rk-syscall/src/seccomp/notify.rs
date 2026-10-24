//! The notifications of `SECCOMP_RET_USER_NOTIF` and the file of the listener.
//!
//! A filter with a listener sends a notification for each call that gives
//! `SECCOMP_RET_USER_NOTIF`. The thread waits until the supervisor reads the notification with
//! `SECCOMP_IOCTL_NOTIF_RECV` and replies with `SECCOMP_IOCTL_NOTIF_SEND`. The supervisor can also
//! add a file to the table of the thread with `SECCOMP_IOCTL_NOTIF_ADDFD`. The thread adds the
//! file itself, because it can then use its own table and its own limits. This is the model of
//! kernel/seccomp.c of Linux.

use crate::cx::{Cx, SysResult};
use crate::run::Entry;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::any::Any;
use rk_abi::Errno;
use rk_abi::native::open::{O_CLOEXEC, O_RDWR};
use rk_frame::user::UserContext;
use rk_proc::Thread;
use rk_proc::bpf::SECCOMP_DATA_SIZE;
use rk_proc::limits::RLIMIT_NOFILE;
use rk_proc::ptrace::NO_SYSCALL;
use rk_proc::seccomp::{AddFd, Filter, Notif, NotifState, Notify};
use rk_vfs::file::{File, FileOps, events};

/// The commands of `ioctl` on a listener.
const SECCOMP_IOCTL_NOTIF_RECV: u32 = 0xc050_2100;
const SECCOMP_IOCTL_NOTIF_SEND: u32 = 0xc018_2101;
const SECCOMP_IOCTL_NOTIF_ID_VALID: u32 = 0x4008_2102;
/// The first value of `SECCOMP_IOCTL_NOTIF_ID_VALID`, with the wrong direction. Linux still
/// accepts it.
const SECCOMP_IOCTL_NOTIF_ID_VALID_WRONG_DIR: u32 = 0x8008_2102;
const SECCOMP_IOCTL_NOTIF_SET_FLAGS: u32 = 0x4008_2104;
/// `SECCOMP_IOCTL_NOTIF_ADDFD` without the direction and the size. The structure can grow, thus
/// the size in the command can change, and Linux accepts each direction.
const SECCOMP_IOCTL_NOTIF_ADDFD: u32 = 0x0000_2103;
/// The bits of the size in the command of `ioctl`.
const IOC_SIZE_MASK: u32 = 0x3fff << 16;
/// The bits of the direction in the command of `ioctl`.
const IOC_DIR_MASK: u32 = 0x3 << 30;

/// The sizes of the structures.
const NOTIF_SIZE: usize = 80;
const NOTIF_RESP_SIZE: usize = 24;
const ADDFD_SIZE: usize = 24;
const PAGE_SIZE: usize = 4096;

/// `SECCOMP_USER_NOTIF_FLAG_CONTINUE`: the thread runs the call.
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
/// `SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP`: the supervisor and the thread run one after the other.
const SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP: u64 = 1;
/// The flags of `SECCOMP_IOCTL_NOTIF_ADDFD`.
const SECCOMP_ADDFD_FLAG_SETFD: u32 = 1;
const SECCOMP_ADDFD_FLAG_SEND: u32 = 2;

/// The operations of the file of a listener.
pub(crate) struct Listener {
    notify: Arc<Notify>,
}

impl FileOps for Listener {
    fn poll(&self, _file: &File) -> u32 {
        let s = self.notify.lock();
        let mut ev = 0;
        if s.list.iter().any(|n| n.state == NotifState::Init) {
            ev |= events::POLLIN;
        }
        if s.list.iter().any(|n| n.state == NotifState::Sent) {
            ev |= events::POLLOUT;
        }
        if s.orphaned {
            ev |= events::POLLHUP;
        }
        ev
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

impl Drop for Listener {
    /// The listener is closed: each notification without a reply gives `ENOSYS`, as
    /// `seccomp_notify_release` of Linux does.
    fn drop(&mut self) {
        let mut s = self.notify.lock();
        s.closed = true;
        for n in s.list.iter_mut().filter(|n| n.state != NotifState::Replied) {
            n.state = NotifState::Replied;
            n.error = -i32::from(Errno::ENOSYS.get());
            n.val = 0;
        }
        drop(s);
        self.notify.wake();
    }
}

/// Makes the file of a new listener. The descriptor has `FD_CLOEXEC`, as in Linux.
pub(super) fn listener_file(notify: Arc<Notify>) -> Arc<File> {
    File::with_ops(Arc::new(Listener { notify }), None, O_RDWR)
}

/// What ends the wait of the thread.
enum Wake {
    /// The supervisor replied with the value, the error and the flags.
    Replied(i64, i32, u32),
    /// The supervisor asked to add a file.
    AddFd(Arc<AddFd>),
    /// A signal came.
    Signal,
}

/// Sends a notification to the listener of `matched` and waits for the reply, as
/// `seccomp_do_user_notification` of Linux does.
pub(super) fn user_notif(
    thread: &Arc<Thread>,
    regs: &mut UserContext,
    number: u64,
    matched: &Arc<Filter>,
    data: [u8; SECCOMP_DATA_SIZE],
) -> Entry {
    // Without a listener, the call gives `ENOSYS`.
    regs.set_syscall_return(Errno::ENOSYS.to_syscall_return() as u64);
    let Some(notify) = matched.notify() else { return Entry::Run(NO_SYSCALL) };
    let id = {
        let mut s = notify.lock();
        if s.closed {
            return Entry::Run(NO_SYSCALL);
        }
        let id = s.next_id;
        s.next_id += 1;
        let tid = thread.tid();
        s.list.push(Notif {
            id,
            tid,
            data,
            state: NotifState::Init,
            val: 0,
            error: 0,
            flags: 0,
            addfd: VecDeque::new(),
        });
        id
    };
    notify.wake();
    let wake = loop {
        let wake = notify.wait.wait_until(|| {
            let mut s = notify.lock();
            let n = s.find(id)?;
            if let Some(a) = n.addfd.pop_front() {
                return Some(Wake::AddFd(a));
            }
            if n.state == NotifState::Replied {
                return Some(Wake::Replied(n.val, n.error, n.flags));
            }
            // After the supervisor received the notification, a filter with
            // `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` waits for a fatal signal only.
            let killable = notify.wait_killable && n.state != NotifState::Init;
            thread.set_killable_wait(killable);
            let signal =
                if killable { thread.fatal_signal_pending() } else { thread.signal_pending() };
            signal.then_some(Wake::Signal)
        });
        thread.set_killable_wait(false);
        let Wake::AddFd(a) = wake else { break wake };
        let r = add_fd(thread, &a);
        let mut s = notify.lock();
        if a.send
            && let Some(n) = s.find(id)
        {
            // A failed add gives the notification back to the supervisor.
            match r {
                Ok(fd) => {
                    n.flags = 0;
                    n.error = 0;
                    n.val = i64::from(fd);
                }
                Err(_) => n.state = NotifState::Sent,
            }
        }
        *a.result.lock() = Some(r);
        drop(s);
        notify.wake();
    };
    {
        let mut s = notify.lock();
        if let Some(i) = s.list.iter().position(|n| n.id == id) {
            let n = s.list.remove(i);
            // The thread did not add these files, and it will not.
            for a in n.addfd {
                *a.result.lock() = Some(Err(Errno::ESRCH));
            }
        }
    }
    notify.wake();
    match wake {
        Wake::Replied(_, _, flags) if flags & SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 => {
            Entry::Run(number)
        }
        Wake::Replied(val, error, _) => {
            let ret = if error != 0 { i64::from(error) } else { val };
            regs.set_syscall_return(ret as u64);
            Entry::Run(NO_SYSCALL)
        }
        _ if thread.is_killed() => Entry::GroupExit,
        // The signal comes first, and then the call starts again.
        _ => {
            regs.set_syscall_return(Errno::ERESTARTSYS.to_syscall_return() as u64);
            Entry::Skip(number)
        }
    }
}

/// Adds the file of `a` to the table of `thread`, with the `RLIMIT_NOFILE` of its process.
fn add_fd(thread: &Thread, a: &AddFd) -> Result<i32, Errno> {
    let process = thread.process();
    let files = process.files().ok_or(Errno::ESRCH)?;
    let limit = usize::try_from(process.limit(RLIMIT_NOFILE).cur).unwrap_or(usize::MAX);
    let file = a.file.clone();
    match a.fd {
        None => files.lock().insert_limited(file, a.cloexec, limit),
        Some(fd) => {
            let old = files.lock().set_limited(fd, file, a.cloexec, limit)?;
            drop(old);
            Ok(fd)
        }
    }
}

/// Gives the notifications of the listener `file`, or `None` if `file` is not a listener.
pub(crate) fn listener_of(file: &File) -> Option<Arc<Notify>> {
    let listener = file.ops().as_any()?.downcast_ref::<Listener>()?;
    Some(listener.notify.clone())
}

/// The `ioctl` commands of a listener.
pub(crate) fn ioctl(cx: &Cx<'_>, notify: &Notify, cmd: u32, arg: u64) -> SysResult {
    match cmd {
        SECCOMP_IOCTL_NOTIF_RECV => recv(cx, notify, arg),
        SECCOMP_IOCTL_NOTIF_SEND => send(cx, notify, arg),
        SECCOMP_IOCTL_NOTIF_ID_VALID | SECCOMP_IOCTL_NOTIF_ID_VALID_WRONG_DIR => {
            let id: u64 = cx.read_val(arg)?;
            let mut s = notify.lock();
            match s.find(id) {
                Some(n) if n.state == NotifState::Sent => Ok(0),
                _ => Err(Errno::ENOENT),
            }
        }
        SECCOMP_IOCTL_NOTIF_SET_FLAGS => {
            if arg & !SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP != 0 {
                return Err(Errno::EINVAL);
            }
            notify.lock().sync = arg != 0;
            Ok(0)
        }
        _ if cmd & !(IOC_SIZE_MASK | IOC_DIR_MASK) == SECCOMP_IOCTL_NOTIF_ADDFD => {
            addfd(cx, notify, arg, ((cmd & IOC_SIZE_MASK) >> 16) as usize)
        }
        _ => Err(Errno::EINVAL),
    }
}

/// `SECCOMP_IOCTL_NOTIF_RECV`: waits for a notification that the supervisor did not receive yet,
/// and writes it to `struct seccomp_notif`.
fn recv(cx: &Cx<'_>, notify: &Notify, arg: u64) -> SysResult {
    // The structure must be zero, so that it can grow later.
    if cx.read_bytes(arg, NOTIF_SIZE)?.iter().any(|&b| b != 0) {
        return Err(Errno::EINVAL);
    }
    let thread = cx.thread;
    let (id, tid, data) = notify.wait.wait_until(|| {
        let mut s = notify.lock();
        if let Some(n) = s.list.iter_mut().find(|n| n.state == NotifState::Init) {
            n.state = NotifState::Sent;
            return Some(Ok((n.id, n.tid, n.data)));
        }
        if s.orphaned {
            return Some(Err(Errno::ENOENT));
        }
        thread.signal_pending().then_some(Err(Errno::ERESTARTSYS))
    })?;
    notify.wake();
    let mut buf = [0u8; NOTIF_SIZE];
    buf[0..8].copy_from_slice(&id.to_ne_bytes());
    buf[8..12].copy_from_slice(&tid.to_ne_bytes());
    buf[16..].copy_from_slice(&data);
    if cx.write_bytes(arg, &buf).is_err() {
        // The supervisor can receive the notification again.
        if let Some(n) = notify.lock().find(id)
            && n.state == NotifState::Sent
        {
            n.state = NotifState::Init;
        }
        notify.wake();
        return Err(Errno::EFAULT);
    }
    Ok(0)
}

/// `SECCOMP_IOCTL_NOTIF_SEND`: the reply to a notification.
fn send(cx: &Cx<'_>, notify: &Notify, arg: u64) -> SysResult {
    let b = cx.read_bytes(arg, NOTIF_RESP_SIZE)?;
    let id = u64::from_ne_bytes(word(&b, 0));
    let val = i64::from_ne_bytes(word(&b, 8));
    let error = i32::from_ne_bytes(half(&b, 16));
    let flags = u32::from_ne_bytes(half(&b, 20));
    if flags & !SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 && (error != 0 || val != 0) {
        return Err(Errno::EINVAL);
    }
    let mut s = notify.lock();
    let n = s.find(id).ok_or(Errno::ENOENT)?;
    // The supervisor replies one time.
    if n.state != NotifState::Sent {
        return Err(Errno::EINPROGRESS);
    }
    n.state = NotifState::Replied;
    n.val = val;
    n.error = error;
    n.flags = flags;
    drop(s);
    notify.wake();
    Ok(0)
}

/// `SECCOMP_IOCTL_NOTIF_ADDFD`: asks the thread of a notification to add a file to its table,
/// and waits until it did. `size` is the size of the structure in the command.
fn addfd(cx: &Cx<'_>, notify: &Notify, arg: u64, size: usize) -> SysResult {
    if !(ADDFD_SIZE..PAGE_SIZE).contains(&size) {
        return Err(Errno::EINVAL);
    }
    let b = cx.read_bytes(arg, size)?;
    // The bytes after the fields that the kernel knows must be zero.
    if b[ADDFD_SIZE..].iter().any(|&x| x != 0) {
        return Err(Errno::E2BIG);
    }
    let id = u64::from_ne_bytes(word(&b, 0));
    let flags = u32::from_ne_bytes(half(&b, 8));
    let srcfd = u32::from_ne_bytes(half(&b, 12));
    let newfd = u32::from_ne_bytes(half(&b, 16));
    let newfd_flags = u32::from_ne_bytes(half(&b, 20));
    if newfd_flags & !O_CLOEXEC != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & !(SECCOMP_ADDFD_FLAG_SETFD | SECCOMP_ADDFD_FLAG_SEND) != 0 {
        return Err(Errno::EINVAL);
    }
    let setfd = flags & SECCOMP_ADDFD_FLAG_SETFD != 0;
    if newfd != 0 && !setfd {
        return Err(Errno::EINVAL);
    }
    let file = cx.file(u64::from(srcfd))?;
    let send = flags & SECCOMP_ADDFD_FLAG_SEND != 0;
    let a = Arc::new(AddFd {
        file,
        fd: setfd.then_some(newfd as i32),
        cloexec: newfd_flags & O_CLOEXEC != 0,
        send,
        result: rk_frame::sync::SpinLock::new(None),
    });
    {
        let mut s = notify.lock();
        let n = s.find(id).ok_or(Errno::ENOENT)?;
        if n.state != NotifState::Sent {
            return Err(Errno::EINPROGRESS);
        }
        if send {
            if !n.addfd.is_empty() {
                return Err(Errno::EBUSY);
            }
            n.state = NotifState::Replied;
        }
        n.addfd.push_back(a.clone());
    }
    notify.wake();
    let thread = cx.thread;
    let r = notify.wait.wait_until(|| {
        if let Some(r) = *a.result.lock() {
            return Some(Some(r));
        }
        thread.signal_pending().then_some(None)
    });
    match r {
        Some(r) => Ok(r? as u64),
        None => {
            // A signal came, but the thread can have added the file in the meantime.
            let mut s = notify.lock();
            if let Some(n) = s.find(id) {
                n.addfd.retain(|x| !Arc::ptr_eq(x, &a));
            }
            drop(s);
            match *a.result.lock() {
                Some(r) => Ok(r? as u64),
                None => Err(Errno::ERESTARTSYS),
            }
        }
    }
}

/// The 8 bytes at `at`.
fn word(b: &[u8], at: usize) -> [u8; 8] {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[at..at + 8]);
    w
}

/// The 4 bytes at `at`.
fn half(b: &[u8], at: usize) -> [u8; 4] {
    let mut w = [0u8; 4];
    w.copy_from_slice(&b[at..at + 4]);
    w
}

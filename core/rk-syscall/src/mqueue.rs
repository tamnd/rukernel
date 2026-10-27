//! The POSIX message queues: `mq_open`, `mq_unlink`, `mq_timedsend`, `mq_timedreceive`,
//! `mq_notify` and `mq_getsetattr`, from ipc/mqueue.c of Linux.
//!
//! A queue is a file of the mqueue file system. All the mounts of the file system and the system
//! calls share one root directory, as the one IPC name space of rukernel. The system calls use an
//! internal mount of the root, so a queue works without a mount. A read of a queue gives a line
//! of status, and `poll` tells if a receive or a send can go on.
//!
//! A queue gives the message with the highest priority first. The pure part of the queue is
//! `rk_vfs::ipc::PrioQueue`. A send to a full queue and a receive from an empty queue wait until
//! the absolute `CLOCK_REALTIME` timeout, unless the file has `O_NONBLOCK`.
//!
//! `mq_notify` registers one process that the kernel tells when a message comes to an empty
//! queue that no receiver waits for. `SIGEV_SIGNAL` sends a signal with `SI_MESGQ`. For
//! `SIGEV_THREAD`, musl makes a thread that waits on an `AF_NETLINK` socket, and the kernel puts
//! a cookie of 32 bytes on that socket with `NetlinkSocket::send_from_kernel`, as
//! `netlink_sendskb` of Linux does.

use crate::cx::{Cx, SysResult};
use crate::info::NSEC_PER_SEC;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::open::{O_ACCMODE, O_CLOEXEC, O_CREAT, O_EXCL, O_NONBLOCK, O_RDWR, O_WRONLY};
use rk_abi::native::poll::{POLLRDNORM, POLLWRNORM};
use rk_abi::native::time::CLOCK_REALTIME;
use rk_abi::native::types::KernelTimespec;
use rk_frame::sync::{Once, SpinLock};
use rk_frame::time::HZ;
use rk_net::Socket;
use rk_net::netlink::NetlinkSocket;
use rk_proc::Process;
use rk_proc::signal::{NSIG, SigInfo};
use rk_vfs::cred::{Cred, cap, may};
use rk_vfs::file::{File, FileOps, events};
use rk_vfs::fstype::{FsType, MountArgs};
use rk_vfs::inode::{
    DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, Timespec, mode,
};
use rk_vfs::ipc::{
    MQ_HARD_MSG_MAX, MQ_HARD_MSGSIZE_MAX, MQ_MSG_DEFAULT, MQ_MSG_MAX, MQ_MSGSIZE_DEFAULT,
    MQ_MSGSIZE_MAX, MQ_QUEUES_MAX, PrioQueue,
};
use rk_vfs::wait::{PollTable, WaitQueue};
use rk_vfs::{Dentry, Location, Mount, MountNamespace, MountSource};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// The magic number of the file system, for `statfs`.
const MQUEUE_MAGIC: u64 = 0x1980_0202;
/// The number of priorities.
const MQ_PRIO_MAX: u64 = 32768;
/// The longest name of a queue.
const NAME_MAX: usize = 255;
/// The size of a queue file, as `FILENT_SIZE` of Linux.
const FILENT_SIZE: u64 = 80;
/// The `si_code` of the signal of `mq_notify`.
const SI_MESGQ: i32 = -3;
/// The kinds of notification of `struct sigevent`.
const SIGEV_SIGNAL: u32 = 0;
const SIGEV_NONE: u32 = 1;
const SIGEV_THREAD: u32 = 2;
/// The layout of `struct sigevent`.
const SIGEVENT_SIZE: usize = 64;
const SIGEV_SIGNO: usize = 8;
const SIGEV_NOTIFY: usize = 12;
/// The size of the cookie of `SIGEV_THREAD`, and the values of its last byte.
const NOTIFY_COOKIE_LEN: usize = 32;
const NOTIFY_WOKENUP: u8 = 1;
const NOTIFY_REMOVED: u8 = 2;

/// The attributes of a queue, as `struct mq_attr`.
#[derive(Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct MqAttr {
    flags: i64,
    maxmsg: i64,
    msgsize: i64,
    curmsgs: i64,
    pad: [i64; 4],
}

/// The way that the kernel tells the registered process about a message.
enum NotifyKind {
    None,
    Signal { signo: u32, value: u64 },
    Thread { sock: Arc<dyn Socket>, cookie: [u8; NOTIFY_COOKIE_LEN] },
}

/// The registration of `mq_notify`.
struct Notify {
    pid: u32,
    process: Weak<Process>,
    kind: NotifyKind,
}

impl Notify {
    /// The value of `sigev_notify`.
    fn code(&self) -> u32 {
        match self.kind {
            NotifyKind::None => SIGEV_NONE,
            NotifyKind::Signal { .. } => SIGEV_SIGNAL,
            NotifyKind::Thread { .. } => SIGEV_THREAD,
        }
    }

    /// Ends the registration. A thread of `SIGEV_THREAD` gets the cookie with `NOTIFY_REMOVED`.
    fn remove(self) {
        if let NotifyKind::Thread { sock, mut cookie } = self.kind {
            cookie[NOTIFY_COOKIE_LEN - 1] = NOTIFY_REMOVED;
            send_cookie(&sock, &cookie);
        }
    }
}

/// The state of a queue.
struct MqState {
    msgs: PrioQueue,
    notify: Option<Notify>,
    /// The number of tasks that wait in a receive.
    receivers: usize,
    uid: u32,
    gid: u32,
    perm: u32,
    atime: Timespec,
    mtime: Timespec,
    ctime: Timespec,
}

/// A queue: the inode of a file of the mqueue file system.
struct MqInode {
    ino: u64,
    state: SpinLock<MqState>,
    wait: Arc<WaitQueue>,
    /// The count of the changes, for an edge triggered epoll entry.
    events: AtomicU64,
}

impl MqInode {
    fn new(maxmsg: usize, msgsize: usize, uid: u32, gid: u32, perm: u32) -> Arc<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(2);
        let now = rk_vfs::now();
        Arc::new(Self {
            ino: NEXT.fetch_add(1, Ordering::Relaxed),
            state: SpinLock::new(MqState {
                msgs: PrioQueue::new(maxmsg, msgsize),
                notify: None,
                receivers: 0,
                uid,
                gid,
                perm: perm & 0o7777,
                atime: now,
                mtime: now,
                ctime: now,
            }),
            wait: Arc::new(WaitQueue::new()),
            events: AtomicU64::new(0),
        })
    }

    fn wake(&self) {
        self.events.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
    }

    /// The line of status that a read gives, as `mqueue_read_file` of Linux.
    fn status(&self) -> Vec<u8> {
        let s = self.state.lock();
        let (code, signo, pid) = match &s.notify {
            Some(n) => {
                let signo = match n.kind {
                    NotifyKind::Signal { signo, .. } => signo,
                    _ => 0,
                };
                (n.code(), signo, n.pid)
            }
            None => (0, 0, 0),
        };
        format!(
            "QSIZE:{:<10} NOTIFY:{:<5} SIGNO:{:<5} NOTIFY_PID:{:<6}\n",
            s.msgs.bytes(),
            code,
            signo,
            pid
        )
        .into_bytes()
    }
}

impl Inode for MqInode {
    fn metadata(&self) -> Metadata {
        let s = self.state.lock();
        Metadata {
            dev: root().dev,
            ino: self.ino,
            mode: mode::S_IFREG | s.perm,
            nlink: 1,
            uid: s.uid,
            gid: s.gid,
            size: FILENT_SIZE,
            blksize: 4096,
            atime: s.atime,
            mtime: s.mtime,
            ctime: s.ctime,
            ..Metadata::default()
        }
    }

    fn set_attr(&self, attr: &SetAttr) -> Result<()> {
        if attr.size.is_some() {
            return Err(Errno::EINVAL);
        }
        let mut s = self.state.lock();
        if let Some(m) = attr.mode {
            s.perm = m & 0o7777;
        }
        if let Some(uid) = attr.uid {
            s.uid = uid;
        }
        if let Some(gid) = attr.gid {
            s.gid = gid;
        }
        if let Some(t) = attr.atime {
            s.atime = t;
        }
        if let Some(t) = attr.mtime {
            s.mtime = t;
        }
        s.ctime = rk_vfs::now();
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let text = self.status();
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(text.len());
        let n = buf.len().min(text.len() - start);
        buf[..n].copy_from_slice(&text[start..start + n]);
        Ok(n)
    }

    fn fs_id(&self) -> u64 {
        root().dev
    }

    fn fs_magic(&self) -> u64 {
        MQUEUE_MAGIC
    }
}

/// The root directory of the file system: the queues by name.
struct MqRoot {
    dev: u64,
    queues: SpinLock<BTreeMap<Vec<u8>, Arc<MqInode>>>,
    /// The owner, the group and the permission bits.
    attr: SpinLock<(u32, u32, u32)>,
}

impl MqRoot {
    /// Adds the queue `name`. Gives `EEXIST` if the name is in use, and `ENOSPC` if the number
    /// of queues is at `fs.mqueue.queues_max` and the caller does not have `CAP_SYS_RESOURCE`.
    fn add(&self, name: &[u8], queue: &Arc<MqInode>, cred: &Cred) -> Result<()> {
        let mut queues = self.queues.lock();
        if queues.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        let max = MQ_QUEUES_MAX.get().max(0) as usize;
        if queues.len() >= max && !cred.capable(cap::SYS_RESOURCE) {
            return Err(Errno::ENOSPC);
        }
        queues.insert(name.to_vec(), queue.clone());
        Ok(())
    }

    fn find(&self, name: &[u8]) -> Option<Arc<MqInode>> {
        self.queues.lock().get(name).cloned()
    }
}

impl Inode for MqRoot {
    fn metadata(&self) -> Metadata {
        let (uid, gid, perm) = *self.attr.lock();
        Metadata {
            dev: self.dev,
            ino: 1,
            mode: mode::S_IFDIR | perm,
            nlink: 2,
            uid,
            gid,
            size: 2 * 20,
            blksize: 4096,
            ..Metadata::default()
        }
    }

    fn set_attr(&self, attr: &SetAttr) -> Result<()> {
        let mut a = self.attr.lock();
        if let Some(uid) = attr.uid {
            a.0 = uid;
        }
        if let Some(gid) = attr.gid {
            a.1 = gid;
        }
        if let Some(m) = attr.mode {
            a.2 = m & 0o7777;
        }
        Ok(())
    }

    fn lookup(&self, name: &[u8]) -> Result<InodeRef> {
        let queue: InodeRef = self.find(name).ok_or(Errno::ENOENT)?;
        Ok(queue)
    }

    /// Makes a queue with the default attributes, for `open` with `O_CREAT` in a mount.
    fn create(&self, name: &[u8], kind: FileType, perm: u32, _rdev: u64) -> Result<InodeRef> {
        if kind != FileType::Regular {
            return Err(Errno::EINVAL);
        }
        let cred = rk_vfs::cred::current();
        let (maxmsg, msgsize) = default_attr();
        let queue = MqInode::new(maxmsg, msgsize, cred.fsuid, cred.fsgid, perm);
        self.add(name, &queue, &cred)?;
        Ok(queue)
    }

    fn unlink(&self, name: &[u8]) -> Result<()> {
        self.queues.lock().remove(name).map(|_| ()).ok_or(Errno::ENOENT)
    }

    fn read_dir(&self, pos: u64) -> Result<Option<(DirEntry, u64)>> {
        let entry = match pos {
            0 => DirEntry { ino: 1, kind: FileType::Directory, name: b".".to_vec() },
            1 => DirEntry { ino: 1, kind: FileType::Directory, name: b"..".to_vec() },
            _ => {
                let queues = self.queues.lock();
                let Some((name, q)) = queues.iter().nth((pos - 2) as usize) else {
                    return Ok(None);
                };
                DirEntry { ino: q.ino, kind: FileType::Regular, name: name.clone() }
            }
        };
        Ok(Some((entry, pos + 1)))
    }

    fn fs_id(&self) -> u64 {
        self.dev
    }

    fn fs_magic(&self) -> u64 {
        MQUEUE_MAGIC
    }
}

static ROOT: Once<Arc<MqRoot>> = Once::new();
static MOUNT: Once<Arc<Mount>> = Once::new();

/// The root directory, which all the mounts share.
fn root() -> &'static Arc<MqRoot> {
    ROOT.call_once(|| {
        Arc::new(MqRoot {
            dev: rk_vfs::anon_dev(),
            queues: SpinLock::new(BTreeMap::new()),
            attr: SpinLock::new((0, 0, mode::S_ISVTX | 0o777)),
        })
    })
}

/// The internal mount of the root, for the files that `mq_open` gives.
fn mount() -> &'static Arc<Mount> {
    MOUNT.call_once(|| {
        let root: InodeRef = root().clone();
        let source = MountSource { source: b"mqueue".to_vec(), fstype: "mqueue", flags: 0 };
        MountNamespace::detached(Dentry::new_root(root), source)
    })
}

fn make_root(_args: &MountArgs<'_>) -> Result<InodeRef> {
    let root: InodeRef = root().clone();
    Ok(root)
}

/// Registers the mqueue file system type.
pub(crate) fn register() {
    rk_vfs::fstype::register(FsType { name: "mqueue", nodev: true, make: make_root });
}

/// The size and the number of messages of a queue without attributes. They are at most the
/// limits, as `mqueue_get_inode` of Linux.
fn default_attr() -> (usize, usize) {
    let maxmsg = MQ_MSG_DEFAULT.get().min(MQ_MSG_MAX.get());
    let msgsize = MQ_MSGSIZE_DEFAULT.get().min(MQ_MSGSIZE_MAX.get());
    (maxmsg.max(1) as usize, msgsize.max(1) as usize)
}

/// Checks the attributes of a new queue, as `mq_attr_ok` of Linux.
fn check_attr(attr: &MqAttr, cred: &Cred) -> Result<(usize, usize)> {
    if attr.maxmsg <= 0 || attr.msgsize <= 0 {
        return Err(Errno::EINVAL);
    }
    let (max_msg, max_size) = if cred.capable(cap::SYS_RESOURCE) {
        (MQ_HARD_MSG_MAX, MQ_HARD_MSGSIZE_MAX)
    } else {
        (MQ_MSG_MAX.get(), MQ_MSGSIZE_MAX.get())
    };
    if attr.maxmsg > i64::from(max_msg) || attr.msgsize > i64::from(max_size) {
        return Err(Errno::EINVAL);
    }
    Ok((attr.maxmsg as usize, attr.msgsize as usize))
}

/// The operations of a file that `mq_open` gives.
struct MqFile {
    queue: Arc<MqInode>,
}

impl FileOps for MqFile {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        let pos = file.pos();
        let n = self.queue.read_at(pos, buf)?;
        file.set_pos(pos + n as u64);
        Ok(n)
    }

    fn poll_wait(&self, _file: &File, table: &mut PollTable) {
        table.add(&self.queue.wait);
    }

    fn poll(&self, _file: &File) -> u32 {
        let s = self.queue.state.lock();
        let mut ev = 0;
        if !s.msgs.is_empty() {
            ev |= events::POLLIN | POLLRDNORM;
        }
        if !s.msgs.is_full() {
            ev |= events::POLLOUT | POLLWRNORM;
        }
        ev
    }

    fn pollable(&self) -> bool {
        true
    }

    fn event_count(&self) -> u64 {
        self.queue.events.load(Ordering::Relaxed)
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

impl Drop for MqFile {
    /// The close of the last descriptor of the file ends the registration of the process that
    /// closes it, as `mqueue_flush_file` of Linux.
    fn drop(&mut self) {
        let Some(pid) = rk_proc::current_thread().map(|t| t.process().pid()) else { return };
        let mut s = self.queue.state.lock();
        if s.notify.as_ref().is_some_and(|n| n.pid == pid) {
            if let Some(n) = s.notify.take() {
                drop(s);
                n.remove();
            }
        }
    }
}

/// Reads the name of a queue. musl takes away the first `/`.
fn read_name(cx: &Cx<'_>, addr: u64) -> Result<Vec<u8>> {
    let name = cx.read_path(addr)?;
    if name.len() > NAME_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    // The name is one entry of the root, as `lookup_one_len` of Linux takes it.
    if name.contains(&b'/') || name == b"." || name == b".." {
        return Err(Errno::EACCES);
    }
    Ok(name)
}

/// The queue of the descriptor `fd`. Gives `EBADF` if the file is not a queue.
fn queue_of(cx: &Cx<'_>, fd: u64) -> Result<(Arc<File>, Arc<MqInode>)> {
    let file = cx.file(fd).map_err(|_| Errno::EBADF)?;
    let queue = file
        .ops()
        .as_any()
        .and_then(|a| a.downcast_ref::<MqFile>())
        .map(|f| f.queue.clone())
        .ok_or(Errno::EBADF)?;
    Ok((file, queue))
}

/// Reads an absolute timeout of `CLOCK_REALTIME` and gives its deadline in ticks.
fn read_timeout(cx: &Cx<'_>, addr: u64) -> Result<Option<u64>> {
    if addr == 0 {
        return Ok(None);
    }
    let ts: KernelTimespec = cx.read_val(addr)?;
    let ns = crate::info::timespec_ns(&ts)?;
    Ok(Some(crate::info::boot_ns(CLOCK_REALTIME, ns).div_ceil(NSEC_PER_SEC / HZ)))
}

pub(crate) fn mq_open(cx: &Cx<'_>, name: u64, flags: u64, perm: u64, attr: u64) -> SysResult {
    let flags = flags as u32;
    let attr: Option<MqAttr> = if attr != 0 { Some(cx.read_val(attr)?) } else { None };
    let name = read_name(cx, name)?;
    let fs = cx.fs()?;
    let cred = cx.process().cred();
    let root = root();
    let mut created = false;
    let queue = match root.find(&name) {
        Some(queue) => {
            if flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL {
                return Err(Errno::EEXIST);
            }
            if flags & O_ACCMODE == O_ACCMODE {
                return Err(Errno::EINVAL);
            }
            let access = match flags & O_ACCMODE {
                O_WRONLY => may::WRITE,
                O_RDWR => may::READ | may::WRITE,
                _ => may::READ,
            };
            cred.permission(&queue.metadata(), access)?;
            queue
        }
        None if flags & O_CREAT == 0 => return Err(Errno::ENOENT),
        None => {
            cred.permission(&root.metadata(), may::WRITE | may::EXEC)?;
            let (maxmsg, msgsize) = match &attr {
                Some(a) => check_attr(a, &cred)?,
                None => default_attr(),
            };
            let perm = perm as u32 & 0o7777 & !fs.umask();
            let queue = MqInode::new(maxmsg, msgsize, cred.fsuid, cred.fsgid, perm);
            root.add(&name, &queue, &cred)?;
            created = true;
            queue
        }
    };
    let inode: InodeRef = queue.clone();
    let dentry = mount().root().clone().add_child(&name, inode);
    let location = Location { mount: mount().clone(), dentry };
    let keep = O_ACCMODE | O_NONBLOCK;
    let file = File::with_ops(Arc::new(MqFile { queue }), Some(location), flags & keep);
    let fd = cx.files()?.lock().insert(file, flags & O_CLOEXEC != 0);
    // Linux takes the descriptor first, so a call that gives `EMFILE` makes no queue.
    if fd.is_err() && created {
        let _ = root.unlink(&name);
        mount().root().forget_child(&name);
    }
    Ok(fd? as u64)
}

pub(crate) fn mq_unlink(cx: &Cx<'_>, name: u64) -> SysResult {
    let name = read_name(cx, name)?;
    let cred = cx.process().cred();
    let root = root();
    let queue = root.find(&name).ok_or(Errno::ENOENT)?;
    let dir = root.metadata();
    cred.permission(&dir, may::WRITE | may::EXEC)?;
    // The sticky bit of the root lets only the owner remove a queue. Linux gives `EACCES` here.
    cred.check_sticky(&dir, &queue.metadata()).map_err(|_| Errno::EACCES)?;
    root.unlink(&name)?;
    mount().root().forget_child(&name);
    Ok(0)
}

/// Tells the registered process that a message came to the empty queue, and ends the
/// registration, as `__do_notify` of Linux. `pid` and `uid` are the sender.
fn notify(s: &mut MqState, pid: u32, uid: u32) {
    let Some(n) = s.notify.take() else { return };
    match n.kind {
        NotifyKind::None => {}
        NotifyKind::Signal { signo, value } => {
            // `mq_notify` takes the signal 0, and then sends nothing.
            if signo != 0 {
                if let Some(process) = n.process.upgrade() {
                    let mut info = SigInfo::new(signo, SI_MESGQ, pid);
                    info.uid = uid;
                    info.value = value;
                    rk_proc::send_signal(&process, info);
                }
            }
        }
        NotifyKind::Thread { sock, mut cookie } => {
            cookie[NOTIFY_COOKIE_LEN - 1] = NOTIFY_WOKENUP;
            send_cookie(&sock, &cookie);
        }
    }
}

pub(crate) fn mq_timedsend(
    cx: &Cx<'_>,
    fd: u64,
    msg: u64,
    len: u64,
    prio: u64,
    timeout: u64,
) -> SysResult {
    let deadline = read_timeout(cx, timeout)?;
    let prio = prio as u32;
    if u64::from(prio) >= MQ_PRIO_MAX {
        return Err(Errno::EINVAL);
    }
    let (file, queue) = queue_of(cx, fd)?;
    if !file.flags().writable() {
        return Err(Errno::EBADF);
    }
    if len > queue.state.lock().msgs.msgsize() as u64 {
        return Err(Errno::EMSGSIZE);
    }
    let data = cx.read_bytes(msg, len as usize)?;
    let nonblock = file.flags().nonblock();
    let process = cx.process();
    let pid = process.pid();
    let uid = process.cred().uid;
    let thread = cx.thread;
    let mut data = Some(data);
    let mut step = || {
        let mut s = queue.state.lock();
        if !s.msgs.is_full() {
            let was_empty = s.msgs.is_empty();
            s.msgs.push(prio, data.take().unwrap_or_default()).ok()?;
            let now = rk_vfs::now();
            s.mtime = now;
            s.ctime = now;
            // A waiting receiver takes the message, so the registered process is not told.
            if was_empty && s.receivers == 0 {
                notify(&mut s, pid, uid);
            }
            return Some(Ok(()));
        }
        if nonblock {
            return Some(Err(Errno::EAGAIN));
        }
        if thread.signal_pending() {
            return Some(Err(Errno::ERESTARTSYS));
        }
        None
    };
    let r = match step() {
        Some(r) => r,
        None => queue
            .wait
            .wait_until_timeout(deadline.unwrap_or(u64::MAX), &mut step)
            .unwrap_or(Err(Errno::ETIMEDOUT)),
    };
    if r.is_ok() {
        queue.wake();
    }
    r.map(|()| 0)
}

pub(crate) fn mq_timedreceive(
    cx: &Cx<'_>,
    fd: u64,
    msg: u64,
    len: u64,
    prio: u64,
    timeout: u64,
) -> SysResult {
    let deadline = read_timeout(cx, timeout)?;
    let (file, queue) = queue_of(cx, fd)?;
    if !file.flags().readable() {
        return Err(Errno::EBADF);
    }
    if len < queue.state.lock().msgs.msgsize() as u64 {
        return Err(Errno::EMSGSIZE);
    }
    let nonblock = file.flags().nonblock();
    let thread = cx.thread;
    let mut waiting = false;
    let mut step = || {
        let mut s = queue.state.lock();
        let r = if let Some(m) = s.msgs.pop() {
            let now = rk_vfs::now();
            s.atime = now;
            s.ctime = now;
            Some(Ok(m))
        } else if nonblock {
            Some(Err(Errno::EAGAIN))
        } else if thread.signal_pending() {
            Some(Err(Errno::ERESTARTSYS))
        } else {
            if !waiting {
                s.receivers += 1;
                waiting = true;
            }
            None
        };
        if r.is_some() && waiting {
            s.receivers -= 1;
            waiting = false;
        }
        r
    };
    let r = match step() {
        Some(r) => r,
        None => {
            let r = queue.wait.wait_until_timeout(deadline.unwrap_or(u64::MAX), &mut step);
            if r.is_none() && waiting {
                queue.state.lock().receivers -= 1;
            }
            r.unwrap_or(Err(Errno::ETIMEDOUT))
        }
    };
    let (p, data) = r?;
    queue.wake();
    if prio != 0 {
        cx.write_val(prio, &p)?;
    }
    cx.write_bytes(msg, &data)?;
    Ok(data.len() as u64)
}

pub(crate) fn mq_notify(cx: &Cx<'_>, fd: u64, sevp: u64) -> SysResult {
    let kind = if sevp == 0 {
        None
    } else {
        let b = cx.read_bytes(sevp, SIGEVENT_SIZE)?;
        let word = |off: usize| u32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]);
        let mut v = [0u8; 8];
        v.copy_from_slice(&b[..8]);
        let value = u64::from_ne_bytes(v);
        let (notify, signo) = (word(SIGEV_NOTIFY), word(SIGEV_SIGNO));
        Some(match notify {
            SIGEV_NONE => NotifyKind::None,
            SIGEV_SIGNAL if signo <= NSIG => NotifyKind::Signal { signo, value },
            SIGEV_THREAD => {
                let mut cookie = [0u8; NOTIFY_COOKIE_LEN];
                cookie.copy_from_slice(&cx.read_bytes(value, NOTIFY_COOKIE_LEN)?);
                let file = cx.file(u64::from(signo)).map_err(|_| Errno::EBADF)?;
                let sock = rk_net::socket_of(&file).ok_or(Errno::ENOTSOCK)?;
                if sock.as_any().downcast_ref::<NetlinkSocket>().is_none() {
                    return Err(Errno::EINVAL);
                }
                NotifyKind::Thread { sock, cookie }
            }
            _ => return Err(Errno::EINVAL),
        })
    };
    let (_, queue) = queue_of(cx, fd)?;
    let process = cx.process();
    let pid = process.pid();
    let mut s = queue.state.lock();
    match kind {
        None => {
            if s.notify.as_ref().is_some_and(|n| n.pid == pid) {
                if let Some(n) = s.notify.take() {
                    n.remove();
                }
                let now = rk_vfs::now();
                s.atime = now;
                s.ctime = now;
            }
        }
        Some(_) if s.notify.is_some() => return Err(Errno::EBUSY),
        Some(kind) => {
            s.notify = Some(Notify { pid, process: Arc::downgrade(&process), kind });
            let now = rk_vfs::now();
            s.atime = now;
            s.ctime = now;
        }
    }
    Ok(0)
}

pub(crate) fn mq_getsetattr(cx: &Cx<'_>, fd: u64, new: u64, old: u64) -> SysResult {
    let new: Option<MqAttr> = if new != 0 { Some(cx.read_val(new)?) } else { None };
    if new.is_some_and(|a| a.flags & !i64::from(O_NONBLOCK) != 0) {
        return Err(Errno::EINVAL);
    }
    let (file, queue) = queue_of(cx, fd)?;
    let current = {
        let s = queue.state.lock();
        MqAttr {
            flags: i64::from(file.flags().0 & O_NONBLOCK),
            maxmsg: s.msgs.maxmsg() as i64,
            msgsize: s.msgs.msgsize() as i64,
            curmsgs: s.msgs.len() as i64,
            pad: [0; 4],
        }
    };
    if let Some(a) = new {
        let flags = file.flags().0 & !O_NONBLOCK;
        file.set_status_flags(flags | (a.flags as u32 & O_NONBLOCK));
    }
    if old != 0 {
        cx.write_val(old, &current)?;
    }
    Ok(0)
}

/// Puts the cookie of `mq_notify` on the netlink socket of the thread of `SIGEV_THREAD`.
fn send_cookie(sock: &Arc<dyn Socket>, cookie: &[u8; NOTIFY_COOKIE_LEN]) {
    if let Some(sock) = sock.as_any().downcast_ref::<NetlinkSocket>() {
        sock.send_from_kernel(cookie.to_vec());
    }
}

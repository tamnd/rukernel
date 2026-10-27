//! fanotify, as fs/notify/fanotify/fanotify.c and fanotify_user.c of Linux.
//!
//! A fanotify group gets the events of open files: an access, a modification, an open and a
//! close, and the permission events before an open and a read. The marks of a group can be on an
//! inode, on a mount or on a file system. A read of the file of the group gives each event as
//! `struct fanotify_event_metadata` with a new descriptor of the file of the event. A process
//! that causes a permission event waits until the listener writes `struct fanotify_response`.
//!
//! The groups report a descriptor only. The groups that report a file handle (`FAN_REPORT_FID`
//! and the other FID bits), the mount events and the pre-content events are not supported.

use super::{Found, Group, Mark, Object, add_object_mark, destroy_mark, mask};
use crate::dentry::Location;
use crate::file::{File, FileOps, UserMemory, events};
use crate::inode::Result;
use crate::wait::{WaitQueue, poll_wake};
use alloc::collections::VecDeque;
use alloc::format;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::fanotify::{
    FAN_ALLOW, FAN_AUDIT, FAN_DENY, FAN_ENABLE_AUDIT, FAN_ERRNO_MASK, FAN_ERRNO_SHIFT,
    FAN_EVENT_METADATA_LEN, FAN_INFO, FAN_MARK_EVICTABLE, FAN_MARK_IGNORE, FAN_MARK_IGNORED_MASK,
    FAN_MARK_IGNORED_SURV_MODIFY, FAN_NOFD, FAN_ONDIR, FAN_PRE_ACCESS, FAN_REPORT_FD_ERROR,
    FAN_REPORT_TID, FANOTIFY_METADATA_VERSION,
};
use rk_abi::native::open as o;
use rk_abi::native::types::{FanotifyEventMetadata, FanotifyResponse};
use rk_frame::sync::{Once, SpinLock};

/// The events of a path, `FANOTIFY_PATH_EVENTS` of Linux.
pub const PATH_EVENTS: u32 = mask::ACCESS
    | mask::MODIFY
    | mask::CLOSE_WRITE
    | mask::CLOSE_NOWRITE
    | mask::OPEN
    | mask::OPEN_EXEC;

/// The permission events, `FANOTIFY_PERM_EVENTS` of Linux.
pub const PERM_EVENTS: u32 = mask::PERM_EVENTS | FAN_PRE_ACCESS;

/// The events that have a descriptor, `FANOTIFY_FD_EVENTS` of Linux.
pub const FD_EVENTS: u32 = PATH_EVENTS | PERM_EVENTS;

/// The flags of a mark mask that are not events, `FANOTIFY_EVENT_FLAGS` of Linux.
pub const EVENT_FLAGS: u32 = mask::EVENT_ON_CHILD | FAN_ONDIR;

/// The bits of `ALL_FSNOTIFY_EVENTS` of Linux: each event, without the flags.
const ALL_FS_EVENTS: u32 = 0x00ff_ffff | mask::RENAME;

/// The events that a read gives in a group that reports a descriptor, `FANOTIFY_OUTGOING_EVENTS`
/// of Linux without the event flags.
const USER_EVENTS: u32 = FD_EVENTS | mask::Q_OVERFLOW;

/// The most events in the queue, without `FAN_UNLIMITED_QUEUE`.
pub const MAX_EVENTS: usize = 16384;

/// The events after which the merge stops, `FANOTIFY_MAX_MERGE_EVENTS` of Linux.
const MAX_MERGE: usize = 128;

/// The flags of a mark, as `FSNOTIFY_MARK_FLAG_*` of Linux.
mod mark_flags {
    /// The mark does not hold its inode, `FSNOTIFY_MARK_FLAG_NO_IREF`.
    pub(super) const NO_IREF: u32 = 1;
    /// The ignore mask has its own event flags, `FSNOTIFY_MARK_FLAG_HAS_IGNORE_FLAGS`.
    pub(super) const HAS_IGNORE_FLAGS: u32 = 2;
    /// A modification does not clear the ignore mask, `FSNOTIFY_MARK_FLAG_IGNORED_SURV_MODIFY`.
    pub(super) const SURV_MODIFY: u32 = 4;
}

/// The functions of the process layer that fanotify uses.
pub struct Hooks {
    /// Puts the open file in the descriptor table of the current process, with close on exec if
    /// the flag is set, and gives the descriptor.
    pub install: fn(Arc<File>, bool) -> Result<i32>,
    /// The thread group ID and the thread ID of the current task.
    pub current: fn() -> (i32, i32),
    /// Tells if a fatal signal is pending for the current task.
    pub fatal: fn() -> bool,
}

static HOOKS: Once<Hooks> = Once::new();

/// Gives the VFS the functions of the process layer. Only the first call has an effect.
pub fn set_hooks(hooks: Hooks) {
    HOOKS.call_once(|| hooks);
}

/// The kind of the object of a mark, as `FAN_MARK_INODE`, `FAN_MARK_MOUNT` and
/// `FAN_MARK_FILESYSTEM`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An inode.
    Inode,
    /// A mount.
    Mount,
    /// A file system.
    Fs,
}

impl Kind {
    fn of(object: &Object) -> Self {
        match object {
            Object::Inode(_) => Self::Inode,
            Object::Mount(_) => Self::Mount,
            Object::Fs(_) => Self::Fs,
        }
    }
}

/// The state of a permission event, as `FAN_EVENT_*` of Linux.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PermState {
    /// In the queue.
    Init,
    /// A read gave the event, and the answer did not come yet.
    Reported,
    /// The answer, with the `response` of the listener.
    Answered(u32),
    /// The task that waits for the answer stopped.
    Canceled,
}

/// The part of a permission event that the task that waits and the listener share.
struct Perm {
    state: SpinLock<PermState>,
}

/// An event in the queue, as `struct fanotify_path_event` of Linux.
struct Event {
    mask: u32,
    at: Location,
    pid: i32,
    perm: Option<Arc<Perm>>,
}

enum Item {
    Event(Event),
    /// The queue was full, `FAN_Q_OVERFLOW`.
    Overflow,
}

struct State {
    queue: VecDeque<Item>,
    /// The queue has the overflow event.
    overflow: bool,
    /// The permission events that a read gave, by the descriptor of the event.
    access: Vec<(i32, Arc<Perm>)>,
    marks: Vec<Arc<Mark>>,
    /// The file of the group is closed: no event goes in the queue.
    closed: bool,
}

/// A fanotify group, as `struct fsnotify_group` with `struct fanotify_group_private_data` of
/// Linux.
pub struct Fanotify {
    me: Weak<Fanotify>,
    /// The flags of `fanotify_init`.
    flags: u32,
    /// The flags of the files of the events, the `event_f_flags` of `fanotify_init`.
    f_flags: u32,
    /// The class: 0 for notification, 1 for content and 2 for pre-content.
    priority: u32,
    max_events: usize,
    state: SpinLock<State>,
    /// The readers wait here.
    wait: WaitQueue,
    /// The tasks with a permission event wait here.
    access_wait: WaitQueue,
    events: AtomicU64,
}

/// Tells if the mask of a mark applies to the event, as `fsnotify_mask_applicable` of Linux.
fn applicable(m: u32, ondir: bool, parent: bool) -> bool {
    !(ondir && m & mask::ISDIR == 0) && !(parent && m & mask::EVENT_ON_CHILD == 0)
}

/// The events that a mark ignores for the event, as `fsnotify_effective_ignore_mask` of Linux.
fn effective_ignore(mark: &Mark, ondir: bool, parent: bool) -> u32 {
    let ignore = mark.ignore();
    if ignore & ALL_FS_EVENTS == 0 {
        return 0;
    }
    if !ondir && !parent {
        return ignore & ALL_FS_EVENTS;
    }
    // As `fsnotify_ignore_mask` of Linux: an ignore mask of the old interface has no event flags
    // of its own. It applies to directories, and to children if the mark mask has them.
    let ignore = if mark.flags() & mark_flags::HAS_IGNORE_FLAGS != 0 {
        ignore
    } else {
        (ignore | mask::ISDIR) & !mask::EVENT_ON_CHILD | (mark.mask() & mask::EVENT_ON_CHILD)
    };
    if !applicable(ignore, ondir, parent) {
        return 0;
    }
    ignore & ALL_FS_EVENTS
}

/// The result of the `response` of a listener, as `fanotify_get_response` of Linux.
fn answer(response: u32) -> Result<()> {
    match response & (FAN_ALLOW | FAN_DENY) {
        FAN_ALLOW => Ok(()),
        FAN_DENY => {
            let errno = (response >> FAN_ERRNO_SHIFT) & FAN_ERRNO_MASK;
            Err(Errno::new(errno as u16).unwrap_or(Errno::EPERM))
        }
        _ => Err(Errno::EPERM),
    }
}

impl Fanotify {
    /// The flags of `fanotify_init`.
    pub fn init_flags(&self) -> u32 {
        self.flags
    }

    /// The class of the group: 0 for notification, 1 for content and 2 for pre-content.
    pub fn priority(&self) -> u32 {
        self.priority
    }

    fn wake(&self) {
        self.events.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
        poll_wake();
    }

    /// Joins the event with an event of the same file in the queue, as `fanotify_merge` of
    /// Linux. A permission event never joins.
    fn merge(st: &mut State, m: u32, at: &Location, pid: i32) -> bool {
        for item in st.queue.iter_mut().rev().take(MAX_MERGE) {
            if let Item::Event(e) = item
                && e.perm.is_none()
                && e.pid == pid
                && Arc::ptr_eq(&e.at.dentry, &at.dentry)
                && Arc::ptr_eq(&e.at.mount, &at.mount)
            {
                e.mask |= m;
                return true;
            }
        }
        false
    }

    /// Waits for the answer to the permission event `perm`, as `fanotify_get_response` of Linux.
    /// Only a fatal signal stops the wait.
    fn wait_answer(&self, perm: &Arc<Perm>) -> Result<()> {
        let fatal = HOOKS.get().map(|h| h.fatal);
        let got = self.access_wait.wait_until(|| {
            if let PermState::Answered(r) = *perm.state.lock() {
                return Some(Some(r));
            }
            if fatal.is_some_and(|f| f()) { Some(None) } else { None }
        });
        if let Some(r) = got {
            return answer(r);
        }
        let mut st = self.state.lock();
        let mut ps = perm.state.lock();
        match *ps {
            // The listener has the event. The answer frees it.
            PermState::Reported => *ps = PermState::Canceled,
            PermState::Init => st.queue.retain(|i| match i {
                Item::Event(e) => !e.perm.as_ref().is_some_and(|p| Arc::ptr_eq(p, perm)),
                Item::Overflow => true,
            }),
            PermState::Answered(_) | PermState::Canceled => {}
        }
        Err(Errno::ERESTARTSYS)
    }

    /// Opens the file of an event for the listener, as `create_fd` of Linux.
    fn open_fd(&self, at: &Location) -> Result<i32> {
        let hooks = HOOKS.get().ok_or(Errno::EMFILE)?;
        let writable = matches!(self.f_flags & o::O_ACCMODE, o::O_WRONLY | o::O_RDWR);
        if writable && at.inode().metadata().file_type() == Some(crate::inode::FileType::Regular) {
            at.mount.want_write()?;
        }
        let file = File::open_inode(at.clone(), self.f_flags & !o::O_CLOEXEC);
        file.set_nonotify();
        (hooks.install)(file, self.f_flags & o::O_CLOEXEC != 0)
    }

    /// The answer of the listener to the permission event of the descriptor `fd`, as
    /// `process_access_response` of Linux.
    fn respond(&self, fd: i32, response: u32) -> Result<()> {
        let errno = (response >> FAN_ERRNO_SHIFT) & FAN_ERRNO_MASK;
        let valid =
            FAN_ALLOW | FAN_DENY | FAN_AUDIT | FAN_INFO | (FAN_ERRNO_MASK << FAN_ERRNO_SHIFT);
        if response & !valid != 0 {
            return Err(Errno::EINVAL);
        }
        match response & (FAN_ALLOW | FAN_DENY) {
            FAN_ALLOW if errno != 0 => return Err(Errno::EINVAL),
            FAN_ALLOW => {}
            FAN_DENY => {
                if errno != 0 && self.priority != 2 {
                    return Err(Errno::EINVAL);
                }
                let ok = [Errno::EIO, Errno::EPERM, Errno::EBUSY, Errno::ETXTBSY, Errno::EAGAIN]
                    .iter()
                    .chain(&[Errno::ENOSPC, Errno::EDQUOT])
                    .any(|e| u32::from(e.get()) == errno);
                if errno != 0 && !ok {
                    return Err(Errno::EINVAL);
                }
            }
            _ => return Err(Errno::EINVAL),
        }
        if response & FAN_AUDIT != 0 && self.flags & FAN_ENABLE_AUDIT == 0 {
            return Err(Errno::EINVAL);
        }
        // The audit rule record that `FAN_INFO` needs is not supported.
        if response & FAN_INFO != 0 || fd < 0 {
            return Err(Errno::EINVAL);
        }
        let perm = {
            let mut st = self.state.lock();
            let i = st.access.iter().position(|(f, _)| *f == fd).ok_or(Errno::ENOENT)?;
            st.access.remove(i).1
        };
        Self::finish(&perm, response);
        self.access_wait.wake_all();
        Ok(())
    }

    /// Gives the answer to a permission event, as `finish_permission_event` of Linux.
    fn finish(perm: &Perm, response: u32) {
        let mut ps = perm.state.lock();
        if *ps != PermState::Canceled {
            *ps = PermState::Answered(response);
        }
    }

    /// Finds the mark of the group on `object`.
    fn find(&self, object: &Object) -> Option<Arc<Mark>> {
        self.state.lock().marks.iter().find(|m| m.object().same(object)).cloned()
    }

    /// Adds the events `m` to the mark on `object`, as `fanotify_add_mark` of Linux. `flags` are
    /// the flags of `fanotify_mark`. The caller examined the flags and the mask.
    ///
    /// # Errors
    ///
    /// Gives `EEXIST` if the flags conflict with the flags of the mark.
    pub fn add_mark(&self, object: Object, m: u32, flags: u32) -> Result<()> {
        let ignore = flags & (FAN_MARK_IGNORE | FAN_MARK_IGNORED_MASK);
        let mark = match self.find(&object) {
            Some(mark) => {
                // As `fanotify_may_update_existing_mark` of Linux.
                let f = mark.flags();
                if flags & FAN_MARK_EVICTABLE != 0 && f & mark_flags::NO_IREF == 0 {
                    return Err(Errno::EEXIST);
                }
                if flags & FAN_MARK_IGNORED_MASK != 0 && f & mark_flags::HAS_IGNORE_FLAGS != 0 {
                    return Err(Errno::EEXIST);
                }
                if flags & FAN_MARK_IGNORE != 0
                    && flags & FAN_MARK_IGNORED_SURV_MODIFY == 0
                    && f & mark_flags::SURV_MODIFY != 0
                {
                    return Err(Errno::EEXIST);
                }
                mark
            }
            None => {
                let group: Arc<dyn Group> = self.me.upgrade().ok_or(Errno::EBADF)?;
                let mark = add_object_mark(group, object, 0, 0);
                if flags & FAN_MARK_EVICTABLE != 0 {
                    mark.set_flags(mark_flags::NO_IREF);
                }
                self.state.lock().marks.push(mark.clone());
                mark
            }
        };
        if ignore == 0 {
            mark.set_mask(mark.mask() | m);
        } else {
            mark.set_ignore(mark.ignore() | m);
        }
        // As `fanotify_mark_update_flags` of Linux.
        let mut f = mark.flags();
        if ignore == FAN_MARK_IGNORE {
            f |= mark_flags::HAS_IGNORE_FLAGS;
        }
        if ignore != 0 && flags & FAN_MARK_IGNORED_SURV_MODIFY != 0 {
            f |= mark_flags::SURV_MODIFY;
        }
        if flags & FAN_MARK_EVICTABLE == 0 {
            f &= !mark_flags::NO_IREF;
        }
        mark.set_flags(f);
        Ok(())
    }

    /// Removes the events `m` from the mark on `object`, as `fanotify_remove_mark` of Linux. The
    /// bits of `umask` stay. The mark goes away when only these bits stay.
    ///
    /// # Errors
    ///
    /// Gives `ENOENT` if the group has no mark on `object`.
    pub fn remove_mark(&self, object: &Object, m: u32, flags: u32, umask: u32) -> Result<()> {
        let mark = self.find(object).ok_or(Errno::ENOENT)?;
        let m = m & !umask;
        if flags & (FAN_MARK_IGNORE | FAN_MARK_IGNORED_MASK) == 0 {
            mark.set_mask(mark.mask() & !m);
        } else {
            mark.set_ignore(mark.ignore() & !m);
        }
        if (mark.mask() | mark.ignore()) & !umask == 0 {
            destroy_mark(&mark);
        }
        Ok(())
    }

    /// Removes the marks of the group on the objects of the kind `kind`, as
    /// `fsnotify_clear_marks_by_group` of Linux.
    pub fn flush_marks(&self, kind: Kind) {
        let marks: Vec<Arc<Mark>> = self
            .state
            .lock()
            .marks
            .iter()
            .filter(|m| Kind::of(m.object()) == kind)
            .cloned()
            .collect();
        for mark in marks {
            destroy_mark(&mark);
        }
    }

    /// The lines of `/proc/PID/fdinfo`, as `fanotify_show_fdinfo` of Linux.
    fn fdinfo(&self) -> Vec<u8> {
        let mut out = format!(
            "fanotify flags:{:x} event-flags:{:x}\n",
            self.flags,
            self.f_flags & !o::O_LARGEFILE
        )
        .into_bytes();
        let marks: Vec<Arc<Mark>> = self.state.lock().marks.clone();
        for mark in marks {
            let mflags = if mark.flags() & mark_flags::SURV_MODIFY != 0 { 1 } else { 0 };
            let line = match mark.object() {
                Object::Inode(inode) => {
                    let meta = inode.metadata();
                    format!("fanotify ino:{:x} sdev:{:x} ", meta.ino, kernel_dev(meta.dev))
                }
                Object::Mount(mount) => format!("fanotify mnt_id:{:x} ", mount.id()),
                Object::Fs(id) => format!("fanotify sdev:{:x} ", kernel_dev(*id)),
            };
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(
                format!(
                    "mflags:{:x} mask:{:x} ignored_mask:{:x}\n",
                    mflags,
                    mark.mask(),
                    mark.ignore()
                )
                .as_bytes(),
            );
        }
        out
    }

    /// Stops the group when its file closes, as `fanotify_release` of Linux: each permission
    /// event gets `FAN_ALLOW`, and the marks go away.
    fn release(&self) {
        let (perms, marks) = {
            let mut st = self.state.lock();
            st.closed = true;
            let mut perms: Vec<Arc<Perm>> = st.access.drain(..).map(|(_, p)| p).collect();
            for item in st.queue.drain(..) {
                if let Item::Event(Event { perm: Some(p), .. }) = item {
                    perms.push(p);
                }
            }
            st.overflow = false;
            (perms, core::mem::take(&mut st.marks))
        };
        for perm in &perms {
            Self::finish(perm, FAN_ALLOW);
        }
        self.access_wait.wake_all();
        for mark in marks {
            destroy_mark(&mark);
        }
    }
}

/// The device number in the encoding of the kernel, `MKDEV`, from the encoding of `stat`.
fn kernel_dev(dev: u64) -> u64 {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    (major << 20) | minor
}

impl Group for Fanotify {
    fn handle_event(&self, _mark: &Arc<Mark>, _mask: u32, _name: Option<&[u8]>, _cookie: u32) {}

    fn freeing_mark(&self, mark: &Arc<Mark>) {
        self.state.lock().marks.retain(|m| !Arc::ptr_eq(m, mark));
    }

    fn wants_paths(&self) -> bool {
        true
    }

    fn priority(&self) -> u32 {
        self.priority
    }

    fn handle_path(&self, at: &Location, m: u32, marks: &[(Found, Arc<Mark>)]) -> Result<()> {
        // A group that reports a descriptor gets the events of regular files and directories
        // only, as `fanotify_group_event_mask` of Linux.
        let meta = at.inode().metadata();
        if !meta.is_dir() && meta.file_type() != Some(crate::inode::FileType::Regular) {
            return Ok(());
        }
        // A modification clears the ignore masks, as `send_to_group` of Linux. A mark on the
        // parent that does not watch the children is not part of the event, as
        // `fsnotify_iter_select_report_types` of Linux, so its ignore mask stays.
        if m & mask::MODIFY != 0 {
            for (found, mark) in marks {
                let watches = (mark.mask() | mark.ignore()) & mask::EVENT_ON_CHILD != 0;
                if *found == Found::Parent && !watches {
                    continue;
                }
                if mark.flags() & mark_flags::SURV_MODIFY == 0 {
                    mark.set_ignore(0);
                }
            }
        }
        let ondir = m & mask::ISDIR != 0;
        let mut want = 0;
        let mut ignore = 0;
        for (found, mark) in marks {
            if !mark.alive() {
                continue;
            }
            let parent = *found == Found::Parent;
            ignore |= effective_ignore(mark, ondir, parent);
            if applicable(mark.mask(), ondir, parent) {
                want |= mark.mask();
            }
        }
        let test = m & want & !ignore & USER_EVENTS;
        if test == 0 {
            return Ok(());
        }
        let (tgid, tid) = HOOKS.get().map_or((0, 0), |h| (h.current)());
        let pid = if self.flags & FAN_REPORT_TID != 0 { tid } else { tgid };
        let perm = (test & PERM_EVENTS != 0)
            .then(|| Arc::new(Perm { state: SpinLock::new(PermState::Init) }));
        {
            let mut st = self.state.lock();
            if st.closed {
                return Ok(());
            }
            if perm.is_none() && Self::merge(&mut st, test, at, pid) {
                return Ok(());
            }
            // A full queue gets one overflow event. A permission event that does not go in the
            // queue gets no answer, so the operation goes on.
            if st.queue.len() >= self.max_events {
                if st.overflow {
                    return Ok(());
                }
                st.overflow = true;
                st.queue.push_back(Item::Overflow);
                drop(st);
                self.wake();
                return Ok(());
            }
            let event = Event { mask: test, at: at.clone(), pid, perm: perm.clone() };
            st.queue.push_back(Item::Event(event));
        }
        self.wake();
        match perm {
            Some(perm) => self.wait_answer(&perm),
            None => Ok(()),
        }
    }
}

/// The operations of the file of a fanotify group.
pub struct FanotifyFile {
    group: Arc<Fanotify>,
}

impl FanotifyFile {
    /// Makes a new group, as `fanotify_init` of Linux after the checks of the flags. `flags` are
    /// the flags of the group, `f_flags` the flags of the files of the events, and `priority` the
    /// class: 0 for notification, 1 for content and 2 for pre-content.
    pub fn new(flags: u32, f_flags: u32, priority: u32, unlimited: bool) -> Self {
        let group = Arc::new_cyclic(|me| Fanotify {
            me: me.clone(),
            flags,
            f_flags,
            priority,
            max_events: if unlimited { usize::MAX } else { MAX_EVENTS },
            state: SpinLock::new(State {
                queue: VecDeque::new(),
                overflow: false,
                access: Vec::new(),
                marks: Vec::new(),
                closed: false,
            }),
            wait: WaitQueue::new(),
            access_wait: WaitQueue::new(),
            events: AtomicU64::new(0),
        });
        Self { group }
    }

    /// The group.
    pub fn group(&self) -> &Arc<Fanotify> {
        &self.group
    }
}

impl Drop for FanotifyFile {
    fn drop(&mut self) {
        self.group.release();
    }
}

/// `FIONREAD` of `asm/ioctls.h`.
const FIONREAD: u32 = rk_abi::native::ioctls::FIONREAD;

/// The size of `struct fanotify_event_metadata`.
const META_LEN: usize = core::mem::size_of::<FanotifyEventMetadata>();

/// Puts `meta` in `out` in the layout of `struct fanotify_event_metadata`.
fn encode(meta: &FanotifyEventMetadata, out: &mut Vec<u8>) {
    let start = out.len();
    out.resize(start + META_LEN, 0);
    let b = &mut out[start..];
    b[core::mem::offset_of!(FanotifyEventMetadata, event_len)..][..4]
        .copy_from_slice(&meta.event_len.to_ne_bytes());
    b[core::mem::offset_of!(FanotifyEventMetadata, vers)] = meta.vers;
    b[core::mem::offset_of!(FanotifyEventMetadata, reserved)] = meta.reserved;
    b[core::mem::offset_of!(FanotifyEventMetadata, metadata_len)..][..2]
        .copy_from_slice(&meta.metadata_len.to_ne_bytes());
    b[core::mem::offset_of!(FanotifyEventMetadata, mask)..][..8]
        .copy_from_slice(&meta.mask.to_ne_bytes());
    b[core::mem::offset_of!(FanotifyEventMetadata, fd)..][..4]
        .copy_from_slice(&meta.fd.to_ne_bytes());
    b[core::mem::offset_of!(FanotifyEventMetadata, pid)..][..4]
        .copy_from_slice(&meta.pid.to_ne_bytes());
}

impl FileOps for FanotifyFile {
    /// A read takes whole events, as `fanotify_read` of Linux. Each event with a file gets a new
    /// descriptor of the file. A permission event then waits in the access list for its answer.
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        let nonblock = file.flags().nonblock();
        let g = &self.group;
        let mut out = Vec::new();
        loop {
            let room = buf.len() - out.len();
            let empty = out.is_empty();
            let next = g.wait.wait_interruptible(|| {
                let mut st = g.state.lock();
                if st.queue.is_empty() {
                    return if !empty {
                        Ok(Some(None))
                    } else if nonblock {
                        Err(Errno::EAGAIN)
                    } else {
                        Ok(None)
                    };
                }
                if room < META_LEN {
                    return if empty { Err(Errno::EINVAL) } else { Ok(Some(None)) };
                }
                let item = st.queue.pop_front();
                match &item {
                    Some(Item::Overflow) => st.overflow = false,
                    Some(Item::Event(Event { perm: Some(p), .. })) => {
                        *p.state.lock() = PermState::Reported;
                    }
                    _ => {}
                }
                Ok(Some(item))
            });
            let item = match next {
                Ok(Some(item)) => item,
                Ok(None) => break,
                Err(e) if out.is_empty() => return Err(e),
                Err(_) => break,
            };
            let (m, fd, pid, perm) = match item {
                // An event without a file has `-EBADF` with `FAN_REPORT_FD_ERROR`, as Linux.
                Item::Overflow if g.flags & FAN_REPORT_FD_ERROR != 0 => {
                    (mask::Q_OVERFLOW, -i32::from(Errno::EBADF.get()), 0, None)
                }
                Item::Overflow => (mask::Q_OVERFLOW, FAN_NOFD as i32, 0, None),
                Item::Event(e) => {
                    let fd = match g.open_fd(&e.at) {
                        Ok(fd) => fd,
                        Err(err) if g.flags & FAN_REPORT_FD_ERROR != 0 => -i32::from(err.get()),
                        Err(err) => {
                            if let Some(p) = &e.perm {
                                Fanotify::finish(p, FAN_DENY);
                                g.access_wait.wake_all();
                            }
                            if out.is_empty() {
                                return Err(err);
                            }
                            break;
                        }
                    };
                    (e.mask, fd, e.pid, e.perm)
                }
            };
            let meta = FanotifyEventMetadata {
                event_len: FAN_EVENT_METADATA_LEN,
                vers: FANOTIFY_METADATA_VERSION as u8,
                reserved: 0,
                metadata_len: FAN_EVENT_METADATA_LEN as u16,
                mask: u64::from(m),
                fd,
                pid,
            };
            encode(&meta, &mut out);
            if let Some(p) = perm {
                if fd >= 0 {
                    g.state.lock().access.push((fd, p));
                } else {
                    Fanotify::finish(&p, FAN_DENY);
                    g.access_wait.wake_all();
                }
            }
        }
        buf[..out.len()].copy_from_slice(&out);
        Ok(out.len())
    }

    /// A write gives the answer to a permission event, as `fanotify_write` of Linux.
    fn write(&self, _file: &File, buf: &[u8]) -> Result<usize> {
        let len = core::mem::size_of::<FanotifyResponse>();
        if buf.len() < len {
            return Err(Errno::EINVAL);
        }
        let word = |off: usize| {
            let mut b = [0u8; 4];
            b.copy_from_slice(&buf[off..off + 4]);
            b
        };
        let fd = i32::from_ne_bytes(word(core::mem::offset_of!(FanotifyResponse, fd)));
        let response = u32::from_ne_bytes(word(core::mem::offset_of!(FanotifyResponse, response)));
        self.group.respond(fd, response)?;
        Ok(len)
    }

    fn ioctl(&self, _file: &File, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        if cmd != FIONREAD {
            return Err(Errno::ENOTTY);
        }
        let bytes = (self.group.state.lock().queue.len() * META_LEN) as i32;
        mem.write(arg, &bytes.to_ne_bytes())?;
        Ok(0)
    }

    fn poll(&self, _file: &File) -> u32 {
        if self.group.state.lock().queue.is_empty() { 0 } else { events::POLLIN }
    }

    fn pollable(&self) -> bool {
        true
    }

    fn event_count(&self) -> u64 {
        self.group.events.load(Ordering::Relaxed)
    }

    fn fdinfo(&self, _file: &File) -> Vec<u8> {
        self.group.fdinfo()
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_old_ignore_mask_applies_to_directories() {
        assert!(applicable(mask::ISDIR | mask::OPEN, true, false));
        assert!(!applicable(mask::OPEN, true, false));
        assert!(!applicable(mask::OPEN, false, true));
        assert!(applicable(mask::OPEN | mask::EVENT_ON_CHILD, false, true));
    }

    #[test]
    fn a_deny_without_errno_gives_eperm() {
        assert_eq!(answer(FAN_ALLOW), Ok(()));
        assert_eq!(answer(FAN_DENY), Err(Errno::EPERM));
        assert_eq!(
            answer(FAN_DENY | (u32::from(Errno::EIO.get()) << FAN_ERRNO_SHIFT)),
            Err(Errno::EIO)
        );
    }
}

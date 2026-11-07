//! fanotify, as fs/notify/fanotify/fanotify.c and fanotify_user.c of Linux.
//!
//! A fanotify group gets the events of open files: an access, a modification, an open and a
//! close, and the permission events before an open and a read. The marks of a group can be on an
//! inode, on a mount or on a file system. A read of the file of the group gives each event as
//! `struct fanotify_event_metadata` with a new descriptor of the file of the event. A process
//! that causes a permission event waits until the listener writes `struct fanotify_response`.
//!
//! A group with `FAN_REPORT_FID`, `FAN_REPORT_DIR_FID`, `FAN_REPORT_NAME` or
//! `FAN_REPORT_TARGET_FID` reports file handles in place of a descriptor, as `name_to_handle_at`
//! gives them. Such a group also gets the events of the entries of directories, the changes of
//! the attributes and the events of the file itself. Each event then has info records after the
//! metadata: the handle of the directory and the name of the entry, the new directory and the
//! new name of a rename, and the handle of the file.
//!
//! The mount events and the pre-content events are not supported.

use super::{Found, FsEvent, Group, Mark, Object, add_object_mark, destroy_mark, mask};
use crate::dentry::Location;
use crate::file::{File, FileOps, UserMemory, events};
use crate::inode::Result;
use crate::user_ns::{Charge, UcountKind};
use crate::wait::{PollTable, WaitQueue};
use alloc::collections::VecDeque;
use alloc::format;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::fanotify::{
    FAN_ALLOW, FAN_AUDIT, FAN_DENY, FAN_ENABLE_AUDIT, FAN_EPIDFD, FAN_ERRNO_MASK, FAN_ERRNO_SHIFT,
    FAN_EVENT_INFO_TYPE_DFID, FAN_EVENT_INFO_TYPE_DFID_NAME, FAN_EVENT_INFO_TYPE_FID,
    FAN_EVENT_INFO_TYPE_NEW_DFID_NAME, FAN_EVENT_INFO_TYPE_OLD_DFID_NAME,
    FAN_EVENT_INFO_TYPE_PIDFD, FAN_EVENT_METADATA_LEN, FAN_INFO, FAN_MARK_EVICTABLE,
    FAN_MARK_IGNORE, FAN_MARK_IGNORED_MASK, FAN_MARK_IGNORED_SURV_MODIFY, FAN_NOFD, FAN_NOPIDFD,
    FAN_ONDIR, FAN_PRE_ACCESS, FAN_REPORT_DFID_NAME_TARGET, FAN_REPORT_DIR_FID,
    FAN_REPORT_FD_ERROR, FAN_REPORT_FID, FAN_REPORT_NAME, FAN_REPORT_PIDFD, FAN_REPORT_TARGET_FID,
    FAN_REPORT_TID, FAN_UNLIMITED_MARKS, FANOTIFY_METADATA_VERSION,
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

/// The bits that report a file handle, `FANOTIFY_FID_BITS` of Linux.
pub const FID_BITS: u32 = FAN_REPORT_DFID_NAME_TARGET;

/// The events of a file and of an entry of a directory, `FANOTIFY_INODE_EVENTS` of Linux.
pub const INODE_EVENTS: u32 = mask::DIRENT | mask::ATTRIB | mask::MOVE_SELF | mask::DELETE_SELF;

/// The events and the flags that a read gives in a group that reports a file handle,
/// `FANOTIFY_OUTGOING_EVENTS` of Linux.
const FID_USER_EVENTS: u32 = USER_EVENTS | INODE_EVENTS | FAN_ONDIR;

/// The size of `struct fanotify_event_info_fid` and `struct file_handle` before the handle,
/// `FANOTIFY_FID_INFO_HDR_LEN` of Linux.
const FID_INFO_HDR_LEN: usize = 20;

/// The size of `struct fanotify_event_info_pidfd`, `FANOTIFY_PIDFD_INFO_LEN` of Linux.
const PIDFD_INFO_LEN: usize = 8;

/// `fs.fanotify.max_queued_events`: the most events in the queue of a new group without
/// `FAN_UNLIMITED_QUEUE`.
pub static MAX_QUEUED_EVENTS: AtomicU32 = AtomicU32::new(16384);

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
    /// The ID in the PID namespace of the current task of the thread or the process with the
    /// global ID `pid`, or 0 if the task does not see it, as `pid_vnr` of Linux.
    pub vpid: fn(i32) -> i32,
    /// Makes the file of a process file descriptor for the process with the global ID `pid`, or
    /// for the thread with this ID and `PIDFD_THREAD` if the flag is set, as `pidfd_prepare` of
    /// Linux.
    pub pidfd: fn(i32, bool) -> Result<Arc<File>>,
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

/// A file handle, as `struct fanotify_fh` of Linux.
#[derive(Clone, PartialEq, Eq)]
struct Fh {
    ty: i32,
    bytes: Vec<u8>,
}

impl Fh {
    /// The handle of `inode`, as `fanotify_encode_fh` of Linux. It is the handle that
    /// `name_to_handle_at` gives. A file system that cannot find an inode from a handle gives
    /// the inode number, as `AT_HANDLE_FID`.
    fn of(inode: &crate::inode::InodeRef) -> Self {
        let (ty, words) = inode.file_handle().unwrap_or_else(|| {
            (crate::inode::fileid::INO32_GEN, alloc::vec![inode.metadata().ino as u32, 0])
        });
        let bytes = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
        Self { ty, bytes }
    }
}

/// The handles and the names of an event of a group that reports a file handle, as
/// `struct fanotify_fid_event` and `struct fanotify_name_event` of Linux.
#[derive(Clone, PartialEq, Eq)]
struct Fid {
    /// The ID of the file system, as `f_fsid` of `statfs`.
    fsid: [i32; 2],
    /// The event has the directory and the name, `FANOTIFY_EVENT_TYPE_FID_NAME` of Linux.
    named: bool,
    /// The directory and the name of the entry. The name can be empty.
    dir: Option<(Fh, Vec<u8>)>,
    /// The new directory and the new name of a rename.
    dir2: Option<(Fh, Vec<u8>)>,
    /// The handle of the file: the object of the event, or the child of a named event.
    object: Option<Fh>,
}

/// The object of an event in the queue.
enum Info {
    /// The path of the file, for a group that reports a descriptor.
    Path(Location),
    /// The handles, for a group that reports a file handle.
    Fid(Fid),
}

/// An event in the queue, as `struct fanotify_event` of Linux.
struct Event {
    mask: u32,
    info: Info,
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
    /// The count of the group for its user, `fanotify_data.ucounts` of Linux.
    charge: Option<Charge>,
    /// The counts of the marks for the user of the group, one for each mark. A group with
    /// `FAN_UNLIMITED_MARKS` has none.
    mark_charges: Vec<Charge>,
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
    /// A user without `CAP_SYS_ADMIN` made the group, `FANOTIFY_UNPRIV` of Linux.
    unpriv: bool,
    max_events: usize,
    state: SpinLock<State>,
    /// The readers wait here.
    wait: Arc<WaitQueue>,
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

    /// Tells if a user without `CAP_SYS_ADMIN` made the group. Such a group has no marks on a
    /// mount or a file system, and its events from other processes have the pid 0.
    pub fn unprivileged(&self) -> bool {
        self.unpriv
    }

    /// The class of the group: 0 for notification, 1 for content and 2 for pre-content.
    pub fn priority(&self) -> u32 {
        self.priority
    }

    fn wake(&self) {
        self.events.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
    }

    /// Joins the event with an event of the same object in the queue, as `fanotify_merge` and
    /// `fanotify_should_merge` of Linux. A permission event never joins. The two events must
    /// both be on a directory or both on another file, and both be a rename or not.
    fn merge(st: &mut State, m: u32, info: &Info, pid: i32) -> bool {
        let kind = mask::ISDIR | mask::RENAME;
        for item in st.queue.iter_mut().rev().take(MAX_MERGE) {
            let Item::Event(e) = item else { continue };
            if e.perm.is_some() || e.pid != pid || (e.mask ^ m) & kind != 0 {
                continue;
            }
            let same = match (&e.info, info) {
                (Info::Path(a), Info::Path(b)) => {
                    Arc::ptr_eq(&a.dentry, &b.dentry) && Arc::ptr_eq(&a.mount, &b.mount)
                }
                // A named event without a directory does not join, as Linux.
                (Info::Fid(a), Info::Fid(b)) => a == b && (!a.named || a.dir.is_some()),
                _ => false,
            };
            if same {
                e.mask |= m;
                return true;
            }
        }
        false
    }

    /// The handles of the event `ev` with the events `m`, as `fanotify_alloc_event` of Linux.
    /// `matched` has a bit for each place of a mark that wants the event, by [`found_bit`].
    fn fid_info(&self, ev: &FsEvent<'_>, m: u32, matched: u32) -> Option<Fid> {
        let fid_mode = self.flags & FID_BITS;
        let dirent = m & mask::DIRENT != 0;
        let ondir = m & FAN_ONDIR != 0;
        // As `fanotify_fid_inode` and `fanotify_dfid_inode` of Linux.
        let mut id =
            if dirent && fid_mode & FAN_REPORT_TARGET_FID == 0 { ev.dir } else { ev.inode };
        let mut dirid = if dirent {
            ev.dir
        } else if ev.inode.is_some_and(|i| i.metadata().is_dir()) {
            ev.inode
        } else {
            ev.dir
        };
        let mut child = None;
        let mut named = false;
        let mut name = ev.name;
        let mut moved = None;
        if fid_mode & FAN_REPORT_DIR_FID != 0
            && let Some(d) = dirid
        {
            // As `fanotify_report_child_fid` of Linux.
            let report_child = if dirent {
                fid_mode & FAN_REPORT_TARGET_FID != 0
            } else {
                fid_mode & FAN_REPORT_FID != 0 && !ondir
            };
            if report_child && id.is_some_and(|i| !Arc::ptr_eq(i, d)) {
                child = id;
            }
            id = Some(d);
            if fid_mode & FAN_REPORT_NAME == 0 {
                named = child.is_some();
                name = None;
            } else if dirent || !ondir {
                named = true;
            }
            // A rename has the old directory and name if the mark of the old directory or of
            // the file system wants it, and the new ones if the mark of the new directory or of
            // the file system wants it.
            if m & mask::RENAME != 0 {
                let fs = matched & found_bit(Found::Fs) != 0;
                if !fs && matched & found_bit(Found::Inode) == 0 {
                    dirid = None;
                    name = None;
                }
                if fs || matched & found_bit(Found::NewDir) != 0 {
                    moved = ev.moved;
                }
            }
        }
        let fsid_of = ev.dir.or(ev.inode)?.fs_fsid();
        let fsid = [fsid_of as i32, (fsid_of >> 32) as i32];
        if named && (name.is_some() || moved.is_some() || child.is_some()) {
            return Some(Fid {
                fsid,
                named: true,
                dir: dirid.map(|d| (Fh::of(d), name.unwrap_or_default().to_vec())),
                dir2: moved.map(|(d, n)| (Fh::of(d), n.to_vec())),
                object: child.map(Fh::of),
            });
        }
        Some(Fid { fsid, named: false, dir: None, dir2: None, object: id.map(Fh::of) })
    }

    /// The size of the event in a read, as `fanotify_event_len` of Linux.
    fn event_len(&self, item: &Item) -> usize {
        let pidfd = if self.flags & FAN_REPORT_PIDFD != 0 { PIDFD_INFO_LEN } else { 0 };
        let Item::Event(Event { info: Info::Fid(fid), mask: m, .. }) = item else {
            return META_LEN + pidfd;
        };
        let mut len = META_LEN + pidfd;
        let mut dot = 0;
        if fid.dir.is_some() || fid.dir2.is_some() {
            for (fh, name) in fid.dir.iter().chain(&fid.dir2) {
                len += fid_info_len(fh.bytes.len(), name.len());
            }
        } else if self.flags & FAN_REPORT_NAME != 0 && m & FAN_ONDIR != 0 {
            dot = 1;
        }
        if let Some(fh) = &fid.object {
            len += fid_info_len(fh.bytes.len(), dot);
        }
        len
    }

    /// Puts the info records of `fid` in `out`, as `copy_info_records_to_user` of Linux: the
    /// directory and the name, then the new directory and the new name, then the file.
    fn put_records(&self, fid: &Fid, m: u32, out: &mut Vec<u8>) {
        let fid_mode = self.flags & FID_BITS;
        let mut first = 0;
        if let Some((fh, name)) = &fid.dir {
            first = if m & mask::RENAME != 0 {
                FAN_EVENT_INFO_TYPE_OLD_DFID_NAME
            } else if name.is_empty() {
                FAN_EVENT_INFO_TYPE_DFID
            } else {
                FAN_EVENT_INFO_TYPE_DFID_NAME
            };
            put_fid(out, first, fid.fsid, fh, name);
        }
        if let Some((fh, name)) = &fid.dir2 {
            first = FAN_EVENT_INFO_TYPE_NEW_DFID_NAME;
            put_fid(out, first, fid.fsid, fh, name);
        }
        if let Some(fh) = &fid.object {
            let (ty, name): (u32, &[u8]) = if fid_mode == FAN_REPORT_FID || first != 0 {
                (FAN_EVENT_INFO_TYPE_FID, b"")
            } else if fid_mode & FAN_REPORT_NAME != 0 && m & FAN_ONDIR != 0 {
                // A directory without a name has the name ".".
                (FAN_EVENT_INFO_TYPE_DFID_NAME, b".")
            } else if m & (mask::DIRENT | FAN_ONDIR) != 0 {
                (FAN_EVENT_INFO_TYPE_DFID, b"")
            } else {
                // A file without a directory, as for `FAN_DELETE_SELF`.
                (FAN_EVENT_INFO_TYPE_FID, b"")
            };
            put_fid(out, ty, fid.fsid, fh, name);
        }
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

    /// Makes a process file descriptor for the listener, for an event of the process with the
    /// global ID `global` that the listener sees as `pid`, as `copy_event_to_user` of Linux.
    /// The descriptor refers to the thread with `FAN_REPORT_TID`, and has `FD_CLOEXEC`. A
    /// process that has gone or that the listener does not see gives `FAN_NOPIDFD`, and another
    /// error gives `FAN_EPIDFD`. With `FAN_REPORT_FD_ERROR`, the value is the negative error.
    fn open_pidfd(&self, global: i32, pid: i32) -> i32 {
        let made = match HOOKS.get() {
            Some(h) if pid != 0 => (h.pidfd)(global, self.flags & FAN_REPORT_TID != 0)
                .and_then(|file| (h.install)(file, true)),
            _ => Err(Errno::ESRCH),
        };
        match made {
            Ok(fd) => fd,
            Err(err) if self.flags & FAN_REPORT_FD_ERROR != 0 => -i32::from(err.get()),
            Err(Errno::ESRCH) => FAN_NOPIDFD as i32,
            Err(_) => FAN_EPIDFD as i32,
        }
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
                // Each mark counts for the user of the group in all the namespaces above it, as
                // `fanotify_add_new_mark` of Linux.
                let charge = match &self.state.lock().charge {
                    Some(c) if self.flags & FAN_UNLIMITED_MARKS == 0 => {
                        Some(c.again(UcountKind::FanotifyMarks).ok_or(Errno::ENOSPC)?)
                    }
                    _ => None,
                };
                let mark = add_object_mark(group, object, 0, 0);
                if flags & FAN_MARK_EVICTABLE != 0 {
                    mark.set_flags(mark_flags::NO_IREF);
                }
                let mut st = self.state.lock();
                st.marks.push(mark.clone());
                st.mark_charges.extend(charge);
                drop(st);
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
            st.mark_charges.clear();
            st.charge = None;
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

/// The bit of a place of a mark in the match mask of an event, as the iterator types of Linux.
fn found_bit(found: Found) -> u32 {
    1 << found as u32
}

/// The size of an info record with a handle of `fh_len` bytes and a name of `name_len` bytes, as
/// `fanotify_fid_info_len` of Linux. A name has a null after it.
fn fid_info_len(fh_len: usize, name_len: usize) -> usize {
    let name = if name_len == 0 { 0 } else { name_len + 1 };
    (FID_INFO_HDR_LEN + fh_len + name).next_multiple_of(4)
}

/// Puts an info record of the type `ty` in `out`, as `copy_fid_info_to_user` of Linux:
/// `struct fanotify_event_info_fid`, the `struct file_handle` with the handle, and the name with
/// a null. Zeros fill the record to a size that is a multiple of 4.
fn put_fid(out: &mut Vec<u8>, ty: u32, fsid: [i32; 2], fh: &Fh, name: &[u8]) {
    let len = fid_info_len(fh.bytes.len(), name.len());
    let start = out.len();
    out.push(ty as u8);
    out.push(0);
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&fsid[0].to_ne_bytes());
    out.extend_from_slice(&fsid[1].to_ne_bytes());
    out.extend_from_slice(&(fh.bytes.len() as u32).to_ne_bytes());
    let ty = if fh.bytes.is_empty() { crate::inode::fileid::INVALID } else { fh.ty };
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(&fh.bytes);
    if !name.is_empty() {
        out.extend_from_slice(name);
        out.push(0);
    }
    out.resize(start + len, 0);
}

impl Group for Fanotify {
    fn handle_event(&self, _mark: &Arc<Mark>, _mask: u32, _name: Option<&[u8]>, _cookie: u32) {}

    fn freeing_mark(&self, mark: &Arc<Mark>) {
        let mut st = self.state.lock();
        let before = st.marks.len();
        st.marks.retain(|m| !Arc::ptr_eq(m, mark));
        if st.marks.len() < before {
            st.mark_charges.pop();
        }
    }

    fn wants_paths(&self) -> bool {
        true
    }

    fn priority(&self) -> u32 {
        self.priority
    }

    fn handle_path(&self, ev: &FsEvent<'_>, marks: &[(Found, Arc<Mark>)]) -> Result<()> {
        let m = ev.mask;
        let ondir = m & mask::ISDIR != 0;
        let fid_mode = self.flags & FID_BITS;
        // As `fanotify_group_event_mask` of Linux. A group that reports a descriptor gets the
        // events of a path to a regular file or a directory only. A group that reports only the
        // handle of the directory needs a directory.
        if fid_mode == 0 {
            let Some(at) = ev.path else { return Ok(()) };
            let meta = at.inode().metadata();
            if !meta.is_dir() && meta.file_type() != Some(crate::inode::FileType::Regular) {
                return Ok(());
            }
        } else if fid_mode & FAN_REPORT_FID == 0 && ev.dir.is_none() && !ondir {
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
        let mut want = 0;
        let mut ignore = 0;
        let mut matched = 0;
        for (found, mark) in marks {
            if !mark.alive() {
                continue;
            }
            let parent = *found == Found::Parent;
            ignore |= effective_ignore(mark, ondir, parent);
            if applicable(mark.mask(), ondir, parent) {
                want |= mark.mask();
                matched |= found_bit(*found);
            }
        }
        let test = m & want & !ignore;
        // A group that reports a file handle gets `FAN_ONDIR`, but not an event with the flags
        // only.
        let test = if fid_mode == 0 {
            test & USER_EVENTS
        } else if test & !EVENT_FLAGS == 0 {
            0
        } else {
            test & FID_USER_EVENTS
        };
        if test == 0 {
            return Ok(());
        }
        let info = if fid_mode == 0 {
            match ev.path {
                Some(at) => Info::Path(at.clone()),
                None => return Ok(()),
            }
        } else {
            match self.fid_info(ev, test, matched) {
                Some(fid) => Info::Fid(fid),
                None => return Ok(()),
            }
        };
        let (tgid, tid) = HOOKS.get().map_or((0, 0), |h| (h.current)());
        let pid = if self.flags & FAN_REPORT_TID != 0 { tid } else { tgid };
        let perm = (test & PERM_EVENTS != 0)
            .then(|| Arc::new(Perm { state: SpinLock::new(PermState::Init) }));
        {
            let mut st = self.state.lock();
            if st.closed {
                return Ok(());
            }
            if perm.is_none() && Self::merge(&mut st, test, &info, pid) {
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
            let event = Event { mask: test, info, pid, perm: perm.clone() };
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
    /// `unpriv` tells that a user without `CAP_SYS_ADMIN` makes the group, and `charge` is the
    /// count of the group for its user. The marks of the group then count for the same user.
    pub fn new(
        flags: u32,
        f_flags: u32,
        priority: u32,
        unlimited: bool,
        unpriv: bool,
        charge: Option<Charge>,
    ) -> Self {
        let group = Arc::new_cyclic(|me| Fanotify {
            me: me.clone(),
            flags,
            f_flags,
            priority,
            unpriv,
            max_events: if unlimited {
                usize::MAX
            } else {
                MAX_QUEUED_EVENTS.load(Ordering::Relaxed) as usize
            },
            state: SpinLock::new(State {
                queue: VecDeque::new(),
                overflow: false,
                access: Vec::new(),
                marks: Vec::new(),
                charge,
                mark_charges: Vec::new(),
                closed: false,
            }),
            wait: Arc::new(WaitQueue::new()),
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
        let nonblock = file.nonblock();
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
                // A buffer that is too small for the next event gives `EINVAL`, as
                // `get_one_event` of Linux.
                let need = st.queue.front().map_or(META_LEN, |item| g.event_len(item));
                if room < need {
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
            let mut fid = None;
            let (m, fd, mut pid, perm) = match item {
                // An event without a file has `-EBADF` with `FAN_REPORT_FD_ERROR`, as Linux.
                Item::Overflow if g.flags & FAN_REPORT_FD_ERROR != 0 => {
                    (mask::Q_OVERFLOW, -i32::from(Errno::EBADF.get()), 0, None)
                }
                Item::Overflow => (mask::Q_OVERFLOW, FAN_NOFD as i32, 0, None),
                Item::Event(Event { info: Info::Fid(f), mask: m, pid, perm }) => {
                    fid = Some(f);
                    (m, FAN_NOFD as i32, pid, perm)
                }
                Item::Event(Event { info: Info::Path(at), mask: m, pid, perm }) => {
                    let fd = match g.open_fd(&at) {
                        Ok(fd) => fd,
                        Err(err) if g.flags & FAN_REPORT_FD_ERROR != 0 => -i32::from(err.get()),
                        Err(err) => {
                            if let Some(p) = &perm {
                                Fanotify::finish(p, FAN_DENY);
                                g.access_wait.wake_all();
                            }
                            if out.is_empty() {
                                return Err(err);
                            }
                            break;
                        }
                    };
                    (m, fd, pid, perm)
                }
            };
            // The pid is the ID in the PID namespace of the reader. An unprivileged group shows
            // the pid of the reader only, as `copy_event_to_user` of Linux.
            let global = pid;
            if g.unpriv && HOOKS.get().map_or(0, |h| (h.current)().0) != pid {
                pid = 0;
            }
            if pid != 0 {
                pid = HOOKS.get().map_or(pid, |h| (h.vpid)(pid));
            }
            let mut records = Vec::new();
            if let Some(f) = &fid {
                g.put_records(f, m, &mut records);
            }
            // The record of the process file descriptor comes after the records of the handles.
            if g.flags & FAN_REPORT_PIDFD != 0 {
                let pidfd = g.open_pidfd(global, pid);
                records.push(FAN_EVENT_INFO_TYPE_PIDFD as u8);
                records.push(0);
                records.extend_from_slice(&(PIDFD_INFO_LEN as u16).to_ne_bytes());
                records.extend_from_slice(&pidfd.to_ne_bytes());
            }
            let meta = FanotifyEventMetadata {
                event_len: FAN_EVENT_METADATA_LEN + records.len() as u32,
                vers: FANOTIFY_METADATA_VERSION as u8,
                reserved: 0,
                metadata_len: FAN_EVENT_METADATA_LEN as u16,
                mask: u64::from(m),
                fd,
                pid,
            };
            encode(&meta, &mut out);
            out.extend_from_slice(&records);
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

    fn poll_wait(&self, _file: &File, table: &mut PollTable) {
        table.add(&self.group.wait);
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
    fn a_record_has_the_handle_and_the_name_with_a_null() {
        let fh = Fh { ty: 1, bytes: alloc::vec![1, 2, 3, 4, 5, 6, 7, 8] };
        let mut out = Vec::new();
        put_fid(&mut out, FAN_EVENT_INFO_TYPE_DFID_NAME, [7, 9], &fh, b"ab");
        assert_eq!(out.len(), 32);
        assert_eq!(out[0], FAN_EVENT_INFO_TYPE_DFID_NAME as u8);
        assert_eq!(u16::from_ne_bytes([out[2], out[3]]), 32);
        assert_eq!(i32::from_ne_bytes([out[4], out[5], out[6], out[7]]), 7);
        assert_eq!(u32::from_ne_bytes([out[12], out[13], out[14], out[15]]), 8);
        assert_eq!(&out[20..28], &fh.bytes[..]);
        assert_eq!(&out[28..], b"ab\0\0");
        assert_eq!(fid_info_len(8, 0), 28);
        let empty = Fh { ty: 1, bytes: Vec::new() };
        let mut out = Vec::new();
        put_fid(&mut out, FAN_EVENT_INFO_TYPE_FID, [0, 0], &empty, b"");
        assert_eq!(i32::from_ne_bytes([out[16], out[17], out[18], out[19]]), 0xff);
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

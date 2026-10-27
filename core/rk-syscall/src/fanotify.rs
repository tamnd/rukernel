//! fanotify: `fanotify_init` and `fanotify_mark`, as fs/notify/fanotify/fanotify_user.c of
//! Linux. The group, its queue and its marks are in `rk_vfs::notify::fanotify`.
//!
//! The groups that report a file handle (`FAN_REPORT_FID` and the other FID bits), the groups of
//! mount events (`FAN_REPORT_MNT`) and `FAN_REPORT_PIDFD` are not supported: `fanotify_init`
//! gives `EINVAL` for them.

use crate::cx::{Cx, SysResult};
use alloc::sync::Arc;
use rk_abi::Errno;
use rk_abi::native::fanotify::{
    FAN_ALL_CLASS_BITS, FAN_ATTRIB, FAN_CLASS_CONTENT, FAN_CLASS_NOTIF, FAN_CLASS_PRE_CONTENT,
    FAN_CLOEXEC, FAN_CREATE, FAN_DELETE, FAN_DELETE_SELF, FAN_ENABLE_AUDIT, FAN_EVENT_ON_CHILD,
    FAN_FS_ERROR, FAN_MARK_ADD, FAN_MARK_DONT_FOLLOW, FAN_MARK_EVICTABLE, FAN_MARK_FILESYSTEM,
    FAN_MARK_FLUSH, FAN_MARK_IGNORE, FAN_MARK_IGNORED_MASK, FAN_MARK_IGNORED_SURV_MODIFY,
    FAN_MARK_INODE, FAN_MARK_MNTNS, FAN_MARK_MOUNT, FAN_MARK_ONLYDIR, FAN_MARK_REMOVE,
    FAN_MNT_ATTACH, FAN_MNT_DETACH, FAN_MOVE, FAN_MOVE_SELF, FAN_NONBLOCK, FAN_ONDIR,
    FAN_PRE_ACCESS, FAN_RENAME, FAN_REPORT_DFID_NAME_TARGET, FAN_REPORT_FD_ERROR, FAN_REPORT_MNT,
    FAN_REPORT_PIDFD, FAN_REPORT_TID, FAN_UNLIMITED_MARKS, FAN_UNLIMITED_QUEUE,
};
use rk_abi::native::open as o;
use rk_vfs::cred::{cap, may};
use rk_vfs::file::File;
use rk_vfs::notify::Object;
use rk_vfs::notify::fanotify::{
    EVENT_FLAGS, FD_EVENTS, Fanotify, FanotifyFile, Kind, PATH_EVENTS, PERM_EVENTS,
};

/// The bits of the classes that need a privilege, `FANOTIFY_PERM_CLASSES` of Linux.
const PERM_CLASSES: u32 = FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT;

/// The bits that report a file handle, `FANOTIFY_FID_BITS` of Linux.
const FID_BITS: u32 = FAN_REPORT_DFID_NAME_TARGET;

/// The flags of `fanotify_init` that need `CAP_SYS_ADMIN`, `FANOTIFY_ADMIN_INIT_FLAGS` of Linux.
const ADMIN_INIT_FLAGS: u32 = PERM_CLASSES
    | FAN_REPORT_TID
    | FAN_REPORT_PIDFD
    | FAN_REPORT_FD_ERROR
    | FAN_UNLIMITED_QUEUE
    | FAN_UNLIMITED_MARKS;

/// The other flags of `fanotify_init`, `FANOTIFY_USER_INIT_FLAGS` of Linux.
const USER_INIT_FLAGS: u32 =
    FAN_CLASS_NOTIF | FID_BITS | FAN_REPORT_MNT | FAN_CLOEXEC | FAN_NONBLOCK;

/// The flags of the files of the events, `FANOTIFY_INIT_ALL_EVENT_F_BITS` of Linux.
const EVENT_F_BITS: u32 = o::O_ACCMODE
    | o::O_APPEND
    | o::O_NONBLOCK
    | o::O_SYNC
    | o::O_DSYNC
    | o::O_CLOEXEC
    | o::O_LARGEFILE
    | o::O_NOATIME;

/// The bits of the kind of a mark, `FANOTIFY_MARK_TYPE_BITS` of Linux.
const MARK_TYPE_BITS: u32 = FAN_MARK_INODE | FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM | FAN_MARK_MNTNS;

/// The bits of the command of a mark, `FANOTIFY_MARK_CMD_BITS` of Linux.
const MARK_CMD_BITS: u32 = FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_FLUSH;

/// The bits of an ignore mask, `FANOTIFY_MARK_IGNORE_BITS` of Linux.
const MARK_IGNORE_BITS: u32 = FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORE;

/// The flags of `fanotify_mark`, `FANOTIFY_MARK_FLAGS` of Linux.
const MARK_FLAGS: u32 = MARK_TYPE_BITS
    | MARK_CMD_BITS
    | MARK_IGNORE_BITS
    | FAN_MARK_DONT_FOLLOW
    | FAN_MARK_ONLYDIR
    | FAN_MARK_IGNORED_SURV_MODIFY
    | FAN_MARK_EVICTABLE;

/// The events of a directory entry, `FANOTIFY_DIRENT_EVENTS` of Linux.
const DIRENT_EVENTS: u32 = FAN_MOVE | FAN_CREATE | FAN_DELETE | FAN_RENAME;

/// The mount events, `FANOTIFY_MOUNT_EVENTS` of Linux.
const MOUNT_EVENTS: u32 = FAN_MNT_ATTACH | FAN_MNT_DETACH;

/// The events of `fanotify_mark`, `FANOTIFY_EVENTS` of Linux.
const EVENTS: u32 = PATH_EVENTS
    | DIRENT_EVENTS
    | FAN_ATTRIB
    | FAN_MOVE_SELF
    | FAN_DELETE_SELF
    | FAN_FS_ERROR
    | MOUNT_EVENTS;

/// The bits that only the mask of a directory can have, `FANOTIFY_DIRONLY_EVENT_BITS` of Linux.
const DIRONLY_EVENT_BITS: u32 = DIRENT_EVENTS | EVENT_FLAGS;

pub(crate) fn fanotify_init(cx: &Cx<'_>, flags: u64, event_f_flags: u64) -> SysResult {
    let flags = flags as u32;
    let mut f_flags = event_f_flags as u32;
    let cred = cx.process().cred();
    if (flags & ADMIN_INIT_FLAGS != 0 || flags & (FID_BITS | FAN_REPORT_MNT) == 0)
        && !cred.capable(cap::SYS_ADMIN)
    {
        return Err(Errno::EPERM);
    }
    if flags & !(ADMIN_INIT_FLAGS | USER_INIT_FLAGS | FAN_ENABLE_AUDIT) != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & (FID_BITS | FAN_REPORT_MNT | FAN_REPORT_PIDFD) != 0 {
        return Err(Errno::EINVAL);
    }
    if f_flags & !EVENT_F_BITS != 0 || f_flags & o::O_ACCMODE == o::O_ACCMODE {
        return Err(Errno::EINVAL);
    }
    let priority = match flags & FAN_ALL_CLASS_BITS {
        FAN_CLASS_NOTIF => 0,
        FAN_CLASS_CONTENT => 1,
        FAN_CLASS_PRE_CONTENT => 2,
        _ => return Err(Errno::EINVAL),
    };
    if flags & FAN_ENABLE_AUDIT != 0 && !cred.capable(cap::AUDIT_WRITE) {
        return Err(Errno::EPERM);
    }
    f_flags |= o::O_LARGEFILE;
    let ops = FanotifyFile::new(flags, f_flags, priority, flags & FAN_UNLIMITED_QUEUE != 0);
    let nonblock = if flags & FAN_NONBLOCK != 0 { o::O_NONBLOCK } else { 0 };
    let file = File::with_ops(Arc::new(ops), None, o::O_RDWR | nonblock);
    file.set_nonotify();
    Ok(cx.files()?.lock().insert(file, flags & FAN_CLOEXEC != 0)? as u64)
}

/// The group of the descriptor `fd`. Gives `EBADF` for a bad descriptor and `EINVAL` for a file
/// that is not a group, as Linux.
fn group(cx: &Cx<'_>, fd: u64) -> Result<Arc<Fanotify>, Errno> {
    let file = cx.file(fd)?;
    file.ops()
        .as_any()
        .and_then(|a| a.downcast_ref::<FanotifyFile>())
        .map(|f| f.group().clone())
        .ok_or(Errno::EINVAL)
}

pub(crate) fn fanotify_mark(
    cx: &Cx<'_>,
    fd: u64,
    flags: u64,
    mask: u64,
    dfd: u64,
    path: u64,
) -> SysResult {
    let flags = flags as u32;
    // Only the low 32 bits of the mask have events.
    let mut mask = u32::try_from(mask).map_err(|_| Errno::EINVAL)?;
    if flags & !MARK_FLAGS != 0 {
        return Err(Errno::EINVAL);
    }
    let mark_type = flags & MARK_TYPE_BITS;
    let kind = match mark_type {
        FAN_MARK_INODE => Kind::Inode,
        FAN_MARK_MOUNT => Kind::Mount,
        FAN_MARK_FILESYSTEM => Kind::Fs,
        // A mark on a mount name space needs `FAN_REPORT_MNT`, which is not supported.
        FAN_MARK_MNTNS => Kind::Mount,
        _ => return Err(Errno::EINVAL),
    };
    let cmd = flags & MARK_CMD_BITS;
    match cmd {
        FAN_MARK_ADD | FAN_MARK_REMOVE if mask == 0 => return Err(Errno::EINVAL),
        FAN_MARK_ADD | FAN_MARK_REMOVE => {}
        FAN_MARK_FLUSH if flags & !(MARK_TYPE_BITS | FAN_MARK_FLUSH) != 0 => {
            return Err(Errno::EINVAL);
        }
        FAN_MARK_FLUSH => {}
        _ => return Err(Errno::EINVAL),
    }
    if mask & !(EVENTS | EVENT_FLAGS | PERM_EVENTS) != 0 {
        return Err(Errno::EINVAL);
    }
    let ignore = flags & MARK_IGNORE_BITS;
    if ignore == MARK_IGNORE_BITS {
        return Err(Errno::EINVAL);
    }
    // The event flags have no effect in an ignore mask of the old interface.
    let mut umask = 0;
    if ignore == FAN_MARK_IGNORED_MASK {
        mask &= !EVENT_FLAGS;
        umask = EVENT_FLAGS;
    }
    let g = group(cx, fd)?;
    if mask & MOUNT_EVENTS != 0 || mark_type == FAN_MARK_MNTNS {
        return Err(Errno::EINVAL);
    }
    if mark_type != FAN_MARK_INODE && !cx.process().cred().capable(cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    // The permission events need a class above notification, and the pre-content events the
    // pre-content class.
    if mask & PERM_EVENTS != 0 && g.priority() == 0 {
        return Err(Errno::EINVAL);
    }
    if mask & FAN_PRE_ACCESS != 0 && g.priority() == 1 {
        return Err(Errno::EINVAL);
    }
    if mask & FAN_FS_ERROR != 0 && mark_type != FAN_MARK_FILESYSTEM {
        return Err(Errno::EINVAL);
    }
    if flags & FAN_MARK_EVICTABLE != 0 && mark_type != FAN_MARK_INODE {
        return Err(Errno::EINVAL);
    }
    // A group that reports a descriptor gets only the events that have a file.
    if mask & !(FD_EVENTS | MOUNT_EVENTS | EVENT_FLAGS) != 0 {
        return Err(Errno::EINVAL);
    }
    if mask & FAN_PRE_ACCESS != 0 && mask & FAN_ONDIR != 0 {
        return Err(Errno::EINVAL);
    }
    if cmd == FAN_MARK_FLUSH {
        g.flush_marks(kind);
        return Ok(0);
    }
    // As `fanotify_find_path` of Linux.
    let fs = cx.fs()?;
    let at = if path == 0 {
        let file = cx.file(dfd)?;
        let at = file.location().ok_or(Errno::EBADF)?.clone();
        if flags & FAN_MARK_ONLYDIR != 0 && !at.inode().metadata().is_dir() {
            return Err(Errno::ENOTDIR);
        }
        at
    } else {
        let path = cx.read_path(path)?;
        let start = cx.dir_start(&fs, dfd, &path)?;
        let at = fs.resolve(&start, &path, flags & FAN_MARK_DONT_FOLLOW == 0)?;
        if flags & FAN_MARK_ONLYDIR != 0 && !at.inode().metadata().is_dir() {
            return Err(Errno::ENOTDIR);
        }
        at
    };
    let is_dir = at.inode().metadata().is_dir();
    if cmd == FAN_MARK_ADD {
        // As `fanotify_events_supported` of Linux. No file system allows the pre-content events.
        if mask & FAN_PRE_ACCESS != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let strict = flags & FAN_MARK_IGNORE != 0 || mask & FAN_RENAME != 0;
        if strict && mark_type == FAN_MARK_INODE && !is_dir && mask & DIRONLY_EVENT_BITS != 0 {
            return Err(Errno::ENOTDIR);
        }
    }
    // A mark needs the read permission of the file.
    fs.permission(&at, may::READ)?;
    let object = match kind {
        Kind::Inode => Object::Inode(at.inode().clone()),
        Kind::Mount => Object::Mount(at.mount.clone()),
        Kind::Fs => Object::Fs(at.inode().fs_id()),
    };
    // `FAN_MARK_IGNORE` needs `FAN_MARK_IGNORED_SURV_MODIFY` on a mount, a file system and a
    // directory.
    if cmd == FAN_MARK_ADD && ignore == FAN_MARK_IGNORE && flags & FAN_MARK_IGNORED_SURV_MODIFY == 0
    {
        if kind != Kind::Inode {
            return Err(Errno::EINVAL);
        }
        if is_dir {
            return Err(Errno::EISDIR);
        }
    }
    // The event flag for children has no effect on a mount, a file system and a file that is not
    // a directory.
    if kind != Kind::Inode || !is_dir {
        mask &= !FAN_EVENT_ON_CHILD;
        umask = FAN_EVENT_ON_CHILD;
    }
    if cmd == FAN_MARK_ADD {
        g.add_mark(object, mask, flags)?;
    } else {
        g.remove_mark(&object, mask, flags, umask)?;
    }
    Ok(0)
}

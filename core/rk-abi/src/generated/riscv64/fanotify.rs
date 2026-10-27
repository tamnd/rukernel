// rk-abigen generated this file from Linux 7.3, from <linux/fanotify.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The events, the flags and the responses of `fanotify_init` and `fanotify_mark`.

/// `FAN_CLASS_NOTIF` from `<linux/fanotify.h>`.
pub const FAN_CLASS_NOTIF: u32 = 0;
/// `FAN_MARK_INODE` from `<linux/fanotify.h>`.
pub const FAN_MARK_INODE: u32 = 0;
/// `FAN_RESPONSE_INFO_NONE` from `<linux/fanotify.h>`.
pub const FAN_RESPONSE_INFO_NONE: u32 = 0;
/// File was accessed.
pub const FAN_ACCESS: u32 = 1;
/// `FAN_ALLOW` from `<linux/fanotify.h>`.
pub const FAN_ALLOW: u32 = 1;
/// `FAN_CLOEXEC` from `<linux/fanotify.h>`.
pub const FAN_CLOEXEC: u32 = 1;
/// `FAN_EVENT_INFO_TYPE_FID` from `<linux/fanotify.h>`.
pub const FAN_EVENT_INFO_TYPE_FID: u32 = 1;
/// `FAN_MARK_ADD` from `<linux/fanotify.h>`.
pub const FAN_MARK_ADD: u32 = 1;
/// `FAN_RESPONSE_INFO_AUDIT_RULE` from `<linux/fanotify.h>`.
pub const FAN_RESPONSE_INFO_AUDIT_RULE: u32 = 1;
/// `FAN_DENY` from `<linux/fanotify.h>`.
pub const FAN_DENY: u32 = 2;
/// `FAN_EVENT_INFO_TYPE_DFID_NAME` from `<linux/fanotify.h>`.
pub const FAN_EVENT_INFO_TYPE_DFID_NAME: u32 = 2;
/// `FAN_MARK_REMOVE` from `<linux/fanotify.h>`.
pub const FAN_MARK_REMOVE: u32 = 2;
/// File was modified.
pub const FAN_MODIFY: u32 = 2;
/// `FAN_NONBLOCK` from `<linux/fanotify.h>`.
pub const FAN_NONBLOCK: u32 = 2;
/// `FANOTIFY_METADATA_VERSION` from `<linux/fanotify.h>`.
pub const FANOTIFY_METADATA_VERSION: u32 = 3;
/// `FAN_EVENT_INFO_TYPE_DFID` from `<linux/fanotify.h>`.
pub const FAN_EVENT_INFO_TYPE_DFID: u32 = 3;
/// Metadata changed.
pub const FAN_ATTRIB: u32 = 4;
/// `FAN_CLASS_CONTENT` from `<linux/fanotify.h>`.
pub const FAN_CLASS_CONTENT: u32 = 4;
/// `FAN_EVENT_INFO_TYPE_PIDFD` from `<linux/fanotify.h>`.
pub const FAN_EVENT_INFO_TYPE_PIDFD: u32 = 4;
/// `FAN_MARK_DONT_FOLLOW` from `<linux/fanotify.h>`.
pub const FAN_MARK_DONT_FOLLOW: u32 = 4;
/// `FAN_EVENT_INFO_TYPE_ERROR` from `<linux/fanotify.h>`.
pub const FAN_EVENT_INFO_TYPE_ERROR: u32 = 5;
/// `FAN_EVENT_INFO_TYPE_RANGE` from `<linux/fanotify.h>`.
pub const FAN_EVENT_INFO_TYPE_RANGE: u32 = 6;
/// `FAN_EVENT_INFO_TYPE_MNT` from `<linux/fanotify.h>`.
pub const FAN_EVENT_INFO_TYPE_MNT: u32 = 7;
/// `FAN_CLASS_PRE_CONTENT` from `<linux/fanotify.h>`.
pub const FAN_CLASS_PRE_CONTENT: u32 = 8;
/// Writable file closed.
pub const FAN_CLOSE_WRITE: u32 = 8;
/// `FAN_ERRNO_BITS` from `<linux/fanotify.h>`.
pub const FAN_ERRNO_BITS: u32 = 8;
/// `FAN_MARK_ONLYDIR` from `<linux/fanotify.h>`.
pub const FAN_MARK_ONLYDIR: u32 = 8;
/// `FAN_EVENT_INFO_TYPE_OLD_DFID_NAME` from `<linux/fanotify.h>`.
pub const FAN_EVENT_INFO_TYPE_OLD_DFID_NAME: u32 = 10;
/// `FAN_ALL_CLASS_BITS` from `<linux/fanotify.h>`.
pub const FAN_ALL_CLASS_BITS: u32 = 12;
/// `FAN_EVENT_INFO_TYPE_NEW_DFID_NAME` from `<linux/fanotify.h>`.
pub const FAN_EVENT_INFO_TYPE_NEW_DFID_NAME: u32 = 12;
/// Bitmask to create audit record for result.
pub const FAN_AUDIT: u32 = 16;
/// Unwritable file closed.
pub const FAN_CLOSE_NOWRITE: u32 = 16;
/// `FAN_MARK_MOUNT` from `<linux/fanotify.h>`.
pub const FAN_MARK_MOUNT: u32 = 16;
/// `FAN_UNLIMITED_QUEUE` from `<linux/fanotify.h>`.
pub const FAN_UNLIMITED_QUEUE: u32 = 16;
/// Close.
pub const FAN_CLOSE: u32 = 24;
/// `FAN_ERRNO_SHIFT` from `<linux/fanotify.h>`.
pub const FAN_ERRNO_SHIFT: u32 = 24;
/// `FAN_EVENT_METADATA_LEN` from `<linux/fanotify.h>`.
pub const FAN_EVENT_METADATA_LEN: u32 = 24;
/// Bitmask to indicate additional information.
pub const FAN_INFO: u32 = 32;
/// `FAN_MARK_IGNORED_MASK` from `<linux/fanotify.h>`.
pub const FAN_MARK_IGNORED_MASK: u32 = 32;
/// File was opened.
pub const FAN_OPEN: u32 = 32;
/// `FAN_UNLIMITED_MARKS` from `<linux/fanotify.h>`.
pub const FAN_UNLIMITED_MARKS: u32 = 32;
/// `FAN_ALL_EVENTS` from `<linux/fanotify.h>`.
pub const FAN_ALL_EVENTS: u32 = 59;
/// `FAN_ALL_INIT_FLAGS` from `<linux/fanotify.h>`.
pub const FAN_ALL_INIT_FLAGS: u32 = 63;
/// `FAN_ENABLE_AUDIT` from `<linux/fanotify.h>`.
pub const FAN_ENABLE_AUDIT: u32 = 64;
/// `FAN_MARK_IGNORED_SURV_MODIFY` from `<linux/fanotify.h>`.
pub const FAN_MARK_IGNORED_SURV_MODIFY: u32 = 64;
/// File was moved from X.
pub const FAN_MOVED_FROM: u32 = 64;
/// `FAN_MARK_FLUSH` from `<linux/fanotify.h>`.
pub const FAN_MARK_FLUSH: u32 = 128;
/// File was moved to Y.
pub const FAN_MOVED_TO: u32 = 128;
/// Report pidfd for event-\>pid.
pub const FAN_REPORT_PIDFD: u32 = 128;
/// Moves.
pub const FAN_MOVE: u32 = 192;
/// `FAN_ALL_MARK_FLAGS` from `<linux/fanotify.h>`.
pub const FAN_ALL_MARK_FLAGS: u32 = 255;
/// `FAN_ERRNO_MASK` from `<linux/fanotify.h>`.
pub const FAN_ERRNO_MASK: u32 = 255;
/// Subfile was created.
pub const FAN_CREATE: u32 = 0x100;
/// `FAN_MARK_FILESYSTEM` from `<linux/fanotify.h>`.
pub const FAN_MARK_FILESYSTEM: u32 = 0x100;
/// Event-\>pid is thread id.
pub const FAN_REPORT_TID: u32 = 0x100;
/// `FAN_MARK_MNTNS` from `<linux/fanotify.h>`.
pub const FAN_MARK_MNTNS: u32 = 0x110;
/// Subfile was deleted.
pub const FAN_DELETE: u32 = 0x200;
/// `FAN_MARK_EVICTABLE` from `<linux/fanotify.h>`.
pub const FAN_MARK_EVICTABLE: u32 = 0x200;
/// Report unique file id.
pub const FAN_REPORT_FID: u32 = 0x200;
/// Self was deleted.
pub const FAN_DELETE_SELF: u32 = 0x400;
/// `FAN_MARK_IGNORE` from `<linux/fanotify.h>`.
pub const FAN_MARK_IGNORE: u32 = 0x400;
/// Report unique directory id.
pub const FAN_REPORT_DIR_FID: u32 = 0x400;
/// `FAN_MARK_IGNORE_SURV` from `<linux/fanotify.h>`.
pub const FAN_MARK_IGNORE_SURV: u32 = 0x440;
/// Self was moved.
pub const FAN_MOVE_SELF: u32 = 0x800;
/// Report events with name.
pub const FAN_REPORT_NAME: u32 = 0x800;
/// `FAN_REPORT_DFID_NAME` from `<linux/fanotify.h>`.
pub const FAN_REPORT_DFID_NAME: u32 = 0xc00;
/// File was opened for exec.
pub const FAN_OPEN_EXEC: u32 = 0x1000;
/// Report dirent target id.
pub const FAN_REPORT_TARGET_FID: u32 = 0x1000;
/// `FAN_REPORT_DFID_NAME_TARGET` from `<linux/fanotify.h>`.
pub const FAN_REPORT_DFID_NAME_TARGET: u32 = 0x1e00;
/// Event-\>fd can report error.
pub const FAN_REPORT_FD_ERROR: u32 = 0x2000;
/// Event queued overflowed.
pub const FAN_Q_OVERFLOW: u32 = 0x4000;
/// Report mount events.
pub const FAN_REPORT_MNT: u32 = 0x4000;
/// Filesystem error.
pub const FAN_FS_ERROR: u32 = 0x8000;
/// File open in perm check.
pub const FAN_OPEN_PERM: u32 = 0x1_0000;
/// File accessed in perm check.
pub const FAN_ACCESS_PERM: u32 = 0x2_0000;
/// `FAN_ALL_PERM_EVENTS` from `<linux/fanotify.h>`.
pub const FAN_ALL_PERM_EVENTS: u32 = 0x3_0000;
/// `FAN_ALL_OUTGOING_EVENTS` from `<linux/fanotify.h>`.
pub const FAN_ALL_OUTGOING_EVENTS: u32 = 0x3_403b;
/// File open/exec in perm check.
pub const FAN_OPEN_EXEC_PERM: u32 = 0x4_0000;
/// Pre-content access hook.
pub const FAN_PRE_ACCESS: u32 = 0x10_0000;
/// Mount was attached.
pub const FAN_MNT_ATTACH: u32 = 0x100_0000;
/// Mount was detached.
pub const FAN_MNT_DETACH: u32 = 0x200_0000;
/// Interested in child events.
pub const FAN_EVENT_ON_CHILD: u32 = 0x800_0000;
/// File was renamed.
pub const FAN_RENAME: u32 = 0x1000_0000;
/// Event occurred against dir.
pub const FAN_ONDIR: u32 = 0x4000_0000;
/// `FAN_EPIDFD` from `<linux/fanotify.h>`.
pub const FAN_EPIDFD: u32 = 0xffff_fffe;
/// `FAN_NOFD` from `<linux/fanotify.h>`.
pub const FAN_NOFD: u32 = 0xffff_ffff;
/// The same value as `FAN_NOFD`.
pub const FAN_NOPIDFD: u32 = 0xffff_ffff;

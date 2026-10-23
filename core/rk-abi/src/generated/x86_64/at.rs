// rk-abigen generated this file from Linux 7.3, from <linux/fcntl.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The directory file descriptor and the flags of the `*at` calls.

/// `AT_FDCWD` from `<linux/fcntl.h>`.
pub const AT_FDCWD: i32 = -100;
/// - Do whatever stat() does.
pub const AT_STATX_SYNC_AS_STAT: i32 = 0;
/// Return the u64 unique mount ID.
pub const AT_HANDLE_MNT_ID_UNIQUE: i32 = 1;
/// `AT_RENAME_NOREPLACE` from `<linux/fcntl.h>`.
pub const AT_RENAME_NOREPLACE: i32 = 1;
/// Request a connectable file handle.
pub const AT_HANDLE_CONNECTABLE: i32 = 2;
/// `AT_RENAME_EXCHANGE` from `<linux/fcntl.h>`.
pub const AT_RENAME_EXCHANGE: i32 = 2;
/// `AT_RENAME_WHITEOUT` from `<linux/fcntl.h>`.
pub const AT_RENAME_WHITEOUT: i32 = 4;
/// `AT_SYMLINK_NOFOLLOW` from `<linux/fcntl.h>`.
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
/// `AT_EACCESS` from `<linux/fcntl.h>`.
pub const AT_EACCESS: i32 = 0x200;
/// `AT_HANDLE_FID` from `<linux/fcntl.h>`.
pub const AT_HANDLE_FID: i32 = 0x200;
/// `AT_REMOVEDIR` from `<linux/fcntl.h>`.
pub const AT_REMOVEDIR: i32 = 0x200;
/// Follow symbolic links.
pub const AT_SYMLINK_FOLLOW: i32 = 0x400;
/// `AT_NO_AUTOMOUNT` from `<linux/fcntl.h>`.
pub const AT_NO_AUTOMOUNT: i32 = 0x800;
/// `AT_EMPTY_PATH` from `<linux/fcntl.h>`.
pub const AT_EMPTY_PATH: i32 = 0x1000;
/// - Force the attributes to be sync'd with the server.
pub const AT_STATX_FORCE_SYNC: i32 = 0x2000;
/// - Don't sync attributes with the server.
pub const AT_STATX_DONT_SYNC: i32 = 0x4000;
/// Type of synchronisation required from statx().
pub const AT_STATX_SYNC_TYPE: i32 = 0x6000;
/// Apply to the entire subtree.
pub const AT_RECURSIVE: i32 = 0x8000;
/// `AT_EXECVE_CHECK` from `<linux/fcntl.h>`.
pub const AT_EXECVE_CHECK: i32 = 0x1_0000;

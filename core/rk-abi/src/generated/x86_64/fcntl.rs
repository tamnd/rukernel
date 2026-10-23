// rk-abigen generated this file from Linux 7.3, from <linux/fcntl.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The commands and flags of `fcntl`, and the special file descriptors.

/// Invalid file descriptor: -10000 - EBADF = -10009.
pub const FD_INVALID: i32 = -10009;
/// Root of the failfs filesystem.
pub const FD_FAILFS_ROOT: i32 = -10004;
/// Root of the nsfs filesystem.
pub const FD_NSFS_ROOT: i32 = -10003;
/// Root of the pidfs filesystem.
pub const FD_PIDFS_ROOT: i32 = -10002;
/// Dup.
pub const F_DUPFD: i32 = 0;
/// `F_OWNER_TID` from `<linux/fcntl.h>`.
pub const F_OWNER_TID: i32 = 0;
/// `F_RDLCK` from `<linux/fcntl.h>`.
pub const F_RDLCK: i32 = 0;
/// Actually anything with low bit set goes.
pub const FD_CLOEXEC: i32 = 1;
/// Get close\_on\_exec.
pub const F_GETFD: i32 = 1;
/// `F_OWNER_PID` from `<linux/fcntl.h>`.
pub const F_OWNER_PID: i32 = 1;
/// Prevent further seals from being set.
pub const F_SEAL_SEAL: i32 = 1;
/// `F_WRLCK` from `<linux/fcntl.h>`.
pub const F_WRLCK: i32 = 1;
/// `F_OWNER_PGRP` from `<linux/fcntl.h>`.
pub const F_OWNER_PGRP: i32 = 2;
/// Prevent file from shrinking.
pub const F_SEAL_SHRINK: i32 = 2;
/// Set/clear close\_on\_exec.
pub const F_SETFD: i32 = 2;
/// `F_UNLCK` from `<linux/fcntl.h>`.
pub const F_UNLCK: i32 = 2;
/// Get file-\>f\_flags.
pub const F_GETFL: i32 = 3;
/// Or 3.
pub const F_EXLCK: i32 = 4;
/// Prevent file from growing.
pub const F_SEAL_GROW: i32 = 4;
/// Set file-\>f\_flags.
pub const F_SETFL: i32 = 4;
/// `F_GETLK` from `<linux/fcntl.h>`.
pub const F_GETLK: i32 = 5;
/// `F_SETLK` from `<linux/fcntl.h>`.
pub const F_SETLK: i32 = 6;
/// `F_SETLKW` from `<linux/fcntl.h>`.
pub const F_SETLKW: i32 = 7;
/// Prevent writes.
pub const F_SEAL_WRITE: i32 = 8;
/// For sockets.
pub const F_SETOWN: i32 = 8;
/// Or 4.
pub const F_SHLCK: i32 = 8;
/// For sockets.
pub const F_GETOWN: i32 = 9;
/// For sockets.
pub const F_SETSIG: i32 = 10;
/// For sockets.
pub const F_GETSIG: i32 = 11;
/// `F_SETOWN_EX` from `<linux/fcntl.h>`.
pub const F_SETOWN_EX: i32 = 15;
/// `F_GETOWN_EX` from `<linux/fcntl.h>`.
pub const F_GETOWN_EX: i32 = 16;
/// Prevent future writes while mapped.
pub const F_SEAL_FUTURE_WRITE: i32 = 16;
/// `F_GETOWNER_UIDS` from `<linux/fcntl.h>`.
pub const F_GETOWNER_UIDS: i32 = 17;
/// Prevent chmod modifying exec bits.
pub const F_SEAL_EXEC: i32 = 32;
/// `F_OFD_GETLK` from `<linux/fcntl.h>`.
pub const F_OFD_GETLK: i32 = 36;
/// `F_OFD_SETLK` from `<linux/fcntl.h>`.
pub const F_OFD_SETLK: i32 = 37;
/// `F_OFD_SETLKW` from `<linux/fcntl.h>`.
pub const F_OFD_SETLKW: i32 = 38;
/// `F_LINUX_SPECIFIC_BASE` from `<linux/fcntl.h>`.
pub const F_LINUX_SPECIFIC_BASE: i32 = 0x400;
/// `F_SETLEASE` from `<linux/fcntl.h>`.
pub const F_SETLEASE: i32 = 0x400;
/// `F_GETLEASE` from `<linux/fcntl.h>`.
pub const F_GETLEASE: i32 = 0x401;
/// `F_NOTIFY` from `<linux/fcntl.h>`.
pub const F_NOTIFY: i32 = 0x402;
/// `F_DUPFD_QUERY` from `<linux/fcntl.h>`.
pub const F_DUPFD_QUERY: i32 = 0x403;
/// `F_CREATED_QUERY` from `<linux/fcntl.h>`.
pub const F_CREATED_QUERY: i32 = 0x404;
/// `F_CANCELLK` from `<linux/fcntl.h>`.
pub const F_CANCELLK: i32 = 0x405;
/// `F_DUPFD_CLOEXEC` from `<linux/fcntl.h>`.
pub const F_DUPFD_CLOEXEC: i32 = 0x406;
/// `F_SETPIPE_SZ` from `<linux/fcntl.h>`.
pub const F_SETPIPE_SZ: i32 = 0x407;
/// `F_GETPIPE_SZ` from `<linux/fcntl.h>`.
pub const F_GETPIPE_SZ: i32 = 0x408;
/// `F_ADD_SEALS` from `<linux/fcntl.h>`.
pub const F_ADD_SEALS: i32 = 0x409;
/// `F_GET_SEALS` from `<linux/fcntl.h>`.
pub const F_GET_SEALS: i32 = 0x40a;
/// `F_GET_RW_HINT` from `<linux/fcntl.h>`.
pub const F_GET_RW_HINT: i32 = 0x40b;
/// `F_SET_RW_HINT` from `<linux/fcntl.h>`.
pub const F_SET_RW_HINT: i32 = 0x40c;
/// `F_GET_FILE_RW_HINT` from `<linux/fcntl.h>`.
pub const F_GET_FILE_RW_HINT: i32 = 0x40d;
/// `F_SET_FILE_RW_HINT` from `<linux/fcntl.h>`.
pub const F_SET_FILE_RW_HINT: i32 = 0x40e;
/// `F_GETDELEG` from `<linux/fcntl.h>`.
pub const F_GETDELEG: i32 = 0x40f;
/// `F_SETDELEG` from `<linux/fcntl.h>`.
pub const F_SETDELEG: i32 = 0x410;

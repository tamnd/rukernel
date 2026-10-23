// rk-abigen generated this file from Linux 7.3, from <linux/fcntl.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The flags of `open`.

/// `O_RDONLY` from `<linux/fcntl.h>`.
pub const O_RDONLY: u32 = 0;
/// `O_WRONLY` from `<linux/fcntl.h>`.
pub const O_WRONLY: u32 = 1;
/// `O_RDWR` from `<linux/fcntl.h>`.
pub const O_RDWR: u32 = 2;
/// `O_ACCMODE` from `<linux/fcntl.h>`.
pub const O_ACCMODE: u32 = 3;
/// Not fcntl.
pub const O_CREAT: u32 = 64;
/// Not fcntl.
pub const O_EXCL: u32 = 128;
/// Not fcntl.
pub const O_NOCTTY: u32 = 0x100;
/// Not fcntl.
pub const O_TRUNC: u32 = 0x200;
/// `O_APPEND` from `<linux/fcntl.h>`.
pub const O_APPEND: u32 = 0x400;
/// The same value as `O_NONBLOCK`.
pub const O_NDELAY: u32 = 0x800;
/// `O_NONBLOCK` from `<linux/fcntl.h>`.
pub const O_NONBLOCK: u32 = 0x800;
/// Used to be O\_SYNC, see below.
pub const O_DSYNC: u32 = 0x1000;
/// Direct disk access hint.
pub const O_DIRECT: u32 = 0x4000;
/// `O_LARGEFILE` from `<linux/fcntl.h>`.
pub const O_LARGEFILE: u32 = 0x8000;
/// Must be a directory.
pub const O_DIRECTORY: u32 = 0x1_0000;
/// Don't follow links.
pub const O_NOFOLLOW: u32 = 0x2_0000;
/// `O_NOATIME` from `<linux/fcntl.h>`.
pub const O_NOATIME: u32 = 0x4_0000;
/// Set close\_on\_exec.
pub const O_CLOEXEC: u32 = 0x8_0000;
/// `O_SYNC` from `<linux/fcntl.h>`.
pub const O_SYNC: u32 = 0x10_1000;
/// `O_PATH` from `<linux/fcntl.h>`.
pub const O_PATH: u32 = 0x20_0000;
/// `O_TMPFILE` from `<linux/fcntl.h>`.
pub const O_TMPFILE: u32 = 0x41_0000;
/// Allow empty path.
pub const O_EMPTYPATH: u32 = 0x400_0000;

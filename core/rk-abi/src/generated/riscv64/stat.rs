// rk-abigen generated this file from Linux 7.3, from <linux/stat.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The file type and mode bits of `st_mode`, and the masks and attributes of `statx`.

/// Want/got stx\_mode & S\_IFMT.
pub const STATX_TYPE: u32 = 1;
/// `S_IXOTH` from `<linux/stat.h>`.
pub const S_IXOTH: u32 = 1;
/// Want/got stx\_mode & ~S\_IFMT.
pub const STATX_MODE: u32 = 2;
/// `S_IWOTH` from `<linux/stat.h>`.
pub const S_IWOTH: u32 = 2;
/// \[I\] File is compressed by the fs.
pub const STATX_ATTR_COMPRESSED: u32 = 4;
/// Want/got stx\_nlink.
pub const STATX_NLINK: u32 = 4;
/// `S_IROTH` from `<linux/stat.h>`.
pub const S_IROTH: u32 = 4;
/// `S_IRWXO` from `<linux/stat.h>`.
pub const S_IRWXO: u32 = 7;
/// Want/got stx\_uid.
pub const STATX_UID: u32 = 8;
/// `S_IXGRP` from `<linux/stat.h>`.
pub const S_IXGRP: u32 = 8;
/// \[I\] File is marked immutable.
pub const STATX_ATTR_IMMUTABLE: u32 = 16;
/// Want/got stx\_gid.
pub const STATX_GID: u32 = 16;
/// `S_IWGRP` from `<linux/stat.h>`.
pub const S_IWGRP: u32 = 16;
/// Want/got stx\_atime.
pub const STATX_ATIME: u32 = 32;
/// \[I\] File is append-only.
pub const STATX_ATTR_APPEND: u32 = 32;
/// `S_IRGRP` from `<linux/stat.h>`.
pub const S_IRGRP: u32 = 32;
/// `S_IRWXG` from `<linux/stat.h>`.
pub const S_IRWXG: u32 = 56;
/// \[I\] File is not to be dumped.
pub const STATX_ATTR_NODUMP: u32 = 64;
/// Want/got stx\_mtime.
pub const STATX_MTIME: u32 = 64;
/// `S_IXUSR` from `<linux/stat.h>`.
pub const S_IXUSR: u32 = 64;
/// Want/got stx\_ctime.
pub const STATX_CTIME: u32 = 128;
/// `S_IWUSR` from `<linux/stat.h>`.
pub const S_IWUSR: u32 = 128;
/// Want/got stx\_ino.
pub const STATX_INO: u32 = 0x100;
/// `S_IRUSR` from `<linux/stat.h>`.
pub const S_IRUSR: u32 = 0x100;
/// `S_IRWXU` from `<linux/stat.h>`.
pub const S_IRWXU: u32 = 0x1c0;
/// Want/got stx\_size.
pub const STATX_SIZE: u32 = 0x200;
/// `S_ISVTX` from `<linux/stat.h>`.
pub const S_ISVTX: u32 = 0x200;
/// Want/got stx\_blocks.
pub const STATX_BLOCKS: u32 = 0x400;
/// `S_ISGID` from `<linux/stat.h>`.
pub const S_ISGID: u32 = 0x400;
/// The stuff in the normal stat struct.
pub const STATX_BASIC_STATS: u32 = 0x7ff;
/// \[I\] File requires key to decrypt in fs.
pub const STATX_ATTR_ENCRYPTED: u32 = 0x800;
/// Want/got stx\_btime.
pub const STATX_BTIME: u32 = 0x800;
/// `S_ISUID` from `<linux/stat.h>`.
pub const S_ISUID: u32 = 0x800;
/// `STATX_ALL` from `<linux/stat.h>`.
pub const STATX_ALL: u32 = 0xfff;
/// Dir: Automount trigger.
pub const STATX_ATTR_AUTOMOUNT: u32 = 0x1000;
/// Got stx\_mnt\_id.
pub const STATX_MNT_ID: u32 = 0x1000;
/// `S_IFIFO` from `<linux/stat.h>`.
pub const S_IFIFO: u32 = 0x1000;
/// Root of a mount.
pub const STATX_ATTR_MOUNT_ROOT: u32 = 0x2000;
/// Want/got direct I/O alignment info.
pub const STATX_DIOALIGN: u32 = 0x2000;
/// `S_IFCHR` from `<linux/stat.h>`.
pub const S_IFCHR: u32 = 0x2000;
/// Want/got extended stx\_mount\_id.
pub const STATX_MNT_ID_UNIQUE: u32 = 0x4000;
/// `S_IFDIR` from `<linux/stat.h>`.
pub const S_IFDIR: u32 = 0x4000;
/// `S_IFBLK` from `<linux/stat.h>`.
pub const S_IFBLK: u32 = 0x6000;
/// Want/got stx\_subvol.
pub const STATX_SUBVOL: u32 = 0x8000;
/// `S_IFREG` from `<linux/stat.h>`.
pub const S_IFREG: u32 = 0x8000;
/// `S_IFLNK` from `<linux/stat.h>`.
pub const S_IFLNK: u32 = 0xa000;
/// `S_IFSOCK` from `<linux/stat.h>`.
pub const S_IFSOCK: u32 = 0xc000;
/// `S_IFMT` from `<linux/stat.h>`.
pub const S_IFMT: u32 = 0xf000;
/// Want/got atomic\_write\_\* fields.
pub const STATX_WRITE_ATOMIC: u32 = 0x1_0000;
/// Want/got dio read alignment info.
pub const STATX_DIO_READ_ALIGN: u32 = 0x2_0000;
/// \[I\] Verity protected file.
pub const STATX_ATTR_VERITY: u32 = 0x10_0000;
/// File is currently in DAX state.
pub const STATX_ATTR_DAX: u32 = 0x20_0000;
/// File supports atomic write operations.
pub const STATX_ATTR_WRITE_ATOMIC: u32 = 0x40_0000;
/// Reserved for future struct statx expansion.
pub const STATX__RESERVED: u32 = 0x8000_0000;

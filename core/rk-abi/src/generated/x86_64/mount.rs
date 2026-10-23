// rk-abigen generated this file from Linux 7.3, from <linux/mount.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The flags of `mount` and `umount2`.

/// Mount read-only.
pub const MS_RDONLY: u32 = 1;
/// Ignore suid and sgid bits.
pub const MS_NOSUID: u32 = 2;
/// Disallow access to device special files.
pub const MS_NODEV: u32 = 4;
/// Disallow program execution.
pub const MS_NOEXEC: u32 = 8;
/// Writes are synced at once.
pub const MS_SYNCHRONOUS: u32 = 16;
/// Sizeof first published struct.
pub const MNT_ID_REQ_SIZE_VER0: u32 = 24;
/// Sizeof second published struct.
pub const MNT_ID_REQ_SIZE_VER1: u32 = 32;
/// Alter flags of a mounted FS.
pub const MS_REMOUNT: u32 = 32;
/// Allow mandatory locks on an FS.
pub const MS_MANDLOCK: u32 = 64;
/// Directory modifications are synchronous.
pub const MS_DIRSYNC: u32 = 128;
/// Do not follow symlinks.
pub const MS_NOSYMFOLLOW: u32 = 0x100;
/// Do not update access times.
pub const MS_NOATIME: u32 = 0x400;
/// Do not update directory access times.
pub const MS_NODIRATIME: u32 = 0x800;
/// `MS_BIND` from `<linux/mount.h>`.
pub const MS_BIND: u32 = 0x1000;
/// `MS_MOVE` from `<linux/mount.h>`.
pub const MS_MOVE: u32 = 0x2000;
/// `MS_REC` from `<linux/mount.h>`.
pub const MS_REC: u32 = 0x4000;
/// `MS_SILENT` from `<linux/mount.h>`.
pub const MS_SILENT: u32 = 0x8000;
/// `MS_VERBOSE` from `<linux/mount.h>`.
pub const MS_VERBOSE: u32 = 0x8000;
/// VFS does not apply the umask.
pub const MS_POSIXACL: u32 = 0x1_0000;
/// Change to unbindable.
pub const MS_UNBINDABLE: u32 = 0x2_0000;
/// Change to private.
pub const MS_PRIVATE: u32 = 0x4_0000;
/// Change to slave.
pub const MS_SLAVE: u32 = 0x8_0000;
/// Change to shared.
pub const MS_SHARED: u32 = 0x10_0000;
/// Update atime relative to mtime/ctime.
pub const MS_RELATIME: u32 = 0x20_0000;
/// This is a kern\_mount call.
pub const MS_KERNMOUNT: u32 = 0x40_0000;
/// Update inode I\_version field.
pub const MS_I_VERSION: u32 = 0x80_0000;
/// Always perform atime updates.
pub const MS_STRICTATIME: u32 = 0x100_0000;
/// Update the on-disk \[acm\]times lazily.
pub const MS_LAZYTIME: u32 = 0x200_0000;
/// `MS_RMT_MASK` from `<linux/mount.h>`.
pub const MS_RMT_MASK: u32 = 0x280_0051;
/// `MS_SUBMOUNT` from `<linux/mount.h>`.
pub const MS_SUBMOUNT: u32 = 0x400_0000;
/// `MS_NOREMOTELOCK` from `<linux/mount.h>`.
pub const MS_NOREMOTELOCK: u32 = 0x800_0000;
/// `MS_NOSEC` from `<linux/mount.h>`.
pub const MS_NOSEC: u32 = 0x1000_0000;
/// `MS_BORN` from `<linux/mount.h>`.
pub const MS_BORN: u32 = 0x2000_0000;
/// `MS_ACTIVE` from `<linux/mount.h>`.
pub const MS_ACTIVE: u32 = 0x4000_0000;
/// `MS_NOUSER` from `<linux/mount.h>`.
pub const MS_NOUSER: u32 = 0x8000_0000;
/// `MS_MGC_VAL` from `<linux/mount.h>`.
pub const MS_MGC_VAL: u32 = 0xc0ed_0000;
/// `MS_MGC_MSK` from `<linux/mount.h>`.
pub const MS_MGC_MSK: u32 = 0xffff_0000;

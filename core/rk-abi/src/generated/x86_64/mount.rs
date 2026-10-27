// rk-abigen generated this file from Linux 7.3, from <linux/mount.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The flags of `mount` and `umount2`, and of the calls of the new mount API.

/// Set parameter, supplying no value.
pub const FSCONFIG_SET_FLAG: u32 = 0;
/// - Update atime relative to mtime/ctime.
pub const MOUNT_ATTR_RELATIME: u32 = 0;
/// Set parameter, supplying a string value.
pub const FSCONFIG_SET_STRING: u32 = 1;
/// `FSMOUNT_CLOEXEC` from `<linux/mount.h>`.
pub const FSMOUNT_CLOEXEC: u32 = 1;
/// `FSOPEN_CLOEXEC` from `<linux/mount.h>`.
pub const FSOPEN_CLOEXEC: u32 = 1;
/// `FSPICK_CLOEXEC` from `<linux/mount.h>`.
pub const FSPICK_CLOEXEC: u32 = 1;
/// List later mounts first.
pub const LISTMOUNT_REVERSE: u32 = 1;
/// Mount read-only.
pub const MOUNT_ATTR_RDONLY: u32 = 1;
/// Follow symlinks on from path.
pub const MOVE_MOUNT_F_SYMLINKS: u32 = 1;
/// Mount read-only.
pub const MS_RDONLY: u32 = 1;
/// Clone the target tree and attach the clone.
pub const OPEN_TREE_CLONE: u32 = 1;
/// Want mountinfo for given fd.
pub const STATMOUNT_BY_FD: u32 = 1;
/// Want/got sb\_...
pub const STATMOUNT_SB_BASIC: u32 = 1;
/// Set parameter, supplying a binary blob value.
pub const FSCONFIG_SET_BINARY: u32 = 2;
/// Create the mount in a new mount namespace.
pub const FSMOUNT_NAMESPACE: u32 = 2;
/// `FSPICK_SYMLINK_NOFOLLOW` from `<linux/mount.h>`.
pub const FSPICK_SYMLINK_NOFOLLOW: u32 = 2;
/// Ignore suid and sgid bits.
pub const MOUNT_ATTR_NOSUID: u32 = 2;
/// Follow automounts on from path.
pub const MOVE_MOUNT_F_AUTOMOUNTS: u32 = 2;
/// Ignore suid and sgid bits.
pub const MS_NOSUID: u32 = 2;
/// Clone the target tree into a new mount namespace.
pub const OPEN_TREE_NAMESPACE: u32 = 2;
/// Want/got mnt\_...
pub const STATMOUNT_MNT_BASIC: u32 = 2;
/// Set parameter, supplying an object by path.
pub const FSCONFIG_SET_PATH: u32 = 3;
/// Set parameter, supplying an object by (empty) path.
pub const FSCONFIG_SET_PATH_EMPTY: u32 = 4;
/// `FSPICK_NO_AUTOMOUNT` from `<linux/mount.h>`.
pub const FSPICK_NO_AUTOMOUNT: u32 = 4;
/// Disallow access to device special files.
pub const MOUNT_ATTR_NODEV: u32 = 4;
/// Empty from path permitted.
pub const MOVE_MOUNT_F_EMPTY_PATH: u32 = 4;
/// Disallow access to device special files.
pub const MS_NODEV: u32 = 4;
/// Want/got propagate\_from.
pub const STATMOUNT_PROPAGATE_FROM: u32 = 4;
/// Set parameter, supplying an object by fd.
pub const FSCONFIG_SET_FD: u32 = 5;
/// Create new or reuse existing superblock.
pub const FSCONFIG_CMD_CREATE: u32 = 6;
/// Invoke superblock reconfiguration.
pub const FSCONFIG_CMD_RECONFIGURE: u32 = 7;
/// Create new superblock, fail if reusing existing superblock.
pub const FSCONFIG_CMD_CREATE_EXCL: u32 = 8;
/// `FSPICK_EMPTY_PATH` from `<linux/mount.h>`.
pub const FSPICK_EMPTY_PATH: u32 = 8;
/// Disallow program execution.
pub const MOUNT_ATTR_NOEXEC: u32 = 8;
/// Disallow program execution.
pub const MS_NOEXEC: u32 = 8;
/// Want/got mnt\_root.
pub const STATMOUNT_MNT_ROOT: u32 = 8;
/// - Do not update access times.
pub const MOUNT_ATTR_NOATIME: u32 = 16;
/// Follow symlinks on to path.
pub const MOVE_MOUNT_T_SYMLINKS: u32 = 16;
/// Writes are synced at once.
pub const MS_SYNCHRONOUS: u32 = 16;
/// Want/got mnt\_point.
pub const STATMOUNT_MNT_POINT: u32 = 16;
/// Sizeof first published struct.
pub const MNT_ID_REQ_SIZE_VER0: u32 = 24;
/// Sizeof second published struct.
pub const MNT_ID_REQ_SIZE_VER1: u32 = 32;
/// Sizeof first published struct.
pub const MOUNT_ATTR_SIZE_VER0: u32 = 32;
/// - Always perform atime updates.
pub const MOUNT_ATTR_STRICTATIME: u32 = 32;
/// Follow automounts on to path.
pub const MOVE_MOUNT_T_AUTOMOUNTS: u32 = 32;
/// Alter flags of a mounted FS.
pub const MS_REMOUNT: u32 = 32;
/// Want/got fs\_type.
pub const STATMOUNT_FS_TYPE: u32 = 32;
/// Empty to path permitted.
pub const MOVE_MOUNT_T_EMPTY_PATH: u32 = 64;
/// Allow mandatory locks on an FS.
pub const MS_MANDLOCK: u32 = 64;
/// Want/got mnt\_ns\_id.
pub const STATMOUNT_MNT_NS_ID: u32 = 64;
/// Setting on how atime should be updated.
pub const MOUNT_ATTR__ATIME: u32 = 112;
/// Do not update directory access times.
pub const MOUNT_ATTR_NODIRATIME: u32 = 128;
/// Directory modifications are synchronous.
pub const MS_DIRSYNC: u32 = 128;
/// Want/got mnt\_opts.
pub const STATMOUNT_MNT_OPTS: u32 = 128;
/// Set sharing group instead.
pub const MOVE_MOUNT_SET_GROUP: u32 = 0x100;
/// Do not follow symlinks.
pub const MS_NOSYMFOLLOW: u32 = 0x100;
/// Want/got fs\_subtype.
pub const STATMOUNT_FS_SUBTYPE: u32 = 0x100;
/// Mount beneath top mount.
pub const MOVE_MOUNT_BENEATH: u32 = 0x200;
/// Want/got sb\_source.
pub const STATMOUNT_SB_SOURCE: u32 = 0x200;
/// `MOVE_MOUNT__MASK` from `<linux/mount.h>`.
pub const MOVE_MOUNT__MASK: u32 = 0x377;
/// Do not update access times.
pub const MS_NOATIME: u32 = 0x400;
/// Want/got opt\_...
pub const STATMOUNT_OPT_ARRAY: u32 = 0x400;
/// Do not update directory access times.
pub const MS_NODIRATIME: u32 = 0x800;
/// Want/got opt\_sec...
pub const STATMOUNT_OPT_SEC_ARRAY: u32 = 0x800;
/// `MS_BIND` from `<linux/mount.h>`.
pub const MS_BIND: u32 = 0x1000;
/// Want/got supported mask flags.
pub const STATMOUNT_SUPPORTED_MASK: u32 = 0x1000;
/// `MS_MOVE` from `<linux/mount.h>`.
pub const MS_MOVE: u32 = 0x2000;
/// Want/got uidmap...
pub const STATMOUNT_MNT_UIDMAP: u32 = 0x2000;
/// `MS_REC` from `<linux/mount.h>`.
pub const MS_REC: u32 = 0x4000;
/// Want/got gidmap...
pub const STATMOUNT_MNT_GIDMAP: u32 = 0x4000;
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
/// Idmap mount to @userns\_fd in struct mount\_attr.
pub const MOUNT_ATTR_IDMAP: u32 = 0x10_0000;
/// Change to shared.
pub const MS_SHARED: u32 = 0x10_0000;
/// Do not follow symlinks.
pub const MOUNT_ATTR_NOSYMFOLLOW: u32 = 0x20_0000;
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

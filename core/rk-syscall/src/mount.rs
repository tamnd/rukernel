//! `mount` and `umount2`.
//!
//! R1 has one mount name space and no propagation between mounts, so a change of the propagation
//! type has no effect. The VFS keeps the flags of a mount for `/proc/self/mounts`, but it does not
//! enforce `MS_RDONLY`, `MS_NOEXEC` and the other flags yet.

use crate::cx::{Cx, PATH_MAX, SysResult};
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::mount::{
    MS_BIND, MS_DIRSYNC, MS_MGC_MSK, MS_MGC_VAL, MS_MOVE, MS_NOATIME, MS_NODEV, MS_NODIRATIME,
    MS_NOEXEC, MS_NOSUID, MS_NOSYMFOLLOW, MS_PRIVATE, MS_RDONLY, MS_RELATIME, MS_REMOUNT,
    MS_SHARED, MS_SLAVE, MS_SYNCHRONOUS, MS_UNBINDABLE,
};
use rk_vfs::MountSource;
use rk_vfs::fstype;

/// The flags of `umount2`. They are in `<sys/mount.h>` of the C library, not in the uAPI.
const MNT_FORCE: u64 = 1;
const MNT_DETACH: u64 = 2;
const MNT_EXPIRE: u64 = 4;
const UMOUNT_NOFOLLOW: u64 = 8;

/// The flags that a mount keeps and `/proc/self/mounts` shows.
const KEPT: u32 = MS_RDONLY
    | MS_NOSUID
    | MS_NODEV
    | MS_NOEXEC
    | MS_SYNCHRONOUS
    | MS_DIRSYNC
    | MS_NOATIME
    | MS_NODIRATIME
    | MS_RELATIME
    | MS_NOSYMFOLLOW;

/// The most bytes of the data string. Linux copies one page.
const DATA_MAX: usize = 4096;

/// The propagation types.
const PROPAGATION: u32 = MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE;

pub(crate) fn mount(
    cx: &Cx<'_>,
    source: u64,
    target: u64,
    fstype: u64,
    flags: u64,
    data: u64,
) -> SysResult {
    let mut flags = flags as u32;
    // Old programs put the magic number 0xC0ED in the high 16 bits.
    if flags & MS_MGC_MSK == MS_MGC_VAL {
        flags &= !MS_MGC_MSK;
    }
    let target = cx.read_path(target)?;
    let fs = cx.fs()?;
    let at = fs.resolve(fs.cwd(), &target, true)?;
    let ns = fs.namespace();
    if flags & MS_REMOUNT != 0 {
        if !at.is_mount_root() {
            return Err(Errno::EINVAL);
        }
        at.mount.set_flags(u64::from(flags & KEPT));
        return Ok(0);
    }
    if flags & MS_BIND != 0 {
        let source = cx.read_path(source)?;
        let from = fs.resolve(fs.cwd(), &source, true)?;
        ns.bind(&from, &at)?;
        return Ok(0);
    }
    if flags & PROPAGATION != 0 {
        if !at.is_mount_root() || (flags & PROPAGATION).count_ones() != 1 {
            return Err(Errno::EINVAL);
        }
        return Ok(0);
    }
    if flags & MS_MOVE != 0 {
        return Err(Errno::EINVAL);
    }
    let vm = cx.vm()?;
    let name = if fstype == 0 { Vec::new() } else { vm.read_cstr(fstype as usize, PATH_MAX)? };
    let ty = fstype::find(&name).ok_or(Errno::ENODEV)?;
    let data = if data == 0 { Vec::new() } else { vm.read_cstr(data as usize, DATA_MAX)? };
    let source = match source {
        0 => Vec::from(&b"none"[..]),
        addr => vm.read_cstr(addr as usize, PATH_MAX)?,
    };
    // A file system on a disk has the block device of the source path.
    let dev = if ty.nodev {
        None
    } else {
        let path = fs.resolve(fs.cwd(), &source, true)?;
        let meta = path.inode().metadata();
        if meta.file_type() != Some(rk_vfs::FileType::BlockDevice) {
            return Err(Errno::ENOTBLK);
        }
        Some(meta.rdev)
    };
    let args = fstype::MountArgs { data: &data, dev, read_only: flags & MS_RDONLY != 0 };
    let root = (ty.make)(&args)?;
    let source = MountSource { source, fstype: ty.name, flags: u64::from(flags & KEPT) };
    ns.mount(root, &at, source)?;
    Ok(0)
}

pub(crate) fn umount2(cx: &Cx<'_>, target: u64, flags: u64) -> SysResult {
    if flags & !(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW) != 0
        || (flags & MNT_EXPIRE != 0 && flags & (MNT_FORCE | MNT_DETACH) != 0)
    {
        return Err(Errno::EINVAL);
    }
    let target = cx.read_path(target)?;
    let fs = cx.fs()?;
    let at = fs.resolve(fs.cwd(), &target, flags & UMOUNT_NOFOLLOW == 0)?;
    fs.namespace().unmount(&at)?;
    Ok(0)
}

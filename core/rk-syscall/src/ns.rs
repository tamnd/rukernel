//! The `ioctl` commands of the namespace files and the joins of `setns`, as fs/nsfs.c and
//! kernel/nsproxy.c of Linux.

use crate::cx::{Cx, SysResult};
use rk_abi::Errno;
use rk_abi::native::open::O_RDONLY;
use rk_proc::Process;
use rk_vfs::cred::cap;
use rk_vfs::nsfs::{NsInode, NsKind};
use rk_vfs::{File, Location};

/// `NS_GET_USERNS` of include/uapi/linux/nsfs.h.
const NS_GET_USERNS: u32 = 0xb701;
/// `NS_GET_PARENT`.
const NS_GET_PARENT: u32 = 0xb702;
/// `NS_GET_NSTYPE`.
const NS_GET_NSTYPE: u32 = 0xb703;
/// `NS_GET_OWNER_UID`.
const NS_GET_OWNER_UID: u32 = 0xb704;
/// `NS_GET_MNTNS_ID`: `_IOR(0xb7, 5, __u64)`.
const NS_GET_MNTNS_ID: u32 = 0x8008_b705;
/// `NS_GET_PID_FROM_PIDNS`: `_IOR(0xb7, 6, int)`.
const NS_GET_PID_FROM_PIDNS: u32 = 0x8004_b706;
/// `NS_GET_TGID_FROM_PIDNS`: `_IOR(0xb7, 7, int)`.
const NS_GET_TGID_FROM_PIDNS: u32 = 0x8004_b707;
/// `NS_GET_PID_IN_PIDNS`: `_IOR(0xb7, 8, int)`.
const NS_GET_PID_IN_PIDNS: u32 = 0x8004_b708;
/// `NS_GET_TGID_IN_PIDNS`: `_IOR(0xb7, 9, int)`.
const NS_GET_TGID_IN_PIDNS: u32 = 0x8004_b709;

/// Opens a file of the namespace with `O_CLOEXEC`, as `open_related_ns` of Linux.
fn open_ns(cx: &Cx<'_>, kind: NsKind, id: u32) -> SysResult {
    let file = File::open_inode(Location::detached(NsInode::new(kind, id)), O_RDONLY);
    Ok(cx.files()?.lock().insert(file, true)? as u64)
}

/// The `ioctl` commands of a file of nsfs, as `ns_ioctl` in fs/nsfs.c of Linux. rukernel has
/// only the user namespace and the PID namespace of the system, so these have no parent.
pub(crate) fn ioctl(cx: &Cx<'_>, kind: NsKind, id: u32, cmd: u32, arg: u64) -> SysResult {
    match cmd {
        // The owner of each namespace is the user namespace of the system, which has no owner.
        NS_GET_USERNS if kind == NsKind::User => Err(Errno::EPERM),
        NS_GET_USERNS => open_ns(cx, NsKind::User, 0),
        NS_GET_PARENT if matches!(kind, NsKind::Pid | NsKind::User) => Err(Errno::EPERM),
        NS_GET_PARENT => Err(Errno::EINVAL),
        NS_GET_NSTYPE => Ok(kind.clone_flag()),
        NS_GET_OWNER_UID if kind != NsKind::User => Err(Errno::EINVAL),
        NS_GET_OWNER_UID => {
            cx.write_val(arg, &0u32)?;
            Ok(0)
        }
        NS_GET_MNTNS_ID if kind != NsKind::Mnt => Err(Errno::EINVAL),
        NS_GET_MNTNS_ID => {
            cx.write_val(arg, &NsInode::ino(kind, id))?;
            Ok(0)
        }
        NS_GET_PID_FROM_PIDNS
        | NS_GET_TGID_FROM_PIDNS
        | NS_GET_PID_IN_PIDNS
        | NS_GET_TGID_IN_PIDNS => {
            if kind != NsKind::Pid {
                return Err(Errno::EINVAL);
            }
            // Each process is in the PID namespace of the system, so an ID is the same in each
            // namespace.
            let id = arg as i32;
            let thread = rk_proc::find_thread(id as rk_proc::Pid).ok_or(Errno::ESRCH)?;
            if matches!(cmd, NS_GET_TGID_FROM_PIDNS | NS_GET_TGID_IN_PIDNS) {
                return Ok(u64::from(thread.process().pid()));
            }
            Ok(id as u64)
        }
        _ => Err(Errno::ENOTTY),
    }
}

/// Puts `process` in the namespace `id` of the kind `kind`, other than a cgroup namespace, as
/// the `install` operations of Linux.
///
/// # Errors
///
/// Gives `EINVAL` for a user namespace: the caller is in the only one, as `userns_install`.
/// Gives `EPERM` without `CAP_SYS_ADMIN`, and also without `CAP_SYS_CHROOT` for a mount
/// namespace, as `mntns_install`.
pub(crate) fn install(cx: &Cx<'_>, process: &Process, kind: NsKind, id: u32) -> Result<(), Errno> {
    if kind == NsKind::User {
        return Err(Errno::EINVAL);
    }
    let cred = process.cred();
    if !cred.capable(cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    if kind == NsKind::Mnt {
        if !cred.capable(cap::SYS_CHROOT) {
            return Err(Errno::EPERM);
        }
        let ns = rk_proc::ns::mnt_ns(id).ok_or(Errno::EINVAL)?;
        cx.fs_shared()?.lock().set_namespace(ns);
    }
    // The caller is in the only namespace of the other kinds.
    Ok(())
}

//! The `ioctl` commands of the namespace files and the joins of `setns`, as fs/nsfs.c and
//! kernel/nsproxy.c of Linux.

use crate::cx::{Cx, SysResult};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_proc::Process;
use rk_vfs::cred::cap;
use rk_vfs::nsfs::{NsInode, NsKind};

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

/// The `ioctl` commands of a file of nsfs, as `ns_ioctl` in fs/nsfs.c of Linux. rukernel has
/// only the user namespace and the PID namespace of the system, so these have no parent.
pub(crate) fn ioctl(cx: &Cx<'_>, kind: NsKind, id: u32, cmd: u32, arg: u64) -> SysResult {
    match cmd {
        // rukernel has no user namespace files, as Linux without `CONFIG_USER_NS`, where
        // `ns_get_owner` gives `EPERM`.
        NS_GET_USERNS => Err(Errno::EPERM),
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

/// The ID of the IPC namespace of the caller, or 0 for a kernel task.
pub(crate) fn ipc_id() -> u32 {
    rk_proc::current_thread().map_or(0, |t| t.ipc_ns().id())
}

/// Removes the objects of the IPC namespace `id` when its last thread leaves it, as
/// `free_ipc_ns` of ipc/namespace.c of Linux.
fn exit_ipc_ns(id: u32) {
    crate::shm::exit_ns(id);
    crate::msg::exit_ns(id);
    crate::sem::exit_ns(id);
    crate::mqueue::exit_ns(id);
}

/// Connects the IPC namespaces of rk-proc to the objects of this crate.
pub(crate) fn init() {
    rk_proc::ns::on_ipc_exit(exit_ipc_ns);
}

/// A table of System V objects for each IPC namespace, as the `ids` of `struct ipc_namespace`
/// of Linux. The first namespace has a static table. The table of another namespace is made at
/// its first use. When the namespace stops, its table becomes empty and goes back to a free
/// list for the next namespace, so a reference to a table stays valid.
pub(crate) struct PerNs<T: 'static> {
    /// The table of the first namespace.
    init: SpinLock<T>,
    /// The tables of the other namespaces, by the ID of the namespace.
    others: SpinLock<BTreeMap<u32, &'static SpinLock<T>>>,
    /// The empty tables that no namespace uses.
    free: SpinLock<Vec<&'static SpinLock<T>>>,
    /// Makes an empty table.
    empty: fn() -> T,
}

impl<T: Send> PerNs<T> {
    /// Makes the tables. `init` is the table of the first namespace.
    pub(crate) const fn new(init: T, empty: fn() -> T) -> Self {
        Self {
            init: SpinLock::new(init),
            others: SpinLock::new(BTreeMap::new()),
            free: SpinLock::new(Vec::new()),
            empty,
        }
    }

    /// The table of the IPC namespace of the caller.
    pub(crate) fn get(&'static self) -> &'static SpinLock<T> {
        let id = ipc_id();
        if id == 0 {
            return &self.init;
        }
        if let Some(t) = self.others.lock().get(&id) {
            return t;
        }
        let table = self.free.lock().pop().unwrap_or_else(|| {
            alloc::boxed::Box::leak(alloc::boxed::Box::new(SpinLock::new((self.empty)())))
        });
        *self.others.lock().entry(id).or_insert(table)
    }

    /// The tables of all the namespaces.
    pub(crate) fn all(&'static self) -> Vec<&'static SpinLock<T>> {
        let mut v = alloc::vec![&self.init];
        v.extend(self.others.lock().values().copied());
        v
    }

    /// Empties the table of the namespace `id` that stops. The objects go after the locks are
    /// free.
    pub(crate) fn exit(&'static self, id: u32) {
        let Some(table) = self.others.lock().remove(&id) else { return };
        let old = core::mem::replace(&mut *table.lock(), (self.empty)());
        drop(old);
        self.free.lock().push(table);
    }
}

//! The `ioctl` commands of the namespace files and the joins of `setns`, as fs/nsfs.c and
//! kernel/nsproxy.c of Linux.

use crate::cx::{Cx, SysResult};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::open::O_RDONLY;
use rk_frame::sync::SpinLock;
use rk_proc::Process;
use rk_proc::pid_namespace::{self, PidNamespace};
use rk_vfs::Location;
use rk_vfs::cred::cap;
use rk_vfs::file::File;
use rk_vfs::inode::InodeRef;
use rk_vfs::nsfs::{NsInode, NsKind};
use rk_vfs::user_ns::{self, UserNs};

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

/// The `ioctl` commands of a file of nsfs, as `ns_ioctl` in fs/nsfs.c of Linux. The first user
/// namespace owns the namespaces of the other kinds.
pub(crate) fn ioctl(cx: &Cx<'_>, kind: NsKind, id: u32, cmd: u32, arg: u64) -> SysResult {
    match cmd {
        NS_GET_USERNS if kind == NsKind::User => user_owner(cx, id),
        NS_GET_USERNS => open_user_ns(cx, Some(user_ns::init().clone())),
        NS_GET_PARENT if kind == NsKind::Pid => pid_parent(cx, id),
        NS_GET_PARENT if kind == NsKind::User => user_owner(cx, id),
        NS_GET_PARENT => Err(Errno::EINVAL),
        NS_GET_NSTYPE => Ok(kind.clone_flag()),
        NS_GET_OWNER_UID if kind != NsKind::User => Err(Errno::EINVAL),
        NS_GET_OWNER_UID => {
            let ns = user_ns::by_id(id).ok_or(Errno::EINVAL)?;
            let me = cx.process().cred();
            let uid = me.user_ns.from_kid_munged(user_ns::IdKind::Uid, ns.owner());
            cx.write_val(arg, &uid)?;
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
            // The file keeps the namespace, so the search finds it.
            let ns = pid_namespace::by_id(id).ok_or(Errno::ESRCH)?;
            let nr = arg as i32;
            if nr <= 0 {
                return Err(Errno::ESRCH);
            }
            let thread = if matches!(cmd, NS_GET_PID_IN_PIDNS | NS_GET_TGID_IN_PIDNS) {
                cx.find_task_by_vpid(nr as u64)
            } else {
                pid_namespace::find_pid_ns(nr as rk_proc::Pid, ns.as_ref())
                    .and_then(rk_proc::find_thread)
            };
            let thread = thread.ok_or(Errno::ESRCH)?;
            let ret = match cmd {
                NS_GET_PID_FROM_PIDNS => cx.vnr(thread.tid()),
                NS_GET_TGID_FROM_PIDNS => cx.vnr(thread.process().pid()),
                NS_GET_PID_IN_PIDNS => pid_namespace::pid_nr_ns(thread.tid(), ns.as_ref()),
                _ => pid_namespace::pid_nr_ns(thread.process().pid(), ns.as_ref()),
            };
            if ret == 0 {
                return Err(Errno::ESRCH);
            }
            Ok(u64::from(ret))
        }
        _ => Err(Errno::ENOTTY),
    }
}

/// Opens the file of the parent of the user namespace `id`, for `NS_GET_USERNS` and
/// `NS_GET_PARENT`, as `userns_owner` and `ns_get_owner` of Linux.
///
/// # Errors
///
/// Gives `EPERM` for the first namespace and for a parent out of the view of the caller.
fn user_owner(cx: &Cx<'_>, id: u32) -> SysResult {
    let ns = user_ns::by_id(id).ok_or(Errno::EPERM)?;
    open_user_ns(cx, ns.parent().cloned())
}

/// Opens the file of the user namespace `ns`, if the caller sees it: it is the user namespace of
/// the caller or a namespace below it.
///
/// # Errors
///
/// Gives `EPERM` for `None` and for a namespace out of the view of the caller.
fn open_user_ns(cx: &Cx<'_>, ns: Option<Arc<UserNs>>) -> SysResult {
    let ns = ns.ok_or(Errno::EPERM)?;
    if !ns.is_in(&cx.process().cred().user_ns) {
        return Err(Errno::EPERM);
    }
    let file = File::open_inode(Location::detached(user_inode(ns)), O_RDONLY);
    Ok(cx.files()?.lock().insert(file, true)? as u64)
}

/// The inode of the user namespace `ns`. The inode keeps the namespace.
pub(crate) fn user_inode(ns: Arc<UserNs>) -> Arc<NsInode> {
    NsInode::with_hold(NsKind::User, ns.id(), ns)
}

/// Puts `process` in the user namespace `ns`, as `userns_install` of Linux. The process gets all
/// the capabilities in the namespace.
///
/// # Errors
///
/// Gives `EINVAL` for the namespace of the process, for a process with more than one thread or
/// a shared file system context, and `EPERM` without `CAP_SYS_ADMIN` in `ns`.
pub(crate) fn join_user_ns(cx: &Cx<'_>, process: &Process, ns: Arc<UserNs>) -> Result<(), Errno> {
    let cred = process.cred();
    if ns == cred.user_ns || process.threads().len() > 1 {
        return Err(Errno::EINVAL);
    }
    // The process and this function hold the context: a third holder shares it.
    if Arc::strong_count(&cx.fs_shared()?) > 2 {
        return Err(Errno::EINVAL);
    }
    if !cred.ns_capable(&ns, cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    process.set_cred(cred.in_user_ns(ns));
    Ok(())
}

/// Opens the file of the parent of the PID namespace `id`, for `NS_GET_PARENT`, as `pidns_get_parent`
/// of Linux. The caller must see the parent: it is the PID namespace of the caller or a
/// descendant of it.
///
/// # Errors
///
/// Gives `EPERM` for the first namespace and for a parent out of the view of the caller.
fn pid_parent(cx: &Cx<'_>, id: u32) -> SysResult {
    let ns = pid_namespace::by_id(id).flatten().ok_or(Errno::EPERM)?;
    let parent = ns.parent().cloned();
    if !pid_namespace::is_descendant(parent.as_ref(), cx.process().pid_ns()) {
        return Err(Errno::EPERM);
    }
    let file = File::open_inode(Location::detached(pid_inode(parent)), O_RDONLY);
    Ok(cx.files()?.lock().insert(file, true)? as u64)
}

/// The inode of the PID namespace `ns`. The inode keeps the namespace.
pub(crate) fn pid_inode(ns: Option<Arc<PidNamespace>>) -> Arc<NsInode> {
    match ns {
        Some(ns) => NsInode::with_hold(NsKind::Pid, ns.id(), ns),
        None => NsInode::new(NsKind::Pid, 0),
    }
}

/// The inode of the PID namespace for the children of `process`, as `pidns_for_children_get`
/// of Linux.
///
/// # Errors
///
/// Gives `ENOENT` for a new namespace whose init did not start yet.
pub(crate) fn pid_for_children_inode(process: &Process) -> Result<InodeRef, Errno> {
    let ns = process.pid_ns_for_children();
    if let Some(n) = &ns
        && !pid_namespace::same(ns.as_ref(), process.pid_ns())
        && !n.has_child_reaper()
    {
        return Err(Errno::ENOENT);
    }
    Ok(pid_inode(ns))
}

/// The inode of the namespace of the kind `kind` of `process`, as the links of `/proc/PID/ns`.
/// The inode of a user, network, UTS or IPC namespace keeps the namespace.
///
/// # Errors
///
/// Gives `ENOENT` for the mount namespace of a process without a file system context.
pub(crate) fn inode_of(process: &Process, kind: NsKind) -> Result<Arc<NsInode>, Errno> {
    Ok(match kind {
        NsKind::User => user_inode(process.cred().user_ns.clone()),
        NsKind::Net => {
            let net = process.net_ns();
            NsInode::with_hold(kind, net.id(), net)
        }
        NsKind::Uts => {
            let uts = process.uts_ns();
            NsInode::with_hold(kind, uts.id(), uts)
        }
        NsKind::Ipc => {
            let ipc = process.ipc_ns();
            NsInode::with_hold(kind, ipc.id(), ipc)
        }
        NsKind::Time => time_inode(process.time_ns()),
        NsKind::Pid => pid_inode(process.pid_ns().cloned()),
        _ => NsInode::new(kind, rk_proc::ns::ns_id(process, kind)?),
    })
}

/// The inode of the time namespace `ns`. The inode keeps the namespace.
pub(crate) fn time_inode(ns: Arc<rk_proc::timens::TimeNs>) -> Arc<NsInode> {
    NsInode::with_hold(NsKind::Time, ns.id(), ns)
}

/// Puts `process` in the namespace `id` of the kind `kind`, other than a cgroup namespace, as
/// the `install` operations of Linux.
///
/// # Errors
///
/// Gives the errors of [`join_user_ns`] for a user namespace. Gives `EPERM` without
/// `CAP_SYS_ADMIN`, and also without `CAP_SYS_CHROOT` for a mount namespace, as `mntns_install`.
pub(crate) fn install(cx: &Cx<'_>, process: &Process, kind: NsKind, id: u32) -> Result<(), Errno> {
    if kind == NsKind::User {
        // The file keeps the namespace, so the search finds it.
        return join_user_ns(cx, process, user_ns::by_id(id).ok_or(Errno::EINVAL)?);
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

//! The IDs of the namespaces of a process, for the files of nsfs (`rk_vfs::nsfs`), as
//! kernel/nscommon.c of Linux.
//!
//! The ID 0 is the first namespace of a kind. rukernel has more than one namespace for the mount,
//! the cgroup, the network, the UTS and the IPC kinds. A mount namespace gets an ID the first time
//! that a file names it.

use crate::process::{INIT_PID, Process, find_process};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use rk_abi::Errno;
use rk_frame::sync::{Once, SpinLock};
use rk_vfs::MountNamespace;
use rk_vfs::nsfs::NsKind;

/// The IDs of the mount namespaces other than the first one.
static MNT_IDS: SpinLock<Vec<(Weak<MountNamespace>, u32)>> = SpinLock::new(Vec::new());

/// The next ID for a mount namespace.
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

/// The first mount namespace: the namespace of init at the first call.
fn init_mnt() -> &'static Weak<MountNamespace> {
    static INIT: Once<Weak<MountNamespace>> = Once::new();
    INIT.call_once(|| {
        find_process(INIT_PID)
            .and_then(|p| p.fs())
            .map_or_else(Weak::new, |fs| Arc::downgrade(fs.lock().namespace()))
    })
}

/// The ID of the mount namespace `ns`. The first mount namespace has the ID 0.
pub fn mnt_id(ns: &Arc<MountNamespace>) -> u32 {
    if core::ptr::eq(init_mnt().as_ptr(), Arc::as_ptr(ns)) {
        return 0;
    }
    let mut ids = MNT_IDS.lock();
    ids.retain(|(w, _)| w.strong_count() > 0);
    if let Some((_, id)) = ids.iter().find(|(w, _)| core::ptr::eq(w.as_ptr(), Arc::as_ptr(ns))) {
        return *id;
    }
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    ids.push((Arc::downgrade(ns), id));
    id
}

/// The mount namespace with the ID `id`, while it exists.
pub fn mnt_ns(id: u32) -> Option<Arc<MountNamespace>> {
    if id == 0 {
        return init_mnt().upgrade();
    }
    MNT_IDS.lock().iter().find(|(_, i)| *i == id).and_then(|(w, _)| w.upgrade())
}

/// The ID of the namespace of the kind `kind` of `process`.
///
/// # Errors
///
/// Gives `ENOENT` for the mount namespace of a process that has no file system context.
pub fn ns_id(process: &Process, kind: NsKind) -> Result<u32, Errno> {
    Ok(match kind {
        NsKind::Mnt => {
            let fs = process.fs().ok_or(Errno::ENOENT)?;
            let ns = fs.lock().namespace().clone();
            mnt_id(&ns)
        }
        NsKind::Cgroup => process.cgroup_ns(),
        NsKind::Net => process.net_ns().id(),
        NsKind::Uts => process.uts_ns().id(),
        NsKind::Ipc => process.ipc_ns().id(),
        _ => 0,
    })
}

/// An IPC namespace, as `struct ipc_namespace` of Linux. The System V objects and the POSIX
/// message queues of a namespace are in rk-syscall, which keeps them by the ID of the namespace.
pub struct IpcNs {
    /// The ID of the namespace for nsfs. The first namespace has the ID 0.
    id: u32,
}

/// The IPC namespaces other than the first one, for `ipc_by_id`.
static IPC_LIVE: SpinLock<Vec<Weak<IpcNs>>> = SpinLock::new(Vec::new());

/// The next ID for an IPC namespace.
static IPC_NEXT_ID: AtomicU32 = AtomicU32::new(1);

/// The function that removes the objects of an IPC namespace that stops.
static IPC_EXIT: Once<fn(u32)> = Once::new();

/// Sets the function that removes the objects of an IPC namespace when it stops, as
/// `free_ipc_ns` of ipc/namespace.c of Linux does with `shm_exit_ns`, `msg_exit_ns` and
/// `sem_exit_ns`.
pub fn on_ipc_exit(f: fn(u32)) {
    IPC_EXIT.call_once(|| f);
}

/// The first IPC namespace, `init_ipc_ns` of Linux.
pub fn init_ipc() -> Arc<IpcNs> {
    static INIT: Once<Arc<IpcNs>> = Once::new();
    INIT.call_once(|| Arc::new(IpcNs { id: 0 })).clone()
}

/// Makes a new IPC namespace with no objects, as `create_ipc_ns` of Linux.
pub fn new_ipc() -> Arc<IpcNs> {
    let ns = Arc::new(IpcNs { id: IPC_NEXT_ID.fetch_add(1, Ordering::Relaxed) });
    let mut live = IPC_LIVE.lock();
    live.retain(|w| w.strong_count() > 0);
    live.push(Arc::downgrade(&ns));
    ns
}

/// The IPC namespace with the ID `id`, while it exists.
pub fn ipc_by_id(id: u32) -> Option<Arc<IpcNs>> {
    if id == 0 {
        return Some(init_ipc());
    }
    IPC_LIVE.lock().iter().filter_map(Weak::upgrade).find(|ns| ns.id == id)
}

impl IpcNs {
    /// The ID of the namespace.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Tells if this is the first namespace.
    pub fn is_init(&self) -> bool {
        self.id == 0
    }
}

impl Drop for IpcNs {
    fn drop(&mut self) {
        if let Some(f) = IPC_EXIT.get() {
            f(self.id);
        }
    }
}

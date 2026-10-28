//! The IDs of the namespaces of a process, for the files of nsfs (`rk_vfs::nsfs`), as
//! kernel/nscommon.c of Linux.
//!
//! The ID 0 is the first namespace of a kind. rukernel has more than one namespace only for the
//! mount and the cgroup kinds. A mount namespace gets an ID the first time that a file names it.

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

/// The ID of the mount namespace `ns`.
fn mnt_id(ns: &Arc<MountNamespace>) -> u32 {
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
        _ => 0,
    })
}

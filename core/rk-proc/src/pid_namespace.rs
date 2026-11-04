//! PID namespaces, as kernel/pid.c and kernel/pid_namespace.c of Linux.
//!
//! The kernel keeps one ID for each thread, process group and session: its ID in the first
//! namespace, the global ID. A thread in a namespace at the level N also has an ID in each
//! namespace from the level N up to the level 1, as the `numbers` of `struct pid`. Each namespace
//! keeps the map between its IDs and the global IDs. The system calls change an ID of the caller
//! namespace to a global ID, and a global ID to an ID of the caller namespace.
//!
//! The first namespace is `None` in the functions here, as `init_pid_ns`.
//!
//! An entry of a map stays after its global ID is free, until the kernel gives the global ID
//! again. A process group or a session keeps its ID after its leader ends, as a `struct pid` of
//! Linux stays while a task uses it. A local ID is in use while its global ID is in use.

use crate::process::{Pid, Process};
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_frame::task::WaitQueue;

/// The deepest level of a namespace, `MAX_PID_NS_LEVEL` of Linux.
pub const MAX_PID_NS_LEVEL: u32 = 32;

/// The lowest ID after a wrap, `RESERVED_PIDS` of Linux.
const RESERVED_PIDS: Pid = 300;

/// A PID namespace, as `struct pid_namespace` of Linux.
pub struct PidNamespace {
    /// The ID of the namespace for nsfs. The first namespace has the ID 0.
    id: u32,
    /// The level: 1 for a child of the first namespace.
    level: u32,
    /// The parent, or `None` for a child of the first namespace.
    parent: Option<Arc<PidNamespace>>,
    inner: SpinLock<Inner>,
    /// `zap_pid_ns_processes` waits here until the other processes of the namespace are gone.
    wait: WaitQueue,
}

struct Inner {
    /// The global ID of each local ID.
    to_global: BTreeMap<Pid, Pid>,
    /// The local ID of each global ID.
    to_local: BTreeMap<Pid, Pid>,
    /// The last local ID that the namespace gave, `ns_last_pid`.
    last: Pid,
    /// The init of the namespace, `child_reaper`: the process with the ID 1.
    reaper: Weak<Process>,
    /// The namespace can take new processes, `PIDNS_ADDING`. It stops when its init ends.
    adding: bool,
}

/// The namespaces other than the first one, for `by_id` and `forget`.
static LIVE: SpinLock<Vec<Weak<PidNamespace>>> = SpinLock::new(Vec::new());

/// The next ID for a namespace.
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

/// Makes a child namespace of `parent`, as `create_pid_namespace` of Linux.
///
/// # Errors
///
/// Gives `ENOSPC` if the new namespace is deeper than `MAX_PID_NS_LEVEL`.
pub fn create_pid_namespace(
    parent: Option<&Arc<PidNamespace>>,
) -> Result<Arc<PidNamespace>, Errno> {
    let level = parent.map_or(0, |p| p.level) + 1;
    if level > MAX_PID_NS_LEVEL {
        return Err(Errno::ENOSPC);
    }
    let ns = Arc::new(PidNamespace {
        id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        level,
        parent: parent.cloned(),
        inner: SpinLock::new(Inner {
            to_global: BTreeMap::new(),
            to_local: BTreeMap::new(),
            last: 0,
            reaper: Weak::new(),
            adding: true,
        }),
        wait: WaitQueue::new(),
    });
    let mut live = LIVE.lock();
    live.retain(|w| w.strong_count() > 0);
    live.push(Arc::downgrade(&ns));
    Ok(ns)
}

/// The namespace with the ID `id`, while it exists. The ID 0 is the first namespace, which is
/// `Some(None)`.
pub fn by_id(id: u32) -> Option<Option<Arc<PidNamespace>>> {
    if id == 0 {
        return Some(None);
    }
    LIVE.lock().iter().filter_map(Weak::upgrade).find(|ns| ns.id == id).map(Some)
}

/// The nsfs ID of the namespace `ns`.
pub fn ns_id(ns: Option<&Arc<PidNamespace>>) -> u32 {
    ns.map_or(0, |ns| ns.id)
}

/// The level of the namespace `ns`.
pub fn ns_level(ns: Option<&Arc<PidNamespace>>) -> u32 {
    ns.map_or(0, |ns| ns.level)
}

/// Tells if `a` and `b` are the same namespace.
pub fn same(a: Option<&Arc<PidNamespace>>, b: Option<&Arc<PidNamespace>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    }
}

/// Tells if `ns` is `ancestor` or a descendant of it.
pub fn is_descendant(ns: Option<&Arc<PidNamespace>>, ancestor: Option<&Arc<PidNamespace>>) -> bool {
    let target = ns_level(ancestor);
    let mut cur = ns;
    while ns_level(cur) > target {
        cur = cur.and_then(|n| n.parent.as_ref());
    }
    same(cur, ancestor)
}

/// The ID of the global ID `pid` in the namespace `ns`, or 0 if `pid` is not in the namespace,
/// as `pid_nr_ns` of Linux.
pub fn pid_nr_ns(pid: Pid, ns: Option<&Arc<PidNamespace>>) -> Pid {
    match ns {
        None => pid,
        Some(_) if pid == 0 => 0,
        Some(ns) => ns.inner.lock().to_local.get(&pid).copied().unwrap_or(0),
    }
}

/// The global ID of the ID `nr` of the namespace `ns`, or `None` if no thread, process group or
/// session of the namespace has it, as `find_pid_ns` of Linux. The caller then finds the object
/// with the global ID.
pub fn find_pid_ns(nr: Pid, ns: Option<&Arc<PidNamespace>>) -> Option<Pid> {
    match ns {
        None => (nr != 0).then_some(nr),
        Some(ns) => {
            let inner = ns.inner.lock();
            let pid = *inner.to_global.get(&nr)?;
            (inner.to_local.get(&pid) == Some(&nr)).then_some(pid)
        }
    }
}

/// The IDs of the global ID `pid` from the namespace `from` down to the namespace `ns` that has
/// it, for the `NSpid` lines of `/proc/PID/status`. `ns` is the deepest namespace of `pid`.
pub fn numbers(
    pid: Pid,
    ns: Option<&Arc<PidNamespace>>,
    from: Option<&Arc<PidNamespace>>,
) -> Vec<Pid> {
    let mut out = Vec::new();
    let mut cur = ns;
    loop {
        out.push(pid_nr_ns(pid, cur));
        if same(cur, from) || cur.is_none() {
            break;
        }
        cur = cur.and_then(|n| n.parent.as_ref());
    }
    out.reverse();
    out
}

/// Removes the old entries of the global ID `pid` in each namespace, before the kernel gives the
/// ID again.
pub(crate) fn forget(pid: Pid) {
    let live: Vec<Arc<PidNamespace>> = LIVE.lock().iter().filter_map(Weak::upgrade).collect();
    for ns in live {
        let mut inner = ns.inner.lock();
        if let Some(nr) = inner.to_local.remove(&pid)
            && inner.to_global.get(&nr) == Some(&pid)
        {
            inner.to_global.remove(&nr);
        }
    }
}

impl PidNamespace {
    /// The ID of the namespace for nsfs.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// The level of the namespace.
    pub fn level(&self) -> u32 {
        self.level
    }

    /// The parent namespace, or `None` for a child of the first namespace.
    pub fn parent(&self) -> Option<&Arc<PidNamespace>> {
        self.parent.as_ref()
    }

    /// The init of the namespace, while it exists.
    pub fn child_reaper(&self) -> Option<Arc<Process>> {
        self.inner.lock().reaper.upgrade()
    }

    /// Tells if the init of the namespace started, so that `pid_for_children` has a file.
    pub fn has_child_reaper(&self) -> bool {
        self.inner.lock().reaper.strong_count() > 0
    }

    /// Tells if `process` is the init of the namespace.
    pub(crate) fn is_child_reaper(&self, process: &Process) -> bool {
        core::ptr::eq(self.inner.lock().reaper.as_ptr(), process)
    }

    pub(crate) fn set_child_reaper(&self, process: &Arc<Process>) {
        self.inner.lock().reaper = Arc::downgrade(process);
    }

    /// The last ID that the namespace gave, `ns_last_pid`.
    pub fn last_pid(&self) -> Pid {
        self.inner.lock().last
    }

    /// Makes `pid + 1` the next ID to try, for a write of `ns_last_pid`.
    pub fn set_last_pid(&self, pid: Pid) {
        self.inner.lock().last = pid;
    }

    /// Stops new processes in the namespace, as `disable_pid_allocation` of Linux.
    pub(crate) fn disable_pid_allocation(&self) {
        self.inner.lock().adding = false;
    }

    /// The wait queue of `zap_pid_ns_processes`.
    pub(crate) fn wait(&self) -> &WaitQueue {
        &self.wait
    }

    /// Gives a local ID in this namespace to the global ID `pid`, as the loop of `alloc_pid` in
    /// kernel/pid.c of Linux. `want` is the ID of `clone3` with `set_tid`, or 0. `used` tells if
    /// a global ID is in use. The caller holds the lock of the table, so that no other
    /// allocation runs at the same time.
    ///
    /// # Errors
    ///
    /// Gives `ENOMEM` if the init of the namespace ended, `EEXIST` if `want` is in use, `EINVAL`
    /// if `want` is not 1 in a namespace without init, and `EAGAIN` if no ID is free.
    pub(crate) fn alloc(
        &self,
        pid: Pid,
        want: Pid,
        max: Pid,
        used: impl Fn(Pid) -> bool,
    ) -> Result<Pid, Errno> {
        if !self.inner.lock().adding {
            return Err(Errno::ENOMEM);
        }
        // An entry is in use if its global ID is in use and still names this local ID.
        let busy = |nr: Pid| {
            let old = {
                let inner = self.inner.lock();
                inner.to_global.get(&nr).copied().filter(|g| inner.to_local.get(g) == Some(&nr))
            };
            old.is_some_and(&used)
        };
        let nr = if want != 0 {
            if busy(want) {
                return Err(Errno::EEXIST);
            }
            want
        } else {
            let mut found = None;
            let mut next = self.inner.lock().last + 1;
            for _ in 0..max {
                if next >= max {
                    next = RESERVED_PIDS.min(max - 1);
                }
                if !busy(next) {
                    found = Some(next);
                    break;
                }
                next += 1;
            }
            found.ok_or(Errno::EAGAIN)?
        };
        let mut inner = self.inner.lock();
        // The first process of a namespace must have the ID 1, as `alloc_pid` checks
        // `child_reaper` for `set_tid`.
        if want != 0 && want != 1 && inner.reaper.strong_count() == 0 {
            return Err(Errno::EINVAL);
        }
        if let Some(old) = inner.to_global.insert(nr, pid)
            && inner.to_local.get(&old) == Some(&nr)
        {
            inner.to_local.remove(&old);
        }
        inner.to_local.insert(pid, nr);
        inner.last = nr;
        Ok(nr)
    }

    /// Removes the local ID of the global ID `pid`, after a failed allocation.
    pub(crate) fn free(&self, pid: Pid) {
        let mut inner = self.inner.lock();
        if let Some(nr) = inner.to_local.remove(&pid)
            && inner.to_global.get(&nr) == Some(&pid)
        {
            inner.to_global.remove(&nr);
        }
    }
}

impl core::fmt::Debug for PidNamespace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PidNamespace").field("id", &self.id).field("level", &self.level).finish()
    }
}

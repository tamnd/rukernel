//! User namespaces, as kernel/user_namespace.c and kernel/ucount.c of Linux.
//!
//! The credentials keep the kernel IDs: the IDs of the first user namespace. A user namespace
//! has a map for the user IDs, the group IDs and the project IDs. Each extent of a map gives a
//! range of IDs in the namespace and the first kernel ID of the range, as `struct uid_gid_map`
//! of Linux keeps it after `map_write`. A process sees the kernel IDs through the maps of its
//! namespace, and an ID that is not in the map is the overflow ID 65534.
//!
//! The first namespace maps all the IDs to themselves. A new namespace has empty maps, and a
//! write to `/proc/PID/uid_map`, `gid_map` or `projid_map` sets each map one time.

use crate::cred::{Cred, cap};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use rk_abi::Errno;
use rk_frame::sync::{Once, SpinLock};

/// An ID that has no value, `INVALID_UID` of Linux.
pub const INVALID_ID: u32 = u32::MAX;

/// The ID that a process sees for a kernel ID that its namespace does not map,
/// `kernel.overflowuid` and `kernel.overflowgid` of Linux.
pub const OVERFLOW_ID: u32 = 65534;

/// The most extents in a map, `UID_GID_MAP_MAX_EXTENTS` of Linux.
pub const MAX_EXTENTS: usize = 340;

/// The deepest level of a user namespace. The first namespace has the level 0, and Linux
/// refuses a new namespace below a namespace of a level above 32.
pub const MAX_LEVEL: u32 = 33;

/// One range of a map: `count` IDs from `first` in the namespace go to the IDs from
/// `lower_first` in the first namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    /// The first ID in the namespace.
    pub first: u32,
    /// The first kernel ID.
    pub lower_first: u32,
    /// The number of IDs.
    pub count: u32,
}

impl Extent {
    /// The last ID in the namespace.
    fn last(&self) -> u32 {
        self.first + (self.count - 1)
    }

    /// The last kernel ID.
    fn lower_last(&self) -> u32 {
        self.lower_first + (self.count - 1)
    }
}

/// A map of IDs, `struct uid_gid_map` of Linux.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdMap {
    extents: Vec<Extent>,
}

impl IdMap {
    /// The map of the first namespace: all the IDs but `INVALID_ID` go to themselves.
    fn identity() -> Self {
        Self { extents: alloc::vec![Extent { first: 0, lower_first: 0, count: u32::MAX }] }
    }

    /// The extents, in the order of the IDs in the namespace.
    pub fn extents(&self) -> &[Extent] {
        &self.extents
    }

    /// The lower ID of the `count` IDs from `id` in the namespace, if one extent has them all,
    /// as `map_id_range_down` of Linux.
    pub fn down_range(&self, id: u32, count: u32) -> Option<u32> {
        let last = id.checked_add(count.checked_sub(1)?)?;
        self.extents
            .iter()
            .find(|e| id >= e.first && last <= e.last())
            .map(|e| id - e.first + e.lower_first)
    }

    /// The lower ID of the ID `id` in the namespace, as `map_id_down` of Linux.
    pub fn down(&self, id: u32) -> Option<u32> {
        self.down_range(id, 1)
    }

    /// The ID in the namespace of the lower ID `id`, as `map_id_up` of Linux.
    pub fn up(&self, id: u32) -> Option<u32> {
        self.extents
            .iter()
            .find(|e| id >= e.lower_first && id <= e.lower_last())
            .map(|e| id - e.lower_first + e.first)
    }
}

/// The kinds of map of a namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdKind {
    /// The user IDs, `/proc/PID/uid_map`.
    Uid,
    /// The group IDs, `/proc/PID/gid_map`.
    Gid,
    /// The project IDs, `/proc/PID/projid_map`.
    Projid,
}

impl IdKind {
    fn index(self) -> usize {
        self as usize
    }
}

/// The kinds of object that a user namespace counts for each user, `enum ucount_type` of Linux.
/// Each one has a `user.max_*` sysctl.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum UcountKind {
    /// `user.max_user_namespaces`.
    User,
    /// `user.max_pid_namespaces`.
    Pid,
    /// `user.max_uts_namespaces`.
    Uts,
    /// `user.max_ipc_namespaces`.
    Ipc,
    /// `user.max_net_namespaces`.
    Net,
    /// `user.max_mnt_namespaces`.
    Mnt,
    /// `user.max_cgroup_namespaces`.
    Cgroup,
    /// `user.max_time_namespaces`.
    Time,
    /// `user.max_inotify_instances`.
    InotifyInstances,
    /// `user.max_inotify_watches`.
    InotifyWatches,
    /// `user.max_fanotify_groups`.
    FanotifyGroups,
    /// `user.max_fanotify_marks`.
    FanotifyMarks,
}

/// The number of kinds of [`UcountKind`].
const UCOUNT_KINDS: usize = 12;

impl UcountKind {
    /// All the kinds, in the order of their sysctls.
    pub const ALL: [Self; UCOUNT_KINDS] = [
        Self::User,
        Self::Pid,
        Self::Uts,
        Self::Ipc,
        Self::Net,
        Self::Mnt,
        Self::Cgroup,
        Self::Time,
        Self::InotifyInstances,
        Self::InotifyWatches,
        Self::FanotifyGroups,
        Self::FanotifyMarks,
    ];

    /// The name of the sysctl in `/proc/sys/user`.
    pub fn name(self) -> &'static str {
        match self {
            Self::User => "max_user_namespaces",
            Self::Pid => "max_pid_namespaces",
            Self::Uts => "max_uts_namespaces",
            Self::Ipc => "max_ipc_namespaces",
            Self::Net => "max_net_namespaces",
            Self::Mnt => "max_mnt_namespaces",
            Self::Cgroup => "max_cgroup_namespaces",
            Self::Time => "max_time_namespaces",
            Self::InotifyInstances => "max_inotify_instances",
            Self::InotifyWatches => "max_inotify_watches",
            Self::FanotifyGroups => "max_fanotify_groups",
            Self::FanotifyMarks => "max_fanotify_marks",
        }
    }

    /// The kind of the sysctl `name` of `/proc/sys/user`.
    pub fn by_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }
}

/// A user namespace, `struct user_namespace` of Linux.
pub struct UserNs {
    parent: Option<Arc<UserNs>>,
    level: u32,
    /// The effective user ID of the process that made the namespace, a kernel ID.
    owner: u32,
    /// The effective group ID of the process that made the namespace, a kernel ID.
    group: u32,
    /// The ID of the namespace for nsfs. The first namespace has the ID 0.
    id: u32,
    /// The user, group and project maps. Each one is set one time.
    maps: [Once<IdMap>; 3],
    /// `setgroups` can work in the namespace, `USERNS_SETGROUPS_ALLOWED` of Linux.
    setgroups_allowed: AtomicBool,
    /// The process that made the namespace had `CAP_SETFCAP`, so a map can give it the root
    /// of the namespace.
    parent_could_setfcap: bool,
    /// The `user.max_*` limits of the namespace.
    max: [AtomicU32; UCOUNT_KINDS],
    /// The counts of the objects of each user and kind in the namespace and below it.
    counts: SpinLock<BTreeMap<(u32, UcountKind), u32>>,
    /// The count of this namespace in its parent, which goes when the namespace stops.
    _charge: Option<Charge>,
}

impl core::fmt::Debug for UserNs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "UserNs({})", self.id)
    }
}

/// Two namespaces are equal if they are the same namespace.
impl PartialEq for UserNs {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self, other)
    }
}

impl Eq for UserNs {}

/// The user namespaces other than the first one, for [`by_id`].
static LIVE: SpinLock<Vec<Weak<UserNs>>> = SpinLock::new(Vec::new());

/// The next ID for a user namespace.
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

/// The lock of the map and `setgroups` writes, `userns_state_mutex` of Linux.
static STATE: SpinLock<()> = SpinLock::new(());

/// The first limit of each kind in the first namespace. The namespaces are half of
/// `kernel.threads-max`, as `fork_init` of Linux sets them.
fn init_max(kind: UcountKind) -> u32 {
    match kind {
        UcountKind::InotifyInstances | UcountKind::FanotifyGroups => 128,
        UcountKind::InotifyWatches | UcountKind::FanotifyMarks => 8192,
        _ => {
            #[cfg(target_os = "none")]
            let threads = (rk_frame::mm::frame_stats().total / 32).max(20) as u32;
            #[cfg(not(target_os = "none"))]
            let threads = 16384;
            threads / 2
        }
    }
}

/// The first user namespace, `init_user_ns` of Linux.
pub fn init() -> &'static Arc<UserNs> {
    static INIT: Once<Arc<UserNs>> = Once::new();
    INIT.call_once(|| {
        let maps = [Once::new(), Once::new(), Once::new()];
        for m in &maps {
            m.call_once(IdMap::identity);
        }
        Arc::new(UserNs {
            parent: None,
            level: 0,
            owner: 0,
            group: 0,
            id: 0,
            maps,
            setgroups_allowed: AtomicBool::new(true),
            parent_could_setfcap: true,
            max: UcountKind::ALL.map(|k| AtomicU32::new(init_max(k))),
            counts: SpinLock::new(BTreeMap::new()),
            _charge: None,
        })
    })
}

/// The user namespace with the ID `id`, while it exists.
pub fn by_id(id: u32) -> Option<Arc<UserNs>> {
    if id == 0 {
        return Some(init().clone());
    }
    // The namespaces that the walk holds go after the lock, because the drop of the last one
    // takes the lock.
    let held: Vec<Arc<UserNs>> = LIVE.lock().iter().filter_map(Weak::upgrade).collect();
    held.into_iter().find(|ns| ns.id == id)
}

impl UserNs {
    /// The ID of the namespace for nsfs.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// The parent namespace, or `None` for the first one.
    pub fn parent(&self) -> Option<&Arc<UserNs>> {
        self.parent.as_ref()
    }

    /// The level: 0 for the first namespace, 1 for its children.
    pub fn level(&self) -> u32 {
        self.level
    }

    /// The effective user ID of the process that made the namespace, a kernel ID.
    pub fn owner(&self) -> u32 {
        self.owner
    }

    /// The effective group ID of the process that made the namespace, a kernel ID.
    pub fn group(&self) -> u32 {
        self.group
    }

    /// Tells if this is the first namespace.
    pub fn is_init(&self) -> bool {
        self.parent.is_none()
    }

    /// The map of the kind `kind`, if it is set.
    pub fn map(&self, kind: IdKind) -> Option<&IdMap> {
        self.maps[kind.index()].get()
    }

    /// The kernel ID of the ID `id` of the kind `kind` in the namespace, as `make_kuid` of
    /// Linux, or `INVALID_ID` if the namespace does not map it.
    pub fn make_kid(&self, kind: IdKind, id: u32) -> u32 {
        self.map(kind).and_then(|m| m.down(id)).unwrap_or(INVALID_ID)
    }

    /// The ID in the namespace of the kernel ID `kid` of the kind `kind`, as `from_kuid` of
    /// Linux, or `INVALID_ID` if the namespace does not map it.
    pub fn from_kid(&self, kind: IdKind, kid: u32) -> u32 {
        if kid == INVALID_ID {
            return INVALID_ID;
        }
        self.map(kind).and_then(|m| m.up(kid)).unwrap_or(INVALID_ID)
    }

    /// The ID in the namespace of the kernel ID `kid`, or the overflow ID if the namespace does
    /// not map it, as `from_kuid_munged` of Linux.
    pub fn from_kid_munged(&self, kind: IdKind, kid: u32) -> u32 {
        match self.from_kid(kind, kid) {
            INVALID_ID => OVERFLOW_ID,
            id => id,
        }
    }

    /// The kernel user ID of the user ID `uid` of the namespace, or `INVALID_ID`.
    pub fn make_kuid(&self, uid: u32) -> u32 {
        self.make_kid(IdKind::Uid, uid)
    }

    /// The kernel group ID of the group ID `gid` of the namespace, or `INVALID_ID`.
    pub fn make_kgid(&self, gid: u32) -> u32 {
        self.make_kid(IdKind::Gid, gid)
    }

    /// Tells if the namespace maps the kernel user ID `kuid`, as `kuid_has_mapping` of Linux.
    pub fn has_uid(&self, kuid: u32) -> bool {
        self.from_kid(IdKind::Uid, kuid) != INVALID_ID
    }

    /// Tells if the namespace maps the kernel group ID `kgid`, as `kgid_has_mapping` of Linux.
    pub fn has_gid(&self, kgid: u32) -> bool {
        self.from_kid(IdKind::Gid, kgid) != INVALID_ID
    }

    /// Tells if `self` is `ns` or a namespace below it, as `in_userns` of Linux.
    pub fn is_in(&self, ns: &UserNs) -> bool {
        let mut p = Some(self);
        while let Some(n) = p {
            if n == ns {
                return true;
            }
            if n.level <= ns.level {
                return false;
            }
            p = n.parent.as_deref();
        }
        false
    }

    /// Tells if `setgroups` can work in the namespace, as `userns_may_setgroups` of Linux: the
    /// group map is set, and `/proc/PID/setgroups` is not `deny`.
    pub fn may_setgroups(&self) -> bool {
        let _lock = STATE.lock();
        self.map(IdKind::Gid).is_some() && self.setgroups_allowed.load(Ordering::Relaxed)
    }

    /// The `user.max_*` limit of the kind `kind`.
    pub fn max(&self, kind: UcountKind) -> u32 {
        self.max[kind as usize].load(Ordering::Relaxed)
    }

    /// Sets the `user.max_*` limit of the kind `kind`.
    pub fn set_max(&self, kind: UcountKind, value: u32) {
        self.max[kind as usize].store(value, Ordering::Relaxed);
    }

    /// The count of the objects of the kind `kind` of the user `uid` in the namespace.
    pub fn count(&self, uid: u32, kind: UcountKind) -> u32 {
        self.counts.lock().get(&(uid, kind)).copied().unwrap_or(0)
    }
}

impl Drop for UserNs {
    fn drop(&mut self) {
        let mut live = LIVE.lock();
        live.retain(|w| w.strong_count() > 0);
    }
}

/// The count of one object in a namespace and in the namespaces above it, as `struct ucounts`
/// of Linux. The count goes when the value goes.
#[derive(Debug)]
pub struct Charge {
    ns: Arc<UserNs>,
    uid: u32,
    kind: UcountKind,
}

/// The namespaces and users of a count: the user `uid` in `ns`, then the owner of each
/// namespace in its parent, as the `ns->ucounts` chain of Linux.
fn chain(ns: &Arc<UserNs>, uid: u32) -> Vec<(Arc<UserNs>, u32)> {
    let mut out = alloc::vec![(ns.clone(), uid)];
    let mut n = ns.clone();
    while let Some(p) = n.parent.clone() {
        out.push((p.clone(), n.owner));
        n = p;
    }
    out
}

/// Counts one object of the kind `kind` of the user `uid` in `ns`, as `inc_ucount` of Linux.
/// Gives `None` if the count of the user in a namespace of the chain gets above its limit.
pub fn charge(ns: &Arc<UserNs>, uid: u32, kind: UcountKind) -> Option<Charge> {
    let links = chain(ns, uid);
    for (i, (n, u)) in links.iter().enumerate() {
        let mut counts = n.counts.lock();
        let c = counts.entry((*u, kind)).or_insert(0);
        if *c >= n.max(kind) {
            drop(counts);
            uncharge(&links[..i], kind);
            return None;
        }
        *c += 1;
    }
    Some(Charge { ns: ns.clone(), uid, kind })
}

/// Takes away one object of the kind `kind` from each link of `links`.
fn uncharge(links: &[(Arc<UserNs>, u32)], kind: UcountKind) {
    for (n, u) in links {
        let mut counts = n.counts.lock();
        if let Some(c) = counts.get_mut(&(*u, kind)) {
            *c -= 1;
            if *c == 0 {
                counts.remove(&(*u, kind));
            }
        }
    }
}

impl Charge {
    /// Counts one object of the kind `kind` for the same user in the same namespace, as
    /// `inc_ucount` of Linux with the `ucounts` of an object. Gives `None` at a limit.
    pub fn again(&self, kind: UcountKind) -> Option<Charge> {
        charge(&self.ns, self.uid, kind)
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        uncharge(&chain(&self.ns, self.uid), self.kind);
    }
}

/// Makes a new user namespace below the namespace of `cred`, and gives the credentials of the
/// process in it, as `create_user_ns` and `set_cred_user_ns` of Linux. The owner is the
/// effective user of `cred`. The process has all the capabilities in the new namespace.
///
/// # Errors
///
/// Gives `ENOSPC` if the namespace is too deep or the user has too many namespaces,
/// `EPERM` if the parent does not map the effective user or group, and the error of the
/// `userns_create` hook of a security module.
pub fn create(cred: &Cred) -> Result<Cred, Errno> {
    let parent = &cred.user_ns;
    if parent.level >= MAX_LEVEL {
        return Err(Errno::ENOSPC);
    }
    let charge = self::charge(parent, cred.euid, UcountKind::User).ok_or(Errno::ENOSPC)?;
    if !parent.has_uid(cred.euid) || !parent.has_gid(cred.egid) {
        return Err(Errno::EPERM);
    }
    let ns = Arc::new(UserNs {
        parent: Some(parent.clone()),
        level: parent.level + 1,
        owner: cred.euid,
        group: cred.egid,
        id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        maps: [Once::new(), Once::new(), Once::new()],
        setgroups_allowed: AtomicBool::new(parent.setgroups_allowed.load(Ordering::Relaxed)),
        parent_could_setfcap: cred.cap_effective & cap::bit(cap::SETFCAP) != 0,
        max: UcountKind::ALL.map(|_| AtomicU32::new(i32::MAX as u32)),
        counts: SpinLock::new(BTreeMap::new()),
        _charge: Some(charge),
    });
    let new = cred.in_user_ns(ns.clone());
    crate::security::userns_create(cred, &new)?;
    {
        let mut live = LIVE.lock();
        live.retain(|w| w.strong_count() > 0);
        live.push(Arc::downgrade(&ns));
    }
    Ok(new)
}

/// Parses the text of a write to a map file into extents, as the loop of `map_write` of Linux:
/// one extent of three numbers on each line.
fn parse_map(text: &[u8]) -> Result<Vec<Extent>, Errno> {
    let text = core::str::from_utf8(text).map_err(|_| Errno::EINVAL)?;
    let mut out: Vec<Extent> = Vec::new();
    let lines: Vec<&str> = text.strip_suffix('\n').unwrap_or(text).split('\n').collect();
    for (i, line) in lines.iter().enumerate() {
        let mut words = line.split_ascii_whitespace();
        let mut num = || -> Result<u32, Errno> {
            let w = words.next().ok_or(Errno::EINVAL)?;
            w.parse::<u32>().map_err(|_| Errno::EINVAL)
        };
        let (first, lower_first, count) = (num()?, num()?, num()?);
        // The numbers are apart, and nothing comes after the third one.
        if words.next().is_some() || !line.starts_with(|c: char| c.is_ascii_digit()) {
            return Err(Errno::EINVAL);
        }
        if first == INVALID_ID || lower_first == INVALID_ID {
            return Err(Errno::EINVAL);
        }
        if count == 0
            || first.checked_add(count).is_none()
            || lower_first.checked_add(count).is_none()
        {
            return Err(Errno::EINVAL);
        }
        let e = Extent { first, lower_first, count };
        let overlap = out.iter().any(|o| {
            (e.first <= o.last() && o.first <= e.last())
                || (e.lower_first <= o.lower_last() && o.lower_first <= e.lower_last())
        });
        if overlap {
            return Err(Errno::EINVAL);
        }
        if out.len() + 1 == MAX_EXTENTS && i + 1 < lines.len() {
            return Err(Errno::EINVAL);
        }
        out.push(e);
    }
    if out.is_empty() {
        return Err(Errno::EINVAL);
    }
    Ok(out)
}

/// The capability that a map of the kind `kind` needs, `cap_setid` of `map_write`.
fn setid_cap(kind: IdKind) -> Option<u32> {
    match kind {
        IdKind::Uid => Some(cap::SETUID),
        IdKind::Gid => Some(cap::SETGID),
        IdKind::Projid => None,
    }
}

/// Tells if `cred` can set a map that gives the kernel root, as `verify_root_map` of Linux.
/// The process needs `CAP_SETFCAP`, because the namespace could else write file capabilities
/// that work outside.
fn root_map_permitted(cred: &Cred, ns: &UserNs) -> bool {
    match ns.parent.as_deref() {
        None => false,
        Some(_) if *cred.user_ns == *ns => ns.parent_could_setfcap,
        Some(parent) => cred.ns_capable(parent, cap::SETFCAP),
    }
}

/// Tells if `cred` can set the map `extents` of the kind `kind` of `ns`, as
/// `new_idmap_permitted` of Linux. The lower IDs of `extents` are IDs of the parent namespace.
fn idmap_permitted(cred: &Cred, ns: &UserNs, kind: IdKind, extents: &[Extent]) -> bool {
    let Some(parent) = ns.parent.as_deref() else { return false };
    // The owner can map its own effective ID, and its effective group if `setgroups` is denied.
    if let [e] = extents
        && e.count == 1
        && ns.owner == cred.euid
    {
        match kind {
            IdKind::Uid if parent.make_kuid(e.lower_first) == cred.euid => return true,
            IdKind::Gid
                if !ns.setgroups_allowed.load(Ordering::Relaxed)
                    && parent.make_kgid(e.lower_first) == cred.egid =>
            {
                return true;
            }
            _ => {}
        }
    }
    match setid_cap(kind) {
        None => true,
        Some(c) => cred.ns_capable(parent, c),
    }
}

/// Writes the map of the kind `kind` of `ns` from the text `text` that `cred` writes at the
/// offset `offset` of `/proc/PID/uid_map`, `gid_map` or `projid_map`, as `proc_uid_map_write`
/// and `map_write` of Linux.
///
/// # Errors
///
/// Gives `EPERM` for the first namespace, for a writer that is not in the namespace or its
/// parent, for a map that is set already, for a writer without `CAP_SYS_ADMIN` in the
/// namespace, and for IDs that the writer may not map or that the parent does not map. Gives
/// `EINVAL` for a write that is not at the offset 0 or is a page or more, and for a text that
/// is not a valid map.
pub fn write_map(
    ns: &Arc<UserNs>,
    kind: IdKind,
    cred: &Cred,
    offset: u64,
    text: &[u8],
) -> Result<(), Errno> {
    let Some(parent) = ns.parent.as_ref() else { return Err(Errno::EPERM) };
    if cred.user_ns != *ns && cred.user_ns != *parent {
        return Err(Errno::EPERM);
    }
    if offset != 0 || text.len() >= 4096 {
        return Err(Errno::EINVAL);
    }
    let _lock = STATE.lock();
    let slot = &ns.maps[kind.index()];
    if slot.get().is_some() {
        return Err(Errno::EPERM);
    }
    if setid_cap(kind).is_some() && !cred.ns_capable(ns, cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    let mut extents = parse_map(text)?;
    if !idmap_permitted(cred, ns, kind, &extents) {
        return Err(Errno::EPERM);
    }
    let parent_map = parent.map(kind).ok_or(Errno::EPERM)?;
    for e in &mut extents {
        e.lower_first = parent_map.down_range(e.lower_first, e.count).ok_or(Errno::EPERM)?;
    }
    if kind == IdKind::Uid
        && extents.iter().any(|e| e.lower_first == 0)
        && !root_map_permitted(cred, ns)
    {
        return Err(Errno::EPERM);
    }
    extents.sort_by_key(|e| e.first);
    slot.call_once(|| IdMap { extents });
    Ok(())
}

/// The text of the map of the kind `kind` of `ns` for a reader in the namespace `reader`, as
/// `uid_m_show` of Linux. The lower IDs are IDs of the namespace of the reader, or of the
/// parent if the reader is in `ns`.
pub fn show_map(ns: &UserNs, kind: IdKind, reader: &UserNs) -> Vec<u8> {
    let lower = match ns.parent.as_deref() {
        Some(p) if reader == ns => p,
        _ => reader,
    };
    let mut out = String::new();
    for e in ns.map(kind).map_or(&[][..], IdMap::extents) {
        let low = lower.from_kid(kind, e.lower_first);
        out += &format!("{:>10} {:>10} {:>10}\n", e.first, low, e.count);
    }
    out.into_bytes()
}

/// The text of `/proc/PID/setgroups` of `ns`, as `proc_setgroups_show` of Linux.
pub fn show_setgroups(ns: &UserNs) -> &'static [u8] {
    if ns.setgroups_allowed.load(Ordering::Relaxed) { b"allow\n" } else { b"deny\n" }
}

/// Writes `/proc/PID/setgroups` of `ns`, as `proc_setgroups_open` and `proc_setgroups_write`
/// of Linux. The text is `allow` or `deny`, with white space after it.
///
/// # Errors
///
/// Gives `EACCES` if `cred` has no `CAP_SYS_ADMIN` in `ns`, `EINVAL` for another text or a write
/// that is not at the offset 0, and `EPERM` for `allow` after `deny` and for `deny` after the
/// group map is set.
pub fn write_setgroups(ns: &UserNs, cred: &Cred, offset: u64, text: &[u8]) -> Result<(), Errno> {
    if !cred.ns_capable(ns, cap::SYS_ADMIN) {
        return Err(Errno::EACCES);
    }
    if offset != 0 || text.len() >= 8 {
        return Err(Errno::EINVAL);
    }
    let (allow, rest) = if let Some(r) = text.strip_prefix(b"allow") {
        (true, r)
    } else if let Some(r) = text.strip_prefix(b"deny") {
        (false, r)
    } else {
        return Err(Errno::EINVAL);
    };
    if !rest.iter().all(u8::is_ascii_whitespace) {
        return Err(Errno::EINVAL);
    }
    let _lock = STATE.lock();
    if allow {
        if !ns.setgroups_allowed.load(Ordering::Relaxed) {
            return Err(Errno::EPERM);
        }
    } else {
        if ns.map(IdKind::Gid).is_some() {
            return Err(Errno::EPERM);
        }
        ns.setgroups_allowed.store(false, Ordering::Relaxed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn child(cred: &Cred) -> Cred {
        create(cred).unwrap()
    }

    #[test]
    fn the_first_namespace_maps_all_ids() {
        let ns = init();
        assert_eq!(ns.make_kuid(1000), 1000);
        assert_eq!(ns.from_kid(IdKind::Gid, 7), 7);
        assert_eq!(ns.make_kuid(INVALID_ID), INVALID_ID);
        let text = show_map(ns, IdKind::Uid, ns);
        assert_eq!(text, b"         0          0 4294967295\n");
    }

    #[test]
    fn a_new_namespace_has_no_map_and_all_capabilities() {
        let mut root = Cred::root();
        root.cap_effective = 0;
        let c = child(&root);
        assert!(c.user_ns.parent().is_some());
        assert_eq!(c.user_ns.level(), 1);
        assert_eq!(c.cap_effective, cap::ALL);
        assert_eq!(c.user_ns.make_kuid(0), INVALID_ID);
        assert_eq!(c.user_ns.from_kid_munged(IdKind::Uid, 0), OVERFLOW_ID);
        assert!(c.ns_capable(&c.user_ns, cap::SYS_ADMIN));
        assert!(!c.capable(cap::SYS_ADMIN));
        assert!(by_id(c.user_ns.id()).is_some());
    }

    #[test]
    fn the_owner_maps_its_own_id() {
        let mut user = Cred::root().setresuid(1000, 1000, 1000).unwrap();
        user.egid = 100;
        let c = child(&user);
        let ns = c.user_ns.clone();
        // The owner in the parent has no `CAP_SETUID`, so only its own ID works.
        assert_eq!(write_map(&ns, IdKind::Uid, &user, 0, b"0 1001 1\n"), Err(Errno::EPERM));
        assert_eq!(write_map(&ns, IdKind::Uid, &user, 0, b"0 1000 1\n"), Ok(()));
        assert_eq!(write_map(&ns, IdKind::Uid, &user, 0, b"0 1000 1\n"), Err(Errno::EPERM));
        assert_eq!(ns.make_kuid(0), 1000);
        assert_eq!(ns.from_kid(IdKind::Uid, 1000), 0);
        // The group needs `deny` in setgroups first.
        assert_eq!(write_map(&ns, IdKind::Gid, &user, 0, b"0 100 1"), Err(Errno::EPERM));
        assert_eq!(write_setgroups(&ns, &c, 0, b"deny"), Ok(()));
        assert_eq!(write_setgroups(&ns, &c, 0, b"allow\n"), Err(Errno::EPERM));
        assert_eq!(write_map(&ns, IdKind::Gid, &user, 0, b"0 100 1"), Ok(()));
        assert_eq!(show_setgroups(&ns), b"deny\n");
        // The parent sees the lower IDs of its own namespace, and the child of the parent.
        assert_eq!(show_map(&ns, IdKind::Uid, init()), b"         0       1000          1\n");
        assert_eq!(show_map(&ns, IdKind::Uid, &ns), b"         0       1000          1\n");
    }

    #[test]
    fn root_maps_ranges_and_the_text_rules_hold() {
        let root = Cred::root();
        let c = child(&root);
        let ns = c.user_ns.clone();
        for bad in [
            &b"0 0"[..],
            b"0 0 0",
            b"0 0 1 2",
            b"0 0 1\n0 5 1",
            b"0 0 1\n5 0 1",
            b"4294967295 0 1",
            b"x 0 1",
            b"",
        ] {
            assert_eq!(write_map(&ns, IdKind::Uid, &root, 0, bad), Err(Errno::EINVAL), "{bad:?}");
        }
        assert_eq!(write_map(&ns, IdKind::Uid, &root, 1, b"0 0 1"), Err(Errno::EINVAL));
        assert_eq!(write_map(&ns, IdKind::Uid, &root, 0, b"0 100000 1000\n2000 0 1"), Ok(()));
        assert_eq!(write_map(&ns, IdKind::Gid, &root, 0, b"0 0 10"), Ok(()));
        assert_eq!(ns.make_kuid(999), 100_999);
        assert_eq!(ns.make_kuid(1000), INVALID_ID);
        assert_eq!(ns.make_kuid(2000), 0);
        // A child of the child maps through the map of the child.
        let mut inner = c.clone();
        inner.euid = ns.make_kuid(0);
        let gc = child(&inner);
        let map = b"0 0 1\n1 1 1\n2 2 1\n3 3 1\n4 4 1\n5 5 990";
        assert_eq!(write_map(&gc.user_ns, IdKind::Uid, &inner, 0, map), Ok(()));
        assert_eq!(gc.user_ns.make_kuid(994), 100_994);
        assert_eq!(gc.user_ns.from_kid(IdKind::Uid, 0), INVALID_ID);
        // IDs that the parent does not map are refused.
        let gc2 = child(&inner);
        assert_eq!(write_map(&gc2.user_ns, IdKind::Uid, &inner, 0, b"0 1000 1"), Err(Errno::EPERM));
    }

    #[test]
    fn capabilities_apply_in_the_namespaces_below() {
        let root = Cred::root();
        let a = child(&root);
        let b = child(&root);
        // Root in the parent is the owner of both, and each child has no capability in the
        // other.
        assert!(root.ns_capable(&a.user_ns, cap::SYS_ADMIN));
        assert!(!b.ns_capable(&a.user_ns, cap::SYS_ADMIN));
        assert!(a.ns_capable(&a.user_ns, cap::SYS_ADMIN));
        // A user who is not the owner has no capability without its own.
        let user = Cred::root().setresuid(1000, 1000, 1000).unwrap();
        assert!(!user.ns_capable(&a.user_ns, cap::SYS_ADMIN));
        let own = child(&user);
        assert!(user.ns_capable(&own.user_ns, cap::SYS_ADMIN));
    }

    #[test]
    fn the_limit_counts_the_namespaces_of_a_user() {
        let root = Cred::root();
        let c = child(&root);
        assert_eq!(write_map(&c.user_ns, IdKind::Uid, &root, 0, b"0 0 100"), Ok(()));
        assert_eq!(write_map(&c.user_ns, IdKind::Gid, &root, 0, b"0 0 100"), Ok(()));
        c.user_ns.set_max(UcountKind::User, 1);
        let mut inner = c.clone();
        inner.euid = 5;
        let one = create(&inner);
        assert!(one.is_ok());
        assert_eq!(c.user_ns.count(5, UcountKind::User), 1);
        assert_eq!(create(&inner).map(|_| ()), Err(Errno::ENOSPC));
        drop(one);
        assert_eq!(c.user_ns.count(5, UcountKind::User), 0);
        // A namespace of the level 33 can have no child.
        let mut deep = root;
        for _ in 0..MAX_LEVEL {
            let next = child(&deep);
            assert_eq!(write_map(&next.user_ns, IdKind::Uid, &deep, 0, b"0 0 1"), Ok(()));
            assert_eq!(write_map(&next.user_ns, IdKind::Gid, &deep, 0, b"0 0 1"), Ok(()));
            deep = next;
        }
        assert_eq!(deep.user_ns.level(), MAX_LEVEL);
        assert_eq!(create(&deep).map(|_| ()), Err(Errno::ENOSPC));
    }

    #[test]
    fn a_group_and_its_marks_count_in_the_namespace_of_the_group() {
        let c = child(&Cred::root());
        c.user_ns.set_max(UcountKind::FanotifyMarks, 2);
        let group = charge(&c.user_ns, 7, UcountKind::FanotifyGroups).unwrap();
        let marks: Vec<_> = (0..2).map(|_| group.again(UcountKind::FanotifyMarks)).collect();
        assert!(marks.iter().all(Option::is_some));
        assert!(group.again(UcountKind::FanotifyMarks).is_none());
        assert_eq!(c.user_ns.count(7, UcountKind::FanotifyMarks), 2);
        assert_eq!(c.user_ns.count(7, UcountKind::FanotifyGroups), 1);
        drop(marks);
        assert_eq!(c.user_ns.count(7, UcountKind::FanotifyMarks), 0);
        assert!(group.again(UcountKind::FanotifyMarks).is_some());
    }
}

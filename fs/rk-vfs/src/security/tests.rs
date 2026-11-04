use super::*;
use crate::cred::cap;
use core::sync::atomic::{AtomicU32, Ordering};
use rk_abi::Errno;

struct Deny(Errno);

impl SecurityHooks for Deny {
    fn task_getsid(&self, _: &Task<'_>) -> Result<()> {
        Err(self.0)
    }
}

static CALLS: AtomicU32 = AtomicU32::new(0);

struct Count;

impl SecurityHooks for Count {
    fn task_getsid(&self, _: &Task<'_>) -> Result<()> {
        CALLS.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

const fn info(
    name: &'static str,
    order: Order,
    flags: u32,
    blobs: BlobSizes,
    hooks: &'static dyn SecurityHooks,
) -> LsmInfo {
    LsmInfo { id: LsmId { name, id: 900 }, order, flags, blobs, hooks }
}

const SOME: BlobSizes = BlobSizes { cred: 4, task: 12, ..BlobSizes::NONE };

static SELINUX: LsmInfo = info("selinux", Order::Mutable, FLAG_LEGACY_MAJOR, SOME, &Count);
static APPARMOR: LsmInfo =
    info("apparmor", Order::Mutable, FLAG_LEGACY_MAJOR | FLAG_EXCLUSIVE, SOME, &Count);
static SMACK: LsmInfo =
    info("smack", Order::Mutable, FLAG_LEGACY_MAJOR | FLAG_EXCLUSIVE, SOME, &Count);
static YAMA: LsmInfo = info("yama", Order::Mutable, 0, BlobSizes::NONE, &Count);
static IMA: LsmInfo =
    info("ima", Order::Last, 0, BlobSizes { inode: 8, ..BlobSizes::NONE }, &Count);
static DENY_PERM: LsmInfo = info("deny1", Order::Mutable, 0, BlobSizes::NONE, &Deny(Errno::EPERM));
static DENY_EACCES: LsmInfo =
    info("deny2", Order::Mutable, 0, BlobSizes::NONE, &Deny(Errno::EACCES));

fn all() -> [&'static LsmInfo; 6] {
    [&IMA, &SELINUX, &APPARMOR, &SMACK, &YAMA, &capability::LSM]
}

#[test]
fn the_capability_module_is_first_and_the_last_modules_are_last() {
    assert_eq!(prepare(&all(), Some("yama,selinux"), None).names(), "capability,yama,selinux,ima");
    assert_eq!(prepare(&all(), Some(""), None).names(), "capability,ima");
    assert_eq!(prepare(&all(), Some("ima,capability"), None).names(), "capability,ima");
}

#[test]
fn the_default_list_gives_the_order_without_lsm() {
    assert_eq!(prepare(&all(), None, None).names(), "capability,yama,selinux,smack,ima");
    assert_eq!(prepare(&[&capability::LSM], None, None).names(), "capability");
}

#[test]
fn duplicates_and_unknown_names_are_ignored() {
    let s = prepare(&all(), Some("yama,nothing,yama,selinux,yama"), None);
    assert_eq!(s.names(), "capability,yama,selinux,ima");
}

#[test]
fn only_one_exclusive_module_is_active() {
    let s = prepare(&all(), Some("apparmor,smack,selinux"), None);
    assert_eq!(s.names(), "capability,apparmor,selinux,ima");
    let s = prepare(&all(), Some("smack,apparmor"), None);
    assert_eq!(s.names(), "capability,smack,ima");
}

#[test]
fn security_selects_one_legacy_major_module() {
    let s = prepare(&all(), None, Some("apparmor"));
    assert_eq!(s.names(), "capability,yama,apparmor,ima");
    // `lsm=` replaces `security=`.
    let s = prepare(&all(), Some("selinux"), Some("apparmor"));
    assert_eq!(s.names(), "capability,selinux,ima");
}

#[test]
fn each_module_gets_aligned_offsets_in_the_blobs() {
    let s = prepare(&all(), Some("selinux,yama,apparmor"), None);
    let offsets: Vec<BlobSizes> = s.active.iter().map(|a| a.offsets).collect();
    // capability, selinux, yama, apparmor, ima.
    assert_eq!(offsets[0], BlobSizes::NONE);
    assert_eq!((offsets[1].cred, offsets[1].task), (0, 0));
    assert_eq!(offsets[2], BlobSizes::NONE);
    assert_eq!((offsets[3].cred, offsets[3].task), (8, 16));
    assert_eq!(offsets[4].inode, 0);
    assert_eq!(s.sizes, BlobSizes { cred: 12, task: 28, inode: 8, ..BlobSizes::NONE });
}

#[test]
fn the_first_error_stops_the_call() {
    let task = Task { pid: 1, cred: &Cred::root(), security: None };
    let s = prepare(
        &[&capability::LSM, &YAMA, &DENY_EACCES, &DENY_PERM],
        Some("deny2,yama,deny1"),
        None,
    );
    let before = CALLS.load(Ordering::Relaxed);
    assert_eq!(first_error(&s.active, |h| h.task_getsid(&task)), Err(Errno::EACCES));
    assert_eq!(CALLS.load(Ordering::Relaxed), before);
    let s = prepare(&[&capability::LSM, &YAMA, &DENY_PERM], Some("yama,deny1"), None);
    assert_eq!(first_error(&s.active, |h| h.task_getsid(&task)), Err(Errno::EPERM));
    assert!(CALLS.load(Ordering::Relaxed) > before);
}

#[test]
fn the_capability_module_checks_the_effective_set() {
    let mut c = Cred::root();
    assert!(capable(&c, cap::SYS_ADMIN, 0));
    c.cap_effective = cap::bit(cap::NET_BIND_SERVICE);
    assert!(!c.capable(cap::SYS_ADMIN));
    assert!(c.capable(cap::NET_BIND_SERVICE));
    assert_eq!(lsm_names(), "capability");
}

#[test]
fn the_hook_table_has_the_names_of_linux() {
    assert_eq!(HOOK_NAMES.len(), HOOK_COUNT);
    assert_eq!(hook_index("binder_set_context_mgr"), Some(0));
    assert!(hook_index("file_open").is_some());
    assert!(hook_index("socket_create").is_some());
    assert_eq!(hook_index("no_such_hook"), None);
    let mut names = HOOK_NAMES.to_vec();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), HOOK_COUNT);
}

#[test]
fn a_blob_keeps_words_and_a_copy_has_the_same_values() {
    let b = Blob::new(12);
    assert_eq!(b.len(), 16);
    b.store(8, 7);
    assert_eq!(b.load(8), 7);
    assert_eq!(b.load(16), 0);
    b.store(16, 1);
    let c = b.clone();
    assert_eq!(c.load(8), 7);
    assert_eq!(b, c);
    assert!(Blob::EMPTY.is_empty());
    assert_eq!(Blob::cred().len(), 0);
}

//! The tests of the key service. The tables of keys and quotas are shared, so each test uses
//! its own user ID.

use super::*;
use rk_abi::native::keyctl::KEYCTL_MOVE_EXCL;

/// The lock of the tests that walk all the keys, and of the tests that expect a key to go with
/// its last reference. A walk holds a reference to each key for a short time, so a key of a
/// different test can stay after its last link goes.
static WALK: SpinLock<()> = SpinLock::new(());

/// The keyrings of a test thread.
struct TestOwner {
    rings: SpinLock<[Option<Arc<Key>>; 3]>,
    reqkey: SpinLock<u8>,
}

impl Default for TestOwner {
    fn default() -> Self {
        Self { rings: SpinLock::new([None, None, None]), reqkey: SpinLock::new(0) }
    }
}

fn index(slot: Slot) -> usize {
    match slot {
        Slot::Thread => 0,
        Slot::Process => 1,
        Slot::Session => 2,
    }
}

impl Owner for TestOwner {
    fn ring(&self, slot: Slot) -> Option<Arc<Key>> {
        self.rings.lock()[index(slot)].clone()
    }

    fn set_ring(&self, slot: Slot, ring: Arc<Key>, replace: bool) -> Arc<Key> {
        let mut rings = self.rings.lock();
        let r = &mut rings[index(slot)];
        if replace || r.is_none() {
            *r = Some(ring);
        }
        r.clone().unwrap()
    }

    fn reqkey(&self) -> u8 {
        *self.reqkey.lock()
    }

    fn set_reqkey(&self, value: u8) {
        *self.reqkey.lock() = value;
    }
}

fn cred(uid: u32) -> Cred {
    Cred {
        uid,
        euid: uid,
        suid: uid,
        fsuid: uid,
        gid: uid,
        egid: uid,
        sgid: uid,
        fsgid: uid,
        cap_permitted: 0,
        cap_effective: 0,
        ..Cred::root()
    }
}

const PROC: i32 = KEY_SPEC_PROCESS_KEYRING;

#[test]
fn add_read_update_describe() {
    let (c, o) = (cred(5001), TestOwner::default());
    let cx = Caller { cred: &c, now: 100, owner: &o };
    let k = add_key(&cx, b"user", Some(b"k1"), b"abc".to_vec(), PROC).unwrap();
    assert_eq!(read(&cx, k, 16).unwrap(), (3, b"abc".to_vec()));
    assert_eq!(read(&cx, k, 2).unwrap(), (3, Vec::new()));
    // The same type and description change the payload of the same key.
    assert_eq!(add_key(&cx, b"user", Some(b"k1"), b"xy".to_vec(), PROC).unwrap(), k);
    assert_eq!(read(&cx, k, 16).unwrap().1, b"xy".to_vec());
    update(&cx, k, b"z".to_vec()).unwrap();
    assert_eq!(read(&cx, k, 16).unwrap().1, b"z".to_vec());
    let d = describe(&cx, k).unwrap();
    assert_eq!(d, b"user;5001;5001;3f010000;k1\0".to_vec());
    assert_eq!(get_security(&cx, k).unwrap(), alloc::vec![0]);
    assert_eq!(get_security(&cx, i32::MAX), Err(Errno::ENOKEY));
}

#[test]
fn add_key_errors() {
    let (c, o) = (cred(5002), TestOwner::default());
    let cx = Caller { cred: &c, now: 0, owner: &o };
    assert_eq!(add_key(&cx, b"nope", Some(b"d"), Vec::new(), PROC), Err(Errno::ENODEV));
    assert_eq!(add_key(&cx, b"keyring", Some(b"d"), b"x".to_vec(), PROC), Err(Errno::EINVAL));
    assert_eq!(add_key(&cx, b"user", Some(b"d"), alloc::vec![0; 32768], PROC), Err(Errno::EINVAL));
    assert_eq!(add_key(&cx, b"logon", Some(b"nocolon"), b"x".to_vec(), PROC), Err(Errno::EINVAL));
    assert_eq!(add_key(&cx, b"user", None, b"x".to_vec(), PROC), Err(Errno::EINVAL));
    let k = add_key(&cx, b"logon", Some(b"a:b"), b"x".to_vec(), PROC).unwrap();
    assert_eq!(read(&cx, k, 16), Err(Errno::EOPNOTSUPP));
    assert_eq!(add_key(&cx, b"user", Some(b"d"), b"x".to_vec(), k), Err(Errno::ENOTDIR));
}

#[test]
fn keyring_read_sizes() {
    let _walk = WALK.lock();
    let (c, o) = (cred(5003), TestOwner::default());
    let cx = Caller { cred: &c, now: 0, owner: &o };
    let a = add_key(&cx, b"user", Some(b"a"), b"1".to_vec(), PROC).unwrap();
    let b = add_key(&cx, b"user", Some(b"b"), b"1".to_vec(), PROC).unwrap();
    assert_eq!(read(&cx, PROC, 4).unwrap(), (8, Vec::new()));
    assert_eq!(read(&cx, PROC, 3), Err(Errno::EINVAL));
    let (n, data) = read(&cx, PROC, 8).unwrap();
    assert_eq!(n, 8);
    let mut want = a.to_ne_bytes().to_vec();
    want.extend_from_slice(&b.to_ne_bytes());
    assert_eq!(data, want);
    clear(&cx, PROC).unwrap();
    assert_eq!(read(&cx, PROC, 8).unwrap(), (0, Vec::new()));
    assert_eq!(read(&cx, a, 8), Err(Errno::ENOKEY));
}

#[test]
fn request_key_negative() {
    let (c, o) = (cred(5004), TestOwner::default());
    let cx = Caller { cred: &c, now: 0, owner: &o };
    assert_eq!(request_key(&cx, b"user", b"d", None, PROC), Err(Errno::ENOKEY));
    assert_eq!(request_key(&cx, b"user", b"d", Some(b"c"), PROC), Err(Errno::ENOKEY));
    let (_, ids) = read(&cx, PROC, 4).unwrap();
    let neg = i32::from_ne_bytes(ids.try_into().unwrap());
    assert_eq!(read(&cx, neg, 16), Err(Errno::ENOKEY));
    // The negative key answers the next request.
    assert_eq!(request_key(&cx, b"user", b"d", Some(b"c"), PROC), Err(Errno::ENOKEY));
    assert_eq!(read(&cx, PROC, 64).unwrap().0, 4);
    assert_eq!(request_key(&cx, b"keyring", b"r", Some(b"c"), PROC), Err(Errno::EPERM));
    assert_eq!(request_key(&cx, b"dead", b"r", None, PROC), Err(Errno::ENOKEY));
    let r = add_key(&cx, b"keyring", Some(b"found"), Vec::new(), PROC).unwrap();
    assert_eq!(request_key(&cx, b"keyring", b"found", None, 0), Ok(r));
}

#[test]
fn revoke_and_expiry() {
    let (c, o) = (cred(5005), TestOwner::default());
    let mut cx = Caller { cred: &c, now: 10, owner: &o };
    let r = add_key(&cx, b"keyring", Some(b"r"), Vec::new(), KEY_SPEC_THREAD_KEYRING).unwrap();
    let e = add_key(&cx, b"keyring", Some(b"e"), Vec::new(), KEY_SPEC_THREAD_KEYRING).unwrap();
    revoke(&cx, r).unwrap();
    set_timeout(&cx, e, 1).unwrap();
    cx.now = 12;
    assert_eq!(request_key(&cx, b"keyring", b"x", None, r), Err(Errno::EKEYREVOKED));
    assert_eq!(request_key(&cx, b"keyring", b"x", None, e), Err(Errno::EKEYEXPIRED));
    assert_eq!(read(&cx, r, 0), Err(Errno::EKEYREVOKED));
    assert_eq!(revoke(&cx, i32::MAX), Err(Errno::ENOKEY));
}

#[test]
fn move_link_and_cycles() {
    let (c, o) = (cred(5006), TestOwner::default());
    let cx = Caller { cred: &c, now: 0, owner: &o };
    let a = add_key(&cx, b"keyring", Some(b"a"), Vec::new(), PROC).unwrap();
    let b = add_key(&cx, b"keyring", Some(b"b"), Vec::new(), PROC).unwrap();
    let ka = add_key(&cx, b"user", Some(b"k"), b"1".to_vec(), a).unwrap();
    let kb = add_key(&cx, b"user", Some(b"k"), b"1".to_vec(), b).unwrap();
    let excl = KEYCTL_MOVE_EXCL as u32;
    assert_eq!(move_key(&cx, ka, a, b, excl), Err(Errno::EEXIST));
    assert_eq!(move_key(&cx, ka, a, b, 2), Err(Errno::EINVAL));
    assert_eq!(move_key(&cx, ka, kb, b, 0), Err(Errno::ENOTDIR));
    assert_eq!(move_key(&cx, kb, a, b, 0), Err(Errno::ENOENT));
    link(&cx, b, a).unwrap();
    assert_eq!(link(&cx, a, b), Err(Errno::EDEADLK));
    assert_eq!(move_key(&cx, b, PROC, b, 0), Err(Errno::EDEADLK));
    unlink(&cx, b, a).unwrap();
    assert_eq!(unlink(&cx, b, a), Err(Errno::ENOENT));
    move_key(&cx, ka, a, b, 0).unwrap();
    assert_eq!(search(&cx, b, b"user", b"k", 0), Ok(ka));
    assert_eq!(search(&cx, a, b"user", b"k", 0), Err(Errno::ENOKEY));
    // The nested keyrings are in the search.
    assert_eq!(search(&cx, PROC, b"user", b"k", 0), Ok(ka));
}

#[test]
fn restrict_reject_all() {
    let (c, o) = (cred(5007), TestOwner::default());
    let cx = Caller { cred: &c, now: 0, owner: &o };
    let r = add_key(&cx, b"keyring", Some(b"r"), Vec::new(), PROC).unwrap();
    let k = add_key(&cx, b"user", Some(b"k"), b"1".to_vec(), PROC).unwrap();
    assert_eq!(restrict(&cx, r, Some(b"user"), None), Err(Errno::EINVAL));
    assert_eq!(restrict(&cx, r, Some(b"asymmetric"), Some(b"x")), Err(Errno::ENOKEY));
    assert_eq!(restrict(&cx, r, Some(b"user"), Some(b"x")), Err(Errno::ENOENT));
    restrict(&cx, r, None, None).unwrap();
    assert_eq!(restrict(&cx, r, None, None), Err(Errno::EEXIST));
    assert_eq!(link(&cx, k, r), Err(Errno::EPERM));
    assert_eq!(add_key(&cx, b"user", Some(b"x"), b"1".to_vec(), r), Err(Errno::EPERM));
}

#[test]
fn quota_and_drop() {
    let _walk = WALK.lock();
    let uid = 5008;
    {
        let (c, o) = (cred(uid), TestOwner::default());
        let cx = Caller { cred: &c, now: 0, owner: &o };
        let mut err = Ok(0);
        for i in 0..300 {
            let desc = alloc::format!("k{i}");
            err = add_key(&cx, b"user", Some(desc.as_bytes()), alloc::vec![1; 10], PROC);
            if err.is_err() {
                break;
            }
        }
        assert_eq!(err, Err(Errno::EDQUOT));
        let u = usage(uid);
        assert!(u.qnkeys <= MAXKEYS.load(Ordering::Relaxed));
        assert!(u.qnbytes <= MAXBYTES.load(Ordering::Relaxed));
        assert!(!key_users_text().is_empty());
    }
    // The keys go with the last reference, and the quota with them.
    assert_eq!(usage(uid), Usage::default());
}

#[test]
fn invalidate_removes_links() {
    let _walk = WALK.lock();
    let (c, o) = (cred(5009), TestOwner::default());
    let cx = Caller { cred: &c, now: 0, owner: &o };
    let k = add_key(&cx, b"user", Some(b"k"), b"1".to_vec(), PROC).unwrap();
    invalidate(&cx, k).unwrap();
    assert_eq!(read(&cx, PROC, 16).unwrap().0, 0);
    assert_eq!(describe(&cx, k), Err(Errno::ENOKEY));
}

#[test]
fn permissions_and_chown() {
    let (c, o) = (cred(5010), TestOwner::default());
    let cx = Caller { cred: &c, now: 0, owner: &o };
    let k = add_key(&cx, b"user", Some(b"k"), b"1".to_vec(), PROC).unwrap();
    let all = POS_ALL | USR_ALL | GRP_ALL | OTH_ALL;
    set_perm(&cx, k, all & !(VIEW | (VIEW << GRP) | (VIEW << USR) | (VIEW << POS))).unwrap();
    assert_eq!(describe(&cx, k), Err(Errno::EACCES));
    assert_eq!(set_perm(&cx, k, 0x40), Err(Errno::EINVAL));
    assert_eq!(chown(&cx, k, 1, u32::MAX), Err(Errno::EACCES));
    assert_eq!(chown(&cx, k, u32::MAX, u32::MAX), Ok(()));
    chown(&cx, k, u32::MAX, 5010).unwrap();
}

#[test]
fn session_and_user_rings() {
    let _walk = WALK.lock();
    let (c, o) = (cred(5011), TestOwner::default());
    let cx = Caller { cred: &c, now: 0, owner: &o };
    let us = get_keyring_id(&cx, KEY_SPEC_USER_SESSION_KEYRING, false).unwrap();
    // With no session keyring, the session keyring is the user session keyring.
    assert_eq!(get_keyring_id(&cx, KEY_SPEC_SESSION_KEYRING, false), Ok(us));
    let s = join_session(&cx, None).unwrap();
    assert_ne!(s, us);
    assert_eq!(get_keyring_id(&cx, KEY_SPEC_SESSION_KEYRING, false), Ok(s));
    assert_eq!(join_session(&cx, Some(b".builtin_trusted_keys")), Err(Errno::EPERM));
    let n = join_session(&cx, Some(b"named")).unwrap();
    assert_eq!(get_keyring_id(&cx, KEY_SPEC_SESSION_KEYRING, false), Ok(n));
    assert_eq!(get_keyring_id(&cx, KEY_SPEC_THREAD_KEYRING, false), Err(Errno::ENOKEY));
    let t = get_keyring_id(&cx, KEY_SPEC_THREAD_KEYRING, true).unwrap();
    assert_eq!(set_reqkey(&cx, 1), Ok(0));
    assert_eq!(get_keyring_id(&cx, KEY_SPEC_THREAD_KEYRING, false), Ok(t));
    assert_eq!(set_reqkey(&cx, -1), Ok(1));
    assert_eq!(set_reqkey(&cx, 6), Err(Errno::EINVAL));
    assert!(!keys_text(&cx).is_empty());
    assert_eq!(capabilities(), [0xe1, 0x03]);
}

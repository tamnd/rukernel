//! The tests of the key service. The tables of keys and quotas are shared, so each test uses
//! its own user ID.

use super::*;
use rk_abi::native::keyctl::KEYCTL_MOVE_EXCL;

/// The keyrings of a test thread.
struct TestOwner {
    rings: SpinLock<[Option<Arc<Key>>; 3]>,
    reqkey: SpinLock<u8>,
    auth: SpinLock<Option<Arc<Key>>>,
}

impl Default for TestOwner {
    fn default() -> Self {
        Self {
            rings: SpinLock::new([None, None, None]),
            reqkey: SpinLock::new(0),
            auth: SpinLock::new(None),
        }
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

    fn auth(&self) -> Option<Arc<Key>> {
        self.auth.lock().clone()
    }

    fn set_auth(&self, auth: Option<Arc<Key>>) {
        *self.auth.lock() = auth;
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
    assert_eq!(restrict(&cx, r, Some(b"asymmetric"), Some(b"x")), Err(Errno::EINVAL));
    assert_eq!(restrict(&cx, r, Some(b"user"), Some(b"x")), Err(Errno::ENOENT));
    restrict(&cx, r, None, None).unwrap();
    assert_eq!(restrict(&cx, r, None, None), Err(Errno::EEXIST));
    assert_eq!(link(&cx, k, r), Err(Errno::EPERM));
    assert_eq!(add_key(&cx, b"user", Some(b"x"), b"1".to_vec(), r), Err(Errno::EPERM));
}

#[test]
fn quota_and_drop() {
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
    assert_eq!(capabilities(), [0xfd, 0x03]);
}

#[test]
fn walk_keeps_no_key_alive() {
    let (c, o) = (cred(5012), TestOwner::default());
    let cx = Caller { cred: &c, now: 0, owner: &o };
    let k = add_key(&cx, b"user", Some(b"k"), b"1".to_vec(), PROC).unwrap();
    // The copy of a walk holds the data of the key, but not the key.
    let walk = all_keys();
    assert!(walk.iter().any(|d| d.serial == k));
    unlink(&cx, k, PROC).unwrap();
    // The key is dead with its last link, as in Linux: a lookup does not find it, its quota is
    // free, and the walks do not show it.
    assert_eq!(describe(&cx, k), Err(Errno::ENOKEY));
    assert_eq!(usage(5012).nkeys, 1);
    assert!(walk.iter().any(|d| d.serial == k && d.usage() == 0));
    let text = keys_text(&cx);
    let line = alloc::format!("{k:08x} ");
    assert!(!alloc::string::String::from_utf8_lossy(&text).contains(line.as_str()));
    collect();
    drop(walk);
}

#[test]
fn dns_resolver_keys() {
    let (c, o) = (cred(5013), TestOwner::default());
    let mut cx = Caller { cred: &c, now: 50, owner: &o };
    // The payload of keyctl05: a binary server list with no good lookup expires after 1 second.
    let list = [0, 0, 1, 0xff, 0, 0];
    let k = add_key(&cx, b"dns_resolver", Some(b"desc"), list.to_vec(), PROC).unwrap();
    // A type with no update gets no write permission, and a second add makes a new key.
    assert_eq!(describe(&cx, k).unwrap(), b"dns_resolver;5013;5013;3b010000;desc\0".to_vec());
    assert_eq!(update(&cx, k, list.to_vec()), Err(Errno::EACCES));
    set_perm(&cx, k, 0x3f00_0000).unwrap();
    assert_eq!(update(&cx, k, list.to_vec()), Err(Errno::EOPNOTSUPP));
    assert_eq!(read(&cx, k, 16).unwrap(), (6, list.to_vec()));
    cx.now = 51;
    assert_eq!(read(&cx, k, 16), Err(Errno::EKEYEXPIRED));
    let k2 = add_key(&cx, b"dns_resolver", Some(b"desc"), list.to_vec(), PROC).unwrap();
    assert_ne!(k2, k);
    // A good lookup does not expire. The text form keeps the data before the options.
    let good = add_key(&cx, b"dns_resolver", Some(b"g"), [0, 0, 1, 0, 1, 0].to_vec(), PROC);
    cx.now = 60;
    assert_eq!(read(&cx, good.unwrap(), 16).unwrap().0, 6);
    // Text ends with a NUL, which the key does not keep.
    let t = add_key(&cx, b"dns_resolver", Some(b"t"), b"1.2.3.4\0".to_vec(), PROC);
    assert_eq!(read(&cx, t.unwrap(), 16).unwrap(), (7, b"1.2.3.4".to_vec()));
    // A key with `dnserror` is positive with no data, and a read gives the error.
    let before = usage(5013).qnbytes;
    let e = add_key(&cx, b"dns_resolver", Some(b"e"), b"x#dnserror=6#\0".to_vec(), PROC).unwrap();
    assert_eq!(usage(5013).qnbytes, before + LINK_BYTES + 2);
    assert_eq!(read(&cx, e, 16), Err(Errno::ENXIO));
    let text = alloc::string::String::from_utf8(keys_text(&cx)).unwrap();
    let line = text.lines().find(|l| l.starts_with(&alloc::format!("{e:08x} "))).unwrap();
    assert!(line.ends_with(" e: -6") && line.contains(" I--Q--- "), "{line}");
    for bad in [
        &b"x"[..],
        b"ab",
        &[0, 0, 1, 0, 1],
        &[0, 1, 1, 0, 1, 0],
        &[0, 0, 2, 0, 1, 0],
        b"a#\0",
        b"a#b=1\0",
        b"a#dnserror=512\0",
        b"a#dnserror=0\0",
        b"a##\0",
    ] {
        let r = add_key(&cx, b"dns_resolver", Some(b"bad"), bad.to_vec(), PROC);
        assert_eq!(r, Err(Errno::EINVAL), "{bad:?}");
    }
}

#[test]
fn big_keys() {
    let (c, o) = (cred(5014), TestOwner::default());
    let cx = Caller { cred: &c, now: 0, owner: &o };
    let ring = get_keyring_id(&cx, PROC, true).unwrap();
    let base = usage(5014).qnbytes;
    // A new key takes 16 bytes of the quota for its payload, as `big_key_preparse`.
    let k = add_key(&cx, b"big_key", Some(b"b"), alloc::vec![7; 2000], ring).unwrap();
    assert_eq!(usage(5014).qnbytes, base + LINK_BYTES + 2 + 16);
    assert_eq!(describe(&cx, k).unwrap(), b"big_key;5014;5014;3f010000;b\0".to_vec());
    assert_eq!(read(&cx, k, 4096).unwrap(), (2000, alloc::vec![7; 2000]));
    assert_eq!(read(&cx, k, 10).unwrap(), (2000, Vec::new()));
    let text = alloc::string::String::from_utf8(keys_text(&cx)).unwrap();
    let line = text.lines().find(|l| l.starts_with(&alloc::format!("{k:08x} "))).unwrap();
    assert!(line.ends_with(" big_key   b: 2000 [file]"), "{line}");
    // An update takes the length of the payload, as `big_key_update`.
    update(&cx, k, b"small".to_vec()).unwrap();
    assert_eq!(usage(5014).qnbytes, base + LINK_BYTES + 2 + 5);
    let text = alloc::string::String::from_utf8(keys_text(&cx)).unwrap();
    assert!(text.contains(" b: 5 [buff]\n"));
    assert_eq!(update(&cx, k, Vec::new()), Err(Errno::EINVAL));
    assert_eq!(update(&cx, k, alloc::vec![0; 1024 * 1024 + 1]), Err(Errno::EINVAL));
    // A second add updates the key.
    assert_eq!(add_key(&cx, b"big_key", Some(b"b"), b"again".to_vec(), ring), Ok(k));
    assert_eq!(read(&cx, k, 16).unwrap(), (5, b"again".to_vec()));
    assert_eq!(add_key(&cx, b"big_key", Some(b"e"), Vec::new(), ring), Err(Errno::EINVAL));
    revoke(&cx, k).unwrap();
    assert_eq!(usage(5014).qnbytes, base + LINK_BYTES + 2);
}

/// A helper of the tests in place of `/sbin/request-key`: it runs as root with the session
/// keyring of the request, assumes the authority, and acts on the callout.
fn helper(req: &Request) -> Result<i32, Errno> {
    let (c, o) = (Cred::root(), TestOwner::default());
    o.set_ring(Slot::Session, req.session.clone(), true);
    let cx = Caller { cred: &c, now: 0, owner: &o };
    let id = req.key;
    assert_eq!(instantiate(&cx, id, b"v".to_vec(), 0), Err(Errno::EPERM));
    assert_eq!(read(&cx, KEY_SPEC_REQKEY_AUTH_KEY, 16), Err(Errno::ENOKEY));
    let auth = assume_authority(&cx, id).unwrap();
    // The payload of the authorization key is the callout.
    let callout = read(&cx, KEY_SPEC_REQKEY_AUTH_KEY, 64).unwrap().1;
    assert_eq!(read(&cx, auth, 64).unwrap().1, callout);
    let args = req.args();
    assert_eq!(args[0], b"create".to_vec());
    assert_eq!(args[1], alloc::format!("{id}").into_bytes());
    assert_eq!(get_keyring_id(&cx, KEY_SPEC_REQUESTOR_KEYRING, false), Ok(req.rings[1]));
    match callout.as_slice() {
        b"inst" => {
            assert_eq!(instantiate(&cx, id + 1, b"v".to_vec(), 0), Err(Errno::EPERM));
            let bad = instantiate(&cx, id, b"v".to_vec(), KEY_SPEC_REQKEY_AUTH_KEY);
            assert_eq!(bad, Err(Errno::EINVAL));
            instantiate(&cx, id, b"v".to_vec(), 0).unwrap();
            // The authority ends with the construction.
            assert!(o.auth().is_none());
            assert_eq!(instantiate(&cx, id, b"w".to_vec(), 0), Err(Errno::EPERM));
            assert_eq!(assume_authority(&cx, id), Err(Errno::ENOKEY));
        }
        b"rej" => {
            reject(&cx, id, 30, Errno::EKEYREJECTED, KEY_SPEC_REQUESTOR_KEYRING).unwrap();
        }
        b"neg" => reject(&cx, id, 30, Errno::ENOKEY, 0).unwrap(),
        // The helper finds a key of the requestor with the authority of the requestor.
        b"search" => {
            let found = request_key(&cx, b"user", b"secret", None, 0).unwrap();
            instantiate(&cx, id, alloc::format!("{found}").into_bytes(), 0).unwrap();
        }
        b"none" => {}
        _ => return Err(Errno::ENOENT),
    }
    Ok(0)
}

#[test]
fn construction_by_the_helper() {
    set_upcall(helper);
    let (c, o) = (cred(5101), TestOwner::default());
    let cx = Caller { cred: &c, now: 0, owner: &o };
    let k = request_key(&cx, b"user", b"a", Some(b"inst"), PROC).unwrap();
    assert_eq!(read(&cx, k, 16).unwrap().1, b"v".to_vec());
    assert_eq!(read(&cx, PROC, 64).unwrap().1, k.to_ne_bytes().to_vec());
    assert_eq!(request_key(&cx, b"user", b"a", Some(b"inst"), PROC), Ok(k));
    // A reject and a negate make negative keys with their errors.
    assert_eq!(request_key(&cx, b"user", b"r", Some(b"rej"), PROC), Err(Errno::EKEYREJECTED));
    assert_eq!(search(&cx, PROC, b"user", b"r", 0), Err(Errno::EKEYREJECTED));
    assert_eq!(request_key(&cx, b"user", b"n", Some(b"neg"), PROC), Err(Errno::ENOKEY));
    // A helper that does not instantiate the key leaves it negative.
    assert_eq!(request_key(&cx, b"user", b"x", Some(b"none"), PROC), Err(Errno::ENOKEY));
    let text = alloc::string::String::from_utf8(keys_text(&cx)).unwrap();
    assert!(text.lines().any(|l| l.contains(" I--Q-N- ") && l.ends_with(" user      x")));
    let s = add_key(&cx, b"user", Some(b"secret"), b"s".to_vec(), PROC).unwrap();
    let k = request_key(&cx, b"user", b"f", Some(b"search"), PROC).unwrap();
    assert_eq!(read(&cx, k, 16).unwrap().1, alloc::format!("{s}").into_bytes());
}

#[test]
fn assume_authority_errors() {
    let (c, o) = (cred(5102), TestOwner::default());
    let cx = Caller { cred: &c, now: 0, owner: &o };
    assert_eq!(assume_authority(&cx, -1), Err(Errno::EINVAL));
    assert_eq!(assume_authority(&cx, 0), Ok(0));
    assert_eq!(assume_authority(&cx, i32::MAX), Err(Errno::ENOKEY));
    assert_eq!(reject(&cx, 1, 0, Errno::ENOKEY, 0), Err(Errno::EPERM));
    assert_eq!(get_keyring_id(&cx, KEY_SPEC_REQUESTOR_KEYRING, false), Err(Errno::ENOKEY));
}

#[test]
fn dh_compute_checks() {
    let (c, o) = (cred(5201), TestOwner::default());
    let cx = Caller { cred: &c, now: 0, owner: &o };
    // A small prime gives EINVAL from the crypto API. The value of the full test is in rk-crypto.
    let mut p = alloc::vec![0xffu8; 192];
    let x = add_key(&cx, b"user", Some(b"x"), alloc::vec![3], PROC).unwrap();
    let g = add_key(&cx, b"user", Some(b"g"), alloc::vec![2], PROC).unwrap();
    let small = add_key(&cx, b"user", Some(b"p1"), alloc::vec![0xff; 190], PROC).unwrap();
    assert_eq!(dh_compute(&cx, x, small, g, 0, None), Err(Errno::EINVAL));
    p[191] = 0xfd;
    let pk = add_key(&cx, b"user", Some(b"p"), p, PROC).unwrap();
    assert_eq!(dh_compute(&cx, x, pk, g, 0, None).unwrap(), (192, Vec::new()));
    assert_eq!(dh_compute(&cx, x, pk, g, 191, None), Err(Errno::EOVERFLOW));
    let (n, v) = dh_compute(&cx, x, pk, g, 256, None).unwrap();
    assert_eq!(n, 192);
    assert_eq!(v[..191], [0; 191]);
    assert_eq!(v[191], 8);
    // The errors of the keys.
    assert_eq!(dh_compute(&cx, x, i32::MAX, g, 0, None), Err(Errno::ENOKEY));
    let ring = add_key(&cx, b"keyring", Some(b"r"), Vec::new(), PROC).unwrap();
    assert_eq!(dh_compute(&cx, x, pk, ring, 0, None), Err(Errno::EOPNOTSUPP));
    // The KDF gives `buflen` bytes.
    let hash = rk_crypto::alloc_hash("sha256").unwrap();
    let kdf = Kdf { hash, otherinfo: b"info".to_vec() };
    let (n, v) = dh_compute(&cx, x, pk, g, 40, Some(kdf)).unwrap();
    assert_eq!((n, v.len()), (40, 40));
}

/// A self-signed RSA certificate and an RSA certificate signed with SHA-1, from rk-crypto.
const CERT: &[u8] = include_bytes!("../../../../sec/rk-crypto/src/testdata/cert.der");
const CERT_SHA1: &[u8] = include_bytes!("../../../../sec/rk-crypto/src/testdata/sha1.der");

#[test]
fn asymmetric_keys_and_restrictions() {
    let (c, o) = (cred(5015), TestOwner::default());
    let cx = Caller { cred: &c, now: 0, owner: &o };
    // Without a description, the key takes the description of the parser.
    let k = add_key(&cx, b"asymmetric", None, CERT.to_vec(), PROC).unwrap();
    let desc = describe(&cx, k).unwrap();
    let want = b";rukernel: rk-test-key: 987d54853a1cfc4027b413c4f4d9914becc3188a\0";
    assert!(desc.ends_with(want), "{:?}", alloc::string::String::from_utf8_lossy(&desc));
    let text = alloc::string::String::from_utf8(keys_text(&cx)).unwrap();
    let line = text.lines().find(|l| l.starts_with(&alloc::format!("{k:08x} "))).unwrap();
    assert!(line.ends_with(": X509.rsa ecc3188a []"), "{line}");
    assert_eq!(add_key(&cx, b"asymmetric", None, b"x".to_vec(), PROC), Err(Errno::EBADMSG));
    // The errors of the restriction texts.
    let r = add_key(&cx, b"keyring", Some(b"r"), Vec::new(), PROC).unwrap();
    for bad in [&b"bogus"[..], b"key_or_keyring", b"key_or_keyring:", b"key_or_keyring:1:x"] {
        assert_eq!(restrict(&cx, r, Some(b"asymmetric"), Some(bad)), Err(Errno::EINVAL));
    }
    assert_eq!(
        restrict(&cx, r, Some(b"asymmetric"), Some(b"key_or_keyring:0x")),
        Err(Errno::EINVAL)
    );
    // Only a chain can have no key.
    for missing in [&b"key_or_keyring:2147483647"[..], b"key_or_keyring:0"] {
        assert_eq!(restrict(&cx, r, Some(b"asymmetric"), Some(missing)), Err(Errno::ENOKEY));
    }
    let own = alloc::format!("key_or_keyring:{r}:chain");
    assert_eq!(restrict(&cx, r, Some(b"asymmetric"), Some(own.as_bytes())), Err(Errno::EDEADLK));
    // The builtin trusted keyring is empty, so it signs no key.
    restrict(&cx, r, Some(b"asymmetric"), Some(b"builtin_trusted")).unwrap();
    let r2 = Some(&b"builtin_and_secondary_trusted"[..]);
    assert_eq!(restrict(&cx, r, Some(b"asymmetric"), r2), Err(Errno::EEXIST));
    let u = add_key(&cx, b"user", Some(b"u"), b"1".to_vec(), PROC).unwrap();
    assert_eq!(link(&cx, u, r), Err(Errno::EOPNOTSUPP));
    assert_eq!(link(&cx, k, r), Err(Errno::ENOKEY));
    assert_eq!(add_key(&cx, b"asymmetric", None, CERT.to_vec(), r), Err(Errno::ENOKEY));
    // The kernel cannot check a signature with SHA-1, so the key has no signature.
    let sha1 = add_key(&cx, b"asymmetric", Some(b"s"), CERT_SHA1.to_vec(), r);
    assert_eq!(sha1, Err(Errno::ENOPKG));
    // The key signs itself.
    let signed = add_key(&cx, b"keyring", Some(b"signed"), Vec::new(), PROC).unwrap();
    let by_key = alloc::format!("key_or_keyring:{k}");
    restrict(&cx, signed, Some(b"asymmetric"), Some(by_key.as_bytes())).unwrap();
    link(&cx, k, signed).unwrap();
    // A chain finds the signer in the keyring itself.
    let chain = add_key(&cx, b"keyring", Some(b"chain"), Vec::new(), PROC).unwrap();
    restrict(&cx, chain, Some(b"asymmetric"), Some(b"key_or_keyring:0:chain")).unwrap();
    assert_eq!(link(&cx, k, chain), Err(Errno::ENOKEY));
    let by_ring = add_key(&cx, b"keyring", Some(b"by_ring"), Vec::new(), PROC).unwrap();
    let text = alloc::format!("key_or_keyring:{signed}");
    restrict(&cx, by_ring, Some(b"asymmetric"), Some(text.as_bytes())).unwrap();
    add_key(&cx, b"asymmetric", Some(b"copy"), CERT.to_vec(), by_ring).unwrap();
    // A keyring has one restriction.
    assert_eq!(restrict(&cx, chain, None, None), Err(Errno::EEXIST));
}

/// The text of `load` for the master key `foo`, the IV 0 to 15 and the data 100 to 119, from the
/// algorithm of Linux in Python.
const ENC_LOAD: &[u8] = b"load default user:masterkey 20 000102030405060708090a0b0c0d0e0f00\
bcf6f5da64267b9fd27ec59531f7ac5aa8c6c0a2a00dc5f8627f4c5428004a1932f19d95a131388d53bbc60a9ac98b\
944f08aac0769b4185c21951e60efbe94d";

#[test]
fn encrypted_keys() {
    let (c, o) = (cred(5016), TestOwner::default());
    let cx = Caller { cred: &c, now: 0, owner: &o };
    // The payloads of keyctl09.
    let data = "abcdefABCDEF1234567890aaaaaaaaaaabcdefABCDEF1234567890aaaaaaaaaa";
    let new = alloc::format!("new enc32 user:masterkey 32 {data}");
    let k = add_key(&cx, b"encrypted", Some(b"k1"), new.into_bytes(), PROC).unwrap();
    // Without the master key, a read gives only the length.
    assert_eq!(read(&cx, k, 128).unwrap(), (186, Vec::new()));
    assert_eq!(read(&cx, k, 186), Err(Errno::ENOKEY));
    let bad = b"new enc32 user:masterkey 32 plaintext123@123!123@123!123@123plaintext123@123!123@123!123@123";
    assert_eq!(add_key(&cx, b"encrypted", Some(b"k2"), bad.to_vec(), PROC), Err(Errno::EINVAL));
    // The key that `load` gives has the data of the text.
    add_key(&cx, b"user", Some(b"masterkey"), b"foo".to_vec(), PROC).unwrap();
    let l = add_key(&cx, b"encrypted", Some(b"l"), ENC_LOAD.to_vec(), PROC).unwrap();
    let (n, text) = read(&cx, l, 4096).unwrap();
    assert_eq!((n, &text[..]), (ENC_LOAD.len() - 5, &ENC_LOAD[5..]));
    let r = find(l).unwrap();
    let want: Vec<u8> = (100..120).collect();
    assert_eq!(r.state.lock().enc.as_ref().unwrap().data, want);
    // A bad HMAC, and a text of a bad length.
    let mut tampered = ENC_LOAD.to_vec();
    *tampered.last_mut().unwrap() = b'e';
    let e = add_key(&cx, b"encrypted", Some(b"t"), tampered.clone(), PROC);
    assert_eq!(e, Err(Errno::EINVAL));
    tampered.pop();
    let e = add_key(&cx, b"encrypted", Some(b"t"), tampered, PROC);
    assert_eq!(e, Err(Errno::EINVAL));
    // A read of a new key and a load of the text give the same data.
    let (_, text) = read(&cx, k, 4096).unwrap();
    let mut load = b"load ".to_vec();
    load.extend_from_slice(&text);
    let k2 = add_key(&cx, b"encrypted", Some(b"k3"), load, PROC).unwrap();
    assert_eq!(read(&cx, k2, 4096).unwrap().1, text);
    let got = find(k2).unwrap().state.lock().enc.as_ref().unwrap().data.clone();
    assert_eq!(rk_crypto::asym::hex(&got), data.to_ascii_lowercase().into_bytes());
    // An update changes only the master key, to one of the same type.
    assert_eq!(update(&cx, k, b"update trusted:m".to_vec()), Err(Errno::EINVAL));
    assert_eq!(update(&cx, k, b"new user:m 32".to_vec()), Err(Errno::EINVAL));
    update(&cx, k, b"update user:other".to_vec()).unwrap();
    assert_eq!(read(&cx, k, 4096), Err(Errno::ENOKEY));
    // An add of a key that is there is an update.
    let again = add_key(&cx, b"encrypted", Some(b"k1"), b"update user:masterkey".to_vec(), PROC);
    assert_eq!(again, Ok(k));
    assert_eq!(read(&cx, k, 4096).unwrap().0, 186);
    // The lengths and the formats.
    for bad in ["new user:m 19", "new user:m 4097", "new enc32 user:m 20", "new user:m 20 00"] {
        let e = add_key(&cx, b"encrypted", Some(b"b"), bad.as_bytes().to_vec(), PROC);
        assert_eq!(e, Err(Errno::EINVAL), "{bad}");
    }
    let e = add_key(&cx, b"encrypted", Some(b"ecr"), b"new ecryptfs user:m 64".to_vec(), PROC);
    assert_eq!(e, Err(Errno::EINVAL));
    let desc = b"0123456789abcdef";
    let e = add_key(&cx, b"encrypted", Some(desc), b"new ecryptfs user:m 64".to_vec(), PROC);
    let text = alloc::string::String::from_utf8(keys_text(&cx)).unwrap();
    let line = text.lines().find(|l| l.starts_with(&alloc::format!("{:08x} ", e.unwrap())));
    assert!(line.unwrap().ends_with(" 0123456789abcdef: 873"), "{line:?}");
    let t = add_key(&cx, b"encrypted", Some(b"tr"), b"new trusted:m 32".to_vec(), PROC).unwrap();
    assert_eq!(read(&cx, t, 4096), Err(Errno::EOPNOTSUPP));
}

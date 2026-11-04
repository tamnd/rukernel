//! The construction of a key that `request_key` does not find, as `security/keys/request_key.c`
//! and `security/keys/request_key_auth.c` of Linux, and the operations of the helper:
//! `KEYCTL_ASSUME_AUTHORITY`, `KEYCTL_INSTANTIATE`, `KEYCTL_NEGATE` and `KEYCTL_REJECT`.
//!
//! The construction makes the key under construction and links it into the destination keyring.
//! It makes an authorization key with the serial number of the key in hex as its description,
//! puts it in a new session keyring `_req.N`, and gives both to the upcall, which runs
//! `/sbin/request-key` with that session keyring and waits for its end. The helper finds the
//! authorization key, assumes it, and instantiates or rejects the key. If the upcall fails, or
//! the key is still under construction after it, the key is negative with `ENOKEY` for 60
//! seconds. Then the authorization key is revoked.

use super::{
    Caller, KEY_SPEC_REQKEY_AUTH_KEY, KEY_SPEC_REQUESTOR_KEYRING, Key, Kind, LINK, LINK_LOCK,
    LOOKUP_CREATE, NEGATIVE_TIMEOUT, Need, Owner, POS, POS_ALL, Prep, Quota, READ, SEARCH, Search,
    Slot, USERS, USR, VIEW, WRITE, abort_link, alloc, begin_link, commit_link, insert_link, lookup,
    set_payload, user_rings,
};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
use rk_frame::task::WaitQueue;
use rk_vfs::cred::Cred;

/// The request of an authorization key, as `struct request_key_auth`.
pub(super) struct Auth {
    /// The key under construction.
    target: Arc<Key>,
    /// The destination keyring of the request.
    pub(super) dest: Option<Arc<Key>>,
    /// The credentials and the keyrings of the process that asked for the key. A revoke of the
    /// authorization key drops them, as `request_key_auth_revoke`.
    requestor: Option<Requestor>,
}

/// The credentials and the keyrings of the process that asked for a key, for the searches of the
/// helper, as `rka->cred`.
#[derive(Clone)]
pub(super) struct Requestor {
    pub(super) cred: Cred,
    rings: [Option<Arc<Key>>; 3],
    reqkey: u8,
}

impl Owner for Requestor {
    fn ring(&self, slot: Slot) -> Option<Arc<Key>> {
        self.rings[slot_index(slot)].clone()
    }

    fn set_ring(&self, slot: Slot, ring: Arc<Key>, _replace: bool) -> Arc<Key> {
        // A search does not make keyrings, so this is not called. The keyrings stay as they were.
        self.ring(slot).unwrap_or(ring)
    }

    fn reqkey(&self) -> u8 {
        self.reqkey
    }

    fn set_reqkey(&self, _value: u8) {}

    fn auth(&self) -> Option<Arc<Key>> {
        None
    }

    fn set_auth(&self, _auth: Option<Arc<Key>>) {}
}

fn slot_index(slot: Slot) -> usize {
    match slot {
        Slot::Thread => 0,
        Slot::Process => 1,
        Slot::Session => 2,
    }
}

/// The requestor of the authorization key `auth` if the key is valid, for the search of the
/// keyrings of the requestor.
pub(super) fn requestor(auth: &Key, now: u64) -> Option<Requestor> {
    auth.validate(now).ok()?;
    auth.state.lock().auth.as_ref()?.requestor.clone()
}

/// Drops the requestor of an authorization key, for its revoke.
pub(super) fn revoke_auth(key: &Key) {
    let old = key.state.lock().auth.as_mut().and_then(|a| a.requestor.take());
    drop(old);
}

/// The ends of key constructions wake this queue.
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
static CONSTRUCTED: WaitQueue = WaitQueue::new();

/// Waits until `key` is not under construction, as `wait_for_key_construction`.
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(super) fn wait(key: &Key) {
    CONSTRUCTED.wait_until(|| (!key.state.lock().pending).then_some(()));
}

/// The host has no tasks to wait on: its upcalls end before the construction does.
#[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
pub(super) fn wait(_key: &Key) {}

/// Wakes the waits for the end of a construction.
fn wake() {
    #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
    CONSTRUCTED.wake_all();
}

/// What the upcall gets: the arguments of `/sbin/request-key` and its session keyring, as
/// `call_sbin_request_key`.
pub struct Request {
    /// The operation: `create`.
    pub op: &'static [u8],
    /// The serial number of the key under construction.
    pub key: i32,
    /// The file system user ID of the requestor.
    pub uid: u32,
    /// The file system group ID of the requestor.
    pub gid: u32,
    /// The thread, process and session keyrings of the requestor, or 0. The session keyring is
    /// the user session keyring if the requestor has no session keyring.
    pub rings: [i32; 3],
    /// The session keyring of the helper, with the authorization key in it.
    pub session: Arc<Key>,
}

impl Request {
    /// The arguments of `/sbin/request-key`, after the path.
    pub fn args(&self) -> [Vec<u8>; 7] {
        let n = |v: i64| alloc::format!("{v}").into_bytes();
        [
            self.op.to_vec(),
            n(self.key.into()),
            n(self.uid.into()),
            n(self.gid.into()),
            n(self.rings[0].into()),
            n(self.rings[1].into()),
            n(self.rings[2].into()),
        ]
    }
}

/// Runs `/sbin/request-key` for a request and waits for its end, as `call_usermodehelper_keys`
/// with `UMH_WAIT_PROC`. Gives the exit status of the helper, or the error that stopped it.
pub type Upcall = fn(&Request) -> Result<i32, Errno>;

/// The upcall of the kernel. Without one, a construction fails as if the helper was not there.
static UPCALL: SpinLock<Option<Upcall>> = SpinLock::new(None);

/// Sets the upcall that runs `/sbin/request-key`.
pub fn set_upcall(upcall: Upcall) {
    *UPCALL.lock() = Some(upcall);
}

/// The permissions of an authorization key, as `request_key_auth_new`.
const AUTH_PERM: u32 = ((VIEW | READ | SEARCH | LINK) << POS) | (VIEW << USR);
/// The permissions of the session keyring of the helper, as `call_sbin_request_key`.
const REQ_PERM: u32 = POS_ALL | ((VIEW | READ) << USR);

/// Constructs a key of `kind` and `desc` in `dest`, as `construct_key_and_link`. Gives the key
/// after the construction, which can be negative.
///
/// # Errors
///
/// Gives `EDQUOT` or the error of the link of the key.
pub(super) fn construct(
    cx: &Caller<'_>,
    kind: Kind,
    desc: &[u8],
    callout: &[u8],
    dest: Arc<Key>,
) -> Result<Arc<Key>, Errno> {
    let key = alloc(
        kind,
        desc,
        cx.cred.fsuid,
        cx.cred.fsgid,
        kind.default_perm(),
        Quota::In,
        Prep::default(),
        None,
        false,
    )?;
    set_pending(&key);
    if let Err(e) = insert_link(&dest, &key) {
        complete(&key, cx.now);
        return Err(e);
    }
    let status = upcall(cx, &key, callout, dest);
    // As `call_sbin_request_key`: the helper must instantiate the key, whatever its status.
    if status.is_err() || key.state.lock().pending {
        complete(&key, cx.now);
    }
    Ok(key)
}

/// Makes the authorization key and the session keyring of the helper, and runs the upcall.
fn upcall(cx: &Caller<'_>, key: &Arc<Key>, callout: &[u8], dest: Arc<Key>) -> Result<i32, Errno> {
    let owner = cx.owner;
    let requestor = Requestor {
        cred: cx.cred.clone(),
        rings: [owner.ring(Slot::Thread), owner.ring(Slot::Process), owner.ring(Slot::Session)],
        reqkey: owner.reqkey(),
    };
    let desc = alloc::format!("{:x}", key.serial);
    let auth = alloc(
        Kind::RequestKeyAuth,
        desc.as_bytes(),
        cx.cred.fsuid,
        cx.cred.fsgid,
        AUTH_PERM,
        Quota::Overrun,
        Prep::new(callout.to_vec()),
        None,
        false,
    )?;
    auth.state.lock().auth =
        Some(Box::new(Auth { target: key.clone(), dest: Some(dest), requestor: Some(requestor) }));
    let serial = |slot| owner.ring(slot).map_or(0, |r: Arc<Key>| r.serial);
    let session = match owner.ring(Slot::Session) {
        Some(s) => s.serial,
        None => user_rings(cx)?.1.serial,
    };
    let name = alloc::format!("_req.{}", key.serial);
    let ring = alloc(
        Kind::Keyring,
        name.as_bytes(),
        cx.cred.fsuid,
        cx.cred.fsgid,
        REQ_PERM,
        Quota::Overrun,
        Prep::default(),
        None,
        false,
    )?;
    insert_link(&ring, &auth)?;
    let request = Request {
        op: b"create",
        key: key.serial,
        uid: cx.cred.fsuid,
        gid: cx.cred.fsgid,
        rings: [serial(Slot::Thread), serial(Slot::Process), session],
        session: ring,
    };
    let call = *UPCALL.lock();
    let status = call.map_or(Err(Errno::ENOENT), |f| f(&request));
    // As `complete_request_key`, the authorization ends with the construction.
    super::ctl::revoke_key(&auth);
    status
}

/// Marks a new key as under construction. It does not count as instantiated in
/// `/proc/key-users` until the construction ends.
fn set_pending(key: &Key) {
    let uid = {
        let mut s = key.state.lock();
        s.pending = true;
        s.uid
    };
    if let Some(u) = USERS.lock().get_mut(&uid) {
        u.nikeys -= 1;
    }
}

/// Ends the construction of `key` with a payload or an error. Gives `EBUSY` if the key is not
/// under construction.
fn finish(key: &Key, result: Result<Prep, (Errno, u64)>, now: u64) -> Result<(), Errno> {
    let (uid, old) = {
        let mut s = key.state.lock();
        if !s.pending {
            return Err(Errno::EBUSY);
        }
        let old = match result {
            Ok(prep) => {
                let old = set_payload(&mut s, prep.payload, prep.quota)?;
                s.error = prep.error;
                if prep.short {
                    s.expiry = now + 1;
                }
                old
            }
            Err((e, expiry)) => {
                s.negative = Some(e);
                s.expiry = expiry;
                Vec::new()
            }
        };
        s.pending = false;
        (s.uid, old)
    };
    if let Some(u) = USERS.lock().get_mut(&uid) {
        u.nikeys += 1;
    }
    drop(old);
    wake();
    Ok(())
}

/// Makes a key that is still under construction negative with `ENOKEY`, as
/// `key_negate_and_link` in `complete_request_key`.
fn complete(key: &Key, now: u64) {
    let _ = finish(key, Err((Errno::ENOKEY, now + NEGATIVE_TIMEOUT)), now);
}

/// Gives the key of the request after its construction, or the error of a negative key, as the
/// wait of `request_key_and_link`.
pub(super) fn result(key: &Key) -> Result<i32, Errno> {
    wait(key);
    match key.state.lock().negative {
        Some(e) => Err(e),
        None => Ok(key.serial),
    }
}

/// An assumed authority: the authorization key, the key under construction and the destination
/// keyring of the request.
type Authority = (Arc<Key>, Arc<Key>, Option<Arc<Key>>);

/// The authorization key that the caller assumed and the key that it may instantiate, as the
/// check of `keyctl_instantiate_key_common` and `keyctl_reject_key`.
fn authority(cx: &Caller<'_>, id: i32) -> Result<Authority, Errno> {
    let auth = cx.owner.auth().ok_or(Errno::EPERM)?;
    let (target, dest) = {
        let s = auth.state.lock();
        let a = s.auth.as_ref().ok_or(Errno::EPERM)?;
        (a.target.clone(), a.dest.clone())
    };
    if target.serial != id {
        return Err(Errno::EPERM);
    }
    Ok((auth, target, dest))
}

/// Checks that the caller assumed the authority to instantiate the key `id`.
///
/// # Errors
///
/// Gives `EPERM` if it did not.
pub fn check_authority(cx: &Caller<'_>, id: i32) -> Result<(), Errno> {
    authority(cx, id).map(|_| ())
}

/// The keyring where the instantiated key goes, as `get_instantiation_keyring`. 0 is no keyring,
/// and a special keyring is the destination keyring of the request.
fn dest_ring(
    cx: &Caller<'_>,
    ring: i32,
    dest: Option<Arc<Key>>,
) -> Result<Option<Arc<Key>>, Errno> {
    if ring == 0 {
        return Ok(None);
    }
    if ring > 0 {
        return Ok(Some(lookup(cx, ring, LOOKUP_CREATE, Need::Perm(WRITE))?.key));
    }
    if ring == KEY_SPEC_REQKEY_AUTH_KEY {
        return Err(Errno::EINVAL);
    }
    if ring >= KEY_SPEC_REQUESTOR_KEYRING {
        return Ok(dest);
    }
    Err(Errno::ENOKEY)
}

/// Ends a construction with `result` and links the key into `ring`, as
/// `key_instantiate_and_link` and `key_reject_and_link`. The authorization key is invalidated,
/// and the caller drops its authority.
fn end(
    cx: &Caller<'_>,
    auth: &Key,
    target: &Arc<Key>,
    ring: Option<Arc<Key>>,
    result: Result<Prep, (Errno, u64)>,
) -> Result<(), Errno> {
    let guard = LINK_LOCK.lock();
    let replace = match &ring {
        Some(r) => Some(begin_link(r, target.kind, &target.desc)?),
        None => None,
    };
    if let Err(e) = finish(target, result, cx.now) {
        if let (Some(r), Some(replace)) = (&ring, replace) {
            abort_link(r, replace);
        }
        return Err(e);
    }
    if let Some(r) = &ring {
        commit_link(r, target);
    }
    drop(guard);
    auth.invalidated.store(true, core::sync::atomic::Ordering::Relaxed);
    super::collect();
    cx.owner.set_auth(None);
    Ok(())
}

/// Instantiates the key under construction `id` with `payload` and links it into `ring`, as
/// `KEYCTL_INSTANTIATE`.
///
/// # Errors
///
/// Gives `EPERM` if the caller has no authority for the key, the error of the destination
/// keyring, `EINVAL` for a bad payload, `EDQUOT`, `EBUSY` if the key is not under construction,
/// or the error of the link.
pub fn instantiate(cx: &Caller<'_>, id: i32, payload: Vec<u8>, ring: i32) -> Result<(), Errno> {
    let (auth, target, dest) = authority(cx, id)?;
    let ring = dest_ring(cx, ring, dest)?;
    let payload = target.kind.preparse(payload)?;
    end(cx, &auth, &target, ring, Ok(payload))
}

/// Makes the key under construction `id` negative with `error` for `timeout` seconds and links
/// it into `ring`, as `KEYCTL_REJECT`. `KEYCTL_NEGATE` is a reject with `ENOKEY`.
///
/// # Errors
///
/// Gives `EPERM` if the caller has no authority for the key, the error of the destination
/// keyring, `EBUSY` if the key is not under construction, or the error of the link.
pub fn reject(
    cx: &Caller<'_>,
    id: i32,
    timeout: u32,
    error: Errno,
    ring: i32,
) -> Result<(), Errno> {
    let (auth, target, dest) = authority(cx, id)?;
    let ring = dest_ring(cx, ring, dest)?;
    end(cx, &auth, &target, ring, Err((error, cx.now + u64::from(timeout))))
}

/// Assumes the authority to instantiate the key `id`, as `KEYCTL_ASSUME_AUTHORITY`. The caller
/// must find the authorization key of `id` in its keyrings. 0 drops the authority. Gives the
/// serial number of the authorization key, or 0.
///
/// # Errors
///
/// Gives `EINVAL` for a negative ID, `ENOKEY` if the caller cannot find the authorization key,
/// or `EKEYREVOKED` if it is revoked.
pub fn assume_authority(cx: &Caller<'_>, id: i32) -> Result<i32, Errno> {
    if id < 0 {
        return Err(Errno::EINVAL);
    }
    if id == 0 {
        cx.owner.set_auth(None);
        return Ok(0);
    }
    let desc = alloc::format!("{id:x}");
    let search = Search {
        cx,
        target: None,
        kind: Kind::RequestKeyAuth,
        desc: desc.as_bytes(),
        state_check: true,
        skip_expired: false,
        check_perm: true,
    };
    let auth = match search.in_process() {
        Ok(k) => k,
        Err(Errno::EAGAIN) => return Err(Errno::ENOKEY),
        Err(e) => return Err(e),
    };
    if auth.state.lock().revoked {
        return Err(Errno::EKEYREVOKED);
    }
    let serial = auth.serial;
    cx.owner.set_auth(Some(auth));
    Ok(serial)
}

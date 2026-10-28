//! The operations of `add_key`, `request_key` and `keyctl`, in the order of the checks of Linux.
//!
//! The system calls copy the strings and the payloads from user memory, and give them here.

use super::{
    Caller, Kind, LINK, LINK_LOCK, LOOKUP_CREATE, LOOKUP_PARTIAL, NEGATIVE_TIMEOUT, NO_GID, Need,
    Quota, READ, SEARCH, SESSION_PERM, SETATTR, Search, Slot, USERS, VIEW, WRITE, abort_link,
    all_keys, alloc, begin_link, check_cycle, collect, commit_link, insert_link, limits, lookup,
    permission, process_ring, remove_link, set_payload, thread_ring, uncharge, user_rings,
};
use super::{GRP_ALL, Key, OTH_ALL, POS_ALL, USR_ALL};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use rk_abi::Errno;
use rk_abi::native::keyctl::{
    KEY_REQKEY_DEFL_DEFAULT, KEY_REQKEY_DEFL_NO_CHANGE, KEY_REQKEY_DEFL_PROCESS_KEYRING,
    KEY_REQKEY_DEFL_REQUESTOR_KEYRING, KEY_REQKEY_DEFL_SESSION_KEYRING,
    KEY_REQKEY_DEFL_THREAD_KEYRING, KEY_REQKEY_DEFL_USER_KEYRING,
    KEY_REQKEY_DEFL_USER_SESSION_KEYRING, KEY_SPEC_SESSION_KEYRING, KEYCTL_CAPS0_CAPABILITIES,
    KEYCTL_CAPS0_INVALIDATE, KEYCTL_CAPS0_MOVE, KEYCTL_CAPS0_RESTRICT_KEYRING,
    KEYCTL_CAPS1_NS_KEY_TAG, KEYCTL_CAPS1_NS_KEYRING_NAME, KEYCTL_MOVE_EXCL,
};
use rk_vfs::cred::{Cred, cap};

/// The overflow ID that a key with no group shows.
const OVERFLOW_ID: u32 = 65534;

/// Adds a key to the keyring `ring`, or changes the payload of the key with the same type and
/// description there, as `add_key`.
///
/// `desc` is `None` if the pointer was null or the description was empty.
///
/// # Errors
///
/// Gives the error of the lookup of `ring`, `ENODEV` for an unknown type, `ENOTDIR`, `EINVAL`
/// for a bad payload or description, `EDQUOT`, `EPERM` for a restricted keyring, or `EACCES` if
/// the key to change has no write permission.
pub fn add_key(
    cx: &Caller<'_>,
    kind: &[u8],
    desc: Option<&[u8]>,
    payload: Vec<u8>,
    ring: i32,
) -> Result<i32, Errno> {
    let ring = lookup(cx, ring, LOOKUP_CREATE, Need::Perm(WRITE))?;
    let kind = Kind::from_name(kind).ok_or(Errno::ENODEV)?;
    if !ring.key.is_keyring() {
        return Err(Errno::ENOTDIR);
    }
    kind.check_payload(&payload)?;
    let desc = desc.ok_or(Errno::EINVAL)?;
    let _g = LINK_LOCK.lock();
    let replace = begin_link(&ring.key, kind, desc)?;
    if kind.can_update() {
        let old = ring.key.links().into_iter().find(|k| {
            k.kind == kind && k.desc == desc && !k.is_invalidated() && !k.state.lock().revoked
        });
        if let Some(key) = old {
            abort_link(&ring.key, replace);
            permission(cx, &key, ring.possessed, WRITE)?;
            change_payload(&key, payload)?;
            return Ok(key.serial);
        }
    }
    let key = alloc(
        kind,
        desc,
        cx.cred.fsuid,
        cx.cred.fsgid,
        kind.default_perm(),
        Quota::In,
        payload,
        None,
        false,
    );
    let key = match key {
        Ok(k) => k,
        Err(e) => {
            abort_link(&ring.key, replace);
            return Err(e);
        }
    };
    commit_link(&ring.key, &key);
    Ok(key.serial)
}

/// Puts a new payload in `key` and makes it positive, as `__key_update`. The old payload goes
/// after the lock.
fn change_payload(key: &Key, payload: Vec<u8>) -> Result<(), Errno> {
    let old = {
        let mut s = key.state.lock();
        let old = set_payload(&mut s, payload)?;
        if s.negative.take().is_some() {
            s.expiry = 0;
        }
        old
    };
    drop(old);
    Ok(())
}

/// Finds a key, as `request_key`. There is no upcall: if no key matches, and the caller gives
/// callout information, a negative key goes in the destination keyring and the call gives
/// `ENOKEY`.
///
/// # Errors
///
/// Gives the error of the lookup of `dest`, `ENOKEY` for an unknown type or no key, the error of
/// a negative, revoked or expired key, `EPERM` for a `keyring` that is not there, `EACCES` if the
/// default keyring has no write permission, or the error of the link.
pub fn request_key(
    cx: &Caller<'_>,
    kind: &[u8],
    desc: &[u8],
    callout: Option<&[u8]>,
    dest: i32,
) -> Result<i32, Errno> {
    let dest = if dest != 0 {
        Some(lookup(cx, dest, LOOKUP_CREATE, Need::Perm(WRITE))?.key)
    } else {
        None
    };
    let kind = Kind::from_name(kind).ok_or(Errno::ENOKEY)?;
    let search = Search {
        cx,
        target: None,
        kind,
        desc,
        state_check: true,
        skip_expired: true,
        check_perm: true,
    };
    match search.in_process() {
        Ok(key) => {
            if let Some(d) = &dest {
                insert_link(d, &key)?;
            }
            return Ok(key.serial);
        }
        Err(Errno::EAGAIN) => {}
        Err(e) => return Err(e),
    }
    if callout.is_none() {
        return Err(Errno::ENOKEY);
    }
    if kind == Kind::Keyring {
        return Err(Errno::EPERM);
    }
    let dest = match dest {
        Some(d) => d,
        None => {
            let d = default_ring(cx)?;
            permission(cx, &d, true, WRITE)?;
            d
        }
    };
    let expiry = cx.now + NEGATIVE_TIMEOUT;
    let key = alloc(
        kind,
        desc,
        cx.cred.fsuid,
        cx.cred.fsgid,
        kind.default_perm(),
        Quota::In,
        Vec::new(),
        Some((Errno::ENOKEY, expiry)),
        false,
    )?;
    insert_link(&dest, &key)?;
    Err(Errno::ENOKEY)
}

/// The default keyring of `request_key`, as `construct_get_dest_keyring`.
fn default_ring(cx: &Caller<'_>) -> Result<Arc<Key>, Errno> {
    let owner = cx.owner;
    let mut step = i32::from(owner.reqkey());
    if step == KEY_REQKEY_DEFL_DEFAULT || step == KEY_REQKEY_DEFL_REQUESTOR_KEYRING {
        step = KEY_REQKEY_DEFL_THREAD_KEYRING;
    }
    if step == KEY_REQKEY_DEFL_USER_KEYRING {
        return Ok(user_rings(cx)?.0);
    }
    let slots = [
        (KEY_REQKEY_DEFL_THREAD_KEYRING, Slot::Thread),
        (KEY_REQKEY_DEFL_PROCESS_KEYRING, Slot::Process),
        (KEY_REQKEY_DEFL_SESSION_KEYRING, Slot::Session),
    ];
    for (value, slot) in slots {
        if step <= value
            && let Some(r) = owner.ring(slot)
        {
            return Ok(r);
        }
    }
    Ok(user_rings(cx)?.1)
}

/// Gives the serial number of the key of `id`, as `KEYCTL_GET_KEYRING_ID`. If `create` is true,
/// a special keyring that is not there is made.
///
/// # Errors
///
/// Gives the error of the lookup.
pub fn get_keyring_id(cx: &Caller<'_>, id: i32, create: bool) -> Result<i32, Errno> {
    let flags = if create { LOOKUP_CREATE } else { 0 };
    Ok(lookup(cx, id, flags, Need::Perm(SEARCH))?.key.serial)
}

/// Joins a new anonymous session keyring, or the keyring with the name `name`, as
/// `KEYCTL_JOIN_SESSION_KEYRING`. Makes the named keyring if the caller cannot find it. Gives
/// the serial number, or 0 if the keyring is the session keyring already.
///
/// # Errors
///
/// Gives `EPERM` for a name that starts with a period, `EINVAL` for an empty name, or `EDQUOT`.
pub fn join_session(cx: &Caller<'_>, name: Option<&[u8]>) -> Result<i32, Errno> {
    let Some(name) = name else {
        return Ok(super::new_session(cx)?.serial);
    };
    if name.first() == Some(&b'.') {
        return Err(Errno::EPERM);
    }
    let ring = match find_by_name(cx, name) {
        Some(r) => {
            if cx.owner.ring(Slot::Session).is_some_and(|s| Arc::ptr_eq(&s, &r)) {
                return Ok(0);
            }
            r
        }
        None => alloc(
            Kind::Keyring,
            name,
            cx.cred.uid,
            cx.cred.gid,
            SESSION_PERM,
            Quota::In,
            Vec::new(),
            None,
            false,
        )?,
    };
    let serial = ring.serial;
    cx.owner.set_ring(Slot::Session, ring, true);
    Ok(serial)
}

/// A keyring with the description `name` that the caller can search, as
/// `find_keyring_by_name`. The user keyrings are not in the search.
fn find_by_name(cx: &Caller<'_>, name: &[u8]) -> Option<Arc<Key>> {
    // The walk takes a reference only to the key that it gives. A dead key does not give one.
    all_keys()
        .iter()
        .filter(|k| {
            k.is_keyring()
                && !k.uid_ring
                && k.desc == name
                && !k.is_invalidated()
                && !k.state.lock().revoked
                && permission(cx, k, false, SEARCH).is_ok()
        })
        .find_map(|k| k.this.upgrade())
}

/// Changes the payload of a key, as `KEYCTL_UPDATE`.
///
/// # Errors
///
/// Gives the error of the lookup, `EOPNOTSUPP` for a keyring, `EINVAL` for a bad payload, or
/// `EDQUOT`.
pub fn update(cx: &Caller<'_>, id: i32, payload: Vec<u8>) -> Result<(), Errno> {
    let r = lookup(cx, id, 0, Need::Perm(WRITE))?;
    if !r.key.kind.can_update() {
        return Err(Errno::EOPNOTSUPP);
    }
    r.key.kind.check_payload(&payload)?;
    change_payload(&r.key, payload)
}

/// Revokes a key, as `KEYCTL_REVOKE`. The write or the setattr permission is necessary. The
/// payload and the links of a keyring go at once.
///
/// # Errors
///
/// Gives the error of the lookup.
pub fn revoke(cx: &Caller<'_>, id: i32) -> Result<(), Errno> {
    let r = match lookup(cx, id, 0, Need::Perm(WRITE)) {
        Err(Errno::EACCES) => lookup(cx, id, 0, Need::Perm(SETATTR))?,
        r => r?,
    };
    let (payload, links) = {
        let mut s = r.key.state.lock();
        if s.revoked {
            return Ok(());
        }
        s.revoked = true;
        let links = core::mem::take(&mut s.links);
        uncharge(&mut s, links.len() as u32 * super::LINK_BYTES);
        (set_payload(&mut s, Vec::new()), links)
    };
    drop(payload);
    drop(links);
    Ok(())
}

/// Changes the owner and the group of a key, as `KEYCTL_CHOWN`. `u32::MAX` keeps the value.
///
/// # Errors
///
/// Gives the error of the lookup, `EACCES` for a change that needs `CAP_SYS_ADMIN`, or `EDQUOT`
/// if the key does not fit in the quota of the new owner.
pub fn chown(cx: &Caller<'_>, id: i32, uid: u32, gid: u32) -> Result<(), Errno> {
    if uid == u32::MAX && gid == u32::MAX {
        return Ok(());
    }
    let r = lookup(cx, id, LOOKUP_CREATE | LOOKUP_PARTIAL, Need::Perm(SETATTR))?;
    let admin = cx.cred.capable(cap::SYS_ADMIN);
    let mut s = r.key.state.lock();
    if !admin {
        if uid != u32::MAX && uid != s.uid {
            return Err(Errno::EACCES);
        }
        if gid != u32::MAX && gid != s.gid && !cx.cred.in_group(gid) {
            return Err(Errno::EACCES);
        }
    }
    if uid != u32::MAX && uid != s.uid {
        let (maxkeys, maxbytes) = limits(uid);
        let bytes = s.quota_bytes;
        let mut users = USERS.lock();
        let new = users.entry(uid).or_default();
        if new.qnkeys + 1 > maxkeys || new.qnbytes.checked_add(bytes).is_none_or(|n| n > maxbytes) {
            if new.nkeys == 0 {
                users.remove(&uid);
            }
            return Err(Errno::EDQUOT);
        }
        new.qnkeys += 1;
        new.qnbytes += bytes;
        new.nkeys += 1;
        new.nikeys += 1;
        if let Some(old) = users.get_mut(&s.uid) {
            old.qnkeys -= 1;
            old.qnbytes -= bytes;
            old.nkeys -= 1;
            old.nikeys -= 1;
            if old.nkeys == 0 {
                users.remove(&s.uid);
            }
        }
        s.uid = uid;
    }
    if gid != u32::MAX {
        s.gid = gid;
    }
    Ok(())
}

/// Sets the permissions of a key, as `KEYCTL_SETPERM`. Only the owner and `CAP_SYS_ADMIN` can.
///
/// # Errors
///
/// Gives `EINVAL` for unknown bits, the error of the lookup, or `EACCES`.
pub fn set_perm(cx: &Caller<'_>, id: i32, perm: u32) -> Result<(), Errno> {
    if perm & !(POS_ALL | USR_ALL | GRP_ALL | OTH_ALL) != 0 {
        return Err(Errno::EINVAL);
    }
    let r = lookup(cx, id, LOOKUP_CREATE | LOOKUP_PARTIAL, Need::Perm(SETATTR))?;
    let mut s = r.key.state.lock();
    if s.uid != cx.cred.fsuid && !cx.cred.capable(cap::SYS_ADMIN) {
        return Err(Errno::EACCES);
    }
    s.perm = perm;
    Ok(())
}

/// The description of a key, as `KEYCTL_DESCRIBE`: `type;uid;gid;perm;description` and a zero
/// byte.
///
/// # Errors
///
/// Gives the error of the lookup.
pub fn describe(cx: &Caller<'_>, id: i32) -> Result<Vec<u8>, Errno> {
    let r = lookup(cx, id, LOOKUP_PARTIAL, Need::Perm(VIEW))?;
    let (uid, gid, perm) = {
        let s = r.key.state.lock();
        (s.uid, s.gid, s.perm)
    };
    let gid = if gid == NO_GID { OVERFLOW_ID } else { gid };
    let mut out =
        alloc::format!("{};{};{};{:08x};", r.key.kind.name(), uid as i32, gid as i32, perm)
            .into_bytes();
    out.extend_from_slice(&r.key.desc);
    out.push(0);
    Ok(out)
}

/// Removes all the links of a keyring, as `KEYCTL_CLEAR`.
///
/// # Errors
///
/// Gives the error of the lookup, or `ENOTDIR`.
pub fn clear(cx: &Caller<'_>, id: i32) -> Result<(), Errno> {
    let r = lookup(cx, id, LOOKUP_CREATE, Need::Perm(WRITE))?;
    if !r.key.is_keyring() {
        return Err(Errno::ENOTDIR);
    }
    let links = {
        let mut s = r.key.state.lock();
        let links = core::mem::take(&mut s.links);
        uncharge(&mut s, links.len() as u32 * super::LINK_BYTES);
        links
    };
    drop(links);
    Ok(())
}

/// Links a key into a keyring, as `KEYCTL_LINK`.
///
/// # Errors
///
/// Gives the error of a lookup or of the link.
pub fn link(cx: &Caller<'_>, id: i32, ring: i32) -> Result<(), Errno> {
    let ring = lookup(cx, ring, LOOKUP_CREATE, Need::Perm(WRITE))?;
    let key = lookup(cx, id, LOOKUP_CREATE, Need::Perm(LINK))?;
    insert_link(&ring.key, &key.key)
}

/// Removes the link to a key from a keyring, as `KEYCTL_UNLINK`.
///
/// # Errors
///
/// Gives the error of a lookup, `ENOTDIR`, or `ENOENT` if the keyring has no link to the key.
pub fn unlink(cx: &Caller<'_>, id: i32, ring: i32) -> Result<(), Errno> {
    let ring = lookup(cx, ring, 0, Need::Perm(WRITE))?;
    let key = lookup(cx, id, LOOKUP_PARTIAL, Need::Unlink)?;
    if !ring.key.is_keyring() {
        return Err(Errno::ENOTDIR);
    }
    let _g = LINK_LOCK.lock();
    remove_link(&ring.key, &key.key)
}

/// Moves the link to a key from one keyring to another, as `KEYCTL_MOVE`.
///
/// # Errors
///
/// Gives `EINVAL` for unknown flags, the error of a lookup, `ENOTDIR`, `ENOENT` if `from` has no
/// link to the key, `EEXIST` with `KEYCTL_MOVE_EXCL` if `to` has a key of the same type and
/// description, or the error of the link.
pub fn move_key(cx: &Caller<'_>, id: i32, from: i32, to: i32, flags: u32) -> Result<(), Errno> {
    if flags & !(KEYCTL_MOVE_EXCL as u32) != 0 {
        return Err(Errno::EINVAL);
    }
    let key = lookup(cx, id, LOOKUP_CREATE, Need::Perm(LINK))?.key;
    let from = lookup(cx, from, 0, Need::Perm(WRITE))?.key;
    let to = lookup(cx, to, LOOKUP_CREATE, Need::Perm(WRITE))?.key;
    if Arc::ptr_eq(&from, &to) {
        return Ok(());
    }
    if !from.is_keyring() || !to.is_keyring() {
        return Err(Errno::ENOTDIR);
    }
    let _g = LINK_LOCK.lock();
    if !from.links().iter().any(|k| Arc::ptr_eq(k, &key)) {
        return Err(Errno::ENOENT);
    }
    let replace = begin_link(&to, key.kind, &key.desc)?;
    let check = if replace && flags & KEYCTL_MOVE_EXCL as u32 != 0 {
        Err(Errno::EEXIST)
    } else {
        check_cycle(&to, &key)
    };
    if let Err(e) = check {
        abort_link(&to, replace);
        return Err(e);
    }
    remove_link(&from, &key)?;
    commit_link(&to, &key);
    Ok(())
}

/// Searches the tree of a keyring for a key, as `KEYCTL_SEARCH`, and links the key into `dest`
/// if it is not 0.
///
/// # Errors
///
/// Gives the error of a lookup, `ENOKEY` for an unknown type or no key, the error of the search,
/// or the error of the link.
pub fn search(
    cx: &Caller<'_>,
    ring: i32,
    kind: &[u8],
    desc: &[u8],
    dest: i32,
) -> Result<i32, Errno> {
    let ring = lookup(cx, ring, 0, Need::Perm(SEARCH))?;
    let dest = if dest != 0 {
        Some(lookup(cx, dest, LOOKUP_CREATE, Need::Perm(WRITE))?.key)
    } else {
        None
    };
    let kind = Kind::from_name(kind).ok_or(Errno::ENOKEY)?;
    let search = Search {
        cx,
        target: None,
        kind,
        desc,
        state_check: true,
        skip_expired: false,
        check_perm: true,
    };
    let key = match search.in_ring(&ring.key, ring.possessed) {
        Err(Errno::EAGAIN) => return Err(Errno::ENOKEY),
        r => r?,
    };
    if let Some(d) = dest {
        permission(cx, &key, ring.possessed, LINK)?;
        insert_link(&d, &key)?;
    }
    Ok(key.serial)
}

/// Reads the payload of a key, or the serial numbers of the links of a keyring, as
/// `KEYCTL_READ`. `buflen` is the size of the buffer of the caller, or 0 if it gave no buffer.
/// Gives the full length and the bytes to copy. The bytes are empty if they do not fit.
///
/// # Errors
///
/// Gives `ENOKEY` if the lookup fails, the error of a negative key, `EACCES`, `EOPNOTSUPP` for
/// a type that the caller cannot read, the error of the state of the key, or `EINVAL` for a
/// keyring and a length that is not a multiple of 4.
pub fn read(cx: &Caller<'_>, id: i32, buflen: usize) -> Result<(usize, Vec<u8>), Errno> {
    let r = lookup(cx, id, 0, Need::Defer).map_err(|_| Errno::ENOKEY)?;
    let key = &r.key;
    if let Some(e) = key.state.lock().negative {
        return Err(e);
    }
    match permission(cx, key, r.possessed, READ) {
        Ok(()) => {}
        Err(_) if r.possessed => {}
        Err(e) => return Err(e),
    }
    if !key.kind.can_read() {
        return Err(Errno::EOPNOTSUPP);
    }
    key.validate(cx.now)?;
    if key.is_keyring() {
        // Linux reads into a kernel buffer of `buflen` bytes, or of no bytes for a buffer
        // larger than a page, and checks the size of that buffer.
        let kbuf = if buflen <= crate::PAGE_SIZE { buflen } else { 0 };
        if kbuf % 4 != 0 {
            return Err(Errno::EINVAL);
        }
        let links = key.links();
        let full = links.len() * 4;
        if full > buflen {
            return Ok((full, Vec::new()));
        }
        let out = links.iter().flat_map(|k| k.serial.to_ne_bytes()).collect();
        return Ok((full, out));
    }
    let s = key.state.lock();
    let full = s.payload.len();
    let out = if full <= buflen { s.payload.clone() } else { Vec::new() };
    Ok((full, out))
}

/// Sets the default keyring of `request_key`, as `KEYCTL_SET_REQKEY_KEYRING`. Gives the old
/// value.
///
/// # Errors
///
/// Gives `EINVAL` for a bad value, or the error of the creation of the thread or process
/// keyring.
pub fn set_reqkey(cx: &Caller<'_>, value: i32) -> Result<i32, Errno> {
    let old = i32::from(cx.owner.reqkey());
    match value {
        KEY_REQKEY_DEFL_NO_CHANGE => return Ok(old),
        KEY_REQKEY_DEFL_THREAD_KEYRING => {
            thread_ring(cx)?;
        }
        KEY_REQKEY_DEFL_PROCESS_KEYRING => {
            process_ring(cx)?;
        }
        KEY_REQKEY_DEFL_DEFAULT
        | KEY_REQKEY_DEFL_SESSION_KEYRING
        | KEY_REQKEY_DEFL_USER_KEYRING
        | KEY_REQKEY_DEFL_USER_SESSION_KEYRING
        | KEY_REQKEY_DEFL_REQUESTOR_KEYRING => {}
        _ => return Err(Errno::EINVAL),
    }
    cx.owner.set_reqkey(value as u8);
    Ok(old)
}

/// Sets the timeout of a key in seconds, as `KEYCTL_SET_TIMEOUT`. 0 removes the timeout.
///
/// # Errors
///
/// Gives the error of the lookup.
pub fn set_timeout(cx: &Caller<'_>, id: i32, seconds: u32) -> Result<(), Errno> {
    let r = lookup(cx, id, LOOKUP_CREATE | LOOKUP_PARTIAL, Need::Perm(SETATTR))?;
    r.key.state.lock().expiry = if seconds == 0 { 0 } else { cx.now + u64::from(seconds) };
    Ok(())
}

/// The security label of a key, as `KEYCTL_GET_SECURITY`. There is no security module, so the
/// label is empty: one zero byte.
///
/// # Errors
///
/// Gives the error of the lookup, and `ENOKEY` for a key that the caller cannot view.
pub fn get_security(cx: &Caller<'_>, id: i32) -> Result<Vec<u8>, Errno> {
    match lookup(cx, id, LOOKUP_PARTIAL, Need::Perm(VIEW)) {
        Ok(_) => Ok(alloc::vec![0]),
        // The caller has no authorization key that permits the view.
        Err(Errno::EACCES) => Err(Errno::ENOKEY),
        Err(e) => Err(e),
    }
}

/// Invalidates a key, as `KEYCTL_INVALIDATE`. The key leaves all the keyrings at once.
///
/// # Errors
///
/// Gives the error of the lookup.
pub fn invalidate(cx: &Caller<'_>, id: i32) -> Result<(), Errno> {
    let r = lookup(cx, id, 0, Need::Perm(SEARCH))?;
    r.key.invalidated.store(true, Ordering::Relaxed);
    drop(r);
    collect();
    Ok(())
}

/// Restricts the links that a keyring accepts, as `KEYCTL_RESTRICT_KEYRING`. With no type and
/// no restriction, the keyring accepts no new links. No type of rukernel has a restriction.
///
/// # Errors
///
/// Gives `EINVAL` for a type without a restriction or a restriction without a type, the error
/// of the lookup, `ENOTDIR`, `ENOKEY` for an unknown type, `ENOENT` for a type without
/// restrictions, or `EEXIST` if the keyring has a restriction.
pub fn restrict(
    cx: &Caller<'_>,
    id: i32,
    kind: Option<&[u8]>,
    restriction: Option<&[u8]>,
) -> Result<(), Errno> {
    if kind.is_some() != restriction.is_some() {
        return Err(Errno::EINVAL);
    }
    let r = lookup(cx, id, 0, Need::Perm(SETATTR))?;
    if !r.key.is_keyring() {
        return Err(Errno::ENOTDIR);
    }
    if let Some(kind) = kind {
        Kind::from_name(kind).ok_or(Errno::ENOKEY)?;
        return Err(Errno::ENOENT);
    }
    let mut s = r.key.state.lock();
    if s.restricted {
        return Err(Errno::EEXIST);
    }
    s.restricted = true;
    Ok(())
}

/// The parent process of the caller, for [`session_to_parent`].
pub struct Parent<'a> {
    /// The parent is init or a kernel thread.
    pub is_init: bool,
    /// The parent has one thread.
    pub single_thread: bool,
    /// The credentials of the parent.
    pub cred: &'a Cred,
    /// The keyrings of the parent.
    pub owner: &'a dyn super::Owner,
}

/// Gives the session keyring of the caller to its parent, as `KEYCTL_SESSION_TO_PARENT`.
/// `parent` is `None` if the caller has no parent.
///
/// # Errors
///
/// Gives the error of the lookup of the session keyring, or `EPERM` if the parent is init, has
/// more than one thread, or has other credentials.
pub fn session_to_parent(cx: &Caller<'_>, parent: Option<Parent<'_>>) -> Result<(), Errno> {
    let ring = lookup(cx, KEY_SPEC_SESSION_KEYRING, 0, Need::Perm(LINK))?.key;
    let parent = parent.ok_or(Errno::EPERM)?;
    if parent.is_init || !parent.single_thread {
        return Err(Errno::EPERM);
    }
    let old = parent.owner.ring(Slot::Session);
    if old.as_ref().is_some_and(|o| Arc::ptr_eq(o, &ring)) {
        return Ok(());
    }
    let (me, p) = (cx.cred, parent.cred);
    if p.uid != me.euid
        || p.euid != me.euid
        || p.suid != me.euid
        || p.gid != me.egid
        || p.egid != me.egid
        || p.sgid != me.egid
    {
        return Err(Errno::EPERM);
    }
    if old.is_some_and(|o| o.state.lock().uid != me.euid) || ring.state.lock().uid != me.euid {
        return Err(Errno::EPERM);
    }
    parent.owner.set_ring(Slot::Session, ring, true);
    Ok(())
}

/// The capabilities of the key service, as `KEYCTL_CAPABILITIES`.
pub fn capabilities() -> [u8; 2] {
    let caps0 = KEYCTL_CAPS0_CAPABILITIES
        | KEYCTL_CAPS0_INVALIDATE
        | KEYCTL_CAPS0_RESTRICT_KEYRING
        | KEYCTL_CAPS0_MOVE;
    let caps1 = KEYCTL_CAPS1_NS_KEYRING_NAME | KEYCTL_CAPS1_NS_KEY_TAG;
    [caps0 as u8, caps1 as u8]
}

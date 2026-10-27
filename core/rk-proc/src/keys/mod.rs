//! The key retention service, as `security/keys` of Linux: the keys and the keyrings of
//! `add_key`, `request_key` and `keyctl`.
//!
//! A key has a type, a description, an owner, a group, permissions and a payload. The types are
//! `user`, `logon` and `keyring`. A keyring holds links to other keys. Each thread can have a
//! thread keyring, each process a process keyring and a session keyring, and each user has a user
//! keyring and a user session keyring. A key is possessed when the caller can find it from these
//! keyrings, and the possessor bits of its permissions then apply too.
//!
//! The functions here do not touch user memory or the clock. The system calls copy the strings
//! and the payload, and give the time in a `Caller`, so the host tests can run them.
//!
//! There is no upcall to `/sbin/request-key`: `request_key` makes a negative key and gives
//! `ENOKEY`. There is no request key authorization key, so `KEYCTL_INSTANTIATE` and its family
//! give `EPERM`.
//!
//! The locks: each key has its own lock, and the code takes one key lock at a time. `LINK_LOCK`
//! makes link, unlink and move one operation at a time, so the cycle check stays true. The table of
//! serial numbers and the table of quotas are the last locks: the code takes no other lock while
//! it holds one of them, and drops no key there.

mod ctl;
mod text;

#[cfg(test)]
mod tests;

pub use ctl::{
    Parent, add_key, capabilities, chown, clear, describe, get_keyring_id, get_security,
    invalidate, join_session, link, move_key, read, request_key, restrict, revoke, search,
    session_to_parent, set_perm, set_reqkey, set_timeout, unlink, update,
};
pub use text::{key_users_text, keys_text};

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::keyctl::{
    KEY_SPEC_GROUP_KEYRING, KEY_SPEC_PROCESS_KEYRING, KEY_SPEC_REQKEY_AUTH_KEY,
    KEY_SPEC_REQUESTOR_KEYRING, KEY_SPEC_SESSION_KEYRING, KEY_SPEC_THREAD_KEYRING,
    KEY_SPEC_USER_KEYRING, KEY_SPEC_USER_SESSION_KEYRING,
};
use rk_frame::sync::SpinLock;
use rk_vfs::cred::Cred;

/// The permission to read the attributes of a key.
pub const VIEW: u32 = 0x01;
/// The permission to read the payload of a key, or the list of a keyring.
pub const READ: u32 = 0x02;
/// The permission to change the payload of a key, or to add and remove links of a keyring.
pub const WRITE: u32 = 0x04;
/// The permission to find a key in a search, or to search a keyring.
pub const SEARCH: u32 = 0x08;
/// The permission to link a key into a keyring.
pub const LINK: u32 = 0x10;
/// The permission to change the owner, the permissions and the timeout of a key.
pub const SETATTR: u32 = 0x20;
/// All the permissions of one class.
pub const ALL: u32 = 0x3f;

/// The shift of the permissions of the possessor.
const POS: u32 = 24;
/// The shift of the permissions of the owner.
const USR: u32 = 16;
/// The shift of the permissions of the group.
const GRP: u32 = 8;

/// All the permissions of the possessor.
pub const POS_ALL: u32 = ALL << POS;
/// All the permissions of the owner.
pub const USR_ALL: u32 = ALL << USR;
/// All the permissions of the group.
pub const GRP_ALL: u32 = ALL << GRP;
/// All the permissions of the other users.
pub const OTH_ALL: u32 = ALL;

/// The group of a key that has no group. Linux shows it as the overflow group.
pub const NO_GID: u32 = u32::MAX;

/// The longest description, with its zero byte. Linux names it `KEY_MAX_DESC_SIZE`.
pub const MAX_DESC: usize = 4096;
/// The longest name of a key type, with its zero byte.
pub const MAX_TYPE: usize = 32;
/// The largest payload of `add_key`.
pub const MAX_PAYLOAD: usize = 1024 * 1024 - 1;
/// The largest payload of a `user` or `logon` key.
const MAX_USER_PAYLOAD: usize = 32767;
/// The bytes of quota that each link of a keyring takes. Linux names it `KEYQUOTA_LINK_BYTES`.
const LINK_BYTES: u32 = 4;
/// The deepest nesting of keyrings that a search goes into.
const MAX_DEPTH: usize = 6;
/// The seconds that a negative key of `request_key` lives.
const NEGATIVE_TIMEOUT: u64 = 60;

/// The most keys of a user other than root: `/proc/sys/kernel/keys/maxkeys`.
pub static MAXKEYS: AtomicU32 = AtomicU32::new(200);
/// The most bytes of the keys of a user other than root: `/proc/sys/kernel/keys/maxbytes`.
pub static MAXBYTES: AtomicU32 = AtomicU32::new(20000);
/// The most keys of root: `/proc/sys/kernel/keys/root_maxkeys`.
pub static ROOT_MAXKEYS: AtomicU32 = AtomicU32::new(1_000_000);
/// The most bytes of the keys of root: `/proc/sys/kernel/keys/root_maxbytes`.
pub static ROOT_MAXBYTES: AtomicU32 = AtomicU32::new(25_000_000);
/// The seconds before the removal of a revoked or expired key: `/proc/sys/kernel/keys/gc_delay`.
/// The kernel keeps the value, but it removes only invalidated keys and keys with no reference.
pub static GC_DELAY: AtomicU32 = AtomicU32::new(300);

/// The limits of the quota of `uid`: the most keys and the most bytes.
fn limits(uid: u32) -> (u32, u32) {
    if uid == 0 {
        (ROOT_MAXKEYS.load(Ordering::Relaxed), ROOT_MAXBYTES.load(Ordering::Relaxed))
    } else {
        (MAXKEYS.load(Ordering::Relaxed), MAXBYTES.load(Ordering::Relaxed))
    }
}

/// The type of a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A key with a payload that a process can read.
    User,
    /// A key with a payload that only the kernel can read.
    Logon,
    /// A key that holds links to other keys.
    Keyring,
}

impl Kind {
    /// The name of the type.
    pub fn name(self) -> &'static str {
        match self {
            Kind::User => "user",
            Kind::Logon => "logon",
            Kind::Keyring => "keyring",
        }
    }

    /// The type with the name `name`.
    pub fn from_name(name: &[u8]) -> Option<Self> {
        match name {
            b"user" => Some(Kind::User),
            b"logon" => Some(Kind::Logon),
            b"keyring" => Some(Kind::Keyring),
            _ => None,
        }
    }

    /// The type can change its payload.
    fn can_update(self) -> bool {
        self != Kind::Keyring
    }

    /// A process can read the payload of the type.
    fn can_read(self) -> bool {
        self != Kind::Logon
    }

    /// The permissions of a new key of this type from `add_key` or `request_key`.
    fn default_perm(self) -> u32 {
        let mut perm = ((VIEW | SEARCH | LINK | SETATTR) << POS) | (VIEW << USR);
        if self.can_read() {
            perm |= READ << POS;
        }
        perm | (WRITE << POS)
    }

    /// Checks the payload of a new key or of an update, as the `preparse` of the type.
    fn check_payload(self, payload: &[u8]) -> Result<(), Errno> {
        let ok = match self {
            Kind::Keyring => payload.is_empty(),
            Kind::User | Kind::Logon => (1..=MAX_USER_PAYLOAD).contains(&payload.len()),
        };
        if ok { Ok(()) } else { Err(Errno::EINVAL) }
    }

    /// Checks the description of a new key, as the `vet_description` of the type. A `logon` key
    /// needs a description with a prefix and a colon.
    fn check_desc(self, desc: &[u8]) -> Result<(), Errno> {
        if self == Kind::Logon && desc.iter().position(|&b| b == b':').is_none_or(|i| i == 0) {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }
}

/// How a new key counts in the quota of its owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Quota {
    /// The key counts, and it must fit in the limits.
    In,
    /// The key counts, but it can go over the limit of keys. The kernel keyrings use this.
    Overrun,
}

/// The state of a key that changes.
struct State {
    uid: u32,
    gid: u32,
    perm: u32,
    revoked: bool,
    /// The error of a negative key, or `None` for a positive key.
    negative: Option<Errno>,
    /// The real time in seconds when the key expires, or 0 if it does not expire.
    expiry: u64,
    payload: Vec<u8>,
    /// The links of a keyring. At most one key of each type and description.
    links: Vec<Arc<Key>>,
    /// The keyring accepts no new links. Only the reject-all restriction is available.
    restricted: bool,
    /// The bytes of the quota of the owner that the key takes.
    quota_bytes: u32,
}

/// A key or a keyring.
pub struct Key {
    serial: i32,
    kind: Kind,
    desc: Vec<u8>,
    /// The key is the user keyring or the user session keyring of a user. A join by name does not
    /// find it.
    uid_ring: bool,
    /// The key is invalidated. It is out of the lock, so that the code can check the links of a
    /// keyring with the lock of the keyring held.
    invalidated: AtomicBool,
    state: SpinLock<State>,
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Key").field("serial", &self.serial).field("kind", &self.kind).finish()
    }
}

impl Key {
    /// The serial number.
    pub fn serial(&self) -> i32 {
        self.serial
    }

    /// The type.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// The description.
    pub fn desc(&self) -> &[u8] {
        &self.desc
    }

    fn is_keyring(&self) -> bool {
        self.kind == Kind::Keyring
    }

    /// The error of `key_validate`: invalidated, revoked or expired.
    fn validate(&self, now: u64) -> Result<(), Errno> {
        if self.is_invalidated() {
            return Err(Errno::ENOKEY);
        }
        let s = self.state.lock();
        if s.revoked {
            Err(Errno::EKEYREVOKED)
        } else if s.expiry != 0 && now >= s.expiry {
            Err(Errno::EKEYEXPIRED)
        } else {
            Ok(())
        }
    }

    /// A copy of the links of a keyring. The links to invalidated keys leave the keyring here,
    /// as the garbage collector of Linux removes them.
    fn links(&self) -> Vec<Arc<Key>> {
        let mut s = self.state.lock();
        if !s.links.iter().any(|k| k.is_invalidated()) {
            return s.links.clone();
        }
        let (live, dead): (Vec<_>, Vec<_>) =
            core::mem::take(&mut s.links).into_iter().partition(|k| !k.is_invalidated());
        uncharge(&mut s, dead.len() as u32 * LINK_BYTES);
        s.links = live.clone();
        drop(s);
        // The dead keys can lose their last reference here, after the lock.
        drop(dead);
        live
    }

    fn is_invalidated(&self) -> bool {
        self.invalidated.load(Ordering::Relaxed)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        let (uid, bytes, links) = {
            let mut s = self.state.lock();
            (s.uid, s.quota_bytes, core::mem::take(&mut s.links))
        };
        SERIALS.lock().remove(&self.serial);
        {
            let mut users = USERS.lock();
            if let Some(u) = users.get_mut(&uid) {
                u.nkeys -= 1;
                u.nikeys -= 1;
                u.qnkeys -= 1;
                u.qnbytes -= bytes;
                if u.nkeys == 0 {
                    users.remove(&uid);
                }
            }
        }
        // The links can hold the last reference of other keys, so they go after the locks.
        drop(links);
    }
}

/// The key use of one user, as `/proc/key-users` shows it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    /// The keys of the user.
    pub nkeys: u32,
    /// The keys of the user that have a payload or an error.
    pub nikeys: u32,
    /// The keys in the quota.
    pub qnkeys: u32,
    /// The bytes in the quota.
    pub qnbytes: u32,
}

/// The keys by serial number. A missing reference is a key that goes away.
static SERIALS: SpinLock<BTreeMap<i32, Weak<Key>>> = SpinLock::new(BTreeMap::new());
/// The key use of each user that has keys.
static USERS: SpinLock<BTreeMap<u32, Usage>> = SpinLock::new(BTreeMap::new());
/// The user keyring and the user session keyring of a user.
type UserRings = (Arc<Key>, Arc<Key>);
/// The user keyring and the user session keyring of each user.
static USER_RINGS: SpinLock<BTreeMap<u32, UserRings>> = SpinLock::new(BTreeMap::new());
/// Makes link, unlink and move one operation at a time.
static LINK_LOCK: SpinLock<()> = SpinLock::new(());
/// The state of the generator of serial numbers.
static RANDOM: AtomicU64 = AtomicU64::new(0);

/// A random number, from SplitMix64 with a seed from the platform.
fn random() -> u64 {
    let mut cur = RANDOM.load(Ordering::Relaxed);
    loop {
        // The first call starts the state from the seed. The exchange expects the value that
        // is in the state, also when that value is 0.
        let base = if cur == 0 { rk_frame::arch::random_seed() | 1 } else { cur };
        let next = base.wrapping_add(0x9e37_79b9_7f4a_7c15);
        match RANDOM.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => {
                let mut z = next;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                return z ^ (z >> 31);
            }
            Err(now) => cur = now,
        }
    }
}

/// The key use of `uid`.
pub fn usage(uid: u32) -> Usage {
    USERS.lock().get(&uid).copied().unwrap_or_default()
}

/// The key use of each user, in the order of the user IDs.
pub fn all_usage() -> Vec<(u32, Usage)> {
    USERS.lock().iter().map(|(&u, &n)| (u, n)).collect()
}

/// Takes `bytes` more of the quota of the owner of the key of `s`. Gives `EDQUOT` if the bytes
/// do not fit.
fn charge(s: &mut State, bytes: u32) -> Result<(), Errno> {
    let (_, max) = limits(s.uid);
    let mut users = USERS.lock();
    let u = users.entry(s.uid).or_default();
    match u.qnbytes.checked_add(bytes) {
        Some(n) if n <= max => u.qnbytes = n,
        _ => return Err(Errno::EDQUOT),
    }
    s.quota_bytes += bytes;
    Ok(())
}

/// Gives back `bytes` of the quota of the owner of the key of `s`.
fn uncharge(s: &mut State, bytes: u32) {
    s.quota_bytes -= bytes;
    if let Some(u) = USERS.lock().get_mut(&s.uid) {
        u.qnbytes -= bytes;
    }
}

/// Changes the payload of `s` to `payload`, with the change of the quota, as
/// `key_payload_reserve`. Gives the old payload, so that the caller frees it after the lock.
fn set_payload(s: &mut State, payload: Vec<u8>) -> Result<Vec<u8>, Errno> {
    let (old, new) = (s.payload.len() as u32, payload.len() as u32);
    if new > old {
        charge(s, new - old)?;
    } else {
        uncharge(s, old - new);
    }
    Ok(core::mem::replace(&mut s.payload, payload))
}

/// Makes a key with a payload, as `key_alloc` and the instantiation.
///
/// Gives `EINVAL` for an empty description or a bad `logon` description, and `EDQUOT` if the
/// key does not fit in the quota of `uid`.
#[allow(clippy::too_many_arguments)]
fn alloc(
    kind: Kind,
    desc: &[u8],
    uid: u32,
    gid: u32,
    perm: u32,
    quota: Quota,
    payload: Vec<u8>,
    negative: Option<(Errno, u64)>,
    uid_ring: bool,
) -> Result<Arc<Key>, Errno> {
    if desc.is_empty() {
        return Err(Errno::EINVAL);
    }
    kind.check_desc(desc)?;
    let desc_bytes = desc.len() as u32 + 1;
    let (maxkeys, maxbytes) = limits(uid);
    let bytes = desc_bytes + payload.len() as u32;
    {
        let mut users = USERS.lock();
        let u = users.entry(uid).or_default();
        if quota == Quota::In
            && (u.qnkeys + 1 > maxkeys
                || u.qnbytes.checked_add(desc_bytes).is_none_or(|n| n > maxbytes))
        {
            if u.nkeys == 0 {
                users.remove(&uid);
            }
            return Err(Errno::EDQUOT);
        }
        // The payload must fit in the bytes in each case, as `key_payload_reserve` checks it.
        if !payload.is_empty() && u.qnbytes.checked_add(bytes).is_none_or(|n| n > maxbytes) {
            if u.nkeys == 0 {
                users.remove(&uid);
            }
            return Err(Errno::EDQUOT);
        }
        u.nkeys += 1;
        u.nikeys += 1;
        u.qnkeys += 1;
        u.qnbytes += bytes;
    }
    let serial = {
        let mut serials = SERIALS.lock();
        loop {
            let s = (random() as u32 >> 1) as i32;
            if s >= 3 && s != i32::MAX && !serials.contains_key(&s) {
                serials.insert(s, Weak::new());
                break s;
            }
        }
    };
    let (negative, expiry) = match negative {
        Some((e, at)) => (Some(e), at),
        None => (None, 0),
    };
    let key = Arc::new(Key {
        serial,
        kind,
        desc: desc.to_vec(),
        uid_ring,
        invalidated: AtomicBool::new(false),
        state: SpinLock::new(State {
            uid,
            gid,
            perm,
            revoked: false,
            negative,
            expiry,
            payload,
            links: Vec::new(),
            restricted: false,
            quota_bytes: bytes,
        }),
    });
    SERIALS.lock().insert(serial, Arc::downgrade(&key));
    Ok(key)
}

/// Makes a keyring of the kernel, which can go over the quota of keys.
fn kernel_ring(desc: &[u8], uid: u32, gid: u32, perm: u32) -> Result<Arc<Key>, Errno> {
    alloc(Kind::Keyring, desc, uid, gid, perm, Quota::Overrun, Vec::new(), None, false)
}

/// The key with the serial number `serial`. An invalidated key is gone, as the garbage collector
/// of Linux removes it at once.
fn find(serial: i32) -> Option<Arc<Key>> {
    let key = SERIALS.lock().get(&serial).and_then(Weak::upgrade)?;
    if key.is_invalidated() { None } else { Some(key) }
}

/// The keyrings of a thread and its process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// The thread keyring.
    Thread,
    /// The process keyring.
    Process,
    /// The session keyring.
    Session,
}

/// The holder of the keyrings of the caller: its thread and its process.
pub trait Owner {
    /// The keyring in `slot`.
    fn ring(&self, slot: Slot) -> Option<Arc<Key>>;
    /// Puts `ring` in `slot`. If `replace` is false and the slot has a keyring, the old keyring
    /// stays. Gives the keyring in the slot.
    fn set_ring(&self, slot: Slot, ring: Arc<Key>, replace: bool) -> Arc<Key>;
    /// The default keyring of `request_key`, a `KEY_REQKEY_DEFL_*` value.
    fn reqkey(&self) -> u8;
    /// Sets the default keyring of `request_key`.
    fn set_reqkey(&self, value: u8);
}

/// The context of a key operation.
pub struct Caller<'a> {
    /// The credentials.
    pub cred: &'a Cred,
    /// The real time in seconds.
    pub now: u64,
    /// The keyrings of the caller.
    pub owner: &'a dyn Owner,
}

/// The `KEY_LOOKUP_CREATE` flag: make the special keyring if it is not there.
pub const LOOKUP_CREATE: u32 = 1;
/// The `KEY_LOOKUP_PARTIAL` flag: accept a negative key.
pub const LOOKUP_PARTIAL: u32 = 2;

/// The access that a lookup needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Need {
    /// These permission bits.
    Perm(u32),
    /// The key goes out of a keyring: no state check and no permission check.
    Unlink,
    /// The caller checks the permissions and the state.
    Defer,
}

/// A key and whether the caller possesses it.
#[derive(Clone, Debug)]
pub struct KeyRef {
    /// The key.
    pub key: Arc<Key>,
    /// The caller possesses the key.
    pub possessed: bool,
}

/// Checks that the caller has the permissions `mask` on `key`, as `key_task_permission`.
fn permission(cx: &Caller<'_>, key: &Key, possessed: bool, mask: u32) -> Result<(), Errno> {
    let (uid, gid, perm) = {
        let s = key.state.lock();
        (s.uid, s.gid, s.perm)
    };
    let cred = cx.cred;
    let mut kperm = if uid == cred.fsuid {
        perm >> USR
    } else if gid != NO_GID
        && perm & GRP_ALL != 0
        && (gid == cred.fsgid || cred.groups.contains(&gid))
    {
        perm >> GRP
    } else {
        perm
    };
    if possessed {
        kperm |= perm >> POS;
    }
    if kperm & mask & ALL == mask { Ok(()) } else { Err(Errno::EACCES) }
}

/// What a search looks for.
struct Search<'a> {
    cx: &'a Caller<'a>,
    /// This one key, for the check of possession.
    target: Option<&'a Arc<Key>>,
    kind: Kind,
    desc: &'a [u8],
    /// Skip the revoked, invalidated, expired and negative keys, with their errors.
    state_check: bool,
    /// An expired key does not give `EKEYEXPIRED`.
    skip_expired: bool,
    /// Check the search permission of the keys and the keyrings.
    check_perm: bool,
}

impl Search<'_> {
    fn matches(&self, key: &Arc<Key>) -> bool {
        match self.target {
            Some(t) => Arc::ptr_eq(t, key),
            None => key.kind == self.kind && key.desc == self.desc,
        }
    }

    /// Checks a key that matches, as `keyring_search_iterator`. Gives the key if the search
    /// accepts it, or puts the error of the skip in `result`.
    fn accept(
        &self,
        key: &Arc<Key>,
        possessed: bool,
        result: &mut Result<Arc<Key>, Errno>,
    ) -> Option<Arc<Key>> {
        let now = self.cx.now;
        if self.state_check {
            let (dead, expiry) = {
                let s = key.state.lock();
                (s.revoked || key.is_invalidated(), s.expiry)
            };
            if dead {
                *result = Err(Errno::EKEYREVOKED);
                return None;
            }
            if expiry != 0 && now >= expiry {
                if !self.skip_expired {
                    *result = Err(Errno::EKEYEXPIRED);
                }
                return None;
            }
        }
        if self.check_perm && permission(self.cx, key, possessed, SEARCH).is_err() {
            *result = Err(Errno::EACCES);
            return None;
        }
        if self.state_check
            && let Some(e) = key.state.lock().negative
        {
            *result = Err(e);
            return None;
        }
        Some(key.clone())
    }

    /// Searches the keys of `ring` and then the keyrings in it, depth first.
    fn walk(
        &self,
        ring: &Arc<Key>,
        possessed: bool,
        depth: usize,
        result: &mut Result<Arc<Key>, Errno>,
    ) -> Option<Arc<Key>> {
        let links = ring.links();
        for k in links.iter().filter(|k| self.matches(k)) {
            if let Some(found) = self.accept(k, possessed, result) {
                return Some(found);
            }
        }
        for k in links.iter().filter(|k| k.is_keyring()) {
            if depth >= MAX_DEPTH {
                continue;
            }
            if self.check_perm && permission(self.cx, k, possessed, SEARCH).is_err() {
                continue;
            }
            if let Some(found) = self.walk(k, possessed, depth + 1, result) {
                return Some(found);
            }
        }
        None
    }

    /// Searches the tree of `ring`, as `keyring_search_rcu`. Gives `EAGAIN` if no key matches.
    fn in_ring(&self, ring: &Arc<Key>, possessed: bool) -> Result<Arc<Key>, Errno> {
        if !ring.is_keyring() {
            return Err(Errno::ENOTDIR);
        }
        if self.check_perm {
            permission(self.cx, ring, possessed, SEARCH)?;
        }
        let mut result = Err(Errno::EAGAIN);
        // The top keyring can be the key, and then the search stops there.
        if self.matches(ring) {
            return match self.accept(ring, possessed, &mut result) {
                Some(found) => Ok(found),
                None => result,
            };
        }
        match self.walk(ring, possessed, 0, &mut result) {
            Some(found) => Ok(found),
            None => result,
        }
    }

    /// Searches the keyrings of the caller, as `search_cred_keyrings_rcu`. A keyring with no key
    /// or a negative key gives the error over the other errors.
    fn in_process(&self) -> Result<Arc<Key>, Errno> {
        let owner = self.cx.owner;
        let session = owner.ring(Slot::Session).or_else(|| user_rings_of(self.cx.cred.uid));
        let rings = [owner.ring(Slot::Thread), owner.ring(Slot::Process), session];
        let mut soft = None;
        let mut hard = Errno::EAGAIN;
        for ring in rings.iter().flatten() {
            match self.in_ring(ring, true) {
                Ok(k) => return Ok(k),
                Err(e) if e == Errno::EAGAIN || e == Errno::ENOKEY => soft = Some(e),
                Err(e) => hard = e,
            }
        }
        Err(soft.unwrap_or(hard))
    }
}

/// The user session keyring of `uid` if it is there. A search does not make it.
fn user_rings_of(uid: u32) -> Option<Arc<Key>> {
    USER_RINGS.lock().get(&uid).map(|(_, s)| s.clone())
}

/// The user keyring and the user session keyring of the user of the caller. Makes them if they
/// are not there, as `look_up_user_keyrings`.
fn user_rings(cx: &Caller<'_>) -> Result<(Arc<Key>, Arc<Key>), Errno> {
    let uid = cx.cred.uid;
    if let Some(r) = USER_RINGS.lock().get(&uid) {
        return Ok(r.clone());
    }
    let perm = (POS_ALL & !(SETATTR << POS)) | USR_ALL;
    let name = alloc::format!("_uid.{uid}");
    let user = alloc(
        Kind::Keyring,
        name.as_bytes(),
        uid,
        NO_GID,
        perm,
        Quota::Overrun,
        Vec::new(),
        None,
        true,
    )?;
    let name = alloc::format!("_uid_ses.{uid}");
    let session = alloc(
        Kind::Keyring,
        name.as_bytes(),
        uid,
        NO_GID,
        perm,
        Quota::Overrun,
        Vec::new(),
        None,
        true,
    )?;
    insert_link(&session, &user)?;
    let mut rings = USER_RINGS.lock();
    // Another thread can make them first. The new keyrings then go after the lock.
    let r = rings.entry(uid).or_insert((user.clone(), session.clone())).clone();
    drop(rings);
    Ok(r)
}

/// Gives the thread keyring, and makes it if it is not there.
fn thread_ring(cx: &Caller<'_>) -> Result<Arc<Key>, Errno> {
    if let Some(r) = cx.owner.ring(Slot::Thread) {
        return Ok(r);
    }
    let ring = kernel_ring(b"_tid", cx.cred.uid, cx.cred.gid, POS_ALL | (VIEW << USR))?;
    Ok(cx.owner.set_ring(Slot::Thread, ring, false))
}

/// Gives the process keyring, and makes it if it is not there.
fn process_ring(cx: &Caller<'_>) -> Result<Arc<Key>, Errno> {
    if let Some(r) = cx.owner.ring(Slot::Process) {
        return Ok(r);
    }
    let ring = kernel_ring(b"_pid", cx.cred.uid, cx.cred.gid, POS_ALL | (VIEW << USR))?;
    Ok(cx.owner.set_ring(Slot::Process, ring, false))
}

/// The permissions of a session keyring from a join.
const SESSION_PERM: u32 = POS_ALL | ((VIEW | READ | LINK) << USR);

/// Makes a new anonymous session keyring and joins it.
fn new_session(cx: &Caller<'_>) -> Result<Arc<Key>, Errno> {
    // As `install_session_keyring_to_cred`, the keyring must fit in the quota if it replaces
    // another session keyring.
    let quota = if cx.owner.ring(Slot::Session).is_some() { Quota::In } else { Quota::Overrun };
    let ring = alloc(
        Kind::Keyring,
        b"_ses",
        cx.cred.uid,
        cx.cred.gid,
        SESSION_PERM,
        quota,
        Vec::new(),
        None,
        false,
    )?;
    Ok(cx.owner.set_ring(Slot::Session, ring, true))
}

/// Finds the key of `id`, a serial number or a special keyring, and checks its state and the
/// permissions, as `lookup_user_key`.
///
/// # Errors
///
/// Gives `ENOKEY` for a key that is not there, `EINVAL` for a bad special ID, the error of the
/// state of the key, or `EACCES`.
pub fn lookup(cx: &Caller<'_>, id: i32, flags: u32, need: Need) -> Result<KeyRef, Errno> {
    let create = flags & LOOKUP_CREATE != 0;
    let (key, possessed) = match id {
        KEY_SPEC_THREAD_KEYRING => {
            let r = if create { Some(thread_ring(cx)?) } else { cx.owner.ring(Slot::Thread) };
            (r.ok_or(Errno::ENOKEY)?, true)
        }
        KEY_SPEC_PROCESS_KEYRING => {
            let r = if create { Some(process_ring(cx)?) } else { cx.owner.ring(Slot::Process) };
            (r.ok_or(Errno::ENOKEY)?, true)
        }
        KEY_SPEC_SESSION_KEYRING => {
            let user_session = || USER_RINGS.lock().get(&cx.cred.uid).map(|r| r.1.clone());
            let r = match cx.owner.ring(Slot::Session) {
                None if create => new_session(cx)?,
                None => {
                    let (_, s) = user_rings(cx)?;
                    cx.owner.set_ring(Slot::Session, s, false)
                }
                Some(r) if create && user_session().is_some_and(|s| Arc::ptr_eq(&s, &r)) => {
                    new_session(cx)?
                }
                Some(r) => r,
            };
            (r, true)
        }
        KEY_SPEC_USER_KEYRING => (user_rings(cx)?.0, true),
        KEY_SPEC_USER_SESSION_KEYRING => (user_rings(cx)?.1, true),
        KEY_SPEC_GROUP_KEYRING => return Err(Errno::EINVAL),
        KEY_SPEC_REQKEY_AUTH_KEY | KEY_SPEC_REQUESTOR_KEYRING => return Err(Errno::ENOKEY),
        _ if id < 1 => return Err(Errno::EINVAL),
        _ => {
            let key = find(id).ok_or(Errno::ENOKEY)?;
            let possessed = is_possessed(cx, &key);
            (key, possessed)
        }
    };
    if need != Need::Unlink {
        if flags & LOOKUP_PARTIAL == 0 {
            if need != Need::Defer {
                if let Some(e) = key.state.lock().negative {
                    return Err(e);
                }
                key.validate(cx.now)?;
            }
        } else if need != Need::Defer {
            key.validate(cx.now)?;
        }
    }
    if let Need::Perm(mask) = need {
        permission(cx, &key, possessed, mask)?;
    }
    Ok(KeyRef { key, possessed })
}

/// The caller can find `key` from its keyrings, with the search permission.
fn is_possessed(cx: &Caller<'_>, key: &Arc<Key>) -> bool {
    let s = Search {
        cx,
        target: Some(key),
        kind: key.kind,
        desc: &key.desc,
        state_check: false,
        skip_expired: false,
        check_perm: true,
    };
    s.in_process().is_ok()
}

/// The keyring `ring` reaches `key`, or the nesting is too deep, as `keyring_detect_cycle`.
/// Gives `EDEADLK` for a cycle and `ELOOP` for a nesting that is too deep.
fn check_cycle(ring: &Arc<Key>, key: &Arc<Key>) -> Result<(), Errno> {
    if !key.is_keyring() {
        return Ok(());
    }
    fn walk(from: &Arc<Key>, to: &Arc<Key>, depth: usize) -> Result<(), Errno> {
        if Arc::ptr_eq(from, to) {
            return Err(Errno::EDEADLK);
        }
        for k in from.links().iter().filter(|k| k.is_keyring()) {
            if depth >= MAX_DEPTH {
                return Err(Errno::ELOOP);
            }
            walk(k, to, depth + 1)?;
        }
        Ok(())
    }
    walk(key, ring, 0)
}

/// Checks that a key of `kind` and `desc` can go in `ring`, as `__key_link_begin` and the check
/// of the restriction after it: `ENOTDIR`, `EKEYREVOKED`, `EDQUOT` and `EPERM`. Takes the quota
/// of a new link. Gives true if the link replaces a link of the same type and description. The
/// caller holds `LINK_LOCK`, and calls [`abort_link`] if it does not commit the link.
fn begin_link(ring: &Arc<Key>, kind: Kind, desc: &[u8]) -> Result<bool, Errno> {
    if !ring.is_keyring() {
        return Err(Errno::ENOTDIR);
    }
    if ring.state.lock().revoked {
        return Err(Errno::EKEYREVOKED);
    }
    let replace = ring.links().iter().any(|k| k.kind == kind && k.desc == desc);
    if !replace {
        charge(&mut ring.state.lock(), LINK_BYTES)?;
    }
    if ring.state.lock().restricted {
        abort_link(ring, replace);
        return Err(Errno::EPERM);
    }
    Ok(replace)
}

/// Gives back the quota that [`begin_link`] took.
fn abort_link(ring: &Arc<Key>, replace: bool) {
    if !replace {
        uncharge(&mut ring.state.lock(), LINK_BYTES);
    }
}

/// Puts `key` in `ring` in the place of a key with the same type and description, as
/// `__key_link`. The old link goes after the lock.
fn commit_link(ring: &Arc<Key>, key: &Arc<Key>) {
    let old = {
        let mut s = ring.state.lock();
        let old = s
            .links
            .iter()
            .position(|k| k.kind == key.kind && k.desc == key.desc)
            .map(|i| s.links.remove(i));
        s.links.push(key.clone());
        old
    };
    drop(old);
}

/// Links `key` into `ring` with all the checks, as `key_link`.
fn insert_link(ring: &Arc<Key>, key: &Arc<Key>) -> Result<(), Errno> {
    let _g = LINK_LOCK.lock();
    let replace = begin_link(ring, key.kind, &key.desc)?;
    if let Err(e) = check_cycle(ring, key) {
        abort_link(ring, replace);
        return Err(e);
    }
    commit_link(ring, key);
    Ok(())
}

/// Removes the link to `key` from `ring`. Gives `ENOENT` if `ring` has no link to it. The
/// caller holds `LINK_LOCK`.
fn remove_link(ring: &Arc<Key>, key: &Arc<Key>) -> Result<(), Errno> {
    let old = {
        let mut s = ring.state.lock();
        let i = s.links.iter().position(|k| Arc::ptr_eq(k, key)).ok_or(Errno::ENOENT)?;
        uncharge(&mut s, LINK_BYTES);
        s.links.remove(i)
    };
    drop(old);
    Ok(())
}

/// Removes the links to invalidated keys from all the keyrings, as the garbage collector.
fn collect() {
    let rings: Vec<Arc<Key>> = {
        let serials = SERIALS.lock();
        serials.values().filter_map(Weak::upgrade).collect::<Vec<_>>()
    };
    // The keys can lose their last reference here, so the lock of the table is not held.
    for r in rings.iter().filter(|r| r.is_keyring()) {
        let _ = r.links();
    }
    drop(rings);
}

/// Makes a thread keyring for a new thread of `cred`, as `copy_creds` does for `CLONE_THREAD`
/// when the parent thread has one.
pub fn new_thread_ring(cred: &Cred) -> Option<Arc<Key>> {
    kernel_ring(b"_tid", cred.uid, cred.gid, POS_ALL | (VIEW << USR)).ok()
}

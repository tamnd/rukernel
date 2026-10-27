//! The text of `/proc/keys` and `/proc/key-users`.

use super::{Caller, Key, NO_GID, POS, SERIALS, VIEW, all_usage, is_possessed, limits, permission};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::fmt::Write;

/// The overflow ID that a key with no group shows.
const OVERFLOW_ID: u32 = 65534;

/// The text of the timeout of a key that expires at `expiry`, as `proc_keys_show`.
fn timeout(expiry: u64, now: u64) -> String {
    if expiry == 0 {
        return String::from("perm");
    }
    if now >= expiry {
        return String::from("expd");
    }
    let t = expiry - now;
    let (n, unit) = if t < 60 {
        (t, 's')
    } else if t < 60 * 60 {
        (t / 60, 'm')
    } else if t < 60 * 60 * 24 {
        (t / (60 * 60), 'h')
    } else if t < 60 * 60 * 24 * 7 {
        (t / (60 * 60 * 24), 'd')
    } else {
        (t / (60 * 60 * 24 * 7), 'w')
    };
    alloc::format!("{n}{unit}")
}

/// Writes the line of `key` to `out`.
fn key_line(out: &mut String, key: &Arc<Key>, now: u64) {
    let links = if key.is_keyring() { key.links().len() } else { 0 };
    let s = key.state.lock();
    let flag = |on: bool, c: char| if on { c } else { '-' };
    let gid = if s.gid == NO_GID { OVERFLOW_ID } else { s.gid };
    let _ = write!(
        out,
        // The flags are instantiated, revoked, dead, quota, user construction, negative and
        // invalidated. A key here is never dead or under construction.
        "{:08x} I{}-Q-{}{} {:5} {:>4} {:08x} {:5} {:5} {:<9.9} ",
        key.serial,
        flag(s.revoked, 'R'),
        flag(s.negative.is_some(), 'N'),
        flag(key.is_invalidated(), 'i'),
        // The references of the tables and of the copy here do not count.
        Arc::strong_count(key) - 1,
        timeout(s.expiry, now),
        s.perm,
        s.uid as i32,
        gid as i32,
        key.kind.name(),
    );
    out.push_str(&String::from_utf8_lossy(&key.desc));
    if s.negative.is_none() {
        if key.is_keyring() {
            if links == 0 {
                out.push_str(": empty");
            } else {
                let _ = write!(out, ": {links}");
            }
        } else {
            let _ = write!(out, ": {}", s.payload.len());
        }
    }
    out.push('\n');
}

/// The text of `/proc/keys`: a line for each key that the caller can view, in the order of the
/// serial numbers.
pub fn keys_text(cx: &Caller<'_>) -> Vec<u8> {
    let all: Vec<Arc<Key>> = SERIALS.lock().values().filter_map(Weak::upgrade).collect();
    let mut out = String::new();
    for key in all.iter().filter(|k| !k.is_invalidated()) {
        // The search for possession is necessary only if the possessor can view the key.
        let pos_view = key.state.lock().perm & (VIEW << POS) != 0;
        let possessed = pos_view && is_possessed(cx, key);
        if permission(cx, key, possessed, VIEW).is_ok() {
            key_line(&mut out, key, cx.now);
        }
    }
    // The keys can lose their last reference here, out of the lock of the table.
    drop(all);
    out.into_bytes()
}

/// The text of `/proc/key-users`: a line for each user that has keys, with the counts and the
/// quota, in the order of the user IDs.
pub fn key_users_text() -> Vec<u8> {
    let mut out = String::new();
    for (uid, u) in all_usage() {
        let (maxkeys, maxbytes) = limits(uid);
        let _ = writeln!(
            out,
            "{:5}: {:5} {}/{} {}/{} {}/{}",
            uid, u.nkeys, u.nkeys, u.nikeys, u.qnkeys, maxkeys, u.qnbytes, maxbytes
        );
    }
    out.into_bytes()
}

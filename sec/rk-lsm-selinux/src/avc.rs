//! The access vector cache (AVC), as security/selinux/avc.c of Linux.
//!
//! The cache keeps the decisions of the security server for a source SID, a target SID and a
//! class of the kernel. A check of permissions looks in the cache first. A denial in
//! permissive mode, or for a permissive domain, adds the permissions to the decision in the
//! cache, so that the next check of the same permissions makes no record. A denial makes an
//! audit record of the type `AVC`, as on Linux.

use crate::classmap::{self, CLASSES};
use crate::server;
use crate::services::{AvDecision, NEVERAUDIT, PERMISSIVE};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use core::fmt::Write;
use core::sync::atomic::{AtomicU32, Ordering};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

/// The number of the hash slots of the cache of Linux, `AVC_CACHE_SLOTS`, for `hash_stats`.
const CACHE_SLOTS: u32 = 512;

/// The number of decisions that a full cache removes, `AVC_CACHE_RECLAIM` of Linux.
const CACHE_RECLAIM: usize = 16;

/// The cache.
struct Cache {
    /// The decisions for a source SID, a target SID and a class.
    nodes: BTreeMap<(u32, u32, u16), AvDecision>,
    /// The number of the last policy load that the cache knows, `avc_cache.latest_notif`.
    latest: u32,
}

static CACHE: SpinLock<Cache> = SpinLock::new(Cache { nodes: BTreeMap::new(), latest: 0 });

/// The largest number of decisions in the cache, the file `avc/cache_threshold` of selinuxfs.
pub static THRESHOLD: AtomicU32 = AtomicU32::new(512);

/// The counters of the file `avc/cache_stats`: lookups, misses, allocations, reclaims, frees.
static STATS: [AtomicU32; 5] = [const { AtomicU32::new(0) }; 5];

fn count(i: usize, n: u32) {
    STATS[i].fetch_add(n, Ordering::Relaxed);
}

/// Gets the decision for `(ssid, tsid, tclass)` from the cache, or from the security server
/// if the cache does not have it, as `avc_lookup` and `avc_compute_av` of Linux.
fn lookup(ssid: u32, tsid: u32, tclass: u16) -> AvDecision {
    count(0, 1);
    if let Some(&avd) = CACHE.lock().nodes.get(&(ssid, tsid, tclass)) {
        return avd;
    }
    count(1, 1);
    let avd = server::compute_av(ssid, tsid, tclass);
    let mut cache = CACHE.lock();
    if avd.seqno < cache.latest {
        rk_frame::println!("SELinux: avc:  seqno {} < latest_notif {}", avd.seqno, cache.latest);
        return avd;
    }
    if cache.nodes.len() >= THRESHOLD.load(Ordering::Relaxed) as usize {
        let old: alloc::vec::Vec<_> = cache.nodes.keys().take(CACHE_RECLAIM).copied().collect();
        for k in &old {
            cache.nodes.remove(k);
        }
        count(3, old.len() as u32);
        count(4, old.len() as u32);
    }
    count(2, 1);
    cache.nodes.insert((ssid, tsid, tclass), avd);
    avd
}

/// Removes all the decisions after a policy load or a change of a boolean, as
/// `avc_ss_reset` of Linux. `seqno` is the number of the policy load.
pub fn reset(seqno: u32) {
    let mut cache = CACHE.lock();
    count(4, cache.nodes.len() as u32);
    cache.nodes.clear();
    cache.latest = cache.latest.max(seqno);
}

/// Checks the permissions `requested` of the class `tclass` of the kernel for the SID `ssid`
/// on the SID `tsid`, without an audit record, as `avc_has_perm_noaudit` of Linux. It gives
/// the decision and the result.
pub fn has_perm_noaudit(
    ssid: u32,
    tsid: u32,
    tclass: u16,
    requested: u32,
) -> (AvDecision, Result<(), Errno>) {
    let avd = lookup(ssid, tsid, tclass);
    if requested & !avd.allowed == 0 {
        return (avd, Ok(()));
    }
    if crate::enforcing() && avd.flags & PERMISSIVE == 0 {
        return (avd, Err(Errno::EACCES));
    }
    // A denial in permissive mode allows the permissions for the next checks, as
    // `avc_update_node(AVC_CALLBACK_GRANT)` of Linux.
    if let Some(node) = CACHE.lock().nodes.get_mut(&(ssid, tsid, tclass))
        && node.seqno == avd.seqno
    {
        node.allowed |= requested;
        count(2, 1);
        count(4, 1);
    }
    (avd, Ok(()))
}

/// Checks the permissions `requested` and makes an audit record if the policy wants one, as
/// `avc_has_perm` of Linux. `extra` adds the fields of the object after `comm`, for example
/// ` capability=21 ` or ` name="a" dev="sda" ino=12`.
///
/// # Errors
///
/// `EACCES` if the policy denies a permission in enforcing mode.
pub fn has_perm(
    ssid: u32,
    tsid: u32,
    tclass: u16,
    requested: u32,
    extra: impl FnOnce(&mut String),
) -> Result<(), Errno> {
    let (avd, rc) = has_perm_noaudit(ssid, tsid, tclass, requested);
    audit(ssid, tsid, tclass, requested, &avd, rc, 0, extra);
    rc
}

/// The permissions that make an audit record and the denied permissions, as
/// `avc_audit_required` of Linux. A denial makes no record if `auditdeny` has a permission
/// that the policy does not audit, as `audit_access` for `access(2)`.
fn audit_required(requested: u32, avd: &AvDecision, failed: bool, auditdeny: u32) -> (u32, u32) {
    if avd.flags & NEVERAUDIT != 0 {
        return (0, 0);
    }
    let denied = requested & !avd.allowed;
    if denied != 0 {
        if auditdeny != 0 && auditdeny & avd.auditdeny == 0 {
            return (0, denied);
        }
        (denied & avd.auditdeny, denied)
    } else if failed {
        (requested, requested)
    } else {
        (requested & avd.auditallow, 0)
    }
}

/// Makes the audit record of a check, as `avc_audit` of Linux. `auditdeny` is as in
/// `avc_audit_required`, 0 for most checks.
#[allow(clippy::too_many_arguments)]
pub fn audit(
    ssid: u32,
    tsid: u32,
    tclass: u16,
    requested: u32,
    avd: &AvDecision,
    rc: Result<(), Errno>,
    auditdeny: u32,
    extra: impl FnOnce(&mut String),
) {
    let (audited, denied) = audit_required(requested, avd, rc.is_err(), auditdeny);
    if audited == 0 || tclass == 0 || usize::from(tclass) > CLASSES.len() {
        return;
    }
    let mut s = String::from(if denied != 0 { "avc:  denied " } else { "avc:  granted " });
    dump_av(&mut s, tclass, audited);
    let (pid, comm) = crate::current();
    let _ = write!(s, " for  pid={pid} comm=");
    untrusted(&mut s, &comm);
    extra(&mut s);
    for (name, sid) in [("s", ssid), ("t", tsid)] {
        match server::sid_to_context(sid) {
            Ok(text) => {
                let _ = write!(s, " {name}context={text}");
            }
            Err(_) => {
                let _ = write!(s, " {name}sid={sid}");
            }
        }
    }
    let _ = write!(s, " tclass={}", classmap::name(tclass).unwrap_or_default());
    if denied != 0 {
        let _ = write!(s, " permissive={}", u8::from(rc.is_ok()));
    }
    for (name, sid) in [("s", ssid), ("t", tsid)] {
        if let Some(text) = server::sid_to_context_invalid(sid) {
            let _ = write!(s, " {name}rawcon=");
            untrusted(&mut s, text.as_bytes());
        }
    }
    rk_net::netlink::audit::log_avc(&s);
}

/// Writes the names of the permissions `av` of the class `tclass` of the kernel, as
/// `avc_dump_av` of Linux. A bit without a name is written in hex digits.
fn dump_av(s: &mut String, tclass: u16, mut av: u32) {
    if av == 0 {
        s.push_str(" null");
        return;
    }
    let perms = CLASSES[usize::from(tclass) - 1].1;
    s.push_str(" {");
    for (i, perm) in perms.iter().enumerate().take(32) {
        if av & (1 << i) != 0 {
            s.push(' ');
            s.push_str(perm);
            av &= !(1 << i);
        }
    }
    if av != 0 {
        let _ = write!(s, " 0x{av:x}");
    }
    s.push_str(" }");
}

/// Adds the text `s` from user space to `out`, as `audit_log_untrustedstring` of Linux: in
/// quotes, or in hex digits if it has a quote, a space or a byte that is not printable ASCII.
pub fn untrusted(out: &mut String, s: &[u8]) {
    if s.iter().any(|&c| c == b'"' || !(0x21..=0x7e).contains(&c)) {
        for c in s {
            let _ = write!(out, "{c:02X}");
        }
    } else {
        out.push('"');
        out.push_str(core::str::from_utf8(s).unwrap_or_default());
        out.push('"');
    }
}

/// The text of the file `avc/cache_stats` of selinuxfs, as `sel_avc_stats_seq_show` of Linux.
pub fn cache_stats() -> String {
    let v: [u32; 5] = core::array::from_fn(|i| STATS[i].load(Ordering::Relaxed));
    format!(
        "lookups hits misses allocations reclaims frees\n{} {} {} {} {} {}\n",
        v[0],
        v[0].wrapping_sub(v[1]),
        v[1],
        v[2],
        v[3],
        v[4]
    )
}

/// The text of the file `avc/hash_stats` of selinuxfs, as `avc_get_hash_stats` of Linux, with
/// the hash function of the cache of Linux.
pub fn hash_stats() -> String {
    let cache = CACHE.lock();
    let mut slots = BTreeMap::<u32, u32>::new();
    for &(s, t, c) in cache.nodes.keys() {
        let h = (s ^ (t << 2) ^ (u32::from(c) << 4)) & (CACHE_SLOTS - 1);
        *slots.entry(h).or_default() += 1;
    }
    format!(
        "entries: {}\nbuckets used: {}/{CACHE_SLOTS}\nlongest chain: {}\n",
        cache.nodes.len(),
        slots.len(),
        slots.values().max().copied().unwrap_or(0)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_names_the_permissions_as_linux() {
        let mut s = String::new();
        dump_av(&mut s, classmap::class::SECURITY, classmap::security::SETENFORCE | 1 << 20);
        assert_eq!(s, " { setenforce 0x100000 }");
        let mut s = String::new();
        dump_av(&mut s, classmap::class::FILE, 0);
        assert_eq!(s, " null");
        let mut avd = AvDecision::new(1);
        avd.allowed = 1;
        avd.auditallow = 1;
        avd.auditdeny = !4;
        assert_eq!(audit_required(1, &avd, false, 0), (1, 0));
        assert_eq!(audit_required(1, &avd, true, 0), (1, 1));
        assert_eq!(audit_required(6, &avd, false, 0), (2, 6));
        // A permission of `auditdeny` that the policy does not audit stops the record.
        assert_eq!(audit_required(6, &avd, false, 4), (0, 6));
        assert_eq!(audit_required(6, &avd, false, 2), (2, 6));
        avd.flags = NEVERAUDIT;
        assert_eq!(audit_required(6, &avd, false, 0), (0, 0));
        let mut s = String::new();
        untrusted(&mut s, b"a b");
        assert_eq!(s, "612062");
    }
}

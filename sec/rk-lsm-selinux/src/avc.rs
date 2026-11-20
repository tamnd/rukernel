//! The access vector cache (AVC), as security/selinux/avc.c of Linux.
//!
//! The cache keeps the decisions of the security server for a source SID, a target SID and a
//! class of the kernel. A check of permissions looks in the cache first. A denial in
//! permissive mode, or for a permissive domain, adds the permissions to the decision in the
//! cache, so that the next check of the same permissions makes no record. A denial makes an
//! audit record of the type `AVC`, as on Linux. For the extended permissions, as the commands
//! of `ioctl`, the cache also keeps the drivers that have rules and the decision of each
//! driver that a check used.

use crate::classmap::{self, CLASSES};
use crate::server;
use crate::services::{
    AvDecision, ExtendedPerms, NEVERAUDIT, PERMISSIVE, XpermsDecision, used, xperm_set, xperm_test,
};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicU32, Ordering};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

/// The number of the hash slots of the cache of Linux, `AVC_CACHE_SLOTS`, for `hash_stats`.
const CACHE_SLOTS: u32 = 512;

/// The number of decisions that a full cache removes, `AVC_CACHE_RECLAIM` of Linux.
const CACHE_RECLAIM: usize = 16;

/// A decision in the cache, `struct avc_entry` of Linux.
struct Node {
    /// The decision.
    avd: AvDecision,
    /// The extended permissions, if the policy has rules of them for the SIDs and the class.
    xp: Option<Box<XpNode>>,
}

/// The extended permissions in the cache, `struct avc_xperms_node` of Linux.
struct XpNode {
    /// The drivers that have rules.
    xp: ExtendedPerms,
    /// The decisions of the drivers that a check used.
    decisions: Vec<XpermsDecision>,
}

impl XpNode {
    /// The decision of `driver` for the base permission `base_perm`, as
    /// `avc_xperms_decision_lookup` of Linux.
    fn decision(&mut self, driver: u8, base_perm: u8) -> Option<&mut XpermsDecision> {
        self.decisions.iter_mut().find(|d| d.driver == driver && d.base_perm == base_perm)
    }
}

/// The cache.
struct Cache {
    /// The decisions for a source SID, a target SID and a class.
    nodes: BTreeMap<(u32, u32, u16), Node>,
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
/// if the cache does not have it, as `avc_lookup` and `avc_compute_av` of Linux. It gives the
/// decision, and for a check of the extended permissions of `ext` (the driver and the base
/// permission), the drivers and the decision of the driver in the cache.
fn lookup(
    ssid: u32,
    tsid: u32,
    tclass: u16,
    ext: Option<(u8, u8)>,
) -> (AvDecision, Option<(ExtendedPerms, Option<XpermsDecision>)>) {
    let get = |n: &mut Node| {
        let xp = n.xp.as_deref_mut().map(|x| {
            let d = ext.and_then(|(driver, base)| x.decision(driver, base).copied());
            (x.xp, d)
        });
        (n.avd, xp)
    };
    count(0, 1);
    if let Some(node) = CACHE.lock().nodes.get_mut(&(ssid, tsid, tclass)) {
        return get(node);
    }
    count(1, 1);
    let mut xp = ExtendedPerms::default();
    let avd = server::compute_av_xperms(ssid, tsid, tclass, Some(&mut xp));
    let mut node = Node { avd, xp: xp.any.then(|| Box::new(XpNode { xp, decisions: Vec::new() })) };
    let mut cache = CACHE.lock();
    if avd.seqno < cache.latest {
        rk_frame::println!("SELinux: avc:  seqno {} < latest_notif {}", avd.seqno, cache.latest);
        return get(&mut node);
    }
    if cache.nodes.len() >= THRESHOLD.load(Ordering::Relaxed) as usize {
        let old: Vec<_> = cache.nodes.keys().take(CACHE_RECLAIM).copied().collect();
        for k in &old {
            cache.nodes.remove(k);
        }
        count(3, old.len() as u32);
        count(4, old.len() as u32);
    }
    count(2, 1);
    let r = get(&mut node);
    cache.nodes.insert((ssid, tsid, tclass), node);
    r
}

/// Changes the decision in the cache for `(ssid, tsid, tclass)` if it is from the policy load
/// `seqno`, as `avc_update_node` of Linux. A change makes a new node on Linux, so it counts
/// an allocation and a free.
fn update(ssid: u32, tsid: u32, tclass: u16, seqno: u32, f: impl FnOnce(&mut Node)) {
    if let Some(node) = CACHE.lock().nodes.get_mut(&(ssid, tsid, tclass))
        && node.avd.seqno == seqno
    {
        f(node);
        count(2, 1);
        count(4, 1);
    }
}

/// The result of a denial of `requested`, as `avc_denied` of Linux: `EACCES` in enforcing
/// mode, except for a permissive domain. Otherwise the cache allows the permissions for the
/// next checks, as `avc_update_node(AVC_CALLBACK_GRANT)`, and for a check of an extended
/// permission, the permission `xperm` of the driver too, as `avc_xperms_allow_perm`.
fn deny(
    ssid: u32,
    tsid: u32,
    tclass: u16,
    requested: u32,
    ext: Option<(u8, u8, u8)>,
    avd: &AvDecision,
) -> Result<(), Errno> {
    if crate::enforcing() && avd.flags & PERMISSIVE == 0 {
        return Err(Errno::EACCES);
    }
    update(ssid, tsid, tclass, avd.seqno, |node| {
        node.avd.allowed |= requested;
        if let (Some(x), Some((driver, base, xperm))) = (node.xp.as_deref_mut(), ext) {
            xperm_set(&mut x.xp.drivers, driver);
            x.xp.base_perms |= base;
            if let Some(d) = x.decision(driver, base)
                && d.used & used::ALLOWED != 0
            {
                xperm_set(&mut d.allowed, xperm);
            }
        }
    });
    Ok(())
}

/// Removes all the decisions after a policy load or a change of a boolean, as
/// `avc_ss_reset` of Linux. `seqno` is the number of the policy load.
pub fn reset(seqno: u32) {
    let mut cache = CACHE.lock();
    count(4, cache.nodes.len() as u32);
    cache.nodes.clear();
    cache.latest = cache.latest.max(seqno);
}

/// The number of the last policy load that the cache knows, as `avc_policy_seqno` of Linux.
/// An open file keeps this number, and a change of it makes the next read or write of the
/// file check the permissions again.
pub fn policy_seqno() -> u32 {
    CACHE.lock().latest
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
    let (avd, _) = lookup(ssid, tsid, tclass, None);
    if requested & !avd.allowed == 0 {
        return (avd, Ok(()));
    }
    (avd, deny(ssid, tsid, tclass, requested, None, &avd))
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

/// Checks the permissions `requested` and the extended permission `xperm` of `driver` for the
/// base permission `base_perm` (a bit of [`crate::services::ext`]), and makes an audit record
/// if the policy wants one, as `avc_has_extended_perms` of Linux. If the policy has no rules
/// of extended permissions for the SIDs and the class, only `requested` counts. Otherwise a
/// driver without rules denies `requested`, and a driver with rules denies it if `xperm` is
/// not allowed. `extra` is as in [`has_perm`].
///
/// # Errors
///
/// `EACCES` if the policy denies a permission in enforcing mode.
#[allow(clippy::too_many_arguments)]
pub fn has_extended_perms(
    ssid: u32,
    tsid: u32,
    tclass: u16,
    requested: u32,
    driver: u8,
    base_perm: u8,
    xperm: u8,
    extra: impl FnOnce(&mut String),
) -> Result<(), Errno> {
    let (mut avd, xp) = lookup(ssid, tsid, tclass, Some((driver, base_perm)));
    let mut xpd = None;
    if let Some((drivers, cached)) = xp {
        let d = match cached {
            Some(d) => Some(d),
            None if !xperm_test(&drivers.drivers, driver)
                || drivers.base_perms & base_perm == 0 =>
            {
                None
            }
            None => {
                let d = server::compute_xperms_decision(ssid, tsid, tclass, driver, base_perm);
                // As `avc_update_node(AVC_CALLBACK_ADD_XPERMS)` of Linux.
                update(ssid, tsid, tclass, avd.seqno, |node| {
                    if let Some(x) = node.xp.as_deref_mut()
                        && x.decision(driver, base_perm).is_none()
                    {
                        x.decisions.push(d);
                    }
                });
                Some(d)
            }
        };
        if !d.is_some_and(|d| d.has(xperm, used::ALLOWED)) {
            avd.allowed &= !requested;
        }
        xpd = d;
    }
    let rc = if requested & !avd.allowed != 0 {
        deny(ssid, tsid, tclass, requested, Some((driver, base_perm, xperm)), &avd)
    } else {
        Ok(())
    };
    let (audited, denied) =
        xperms_audit_required(requested, &avd, xpd.as_ref(), xperm, rc.is_err());
    record(ssid, tsid, tclass, audited, denied, rc, extra);
    rc
}

/// The permissions that make an audit record and the denied permissions for a check of an
/// extended permission, as `avc_xperms_audit_required` of Linux. A `dontauditxperm` rule for
/// `perm` stops the record of a denial, and an allowed permission makes a record only with an
/// `auditallowxperm` rule for `perm`.
fn xperms_audit_required(
    requested: u32,
    avd: &AvDecision,
    xpd: Option<&XpermsDecision>,
    perm: u8,
    failed: bool,
) -> (u32, u32) {
    let denied = requested & !avd.allowed;
    if denied != 0 {
        let audited = denied & avd.auditdeny;
        if audited != 0 && xpd.is_some_and(|d| d.has(perm, used::DONTAUDIT)) {
            return (0, denied);
        }
        (audited, denied)
    } else if failed {
        (requested, requested)
    } else {
        let audited = requested & avd.auditallow;
        if audited != 0 && xpd.is_some_and(|d| !d.has(perm, used::AUDITALLOW)) {
            return (0, 0);
        }
        (audited, 0)
    }
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
    record(ssid, tsid, tclass, audited, denied, rc, extra);
}

/// Makes the record of the permissions `audited`, of which `denied` are denied, as
/// `slow_avc_audit` of Linux.
fn record(
    ssid: u32,
    tsid: u32,
    tclass: u16,
    audited: u32,
    denied: u32,
    rc: Result<(), Errno>,
    extra: impl FnOnce(&mut String),
) {
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

    #[test]
    fn an_extended_permission_makes_a_record_as_linux() {
        let mut avd = AvDecision::new(1);
        avd.allowed = 1;
        avd.auditallow = 1;
        let mut xpd = XpermsDecision::new(0x54, crate::services::ext::IOCTL);
        xpd.used = used::AUDITALLOW | used::DONTAUDIT;
        xperm_set(&mut xpd.auditallow, 1);
        xperm_set(&mut xpd.dontaudit, 2);
        // A denial makes a record without a dontauditxperm rule for the function.
        assert_eq!(xperms_audit_required(2, &avd, Some(&xpd), 3, true), (2, 2));
        assert_eq!(xperms_audit_required(2, &avd, Some(&xpd), 2, true), (0, 2));
        assert_eq!(xperms_audit_required(2, &avd, None, 2, true), (2, 2));
        // An allowed permission of auditallow makes a record only with an auditallowxperm
        // rule for the function.
        assert_eq!(xperms_audit_required(1, &avd, Some(&xpd), 1, false), (1, 0));
        assert_eq!(xperms_audit_required(1, &avd, Some(&xpd), 2, false), (0, 0));
        assert_eq!(xperms_audit_required(1, &avd, None, 2, false), (1, 0));
        assert_eq!(xperms_audit_required(1, &avd, Some(&xpd), 1, true), (1, 1));
        // A kind of rule that the policy does not use has no functions.
        xpd.used = 0;
        assert_eq!(xperms_audit_required(2, &avd, Some(&xpd), 2, true), (2, 2));
        assert_eq!(xperms_audit_required(1, &avd, Some(&xpd), 1, false), (0, 0));
    }
}

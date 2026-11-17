//! The security server, as the functions `security_*` of security/selinux/ss/services.c of
//! Linux. They use the loaded policy, its table of SIDs and its map of the classes of the
//! kernel.

use crate::policydb::{Context, Policydb, fs_use};
use crate::services::{self, AvDecision, Mapping, NEVERAUDIT, PERMISSIVE, set_mapping};
use crate::sidtab::{Entry, INITIAL_NAMES, NUM_INITIAL, Sidtab, sid};
use crate::{POLICY, POLICY_MUTEX, POLICYCAP_NAMES, POLICYLOAD, SEQUENCE};
use crate::{avc, classmap, enforcing, policy};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

/// A loaded policy, `struct selinux_policy` of Linux, with the bytes that `load_policy` wrote,
/// which the file `policy` of selinuxfs gives back.
pub struct Policy {
    /// The policy. It is in a box, because a copy on the kernel stack is large.
    pub db: Box<Policydb>,
    /// The binary policy.
    pub data: Vec<u8>,
    /// The map of the classes and the permissions of the kernel.
    pub map: Vec<Mapping>,
    /// The table of the SIDs.
    pub sidtab: SpinLock<Sidtab>,
    /// The number of the policy load, `latest_granting` of Linux.
    pub seqno: u32,
}

/// The context of a SID, or `None` with the message of Linux if the table has no context for
/// it.
fn search(p: &Policy, sid: u32, force: bool, func: &str) -> Option<Entry> {
    let e = p.sidtab.lock().search(sid, force);
    if e.is_none() {
        rk_frame::println!("SELinux: {func}:  unrecognized SID {sid}");
    }
    e
}

/// The decision for the SIDs `ssid` and `tsid` and the class `tclass` of the kernel, as
/// `security_compute_av` of Linux. Before the first policy load, all is allowed.
pub fn compute_av(ssid: u32, tsid: u32, tclass: u16) -> AvDecision {
    let Some(p) = policy() else { return AvDecision { allowed: u32::MAX, ..AvDecision::new(0) } };
    let mut avd = AvDecision::new(p.seqno);
    let class = services::unmap_class(&p.map, tclass);
    let unknown = tclass != 0 && class == 0;
    if let Some(d) = decide(&p, ssid, tsid, class, unknown, &mut avd, "security_compute_av") {
        avd.allowed = d.allowed;
        avd.auditallow = d.auditallow;
        avd.auditdeny = d.auditdeny;
        services::map_decision(&p.map, tclass, &mut avd, p.db.allow_unknown);
    }
    finish(avd)
}

/// The decision for the class `tclass` of the policy, as `security_compute_av_user` of Linux,
/// for the file `access` of selinuxfs.
pub fn compute_av_user(ssid: u32, tsid: u32, tclass: u32) -> AvDecision {
    let Some(p) = policy() else { return AvDecision { allowed: u32::MAX, ..AvDecision::new(0) } };
    let mut avd = AvDecision::new(p.seqno);
    let unknown = tclass == 0;
    if let Some(d) = decide(&p, ssid, tsid, tclass, unknown, &mut avd, "security_compute_av_user") {
        avd.allowed = d.allowed;
        avd.auditallow = d.auditallow;
        avd.auditdeny = d.auditdeny;
    }
    finish(avd)
}

/// The common part of [`compute_av`] and [`compute_av_user`]. It sets the flags of `avd`, and
/// gives the decision of the rules, or `None` if `avd` is the decision.
fn decide(
    p: &Policy,
    ssid: u32,
    tsid: u32,
    tclass: u32,
    unknown: bool,
    avd: &mut AvDecision,
    func: &str,
) -> Option<AvDecision> {
    let s = search(p, ssid, false, func)?.context;
    if p.db.permissive.get(s.ty) {
        avd.flags |= PERMISSIVE;
    }
    if p.db.neveraudit.get(s.ty) {
        avd.flags |= NEVERAUDIT;
    }
    if avd.flags == PERMISSIVE | NEVERAUDIT {
        avd.allowed = u32::MAX;
        return None;
    }
    let t = search(p, tsid, false, func)?.context;
    if unknown {
        if p.db.allow_unknown {
            avd.allowed = u32::MAX;
        }
        return None;
    }
    Some(p.db.context_compute_av(&s, &t, tclass))
}

/// A domain that makes no audit records has no audit bits.
fn finish(mut avd: AvDecision) -> AvDecision {
    if avd.flags & NEVERAUDIT != 0 {
        avd.auditallow = 0;
        avd.auditdeny = 0;
    }
    avd
}

/// The SID of the context in the text `text`, as `security_context_to_sid_core` of Linux. The
/// text ends at the first NUL. A context without a range takes the range of the SID `def_sid`,
/// if it is not 0. With `force`, a context that the policy does not accept gets a SID, which
/// gives the context of the SID `unlabeled`. Before the first policy load, the name of an
/// initial SID gives its SID, and another text gives the SID `kernel`.
///
/// # Errors
///
/// `EINVAL` if the text is empty or if the policy does not accept the context.
pub fn context_to_sid(text: &[u8], def_sid: u32, force: bool) -> Result<u32, Errno> {
    if text.is_empty() {
        return Err(Errno::EINVAL);
    }
    let text = text.split(|&c| c == 0).next().unwrap_or_default();
    let text = core::str::from_utf8(text).ok();
    loop {
        let Some(p) = policy() else {
            let found =
                (1..NUM_INITIAL).find(|&i| text.is_some() && INITIAL_NAMES[i as usize] == text);
            return Ok(found.unwrap_or(sid::KERNEL));
        };
        let def = match def_sid {
            0 => None,
            s => p.sidtab.lock().search(s, false).map(|e| e.context),
        };
        let entry = match text.and_then(|t| p.db.string_to_context(t, def.as_ref())) {
            Some(c) => Entry { context: c, invalid: None },
            None if force => {
                let raw = String::from_utf8_lossy(text.unwrap_or_default().as_bytes());
                Entry { context: Default::default(), invalid: Some(raw.into_owned()) }
            }
            None => return Err(Errno::EINVAL),
        };
        let mut tab = p.sidtab.lock();
        if !tab.frozen {
            return Ok(tab.context_to_sid(&p.db, entry));
        }
    }
}

/// The text of the context of the SID `sid`, as `security_sid_to_context` of Linux. A SID of a
/// context that the policy does not accept gives the context of the SID `unlabeled`.
///
/// # Errors
///
/// `EINVAL` if there is no context for the SID.
pub fn sid_to_context(sid: u32) -> Result<String, Errno> {
    sid_to_context_core(sid, false)
}

/// The text of the context of the SID `sid`, also of a context that the policy does not
/// accept, as `security_sid_to_context_force` of Linux.
///
/// # Errors
///
/// `EINVAL` if there is no context for the SID.
pub fn sid_to_context_force(sid: u32) -> Result<String, Errno> {
    sid_to_context_core(sid, true)
}

/// The text of the context of the SID `sid` if the policy does not accept it, as
/// `security_sid_to_context_inval` of Linux.
pub fn sid_to_context_invalid(sid: u32) -> Option<String> {
    policy()?.sidtab.lock().search(sid, true)?.invalid
}

fn sid_to_context_core(sid: u32, force: bool) -> Result<String, Errno> {
    let func = "security_sid_to_context_core";
    let Some(p) = policy() else {
        if sid > NUM_INITIAL {
            rk_frame::println!(
                "SELinux: {func}:  called before initial load_policy on unknown SID {sid}"
            );
            return Err(Errno::EINVAL);
        }
        // Before the policy load, the SID `init` gives `kernel`, because systemd and old
        // versions of libselinux take another context to tell that a policy is loaded.
        let sid = if sid == sid::INIT { sid::KERNEL } else { sid };
        return INITIAL_NAMES[sid as usize].map(String::from).ok_or(Errno::EINVAL);
    };
    let e = search(&p, sid, force, func).ok_or(Errno::EINVAL)?;
    Ok(e.invalid.unwrap_or_else(|| p.db.context_to_string(&e.context)))
}

/// The SID of a new object or of a process after an exec, as `security_compute_sid` of Linux.
/// `tclass` is a class of the kernel if `kern` is true, else a class of the policy.
fn compute_sid(
    ssid: u32,
    tsid: u32,
    tclass: u32,
    specified: u16,
    name: Option<&[u8]>,
    kern: bool,
) -> Result<u32, Errno> {
    let func = "security_compute_sid";
    let Some(p) = policy() else {
        return Ok(if tclass == u32::from(classmap::class::PROCESS) { ssid } else { tsid });
    };
    let (class, sock) = if kern {
        let k = u16::try_from(tclass).unwrap_or(0);
        (services::unmap_class(&p.map, k), classmap::is_socket(k))
    } else {
        (tclass, services::is_socket_value(&p.map, tclass))
    };
    let s = search(&p, ssid, false, func).ok_or(Errno::EINVAL)?.context;
    let t = search(&p, tsid, false, func).ok_or(Errno::EINVAL)?.context;
    let new =
        p.db.context_compute_sid(&s, &t, class, specified, name, sock).ok_or(Errno::EINVAL)?;
    if !p.db.context_valid(&new) {
        let mut text = String::from("op=security_compute_sid invalid_context=");
        avc::untrusted(&mut text, p.db.context_to_string(&new).as_bytes());
        let ctx = |sid| sid_to_context_force(sid).unwrap_or_default();
        let cname = p.db.name(crate::policydb::sym::CLASSES, class).unwrap_or_default();
        text.push_str(&format!(" scontext={} tcontext={} tclass={cname}", ctx(ssid), ctx(tsid)));
        services::log_err(&text);
        if enforcing() {
            return Err(Errno::EACCES);
        }
    }
    if new == s {
        return Ok(ssid);
    }
    if new == t {
        return Ok(tsid);
    }
    loop {
        let p = policy().ok_or(Errno::EINVAL)?;
        let mut tab = p.sidtab.lock();
        if !tab.frozen {
            return Ok(tab.context_to_sid(&p.db, Entry { context: new, invalid: None }));
        }
    }
}

/// The SID of a new object of the class `tclass` of the kernel, as `security_transition_sid`
/// of Linux. `name` is the name of a new file.
///
/// # Errors
///
/// `EINVAL` for an unknown SID, `EACCES` for a context that the policy does not accept in
/// enforcing mode.
pub fn transition_sid(
    ssid: u32,
    tsid: u32,
    tclass: u16,
    name: Option<&[u8]>,
) -> Result<u32, Errno> {
    compute_sid(ssid, tsid, u32::from(tclass), crate::avtab::spec::TRANSITION, name, true)
}

/// The SID of a new object of the class `tclass` of the policy, as
/// `security_transition_sid_user` of Linux, for the file `create` of selinuxfs.
///
/// # Errors
///
/// As [`transition_sid`].
pub fn transition_sid_user(
    ssid: u32,
    tsid: u32,
    tclass: u32,
    name: Option<&[u8]>,
) -> Result<u32, Errno> {
    compute_sid(ssid, tsid, tclass, crate::avtab::spec::TRANSITION, name, false)
}

/// The SID of a member of a polyinstantiated object, as `security_member_sid` of Linux.
///
/// # Errors
///
/// As [`transition_sid`].
pub fn member_sid(ssid: u32, tsid: u32, tclass: u32) -> Result<u32, Errno> {
    compute_sid(ssid, tsid, tclass, crate::avtab::spec::MEMBER, None, false)
}

/// The SID for a relabel of an object, as `security_change_sid` of Linux.
///
/// # Errors
///
/// As [`transition_sid`].
pub fn change_sid(ssid: u32, tsid: u32, tclass: u32) -> Result<u32, Errno> {
    compute_sid(ssid, tsid, tclass, crate::avtab::spec::CHANGE, None, false)
}

/// The SID of the context that `find` gives from the policy, as `ocontext_to_sid` of Linux, or
/// `None` before the first policy load or if `find` gives no context. A policy load between
/// the search and the table of the SIDs makes the search again in the new policy.
fn ocontext_sid(mut find: impl FnMut(&Policy) -> Option<Context>) -> Option<u32> {
    loop {
        let p = policy()?;
        let context = find(&p)?;
        let mut tab = p.sidtab.lock();
        if !tab.frozen {
            return Some(tab.context_to_sid(&p.db, Entry { context, invalid: None }));
        }
    }
}

/// The context of the first `genfscon` rule of the file system type `fstype` for the path
/// `path` and the class `tclass` of the kernel, as `__security_genfs_sid` of Linux. The rules
/// of a type are sorted with the longest path first, and a rule is for a path that starts with
/// its path. A rule without a class is for each class.
fn genfs_context(p: &Policy, fstype: &str, path: &[u8], tclass: u16) -> Option<Context> {
    let class = services::unmap_class(&p.map, tclass);
    let (_, rules) = p.db.genfs.iter().find(|(name, _)| name == fstype)?;
    let rule = rules
        .iter()
        .find(|r| (r.sclass == 0 || r.sclass == class) && path.starts_with(r.path.as_bytes()))?;
    Some(rule.context.clone())
}

/// The way that the policy labels the files of the file system type `fstype`, and the SID of
/// the file system, as `security_fs_use` of Linux. A `fs_use_*` rule for the type gives its
/// behavior and its context. Else the `genfscon` rule of the type for `/` gives
/// [`fs_use::GENFS`] and its context, and a type without a rule gets [`fs_use::NONE`] and the
/// SID `unlabeled`. Before the first policy load, all types get [`fs_use::NONE`].
pub fn fs_use(fstype: &str) -> (u32, u32) {
    let mut behavior = fs_use::NONE;
    let sid = ocontext_sid(|p| {
        if let Some(c) = p.db.ocon.fsuse.iter().find(|c| c.key.fstype == fstype) {
            behavior = c.key.behavior;
            return Some(c.context.clone());
        }
        let c = genfs_context(p, fstype, b"/", classmap::class::DIR);
        behavior = if c.is_some() { fs_use::GENFS } else { fs_use::NONE };
        c
    });
    (behavior, sid.unwrap_or(sid::UNLABELED))
}

/// The SID of the file `path` of the class `tclass` of the kernel in a file system of the type
/// `fstype`, from the `genfscon` rules, as `security_genfs_sid` of Linux.
///
/// # Errors
///
/// `ENOENT` if no rule is for the file, or before the first policy load.
pub fn genfs_sid(fstype: &str, path: &[u8], tclass: u16) -> Result<u32, Errno> {
    ocontext_sid(|p| genfs_context(p, fstype, path, tclass)).ok_or(Errno::ENOENT)
}

/// Checks that the type of the SID `new` is the type of the SID `old` or has it in its chain of
/// bounds, as `security_bounded_transition` of Linux. A bounded type has only a part of the
/// permissions of its bound, so a change to it gives no new permission. A denial makes a
/// `SELINUX_ERR` audit record. Before the first policy load, all changes are bounded.
///
/// # Errors
///
/// `EINVAL` for an unknown SID, `EPERM` if the type of `new` is not bounded by the type of
/// `old`.
pub fn bounded_transition(old: u32, new: u32) -> Result<(), Errno> {
    let Some(p) = policy() else { return Ok(()) };
    let func = "security_bounded_transition";
    let o = search(&p, old, false, func).ok_or(Errno::EINVAL)?.context;
    let n = search(&p, new, false, func).ok_or(Errno::EINVAL)?.context;
    if o.ty == n.ty || p.db.type_bounded_by(n.ty, o.ty) {
        return Ok(());
    }
    services::log_err(&format!(
        "op=security_bounded_transition seresult=denied oldcontext={} newcontext={}",
        p.db.context_to_string(&o),
        p.db.context_to_string(&n)
    ));
    Err(Errno::EPERM)
}

/// Reads a binary policy into a box. The function is not inline, so that the large values of
/// the read are not in the frame of [`load_policy`] on the kernel stack.
#[inline(never)]
fn read_policy(data: &[u8]) -> Result<Box<Policydb>, Errno> {
    match Policydb::read(data) {
        Ok(db) => Ok(Box::new(db)),
        Err(e) => {
            rk_frame::println!("SELinux:  policydb: {e}");
            Err(Errno::EINVAL)
        }
    }
}

/// Loads a binary policy, as `security_load_policy` and `selinux_policy_commit` of Linux. A
/// new policy keeps the values of the booleans of the old policy and the SIDs. The load
/// prints the policy capabilities, removes the decisions of the cache, and updates the status
/// page.
///
/// # Errors
///
/// `EINVAL` if the policy is bad.
pub fn load_policy(data: &[u8]) -> Result<(), Errno> {
    let db = read_policy(data)?;
    let map = set_mapping(&db).ok_or(Errno::EINVAL)?;
    let mut sidtab = Sidtab::new(&db).ok_or(Errno::EINVAL)?;
    let _guard = POLICY_MUTEX.lock();
    let old = policy();
    if let Some(old) = &old {
        for b in old.db.bools.iter().flatten() {
            if let Some(n) = db.bools.iter().flatten().find(|n| n.name == b.name) {
                n.state.store(b.state.load(Ordering::Relaxed), Ordering::Relaxed);
            }
        }
        db.evaluate_conds();
        if old.db.mls && !db.mls {
            rk_frame::println!("SELinux: Disabling MLS support...");
        } else if !old.db.mls && db.mls {
            rk_frame::println!("SELinux: Enabling MLS support...");
        }
    }
    let seqno = old.as_ref().map_or(1, |o| o.seqno + 1);
    let caps: Vec<_> = (0..POLICYCAP_NAMES.len()).map(|i| db.policycap(i as u32)).collect();
    let unknown: Vec<_> =
        db.policycaps.iter().filter(|&c| c as usize >= POLICYCAP_NAMES.len()).collect();
    // The old table stays locked until the new policy is in place, so that no new SID goes to
    // the old table after the copy.
    let mut old_tab = old.as_ref().map(|o| o.sidtab.lock());
    if let (Some(old), Some(tab)) = (&old, &mut old_tab) {
        tab.convert(&old.db, &db, &mut sidtab, enforcing());
        tab.frozen = true;
    }
    let new = Policy { db, data: data.to_vec(), map, sidtab: SpinLock::new(sidtab), seqno };
    *POLICY.lock() = Some(Arc::new(new));
    drop(old_tab);
    for (name, on) in POLICYCAP_NAMES.iter().zip(caps) {
        rk_frame::println!("SELinux:  policy capability {name}={}", u8::from(on));
    }
    for c in unknown {
        rk_frame::println!("SELinux:  unknown policy capability {c}");
    }
    avc::reset(seqno);
    POLICYLOAD.store(seqno, Ordering::Relaxed);
    SEQUENCE.fetch_add(2, Ordering::Relaxed);
    Ok(())
}

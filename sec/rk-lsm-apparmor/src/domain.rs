//! The label of a task and its change at `execve`, as domain.c and the label parts of lsm.c,
//! file.c and procattr.c of Linux.
//!
//! The credentials blob holds the label of the task: 0 for `unconfined`, or the number of the
//! name of a label. The name of a label is the full name of a profile, or a stack of profiles:
//! their full names with `//&` between them, as Linux writes a label. The name gives the newest
//! version of each profile, as the proxy of a label of Linux does. A profile that was removed
//! goes out of the label, and a label with no profile is `unconfined`. After the label, the blob
//! holds the context of the task, `struct aa_task_ctx` of Linux: the label before a hat, the
//! label for the next exec and the token of the hat ([`slot`]).
//!
//! Each profile of a stack checks each operation, and the exec of a task with a stack changes
//! each profile of the stack, as on Linux.
//!
//! A profile in enforce mode denies an operation that its rules do not allow: the operation
//! gives `EACCES` and the log gets a `DENIED` record. A profile in complain mode gives an
//! `ALLOWED` record and the operation goes on. A profile in kill mode also kills the task. A
//! `deny` rule denies in each mode, as on Linux.

use crate::audit::{self, Kind};
use crate::dfa::{NOMATCH, State};
use crate::policy::{self, Mode, Profile};
use crate::unpack::{Pdb, Perms, class, perm, x};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::cred::Cred;
use rk_vfs::inode::Result;
use rk_vfs::security::{Bprm, Task, id};

/// The names of the profiles in the credentials blobs.
struct Names {
    /// The number of each name.
    ids: BTreeMap<String, u64>,
    /// The names. The name with the number 1 is first.
    names: Vec<String>,
}

static NAMES: SpinLock<Names> = SpinLock::new(Names { ids: BTreeMap::new(), names: Vec::new() });

/// The size of the part of AppArmor in the credentials blob: the label and the context of the
/// task.
pub const CRED_BLOB: usize = 32;

/// The byte offsets of the words in the part of AppArmor in the credentials blob.
pub mod slot {
    /// The label of the task: 0 for `unconfined`, or the number of the name of a label.
    pub const LABEL: usize = 0;
    /// The label before the change to a hat, `previous`, as a [`super::label_ref`].
    pub const PREVIOUS: usize = 8;
    /// The label for the next exec, `onexec`, as a [`super::label_ref`].
    pub const ONEXEC: usize = 16;
    /// The token of the hat, `token`. With a label for the next exec, it is 1 if the label
    /// goes on a stack.
    pub const TOKEN: usize = 24;
}

/// The value of a [`label_ref`] for `unconfined`.
const UNCONFINED_REF: u64 = u64::MAX;

/// The byte offset of the part of AppArmor in the credentials blob, or `None` if the module is
/// not active.
fn cred_offset() -> Option<usize> {
    rk_vfs::security::modules()
        .iter()
        .find(|m| m.info.id.id == id::APPARMOR)
        .map(|m| m.offsets.cred)
}

/// The number of the name `name`. A new name gets the next number.
fn intern(name: &str) -> u64 {
    let mut n = NAMES.lock();
    if let Some(&i) = n.ids.get(name) {
        return i;
    }
    n.names.push(String::from(name));
    let i = n.names.len() as u64;
    n.ids.insert(String::from(name), i);
    i
}

/// The word at the byte offset `slot` of the part of AppArmor in the blob of `cred`.
pub fn load(cred: &Cred, slot: usize) -> u64 {
    cred_offset().map_or(0, |off| cred.security.load(off + slot))
}

/// Writes the word at the byte offset `slot` of the part of AppArmor in the blob of `cred`.
pub fn store(cred: &Cred, slot: usize, value: u64) {
    if let Some(off) = cred_offset() {
        cred.security.store(off + slot, value);
    }
}

/// The number of the label of `cred`. 0 is `unconfined`.
pub fn label_id(cred: &Cred) -> u64 {
    load(cred, slot::LABEL)
}

/// A label: the profiles of a stack, or one profile. No profile is `unconfined`.
pub type Label = Vec<Arc<Profile>>;

/// The separator of the profiles of a stack in the name of a label.
pub const STACK: &str = "//&";

/// The name of the label `l` for the blob: the full names of its profiles with `//&` between
/// them. Gives `None` for `unconfined`.
fn label_name(l: &[Arc<Profile>]) -> Option<String> {
    let names: Vec<_> = l.iter().map(|p| p.fqname()).collect();
    (!names.is_empty()).then(|| names.join(STACK))
}

/// The word that refers to the label `l` in the context of a task. 0 is no label, so
/// `unconfined` has its own value.
pub fn label_ref(l: &[Arc<Profile>]) -> u64 {
    label_name(l).map_or(UNCONFINED_REF, |n| intern(&n))
}

/// The newest label of the word `v` of the context of a task. `None` is no label.
pub fn ref_label(v: u64) -> Option<Label> {
    match v {
        0 => None,
        UNCONFINED_REF => Some(Vec::new()),
        v => Some(label_by_id(v)),
    }
}

/// The stack of the labels `a` and `b`, as `aa_label_merge` of Linux: the profiles of `a`, then
/// the profiles of `b` that are not in `a`.
pub fn merge(a: &[Arc<Profile>], b: &[Arc<Profile>]) -> Label {
    let mut out = a.to_vec();
    for p in b {
        if !out.iter().any(|q| q.fqname() == p.fqname()) {
            out.push(p.clone());
        }
    }
    out
}

/// Clears the label before the hat, the label for the next exec and the token, as
/// `aa_clear_task_ctx_trans` of Linux.
pub fn clear_trans(cred: &Cred) {
    for s in [slot::PREVIOUS, slot::ONEXEC, slot::TOKEN] {
        store(cred, s, 0);
    }
}

/// The newest label of the label number `id`, `aa_get_newest_label` of Linux. A profile that
/// was removed goes out of the label.
pub fn label_by_id(id: u64) -> Label {
    let Some(i) = usize::try_from(id).ok().and_then(|i| i.checked_sub(1)) else {
        return Vec::new();
    };
    let Some(name) = NAMES.lock().names.get(i).cloned() else { return Vec::new() };
    name.split(STACK).filter_map(policy::lookup_fq).collect()
}

/// The first profile of the label number `id`. `None` is `unconfined`.
pub fn profile_by_id(id: u64) -> Option<Arc<Profile>> {
    label_by_id(id).into_iter().next()
}

/// The label of `cred`, `aa_get_newest_cred_label` of Linux.
pub fn label_of(cred: &Cred) -> Label {
    label_by_id(label_id(cred))
}

/// The first profile of the label of `cred`, for a view of the names. `None` is `unconfined`.
pub fn profile_of(cred: &Cred) -> Option<Arc<Profile>> {
    profile_by_id(label_id(cred))
}

/// Sets the label of `cred`, `set_cred_label` of Linux.
pub fn set_label(cred: &Cred, l: &[Arc<Profile>]) {
    store(cred, slot::LABEL, label_name(l).map_or(0, |n| intern(&n)));
}

/// Sets the label of `cred` to the profile `p`. `None` is `unconfined`.
pub fn set_profile(cred: &Cred, p: Option<&Arc<Profile>>) {
    set_label(cred, p.map(core::slice::from_ref).unwrap_or_default());
}

/// The text of the label `l` with its mode, as `aa_getprocattr` of Linux gives it to a task with
/// the profile `view`, without the new line. `unconfined` has no mode, and a stack of profiles
/// with different modes has the mode `mixed`.
pub fn label_text(l: &[Arc<Profile>], view: Option<&Profile>) -> String {
    let Some(first) = l.first() else { return String::from("unconfined") };
    let names: Vec<_> = l.iter().map(|p| p.name_in(view)).collect();
    let same = l.iter().all(|p| p.mode == first.mode);
    let mode = if same { first.mode.name() } else { "mixed" };
    format!("{} ({mode})", names.join(STACK))
}

/// A read of `/proc/PID/attr/NAME`, `apparmor_getprocattr` of Linux. `current` gives the
/// label of the task, `prev` the label before the hat and `exec` the label for the next exec.
///
/// # Errors
///
/// Gives `EINVAL` for `prev` and `exec` when the task has no such label, and for another name.
pub fn getprocattr(task: &Task<'_>, name: &str) -> Result<Vec<u8>> {
    let label = match name {
        "current" => label_of(task.cred),
        "prev" => ref_label(load(task.cred, slot::PREVIOUS)).ok_or(Errno::EINVAL)?,
        "exec" => ref_label(load(task.cred, slot::ONEXEC)).ok_or(Errno::EINVAL)?,
        _ => return Err(Errno::EINVAL),
    };
    let view = profile_of(&rk_vfs::cred::current());
    let mut s = label_text(&label, view.as_deref());
    s.push('\n');
    Ok(s.into_bytes())
}

/// The attribute `attr` of `task` for `lsm_get_self_attr`, `apparmor_getselfattr` of Linux:
/// the text of the label, without a new line.
///
/// # Errors
///
/// Gives `ENOENT` for `LSM_ATTR_PREV` and `LSM_ATTR_EXEC` when the task has no such label, and
/// `EOPNOTSUPP` for another attribute.
pub fn getselfattr(attr: u64, task: &Task<'_>) -> Result<Vec<u8>> {
    use rk_vfs::security::attr;
    let label = match attr {
        attr::CURRENT => label_of(task.cred),
        attr::PREV => ref_label(load(task.cred, slot::PREVIOUS)).ok_or(Errno::ENOENT)?,
        attr::EXEC => ref_label(load(task.cred, slot::ONEXEC)).ok_or(Errno::ENOENT)?,
        _ => return Err(Errno::EOPNOTSUPP),
    };
    let view = profile_of(task.cred);
    Ok(label_text(&label, view.as_deref()).into_bytes())
}

/// The permissions of the accept state `state` for the owner of the file or for the others,
/// `aa_lookup_fperms` of Linux.
fn lookup_fperms(pdb: &Pdb, state: State, owner: bool) -> Perms {
    let Some(d) = pdb.dfa.as_ref() else { return Perms::default() };
    let index = d.accept().get(state as usize).copied().unwrap_or(0) as usize;
    pdb.perms.get(index + usize::from(!owner)).copied().unwrap_or_default()
}

/// Adds the permissions `b` to the permissions `a` of all the parts of a label,
/// `aa_perms_accum` of Linux.
fn accum(a: &mut Perms, b: &Perms) {
    a.deny |= b.deny;
    a.allow &= b.allow & !a.deny;
    a.audit |= b.audit & a.allow;
    a.quiet &= b.quiet & !a.allow;
    a.kill |= b.kill & !a.allow;
    a.complain |= b.complain & !a.allow & !a.deny;
    a.cond |= b.cond & !a.allow & !a.deny;
    a.hide &= b.hide & !a.allow;
    a.prompt |= b.prompt & !a.allow & !a.deny;
    a.subtree |= b.subtree & !a.deny;
}

/// The permissions of the file rules for the path `name`, `aa_str_perms` of Linux. `owner`
/// tells if the file system user ID of the task is the owner of the file.
pub fn str_perms(pdb: &Pdb, name: &[u8], owner: bool) -> Perms {
    str_perms_at(pdb, pdb.start[class::FILE], name, owner).1
}

/// As [`str_perms`], but from the state `start`. Also gives the state after the name, for the
/// second name of a pair of names.
pub fn str_perms_at(pdb: &Pdb, start: State, name: &[u8], owner: bool) -> (State, Perms) {
    let Some(d) = pdb.dfa.as_ref() else { return (NOMATCH, Perms::default()) };
    let state = d.match_bytes(start, name);
    (state, lookup_fperms(pdb, state, owner))
}

/// The characters of the file permissions in the log, `aa_file_perm_chrs` of Linux.
const FILE_PERM_CHRS: &[u8] = b"xwracd         km l     ";

/// The permissions that the log of a file operation shows, `AA_AUDIT_FILE_MASK` of Linux.
pub const AUDIT_FILE_MASK: u32 = perm::READ
    | perm::WRITE
    | perm::EXEC
    | perm::APPEND
    | perm::CREATE
    | perm::DELETE
    | perm::GETATTR
    | perm::SETATTR
    | perm::CHMOD
    | perm::CHOWN
    | perm::LOCK
    | perm::EXEC_MMAP
    | perm::LINK;

/// The permissions that have a character, `PERMS_CHRS_MASK` of Linux.
const CHRS_MASK: u32 = perm::READ
    | perm::WRITE
    | perm::CREATE
    | perm::DELETE
    | perm::LINK
    | perm::LOCK
    | perm::EXEC
    | perm::EXEC_MMAP
    | perm::APPEND;

/// The text of the permissions `mask`, as `map_mask_to_chr_mask` and `aa_perm_mask_to_str` of
/// Linux.
pub fn mask_text(mask: u32) -> String {
    let mut m = mask & CHRS_MASK;
    if mask & perm::GETATTR != 0 {
        m |= perm::READ;
    }
    if mask & (perm::SETATTR | perm::CHMOD | perm::CHOWN) != 0 {
        m |= perm::WRITE;
    }
    FILE_PERM_CHRS
        .iter()
        .enumerate()
        .filter(|&(i, _)| m & (1 << i) != 0)
        .map(|(_, &c)| char::from(c))
        .collect()
}

/// A file operation for the log, the file part of `struct apparmor_audit_data` of Linux.
pub struct FileAudit<'a> {
    /// The operation, `OP_*`.
    pub op: &'static str,
    /// The permissions that the task asks for.
    pub request: u32,
    /// The path of the file, or the name of the hat or the profile of a change. The record
    /// has no name if it is empty.
    pub name: &'a [u8],
    /// The target of the operation: a label or a path.
    pub target: Option<&'a str>,
    /// The owner of the file.
    pub ouid: u32,
    /// A text about the result.
    pub info: Option<&'static str>,
    /// The error, `EACCES` if the policy does not allow the operation.
    pub error: Option<Errno>,
}

/// Logs a file operation of a task with the profile `p` (`None` for `unconfined`), as
/// `aa_audit_file` and `aa_audit` of Linux. Gives the error of the operation: a denial of a
/// profile in complain mode gives an `ALLOWED` record and no error, and a denial of the other
/// modes gives a `DENIED` record and the error. A failure of `unconfined` gives `DENIED`.
///
/// # Errors
///
/// Gives the error of `a`, except for a denial that complain mode allows.
pub fn audit_file(p: Option<&Profile>, perms: &Perms, a: &FileAudit<'_>) -> Result<()> {
    audit_file_as(p, perms, a, None)
}

/// The kind of the record of a failure, as `aa_audit` of Linux: `ALLOWED` for a profile in
/// complain mode, `KILLED` for a profile in kill mode, and `DENIED` for the others.
pub fn mode_kind(p: Option<&Profile>) -> Kind {
    match p.map(|p| p.mode) {
        Some(Mode::Complain) => Kind::Allowed,
        Some(Mode::Kill) => Kind::Killed,
        _ => Kind::Denied,
    }
}

/// The result of a record of the kind `kind` with the error `error`, as the end of `aa_audit`
/// of Linux: complain mode allows a denial, `complain_error`. A record of the kind `KILLED`
/// kills the task.
///
/// # Errors
///
/// Gives `error`, except for a denial that complain mode allows.
pub fn outcome(kind: Kind, error: Option<Errno>) -> Result<()> {
    if kind == Kind::Killed {
        audit::kill_current();
    }
    match error {
        Some(Errno::EACCES | Errno::EPERM) if kind == Kind::Allowed => Ok(()),
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// As [`audit_file`], but a failure gives a record of the kind `kind` if it is there.
///
/// # Errors
///
/// Gives the error of `a`, except for a denial that complain mode allows.
pub fn audit_file_as(
    p: Option<&Profile>,
    perms: &Perms,
    a: &FileAudit<'_>,
    kind: Option<Kind>,
) -> Result<()> {
    let audit_all = p.and_then(|p| p.rules.as_ref()).is_some_and(|r| r.audit);
    let mut request = a.request;
    let kind = if a.error.is_none() {
        // Only the permissions that the policy audits, or all with the audit mode `all`.
        request &= if audit_all { 0xffff } else { perms.audit };
        Kind::Audit
    } else {
        // Only the permissions that the policy does not allow.
        request &= !perms.allow;
        let kill = request & perms.kill != 0;
        // A rule with `quiet` hides them, but not with the audit mode `all`. As on Linux, a
        // denial with no record gives its error also in complain mode: a `deny` rule denies in
        // each mode.
        if !audit_all {
            request &= !perms.quiet;
        }
        if request == 0 {
            return a.error.map_or(Ok(()), Err);
        }
        match kind {
            Some(k) => k,
            None if kill => Kind::Killed,
            None => mode_kind(p),
        }
    };
    if request == 0 {
        return Ok(());
    }
    let denied = request & !perms.allow;
    let mut tail = String::new();
    if request & AUDIT_FILE_MASK != 0 {
        tail.push_str(&format!(" requested_mask=\"{}\"", mask_text(request)));
    }
    if denied & AUDIT_FILE_MASK != 0 {
        tail.push_str(&format!(" denied_mask=\"{}\"", mask_text(denied)));
    }
    if request & AUDIT_FILE_MASK != 0 {
        let fsuid = rk_vfs::cred::current().fsuid;
        tail.push_str(&format!(" fsuid={fsuid} ouid={}", a.ouid));
    }
    if let Some(t) = a.target {
        tail.push_str(" target=");
        audit::untrusted(&mut tail, t.as_bytes());
    }
    let name = String::from_utf8_lossy(a.name);
    let fq = p.map(Profile::fqname);
    let d = audit::Data {
        op: Some(a.op),
        class: Some("file"),
        info: a.info,
        error: a.error.map_or(0, |e| -i32::from(e.get())),
        profile: Some(fq.as_deref().unwrap_or("unconfined")),
        name: (!a.name.is_empty()).then_some(name.as_ref()),
    };
    audit::log(kind, &d, &tail);
    outcome(kind, a.error)
}

/// The text of a conflict of two attachments, `CONFLICTING_ATTACH_STR` of Linux.
const CONFLICT: &str = "conflicting profile attachments";

/// The best attach of the profiles `list` for the program `name`, `find_attach` of Linux.
/// Gives the profile, or the text of a conflict.
fn find_attach(list: &[Arc<Profile>], name: &[u8]) -> (Option<Arc<Profile>>, Option<&'static str>) {
    let mut best: Option<&Arc<Profile>> = None;
    let mut best_len = 0;
    let mut conflict = false;
    for p in list {
        let xm = p.rules.as_ref().map(|r| (&r.xmatch, r.xmatch_len));
        let Some((xm, xmatch_len, d)) = xm.and_then(|(xm, l)| Some((xm, l, xm.dfa.as_ref()?)))
        else {
            // A profile without a pattern attaches to the program with its exact name.
            if p.base_name().as_bytes() == name {
                return (Some(p.clone()), None);
            }
            continue;
        };
        let (state, count) = d.leftmatch(xm.start[class::XMATCH], name);
        let index = d.accept().get(state as usize).copied().unwrap_or(0) as usize;
        let allow = xm.perms.get(index).map_or(0, |p| p.allow);
        // Each state that accepts is a match.
        if state == NOMATCH || allow & perm::EXEC == 0 || count < best_len {
            continue;
        }
        // A match with the same length is a conflict. This kernel does not check the extended
        // attributes of the file.
        if count == best_len {
            conflict = true;
            continue;
        }
        best = Some(p);
        best_len = count.max(xmatch_len);
        conflict = false;
    }
    if conflict {
        return (None, Some(CONFLICT));
    }
    (best.cloned(), None)
}

/// The profile of the transition table entry of `xindex` in `p`, `x_table_lookup` of Linux.
/// Gives the profile and the name of the entry. Only the first name of the entry counts, as on
/// Linux.
fn x_table_lookup(p: &Profile, xindex: u32) -> (Option<Arc<Profile>>, Option<String>) {
    let Some(r) = p.rules.as_ref() else { return (None, None) };
    let index = (xindex & x::INDEX_MASK) as usize;
    let Some(ent) = r.file.trans.get(index) else { return (None, None) };
    let first = ent.text.split(|&b| b == 0).next().unwrap_or(&[]);
    let next = String::from_utf8_lossy(first).into_owned();
    let lookup = next.strip_prefix('&').unwrap_or(&next);
    let found = if xindex & x::CHILD != 0 {
        policy::with_ns(p.ns.as_deref(), |ns| ns.lookup(&format!("{}//{lookup}", p.name)))
    } else if lookup.starts_with(':') {
        policy::lookup_fq(lookup)
    } else {
        policy::with_ns(p.ns.as_deref(), |ns| ns.lookup(lookup))
    };
    (found, Some(next))
}

/// The result of an exec transition.
struct Transition {
    /// The new profile, `None` for `unconfined`.
    new: Option<Arc<Profile>>,
    /// A text about the result.
    info: Option<&'static str>,
}

/// The label for the exec of `name` from `p` with the transition `xindex`, `x_to_label` of
/// Linux. `None` if no label is there. A stack (`&NAME`) is not there yet: the transition takes
/// the attach of the program, without the stack. Also gives the name of the lookup, for the
/// record of a failure.
fn x_to_label(p: &Arc<Profile>, name: &[u8], xindex: u32) -> (Option<Transition>, Option<String>) {
    let mut info = None;
    let mut new: Option<Option<Arc<Profile>>> = None;
    let mut by_name = xindex & x::TYPE_MASK == x::NAME;
    let mut lookup = None;
    if xindex & x::TYPE_MASK == x::TABLE {
        let (found, n) = x_table_lookup(p, xindex);
        by_name = found.is_some() && n.as_deref().is_some_and(|n| n.starts_with('&'));
        if !by_name {
            new = found.map(Some);
            lookup = n;
        }
    }
    if by_name {
        lookup = Some(String::from_utf8_lossy(name).into_owned());
        let parent = if xindex & x::CHILD != 0 { Some(p.name.as_str()) } else { None };
        let list = policy::with_ns(p.ns.as_deref(), |ns| ns.children(parent));
        let (found, i) = find_attach(&list, name);
        info = i;
        new = found.map(Some);
    }
    if new.is_none() {
        let conflict = info == Some(CONFLICT);
        if xindex & x::INHERIT != 0 {
            info = Some(if conflict {
                "conflicting profile attachments - ix fallback"
            } else {
                "ix fallback"
            });
            new = Some(Some(p.clone()));
        } else if xindex & x::UNCONFINED != 0 {
            info = Some(if conflict {
                "conflicting profile attachments - ux fallback"
            } else {
                "ux fallback"
            });
            new = Some(None);
        }
    }
    (new.map(|new| Transition { new, info }), lookup)
}

/// The new label of an exec of the file `name` with the owner `ouid` from the profile `p`,
/// `profile_transition` of Linux. Gives the new profile and if the program gets `AT_SECURE`.
/// In complain mode, an exec with no exec rule gets a learning profile.
///
/// # Errors
///
/// Gives `EACCES` if the rules do not allow the exec, or if the profile of the transition is
/// not there.
fn profile_transition(
    p: &Arc<Profile>,
    name: &[u8],
    ouid: u32,
) -> Result<(Option<Arc<Profile>>, bool)> {
    let owner = rk_vfs::cred::current().fsuid == ouid;
    let mut perms = p.rules.as_ref().map_or(Perms::default(), |r| str_perms(&r.file, name, owner));
    let mut a = FileAudit {
        op: "exec",
        request: perm::EXEC,
        name,
        target: None,
        ouid,
        info: None,
        error: None,
    };
    let mut found = None;
    let mut lookup = None;
    if perms.allow & perm::EXEC != 0 {
        match x_to_label(p, name, perms.xindex) {
            (Some(t), _) => found = Some(t),
            (None, l) => {
                a.info = Some("profile transition not found");
                perms.allow &= !perm::EXEC;
                lookup = l;
            }
        }
    }
    let (new, secure, target) = match found {
        Some(t) => {
            let same = t.new.as_ref().is_some_and(|n| Arc::ptr_eq(n, p));
            a.info = t.info;
            // The fallback to `ix` after a conflict is always in the log.
            if same && matches!(t.info, Some(i) if i.starts_with(CONFLICT)) {
                perms.audit |= perm::EXEC;
            }
            let secure = !(same && t.info.is_some()) && perms.xindex & x::UNSAFE == 0;
            let target = t.new.as_ref().map_or(String::from("unconfined"), |n| n.name.clone());
            (t.new, secure, target)
        }
        // In complain mode, a missing transition makes a learning profile, as
        // `aa_new_learning_profile` of Linux.
        None if p.mode == Mode::Complain => {
            let base = String::from_utf8_lossy(name);
            let learn = policy::with_ns(p.ns.as_deref(), |ns| ns.learning(p, false, &base));
            a.error = Some(Errno::EACCES);
            let target = learn.name.clone();
            (Some(learn), false, target)
        }
        None => {
            a.error = Some(Errno::EACCES);
            a.target = lookup.as_deref();
            audit_file(Some(p), &perms, &a)?;
            return Err(Errno::EACCES);
        }
    };
    a.target = Some(&target);
    audit_file(Some(p), &perms, &a)?;
    Ok((new, secure))
}

/// The check of an exec of the file `name` with the owner `ouid` from the profile `p` with a
/// label for the exec, `profile_onexec` of Linux. Gives if the program gets `AT_SECURE`.
///
/// # Errors
///
/// Gives `EACCES` if the rules have no match for the label, as on Linux in each mode.
fn profile_onexec(
    p: &Profile,
    onexec: &[Arc<Profile>],
    stack: bool,
    name: &[u8],
    ouid: u32,
) -> Result<bool> {
    let fsuid = rk_vfs::cred::current().fsuid;
    let empty = Pdb::default();
    let file = p.rules.as_ref().map_or(&empty, |r| &r.file);
    let state = file.dfa.as_ref().map_or(NOMATCH, |d| d.match_bytes(file.start[class::FILE], name));
    let mut perms = lookup_fperms(file, state, fsuid == ouid);
    let mut info = Some("change_profile onexec");
    let mut error = Some(Errno::EACCES);
    let mut secure = false;
    // A rule `change_profile -> &NAME` matches a stack with `&` before the name.
    let pre = if stack { "&" } else { "" };
    let target = format!("{pre}{}", label_text_plain(onexec, Some(p)));
    if perms.allow & perm::ONEXEC == 0 {
        info = Some("no change_onexec valid for executable");
    } else {
        // The rule `exec\0change_profile` pairs the exec with the change of the profile.
        let next = file.dfa.as_ref().map_or(NOMATCH, |d| d.next(state, 0));
        let mut found = change_perms(file, next, &target, perm::ONEXEC, fsuid);
        if !matches!(found, Some((_, true))) && onexec.len() > 1 {
            // As `label_components_match` of Linux, each profile of the label can match a
            // rule of its own. The permissions are the permissions that all the rules give.
            let mut all = Perms { allow: !0, quiet: !0, hide: !0, ..Perms::default() };
            for c in onexec {
                let one = format!("{pre}{}", label_text_plain(core::slice::from_ref(c), Some(p)));
                let (cp, _) =
                    change_perms(file, next, &one, perm::ONEXEC, fsuid).ok_or(Errno::EACCES)?;
                accum(&mut all, &cp);
            }
            found = Some((all, all.allow & perm::ONEXEC == perm::ONEXEC));
        }
        let (tp, ok) = found.ok_or(Errno::EACCES)?;
        perms = tp;
        if ok {
            error = None;
            secure = perms.xindex & x::UNSAFE == 0;
        } else {
            perms.allow &= !perm::ONEXEC;
        }
    }
    let a = FileAudit {
        op: "exec",
        request: perm::ONEXEC,
        name,
        target: Some(&target),
        ouid,
        info,
        error,
    };
    audit_file(Some(p), &perms, &a)?;
    Ok(secure)
}

/// The name of the label `l` without the mode, as the rules of the profile `view` match it,
/// `match_component` of Linux: `:NS:NAME` for a profile of another namespace, and `//&` between
/// the profiles of a stack.
pub fn label_text_plain(l: &[Arc<Profile>], view: Option<&Profile>) -> String {
    if l.is_empty() {
        return String::from("unconfined");
    }
    let view_ns = view.and_then(|v| v.ns.as_deref());
    let names: Vec<_> = l
        .iter()
        .map(|p| match p.ns.as_deref() {
            Some(ns) if view_ns != Some(ns) => format!(":{ns}:{}", p.name),
            _ => p.name.clone(),
        })
        .collect();
    names.join(STACK)
}

/// The permissions of the file rules of a profile for a change to the label `target` from the
/// state `start`, `change_profile_perms` and `label_match` of Linux for a label of one profile.
/// Gives the permissions and if they have all of `request`, or `None` if the rules have no
/// match for the name. On Linux, no match gives `EACCES` with no record, also in complain mode.
pub fn change_perms(
    file: &Pdb,
    start: State,
    target: &str,
    request: u32,
    fsuid: u32,
) -> Option<(Perms, bool)> {
    let d = file.dfa.as_ref()?;
    if start == NOMATCH {
        return None;
    }
    let state = d.match_bytes(start, target.as_bytes());
    if state == NOMATCH {
        return None;
    }
    // The match of a label has the owner condition of the user 0, as `struct path_cond` with
    // no values of Linux.
    let perms = lookup_fperms(file, state, fsuid == 0);
    Some((perms, perms.allow & request == request))
}

/// The change of the label at an exec, `apparmor_bprm_creds_for_exec` of Linux. A label for
/// the exec from `change_onexec` comes before the rules of the profile.
///
/// # Errors
///
/// Gives `EACCES` if the label for the exec has no match in the rules, as [`profile_onexec`].
pub fn bprm_creds_for_exec(bprm: &mut Bprm<'_>) -> Result<()> {
    let old = label_of(bprm.cred);
    let name = bprm.file.absolute_path();
    let ouid = bprm.file.inode().metadata().uid;
    let onexec = ref_label(load(bprm.cred, slot::ONEXEC));
    // As `ctx->token` of Linux, the token tells if the label for the exec goes on a stack.
    let stack = load(bprm.cred, slot::TOKEN) == 1;
    // The program starts with no hat and no label for the next exec, as
    // `apparmor_bprm_committed_creds` of Linux.
    clear_trans(bprm.cred);
    if let Some(target) = onexec {
        let mut secure = false;
        for p in old.iter().filter(|p| p.mode != Mode::Unconfined) {
            secure |= profile_onexec(p, &target, stack, &name, ouid)?;
        }
        if secure {
            bprm.secureexec = true;
        }
        // A stack goes on the label of the task, as `aa_label_merge` in `handle_onexec`.
        let target = if stack { merge(&old, &target) } else { target };
        set_label(bprm.cred, &target);
        return Ok(());
    }
    // Each profile of a stack changes, as `fn_label_build` in `handle_onexec` and
    // `apparmor_bprm_creds_for_exec` of Linux.
    let mut new = Vec::new();
    let mut secure = false;
    for p in &old {
        let (next, s) = if p.mode == Mode::Unconfined {
            (Some(attach_unconfined(Some(p), &name, ouid).unwrap_or_else(|| p.clone())), false)
        } else {
            profile_transition(p, &name, ouid)?
        };
        secure |= s;
        new = merge(&new, next.as_slice());
    }
    if old.is_empty() {
        new.extend(attach_unconfined(None, &name, ouid));
    }
    if secure {
        bprm.secureexec = true;
    }
    set_label(bprm.cred, &new);
    Ok(())
}

/// The profile that attaches to the program `name` for an unconfined task with the profile
/// `old`, if there is one.
fn attach_unconfined(old: Option<&Profile>, name: &[u8], ouid: u32) -> Option<Arc<Profile>> {
    let list = policy::with_ns(old.and_then(|p| p.ns.as_deref()), |ns| ns.children(None));
    let (found, info) = find_attach(&list, name);
    if let Some(info) = info {
        let perms = Perms { allow: perm::EXEC, audit: perm::EXEC, ..Perms::default() };
        let a = FileAudit {
            op: "exec",
            request: perm::EXEC,
            name,
            target: None,
            ouid,
            info: Some(info),
            error: None,
        };
        // The record has no error, so it gives no error.
        let _ = audit_file(old, &perms, &a);
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Change, Ns, replace};

    /// The policy of `rk_test`: it attaches to /usr/bin/rk-test, and allows a read of
    /// /etc/hostname and a read and a write in /tmp.
    const RK_TEST: &[u8] = include_bytes!("../tests/rk_test.bin");

    #[test]
    fn a_profile_attaches_to_its_program() {
        let ns = Ns::new("t");
        assert!(replace(&ns, Change::Load, RK_TEST).is_ok());
        let top = ns.children(None);
        assert_eq!(top.len(), 1);
        let (p, info) = find_attach(&top, b"/usr/bin/rk-test");
        assert_eq!(p.map(|p| p.name.clone()).as_deref(), Some("rk_test"));
        assert_eq!(info, None);
        assert!(find_attach(&top, b"/usr/bin/rk-tes").0.is_none());
        assert!(find_attach(&top, b"/usr/bin/rk-test2").0.is_none());
        let hats = ns.children(Some("rk_test"));
        assert_eq!(hats.len(), 1);
        assert_eq!(hats[0].base_name(), "hat1");
        // Two profiles with the same attach are a conflict.
        let two = [top[0].clone(), top[0].clone()];
        let (p, info) = find_attach(&two, b"/usr/bin/rk-test");
        assert!(p.is_none());
        assert_eq!(info, Some(CONFLICT));
    }

    #[test]
    fn the_file_rules_give_the_permissions_of_a_path() {
        let ns = Ns::new("t");
        assert!(replace(&ns, Change::Load, RK_TEST).is_ok());
        let p = ns.lookup("rk_test").unwrap();
        let file = &p.rules.as_ref().unwrap().file;
        assert_eq!(str_perms(file, b"/etc/hostname", true).allow & perm::READ, perm::READ);
        assert_eq!(str_perms(file, b"/etc/hostname", true).allow & perm::WRITE, 0);
        let tmp = str_perms(file, b"/tmp/rk-sub", true);
        assert_eq!(tmp.allow & (perm::READ | perm::WRITE | perm::EXEC), perm::READ | perm::WRITE);
        // As on Linux, the map of the old format allows `getattr` in each state.
        assert_eq!(str_perms(file, b"/etc/passwd", true).allow, perm::GETATTR);
        let learn = ns.learning(&p, false, "/tmp/rk-sub");
        assert_eq!(learn.name, "rk_test//null-/tmp/rk-sub");
        let l = [learn.clone()];
        assert_eq!(label_text(&l, None), "rk_test//null-/tmp/rk-sub (complain)");
        let two = merge(&l, &[p.clone(), learn.clone()]);
        assert_eq!(label_text(&two, None), "rk_test//null-/tmp/rk-sub//&rk_test (complain)");
        assert_eq!(label_text_plain(&two, None), "rk_test//null-/tmp/rk-sub//&rk_test");
        assert!(Arc::ptr_eq(&learn, &ns.learning(&p, false, "/tmp/rk-sub")));
        assert_eq!(label_text(&[], None), "unconfined");
    }

    #[test]
    fn the_parts_of_a_label_give_the_permissions_that_all_of_them_give() {
        let mut all = Perms { allow: !0, quiet: !0, hide: !0, ..Perms::default() };
        let a = Perms { allow: perm::ONEXEC | perm::READ, audit: perm::READ, ..Perms::default() };
        let b = Perms { allow: perm::ONEXEC | perm::WRITE, deny: perm::READ, ..Perms::default() };
        accum(&mut all, &a);
        assert_eq!(all.allow, perm::ONEXEC | perm::READ);
        accum(&mut all, &b);
        assert_eq!((all.allow, all.deny, all.audit), (perm::ONEXEC, perm::READ, perm::READ));
        // As on Linux, the permissions of the parts have no exec transition, thus no
        // `AT_SECURE` exception.
        assert_eq!(all.xindex & x::UNSAFE, 0);
    }

    #[test]
    fn the_masks_of_the_log_are_as_on_linux() {
        assert_eq!(mask_text(perm::EXEC), "x");
        assert_eq!(mask_text(perm::READ | perm::WRITE), "wr");
        assert_eq!(mask_text(perm::GETATTR), "r");
        assert_eq!(mask_text(perm::CHMOD | perm::APPEND), "wa");
        assert_eq!(mask_text(perm::LINK | perm::LOCK | perm::EXEC_MMAP), "kml");
    }
}

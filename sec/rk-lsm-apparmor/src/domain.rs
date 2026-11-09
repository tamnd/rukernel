//! The label of a task and its change at `execve`, as domain.c and the label parts of lsm.c,
//! file.c and procattr.c of Linux.
//!
//! The credentials blob holds the label of the task: 0 for `unconfined`, or the number of the
//! name of a profile. The name gives the newest version of the profile, as the proxy of a label
//! of Linux does. A profile that was removed gives `unconfined`.
//!
//! This kernel does not deny an operation. Each profile acts as a profile in complain mode: the
//! log tells what the policy does not allow, and the operation goes on.

use crate::audit::{self, Kind};
use crate::dfa::{NOMATCH, State};
use crate::policy::{Mode, Profile, ROOT};
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

/// The size of the part of AppArmor in the credentials blob: the number of the name of the
/// profile.
pub const CRED_BLOB: usize = 8;

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

/// The number of the label of `cred`. 0 is `unconfined`.
pub fn label_id(cred: &Cred) -> u64 {
    cred_offset().map_or(0, |off| cred.security.load(off))
}

/// The newest profile of the label number `id`, `aa_get_newest_label` of Linux. `None` is
/// `unconfined`.
pub fn profile_by_id(id: u64) -> Option<Arc<Profile>> {
    let i = usize::try_from(id).ok()?.checked_sub(1)?;
    let name = NAMES.lock().names.get(i)?.clone();
    ROOT.lookup(&name)
}

/// The profile of `cred`, `aa_get_newest_cred_label` of Linux. `None` is `unconfined`.
pub fn profile_of(cred: &Cred) -> Option<Arc<Profile>> {
    profile_by_id(label_id(cred))
}

/// Sets the profile of `cred`, `set_cred_label` of Linux. `None` is `unconfined`.
pub fn set_profile(cred: &Cred, p: Option<&Profile>) {
    if let Some(off) = cred_offset() {
        cred.security.store(off, p.map_or(0, |p| intern(&p.name)));
    }
}

/// The text of a label with its mode, as `aa_getprocattr` of Linux gives it, without the new
/// line. `unconfined` has no mode.
pub fn label_text(p: Option<&Profile>) -> String {
    match p {
        None => String::from("unconfined"),
        Some(p) => format!("{} ({})", p.name, p.mode.name()),
    }
}

/// A read of `/proc/PID/attr/NAME`, `apparmor_getprocattr` of Linux. `current` gives the
/// label of the task. No task has a label for `prev` or `exec` yet, so they give `ENOENT`.
///
/// # Errors
///
/// Gives `ENOENT` for `prev` and `exec`, and `EINVAL` for another name.
pub fn getprocattr(task: &Task<'_>, name: &str) -> Result<Vec<u8>> {
    match name {
        "current" => {
            let mut s = label_text(profile_of(task.cred).as_deref());
            s.push('\n');
            Ok(s.into_bytes())
        }
        "prev" | "exec" => Err(Errno::ENOENT),
        _ => Err(Errno::EINVAL),
    }
}

/// The permissions of the accept state `state` for the owner of the file or for the others,
/// `aa_lookup_fperms` of Linux.
fn lookup_fperms(pdb: &Pdb, state: State, owner: bool) -> Perms {
    let Some(d) = pdb.dfa.as_ref() else { return Perms::default() };
    let index = d.accept().get(state as usize).copied().unwrap_or(0) as usize;
    pdb.perms.get(index + usize::from(!owner)).copied().unwrap_or_default()
}

/// The permissions of the file rules for the path `name`, `aa_str_perms` of Linux. `owner`
/// tells if the file system user ID of the task is the owner of the file.
pub fn str_perms(pdb: &Pdb, name: &[u8], owner: bool) -> Perms {
    let Some(d) = pdb.dfa.as_ref() else { return Perms::default() };
    lookup_fperms(pdb, d.match_bytes(pdb.start[class::FILE], name), owner)
}

/// The characters of the file permissions in the log, `aa_file_perm_chrs` of Linux.
const FILE_PERM_CHRS: &[u8] = b"xwracd         km l     ";

/// The permissions that the log of a file operation shows, `AA_AUDIT_FILE_MASK` of Linux.
const AUDIT_FILE_MASK: u32 = perm::READ
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
    /// The path of the file.
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
/// `aa_audit_file` and `aa_audit` of Linux. Each profile acts in complain mode, so a denial
/// gives a record of the kind `ALLOWED`.
pub fn audit_file(p: Option<&Profile>, perms: &Perms, a: &FileAudit<'_>) {
    let audit_all = p.and_then(|p| p.rules.as_ref()).is_some_and(|r| r.audit);
    let mut request = a.request;
    let kind = if a.error.is_none() {
        // Only the permissions that the policy audits, or all with the audit mode `all`.
        request &= if audit_all { 0xffff } else { perms.audit };
        Kind::Audit
    } else {
        // Only the permissions that the policy does not allow. A rule with `quiet` hides
        // them, but not with the audit mode `all`.
        request &= !perms.allow;
        if !audit_all {
            request &= !perms.quiet;
        }
        Kind::Allowed
    };
    if request == 0 {
        return;
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
    let d = audit::Data {
        op: Some(a.op),
        class: Some("file"),
        info: a.info,
        error: a.error.map_or(0, |e| -i32::from(e.get())),
        profile: Some(p.map_or("unconfined", |p| &p.name)),
        name: Some(&name),
    };
    audit::log(kind, &d, &tail);
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
        ROOT.lookup(&format!("{}//{lookup}", p.name))
    } else if lookup.starts_with(':') {
        // No namespace is there other than the root namespace.
        None
    } else {
        ROOT.lookup(lookup)
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
/// the attach of the program, without the stack.
fn x_to_label(p: &Arc<Profile>, name: &[u8], xindex: u32) -> Option<Transition> {
    let mut info = None;
    let mut new: Option<Option<Arc<Profile>>> = None;
    let mut by_name = xindex & x::TYPE_MASK == x::NAME;
    if xindex & x::TYPE_MASK == x::TABLE {
        let (found, n) = x_table_lookup(p, xindex);
        by_name = found.is_some() && n.as_deref().is_some_and(|n| n.starts_with('&'));
        if !by_name {
            new = found.map(Some);
        }
    }
    if by_name {
        let parent = if xindex & x::CHILD != 0 { Some(p.name.as_str()) } else { None };
        let (found, i) = find_attach(&ROOT.children(parent), name);
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
    new.map(|new| Transition { new, info })
}

/// The new label of an exec of the file `name` with the owner `ouid` from the profile `p`,
/// `profile_transition` of Linux for a profile in complain mode. Gives the new profile and if
/// the program gets `AT_SECURE`.
fn profile_transition(p: &Arc<Profile>, name: &[u8], ouid: u32) -> (Option<Arc<Profile>>, bool) {
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
    if perms.allow & perm::EXEC != 0 {
        match x_to_label(p, name, perms.xindex) {
            Some(t) => found = Some(t),
            None => {
                // In complain mode, a missing transition makes a learning profile.
                a.info = Some("profile transition not found");
                perms.allow &= !perm::EXEC;
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
        None => {
            // No exec permission: a learning profile, as `aa_new_learning_profile` of Linux.
            let learn = ROOT.learning(p, &String::from_utf8_lossy(name));
            a.error = Some(Errno::EACCES);
            let target = learn.name.clone();
            (Some(learn), false, target)
        }
    };
    a.target = Some(&target);
    audit_file(Some(p), &perms, &a);
    (new, secure)
}

/// The change of the label at an exec, `apparmor_bprm_creds_for_exec` of Linux.
pub fn bprm_creds_for_exec(bprm: &mut Bprm<'_>) {
    let old = profile_of(bprm.cred);
    let name = bprm.file.absolute_path();
    let ouid = bprm.file.inode().metadata().uid;
    let (new, secure) = match old.as_ref().filter(|p| p.mode != Mode::Unconfined) {
        Some(p) => profile_transition(p, &name, ouid),
        None => {
            // An unconfined task gets the profile that attaches to the program, if there is one.
            let (found, info) = find_attach(&ROOT.children(None), &name);
            if let Some(info) = info {
                let perms = Perms { allow: perm::EXEC, audit: perm::EXEC, ..Perms::default() };
                let a = FileAudit {
                    op: "exec",
                    request: perm::EXEC,
                    name: &name,
                    target: None,
                    ouid,
                    info: Some(info),
                    error: None,
                };
                audit_file(old.as_deref(), &perms, &a);
            }
            (found.or(old), false)
        }
    };
    if secure {
        bprm.secureexec = true;
    }
    set_profile(bprm.cred, new.as_deref());
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
        let learn = ns.learning(&p, "/tmp/rk-sub");
        assert_eq!(learn.name, "rk_test//null-/tmp/rk-sub");
        assert_eq!(label_text(Some(&learn)), "rk_test//null-/tmp/rk-sub (complain)");
        assert!(Arc::ptr_eq(&learn, &ns.learning(&p, "/tmp/rk-sub")));
        assert_eq!(label_text(None), "unconfined");
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

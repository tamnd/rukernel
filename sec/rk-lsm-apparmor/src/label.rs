//! The checks of the rules of the policy DB against another label, as label.c and lib.c of
//! Linux: the signal, ptrace and unix socket rules name the label of the peer.

use crate::audit::{self, Kind};
use crate::dfa::{NOMATCH, State};
use crate::domain::{self, STACK};
use crate::policy::{Mode, Profile};
use crate::unpack::{Pdb, Perms};
use alloc::string::String;
use alloc::sync::Arc;
use rk_abi::Errno;
use rk_vfs::inode::Result;

/// `ALL_PERMS_MASK`.
const ALL: u32 = u32::MAX;

/// The permissions of a label with no part that the rules see, `allperms` of Linux.
const ALL_PERMS: Perms = Perms {
    allow: ALL,
    deny: 0,
    subtree: 0,
    cond: 0,
    kill: 0,
    complain: 0,
    prompt: 0,
    audit: 0,
    quiet: ALL,
    hide: ALL,
    xindex: 0,
    tag: 0,
    label: 0,
};

/// The start state of the class `class` in the policy DB of `p`, `RULE_MEDIATES` of Linux.
/// Gives `None` if the rules of the profile do not mediate the class.
pub fn mediates(p: &Profile, class: usize) -> Option<(&Pdb, State)> {
    let pdb: &Pdb = &p.rules.as_ref()?.policy;
    pdb.dfa.as_ref()?;
    let start = *pdb.start.get(class)?;
    (start != NOMATCH).then_some((pdb, start))
}

/// The permissions of the state `state` of the policy DB, `aa_lookup_perms` of Linux.
pub fn lookup(pdb: &Pdb, state: State) -> Perms {
    let Some(d) = pdb.dfa.as_ref() else { return Perms::default() };
    let index = d.accept().get(state as usize).copied().unwrap_or(0) as usize;
    pdb.perms.get(index).copied().unwrap_or_default()
}

/// Adds the modes of the profile `p` to `perms`, `aa_apply_modes_to_perms` of Linux.
pub fn apply_modes(p: &Profile, perms: &mut Perms) {
    if p.rules.as_ref().is_some_and(|r| r.audit) {
        perms.audit = ALL;
        perms.quiet = 0;
    }
    match p.mode {
        Mode::Kill => perms.kill = ALL,
        Mode::Complain => perms.complain = ALL,
        Mode::User => perms.prompt = ALL,
        _ => {}
    }
}

/// The text of the part `tp` of a label for the rules of `p`, or `None` if the rules do not see
/// it, `aa_ns_visible` of Linux without the child namespaces.
fn component(p: &Profile, tp: &Profile) -> Option<String> {
    (p.ns == tp.ns).then(|| tp.name.clone())
}

/// The names of the parts of the label `peer` that the rules of `p` see. `unconfined` is the
/// profile `unconfined` of the root namespace.
fn components(p: &Profile, peer: &[Arc<Profile>]) -> alloc::vec::Vec<String> {
    if peer.is_empty() {
        return if p.ns.is_none() {
            alloc::vec![String::from("unconfined")]
        } else {
            alloc::vec![]
        };
    }
    peer.iter().filter_map(|tp| component(p, tp)).collect()
}

/// The permissions of the rules of `p` from the state `state` for the label `peer`,
/// `aa_label_match` of Linux: the match of the full label, then the match of each part.
pub fn label_match(
    p: &Profile,
    pdb: &Pdb,
    peer: &[Arc<Profile>],
    state: State,
    request: u32,
) -> Perms {
    let Some(d) = pdb.dfa.as_ref() else { return Perms::default() };
    let names = components(p, peer);
    if names.is_empty() {
        return ALL_PERMS;
    }
    // `label_compound_match`: a part that does not match gives no permissions.
    let mut s = d.match_bytes(state, names[0].as_bytes());
    for n in &names[1..] {
        if s == NOMATCH {
            break;
        }
        s = d.match_bytes(s, STACK.as_bytes());
        s = d.match_bytes(s, n.as_bytes());
    }
    if s == NOMATCH {
        return Perms::default();
    }
    let mut perms = lookup(pdb, s);
    apply_modes(p, &mut perms);
    if perms.allow & request == request {
        return perms;
    }
    // `label_components_match`: each part on its own.
    let mut perms = ALL_PERMS;
    for n in &names {
        let s = d.match_bytes(state, n.as_bytes());
        if s == NOMATCH {
            return Perms::default();
        }
        let mut tmp = lookup(pdb, s);
        apply_modes(p, &mut tmp);
        domain::accum(&mut perms, &tmp);
    }
    perms
}

/// The name of the label `peer` in a record, as `aa_label_xaudit` of Linux with no mode.
pub fn peer_text(peer: &[Arc<Profile>], view: &Profile) -> String {
    let mut s = String::new();
    audit::untrusted(&mut s, domain::label_text_plain(peer, Some(view)).as_bytes());
    s
}

/// The check of `request` with the permissions `perms` of the profile `p`, `aa_check_perms` of
/// Linux. A denial has a record with the operation `op` and the class `class`, and `tail` gives
/// the fields after `comm` for the request and the denied permissions.
///
/// # Errors
///
/// Gives `EACCES`, or `ENOENT` for permissions that the policy hides, except in complain mode.
pub fn check_perms(
    p: &Profile,
    perms: &Perms,
    request: u32,
    op: &str,
    class: &str,
    tail: impl FnOnce(u32, u32) -> String,
) -> Result<()> {
    check_perms_info(Some(p), perms, request, op, class, None, tail)
}

/// [`check_perms`] with the text `info` in the record. `None` for `p` is `unconfined`.
///
/// # Errors
///
/// Gives the errors of [`check_perms`].
pub fn check_perms_info(
    p: Option<&Profile>,
    perms: &Perms,
    request: u32,
    op: &str,
    class: &str,
    info: Option<&str>,
    tail: impl FnOnce(u32, u32) -> String,
) -> Result<()> {
    let mut request = request;
    let mut denied = request & (!perms.allow | perms.deny);
    let (kind, error) = if denied == 0 {
        // Only the permissions that the policy audits.
        request &= perms.audit;
        if request == 0 {
            return Ok(());
        }
        (Kind::Audit, None)
    } else {
        let kind = if denied & perms.kill != 0 {
            Kind::Killed
        } else if denied == denied & perms.complain {
            Kind::Allowed
        } else {
            Kind::Denied
        };
        let error = if denied == denied & perms.hide { Errno::ENOENT } else { Errno::EACCES };
        denied &= !perms.quiet;
        if denied == 0 {
            return Err(error);
        }
        (kind, Some(error))
    };
    let fq = p.map_or(alloc::borrow::Cow::Borrowed("unconfined"), Profile::fqname);
    let d = audit::Data {
        op: Some(op),
        class: Some(class),
        info,
        error: error.map_or(0, |e| -i32::from(e.get())),
        profile: Some(&fq),
        name: None,
    };
    audit::log(kind, &d, &tail(request, denied));
    // As `aa_check_perms` of Linux, the record of the kind `KILLED` does not kill the task.
    match error {
        Some(_) if kind == Kind::Allowed => Ok(()),
        Some(e) => Err(e),
        None => Ok(()),
    }
}

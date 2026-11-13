//! The mediation of `ptrace`, as the ptrace part of task.c of Linux.
//!
//! The rules of the tracer must allow it to trace or read the label of the tracee, and the
//! rules of the tracee must allow the tracer to trace or read it. A profile without ptrace
//! rules uses the old check: the tracer needs `CAP_SYS_PTRACE` for a task with another label. A
//! denial gives `EACCES` and a record of the class `ptrace`:
//!
//! ```text
//! apparmor="DENIED" operation="ptrace" class="ptrace" profile="P" pid=PID comm="COMM"
//!     requested_mask="trace" denied_mask="trace" peer="unconfined"
//! ```

use crate::audit;
use crate::capability;
use crate::domain::{self, Label};
use crate::label;
use crate::policy::{Mode, Profile};
use crate::unpack::{class, perm};
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use rk_vfs::cred::{Cred, cap};
use rk_vfs::inode::Result;

/// `PTRACE_MODE_READ` of the `ptrace_access_check` hook.
const PTRACE_MODE_READ: u32 = 0x01;
/// `PTRACE_PERM_SHIFT`: the request of the tracee is the request of the tracer shifted by it,
/// `AA_MAY_BE_READ` and `AA_MAY_BE_TRACED`.
const SHIFT: u32 = 2;
/// `AA_PTRACE_PERM_MASK`.
const MASK: u32 = perm::READ | perm::WRITE | perm::CREATE | perm::APPEND;

/// The name of a ptrace permission in a record, `audit_ptrace_mask` of Linux.
fn mask_text(mask: u32) -> &'static str {
    match mask {
        perm::READ => "read",
        perm::WRITE => "trace",
        perm::CREATE => "readby",
        perm::APPEND => "tracedby",
        _ => "",
    }
}

/// The fields of a record of `ptrace` after `comm`, `audit_ptrace_cb` of Linux.
fn tail(request: u32, denied: u32, peer: &[Arc<Profile>], p: &Profile) -> String {
    let mut s = String::new();
    if request & MASK != 0 {
        s.push_str(&format!(" requested_mask=\"{}\"", mask_text(request)));
        if denied & MASK != 0 {
            s.push_str(&format!(" denied_mask=\"{}\"", mask_text(denied)));
        }
    }
    s.push_str(" peer=");
    s.push_str(&label::peer_text(peer, p));
    s
}

/// The check of the ptrace rules of `p` for the label `peer`, `profile_ptrace_perm` and
/// `aa_profile_match_label` of Linux.
fn profile_ptrace_perm(p: &Profile, peer: &[Arc<Profile>], request: u32) -> Result<()> {
    let Some(pdb) = p.rules.as_ref().map(|r| &*r.policy) else { return Ok(()) };
    let Some(d) = pdb.dfa.as_ref() else { return Ok(()) };
    let state = d.next(pdb.start[class::LABEL], class::PTRACE as u8);
    let mut perms = label::label_match(p, pdb, peer, state, request);
    label::apply_modes(p, &mut perms);
    label::check_perms(p, &perms, request, "ptrace", "ptrace", |r, dn| tail(r, dn, peer, p))
}

/// The check of the tracee profile `p` for the tracer label `tracer`, `profile_tracee_perm`
/// of Linux.
fn profile_tracee_perm(p: &Profile, tracer: &[Arc<Profile>], request: u32) -> Result<()> {
    if p.mode == Mode::Unconfined
        || tracer.is_empty()
        || label::mediates(p, class::PTRACE).is_none()
    {
        return Ok(());
    }
    profile_ptrace_perm(p, tracer, request)
}

/// The check of the tracer profile `p` for the tracee label `tracee`, `profile_tracer_perm`
/// of Linux.
fn profile_tracer_perm(p: &Arc<Profile>, tracee: &[Arc<Profile>], request: u32) -> Result<()> {
    if p.mode == Mode::Unconfined {
        return Ok(());
    }
    if label::mediates(p, class::PTRACE).is_some() {
        return profile_ptrace_perm(p, tracee, request);
    }
    // The old check of a profile without ptrace rules: a task with the same label needs no
    // capability.
    if tracee.len() == 1 && Arc::ptr_eq(&tracee[0], p) {
        return Ok(());
    }
    let error = capability::profile_capable(p, cap::SYS_PTRACE, 0).err();
    let audit_all = p.rules.as_ref().is_some_and(|r| r.audit);
    let kind = match error {
        None if !audit_all => return Ok(()),
        None => audit::Kind::Audit,
        Some(_) => domain::mode_kind(Some(p)),
    };
    let fq = p.fqname();
    let d = audit::Data {
        op: Some("ptrace"),
        class: Some("ptrace"),
        info: None,
        error: error.map_or(0, |e| -i32::from(e.get())),
        profile: Some(&fq),
        name: None,
    };
    audit::log(kind, &d, &tail(0, 0, tracee, p));
    domain::outcome(kind, error)
}

/// `aa_may_ptrace` of Linux: the task with the label `tracer` traces or reads the task with
/// the label `tracee`. `request` is `AA_PTRACE_TRACE` or `AA_PTRACE_READ`.
///
/// # Errors
///
/// Gives `EACCES` if the rules of the tracer or of the tracee do not allow it, or `EPERM` for a
/// profile without ptrace rules and without `CAP_SYS_PTRACE`, except in complain mode.
pub(crate) fn may_ptrace(tracer: &Label, tracee: &Label, request: u32) -> Result<()> {
    let mut first = Ok(());
    for p in tracer {
        if let Err(e) = profile_tracer_perm(p, tracee, request) {
            first = Err(e);
        }
    }
    let mut second = Ok(());
    for p in tracee {
        if let Err(e) = profile_tracee_perm(p, tracer, request << SHIFT) {
            second = Err(e);
        }
    }
    // As `xcheck` of Linux: the error of the tracee comes first.
    match second {
        Err(e) => Err(e),
        Ok(()) => first,
    }
}

/// `apparmor_ptrace_access_check` of Linux: the task with `cred` traces or reads the task with
/// `tcred`. `mode` has the `PTRACE_MODE_*` bits.
///
/// # Errors
///
/// Gives the error of [`may_ptrace`].
pub fn access_check(cred: &Cred, tcred: &Cred, mode: u32) -> Result<()> {
    if domain::label_id(cred) == 0 && domain::label_id(tcred) == 0 {
        return Ok(());
    }
    let request = if mode & PTRACE_MODE_READ != 0 { perm::READ } else { perm::WRITE };
    may_ptrace(&domain::label_of(cred), &domain::label_of(tcred), request)
}

/// `apparmor_ptrace_traceme` of Linux: the task with `parent` becomes the tracer of the current
/// task.
///
/// # Errors
///
/// Gives the error of [`may_ptrace`].
pub fn traceme(parent: &Cred) -> Result<()> {
    let cred = rk_vfs::cred::current();
    if domain::label_id(parent) == 0 && domain::label_id(&cred) == 0 {
        return Ok(());
    }
    may_ptrace(&domain::label_of(parent), &domain::label_of(&cred), perm::WRITE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_of_the_tracee_has_its_own_names() {
        assert_eq!(mask_text(perm::WRITE), "trace");
        assert_eq!(mask_text(perm::READ), "read");
        assert_eq!(mask_text(perm::WRITE << SHIFT), "tracedby");
        assert_eq!(mask_text(perm::READ << SHIFT), "readby");
    }
}

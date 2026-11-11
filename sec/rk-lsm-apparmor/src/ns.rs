//! The mediation of the user namespaces, as `apparmor_userns_create` and `aa_profile_ns_perm`
//! of the Ubuntu kernel.
//!
//! A profile with `userns` rules can make a user namespace only if a rule allows it. A rule can
//! also give the label of the task in the new namespace. Three files of `/proc/sys/kernel`
//! change the checks:
//!
//! - `apparmor_restrict_unprivileged_userns`: at 1, an `unconfined` task without
//!   `CAP_SYS_ADMIN` goes to the profile `unprivileged_userns` in the new namespace. If that
//!   profile is not there, the task cannot make the namespace.
//! - `apparmor_restrict_unprivileged_userns_force`: at 1, a profile without `userns` rules
//!   cannot make a user namespace.
//! - `apparmor_restrict_unprivileged_userns_complain`: at 1, a denial only gives a record.
//!
//! The value of each file at boot is 0. A denial gives `EACCES` and a record of the class
//! `namespace`:
//!
//! ```text
//! apparmor="DENIED" operation="userns_create" class="namespace" profile="P" pid=PID
//!     comm="COMM" requested="userns_create" denied="userns_create"
//! ```

use crate::audit;
use crate::capability::CAP_OPT_NOAUDIT;
use crate::domain::{self, Label};
use crate::label;
use crate::policy::{self, Profile};
use crate::unpack::{Perms, class, x};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};
use rk_abi::Errno;
use rk_vfs::cred::{self, Cred, cap};
use rk_vfs::inode::Result;
use rk_vfs::security::Sysctl;

/// `AA_USERNS_CREATE`.
const USERNS_CREATE: u32 = 8;
/// The profile of an unprivileged task that is `unconfined`, in its new user namespace.
const UNPRIVILEGED: &str = "unprivileged_userns";

/// `aa_unprivileged_userns_restricted`.
static RESTRICTED: AtomicI32 = AtomicI32::new(0);
/// `aa_unprivileged_userns_restricted_force`.
static FORCE: AtomicI32 = AtomicI32::new(0);
/// `aa_unprivileged_userns_restricted_complain`.
static COMPLAIN: AtomicI32 = AtomicI32::new(0);

/// Sets `value` to `v` for a process that can manage the policy, as `apparmor_dointvec` of
/// Linux.
fn set(value: &AtomicI32, v: i32) -> Result<()> {
    if !policy::admin_capable(&cred::current()) {
        return Err(Errno::EPERM);
    }
    value.store(v, Ordering::Relaxed);
    Ok(())
}

/// The files of `/proc/sys/kernel`, as the part of `apparmor_sysctl_table` of Ubuntu for the
/// user namespaces.
pub static SYSCTLS: [Sysctl; 3] = [
    Sysctl {
        name: "kernel/apparmor_restrict_unprivileged_userns",
        mode: 0o644,
        get: || RESTRICTED.load(Ordering::Relaxed),
        set: |v| set(&RESTRICTED, v),
    },
    Sysctl {
        name: "kernel/apparmor_restrict_unprivileged_userns_force",
        mode: 0o600,
        get: || FORCE.load(Ordering::Relaxed),
        set: |v| set(&FORCE, v),
    },
    Sysctl {
        name: "kernel/apparmor_restrict_unprivileged_userns_complain",
        mode: 0o600,
        get: || COMPLAIN.load(Ordering::Relaxed),
        set: |v| set(&COMPLAIN, v),
    },
];

/// The fields of a record of `userns_create` after `comm`, `audit_ns_cb` of Ubuntu. `target`
/// is the text of the label in the new namespace.
fn tail(request: u32, denied: u32, target: Option<&str>) -> String {
    let mut s = String::new();
    if request & USERNS_CREATE != 0 {
        s.push_str(" requested=\"userns_create\"");
    }
    if denied & USERNS_CREATE != 0 {
        s.push_str(" denied=\"userns_create\"");
    }
    if let Some(t) = target {
        s.push_str(" target=");
        s.push_str(t);
    }
    s
}

/// The text of a name in a record, as `audit_log_untrustedstring` of Linux.
fn quoted(name: &str) -> String {
    let mut s = String::new();
    audit::untrusted(&mut s, name.as_bytes());
    s
}

/// The label of a `userns` rule with the transition `xindex` of `p`, `ns_x_to_label` of Ubuntu.
/// Gives `None` for no transition, or the label and a text about it. An error has a text and
/// the name of the transition.
fn x_to_label(
    p: &Arc<Profile>,
    xindex: u32,
) -> core::result::Result<Option<(Label, Option<&'static str>)>, (&'static str, Option<String>)> {
    let (mut new, mut stack) = (None, None);
    match xindex & x::TYPE_MASK {
        0 => return Ok(None),
        x::TABLE => {
            let (found, name) = domain::x_table_lookup(p, xindex);
            let Some(found) = found else {
                return Err(("failed to find transition profile", name));
            };
            if name.as_deref().is_some_and(|n| n.starts_with('&')) {
                stack = Some(found);
            } else {
                new = Some(alloc::vec![found]);
            }
        }
        _ => return Err(("invalid profile transition type", None)),
    }
    let mut info = None;
    let base = new.unwrap_or_else(|| {
        if xindex & x::UNCONFINED != 0 {
            info = Some("ux fallback");
            Vec::new()
        } else {
            if xindex & x::INHERIT != 0 {
                info = Some("ix fallback");
            }
            alloc::vec![p.clone()]
        }
    });
    let label = match stack {
        Some(s) => domain::merge(&base, &[s]),
        None => base,
    };
    Ok(Some((label, info)))
}

/// The check of `userns_create` for the profile `p` of the label of `cred`, `None` for
/// `unconfined`, `aa_profile_ns_perm` of Ubuntu. Gives the label of the part `p` in the new
/// namespace.
fn profile_ns_perm(p: Option<&Arc<Profile>>, cred: &Cred) -> Result<Label> {
    let request = USERNS_CREATE;
    let keep = || p.map_or_else(Vec::new, |p| alloc::vec![p.clone()]);
    let state = p.and_then(|p| label::mediates(p, class::NS));
    let mut perms = Perms::default();
    let mut info = None;
    let mut target = None;
    let mut new = keep();
    match (p, state) {
        (None, _) => {
            let admin = cred.cap_effective & cap::bit(cap::SYS_ADMIN) != 0
                && rk_vfs::security::capable_lsm(cred, cap::SYS_ADMIN, CAP_OPT_NOAUDIT);
            if RESTRICTED.load(Ordering::Relaxed) == 0 || admin {
                return Ok(new);
            }
            match policy::lookup_fq(UNPRIVILEGED) {
                None => {
                    info = Some(
                        "Userns create restricted - failed to find unprivileged_userns profile",
                    );
                    target = Some(quoted(UNPRIVILEGED));
                    perms.deny |= request;
                }
                Some(u) => {
                    info = Some("Userns create - transitioning profile");
                    target = Some(quoted(&u.fqname()));
                    perms.audit = request;
                    perms.allow = request;
                    new = alloc::vec![u];
                }
            }
        }
        (Some(p), None) if FORCE.load(Ordering::Relaxed) == 0 => return Ok(alloc::vec![p.clone()]),
        (Some(p), state) => {
            if let Some((pdb, s)) = state {
                perms = label::lookup(pdb, s);
            }
            match x_to_label(p, perms.xindex) {
                Err((i, name)) => {
                    info = Some(i);
                    target = name.as_deref().map(quoted);
                    perms.deny |= request;
                }
                Ok(None) => {}
                Ok(Some((l, i))) => {
                    info = i;
                    target = Some(label::peer_text(&l, p));
                    new = l;
                }
            }
        }
    }
    if COMPLAIN.load(Ordering::Relaxed) != 0 {
        perms.complain = u32::MAX;
    }
    if let Some(p) = p {
        label::apply_modes(p, &mut perms);
    }
    let t = target.as_deref();
    let tail = |r, d| tail(r, d, t);
    label::check_perms_info(
        p.map(|p| &**p),
        &perms,
        request,
        "userns_create",
        "namespace",
        info,
        tail,
    )?;
    Ok(new)
}

/// The `userns_create` hook, `apparmor_userns_create` of Ubuntu: the task with the
/// credentials `cred` makes a user namespace, and `new` are its credentials in it. The label
/// of `new` changes if a rule gives a transition.
///
/// # Errors
///
/// Gives `EACCES` if a profile of the label does not allow it, except in complain mode.
pub fn userns_create(cred: &Cred, new: &Cred) -> Result<()> {
    let label = domain::label_of(cred);
    let mediates = label.iter().any(|p| label::mediates(p, class::NS).is_some());
    if RESTRICTED.load(Ordering::Relaxed) == 0 && !mediates {
        return Ok(());
    }
    let out = if label.is_empty() {
        profile_ns_perm(None, cred)?
    } else {
        let mut out = Vec::new();
        for p in &label {
            out = domain::merge(&out, &profile_ns_perm(Some(p), cred)?);
        }
        out
    };
    let names = |l: &[Arc<Profile>]| l.iter().map(|p| p.fqname().into_owned()).collect::<Vec<_>>();
    if names(&out) != names(&label) {
        domain::set_label(new, &out);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_record_names_the_request_and_the_target() {
        assert_eq!(tail(USERNS_CREATE, 0, None), " requested=\"userns_create\"");
        assert_eq!(
            tail(USERNS_CREATE, USERNS_CREATE, Some("\"unprivileged_userns\"")),
            " requested=\"userns_create\" denied=\"userns_create\" target=\"unprivileged_userns\""
        );
        assert_eq!(quoted(UNPRIVILEGED), "\"unprivileged_userns\"");
    }

    #[test]
    fn the_files_have_the_modes_of_ubuntu() {
        let modes: Vec<_> = SYSCTLS.iter().map(|s| (s.name, s.mode)).collect();
        assert_eq!(modes[0], ("kernel/apparmor_restrict_unprivileged_userns", 0o644));
        assert_eq!(modes[1].1, 0o600);
        assert_eq!(modes[2].1, 0o600);
        assert_eq!((SYSCTLS[0].get)(), 0);
    }
}

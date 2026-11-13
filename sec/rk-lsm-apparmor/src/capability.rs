//! The mediation of the capabilities, as capability.c of Linux.
//!
//! A confined task has a capability only if each profile of its label allows it. The check
//! comes after the check of the capability module, so a task without the capability in its
//! effective set gets no record. A denial gives `EPERM` and a record of the class `cap`:
//!
//! ```text
//! apparmor="DENIED" operation="capable" class="cap" profile="P" pid=PID comm="COMM"
//!     capability=13  capname="net_raw"
//! ```

use crate::audit::{self, Kind};
use crate::domain;
use crate::policy::{Mode, Profile};
use alloc::format;
use alloc::sync::Arc;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::cred::Cred;
use rk_vfs::inode::Result;

/// `CAP_OPT_NOAUDIT`: the caller asks for no record.
pub const CAP_OPT_NOAUDIT: u32 = 1 << 1;

/// The last profile with a record of a denial and its capabilities, as the `audit_cache` of
/// Linux. A second denial of the same capability for the same profile gives no record. Linux
/// has one cache for each CPU. This kernel has one.
static CACHE: SpinLock<(usize, u64)> = SpinLock::new((0, 0));

/// The name of the capability `cap` in the record, as `capability_names` of Linux.
fn cap_name(cap: u32) -> &'static str {
    crate::features::CAPS_MASK.split(' ').nth(cap as usize).unwrap_or("?")
}

/// The bit of the capability `cap` in a set of the policy.
fn bit(cap: u32) -> u64 {
    1u64.checked_shl(cap).unwrap_or(0)
}

/// Logs the check of the capability `cap` for the profile `p` with the result `error`, as
/// `audit_caps` of Linux.
///
/// # Errors
///
/// Gives `error`, except for a denial that complain mode allows.
fn audit_caps(
    p: &Arc<Profile>,
    cap: u32,
    info: Option<&'static str>,
    error: Option<Errno>,
) -> Result<()> {
    let rules = p.rules.as_deref();
    let audit_all = rules.is_some_and(|r| r.audit);
    let caps = rules.map(|r| r.caps).unwrap_or_default();
    let kind = match error {
        // An allowed capability has a record only if the policy audits it.
        None if !audit_all && caps.audit & bit(cap) == 0 => return Ok(()),
        None => Kind::Audit,
        Some(_) if p.mode == Mode::Kill => Kind::Killed,
        // A rule with `quiet` hides the denial, also in complain mode, as on Linux.
        Some(e) if caps.quiet & bit(cap) != 0 && !audit_all => return Err(e),
        Some(_) => domain::mode_kind(Some(p)),
    };
    // The same denial again gives no record.
    {
        let mut cache = CACHE.lock();
        let key = Arc::as_ptr(p) as usize;
        if cache.0 == key && cache.1 & bit(cap) != 0 {
            // As on Linux, a repeated denial does not kill the task again.
            let kind = if p.mode == Mode::Complain { Kind::Allowed } else { Kind::Denied };
            return domain::outcome(kind, error);
        }
        if cache.0 != key {
            *cache = (key, 0);
        }
        cache.1 |= bit(cap);
    }
    let fq = p.fqname();
    let d = audit::Data {
        op: Some("capable"),
        class: Some("cap"),
        info,
        error: error.map_or(0, |e| -i32::from(e.get())),
        profile: Some(&fq),
        name: None,
    };
    let mut tail = format!(" capability={cap}  capname=");
    audit::untrusted(&mut tail, cap_name(cap).as_bytes());
    audit::log(kind, &d, &tail);
    domain::outcome(kind, error)
}

/// The check of the capability `cap` for the profile `p`, `profile_capable` of Linux.
///
/// # Errors
///
/// Gives `EPERM` if the profile does not allow the capability, except in complain mode.
pub(crate) fn profile_capable(p: &Arc<Profile>, cap: u32, opts: u32) -> Result<()> {
    let caps = p.rules.as_ref().map(|r| r.caps).unwrap_or_default();
    let error = (caps.allow & bit(cap) == 0).then_some(Errno::EPERM);
    let mut info = None;
    if opts & CAP_OPT_NOAUDIT != 0 {
        if p.mode != Mode::Complain {
            return error.map_or(Ok(()), Err);
        }
        // Complain mode logs the request, but tells that it is optional.
        info = Some("optional: no audit");
    }
    audit_caps(p, cap, info, error)
}

/// `apparmor_capable` and `aa_capable` of Linux: the task with `cred` uses the capability
/// `cap`. Each profile of the label checks it.
///
/// # Errors
///
/// Gives the error of the last profile that denies the capability.
pub fn capable(cred: &Cred, cap: u32, opts: u32) -> Result<()> {
    if domain::label_id(cred) == 0 {
        return Ok(());
    }
    let mut result = Ok(());
    for p in domain::label_of(cred).iter().filter(|p| p.mode != Mode::Unconfined) {
        if let Err(e) = profile_capable(p, cap, opts) {
            result = Err(e);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_capability_has_the_name_of_linux() {
        assert_eq!(cap_name(0), "chown");
        assert_eq!(cap_name(13), "net_raw");
        assert_eq!(cap_name(21), "sys_admin");
        assert_eq!(cap_name(40), "checkpoint_restore");
        assert_eq!(bit(64), 0);
    }
}

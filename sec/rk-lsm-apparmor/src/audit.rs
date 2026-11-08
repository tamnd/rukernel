//! The audit records of AppArmor, as security/apparmor/audit.c of Linux and
//! `common_lsm_audit` of security/lsm_audit.c.
//!
//! Each record has the type `AUDIT_AVC` (1400). It goes to auditd, or to the kernel log if no
//! auditd is there:
//!
//! ```text
//! audit: type=1400 audit(SEC.MSEC:SERIAL): apparmor="STATUS" operation="profile_load"
//!     profile="unconfined" name="NAME" pid=PID comm="COMM"
//! ```

use alloc::format;
use alloc::string::String;
use core::fmt::Write;

/// The kind of a record, `enum audit_type` and `aa_audit_type` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An operation that the policy allows and that it logs.
    Audit,
    /// An operation that the profile in complain mode allows, but that the policy does not.
    Allowed,
    /// An operation that the policy denies.
    Denied,
    /// A change of the policy.
    Status,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Audit => "AUDIT",
            Self::Allowed => "ALLOWED",
            Self::Denied => "DENIED",
            Self::Status => "STATUS",
        }
    }
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

/// The parts of a record, `struct apparmor_audit_data` of Linux.
#[derive(Default)]
pub struct Data<'a> {
    /// The operation, `op`.
    pub op: Option<&'a str>,
    /// The class of the rule, `class`, as `aa_class_names` of Linux.
    pub class: Option<&'a str>,
    /// The text that tells why, `info`.
    pub info: Option<&'a str>,
    /// The error number, negative, or 0.
    pub error: i32,
    /// The name of the profile of the process, `subj_label`.
    pub profile: Option<&'a str>,
    /// The name of the object, `name`.
    pub name: Option<&'a str>,
}

/// The process ID and the name of the current process.
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn current() -> (u32, alloc::vec::Vec<u8>) {
    rk_proc::current_thread().map_or((0, alloc::vec::Vec::new()), |t| {
        let p = t.process();
        (p.pid(), p.comm())
    })
}

/// The process ID and the name of the current process. A build for the host has no process.
#[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn current() -> (u32, alloc::vec::Vec<u8>) {
    (0, alloc::vec::Vec::new())
}

/// The text of a record without its fields after `comm`, as `audit_pre` of Linux and
/// `dump_common_audit_data` of Linux.
fn text(kind: Kind, d: &Data<'_>, pid: u32, comm: &[u8]) -> String {
    let mut s = format!("apparmor=\"{}\"", kind.name());
    if let Some(op) = d.op {
        let _ = write!(s, " operation=\"{op}\"");
    }
    if let Some(class) = d.class {
        let _ = write!(s, " class=\"{class}\"");
    }
    if let Some(info) = d.info {
        let _ = write!(s, " info=\"{info}\"");
        if d.error != 0 {
            let _ = write!(s, " error={}", d.error);
        }
    }
    if let Some(p) = d.profile {
        s.push_str(" profile=");
        untrusted(&mut s, p.as_bytes());
    }
    if let Some(n) = d.name {
        s.push_str(" name=");
        untrusted(&mut s, n.as_bytes());
    }
    let _ = write!(s, " pid={pid} comm=");
    untrusted(&mut s, comm);
    s
}

/// Sends a record, as `aa_audit_msg` of Linux. `tail` is the text of the fields that the
/// caller adds after `comm`, with a space before each field.
pub fn log(kind: Kind, d: &Data<'_>, tail: &str) {
    let (pid, comm) = current();
    let mut s = text(kind, d, pid, &comm);
    s.push_str(tail);
    rk_net::netlink::audit::log_avc(&s);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_text_of_a_record_is_as_on_linux() {
        let d = Data {
            op: Some("profile_load"),
            profile: Some("unconfined"),
            name: Some("rk_test"),
            ..Data::default()
        };
        assert_eq!(
            text(Kind::Status, &d, 7, b"apparmor_parser"),
            "apparmor=\"STATUS\" operation=\"profile_load\" profile=\"unconfined\" \
             name=\"rk_test\" pid=7 comm=\"apparmor_parser\""
        );
        let d = Data {
            op: Some("profile_replace"),
            class: None,
            info: Some("profile already exists"),
            error: -17,
            profile: Some("unconfined"),
            name: Some("a b"),
        };
        assert_eq!(
            text(Kind::Status, &d, 1, b"x"),
            "apparmor=\"STATUS\" operation=\"profile_replace\" info=\"profile already exists\" \
             error=-17 profile=\"unconfined\" name=612062 pid=1 comm=\"x\""
        );
        assert_eq!(Kind::Denied.name(), "DENIED");
    }
}

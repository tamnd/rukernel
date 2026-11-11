//! The changes of the label that a task asks for, as `change_hat` and `change_profile` in
//! domain.c, task.c and procattr.c of Linux, and `do_setattr` of lsm.c.
//!
//! A task writes a command to `/proc/self/attr/current` or `/proc/self/attr/exec`, or gives it
//! to `lsm_set_self_attr`, as libapparmor does:
//!
//! ```text
//! changehat TOKEN^HAT     changes to the hat HAT, with the token TOKEN in hex
//! changehat TOKEN^        goes back from the hat, with the same token
//! permhat TOKEN^HAT       only does the checks of changehat
//! changeprofile NAME      changes to the profile NAME
//! permprofile NAME        only does the checks of changeprofile
//! exec NAME               changes to the profile NAME at the next exec (attr/exec only)
//! stack NAME              puts the profile NAME on a stack, now or at the next exec
//! ```
//!
//! After `changehat TOKEN^`, the names of more hats can follow, each after a 0 byte. The task
//! goes to the first hat that is there.
//!
//! Each profile acts in complain mode for the `change_profile` rules: a change that the rules
//! do not allow gives an `ALLOWED` record and goes on. A hat or a profile that is not there
//! gives a learning profile in complain mode, and an error in the other modes, as on Linux. A
//! wrong token kills the task, also in complain mode, as on Linux.
//!
//! `changeprofile &NAME` and `exec &NAME` put the profile NAME on a stack with the label of the
//! task, and NAME can itself be a stack `A//&B`. As on Linux, a stack has no check of the
//! `change_profile` rules, because a stack only adds limits. A stack that is not there gives
//! `ENOENT` and no learning profile. A stack for the next exec goes on the label of the task at
//! the exec, as on Linux. A task with a stack can not change its hat, and gets `EPERM`.

use crate::audit::{self, Kind};
use crate::domain::{self, FileAudit, slot};
use crate::policy::{self, Mode, Ns, Profile};
use crate::unpack::{Pdb, Perms, class, perm};
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::cred::Cred;
use rk_vfs::inode::Result;
use rk_vfs::security::attr;

/// The operation of `change_hat`, `OP_CHANGE_HAT`.
const OP_CHANGE_HAT: &str = "change_hat";

/// The most hats in one `changehat`, as `aa_setprocattr_changehat` of Linux.
const MAX_HATS: usize = 16;

/// A space for `strim` and `skip_spaces` of Linux.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// The bytes of `b` up to the first 0 byte, as a C string.
fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// A command of `do_setattr` of Linux.
#[derive(Debug, PartialEq, Eq)]
struct Command {
    /// The value with a 0 byte at its end, with the 0 bytes that `strim` and `strsep` of Linux
    /// put in it.
    buf: Vec<u8>,
    /// The command word.
    name: Vec<u8>,
    /// The byte offset of the arguments in `buf`.
    args: usize,
}

/// Splits the value of a write into the command and its arguments, as the start of
/// `do_setattr` of Linux: the spaces at the start and the end go away, and a space comes
/// after the command. Gives `None` if no argument is there.
fn split_command(value: &[u8]) -> Option<Command> {
    let mut buf = value.to_vec();
    if buf.last() != Some(&0) {
        buf.push(0);
    }
    let mut end = cstr(&buf).len();
    while end > 0 && is_space(buf[end - 1]) {
        end -= 1;
    }
    buf[end] = 0;
    let mut start = 0;
    while start < end && is_space(buf[start]) {
        start += 1;
    }
    let sp = buf[start..end].iter().position(|&c| c == b' ')?;
    let name = buf[start..start + sp].to_vec();
    let mut args = start + sp + 1;
    while is_space(buf[args]) {
        args += 1;
    }
    if buf[args] == 0 {
        return None;
    }
    Some(Command { buf, name, args })
}

/// Splits the token from the names of the hats, as `split_token_from_name` of Linux: the
/// token in hex, as `simple_strtoull`, then `^`. Gives the token and the byte offset of the
/// names.
fn split_token(args: &[u8]) -> Option<(u64, usize)> {
    let mut i = 0;
    if args.len() > 2 && args[0] == b'0' && args[1] | 0x20 == b'x' && args[2].is_ascii_hexdigit() {
        i = 2;
    }
    let mut token = 0u64;
    while let Some(d) = args.get(i).and_then(|&c| char::from(c).to_digit(16)) {
        token = token.wrapping_mul(16).wrapping_add(u64::from(d));
        i += 1;
    }
    (i > 0 && args.get(i) == Some(&b'^')).then_some((token, i + 1))
}

/// The token and the names of the hats of `changehat`, as `aa_setprocattr_changehat` of
/// Linux. `args` are the arguments, and the names end at the byte offset `end` of them.
fn parse_hats(args: &[u8], end: usize) -> Option<(u64, Vec<&[u8]>)> {
    let (token, mut i) = split_token(args)?;
    let mut hats = Vec::new();
    if cstr(&args[i..]).is_empty() {
        // No hat: a return from the hat, which needs a token.
        return (token != 0).then_some((token, hats));
    }
    while i < end && hats.len() < MAX_HATS {
        let h = cstr(&args[i..]);
        hats.push(h);
        i += h.len() + 1;
    }
    Some((token, hats))
}

/// A write of `value` to the attribute `attr` of the caller, `do_setattr` of Linux. Gives the
/// count of bytes.
///
/// # Errors
///
/// Gives `EINVAL` for a command that is not correct, and the error of the change.
pub fn setattr(attr: u64, value: &[u8]) -> Result<usize> {
    let cmd = split_command(value).ok_or(Errno::EINVAL)?;
    let args = &cmd.buf[cmd.args..];
    let r = match (attr, cmd.name.as_slice()) {
        (attr::CURRENT, b"changehat" | b"permhat") => {
            let (token, hats) = parse_hats(args, value.len() - cmd.args).ok_or(Errno::EINVAL)?;
            change_hat(&hats, token, cmd.name == b"permhat")
        }
        (attr::CURRENT, b"changeprofile") => change_profile(cstr(args), false, false, false),
        (attr::CURRENT, b"permprofile") => change_profile(cstr(args), false, false, true),
        (attr::CURRENT, b"stack") => change_profile(cstr(args), true, false, false),
        (attr::EXEC, b"exec") => change_profile(cstr(args), false, true, false),
        (attr::EXEC, b"stack") => change_profile(cstr(args), true, true, false),
        _ => {
            bad_command(attr);
            Err(Errno::EINVAL)
        }
    };
    r.map(|()| value.len())
}

/// The record of a command that is not known, as the end of `do_setattr` of Linux. It is a
/// denial in each mode.
fn bad_command(attr: u64) {
    let p = domain::profile_of(&rk_vfs::cred::current());
    let fq = p.as_deref().map(Profile::fqname);
    let d = audit::Data {
        op: Some("setprocattr"),
        info: Some(match attr {
            attr::CURRENT => "current",
            attr::EXEC => "exec",
            _ => "invalid",
        }),
        error: -i32::from(Errno::EINVAL.get()),
        profile: Some(fq.as_deref().unwrap_or("unconfined")),
        ..audit::Data::default()
    };
    audit::log(Kind::Denied, &d, "");
}

/// The attribute with the name `name` of `/proc/self/attr`, `lsm_name_to_attr` of Linux. 0 is
/// a name that is not known.
pub fn attr_of_name(name: &str) -> u64 {
    match name {
        "current" => attr::CURRENT,
        "exec" => attr::EXEC,
        "fscreate" => attr::FSCREATE,
        "keycreate" => attr::KEYCREATE,
        "prev" => attr::PREV,
        "sockcreate" => attr::SOCKCREATE,
        _ => attr::UNDEF,
    }
}

/// Gives the caller the new credentials `new`, as `commit_creds` of Linux.
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn commit(new: Cred) {
    if let Some(t) = rk_proc::current_thread() {
        t.process().set_cred(new);
    }
}

/// A build for the host has no process.
#[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn commit(_new: Cred) {}

/// Sends `SIGKILL` to the caller, as `aa_audit` of Linux does for a record of the kind
/// `KILLED`.
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn kill_current() {
    use rk_abi::native::signal::SIGKILL;
    if let Some(t) = rk_proc::current_thread() {
        rk_proc::send_signal(t.process(), rk_proc::signal::SigInfo::new(SIGKILL, 0, 0));
    }
}

/// A build for the host has no process.
#[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn kill_current() {}

/// A record of `change_hat` for the profile `p`.
fn audit_hat(
    p: Option<&Profile>,
    perms: &Perms,
    name: &[u8],
    target: Option<&str>,
    info: Option<&'static str>,
    error: Errno,
    kind: Kind,
) {
    let a = FileAudit {
        op: OP_CHANGE_HAT,
        request: perm::CHANGEHAT,
        name,
        target,
        ouid: 0,
        info,
        error: Some(error),
    };
    domain::audit_file_as(p, perms, &a, Some(kind));
}

/// The record of a wrong token, and the kill of the caller, as the label `kill` of
/// `aa_change_hat` of Linux. Gives `EACCES`.
fn token_fail(p: Option<&Profile>, target: &[Arc<Profile>]) -> Errno {
    let perms = Perms { kill: perm::CHANGEHAT, ..Perms::default() };
    let target = domain::label_text_plain(target, p);
    audit_hat(
        p,
        &perms,
        b"",
        Some(&target),
        Some("failed token match"),
        Errno::EACCES,
        Kind::Killed,
    );
    kill_current();
    Errno::EACCES
}

/// The hat of `p` for the first name in `hats` that is there, as `change_hat` and
/// `build_change_hat` of Linux. A profile in complain mode takes the first name, and gets a
/// learning hat if the hat is not there.
fn find_hat(ns: &Ns, p: &Profile, hats: &[&[u8]]) -> Result<Arc<Profile>> {
    // A hat changes to a hat of its parent, and a profile to one of its own hats.
    let root = if p.hat { p.parent().unwrap_or("") } else { p.name.as_str() };
    let complain = p.mode == Mode::Complain;
    let lookup = |name: &[u8]| ns.lookup(&format!("{root}//{}", String::from_utf8_lossy(name)));
    let mut found = None;
    let mut fail = None;
    for &name in hats {
        match lookup(name) {
            None if !complain => continue,
            Some(h) if !h.hat => fail = Some((name, "target not hat", Errno::EPERM)),
            _ => found = Some(name),
        }
        break;
    }
    let Some(name) = found else {
        let (name, info, error) = fail.unwrap_or_else(|| {
            if ns.children(Some(&p.name)).is_empty() {
                (&b""[..], "no hats defined", Errno::ECHILD)
            } else {
                (&b""[..], "hat not found", Errno::ENOENT)
            }
        });
        // The probe of more than one hat is not in the log, as on Linux.
        if hats.len() > 1 || complain {
            audit_hat(
                Some(p),
                &Perms::default(),
                name,
                None,
                Some(info),
                error,
                domain::mode_kind(Some(p)),
            );
        }
        return Err(error);
    };
    let (hat, error) = match lookup(name) {
        Some(h) => (h, None),
        None => (ns.learning(p, true, &String::from_utf8_lossy(name)), Some(Errno::ENOENT)),
    };
    if let Some(error) = error {
        audit_hat(Some(p), &Perms::default(), name, Some(&hat.name), None, error, Kind::Allowed);
    }
    Ok(hat)
}

/// The change to the first hat of `hats` that is there, or back from the hat with no hats,
/// `aa_change_hat` of Linux. `test` only does the checks.
fn change_hat(hats: &[&[u8]], token: u64, test: bool) -> Result<()> {
    let cred = rk_vfs::cred::current();
    let full = domain::label_of(&cred);
    let label = full.first().cloned();
    if full.len() > 1 {
        // A change of the hat of each profile of a stack is not there yet.
        let p = label.as_deref();
        let info = Some("stack can not change_hat");
        audit_hat(p, &Perms::default(), b"", None, info, Errno::EPERM, domain::mode_kind(p));
        return Err(Errno::EPERM);
    }
    let unconfined = label.as_ref().is_none_or(|p| p.mode == Mode::Unconfined);
    let no_hats =
        |p: &Profile| policy::with_ns(p.ns.as_deref(), |ns| ns.children(Some(&p.name)).is_empty());
    if unconfined && label.as_deref().is_none_or(no_hats) {
        let p = label.as_deref();
        let info = Some("unconfined can not change_hat");
        audit_hat(p, &Perms::default(), b"", None, info, Errno::EPERM, domain::mode_kind(p));
        return Err(Errno::EPERM);
    }
    let previous = domain::ref_label(domain::load(&cred, slot::PREVIOUS));
    let same_token = domain::load(&cred, slot::TOKEN) == token;
    if let Some(p) = label.as_ref().filter(|_| !hats.is_empty()) {
        let hat = policy::with_ns(p.ns.as_deref(), |ns| find_hat(ns, p, hats))?;
        if test {
            return Ok(());
        }
        // `aa_set_current_hat`: the first change keeps the label and the token.
        if previous.is_some() && !same_token {
            return Err(token_fail(Some(p), core::slice::from_ref(&hat)));
        }
        let new = Cred::clone(&cred);
        if previous.is_none() {
            domain::store(&new, slot::PREVIOUS, domain::label_ref(&full));
            domain::store(&new, slot::TOKEN, token);
        }
        domain::set_profile(&new, Some(&hat));
        domain::store(&new, slot::ONEXEC, 0);
        commit(new);
    } else if let Some(prev) = previous.filter(|_| !test) {
        // `aa_restore_previous_label`.
        if !same_token {
            return Err(token_fail(label.as_deref(), &prev));
        }
        let new = Cred::clone(&cred);
        domain::set_label(&new, &prev);
        domain::clear_trans(&new);
        commit(new);
    }
    Ok(())
}

/// The profile with the name `name`, as `aa_label_parse` of Linux for one component of a label:
/// `NAME` in the namespace of the profile `view`, or `:NS:NAME` or `:NS://NAME` in the child
/// namespace `NS`. `Some(None)` is `unconfined`.
fn parse_profile(name: &str, view: Option<&Profile>) -> Option<Option<Arc<Profile>>> {
    if name == "unconfined" {
        return Some(None);
    }
    if name.starts_with(':') {
        return policy::lookup_fq(name).map(Some);
    }
    policy::with_ns(view.and_then(|v| v.ns.as_deref()), |ns| ns.lookup(name)).map(Some)
}

/// The label with the name `name`, `aa_label_parse` of Linux: the profiles of the components
/// with `//&` between them. An empty label is `unconfined`. Gives `None` if a profile is not
/// there.
fn parse_label(name: &str, view: Option<&Profile>) -> Option<domain::Label> {
    let mut out = Vec::new();
    for part in name.split(domain::STACK) {
        out.extend(parse_profile(part, view)?);
    }
    Some(out)
}

/// The change to the label `fqname` now, or at the next exec with `onexec`, as
/// `aa_change_profile` of Linux. `test` only does the checks. A name that starts with `&` puts
/// the label on a stack with the label of the task, as `stack`.
fn change_profile(fqname: &[u8], stack: bool, onexec: bool, test: bool) -> Result<()> {
    let (stack, fqname) = match fqname {
        [b'&', rest @ ..] => (true, rest),
        _ => (stack, fqname),
    };
    if fqname.is_empty() {
        return Err(Errno::EINVAL);
    }
    let cred = rk_vfs::cred::current();
    let full = domain::label_of(&cred);
    let label = full.first().cloned();
    let (op, request) = if onexec {
        ("change_onexec", perm::ONEXEC)
    } else {
        ("change_profile", perm::CHANGE_PROFILE)
    };
    let name = String::from_utf8_lossy(fqname);
    let mut a =
        FileAudit { op, request, name: fqname, target: None, ouid: 0, info: None, error: None };
    let complain = label.as_ref().is_some_and(|p| p.mode == Mode::Complain);
    let target = match (parse_label(&name, label.as_deref()), label.as_ref()) {
        (Some(t), _) => {
            // As on Linux, a stack is always a subset, so only a change has the check.
            for p in full.iter().filter(|p| p.mode != Mode::Unconfined && !stack) {
                let empty = Pdb::default();
                let file = p.rules.as_ref().map_or(&empty, |r| &r.file);
                let target = domain::label_text_plain(&t, Some(p));
                let fsuid = cred.fsuid;
                let start = file.start[class::FILE];
                let (perms, ok) = domain::change_perms(file, start, &target, request, fsuid)
                    .ok_or(Errno::EACCES)?;
                if !ok {
                    // As in complain mode, the change goes on.
                    let a = FileAudit { target: Some(&target), error: Some(Errno::EACCES), ..a };
                    domain::audit_file(Some(p), &perms, &a);
                }
            }
            t
        }
        // In complain mode, a profile that is not there gives a learning profile.
        (None, Some(p)) if complain && !test && !stack && !name.contains(domain::STACK) => {
            alloc::vec![policy::with_ns(p.ns.as_deref(), |ns| ns.learning(p, false, &name))]
        }
        (None, _) => {
            a.info = Some("label not found");
            a.error = Some(Errno::ENOENT);
            let p = label.as_deref();
            domain::audit_file_as(p, &Perms::default(), &a, Some(domain::mode_kind(p)));
            return Err(Errno::ENOENT);
        }
    };
    if test {
        return Ok(());
    }
    let new = Cred::clone(&cred);
    if onexec {
        // As `aa_set_current_onexec` of Linux, the label for the exec is the target only, and
        // the token tells if it goes on a stack. The exec makes the stack.
        domain::store(&new, slot::ONEXEC, domain::label_ref(&target));
        domain::store(&new, slot::TOKEN, u64::from(stack));
    } else {
        let target = if stack { domain::merge(&full, &target) } else { target };
        // `aa_replace_current_label`: a change to `unconfined` clears the context.
        if target.is_empty() {
            domain::clear_trans(&new);
        }
        domain::set_label(&new, &target);
    }
    commit(new);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Change, replace};

    /// The policy of `rk_test` with the hat `hat1`.
    const RK_TEST: &[u8] = include_bytes!("../tests/rk_test.bin");

    #[test]
    fn a_command_splits_as_on_linux() {
        let c = split_command(b"  changehat 0000000000000007^hat1\n").unwrap();
        assert_eq!(c.name, b"changehat");
        assert_eq!(cstr(&c.buf[c.args..]), b"0000000000000007^hat1");
        assert!(split_command(b"changehat").is_none());
        assert!(split_command(b"changehat   \n").is_none());
        let c = split_command(b"exec  rk_test\0").unwrap();
        assert_eq!((c.name.as_slice(), cstr(&c.buf[c.args..])), (&b"exec"[..], &b"rk_test"[..]));
    }

    #[test]
    fn the_token_and_the_hats_are_as_on_linux() {
        assert_eq!(split_token(b"0000000000000007^hat1"), Some((7, 17)));
        assert_eq!(split_token(b"0x1f^"), Some((0x1f, 5)));
        assert_eq!(split_token(b"^hat1"), None);
        assert_eq!(split_token(b"12"), None);
        let args = b"7^a\0b\0";
        let (token, hats) = parse_hats(args, args.len()).unwrap();
        assert_eq!((token, hats), (7, [&b"a"[..], &b"b"[..]].to_vec()));
        // A return from a hat needs a token.
        assert_eq!(parse_hats(b"0^\0", 3), None);
        assert_eq!(parse_hats(b"5^\0", 3), Some((5, Vec::new())));
        assert_eq!(attr_of_name("exec"), attr::EXEC);
        assert_eq!(attr_of_name("other"), attr::UNDEF);
    }

    #[test]
    fn a_hat_is_found_as_on_linux() {
        let ns = Ns::new("t");
        assert!(replace(&ns, Change::Load, RK_TEST).is_ok());
        let p = ns.lookup("rk_test").unwrap();
        // rk_test is in complain mode: the first name counts, and a missing hat is learnt.
        assert_eq!(find_hat(&ns, &p, &[b"hat1"]).unwrap().name, "rk_test//hat1");
        let learn = find_hat(&ns, &p, &[b"none", b"hat1"]).unwrap();
        assert_eq!((learn.name.as_str(), learn.hat), ("rk_test//null-none", true));
        // rk_test//hat1 is in enforce mode: it finds the hats of its parent.
        let hat = ns.lookup("rk_test//hat1").unwrap();
        assert!(hat.hat);
        assert_eq!(find_hat(&ns, &hat, &[b"x", b"hat1"]).unwrap().name, "rk_test//hat1");
        assert_eq!(find_hat(&ns, &hat, &[b"x"]).unwrap_err(), Errno::ECHILD);
        assert_eq!(find_hat(&ns, &hat, &[b"null-none"]).unwrap().name, "rk_test//null-none");
        assert_eq!(find_hat(&ns, &p, &[b"null-none"]).unwrap().name, "rk_test//null-none");
    }

    #[test]
    fn a_stack_parses_as_on_linux() {
        assert!(replace(&policy::ROOT, Change::Load, RK_TEST).is_ok());
        let names = |l: &[Arc<Profile>]| l.iter().map(|p| p.name.clone()).collect::<Vec<_>>();
        let l = parse_label("rk_test//&rk_test//hat1", None).unwrap();
        assert_eq!(names(&l), ["rk_test", "rk_test//hat1"]);
        assert_eq!(domain::label_text_plain(&l, None), "rk_test//&rk_test//hat1");
        assert!(parse_label("unconfined", None).unwrap().is_empty());
        assert!(parse_label("rk_test//&none", None).is_none());
        // The stack of a label with a part of it adds only the new profiles.
        let one = parse_label("rk_test", None).unwrap();
        assert_eq!(names(&domain::merge(&one, &l)), ["rk_test", "rk_test//hat1"]);
    }
}

//! The policy: the namespaces and their profiles, as security/apparmor/policy.c and
//! policy_ns.c of Linux.
//!
//! There is one namespace now, the root namespace `root`. A load of a policy in another
//! namespace gives `EOPNOTSUPP`.
//!
//! The profiles of a namespace make a tree. A hat or a child profile has the name of its
//! parent, then `//` and its own name. The namespace keeps all the profiles in one list, the
//! newest first, and the tree comes from the names.

use crate::audit::{self, Kind};
use crate::unpack::{self, Unpacked};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::cred::Cred;
use rk_vfs::inode::Result;

/// `CAP_MAC_ADMIN`, the capability to change the policy.
const CAP_MAC_ADMIN: u32 = 33;

/// The mode of a profile, `enum profile_mode` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The profile denies what the policy does not allow.
    Enforce,
    /// The profile allows all and logs what the policy does not allow.
    Complain,
    /// The profile kills the task at a denial.
    Kill,
    /// The profile does not confine.
    Unconfined,
    /// The profile asks a program in user space.
    User,
}

impl Mode {
    /// The name of the mode, as `aa_profile_mode_names` of Linux.
    pub fn name(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Complain => "complain",
            Self::Kill => "kill",
            Self::Unconfined => "unconfined",
            Self::User => "user",
        }
    }
}

/// A profile, `struct aa_profile` of Linux.
#[derive(Debug)]
pub struct Profile {
    /// The full name, with the names of the parents for a hat.
    pub name: String,
    /// The mode.
    pub mode: Mode,
    /// The rules, from the unpack of the policy. A profile that the load made for a missing
    /// parent of a hat has no rules, as a profile with `FLAG_NULL` of Linux.
    pub rules: Option<Box<Unpacked>>,
    /// The profile is a hat, `FLAG_HAT` of Linux. A task can change to it with `change_hat`.
    pub hat: bool,
}

impl Profile {
    /// A profile for a missing parent, as `aa_alloc_null` of Linux. It is in complain mode.
    fn null(name: &str, hat: bool) -> Self {
        Self { name: String::from(name), mode: Mode::Complain, rules: None, hat }
    }

    /// The name of the parent, if the profile is a hat or a child profile.
    pub fn parent(&self) -> Option<&str> {
        parent_of(&self.name)
    }

    /// The name without the names of the parents, `base.name` of Linux.
    pub fn base_name(&self) -> &str {
        self.name.rfind("//").map_or(&self.name, |i| &self.name[i + 2..])
    }
}

/// The name of the parent of the profile `name`.
fn parent_of(name: &str) -> Option<&str> {
    name.rfind("//").map(|i| &name[..i])
}

/// A policy namespace, `struct aa_ns` of Linux.
pub struct Ns {
    /// The name.
    pub name: &'static str,
    /// The number of changes of the policy, `revision`.
    revision: AtomicU64,
    /// The profiles, the newest first.
    profiles: SpinLock<Vec<Arc<Profile>>>,
}

impl Ns {
    /// An empty namespace.
    pub const fn new(name: &'static str) -> Self {
        Self { name, revision: AtomicU64::new(0), profiles: SpinLock::new(Vec::new()) }
    }

    /// The number of changes of the policy.
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Relaxed)
    }

    /// The profiles in the order of a walk of the tree, as the file `profiles` of Linux: each
    /// profile comes before its children, and the newest of the profiles with the same parent
    /// comes first.
    pub fn profiles(&self) -> Vec<Arc<Profile>> {
        let all = self.profiles.lock().clone();
        let mut out = Vec::with_capacity(all.len());
        walk(&all, None, &mut out);
        out
    }

    /// The profile with the name `name`, `__lookup_profile` of Linux.
    pub fn lookup(&self, name: &str) -> Option<Arc<Profile>> {
        self.profiles.lock().iter().find(|p| p.name == name).cloned()
    }

    /// The profiles with the parent `parent`, the newest first, as the list of profiles of a
    /// namespace or of a profile of Linux.
    pub fn children(&self, parent: Option<&str>) -> Vec<Arc<Profile>> {
        self.profiles.lock().iter().filter(|p| p.parent() == parent).cloned().collect()
    }

    /// The learning profile of `parent` for the program or the hat `base`, as
    /// `aa_new_learning_profile` of Linux: `PARENT//null-BASE` in complain mode with no rules.
    /// `hat` tells if it is a hat. A profile with this name that is there comes back.
    pub fn learning(&self, parent: &Profile, hat: bool, base: &str) -> Arc<Profile> {
        let name = format!("{}//null-{base}", parent.name);
        let mut list = self.profiles.lock();
        if let Some(p) = list.iter().find(|p| p.name == name) {
            return p.clone();
        }
        let p = Arc::new(Profile::null(&name, hat));
        list.insert(0, p.clone());
        p
    }
}

/// Adds the children of `parent` and their children to `out`.
fn walk(all: &[Arc<Profile>], parent: Option<&str>, out: &mut Vec<Arc<Profile>>) {
    for p in all.iter().filter(|p| p.parent() == parent) {
        out.push(p.clone());
        walk(all, Some(&p.name), out);
    }
}

/// The root namespace, `root_ns` of Linux.
pub static ROOT: Ns = Ns::new("root");

/// The kind of a change of the policy, for the checks and the messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// `.load`: adds new profiles, `AA_MAY_LOAD_POLICY`.
    Load,
    /// `.replace`: adds or replaces profiles, `AA_MAY_REPLACE_POLICY`.
    Replace,
    /// `.remove`: removes a profile, `AA_MAY_REMOVE_POLICY`.
    Remove,
}

/// The process can see the policy, as `aa_policy_view_capable` of Linux: its effective user or
/// a group is root in the first user namespace.
pub fn view_capable(cred: &Cred) -> bool {
    let root = cred.euid == 0 || cred.egid == 0 || cred.groups.binary_search(&0).is_ok();
    root && Arc::ptr_eq(&cred.user_ns, rk_vfs::user_ns::init())
}

/// The process can change the policy, as `aa_policy_admin_capable` of Linux: it can see the
/// policy and it has `CAP_MAC_ADMIN`.
pub fn admin_capable(cred: &Cred) -> bool {
    view_capable(cred) && cred.capable(CAP_MAC_ADMIN)
}

/// Checks a change of the policy, as `aa_may_manage_policy` of Linux.
///
/// # Errors
///
/// Gives `EACCES` if the process cannot change the policy.
pub fn may_manage(cred: &Cred, change: Change) -> Result<()> {
    if !admin_capable(cred) {
        status(change.op(), Some(("not policy admin", Errno::EACCES)), None);
        return Err(Errno::EACCES);
    }
    Ok(())
}

impl Change {
    /// The name of the operation in the log, `OP_PROF_*` of Linux.
    fn op(self) -> &'static str {
        match self {
            Self::Load => "profile_load",
            Self::Replace => "profile_replace",
            Self::Remove => "profile_remove",
        }
    }
}

/// The label of the process in the log. All processes are unconfined now.
const SUBJECT: &str = "unconfined";

/// Logs a change of the policy, as `audit_policy` of Linux. `fail` has the text and the error
/// of a failure.
fn status(op: &str, fail: Option<(&str, Errno)>, name: Option<&str>) {
    let info = fail.map(|f| f.0);
    let error = fail.map_or(0, |f| -i32::from(f.1.get()));
    let d = audit::Data { op: Some(op), class: None, info, error, profile: Some(SUBJECT), name };
    audit::log(Kind::Status, &d, "");
}

/// Logs a failure of the unpack, as `audit_iface` of Linux. The name comes two times, as on
/// Linux: the second time with the offset in the data.
fn unpack_status(e: &unpack::Error) {
    let error = -i32::from(e.errno.get());
    let name = e.name.as_deref();
    let d = audit::Data {
        op: None,
        class: None,
        info: Some(e.info),
        error,
        profile: Some(SUBJECT),
        name,
    };
    let mut tail = String::new();
    if let Some(n) = name {
        tail.push_str(" name=");
        audit::untrusted(&mut tail, n.as_bytes());
    }
    if e.pos != 0 {
        tail.push_str(&format!(" offset={}", e.pos));
    }
    audit::log(Kind::Status, &d, &tail);
}

/// An error of a change of the policy, with the text and the name of the profile for the log.
fn error(errno: Errno, info: &'static str, name: Option<&str>) -> unpack::Error {
    unpack::Error { errno, info, name: name.map(String::from), pos: 0 }
}

/// Loads or replaces the profiles of the binary policy `data` in `ns`, as
/// `aa_replace_profiles` of Linux. Gives the count of bytes that it took.
///
/// A new profile comes first in the list. A profile that replaces a profile takes its place,
/// and the children of the old profile stay. A hat whose parent is not there gets a parent in
/// complain mode with no rules. As on Linux, the profile that `rename` names stays.
///
/// # Errors
///
/// - The errors of [`unpack::unpack`].
/// - `EACCES` if the profiles are in different namespaces.
/// - `EOPNOTSUPP` if the profiles are not in `ns`.
/// - `EEXIST` for a [`Change::Load`] of a profile that is there.
pub fn replace(ns: &Ns, change: Change, data: &[u8]) -> core::result::Result<usize, unpack::Error> {
    let policy = unpack::unpack(data).inspect_err(unpack_status)?;
    let mut ns_name = policy.ns.as_deref();
    let mut count = 0;
    for p in &policy.profiles {
        let mixed = match (ns_name, p.ns.as_deref()) {
            (Some(a), Some(b)) => a != b,
            (None, Some(b)) => {
                ns_name = Some(b);
                count > 0
            }
            (_, None) => {
                count += 1;
                false
            }
        };
        if mixed {
            let info = "policy load has mixed namespaces";
            status(change.op(), Some((info, Errno::EACCES)), Some(&p.name));
            return Err(error(Errno::EACCES, info, Some(&p.name)));
        }
    }
    if ns_name.is_some() {
        let info = "policy namespaces are not supported";
        status(Change::Load.op(), Some((info, Errno::EOPNOTSUPP)), None);
        return Err(error(Errno::EOPNOTSUPP, info, None));
    }
    let mut list = ns.profiles.lock();
    if change == Change::Load {
        let there = |name: &str| list.iter().any(|q| q.name == name);
        for p in &policy.profiles {
            if there(&p.name) || p.rename.as_deref().is_some_and(there) {
                // The load found the old profile, so Linux logs a replace.
                let info = "profile already exists";
                status(Change::Replace.op(), Some((info, Errno::EEXIST)), Some(&p.name));
                return Err(error(Errno::EEXIST, info, Some(&p.name)));
            }
        }
    }
    for p in policy.profiles {
        let mut parent = parent_of(&p.name);
        while let Some(name) = parent {
            if !list.iter().any(|q| q.name == name) {
                list.insert(0, Arc::new(Profile::null(name, false)));
            }
            parent = parent_of(name);
        }
        let hat = p.hat;
        let new = Arc::new(Profile { name: p.name.clone(), mode: p.mode, rules: Some(p), hat });
        let old = list.iter().position(|q| q.name == new.name);
        let op = if old.is_some() { Change::Replace } else { Change::Load };
        status(op.op(), None, Some(&new.name));
        match old {
            Some(i) => list[i] = new,
            None => list.insert(0, new),
        }
    }
    ns.revision.fetch_add(1, Ordering::Relaxed);
    Ok(data.len())
}

/// Tells if the profile `name` is `top` or one of its children.
fn is_in(name: &str, top: &str) -> bool {
    name.strip_prefix(top).is_some_and(|r| r.is_empty() || r.starts_with("//"))
}

/// Removes the profile with the name `name` and its children from `ns`, as
/// `aa_remove_profiles` of Linux. The name ends at the first 0 byte. As on Linux, a new line at
/// the end is a part of the name. Gives the count of bytes that it took.
///
/// # Errors
///
/// Gives `ENOENT` for an empty name, a name in a namespace or a name with no profile.
pub fn remove(ns: &Ns, name: &[u8]) -> Result<usize> {
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let fq = &name[..end];
    let fq = String::from_utf8_lossy(fq);
    let op = Change::Remove.op();
    let fail = |info, name: Option<&str>| {
        status(op, Some((info, Errno::ENOENT)), name);
        Err(Errno::ENOENT)
    };
    if fq.is_empty() {
        return fail("no profile specified", Some(&fq));
    }
    // No namespace is there other than the root namespace.
    if fq.starts_with(':') {
        return fail("namespace does not exist", unpack::split_fqname(&fq).0);
    }
    let mut profiles = ns.profiles.lock();
    if !profiles.iter().any(|p| p.name == fq) {
        return fail("profile does not exist", Some(&fq));
    }
    profiles.retain(|p| !is_in(&p.name, &fq));
    ns.revision.fetch_add(1, Ordering::Relaxed);
    status(op, None, Some(&fq));
    Ok(name.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The policy of `rk_test` with the hat `hat1`, as in the tests of [`unpack`].
    const RK_TEST: &[u8] = include_bytes!("../tests/rk_test.bin");

    fn names(ns: &Ns) -> Vec<String> {
        ns.profiles().iter().map(|p| alloc::format!("{} ({})", p.name, p.mode.name())).collect()
    }

    #[test]
    fn root_may_change_the_policy_and_a_user_may_not() {
        let root = Cred::root();
        assert!(admin_capable(&root));
        assert_eq!(may_manage(&root, Change::Load), Ok(()));
        let mut user = Cred::root();
        user.euid = 1000;
        user.egid = 1000;
        assert!(!view_capable(&user));
        assert_eq!(may_manage(&user, Change::Remove), Err(Errno::EACCES));
    }

    #[test]
    fn a_load_adds_the_profiles_and_a_remove_takes_them_away() {
        let ns = Ns::new("t");
        assert_eq!(remove(&ns, b""), Err(Errno::ENOENT));
        assert_eq!(remove(&ns, b"rk_test\n"), Err(Errno::ENOENT));
        assert_eq!(replace(&ns, Change::Load, RK_TEST), Ok(RK_TEST.len()));
        assert_eq!(ns.revision(), 1);
        assert_eq!(names(&ns), ["rk_test (complain)", "rk_test//hat1 (enforce)"]);
        let e = replace(&ns, Change::Load, RK_TEST).unwrap_err();
        assert_eq!(
            (e.errno, e.info, e.name.as_deref()),
            (Errno::EEXIST, "profile already exists", Some("rk_test"))
        );
        assert_eq!(ns.revision(), 1);
        let old = ns.lookup("rk_test").unwrap();
        assert_eq!(replace(&ns, Change::Replace, RK_TEST), Ok(RK_TEST.len()));
        assert_eq!(ns.revision(), 2);
        assert!(!Arc::ptr_eq(&old, &ns.lookup("rk_test").unwrap()));
        assert!(ns.lookup("rk_test").unwrap().rules.is_some());
        assert_eq!(remove(&ns, b":ns:rk_test"), Err(Errno::ENOENT));
        assert_eq!(remove(&ns, b"rk_test\n"), Err(Errno::ENOENT));
        assert_eq!(remove(&ns, b"rk_test\0"), Ok(8));
        assert_eq!(ns.revision(), 3);
        assert!(ns.profiles().is_empty());
        let e = replace(&ns, Change::Load, b"x").unwrap_err();
        assert_eq!((e.errno, e.info), (Errno::EPROTONOSUPPORT, "invalid profile format"));
    }

    #[test]
    fn the_tree_order_and_the_missing_parents() {
        let ns = Ns::new("t");
        {
            let mut l = ns.profiles.lock();
            for n in ["b//x", "a", "b", "a//y", "a//y//z"] {
                l.insert(0, Arc::new(Profile::null(n, false)));
            }
        }
        let order: Vec<String> = ns.profiles().iter().map(|p| p.name.clone()).collect();
        assert_eq!(order, ["b", "b//x", "a", "a//y", "a//y//z"]);
        assert_eq!(remove(&ns, b"a//y"), Ok(4));
        assert_eq!(remove(&ns, b"b"), Ok(1));
        let order: Vec<String> = ns.profiles().iter().map(|p| p.name.clone()).collect();
        assert_eq!(order, ["a"]);
        // The hat of a load that has no parent gets a parent with no rules.
        let ns = Ns::new("t");
        let first = RK_TEST.windows(7).position(|w| w == b"version").unwrap();
        let second = RK_TEST[first + 1..].windows(7).position(|w| w == b"version").unwrap();
        // The hat has its own header, with the name of the element 3 bytes before the text.
        let data = &RK_TEST[first + second - 2..];
        assert_eq!(replace(&ns, Change::Load, data), Ok(data.len()));
        assert_eq!(names(&ns), ["rk_test (complain)", "rk_test//hat1 (enforce)"]);
        assert!(ns.lookup("rk_test").unwrap().rules.is_none());
        assert_eq!(Mode::Complain.name(), "complain");
        assert!(is_in("a//b", "a") && is_in("a", "a") && !is_in("ab", "a"));
    }
}

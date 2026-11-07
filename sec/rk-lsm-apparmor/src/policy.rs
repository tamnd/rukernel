//! The policy: the namespaces and their profiles, as security/apparmor/policy.c and
//! policy_ns.c of Linux.
//!
//! There is one namespace now, the root namespace `root`. It has no profile yet: the unpack of
//! a binary policy comes later, so a load gives `EPROTO`, as a load of a policy that the kernel
//! cannot unpack.

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

/// A profile.
pub struct Profile {
    /// The full name, with the names of the parents for a hat.
    pub name: String,
    /// The mode.
    pub mode: Mode,
}

/// A policy namespace, `struct aa_ns` of Linux.
pub struct Ns {
    /// The name.
    pub name: &'static str,
    /// The number of changes of the policy, `revision`.
    revision: AtomicU64,
    /// The profiles, in the order of the loads.
    profiles: SpinLock<Vec<Arc<Profile>>>,
}

impl Ns {
    /// The number of changes of the policy.
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Relaxed)
    }

    /// The profiles.
    pub fn profiles(&self) -> Vec<Arc<Profile>> {
        self.profiles.lock().clone()
    }
}

/// The root namespace, `root_ns` of Linux.
pub static ROOT: Ns =
    Ns { name: "root", revision: AtomicU64::new(0), profiles: SpinLock::new(Vec::new()) };

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
pub fn may_manage(cred: &Cred, _change: Change) -> Result<()> {
    if !admin_capable(cred) {
        return Err(Errno::EACCES);
    }
    Ok(())
}

/// Loads or replaces the profiles of the binary policy `data` in `ns`, as
/// `aa_replace_profiles` of Linux. Gives the count of bytes that it took.
///
/// # Errors
///
/// Gives `EPROTO`: the unpack of a binary policy is not there yet.
pub fn replace(_ns: &Ns, _change: Change, _data: &[u8]) -> Result<usize> {
    Err(Errno::EPROTO)
}

/// Removes the profile with the name `name` from `ns`, as `aa_remove_profiles` of Linux. The
/// name ends at the first 0 byte. As on Linux, a new line at the end is a part of the name.
/// Gives the count of bytes that it took.
///
/// # Errors
///
/// Gives `ENOENT` for an empty name or a name with no profile.
pub fn remove(ns: &Ns, name: &[u8]) -> Result<usize> {
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let fq = &name[..end];
    if fq.is_empty() {
        return Err(Errno::ENOENT);
    }
    let mut profiles = ns.profiles.lock();
    let before = profiles.len();
    profiles.retain(|p| p.name.as_bytes() != fq);
    if profiles.len() == before {
        return Err(Errno::ENOENT);
    }
    ns.revision.fetch_add(1, Ordering::Relaxed);
    Ok(name.len())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn a_remove_of_a_profile_that_is_not_there_fails() {
        let ns = Ns { name: "t", revision: AtomicU64::new(0), profiles: SpinLock::new(Vec::new()) };
        assert_eq!(remove(&ns, b""), Err(Errno::ENOENT));
        assert_eq!(remove(&ns, b"/bin/true\n"), Err(Errno::ENOENT));
        let p = Arc::new(Profile { name: String::from("/bin/true"), mode: Mode::Complain });
        ns.profiles.lock().push(p);
        assert_eq!(remove(&ns, b"/bin/true\n"), Err(Errno::ENOENT));
        assert_eq!(remove(&ns, b"/bin/true\0\n"), Ok(11));
        assert_eq!(ns.revision(), 1);
        assert!(ns.profiles().is_empty());
        assert_eq!(Mode::Complain.name(), "complain");
        assert_eq!(replace(&ns, Change::Load, b"x"), Err(Errno::EPROTO));
    }
}

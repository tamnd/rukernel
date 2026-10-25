//! The credentials of a process: the user and group IDs, the supplementary groups, and the
//! capability sets.
//!
//! The rules of the `set*id` calls, of `capset` and of an `execve` are those of `kernel/sys.c` and
//! `security/commoncap.c` of Linux. Linux keeps the credentials for each thread, and the C library
//! changes them in all the threads of a process. rukernel keeps them for each process, which gives
//! the same result for a program that uses the C library.

use crate::inode::{FileType, Metadata, Result, mode};
use alloc::vec::Vec;
use rk_abi::Errno;

/// An ID that a `set*id` call does not change.
pub const KEEP: u32 = u32::MAX;

/// The largest number of supplementary groups, `NGROUPS_MAX` of Linux.
pub const NGROUPS_MAX: usize = 65536;

/// The capabilities that rukernel knows.
pub mod cap {
    /// Change the owner and the group of a file.
    pub const CHOWN: u32 = 0;
    /// Skip the permission checks of a file.
    pub const DAC_OVERRIDE: u32 = 1;
    /// Skip the read and search checks of a file.
    pub const DAC_READ_SEARCH: u32 = 2;
    /// Act as the owner of each file.
    pub const FOWNER: u32 = 3;
    /// Keep the set-user-ID and set-group-ID bits when a file changes.
    pub const FSETID: u32 = 4;
    /// Send a signal to each process.
    pub const KILL: u32 = 5;
    /// Change the group IDs.
    pub const SETGID: u32 = 6;
    /// Change the user IDs.
    pub const SETUID: u32 = 7;
    /// Change the capability sets past the usual limits.
    pub const SETPCAP: u32 = 8;
    /// Set the immutable and append-only flags of a file.
    pub const LINUX_IMMUTABLE: u32 = 9;
    /// Use `chroot`.
    pub const SYS_CHROOT: u32 = 18;
    /// Trace each process.
    pub const SYS_PTRACE: u32 = 19;
    /// Do the many administration operations.
    pub const SYS_ADMIN: u32 = 21;
    /// Go past the resource limits.
    pub const SYS_RESOURCE: u32 = 24;
    /// Make a device file.
    pub const MKNOD: u32 = 27;
    /// Set the capabilities of a file.
    pub const SETFCAP: u32 = 31;
    /// Skip the mandatory access control.
    pub const MAC_OVERRIDE: u32 = 32;
    /// The highest capability of Linux, `CAP_CHECKPOINT_RESTORE`.
    pub const LAST: u32 = 40;
    /// All the capabilities.
    pub const ALL: u64 = (1 << (LAST + 1)) - 1;

    /// Gives the bit of a capability.
    pub const fn bit(cap: u32) -> u64 {
        1 << cap
    }

    /// The capabilities that a change of the file system user ID to root or from root adds or
    /// removes, `CAP_FS_SET` of Linux.
    pub const FS_SET: u64 = bit(CHOWN)
        | bit(DAC_OVERRIDE)
        | bit(DAC_READ_SEARCH)
        | bit(FOWNER)
        | bit(FSETID)
        | bit(LINUX_IMMUTABLE)
        | bit(MKNOD)
        | bit(MAC_OVERRIDE);
}

/// The bits of `PR_SET_SECUREBITS`.
pub mod secure {
    /// Root gets no capabilities from an `execve`.
    pub const NOROOT: u32 = 1 << 0;
    /// A change of the user IDs does not change the capabilities.
    pub const NO_SETUID_FIXUP: u32 = 1 << 2;
    /// A change from root to a user keeps the permitted capabilities.
    pub const KEEP_CAPS: u32 = 1 << 4;
    /// The `KEEP_CAPS` bit cannot change.
    pub const KEEP_CAPS_LOCKED: u32 = 1 << 5;
    /// The ambient capabilities cannot grow.
    pub const NO_CAP_AMBIENT_RAISE: u32 = 1 << 6;
    /// All the bits that are not locks.
    pub const ALL_BITS: u32 = 0x55;
    /// All the lock bits. Each lock is one bit above the bit that it locks.
    pub const ALL_LOCKS: u32 = ALL_BITS << 1;
}

/// The access bits of a permission check, `MAY_*` of Linux.
pub mod may {
    /// Execute a file, or search a directory.
    pub const EXEC: u32 = 1;
    /// Write.
    pub const WRITE: u32 = 2;
    /// Read.
    pub const READ: u32 = 4;
}

/// The credentials of a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cred {
    /// The real user ID.
    pub uid: u32,
    /// The effective user ID.
    pub euid: u32,
    /// The saved user ID.
    pub suid: u32,
    /// The user ID of the file system checks.
    pub fsuid: u32,
    /// The real group ID.
    pub gid: u32,
    /// The effective group ID.
    pub egid: u32,
    /// The saved group ID.
    pub sgid: u32,
    /// The group ID of the file system checks.
    pub fsgid: u32,
    /// The supplementary groups, in increasing order.
    pub groups: Vec<u32>,
    /// The inheritable capabilities.
    pub cap_inheritable: u64,
    /// The permitted capabilities.
    pub cap_permitted: u64,
    /// The effective capabilities, which the checks use.
    pub cap_effective: u64,
    /// The capability bounding set.
    pub cap_bset: u64,
    /// The ambient capabilities.
    pub cap_ambient: u64,
    /// The bits of `PR_SET_SECUREBITS`.
    pub securebits: u32,
}

/// The file that an `execve` runs, for [`Cred::exec`].
#[derive(Clone, Copy, Debug)]
pub struct ExecFile {
    /// The mode of the file, with the type bits.
    pub mode: u32,
    /// The owner of the file.
    pub uid: u32,
    /// The group of the file.
    pub gid: u32,
    /// The set-user-ID and set-group-ID bits have no effect: the mount has `nosuid`, the process
    /// has no_new_privs, or a tracer traces it.
    pub no_setid: bool,
}

impl Default for Cred {
    fn default() -> Self {
        Self::root()
    }
}

impl Cred {
    /// The credentials of init: root with all the capabilities.
    pub fn root() -> Self {
        Self {
            uid: 0,
            euid: 0,
            suid: 0,
            fsuid: 0,
            gid: 0,
            egid: 0,
            sgid: 0,
            fsgid: 0,
            groups: Vec::new(),
            cap_inheritable: 0,
            cap_permitted: cap::ALL,
            cap_effective: cap::ALL,
            cap_bset: cap::ALL,
            cap_ambient: 0,
            securebits: 0,
        }
    }

    /// The process has the capability in its effective set.
    pub fn capable(&self, cap: u32) -> bool {
        self.cap_effective & cap::bit(cap) != 0
    }

    /// The group is the file system group or a supplementary group.
    pub fn in_group(&self, gid: u32) -> bool {
        gid == self.fsgid || self.groups.binary_search(&gid).is_ok()
    }

    /// Checks the access `mask` (the bits of [`may`]) to a file with the attributes `meta`, as
    /// `generic_permission` of Linux. The owner bits apply to the owner, the group bits to a
    /// member of the group, and the other bits to the others. `CAP_DAC_OVERRIDE` and
    /// `CAP_DAC_READ_SEARCH` skip the check.
    ///
    /// # Errors
    ///
    /// Gives `EACCES` if the access is not allowed.
    pub fn permission(&self, meta: &Metadata, mask: u32) -> Result<()> {
        let mask = mask & (may::READ | may::WRITE | may::EXEC);
        let bits = if self.fsuid == meta.uid {
            meta.mode >> 6
        } else if self.in_group(meta.gid) {
            meta.mode >> 3
        } else {
            meta.mode
        };
        if bits & mask == mask {
            return Ok(());
        }
        if meta.is_dir() {
            if (mask & may::WRITE == 0 && self.capable(cap::DAC_READ_SEARCH))
                || self.capable(cap::DAC_OVERRIDE)
            {
                return Ok(());
            }
            return Err(Errno::EACCES);
        }
        if mask == may::READ && self.capable(cap::DAC_READ_SEARCH) {
            return Ok(());
        }
        // A file runs with `CAP_DAC_OVERRIDE` only if it has an execute bit.
        if (mask & may::EXEC == 0 || meta.mode & 0o111 != 0) && self.capable(cap::DAC_OVERRIDE) {
            return Ok(());
        }
        Err(Errno::EACCES)
    }

    /// The process owns the file or has `CAP_FOWNER`, as `inode_owner_or_capable` of Linux.
    pub fn owns(&self, meta: &Metadata) -> bool {
        self.fsuid == meta.uid || self.capable(cap::FOWNER)
    }

    /// Checks that the process can remove or rename the file `child` from the directory `dir`.
    /// In a sticky directory, only the owner of the file or of the directory can, as
    /// `check_sticky` of Linux.
    ///
    /// # Errors
    ///
    /// Gives `EPERM` if the sticky bit forbids the change.
    pub fn check_sticky(&self, dir: &Metadata, child: &Metadata) -> Result<()> {
        if dir.mode & mode::S_ISVTX == 0
            || self.fsuid == child.uid
            || self.fsuid == dir.uid
            || self.capable(cap::FOWNER)
        {
            return Ok(());
        }
        Err(Errno::EPERM)
    }

    /// The owner, the group and the permission bits of a new file of the type `kind` in the
    /// directory `dir`, as `inode_init_owner` and `mode_strip_sgid` of Linux. A file in a
    /// set-group-ID directory gets the group of the directory, and a new directory there is
    /// set-group-ID too. A file that is not a directory loses the set-group-ID bit if it has the
    /// group execute bit and the process is not in the group of the directory.
    pub fn new_owner(&self, dir: &Metadata, kind: FileType, perm: u32) -> (u32, u32, u32) {
        let mut perm = perm;
        let sgid_dir = dir.mode & mode::S_ISGID != 0;
        if kind == FileType::Directory {
            if sgid_dir {
                perm |= mode::S_ISGID;
            }
        } else if perm & (mode::S_ISGID | 0o010) == mode::S_ISGID | 0o010
            && !self.in_group(dir.gid)
            && !self.capable(cap::FSETID)
        {
            perm &= !mode::S_ISGID;
        }
        (self.fsuid, if sgid_dir { dir.gid } else { self.fsgid }, perm)
    }

    /// The credentials of `access` and `faccessat` without `AT_EACCESS`: the real IDs take the
    /// place of the file system IDs, and a user other than root has no capabilities.
    pub fn for_access(&self) -> Self {
        let mut c = self.clone();
        c.fsuid = c.uid;
        c.fsgid = c.gid;
        if c.securebits & secure::NO_SETUID_FIXUP == 0 {
            c.cap_effective = if c.uid == 0 { c.cap_permitted } else { 0 };
        }
        c
    }

    /// The new credentials after `setuid`.
    ///
    /// # Errors
    ///
    /// Gives `EPERM` if the caller has no `CAP_SETUID` and the ID is not its real or saved ID.
    pub fn setuid(&self, uid: u32) -> Result<Self> {
        if uid == KEEP {
            return Err(Errno::EINVAL);
        }
        let mut new = self.clone();
        if self.capable(cap::SETUID) {
            new.uid = uid;
            new.suid = uid;
        } else if uid != self.uid && uid != self.suid {
            return Err(Errno::EPERM);
        }
        new.euid = uid;
        new.fsuid = uid;
        new.fix_setuid(self);
        Ok(new)
    }

    /// The new credentials after `setreuid`.
    ///
    /// # Errors
    ///
    /// Gives `EPERM` if the caller has no `CAP_SETUID` and an ID is not allowed.
    pub fn setreuid(&self, ruid: u32, euid: u32) -> Result<Self> {
        let free = self.capable(cap::SETUID);
        let mut new = self.clone();
        if ruid != KEEP {
            if !free && ruid != self.uid && ruid != self.euid {
                return Err(Errno::EPERM);
            }
            new.uid = ruid;
        }
        if euid != KEEP {
            if !free && euid != self.uid && euid != self.euid && euid != self.suid {
                return Err(Errno::EPERM);
            }
            new.euid = euid;
        }
        if ruid != KEEP || (euid != KEEP && euid != self.uid) {
            new.suid = new.euid;
        }
        new.fsuid = new.euid;
        new.fix_setuid(self);
        Ok(new)
    }

    /// The new credentials after `setresuid`.
    ///
    /// # Errors
    ///
    /// Gives `EPERM` if the caller has no `CAP_SETUID` and an ID is not one of its three IDs.
    pub fn setresuid(&self, ruid: u32, euid: u32, suid: u32) -> Result<Self> {
        let old = [self.uid, self.euid, self.suid];
        if !self.capable(cap::SETUID)
            && [ruid, euid, suid].iter().any(|id| *id != KEEP && !old.contains(id))
        {
            return Err(Errno::EPERM);
        }
        let mut new = self.clone();
        for (to, id) in [(&mut new.uid, ruid), (&mut new.euid, euid), (&mut new.suid, suid)] {
            if id != KEEP {
                *to = id;
            }
        }
        new.fsuid = new.euid;
        new.fix_setuid(self);
        Ok(new)
    }

    /// The new credentials after `setfsuid`, or `None` if the call changes nothing. The call
    /// always gives the old file system user ID.
    pub fn setfsuid(&self, uid: u32) -> Option<Self> {
        let allowed = [self.uid, self.euid, self.suid, self.fsuid].contains(&uid)
            || self.capable(cap::SETUID);
        if uid == KEEP || !allowed || uid == self.fsuid {
            return None;
        }
        let mut new = self.clone();
        new.fsuid = uid;
        if self.securebits & secure::NO_SETUID_FIXUP == 0 {
            if self.fsuid == 0 {
                new.cap_effective &= !cap::FS_SET;
            } else if uid == 0 {
                new.cap_effective |= new.cap_permitted & cap::FS_SET;
            }
        }
        Some(new)
    }

    /// The new credentials after `setgid`.
    ///
    /// # Errors
    ///
    /// Gives `EPERM` if the caller has no `CAP_SETGID` and the ID is not its real or saved ID.
    pub fn setgid(&self, gid: u32) -> Result<Self> {
        if gid == KEEP {
            return Err(Errno::EINVAL);
        }
        let mut new = self.clone();
        if self.capable(cap::SETGID) {
            new.gid = gid;
            new.sgid = gid;
        } else if gid != self.gid && gid != self.sgid {
            return Err(Errno::EPERM);
        }
        new.egid = gid;
        new.fsgid = gid;
        Ok(new)
    }

    /// The new credentials after `setregid`.
    ///
    /// # Errors
    ///
    /// Gives `EPERM` if the caller has no `CAP_SETGID` and an ID is not allowed.
    pub fn setregid(&self, rgid: u32, egid: u32) -> Result<Self> {
        let free = self.capable(cap::SETGID);
        let mut new = self.clone();
        if rgid != KEEP {
            if !free && rgid != self.gid && rgid != self.egid {
                return Err(Errno::EPERM);
            }
            new.gid = rgid;
        }
        if egid != KEEP {
            if !free && egid != self.gid && egid != self.egid && egid != self.sgid {
                return Err(Errno::EPERM);
            }
            new.egid = egid;
        }
        if rgid != KEEP || (egid != KEEP && egid != self.gid) {
            new.sgid = new.egid;
        }
        new.fsgid = new.egid;
        Ok(new)
    }

    /// The new credentials after `setresgid`.
    ///
    /// # Errors
    ///
    /// Gives `EPERM` if the caller has no `CAP_SETGID` and an ID is not one of its three IDs.
    pub fn setresgid(&self, rgid: u32, egid: u32, sgid: u32) -> Result<Self> {
        let old = [self.gid, self.egid, self.sgid];
        if !self.capable(cap::SETGID)
            && [rgid, egid, sgid].iter().any(|id| *id != KEEP && !old.contains(id))
        {
            return Err(Errno::EPERM);
        }
        let mut new = self.clone();
        for (to, id) in [(&mut new.gid, rgid), (&mut new.egid, egid), (&mut new.sgid, sgid)] {
            if id != KEEP {
                *to = id;
            }
        }
        new.fsgid = new.egid;
        Ok(new)
    }

    /// The new credentials after `setfsgid`, or `None` if the call changes nothing.
    pub fn setfsgid(&self, gid: u32) -> Option<Self> {
        let allowed = [self.gid, self.egid, self.sgid, self.fsgid].contains(&gid)
            || self.capable(cap::SETGID);
        if gid == KEEP || !allowed || gid == self.fsgid {
            return None;
        }
        let mut new = self.clone();
        new.fsgid = gid;
        Some(new)
    }

    /// The new credentials after `setgroups`.
    ///
    /// # Errors
    ///
    /// Gives `EPERM` if the caller has no `CAP_SETGID`.
    pub fn setgroups(&self, mut groups: Vec<u32>) -> Result<Self> {
        if !self.capable(cap::SETGID) {
            return Err(Errno::EPERM);
        }
        groups.sort_unstable();
        let mut new = self.clone();
        new.groups = groups;
        Ok(new)
    }

    /// The new credentials after `capset`.
    ///
    /// # Errors
    ///
    /// Gives `EPERM` if a set grows past what the old sets allow.
    pub fn capset(&self, effective: u64, permitted: u64, inheritable: u64) -> Result<Self> {
        let (effective, permitted, inheritable) =
            (effective & cap::ALL, permitted & cap::ALL, inheritable & cap::ALL);
        let subset = |a: u64, b: u64| a & !b == 0;
        if (!self.capable(cap::SETPCAP)
            && !subset(inheritable, self.cap_inheritable | self.cap_permitted))
            || !subset(inheritable, self.cap_inheritable | self.cap_bset)
            || !subset(permitted, self.cap_permitted)
            || !subset(effective, permitted)
        {
            return Err(Errno::EPERM);
        }
        let mut new = self.clone();
        new.cap_effective = effective;
        new.cap_permitted = permitted;
        new.cap_inheritable = inheritable;
        new.cap_ambient &= permitted & inheritable;
        Ok(new)
    }

    /// The new credentials after `PR_SET_SECUREBITS`.
    ///
    /// # Errors
    ///
    /// Gives `EPERM` if the caller has no `CAP_SETPCAP`, the bits are not known, or the call
    /// changes a locked bit or clears a lock.
    pub fn set_securebits(&self, bits: u32) -> Result<Self> {
        let old = self.securebits;
        if ((old & secure::ALL_LOCKS) >> 1) & (old ^ bits) != 0
            || old & secure::ALL_LOCKS & !bits != 0
            || bits & !(secure::ALL_LOCKS | secure::ALL_BITS) != 0
            || !self.capable(cap::SETPCAP)
        {
            return Err(Errno::EPERM);
        }
        let mut new = self.clone();
        new.securebits = bits;
        Ok(new)
    }

    /// The new credentials after `PR_SET_KEEPCAPS`.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` if the value is not 0 or 1, or `EPERM` if the bit is locked.
    pub fn set_keepcaps(&self, on: u64) -> Result<Self> {
        if on > 1 {
            return Err(Errno::EINVAL);
        }
        if self.securebits & secure::KEEP_CAPS_LOCKED != 0 {
            return Err(Errno::EPERM);
        }
        let mut new = self.clone();
        new.securebits &= !secure::KEEP_CAPS;
        if on == 1 {
            new.securebits |= secure::KEEP_CAPS;
        }
        Ok(new)
    }

    /// The new credentials after `PR_CAPBSET_DROP`.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` for an unknown capability, or `EPERM` without `CAP_SETPCAP`.
    pub fn drop_bset(&self, c: u64) -> Result<Self> {
        let c = valid_cap(c)?;
        if !self.capable(cap::SETPCAP) {
            return Err(Errno::EPERM);
        }
        let mut new = self.clone();
        new.cap_bset &= !cap::bit(c);
        Ok(new)
    }

    /// The new credentials after `PR_CAP_AMBIENT_RAISE`, or after `PR_CAP_AMBIENT_LOWER` if
    /// `raise` is false.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` for an unknown capability, or `EPERM` if the capability is not permitted
    /// and inheritable, or the securebits forbid a raise.
    pub fn set_ambient(&self, c: u64, raise: bool) -> Result<Self> {
        let c = valid_cap(c)?;
        let bit = cap::bit(c);
        let mut new = self.clone();
        if raise {
            if self.cap_permitted & bit == 0
                || self.cap_inheritable & bit == 0
                || self.securebits & secure::NO_CAP_AMBIENT_RAISE != 0
            {
                return Err(Errno::EPERM);
            }
            new.cap_ambient |= bit;
        } else {
            new.cap_ambient &= !bit;
        }
        Ok(new)
    }

    /// The new credentials after an `execve` of the file, and if the program gets the secure mode
    /// of `AT_SECURE`. rukernel has no file capabilities, so this is the transition of Linux for a
    /// file without the `security.capability` attribute.
    pub fn exec(&self, file: ExecFile) -> (Self, bool) {
        let mut new = self.clone();
        if !file.no_setid && file.mode & 0o4000 != 0 {
            new.euid = file.uid;
        }
        if !file.no_setid && file.mode & 0o2010 == 0o2010 {
            new.egid = file.gid;
        }
        let setid = new.euid != self.uid || new.egid != self.gid;
        if setid {
            new.cap_ambient = 0;
        }
        let mut permitted = 0;
        let mut raise = false;
        if self.securebits & secure::NOROOT == 0 && (new.euid == 0 || new.uid == 0) {
            permitted = self.cap_bset | self.cap_inheritable;
            raise = new.euid == 0;
        }
        new.cap_permitted = permitted | new.cap_ambient;
        new.cap_effective = if raise { new.cap_permitted } else { new.cap_ambient };
        new.suid = new.euid;
        new.fsuid = new.euid;
        new.sgid = new.egid;
        new.fsgid = new.egid;
        new.securebits &= !secure::KEEP_CAPS;
        let grew = new.cap_permitted & !new.cap_ambient != 0;
        let secure = setid || (new.uid != 0 && (raise || grew));
        (new, secure)
    }

    /// Changes the capabilities after a change of the user IDs, as `cap_emulate_setxuid` of
    /// Linux: a process that leaves root loses its capabilities.
    fn fix_setuid(&mut self, old: &Self) {
        if self.securebits & secure::NO_SETUID_FIXUP != 0 {
            return;
        }
        let was_root = old.uid == 0 || old.euid == 0 || old.suid == 0;
        let is_root = self.uid == 0 || self.euid == 0 || self.suid == 0;
        if was_root && !is_root {
            if self.securebits & secure::KEEP_CAPS == 0 {
                self.cap_permitted = 0;
                self.cap_effective = 0;
            }
            self.cap_ambient = 0;
        }
        if old.euid == 0 && self.euid != 0 {
            self.cap_effective = 0;
        }
        if old.euid != 0 && self.euid == 0 {
            self.cap_effective = self.cap_permitted;
        }
    }
}

/// Checks the number of a capability.
///
/// # Errors
///
/// Gives `EINVAL` if the capability is not known.
pub fn valid_cap(c: u64) -> Result<u32> {
    if c > u64::from(cap::LAST) {
        return Err(Errno::EINVAL);
    }
    Ok(c as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    impl Cred {
        fn setgroups_unchecked(&self, groups: &[u32]) -> Self {
            let mut c = self.clone();
            c.groups = groups.to_vec();
            c
        }
    }

    fn user(id: u32) -> Cred {
        Cred::root().setresgid(id, id, id).unwrap().setresuid(id, id, id).unwrap()
    }

    #[test]
    fn root_that_becomes_a_user_loses_its_capabilities() {
        let c = Cred::root().setuid(1000).unwrap();
        assert_eq!((c.uid, c.euid, c.suid, c.fsuid), (1000, 1000, 1000, 1000));
        assert_eq!((c.cap_permitted, c.cap_effective), (0, 0));
        assert_eq!(c.setuid(0), Err(Errno::EPERM));
    }

    #[test]
    fn keepcaps_keeps_the_permitted_set() {
        let c = Cred::root().set_keepcaps(1).unwrap().setresuid(1000, 1000, 1000).unwrap();
        assert_eq!(c.cap_permitted, cap::ALL);
        assert_eq!(c.cap_effective, 0);
        assert_eq!(Cred::root().set_keepcaps(2), Err(Errno::EINVAL));
    }

    #[test]
    fn a_saved_id_lets_the_effective_id_come_back() {
        let c = Cred::root().setresuid(1000, 2000, 0).unwrap();
        assert_eq!(c.cap_effective, 0);
        assert_eq!(c.cap_permitted, cap::ALL);
        let back = c.setresuid(KEEP, 0, KEEP).unwrap();
        assert_eq!(back.euid, 0);
        assert_eq!(back.cap_effective, cap::ALL);
        let u = user(1000);
        assert_eq!(u.setresuid(KEEP, 0, KEEP), Err(Errno::EPERM));
        assert!(u.setresuid(1000, KEEP, 1000).is_ok());
    }

    #[test]
    fn setreuid_sets_the_saved_id() {
        let c = Cred::root().setreuid(KEEP, 1000).unwrap();
        assert_eq!((c.uid, c.euid, c.suid), (0, 1000, 1000));
        let c = Cred::root().setreuid(KEEP, 0).unwrap();
        assert_eq!(c.suid, 0);
        let u = user(1000);
        assert_eq!(u.setreuid(5, KEEP), Err(Errno::EPERM));
    }

    #[test]
    fn setfsuid_moves_the_file_capabilities() {
        let c = Cred::root().setfsuid(1000).unwrap();
        assert_eq!(c.fsuid, 1000);
        assert_eq!(c.cap_effective, cap::ALL & !cap::FS_SET);
        let back = c.setfsuid(0).unwrap();
        assert_eq!(back.cap_effective, cap::ALL);
        assert!(user(1000).setfsuid(5).is_none());
        assert!(user(1000).setfsuid(1000).is_none());
    }

    #[test]
    fn a_user_cannot_set_the_groups() {
        let c = Cred::root().setgroups(vec![30, 10, 20]).unwrap();
        assert_eq!(c.groups, [10, 20, 30]);
        assert!(c.in_group(20));
        assert!(!c.in_group(25));
        assert_eq!(user(1000).setgroups(vec![]), Err(Errno::EPERM));
    }

    #[test]
    fn capset_only_drops() {
        let c = Cred::root()
            .capset(cap::bit(cap::CHOWN), cap::bit(cap::CHOWN) | cap::bit(cap::KILL), 0)
            .unwrap();
        assert!(c.capable(cap::CHOWN));
        assert!(!c.capable(cap::KILL));
        assert_eq!(c.capset(cap::bit(cap::SETUID), cap::bit(cap::SETUID), 0), Err(Errno::EPERM));
        assert_eq!(c.capset(cap::bit(cap::KILL), cap::bit(cap::CHOWN), 0), Err(Errno::EPERM));
    }

    #[test]
    fn an_ambient_capability_needs_permitted_and_inheritable() {
        let c = Cred::root();
        assert_eq!(c.set_ambient(u64::from(cap::KILL), true), Err(Errno::EPERM));
        let c = c.capset(cap::ALL, cap::ALL, cap::bit(cap::KILL)).unwrap();
        let c = c.set_ambient(u64::from(cap::KILL), true).unwrap();
        assert_eq!(c.cap_ambient, cap::bit(cap::KILL));
        let c = c.set_keepcaps(1).unwrap().setresuid(1000, 1000, 1000).unwrap();
        assert_eq!(c.cap_ambient, 0);
        assert_eq!(c.set_ambient(u64::from(cap::LAST + 1), true), Err(Errno::EINVAL));
    }

    #[test]
    fn locked_securebits_do_not_change() {
        let c = Cred::root().set_securebits(secure::KEEP_CAPS | secure::KEEP_CAPS_LOCKED).unwrap();
        assert_eq!(c.set_securebits(secure::KEEP_CAPS_LOCKED), Err(Errno::EPERM));
        assert_eq!(c.set_securebits(secure::KEEP_CAPS), Err(Errno::EPERM));
        assert_eq!(c.set_keepcaps(0), Err(Errno::EPERM));
        assert_eq!(Cred::root().set_securebits(1 << 12), Err(Errno::EPERM));
    }

    #[test]
    fn exec_of_a_setuid_file_changes_the_effective_id() {
        let file = ExecFile { mode: 0o4755, uid: 0, gid: 0, no_setid: false };
        let (c, secure) = user(1000).exec(file);
        assert_eq!((c.uid, c.euid, c.suid, c.fsuid), (1000, 0, 0, 0));
        assert_eq!(c.cap_effective, cap::ALL);
        assert!(secure);
        let (c, secure) = user(1000).exec(ExecFile { no_setid: true, ..file });
        assert_eq!((c.euid, c.cap_permitted), (1000, 0));
        assert!(!secure);
    }

    #[test]
    fn exec_by_root_keeps_all_the_capabilities() {
        let plain = ExecFile { mode: 0o755, uid: 1000, gid: 1000, no_setid: false };
        let (c, secure) = Cred::root().exec(plain);
        assert_eq!(c, Cred::root());
        assert!(!secure);
        let dropped = Cred::root().drop_bset(u64::from(cap::SYS_ADMIN)).unwrap();
        let (c, _) = dropped.exec(plain);
        assert!(!c.capable(cap::SYS_ADMIN));
        let (c, _) = Cred::root().setresuid(0, 1000, 1000).unwrap().exec(plain);
        assert_eq!(c.cap_permitted, cap::ALL);
        assert_eq!(c.cap_effective, 0);
    }

    fn meta(kind: u32, perm: u32, uid: u32, gid: u32) -> Metadata {
        Metadata { mode: kind | perm, uid, gid, ..Metadata::default() }
    }

    #[test]
    fn the_class_of_the_caller_picks_the_bits() {
        let u = user(1000);
        let file = meta(mode::S_IFREG, 0o604, 1000, 50);
        assert_eq!(u.permission(&file, may::READ | may::WRITE), Ok(()));
        assert_eq!(u.permission(&file, may::EXEC), Err(Errno::EACCES));
        // The owner bits apply to the owner, even if the other bits allow more.
        let file = meta(mode::S_IFREG, 0o066, 1000, 50);
        assert_eq!(u.permission(&file, may::READ), Err(Errno::EACCES));
        let g = u.setgroups_unchecked(&[50]);
        let file = meta(mode::S_IFREG, 0o040, 2000, 50);
        assert_eq!(g.permission(&file, may::READ), Ok(()));
        assert_eq!(u.permission(&file, may::READ), Err(Errno::EACCES));
    }

    #[test]
    fn root_skips_the_bits_but_not_the_execute_bit() {
        let root = Cred::root();
        assert_eq!(root.permission(&meta(mode::S_IFREG, 0, 5, 5), may::READ | may::WRITE), Ok(()));
        assert_eq!(
            root.permission(&meta(mode::S_IFREG, 0o600, 5, 5), may::EXEC),
            Err(Errno::EACCES)
        );
        assert_eq!(root.permission(&meta(mode::S_IFREG, 0o010, 5, 5), may::EXEC), Ok(()));
        assert_eq!(root.permission(&meta(mode::S_IFDIR, 0, 5, 5), may::EXEC | may::WRITE), Ok(()));
        let search = Cred::root().capset(cap::bit(cap::DAC_READ_SEARCH), cap::ALL, 0).unwrap();
        assert_eq!(search.permission(&meta(mode::S_IFDIR, 0, 5, 5), may::EXEC | may::READ), Ok(()));
        assert_eq!(
            search.permission(&meta(mode::S_IFDIR, 0, 5, 5), may::WRITE),
            Err(Errno::EACCES)
        );
        assert_eq!(search.permission(&meta(mode::S_IFREG, 0, 5, 5), may::READ), Ok(()));
    }

    #[test]
    fn the_sticky_bit_protects_the_files_of_others() {
        let u = user(1000);
        let tmp = meta(mode::S_IFDIR, 0o1777, 0, 0);
        assert_eq!(u.check_sticky(&tmp, &meta(mode::S_IFREG, 0o644, 2000, 0)), Err(Errno::EPERM));
        assert_eq!(u.check_sticky(&tmp, &meta(mode::S_IFREG, 0o644, 1000, 0)), Ok(()));
        assert_eq!(Cred::root().check_sticky(&tmp, &meta(mode::S_IFREG, 0o644, 2000, 0)), Ok(()));
    }

    #[test]
    fn a_setgid_directory_gives_its_group() {
        let u = user(1000);
        let dir = meta(mode::S_IFDIR, 0o2775, 0, 50);
        assert_eq!(u.new_owner(&dir, FileType::Directory, 0o755), (1000, 50, 0o2755));
        assert_eq!(u.new_owner(&dir, FileType::Regular, 0o2755), (1000, 50, 0o755));
        assert_eq!(Cred::root().new_owner(&dir, FileType::Regular, 0o2755), (0, 50, 0o2755));
        let plain = meta(mode::S_IFDIR, 0o755, 0, 50);
        assert_eq!(u.new_owner(&plain, FileType::Regular, 0o644), (1000, 1000, 0o644));
        assert_eq!(u.new_owner(&plain, FileType::Regular, 0o2744), (1000, 1000, 0o2744));
        assert_eq!(u.new_owner(&plain, FileType::Regular, 0o2775), (1000, 1000, 0o775));
    }

    #[test]
    fn access_uses_the_real_ids() {
        let c = Cred::root().setresuid(1000, 0, 0).unwrap().for_access();
        assert_eq!((c.fsuid, c.cap_effective), (1000, 0));
        let c = Cred::root().setresuid(0, 1000, 1000).unwrap().for_access();
        assert_eq!((c.fsuid, c.cap_effective), (0, cap::ALL));
    }

    #[test]
    fn setgid_needs_group_execute() {
        let (c, _) = user(1000).exec(ExecFile { mode: 0o2755, uid: 0, gid: 50, no_setid: false });
        assert_eq!((c.egid, c.sgid), (50, 50));
        let (c, _) = user(1000).exec(ExecFile { mode: 0o2745, uid: 0, gid: 50, no_setid: false });
        assert_eq!(c.egid, 1000);
    }
}

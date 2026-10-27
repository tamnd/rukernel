//! The credentials of a process: the user and group IDs, the supplementary groups, and the
//! capability sets.
//!
//! The rules of the `set*id` calls, of `capset` and of an `execve` are those of `kernel/sys.c` and
//! `security/commoncap.c` of Linux. Linux keeps the credentials for each thread, and the C library
//! changes them in all the threads of a process. rukernel keeps them for each process, which gives
//! the same result for a program that uses the C library.

use crate::acl::{self, Acl};
use crate::inode::{FileType, Inode, Metadata, Result, SetAttr, mode};
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::Once;

/// The `fs.protected_*` sysctls of Linux, which guard the files in sticky directories that other
/// users can write. Each one is 0, the default of Linux, until a write to `/proc/sys/fs` changes
/// it.
pub mod protected {
    use core::sync::atomic::{AtomicU32, Ordering};

    /// `fs.protected_symlinks`: 0 or 1.
    pub static SYMLINKS: AtomicU32 = AtomicU32::new(0);
    /// `fs.protected_hardlinks`: 0 or 1.
    pub static HARDLINKS: AtomicU32 = AtomicU32::new(0);
    /// `fs.protected_regular`: 0, 1 or 2.
    pub static REGULAR: AtomicU32 = AtomicU32::new(0);
    /// `fs.protected_fifos`: 0, 1 or 2.
    pub static FIFOS: AtomicU32 = AtomicU32::new(0);

    /// The value of a sysctl.
    pub fn get(v: &AtomicU32) -> u32 {
        v.load(Ordering::Relaxed)
    }
}

static CURRENT: Once<fn() -> Option<Arc<Cred>>> = Once::new();

/// Gives the VFS the credentials of the process that runs now, for the checks of a write that
/// has no other way to know them. Only the first call has an effect.
pub fn set_current(f: fn() -> Option<Arc<Cred>>) {
    CURRENT.call_once(|| f);
}

/// The credentials of the process that runs now. Before [`set_current`], and in the kernel
/// itself, they are those of root.
pub fn current() -> Arc<Cred> {
    CURRENT.get().and_then(|f| f()).unwrap_or_else(|| Arc::new(Cred::root()))
}

/// The bits that a write or a change of the owner clears from the mode of a file, as
/// `setattr_should_drop_suidgid` of Linux: the set-user-ID bit, and the set-group-ID bit if the
/// group can run the file.
fn kill_bits(perm: u32) -> u32 {
    let mut kill = perm & mode::S_ISUID;
    if perm & (mode::S_ISGID | 0o010) == mode::S_ISGID | 0o010 {
        kill |= mode::S_ISGID;
    }
    kill
}

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
    /// Bind a socket to a port below 1024.
    pub const NET_BIND_SERVICE: u32 = 10;
    /// Use raw sockets.
    pub const NET_RAW: u32 = 13;
    /// Lock the shared memory segments of other users.
    pub const IPC_LOCK: u32 = 14;
    /// Skip the permission checks of the System V IPC objects.
    pub const IPC_OWNER: u32 = 15;
    /// Use `chroot`.
    pub const SYS_CHROOT: u32 = 18;
    /// Trace each process.
    pub const SYS_PTRACE: u32 = 19;
    /// Do the many administration operations.
    pub const SYS_ADMIN: u32 = 21;
    /// Lower the nice value and change the priority of each process.
    pub const SYS_NICE: u32 = 23;
    /// Go past the resource limits.
    pub const SYS_RESOURCE: u32 = 24;
    /// Make a device file.
    pub const MKNOD: u32 = 27;
    /// Set the capabilities of a file.
    pub const SETFCAP: u32 = 31;
    /// Skip the mandatory access control.
    pub const MAC_OVERRIDE: u32 = 32;
    /// Read and clear the kernel log.
    pub const SYSLOG: u32 = 34;
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

/// The owner, the creator and the mode of a System V IPC object, as `struct kern_ipc_perm` of
/// Linux.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpcOwner {
    /// The user ID of the owner.
    pub uid: u32,
    /// The group ID of the owner.
    pub gid: u32,
    /// The user ID of the creator.
    pub cuid: u32,
    /// The group ID of the creator.
    pub cgid: u32,
    /// The permission bits.
    pub mode: u32,
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
    /// has no_new_privs, or a tracer without `CAP_SYS_PTRACE` traces it.
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
    /// `CAP_DAC_READ_SEARCH` skip the check. This check does not read the ACL of the file. Use
    /// [`Cred::inode_permission`] for a file that can have one.
    ///
    /// # Errors
    ///
    /// Gives `EACCES` if the access is not allowed.
    pub fn permission(&self, meta: &Metadata, mask: u32) -> Result<()> {
        self.check(meta, mask, || None)
    }

    /// Checks the access `mask` to `inode`, as [`Cred::permission`], with the access ACL of the
    /// inode if it has one.
    ///
    /// # Errors
    ///
    /// Gives `EACCES` if the access is not allowed, and `EIO` for a damaged ACL.
    pub fn inode_permission(&self, inode: &dyn Inode, mask: u32) -> Result<()> {
        self.check(&inode.metadata(), mask, || acl::access(inode))
    }

    /// The check of [`Cred::permission`]. `acl` gives the access ACL. The ACL applies only to
    /// a process that does not own the file, and only if the mode has group bits, as
    /// `acl_permission_check` of Linux.
    pub(crate) fn check(
        &self,
        meta: &Metadata,
        mask: u32,
        acl: impl FnOnce() -> Option<Acl>,
    ) -> Result<()> {
        let mask = mask & (may::READ | may::WRITE | may::EXEC);
        let allowed = if self.fsuid == meta.uid {
            (meta.mode >> 6) & mask == mask
        } else if let Some(acl) = (meta.mode & 0o070 != 0).then(acl).flatten() {
            acl.permits(self, meta, mask)?
        } else if self.in_group(meta.gid) {
            (meta.mode >> 3) & mask == mask
        } else {
            meta.mode & mask == mask
        };
        if allowed {
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

    /// Checks that the walk can follow the symbolic link `link` in the directory `dir`, as
    /// `may_follow_link` of Linux. With `level` 1 (`fs.protected_symlinks`), a link in a sticky
    /// directory that all can write is followed only by the owner of the link, or if the owner
    /// of the directory owns the link.
    ///
    /// # Errors
    ///
    /// Gives `EACCES` if the protection forbids the follow.
    pub fn may_follow_link(&self, level: u32, dir: &Metadata, link: &Metadata) -> Result<()> {
        const STICKY_ALL: u32 = mode::S_ISVTX | 0o002;
        if level == 0
            || self.fsuid == link.uid
            || dir.mode & STICKY_ALL != STICKY_ALL
            || dir.uid == link.uid
        {
            return Ok(());
        }
        Err(Errno::EACCES)
    }

    /// Checks that the process can make a hard link to `inode`, as `may_linkat` of Linux. With
    /// `level` 1 (`fs.protected_hardlinks`), the process must own the file, or the file must be
    /// a regular file that is not set-user-ID, not set-group-ID with the group execute bit, and
    /// that the process can read and write.
    ///
    /// # Errors
    ///
    /// Gives `EPERM` if the protection forbids the link.
    pub fn may_link(&self, level: u32, inode: &dyn Inode) -> Result<()> {
        let meta = inode.metadata();
        if level == 0 || self.owns(&meta) {
            return Ok(());
        }
        let safe = meta.file_type() == Some(FileType::Regular)
            && meta.mode & mode::S_ISUID == 0
            && meta.mode & (mode::S_ISGID | 0o010) != (mode::S_ISGID | 0o010)
            && self.inode_permission(inode, may::READ | may::WRITE).is_ok();
        if safe { Ok(()) } else { Err(Errno::EPERM) }
    }

    /// Checks an `open` with `O_CREAT` of the file `child` that is already in the directory
    /// `dir`, as `may_create_in_sticky` of Linux. `regular` and `fifos` are the levels of
    /// `fs.protected_regular` and `fs.protected_fifos`. In a sticky directory, a file of another
    /// user that the owner of the directory does not own is refused at level 1 if all can write
    /// the directory, and at level 2 also if the group can write it.
    ///
    /// # Errors
    ///
    /// Gives `EACCES` if the protection forbids the open.
    pub fn may_create_in_sticky(
        &self,
        regular: u32,
        fifos: u32,
        dir: &Metadata,
        child: &Metadata,
    ) -> Result<()> {
        let kind = child.file_type();
        if dir.mode & mode::S_ISVTX == 0
            || (kind == Some(FileType::Regular) && regular == 0)
            || (kind == Some(FileType::Fifo) && fifos == 0)
            || child.uid == dir.uid
            || child.uid == self.fsuid
        {
            return Ok(());
        }
        if dir.mode & 0o002 != 0 {
            return Err(Errno::EACCES);
        }
        if dir.mode & 0o020 != 0
            && ((kind == Some(FileType::Fifo) && fifos >= 2)
                || (kind == Some(FileType::Regular) && regular >= 2))
        {
            return Err(Errno::EACCES);
        }
        Ok(())
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
        } else {
            perm = self.strip_sgid(dir, kind, perm);
        }
        (self.fsuid, if sgid_dir { dir.gid } else { self.fsgid }, perm)
    }

    /// Removes the set-group-ID bit from the mode `perm` of a new file in the directory `dir`, as
    /// `mode_strip_sgid` of Linux. The bit stays on a directory, on a file that is not executable
    /// by the group, in a directory without the set-group-ID bit, and for a process that is in
    /// the group of `dir` or has `CAP_FSETID`. In a directory without the bit, the file gets the
    /// file system group of the process, thus the bit is safe. Use this before the umask, because
    /// the umask can remove the execute bit of the group.
    pub fn strip_sgid(&self, dir: &Metadata, kind: FileType, perm: u32) -> u32 {
        if kind != FileType::Directory
            && dir.mode & mode::S_ISGID != 0
            && perm & (mode::S_ISGID | 0o010) == mode::S_ISGID | 0o010
            && !self.in_group(dir.gid)
            && !self.capable(cap::FSETID)
        {
            perm & !mode::S_ISGID
        } else {
            perm
        }
    }

    /// Checks a change of the attributes `attr` of a file with the attributes `meta`, as
    /// `setattr_prepare` of Linux. Only the owner or a process with `CAP_FOWNER` can change the
    /// mode or set a time that is not now. Only a process with `CAP_CHOWN` can give the file to
    /// another user, and the owner can only give it to a group that it is in. A new mode loses
    /// the set-group-ID bit if the process is not in the group of the file and has no
    /// `CAP_FSETID`.
    ///
    /// # Errors
    ///
    /// Gives `EPERM` if the process cannot make the change.
    pub fn setattr_prepare(&self, meta: &Metadata, attr: &mut SetAttr) -> Result<()> {
        let chown = self.capable(cap::CHOWN);
        if let Some(uid) = attr.uid
            && !(self.fsuid == meta.uid && uid == meta.uid)
            && !chown
        {
            return Err(Errno::EPERM);
        }
        if let Some(gid) = attr.gid
            && !(self.fsuid == meta.uid && (gid == meta.gid || self.in_group(gid)))
            && !chown
        {
            return Err(Errno::EPERM);
        }
        if let Some(perm) = attr.mode {
            if !self.owns(meta) {
                return Err(Errno::EPERM);
            }
            if !self.in_group(attr.gid.unwrap_or(meta.gid)) && !self.capable(cap::FSETID) {
                attr.mode = Some(perm & !mode::S_ISGID);
            }
        }
        if attr.explicit_times && !self.owns(meta) {
            return Err(Errno::EPERM);
        }
        Ok(())
    }

    /// Adds to `attr` the change of the mode of a `chown` of a file with the attributes `meta`,
    /// as `chown_common` of Linux. A file that is not a directory loses the set-user-ID bit, and
    /// the set-group-ID bit if the group can run it or the process may not keep it. Root loses
    /// them too.
    pub fn chown_kill(&self, meta: &Metadata, attr: &mut SetAttr) {
        if meta.is_dir() {
            return;
        }
        let perm = meta.mode & 0o7777;
        let mut kill = kill_bits(perm);
        if perm & mode::S_ISGID != 0 && !self.in_group(meta.gid) && !self.capable(cap::FSETID) {
            kill |= mode::S_ISGID;
        }
        if kill != 0 {
            attr.mode = Some(perm & !kill);
        }
    }

    /// The new mode of a regular file with the attributes `meta` after a write or a truncate by
    /// this process, as `file_remove_privs` of Linux, or `None` if the mode does not change. The
    /// set-group-ID bit goes if the group can run the file or the process is not in the group. A
    /// process with `CAP_FSETID` keeps the bits.
    pub fn write_kill(&self, meta: &Metadata) -> Option<u32> {
        let perm = meta.mode & 0o7777;
        let mut kill = kill_bits(perm);
        if perm & mode::S_ISGID != 0 && !self.in_group(meta.gid) {
            kill |= mode::S_ISGID;
        }
        (kill != 0 && meta.file_type() == Some(FileType::Regular) && !self.capable(cap::FSETID))
            .then_some(perm & !kill)
    }

    /// Checks the access to the extended attribute `name` of a file with the attributes `meta`,
    /// as `xattr_permission` of Linux. A `trusted.` attribute needs `CAP_SYS_ADMIN`. A `user.`
    /// attribute needs the read or the write permission on the file, and only a regular file, a
    /// directory and a socket have them. In a sticky directory, only the owner can change one.
    /// The VFS does not check the `security.` and `system.` attributes.
    ///
    /// # Errors
    ///
    /// Gives `EPERM` for a change and `ENODATA` for a read that the rules refuse, or `EACCES`.
    pub fn xattr_permission(&self, inode: &dyn Inode, name: &[u8], write: bool) -> Result<()> {
        self.xattr_check(&inode.metadata(), name, write, || acl::access(inode))
    }

    /// The check of [`Cred::xattr_permission`]. `acl` gives the access ACL of the file.
    fn xattr_check(
        &self,
        meta: &Metadata,
        name: &[u8],
        write: bool,
        acl: impl FnOnce() -> Option<Acl>,
    ) -> Result<()> {
        let refused = if write { Errno::EPERM } else { Errno::ENODATA };
        if name.starts_with(b"security.") || name.starts_with(b"system.") {
            return Ok(());
        }
        if name.starts_with(b"trusted.") {
            return if self.capable(cap::SYS_ADMIN) { Ok(()) } else { Err(refused) };
        }
        if name.starts_with(b"user.") {
            let kind = meta.file_type();
            if !matches!(kind, Some(FileType::Regular | FileType::Directory | FileType::Socket)) {
                return Err(refused);
            }
            if kind == Some(FileType::Directory)
                && meta.mode & mode::S_ISVTX != 0
                && write
                && !self.owns(meta)
            {
                return Err(Errno::EPERM);
            }
        }
        self.check(meta, if write { may::WRITE } else { may::READ }, acl)
    }

    /// Checks the access `flag` to a System V IPC object, as `ipcperms` of Linux. `flag` has the
    /// permission bits of the access, for example 0o444 for a read. The owner bits apply if the
    /// effective user ID is the owner or the creator, the group bits if the process is in the
    /// group of the owner or of the creator, and the other bits to the others.
    /// `CAP_IPC_OWNER` skips the check.
    ///
    /// # Errors
    ///
    /// Gives `EACCES` if the access is not allowed.
    pub fn ipc_permission(&self, ipc: &IpcOwner, flag: u32) -> Result<()> {
        let requested = (flag >> 6) | (flag >> 3) | flag;
        let granted = if self.euid == ipc.cuid || self.euid == ipc.uid {
            ipc.mode >> 6
        } else if self.in_group(ipc.cgid) || self.in_group(ipc.gid) {
            ipc.mode >> 3
        } else {
            ipc.mode
        };
        if requested & !granted & 0o7 != 0 && !self.capable(cap::IPC_OWNER) {
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    /// Tells if the process can change or remove a System V IPC object with `IPC_SET` or
    /// `IPC_RMID`, as `ipcctl_obtain_check` of Linux: its effective user ID is the owner or the
    /// creator, or it has `CAP_SYS_ADMIN`.
    pub fn ipc_owns(&self, ipc: &IpcOwner) -> bool {
        self.euid == ipc.cuid || self.euid == ipc.uid || self.capable(cap::SYS_ADMIN)
    }

    /// Tells if the process can send a signal to a process with the credentials `target`, as
    /// `kill_ok_by_cred` of Linux: its real or effective user ID is the real or saved user ID of
    /// the target, or it has `CAP_KILL`.
    pub fn may_kill(&self, target: &Self) -> bool {
        self.euid == target.suid
            || self.euid == target.uid
            || self.uid == target.suid
            || self.uid == target.uid
            || self.capable(cap::KILL)
    }

    /// Tells if the real user and group IDs of the process are all the user and group IDs of
    /// the target, as the checks of `ptrace` and `prlimit` of Linux want.
    pub fn same_ids(&self, target: &Self) -> bool {
        [target.uid, target.euid, target.suid].iter().all(|&id| id == self.uid)
            && [target.gid, target.egid, target.sgid].iter().all(|&id| id == self.gid)
    }

    /// Tells if the process can trace a process with the credentials `target`, as
    /// `__ptrace_may_access` and `cap_ptrace_access_check` of Linux: it has the same IDs and at
    /// least the permitted capabilities of the target, or it has `CAP_SYS_PTRACE`.
    pub fn may_ptrace(&self, target: &Self) -> bool {
        self.capable(cap::SYS_PTRACE)
            || (self.same_ids(target) && target.cap_permitted & !self.cap_permitted == 0)
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

    /// The new credentials after `setresuid`. A call that changes no ID keeps the file system
    /// user ID, as `__sys_setresuid` of Linux.
    ///
    /// # Errors
    ///
    /// Gives `EPERM` if the caller has no `CAP_SETUID` and an ID is not one of its three IDs.
    pub fn setresuid(&self, ruid: u32, euid: u32, suid: u32) -> Result<Self> {
        if (ruid == KEEP || ruid == self.uid)
            && (euid == KEEP || (euid == self.euid && euid == self.fsuid))
            && (suid == KEEP || suid == self.suid)
        {
            return Ok(self.clone());
        }
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

    /// The new credentials after `setresgid`. A call that changes no ID keeps the file system
    /// group ID, as `__sys_setresgid` of Linux.
    ///
    /// # Errors
    ///
    /// Gives `EPERM` if the caller has no `CAP_SETGID` and an ID is not one of its three IDs.
    pub fn setresgid(&self, rgid: u32, egid: u32, sgid: u32) -> Result<Self> {
        if (rgid == KEEP || rgid == self.gid)
            && (egid == KEEP || (egid == self.egid && egid == self.fsgid))
            && (sgid == KEEP || sgid == self.sgid)
        {
            return Ok(self.clone());
        }
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
    /// Gives `EPERM` without `CAP_SETPCAP`, or `EINVAL` for an unknown capability. Linux does
    /// the checks in this order.
    pub fn drop_bset(&self, c: u64) -> Result<Self> {
        if !self.capable(cap::SETPCAP) {
            return Err(Errno::EPERM);
        }
        let c = valid_cap(c)?;
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
    fn the_group_calls_follow_the_user_calls() {
        let c = Cred::root().setgid(50).unwrap();
        assert_eq!((c.gid, c.egid, c.sgid, c.fsgid), (50, 50, 50, 50));
        assert_eq!(user(1000).setresgid(KEEP, KEEP, 60), Err(Errno::EPERM));
        let c = Cred::root().setresgid(10, 20, 30).unwrap().setresuid(1000, 1000, 1000).unwrap();
        assert_eq!(c.setgid(30).map(|n| (n.gid, n.egid, n.sgid, n.fsgid)), Ok((10, 30, 30, 30)));
        assert_eq!(c.setgid(40), Err(Errno::EPERM));
        assert_eq!(c.setregid(KEEP, 30).map(|n| (n.gid, n.egid, n.sgid)), Ok((10, 30, 30)));
        assert_eq!(c.setregid(30, KEEP), Err(Errno::EPERM));
        assert_eq!(c.setregid(20, KEEP).map(|n| (n.gid, n.egid, n.sgid)), Ok((20, 20, 20)));
        assert_eq!(c.setresgid(30, 10, 20).map(|n| (n.gid, n.egid, n.sgid)), Ok((30, 10, 20)));
        assert_eq!(c.setresgid(KEEP, 40, KEEP), Err(Errno::EPERM));
        assert_eq!(c.setfsgid(30).map(|n| n.fsgid), Some(30));
        assert!(c.setfsgid(40).is_none());
        assert_eq!(c.setgid(KEEP), Err(Errno::EINVAL));
        assert_eq!(c.setuid(KEEP), Err(Errno::EINVAL));
    }

    #[test]
    fn a_setresuid_that_changes_nothing_keeps_the_file_system_id() {
        let c = Cred::root().setresuid(1000, 1000, 0).unwrap().setfsuid(0).unwrap();
        assert_eq!((c.euid, c.fsuid), (1000, 0));
        assert_eq!(c.setresuid(KEEP, KEEP, KEEP).map(|n| n.fsuid), Ok(0));
        assert_eq!(c.setresuid(1000, KEEP, 0).map(|n| n.fsuid), Ok(0));
        assert_eq!(c.setresuid(KEEP, 1000, KEEP).map(|n| n.fsuid), Ok(1000));
        let g = Cred::root().setresgid(10, 10, 10).unwrap().setfsgid(0).unwrap();
        assert_eq!(g.setresgid(KEEP, KEEP, KEEP).map(|n| n.fsgid), Ok(0));
        assert_eq!(g.setresgid(KEEP, 10, KEEP).map(|n| n.fsgid), Ok(10));
    }

    #[test]
    fn the_bounding_set_drop_checks_the_capability_first() {
        assert_eq!(user(1000).drop_bset(u64::from(cap::LAST + 1)), Err(Errno::EPERM));
        assert_eq!(Cred::root().drop_bset(u64::from(cap::LAST + 1)), Err(Errno::EINVAL));
        let c = Cred::root().drop_bset(u64::from(cap::SYS_ADMIN)).unwrap();
        assert_eq!(c.cap_bset, cap::ALL & !cap::bit(cap::SYS_ADMIN));
        let file = ExecFile { mode: 0o755, uid: 0, gid: 0, no_setid: false };
        assert!(!c.exec(file).0.capable(cap::SYS_ADMIN));
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
    fn exec_keeps_the_ambient_set_and_applies_the_setgid_bit() {
        let kill = cap::bit(cap::KILL);
        let c = Cred::root().capset(cap::ALL, cap::ALL, kill).unwrap();
        let c = c.set_ambient(u64::from(cap::KILL), true).unwrap();
        let c = c.set_keepcaps(1).unwrap().setresuid(1000, 1000, 1000).unwrap();
        let c = c.set_ambient(u64::from(cap::KILL), true).unwrap();
        let plain = ExecFile { mode: 0o755, uid: 0, gid: 0, no_setid: false };
        let (n, secure) = c.exec(plain);
        assert_eq!((n.cap_permitted, n.cap_effective, n.cap_ambient), (kill, kill, kill));
        assert_eq!(n.securebits & secure::KEEP_CAPS, 0);
        assert!(!secure);
        let (n, secure) = c.exec(ExecFile { mode: 0o2755, gid: 50, ..plain });
        assert_eq!((n.gid, n.egid, n.sgid, n.fsgid), (0, 50, 50, 50));
        assert_eq!((n.cap_permitted, n.cap_ambient), (0, 0));
        assert!(secure);
        let (n, _) = c.exec(ExecFile { mode: 0o2745, gid: 50, ..plain });
        assert_eq!(n.egid, 0);
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
    fn protected_symlinks_refuses_a_link_of_another_user_in_a_sticky_directory() {
        let u = user(1000);
        let tmp = meta(mode::S_IFDIR, mode::S_ISVTX | 0o777, 3000, 0);
        let link = meta(mode::S_IFLNK, 0o777, 2000, 0);
        assert_eq!(u.may_follow_link(0, &tmp, &link), Ok(()));
        assert_eq!(u.may_follow_link(1, &tmp, &link), Err(Errno::EACCES));
        assert_eq!(u.may_follow_link(1, &tmp, &meta(mode::S_IFLNK, 0o777, 1000, 0)), Ok(()));
        assert_eq!(u.may_follow_link(1, &tmp, &meta(mode::S_IFLNK, 0o777, 3000, 0)), Ok(()));
        let shut = meta(mode::S_IFDIR, mode::S_ISVTX | 0o775, 3000, 0);
        assert_eq!(u.may_follow_link(1, &shut, &link), Ok(()));
    }

    #[test]
    fn protected_regular_refuses_an_open_with_o_creat_of_a_file_of_another_user() {
        let u = user(1000);
        let all = meta(mode::S_IFDIR, mode::S_ISVTX | 0o777, 3000, 0);
        let group = meta(mode::S_IFDIR, mode::S_ISVTX | 0o775, 3000, 0);
        let file = meta(mode::S_IFREG, 0o666, 2000, 0);
        let fifo = meta(mode::S_IFIFO, 0o666, 2000, 0);
        assert_eq!(u.may_create_in_sticky(0, 0, &all, &file), Ok(()));
        assert_eq!(u.may_create_in_sticky(1, 0, &all, &file), Err(Errno::EACCES));
        assert_eq!(u.may_create_in_sticky(1, 0, &group, &file), Ok(()));
        assert_eq!(u.may_create_in_sticky(2, 0, &group, &file), Err(Errno::EACCES));
        assert_eq!(u.may_create_in_sticky(2, 0, &group, &fifo), Ok(()));
        assert_eq!(u.may_create_in_sticky(0, 2, &group, &fifo), Err(Errno::EACCES));
        let own = meta(mode::S_IFREG, 0o666, 1000, 0);
        assert_eq!(u.may_create_in_sticky(2, 2, &all, &own), Ok(()));
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
        assert_eq!(u.new_owner(&plain, FileType::Regular, 0o2775), (1000, 1000, 0o2775));
        assert_eq!(u.strip_sgid(&plain, FileType::Regular, 0o2010), 0o2010);
        assert_eq!(u.strip_sgid(&dir, FileType::Regular, 0o2010), 0o10);
        assert_eq!(u.strip_sgid(&dir, FileType::Directory, 0o2010), 0o2010);
        assert_eq!(u.strip_sgid(&dir, FileType::Regular, 0o2000), 0o2000);
    }

    #[test]
    fn only_the_owner_changes_the_mode_and_root_gives_files_away() {
        let u = user(1000);
        let mine = meta(mode::S_IFREG, 0o2755, 1000, 50);
        let mut attr = SetAttr { mode: Some(0o2755), ..SetAttr::default() };
        assert_eq!(u.setattr_prepare(&mine, &mut attr), Ok(()));
        assert_eq!(attr.mode, Some(0o755));
        let mut attr = SetAttr { mode: Some(0o644), ..SetAttr::default() };
        assert_eq!(
            u.setattr_prepare(&meta(mode::S_IFREG, 0o644, 0, 0), &mut attr),
            Err(Errno::EPERM)
        );
        let mut attr = SetAttr { uid: Some(2000), ..SetAttr::default() };
        assert_eq!(u.setattr_prepare(&mine, &mut attr), Err(Errno::EPERM));
        let mut attr = SetAttr { uid: Some(1000), gid: Some(1000), ..SetAttr::default() };
        assert_eq!(u.setattr_prepare(&mine, &mut attr), Ok(()));
        let mut attr = SetAttr { gid: Some(7), ..SetAttr::default() };
        assert_eq!(u.setattr_prepare(&mine, &mut attr), Err(Errno::EPERM));
        let mut attr = SetAttr { uid: Some(2000), gid: Some(7), ..SetAttr::default() };
        assert_eq!(Cred::root().setattr_prepare(&mine, &mut attr), Ok(()));
        let mut attr = SetAttr { explicit_times: true, ..SetAttr::default() };
        assert_eq!(
            u.setattr_prepare(&meta(mode::S_IFREG, 0o666, 0, 0), &mut attr),
            Err(Errno::EPERM)
        );
    }

    #[test]
    fn a_write_and_a_chown_clear_the_set_id_bits() {
        let u = user(1000);
        let file = meta(mode::S_IFREG, 0o6755, 1000, 1000);
        assert_eq!(u.write_kill(&file), Some(0o755));
        assert_eq!(Cred::root().write_kill(&file), None);
        assert_eq!(u.write_kill(&meta(mode::S_IFREG, 0o2745, 1000, 1000)), None);
        // A process that is not in the group of the file clears the bit too.
        assert_eq!(u.write_kill(&meta(mode::S_IFREG, 0o6666, 0, 0)), Some(0o666));
        let mut attr = SetAttr::default();
        Cred::root().chown_kill(&file, &mut attr);
        assert_eq!(attr.mode, Some(0o755));
        let mut attr = SetAttr::default();
        Cred::root().chown_kill(&meta(mode::S_IFDIR, 0o6755, 0, 0), &mut attr);
        assert_eq!(attr.mode, None);
    }

    #[test]
    fn the_namespaces_of_the_extended_attributes() {
        let u = user(1000);
        let file = meta(mode::S_IFREG, 0o644, 0, 0);
        assert_eq!(u.xattr_check(&file, b"trusted.a", false, || None), Err(Errno::ENODATA));
        assert_eq!(u.xattr_check(&file, b"trusted.a", true, || None), Err(Errno::EPERM));
        assert_eq!(Cred::root().xattr_check(&file, b"trusted.a", true, || None), Ok(()));
        assert_eq!(u.xattr_check(&file, b"user.a", false, || None), Ok(()));
        assert_eq!(u.xattr_check(&file, b"user.a", true, || None), Err(Errno::EACCES));
        assert_eq!(u.xattr_check(&file, b"security.a", true, || None), Ok(()));
        let link = meta(mode::S_IFLNK, 0o777, 1000, 0);
        assert_eq!(u.xattr_check(&link, b"user.a", true, || None), Err(Errno::EPERM));
        let tmp = meta(mode::S_IFDIR, 0o1777, 0, 0);
        assert_eq!(u.xattr_check(&tmp, b"user.a", true, || None), Err(Errno::EPERM));
    }

    #[test]
    fn signals_and_traces_need_the_same_user() {
        let (a, b) = (user(1000), user(2000));
        assert!(a.may_kill(&a) && !a.may_kill(&b) && Cred::root().may_kill(&b));
        let saved = Cred::root().setresuid(2000, 2000, 1000).unwrap();
        assert!(a.may_kill(&saved));
        assert!(a.may_ptrace(&a) && !a.may_ptrace(&b) && !a.may_ptrace(&saved));
        assert!(!a.may_ptrace(&Cred::root()) && Cred::root().may_ptrace(&a));
    }

    #[test]
    fn access_uses_the_real_ids() {
        let c = Cred::root().setresuid(1000, 0, 0).unwrap().for_access();
        assert_eq!((c.fsuid, c.cap_effective), (1000, 0));
        let c = Cred::root().setresuid(0, 1000, 1000).unwrap().for_access();
        assert_eq!((c.fsuid, c.cap_effective), (0, cap::ALL));
    }

    #[test]
    fn ipc_objects_check_the_owner_and_the_creator() {
        let ipc = IpcOwner { uid: 1000, gid: 50, cuid: 2000, cgid: 60, mode: 0o640 };
        let (owner, creator, other) = (user(1000), user(2000), user(3000));
        assert_eq!(owner.ipc_permission(&ipc, 0o666), Ok(()));
        assert_eq!(creator.ipc_permission(&ipc, 0o600), Ok(()));
        assert_eq!(other.ipc_permission(&ipc, 0o444), Err(Errno::EACCES));
        // A member of the group of the creator gets the group bits.
        let member = other.setgroups_unchecked(&[60]);
        assert_eq!(member.ipc_permission(&ipc, 0o444), Ok(()));
        assert_eq!(member.ipc_permission(&ipc, 0o222), Err(Errno::EACCES));
        assert_eq!(Cred::root().ipc_permission(&ipc, 0o777), Ok(()));
        assert!(owner.ipc_owns(&ipc) && creator.ipc_owns(&ipc));
        assert!(!member.ipc_owns(&ipc) && Cred::root().ipc_owns(&ipc));
    }

    #[test]
    fn setgid_needs_group_execute() {
        let (c, _) = user(1000).exec(ExecFile { mode: 0o2755, uid: 0, gid: 50, no_setid: false });
        assert_eq!((c.egid, c.sgid), (50, 50));
        let (c, _) = user(1000).exec(ExecFile { mode: 0o2745, uid: 0, gid: 50, no_setid: false });
        assert_eq!(c.egid, 1000);
    }
}

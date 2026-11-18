//! The checks of the access to files, the inode and file hooks of security/selinux/hooks.c of
//! Linux: the permissions of a path walk and of `access`, of an open, of a `stat`, and of a
//! change of the attributes or of the size.

use crate::classmap::{dir, file};
use crate::inode::inode_label;
use crate::{avc, task};
use alloc::string::String;
use core::fmt::Write;
use rk_abi::native::open::{O_ACCMODE, O_APPEND, O_RDONLY, O_RDWR, O_WRONLY};
use rk_vfs::cred::{Cred, may};
use rk_vfs::dentry::Location;
use rk_vfs::file::File;
use rk_vfs::inode::{Inode, Result, SetAttr};

/// The number of the policy capability `open_perms` in [`crate::POLICYCAP_NAMES`].
const POLICYCAP_OPEN_PERMS: u32 = 1;

/// The type bits of a mode, `S_IFMT`, and the type of a directory, `S_IFDIR`.
const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;

/// Tells if the policy has the capability `open_perms`, so an open needs the permission
/// `open`, as `selinux_policycap_openperm` of Linux.
fn open_perms() -> bool {
    crate::policy().is_some_and(|p| p.db.policycap(POLICYCAP_OPEN_PERMS))
}

/// The permissions of the access `mask` (the bits of [`may`]) to a file with the mode `mode`,
/// as `file_mask_to_av` of Linux. An access with `MAY_APPEND` needs `append` in place of
/// `write`, and the search of a directory needs `search`.
pub fn file_mask_to_av(mode: u32, mask: u32) -> u32 {
    let mut av = 0;
    if mode & S_IFMT == S_IFDIR {
        if mask & may::EXEC != 0 {
            av |= dir::SEARCH;
        }
        if mask & may::WRITE != 0 {
            av |= file::WRITE;
        }
        if mask & may::READ != 0 {
            av |= file::READ;
        }
        return av;
    }
    if mask & may::EXEC != 0 {
        av |= file::EXECUTE;
    }
    if mask & may::READ != 0 {
        av |= file::READ;
    }
    if mask & may::APPEND != 0 {
        av |= file::APPEND;
    } else if mask & may::WRITE != 0 {
        av |= file::WRITE;
    }
    av
}

/// The permissions of an open with the flags `flags`, as `open_file_to_av` of Linux: `read`
/// and `write`, or `append` with `O_APPEND`, and `open` if `open` tells that the policy has
/// `open_perms`. The access mode 3, which only allows `ioctl`, needs `ioctl`.
fn open_to_av(flags: u32, open: bool) -> u32 {
    let write = if flags & O_APPEND != 0 { file::APPEND } else { file::WRITE };
    let av = match flags & O_ACCMODE {
        O_RDONLY => file::READ,
        O_WRONLY => write,
        O_RDWR => file::READ | write,
        _ => file::IOCTL,
    };
    if open { av | file::OPEN } else { av }
}

/// Writes the field ` dev="vda"` of the mount of `at`: the name of the device, or for a mount
/// without a device the name of the type of the file system, as `s_id` of Linux.
fn dev_field(s: &mut String, at: &Location) {
    let source = at.mount.source();
    s.push_str(" dev=");
    match source.source.strip_prefix(b"/dev/") {
        Some(dev) if !dev.is_empty() => avc::untrusted(s, dev),
        _ => avc::untrusted(s, source.fstype.as_bytes()),
    }
}

/// The fields of the file `at` in an AVC record, as `LSM_AUDIT_DATA_PATH` and
/// `LSM_AUDIT_DATA_FILE` in `dump_common_audit_data` of Linux: ` path="/bin/sh" dev="vda"
/// ino=12`.
pub fn path_fields(at: &Location) -> impl FnOnce(&mut String) + '_ {
    move |s| {
        s.push_str(" path=");
        avc::untrusted(s, &at.absolute_path());
        dev_field(s, at);
        let _ = write!(s, " ino={}", at.inode().metadata().ino);
    }
}

/// The fields of the file `inode` at `at` in an AVC record, as `LSM_AUDIT_DATA_INODE` and
/// `LSM_AUDIT_DATA_DENTRY` of Linux: ` name="sh" dev="vda" ino=12`. Without `at`, the record
/// has only the inode number.
fn inode_fields<'a>(
    inode: &'a dyn Inode,
    at: Option<&'a Location>,
) -> impl FnOnce(&mut String) + 'a {
    move |s| {
        if let Some(at) = at {
            s.push_str(" name=");
            avc::untrusted(s, &at.dentry.name());
            dev_field(s, at);
        }
        let _ = write!(s, " ino={}", inode.metadata().ino);
    }
}

/// Checks the access `mask` of the task with `cred` to `inode`, as `selinux_inode_permission`
/// of Linux. Only the bits of read, write, execute and append count. For `access(2)`, which
/// has `MAY_ACCESS`, a denial makes no record if the policy does not audit `audit_access`.
/// Before the first policy load, each access is allowed.
///
/// # Errors
///
/// `EACCES` if the policy denies a permission in enforcing mode.
pub fn inode_permission(
    cred: &Cred,
    inode: &dyn Inode,
    at: Option<&Location>,
    mask: u32,
) -> Result<()> {
    let bits = mask & (may::RWX | may::APPEND);
    if bits == 0 || !crate::initialized() {
        return Ok(());
    }
    let (isid, sclass) = inode_label(inode, at);
    let perms = file_mask_to_av(inode.metadata().mode, bits);
    let ssid = task::cred_sid(cred);
    let (avd, rc) = avc::has_perm_noaudit(ssid, isid, sclass, perms);
    let auditdeny = if mask & may::ACCESS != 0 { file::AUDIT_ACCESS } else { 0 };
    avc::audit(ssid, isid, sclass, perms, &avd, rc, auditdeny, inode_fields(inode, at));
    rc
}

/// Checks the open of `f` with the flags `flags` by the task with `cred`, as
/// `selinux_file_open` of Linux.
///
/// # Errors
///
/// `EACCES` if the policy denies a permission in enforcing mode.
pub fn file_open(f: &File, cred: &Cred, flags: u32) -> Result<()> {
    let Some(inode) = f.inode().filter(|_| crate::initialized()) else {
        return Ok(());
    };
    let at = f.location();
    let (isid, sclass) = inode_label(&**inode, at);
    let ssid = task::cred_sid(cred);
    let av = open_to_av(flags, open_perms());
    match at {
        Some(at) => avc::has_perm(ssid, isid, sclass, av, path_fields(at)),
        None => avc::has_perm(ssid, isid, sclass, av, inode_fields(&**inode, None)),
    }
}

/// Checks the permission `getattr` of the current task on the file `at` for `stat`, as
/// `selinux_inode_getattr` of Linux.
///
/// # Errors
///
/// `EACCES` if the policy denies the permission in enforcing mode.
pub fn inode_getattr(at: &Location) -> Result<()> {
    if !crate::initialized() {
        return Ok(());
    }
    let (isid, sclass) = inode_label(&**at.inode(), Some(at));
    avc::has_perm(crate::current_sid(), isid, sclass, file::GETATTR, path_fields(at))
}

/// Checks the permissions `av` of the current task on `inode` at `at`, as `dentry_has_perm`
/// of Linux.
fn inode_has_perm(inode: &dyn Inode, at: Option<&Location>, av: u32) -> Result<()> {
    if !crate::initialized() {
        return Ok(());
    }
    let (isid, sclass) = inode_label(inode, at);
    avc::has_perm(crate::current_sid(), isid, sclass, av, inode_fields(inode, at))
}

/// Checks the change `attr` of the attributes of `inode`, as `selinux_inode_setattr` of Linux:
/// a change of the mode, of the owner or of the times that the caller gives needs `setattr`,
/// and another change, as a change of the times to now, needs `write`.
///
/// # Errors
///
/// `EACCES` if the policy denies the permission in enforcing mode.
pub fn inode_setattr(inode: &dyn Inode, at: Option<&Location>, attr: &SetAttr) -> Result<()> {
    let av =
        if attr.mode.is_some() || attr.uid.is_some() || attr.gid.is_some() || attr.explicit_times {
            file::SETATTR
        } else if attr.size.is_some() && open_perms() {
            file::WRITE | file::OPEN
        } else {
            file::WRITE
        };
    inode_has_perm(inode, at, av)
}

/// Checks the `truncate(2)` of the file `at`, as `selinux_inode_setattr` of Linux for a change
/// of the size without a file: `write`, and `open` if the policy has `open_perms`.
///
/// # Errors
///
/// `EACCES` if the policy denies a permission in enforcing mode.
pub fn path_truncate(at: &Location) -> Result<()> {
    let av = if open_perms() { file::WRITE | file::OPEN } else { file::WRITE };
    inode_has_perm(&**at.inode(), Some(at), av)
}

/// Checks the truncate of the open file `f` by `ftruncate` or by an open with `O_TRUNC`, as
/// `selinux_inode_setattr` of Linux for a change of the size with `ATTR_FILE`: `write`.
///
/// # Errors
///
/// `EACCES` if the policy denies the permission in enforcing mode.
pub fn file_truncate(f: &File) -> Result<()> {
    match f.inode() {
        Some(inode) => inode_has_perm(&**inode, f.location(), file::WRITE),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use rk_abi::Errno;
    use rk_vfs::dentry::{Dentry, MountNamespace, MountSource};
    use rk_vfs::inode::{InodeRef, Metadata};

    /// An inode of the mode `0`.
    struct Node(u32);

    impl Inode for Node {
        fn metadata(&self) -> Metadata {
            Metadata { mode: self.0, ino: 7, ..Metadata::default() }
        }
        fn set_attr(&self, _attr: &SetAttr) -> Result<()> {
            Ok(())
        }
    }

    fn setup() -> std::sync::MutexGuard<'static, ()> {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            rk_vfs::security::register(&crate::LSM);
            rk_vfs::security::init(Some("selinux"), None);
        });
        let guard = crate::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        crate::load_policy(include_bytes!("../tests/rk_test.35.bin")).unwrap();
        guard
    }

    #[test]
    fn the_policy_checks_the_access_to_a_file() {
        let _guard = setup();
        // A file of selinuxfs has the type security_t, which kernel_t can read and search.
        let source = MountSource { source: b"none".to_vec(), fstype: "selinuxfs", flags: 0 };
        let root = Dentry::new_root(Arc::new(Node(0o040_755)));
        let dir = Location { mount: MountNamespace::detached(root.clone(), source), dentry: root };
        let inode: InodeRef = Arc::new(Node(0o100_644));
        let at =
            Location { mount: dir.mount.clone(), dentry: dir.dentry.add_child(b"enforce", inode) };
        let cred = Cred::root();
        let check = |at: &Location, mask| inode_permission(&cred, &**at.inode(), Some(at), mask);
        crate::set_enforcing(true);
        assert_eq!(check(&dir, may::EXEC | may::READ), Ok(()));
        assert_eq!(check(&at, may::READ | may::ACCESS), Ok(()));
        assert_eq!(check(&at, may::ACCESS), Ok(()));
        assert_eq!(check(&at, may::WRITE), Err(Errno::EACCES));
        assert_eq!(check(&at, may::WRITE | may::APPEND), Err(Errno::EACCES));
        assert_eq!(inode_getattr(&at), Ok(()));
        let chmod = SetAttr { mode: Some(0o600), ..SetAttr::default() };
        assert_eq!(inode_setattr(&**at.inode(), Some(&at), &chmod), Err(Errno::EACCES));
        assert_eq!(path_truncate(&at), Err(Errno::EACCES));
        // The permissive mode allows the access.
        crate::set_enforcing(false);
        assert_eq!(check(&at, may::WRITE), Ok(()));
        assert_eq!(inode_setattr(&**at.inode(), Some(&at), &chmod), Ok(()));
    }

    #[test]
    fn a_mask_gives_the_permissions_of_linux() {
        let reg = 0o100_644;
        assert_eq!(file_mask_to_av(reg, may::READ), file::READ);
        assert_eq!(file_mask_to_av(reg, may::READ | may::WRITE), file::READ | file::WRITE);
        assert_eq!(file_mask_to_av(reg, may::WRITE | may::APPEND), file::APPEND);
        assert_eq!(file_mask_to_av(reg, may::EXEC), file::EXECUTE);
        assert_eq!(file_mask_to_av(0o020_666, may::WRITE), file::WRITE);
        let dir = 0o040_755;
        assert_eq!(file_mask_to_av(dir, may::EXEC), dir::SEARCH);
        assert_eq!(file_mask_to_av(dir, may::WRITE | may::EXEC), file::WRITE | dir::SEARCH);
        assert_eq!(file_mask_to_av(dir, may::READ | may::APPEND), file::READ);
        assert_eq!(file_mask_to_av(reg, may::ACCESS), 0);
    }

    #[test]
    fn an_open_gives_the_permissions_of_linux() {
        assert_eq!(open_to_av(O_RDONLY, false), file::READ);
        assert_eq!(open_to_av(O_WRONLY, false), file::WRITE);
        assert_eq!(open_to_av(O_RDWR | O_APPEND, false), file::READ | file::APPEND);
        assert_eq!(open_to_av(3, false), file::IOCTL);
        assert_eq!(open_to_av(O_RDONLY, true), file::READ | file::OPEN);
    }
}

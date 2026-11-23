//! The labels of the new files and the changes of the attribute `security.selinux`, as
//! `selinux_inode_init_security`, `selinux_inode_setxattr`, `selinux_inode_post_setxattr`,
//! `selinux_inode_setsecurity` and `selinux_inode_removexattr` in security/selinux/hooks.c of
//! Linux.

use crate::classmap::{class, file, filesystem};
use crate::file::{inode_fields, inode_has_perm};
use crate::inode::{XATTR_NAME, inode_label, mode_to_class, sblabel, set_label};
use crate::namei::new_file_sid;
use crate::{avc, server, services, task};
use alloc::string::String;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::dentry::Location;
use rk_vfs::inode::{Inode, Result};

/// Gives the new file `inode` with the name `name` in `dir` its label, as
/// `selinux_inode_init_security` of Linux: the SID of `fscreate` or of the type transition,
/// the label of the check of [`crate::namei::may_create`]. On a file system that keeps the
/// labels, the context also goes to `xattrs` for the file, with a null byte at the end. Before
/// the first policy load, the file gets its label at its first use.
///
/// # Errors
///
/// The errors of [`new_file_sid`].
pub fn init_security(
    inode: &dyn Inode,
    dir: &Location,
    name: Option<&[u8]>,
    xattrs: &mut Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<()> {
    if !crate::initialized() {
        return Ok(());
    }
    let cred = rk_vfs::cred::current();
    let create_sid = task::load(&cred, task::slot::CREATE);
    let sclass = mode_to_class(inode.metadata().mode);
    let sid = new_file_sid(task::cred_sid(&cred), create_sid, dir, name, sclass)?;
    set_label(inode, sid);
    if sblabel(dir.mount.fstype()) {
        let mut value = server::sid_to_context_force(sid)?.into_bytes();
        value.push(0);
        xattrs.push((XATTR_NAME.to_vec(), value));
    }
    Ok(())
}

/// The SID of the context `value` of `setxattr`. A context that the policy does not accept
/// needs `CAP_MAC_ADMIN`, else it makes a `SELINUX_ERR` record without the null byte at the
/// end.
fn new_sid(value: &[u8]) -> Result<u32> {
    match server::context_to_sid(value, 0, false) {
        Err(Errno::EINVAL) => {
            if !crate::task::has_cap_mac_admin(true) {
                let mut s = String::from("op=setxattr invalid_context=");
                avc::untrusted(&mut s, value.strip_suffix(&[0]).unwrap_or(value));
                services::log_err(&s);
                return Err(Errno::EINVAL);
            }
            server::context_to_sid(value, 0, true)
        }
        r => r,
    }
}

/// Checks the change of the attribute `name` of `inode` at `at` to `value`, as
/// `selinux_inode_setxattr` of Linux. Another attribute needs `setattr` on the file. A new
/// label needs a file system that keeps the labels, the owner of the file or `CAP_FOWNER`,
/// `relabelfrom` on the old label and `relabelto` on the new label, the `validatetrans` rules
/// of the class, and `associate` of the new label with the file system.
///
/// # Errors
///
/// `EOPNOTSUPP` for a file system that does not keep the labels, `EPERM` for a task that does
/// not own the file, `EINVAL` for a bad context, and `EACCES` or `EPERM` if the policy denies
/// the change in enforcing mode.
pub fn setxattr(inode: &dyn Inode, at: Option<&Location>, name: &[u8], value: &[u8]) -> Result<()> {
    if name != XATTR_NAME {
        return inode_has_perm(inode, at, file::SETATTR);
    }
    let cred = rk_vfs::cred::current();
    let owns = cred.owns(&inode.metadata());
    if !crate::initialized() {
        return if owns { Ok(()) } else { Err(Errno::EPERM) };
    }
    let Some(at) = at.filter(|at| sblabel(at.mount.fstype())) else {
        return Err(Errno::EOPNOTSUPP);
    };
    if !owns {
        return Err(Errno::EPERM);
    }
    let sid = task::cred_sid(&cred);
    let (isid, sclass) = inode_label(inode, Some(at));
    avc::has_perm(sid, isid, sclass, file::RELABELFROM, inode_fields(inode, Some(at)))?;
    let new = new_sid(value)?;
    avc::has_perm(sid, new, sclass, file::RELABELTO, inode_fields(inode, Some(at)))?;
    server::validate_transition(isid, new, sid, sclass)?;
    let (_, fs_sid) = server::fs_use(at.mount.fstype());
    let fields = inode_fields(inode, Some(at));
    avc::has_perm(new, fs_sid, class::FILESYSTEM, filesystem::ASSOCIATE, fields)
}

/// Gives `inode` the label of the new value of `security.selinux` after the file system took
/// it, as `selinux_inode_post_setxattr` of Linux.
pub fn post_setxattr(inode: &dyn Inode, name: &[u8], value: &[u8]) {
    if name != XATTR_NAME || !crate::initialized() {
        return;
    }
    match server::context_to_sid(value, 0, true) {
        Ok(sid) => set_label(inode, sid),
        Err(e) => {
            let ino = inode.metadata().ino;
            rk_frame::println!("SELinux:  unable to map context to SID for ino {ino}, rc={e:?}");
        }
    }
}

/// Changes the label of `inode` at `at` to `value` for a file system that does not keep the
/// attribute `security.selinux`, as `selinux_inode_setsecurity` of Linux. `None` for another
/// name. The file system must keep the labels in memory, as sysfs and cgroup2.
pub fn setsecurity(
    inode: &dyn Inode,
    at: Option<&Location>,
    name: &[u8],
    value: &[u8],
) -> Option<Result<()>> {
    if name != b"selinux" {
        return None;
    }
    if !crate::initialized() || !at.is_some_and(|at| sblabel(at.mount.fstype())) {
        return Some(Err(Errno::EOPNOTSUPP));
    }
    if value.is_empty() {
        return Some(Err(Errno::EACCES));
    }
    Some(server::context_to_sid(value, 0, false).map(|sid| set_label(inode, sid)))
}

/// Checks the removal of the attribute `name` of `inode` at `at`, as
/// `selinux_inode_removexattr` of Linux. Another attribute needs `setattr` on the file. After
/// the first policy load, no task can remove the label: each file has one.
///
/// # Errors
///
/// `EACCES` for `security.selinux`, and if the policy denies `setattr` in enforcing mode.
pub fn removexattr(inode: &dyn Inode, at: Option<&Location>, name: &[u8]) -> Result<()> {
    if name != XATTR_NAME {
        return inode_has_perm(inode, at, file::SETATTR);
    }
    if crate::initialized() { Err(Errno::EACCES) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use rk_vfs::dentry::{Dentry, MountNamespace, MountSource};
    use rk_vfs::inode::{InodeRef, Metadata, SetAttr};

    /// An inode of the mode `0`.
    struct Node(u32);

    impl Inode for Node {
        fn metadata(&self) -> Metadata {
            Metadata { mode: self.0, ino: 9, ..Metadata::default() }
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

    /// The root directory of a mount of `fstype`, and the file `x` in it.
    fn mount(fstype: &'static str) -> (Location, Location) {
        let source = MountSource { source: b"none".to_vec(), fstype, flags: 0 };
        let root = Dentry::new_root(Arc::new(Node(0o040_755)));
        let dir = Location { mount: MountNamespace::detached(root.clone(), source), dentry: root };
        let inode: InodeRef = Arc::new(Node(0o100_644));
        let at = Location { mount: dir.mount.clone(), dentry: dir.dentry.add_child(b"x", inode) };
        (dir, at)
    }

    fn label(at: &Location) -> String {
        server::sid_to_context(inode_label(&**at.inode(), Some(at)).0).unwrap()
    }

    fn sid(context: &str) -> u32 {
        server::context_to_sid(context.as_bytes(), 0, false).unwrap()
    }

    #[test]
    fn a_new_file_gets_its_label_and_the_attribute() {
        let _guard = setup();
        let (tmp, at) = mount("tmpfs");
        let mut xattrs = Vec::new();
        init_security(&**at.inode(), &tmp, Some(b"x"), &mut xattrs).unwrap();
        assert_eq!(label(&at), "system_u:object_r:tmpfs_t:s0");
        let value = b"system_u:object_r:tmpfs_t:s0\0".to_vec();
        assert_eq!(xattrs, alloc::vec![(XATTR_NAME.to_vec(), value)]);
        // selinuxfs does not keep the labels, so the file gets no attribute.
        let (sel, at) = mount("selinuxfs");
        let mut xattrs = Vec::new();
        init_security(&**at.inode(), &sel, None, &mut xattrs).unwrap();
        assert_eq!(label(&at), "system_u:object_r:security_t:s0");
        assert!(xattrs.is_empty());
    }

    #[test]
    fn a_change_of_the_label_needs_the_relabel_permissions() {
        let _guard = setup();
        let (_, at) = mount("tmpfs");
        let inode = &**at.inode();
        let etc = b"system_u:object_r:etc_t:s0\0";
        crate::set_enforcing(true);
        // kernel_t has no relabelfrom on tmpfs_t.
        assert_eq!(setxattr(inode, Some(&at), XATTR_NAME, etc), Err(Errno::EACCES));
        assert_eq!(setxattr(inode, Some(&at), b"user.a", b"1"), Err(Errno::EACCES));
        assert_eq!(removexattr(inode, Some(&at), b"user.a"), Err(Errno::EACCES));
        crate::set_enforcing(false);
        assert_eq!(setxattr(inode, Some(&at), XATTR_NAME, etc), Ok(()));
        assert_eq!(setxattr(inode, Some(&at), XATTR_NAME, b"bad"), Ok(()));
        assert_eq!(setxattr(inode, None, XATTR_NAME, etc), Err(Errno::EOPNOTSUPP));
        assert_eq!(removexattr(inode, Some(&at), b"user.a"), Ok(()));
        assert_eq!(removexattr(inode, Some(&at), XATTR_NAME), Err(Errno::EACCES));
        post_setxattr(inode, XATTR_NAME, etc);
        assert_eq!(label(&at), "system_u:object_r:etc_t:s0");
        post_setxattr(inode, b"user.a", b"system_u:object_r:bin_t:s0");
        assert_eq!(label(&at), "system_u:object_r:etc_t:s0");
        let (_, sel) = mount("selinuxfs");
        let e = setxattr(&**sel.inode(), Some(&sel), XATTR_NAME, etc);
        assert_eq!(e, Err(Errno::EOPNOTSUPP));
    }

    #[test]
    fn the_validatetrans_rules_check_a_change_of_the_level() {
        let _guard = setup();
        let s0 = sid("system_u:object_r:etc_t:s0");
        let s1 = sid("system_u:object_r:etc_t:s1");
        let task = sid("system_u:system_r:init_t:s0");
        crate::set_enforcing(true);
        assert_eq!(server::validate_transition(s0, s0, task, class::FILE), Ok(()));
        assert_eq!(server::validate_transition(s0, s1, task, class::FILE), Err(Errno::EPERM));
        // The class dir has no rules.
        assert_eq!(server::validate_transition(s0, s1, task, class::DIR), Ok(()));
        crate::set_enforcing(false);
        assert_eq!(server::validate_transition(s0, s1, task, class::FILE), Ok(()));
    }

    #[test]
    fn setsecurity_changes_the_label_in_memory() {
        let _guard = setup();
        let (_, sys) = mount("sysfs");
        let inode = &**sys.inode();
        let etc = b"system_u:object_r:etc_t:s0";
        assert!(setsecurity(inode, Some(&sys), b"ima", etc).is_none());
        assert_eq!(setsecurity(inode, Some(&sys), b"selinux", b""), Some(Err(Errno::EACCES)));
        assert_eq!(setsecurity(inode, Some(&sys), b"selinux", b"bad"), Some(Err(Errno::EINVAL)));
        assert_eq!(setsecurity(inode, Some(&sys), b"selinux", etc), Some(Ok(())));
        assert_eq!(label(&sys), "system_u:object_r:etc_t:s0");
        let (_, sel) = mount("selinuxfs");
        let e = setsecurity(&**sel.inode(), Some(&sel), b"selinux", etc);
        assert_eq!(e, Some(Err(Errno::EOPNOTSUPP)));
    }
}

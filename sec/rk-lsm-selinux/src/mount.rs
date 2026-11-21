//! The checks of the mounts, as `selinux_mount`, `selinux_move_mount` and `selinux_umount` of
//! security/selinux/hooks.c of Linux: a new mount and a move of a mount need `mounton` on the
//! place of the mount, a remount needs `remount` of the file system, and an unmount needs
//! `unmount` of the file system.

use crate::classmap::{class, file, filesystem};
use crate::file::path_fields;
use crate::inode::inode_label;
use crate::{avc, server};
use rk_abi::native::mount::MS_REMOUNT;
use rk_vfs::dentry::Location;
use rk_vfs::inode::Result;
use rk_vfs::security::MountReq;

/// Checks the permissions `perms` of the class `filesystem` of the current task on the file
/// system of the mount of `at`, as `superblock_has_perm` of Linux. The SID of the file system
/// is the SID of `security_fs_use`. The record has no fields of the object, as Linux gives no
/// audit data for the remount and the unmount.
///
/// # Errors
///
/// `EACCES` if the policy denies a permission in enforcing mode.
fn superblock_has_perm(at: &Location, perms: u32) -> Result<()> {
    if !crate::initialized() {
        return Ok(());
    }
    let (_, fs_sid) = server::fs_use(at.mount.fstype());
    avc::has_perm(crate::current_sid(), fs_sid, class::FILESYSTEM, perms, |_| {})
}

/// Checks `mounton` of the current task on the place `at`, as `path_has_perm` with
/// `FILE__MOUNTON` of Linux.
///
/// # Errors
///
/// `EACCES` if the policy denies the permission in enforcing mode.
fn mounton(at: &Location) -> Result<()> {
    if !crate::initialized() {
        return Ok(());
    }
    let (isid, sclass) = inode_label(&**at.inode(), Some(at));
    avc::has_perm(crate::current_sid(), isid, sclass, file::MOUNTON, path_fields(at))
}

/// Checks `mount(2)`, as `selinux_mount` of Linux: `remount` of the file system for
/// `MS_REMOUNT`, else `mounton` on the place of the mount.
///
/// # Errors
///
/// `EACCES` if the policy denies the permission in enforcing mode.
pub fn sb_mount(req: &MountReq<'_>) -> Result<()> {
    if req.flags & MS_REMOUNT != 0 {
        return superblock_has_perm(req.at, filesystem::REMOUNT);
    }
    mounton(req.at)
}

/// Checks `move_mount(2)` to `to`, as `selinux_move_mount` of Linux: `mounton` on `to`.
///
/// # Errors
///
/// `EACCES` if the policy denies the permission in enforcing mode.
pub fn move_mount(to: &Location) -> Result<()> {
    mounton(to)
}

/// Checks `umount2(2)` of the mount with the root `root`, as `selinux_umount` of Linux:
/// `unmount` of the file system.
///
/// # Errors
///
/// `EACCES` if the policy denies the permission in enforcing mode.
pub fn sb_umount(root: &Location) -> Result<()> {
    superblock_has_perm(root, filesystem::UNMOUNT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use rk_abi::Errno;
    use rk_vfs::dentry::{Dentry, MountNamespace, MountSource};
    use rk_vfs::inode::{Inode, Metadata, SetAttr};

    /// A directory.
    struct Dir;

    impl Inode for Dir {
        fn metadata(&self) -> Metadata {
            Metadata { mode: 0o040_755, ino: 5, ..Metadata::default() }
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

    /// The root directory of a mount of `fstype`.
    fn root(fstype: &'static str) -> Location {
        let source = MountSource { source: b"none".to_vec(), fstype, flags: 0 };
        let root = Dentry::new_root(Arc::new(Dir));
        Location { mount: MountNamespace::detached(root.clone(), source), dentry: root }
    }

    /// A mount on `at` with the `MS_*` flags `flags`.
    fn req<'a>(
        at: &'a Location,
        flags: u32,
        lookup: &'a dyn Fn(&[u8]) -> Result<Location>,
    ) -> MountReq<'a> {
        MountReq { at, dev_name: None, fstype: None, flags, data: None, fs_flags: None, lookup }
    }

    #[test]
    fn the_mounts_need_mounton_remount_and_unmount() {
        let _guard = setup();
        let lookup = |_: &[u8]| Err(Errno::ENOENT);
        // The policy gives kernel_t no permission of the mounts.
        let (tmp, sel) = (root("tmpfs"), root("selinuxfs"));
        crate::set_enforcing(true);
        for at in [&tmp, &sel] {
            assert_eq!(sb_mount(&req(at, 0, &lookup)), Err(Errno::EACCES));
            assert_eq!(sb_mount(&req(at, MS_REMOUNT, &lookup)), Err(Errno::EACCES));
            assert_eq!(move_mount(at), Err(Errno::EACCES));
            assert_eq!(sb_umount(at), Err(Errno::EACCES));
        }
        crate::set_enforcing(false);
        // Permissive mode only makes the records.
        assert_eq!(sb_mount(&req(&tmp, 0, &lookup)), Ok(()));
        assert_eq!(sb_mount(&req(&tmp, MS_REMOUNT, &lookup)), Ok(()));
        assert_eq!(move_mount(&sel), Ok(()));
        assert_eq!(sb_umount(&sel), Ok(()));
    }

    #[test]
    fn the_file_system_has_the_sid_of_its_fs_use_rule() {
        let _guard = setup();
        let sid = |fstype| server::sid_to_context(server::fs_use(fstype).1).unwrap();
        assert_eq!(sid("tmpfs"), "system_u:object_r:tmpfs_t:s0");
        assert_eq!(sid("selinuxfs"), "system_u:object_r:security_t:s0");
    }
}

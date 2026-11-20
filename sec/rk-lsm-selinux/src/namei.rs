//! The checks of the operations on the names of the directories, as `may_create`, `may_link`
//! and `may_rename` in security/selinux/hooks.c of Linux: the new files of `open` with
//! `O_CREAT`, `mkdir`, `mknod` and `symlink`, and `link`, `unlink`, `rmdir` and `rename`.

use crate::classmap::{class, dir, file, filesystem};
use crate::file::inode_fields;
use crate::inode::{inode_label, sblabel};
use crate::{avc, server, task};
use alloc::string::String;
use alloc::sync::Arc;
use rk_vfs::dentry::Location;
use rk_vfs::inode::Result;

/// The fields of a new name in an AVC record, as `LSM_AUDIT_DATA_DENTRY` of Linux for a
/// dentry without an inode: ` name="new"`.
fn name_fields(name: &[u8]) -> impl FnOnce(&mut String) + '_ {
    move |s| {
        s.push_str(" name=");
        avc::untrusted(s, name);
    }
}

/// The fields of the file `at` in an AVC record: ` name="old" dev="vda" ino=12`.
fn at_fields(at: &Location) -> impl FnOnce(&mut String) + '_ {
    inode_fields(&**at.inode(), Some(at))
}

/// The SID of a new file of the class `tclass` with the name `name` in the directory `dir`, as
/// `selinux_determine_inode_label` of Linux. `ssid` is the SID of the task and `create_sid`
/// its SID for new files from `/proc/self/attr/fscreate`, or 0. A file system that keeps the
/// labels takes `create_sid`. Else the new file gets the type transition from the task to the
/// directory for the name.
///
/// # Errors
///
/// The errors of [`server::transition_sid`].
pub fn new_file_sid(
    ssid: u32,
    create_sid: u32,
    dir: &Location,
    name: &[u8],
    tclass: u16,
) -> Result<u32> {
    if create_sid != 0 && sblabel(dir.mount.fstype()) {
        return Ok(create_sid);
    }
    let (dsid, _) = inode_label(&**dir.inode(), Some(dir));
    server::transition_sid(ssid, dsid, tclass, Some(name))
}

/// Checks that the current task can make the file `name` of the class `tclass` in `dir`, as
/// `may_create` of Linux: `add_name` and `search` on the directory, `create` on the label of
/// the new file, and `associate` of that label with the file system.
///
/// # Errors
///
/// `EACCES` if the policy denies a permission in enforcing mode, and the errors of
/// [`new_file_sid`].
pub fn may_create(dir: &Location, name: &[u8], tclass: u16) -> Result<()> {
    if !crate::initialized() {
        return Ok(());
    }
    let cred = rk_vfs::cred::current();
    let ssid = task::cred_sid(&cred);
    let (dsid, _) = inode_label(&**dir.inode(), Some(dir));
    let av = dir::ADD_NAME | dir::SEARCH;
    avc::has_perm(ssid, dsid, class::DIR, av, name_fields(name))?;
    let create_sid = task::load(&cred, task::slot::CREATE);
    let new = new_file_sid(ssid, create_sid, dir, name, tclass)?;
    avc::has_perm(ssid, new, tclass, file::CREATE, name_fields(name))?;
    let (_, fs_sid) = server::fs_use(dir.mount.fstype());
    avc::has_perm(new, fs_sid, class::FILESYSTEM, filesystem::ASSOCIATE, name_fields(name))
}

/// The operation of [`may_link`], `MAY_LINK`, `MAY_UNLINK` and `MAY_RMDIR` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Link {
    /// A new name in the directory for the file.
    Link,
    /// The removal of a file from the directory.
    Unlink,
    /// The removal of a directory from the directory.
    Rmdir,
}

/// Checks that the current task can add a name for the file `at` to `dir` or remove it, as
/// `may_link` of Linux: `search` and `add_name` or `remove_name` on the directory, and `link`,
/// `unlink` or `rmdir` on the file.
///
/// # Errors
///
/// `EACCES` if the policy denies a permission in enforcing mode.
pub fn may_link(dir: &Location, at: &Location, kind: Link) -> Result<()> {
    if !crate::initialized() {
        return Ok(());
    }
    let ssid = crate::current_sid();
    let (dsid, _) = inode_label(&**dir.inode(), Some(dir));
    let av = match kind {
        Link::Link => dir::SEARCH | dir::ADD_NAME,
        Link::Unlink | Link::Rmdir => dir::SEARCH | dir::REMOVE_NAME,
    };
    avc::has_perm(ssid, dsid, class::DIR, av, at_fields(at))?;
    let (isid, sclass) = inode_label(&**at.inode(), Some(at));
    let av = match kind {
        Link::Link => file::LINK,
        Link::Unlink => file::UNLINK,
        Link::Rmdir => dir::RMDIR,
    };
    avc::has_perm(ssid, isid, sclass, av, at_fields(at))
}

/// Checks that the current task can move the file `old` from `old_dir` to the name `name` in
/// `new_dir`, where `new` is now, as `may_rename` of Linux: `remove_name` and `search` on the
/// old directory, `rename` on the file, `reparent` for a directory that moves to another
/// directory, `add_name` and `search` on the new directory, and for a file that the move
/// replaces, `remove_name` on the new directory and `unlink` or `rmdir` on that file.
///
/// # Errors
///
/// `EACCES` if the policy denies a permission in enforcing mode.
pub fn may_rename(
    old_dir: &Location,
    old: &Location,
    new_dir: &Location,
    name: &[u8],
    new: Option<&Location>,
) -> Result<()> {
    if !crate::initialized() {
        return Ok(());
    }
    let ssid = crate::current_sid();
    let (old_dsid, _) = inode_label(&**old_dir.inode(), Some(old_dir));
    let (old_sid, old_class) = inode_label(&**old.inode(), Some(old));
    let av = dir::REMOVE_NAME | dir::SEARCH;
    avc::has_perm(ssid, old_dsid, class::DIR, av, at_fields(old))?;
    avc::has_perm(ssid, old_sid, old_class, file::RENAME, at_fields(old))?;
    if old_class == class::DIR && !Arc::ptr_eq(old_dir.inode(), new_dir.inode()) {
        avc::has_perm(ssid, old_sid, old_class, dir::REPARENT, at_fields(old))?;
    }
    let (new_dsid, _) = inode_label(&**new_dir.inode(), Some(new_dir));
    let Some(new) = new else {
        let av = dir::ADD_NAME | dir::SEARCH;
        return avc::has_perm(ssid, new_dsid, class::DIR, av, name_fields(name));
    };
    let av = dir::ADD_NAME | dir::SEARCH | dir::REMOVE_NAME;
    avc::has_perm(ssid, new_dsid, class::DIR, av, at_fields(new))?;
    let (new_sid, new_class) = inode_label(&**new.inode(), Some(new));
    let av = if new_class == class::DIR { dir::RMDIR } else { file::UNLINK };
    avc::has_perm(ssid, new_sid, new_class, av, at_fields(new))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidtab::sid;
    use rk_abi::Errno;
    use rk_vfs::dentry::{Dentry, MountNamespace, MountSource};
    use rk_vfs::inode::{Inode, InodeRef, Metadata, SetAttr};

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

    /// The root directory of a mount of `fstype`, and the file `name` of the mode `mode` in it.
    fn mount(fstype: &'static str, name: &[u8], mode: u32) -> (Location, Location) {
        let source = MountSource { source: b"none".to_vec(), fstype, flags: 0 };
        let root = Dentry::new_root(Arc::new(Node(0o040_755)));
        let dir = Location { mount: MountNamespace::detached(root.clone(), source), dentry: root };
        let inode: InodeRef = Arc::new(Node(mode));
        let at = Location { mount: dir.mount.clone(), dentry: dir.dentry.add_child(name, inode) };
        (dir, at)
    }

    fn context(sid: u32) -> String {
        server::sid_to_context(sid).unwrap()
    }

    #[test]
    fn a_new_file_gets_the_label_of_the_type_transition_for_its_name() {
        let _guard = setup();
        let (tmp, _) = mount("tmpfs", b"x", 0o100_644);
        // The SID `init` has the context of `kernel` without the capability
        // `userspace_initial_context`, so the test takes a SID of init_t.
        let init = server::context_to_sid(b"system_u:system_r:init_t:s0", 0, false).unwrap();
        let new = |create, name: &[u8], tclass| new_file_sid(init, create, &tmp, name, tclass);
        assert_eq!(context(new(0, b"named", class::DIR).unwrap()), "system_u:object_r:bin_t:s0");
        assert_eq!(context(new(0, b"other", class::DIR).unwrap()), "system_u:object_r:tmpfs_t:s0");
        assert_eq!(context(new(0, b"named", class::FILE).unwrap()), "system_u:object_r:etc_t:s0");
        // tmpfs keeps the labels, so the SID of fscreate is the label. selinuxfs does not.
        assert_eq!(new(sid::DEVNULL, b"named", class::DIR), Ok(sid::DEVNULL));
        let (sel, _) = mount("selinuxfs", b"x", 0o100_644);
        let label = new_file_sid(init, sid::DEVNULL, &sel, b"x", class::FILE).unwrap();
        assert_eq!(context(label), "system_u:object_r:security_t:s0");
    }

    #[test]
    fn the_policy_checks_the_names_of_a_directory() {
        let _guard = setup();
        // kernel_t can search the directories of selinuxfs, and not add or remove a name.
        let (dir, at) = mount("selinuxfs", b"enforce", 0o100_644);
        let (_, sub) = mount("selinuxfs", b"sub", 0o040_755);
        crate::set_enforcing(true);
        assert_eq!(may_create(&dir, b"new", class::FILE), Err(Errno::EACCES));
        assert_eq!(may_link(&dir, &at, Link::Link), Err(Errno::EACCES));
        assert_eq!(may_link(&dir, &at, Link::Unlink), Err(Errno::EACCES));
        assert_eq!(may_rename(&dir, &at, &dir, b"new", None), Err(Errno::EACCES));
        assert_eq!(may_rename(&dir, &sub, &dir, b"new", Some(&at)), Err(Errno::EACCES));
        crate::set_enforcing(false);
        assert_eq!(may_create(&dir, b"new", class::FILE), Ok(()));
        assert_eq!(may_link(&dir, &sub, Link::Rmdir), Ok(()));
        assert_eq!(may_rename(&dir, &at, &dir, b"new", None), Ok(()));
    }

    #[test]
    fn a_new_name_has_only_the_name_in_the_record() {
        let mut s = String::new();
        name_fields(b"new")(&mut s);
        assert_eq!(s, " name=\"new\"");
    }
}

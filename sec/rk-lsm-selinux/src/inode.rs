//! The labels of the inodes, `struct inode_security_struct` of security/selinux of Linux: the
//! SID of each file from the `fs_use_*` and `genfscon` rules of the policy or from the
//! attribute `security.selinux`, and the attribute that `getxattr` gives.
//!
//! Linux labels an inode when a dentry gets it, or at the policy load for the inodes that came
//! before. Here a file gets its label at its first use after the policy load, with the mount
//! and the dentry of the use, and the label stays in the blob of the inode. A new file gets
//! its label when the VFS makes it, and a write of `security.selinux` changes the label, in
//! [`crate::xattr`].

use crate::classmap::class;
use crate::policydb::fs_use;
use crate::server;
use crate::sidtab::sid;
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::dentry::Location;
use rk_vfs::inode::{Inode, Result};
use rk_vfs::security::blob::Blob;
use rk_vfs::security::id;

/// The size of the part of SELinux in the inode blob: the four words of [`slot`].
pub const INODE_BLOB: usize = 32;

/// The byte offsets of the fields in the part of SELinux in the inode blob, the fields of
/// `struct inode_security_struct` of Linux.
pub mod slot {
    /// 1 if [`SID`] and [`SCLASS`] hold the label, `initialized` of Linux.
    pub const STATE: usize = 0;
    /// The SID of the file, `sid`.
    pub const SID: usize = 8;
    /// The class of the kernel of the file, `sclass`.
    pub const SCLASS: usize = 16;
    /// The SID of the task that made the inode, `task_sid`.
    pub const TASK_SID: usize = 24;
}

/// The name of the attribute of the label, `XATTR_NAME_SELINUX` of Linux.
pub const XATTR_NAME: &[u8] = b"security.selinux";

/// The number of the policy capability `genfs_seclabel_symlinks` in
/// [`crate::POLICYCAP_NAMES`].
const POLICYCAP_GENFS_SECLABEL_SYMLINKS: u32 = 6;

/// The number of the policy capability `cgroup_seclabel` in [`crate::POLICYCAP_NAMES`].
const POLICYCAP_CGROUP_SECLABEL: u32 = 4;

/// The type bits of a mode, `S_IFMT`.
const S_IFMT: u32 = 0o170_000;

/// The byte offset of the part of SELinux in the inode blob, or `None` if the module is not
/// active.
fn inode_offset() -> Option<usize> {
    rk_vfs::security::modules()
        .iter()
        .find(|m| m.info.id.id == id::SELINUX)
        .map(|m| m.offsets.inode)
}

/// The class of the kernel of a file of the mode `mode`, as `inode_mode_to_security_class` of
/// Linux.
pub fn mode_to_class(mode: u32) -> u16 {
    match mode & S_IFMT {
        0o140_000 => class::SOCK_FILE,
        0o120_000 => class::LNK_FILE,
        0o060_000 => class::BLK_FILE,
        0o040_000 => class::DIR,
        0o020_000 => class::CHR_FILE,
        0o010_000 => class::FIFO_FILE,
        _ => class::FILE,
    }
}

/// How the `genfscon` rules label a file system type, the flags `SE_SBGENFS`, `SE_SBPROC` and
/// `SE_SBGENFS_XATTR` that `selinux_set_mnt_opts` of Linux gives a super block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Genfs {
    /// Each file has the label of the rule for its path, else the file system has one label.
    paths: bool,
    /// The paths start with the number of a process, which the rules do not have.
    proc: bool,
    /// An attribute `security.selinux` comes before the rules.
    xattr: bool,
}

fn genfs_flags(fstype: &str) -> Genfs {
    match fstype {
        "proc" => Genfs { paths: true, proc: true, xattr: false },
        "debugfs" | "binder" | "bpf" | "pstore" | "securityfs" => {
            Genfs { paths: true, ..Genfs::default() }
        }
        "sysfs" | "tracefs" | "cgroup" | "cgroup2" => {
            Genfs { paths: true, xattr: true, ..Genfs::default() }
        }
        _ => Genfs::default(),
    }
}

/// Tells if the files of the file system type `fstype` keep their labels, so a task can give
/// the label of a new file, as `SBLABEL_MNT` from `selinux_is_sblabel_mnt` of Linux: the
/// `fs_use_*` rules, and a few `genfscon` types with an attribute `security.selinux` in memory.
pub fn sblabel(fstype: &str) -> bool {
    match server::fs_use(fstype).0 {
        fs_use::XATTR | fs_use::TRANS | fs_use::TASK => true,
        fs_use::GENFS => match fstype {
            "sysfs" | "pstore" | "debugfs" | "tracefs" | "rootfs" => true,
            "cgroup" | "cgroup2" => {
                crate::policy().is_some_and(|p| p.db.policycap(POLICYCAP_CGROUP_SECLABEL))
            }
            _ => false,
        },
        _ => false,
    }
}

/// The path of a file in `/proc` without the number of the process at the start, as
/// `selinux_genfs_get_sid` of Linux: `/1/attr` gives `/attr`, and `/1` gives `/`.
fn strip_pid(path: Vec<u8>) -> Vec<u8> {
    let digits = path.iter().skip(1).take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return path;
    }
    let rest = &path[1 + digits..];
    let slashes = rest.iter().take_while(|&&c| c == b'/').count();
    let mut out = vec![b'/'];
    out.extend_from_slice(&rest[slashes..]);
    out
}

/// The SID of the attribute `security.selinux` of `inode`, as `inode_doinit_use_xattr` of
/// Linux. An inode without the attribute, or a file system without attributes, gives
/// `def_sid`. A context that the policy does not accept gets a SID of its own, as a forced
/// context. `None` for another error of the read: the file then has no label yet.
fn xattr_sid(inode: &dyn Inode, def_sid: u32) -> Option<u32> {
    match inode.get_xattr(XATTR_NAME) {
        Ok(v) => Some(server::context_to_sid(&v, def_sid, true).unwrap_or(def_sid)),
        Err(Errno::ENODATA | Errno::EOPNOTSUPP) => Some(def_sid),
        Err(_) => None,
    }
}

/// The SID of `inode` at `at` from the policy, as `inode_doinit_with_dentry` of Linux, with the
/// class of the kernel of the file. `task_sid` is the SID of the task that made the inode.
/// `None` if the label is not known: then the file has the SID `unlabeled` for now.
fn label(inode: &dyn Inode, at: &Location, task_sid: u32) -> Option<(u32, u16)> {
    let fstype = at.mount.fstype();
    let mode = inode.metadata().mode;
    let sclass = mode_to_class(mode);
    let (behavior, fs_sid) = server::fs_use(fstype);
    let sid = match behavior {
        fs_use::XATTR => xattr_sid(inode, sid::FILE)?,
        fs_use::TASK => task_sid,
        fs_use::TRANS => server::transition_sid(task_sid, fs_sid, sclass, None).ok()?,
        _ => {
            let genfs = genfs_flags(fstype);
            let symlinks =
                crate::policy().is_some_and(|p| p.db.policycap(POLICYCAP_GENFS_SECLABEL_SYMLINKS));
            if genfs.paths && (sclass != class::LNK_FILE || symlinks) {
                let path = at.dentry.fs_path();
                let path = if genfs.proc { strip_pid(path) } else { path };
                let s = server::genfs_sid(fstype, &path, sclass).unwrap_or(sid::UNLABELED);
                if genfs.xattr { xattr_sid(inode, s)? } else { s }
            } else {
                fs_sid
            }
        }
    };
    Some((sid, sclass))
}

/// Records the SID of the task that makes `inode` in its blob, as `inode_alloc_security` of
/// Linux.
pub fn alloc_security(blob: &Blob) {
    if let Some(off) = inode_offset() {
        blob.store(off + slot::TASK_SID, u64::from(crate::current_sid()));
    }
}

/// The SID of the file `inode`, as `inode_security` of Linux. A file without a label gets its
/// label from the policy here, which needs `at` for most file systems. Before the first policy
/// load, and for a file without a known label, the SID is `unlabeled`.
pub fn inode_sid(inode: &dyn Inode, at: Option<&Location>) -> u32 {
    inode_label(inode, at).0
}

/// The SID and the class of the file `inode`, as [`inode_sid`]. A file without a label has the
/// class of its mode.
pub fn inode_label(inode: &dyn Inode, at: Option<&Location>) -> (u32, u16) {
    let unlabeled = || (sid::UNLABELED, mode_to_class(inode.metadata().mode));
    if !crate::initialized() {
        return unlabeled();
    }
    let part = inode_offset().zip(rk_vfs::security::blob::inode_blob(inode));
    if let Some((off, blob)) = &part
        && blob.load(off + slot::STATE) == 1
    {
        return (blob.load(off + slot::SID) as u32, blob.load(off + slot::SCLASS) as u16);
    }
    let task_sid =
        part.as_ref().map_or(sid::KERNEL, |(off, b)| match b.load(off + slot::TASK_SID) {
            0 => sid::KERNEL,
            s => s as u32,
        });
    let Some((sid, sclass)) = at.and_then(|at| label(inode, at, task_sid)) else {
        return unlabeled();
    };
    if let Some((off, blob)) = &part {
        store(blob, *off, sid, sclass);
    }
    (sid, sclass)
}

/// Writes the label `sid` and `sclass` to the part of SELinux at `off` in the inode blob
/// `blob`. The state comes last, so a reader that sees it also sees the label.
fn store(blob: &Blob, off: usize, sid: u32, sclass: u16) {
    blob.store(off + slot::SID, u64::from(sid));
    blob.store(off + slot::SCLASS, u64::from(sclass));
    blob.store(off + slot::STATE, 1);
}

/// Gives `inode` the SID `sid` and the class of its mode, as the change of `isec` in
/// `selinux_inode_init_security` and `selinux_inode_post_setxattr` of Linux. An inode without
/// a blob keeps no label.
pub fn set_label(inode: &dyn Inode, sid: u32) {
    if let Some((off, blob)) = inode_offset().zip(rk_vfs::security::blob::inode_blob(inode)) {
        store(&blob, off, sid, mode_to_class(inode.metadata().mode));
    }
}

/// The value of the attribute `security.` + `name` of `inode`, as `selinux_inode_getsecurity`
/// of Linux: for `selinux`, the context of the file with a null byte at the end. A task with
/// `CAP_MAC_ADMIN` also gets a context that the policy does not accept. `None` before the
/// first policy load and for another name, so the attribute of the file system is the value.
pub fn getsecurity(
    inode: &dyn Inode,
    at: Option<&Location>,
    name: &[u8],
) -> Option<Result<Vec<u8>>> {
    if !crate::initialized() || name != b"selinux" {
        return None;
    }
    let sid = inode_sid(inode, at);
    let text = if crate::task::has_cap_mac_admin(false) {
        server::sid_to_context_force(sid)
    } else {
        server::sid_to_context(sid)
    };
    Some(text.map(|t| {
        let mut v = t.into_bytes();
        v.push(0);
        v
    }))
}

/// The names of the attributes that SELinux adds to the list of `inode`, as
/// `selinux_inode_listsecurity` of Linux: `security.selinux` after the first policy load. A
/// file system with the labels in its attributes lists them itself.
pub fn listsecurity(_inode: &dyn Inode, at: Option<&Location>) -> Vec<Vec<u8>> {
    if !crate::initialized()
        || at.is_some_and(|at| server::fs_use(at.mount.fstype()).0 == fs_use::XATTR)
    {
        return Vec::new();
    }
    vec![XATTR_NAME.to_vec()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use rk_vfs::dentry::{Dentry, MountNamespace, MountSource};
    use rk_vfs::inode::{InodeRef, Metadata, SetAttr};

    /// An inode of the mode `0`, with the attribute `security.selinux` `1` if it is not empty.
    struct File(u32, &'static [u8]);

    impl Inode for File {
        fn metadata(&self) -> Metadata {
            Metadata { mode: self.0, ..Metadata::default() }
        }
        fn set_attr(&self, _attr: &SetAttr) -> Result<()> {
            Ok(())
        }
        fn get_xattr(&self, name: &[u8]) -> Result<Vec<u8>> {
            if name == XATTR_NAME && !self.1.is_empty() {
                Ok(self.1.to_vec())
            } else {
                Err(Errno::ENODATA)
            }
        }
    }

    const DIR: u32 = 0o040_755;
    const REG: u32 = 0o100_644;
    const LNK: u32 = 0o120_777;

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

    /// A file system of the type `fstype` with the root `root`, and its mount.
    fn mount(fstype: &'static str, root: u32) -> Location {
        let source = MountSource { source: b"none".to_vec(), fstype, flags: 0 };
        let dentry = Dentry::new_root(Arc::new(File(root, b"")));
        let mount = MountNamespace::detached(dentry.clone(), source);
        Location { mount, dentry }
    }

    /// Adds the file `name` to the directory `dir`.
    fn child(dir: &Location, name: &str, inode: File) -> Location {
        let inode: InodeRef = Arc::new(inode);
        let dentry = dir.dentry.add_child(name.as_bytes(), inode);
        Location { mount: dir.mount.clone(), dentry }
    }

    fn context(at: &Location) -> Vec<u8> {
        getsecurity(&**at.inode(), Some(at), b"selinux").unwrap().unwrap()
    }

    #[test]
    fn the_class_of_a_file_comes_from_its_mode() {
        assert_eq!(mode_to_class(DIR), class::DIR);
        assert_eq!(mode_to_class(REG), class::FILE);
        assert_eq!(mode_to_class(LNK), class::LNK_FILE);
        assert_eq!(mode_to_class(0o140_777), class::SOCK_FILE);
        assert_eq!(mode_to_class(0o010_600), class::FIFO_FILE);
        assert_eq!(mode_to_class(0o020_600), class::CHR_FILE);
        assert_eq!(mode_to_class(0o060_600), class::BLK_FILE);
        assert_eq!(mode_to_class(0), class::FILE);
    }

    #[test]
    fn the_paths_in_proc_lose_the_number_of_the_process() {
        let strip = |p: &[u8]| strip_pid(p.to_vec());
        assert_eq!(strip(b"/1/attr"), b"/attr");
        assert_eq!(strip(b"/123/attr/current"), b"/attr/current");
        assert_eq!(strip(b"/1"), b"/");
        assert_eq!(strip(b"/"), b"/");
        assert_eq!(strip(b"/sys/kernel"), b"/sys/kernel");
        assert_eq!(strip(b"/12x"), b"/x");
    }

    #[test]
    fn the_policy_gives_the_behavior_of_each_file_system_type() {
        let _guard = setup();
        let sid_of = |t: &str| server::context_to_sid(t.as_bytes(), 0, false).unwrap();
        assert_eq!(server::fs_use("ext4"), (fs_use::XATTR, sid_of("system_u:object_r:fs_t:s0")));
        assert_eq!(server::fs_use("pipefs").0, fs_use::TASK);
        assert_eq!(
            server::fs_use("tmpfs"),
            (fs_use::TRANS, sid_of("system_u:object_r:tmpfs_t:s0"))
        );
        assert_eq!(server::fs_use("proc"), (fs_use::GENFS, sid_of("system_u:object_r:proc_t:s0")));
        assert_eq!(server::fs_use("rootfs"), (fs_use::NONE, sid::UNLABELED));
        assert_eq!(
            server::genfs_sid("proc", b"/sys/kernel", class::DIR),
            Ok(sid_of("system_u:object_r:sysfs_t:s0"))
        );
        assert_eq!(
            server::genfs_sid("proc", b"/kmsg", class::FILE),
            Ok(sid_of("system_u:object_r:etc_t:s1"))
        );
        assert_eq!(
            server::genfs_sid("proc", b"/kmsg", class::DIR),
            Ok(sid_of("system_u:object_r:proc_t:s0"))
        );
        assert_eq!(server::genfs_sid("rootfs", b"/", class::DIR), Err(Errno::ENOENT));
    }

    #[test]
    fn a_file_of_proc_gets_the_label_of_the_rule_for_its_path() {
        let _guard = setup();
        let root = mount("proc", DIR);
        assert_eq!(context(&root), b"system_u:object_r:proc_t:s0\0");
        let sys = child(&root, "sys", File(DIR, b""));
        assert_eq!(context(&sys), b"system_u:object_r:sysfs_t:s0\0");
        let kmsg = child(&root, "kmsg", File(REG, b""));
        assert_eq!(context(&kmsg), b"system_u:object_r:etc_t:s1\0");
        let pid = child(&root, "1", File(DIR, b""));
        let attr = child(&pid, "sys", File(DIR, b""));
        assert_eq!(context(&attr), b"system_u:object_r:sysfs_t:s0\0");
        let link = child(&root, "self", File(LNK, b""));
        assert_eq!(context(&link), b"system_u:object_r:proc_t:s0\0");
        // The label stays in the blob, also for a use without the path.
        assert_eq!(inode_sid(&**kmsg.inode(), None), inode_sid(&**kmsg.inode(), Some(&kmsg)));
        assert_eq!(listsecurity(&**kmsg.inode(), Some(&kmsg)), vec![XATTR_NAME.to_vec()]);
    }

    #[test]
    fn the_other_behaviors_label_the_files() {
        let _guard = setup();
        // fs_use_xattr: the attribute, else the SID `file`.
        let ext4 = mount("ext4", DIR);
        assert_eq!(context(&ext4), b"system_u:object_r:unlabeled_t:s0\0");
        let etc = child(&ext4, "etc", File(DIR, b"system_u:object_r:etc_t:s0\0"));
        assert_eq!(context(&etc), b"system_u:object_r:etc_t:s0\0");
        assert!(listsecurity(&**etc.inode(), Some(&etc)).is_empty());
        // fs_use_trans: the type transition of the task in the file system.
        let tmp = mount("tmpfs", DIR);
        assert_eq!(context(&tmp), b"system_u:object_r:tmpfs_t:s0\0");
        // genfscon for `/` only, and no rule at all.
        let selinuxfs = mount("selinuxfs", DIR);
        let enforce = child(&selinuxfs, "enforce", File(REG, b""));
        assert_eq!(context(&enforce), b"system_u:object_r:security_t:s0\0");
        let rootfs = mount("rootfs", DIR);
        assert_eq!(context(&rootfs), b"system_u:object_r:unlabeled_t:s0\0");
        // Another name of `security.` is for the file system.
        assert!(getsecurity(&**rootfs.inode(), Some(&rootfs), b"ima").is_none());
    }
}

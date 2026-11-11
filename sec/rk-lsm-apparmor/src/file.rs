//! The mediation of the open files, as file.c and the file hooks of lsm.c of Linux.
//!
//! The blob of an open file holds the label of the task that made the file and the permissions
//! that the policy checked, as `struct aa_file_ctx` of Linux. A read, a write, a lock or a map
//! of the file checks the policy again only if the task has an other label, or if it asks for
//! more permissions. A file that an unconfined task made has no check, as on Linux.
//!
//! As in [`crate::domain`], each profile acts in complain mode: the log tells what the policy
//! does not allow, and the operation goes on.

use crate::domain::{self, FileAudit, audit_file, str_perms};
use crate::policy::{Mode, Profile};
use crate::unpack::{Perms, perm};
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::mman::{MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};
use rk_abi::native::open as o;
use rk_vfs::cred::Cred;
use rk_vfs::dentry::Location;
use rk_vfs::file::File;
use rk_vfs::inode::FileType;
use rk_vfs::security::id;

/// The size of the part of AppArmor in the blob of a file: the label and the permissions.
pub const FILE_BLOB: usize = 16;

/// The offset of the label number in the part of AppArmor.
const LABEL: usize = 0;
/// The offset of the permissions that the policy checked.
const ALLOW: usize = 8;

/// The names of the file operations in the log, `OP_*` of Linux.
pub mod op {
    /// `OP_OPEN`.
    pub const OPEN: &str = "open";
    /// `OP_FPERM`: a read or a write.
    pub const FPERM: &str = "file_perm";
    /// `OP_FLOCK`.
    pub const FLOCK: &str = "file_lock";
    /// `OP_FMMAP`.
    pub const FMMAP: &str = "file_mmap";
}

/// `LOCK_EX` of `flock`.
const LOCK_EX: u32 = 2;
/// `LOCK_NB` of `flock`.
const LOCK_NB: u32 = 4;

/// The byte offset of the part of AppArmor in the blob of a file, or `None` if the module is
/// not active.
fn file_offset() -> Option<usize> {
    rk_vfs::security::modules()
        .iter()
        .find(|m| m.info.id.id == id::APPARMOR)
        .map(|m| m.offsets.file)
}

/// The permissions of an open with the flags `flags`, `aa_map_file_to_perms` of Linux. An
/// open with `O_APPEND` asks for an append and not for a write. `O_TRUNC` asks for a write and
/// `O_CREAT` for a create.
pub fn map_open_flags(flags: u32) -> u32 {
    // The access mode of the file, as `OPEN_FMODE` of Linux: 1 is a read and 2 is a write.
    let fmode = (flags + 1) & o::O_ACCMODE;
    let mut p = 0;
    if fmode & 2 != 0 {
        p |= perm::WRITE;
    }
    if fmode & 1 != 0 {
        p |= perm::READ;
    }
    if flags & o::O_APPEND != 0 && p & perm::WRITE != 0 {
        p = (p & !perm::WRITE) | perm::APPEND;
    }
    if flags & o::O_TRUNC != 0 {
        p |= perm::WRITE;
    }
    if flags & o::O_CREAT != 0 {
        p |= perm::CREATE;
    }
    p
}

/// The permissions of a map with the protection `prot` and the flags `flags`, as `common_mmap`
/// of Linux. A private map does not write the file, so it does not ask for a write.
pub fn map_mmap_prot(prot: u64, flags: u64) -> u32 {
    let mut mask = 0;
    if prot & u64::from(PROT_READ) != 0 {
        mask |= perm::READ;
    }
    if prot & u64::from(PROT_WRITE) != 0 && flags & u64::from(MAP_PRIVATE) == 0 {
        mask |= perm::WRITE;
    }
    if prot & u64::from(PROT_EXEC) != 0 {
        mask |= perm::EXEC_MMAP;
    }
    mask
}

/// The name of a file for the rules, as `aa_path_name` of Linux: the path from the root of the
/// name space, with a `/` at the end for a directory other than the root.
pub fn path_name(path: Vec<u8>, dir: bool) -> Vec<u8> {
    let mut name = path;
    if dir && name != b"/" {
        name.push(b'/');
    }
    name
}

/// Checks the permissions `request` on the file at `at` for the profile `p`, and logs the
/// result, as `profile_path_perm` and `__aa_path_perm` of Linux. `fsuid` is the file system
/// user ID of the task. Tells if the policy allows the request.
fn path_perm(op: &'static str, p: &Profile, at: &Location, request: u32, fsuid: u32) -> bool {
    if p.mode == Mode::Unconfined {
        return true;
    }
    let meta = at.inode().metadata();
    let dir = meta.file_type() == Some(FileType::Directory);
    let name = path_name(at.absolute_path(), dir);
    let owner = fsuid == meta.uid;
    let perms = p.rules.as_ref().map_or(Perms::default(), |r| str_perms(&r.file, &name, owner));
    let error = (request & !perms.allow != 0).then_some(Errno::EACCES);
    let a = FileAudit { op, request, name: &name, target: None, ouid: meta.uid, info: None, error };
    audit_file(Some(p), &perms, &a);
    error.is_none()
}

/// `apparmor_file_alloc_security` of Linux: the file gets the label of the task.
pub fn file_alloc(file: &File) {
    if let Some(off) = file_offset() {
        let cred = rk_vfs::cred::current();
        file.security().store(off + LABEL, domain::label_id(&cred));
        file.security().store(off + ALLOW, 0);
    }
}

/// `apparmor_file_open` of Linux: the check of an open with the flags `flags` by a task with
/// `cred`. The file keeps the permissions of the open.
pub fn file_open(file: &File, cred: &Cred, flags: u32) {
    let Some(off) = file_offset() else { return };
    // A file that is not in the tree of a file system has no path to check.
    let Some(at) = file.location() else { return };
    let request = map_open_flags(flags);
    // Each profile of a stack checks the open.
    for p in domain::label_of(cred).iter().filter(|p| p.mode != Mode::Unconfined) {
        path_perm(op::OPEN, p, at, request, cred.fsuid);
    }
    file.security().store(off + ALLOW, u64::from(request));
}

/// The check of the permissions `request` on an open file, `aa_file_perm` and
/// `__file_path_perm` of Linux.
pub fn file_perm(op: &'static str, file: &File, request: u32) {
    let Some(off) = file_offset() else { return };
    let cred = rk_vfs::cred::current();
    let label = domain::label_id(&cred);
    if label == 0 {
        return;
    }
    let blob = file.security();
    let flabel = blob.load(off + LABEL);
    let allow = blob.load(off + ALLOW) as u32;
    let denied = request & !allow;
    // A file of an unconfined task goes to the others with no check, as `__file_is_delegated`.
    // The same label with no new permission needs no check.
    if flabel == 0 || (denied == 0 && flabel == label) {
        return;
    }
    let Some(at) = file.location() else { return };
    // The newest version of the label of the task. A profile that was removed goes out of
    // the label. Each profile of a stack checks the access.
    let l = domain::label_by_id(label);
    // Each profile makes its record, so the check does not stop at the first denial.
    let check = |l: &[Arc<Profile>]| {
        let confined = l.iter().filter(|p| p.mode != Mode::Unconfined);
        confined.filter(|p| !path_perm(op, p, at, request, cred.fsuid)).count() == 0
    };
    let mut ok = true;
    if flabel != label {
        ok = check(&l);
    }
    if denied != 0 && ok {
        // The label of the file also checks the new permissions.
        ok = if flabel == label { check(&l) } else { check(&domain::label_by_id(flabel)) };
    }
    // As `update_file_ctx` of Linux. This kernel keeps one label for a file, so the file gets
    // the label of the task.
    if ok {
        blob.store(off + LABEL, label);
        blob.store(off + ALLOW, u64::from(allow | request));
    }
}

/// `apparmor_file_lock` of Linux: a `flock` with the operation `cmd`. An exclusive lock also
/// asks for a write.
pub fn file_lock(file: &File, cmd: u32) {
    let mut mask = perm::LOCK;
    if cmd & !LOCK_NB == LOCK_EX {
        mask |= perm::WRITE;
    }
    file_perm(op::FLOCK, file, mask);
}

/// `apparmor_mmap_file` of Linux: a map of `file` with the protection `prot` and the flags
/// `flags`.
pub fn mmap_file(file: Option<&File>, prot: u64, flags: u64) {
    if let Some(file) = file {
        file_perm(op::FMMAP, file, map_mmap_prot(prot, flags));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flags_of_an_open_give_the_permissions_of_linux() {
        assert_eq!(map_open_flags(o::O_RDONLY), perm::READ);
        assert_eq!(map_open_flags(o::O_WRONLY), perm::WRITE);
        assert_eq!(map_open_flags(o::O_RDWR), perm::READ | perm::WRITE);
        assert_eq!(map_open_flags(o::O_WRONLY | o::O_APPEND), perm::APPEND);
        assert_eq!(map_open_flags(o::O_RDWR | o::O_APPEND), perm::READ | perm::APPEND);
        assert_eq!(map_open_flags(o::O_RDONLY | o::O_APPEND), perm::READ);
        assert_eq!(
            map_open_flags(o::O_WRONLY | o::O_CREAT | o::O_TRUNC),
            perm::WRITE | perm::CREATE
        );
        assert_eq!(
            map_open_flags(o::O_WRONLY | o::O_APPEND | o::O_TRUNC),
            perm::APPEND | perm::WRITE
        );
        // The access mode 3 is neither a read nor a write, as `OPEN_FMODE` of Linux.
        assert_eq!(map_open_flags(3), 0);
    }

    #[test]
    fn a_map_asks_for_the_permissions_of_its_protection() {
        let prot = u64::from(PROT_READ | PROT_WRITE | PROT_EXEC);
        let private = u64::from(MAP_PRIVATE);
        assert_eq!(map_mmap_prot(prot, 1), perm::READ | perm::WRITE | perm::EXEC_MMAP);
        assert_eq!(map_mmap_prot(prot, private), perm::READ | perm::EXEC_MMAP);
        assert_eq!(map_mmap_prot(0, 1), 0);
        assert_eq!(domain::mask_text(perm::READ | perm::EXEC_MMAP), "rm");
        assert_eq!(domain::mask_text(perm::LOCK | perm::WRITE), "wk");
    }

    #[test]
    fn the_rules_of_rk_test_allow_a_create_in_tmp_and_not_a_lock() {
        use crate::policy::{Change, Ns, replace};
        let ns = Ns::new("t");
        assert!(replace(&ns, Change::Load, include_bytes!("../tests/rk_test.bin")).is_ok());
        let p = ns.lookup("rk_test").unwrap();
        let file = &p.rules.as_ref().unwrap().file;
        let tmp = str_perms(file, b"/tmp/rk-aa-w", true);
        let open = map_open_flags(o::O_WRONLY | o::O_CREAT | o::O_TRUNC);
        assert_eq!(open & !tmp.allow, 0);
        assert_eq!((perm::LOCK | perm::WRITE) & !tmp.allow, perm::LOCK);
        let other = str_perms(file, b"/etc/rk_test.aa", true);
        assert_eq!((perm::READ | perm::EXEC_MMAP) & !other.allow, perm::READ | perm::EXEC_MMAP);
        assert_eq!(perm::READ & !str_perms(file, b"/usr/bin/", true).allow, perm::READ);
    }

    #[test]
    fn a_directory_has_a_slash_at_the_end_of_its_name() {
        assert_eq!(path_name(b"/tmp".to_vec(), true), b"/tmp/");
        assert_eq!(path_name(b"/".to_vec(), true), b"/");
        assert_eq!(path_name(b"/etc/hostname".to_vec(), false), b"/etc/hostname");
    }
}

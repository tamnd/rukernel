//! The mediation of the open files, as file.c and the file hooks of lsm.c of Linux.
//!
//! The blob of an open file holds the label of the task that made the file and the permissions
//! that the policy checked, as `struct aa_file_ctx` of Linux. A read, a write, a lock or a map
//! of the file checks the policy again only if the task has an other label, or if it asks for
//! more permissions. A file that an unconfined task made has no check, as on Linux.
//!
//! An access that the policy does not allow gives `EACCES` for a profile in enforce mode, as
//! in [`crate::domain`]. Each profile of a stack makes its record, and the access gives the error
//! of the last profile that denies it, as `fn_for_each` of Linux.

use crate::dfa::NOMATCH;
use crate::domain::{self, FileAudit, audit_file, str_perms};
use crate::net;
use crate::policy::{Mode, Profile};
use crate::unpack::{Perms, class, perm, x};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::mman::{MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};
use rk_abi::native::open as o;
use rk_abi::native::stat::{S_IFDIR, S_IFMT};
use rk_vfs::cred::Cred;
use rk_vfs::dentry::Location;
use rk_vfs::file::File;
use rk_vfs::inode::{FileType, Result};
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
    /// `OP_UNLINK`.
    pub const UNLINK: &str = "unlink";
    /// `OP_MKDIR`.
    pub const MKDIR: &str = "mkdir";
    /// `OP_RMDIR`.
    pub const RMDIR: &str = "rmdir";
    /// `OP_MKNOD`. An open that makes a file also has this name.
    pub const MKNOD: &str = "mknod";
    /// `OP_TRUNC`.
    pub const TRUNC: &str = "truncate";
    /// `OP_LINK`.
    pub const LINK: &str = "link";
    /// `OP_SYMLINK`.
    pub const SYMLINK: &str = "symlink";
    /// `OP_RENAME_SRC`.
    pub const RENAME_SRC: &str = "rename_src";
    /// `OP_RENAME_DEST`.
    pub const RENAME_DEST: &str = "rename_dest";
    /// `OP_CHMOD`.
    pub const CHMOD: &str = "chmod";
    /// `OP_CHOWN`.
    pub const CHOWN: &str = "chown";
    /// `OP_GETATTR`.
    pub const GETATTR: &str = "getattr";
}

/// `LOCK_EX` of `flock`.
const LOCK_EX: u32 = 2;
/// `LOCK_NB` of `flock`.
const LOCK_NB: u32 = 4;

/// `RENAME_EXCHANGE` of `renameat2`.
const RENAME_EXCHANGE: u32 = 2;

/// The permission that tells that a link must be a subset of its target, `AA_LINK_SUBSET` of
/// Linux. It has the bit of the lock.
const LINK_SUBSET: u32 = perm::LOCK;

/// The permissions that the old name of a rename asks for.
const RENAME_SRC: u32 = perm::READ | perm::GETATTR | perm::WRITE | perm::SETATTR | perm::DELETE;
/// The permissions that the new name of a rename asks for.
const RENAME_DEST: u32 = perm::WRITE | perm::SETATTR | perm::CREATE;

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

/// The condition of a check of a path, `struct path_cond` of Linux: the owner of the file and
/// the type. The name of a directory ends with a `/`.
#[derive(Clone, Copy)]
struct Cond {
    uid: u32,
    dir: bool,
}

impl Cond {
    /// The condition of the file at `at`.
    fn of(at: &Location) -> Self {
        let meta = at.inode().metadata();
        Self { uid: meta.uid, dir: meta.file_type() == Some(FileType::Directory) }
    }
}

/// The name of the new file `name` in the directory `dir`, for a file that is not there yet.
fn child_name(dir: &Location, name: &[u8], is_dir: bool) -> Vec<u8> {
    let mut path = dir.absolute_path();
    if path != b"/" {
        path.push(b'/');
    }
    path.extend_from_slice(name);
    path_name(path, is_dir)
}

/// Checks the permissions `request` on the file with the name `name` for the profile `p`, and
/// logs the result, as `__aa_path_perm` of Linux. `fsuid` is the file system user ID of the
/// task.
///
/// # Errors
///
/// Gives `EACCES` if the policy does not allow the request, except in complain mode.
fn name_perm(
    op: &'static str,
    p: &Profile,
    name: &[u8],
    request: u32,
    cond: Cond,
    fsuid: u32,
) -> Result<()> {
    if p.mode == Mode::Unconfined {
        return Ok(());
    }
    let owner = fsuid == cond.uid;
    let perms = p.rules.as_ref().map_or(Perms::default(), |r| str_perms(&r.file, name, owner));
    let error = (request & !perms.allow != 0).then_some(Errno::EACCES);
    let a = FileAudit { op, request, name, target: None, ouid: cond.uid, info: None, error };
    audit_file(Some(p), &perms, &a)
}

/// The check of each profile of `l` that is not unconfined, `fn_for_each_confined` of Linux.
/// Each profile makes its record, so the check does not stop at the first denial.
///
/// # Errors
///
/// Gives the error of the last profile that denies the request.
fn label_name_perm(
    op: &'static str,
    l: &[Arc<Profile>],
    name: &[u8],
    request: u32,
    cond: Cond,
    fsuid: u32,
) -> Result<()> {
    let mut result = Ok(());
    for p in l.iter().filter(|p| p.mode != Mode::Unconfined) {
        if let Err(e) = name_perm(op, p, name, request, cond, fsuid) {
            result = Err(e);
        }
    }
    result
}

/// [`label_name_perm`] for the file at `at`, `aa_path_perm` of Linux.
///
/// # Errors
///
/// Gives the error of the last profile that denies the request.
pub(crate) fn label_path_perm(
    op: &'static str,
    l: &[Arc<Profile>],
    at: &Location,
    request: u32,
    fsuid: u32,
) -> Result<()> {
    let cond = Cond::of(at);
    let name = path_name(at.absolute_path(), cond.dir);
    label_name_perm(op, l, &name, request, cond, fsuid)
}

/// The label of the current task and its file system user ID. `None` is `unconfined`, which
/// has no check.
fn current_label() -> Option<(domain::Label, u32)> {
    let cred = rk_vfs::cred::current();
    if domain::label_id(&cred) == 0 {
        return None;
    }
    Some((domain::label_of(&cred), cred.fsuid))
}

/// The check of the permissions `request` on the file at `at` by the current task,
/// `common_perm_cond` of Linux. It is for a remove, a truncate, a `chmod`, a `chown` and a
/// `stat`.
///
/// # Errors
///
/// Gives `EACCES` if the policy does not allow the request.
pub fn path_cond(op: &'static str, at: &Location, request: u32) -> Result<()> {
    let Some((l, fsuid)) = current_label() else { return Ok(()) };
    label_path_perm(op, &l, at, request, fsuid)
}

/// The check of a new file `name` with the mode `mode` in the directory `dir`,
/// `common_perm_create` of Linux. The task is the owner of the new file.
///
/// # Errors
///
/// Gives `EACCES` if the policy does not allow the create.
pub fn path_create(op: &'static str, dir: &Location, name: &[u8], mode: u32) -> Result<()> {
    let Some((l, fsuid)) = current_label() else { return Ok(()) };
    let cond = Cond { uid: fsuid, dir: mode & S_IFMT == S_IFDIR };
    let name = child_name(dir, name, cond.dir);
    label_name_perm(op, &l, &name, perm::CREATE, cond, fsuid)
}

/// `apparmor_path_rename` of Linux: a rename of the file `old` to the name `name` in `dir`. `new`
/// is the file that has the new name now. The old name asks for the permissions of a read, a
/// write and a delete, and the new name for a write and a create. An exchange also checks the
/// two names the other way.
///
/// # Errors
///
/// Gives `EACCES` if the policy does not allow the rename.
pub fn path_rename(
    old: &Location,
    dir: &Location,
    name: &[u8],
    new: Option<&Location>,
    flags: u32,
) -> Result<()> {
    let Some((l, fsuid)) = current_label() else { return Ok(()) };
    let cond = Cond::of(old);
    if flags & RENAME_EXCHANGE != 0
        && let Some(new) = new
    {
        // As Linux, the condition of the other way has the type of the new file and the owner
        // of the old file.
        let other = Cond { uid: cond.uid, dir: Cond::of(new).dir };
        let new_name = child_name(dir, name, other.dir);
        label_name_perm(op::RENAME_SRC, &l, &new_name, RENAME_SRC, other, fsuid)?;
        let old_name = path_name(old.absolute_path(), other.dir);
        label_name_perm(op::RENAME_DEST, &l, &old_name, RENAME_DEST, other, fsuid)?;
    }
    let old_name = path_name(old.absolute_path(), cond.dir);
    label_name_perm(op::RENAME_SRC, &l, &old_name, RENAME_SRC, cond, fsuid)?;
    let new_name = child_name(dir, name, cond.dir);
    label_name_perm(op::RENAME_DEST, &l, &new_name, RENAME_DEST, cond, fsuid)
}

/// `apparmor_path_link` and `aa_path_link` of Linux: a hard link with the name `name` in `dir`
/// to the file `old`.
///
/// # Errors
///
/// Gives `EACCES` if the policy does not allow the link.
pub fn path_link(old: &Location, dir: &Location, name: &[u8]) -> Result<()> {
    let Some((l, fsuid)) = current_label() else { return Ok(()) };
    let cond = Cond::of(old);
    // The names of a link have no `/` at the end, as `aa_path_link` of Linux.
    let lname = child_name(dir, name, false);
    let tname = old.absolute_path();
    let mut result = Ok(());
    for p in l.iter().filter(|p| p.mode != Mode::Unconfined) {
        if let Err(e) = profile_path_link(p, &lname, &tname, cond, fsuid) {
            result = Err(e);
        }
    }
    result
}

/// Tells if the exec transition of a link is a subset of the transition of its target,
/// `xindex_is_subset` of Linux.
fn xindex_is_subset(link: u32, target: u32) -> bool {
    (link & !x::UNSAFE) == (target & !x::UNSAFE)
        && (link & x::UNSAFE == 0 || target & x::UNSAFE != 0)
}

/// The check of a link with the name `lname` to the file `tname` for the profile `p`,
/// `profile_path_link` of Linux. The pair of the names must have the link permission. If the
/// pair has the subset permission, the permissions of the link must be a subset of the
/// permissions of the target.
///
/// # Errors
///
/// Gives `EACCES` if the policy does not allow the link, except in complain mode.
fn profile_path_link(
    p: &Profile,
    lname: &[u8],
    tname: &[u8],
    cond: Cond,
    fsuid: u32,
) -> Result<()> {
    let owner = fsuid == cond.uid;
    let pdb = p.rules.as_ref().map(|r| &r.file);
    let mut request = perm::LINK;
    let mut info = None;
    let (state, mut lperms) = match pdb {
        Some(f) => domain::str_perms_at(f, f.start[class::FILE], lname, owner),
        None => (NOMATCH, Perms::default()),
    };
    let error = 'check: {
        let Some(f) = pdb.filter(|_| lperms.allow & perm::LINK != 0) else {
            break 'check Some(Errno::EACCES);
        };
        // The target follows the link name after a null byte.
        let next = f.dfa.as_ref().map_or(NOMATCH, |d| d.next(state, 0));
        let (_, perms) = domain::str_perms_at(f, next, tname, owner);
        // The audit, quiet and kill masks of a link are in the entry of the pair.
        lperms.audit = perms.audit;
        lperms.quiet = perms.quiet;
        lperms.kill = perms.kill;
        if perms.allow & perm::LINK == 0 {
            info = Some("target restricted");
            lperms = perms;
            break 'check Some(Errno::EACCES);
        }
        if perms.allow & LINK_SUBSET == 0 {
            break 'check None;
        }
        // The permissions of the link, other than the link, must be a subset of the
        // permissions of the target.
        let perms = str_perms(f, tname, owner);
        request = lperms.allow & !perm::LINK;
        lperms.allow &= perms.allow | perm::LINK;
        request |= domain::AUDIT_FILE_MASK & (lperms.allow & !perms.allow);
        if request & !lperms.allow != 0 {
            break 'check Some(Errno::EACCES);
        }
        if lperms.allow & perm::EXEC != 0 && !xindex_is_subset(lperms.xindex, perms.xindex) {
            lperms.allow &= !perm::EXEC;
            request |= perm::EXEC;
            info = Some("link not subset of target");
            break 'check Some(Errno::EACCES);
        }
        None
    };
    let target = String::from_utf8_lossy(tname);
    let a = FileAudit {
        op: op::LINK,
        request,
        name: lname,
        target: Some(&target),
        ouid: cond.uid,
        info,
        error,
    };
    audit_file(Some(p), &lperms, &a)
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
///
/// # Errors
///
/// Gives `EACCES` if the policy does not allow the open.
pub fn file_open(file: &File, cred: &Cred, flags: u32) -> Result<()> {
    let Some(off) = file_offset() else { return Ok(()) };
    // A file that is not in the tree of a file system has no path to check.
    let Some(at) = file.location() else { return Ok(()) };
    let request = map_open_flags(flags);
    // Each profile of a stack checks the open.
    let result = label_path_perm(op::OPEN, &domain::label_of(cred), at, request, cred.fsuid);
    file.security().store(off + ALLOW, u64::from(request));
    result
}

/// The check of the permissions `request` on an open file, `aa_file_perm` and
/// `__file_path_perm` of Linux.
///
/// # Errors
///
/// Gives `EACCES` if the policy does not allow the access.
pub fn file_perm(op: &'static str, file: &File, request: u32) -> Result<()> {
    let Some(off) = file_offset() else { return Ok(()) };
    let cred = rk_vfs::cred::current();
    let label = domain::label_id(&cred);
    if label == 0 {
        return Ok(());
    }
    let blob = file.security();
    let flabel = blob.load(off + LABEL);
    let allow = blob.load(off + ALLOW) as u32;
    let denied = request & !allow;
    // A file of an unconfined task goes to the others with no check, as `__file_is_delegated`.
    // The same label with no new permission needs no check.
    if flabel == 0 || (denied == 0 && flabel == label) {
        return Ok(());
    }
    let Some(at) = file.location() else {
        return sock_perm(op, file, request, denied, (label, flabel), allow);
    };
    // The newest version of the label of the task. A profile that was removed goes out of
    // the label. Each profile of a stack checks the access.
    let l = domain::label_by_id(label);
    let check = |l: &[Arc<Profile>]| label_path_perm(op, l, at, request, cred.fsuid);
    if flabel != label {
        check(&l)?;
    }
    if denied != 0 {
        // The label of the file also checks the new permissions.
        if flabel == label { check(&l) } else { check(&domain::label_by_id(flabel)) }?;
    }
    // As `update_file_ctx` of Linux. This kernel keeps one label for a file, so the file gets
    // the label of the task.
    blob.store(off + LABEL, label);
    blob.store(off + ALLOW, u64::from(allow | request));
    Ok(())
}

/// The check of a read or a write of a socket file, `__file_sock_perm` of Linux. The label of
/// the task checks the access, and the label of the file also checks the new permissions
/// `denied`. `labels` has the numbers of the labels of the task and of the file. A file that is
/// not a socket has no check.
///
/// # Errors
///
/// Gives `EACCES` if the policy does not allow the access.
fn sock_perm(
    op: &'static str,
    file: &File,
    request: u32,
    denied: u32,
    labels: (u64, u64),
    allow: u32,
) -> Result<()> {
    let (label, flabel) = labels;
    let Some(off) = file_offset() else { return Ok(()) };
    let (Some(socket), Some(security)) = (rk_net::socket_of(file), rk_net::sock_security(file))
    else {
        return Ok(());
    };
    let names = rk_net::LsmNames(&*socket);
    let sock = rk_net::lsm_sock(&*socket, security, &names);
    let mut result = net::sock_file_perm(&domain::label_by_id(label), op, request, &sock);
    if denied != 0 {
        if let Err(e) = net::sock_file_perm(&domain::label_by_id(flabel), op, request, &sock) {
            result = Err(e);
        }
    }
    result?;
    let blob = file.security();
    blob.store(off + LABEL, label);
    blob.store(off + ALLOW, u64::from(allow | request));
    Ok(())
}

/// `apparmor_file_lock` of Linux: a `flock` with the operation `cmd`. An exclusive lock also
/// asks for a write.
///
/// # Errors
///
/// Gives `EACCES` if the policy does not allow the lock.
pub fn file_lock(file: &File, cmd: u32) -> Result<()> {
    let mut mask = perm::LOCK;
    if cmd & !LOCK_NB == LOCK_EX {
        mask |= perm::WRITE;
    }
    file_perm(op::FLOCK, file, mask)
}

/// `apparmor_mmap_file` of Linux: a map of `file` with the protection `prot` and the flags
/// `flags`.
///
/// # Errors
///
/// Gives `EACCES` if the policy does not allow the map.
pub fn mmap_file(file: Option<&File>, prot: u64, flags: u64) -> Result<()> {
    file.map_or(Ok(()), |file| file_perm(op::FMMAP, file, map_mmap_prot(prot, flags)))
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
    fn the_exec_of_a_link_must_be_the_exec_of_its_target() {
        let name = x::NAME | 1;
        assert!(xindex_is_subset(name, name));
        assert!(xindex_is_subset(name, name | x::UNSAFE));
        assert!(!xindex_is_subset(name | x::UNSAFE, name));
        assert!(!xindex_is_subset(name, x::NAME | 2));
    }

    #[test]
    fn a_directory_has_a_slash_at_the_end_of_its_name() {
        assert_eq!(path_name(b"/tmp".to_vec(), true), b"/tmp/");
        assert_eq!(path_name(b"/".to_vec(), true), b"/");
        assert_eq!(path_name(b"/etc/hostname".to_vec(), false), b"/etc/hostname");
    }
}

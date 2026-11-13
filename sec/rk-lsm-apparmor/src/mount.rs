//! The mediation of the mounts, as mount.c of Linux.
//!
//! A profile with `mount` rules can mount, unmount, move a mount and change the root only if a
//! rule allows it. A `mount` rule matches the mount point, the source, the type of the file
//! system, the flags and the options, in this order. A `umount` rule matches the mount point,
//! and a `pivot_root` rule matches the new root and then the place of the old root. A profile
//! without `mount` rules does not check the mounts.
//!
//! A denial gives `EACCES` and a record of the class `mount`:
//!
//! ```text
//! apparmor="DENIED" operation="mount" class="mount" info="failed flags match" error=-13
//!     profile="P" name="/mnt/" pid=PID comm="COMM" fstype="tmpfs" srcname="none"
//!     flags="rw, nosuid"
//! ```

use crate::audit::{self, Kind};
use crate::domain::{self, mode_kind, outcome};
use crate::file::path_name;
use crate::label;
use crate::policy::{Mode, Profile};
use crate::unpack::{Pdb, Perms, class};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::mount::{
    MS_ACTIVE, MS_BIND, MS_BORN, MS_DIRSYNC, MS_I_VERSION, MS_KERNMOUNT, MS_MANDLOCK, MS_MOVE,
    MS_NOATIME, MS_NODEV, MS_NODIRATIME, MS_NOEXEC, MS_NOSEC, MS_NOSUID, MS_NOUSER, MS_POSIXACL,
    MS_PRIVATE, MS_RDONLY, MS_REC, MS_RELATIME, MS_REMOUNT, MS_SHARED, MS_SILENT, MS_SLAVE,
    MS_STRICTATIME, MS_SYNCHRONOUS, MS_UNBINDABLE,
};
use rk_vfs::dentry::Location;
use rk_vfs::inode::{FileType, Result};
use rk_vfs::security::MountReq;

/// `AA_MAY_PIVOTROOT`.
const MAY_PIVOTROOT: u32 = 0x01;
/// `AA_MAY_MOUNT`.
const MAY_MOUNT: u32 = 0x02;
/// `AA_MAY_UMOUNT`.
const MAY_UMOUNT: u32 = 0x04;
/// `AA_AUDIT_DATA`: the record has the options.
const AUDIT_DATA: u32 = 0x40;
/// `AA_MNT_CONT_MATCH`: the rule also matches the options.
const CONT_MATCH: u32 = 0x40;
/// The flags that the rules do not see, `AA_MS_IGNORE_MASK`.
const IGNORE: u32 = MS_KERNMOUNT | MS_NOSEC | MS_ACTIVE | MS_BORN;
/// The flags of a change of the propagation.
const PROPAGATION: u32 = MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE;

/// The text of each result of [`do_match`], `mnt_info_table` of Linux.
const INFO: [&str; 7] = [
    "match succeeded",
    "failed mntpnt match",
    "failed srcname match",
    "failed type match",
    "failed flags match",
    "failed data match",
    "failed perms check",
];

/// The text of the flags in a record, `audit_mnt_flags` of Linux.
fn flags_text(flags: u32) -> String {
    let rec = flags & MS_REC != 0;
    let mut s = String::from(if flags & MS_RDONLY != 0 { "ro" } else { "rw" });
    let names: [(u32, &str, &str); 21] = [
        (MS_NOSUID, "nosuid", ""),
        (MS_NODEV, "nodev", ""),
        (MS_NOEXEC, "noexec", ""),
        (MS_SYNCHRONOUS, "sync", ""),
        (MS_REMOUNT, "remount", ""),
        (MS_MANDLOCK, "mand", ""),
        (MS_DIRSYNC, "dirsync", ""),
        (MS_NOATIME, "noatime", ""),
        (MS_NODIRATIME, "nodiratime", ""),
        (MS_BIND, "bind", "rbind"),
        (MS_MOVE, "move", ""),
        (MS_SILENT, "silent", ""),
        (MS_POSIXACL, "acl", ""),
        (MS_UNBINDABLE, "unbindable", "runbindable"),
        (MS_PRIVATE, "private", "rprivate"),
        (MS_SLAVE, "slave", "rslave"),
        (MS_SHARED, "shared", "rshared"),
        (MS_RELATIME, "relatime", ""),
        (MS_I_VERSION, "iversion", ""),
        (MS_STRICTATIME, "strictatime", ""),
        (MS_NOUSER, "nouser", ""),
    ];
    for (bit, name, rname) in names {
        if flags & bit != 0 {
            s.push_str(", ");
            s.push_str(if rec && !rname.is_empty() { rname } else { name });
        }
    }
    s
}

/// The data of a record of a mount, the `mnt` part of `struct apparmor_audit_data` of Linux.
struct Rec<'a> {
    /// The operation: `mount`, `umount` or `pivotroot`.
    op: &'static str,
    /// The mount point, or the new root.
    name: &'a [u8],
    /// The source, or the place of the old root.
    src: Option<&'a [u8]>,
    /// The type of the file system.
    fstype: Option<&'a [u8]>,
    /// The flags.
    flags: u32,
    /// The options.
    data: Option<&'a [u8]>,
    /// The permission that the operation needs.
    request: u32,
}

/// The fields of a record after `comm`, `audit_cb` of mount.c of Linux.
fn tail(r: &Rec<'_>, data: bool) -> String {
    let mut s = String::new();
    if let Some(t) = r.fstype {
        s.push_str(" fstype=");
        audit::untrusted(&mut s, t);
    }
    if let Some(src) = r.src {
        s.push_str(" srcname=");
        audit::untrusted(&mut s, src);
    }
    if r.flags != 0 {
        s.push_str(" flags=\"");
        s.push_str(&flags_text(r.flags));
        s.push('"');
    }
    if let Some(d) = r.data.filter(|_| data) {
        s.push_str(" options=");
        audit::untrusted(&mut s, d);
    }
    s
}

/// The record of a check of the profile `p`, `audit_mount` of Linux. `error` is the result of
/// the check.
///
/// # Errors
///
/// Gives `error`, except for a denial that complain mode allows.
fn audit_mount(
    p: &Profile,
    r: &Rec<'_>,
    perms: &Perms,
    info: Option<&str>,
    error: Option<Errno>,
) -> Result<()> {
    let audit_all = p.rules.as_ref().is_some_and(|r| r.audit);
    let mut request = r.request;
    let kind = if error.is_none() {
        // Only the permissions that the policy audits.
        request &= if audit_all { 0xffff } else { perms.audit };
        if request == 0 {
            return Ok(());
        }
        Kind::Audit
    } else {
        // Only the permissions that the policy does not allow.
        request &= !perms.allow;
        let kill = request & perms.kill != 0;
        if !audit_all {
            request &= !perms.quiet;
        }
        if request == 0 {
            return error.map_or(Ok(()), Err);
        }
        if kill { Kind::Killed } else { mode_kind(Some(p)) }
    };
    let name = String::from_utf8_lossy(r.name);
    let fq = p.fqname();
    let d = audit::Data {
        op: Some(r.op),
        class: Some("mount"),
        info,
        error: error.map_or(0, |e| -i32::from(e.get())),
        profile: Some(&fq),
        name: Some(&name),
    };
    audit::log(kind, &d, &tail(r, perms.audit & AUDIT_DATA != 0));
    outcome(kind, error)
}

/// The match of a mount in the policy `pdb` from the state `start`, `do_match_mnt` of Linux.
/// Gives the index of the result in [`INFO`], 0 for a match, and the permissions of the last
/// state.
#[allow(clippy::too_many_arguments)]
fn do_match(
    pdb: &Pdb,
    start: u32,
    mntpnt: &[u8],
    dev: Option<&[u8]>,
    fstype: Option<&[u8]>,
    flags: u32,
    data: Option<&[u8]>,
    binary: bool,
) -> (usize, Perms) {
    let mut perms = Perms::default();
    let Some(d) = pdb.dfa.as_ref() else { return (1, perms) };
    let mut state = d.next(d.match_bytes(start, mntpnt), 0);
    if state == 0 {
        return (1, perms);
    }
    if let Some(dev) = dev {
        state = d.match_bytes(state, dev);
    }
    state = d.next(state, 0);
    if state == 0 {
        return (2, perms);
    }
    if let Some(t) = fstype {
        state = d.match_bytes(state, t);
    }
    state = d.next(state, 0);
    if state == 0 {
        return (3, perms);
    }
    // Each flag is a byte, its bit number and 1, `match_mnt_flags` of Linux.
    for i in 0..32u8 {
        if flags & (1 << i) != 0 {
            state = d.next(state, i + 1);
        }
    }
    if state == 0 {
        return (4, perms);
    }
    perms = label::lookup(pdb, state);
    if perms.allow & MAY_MOUNT != 0 {
        return (0, perms);
    }
    // The options, only if they are text and the rule has a pattern for them.
    if let Some(data) = data.filter(|_| !binary && perms.allow & CONT_MATCH != 0) {
        state = d.next(state, 0);
        if state == 0 {
            return (4, perms);
        }
        state = d.match_bytes(state, data);
        if state == 0 {
            return (5, perms);
        }
        perms = label::lookup(pdb, state);
        if perms.allow & MAY_MOUNT != 0 {
            return (0, perms);
        }
    }
    (6, perms)
}

/// The name of the file at `at` for the rules, with a `/` at the end for a directory.
fn name_of(at: &Location) -> Vec<u8> {
    let dir = at.inode().metadata().file_type() == Some(FileType::Directory);
    path_name(at.absolute_path(), dir)
}

/// The source of a mount for the rules: the name of a file, or a text.
#[derive(Clone, Copy)]
enum Src<'a> {
    /// The file of a bind mount, of a move or of a file system on a device.
    Path(&'a Location),
    /// The text that the caller gives.
    Text(Option<&'a [u8]>),
}

/// The check of a mount on `at` for the profile `p`, `match_mnt` and `match_mnt_path_str` of
/// Linux.
///
/// # Errors
///
/// Gives `EACCES` if no rule allows the mount, except in complain mode.
fn match_mnt(
    p: &Profile,
    at: &Location,
    src: Src<'_>,
    fstype: Option<&[u8]>,
    flags: u32,
    data: Option<&[u8]>,
    binary: bool,
) -> Result<()> {
    let Some((pdb, start)) = label::mediates(p, class::MOUNT) else { return Ok(()) };
    let src = match src {
        Src::Path(l) => Some(name_of(l)),
        Src::Text(t) => t.map(<[u8]>::to_vec),
    };
    let mntpnt = name_of(at);
    let (pos, perms) = do_match(pdb, start, &mntpnt, src.as_deref(), fstype, flags, data, binary);
    let r = Rec {
        op: "mount",
        name: &mntpnt,
        src: src.as_deref(),
        fstype,
        flags,
        data,
        request: MAY_MOUNT,
    };
    let (info, error) = match pos {
        0 => (None, None),
        _ => (Some(INFO[pos]), Some(Errno::EACCES)),
    };
    audit_mount(p, &r, &perms, info, error)
}

/// The label of the current task, or `None` if it is `unconfined`.
fn confined() -> Option<domain::Label> {
    let cred = rk_vfs::cred::current();
    (domain::label_id(&cred) != 0).then(|| domain::label_of(&cred))
}

/// The check of each profile of `l` that is not unconfined, `fn_for_each_confined` of Linux.
/// Each profile makes its record.
///
/// # Errors
///
/// Gives the error of the last profile that denies.
fn each(l: &[Arc<Profile>], f: impl Fn(&Profile) -> Result<()>) -> Result<()> {
    let mut result = Ok(());
    for p in l.iter().filter(|p| p.mode != Mode::Unconfined) {
        if let Err(e) = f(p) {
            result = Err(e);
        }
    }
    result
}

/// Tells if the mount of `at` is in the mount name space of the current task, `our_mnt` of
/// Linux.
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn our_mount(at: &Location) -> bool {
    let fs = rk_proc::current_thread().and_then(|t| t.process().fs());
    fs.is_none_or(|fs| fs.lock().namespace().contains(&at.mount))
}

/// A build for the host has no process.
#[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn our_mount(_at: &Location) -> bool {
    true
}

/// The check of a move of the mount `from` to `to`, `aa_move_mount` of Linux. A mount that is
/// not in the name space of the task, as a mount of `fsmount` or of `open_tree`, has no source
/// in the match.
fn move_label(l: &[Arc<Profile>], from: &Location, to: &Location) -> Result<()> {
    let src = if our_mount(from) { Src::Path(from) } else { Src::Text(None) };
    each(l, |p| match_mnt(p, to, src, None, MS_MOVE, None, false))
}

/// The `sb_mount` hook, `apparmor_sb_mount` of Linux. The flags select the check: a remount,
/// a bind mount, a change of the propagation, a move or a new mount.
///
/// # Errors
///
/// Gives `EACCES` if a profile does not allow the mount. A bind mount or a move without a source
/// gives `EINVAL`, a new mount of an unknown type gives `ENODEV`, and a new mount of a file
/// system on a device without a source gives `ENOENT`. The lookup of a source can fail too.
pub fn sb_mount(req: &MountReq<'_>) -> Result<()> {
    let Some(l) = confined() else { return Ok(()) };
    let flags = req.flags & !IGNORE;
    let at = req.at;
    let source = || match req.dev_name {
        Some(d) if !d.is_empty() => (req.lookup)(d),
        _ => Err(Errno::EINVAL),
    };
    if flags & MS_REMOUNT != 0 {
        // rukernel has no file system with binary options, `FS_BINARY_MOUNTDATA`.
        each(&l, |p| match_mnt(p, at, Src::Text(None), None, flags, req.data, false))
    } else if flags & MS_BIND != 0 {
        let from = source()?;
        let flags = flags & (MS_REC | MS_BIND);
        each(&l, |p| match_mnt(p, at, Src::Path(&from), None, flags, None, false))
    } else if flags & PROPAGATION != 0 {
        // The flags that `do_change_type` of Linux reads.
        let flags = flags & (MS_REC | MS_SILENT | PROPAGATION);
        each(&l, |p| match_mnt(p, at, Src::Text(None), None, flags, None, false))
    } else if flags & MS_MOVE != 0 {
        let from = source()?;
        move_label(&l, &from, at)
    } else {
        new_mount(&l, req, flags)
    }
}

/// The check of a new mount, `aa_new_mount` of Linux. The source of a file system on a device
/// is the name of the device file. A mount without a type has binary options.
fn new_mount(l: &[Arc<Profile>], req: &MountReq<'_>, flags: u32) -> Result<()> {
    let mut binary = true;
    let mut dev = None;
    if req.fstype.is_some() {
        let ty = req.fs_flags.ok_or(Errno::ENODEV)?;
        binary = ty.binary;
        if ty.requires_dev {
            match req.dev_name {
                Some(d) if !d.is_empty() => dev = Some((req.lookup)(d)?),
                _ => return Err(Errno::ENOENT),
            }
        }
    }
    let src = dev.as_ref().map_or(Src::Text(req.dev_name), Src::Path);
    each(l, |p| match_mnt(p, req.at, src, req.fstype, flags, req.data, binary))
}

/// The `sb_umount` hook, `apparmor_sb_umount` and `profile_umount` of Linux. `root` is the
/// root of the mount.
///
/// # Errors
///
/// Gives `EACCES` if a profile does not allow the unmount.
pub fn sb_umount(root: &Location) -> Result<()> {
    let Some(l) = confined() else { return Ok(()) };
    each(&l, |p| {
        let Some((pdb, start)) = label::mediates(p, class::MOUNT) else { return Ok(()) };
        let name = name_of(root);
        let perms = pdb
            .dfa
            .as_ref()
            .map_or_else(Perms::default, |d| label::lookup(pdb, d.match_bytes(start, &name)));
        let error = (perms.allow & MAY_UMOUNT == 0).then_some(Errno::EACCES);
        let r = Rec {
            op: "umount",
            name: &name,
            src: None,
            fstype: None,
            flags: 0,
            data: None,
            request: MAY_UMOUNT,
        };
        audit_mount(p, &r, &perms, None, error)
    })
}

/// The `sb_pivotroot` hook, `apparmor_sb_pivotroot` and `build_pivotroot` of Linux: `new` is
/// the new root, and `old` is the place of the old root. rukernel has no transition of a
/// `pivot_root` rule, so the label does not change.
///
/// # Errors
///
/// Gives `EACCES` if a profile does not allow the change.
pub fn sb_pivotroot(old: &Location, new: &Location) -> Result<()> {
    let Some(l) = confined() else { return Ok(()) };
    each(&l, |p| {
        let Some((pdb, start)) = label::mediates(p, class::MOUNT) else { return Ok(()) };
        let old_name = name_of(old);
        let new_name = name_of(new);
        let perms = pdb.dfa.as_ref().map_or_else(Perms::default, |d| {
            let state = d.next(d.match_bytes(start, &new_name), 0);
            label::lookup(pdb, d.match_bytes(state, &old_name))
        });
        let error = (perms.allow & MAY_PIVOTROOT == 0).then_some(Errno::EACCES);
        let r = Rec {
            op: "pivotroot",
            name: &new_name,
            src: Some(&old_name),
            fstype: None,
            flags: 0,
            data: None,
            request: MAY_PIVOTROOT,
        };
        audit_mount(p, &r, &perms, None, error)
    })
}

/// The `move_mount` hook, `apparmor_move_mount` of Linux.
///
/// # Errors
///
/// Gives `EACCES` if a profile does not allow the move.
pub fn move_mount(from: &Location, to: &Location) -> Result<()> {
    let Some(l) = confined() else { return Ok(()) };
    move_label(&l, from, to)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flags_have_the_names_of_linux() {
        assert_eq!(flags_text(0), "rw");
        assert_eq!(flags_text(MS_RDONLY | MS_NOSUID | MS_NODEV), "ro, nosuid, nodev");
        assert_eq!(flags_text(MS_BIND), "rw, bind");
        assert_eq!(flags_text(MS_BIND | MS_REC), "rw, rbind");
        assert_eq!(flags_text(MS_PRIVATE | MS_REC), "rw, rprivate");
        assert_eq!(flags_text(MS_MOVE), "rw, move");
    }

    #[test]
    fn the_record_has_the_fields_of_linux() {
        let r = Rec {
            op: "mount",
            name: b"/mnt/",
            src: Some(b"/dev/loop0"),
            fstype: Some(b"ext2"),
            flags: MS_NOEXEC,
            data: Some(b"acl"),
            request: MAY_MOUNT,
        };
        assert_eq!(tail(&r, false), " fstype=\"ext2\" srcname=\"/dev/loop0\" flags=\"rw, noexec\"");
        assert_eq!(
            tail(&r, true),
            " fstype=\"ext2\" srcname=\"/dev/loop0\" flags=\"rw, noexec\" options=\"acl\""
        );
        let r = Rec { flags: 0, src: None, fstype: None, data: None, ..r };
        assert_eq!(tail(&r, true), "");
        assert_eq!(INFO[4], "failed flags match");
    }
}

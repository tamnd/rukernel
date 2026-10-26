//! POSIX access control lists, as fs/posix_acl.c of Linux.
//!
//! A file keeps its access ACL in the extended attribute `system.posix_acl_access`, and a
//! directory keeps the default ACL of its new files in `system.posix_acl_default`. The value has
//! the format of `<linux/posix_acl_xattr.h>`: a 32-bit version, 2, and entries of 8 bytes with a
//! 16-bit tag, 16-bit permission bits and a 32-bit ID, all in little endian. A file system that
//! keeps the ACL in another format on the disk changes it in its `get_xattr` and `set_xattr`.
//!
//! The owner entry, the owning group entry and the other entry of an access ACL are the same as
//! the permission bits of the mode. If the ACL has a mask entry, the group bits of the mode are
//! the mask. An ACL that has only these three entries is the same as the mode, and the file does
//! not keep it.

use crate::cred::Cred;
use crate::inode::{FileType, Inode, Metadata, Result, SetAttr, mode};
use alloc::vec::Vec;
use rk_abi::Errno;

/// The name of the access ACL.
pub const ACCESS: &[u8] = b"system.posix_acl_access";
/// The name of the default ACL of a directory.
pub const DEFAULT: &[u8] = b"system.posix_acl_default";
/// The version in the header of the value, `POSIX_ACL_XATTR_VERSION`.
pub const VERSION: u32 = 2;
/// The ID of an entry that has no ID, `ACL_UNDEFINED_ID`.
pub const UNDEFINED_ID: u32 = u32::MAX;

/// The tags of the entries, in the order that an ACL keeps them.
pub mod tag {
    /// The owner of the file.
    pub const USER_OBJ: u16 = 0x01;
    /// A named user.
    pub const USER: u16 = 0x02;
    /// The owning group of the file.
    pub const GROUP_OBJ: u16 = 0x04;
    /// A named group.
    pub const GROUP: u16 = 0x08;
    /// The largest permission of the named entries and of the owning group.
    pub const MASK: u16 = 0x10;
    /// The other users.
    pub const OTHER: u16 = 0x20;
}

/// One entry of an ACL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The tag, one of [`tag`].
    pub tag: u16,
    /// The permission bits: 4 for read, 2 for write and 1 for execute.
    pub perm: u16,
    /// The user or the group of a named entry, else [`UNDEFINED_ID`].
    pub id: u32,
}

/// An ACL. A valid ACL has its entries in the order of their tags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Acl(pub Vec<Entry>);

impl Acl {
    /// Reads an ACL from the value of its attribute, as `posix_acl_from_xattr` and
    /// `posix_acl_valid` of Linux. An empty value, or a value with no entries, gives `None`.
    ///
    /// # Errors
    ///
    /// Gives `EOPNOTSUPP` for an unknown version, and `EINVAL` for a bad size or an invalid
    /// ACL.
    pub fn from_xattr(value: &[u8]) -> Result<Option<Self>> {
        let acl = Self::parse(value)?;
        if let Some(acl) = &acl {
            acl.valid()?;
        }
        Ok(acl)
    }

    /// Reads an ACL from the value of its attribute, as `posix_acl_from_xattr` of Linux. This
    /// does not check the order of the entries. Use [`Acl::valid`] for that check.
    ///
    /// # Errors
    ///
    /// Gives `EOPNOTSUPP` for an unknown version, and `EINVAL` for a bad size, an unknown tag
    /// or a named entry without an ID.
    pub fn parse(value: &[u8]) -> Result<Option<Self>> {
        if value.is_empty() {
            return Ok(None);
        }
        if value.len() < 4 {
            return Err(Errno::EINVAL);
        }
        if u32::from_le_bytes([value[0], value[1], value[2], value[3]]) != VERSION {
            return Err(Errno::EOPNOTSUPP);
        }
        let body = &value[4..];
        if !body.len().is_multiple_of(8) {
            return Err(Errno::EINVAL);
        }
        if body.is_empty() {
            return Ok(None);
        }
        let mut entries = Vec::with_capacity(body.len() / 8);
        for e in body.as_chunks::<8>().0 {
            let tag = u16::from_le_bytes([e[0], e[1]]);
            let perm = u16::from_le_bytes([e[2], e[3]]);
            let id = match tag {
                tag::USER | tag::GROUP => u32::from_le_bytes([e[4], e[5], e[6], e[7]]),
                tag::USER_OBJ | tag::GROUP_OBJ | tag::MASK | tag::OTHER => UNDEFINED_ID,
                _ => return Err(Errno::EINVAL),
            };
            // `make_kuid` of Linux does not map the ID -1.
            if id == UNDEFINED_ID && matches!(tag, tag::USER | tag::GROUP) {
                return Err(Errno::EINVAL);
            }
            entries.push(Entry { tag, perm, id });
        }
        Ok(Some(Self(entries)))
    }

    /// Gives the value of the attribute of the ACL, as `posix_acl_to_xattr` of Linux.
    pub fn to_xattr(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 8 * self.0.len());
        out.extend_from_slice(&VERSION.to_le_bytes());
        for e in &self.0 {
            out.extend_from_slice(&e.tag.to_le_bytes());
            out.extend_from_slice(&e.perm.to_le_bytes());
            out.extend_from_slice(&e.id.to_le_bytes());
        }
        out
    }

    /// Checks the order and the contents of the entries, as `posix_acl_valid` of Linux. An ACL
    /// has one owner entry, then the named users, one owning group entry, the named groups, a
    /// mask entry if it has named entries, and one other entry.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` for an invalid ACL.
    pub fn valid(&self) -> Result<()> {
        let mut state = tag::USER_OBJ;
        let mut needs_mask = false;
        for e in &self.0 {
            if e.perm & !7 != 0 {
                return Err(Errno::EINVAL);
            }
            state = match e.tag {
                tag::USER_OBJ if state == tag::USER_OBJ => tag::USER,
                tag::USER | tag::GROUP if state == e.tag && e.id != UNDEFINED_ID => {
                    needs_mask = true;
                    state
                }
                tag::GROUP_OBJ if state == tag::USER => tag::GROUP,
                tag::MASK if state == tag::GROUP => tag::OTHER,
                tag::OTHER if state == tag::OTHER || (state == tag::GROUP && !needs_mask) => 0,
                _ => return Err(Errno::EINVAL),
            };
        }
        if state == 0 { Ok(()) } else { Err(Errno::EINVAL) }
    }

    /// Gives the permission bits of the mode that the ACL gives, and `true` if the ACL is the
    /// same as these bits, as `posix_acl_equiv_mode` of Linux.
    pub fn equiv_mode(&self) -> (u32, bool) {
        let mut bits = 0;
        let mut equiv = true;
        for e in &self.0 {
            let perm = u32::from(e.perm & 7);
            match e.tag {
                tag::USER_OBJ => bits |= perm << 6,
                tag::GROUP_OBJ => bits |= perm << 3,
                tag::OTHER => bits |= perm,
                tag::MASK => {
                    bits = (bits & !0o070) | (perm << 3);
                    equiv = false;
                }
                _ => equiv = false,
            }
        }
        (bits, equiv)
    }

    /// Checks the access `want` of `cred` to the file with the attributes `meta`, as
    /// `posix_acl_permission` of Linux. A named user, the owning group and a named group get
    /// their bits and the bits of the mask.
    ///
    /// # Errors
    ///
    /// Gives `EIO` for an ACL without the entries that the check needs.
    pub fn permits(&self, cred: &Cred, meta: &Metadata, want: u32) -> Result<bool> {
        let want = want as u16 & 7;
        let mut found = false;
        for (i, e) in self.0.iter().enumerate() {
            let masked = match e.tag {
                tag::USER_OBJ if cred.fsuid == meta.uid => false,
                tag::USER if e.id == cred.fsuid => true,
                tag::GROUP_OBJ | tag::GROUP => {
                    let gid = if e.tag == tag::GROUP { e.id } else { meta.gid };
                    if !cred.in_group(gid) {
                        continue;
                    }
                    found = true;
                    if e.perm & want != want {
                        continue;
                    }
                    true
                }
                tag::OTHER if found => return Ok(false),
                tag::OTHER => false,
                tag::USER_OBJ | tag::USER | tag::MASK => continue,
                _ => return Err(Errno::EIO),
            };
            let mask = if masked {
                self.0[i + 1..].iter().find(|m| m.tag == tag::MASK).map_or(7, |m| m.perm)
            } else {
                7
            };
            return Ok(e.perm & mask & want == want);
        }
        Err(Errno::EIO)
    }

    /// Changes the ACL for the new permission bits `perm` of a `chmod`, as `__posix_acl_chmod`
    /// of Linux. The group bits go to the mask entry if the ACL has one, else to the owning
    /// group entry.
    pub fn chmod(&mut self, perm: u32) {
        let mut group = None;
        for (i, e) in self.0.iter_mut().enumerate() {
            match e.tag {
                tag::USER_OBJ => e.perm = ((perm >> 6) & 7) as u16,
                tag::OTHER => e.perm = (perm & 7) as u16,
                tag::GROUP_OBJ if group.is_none() => group = Some(i),
                tag::MASK => group = Some(i),
                _ => {}
            }
        }
        if let Some(i) = group {
            self.0[i].perm = ((perm >> 3) & 7) as u16;
        }
    }

    /// Masks the ACL of a new file with the permission bits `perm` that the call asks for, and
    /// gives the new permission bits and `true` if the ACL is the same as them, as
    /// `posix_acl_create_masq` of Linux. The bits above the permission bits stay.
    pub fn create_masq(&mut self, perm: u32) -> (u32, bool) {
        let mut perm = perm;
        let mut equiv = true;
        let mut group = None;
        let mut mask = None;
        for (i, e) in self.0.iter_mut().enumerate() {
            match e.tag {
                tag::USER_OBJ => {
                    e.perm &= ((perm >> 6) & 7) as u16;
                    perm &= (u32::from(e.perm) << 6) | !0o700;
                }
                tag::GROUP_OBJ => group = Some(i),
                tag::MASK => {
                    mask = Some(i);
                    equiv = false;
                }
                tag::OTHER => {
                    e.perm &= (perm & 7) as u16;
                    perm &= u32::from(e.perm) | !0o007;
                }
                _ => equiv = false,
            }
        }
        if let Some(i) = mask.or(group) {
            let e = &mut self.0[i];
            e.perm &= ((perm >> 3) & 7) as u16;
            perm &= (u32::from(e.perm) << 3) | !0o070;
        }
        (perm, equiv)
    }
}

/// Reads the ACL `name` of `inode`. A file without the ACL, a file system without POSIX ACLs,
/// and a damaged value give `None`.
fn read(inode: &dyn Inode, name: &[u8]) -> Option<Acl> {
    if !inode.posix_acl() {
        return None;
    }
    inode.get_xattr(name).ok().and_then(|v| Acl::from_xattr(&v).ok().flatten())
}

/// The access ACL of `inode`, if it has one.
pub fn access(inode: &dyn Inode) -> Option<Acl> {
    read(inode, ACCESS)
}

/// Gives the value of the ACL `name` of `inode`, for `getxattr`, as `vfs_get_acl` of Linux.
///
/// # Errors
///
/// Gives `EOPNOTSUPP` if the file system has no POSIX ACLs, and `ENODATA` if the file does not
/// have the ACL.
pub fn get(inode: &dyn Inode, name: &[u8]) -> Result<Vec<u8>> {
    if !inode.posix_acl() {
        return Err(Errno::EOPNOTSUPP);
    }
    inode.get_xattr(name)
}

/// Tells if `name` is the name of an ACL, as `is_posix_acl_xattr` of Linux.
pub fn is_name(name: &[u8]) -> bool {
    name == ACCESS || name == DEFAULT
}

/// Tells if `listxattr` shows the attribute `name` of `inode`. The names of the ACLs show only
/// on a file system with POSIX ACLs, as `posix_acl_xattr_list` of Linux.
pub fn listed(inode: &dyn Inode, name: &[u8]) -> bool {
    !is_name(name) || inode.posix_acl()
}

/// Removes the attribute `name`. An attribute that does not exist is not an error.
fn clear(inode: &dyn Inode, name: &[u8]) -> Result<()> {
    match inode.remove_xattr(name) {
        Err(Errno::ENODATA) => Ok(()),
        r => r,
    }
}

/// Checks a change of the ACL `name` of `inode` to `acl`, as `set_posix_acl` of Linux. Gives
/// `Ok(false)` if there is nothing to do: the removal of a default ACL of a file that is not a
/// directory.
fn may_set(cred: &Cred, inode: &dyn Inode, name: &[u8], acl: Option<&Acl>) -> Result<bool> {
    let meta = inode.metadata();
    // A symbolic link has no `set_acl` operation in Linux.
    if !inode.posix_acl() || meta.file_type() == Some(FileType::Symlink) {
        return Err(Errno::EOPNOTSUPP);
    }
    if name == DEFAULT && !meta.is_dir() {
        return if acl.is_some() { Err(Errno::EACCES) } else { Ok(false) };
    }
    if !cred.owns(&meta) {
        return Err(Errno::EPERM);
    }
    if let Some(acl) = acl {
        acl.valid()?;
    }
    Ok(true)
}

/// Sets the ACL `name` of `inode` to `value`, for `setxattr`, as `vfs_set_acl` and
/// `posix_acl_update_mode` of Linux. Only the owner or a process with `CAP_FOWNER` can set an
/// ACL. An access ACL also sets the permission bits of the mode, and the file does not keep an
/// ACL that is the same as the mode. If the process is not in the group of the file and does
/// not have `CAP_FSETID`, the set-group-ID bit goes. An empty value removes the ACL. As Linux,
/// the flags `XATTR_CREATE` and `XATTR_REPLACE` do not apply to an ACL.
///
/// # Errors
///
/// Gives `EOPNOTSUPP` for a file system without POSIX ACLs and for a symbolic link, `EACCES`
/// for a default ACL on a file that is not a directory, `EPERM` if the process does not own the
/// file, and `EINVAL` for an invalid ACL.
pub fn set(cred: &Cred, inode: &dyn Inode, name: &[u8], value: &[u8]) -> Result<()> {
    let acl = Acl::parse(value)?;
    if !may_set(cred, inode, name, acl.as_ref())? {
        return Ok(());
    }
    let Some(acl) = acl else {
        return clear(inode, name);
    };
    if name == DEFAULT {
        return inode.set_xattr(DEFAULT, &acl.to_xattr(), 0);
    }
    let meta = inode.metadata();
    let (bits, equiv) = acl.equiv_mode();
    if equiv {
        clear(inode, ACCESS)?;
    } else {
        inode.set_xattr(ACCESS, &acl.to_xattr(), 0)?;
    }
    let mut perm = (meta.mode & 0o7000) | bits;
    if !cred.in_group(meta.gid) && !cred.capable(crate::cred::cap::FSETID) {
        perm &= !mode::S_ISGID;
    }
    if perm != meta.mode & 0o7777 {
        inode.set_attr(&SetAttr { mode: Some(perm), ..SetAttr::default() })?;
    }
    Ok(())
}

/// Removes the ACL `name` of `inode`, for `removexattr`, as `vfs_remove_acl` of Linux. The mode
/// does not change. As Linux, a file without the ACL is not an error.
///
/// # Errors
///
/// Gives the errors of the checks of [`set`].
pub fn remove(cred: &Cred, inode: &dyn Inode, name: &[u8]) -> Result<()> {
    if !may_set(cred, inode, name, None)? {
        return Ok(());
    }
    clear(inode, name)
}

/// Changes the access ACL of `inode` after a `chmod` to the permission bits `perm`, as
/// `posix_acl_chmod` of Linux. A file without an ACL does not change.
///
/// # Errors
///
/// Gives the error of the write of the attribute.
pub fn chmod(inode: &dyn Inode, perm: u32) -> Result<()> {
    if !inode.posix_acl() || inode.metadata().file_type() == Some(FileType::Symlink) {
        return Ok(());
    }
    let Some(mut acl) = access(inode) else {
        return Ok(());
    };
    acl.chmod(perm);
    inode.set_xattr(ACCESS, &acl.to_xattr(), 0)
}

/// The ACLs that a new file gets from the default ACL of its directory.
#[derive(Clone, Debug)]
pub struct Inherit {
    /// The default ACL of the directory, which a new directory also gets.
    default: Acl,
    /// The access ACL of the new file, if it is not the same as the mode.
    access: Option<Acl>,
}

/// Gives the permission bits of a new file of the type `kind` with the bits `perm` in the
/// directory `dir`, and the ACLs that the file gets, as `posix_acl_create` of Linux. If the
/// directory has a default ACL, the ACL masks the bits and the umask does not apply. Else the
/// umask applies, as on a file system without POSIX ACLs.
pub fn create(dir: &dyn Inode, kind: FileType, perm: u32, umask: u32) -> (u32, Option<Inherit>) {
    let default = match kind {
        FileType::Symlink => None,
        _ => read(dir, DEFAULT),
    };
    let Some(default) = default else {
        return (perm & !umask, None);
    };
    let mut access = default.clone();
    let (perm, equiv) = access.create_masq(perm);
    (perm, Some(Inherit { default, access: (!equiv).then_some(access) }))
}

impl Inherit {
    /// Writes the ACLs to the new inode `inode`.
    ///
    /// # Errors
    ///
    /// Gives the error of the write of an attribute.
    pub fn apply(&self, inode: &dyn Inode) -> Result<()> {
        if inode.metadata().is_dir() {
            inode.set_xattr(DEFAULT, &self.default.to_xattr(), 0)?;
        }
        if let Some(access) = &self.access {
            inode.set_xattr(ACCESS, &access.to_xattr(), 0)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn e(tag: u16, perm: u16, id: u32) -> Entry {
        Entry { tag, perm, id }
    }

    fn named() -> Acl {
        Acl(vec![
            e(tag::USER_OBJ, 7, UNDEFINED_ID),
            e(tag::USER, 6, 1000),
            e(tag::GROUP_OBJ, 5, UNDEFINED_ID),
            e(tag::GROUP, 7, 50),
            e(tag::MASK, 4, UNDEFINED_ID),
            e(tag::OTHER, 0, UNDEFINED_ID),
        ])
    }

    fn meta(perm: u32) -> Metadata {
        Metadata { mode: mode::S_IFREG | perm, uid: 0, gid: 0, ..Metadata::default() }
    }

    fn user(id: u32, groups: &[u32]) -> Cred {
        let mut c = Cred::root().setresgid(id, id, id).unwrap();
        c.groups = groups.to_vec();
        c.setresuid(id, id, id).unwrap()
    }

    #[test]
    fn the_value_goes_back_to_the_same_acl() {
        let acl = named();
        let value = acl.to_xattr();
        assert_eq!(value.len(), 4 + 6 * 8);
        assert_eq!(Acl::from_xattr(&value), Ok(Some(acl)));
        assert_eq!(Acl::from_xattr(&[]), Ok(None));
        assert_eq!(Acl::from_xattr(&VERSION.to_le_bytes()), Ok(None));
        assert_eq!(Acl::from_xattr(&1u32.to_le_bytes()), Err(Errno::EOPNOTSUPP));
        assert_eq!(Acl::from_xattr(&value[..value.len() - 1]), Err(Errno::EINVAL));
    }

    #[test]
    fn an_acl_must_have_its_entries_in_order() {
        let mut acl = named();
        acl.0.remove(4);
        assert_eq!(acl.valid(), Err(Errno::EINVAL));
        let mut acl = named();
        acl.0.swap(0, 2);
        assert_eq!(acl.valid(), Err(Errno::EINVAL));
        let mut acl = named();
        acl.0[1].perm = 8;
        assert_eq!(acl.valid(), Err(Errno::EINVAL));
        let short = Acl(vec![
            e(tag::USER_OBJ, 6, UNDEFINED_ID),
            e(tag::GROUP_OBJ, 4, UNDEFINED_ID),
            e(tag::OTHER, 4, UNDEFINED_ID),
        ]);
        assert_eq!(short.valid(), Ok(()));
        assert_eq!(short.equiv_mode(), (0o644, true));
        assert_eq!(named().equiv_mode(), (0o740, false));
    }

    #[test]
    fn the_mask_limits_the_named_entries() {
        let acl = named();
        let m = meta(0o740);
        assert_eq!(acl.permits(&user(1000, &[]), &m, 4), Ok(true));
        assert_eq!(acl.permits(&user(1000, &[]), &m, 2), Ok(false));
        assert_eq!(acl.permits(&user(2000, &[50]), &m, 4), Ok(true));
        assert_eq!(acl.permits(&user(2000, &[50]), &m, 1), Ok(false));
        // A process in a group that does not match gets nothing, not the other bits.
        let mut open = named();
        open.0[5].perm = 7;
        assert_eq!(open.permits(&user(2000, &[0]), &m, 1), Ok(false));
        assert_eq!(open.permits(&user(2000, &[]), &m, 1), Ok(true));
        assert_eq!(acl.permits(&Cred::root(), &m, 7), Ok(true));
    }

    #[test]
    fn chmod_and_create_change_the_mask() {
        let mut acl = named();
        acl.chmod(0o750);
        assert_eq!((acl.0[0].perm, acl.0[2].perm, acl.0[4].perm, acl.0[5].perm), (7, 5, 5, 0));
        let mut acl = named();
        assert_eq!(acl.create_masq(0o666), (0o640, false));
        assert_eq!((acl.0[0].perm, acl.0[4].perm, acl.0[5].perm), (6, 4, 0));
        let mut short = Acl(vec![
            e(tag::USER_OBJ, 7, UNDEFINED_ID),
            e(tag::GROUP_OBJ, 5, UNDEFINED_ID),
            e(tag::OTHER, 5, UNDEFINED_ID),
        ]);
        assert_eq!(short.create_masq(0o2666), (0o2644, true));
    }

    #[test]
    fn the_group_bits_turn_on_the_acl() {
        let acl = named();
        let c = user(1000, &[]);
        assert_eq!(c.check(&meta(0o740), 4, || Some(acl.clone())), Ok(()));
        assert_eq!(c.check(&meta(0o700), 4, || Some(acl.clone())), Err(Errno::EACCES));
        let owned = Metadata { uid: 1000, ..meta(0o040) };
        assert_eq!(c.check(&owned, 4, || Some(acl.clone())), Err(Errno::EACCES));
    }
}

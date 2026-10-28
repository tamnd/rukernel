//! `statmount` and `listmount`, as fs/namespace.c of Linux.
//!
//! A mount has a unique ID, which `statx` gives with `STATX_MNT_ID_UNIQUE`. `listmount` gives the
//! unique IDs of the mounts under a mount, in the order of the IDs. `statmount` gives the fields of
//! `struct statmount` for one mount, and the strings that the mask asks for after the structure.
//!
//! The ID of a mount name space is the inode number of its file in `/proc/PID/ns`, as
//! `NS_GET_MNTNS_ID` gives it. A request can give the ID of another mount name space. A request
//! for a name space by a descriptor gives `EBADF` for a bad descriptor and `EINVAL` for another
//! descriptor.

use crate::cx::{Cx, SysResult};
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::lsmt::LSMT_ROOT;
use rk_abi::native::mount::{
    LISTMOUNT_REVERSE, MNT_ID_REQ_SIZE_VER0, MNT_ID_REQ_SIZE_VER1, MOUNT_ATTR_NOATIME,
    MOUNT_ATTR_NODEV, MOUNT_ATTR_NODIRATIME, MOUNT_ATTR_NOEXEC, MOUNT_ATTR_NOSUID,
    MOUNT_ATTR_NOSYMFOLLOW, MOUNT_ATTR_RDONLY, MOUNT_ATTR_RELATIME, MOUNT_ATTR_STRICTATIME,
    MS_DIRSYNC, MS_LAZYTIME, MS_NOATIME, MS_NODEV, MS_NODIRATIME, MS_NOEXEC, MS_NOSUID,
    MS_NOSYMFOLLOW, MS_PRIVATE, MS_RDONLY, MS_RELATIME, MS_SHARED, MS_SLAVE, MS_SYNCHRONOUS,
    MS_UNBINDABLE, STATMOUNT_BY_FD, STATMOUNT_FS_SUBTYPE, STATMOUNT_FS_TYPE, STATMOUNT_MNT_BASIC,
    STATMOUNT_MNT_GIDMAP, STATMOUNT_MNT_NS_ID, STATMOUNT_MNT_OPTS, STATMOUNT_MNT_POINT,
    STATMOUNT_MNT_ROOT, STATMOUNT_MNT_UIDMAP, STATMOUNT_OPT_ARRAY, STATMOUNT_OPT_SEC_ARRAY,
    STATMOUNT_PROPAGATE_FROM, STATMOUNT_SB_BASIC, STATMOUNT_SB_SOURCE, STATMOUNT_SUPPORTED_MASK,
};
use rk_abi::native::types::Statmount;
use rk_vfs::dentry::{Location, Mount, MountNamespace, UNIQUE_ID_OFFSET};
use rk_vfs::device::{major, minor};
use rk_vfs::nsfs::{NsInode, NsKind};
use rk_vfs::{FsContext, cred::cap};
use zerocopy::{FromZeros, IntoBytes};

/// The most bytes of a `struct mnt_id_req`, `PAGE_SIZE` of `copy_mnt_id_req` of Linux.
const REQ_MAX: u32 = 4096;

/// The most IDs of one `listmount`, as Linux.
const LIST_MAX: u64 = 1_000_000;

/// The size of `struct statmount` without the strings.
const SM_SIZE: usize = size_of::<Statmount>();

/// The flags of the mask that this kernel gives, `STATMOUNT_SUPPORTED` of Linux without the ID
/// maps.
const SUPPORTED: u32 = STATMOUNT_SB_BASIC
    | STATMOUNT_MNT_BASIC
    | STATMOUNT_PROPAGATE_FROM
    | STATMOUNT_MNT_ROOT
    | STATMOUNT_MNT_POINT
    | STATMOUNT_FS_TYPE
    | STATMOUNT_MNT_OPTS
    | STATMOUNT_FS_SUBTYPE
    | STATMOUNT_SB_SOURCE
    | STATMOUNT_OPT_ARRAY
    | STATMOUNT_OPT_SEC_ARRAY
    | STATMOUNT_MNT_NS_ID
    | STATMOUNT_SUPPORTED_MASK;

/// The flags of the mask that give a string, `STATMOUNT_STRING_REQ` of Linux.
const STRING_REQ: u32 = STATMOUNT_MNT_ROOT
    | STATMOUNT_MNT_POINT
    | STATMOUNT_FS_TYPE
    | STATMOUNT_MNT_OPTS
    | STATMOUNT_FS_SUBTYPE
    | STATMOUNT_SB_SOURCE
    | STATMOUNT_OPT_ARRAY
    | STATMOUNT_OPT_SEC_ARRAY
    | STATMOUNT_MNT_UIDMAP
    | STATMOUNT_MNT_GIDMAP;

/// The fields of `struct mnt_id_req`.
struct Request {
    /// `mnt_ns_fd`, or `mnt_fd` for `STATMOUNT_BY_FD`.
    fd: u32,
    mnt_id: u64,
    param: u64,
    mnt_ns_id: u64,
}

/// Reads the request at `addr`, as `copy_mnt_id_req` of Linux. The bytes after the known fields
/// must be 0.
fn read_request(cx: &Cx<'_>, addr: u64, by_fd: bool) -> Result<Request, Errno> {
    let size: u32 = cx.read_val(addr)?;
    if size > REQ_MAX {
        return Err(Errno::E2BIG);
    }
    if size < MNT_ID_REQ_SIZE_VER0 {
        return Err(Errno::EINVAL);
    }
    let bytes = cx.read_bytes(addr, size as usize)?;
    let known = MNT_ID_REQ_SIZE_VER1 as usize;
    if bytes.len() > known && bytes[known..].iter().any(|&b| b != 0) {
        return Err(Errno::E2BIG);
    }
    let mut raw = [0u8; MNT_ID_REQ_SIZE_VER1 as usize];
    let n = bytes.len().min(known);
    raw[..n].copy_from_slice(&bytes[..n]);
    let u64_at = |at: usize| u64::from_ne_bytes(raw[at..at + 8].try_into().unwrap_or_default());
    let req = Request {
        fd: u32::from_ne_bytes(raw[4..8].try_into().unwrap_or_default()),
        mnt_id: u64_at(8),
        param: u64_at(16),
        mnt_ns_id: u64_at(24),
    };
    if by_fd {
        if req.mnt_id != 0 || req.mnt_ns_id != 0 {
            return Err(Errno::EINVAL);
        }
    } else if (req.fd != 0 && req.mnt_ns_id != 0) || req.mnt_id <= UNIQUE_ID_OFFSET {
        return Err(Errno::EINVAL);
    }
    Ok(req)
}

/// The name space of the request, as `grab_requested_mnt_ns` of Linux. Another name space than
/// the name space of the caller needs `CAP_SYS_ADMIN`.
fn namespace(cx: &Cx<'_>, fs: &FsContext, req: &Request) -> Result<Arc<MountNamespace>, Errno> {
    if req.mnt_ns_id != 0 {
        let id = NsInode::id_of(NsKind::Mnt, req.mnt_ns_id).ok_or(Errno::ENOENT)?;
        let ns = rk_proc::ns::mnt_ns(id).ok_or(Errno::ENOENT)?;
        if !Arc::ptr_eq(&ns, fs.namespace()) && !cx.process().cred().capable(cap::SYS_ADMIN) {
            return Err(Errno::EPERM);
        }
        return Ok(ns);
    }
    if req.fd != 0 {
        cx.file(u64::from(req.fd))?;
        return Err(Errno::EINVAL);
    }
    Ok(fs.namespace().clone())
}

/// The location of the root of `mount`.
fn top(mount: &Arc<Mount>) -> Location {
    Location { mount: mount.clone(), dentry: mount.root().clone() }
}

/// Checks that the caller can see `at`: it is under the root of the caller, or the caller has
/// `CAP_SYS_ADMIN`.
fn may_see(cx: &Cx<'_>, fs: &FsContext, at: &Location) -> Result<(), Errno> {
    if at.is_reachable_from(fs.root()) || cx.process().cred().capable(cap::SYS_ADMIN) {
        Ok(())
    } else {
        Err(Errno::EPERM)
    }
}

pub(crate) fn listmount(cx: &Cx<'_>, req: u64, ids: u64, nr: u64, flags: u64) -> SysResult {
    if flags & !u64::from(LISTMOUNT_REVERSE) != 0 {
        return Err(Errno::EINVAL);
    }
    if nr > LIST_MAX {
        return Err(Errno::EOVERFLOW);
    }
    let req = read_request(cx, req, false)?;
    let last = req.param;
    if last != 0 && last <= UNIQUE_ID_OFFSET {
        return Err(Errno::EINVAL);
    }
    let fs = cx.fs()?;
    let ns = namespace(cx, &fs, &req)?;
    let orig = if req.mnt_id == LSMT_ROOT {
        fs.root().clone()
    } else {
        top(&ns.find_unique(req.mnt_id).ok_or(Errno::ENOENT)?)
    };
    may_see(cx, &fs, &orig)?;
    let reverse = flags & u64::from(LISTMOUNT_REVERSE) != 0;
    let mut mounts = ns.mounts();
    mounts.sort_by_key(|m| m.unique_id());
    if reverse {
        mounts.reverse();
    }
    let mut out: Vec<u64> = Vec::new();
    for m in mounts {
        if out.len() as u64 == nr {
            break;
        }
        let id = m.unique_id();
        let after = last == 0 || if reverse { id < last } else { id > last };
        if !after || id == req.mnt_id || !top(&m).is_reachable_from(&orig) {
            continue;
        }
        out.push(id);
    }
    if !out.is_empty() {
        cx.write_bytes(ids, out.as_bytes())?;
    }
    Ok(out.len() as u64)
}

/// The `MOUNT_ATTR_*` flags of a mount with the `MS_*` flags `flags`, as `mnt_to_attr_flags` of
/// Linux.
fn attr_flags(flags: u32) -> u64 {
    let bits = [
        (MS_RDONLY, MOUNT_ATTR_RDONLY),
        (MS_NOSUID, MOUNT_ATTR_NOSUID),
        (MS_NODEV, MOUNT_ATTR_NODEV),
        (MS_NOEXEC, MOUNT_ATTR_NOEXEC),
        (MS_NODIRATIME, MOUNT_ATTR_NODIRATIME),
        (MS_NOSYMFOLLOW, MOUNT_ATTR_NOSYMFOLLOW),
    ];
    let mut attr = bits.iter().filter(|(ms, _)| flags & ms != 0).fold(0, |all, (_, a)| all | a);
    attr |= if flags & MS_NOATIME != 0 {
        MOUNT_ATTR_NOATIME
    } else if flags & MS_RELATIME != 0 {
        MOUNT_ATTR_RELATIME
    } else {
        MOUNT_ATTR_STRICTATIME
    };
    u64::from(attr)
}

/// The `MS_*` propagation flags of a mount, as `mnt_to_propagation_flags` of Linux.
fn propagation_flags(mount: &Mount) -> u64 {
    let p = mount.propagation();
    let mut flags = 0;
    if p.group != 0 {
        flags |= MS_SHARED;
    }
    if p.master != 0 {
        flags |= MS_SLAVE;
    }
    if p.unbindable {
        flags |= MS_UNBINDABLE;
    }
    if flags == 0 {
        flags = MS_PRIVATE;
    }
    u64::from(flags)
}

/// The result of `statmount` while it is made, as `struct kstatmount` of Linux.
struct Stat {
    sm: Statmount,
    /// The strings after the structure. The first byte is the empty string of each offset that
    /// the result does not set.
    strings: Vec<u8>,
    /// The size of the buffer of the caller.
    bufsize: usize,
}

impl Stat {
    /// Adds the string `s` for the flag `flag` and gives its offset, as `statmount_string` of
    /// Linux. An empty string adds nothing.
    fn string(&mut self, flag: u32, s: &[u8]) -> Result<Option<u32>, Errno> {
        if self.strings.is_empty() {
            self.strings.push(0);
        }
        if s.is_empty() {
            return Ok(None);
        }
        let start = self.strings.len();
        self.strings.extend_from_slice(s);
        if SM_SIZE + self.strings.len() >= self.bufsize {
            return Err(Errno::EOVERFLOW);
        }
        self.strings.push(0);
        self.sm.mask |= u64::from(flag);
        Ok(Some(start as u32))
    }

    /// Adds a list of strings with a 0 after each, as `statmount_opt_array` of Linux. Gives the
    /// offset and the number of strings.
    fn array(&mut self, flag: u32, list: &[&[u8]]) -> Result<Option<(u32, u32)>, Errno> {
        let mut joined = Vec::new();
        for (i, s) in list.iter().enumerate() {
            if i > 0 {
                joined.push(0);
            }
            joined.extend_from_slice(s);
        }
        Ok(self.string(flag, &joined)?.map(|at| (at, list.len() as u32)))
    }
}

pub(crate) fn statmount(cx: &Cx<'_>, req: u64, buf: u64, bufsize: u64, flags: u64) -> SysResult {
    if flags & !u64::from(STATMOUNT_BY_FD) != 0 {
        return Err(Errno::EINVAL);
    }
    let by_fd = flags != 0;
    let req = read_request(cx, req, by_fd)?;
    let fs = cx.fs()?;
    let mut mask = req.param;
    let bufsize = usize::try_from(bufsize).map_err(|_| Errno::EOVERFLOW)?;
    if mask & u64::from(STRING_REQ) != 0 && bufsize == SM_SIZE {
        return Err(Errno::EOVERFLOW);
    }
    let mut ns = Some(fs.namespace().clone());
    let mount = if by_fd {
        let file = cx.file(u64::from(req.fd))?;
        let mount = file.location().ok_or(Errno::EINVAL)?.mount.clone();
        if !ns.as_ref().is_some_and(|ns| ns.contains(&mount)) {
            // A mount of another name space has no path and no name space ID here.
            mask &= !u64::from(STATMOUNT_MNT_POINT | STATMOUNT_MNT_NS_ID);
            ns = None;
        }
        mount
    } else {
        let found = namespace(cx, &fs, &req)?;
        let mount = found.find_unique(req.mnt_id).ok_or(Errno::ENOENT)?;
        may_see(cx, &fs, &top(&mount))?;
        ns = Some(found);
        mount
    };
    let mut st = Stat { sm: Statmount::new_zeroed(), strings: Vec::new(), bufsize };
    let has = |flag: u32| mask & u64::from(flag) != 0;
    let source = mount.source();
    let mflags = source.flags as u32;
    let root = mount.root().inode().clone();
    if has(STATMOUNT_MNT_BASIC) {
        let sm = &mut st.sm;
        sm.mask |= u64::from(STATMOUNT_MNT_BASIC);
        sm.mnt_id = mount.unique_id();
        sm.mnt_id_old = mount.id() as u32;
        // The root mount is its own parent, as Linux.
        let parent = mount.parent().unwrap_or_else(|| mount.clone());
        sm.mnt_parent_id = parent.unique_id();
        sm.mnt_parent_id_old = parent.id() as u32;
        sm.mnt_attr = attr_flags(mflags);
        sm.mnt_propagation = propagation_flags(&mount);
        sm.mnt_peer_group = mount.propagation().group;
        sm.mnt_master = mount.propagation().master;
    }
    if has(STATMOUNT_SB_BASIC) {
        let dev = root.metadata().dev;
        let sm = &mut st.sm;
        sm.mask |= u64::from(STATMOUNT_SB_BASIC);
        sm.sb_dev_major = major(dev);
        sm.sb_dev_minor = minor(dev);
        sm.sb_magic = crate::fs::fs_magic(Some(&root));
        let ro = if root.is_read_only() { MS_RDONLY } else { 0 };
        sm.sb_flags = ro | (mflags & (MS_SYNCHRONOUS | MS_DIRSYNC | MS_LAZYTIME));
    }
    if has(STATMOUNT_PROPAGATE_FROM) {
        st.sm.mask |= u64::from(STATMOUNT_PROPAGATE_FROM);
        if mount.propagation().master != 0 {
            st.sm.propagate_from = fs.namespace().propagate_from(&mount, fs.root());
        }
    }
    if has(STATMOUNT_FS_TYPE)
        && let Some(at) = st.string(STATMOUNT_FS_TYPE, source.fstype.as_bytes())?
    {
        st.sm.fs_type = at;
    }
    if has(STATMOUNT_MNT_ROOT)
        && let Some(at) = st.string(STATMOUNT_MNT_ROOT, &mount.root().fs_path())?
    {
        st.sm.mnt_root = at;
    }
    // A mount that is not under the root of the caller has no path, as `seq_path_root` of Linux.
    if has(STATMOUNT_MNT_POINT) {
        let at = top(&mount);
        let path = if at.is_reachable_from(fs.root()) { fs.path_of(&at)? } else { Vec::new() };
        if let Some(at) = st.string(STATMOUNT_MNT_POINT, &path)? {
            st.sm.mnt_point = at;
        }
    }
    // The options of the file system have a comma before each.
    let options = root.fs_options();
    let list: Vec<&[u8]> = options.split(|&b| b == b',').filter(|o| !o.is_empty()).collect();
    if has(STATMOUNT_MNT_OPTS)
        && let Some(at) = st.string(STATMOUNT_MNT_OPTS, &list.join(&b","[..]))?
    {
        st.sm.mnt_opts = at;
    }
    if has(STATMOUNT_OPT_ARRAY)
        && let Some((at, n)) = st.array(STATMOUNT_OPT_ARRAY, &list)?
    {
        st.sm.opt_array = at;
        st.sm.opt_num = n;
    }
    if has(STATMOUNT_SB_SOURCE)
        && let Some(at) = st.string(STATMOUNT_SB_SOURCE, &source.source)?
    {
        st.sm.sb_source = at;
    }
    if has(STATMOUNT_MNT_NS_ID)
        && let Some(ns) = &ns
    {
        st.sm.mask |= u64::from(STATMOUNT_MNT_NS_ID);
        st.sm.mnt_ns_id = NsInode::ino(NsKind::Mnt, rk_proc::ns::mnt_id(ns));
    }
    if has(STATMOUNT_SUPPORTED_MASK) {
        st.sm.mask |= u64::from(STATMOUNT_SUPPORTED_MASK);
        st.sm.supported_mask = u64::from(SUPPORTED);
    }
    // The structure, or its start if the buffer is small, and then the strings, as
    // `copy_statmount_to_user` of Linux.
    let copy = bufsize.min(SM_SIZE);
    if !st.strings.is_empty() {
        cx.write_bytes(buf + SM_SIZE as u64, &st.strings)?;
    }
    st.sm.size = (copy + st.strings.len()) as u32;
    cx.write_bytes(buf, &st.sm.as_bytes()[..copy])?;
    Ok(0)
}

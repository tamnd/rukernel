//! The extended attribute calls: `setxattr`, `getxattr`, `listxattr` and `removexattr`, with
//! their `l` forms, which do not follow a symbolic link, and their `f` forms, which take a file
//! descriptor. Linux has them in fs/xattr.c.

use crate::cx::{Cx, SysResult};
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::InodeRef;
use rk_vfs::xattr::{XATTR_CREATE, XATTR_REPLACE};

/// The longest name of an attribute, without the null byte.
const XATTR_NAME_MAX: usize = 255;
/// The largest value of an attribute.
const XATTR_SIZE_MAX: usize = 65536;
/// The largest list of names.
const XATTR_LIST_MAX: usize = 65536;
/// The namespaces that the kernel knows. `system.` holds the ACLs, which no file system keeps
/// yet, so a name in it gives `EOPNOTSUPP`.
const NAMESPACES: [&[u8]; 3] = [b"user.", b"trusted.", b"security."];

/// The file of an attribute call. A file descriptor of a pipe or a socket has no inode.
type Target = Option<InodeRef>;

/// Finds the inode of the path at `path`.
fn path_target(cx: &Cx<'_>, path: u64, follow: bool) -> Result<Target, Errno> {
    let path = cx.read_path(path)?;
    let fs = cx.fs()?;
    let start = fs.cwd().clone();
    Ok(Some(fs.resolve(&start, &path, follow)?.inode().clone()))
}

/// Finds the inode of the open file `fd`.
fn fd_target(cx: &Cx<'_>, fd: u64) -> Result<Target, Errno> {
    Ok(cx.file(fd)?.inode().cloned())
}

/// Reads the name of an attribute. An empty name or a name that is too long gives `ERANGE`, and
/// a name outside the known namespaces gives `EOPNOTSUPP`, as Linux.
fn read_name(cx: &Cx<'_>, addr: u64) -> Result<Vec<u8>, Errno> {
    let name = cx
        .vm()?
        .read_cstr(addr as usize, XATTR_NAME_MAX + 1)
        .map_err(|e| if e == Errno::ENAMETOOLONG { Errno::ERANGE } else { e })?;
    if name.is_empty() {
        return Err(Errno::ERANGE);
    }
    if !NAMESPACES.iter().any(|ns| name.starts_with(ns)) {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(name)
}

/// Linux keeps a `user.` attribute only on a regular file and a directory. A change of one on
/// another file gives `EPERM`, and a read gives `ENODATA`.
fn check_user(inode: &InodeRef, name: &[u8], change: bool) -> Result<(), Errno> {
    let meta = inode.metadata();
    if name.starts_with(b"user.")
        && !meta.is_dir()
        && meta.file_type() != Some(rk_vfs::FileType::Regular)
    {
        return Err(if change { Errno::EPERM } else { Errno::ENODATA });
    }
    Ok(())
}

/// Copies `data` to the user buffer at `addr` of `size` bytes. A size of 0 asks for the length.
/// Gives `ERANGE` if the buffer is too small, and `E2BIG` if the data is larger than `max`.
fn give(cx: &Cx<'_>, addr: u64, size: u64, data: &[u8], max: usize) -> SysResult {
    if data.len() > max {
        return Err(Errno::E2BIG);
    }
    if size == 0 {
        return Ok(data.len() as u64);
    }
    if (size.min(max as u64) as usize) < data.len() {
        return Err(Errno::ERANGE);
    }
    cx.write_bytes(addr, data)?;
    Ok(data.len() as u64)
}

fn set(cx: &Cx<'_>, target: Target, name: Vec<u8>, value: u64, size: u64, flags: u64) -> SysResult {
    let Some(inode) = target else {
        return Err(Errno::EOPNOTSUPP);
    };
    check_user(&inode, &name, true)?;
    let value = if size == 0 { Vec::new() } else { cx.read_bytes(value, size as usize)? };
    inode.set_xattr(&name, &value, flags as u32)?;
    Ok(0)
}

/// Checks the flags and the size of `setxattr` before the call finds the file, as Linux.
fn set_args(cx: &Cx<'_>, name: u64, size: u64, flags: u64) -> Result<Vec<u8>, Errno> {
    if flags & !u64::from(XATTR_CREATE | XATTR_REPLACE) != 0 {
        return Err(Errno::EINVAL);
    }
    let name = read_name(cx, name)?;
    if size > XATTR_SIZE_MAX as u64 {
        return Err(Errno::E2BIG);
    }
    Ok(name)
}

fn get(cx: &Cx<'_>, target: Target, name: Vec<u8>, value: u64, size: u64) -> SysResult {
    let Some(inode) = target else {
        return Err(Errno::ENODATA);
    };
    check_user(&inode, &name, false)?;
    let data = inode.get_xattr(&name)?;
    give(cx, value, size, &data, XATTR_SIZE_MAX)
}

fn list(cx: &Cx<'_>, target: Target, addr: u64, size: u64) -> SysResult {
    let Some(inode) = target else {
        return Ok(0);
    };
    let mut out = Vec::new();
    for name in inode.list_xattr()? {
        out.extend_from_slice(&name);
        out.push(0);
    }
    give(cx, addr, size, &out, XATTR_LIST_MAX)
}

fn remove(target: Target, name: Vec<u8>) -> SysResult {
    let Some(inode) = target else {
        return Err(Errno::ENODATA);
    };
    check_user(&inode, &name, true)?;
    inode.remove_xattr(&name)?;
    Ok(0)
}

pub(crate) fn path_setxattr(
    cx: &Cx<'_>,
    path: u64,
    name: u64,
    value: u64,
    size: u64,
    flags: u64,
    follow: bool,
) -> SysResult {
    let name = set_args(cx, name, size, flags)?;
    set(cx, path_target(cx, path, follow)?, name, value, size, flags)
}

pub(crate) fn fsetxattr(
    cx: &Cx<'_>,
    fd: u64,
    name: u64,
    value: u64,
    size: u64,
    flags: u64,
) -> SysResult {
    let name = set_args(cx, name, size, flags)?;
    set(cx, fd_target(cx, fd)?, name, value, size, flags)
}

pub(crate) fn path_getxattr(
    cx: &Cx<'_>,
    path: u64,
    name: u64,
    value: u64,
    size: u64,
    follow: bool,
) -> SysResult {
    let target = path_target(cx, path, follow)?;
    get(cx, target, read_name(cx, name)?, value, size)
}

pub(crate) fn fgetxattr(cx: &Cx<'_>, fd: u64, name: u64, value: u64, size: u64) -> SysResult {
    let target = fd_target(cx, fd)?;
    get(cx, target, read_name(cx, name)?, value, size)
}

pub(crate) fn path_listxattr(
    cx: &Cx<'_>,
    path: u64,
    list_addr: u64,
    size: u64,
    follow: bool,
) -> SysResult {
    list(cx, path_target(cx, path, follow)?, list_addr, size)
}

pub(crate) fn flistxattr(cx: &Cx<'_>, fd: u64, list_addr: u64, size: u64) -> SysResult {
    list(cx, fd_target(cx, fd)?, list_addr, size)
}

pub(crate) fn path_removexattr(cx: &Cx<'_>, path: u64, name: u64, follow: bool) -> SysResult {
    let target = path_target(cx, path, follow)?;
    remove(target, read_name(cx, name)?)
}

pub(crate) fn fremovexattr(cx: &Cx<'_>, fd: u64, name: u64) -> SysResult {
    let target = fd_target(cx, fd)?;
    remove(target, read_name(cx, name)?)
}

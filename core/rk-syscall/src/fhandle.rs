//! The file handle calls: `name_to_handle_at` and `open_by_handle_at`. A file handle names an
//! inode of a file system without a path, and stays valid after a rename of the file or a new
//! mount of the file system. Linux has them in fs/fhandle.c.

use crate::cx::{Cx, SysResult};
use rk_abi::Errno;
use rk_abi::native::at::{
    AT_EMPTY_PATH, AT_FDCWD, AT_HANDLE_FID, AT_HANDLE_MNT_ID_UNIQUE, AT_SYMLINK_FOLLOW,
};
use rk_abi::native::open::{O_CLOEXEC, O_CREAT, O_EXCL};
use rk_vfs::inode::fileid;
use zerocopy::IntoBytes;

/// The largest handle in bytes, `MAX_HANDLE_SZ` of `<linux/fcntl.h>`.
const MAX_HANDLE_SZ: u32 = 128;
/// The bits of `handle_type` that are flags of the VFS, not of the file system.
const FILEID_USER_FLAGS_MASK: i32 = 0xffff_0000_u32 as i32;
/// The flag of a handle of a parent and its child, from `AT_HANDLE_CONNECTABLE`.
const FILEID_IS_CONNECTABLE: i32 = 0x1_0000;
/// The flag of a handle of a directory, from `AT_HANDLE_CONNECTABLE`.
const FILEID_IS_DIR: i32 = 0x2_0000;

/// Reads the head of a `struct file_handle`: `handle_bytes` and `handle_type`.
fn read_head(cx: &Cx<'_>, handle: u64) -> Result<(u32, i32), Errno> {
    let head: [u32; 2] = cx.read_val(handle)?;
    Ok((head[0], head[1] as i32))
}

/// `name_to_handle_at`. `AT_HANDLE_CONNECTABLE` gives `EINVAL`, as on Linux before 6.13. With
/// `AT_HANDLE_FID`, a file system that cannot find an inode from a handle gives the inode
/// number, as `exportfs_encode_inode_fh` of Linux.
pub(crate) fn name_to_handle_at(
    cx: &Cx<'_>,
    dirfd: u64,
    path: u64,
    handle: u64,
    mnt_id: u64,
    flags: u64,
) -> SysResult {
    let flags = flags as i32;
    let known = AT_SYMLINK_FOLLOW | AT_EMPTY_PATH | AT_HANDLE_FID | AT_HANDLE_MNT_ID_UNIQUE;
    if flags & !known != 0 {
        return Err(Errno::EINVAL);
    }
    let path = cx.read_path_opt(path, flags & AT_EMPTY_PATH != 0)?;
    let fs = cx.fs()?;
    let start = cx.dir_start(&fs, dirfd, &path)?;
    let at = if path.is_empty() {
        start
    } else {
        fs.resolve(&start, &path, flags & AT_SYMLINK_FOLLOW != 0)?
    };
    let inode = at.inode();
    let (ty, words) = match inode.file_handle() {
        Some(fh) => fh,
        None if flags & AT_HANDLE_FID != 0 => {
            (fileid::INO32_GEN, alloc::vec![inode.metadata().ino as u32, 0])
        }
        None => return Err(Errno::EOPNOTSUPP),
    };
    let (size, _) = read_head(cx, handle)?;
    if size > MAX_HANDLE_SZ {
        return Err(Errno::EINVAL);
    }
    let id = at.mount.id();
    if flags & AT_HANDLE_MNT_ID_UNIQUE != 0 {
        cx.write_val(mnt_id, &id)?;
    } else {
        cx.write_val(mnt_id, &(id as i32))?;
    }
    let need = (words.len() * 4) as u32;
    // A small buffer gets the size that the handle needs, and no handle.
    if need > size {
        cx.write_val(handle, &[need, fileid::INVALID as u32])?;
        return Err(Errno::EOVERFLOW);
    }
    cx.write_val(handle, &[need, ty as u32])?;
    cx.write_bytes(handle + 8, words.as_bytes())?;
    Ok(0)
}

/// `open_by_handle_at`. `mountdirfd` gives the mount, and `flags` are the flags of `open`.
pub(crate) fn open_by_handle_at(
    cx: &Cx<'_>,
    mountdirfd: u64,
    handle: u64,
    flags: u64,
) -> SysResult {
    let (size, ty) = read_head(cx, handle)?;
    if size > MAX_HANDLE_SZ || size == 0 {
        return Err(Errno::EINVAL);
    }
    if ty < 0 || ty & FILEID_USER_FLAGS_MASK & !(FILEID_IS_CONNECTABLE | FILEID_IS_DIR) != 0 {
        return Err(Errno::EINVAL);
    }
    let fs = cx.fs()?;
    let mount = match mountdirfd as i32 {
        AT_FDCWD => fs.cwd().clone(),
        fd if fd >= 0 => cx.file(mountdirfd)?.location().ok_or(Errno::EBADF)?.clone(),
        _ => return Err(Errno::EBADF),
    };
    let bytes = cx.read_bytes(handle + 8, size as usize)?;
    let words: alloc::vec::Vec<u32> =
        bytes.chunks_exact(4).map(|w| u32::from_ne_bytes([w[0], w[1], w[2], w[3]])).collect();
    let at = fs.handle_location(&mount, ty & !FILEID_USER_FLAGS_MASK, &words)?;
    if ty & FILEID_IS_DIR != 0 && !at.inode().metadata().is_dir() {
        return Err(Errno::ESTALE);
    }
    let flags = flags as u32 & !(O_CREAT | O_EXCL);
    let file = fs.open_at(at, flags)?;
    let fd = cx.files()?.lock().insert(file, flags & O_CLOEXEC != 0)?;
    Ok(fd as u64)
}

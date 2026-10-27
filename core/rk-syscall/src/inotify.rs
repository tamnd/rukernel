//! inotify: `inotify_init`, `inotify_init1`, `inotify_add_watch` and `inotify_rm_watch`, as
//! fs/notify/inotify/inotify_user.c of Linux. The instance, its queue and its marks are in
//! `rk_vfs::notify::inotify`.

use crate::cx::{Cx, SysResult};
use alloc::sync::Arc;
use rk_abi::Errno;
use rk_abi::native::open::O_RDONLY;
use rk_vfs::cred::may;
use rk_vfs::file::File;
use rk_vfs::notify::inotify::{ALL_BITS, Inotify, InotifyFile, flags};

pub(crate) fn inotify_init1(cx: &Cx<'_>, arg: u64) -> SysResult {
    let arg = u32::try_from(arg).map_err(|_| Errno::EINVAL)?;
    if arg & !(flags::CLOEXEC | flags::NONBLOCK) != 0 {
        return Err(Errno::EINVAL);
    }
    let ops = InotifyFile::new(cx.process().cred().euid)?;
    let file = File::with_ops(Arc::new(ops), None, O_RDONLY | (arg & flags::NONBLOCK));
    Ok(cx.files()?.lock().insert(file, arg & flags::CLOEXEC != 0)? as u64)
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn inotify_init(cx: &Cx<'_>) -> SysResult {
    inotify_init1(cx, 0)
}

/// The instance of the descriptor `fd`. Gives `EBADF` for a bad descriptor and `EINVAL` for a
/// file that is not an instance, as Linux.
fn instance(cx: &Cx<'_>, fd: u64) -> Result<Arc<Inotify>, Errno> {
    let file = cx.file(fd)?;
    file.ops()
        .as_any()
        .and_then(|a| a.downcast_ref::<InotifyFile>())
        .map(|f| f.group().clone())
        .ok_or(Errno::EINVAL)
}

pub(crate) fn inotify_add_watch(cx: &Cx<'_>, fd: u64, path: u64, mask: u64) -> SysResult {
    let mask = mask as u32;
    if mask & flags::MASK_ADD != 0 && mask & flags::MASK_CREATE != 0 {
        return Err(Errno::EINVAL);
    }
    if mask & ALL_BITS == 0 {
        return Err(Errno::EINVAL);
    }
    let group = instance(cx, fd)?;
    let path = cx.read_path(path)?;
    let fs = cx.fs()?;
    // As `inotify_find_inode` of Linux: the watch needs the read permission.
    let at = fs.resolve(fs.cwd(), &path, mask & flags::DONT_FOLLOW == 0)?;
    if mask & flags::ONLYDIR != 0 && !at.inode().metadata().is_dir() {
        return Err(Errno::ENOTDIR);
    }
    fs.permission(&at, may::READ)?;
    let wd = group.add_watch(at.inode(), mask)?;
    Ok(wd as u64)
}

pub(crate) fn inotify_rm_watch(cx: &Cx<'_>, fd: u64, wd: u64) -> SysResult {
    let group = instance(cx, fd)?;
    group.rm_watch(wd as i32)?;
    Ok(0)
}

//! `swapon` and `swapoff`. The VFS keeps the active areas, and rukernel does not move pages to
//! them yet. See [`rk_vfs::swap`].

use crate::cx::{Cx, SysResult};
use rk_abi::Errno;
use rk_abi::native::open::{O_EXCL, O_LARGEFILE, O_RDWR};
use rk_vfs::FileType;
use rk_vfs::swap::flags::VALID;

/// Checks that the caller can change the swap areas: it needs `CAP_SYS_ADMIN`, as Linux.
fn may_swap(cx: &Cx<'_>) -> Result<(), Errno> {
    if cx.process().cred().capable(rk_vfs::cred::cap::SYS_ADMIN) {
        Ok(())
    } else {
        Err(Errno::EPERM)
    }
}

/// `swapon`. The checks are those of Linux, in its order: the flags, the capability, the path,
/// and then the file and its header.
pub(crate) fn swapon(cx: &Cx<'_>, path: u64, flags: u64) -> SysResult {
    // The flags are an `int`.
    let flags = flags as u32;
    if flags & !VALID != 0 {
        return Err(Errno::EINVAL);
    }
    may_swap(cx)?;
    let path = cx.read_path(path)?;
    let fs = cx.fs()?;
    let at = fs.resolve(fs.cwd(), &path, true)?;
    // A block device is claimed, so a mounted device gives `EBUSY`.
    let block = at.inode().metadata().file_type() == Some(FileType::BlockDevice);
    let open = O_RDWR | O_LARGEFILE | if block { O_EXCL } else { 0 };
    let file = fs.open(fs.cwd(), &path, open, 0)?;
    let name = file.location().map_or(path, rk_vfs::Location::absolute_path);
    rk_vfs::swap::activate(file, name, flags)?;
    rk_mm::tunables::set_swap_pages(rk_vfs::swap::total_pages() as usize);
    Ok(0)
}

/// `swapoff`. A path that is not an active area gives `EINVAL`.
pub(crate) fn swapoff(cx: &Cx<'_>, path: u64) -> SysResult {
    may_swap(cx)?;
    let path = cx.read_path(path)?;
    let fs = cx.fs()?;
    let at = fs.resolve(fs.cwd(), &path, true)?;
    rk_vfs::swap::deactivate(at.inode())?;
    rk_mm::tunables::set_swap_pages(rk_vfs::swap::total_pages() as usize);
    Ok(0)
}

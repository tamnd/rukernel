//! `swapon` and `swapoff`. The VFS keeps the active areas. See [`rk_vfs::swap`].

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

/// The passes of `swapoff` over the processes. After a pass that reads no page, the pages that
/// stay used make the call give `EBUSY`.
const UNUSE_PASSES: usize = 4;

/// `swapoff`. A path that is not an active area gives `EINVAL`. The pages that entries use in the
/// area come back into memory first, as `try_to_unuse` of Linux. After an error, the area stays
/// active.
pub(crate) fn swapoff(cx: &Cx<'_>, path: u64) -> SysResult {
    may_swap(cx)?;
    let path = cx.read_path(path)?;
    let fs = cx.fs()?;
    let at = fs.resolve(fs.cwd(), &path, true)?;
    let inode = at.inode();
    let (kind, used) = rk_vfs::swap::begin_off(inode)?;
    let done = unuse(cx, kind, used).and_then(|()| rk_vfs::swap::deactivate(inode));
    if done.is_err() {
        rk_vfs::swap::cancel(inode);
    }
    done?;
    rk_mm::tunables::set_swap_pages(rk_vfs::swap::total_pages() as usize);
    Ok(0)
}

/// Reads the `used` pages of the area of type `kind` back into the processes that have them.
///
/// # Errors
///
/// Gives `ENOMEM` if the pages do not fit in the free memory, as the check of `swapoff` of Linux
/// with `security_vm_enough_memory_mm`, or if a read finds no free frame. Gives `EINTR` if a
/// signal comes, and `EIO` if the disk gives an error.
fn unuse(cx: &Cx<'_>, kind: u64, used: u64) -> Result<(), Errno> {
    if used == 0 {
        return Ok(());
    }
    let stats = rk_frame::mm::frame_stats();
    let free = stats.free.saturating_sub(rk_mm::tunables::reserve_pages(stats.total));
    if used > free as u64 {
        return Err(Errno::ENOMEM);
    }
    for _ in 0..UNUSE_PASSES {
        let mut n = 0;
        for p in rk_proc::processes().into_iter().filter(|p| !p.is_zombie()) {
            if cx.thread.signal_pending() {
                return Err(Errno::EINTR);
            }
            let Some(vm) = p.vm() else { continue };
            n += vm.unuse_swap(|e| rk_vfs::swap::kind_of(e) == kind)?;
        }
        if n == 0 || rk_vfs::swap::used_of(kind) == 0 {
            break;
        }
    }
    Ok(())
}

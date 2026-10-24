//! The system call `memfd_create`: a file in memory with no name in the tree.
//!
//! Each file is a regular file of one private tmpfs. The call makes the file in the root of that
//! tmpfs, then removes the name at once, as `shmem_file_setup` of Linux gives a file with no
//! link. The dentry keeps the name `memfd:NAME`, thus `/proc/PID/fd` shows that name.

use crate::cx::{Cx, SysResult};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::open::{O_LARGEFILE, O_RDWR};
use rk_frame::sync::SpinLock;
use rk_vfs::inode::FileType;
use rk_vfs::{File, Location, MountNamespace};

/// The flags of `memfd_create`.
const MFD_CLOEXEC: u32 = 0x1;
const MFD_ALLOW_SEALING: u32 = 0x2;
const MFD_HUGETLB: u32 = 0x4;
const MFD_NOEXEC_SEAL: u32 = 0x8;
const MFD_EXEC: u32 = 0x10;

/// The longest name, without the prefix `memfd:` and the null byte, as `MFD_NAME_MAX_LEN`.
const NAME_MAX: usize = 249;

/// The root of the private tmpfs, made at the first call.
static ROOT: SpinLock<Option<Location>> = SpinLock::new(None);

/// A counter that makes each name in the root unique.
static NEXT: AtomicU64 = AtomicU64::new(1);

fn root() -> Location {
    let mut root = ROOT.lock();
    root.get_or_insert_with(|| MountNamespace::new(rk_fs_tmpfs::new(0o1777)).root()).clone()
}

pub(crate) fn memfd_create(cx: &Cx<'_>, name: u64, flags: u64) -> SysResult {
    let flags = u32::try_from(flags).map_err(|_| Errno::EINVAL)?;
    if flags & !(MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB | MFD_NOEXEC_SEAL | MFD_EXEC) != 0
        || flags & MFD_HUGETLB != 0
        || flags & (MFD_NOEXEC_SEAL | MFD_EXEC) == MFD_NOEXEC_SEAL | MFD_EXEC
    {
        return Err(Errno::EINVAL);
    }
    let name = match cx.vm()?.read_cstr(name as usize, NAME_MAX + 1) {
        Err(Errno::ENAMETOOLONG) => return Err(Errno::EINVAL),
        r => r?,
    };
    let root = root();
    let mut temp = Vec::from(&b"memfd."[..]);
    temp.extend_from_slice(alloc::format!("{}", NEXT.fetch_add(1, Ordering::Relaxed)).as_bytes());
    let inode = root.inode().create(&temp, FileType::Regular, 0o777, 0)?;
    let mut shown = Vec::from(&b"memfd:"[..]);
    shown.extend_from_slice(&name);
    let dentry = root.dentry.add_child(&shown, inode);
    root.dentry.forget_child(&shown);
    root.inode().unlink(&temp)?;
    let file = File::open_inode(Location { mount: root.mount, dentry }, O_RDWR | O_LARGEFILE);
    let fd = cx.files()?.lock().insert(file, flags & MFD_CLOEXEC != 0)?;
    Ok(fd as u64)
}

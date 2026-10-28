//! The system call `memfd_create`: a file in memory with no name in the tree.
//!
//! Each file is a regular file of one private tmpfs. The call makes the file in the root of that
//! tmpfs, then removes the name at once, as `shmem_file_setup` of Linux gives a file with no
//! link. The dentry keeps the name `memfd:NAME`, thus `/proc/PID/fd` shows that name. A file of
//! `MFD_HUGETLB` is a file of one private hugetlbfs in the same way.

use crate::cx::{Cx, SysResult};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::fcntl::F_SEAL_EXEC;
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

/// The bits of the size of a huge page, as `MFD_HUGE_SHIFT` and `MFD_HUGE_MASK`.
const MFD_HUGE_SHIFT: u32 = 26;
const MFD_HUGE_MASK: u32 = 0x3f;

/// The root of the private tmpfs, made at the first call.
static ROOT: SpinLock<Option<Location>> = SpinLock::new(None);

/// The root of the private hugetlbfs, for `MFD_HUGETLB`.
static HUGE_ROOT: SpinLock<Option<Location>> = SpinLock::new(None);

/// A counter that makes each name in the root unique.
static NEXT: AtomicU64 = AtomicU64::new(1);

fn root() -> Location {
    let mut root = ROOT.lock();
    root.get_or_insert_with(|| MountNamespace::new(rk_fs_tmpfs::new(0o1777)).root()).clone()
}

fn huge_root() -> Location {
    let mut root = HUGE_ROOT.lock();
    root.get_or_insert_with(|| MountNamespace::new(rk_fs_hugetlbfs::internal()).root()).clone()
}

pub(crate) fn memfd_create(cx: &Cx<'_>, name: u64, flags: u64) -> SysResult {
    let flags = u32::try_from(flags).map_err(|_| Errno::EINVAL)?;
    // A file of huge pages has the size of its pages in the high bits, as `memfd_create` of
    // Linux.
    let known = MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB | MFD_NOEXEC_SEAL | MFD_EXEC;
    let huge = flags & MFD_HUGETLB != 0;
    let known = if huge { known | MFD_HUGE_MASK << MFD_HUGE_SHIFT } else { known };
    if flags & !known != 0 || flags & (MFD_NOEXEC_SEAL | MFD_EXEC) == MFD_NOEXEC_SEAL | MFD_EXEC {
        return Err(Errno::EINVAL);
    }
    // The pool has only pages of 2 MiB. Another size gives `ENODEV`, as `hugetlb_file_setup`.
    if huge {
        crate::mm::hugetlb_size(flags >> MFD_HUGE_SHIFT).map_err(|_| Errno::ENODEV)?;
    }
    let name = match cx.vm()?.read_cstr(name as usize, NAME_MAX + 1) {
        Err(Errno::ENAMETOOLONG) => return Err(Errno::EINVAL),
        r => r?,
    };
    let root = if huge { huge_root() } else { root() };
    let mut temp = Vec::from(&b"memfd."[..]);
    temp.extend_from_slice(alloc::format!("{}", NEXT.fetch_add(1, Ordering::Relaxed)).as_bytes());
    // `MFD_NOEXEC_SEAL` gives a file without the execute bits and with `F_SEAL_EXEC`, and
    // `MFD_ALLOW_SEALING` removes `F_SEAL_SEAL`, as `memfd_alloc_file` of Linux.
    let noexec = flags & MFD_NOEXEC_SEAL != 0;
    let inode =
        root.inode().create(&temp, FileType::Regular, if noexec { 0o666 } else { 0o777 }, 0)?;
    if noexec {
        inode.set_seals(F_SEAL_EXEC as u32)?;
    } else if flags & MFD_ALLOW_SEALING != 0 {
        inode.set_seals(0)?;
    }
    let mut shown = Vec::from(&b"memfd:"[..]);
    shown.extend_from_slice(&name);
    let dentry = root.dentry.add_child(&shown, inode);
    root.dentry.forget_child(&shown);
    root.inode().unlink(&temp)?;
    let file = File::open_inode(Location { mount: root.mount, dentry }, O_RDWR | O_LARGEFILE);
    let fd = cx.files()?.lock().insert(file, flags & MFD_CLOEXEC != 0)?;
    Ok(fd as u64)
}

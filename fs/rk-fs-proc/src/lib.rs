//! procfs: the files of `/proc`, which give the state of the kernel and of each process.
//!
//! Each file makes its text at each read, from the state of that moment. The text has the format
//! of Linux, because programs and libraries parse it. The LTP library reads `/proc/meminfo`,
//! `/proc/PID/stat` and `/proc/sys`, and the C libraries read `/proc/self/maps` and
//! `/proc/self/fd`. Linux has the same files in fs/proc.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod kernel;
#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
mod node;
pub mod text;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub use kernel::{KernelInfo, set_kernel_info};

/// The magic number of procfs, `PROC_SUPER_MAGIC` of `<linux/magic.h>`.
pub const PROC_SUPER_MAGIC: u64 = 0x9fa0;

use rk_vfs::fstype::FsType;

/// The file system type of procfs, for `mount -t proc`.
pub const FS_TYPE: FsType = FsType { name: "proc", nodev: true, make: mount };

/// Makes the root of a mount of procfs. procfs takes no options yet, so `data` has no effect.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn mount(_data: &[u8]) -> rk_vfs::Result<rk_vfs::InodeRef> {
    Ok(kernel::root())
}

/// A host build has no processes, so it has no procfs.
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
fn mount(_data: &[u8]) -> rk_vfs::Result<rk_vfs::InodeRef> {
    Err(rk_abi::Errno::ENODEV)
}

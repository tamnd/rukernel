//! The root file system.
//!
//! In R1 the root is a tmpfs, and the kernel unpacks the initramfs into it, per
//! spec/22-milestones.md. Linux does the same in init/initramfs.c.

use rk_frame::boot::BootInfo;
use rk_frame::println;
use rk_frame::sync::Once;
use rk_vfs::{FsContext, MountNamespace};

static ROOT: Once<FsContext> = Once::new();

/// Makes the root tmpfs and unpacks the initramfs into it, if the boot loader gave one.
pub(crate) fn init(boot: &BootInfo) {
    let root = ROOT.call_once(|| FsContext::new(MountNamespace::new(rk_fs_tmpfs::new(0o755))));
    let Some(data) = boot.initrd_bytes() else {
        println!("initramfs: none, the root file system is empty");
        return;
    };
    match rk_vfs::cpio::unpack(root, data) {
        Ok(n) => println!("initramfs: {n} entries in {} KiB", data.len() >> 10),
        Err(e) => println!("initramfs: the archive is not correct, error {}", e.get()),
    }
}

/// The file system context of the first process.
pub(crate) fn context() -> Option<&'static FsContext> {
    ROOT.get()
}

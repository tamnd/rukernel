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
    rk_vfs::fstype::register(rk_fs_tmpfs::FS_TYPE);
    #[cfg(target_arch = "x86_64")]
    {
        rk_vfs::fstype::register(rk_fs_proc::FS_TYPE);
        rk_fs_proc::set_kernel_info(rk_fs_proc::KernelInfo {
            release: rk_syscall::UNAME_RELEASE,
            version: rk_syscall::UNAME_VERSION,
            cmdline: alloc::string::String::from(boot.cmdline()),
        });
    }
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

/// Makes `/dev` and the device files of the console, the memory devices and the disks, if the initramfs did
/// not make them. Linux has devtmpfs for this. rukernel gets devtmpfs in a later release.
#[cfg(target_arch = "x86_64")]
pub(crate) fn make_dev(fs: &FsContext) {
    use rk_vfs::inode::mode::{S_IFBLK, S_IFCHR};

    let root = fs.root().clone();
    let _ = fs.mkdir(&root, b"/dev", 0o755);
    let mut nodes = alloc::vec![
        (alloc::string::String::from("console"), 0o600, rk_drv_tty::CONSOLE_RDEV),
        (alloc::string::String::from("tty"), 0o666, rk_drv_tty::TTY_RDEV),
        (alloc::string::String::from("ttyS0"), 0o660, rk_drv_tty::TTYS0_RDEV),
    ];
    for dev in rk_drv_mem::MemDevice::ALL {
        nodes.push((alloc::string::String::from(dev.name()), 0o666, dev.rdev()));
    }
    let mut nodes: alloc::vec::Vec<_> =
        nodes.into_iter().map(|(name, perm, rdev)| (name, S_IFCHR | perm, rdev)).collect();
    for (name, rdev) in rk_vfs::blockdev::block_devices() {
        nodes.push((name, S_IFBLK | 0o660, rdev));
    }
    for (name, mode, rdev) in nodes {
        let path = alloc::format!("/dev/{name}");
        match fs.mknod(&root, path.as_bytes(), mode, rdev) {
            Ok(_) | Err(rk_abi::Errno::EEXIST) => {}
            Err(e) => println!("rootfs: cannot make {path}, error {}", e.get()),
        }
    }
}

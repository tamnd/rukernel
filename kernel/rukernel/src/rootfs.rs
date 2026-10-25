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
    rk_vfs::fstype::register(rk_fs_tmpfs::DEVTMPFS);
    rk_vfs::fstype::register(rk_fs_overlay::FS_TYPE);
    for t in rk_fs_ext4::FS_TYPES {
        rk_vfs::fstype::register(t);
    }
    #[cfg(target_arch = "x86_64")]
    {
        rk_vfs::fstype::register(rk_fs_proc::FS_TYPE);
        rk_vfs::fstype::register(rk_fs_sys::FS_TYPE);
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

/// Puts the character devices in the list of devices, and makes `/dev` and a device file for
/// each device in the list, if the initramfs did not make them. devtmpfs and sysfs show the same
/// list. Linux does not mount devtmpfs on an initramfs, so the kernel makes the files here.
#[cfg(target_arch = "x86_64")]
pub(crate) fn make_dev(fs: &FsContext) {
    use alloc::string::String;
    use rk_vfs::device::{DeviceInfo, add_device, devices};
    use rk_vfs::inode::mode::{S_IFBLK, S_IFCHR};

    let tty = [
        ("console", 0o600, rk_drv_tty::CONSOLE_RDEV),
        ("tty", 0o666, rk_drv_tty::TTY_RDEV),
        ("ttyS0", 0o660, rk_drv_tty::TTYS0_RDEV),
    ];
    for (name, perm, rdev) in tty {
        add_device(DeviceInfo { name: String::from(name), class: "tty", rdev, block: false, perm });
    }
    for dev in rk_drv_mem::MemDevice::ALL {
        let name = String::from(dev.name());
        add_device(DeviceInfo { name, class: "mem", rdev: dev.rdev(), block: false, perm: 0o666 });
    }
    let root = fs.root().clone();
    let _ = fs.mkdir(&root, b"/dev", 0o755);
    for d in devices() {
        let path = alloc::format!("/dev/{}", d.name);
        let mode = if d.block { S_IFBLK } else { S_IFCHR } | d.perm;
        match fs.mknod(&root, path.as_bytes(), mode, d.rdev) {
            Ok(_) | Err(rk_abi::Errno::EEXIST) => {}
            Err(e) => println!("rootfs: cannot make {path}, error {}", e.get()),
        }
    }
}

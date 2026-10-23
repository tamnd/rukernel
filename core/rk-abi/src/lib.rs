//! The Linux ABI as typed Rust.
//!
//! `rk-abigen` generates the system call tables, the structure layouts and the uAPI constants into
//! `src/generated/` from the Linux source tree, per spec/04-abi-surface.md. Nobody writes these
//! values by hand. Each architecture has a module, and `native` is the module of the target.

#![no_std]
#![forbid(unsafe_code)]

mod errno;
mod generated;

pub use generated::{aarch64, riscv64, x86_64};

/// The ABI of the target architecture.
#[cfg(target_arch = "aarch64")]
pub use generated::aarch64 as native;
/// The ABI of the target architecture.
#[cfg(target_arch = "riscv64")]
pub use generated::riscv64 as native;
/// The ABI of the target architecture.
#[cfg(target_arch = "x86_64")]
pub use generated::x86_64 as native;

pub use errno::Errno;

#[cfg(test)]
mod tests {
    use super::{aarch64, riscv64, x86_64};

    // The numbers that the Linux uAPI headers give, as a check of the generated tables.
    #[test]
    fn known_numbers() {
        assert_eq!(x86_64::syscalls::READ, 0);
        assert_eq!(x86_64::syscalls::EXIT_GROUP, 231);
        assert_eq!(aarch64::syscalls::OPENAT, 56);
        assert_eq!(riscv64::syscalls::RISCV_HWPROBE, 258);
    }

    #[test]
    fn known_constants() {
        use crate::Errno;
        assert_eq!(Errno::ENOSYS.get(), 38);
        assert_eq!(Errno::EWOULDBLOCK, Errno::EAGAIN);
        assert_eq!(x86_64::errno::EHWPOISON, 133);
        // O_DIRECT and O_DIRECTORY are not the same on x86-64 and arm64.
        assert_eq!(x86_64::open::O_DIRECTORY, 0o200000);
        assert_eq!(aarch64::open::O_DIRECTORY, 0o40000);
        assert_eq!(riscv64::open::O_DIRECTORY, 0o200000);
        assert_eq!(x86_64::at::AT_FDCWD, -100);
        assert_eq!(x86_64::mman::MAP_ANONYMOUS, 0x20);
        assert_eq!(x86_64::sched::CLONE_INTO_CGROUP, 1 << 33);
        assert_eq!(aarch64::signal::SIGSTKSZ, 16384);
        // Linux 7.3 also has FUTEX_ROBUST_UNLOCK and FUTEX_ROBUST_LIST32 in the mask.
        assert_eq!(x86_64::futex::FUTEX_CMD_MASK, !(128 | 256 | 512 | 1024));
        assert_eq!(x86_64::stat::S_IFDIR, 0o40000);
        assert_eq!(x86_64::ioctls::TCGETS, 0x5401);
        assert_eq!(x86_64::termbits::ICANON, 2);
        assert_eq!(x86_64::auxv::AT_RANDOM, 25);
        assert_eq!(x86_64::elf::PT_LOAD, 1);
        assert_eq!(x86_64::random::GRND_NONBLOCK, 1);
    }

    #[test]
    fn known_layouts() {
        assert_eq!(size_of::<x86_64::types::Stat>(), 144);
        assert_eq!(size_of::<aarch64::types::Stat>(), 128);
        assert_eq!(size_of::<riscv64::types::Stat>(), 128);
        // struct epoll_event is packed only on x86-64.
        assert_eq!(size_of::<x86_64::types::EpollEvent>(), 12);
        assert_eq!(size_of::<aarch64::types::EpollEvent>(), 16);
        assert_eq!(size_of::<x86_64::types::Statx>(), 256);
        assert_eq!(size_of::<x86_64::types::CloneArgs>(), 88);
        assert_eq!(size_of::<x86_64::types::NewUtsname>(), 390);
    }

    #[test]
    fn a_structure_is_read_from_bytes() {
        use zerocopy::FromBytes;
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&5i64.to_ne_bytes());
        bytes[8..].copy_from_slice(&7i64.to_ne_bytes());
        let ts = x86_64::types::KernelTimespec::read_from_bytes(&bytes);
        assert_eq!(ts.map(|t| (t.tv_sec, t.tv_nsec)), Ok((5, 7)));
    }

    #[test]
    fn the_name_table_matches_the_numbers() {
        assert_eq!(x86_64::syscalls::SYSCALLS[x86_64::syscalls::WRITE as usize], Some("write"));
        // uselib has a number on x86-64 but no entry point.
        assert_eq!(x86_64::syscalls::SYSCALLS[x86_64::syscalls::USELIB as usize], None);
        assert_eq!(aarch64::syscalls::SYSCALLS.len(), aarch64::syscalls::NR_SYSCALLS);
    }
}

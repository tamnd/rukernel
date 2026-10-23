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
    fn the_name_table_matches_the_numbers() {
        assert_eq!(x86_64::syscalls::SYSCALLS[x86_64::syscalls::WRITE as usize], Some("write"));
        // uselib has a number on x86-64 but no entry point.
        assert_eq!(x86_64::syscalls::SYSCALLS[x86_64::syscalls::USELIB as usize], None);
        assert_eq!(aarch64::syscalls::SYSCALLS.len(), aarch64::syscalls::NR_SYSCALLS);
    }
}

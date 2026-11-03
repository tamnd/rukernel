//! The eBPF objects of rukernel, kernel/bpf of Linux.
//!
//! This crate has the `bpf(2)` system call without the access to the memory and the files of the
//! process, which the caller gives through [`syscall::Env`]. The maps keep the Linux names, so a
//! reader can compare each function with Linux 7.3. See spec/11-bpf.md.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod attr;
pub mod file;
pub mod map;
pub mod syscall;
pub mod uapi;
pub mod value;

use core::sync::atomic::AtomicU32;

/// The sysctl `kernel.unprivileged_bpf_disabled`, `sysctl_unprivileged_bpf_disabled` of Linux.
/// With 0 a process without `CAP_BPF` can make maps. With 1 it cannot, and the value cannot
/// change. With 2 it cannot, and a process with `CAP_SYS_ADMIN` can change the value. rukernel
/// starts with 2, as `CONFIG_BPF_UNPRIV_DEFAULT_OFF` of Linux, per spec/11-bpf.md section 11.6.
pub static UNPRIVILEGED_BPF_DISABLED: AtomicU32 = AtomicU32::new(2);

/// Writes the sysctl `kernel.unprivileged_bpf_disabled`, as `bpf_unpriv_handler` in
/// kernel/bpf/syscall.c of Linux. `admin` tells if the writer has `CAP_SYS_ADMIN`.
pub fn bpf_unpriv_handler(value: i64, admin: bool) -> Result<(), rk_abi::Errno> {
    use core::sync::atomic::Ordering;
    use rk_abi::Errno;
    if !admin {
        return Err(Errno::EPERM);
    }
    if !(0..=2).contains(&value) {
        return Err(Errno::EINVAL);
    }
    let old = UNPRIVILEGED_BPF_DISABLED.load(Ordering::Relaxed);
    // A value of 1 is locked.
    if old == 1 && value != 1 {
        return Err(Errno::EPERM);
    }
    UNPRIVILEGED_BPF_DISABLED.store(value as u32, Ordering::Relaxed);
    Ok(())
}

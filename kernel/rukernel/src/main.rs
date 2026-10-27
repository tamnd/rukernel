//! The rukernel binary.
//!
//! This crate links the parts of the kernel and contains the main function. It has no unsafe
//! code: rk-frame calls `main` after it sets up the CPU, per spec/03-architecture.md section 3.1.
//!
//! The binary runs on bare metal targets only. On a host, `cargo run` gives a short message.
//! Use `cargo xtask qemu` to boot the kernel.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
#![forbid(unsafe_code)]

#[cfg(target_os = "none")]
extern crate alloc;

#[cfg(target_os = "none")]
mod kernel;
#[cfg(target_os = "none")]
mod rootfs;
#[cfg(target_os = "none")]
mod selftest;
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod syscall;

#[cfg(not(target_os = "none"))]
fn main() {
    eprintln!("rukernel runs on a bare metal target. Use `cargo xtask qemu` to boot it.");
    std::process::exit(2);
}

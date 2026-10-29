//! The trusted base of rukernel.
//!
//! This crate is the only crate in the kernel that can contain `unsafe` code, per
//! spec/03-architecture.md section 3.1. It gives safe interfaces to the hardware: frames, page
//! tables, traps, interrupts, locks, RCU, user memory access and DMA. All other crates use these
//! interfaces and forbid `unsafe` code. Thus the soundness of the kernel depends on this crate,
//! the compiler and the hardware only.
//!
//! The budget for this crate is 25,000 lines, per spec/02-the-goal.md section 2.4. Each `unsafe`
//! block has a `// SAFETY:` comment. Clippy rejects a block without one.

#![no_std]

#[cfg(target_os = "none")]
extern crate alloc;

pub mod addr;
pub mod arch;
pub mod boot;
pub mod console;
pub mod cpu;
pub mod date;
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(crate) mod fdt;
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub mod iomem;
#[cfg(target_os = "none")]
pub mod irq;
pub mod mm;
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub mod pci;
#[cfg(any(test, all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub(crate) mod pci_window;
pub mod sync;
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub mod task;
#[cfg(target_os = "none")]
pub mod time;
#[cfg(target_os = "none")]
pub mod trap;
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub mod user;
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub mod vdso;
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub mod vm;

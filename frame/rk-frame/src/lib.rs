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

pub mod addr;
pub mod arch;

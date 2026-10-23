//! The Linux ABI as typed Rust.
//!
//! In milestone R0, `rk-abigen` generates the system call tables, the structure layouts and the
//! uAPI constants into this crate from the Linux source tree, per spec/04-abi-surface.md. Nobody
//! writes these values by hand. Before then, the crate contains the error numbers only.

#![no_std]
#![forbid(unsafe_code)]

mod errno;

pub use errno::Errno;

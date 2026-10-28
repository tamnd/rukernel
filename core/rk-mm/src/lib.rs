//! The memory manager of rukernel.
//!
//! It keeps the virtual memory areas of each process, gives a frame to a page at the first
//! access, and copies a private page at the first write after `fork`. It gives `mmap`, `munmap`,
//! `mprotect` and `brk`, per spec/07-memory.md. R1 has anonymous memory and the mappings of files
//! that rk-vfs gives through the `MmFile` trait.
//!
//! The areas are a pure type, so the tests on the host examine them. The address space uses the
//! page table of rk-frame and runs in the kernel only.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod ksm;
pub mod tunables;
pub mod vma;

#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod space;

#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub use space::{
    Access, AddressSpace, FileRef, MMAP_MIN_ADDR, MMAP_TOP, MmFile, MmapRequest, Remap, STACK_SIZE,
    STACK_TOP,
};
pub use vma::{Backing, HugeAdvice, PAGE_SIZE, Prot, Vma, VmaKind, VmaSet};

/// The free frames that a page of a process cannot take. The kernel keeps them for its heap and
/// for its own work when the memory is short, so that the OOM killer can run. A fault that finds
/// fewer free frames gives `ENOMEM`, as the min watermark of Linux.
pub const USER_RESERVE: usize = 256;

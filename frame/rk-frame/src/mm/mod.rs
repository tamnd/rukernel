//! Physical memory and the kernel address space.
//!
//! The safe kernel crates get memory through owned values. A `Frame` owns one physical page and
//! gives it back when it is dropped. A `Mapping` owns a frame and a kernel virtual address for it,
//! and removes the mapping when it is dropped. No safe function gives a raw address that the
//! caller can write through.

// riscv64 has no boot path yet, so the boot code that fills the allocator is not there.
#[cfg(any(test, target_os = "none"))]
#[cfg_attr(target_arch = "riscv64", allow(dead_code))]
pub(crate) mod bitmap;

#[cfg(target_os = "none")]
#[cfg_attr(target_arch = "riscv64", allow(dead_code))]
pub(crate) mod frame;
#[cfg(target_os = "none")]
mod heap;
#[cfg(target_os = "none")]
pub use frame::{
    Frame, FrameStats, Mapping, PageInfo, alloc_frame, alloc_zeroed_frame, frame_stats, query,
    translate, vmap,
};
#[cfg(target_os = "none")]
pub use heap::{HeapStats, heap_stats};

//! The vDSO of arm64. It does not exist yet, so a new program gets no `AT_SYSINFO_EHDR` and the C
//! library makes the time system calls.
//!
//! TODO(#329): build a vDSO for arm64 from the generic counter, as `vdso/x86_64.rs` does from the
//! time stamp counter.

use crate::mm::Frame;
use alloc::sync::Arc;

/// The vDSO, a shared object. It is empty on arm64.
pub static IMAGE: &[u8] = &[];

/// The data page of the vDSO. There is none on arm64.
pub fn data_page() -> Option<Arc<Frame>> {
    None
}

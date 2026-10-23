//! Operations that each architecture does in a different way.
//!
//! The entry code, the context switch and the page table formats come here in milestone R0, per
//! spec/22-milestones.md.

/// The name of the architecture, as `uname -m` gives it on Linux.
#[cfg(target_arch = "x86_64")]
pub const UNAME_MACHINE: &str = "x86_64";
/// The name of the architecture, as `uname -m` gives it on Linux.
#[cfg(target_arch = "aarch64")]
pub const UNAME_MACHINE: &str = "aarch64";
/// The name of the architecture, as `uname -m` gives it on Linux.
#[cfg(target_arch = "riscv64")]
pub const UNAME_MACHINE: &str = "riscv64";

/// Tells the processor that this CPU waits in a spin loop.
#[inline]
pub fn cpu_relax() {
    core::hint::spin_loop();
}

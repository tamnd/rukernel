//! Operations that each architecture does in a different way.
//!
//! The code for the hardware is in one module for each architecture. Only x86-64 boots in milestone
//! R0. The arm64 and riscv64 modules park the CPU until their milestones, per spec/22-milestones.md.

/// The name of the architecture, as `uname -m` gives it on Linux.
#[cfg(target_arch = "x86_64")]
pub const UNAME_MACHINE: &str = "x86_64";
/// The name of the architecture, as `uname -m` gives it on Linux.
#[cfg(target_arch = "aarch64")]
pub const UNAME_MACHINE: &str = "aarch64";
/// The name of the architecture, as `uname -m` gives it on Linux.
#[cfg(target_arch = "riscv64")]
pub const UNAME_MACHINE: &str = "riscv64";

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) mod x86_64;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub use x86_64::{halt_forever, qemu_exit};

#[cfg(all(target_os = "none", not(target_arch = "x86_64")))]
mod stub;
#[cfg(all(target_os = "none", not(target_arch = "x86_64")))]
pub use stub::{halt_forever, qemu_exit};

/// Tells the processor that this CPU waits in a spin loop.
#[inline]
pub fn cpu_relax() {
    core::hint::spin_loop();
}

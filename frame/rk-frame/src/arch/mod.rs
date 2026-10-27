//! Operations that each architecture does in a different way.
//!
//! The code for the hardware is in one module for each architecture. x86-64 boots since milestone
//! R0. arm64 boots to the console and the timer tick on QEMU virt from milestone R4. The riscv64
//! module parks the CPU until its milestone, per spec/22-milestones.md.

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
pub(crate) use x86_64 as imp;

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub(crate) mod aarch64;
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub(crate) use aarch64 as imp;

#[cfg(all(target_os = "none", target_arch = "riscv64"))]
pub(crate) mod stub;
#[cfg(all(target_os = "none", target_arch = "riscv64"))]
pub(crate) use stub as imp;

#[cfg(target_os = "none")]
pub use imp::{halt_forever, qemu_exit, random_seed};

/// Gives 64 bits for a random seed. A host build is for the unit tests only, so the value is a
/// constant.
#[cfg(not(target_os = "none"))]
pub fn random_seed() -> u64 {
    0x9e37_79b9_7f4a_7c15
}

/// Tells the processor that this CPU waits in a spin loop.
#[inline]
pub fn cpu_relax() {
    core::hint::spin_loop();
}

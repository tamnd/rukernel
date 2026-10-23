//! The entry point for the architectures that do not boot yet.
//!
//! arm64 boots in milestone R4 and riscv64 in milestone R8, per spec/22-milestones.md. Until then,
//! the kernel links for these targets and the entry point stops the CPU. Thus the build checks the
//! architecture independent code on all three targets.

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".section .text._start, \"ax\"",
    ".global _start",
    "_start:",
    "1: wfi",
    "b 1b",
);

#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".section .text._start, \"ax\"",
    ".global _start",
    "_start:",
    "1: wfi",
    "j 1b",
);

/// Stops this CPU. The CPU does not continue.
pub fn halt_forever() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Stops the virtual machine with an exit code. These architectures have no exit device yet, so
/// the CPU stops.
pub fn qemu_exit(_code: u32) -> ! {
    halt_forever()
}

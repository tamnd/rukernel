//! The CPUs of the machine.
//!
//! The boot CPU has the number 0, and the other CPUs have the numbers after it, in the order in
//! which they start. Only x86-64 starts the other CPUs. The other architectures and the host
//! build of the unit tests run on one CPU.

/// The largest number of CPUs. A CPU mask of the scheduler has one bit for each CPU in a `u64`.
pub const MAX_CPUS: usize = 64;

/// The number of CPUs that run.
pub fn count() -> usize {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    return crate::arch::imp::cpu::count();
    #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
    1
}

/// The number of the CPU that runs this code.
pub fn id() -> usize {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    return crate::arch::imp::cpu::id();
    #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
    0
}

/// Starts the other CPUs, and gives the number of CPUs that run. The kernel calls this one time,
/// after it gives the scheduler.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub fn start_all() -> usize {
    crate::arch::imp::smp::start_cpus()
}

/// Makes each CPU do a full memory barrier, and returns when each CPU did it, for
/// `membarrier(2)`. The other CPUs get an interrupt.
pub fn barrier_all() {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    crate::arch::imp::smp::shootdown(0, crate::arch::imp::smp::BARRIER);
}

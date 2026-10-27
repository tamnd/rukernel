//! The data of each CPU.
//!
//! TPIDR_EL1 of a CPU holds the address of its `Local` value, as Linux keeps the per CPU offset
//! there. User code cannot read TPIDR_EL1. The entry to user mode and the return from it read and
//! write the first fields from assembly. Rust code finds the number of the CPU in `Local`, and the
//! other values of the CPU by that number.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// The most CPUs that the kernel uses. A mask of the CPUs fits in a `u64`.
pub(crate) const MAX_CPUS: usize = 64;

/// The offsets of the fields of `Local`, for the assembly.
pub(crate) const KERNEL_SP: usize = 0;
pub(crate) const USER_REGS: usize = 8;

/// The values of one CPU that the entry code uses.
#[repr(C)]
pub(crate) struct Local {
    /// The kernel stack pointer of `user::enter`, after it saves the registers that it must keep.
    pub(crate) kernel_sp: AtomicU64,
    /// The address of the `UserRegs` value of the user code that runs on the CPU.
    pub(crate) user_regs: AtomicU64,
    /// The address of the `FpuState` value of the user code that runs on the CPU.
    pub(crate) user_fpu: AtomicU64,
    /// The number of the CPU.
    id: AtomicU64,
    /// The ESR and the FAR of the last exception in user mode.
    pub(crate) exception: [AtomicU64; 2],
}

static LOCALS: [Local; MAX_CPUS] = [const {
    Local {
        kernel_sp: AtomicU64::new(0),
        user_regs: AtomicU64::new(0),
        user_fpu: AtomicU64::new(0),
        id: AtomicU64::new(0),
        exception: [const { AtomicU64::new(0) }; 2],
    }
}; MAX_CPUS];

/// The number of CPUs that run.
static COUNT: AtomicUsize = AtomicUsize::new(1);

/// The affinity fields of MPIDR_EL1: Aff0 to Aff2 and Aff3.
const MPIDR_AFFINITY: u64 = 0xff_00ff_ffff;

/// The affinity of this CPU, from MPIDR_EL1.
pub(crate) fn read_mpidr() -> u64 {
    let value: u64;
    // SAFETY: reading MPIDR_EL1 has no side effect.
    unsafe { core::arch::asm!("mrs {}, mpidr_el1", out(reg) value, options(nomem, nostack)) };
    value & MPIDR_AFFINITY
}

/// Makes the CPU with the number `id` use its `Local` value.
pub(crate) fn init(id: usize) {
    let local = &LOCALS[id];
    local.id.store(id as u64, Ordering::Relaxed);
    // SAFETY: TPIDR_EL1 is for the kernel only. `id` and the entry code read it, and only this
    // function writes it.
    unsafe {
        core::arch::asm!("msr tpidr_el1, {}", in(reg) local as *const Local as u64, options(nomem, nostack))
    };
}

/// The number of this CPU. The boot CPU has the number 0.
pub(crate) fn id() -> usize {
    local().id.load(Ordering::Relaxed) as usize
}

/// The values of this CPU.
pub(crate) fn local() -> &'static Local {
    let addr: u64;
    // SAFETY: reading TPIDR_EL1 has no side effect.
    unsafe { core::arch::asm!("mrs {}, tpidr_el1", out(reg) addr, options(nomem, nostack)) };
    // SAFETY: `init` set TPIDR_EL1 to the address of an element of `LOCALS`, which lives as long
    // as the kernel.
    unsafe { &*(addr as *const Local) }
}

/// The number of CPUs that run.
pub(crate) fn count() -> usize {
    COUNT.load(Ordering::Acquire)
}

/// Counts one more CPU that runs.
pub(crate) fn add_online() {
    COUNT.fetch_add(1, Ordering::AcqRel);
}

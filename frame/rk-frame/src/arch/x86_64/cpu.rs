//! The data of each CPU.
//!
//! The GS base of a CPU in kernel mode is the address of its `Local` value. The entry code reads
//! and writes the first fields with `%gs:` addresses, because it runs before it has a stack. In
//! user mode the GS base is 0, and the entry code changes it with `swapgs`. Rust code finds the
//! number of the CPU at `%gs:24`, and the other values of the CPU by that number.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// The most CPUs that the kernel uses. A mask of the CPUs fits in a `u64`.
pub(crate) const MAX_CPUS: usize = 64;

/// The offsets of the fields of `Local`, for the entry code.
pub(crate) const KERNEL_RSP: usize = 0;
pub(crate) const USER_REGS: usize = 8;
pub(crate) const USER_RSP: usize = 16;
const ID: usize = 24;

/// The values of one CPU that the entry code uses.
#[repr(C)]
pub(crate) struct Local {
    /// The kernel stack pointer of `user::enter`, after it pushes the registers that it must keep.
    pub(crate) kernel_rsp: AtomicU64,
    /// The address of the `UserRegs` value of the user code that runs on the CPU.
    pub(crate) user_regs: AtomicU64,
    /// The user stack pointer at a `syscall` instruction, until the entry code saves it.
    pub(crate) user_rsp: AtomicU64,
    /// The number of the CPU.
    id: AtomicU64,
    /// The vector, the error code and CR2 of the last exception in user mode.
    pub(crate) exception: [AtomicU64; 3],
}

static LOCALS: [Local; MAX_CPUS] = [const {
    Local {
        kernel_rsp: AtomicU64::new(0),
        user_regs: AtomicU64::new(0),
        user_rsp: AtomicU64::new(0),
        id: AtomicU64::new(0),
        exception: [const { AtomicU64::new(0) }; 3],
    }
}; MAX_CPUS];

/// The local APIC ID of each CPU.
static APIC_IDS: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
/// The number of CPUs that run.
static COUNT: AtomicUsize = AtomicUsize::new(1);

const IA32_GS_BASE: u32 = 0xc000_0101;
const IA32_KERNEL_GS_BASE: u32 = 0xc000_0102;

fn wrmsr(msr: u32, value: u64) {
    // SAFETY: the callers write the GS base MSRs, which change only the base of GS. The kernel
    // reads GS only through `id` and the entry code.
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") msr, in("eax") value as u32, in("edx") (value >> 32) as u32, options(nomem, nostack, preserves_flags))
    };
}

/// Makes the CPU with the number `id` use its `Local` value. The GS base of user mode is 0.
pub(crate) fn init(id: usize, apic_id: u32) {
    let local = &LOCALS[id];
    local.id.store(id as u64, Ordering::Relaxed);
    APIC_IDS[id].store(apic_id, Ordering::Relaxed);
    wrmsr(IA32_GS_BASE, local as *const Local as u64);
    wrmsr(IA32_KERNEL_GS_BASE, 0);
}

/// The number of this CPU. The boot CPU has the number 0.
pub(crate) fn id() -> usize {
    let id: u64;
    // SAFETY: `init` set the GS base to the `Local` value of this CPU before any code calls this
    // function, and the kernel GS base is in use in kernel mode. The field is a `u64` that only
    // `init` writes.
    unsafe {
        core::arch::asm!("mov {}, gs:[{id}]", out(reg) id, id = const ID, options(nostack, readonly, preserves_flags))
    };
    id as usize
}

/// The values of this CPU.
pub(crate) fn local() -> &'static Local {
    &LOCALS[id()]
}

/// The number of CPUs that run.
pub(crate) fn count() -> usize {
    COUNT.load(Ordering::Acquire)
}

/// Counts one more CPU that runs.
pub(crate) fn add_online() {
    COUNT.fetch_add(1, Ordering::AcqRel);
}

/// The local APIC ID of the CPU `id`.
pub(crate) fn apic_id(id: usize) -> u32 {
    APIC_IDS[id].load(Ordering::Relaxed)
}

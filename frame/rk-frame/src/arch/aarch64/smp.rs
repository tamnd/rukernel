//! The other CPUs: their start, and the interrupts between CPUs.
//!
//! The device tree gives the MPIDR affinity of each CPU. The boot CPU starts the other CPUs one at
//! a time with the PSCI call `CPU_ON`, as Linux does in `psci_boot_secondary`. A CPU starts with
//! the MMU off at `rk_aarch64_secondary` in boot.rs, which turns the MMU on with the boot page
//! tables, takes its stack from `rk_ap_stacks` and calls `secondary_entry`.
//!
//! A CPU sends the SGI `SGI_CALL` to tell other CPUs to stop the use of an address space, and
//! `SGI_RESCHEDULE` to wake a CPU that waits for an interrupt. The TLB invalidations of arm64 go
//! to each CPU of the inner shareable domain, so a change of a page table needs no interrupt.

use super::{cpu, gic, paging};
use crate::sync::SpinLock;
use alloc::alloc::{Layout, alloc};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The SGI that tells a CPU to do the request of `shootdown`.
pub(crate) const SGI_CALL: u32 = 1;
/// The SGI that wakes a CPU.
pub(crate) const SGI_RESCHEDULE: u32 = 2;

/// The address in `FLUSH_ADDR` that tells each CPU to stop the use of the address space.
pub(crate) const LEAVE: u64 = u64::MAX;
/// The address in `FLUSH_ADDR` that tells each CPU to do nothing. The interrupt is a full
/// memory barrier, which `membarrier(2)` needs.
pub(crate) const BARRIER: u64 = u64::MAX - 1;

/// One request at a time goes to the other CPUs.
static FLUSH: SpinLock<()> = SpinLock::new(());
/// The address space of the request, or 0 for each CPU.
static FLUSH_ROOT: AtomicU64 = AtomicU64::new(0);
/// The request: `LEAVE` or `BARRIER`.
static FLUSH_ADDR: AtomicU64 = AtomicU64::new(0);
/// The CPUs that did not do the request yet.
static PENDING: AtomicU64 = AtomicU64::new(0);

/// Tells each other CPU that uses the address space `root` to do the request `addr`: `LEAVE`
/// loads no user table, and `BARRIER` is a memory barrier. A `root` of 0 is for each CPU. The
/// function returns when each of these CPUs did it.
pub(crate) fn shootdown(root: u64, addr: u64) {
    let me = cpu::id();
    // The change of the page table comes before the read of the address space of each CPU, and
    // `paging::activate` changes the address space before it loads the table. Thus a CPU that is
    // not in the mask loads the table after the change, and has no old TLB entry.
    core::sync::atomic::fence(Ordering::SeqCst);
    let mask = (0..cpu::count())
        .filter(|&c| c != me && (root == 0 || paging::active_on(c) == root))
        .fold(0u64, |m, c| m | 1 << c);
    if mask == 0 {
        return;
    }
    let _guard = loop {
        if let Some(guard) = FLUSH.try_lock() {
            break guard;
        }
        poll();
        core::hint::spin_loop();
    };
    FLUSH_ROOT.store(root, Ordering::Relaxed);
    FLUSH_ADDR.store(addr, Ordering::Relaxed);
    PENDING.store(mask, Ordering::Release);
    for c in (0..cpu::count()).filter(|c| mask & 1 << c != 0) {
        gic::send_sgi(c, SGI_CALL);
    }
    while PENDING.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
    }
}

/// Does the request of `shootdown` if this CPU has one. The interrupt handler calls it, and so
/// does each loop that waits with interrupts off for another CPU.
pub(crate) fn poll() {
    let bit = 1u64 << cpu::id();
    if PENDING.load(Ordering::Acquire) & bit == 0 {
        return;
    }
    let root = FLUSH_ROOT.load(Ordering::Relaxed);
    if FLUSH_ADDR.load(Ordering::Relaxed) == LEAVE {
        paging::leave(root);
    } else {
        core::sync::atomic::fence(Ordering::SeqCst);
    }
    PENDING.fetch_and(!bit, Ordering::Release);
}

/// Wakes the CPU `id` if it waits for an interrupt.
pub(crate) fn reschedule(id: usize) {
    gic::send_sgi(id, SGI_RESCHEDULE);
}

/// The PSCI function that starts a CPU, in the SMC64 range.
const PSCI_CPU_ON: u64 = 0xc400_0003;

/// The MPIDR affinity of each CPU of the device tree, and their number.
static CPUS: SpinLock<([u64; cpu::MAX_CPUS], usize)> = SpinLock::new(([0; cpu::MAX_CPUS], 0));

/// Keeps the CPUs of the device tree for `start_cpus`.
pub(crate) fn set_cpus(cpus: &[u64]) {
    let mut list = CPUS.lock();
    let n = cpus.len().min(cpu::MAX_CPUS);
    list.0[..n].copy_from_slice(&cpus[..n]);
    list.1 = n;
}

/// The top of the stack of each CPU that starts. `rk_aarch64_secondary` reads it after it turns
/// the MMU on.
#[unsafe(export_name = "rk_ap_stacks")]
static AP_STACKS: [AtomicU64; cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; cpu::MAX_CPUS];

/// The CPU that starts sets this when it runs.
static STARTED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    fn rk_aarch64_secondary();
}

/// Makes a PSCI call with three arguments and gives the result.
fn psci(function: u64, a: u64, b: u64, c: u64) -> i64 {
    let result: u64;
    if super::PSCI_SMC.load(Ordering::Relaxed) {
        // SAFETY: the PSCI firmware changes only x0 to x3 of this CPU. `CPU_ON` starts another CPU
        // at the entry code of the kernel.
        unsafe {
            core::arch::asm!("smc #0", inout("x0") function => result, inout("x1") a => _,
                inout("x2") b => _, inout("x3") c => _, options(nostack))
        };
    } else {
        // SAFETY: as above.
        unsafe {
            core::arch::asm!("hvc #0", inout("x0") function => result, inout("x1") a => _,
                inout("x2") b => _, inout("x3") c => _, options(nostack))
        };
    }
    result as i64
}

/// Starts the CPU with the affinity `mpidr` as the CPU `id`. Gives `true` if it runs.
fn start_cpu(id: usize, mpidr: u64) -> bool {
    let size = crate::task::KERNEL_STACK_SIZE;
    let Ok(layout) = Layout::from_size_align(size, 16) else { return false };
    // SAFETY: the layout has a size that is not 0.
    let stack = unsafe { alloc(layout) };
    if stack.is_null() {
        return false;
    }
    // The stack is new and stays for all of the run time, because the CPU runs on it until it
    // stops.
    AP_STACKS[id].store(stack as u64 + size as u64, Ordering::Release);
    STARTED.store(false, Ordering::Release);
    // The CPU reads the stack with its MMU on, through its caches, which are coherent with the
    // caches of this CPU. The DSB makes the store complete before the call.
    // SAFETY: the barrier changes no memory.
    unsafe { core::arch::asm!("dsb ish", options(nostack, preserves_flags)) };
    let entry = paging::kernel_virt_to_phys(rk_aarch64_secondary as *const () as usize);
    let result = psci(PSCI_CPU_ON, mpidr, entry, id as u64);
    if result != 0 {
        crate::console::_print_panic(format_args!(
            "rk-frame: PSCI CPU_ON of CPU {mpidr:#x} gives {result}\n"
        ));
        return false;
    }
    let end = super::timer::nanos() + 1_000_000_000;
    while super::timer::nanos() < end {
        if STARTED.load(Ordering::Acquire) {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// The first Rust code of a CPU that is not the boot CPU. `rk_aarch64_secondary` calls it on the
/// stack of the CPU, with the MMU on.
#[unsafe(no_mangle)]
extern "C" fn rk_frame_aarch64_secondary_entry(id: u64) -> ! {
    let id = id as usize;
    cpu::init(id);
    paging::init_cpu();
    gic::init_cpu();
    super::timer::init_cpu();
    super::user::init_cpu();
    cpu::add_online();
    STARTED.store(true, Ordering::Release);
    crate::task::run_secondary()
}

/// Starts each CPU that the device tree gives, up to `cpu::MAX_CPUS`. Gives the number of CPUs
/// that run.
pub(crate) fn start_cpus() -> usize {
    let me = cpu::read_mpidr();
    let (list, n) = *CPUS.lock();
    for &mpidr in list[..n].iter().filter(|&&m| m != me) {
        let id = cpu::count();
        if id >= cpu::MAX_CPUS || id >= gic::max_cpus() {
            break;
        }
        if !start_cpu(id, mpidr) {
            crate::console::_print_panic(format_args!(
                "rk-frame: CPU with MPIDR {mpidr:#x} does not start\n"
            ));
        }
    }
    cpu::count()
}

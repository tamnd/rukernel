//! The arm64 code of the frame.
//!
//! The kernel boots from a Linux arm64 `Image` on the QEMU `virt` machine. It runs at EL1 with the
//! MMU on. The console is the PL011 UART, the interrupt controller is a GICv2, and the tick comes
//! from the virtual timer of the generic timer. The device tree gives the addresses, and the
//! addresses of QEMU `virt` are the fallback. TODO(#329): support GICv3.

pub(crate) mod boot;
pub(crate) mod cpu;
pub(crate) mod gic;
pub(crate) mod paging;
pub(crate) mod pl011;
pub(crate) mod smp;
pub(crate) mod task;
pub(crate) mod timer;
pub(crate) mod trap;
pub(crate) mod user;

use core::sync::atomic::{AtomicBool, Ordering};

/// Handles an interrupt from the GIC. The trap handler calls this with interrupts off.
fn interrupt() {
    let iar = gic::ack();
    let id = iar & 0x3ff;
    if id == timer::intid() {
        timer::tick();
        gic::eoi(iar);
    } else if id == smp::SGI_CALL {
        smp::poll();
        gic::eoi(iar);
    } else if id == smp::SGI_RESCHEDULE {
        gic::eoi(iar);
    } else if id >= gic::SPURIOUS {
        // A spurious interrupt has no end of interrupt.
    } else {
        crate::console::_print_panic(format_args!("rk-frame: unexpected interrupt {id}\n"));
        gic::eoi(iar);
    }
}

/// Tells if PSCI calls use `smc`. Else they use `hvc`, as on QEMU `virt` without EL3.
pub(crate) static PSCI_SMC: AtomicBool = AtomicBool::new(false);

/// Sets the PSCI call method, from the `/psci` node of the device tree.
fn set_psci_smc(smc: bool) {
    PSCI_SMC.store(smc, Ordering::Relaxed);
}

/// The PSCI function that turns the machine off.
const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;

/// The early console that the architecture independent code writes to: the PL011 UART.
pub(crate) mod console {
    pub(crate) use super::pl011::{try_read, write_bytes, write_raw};
}

/// Stops this CPU with interrupts off. The CPU does not continue.
pub fn halt_forever() -> ! {
    loop {
        // SAFETY: masking the exceptions and `wfi` change no memory. With the exceptions masked,
        // the CPU stays here.
        unsafe { core::arch::asm!("msr daifset, #0xf", "wfi", options(nomem, nostack)) };
    }
}

/// Stops the virtual machine through PSCI `SYSTEM_OFF`. QEMU then exits with the status 0, so the
/// code does not get to the host. The boot test reads the result from the console. If the call
/// returns, the CPU stops.
pub fn qemu_exit(_code: u32) -> ! {
    // The PSCI call turns the machine off. If the firmware has no PSCI, the call returns an error
    // in x0, and the code stops the CPU.
    if PSCI_SMC.load(Ordering::Relaxed) {
        // SAFETY: as above. The call changes only x0.
        unsafe {
            core::arch::asm!("smc #0", inout("x0") PSCI_SYSTEM_OFF => _, options(nomem, nostack));
        }
    } else {
        // SAFETY: as above.
        unsafe {
            core::arch::asm!("hvc #0", inout("x0") PSCI_SYSTEM_OFF => _, options(nomem, nostack));
        }
    }
    halt_forever()
}

/// Gives 64 bits for a random seed, from the `RNDR` register if the CPU has `FEAT_RNG`, else from
/// the counter of the generic timer.
pub fn random_seed() -> u64 {
    let isar0: u64;
    // SAFETY: reading ID_AA64ISAR0_EL1 has no side effect.
    unsafe {
        core::arch::asm!("mrs {}, id_aa64isar0_el1", out(reg) isar0, options(nomem, nostack))
    };
    if isar0 >> 60 != 0 {
        for _ in 0..10 {
            let value: u64;
            let ok: u64;
            // SAFETY: the CPU has FEAT_RNG, so RNDR exists. A read sets NZCV, and `cset` reads it.
            unsafe {
                core::arch::asm!(
                    "mrs {v}, s3_3_c2_c4_0",
                    "cset {ok}, ne",
                    v = out(reg) value,
                    ok = out(reg) ok,
                    options(nomem, nostack),
                );
            }
            if ok != 0 {
                return value;
            }
        }
    }
    let count: u64;
    // SAFETY: reading CNTVCT_EL0 has no side effect.
    unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) count, options(nomem, nostack)) };
    count.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

/// Copies of memory that user code can write at the same time. These copy one byte at a time,
/// with volatile accesses. TODO(#329): use a faster copy when arm64 has user mode.
pub(crate) mod mem {
    /// Copies `len` bytes from `src` to `dst`.
    ///
    /// # Safety
    ///
    /// The two ranges must be valid kernel memory, and they must not overlap.
    pub(crate) unsafe fn copy(dst: *mut u8, src: *const u8, len: usize) {
        for i in 0..len {
            // SAFETY: the caller gives a valid range of `len` bytes at `src`.
            let byte = unsafe { src.wrapping_add(i).read_volatile() };
            // SAFETY: the caller gives a valid range of `len` bytes at `dst`.
            unsafe { dst.wrapping_add(i).write_volatile(byte) };
        }
    }

    /// Writes `len` zero bytes at `dst`.
    ///
    /// # Safety
    ///
    /// The range must be valid kernel memory.
    pub(crate) unsafe fn zero(dst: *mut u8, len: usize) {
        for i in 0..len {
            // SAFETY: the caller gives a valid range of `len` bytes.
            unsafe { dst.wrapping_add(i).write_volatile(0) };
        }
    }
}

/// Interrupt control on this CPU. The handlers use only atomic values and the GIC, so an
/// interrupt cannot stop on a lock that the interrupted code holds.
pub(crate) mod irq {
    /// Lets this CPU take interrupts.
    pub(crate) fn enable() {
        // SAFETY: the vector table is set, and the handlers take no locks.
        unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack)) };
    }

    /// Stops this CPU from taking interrupts.
    pub(crate) fn disable() {
        // SAFETY: this changes only the IRQ mask.
        unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack)) };
    }

    /// Tells if this CPU takes interrupts.
    pub(crate) fn enabled() -> bool {
        let daif: u64;
        // SAFETY: reading DAIF has no side effect.
        unsafe { core::arch::asm!("mrs {}, daif", out(reg) daif, options(nomem, nostack)) };
        daif & (1 << 7) == 0
    }

    /// Waits for the next interrupt, then lets this CPU take it. A pending interrupt wakes `wfi`
    /// also when it is masked, so no interrupt is lost between the check and the wait.
    pub(crate) fn wait() {
        // SAFETY: as for `enable`. `wfi` changes no memory.
        unsafe { core::arch::asm!("wfi", "msr daifclr, #2", options(nomem, nostack)) };
    }
}

/// The real time clock: a PL031, at the address that the device tree gives, else at the address
/// of QEMU `virt`.
pub(crate) mod rtc {
    use super::paging::MMIO_BASE;
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// The virtual address of the data register, which counts the seconds since the epoch.
    static RTCDR: AtomicUsize = AtomicUsize::new(MMIO_BASE + 0x0901_0000);

    /// Uses the PL031 at the virtual address `base`, from the device tree.
    pub(crate) fn set_base(base: usize) {
        RTCDR.store(base, Ordering::Relaxed);
    }

    /// Gives the seconds since the epoch.
    pub(crate) fn read() -> Option<u64> {
        let addr = RTCDR.load(Ordering::Relaxed);
        // SAFETY: the page tables map the PL031 registers as device memory at this address: the
        // boot window of `MMIO_BASE` or a mapping of `paging::map_device`. The read has no side
        // effect.
        let secs = unsafe { (addr as *const u32).read_volatile() };
        (secs != 0).then_some(u64::from(secs))
    }
}

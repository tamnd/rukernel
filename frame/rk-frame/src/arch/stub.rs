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

/// Gives 64 bits for a random seed. These architectures have no source yet, so the value is a
/// constant.
pub fn random_seed() -> u64 {
    0x9e37_79b9_7f4a_7c15
}

/// The trap counters and functions. These architectures have no trap handler yet.
pub(crate) mod trap {
    use core::sync::atomic::AtomicU64;

    pub(crate) static BREAKPOINTS: AtomicU64 = AtomicU64::new(0);
    pub(crate) static PAGE_FAULTS: AtomicU64 = AtomicU64::new(0);
    pub(crate) static FIXUPS: AtomicU64 = AtomicU64::new(0);

    pub(crate) fn breakpoint() {}

    pub(crate) fn probe_read_u64(_addr: usize) -> Option<u64> {
        None
    }

    pub(crate) fn probe_writable(_addr: usize) -> bool {
        false
    }

    pub(crate) fn kernel_image() -> (usize, usize) {
        (0, 0)
    }
}

/// Copies of memory that user code can write at the same time. These architectures copy one byte
/// at a time, with volatile accesses.
pub(crate) mod mem {
    /// Copies `len` bytes from `src` to `dst`.
    ///
    /// # Safety
    ///
    /// The two ranges must be valid kernel memory, and they must not overlap.
    pub(crate) unsafe fn copy(dst: *mut u8, src: *const u8, len: usize) {
        for i in 0..len {
            // SAFETY: the caller gives two valid ranges of `len` bytes.
            unsafe { dst.add(i).write_volatile(src.add(i).read_volatile()) };
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
            unsafe { dst.add(i).write_volatile(0) };
        }
    }
}

/// The page tables. These architectures have none yet, and the frame allocator has no frames, so
/// no `Frame` or `Mapping` exists.
pub(crate) mod paging {
    use crate::mm::PageInfo;

    pub(crate) const VMALLOC_START: usize = 0;
    pub(crate) const HEAP_START: usize = 0;
    pub(crate) const HEAP_END: usize = 0;

    pub(crate) fn phys_to_virt(_phys: u64) -> usize {
        unreachable!("no page tables on this architecture yet")
    }

    pub(crate) fn map_page(_virt: usize, _phys: u64, _writable: bool) -> Result<(), ()> {
        Err(())
    }

    pub(crate) fn unmap_page(_virt: usize) -> Option<u64> {
        None
    }

    pub(crate) fn query(_virt: usize) -> Option<PageInfo> {
        None
    }
}

/// The timer values. These architectures have no timer yet, so the values stay 0.
pub(crate) mod timer {
    use core::sync::atomic::AtomicU64;

    pub(crate) const HZ: u64 = 250;
    pub(crate) static TICKS: AtomicU64 = AtomicU64::new(0);
    pub(crate) static TIMER_HZ: AtomicU64 = AtomicU64::new(0);

    /// The nanoseconds since boot, from the tick count.
    pub(crate) fn nanos() -> u64 {
        TICKS.load(core::sync::atomic::Ordering::Relaxed) * (1_000_000_000 / HZ)
    }

    /// The nanoseconds of the clock since boot, from the tick count.
    pub(crate) fn clock_ns() -> u64 {
        nanos()
    }
}

/// Interrupt control. These architectures take no interrupts yet.
pub(crate) mod irq {
    pub(crate) fn enable() {}

    pub(crate) fn disable() {}

    pub(crate) fn enabled() -> bool {
        false
    }

    pub(crate) fn wait() {
        core::hint::spin_loop();
    }
}

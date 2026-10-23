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

/// The page tables. These architectures have none yet, and the frame allocator has no frames, so
/// no `Frame` or `Mapping` exists.
pub(crate) mod paging {
    use crate::mm::PageInfo;

    pub(crate) const VMALLOC_START: usize = 0;
    pub(crate) const VMALLOC_END: usize = 0;

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

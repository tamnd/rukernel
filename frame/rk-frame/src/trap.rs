//! Traps: exceptions and interrupts.
//!
//! The trap entry and the trap handler are in the module of each architecture. This module gives
//! the parts that the safe kernel crates use: the trap counters, a breakpoint, and a read that
//! does not panic on a fault.

use crate::addr::VirtAddr;
use crate::arch::imp;
use core::sync::atomic::Ordering;

/// The number of traps of some kinds since boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrapCounts {
    /// Breakpoint traps.
    pub breakpoints: u64,
    /// Page faults, with the faults that a fixup handled.
    pub page_faults: u64,
    /// Faults that an exception table entry handled.
    pub fixups: u64,
}

/// Gives the trap counters.
pub fn counts() -> TrapCounts {
    TrapCounts {
        breakpoints: imp::trap::BREAKPOINTS.load(Ordering::Relaxed),
        page_faults: imp::trap::PAGE_FAULTS.load(Ordering::Relaxed),
        fixups: imp::trap::FIXUPS.load(Ordering::Relaxed),
    }
}

/// Stops at a breakpoint. Without a debugger, the trap handler counts the breakpoint and the code
/// continues.
pub fn breakpoint() {
    imp::trap::breakpoint();
}

/// A memory access faulted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault;

/// Reads 8 bytes at a kernel address. An address that is not mapped gives `Err(Fault)`, and the
/// kernel does not panic.
pub fn probe_read_u64(addr: VirtAddr) -> Result<u64, Fault> {
    imp::trap::probe_read_u64(addr.get()).ok_or(Fault)
}

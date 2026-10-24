//! The vDSO and its data page, per spec/05-processes-signals-exec.md section 5.4.
//!
//! The build script links the vDSO from `vdso/x86_64.rs`. The kernel maps the data page and the
//! vDSO in each process, with the data page directly below the vDSO. The timer interrupt writes
//! the tick count to the data page, so the time in the vDSO is the same as the time of the
//! system calls.

use crate::arch::imp::paging;
use crate::mm::{Frame, alloc_zeroed_frame};
use crate::sync::Once;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

/// The vDSO, a shared object.
pub static IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vdso.so"));

/// The word of the data page with the tick count.
const TICKS: usize = 0;
/// The word of the data page with the nanoseconds of one tick.
const NS_PER_TICK: usize = 1;

static DATA: Once<Option<Arc<Frame>>> = Once::new();
/// The physical address of the data page, or 0 before `data_page` makes it.
static DATA_PHYS: AtomicU64 = AtomicU64::new(0);

/// The data page. The first call makes it. Gives `None` if no frame is free.
pub fn data_page() -> Option<Arc<Frame>> {
    DATA.call_once(|| {
        let mut frame = alloc_zeroed_frame()?;
        frame.write_u64(NS_PER_TICK, 1_000_000_000 / crate::time::HZ);
        DATA_PHYS.store(frame.addr().get(), Ordering::Release);
        tick();
        Some(Arc::new(frame))
    })
    .clone()
}

/// Writes the tick count to the data page. The timer interrupt calls it after each tick.
pub(crate) fn tick() {
    let phys = DATA_PHYS.load(Ordering::Acquire);
    if phys == 0 {
        return;
    }
    let word = (paging::phys_to_virt(phys) as *mut u64).wrapping_add(TICKS);
    // SAFETY: the data page lives in `DATA` until the kernel stops, and the direct map maps it.
    // The kernel writes the page only here and in `data_page` before it is in `DATA`. A user
    // process maps it read only. One aligned store of 8 bytes is atomic on x86-64, so the vDSO
    // reads the old count or the new count.
    unsafe { word.write_volatile(crate::time::ticks()) };
}

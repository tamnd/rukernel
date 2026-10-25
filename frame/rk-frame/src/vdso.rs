//! The vDSO and its data page, per spec/05-processes-signals-exec.md section 5.4.
//!
//! The build script links the vDSO from `vdso/x86_64.rs`. The kernel maps the data page and the
//! vDSO in each process, with the data page directly below the vDSO. The timer interrupt writes
//! the tick count and the time stamp counter of the tick to the data page, so the time in the
//! vDSO is the same as the time of the system calls.

use crate::arch::imp::paging;
use crate::mm::{Frame, alloc_zeroed_frame};
use crate::sync::Once;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering, compiler_fence};

/// The vDSO, a shared object.
pub static IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vdso.so"));

/// The word of the data page with the tick count.
const TICKS: usize = 0;
/// The word of the data page with the nanoseconds of one tick.
const NS_PER_TICK: usize = 1;
/// The word of the data page with the sequence count. It is odd while the kernel writes the page.
const SEQ: usize = 2;
/// The word of the data page with the time stamp counter at the last tick.
const TICK_TSC: usize = 3;
/// The word of the data page with the nanoseconds of one cycle of the time stamp counter, times
/// 2^32.
const TSC_MULT: usize = 4;
/// The word of the data page with the nanoseconds of `CLOCK_REALTIME` at boot. It does not change.
const REALTIME_OFFSET: usize = 5;

static DATA: Once<Option<Arc<Frame>>> = Once::new();
/// The physical address of the data page, or 0 before `data_page` makes it.
static DATA_PHYS: AtomicU64 = AtomicU64::new(0);

/// The data page. The first call makes it. Gives `None` if no frame is free.
pub fn data_page() -> Option<Arc<Frame>> {
    DATA.call_once(|| {
        let mut frame = alloc_zeroed_frame()?;
        frame.write_u64(NS_PER_TICK, 1_000_000_000 / crate::time::HZ);
        frame.write_u64(REALTIME_OFFSET, crate::time::realtime_offset_ns());
        DATA_PHYS.store(frame.addr().get(), Ordering::Release);
        tick();
        Some(Arc::new(frame))
    })
    .clone()
}

/// Writes the tick count and the time stamp counter of the tick to the data page. The timer
/// interrupt calls it after each tick.
pub(crate) fn tick() {
    let phys = DATA_PHYS.load(Ordering::Acquire);
    if phys == 0 {
        return;
    }
    let page = paging::phys_to_virt(phys) as *mut u64;
    let (tick_tsc, mult) = crate::arch::imp::timer::tsc_state();
    // SAFETY: the data page lives in `DATA` until the kernel stops, and the direct map maps it.
    // The kernel writes the page only here and in `data_page` before it is in `DATA`, and the
    // timer interrupt does not nest. A user process maps it read only. The sequence count is odd
    // while the other words change, so the vDSO reads them again if it sees an odd count or a
    // changed count.
    unsafe {
        let seq = page.wrapping_add(SEQ);
        let count = seq.read_volatile();
        seq.write_volatile(count.wrapping_add(1));
        compiler_fence(Ordering::SeqCst);
        page.wrapping_add(TICKS).write_volatile(crate::time::ticks());
        page.wrapping_add(TICK_TSC).write_volatile(tick_tsc);
        page.wrapping_add(TSC_MULT).write_volatile(mult);
        compiler_fence(Ordering::SeqCst);
        seq.write_volatile(count.wrapping_add(2));
    }
}

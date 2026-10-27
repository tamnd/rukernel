//! The part of the vDSO that is the same on each architecture: the layout of the data page and
//! the calculation of the time. The file of the architecture gives `data`, the page below the
//! vDSO, `counter`, the counter of the clock, and `syscall2`, a system call with two arguments.

use super::{counter, data, syscall2};
use core::sync::atomic::{Ordering, compiler_fence};

/// The data page. The layout is private to the kernel and to the vDSO, see the word constants in
/// `rk_frame::vdso`.
#[repr(C)]
pub struct Data {
    ticks: u64,
    ns_per_tick: u64,
    seq: u64,
    tick_counter: u64,
    counter_mult: u64,
    realtime_offset: u64,
}

#[repr(C)]
pub struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
pub struct Timeval {
    tv_sec: i64,
    tv_usec: i64,
}

pub const NSEC_PER_SEC: u64 = 1_000_000_000;
pub const PAGE_SIZE: usize = 4096;

/// The nanoseconds since boot and the offset of `CLOCK_REALTIME`. This is the calculation of
/// `clock_ns` in the kernel. The two values come from the same version of the page.
fn now_and_offset() -> (u64, u64) {
    let d = data();
    // SAFETY: the kernel maps the data page below the vDSO, and it writes each field with one
    // aligned store. The sequence count tells if the kernel changed the page between the reads.
    unsafe {
        loop {
            let seq = core::ptr::addr_of!((*d).seq).read_volatile();
            compiler_fence(Ordering::SeqCst);
            let ticks = core::ptr::addr_of!((*d).ticks).read_volatile();
            let ns_per_tick = core::ptr::addr_of!((*d).ns_per_tick).read_volatile();
            let base = core::ptr::addr_of!((*d).tick_counter).read_volatile();
            let mult = core::ptr::addr_of!((*d).counter_mult).read_volatile();
            let offset = core::ptr::addr_of!((*d).realtime_offset).read_volatile();
            let now = counter();
            compiler_fence(Ordering::SeqCst);
            if seq & 1 == 0 && core::ptr::addr_of!((*d).seq).read_volatile() == seq {
                let cycles = now.saturating_sub(base);
                let part = ((u128::from(cycles) * u128::from(mult)) >> 32)
                    .min(u128::from(ns_per_tick.saturating_sub(1)));
                return (ticks.wrapping_mul(ns_per_tick).wrapping_add(part as u64), offset);
            }
        }
    }
}

/// The nanoseconds of `CLOCK_REALTIME`. This is the calculation of `realtime_ns` in the kernel.
pub fn realtime_ns() -> u64 {
    let (now, offset) = now_and_offset();
    now.wrapping_add(offset)
}

/// The time of the clock `clock`, which `known` accepts, in nanoseconds.
fn clock_ns(clock: i32) -> u64 {
    // CLOCK_REALTIME, CLOCK_REALTIME_COARSE and CLOCK_TAI follow the real time.
    if matches!(clock, 0 | 5 | 11) { realtime_ns() } else { now_and_offset().0 }
}

/// The resolution of the clocks, in nanoseconds.
fn resolution_ns() -> u64 {
    let d = data();
    // SAFETY: as in `now_and_offset`.
    unsafe { core::ptr::addr_of!((*d).ns_per_tick).read_volatile() }
}

/// Tells if the data page gives the clock.
fn known(clock: i32) -> bool {
    // CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE,
    // CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME and CLOCK_TAI.
    matches!(clock, 0 | 1 | 4 | 5 | 6 | 7 | 11)
}

/// `clock_gettime`. `nr` is the number of the system call for the clocks that the data page does
/// not give.
///
/// # Safety
///
/// `ts` points to a `timespec`. A bad pointer is a fault in the caller, as on Linux.
pub unsafe fn clock_gettime(nr: usize, clock: i32, ts: *mut Timespec) -> i32 {
    if !known(clock) {
        return syscall2(nr, clock as usize, ts as usize);
    }
    let ns = clock_ns(clock);
    let value =
        Timespec { tv_sec: (ns / NSEC_PER_SEC) as i64, tv_nsec: (ns % NSEC_PER_SEC) as i64 };
    // SAFETY: the caller gives a pointer to a `timespec`.
    unsafe { ts.write_volatile(value) };
    0
}

/// `clock_getres`. `nr` is the number of the system call for the clocks that the data page does
/// not give.
///
/// # Safety
///
/// `res` is null or points to a `timespec`.
pub unsafe fn clock_getres(nr: usize, clock: i32, res: *mut Timespec) -> i32 {
    if !known(clock) {
        return syscall2(nr, clock as usize, res as usize);
    }
    if !res.is_null() {
        let ns = resolution_ns();
        let value =
            Timespec { tv_sec: (ns / NSEC_PER_SEC) as i64, tv_nsec: (ns % NSEC_PER_SEC) as i64 };
        // SAFETY: the caller gives a pointer to a `timespec`.
        unsafe { res.write_volatile(value) };
    }
    0
}

/// `gettimeofday`.
///
/// # Safety
///
/// `tv` is null or points to a `timeval`, and `tz` is null or points to a `timezone`.
pub unsafe fn gettimeofday(tv: *mut Timeval, tz: *mut [i32; 2]) -> i32 {
    if !tv.is_null() {
        let ns = realtime_ns();
        let value = Timeval {
            tv_sec: (ns / NSEC_PER_SEC) as i64,
            tv_usec: (ns % NSEC_PER_SEC / 1000) as i64,
        };
        // SAFETY: the caller gives a pointer to a `timeval`.
        unsafe { tv.write_volatile(value) };
    }
    if !tz.is_null() {
        // SAFETY: the caller gives a pointer to a `timezone`. The kernel has no time zone, as
        // Linux by default.
        unsafe { tz.write_volatile([0, 0]) };
    }
    0
}

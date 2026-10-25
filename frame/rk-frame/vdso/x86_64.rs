//! The vDSO of x86-64. The build script of rk-frame compiles this file to an object and links it
//! with `vdso.ld` to a shared object. The kernel maps the shared object in each process, with the
//! data page directly below it. glibc and musl find the functions by name and by the version
//! `LINUX_2.6`, as on Linux.
//!
//! The functions read the time from the data page. The kernel writes the tick count and the time
//! stamp counter of the tick to the page at each timer tick. The functions add the time of the
//! counter since the tick, less than one tick, so the time is the same as the time of the system
//! calls. A clock that the
//! data page does not give goes to the system call.

#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;
use core::sync::atomic::{Ordering, compiler_fence};

/// The data page. The layout is private to the kernel and to this file, see
/// the word constants in `rk_frame::vdso`.
#[repr(C)]
struct Data {
    ticks: u64,
    ns_per_tick: u64,
    seq: u64,
    tick_tsc: u64,
    tsc_mult: u64,
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

const NSEC_PER_SEC: u64 = 1_000_000_000;
const PAGE_SIZE: usize = 4096;
const SYS_CLOCK_GETTIME: usize = 228;
const SYS_CLOCK_GETRES: usize = 229;

/// The data page, at the page below the first byte of the vDSO.
fn data() -> *const Data {
    let base: usize;
    // SAFETY: the instruction only computes an address. `__ehdr_start` is the ELF header of the
    // vDSO, at the start of its first page.
    unsafe {
        asm!("lea {}, [rip + __ehdr_start]", out(reg) base, options(pure, nomem, nostack));
    }
    base.wrapping_sub(PAGE_SIZE) as *const Data
}

/// Reads the time stamp counter.
fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: `rdtsc` writes only EAX and EDX.
    unsafe { asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)) };
    (u64::from(hi) << 32) | u64::from(lo)
}

/// The nanoseconds since boot. This is the calculation of `clock_ns` in the kernel.
fn now_ns() -> u64 {
    let d = data();
    // SAFETY: the kernel maps the data page below the vDSO, and it writes each field with one
    // aligned store. The sequence count tells if the kernel changed the page between the reads.
    unsafe {
        loop {
            let seq = core::ptr::addr_of!((*d).seq).read_volatile();
            compiler_fence(Ordering::SeqCst);
            let ticks = core::ptr::addr_of!((*d).ticks).read_volatile();
            let ns_per_tick = core::ptr::addr_of!((*d).ns_per_tick).read_volatile();
            let base = core::ptr::addr_of!((*d).tick_tsc).read_volatile();
            let mult = core::ptr::addr_of!((*d).tsc_mult).read_volatile();
            let now = rdtsc();
            compiler_fence(Ordering::SeqCst);
            if seq & 1 == 0 && core::ptr::addr_of!((*d).seq).read_volatile() == seq {
                let cycles = now.saturating_sub(base);
                let part = ((u128::from(cycles) * u128::from(mult)) >> 32)
                    .min(u128::from(ns_per_tick.saturating_sub(1)));
                return ticks.wrapping_mul(ns_per_tick).wrapping_add(part as u64);
            }
        }
    }
}

/// The nanoseconds of `CLOCK_REALTIME`. This is the calculation of `realtime_ns` in the kernel.
fn realtime_ns() -> u64 {
    let d = data();
    // SAFETY: as in `now_ns`. The kernel writes the word before it maps the page, and it does not
    // change it.
    let offset = unsafe { core::ptr::addr_of!((*d).realtime_offset).read_volatile() };
    now_ns().wrapping_add(offset)
}

/// The time of the clock `clock`, which `known` accepts, in nanoseconds.
fn clock_ns(clock: i32) -> u64 {
    // CLOCK_REALTIME, CLOCK_REALTIME_COARSE and CLOCK_TAI follow the real time.
    if matches!(clock, 0 | 5 | 11) { realtime_ns() } else { now_ns() }
}

/// The resolution of the clocks, in nanoseconds.
fn resolution_ns() -> u64 {
    let d = data();
    // SAFETY: as in `now_ns`.
    unsafe { core::ptr::addr_of!((*d).ns_per_tick).read_volatile() }
}

/// Tells if the data page gives the clock.
fn known(clock: i32) -> bool {
    // CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE,
    // CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME and CLOCK_TAI.
    matches!(clock, 0 | 1 | 4 | 5 | 6 | 7 | 11)
}

fn syscall2(nr: usize, a: usize, b: usize) -> i32 {
    let ret: isize;
    // SAFETY: the system call reads its two arguments and writes only user memory that the
    // caller gave.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr as isize => ret,
            in("rdi") a,
            in("rsi") b,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret as i32
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __vdso_clock_gettime(clock: i32, ts: *mut Timespec) -> i32 {
    if !known(clock) {
        return syscall2(SYS_CLOCK_GETTIME, clock as usize, ts as usize);
    }
    let ns = clock_ns(clock);
    let value =
        Timespec { tv_sec: (ns / NSEC_PER_SEC) as i64, tv_nsec: (ns % NSEC_PER_SEC) as i64 };
    // SAFETY: the caller gives a pointer to a `timespec`. A bad pointer is a fault in the caller,
    // as on Linux.
    unsafe { ts.write_volatile(value) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __vdso_clock_getres(clock: i32, res: *mut Timespec) -> i32 {
    if !known(clock) {
        return syscall2(SYS_CLOCK_GETRES, clock as usize, res as usize);
    }
    if !res.is_null() {
        let ns = resolution_ns();
        let value =
            Timespec { tv_sec: (ns / NSEC_PER_SEC) as i64, tv_nsec: (ns % NSEC_PER_SEC) as i64 };
        // SAFETY: as in `__vdso_clock_gettime`.
        unsafe { res.write_volatile(value) };
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __vdso_gettimeofday(tv: *mut Timeval, tz: *mut [i32; 2]) -> i32 {
    if !tv.is_null() {
        let ns = realtime_ns();
        let value = Timeval {
            tv_sec: (ns / NSEC_PER_SEC) as i64,
            tv_usec: (ns % NSEC_PER_SEC / 1000) as i64,
        };
        // SAFETY: as in `__vdso_clock_gettime`.
        unsafe { tv.write_volatile(value) };
    }
    if !tz.is_null() {
        // SAFETY: as in `__vdso_clock_gettime`. The kernel has no time zone, as Linux by default.
        unsafe { tz.write_volatile([0, 0]) };
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __vdso_time(t: *mut i64) -> i64 {
    let sec = (realtime_ns() / NSEC_PER_SEC) as i64;
    if !t.is_null() {
        // SAFETY: as in `__vdso_clock_gettime`.
        unsafe { t.write_volatile(sec) };
    }
    sec
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __vdso_getcpu(cpu: *mut u32, node: *mut u32) -> i32 {
    // The limit of the segment 0x7b has the CPU number and the node number, as in Linux.
    let p: u32;
    // SAFETY: `lsl` only reads the GDT entry of the selector and writes the register and ZF.
    unsafe {
        core::arch::asm!("lsl {p:e}, {sel:e}", p = out(reg) p, sel = in(reg) 0x7bu32, options(nomem, nostack))
    };
    if !cpu.is_null() {
        // SAFETY: as in `__vdso_clock_gettime`.
        unsafe { cpu.write_volatile(p & 0xfff) };
    }
    if !node.is_null() {
        // SAFETY: as in `__vdso_clock_gettime`.
        unsafe { node.write_volatile(p >> 12) };
    }
    0
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}

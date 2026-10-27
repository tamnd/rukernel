//! The vDSO of x86-64. The build script of rk-frame compiles this file to an object and links it
//! with `vdso.ld` and `x86_64.ver` to a shared object. The kernel maps the shared object in each process, with the
//! data page directly below it. glibc and musl find the functions by name and by the version
//! `LINUX_2.6`, as on Linux.
//!
//! The functions read the time from the data page. The kernel writes the tick count and the time
//! stamp counter of the tick to the page at each timer tick. The functions add the time of the
//! counter since the tick, less than one tick, so the time is the same as the time of the system
//! calls. A clock that the data page does not give goes to the system call. `common.rs` has the
//! calculation.

#![no_std]
#![no_main]

mod common;

use common::{NSEC_PER_SEC, PAGE_SIZE, Timespec, Timeval};
use core::arch::asm;
use core::panic::PanicInfo;

const SYS_CLOCK_GETTIME: usize = 228;
const SYS_CLOCK_GETRES: usize = 229;

/// The data page, at the page below the first byte of the vDSO.
fn data() -> *const common::Data {
    let base: usize;
    // SAFETY: the instruction only computes an address. `__ehdr_start` is the ELF header of the
    // vDSO, at the start of its first page.
    unsafe {
        asm!("lea {}, [rip + __ehdr_start]", out(reg) base, options(pure, nomem, nostack));
    }
    base.wrapping_sub(PAGE_SIZE) as *const common::Data
}

/// Reads the time stamp counter.
fn counter() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: `rdtsc` writes only EAX and EDX.
    unsafe { asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)) };
    (u64::from(hi) << 32) | u64::from(lo)
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
    // SAFETY: the caller gives the arguments of `clock_gettime`.
    unsafe { common::clock_gettime(SYS_CLOCK_GETTIME, clock, ts) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __vdso_clock_getres(clock: i32, res: *mut Timespec) -> i32 {
    // SAFETY: the caller gives the arguments of `clock_getres`.
    unsafe { common::clock_getres(SYS_CLOCK_GETRES, clock, res) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __vdso_gettimeofday(tv: *mut Timeval, tz: *mut [i32; 2]) -> i32 {
    // SAFETY: the caller gives the arguments of `gettimeofday`.
    unsafe { common::gettimeofday(tv, tz) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __vdso_time(t: *mut i64) -> i64 {
    let sec = (common::realtime_ns() / NSEC_PER_SEC) as i64;
    if !t.is_null() {
        // SAFETY: the caller gives a valid pointer. A bad pointer is a fault in the caller.
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
        // SAFETY: the caller gives a valid pointer. A bad pointer is a fault in the caller.
        unsafe { cpu.write_volatile(p & 0xfff) };
    }
    if !node.is_null() {
        // SAFETY: the caller gives a valid pointer. A bad pointer is a fault in the caller.
        unsafe { node.write_volatile(p >> 12) };
    }
    0
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}

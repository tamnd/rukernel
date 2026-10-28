//! The vDSO of arm64. The build script of rk-frame compiles this file to an object and links it
//! with `vdso.ld` and `aarch64.ver` to a shared object. The kernel maps the shared object in each
//! process, with the data page directly below it. glibc and musl find the functions by name and by
//! the version `LINUX_2.6.39`, as on Linux.
//!
//! The time functions read the time from the data page. The kernel writes the tick count and the
//! virtual counter of the generic timer at the tick to the page at each timer tick. The functions
//! add the time of the counter since the tick, less than one tick, so the time is the same as the
//! time of the system calls. User code can read the virtual counter, because the kernel sets
//! `CNTKCTL_EL1.EL0VCTEN`. `common.rs` has the calculation.
//!
//! `__kernel_rt_sigreturn` is the return of a signal handler. The kernel puts its address in the
//! link register of the handler when the C library gives no `SA_RESTORER`, as Linux does.

#![no_std]
#![no_main]

mod common;

use common::{PAGE_SIZE, Timespec, Timeval};
use core::arch::{asm, global_asm};
use core::panic::PanicInfo;

const SYS_CLOCK_GETTIME: usize = 113;
const SYS_CLOCK_GETRES: usize = 114;

// The return of a signal handler, as arch/arm64/kernel/vdso/sigreturn.S of Linux. The `nop` is
// before the symbol, as in Linux, because an unwinder looks at the instruction before the return
// address. The system call is `rt_sigreturn`, 139.
global_asm!(
    ".text",
    ".balign 16",
    "nop",
    ".globl __kernel_rt_sigreturn",
    ".type __kernel_rt_sigreturn, %function",
    "__kernel_rt_sigreturn:",
    "mov x8, #139",
    "svc #0",
    ".size __kernel_rt_sigreturn, . - __kernel_rt_sigreturn",
);

/// The data page, at the page below the first byte of the vDSO.
fn data() -> *const common::Data {
    let base: usize;
    // SAFETY: the instructions only compute an address. `__ehdr_start` is the ELF header of the
    // vDSO, at the start of its first page.
    unsafe {
        asm!(
            "adrp {0}, __ehdr_start",
            "add {0}, {0}, :lo12:__ehdr_start",
            out(reg) base,
            options(pure, nomem, nostack),
        );
    }
    base.wrapping_sub(PAGE_SIZE) as *const common::Data
}

/// Reads the virtual counter. The ISB orders the read after the reads of the data page, as
/// `__arch_get_hw_counter` of Linux does.
fn counter() -> u64 {
    let value: u64;
    // SAFETY: the kernel lets user code read CNTVCT_EL0. The read has no side effect.
    unsafe { asm!("isb", "mrs {}, cntvct_el0", out(reg) value, options(nomem, nostack)) };
    value
}

fn syscall2(nr: usize, a: usize, b: usize) -> i32 {
    let ret: isize;
    // SAFETY: the system call reads its two arguments and writes only user memory that the
    // caller gave.
    unsafe {
        asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a as isize => ret,
            in("x1") b,
            options(nostack),
        );
    }
    ret as i32
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __kernel_clock_gettime(clock: i32, ts: *mut Timespec) -> i32 {
    // SAFETY: the caller gives the arguments of `clock_gettime`.
    unsafe { common::clock_gettime(SYS_CLOCK_GETTIME, clock, ts) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __kernel_clock_getres(clock: i32, res: *mut Timespec) -> i32 {
    // SAFETY: the caller gives the arguments of `clock_getres`.
    unsafe { common::clock_getres(SYS_CLOCK_GETRES, clock, res) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __kernel_gettimeofday(tv: *mut Timeval, tz: *mut [i32; 2]) -> i32 {
    // SAFETY: the caller gives the arguments of `gettimeofday`.
    unsafe { common::gettimeofday(tv, tz) }
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {}
}

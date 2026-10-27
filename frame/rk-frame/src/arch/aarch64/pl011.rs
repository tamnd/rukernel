//! The PL011 UART, the early console of arm64.
//!
//! The kernel writes the boot log here before any other device works. The firmware or QEMU sets
//! the baud rate, so the kernel does not program the UART, as the `earlycon` driver of Linux. The
//! console is polled.

use super::paging::MMIO_BASE;

/// The UART of QEMU virt, in the device window of the boot page tables.
// TODO: read the address from `/chosen/stdout-path` of the device tree.
const BASE: usize = MMIO_BASE + 0x0900_0000;

/// The data register.
const DR: usize = 0x00;
/// The flag register.
const FR: usize = 0x18;
/// The receive FIFO is empty.
const FR_RXFE: u32 = 1 << 4;
/// The transmit FIFO is full.
const FR_TXFF: u32 = 1 << 5;

fn read(reg: usize) -> u32 {
    // SAFETY: the boot page tables map the UART registers as device memory at `BASE`, and rk-frame
    // owns the UART. A read of the flag or data register changes no memory.
    unsafe { ((BASE + reg) as *const u32).read_volatile() }
}

fn write(reg: usize, value: u32) {
    // SAFETY: as for `read`. A write to the data register sends one byte.
    unsafe { ((BASE + reg) as *mut u32).write_volatile(value) };
}

fn put(b: u8) {
    while read(FR) & FR_TXFF != 0 {
        core::hint::spin_loop();
    }
    write(DR, u32::from(b));
}

/// Writes bytes to the UART. A line feed becomes a carriage return and a line feed.
pub(crate) fn write_bytes(bytes: &[u8]) {
    for &b in bytes {
        if b == b'\n' {
            put(b'\r');
        }
        put(b);
    }
}

/// Writes bytes to the UART with no change.
pub(crate) fn write_raw(bytes: &[u8]) {
    for &b in bytes {
        put(b);
    }
}

/// Reads one byte, if a byte came.
pub(crate) fn try_read() -> Option<u8> {
    if read(FR) & FR_RXFE != 0 { None } else { Some(read(DR) as u8) }
}

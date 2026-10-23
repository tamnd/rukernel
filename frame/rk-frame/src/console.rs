//! The early console.
//!
//! The boot log goes to the serial port of the architecture. `printk`, the log levels and
//! `/dev/kmsg` come in a safe crate in R1. This module is only the lowest writer.

use crate::sync::SpinLock;
use core::fmt::{self, Write};

struct Console;

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        #[cfg(all(target_os = "none", target_arch = "x86_64"))]
        crate::arch::x86_64::serial::write_bytes(s.as_bytes());
        #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
        let _ = s;
        Ok(())
    }
}

static CONSOLE: SpinLock<Console> = SpinLock::new(Console);

/// Writes formatted text to the console. Use `print!` and `println!`.
#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    // A write to the serial port cannot fail, so the result is always `Ok`.
    let _ = CONSOLE.lock().write_fmt(args);
}

/// Writes formatted text to the console, if the lock is free. The panic path uses this function,
/// so that a panic while the console is held does not stop the CPU with no message.
#[doc(hidden)]
pub fn _print_panic(args: fmt::Arguments<'_>) {
    match CONSOLE.try_lock() {
        Some(mut c) => {
            let _ = c.write_fmt(args);
        }
        None => {
            let _ = Console.write_fmt(args);
        }
    }
}

/// Writes bytes to the console with no change: a line feed stays a line feed. The console device
/// of the tty layer uses this function for the output of user programs.
pub fn write_bytes(bytes: &[u8]) {
    let _guard = CONSOLE.lock();
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    crate::arch::x86_64::serial::write_raw(bytes);
    #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
    let _ = bytes;
}

/// Reads one byte from the console, if a byte came. The console is polled until the tty layer
/// gets the interrupt of the serial port.
pub fn try_read_byte() -> Option<u8> {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    return crate::arch::x86_64::serial::try_read();
    #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
    None
}

/// Writes formatted text to the early console.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => { $crate::console::_print(format_args!($($arg)*)) };
}

/// Writes formatted text and a line feed to the early console.
#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => { $crate::console::_print(format_args!("{}\n", format_args!($($arg)*))) };
}

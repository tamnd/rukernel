//! The early console.
//!
//! The boot log goes to the serial port of the architecture. The text of `print!` also goes to
//! the kernel log, a ring of `LOG_SIZE` bytes that `syslog(2)` reads. Each line of the log starts
//! with the level and the time since boot, as `<6>[    1.234567] `, which `dmesg` reads.

use crate::sync::SpinLock;
use core::fmt::{self, Write};

/// The size of the kernel log, as `CONFIG_LOG_BUF_SHIFT=16` of Linux.
pub const LOG_SIZE: usize = 1 << 16;

/// The kernel log. `end` counts all the bytes that went in the log, so the byte `i` is at
/// `i % LOG_SIZE` while `end - i <= LOG_SIZE`.
struct Log {
    buf: [u8; LOG_SIZE],
    end: u64,
    /// The first byte that `syslog` with `SYSLOG_ACTION_READ` did not read.
    read: u64,
    /// The first byte after the last clear.
    clear: u64,
    /// The next byte starts a line.
    line_start: bool,
}

impl Log {
    fn push(&mut self, b: u8) {
        self.buf[(self.end % LOG_SIZE as u64) as usize] = b;
        self.end += 1;
    }

    fn write(&mut self, s: &str) {
        for &b in s.as_bytes() {
            if self.line_start {
                #[cfg(target_os = "none")]
                let ns = crate::time::nanos();
                #[cfg(not(target_os = "none"))]
                let ns = 0u64;
                let mut prefix = Prefix([0; 32], 0);
                let _ =
                    write!(prefix, "<6>[{:5}.{:06}] ", ns / 1_000_000_000, ns / 1000 % 1_000_000);
                for i in 0..prefix.1 {
                    self.push(prefix.0[i]);
                }
            }
            self.push(b);
            self.line_start = b == b'\n';
        }
    }

    /// The first byte that is still in the ring.
    fn oldest(&self) -> u64 {
        self.end.saturating_sub(LOG_SIZE as u64)
    }

    /// Copies the bytes from `from` to the end of the log, or as many as fit, to `out`.
    fn copy(&self, from: u64, out: &mut [u8]) -> usize {
        let from = from.max(self.oldest());
        let n = ((self.end - from) as usize).min(out.len());
        for (i, b) in out[..n].iter_mut().enumerate() {
            *b = self.buf[((from + i as u64) % LOG_SIZE as u64) as usize];
        }
        n
    }
}

/// A small buffer for the prefix of a line.
struct Prefix([u8; 32], usize);

impl Write for Prefix {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = s.len().min(self.0.len() - self.1);
        self.0[self.1..self.1 + n].copy_from_slice(&s.as_bytes()[..n]);
        self.1 += n;
        Ok(())
    }
}

static LOG: SpinLock<Log> =
    SpinLock::new(Log { buf: [0; LOG_SIZE], end: 0, read: 0, clear: 0, line_start: true });

/// Reads the bytes of the kernel log that `log_read` did not read yet, as `SYSLOG_ACTION_READ`.
/// Gives the number of bytes in `out`.
pub fn log_read(out: &mut [u8]) -> usize {
    let mut log = LOG.lock();
    let from = log.read.max(log.oldest());
    let n = log.copy(from, out);
    log.read = from + n as u64;
    n
}

/// Reads the last bytes of the kernel log after the last clear, as many as fit in `out`, as
/// `SYSLOG_ACTION_READ_ALL`. Gives the number of bytes in `out`.
pub fn log_read_all(out: &mut [u8]) -> usize {
    let log = LOG.lock();
    let from = log.clear.max(log.oldest()).max(log.end.saturating_sub(out.len() as u64));
    log.copy(from, out)
}

/// Clears the kernel log, as `SYSLOG_ACTION_CLEAR`. A later `log_read_all` gives only the new
/// bytes.
pub fn log_clear() {
    let mut log = LOG.lock();
    log.clear = log.end;
}

/// The number of bytes that `log_read` can read, as `SYSLOG_ACTION_SIZE_UNREAD`.
pub fn log_unread() -> usize {
    let log = LOG.lock();
    (log.end - log.read.max(log.oldest())) as usize
}

struct Console;

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // The panic path can write while a CPU holds the log, so a busy log loses the text.
        if let Some(mut log) = LOG.try_lock() {
            log.write(s);
        }
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

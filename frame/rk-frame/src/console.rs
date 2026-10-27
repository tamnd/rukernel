//! The early console.
//!
//! The boot log goes to the serial port of the architecture. The text of `print!` also goes to
//! the kernel log, a ring of `LOG_SIZE` bytes that `syslog(2)` reads. Each line of the log starts
//! with the level and the time since boot, as `<6>[    1.234567] `, which `dmesg` reads.
//!
//! The log is also a list of records, as the ring buffer of Linux. A line of `print!` is one
//! record. A write to `/dev/kmsg` is one record, and each line of it starts with the same prefix.
//! An index keeps the place of each record in the ring, so that `/dev/kmsg` can read the records
//! one at a time with their sequence numbers.

use crate::sync::SpinLock;
use core::fmt::{self, Write};

/// The size of the kernel log, as `CONFIG_LOG_BUF_SHIFT=16` of Linux.
pub const LOG_SIZE: usize = 1 << 16;

/// The number of records in the index of the kernel log. A line of the log has about 60 bytes,
/// so the index can keep each record that is still in the ring.
const RECORDS: usize = 2048;

/// The level of the text of `print!`, `KERN_INFO`.
const KERNEL_PRIO: u16 = 6;

/// The place of a record in the kernel log.
#[derive(Clone, Copy)]
struct Record {
    /// The first byte of the record.
    start: u64,
    /// The byte after the line feed at the end of the record.
    end: u64,
    /// The length of the prefix at the start of each line.
    prefix: u16,
    /// The facility and the level, as `(facility << 3) | level`.
    prio: u16,
    /// The time since boot, in nanoseconds.
    ns: u64,
}

impl Record {
    const EMPTY: Self = Self { start: 0, end: 0, prefix: 0, prio: 0, ns: 0 };
}

/// A record of the kernel log, as `struct printk_info` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogRecord {
    /// The sequence number.
    pub seq: u64,
    /// The facility and the level, as `(facility << 3) | level`.
    pub prio: u16,
    /// The time since boot, in nanoseconds.
    pub ns: u64,
    /// The length of the text. The text can be longer than the buffer that `log_record` fills.
    pub len: usize,
}

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
    /// The place of each record, at its sequence number modulo `RECORDS`.
    records: [Record; RECORDS],
    /// The sequence number of the next record.
    next: u64,
    /// The sequence number of the first record after the last clear.
    clear_seq: u64,
    /// The record of the line that does not have its line feed yet.
    cur: Record,
}

impl Log {
    fn push(&mut self, b: u8) {
        self.buf[(self.end % LOG_SIZE as u64) as usize] = b;
        self.end += 1;
    }

    fn write(&mut self, s: &str, ns: u64) {
        for &b in s.as_bytes() {
            if self.line_start {
                self.start_record(KERNEL_PRIO, ns);
            }
            self.push(b);
            self.line_start = b == b'\n';
            if self.line_start {
                self.end_record();
            }
        }
    }

    /// Writes the prefix of a new record, and starts the record.
    fn start_record(&mut self, prio: u16, ns: u64) {
        let prefix = Prefix::new(prio, ns);
        self.cur = Record { start: self.end, end: self.end, prefix: prefix.1 as u16, prio, ns };
        self.push_prefix(&prefix);
    }

    fn push_prefix(&mut self, prefix: &Prefix) {
        for i in 0..prefix.1 {
            self.push(prefix.0[i]);
        }
    }

    /// Puts the record that ends here in the index.
    fn end_record(&mut self) {
        self.cur.end = self.end;
        self.records[(self.next % RECORDS as u64) as usize] = self.cur;
        self.next += 1;
    }

    /// Puts `text` in the log as one record, as `vprintk_store` of Linux. One line feed at the end
    /// of the text is not part of the record. A line of `print!` that has no line feed yet ends
    /// before the record.
    fn emit(&mut self, prio: u16, ns: u64, text: &[u8]) {
        if !self.line_start {
            self.push(b'\n');
            self.line_start = true;
            self.end_record();
        }
        let text = text.strip_suffix(b"\n").unwrap_or(text);
        let prefix = Prefix::new(prio, ns);
        self.cur = Record { start: self.end, end: self.end, prefix: prefix.1 as u16, prio, ns };
        for line in text.split(|&b| b == b'\n') {
            self.push_prefix(&prefix);
            for &b in line {
                self.push(b);
            }
            self.push(b'\n');
        }
        self.end_record();
    }

    /// The sequence number of the first record that is still in the ring.
    fn first_seq(&self) -> u64 {
        let oldest = self.oldest();
        let mut seq = self.next.saturating_sub(RECORDS as u64);
        while seq < self.next && self.records[(seq % RECORDS as u64) as usize].start < oldest {
            seq += 1;
        }
        seq
    }

    /// Copies the text of the record `seq`, or of the first record after it if the record is
    /// not in the ring now, to `out`. The prefix of each line is not part of the text.
    fn record(&self, seq: u64, out: &mut [u8]) -> Option<LogRecord> {
        let seq = seq.max(self.first_seq());
        if seq >= self.next {
            return None;
        }
        let r = self.records[(seq % RECORDS as u64) as usize];
        let mut len = 0;
        let mut at = r.start;
        while at < r.end {
            if len > 0
                && let Some(b) = out.get_mut(len - 1)
            {
                *b = b'\n';
            }
            at += u64::from(r.prefix);
            while at < r.end {
                let b = self.buf[(at % LOG_SIZE as u64) as usize];
                at += 1;
                if b == b'\n' {
                    break;
                }
                if let Some(o) = out.get_mut(len) {
                    *o = b;
                }
                len += 1;
            }
            len += 1;
        }
        Some(LogRecord { seq, prio: r.prio, ns: r.ns, len: len.saturating_sub(1) })
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

impl Prefix {
    /// The prefix of each line of a record, as `info_print_prefix` of Linux for `syslog`.
    fn new(prio: u16, ns: u64) -> Self {
        let mut prefix = Self([0; 32], 0);
        let _ = write!(prefix, "<{prio}>[{:5}.{:06}] ", ns / 1_000_000_000, ns / 1000 % 1_000_000);
        prefix
    }
}

impl Write for Prefix {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = s.len().min(self.0.len() - self.1);
        self.0[self.1..self.1 + n].copy_from_slice(&s.as_bytes()[..n]);
        self.1 += n;
        Ok(())
    }
}

impl Log {
    const fn new() -> Self {
        Self {
            buf: [0; LOG_SIZE],
            end: 0,
            read: 0,
            clear: 0,
            line_start: true,
            records: [Record::EMPTY; RECORDS],
            next: 0,
            clear_seq: 0,
            cur: Record::EMPTY,
        }
    }
}

static LOG: SpinLock<Log> = SpinLock::new(Log::new());

/// The time since boot for a new record.
fn now_ns() -> u64 {
    #[cfg(target_os = "none")]
    return crate::time::nanos();
    #[cfg(not(target_os = "none"))]
    0
}

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
    log.clear_seq = log.next;
}

/// Puts `text` in the kernel log as one record with the facility and the level `prio`, and writes
/// it to the console, as `vprintk_emit` of Linux. `/dev/kmsg` uses this function.
pub fn log_emit(prio: u16, text: &[u8]) {
    let _guard = CONSOLE.lock();
    LOG.lock().emit(prio, now_ns(), text);
    let text = text.strip_suffix(b"\n").unwrap_or(text);
    #[cfg(target_os = "none")]
    {
        crate::arch::imp::console::write_bytes(text);
        crate::arch::imp::console::write_bytes(b"\n");
    }
    #[cfg(not(target_os = "none"))]
    let _ = text;
}

/// Copies the text of the record `seq` of the kernel log to `out`, as much as fits. If the record
/// is not in the ring now, the first record after it takes its place, and the caller sees another
/// sequence number. Gives `None` if no record has the number `seq` or a higher number yet.
pub fn log_record(seq: u64, out: &mut [u8]) -> Option<LogRecord> {
    LOG.lock().record(seq, out)
}

/// The sequence number of the first record that is still in the kernel log.
pub fn log_first_seq() -> u64 {
    LOG.lock().first_seq()
}

/// The sequence number of the first record after the last clear, or of the first record that is
/// still in the log if it is later.
pub fn log_clear_seq() -> u64 {
    let log = LOG.lock();
    log.clear_seq.max(log.first_seq())
}

/// The sequence number of the next record of the kernel log.
pub fn log_next_seq() -> u64 {
    LOG.lock().next
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
            log.write(s, now_ns());
        }
        #[cfg(target_os = "none")]
        crate::arch::imp::console::write_bytes(s.as_bytes());
        #[cfg(not(target_os = "none"))]
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
    #[cfg(target_os = "none")]
    crate::arch::imp::console::write_raw(bytes);
    #[cfg(not(target_os = "none"))]
    let _ = bytes;
}

/// Reads one byte from the console, if a byte came. The console is polled until the tty layer
/// gets the interrupt of the serial port.
pub fn try_read_byte() -> Option<u8> {
    #[cfg(target_os = "none")]
    return crate::arch::imp::console::try_read();
    #[cfg(not(target_os = "none"))]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_keep_lines_and_writes() {
        let mut log = Log::new();
        log.write("boot\npart", 1_500_000_000);
        log.emit(12, 2_000_000_000, b"one\ntwo\n");
        let mut out = [0u8; 64];
        let r = log.record(0, &mut out).unwrap();
        assert_eq!((r.seq, r.prio, &out[..r.len]), (0, 6, &b"boot"[..]));
        let r = log.record(1, &mut out).unwrap();
        assert_eq!(&out[..r.len], b"part");
        let r = log.record(2, &mut out).unwrap();
        assert_eq!((r.prio, r.ns, &out[..r.len]), (12, 2_000_000_000, &b"one\ntwo"[..]));
        assert!(log.record(3, &mut out).is_none());
        let mut all = [0u8; 128];
        let n = log.copy(0, &mut all);
        let text = "<6>[    1.500000] boot\n<6>[    1.500000] part\n\
                    <12>[    2.000000] one\n<12>[    2.000000] two\n";
        assert_eq!(&all[..n], text.as_bytes());
    }

    #[test]
    fn a_lost_record_gives_the_first_one_after_it() {
        let mut log = Log::new();
        for _ in 0..LOG_SIZE / 40 {
            log.emit(14, 0, &[b'x'; 40]);
        }
        let first = log.first_seq();
        assert!(first > 0);
        let mut out = [0u8; 64];
        let r = log.record(0, &mut out).unwrap();
        assert_eq!((r.seq, r.len), (first, 40));
    }
}

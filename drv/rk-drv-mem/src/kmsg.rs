//! `/dev/kmsg`, the device of the kernel log, as kernel/printk/printk.c in Linux.
//!
//! A write puts one record in the kernel log. A `<N>` at the start of the write gives the level
//! in the low 3 bits of `N` and the facility in the other bits. Without it, the level is 4, the
//! `default_message_loglevel` of Linux, and the facility is 1, `LOG_USER`, so that a record from
//! a user program is not the same as a record of the kernel. A read gives one record as
//! `prio,seq,usec,-;text` and a line feed, as `devkmsg_read`. Each open file has its own sequence
//! number, and `lseek` moves it.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::poll::{POLLERR, POLLIN, POLLPRI, POLLRDNORM};
use rk_frame::console::{self, LogRecord};
use rk_frame::sync::SpinLock;
use rk_vfs::device::{self, CharDevice, makedev};
use rk_vfs::inode::Result;
use rk_vfs::wait::PollTable;
use rk_vfs::{File, FileOps, WaitQueue, Whence};

/// The device number of `/dev/kmsg`.
pub const KMSG_RDEV: u64 = makedev(crate::MEM_MAJOR, 11);

/// The largest write and the largest text of a record, `PRINTKRB_RECORD_MAX` of Linux.
const RECORD_MAX: usize = 1024;

/// The level of a write without a level, `default_message_loglevel` of Linux.
const DEFAULT_LEVEL: u32 = 4;

/// The facility of a write without a facility, `LOG_USER`.
const LOG_USER: u32 = 1;

/// The readers and the waits of `poll` that wait for a new record. A write to `/dev/kmsg` wakes
/// them, and `wake_readers` wakes them after a record of the kernel. A reader also looks at the
/// log at each tick, so that a signal stops its wait.
static WAIT: WaitQueue = WaitQueue::new();

/// The sequence number of the next record of the log when `wake_readers` last looked.
static WOKEN: AtomicU64 = AtomicU64::new(0);

/// Wakes the readers and the waits of `poll` if the kernel log has a new record, as
/// `wake_up_klogd` of Linux. The code that prints a record can hold any lock, so it cannot wake
/// them. The bottom half calls this function after the interrupts, as the `irq_work` of Linux.
#[cfg_attr(
    not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))),
    allow(dead_code)
)]
fn wake_readers() {
    let next = console::log_next_seq();
    if WOKEN.swap(next, Ordering::Relaxed) != next {
        WAIT.wake_all();
    }
}

/// Gives the facility and the level of a write, and the text of the record, as `devkmsg_write`.
/// The text stops at a null byte, as the `%s` of Linux.
pub fn parse(buf: &[u8]) -> (u16, &[u8]) {
    let buf = buf.split(|&b| b == 0).next().unwrap_or(buf);
    let mut level = DEFAULT_LEVEL;
    let mut facility = LOG_USER;
    let mut text = buf;
    if let Some(rest) = buf.strip_prefix(b"<") {
        let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        if rest.get(digits) == Some(&b'>') {
            // `simple_strtoul` gives an `unsigned long`, and Linux keeps the low 32 bits.
            let u = rest[..digits]
                .iter()
                .fold(0u64, |n, &d| n.wrapping_mul(10).wrapping_add(u64::from(d - b'0')))
                as u32;
            level = u & 7;
            if (u >> 3) & 0xff != 0 {
                facility = (u >> 3) & 0xff;
            }
            text = &rest[digits + 1..];
        }
    }
    (((facility << 3) | level) as u16, text)
}

/// Formats a record for a read, as `info_print_ext_header` and `msg_print_ext_body` of Linux. A
/// byte that cannot be printed and a backslash become `\xNN`.
pub fn format(rec: &LogRecord, text: &[u8]) -> Vec<u8> {
    let mut out = Out(Vec::with_capacity(text.len() + 32));
    let _ = write!(out, "{},{},{},-;", rec.prio, rec.seq, rec.ns / 1000);
    for &c in text {
        if !(b' '..127).contains(&c) || c == b'\\' {
            let _ = write!(out, "\\x{c:02x}");
        } else {
            out.0.push(c);
        }
    }
    out.0.push(b'\n');
    out.0
}

struct Out(Vec<u8>);

impl Write for Out {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// An open file of `/dev/kmsg`.
struct KmsgFile {
    /// The sequence number of the next record to read.
    seq: SpinLock<u64>,
}

impl KmsgFile {
    /// Reads the next record, if there is one.
    fn read_record(&self, buf: &mut [u8]) -> Option<Result<usize>> {
        let mut seq = self.seq.lock();
        let mut text = [0u8; RECORD_MAX];
        let rec = console::log_record(*seq, &mut text)?;
        if rec.seq != *seq {
            // The record is not in the ring now. Linux gives `EPIPE` one time and then reads the
            // first record that is still in the ring.
            *seq = rec.seq;
            return Some(Err(Errno::EPIPE));
        }
        *seq += 1;
        let out = format(&rec, &text[..rec.len.min(RECORD_MAX)]);
        if out.len() > buf.len() {
            return Some(Err(Errno::EINVAL));
        }
        buf[..out.len()].copy_from_slice(&out);
        Some(Ok(out.len()))
    }
}

impl FileOps for KmsgFile {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        loop {
            if let Some(result) = self.read_record(buf) {
                return result;
            }
            if file.nonblock() {
                return Err(Errno::EAGAIN);
            }
            if rk_vfs::wait::interrupted() {
                return Err(Errno::ERESTARTSYS);
            }
            #[cfg(target_os = "none")]
            let deadline = rk_frame::time::ticks() + 1;
            #[cfg(not(target_os = "none"))]
            let deadline = 0;
            let seq = *self.seq.lock();
            WAIT.wait_until_timeout(deadline, || (console::log_next_seq() > seq).then_some(()));
        }
    }

    fn write(&self, _file: &File, buf: &[u8]) -> Result<usize> {
        if buf.len() > RECORD_MAX {
            return Err(Errno::EINVAL);
        }
        let (prio, text) = parse(buf);
        console::log_emit(prio, text);
        WAIT.wake_all();
        Ok(buf.len())
    }

    fn llseek(&self, _file: &File, offset: i64, whence: Whence) -> Option<Result<u64>> {
        if offset != 0 {
            return Some(Err(Errno::ESPIPE));
        }
        let seq = match whence {
            Whence::Set => console::log_first_seq(),
            // The first record after the last clear, as `dmesg -c` makes it.
            Whence::Data => console::log_clear_seq(),
            Whence::End => console::log_next_seq(),
            _ => return Some(Err(Errno::EINVAL)),
        };
        *self.seq.lock() = seq;
        Some(Ok(0))
    }

    fn poll_wait(&self, _file: &File, table: &mut PollTable) {
        table.add_static(&WAIT);
    }

    fn poll(&self, _file: &File) -> u32 {
        let seq = *self.seq.lock();
        match console::log_record(seq, &mut []) {
            Some(rec) if rec.seq != seq => POLLIN | POLLRDNORM | POLLERR | POLLPRI,
            Some(_) => POLLIN | POLLRDNORM,
            None => 0,
        }
    }

    fn pollable(&self) -> bool {
        true
    }
}

/// The driver of `/dev/kmsg`.
struct Kmsg;

impl CharDevice for Kmsg {
    fn open(&self, _flags: u32) -> Result<Arc<dyn FileOps>> {
        // With `dmesg_restrict` at 0, as in Linux by default, each process can read the log.
        Ok(Arc::new(KmsgFile { seq: SpinLock::new(console::log_first_seq()) }))
    }
}

/// Adds `/dev/kmsg` to the table of character devices.
pub(crate) fn init() {
    device::register_char(KMSG_RDEV, Arc::new(Kmsg));
    WOKEN.store(console::log_next_seq(), Ordering::Relaxed);
    #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
    rk_frame::task::add_bottom_half(wake_readers);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_gives_the_level_and_the_facility() {
        assert_eq!(parse(b"run fstests\n"), (12, &b"run fstests\n"[..]));
        assert_eq!(parse(b"<3>disk error"), (11, &b"disk error"[..]));
        assert_eq!(parse(b"<30>daemon"), (30, &b"daemon"[..]));
        assert_eq!(parse(b"<>empty"), (8, &b"empty"[..]));
        assert_eq!(parse(b"<4 no"), (12, &b"<4 no"[..]));
        assert_eq!(parse(b"text\0more"), (12, &b"text"[..]));
    }

    #[test]
    fn a_kernel_record_wakes_the_readers() {
        wake_readers();
        let before = WOKEN.load(Ordering::Relaxed);
        console::log_emit(14, b"a record of the kernel");
        wake_readers();
        assert!(WOKEN.load(Ordering::Relaxed) > before);
    }

    #[test]
    fn format_escapes_the_text() {
        let rec = LogRecord { seq: 7, prio: 12, ns: 2_500_000_000, len: 0 };
        assert_eq!(format(&rec, b"a\\b\nc"), b"12,7,2500000,-;a\\x5cb\\x0ac\n");
    }

    #[test]
    fn write_and_read_a_record() {
        let file = KmsgFile { seq: SpinLock::new(console::log_next_seq()) };
        let ops: Arc<dyn FileOps> = Arc::new(KmsgFile { seq: SpinLock::new(0) });
        let f = File::with_ops(ops, None, rk_abi::native::open::O_RDWR);
        assert_eq!(file.write(&f, b"<6>hello\n"), Ok(9));
        let mut buf = [0u8; 64];
        let n = file.read_record(&mut buf).unwrap().unwrap();
        let line = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(line.starts_with("14,") && line.ends_with(",-;hello\n"), "{line}");
        assert_eq!(file.read_record(&mut buf[..4]), None);
    }
}

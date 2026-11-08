//! The line discipline N_TTY: the input and output processing of a terminal.
//!
//! The input processing changes the bytes from the device per the `termios` flags, edits the line
//! in canonical mode, echoes the bytes and finds the bytes that send a signal. The output
//! processing changes the bytes that a program writes, for example a line feed to a carriage
//! return and a line feed. This is drivers/tty/n_tty.c of Linux with the common flags only.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use rk_abi::native::signal::{SIGINT, SIGQUIT, SIGTSTP};
use rk_abi::native::termbits::{
    B0, B38400, BOTHER, CBAUD, CBAUDEX, CREAD, CS8, ECHO, ECHOCTL, ECHOE, ECHOK, ECHOKE, ECHONL,
    HUPCL, IBSHIFT, ICANON, ICRNL, IEXTEN, IGNCR, INLCR, ISIG, ISTRIP, IXON, NOFLSH, ONLCR, OPOST,
    VEOF, VEOL, VEOL2, VERASE, VINTR, VKILL, VMIN, VQUIT, VSUSP, VWERASE,
};
use rk_abi::native::types::{Termios, Termios2};

/// The most bytes that the line discipline keeps. Linux names it `N_TTY_BUF_SIZE`.
pub const BUF_SIZE: usize = 4096;

/// The `termios` of a new terminal, as `tty_std_termios` in Linux.
pub const fn default_termios() -> Termios {
    Termios {
        c_iflag: ICRNL | IXON,
        c_oflag: OPOST | ONLCR,
        c_cflag: B38400 | CS8 | CREAD | HUPCL,
        c_lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
        c_line: 0,
        // INTR ^C, QUIT ^\, ERASE DEL, KILL ^U, EOF ^D, TIME 0, MIN 1, SWTC 0, START ^Q, STOP ^S,
        // SUSP ^Z, EOL 0, REPRINT ^R, DISCARD ^O, WERASE ^W, LNEXT ^V, EOL2 0.
        c_cc: [3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0, 0, 0],
    }
}

/// The speed of a new terminal, as `tty_std_termios` in Linux.
const DEFAULT_SPEED: u32 = 38400;

/// The speeds of the values of `CBAUD`, as `baud_table` of drivers/tty/tty_baudrate.c of Linux.
/// The values with `CBAUDEX` come after `B38400`.
const BAUD_TABLE: [u32; 31] = [
    0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 38400, 57600,
    115_200, 230_400, 460_800, 500_000, 576_000, 921_600, 1_000_000, 1_152_000, 1_500_000,
    2_000_000, 2_500_000, 3_000_000, 3_500_000, 4_000_000,
];

/// Gives the speed of the value `cbaud` of `CBAUD`, or `other` for `BOTHER`, as
/// `tty_termios_baud_rate` of Linux.
fn baud_rate(cbaud: u32, other: u32) -> u32 {
    let cbaud = cbaud & CBAUD;
    if cbaud == BOTHER {
        return other;
    }
    let index = if cbaud & CBAUDEX != 0 { (cbaud & !CBAUDEX) + 15 } else { cbaud };
    BAUD_TABLE.get(index as usize).copied().unwrap_or(0)
}

/// The input and the line of one terminal.
#[derive(Clone, Debug)]
pub struct LineDiscipline {
    termios: Termios,
    /// The input and the output speed, `c_ispeed` and `c_ospeed` of `struct ktermios`.
    speeds: (u32, u32),
    /// The line that the user edits, in canonical mode.
    line: Vec<u8>,
    /// The lines that a read can take, in canonical mode. A line that `VEOF` ended has no line
    /// feed, and an empty one makes a read give 0.
    lines: VecDeque<Vec<u8>>,
    /// The bytes that a read can take, in non canonical mode.
    raw: VecDeque<u8>,
}

impl Default for LineDiscipline {
    fn default() -> Self {
        Self::new()
    }
}

/// Tells if `flag` is set in `flags`.
const fn has(flags: u32, flag: u32) -> bool {
    flags & flag != 0
}

impl LineDiscipline {
    /// Makes the line discipline of a new terminal.
    pub const fn new() -> Self {
        Self {
            termios: default_termios(),
            speeds: (DEFAULT_SPEED, DEFAULT_SPEED),
            line: Vec::new(),
            lines: VecDeque::new(),
            raw: VecDeque::new(),
        }
    }

    /// The `termios`, for `TCGETS`.
    pub fn termios(&self) -> Termios {
        self.termios
    }

    /// The `termios` with the speeds, for `TCGETS2`.
    pub fn termios2(&self) -> Termios2 {
        let t = self.termios;
        Termios2 {
            c_iflag: t.c_iflag,
            c_oflag: t.c_oflag,
            c_cflag: t.c_cflag,
            c_lflag: t.c_lflag,
            c_line: t.c_line,
            c_cc: t.c_cc,
            c_ispeed: self.speeds.0,
            c_ospeed: self.speeds.1,
        }
    }

    /// Sets the `termios` and the speeds, for `TCSETS2`.
    pub fn set_termios2(&mut self, t: Termios2) {
        let termios = Termios {
            c_iflag: t.c_iflag,
            c_oflag: t.c_oflag,
            c_cflag: t.c_cflag,
            c_lflag: t.c_lflag,
            c_line: t.c_line,
            c_cc: t.c_cc,
        };
        self.speeds = (t.c_ispeed, t.c_ospeed);
        self.set_termios(termios);
    }

    /// Sets the `termios`, for `TCSETS`. A change to non canonical mode gives the bytes of the
    /// line that the user edits to the reader. The speeds come from the `Bnnn` values of
    /// `c_cflag`, or stay for `BOTHER`, as `set_termios` in drivers/tty/tty_ioctl.c of Linux.
    pub fn set_termios(&mut self, termios: Termios) {
        let was_canon = self.canonical();
        let (ispeed, ospeed) = self.speeds;
        let ospeed = baud_rate(termios.c_cflag, ospeed);
        let input = (termios.c_cflag >> IBSHIFT) & CBAUD;
        let ispeed = if input == B0 { ospeed } else { baud_rate(input, ispeed) };
        self.speeds = (ispeed, ospeed);
        self.termios = termios;
        if was_canon && !self.canonical() {
            for line in self.lines.drain(..) {
                self.raw.extend(line);
            }
            self.raw.extend(self.line.drain(..));
        }
    }

    fn canonical(&self) -> bool {
        has(self.termios.c_lflag, ICANON)
    }

    fn cc(&self, index: u32) -> u8 {
        self.termios.c_cc[index as usize]
    }

    /// Tells if `b` is the control byte `index`. A control byte of 0 is off.
    fn is_cc(&self, b: u8, index: u32) -> bool {
        let c = self.cc(index);
        c != 0 && b == c
    }

    /// Removes the input that no reader took, for `TCFLSH` and a signal.
    pub fn flush_input(&mut self) {
        self.line.clear();
        self.lines.clear();
        self.raw.clear();
    }

    /// The number of bytes that a read can take now, for `FIONREAD`.
    pub fn available(&self) -> usize {
        if self.canonical() { self.lines.iter().map(Vec::len).sum() } else { self.raw.len() }
    }

    /// Tells if a read gives data or the end of the file now.
    pub fn readable(&self) -> bool {
        if self.canonical() {
            !self.lines.is_empty()
        } else {
            let min = usize::from(self.cc(VMIN)).max(1);
            self.raw.len() >= min
        }
    }

    fn len(&self) -> usize {
        self.line.len() + self.lines.iter().map(Vec::len).sum::<usize>() + self.raw.len()
    }

    /// Echoes `b` to `echo`. A control byte with `ECHOCTL` is `^` and a letter.
    fn echo_byte(&self, b: u8, echo: &mut Vec<u8>) {
        if has(self.termios.c_lflag, ECHOCTL) && b < 0x20 && b != b'\t' && b != b'\n' {
            echo.extend_from_slice(&[b'^', b + 0x40]);
        } else if b == 0x7f && has(self.termios.c_lflag, ECHOCTL) {
            echo.extend_from_slice(b"^?");
        } else {
            echo.push(b);
        }
    }

    /// Erases one byte of the line, and echoes the erase.
    fn erase(&mut self, echo: &mut Vec<u8>) -> bool {
        let Some(b) = self.line.pop() else { return false };
        if has(self.termios.c_lflag, ECHO) && has(self.termios.c_lflag, ECHOE) {
            let width =
                if has(self.termios.c_lflag, ECHOCTL) && (b < 0x20 || b == 0x7f) { 2 } else { 1 };
            for _ in 0..width {
                echo.extend_from_slice(b"\x08 \x08");
            }
        }
        true
    }

    /// Takes one byte from the device. The bytes to echo go to `echo`, before the output
    /// processing. Gives the signal to send to the foreground process group, if the byte is a
    /// signal byte.
    pub fn receive(&mut self, mut b: u8, echo: &mut Vec<u8>) -> Option<u32> {
        let iflag = self.termios.c_iflag;
        let lflag = self.termios.c_lflag;
        if has(iflag, ISTRIP) {
            b &= 0x7f;
        }
        if b == b'\r' {
            if has(iflag, IGNCR) {
                return None;
            }
            if has(iflag, ICRNL) {
                b = b'\n';
            }
        } else if b == b'\n' && has(iflag, INLCR) {
            b = b'\r';
        }
        if has(lflag, ISIG) {
            let sig = if self.is_cc(b, VINTR) {
                Some(SIGINT)
            } else if self.is_cc(b, VQUIT) {
                Some(SIGQUIT)
            } else if self.is_cc(b, VSUSP) {
                Some(SIGTSTP)
            } else {
                None
            };
            if let Some(sig) = sig {
                if !has(lflag, NOFLSH) {
                    self.flush_input();
                }
                if has(lflag, ECHO) {
                    self.echo_byte(b, echo);
                }
                return Some(sig);
            }
        }
        if self.canonical() {
            if self.is_cc(b, VERASE) {
                self.erase(echo);
                return None;
            }
            if self.is_cc(b, VWERASE) && has(lflag, IEXTEN) {
                while self.line.last().is_some_and(|c| c.is_ascii_whitespace()) {
                    self.erase(echo);
                }
                while self.line.last().is_some_and(|c| !c.is_ascii_whitespace()) {
                    self.erase(echo);
                }
                return None;
            }
            if self.is_cc(b, VKILL) {
                while self.erase(echo) {}
                return None;
            }
            if self.is_cc(b, VEOF) {
                self.lines.push_back(core::mem::take(&mut self.line));
                return None;
            }
            // Keep one byte free for the line feed that ends the line.
            let end = b == b'\n' || self.is_cc(b, VEOL) || self.is_cc(b, VEOL2);
            if !end && self.len() >= BUF_SIZE - 1 {
                return None;
            }
            if has(lflag, ECHO) || (b == b'\n' && has(lflag, ECHONL)) {
                self.echo_byte(b, echo);
            }
            self.line.push(b);
            if end {
                self.lines.push_back(core::mem::take(&mut self.line));
            }
            return None;
        }
        if self.raw.len() >= BUF_SIZE {
            return None;
        }
        if has(lflag, ECHO) {
            self.echo_byte(b, echo);
        }
        self.raw.push_back(b);
        None
    }

    /// Gives the bytes that a read takes, up to `buf.len()`. In canonical mode a read takes at
    /// most one line. Gives 0 at the end of the file.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }
        if self.canonical() {
            let Some(line) = self.lines.front_mut() else { return 0 };
            let n = line.len().min(buf.len());
            buf[..n].copy_from_slice(&line[..n]);
            line.drain(..n);
            if line.is_empty() {
                self.lines.pop_front();
            }
            n
        } else {
            let n = self.raw.len().min(buf.len());
            for (dst, src) in buf.iter_mut().zip(self.raw.drain(..n)) {
                *dst = src;
            }
            n
        }
    }

    /// Does the output processing of `data` and appends the result to `out`.
    pub fn process_output(&self, data: &[u8], out: &mut Vec<u8>) {
        let oflag = self.termios.c_oflag;
        if !has(oflag, OPOST) || !has(oflag, ONLCR) {
            out.extend_from_slice(data);
            return;
        }
        for &b in data {
            if b == b'\n' {
                out.push(b'\r');
            }
            out.push(b);
        }
    }
}

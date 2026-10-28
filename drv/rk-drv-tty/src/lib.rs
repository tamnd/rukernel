//! The terminals of rukernel.
//!
//! The serial console is the first terminal. `/dev/console` (5, 1), `/dev/tty` (5, 0) and
//! `/dev/ttyS0` (4, 64) open it. The line discipline does the input and output processing, per
//! spec/22-milestones.md item R1. The pseudo terminals of [`pty`] are the other terminals.
//!
//! R1 has no I/O APIC, so the serial port has no interrupt. The driver reads the serial port in
//! the bottom half of rk-frame instead, after each interrupt. The timer interrupts 250 times each
//! second, so the input comes in at most 4 ms, and `^C` stops a program that does not read.
//!
//! A terminal has a session, the session of the processes that have it as their controlling
//! terminal. A session has at most one controlling terminal, so the controlling terminal of a
//! process is the terminal with the session of the process.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod ldisc;
pub mod pty;

use alloc::sync::Arc;
use alloc::vec::Vec;
use ldisc::LineDiscipline;
use rk_abi::Errno;
use rk_abi::native::ioctls::{
    FIONREAD, TCFLSH, TCGETS, TCSBRK, TCSBRKP, TCSETS, TCSETSF, TCSETSW, TCXONC, TIOCGPGRP,
    TIOCGPTPEER, TIOCGSID, TIOCGWINSZ, TIOCNOTTY, TIOCSCTTY, TIOCSPGRP, TIOCSWINSZ,
};
use rk_abi::native::poll::{POLLIN, POLLOUT};
use rk_abi::native::termbits::{TCIFLUSH, TCIOFLUSH};
use rk_abi::native::types::{Termios, Winsize};
use rk_frame::sync::SpinLock;
use rk_vfs::device::{self, CharDevice, makedev};
use rk_vfs::inode::Result;
use rk_vfs::wait::PollTable;
use rk_vfs::{File, FileOps, UserMemory, WaitQueue};
use zerocopy::{FromZeros, IntoBytes};

/// The device number of `/dev/tty`, the controlling terminal of the caller.
pub const TTY_RDEV: u64 = makedev(5, 0);
/// The device number of `/dev/console`.
pub const CONSOLE_RDEV: u64 = makedev(5, 1);
/// The device number of `/dev/ttyS0`, the first serial port.
pub const TTYS0_RDEV: u64 = makedev(4, 64);

/// The state of a terminal.
struct Tty {
    ldisc: LineDiscipline,
    winsize: Winsize,
    /// The foreground process group, or 0.
    pgrp: u32,
    /// The session of the terminal, or 0.
    sid: u32,
}

impl Tty {
    /// The state of a new terminal.
    const fn new() -> Self {
        Self {
            ldisc: LineDiscipline::new(),
            winsize: Winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 },
            pgrp: 0,
            sid: 0,
        }
    }
}

static CONSOLE: SpinLock<Tty> = SpinLock::new(Tty::new());

/// The type of the function that sends a signal to a process group.
type SignalFn = fn(u32, u32);

/// The function that sends a signal to a process group. The process layer sets it.
static SIGNAL: SpinLock<Option<SignalFn>> = SpinLock::new(None);

/// Sets the function that sends the signal of a byte such as `^C` to the foreground process
/// group. Its arguments are the process group and the signal.
pub fn set_signal_handler(f: fn(u32, u32)) {
    *SIGNAL.lock() = Some(f);
}

/// Sends each signal of `signals` to its process group. A group of 0 gets no signal.
fn send_signals(signals: Vec<(u32, u32)>) {
    if signals.is_empty() {
        return;
    }
    let handler = *SIGNAL.lock();
    if let Some(send) = handler {
        for (pgrp, sig) in signals {
            if pgrp != 0 {
                send(pgrp, sig);
            }
        }
    }
}

/// The process that runs a terminal operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caller {
    /// The process ID.
    pub pid: u32,
    /// The process group ID.
    pub pgid: u32,
    /// The session ID.
    pub sid: u32,
}

impl Caller {
    /// Tells if the process is the leader of its session.
    fn leader(&self) -> bool {
        self.pid != 0 && self.pid == self.sid
    }
}

/// The function that gives the process that runs now. The process layer sets it.
static CALLER: SpinLock<Option<fn() -> Caller>> = SpinLock::new(None);

/// Sets the function that gives the process that runs now, for the controlling terminal.
pub fn set_caller_hook(f: fn() -> Caller) {
    *CALLER.lock() = Some(f);
}

/// The process that runs now. Without the hook it is the kernel, which has no session.
fn caller() -> Caller {
    let hook = *CALLER.lock();
    hook.map_or_else(Caller::default, |f| f())
}

/// Tells if the process that runs now has `CAP_SYS_ADMIN`.
fn admin() -> bool {
    rk_vfs::cred::current().capable(rk_vfs::cred::cap::SYS_ADMIN)
}

/// Tells if the session `sid` has a controlling terminal.
fn session_has_tty(sid: u32) -> bool {
    if sid == 0 {
        return false;
    }
    let console = CONSOLE.lock().sid;
    console == sid || pty::slave_has_session(sid)
}

/// Ends the controlling terminal of the session `sid` after the exit of its leader, as
/// `disassociate_ctty(1)` of Linux for a pseudo terminal: the foreground process group gets
/// `SIGHUP`, and the terminal has no session after it. The console stays with its session.
pub fn session_leader_exit(sid: u32) {
    send_signals(pty::end_session(sid));
}

/// The readers of the console wait here for input.
static INPUT_WAIT: WaitQueue = WaitQueue::new();

/// Makes `sid` the session and `pgrp` the foreground process group of the console. The kernel
/// calls it for init, which has the console as its controlling terminal.
pub fn set_console_session(sid: u32, pgrp: u32) {
    let mut tty = CONSOLE.lock();
    tty.sid = sid;
    tty.pgrp = pgrp;
}

/// Writes `data` to the console after the output processing.
fn console_write(tty: &Tty, data: &[u8]) {
    let mut out = Vec::with_capacity(data.len() + data.len() / 8);
    tty.ldisc.process_output(data, &mut out);
    rk_frame::console::write_bytes(&out);
}

/// Takes the bytes that came from the serial port, wakes the readers and gives each signal to
/// the process layer.
pub fn poll_input() {
    let mut signals = Vec::new();
    let mut received = false;
    {
        let mut tty = CONSOLE.lock();
        let mut echo = Vec::new();
        while let Some(b) = rk_frame::console::try_read_byte() {
            received = true;
            if let Some(sig) = tty.ldisc.receive(b, &mut echo) {
                signals.push((tty.pgrp, sig));
            }
        }
        if !echo.is_empty() {
            console_write(&tty, &echo);
        }
    }
    if received {
        INPUT_WAIT.wake_all();
    }
    send_signals(signals);
}

/// An open file of the console.
struct ConsoleFile;

impl FileOps for ConsoleFile {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        INPUT_WAIT.wait_interruptible(|| {
            poll_input();
            let mut tty = CONSOLE.lock();
            if tty.ldisc.readable() || buf.is_empty() {
                return Ok(Some(tty.ldisc.read(buf)));
            }
            if file.nonblock() {
                return Err(Errno::EAGAIN);
            }
            Ok(None)
        })
    }

    fn write(&self, _file: &File, buf: &[u8]) -> Result<usize> {
        poll_input();
        console_write(&CONSOLE.lock(), buf);
        Ok(buf.len())
    }

    fn ioctl(&self, _file: &File, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        let mut tty = CONSOLE.lock();
        match cmd {
            TCGETS => mem.write(arg, tty.ldisc.termios().as_bytes())?,
            TCSETS | TCSETSW | TCSETSF => {
                let mut t = Termios::new_zeroed();
                mem.read(arg, t.as_mut_bytes())?;
                if cmd == TCSETSF {
                    tty.ldisc.flush_input();
                }
                tty.ldisc.set_termios(t);
            }
            TIOCGWINSZ => mem.write(arg, tty.winsize.as_bytes())?,
            TIOCSWINSZ => {
                let mut w = Winsize::new_zeroed();
                mem.read(arg, w.as_mut_bytes())?;
                tty.winsize = w;
            }
            TIOCGPGRP => mem.write(arg, &tty.pgrp.to_ne_bytes())?,
            TIOCSPGRP => {
                let mut pgrp = [0u8; 4];
                mem.read(arg, &mut pgrp)?;
                let pgrp = i32::from_ne_bytes(pgrp);
                if pgrp < 0 {
                    return Err(Errno::EINVAL);
                }
                tty.pgrp = pgrp as u32;
            }
            TIOCGSID => {
                if tty.sid == 0 {
                    return Err(Errno::ENOTTY);
                }
                mem.write(arg, &tty.sid.to_ne_bytes())?;
            }
            FIONREAD => mem.write(arg, &(tty.ldisc.available() as i32).to_ne_bytes())?,
            TCFLSH => {
                if arg as u32 == TCIFLUSH || arg as u32 == TCIOFLUSH {
                    tty.ldisc.flush_input();
                }
            }
            TIOCSCTTY | TIOCNOTTY | TCSBRK | TCSBRKP | TCXONC => {}
            // Only the master of a pseudo terminal has a peer, as `ptm_open_peer` of Linux.
            TIOCGPTPEER => return Err(Errno::EIO),
            _ => return Err(Errno::ENOTTY),
        }
        Ok(0)
    }

    fn pollable(&self) -> bool {
        true
    }

    fn poll_wait(&self, _file: &File, table: &mut PollTable) {
        table.add_static(&INPUT_WAIT);
    }

    fn poll(&self, _file: &File) -> u32 {
        poll_input();
        let readable = CONSOLE.lock().ldisc.readable();
        if readable { POLLIN | POLLOUT } else { POLLOUT }
    }
}

struct ConsoleDevice;

impl CharDevice for ConsoleDevice {
    fn open(&self, _flags: u32) -> Result<Arc<dyn FileOps>> {
        Ok(Arc::new(ConsoleFile))
    }
}

/// The driver of `/dev/tty`, the controlling terminal of the caller, as
/// `tty_open_current_tty` of Linux. A process without a pseudo terminal as its controlling
/// terminal gets the console.
struct CurrentTtyDevice;

impl CharDevice for CurrentTtyDevice {
    fn open(&self, flags: u32) -> Result<Arc<dyn FileOps>> {
        match pty::open_ctty(caller().sid, flags) {
            Some(ops) => ops,
            None => Ok(Arc::new(ConsoleFile)),
        }
    }
}

/// Adds the console devices and `/dev/ptmx` to the table of character devices, and adds
/// `poll_input` to the bottom half.
pub fn init() {
    for rdev in [CONSOLE_RDEV, TTYS0_RDEV] {
        device::register_char(rdev, Arc::new(ConsoleDevice));
    }
    device::register_char(TTY_RDEV, Arc::new(CurrentTtyDevice));
    pty::init();
    #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
    rk_frame::task::add_bottom_half(poll_input);
}

#[cfg(test)]
mod tests;

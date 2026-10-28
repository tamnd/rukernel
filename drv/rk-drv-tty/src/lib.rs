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
//! process is the terminal with the session of the process. A process that left it with
//! `TIOCNOTTY` has no controlling terminal, as `proc_clear_tty` of Linux.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod ldisc;
pub mod netldisc;
pub mod pty;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use ldisc::LineDiscipline;
use rk_abi::Errno;
use rk_abi::native::ioctls::{
    FIONREAD, TCFLSH, TCGETS, TCSBRK, TCSBRKP, TCSETS, TCSETSF, TCSETSW, TCXONC, TIOCGPGRP,
    TIOCGPTPEER, TIOCGSID, TIOCGWINSZ, TIOCNOTTY, TIOCSCTTY, TIOCSPGRP, TIOCSWINSZ, TIOCVHANGUP,
};
use rk_abi::native::open::O_NOCTTY;
use rk_abi::native::poll::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM};
use rk_abi::native::signal::{SIGCONT, SIGHUP, SIGTTOU};
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

/// The functions of the process layer for the sessions of the terminals.
#[derive(Clone, Copy, Debug)]
pub struct SessionHooks {
    /// Sends the signal of its second argument to the leader of the session of its first
    /// argument, as `tty_signal_session_leader` of Linux does after a hang up.
    pub signal_leader: fn(u32, u32),
    /// The session of the process group of its argument, or `None` if no process has it, as
    /// `session_of_pgrp` of Linux.
    pub pgrp_session: fn(u32) -> Option<u32>,
    /// Makes the process that runs now leave the controlling terminal of its session, as
    /// `proc_clear_tty` of Linux.
    pub leave_ctty: fn(),
    /// Tells if the thread that runs now blocks or ignores `SIGTTOU`, as `is_ignored` of
    /// drivers/tty/tty_jobctrl.c of Linux.
    pub ttou_ignored: fn() -> bool,
    /// Tells if the process group of its argument is orphaned, as `is_current_pgrp_orphaned`
    /// of Linux: no member has a parent in another group of the same session.
    pub pgrp_orphaned: fn(u32) -> bool,
}

/// The functions of the process layer for the sessions. The process layer sets them.
static SESSION: SpinLock<Option<SessionHooks>> = SpinLock::new(None);

/// Sets the functions of the process layer for the sessions of the terminals.
pub fn set_session_hooks(hooks: SessionHooks) {
    *SESSION.lock() = Some(hooks);
}

/// The functions of the process layer for the sessions, if it set them.
fn session_hooks() -> Option<SessionHooks> {
    *SESSION.lock()
}

/// Sends `SIGHUP` and `SIGCONT` to the leader of the session `sid` after the hang up of its
/// controlling terminal, as `tty_signal_session_leader` of Linux. A session of 0 gets no signal.
fn hang_up_session(sid: u32) {
    if let Some(hooks) = session_hooks().filter(|_| sid != 0) {
        (hooks.signal_leader)(sid, SIGHUP);
        (hooks.signal_leader)(sid, SIGCONT);
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
    /// The process left the controlling terminal of its session with `TIOCNOTTY`.
    pub no_ctty: bool,
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

impl Tty {
    /// Tells if the terminal is the controlling terminal of `c`.
    fn is_ctty_of(&self, c: &Caller) -> bool {
        c.sid != 0 && self.sid == c.sid && !c.no_ctty
    }

    /// Takes the session from the terminal for a hang up, as `__tty_hangup` of Linux: the
    /// terminal has no session and no foreground process group after it, and its input goes
    /// away. Gives the session, for [`hang_up_session`].
    fn hang_up(&mut self) -> u32 {
        self.pgrp = 0;
        self.ldisc.flush_input();
        core::mem::take(&mut self.sid)
    }
}

/// Reads the argument of `TIOCSPGRP` and finds the session of the group, as `tiocspgrp` of Linux
/// does before its checks of the terminal. It runs before the lock of the terminal, because the
/// process layer takes its own locks. Gives the group and its session.
fn read_pgrp(mem: &dyn UserMemory, arg: usize) -> Result<(u32, Option<u32>)> {
    let mut v = [0u8; 4];
    mem.read(arg, &mut v)?;
    let pgrp = i32::from_ne_bytes(v);
    if pgrp < 0 {
        return Err(Errno::EINVAL);
    }
    let pgrp = pgrp as u32;
    Ok((pgrp, session_hooks().and_then(|h| (h.pgrp_session)(pgrp))))
}

/// Checks that the caller `c` can set the foreground process group of a terminal, as
/// `tty_check_change` of drivers/tty/tty_jobctrl.c of Linux. `is_ctty` tells if the terminal is
/// the controlling terminal of the caller, and `tty_pgrp` is its foreground process group. A
/// caller in a background group gets `SIGTTOU` for its group, and the call starts again after
/// the signal (`ERESTARTSYS`). A caller that blocks or ignores `SIGTTOU` can set it. A caller in
/// an orphaned group gets `ENOTTY`, as `tiocspgrp` changes the `EIO` of `tty_check_change`.
///
/// The caller does not hold the lock of the terminal, because the process layer takes its own
/// locks.
fn check_change(is_ctty: bool, tty_pgrp: u32, c: &Caller) -> Result<()> {
    if !is_ctty || tty_pgrp == 0 || c.pgid == tty_pgrp {
        return Ok(());
    }
    let Some(hooks) = session_hooks() else { return Ok(()) };
    if (hooks.ttou_ignored)() {
        return Ok(());
    }
    if (hooks.pgrp_orphaned)(c.pgid) {
        return Err(Errno::ENOTTY);
    }
    send_signals(alloc::vec![(c.pgid, SIGTTOU)]);
    Err(Errno::ERESTARTSYS)
}

/// `TIOCSPGRP` on `tty`, as `tiocspgrp` of Linux. The terminal must be the controlling terminal
/// of the caller, and the group `pgrp` with the session `session` must be in the session of the
/// caller. Gives `ENOTTY`, `ESRCH` for a group that no process has, or `EPERM`.
fn set_pgrp(tty: &mut Tty, c: &Caller, (pgrp, session): (u32, Option<u32>)) -> Result<()> {
    if !tty.is_ctty_of(c) {
        return Err(Errno::ENOTTY);
    }
    if session.ok_or(Errno::ESRCH)? != c.sid {
        return Err(Errno::EPERM);
    }
    tty.pgrp = pgrp;
    Ok(())
}

/// `TIOCSCTTY` on `tty`: the terminal becomes the controlling terminal of the session of the
/// caller `c`, as `tiocsctty` of Linux. The caller must be a session leader without a
/// controlling terminal (`has_tty` is false). A terminal of another session needs `arg` 1 and
/// `CAP_SYS_ADMIN`, and then the other session loses it. A file that is not open for a read needs
/// `CAP_SYS_ADMIN`.
fn set_ctty(tty: &mut Tty, c: &Caller, has_tty: bool, file: &File, arg: usize) -> Result<usize> {
    if c.leader() && tty.sid == c.sid {
        return Ok(0);
    }
    if !c.leader() || has_tty {
        return Err(Errno::EPERM);
    }
    let admin = admin();
    if tty.sid != 0 && !(arg == 1 && admin) {
        return Err(Errno::EPERM);
    }
    if !file.flags().readable() && !admin {
        return Err(Errno::EPERM);
    }
    tty.sid = c.sid;
    tty.pgrp = c.pgid;
    Ok(0)
}

/// `TIOCNOTTY` on `tty`, as `tiocnotty` of Linux. The terminal must be the controlling terminal
/// of the caller, else the result is `ENOTTY`. For a session leader the foreground process group
/// gets `SIGHUP` and `SIGCONT`, and the terminal has no session after it, as
/// `disassociate_ctty(0)`. Another process leaves the terminal, and the terminal stays with the
/// session. Gives the signals.
fn leave_ctty(tty: &mut Tty, c: &Caller) -> Result<Vec<(u32, u32)>> {
    if !tty.is_ctty_of(c) {
        return Err(Errno::ENOTTY);
    }
    if !c.leader() {
        return Ok(Vec::new());
    }
    let pgrp = core::mem::take(&mut tty.pgrp);
    tty.sid = 0;
    Ok(alloc::vec![(pgrp, SIGHUP), (pgrp, SIGCONT)])
}

/// Ends `TIOCNOTTY` after the lock of the terminal: sends the signals of [`leave_ctty`], and a
/// process that is not the session leader leaves the controlling terminal.
fn finish_leave_ctty(c: &Caller, signals: Vec<(u32, u32)>) {
    send_signals(signals);
    if !c.leader()
        && let Some(hooks) = session_hooks()
    {
        (hooks.leave_ctty)();
    }
}

/// The poll events of a file after a hang up, as `hung_up_tty_poll` of Linux. After a hang up a
/// read gives the end of the file, and a write gives `EIO`.
const HUNG_POLL: u32 = POLLIN | POLLOUT | POLLERR | POLLHUP | POLLRDNORM | POLLWRNORM;

/// The result of an ioctl after a hang up, as `hung_up_tty_ioctl` of Linux.
fn hung_ioctl(cmd: u32) -> Result<usize> {
    Err(if cmd == TIOCSPGRP { Errno::ENOTTY } else { Errno::EIO })
}

/// `TIOCVHANGUP` needs `CAP_SYS_ADMIN`, as `tty_ioctl` of Linux.
fn check_vhangup() -> Result<()> {
    if admin() { Ok(()) } else { Err(Errno::EPERM) }
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

/// The number of hang ups of the console. A file of the console from before a hang up is hung up.
static CONSOLE_HANGUPS: AtomicU64 = AtomicU64::new(0);

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
struct ConsoleFile {
    /// The number of hang ups of the console at the open.
    hangups: u64,
}

impl ConsoleFile {
    fn new() -> Arc<Self> {
        Arc::new(Self { hangups: CONSOLE_HANGUPS.load(Ordering::Acquire) })
    }

    /// Tells if the console had a hang up after the open of the file.
    fn hung(&self) -> bool {
        CONSOLE_HANGUPS.load(Ordering::Acquire) != self.hangups
    }
}

impl FileOps for ConsoleFile {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        INPUT_WAIT.wait_interruptible(|| {
            if self.hung() {
                return Ok(Some(0));
            }
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
        if self.hung() {
            return Err(Errno::EIO);
        }
        poll_input();
        console_write(&CONSOLE.lock(), buf);
        Ok(buf.len())
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        if self.hung() {
            return hung_ioctl(cmd);
        }
        let c = caller();
        match cmd {
            TIOCSCTTY => {
                // The search takes the lock of the console, so it comes first.
                let has_tty = session_has_tty(c.sid);
                return set_ctty(&mut CONSOLE.lock(), &c, has_tty, file, arg);
            }
            TIOCNOTTY => {
                let signals = leave_ctty(&mut CONSOLE.lock(), &c)?;
                finish_leave_ctty(&c, signals);
                return Ok(0);
            }
            TIOCSPGRP => {
                let (is_ctty, tty_pgrp) = {
                    let tty = CONSOLE.lock();
                    (tty.is_ctty_of(&c), tty.pgrp)
                };
                check_change(is_ctty, tty_pgrp, &c)?;
                let pgrp = read_pgrp(mem, arg)?;
                set_pgrp(&mut CONSOLE.lock(), &c, pgrp)?;
                return Ok(0);
            }
            // The hang up of the console, as `tty_vhangup`: each open file of the console is hung
            // up, and the leader of its session gets `SIGHUP` and `SIGCONT`. A new open works.
            TIOCVHANGUP => {
                check_vhangup()?;
                let sid = {
                    let mut tty = CONSOLE.lock();
                    CONSOLE_HANGUPS.fetch_add(1, Ordering::AcqRel);
                    tty.hang_up()
                };
                INPUT_WAIT.wake_all();
                hang_up_session(sid);
                return Ok(0);
            }
            _ => {}
        }
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
            // The process group and the session are only for a process with the console as its
            // controlling terminal, as `tiocgpgrp` and `tiocgsid` of Linux.
            TIOCGPGRP | TIOCGSID if !tty.is_ctty_of(&c) => return Err(Errno::ENOTTY),
            TIOCGPGRP => mem.write(arg, &tty.pgrp.to_ne_bytes())?,
            TIOCGSID => mem.write(arg, &tty.sid.to_ne_bytes())?,
            FIONREAD => mem.write(arg, &(tty.ldisc.available() as i32).to_ne_bytes())?,
            TCFLSH => {
                if arg as u32 == TCIFLUSH || arg as u32 == TCIOFLUSH {
                    tty.ldisc.flush_input();
                }
            }
            TCSBRK | TCSBRKP | TCXONC => {}
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
        if self.hung() {
            return HUNG_POLL;
        }
        poll_input();
        let readable = CONSOLE.lock().ldisc.readable();
        if readable { POLLIN | POLLOUT } else { POLLOUT }
    }
}

/// The driver of the console.
struct ConsoleDevice {
    /// The console can become the controlling terminal at an open through this device. The open
    /// of `/dev/console` does not set it, as `tty_open` of Linux.
    ctty: bool,
}

impl CharDevice for ConsoleDevice {
    /// Without `O_NOCTTY`, the console becomes the controlling terminal of a session leader
    /// without one, if the console has no session, as `tty_open_proc_set_tty` of Linux.
    fn open(&self, flags: u32) -> Result<Arc<dyn FileOps>> {
        let c = caller();
        if self.ctty && flags & O_NOCTTY == 0 && c.leader() && !session_has_tty(c.sid) {
            let mut tty = CONSOLE.lock();
            if tty.sid == 0 {
                tty.sid = c.sid;
                tty.pgrp = c.pgid;
            }
        }
        Ok(ConsoleFile::new())
    }
}

/// The driver of `/dev/tty`, the controlling terminal of the caller, as
/// `tty_open_current_tty` of Linux. A process without a controlling terminal gets `ENXIO`.
struct CurrentTtyDevice;

impl CharDevice for CurrentTtyDevice {
    fn open(&self, flags: u32) -> Result<Arc<dyn FileOps>> {
        let c = caller();
        if CONSOLE.lock().is_ctty_of(&c) {
            return Ok(ConsoleFile::new());
        }
        pty::open_ctty(&c, flags).unwrap_or(Err(Errno::ENXIO))
    }
}

/// Adds the console devices and `/dev/ptmx` to the table of character devices, and adds
/// `poll_input` to the bottom half.
pub fn init() {
    device::register_char(CONSOLE_RDEV, Arc::new(ConsoleDevice { ctty: false }));
    device::register_char(TTYS0_RDEV, Arc::new(ConsoleDevice { ctty: true }));
    device::register_char(TTY_RDEV, Arc::new(CurrentTtyDevice));
    pty::init();
    #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
    rk_frame::task::add_bottom_half(poll_input);
}

#[cfg(test)]
mod tests;

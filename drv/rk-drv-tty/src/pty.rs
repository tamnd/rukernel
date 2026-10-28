//! The Unix 98 pseudo terminals: `/dev/ptmx`, the master side, and devpts, which has the slave
//! side, as drivers/tty/pty.c and fs/devpts/inode.c of Linux.
//!
//! Each open of `/dev/ptmx` makes a new pair. The master file is the open file of `/dev/ptmx`.
//! The slave is the character device (136, N) and has the file `N` in devpts, which is mounted on
//! `/dev/pts`. A new slave is locked: it opens only after `TIOCSPTLCK` with 0 on the master.
//!
//! The data that the master writes goes through the line discipline of the slave, as the input
//! of a terminal. The data that the slave writes goes through the output processing of the slave
//! and to the master. The `termios` and the window size of a pair are those of the slave, and
//! the ioctls of the master change them, as `tty_mode_ioctl` of Linux with `tty->link`.
//!
//! There is one devpts instance. Each mount of devpts shows it, as the mount option `newinstance`
//! was not given.

use crate::{Tty, send_signals};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::ioctls::{
    FIONREAD, TCFLSH, TCGETA, TCGETS, TCSBRK, TCSBRKP, TCSETA, TCSETAF, TCSETAW, TCSETS, TCSETSF,
    TCSETSW, TCXONC, TIOCGETD, TIOCGPGRP, TIOCGPKT, TIOCGPTLCK, TIOCGPTN, TIOCGSID, TIOCGWINSZ,
    TIOCNOTTY, TIOCOUTQ, TIOCPKT, TIOCPKT_DATA, TIOCSCTTY, TIOCSETD, TIOCSPGRP, TIOCSPTLCK,
    TIOCSWINSZ,
};
use rk_abi::native::poll::{POLLHUP, POLLIN, POLLOUT};
use rk_abi::native::signal::SIGWINCH;
use rk_abi::native::termbits::{TCIFLUSH, TCIOFLUSH, TCOFLUSH};
use rk_abi::native::types::{Termio, Termios, Winsize};
use rk_frame::sync::{Once, SpinLock};
use rk_vfs::device::{self, CharDevice, makedev};
use rk_vfs::fstype::{FsType, MountArgs};
use rk_vfs::inode::{FileType, InodeRef, Result};
use rk_vfs::wait::PollTable;
use rk_vfs::{File, FileOps, UserMemory, WaitQueue};
use zerocopy::{FromZeros, IntoBytes};

/// The device number of `/dev/ptmx`.
pub const PTMX_RDEV: u64 = makedev(5, 2);
/// The major number of the slaves, `UNIX98_PTY_SLAVE_MAJOR` of Linux.
pub const SLAVE_MAJOR: u32 = 136;
/// The most pairs at the same time, the default of `kernel.pty.max` of Linux.
pub const MAX_PAIRS: u32 = 4096;
/// The most bytes that wait for the master to read them. Linux has a buffer of about 64 KiB in
/// the TTY port of the master.
const MASTER_BUF: usize = 64 * 1024;
/// The permission bits of a slave file, the default `mode=0600` of devpts.
const SLAVE_PERM: u32 = 0o600;

/// The file system type for `mount -t devpts`.
pub const DEVPTS: FsType = FsType { name: "devpts", nodev: true, make: mount_devpts };

/// The root directory of devpts.
fn devpts_root() -> &'static InodeRef {
    static ROOT: Once<InodeRef> = Once::new();
    ROOT.call_once(|| {
        let root = rk_fs_tmpfs::new(0o755);
        // devpts has its own `ptmx` with the mode 0, as `mknod_ptmx` of Linux.
        let _ = root.create(b"ptmx", FileType::CharDevice, 0, PTMX_RDEV);
        root
    })
}

/// Gives the root of devpts for `mount(2)`. The options have no effect.
fn mount_devpts(_args: &MountArgs<'_>) -> Result<InodeRef> {
    Ok(devpts_root().clone())
}

/// The state of a pair.
struct PairState {
    /// The terminal of the slave.
    tty: Tty,
    /// The bytes that the slave wrote and that the master did not read yet.
    to_master: VecDeque<u8>,
    /// `TIOCSPTLCK`: the slave does not open.
    locked: bool,
    /// `TIOCPKT`: each read of the master starts with a status byte.
    packet: bool,
    /// The master file is open.
    master_open: bool,
    /// The number of open files of the slave.
    slave_opens: usize,
    /// The slave was open and each of its files is closed now, `TTY_OTHER_CLOSED` of the master.
    slave_closed: bool,
}

/// A pair of a master and a slave.
struct Pair {
    index: u32,
    state: SpinLock<PairState>,
    /// The readers and the writers of both sides wait here.
    wait: Arc<WaitQueue>,
}

/// The pairs, by their index.
static PAIRS: SpinLock<BTreeMap<u32, Arc<Pair>>> = SpinLock::new(BTreeMap::new());

/// The name of the slave file of `index` in devpts.
fn slave_name(index: u32) -> Vec<u8> {
    format!("{index}").into_bytes()
}

/// Makes a new pair, as `ptmx_open` of Linux. Gives `ENOSPC` when there are `MAX_PAIRS` pairs.
fn open_pair() -> Result<Arc<Pair>> {
    let pair = {
        let mut pairs = PAIRS.lock();
        // The smallest free index, as the IDA of devpts.
        let index = (0..MAX_PAIRS).find(|i| !pairs.contains_key(i)).ok_or(Errno::ENOSPC)?;
        let pair = Arc::new(Pair {
            index,
            state: SpinLock::new(PairState {
                tty: Tty::new(),
                to_master: VecDeque::new(),
                locked: true,
                packet: false,
                master_open: true,
                slave_opens: 0,
                slave_closed: false,
            }),
            wait: Arc::new(WaitQueue::new()),
        });
        pairs.insert(index, pair.clone());
        pair
    };
    let rdev = makedev(SLAVE_MAJOR, pair.index);
    device::register_char(rdev, Arc::new(SlaveDevice { index: pair.index }));
    let name = slave_name(pair.index);
    if let Err(e) = devpts_root().create(&name, FileType::CharDevice, SLAVE_PERM, rdev) {
        close_master(&pair);
        return Err(e);
    }
    Ok(pair)
}

/// Removes the pair after the close of the master, as `pty_close` and `devpts_pty_kill` of
/// Linux. The open files of the slave stay, and they get a hang up.
fn close_master(pair: &Pair) {
    pair.state.lock().master_open = false;
    let _ = devpts_root().unlink(&slave_name(pair.index));
    device::unregister_char(makedev(SLAVE_MAJOR, pair.index));
    PAIRS.lock().remove(&pair.index);
    pair.wait.wake_all();
}

/// Gives the input `data` to the line discipline of the slave, as a write to the master. The
/// echo goes back to the master. Gives the signals for the foreground process group.
fn receive(st: &mut PairState, data: &[u8]) -> Vec<(u32, u32)> {
    let mut signals = Vec::new();
    let mut echo = Vec::new();
    for &b in data {
        if let Some(sig) = st.tty.ldisc.receive(b, &mut echo) {
            signals.push((st.tty.pgrp, sig));
        }
    }
    if !echo.is_empty() {
        let mut out = Vec::with_capacity(echo.len());
        st.tty.ldisc.process_output(&echo, &mut out);
        st.to_master.extend(out);
    }
    signals
}

/// Runs an ioctl of the terminal on the pair, from either side. Gives `None` for a command that
/// the terminal does not have. `master` tells the side of `TCFLSH` and `FIONREAD`.
fn tty_ioctl(
    pair: &Pair,
    master: bool,
    cmd: u32,
    arg: usize,
    mem: &dyn UserMemory,
) -> Option<Result<usize>> {
    let mut signals = Vec::new();
    let r = (|| {
        let mut st = pair.state.lock();
        match cmd {
            TCGETS => mem.write(arg, st.tty.ldisc.termios().as_bytes())?,
            TCSETS | TCSETSW | TCSETSF => {
                let mut t = Termios::new_zeroed();
                mem.read(arg, t.as_mut_bytes())?;
                if cmd == TCSETSF {
                    st.tty.ldisc.flush_input();
                }
                st.tty.ldisc.set_termios(t);
            }
            TCGETA => mem.write(arg, to_termio(&st.tty.ldisc.termios()).as_bytes())?,
            TCSETA | TCSETAW | TCSETAF => {
                let mut t = Termio::new_zeroed();
                mem.read(arg, t.as_mut_bytes())?;
                if cmd == TCSETAF {
                    st.tty.ldisc.flush_input();
                }
                let t = from_termio(&st.tty.ldisc.termios(), &t);
                st.tty.ldisc.set_termios(t);
            }
            TIOCGWINSZ => mem.write(arg, st.tty.winsize.as_bytes())?,
            TIOCSWINSZ => {
                let mut w = Winsize::new_zeroed();
                mem.read(arg, w.as_mut_bytes())?;
                // A new size sends `SIGWINCH` to the foreground group, as `tty_do_resize`.
                if w.as_bytes() != st.tty.winsize.as_bytes() && st.tty.pgrp != 0 {
                    signals.push((st.tty.pgrp, SIGWINCH));
                }
                st.tty.winsize = w;
            }
            TIOCGPGRP => mem.write(arg, &st.tty.pgrp.to_ne_bytes())?,
            TIOCSPGRP => {
                let mut pgrp = [0u8; 4];
                mem.read(arg, &mut pgrp)?;
                let pgrp = i32::from_ne_bytes(pgrp);
                if pgrp < 0 {
                    return Err(Errno::EINVAL);
                }
                st.tty.pgrp = pgrp as u32;
            }
            TIOCGSID => {
                if st.tty.sid == 0 {
                    return Err(Errno::ENOTTY);
                }
                mem.write(arg, &st.tty.sid.to_ne_bytes())?;
            }
            FIONREAD => {
                let n = if master { st.to_master.len() } else { st.tty.ldisc.available() };
                mem.write(arg, &(n as i32).to_ne_bytes())?;
            }
            TIOCOUTQ => {
                let n = if master { 0 } else { st.to_master.len() };
                mem.write(arg, &(n as i32).to_ne_bytes())?;
            }
            TCFLSH => {
                let how = arg as u32;
                if how != TCIFLUSH && how != TCOFLUSH && how != TCIOFLUSH {
                    return Err(Errno::EINVAL);
                }
                // The input of the master is the output of the slave.
                let (input, output) = (how != TCOFLUSH, how != TCIFLUSH);
                if (master && input) || (!master && output) {
                    st.to_master.clear();
                }
                if (master && output) || (!master && input) {
                    st.tty.ldisc.flush_input();
                }
            }
            // Only the line discipline `N_TTY` (0) is in the kernel. Linux gives `EINVAL` for a
            // line discipline that has no module, as `tty_ldisc_get`.
            TIOCGETD => mem.write(arg, &0i32.to_ne_bytes())?,
            TIOCSETD => {
                if read_int(mem, arg)? != 0 {
                    return Err(Errno::EINVAL);
                }
            }
            TIOCSCTTY | TIOCNOTTY | TCSBRK | TCSBRKP | TCXONC => {}
            _ => return Ok(None),
        }
        Ok(Some(0))
    })();
    send_signals(signals);
    r.transpose()
}

/// The `termio` of `t`, as `kernel_termios_to_user_termio` of Linux.
fn to_termio(t: &Termios) -> Termio {
    let mut o = Termio::new_zeroed();
    o.c_iflag = t.c_iflag as u16;
    o.c_oflag = t.c_oflag as u16;
    o.c_cflag = t.c_cflag as u16;
    o.c_lflag = t.c_lflag as u16;
    o.c_line = t.c_line;
    let n = o.c_cc.len();
    o.c_cc.copy_from_slice(&t.c_cc[..n]);
    o
}

/// The `termios` of `old` with the values of `t`, as `user_termio_to_kernel_termios` of Linux.
/// The high 16 bits of the flags and the control bytes after the eighth stay.
fn from_termio(old: &Termios, t: &Termio) -> Termios {
    let mut n = *old;
    n.c_iflag = (old.c_iflag & 0xffff_0000) | u32::from(t.c_iflag);
    n.c_oflag = (old.c_oflag & 0xffff_0000) | u32::from(t.c_oflag);
    n.c_cflag = (old.c_cflag & 0xffff_0000) | u32::from(t.c_cflag);
    n.c_lflag = (old.c_lflag & 0xffff_0000) | u32::from(t.c_lflag);
    n.c_line = t.c_line;
    n.c_cc[..t.c_cc.len()].copy_from_slice(&t.c_cc);
    n
}

/// Reads an `int` argument of an ioctl.
fn read_int(mem: &dyn UserMemory, arg: usize) -> Result<i32> {
    let mut v = [0u8; 4];
    mem.read(arg, &mut v)?;
    Ok(i32::from_ne_bytes(v))
}

/// The open file of the master, an open file of `/dev/ptmx`.
struct MasterFile {
    pair: Arc<Pair>,
}

impl Drop for MasterFile {
    fn drop(&mut self) {
        close_master(&self.pair);
    }
}

impl FileOps for MasterFile {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        let pair = &self.pair;
        let n = pair.wait.wait_interruptible(|| {
            let mut st = pair.state.lock();
            if buf.is_empty() {
                return Ok(Some(0));
            }
            if !st.to_master.is_empty() {
                // In packet mode the data comes after the status byte `TIOCPKT_DATA`.
                let skip = usize::from(st.packet);
                if skip == 1 {
                    buf[0] = TIOCPKT_DATA as u8;
                }
                let n = st.to_master.len().min(buf.len() - skip);
                for (dst, src) in buf[skip..].iter_mut().zip(st.to_master.drain(..n)) {
                    *dst = src;
                }
                return Ok(Some(n + skip));
            }
            // The slave hung up: the data is all read, as `n_tty_read` with
            // `TTY_OTHER_CLOSED`.
            if st.slave_closed {
                return Err(Errno::EIO);
            }
            if file.nonblock() {
                return Err(Errno::EAGAIN);
            }
            Ok(None)
        })?;
        pair.wait.wake_all();
        Ok(n)
    }

    fn write(&self, _file: &File, buf: &[u8]) -> Result<usize> {
        let signals = {
            let mut st = self.pair.state.lock();
            receive(&mut st, buf)
        };
        send_signals(signals);
        self.pair.wait.wake_all();
        Ok(buf.len())
    }

    fn ioctl(&self, _file: &File, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        let pair = &self.pair;
        match cmd {
            TIOCGPTN => mem.write(arg, &pair.index.to_ne_bytes())?,
            TIOCSPTLCK => {
                let v = read_int(mem, arg)?;
                pair.state.lock().locked = v != 0;
            }
            TIOCGPTLCK => {
                let v = i32::from(pair.state.lock().locked);
                mem.write(arg, &v.to_ne_bytes())?;
            }
            TIOCPKT => {
                let v = read_int(mem, arg)?;
                pair.state.lock().packet = v != 0;
            }
            TIOCGPKT => {
                let v = i32::from(pair.state.lock().packet);
                mem.write(arg, &v.to_ne_bytes())?;
            }
            _ => return tty_ioctl(pair, true, cmd, arg, mem).unwrap_or(Err(Errno::ENOTTY)),
        }
        Ok(0)
    }

    fn pollable(&self) -> bool {
        true
    }

    fn poll_wait(&self, _file: &File, table: &mut PollTable) {
        table.add(&self.pair.wait);
    }

    fn poll(&self, _file: &File) -> u32 {
        let st = self.pair.state.lock();
        let mut events = POLLOUT;
        if !st.to_master.is_empty() {
            events |= POLLIN;
        }
        if st.slave_closed {
            events |= POLLIN | POLLHUP;
        }
        events
    }
}

/// The open file of a slave.
struct SlaveFile {
    pair: Arc<Pair>,
}

impl Drop for SlaveFile {
    fn drop(&mut self) {
        {
            let mut st = self.pair.state.lock();
            st.slave_opens -= 1;
            if st.slave_opens == 0 {
                st.slave_closed = true;
            }
        }
        self.pair.wait.wake_all();
    }
}

impl FileOps for SlaveFile {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        let pair = &self.pair;
        let n = pair.wait.wait_interruptible(|| {
            let mut st = pair.state.lock();
            if st.tty.ldisc.readable() || buf.is_empty() {
                return Ok(Some(st.tty.ldisc.read(buf)));
            }
            // A read after the hang up gives the end of the file, as `hung_up_tty_read`.
            if !st.master_open {
                return Ok(Some(0));
            }
            if file.nonblock() {
                return Err(Errno::EAGAIN);
            }
            Ok(None)
        })?;
        pair.wait.wake_all();
        Ok(n)
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize> {
        let pair = &self.pair;
        pair.wait.wait_interruptible(|| {
            let mut st = pair.state.lock();
            if !st.master_open {
                return Err(Errno::EIO);
            }
            if st.to_master.len() < MASTER_BUF {
                let mut out = Vec::with_capacity(buf.len() + buf.len() / 8);
                st.tty.ldisc.process_output(buf, &mut out);
                st.to_master.extend(out);
                return Ok(Some(()));
            }
            if file.nonblock() {
                return Err(Errno::EAGAIN);
            }
            Ok(None)
        })?;
        pair.wait.wake_all();
        Ok(buf.len())
    }

    fn ioctl(&self, _file: &File, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        tty_ioctl(&self.pair, false, cmd, arg, mem).unwrap_or(Err(Errno::ENOTTY))
    }

    fn pollable(&self) -> bool {
        true
    }

    fn poll_wait(&self, _file: &File, table: &mut PollTable) {
        table.add(&self.pair.wait);
    }

    fn poll(&self, _file: &File) -> u32 {
        let st = self.pair.state.lock();
        if !st.master_open {
            return POLLIN | POLLOUT | POLLHUP;
        }
        let mut events = 0;
        if st.tty.ldisc.readable() {
            events |= POLLIN;
        }
        if st.to_master.len() < MASTER_BUF {
            events |= POLLOUT;
        }
        events
    }
}

/// The driver of `/dev/ptmx`.
struct PtmxDevice;

impl CharDevice for PtmxDevice {
    fn open(&self, _flags: u32) -> Result<Arc<dyn FileOps>> {
        Ok(Arc::new(MasterFile { pair: open_pair()? }))
    }
}

/// The driver of the slave of one pair.
struct SlaveDevice {
    index: u32,
}

impl CharDevice for SlaveDevice {
    fn open(&self, _flags: u32) -> Result<Arc<dyn FileOps>> {
        let pair = PAIRS.lock().get(&self.index).cloned().ok_or(Errno::EIO)?;
        {
            let mut st = pair.state.lock();
            // A locked slave does not open, as `pty_unix98_install` and `tty_open`.
            if st.locked || !st.master_open {
                return Err(Errno::EIO);
            }
            st.slave_opens += 1;
            st.slave_closed = false;
        }
        Ok(Arc::new(SlaveFile { pair }))
    }
}

/// Adds `/dev/ptmx` to the table of character devices.
pub fn init() {
    device::register_char(PTMX_RDEV, Arc::new(PtmxDevice));
}

#[cfg(test)]
pub(crate) fn open_ptmx() -> Result<Arc<dyn FileOps>> {
    PtmxDevice.open(0)
}

#[cfg(test)]
pub(crate) fn open_slave(index: u32) -> Result<Arc<dyn FileOps>> {
    device::open_char(makedev(SLAVE_MAJOR, index), 0)
}

#[cfg(test)]
pub(crate) fn slave_exists(index: u32) -> bool {
    devpts_root().lookup(&slave_name(index)).is_ok()
}

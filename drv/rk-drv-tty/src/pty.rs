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
//! Each mount of devpts is a new instance, as `get_tree_nodev` of Linux. An instance has its
//! own slaves and its own numbers, and the option `newinstance` has no effect. An open of
//! `/dev/ptmx` uses the instance on `pts` in the same directory, as `devpts_acquire`, and an
//! open of the `ptmx` file of devpts uses its own instance. The open of a slave finds the pair
//! through the file in devpts, as `devpts_get_priv`, so a slave device file out of devpts does
//! not open.
//!
//! `TIOCSETD` on the slave sets the line discipline of the slave. `N_SLIP` and `N_SLCAN` make a
//! network device, as [`crate::netldisc`] tells. The data that the master writes then goes to the
//! device, and the frames that the device sends go to the master.

use crate::netldisc::{LineOut, N_TTY, NR_LDISCS, NetLine, Proto};
use crate::{
    Caller, HUNG_POLL, Tty, caller, check_change, check_vhangup, finish_leave_ctty,
    hang_up_session, hung_ioctl, leave_ctty, read_pgrp, send_signals, session_has_tty, set_ctty,
    set_pgrp,
};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use rk_abi::Errno;
use rk_abi::native::ioctls::{
    FIONREAD, TCFLSH, TCGETA, TCGETS, TCSBRK, TCSBRKP, TCSETA, TCSETAF, TCSETAW, TCSETS, TCSETSF,
    TCSETSW, TCXONC, TIOCGETD, TIOCGPGRP, TIOCGPKT, TIOCGPTLCK, TIOCGPTN, TIOCGPTPEER, TIOCGSID,
    TIOCGWINSZ, TIOCNOTTY, TIOCOUTQ, TIOCPKT, TIOCPKT_DATA, TIOCSCTTY, TIOCSETD, TIOCSPGRP,
    TIOCSPTLCK, TIOCSWINSZ, TIOCVHANGUP,
};
use rk_abi::native::open::{O_CLOEXEC, O_CREAT, O_EXCL, O_NOCTTY, O_TRUNC};
use rk_abi::native::poll::{POLLHUP, POLLIN, POLLOUT};
use rk_abi::native::signal::{SIGHUP, SIGWINCH};
use rk_abi::native::sockios::SIOCGIFNAME;
use rk_abi::native::termbits::{TCIFLUSH, TCIOFLUSH, TCOFLUSH};
use rk_abi::native::types::{Termio, Termios, Winsize};
use rk_frame::sync::SpinLock;
use rk_vfs::device::{self, CharDevice, makedev, minor};
use rk_vfs::fstype::{FsType, MountArgs};
use rk_vfs::inode::{FileType, Inode, InodeRef, Result, SetAttr};
use rk_vfs::wait::PollTable;
use rk_vfs::{File, FileOps, Location, Mount, UserMemory, WaitQueue};
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
const DEFAULT_MODE: u32 = 0o600;
/// The most slaves of one instance, `NR_UNIX98_PTY_MAX` of Linux, the default and the limit of
/// the option `max`.
const NR_MAX: u32 = 1 << 20;

/// The magic number of devpts in `statfs`, `DEVPTS_SUPER_MAGIC` of Linux.
pub const DEVPTS_SUPER_MAGIC: u64 = 0x1cd1;

/// The file system type for `mount -t devpts`.
pub const DEVPTS: FsType = FsType { name: "devpts", nodev: true, make: mount_devpts };

/// The options of a mount of devpts, as `struct pts_mount_opts` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Options {
    /// The owner of a new slave file, or `None` for the file system user of the caller.
    uid: Option<u32>,
    /// The group of a new slave file, or `None` for the file system group of the caller.
    gid: Option<u32>,
    /// The permission bits of a new slave file.
    mode: u32,
    /// The permission bits of the `ptmx` file of devpts.
    ptmxmode: u32,
    /// The most slaves at the same time. The numbers are below it.
    max: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self { uid: None, gid: None, mode: DEFAULT_MODE, ptmxmode: 0, max: NR_MAX }
    }
}

/// The flags of the super block that the options of each file system can have, as
/// `vfs_parse_sb_flag` of Linux.
const SB_FLAGS: [&[u8]; 10] = [
    b"ro",
    b"rw",
    b"sync",
    b"async",
    b"dirsync",
    b"lazytime",
    b"nolazytime",
    b"mand",
    b"nomand",
    b"silent",
];

/// Reads the options of a mount of devpts, as `devpts_parse_param` of Linux. An unknown option
/// or a bad value gives `EINVAL`.
fn parse_options(data: &[u8]) -> Result<Options> {
    let mut opts = Options::default();
    let data = data.split(|&b| b == 0).next().unwrap_or(&[]);
    for opt in data.split(|&b| b == b',').filter(|o| !o.is_empty()) {
        let (key, value) = match opt.iter().position(|&b| b == b'=') {
            Some(i) => (&opt[..i], Some(&opt[i + 1..])),
            None => (opt, None),
        };
        let number = |radix: u32| -> Result<u32> {
            let v = core::str::from_utf8(value.ok_or(Errno::EINVAL)?).map_err(|_| Errno::EINVAL)?;
            u32::from_str_radix(v, radix).map_err(|_| Errno::EINVAL)
        };
        match key {
            b"uid" | b"gid" => {
                // `(uid_t)-1` is not a valid ID, as `make_kuid`.
                let id = Some(number(10)?).filter(|&id| id != u32::MAX).ok_or(Errno::EINVAL)?;
                if key == b"uid" {
                    opts.uid = id.into();
                } else {
                    opts.gid = id.into();
                }
            }
            b"mode" => opts.mode = number(8)? & 0o7777,
            b"ptmxmode" => opts.ptmxmode = number(8)? & 0o7777,
            b"max" => {
                let max = number(10)?;
                if max == 0 || max > NR_MAX {
                    return Err(Errno::EINVAL);
                }
                opts.max = max;
            }
            b"newinstance" if value.is_none() => {}
            k if value.is_none() && SB_FLAGS.contains(&k) => {}
            _ => return Err(Errno::EINVAL),
        }
    }
    Ok(opts)
}

/// An instance of devpts, as `struct pts_fs_info` of Linux.
struct Instance {
    /// The root directory. The mounts hold it.
    root: Weak<dyn Inode>,
    /// The options of the mount.
    opts: Options,
    /// The pairs, by their number.
    pairs: SpinLock<BTreeMap<u32, Arc<Pair>>>,
}

/// The instances of devpts, by the device number of their file system. An instance stays while
/// a mount holds its root or while it has a pair.
static INSTANCES: SpinLock<BTreeMap<u64, Arc<Instance>>> = SpinLock::new(BTreeMap::new());

/// The number of pairs in all the instances.
static NR_PAIRS: AtomicU32 = AtomicU32::new(0);

/// Makes a new instance of devpts with the options `opts`, and gives its root.
fn new_instance(opts: Options) -> Result<InodeRef> {
    // Only the kernel makes and removes the files of devpts. `mknod` and the other operations
    // on the names give `EPERM`, as the `simple_dir_inode_operations` of devpts.
    let root = rk_fs_tmpfs::new_fixed(0o755, DEVPTS_SUPER_MAGIC);
    // devpts has its own `ptmx`, with the mode 0 by default, as `mknod_ptmx` of Linux.
    rk_fs_tmpfs::kernel_create(&root, b"ptmx", FileType::CharDevice, opts.ptmxmode, PTMX_RDEV)?;
    let inst =
        Instance { root: Arc::downgrade(&root), opts, pairs: SpinLock::new(BTreeMap::new()) };
    let mut all = INSTANCES.lock();
    all.retain(|_, i| i.root.strong_count() > 0 || !i.pairs.lock().is_empty());
    all.insert(root.metadata().dev, Arc::new(inst));
    Ok(root)
}

/// Gives the root of a new instance of devpts for `mount(2)`.
fn mount_devpts(args: &MountArgs<'_>) -> Result<InodeRef> {
    new_instance(parse_options(args.data)?)
}

/// The instance of devpts of the file system with the device number `dev`.
fn instance(dev: u64) -> Option<Arc<Instance>> {
    INSTANCES.lock().get(&dev).cloned()
}

/// The instance of devpts on `pts` in the directory of `at`, and the root of its mount, as
/// `devpts_ptmx_path` of Linux. Gives `ENOENT` if `pts` is not there, and `ENODEV` if `pts` has
/// no devpts on it.
fn ptmx_path(at: &Location) -> Result<(Arc<Instance>, Location)> {
    let parent = at.dentry.parent().ok_or(Errno::ENOENT)?;
    parent.lookup(b"pts").map_err(|_| Errno::ENOENT)?;
    let pts = at.sibling_mount(b"pts").ok_or(Errno::ENODEV)?;
    // The mount must show the root of devpts.
    let inst = instance(pts.inode().metadata().dev).ok_or(Errno::ENODEV)?;
    if !pts.is_mount_root() || inst.root.upgrade().is_none_or(|r| !Arc::ptr_eq(&r, pts.inode())) {
        return Err(Errno::ENODEV);
    }
    Ok((inst, pts))
}

/// The instance of devpts of the file system of the mount of `at`.
fn mount_instance(at: &Location) -> Option<Arc<Instance>> {
    instance(at.mount.root().inode().metadata().dev)
}

/// The instance of devpts for an open of the `ptmx` file at `at`, as `devpts_acquire` of Linux.
/// The `ptmx` file of devpts uses its own instance. Another file uses the instance on `pts` in
/// its directory, see [`ptmx_path`].
fn ptmx_instance(at: &Location) -> Result<Arc<Instance>> {
    match mount_instance(at) {
        Some(inst) => Ok(inst),
        None => ptmx_path(at).map(|(inst, _)| inst),
    }
}

/// A mount of the instance `inst` of devpts for the master that opened at `at`, for
/// `TIOCGPTPEER`, as `devpts_mntget` of Linux. The search goes up while `at` is the root of a
/// bind mount of one file, as a bind mount of `/dev/pts/ptmx` on `/dev/ptmx`. A mount of another
/// file system uses `pts` in the directory. Gives `ENODEV` if the mount is not of `inst`.
fn mntget(at: &Location, inst: &Arc<Instance>) -> Result<Arc<Mount>> {
    let mut at = at.clone();
    while at.is_mount_root() {
        match at.mount.mountpoint() {
            Some(up) => at = up,
            None => break,
        }
    }
    if mount_instance(&at).is_none_or(|i| !Arc::ptr_eq(&i, inst)) {
        at = ptmx_path(&at)?.1;
    }
    match mount_instance(&at) {
        Some(i) if Arc::ptr_eq(&i, inst) => Ok(at.mount),
        _ => Err(Errno::ENODEV),
    }
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
    /// No file of the slave is open, `TTY_OTHER_CLOSED` of the master. It is true before the
    /// first open of the slave too.
    slave_closed: bool,
    /// The number of hang ups of the slave. A slave file of an older hang up is hung up.
    slave_hangups: u64,
    /// The line discipline of the slave that makes a network device, or `None` for `N_TTY`.
    line: Option<Arc<NetLine>>,
}

/// A pair of a master and a slave.
struct Pair {
    index: u32,
    /// The instance of devpts of the pair.
    inst: Arc<Instance>,
    state: SpinLock<PairState>,
    /// The readers and the writers of both sides wait here.
    wait: Arc<WaitQueue>,
}

/// The name of the slave file of `index` in devpts.
fn slave_name(index: u32) -> Vec<u8> {
    format!("{index}").into_bytes()
}

/// Makes a new pair in `inst`, as `ptmx_open` of Linux. Gives `ENOSPC` when there are
/// `MAX_PAIRS` pairs, or when `inst` has no free number below its option `max`.
fn open_pair(inst: &Arc<Instance>) -> Result<Arc<Pair>> {
    NR_PAIRS
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < MAX_PAIRS).then_some(n + 1))
        .map_err(|_| Errno::ENOSPC)?;
    let pair = {
        let mut pairs = inst.pairs.lock();
        // The smallest free number, as the IDA of devpts.
        let Some(index) = (0..inst.opts.max).find(|i| !pairs.contains_key(i)) else {
            NR_PAIRS.fetch_sub(1, Ordering::AcqRel);
            return Err(Errno::ENOSPC);
        };
        let pair = Arc::new(Pair {
            index,
            inst: inst.clone(),
            state: SpinLock::new(PairState {
                tty: Tty::new(),
                to_master: VecDeque::new(),
                locked: true,
                packet: false,
                master_open: true,
                slave_opens: 0,
                slave_closed: true,
                slave_hangups: 0,
                line: None,
            }),
            wait: Arc::new(WaitQueue::new()),
        });
        pairs.insert(index, pair.clone());
        pair
    };
    if let Err(e) = make_slave_file(&pair) {
        close_master(&pair);
        return Err(e);
    }
    Ok(pair)
}

/// Makes the slave file of `pair` in devpts, as `devpts_pty_new` of Linux.
fn make_slave_file(pair: &Pair) -> Result<()> {
    let Some(root) = pair.inst.root.upgrade() else { return Ok(()) };
    let opts = &pair.inst.opts;
    let rdev = makedev(SLAVE_MAJOR, pair.index);
    let name = slave_name(pair.index);
    let node = rk_fs_tmpfs::kernel_create(&root, &name, FileType::CharDevice, opts.mode, rdev)?;
    let cred = rk_vfs::cred::current();
    let attr = SetAttr {
        uid: Some(opts.uid.unwrap_or(cred.fsuid)),
        gid: Some(opts.gid.unwrap_or(cred.fsgid)),
        ..SetAttr::default()
    };
    node.set_attr(&attr)
}

/// Removes the pair after the close of the master, as `pty_close` and `devpts_pty_kill` of
/// Linux. The open files of the slave stay, and they get a hang up: the slave has no session
/// after it, and the leader of its session gets `SIGHUP` and `SIGCONT`, as `tty_vhangup` of the
/// slave.
fn close_master(pair: &Pair) {
    let (sid, line) = {
        let mut st = pair.state.lock();
        st.master_open = false;
        (st.tty.hang_up(), st.line.take())
    };
    close_line(line);
    if let Some(root) = pair.inst.root.upgrade() {
        let _ = rk_fs_tmpfs::kernel_unlink(&root, &slave_name(pair.index));
    }
    pair.inst.pairs.lock().remove(&pair.index);
    NR_PAIRS.fetch_sub(1, Ordering::AcqRel);
    pair.wait.wake_all();
    hang_up_session(sid);
}

/// The frames that the network device of the slave sends go to the master, as `pty_write` of
/// Linux.
impl LineOut for Pair {
    fn write_line(&self, data: &[u8]) -> Result<()> {
        {
            let mut st = self.state.lock();
            if !st.master_open {
                return Ok(());
            }
            if st.to_master.len() >= MASTER_BUF {
                return Err(Errno::ENOBUFS);
            }
            st.to_master.extend(data);
        }
        self.wait.wake_all();
        Ok(())
    }
}

/// Closes the line discipline `line` that a hang up or a change took from the slave. The caller
/// does not hold the lock of the pair, because the network device takes other locks.
fn close_line(line: Option<Arc<NetLine>>) {
    if let Some(line) = line {
        line.close();
    }
}

/// Sets the line discipline `n` on the slave of `pair`, as `tty_set_ldisc` of Linux. The old
/// line discipline closes after the new one opens. The same line discipline again does nothing.
///
/// Linux opens the line discipline of `c_line` again at the next open of the slave after a hang
/// up. Here a hang up gives the slave `N_TTY`.
fn set_ldisc(pair: &Arc<Pair>, n: i32) -> Result<usize> {
    // A number without a line discipline in the kernel gives `EINVAL`, as `tty_ldisc_get`.
    if !(N_TTY..NR_LDISCS).contains(&n) {
        return Err(Errno::EINVAL);
    }
    let proto = match n {
        N_TTY => None,
        n => Some(Proto::from_ldisc(n).ok_or(Errno::EINVAL)?),
    };
    let current = pair.state.lock().line.as_ref().map_or(N_TTY, |l| l.ldisc());
    if current == n {
        return Ok(0);
    }
    let new = match proto {
        Some(proto) => {
            let out: Weak<dyn LineOut> = Arc::downgrade(pair) as Weak<dyn LineOut>;
            Some(NetLine::open(proto, out)?)
        }
        None => None,
    };
    let old = {
        let mut st = pair.state.lock();
        st.tty.ldisc.flush_input();
        core::mem::replace(&mut st.line, new)
    };
    close_line(old);
    pair.wait.wake_all();
    Ok(0)
}

/// Each pair of each instance of devpts.
fn all_pairs() -> Vec<Arc<Pair>> {
    let all = INSTANCES.lock();
    all.values().flat_map(|i| i.pairs.lock().values().cloned().collect::<Vec<_>>()).collect()
}

/// Tells if a slave has the session `sid`.
pub(crate) fn slave_has_session(sid: u32) -> bool {
    all_pairs().iter().any(|p| p.state.lock().tty.sid == sid)
}

/// Takes the session `sid` from the slave that has it, after the exit of the session leader.
/// Gives `SIGHUP` for the foreground process group, as `disassociate_ctty(1)` of Linux.
pub(crate) fn end_session(sid: u32) -> Vec<(u32, u32)> {
    let mut signals = Vec::new();
    if sid == 0 {
        return signals;
    }
    for pair in all_pairs() {
        let mut st = pair.state.lock();
        if st.tty.sid == sid {
            signals.push((st.tty.pgrp, SIGHUP));
            st.tty.sid = 0;
            st.tty.pgrp = 0;
        }
    }
    signals
}

/// Opens the slave that is the controlling terminal of `c`, for `/dev/tty`. Gives `None` if no
/// slave is.
pub(crate) fn open_ctty(c: &Caller, flags: u32) -> Option<Result<Arc<dyn FileOps>>> {
    let pair = all_pairs().into_iter().find(|p| p.state.lock().tty.is_ctty_of(c))?;
    Some(open_slave_file(&pair, flags | O_NOCTTY))
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
    pair: &Arc<Pair>,
    master: bool,
    file: &File,
    cmd: u32,
    arg: usize,
    mem: &dyn UserMemory,
) -> Option<Result<usize>> {
    let c = caller();
    // These commands take other locks first, so they come before the lock of the pair. Both
    // sides run them on the slave, as `real_tty` of Linux.
    match cmd {
        TIOCSCTTY => {
            let has_tty = session_has_tty(c.sid);
            return Some(set_ctty(&mut pair.state.lock().tty, &c, has_tty, file, arg));
        }
        // Only the slave can be the controlling terminal of the caller.
        TIOCNOTTY if master => return Some(Err(Errno::ENOTTY)),
        TIOCNOTTY => {
            let r = leave_ctty(&mut pair.state.lock().tty, &c);
            return Some(r.map(|signals| finish_leave_ctty(&c, signals)).map(|()| 0));
        }
        // Only the slave has the line disciplines that make a network device.
        TIOCSETD if !master => return Some(read_int(mem, arg).and_then(|n| set_ldisc(pair, n))),
        TIOCSPGRP => {
            let (is_ctty, tty_pgrp) = {
                let st = pair.state.lock();
                (st.tty.is_ctty_of(&c), st.tty.pgrp)
            };
            if let Err(e) = check_change(is_ctty, tty_pgrp, &c) {
                return Some(Err(e));
            }
            let r = read_pgrp(mem, arg).and_then(|p| set_pgrp(&mut pair.state.lock().tty, &c, p));
            return Some(r.map(|()| 0));
        }
        _ => {}
    }
    let mut signals = Vec::new();
    let r = (|| {
        let mut st = pair.state.lock();
        // On the slave, the process group and the session are only for a process with the
        // slave as its controlling terminal, as `tiocgpgrp` and `tiocgsid` of Linux.
        if matches!(cmd, TIOCGPGRP | TIOCGSID) && !master && !st.tty.is_ctty_of(&c) {
            return Err(Errno::ENOTTY);
        }
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
                    if let Some(line) = &st.line {
                        line.flush();
                    }
                }
            }
            TIOCGETD => {
                let n = if master { N_TTY } else { st.line.as_ref().map_or(N_TTY, |l| l.ldisc()) };
                mem.write(arg, &n.to_ne_bytes())?;
            }
            // The master has only `N_TTY`.
            TIOCSETD => {
                if read_int(mem, arg)? != N_TTY {
                    return Err(Errno::EINVAL);
                }
            }
            // The name of the network device with the NUL, as `slip_ioctl` and `slcan_ioctl` of
            // Linux. `N_TTY` does not have it.
            SIOCGIFNAME if !master && st.line.is_some() => {
                let mut name = st.line.as_ref().map(|l| l.name()).unwrap_or_default().into_bytes();
                name.push(0);
                mem.write(arg, &name)?;
            }
            TCSBRK | TCSBRKP | TCXONC => {}
            // Only the master has a peer, as `ptm_open_peer` of Linux.
            TIOCGPTPEER => return Err(Errno::EIO),
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
    /// The location of the open of the `ptmx` file, for the mount of devpts of `TIOCGPTPEER`.
    at: Option<Location>,
    /// `TIOCVHANGUP` hung up the master.
    hung: AtomicBool,
}

impl Drop for MasterFile {
    fn drop(&mut self) {
        close_master(&self.pair);
    }
}

impl MasterFile {
    fn hung(&self) -> bool {
        self.hung.load(Ordering::Acquire)
    }
}

impl FileOps for MasterFile {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        let pair = &self.pair;
        let n = pair.wait.wait_interruptible(|| {
            if self.hung() {
                return Ok(Some(0));
            }
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
            // No slave file is open, before the first open of the slave or after the last
            // close: the data is all read, as `n_tty_read` with `TTY_OTHER_CLOSED`.
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
        if self.hung() {
            return Err(Errno::EIO);
        }
        let mut kick = false;
        let signals = {
            let mut st = self.pair.state.lock();
            match &st.line {
                Some(line) => {
                    kick = line.receive(buf);
                    Vec::new()
                }
                None => receive(&mut st, buf),
            }
        };
        if kick {
            rk_net::dev::kick_rx();
        }
        send_signals(signals);
        self.pair.wait.wake_all();
        Ok(buf.len())
    }

    fn ioctl(&self, file: &File, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        if self.hung() {
            return hung_ioctl(cmd);
        }
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
            // The hang up of the master, as `tty_vhangup`. The slave stays until the close of
            // the master.
            TIOCVHANGUP => {
                check_vhangup()?;
                self.hung.store(true, Ordering::Release);
                pair.wait.wake_all();
            }
            _ => {
                return tty_ioctl(pair, true, file, cmd, arg, mem).unwrap_or(Err(Errno::ENOTTY));
            }
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
        if self.hung() {
            return HUNG_POLL;
        }
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

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

/// The open file of a slave.
struct SlaveFile {
    pair: Arc<Pair>,
    /// The number of hang ups of the slave at the open.
    hangups: u64,
}

impl SlaveFile {
    /// Tells if the file is hung up: the master is closed, or the slave had a hang up after the
    /// open.
    fn hung(&self, st: &PairState) -> bool {
        !st.master_open || st.slave_hangups != self.hangups
    }
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
            // A read after the hang up gives the end of the file, as `hung_up_tty_read`.
            if self.hung(&st) {
                return Ok(Some(0));
            }
            // A line discipline without a read gives `EIO`, as `tty_read` of Linux.
            if st.line.is_some() {
                return Err(Errno::EIO);
            }
            if st.tty.ldisc.readable() || buf.is_empty() {
                return Ok(Some(st.tty.ldisc.read(buf)));
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
            // A line discipline without a write gives `EIO`, as `tty_write` of Linux.
            if self.hung(&st) || st.line.is_some() {
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

    fn ioctl(&self, file: &File, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
        let pair = &self.pair;
        if self.hung(&pair.state.lock()) {
            return hung_ioctl(cmd);
        }
        if cmd == TIOCVHANGUP {
            // The hang up of the slave, as `tty_vhangup`: each open file of the slave is hung
            // up, and the slave has no session after it. A new open of the slave works.
            // The leader of the session gets `SIGHUP` and `SIGCONT`, as
            // `tty_signal_session_leader` of Linux.
            // The line discipline closes, as `tty_ldisc_hangup`.
            check_vhangup()?;
            let (sid, line) = {
                let mut st = pair.state.lock();
                st.slave_hangups += 1;
                (st.tty.hang_up(), st.line.take())
            };
            close_line(line);
            pair.wait.wake_all();
            hang_up_session(sid);
            return Ok(0);
        }
        tty_ioctl(pair, false, file, cmd, arg, mem).unwrap_or(Err(Errno::ENOTTY))
    }

    fn pollable(&self) -> bool {
        true
    }

    fn poll_wait(&self, _file: &File, table: &mut PollTable) {
        table.add(&self.pair.wait);
    }

    fn poll(&self, _file: &File) -> u32 {
        let st = self.pair.state.lock();
        if self.hung(&st) {
            return HUNG_POLL;
        }
        // A line discipline without a poll gives no events, as `tty_poll` of Linux.
        if st.line.is_some() {
            return 0;
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

/// Opens the slave of `pair` with the open flags `flags`, as `pty_open` of Linux. A locked slave
/// and a slave without its master give `EIO`. Without `O_NOCTTY`, the slave becomes the
/// controlling terminal of a session leader without one, as `tty_open_proc_set_tty`.
fn open_slave_file(pair: &Arc<Pair>, flags: u32) -> Result<Arc<dyn FileOps>> {
    let c = caller();
    let ctty = flags & O_NOCTTY == 0 && c.leader() && !session_has_tty(c.sid);
    let mut st = pair.state.lock();
    if st.locked || !st.master_open {
        return Err(Errno::EIO);
    }
    st.slave_opens += 1;
    st.slave_closed = false;
    if ctty && st.tty.sid == 0 {
        st.tty.sid = c.sid;
        st.tty.pgrp = c.pgid;
    }
    let hangups = st.slave_hangups;
    drop(st);
    Ok(Arc::new(SlaveFile { pair: pair.clone(), hangups }))
}

/// Opens the slave of the master file `file` with the open flags `flags`, for `TIOCGPTPEER`, as
/// `ptm_open_peer` of Linux. The new file has the slave file of devpts as its location. Gives
/// `None` if `file` is not a master.
pub fn open_peer(file: &File, flags: u32) -> Option<Result<Arc<File>>> {
    let master = file.ops().as_any()?.downcast_ref::<MasterFile>()?;
    Some((|| {
        if master.hung() {
            return Err(Errno::EIO);
        }
        let pair = &master.pair;
        let location = match &master.at {
            Some(at) => {
                let mount = mntget(at, &pair.inst)?;
                let dentry = mount.root().lookup(&slave_name(pair.index))?;
                Some(Location { mount, dentry })
            }
            None => None,
        };
        let ops = open_slave_file(pair, flags)?;
        // The flags of the open file, as `do_dentry_open` of Linux. `O_CLOEXEC` is a flag of
        // the file descriptor.
        let flags = flags & !(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_CLOEXEC);
        Ok(File::with_ops(ops, location, flags))
    })())
}

/// The driver of `/dev/ptmx` and of the `ptmx` file of each instance of devpts.
struct PtmxDevice;

impl CharDevice for PtmxDevice {
    /// Without the device file there is no instance of devpts, and the open fails as
    /// `devpts_acquire` of Linux without `pts`.
    fn open(&self, _flags: u32) -> Result<Arc<dyn FileOps>> {
        Err(Errno::ENODEV)
    }

    fn open_at(&self, at: &Location, _flags: u32) -> Result<Arc<dyn FileOps>> {
        let inst = ptmx_instance(at)?;
        let master: Arc<dyn FileOps> = open_master(&inst, Some(at.clone()))?;
        Ok(master)
    }
}

/// Opens a new master in `inst`.
fn open_master(inst: &Arc<Instance>, at: Option<Location>) -> Result<Arc<MasterFile>> {
    Ok(Arc::new(MasterFile { pair: open_pair(inst)?, at, hung: AtomicBool::new(false) }))
}

/// The driver of the slaves, the major number `SLAVE_MAJOR`. A slave opens only through its file
/// in devpts, as `pts_unix98_lookup` of Linux, else the open gives `EIO`.
struct SlaveDevice;

impl CharDevice for SlaveDevice {
    fn open(&self, _flags: u32) -> Result<Arc<dyn FileOps>> {
        Err(Errno::EIO)
    }

    fn open_at(&self, at: &Location, flags: u32) -> Result<Arc<dyn FileOps>> {
        let meta = at.inode().metadata();
        let inst = instance(meta.dev).ok_or(Errno::EIO)?;
        let pair = inst.pairs.lock().get(&minor(meta.rdev)).cloned().ok_or(Errno::EIO)?;
        open_slave_file(&pair, flags)
    }
}

/// Adds `/dev/ptmx` and the slaves to the table of character devices.
pub fn init() {
    device::register_char(PTMX_RDEV, Arc::new(PtmxDevice));
    device::register_char_major(SLAVE_MAJOR, Arc::new(SlaveDevice));
}

/// A new instance of devpts for a test, with the mount options `data`. The root holds it.
#[cfg(test)]
pub(crate) fn test_instance(data: &[u8]) -> Result<InodeRef> {
    new_instance(parse_options(data)?)
}

/// Opens a new master in the instance of devpts of `root`.
#[cfg(test)]
pub(crate) fn open_ptmx(root: &InodeRef) -> Result<Arc<dyn FileOps>> {
    let inst = instance(root.metadata().dev).ok_or(Errno::ENODEV)?;
    let master: Arc<dyn FileOps> = open_master(&inst, None)?;
    Ok(master)
}

/// Opens the slave `index` of the instance of devpts of `root`.
#[cfg(test)]
pub(crate) fn open_slave(root: &InodeRef, index: u32, flags: u32) -> Result<Arc<dyn FileOps>> {
    let inst = instance(root.metadata().dev).ok_or(Errno::ENODEV)?;
    let pair = inst.pairs.lock().get(&index).cloned().ok_or(Errno::ENXIO)?;
    open_slave_file(&pair, flags)
}

/// The options of a mount of devpts as a tuple, for a test: uid, gid, mode, ptmxmode and max.
#[cfg(test)]
pub(crate) type TestOptions = (Option<u32>, Option<u32>, u32, u32, u32);

/// The options of a mount of devpts, for a test.
#[cfg(test)]
pub(crate) fn test_options(data: &[u8]) -> Result<TestOptions> {
    let o = parse_options(data)?;
    Ok((o.uid, o.gid, o.mode, o.ptmxmode, o.max))
}

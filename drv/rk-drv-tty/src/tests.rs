use crate::ldisc::{LineDiscipline, default_termios};
use alloc::vec::Vec;
use rk_abi::native::signal::SIGINT;
use rk_abi::native::termbits::{ECHO, ICANON, VMIN};

fn feed(ld: &mut LineDiscipline, bytes: &[u8]) -> (Vec<u8>, Vec<u32>) {
    let mut echo = Vec::new();
    let mut signals = Vec::new();
    for &b in bytes {
        signals.extend(ld.receive(b, &mut echo));
    }
    (echo, signals)
}

#[test]
fn canonical_line() {
    let mut ld = LineDiscipline::new();
    let (echo, _) = feed(&mut ld, b"ls");
    assert_eq!(echo, b"ls");
    assert!(!ld.readable());
    feed(&mut ld, b"x\x7f\r");
    assert!(ld.readable());
    let mut buf = [0u8; 2];
    assert_eq!(ld.read(&mut buf), 2);
    assert_eq!(&buf, b"ls");
    assert_eq!(ld.read(&mut buf), 1);
    assert_eq!(buf[0], b'\n');
    assert!(!ld.readable());
}

#[test]
fn erase_and_kill() {
    let mut ld = LineDiscipline::new();
    let (echo, _) = feed(&mut ld, b"ab\x7f");
    assert_eq!(echo, b"ab\x08 \x08");
    feed(&mut ld, b"cd ef\x17\x15gh\n");
    let mut buf = [0u8; 16];
    let n = ld.read(&mut buf);
    assert_eq!(&buf[..n], b"gh\n");
}

#[test]
fn end_of_file() {
    let mut ld = LineDiscipline::new();
    feed(&mut ld, b"ab\x04\x04");
    let mut buf = [0u8; 16];
    assert_eq!(ld.read(&mut buf), 2);
    assert!(ld.readable());
    assert_eq!(ld.read(&mut buf), 0);
    assert!(!ld.readable());
}

#[test]
fn interrupt_flushes_the_line() {
    let mut ld = LineDiscipline::new();
    let (echo, signals) = feed(&mut ld, b"sleep\x03");
    assert_eq!(signals, [SIGINT]);
    assert!(echo.ends_with(b"^C"));
    feed(&mut ld, b"\n");
    let mut buf = [0u8; 16];
    assert_eq!(ld.read(&mut buf), 1);
}

#[test]
fn raw_mode() {
    let mut ld = LineDiscipline::new();
    feed(&mut ld, b"ab");
    let mut t = default_termios();
    t.c_lflag &= !(ICANON | ECHO);
    t.c_cc[VMIN as usize] = 1;
    ld.set_termios(t);
    assert!(ld.readable());
    let (echo, _) = feed(&mut ld, b"c");
    assert!(echo.is_empty());
    let mut buf = [0u8; 16];
    assert_eq!(ld.read(&mut buf), 3);
    assert_eq!(&buf[..3], b"abc");
}

#[test]
fn output_processing() {
    let ld = LineDiscipline::new();
    let mut out = Vec::new();
    ld.process_output(b"a\nb\n", &mut out);
    assert_eq!(out, b"a\r\nb\r\n");
}

/// A user memory of 256 bytes at the address 0x1000. Other addresses give `EFAULT`.
struct Mem(core::cell::RefCell<[u8; 256]>);

const BASE: usize = 0x1000;

impl Mem {
    fn range(&self, addr: usize, len: usize) -> rk_vfs::inode::Result<core::ops::Range<usize>> {
        let start = addr.checked_sub(BASE).ok_or(rk_abi::Errno::EFAULT)?;
        if start + len > 256 {
            return Err(rk_abi::Errno::EFAULT);
        }
        Ok(start..start + len)
    }

    fn int(&self) -> i32 {
        i32::from_ne_bytes(self.0.borrow()[..4].try_into().unwrap())
    }

    fn set_int(&self, v: i32) {
        self.0.borrow_mut()[..4].copy_from_slice(&v.to_ne_bytes());
    }
}

impl rk_vfs::UserMemory for Mem {
    fn read(&self, addr: usize, buf: &mut [u8]) -> rk_vfs::inode::Result<()> {
        let r = self.range(addr, buf.len())?;
        buf.copy_from_slice(&self.0.borrow()[r]);
        Ok(())
    }

    fn write(&self, addr: usize, buf: &[u8]) -> rk_vfs::inode::Result<()> {
        let r = self.range(addr, buf.len())?;
        self.0.borrow_mut()[r].copy_from_slice(buf);
        Ok(())
    }
}

#[test]
fn pseudo_terminal_pair() {
    use crate::pty::{open_ptmx, open_slave, test_instance};
    use rk_abi::Errno;
    use rk_abi::native::ioctls::{
        TCGETA, TCGETS, TIOCGETD, TIOCGPTN, TIOCGWINSZ, TIOCSETD, TIOCSPTLCK, TIOCSWINSZ,
    };
    use rk_abi::native::open::{O_NOCTTY, O_NONBLOCK};
    use rk_vfs::File;

    let root = test_instance(b"").unwrap();
    let exists = |index: u32| root.lookup(alloc::format!("{index}").as_bytes()).is_ok();
    let mem = Mem(core::cell::RefCell::new([0; 256]));
    let master = open_ptmx(&root).unwrap();
    let mf = File::with_ops(master.clone(), None, O_NONBLOCK);
    // musl `openpty`: `TIOCSPTLCK` with 0, `TIOCGPTN`, and then the open of the slave.
    assert_eq!(master.ioctl(&mf, TIOCGPTN, BASE, &mem), Ok(0));
    let index = mem.int() as u32;
    // Each instance of devpts has its own numbers.
    assert_eq!(index, 0);
    assert!(exists(index));
    assert_eq!(open_slave(&root, index, O_NOCTTY).err(), Some(Errno::EIO));
    // A read of the master before the first open of the slave gives `EIO`.
    let mut buf = [0u8; 32];
    assert_eq!(master.read(&mf, &mut buf), Err(Errno::EIO));
    mem.set_int(0);
    assert_eq!(master.ioctl(&mf, TIOCSPTLCK, BASE, &mem), Ok(0));
    let slave = open_slave(&root, index, O_NOCTTY).unwrap();
    let sf = File::with_ops(slave.clone(), None, O_NONBLOCK);

    // The ioctls of LTP ioctl01: a bad pointer gives `EFAULT`, a bad command gives `ENOTTY`.
    assert_eq!(master.ioctl(&mf, TCGETA, 0, &mem), Err(Errno::EFAULT));
    assert_eq!(master.ioctl(&mf, TCGETS, 0, &mem), Err(Errno::EFAULT));
    assert_eq!(master.ioctl(&mf, 0x5400 | 0xff, BASE, &mem), Err(Errno::ENOTTY));
    assert_eq!(master.ioctl(&mf, TCGETA, BASE, &mem), Ok(0));
    assert_eq!(slave.ioctl(&sf, TCGETS, BASE, &mem), Ok(0));
    // Only `N_TTY` is a line discipline.
    mem.set_int(15);
    assert_eq!(master.ioctl(&mf, TIOCSETD, BASE, &mem), Err(Errno::EINVAL));
    assert_eq!(master.ioctl(&mf, TIOCGETD, BASE, &mem), Ok(0));
    assert_eq!(mem.int(), 0);
    // The window size is the same on both sides.
    mem.0.borrow_mut()[..8].copy_from_slice(&[24, 0, 80, 0, 0, 0, 0, 0]);
    assert_eq!(master.ioctl(&mf, TIOCSWINSZ, BASE, &mem), Ok(0));
    mem.0.borrow_mut()[..8].fill(0);
    assert_eq!(slave.ioctl(&sf, TIOCGWINSZ, BASE, &mem), Ok(0));
    assert_eq!(&mem.0.borrow()[..4], &[24, 0, 80, 0]);

    // The master writes a line: the slave reads it, and the echo goes back to the master.
    assert_eq!(slave.read(&sf, &mut buf), Err(Errno::EAGAIN));
    assert_eq!(master.write(&mf, b"hi\n"), Ok(3));
    assert_eq!(slave.read(&sf, &mut buf), Ok(3));
    assert_eq!(&buf[..3], b"hi\n");
    assert_eq!(master.read(&mf, &mut buf), Ok(4));
    assert_eq!(&buf[..4], b"hi\r\n");
    // The slave writes: the output processing changes "\n" to "\r\n".
    assert_eq!(slave.write(&sf, b"ok\n"), Ok(3));
    assert_eq!(master.read(&mf, &mut buf), Ok(4));
    assert_eq!(&buf[..4], b"ok\r\n");
    assert_eq!(master.read(&mf, &mut buf), Err(Errno::EAGAIN));

    // After the close of the slave, a read of the master gives `EIO`.
    drop(sf);
    drop(slave);
    assert_eq!(master.read(&mf, &mut buf), Err(Errno::EIO));
    // A new open of the slave works again.
    let slave = open_slave(&root, index, O_NOCTTY).unwrap();
    let sf = File::with_ops(slave.clone(), None, O_NONBLOCK);
    // After the close of the master, the slave file goes away and the slave hangs up.
    drop(mf);
    drop(master);
    assert!(!exists(index));
    assert_eq!(open_slave(&root, index, O_NOCTTY).err(), Some(Errno::ENXIO));
    assert_eq!(slave.read(&sf, &mut buf), Ok(0));
    assert_eq!(slave.write(&sf, b"x"), Err(Errno::EIO));
    assert_eq!(slave.ioctl(&sf, TCGETS, BASE, &mem), Err(Errno::EIO));
}

/// The process of the hook of `set_caller_hook` in the tests: the process ID, the process group,
/// the session, and 1 if the process left its controlling terminal.
static CALLER: [core::sync::atomic::AtomicU32; 4] =
    [const { core::sync::atomic::AtomicU32::new(0) }; 4];

fn test_caller() -> crate::Caller {
    use core::sync::atomic::Ordering::Relaxed;
    crate::Caller {
        pid: CALLER[0].load(Relaxed),
        pgid: CALLER[1].load(Relaxed),
        sid: CALLER[2].load(Relaxed),
        no_ctty: CALLER[3].load(Relaxed) != 0,
    }
}

fn set_caller(pid: u32, pgid: u32, sid: u32) {
    use core::sync::atomic::Ordering::Relaxed;
    for (a, v) in CALLER.iter().zip([pid, pgid, sid, 0]) {
        a.store(v, Relaxed);
    }
}

/// The signals of the hook `signal_leader` in the tests: the session and the signal.
static LEADER_SIGNALS: rk_frame::sync::SpinLock<Vec<(u32, u32)>> =
    rk_frame::sync::SpinLock::new(Vec::new());

/// The signals of the hook of `set_signal_handler` in the tests: the group and the signal.
static GROUP_SIGNALS: rk_frame::sync::SpinLock<Vec<(u32, u32)>> =
    rk_frame::sync::SpinLock::new(Vec::new());

/// The state of `SIGTTOU` for the hooks in the tests: bit 0 tells that the caller ignores it,
/// and bit 1 tells that the group of the caller is orphaned.
static TTOU: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The hooks of the sessions in the tests. The groups 920 and 921 are in the session 920, and the
/// group 950 is in the session 950. No process has another group.
fn set_test_session_hooks() {
    crate::set_signal_handler(|pgrp, sig| GROUP_SIGNALS.lock().push((pgrp, sig)));
    crate::set_session_hooks(crate::SessionHooks {
        signal_leader: |sid, sig| LEADER_SIGNALS.lock().push((sid, sig)),
        pgrp_session: |pgrp| match pgrp {
            920 | 921 => Some(920),
            950 => Some(950),
            _ => None,
        },
        leave_ctty: || CALLER[3].store(1, core::sync::atomic::Ordering::Relaxed),
        ttou_ignored: || TTOU.load(core::sync::atomic::Ordering::Relaxed) & 1 != 0,
        pgrp_orphaned: |_| TTOU.load(core::sync::atomic::Ordering::Relaxed) & 2 != 0,
    });
}

#[test]
fn pseudo_terminal_hang_up() {
    use crate::pty::{open_ptmx, open_slave, test_instance};
    use rk_abi::Errno;
    use rk_abi::native::ioctls::{TCGETS, TIOCGPTPEER, TIOCSPGRP, TIOCSPTLCK, TIOCVHANGUP};
    use rk_abi::native::open::{O_NOCTTY, O_NONBLOCK};
    use rk_abi::native::poll::{POLLERR, POLLHUP};
    use rk_vfs::File;

    let root = test_instance(b"newinstance").unwrap();
    let mem = Mem(core::cell::RefCell::new([0; 256]));
    let master = open_ptmx(&root).unwrap();
    let mf = File::with_ops(master.clone(), None, O_NONBLOCK);
    mem.set_int(0);
    assert_eq!(master.ioctl(&mf, TIOCSPTLCK, BASE, &mem), Ok(0));
    let slave = open_slave(&root, 0, O_NOCTTY).unwrap();
    let sf = File::with_ops(slave.clone(), None, O_NONBLOCK);
    // Only the master has a peer.
    assert_eq!(slave.ioctl(&sf, TIOCGPTPEER, 0, &mem), Err(Errno::EIO));

    // `TIOCVHANGUP` on the slave hangs up each open file of the slave. A new open works.
    assert_eq!(slave.ioctl(&sf, TIOCVHANGUP, 0, &mem), Ok(0));
    let mut buf = [0u8; 8];
    assert_eq!(master.write(&mf, b"x\n"), Ok(2));
    assert_eq!(slave.read(&sf, &mut buf), Ok(0));
    assert_eq!(slave.write(&sf, b"x"), Err(Errno::EIO));
    assert_eq!(slave.ioctl(&sf, TCGETS, BASE, &mem), Err(Errno::EIO));
    assert_eq!(slave.ioctl(&sf, TIOCSPGRP, BASE, &mem), Err(Errno::ENOTTY));
    assert_eq!(slave.poll(&sf) & (POLLHUP | POLLERR), POLLHUP | POLLERR);
    let again = open_slave(&root, 0, O_NOCTTY).unwrap();
    let af = File::with_ops(again.clone(), None, O_NONBLOCK);
    assert_eq!(again.write(&af, b"ok"), Ok(2));
    drop((sf, slave, af, again));

    // `TIOCVHANGUP` on the master hangs up the master. The slave goes at the close.
    assert_eq!(master.ioctl(&mf, TIOCVHANGUP, 0, &mem), Ok(0));
    assert_eq!(master.read(&mf, &mut buf), Ok(0));
    assert_eq!(master.write(&mf, b"x"), Err(Errno::EIO));
    assert_eq!(master.ioctl(&mf, TCGETS, BASE, &mem), Err(Errno::EIO));
    assert!(root.lookup(b"0").is_ok());
    drop((mf, master));
    assert!(root.lookup(b"0").is_err());
}

#[test]
fn pseudo_terminal_controlling_terminal() {
    use crate::pty::{open_ptmx, open_slave, test_instance};
    use rk_abi::Errno;
    use rk_abi::native::ioctls::{
        TIOCGPGRP, TIOCGSID, TIOCNOTTY, TIOCSCTTY, TIOCSPGRP, TIOCSPTLCK, TIOCVHANGUP,
    };
    use rk_abi::native::open::{O_NOCTTY, O_NONBLOCK};
    use rk_abi::native::signal::{SIGCONT, SIGHUP};
    use rk_vfs::File;

    crate::set_caller_hook(test_caller);
    let root = test_instance(b"").unwrap();
    let mem = Mem(core::cell::RefCell::new([0; 256]));
    let master = open_ptmx(&root).unwrap();
    let mf = File::with_ops(master.clone(), None, O_NONBLOCK);
    mem.set_int(0);
    assert_eq!(master.ioctl(&mf, TIOCSPTLCK, BASE, &mem), Ok(0));
    let slave = open_slave(&root, 0, O_NOCTTY).unwrap();
    let sf = File::with_ops(slave.clone(), None, O_NONBLOCK);

    // A process that is not a session leader cannot take a controlling terminal.
    set_caller(901, 900, 900);
    assert_eq!(slave.ioctl(&sf, TIOCSCTTY, 0, &mem), Err(Errno::EPERM));
    assert_eq!(slave.ioctl(&sf, TIOCGSID, BASE, &mem), Err(Errno::ENOTTY));
    // The session leader takes it, through the master too.
    set_caller(900, 900, 900);
    assert_eq!(master.ioctl(&mf, TIOCSCTTY, 0, &mem), Ok(0));
    assert_eq!(slave.ioctl(&sf, TIOCSCTTY, 0, &mem), Ok(0));
    assert_eq!(slave.ioctl(&sf, TIOCGSID, BASE, &mem), Ok(0));
    assert_eq!(mem.int(), 900);
    assert_eq!(master.ioctl(&mf, TIOCGSID, BASE, &mem), Ok(0));
    assert_eq!(slave.ioctl(&sf, TIOCGPGRP, BASE, &mem), Ok(0));
    assert_eq!(mem.int(), 900);
    // A process of another session gets `ENOTTY` for the session of the slave.
    set_caller(905, 905, 905);
    assert_eq!(slave.ioctl(&sf, TIOCGSID, BASE, &mem), Err(Errno::ENOTTY));
    // The slave of another session needs the argument 1 and `CAP_SYS_ADMIN`.
    assert_eq!(slave.ioctl(&sf, TIOCSCTTY, 0, &mem), Err(Errno::EPERM));
    assert_eq!(slave.ioctl(&sf, TIOCSCTTY, 1, &mem), Ok(0));
    assert_eq!(slave.ioctl(&sf, TIOCGSID, BASE, &mem), Ok(0));
    assert_eq!(mem.int(), 905);
    // `TIOCNOTTY`: the master is never the controlling terminal.
    assert_eq!(master.ioctl(&mf, TIOCNOTTY, 0, &mem), Err(Errno::ENOTTY));
    assert_eq!(slave.ioctl(&sf, TIOCNOTTY, 0, &mem), Ok(0));
    assert_eq!(slave.ioctl(&sf, TIOCGSID, BASE, &mem), Err(Errno::ENOTTY));
    assert_eq!(master.ioctl(&mf, TIOCGSID, BASE, &mem), Err(Errno::ENOTTY));

    // An open without `O_NOCTTY` by a session leader without a controlling terminal makes the
    // slave its controlling terminal. The exit of the leader ends it.
    set_caller(910, 910, 910);
    let other = open_slave(&root, 0, 0).unwrap();
    assert_eq!(slave.ioctl(&sf, TIOCGSID, BASE, &mem), Ok(0));
    assert_eq!(mem.int(), 910);
    crate::session_leader_exit(910);
    assert_eq!(slave.ioctl(&sf, TIOCGSID, BASE, &mem), Err(Errno::ENOTTY));
    drop(other);

    // `TIOCSPGRP` needs the slave as the controlling terminal of the caller and a group of the
    // session of the caller, as `tiocspgrp` of Linux. The master sets the group of the slave.
    set_test_session_hooks();
    set_caller(920, 920, 920);
    mem.set_int(920);
    assert_eq!(slave.ioctl(&sf, TIOCSPGRP, BASE, &mem), Err(Errno::ENOTTY));
    assert_eq!(slave.ioctl(&sf, TIOCSCTTY, 0, &mem), Ok(0));
    mem.set_int(921);
    assert_eq!(slave.ioctl(&sf, TIOCSPGRP, BASE, &mem), Ok(0));
    assert_eq!(slave.ioctl(&sf, TIOCGPGRP, BASE, &mem), Ok(0));
    assert_eq!(mem.int(), 921);
    // The group 920 is in the background now. The check of `tty_check_change` comes first, so
    // the caller ignores `SIGTTOU` for the checks of the group argument.
    use core::sync::atomic::Ordering::Relaxed;
    use rk_abi::native::signal::SIGTTOU;
    TTOU.store(1, Relaxed);
    for (pgrp, err) in [(950, Errno::EPERM), (999, Errno::ESRCH), (-1, Errno::EINVAL)] {
        mem.set_int(pgrp);
        assert_eq!(slave.ioctl(&sf, TIOCSPGRP, BASE, &mem), Err(err));
    }
    TTOU.store(0, Relaxed);
    // `TIOCSPGRP` from the background sends `SIGTTOU` to the group of the caller, and the call
    // starts again after the signal, as `tty_check_change` of Linux. The master sets the group
    // of the slave, so the check is the same on the master.
    mem.set_int(920);
    GROUP_SIGNALS.lock().clear();
    assert_eq!(master.ioctl(&mf, TIOCSPGRP, BASE, &mem), Err(Errno::ERESTARTSYS));
    assert_eq!(slave.ioctl(&sf, TIOCSPGRP, BASE, &mem), Err(Errno::ERESTARTSYS));
    assert_eq!(*GROUP_SIGNALS.lock(), [(920, SIGTTOU), (920, SIGTTOU)]);
    // An orphaned group gets no signal, and `ENOTTY`.
    TTOU.store(2, Relaxed);
    assert_eq!(slave.ioctl(&sf, TIOCSPGRP, BASE, &mem), Err(Errno::ENOTTY));
    assert_eq!(GROUP_SIGNALS.lock().len(), 2);
    // A caller that blocks or ignores `SIGTTOU` sets the group.
    TTOU.store(1, Relaxed);
    assert_eq!(master.ioctl(&mf, TIOCSPGRP, BASE, &mem), Ok(0));
    TTOU.store(0, Relaxed);
    // The foreground group sets it without a check.
    mem.set_int(921);
    assert_eq!(slave.ioctl(&sf, TIOCSPGRP, BASE, &mem), Ok(0));
    mem.set_int(920);
    assert_eq!(slave.ioctl(&sf, TIOCSPGRP, BASE, &mem), Err(Errno::ERESTARTSYS));
    assert_eq!(GROUP_SIGNALS.lock().len(), 3);
    TTOU.store(1, Relaxed);
    assert_eq!(slave.ioctl(&sf, TIOCSPGRP, BASE, &mem), Ok(0));
    TTOU.store(0, Relaxed);
    // A process without the slave as its controlling terminal gets no signal.
    set_caller(930, 930, 930);
    assert_eq!(slave.ioctl(&sf, TIOCSPGRP, BASE, &mem), Err(Errno::ENOTTY));

    // `TIOCNOTTY` from a process that is not the session leader: the process leaves the slave,
    // and the slave stays with the session.
    set_caller(922, 921, 920);
    assert_eq!(slave.ioctl(&sf, TIOCNOTTY, 0, &mem), Ok(0));
    assert_eq!(CALLER[3].load(core::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(slave.ioctl(&sf, TIOCGSID, BASE, &mem), Err(Errno::ENOTTY));
    assert_eq!(slave.ioctl(&sf, TIOCNOTTY, 0, &mem), Err(Errno::ENOTTY));
    set_caller(920, 920, 920);
    assert_eq!(slave.ioctl(&sf, TIOCGSID, BASE, &mem), Ok(0));
    assert_eq!(mem.int(), 920);

    // A hang up of the slave sends `SIGHUP` and `SIGCONT` to the session leader, as
    // `tty_signal_session_leader` of Linux, and the slave has no session after it.
    LEADER_SIGNALS.lock().retain(|&(sid, _)| sid != 920);
    assert_eq!(slave.ioctl(&sf, TIOCVHANGUP, 0, &mem), Ok(0));
    let sent = |sid: u32| LEADER_SIGNALS.lock().iter().filter(|s| s.0 == sid).count();
    assert_eq!(*LEADER_SIGNALS.lock(), [(920, SIGHUP), (920, SIGCONT)]);
    drop((sf, slave));
    // The close of the master hangs up the slave too.
    let slave = open_slave(&root, 0, 0).unwrap();
    let sf = File::with_ops(slave.clone(), None, O_NONBLOCK);
    assert_eq!(slave.ioctl(&sf, TIOCGSID, BASE, &mem), Ok(0));
    drop((mf, master));
    assert_eq!(sent(920), 4);
    assert_eq!(slave.read(&sf, &mut [0u8; 4]), Ok(0));
    set_caller(0, 0, 0);
}

#[test]
fn devpts_options() {
    use crate::pty::{open_ptmx, test_instance, test_options};
    use rk_abi::Errno;

    assert_eq!(test_options(b""), Ok((None, None, 0o600, 0, 1 << 20)));
    assert_eq!(
        test_options(b"newinstance,gid=5,mode=620,ptmxmode=666,max=2,rw"),
        Ok((None, Some(5), 0o620, 0o666, 2))
    );
    for bad in [&b"max=0"[..], b"mode=9", b"uid", b"newinstance=1", b"bad", b"uid=4294967295"] {
        assert_eq!(test_options(bad), Err(Errno::EINVAL));
    }
    // The option `max` limits the pairs of the instance. The `ptmx` file has `ptmxmode`.
    let root = test_instance(b"max=1,ptmxmode=0666").unwrap();
    assert_eq!(root.lookup(b"ptmx").unwrap().metadata().mode & 0o7777, 0o666);
    let first = open_ptmx(&root).unwrap();
    assert_eq!(open_ptmx(&root).err(), Some(Errno::ENOSPC));
    drop(first);
    assert!(open_ptmx(&root).is_ok());

    // devpts has its own magic number, and only the kernel makes and removes its files.
    assert_eq!(root.fs_magic(), crate::pty::DEVPTS_SUPER_MAGIC);
    let dev = rk_vfs::FileType::CharDevice;
    assert_eq!(root.create(b"x", dev, 0o600, 0).err(), Some(Errno::EPERM));
    assert_eq!(root.create(b"d", rk_vfs::FileType::Directory, 0o755, 0).err(), Some(Errno::EPERM));
    assert_eq!(root.symlink(b"s", b"ptmx").err(), Some(Errno::EPERM));
    assert_eq!(root.unlink(b"ptmx"), Err(Errno::EPERM));
    assert_eq!(root.tmpfile(0o600).err(), Some(Errno::EOPNOTSUPP));
    assert!(root.lookup(b"ptmx").is_ok());
}

#[test]
fn slip_and_slcan_codecs() {
    use crate::netldisc::{LineRx, slcan_decode, slcan_encode, slip_encode};

    // SLIP changes `END` and `ESC` in the data, and puts `END` at both ends, as `slip_esc`.
    let mut out = Vec::new();
    slip_encode(&[1, 0xc0, 2, 0xdb, 3], &mut out);
    assert_eq!(out, [0xc0, 1, 0xdb, 0xdc, 2, 0xdb, 0xdd, 3, 0xc0]);
    let mut rx = LineRx::default();
    let frames: Vec<_> = out.iter().filter_map(|&b| rx.slip(b, 1152)).collect();
    assert_eq!(frames, [alloc::vec![1, 0xc0, 2, 0xdb, 3]]);
    // A frame of 2 bytes or less goes away, as `slip_unesc`.
    assert_eq!([1u8, 2, 0xc0].iter().filter_map(|&b| rx.slip(b, 1152)).count(), 0);
    // A frame that is too large goes away, and the next frame is good.
    let big: Vec<u8> = [[7u8; 9].as_slice(), &[0xc0, 4, 5, 6, 0xc0]].concat();
    let frames: Vec<_> = big.iter().filter_map(|&b| rx.slip(b, 8)).collect();
    assert_eq!(frames, [alloc::vec![4, 5, 6]]);

    // The frame of LTP pty04: the identifier 1, 8 bytes of `_`, and zero padding.
    let line = b"t00185f5f5f5f5f5f5f5f";
    let frame = slcan_decode(line).unwrap();
    assert_eq!(frame[..8], [1, 0, 0, 0, 8, 0, 0, 0]);
    assert_eq!(frame[8..], [b'_'; 8]);
    // The line that the device sends has uppercase digits, as `slc_encaps`.
    let mut out = Vec::new();
    assert!(slcan_encode(&frame, &mut out));
    assert_eq!(out, b"t00185F5F5F5F5F5F5F5F\r");
    assert_eq!(slcan_decode(&out[..out.len() - 1]), Some(frame));
    // An extended remote request has no data.
    let frame = slcan_decode(b"R123456782").unwrap();
    assert_eq!(u32::from_ne_bytes(frame[..4].try_into().unwrap()), 0xc000_0000 | 0x1234_5678);
    assert_eq!(frame[4], 2);
    out.clear();
    assert!(slcan_encode(&frame, &mut out));
    assert_eq!(out, b"R123456782\r");
    // Bad lines and frames.
    for line in [&b"x0011"[..], b"t0019", b"t00Z1aa", b"t0012aa", b"t001"] {
        assert_eq!(slcan_decode(line), None);
    }
    let mut bad = [0u8; 16];
    bad[4] = 9;
    assert!(!slcan_encode(&bad, &mut out));
    // A line ends at a carriage return or a bell. A short line goes away.
    let mut rx = LineRx::default();
    let lines: Vec<_> = b"t0010\rt01\x07r0020\x07".iter().filter_map(|&b| rx.slcan(b)).collect();
    assert_eq!(lines, [b"t0010".to_vec(), b"r0020".to_vec()]);
}

#[test]
fn slip_line_discipline() {
    use crate::netldisc::{N_SLCAN, N_SLIP, N_TTY};
    use crate::pty::{open_ptmx, open_slave, test_instance};
    use rk_abi::Errno;
    use rk_abi::native::ioctls::{TIOCGETD, TIOCSETD, TIOCSPTLCK, TIOCVHANGUP};
    use rk_abi::native::open::{O_NOCTTY, O_NONBLOCK};
    use rk_abi::native::sockios::SIOCGIFNAME;
    use rk_net::buf::NetBuf;
    use rk_net::consts::ARPHRD_SLIP;
    use rk_net::ether::{EthHeader, HLEN, MacAddr};
    use rk_vfs::File;

    let root = test_instance(b"").unwrap();
    let mem = Mem(core::cell::RefCell::new([0; 256]));
    let master = open_ptmx(&root).unwrap();
    let mf = File::with_ops(master.clone(), None, O_NONBLOCK);
    mem.set_int(0);
    assert_eq!(master.ioctl(&mf, TIOCSPTLCK, BASE, &mem), Ok(0));
    let slave = open_slave(&root, 0, O_NOCTTY).unwrap();
    let sf = File::with_ops(slave.clone(), None, O_NONBLOCK);

    // `N_TTY` has no network device. A number that is not a line discipline gives `EINVAL`.
    assert_eq!(slave.ioctl(&sf, SIOCGIFNAME, BASE, &mem), Err(Errno::ENOTTY));
    for n in [-1, 2, 31] {
        mem.set_int(n);
        assert_eq!(slave.ioctl(&sf, TIOCSETD, BASE, &mem), Err(Errno::EINVAL));
    }
    mem.set_int(N_SLIP);
    assert_eq!(slave.ioctl(&sf, TIOCSETD, BASE, &mem), Ok(0));
    assert_eq!(slave.ioctl(&sf, TIOCSETD, BASE, &mem), Ok(0));
    assert_eq!(slave.ioctl(&sf, TIOCGETD, BASE, &mem), Ok(0));
    assert_eq!(mem.int(), N_SLIP);
    // The master keeps `N_TTY`.
    assert_eq!(master.ioctl(&mf, TIOCGETD, BASE, &mem), Ok(0));
    assert_eq!(mem.int(), N_TTY);
    assert_eq!(slave.ioctl(&sf, SIOCGIFNAME, BASE, &mem), Ok(0));
    let name = mem.0.borrow().split(|&b| b == 0).next().unwrap().to_vec();
    let name = alloc::string::String::from_utf8(name).unwrap();
    assert!(name.starts_with("sl"));
    let dev = rk_net::dev::by_name(&name).unwrap();
    assert_eq!(dev.kind().arphrd(), ARPHRD_SLIP);
    assert_eq!(dev.mtu(), 296);
    let poll = || {
        let mut frames = Vec::new();
        dev.poll(8, &mut |_, f| frames.push(f.data()[HLEN..].to_vec()));
        frames
    };

    // A device that is down drops the bytes.
    assert_eq!(master.write(&mf, &[1, 2, 3, 0xc0]), Ok(4));
    assert!(poll().is_empty());
    dev.set_up(true);
    assert_eq!(master.write(&mf, &[1, 0xdb, 0xdc, 2]), Ok(4));
    assert_eq!(master.write(&mf, &[0xc0]), Ok(1));
    assert_eq!(poll(), [alloc::vec![1, 0xc0, 2]]);
    // A frame that the device sends goes to the master.
    let mut frame = NetBuf::new(HLEN, 3);
    frame.put(3).copy_from_slice(&[5, 6, 7]);
    EthHeader { dst: MacAddr::ZERO, src: MacAddr::ZERO, ethertype: 0x800 }.push(&mut frame);
    assert_eq!(dev.transmit_from(frame, 0), Ok(()));
    let mut buf = [0u8; 16];
    assert_eq!(master.read(&mf, &mut buf), Ok(5));
    assert_eq!(buf[..5], [0xc0, 5, 6, 7, 0xc0]);
    // SLIP has no read and no write for the slave.
    assert_eq!(slave.read(&sf, &mut buf), Err(Errno::EIO));
    assert_eq!(slave.write(&sf, b"x"), Err(Errno::EIO));

    // A change of the line discipline removes the device and makes a new one.
    mem.set_int(N_SLCAN);
    assert_eq!(slave.ioctl(&sf, TIOCSETD, BASE, &mem), Ok(0));
    assert!(rk_net::dev::by_name(&name).is_none());
    assert_eq!(slave.ioctl(&sf, SIOCGIFNAME, BASE, &mem), Ok(0));
    assert!(mem.0.borrow().starts_with(b"slcan"));
    // A hang up of the slave removes the device and gives the slave `N_TTY`.
    assert_eq!(slave.ioctl(&sf, TIOCVHANGUP, 0, &mem), Ok(0));
    let name = mem.0.borrow().split(|&b| b == 0).next().unwrap().to_vec();
    assert!(rk_net::dev::by_name(core::str::from_utf8(&name).unwrap()).is_none());
    let again = open_slave(&root, 0, O_NOCTTY).unwrap();
    let af = File::with_ops(again.clone(), None, O_NONBLOCK);
    assert_eq!(again.ioctl(&af, TIOCGETD, BASE, &mem), Ok(0));
    assert_eq!(mem.int(), N_TTY);
}

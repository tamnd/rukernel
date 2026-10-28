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
    use crate::pty::{open_ptmx, open_slave, slave_exists};
    use rk_abi::Errno;
    use rk_abi::native::ioctls::{
        TCGETA, TCGETS, TIOCGETD, TIOCGPTN, TIOCGWINSZ, TIOCSETD, TIOCSPTLCK, TIOCSWINSZ,
    };
    use rk_abi::native::open::O_NONBLOCK;
    use rk_vfs::File;

    let mem = Mem(core::cell::RefCell::new([0; 256]));
    let master = open_ptmx().unwrap();
    let mf = File::with_ops(master.clone(), None, O_NONBLOCK);
    // musl `openpty`: `TIOCSPTLCK` with 0, `TIOCGPTN`, and then the open of the slave.
    assert_eq!(master.ioctl(&mf, TIOCGPTN, BASE, &mem), Ok(0));
    let index = mem.int() as u32;
    assert!(slave_exists(index));
    assert_eq!(open_slave(index).err(), Some(Errno::EIO));
    mem.set_int(0);
    assert_eq!(master.ioctl(&mf, TIOCSPTLCK, BASE, &mem), Ok(0));
    let slave = open_slave(index).unwrap();
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
    let mut buf = [0u8; 32];
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
    let slave = open_slave(index).unwrap();
    let sf = File::with_ops(slave.clone(), None, O_NONBLOCK);
    // After the close of the master, the slave file goes away and the slave hangs up.
    drop(mf);
    drop(master);
    assert!(!slave_exists(index));
    assert_eq!(open_slave(index).err(), Some(Errno::ENXIO));
    assert_eq!(slave.read(&sf, &mut buf), Ok(0));
    assert_eq!(slave.write(&sf, b"x"), Err(Errno::EIO));
}

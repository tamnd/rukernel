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

use super::{Options, Timeout};
use rk_abi::Errno;
use rk_abi::native::socket::{
    SO_BUSY_POLL, SO_KEEPALIVE, SO_RCVBUF, SO_RCVTIMEO_OLD, SO_SNDBUF, SO_TYPE,
};

fn timeval(sec: i64, usec: i64) -> [u8; 16] {
    let mut v = [0; 16];
    v[..8].copy_from_slice(&sec.to_ne_bytes());
    v[8..].copy_from_slice(&usec.to_ne_bytes());
    v
}

#[test]
fn buffer_sizes_are_doubled_and_clamped() {
    let mut o = Options::default();
    o.set(SO_SNDBUF, &1000_i32.to_ne_bytes()).ok();
    assert_eq!(o.sndbuf, 4608);
    o.set(SO_RCVBUF, &50_000_i32.to_ne_bytes()).ok();
    assert_eq!(o.rcvbuf, 100_000);
    o.set(SO_SNDBUF, &i32::MAX.to_ne_bytes()).ok();
    assert_eq!(o.sndbuf, 425_984);
}

#[test]
fn flags_keep_zero_or_one() {
    let mut o = Options::default();
    assert_eq!(o.get(SO_KEEPALIVE), Ok(0_i32.to_ne_bytes().to_vec()));
    assert_eq!(o.set(SO_KEEPALIVE, &7_i32.to_ne_bytes()), Ok(()));
    assert_eq!(o.get(SO_KEEPALIVE), Ok(1_i32.to_ne_bytes().to_vec()));
    assert_eq!(o.set(SO_KEEPALIVE, &[1]), Err(Errno::EINVAL));
}

#[test]
fn unknown_option_is_enoprotoopt() {
    let mut o = Options::default();
    assert_eq!(o.get(SO_TYPE), Err(Errno::ENOPROTOOPT));
    assert_eq!(o.set(SO_TYPE, &1_i32.to_ne_bytes()), Err(Errno::ENOPROTOOPT));
}

#[test]
fn timeouts() {
    let mut o = Options::default();
    assert_eq!(o.rcvtimeo.ticks(), None);
    assert_eq!(o.set(SO_RCVTIMEO_OLD, &timeval(0, 1_000_000)), Err(Errno::EDOM));
    assert_eq!(o.set(SO_RCVTIMEO_OLD, &[0; 8]), Err(Errno::EINVAL));
    assert_eq!(o.set(SO_RCVTIMEO_OLD, &timeval(2, 5)), Ok(()));
    assert_eq!(o.rcvtimeo.ticks(), Some(201));
    assert_eq!(o.get(SO_RCVTIMEO_OLD), Ok(timeval(2, 5).to_vec()));
    assert_eq!(o.set(SO_RCVTIMEO_OLD, &timeval(-1, 0)), Ok(()));
    assert_eq!(o.rcvtimeo.ticks(), Some(1));
    assert_eq!(Timeout::default().ticks(), None);
}

/// `SO_BUSY_POLL` keeps a time that is not negative, as `sk_setsockopt` of Linux.
#[test]
fn busy_poll() {
    let mut o = Options::default();
    assert_eq!(o.get(SO_BUSY_POLL), Ok(0_i32.to_ne_bytes().to_vec()));
    assert_eq!(o.set(SO_BUSY_POLL, &50_i32.to_ne_bytes()), Ok(()));
    assert_eq!(o.get(SO_BUSY_POLL), Ok(50_i32.to_ne_bytes().to_vec()));
    assert_eq!(o.set(SO_BUSY_POLL, &(-1_i32).to_ne_bytes()), Err(Errno::EINVAL));
    assert_eq!(o.get(SO_BUSY_POLL), Ok(50_i32.to_ne_bytes().to_vec()));
}

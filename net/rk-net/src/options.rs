//! The options of the level `SOL_SOCKET` that each family shares, as `sk_setsockopt` and
//! `sk_getsockopt` of net/core/sock.c have them.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::socket::{
    SO_BROADCAST, SO_DEBUG, SO_DONTROUTE, SO_KEEPALIVE, SO_LINGER, SO_MARK, SO_NO_CHECK,
    SO_OOBINLINE, SO_PRIORITY, SO_RCVBUF, SO_RCVBUFFORCE, SO_RCVLOWAT, SO_RCVTIMEO_NEW,
    SO_RCVTIMEO_OLD, SO_REUSEADDR, SO_REUSEPORT, SO_SNDBUF, SO_SNDBUFFORCE, SO_SNDTIMEO_NEW,
    SO_SNDTIMEO_OLD, SO_TIMESTAMP_NEW, SO_TIMESTAMP_OLD, SO_TIMESTAMPNS_NEW, SO_TIMESTAMPNS_OLD,
};
use rk_vfs::inode::Result;

/// The defaults and the limits of the buffer sizes: `net.core.wmem_default`, `wmem_max`,
/// `rmem_default` and `rmem_max`.
const WMEM_DEFAULT: u32 = 212_992;
const WMEM_MAX: u32 = 212_992;
const RMEM_DEFAULT: u32 = 212_992;
const RMEM_MAX: u32 = 212_992;
/// The smallest buffers, `SOCK_MIN_SNDBUF` and `SOCK_MIN_RCVBUF` of Linux.
const MIN_SNDBUF: u32 = 4608;
const MIN_RCVBUF: u32 = 2304;

/// The ticks of the timer each second, for the timeouts.
fn hz() -> u64 {
    #[cfg(target_os = "none")]
    {
        rk_frame::time::HZ
    }
    #[cfg(not(target_os = "none"))]
    {
        100
    }
}

/// The ticks of the timer since boot. The host has no timer.
pub(crate) fn now() -> u64 {
    #[cfg(target_os = "none")]
    {
        rk_frame::time::ticks()
    }
    #[cfg(not(target_os = "none"))]
    {
        0
    }
}

/// The timeout of `SO_RCVTIMEO` or `SO_SNDTIMEO`, as a `struct timeval`. Zero is no timeout.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timeout {
    sec: i64,
    usec: i64,
}

impl Timeout {
    /// The timeout in ticks of the timer, or `None` for no timeout. A timeout that is not 0
    /// is at least one tick.
    pub fn ticks(self) -> Option<u64> {
        if self.sec == 0 && self.usec == 0 {
            return None;
        }
        let hz = hz();
        let t = (self.sec as u64).saturating_mul(hz) + (self.usec as u64 * hz).div_ceil(1_000_000);
        Some(t.max(1))
    }

    fn parse(value: &[u8]) -> Result<Self> {
        let Some((sec, rest)) = value.split_first_chunk::<8>() else {
            return Err(Errno::EINVAL);
        };
        let Some((usec, _)) = rest.split_first_chunk::<8>() else {
            return Err(Errno::EINVAL);
        };
        let (sec, usec) = (i64::from_ne_bytes(*sec), i64::from_ne_bytes(*usec));
        if !(0..1_000_000).contains(&usec) {
            return Err(Errno::EDOM);
        }
        // A time before 0 is no wait, as `sock_set_timeout` of Linux gives it.
        if sec < 0 {
            return Ok(Self { sec: 0, usec: 1 });
        }
        Ok(Self { sec, usec })
    }

    fn bytes(self) -> Vec<u8> {
        let mut v = Vec::with_capacity(16);
        v.extend_from_slice(&self.sec.to_ne_bytes());
        v.extend_from_slice(&self.usec.to_ne_bytes());
        v
    }
}

/// The options of one socket.
#[derive(Debug)]
pub struct Options {
    /// The size of the send buffer.
    pub sndbuf: u32,
    /// The size of the receive buffer.
    pub rcvbuf: u32,
    /// The timeout of a receive.
    pub rcvtimeo: Timeout,
    /// The timeout of a send.
    pub sndtimeo: Timeout,
    /// The other options that keep an integer. A flag keeps 0 or 1.
    ints: BTreeMap<u32, i32>,
    /// `SO_LINGER`: the flag and the time.
    linger: (i32, i32),
}

impl Default for Options {
    fn default() -> Self {
        Self {
            sndbuf: WMEM_DEFAULT,
            rcvbuf: RMEM_DEFAULT,
            rcvtimeo: Timeout::default(),
            sndtimeo: Timeout::default(),
            ints: BTreeMap::new(),
            linger: (0, 0),
        }
    }
}

/// The options that keep 0 or 1.
const FLAGS: &[u32] = &[
    SO_DEBUG,
    SO_REUSEADDR,
    SO_REUSEPORT,
    SO_DONTROUTE,
    SO_BROADCAST,
    SO_KEEPALIVE,
    SO_OOBINLINE,
    SO_NO_CHECK,
    SO_TIMESTAMP_OLD,
    SO_TIMESTAMP_NEW,
    SO_TIMESTAMPNS_OLD,
    SO_TIMESTAMPNS_NEW,
];

/// Reads an `int` value. A shorter value gives `EINVAL`, as Linux.
pub(crate) fn int_of(value: &[u8]) -> Result<i32> {
    let Some((v, _)) = value.split_first_chunk::<4>() else {
        return Err(Errno::EINVAL);
    };
    Ok(i32::from_ne_bytes(*v))
}

/// The bytes of an `int` value.
fn int(v: i32) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

impl Options {
    /// Sets the option `name` of the level `SOL_SOCKET`. Gives `ENOPROTOOPT` for an option that
    /// is not here.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` for a short value, `EDOM` for a bad time, or `ENOPROTOOPT`.
    pub fn set(&mut self, name: u32, value: &[u8]) -> Result<()> {
        match name {
            SO_RCVTIMEO_OLD | SO_RCVTIMEO_NEW => self.rcvtimeo = Timeout::parse(value)?,
            SO_SNDTIMEO_OLD | SO_SNDTIMEO_NEW => self.sndtimeo = Timeout::parse(value)?,
            SO_LINGER => {
                let Some((on, rest)) = value.split_first_chunk::<4>() else {
                    return Err(Errno::EINVAL);
                };
                let Some((time, _)) = rest.split_first_chunk::<4>() else {
                    return Err(Errno::EINVAL);
                };
                self.linger = (i32::from(i32::from_ne_bytes(*on) != 0), i32::from_ne_bytes(*time));
            }
            _ => {
                let v = int_of(value)?;
                match name {
                    SO_SNDBUF | SO_SNDBUFFORCE => {
                        let max = if name == SO_SNDBUF { WMEM_MAX } else { i32::MAX as u32 / 2 };
                        let v = (v.max(0) as u32).min(max);
                        self.sndbuf = (v * 2).max(MIN_SNDBUF);
                    }
                    SO_RCVBUF | SO_RCVBUFFORCE => {
                        let max = if name == SO_RCVBUF { RMEM_MAX } else { i32::MAX as u32 / 2 };
                        let v = (v.max(0) as u32).min(max);
                        self.rcvbuf = (v * 2).max(MIN_RCVBUF);
                    }
                    SO_RCVLOWAT => {
                        self.ints.insert(name, v.max(1));
                    }
                    SO_PRIORITY | SO_MARK => {
                        self.ints.insert(name, v);
                    }
                    _ if FLAGS.contains(&name) => {
                        self.ints.insert(name, i32::from(v != 0));
                    }
                    _ => return Err(Errno::ENOPROTOOPT),
                }
            }
        }
        Ok(())
    }

    /// Gives the option `name` of the level `SOL_SOCKET`. Gives `ENOPROTOOPT` for an option that
    /// is not here.
    ///
    /// # Errors
    ///
    /// Gives `ENOPROTOOPT`.
    pub fn get(&self, name: u32) -> Result<Vec<u8>> {
        Ok(match name {
            SO_RCVTIMEO_OLD | SO_RCVTIMEO_NEW => self.rcvtimeo.bytes(),
            SO_SNDTIMEO_OLD | SO_SNDTIMEO_NEW => self.sndtimeo.bytes(),
            SO_LINGER => {
                let mut v = int(self.linger.0);
                v.extend_from_slice(&self.linger.1.to_ne_bytes());
                v
            }
            SO_SNDBUF => int(self.sndbuf as i32),
            SO_RCVBUF => int(self.rcvbuf as i32),
            SO_RCVLOWAT => int(self.ints.get(&name).copied().unwrap_or(1)),
            SO_PRIORITY | SO_MARK => int(self.ints.get(&name).copied().unwrap_or(0)),
            _ if FLAGS.contains(&name) => int(self.ints.get(&name).copied().unwrap_or(0)),
            _ => return Err(Errno::ENOPROTOOPT),
        })
    }
}

//! The address of an IPv4 socket, `struct sockaddr_in`: the family in the byte order of the
//! machine, the port and the address in network byte order, and 8 bytes of zeros.

use crate::ipv4::{self, Addr};
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_net::consts::{AF_INET, AF_UNSPEC};
use rk_vfs::inode::Result;

/// The size of `struct sockaddr_in`.
pub const LEN: usize = 16;

fn family(a: &[u8]) -> Option<u32> {
    a.first_chunk::<2>().map(|f| u32::from(u16::from_ne_bytes(*f)))
}

/// The address and the port of `a`. The caller checks the length and the family.
fn fields(a: &[u8]) -> (Addr, u16) {
    (Addr::try_from(&a[4..8]).unwrap_or_default(), u16::from_be_bytes([a[2], a[3]]))
}

/// Reads the address of `bind`, as `inet_bind_sk` of Linux. `AF_UNSPEC` with `0.0.0.0` is the
/// same as `AF_INET`, for old programs.
///
/// # Errors
///
/// Gives `EINVAL` for a short address and `EAFNOSUPPORT` for another family.
pub fn parse_bind(a: &[u8]) -> Result<(Addr, u16)> {
    if a.len() < LEN {
        return Err(Errno::EINVAL);
    }
    let (addr, port) = fields(a);
    match family(a) {
        Some(AF_INET) => Ok((addr, port)),
        Some(AF_UNSPEC) if addr == ipv4::ANY => Ok((addr, port)),
        _ => Err(Errno::EAFNOSUPPORT),
    }
}

/// Reads the address of `connect`, as `inet_dgram_connect` of Linux. `AF_UNSPEC` gives `None`:
/// remove the peer.
///
/// # Errors
///
/// Gives `EINVAL` for a short address and `EAFNOSUPPORT` for another family.
pub fn parse_connect(a: &[u8]) -> Result<Option<(Addr, u16)>> {
    match family(a) {
        None => Err(Errno::EINVAL),
        Some(AF_UNSPEC) => Ok(None),
        Some(_) if a.len() < LEN => Err(Errno::EINVAL),
        Some(AF_INET) => Ok(Some(fields(a))),
        Some(_) => Err(Errno::EAFNOSUPPORT),
    }
}

/// Reads the address of `sendto` and `sendmsg`, as `udp_sendmsg` of Linux. `AF_UNSPEC` is the
/// same as `AF_INET`.
///
/// # Errors
///
/// Gives `EINVAL` for a short address and `EAFNOSUPPORT` for another family.
pub fn parse_send(a: &[u8]) -> Result<Option<(Addr, u16)>> {
    if a.len() < LEN {
        return Err(Errno::EINVAL);
    }
    match family(a) {
        Some(AF_INET | AF_UNSPEC) => Ok(Some(fields(a))),
        _ => Err(Errno::EAFNOSUPPORT),
    }
}

/// The bytes of the address `addr` with the port `port`.
pub fn make(addr: Addr, port: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(LEN);
    v.extend_from_slice(&(AF_INET as u16).to_ne_bytes());
    v.extend_from_slice(&port.to_be_bytes());
    v.extend_from_slice(&addr);
    v.extend_from_slice(&[0; 8]);
    v
}

/// The port of the address `a` of `bind`, for the check of `CAP_NET_BIND_SERVICE` in the
/// system call layer. Gives `None` for a short address.
pub fn port_of(a: &[u8]) -> Option<u16> {
    let a = a.get(..LEN)?;
    Some(u16::from_be_bytes([a[2], a[3]]))
}

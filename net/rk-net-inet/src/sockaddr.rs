//! The address of an IPv4 socket, `struct sockaddr_in`: the family in the byte order of the
//! machine, the port and the address in network byte order, and 8 bytes of zeros. And the
//! address of an IPv6 socket, `struct sockaddr_in6`: the family, the port, the flow information,
//! the address and the scope ID.
//!
//! The functions with the suffix `_in` take the family of the socket and give an address of
//! `ip`: an IPv4 address is IPv4-mapped.

use crate::ip::{self, Ip};
use crate::ipv4::{self, Addr};
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_net::consts::{AF_INET, AF_INET6, AF_UNSPEC};
use rk_vfs::inode::Result;

/// The size of `struct sockaddr_in`.
pub const LEN: usize = 16;
/// The size of `struct sockaddr_in6`.
pub const LEN6: usize = 28;
/// The size of `struct sockaddr_in6` of RFC 2133, without the scope ID, `SIN6_LEN_RFC2133`.
pub const RFC2133: usize = 24;

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
    let a = a.get(..4)?;
    Some(u16::from_be_bytes([a[2], a[3]]))
}

/// An address of a socket of either family: the address, the port and the scope ID.
pub type InAddr = (Ip, u16, u32);

/// The address, the port and the scope ID of the IPv6 address `a`. The caller checks the
/// length and the family. An address of RFC 2133 has no scope ID.
fn fields6(a: &[u8]) -> InAddr {
    let addr = Ip::try_from(&a[8..24]).unwrap_or_default();
    let scope = a.get(24..28).map_or(0, |s| u32::from_ne_bytes([s[0], s[1], s[2], s[3]]));
    (addr, u16::from_be_bytes([a[2], a[3]]), scope)
}

/// Reads the address of `bind` for a socket of the family `af`, as `inet6_bind_sk` of Linux.
///
/// # Errors
///
/// Gives `EINVAL` for a short address and `EAFNOSUPPORT` for another family.
pub fn parse_bind_in(af: u32, a: &[u8]) -> Result<InAddr> {
    if af == AF_INET {
        let (addr, port) = parse_bind(a)?;
        return Ok((ip::mapped(addr), port, 0));
    }
    if a.len() < RFC2133 {
        return Err(Errno::EINVAL);
    }
    match family(a) {
        Some(AF_INET6) => Ok(fields6(a)),
        _ => Err(Errno::EAFNOSUPPORT),
    }
}

/// Reads the address of `connect` for a datagram socket of the family `af`, as
/// `ip6_datagram_connect` of Linux. `AF_UNSPEC` gives `None`: remove the peer. An IPv6 socket
/// takes an `AF_INET` address as an IPv4-mapped address.
///
/// # Errors
///
/// Gives `EINVAL` for a short address and `EAFNOSUPPORT` for another family.
pub fn parse_connect_in(af: u32, a: &[u8]) -> Result<Option<InAddr>> {
    if af == AF_INET {
        return Ok(parse_connect(a)?.map(|(addr, port)| (ip::mapped(addr), port, 0)));
    }
    match family(a) {
        None => Err(Errno::EINVAL),
        Some(AF_UNSPEC) => Ok(None),
        Some(AF_INET) if a.len() < LEN => Err(Errno::EINVAL),
        Some(AF_INET) => {
            let (addr, port) = fields(a);
            Ok(Some((ip::mapped(addr), port, 0)))
        }
        Some(_) if a.len() < RFC2133 => Err(Errno::EINVAL),
        Some(AF_INET6) => Ok(Some(fields6(a))),
        Some(_) => Err(Errno::EAFNOSUPPORT),
    }
}

/// Reads the address of `sendto` and `sendmsg` for a socket of the family `af`, as
/// `udpv6_sendmsg` of Linux. `None` is the peer of the socket: an IPv6 socket takes
/// `AF_UNSPEC` as no address.
///
/// # Errors
///
/// Gives `EINVAL` for a short address or another family on an IPv6 socket, and the errors of
/// `parse_send` on an IPv4 socket.
pub fn parse_send_in(af: u32, a: &[u8]) -> Result<Option<InAddr>> {
    if af == AF_INET {
        return Ok(parse_send(a)?.map(|(addr, port)| (ip::mapped(addr), port, 0)));
    }
    match family(a) {
        None => Err(Errno::EINVAL),
        Some(AF_UNSPEC) => Ok(None),
        Some(AF_INET) if a.len() < LEN => Err(Errno::EINVAL),
        Some(AF_INET) => {
            let (addr, port) = fields(a);
            Ok(Some((ip::mapped(addr), port, 0)))
        }
        Some(AF_INET6) if a.len() >= RFC2133 => Ok(Some(fields6(a))),
        _ => Err(Errno::EINVAL),
    }
}

/// The bytes of the address `addr` with the port `port` for a socket of the family `af`. An
/// IPv6 socket gives an IPv4 address as an IPv4-mapped address, as Linux does.
pub fn make_in(af: u32, addr: &Ip, port: u16, scope: u32) -> Vec<u8> {
    if af == AF_INET {
        return make(ip::v4(addr).unwrap_or(ipv4::ANY), port);
    }
    let mut v = Vec::with_capacity(LEN6);
    v.extend_from_slice(&(AF_INET6 as u16).to_ne_bytes());
    v.extend_from_slice(&port.to_be_bytes());
    v.extend_from_slice(&[0; 4]);
    v.extend_from_slice(addr);
    v.extend_from_slice(&scope.to_ne_bytes());
    v
}

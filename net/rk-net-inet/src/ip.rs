//! The address of a socket of both families. A socket keeps an IPv4 address as an IPv4-mapped
//! IPv6 address `::ffff:a.b.c.d`, as Linux does for a dual stack socket. Thus the tables of the
//! ports and of the TCP connections have one key for IPv4 and IPv6, and an `AF_INET6` socket
//! without `IPV6_V6ONLY` takes IPv4 packets too.

use crate::ipv4::{self, Addr};

/// An IPv6 address in network byte order, or an IPv4-mapped address.
pub type Ip = [u8; 16];

/// The IPv6 address `::`, `in6addr_any`.
pub const ANY: Ip = [0; 16];
/// The IPv6 address `::1`, `in6addr_loopback`.
pub const LOOPBACK: Ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// The IPv4 address `0.0.0.0` as a mapped address: each IPv4 address.
pub const V4_ANY: Ip = mapped(ipv4::ANY);

/// The IPv4-mapped address of `a`.
pub const fn mapped(a: Addr) -> Ip {
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a[0], a[1], a[2], a[3]]
}

/// The IPv4 address in `a`, if `a` is an IPv4-mapped address.
pub fn v4(a: &Ip) -> Option<Addr> {
    (a[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]).then(|| [a[12], a[13], a[14], a[15]])
}

/// Tells if `a` is a wildcard: `::` or `0.0.0.0`.
pub fn is_any(a: &Ip) -> bool {
    *a == ANY || *a == V4_ANY
}

/// Tells if a socket with the local address `bound` and the flag `v6only` takes a packet to
/// `dst`, as the address checks of `compute_score` and `inet6_rcv_saddr_equal` of Linux.
pub fn takes(bound: &Ip, v6only: bool, dst: &Ip) -> bool {
    if bound == dst {
        return true;
    }
    match v4(dst) {
        Some(_) => *bound == V4_ANY || (*bound == ANY && !v6only),
        None => *bound == ANY,
    }
}

/// Tells if two bound addresses of one port overlap, as `inet_rcv_saddr_equal` of Linux. The
/// address `::` without `IPV6_V6ONLY` takes each IPv4 and each IPv6 address.
pub fn overlap(a: &Ip, a_v6only: bool, b: &Ip, b_v6only: bool) -> bool {
    takes(a, a_v6only, b) || takes(b, b_v6only, a)
}

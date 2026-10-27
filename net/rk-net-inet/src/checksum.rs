//! The Internet checksum of RFC 1071, as net/core/utils.c and the `csum_*` functions of Linux.

/// Adds the 16-bit words of `data` to `sum`, in network byte order. An odd last byte is the
/// high byte of a word.
pub fn add(mut sum: u32, data: &[u8]) -> u32 {
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes(*w)));
        // Fold early, so that a long packet does not overflow the sum.
        sum = (sum & 0xffff) + (sum >> 16);
    }
    if let [last] = rest {
        sum = sum.wrapping_add(u32::from(*last) << 8);
    }
    sum
}

/// Folds `sum` to 16 bits and gives the complement, as `csum_fold` of Linux.
pub fn fold(mut sum: u32) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The checksum of `data`. A packet with a correct checksum field gives 0.
pub fn checksum(data: &[u8]) -> u16 {
    fold(add(0, data))
}

/// The sum of the pseudo header of UDP and TCP, as `csum_tcpudp_nofold` of Linux.
pub fn pseudo(src: [u8; 4], dst: [u8; 4], protocol: u8, len: u16) -> u32 {
    let sum = add(add(0, &src), &dst);
    sum + u32::from(protocol) + u32::from(len)
}

/// The checksum of a UDP datagram `udp` (the header and the data) from `src` to `dst`. The
/// value 0 means "no checksum" in UDP, thus a sum of 0 gives `0xffff`, as RFC 768.
pub fn udp(src: [u8; 4], dst: [u8; 4], udp: &[u8]) -> u16 {
    let len = u16::try_from(udp.len()).unwrap_or(u16::MAX);
    let sum = fold(add(pseudo(src, dst, crate::ipv4::PROTO_UDP, len), udp));
    if sum == 0 { 0xffff } else { sum }
}

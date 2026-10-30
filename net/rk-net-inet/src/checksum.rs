//! The Internet checksum of RFC 1071, as net/core/utils.c and the `csum_*` functions of Linux.

use zerocopy::FromBytes;

/// Adds the 16-bit words of `data` to `sum`, in network byte order. An odd last byte is the
/// high byte of a word.
///
/// The middle of `data` goes in aligned 64-bit words, as `do_csum` of Linux. The sum of the
/// 16-bit words does not depend on the byte order, except for a swap of the two bytes of the
/// result (RFC 1071 section 2). A part that starts at an odd offset gets a swap too. The words
/// must be aligned: the arm64 target has `strict-align`, so a load of a word that is not known
/// to be aligned is 8 loads of single bytes. A loop of 16-bit words used about 4 instructions
/// for each byte, and on QEMU without KVM the checksums were a large part of the time of the TCP
/// stream on loopback (#465).
pub fn add(sum: u32, data: &[u8]) -> u32 {
    let skip = data.as_ptr().align_offset(8).min(data.len());
    let (head, rest) = data.split_at(skip);
    let (body, tail) = rest.split_at(rest.len() / 8 * 8);
    let odd = head.len() % 2 == 1;
    let swap = |v: u16| if odd { v.swap_bytes() } else { v };
    let total = u64::from(sum)
        + u64::from(add_bytes(head))
        + u64::from(swap(add_words(body)))
        + u64::from(swap(add_bytes(tail)));
    fold16(total)
}

/// The sum of the 16-bit words of `body`, in network byte order, folded to 16 bits. The length
/// of `body` is a multiple of 8.
fn add_words(body: &[u8]) -> u16 {
    let mut acc = 0u64;
    let mut add = |w: u64| {
        let (s, carry) = acc.overflowing_add(w);
        acc = s + u64::from(carry);
    };
    match <[u64]>::ref_from_bytes(body) {
        Ok(words) => words.iter().for_each(|&w| add(w)),
        // Not aligned: this does not occur, because `add` aligns `body`.
        Err(_) => body.as_chunks::<8>().0.iter().for_each(|w| add(u64::from_ne_bytes(*w))),
    }
    // The sum of the 16-bit words in the byte order of the CPU, then in network byte order.
    u16::from_be(fold16((acc & 0xffff_ffff) + (acc >> 32)) as u16)
}

/// Folds a sum to 16 bits with the end-around carry, as `fold` does, but with no complement.
fn fold16(mut sum: u64) -> u32 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u32
}

/// The sum of the 16-bit words of `data`, in network byte order, folded to 16 bits.
fn add_bytes(data: &[u8]) -> u16 {
    let (words, rest) = data.as_chunks::<2>();
    let mut sum = 0u64;
    for w in words {
        sum += u64::from(u16::from_be_bytes(*w));
    }
    if let [last] = rest {
        sum += u64::from(*last) << 8;
    }
    fold16(sum) as u16
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

/// The sum of the pseudo header of RFC 8200 for an upper layer packet of `len` bytes, as
/// `csum_ipv6_magic` of Linux. Two IPv4-mapped addresses give the pseudo header of IPv4, for
/// the packets of a dual stack socket.
pub fn pseudo_ip(src: &crate::ip::Ip, dst: &crate::ip::Ip, protocol: u8, len: u32) -> u32 {
    if let (Some(s), Some(d)) = (crate::ip::v4(src), crate::ip::v4(dst)) {
        return pseudo(s, d, protocol, len as u16);
    }
    let sum = add(add(0, src), dst);
    // The length is a field of 32 bits: its two words go in the sum.
    sum + (len >> 16) + (len & 0xffff) + u32::from(protocol)
}

/// The checksum of the upper layer packet `data` from `src` to `dst`, with the pseudo header
/// of `pseudo_ip`.
pub fn upper(src: &crate::ip::Ip, dst: &crate::ip::Ip, protocol: u8, data: &[u8]) -> u16 {
    fold(add(pseudo_ip(src, dst, protocol, data.len() as u32), data))
}

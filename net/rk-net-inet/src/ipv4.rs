//! The IPv4 header of RFC 791, as `struct iphdr` of Linux and the checks of `ip_rcv_core` in
//! net/ipv4/ip_input.c.

use crate::checksum;

/// The length of a header without options.
pub const HLEN: usize = 20;
/// The protocol number of ICMP.
pub const PROTO_ICMP: u8 = 1;
/// The protocol number of TCP.
pub const PROTO_TCP: u8 = 6;
/// The protocol number of UDP.
pub const PROTO_UDP: u8 = 17;
/// The default time to live, `net.ipv4.ip_default_ttl` of Linux.
pub const DEFAULT_TTL: u8 = 64;
/// The flag "do not fragment" in the field of the fragment offset.
pub const DF: u16 = 0x4000;
/// The flag "more fragments".
pub const MF: u16 = 0x2000;
/// The bits of the fragment offset.
pub const OFFSET_MASK: u16 = 0x1fff;
/// The largest packet.
pub const MAX_LEN: usize = 65535;

/// An IPv4 address in network byte order.
pub type Addr = [u8; 4];

/// The address `0.0.0.0`, `INADDR_ANY`.
pub const ANY: Addr = [0; 4];
/// The address `255.255.255.255`, `INADDR_BROADCAST`.
pub const BROADCAST: Addr = [255; 4];
/// The address `127.0.0.1`, `INADDR_LOOPBACK`.
pub const LOOPBACK: Addr = [127, 0, 0, 1];

/// Tells if `a` is a multicast address, 224.0.0.0/4.
pub fn is_multicast(a: Addr) -> bool {
    a[0] & 0xf0 == 0xe0
}

/// Tells if `a` is in 127.0.0.0/8.
pub fn is_loopback(a: Addr) -> bool {
    a[0] == 127
}

/// The mask of a prefix of `len` bits.
pub fn mask(len: u8) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - u32::from(len.min(32))) }
}

/// Tells if `a` and `b` have the same first `len` bits.
pub fn same_net(a: Addr, b: Addr, len: u8) -> bool {
    (u32::from_be_bytes(a) ^ u32::from_be_bytes(b)) & mask(len) == 0
}

/// The first `len` bits of `a`, with the other bits zero.
pub fn prefix(a: Addr, len: u8) -> Addr {
    (u32::from_be_bytes(a) & mask(len)).to_be_bytes()
}

/// The reasons that the input drops a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bad {
    /// The packet is shorter than its header, or the header is not IPv4.
    Header,
    /// The checksum of the header is wrong.
    Checksum,
    /// The total length is not in the frame.
    Length,
}

/// An IPv4 header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The length of the header in bytes, with the options.
    pub hlen: usize,
    /// The type of service.
    pub tos: u8,
    /// The length of the packet, with the header.
    pub total_len: u16,
    /// The identification of the packet, for the fragments.
    pub id: u16,
    /// The flags and the fragment offset.
    pub frag: u16,
    /// The time to live.
    pub ttl: u8,
    /// The protocol of the payload.
    pub protocol: u8,
    /// The source address.
    pub src: Addr,
    /// The destination address.
    pub dst: Addr,
}

impl Header {
    /// A header without options for a payload of `payload` bytes.
    pub fn new(src: Addr, dst: Addr, protocol: u8, payload: usize) -> Self {
        Self {
            hlen: HLEN,
            tos: 0,
            total_len: (HLEN + payload).min(MAX_LEN) as u16,
            id: 0,
            frag: DF,
            ttl: DEFAULT_TTL,
            protocol,
            src,
            dst,
        }
    }

    /// Reads and checks the header of `packet`, as `ip_rcv_core` of Linux: the version is 4, the
    /// header length is at least 20, the checksum is right and the total length is in the
    /// packet. A fragment is valid too: `is_fragment` tells it.
    pub fn parse(packet: &[u8]) -> Result<Self, Bad> {
        let p = packet.get(..HLEN).ok_or(Bad::Header)?;
        let hlen = usize::from(p[0] & 0xf) * 4;
        if p[0] >> 4 != 4 || hlen < HLEN {
            return Err(Bad::Header);
        }
        let header = packet.get(..hlen).ok_or(Bad::Header)?;
        if checksum::checksum(header) != 0 {
            return Err(Bad::Checksum);
        }
        let be16 = |at: usize| u16::from_be_bytes([p[at], p[at + 1]]);
        let total_len = be16(2);
        if usize::from(total_len) > packet.len() || usize::from(total_len) < hlen {
            return Err(Bad::Length);
        }
        let frag = be16(6);
        Ok(Self {
            hlen,
            tos: p[1],
            total_len,
            id: be16(4),
            frag,
            ttl: p[8],
            protocol: p[9],
            src: [p[12], p[13], p[14], p[15]],
            dst: [p[16], p[17], p[18], p[19]],
        })
    }

    /// Reads the fields of a header without the checks of `parse`, for the start of a packet in
    /// an ICMP error and for a packet that a raw socket gives. Gives `None` if the start is not
    /// an IPv4 header.
    pub fn parse_loose(packet: &[u8]) -> Option<Self> {
        let p = packet.get(..HLEN)?;
        let hlen = usize::from(p[0] & 0xf) * 4;
        if p[0] >> 4 != 4 || hlen < HLEN || hlen > packet.len() {
            return None;
        }
        let be16 = |at: usize| u16::from_be_bytes([p[at], p[at + 1]]);
        Some(Self {
            hlen,
            tos: p[1],
            total_len: be16(2),
            id: be16(4),
            frag: be16(6),
            ttl: p[8],
            protocol: p[9],
            src: [p[12], p[13], p[14], p[15]],
            dst: [p[16], p[17], p[18], p[19]],
        })
    }

    /// Tells if the packet is a fragment: it has the flag "more fragments" or an offset.
    pub fn is_fragment(&self) -> bool {
        self.frag & (MF | OFFSET_MASK) != 0
    }

    /// The offset of the data of a fragment in the packet, in bytes.
    pub fn frag_offset(&self) -> usize {
        usize::from(self.frag & OFFSET_MASK) * 8
    }

    /// The bytes of the header without options, with the checksum.
    pub fn to_bytes(&self) -> [u8; HLEN] {
        let mut p = [0; HLEN];
        p[0] = 0x45;
        p[1] = self.tos;
        p[2..4].copy_from_slice(&self.total_len.to_be_bytes());
        p[4..6].copy_from_slice(&self.id.to_be_bytes());
        p[6..8].copy_from_slice(&self.frag.to_be_bytes());
        p[8] = self.ttl;
        p[9] = self.protocol;
        p[12..16].copy_from_slice(&self.src);
        p[16..20].copy_from_slice(&self.dst);
        let sum = checksum::checksum(&p);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        p
    }
}

/// The header of a UDP datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpHeader {
    /// The source port.
    pub src: u16,
    /// The destination port.
    pub dst: u16,
    /// The length of the header and the data.
    pub len: u16,
    /// The checksum, or 0 for none.
    pub check: u16,
}

/// The length of a UDP header.
pub const UDP_HLEN: usize = 8;

impl UdpHeader {
    /// Reads the header. Gives `None` if the datagram is too short for the header or for its
    /// length field.
    pub fn parse(d: &[u8]) -> Option<Self> {
        let p = d.get(..UDP_HLEN)?;
        let be16 = |at: usize| u16::from_be_bytes([p[at], p[at + 1]]);
        let h = Self { src: be16(0), dst: be16(2), len: be16(4), check: be16(6) };
        if usize::from(h.len) < UDP_HLEN || usize::from(h.len) > d.len() {
            return None;
        }
        Some(h)
    }

    /// The bytes of the header.
    pub fn to_bytes(&self) -> [u8; UDP_HLEN] {
        let mut p = [0; UDP_HLEN];
        p[0..2].copy_from_slice(&self.src.to_be_bytes());
        p[2..4].copy_from_slice(&self.dst.to_be_bytes());
        p[4..6].copy_from_slice(&self.len.to_be_bytes());
        p[6..8].copy_from_slice(&self.check.to_be_bytes());
        p
    }
}

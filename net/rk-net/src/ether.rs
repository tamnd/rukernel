//! Ethernet addresses and the Ethernet header, from IEEE 802.3 and net/ethernet/eth.c of Linux.

use crate::buf::NetBuf;
use core::fmt;
use rk_abi::native::if_ether::{ETH_ALEN, ETH_HLEN};

/// The length of an Ethernet address.
const ALEN: usize = ETH_ALEN as usize;
/// The length of the Ethernet header.
pub const HLEN: usize = ETH_HLEN as usize;

/// An Ethernet address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; ALEN]);

impl MacAddr {
    /// The broadcast address.
    pub const BROADCAST: Self = Self([0xff; ALEN]);
    /// The address with all bits zero. The loopback device has it.
    pub const ZERO: Self = Self([0; ALEN]);

    /// Tells if the address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    /// Tells if the address is a multicast address. The broadcast address is one too.
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 1 != 0
    }
}

/// The form of `ip link`: six bytes in lower case hexadecimal with colons.
impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// The Ethernet header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthHeader {
    /// The address of the destination.
    pub dst: MacAddr,
    /// The address of the source.
    pub src: MacAddr,
    /// The protocol ID of the payload, for example `ETH_P_IP`.
    pub ethertype: u16,
}

impl EthHeader {
    /// Reads the header at the start of `frame`. Gives `None` if the frame is too short.
    pub fn parse(frame: &[u8]) -> Option<Self> {
        let h = frame.get(..HLEN)?;
        let mac = |at: usize| {
            let mut m = [0; ALEN];
            m.copy_from_slice(&h[at..at + ALEN]);
            MacAddr(m)
        };
        Some(Self {
            dst: mac(0),
            src: mac(ALEN),
            ethertype: u16::from_be_bytes([h[2 * ALEN], h[2 * ALEN + 1]]),
        })
    }

    /// The bytes of the header, in network byte order.
    pub fn to_bytes(&self) -> [u8; HLEN] {
        let mut h = [0; HLEN];
        h[..ALEN].copy_from_slice(&self.dst.0);
        h[ALEN..2 * ALEN].copy_from_slice(&self.src.0);
        h[2 * ALEN..].copy_from_slice(&self.ethertype.to_be_bytes());
        h
    }

    /// Puts the header before the data of `buf`, as `eth_header` of Linux.
    pub fn push(&self, buf: &mut NetBuf) {
        buf.push(HLEN).copy_from_slice(&self.to_bytes());
        buf.protocol = self.ethertype;
    }

    /// Removes the header from the start of `buf` and gives it, as `eth_type_trans` of Linux.
    /// Sets the protocol of the buffer. Gives `None` if the frame is too short.
    pub fn pull(buf: &mut NetBuf) -> Option<Self> {
        let h = Self::parse(buf.pull(HLEN)?)?;
        buf.protocol = h.ethertype;
        Some(h)
    }
}

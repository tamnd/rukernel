//! The ARP packet for IPv4 over Ethernet, from RFC 826 and net/ipv4/arp.c of Linux.
//!
//! This module only reads and writes the packet. The neighbour table and the replies to the
//! requests of other hosts come with the IPv4 stack.

use crate::buf::{HEADROOM, NetBuf};
use crate::consts::{ARPHRD_ETHER, ARPOP_REPLY, ARPOP_REQUEST};
use crate::ether::{EthHeader, MacAddr};
use rk_abi::native::if_ether::{ETH_ALEN, ETH_P_ARP, ETH_P_IP};

/// The length of an ARP packet for IPv4 over Ethernet.
pub const LEN: usize = 28;

/// An ARP packet for IPv4 over Ethernet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpPacket {
    /// The operation: `ARPOP_REQUEST` or `ARPOP_REPLY`.
    pub op: u16,
    /// The Ethernet address of the sender.
    pub sender_mac: MacAddr,
    /// The IPv4 address of the sender.
    pub sender_ip: [u8; 4],
    /// The Ethernet address of the target. A request has zeros here.
    pub target_mac: MacAddr,
    /// The IPv4 address of the target.
    pub target_ip: [u8; 4],
}

impl ArpPacket {
    /// A request for the Ethernet address of `target_ip`.
    pub fn request(sender_mac: MacAddr, sender_ip: [u8; 4], target_ip: [u8; 4]) -> Self {
        Self { op: ARPOP_REQUEST, sender_mac, sender_ip, target_mac: MacAddr::ZERO, target_ip }
    }

    /// Tells if the packet is a reply.
    pub fn is_reply(&self) -> bool {
        self.op == ARPOP_REPLY
    }

    /// Reads a packet. Gives `None` if the packet is too short or is not for IPv4 over Ethernet.
    pub fn parse(p: &[u8]) -> Option<Self> {
        let p = p.get(..LEN)?;
        let be16 = |at: usize| u16::from_be_bytes([p[at], p[at + 1]]);
        if be16(0) != ARPHRD_ETHER
            || u32::from(be16(2)) != ETH_P_IP
            || u32::from(p[4]) != ETH_ALEN
            || p[5] != 4
        {
            return None;
        }
        let mac = |at: usize| MacAddr(p[at..at + 6].try_into().unwrap_or_default());
        let ip = |at: usize| p[at..at + 4].try_into().unwrap_or_default();
        Some(Self {
            op: be16(6),
            sender_mac: mac(8),
            sender_ip: ip(14),
            target_mac: mac(18),
            target_ip: ip(24),
        })
    }

    /// The bytes of the packet, in network byte order.
    pub fn to_bytes(&self) -> [u8; LEN] {
        let mut p = [0; LEN];
        p[0..2].copy_from_slice(&ARPHRD_ETHER.to_be_bytes());
        p[2..4].copy_from_slice(&(ETH_P_IP as u16).to_be_bytes());
        p[4] = ETH_ALEN as u8;
        p[5] = 4;
        p[6..8].copy_from_slice(&self.op.to_be_bytes());
        p[8..14].copy_from_slice(&self.sender_mac.0);
        p[14..18].copy_from_slice(&self.sender_ip);
        p[18..24].copy_from_slice(&self.target_mac.0);
        p[24..28].copy_from_slice(&self.target_ip);
        p
    }

    /// An Ethernet frame with the packet, to `dst`, as `arp_create` of Linux.
    pub fn to_frame(&self, dst: MacAddr) -> NetBuf {
        let mut buf = NetBuf::new(HEADROOM, LEN);
        buf.extend_from_slice(&self.to_bytes());
        EthHeader { dst, src: self.sender_mac, ethertype: ETH_P_ARP as u16 }.push(&mut buf);
        buf
    }
}

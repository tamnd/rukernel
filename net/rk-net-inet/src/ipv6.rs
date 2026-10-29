//! The IPv6 header of RFC 8200, the extension headers that a host skips, and the classes of the
//! addresses of RFC 4291, as `struct ipv6hdr`, net/ipv6/ip6_input.c and `__ipv6_addr_type` of
//! Linux.
//!
//! The types of the messages and the options of neighbour discovery are in include/net/ndisc.h
//! of Linux, which is not a uAPI header. Thus rk-abigen cannot extract them, and they are here
//! by hand with the values of RFC 4861.

use crate::ip::Ip;
use rk_net::ether::MacAddr;

/// The length of the header.
pub const HLEN: usize = 40;
/// The protocol number of ICMPv6.
pub const PROTO_ICMPV6: u8 = 58;
/// The extension header "hop-by-hop options".
pub const NEXT_HOPOPTS: u8 = 0;
/// The extension header "routing".
pub const NEXT_ROUTING: u8 = 43;
/// The extension header "fragment".
pub const NEXT_FRAGMENT: u8 = 44;
/// No next header.
pub const NEXT_NONE: u8 = 59;
/// The extension header "destination options".
pub const NEXT_DSTOPTS: u8 = 60;
/// The default hop limit, `net.ipv6.conf.all.hop_limit` of Linux.
pub const DEFAULT_HOPS: u8 = 64;
/// The smallest MTU of a link of IPv6, `IPV6_MIN_MTU` of Linux.
pub const MIN_MTU: usize = 1280;

/// The ICMPv6 type of a router solicitation, `NDISC_ROUTER_SOLICITATION`.
pub const NDISC_ROUTER_SOLICITATION: u8 = 133;
/// The ICMPv6 type of a router advertisement.
pub const NDISC_ROUTER_ADVERTISEMENT: u8 = 134;
/// The ICMPv6 type of a neighbour solicitation.
pub const NDISC_NEIGHBOUR_SOLICITATION: u8 = 135;
/// The ICMPv6 type of a neighbour advertisement.
pub const NDISC_NEIGHBOUR_ADVERTISEMENT: u8 = 136;
/// The ICMPv6 type of a redirect.
pub const NDISC_REDIRECT: u8 = 137;
/// The option with the link address of the sender, `ND_OPT_SOURCE_LL_ADDR`.
pub const ND_OPT_SOURCE_LL_ADDR: u8 = 1;
/// The option with the link address of the target.
pub const ND_OPT_TARGET_LL_ADDR: u8 = 2;
/// The option with a prefix of the link.
pub const ND_OPT_PREFIX_INFO: u8 = 3;
/// The flag "router" of a neighbour advertisement.
pub const NA_ROUTER: u8 = 0x80;
/// The flag "solicited" of a neighbour advertisement.
pub const NA_SOLICITED: u8 = 0x40;
/// The flag "override" of a neighbour advertisement.
pub const NA_OVERRIDE: u8 = 0x20;
/// The flag "on link" of a prefix option.
pub const PREFIX_ONLINK: u8 = 0x80;
/// The flag "autonomous address configuration" of a prefix option.
pub const PREFIX_AUTONOMOUS: u8 = 0x40;

/// The address `ff02::1`: all of the nodes of the link.
pub const ALL_NODES: Ip = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// The address `ff02::2`: all of the routers of the link.
pub const ALL_ROUTERS: Ip = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
/// The address `ff01::1`: all of the nodes of the interface.
pub const ALL_NODES_IF: Ip = [0xff, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// The scope of an address in /proc/net/if_inet6, `IPV6_ADDR_SCOPE_*` of Linux shifted by 4.
pub const SCOPE_GLOBAL: u8 = 0x00;
/// The scope of the loopback address.
pub const SCOPE_HOST: u8 = 0x10;
/// The scope of a link local address.
pub const SCOPE_LINK: u8 = 0x20;
/// The scope of a site local address.
pub const SCOPE_SITE: u8 = 0x40;

/// Tells if `a` is a multicast address, `ff00::/8`.
pub fn is_multicast(a: &Ip) -> bool {
    a[0] == 0xff
}

/// Tells if `a` is a link local unicast address, `fe80::/10`.
pub fn is_link_local(a: &Ip) -> bool {
    a[0] == 0xfe && a[1] & 0xc0 == 0x80
}

/// Tells if `a` is a site local unicast address, `fec0::/10`. RFC 3879 deprecates them, but
/// the user network of QEMU gives one.
pub fn is_site_local(a: &Ip) -> bool {
    a[0] == 0xfe && a[1] & 0xc0 == 0xc0
}

/// Tells if `a` needs an interface to have a meaning: a link local address, or a multicast
/// address of the scope of the interface or the link, as `__ipv6_addr_needs_scope_id`.
pub fn needs_scope(a: &Ip) -> bool {
    is_link_local(a) || (is_multicast(a) && matches!(a[1] & 0xf, 1 | 2))
}

/// The scope of the unicast address `a` for /proc/net/if_inet6 and for the choice of a source
/// address.
pub fn scope(a: &Ip) -> u8 {
    if *a == crate::ip::LOOPBACK {
        SCOPE_HOST
    } else if is_link_local(a) {
        SCOPE_LINK
    } else if is_site_local(a) {
        SCOPE_SITE
    } else {
        SCOPE_GLOBAL
    }
}

/// The scope of `a` for rtnetlink, `RT_SCOPE_*` of Linux, as `ifa_scope` of an address.
pub fn rt_scope(a: &Ip) -> u8 {
    match scope(a) {
        SCOPE_HOST => 254,
        SCOPE_LINK => 253,
        SCOPE_SITE => 200,
        _ => 0,
    }
}

/// The solicited node multicast address of `a`, `ff02::1:ffXX:XXXX`, as
/// `addrconf_addr_solict_mult` of Linux.
pub fn solicited_node(a: &Ip) -> Ip {
    let mut m = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 0];
    m[13..].copy_from_slice(&a[13..]);
    m
}

/// The Ethernet address of the multicast address `a`, `33:33:` and the last 32 bits, as
/// `ipv6_eth_mc_map` of Linux.
pub fn multicast_mac(a: &Ip) -> MacAddr {
    MacAddr([0x33, 0x33, a[12], a[13], a[14], a[15]])
}

/// The interface ID of RFC 4291 from an Ethernet address: the modified EUI-64, as
/// `addrconf_ifid_eui48` of Linux.
pub fn eui64(mac: MacAddr) -> [u8; 8] {
    let m = mac.0;
    [m[0] ^ 2, m[1], m[2], 0xff, 0xfe, m[3], m[4], m[5]]
}

/// The address of the prefix `prefix` of 64 bits with the interface ID `id`.
pub fn with_id(prefix: &Ip, id: [u8; 8]) -> Ip {
    let mut a = *prefix;
    a[8..].copy_from_slice(&id);
    a
}

/// The link local address `fe80::/64` with the interface ID `id`.
pub fn link_local(id: [u8; 8]) -> Ip {
    let mut a = [0; 16];
    a[0] = 0xfe;
    a[1] = 0x80;
    a[8..].copy_from_slice(&id);
    a
}

/// The first `len` bits of `a`, with the other bits zero.
pub fn prefix(a: &Ip, len: u8) -> Ip {
    let mut out = [0; 16];
    let len = usize::from(len.min(128));
    let (whole, bits) = (len / 8, len % 8);
    out[..whole].copy_from_slice(&a[..whole]);
    if bits != 0 {
        out[whole] = a[whole] & (0xff << (8 - bits));
    }
    out
}

/// Tells if `a` and `b` have the same first `len` bits.
pub fn same_net(a: &Ip, b: &Ip, len: u8) -> bool {
    prefix(a, len) == prefix(b, len)
}

/// The reasons that the input drops a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bad {
    /// The packet is shorter than its header, or the header is not IPv6.
    Header,
    /// The payload length is not in the frame.
    Length,
    /// The packet is a fragment. `Frag::find` gives its fragment header.
    Fragment,
}

/// The fragment header of a packet, `struct frag_hdr` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frag {
    /// The offset of the fragment header in the packet. The headers before it are the part
    /// that is not fragmented.
    pub at: usize,
    /// The offset of the field that names the fragment header.
    pub nh: usize,
    /// The next header after the fragment header.
    pub next: u8,
    /// The offset of the data of the fragment in the packet, in bytes.
    pub offset: usize,
    /// The flag "more fragments".
    pub more: bool,
    /// The identification.
    pub id: u32,
}

/// The length of a fragment header.
pub const FRAG_HLEN: usize = 8;

impl Frag {
    /// Finds the fragment header of `packet` after the extension headers before it, as
    /// `ipv6_frag_rcv` in net/ipv6/reassembly.c of Linux. `packet` ends at the end of the
    /// payload.
    pub fn find(packet: &[u8]) -> Option<Self> {
        let (mut next, mut at, mut nh) = (*packet.get(6)?, HLEN, 6);
        while matches!(next, NEXT_HOPOPTS | NEXT_ROUTING | NEXT_DSTOPTS) {
            let e = packet.get(at..at + 2)?;
            next = e[0];
            nh = at;
            at += (usize::from(e[1]) + 1) * 8;
        }
        if next != NEXT_FRAGMENT {
            return None;
        }
        let f = packet.get(at..at + FRAG_HLEN)?;
        let off = u16::from_be_bytes([f[2], f[3]]);
        Some(Self {
            at,
            nh,
            next: f[0],
            offset: usize::from(off & !7),
            more: off & 1 != 0,
            id: u32::from_be_bytes([f[4], f[5], f[6], f[7]]),
        })
    }

    /// The bytes of a fragment header, as `ip6_frag_next` of Linux.
    pub fn to_bytes(&self) -> [u8; FRAG_HLEN] {
        let mut b = [0u8; FRAG_HLEN];
        b[0] = self.next;
        let off = (self.offset as u16 & !7) | u16::from(self.more);
        b[2..4].copy_from_slice(&off.to_be_bytes());
        b[4..8].copy_from_slice(&self.id.to_be_bytes());
        b
    }
}

/// An IPv6 header, with the extension headers that the host skips.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The traffic class.
    pub tclass: u8,
    /// The flow label.
    pub flow: u32,
    /// The length of the payload, with the extension headers.
    pub payload_len: u16,
    /// The next header of the fixed header.
    pub next: u8,
    /// The hop limit.
    pub hops: u8,
    /// The source address.
    pub src: Ip,
    /// The destination address.
    pub dst: Ip,
    /// The protocol of the upper layer after the extension headers.
    pub protocol: u8,
    /// The offset of the upper layer header from the start of the packet.
    pub l4: usize,
    /// The offset of the field that has `protocol`, for an ICMPv6 parameter problem.
    pub nh: usize,
}

impl Header {
    /// A header for `payload` bytes of the protocol `next`.
    pub fn new(src: Ip, dst: Ip, next: u8, payload: usize) -> Self {
        Self {
            tclass: 0,
            flow: 0,
            payload_len: payload as u16,
            next,
            hops: DEFAULT_HOPS,
            src,
            dst,
            protocol: next,
            l4: HLEN,
            nh: 6,
        }
    }

    /// Reads the fixed header in `b`.
    fn fixed(b: &[u8]) -> Option<Self> {
        let b = b.get(..HLEN)?;
        if b[0] >> 4 != 6 {
            return None;
        }
        let word = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        Some(Self {
            tclass: (word >> 20) as u8,
            flow: word & 0xf_ffff,
            payload_len: u16::from_be_bytes([b[4], b[5]]),
            next: b[6],
            hops: b[7],
            src: b[8..24].try_into().unwrap_or_default(),
            dst: b[24..40].try_into().unwrap_or_default(),
            protocol: b[6],
            l4: HLEN,
            nh: 6,
        })
    }

    /// Reads the header of `packet` and skips its extension headers, as the inner packet of an
    /// ICMPv6 error. The packet can be cut after the headers.
    pub fn parse_loose(packet: &[u8]) -> Option<Self> {
        let mut h = Self::fixed(packet)?;
        h.skip_extensions(packet).ok()?;
        Some(h)
    }

    /// Reads and checks the header of a received packet, as `ipv6_rcv` of Linux, and skips the
    /// extension headers.
    ///
    /// # Errors
    ///
    /// Gives the reason to drop the packet.
    pub fn parse(packet: &[u8]) -> Result<Self, Bad> {
        let mut h = Self::fixed(packet).ok_or(Bad::Header)?;
        if HLEN + usize::from(h.payload_len) > packet.len() {
            return Err(Bad::Length);
        }
        h.skip_extensions(&packet[..HLEN + usize::from(h.payload_len)])?;
        Ok(h)
    }

    /// Skips the extension headers, as `ipv6_skip_exthdr` of Linux. A fragment header gives
    /// `Bad::Fragment`.
    fn skip_extensions(&mut self, packet: &[u8]) -> Result<(), Bad> {
        let (mut next, mut at, mut nh) = (self.next, HLEN, 6);
        while matches!(next, NEXT_HOPOPTS | NEXT_ROUTING | NEXT_DSTOPTS | NEXT_FRAGMENT) {
            if next == NEXT_FRAGMENT {
                return Err(Bad::Fragment);
            }
            let e = packet.get(at..at + 2).ok_or(Bad::Header)?;
            next = e[0];
            nh = at;
            at += (usize::from(e[1]) + 1) * 8;
        }
        if at > packet.len() {
            return Err(Bad::Header);
        }
        self.protocol = next;
        self.l4 = at;
        self.nh = nh;
        Ok(())
    }

    /// The offset of the first routing header of `packet`, after the extension headers before
    /// it, or `None`. The extension headers are in the packet, as `parse` checked.
    pub fn routing_header(&self, packet: &[u8]) -> Option<usize> {
        let (mut next, mut at) = (self.next, HLEN);
        while matches!(next, NEXT_HOPOPTS | NEXT_DSTOPTS) {
            let e = packet.get(at..at + 2)?;
            next = e[0];
            at += (usize::from(e[1]) + 1) * 8;
        }
        (next == NEXT_ROUTING).then_some(at)
    }

    /// The bytes of the fixed header.
    pub fn to_bytes(&self) -> [u8; HLEN] {
        let mut b = [0u8; HLEN];
        let word = (6u32 << 28) | (u32::from(self.tclass) << 20) | (self.flow & 0xf_ffff);
        b[0..4].copy_from_slice(&word.to_be_bytes());
        b[4..6].copy_from_slice(&self.payload_len.to_be_bytes());
        b[6] = self.next;
        b[7] = self.hops;
        b[8..24].copy_from_slice(&self.src);
        b[24..40].copy_from_slice(&self.dst);
        b
    }
}

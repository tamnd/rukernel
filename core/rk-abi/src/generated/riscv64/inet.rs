// rk-abigen generated this file from Linux 7.3, from <linux/in.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The IP protocol numbers, the options of the level `IPPROTO_IP` and the special IPv4 addresses.

/// `INADDR_ANY` from `<linux/in.h>`.
pub const INADDR_ANY: u32 = 0;
/// Dummy protocol for TCP.
pub const IPPROTO_IP: u32 = 0;
/// Never send DF frames.
pub const IP_PMTUDISC_DONT: u32 = 0;
/// Internet Control Message Protocol.
pub const IPPROTO_ICMP: u32 = 1;
/// `IP_DEFAULT_MULTICAST_LOOP` from `<linux/in.h>`.
pub const IP_DEFAULT_MULTICAST_LOOP: u32 = 1;
/// `IP_DEFAULT_MULTICAST_TTL` from `<linux/in.h>`.
pub const IP_DEFAULT_MULTICAST_TTL: u32 = 1;
/// Use per route hints.
pub const IP_PMTUDISC_WANT: u32 = 1;
/// `IP_TOS` from `<linux/in.h>`.
pub const IP_TOS: u32 = 1;
/// Internet Group Management Protocol.
pub const IPPROTO_IGMP: u32 = 2;
/// Always DF.
pub const IP_PMTUDISC_DO: u32 = 2;
/// `IP_TTL` from `<linux/in.h>`.
pub const IP_TTL: u32 = 2;
/// `IP_HDRINCL` from `<linux/in.h>`.
pub const IP_HDRINCL: u32 = 3;
/// Ignore dst pmtu.
pub const IP_PMTUDISC_PROBE: u32 = 3;
/// IPIP tunnels (older KA9Q tunnels use 94).
pub const IPPROTO_IPIP: u32 = 4;
/// `IP_OPTIONS` from `<linux/in.h>`.
pub const IP_OPTIONS: u32 = 4;
/// `IP_PMTUDISC_INTERFACE` from `<linux/in.h>`.
pub const IP_PMTUDISC_INTERFACE: u32 = 4;
/// `IP_PMTUDISC_OMIT` from `<linux/in.h>`.
pub const IP_PMTUDISC_OMIT: u32 = 5;
/// `IP_ROUTER_ALERT` from `<linux/in.h>`.
pub const IP_ROUTER_ALERT: u32 = 5;
/// Transmission Control Protocol.
pub const IPPROTO_TCP: u32 = 6;
/// `IP_RECVOPTS` from `<linux/in.h>`.
pub const IP_RECVOPTS: u32 = 6;
/// The same value as `IP_RETOPTS`.
pub const IP_RECVRETOPTS: u32 = 7;
/// `IP_RETOPTS` from `<linux/in.h>`.
pub const IP_RETOPTS: u32 = 7;
/// Exterior Gateway Protocol.
pub const IPPROTO_EGP: u32 = 8;
/// `IP_PKTINFO` from `<linux/in.h>`.
pub const IP_PKTINFO: u32 = 8;
/// `IP_PKTOPTIONS` from `<linux/in.h>`.
pub const IP_PKTOPTIONS: u32 = 9;
/// `IP_MTU_DISCOVER` from `<linux/in.h>`.
pub const IP_MTU_DISCOVER: u32 = 10;
/// `IP_RECVERR` from `<linux/in.h>`.
pub const IP_RECVERR: u32 = 11;
/// PUP protocol.
pub const IPPROTO_PUP: u32 = 12;
/// `IP_RECVTTL` from `<linux/in.h>`.
pub const IP_RECVTTL: u32 = 12;
/// `IP_RECVTOS` from `<linux/in.h>`.
pub const IP_RECVTOS: u32 = 13;
/// `IP_MTU` from `<linux/in.h>`.
pub const IP_MTU: u32 = 14;
/// `IP_FREEBIND` from `<linux/in.h>`.
pub const IP_FREEBIND: u32 = 15;
/// `IP_IPSEC_POLICY` from `<linux/in.h>`.
pub const IP_IPSEC_POLICY: u32 = 16;
/// User Datagram Protocol.
pub const IPPROTO_UDP: u32 = 17;
/// `IP_XFRM_POLICY` from `<linux/in.h>`.
pub const IP_XFRM_POLICY: u32 = 17;
/// `IP_PASSSEC` from `<linux/in.h>`.
pub const IP_PASSSEC: u32 = 18;
/// `IP_TRANSPARENT` from `<linux/in.h>`.
pub const IP_TRANSPARENT: u32 = 19;
/// `IP_ORIGDSTADDR` from `<linux/in.h>`.
pub const IP_ORIGDSTADDR: u32 = 20;
/// The same value as `IP_ORIGDSTADDR`.
pub const IP_RECVORIGDSTADDR: u32 = 20;
/// `IP_MINTTL` from `<linux/in.h>`.
pub const IP_MINTTL: u32 = 21;
/// XNS IDP protocol.
pub const IPPROTO_IDP: u32 = 22;
/// `IP_NODEFRAG` from `<linux/in.h>`.
pub const IP_NODEFRAG: u32 = 22;
/// `IP_CHECKSUM` from `<linux/in.h>`.
pub const IP_CHECKSUM: u32 = 23;
/// `IP_BIND_ADDRESS_NO_PORT` from `<linux/in.h>`.
pub const IP_BIND_ADDRESS_NO_PORT: u32 = 24;
/// `IP_RECVFRAGSIZE` from `<linux/in.h>`.
pub const IP_RECVFRAGSIZE: u32 = 25;
/// `IP_RECVERR_RFC4884` from `<linux/in.h>`.
pub const IP_RECVERR_RFC4884: u32 = 26;
/// SO Transport Protocol Class 4.
pub const IPPROTO_TP: u32 = 29;
/// `IP_MULTICAST_IF` from `<linux/in.h>`.
pub const IP_MULTICAST_IF: u32 = 32;
/// Datagram Congestion Control Protocol.
pub const IPPROTO_DCCP: u32 = 33;
/// `IP_MULTICAST_TTL` from `<linux/in.h>`.
pub const IP_MULTICAST_TTL: u32 = 33;
/// `IP_MULTICAST_LOOP` from `<linux/in.h>`.
pub const IP_MULTICAST_LOOP: u32 = 34;
/// `IP_ADD_MEMBERSHIP` from `<linux/in.h>`.
pub const IP_ADD_MEMBERSHIP: u32 = 35;
/// `IP_DROP_MEMBERSHIP` from `<linux/in.h>`.
pub const IP_DROP_MEMBERSHIP: u32 = 36;
/// `IP_UNBLOCK_SOURCE` from `<linux/in.h>`.
pub const IP_UNBLOCK_SOURCE: u32 = 37;
/// `IP_BLOCK_SOURCE` from `<linux/in.h>`.
pub const IP_BLOCK_SOURCE: u32 = 38;
/// `IP_ADD_SOURCE_MEMBERSHIP` from `<linux/in.h>`.
pub const IP_ADD_SOURCE_MEMBERSHIP: u32 = 39;
/// `IP_DROP_SOURCE_MEMBERSHIP` from `<linux/in.h>`.
pub const IP_DROP_SOURCE_MEMBERSHIP: u32 = 40;
/// IPv6-in-IPv4 tunnelling.
pub const IPPROTO_IPV6: u32 = 41;
/// `IP_MSFILTER` from `<linux/in.h>`.
pub const IP_MSFILTER: u32 = 41;
/// RSVP Protocol.
pub const IPPROTO_RSVP: u32 = 46;
/// Cisco GRE tunnels (rfc 1701,1702).
pub const IPPROTO_GRE: u32 = 47;
/// `IP_MULTICAST_ALL` from `<linux/in.h>`.
pub const IP_MULTICAST_ALL: u32 = 49;
/// Encapsulation Security Payload protocol.
pub const IPPROTO_ESP: u32 = 50;
/// `IP_UNICAST_IF` from `<linux/in.h>`.
pub const IP_UNICAST_IF: u32 = 50;
/// Authentication Header protocol.
pub const IPPROTO_AH: u32 = 51;
/// `IP_LOCAL_PORT_RANGE` from `<linux/in.h>`.
pub const IP_LOCAL_PORT_RANGE: u32 = 51;
/// `IP_PROTOCOL` from `<linux/in.h>`.
pub const IP_PROTOCOL: u32 = 52;
/// Multicast Transport Protocol.
pub const IPPROTO_MTP: u32 = 92;
/// IP option pseudo header for BEET.
pub const IPPROTO_BEETPH: u32 = 94;
/// Encapsulation Header.
pub const IPPROTO_ENCAP: u32 = 98;
/// Protocol Independent Multicast.
pub const IPPROTO_PIM: u32 = 103;
/// Compression Header Protocol.
pub const IPPROTO_COMP: u32 = 108;
/// Layer 2 Tunnelling Protocol.
pub const IPPROTO_L2TP: u32 = 115;
/// Stream Control Transport Protocol.
pub const IPPROTO_SCTP: u32 = 132;
/// UDP-Lite (RFC 3828).
pub const IPPROTO_UDPLITE: u32 = 136;
/// MPLS in IP (RFC 4023).
pub const IPPROTO_MPLS: u32 = 137;
/// Ethernet-within-IPv6 Encapsulation.
pub const IPPROTO_ETHERNET: u32 = 143;
/// AGGFRAG in ESP (RFC 9347).
pub const IPPROTO_AGGFRAG: u32 = 144;
/// Raw IP packets.
pub const IPPROTO_RAW: u32 = 255;
/// Shared Memory Communications.
pub const IPPROTO_SMC: u32 = 0x100;
/// Multipath TCP connection.
pub const IPPROTO_MPTCP: u32 = 0x106;
/// 127.0.0.1.
pub const INADDR_LOOPBACK: u32 = 0x7f00_0001;
/// `INADDR_DUMMY` from `<linux/in.h>`.
pub const INADDR_DUMMY: u32 = 0xc000_0008;
/// 224.0.0.0.
pub const INADDR_UNSPEC_GROUP: u32 = 0xe000_0000;
/// 224.0.0.1.
pub const INADDR_ALLHOSTS_GROUP: u32 = 0xe000_0001;
/// 224.0.0.2.
pub const INADDR_ALLRTRS_GROUP: u32 = 0xe000_0002;
/// 224.0.0.106.
pub const INADDR_ALLSNOOPERS_GROUP: u32 = 0xe000_006a;
/// 224.0.0.255.
pub const INADDR_MAX_LOCAL_GROUP: u32 = 0xe000_00ff;
/// `INADDR_BROADCAST` from `<linux/in.h>`.
pub const INADDR_BROADCAST: u32 = 0xffff_ffff;
/// `INADDR_NONE` from `<linux/in.h>`.
pub const INADDR_NONE: u32 = 0xffff_ffff;

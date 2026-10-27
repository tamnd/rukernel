// rk-abigen generated this file from Linux 7.3, from <linux/in6.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The options of the level `IPPROTO_IPV6` and the fields of the IPv6 flow information.

/// `IPV6_FL_A_GET` from `<linux/in6.h>`.
pub const IPV6_FL_A_GET: u32 = 0;
/// `IPV6_FL_S_NONE` from `<linux/in6.h>`.
pub const IPV6_FL_S_NONE: u32 = 0;
/// `IPV6_PMTUDISC_DONT` from `<linux/in6.h>`.
pub const IPV6_PMTUDISC_DONT: u32 = 0;
/// `IPV6_PRIORITY_UNCHARACTERIZED` from `<linux/in6.h>`.
pub const IPV6_PRIORITY_UNCHARACTERIZED: u32 = 0;
/// `IPV6_TLV_PAD1` from `<linux/in6.h>`.
pub const IPV6_TLV_PAD1: u32 = 0;
/// `IPV6_ADDRFORM` from `<linux/in6.h>`.
pub const IPV6_ADDRFORM: u32 = 1;
/// `IPV6_FL_A_PUT` from `<linux/in6.h>`.
pub const IPV6_FL_A_PUT: u32 = 1;
/// `IPV6_FL_F_CREATE` from `<linux/in6.h>`.
pub const IPV6_FL_F_CREATE: u32 = 1;
/// `IPV6_FL_S_EXCL` from `<linux/in6.h>`.
pub const IPV6_FL_S_EXCL: u32 = 1;
/// `IPV6_PMTUDISC_WANT` from `<linux/in6.h>`.
pub const IPV6_PMTUDISC_WANT: u32 = 1;
/// `IPV6_PREFER_SRC_TMP` from `<linux/in6.h>`.
pub const IPV6_PREFER_SRC_TMP: u32 = 1;
/// `IPV6_TLV_PADN` from `<linux/in6.h>`.
pub const IPV6_TLV_PADN: u32 = 1;
/// `IPV6_2292PKTINFO` from `<linux/in6.h>`.
pub const IPV6_2292PKTINFO: u32 = 2;
/// `IPV6_FL_A_RENEW` from `<linux/in6.h>`.
pub const IPV6_FL_A_RENEW: u32 = 2;
/// `IPV6_FL_F_EXCL` from `<linux/in6.h>`.
pub const IPV6_FL_F_EXCL: u32 = 2;
/// `IPV6_FL_S_PROCESS` from `<linux/in6.h>`.
pub const IPV6_FL_S_PROCESS: u32 = 2;
/// `IPV6_PMTUDISC_DO` from `<linux/in6.h>`.
pub const IPV6_PMTUDISC_DO: u32 = 2;
/// `IPV6_PREFER_SRC_PUBLIC` from `<linux/in6.h>`.
pub const IPV6_PREFER_SRC_PUBLIC: u32 = 2;
/// `IPV6_2292HOPOPTS` from `<linux/in6.h>`.
pub const IPV6_2292HOPOPTS: u32 = 3;
/// `IPV6_FL_S_USER` from `<linux/in6.h>`.
pub const IPV6_FL_S_USER: u32 = 3;
/// `IPV6_PMTUDISC_PROBE` from `<linux/in6.h>`.
pub const IPV6_PMTUDISC_PROBE: u32 = 3;
/// `IPV6_2292DSTOPTS` from `<linux/in6.h>`.
pub const IPV6_2292DSTOPTS: u32 = 4;
/// `IPV6_FL_F_REFLECT` from `<linux/in6.h>`.
pub const IPV6_FL_F_REFLECT: u32 = 4;
/// `IPV6_PMTUDISC_INTERFACE` from `<linux/in6.h>`.
pub const IPV6_PMTUDISC_INTERFACE: u32 = 4;
/// `IPV6_PREFER_SRC_COA` from `<linux/in6.h>`.
pub const IPV6_PREFER_SRC_COA: u32 = 4;
/// `IPV6_2292RTHDR` from `<linux/in6.h>`.
pub const IPV6_2292RTHDR: u32 = 5;
/// `IPV6_PMTUDISC_OMIT` from `<linux/in6.h>`.
pub const IPV6_PMTUDISC_OMIT: u32 = 5;
/// `IPV6_TLV_ROUTERALERT` from `<linux/in6.h>`.
pub const IPV6_TLV_ROUTERALERT: u32 = 5;
/// `IPV6_2292PKTOPTIONS` from `<linux/in6.h>`.
pub const IPV6_2292PKTOPTIONS: u32 = 6;
/// `IPV6_CHECKSUM` from `<linux/in6.h>`.
pub const IPV6_CHECKSUM: u32 = 7;
/// RFC 5570.
pub const IPV6_TLV_CALIPSO: u32 = 7;
/// `IPV6_2292HOPLIMIT` from `<linux/in6.h>`.
pub const IPV6_2292HOPLIMIT: u32 = 8;
/// `IPV6_FL_F_REMOTE` from `<linux/in6.h>`.
pub const IPV6_FL_F_REMOTE: u32 = 8;
/// `IPV6_PREFER_SRC_CGA` from `<linux/in6.h>`.
pub const IPV6_PREFER_SRC_CGA: u32 = 8;
/// `IPV6_NEXTHOP` from `<linux/in6.h>`.
pub const IPV6_NEXTHOP: u32 = 9;
/// Obsolete.
pub const IPV6_AUTHHDR: u32 = 10;
/// `IPV6_FLOWINFO` from `<linux/in6.h>`.
pub const IPV6_FLOWINFO: u32 = 11;
/// `IPV6_UNICAST_HOPS` from `<linux/in6.h>`.
pub const IPV6_UNICAST_HOPS: u32 = 16;
/// `IPV6_MULTICAST_IF` from `<linux/in6.h>`.
pub const IPV6_MULTICAST_IF: u32 = 17;
/// `IPV6_MULTICAST_HOPS` from `<linux/in6.h>`.
pub const IPV6_MULTICAST_HOPS: u32 = 18;
/// `IPV6_MULTICAST_LOOP` from `<linux/in6.h>`.
pub const IPV6_MULTICAST_LOOP: u32 = 19;
/// `IPV6_ADD_MEMBERSHIP` from `<linux/in6.h>`.
pub const IPV6_ADD_MEMBERSHIP: u32 = 20;
/// `IPV6_DROP_MEMBERSHIP` from `<linux/in6.h>`.
pub const IPV6_DROP_MEMBERSHIP: u32 = 21;
/// `IPV6_ROUTER_ALERT` from `<linux/in6.h>`.
pub const IPV6_ROUTER_ALERT: u32 = 22;
/// `IPV6_MTU_DISCOVER` from `<linux/in6.h>`.
pub const IPV6_MTU_DISCOVER: u32 = 23;
/// `IPV6_MTU` from `<linux/in6.h>`.
pub const IPV6_MTU: u32 = 24;
/// `IPV6_RECVERR` from `<linux/in6.h>`.
pub const IPV6_RECVERR: u32 = 25;
/// `IPV6_V6ONLY` from `<linux/in6.h>`.
pub const IPV6_V6ONLY: u32 = 26;
/// `IPV6_JOIN_ANYCAST` from `<linux/in6.h>`.
pub const IPV6_JOIN_ANYCAST: u32 = 27;
/// `IPV6_LEAVE_ANYCAST` from `<linux/in6.h>`.
pub const IPV6_LEAVE_ANYCAST: u32 = 28;
/// `IPV6_MULTICAST_ALL` from `<linux/in6.h>`.
pub const IPV6_MULTICAST_ALL: u32 = 29;
/// `IPV6_ROUTER_ALERT_ISOLATE` from `<linux/in6.h>`.
pub const IPV6_ROUTER_ALERT_ISOLATE: u32 = 30;
/// `IPV6_RECVERR_RFC4884` from `<linux/in6.h>`.
pub const IPV6_RECVERR_RFC4884: u32 = 31;
/// `IPV6_FLOWLABEL_MGR` from `<linux/in6.h>`.
pub const IPV6_FLOWLABEL_MGR: u32 = 32;
/// `IPV6_FLOWINFO_SEND` from `<linux/in6.h>`.
pub const IPV6_FLOWINFO_SEND: u32 = 33;
/// `IPV6_IPSEC_POLICY` from `<linux/in6.h>`.
pub const IPV6_IPSEC_POLICY: u32 = 34;
/// `IPV6_XFRM_POLICY` from `<linux/in6.h>`.
pub const IPV6_XFRM_POLICY: u32 = 35;
/// `IPV6_HDRINCL` from `<linux/in6.h>`.
pub const IPV6_HDRINCL: u32 = 36;
/// `IPV6_RECVPKTINFO` from `<linux/in6.h>`.
pub const IPV6_RECVPKTINFO: u32 = 49;
/// RFC 9486.
pub const IPV6_TLV_IOAM: u32 = 49;
/// `IPV6_PKTINFO` from `<linux/in6.h>`.
pub const IPV6_PKTINFO: u32 = 50;
/// `IPV6_RECVHOPLIMIT` from `<linux/in6.h>`.
pub const IPV6_RECVHOPLIMIT: u32 = 51;
/// `IPV6_HOPLIMIT` from `<linux/in6.h>`.
pub const IPV6_HOPLIMIT: u32 = 52;
/// `IPV6_RECVHOPOPTS` from `<linux/in6.h>`.
pub const IPV6_RECVHOPOPTS: u32 = 53;
/// `IPV6_HOPOPTS` from `<linux/in6.h>`.
pub const IPV6_HOPOPTS: u32 = 54;
/// `IPV6_RTHDRDSTOPTS` from `<linux/in6.h>`.
pub const IPV6_RTHDRDSTOPTS: u32 = 55;
/// `IPV6_RECVRTHDR` from `<linux/in6.h>`.
pub const IPV6_RECVRTHDR: u32 = 56;
/// `IPV6_RTHDR` from `<linux/in6.h>`.
pub const IPV6_RTHDR: u32 = 57;
/// `IPV6_RECVDSTOPTS` from `<linux/in6.h>`.
pub const IPV6_RECVDSTOPTS: u32 = 58;
/// `IPV6_DSTOPTS` from `<linux/in6.h>`.
pub const IPV6_DSTOPTS: u32 = 59;
/// `IPV6_RECVPATHMTU` from `<linux/in6.h>`.
pub const IPV6_RECVPATHMTU: u32 = 60;
/// `IPV6_PATHMTU` from `<linux/in6.h>`.
pub const IPV6_PATHMTU: u32 = 61;
/// `IPV6_DONTFRAG` from `<linux/in6.h>`.
pub const IPV6_DONTFRAG: u32 = 62;
/// `IPV6_RECVTCLASS` from `<linux/in6.h>`.
pub const IPV6_RECVTCLASS: u32 = 66;
/// `IPV6_TCLASS` from `<linux/in6.h>`.
pub const IPV6_TCLASS: u32 = 67;
/// `IPV6_AUTOFLOWLABEL` from `<linux/in6.h>`.
pub const IPV6_AUTOFLOWLABEL: u32 = 70;
/// `IPV6_ADDR_PREFERENCES` from `<linux/in6.h>`.
pub const IPV6_ADDR_PREFERENCES: u32 = 72;
/// `IPV6_MINHOPCOUNT` from `<linux/in6.h>`.
pub const IPV6_MINHOPCOUNT: u32 = 73;
/// `IPV6_ORIGDSTADDR` from `<linux/in6.h>`.
pub const IPV6_ORIGDSTADDR: u32 = 74;
/// The same value as `IPV6_ORIGDSTADDR`.
pub const IPV6_RECVORIGDSTADDR: u32 = 74;
/// `IPV6_TRANSPARENT` from `<linux/in6.h>`.
pub const IPV6_TRANSPARENT: u32 = 75;
/// `IPV6_UNICAST_IF` from `<linux/in6.h>`.
pub const IPV6_UNICAST_IF: u32 = 76;
/// `IPV6_RECVFRAGSIZE` from `<linux/in6.h>`.
pub const IPV6_RECVFRAGSIZE: u32 = 77;
/// `IPV6_FREEBIND` from `<linux/in6.h>`.
pub const IPV6_FREEBIND: u32 = 78;
/// `IPV6_TLV_JUMBO` from `<linux/in6.h>`.
pub const IPV6_TLV_JUMBO: u32 = 194;
/// Home address option.
pub const IPV6_TLV_HAO: u32 = 201;
/// `IPV6_FL_S_ANY` from `<linux/in6.h>`.
pub const IPV6_FL_S_ANY: u32 = 255;
/// `IPV6_PREFER_SRC_PUBTMP_DEFAULT` from `<linux/in6.h>`.
pub const IPV6_PREFER_SRC_PUBTMP_DEFAULT: u32 = 0x100;
/// `IPV6_PRIORITY_FILLER` from `<linux/in6.h>`.
pub const IPV6_PRIORITY_FILLER: u32 = 0x100;
/// `IPV6_PRIORITY_UNATTENDED` from `<linux/in6.h>`.
pub const IPV6_PRIORITY_UNATTENDED: u32 = 0x200;
/// `IPV6_PRIORITY_RESERVED1` from `<linux/in6.h>`.
pub const IPV6_PRIORITY_RESERVED1: u32 = 0x300;
/// `IPV6_PREFER_SRC_HOME` from `<linux/in6.h>`.
pub const IPV6_PREFER_SRC_HOME: u32 = 0x400;
/// `IPV6_PRIORITY_BULK` from `<linux/in6.h>`.
pub const IPV6_PRIORITY_BULK: u32 = 0x400;
/// `IPV6_PRIORITY_RESERVED2` from `<linux/in6.h>`.
pub const IPV6_PRIORITY_RESERVED2: u32 = 0x500;
/// `IPV6_PRIORITY_INTERACTIVE` from `<linux/in6.h>`.
pub const IPV6_PRIORITY_INTERACTIVE: u32 = 0x600;
/// `IPV6_PRIORITY_CONTROL` from `<linux/in6.h>`.
pub const IPV6_PRIORITY_CONTROL: u32 = 0x700;
/// `IPV6_PREFER_SRC_NONCGA` from `<linux/in6.h>`.
pub const IPV6_PREFER_SRC_NONCGA: u32 = 0x800;
/// `IPV6_PRIORITY_8` from `<linux/in6.h>`.
pub const IPV6_PRIORITY_8: u32 = 0x800;
/// `IPV6_PRIORITY_9` from `<linux/in6.h>`.
pub const IPV6_PRIORITY_9: u32 = 0x900;
/// `IPV6_PRIORITY_10` from `<linux/in6.h>`.
pub const IPV6_PRIORITY_10: u32 = 0xa00;
/// `IPV6_PRIORITY_11` from `<linux/in6.h>`.
pub const IPV6_PRIORITY_11: u32 = 0xb00;
/// `IPV6_PRIORITY_12` from `<linux/in6.h>`.
pub const IPV6_PRIORITY_12: u32 = 0xc00;
/// `IPV6_PRIORITY_13` from `<linux/in6.h>`.
pub const IPV6_PRIORITY_13: u32 = 0xd00;
/// `IPV6_PRIORITY_14` from `<linux/in6.h>`.
pub const IPV6_PRIORITY_14: u32 = 0xe00;
/// `IPV6_PRIORITY_15` from `<linux/in6.h>`.
pub const IPV6_PRIORITY_15: u32 = 0xf00;
/// `IPV6_FLOWINFO_FLOWLABEL` from `<linux/in6.h>`.
pub const IPV6_FLOWINFO_FLOWLABEL: u32 = 0xf_ffff;
/// `IPV6_FLOWINFO_PRIORITY` from `<linux/in6.h>`.
pub const IPV6_FLOWINFO_PRIORITY: u32 = 0xff0_0000;

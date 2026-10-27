// rk-abigen generated this file from Linux 7.3, from <linux/rtnetlink.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The message types, groups, route types, scopes, tables and attributes of rtnetlink.

/// `RTA_UNSPEC` from `<linux/rtnetlink.h>`.
pub const RTA_UNSPEC: u32 = 0;
/// `RTNLGRP_NONE` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_NONE: u32 = 0;
/// `RTN_UNSPEC` from `<linux/rtnetlink.h>`.
pub const RTN_UNSPEC: u32 = 0;
/// `RTPROT_UNSPEC` from `<linux/rtnetlink.h>`.
pub const RTPROT_UNSPEC: u32 = 0;
/// `RT_SCOPE_UNIVERSE` from `<linux/rtnetlink.h>`.
pub const RT_SCOPE_UNIVERSE: u32 = 0;
/// `RT_TABLE_UNSPEC` from `<linux/rtnetlink.h>`.
pub const RT_TABLE_UNSPEC: u32 = 0;
/// `RTA_DST` from `<linux/rtnetlink.h>`.
pub const RTA_DST: u32 = 1;
/// `RTMGRP_LINK` from `<linux/rtnetlink.h>`.
pub const RTMGRP_LINK: u32 = 1;
/// Nexthop is dead (used by multipath).
pub const RTNH_F_DEAD: u32 = 1;
/// `RTNLGRP_LINK` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_LINK: u32 = 1;
/// `RTN_UNICAST` from `<linux/rtnetlink.h>`.
pub const RTN_UNICAST: u32 = 1;
/// `RTPROT_REDIRECT` from `<linux/rtnetlink.h>`.
pub const RTPROT_REDIRECT: u32 = 1;
/// `RTA_SRC` from `<linux/rtnetlink.h>`.
pub const RTA_SRC: u32 = 2;
/// `RTMGRP_NOTIFY` from `<linux/rtnetlink.h>`.
pub const RTMGRP_NOTIFY: u32 = 2;
/// Do recursive gateway lookup.
pub const RTNH_F_PERVASIVE: u32 = 2;
/// `RTNLGRP_NOTIFY` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_NOTIFY: u32 = 2;
/// `RTN_LOCAL` from `<linux/rtnetlink.h>`.
pub const RTN_LOCAL: u32 = 2;
/// Route installed by kernel.
pub const RTPROT_KERNEL: u32 = 2;
/// `RTA_IIF` from `<linux/rtnetlink.h>`.
pub const RTA_IIF: u32 = 3;
/// `RTNLGRP_NEIGH` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_NEIGH: u32 = 3;
/// `RTN_BROADCAST` from `<linux/rtnetlink.h>`.
pub const RTN_BROADCAST: u32 = 3;
/// Route installed during boot.
pub const RTPROT_BOOT: u32 = 3;
/// `RTA_ALIGNTO` from `<linux/rtnetlink.h>`.
pub const RTA_ALIGNTO: u32 = 4;
/// `RTA_OIF` from `<linux/rtnetlink.h>`.
pub const RTA_OIF: u32 = 4;
/// `RTMGRP_NEIGH` from `<linux/rtnetlink.h>`.
pub const RTMGRP_NEIGH: u32 = 4;
/// Gateway is forced on link.
pub const RTNH_F_ONLINK: u32 = 4;
/// `RTNLGRP_TC` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_TC: u32 = 4;
/// `RTN_ANYCAST` from `<linux/rtnetlink.h>`.
pub const RTN_ANYCAST: u32 = 4;
/// Route installed by administrator.
pub const RTPROT_STATIC: u32 = 4;
/// `RTA_GATEWAY` from `<linux/rtnetlink.h>`.
pub const RTA_GATEWAY: u32 = 5;
/// `RTNLGRP_IPV4_IFADDR` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_IPV4_IFADDR: u32 = 5;
/// `RTN_MULTICAST` from `<linux/rtnetlink.h>`.
pub const RTN_MULTICAST: u32 = 5;
/// `RTA_PRIORITY` from `<linux/rtnetlink.h>`.
pub const RTA_PRIORITY: u32 = 6;
/// `RTNLGRP_IPV4_MROUTE` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_IPV4_MROUTE: u32 = 6;
/// `RTN_BLACKHOLE` from `<linux/rtnetlink.h>`.
pub const RTN_BLACKHOLE: u32 = 6;
/// `RTA_PREFSRC` from `<linux/rtnetlink.h>`.
pub const RTA_PREFSRC: u32 = 7;
/// `RTNLGRP_IPV4_ROUTE` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_IPV4_ROUTE: u32 = 7;
/// `RTN_UNREACHABLE` from `<linux/rtnetlink.h>`.
pub const RTN_UNREACHABLE: u32 = 7;
/// `RTA_METRICS` from `<linux/rtnetlink.h>`.
pub const RTA_METRICS: u32 = 8;
/// `RTMGRP_TC` from `<linux/rtnetlink.h>`.
pub const RTMGRP_TC: u32 = 8;
/// Nexthop is offloaded.
pub const RTNH_F_OFFLOAD: u32 = 8;
/// `RTNLGRP_IPV4_RULE` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_IPV4_RULE: u32 = 8;
/// `RTN_PROHIBIT` from `<linux/rtnetlink.h>`.
pub const RTN_PROHIBIT: u32 = 8;
/// Apparently, GateD.
pub const RTPROT_GATED: u32 = 8;
/// `RTA_MULTIPATH` from `<linux/rtnetlink.h>`.
pub const RTA_MULTIPATH: u32 = 9;
/// `RTNLGRP_IPV6_IFADDR` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_IPV6_IFADDR: u32 = 9;
/// `RTN_THROW` from `<linux/rtnetlink.h>`.
pub const RTN_THROW: u32 = 9;
/// RDISC/ND router advertisements.
pub const RTPROT_RA: u32 = 9;
/// `RTA_PROTOINFO` from `<linux/rtnetlink.h>`.
pub const RTA_PROTOINFO: u32 = 10;
/// `RTNLGRP_IPV6_MROUTE` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_IPV6_MROUTE: u32 = 10;
/// `RTN_NAT` from `<linux/rtnetlink.h>`.
pub const RTN_NAT: u32 = 10;
/// Merit MRT.
pub const RTPROT_MRT: u32 = 10;
/// `RTA_FLOW` from `<linux/rtnetlink.h>`.
pub const RTA_FLOW: u32 = 11;
/// `RTNLGRP_IPV6_ROUTE` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_IPV6_ROUTE: u32 = 11;
/// `RTN_XRESOLVE` from `<linux/rtnetlink.h>`.
pub const RTN_XRESOLVE: u32 = 11;
/// Zebra.
pub const RTPROT_ZEBRA: u32 = 11;
/// `RTA_CACHEINFO` from `<linux/rtnetlink.h>`.
pub const RTA_CACHEINFO: u32 = 12;
/// `RTNLGRP_IPV6_IFINFO` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_IPV6_IFINFO: u32 = 12;
/// BIRD.
pub const RTPROT_BIRD: u32 = 12;
/// `RTA_SESSION` from `<linux/rtnetlink.h>`.
pub const RTA_SESSION: u32 = 13;
/// DECnet routing daemon.
pub const RTPROT_DNROUTED: u32 = 13;
/// `RTA_MP_ALGO` from `<linux/rtnetlink.h>`.
pub const RTA_MP_ALGO: u32 = 14;
/// XORP.
pub const RTPROT_XORP: u32 = 14;
/// `RTA_TABLE` from `<linux/rtnetlink.h>`.
pub const RTA_TABLE: u32 = 15;
/// Netsukuku.
pub const RTPROT_NTK: u32 = 15;
/// `RTA_MARK` from `<linux/rtnetlink.h>`.
pub const RTA_MARK: u32 = 16;
/// `RTMGRP_IPV4_IFADDR` from `<linux/rtnetlink.h>`.
pub const RTMGRP_IPV4_IFADDR: u32 = 16;
/// `RTM_BASE` from `<linux/rtnetlink.h>`.
pub const RTM_BASE: u32 = 16;
/// `RTM_NEWLINK` from `<linux/rtnetlink.h>`.
pub const RTM_NEWLINK: u32 = 16;
/// Carrier-down on nexthop.
pub const RTNH_F_LINKDOWN: u32 = 16;
/// DHCP client.
pub const RTPROT_DHCP: u32 = 16;
/// `RTA_MFC_STATS` from `<linux/rtnetlink.h>`.
pub const RTA_MFC_STATS: u32 = 17;
/// `RTM_DELLINK` from `<linux/rtnetlink.h>`.
pub const RTM_DELLINK: u32 = 17;
/// Multicast daemon.
pub const RTPROT_MROUTED: u32 = 17;
/// `RTA_VIA` from `<linux/rtnetlink.h>`.
pub const RTA_VIA: u32 = 18;
/// `RTM_GETLINK` from `<linux/rtnetlink.h>`.
pub const RTM_GETLINK: u32 = 18;
/// `RTNLGRP_IPV6_PREFIX` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_IPV6_PREFIX: u32 = 18;
/// Keepalived daemon.
pub const RTPROT_KEEPALIVED: u32 = 18;
/// `RTA_NEWDST` from `<linux/rtnetlink.h>`.
pub const RTA_NEWDST: u32 = 19;
/// `RTM_SETLINK` from `<linux/rtnetlink.h>`.
pub const RTM_SETLINK: u32 = 19;
/// `RTNLGRP_IPV6_RULE` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_IPV6_RULE: u32 = 19;
/// `RTA_PREF` from `<linux/rtnetlink.h>`.
pub const RTA_PREF: u32 = 20;
/// `RTM_NEWADDR` from `<linux/rtnetlink.h>`.
pub const RTM_NEWADDR: u32 = 20;
/// `RTNLGRP_ND_USEROPT` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_ND_USEROPT: u32 = 20;
/// `RTA_ENCAP_TYPE` from `<linux/rtnetlink.h>`.
pub const RTA_ENCAP_TYPE: u32 = 21;
/// `RTM_DELADDR` from `<linux/rtnetlink.h>`.
pub const RTM_DELADDR: u32 = 21;
/// `RTNLGRP_PHONET_IFADDR` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_PHONET_IFADDR: u32 = 21;
/// `RTA_ENCAP` from `<linux/rtnetlink.h>`.
pub const RTA_ENCAP: u32 = 22;
/// `RTM_GETADDR` from `<linux/rtnetlink.h>`.
pub const RTM_GETADDR: u32 = 22;
/// `RTNLGRP_PHONET_ROUTE` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_PHONET_ROUTE: u32 = 22;
/// `RTA_EXPIRES` from `<linux/rtnetlink.h>`.
pub const RTA_EXPIRES: u32 = 23;
/// `RTNLGRP_DCB` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_DCB: u32 = 23;
/// `RTA_PAD` from `<linux/rtnetlink.h>`.
pub const RTA_PAD: u32 = 24;
/// `RTM_NEWROUTE` from `<linux/rtnetlink.h>`.
pub const RTM_NEWROUTE: u32 = 24;
/// `RTNLGRP_IPV4_NETCONF` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_IPV4_NETCONF: u32 = 24;
/// `RTA_UID` from `<linux/rtnetlink.h>`.
pub const RTA_UID: u32 = 25;
/// `RTM_DELROUTE` from `<linux/rtnetlink.h>`.
pub const RTM_DELROUTE: u32 = 25;
/// `RTNLGRP_IPV6_NETCONF` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_IPV6_NETCONF: u32 = 25;
/// `RTA_TTL_PROPAGATE` from `<linux/rtnetlink.h>`.
pub const RTA_TTL_PROPAGATE: u32 = 26;
/// `RTM_GETROUTE` from `<linux/rtnetlink.h>`.
pub const RTM_GETROUTE: u32 = 26;
/// `RTNLGRP_MDB` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_MDB: u32 = 26;
/// `RTA_IP_PROTO` from `<linux/rtnetlink.h>`.
pub const RTA_IP_PROTO: u32 = 27;
/// `RTM_NR_FAMILIES` from `<linux/rtnetlink.h>`.
pub const RTM_NR_FAMILIES: u32 = 27;
/// `RTNLGRP_MPLS_ROUTE` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_MPLS_ROUTE: u32 = 27;
/// `RTA_SPORT` from `<linux/rtnetlink.h>`.
pub const RTA_SPORT: u32 = 28;
/// `RTM_NEWNEIGH` from `<linux/rtnetlink.h>`.
pub const RTM_NEWNEIGH: u32 = 28;
/// `RTNLGRP_NSID` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_NSID: u32 = 28;
/// `RTA_DPORT` from `<linux/rtnetlink.h>`.
pub const RTA_DPORT: u32 = 29;
/// `RTM_DELNEIGH` from `<linux/rtnetlink.h>`.
pub const RTM_DELNEIGH: u32 = 29;
/// `RTNLGRP_MPLS_NETCONF` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_MPLS_NETCONF: u32 = 29;
/// `RTA_NH_ID` from `<linux/rtnetlink.h>`.
pub const RTA_NH_ID: u32 = 30;
/// `RTM_GETNEIGH` from `<linux/rtnetlink.h>`.
pub const RTM_GETNEIGH: u32 = 30;
/// `RTNLGRP_IPV4_MROUTE_R` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_IPV4_MROUTE_R: u32 = 30;
/// `RTA_FLOWLABEL` from `<linux/rtnetlink.h>`.
pub const RTA_FLOWLABEL: u32 = 31;
/// `RTNLGRP_IPV6_MROUTE_R` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_IPV6_MROUTE_R: u32 = 31;
/// `RTA_DEL_REASON` from `<linux/rtnetlink.h>`.
pub const RTA_DEL_REASON: u32 = 32;
/// `RTMGRP_IPV4_MROUTE` from `<linux/rtnetlink.h>`.
pub const RTMGRP_IPV4_MROUTE: u32 = 32;
/// `RTM_NEWRULE` from `<linux/rtnetlink.h>`.
pub const RTM_NEWRULE: u32 = 32;
/// The entry is unresolved (ipmr).
pub const RTNH_F_UNRESOLVED: u32 = 32;
/// `RTNLGRP_NEXTHOP` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_NEXTHOP: u32 = 32;
/// `RTM_DELRULE` from `<linux/rtnetlink.h>`.
pub const RTM_DELRULE: u32 = 33;
/// `RTNLGRP_BRVLAN` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_BRVLAN: u32 = 33;
/// `RTM_GETRULE` from `<linux/rtnetlink.h>`.
pub const RTM_GETRULE: u32 = 34;
/// `RTNLGRP_MCTP_IFADDR` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_MCTP_IFADDR: u32 = 34;
/// `RTNLGRP_TUNNEL` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_TUNNEL: u32 = 35;
/// `RTM_NEWQDISC` from `<linux/rtnetlink.h>`.
pub const RTM_NEWQDISC: u32 = 36;
/// `RTNLGRP_STATS` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_STATS: u32 = 36;
/// `RTM_DELQDISC` from `<linux/rtnetlink.h>`.
pub const RTM_DELQDISC: u32 = 37;
/// `RTNLGRP_IPV4_MCADDR` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_IPV4_MCADDR: u32 = 37;
/// `RTM_GETQDISC` from `<linux/rtnetlink.h>`.
pub const RTM_GETQDISC: u32 = 38;
/// `RTNLGRP_IPV6_MCADDR` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_IPV6_MCADDR: u32 = 38;
/// `RTNLGRP_IPV6_ACADDR` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_IPV6_ACADDR: u32 = 39;
/// `RTNLGRP_MAX` from `<linux/rtnetlink.h>`.
pub const RTNLGRP_MAX: u32 = 39;
/// `RTM_NEWTCLASS` from `<linux/rtnetlink.h>`.
pub const RTM_NEWTCLASS: u32 = 40;
/// `RTM_DELTCLASS` from `<linux/rtnetlink.h>`.
pub const RTM_DELTCLASS: u32 = 41;
/// `RTM_GETTCLASS` from `<linux/rtnetlink.h>`.
pub const RTM_GETTCLASS: u32 = 42;
/// Babel daemon.
pub const RTPROT_BABEL: u32 = 42;
/// `RTM_NEWTFILTER` from `<linux/rtnetlink.h>`.
pub const RTM_NEWTFILTER: u32 = 44;
/// `RTM_DELTFILTER` from `<linux/rtnetlink.h>`.
pub const RTM_DELTFILTER: u32 = 45;
/// `RTM_GETTFILTER` from `<linux/rtnetlink.h>`.
pub const RTM_GETTFILTER: u32 = 46;
/// `RTM_NEWACTION` from `<linux/rtnetlink.h>`.
pub const RTM_NEWACTION: u32 = 48;
/// `RTM_DELACTION` from `<linux/rtnetlink.h>`.
pub const RTM_DELACTION: u32 = 49;
/// `RTM_GETACTION` from `<linux/rtnetlink.h>`.
pub const RTM_GETACTION: u32 = 50;
/// `RTM_NEWPREFIX` from `<linux/rtnetlink.h>`.
pub const RTM_NEWPREFIX: u32 = 52;
/// `RTM_NEWMULTICAST` from `<linux/rtnetlink.h>`.
pub const RTM_NEWMULTICAST: u32 = 56;
/// `RTM_DELMULTICAST` from `<linux/rtnetlink.h>`.
pub const RTM_DELMULTICAST: u32 = 57;
/// `RTM_GETMULTICAST` from `<linux/rtnetlink.h>`.
pub const RTM_GETMULTICAST: u32 = 58;
/// `RTM_NEWANYCAST` from `<linux/rtnetlink.h>`.
pub const RTM_NEWANYCAST: u32 = 60;
/// `RTM_DELANYCAST` from `<linux/rtnetlink.h>`.
pub const RTM_DELANYCAST: u32 = 61;
/// `RTM_GETANYCAST` from `<linux/rtnetlink.h>`.
pub const RTM_GETANYCAST: u32 = 62;
/// `RTMGRP_IPV4_ROUTE` from `<linux/rtnetlink.h>`.
pub const RTMGRP_IPV4_ROUTE: u32 = 64;
/// `RTM_NEWNEIGHTBL` from `<linux/rtnetlink.h>`.
pub const RTM_NEWNEIGHTBL: u32 = 64;
/// Nexthop is trapping packets.
pub const RTNH_F_TRAP: u32 = 64;
/// `RTM_GETNEIGHTBL` from `<linux/rtnetlink.h>`.
pub const RTM_GETNEIGHTBL: u32 = 66;
/// `RTM_SETNEIGHTBL` from `<linux/rtnetlink.h>`.
pub const RTM_SETNEIGHTBL: u32 = 67;
/// `RTM_NEWNDUSEROPT` from `<linux/rtnetlink.h>`.
pub const RTM_NEWNDUSEROPT: u32 = 68;
/// `RTM_NEWADDRLABEL` from `<linux/rtnetlink.h>`.
pub const RTM_NEWADDRLABEL: u32 = 72;
/// `RTM_DELADDRLABEL` from `<linux/rtnetlink.h>`.
pub const RTM_DELADDRLABEL: u32 = 73;
/// `RTM_GETADDRLABEL` from `<linux/rtnetlink.h>`.
pub const RTM_GETADDRLABEL: u32 = 74;
/// `RTM_GETDCB` from `<linux/rtnetlink.h>`.
pub const RTM_GETDCB: u32 = 78;
/// `RTM_SETDCB` from `<linux/rtnetlink.h>`.
pub const RTM_SETDCB: u32 = 79;
/// `RTM_NEWNETCONF` from `<linux/rtnetlink.h>`.
pub const RTM_NEWNETCONF: u32 = 80;
/// `RTM_DELNETCONF` from `<linux/rtnetlink.h>`.
pub const RTM_DELNETCONF: u32 = 81;
/// `RTM_GETNETCONF` from `<linux/rtnetlink.h>`.
pub const RTM_GETNETCONF: u32 = 82;
/// `RTM_NEWMDB` from `<linux/rtnetlink.h>`.
pub const RTM_NEWMDB: u32 = 84;
/// OVN daemon.
pub const RTPROT_OVN: u32 = 84;
/// `RTM_DELMDB` from `<linux/rtnetlink.h>`.
pub const RTM_DELMDB: u32 = 85;
/// `RTM_GETMDB` from `<linux/rtnetlink.h>`.
pub const RTM_GETMDB: u32 = 86;
/// `RTM_NEWNSID` from `<linux/rtnetlink.h>`.
pub const RTM_NEWNSID: u32 = 88;
/// `RTM_DELNSID` from `<linux/rtnetlink.h>`.
pub const RTM_DELNSID: u32 = 89;
/// `RTM_GETNSID` from `<linux/rtnetlink.h>`.
pub const RTM_GETNSID: u32 = 90;
/// `RTM_NEWSTATS` from `<linux/rtnetlink.h>`.
pub const RTM_NEWSTATS: u32 = 92;
/// `RTM_GETSTATS` from `<linux/rtnetlink.h>`.
pub const RTM_GETSTATS: u32 = 94;
/// `RTM_SETSTATS` from `<linux/rtnetlink.h>`.
pub const RTM_SETSTATS: u32 = 95;
/// `RTM_NEWCACHEREPORT` from `<linux/rtnetlink.h>`.
pub const RTM_NEWCACHEREPORT: u32 = 96;
/// Open Routing (Open/R) Routes.
pub const RTPROT_OPENR: u32 = 99;
/// `RTM_NEWCHAIN` from `<linux/rtnetlink.h>`.
pub const RTM_NEWCHAIN: u32 = 100;
/// `RTM_DELCHAIN` from `<linux/rtnetlink.h>`.
pub const RTM_DELCHAIN: u32 = 101;
/// `RTM_GETCHAIN` from `<linux/rtnetlink.h>`.
pub const RTM_GETCHAIN: u32 = 102;
/// `RTM_NEWNEXTHOP` from `<linux/rtnetlink.h>`.
pub const RTM_NEWNEXTHOP: u32 = 104;
/// `RTM_DELNEXTHOP` from `<linux/rtnetlink.h>`.
pub const RTM_DELNEXTHOP: u32 = 105;
/// `RTM_GETNEXTHOP` from `<linux/rtnetlink.h>`.
pub const RTM_GETNEXTHOP: u32 = 106;
/// `RTM_NEWLINKPROP` from `<linux/rtnetlink.h>`.
pub const RTM_NEWLINKPROP: u32 = 108;
/// `RTM_NR_MSGTYPES` from `<linux/rtnetlink.h>`.
pub const RTM_NR_MSGTYPES: u32 = 108;
/// `RTM_DELLINKPROP` from `<linux/rtnetlink.h>`.
pub const RTM_DELLINKPROP: u32 = 109;
/// `RTM_GETLINKPROP` from `<linux/rtnetlink.h>`.
pub const RTM_GETLINKPROP: u32 = 110;
/// `RTM_NEWVLAN` from `<linux/rtnetlink.h>`.
pub const RTM_NEWVLAN: u32 = 112;
/// `RTM_DELVLAN` from `<linux/rtnetlink.h>`.
pub const RTM_DELVLAN: u32 = 113;
/// `RTM_GETVLAN` from `<linux/rtnetlink.h>`.
pub const RTM_GETVLAN: u32 = 114;
/// `RTM_NEWNEXTHOPBUCKET` from `<linux/rtnetlink.h>`.
pub const RTM_NEWNEXTHOPBUCKET: u32 = 116;
/// `RTM_DELNEXTHOPBUCKET` from `<linux/rtnetlink.h>`.
pub const RTM_DELNEXTHOPBUCKET: u32 = 117;
/// `RTM_GETNEXTHOPBUCKET` from `<linux/rtnetlink.h>`.
pub const RTM_GETNEXTHOPBUCKET: u32 = 118;
/// `RTM_NEWTUNNEL` from `<linux/rtnetlink.h>`.
pub const RTM_NEWTUNNEL: u32 = 120;
/// `RTM_DELTUNNEL` from `<linux/rtnetlink.h>`.
pub const RTM_DELTUNNEL: u32 = 121;
/// `RTM_GETTUNNEL` from `<linux/rtnetlink.h>`.
pub const RTM_GETTUNNEL: u32 = 122;
/// `RTM_MAX` from `<linux/rtnetlink.h>`.
pub const RTM_MAX: u32 = 123;
/// `RTMGRP_IPV4_RULE` from `<linux/rtnetlink.h>`.
pub const RTMGRP_IPV4_RULE: u32 = 128;
/// BGP Routes.
pub const RTPROT_BGP: u32 = 186;
/// ISIS Routes.
pub const RTPROT_ISIS: u32 = 187;
/// OSPF Routes.
pub const RTPROT_OSPF: u32 = 188;
/// RIP Routes.
pub const RTPROT_RIP: u32 = 189;
/// EIGRP Routes.
pub const RTPROT_EIGRP: u32 = 192;
/// `RT_SCOPE_SITE` from `<linux/rtnetlink.h>`.
pub const RT_SCOPE_SITE: u32 = 200;
/// `RT_TABLE_COMPAT` from `<linux/rtnetlink.h>`.
pub const RT_TABLE_COMPAT: u32 = 252;
/// `RT_SCOPE_LINK` from `<linux/rtnetlink.h>`.
pub const RT_SCOPE_LINK: u32 = 253;
/// `RT_TABLE_DEFAULT` from `<linux/rtnetlink.h>`.
pub const RT_TABLE_DEFAULT: u32 = 253;
/// `RT_SCOPE_HOST` from `<linux/rtnetlink.h>`.
pub const RT_SCOPE_HOST: u32 = 254;
/// `RT_TABLE_MAIN` from `<linux/rtnetlink.h>`.
pub const RT_TABLE_MAIN: u32 = 254;
/// `RT_SCOPE_NOWHERE` from `<linux/rtnetlink.h>`.
pub const RT_SCOPE_NOWHERE: u32 = 255;
/// `RT_TABLE_LOCAL` from `<linux/rtnetlink.h>`.
pub const RT_TABLE_LOCAL: u32 = 255;
/// `RTMGRP_IPV6_IFADDR` from `<linux/rtnetlink.h>`.
pub const RTMGRP_IPV6_IFADDR: u32 = 0x100;
/// Notify user of route change.
pub const RTM_F_NOTIFY: u32 = 0x100;
/// `RTMGRP_IPV6_MROUTE` from `<linux/rtnetlink.h>`.
pub const RTMGRP_IPV6_MROUTE: u32 = 0x200;
/// This route is cloned.
pub const RTM_F_CLONED: u32 = 0x200;
/// `RTMGRP_IPV6_ROUTE` from `<linux/rtnetlink.h>`.
pub const RTMGRP_IPV6_ROUTE: u32 = 0x400;
/// Multipath equalizer: NI.
pub const RTM_F_EQUALIZE: u32 = 0x400;
/// `RTMGRP_IPV6_IFINFO` from `<linux/rtnetlink.h>`.
pub const RTMGRP_IPV6_IFINFO: u32 = 0x800;
/// Prefix addresses.
pub const RTM_F_PREFIX: u32 = 0x800;
/// Set rtm\_table to FIB lookup result.
pub const RTM_F_LOOKUP_TABLE: u32 = 0x1000;
/// Return full fib lookup match.
pub const RTM_F_FIB_MATCH: u32 = 0x2000;
/// Route is offloaded.
pub const RTM_F_OFFLOAD: u32 = 0x4000;
/// Route is trapping packets.
pub const RTM_F_TRAP: u32 = 0x8000;
/// `RTMGRP_IPV6_PREFIX` from `<linux/rtnetlink.h>`.
pub const RTMGRP_IPV6_PREFIX: u32 = 0x2_0000;
/// `RTM_F_OFFLOAD_FAILED` from `<linux/rtnetlink.h>`.
pub const RTM_F_OFFLOAD_FAILED: u32 = 0x2000_0000;
/// `RT_TABLE_MAX` from `<linux/rtnetlink.h>`.
pub const RT_TABLE_MAX: u32 = 0xffff_ffff;

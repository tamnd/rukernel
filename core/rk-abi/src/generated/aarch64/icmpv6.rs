// rk-abigen generated this file from Linux 7.3, from <linux/icmpv6.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The types and the codes of ICMPv6 messages and the socket option `ICMPV6_FILTER`.

/// `ICMPV6_EXC_HOPLIMIT` from `<linux/icmpv6.h>`.
pub const ICMPV6_EXC_HOPLIMIT: u32 = 0;
/// `ICMPV6_HDR_FIELD` from `<linux/icmpv6.h>`.
pub const ICMPV6_HDR_FIELD: u32 = 0;
/// `ICMPV6_NOROUTE` from `<linux/icmpv6.h>`.
pub const ICMPV6_NOROUTE: u32 = 0;
/// `ICMPV6_ROUTER_PREF_MEDIUM` from `<linux/icmpv6.h>`.
pub const ICMPV6_ROUTER_PREF_MEDIUM: u32 = 0;
/// `ICMPV6_ADM_PROHIBITED` from `<linux/icmpv6.h>`.
pub const ICMPV6_ADM_PROHIBITED: u32 = 1;
/// `ICMPV6_DEST_UNREACH` from `<linux/icmpv6.h>`.
pub const ICMPV6_DEST_UNREACH: u32 = 1;
/// `ICMPV6_EXC_FRAGTIME` from `<linux/icmpv6.h>`.
pub const ICMPV6_EXC_FRAGTIME: u32 = 1;
/// `ICMPV6_FILTER` from `<linux/icmpv6.h>`.
pub const ICMPV6_FILTER: u32 = 1;
/// `ICMPV6_FILTER_BLOCK` from `<linux/icmpv6.h>`.
pub const ICMPV6_FILTER_BLOCK: u32 = 1;
/// `ICMPV6_ROUTER_PREF_HIGH` from `<linux/icmpv6.h>`.
pub const ICMPV6_ROUTER_PREF_HIGH: u32 = 1;
/// `ICMPV6_UNK_NEXTHDR` from `<linux/icmpv6.h>`.
pub const ICMPV6_UNK_NEXTHDR: u32 = 1;
/// `ICMPV6_FILTER_PASS` from `<linux/icmpv6.h>`.
pub const ICMPV6_FILTER_PASS: u32 = 2;
/// `ICMPV6_NOT_NEIGHBOUR` from `<linux/icmpv6.h>`.
pub const ICMPV6_NOT_NEIGHBOUR: u32 = 2;
/// `ICMPV6_PKT_TOOBIG` from `<linux/icmpv6.h>`.
pub const ICMPV6_PKT_TOOBIG: u32 = 2;
/// `ICMPV6_ROUTER_PREF_INVALID` from `<linux/icmpv6.h>`.
pub const ICMPV6_ROUTER_PREF_INVALID: u32 = 2;
/// `ICMPV6_UNK_OPTION` from `<linux/icmpv6.h>`.
pub const ICMPV6_UNK_OPTION: u32 = 2;
/// `ICMPV6_ADDR_UNREACH` from `<linux/icmpv6.h>`.
pub const ICMPV6_ADDR_UNREACH: u32 = 3;
/// `ICMPV6_FILTER_BLOCKOTHERS` from `<linux/icmpv6.h>`.
pub const ICMPV6_FILTER_BLOCKOTHERS: u32 = 3;
/// `ICMPV6_HDR_INCOMP` from `<linux/icmpv6.h>`.
pub const ICMPV6_HDR_INCOMP: u32 = 3;
/// `ICMPV6_ROUTER_PREF_LOW` from `<linux/icmpv6.h>`.
pub const ICMPV6_ROUTER_PREF_LOW: u32 = 3;
/// `ICMPV6_TIME_EXCEED` from `<linux/icmpv6.h>`.
pub const ICMPV6_TIME_EXCEED: u32 = 3;
/// `ICMPV6_FILTER_PASSONLY` from `<linux/icmpv6.h>`.
pub const ICMPV6_FILTER_PASSONLY: u32 = 4;
/// `ICMPV6_PARAMPROB` from `<linux/icmpv6.h>`.
pub const ICMPV6_PARAMPROB: u32 = 4;
/// `ICMPV6_PORT_UNREACH` from `<linux/icmpv6.h>`.
pub const ICMPV6_PORT_UNREACH: u32 = 4;
/// `ICMPV6_POLICY_FAIL` from `<linux/icmpv6.h>`.
pub const ICMPV6_POLICY_FAIL: u32 = 5;
/// `ICMPV6_REJECT_ROUTE` from `<linux/icmpv6.h>`.
pub const ICMPV6_REJECT_ROUTE: u32 = 6;
/// `ICMPV6_ERRMSG_MAX` from `<linux/icmpv6.h>`.
pub const ICMPV6_ERRMSG_MAX: u32 = 127;
/// `ICMPV6_ECHO_REQUEST` from `<linux/icmpv6.h>`.
pub const ICMPV6_ECHO_REQUEST: u32 = 128;
/// `ICMPV6_INFOMSG_MASK` from `<linux/icmpv6.h>`.
pub const ICMPV6_INFOMSG_MASK: u32 = 128;
/// `ICMPV6_ECHO_REPLY` from `<linux/icmpv6.h>`.
pub const ICMPV6_ECHO_REPLY: u32 = 129;
/// `ICMPV6_MGM_QUERY` from `<linux/icmpv6.h>`.
pub const ICMPV6_MGM_QUERY: u32 = 130;
/// `ICMPV6_MGM_REPORT` from `<linux/icmpv6.h>`.
pub const ICMPV6_MGM_REPORT: u32 = 131;
/// `ICMPV6_MGM_REDUCTION` from `<linux/icmpv6.h>`.
pub const ICMPV6_MGM_REDUCTION: u32 = 132;
/// `ICMPV6_NI_QUERY` from `<linux/icmpv6.h>`.
pub const ICMPV6_NI_QUERY: u32 = 139;
/// `ICMPV6_NI_REPLY` from `<linux/icmpv6.h>`.
pub const ICMPV6_NI_REPLY: u32 = 140;
/// `ICMPV6_MLD2_REPORT` from `<linux/icmpv6.h>`.
pub const ICMPV6_MLD2_REPORT: u32 = 143;
/// `ICMPV6_DHAAD_REQUEST` from `<linux/icmpv6.h>`.
pub const ICMPV6_DHAAD_REQUEST: u32 = 144;
/// `ICMPV6_DHAAD_REPLY` from `<linux/icmpv6.h>`.
pub const ICMPV6_DHAAD_REPLY: u32 = 145;
/// `ICMPV6_MOBILE_PREFIX_SOL` from `<linux/icmpv6.h>`.
pub const ICMPV6_MOBILE_PREFIX_SOL: u32 = 146;
/// `ICMPV6_MOBILE_PREFIX_ADV` from `<linux/icmpv6.h>`.
pub const ICMPV6_MOBILE_PREFIX_ADV: u32 = 147;
/// `ICMPV6_MRDISC_ADV` from `<linux/icmpv6.h>`.
pub const ICMPV6_MRDISC_ADV: u32 = 151;
/// `ICMPV6_MRDISC_SOL` from `<linux/icmpv6.h>`.
pub const ICMPV6_MRDISC_SOL: u32 = 152;
/// `ICMPV6_EXT_ECHO_REQUEST` from `<linux/icmpv6.h>`.
pub const ICMPV6_EXT_ECHO_REQUEST: u32 = 160;
/// `ICMPV6_EXT_ECHO_REPLY` from `<linux/icmpv6.h>`.
pub const ICMPV6_EXT_ECHO_REPLY: u32 = 161;
/// `ICMPV6_MSG_MAX` from `<linux/icmpv6.h>`.
pub const ICMPV6_MSG_MAX: u32 = 255;

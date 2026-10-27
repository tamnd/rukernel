// rk-abigen generated this file from Linux 7.3, from <linux/if_link.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The attributes of a link message of rtnetlink.

/// `IFLA_UNSPEC` from `<linux/if_link.h>`.
pub const IFLA_UNSPEC: u32 = 0;
/// `IFLA_XDP_UNSPEC` from `<linux/if_link.h>`.
pub const IFLA_XDP_UNSPEC: u32 = 0;
/// `XDP_ATTACHED_NONE` from `<linux/if_link.h>`.
pub const XDP_ATTACHED_NONE: u32 = 0;
/// `IFLA_ADDRESS` from `<linux/if_link.h>`.
pub const IFLA_ADDRESS: u32 = 1;
/// `IFLA_XDP_FD` from `<linux/if_link.h>`.
pub const IFLA_XDP_FD: u32 = 1;
/// `IFLA_BROADCAST` from `<linux/if_link.h>`.
pub const IFLA_BROADCAST: u32 = 2;
/// `IFLA_XDP_ATTACHED` from `<linux/if_link.h>`.
pub const IFLA_XDP_ATTACHED: u32 = 2;
/// `IFLA_IFNAME` from `<linux/if_link.h>`.
pub const IFLA_IFNAME: u32 = 3;
/// `IFLA_MTU` from `<linux/if_link.h>`.
pub const IFLA_MTU: u32 = 4;
/// `IFLA_LINK` from `<linux/if_link.h>`.
pub const IFLA_LINK: u32 = 5;
/// `IFLA_QDISC` from `<linux/if_link.h>`.
pub const IFLA_QDISC: u32 = 6;
/// `IFLA_STATS` from `<linux/if_link.h>`.
pub const IFLA_STATS: u32 = 7;
/// `IFLA_COST` from `<linux/if_link.h>`.
pub const IFLA_COST: u32 = 8;
/// `IFLA_PRIORITY` from `<linux/if_link.h>`.
pub const IFLA_PRIORITY: u32 = 9;
/// `IFLA_MASTER` from `<linux/if_link.h>`.
pub const IFLA_MASTER: u32 = 10;
/// `IFLA_WIRELESS` from `<linux/if_link.h>`.
pub const IFLA_WIRELESS: u32 = 11;
/// `IFLA_PROTINFO` from `<linux/if_link.h>`.
pub const IFLA_PROTINFO: u32 = 12;
/// `IFLA_TXQLEN` from `<linux/if_link.h>`.
pub const IFLA_TXQLEN: u32 = 13;
/// `IFLA_MAP` from `<linux/if_link.h>`.
pub const IFLA_MAP: u32 = 14;
/// `IFLA_WEIGHT` from `<linux/if_link.h>`.
pub const IFLA_WEIGHT: u32 = 15;
/// `IFLA_OPERSTATE` from `<linux/if_link.h>`.
pub const IFLA_OPERSTATE: u32 = 16;
/// `IFLA_LINKMODE` from `<linux/if_link.h>`.
pub const IFLA_LINKMODE: u32 = 17;
/// `IFLA_LINKINFO` from `<linux/if_link.h>`.
pub const IFLA_LINKINFO: u32 = 18;
/// `IFLA_NET_NS_PID` from `<linux/if_link.h>`.
pub const IFLA_NET_NS_PID: u32 = 19;
/// `IFLA_IFALIAS` from `<linux/if_link.h>`.
pub const IFLA_IFALIAS: u32 = 20;
/// `IFLA_NUM_VF` from `<linux/if_link.h>`.
pub const IFLA_NUM_VF: u32 = 21;
/// `IFLA_VFINFO_LIST` from `<linux/if_link.h>`.
pub const IFLA_VFINFO_LIST: u32 = 22;
/// `IFLA_STATS64` from `<linux/if_link.h>`.
pub const IFLA_STATS64: u32 = 23;
/// `IFLA_VF_PORTS` from `<linux/if_link.h>`.
pub const IFLA_VF_PORTS: u32 = 24;
/// `IFLA_PORT_SELF` from `<linux/if_link.h>`.
pub const IFLA_PORT_SELF: u32 = 25;
/// `IFLA_AF_SPEC` from `<linux/if_link.h>`.
pub const IFLA_AF_SPEC: u32 = 26;
/// `IFLA_GROUP` from `<linux/if_link.h>`.
pub const IFLA_GROUP: u32 = 27;
/// `IFLA_NET_NS_FD` from `<linux/if_link.h>`.
pub const IFLA_NET_NS_FD: u32 = 28;
/// `IFLA_EXT_MASK` from `<linux/if_link.h>`.
pub const IFLA_EXT_MASK: u32 = 29;
/// `IFLA_PROMISCUITY` from `<linux/if_link.h>`.
pub const IFLA_PROMISCUITY: u32 = 30;
/// `IFLA_NUM_TX_QUEUES` from `<linux/if_link.h>`.
pub const IFLA_NUM_TX_QUEUES: u32 = 31;
/// `IFLA_NUM_RX_QUEUES` from `<linux/if_link.h>`.
pub const IFLA_NUM_RX_QUEUES: u32 = 32;
/// `IFLA_CARRIER` from `<linux/if_link.h>`.
pub const IFLA_CARRIER: u32 = 33;
/// `IFLA_PHYS_PORT_ID` from `<linux/if_link.h>`.
pub const IFLA_PHYS_PORT_ID: u32 = 34;
/// `IFLA_CARRIER_CHANGES` from `<linux/if_link.h>`.
pub const IFLA_CARRIER_CHANGES: u32 = 35;
/// `IFLA_PHYS_SWITCH_ID` from `<linux/if_link.h>`.
pub const IFLA_PHYS_SWITCH_ID: u32 = 36;
/// `IFLA_LINK_NETNSID` from `<linux/if_link.h>`.
pub const IFLA_LINK_NETNSID: u32 = 37;
/// `IFLA_PHYS_PORT_NAME` from `<linux/if_link.h>`.
pub const IFLA_PHYS_PORT_NAME: u32 = 38;
/// `IFLA_PROTO_DOWN` from `<linux/if_link.h>`.
pub const IFLA_PROTO_DOWN: u32 = 39;
/// `IFLA_GSO_MAX_SEGS` from `<linux/if_link.h>`.
pub const IFLA_GSO_MAX_SEGS: u32 = 40;
/// `IFLA_GSO_MAX_SIZE` from `<linux/if_link.h>`.
pub const IFLA_GSO_MAX_SIZE: u32 = 41;
/// `IFLA_PAD` from `<linux/if_link.h>`.
pub const IFLA_PAD: u32 = 42;
/// `IFLA_XDP` from `<linux/if_link.h>`.
pub const IFLA_XDP: u32 = 43;
/// `IFLA_EVENT` from `<linux/if_link.h>`.
pub const IFLA_EVENT: u32 = 44;
/// `IFLA_NEW_NETNSID` from `<linux/if_link.h>`.
pub const IFLA_NEW_NETNSID: u32 = 45;
/// `IFLA_IF_NETNSID` from `<linux/if_link.h>`.
pub const IFLA_IF_NETNSID: u32 = 46;
/// New alias.
pub const IFLA_TARGET_NETNSID: u32 = 46;
/// `IFLA_CARRIER_UP_COUNT` from `<linux/if_link.h>`.
pub const IFLA_CARRIER_UP_COUNT: u32 = 47;
/// `IFLA_CARRIER_DOWN_COUNT` from `<linux/if_link.h>`.
pub const IFLA_CARRIER_DOWN_COUNT: u32 = 48;
/// `IFLA_NEW_IFINDEX` from `<linux/if_link.h>`.
pub const IFLA_NEW_IFINDEX: u32 = 49;
/// `IFLA_MIN_MTU` from `<linux/if_link.h>`.
pub const IFLA_MIN_MTU: u32 = 50;
/// `IFLA_MAX_MTU` from `<linux/if_link.h>`.
pub const IFLA_MAX_MTU: u32 = 51;
/// `IFLA_PROP_LIST` from `<linux/if_link.h>`.
pub const IFLA_PROP_LIST: u32 = 52;
/// `IFLA_ALT_IFNAME` from `<linux/if_link.h>`.
pub const IFLA_ALT_IFNAME: u32 = 53;
/// `IFLA_PERM_ADDRESS` from `<linux/if_link.h>`.
pub const IFLA_PERM_ADDRESS: u32 = 54;
/// `IFLA_PROTO_DOWN_REASON` from `<linux/if_link.h>`.
pub const IFLA_PROTO_DOWN_REASON: u32 = 55;
/// `IFLA_PARENT_DEV_NAME` from `<linux/if_link.h>`.
pub const IFLA_PARENT_DEV_NAME: u32 = 56;
/// `IFLA_PARENT_DEV_BUS_NAME` from `<linux/if_link.h>`.
pub const IFLA_PARENT_DEV_BUS_NAME: u32 = 57;
/// `IFLA_GRO_MAX_SIZE` from `<linux/if_link.h>`.
pub const IFLA_GRO_MAX_SIZE: u32 = 58;
/// `IFLA_TSO_MAX_SIZE` from `<linux/if_link.h>`.
pub const IFLA_TSO_MAX_SIZE: u32 = 59;
/// `IFLA_TSO_MAX_SEGS` from `<linux/if_link.h>`.
pub const IFLA_TSO_MAX_SEGS: u32 = 60;
/// `IFLA_ALLMULTI` from `<linux/if_link.h>`.
pub const IFLA_ALLMULTI: u32 = 61;
/// `IFLA_DEVLINK_PORT` from `<linux/if_link.h>`.
pub const IFLA_DEVLINK_PORT: u32 = 62;
/// `IFLA_GSO_IPV4_MAX_SIZE` from `<linux/if_link.h>`.
pub const IFLA_GSO_IPV4_MAX_SIZE: u32 = 63;
/// `IFLA_GRO_IPV4_MAX_SIZE` from `<linux/if_link.h>`.
pub const IFLA_GRO_IPV4_MAX_SIZE: u32 = 64;
/// `IFLA_DPLL_PIN` from `<linux/if_link.h>`.
pub const IFLA_DPLL_PIN: u32 = 65;
/// `IFLA_MAX_PACING_OFFLOAD_HORIZON` from `<linux/if_link.h>`.
pub const IFLA_MAX_PACING_OFFLOAD_HORIZON: u32 = 66;
/// `IFLA_NETNS_IMMUTABLE` from `<linux/if_link.h>`.
pub const IFLA_NETNS_IMMUTABLE: u32 = 67;
/// `IFLA_HEADROOM` from `<linux/if_link.h>`.
pub const IFLA_HEADROOM: u32 = 68;
/// `IFLA_TAILROOM` from `<linux/if_link.h>`.
pub const IFLA_TAILROOM: u32 = 69;

// rk-abigen generated this file from Linux 7.3, from <linux/netlink.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The netlink protocols, the message flags and types, and the socket options of netlink.

/// Routing/device hook.
pub const NETLINK_ROUTE: u32 = 0;
/// `NETLINK_UNCONNECTED` from `<linux/netlink.h>`.
pub const NETLINK_UNCONNECTED: u32 = 0;
/// `NLMSGERR_ATTR_UNUSED` from `<linux/netlink.h>`.
pub const NLMSGERR_ATTR_UNUSED: u32 = 0;
/// `NETLINK_ADD_MEMBERSHIP` from `<linux/netlink.h>`.
pub const NETLINK_ADD_MEMBERSHIP: u32 = 1;
/// `NETLINK_CONNECTED` from `<linux/netlink.h>`.
pub const NETLINK_CONNECTED: u32 = 1;
/// Unused number.
pub const NETLINK_UNUSED: u32 = 1;
/// `NLMSGERR_ATTR_MSG` from `<linux/netlink.h>`.
pub const NLMSGERR_ATTR_MSG: u32 = 1;
/// Nothing.
pub const NLMSG_NOOP: u32 = 1;
/// It is request message.
pub const NLM_F_REQUEST: u32 = 1;
/// `NETLINK_DROP_MEMBERSHIP` from `<linux/netlink.h>`.
pub const NETLINK_DROP_MEMBERSHIP: u32 = 2;
/// Reserved for user mode socket protocols.
pub const NETLINK_USERSOCK: u32 = 2;
/// `NLMSGERR_ATTR_OFFS` from `<linux/netlink.h>`.
pub const NLMSGERR_ATTR_OFFS: u32 = 2;
/// Error.
pub const NLMSG_ERROR: u32 = 2;
/// Multipart message, terminated by NLMSG\_DONE.
pub const NLM_F_MULTI: u32 = 2;
/// Unused number, formerly ip\_queue.
pub const NETLINK_FIREWALL: u32 = 3;
/// `NETLINK_PKTINFO` from `<linux/netlink.h>`.
pub const NETLINK_PKTINFO: u32 = 3;
/// `NLMSGERR_ATTR_COOKIE` from `<linux/netlink.h>`.
pub const NLMSGERR_ATTR_COOKIE: u32 = 3;
/// End of a dump.
pub const NLMSG_DONE: u32 = 3;
/// `NETLINK_BROADCAST_ERROR` from `<linux/netlink.h>`.
pub const NETLINK_BROADCAST_ERROR: u32 = 4;
/// The same value as `NETLINK_SOCK_DIAG`.
pub const NETLINK_INET_DIAG: u32 = 4;
/// Socket monitoring.
pub const NETLINK_SOCK_DIAG: u32 = 4;
/// `NLA_ALIGNTO` from `<linux/netlink.h>`.
pub const NLA_ALIGNTO: u32 = 4;
/// `NLA_HDRLEN` from `<linux/netlink.h>`.
pub const NLA_HDRLEN: u32 = 4;
/// `NLMSGERR_ATTR_POLICY` from `<linux/netlink.h>`.
pub const NLMSGERR_ATTR_POLICY: u32 = 4;
/// `NLMSG_ALIGNTO` from `<linux/netlink.h>`.
pub const NLMSG_ALIGNTO: u32 = 4;
/// Data lost.
pub const NLMSG_OVERRUN: u32 = 4;
/// Reply with ack, with zero or error code.
pub const NLM_F_ACK: u32 = 4;
/// Netfilter/iptables ULOG.
pub const NETLINK_NFLOG: u32 = 5;
/// `NETLINK_NO_ENOBUFS` from `<linux/netlink.h>`.
pub const NETLINK_NO_ENOBUFS: u32 = 5;
/// `NLMSGERR_ATTR_MISS_TYPE` from `<linux/netlink.h>`.
pub const NLMSGERR_ATTR_MISS_TYPE: u32 = 5;
/// `NETLINK_RX_RING` from `<linux/netlink.h>`.
pub const NETLINK_RX_RING: u32 = 6;
/// Ipsec.
pub const NETLINK_XFRM: u32 = 6;
/// `NLMSGERR_ATTR_MISS_NEST` from `<linux/netlink.h>`.
pub const NLMSGERR_ATTR_MISS_NEST: u32 = 6;
/// SELinux event notifications.
pub const NETLINK_SELINUX: u32 = 7;
/// `NETLINK_TX_RING` from `<linux/netlink.h>`.
pub const NETLINK_TX_RING: u32 = 7;
/// Open-iSCSI.
pub const NETLINK_ISCSI: u32 = 8;
/// `NETLINK_LISTEN_ALL_NSID` from `<linux/netlink.h>`.
pub const NETLINK_LISTEN_ALL_NSID: u32 = 8;
/// Receive resulting notifications.
pub const NLM_F_ECHO: u32 = 8;
/// Auditing.
pub const NETLINK_AUDIT: u32 = 9;
/// `NETLINK_LIST_MEMBERSHIPS` from `<linux/netlink.h>`.
pub const NETLINK_LIST_MEMBERSHIPS: u32 = 9;
/// `NETLINK_CAP_ACK` from `<linux/netlink.h>`.
pub const NETLINK_CAP_ACK: u32 = 10;
/// `NETLINK_FIB_LOOKUP` from `<linux/netlink.h>`.
pub const NETLINK_FIB_LOOKUP: u32 = 10;
/// `NETLINK_CONNECTOR` from `<linux/netlink.h>`.
pub const NETLINK_CONNECTOR: u32 = 11;
/// `NETLINK_EXT_ACK` from `<linux/netlink.h>`.
pub const NETLINK_EXT_ACK: u32 = 11;
/// `NETLINK_GET_STRICT_CHK` from `<linux/netlink.h>`.
pub const NETLINK_GET_STRICT_CHK: u32 = 12;
/// Netfilter subsystem.
pub const NETLINK_NETFILTER: u32 = 12;
/// `NETLINK_IP6_FW` from `<linux/netlink.h>`.
pub const NETLINK_IP6_FW: u32 = 13;
/// DECnet routing messages (obsolete).
pub const NETLINK_DNRTMSG: u32 = 14;
/// Kernel messages to userspace.
pub const NETLINK_KOBJECT_UEVENT: u32 = 15;
/// `NETLINK_GENERIC` from `<linux/netlink.h>`.
pub const NETLINK_GENERIC: u32 = 16;
/// `NLMSG_HDRLEN` from `<linux/netlink.h>`.
pub const NLMSG_HDRLEN: u32 = 16;
/// \< 0x10: reserved control messages.
pub const NLMSG_MIN_TYPE: u32 = 16;
/// Dump was inconsistent due to sequence change.
pub const NLM_F_DUMP_INTR: u32 = 16;
/// SCSI Transports.
pub const NETLINK_SCSITRANSPORT: u32 = 18;
/// `NETLINK_ECRYPTFS` from `<linux/netlink.h>`.
pub const NETLINK_ECRYPTFS: u32 = 19;
/// `NETLINK_RDMA` from `<linux/netlink.h>`.
pub const NETLINK_RDMA: u32 = 20;
/// Crypto layer.
pub const NETLINK_CRYPTO: u32 = 21;
/// SMC monitoring.
pub const NETLINK_SMC: u32 = 22;
/// Dump was filtered as requested.
pub const NLM_F_DUMP_FILTERED: u32 = 32;
/// Request was capped.
pub const NLM_F_CAPPED: u32 = 0x100;
/// Do not delete recursively.
pub const NLM_F_NONREC: u32 = 0x100;
/// Override existing.
pub const NLM_F_REPLACE: u32 = 0x100;
/// Specify tree root.
pub const NLM_F_ROOT: u32 = 0x100;
/// Extended ACK TVLs were included.
pub const NLM_F_ACK_TLVS: u32 = 0x200;
/// Delete multiple objects.
pub const NLM_F_BULK: u32 = 0x200;
/// Do not touch, if it exists.
pub const NLM_F_EXCL: u32 = 0x200;
/// Return all matching.
pub const NLM_F_MATCH: u32 = 0x200;
/// `NLM_F_DUMP` from `<linux/netlink.h>`.
pub const NLM_F_DUMP: u32 = 0x300;
/// Atomic GET.
pub const NLM_F_ATOMIC: u32 = 0x400;
/// Create, if it does not exist.
pub const NLM_F_CREATE: u32 = 0x400;
/// Add to end of list.
pub const NLM_F_APPEND: u32 = 0x800;
/// `NLA_F_NET_BYTEORDER` from `<linux/netlink.h>`.
pub const NLA_F_NET_BYTEORDER: u32 = 0x4000;
/// `NLA_F_NESTED` from `<linux/netlink.h>`.
pub const NLA_F_NESTED: u32 = 0x8000;
/// `NLA_TYPE_MASK` from `<linux/netlink.h>`.
pub const NLA_TYPE_MASK: u32 = 0xffff_3fff;

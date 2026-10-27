// rk-abigen generated this file from Linux 7.3, from <linux/if_addr.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The attributes and flags of an address message of rtnetlink.

/// `IFAPROT_UNSPEC` from `<linux/if_addr.h>`.
pub const IFAPROT_UNSPEC: u32 = 0;
/// `IFA_UNSPEC` from `<linux/if_addr.h>`.
pub const IFA_UNSPEC: u32 = 0;
/// Loopback.
pub const IFAPROT_KERNEL_LO: u32 = 1;
/// `IFA_ADDRESS` from `<linux/if_addr.h>`.
pub const IFA_ADDRESS: u32 = 1;
/// `IFA_F_SECONDARY` from `<linux/if_addr.h>`.
pub const IFA_F_SECONDARY: u32 = 1;
/// The same value as `IFA_F_SECONDARY`.
pub const IFA_F_TEMPORARY: u32 = 1;
/// Set by kernel from router announcement.
pub const IFAPROT_KERNEL_RA: u32 = 2;
/// `IFA_F_NODAD` from `<linux/if_addr.h>`.
pub const IFA_F_NODAD: u32 = 2;
/// `IFA_LOCAL` from `<linux/if_addr.h>`.
pub const IFA_LOCAL: u32 = 2;
/// Link-local set by kernel.
pub const IFAPROT_KERNEL_LL: u32 = 3;
/// `IFA_LABEL` from `<linux/if_addr.h>`.
pub const IFA_LABEL: u32 = 3;
/// `IFA_BROADCAST` from `<linux/if_addr.h>`.
pub const IFA_BROADCAST: u32 = 4;
/// `IFA_F_OPTIMISTIC` from `<linux/if_addr.h>`.
pub const IFA_F_OPTIMISTIC: u32 = 4;
/// `IFA_ANYCAST` from `<linux/if_addr.h>`.
pub const IFA_ANYCAST: u32 = 5;
/// `IFA_CACHEINFO` from `<linux/if_addr.h>`.
pub const IFA_CACHEINFO: u32 = 6;
/// `IFA_MULTICAST` from `<linux/if_addr.h>`.
pub const IFA_MULTICAST: u32 = 7;
/// `IFA_FLAGS` from `<linux/if_addr.h>`.
pub const IFA_FLAGS: u32 = 8;
/// `IFA_F_DADFAILED` from `<linux/if_addr.h>`.
pub const IFA_F_DADFAILED: u32 = 8;
/// `IFA_RT_PRIORITY` from `<linux/if_addr.h>`.
pub const IFA_RT_PRIORITY: u32 = 9;
/// `IFA_TARGET_NETNSID` from `<linux/if_addr.h>`.
pub const IFA_TARGET_NETNSID: u32 = 10;
/// `IFA_PROTO` from `<linux/if_addr.h>`.
pub const IFA_PROTO: u32 = 11;
/// `IFA_MC_USERS` from `<linux/if_addr.h>`.
pub const IFA_MC_USERS: u32 = 12;
/// `IFA_F_HOMEADDRESS` from `<linux/if_addr.h>`.
pub const IFA_F_HOMEADDRESS: u32 = 16;
/// `IFA_F_DEPRECATED` from `<linux/if_addr.h>`.
pub const IFA_F_DEPRECATED: u32 = 32;
/// `IFA_F_TENTATIVE` from `<linux/if_addr.h>`.
pub const IFA_F_TENTATIVE: u32 = 64;
/// `IFA_F_PERMANENT` from `<linux/if_addr.h>`.
pub const IFA_F_PERMANENT: u32 = 128;
/// `IFA_F_MANAGETEMPADDR` from `<linux/if_addr.h>`.
pub const IFA_F_MANAGETEMPADDR: u32 = 0x100;
/// `IFA_F_NOPREFIXROUTE` from `<linux/if_addr.h>`.
pub const IFA_F_NOPREFIXROUTE: u32 = 0x200;
/// `IFA_F_MCAUTOJOIN` from `<linux/if_addr.h>`.
pub const IFA_F_MCAUTOJOIN: u32 = 0x400;
/// `IFA_F_STABLE_PRIVACY` from `<linux/if_addr.h>`.
pub const IFA_F_STABLE_PRIVACY: u32 = 0x800;

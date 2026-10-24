// rk-abigen generated this file from Linux 7.3, from <asm/socket.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The options of `getsockopt` and `setsockopt` at the level `SOL_SOCKET`, and the types of the control messages.

/// `SOL_SOCKET` from `<asm/socket.h>`.
pub const SOL_SOCKET: u32 = 1;
/// `SO_DEBUG` from `<asm/socket.h>`.
pub const SO_DEBUG: u32 = 1;
/// `SO_REUSEADDR` from `<asm/socket.h>`.
pub const SO_REUSEADDR: u32 = 2;
/// `SO_TYPE` from `<asm/socket.h>`.
pub const SO_TYPE: u32 = 3;
/// `SO_ERROR` from `<asm/socket.h>`.
pub const SO_ERROR: u32 = 4;
/// `SO_DONTROUTE` from `<asm/socket.h>`.
pub const SO_DONTROUTE: u32 = 5;
/// `SO_BROADCAST` from `<asm/socket.h>`.
pub const SO_BROADCAST: u32 = 6;
/// `SO_SNDBUF` from `<asm/socket.h>`.
pub const SO_SNDBUF: u32 = 7;
/// `SO_RCVBUF` from `<asm/socket.h>`.
pub const SO_RCVBUF: u32 = 8;
/// `SO_KEEPALIVE` from `<asm/socket.h>`.
pub const SO_KEEPALIVE: u32 = 9;
/// `SO_OOBINLINE` from `<asm/socket.h>`.
pub const SO_OOBINLINE: u32 = 10;
/// `SO_NO_CHECK` from `<asm/socket.h>`.
pub const SO_NO_CHECK: u32 = 11;
/// `SO_PRIORITY` from `<asm/socket.h>`.
pub const SO_PRIORITY: u32 = 12;
/// `SO_LINGER` from `<asm/socket.h>`.
pub const SO_LINGER: u32 = 13;
/// `SO_BSDCOMPAT` from `<asm/socket.h>`.
pub const SO_BSDCOMPAT: u32 = 14;
/// `SO_REUSEPORT` from `<asm/socket.h>`.
pub const SO_REUSEPORT: u32 = 15;
/// `SO_PASSCRED` from `<asm/socket.h>`.
pub const SO_PASSCRED: u32 = 16;
/// `SO_PEERCRED` from `<asm/socket.h>`.
pub const SO_PEERCRED: u32 = 17;
/// `SO_RCVLOWAT` from `<asm/socket.h>`.
pub const SO_RCVLOWAT: u32 = 18;
/// `SO_SNDLOWAT` from `<asm/socket.h>`.
pub const SO_SNDLOWAT: u32 = 19;
/// The same value as `SO_RCVTIMEO_OLD`.
pub const SO_RCVTIMEO: u32 = 20;
/// `SO_RCVTIMEO_OLD` from `<asm/socket.h>`.
pub const SO_RCVTIMEO_OLD: u32 = 20;
/// The same value as `SO_SNDTIMEO_OLD`.
pub const SO_SNDTIMEO: u32 = 21;
/// `SO_SNDTIMEO_OLD` from `<asm/socket.h>`.
pub const SO_SNDTIMEO_OLD: u32 = 21;
/// `SO_SECURITY_AUTHENTICATION` from `<asm/socket.h>`.
pub const SO_SECURITY_AUTHENTICATION: u32 = 22;
/// `SO_SECURITY_ENCRYPTION_TRANSPORT` from `<asm/socket.h>`.
pub const SO_SECURITY_ENCRYPTION_TRANSPORT: u32 = 23;
/// `SO_SECURITY_ENCRYPTION_NETWORK` from `<asm/socket.h>`.
pub const SO_SECURITY_ENCRYPTION_NETWORK: u32 = 24;
/// `SO_BINDTODEVICE` from `<asm/socket.h>`.
pub const SO_BINDTODEVICE: u32 = 25;
/// `SO_ATTACH_FILTER` from `<asm/socket.h>`.
pub const SO_ATTACH_FILTER: u32 = 26;
/// The same value as `SO_ATTACH_FILTER`.
pub const SO_GET_FILTER: u32 = 26;
/// The same value as `SO_DETACH_FILTER`.
pub const SO_DETACH_BPF: u32 = 27;
/// `SO_DETACH_FILTER` from `<asm/socket.h>`.
pub const SO_DETACH_FILTER: u32 = 27;
/// `SO_PEERNAME` from `<asm/socket.h>`.
pub const SO_PEERNAME: u32 = 28;
/// The same value as `SO_TIMESTAMP`.
pub const SCM_TIMESTAMP: u32 = 29;
/// The same value as `SO_TIMESTAMP_OLD`.
pub const SO_TIMESTAMP: u32 = 29;
/// `SO_TIMESTAMP_OLD` from `<asm/socket.h>`.
pub const SO_TIMESTAMP_OLD: u32 = 29;
/// `SO_ACCEPTCONN` from `<asm/socket.h>`.
pub const SO_ACCEPTCONN: u32 = 30;
/// `SO_PEERSEC` from `<asm/socket.h>`.
pub const SO_PEERSEC: u32 = 31;
/// `SO_SNDBUFFORCE` from `<asm/socket.h>`.
pub const SO_SNDBUFFORCE: u32 = 32;
/// `SO_RCVBUFFORCE` from `<asm/socket.h>`.
pub const SO_RCVBUFFORCE: u32 = 33;
/// `SO_PASSSEC` from `<asm/socket.h>`.
pub const SO_PASSSEC: u32 = 34;
/// The same value as `SO_TIMESTAMPNS`.
pub const SCM_TIMESTAMPNS: u32 = 35;
/// The same value as `SO_TIMESTAMPNS_OLD`.
pub const SO_TIMESTAMPNS: u32 = 35;
/// `SO_TIMESTAMPNS_OLD` from `<asm/socket.h>`.
pub const SO_TIMESTAMPNS_OLD: u32 = 35;
/// `SO_MARK` from `<asm/socket.h>`.
pub const SO_MARK: u32 = 36;
/// The same value as `SO_TIMESTAMPING`.
pub const SCM_TIMESTAMPING: u32 = 37;
/// The same value as `SO_TIMESTAMPING_OLD`.
pub const SO_TIMESTAMPING: u32 = 37;
/// `SO_TIMESTAMPING_OLD` from `<asm/socket.h>`.
pub const SO_TIMESTAMPING_OLD: u32 = 37;
/// `SO_PROTOCOL` from `<asm/socket.h>`.
pub const SO_PROTOCOL: u32 = 38;
/// `SO_DOMAIN` from `<asm/socket.h>`.
pub const SO_DOMAIN: u32 = 39;
/// `SO_RXQ_OVFL` from `<asm/socket.h>`.
pub const SO_RXQ_OVFL: u32 = 40;
/// The same value as `SO_WIFI_STATUS`.
pub const SCM_WIFI_STATUS: u32 = 41;
/// `SO_WIFI_STATUS` from `<asm/socket.h>`.
pub const SO_WIFI_STATUS: u32 = 41;
/// `SO_PEEK_OFF` from `<asm/socket.h>`.
pub const SO_PEEK_OFF: u32 = 42;
/// `SO_NOFCS` from `<asm/socket.h>`.
pub const SO_NOFCS: u32 = 43;
/// `SO_LOCK_FILTER` from `<asm/socket.h>`.
pub const SO_LOCK_FILTER: u32 = 44;
/// `SO_SELECT_ERR_QUEUE` from `<asm/socket.h>`.
pub const SO_SELECT_ERR_QUEUE: u32 = 45;
/// `SO_BUSY_POLL` from `<asm/socket.h>`.
pub const SO_BUSY_POLL: u32 = 46;
/// `SO_MAX_PACING_RATE` from `<asm/socket.h>`.
pub const SO_MAX_PACING_RATE: u32 = 47;
/// `SO_BPF_EXTENSIONS` from `<asm/socket.h>`.
pub const SO_BPF_EXTENSIONS: u32 = 48;
/// `SO_INCOMING_CPU` from `<asm/socket.h>`.
pub const SO_INCOMING_CPU: u32 = 49;
/// `SO_ATTACH_BPF` from `<asm/socket.h>`.
pub const SO_ATTACH_BPF: u32 = 50;
/// `SO_ATTACH_REUSEPORT_CBPF` from `<asm/socket.h>`.
pub const SO_ATTACH_REUSEPORT_CBPF: u32 = 51;
/// `SO_ATTACH_REUSEPORT_EBPF` from `<asm/socket.h>`.
pub const SO_ATTACH_REUSEPORT_EBPF: u32 = 52;
/// `SO_CNX_ADVICE` from `<asm/socket.h>`.
pub const SO_CNX_ADVICE: u32 = 53;
/// `SCM_TIMESTAMPING_OPT_STATS` from `<asm/socket.h>`.
pub const SCM_TIMESTAMPING_OPT_STATS: u32 = 54;
/// `SO_MEMINFO` from `<asm/socket.h>`.
pub const SO_MEMINFO: u32 = 55;
/// `SO_INCOMING_NAPI_ID` from `<asm/socket.h>`.
pub const SO_INCOMING_NAPI_ID: u32 = 56;
/// `SO_COOKIE` from `<asm/socket.h>`.
pub const SO_COOKIE: u32 = 57;
/// `SCM_TIMESTAMPING_PKTINFO` from `<asm/socket.h>`.
pub const SCM_TIMESTAMPING_PKTINFO: u32 = 58;
/// `SO_PEERGROUPS` from `<asm/socket.h>`.
pub const SO_PEERGROUPS: u32 = 59;
/// `SO_ZEROCOPY` from `<asm/socket.h>`.
pub const SO_ZEROCOPY: u32 = 60;
/// The same value as `SO_TXTIME`.
pub const SCM_TXTIME: u32 = 61;
/// `SO_TXTIME` from `<asm/socket.h>`.
pub const SO_TXTIME: u32 = 61;
/// `SO_BINDTOIFINDEX` from `<asm/socket.h>`.
pub const SO_BINDTOIFINDEX: u32 = 62;
/// `SO_TIMESTAMP_NEW` from `<asm/socket.h>`.
pub const SO_TIMESTAMP_NEW: u32 = 63;
/// `SO_TIMESTAMPNS_NEW` from `<asm/socket.h>`.
pub const SO_TIMESTAMPNS_NEW: u32 = 64;
/// `SO_TIMESTAMPING_NEW` from `<asm/socket.h>`.
pub const SO_TIMESTAMPING_NEW: u32 = 65;
/// `SO_RCVTIMEO_NEW` from `<asm/socket.h>`.
pub const SO_RCVTIMEO_NEW: u32 = 66;
/// `SO_SNDTIMEO_NEW` from `<asm/socket.h>`.
pub const SO_SNDTIMEO_NEW: u32 = 67;
/// `SO_DETACH_REUSEPORT_BPF` from `<asm/socket.h>`.
pub const SO_DETACH_REUSEPORT_BPF: u32 = 68;
/// `SO_PREFER_BUSY_POLL` from `<asm/socket.h>`.
pub const SO_PREFER_BUSY_POLL: u32 = 69;
/// `SO_BUSY_POLL_BUDGET` from `<asm/socket.h>`.
pub const SO_BUSY_POLL_BUDGET: u32 = 70;
/// `SO_NETNS_COOKIE` from `<asm/socket.h>`.
pub const SO_NETNS_COOKIE: u32 = 71;
/// `SO_BUF_LOCK` from `<asm/socket.h>`.
pub const SO_BUF_LOCK: u32 = 72;
/// `SO_RESERVE_MEM` from `<asm/socket.h>`.
pub const SO_RESERVE_MEM: u32 = 73;
/// `SO_TXREHASH` from `<asm/socket.h>`.
pub const SO_TXREHASH: u32 = 74;
/// `SO_RCVMARK` from `<asm/socket.h>`.
pub const SO_RCVMARK: u32 = 75;
/// `SO_PASSPIDFD` from `<asm/socket.h>`.
pub const SO_PASSPIDFD: u32 = 76;
/// `SO_PEERPIDFD` from `<asm/socket.h>`.
pub const SO_PEERPIDFD: u32 = 77;
/// The same value as `SO_DEVMEM_LINEAR`.
pub const SCM_DEVMEM_LINEAR: u32 = 78;
/// `SO_DEVMEM_LINEAR` from `<asm/socket.h>`.
pub const SO_DEVMEM_LINEAR: u32 = 78;
/// The same value as `SO_DEVMEM_DMABUF`.
pub const SCM_DEVMEM_DMABUF: u32 = 79;
/// `SO_DEVMEM_DMABUF` from `<asm/socket.h>`.
pub const SO_DEVMEM_DMABUF: u32 = 79;
/// `SO_DEVMEM_DONTNEED` from `<asm/socket.h>`.
pub const SO_DEVMEM_DONTNEED: u32 = 80;
/// `SCM_TS_OPT_ID` from `<asm/socket.h>`.
pub const SCM_TS_OPT_ID: u32 = 81;
/// `SO_RCVPRIORITY` from `<asm/socket.h>`.
pub const SO_RCVPRIORITY: u32 = 82;
/// `SO_PASSRIGHTS` from `<asm/socket.h>`.
pub const SO_PASSRIGHTS: u32 = 83;
/// The same value as `SO_INQ`.
pub const SCM_INQ: u32 = 84;
/// `SO_INQ` from `<asm/socket.h>`.
pub const SO_INQ: u32 = 84;
/// `SO_RIGHTS_NOTRUNC` from `<asm/socket.h>`.
pub const SO_RIGHTS_NOTRUNC: u32 = 85;

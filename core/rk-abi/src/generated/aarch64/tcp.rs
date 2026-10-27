// rk-abigen generated this file from Linux 7.3, from <linux/tcp.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The options of the level `IPPROTO_TCP`.

/// `TCP_ACCECN_OPT_NOT_SEEN` from `<linux/tcp.h>`.
pub const TCP_ACCECN_OPT_NOT_SEEN: u32 = 0;
/// `TCP_REPAIR_OFF` from `<linux/tcp.h>`.
pub const TCP_REPAIR_OFF: u32 = 0;
/// `TCP_ACCECN_OPT_EMPTY_SEEN` from `<linux/tcp.h>`.
pub const TCP_ACCECN_OPT_EMPTY_SEEN: u32 = 1;
/// L3 ifindex for VRF.
pub const TCP_AO_KEYF_IFINDEX: u32 = 1;
/// Address prefix length.
pub const TCP_MD5SIG_FLAG_PREFIX: u32 = 1;
/// Turn off Nagle's algorithm.
pub const TCP_NODELAY: u32 = 1;
/// `TCP_RECEIVE_ZEROCOPY_FLAG_TLB_CLEAN_HINT` from `<linux/tcp.h>`.
pub const TCP_RECEIVE_ZEROCOPY_FLAG_TLB_CLEAN_HINT: u32 = 1;
/// `TCP_REPAIR_ON` from `<linux/tcp.h>`.
pub const TCP_REPAIR_ON: u32 = 1;
/// `TCP_ACCECN_OPT_COUNTER_SEEN` from `<linux/tcp.h>`.
pub const TCP_ACCECN_OPT_COUNTER_SEEN: u32 = 2;
/// `TCP_AO_KEYF_EXCLUDE_OPT` from `<linux/tcp.h>`.
pub const TCP_AO_KEYF_EXCLUDE_OPT: u32 = 2;
/// Limit MSS.
pub const TCP_MAXSEG: u32 = 2;
/// Ifindex set.
pub const TCP_MD5SIG_FLAG_IFINDEX: u32 = 2;
/// `TCP_ACCECN_OPT_FAIL_SEEN` from `<linux/tcp.h>`.
pub const TCP_ACCECN_OPT_FAIL_SEEN: u32 = 3;
/// Never send partially complete segments.
pub const TCP_CORK: u32 = 3;
/// Start keeplives after this period.
pub const TCP_KEEPIDLE: u32 = 4;
/// Interval between keepalives.
pub const TCP_KEEPINTVL: u32 = 5;
/// Number of keepalives before death.
pub const TCP_KEEPCNT: u32 = 6;
/// Number of SYN retransmits.
pub const TCP_SYNCNT: u32 = 7;
/// Life time of orphaned FIN-WAIT-2 state.
pub const TCP_LINGER2: u32 = 8;
/// Wake up listener only when data arrive.
pub const TCP_DEFER_ACCEPT: u32 = 9;
/// Bound advertised window.
pub const TCP_WINDOW_CLAMP: u32 = 10;
/// Information about this connection.
pub const TCP_INFO: u32 = 11;
/// Block/reenable quick acks.
pub const TCP_QUICKACK: u32 = 12;
/// Congestion control algorithm.
pub const TCP_CONGESTION: u32 = 13;
/// TCP MD5 Signature (RFC2385).
pub const TCP_MD5SIG: u32 = 14;
/// Use linear timeouts for thin streams.
pub const TCP_THIN_LINEAR_TIMEOUTS: u32 = 16;
/// Fast retrans. after 1 dupack.
pub const TCP_THIN_DUPACK: u32 = 17;
/// How long for loss retry before timeout.
pub const TCP_USER_TIMEOUT: u32 = 18;
/// TCP sock is under repair right now.
pub const TCP_REPAIR: u32 = 19;
/// `TCP_REPAIR_QUEUE` from `<linux/tcp.h>`.
pub const TCP_REPAIR_QUEUE: u32 = 20;
/// `TCP_QUEUE_SEQ` from `<linux/tcp.h>`.
pub const TCP_QUEUE_SEQ: u32 = 21;
/// `TCP_REPAIR_OPTIONS` from `<linux/tcp.h>`.
pub const TCP_REPAIR_OPTIONS: u32 = 22;
/// Enable FastOpen on listeners.
pub const TCP_FASTOPEN: u32 = 23;
/// `TCP_TIMESTAMP` from `<linux/tcp.h>`.
pub const TCP_TIMESTAMP: u32 = 24;
/// Limit number of unsent bytes in write queue.
pub const TCP_NOTSENT_LOWAT: u32 = 25;
/// Get Congestion Control (optional) info.
pub const TCP_CC_INFO: u32 = 26;
/// Record SYN headers for new connections.
pub const TCP_SAVE_SYN: u32 = 27;
/// Get SYN headers recorded for connection.
pub const TCP_SAVED_SYN: u32 = 28;
/// Get/set window parameters.
pub const TCP_REPAIR_WINDOW: u32 = 29;
/// Attempt FastOpen with connect.
pub const TCP_FASTOPEN_CONNECT: u32 = 30;
/// Attach a ULP to a TCP connection.
pub const TCP_ULP: u32 = 31;
/// TCP MD5 Signature with extensions.
pub const TCP_MD5SIG_EXT: u32 = 32;
/// Set the key for Fast Open (cookie).
pub const TCP_FASTOPEN_KEY: u32 = 33;
/// Enable TFO without a TFO cookie.
pub const TCP_FASTOPEN_NO_COOKIE: u32 = 34;
/// `TCP_ZEROCOPY_RECEIVE` from `<linux/tcp.h>`.
pub const TCP_ZEROCOPY_RECEIVE: u32 = 35;
/// The same value as `TCP_INQ`.
pub const TCP_CM_INQ: u32 = 36;
/// Notify bytes available to read as a cmsg on read.
pub const TCP_INQ: u32 = 36;
/// Delay outgoing packets by XX usec.
pub const TCP_TX_DELAY: u32 = 37;
/// Add/Set MKT.
pub const TCP_AO_ADD_KEY: u32 = 38;
/// Delete MKT.
pub const TCP_AO_DEL_KEY: u32 = 39;
/// Set/list TCP-AO per-socket options.
pub const TCP_AO_INFO: u32 = 40;
/// List MKT(s).
pub const TCP_AO_GET_KEYS: u32 = 41;
/// Get/Set SNEs and ISNs.
pub const TCP_AO_REPAIR: u32 = 42;
/// Is MPTCP being used?
pub const TCP_IS_MPTCP: u32 = 43;
/// Max rto time in ms.
pub const TCP_RTO_MAX_MS: u32 = 44;
/// Min rto time in us.
pub const TCP_RTO_MIN_US: u32 = 45;
/// Max delayed ack time in us.
pub const TCP_DELACK_MAX_US: u32 = 46;
/// `TCP_AO_MAXKEYLEN` from `<linux/tcp.h>`.
pub const TCP_AO_MAXKEYLEN: u32 = 80;
/// `TCP_MD5SIG_MAXKEYLEN` from `<linux/tcp.h>`.
pub const TCP_MD5SIG_MAXKEYLEN: u32 = 80;
/// IPv4 (RFC1122, RFC2581).
pub const TCP_MSS_DEFAULT: u32 = 0x218;
/// IPv6 (tunneled), EDNS0 (RFC3226).
pub const TCP_MSS_DESIRED: u32 = 0x4c4;
/// Turn off without window probes.
pub const TCP_REPAIR_OFF_NO_WP: u32 = 0xffff_ffff;

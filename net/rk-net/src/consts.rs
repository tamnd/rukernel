//! The constants of the socket calls and of the network devices that rk-abigen does not extract.
//!
//! Linux defines the families, the types, the flags of the messages and the types of the control
//! messages in include/linux/socket.h and include/linux/net.h, which are not uAPI headers. Thus
//! rk-abigen cannot extract them, and this module has the values of Linux 7.3. The C library
//! has the same values in its own headers.

/// The families.
pub const AF_UNSPEC: u32 = 0;
/// Unix sockets.
pub const AF_UNIX: u32 = 1;
/// IPv4.
pub const AF_INET: u32 = 2;
/// IPv6.
pub const AF_INET6: u32 = 10;
/// The first family number that Linux does not have.
pub const AF_MAX: u32 = 46;

/// A stream of bytes with a connection.
pub const SOCK_STREAM: u32 = 1;
/// Datagrams.
pub const SOCK_DGRAM: u32 = 2;
/// Raw packets.
pub const SOCK_RAW: u32 = 3;
/// Datagrams with a connection, in order and with their boundaries.
pub const SOCK_SEQPACKET: u32 = 5;
/// The bits of the type in the argument of `socket`.
pub const SOCK_TYPE_MASK: u32 = 0xf;
/// The flag of `socket` and `accept4` for `O_NONBLOCK`.
pub const SOCK_NONBLOCK: u32 = rk_abi::native::open::O_NONBLOCK;
/// The flag of `socket` and `accept4` for `O_CLOEXEC`.
pub const SOCK_CLOEXEC: u32 = rk_abi::native::open::O_CLOEXEC;

/// The flags of `send` and `recv`.
pub const MSG_OOB: u32 = 0x1;
/// Receive the data without removing it.
pub const MSG_PEEK: u32 = 0x2;
/// Do not use a gateway.
pub const MSG_DONTROUTE: u32 = 0x4;
/// The control data was truncated.
pub const MSG_CTRUNC: u32 = 0x8;
/// The datagram was truncated, or give the full size of the datagram.
pub const MSG_TRUNC: u32 = 0x20;
/// Do not wait.
pub const MSG_DONTWAIT: u32 = 0x40;
/// The end of a record.
pub const MSG_EOR: u32 = 0x80;
/// Wait for all of the data.
pub const MSG_WAITALL: u32 = 0x100;
/// Confirm the path to the neighbour.
pub const MSG_CONFIRM: u32 = 0x800;
/// Receive from the error queue.
pub const MSG_ERRQUEUE: u32 = 0x2000;
/// Do not send `SIGPIPE`.
pub const MSG_NOSIGNAL: u32 = 0x4000;
/// More data comes.
pub const MSG_MORE: u32 = 0x8000;
/// For `recvmmsg`: wait only for the first message.
pub const MSG_WAITFORONE: u32 = 0x1_0000;
/// Set `FD_CLOEXEC` on the files of `SCM_RIGHTS`.
pub const MSG_CMSG_CLOEXEC: u32 = 0x4000_0000;

/// The arguments of `shutdown`.
pub const SHUT_RD: u32 = 0;
/// Stop the sends.
pub const SHUT_WR: u32 = 1;
/// Stop the receives and the sends.
pub const SHUT_RDWR: u32 = 2;

/// The control message with files.
pub const SCM_RIGHTS: u32 = 1;
/// The control message with credentials.
pub const SCM_CREDENTIALS: u32 = 2;
/// The most files in one control message, as `SCM_MAX_FD` of Linux.
pub const SCM_MAX_FD: usize = 253;

/// The largest backlog of `listen`, the default of `net.core.somaxconn`.
pub const SOMAXCONN: u32 = 4096;

// linux/if.h and linux/if_arp.h are uAPI headers, but they include <sys/socket.h> of the C
// library. The probe of rk-abigen compiles without the C library, so it cannot extract them. The
// values below are the values of Linux 7.3.

/// The flags of a network device, from `enum net_device_flags`: the administrator set the device
/// up.
pub const IFF_UP: u32 = 0x1;
/// The device has a broadcast address.
pub const IFF_BROADCAST: u32 = 0x2;
/// The device is a loopback device.
pub const IFF_LOOPBACK: u32 = 0x8;
/// The device is up and has a link.
pub const IFF_RUNNING: u32 = 0x40;
/// The device can send multicast packets.
pub const IFF_MULTICAST: u32 = 0x1000;
/// The link of the device is up.
pub const IFF_LOWER_UP: u32 = 0x1_0000;

/// The hardware types of `struct sockaddr_ll` and of `ARPHRD_*` in linux/if_arp.h: Ethernet.
pub const ARPHRD_ETHER: u16 = 1;
/// The loopback device.
pub const ARPHRD_LOOPBACK: u16 = 772;

/// The ARP operations: a request.
pub const ARPOP_REQUEST: u16 = 1;
/// A reply.
pub const ARPOP_REPLY: u16 = 2;

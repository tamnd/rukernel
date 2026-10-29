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
/// Netlink sockets.
pub const AF_NETLINK: u32 = 16;
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
/// The administrator turned on the debug messages of the driver.
pub const IFF_DEBUG: u32 = 0x4;
/// The device is a loopback device.
pub const IFF_LOOPBACK: u32 = 0x8;
/// The device is a point to point link.
pub const IFF_POINTOPOINT: u32 = 0x10;
/// Not used. The administrator can set it.
pub const IFF_NOTRAILERS: u32 = 0x20;
/// The device is up and has a link.
pub const IFF_RUNNING: u32 = 0x40;
/// The device does not use ARP.
pub const IFF_NOARP: u32 = 0x80;
/// The device receives all packets.
pub const IFF_PROMISC: u32 = 0x100;
/// The device receives all multicast packets.
pub const IFF_ALLMULTI: u32 = 0x200;
/// The master of a load balancing group.
pub const IFF_MASTER: u32 = 0x400;
/// A slave of a load balancing group.
pub const IFF_SLAVE: u32 = 0x800;
/// The device can send multicast packets.
pub const IFF_MULTICAST: u32 = 0x1000;
/// The device can select the type of its media.
pub const IFF_PORTSEL: u32 = 0x2000;
/// The device selects the type of its media itself.
pub const IFF_AUTOMEDIA: u32 = 0x4000;
/// The addresses of the device change when it goes down.
pub const IFF_DYNAMIC: u32 = 0x8000;
/// The link of the device is up.
pub const IFF_LOWER_UP: u32 = 0x1_0000;
/// The device waits for an external event.
pub const IFF_DORMANT: u32 = 0x2_0000;
/// The device echoes the sent packets.
pub const IFF_ECHO: u32 = 0x4_0000;

/// The size of the name of a network device with its NUL byte.
pub const IFNAMSIZ: usize = 16;

/// The operational states of RFC 2863, from linux/if.h: the state is not known.
pub const IF_OPER_UNKNOWN: u8 = 0;
/// The device is not there.
pub const IF_OPER_NOTPRESENT: u8 = 1;
/// The device is down.
pub const IF_OPER_DOWN: u8 = 2;
/// A lower device is down.
pub const IF_OPER_LOWERLAYERDOWN: u8 = 3;
/// The device is in a test mode.
pub const IF_OPER_TESTING: u8 = 4;
/// The device waits for an external event.
pub const IF_OPER_DORMANT: u8 = 5;
/// The device is up.
pub const IF_OPER_UP: u8 = 6;

// linux/route.h includes <sys/socket.h> through linux/if.h, so rk-abigen cannot extract it.

/// The flags of `struct rtentry` for `SIOCADDRT` and of /proc/net/route: the route is usable.
pub const RTF_UP: u32 = 0x1;
/// The route goes through a gateway.
pub const RTF_GATEWAY: u32 = 0x2;
/// The route goes to one host.
pub const RTF_HOST: u32 = 0x4;
/// The route has an MTU.
pub const RTF_MTU: u32 = 0x40;
/// The route has a window size.
pub const RTF_WINDOW: u32 = 0x80;
/// The route has an initial round trip time.
pub const RTF_IRTT: u32 = 0x100;
/// The route rejects the packets.
pub const RTF_REJECT: u32 = 0x200;

/// The level of the options of netlink sockets, from include/linux/socket.h.
pub const SOL_NETLINK: u32 = 270;

/// The hardware types of `struct sockaddr_ll` and of `ARPHRD_*` in linux/if_arp.h: Ethernet.
pub const ARPHRD_ETHER: u16 = 1;
/// The loopback device.
pub const ARPHRD_LOOPBACK: u16 = 772;
/// A device without a link header, as a TUN device.
pub const ARPHRD_NONE: u16 = 0xfffe;
/// A SLIP line.
pub const ARPHRD_SLIP: u16 = 256;
/// A CAN bus, as a SLCAN line.
pub const ARPHRD_CAN: u16 = 280;
/// The flag of an ARP entry with a known hardware address, `ATF_COM` of linux/if_arp.h, for
/// /proc/net/arp. The value is written by hand, as the values of `ARPHRD_*`.
pub const ATF_COM: u32 = 0x02;
/// The flag of a permanent ARP entry, `ATF_PERM` of linux/if_arp.h.
pub const ATF_PERM: u32 = 0x04;
/// The flag of a published ARP entry for proxy ARP, `ATF_PUBL` of linux/if_arp.h.
pub const ATF_PUBL: u32 = 0x08;
/// The flag of an ARP request with a netmask, `ATF_NETMASK` of linux/if_arp.h.
pub const ATF_NETMASK: u32 = 0x20;
/// The flag of an ARP entry that is not published, `ATF_DONTPUB` of linux/if_arp.h.
pub const ATF_DONTPUB: u32 = 0x40;

/// The ARP operations: a request.
pub const ARPOP_REQUEST: u16 = 1;
/// A reply.
pub const ARPOP_REPLY: u16 = 2;

// linux/icmp.h is a uAPI header, but it includes linux/if.h, which includes <sys/socket.h> of
// the C library. Thus rk-abigen cannot extract it, and the values below are the values of Linux
// 7.3.

/// The ICMP types: an echo reply.
pub const ICMP_ECHOREPLY: u8 = 0;
/// The destination cannot be reached.
pub const ICMP_DEST_UNREACH: u8 = 3;
/// A better route is on the link.
pub const ICMP_REDIRECT: u8 = 5;
/// An echo request.
pub const ICMP_ECHO: u8 = 8;
/// The time to live of the packet is over.
pub const ICMP_TIME_EXCEEDED: u8 = 11;
/// A bad parameter in the header.
pub const ICMP_PARAMETERPROB: u8 = 12;

/// The codes of `ICMP_DEST_UNREACH`: the network cannot be reached.
pub const ICMP_NET_UNREACH: u8 = 0;
/// The host cannot be reached.
pub const ICMP_HOST_UNREACH: u8 = 1;
/// The protocol cannot be reached.
pub const ICMP_PROT_UNREACH: u8 = 2;
/// The port cannot be reached.
pub const ICMP_PORT_UNREACH: u8 = 3;
/// The packet must be fragmented, but it has the flag "do not fragment".
pub const ICMP_FRAG_NEEDED: u8 = 4;
/// A filter of the administrator stops the packet.
pub const ICMP_PKT_FILTERED: u8 = 13;
/// The code of `ICMP_REDIRECT` for a redirect of one host.
pub const ICMP_REDIR_HOST: u8 = 1;
/// The code of `ICMP_TIME_EXCEEDED` when the time to live is over in transit.
pub const ICMP_EXC_TTL: u8 = 0;

/// The option of the level `SOL_RAW` for a raw ICMP socket: a mask of the ICMP types to drop.
pub const ICMP_FILTER: u32 = 1;
/// The level of the options of raw sockets, from include/linux/socket.h.
pub const SOL_RAW: u32 = 255;

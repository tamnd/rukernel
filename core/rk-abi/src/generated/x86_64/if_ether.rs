// rk-abigen generated this file from Linux 7.3, from <linux/if_ether.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The sizes of an Ethernet frame and the protocol IDs of the Ethernet header.

/// Dummy type for 802.3 frames.
pub const ETH_P_802_3: u32 = 1;
/// Dummy protocol id for AX.25.
pub const ETH_P_AX25: u32 = 2;
/// Octets in ethernet type field.
pub const ETH_TLEN: u32 = 2;
/// Every packet (be careful!!!).
pub const ETH_P_ALL: u32 = 3;
/// Octets in the FCS.
pub const ETH_FCS_LEN: u32 = 4;
/// 802.2 frames.
pub const ETH_P_802_2: u32 = 4;
/// Internal only.
pub const ETH_P_SNAP: u32 = 5;
/// Octets in one ethernet addr.
pub const ETH_ALEN: u32 = 6;
/// DEC DDCMP: Internal only.
pub const ETH_P_DDCMP: u32 = 6;
/// Dummy type for WAN PPP frames.
pub const ETH_P_WAN_PPP: u32 = 7;
/// Dummy type for PPP MP frames.
pub const ETH_P_PPP_MP: u32 = 8;
/// Localtalk pseudo type.
pub const ETH_P_LOCALTALK: u32 = 9;
/// CAN: Controller Area Network.
pub const ETH_P_CAN: u32 = 12;
/// CANFD: CAN flexible data rate.
pub const ETH_P_CANFD: u32 = 13;
/// Total octets in header.
pub const ETH_HLEN: u32 = 14;
/// CANXL: eXtended frame Length.
pub const ETH_P_CANXL: u32 = 14;
/// Dummy type for Atalk over PPP.
pub const ETH_P_PPPTALK: u32 = 16;
/// 802.2 frames.
pub const ETH_P_TR_802_2: u32 = 17;
/// Mobitex (kaz@cafe.net).
pub const ETH_P_MOBITEX: u32 = 21;
/// Card specific control frames.
pub const ETH_P_CONTROL: u32 = 22;
/// Linux-IrDA.
pub const ETH_P_IRDA: u32 = 23;
/// Acorn Econet.
pub const ETH_P_ECONET: u32 = 24;
/// HDLC frames.
pub const ETH_P_HDLC: u32 = 25;
/// 1A for ArcNet :-).
pub const ETH_P_ARCNET: u32 = 26;
/// Distributed Switch Arch.
pub const ETH_P_DSA: u32 = 27;
/// Trailer switch tagging.
pub const ETH_P_TRAILER: u32 = 28;
/// Min. octets in frame sans FCS.
pub const ETH_ZLEN: u32 = 60;
/// Min IPv4 MTU per RFC791.
pub const ETH_MIN_MTU: u32 = 68;
/// Ethernet Loopback packet.
pub const ETH_P_LOOP: u32 = 96;
/// Nokia Phonet frames.
pub const ETH_P_PHONET: u32 = 245;
/// IEEE802.15.4 frame.
pub const ETH_P_IEEE802154: u32 = 246;
/// ST-Ericsson CAIF protocol.
pub const ETH_P_CAIF: u32 = 247;
/// Multiplexed DSA protocol.
pub const ETH_P_XDSA: u32 = 248;
/// `ETH_P_MAP` from `<linux/if_ether.h>`.
pub const ETH_P_MAP: u32 = 249;
/// `ETH_P_MCTP` from `<linux/if_ether.h>`.
pub const ETH_P_MCTP: u32 = 250;
/// `ETH_P_GRE_OSI` from `<linux/if_ether.h>`.
pub const ETH_P_GRE_OSI: u32 = 254;
/// Xerox PUP packet.
pub const ETH_P_PUP: u32 = 0x200;
/// Xerox PUP Addr Trans packet.
pub const ETH_P_PUPAT: u32 = 0x201;
/// Max. octets in payload.
pub const ETH_DATA_LEN: u32 = 0x5dc;
/// Max. octets in frame sans FCS.
pub const ETH_FRAME_LEN: u32 = 0x5ea;
/// `ETH_P_802_3_MIN` from `<linux/if_ether.h>`.
pub const ETH_P_802_3_MIN: u32 = 0x600;
/// Internet Protocol packet.
pub const ETH_P_IP: u32 = 0x800;
/// CCITT X.25.
pub const ETH_P_X25: u32 = 0x805;
/// Address Resolution packet.
pub const ETH_P_ARP: u32 = 0x806;
/// G8BPQ AX.25 Ethernet Packet \[ NOT AN OFFICIALLY REGISTERED ID \].
pub const ETH_P_BPQ: u32 = 0x8ff;
/// Xerox IEEE802.3 PUP packet.
pub const ETH_P_IEEEPUP: u32 = 0xa00;
/// Xerox IEEE802.3 PUP Addr Trans packet.
pub const ETH_P_IEEEPUPAT: u32 = 0xa01;
/// ERSPAN version 2 (type III).
pub const ETH_P_ERSPAN2: u32 = 0x22eb;
/// TSN (IEEE 1722) packet.
pub const ETH_P_TSN: u32 = 0x22f0;
/// B.A.T.M.A.N.-Advanced packet \[ NOT AN OFFICIALLY REGISTERED ID \].
pub const ETH_P_BATMAN: u32 = 0x4305;
/// DEC Assigned proto.
pub const ETH_P_DEC: u32 = 0x6000;
/// DEC DNA Dump/Load.
pub const ETH_P_DNA_DL: u32 = 0x6001;
/// DEC DNA Remote Console.
pub const ETH_P_DNA_RC: u32 = 0x6002;
/// DEC DNA Routing.
pub const ETH_P_DNA_RT: u32 = 0x6003;
/// DEC LAT.
pub const ETH_P_LAT: u32 = 0x6004;
/// DEC Diagnostics.
pub const ETH_P_DIAG: u32 = 0x6005;
/// DEC Customer use.
pub const ETH_P_CUST: u32 = 0x6006;
/// DEC Systems Comms Arch.
pub const ETH_P_SCA: u32 = 0x6007;
/// Trans Ether Bridging.
pub const ETH_P_TEB: u32 = 0x6558;
/// Reverse Addr Res packet.
pub const ETH_P_RARP: u32 = 0x8035;
/// Appletalk DDP.
pub const ETH_P_ATALK: u32 = 0x809b;
/// Appletalk AARP.
pub const ETH_P_AARP: u32 = 0x80f3;
/// 802.1Q VLAN Extended Header.
pub const ETH_P_8021Q: u32 = 0x8100;
/// IPX over DIX.
pub const ETH_P_IPX: u32 = 0x8137;
/// IPv6 over bluebook.
pub const ETH_P_IPV6: u32 = 0x86dd;
/// IEEE Pause frames. See 802.3 31B.
pub const ETH_P_PAUSE: u32 = 0x8808;
/// Slow Protocol. See 802.3ad 43B.
pub const ETH_P_SLOW: u32 = 0x8809;
/// `ETH_P_WCCP` from `<linux/if_ether.h>`.
pub const ETH_P_WCCP: u32 = 0x883e;
/// MPLS Unicast traffic.
pub const ETH_P_MPLS_UC: u32 = 0x8847;
/// MPLS Multicast traffic.
pub const ETH_P_MPLS_MC: u32 = 0x8848;
/// MultiProtocol Over ATM.
pub const ETH_P_ATMMPOA: u32 = 0x884c;
/// PPPoE discovery messages.
pub const ETH_P_PPP_DISC: u32 = 0x8863;
/// PPPoE session messages.
pub const ETH_P_PPP_SES: u32 = 0x8864;
/// HPNA, wlan link local tunnel.
pub const ETH_P_LINK_CTL: u32 = 0x886c;
/// 802.1AC LLC \> 1500 bytes.
pub const ETH_P_8021AC: u32 = 0x8870;
/// `ETH_P_ATMFATE` from `<linux/if_ether.h>`.
pub const ETH_P_ATMFATE: u32 = 0x8884;
/// Port Access Entity (IEEE 802.1X).
pub const ETH_P_PAE: u32 = 0x888e;
/// PROFINET.
pub const ETH_P_PROFINET: u32 = 0x8892;
/// Multiple proprietary protocols.
pub const ETH_P_REALTEK: u32 = 0x8899;
/// ATA over Ethernet.
pub const ETH_P_AOE: u32 = 0x88a2;
/// EtherCAT.
pub const ETH_P_ETHERCAT: u32 = 0x88a4;
/// 802.1ad Service VLAN.
pub const ETH_P_8021AD: u32 = 0x88a8;
/// 802.1 Local Experimental 1.
pub const ETH_P_802_EX1: u32 = 0x88b5;
/// ERSPAN type II.
pub const ETH_P_ERSPAN: u32 = 0x88be;
/// `ETH_P_MXLGSW` from `<linux/if_ether.h>`.
pub const ETH_P_MXLGSW: u32 = 0x88c3;
/// 802.11 Preauthentication.
pub const ETH_P_PREAUTH: u32 = 0x88c7;
/// TIPC.
pub const ETH_P_TIPC: u32 = 0x88ca;
/// Link Layer Discovery Protocol.
pub const ETH_P_LLDP: u32 = 0x88cc;
/// Media Redundancy Protocol.
pub const ETH_P_MRP: u32 = 0x88e3;
/// 802.1ae MACsec.
pub const ETH_P_MACSEC: u32 = 0x88e5;
/// 802.1ah Backbone Service Tag.
pub const ETH_P_8021AH: u32 = 0x88e7;
/// 802.1Q MVRP.
pub const ETH_P_MVRP: u32 = 0x88f5;
/// IEEE 1588 Timesync.
pub const ETH_P_1588: u32 = 0x88f7;
/// NCSI protocol.
pub const ETH_P_NCSI: u32 = 0x88f8;
/// IEC 62439-3 PRP/HSRv0.
pub const ETH_P_PRP: u32 = 0x88fb;
/// Connectivity Fault Management.
pub const ETH_P_CFM: u32 = 0x8902;
/// Fibre Channel over Ethernet.
pub const ETH_P_FCOE: u32 = 0x8906;
/// TDLS.
pub const ETH_P_TDLS: u32 = 0x890d;
/// FCoE Initialization Protocol.
pub const ETH_P_FIP: u32 = 0x8914;
/// Infiniband over Ethernet.
pub const ETH_P_IBOE: u32 = 0x8915;
/// IEEE 802.21 Media Independent Handover Protocol.
pub const ETH_P_80221: u32 = 0x8917;
/// IEC 62439-3 HSRv1.
pub const ETH_P_HSR: u32 = 0x892f;
/// Network Service Header.
pub const ETH_P_NSH: u32 = 0x894f;
/// Ethernet loopback packet, per IEEE 802.3.
pub const ETH_P_LOOPBACK: u32 = 0x9000;
/// Deprecated QinQ VLAN \[ NOT AN OFFICIALLY REGISTERED ID \].
pub const ETH_P_QINQ1: u32 = 0x9100;
/// Deprecated QinQ VLAN \[ NOT AN OFFICIALLY REGISTERED ID \].
pub const ETH_P_QINQ2: u32 = 0x9200;
/// Deprecated QinQ VLAN \[ NOT AN OFFICIALLY REGISTERED ID \].
pub const ETH_P_QINQ3: u32 = 0x9300;
/// Motorcomm YT921x DSA \[ NOT AN OFFICIALLY REGISTERED ID \].
pub const ETH_P_YT921X: u32 = 0x9988;
/// Ethertype DSA \[ NOT AN OFFICIALLY REGISTERED ID \].
pub const ETH_P_EDSA: u32 = 0xdada;
/// Fake VLAN Header for DSA \[ NOT AN OFFICIALLY REGISTERED ID \].
pub const ETH_P_DSA_8021Q: u32 = 0xdadb;
/// A5PSW Tag Value \[ NOT AN OFFICIALLY REGISTERED ID \].
pub const ETH_P_DSA_A5PSW: u32 = 0xe001;
/// ForCES inter-FE LFB type.
pub const ETH_P_IFE: u32 = 0xed3e;
/// IBM af\_iucv \[ NOT AN OFFICIALLY REGISTERED ID \].
pub const ETH_P_AF_IUCV: u32 = 0xfbfb;
/// NXP NETC DSA \[ NOT AN OFFICIALLY REGISTERED ID \].
pub const ETH_P_NXP_NETC: u32 = 0xfd3a;
/// 65535, same as IP\_MAX\_MTU.
pub const ETH_MAX_MTU: u32 = 0xffff;

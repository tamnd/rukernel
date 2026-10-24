// rk-abigen generated this file from Linux 7.3, from <linux/sockios.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The `ioctl` commands of sockets.

/// `SIOCSPGRP` from `<linux/sockios.h>`.
pub const SIOCSPGRP: u32 = 0x8902;
/// `SIOCGPGRP` from `<linux/sockios.h>`.
pub const SIOCGPGRP: u32 = 0x8904;
/// `SIOCATMARK` from `<linux/sockios.h>`.
pub const SIOCATMARK: u32 = 0x8905;
/// The same value as `SIOCGSTAMP_OLD`.
pub const SIOCGSTAMP: u32 = 0x8906;
/// Get stamp (timeval).
pub const SIOCGSTAMP_OLD: u32 = 0x8906;
/// The same value as `SIOCGSTAMPNS_OLD`.
pub const SIOCGSTAMPNS: u32 = 0x8907;
/// Get stamp (timespec).
pub const SIOCGSTAMPNS_OLD: u32 = 0x8907;
/// Add routing table entry.
pub const SIOCADDRT: u32 = 0x890b;
/// Delete routing table entry.
pub const SIOCDELRT: u32 = 0x890c;
/// Unused.
pub const SIOCRTMSG: u32 = 0x890d;
/// Get iface name.
pub const SIOCGIFNAME: u32 = 0x8910;
/// Set iface channel.
pub const SIOCSIFLINK: u32 = 0x8911;
/// Get iface list.
pub const SIOCGIFCONF: u32 = 0x8912;
/// Get flags.
pub const SIOCGIFFLAGS: u32 = 0x8913;
/// Set flags.
pub const SIOCSIFFLAGS: u32 = 0x8914;
/// Get PA address.
pub const SIOCGIFADDR: u32 = 0x8915;
/// Set PA address.
pub const SIOCSIFADDR: u32 = 0x8916;
/// Get remote PA address.
pub const SIOCGIFDSTADDR: u32 = 0x8917;
/// Set remote PA address.
pub const SIOCSIFDSTADDR: u32 = 0x8918;
/// Get broadcast PA address.
pub const SIOCGIFBRDADDR: u32 = 0x8919;
/// Set broadcast PA address.
pub const SIOCSIFBRDADDR: u32 = 0x891a;
/// Get network PA mask.
pub const SIOCGIFNETMASK: u32 = 0x891b;
/// Set network PA mask.
pub const SIOCSIFNETMASK: u32 = 0x891c;
/// Get metric.
pub const SIOCGIFMETRIC: u32 = 0x891d;
/// Set metric.
pub const SIOCSIFMETRIC: u32 = 0x891e;
/// Get memory address (BSD).
pub const SIOCGIFMEM: u32 = 0x891f;
/// Set memory address (BSD).
pub const SIOCSIFMEM: u32 = 0x8920;
/// Get MTU size.
pub const SIOCGIFMTU: u32 = 0x8921;
/// Set MTU size.
pub const SIOCSIFMTU: u32 = 0x8922;
/// Set interface name.
pub const SIOCSIFNAME: u32 = 0x8923;
/// Set hardware address.
pub const SIOCSIFHWADDR: u32 = 0x8924;
/// Get/set encapsulations.
pub const SIOCGIFENCAP: u32 = 0x8925;
/// `SIOCSIFENCAP` from `<linux/sockios.h>`.
pub const SIOCSIFENCAP: u32 = 0x8926;
/// Get hardware address.
pub const SIOCGIFHWADDR: u32 = 0x8927;
/// Driver slaving support.
pub const SIOCGIFSLAVE: u32 = 0x8929;
/// `SIOCSIFSLAVE` from `<linux/sockios.h>`.
pub const SIOCSIFSLAVE: u32 = 0x8930;
/// Multicast address lists.
pub const SIOCADDMULTI: u32 = 0x8931;
/// `SIOCDELMULTI` from `<linux/sockios.h>`.
pub const SIOCDELMULTI: u32 = 0x8932;
/// Name -\> if\_index mapping.
pub const SIOCGIFINDEX: u32 = 0x8933;
/// Set/get extended flags set.
pub const SIOCSIFPFLAGS: u32 = 0x8934;
/// `SIOCGIFPFLAGS` from `<linux/sockios.h>`.
pub const SIOCGIFPFLAGS: u32 = 0x8935;
/// Delete PA address.
pub const SIOCDIFADDR: u32 = 0x8936;
/// Set hardware broadcast addr.
pub const SIOCSIFHWBROADCAST: u32 = 0x8937;
/// Get number of devices.
pub const SIOCGIFCOUNT: u32 = 0x8938;
/// Bridging support.
pub const SIOCGIFBR: u32 = 0x8940;
/// Set bridging options.
pub const SIOCSIFBR: u32 = 0x8941;
/// Get the tx queue length.
pub const SIOCGIFTXQLEN: u32 = 0x8942;
/// Set the tx queue length.
pub const SIOCSIFTXQLEN: u32 = 0x8943;
/// Ethtool interface.
pub const SIOCETHTOOL: u32 = 0x8946;
/// Get address of MII PHY in use.
pub const SIOCGMIIPHY: u32 = 0x8947;
/// Read MII PHY register.
pub const SIOCGMIIREG: u32 = 0x8948;
/// Write MII PHY register.
pub const SIOCSMIIREG: u32 = 0x8949;
/// Get/set netdev parameters.
pub const SIOCWANDEV: u32 = 0x894a;
/// Output queue size (not sent only).
pub const SIOCOUTQNSD: u32 = 0x894b;
/// Get socket network namespace.
pub const SIOCGSKNS: u32 = 0x894c;
/// Delete ARP table entry.
pub const SIOCDARP: u32 = 0x8953;
/// Get ARP table entry.
pub const SIOCGARP: u32 = 0x8954;
/// Set ARP table entry.
pub const SIOCSARP: u32 = 0x8955;
/// Delete RARP table entry.
pub const SIOCDRARP: u32 = 0x8960;
/// Get RARP table entry.
pub const SIOCGRARP: u32 = 0x8961;
/// Set RARP table entry.
pub const SIOCSRARP: u32 = 0x8962;
/// Get device parameters.
pub const SIOCGIFMAP: u32 = 0x8970;
/// Set device parameters.
pub const SIOCSIFMAP: u32 = 0x8971;
/// Create new DLCI device.
pub const SIOCADDDLCI: u32 = 0x8980;
/// Delete DLCI device.
pub const SIOCDELDLCI: u32 = 0x8981;
/// 802.1Q VLAN support.
pub const SIOCGIFVLAN: u32 = 0x8982;
/// Set 802.1Q VLAN options.
pub const SIOCSIFVLAN: u32 = 0x8983;
/// Enslave a device to the bond.
pub const SIOCBONDENSLAVE: u32 = 0x8990;
/// Release a slave from the bond.
pub const SIOCBONDRELEASE: u32 = 0x8991;
/// Set the hw addr of the bond.
pub const SIOCBONDSETHWADDR: u32 = 0x8992;
/// Rtn info about slave state.
pub const SIOCBONDSLAVEINFOQUERY: u32 = 0x8993;
/// Rtn info about bond state.
pub const SIOCBONDINFOQUERY: u32 = 0x8994;
/// Update to a new active slave.
pub const SIOCBONDCHANGEACTIVE: u32 = 0x8995;
/// Create new bridge device.
pub const SIOCBRADDBR: u32 = 0x89a0;
/// Remove bridge device.
pub const SIOCBRDELBR: u32 = 0x89a1;
/// Add interface to bridge.
pub const SIOCBRADDIF: u32 = 0x89a2;
/// Remove interface from bridge.
pub const SIOCBRDELIF: u32 = 0x89a3;
/// Set and get config.
pub const SIOCSHWTSTAMP: u32 = 0x89b0;
/// Get config.
pub const SIOCGHWTSTAMP: u32 = 0x89b1;
/// To 89EF.
pub const SIOCPROTOPRIVATE: u32 = 0x89e0;
/// To 89FF.
pub const SIOCDEVPRIVATE: u32 = 0x89f0;

//! The offload features of a network device, as `netdev_features_t` of
//! <linux/netdev_features.h>, and their checks, as `netdev_fix_features` of net/core/dev.c.
//!
//! A device has three sets of features. `hw` has the features that the administrator can
//! change, `wanted` has the features that the administrator asked for, and `active` has the
//! features that are on. `ethtool -k` shows them, and `ethtool -K` changes `wanted`.

/// The number of feature bits, `NETDEV_FEATURE_COUNT` of Linux.
pub const COUNT: u32 = 64;

/// Scatter and gather, `NETIF_F_SG`.
pub const SG: u64 = 1 << 0;
/// The checksum of TCP and UDP over IPv4, `NETIF_F_IP_CSUM`.
pub const IP_CSUM: u64 = 1 << 1;
/// The checksum of all packets, `NETIF_F_HW_CSUM`.
pub const HW_CSUM: u64 = 1 << 3;
/// The checksum of TCP and UDP over IPv6, `NETIF_F_IPV6_CSUM`.
pub const IPV6_CSUM: u64 = 1 << 4;
/// DMA to high memory, `NETIF_F_HIGHDMA`.
pub const HIGHDMA: u64 = 1 << 5;
/// Scatter and gather of a fragment list, `NETIF_F_FRAGLIST`.
pub const FRAGLIST: u64 = 1 << 6;
/// The device cannot carry VLAN packets, `NETIF_F_VLAN_CHALLENGED`.
pub const VLAN_CHALLENGED: u64 = 1 << 10;
/// Software GSO, `NETIF_F_GSO`.
pub const GSO: u64 = 1 << 11;
/// Generic receive offload, `NETIF_F_GRO`.
pub const GRO: u64 = 1 << 14;
/// Large receive offload, `NETIF_F_LRO`.
pub const LRO: u64 = 1 << 15;
/// TCP segmentation over IPv4, `NETIF_F_TSO`.
pub const TSO: u64 = 1 << 16;
/// TCP segmentation with ECN, `NETIF_F_TSO_ECN`.
pub const TSO_ECN: u64 = 1 << 18;
/// TCP segmentation that can change the IPv4 ID, `NETIF_F_TSO_MANGLEID`.
pub const TSO_MANGLEID: u64 = 1 << 19;
/// TCP segmentation over IPv6, `NETIF_F_TSO6`.
pub const TSO6: u64 = 1 << 20;
/// SCTP segmentation, `NETIF_F_GSO_SCTP`.
pub const GSO_SCTP: u64 = 1 << 30;
/// UDP segmentation, `NETIF_F_GSO_UDP_L4`.
pub const GSO_UDP_L4: u64 = 1 << 33;
/// Segmentation of a fragment list, `NETIF_F_GSO_FRAGLIST`.
pub const GSO_FRAGLIST: u64 = 1 << 34;
/// TCP segmentation with AccECN, `NETIF_F_GSO_ACCECN`.
pub const GSO_ACCECN: u64 = 1 << 35;
/// The SCTP checksum, `NETIF_F_SCTP_CRC`.
pub const SCTP_CRC: u64 = 1 << 37;
/// The receive checksum, `NETIF_F_RXCSUM`.
pub const RXCSUM: u64 = 1 << 40;
/// Copies from the user without the cache, `NETIF_F_NOCACHE_COPY`.
pub const NOCACHE_COPY: u64 = 1 << 41;
/// The device sends its frames back, `NETIF_F_LOOPBACK`.
pub const LOOPBACK: u64 = 1 << 42;
/// The frames keep their FCS, `NETIF_F_RXFCS`.
pub const RXFCS: u64 = 1 << 43;
/// TLS offload on transmit, `NETIF_F_HW_TLS_TX`.
pub const HW_TLS_TX: u64 = 1 << 53;
/// TLS offload on receive, `NETIF_F_HW_TLS_RX`.
pub const HW_TLS_RX: u64 = 1 << 54;
/// Hardware GRO, `NETIF_F_GRO_HW`.
pub const GRO_HW: u64 = 1 << 55;
/// GRO of a fragment list, `NETIF_F_GRO_FRAGLIST`.
pub const GRO_FRAGLIST: u64 = 1 << 57;
/// UDP GRO for forwarding, `NETIF_F_GRO_UDP_FWD`.
pub const GRO_UDP_FWD: u64 = 1 << 59;

/// All of the TCP segmentation features, `NETIF_F_ALL_TSO`.
pub const ALL_TSO: u64 = TSO | TSO6 | TSO_ECN | TSO_MANGLEID;
/// The segmentation features with a software fallback, `NETIF_F_GSO_SOFTWARE`.
pub const GSO_SOFTWARE: u64 = ALL_TSO | GSO_ACCECN | GSO_SCTP | GSO_UDP_L4 | GSO_FRAGLIST;
/// The features that the administrator can never change, `NETIF_F_NEVER_CHANGE`.
pub const NEVER_CHANGE: u64 = VLAN_CHALLENGED;
/// The features that ethtool can change, `NETIF_F_ETHTOOL_BITS`.
pub const ETHTOOL_BITS: u64 = !NEVER_CHANGE;
/// The software features that are on for each device, `NETIF_F_SOFT_FEATURES`.
const SOFT: u64 = GSO | GRO;
/// The software features that are off at first, `NETIF_F_SOFT_FEATURES_OFF`.
const SOFT_OFF: u64 = GRO_FRAGLIST | GRO_UDP_FWD;

/// The names of the features, `netdev_features_strings` of Linux. A bit without a feature has
/// an empty name.
pub static NAMES: [&str; COUNT as usize] = [
    "tx-scatter-gather",
    "tx-checksum-ipv4",
    "",
    "tx-checksum-ip-generic",
    "tx-checksum-ipv6",
    "highdma",
    "tx-scatter-gather-fraglist",
    "tx-vlan-hw-insert",
    "rx-vlan-hw-parse",
    "rx-vlan-filter",
    "vlan-challenged",
    "tx-generic-segmentation",
    "",
    "",
    "rx-gro",
    "rx-lro",
    "tx-tcp-segmentation",
    "tx-gso-robust",
    "tx-tcp-ecn-segmentation",
    "tx-tcp-mangleid-segmentation",
    "tx-tcp6-segmentation",
    "tx-fcoe-segmentation",
    "tx-gre-segmentation",
    "tx-gre-csum-segmentation",
    "tx-ipxip4-segmentation",
    "tx-ipxip6-segmentation",
    "tx-udp_tnl-segmentation",
    "tx-udp_tnl-csum-segmentation",
    "tx-gso-partial",
    "tx-tunnel-remcsum-segmentation",
    "tx-sctp-segmentation",
    "tx-esp-segmentation",
    "",
    "tx-udp-segmentation",
    "tx-gso-list",
    "tx-tcp-accecn-segmentation",
    "tx-checksum-fcoe-crc",
    "tx-checksum-sctp",
    "rx-ntuple-filter",
    "rx-hashing",
    "rx-checksum",
    "tx-nocache-copy",
    "loopback",
    "rx-fcs",
    "rx-all",
    "tx-vlan-stag-hw-insert",
    "rx-vlan-stag-hw-parse",
    "rx-vlan-stag-filter",
    "l2-fwd-offload",
    "hw-tc-offload",
    "esp-hw-offload",
    "esp-tx-csum-hw-offload",
    "rx-udp_tunnel-port-offload",
    "tls-hw-tx-offload",
    "tls-hw-rx-offload",
    "rx-gro-hw",
    "",
    "rx-gro-list",
    "macsec-hw-offload",
    "rx-udp-gro-forwarding",
    "hsr-tag-ins-offload",
    "hsr-tag-rm-offload",
    "hsr-fwd-offload",
    "hsr-dup-offload",
];

/// Tells if `f` has the checksum of IPv4 and IPv6 or the generic checksum, as
/// `netdev_has_ip_or_hw_csum` of Linux.
fn ip_or_hw_csum(f: u64) -> bool {
    f & (IP_CSUM | IPV6_CSUM) == IP_CSUM | IPV6_CSUM || f & HW_CSUM != 0
}

/// Removes the features of `f` that need a feature that is not in `f`, as `netdev_fix_features`
/// of Linux.
pub fn fix(mut f: u64) -> u64 {
    if f & HW_CSUM != 0 && f & (IP_CSUM | IPV6_CSUM) != 0 {
        f &= !(IP_CSUM | IPV6_CSUM);
    }
    if f & ALL_TSO != 0 && f & SG == 0 {
        f &= !ALL_TSO;
    }
    if f & TSO != 0 && f & (HW_CSUM | IP_CSUM) == 0 {
        f &= !(TSO | TSO_ECN);
    }
    if f & TSO6 != 0 && f & (HW_CSUM | IPV6_CSUM) == 0 {
        f &= !TSO6;
    }
    if f & TSO_MANGLEID != 0 && f & TSO == 0 {
        f &= !TSO_MANGLEID;
    }
    if f & ALL_TSO == TSO_ECN {
        f &= !TSO_ECN;
    }
    if f & GSO != 0 && f & SG == 0 {
        f &= !GSO;
    }
    if f & RXCSUM == 0 {
        f &= !GRO_HW;
    }
    if f & RXFCS != 0 {
        f &= !(LRO | GRO_HW);
    }
    if f & GRO_HW != 0 && f & LRO != 0 {
        f &= !LRO;
    }
    if f & HW_TLS_TX != 0 && !ip_or_hw_csum(f) {
        f &= !HW_TLS_TX;
    }
    if f & HW_TLS_RX != 0 && f & RXCSUM == 0 {
        f &= !HW_TLS_RX;
    }
    if f & GSO_UDP_L4 != 0 && !ip_or_hw_csum(f) {
        f &= !GSO_UDP_L4;
    }
    f
}

/// The features of a new device, as `register_netdevice` of Linux does them. `features` and
/// `hw` come from the driver. Gives the active, the `hw` and the wanted features.
pub fn initial(features: u64, hw: u64, loopback: bool) -> (u64, u64, u64) {
    let mut hw = hw | SOFT | SOFT_OFF;
    let features = features | SOFT;
    let wanted = features & hw;
    if !loopback {
        hw |= NOCACHE_COPY;
    }
    if hw & TSO != 0 {
        hw |= TSO_MANGLEID;
    }
    (update(features, hw, wanted), hw, wanted)
}

/// The active features after a change of the wanted features, as `__netdev_update_features`
/// of Linux.
pub fn update(active: u64, hw: u64, wanted: u64) -> u64 {
    fix((active & !hw) | wanted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtio_net_has_highdma_rxcsum_and_gro() {
        let (active, hw, wanted) = initial(HIGHDMA | RXCSUM, 0, false);
        assert_eq!(active, HIGHDMA | RXCSUM | GRO);
        assert_eq!(hw, GSO | GRO | GRO_FRAGLIST | GRO_UDP_FWD | NOCACHE_COPY);
        assert_eq!(wanted, GSO | GRO);
    }

    #[test]
    fn tso_needs_sg_and_a_checksum() {
        assert_eq!(fix(TSO | SG), SG);
        assert_eq!(fix(TSO | SG | HW_CSUM), TSO | SG | HW_CSUM);
        assert_eq!(fix(TSO_ECN | SG | HW_CSUM), SG | HW_CSUM);
    }
}

//! The VLAN devices of 802.1Q and 802.1ad, as net/8021q of Linux.
//!
//! A VLAN device sits on a lower device and has a VLAN ID and a protocol. A frame that it sends
//! gets a tag with the protocol and the ID after the link addresses, and goes out of the lower
//! device. A tagged frame that the lower device receives loses its tag before the hooks of the
//! ingress of the lower device, as `skb_vlan_untag` of Linux, and the tag stays with the frame
//! (`NetBuf::vlan`). After the hooks, the frame goes to the VLAN device with the same protocol
//! and ID, as `vlan_do_receive` of Linux. When the lower device goes away, its VLAN devices go
//! too.

use crate::buf::NetBuf;
use crate::dev::{self, LinkKind, NetDevice, NetDriver};
use crate::ether::{HLEN, MacAddr};
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::inode::Result;

/// The kind of the device, for `IFLA_INFO_KIND`.
pub const KIND: &str = "vlan";

/// The protocol of a tag of 802.1Q, `ETH_P_8021Q` of Linux.
pub const ETH_P_8021Q: u16 = 0x8100;
/// The protocol of a tag of 802.1ad, `ETH_P_8021AD` of Linux.
pub const ETH_P_8021AD: u16 = 0x88a8;
/// The length of a tag, `VLAN_HLEN` of Linux.
pub const VLAN_HLEN: usize = 4;
/// The bits of the VLAN ID in the tag, `VLAN_VID_MASK` of Linux.
pub const VLAN_VID_MASK: u16 = 0x0fff;

// The attributes of the `IFLA_INFO_DATA` of a VLAN device, `IFLA_VLAN_*` of Linux.

/// The VLAN ID, a `u16`.
pub const IFLA_VLAN_ID: u16 = 1;
/// The flags and the mask of the flags to change, `struct ifla_vlan_flags`.
pub const IFLA_VLAN_FLAGS: u16 = 2;
/// The map of the priority of a frame to the priority of its tag, on send.
pub const IFLA_VLAN_EGRESS_QOS: u16 = 3;
/// The map of the priority of a tag to the priority of the frame, on receive.
pub const IFLA_VLAN_INGRESS_QOS: u16 = 4;
/// The protocol of the tag, a `u16` in network order.
pub const IFLA_VLAN_PROTOCOL: u16 = 5;
/// The last attribute.
pub const IFLA_VLAN_MAX: u16 = 5;

/// The flag of a VLAN device that puts the tag in the frame only on the lower device,
/// `VLAN_FLAG_REORDER_HDR` of Linux. A new device has it, and rukernel has no other way.
const VLAN_FLAG_REORDER_HDR: u32 = 0x1;

/// Tells if `proto` is the protocol of a tag, as `eth_type_vlan` of Linux.
pub fn is_vlan_proto(proto: u16) -> bool {
    proto == ETH_P_8021Q || proto == ETH_P_8021AD
}

/// A VLAN device.
pub struct Vlan {
    mac: MacAddr,
    /// How the device got `mac`, one of the `NET_ADDR_*` values.
    assign: u8,
    lower: Weak<NetDevice>,
    proto: u16,
    id: u16,
    mtu: u32,
}

/// The VLAN devices: the lower device, the protocol, the ID and the VLAN device, as the
/// `vlan_group` of each lower device of Linux.
struct Entry {
    lower: Weak<NetDevice>,
    proto: u16,
    id: u16,
    dev: Weak<NetDevice>,
}

static VLANS: SpinLock<Vec<Entry>> = SpinLock::new(Vec::new());

impl NetDriver for Vlan {
    fn kind(&self) -> LinkKind {
        LinkKind::Ether
    }

    fn mac(&self) -> MacAddr {
        self.mac
    }

    fn addr_assign_type(&self) -> u8 {
        self.assign
    }

    fn can_set_mac(&self) -> bool {
        true
    }

    /// The MTU of the lower device, as `vlan_dev_init` of Linux.
    fn mtu(&self) -> u32 {
        self.mtu
    }

    /// The MTU of the lower device, as `vlan_dev_change_mtu` of Linux.
    fn max_mtu(&self) -> u32 {
        self.lower.upgrade().map_or(self.mtu, |l| l.mtu())
    }

    fn link_kind(&self) -> Option<&'static str> {
        Some(KIND)
    }

    fn lower(&self) -> Option<Arc<NetDevice>> {
        self.lower.upgrade()
    }

    /// The protocol, the ID and the flags, as `vlan_fill_info` of Linux.
    fn link_info_data(&self) -> Vec<(u16, Vec<u8>)> {
        let mut flags = VLAN_FLAG_REORDER_HDR.to_ne_bytes().to_vec();
        flags.extend_from_slice(&u32::MAX.to_ne_bytes());
        vec![
            (IFLA_VLAN_PROTOCOL, self.proto.to_be_bytes().to_vec()),
            (IFLA_VLAN_ID, self.id.to_ne_bytes().to_vec()),
            (IFLA_VLAN_FLAGS, flags),
        ]
    }

    /// The link is up when the lower device is up and has its link, as
    /// `netif_stacked_transfer_operstate` of Linux.
    fn link_up(&self) -> bool {
        self.lower.upgrade().is_some_and(|l| l.is_up() && l.carrier())
    }

    /// Puts the tag after the link addresses and sends the frame on the lower device, as
    /// `vlan_dev_hard_start_xmit` and `vlan_insert_tag` of Linux. The priority of the tag is
    /// 0, as with no egress map.
    fn transmit(&self, mut frame: NetBuf) -> Result<()> {
        let Some(lower) = self.lower.upgrade() else { return Err(Errno::ENODEV) };
        if frame.len() < HLEN {
            return Err(Errno::EINVAL);
        }
        let mut addrs = [0u8; 12];
        addrs.copy_from_slice(&frame.data()[..12]);
        frame.push(VLAN_HLEN);
        let d = frame.data_mut();
        d[..12].copy_from_slice(&addrs);
        d[12..14].copy_from_slice(&self.proto.to_be_bytes());
        d[14..16].copy_from_slice(&(self.id & VLAN_VID_MASK).to_be_bytes());
        lower.transmit(frame)
    }

    /// The frames come from the lower device, in `receive` of the stack.
    fn poll(&self, _budget: usize, _deliver: &mut dyn FnMut(NetBuf)) -> usize {
        0
    }
}

/// Makes a VLAN device on `lower` in the current namespace, as `vlan_newlink` and
/// `register_vlan_dev` of Linux. A missing name gives `vlanN`, and a missing address gives the
/// address of `lower`. Gives `ERANGE` for an ID above 4094, `EPROTONOSUPPORT` for a protocol that
/// is not 802.1Q or 802.1ad, `EEXIST` if `lower` has a VLAN device with the protocol and the ID
/// already, and `EINVAL` for an MTU above the MTU of `lower`.
pub fn create(
    name: Option<&[u8]>,
    lower: &Arc<NetDevice>,
    proto: u16,
    id: u16,
    mac: Option<MacAddr>,
    mtu: Option<u32>,
) -> Result<Arc<NetDevice>> {
    if id >= VLAN_VID_MASK {
        return Err(Errno::ERANGE);
    }
    if !is_vlan_proto(proto) {
        return Err(Errno::EPROTONOSUPPORT);
    }
    if lower.kind() != LinkKind::Ether {
        return Err(Errno::EOPNOTSUPP);
    }
    let max = lower.mtu();
    let mtu = mtu.unwrap_or(max);
    if mtu > max {
        return Err(Errno::EINVAL);
    }
    if find(lower, proto, id).is_some() {
        return Err(Errno::EEXIST);
    }
    let v = Vlan {
        mac: mac.unwrap_or_else(|| lower.mac()),
        assign: if mac.is_some() { dev::NET_ADDR_SET } else { dev::NET_ADDR_STOLEN },
        lower: Arc::downgrade(lower),
        proto,
        id,
        mtu,
    };
    // The device is there before its entry, and a frame of its tag goes to the stack of the
    // lower device until then. The lock is not held while the device registers.
    let dev = dev::register_named(Arc::new(v), name)?;
    let mut vlans = VLANS.lock();
    vlans.retain(|e| e.dev.strong_count() > 0);
    if find_in(&vlans, lower, proto, id).is_some() {
        drop(vlans);
        dev::unregister(&dev);
        return Err(Errno::EEXIST);
    }
    vlans.push(Entry { lower: Arc::downgrade(lower), proto, id, dev: Arc::downgrade(&dev) });
    Ok(dev)
}

fn find_in(vlans: &[Entry], lower: &NetDevice, proto: u16, id: u16) -> Option<Arc<NetDevice>> {
    vlans
        .iter()
        .filter(|e| e.proto == proto && e.id == id)
        .filter(|e| e.lower.upgrade().is_some_and(|l| core::ptr::eq(&*l, lower)))
        .find_map(|e| e.dev.upgrade())
}

/// The VLAN device of `lower` with the protocol `proto` and the ID `id`, as
/// `vlan_find_dev` of Linux.
pub fn find(lower: &NetDevice, proto: u16, id: u16) -> Option<Arc<NetDevice>> {
    find_in(&VLANS.lock(), lower, proto, id & VLAN_VID_MASK)
}

/// Takes the tag out of a frame that `receive` gave, after its link header, as
/// `skb_vlan_untag` of Linux: the tag goes to `frame.vlan`, the link header moves up by the
/// length of the tag, and `frame.protocol` is the protocol after the tag. The data of the frame
/// starts after the link header. Does nothing if the frame has a tag already or is too short.
pub fn untag(frame: &mut NetBuf) {
    if frame.vlan.is_some() || !is_vlan_proto(frame.protocol) {
        return;
    }
    let Some(eth) = frame.mac_data().filter(|m| m.len() >= HLEN + VLAN_HLEN) else { return };
    let mut addrs = [0u8; 12];
    addrs.copy_from_slice(&eth[..12]);
    let tci = u16::from_be_bytes([eth[14], eth[15]]);
    let inner = u16::from_be_bytes([eth[16], eth[17]]);
    let proto = frame.protocol;
    let _ = frame.pull(VLAN_HLEN);
    let h = frame.push(HLEN);
    h[..12].copy_from_slice(&addrs);
    h[12..].copy_from_slice(&inner.to_be_bytes());
    let _ = frame.pull(HLEN);
    frame.set_mac_header(HLEN);
    frame.vlan = Some((proto, tci));
    frame.protocol = inner;
}

/// Removes the VLAN devices of `dev` and the entry of `dev` itself when `dev` goes away, as
/// `vlan_device_event` of Linux with `NETDEV_UNREGISTER`.
pub(crate) fn unregistered(dev: &NetDevice) {
    let gone: Vec<Arc<NetDevice>> = {
        let mut vlans = VLANS.lock();
        let gone = vlans
            .iter()
            .filter(|e| e.lower.upgrade().is_some_and(|l| core::ptr::eq(&*l, dev)))
            .filter_map(|e| e.dev.upgrade())
            .collect();
        vlans.retain(|e| {
            e.dev.upgrade().is_some_and(|d| !core::ptr::eq(&*d, dev))
                && e.lower.upgrade().is_some_and(|l| !core::ptr::eq(&*l, dev))
        });
        gone
    };
    for d in gone {
        dev::unregister(&d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untag_moves_the_tag_out_of_the_frame() {
        let mut f = NetBuf::from_slice(&[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x88, 0xa8, 0x20, 0x7b, 0x08, 0x00, 0x45, 0,
        ]);
        let _ = f.pull(HLEN);
        f.set_mac_header(HLEN);
        f.protocol = ETH_P_8021AD;
        untag(&mut f);
        assert_eq!(f.vlan, Some((ETH_P_8021AD, 0x207b)));
        assert_eq!(f.protocol, 0x0800);
        assert_eq!(f.data(), &[0x45, 0]);
        assert_eq!(f.mac_data().unwrap()[..14], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 8, 0]);
    }

    #[test]
    fn a_frame_with_no_tag_stays_the_same() {
        let mut f = NetBuf::from_slice(&[0; 20]);
        let _ = f.pull(HLEN);
        f.set_mac_header(HLEN);
        f.protocol = 0x0800;
        let before = f.clone();
        untag(&mut f);
        assert_eq!(f, before);
    }
}

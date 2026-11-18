//! The bridge devices, as net/bridge of Linux, with no ports.
//!
//! `ip link add br0 type bridge` makes a bridge as `br_dev_setup` of Linux: a random address,
//! the MTU of Ethernet, and no ports. rukernel cannot add a port to a bridge yet (`ip link set
//! DEV master br0` gives `EOPNOTSUPP`), so a bridge forwards no frame. With no port, a bridge
//! has no carrier, as in Linux, and a frame that it sends goes to no port. Programs and tests
//! use a bridge as a device to hook on, and as a place for addresses.

use crate::buf::NetBuf;
use crate::dev::{self, LinkKind, NetDevice, NetDriver};
use crate::ether::MacAddr;
use alloc::sync::Arc;
use rk_vfs::inode::Result;

/// The kind of the device, for `IFLA_INFO_KIND`.
pub const KIND: &str = "bridge";

/// The largest MTU of a bridge with no ports, `ETH_MAX_MTU` of Linux.
const MAX_MTU: u32 = 65535;

/// A bridge with no ports.
pub struct Bridge {
    mac: MacAddr,
    /// How the device got `mac`, one of the `NET_ADDR_*` values.
    assign: u8,
}

impl NetDriver for Bridge {
    fn kind(&self) -> LinkKind {
        LinkKind::Ether
    }

    fn mac(&self) -> MacAddr {
        self.mac
    }

    fn addr_assign_type(&self) -> u8 {
        self.assign
    }

    /// A bridge has `IFF_LIVE_ADDR_CHANGE`, as `br_dev_setup` of Linux.
    fn can_set_mac(&self) -> bool {
        true
    }

    fn max_mtu(&self) -> u32 {
        MAX_MTU
    }

    /// A bridge has its carrier when a port forwards, as `br_port_carrier_check` of Linux, so
    /// a bridge with no ports has none.
    fn link_up(&self) -> bool {
        false
    }

    fn link_kind(&self) -> Option<&'static str> {
        Some(KIND)
    }

    /// The frame goes to the ports, as `br_dev_xmit` of Linux, and with no ports it goes
    /// away. The device counts it.
    fn transmit(&self, _frame: NetBuf) -> Result<()> {
        Ok(())
    }

    fn poll(&self, _budget: usize, _deliver: &mut dyn FnMut(NetBuf)) -> usize {
        0
    }
}

/// Makes a bridge in the current namespace, as `br_dev_setup` and `rtnl_newlink` of Linux. A
/// missing name gives `bridgeN`, and a missing address gives a random address.
pub fn create(name: Option<&[u8]>, mac: Option<MacAddr>) -> Result<Arc<NetDevice>> {
    let b = Bridge {
        mac: mac.unwrap_or_else(crate::veth::random_mac),
        assign: if mac.is_some() { dev::NET_ADDR_SET } else { dev::NET_ADDR_RANDOM },
    };
    dev::register_named(Arc::new(b), name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bridge_with_no_ports_has_no_carrier() {
        let b = create(Some(b"br-test0"), None).unwrap();
        assert_eq!(b.link_kind(), Some(KIND));
        assert!(!b.carrier());
        assert_eq!(b.mtu(), 1500);
        dev::unregister(&b);
    }
}

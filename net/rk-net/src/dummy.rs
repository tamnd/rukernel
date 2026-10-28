//! The dummy devices, as drivers/net/dummy.c of Linux.
//!
//! A dummy device takes each frame and drops it. Its link is always up. Programs use it as a
//! place for addresses and routes, and LTP uses it to test the namespaces.

use crate::buf::NetBuf;
use crate::dev::{self, LinkKind, NetDevice, NetDriver};
use crate::ether::MacAddr;
use alloc::sync::Arc;
use rk_vfs::inode::Result;

/// The kind of the device, for `IFLA_INFO_KIND`.
pub const KIND: &str = "dummy";

/// The largest MTU of a dummy device: Linux sets no limit, so this is `ETH_MAX_MTU`.
const MAX_MTU: u32 = 65535;

/// A dummy device.
pub struct Dummy {
    mac: MacAddr,
}

impl NetDriver for Dummy {
    fn kind(&self) -> LinkKind {
        LinkKind::Ether
    }

    fn mac(&self) -> MacAddr {
        self.mac
    }

    fn max_mtu(&self) -> u32 {
        MAX_MTU
    }

    fn link_kind(&self) -> Option<&'static str> {
        Some(KIND)
    }

    /// The frame goes away, as `dummy_xmit` of Linux. The device counts it.
    fn transmit(&self, _frame: NetBuf) -> Result<()> {
        Ok(())
    }

    fn poll(&self, _budget: usize, _deliver: &mut dyn FnMut(NetBuf)) -> usize {
        0
    }
}

/// Makes a dummy device in the current namespace, as `dummy_setup` and `rtnl_newlink` of Linux.
/// A missing name gives `dummyN`.
pub fn create(name: Option<&[u8]>) -> Result<Arc<NetDevice>> {
    dev::register_named(Arc::new(Dummy { mac: crate::veth::random_mac() }), name)
}

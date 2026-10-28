//! The virtual Ethernet pairs, as drivers/net/veth.c of Linux.
//!
//! A pair has two devices. A frame that one end sends waits in the queue of the other end until
//! the next poll of the devices. The two ends can be in different namespaces, so a pair joins
//! two namespaces. When one end goes away, the other end goes too.

use crate::buf::NetBuf;
use crate::dev::{self, LinkKind, NetDevice, NetDriver};
use crate::ether::MacAddr;
use crate::ns::{self, NetNs};
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU64, Ordering};
use rk_frame::sync::SpinLock;
use rk_vfs::inode::Result;

/// The kind of the device, for `IFLA_INFO_KIND`.
pub const KIND: &str = "veth";

/// The largest MTU of a veth device, as `ETH_MAX_MTU` of Linux.
const MAX_MTU: u32 = 65535;

/// The most frames that wait in one end.
const BACKLOG: usize = 1000;

/// One end of a pair.
pub struct Veth {
    mac: MacAddr,
    queue: SpinLock<VecDeque<NetBuf>>,
    /// The driver of the other end.
    peer: SpinLock<Weak<Veth>>,
    /// The device of the other end.
    peer_dev: SpinLock<Weak<NetDevice>>,
}

/// A random hardware address with the local bit set, as `eth_hw_addr_random` of Linux.
fn random_mac() -> MacAddr {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let mut x = rk_frame::arch::random_seed() ^ n.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    // A mix of the bits, as splitmix64.
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^= x >> 31;
    let b = x.to_le_bytes();
    MacAddr([(b[0] & 0xfe) | 0x02, b[1], b[2], b[3], b[4], b[5]])
}

impl Veth {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            mac: random_mac(),
            queue: SpinLock::new(VecDeque::new()),
            peer: SpinLock::new(Weak::new()),
            peer_dev: SpinLock::new(Weak::new()),
        })
    }
}

impl NetDriver for Veth {
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

    fn peer(&self) -> Option<Arc<NetDevice>> {
        self.peer_dev.lock().upgrade()
    }

    /// The link is up when the other end is up, as `veth_open` of Linux sets the carrier.
    fn link_up(&self) -> bool {
        self.peer().is_some_and(|p| p.is_up())
    }

    /// Puts the frame in the queue of the other end, as `veth_xmit` of Linux. A frame to an end
    /// that is down goes away.
    fn transmit(&self, frame: NetBuf) -> Result<()> {
        let Some(peer) = self.peer.lock().upgrade() else { return Ok(()) };
        if !self.link_up() {
            return Ok(());
        }
        let mut q = peer.queue.lock();
        if q.len() >= BACKLOG {
            return Err(rk_abi::Errno::ENOBUFS);
        }
        q.push_back(frame);
        Ok(())
    }

    fn poll(&self, budget: usize, deliver: &mut dyn FnMut(NetBuf)) -> usize {
        let mut n = 0;
        while n < budget {
            // The lock is not held while `deliver` runs, so `deliver` can send on the pair.
            let Some(frame) = self.queue.lock().pop_front() else { break };
            deliver(frame);
            n += 1;
        }
        n
    }
}

/// Makes a pair, as `veth_newlink` of Linux. The end `peer_name` is made first in the namespace
/// `peer_ns`, and then the end `name` in the current namespace. A missing name gives `vethN`.
/// Gives the two devices, the end `name` first.
pub fn create(
    name: Option<&[u8]>,
    peer_name: Option<&[u8]>,
    peer_ns: Option<&NetNs>,
) -> Result<(Arc<NetDevice>, Arc<NetDevice>)> {
    let (a, b) = (Veth::new(), Veth::new());
    *a.peer.lock() = Arc::downgrade(&b);
    *b.peer.lock() = Arc::downgrade(&a);
    let peer = {
        let _in = peer_ns.map(ns::enter);
        dev::register_named(b.clone(), peer_name)?
    };
    let dev = match dev::register_named(a.clone(), name) {
        Ok(d) => d,
        Err(e) => {
            dev::unregister(&peer);
            return Err(e);
        }
    };
    *a.peer_dev.lock() = Arc::downgrade(&peer);
    *b.peer_dev.lock() = Arc::downgrade(&dev);
    Ok((dev, peer))
}

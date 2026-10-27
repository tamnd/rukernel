//! The network devices, as `struct net_device` of Linux in net/core/dev.c.
//!
//! A driver implements `NetDriver` and gives it to `register`, which gives the device a name and
//! an interface index. The device counts the packets and the bytes, and it checks the flags and
//! the MTU, so a driver only moves frames. A frame on the receive path goes from `NetDevice::poll`
//! to a function of the caller. This is the place of the NAPI poll of Linux, and the IPv4 stack
//! puts its receive function here. The drivers do not use interrupts yet, so the caller polls.

use crate::buf::NetBuf;
use crate::consts::{
    ARPHRD_ETHER, ARPHRD_LOOPBACK, IFF_BROADCAST, IFF_LOOPBACK, IFF_LOWER_UP, IFF_MULTICAST,
    IFF_RUNNING, IFF_UP,
};
use crate::ether::{HLEN, MacAddr};
use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::if_ether::ETH_DATA_LEN;
use rk_frame::sync::SpinLock;
use rk_vfs::inode::Result;

/// The kind of the link of a device. It gives the name, the hardware type and the flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkKind {
    /// An Ethernet device, with the name `ethN`.
    Ether,
    /// The loopback device `lo`.
    Loopback,
}

impl LinkKind {
    /// The hardware type, as `dev->type` of Linux.
    pub fn arphrd(self) -> u16 {
        match self {
            Self::Ether => ARPHRD_ETHER,
            Self::Loopback => ARPHRD_LOOPBACK,
        }
    }

    /// The flags that do not change: what the device can do.
    fn base_flags(self) -> u32 {
        match self {
            Self::Ether => IFF_BROADCAST | IFF_MULTICAST,
            Self::Loopback => IFF_LOOPBACK,
        }
    }
}

/// The driver of a network device. Each frame starts with the link header, which is an Ethernet
/// header for both kinds, as Linux has for the loopback device.
pub trait NetDriver: Send + Sync {
    /// The kind of the link.
    fn kind(&self) -> LinkKind;

    /// The hardware address.
    fn mac(&self) -> MacAddr;

    /// The largest payload of a frame after the link header.
    fn mtu(&self) -> u32 {
        ETH_DATA_LEN
    }

    /// Tells if the link is up, as `netif_carrier_ok` of Linux.
    fn link_up(&self) -> bool {
        true
    }

    /// Sends one frame. Gives `ENOBUFS` if the queue of the device is full.
    fn transmit(&self, frame: NetBuf) -> Result<()>;

    /// Gives at most `budget` received frames to `deliver`, and gives the number of frames.
    fn poll(&self, budget: usize, deliver: &mut dyn FnMut(NetBuf)) -> usize;
}

/// The statistics of a device, in the order of `struct rtnl_link_stats64` of Linux.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// The frames that the device received.
    pub rx_packets: u64,
    /// The frames that the device sent.
    pub tx_packets: u64,
    /// The bytes of the received frames.
    pub rx_bytes: u64,
    /// The bytes of the sent frames.
    pub tx_bytes: u64,
    /// The received frames with an error.
    pub rx_errors: u64,
    /// The frames that the device could not send.
    pub tx_errors: u64,
    /// The received frames that the kernel dropped.
    pub rx_dropped: u64,
    /// The frames to send that the kernel dropped.
    pub tx_dropped: u64,
}

#[derive(Default)]
struct Counters {
    rx_packets: AtomicU64,
    tx_packets: AtomicU64,
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    rx_errors: AtomicU64,
    tx_errors: AtomicU64,
    rx_dropped: AtomicU64,
    tx_dropped: AtomicU64,
}

fn add(c: &AtomicU64, n: usize) {
    c.fetch_add(n as u64, Ordering::Relaxed);
}

/// A registered network device.
pub struct NetDevice {
    name: String,
    ifindex: u32,
    kind: LinkKind,
    /// The flags that the administrator sets. Only `IFF_UP` is used now.
    admin: AtomicU32,
    mtu: AtomicU32,
    counters: Counters,
    driver: Arc<dyn NetDriver>,
}

impl NetDevice {
    /// The name, for example `eth0`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The interface index. The loopback device has the index 1.
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// The kind of the link.
    pub fn kind(&self) -> LinkKind {
        self.kind
    }

    /// The hardware address.
    pub fn mac(&self) -> MacAddr {
        self.driver.mac()
    }

    /// The MTU.
    pub fn mtu(&self) -> u32 {
        self.mtu.load(Ordering::Relaxed)
    }

    /// Sets the MTU. Gives `EINVAL` if the driver cannot send frames of this size.
    pub fn set_mtu(&self, mtu: u32) -> Result<()> {
        if mtu == 0 || mtu > self.driver.mtu() {
            return Err(Errno::EINVAL);
        }
        self.mtu.store(mtu, Ordering::Relaxed);
        Ok(())
    }

    /// Tells if the administrator set the device up.
    pub fn is_up(&self) -> bool {
        self.admin.load(Ordering::Relaxed) & IFF_UP != 0
    }

    /// Sets the device up or down, as `dev_open` and `dev_close` of Linux. A new device is down.
    pub fn set_up(&self, up: bool) {
        if up {
            self.admin.fetch_or(IFF_UP, Ordering::Relaxed);
        } else {
            self.admin.fetch_and(!IFF_UP, Ordering::Relaxed);
        }
    }

    /// The flags, as `dev_get_flags` of Linux: the flags of the administrator, the flags of the
    /// kind, and `IFF_RUNNING` and `IFF_LOWER_UP` when the link is up.
    pub fn flags(&self) -> u32 {
        let mut flags = self.admin.load(Ordering::Relaxed) | self.kind.base_flags();
        if self.driver.link_up() {
            flags |= IFF_LOWER_UP;
            if flags & IFF_UP != 0 {
                flags |= IFF_RUNNING;
            }
        }
        flags
    }

    /// The statistics.
    pub fn stats(&self) -> Stats {
        let c = &self.counters;
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        Stats {
            rx_packets: get(&c.rx_packets),
            tx_packets: get(&c.tx_packets),
            rx_bytes: get(&c.rx_bytes),
            tx_bytes: get(&c.tx_bytes),
            rx_errors: get(&c.rx_errors),
            tx_errors: get(&c.tx_errors),
            rx_dropped: get(&c.rx_dropped),
            tx_dropped: get(&c.tx_dropped),
        }
    }

    /// Sends a frame that starts with the link header. Gives `ENETDOWN` if the device is down,
    /// and `EMSGSIZE` if the payload is larger than the MTU.
    pub fn transmit(&self, frame: NetBuf) -> Result<()> {
        if !self.is_up() {
            add(&self.counters.tx_dropped, 1);
            return Err(Errno::ENETDOWN);
        }
        if frame.len() < HLEN || frame.len() - HLEN > self.mtu() as usize {
            add(&self.counters.tx_dropped, 1);
            return Err(Errno::EMSGSIZE);
        }
        let len = frame.len();
        match self.driver.transmit(frame) {
            Ok(()) => {
                add(&self.counters.tx_packets, 1);
                add(&self.counters.tx_bytes, len);
                Ok(())
            }
            Err(e) => {
                add(
                    if e == Errno::ENOBUFS {
                        &self.counters.tx_dropped
                    } else {
                        &self.counters.tx_errors
                    },
                    1,
                );
                Err(e)
            }
        }
    }

    /// Takes at most `budget` received frames from the driver and gives each to `deliver`, with
    /// the interface index set. Gives the number of frames. A device that is down drops the
    /// frames.
    pub fn poll(&self, budget: usize, deliver: &mut dyn FnMut(&NetDevice, NetBuf)) -> usize {
        let up = self.is_up();
        self.driver.poll(budget, &mut |mut frame| {
            if !up {
                add(&self.counters.rx_dropped, 1);
                return;
            }
            add(&self.counters.rx_packets, 1);
            add(&self.counters.rx_bytes, frame.len());
            frame.ifindex = self.ifindex;
            deliver(self, frame);
        })
    }
}

/// The registered devices, in the order of their interface index.
static DEVICES: SpinLock<Vec<Arc<NetDevice>>> = SpinLock::new(Vec::new());

/// Registers a device and gives it. The loopback device gets the name `lo`, and an Ethernet
/// device gets `ethN` with the lowest free `N`, as `dev_alloc_name` of Linux. The interface index
/// is one more than the largest index in use. Gives `EEXIST` for a second loopback device.
pub fn register(driver: Arc<dyn NetDriver>) -> Result<Arc<NetDevice>> {
    let mut devices = DEVICES.lock();
    let kind = driver.kind();
    let taken = |name: &str| devices.iter().any(|d| d.name == name);
    let name = match kind {
        LinkKind::Loopback if taken("lo") => return Err(Errno::EEXIST),
        LinkKind::Loopback => String::from("lo"),
        LinkKind::Ether => match (0..).map(|n| format!("eth{n}")).find(|n| !taken(n)) {
            Some(name) => name,
            None => return Err(Errno::ENFILE),
        },
    };
    let ifindex = devices.iter().map(|d| d.ifindex).max().unwrap_or(0) + 1;
    let dev = Arc::new(NetDevice {
        name,
        ifindex,
        kind,
        admin: AtomicU32::new(0),
        mtu: AtomicU32::new(driver.mtu()),
        counters: Counters::default(),
        driver,
    });
    devices.push(dev.clone());
    Ok(dev)
}

/// Finds a device by its name.
pub fn by_name(name: &str) -> Option<Arc<NetDevice>> {
    DEVICES.lock().iter().find(|d| d.name == name).cloned()
}

/// Finds a device by its interface index.
pub fn by_index(ifindex: u32) -> Option<Arc<NetDevice>> {
    DEVICES.lock().iter().find(|d| d.ifindex == ifindex).cloned()
}

/// All registered devices.
pub fn devices() -> Vec<Arc<NetDevice>> {
    DEVICES.lock().clone()
}

/// Registers the loopback device, so that it gets the interface index 1 as on Linux. The kernel
/// calls this before it starts the drivers. A second call does nothing.
pub fn init() {
    if by_name("lo").is_none() {
        // Only a second loopback device gives an error, and a race of two calls at boot is not
        // possible, so the result is not needed.
        let _ = register(Arc::new(Loopback::default()));
    }
}

/// The most frames that wait in the loopback device, as the default `netdev_max_backlog` of
/// Linux.
const LOOPBACK_BACKLOG: usize = 1000;

/// The loopback device, as drivers/net/loopback.c of Linux. A sent frame waits in a queue until
/// the next poll of the device.
pub struct Loopback {
    queue: SpinLock<VecDeque<NetBuf>>,
}

impl Default for Loopback {
    fn default() -> Self {
        Self { queue: SpinLock::new(VecDeque::new()) }
    }
}

/// The MTU of the loopback device, as `LOOPBACK_MTU` of Linux.
const LOOPBACK_MTU: u32 = 65536;

impl NetDriver for Loopback {
    fn kind(&self) -> LinkKind {
        LinkKind::Loopback
    }

    fn mac(&self) -> MacAddr {
        MacAddr::ZERO
    }

    fn mtu(&self) -> u32 {
        LOOPBACK_MTU
    }

    fn transmit(&self, frame: NetBuf) -> Result<()> {
        let mut q = self.queue.lock();
        if q.len() >= LOOPBACK_BACKLOG {
            return Err(Errno::ENOBUFS);
        }
        q.push_back(frame);
        Ok(())
    }

    fn poll(&self, budget: usize, deliver: &mut dyn FnMut(NetBuf)) -> usize {
        let mut n = 0;
        while n < budget {
            // The lock is not held while `deliver` runs, so `deliver` can send again on the device.
            let Some(frame) = self.queue.lock().pop_front() else { break };
            deliver(frame);
            n += 1;
        }
        n
    }
}

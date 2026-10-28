//! The network devices, as `struct net_device` of Linux in net/core/dev.c.
//!
//! A driver implements `NetDriver` and gives it to `register`, which gives the device a name and
//! an interface index. The device counts the packets and the bytes, and it checks the flags and
//! the MTU, so a driver only moves frames. A frame on the receive path goes from `NetDevice::poll`
//! to a function of the caller. This is the place of the NAPI poll of Linux, and the IPv4 stack
//! puts its receive function here. The drivers do not use interrupts yet, so the caller polls.

use crate::buf::NetBuf;
use crate::consts::{
    ARPHRD_ETHER, ARPHRD_LOOPBACK, IF_OPER_DOWN, IF_OPER_LOWERLAYERDOWN, IF_OPER_UNKNOWN,
    IF_OPER_UP, IFF_ALLMULTI, IFF_AUTOMEDIA, IFF_BROADCAST, IFF_DEBUG, IFF_DORMANT, IFF_DYNAMIC,
    IFF_LOOPBACK, IFF_LOWER_UP, IFF_MULTICAST, IFF_NOARP, IFF_NOTRAILERS, IFF_PORTSEL, IFF_PROMISC,
    IFF_RUNNING, IFF_UP, IFNAMSIZ,
};
use crate::ether::{HLEN, MacAddr};
use crate::ns::{self, NetNs};
use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
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

    /// The flags of a new device, as `ether_setup` and `loopback_setup` of Linux set them.
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

    /// The largest payload of a frame after the link header, which is the MTU of a new device.
    fn mtu(&self) -> u32 {
        ETH_DATA_LEN
    }

    /// The largest MTU, as `dev->max_mtu` of Linux.
    fn max_mtu(&self) -> u32 {
        self.mtu()
    }

    /// The kind of a virtual device for `IFLA_INFO_KIND`, as the `kind` of `rtnl_link_ops` of
    /// Linux. It is also the prefix of the name. A virtual device goes away with its namespace.
    fn link_kind(&self) -> Option<&'static str> {
        None
    }

    /// The other end of a pair of devices, for `IFLA_LINK`. The two ends go away together.
    fn peer(&self) -> Option<Arc<NetDevice>> {
        None
    }

    /// The smallest MTU, as `dev->min_mtu` of Linux.
    fn min_mtu(&self) -> u32 {
        match self.kind() {
            LinkKind::Ether => ETH_MIN_MTU,
            LinkKind::Loopback => 0,
        }
    }

    /// Tells if the link is up, as `netif_carrier_ok` of Linux.
    fn link_up(&self) -> bool {
        true
    }

    /// The name of the parent device and of its bus, as `IFLA_PARENT_DEV_NAME` and
    /// `IFLA_PARENT_DEV_BUS_NAME` of Linux give them. For example `virtio0` and `virtio`.
    fn parent(&self) -> Option<(String, &'static str)> {
        None
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

/// The smallest MTU of an Ethernet device, `ETH_MIN_MTU` of Linux.
const ETH_MIN_MTU: u32 = 68;

/// The flags that `dev_change_flags` of Linux takes from the caller.
const SETTABLE: u32 = IFF_DEBUG
    | IFF_NOTRAILERS
    | IFF_NOARP
    | IFF_DYNAMIC
    | IFF_MULTICAST
    | IFF_PORTSEL
    | IFF_AUTOMEDIA;

/// The default length of the transmit queue, `DEFAULT_TX_QUEUE_LEN` of Linux.
pub const TX_QUEUE_LEN: u32 = 1000;

/// A change of a device, for the functions of `add_notifier`. Linux has the same events in
/// `enum netdev_cmd`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// The device is now up, as `NETDEV_UP`.
    Up,
    /// The device is now down, as `NETDEV_DOWN`.
    Down,
    /// The flags in the value changed, as `__dev_notify_flags`.
    Flags(u32),
    /// The MTU changed, as `NETDEV_CHANGEMTU`.
    Mtu,
    /// The name changed, as `NETDEV_CHANGENAME`.
    Name,
    /// The device is now in the namespace, as `NETDEV_REGISTER`.
    Register,
    /// The device goes away from the namespace, as `NETDEV_UNREGISTER`. It is down.
    Unregister,
}

/// A function that gets the changes of each device, as a `notifier_block` of Linux.
pub type Notifier = fn(&NetDevice, Event);

/// The functions that get the changes of each device.
static NOTIFIERS: SpinLock<Vec<Notifier>> = SpinLock::new(Vec::new());

/// Adds a function that gets each change of each device, as `register_netdevice_notifier` of
/// Linux. The function runs without a lock of the device layer.
pub fn add_notifier(f: Notifier) {
    NOTIFIERS.lock().push(f);
}

/// Gives `event` of `dev` to each notifier, in the namespace of the device.
fn notify(dev: &NetDevice, event: Event) {
    let _in = ns::enter_index(dev.net());
    let list = NOTIFIERS.lock().clone();
    for f in list {
        f(dev, event);
    }
}

/// A registered network device.
pub struct NetDevice {
    name: SpinLock<String>,
    ifindex: AtomicU32,
    /// The index of the namespace, as `dev_net` of Linux.
    net: AtomicUsize,
    kind: LinkKind,
    /// The flags of the device, as `dev->flags` of Linux, without `IFF_RUNNING` and
    /// `IFF_LOWER_UP`.
    dflags: AtomicU32,
    /// The flags `IFF_PROMISC` and `IFF_ALLMULTI` that the administrator set, as `dev->gflags`.
    gflags: AtomicU32,
    mtu: AtomicU32,
    txqlen: AtomicU32,
    /// The device was up one time, thus it has its queue discipline.
    activated: AtomicBool,
    counters: Counters,
    driver: Arc<dyn NetDriver>,
}

/// Tells if `name` is a valid name of a device, as `dev_valid_name` of Linux.
pub fn valid_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() < IFNAMSIZ
        && name != b"."
        && name != b".."
        && name.iter().all(|&c| c != b'/' && c != b':' && !c.is_ascii_whitespace() && c != 0)
}

impl NetDevice {
    /// The name, for example `eth0`.
    pub fn name(&self) -> String {
        self.name.lock().clone()
    }

    /// Changes the name, as `dev_change_name` of Linux. Gives `EINVAL` for a bad name, `EBUSY`
    /// if the device is up, and `EEXIST` if another device has the name.
    pub fn set_name(&self, name: &[u8]) -> Result<()> {
        if self.name.lock().as_bytes() == name {
            return Ok(());
        }
        if !valid_name(name) {
            return Err(Errno::EINVAL);
        }
        let Ok(name) = core::str::from_utf8(name) else {
            return Err(Errno::EINVAL);
        };
        if self.is_up() {
            return Err(Errno::EBUSY);
        }
        {
            let devices = DEVICES.lock();
            if devices.iter().any(|d| d.net() == self.net() && *d.name.lock() == name) {
                return Err(Errno::EEXIST);
            }
            *self.name.lock() = String::from(name);
        }
        notify(self, Event::Name);
        Ok(())
    }

    /// The interface index. The loopback device has the index 1. Each namespace has its own
    /// indexes.
    pub fn ifindex(&self) -> u32 {
        self.ifindex.load(Ordering::Relaxed)
    }

    /// The index of the namespace of the device.
    pub fn net(&self) -> usize {
        self.net.load(Ordering::Relaxed)
    }

    /// The kind of a virtual device, for `IFLA_INFO_KIND`.
    pub fn link_kind(&self) -> Option<&'static str> {
        self.driver.link_kind()
    }

    /// The other end of a pair of devices.
    pub fn peer(&self) -> Option<Arc<NetDevice>> {
        self.driver.peer()
    }

    /// The driver.
    pub fn driver(&self) -> &Arc<dyn NetDriver> {
        &self.driver
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

    /// The length of the transmit queue, as `dev->tx_queue_len` of Linux.
    pub fn txqlen(&self) -> u32 {
        self.txqlen.load(Ordering::Relaxed)
    }

    /// Sets the length of the transmit queue. The drivers do not use it.
    pub fn set_txqlen(&self, len: u32) {
        self.txqlen.store(len, Ordering::Relaxed);
    }

    /// The smallest MTU.
    pub fn min_mtu(&self) -> u32 {
        self.driver.min_mtu()
    }

    /// The largest MTU. The loopback device has 0, which is no limit on Linux, but the device
    /// cannot send more than its MTU of 64 KiB.
    pub fn max_mtu(&self) -> u32 {
        match self.kind {
            LinkKind::Loopback => 0,
            LinkKind::Ether => self.driver.max_mtu(),
        }
    }

    /// Sets the MTU, as `dev_set_mtu` of Linux. Gives `EINVAL` if the MTU is out of the range
    /// of the device.
    pub fn set_mtu(&self, mtu: u32) -> Result<()> {
        if mtu == self.mtu() {
            return Ok(());
        }
        let max = self.max_mtu();
        if mtu < self.min_mtu() || (max > 0 && mtu > max) || mtu > i32::MAX as u32 {
            return Err(Errno::EINVAL);
        }
        self.mtu.store(mtu, Ordering::Relaxed);
        notify(self, Event::Mtu);
        Ok(())
    }

    /// Tells if the administrator set the device up.
    pub fn is_up(&self) -> bool {
        self.dflags.load(Ordering::Relaxed) & IFF_UP != 0
    }

    /// Sets the device up or down, as `dev_open` and `dev_close` of Linux. A new device is down.
    pub fn set_up(&self, up: bool) {
        let flags = self.flags() & !IFF_UP;
        // A change of only `IFF_UP` cannot fail.
        let _ = self.change_flags(if up { flags | IFF_UP } else { flags });
    }

    /// Changes the flags, as `dev_change_flags` of Linux. The caller can change `IFF_UP`,
    /// `IFF_PROMISC`, `IFF_ALLMULTI` and the flags in `SETTABLE`. The other flags in `flags` do
    /// nothing.
    pub fn change_flags(&self, flags: u32) -> Result<()> {
        let old = self.dflags.load(Ordering::Relaxed);
        let old_g = self.gflags.load(Ordering::Relaxed);
        let mut new = (flags & SETTABLE) | (old & !SETTABLE);
        if (old ^ flags) & IFF_UP != 0 {
            new = (new & !IFF_UP) | (flags & IFF_UP);
            if flags & IFF_UP != 0 {
                self.activated.store(true, Ordering::Relaxed);
            }
        }
        let g = flags & (IFF_PROMISC | IFF_ALLMULTI);
        self.dflags.store((new & !(IFF_PROMISC | IFF_ALLMULTI)) | g, Ordering::Relaxed);
        self.gflags.store(g, Ordering::Relaxed);
        let changes = (old ^ new) | (old_g ^ g);
        if changes & IFF_UP != 0 {
            notify(self, if new & IFF_UP != 0 { Event::Up } else { Event::Down });
        }
        if changes != 0 {
            notify(self, Event::Flags(changes));
        }
        Ok(())
    }

    /// The flags, as `netif_get_flags` of Linux: the flags of the device, and `IFF_RUNNING` and
    /// `IFF_LOWER_UP` when the device is up and the link is up.
    pub fn flags(&self) -> u32 {
        let mut flags = self.dflags.load(Ordering::Relaxed)
            & !(IFF_PROMISC | IFF_ALLMULTI | IFF_RUNNING | IFF_LOWER_UP | IFF_DORMANT);
        flags |= self.gflags.load(Ordering::Relaxed);
        if flags & IFF_UP != 0 && self.driver.link_up() {
            flags |= IFF_RUNNING | IFF_LOWER_UP;
        }
        flags
    }

    /// The count of users of the promiscuous mode, as `dev->promiscuity` of Linux.
    pub fn promiscuity(&self) -> u32 {
        u32::from(self.gflags.load(Ordering::Relaxed) & IFF_PROMISC != 0)
    }

    /// The count of users of the all-multicast mode, as `dev->allmulti` of Linux.
    pub fn allmulti(&self) -> u32 {
        u32::from(self.gflags.load(Ordering::Relaxed) & IFF_ALLMULTI != 0)
    }

    /// Tells if the link has a carrier, as `netif_carrier_ok` of Linux.
    pub fn carrier(&self) -> bool {
        self.driver.link_up()
    }

    /// The count of carrier changes since the registration. A driver sets the carrier on one
    /// time when it starts.
    pub fn carrier_up_count(&self) -> u32 {
        u32::from(self.kind == LinkKind::Ether && self.carrier())
    }

    /// The state of the link for RFC 2863, `IF_OPER_*`, as `rfc2863_policy` of Linux. The
    /// loopback device does not tell its carrier, thus its state is unknown when it is up.
    pub fn operstate(&self) -> u8 {
        if !self.is_up() {
            IF_OPER_DOWN
        } else if self.kind == LinkKind::Loopback {
            IF_OPER_UNKNOWN
        } else if self.carrier() {
            IF_OPER_UP
        } else {
            IF_OPER_LOWERLAYERDOWN
        }
    }

    /// The name of the queue discipline. A device that was never up has `noop`.
    pub fn qdisc(&self) -> &'static str {
        if !self.activated.load(Ordering::Relaxed) {
            "noop"
        } else if self.kind == LinkKind::Loopback {
            "noqueue"
        } else {
            "pfifo_fast"
        }
    }

    /// The broadcast hardware address.
    pub fn broadcast(&self) -> MacAddr {
        match self.kind {
            LinkKind::Ether => MacAddr::BROADCAST,
            LinkKind::Loopback => MacAddr::ZERO,
        }
    }

    /// The parent device and its bus.
    pub fn parent(&self) -> Option<(String, &'static str)> {
        self.driver.parent()
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
            frame.ifindex = self.ifindex();
            deliver(self, frame);
        })
    }
}

/// The registered devices of all namespaces, in the order of their registration.
static DEVICES: SpinLock<Vec<Arc<NetDevice>>> = SpinLock::new(Vec::new());

/// The lowest free interface index of the namespace `net`, as `dev_index_reserve` of Linux. The
/// index is one more than the largest index in use.
fn new_index(devices: &[Arc<NetDevice>], net: usize) -> u32 {
    devices.iter().filter(|d| d.net() == net).map(|d| d.ifindex()).max().unwrap_or(0) + 1
}

/// Registers a device in the current namespace and gives it. The loopback device gets the name
/// `lo`, and an Ethernet device gets `ethN` with the lowest free `N`, as `dev_alloc_name` of
/// Linux. The interface index is one more than the largest index in use. Gives `EEXIST` for a
/// second loopback device.
pub fn register(driver: Arc<dyn NetDriver>) -> Result<Arc<NetDevice>> {
    register_named(driver, None)
}

/// Registers a device in the current namespace with the name `name`, as `register_netdevice` of
/// Linux. Without a name, a virtual device gets its kind and the lowest free number, as `vethN`.
/// Gives `EEXIST` if the name is in use, and `EINVAL` for a bad name.
pub fn register_named(driver: Arc<dyn NetDriver>, name: Option<&[u8]>) -> Result<Arc<NetDevice>> {
    let net = ns::current_index();
    let dev = {
        let mut devices = DEVICES.lock();
        let kind = driver.kind();
        let taken = |name: &str| devices.iter().any(|d| d.net() == net && *d.name.lock() == name);
        let name = match (kind, name) {
            (LinkKind::Loopback, _) if taken("lo") => return Err(Errno::EEXIST),
            (LinkKind::Loopback, _) => String::from("lo"),
            (LinkKind::Ether, Some(name)) => {
                let name = core::str::from_utf8(name).map_err(|_| Errno::EINVAL)?;
                if !valid_name(name.as_bytes()) {
                    return Err(Errno::EINVAL);
                }
                if taken(name) {
                    return Err(Errno::EEXIST);
                }
                String::from(name)
            }
            (LinkKind::Ether, None) => {
                let prefix = driver.link_kind().unwrap_or("eth");
                match (0..).map(|n| format!("{prefix}{n}")).find(|n| !taken(n)) {
                    Some(name) => name,
                    None => return Err(Errno::ENFILE),
                }
            }
        };
        let ifindex = new_index(&devices, net);
        let dev = Arc::new(NetDevice {
            name: SpinLock::new(name),
            ifindex: AtomicU32::new(ifindex),
            net: AtomicUsize::new(net),
            kind,
            dflags: AtomicU32::new(kind.base_flags()),
            gflags: AtomicU32::new(0),
            mtu: AtomicU32::new(driver.mtu()),
            txqlen: AtomicU32::new(TX_QUEUE_LEN),
            activated: AtomicBool::new(false),
            counters: Counters::default(),
            driver,
        });
        devices.push(dev.clone());
        dev
    };
    notify(&dev, Event::Register);
    Ok(dev)
}

/// Tells if `dev` is registered.
fn registered(dev: &NetDevice) -> bool {
    DEVICES.lock().iter().any(|d| core::ptr::eq(&**d, dev))
}

/// Removes a device, as `unregister_netdevice` of Linux. The device goes down first. The other
/// end of a pair goes too.
pub fn unregister(dev: &Arc<NetDevice>) {
    if !registered(dev) {
        return;
    }
    dev.set_up(false);
    notify(dev, Event::Unregister);
    DEVICES.lock().retain(|d| !Arc::ptr_eq(d, dev));
    if let Some(peer) = dev.peer() {
        unregister(&peer);
    }
}

/// Moves a device to the namespace `to`, as `__dev_change_net_namespace` of Linux. The device
/// goes down, and it keeps its index if the index is free in `to`. Gives `EINVAL` for the
/// loopback device, and `EEXIST` if `to` has a device with the same name.
pub fn move_to(dev: &Arc<NetDevice>, to: &NetNs) -> Result<()> {
    if dev.kind == LinkKind::Loopback {
        return Err(Errno::EINVAL);
    }
    let net = to.index();
    if dev.net() == net {
        return Ok(());
    }
    {
        let devices = DEVICES.lock();
        let name = dev.name();
        if devices.iter().any(|d| d.net() == net && *d.name.lock() == name) {
            return Err(Errno::EEXIST);
        }
    }
    dev.set_up(false);
    notify(dev, Event::Unregister);
    {
        let devices = DEVICES.lock();
        let index = dev.ifindex();
        if devices.iter().any(|d| d.net() == net && d.ifindex() == index) {
            dev.ifindex.store(new_index(&devices, net), Ordering::Relaxed);
        }
        dev.net.store(net, Ordering::Relaxed);
    }
    notify(dev, Event::Register);
    Ok(())
}

/// Finds a device of the current namespace by its name.
pub fn by_name(name: &str) -> Option<Arc<NetDevice>> {
    let net = ns::current_index();
    DEVICES.lock().iter().find(|d| d.net() == net && *d.name.lock() == name).cloned()
}

/// Finds a device of the current namespace by its interface index.
pub fn by_index(ifindex: u32) -> Option<Arc<NetDevice>> {
    let net = ns::current_index();
    DEVICES.lock().iter().find(|d| d.net() == net && d.ifindex() == ifindex).cloned()
}

/// The devices of the current namespace, in the order of their interface index.
pub fn devices() -> Vec<Arc<NetDevice>> {
    let net = ns::current_index();
    let mut list: Vec<_> = DEVICES.lock().iter().filter(|d| d.net() == net).cloned().collect();
    list.sort_by_key(|d| d.ifindex());
    list
}

/// The devices of all namespaces, for the poll of the devices.
pub fn all_devices() -> Vec<Arc<NetDevice>> {
    DEVICES.lock().clone()
}

/// Makes the loopback device of a new namespace, as `loopback_net_init` of Linux. The device is
/// down.
fn ns_init() {
    // Only a second loopback device gives an error, and a new namespace has none.
    let _ = register(Arc::new(Loopback::default()));
}

/// Takes the devices out of a namespace that stops, as `default_device_exit_batch` of Linux. A
/// virtual device and the loopback device go away. The other devices go back to the first
/// namespace.
fn ns_exit() {
    let net = ns::current_index();
    let init = ns::init_ns();
    let list: Vec<_> = DEVICES.lock().iter().filter(|d| d.net() == net).cloned().collect();
    for dev in list {
        if dev.kind == LinkKind::Loopback || dev.link_kind().is_some() {
            unregister(&dev);
        } else if move_to(&dev, &init).is_err() {
            // The first namespace has a device with the same name, as on Linux, which then
            // gives the device the name `devN`.
            let name = (0..).map(|n| format!("dev{n}")).find(|n| by_name_in(0, n).is_none());
            if let Some(name) = name {
                *dev.name.lock() = name;
            }
            let _ = move_to(&dev, &init);
        }
    }
}

/// Finds a device of the namespace `net` by its name.
fn by_name_in(net: usize, name: &str) -> Option<Arc<NetDevice>> {
    DEVICES.lock().iter().find(|d| d.net() == net && *d.name.lock() == name).cloned()
}

/// Registers the loopback device, so that it gets the interface index 1 as on Linux. The kernel
/// calls this before it starts the drivers. A second call does nothing.
pub fn init() {
    static OPS: AtomicBool = AtomicBool::new(false);
    if !OPS.swap(true, Ordering::Relaxed) {
        ns::add_device_ops(ns_init, ns_exit);
    }
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

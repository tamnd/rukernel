//! The devices of the classes that are in the directory of a device on a bus, as on Linux: a disk
//! of a virtio device is in `/sys/devices/pci0000:00/0000:00:02.0/virtio1/block/vda`, and an
//! interface of a virtio device is in `.../virtio2/net/eth0`.
//!
//! `rk_vfs::uevent::devpath` and `rk_net::netlink::uevent::path` give the paths. The directory of
//! the virtio device gets a directory for each class, with a directory for each device in it. The
//! directory of the device has the files of a device in `/sys/devices/virtual`, the link `device`
//! to the virtio device, and the file `uevent`, which takes a write.

use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use rk_net::dev::NetDevice;
use rk_net::ns::NetNs;
use rk_vfs::device::DeviceInfo;

use super::Kind;

/// A device of a class in the directory of a device on a bus.
pub(crate) enum Placed {
    Dev(DeviceInfo),
    Net(Arc<NetDevice>),
}

impl Placed {
    /// The path of the directory of the device below `/sys`, without the `/` at the start.
    fn path(&self) -> String {
        let path = match self {
            Self::Dev(d) => rk_vfs::uevent::devpath(d),
            Self::Net(n) => net_path(n),
        };
        String::from(path.trim_start_matches('/'))
    }
}

/// The path of the directory of the interface `d` below `/sys`, with a `/` at the start.
pub(crate) fn net_path(d: &NetDevice) -> String {
    rk_net::netlink::uevent::path(d, &d.name())
}

/// Tells if the directory at `path` below `/sys` is in `/sys/devices/virtual`.
pub(crate) fn is_virtual(path: &str) -> bool {
    path.trim_start_matches('/').starts_with("devices/virtual/")
}

/// The interfaces of the namespace `ns`. A namespace that stopped has none.
pub(crate) fn net_devices(ns: &Weak<NetNs>) -> Vec<Arc<NetDevice>> {
    ns.upgrade().map_or_else(Vec::new, |ns| {
        let _in = rk_net::ns::enter(&ns);
        rk_net::dev::devices()
    })
}

/// The devices of `list` and the interfaces of `net` that are in the directory of a device on a
/// bus.
pub(crate) fn all(list: &[DeviceInfo], net: &[Arc<NetDevice>]) -> Vec<Placed> {
    let devs = list.iter().filter(|d| !is_virtual(&rk_vfs::uevent::devpath(d)));
    let mut out: Vec<Placed> = devs.cloned().map(Placed::Dev).collect();
    let nets = net.iter().filter(|d| !is_virtual(&net_path(d)));
    out.extend(nets.cloned().map(Placed::Net));
    out
}

/// The `../` that go from the directory at `path` below `/sys` to `/sys`.
pub(crate) fn up(path: &str) -> String {
    "../".repeat(path.trim_start_matches('/').split('/').count())
}

/// The link `device` of the device with the directory at `path`, to the device on the bus, or
/// `None` for a device in `/sys/devices/virtual`. The path ends with `BUS_DEVICE/CLASS/NAME`.
pub(crate) fn device_link(path: &str) -> Option<(String, Kind)> {
    if is_virtual(path) {
        return None;
    }
    let mut parts = path.rsplit('/');
    let bus_device = parts.nth(2)?;
    Some((String::from("device"), Kind::Link(format!("../../../{bus_device}").into_bytes())))
}

/// The parent of the directory at `path`.
fn parent(path: &str) -> &str {
    path.rfind('/').map_or("", |i| &path[..i])
}

/// The last part of `path`.
fn base(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The entries of the directory at `path` below `/sys`, if it is the directory of a device of
/// `placed` or in it, or the directory of a class in the directory of a device on a bus.
pub(crate) fn entries(path: &str, placed: &[Placed]) -> Option<Vec<(String, Kind)>> {
    let paths: Vec<String> = placed.iter().map(Placed::path).collect();
    if paths.iter().any(|p| parent(p) == path) {
        let mut names: Vec<(String, Kind)> = paths
            .iter()
            .filter(|p| parent(p) == path)
            .map(|p| (String::from(base(p)), Kind::Dir))
            .collect();
        names.sort_by(|a, b| a.0.cmp(&b.0));
        names.dedup_by(|a, b| a.0 == b.0);
        return Some(names);
    }
    let below = |p: &str| path.strip_prefix(p).is_some_and(|r| r.is_empty() || r.starts_with('/'));
    let (p, d) = paths.iter().zip(placed).find(|(p, _)| below(p))?;
    let out = match (&path[p.len()..], d) {
        ("", Placed::Dev(d)) => super::device_entries(d),
        ("", Placed::Net(n)) => super::net_entries(n),
        ("/queue", Placed::Dev(d)) if d.block => super::queue_entries(d),
        ("/loop", Placed::Dev(d)) if d.block => {
            let files = rk_vfs::loopdev::sysfs_files(d.rdev)?;
            files
                .into_iter()
                .map(|(n, text)| (String::from(n), Kind::File(text.into_bytes())))
                .collect()
        }
        ("/statistics", Placed::Net(n)) => super::net_statistics(n),
        _ => return None,
    };
    Some(out)
}

/// The directories of the classes in the directory at `path` of a device on a bus: `block` for a
/// virtio device with a disk.
pub(crate) fn classes(path: &str, placed: &[Placed]) -> Vec<(String, Kind)> {
    let mut out: Vec<(String, Kind)> = placed
        .iter()
        .map(Placed::path)
        .filter(|p| parent(parent(p)) == path)
        .map(|p| (String::from(base(parent(&p))), Kind::Dir))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.dedup_by(|a, b| a.0 == b.0);
    out
}

/// The device of the file `uevent` at `path`, if it is the file of a device of `placed`.
pub(crate) fn uevent_device<'a>(path: &str, placed: &'a [Placed]) -> Option<&'a Placed> {
    let dir = path.strip_suffix("/uevent")?;
    placed.iter().find(|p| p.path() == dir)
}

/// Tells if the file at `path` is the file `uevent` of a device in the directory of a device on a
/// bus. `ns` is the network namespace of the mount.
pub(crate) fn is_uevent(path: &str, ns: &Weak<NetNs>) -> bool {
    path.ends_with("/uevent")
        && !is_virtual(path)
        && uevent_device(path, &all(&rk_vfs::device::devices(), &net_devices(ns))).is_some()
}

/// Sends the event that a process writes to the file `uevent` at `path`, as `uevent_store` of
/// Linux. `ns` is the network namespace of the mount.
pub(crate) fn write_uevent(path: &str, ns: &Weak<NetNs>, text: &[u8]) -> rk_vfs::Result<()> {
    let placed = all(&rk_vfs::device::devices(), &net_devices(ns));
    let d = uevent_device(path, &placed).ok_or(rk_abi::Errno::ENODEV)?;
    let (action, vars) = rk_vfs::uevent::parse_synth(text)?;
    match d {
        Placed::Dev(d) => rk_vfs::uevent::synth_device(d, action, vars),
        Placed::Net(n) => {
            let ns = ns.upgrade().ok_or(rk_abi::Errno::ENODEV)?;
            let _in = rk_net::ns::enter(&ns);
            rk_net::netlink::uevent::synth(n, action, vars);
        }
    }
    Ok(())
}

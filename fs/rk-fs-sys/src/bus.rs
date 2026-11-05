//! The devices on the buses: `/sys/devices/pci0000:00`, `/sys/devices/platform`, `/sys/bus` and
//! `/sys/module`, as drivers/pci/pci-sysfs.c, drivers/base/bus.c and kernel/params.c of Linux.
//!
//! A PCI function has `vendor`, `device`, `class`, `modalias`, `uevent` and the links `driver` and
//! `subsystem`. The virtio device on a transport is the directory `virtioN` of the function or of
//! the platform device. `/sys/bus/BUS/devices` has a link to each device, and
//! `/sys/bus/BUS/drivers` has a directory for each driver. `/sys/module` has the drivers that are
//! modules on Linux. They are in the kernel here, as with `=y` on Linux.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::Result;
use rk_vfs::bus::{PCI_ROOT, PciFunction, PlatformDevice, Transport, VirtioDevice};

use super::Kind;

/// The directory of the platform devices below `/sys/devices`.
const PLATFORM: &str = "platform";

/// The buses, with their drivers. Each driver has the name of its module.
const BUSES: [(&str, &[(&str, &str)]); 3] = [
    ("pci", &[("virtio-pci", "virtio_pci")]),
    ("platform", &[("virtio-mmio", "virtio_mmio")]),
    ("virtio", &[("virtio_blk", "virtio_blk"), ("virtio_net", "virtio_net")]),
];

/// A file with the text `text`.
fn file(name: &str, text: String) -> (String, Kind) {
    (String::from(name), Kind::File(text.into_bytes()))
}

/// A link to `to`.
fn link(name: &str, to: String) -> (String, Kind) {
    (String::from(name), Kind::Link(to.into_bytes()))
}

/// A directory.
fn dir(name: &str) -> (String, Kind) {
    (String::from(name), Kind::Dir)
}

/// The text of the file `uevent` with the variables `vars`, one on each line.
fn lines(vars: &[String]) -> String {
    vars.iter().map(|v| format!("{v}\n")).collect()
}

/// A device on one of the buses, with the path of its directory below `/sys`.
enum Device {
    Pci(PciFunction),
    Platform(PlatformDevice),
    Virtio(VirtioDevice),
}

impl Device {
    /// The bus of the device, for the link `subsystem` and for the event.
    fn bus(&self) -> &'static str {
        match self {
            Self::Pci(_) => "pci",
            Self::Platform(_) => PLATFORM,
            Self::Virtio(_) => "virtio",
        }
    }

    /// The name of the device on its bus.
    fn name(&self) -> String {
        match self {
            Self::Pci(f) => f.name(),
            Self::Platform(d) => d.name(),
            Self::Virtio(d) => d.name(),
        }
    }

    /// The path of the directory of the device below `/sys`, with a `/` at the start.
    fn path(&self) -> String {
        match self {
            Self::Pci(f) => rk_vfs::bus::transport_path(Transport::Pci(f.bus, f.slot, f.function)),
            Self::Platform(d) => rk_vfs::bus::transport_path(Transport::Mmio(d.phys)),
            Self::Virtio(d) => format!("{}/{}", rk_vfs::bus::transport_path(d.transport), d.name()),
        }
    }

    /// The driver of the device.
    fn driver(&self) -> Option<&'static str> {
        match self {
            Self::Pci(f) => f.driver,
            Self::Platform(d) => d.driver,
            Self::Virtio(d) => d.driver,
        }
    }

    /// The variables of the file `uevent` of the device.
    fn uevent(&self) -> Vec<String> {
        match self {
            Self::Pci(f) => f.uevent(),
            Self::Platform(d) => d.uevent(),
            Self::Virtio(d) => d.uevent(),
        }
    }
}

/// All devices on the buses.
fn all() -> Vec<Device> {
    let mut out: Vec<Device> = rk_vfs::bus::pci().into_iter().map(Device::Pci).collect();
    out.extend(rk_vfs::bus::platform().into_iter().map(Device::Platform));
    out.extend(rk_vfs::bus::virtio().into_iter().map(Device::Virtio));
    out
}

/// The `../` that go from the directory at `path` below `/sys` to `/sys`.
fn up(path: &str) -> String {
    "../".repeat(path.trim_start_matches('/').split('/').count())
}

/// The entries of the directory of the device `d`, with the virtio devices `virtio` on it.
fn device_entries(d: &Device, virtio: &[VirtioDevice]) -> Vec<(String, Kind)> {
    let path = d.path();
    let up = up(&path);
    let mut out = Vec::new();
    match d {
        Device::Pci(f) => {
            out.push(file("class", format!("{:#08x}\n", f.class)));
            out.push(file("device", format!("{:#06x}\n", f.device)));
            out.push(file("enable", format!("{}\n", u8::from(f.driver.is_some()))));
            out.push(file("irq", format!("{}\n", f.irq)));
            out.push(file("revision", format!("{:#04x}\n", f.revision)));
            out.push(file("subsystem_device", format!("{:#06x}\n", f.subsystem_device)));
            out.push(file("subsystem_vendor", format!("{:#06x}\n", f.subsystem_vendor)));
            out.push(file("vendor", format!("{:#06x}\n", f.vendor)));
        }
        Device::Platform(_) => {}
        Device::Virtio(v) => {
            out.push(file("device", format!("{:#06x}\n", v.device)));
            out.push(file("vendor", format!("{:#06x}\n", v.vendor)));
        }
    }
    if !matches!(d, Device::Virtio(_)) {
        out.push(file("driver_override", String::from("(null)\n")));
    }
    if let Some(drv) = d.driver() {
        out.push(link("driver", format!("{up}bus/{}/drivers/{drv}", d.bus())));
    }
    let modalias =
        d.uevent().into_iter().find_map(|v| v.strip_prefix("MODALIAS=").map(String::from));
    out.push(file("modalias", format!("{}\n", modalias.unwrap_or_default())));
    out.push(dir("power"));
    out.push(link("subsystem", format!("{up}bus/{}", d.bus())));
    out.push(file("uevent", lines(&d.uevent())));
    for v in virtio {
        out.push(dir(&v.name()));
    }
    out
}

/// The virtio devices on the transport `t`.
fn on(t: Transport) -> Vec<VirtioDevice> {
    rk_vfs::bus::virtio().into_iter().filter(|v| v.transport == t).collect()
}

/// The entries of the directory `rest` below `/sys/devices/pci0000:00` or
/// `/sys/devices/platform`. `top` is the name of that directory.
fn transport_entries(top: &str, rest: &[&str]) -> Option<Vec<(String, Kind)>> {
    let (t, dev) = match top {
        PCI_ROOT => {
            let f =
                rk_vfs::bus::pci().into_iter().find(|f| rest.first() == Some(&f.name().as_str()));
            f.map(|f| (Transport::Pci(f.bus, f.slot, f.function), Device::Pci(f)))
        }
        _ => {
            let d = rk_vfs::bus::platform()
                .into_iter()
                .find(|d| rest.first() == Some(&d.name().as_str()));
            d.map(|d| (Transport::Mmio(d.phys), Device::Platform(d)))
        }
    }
    .unzip();
    let out = match rest {
        [] => {
            let mut out: Vec<(String, Kind)> = match top {
                PCI_ROOT => rk_vfs::bus::pci().iter().map(|f| dir(&f.name())).collect(),
                _ => rk_vfs::bus::platform().iter().map(|d| dir(&d.name())).collect(),
            };
            out.push(dir("power"));
            out.push(file("uevent", String::new()));
            out
        }
        [_] => device_entries(&dev?, &on(t?)),
        [_, "power"] | [_, _, "power"] => {
            let _ = (t?, dev?);
            Vec::new()
        }
        [_, name] => {
            let v = on(t?).into_iter().find(|v| v.name() == *name)?;
            device_entries(&Device::Virtio(v), &[])
        }
        _ => return None,
    };
    Some(out)
}

/// The entries of the directory `rest` below `/sys/devices` that this module has, or `None`.
/// `rest` is not empty.
pub(crate) fn devices_entries(rest: &[&str]) -> Option<Vec<(String, Kind)>> {
    match rest {
        [top, rest @ ..] if *top == PCI_ROOT && !rk_vfs::bus::pci().is_empty() => {
            transport_entries(top, rest)
        }
        [PLATFORM, rest @ ..] => transport_entries(PLATFORM, rest),
        _ => None,
    }
}

/// The names below `/sys/devices` that this module has.
pub(crate) fn devices_top() -> Vec<&'static str> {
    if rk_vfs::bus::pci().is_empty() {
        Vec::from([PLATFORM])
    } else {
        Vec::from([PCI_ROOT, PLATFORM])
    }
}

/// The entries of the directory `rest` below `/sys/bus`.
pub(crate) fn bus_entries(rest: &[&str]) -> Option<Vec<(String, Kind)>> {
    let devices = all();
    let find = |bus: &str| BUSES.iter().find(|(b, _)| *b == bus).map(|&(_, d)| d);
    let out = match rest {
        [] => BUSES.iter().map(|(b, _)| dir(b)).collect(),
        [bus] => {
            find(*bus)?;
            Vec::from([
                dir("devices"),
                dir("drivers"),
                file("drivers_autoprobe", String::from("1\n")),
                file("drivers_probe", String::new()),
                file("uevent", String::new()),
            ])
        }
        [bus, "devices"] => {
            find(*bus)?;
            let on = devices.iter().filter(|d| d.bus() == *bus);
            on.map(|d| link(&d.name(), format!("../../..{}", d.path()))).collect()
        }
        [bus, "drivers"] => find(*bus)?.iter().map(|(d, _)| dir(d)).collect(),
        [bus, "drivers", drv] => {
            let &(drv, module) = find(*bus)?.iter().find(|(d, _)| *d == *drv)?;
            let bound = devices.iter().filter(|d| d.bus() == *bus && d.driver() == Some(drv));
            let mut out: Vec<(String, Kind)> =
                bound.map(|d| link(&d.name(), format!("../../../..{}", d.path()))).collect();
            out.push(file("bind", String::new()));
            out.push(link("module", format!("../../../../module/{module}")));
            out.push(file("uevent", String::new()));
            out.push(file("unbind", String::new()));
            out
        }
        _ => return None,
    };
    Some(out)
}

/// The entries of the directory `rest` below `/sys/module`.
pub(crate) fn module_entries(rest: &[&str]) -> Option<Vec<(String, Kind)>> {
    let out = match rest {
        [] => {
            let mut names: Vec<&str> =
                BUSES.iter().flat_map(|(_, d)| d.iter().map(|x| x.1)).collect();
            names.sort_unstable();
            names.into_iter().map(dir).collect()
        }
        [m] => {
            drivers(m).next()?;
            Vec::from([dir("drivers"), file("uevent", String::new())])
        }
        [m, "drivers"] => drivers(m)
            .map(|(b, d)| link(&format!("{b}:{d}"), format!("../../../bus/{b}/drivers/{d}")))
            .collect(),
        _ => return None,
    };
    Some(out)
}

/// The drivers that are in the module `m`, each with its bus.
fn drivers(m: &str) -> impl Iterator<Item = (&'static str, &'static str)> + '_ {
    BUSES
        .iter()
        .flat_map(|&(b, d)| d.iter().map(move |&(d, m)| (b, d, m)))
        .filter(move |x| x.2 == m)
        .map(|(b, d, _)| (b, d))
}

/// The device of the file `uevent` at `path`, or `None` for the file of a root, which takes a
/// write and sends no event, as a device of Linux with no bus. Gives `Err` if `path` is not such
/// a file.
fn uevent_device(path: &str) -> core::result::Result<Option<Device>, ()> {
    let parts: Vec<&str> = path.split('/').collect();
    let ["devices", top, rest @ .., "uevent"] = &parts[..] else { return Err(()) };
    if *top != PCI_ROOT && *top != PLATFORM {
        return Err(());
    }
    if rest.is_empty() {
        return Ok(None);
    }
    let dir = format!("/devices/{top}/{}", rest.join("/"));
    all().into_iter().find(|d| d.path() == dir).map(Some).ok_or(())
}

/// Tells if the file at `path` is the file `uevent` of a device on a bus.
pub(crate) fn is_uevent(path: &str) -> bool {
    uevent_device(path).is_ok()
}

/// Sends the event that a process writes to the file `uevent` at `path`, as `uevent_store` of
/// Linux.
pub(crate) fn write_uevent(path: &str, text: &[u8]) -> Result<()> {
    let d = uevent_device(path).map_err(|()| Errno::ENODEV)?;
    let (action, vars) = rk_vfs::uevent::parse_synth(text)?;
    if let Some(d) = d {
        let mut e = rk_vfs::uevent::Event::new(action, d.path(), d.bus());
        e.vars = vars;
        e.vars.extend(d.uevent());
        rk_vfs::uevent::send(&e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[(String, Kind)]) -> Vec<&str> {
        v.iter().map(|(n, _)| n.as_str()).collect()
    }

    #[test]
    fn a_function_has_its_files_and_its_virtio_device() {
        rk_vfs::bus::add_pci(PciFunction {
            bus: 0,
            slot: 3,
            function: 0,
            vendor: 0x1af4,
            device: 0x1000,
            class: 0x02_0000,
            revision: 0,
            subsystem_vendor: 0x1af4,
            subsystem_device: 1,
            irq: 11,
            driver: Some("virtio-pci"),
        });
        rk_vfs::bus::add_virtio(VirtioDevice {
            index: 7,
            transport: Transport::Pci(0, 3, 0),
            device: 1,
            vendor: 0x1af4,
            driver: Some("virtio_net"),
        });
        let f = devices_entries(&[PCI_ROOT, "0000:00:03.0"]).unwrap();
        assert!(names(&f).contains(&"virtio7"));
        let get = |v: &[(String, Kind)], n: &str| v.iter().find(|(m, _)| m == n).unwrap().1.clone();
        assert_eq!(get(&f, "vendor"), Kind::File(b"0x1af4\n".to_vec()));
        assert_eq!(get(&f, "class"), Kind::File(b"0x020000\n".to_vec()));
        assert_eq!(get(&f, "driver"), Kind::Link(b"../../../bus/pci/drivers/virtio-pci".to_vec()));
        assert_eq!(get(&f, "subsystem"), Kind::Link(b"../../../bus/pci".to_vec()));
        let v = devices_entries(&[PCI_ROOT, "0000:00:03.0", "virtio7"]).unwrap();
        assert_eq!(get(&v, "modalias"), Kind::File(b"virtio:d00000001v00001AF4\n".to_vec()));
        assert_eq!(
            get(&v, "driver"),
            Kind::Link(b"../../../../bus/virtio/drivers/virtio_net".to_vec())
        );
        let b = bus_entries(&["virtio", "devices"]).unwrap();
        assert_eq!(
            get(&b, "virtio7"),
            Kind::Link(b"../../../devices/pci0000:00/0000:00:03.0/virtio7".to_vec())
        );
        let d = bus_entries(&["pci", "drivers", "virtio-pci"]).unwrap();
        assert_eq!(
            get(&d, "0000:00:03.0"),
            Kind::Link(b"../../../../devices/pci0000:00/0000:00:03.0".to_vec())
        );
        assert_eq!(get(&d, "module"), Kind::Link(b"../../../../module/virtio_pci".to_vec()));
        let m = module_entries(&["virtio_net", "drivers"]).unwrap();
        assert_eq!(
            get(&m, "virtio:virtio_net"),
            Kind::Link(b"../../../bus/virtio/drivers/virtio_net".to_vec())
        );
        assert!(is_uevent("devices/pci0000:00/0000:00:03.0/virtio7/uevent"));
        assert!(is_uevent("devices/pci0000:00/uevent"));
        assert!(!is_uevent("devices/pci0000:00/0000:00:09.0/uevent"));
        assert_eq!(devices_entries(&[PCI_ROOT, "0000:00:09.0"]), None);
        assert_eq!(bus_entries(&["usb"]), None);
    }
}

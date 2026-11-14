//! sysfs: the files of `/sys`, which show the devices of the kernel.
//!
//! The tree comes from the list of devices in `rk_vfs::device`. Each lookup makes the entries
//! again, so a device that a driver adds after the mount shows at the next lookup. The layout
//! follows Linux, because udev, mdev and the C libraries read it:
//!
//! - `/sys/devices/virtual/CLASS/NAME` is the directory of a device. It has the files `dev` and
//!   `uevent`, and the link `subsystem`. A block device also has `size`, `ro`, `removable` and
//!   the directory `queue` with the limits of the queue, and `stat` and `inflight` with the
//!   counts of the queue, as block/genhd.c of Linux.
//!   A loop device with a file also has the directory `loop`, which `losetup` reads. The
//!   driver of a class can give more files, as `tpm_version_major` and `pcr-sha256` of a TPM.
//!   A write of `ACTION [UUID [KEY=VALUE...]]` to `uevent` sends an event of the device, as
//!   `udevadm trigger` asks for.
//! - `/sys/class/CLASS/NAME` and `/sys/block/NAME` are links to the directory of the device.
//! - `/sys/dev/block/MAJ:MIN` and `/sys/dev/char/MAJ:MIN` are links to the same directory.
//! - `/sys/fs/cgroup` is an empty directory, where cgroup2 is mounted.
//! - `/sys/fs/ext4/features` has a file for each feature of ext4 that programs look for. The
//!   online resize of `resize2fs` reads `meta_bg_resize`.
//! - `/sys/kernel/config`, `/sys/kernel/debug`, `/sys/kernel/tracing` and
//!   `/sys/fs/fuse/connections` are empty directories, where configfs, debugfs, tracefs and
//!   fusectl of the module `kfs` are mounted.
//! - `/sys/kernel/uevent_seqnum` has the sequence number of the last event of the devices.
//! - `/sys/kernel/mm/ksm` has the files of Kernel Samepage Merging. A write to some of them
//!   changes the settings of KSM.
//! - `/sys/kernel/mm/transparent_hugepage` has the policy for huge pages. `enabled` and `defrag`
//!   take a write, as in Linux.
//! - `/sys/kernel/mm/hugepages/hugepages-2048kB` has the counters of the pool of hugetlbfs.
//!   `nr_hugepages` and `nr_overcommit_hugepages` take a write, as in Linux. LTP looks for that
//!   directory to know if it can mount hugetlbfs.
//! - `/sys/devices/virtual/net/NAME` is the directory of a network interface, from the list of
//!   `rk_net::dev`. It has the attributes of net/core/net-sysfs.c of Linux and the directory
//!   `statistics`. `/sys/class/net/NAME` is a link to it.
//! - `/sys/devices/virtual/input/inputN` is the directory of an input device, from
//!   `rk_vfs::input`, with `name`, `id`, `capabilities` and a directory for each handler, as
//!   `mouse0` and `event0`. `/sys/class/input` has a link to each of them.
//! - `/sys/devices/system/cpu` has a directory `cpuN` with `topology` for each CPU, and the
//!   files `online`, `possible` and `present`. `/sys/devices/system/node` has the one NUMA node
//!   `node0`. glibc reads `online` for `get_nprocs` and `possible` for `get_nprocs_conf`.
//! - `/sys/devices/pci0000:00` has a directory for each PCI function, and
//!   `/sys/devices/platform` has the virtio MMIO devices of the device tree, from
//!   `rk_vfs::bus`. The virtio device on a transport is the directory `virtioN` of the
//!   transport. `/sys/bus/pci`, `/sys/bus/platform` and `/sys/bus/virtio` have links to them,
//!   and `/sys/module` has the modules of their drivers.
//! - A mount of sysfs keeps the network namespace of the task that mounts it, as the namespace
//!   tag of kernfs in fs/sysfs/mount.c of Linux. The mount shows only the interfaces of that
//!   namespace, and a mount in another namespace is another file system.
//!
//! Linux puts a device of a class below the directory of its parent on a bus. This kernel does
//! that for the disks and the interfaces of the virtio devices, as
//! `/sys/devices/pci0000:00/0000:00:02.0/virtio1/block/vda`, with the module `placed`. udev
//! reads the parents for the names of `path_id` and `net_id`. The other devices of the classes
//! are in `/sys/devices/virtual`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod bus;
mod cpu;
mod firmware;
pub mod kfs;
mod mm;
mod placed;

pub use bus::{Param, add_param};

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::Once;
use rk_net::consts::{IFF_DORMANT, IFF_LOWER_UP, IFF_RUNNING};
use rk_net::dev::NetDevice;
use rk_net::ns::NetNs;
use rk_vfs::blockdev::{block_queue, block_sectors};
use rk_vfs::device::{DeviceInfo, devices, major, minor};
use rk_vfs::fstype::{FsType, MountArgs};
use rk_vfs::inode::mode;
use rk_vfs::{DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, now};

/// The magic number of sysfs, `SYSFS_MAGIC` of `<linux/magic.h>`.
pub const SYSFS_MAGIC: u64 = 0x6265_6572;

/// The file system type of sysfs, for `mount -t sysfs`.
pub const FS_TYPE: FsType = FsType { name: "sysfs", nodev: true, make: mount };

/// The directories at the top of sysfs. `power` has no entries.
const TOP: [&str; 10] =
    ["block", "bus", "class", "dev", "devices", "firmware", "fs", "kernel", "module", "power"];

/// The files of `/sys/fs/ext4/features`, as Linux. `resize2fs` grows a mounted file system past
/// its reserved descriptor blocks only if `meta_bg_resize` is there.
const EXT4_FEATURES: [&str; 1] = ["meta_bg_resize"];

/// The size of a huge page that one PMD entry maps, `HPAGE_PMD_SIZE` of Linux.
const HPAGE_PMD_SIZE: usize = 2 << 20;

/// The path of the directory of the policy for transparent huge pages.
const THP_DIR: &str = "kernel/mm/transparent_hugepage";

/// The files of `/sys/kernel/mm/transparent_hugepage`, with their text.
fn thp_entries() -> Vec<(String, Kind)> {
    let file = |name: &str, text: String| (String::from(name), Kind::File(text.into_bytes()));
    Vec::from([
        file("defrag", rk_mm::tunables::show_thp_defrag()),
        file("enabled", rk_mm::tunables::show_thp_enabled()),
        file("hpage_pmd_size", format!("{HPAGE_PMD_SIZE}\n")),
        file("shmem_enabled", String::from("always within_size advise [never] deny force\n")),
        file("use_zero_page", String::from("1\n")),
    ])
}

/// Writes the file at `path`, if it is a file that takes a write. Gives `EACCES` for a file that
/// does not take a write, and `EINVAL` for a value that the file does not know.
fn write_file(path: &str, text: &[u8]) -> Result<()> {
    let set = match path.strip_prefix(THP_DIR) {
        Some("/enabled") => rk_mm::tunables::set_thp_enabled,
        Some("/defrag") => rk_mm::tunables::set_thp_defrag,
        _ => return Err(Errno::EACCES),
    };
    set(text).ok_or(Errno::EINVAL)
}

/// Tells if the file at `path` takes a write.
fn writable(path: &str) -> bool {
    path.strip_prefix(THP_DIR).is_some_and(|f| f == "/enabled" || f == "/defrag")
        || uevent_device(path).is_some()
        || bus::is_uevent(path)
}

/// The class and the name of the device of the file `uevent` at `path`.
fn uevent_device(path: &str) -> Option<(&str, &str)> {
    match path.split('/').collect::<Vec<_>>()[..] {
        ["devices", "virtual", class, name, "uevent"] => Some((class, name)),
        _ => None,
    }
}

/// Sends the event that a process writes to the file `uevent` of a device at `path`, as
/// `uevent_store` of Linux. `ns` is the network namespace of the mount. The event of a network
/// device goes to the sockets of its namespace, and the event of another device goes to all
/// namespaces. Gives `EINVAL` for a bad text and `ENODEV` when the device is gone.
fn write_uevent(path: &str, ns: &Weak<NetNs>, text: &[u8]) -> Result<()> {
    let (class, name) = uevent_device(path).ok_or(Errno::EACCES)?;
    let (action, vars) = rk_vfs::uevent::parse_synth(text)?;
    if class == NET {
        let ns = ns.upgrade().ok_or(Errno::ENODEV)?;
        let _in = rk_net::ns::enter(&ns);
        let d = rk_net::dev::devices().into_iter().find(|d| d.name() == name);
        rk_net::netlink::uevent::synth(&*d.ok_or(Errno::ENODEV)?, action, vars);
    } else if class == INPUT {
        rk_vfs::input::synth(name, action, vars)?;
    } else {
        let d = devices().into_iter().find(|d| d.class == class && node_name(d) == name);
        rk_vfs::uevent::synth_device(&d.ok_or(Errno::ENODEV)?, action, vars);
    }
    Ok(())
}

/// The block size that `stat` gives for a sysfs file, as Linux gives.
const BLOCK_SIZE: u32 = 4096;

/// Makes the root of a mount of sysfs. sysfs takes no options, so `args` has no effect. The
/// mount keeps the network namespace of the caller, as `sysfs_get_tree` of Linux. It does not
/// keep the namespace alive, as the passive reference of Linux.
fn mount(_args: &MountArgs<'_>) -> Result<InodeRef> {
    Ok(Arc::new(Node {
        path: String::new(),
        kind: Kind::Dir,
        net: Arc::downgrade(&rk_net::ns::current()),
    }))
}

/// The kind of an entry of sysfs, with its contents.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    Dir,
    File(Vec<u8>),
    Link(Vec<u8>),
    /// A file of KSM or of the pool of hugetlbfs. A read gives the value of that moment.
    /// `writable` tells that a write can change it.
    Mm {
        writable: bool,
    },
}

/// An inode of sysfs. `path` is the path from the root, without a `/` at the start. `net` is
/// the network namespace of the mount.
struct Node {
    path: String,
    kind: Kind,
    net: Weak<NetNs>,
}

/// The device of sysfs in the network namespace with the ID `net`. The mounts of one namespace
/// show the same files, so they have one device, as the super block of Linux for each namespace
/// tag. The mounts of two namespaces have two devices, so a mount on another mount of sysfs
/// works in a new namespace.
fn dev(net: u32) -> u64 {
    static DEV: Once<u64> = Once::new();
    /// The devices of the namespaces other than the first one, by the ID of the namespace.
    static OTHERS: rk_frame::sync::SpinLock<Vec<(u32, u64)>> =
        rk_frame::sync::SpinLock::new(Vec::new());
    if net == 0 {
        return *DEV.call_once(rk_vfs::anon_dev);
    }
    let mut others = OTHERS.lock();
    // The device of a namespace that stopped can go to a new namespace with another ID.
    others.retain(|&(id, _)| rk_net::ns::by_id(id).is_some() || id == net);
    if let Some(&(_, d)) = others.iter().find(|&&(id, _)| id == net) {
        return d;
    }
    let d = rk_vfs::anon_dev();
    others.push((net, d));
    d
}

/// The inode number of the entry at `path`. The number is a hash of the path, so an entry keeps
/// its number when a lookup makes it again.
fn ino(path: &str) -> u64 {
    if path.is_empty() {
        return 1;
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in path.as_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    // Keep the numbers positive in a signed 64 bit value, and away from 1.
    (h >> 1) | 2
}

/// The path of the parent of `path`.
fn parent(path: &str) -> &str {
    path.rfind('/').map_or("", |i| &path[..i])
}

/// The name of a device number in `/sys/dev`: `MAJ:MIN`.
fn numbers(d: &DeviceInfo) -> String {
    format!("{}:{}", major(d.rdev), minor(d.rdev))
}

/// The class of the network interfaces.
const NET: &str = "net";

/// The names of the states of `operstate`, by `IF_OPER_*`, as `operstates` of Linux.
const OPERSTATES: [&str; 7] =
    ["unknown", "notpresent", "down", "lowerlayerdown", "testing", "dormant", "up"];

/// The files of the directory `statistics` of an interface, as `netstat_attrs` of Linux. The
/// device layer does not keep the counters that are not in `Stats`, so they are 0.
fn net_statistics(d: &NetDevice) -> Vec<(String, Kind)> {
    let s = d.stats();
    let values = [
        ("collisions", 0),
        ("multicast", 0),
        ("rx_bytes", s.rx_bytes),
        ("rx_compressed", 0),
        ("rx_crc_errors", 0),
        ("rx_dropped", s.rx_dropped),
        ("rx_errors", s.rx_errors),
        ("rx_fifo_errors", 0),
        ("rx_frame_errors", 0),
        ("rx_length_errors", 0),
        ("rx_missed_errors", 0),
        ("rx_nohandler", 0),
        ("rx_over_errors", 0),
        ("rx_packets", s.rx_packets),
        ("tx_aborted_errors", 0),
        ("tx_bytes", s.tx_bytes),
        ("tx_carrier_errors", 0),
        ("tx_compressed", 0),
        ("tx_dropped", s.tx_dropped),
        ("tx_errors", s.tx_errors),
        ("tx_fifo_errors", 0),
        ("tx_heartbeat_errors", 0),
        ("tx_packets", s.tx_packets),
        ("tx_window_errors", 0),
    ];
    values
        .iter()
        .map(|(n, v)| (String::from(*n), Kind::File(format!("{v}\n").into_bytes())))
        .collect()
}

/// The files and links in the directory of the network interface `d`, as `net_class_attrs` of
/// Linux. `flags` has the flags of the device without the flags of the state of the link, as
/// `dev->flags`. `carrier` is there only when the interface is up, because Linux gives
/// `EINVAL` for a read of it on an interface that is down.
fn net_entries(d: &NetDevice) -> Vec<(String, Kind)> {
    let file = |name: &str, text: String| (String::from(name), Kind::File(text.into_bytes()));
    let flags = d.flags() & !(IFF_RUNNING | IFF_LOWER_UP | IFF_DORMANT);
    let index = d.ifindex();
    // The index of the other end of a veth pair, as `dev_get_iflink` and `veth_get_iflink` of
    // Linux. Another device gives its own index.
    let iflink = d.peer().map_or(index, |p| p.ifindex());
    let mut out = Vec::from([
        file("addr_assign_type", format!("{}\n", d.addr_assign_type())),
        file("addr_len", format!("{}\n", d.mac().0.len())),
        file("address", format!("{}\n", d.mac())),
        file("broadcast", format!("{}\n", d.broadcast())),
    ]);
    if d.is_up() {
        out.push(file("carrier", format!("{}\n", u8::from(d.carrier()))));
    }
    out.extend([file("dev_id", String::from("0x0\n")), file("dev_port", String::from("0\n"))]);
    let path = placed::net_path(d);
    out.extend(placed::device_link(&path));
    out.extend([
        file("dormant", String::from("0\n")),
        file("flags", format!("{flags:#x}\n")),
        file("ifindex", format!("{index}\n")),
        file("iflink", format!("{iflink}\n")),
        file("mtu", format!("{}\n", d.mtu())),
        file("name_assign_type", format!("{}\n", d.name_assign_type())),
        file("operstate", format!("{}\n", OPERSTATES[usize::from(d.operstate()).min(6)])),
        (String::from("statistics"), Kind::Dir),
        (
            String::from("subsystem"),
            Kind::Link(format!("{}class/net", placed::up(&path)).into_bytes()),
        ),
        file("tx_queue_len", format!("{}\n", d.txqlen())),
        file("type", format!("{}\n", d.kind().arphrd())),
        file("uevent", format!("INTERFACE={}\nIFINDEX={index}\n", d.name())),
    ]);
    out
}

/// The name of the device `d` in sysfs: the last part of its path in `/dev`, as `tun` for
/// `net/tun`.
fn node_name(d: &DeviceInfo) -> &str {
    d.name.rsplit('/').next().unwrap_or(&d.name)
}

/// The files and links in the directory of the device `d`.
fn device_entries(d: &DeviceInfo) -> Vec<(String, Kind)> {
    let mut uevent =
        format!("MAJOR={}\nMINOR={}\nDEVNAME={}\n", major(d.rdev), minor(d.rdev), d.name);
    if d.block {
        uevent.push_str("DEVTYPE=disk\n");
    }
    let path = rk_vfs::uevent::devpath(d);
    let mut out = Vec::new();
    out.push((String::from("dev"), Kind::File(format!("{}\n", numbers(d)).into_bytes())));
    out.extend(placed::device_link(&path));
    if d.block {
        let size = block_sectors(d.rdev).unwrap_or(0);
        let ro = block_queue(d.rdev).is_some_and(|q| q.read_only());
        let inflight = format!("{:>8} {:>8}\n", 0, 0);
        out.push((String::from("inflight"), Kind::File(inflight.into_bytes())));
        if rk_vfs::loopdev::sysfs_files(d.rdev).is_some() {
            out.push((String::from("loop"), Kind::Dir));
        }
        out.push((String::from("queue"), Kind::Dir));
        out.push((String::from("removable"), Kind::File(b"0\n".to_vec())));
        out.push((String::from("ro"), Kind::File(format!("{}\n", u8::from(ro)).into_bytes())));
        out.push((String::from("size"), Kind::File(format!("{size}\n").into_bytes())));
        let fields = block_queue(d.rdev).map_or([0; 17], |q| q.stats().fields());
        let stat: Vec<String> = fields.iter().map(|v| format!("{v:>8}")).collect();
        let stat = format!("{}\n", stat.join(" "));
        out.push((String::from("stat"), Kind::File(stat.into_bytes())));
    }
    let subsystem = format!("{}class/{}", placed::up(&path), d.class);
    out.push((String::from("subsystem"), Kind::Link(subsystem.into_bytes())));
    out.push((String::from("uevent"), Kind::File(uevent.into_bytes())));
    // The attributes of the class, as `tpm_version_major` of a TPM.
    if let Some(attrs) = rk_vfs::device::class_attrs(d, &[]) {
        out.extend(input_entries(attrs));
        out.sort_by(|a, b| a.0.cmp(&b.0));
    }
    out
}

/// The files of the directory `queue` of the block device `d`, as block/blk-sysfs.c of Linux.
/// The sizes of a block are those of the queue: sectors of 512 bytes. The memory of a direct I/O
/// must be aligned to 512 bytes, the default `dma_alignment` of Linux.
fn queue_entries(d: &DeviceInfo) -> Vec<(String, Kind)> {
    let file = |name: &str, text: String| (String::from(name), Kind::File(text.into_bytes()));
    let ra_pages = block_queue(d.rdev).map_or(rk_vfs::blockdev::READAHEAD_PAGES, |q| q.ra_pages());
    let sector = rk_vfs::blockdev::SECTOR_SIZE;
    alloc::vec![
        file("dma_alignment", format!("{}\n", sector - 1)),
        file("hw_sector_size", format!("{sector}\n")),
        file("logical_block_size", format!("{sector}\n")),
        file("minimum_io_size", format!("{sector}\n")),
        file("optimal_io_size", String::from("0\n")),
        file("physical_block_size", format!("{sector}\n")),
        file("read_ahead_kb", format!("{}\n", ra_pages * 4)),
        file("rotational", String::from("0\n")),
    ]
}

/// The class of the input devices. Their directories come from `rk_vfs::input`.
const INPUT: &str = "input";

/// The class of the DMI device, which has the fields of the SMBIOS tables.
const DMI: &str = "dmi";

/// The entries of a directory of the input devices, or of the attributes of a class.
fn input_entries(list: Vec<(String, rk_vfs::input::SysEntry)>) -> Vec<(String, Kind)> {
    use rk_vfs::input::SysEntry;
    list.into_iter()
        .map(|(name, e)| {
            let kind = match e {
                SysEntry::Dir => Kind::Dir,
                SysEntry::File(text) => Kind::File(text),
                SysEntry::Link(to) => Kind::Link(to),
            };
            (name, kind)
        })
        .collect()
}

/// The device of `list` with the directory `/sys/devices/virtual/CLASS/NAME`.
fn virtual_device<'a>(list: &'a [DeviceInfo], class: &str, name: &str) -> Option<&'a DeviceInfo> {
    let found = list.iter().find(|d| d.class == class && node_name(d) == name)?;
    placed::is_virtual(&rk_vfs::uevent::devpath(found)).then_some(found)
}

/// The entries of the directory at `path`, from the list of devices `list`. Gives `None` if no
/// directory has the path.
///
/// The interfaces are the ones of the namespace `ns`. A namespace that stopped has none.
fn entries(path: &str, list: &[DeviceInfo], ns: &Weak<NetNs>) -> Option<Vec<(String, Kind)>> {
    let mut classes: BTreeSet<&str> = list.iter().map(|d| d.class).collect();
    classes.insert(NET);
    classes.insert(INPUT);
    let smbios = rk_frame::firmware::smbios();
    if smbios.is_some() {
        classes.insert(DMI);
    }
    let fdt = rk_frame::firmware::device_tree();
    let net = placed::net_devices(ns);
    // The interfaces in `/sys/devices/virtual/net`.
    let net_dev = |name: &str| {
        net.iter().find(|d| d.name() == name && placed::is_virtual(&placed::net_path(d))).cloned()
    };
    let parts: Vec<&str> = if path.is_empty() { Vec::new() } else { path.split('/').collect() };
    let dirs = |names: &mut dyn Iterator<Item = &str>| -> Vec<(String, Kind)> {
        names.map(|n| (String::from(n), Kind::Dir)).collect()
    };
    let to_device = |up: &str, d: &DeviceInfo| {
        let path = rk_vfs::uevent::devpath(d);
        Kind::Link(format!("{up}{}", path.trim_start_matches('/')).into_bytes())
    };
    let out = match parts[..] {
        [] => dirs(&mut TOP.iter().copied()),
        ["block"] => list
            .iter()
            .filter(|d| d.block)
            .map(|d| (String::from(node_name(d)), to_device("../", d)))
            .collect(),
        ["class"] | ["devices", "virtual"] => dirs(&mut classes.iter().copied()),
        ["class", NET] => net
            .iter()
            .map(|d| {
                let to = format!("../..{}", placed::net_path(d));
                (d.name(), Kind::Link(to.into_bytes()))
            })
            .collect(),
        ["class", INPUT] => input_entries(rk_vfs::input::sysfs_class()),
        // The DMI device of drivers/firmware/dmi-id.c, from the SMBIOS tables.
        ["class", DMI] if smbios.is_some() => {
            Vec::from([(String::from("id"), Kind::Link(b"../../devices/virtual/dmi/id".to_vec()))])
        }
        ["devices", "virtual", DMI] if smbios.is_some() => dirs(&mut ["id"].into_iter()),
        ["devices", "virtual", DMI, "id", ref rest @ ..] => {
            let s = smbios?;
            firmware::dmi_entries(s.entry, s.table, rest)?
        }
        ["firmware"] => {
            let mut out = Vec::new();
            if fdt.is_some() {
                out.push((String::from("devicetree"), Kind::Dir));
            }
            if smbios.is_some() {
                out.push((String::from("dmi"), Kind::Dir));
            }
            if let Some(blob) = fdt {
                out.push((String::from("fdt"), Kind::File(blob.to_vec())));
            }
            out
        }
        ["firmware", "dmi"] if smbios.is_some() => dirs(&mut ["tables"].into_iter()),
        ["firmware", "dmi", "tables"] => {
            let s = smbios?;
            Vec::from([
                (String::from("DMI"), Kind::File(s.table.to_vec())),
                (String::from("smbios_entry_point"), Kind::File(s.entry.to_vec())),
            ])
        }
        ["firmware", "devicetree"] if fdt.is_some() => dirs(&mut ["base"].into_iter()),
        ["firmware", "devicetree", "base", ref rest @ ..] => firmware::fdt_entries(fdt?, rest)?,
        ["devices", "virtual", INPUT, ref rest @ ..] => input_entries(rk_vfs::input::sysfs(rest)?),
        ["devices", "virtual", NET] => {
            let here = net.iter().filter(|d| placed::is_virtual(&placed::net_path(d)));
            here.map(|d| (d.name(), Kind::Dir)).collect()
        }
        ["devices", "virtual", NET, name] => net_entries(&*net_dev(name)?),
        ["devices", "virtual", NET, name, "statistics"] => net_statistics(&*net_dev(name)?),
        ["class", class] => list
            .iter()
            .filter(|d| d.class == class)
            .map(|d| (String::from(node_name(d)), to_device("../../", d)))
            .collect(),
        ["dev"] => dirs(&mut ["block", "char"].into_iter()),
        ["dev", kind @ ("block" | "char")] => list
            .iter()
            .filter(|d| d.block == (kind == "block"))
            .map(|d| (numbers(d), to_device("../../", d)))
            .collect(),
        ["devices"] => {
            let mut names = bus::devices_top();
            names.extend(["system", "virtual"]);
            names.sort_unstable();
            dirs(&mut names.into_iter())
        }
        ["devices", top, ..] if bus::devices_top().iter().any(|t| *t == top) => {
            let below = placed::all(list, &net);
            if let Some(out) = placed::entries(path, &below) {
                return Some(out);
            }
            let mut out = bus::devices_entries(&parts[1..])?;
            out.extend(placed::classes(path, &below));
            out
        }
        ["bus", ref rest @ ..] => bus::bus_entries(rest)?,
        ["module", ref rest @ ..] => bus::module_entries(rest)?,
        ["devices", "system", ref rest @ ..] => cpu::entries(rk_frame::cpu::count(), rest)?,
        ["devices", "virtual", class] if classes.contains(class) => list
            .iter()
            .filter(|d| d.class == class && placed::is_virtual(&rk_vfs::uevent::devpath(d)))
            .map(|d| (String::from(node_name(d)), Kind::Dir))
            .collect(),
        ["devices", "virtual", class, name] => device_entries(virtual_device(list, class, name)?),
        ["devices", "virtual", class, name, "queue"] => {
            queue_entries(virtual_device(list, class, name).filter(|d| d.block)?)
        }
        ["devices", "virtual", class, name, "loop"] => {
            let d = virtual_device(list, class, name).filter(|d| d.block)?;
            let files = rk_vfs::loopdev::sysfs_files(d.rdev)?;
            files
                .into_iter()
                .map(|(n, text)| (String::from(n), Kind::File(text.into_bytes())))
                .collect()
        }
        // A directory of the attributes of the class, as `pcr-sha256` of a TPM.
        ["devices", "virtual", class, name, ref rest @ ..] => {
            input_entries(rk_vfs::device::class_attrs(virtual_device(list, class, name)?, rest)?)
        }
        // `/sys/fs/cgroup` is the place where the init system mounts cgroup2, and `/sys/fs/bpf`
        // is the place for bpffs.
        // `/sys/fs/fuse/connections` is the place of fusectl.
        ["fs"] => dirs(&mut ["bpf", "cgroup", "ext4", "fuse"].into_iter()),
        ["fs", "bpf"] | ["fs", "cgroup"] | ["fs", "fuse", "connections"] => Vec::new(),
        ["fs", "fuse"] => dirs(&mut ["connections"].into_iter()),
        ["fs", "ext4"] => dirs(&mut ["features"].into_iter()),
        ["fs", "ext4", "features"] => EXT4_FEATURES
            .iter()
            .map(|&n| (String::from(n), Kind::File(b"supported\n".to_vec())))
            .collect(),
        ["kernel"] => {
            let mut out = dirs(&mut ["config", "debug", "mm", "security", "tracing"].into_iter());
            let seqnum = format!("{}\n", rk_vfs::uevent::seqnum());
            out.push((String::from("uevent_seqnum"), Kind::File(seqnum.into_bytes())));
            out
        }
        // The mount points of securityfs, configfs, debugfs and tracefs, as
        // `sysfs_create_mount_point` of Linux makes them.
        ["kernel", "security" | "config" | "debug" | "tracing"] => Vec::new(),
        ["kernel", "mm", "transparent_hugepage"] => thp_entries(),
        ["kernel", "mm", ref rest @ ..] => mm::entries(rest)?,
        [top] if TOP.contains(&top) => Vec::new(),
        _ => return None,
    };
    Some(out)
}

impl Node {
    /// The entries of this directory, from the list of devices of this moment.
    fn children(&self) -> Result<Vec<(String, Kind)>> {
        match self.kind {
            Kind::Dir => entries(&self.path, &devices(), &self.net).ok_or(Errno::ENOENT),
            _ => Err(Errno::ENOTDIR),
        }
    }

    /// The path of the entry `name` of this directory.
    fn child_path(&self, name: &str) -> String {
        if self.path.is_empty() { String::from(name) } else { format!("{}/{name}", self.path) }
    }

    /// A directory of sysfs does not take new names, and a file is not a directory.
    fn no_change<T>(&self) -> Result<T> {
        Err(if self.kind == Kind::Dir { Errno::EPERM } else { Errno::ENOTDIR })
    }
}

impl Inode for Node {
    fn metadata(&self) -> Metadata {
        let (kind, perm, nlink, size) = match &self.kind {
            Kind::Dir => (mode::S_IFDIR, 0o755, 2, 0),
            Kind::File(_) if writable(&self.path) || placed::is_uevent(&self.path, &self.net) => {
                (mode::S_IFREG, 0o644, 1, BLOCK_SIZE as u64)
            }
            // The binary files of the firmware have their size, as the `bin_attribute` of Linux.
            Kind::File(text) if self.path.starts_with("firmware/") => {
                let perm = if firmware::private(&self.path) { 0o400 } else { 0o444 };
                (mode::S_IFREG, perm, 1, text.len() as u64)
            }
            Kind::File(_) if firmware::private(&self.path) => {
                (mode::S_IFREG, 0o400, 1, BLOCK_SIZE as u64)
            }
            Kind::File(_) | Kind::Mm { writable: false } => {
                (mode::S_IFREG, 0o444, 1, BLOCK_SIZE as u64)
            }
            Kind::Mm { writable: true } => (mode::S_IFREG, 0o644, 1, BLOCK_SIZE as u64),
            Kind::Link(target) => (mode::S_IFLNK, 0o777, 1, target.len() as u64),
        };
        let t = now();
        let net = self.net.upgrade().map_or(u32::MAX, |n| n.id());
        Metadata {
            dev: dev(net),
            ino: ino(&self.path),
            mode: kind | perm,
            nlink,
            size,
            blksize: BLOCK_SIZE,
            atime: t,
            mtime: t,
            ctime: t,
            ..Metadata::default()
        }
    }

    fn set_attr(&self, attr: &SetAttr) -> Result<()> {
        if attr.mode.is_some() || attr.uid.is_some() || attr.gid.is_some() {
            return Err(Errno::EPERM);
        }
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let live;
        let text = match &self.kind {
            Kind::File(text) => text,
            Kind::Mm { .. } => {
                live = mm::read(&self.path);
                &live
            }
            Kind::Dir => return Err(Errno::EISDIR),
            Kind::Link(_) => return Err(Errno::EINVAL),
        };
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(text.len());
        let n = buf.len().min(text.len() - start);
        buf[..n].copy_from_slice(&text[start..start + n]);
        Ok(n)
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize> {
        match self.kind {
            Kind::Mm { writable: true } => mm::write(&self.path, buf),
            Kind::File(_) if uevent_device(&self.path).is_some() => {
                write_uevent(&self.path, &self.net, buf).map(|()| buf.len())
            }
            Kind::File(_) if placed::is_uevent(&self.path, &self.net) => {
                placed::write_uevent(&self.path, &self.net, buf).map(|()| buf.len())
            }
            Kind::File(_) if bus::is_uevent(&self.path) => {
                bus::write_uevent(&self.path, buf).map(|()| buf.len())
            }
            Kind::File(_) => write_file(&self.path, buf).map(|()| buf.len()),
            Kind::Mm { .. } => Err(Errno::EACCES),
            _ => Err(Errno::EINVAL),
        }
    }

    fn lookup(&self, name: &[u8]) -> Result<InodeRef> {
        let name = core::str::from_utf8(name).map_err(|_| Errno::ENOENT)?;
        let (name, kind) =
            self.children()?.into_iter().find(|(n, _)| n == name).ok_or(Errno::ENOENT)?;
        Ok(Arc::new(Node { path: self.child_path(&name), kind, net: self.net.clone() }))
    }

    fn create(&self, _: &[u8], _: FileType, _: u32, _: u64) -> Result<InodeRef> {
        self.no_change()
    }

    fn symlink(&self, _: &[u8], _: &[u8]) -> Result<InodeRef> {
        self.no_change()
    }

    fn link(&self, _: &[u8], _: &InodeRef) -> Result<()> {
        self.no_change()
    }

    fn unlink(&self, _: &[u8]) -> Result<()> {
        self.no_change()
    }

    fn rmdir(&self, _: &[u8]) -> Result<()> {
        self.no_change()
    }

    fn rename(&self, _: &[u8], _: &InodeRef, _: &[u8]) -> Result<()> {
        self.no_change()
    }

    fn read_link(&self) -> Result<Vec<u8>> {
        match &self.kind {
            Kind::Link(target) => Ok(target.clone()),
            _ => Err(Errno::EINVAL),
        }
    }

    fn read_dir(&self, pos: u64) -> Result<Option<(DirEntry, u64)>> {
        let children = self.children()?;
        let entry = match pos {
            0 => DirEntry { ino: ino(&self.path), kind: FileType::Directory, name: b".".to_vec() },
            1 => DirEntry {
                ino: ino(parent(&self.path)),
                kind: FileType::Directory,
                name: b"..".to_vec(),
            },
            _ => {
                let Some((name, kind)) = children.into_iter().nth((pos - 2) as usize) else {
                    return Ok(None);
                };
                let kind = match kind {
                    Kind::Dir => FileType::Directory,
                    Kind::File(_) | Kind::Mm { .. } => FileType::Regular,
                    Kind::Link(_) => FileType::Symlink,
                };
                DirEntry { ino: ino(&self.child_path(&name)), kind, name: name.into_bytes() }
            }
        };
        Ok(Some((entry, pos + 1)))
    }

    fn fs_magic(&self) -> u64 {
        SYSFS_MAGIC
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rk_vfs::device::makedev;

    fn list() -> Vec<DeviceInfo> {
        let info = |name: &str, class, rdev, block| DeviceInfo {
            name: String::from(name),
            class,
            rdev,
            block,
            perm: 0o660,
        };
        alloc::vec![
            info("null", "mem", makedev(1, 3), false),
            info("vda", "block", makedev(254, 0), true),
            info("ttyS0", "tty", makedev(4, 64), false),
        ]
    }

    fn init() -> Weak<NetNs> {
        Arc::downgrade(&rk_net::ns::init_ns())
    }

    fn names(path: &str) -> Vec<String> {
        entries(path, &list(), &init()).unwrap().into_iter().map(|(n, _)| n).collect()
    }

    fn get(path: &str) -> Kind {
        let (dir, name) = path.rsplit_once('/').unwrap();
        entries(dir, &list(), &init()).unwrap().into_iter().find(|(n, _)| n == name).unwrap().1
    }

    #[test]
    fn an_interface_has_the_files_of_linux() {
        rk_net::dev::init();
        assert_eq!(get("class/net/lo"), Kind::Link(b"../../devices/virtual/net/lo".to_vec()));
        assert!(names("devices/virtual").contains(&String::from("net")));
        let lo = "devices/virtual/net/lo";
        assert_eq!(get(&format!("{lo}/mtu")), Kind::File(b"65536\n".to_vec()));
        assert_eq!(get(&format!("{lo}/type")), Kind::File(b"772\n".to_vec()));
        assert_eq!(get(&format!("{lo}/name_assign_type")), Kind::File(b"2\n".to_vec()));
        assert_eq!(get(&format!("{lo}/address")), Kind::File(b"00:00:00:00:00:00\n".to_vec()));
        assert!(names(&format!("{lo}/statistics")).contains(&String::from("rx_bytes")));
    }

    #[test]
    fn the_iflink_of_a_veth_end_is_the_index_of_the_other_end() {
        rk_net::dev::init();
        let (a, b) = rk_net::veth::create(Some(b"sva"), Some(b"svb"), None, [None; 2]).unwrap();
        let iflink = |name: &str| get(&format!("devices/virtual/net/{name}/iflink"));
        assert_eq!(iflink("sva"), Kind::File(format!("{}\n", b.ifindex()).into_bytes()));
        assert_eq!(iflink("svb"), Kind::File(format!("{}\n", a.ifindex()).into_bytes()));
        assert_eq!(iflink("lo"), Kind::File(b"1\n".to_vec()));
        assert!(names("class/net").contains(&String::from("sva")));
        rk_net::dev::unregister(&a);
        assert!(!names("class/net").contains(&String::from("svb")));
    }

    #[test]
    fn addr_assign_type_tells_how_the_device_got_its_address() {
        rk_net::dev::init();
        let mac = rk_net::ether::MacAddr([0x02, 0, 0, 0, 0, 0x28]);
        let (a, _) =
            rk_net::veth::create(Some(b"sha"), Some(b"shb"), None, [None, Some(mac)]).unwrap();
        let assign = |name: &str| get(&format!("devices/virtual/net/{name}/addr_assign_type"));
        // A random address gives 1, a set address gives 3, and a permanent address gives 0, as
        // `NET_ADDR_*` of Linux.
        assert_eq!(assign("sha"), Kind::File(b"1\n".to_vec()));
        assert_eq!(assign("shb"), Kind::File(b"3\n".to_vec()));
        assert_eq!(assign("lo"), Kind::File(b"0\n".to_vec()));
        a.set_mac(rk_net::consts::ARPHRD_ETHER, mac).unwrap();
        assert_eq!(assign("sha"), Kind::File(b"3\n".to_vec()));
        rk_net::dev::unregister(&a);
    }

    #[test]
    fn the_top_has_the_directories_of_linux() {
        assert_eq!(names(""), TOP);
        assert_eq!(names("class"), ["block", "input", "mem", "net", "tty"]);
        assert_eq!(names("devices/virtual"), ["block", "input", "mem", "net", "tty"]);
        assert_eq!(names("bus"), ["pci", "platform", "virtio"]);
        assert!(names("power").is_empty());
        assert!(entries("nothing", &list(), &init()).is_none());
        assert!(entries("devices/virtual/disk", &list(), &init()).is_none());
    }

    #[test]
    fn the_links_point_to_the_directory_of_the_device() {
        assert_eq!(names("block"), ["vda"]);
        assert_eq!(get("block/vda"), Kind::Link(b"../devices/virtual/block/vda".to_vec()));
        assert_eq!(get("class/mem/null"), Kind::Link(b"../../devices/virtual/mem/null".to_vec()));
        assert_eq!(names("dev/char"), ["1:3", "4:64"]);
        assert_eq!(get("dev/block/254:0"), Kind::Link(b"../../devices/virtual/block/vda".to_vec()));
    }

    #[test]
    fn a_device_has_its_numbers_and_its_uevent() {
        assert_eq!(names("devices/virtual/tty/ttyS0"), ["dev", "subsystem", "uevent"]);
        assert_eq!(get("devices/virtual/tty/ttyS0/dev"), Kind::File(b"4:64\n".to_vec()));
        assert_eq!(
            get("devices/virtual/block/vda/uevent"),
            Kind::File(b"MAJOR=254\nMINOR=0\nDEVNAME=vda\nDEVTYPE=disk\n".to_vec())
        );
        assert_eq!(
            names("devices/virtual/block/vda"),
            ["dev", "inflight", "queue", "removable", "ro", "size", "stat", "subsystem", "uevent"]
        );
        assert_eq!(
            get("devices/virtual/block/vda/queue/logical_block_size"),
            Kind::File(b"512\n".to_vec())
        );
        assert_eq!(
            get("devices/virtual/block/vda/queue/dma_alignment"),
            Kind::File(b"511\n".to_vec())
        );
        assert_eq!(
            get("devices/virtual/mem/null/subsystem"),
            Kind::Link(b"../../../../class/mem".to_vec())
        );
    }

    #[test]
    fn a_class_gives_its_attributes() {
        use rk_vfs::input::SysEntry;
        fn attrs(d: &DeviceInfo, rest: &[&str]) -> Option<Vec<(String, SysEntry)>> {
            let file = |name: &str, text: String| (String::from(name), SysEntry::File(text.into()));
            match rest {
                [] => Some(alloc::vec![
                    file("version", format!("{}\n", rk_vfs::device::minor(d.rdev))),
                    (String::from("banks"), SysEntry::Dir),
                ]),
                ["banks"] => Some(alloc::vec![file("0", String::from("00\n"))]),
                _ => None,
            }
        }
        rk_vfs::device::set_class_attrs("attrs", attrs);
        let mut list = list();
        list.push(DeviceInfo {
            name: String::from("thing0"),
            class: "attrs",
            rdev: makedev(10, 7),
            block: false,
            perm: 0o600,
        });
        let at = |path: &str| entries(path, &list, &init());
        let names =
            |path: &str| -> Vec<String> { at(path).unwrap().into_iter().map(|(n, _)| n).collect() };
        let dir = "devices/virtual/attrs/thing0";
        assert_eq!(names(dir), ["banks", "dev", "subsystem", "uevent", "version"]);
        let version = at(dir).unwrap().into_iter().find(|(n, _)| n == "version").unwrap().1;
        assert_eq!(version, Kind::File(b"7\n".to_vec()));
        assert_eq!(
            at(&format!("{dir}/banks")).unwrap(),
            [(String::from("0"), Kind::File(b"00\n".to_vec()))]
        );
        assert!(at(&format!("{dir}/nothing")).is_none());
        // The other classes have no more files.
        assert_eq!(names("devices/virtual/tty/ttyS0"), ["dev", "subsystem", "uevent"]);
    }

    #[test]
    fn only_the_uevent_file_of_a_device_takes_an_event() {
        assert!(writable("devices/virtual/mem/null/uevent"));
        assert!(writable("devices/virtual/net/lo/uevent"));
        assert!(!writable("devices/virtual/mem/null/dev"));
        assert!(!writable("devices/system/cpu/cpu0/uevent"));
        assert_eq!(
            write_uevent("devices/virtual/mem/null/dev", &init(), b"add"),
            Err(Errno::EACCES)
        );
        assert_eq!(
            write_uevent("devices/virtual/mem/zz/uevent", &init(), b"add"),
            Err(Errno::ENODEV)
        );
        assert_eq!(
            write_uevent("devices/virtual/mem/null/uevent", &init(), b"go"),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn a_disk_of_a_virtio_device_is_in_its_directory() {
        use rk_vfs::bus::{PciFunction, Transport, VirtioDevice};
        rk_vfs::bus::add_pci(PciFunction {
            bus: 0,
            slot: 5,
            function: 0,
            vendor: 0x1af4,
            device: 0x1001,
            class: 0x01_0000,
            revision: 0,
            subsystem_vendor: 0x1af4,
            subsystem_device: 2,
            irq: 10,
            driver: Some("virtio-pci"),
        });
        rk_vfs::bus::add_virtio(VirtioDevice {
            index: 21,
            transport: Transport::Pci(0, 5, 0),
            device: 2,
            vendor: 0x1af4,
            driver: Some("virtio_blk"),
        });
        rk_vfs::bus::set_block_parent(makedev(254, 32), 21);
        let mut list = list();
        list.push(DeviceInfo {
            name: String::from("vdc"),
            class: "block",
            rdev: makedev(254, 32),
            block: true,
            perm: 0o660,
        });
        let ent = |path: &str| entries(path, &list, &init());
        let has = |path: &str, name: &str| ent(path).unwrap().iter().any(|(n, _)| n == name);
        let get = |path: &str, name: &str| {
            ent(path).unwrap().into_iter().find(|(n, _)| n == name).unwrap().1
        };
        let dir = "devices/pci0000:00/0000:00:05.0/virtio21";
        assert!(has(dir, "block"));
        assert!(has(dir, "modalias"));
        let names: Vec<String> =
            ent(&format!("{dir}/block")).unwrap().into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["vdc"]);
        let vdc = format!("{dir}/block/vdc");
        assert_eq!(get(&vdc, "device"), Kind::Link(b"../../../virtio21".to_vec()));
        assert_eq!(get(&vdc, "subsystem"), Kind::Link(b"../../../../../../class/block".to_vec()));
        assert_eq!(get(&vdc, "dev"), Kind::File(b"254:32\n".to_vec()));
        assert!(has(&format!("{vdc}/queue"), "logical_block_size"));
        assert_eq!(get("block", "vdc"), Kind::Link(format!("../{vdc}").into_bytes()));
        assert_eq!(get("dev/block", "254:32"), Kind::Link(format!("../../{vdc}").into_bytes()));
        assert!(!has("devices/virtual/block", "vdc"));
        assert!(has("devices/virtual/block", "vda"));
        assert_eq!(ent("devices/virtual/block/vdc"), None);
        assert_eq!(ent(&format!("{dir}/block/vdd")), None);
        assert!(!has("devices/virtual/block/vda", "device"));
    }

    #[test]
    fn only_a_loop_device_with_a_file_has_the_loop_directory() {
        assert!(!names("devices/virtual/block/vda").contains(&String::from("loop")));
        assert_eq!(entries("devices/virtual/block/vda/loop", &list(), &init()), None);
        assert_eq!(get("devices/virtual/block/vda/ro"), Kind::File(b"0\n".to_vec()));
    }

    #[test]
    fn ext4_tells_its_features() {
        assert_eq!(names("fs"), ["bpf", "cgroup", "ext4", "fuse"]);
        assert!(names("fs/fuse/connections").is_empty());
        assert!(names("fs/bpf").is_empty());
        assert!(names("fs/cgroup").is_empty());
        assert_eq!(names("fs/ext4/features"), ["meta_bg_resize"]);
        assert_eq!(get("fs/ext4/features/meta_bg_resize"), Kind::File(b"supported\n".to_vec()));
    }

    #[test]
    fn ksm_has_the_files_of_linux() {
        assert_eq!(
            names("kernel"),
            ["config", "debug", "mm", "security", "tracing", "uevent_seqnum"]
        );
        for d in ["security", "config", "debug", "tracing"] {
            assert!(names(&format!("kernel/{d}")).is_empty());
        }
        assert_eq!(names("kernel/mm"), ["hugepages", "ksm", "transparent_hugepage"]);
        let files = names("kernel/mm/ksm");
        for f in ["run", "pages_to_scan", "sleep_millisecs", "full_scans", "pages_shared"] {
            assert!(files.contains(&String::from(f)), "{f}");
        }
        assert_eq!(get("kernel/mm/ksm/run"), Kind::Mm { writable: true });
        assert_eq!(get("kernel/mm/ksm/pages_shared"), Kind::Mm { writable: false });
        let run = Node {
            path: String::from("kernel/mm/ksm/run"),
            kind: Kind::Mm { writable: true },
            net: init(),
        };
        assert_eq!(run.metadata().mode, mode::S_IFREG | 0o644);
        let mut buf = [0u8; 8];
        assert_eq!(run.read_at(0, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], b"0\n");
        assert_eq!(run.write_at(0, b"7").unwrap_err(), Errno::EINVAL);
        let shared = Node {
            path: String::from("kernel/mm/ksm/pages_shared"),
            kind: Kind::Mm { writable: false },
            net: init(),
        };
        assert_eq!(shared.write_at(0, b"1").unwrap_err(), Errno::EACCES);
    }

    #[test]
    fn the_pool_of_hugetlbfs_has_the_files_of_linux() {
        let dir = "kernel/mm/hugepages/hugepages-2048kB";
        assert_eq!(names("kernel/mm/hugepages"), ["hugepages-2048kB"]);
        assert!(names(dir).contains(&String::from("resv_hugepages")));
        assert_eq!(get(&format!("{dir}/nr_hugepages")), Kind::Mm { writable: true });
        let free = Node {
            path: format!("{dir}/free_hugepages"),
            kind: Kind::Mm { writable: false },
            net: init(),
        };
        let mut buf = [0u8; 8];
        assert_eq!(free.read_at(0, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], b"0\n");
        assert_eq!(free.write_at(0, b"1").unwrap_err(), Errno::EACCES);
    }

    #[test]
    fn the_policy_for_huge_pages_takes_a_write() {
        assert_eq!(
            get("kernel/mm/transparent_hugepage/hpage_pmd_size"),
            Kind::File(b"2097152\n".to_vec())
        );
        let enabled =
            Node { path: format!("{THP_DIR}/enabled"), kind: Kind::File(Vec::new()), net: init() };
        assert_eq!(enabled.metadata().mode, mode::S_IFREG | 0o644);
        assert_eq!(enabled.write_at(0, b"sometimes\n").unwrap_err(), Errno::EINVAL);
        assert_eq!(enabled.write_at(0, b"madvise\n").unwrap(), 8);
        assert_eq!(rk_mm::tunables::show_thp_enabled(), "always [madvise] never\n");
        enabled.write_at(0, b"always").unwrap();
    }

    #[test]
    fn a_node_reads_and_does_not_change() {
        let file =
            Node { path: String::from("a/b"), kind: Kind::File(b"hello\n".to_vec()), net: init() };
        let mut buf = [0u8; 4];
        assert_eq!(file.read_at(4, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], b"o\n");
        assert_eq!(file.write_at(0, b"x").unwrap_err(), Errno::EACCES);
        assert_eq!(file.metadata().mode, mode::S_IFREG | 0o444);
        assert_eq!(file.fs_magic(), SYSFS_MAGIC);
        let root = Node { path: String::new(), kind: Kind::Dir, net: init() };
        assert_eq!(root.metadata().ino, 1);
        assert_eq!(root.unlink(b"block").unwrap_err(), Errno::EPERM);
        assert_eq!(root.lookup(b"nothing").err(), Some(Errno::ENOENT));
        let block = root.lookup(b"block").unwrap();
        assert_eq!(block.metadata().ino, ino("block"));
        assert_eq!(block.read_dir(1).unwrap().unwrap().0.ino, 1);
        assert_eq!(parent("devices/virtual"), "devices");
    }
}

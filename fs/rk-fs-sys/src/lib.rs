//! sysfs: the files of `/sys`, which show the devices of the kernel.
//!
//! The tree comes from the list of devices in `rk_vfs::device`. Each lookup makes the entries
//! again, so a device that a driver adds after the mount shows at the next lookup. The layout
//! follows Linux, because udev, mdev and the C libraries read it:
//!
//! - `/sys/devices/virtual/CLASS/NAME` is the directory of a device. It has the files `dev` and
//!   `uevent`, and the link `subsystem`. A block device also has `size`, `ro`, `removable` and
//!   the directory `queue` with the limits of the queue.
//!   A loop device with a file also has the directory `loop`, which `losetup` reads.
//! - `/sys/class/CLASS/NAME` and `/sys/block/NAME` are links to the directory of the device.
//! - `/sys/dev/block/MAJ:MIN` and `/sys/dev/char/MAJ:MIN` are links to the same directory.
//! - `/sys/fs/cgroup` is an empty directory, where cgroup2 is mounted.
//! - `/sys/fs/ext4/features` has a file for each feature of ext4 that programs look for. The
//!   online resize of `resize2fs` reads `meta_bg_resize`.
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
//!
//! Linux puts a device of a bus below the directory of the bus. This kernel puts all devices in
//! `/sys/devices/virtual`. A program that follows the links does not see the difference.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod mm;

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::Once;
use rk_net::consts::{IFF_DORMANT, IFF_LOWER_UP, IFF_RUNNING};
use rk_net::dev::NetDevice;
use rk_vfs::blockdev::{block_queue, block_sectors};
use rk_vfs::device::{DeviceInfo, devices, major, minor};
use rk_vfs::fstype::{FsType, MountArgs};
use rk_vfs::inode::mode;
use rk_vfs::{DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, now};

/// The magic number of sysfs, `SYSFS_MAGIC` of `<linux/magic.h>`.
pub const SYSFS_MAGIC: u64 = 0x6265_6572;

/// The file system type of sysfs, for `mount -t sysfs`.
pub const FS_TYPE: FsType = FsType { name: "sysfs", nodev: true, make: mount };

/// The directories at the top of sysfs. Only `block`, `class`, `dev`, `devices`, `fs` and `kernel`
/// have entries.
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
}

/// The block size that `stat` gives for a sysfs file, as Linux gives.
const BLOCK_SIZE: u32 = 4096;

/// Makes the root of a mount of sysfs. sysfs takes no options, so `args` has no effect.
fn mount(_args: &MountArgs<'_>) -> Result<InodeRef> {
    Ok(Arc::new(Node { path: String::new(), kind: Kind::Dir }))
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

/// An inode of sysfs. `path` is the path from the root, without a `/` at the start.
struct Node {
    path: String,
    kind: Kind,
}

/// The device of sysfs. Each mount of sysfs shows the same files, so they have one device.
fn dev() -> u64 {
    static DEV: Once<u64> = Once::new();
    *DEV.call_once(rk_vfs::anon_dev)
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
    let mut out = Vec::from([
        file("addr_assign_type", String::from("0\n")),
        file("addr_len", format!("{}\n", d.mac().0.len())),
        file("address", format!("{}\n", d.mac())),
        file("broadcast", format!("{}\n", d.broadcast())),
    ]);
    if d.is_up() {
        out.push(file("carrier", format!("{}\n", u8::from(d.carrier()))));
    }
    out.extend([
        file("dev_id", String::from("0x0\n")),
        file("dev_port", String::from("0\n")),
        file("dormant", String::from("0\n")),
        file("flags", format!("{flags:#x}\n")),
        file("ifindex", format!("{index}\n")),
        file("iflink", format!("{index}\n")),
        file("mtu", format!("{}\n", d.mtu())),
        file("operstate", format!("{}\n", OPERSTATES[usize::from(d.operstate()).min(6)])),
        (String::from("statistics"), Kind::Dir),
        (String::from("subsystem"), Kind::Link(b"../../../../class/net".to_vec())),
        file("tx_queue_len", format!("{}\n", d.txqlen())),
        file("type", format!("{}\n", d.kind().arphrd())),
        file("uevent", format!("INTERFACE={}\nIFINDEX={index}\n", d.name())),
    ]);
    out
}

/// The files and links in the directory of the device `d`.
fn device_entries(d: &DeviceInfo) -> Vec<(String, Kind)> {
    let mut uevent =
        format!("MAJOR={}\nMINOR={}\nDEVNAME={}\n", major(d.rdev), minor(d.rdev), d.name);
    if d.block {
        uevent.push_str("DEVTYPE=disk\n");
    }
    let mut out = Vec::new();
    out.push((String::from("dev"), Kind::File(format!("{}\n", numbers(d)).into_bytes())));
    if d.block {
        let size = block_sectors(d.rdev).unwrap_or(0);
        let ro = block_queue(d.rdev).is_some_and(|q| q.read_only());
        if rk_vfs::loopdev::sysfs_files(d.rdev).is_some() {
            out.push((String::from("loop"), Kind::Dir));
        }
        out.push((String::from("queue"), Kind::Dir));
        out.push((String::from("removable"), Kind::File(b"0\n".to_vec())));
        out.push((String::from("ro"), Kind::File(format!("{}\n", u8::from(ro)).into_bytes())));
        out.push((String::from("size"), Kind::File(format!("{size}\n").into_bytes())));
    }
    let subsystem = format!("../../../../class/{}", d.class);
    out.push((String::from("subsystem"), Kind::Link(subsystem.into_bytes())));
    out.push((String::from("uevent"), Kind::File(uevent.into_bytes())));
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

/// The entries of the directory at `path`, from the list of devices `list`. Gives `None` if no
/// directory has the path.
fn entries(path: &str, list: &[DeviceInfo]) -> Option<Vec<(String, Kind)>> {
    let mut classes: BTreeSet<&str> = list.iter().map(|d| d.class).collect();
    classes.insert(NET);
    let net = rk_net::dev::devices();
    let net_dev = |name: &str| net.iter().find(|d| d.name() == name).cloned();
    let parts: Vec<&str> = if path.is_empty() { Vec::new() } else { path.split('/').collect() };
    let dirs = |names: &mut dyn Iterator<Item = &str>| -> Vec<(String, Kind)> {
        names.map(|n| (String::from(n), Kind::Dir)).collect()
    };
    let to_device = |up: &str, d: &DeviceInfo| {
        Kind::Link(format!("{up}devices/virtual/{}/{}", d.class, d.name).into_bytes())
    };
    let out = match parts[..] {
        [] => dirs(&mut TOP.iter().copied()),
        ["block"] => {
            list.iter().filter(|d| d.block).map(|d| (d.name.clone(), to_device("../", d))).collect()
        }
        ["class"] | ["devices", "virtual"] => dirs(&mut classes.iter().copied()),
        ["class", NET] => net
            .iter()
            .map(|d| {
                let to = format!("../../devices/virtual/{NET}/{}", d.name());
                (d.name(), Kind::Link(to.into_bytes()))
            })
            .collect(),
        ["devices", "virtual", NET] => net.iter().map(|d| (d.name(), Kind::Dir)).collect(),
        ["devices", "virtual", NET, name] => net_entries(&*net_dev(name)?),
        ["devices", "virtual", NET, name, "statistics"] => net_statistics(&*net_dev(name)?),
        ["class", class] => list
            .iter()
            .filter(|d| d.class == class)
            .map(|d| (d.name.clone(), to_device("../../", d)))
            .collect(),
        ["dev"] => dirs(&mut ["block", "char"].into_iter()),
        ["dev", kind @ ("block" | "char")] => list
            .iter()
            .filter(|d| d.block == (kind == "block"))
            .map(|d| (numbers(d), to_device("../../", d)))
            .collect(),
        ["devices"] => dirs(&mut ["virtual"].into_iter()),
        ["devices", "virtual", class] if classes.contains(class) => {
            list.iter().filter(|d| d.class == class).map(|d| (d.name.clone(), Kind::Dir)).collect()
        }
        ["devices", "virtual", class, name] => {
            device_entries(list.iter().find(|d| d.class == class && d.name == name)?)
        }
        ["devices", "virtual", class, name, "queue"] => {
            queue_entries(list.iter().find(|d| d.class == class && d.name == name && d.block)?)
        }
        ["devices", "virtual", class, name, "loop"] => {
            let d = list.iter().find(|d| d.class == class && d.name == name && d.block)?;
            let files = rk_vfs::loopdev::sysfs_files(d.rdev)?;
            files
                .into_iter()
                .map(|(n, text)| (String::from(n), Kind::File(text.into_bytes())))
                .collect()
        }
        // `/sys/fs/cgroup` is the place where the init system mounts cgroup2.
        ["fs"] => dirs(&mut ["cgroup", "ext4"].into_iter()),
        ["fs", "cgroup"] => Vec::new(),
        ["fs", "ext4"] => dirs(&mut ["features"].into_iter()),
        ["fs", "ext4", "features"] => EXT4_FEATURES
            .iter()
            .map(|&n| (String::from(n), Kind::File(b"supported\n".to_vec())))
            .collect(),
        ["kernel"] => dirs(&mut ["mm"].into_iter()),
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
            Kind::Dir => entries(&self.path, &devices()).ok_or(Errno::ENOENT),
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
            Kind::File(_) if writable(&self.path) => (mode::S_IFREG, 0o644, 1, BLOCK_SIZE as u64),
            Kind::File(_) | Kind::Mm { writable: false } => {
                (mode::S_IFREG, 0o444, 1, BLOCK_SIZE as u64)
            }
            Kind::Mm { writable: true } => (mode::S_IFREG, 0o644, 1, BLOCK_SIZE as u64),
            Kind::Link(target) => (mode::S_IFLNK, 0o777, 1, target.len() as u64),
        };
        let t = now();
        Metadata {
            dev: dev(),
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
            Kind::File(_) => write_file(&self.path, buf).map(|()| buf.len()),
            Kind::Mm { .. } => Err(Errno::EACCES),
            _ => Err(Errno::EINVAL),
        }
    }

    fn lookup(&self, name: &[u8]) -> Result<InodeRef> {
        let name = core::str::from_utf8(name).map_err(|_| Errno::ENOENT)?;
        let (name, kind) =
            self.children()?.into_iter().find(|(n, _)| n == name).ok_or(Errno::ENOENT)?;
        Ok(Arc::new(Node { path: self.child_path(&name), kind }))
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

    fn names(path: &str) -> Vec<String> {
        entries(path, &list()).unwrap().into_iter().map(|(n, _)| n).collect()
    }

    fn get(path: &str) -> Kind {
        let (dir, name) = path.rsplit_once('/').unwrap();
        entries(dir, &list()).unwrap().into_iter().find(|(n, _)| n == name).unwrap().1
    }

    #[test]
    fn an_interface_has_the_files_of_linux() {
        rk_net::dev::init();
        assert_eq!(get("class/net/lo"), Kind::Link(b"../../devices/virtual/net/lo".to_vec()));
        assert!(names("devices/virtual").contains(&String::from("net")));
        let lo = "devices/virtual/net/lo";
        assert_eq!(get(&format!("{lo}/mtu")), Kind::File(b"65536\n".to_vec()));
        assert_eq!(get(&format!("{lo}/type")), Kind::File(b"772\n".to_vec()));
        assert_eq!(get(&format!("{lo}/address")), Kind::File(b"00:00:00:00:00:00\n".to_vec()));
        assert!(names(&format!("{lo}/statistics")).contains(&String::from("rx_bytes")));
    }

    #[test]
    fn the_top_has_the_directories_of_linux() {
        assert_eq!(names(""), TOP);
        assert_eq!(names("class"), ["block", "mem", "net", "tty"]);
        assert_eq!(names("devices/virtual"), ["block", "mem", "net", "tty"]);
        assert!(names("bus").is_empty());
        assert!(entries("nothing", &list()).is_none());
        assert!(entries("devices/virtual/disk", &list()).is_none());
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
            ["dev", "queue", "removable", "ro", "size", "subsystem", "uevent"]
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
    fn only_a_loop_device_with_a_file_has_the_loop_directory() {
        assert!(!names("devices/virtual/block/vda").contains(&String::from("loop")));
        assert_eq!(entries("devices/virtual/block/vda/loop", &list()), None);
        assert_eq!(get("devices/virtual/block/vda/ro"), Kind::File(b"0\n".to_vec()));
    }

    #[test]
    fn ext4_tells_its_features() {
        assert_eq!(names("fs"), ["cgroup", "ext4"]);
        assert!(names("fs/cgroup").is_empty());
        assert_eq!(names("fs/ext4/features"), ["meta_bg_resize"]);
        assert_eq!(get("fs/ext4/features/meta_bg_resize"), Kind::File(b"supported\n".to_vec()));
    }

    #[test]
    fn ksm_has_the_files_of_linux() {
        assert_eq!(names("kernel"), ["mm"]);
        assert_eq!(names("kernel/mm"), ["hugepages", "ksm", "transparent_hugepage"]);
        let files = names("kernel/mm/ksm");
        for f in ["run", "pages_to_scan", "sleep_millisecs", "full_scans", "pages_shared"] {
            assert!(files.contains(&String::from(f)), "{f}");
        }
        assert_eq!(get("kernel/mm/ksm/run"), Kind::Mm { writable: true });
        assert_eq!(get("kernel/mm/ksm/pages_shared"), Kind::Mm { writable: false });
        let run =
            Node { path: String::from("kernel/mm/ksm/run"), kind: Kind::Mm { writable: true } };
        assert_eq!(run.metadata().mode, mode::S_IFREG | 0o644);
        let mut buf = [0u8; 8];
        assert_eq!(run.read_at(0, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], b"0\n");
        assert_eq!(run.write_at(0, b"7").unwrap_err(), Errno::EINVAL);
        let shared = Node {
            path: String::from("kernel/mm/ksm/pages_shared"),
            kind: Kind::Mm { writable: false },
        };
        assert_eq!(shared.write_at(0, b"1").unwrap_err(), Errno::EACCES);
    }

    #[test]
    fn the_pool_of_hugetlbfs_has_the_files_of_linux() {
        let dir = "kernel/mm/hugepages/hugepages-2048kB";
        assert_eq!(names("kernel/mm/hugepages"), ["hugepages-2048kB"]);
        assert!(names(dir).contains(&String::from("resv_hugepages")));
        assert_eq!(get(&format!("{dir}/nr_hugepages")), Kind::Mm { writable: true });
        let free =
            Node { path: format!("{dir}/free_hugepages"), kind: Kind::Mm { writable: false } };
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
        let enabled = Node { path: format!("{THP_DIR}/enabled"), kind: Kind::File(Vec::new()) };
        assert_eq!(enabled.metadata().mode, mode::S_IFREG | 0o644);
        assert_eq!(enabled.write_at(0, b"sometimes\n").unwrap_err(), Errno::EINVAL);
        assert_eq!(enabled.write_at(0, b"madvise\n").unwrap(), 8);
        assert_eq!(rk_mm::tunables::show_thp_enabled(), "always [madvise] never\n");
        enabled.write_at(0, b"always").unwrap();
    }

    #[test]
    fn a_node_reads_and_does_not_change() {
        let file = Node { path: String::from("a/b"), kind: Kind::File(b"hello\n".to_vec()) };
        let mut buf = [0u8; 4];
        assert_eq!(file.read_at(4, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], b"o\n");
        assert_eq!(file.write_at(0, b"x").unwrap_err(), Errno::EACCES);
        assert_eq!(file.metadata().mode, mode::S_IFREG | 0o444);
        assert_eq!(file.fs_magic(), SYSFS_MAGIC);
        let root = Node { path: String::new(), kind: Kind::Dir };
        assert_eq!(root.metadata().ino, 1);
        assert_eq!(root.unlink(b"block").unwrap_err(), Errno::EPERM);
        assert_eq!(root.lookup(b"nothing").err(), Some(Errno::ENOENT));
        let block = root.lookup(b"block").unwrap();
        assert_eq!(block.metadata().ino, ino("block"));
        assert_eq!(block.read_dir(1).unwrap().unwrap().0.ino, 1);
        assert_eq!(parent("devices/virtual"), "devices");
    }
}

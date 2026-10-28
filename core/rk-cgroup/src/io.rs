//! The io controller: `io.stat`, `io.max` and `io.weight`, as block/blk-cgroup.c and
//! block/blk-throttle.c of Linux.
//!
//! The block layer charges each bio to the cgroup of the task that submits it and to each
//! cgroup above, and `io.stat` shows the counts of each device. `io.max` limits the bytes and the
//! I/O operations in each second for a device. A charge over a limit gives a delay, and the task
//! waits for that time before it goes back to user mode.
//!
//! `io.weight` shares a device among the cgroups that use it at the same time, with a virtual
//! time as a fair queue. Each cgroup that did I/O on the device in the last [`ACTIVE_NS`] is
//! active. A cgroup gets the part of the device that its weight gives among the active siblings,
//! at each level of the tree. Its virtual time moves forward by the bytes of each charge divided
//! by that part, and the virtual time of the device moves forward by the bytes. A cgroup whose
//! virtual time is ahead of the device waits for the time that the device takes for the
//! difference, so a cgroup with twice the weight gets twice the bytes. Linux does this with the
//! iocost or BFQ scheduler.

use crate::{CgId, MAX};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use rk_abi::Errno;

/// The smallest weight of `io.weight`, `CGROUP_WEIGHT_MIN` of Linux.
pub const WEIGHT_MIN: u32 = 1;
/// The default weight of `io.weight`, `CGROUP_WEIGHT_DFL` of Linux.
pub const WEIGHT_DEFAULT: u32 = 100;
/// The largest weight of `io.weight`, `CGROUP_WEIGHT_MAX` of Linux.
pub const WEIGHT_MAX: u32 = 10_000;

/// The keys of `io.max`, in the order of Linux.
const LIMIT_KEYS: [&str; 4] = ["rbps", "wbps", "riops", "wiops"];

/// The nanoseconds in one second.
const NS_PER_SEC: u128 = 1_000_000_000;

/// A cgroup that did I/O on a device in this time in nanoseconds is active on the device.
pub const ACTIVE_NS: u64 = 100_000_000;

/// The bytes that a cgroup can be ahead of the device before it waits.
const SLACK_BYTES: u64 = 256 << 10;

/// The longest wait for `io.weight` for one charge, in nanoseconds.
const WEIGHT_DELAY_MAX: u64 = 250_000_000;

/// The unit of the part of a device that a cgroup gets: the whole device.
pub const SHARE_UNIT: u64 = 1 << 16;

/// The kind of an I/O.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// A read.
    Read,
    /// A write.
    Write,
    /// A discard. The limits of `io.max` count it as a write, as blk-throttle of Linux does.
    Discard,
}

/// The major number of a device number, in the encoding of Linux.
pub const fn major(dev: u64) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as u32
}

/// The minor number of a device number, in the encoding of Linux.
pub const fn minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32
}

/// Makes a device number from the major and the minor number, in the encoding of Linux.
pub const fn makedev(major: u32, minor: u32) -> u64 {
    let (major, minor) = (major as u64, minor as u64);
    (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12) | ((major & !0xfff) << 32)
}

/// Reads a device as `MAJ:MIN`.
///
/// # Errors
///
/// Gives `EINVAL` for text that is not a device.
pub fn parse_dev(word: &str) -> Result<u64, Errno> {
    let (maj, min) = word.split_once(':').ok_or(Errno::EINVAL)?;
    let maj = maj.parse::<u32>().map_err(|_| Errno::EINVAL)?;
    let min = min.parse::<u32>().map_err(|_| Errno::EINVAL)?;
    Ok(makedev(maj, min))
}

/// The device of a write of `io.max` or `io.weight`: the first word if it is `MAJ:MIN`.
pub fn dev_of_write(data: &[u8]) -> Option<u64> {
    let text = core::str::from_utf8(data).ok()?;
    parse_dev(text.split_ascii_whitespace().next()?).ok()
}

/// The counts of one device in `io.stat`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoStat {
    /// The bytes that the device read.
    pub rbytes: u64,
    /// The bytes that the device wrote.
    pub wbytes: u64,
    /// The read bios.
    pub rios: u64,
    /// The write bios.
    pub wios: u64,
    /// The bytes that the device discarded.
    pub dbytes: u64,
    /// The discard bios.
    pub dios: u64,
}

/// The values of the io controller of one cgroup.
#[derive(Clone, Debug)]
pub struct Io {
    /// The counts of each device, with the subtree.
    pub stat: BTreeMap<u64, IoStat>,
    /// The limits of `io.max` of each device: `rbps`, `wbps`, `riops` and `wiops`. [`MAX`] is
    /// no limit. A device without a limit has no entry.
    pub max: BTreeMap<u64, [u64; 4]>,
    /// The default weight of `io.weight`.
    pub weight: u32,
    /// The weights of `io.weight` for single devices.
    pub weights: BTreeMap<u64, u32>,
    /// The time in nanoseconds when the use of each limit of each device is under the limit
    /// again. A charge moves it forward by the time that the limit gives to the charge.
    next: BTreeMap<(u64, usize), u64>,
}

impl Default for Io {
    fn default() -> Self {
        Self {
            stat: BTreeMap::new(),
            max: BTreeMap::new(),
            weight: WEIGHT_DEFAULT,
            weights: BTreeMap::new(),
            next: BTreeMap::new(),
        }
    }
}

impl Io {
    /// Adds a charge of `bytes` bytes in `ios` bios of the kind `op` to the device `dev` at the
    /// time `now`. With `limit`, the limits of `io.max` apply. Gives the delay in nanoseconds
    /// that keeps the use under the limits.
    pub fn charge(&mut self, dev: u64, op: Op, bytes: u64, ios: u64, now: u64, limit: bool) -> u64 {
        let s = self.stat.entry(dev).or_default();
        match op {
            Op::Read => {
                s.rbytes += bytes;
                s.rios += ios;
            }
            Op::Write => {
                s.wbytes += bytes;
                s.wios += ios;
            }
            Op::Discard => {
                s.dbytes += bytes;
                s.dios += ios;
            }
        }
        let Some(&max) = self.max.get(&dev).filter(|_| limit) else { return 0 };
        let w = usize::from(op != Op::Read);
        let mut delay = 0;
        for (k, amount) in [(w, bytes), (2 + w, ios)] {
            if max[k] == MAX || amount == 0 {
                continue;
            }
            let cost = u128::from(amount) * NS_PER_SEC / u128::from(max[k]);
            let cost = u64::try_from(cost).unwrap_or(u64::MAX);
            let next = self.next.entry((dev, k)).or_insert(now);
            *next = (*next).max(now).saturating_add(cost);
            delay = delay.max(*next - now);
        }
        delay
    }

    /// The weight of `io.weight` for the device `dev`.
    pub fn weight_of(&self, dev: u64) -> u32 {
        self.weights.get(&dev).copied().unwrap_or(self.weight)
    }

    /// The text of `io.stat`: one line for each device with counts.
    pub fn show_stat(&self) -> String {
        let mut out = String::new();
        for (&dev, s) in &self.stat {
            out.push_str(&format!(
                "{}:{} rbytes={} wbytes={} rios={} wios={} dbytes={} dios={}\n",
                major(dev),
                minor(dev),
                s.rbytes,
                s.wbytes,
                s.rios,
                s.wios,
                s.dbytes,
                s.dios
            ));
        }
        out
    }

    /// The text of `io.max`: one line for each device with a limit.
    pub fn show_max(&self) -> String {
        let mut out = String::new();
        for (&dev, max) in &self.max {
            out.push_str(&format!("{}:{}", major(dev), minor(dev)));
            for (key, &v) in LIMIT_KEYS.iter().zip(max) {
                if v == MAX {
                    out.push_str(&format!(" {key}=max"));
                } else {
                    out.push_str(&format!(" {key}={v}"));
                }
            }
            out.push('\n');
        }
        out
    }

    /// The text of `io.weight`: the default weight, and the weight of each device that has
    /// one.
    pub fn show_weight(&self) -> String {
        let mut out = format!("default {}\n", self.weight);
        for (&dev, w) in &self.weights {
            out.push_str(&format!("{}:{} {w}\n", major(dev), minor(dev)));
        }
        out
    }

    /// Does a write of `io.max`: `MAJ:MIN` and the limits to change, as `rbps=1048576` or
    /// `wiops=max`, as `tg_set_limit` of Linux. A device with no limit left loses its entry.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` for text that is not valid, and `ERANGE` for a limit of 0.
    pub fn write_max(&mut self, text: &str) -> Result<(), Errno> {
        let mut words = text.split_ascii_whitespace();
        let dev = parse_dev(words.next().ok_or(Errno::EINVAL)?)?;
        let mut max = self.max.get(&dev).copied().unwrap_or([MAX; 4]);
        for word in words {
            let (key, value) = word.split_once('=').ok_or(Errno::EINVAL)?;
            let k = LIMIT_KEYS.iter().position(|&x| x == key).ok_or(Errno::EINVAL)?;
            max[k] = match value {
                "max" => MAX,
                v => match v.parse::<u64>().map_err(|_| Errno::EINVAL)? {
                    0 => return Err(Errno::ERANGE),
                    v => v,
                },
            };
        }
        if max == [MAX; 4] {
            self.max.remove(&dev);
        } else {
            self.max.insert(dev, max);
        }
        self.next.retain(|&(d, _), _| d != dev);
        Ok(())
    }

    /// Does a write of `io.weight`: `default N` or `N` for the default weight, `MAJ:MIN N` for
    /// one device, and `MAJ:MIN default` to remove the weight of a device.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` for text that is not valid or a weight out of the range.
    pub fn write_weight(&mut self, text: &str) -> Result<(), Errno> {
        let weight = |w: &str| -> Result<u32, Errno> {
            let w = w.parse::<u32>().map_err(|_| Errno::EINVAL)?;
            if (WEIGHT_MIN..=WEIGHT_MAX).contains(&w) { Ok(w) } else { Err(Errno::EINVAL) }
        };
        let mut words = text.split_ascii_whitespace();
        let first = words.next().ok_or(Errno::EINVAL)?;
        let second = words.next();
        if words.next().is_some() {
            return Err(Errno::EINVAL);
        }
        match (first, second) {
            ("default", Some(w)) | (w, None) => self.weight = weight(w)?,
            (dev, Some("default")) => {
                self.weights.remove(&parse_dev(dev)?);
            }
            (dev, Some(w)) => {
                let dev = parse_dev(dev)?;
                self.weights.insert(dev, weight(w)?);
            }
        }
        Ok(())
    }
}

/// The state of one device for the share of `io.weight`.
#[derive(Clone, Debug, Default)]
pub struct Share {
    /// The virtual time of the device: the bytes that it did.
    vtime: u64,
    /// The bytes and the time in nanoseconds that the device took for them, for its speed. The
    /// counts go down by half when the time passes a second, so the speed follows the device.
    bytes: u64,
    busy: u64,
    /// The virtual time and the time of the last charge of each cgroup that does I/O.
    cgroups: BTreeMap<CgId, (u64, u64)>,
}

impl Share {
    /// The cgroups that did I/O on the device since `now - ACTIVE_NS`. Forgets the others.
    pub fn active(&mut self, now: u64) -> alloc::vec::Vec<CgId> {
        let since = now.saturating_sub(ACTIVE_NS);
        self.cgroups.retain(|_, &mut (_, last)| last >= since);
        self.cgroups.keys().copied().collect()
    }

    /// Adds a charge of `bytes` that took `ns` of the device to the cgroup `id`, which gets the
    /// part `share` of the device, in units of [`SHARE_UNIT`]. Gives the time in nanoseconds
    /// that the cgroup waits, so that it does not get more than its part.
    pub fn charge(&mut self, id: CgId, bytes: u64, ns: u64, share: u64, now: u64) -> u64 {
        self.bytes += bytes;
        self.busy += ns;
        if self.busy > 1_000_000_000 {
            self.bytes /= 2;
            self.busy /= 2;
        }
        let share = share.clamp(1, SHARE_UNIT);
        let cost = u128::from(bytes) * u128::from(SHARE_UNIT) / u128::from(share);
        let cost = u64::try_from(cost).unwrap_or(u64::MAX);
        let vtime = self.vtime;
        let entry = self.cgroups.entry(id).or_insert((vtime, now));
        entry.0 = entry.0.max(vtime).saturating_add(cost);
        entry.1 = now;
        let ahead = entry.0;
        self.vtime += bytes;
        let lead = ahead.saturating_sub(self.vtime).saturating_sub(SLACK_BYTES);
        if lead == 0 || self.bytes == 0 || self.busy == 0 {
            return 0;
        }
        // The time that the device takes for the bytes of the lead, at its speed.
        let delay = u128::from(lead) * u128::from(self.busy) / u128::from(self.bytes);
        u64::try_from(delay).unwrap_or(u64::MAX).min(WEIGHT_DELAY_MAX)
    }
}

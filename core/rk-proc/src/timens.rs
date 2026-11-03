//! Time namespaces, as kernel/time/namespace.c of Linux.
//!
//! A time namespace has an offset for `CLOCK_MONOTONIC` and one for `CLOCK_BOOTTIME`. The clocks
//! of a thread in the namespace are the clocks of the system plus the offsets. `unshare` and
//! `clone3` with `CLONE_NEWTIME` make a namespace for the children of the caller, and the caller
//! can set the offsets in `/proc/PID/timens_offsets` until the first process goes in. Then the
//! offsets do not change.
//!
//! Each namespace has a page with the two offsets for the vDSO. The kernel maps the page of the
//! namespace of a process below the data page of the vDSO, as `timens_page` of Linux.

use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use rk_abi::Errno;
use rk_frame::mm::{Frame, alloc_zeroed_frame};
use rk_frame::sync::{Once, SpinLock};

/// The index of the offset of `CLOCK_MONOTONIC`.
pub const MONOTONIC: usize = 0;
/// The index of the offset of `CLOCK_BOOTTIME`.
pub const BOOTTIME: usize = 1;

/// The clock IDs of include/uapi/linux/time.h that a time namespace moves.
const CLOCK_MONOTONIC: u32 = 1;
const CLOCK_MONOTONIC_RAW: u32 = 4;
const CLOCK_MONOTONIC_COARSE: u32 = 6;
/// The clock ID of `CLOCK_BOOTTIME`.
pub const CLOCK_BOOTTIME: u32 = 7;
const CLOCK_BOOTTIME_ALARM: u32 = 9;

/// A time namespace, as `struct time_namespace` of Linux.
pub struct TimeNs {
    /// The ID of the namespace for nsfs. The first namespace has the ID 0.
    id: u32,
    /// The offsets of `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` in nanoseconds.
    offsets: SpinLock<[i64; 2]>,
    /// Set when the first process goes in. The offsets cannot change then, as
    /// `frozen_offsets` of Linux.
    frozen: AtomicBool,
    /// The page of the vDSO with the offsets, or `None` if no frame was free.
    page: Option<Arc<Frame>>,
}

/// The time namespaces other than the first one, for `by_id`.
static LIVE: SpinLock<Vec<Weak<TimeNs>>> = SpinLock::new(Vec::new());

/// The next ID for a time namespace.
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

/// The first time namespace, `init_time_ns` of Linux. Its offsets are 0.
pub fn init_ns() -> Arc<TimeNs> {
    static INIT: Once<Arc<TimeNs>> = Once::new();
    INIT.call_once(|| {
        Arc::new(TimeNs {
            id: 0,
            offsets: SpinLock::new([0; 2]),
            frozen: AtomicBool::new(true),
            page: alloc_zeroed_frame().map(Arc::new),
        })
    })
    .clone()
}

/// Makes a new time namespace with the offsets of `parent`, as `clone_time_ns` of Linux.
///
/// # Errors
///
/// Gives `ENOMEM` if no frame is free for the page of the vDSO.
pub fn new(parent: &TimeNs) -> Result<Arc<TimeNs>, Errno> {
    let page = alloc_zeroed_frame().ok_or(Errno::ENOMEM)?;
    let ns = Arc::new(TimeNs {
        id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        offsets: SpinLock::new(parent.offsets()),
        frozen: AtomicBool::new(false),
        page: Some(Arc::new(page)),
    });
    let mut live = LIVE.lock();
    live.retain(|w| w.strong_count() > 0);
    live.push(Arc::downgrade(&ns));
    Ok(ns)
}

/// The time namespace with the ID `id`, while it exists.
pub fn by_id(id: u32) -> Option<Arc<TimeNs>> {
    if id == 0 {
        return Some(init_ns());
    }
    LIVE.lock().iter().filter_map(Weak::upgrade).find(|ns| ns.id == id)
}

/// The nanoseconds in a second.
const NSEC_PER_SEC: i64 = 1_000_000_000;
/// The largest second of a time, `KTIME_SEC_MAX` of Linux.
const KTIME_SEC_MAX: i64 = i64::MAX / NSEC_PER_SEC;
/// The size of a page: a write to `timens_offsets` must be smaller.
const PAGE_SIZE: usize = 4096;

/// Gives the text of `/proc/PID/timens_offsets` for the namespace `ns`, as
/// `proc_timens_show_offsets` of Linux.
pub fn show_offsets(ns: &TimeNs) -> String {
    let offsets = ns.offsets();
    let mut out = String::new();
    for (name, off) in [("monotonic", offsets[MONOTONIC]), ("boottime", offsets[BOOTTIME])] {
        let (sec, nsec) = (off.div_euclid(NSEC_PER_SEC), off.rem_euclid(NSEC_PER_SEC));
        out += &format!("{name:<10} {sec:>10} {nsec:>9}\n");
    }
    out
}

/// Sets the offsets of `ns` from a write of `text` to `/proc/PID/timens_offsets`, as
/// `proc_timens_offsets_write` and `proc_timens_set_offset` of Linux. Each line is
/// `CLOCK SECONDS NANOSECONDS`, and `CLOCK` is `monotonic`, `boottime` or a clock ID. `now`
/// gives the time since boot in nanoseconds. `may_set` tells if the caller has `CAP_SYS_TIME`.
///
/// # Errors
///
/// Gives `EINVAL` for bad text or a clock other than `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME`,
/// `EPERM` without `CAP_SYS_TIME`, `ERANGE` for a time out of the range of the clock, and
/// `EACCES` if a process went in the namespace.
pub fn write_offsets(ns: &TimeNs, text: &[u8], now: u64, may_set: bool) -> Result<(), Errno> {
    if text.len() >= PAGE_SIZE {
        return Err(Errno::EINVAL);
    }
    let text = core::str::from_utf8(text).map_err(|_| Errno::EINVAL)?;
    let mut new: Vec<(u32, i64, i64)> = Vec::new();
    for line in text.split_terminator('\n') {
        let mut words = line.split_ascii_whitespace();
        let (Some(clock), Some(sec), Some(nsec)) = (words.next(), words.next(), words.next())
        else {
            return Err(Errno::EINVAL);
        };
        if clock.len() > 9 {
            return Err(Errno::EINVAL);
        }
        let sec: i64 = sec.parse().map_err(|_| Errno::EINVAL)?;
        let nsec: u64 = nsec.parse().map_err(|_| Errno::EINVAL)?;
        if nsec >= NSEC_PER_SEC as u64 {
            return Err(Errno::EINVAL);
        }
        let clock = match clock {
            "monotonic" => CLOCK_MONOTONIC,
            "boottime" => CLOCK_BOOTTIME,
            c => c.parse::<i32>().map_err(|_| Errno::EINVAL)? as u32,
        };
        new.push((clock, sec, nsec as i64));
        if new.len() == 2 {
            break;
        }
    }
    if new.is_empty() {
        return Err(Errno::EINVAL);
    }
    if !may_set {
        return Err(Errno::EPERM);
    }
    let mut set = Vec::with_capacity(new.len());
    for (clock, sec, nsec) in new {
        let index = match clock {
            CLOCK_MONOTONIC => MONOTONIC,
            CLOCK_BOOTTIME => BOOTTIME,
            _ => return Err(Errno::EINVAL),
        };
        if !(-KTIME_SEC_MAX..=KTIME_SEC_MAX).contains(&sec) {
            return Err(Errno::ERANGE);
        }
        // The time of the clock in the namespace must stay far from the end of the range.
        let tsec =
            (i128::from(now) + i128::from(nsec)) / i128::from(NSEC_PER_SEC) + i128::from(sec);
        if !(0..=i128::from(KTIME_SEC_MAX / 2)).contains(&tsec) {
            return Err(Errno::ERANGE);
        }
        set.push((index, sec * NSEC_PER_SEC + nsec));
    }
    ns.set_offsets(&set)
}

/// The index of the offset of `clock`, or `None` for a clock that a time namespace does not move,
/// as `timens_add_monotonic` and `timens_add_boottime` of Linux.
pub fn offset_index(clock: u32) -> Option<usize> {
    match clock {
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_MONOTONIC_COARSE => Some(MONOTONIC),
        CLOCK_BOOTTIME | CLOCK_BOOTTIME_ALARM => Some(BOOTTIME),
        _ => None,
    }
}

impl TimeNs {
    /// The ID of the namespace.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Tells if this is the first namespace.
    pub fn is_init(&self) -> bool {
        self.id == 0
    }

    /// The offsets of `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` in nanoseconds.
    pub fn offsets(&self) -> [i64; 2] {
        *self.offsets.lock()
    }

    /// The offset of `clock` in nanoseconds: 0 for a clock that the namespace does not move.
    pub fn offset(&self, clock: u32) -> i64 {
        offset_index(clock).map_or(0, |i| self.offsets()[i])
    }

    /// Gives the time `ns` of `clock` in the namespace, from the time of the system.
    pub fn to_ns(&self, clock: u32, ns: u64) -> u64 {
        (i128::from(ns) + i128::from(self.offset(clock))).clamp(0, i128::from(u64::MAX)) as u64
    }

    /// Gives the time of the system of the time `ns` of `clock` in the namespace, as
    /// `timens_ktime_to_host` of Linux.
    pub fn to_host(&self, clock: u32, ns: u64) -> u64 {
        (i128::from(ns) - i128::from(self.offset(clock))).clamp(0, i128::from(u64::MAX)) as u64
    }

    /// Sets the offsets, pairs of an index and a value in nanoseconds, as
    /// `proc_timens_set_offset` of Linux.
    ///
    /// # Errors
    ///
    /// Gives `EACCES` if a process went in the namespace.
    pub fn set_offsets(&self, new: &[(usize, i64)]) -> Result<(), Errno> {
        let mut offsets = self.offsets.lock();
        if self.frozen.load(Ordering::Acquire) {
            return Err(Errno::EACCES);
        }
        for &(i, v) in new {
            offsets[i] = v;
        }
        Ok(())
    }

    /// Stops the changes of the offsets and writes them to the page of the vDSO, before the
    /// first process goes in, as `timens_set_vvar_page` of Linux.
    pub fn freeze(&self) {
        let offsets = self.offsets.lock();
        if self.frozen.load(Ordering::Acquire) {
            return;
        }
        if let Some(page) = &self.page {
            page.write_bytes(0, &offsets[MONOTONIC].to_ne_bytes());
            page.write_bytes(8, &offsets[BOOTTIME].to_ne_bytes());
        }
        self.frozen.store(true, Ordering::Release);
    }

    /// The page of the vDSO with the offsets.
    pub fn page(&self) -> Option<&Arc<Frame>> {
        self.page.as_ref()
    }
}

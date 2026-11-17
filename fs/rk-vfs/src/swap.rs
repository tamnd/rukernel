//! The swap areas of `swapon` and `swapoff`.
//!
//! A swap area is a regular file or a block device with the header of `mkswap`. `swapon` examines
//! the header and the blocks of the file, as Linux does, and then the area is active: a write, a
//! truncate, a `fallocate` and a shared writable mapping of the file give `ETXTBSY`, and
//! `/proc/swaps` shows the area.
//!
//! Each area has a map of its pages, as the `swap_map` of Linux. [`alloc`] gives a free page of the
//! area with the highest priority as a swap entry, and [`write_page`] and [`read_page`] move the
//! data of the entry with direct I/O to the queue of the disk, as `swap_writepage` and
//! `swap_read_folio` of Linux. A swap file uses the runs of the disk that `swapon` found in its
//! extents, as the `swap_extent` list of Linux.

use crate::FileType;
use crate::file::File;
use crate::inode::{FiemapExtent, Inode, InodeRef, Result};
use crate::wait::WaitQueue;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use rk_abi::Errno;
use rk_block::Queue;
use rk_block::cache::PAGE_SIZE;
use rk_frame::sync::SpinLock;

/// The flags of `swapon`, from `<linux/swap.h>`.
pub mod flags {
    /// The low bits give the priority.
    pub const SWAP_FLAG_PREFER: u32 = 0x8000;
    /// The priority bits.
    pub const SWAP_FLAG_PRIO_MASK: u32 = 0x7fff;
    /// Discards the free pages.
    pub const SWAP_FLAG_DISCARD: u32 = 0x10000;
    /// Discards the area once, at `swapon`.
    pub const SWAP_FLAG_DISCARD_ONCE: u32 = 0x20000;
    /// Discards the pages when they become free.
    pub const SWAP_FLAG_DISCARD_PAGES: u32 = 0x40000;
    /// All the flags that Linux knows.
    pub const VALID: u32 = SWAP_FLAG_PRIO_MASK
        | SWAP_FLAG_PREFER
        | SWAP_FLAG_DISCARD
        | SWAP_FLAG_DISCARD_ONCE
        | SWAP_FLAG_DISCARD_PAGES;
}

/// The most active areas, as `MAX_SWAPFILES` of Linux without the special types.
pub const MAX_SWAPFILES: usize = 29;

/// The most bad pages that a header can list, as `MAX_SWAP_BADPAGES` of Linux for a page of 4096
/// bytes.
const MAX_BADPAGES: u32 = 637;

/// The offsets of the fields of `union swap_header` in the first page.
mod header {
    pub(super) const VERSION: usize = 1024;
    pub(super) const LAST_PAGE: usize = 1028;
    pub(super) const NR_BADPAGES: usize = 1032;
    pub(super) const BADPAGES: usize = 1536;
}

/// The use of the pages of an area, as the `swap_map` of Linux with one bit for each page. The
/// first page has the header, and it and the bad pages are never free.
#[derive(Debug, Default)]
struct Slots {
    /// One bit for each page of the area, set for a page that is used.
    used: Vec<u64>,
    /// The number of pages, with the header.
    pages: u64,
    /// The pages that entries use, as `inuse_pages` of Linux.
    inuse: u64,
    /// The page where the next search starts, as `cluster_next` of Linux.
    next: u64,
}

impl Slots {
    /// The map of an area of `pages` pages with the header, and the bad pages `bad`.
    fn new(pages: u64, bad: &[u64]) -> Self {
        let words = usize::try_from(pages.div_ceil(64)).unwrap_or(0);
        let mut s = Self { used: alloc::vec![0; words], pages, inuse: 0, next: 1 };
        for &page in core::iter::once(&0).chain(bad) {
            s.mark(page);
        }
        // The bits after the last page are used.
        for page in pages..words as u64 * 64 {
            s.mark(page);
        }
        s
    }

    fn mark(&mut self, page: u64) {
        if let Some(w) = self.used.get_mut((page / 64) as usize) {
            *w |= 1 << (page % 64);
        }
    }

    /// Gives a free page and marks it used, or `None` if the area is full.
    fn alloc(&mut self) -> Option<u64> {
        let words = self.used.len();
        let start = (self.next / 64) as usize;
        for i in (start..words).chain(0..start) {
            let w = self.used[i];
            if w != u64::MAX {
                let page = i as u64 * 64 + u64::from(w.trailing_ones());
                self.mark(page);
                self.inuse += 1;
                self.next = page + 1;
                return Some(page);
            }
        }
        None
    }

    /// Marks the used page `page` free. Gives `false` for a page that is not used or that is not
    /// an entry.
    fn free(&mut self, page: u64) -> bool {
        if page == 0 || page >= self.pages {
            return false;
        }
        let Some(w) = self.used.get_mut((page / 64) as usize) else { return false };
        let bit = 1 << (page % 64);
        if *w & bit == 0 {
            return false;
        }
        *w &= !bit;
        self.inuse -= 1;
        true
    }
}

/// The place of the pages of an area on the disk.
struct Disk {
    queue: Arc<Queue>,
    /// The runs of the disk that hold the pages of the area, in order: the first page of the run
    /// on the disk and the number of pages. A block device has one run.
    runs: Vec<(u64, u64)>,
}

/// The sector of the disk of the page `page` of an area on the runs `runs` of the disk.
fn sector(runs: &[(u64, u64)], mut page: u64) -> Option<u64> {
    for &(first, n) in runs {
        if page < n {
            return Some((first + page) * (PAGE_SIZE as u64 / 512));
        }
        page -= n;
    }
    None
}

/// An active swap area.
pub struct Swap {
    file: Arc<File>,
    /// The type of the entries of the area, as the index of `swap_info` of Linux. It does not
    /// change while the area is active.
    kind: u64,
    slots: Slots,
    disk: Option<Disk>,
    /// The path of the file at `swapon`, as `/proc/swaps` shows it.
    pub path: Vec<u8>,
    /// The file is a block device.
    pub partition: bool,
    /// The pages of the area that can hold data. The first page has the header.
    pub pages: u64,
    /// The priority.
    pub priority: i32,
}

impl Swap {
    fn inode(&self) -> Option<&InodeRef> {
        self.file.inode()
    }

    /// The pages that entries use, as the `Used` column of `/proc/swaps`.
    pub fn used(&self) -> u64 {
        self.slots.inuse
    }
}

/// The bits of the type in a swap entry. The low bits are the page in the area, as `swp_entry_t`
/// of Linux.
const KIND_SHIFT: u32 = 58;

/// The swap entry of the page `page` of the area of type `kind`.
const fn entry(kind: u64, page: u64) -> u64 {
    kind << KIND_SHIFT | page
}

/// The type and the page of the swap entry `e`.
const fn split(e: u64) -> (u64, u64) {
    (e >> KIND_SHIFT, e & ((1 << KIND_SHIFT) - 1))
}

/// The active areas, in the order of `swapon`.
static SWAPS: SpinLock<Vec<Swap>> = SpinLock::new(Vec::new());
/// The number of active areas, so that a write does not take the lock when there is none.
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
/// The priority of the last area without `SWAP_FLAG_PREFER`.
static LEAST: SpinLock<i32> = SpinLock::new(-1);
/// The count of the changes of the areas, as `proc_poll_event` of Linux.
static EVENT: AtomicU64 = AtomicU64::new(0);
/// The queue that a change of the areas wakes, as `proc_poll_wait` of Linux.
static POLL: WaitQueue = WaitQueue::new();

/// Counts a change of the areas and wakes the waits of `poll` on `/proc/swaps`.
fn touch() {
    EVENT.fetch_add(1, Ordering::Relaxed);
    POLL.wake_all();
}

/// The count of the changes of the areas. An open file of `/proc/swaps` has an event of
/// `POLLPRI` and `POLLERR` when the count changes, as `swaps_poll` of Linux. systemd watches the
/// file for its swap units.
pub fn event() -> u64 {
    EVENT.load(Ordering::Relaxed)
}

/// The queue that a change of the areas wakes.
pub fn poll_queue() -> &'static WaitQueue {
    &POLL
}

fn key(inode: &dyn Inode) -> usize {
    core::ptr::from_ref(inode).cast::<()>() as usize
}

/// Tells if `inode` is an active swap area, as `IS_SWAPFILE` of Linux.
pub fn is_active(inode: &dyn Inode) -> bool {
    if ACTIVE.load(Ordering::Acquire) == 0 {
        return false;
    }
    let k = key(inode);
    SWAPS.lock().iter().any(|s| s.inode().is_some_and(|i| key(&**i) == k))
}

/// Gives `ETXTBSY` if `inode` is an active swap area. A write, a truncate and a `fallocate` of
/// such a file give the error on Linux.
///
/// # Errors
///
/// Gives `ETXTBSY` for an active swap area.
pub fn check(inode: &dyn Inode) -> Result<()> {
    if is_active(inode) { Err(Errno::ETXTBSY) } else { Ok(()) }
}

/// Reads the header in `page`, the first page of an area, as `read_swap_header` of Linux. Gives
/// the number of pages that the header gives, with the first page.
///
/// # Errors
///
/// Gives `EINVAL` for a page without the magic of `mkswap`, a version other than 1, an area of
/// one page, or too many bad pages.
pub fn read_header(page: &[u8]) -> Result<u64> {
    if page.len() < PAGE_SIZE || &page[PAGE_SIZE - 10..PAGE_SIZE] != b"SWAPSPACE2" {
        return Err(Errno::EINVAL);
    }
    let field =
        |at: usize| u32::from_le_bytes([page[at], page[at + 1], page[at + 2], page[at + 3]]);
    // A header that a machine of the other byte order wrote has the fields swapped.
    let swapped = field(header::VERSION) != 1;
    let get = |at: usize| if swapped { field(at).swap_bytes() } else { field(at) };
    if get(header::VERSION) != 1 {
        return Err(Errno::EINVAL);
    }
    let last = get(header::LAST_PAGE);
    let bad = get(header::NR_BADPAGES);
    if last == 0 || bad > MAX_BADPAGES {
        return Err(Errno::EINVAL);
    }
    for i in 0..bad as usize {
        if get(header::BADPAGES + 4 * i) > last {
            return Err(Errno::EINVAL);
        }
    }
    Ok(u64::from(last) + 1)
}

/// The bad pages that the header in `page` lists. `read_header` checked the header.
fn bad_pages(page: &[u8]) -> Vec<u64> {
    let field =
        |at: usize| u32::from_le_bytes([page[at], page[at + 1], page[at + 2], page[at + 3]]);
    let swapped = field(header::VERSION) != 1;
    let get = |at: usize| if swapped { field(at).swap_bytes() } else { field(at) };
    let n = get(header::NR_BADPAGES).min(MAX_BADPAGES) as usize;
    (0..n).map(|i| u64::from(get(header::BADPAGES + 4 * i))).collect()
}

/// The pages of the regular file `file` that can be in an area of at most `max` pages, as
/// `iomap_swapfile_activate` of Linux finds them. Each block up to the end must be on the disk,
/// and an extent that is allocated but not written is good. Only the pages of the disk that the
/// file fully holds count, so a file without one such page gives `EINVAL`.
/// Gives the pages and the runs of the disk that hold them.
fn file_pages(file: &File, inode: &InodeRef, max: u64) -> Result<(u64, Vec<(u64, u64)>)> {
    // Linux makes the map of the file durable first.
    file.sync()?;
    let size = inode.metadata().size / PAGE_SIZE as u64 * PAGE_SIZE as u64;
    // A file system without extents cannot hold a swap area.
    let extents = inode.fiemap(0, size).map_err(|_| Errno::EINVAL)?;
    let runs = disk_runs(&extents, size)?;
    Ok((runs.iter().map(|r| r.1).sum::<u64>().min(max), runs))
}

/// The pages of the disk that the extents of the first `len` bytes of a file fully hold, at most
/// `max`, as `iomap_swapfile_iter` and `iomap_swapfile_add_extent` of Linux count them. Extents
/// that are next to each other on the disk join, and each run of the disk then counts only its
/// pages that are aligned to a page.
///
/// # Errors
///
/// Gives `EINVAL` for a hole, inline data, or no full page.
#[cfg(test)]
fn usable_pages(extents: &[FiemapExtent], len: u64, max: u64) -> Result<u64> {
    Ok(disk_runs(extents, len)?.iter().map(|r| r.1).sum::<u64>().min(max))
}

/// The runs of whole pages of the disk that the extents of the first `len` bytes of a file hold,
/// as the first page of the disk and the number of pages, as `usable_pages` counts them.
///
/// # Errors
///
/// Gives `EINVAL` for a hole, inline data, or no full page.
fn disk_runs(extents: &[FiemapExtent], len: u64) -> Result<Vec<(u64, u64)>> {
    let page = PAGE_SIZE as u64;
    let mut runs = Vec::new();
    // The pages of a run of the disk at `start` with `length` bytes.
    let mut aligned = |(start, length): (u64, u64)| {
        let first = start.div_ceil(page);
        let next = start.saturating_add(length) / page;
        if next > first {
            runs.push((first, next - first));
        }
    };
    let mut at = 0;
    let mut run: Option<(u64, u64)> = None;
    for e in extents {
        if at >= len {
            break;
        }
        let end = e.logical.saturating_add(e.length).min(len);
        if end <= at {
            continue;
        }
        if e.logical > at || e.inline {
            return Err(Errno::EINVAL);
        }
        let physical = e.physical + (at - e.logical);
        let length = end - at;
        run = match run {
            Some((start, n)) if start + n == physical => Some((start, n + length)),
            Some(r) => {
                aligned(r);
                Some((physical, length))
            }
            None => Some((physical, length)),
        };
        at = end;
    }
    if at < len {
        return Err(Errno::EINVAL);
    }
    if let Some(r) = run {
        aligned(r);
    }
    if runs.is_empty() {
        return Err(Errno::EINVAL);
    }
    Ok(runs)
}

/// Makes `file`, which `swapon` opened at `path`, an active swap area with the `swapon` flags
/// `swap_flags`. The caller checked the flags and the capability.
///
/// # Errors
///
/// Gives `EBUSY` if the file is an active area, `EINVAL` for a file that is not a regular file or
/// a block device, a bad header, a file with holes, or a file without a full page of the disk,
/// and `EPERM` if `MAX_SWAPFILES` areas are active.
pub fn activate(file: Arc<File>, path: Vec<u8>, swap_flags: u32) -> Result<()> {
    let inode = file.inode().ok_or(Errno::EINVAL)?.clone();
    let meta = inode.metadata();
    let partition = match meta.file_type() {
        Some(FileType::Regular) => false,
        Some(FileType::BlockDevice) => true,
        _ => return Err(Errno::EINVAL),
    };
    if is_active(&*inode) {
        return Err(Errno::EBUSY);
    }
    let mut page = alloc::vec![0u8; PAGE_SIZE];
    let mut done = 0;
    while done < PAGE_SIZE {
        let n = file.read_at(done as u64, &mut page[done..])?;
        if n == 0 {
            return Err(Errno::EINVAL);
        }
        done += n;
    }
    let max = read_header(&page)?;
    // An area on a file system without a disk, as a file of a FUSE file system, has no queue.
    // `swapon` accepts it, and no entry goes to it.
    let queue = crate::blockdev::block_queue(if partition { meta.rdev } else { meta.dev });
    let (pages, runs) = if partition {
        // The pages that `mkswap` wrote through the cache of the device go to the disk first,
        // as the writes of the area go to the disk directly.
        file.sync()?;
        // The inode of the device node has no size. The size is the size of the disk, as
        // `bdev_nr_bytes` of Linux.
        let size = queue.as_ref().map_or(0, |q| q.sectors() * crate::blockdev::SECTOR_SIZE as u64);
        let pages = max.min(size / PAGE_SIZE as u64);
        (pages, alloc::vec![(0, pages)])
    } else {
        file_pages(&file, &inode, max)?
    };
    if pages <= 1 {
        return Err(Errno::EINVAL);
    }
    let disk = queue.map(|queue| Disk { queue, runs });
    let slots = Slots::new(pages, &bad_pages(&page));
    let priority = if swap_flags & flags::SWAP_FLAG_PREFER != 0 {
        (swap_flags & flags::SWAP_FLAG_PRIO_MASK) as i32
    } else {
        let mut least = LEAST.lock();
        *least -= 1;
        *least
    };
    let mut swaps = SWAPS.lock();
    if swaps.len() >= MAX_SWAPFILES {
        return Err(Errno::EPERM);
    }
    if swaps.iter().any(|s| s.inode().is_some_and(|i| Arc::ptr_eq(i, &inode))) {
        return Err(Errno::EBUSY);
    }
    let kind = (0..MAX_SWAPFILES as u64).find(|k| swaps.iter().all(|s| s.kind != *k)).unwrap_or(0);
    swaps.push(Swap { file, kind, slots, disk, path, partition, pages: pages - 1, priority });
    ACTIVE.store(swaps.len(), Ordering::Release);
    drop(swaps);
    touch();
    Ok(())
}

/// Ends the active swap area of `inode`, for `swapoff`.
///
/// # Errors
///
/// Gives `EINVAL` if `inode` is not an active area, and `EBUSY` if entries use pages of the area.
/// rukernel does not read the pages back into memory yet, as `try_to_unuse` of Linux does.
pub fn deactivate(inode: &InodeRef) -> Result<()> {
    let mut swaps = SWAPS.lock();
    let i = swaps
        .iter()
        .position(|s| s.inode().is_some_and(|x| Arc::ptr_eq(x, inode)))
        .ok_or(Errno::EINVAL)?;
    if swaps[i].slots.inuse > 0 {
        return Err(Errno::EBUSY);
    }
    let swap = swaps.remove(i);
    ACTIVE.store(swaps.len(), Ordering::Release);
    // The areas after it with a priority that `swapon` gave move up, as `swapoff` of Linux.
    if swap.priority < 0 {
        for s in swaps.iter_mut().filter(|s| s.priority < swap.priority) {
            s.priority += 1;
        }
        *LEAST.lock() += 1;
    }
    drop(swaps);
    drop(swap);
    touch();
    Ok(())
}

/// Calls `f` with each active area, in the order of `swapon`.
pub fn for_each(mut f: impl FnMut(&Swap)) {
    for s in SWAPS.lock().iter() {
        f(s);
    }
}

/// The number of pages in all the active areas.
pub fn total_pages() -> u64 {
    if ACTIVE.load(Ordering::Acquire) == 0 {
        return 0;
    }
    SWAPS.lock().iter().map(|s| s.pages).sum()
}

/// The number of pages that entries use in all the active areas.
pub fn used_pages() -> u64 {
    if ACTIVE.load(Ordering::Acquire) == 0 {
        return 0;
    }
    SWAPS.lock().iter().map(|s| s.slots.inuse).sum()
}

/// Gives a free page of an area as a swap entry, as `folio_alloc_swap` of Linux. The area with
/// the highest priority that has a free page and a disk gives it. Gives `None` if no area has a
/// free page.
pub fn alloc() -> Option<u64> {
    if ACTIVE.load(Ordering::Acquire) == 0 {
        return None;
    }
    let mut swaps = SWAPS.lock();
    let mut order: Vec<usize> = (0..swaps.len()).filter(|&i| swaps[i].disk.is_some()).collect();
    order.sort_by_key(|&i| core::cmp::Reverse(swaps[i].priority));
    order.into_iter().find_map(|i| {
        let s = &mut swaps[i];
        s.slots.alloc().map(|page| entry(s.kind, page))
    })
}

/// Makes the page of the swap entry `e` free, as `swap_entries_free` of Linux. An entry of an
/// area that is not active does nothing.
pub fn free(e: u64) {
    let (kind, page) = split(e);
    if let Some(s) = SWAPS.lock().iter_mut().find(|s| s.kind == kind) {
        s.slots.free(page);
    }
}

/// The queue and the sector of the disk of the swap entry `e`.
fn locate(e: u64) -> Result<(Arc<Queue>, u64)> {
    let (kind, page) = split(e);
    let swaps = SWAPS.lock();
    let s = swaps.iter().find(|s| s.kind == kind && page > 0 && page < s.slots.pages);
    let disk = s.and_then(|s| s.disk.as_ref()).ok_or(Errno::EINVAL)?;
    let sector = sector(&disk.runs, page).ok_or(Errno::EINVAL)?;
    Ok((disk.queue.clone(), sector))
}

/// Writes the page `data` to the swap entry `e`, with direct I/O to the disk.
///
/// # Errors
///
/// Gives `EINVAL` for an entry of no active area, and the error of the disk.
pub fn write_page(e: u64, data: &[u8]) -> Result<()> {
    let (queue, sector) = locate(e)?;
    queue.write(sector, &data[..PAGE_SIZE])
}

/// Reads the page of the swap entry `e` into `buf`, with direct I/O from the disk.
///
/// # Errors
///
/// Gives `EINVAL` for an entry of no active area, and the error of the disk.
pub fn read_page(e: u64, buf: &mut [u8]) -> Result<()> {
    let (queue, sector) = locate(e)?;
    queue.read(sector, &mut buf[..PAGE_SIZE])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(last: u32, bad: &[u32]) -> Vec<u8> {
        let mut p = alloc::vec![0u8; PAGE_SIZE];
        p[PAGE_SIZE - 10..].copy_from_slice(b"SWAPSPACE2");
        p[header::VERSION..header::VERSION + 4].copy_from_slice(&1u32.to_le_bytes());
        p[header::LAST_PAGE..header::LAST_PAGE + 4].copy_from_slice(&last.to_le_bytes());
        let n = (bad.len() as u32).to_le_bytes();
        p[header::NR_BADPAGES..header::NR_BADPAGES + 4].copy_from_slice(&n);
        for (i, b) in bad.iter().enumerate() {
            let at = header::BADPAGES + 4 * i;
            p[at..at + 4].copy_from_slice(&b.to_le_bytes());
        }
        p
    }

    #[test]
    fn the_slots_skip_the_header_and_the_bad_pages() {
        let mut s = Slots::new(70, &[2, 65]);
        let mut got = Vec::new();
        while let Some(p) = s.alloc() {
            got.push(p);
        }
        let want: Vec<u64> = (1..70).filter(|p| *p != 2 && *p != 65).collect();
        assert_eq!(got, want);
        assert_eq!(s.inuse, 67);
        assert!(s.free(30));
        assert!(!s.free(30));
        assert!(!s.free(0));
        assert!(!s.free(70));
        assert_eq!(s.alloc(), Some(30));
        assert_eq!(s.alloc(), None);
    }

    #[test]
    fn an_entry_has_the_type_and_the_page() {
        assert_eq!(split(entry(3, 12345)), (3, 12345));
        assert_eq!(bad_pages(&page(9, &[3, 7])), [3, 7]);
    }

    #[test]
    fn the_runs_of_a_file_give_the_sectors() {
        let p = PAGE_SIZE as u64;
        let runs = disk_runs(&[extent(0, 4 * p, 2 * p), extent(2 * p, 10 * p, 3 * p)], 5 * p);
        assert_eq!(runs, Ok(alloc::vec![(4, 2), (10, 3)]));
        let runs = [(4, 2), (10, 3)];
        assert_eq!(sector(&runs, 1), Some(5 * 8));
        assert_eq!(sector(&runs, 2), Some(10 * 8));
        assert_eq!(sector(&runs, 5), None);
    }

    #[test]
    fn the_header_of_mkswap_gives_the_pages() {
        assert_eq!(read_header(&page(9, &[])), Ok(10));
        assert_eq!(read_header(&page(2, &[1])), Ok(3));
        let mut swapped = page(9, &[]);
        swapped[header::VERSION..header::VERSION + 4].copy_from_slice(&1u32.to_be_bytes());
        swapped[header::LAST_PAGE..header::LAST_PAGE + 4].copy_from_slice(&9u32.to_be_bytes());
        assert_eq!(read_header(&swapped), Ok(10));
    }

    #[test]
    fn a_bad_header_gives_einval() {
        assert_eq!(read_header(&page(0, &[])), Err(Errno::EINVAL));
        assert_eq!(read_header(&page(9, &[10])), Err(Errno::EINVAL));
        let mut old = page(9, &[]);
        old[PAGE_SIZE - 10..].copy_from_slice(b"SWAP-SPACE");
        assert_eq!(read_header(&old), Err(Errno::EINVAL));
        let mut v2 = page(9, &[]);
        v2[header::VERSION] = 2;
        assert_eq!(read_header(&v2), Err(Errno::EINVAL));
        assert_eq!(read_header(&[0u8; 100]), Err(Errno::EINVAL));
    }

    fn extent(logical: u64, physical: u64, length: u64) -> FiemapExtent {
        FiemapExtent { logical, physical, length, unwritten: false, inline: false, delalloc: false }
    }

    #[test]
    fn the_aligned_pages_of_the_disk_count() {
        let p = PAGE_SIZE as u64;
        assert_eq!(usable_pages(&[extent(0, 4 * p, 10 * p)], 10 * p, 100), Ok(10));
        assert_eq!(usable_pages(&[extent(0, 4 * p, 10 * p)], 10 * p, 6), Ok(6));
        // Two extents that are next to each other on the disk join.
        let joined = [extent(0, p + 1024, p), extent(p, 2 * p + 1024, p)];
        assert_eq!(usable_pages(&joined, 2 * p, 100), Ok(1));
        // An extent that is not written is good.
        let mut unwritten = extent(0, 0, 2 * p);
        unwritten.unwritten = true;
        assert_eq!(usable_pages(&[unwritten], 2 * p, 100), Ok(2));
    }

    #[test]
    fn a_file_without_a_full_page_of_the_disk_gives_einval() {
        // As generic/641: blocks of 1024 bytes, and runs of three blocks with a gap between them.
        let b = 1024;
        let p = PAGE_SIZE as u64;
        let runs: Vec<_> =
            (0..4).map(|i| extent(3 * b * i, 1_000_000 * b + 4 * b * i, 3 * b)).collect();
        assert_eq!(usable_pages(&runs, 3 * p, 100), Err(Errno::EINVAL));
        assert_eq!(usable_pages(&[], 0, 100), Err(Errno::EINVAL));
    }

    #[test]
    fn a_hole_or_inline_data_gives_einval() {
        let p = PAGE_SIZE as u64;
        let hole = [extent(0, 0, p), extent(2 * p, 2 * p, p)];
        assert_eq!(usable_pages(&hole, 3 * p, 100), Err(Errno::EINVAL));
        assert_eq!(usable_pages(&[extent(0, 0, p)], 2 * p, 100), Err(Errno::EINVAL));
        let mut inline = extent(0, 0, p);
        inline.inline = true;
        assert_eq!(usable_pages(&[inline], p, 100), Err(Errno::EINVAL));
    }
}

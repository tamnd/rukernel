//! The swap areas of `swapon` and `swapoff`.
//!
//! A swap area is a regular file or a block device with the header of `mkswap`. `swapon` examines
//! the header and the blocks of the file, as Linux does, and then the area is active: a write, a
//! truncate, a `fallocate` and a shared writable mapping of the file give `ETXTBSY`, and
//! `/proc/swaps` shows the area. rukernel does not move pages to a swap area yet, so the used
//! count of each area stays 0.

use crate::FileType;
use crate::file::File;
use crate::inode::{FiemapExtent, Inode, InodeRef, Result};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use rk_abi::Errno;
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

/// An active swap area.
pub struct Swap {
    file: Arc<File>,
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
}

/// The active areas, in the order of `swapon`.
static SWAPS: SpinLock<Vec<Swap>> = SpinLock::new(Vec::new());
/// The number of active areas, so that a write does not take the lock when there is none.
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
/// The priority of the last area without `SWAP_FLAG_PREFER`.
static LEAST: SpinLock<i32> = SpinLock::new(-1);

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

/// The pages of the regular file `file` that can be in an area of at most `max` pages, as
/// `iomap_swapfile_activate` of Linux finds them. Each block up to the end must be on the disk,
/// and an extent that is allocated but not written is good. Only the pages of the disk that the
/// file fully holds count, so a file without one such page gives `EINVAL`.
fn file_pages(file: &File, inode: &InodeRef, max: u64) -> Result<u64> {
    // Linux makes the map of the file durable first.
    file.sync()?;
    let size = inode.metadata().size / PAGE_SIZE as u64 * PAGE_SIZE as u64;
    // A file system without extents cannot hold a swap area.
    let extents = inode.fiemap(0, size).map_err(|_| Errno::EINVAL)?;
    usable_pages(&extents, size, max)
}

/// The pages of the disk that the extents of the first `len` bytes of a file fully hold, at most
/// `max`, as `iomap_swapfile_iter` and `iomap_swapfile_add_extent` of Linux count them. Extents
/// that are next to each other on the disk join, and each run of the disk then counts only its
/// pages that are aligned to a page.
///
/// # Errors
///
/// Gives `EINVAL` for a hole, inline data, or no full page.
fn usable_pages(extents: &[FiemapExtent], len: u64, max: u64) -> Result<u64> {
    let page = PAGE_SIZE as u64;
    // The pages of a run of the disk at `start` with `length` bytes.
    let aligned = |(start, length): (u64, u64)| {
        let first = start.div_ceil(page);
        let next = start.saturating_add(length) / page;
        next.saturating_sub(first)
    };
    let mut at = 0;
    let mut run: Option<(u64, u64)> = None;
    let mut pages: u64 = 0;
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
                pages = pages.saturating_add(aligned(r));
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
        pages = pages.saturating_add(aligned(r));
    }
    if pages == 0 {
        return Err(Errno::EINVAL);
    }
    Ok(pages.min(max))
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
    let pages = if partition {
        let size = file.metadata()?.size;
        max.min(size / PAGE_SIZE as u64)
    } else {
        file_pages(&file, &inode, max)?
    };
    if pages <= 1 {
        return Err(Errno::EINVAL);
    }
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
    swaps.push(Swap { file, path, partition, pages: pages - 1, priority });
    ACTIVE.store(swaps.len(), Ordering::Release);
    Ok(())
}

/// Ends the active swap area of `inode`, for `swapoff`.
///
/// # Errors
///
/// Gives `EINVAL` if `inode` is not an active area.
pub fn deactivate(inode: &InodeRef) -> Result<()> {
    let mut swaps = SWAPS.lock();
    let i = swaps
        .iter()
        .position(|s| s.inode().is_some_and(|x| Arc::ptr_eq(x, inode)))
        .ok_or(Errno::EINVAL)?;
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

//! The pool of huge pages in the kernel, and the files of huge pages.
//!
//! The pool keeps `HugeRun` values of rk-frame. A page fault takes a run, and the run comes back
//! to the pool through the hook of rk-frame when the last of its frames is dropped. A
//! [`HugeFile`] keeps the huge pages of a file of hugetlbfs, of a `SHM_HUGETLB` segment or of a
//! shared `MAP_HUGETLB` mapping, as the page cache of the inode of hugetlbfs in Linux.

use super::{AddressSpace, MmFile, above_reserve};
use crate::hugetlb::{Counts, HPAGE_SIZE, Pool};
use crate::tunables;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::mm::{Frame, HUGE_FRAMES, HugeRun, frame_stats, set_huge_return_hook};
use rk_frame::sync::{Once, SpinLock};

/// A huge page: the run of `HUGE_FRAMES` frames, in order.
pub type HugePage = Vec<Arc<Frame>>;

static POOL: SpinLock<Pool<HugeRun>> = SpinLock::new(Pool::new());
static HOOK: Once<()> = Once::new();

/// Runs `f` on the pool. The hook of rk-frame is set before the first use.
fn with_pool<R>(f: impl FnOnce(&mut Pool<HugeRun>) -> R) -> R {
    HOOK.call_once(|| set_huge_return_hook(give_back));
    f(&mut POOL.lock())
}

/// Takes a run back from the last frame of a huge page. A surplus page goes back to the
/// allocator, after the lock of the pool is released.
fn give_back(run: HugeRun) {
    let gone = with_pool(|p| p.give_back(run));
    drop(gone);
}

/// Takes a new run from the allocator for the pool. The pool does not take the last memory: an
/// eighth of the memory and the reserve of `vm.min_free_kbytes` stay for the rest of the kernel.
fn new_run() -> Option<HugeRun> {
    let stats = frame_stats();
    let keep = tunables::reserve_pages(stats.total) + stats.total / 8;
    if stats.free < HUGE_FRAMES + keep {
        return None;
    }
    HugeRun::alloc()
}

/// The address spaces that map a file of hugetlbfs, so a truncate or a hole can remove the pages
/// that go away from them, as `hugetlb_vmdelete_list` of Linux does with the `i_mmap` tree.
static SPACES: SpinLock<Vec<Weak<AddressSpace>>> = SpinLock::new(Vec::new());

/// Adds `space` to the address spaces that a truncate of a file of hugetlbfs examines, if it maps
/// such a file. The list forgets the address spaces that went away.
pub fn track(space: &Arc<AddressSpace>) {
    if !space.maps_huge_file() {
        return;
    }
    let mut spaces = SPACES.lock();
    spaces.retain(|w| w.strong_count() > 0);
    if !spaces.iter().any(|w| core::ptr::eq(w.as_ptr(), Arc::as_ptr(space))) {
        spaces.push(Arc::downgrade(space));
    }
}

/// Removes the pages `first..end` of `file` from each address space that maps them.
fn unmap_pages(file: &HugeFile, first: u64, end: u64) {
    let spaces: Vec<Arc<AddressSpace>> = SPACES.lock().iter().filter_map(Weak::upgrade).collect();
    for space in &spaces {
        space.unmap_huge_file(file, first, end);
    }
    // An address space that goes away now does it after the lock of the list is released.
    drop(spaces);
}

/// The counters of the pool.
pub fn counts() -> Counts {
    with_pool(|p| p.counts())
}

/// Sets `vm.nr_hugepages`, the persistent pages of the pool. The pool can get fewer pages if the
/// memory is not enough, as on Linux.
pub fn set_nr_hugepages(count: usize) {
    let gone = with_pool(|p| p.set_persistent(count, new_run));
    drop(gone);
}

/// Sets `vm.nr_overcommit_hugepages`, the most surplus pages.
pub fn set_nr_overcommit_hugepages(count: usize) {
    with_pool(|p| p.set_overcommit(count));
}

/// Reserves `n` huge pages for a new mapping or segment.
///
/// # Errors
///
/// `ENOMEM` if the pool does not have the pages.
pub fn reserve(n: usize) -> Result<(), Errno> {
    if n == 0 {
        return Ok(());
    }
    let (ok, gone) = with_pool(|p| p.reserve(n, new_run));
    drop(gone);
    if ok { Ok(()) } else { Err(Errno::ENOMEM) }
}

/// Removes `n` reservations that no page used.
pub fn unreserve(n: usize) {
    if n != 0 {
        let gone = with_pool(|p| p.unreserve(n));
        drop(gone);
    }
}

/// Takes a huge page with zeros from the pool. `reserved` tells that the caller has a
/// reservation for it.
///
/// # Errors
///
/// `ENOSPC` if the pool has no page for the caller. A page fault then sends `SIGBUS`, as on Linux.
pub fn alloc_page(reserved: bool) -> Result<HugePage, Errno> {
    let run = with_pool(|p| p.take(reserved, new_run)).ok_or(Errno::ENOSPC)?;
    Ok(run.into_frames().into_iter().map(Arc::new).collect())
}

/// Takes a copy of the huge page `from` from the pool, for copy on write.
///
/// # Errors
///
/// As for `alloc_page`.
pub fn copy_page(from: &[Arc<Frame>], reserved: bool) -> Result<HugePage, Errno> {
    let copy = alloc_page(reserved)?;
    for (to, from) in copy.iter().zip(from) {
        to.copy_from(from);
    }
    Ok(copy)
}

/// Takes a transparent huge page from the allocator for copy on write, and copies `from` to it.
/// Gives `None` if no run is free, so the caller copies one page of 4 KiB.
pub(super) fn copy_thp(from: &[Arc<Frame>], memcg: u32) -> Option<HugePage> {
    let stats = frame_stats();
    if stats.free < HUGE_FRAMES + tunables::reserve_pages(stats.total) || above_reserve().is_err() {
        return None;
    }
    let frames = rk_frame::mm::alloc_huge_frames()?;
    let copy = super::charge_block(frames, memcg)?;
    for (to, from) in copy.iter().zip(from) {
        to.copy_from(from);
    }
    Some(copy)
}

struct FileState {
    /// The huge pages, by the index of the huge page in the file.
    pages: BTreeMap<u64, HugePage>,
    /// The indexes that a shared mapping reserved and that have no page yet.
    reserved: BTreeSet<u64>,
    /// The size of the file in bytes.
    size: u64,
}

/// The huge pages of one file of hugetlbfs, of a `SHM_HUGETLB` segment or of a shared
/// `MAP_HUGETLB` mapping. Each mapping of the file finds the same pages. A page stays until the
/// file is truncated or goes away.
pub struct HugeFile {
    state: SpinLock<FileState>,
    /// The device, the inode number and the path, for /proc/PID/maps.
    name: SpinLock<(u64, u64, Vec<u8>)>,
}

/// The number of huge pages for `bytes` bytes.
fn huge_pages(bytes: u64) -> u64 {
    bytes.div_ceil(HPAGE_SIZE as u64)
}

impl HugeFile {
    /// Makes an empty file of `size` bytes with the name `name` for /proc/PID/maps.
    pub fn new(dev: u64, ino: u64, path: Vec<u8>, size: u64) -> Arc<Self> {
        let state = FileState { pages: BTreeMap::new(), reserved: BTreeSet::new(), size };
        Arc::new(Self { state: SpinLock::new(state), name: SpinLock::new((dev, ino, path)) })
    }

    /// Sets the path that /proc/PID/maps shows.
    pub fn set_path(&self, path: Vec<u8>) {
        self.name.lock().2 = path;
    }

    /// The size of the file in bytes.
    pub fn size(&self) -> u64 {
        self.state.lock().size
    }

    /// The number of huge pages that the file has.
    pub fn page_count(&self) -> usize {
        self.state.lock().pages.len()
    }

    /// Makes the file at least `size` bytes long, as a writable mapping of hugetlbfs does.
    pub fn grow_to(&self, size: u64) {
        let mut st = self.state.lock();
        st.size = st.size.max(size);
    }

    /// Changes the size of the file. The pages and the reservations after the new end go, and the
    /// address spaces that map them lose them.
    pub fn set_size(&self, size: u64) {
        let first = huge_pages(size);
        let (gone, unused) = {
            let mut st = self.state.lock();
            st.size = size;
            let gone = st.pages.split_off(&first);
            let unused = st.reserved.split_off(&first).len();
            (gone, unused)
        };
        unmap_pages(self, first, u64::MAX);
        drop(gone);
        unreserve(unused);
    }

    /// Reserves the huge pages `first..end` of the file for a shared mapping, as
    /// `hugetlb_reserve_pages` of Linux. A page that the file has, or that another mapping
    /// reserved, needs no new reservation.
    ///
    /// # Errors
    ///
    /// `ENOMEM` if the pool does not have the pages.
    pub fn reserve(&self, first: u64, end: u64) -> Result<(), Errno> {
        let mut st = self.state.lock();
        let new: Vec<u64> = (first..end)
            .filter(|i| !st.pages.contains_key(i) && !st.reserved.contains(i))
            .collect();
        reserve(new.len())?;
        st.reserved.extend(new);
        Ok(())
    }

    /// Gives the huge page `index`, if the file has it.
    pub fn lookup(&self, index: u64) -> Option<HugePage> {
        self.state.lock().pages.get(&index).cloned()
    }

    /// Gives the huge page `index`, and takes it from the pool if the file does not have it.
    ///
    /// # Errors
    ///
    /// `ENXIO` for a page after the end of the file, and `ENOSPC` if the pool has no page. A
    /// page fault sends `SIGBUS` for each.
    pub fn page_at(&self, index: u64) -> Result<HugePage, Errno> {
        let mut st = self.state.lock();
        if index >= huge_pages(st.size) {
            return Err(Errno::ENXIO);
        }
        if let Some(page) = st.pages.get(&index) {
            return Ok(page.clone());
        }
        let reserved = st.reserved.remove(&index);
        match alloc_page(reserved) {
            Ok(page) => {
                st.pages.insert(index, page.clone());
                Ok(page)
            }
            Err(e) => {
                if reserved {
                    st.reserved.insert(index);
                }
                Err(e)
            }
        }
    }

    /// Gives a page to each index in `first..end` that has none, for `fallocate`. The size of
    /// the file does not change.
    ///
    /// # Errors
    ///
    /// `ENOSPC` if the pool has no page.
    pub fn allocate(&self, first: u64, end: u64) -> Result<(), Errno> {
        for index in first..end {
            let mut st = self.state.lock();
            if st.pages.contains_key(&index) {
                continue;
            }
            let reserved = st.reserved.remove(&index);
            match alloc_page(reserved) {
                Ok(page) => {
                    st.pages.insert(index, page);
                }
                Err(e) => {
                    if reserved {
                        st.reserved.insert(index);
                    }
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Removes the pages and the reservations of `first..end`, for `FALLOC_FL_PUNCH_HOLE`. The
    /// address spaces that map the pages lose them.
    pub fn punch(&self, first: u64, end: u64) {
        if first >= end {
            return;
        }
        let (gone, unused) = {
            let mut st = self.state.lock();
            let mut gone = Vec::new();
            let indexes: Vec<u64> = st.pages.range(first..end).map(|(&i, _)| i).collect();
            for i in indexes {
                gone.extend(st.pages.remove(&i));
            }
            let reserved: Vec<u64> = st.reserved.range(first..end).copied().collect();
            for i in &reserved {
                st.reserved.remove(i);
            }
            (gone, reserved.len())
        };
        unmap_pages(self, first, end);
        drop(gone);
        unreserve(unused);
    }

    /// Writes zeros to `offset..offset + len` in the pages that the file has, as
    /// `hugetlbfs_zero_partial_page` of Linux does for the ends of a hole.
    pub fn zero(&self, offset: u64, len: u64) {
        let page = rk_frame::addr::PAGE_SIZE as u64;
        let mut at = offset;
        let end = offset.saturating_add(len);
        while at < end {
            let index = at / HPAGE_SIZE as u64;
            let in_page = at % HPAGE_SIZE as u64;
            let n = (page - in_page % page).min(end - at);
            if let Some(frames) = self.lookup(index) {
                frames[(in_page / page) as usize].fill_zero((in_page % page) as usize, n as usize);
            }
            at += n;
        }
    }

    /// Copies the bytes at `offset` to `buf`, up to the end of the file. A hole reads as zeros.
    /// Gives the number of bytes.
    pub fn read(&self, offset: u64, buf: &mut [u8]) -> usize {
        let size = self.size();
        let len = usize::try_from(size.saturating_sub(offset)).unwrap_or(usize::MAX);
        let len = len.min(buf.len());
        let mut done = 0;
        while done < len {
            let at = offset + done as u64;
            let index = at / HPAGE_SIZE as u64;
            let in_page = (at % HPAGE_SIZE as u64) as usize;
            let frame = in_page / rk_frame::addr::PAGE_SIZE;
            let in_frame = in_page % rk_frame::addr::PAGE_SIZE;
            let n = (rk_frame::addr::PAGE_SIZE - in_frame).min(len - done);
            match self.lookup(index) {
                Some(page) => page[frame].read_bytes(in_frame, &mut buf[done..done + n]),
                None => buf[done..done + n].fill(0),
            }
            done += n;
        }
        len
    }
}

impl Drop for HugeFile {
    fn drop(&mut self) {
        let unused = self.state.lock().reserved.len();
        unreserve(unused);
    }
}

impl MmFile for HugeFile {
    fn page(&self, index: u64) -> Result<Arc<Frame>, Errno> {
        let page = self.page_at(index / HUGE_FRAMES as u64)?;
        Ok(page[(index % HUGE_FRAMES as u64) as usize].clone())
    }

    fn name(&self) -> (u64, u64, Vec<u8>) {
        self.name.lock().clone()
    }

    fn huge_file(&self) -> Option<&HugeFile> {
        Some(self)
    }
}

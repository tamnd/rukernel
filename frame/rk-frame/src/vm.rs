//! User address spaces.
//!
//! A `VmSpace` is the page table of one process. The user half is its own, and the kernel half is
//! the same in each address space. The kernel loads the address space of a process before it runs
//! the user code of the process.
//!
//! The address space owns the frames that it maps. Each frame is in an `Arc`, so two address
//! spaces can map the same frame, after `fork` or for a `MAP_SHARED` mapping, and a file can keep
//! the frame in its page cache. A frame goes back to the allocator when the last `Arc` goes.
//!
//! A run of 512 frames that is 2 MiB aligned can be mapped at a 2 MiB aligned address with one
//! huge entry, as the transparent huge pages of Linux. Each frame of the run is still a page of the
//! address space, but the space keeps one entry for the huge page and not one for each page, so a
//! `fork` and the exit of a process do not walk 512 entries for it. A change to one page of the run
//! splits the huge entry into a last level table first, and the pages get their own entries then.
//! The table for the split is made when the huge page is mapped, as the deposited table of Linux,
//! so a split cannot fail.
//!
//! The kernel reads and writes user memory with `read` and `write`. These functions walk the page
//! table in software and copy through the direct map, so they work on an address space that is not
//! active too. A page that is not mapped gives a `UserFault`. The memory manager handles the fault
//! and tries the copy again.

use crate::addr::{PAGE_SIZE, VirtAddr};
use crate::arch::imp::paging;
use crate::mm::frame::free_frame_phys;
use crate::mm::{Frame, HUGE_FRAMES};
use crate::sync::SpinLock;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

/// The end of the user half of the address space. Each user address is below it.
pub const USER_END: usize = paging::USER_END;

/// The size of a huge page.
pub const HUGE_PAGE_SIZE: usize = HUGE_FRAMES * PAGE_SIZE;

/// The number of huge pages that the address spaces map now.
static HUGE_MAPPED: AtomicUsize = AtomicUsize::new(0);

/// The number of huge pages that the address spaces map now. /proc/meminfo shows it as
/// `AnonHugePages`.
pub fn huge_pages_mapped() -> usize {
    HUGE_MAPPED.load(Ordering::Relaxed)
}

/// The permissions of a user page. A page that allows no access keeps its frame, but each access
/// to it is a page fault. On x86-64, a page that allows a write or an instruction fetch can also
/// be read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PageProt {
    /// A read is allowed.
    pub readable: bool,
    /// A write is allowed.
    pub writable: bool,
    /// An instruction fetch is allowed.
    pub executable: bool,
}

impl PageProt {
    /// A page that allows no access.
    pub const NONE: Self = Self { readable: false, writable: false, executable: false };

    fn bits(self) -> paging::UserProt {
        (self.readable, self.writable, self.executable)
    }

    fn allows(self, write: bool) -> bool {
        if write { self.writable } else { self.readable || self.writable || self.executable }
    }
}

/// Why a page could not be mapped.
#[derive(Debug, PartialEq, Eq)]
pub enum MapError {
    /// The address is not page aligned or is not in the user half.
    BadAddress,
    /// A page is mapped at the address already.
    Mapped,
    /// No frame is free for a page table.
    NoMemory,
}

/// An area of the parent that `VmSpace::fork` copies to the child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkArea {
    /// The first address of the area. It is page aligned.
    pub start: usize,
    /// The end of the area. It is page aligned.
    pub end: usize,
    /// The area is shared, so both spaces keep the permissions of each page. A private area is
    /// read only in both spaces, so the first write in either one copies the page.
    pub shared: bool,
}

impl ForkArea {
    /// The permissions of a page of the area after the fork, in both spaces.
    fn prot(self, prot: PageProt) -> PageProt {
        if self.shared { prot } else { PageProt { writable: false, ..prot } }
    }
}

/// An access to user memory found a page that is not mapped, or a write found a page that is not
/// writable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserFault {
    /// The first address that the access could not use.
    pub addr: usize,
    /// The access was a write.
    pub write: bool,
}

/// A huge page of an address space.
struct Huge {
    /// The last level table for the split of the page.
    table: u64,
    /// The page is a transparent huge page. A page of hugetlbfs is not.
    thp: bool,
    /// The `HUGE_FRAMES` frames of the page, in address order.
    frames: Vec<Arc<Frame>>,
    /// The permissions of each page of the huge page.
    prot: PageProt,
}

struct Inner {
    /// The physical address of the top level table.
    root: u64,
    /// The frame and the permissions at each mapped page address that is not in a huge page.
    pages: BTreeMap<usize, (Arc<Frame>, PageProt)>,
    /// The huge pages by their address. No address of `pages` is in a huge page.
    huge: BTreeMap<usize, Huge>,
}

/// The address of the huge page that contains `addr`.
fn block_of(addr: usize) -> usize {
    addr & !(HUGE_PAGE_SIZE - 1)
}

impl Inner {
    /// Gives the frame and the permissions of the page at the page address `addr`.
    fn get(&self, addr: usize) -> Option<(&Arc<Frame>, PageProt)> {
        if let Some((frame, prot)) = self.pages.get(&addr) {
            return Some((frame, *prot));
        }
        let block = block_of(addr);
        let huge = self.huge.get(&block)?;
        Some((&huge.frames[(addr - block) / PAGE_SIZE], huge.prot))
    }

    /// Changes the huge page that contains `addr`, if there is one, to 4 KiB pages.
    fn split(&mut self, addr: usize) {
        let block = block_of(addr);
        if let Some(huge) = self.huge.remove(&block) {
            paging::user_split_huge(self.root, block, huge.table);
            if huge.thp {
                HUGE_MAPPED.fetch_sub(1, Ordering::Relaxed);
            }
            let pages = huge.frames.into_iter().enumerate();
            self.pages.extend(pages.map(|(i, f)| (block + i * PAGE_SIZE, (f, huge.prot))));
        }
    }

    /// Calls `f` for each mapped page address in `start..end`, in order.
    fn each_page(&self, start: usize, end: usize, mut f: impl FnMut(usize)) {
        let mut small = self.pages.range(start..end).map(|(&a, _)| a).peekable();
        for &block in self.huge.range(block_of(start)..end).map(|(b, _)| b) {
            let (from, to) = (block.max(start), (block + HUGE_PAGE_SIZE).min(end));
            while let Some(a) = small.next_if(|&a| a < from) {
                f(a);
            }
            (from..to).step_by(PAGE_SIZE).for_each(&mut f);
        }
        small.for_each(f);
    }

    /// The number of mapped pages in `start..end`.
    fn count(&self, start: usize, end: usize) -> usize {
        let huge = self
            .huge
            .range(block_of(start)..end)
            .map(|(&block, _)| ((block + HUGE_PAGE_SIZE).min(end) - block.max(start)) / PAGE_SIZE);
        self.pages.range(start..end).count() + huge.sum::<usize>()
    }
}

/// The page table of one user address space.
pub struct VmSpace {
    inner: SpinLock<Inner>,
    /// A copy of `Inner::root`, which does not change. `activate` reads it without the lock.
    root: u64,
}

impl VmSpace {
    /// Makes an empty address space. Gives `None` if no frame is free for the top level table.
    pub fn new() -> Option<Self> {
        let root = paging::new_user_root()?;
        let inner = Inner { root, pages: BTreeMap::new(), huge: BTreeMap::new() };
        Some(Self { inner: SpinLock::new(inner), root })
    }

    /// Maps `frame` at the user address `addr`.
    ///
    /// # Errors
    ///
    /// Gives an error if `addr` is not page aligned or not in the user half, if a page is mapped
    /// there already, or if no frame is free for a page table.
    pub fn map(&self, addr: VirtAddr, frame: Arc<Frame>, prot: PageProt) -> Result<(), MapError> {
        let a = addr.get();
        if !a.is_multiple_of(PAGE_SIZE) || a >= USER_END {
            return Err(MapError::BadAddress);
        }
        let mut inner = self.inner.lock();
        if inner.get(a).is_some() {
            return Err(MapError::Mapped);
        }
        paging::user_map(inner.root, a, frame.addr().get(), prot.bits())
            .map_err(|()| MapError::NoMemory)?;
        inner.pages.insert(a, (frame, prot));
        Ok(())
    }

    /// Maps the run of `HUGE_FRAMES` frames in `frames` at `addr` with one huge entry.
    ///
    /// # Errors
    ///
    /// Gives an error if `addr` is not 2 MiB aligned or not in the user half, if a page is mapped
    /// in the range already, or if no frame is free for a page table.
    ///
    /// # Panics
    ///
    /// If `frames` is not a run that `alloc_huge_frames` gave.
    pub fn map_huge(
        &self,
        addr: VirtAddr,
        frames: Vec<Arc<Frame>>,
        prot: PageProt,
    ) -> Result<(), MapError> {
        self.map_block(addr.get(), frames, prot, true)
    }

    /// Maps a huge page of hugetlbfs, as `map_huge` does. /proc/meminfo does not count the page
    /// in `AnonHugePages`.
    ///
    /// # Errors
    ///
    /// As for `map_huge`.
    ///
    /// # Panics
    ///
    /// If `frames` is not a run of `HUGE_FRAMES` frames that is 2 MiB aligned.
    pub fn map_hugetlb(
        &self,
        addr: VirtAddr,
        frames: Vec<Arc<Frame>>,
        prot: PageProt,
    ) -> Result<(), MapError> {
        self.map_block(addr.get(), frames, prot, false)
    }

    fn map_block(
        &self,
        a: usize,
        frames: Vec<Arc<Frame>>,
        prot: PageProt,
        thp: bool,
    ) -> Result<(), MapError> {
        if !a.is_multiple_of(HUGE_PAGE_SIZE)
            || a.checked_add(HUGE_PAGE_SIZE).is_none_or(|e| e > USER_END)
        {
            return Err(MapError::BadAddress);
        }
        let first = frames[0].addr().get();
        assert!(frames.len() == HUGE_FRAMES && first.is_multiple_of(HUGE_PAGE_SIZE as u64));
        for (i, f) in frames.iter().enumerate() {
            assert_eq!(f.addr().get(), first + (i * PAGE_SIZE) as u64, "the frames are not a run");
        }
        let mut inner = self.inner.lock();
        if inner.huge.contains_key(&a) || inner.pages.range(a..a + HUGE_PAGE_SIZE).next().is_some()
        {
            return Err(MapError::Mapped);
        }
        let table = paging::user_map_huge(inner.root, a, first, prot.bits())
            .map_err(|()| MapError::NoMemory)?;
        inner.huge.insert(a, Huge { table, thp, frames, prot });
        if thp {
            HUGE_MAPPED.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// The number of huge pages that are mapped.
    pub fn huge_count(&self) -> usize {
        self.inner.lock().huge.len()
    }

    /// Gives the frames and the permissions of the huge page at the 2 MiB aligned `block`, or
    /// `None` if no huge page is mapped there.
    pub fn huge_block(&self, block: VirtAddr) -> Option<(Vec<Arc<Frame>>, PageProt)> {
        let inner = self.inner.lock();
        let huge = inner.huge.get(&block.get())?;
        Some((huge.frames.clone(), huge.prot))
    }

    /// Changes the permissions of the huge page at the 2 MiB aligned `block` and keeps it whole.
    /// Gives `false` if no huge page is mapped there, or if `prot` allows no access. The caller
    /// then changes each page with `protect`, which splits the huge page.
    pub fn protect_huge(&self, block: VirtAddr, prot: PageProt) -> bool {
        let a = block.get();
        let mut inner = self.inner.lock();
        let root = inner.root;
        let Some(huge) = inner.huge.get_mut(&a).filter(|_| prot != PageProt::NONE) else {
            return false;
        };
        huge.prot = prot;
        paging::user_protect_huge(root, a, huge.frames[0].addr().get(), prot.bits());
        true
    }

    /// Makes the address space of a child of `fork` with the pages of this space in `areas`. The
    /// areas are in address order and do not overlap. The child maps the same frames. A page of a
    /// private area becomes read only in both spaces. A huge page that is all in one area stays a
    /// huge page in both spaces. A huge page that is in part in an area stays whole in this space
    /// if its permissions do not change, and the child maps its pages one by one.
    ///
    /// The copy works on one last level table at a time, and one TLB flush is for all the pages
    /// of an area that become read only.
    ///
    /// # Errors
    ///
    /// Gives `MapError::NoMemory` if no frame is free for a page table.
    pub fn fork(&self, areas: &[ForkArea]) -> Result<Self, MapError> {
        let child = Self::new().ok_or(MapError::NoMemory)?;
        let mut parent = self.inner.lock();
        let mut c = child.inner.lock();
        let root = parent.root;
        // The pages of the huge pages that the child maps one by one.
        let mut extra = Vec::new();
        // The huge pages first, so the pass over the 4 KiB pages below sees the splits.
        let mut next = 0;
        while let Some((&block, huge)) = parent.huge.range_mut(next..).next() {
            next = block + HUGE_PAGE_SIZE;
            let prot = huge.prot;
            let i = areas.partition_point(|r| r.end <= block);
            if let Some(&area) = areas.get(i).filter(|r| r.start <= block && next <= r.end) {
                let ro = area.prot(prot);
                if ro != PageProt::NONE {
                    let phys = huge.frames[0].addr().get();
                    if ro != prot {
                        huge.prot = ro;
                        paging::user_protect_huge(root, block, phys, ro.bits());
                    }
                    let table = paging::user_map_huge(c.root, block, phys, ro.bits())
                        .map_err(|()| MapError::NoMemory)?;
                    let (thp, frames) = (huge.thp, huge.frames.clone());
                    c.huge.insert(block, Huge { table, thp, frames, prot: ro });
                    if thp {
                        HUGE_MAPPED.fetch_add(1, Ordering::Relaxed);
                    }
                    continue;
                }
            }
            // The pages of a private area become read only, and that splits the huge page.
            let private = areas[i..].iter().take_while(|r| r.start < next).any(|r| !r.shared);
            if prot.writable && private {
                parent.split(block);
                continue;
            }
            // The huge page stays whole in this space, and the child maps the pages of it that
            // are in the areas.
            for area in areas[i..].iter().take_while(|r| r.start < next) {
                for a in (area.start.max(block)..area.end.min(next)).step_by(PAGE_SIZE) {
                    let frame = huge.frames[(a - block) / PAGE_SIZE].clone();
                    extra.push((a, (frame, area.prot(prot))));
                }
            }
        }
        // The child gets the pages in the areas. A clone of the whole map makes no search for
        // each page, and the pages outside the areas go after it.
        let mut pages = parent.pages.clone();
        let mut i = 0;
        pages.retain(|&a, (_, prot)| {
            while areas.get(i).is_some_and(|r| r.end <= a) {
                i += 1;
            }
            match areas.get(i) {
                Some(area) if area.start <= a => {
                    *prot = area.prot(*prot);
                    true
                }
                _ => false,
            }
        });
        pages.extend(extra);
        // The pages of the private areas become read only in this space. A page that is read only
        // after an earlier fork needs no change.
        for area in areas.iter().filter(|r| !r.shared) {
            let ro = parent.pages.range_mut(area.start..area.end).filter(|(_, (_, p))| p.writable);
            paging::user_protect_many(
                root,
                ro.map(|(&a, (f, p))| {
                    p.writable = false;
                    (a, f.addr().get(), p.bits())
                }),
            );
        }
        // The child maps the pages that are not in its huge pages.
        let small = pages.iter().map(|(&a, (f, p))| (a, f.addr().get(), p.bits()));
        paging::user_map_new(c.root, small).map_err(|()| MapError::NoMemory)?;
        c.pages = pages;
        drop(c);
        Ok(child)
    }

    /// Removes the pages in `start..end`. A huge page that is all in the range goes as one, and a
    /// huge page that is in part in the range is split first.
    pub fn unmap_range(&self, start: VirtAddr, end: VirtAddr) {
        let (start, end) = (start.get(), end.get());
        // The frames go after the lock, as the frames that `unmap` gives. They go in batches of
        // the pages of one huge page, so a large range needs no large list when memory is short.
        let batch = HUGE_FRAMES;
        let mut gone = Vec::with_capacity(batch);
        let first = start & !(HUGE_PAGE_SIZE - 1);
        let mut inner = self.inner.lock();
        while let Some(&block) = inner.huge.range(first..end).next().map(|(b, _)| b) {
            if block >= start && block + HUGE_PAGE_SIZE <= end {
                let Some(huge) = inner.huge.remove(&block) else { break };
                paging::user_unmap_huge(inner.root, block, huge.table);
                if huge.thp {
                    HUGE_MAPPED.fetch_sub(1, Ordering::Relaxed);
                }
                drop(inner);
                drop(huge);
                inner = self.inner.lock();
            } else {
                inner.split(block);
            }
        }
        loop {
            let root = inner.root;
            while gone.len() < batch {
                let Some((&a, _)) = inner.pages.range(start..end).next() else { break };
                gone.extend(inner.pages.remove(&a));
                paging::user_unmap(root, a);
            }
            let done = gone.len() < batch;
            drop(inner);
            gone.clear();
            if done {
                return;
            }
            inner = self.inner.lock();
        }
    }

    /// Removes the page at `addr` and gives its frame.
    pub fn unmap(&self, addr: VirtAddr) -> Option<Arc<Frame>> {
        let mut inner = self.inner.lock();
        inner.get(addr.get())?;
        inner.split(addr.get());
        let (frame, _) = inner.pages.remove(&addr.get())?;
        paging::user_unmap(inner.root, addr.get());
        Some(frame)
    }

    /// Changes the permissions of the page at `addr`. Gives `false` if no page is mapped there.
    pub fn protect(&self, addr: VirtAddr, prot: PageProt) -> bool {
        let mut inner = self.inner.lock();
        let root = inner.root;
        let block = block_of(addr.get());
        match inner.get(addr.get()) {
            None => return false,
            // A huge page stays whole when its permissions do not change.
            Some((_, old)) if old == prot && inner.huge.contains_key(&block) => return true,
            Some(_) => inner.split(block),
        }
        let Some((frame, old)) = inner.pages.get_mut(&addr.get()) else { return false };
        *old = prot;
        paging::user_protect(root, addr.get(), frame.addr().get(), prot.bits());
        true
    }

    /// Gives the frame and the permissions of the page that contains `addr`.
    pub fn page(&self, addr: VirtAddr) -> Option<(Arc<Frame>, PageProt)> {
        let page = addr.get() & !(PAGE_SIZE - 1);
        self.inner.lock().get(page).map(|(frame, prot)| (frame.clone(), prot))
    }

    /// Gives the page addresses in `start..end` that are mapped, in order.
    pub fn mapped_pages(&self, start: VirtAddr, end: VirtAddr) -> alloc::vec::Vec<VirtAddr> {
        let inner = self.inner.lock();
        let mut out = Vec::new();
        inner.each_page(start.get(), end.get(), |a| out.push(VirtAddr::new(a)));
        out
    }

    /// The number of mapped pages in `start..end`. It allocates no memory, so the OOM killer can
    /// use it.
    pub fn pages_in(&self, start: VirtAddr, end: VirtAddr) -> usize {
        self.inner.lock().count(start.get(), end.get())
    }

    /// Adds the page addresses in `start..end` that are mapped to `out`, in order. Gives `false`
    /// and adds nothing if the kernel heap has no memory for them.
    pub fn try_mapped_pages(&self, start: VirtAddr, end: VirtAddr, out: &mut Vec<usize>) -> bool {
        let inner = self.inner.lock();
        if out.try_reserve(inner.count(start.get(), end.get())).is_err() {
            return false;
        }
        inner.each_page(start.get(), end.get(), |a| out.push(a));
        true
    }

    /// The number of mapped pages.
    pub fn page_count(&self) -> usize {
        let inner = self.inner.lock();
        inner.pages.len() + inner.huge.len() * HUGE_FRAMES
    }

    /// Loads this address space, so the user code of the process can run.
    pub fn activate(&self) {
        paging::activate(self.root);
    }

    /// Loads the kernel page table. No user address space is active after this.
    pub fn deactivate() {
        paging::activate(0);
    }

    /// Copies user memory at `addr` to `buf`.
    ///
    /// # Errors
    ///
    /// Gives the first address that is not mapped. The bytes before it are copied.
    pub fn read(&self, addr: VirtAddr, buf: &mut [u8]) -> Result<(), UserFault> {
        self.copy(addr.get(), buf.len(), false, |frame, offset, done, len| {
            frame.read_bytes(offset, &mut buf[done..done + len]);
        })
    }

    /// Copies `buf` to user memory at `addr`.
    ///
    /// # Errors
    ///
    /// Gives the first address that is not mapped or not writable. The bytes before it are
    /// copied.
    pub fn write(&self, addr: VirtAddr, buf: &[u8]) -> Result<(), UserFault> {
        self.copy(addr.get(), buf.len(), true, |frame, offset, done, len| {
            frame.write_bytes(offset, &buf[done..done + len]);
        })
    }

    /// Writes `new` to the aligned 32 bit word at `addr` if the word has the value `old`, in one
    /// atomic operation, and gives the value that the word had.
    ///
    /// # Errors
    ///
    /// Gives the address if the word is not mapped or not writable.
    pub fn compare_exchange_u32(
        &self,
        addr: VirtAddr,
        old: u32,
        new: u32,
    ) -> Result<u32, UserFault> {
        let mut value = 0;
        self.copy(addr.get(), 4, true, |frame, offset, _, _| {
            value = frame.compare_exchange_u32(offset, old, new);
        })?;
        Ok(value)
    }

    /// Fills `len` bytes of user memory at `addr` with zeros.
    ///
    /// # Errors
    ///
    /// As for `write`.
    pub fn fill_zero(&self, addr: VirtAddr, len: usize) -> Result<(), UserFault> {
        self.copy(addr.get(), len, true, |frame, offset, _, n| frame.fill_zero(offset, n))
    }

    /// Calls `f` for each part of `len` bytes at `addr` that is in one page. `f` gets the frame,
    /// the offset in the frame, the bytes done before this part and the length of the part.
    fn copy(
        &self,
        addr: usize,
        len: usize,
        write: bool,
        mut f: impl FnMut(&Frame, usize, usize, usize),
    ) -> Result<(), UserFault> {
        let Some(end) = addr.checked_add(len).filter(|&e| e <= USER_END) else {
            return Err(UserFault { addr: addr.max(USER_END), write });
        };
        let mut done = 0;
        while addr + done < end {
            let at = addr + done;
            let page = at & !(PAGE_SIZE - 1);
            let offset = at - page;
            let n = (PAGE_SIZE - offset).min(end - at);
            let frame = {
                let inner = self.inner.lock();
                match inner.get(page) {
                    Some((frame, prot)) if prot.allows(write) => frame.clone(),
                    _ => return Err(UserFault { addr: at, write }),
                }
            };
            f(&frame, offset, done, n);
            done += n;
        }
        Ok(())
    }
}

impl Drop for VmSpace {
    fn drop(&mut self) {
        let inner = self.inner.lock();
        if paging::is_active(inner.root) {
            paging::activate(0);
        }
        paging::free_user_root(inner.root);
        // `free_user_root` does not see the tables for the splits of the huge pages.
        for huge in inner.huge.values() {
            free_frame_phys(huge.table);
        }
        let thp = inner.huge.values().filter(|huge| huge.thp).count();
        HUGE_MAPPED.fetch_sub(thp, Ordering::Relaxed);
        // The frames go when `pages` and `huge` are dropped, after the tables that map them are
        // gone.
    }
}

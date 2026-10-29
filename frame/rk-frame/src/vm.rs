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
use crate::blocks::BlockTree;
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

/// A frame that a page table entry maps. The value counts in the map count of the frame while it
/// lives, as the reverse map of Linux (mm/rmap.c) does. Other references to the frame, as the
/// page cache of a file, do not count. See [`Frame::map_count`].
struct Mapped(Arc<Frame>);

impl Mapped {
    fn new(frame: Arc<Frame>) -> Self {
        frame.map_get();
        Self(frame)
    }
}

impl Clone for Mapped {
    fn clone(&self) -> Self {
        Self::new(self.0.clone())
    }
}

impl Drop for Mapped {
    fn drop(&mut self) {
        self.0.map_put();
    }
}

impl core::ops::Deref for Mapped {
    type Target = Arc<Frame>;

    fn deref(&self) -> &Arc<Frame> {
        &self.0
    }
}

/// A huge page of an address space.
struct Huge {
    /// The last level table for the split of the page.
    table: u64,
    /// The page is a transparent huge page. A page of hugetlbfs is not.
    thp: bool,
    /// The `HUGE_FRAMES` frames of the page, in address order.
    frames: Vec<Mapped>,
    /// The permissions of each page of the huge page.
    prot: PageProt,
}

/// The pages of one 2 MiB block, the range of one last level table. The lock of the block is the
/// lock of the table and of its entry in the table above, as the split page table lock of Linux
/// (`pte_lockptr` and `pmd_lock` in include/linux/mm.h).
#[derive(Default)]
struct Block {
    /// The frame and the permissions at each mapped page address, if the block is not a huge
    /// page.
    pages: BTreeMap<usize, (Mapped, PageProt)>,
    /// The huge page of the block. Then `pages` is empty.
    huge: Option<Huge>,
}

// A block of `VmSpace` is the range of one huge page.
const _: () = assert!(crate::blocks::BLOCK_SIZE == HUGE_PAGE_SIZE);

/// The address of the huge page that contains `addr`.
fn block_of(addr: usize) -> usize {
    addr & !(HUGE_PAGE_SIZE - 1)
}

/// The part of `start..end` in the block at `block`.
fn clip(block: usize, start: usize, end: usize) -> (usize, usize) {
    (start.max(block), end.min(block + HUGE_PAGE_SIZE))
}

impl Block {
    /// Gives the frame and the permissions of the page at the page address `addr` in the block.
    fn get(&self, addr: usize) -> Option<(&Arc<Frame>, PageProt)> {
        if let Some(huge) = &self.huge {
            return Some((&huge.frames[(addr - block_of(addr)) / PAGE_SIZE].0, huge.prot));
        }
        self.pages.get(&addr).map(|(frame, prot)| (&frame.0, *prot))
    }

    /// Calls `f` for each mapped page address in `start..end` of the block, in order.
    fn each_page(&self, start: usize, end: usize, f: impl FnMut(usize)) {
        if self.huge.is_some() {
            (start..end).step_by(PAGE_SIZE).for_each(f);
        } else {
            self.pages.range(start..end).map(|(&a, _)| a).for_each(f);
        }
    }

    /// The number of mapped pages in `start..end` of the block.
    fn count(&self, start: usize, end: usize) -> usize {
        if self.huge.is_some() {
            (end - start) / PAGE_SIZE
        } else {
            self.pages.range(start..end).count()
        }
    }
}

/// The page table of one user address space.
///
/// Each 2 MiB block has its own lock, so two calls on different blocks do not wait for each other,
/// for example two page faults of two threads. A call on a range locks one block at a time. The
/// tables above the blocks are never freed while the space lives, so a walk to a block needs no
/// lock, and a new table goes in with a compare and swap (`next_table` of paging).
pub struct VmSpace {
    /// The physical address of the top level table. It does not change.
    root: u64,
    /// The pages of each block.
    blocks: BlockTree<SpinLock<Block>>,
    /// The number of mapped pages that are not in a huge page.
    small: AtomicUsize,
    /// The number of huge pages.
    huge: AtomicUsize,
}

impl VmSpace {
    /// Makes an empty address space. Gives `None` if no frame is free for the top level table.
    pub fn new() -> Option<Self> {
        let root = paging::new_user_root()?;
        let blocks = BlockTree::new(USER_END);
        Some(Self { root, blocks, small: AtomicUsize::new(0), huge: AtomicUsize::new(0) })
    }

    /// The lock of the block of `addr`, if the block had a page.
    fn block(&self, addr: usize) -> Option<&SpinLock<Block>> {
        self.blocks.get(addr)
    }

    /// The lock of the block of `addr`, which is below `USER_END`.
    fn block_or_new(&self, addr: usize) -> &SpinLock<Block> {
        self.blocks.get_or_make(addr, || SpinLock::new(Block::default()))
    }

    /// Changes the huge page of the block at `block`, if it has one, to 4 KiB pages.
    fn split(&self, b: &mut Block, block: usize) {
        if let Some(huge) = b.huge.take() {
            paging::user_split_huge(self.root, block, huge.table);
            if huge.thp {
                HUGE_MAPPED.fetch_sub(1, Ordering::Relaxed);
            }
            self.huge.fetch_sub(1, Ordering::Relaxed);
            self.small.fetch_add(HUGE_FRAMES, Ordering::Relaxed);
            let pages = huge.frames.into_iter().enumerate();
            b.pages.extend(pages.map(|(i, f)| (block + i * PAGE_SIZE, (f, huge.prot))));
        }
    }

    /// Puts a huge page in the block at `block`, which has no page.
    fn put_huge(&self, b: &mut Block, huge: Huge) {
        if huge.thp {
            HUGE_MAPPED.fetch_add(1, Ordering::Relaxed);
        }
        self.huge.fetch_add(1, Ordering::Relaxed);
        b.huge = Some(huge);
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
        let mut b = self.block_or_new(a).lock();
        if b.get(a).is_some() {
            return Err(MapError::Mapped);
        }
        paging::user_map(self.root, a, frame.addr().get(), prot.bits())
            .map_err(|()| MapError::NoMemory)?;
        b.pages.insert(a, (Mapped::new(frame), prot));
        self.small.fetch_add(1, Ordering::Relaxed);
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
        let mut b = self.block_or_new(a).lock();
        if b.huge.is_some() || !b.pages.is_empty() {
            return Err(MapError::Mapped);
        }
        let table = paging::user_map_huge(self.root, a, first, prot.bits())
            .map_err(|()| MapError::NoMemory)?;
        let frames = frames.into_iter().map(Mapped::new).collect();
        self.put_huge(&mut b, Huge { table, thp, frames, prot });
        Ok(())
    }

    /// The number of huge pages that are mapped.
    pub fn huge_count(&self) -> usize {
        self.huge.load(Ordering::Relaxed)
    }

    /// Gives the frames and the permissions of the huge page at the 2 MiB aligned `block`, or
    /// `None` if no huge page is mapped there.
    pub fn huge_block(&self, block: VirtAddr) -> Option<(Vec<Arc<Frame>>, PageProt)> {
        let b = self.block(block.get())?.lock();
        let huge = b.huge.as_ref()?;
        Some((huge.frames.iter().map(|f| f.0.clone()).collect(), huge.prot))
    }

    /// Changes the permissions of the huge page at the 2 MiB aligned `block` and keeps it whole.
    /// Gives `false` if no huge page is mapped there, or if `prot` allows no access. The caller
    /// then changes each page with `protect`, which splits the huge page.
    pub fn protect_huge(&self, block: VirtAddr, prot: PageProt) -> bool {
        let a = block.get();
        let Some(lock) = self.block(a) else { return false };
        let mut b = lock.lock();
        let Some(huge) = b.huge.as_mut().filter(|_| prot != PageProt::NONE) else {
            return false;
        };
        huge.prot = prot;
        paging::user_protect_huge(self.root, a, huge.frames[0].addr().get(), prot.bits());
        true
    }

    /// Makes the address space of a child of `fork` with the pages of this space in `areas`. The
    /// areas are in address order and do not overlap. The child maps the same frames. A page of a
    /// private area becomes read only in both spaces. A huge page that is all in one area stays a
    /// huge page in both spaces. A huge page that is in part in an area stays whole in this space
    /// if its permissions do not change, and the child maps its pages one by one.
    ///
    /// The copy locks one block at a time, as `copy_pte_range` of Linux takes the lock of one last
    /// level table at a time. The caller makes sure that no page fault changes the areas during the
    /// copy. One TLB flush at the end is for all the pages that become read only.
    ///
    /// # Errors
    ///
    /// Gives `MapError::NoMemory` if no frame is free for a page table.
    pub fn fork(&self, areas: &[ForkArea]) -> Result<Self, MapError> {
        let child = Self::new().ok_or(MapError::NoMemory)?;
        let mut flush = false;
        let copied = self.blocks.each(0, USER_END, |block, lock| {
            self.fork_block(&child, &mut lock.lock(), block, areas, &mut flush)
        });
        if flush {
            paging::user_flush_all(self.root);
        }
        copied.map(|()| child)
    }

    /// Copies the block at `block` to `child`, for `fork`. Sets `flush` if a page of this space
    /// became read only.
    fn fork_block(
        &self,
        child: &Self,
        b: &mut Block,
        block: usize,
        areas: &[ForkArea],
        flush: &mut bool,
    ) -> Result<(), MapError> {
        let next = block + HUGE_PAGE_SIZE;
        let i = areas.partition_point(|r| r.end <= block);
        let near = || areas[i..].iter().take_while(|r| r.start < next);
        // The pages that the child maps one by one.
        let mut pages = BTreeMap::new();
        if let Some(huge) = &mut b.huge {
            let prot = huge.prot;
            if let Some(&area) = areas.get(i).filter(|r| r.start <= block && next <= r.end) {
                let ro = area.prot(prot);
                if ro != PageProt::NONE {
                    let phys = huge.frames[0].addr().get();
                    if ro != prot {
                        huge.prot = ro;
                        paging::user_protect_huge(self.root, block, phys, ro.bits());
                    }
                    let table = paging::user_map_huge(child.root, block, phys, ro.bits())
                        .map_err(|()| MapError::NoMemory)?;
                    let (thp, frames) = (huge.thp, huge.frames.clone());
                    let mut c = child.block_or_new(block).lock();
                    child.put_huge(&mut c, Huge { table, thp, frames, prot: ro });
                    return Ok(());
                }
            }
            // The pages of a private area become read only, and that splits the huge page.
            if prot.writable && near().any(|r| !r.shared) {
                self.split(b, block);
            } else {
                // The huge page stays whole in this space, and the child maps the pages of it
                // that are in the areas.
                for area in near() {
                    for a in (area.start.max(block)..area.end.min(next)).step_by(PAGE_SIZE) {
                        let frame = huge.frames[(a - block) / PAGE_SIZE].clone();
                        pages.insert(a, (frame, area.prot(prot)));
                    }
                }
            }
        }
        // The child gets the 4 KiB pages in the areas.
        let mut j = i;
        for (&a, (frame, prot)) in &b.pages {
            while areas.get(j).is_some_and(|r| r.end <= a) {
                j += 1;
            }
            if let Some(area) = areas.get(j).filter(|r| r.start <= a) {
                pages.insert(a, (frame.clone(), area.prot(*prot)));
            }
        }
        // The pages of the private areas become read only in this space. A page that is read only
        // after an earlier fork needs no change.
        for area in near().filter(|r| !r.shared) {
            let (from, to) = clip(block, area.start, area.end);
            let ro = b.pages.range_mut(from..to).filter(|(_, (_, p))| p.writable);
            *flush |= paging::user_protect_many(
                self.root,
                ro.map(|(&a, (f, p))| {
                    p.writable = false;
                    (a, f.addr().get(), p.bits())
                }),
            );
        }
        if pages.is_empty() {
            return Ok(());
        }
        let small = pages.iter().map(|(&a, (f, p))| (a, f.addr().get(), p.bits()));
        paging::user_map_new(child.root, small).map_err(|()| MapError::NoMemory)?;
        child.small.fetch_add(pages.len(), Ordering::Relaxed);
        let mut c = child.block_or_new(block).lock();
        c.pages = pages;
        Ok(())
    }

    /// Removes the pages in `start..end`. A huge page that is all in the range goes as one, and a
    /// huge page that is in part in the range is split first.
    pub fn unmap_range(&self, start: VirtAddr, end: VirtAddr) {
        let (start, end) = (start.get(), end.get());
        let _ = self.blocks.each(start, end, |block, lock| {
            let mut b = lock.lock();
            let (from, to) = clip(block, start, end);
            let mut huge = None;
            if b.huge.is_some() {
                if (from, to) == (block, block + HUGE_PAGE_SIZE) {
                    huge = b.huge.take();
                    if let Some(huge) = &huge {
                        paging::user_unmap_huge(self.root, block, huge.table);
                        if huge.thp {
                            HUGE_MAPPED.fetch_sub(1, Ordering::Relaxed);
                        }
                        self.huge.fetch_sub(1, Ordering::Relaxed);
                    }
                } else {
                    self.split(&mut b, block);
                }
            }
            let mut gone = b.pages.split_off(&from);
            let mut after = gone.split_off(&to);
            b.pages.append(&mut after);
            for &a in gone.keys() {
                paging::user_unmap(self.root, a);
            }
            self.small.fetch_sub(gone.len(), Ordering::Relaxed);
            // The frames go after the lock.
            drop(b);
            drop((gone, huge));
            Ok::<(), ()>(())
        });
    }

    /// Removes the page at `addr` and gives its frame.
    pub fn unmap(&self, addr: VirtAddr) -> Option<Arc<Frame>> {
        let a = addr.get();
        let mut b = self.block(a)?.lock();
        b.get(a)?;
        self.split(&mut b, block_of(a));
        let (frame, _) = b.pages.remove(&a)?;
        paging::user_unmap(self.root, a);
        self.small.fetch_sub(1, Ordering::Relaxed);
        Some(frame.0.clone())
    }

    /// Changes the permissions of the page at `addr`. Gives `false` if no page is mapped there.
    pub fn protect(&self, addr: VirtAddr, prot: PageProt) -> bool {
        let a = addr.get();
        let Some(lock) = self.block(a) else { return false };
        let mut b = lock.lock();
        match b.get(a) {
            None => return false,
            // A huge page stays whole when its permissions do not change.
            Some((_, old)) if old == prot && b.huge.is_some() => return true,
            Some(_) => self.split(&mut b, block_of(a)),
        }
        let Some((frame, old)) = b.pages.get_mut(&a) else { return false };
        *old = prot;
        paging::user_protect(self.root, a, frame.addr().get(), prot.bits());
        true
    }

    /// Makes the pages in `start..end` read only, as `mkclean` and the clear of soft-dirty of Linux.
    /// The next write to a page then faults. A huge page that is all in the range stays whole, and
    /// a writable huge page that is in part in the range is split first. One TLB flush at the end is
    /// for all the 4 KiB pages, as `change_protection` of Linux flushes the range after it.
    pub fn write_protect(&self, start: VirtAddr, end: VirtAddr) {
        let (start, end) = (start.get(), end.get());
        let mut flush = false;
        let _ = self.blocks.each(start, end, |block, lock| {
            let mut b = lock.lock();
            let (from, to) = clip(block, start, end);
            if let Some(huge) = b.huge.as_mut().filter(|h| h.prot.writable) {
                if (from, to) == (block, block + HUGE_PAGE_SIZE) {
                    huge.prot.writable = false;
                    let (phys, bits) = (huge.frames[0].addr().get(), huge.prot.bits());
                    paging::user_protect_huge(self.root, block, phys, bits);
                } else {
                    self.split(&mut b, block);
                }
            }
            let ro = b.pages.range_mut(from..to).filter(|(_, (_, p))| p.writable);
            flush |= paging::user_protect_many(
                self.root,
                ro.map(|(&a, (f, p))| {
                    p.writable = false;
                    (a, f.addr().get(), p.bits())
                }),
            );
            Ok::<(), ()>(())
        });
        if flush {
            paging::user_flush_all(self.root);
        }
    }

    /// Makes the page at `addr` read only if it maps the frame at the physical address `phys` and
    /// is writable, as `page_mkclean_one` of Linux. A huge page is split first. Gives `true` if the
    /// page changed.
    pub fn write_protect_frame(&self, addr: VirtAddr, phys: u64) -> bool {
        let a = addr.get();
        let Some(lock) = self.block(a) else { return false };
        let mut b = lock.lock();
        match b.get(a) {
            Some((frame, prot)) if prot.writable && frame.addr().get() == phys => {}
            _ => return false,
        }
        self.split(&mut b, block_of(a));
        let Some((_, prot)) = b.pages.get_mut(&a) else { return false };
        prot.writable = false;
        let bits = prot.bits();
        paging::user_protect(self.root, a, phys, bits);
        true
    }

    /// Tells if the page at `addr` is a part of a huge page that is mapped whole.
    pub fn is_huge(&self, addr: VirtAddr) -> bool {
        self.block(addr.get()).is_some_and(|lock| lock.lock().huge.is_some())
    }

    /// Gives the frame and the permissions of the page that contains `addr`.
    pub fn page(&self, addr: VirtAddr) -> Option<(Arc<Frame>, PageProt)> {
        let page = addr.get() & !(PAGE_SIZE - 1);
        let b = self.block(page)?.lock();
        b.get(page).map(|(frame, prot)| (frame.clone(), prot))
    }

    /// Gives the page addresses in `start..end` that are mapped, in order.
    pub fn mapped_pages(&self, start: VirtAddr, end: VirtAddr) -> alloc::vec::Vec<VirtAddr> {
        let (start, end) = (start.get(), end.get());
        let mut out = Vec::new();
        let _ = self.blocks.each(start, end, |block, lock| {
            let (from, to) = clip(block, start, end);
            lock.lock().each_page(from, to, |a| out.push(VirtAddr::new(a)));
            Ok::<(), ()>(())
        });
        out
    }

    /// The number of mapped pages in `start..end`. It allocates no memory, so the OOM killer can
    /// use it.
    pub fn pages_in(&self, start: VirtAddr, end: VirtAddr) -> usize {
        let (start, end) = (start.get(), end.get());
        let mut n = 0;
        let _ = self.blocks.each(start, end, |block, lock| {
            let (from, to) = clip(block, start, end);
            n += lock.lock().count(from, to);
            Ok::<(), ()>(())
        });
        n
    }

    /// Adds the page addresses in `start..end` that are mapped to `out`, in order. Gives `false`
    /// and adds nothing if the kernel heap has no memory for them.
    pub fn try_mapped_pages(&self, start: VirtAddr, end: VirtAddr, out: &mut Vec<usize>) -> bool {
        let (start, end) = (start.get(), end.get());
        let len = out.len();
        let added = self.blocks.each(start, end, |block, lock| {
            let (from, to) = clip(block, start, end);
            let b = lock.lock();
            out.try_reserve(b.count(from, to))?;
            b.each_page(from, to, |a| out.push(a));
            Ok::<(), alloc::collections::TryReserveError>(())
        });
        if added.is_err() {
            out.truncate(len);
        }
        added.is_ok()
    }

    /// The number of mapped pages.
    pub fn page_count(&self) -> usize {
        self.small.load(Ordering::Relaxed) + self.huge.load(Ordering::Relaxed) * HUGE_FRAMES
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
                let Some(lock) = self.block(page) else {
                    return Err(UserFault { addr: at, write });
                };
                match lock.lock().get(page) {
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
        if paging::is_active(self.root) {
            paging::activate(0);
        }
        paging::free_user_root(self.root);
        // `free_user_root` does not see the tables for the splits of the huge pages.
        let mut thp = 0;
        self.blocks.each_all(|_, lock| {
            if let Some(huge) = &lock.lock().huge {
                free_frame_phys(huge.table);
                thp += usize::from(huge.thp);
            }
        });
        HUGE_MAPPED.fetch_sub(thp, Ordering::Relaxed);
        // The frames go when `blocks` is dropped, after the tables that map them are gone.
    }
}

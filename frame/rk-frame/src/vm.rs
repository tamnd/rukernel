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
use crate::blocks::{BlockTree, TOP_LEVEL};
use crate::mm::frame::free_frame_phys;
use crate::mm::{Frame, HUGE_FRAMES};
use crate::status::{PageStatus, SLOTS, StatusTable};
use crate::sync::SpinLock;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::{Cell, UnsafeCell};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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

/// A change of the pages of a range that `VmSpace::change_status` makes in the same walk and
/// under the same lock of each 2 MiB block as the change of their statuses, as a change of
/// CortenMM writes the metadata and the entries of a page table page together. `VmSpace::finish`
/// ends it: it flushes the TLB one time for all the 4 KiB pages, and frees the frames after the
/// flush, as `tlb_finish_mmu` of Linux.
pub struct PageChange {
    op: PageOp,
    /// The range has one page, so each entry gets its own flush, as one `invlpg` costs less than
    /// a flush of all the entries.
    each: bool,
    /// An entry changed, and the TLB needs a flush.
    flush: bool,
    /// The pages that the change removed. Their frames go after the flush.
    freed: Vec<BTreeMap<usize, (Mapped, PageProt)>>,
    /// The huge pages that the change removed. They had their own flush.
    huge: Vec<Huge>,
}

/// What a [`PageChange`] does to each page.
#[derive(Clone, Copy)]
enum PageOp {
    Unmap,
    Protect(PageProt),
}

impl PageChange {
    fn new(op: PageOp, start: VirtAddr, end: VirtAddr) -> Self {
        let each = end.get() - start.get() <= PAGE_SIZE;
        Self { op, each, flush: false, freed: Vec::new(), huge: Vec::new() }
    }

    /// Removes the pages of `start..end`, as `unmap_range`. The change can cover a part of the
    /// range in each call.
    pub fn unmap(start: VirtAddr, end: VirtAddr) -> Self {
        Self::new(PageOp::Unmap, start, end)
    }

    /// Gives the pages of `start..end` the permissions `prot`. A huge page that is all in the
    /// range stays whole if `prot` allows an access, and else it is split.
    pub fn protect(start: VirtAddr, end: VirtAddr, prot: PageProt) -> Self {
        Self::new(PageOp::Protect(prot), start, end)
    }
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

/// The metadata of one page table page for the memory manager, as the metadata array of a page
/// table page of CortenMM. It has the status of each entry of the page, the lock of the page, and
/// the flag that tells if the node of the page is in the tree of the memory manager (it is live).
///
/// `holder` is the lock: the CortenMM backend holds it for the whole change of the statuses of the
/// page, or for a whole page fault in its block, as the lock of a page table page of CortenMM. A
/// fault finds the lock of its block with the walk of the page table, with no lock, and does not
/// walk the tables above. A call takes the hold of a block before the lock of its pages, and it
/// does not wait for a hold while it holds the lock of the pages.
///
/// Only the task that holds the page reads or changes its statuses, so a reader of the statuses
/// takes one lock, the hold, and not the lock of the pages too. The calls that change the pages of
/// another address space, as the write protect of a page for a write back, take only the lock of
/// the pages, and do not wait for a hold.
#[derive(Default)]
struct Meta {
    /// 0 if no task holds the page. Else the key of the holder (`task::current_key`), with the
    /// low bit set while a call of the holder uses the statuses.
    holder: AtomicUsize,
    /// The status table has a status. Only the holder changes it.
    used: AtomicBool,
    /// The node of the page is in the tree of the memory manager. Only the holder of the page and
    /// of its parent changes it.
    live: AtomicBool,
    /// The number of live nodes below this one, so a check for an empty node does not read the
    /// 512 entries.
    live_children: AtomicUsize,
    /// The status of each entry of the page. The memory manager sets it. A page can have a status
    /// and no frame.
    status: UnsafeCell<StatusTable>,
}

// SAFETY: `status` is the only field that is not `Sync`. Only the task with its key in `holder`
// gets a reference to it, in `with_status`, which sets the low bit of `holder` for the life of
// the reference, so a second reference cannot exist. A task runs on one CPU at a time.
unsafe impl Sync for Meta {}

impl Meta {
    /// Holds the page, and waits while another task holds it.
    fn hold(&self) {
        let key = crate::task::current_key();
        while self
            .holder
            .compare_exchange_weak(0, key, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // The holder can wait for a TLB request of this CPU.
            while self.holder.load(Ordering::Relaxed) != 0 {
                crate::sync::wait_hint();
            }
        }
    }

    /// Holds the page if no task holds it.
    fn try_hold(&self) -> bool {
        let key = crate::task::current_key();
        self.holder.compare_exchange(0, key, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    /// Ends the hold of the page.
    ///
    /// # Panics
    ///
    /// If the current task does not hold the page.
    fn release(&self) {
        let key = crate::task::current_key();
        let freed = self.holder.compare_exchange(key, 0, Ordering::Release, Ordering::Relaxed);
        assert!(freed.is_ok(), "a task ends a hold of a page table page that it does not hold");
    }

    /// Calls `f` with the status table. `f` does not use the address space.
    ///
    /// # Panics
    ///
    /// If the current task does not hold the page, or if `f` is in a call of `f`.
    fn with_status<R>(&self, f: impl FnOnce(&mut StatusTable) -> R) -> R {
        let key = crate::task::current_key();
        let used = self.holder.compare_exchange(key, key | 1, Ordering::Relaxed, Ordering::Relaxed);
        assert!(used.is_ok(), "a call uses a status table that the task does not hold");
        // SAFETY: `holder` is `key | 1` until the store below, so no other call of this task or
        // of another task gets a reference to the table in that time.
        let table = unsafe { &mut *self.status.get() };
        let r = f(table);
        self.used.store(!table.is_empty(), Ordering::Relaxed);
        self.holder.store(key, Ordering::Relaxed);
        r
    }

    /// Tells if the status table has a status. The answer is exact only for the holder.
    fn has_status(&self) -> bool {
        self.used.load(Ordering::Relaxed)
    }

    fn is_live(&self) -> bool {
        self.live.load(Ordering::Relaxed)
    }

    /// Tells if the node has no status and no live node below it.
    fn is_empty(&self) -> bool {
        !self.has_status() && self.live_children.load(Ordering::Relaxed) == 0
    }
}

/// The locks of one 2 MiB block. `pages` is the lock of the last level table. `meta` has the
/// statuses of the pages and the hold of the block for the memory manager.
struct BlockLock {
    pages: SpinLock<Block>,
    meta: Meta,
}

impl Default for BlockLock {
    fn default() -> Self {
        Self { pages: SpinLock::new(Block::default()), meta: Meta::default() }
    }
}

impl core::ops::Deref for BlockLock {
    type Target = SpinLock<Block>;

    fn deref(&self) -> &SpinLock<Block> {
        &self.pages
    }
}

// A block of `VmSpace` is the range of one huge page.
const _: () = assert!(crate::blocks::BLOCK_SIZE == HUGE_PAGE_SIZE);

/// The address of the huge page that contains `addr`.
fn block_of(addr: usize) -> usize {
    addr & !(HUGE_PAGE_SIZE - 1)
}

/// The index of the page at `addr` in its block.
fn slot_of(addr: usize) -> usize {
    (addr - block_of(addr)) / PAGE_SIZE
}

// A block has one status for each page.
const _: () = assert!(SLOTS == HUGE_FRAMES);

/// The part of `start..end` in the block at `block`.
fn clip(block: usize, start: usize, end: usize) -> (usize, usize) {
    (start.max(block), end.min(block + HUGE_PAGE_SIZE))
}

/// The index of the entry of `addr` in its page table page of `level`. A block is at level 1.
fn entry_of(level: u32, addr: usize) -> usize {
    (addr >> (PAGE_SIZE.trailing_zeros() + 9 * (level - 1))) % SLOTS
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
    blocks: BlockTree<BlockLock, Meta>,
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
        self.blocks.get(addr).map(|b| &b.pages)
    }

    /// The lock of the block of `addr`, which is below `USER_END`.
    fn block_or_new(&self, addr: usize) -> &SpinLock<Block> {
        &self.blocks.get_or_make(addr, BlockLock::default).pages
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

    /// Holds the status table of the 2 MiB block of `addr` for the memory manager, and waits
    /// while another call holds it. Without `make`, it gives `false` with no hold if the block
    /// has no table yet. The CortenMM backend holds the table while it reads or changes the
    /// statuses of the block, and for a whole page fault in the block. The holder takes no other
    /// hold of a status table while it waits for this one, except as the tree of the backend
    /// allows (core/rk-mm/src/pttree.rs).
    ///
    /// # Panics
    ///
    /// If `make` is set and `addr` is not below `USER_END`.
    pub fn hold_status(&self, addr: VirtAddr, make: bool) -> bool {
        let lock = if make {
            self.blocks.get_or_make(addr.get(), BlockLock::default)
        } else {
            match self.blocks.get(addr.get()) {
                Some(lock) => lock,
                None => return false,
            }
        };
        lock.meta.hold();
        true
    }

    /// Holds the status table of the block of `addr` as `hold_status` with `make`, if no other
    /// call holds it. Gives `false` with no hold if one does.
    ///
    /// # Panics
    ///
    /// If `addr` is not below `USER_END`.
    pub fn try_hold_status(&self, addr: VirtAddr) -> bool {
        self.blocks.get_or_make(addr.get(), BlockLock::default).meta.try_hold()
    }

    /// Ends the hold of the status table of the block of `addr`, which the caller holds.
    ///
    /// # Panics
    ///
    /// If the current task does not hold the table.
    pub fn release_status(&self, addr: VirtAddr) {
        if let Some(lock) = self.blocks.get(addr.get()) {
            lock.meta.release();
        }
    }

    /// The metadata of the page table page of `level` at `addr`, if the page is there. Level 1
    /// is the last level table of a 2 MiB block.
    fn meta(&self, level: u32, addr: usize) -> Option<&Meta> {
        if level == 1 {
            self.blocks.get(addr).map(|b| &b.meta)
        } else {
            self.blocks.meta(level, addr)
        }
    }

    /// The metadata of the page table page of `level` at `addr`. The page is made if it is not
    /// there.
    fn meta_or_make(&self, level: u32, addr: usize) -> &Meta {
        if level == 1 {
            &self.blocks.get_or_make(addr, BlockLock::default).meta
        } else {
            self.blocks.meta_or_make(level, addr)
        }
    }

    /// Holds the page table page of `level` at `addr` for the memory manager, as `hold_status`
    /// holds the page of level 1. Level 1 is the last level, and level 4 is the top.
    ///
    /// # Panics
    ///
    /// If `make` is set and `addr` is not below `USER_END`.
    pub fn hold_node(&self, level: u32, addr: VirtAddr, make: bool) -> bool {
        let a = addr.get();
        let meta = if make { Some(self.meta_or_make(level, a)) } else { self.meta(level, a) };
        meta.map(Meta::hold).is_some()
    }

    /// Holds the page table page of `level` at `addr` as `hold_node` with `make`, if no other
    /// call holds it. Gives `false` with no hold if one does.
    pub fn try_hold_node(&self, level: u32, addr: VirtAddr) -> bool {
        self.meta_or_make(level, addr.get()).try_hold()
    }

    /// Ends the hold of the page table page of `level` at `addr`, which the caller holds.
    ///
    /// # Panics
    ///
    /// If the current task does not hold the page.
    pub fn release_node(&self, level: u32, addr: VirtAddr) {
        if let Some(meta) = self.meta(level, addr.get()) {
            meta.release();
        }
    }

    /// Tells if the page table page of `level` at `addr` is in the tree of the memory manager.
    /// A walk reads it with no hold.
    pub fn node_live(&self, level: u32, addr: VirtAddr) -> bool {
        self.meta(level, addr.get()).is_some_and(Meta::is_live)
    }

    /// Puts the page table page of `level` at `addr` in the tree of the memory manager, or takes
    /// it out. The caller holds the page and the page above it.
    ///
    /// # Panics
    ///
    /// If the current task does not hold the page.
    pub fn set_node_live(&self, level: u32, addr: VirtAddr, live: bool) {
        let a = addr.get();
        let meta = if live { Some(self.meta_or_make(level, a)) } else { self.meta(level, a) };
        if let Some(meta) = meta {
            Self::set_live(&self.blocks, meta, level, a, live);
        }
    }

    /// Sets the live flag of `meta`, the page of `level` at `addr` in `blocks`, and counts it in
    /// the page above it.
    fn set_live(
        blocks: &BlockTree<BlockLock, Meta>,
        meta: &Meta,
        level: u32,
        addr: usize,
        live: bool,
    ) {
        meta.with_status(|_| {});
        if meta.live.swap(live, Ordering::Relaxed) == live || level == TOP_LEVEL {
            return;
        }
        let parent = blocks.meta(level + 1, addr).expect("a page table page has a parent");
        if live {
            parent.live_children.fetch_add(1, Ordering::Relaxed);
        } else {
            parent.live_children.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Tells if the page table page of `level` at `addr` has no status and no page below it in
    /// the tree. The answer is exact only for the holder.
    pub fn node_is_empty(&self, level: u32, addr: VirtAddr) -> bool {
        self.meta(level, addr.get()).is_none_or(Meta::is_empty)
    }

    /// Gives the status of the entry of `addr` in the page table page of `level`, which is above
    /// level 1. The caller holds the page.
    pub fn node_status(&self, level: u32, addr: VirtAddr) -> Option<PageStatus> {
        let a = addr.get();
        let meta = self.meta(level, a).filter(|m| m.has_status())?;
        meta.with_status(|t| t.get(entry_of(level, a)).cloned())
    }

    /// Sets the status of each entry of the page table page of `level` in `start..end`, or
    /// removes it with `None`. The range is in one page above level 1, and it is aligned to the
    /// entries. The caller holds the page.
    pub fn set_node_status(
        &self,
        level: u32,
        start: VirtAddr,
        end: VirtAddr,
        status: Option<&PageStatus>,
    ) {
        let (start, end) = (start.get(), end.get());
        let meta = if status.is_some() {
            Some(self.meta_or_make(level, start))
        } else {
            self.meta(level, start)
        };
        if let Some(meta) = meta.filter(|m| status.is_some() || m.has_status()) {
            let (first, last) = (entry_of(level, start), entry_of(level, end - 1) + 1);
            meta.with_status(|t| t.set(first, last, status));
        }
    }

    /// Calls `f` with the index of each entry from `first` to `last` of the page table page of
    /// `level` at `addr` that points to a page in the tree of the memory manager, or that has a
    /// status, in order. `f` gets `None` for an entry that points to a page in the tree, and else
    /// the status. The level is above 1. The caller holds the page, and `f` does not use the
    /// address space. One call reads the entries of the page faster than a call of `node_live`
    /// and `node_status` for each entry.
    pub fn node_entries(
        &self,
        level: u32,
        addr: VirtAddr,
        first: usize,
        last: usize,
        mut f: impl FnMut(usize, Option<&PageStatus>),
    ) {
        let a = addr.get();
        let Some(meta) = self.meta(level, a) else { return };
        // A bit for each entry that points to a page in the tree.
        let bits: [Cell<u64>; SLOTS / 64] = Default::default();
        if meta.live_children.load(Ordering::Relaxed) != 0 {
            let mark = |i: usize| bits[i / 64].set(bits[i / 64].get() | 1 << (i % 64));
            let node = |i, m: &Meta| {
                if m.is_live() {
                    mark(i);
                }
            };
            let block = |i, b: &BlockLock| {
                if b.meta.is_live() {
                    mark(i);
                }
            };
            self.blocks.children(level, a, first..=last, node, block);
        }
        let mut live = bits.map(Cell::into_inner);
        // Gives the first entry below `end` that points to a page in the tree, and clears its bit.
        let mut live_below = |end: usize| {
            let w = live.iter().position(|&w| w != 0)?;
            let i = w * 64 + live[w].trailing_zeros() as usize;
            (i < end).then(|| {
                live[w] &= live[w] - 1;
                i
            })
        };
        if meta.has_status() {
            meta.with_status(|t| {
                t.each(first, last, |i, s| {
                    while let Some(j) = live_below(i) {
                        f(j, None);
                    }
                    // A live entry has no status, but the order stays right if it has one.
                    if live_below(i + 1).is_some() {
                        f(i, None);
                    } else {
                        f(i, Some(s));
                    }
                });
            });
        }
        while let Some(j) = live_below(SLOTS) {
            f(j, None);
        }
    }

    /// Gives the status of the page at `addr`. The caller holds the status table of the block,
    /// or the block has no status.
    ///
    /// # Panics
    ///
    /// If the block has a status and the current task does not hold its table. The same is true
    /// for each call below that reads or changes the statuses.
    pub fn status(&self, addr: VirtAddr) -> Option<PageStatus> {
        let a = addr.get();
        let lock = self.blocks.get(a).filter(|l| l.meta.has_status())?;
        lock.meta.with_status(|t| t.get(slot_of(a)).cloned())
    }

    /// Sets the status of each page in the page aligned range `start..end`, or removes it with
    /// `None`. The frames of the pages do not change. The caller holds the status table of each
    /// block of the range.
    pub fn set_status(&self, start: VirtAddr, end: VirtAddr, status: Option<&PageStatus>) {
        self.change_status(start, end, status, None, |_, _, _| {});
    }

    /// Sets the status of each page in the page aligned range `start..end`, or removes it with
    /// `None`, and makes the change `change` to the pages of the range, in one walk with one lock
    /// of each block. `old` gets each run of the old statuses of the range with one status value,
    /// in address order, with the lock of the block held, so it does not use this space. The range
    /// is small: the memory manager gives one block.
    pub fn change_status(
        &self,
        start: VirtAddr,
        end: VirtAddr,
        status: Option<&PageStatus>,
        mut change: Option<&mut PageChange>,
        mut old: impl FnMut(usize, usize, &PageStatus),
    ) {
        let (start, end) = (start.get(), end.get().min(USER_END));
        let mut block = block_of(start);
        while block < end {
            // A block with no lock has no status and no page.
            let lock = if status.is_some() {
                Some(self.blocks.get_or_make(block, BlockLock::default))
            } else {
                self.blocks.get(block)
            };
            if let Some(lock) = lock {
                let (from, to) = clip(block, start, end);
                let (first, last) = (slot_of(from), slot_of(to - 1) + 1);
                if status.is_some() || lock.meta.has_status() {
                    lock.meta.with_status(|t| {
                        t.runs(first, last, |a, z, s| {
                            old(block + a * PAGE_SIZE, block + z * PAGE_SIZE, s)
                        });
                        t.set(first, last, status);
                    });
                }
                if let Some(c) = change.as_deref_mut() {
                    self.change_block(&mut lock.lock(), block, from, to, c);
                }
            }
            block += HUGE_PAGE_SIZE;
        }
    }

    /// Makes the change `change` to the pages of the page aligned range `start..end`, with one
    /// lock of each block that has a page. The statuses do not change.
    pub fn change_pages(&self, start: VirtAddr, end: VirtAddr, change: &mut PageChange) {
        let (start, end) = (start.get(), end.get());
        let _ = self.blocks.each(start, end, |block, lock| {
            let (from, to) = clip(block, start, end);
            self.change_block(&mut lock.lock(), block, from, to, change);
            Ok::<(), ()>(())
        });
    }

    /// Ends the change `change`: one TLB flush for all its 4 KiB pages, and then the free of
    /// their frames.
    pub fn finish(&self, change: PageChange) {
        if change.flush {
            paging::user_flush_all(self.root);
        }
        drop(change);
    }

    /// Makes the change `c` to the pages of `from..to` in the block at `block`.
    fn change_block(
        &self,
        b: &mut Block,
        block: usize,
        from: usize,
        to: usize,
        c: &mut PageChange,
    ) {
        let whole = (from, to) == (block, block + HUGE_PAGE_SIZE);
        match c.op {
            PageOp::Unmap => {
                if let Some(huge) = b.huge.take_if(|_| whole) {
                    paging::user_unmap_huge(self.root, block, huge.table);
                    if huge.thp {
                        HUGE_MAPPED.fetch_sub(1, Ordering::Relaxed);
                    }
                    self.huge.fetch_sub(1, Ordering::Relaxed);
                    c.huge.push(huge);
                }
                self.split(b, block);
                let mut gone = b.pages.split_off(&from);
                let mut after = gone.split_off(&to);
                b.pages.append(&mut after);
                if gone.is_empty() {
                    return;
                }
                if c.each {
                    gone.keys().for_each(|&a| paging::user_unmap(self.root, a));
                } else {
                    c.flush |= paging::user_unmap_many(self.root, gone.keys().copied());
                }
                self.small.fetch_sub(gone.len(), Ordering::Relaxed);
                c.freed.push(gone);
            }
            PageOp::Protect(prot) => {
                if let Some(huge) = &mut b.huge {
                    // A huge page keeps one entry if its permissions do not change, as `protect`.
                    if huge.prot == prot {
                        return;
                    }
                    if whole && prot != PageProt::NONE {
                        huge.prot = prot;
                        let phys = huge.frames[0].addr().get();
                        paging::user_protect_huge(self.root, block, phys, prot.bits());
                        return;
                    }
                    self.split(b, block);
                }
                let pages = b.pages.range_mut(from..to).filter(|(_, (_, p))| *p != prot);
                let mut pages = pages.map(|(&a, (f, p))| {
                    *p = prot;
                    (a, f.addr().get(), prot.bits())
                });
                if c.each {
                    pages
                        .for_each(|(a, phys, bits)| paging::user_protect(self.root, a, phys, bits));
                } else {
                    c.flush |= paging::user_protect_many(self.root, &mut pages);
                }
            }
        }
    }

    /// Calls `f` with each run of pages in `start..end` that have the same status value, in
    /// address order. `f` runs with the lock of the block held, so it does not use this space.
    /// The walk looks at each 2 MiB block of the range, so the range is small: the memory manager
    /// gives one block. The walk uses a plain loop and not `BlockTree::each`, because it runs deep
    /// in the stack of `mmap` and the debug kernel has large frames.
    pub fn status_runs(
        &self,
        start: VirtAddr,
        end: VirtAddr,
        mut f: impl FnMut(usize, usize, &PageStatus),
    ) {
        let (mut addr, end) = (start.get(), end.get().min(USER_END));
        while addr < end {
            let block = block_of(addr);
            let to = end.min(block + HUGE_PAGE_SIZE);
            if let Some(lock) = self.blocks.get(addr).filter(|l| l.meta.has_status()) {
                lock.meta.with_status(|t| {
                    t.runs(slot_of(addr), slot_of(to - 1) + 1, |a, z, s| {
                        f(block + a * PAGE_SIZE, block + z * PAGE_SIZE, s)
                    });
                });
            }
            addr = to;
        }
    }

    /// Gives the run of the page at `addr` in its 2 MiB block: the largest range of pages around
    /// it with statuses that `same` joins, and the status of the first page of the run. `same`
    /// runs with the lock of the block held, so it does not use this space.
    pub fn status_run(
        &self,
        addr: VirtAddr,
        same: impl Fn(&PageStatus, &PageStatus) -> bool,
    ) -> Option<(usize, usize, PageStatus)> {
        let a = addr.get();
        let block = block_of(a);
        let lock = self.blocks.get(a).filter(|l| l.meta.has_status())?;
        let (first, end, s) = lock.meta.with_status(|t| t.run_at(slot_of(a), same))?;
        Some((block + first * PAGE_SIZE, block + end * PAGE_SIZE, s))
    }

    /// Tells if a page of the 2 MiB block of `addr` has a status. The answer is exact only for
    /// the holder of the status table, and it takes no lock.
    pub fn has_status(&self, addr: VirtAddr) -> bool {
        self.blocks.get(addr.get()).is_some_and(|l| l.meta.has_status())
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
        self.fork_with(areas, |_| None)
    }

    /// `fork`, and the child gets the status that `map` gives for each status of this space, or
    /// no status for `None`. The copy of the statuses is in the same walk of the page table as
    /// the copy of the pages. `map` gets each run of one status value in a block one time.
    ///
    /// # Errors
    ///
    /// As for `fork`.
    pub fn fork_with(
        &self,
        areas: &[ForkArea],
        mut map: impl FnMut(&PageStatus) -> Option<PageStatus>,
    ) -> Result<Self, MapError> {
        let child = Self::new().ok_or(MapError::NoMemory)?;
        let mut flush = false;
        let copied = self.blocks.each(0, USER_END, |block, lock| {
            child.fork_node(1, block, &lock.meta, &mut map);
            let mut b = lock.lock();
            self.fork_block(&child, &mut b, block, areas, &mut flush)
        });
        // The pages above the blocks come after the pages below them, so the child knows which
        // pages below a page are in its tree.
        if copied.is_ok() {
            self.blocks.each_node(|level, base, meta| child.fork_node(level, base, meta, &mut map));
        }
        if flush {
            paging::user_flush_all(self.root);
        }
        copied.map(|()| child)
    }

    /// Copies the statuses of `meta`, the page table page of `level` at `addr` of the parent, to
    /// this new space of a child of `fork`. The page of the child is in the tree if the page of
    /// the parent is, and if it has a status or a page below it in the tree of the child. The top
    /// is always in the tree. The parent holds each page of its tree. No other call uses the
    /// child yet.
    fn fork_node(
        &self,
        level: u32,
        addr: usize,
        meta: &Meta,
        map: &mut impl FnMut(&PageStatus) -> Option<PageStatus>,
    ) {
        if !meta.is_live() {
            return;
        }
        let status = if meta.has_status() {
            meta.with_status(|t| t.map(map))
        } else {
            StatusTable::default()
        };
        let below =
            self.meta(level, addr).is_some_and(|m| m.live_children.load(Ordering::Relaxed) > 0);
        if status.is_empty() && !below && level != TOP_LEVEL {
            return;
        }
        let c = self.meta_or_make(level, addr);
        c.hold();
        c.with_status(|t| *t = status);
        Self::set_live(&self.blocks, c, level, addr, true);
        c.release();
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
    /// huge page that is in part in the range is split first. The 4 KiB pages get one TLB flush
    /// at the end, as the `mmu_gather` of Linux (`tlb_finish_mmu` in mm/mmu_gather.c), and their
    /// frames go after that flush, so no CPU can use a frame that was freed. A flush for each
    /// page sent one shootdown for each page, and the `munmap` of `fault_mt` on 4 CPUs sent about
    /// 6000 shootdowns where Linux sends about 9 (#468).
    pub fn unmap_range(&self, start: VirtAddr, end: VirtAddr) {
        let mut change = PageChange::unmap(start, end);
        self.change_pages(start, end, &mut change);
        self.finish(change);
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

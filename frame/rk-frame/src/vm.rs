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
//! address space. A change to one page of the run splits the huge entry into a last level table
//! first. The table for the split is made when the huge page is mapped, as the deposited table of
//! Linux, so a split cannot fail.
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

/// An access to user memory found a page that is not mapped, or a write found a page that is not
/// writable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserFault {
    /// The first address that the access could not use.
    pub addr: usize,
    /// The access was a write.
    pub write: bool,
}

struct Inner {
    /// The physical address of the top level table.
    root: u64,
    /// The frame and the permissions at each mapped page address.
    pages: BTreeMap<usize, (Arc<Frame>, PageProt)>,
    /// The address of each huge page, and the last level table for its split.
    huge: BTreeMap<usize, u64>,
}

impl Inner {
    /// Changes the huge page that contains `addr`, if there is one, to 4 KiB pages.
    fn split(&mut self, addr: usize) {
        let block = addr & !(HUGE_PAGE_SIZE - 1);
        if let Some(table) = self.huge.remove(&block) {
            paging::user_split_huge(self.root, block, table);
            HUGE_MAPPED.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// The page table of one user address space.
pub struct VmSpace {
    inner: SpinLock<Inner>,
}

impl VmSpace {
    /// Makes an empty address space. Gives `None` if no frame is free for the top level table.
    pub fn new() -> Option<Self> {
        let root = paging::new_user_root()?;
        let inner = Inner { root, pages: BTreeMap::new(), huge: BTreeMap::new() };
        Some(Self { inner: SpinLock::new(inner) })
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
        if inner.pages.contains_key(&a) {
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
        let a = addr.get();
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
        if inner.pages.range(a..a + HUGE_PAGE_SIZE).next().is_some() {
            return Err(MapError::Mapped);
        }
        let table = paging::user_map_huge(inner.root, a, first, prot.bits())
            .map_err(|()| MapError::NoMemory)?;
        inner.huge.insert(a, table);
        HUGE_MAPPED.fetch_add(1, Ordering::Relaxed);
        for (i, f) in frames.into_iter().enumerate() {
            inner.pages.insert(a + i * PAGE_SIZE, (f, prot));
        }
        Ok(())
    }

    /// The number of huge pages that are mapped.
    pub fn huge_count(&self) -> usize {
        self.inner.lock().huge.len()
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
        while let Some((&block, &table)) = inner.huge.range(first..end).next() {
            if block >= start && block + HUGE_PAGE_SIZE <= end {
                inner.huge.remove(&block);
                paging::user_unmap_huge(inner.root, block, table);
                HUGE_MAPPED.fetch_sub(1, Ordering::Relaxed);
                while let Some((&a, _)) = inner.pages.range(block..block + HUGE_PAGE_SIZE).next() {
                    gone.extend(inner.pages.remove(&a));
                }
                drop(inner);
                gone.clear();
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
        if !inner.pages.contains_key(&addr.get()) {
            return None;
        }
        inner.split(addr.get());
        let (frame, _) = inner.pages.remove(&addr.get())?;
        paging::user_unmap(inner.root, addr.get());
        Some(frame)
    }

    /// Changes the permissions of the page at `addr`. Gives `false` if no page is mapped there.
    pub fn protect(&self, addr: VirtAddr, prot: PageProt) -> bool {
        let mut inner = self.inner.lock();
        let root = inner.root;
        let block = addr.get() & !(HUGE_PAGE_SIZE - 1);
        match inner.pages.get(&addr.get()) {
            None => return false,
            // A huge page stays whole when its permissions do not change.
            Some((_, old)) if *old == prot && inner.huge.contains_key(&block) => return true,
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
        self.inner.lock().pages.get(&page).cloned()
    }

    /// Gives the page addresses in `start..end` that are mapped, in order.
    pub fn mapped_pages(&self, start: VirtAddr, end: VirtAddr) -> alloc::vec::Vec<VirtAddr> {
        let inner = self.inner.lock();
        inner.pages.range(start.get()..end.get()).map(|(&a, _)| VirtAddr::new(a)).collect()
    }

    /// The number of mapped pages in `start..end`. It allocates no memory, so the OOM killer can
    /// use it.
    pub fn pages_in(&self, start: VirtAddr, end: VirtAddr) -> usize {
        self.inner.lock().pages.range(start.get()..end.get()).count()
    }

    /// Adds the page addresses in `start..end` that are mapped to `out`, in order. Gives `false`
    /// and adds nothing if the kernel heap has no memory for them.
    pub fn try_mapped_pages(&self, start: VirtAddr, end: VirtAddr, out: &mut Vec<usize>) -> bool {
        let inner = self.inner.lock();
        let pages = inner.pages.range(start.get()..end.get());
        if out.try_reserve(pages.clone().count()).is_err() {
            return false;
        }
        out.extend(pages.map(|(&a, _)| a));
        true
    }

    /// The number of mapped pages.
    pub fn page_count(&self) -> usize {
        self.inner.lock().pages.len()
    }

    /// Loads this address space, so the user code of the process can run.
    pub fn activate(&self) {
        paging::activate(self.inner.lock().root);
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
                match inner.pages.get(&page) {
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
        for &table in inner.huge.values() {
            free_frame_phys(table);
        }
        HUGE_MAPPED.fetch_sub(inner.huge.len(), Ordering::Relaxed);
        // The frames go when `pages` is dropped, after the tables that map them are gone.
    }
}

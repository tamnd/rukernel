//! The CortenMM backend of the address space. The `corten` feature of rk-mm selects it, per
//! spec/24-open-questions.md question 1.
//!
//! The statuses of the pages in a [`Tree`] are the source of truth, and there is no tree of
//! areas. A page fault, `mmap`, `munmap`, `mprotect` and `brk` lock only the nodes of their range,
//! so these calls on ranges in different nodes do not wait for each other. The other calls are
//! rare. They lock the whole tree with [`Corten::lock`], which makes the areas from the statuses,
//! lets the code of the VMA backend change them, and writes the changes back to the tree. The
//! areas that `/proc/PID/maps` shows come from the statuses in the same way: a run of pages with
//! the same status is one area.

use super::{
    Access, AddressSpace, FileRef, LOW32, MMAP_MIN_ADDR, MMAP_TOP, MmapRequest, STACK_GUARD_GAP,
    STACK_SIZE, SharedAnon, State, charge_commit, page_prot, uncharge_commit, write_back,
};
use crate::hugetlb::HPAGE_SIZE;
use crate::pttree::{RangeLock, TREE_END, Tree};
use crate::tunables::{self, OVERCOMMIT_NEVER};
use crate::vma::{Backing, HugeAdvice, PAGE_SIZE, Prot, Vma, VmaKind, VmaSet};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use rk_abi::Errno;
use rk_frame::addr::VirtAddr;
use rk_frame::sync::{SpinLock, SpinLockGuard};
use rk_frame::vm::{HUGE_PAGE_SIZE, USER_END};

/// The status of a page: the area that mapped it. The start and the file offset of the area give
/// the offset of each page. The end has no meaning, because a later call can change a part of
/// the pages.
pub(super) type Status = Arc<Vma<FileRef>>;

/// Tells if two statuses are the same area, so that two runs of pages next to each other with
/// them are one area. The attributes are the same, and a file has the same offset for each page.
/// These are the merge rules of `vma_merge` in Linux.
fn same_area(a: &Vma<FileRef>, b: &Vma<FileRef>) -> bool {
    let backing = match (&a.backing, &b.backing) {
        (Backing::Anon, Backing::Anon) => true,
        (Backing::File { file: f, offset: x }, Backing::File { file: g, offset: y }) => {
            Arc::ptr_eq(f, g) && x.wrapping_sub(a.start as u64) == y.wrapping_sub(b.start as u64)
        }
        _ => false,
    };
    backing
        && a.prot == b.prot
        && a.shared == b.shared
        && a.may_write == b.may_write
        && a.locked == b.locked
        && a.grows_down == b.grows_down
        && a.mergeable == b.mergeable
        && a.huge == b.huge
        && a.account == b.account
        && a.hugetlb == b.hugetlb
        && a.dont_fork == b.dont_fork
        && a.wipe_on_fork == b.wipe_on_fork
        && a.kind == b.kind
}

fn same_status(a: &Status, b: &Status) -> bool {
    Arc::ptr_eq(a, b) || same_area(a, b)
}

/// The area of the status `s` for the pages in `start..end`.
fn view(s: &Vma<FileRef>, start: usize, end: usize) -> Vma<FileRef> {
    let mut v = s.clone();
    // Each page of the area has the same offset from its address, so the wrapping sum is right
    // also for a start below the start of `s`.
    if let Backing::File { offset, .. } = &mut v.backing {
        *offset = offset.wrapping_add((start as u64).wrapping_sub(s.start as u64));
    }
    v.start = start;
    v.end = end;
    v
}

/// The areas in `start..end` of a locked range.
fn views(range: &RangeLock<Status>, start: usize, end: usize) -> Vec<Vma<FileRef>> {
    range.runs(start, end, same_status).into_iter().map(|(a, b, s)| view(&s, a, b)).collect()
}

/// The area of the page at `addr`, clipped to the span of the lock. A page fault uses it, and
/// its lock spans the 2 MiB block of the page.
fn area_at(range: &RangeLock<Status>, addr: usize) -> Option<Vma<FileRef>> {
    let (a, b, s) = range.run_at(addr, same_status)?;
    Some(view(&s, a, b))
}

/// A range in the set of reserved ranges. Only its range has a meaning.
fn placeholder(start: usize, end: usize) -> Vma<FileRef> {
    Vma::anon(start, end, Prot::default(), VmaKind::Normal)
}

/// Adds `start..end` to the reserved ranges.
fn reserve(va: &mut VmaSet<FileRef>, start: usize, end: usize) {
    va.remove_range(start, end);
    va.insert_merged(placeholder(start, end));
}

/// The data of an address space that is not in the tree.
pub(super) struct Meta {
    brk_start: usize,
    brk: usize,
    lock_future: bool,
    /// The guard pages of `MADV_GUARD_INSTALL`.
    guards: BTreeSet<usize>,
}

/// The state of an address space in the CortenMM backend.
///
/// The order of the locks is `meta`, then the nodes of the tree, then `va`. A call can skip a
/// lock, but it does not take them in another order.
pub(super) struct Corten {
    tree: Tree<Status>,
    /// The ranges that are mapped or that a `mmap` reserved. The search for a free range uses
    /// them, as the free list of a virtual address allocator. Each status is in a range of the
    /// set when no call is in progress.
    va: SpinLock<VmaSet<FileRef>>,
    meta: SpinLock<Meta>,
}

impl Corten {
    /// Makes the state with the areas of `st`.
    pub(super) fn new(st: State) -> Self {
        let c = Self {
            tree: Tree::new(),
            va: SpinLock::new(VmaSet::new()),
            meta: SpinLock::new(Meta {
                brk_start: 0,
                brk: 0,
                lock_future: false,
                guards: BTreeSet::new(),
            }),
        };
        *c.lock() = st;
        c
    }

    /// Locks the whole address space, and gives its areas.
    pub(super) fn lock(&self) -> Whole<'_> {
        let meta = self.meta.lock();
        let range = self.tree.lock(0, TREE_END);
        let va = self.va.lock();
        Whole::new(range, meta, va)
    }

    /// Locks the whole address space if no other call holds a part of it.
    pub(super) fn try_lock(&self) -> Option<Whole<'_>> {
        let meta = self.meta.try_lock()?;
        let range = self.tree.try_lock_all()?;
        let va = self.va.try_lock()?;
        Some(Whole::new(range, meta, va))
    }
}

/// The guard of the whole address space. It gives the areas as a [`State`], and writes the
/// changes back to the tree when it is dropped.
pub(super) struct Whole<'a> {
    range: RangeLock<Status>,
    meta: SpinLockGuard<'a, Meta>,
    va: SpinLockGuard<'a, VmaSet<FileRef>>,
    /// The areas before the changes.
    old: Vec<Vma<FileRef>>,
    state: State,
    changed: bool,
}

impl<'a> Whole<'a> {
    fn new(
        range: RangeLock<Status>,
        meta: SpinLockGuard<'a, Meta>,
        va: SpinLockGuard<'a, VmaSet<FileRef>>,
    ) -> Self {
        let old = views(&range, 0, TREE_END);
        let mut vmas = VmaSet::new();
        for v in &old {
            vmas.insert(v.clone());
        }
        let state = State {
            vmas,
            brk_start: meta.brk_start,
            brk: meta.brk,
            lock_future: meta.lock_future,
            guards: meta.guards.clone(),
        };
        Self { range, meta, va, old, state, changed: false }
    }
}

impl Deref for Whole<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        &self.state
    }
}

impl DerefMut for Whole<'_> {
    fn deref_mut(&mut self) -> &mut State {
        self.changed = true;
        &mut self.state
    }
}

impl Drop for Whole<'_> {
    fn drop(&mut self) {
        if !self.changed {
            return;
        }
        self.meta.brk_start = self.state.brk_start;
        self.meta.brk = self.state.brk;
        self.meta.lock_future = self.state.lock_future;
        self.meta.guards.clone_from(&self.state.guards);
        let new: Vec<Vma<FileRef>> = self.state.vmas.iter().cloned().collect();
        let same = |a: &Vma<FileRef>, b: &Vma<FileRef>| {
            a.start == b.start && a.end == b.end && same_area(a, b)
        };
        // Write only the range from the first area that changed to the last one.
        let n = self.old.len().min(new.len());
        let head = (0..n).find(|&i| !same(&self.old[i], &new[i])).unwrap_or(n);
        if head == self.old.len() && head == new.len() {
            return;
        }
        let tail = (0..n - head)
            .take_while(|&i| same(&self.old[self.old.len() - 1 - i], &new[new.len() - 1 - i]))
            .count();
        let (old, mid) = (&self.old[head..self.old.len() - tail], &new[head..new.len() - tail]);
        let lo = old.iter().chain(mid).map(|v| v.start).min().unwrap_or(0);
        let hi = old.iter().chain(mid).map(|v| v.end).max().unwrap_or(0);
        if lo < hi {
            self.range.set(lo, hi, None);
        }
        for v in mid {
            self.range.set(v.start, v.end, Some(Arc::new(v.clone())));
        }
        let mut va = VmaSet::new();
        for v in &new {
            va.insert_merged(placeholder(v.start, v.end));
        }
        *self.va = va;
    }
}

impl AddressSpace {
    /// Handles a page fault at `addr` with the lock of the node of its 2 MiB block.
    pub(super) fn corten_fault(&self, addr: usize, access: Access) -> Result<(), Errno> {
        let page = addr & !(PAGE_SIZE - 1);
        if page >= USER_END {
            return Err(Errno::EFAULT);
        }
        // A guard page gives `SIGSEGV`, as `handle_pte_marker` of Linux.
        if self.state.meta.lock().guards.contains(&page) {
            return Err(Errno::EFAULT);
        }
        loop {
            let range = self.state.tree.lock(page, page + PAGE_SIZE);
            if let Some(vma) = area_at(&range, page) {
                return self.fault_area(&vma, addr, access);
            }
            drop(range);
            // A fault below an area that grows down makes the area larger. This is rare, so it
            // locks the whole space.
            let mut st = self.state.lock();
            if st.vmas.find(addr).is_none() && !st.vmas.grow_down(addr, STACK_GUARD_GAP, STACK_SIZE)
            {
                return Err(Errno::EFAULT);
            }
        }
    }

    /// Gives the area of the page at `addr`, clipped to its 2 MiB block.
    pub(super) fn corten_area(&self, addr: usize) -> Option<Vma<FileRef>> {
        let page = addr & !(PAGE_SIZE - 1);
        if page >= USER_END {
            return None;
        }
        area_at(&self.state.tree.lock(page, page + PAGE_SIZE), page)
    }

    /// Removes the pages of `start..end` in a locked range, as `unmap_locked`.
    fn clear_locked(&self, range: &mut RangeLock<Status>, start: usize, end: usize) {
        for vma in views(range, start, end) {
            if vma.hugetlb && !vma.shared {
                self.unreserve_private(vma.start, vma.end);
            }
            self.vm.unmap_range(VirtAddr::new(vma.start), VirtAddr::new(vma.end));
            if vma.account {
                uncharge_commit(vma.len());
            }
            // munmap has no error for a failed write back, as on Linux.
            let _ = write_back(&vma, vma.start, vma.end);
        }
        range.set(start, end, None);
        self.state.va.lock().remove_range(start, end);
    }

    /// Tells if `start` or `end` is in a hugetlb area and is not 2 MiB aligned, as `splits_huge`.
    /// The range is locked up to `end` and one page more.
    fn corten_splits_huge(range: &RangeLock<Status>, start: usize, end: usize) -> bool {
        [start, end].into_iter().any(|x| {
            !x.is_multiple_of(HPAGE_SIZE) && x < TREE_END && range.get(x).is_some_and(|v| v.hugetlb)
        })
    }

    /// `mmap` of memory that is not hugetlb. `len` is page aligned.
    pub(super) fn corten_mmap(&self, req: MmapRequest, len: usize) -> Result<usize, Errno> {
        let lock_future = self.state.meta.lock().lock_future;
        let fixed = req.fixed || req.noreplace;
        if fixed {
            if !req.addr.is_multiple_of(PAGE_SIZE) {
                return Err(Errno::EINVAL);
            }
            if req.addr.checked_add(len).is_none_or(|e| e > USER_END) {
                return Err(Errno::ENOMEM);
            }
        }
        loop {
            let start = if fixed {
                req.addr
            } else {
                let mut va = self.state.va.lock();
                if va.len() > tunables::max_map_count() {
                    return Err(Errno::ENOMEM);
                }
                let (bottom, top) = if req.low32 { LOW32 } else { (MMAP_MIN_ADDR, MMAP_TOP) };
                let hint = req.addr & !(PAGE_SIZE - 1);
                let hint_ok = hint >= MMAP_MIN_ADDR
                    && hint
                        .checked_add(len)
                        .is_some_and(|e| e <= if req.low32 { top } else { USER_END })
                    && !va.overlaps(hint, hint + len);
                let gap = va.find_gap(len, bottom, top);
                let start = if hint_ok { hint } else { gap.ok_or(Errno::ENOMEM)? };
                reserve(&mut va, start, start + len);
                start
            };
            let end = start + len;
            let mut range = self.state.tree.lock(start, end);
            if range.any(start, end) {
                if req.noreplace {
                    return Err(Errno::EEXIST);
                }
                if !fixed {
                    // A `MAP_FIXED` call or a call on the whole space took the range after the
                    // search. Give back the part of the range that has no status, and search again.
                    let taken = views(&range, start, end);
                    let mut va = self.state.va.lock();
                    va.remove_range(start, end);
                    for v in taken {
                        reserve(&mut va, v.start, v.end);
                    }
                    continue;
                }
                self.clear_locked(&mut range, start, end);
            }
            if fixed && self.state.va.lock().len() > tunables::max_map_count() {
                return Err(Errno::ENOMEM);
            }
            let no_file = req.file.is_none();
            let account = !(req.noreserve && tunables::overcommit_memory() != OVERCOMMIT_NEVER)
                && if req.shared { no_file } else { req.prot.write };
            if account && let Err(e) = charge_commit(len) {
                if !fixed {
                    self.state.va.lock().remove_range(start, end);
                }
                return Err(e);
            }
            let backing = match req.file.clone() {
                Some((file, offset)) => Backing::File { file, offset },
                None if req.shared => {
                    let file: FileRef =
                        Arc::new(SharedAnon { pages: SpinLock::new(BTreeMap::new()) });
                    Backing::File { file, offset: 0 }
                }
                None => Backing::Anon,
            };
            let locked = req.locked || lock_future;
            let vma = Vma {
                start,
                end,
                prot: req.prot,
                shared: req.shared,
                may_write: req.may_write,
                locked,
                grows_down: req.grows_down,
                mergeable: false,
                huge: HugeAdvice::None,
                account,
                hugetlb: false,
                backing,
                kind: req.kind,
                dont_fork: false,
                wipe_on_fork: false,
            };
            range.set(start, end, Some(Arc::new(vma)));
            reserve(&mut self.state.va.lock(), start, end);
            drop(range);
            if req.populate || locked {
                // A page that cannot get its frame now gets it at the first access, as on Linux.
                let _ = self.populate(start, end);
            }
            return Ok(start);
        }
    }

    /// `munmap` of the page aligned range `start..end`.
    pub(super) fn corten_munmap(&self, start: usize, end: usize) -> Result<(), Errno> {
        let mut range = self.state.tree.lock(start, (end + PAGE_SIZE).min(TREE_END));
        if Self::corten_splits_huge(&range, start, end) {
            return Err(Errno::EINVAL);
        }
        self.clear_locked(&mut range, start, end);
        Ok(())
    }

    /// `mprotect` of the page aligned range `start..end`.
    pub(super) fn corten_mprotect(
        &self,
        start: usize,
        end: usize,
        prot: Prot,
    ) -> Result<(), Errno> {
        let mut range = self.state.tree.lock(start, (end + PAGE_SIZE).min(TREE_END));
        let old = views(&range, start, end);
        let mut at = start;
        for v in &old {
            if v.start != at {
                break;
            }
            at = v.end;
        }
        if at != end {
            return Err(Errno::ENOMEM);
        }
        if Self::corten_splits_huge(&range, start, end) {
            return Err(Errno::EINVAL);
        }
        if prot.write && old.iter().any(|v| !v.may_write) {
            return Err(Errno::EACCES);
        }
        // A private area that gets write access goes in the commit count, as in Linux.
        if prot.write {
            let more: usize =
                old.iter().filter(|v| !v.shared && !v.account && !v.hugetlb).map(Vma::len).sum();
            charge_commit(more)?;
        }
        for mut vma in old {
            vma.prot = prot;
            vma.account |= prot.write && !vma.shared && !vma.hugetlb;
            range.set(vma.start, vma.end, Some(Arc::new(vma.clone())));
            let mut next = 0;
            for page in self.vm.mapped_pages(VirtAddr::new(vma.start), VirtAddr::new(vma.end)) {
                let a = page.get();
                if a < next {
                    continue;
                }
                // A private page that gets write access stays read only, and the next write
                // fault makes it writable if this address space is its only user.
                let new = page_prot(&vma, false);
                // A huge page that is all in the range keeps one entry.
                if a.is_multiple_of(HUGE_PAGE_SIZE)
                    && a + HUGE_PAGE_SIZE <= vma.end
                    && self.vm.protect_huge(page, new)
                {
                    next = a + HUGE_PAGE_SIZE;
                    continue;
                }
                self.vm.protect(page, new);
            }
        }
        Ok(())
    }

    /// `brk`, as the VMA backend does it.
    pub(super) fn corten_brk(&self, addr: usize) -> usize {
        let mut meta = self.state.meta.lock();
        let (Some(old_end), Some(new_end)) =
            (crate::vma::page_up(meta.brk), crate::vma::page_up(addr))
        else {
            return meta.brk;
        };
        if addr < meta.brk_start || meta.brk_start == 0 || new_end > MMAP_TOP {
            return meta.brk;
        }
        if new_end > old_end {
            let mut range = self.state.tree.lock(old_end, new_end);
            if range.any(old_end, new_end) || charge_commit(new_end - old_end).is_err() {
                return meta.brk;
            }
            let mut vma = Vma::anon(old_end, new_end, Prot::RW, VmaKind::Heap);
            vma.locked = meta.lock_future;
            vma.account = true;
            range.set(old_end, new_end, Some(Arc::new(vma)));
            reserve(&mut self.state.va.lock(), old_end, new_end);
        } else if new_end < old_end {
            let mut range = self.state.tree.lock(new_end, old_end);
            self.clear_locked(&mut range, new_end, old_end);
        }
        meta.brk = addr;
        addr
    }
}

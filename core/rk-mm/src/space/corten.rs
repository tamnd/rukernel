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
    Access, AddressSpace, FileRef, LOW32, MMAP_MIN_ADDR, MMAP_TOP, MmapRequest, SharedAnon, State,
    charge_commit, map_error, page_prot, uncharge_commit, write_back,
};
use crate::hugetlb::HPAGE_SIZE;
use crate::pttree::{RangeLock, TREE_END, Tree};
use crate::tunables::{self, OVERCOMMIT_NEVER};
use crate::vma::{Backing, HugeAdvice, PAGE_SIZE, Prot, Vma, VmaKind, VmaSet};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicUsize, Ordering};
use rk_abi::Errno;
use rk_frame::addr::VirtAddr;
use rk_frame::sync::{SpinLock, SpinLockGuard};
use rk_frame::vm::{ForkArea, HUGE_PAGE_SIZE, USER_END};

/// The status of a page: the area that mapped it. The start and the file offset of the area give
/// the offset of each page. The end has no meaning, because a later call can change a part of
/// the pages.
pub(super) type Status = Arc<Vma<FileRef>>;

/// Tells if two statuses are the same area, so that two runs of pages next to each other with
/// them are one area. These are the merge rules of `vma_merge` in Linux, as the VMA backend uses
/// them.
fn same_status(a: &Status, b: &Status) -> bool {
    Arc::ptr_eq(a, b) || a.can_merge(b)
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

/// The number of areas in a list of areas in address order: a run of areas that touch and can
/// merge is one area, as in the tree.
fn area_count<'a>(areas: impl Iterator<Item = &'a Vma<FileRef>>) -> usize {
    let mut last: Option<&Vma<FileRef>> = None;
    let mut n = 0;
    for v in areas {
        if !last.is_some_and(|l| l.end == v.start && l.can_merge(v)) {
            n += 1;
        }
        last = Some(v);
    }
    n
}

/// The range of the lock of a change of `start..end`: one page more on each side, if the tree
/// has it, so that the change can count the areas that it joins or splits.
fn window(start: usize, end: usize) -> (usize, usize) {
    (start.saturating_sub(PAGE_SIZE), (end + PAGE_SIZE).min(TREE_END))
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
}

/// The state of an address space in the CortenMM backend.
///
/// The order of the locks is `meta`, then the nodes of the tree, then `va`, then `guards`. A call
/// can skip a lock, but it does not take them in another order.
pub(super) struct Corten {
    tree: Tree<Status>,
    /// The ranges that are mapped or that a `mmap` reserved. The search for a free range uses
    /// them, as the free list of a virtual address allocator. Each status is in a range of the
    /// set when no call is in progress.
    va: SpinLock<VmaSet<FileRef>>,
    meta: SpinLock<Meta>,
    /// The guard pages of `MADV_GUARD_INSTALL`. A call holds this lock only for a short time, and
    /// takes no other lock while it holds it.
    guards: SpinLock<BTreeSet<usize>>,
    /// The number of areas, as `map_count` of Linux. A change of a range locks one page more on
    /// each side, so it sees each area that it joins or splits, and two changes that can change
    /// the count of one area do not run at the same time.
    count: AtomicUsize,
}

impl Corten {
    /// Makes the state with the areas of `st`.
    pub(super) fn new(st: State) -> Self {
        let c = Self {
            tree: Tree::new(),
            va: SpinLock::new(VmaSet::new()),
            meta: SpinLock::new(Meta { brk_start: 0, brk: 0, lock_future: false }),
            guards: SpinLock::new(BTreeSet::new()),
            count: AtomicUsize::new(0),
        };
        *c.lock() = st;
        c
    }

    /// Sets the status of `start..end` in `range`, and changes the count of areas. `range` locks
    /// the [`window`] of the range.
    fn set(&self, range: &mut RangeLock<Status>, start: usize, end: usize, status: Option<Status>) {
        let (lo, hi) = window(start, end);
        let before = range.runs(lo, hi, same_status).len();
        range.set(start, end, status);
        let after = range.runs(lo, hi, same_status).len();
        if after >= before {
            self.count.fetch_add(after - before, Ordering::Relaxed);
        } else {
            self.count.fetch_sub(before - after, Ordering::Relaxed);
        }
    }

    /// The number of areas.
    fn count(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// Locks the whole address space, and gives its areas.
    pub(super) fn lock(&self) -> Whole<'_> {
        let meta = self.meta.lock();
        let range = self.tree.lock(0, TREE_END);
        let va = self.va.lock();
        Whole::new(range, meta, va, &self.guards, &self.count)
    }

    /// Locks the whole address space if no other call holds a part of it.
    pub(super) fn try_lock(&self) -> Option<Whole<'_>> {
        let meta = self.meta.try_lock()?;
        let range = self.tree.try_lock_all()?;
        let va = self.va.try_lock()?;
        Some(Whole::new(range, meta, va, &self.guards, &self.count))
    }
}

/// The guard of the whole address space. It gives the areas as a [`State`], and writes the
/// changes back to the tree when it is dropped.
pub(super) struct Whole<'a> {
    range: RangeLock<Status>,
    meta: SpinLockGuard<'a, Meta>,
    va: SpinLockGuard<'a, VmaSet<FileRef>>,
    guards: &'a SpinLock<BTreeSet<usize>>,
    count: &'a AtomicUsize,
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
        guards: &'a SpinLock<BTreeSet<usize>>,
        count: &'a AtomicUsize,
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
            guards: guards.lock().clone(),
        };
        Self { range, meta, va, guards, count, old, state, changed: false }
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
        self.guards.lock().clone_from(&self.state.guards);
        let new: Vec<Vma<FileRef>> = self.state.vmas.iter().cloned().collect();
        self.count.store(area_count(new.iter()), Ordering::Relaxed);
        let same = |a: &Vma<FileRef>, b: &Vma<FileRef>| {
            a.start == b.start && a.end == b.end && a.same_mapping(b)
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
    /// `fork` with a walk of the tree. The child gets a copy of the tree, as `dup_mmap` in
    /// kernel/fork.c of Linux copies the areas, and no call makes the list of areas.
    pub(super) fn corten_fork(&self) -> Result<Self, Errno> {
        let meta = self.state.meta.lock();
        let all = self.state.tree.lock(0, TREE_END);
        let runs = all.runs(0, TREE_END, same_status);
        // An area of `MADV_DONTFORK` does not go to the child, and an area of `MADV_WIPEONFORK`
        // goes without its pages.
        let copied = |s: &Status| !s.dont_fork && !s.wipe_on_fork;
        let areas: Vec<ForkArea> = runs
            .iter()
            .filter(|r| copied(&r.2))
            .map(|r| ForkArea { start: r.0, end: r.1, shared: r.2.shared })
            .collect();
        let vm = self.vm.fork(&areas).map_err(map_error)?;
        // The private areas of the child go in the commit count. The memory of a shared area is
        // in the count one time.
        let charge = runs.iter().filter(|r| r.2.account && !r.2.shared && !r.2.dont_fork);
        charge_commit(charge.map(|r| r.1 - r.0).sum())?;
        // The child does not get the locks of the parent, as on Linux. Each status of the parent
        // gives one status of the child, so the pages of an area keep one status.
        let mut copies: BTreeMap<usize, Option<Status>> = BTreeMap::new();
        // The slots of a node often hold the same status, so the last copy comes first.
        let mut recent: Option<(usize, Option<Status>)> = None;
        let mut map = |s: &Status| {
            let key = Arc::as_ptr(s) as usize;
            if let Some((k, copy)) = &recent
                && *k == key
            {
                return copy.clone();
            }
            let copy = copies.entry(key).or_insert_with(|| {
                (!s.dont_fork).then(|| {
                    let mut v = Vma::clone(s);
                    v.locked = false;
                    v.account &= !v.shared;
                    Arc::new(v)
                })
            });
            recent = Some((key, copy.clone()));
            copy.clone()
        };
        let tree = Tree::fork(&all, &mut map);
        let mut va = VmaSet::new();
        let mut count = 0;
        let mut last: Option<(usize, Status)> = None;
        for (start, end, s) in &runs {
            let Some(s) = map(s) else { continue };
            va.insert_merged(placeholder(*start, *end));
            if !last.as_ref().is_some_and(|(e, l)| e == start && same_status(l, &s)) {
                count += 1;
            }
            last = Some((*end, s));
        }
        // The guard pages of the areas with their pages go to the child, as the guard markers
        // that `copy_page_range` of Linux copies.
        let guards: BTreeSet<usize> = {
            let guards = self.state.guards.lock();
            let keep = |g: &&usize| {
                let i = runs.partition_point(|r| r.1 <= **g);
                runs.get(i).is_some_and(|r| r.0 <= **g && copied(&r.2))
            };
            guards.iter().filter(keep).copied().collect()
        };
        let state = Corten {
            tree,
            va: SpinLock::new(va),
            meta: SpinLock::new(Meta {
                brk_start: meta.brk_start,
                brk: meta.brk,
                lock_future: false,
            }),
            guards: SpinLock::new(guards),
            count: AtomicUsize::new(count),
        };
        drop(all);
        drop(meta);
        Ok(Self::with_state(vm, state))
    }

    /// Handles a page fault at `addr` with the lock of the node of its 2 MiB block.
    pub(super) fn corten_fault(&self, addr: usize, access: Access) -> Result<(), Errno> {
        let page = addr & !(PAGE_SIZE - 1);
        if page >= USER_END {
            return Err(Errno::EFAULT);
        }
        // A guard page gives `SIGSEGV`, as `handle_pte_marker` of Linux.
        if self.state.guards.lock().contains(&page) {
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
            if st.vmas.find(addr).is_none() {
                self.grow_stack(&mut st, addr)?;
            }
        }
    }

    /// Tells if the page at `page` is a guard page.
    pub(super) fn corten_is_guard(&self, page: usize) -> bool {
        self.state.guards.lock().contains(&page)
    }

    /// Gives the area of the page at `addr`, clipped to its 2 MiB block.
    pub(super) fn corten_area(&self, addr: usize) -> Option<Vma<FileRef>> {
        let page = addr & !(PAGE_SIZE - 1);
        if page >= USER_END {
            return None;
        }
        area_at(&self.state.tree.lock(page, page + PAGE_SIZE), page)
    }

    /// Removes the pages of `start..end` in a locked range, as `unmap_locked`. The range locks the
    /// [`window`] of `start..end`.
    fn clear_locked(&self, range: &mut RangeLock<Status>, start: usize, end: usize) {
        // The guard pages of the range go with it, as on Linux.
        {
            let mut guards = self.state.guards.lock();
            let inside: Vec<usize> = guards.range(start..end).copied().collect();
            for g in inside {
                guards.remove(&g);
            }
        }
        for vma in views(range, start, end) {
            if vma.hugetlb && !vma.shared {
                self.unreserve_private(vma.start, vma.end);
            }
            self.unmap_pages(VirtAddr::new(vma.start), VirtAddr::new(vma.end));
            if vma.account {
                uncharge_commit(vma.len());
            }
            // munmap has no error for a failed write back, as on Linux.
            let _ = write_back(&vma, vma.start, vma.end);
        }
        self.state.set(range, start, end, None);
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
                if self.state.count() > tunables::max_map_count() {
                    return Err(Errno::ENOMEM);
                }
                let mut va = self.state.va.lock();
                let (bottom, top) =
                    if req.low32 { LOW32 } else { (MMAP_MIN_ADDR, self.mmap_top()) };
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
            let (lo, hi) = window(start, end);
            let mut range = self.state.tree.lock(lo, hi);
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
            if fixed && self.state.count() > tunables::max_map_count() {
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
            self.state.set(&mut range, start, end, Some(Arc::new(vma)));
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
        let (lo, hi) = window(start, end);
        let mut range = self.state.tree.lock(lo, hi);
        if Self::corten_splits_huge(&range, start, end) {
            return Err(Errno::EINVAL);
        }
        // The unmap of the middle of an area makes one area more. Linux lets the count go above
        // `max_map_count` for a short time only, so it gives `ENOMEM` here, as
        // `do_vmi_align_munmap` in mm/vma.c.
        if lo < start
            && end < hi
            && self.state.count() >= tunables::max_map_count()
            && matches!(&range.runs(lo, hi, same_status)[..], [(a, b, _)] if *a == lo && *b == hi)
        {
            return Err(Errno::ENOMEM);
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
        let (lo, hi) = window(start, end);
        let mut range = self.state.tree.lock(lo, hi);
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
            self.state.set(&mut range, vma.start, vma.end, Some(Arc::new(vma.clone())));
            let mut next = 0;
            for page in self.vm.mapped_pages(VirtAddr::new(vma.start), VirtAddr::new(vma.end)) {
                let a = page.get();
                if a < next {
                    continue;
                }
                // A private page that gets write access stays read only, and the next write
                // fault makes it writable if this address space is its only user.
                let new = self.soft_prot(a, page_prot(&vma, false));
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
            let (lo, hi) = window(old_end, new_end);
            let mut range = self.state.tree.lock(lo, hi);
            if range.any(old_end, new_end) || charge_commit(new_end - old_end).is_err() {
                return meta.brk;
            }
            let mut vma = Vma::anon(old_end, new_end, Prot::RW, VmaKind::Heap);
            vma.locked = meta.lock_future;
            vma.account = true;
            self.state.set(&mut range, old_end, new_end, Some(Arc::new(vma)));
            reserve(&mut self.state.va.lock(), old_end, new_end);
            self.soft.lock().mapped(old_end, new_end);
        } else if new_end < old_end {
            let (lo, hi) = window(new_end, old_end);
            let mut range = self.state.tree.lock(lo, hi);
            self.clear_locked(&mut range, new_end, old_end);
        }
        meta.brk = addr;
        addr
    }
}

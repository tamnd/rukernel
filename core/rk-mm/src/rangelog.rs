//! A log of the changes to the used ranges of an address space, for the search for a free range
//! of `mmap`.
//!
//! The CortenMM backend keeps the used ranges in a [`VmaSet`] with its own lock, and `mmap`
//! searches it for a free range, as `vm_unmapped_area` of Linux (mm/mmap.c) searches the maple
//! tree. The page table tree is the source of truth. The set is only a fast copy of it, so a
//! call that changes the tree does not need the lock of the set. It adds the change to this log
//! instead, and the next search applies the log to the set first.
//!
//! The log has one part for each group of CPUs, so the calls of two CPUs do not share a lock. A
//! change gets a sequence number while the caller holds the lock of the range in the tree. Two
//! changes of ranges that overlap thus get their numbers in the order of the changes to the tree,
//! and the search applies them in this order.

use crate::vma::{Prot, Vma, VmaKind, VmaSet};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_frame::sync::SpinLock;

/// The number of parts of a log.
pub const PARTS: usize = 8;

/// The number of changes in one part above which the caller applies the log, so that the log of
/// a process that never searches stays small.
pub const PART_LIMIT: usize = 64;

/// A change of the used ranges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Change {
    seq: u64,
    /// The start of the range.
    pub start: usize,
    /// The end of the range.
    pub end: usize,
    /// `true` if the range is now used, `false` if it is now free.
    pub used: bool,
}

/// A part of the log on its own cache line, so two CPUs that add changes do not share a line.
#[repr(align(64))]
struct Part(SpinLock<Vec<Change>>);

/// The log of the changes of the used ranges of one address space.
pub struct RangeLog {
    seq: AtomicU64,
    parts: [Part; PARTS],
}

impl Default for RangeLog {
    fn default() -> Self {
        Self::new()
    }
}

impl RangeLog {
    /// Makes an empty log.
    pub fn new() -> Self {
        Self {
            seq: AtomicU64::new(0),
            parts: core::array::from_fn(|_| Part(SpinLock::new(Vec::new()))),
        }
    }

    /// Adds a change of `start..end` from the CPU `cpu`. The caller holds the lock of the range in
    /// the page table tree. Gives `true` if the part of the CPU is long, and the caller must then
    /// apply the log.
    pub fn push(&self, cpu: usize, start: usize, end: usize, used: bool) -> bool {
        if start >= end {
            return false;
        }
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let mut part = self.parts[cpu % PARTS].0.lock();
        part.push(Change { seq, start, end, used });
        part.len() > PART_LIMIT
    }

    /// Takes all the changes, in the order of their numbers.
    pub fn take(&self) -> Vec<Change> {
        let mut all = Vec::new();
        for part in &self.parts {
            let mut p = part.0.lock();
            if all.is_empty() {
                core::mem::swap(&mut all, &mut *p);
            } else {
                all.append(&mut p);
            }
        }
        all.sort_unstable_by_key(|c| c.seq);
        all
    }

    /// Tells if the log has no change.
    pub fn is_empty(&self) -> bool {
        self.parts.iter().all(|p| p.0.lock().is_empty())
    }

    /// Applies all the changes to the used ranges `va`, and empties the log.
    pub fn apply<F: Clone + PartialEq>(&self, va: &mut VmaSet<F>) {
        for c in self.take() {
            if c.used {
                reserve(va, c.start, c.end);
            } else {
                va.remove_range(c.start, c.end);
            }
        }
    }
}

/// Adds `start..end` to the used ranges `va`. Only the range of the area in the set has a meaning.
pub fn reserve<F: Clone + PartialEq>(va: &mut VmaSet<F>, start: usize, end: usize) {
    va.remove_range(start, end);
    va.insert_merged(Vma::anon(start, end, Prot::default(), VmaKind::Normal));
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const P: usize = crate::vma::PAGE_SIZE;

    fn ranges(va: &VmaSet<u32>) -> Vec<(usize, usize)> {
        va.iter().map(|v| (v.start, v.end)).collect()
    }

    #[test]
    fn changes_apply_in_order() {
        let log = RangeLog::new();
        let mut va: VmaSet<u32> = VmaSet::new();
        // The changes of one range come from different CPUs.
        log.push(0, 10 * P, 20 * P, true);
        log.push(3, 12 * P, 14 * P, false);
        log.push(5, 12 * P, 13 * P, true);
        log.push(1, 30 * P, 31 * P, true);
        log.push(2, 30 * P, 30 * P, true);
        log.apply(&mut va);
        assert!(log.is_empty());
        assert_eq!(ranges(&va), [(10 * P, 13 * P), (14 * P, 20 * P), (30 * P, 31 * P)]);
        // A later change frees a part that a direct reservation used.
        reserve(&mut va, 40 * P, 42 * P);
        log.push(7, 41 * P, 42 * P, false);
        log.apply(&mut va);
        assert_eq!(va.iter().last().map(|v| (v.start, v.end)), Some((40 * P, 41 * P)));
    }

    #[test]
    fn a_long_part_asks_for_an_apply() {
        let log = RangeLog::new();
        let long = (0..=PART_LIMIT).map(|i| log.push(4, i * 2 * P, (i * 2 + 1) * P, true));
        assert_eq!(long.filter(|&l| l).count(), 1);
        // The other parts stay short.
        assert!(!log.push(5, 0, P, false));
        assert_eq!(log.take().len(), PART_LIMIT + 2);
    }

    #[test]
    fn threads_with_a_lock_for_each_range() {
        use std::sync::Arc as StdArc;
        // Two threads share each lock, as two calls lock the same range of the tree. Each thread
        // maps and unmaps its own pages with the lock held. The last change of each page is an
        // unmap, except for the last page of the first thread of each lock.
        let log = StdArc::new(RangeLog::new());
        let locks: StdArc<Vec<std::sync::Mutex<()>>> =
            StdArc::new((0..4).map(|_| std::sync::Mutex::new(())).collect());
        let workers: Vec<_> = (0..8usize)
            .map(|n| {
                let (log, locks) = (log.clone(), locks.clone());
                std::thread::spawn(move || {
                    for i in 0..500 {
                        let r = n % 4;
                        let page = (r * 1000 + n / 4 * 100 + i % 50) * P;
                        let _g = locks[r].lock().unwrap();
                        log.push(n, page, page + P, true);
                        if i != 499 || n >= 4 {
                            log.push(n, page, page + P, false);
                        }
                    }
                })
            })
            .collect();
        let mut va: VmaSet<u32> = VmaSet::new();
        // The search applies the log while the threads run.
        for _ in 0..50 {
            log.apply(&mut va);
        }
        for w in workers {
            w.join().unwrap();
        }
        log.apply(&mut va);
        let want: Vec<(usize, usize)> =
            (0..4).map(|r| ((r * 1000 + 49) * P, (r * 1000 + 50) * P)).collect();
        assert_eq!(ranges(&va), want);
    }
}

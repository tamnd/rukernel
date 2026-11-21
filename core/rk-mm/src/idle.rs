//! The mark of an address space that the reclaim of anonymous memory found with no page to take.
//!
//! The reclaim of a memory cgroup looks at each process of the cgroup in turn. A process that
//! only sleeps, or whose pages `fork` shares with its children, has no page that can go. Linux
//! takes pages from the LRU lists of the cgroup and does not look at such a process again and
//! again. Here the reclaim looks at the page tables, so it skips a space that had no page to give
//! at the last look and that has the same number of pages now. The mark is good for
//! [`IDLE_NS`] only, because a page can become a page of only one space without a fault of
//! this space, for example when a child exits.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// The time in nanoseconds for which a mark stays good.
pub const IDLE_NS: u64 = 1_000_000_000;

/// The mark. The pages are one more than the number of pages of the space at the look, and 0
/// when the space has no mark.
#[derive(Default)]
pub struct Idle {
    pages: AtomicUsize,
    at: AtomicU64,
}

impl Idle {
    /// Marks the space, which has `pages` pages at the time `now` and no page to give.
    pub fn mark(&self, pages: usize, now: u64) {
        self.at.store(now, Ordering::Relaxed);
        self.pages.store(pages.saturating_add(1), Ordering::Relaxed);
    }

    /// Removes the mark.
    pub fn clear(&self) {
        self.pages.store(0, Ordering::Relaxed);
    }

    /// Tells if the reclaim can skip the space, which has `pages` pages at the time `now`.
    pub fn skip(&self, pages: usize, now: u64) -> bool {
        self.pages.load(Ordering::Relaxed) == pages.saturating_add(1)
            && now.saturating_sub(self.at.load(Ordering::Relaxed)) < IDLE_NS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_space_with_no_mark_is_not_skipped() {
        let idle = Idle::default();
        assert!(!idle.skip(0, 0));
        assert!(!idle.skip(5, 100));
    }

    #[test]
    fn a_marked_space_is_skipped_while_its_pages_stay_the_same() {
        let idle = Idle::default();
        idle.mark(10, 1000);
        assert!(idle.skip(10, 1000));
        assert!(idle.skip(10, 1000 + IDLE_NS - 1));
        // A fault or an unmap changes the pages, and the reclaim looks again.
        assert!(!idle.skip(11, 1000));
        assert!(!idle.skip(9, 1000));
    }

    #[test]
    fn a_mark_ends_after_its_time_or_a_clear() {
        let idle = Idle::default();
        idle.mark(0, 1000);
        assert!(idle.skip(0, 1000));
        assert!(!idle.skip(0, 1000 + IDLE_NS));
        idle.mark(3, 5);
        idle.clear();
        assert!(!idle.skip(3, 5));
    }
}

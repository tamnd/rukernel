//! The soft-dirty state of the pages of an address space, as `CONFIG_MEM_SOFT_DIRTY` of Linux.
//!
//! A write of 4 to `/proc/PID/clear_refs` makes all the pages of the process clean. The kernel then
//! makes the pages read only, so the next write to a page is a fault that marks the page
//! soft-dirty again. `/proc/PID/pagemap` shows the state in the bit 55 of each entry.
//!
//! Linux keeps the state in a bit of each page table entry and in the flag `VM_SOFTDIRTY` of each
//! area. A new area has the flag, so all its pages are soft-dirty. [`SoftDirty`] keeps the same
//! state without the page tables, so the tests on the host examine it. The clean ranges are the
//! areas without `VM_SOFTDIRTY`, and the written pages are the entries with the bit.

use alloc::collections::{BTreeMap, BTreeSet};

/// The size of a page.
const PAGE: usize = crate::vma::PAGE_SIZE;

/// The soft-dirty state of one address space.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SoftDirty {
    /// The ranges that were clean at the last clear and that no new map covered after it, by
    /// start, with their ends. The ranges do not overlap and do not touch.
    clean: BTreeMap<usize, usize>,
    /// The pages in the clean ranges that a write changed after the last clear.
    written: BTreeSet<usize>,
}

impl SoftDirty {
    /// Makes the state of a new address space, where all the pages are soft-dirty.
    pub const fn new() -> Self {
        Self { clean: BTreeMap::new(), written: BTreeSet::new() }
    }

    /// Tells if a clear made a range clean. If not, all the pages are soft-dirty and the faults
    /// need no change.
    pub fn tracking(&self) -> bool {
        !self.clean.is_empty()
    }

    /// Makes the pages in `ranges` clean, as `clear_soft_dirty` and the clear of `VM_SOFTDIRTY` of
    /// Linux. `ranges` are the areas of the address space as `(start, end)`, in address order.
    pub fn clear(&mut self, ranges: impl IntoIterator<Item = (usize, usize)>) {
        self.clean.clear();
        self.written.clear();
        for (start, end) in ranges {
            if start >= end {
                continue;
            }
            // Two areas that touch become one range.
            match self.clean.last_key_value() {
                Some((&s, &e)) if e == start => {
                    self.clean.insert(s, end);
                }
                _ => {
                    self.clean.insert(start, end);
                }
            }
        }
    }

    /// Records that `start..end` has a new map, as a new area with `VM_SOFTDIRTY` of Linux. All
    /// its pages become soft-dirty, also the pages with no frame.
    pub fn mapped(&mut self, start: usize, end: usize) {
        if start >= end || self.clean.is_empty() {
            return;
        }
        // The ranges that overlap `start..end`, as the range before `start` can reach into it.
        let first = self.clean.range(..start).next_back().map_or(start, |(&s, _)| s);
        let hit: alloc::vec::Vec<(usize, usize)> = self
            .clean
            .range(first..end)
            .filter(|&(_, &e)| e > start)
            .map(|(&s, &e)| (s, e))
            .collect();
        for (s, e) in hit {
            self.clean.remove(&s);
            if s < start {
                self.clean.insert(s, start);
            }
            if end < e {
                self.clean.insert(end, e);
            }
        }
        let gone: alloc::vec::Vec<usize> = self.written.range(start..end).copied().collect();
        for page in gone {
            self.written.remove(&page);
        }
    }

    /// Records that the area at `old` grew down to `start`, as `expand_downwards` of Linux. The
    /// area keeps its state, so the new pages are clean if the area is clean. A fault then marks
    /// each page that a write changes.
    pub fn grew(&mut self, start: usize, old: usize) {
        let Some((&s, &e)) = self.clean.range(..=old).next_back().filter(|&(_, &e)| old < e) else {
            return;
        };
        if s <= start {
            return;
        }
        self.clean.remove(&s);
        // A range before `start` can reach the new range.
        match self.clean.range(..s).next_back() {
            Some((&below, &end)) if end >= start => {
                self.clean.insert(below, e);
            }
            _ => {
                self.clean.insert(start, e);
            }
        }
    }

    /// Records that the pages in `start..end` lost their frames, as the zap of the page table
    /// entries of Linux removes their soft-dirty bits. A page there then has only the state of
    /// its area until a write marks it again.
    pub fn unmapped(&mut self, start: usize, end: usize) {
        if self.written.range(start..end).next().is_none() {
            return;
        }
        let gone: alloc::vec::Vec<usize> = self.written.range(start..end).copied().collect();
        for page in gone {
            self.written.remove(&page);
        }
    }

    /// Records a write to the pages in `start..end`, as the soft-dirty bit that a write fault sets
    /// in a page table entry of Linux.
    pub fn wrote(&mut self, start: usize, end: usize) {
        let mut page = start & !(PAGE - 1);
        while page < end {
            if self.in_clean(page) {
                self.written.insert(page);
            }
            page += PAGE;
        }
    }

    /// Tells if the page at `page` is in a clean range, so a page there has the soft-dirty bit
    /// only after a write.
    fn in_clean(&self, page: usize) -> bool {
        self.clean.range(..=page).next_back().is_some_and(|(_, &e)| page < e)
    }

    /// Tells if the page at `page` is soft-dirty. `present` tells that the page has a frame. A page
    /// with no frame has only the state of its area, as `pagemap_pte_hole` of Linux.
    pub fn is_dirty(&self, page: usize, present: bool) -> bool {
        let page = page & !(PAGE - 1);
        !self.in_clean(page) || (present && self.written.contains(&page))
    }

    /// Tells if any page in `start..end` is clean, so a page there must stay read only until a
    /// write marks it.
    pub fn any_clean(&self, start: usize, end: usize) -> bool {
        let mut page = start & !(PAGE - 1);
        while page < end {
            if self.in_clean(page) && !self.written.contains(&page) {
                return true;
            }
            page += PAGE;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: usize = PAGE;

    #[test]
    fn new_pages_are_dirty() {
        let s = SoftDirty::new();
        assert!(!s.tracking());
        assert!(s.is_dirty(0x1000, true));
        assert!(s.is_dirty(0x1000, false));
        assert!(!s.any_clean(0, 16 * P));
    }

    #[test]
    fn clear_then_write() {
        let mut s = SoftDirty::new();
        s.clear([(0x10_000, 0x20_000), (0x20_000, 0x30_000), (0x40_000, 0x41_000)]);
        assert!(s.tracking());
        assert_eq!(s.clean.len(), 2);
        assert!(!s.is_dirty(0x10_000, true));
        assert!(!s.is_dirty(0x2f_fff, true));
        assert!(s.is_dirty(0x30_000, true));
        s.wrote(0x12_000, 0x12_000 + P);
        assert!(s.is_dirty(0x12_000, true));
        assert!(s.is_dirty(0x12_abc, true));
        // A page with no frame has the state of its area.
        assert!(!s.is_dirty(0x12_000, false));
        assert!(!s.is_dirty(0x13_000, true));
        assert!(s.any_clean(0x12_000, 0x14_000));
        assert!(!s.any_clean(0x12_000, 0x13_000));
        // A write outside the clean ranges needs no record.
        s.wrote(0x30_000, 0x31_000);
        assert_eq!(s.written.len(), 1);
        // A new clear makes the written pages clean again.
        s.clear([(0x10_000, 0x30_000)]);
        assert!(!s.is_dirty(0x12_000, true));
    }

    #[test]
    fn new_map_is_dirty() {
        let mut s = SoftDirty::new();
        s.clear([(0x10_000, 0x20_000)]);
        s.wrote(0x15_000, 0x16_000);
        s.mapped(0x14_000, 0x16_000);
        assert!(s.is_dirty(0x14_000, false));
        assert!(s.is_dirty(0x15_000, false));
        assert!(!s.is_dirty(0x13_000, true));
        assert!(!s.is_dirty(0x16_000, true));
        assert!(s.written.is_empty());
        assert_eq!(s.clean.len(), 2);
        // A map over all the clean ranges ends the tracking.
        s.mapped(0, 0x100_000);
        assert!(!s.tracking());
        assert!(s.is_dirty(0x10_000, false));
    }

    #[test]
    fn stack_growth_is_clean() {
        let mut s = SoftDirty::new();
        s.clear([(0x10_000, 0x20_000), (0x40_000, 0x50_000)]);
        s.grew(0x3c_000, 0x40_000);
        assert!(!s.is_dirty(0x3c_000, false));
        assert!(!s.is_dirty(0x3f_000, true));
        assert!(s.is_dirty(0x3b_000, false));
        assert_eq!(s.clean.get(&0x3c_000), Some(&0x50_000));
        // A write marks the new page as any other page.
        s.wrote(0x3c_000, 0x3d_000);
        assert!(s.is_dirty(0x3c_000, true));
        // The growth of an area that a new map made soft-dirty stays soft-dirty.
        s.mapped(0x60_000, 0x70_000);
        s.grew(0x5c_000, 0x60_000);
        assert!(s.is_dirty(0x5c_000, false));
        // The new range joins a clean range below it.
        s.grew(0x20_000, 0x3c_000);
        assert_eq!(s.clean.get(&0x10_000), Some(&0x50_000));
        assert_eq!(s.clean.len(), 1);
    }

    #[test]
    fn unmap_clears_the_written_pages() {
        let mut s = SoftDirty::new();
        s.clear([(0x10_000, 0x20_000)]);
        s.wrote(0x11_000, 0x13_000);
        s.unmapped(0x12_000, 0x20_000);
        assert!(s.is_dirty(0x11_000, true));
        // A page that comes back after the unmap is clean until a write.
        assert!(!s.is_dirty(0x12_000, true));
        assert!(s.any_clean(0x12_000, 0x13_000));
        s.unmapped(0, 0x100_000);
        assert!(s.written.is_empty());
        assert!(s.tracking());
    }

    #[test]
    fn huge_write_marks_each_page() {
        let mut s = SoftDirty::new();
        s.clear([(0x20_0000, 0x60_0000)]);
        s.wrote(0x20_0000, 0x40_0000);
        assert!(s.is_dirty(0x3f_f000, true));
        assert!(!s.is_dirty(0x40_0000, true));
    }
}

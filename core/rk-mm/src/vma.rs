//! The virtual memory areas of an address space.
//!
//! A `Vma` is a range of user addresses with one set of permissions and one backing: anonymous
//! memory or a file. Linux names it `struct vm_area_struct`. The `VmaSet` keeps the areas of one
//! address space in order, and splits an area when a call changes a part of it.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// The size of a page.
pub const PAGE_SIZE: usize = 4096;

/// Rounds `value` up to a multiple of the page size. Gives `None` on overflow.
pub fn page_up(value: usize) -> Option<usize> {
    Some(value.checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1))
}

/// Tells if `value` is a multiple of the page size.
pub fn is_page_aligned(value: usize) -> bool {
    value.is_multiple_of(PAGE_SIZE)
}

/// The access that a mapping allows, as `PROT_READ`, `PROT_WRITE` and `PROT_EXEC` give.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Prot {
    /// `PROT_READ`.
    pub read: bool,
    /// `PROT_WRITE`.
    pub write: bool,
    /// `PROT_EXEC`.
    pub exec: bool,
}

impl Prot {
    /// Read and write.
    pub const RW: Self = Self { read: true, write: true, exec: false };

    /// Makes the value from the `prot` argument of `mmap`. Gives `None` for an unknown bit.
    pub fn from_bits(bits: u32) -> Option<Self> {
        if bits & !7 != 0 {
            return None;
        }
        Some(Self { read: bits & 1 != 0, write: bits & 2 != 0, exec: bits & 4 != 0 })
    }
}

/// What an area holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Backing<F> {
    /// Anonymous memory. Each page is zero at the first access.
    Anon,
    /// The pages of a file, from the byte `offset` of the file at the start of the area.
    File {
        /// The file.
        file: F,
        /// The offset in the file of the start of the area. It is page aligned.
        offset: u64,
    },
}

/// What the area is for. `/proc/PID/maps` shows the name of the heap and the stack.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VmaKind {
    /// A mapping that `mmap` or the ELF loader made.
    #[default]
    Normal,
    /// The heap of `brk`.
    Heap,
    /// The main stack.
    Stack,
}

/// One virtual memory area.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vma<F> {
    /// The first address. It is page aligned.
    pub start: usize,
    /// The address after the last byte. It is page aligned.
    pub end: usize,
    /// The access that the area allows.
    pub prot: Prot,
    /// `MAP_SHARED`: a write goes to the backing, and each address space that maps it sees it.
    pub shared: bool,
    /// The area can get write access. It is false for a shared mapping of a file that is not open
    /// for writing. Linux names it `VM_MAYWRITE`.
    pub may_write: bool,
    /// `mlock`: the pages of the area stay in memory. Linux names it `VM_LOCKED`. R1 has no swap,
    /// so the flag only changes the counts that procfs shows.
    pub locked: bool,
    /// `MAP_GROWSDOWN`: a fault on the page below the area makes the area larger. Linux names it
    /// `VM_GROWSDOWN`.
    pub grows_down: bool,
    /// What the area holds.
    pub backing: Backing<F>,
    /// What the area is for.
    pub kind: VmaKind,
}

impl<F: Clone> Vma<F> {
    /// Makes an anonymous private area.
    pub fn anon(start: usize, end: usize, prot: Prot, kind: VmaKind) -> Self {
        Self {
            start,
            end,
            prot,
            shared: false,
            may_write: true,
            locked: false,
            grows_down: false,
            backing: Backing::Anon,
            kind,
        }
    }

    /// Cuts the area at `addr`. This area keeps the part below `addr`, and the function gives the
    /// part above it.
    fn split_off(&mut self, addr: usize) -> Self {
        debug_assert!(self.start < addr && addr < self.end && is_page_aligned(addr));
        let mut upper = self.clone();
        upper.start = addr;
        if let Backing::File { offset, .. } = &mut upper.backing {
            *offset += (addr - self.start) as u64;
        }
        self.end = addr;
        upper
    }

    /// The length of the area in bytes.
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Tells if the area is empty. An area in a `VmaSet` is never empty.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// The areas of one address space, in address order. No two areas overlap.
#[derive(Clone, Debug)]
pub struct VmaSet<F> {
    areas: BTreeMap<usize, Vma<F>>,
}

impl<F: Clone> Default for VmaSet<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Clone> VmaSet<F> {
    /// Makes an empty set.
    pub const fn new() -> Self {
        Self { areas: BTreeMap::new() }
    }

    /// Gives the area that contains `addr`.
    pub fn find(&self, addr: usize) -> Option<&Vma<F>> {
        self.areas.range(..=addr).next_back().map(|(_, v)| v).filter(|v| addr < v.end)
    }

    /// Tells if an area has an address in `start..end`.
    pub fn overlaps(&self, start: usize, end: usize) -> bool {
        self.areas.range(..end).next_back().is_some_and(|(_, v)| v.end > start)
    }

    /// Adds an area.
    ///
    /// # Panics
    ///
    /// If the area is empty, is not page aligned or overlaps an area of the set.
    pub fn insert(&mut self, vma: Vma<F>) {
        assert!(vma.start < vma.end, "the area is empty");
        assert!(is_page_aligned(vma.start) && is_page_aligned(vma.end), "the area is not aligned");
        assert!(!self.overlaps(vma.start, vma.end), "the area overlaps another area");
        self.areas.insert(vma.start, vma);
    }

    /// Makes `start` and `end` the edges of areas, if an area contains them.
    fn split_at_edges(&mut self, start: usize, end: usize) {
        for at in [start, end] {
            let Some((&key, _)) = self.areas.range(..at).next_back() else { continue };
            let Some(vma) = self.areas.get_mut(&key) else { continue };
            if vma.start < at && at < vma.end {
                let upper = vma.split_off(at);
                self.areas.insert(at, upper);
            }
        }
    }

    /// Removes the parts of each area in `start..end`, and gives them in address order.
    pub fn remove_range(&mut self, start: usize, end: usize) -> Vec<Vma<F>> {
        self.split_at_edges(start, end);
        let keys: Vec<usize> = self.areas.range(start..end).map(|(&k, _)| k).collect();
        keys.into_iter().filter_map(|k| self.areas.remove(&k)).collect()
    }

    /// Tells if the areas cover each address in `start..end`.
    pub fn covers(&self, start: usize, end: usize) -> bool {
        let mut at = start;
        while at < end {
            match self.find(at) {
                Some(v) => at = v.end,
                None => return false,
            }
        }
        true
    }

    /// Calls `f` for each area in `start..end`, after the areas are split at `start` and `end`.
    pub fn update_range(&mut self, start: usize, end: usize, mut f: impl FnMut(&mut Vma<F>)) {
        self.split_at_edges(start, end);
        for (_, vma) in self.areas.range_mut(start..end) {
            f(vma);
        }
    }

    /// Makes the area above `addr` start at the page of `addr`, if the area grows down. The area
    /// keeps `gap` free bytes to the area below it, and its size stays at or below `max`. Gives
    /// `true` if the area grew. `addr` is not in an area.
    pub fn grow_down(&mut self, addr: usize, gap: usize, max: usize) -> bool {
        let start = addr & !(PAGE_SIZE - 1);
        let Some((&key, vma)) = self.areas.range(addr..).next() else { return false };
        if !vma.grows_down || vma.end - start > max {
            return false;
        }
        if let Some((_, below)) = self.areas.range(..addr).next_back()
            && below.end.saturating_add(gap) > start
        {
            return false;
        }
        let delta = (vma.start - start) as u64;
        if matches!(vma.backing, Backing::File { offset, .. } if offset < delta) {
            return false;
        }
        let Some(mut vma) = self.areas.remove(&key) else { return false };
        if let Backing::File { offset, .. } = &mut vma.backing {
            *offset -= delta;
        }
        vma.start = start;
        self.areas.insert(start, vma);
        true
    }

    /// Finds the highest free range of `len` bytes that ends at or below `top` and starts at or
    /// above `bottom`. This is the top down search of Linux.
    pub fn find_gap(&self, len: usize, bottom: usize, top: usize) -> Option<usize> {
        let mut end = top;
        for (_, vma) in self.areas.range(..top).rev() {
            if vma.end <= end && end - vma.end >= len {
                break;
            }
            end = end.min(vma.start);
        }
        let start = end.checked_sub(len)?;
        (start >= bottom).then_some(start)
    }

    /// The areas in address order.
    pub fn iter(&self) -> impl Iterator<Item = &Vma<F>> {
        self.areas.values()
    }

    /// The number of areas.
    pub fn len(&self) -> usize {
        self.areas.len()
    }

    /// Tells if the set has no area.
    pub fn is_empty(&self) -> bool {
        self.areas.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: usize = PAGE_SIZE;

    fn set(ranges: &[(usize, usize)]) -> VmaSet<u32> {
        let mut s = VmaSet::new();
        for &(a, b) in ranges {
            s.insert(Vma::anon(a * P, b * P, Prot::RW, VmaKind::Normal));
        }
        s
    }

    fn ranges(s: &VmaSet<u32>) -> Vec<(usize, usize)> {
        s.iter().map(|v| (v.start / P, v.end / P)).collect()
    }

    #[test]
    fn find_and_overlap() {
        let s = set(&[(10, 20), (30, 40)]);
        assert_eq!(s.find(10 * P).map(|v| v.start), Some(10 * P));
        assert_eq!(s.find(20 * P - 1).map(|v| v.start), Some(10 * P));
        assert!(s.find(20 * P).is_none());
        assert!(s.find(5 * P).is_none());
        assert!(s.overlaps(15 * P, 35 * P));
        assert!(!s.overlaps(20 * P, 30 * P));
        assert!(s.overlaps(39 * P, 50 * P));
    }

    #[test]
    fn remove_the_middle_splits_an_area() {
        let mut s = set(&[(10, 20)]);
        let removed = s.remove_range(12 * P, 15 * P);
        assert_eq!(removed.len(), 1);
        assert_eq!((removed[0].start, removed[0].end), (12 * P, 15 * P));
        assert_eq!(ranges(&s), [(10, 12), (15, 20)]);
    }

    #[test]
    fn remove_across_areas() {
        let mut s = set(&[(10, 20), (20, 30), (40, 50)]);
        let removed = s.remove_range(15 * P, 45 * P);
        assert_eq!(removed.len(), 3);
        assert_eq!(ranges(&s), [(10, 15), (45, 50)]);
    }

    #[test]
    fn an_area_grows_down_up_to_the_gap() {
        let mut s = set(&[(10, 20), (300, 310)]);
        s.update_range(300 * P, 310 * P, |v| v.grows_down = true);
        assert!(s.grow_down(295 * P + 8, 256 * P, 64 * P));
        assert_eq!(ranges(&s), [(10, 20), (295, 310)]);
        assert!(!s.grow_down(275 * P, 256 * P, 64 * P), "the gap to the area below");
        assert!(!s.grow_down(15 * P + 20 * P, 0, 64 * P), "the size limit");
        assert!(!s.grow_down(5 * P, 0, 64 * P), "the area does not grow down");
    }

    #[test]
    fn split_moves_the_file_offset() {
        let mut s = VmaSet::new();
        s.insert(Vma {
            start: 10 * P,
            end: 20 * P,
            prot: Prot::RW,
            shared: true,
            may_write: true,
            locked: false,
            grows_down: false,
            backing: Backing::File { file: 7u32, offset: 0x1000 },
            kind: VmaKind::Normal,
        });
        s.update_range(13 * P, 20 * P, |v| v.prot.write = false);
        let upper = s.find(13 * P).cloned();
        assert_eq!(
            upper.as_ref().map(|v| v.backing.clone()),
            Some(Backing::File { file: 7, offset: 0x1000 + 3 * P as u64 })
        );
        assert_eq!(upper.map(|v| v.prot.write), Some(false));
        assert_eq!(s.find(12 * P).map(|v| v.prot.write), Some(true));
    }

    #[test]
    fn covers_needs_each_page() {
        let s = set(&[(10, 20), (20, 30), (31, 40)]);
        assert!(s.covers(10 * P, 30 * P));
        assert!(!s.covers(10 * P, 32 * P));
        assert!(!s.covers(9 * P, 11 * P));
    }

    #[test]
    fn the_gap_search_is_top_down() {
        let s = set(&[(90, 100), (70, 85)]);
        assert_eq!(s.find_gap(5 * P, 0, 100 * P), Some(85 * P));
        assert_eq!(s.find_gap(6 * P, 0, 100 * P), Some(64 * P));
        assert_eq!(s.find_gap(10 * P, 0, 110 * P), Some(100 * P));
        assert_eq!(s.find_gap(80 * P, 0, 100 * P), None);
        assert_eq!(s.find_gap(10 * P, 65 * P, 100 * P), None);
    }

    #[test]
    fn prot_bits() {
        assert_eq!(Prot::from_bits(3), Some(Prot::RW));
        assert_eq!(Prot::from_bits(0), Some(Prot::default()));
        assert_eq!(Prot::from_bits(8), None);
    }
}

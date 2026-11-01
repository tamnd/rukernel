//! The status of each page of a last level page table.
//!
//! CortenMM (SOSP 2025) keeps the status of each page in a metadata array next to each page table
//! page, so one lock and one walk of the page table cover a change. The status tells how the page
//! is mapped, also when it has no frame: for example the area of the page, its protection, or its
//! file and offset. `VmSpace` keeps a [`StatusTable`] next to each last level table, under the
//! lock of the table (see `Block` in vm.rs).
//!
//! rk-frame does not know the type of a status. A status is a [`PageStatus`], and the memory
//! manager gets its type back with `Arc::downcast`.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::any::Any;

/// The status of a page. The memory manager gives the type.
pub type PageStatus = Arc<dyn Any + Send + Sync>;

/// The number of pages of one last level table.
pub(crate) const SLOTS: usize = 512;

/// The statuses in one chunk of a [`StatusTable`]. A chunk is 2 KiB, a small allocation of the
/// kernel heap. An allocation of more than 2 KiB maps pages of the heap, and its free sends a TLB
/// shootdown to each CPU.
const CHUNK: usize = 128;

const _: () = assert!(CHUNK * size_of::<Option<PageStatus>>() <= 2048);

/// One chunk of statuses.
type Chunk = Box<[Option<PageStatus>]>;

/// The status of each page of one last level table. A chunk with no status has no memory.
#[derive(Default)]
pub(crate) struct StatusTable {
    chunks: [Option<Chunk>; SLOTS / CHUNK],
}

/// Tells if two statuses are the same value.
fn same_value(a: &PageStatus, b: &PageStatus) -> bool {
    Arc::ptr_eq(a, b)
}

impl StatusTable {
    /// The status of the page at the index `i`.
    pub(crate) fn get(&self, i: usize) -> Option<&PageStatus> {
        self.chunks[i / CHUNK].as_ref()?[i % CHUNK].as_ref()
    }

    /// Calls `f` with the index and the status of each page from the index `first` to `last`
    /// that has a status, in order. A chunk with no status costs one check.
    pub(crate) fn each(&self, first: usize, last: usize, mut f: impl FnMut(usize, &PageStatus)) {
        let mut i = first;
        while i <= last.min(SLOTS - 1) {
            let c = i / CHUNK;
            let to = last.min((c + 1) * CHUNK - 1);
            if let Some(chunk) = &self.chunks[c] {
                for j in i..=to {
                    if let Some(s) = &chunk[j % CHUNK] {
                        f(j, s);
                    }
                }
            }
            i = to + 1;
        }
    }

    /// Tells if no page has a status.
    pub(crate) fn is_empty(&self) -> bool {
        self.chunks.iter().all(Option::is_none)
    }

    /// Sets the status of each page from the index `first` up to `end`, or removes it with
    /// `None`. A chunk with no status after the change frees its memory.
    pub(crate) fn set(&mut self, first: usize, end: usize, status: Option<&PageStatus>) {
        let end = end.min(SLOTS);
        let mut i = first;
        while i < end {
            let c = i / CHUNK;
            let to = end.min((c + 1) * CHUNK);
            match status {
                Some(s) => {
                    let chunk =
                        self.chunks[c].get_or_insert_with(|| (0..CHUNK).map(|_| None).collect());
                    for slot in &mut chunk[i % CHUNK..to - c * CHUNK] {
                        *slot = Some(s.clone());
                    }
                }
                None => {
                    if let Some(chunk) = &mut self.chunks[c] {
                        for slot in &mut chunk[i % CHUNK..to - c * CHUNK] {
                            *slot = None;
                        }
                        if chunk.iter().all(Option::is_none) {
                            self.chunks[c] = None;
                        }
                    }
                }
            }
            i = to;
        }
    }

    /// Calls `f` with each run of pages from the index `first` up to `end` that have the same
    /// status value, in order. A run is a range of indexes.
    pub(crate) fn runs(
        &self,
        first: usize,
        end: usize,
        mut f: impl FnMut(usize, usize, &PageStatus),
    ) {
        let mut run: Option<(usize, usize, &PageStatus)> = None;
        for i in first..end.min(SLOTS) {
            let Some(s) = self.get(i) else {
                if let Some((a, b, s)) = run.take() {
                    f(a, b, s);
                }
                continue;
            };
            match &mut run {
                Some((_, b, t)) if same_value(t, s) => *b = i + 1,
                _ => {
                    if let Some((a, b, t)) = run.replace((i, i + 1, s)) {
                        f(a, b, t);
                    }
                }
            }
        }
        if let Some((a, b, s)) = run {
            f(a, b, s);
        }
    }

    /// Gives the run of the page at the index `i`: the largest range of indexes around `i` with
    /// statuses that `same` joins, and the status of the first page of the run. Two pages with the
    /// same status value are in one run, and `same` is not called for them.
    pub(crate) fn run_at(
        &self,
        i: usize,
        same: impl Fn(&PageStatus, &PageStatus) -> bool,
    ) -> Option<(usize, usize, PageStatus)> {
        let s = self.get(i)?;
        let joins = |j: usize| self.get(j).is_some_and(|t| same_value(s, t) || same(s, t));
        let mut first = i;
        while first > 0 && joins(first - 1) {
            first -= 1;
        }
        let mut end = i + 1;
        while end < SLOTS && joins(end) {
            end += 1;
        }
        Some((first, end, self.get(first)?.clone()))
    }

    /// Makes a table with the status that `map` gives for each status, or no status for `None`,
    /// as `fork` copies the page table. `map` gets each run of one status value one time.
    pub(crate) fn map(&self, mut map: impl FnMut(&PageStatus) -> Option<PageStatus>) -> Self {
        let mut copy = Self::default();
        self.runs(0, SLOTS, |a, b, s| {
            if let Some(c) = map(s) {
                copy.set(a, b, Some(&c));
            }
        });
        copy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn status(n: u32) -> PageStatus {
        Arc::new(n)
    }

    fn value(s: &PageStatus) -> u32 {
        s.downcast_ref::<u32>().copied().unwrap_or(u32::MAX)
    }

    fn runs(t: &StatusTable) -> Vec<(usize, usize, u32)> {
        let mut out = Vec::new();
        t.runs(0, SLOTS, |a, b, s| out.push((a, b, value(s))));
        out
    }

    #[test]
    fn set_get_and_clear() {
        let mut t = StatusTable::default();
        assert!(t.is_empty());
        let (a, b) = (status(1), status(2));
        t.set(10, 300, Some(&a));
        t.set(100, 140, Some(&b));
        assert_eq!(t.get(9).map(value), None);
        assert_eq!(t.get(10).map(value), Some(1));
        assert_eq!(t.get(120).map(value), Some(2));
        assert_eq!(t.get(299).map(value), Some(1));
        assert_eq!(t.get(300).map(value), None);
        assert_eq!(runs(&t), [(10, 100, 1), (100, 140, 2), (140, 300, 1)]);
        // Each page holds a reference to the value.
        assert_eq!(Arc::strong_count(&a), 1 + 290 - 40);
        t.set(0, SLOTS, None);
        assert!(t.is_empty());
        assert_eq!(Arc::strong_count(&a), 1);
    }

    #[test]
    fn each_gives_the_pages_with_a_status_in_order() {
        let mut t = StatusTable::default();
        let (a, b) = (status(1), status(2));
        t.set(126, 130, Some(&a));
        t.set(400, 401, Some(&b));
        let mut seen = Vec::new();
        t.each(127, SLOTS + 5, |i, s| seen.push((i, value(s))));
        assert_eq!(seen, [(127, 1), (128, 1), (129, 1), (400, 2)]);
        seen.clear();
        t.each(130, 399, |i, s| seen.push((i, value(s))));
        assert!(seen.is_empty());
    }

    #[test]
    fn a_chunk_with_no_status_frees_its_memory() {
        let mut t = StatusTable::default();
        let a = status(1);
        t.set(0, SLOTS, Some(&a));
        assert!(t.chunks.iter().all(Option::is_some));
        t.set(CHUNK, 3 * CHUNK, None);
        assert!(t.chunks[0].is_some() && t.chunks[3].is_some());
        assert!(t.chunks[1].is_none() && t.chunks[2].is_none());
        // A part of a chunk keeps the chunk.
        t.set(1, CHUNK, None);
        assert!(t.chunks[0].is_some());
        assert_eq!(runs(&t), [(0, 1, 1), (3 * CHUNK, SLOTS, 1)]);
    }

    #[test]
    fn two_values_are_two_runs() {
        // Two values that are equal but not the same value are two runs. `run_at` joins them
        // with `same`.
        let mut t = StatusTable::default();
        t.set(0, 200, Some(&status(5)));
        t.set(200, 400, Some(&status(5)));
        assert_eq!(runs(&t), [(0, 200, 5), (200, 400, 5)]);
        let never = |_: &PageStatus, _: &PageStatus| false;
        let equal = |a: &PageStatus, b: &PageStatus| value(a) == value(b);
        assert_eq!(t.run_at(250, never).map(|r| (r.0, r.1)), Some((200, 400)));
        assert_eq!(t.run_at(250, equal).map(|r| (r.0, r.1)), Some((0, 400)));
        assert!(t.run_at(400, equal).is_none());
    }

    #[test]
    fn map_copies_each_value_one_time() {
        let mut t = StatusTable::default();
        let (a, b) = (status(1), status(2));
        t.set(0, 256, Some(&a));
        t.set(256, 300, Some(&b));
        t.set(300, 310, Some(&a));
        let mut calls = 0;
        let copy = t.map(|s| {
            calls += 1;
            (value(s) == 1).then(|| status(11))
        });
        assert_eq!(calls, 3);
        assert_eq!(runs(&copy), [(0, 256, 11), (300, 310, 11)]);
        assert_eq!(runs(&t), [(0, 256, 1), (256, 300, 2), (300, 310, 1)]);
    }
}

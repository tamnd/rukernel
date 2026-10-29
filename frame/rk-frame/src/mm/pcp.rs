//! The lists of free items of one CPU, as the per-CPU pagesets (`struct per_cpu_pages`) of
//! mm/page_alloc.c of Linux.
//!
//! The frame allocator and the heap keep a short list of free frames or free objects for each CPU.
//! An allocation takes an item from the list of its CPU, and a free puts the item on that list, so
//! the CPUs do not share the global lock for each item. An empty list takes a batch of items from
//! the global allocator under one lock, as `rmqueue_bulk` of Linux. A full list gives a batch back,
//! as `free_pcppages_bulk` of Linux.

/// A list of up to `HIGH` free items, which are frame numbers or object addresses.
pub(crate) struct CpuList<const HIGH: usize> {
    items: [usize; HIGH],
    len: usize,
}

impl<const HIGH: usize> CpuList<HIGH> {
    /// Makes an empty list.
    pub(crate) const fn new() -> Self {
        Self { items: [0; HIGH], len: 0 }
    }

    /// The number of items on the list.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Takes the item that went on the list last, as it is the most likely to be in the cache. If
    /// the list is empty, it takes up to `batch` items from `take` first. `take` gives `None` when
    /// the global allocator has no more items. Gives `None` if the list and `take` have no item.
    pub(crate) fn pop_or_refill(
        &mut self,
        batch: usize,
        mut take: impl FnMut() -> Option<usize>,
    ) -> Option<usize> {
        if self.len == 0 {
            for _ in 0..batch.min(HIGH) {
                let Some(item) = take() else { break };
                self.items[self.len] = item;
                self.len += 1;
            }
        }
        self.len = self.len.checked_sub(1)?;
        Some(self.items[self.len])
    }

    /// Puts `item` on the list. If the list is full, it gives the `batch` items that went on it
    /// first to `give` before.
    pub(crate) fn push_or_drain(&mut self, item: usize, batch: usize, give: impl FnMut(usize)) {
        if self.len == HIGH {
            let n = batch.clamp(1, HIGH);
            self.items[..n].iter().copied().for_each(give);
            self.items.copy_within(n.., 0);
            self.len -= n;
        }
        self.items[self.len] = item;
        self.len += 1;
    }

    /// Gives all the items to `give` and makes the list empty, as `drain_pages` of Linux.
    pub(crate) fn drain(&mut self, give: impl FnMut(usize)) {
        self.items[..self.len].iter().copied().for_each(give);
        self.len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn an_empty_list_takes_a_batch() {
        let mut list = CpuList::<8>::new();
        let mut global: Vec<usize> = (0..10).collect();
        assert_eq!(list.pop_or_refill(4, || global.pop()), Some(6));
        // The batch was 9, 8, 7 and 6, and the last one is the first to go.
        assert_eq!(list.len(), 3);
        assert_eq!(global.len(), 6);
        assert_eq!(list.pop_or_refill(4, || global.pop()), Some(7));
        assert_eq!(list.pop_or_refill(4, || unreachable!()), Some(8));
        assert_eq!(list.pop_or_refill(4, || unreachable!()), Some(9));
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn an_empty_list_with_no_global_item_gives_none() {
        let mut list = CpuList::<8>::new();
        assert_eq!(list.pop_or_refill(4, || None), None);
        // A short global list fills the list in part.
        let mut global = alloc::vec![1];
        assert_eq!(list.pop_or_refill(4, || global.pop()), Some(1));
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn a_full_list_gives_back_its_oldest_batch() {
        let mut list = CpuList::<4>::new();
        let mut back = Vec::new();
        for item in 0..4 {
            list.push_or_drain(item, 2, |i| back.push(i));
        }
        assert!(back.is_empty());
        list.push_or_drain(4, 2, |i| back.push(i));
        assert_eq!(back, [0, 1]);
        assert_eq!(list.len(), 3);
        // The items that stay keep their order.
        assert_eq!(list.pop_or_refill(2, || None), Some(4));
        assert_eq!(list.pop_or_refill(2, || None), Some(3));
        assert_eq!(list.pop_or_refill(2, || None), Some(2));
        assert_eq!(list.pop_or_refill(2, || None), None);
    }

    #[test]
    fn drain_gives_all_items() {
        let mut list = CpuList::<4>::new();
        for item in [5, 6, 7] {
            list.push_or_drain(item, 2, |_| unreachable!());
        }
        let mut back = Vec::new();
        list.drain(|i| back.push(i));
        assert_eq!(back, [5, 6, 7]);
        assert_eq!(list.len(), 0);
        list.drain(|_| unreachable!());
    }

    #[test]
    fn no_item_is_lost_or_given_two_times() {
        let mut list = CpuList::<16>::new();
        let mut global: Vec<usize> = (0..100).collect();
        let mut taken = Vec::new();
        for round in 0..50 {
            for _ in 0..(round % 7) {
                taken.extend(list.pop_or_refill(5, || global.pop()));
            }
            for _ in 0..(round % 5) {
                if let Some(item) = taken.pop() {
                    list.push_or_drain(item, 5, |i| global.push(i));
                }
            }
        }
        list.drain(|i| global.push(i));
        global.extend(taken);
        global.sort_unstable();
        assert_eq!(global, (0..100).collect::<Vec<_>>());
    }
}

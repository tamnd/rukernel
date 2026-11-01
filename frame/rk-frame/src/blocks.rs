//! The tree that finds the value of each 2 MiB block of a user address space.
//!
//! `VmSpace` keeps the pages of each 2 MiB block under the lock of the block, as the split page
//! table locks of Linux keep a lock for each last level page table (`pte_lockptr` in
//! include/linux/mm.h). The last level table of x86-64 and arm64 maps 2 MiB. This tree finds that
//! lock from an address. It has the shape of the upper levels of the page table: a slot of the top
//! level covers 512 GiB, a slot of the middle level 1 GiB, and a slot of the lowest level is one
//! 2 MiB block.
//!
//! A lookup takes no lock. A slot is empty or points to its child, and it changes only one time,
//! from empty to the child, with a compare and swap. If two CPUs make the same child at the same
//! time, one of them drops its copy. A child stays until the tree is dropped, as the page tables
//! of a user address space stay until the address space goes.
//!
//! Each node above the blocks has a value of type `M` too, the metadata of the page table page of
//! the same range: the top node for the top level table, a middle node for a table of 512 GiB, and
//! a node of the lowest level for a table of 1 GiB.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ops::RangeInclusive;
use core::sync::atomic::{AtomicPtr, Ordering};

/// The number of slots of a middle or a lowest level node.
const FANOUT: usize = 512;
/// The size of a block.
pub(crate) const BLOCK_SIZE: usize = 1 << BLOCK_SHIFT;
const BLOCK_SHIFT: u32 = 21;
const MID_SHIFT: u32 = 30;
const TOP_SHIFT: u32 = 39;

/// A slot that is empty or owns a boxed value.
struct Slot<T> {
    ptr: AtomicPtr<T>,
    /// The slot owns a `T`, so it is `Send` and `Sync` only as the impls below allow.
    _owns: PhantomData<*const T>,
}

// SAFETY: the slot owns its value, as a `Box<T>` does, so it can go to another CPU if `T` can.
unsafe impl<T: Send> Send for Slot<T> {}
// SAFETY: a shared slot gives `&T` on each CPU, and a CPU can make the value that the owner drops
// later. Thus `T` must be `Sync` and `Send`.
unsafe impl<T: Send + Sync> Sync for Slot<T> {}

impl<T> Slot<T> {
    const fn new() -> Self {
        Self { ptr: AtomicPtr::new(core::ptr::null_mut()), _owns: PhantomData }
    }

    fn get(&self) -> Option<&T> {
        let p = self.ptr.load(Ordering::Acquire);
        // SAFETY: a pointer that is not null comes from `Box::into_raw` in `get_or_make`, with
        // release order. The box lives until the slot is dropped, and that needs `&mut self`.
        unsafe { p.as_ref() }
    }

    fn get_or_make(&self, make: impl FnOnce() -> T) -> &T {
        if let Some(value) = self.get() {
            return value;
        }
        let new = Box::into_raw(Box::new(make()));
        let null = core::ptr::null_mut();
        match self.ptr.compare_exchange(null, new, Ordering::AcqRel, Ordering::Acquire) {
            // SAFETY: the slot owns `new` now, as for `get`.
            Ok(_) => unsafe { &*new },
            Err(old) => {
                // SAFETY: the compare and swap failed, so `new` is still only ours.
                drop(unsafe { Box::from_raw(new) });
                // SAFETY: `old` is the value of another CPU, which the slot owns, as for `get`.
                unsafe { &*old }
            }
        }
    }
}

impl<T> Drop for Slot<T> {
    fn drop(&mut self) {
        let p = *self.ptr.get_mut();
        if !p.is_null() {
            // SAFETY: the pointer comes from `Box::into_raw`, and the slot owns it.
            drop(unsafe { Box::from_raw(p) });
        }
    }
}

/// `n` empty slots. They come from the heap directly, not from the stack.
fn slots<T>(n: usize) -> Box<[Slot<T>]> {
    (0..n).map(|_| Slot::new()).collect::<Vec<_>>().into_boxed_slice()
}

/// The slots of a node of `n` slots of `1 << shift` bytes at `base` that `start..end` touches. The
/// range touches the node.
fn touched(base: usize, shift: u32, n: usize, start: usize, end: usize) -> RangeInclusive<usize> {
    let first = start.saturating_sub(base) >> shift;
    let last = ((end - 1).saturating_sub(base) >> shift).min(n - 1);
    first..=last
}

/// A node: the value of its page table page and its slots.
struct Node<C, M> {
    meta: M,
    slots: Box<[Slot<C>]>,
}

impl<C, M: Default> Node<C, M> {
    fn new(n: usize) -> Self {
        Self { meta: M::default(), slots: slots(n) }
    }
}

type Leaf<T, M> = Node<T, M>;
type Mid<T, M> = Node<Leaf<T, M>, M>;

/// A value of type `T` for each 2 MiB block of the addresses below an end, and a value of type
/// `M` for each node above the blocks.
pub(crate) struct BlockTree<T, M = ()> {
    top: Node<Mid<T, M>, M>,
    end: usize,
}

/// The level of the nodes of the lowest level, as the levels of the page table: a block is at
/// level 1.
pub(crate) const LEAF_LEVEL: u32 = 2;
/// The level of the top node.
pub(crate) const TOP_LEVEL: u32 = 4;

impl<T, M: Default> BlockTree<T, M> {
    /// Makes a tree for the addresses below `end`, with no value.
    pub(crate) fn new(end: usize) -> Self {
        Self { top: Node::new(end.div_ceil(1 << TOP_SHIFT)), end }
    }

    fn index(addr: usize, shift: u32) -> usize {
        (addr >> shift) % FANOUT
    }

    /// Gives the value of the block of `addr`, if it has one.
    pub(crate) fn get(&self, addr: usize) -> Option<&T> {
        let mid = self.top.slots.get(addr >> TOP_SHIFT)?.get()?;
        let leaf = mid.slots[Self::index(addr, MID_SHIFT)].get()?;
        leaf.slots[Self::index(addr, BLOCK_SHIFT)].get()
    }

    /// Gives the value of the block of `addr`, and makes it with `make` if it has none.
    ///
    /// # Panics
    ///
    /// If `addr` is not below the end of the tree.
    pub(crate) fn get_or_make(&self, addr: usize, make: impl FnOnce() -> T) -> &T {
        let leaf = self.leaf_or_make(addr);
        leaf.slots[Self::index(addr, BLOCK_SHIFT)].get_or_make(make)
    }

    /// The node of the lowest level of `addr`, which is made if it is not there.
    fn leaf_or_make(&self, addr: usize) -> &Leaf<T, M> {
        assert!(addr < self.end, "{addr:#x} is outside the tree");
        let mid = self.top.slots[addr >> TOP_SHIFT].get_or_make(|| Node::new(FANOUT));
        mid.slots[Self::index(addr, MID_SHIFT)].get_or_make(|| Node::new(FANOUT))
    }

    /// Gives the value of the node of `level` that has `addr`, if the node is there. The level
    /// is from [`LEAF_LEVEL`] to [`TOP_LEVEL`].
    pub(crate) fn meta(&self, level: u32, addr: usize) -> Option<&M> {
        if level == TOP_LEVEL {
            return Some(&self.top.meta);
        }
        let mid = self.top.slots.get(addr >> TOP_SHIFT)?.get()?;
        if level == TOP_LEVEL - 1 {
            return Some(&mid.meta);
        }
        mid.slots[Self::index(addr, MID_SHIFT)].get().map(|leaf| &leaf.meta)
    }

    /// Gives the value of the node of `level` that has `addr` as `meta`, and makes the node if
    /// it is not there.
    ///
    /// # Panics
    ///
    /// If `addr` is not below the end of the tree.
    pub(crate) fn meta_or_make(&self, level: u32, addr: usize) -> &M {
        match level {
            TOP_LEVEL => &self.top.meta,
            LEAF_LEVEL => &self.leaf_or_make(addr).meta,
            _ => {
                assert!(addr < self.end, "{addr:#x} is outside the tree");
                &self.top.slots[addr >> TOP_SHIFT].get_or_make(|| Node::new(FANOUT)).meta
            }
        }
    }

    /// Calls `node` with the index and the value of each node in the slots `slots` of the node of
    /// `level` that has `addr`, in order. For a node of [`LEAF_LEVEL`], `block` gets the index and
    /// the value of each block in the slots. A slot with no node or no block gets no call.
    pub(crate) fn children(
        &self,
        level: u32,
        addr: usize,
        slots: RangeInclusive<usize>,
        mut node: impl FnMut(usize, &M),
        mut block: impl FnMut(usize, &T),
    ) {
        if level == TOP_LEVEL {
            for i in slots {
                if let Some(mid) = self.top.slots.get(i).and_then(Slot::get) {
                    node(i, &mid.meta);
                }
            }
            return;
        }
        let Some(mid) = self.top.slots.get(addr >> TOP_SHIFT).and_then(Slot::get) else {
            return;
        };
        if level == TOP_LEVEL - 1 {
            for i in slots {
                if let Some(leaf) = mid.slots[i].get() {
                    node(i, &leaf.meta);
                }
            }
            return;
        }
        let Some(leaf) = mid.slots[Self::index(addr, MID_SHIFT)].get() else { return };
        for i in slots {
            if let Some(value) = leaf.slots[i].get() {
                block(i, value);
            }
        }
    }

    /// Calls `f` with the level, the first address and the value of each node above the blocks,
    /// with each node after the nodes below it, in address order.
    pub(crate) fn each_node(&self, mut f: impl FnMut(u32, usize, &M)) {
        for (t, mid) in self.top.slots.iter().enumerate() {
            let Some(mid) = mid.get() else { continue };
            let mid_base = t << TOP_SHIFT;
            for (m, leaf) in mid.slots.iter().enumerate() {
                if let Some(leaf) = leaf.get() {
                    f(LEAF_LEVEL, mid_base + (m << MID_SHIFT), &leaf.meta);
                }
            }
            f(TOP_LEVEL - 1, mid_base, &mid.meta);
        }
        f(TOP_LEVEL, 0, &self.top.meta);
    }

    /// Calls `f` with the address and the value of each block that has a value and that
    /// `start..end` touches, in address order. It stops at the first error of `f`.
    ///
    /// # Errors
    ///
    /// The first error of `f`.
    pub(crate) fn each<E>(
        &self,
        start: usize,
        end: usize,
        mut f: impl FnMut(usize, &T) -> Result<(), E>,
    ) -> Result<(), E> {
        let end = end.min(self.end);
        if start >= end {
            return Ok(());
        }
        for t in touched(0, TOP_SHIFT, self.top.slots.len(), start, end) {
            let Some(mid) = self.top.slots[t].get() else { continue };
            let mid_base = t << TOP_SHIFT;
            for m in touched(mid_base, MID_SHIFT, FANOUT, start, end) {
                let Some(leaf) = mid.slots[m].get() else { continue };
                let leaf_base = mid_base + (m << MID_SHIFT);
                for b in touched(leaf_base, BLOCK_SHIFT, FANOUT, start, end) {
                    if let Some(value) = leaf.slots[b].get() {
                        f(leaf_base + (b << BLOCK_SHIFT), value)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Calls `f` for each block that has a value, in address order.
    pub(crate) fn each_all(&self, mut f: impl FnMut(usize, &T)) {
        let _ = self.each(0, self.end, |a, v| {
            f(a, v);
            Ok::<(), ()>(())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicUsize;

    const END: usize = 0x0000_7fff_ffff_f000;

    fn blocks(tree: &BlockTree<usize>, start: usize, end: usize) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let _ = tree.each(start, end, |a, &v| {
            out.push((a, v));
            Ok::<(), ()>(())
        });
        out
    }

    #[test]
    fn a_new_tree_has_no_block() {
        let tree = BlockTree::<usize>::new(END);
        assert!(tree.get(0).is_none());
        assert!(tree.get(END - 1).is_none());
        assert!(tree.get(END).is_none());
        assert!(blocks(&tree, 0, END).is_empty());
    }

    #[test]
    fn a_block_covers_2_mib() {
        let tree = BlockTree::<_>::new(END);
        assert_eq!(*tree.get_or_make(0x40_0000 + 5, || 7), 7);
        assert_eq!(tree.get(0x40_0000), Some(&7));
        assert_eq!(tree.get(0x5f_ffff), Some(&7));
        assert!(tree.get(0x60_0000).is_none());
        assert!(tree.get(0x3f_ffff).is_none());
        // A second make gives the first value.
        assert_eq!(*tree.get_or_make(0x41_0000, || 8), 7);
    }

    #[test]
    fn each_gives_the_blocks_of_a_range_in_order() {
        let tree = BlockTree::<_>::new(END);
        let addrs = [END - 1, 0, 1 << 39, (1 << 30) + BLOCK_SIZE, 1 << 30, 5 * BLOCK_SIZE];
        for (i, &a) in addrs.iter().enumerate() {
            tree.get_or_make(a, || i);
        }
        let all = blocks(&tree, 0, END);
        let want = [
            (0, 1),
            (5 * BLOCK_SIZE, 5),
            (1 << 30, 4),
            ((1 << 30) + BLOCK_SIZE, 3),
            (1 << 39, 2),
            ((END - 1) & !(BLOCK_SIZE - 1), 0),
        ];
        assert_eq!(all, want);
        // A range that starts and ends in the middle of blocks touches them.
        let some = blocks(&tree, 5 * BLOCK_SIZE + 1, (1 << 30) + 1);
        assert_eq!(some, [(5 * BLOCK_SIZE, 5), (1 << 30, 4)]);
        assert!(blocks(&tree, BLOCK_SIZE, 5 * BLOCK_SIZE).is_empty());
        assert!(blocks(&tree, 7, 7).is_empty());
        // `each` stops at the first error.
        let mut n = 0;
        let r = tree.each(0, END, |_, _| {
            n += 1;
            if n == 2 { Err(n) } else { Ok(()) }
        });
        assert_eq!((r, n), (Err(2), 2));
    }

    #[test]
    fn the_nodes_above_the_blocks_have_values() {
        let tree = BlockTree::<usize, AtomicUsize>::new(END);
        let (g1, g512) = (1 << MID_SHIFT, 1 << TOP_SHIFT);
        assert!(tree.meta(LEAF_LEVEL, g1).is_none());
        assert!(tree.meta(3, g512).is_none());
        if let Some(top) = tree.meta(TOP_LEVEL, 0) {
            top.store(4, Ordering::Relaxed);
        }
        tree.meta_or_make(LEAF_LEVEL, g512 + g1 + 5).store(2, Ordering::Relaxed);
        tree.meta_or_make(3, g512 + 7).fetch_add(3, Ordering::Relaxed);
        let mut seen = Vec::new();
        tree.each_node(|l, a, m| seen.push((l, a, m.load(Ordering::Relaxed))));
        assert_eq!(seen, [(LEAF_LEVEL, g512 + g1, 2), (3, g512, 3), (TOP_LEVEL, 0, 4)]);
        // A block makes the nodes above it.
        tree.get_or_make(5 * BLOCK_SIZE, || 1);
        assert!(tree.meta(LEAF_LEVEL, 0).is_some() && tree.meta(3, 0).is_some());
        assert!(blocks_of(&tree).eq([5 * BLOCK_SIZE]));
        // Each node gives the nodes or the blocks below it.
        let below = |level, addr, slots| {
            let seen = core::cell::RefCell::new(Vec::new());
            let node = |i, m: &AtomicUsize| seen.borrow_mut().push((i, m.load(Ordering::Relaxed)));
            let block = |i, b: &usize| seen.borrow_mut().push((i, *b));
            tree.children(level, addr, slots, node, block);
            seen.into_inner()
        };
        assert_eq!(below(TOP_LEVEL, 0, 0..=255), [(0, 0), (1, 3)]);
        assert_eq!(below(3, g512, 0..=511), [(1, 2)]);
        assert_eq!(below(3, g512, 2..=511), []);
        assert_eq!(below(LEAF_LEVEL, 0, 0..=511), [(5, 1)]);
        assert_eq!(below(LEAF_LEVEL, g1, 0..=511), []);
    }

    fn blocks_of(tree: &BlockTree<usize, AtomicUsize>) -> impl Iterator<Item = usize> {
        let mut out = Vec::new();
        tree.each_all(|a, _| out.push(a));
        out.into_iter()
    }

    #[test]
    #[should_panic(expected = "outside the tree")]
    fn a_make_past_the_end_panics() {
        BlockTree::<_>::new(END).get_or_make(END, || 0);
    }

    /// Counts the values that are dropped.
    struct Counted<'a>(&'a AtomicUsize);

    impl Drop for Counted<'_> {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn the_tree_drops_its_values() {
        let dropped = AtomicUsize::new(0);
        let tree = BlockTree::<_>::new(END);
        for i in 0..10 {
            tree.get_or_make(i << 30, || Counted(&dropped));
        }
        // A second make for a block makes no value.
        tree.get_or_make(0, || Counted(&dropped));
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        drop(tree);
        assert_eq!(dropped.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn threads_make_one_value_for_each_block() {
        extern crate std;
        let tree = std::sync::Arc::new(BlockTree::<AtomicUsize>::new(END));
        let made = std::sync::Arc::new(AtomicUsize::new(0));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let (tree, made) = (tree.clone(), made.clone());
                std::thread::spawn(move || {
                    for b in 0..256 {
                        let v: &AtomicUsize = tree.get_or_make(b * BLOCK_SIZE, || {
                            made.fetch_add(1, Ordering::Relaxed);
                            AtomicUsize::new(0)
                        });
                        v.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap_or_else(|_| panic!("a thread failed"));
        }
        let mut n = 0;
        tree.each_all(|_, v| {
            assert_eq!(v.load(Ordering::Relaxed), 4);
            n += 1;
        });
        assert_eq!(n, 256);
        assert!(made.load(Ordering::Relaxed) >= 256);
    }
}

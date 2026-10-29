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

type Leaf<T> = Box<[Slot<T>]>;
type Mid<T> = Box<[Slot<Leaf<T>>]>;

/// A value of type `T` for each 2 MiB block of the addresses below an end.
pub(crate) struct BlockTree<T> {
    top: Box<[Slot<Mid<T>>]>,
    end: usize,
}

impl<T> BlockTree<T> {
    /// Makes a tree for the addresses below `end`, with no value.
    pub(crate) fn new(end: usize) -> Self {
        Self { top: slots(end.div_ceil(1 << TOP_SHIFT)), end }
    }

    fn index(addr: usize, shift: u32) -> usize {
        (addr >> shift) % FANOUT
    }

    /// Gives the value of the block of `addr`, if it has one.
    pub(crate) fn get(&self, addr: usize) -> Option<&T> {
        let mid = self.top.get(addr >> TOP_SHIFT)?.get()?;
        let leaf = mid[Self::index(addr, MID_SHIFT)].get()?;
        leaf[Self::index(addr, BLOCK_SHIFT)].get()
    }

    /// Gives the value of the block of `addr`, and makes it with `make` if it has none.
    ///
    /// # Panics
    ///
    /// If `addr` is not below the end of the tree.
    pub(crate) fn get_or_make(&self, addr: usize, make: impl FnOnce() -> T) -> &T {
        assert!(addr < self.end, "{addr:#x} is outside the tree");
        let mid = self.top[addr >> TOP_SHIFT].get_or_make(|| slots(FANOUT));
        let leaf = mid[Self::index(addr, MID_SHIFT)].get_or_make(|| slots(FANOUT));
        leaf[Self::index(addr, BLOCK_SHIFT)].get_or_make(make)
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
        for t in touched(0, TOP_SHIFT, self.top.len(), start, end) {
            let Some(mid) = self.top[t].get() else { continue };
            let mid_base = t << TOP_SHIFT;
            for m in touched(mid_base, MID_SHIFT, FANOUT, start, end) {
                let Some(leaf) = mid[m].get() else { continue };
                let leaf_base = mid_base + (m << MID_SHIFT);
                for b in touched(leaf_base, BLOCK_SHIFT, FANOUT, start, end) {
                    if let Some(value) = leaf[b].get() {
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
        let tree = BlockTree::new(END);
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
        let tree = BlockTree::new(END);
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
    #[should_panic(expected = "outside the tree")]
    fn a_make_past_the_end_panics() {
        BlockTree::new(END).get_or_make(END, || 0);
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
        let tree = BlockTree::new(END);
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
        let tree = std::sync::Arc::new(BlockTree::new(END));
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

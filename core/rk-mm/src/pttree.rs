//! The page table tree of the CortenMM backend.
//!
//! The tree has the shape of the page table of x86-64 and arm64 with 4 levels: each node has 512
//! slots, a slot of the lowest level is one page of 4 KiB, and the root covers 256 TiB. A slot is
//! empty, holds the status of each page in it, or points to a node of the next level. The status
//! of a page tells if the page is mapped and how. Thus the tree is the source of truth for the
//! address space, and there is no tree of areas. CortenMM (SOSP 2025) keeps the status in the page
//! table pages. This tree keeps it in nodes of the same shape, because the page table of rk-frame
//! has one lock. spec/24-open-questions.md question 1 is the experiment.
//!
//! Each node has its own lock. A [`RangeLock`] locks the lowest node that covers a range, and
//! each node below it in the range. Thus two operations on ranges in different nodes do not wait
//! for each other: a page fault locks one node of the lowest level, which covers 2 MiB.
//!
//! A lock goes down from the root with no lock, as the RCU walk of CortenMM, to the lowest node
//! that covers the range, and then locks that node and each node below it in the range. Thus an
//! operation does not wait at a node above its range, and a page fault does not wait for a call
//! on another 2 MiB block. A walk locks a node on the way only to make a missing child. A node
//! that a holder removes from the tree is dead, and a walk that locks a dead node starts again.
//!
//! The protocol has no deadlock. An operation waits for a node only when it holds no node, or
//! when it holds an ancestor of the node, so each chain of waits goes down the tree. A node that a
//! holder makes is locked before other operations can see it.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use rk_frame::sync::SpinLock;

/// The number of slots in a node.
pub const FANOUT: usize = 512;
/// The number of levels. A node of level 1 has a slot for each page.
pub const LEVELS: u32 = 4;
const PAGE_SHIFT: u32 = 12;
const BITS: u32 = 9;
/// The end of the addresses that the tree covers, 256 TiB.
pub const TREE_END: usize = 1 << (PAGE_SHIFT + BITS * LEVELS);

/// The bytes of one slot of a node of `level`.
const fn slot_size(level: u32) -> usize {
    1 << (PAGE_SHIFT + BITS * (level - 1))
}

/// What a slot holds.
enum Slot<S> {
    /// No page of the slot is mapped.
    Empty,
    /// Each page of the slot has this status.
    Status(S),
    /// The node of the next level.
    Child(Arc<Node<S>>),
}

impl<S: Clone> Slot<S> {
    /// A copy of an empty slot or a slot with a status, for each slot of a new child.
    fn leaf_copy(&self) -> Self {
        match self {
            Slot::Status(s) => Slot::Status(s.clone()),
            _ => Slot::Empty,
        }
    }
}

/// One node of the tree.
struct Node<S> {
    level: u32,
    /// The first address of the node.
    base: usize,
    /// The lock of the node. Only the holder changes `slots`.
    busy: AtomicBool,
    /// The node is not in the tree now. Only the holder sets it.
    dead: AtomicBool,
    /// The slots. A walk reads them with no `busy`, so the spin lock gives safe access. It is held
    /// only for a short time.
    slots: SpinLock<Vec<Slot<S>>>,
}

impl<S: Clone> Node<S> {
    /// Makes a node with each slot a copy of `fill`. The caller holds the new node.
    fn new_held(level: u32, base: usize, fill: &Slot<S>) -> Self {
        let slots = (0..FANOUT).map(|_| fill.leaf_copy()).collect();
        Self {
            level,
            base,
            busy: AtomicBool::new(true),
            dead: AtomicBool::new(false),
            slots: SpinLock::new(slots),
        }
    }
}

impl<S> Node<S> {
    fn acquire(&self) {
        while self
            .busy
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.busy.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
    }

    fn try_acquire(&self) -> bool {
        self.busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    fn release(&self) {
        self.busy.store(false, Ordering::Release);
    }

    /// Locks the node, and gives `false` with no lock if the node is dead.
    fn acquire_live(&self) -> bool {
        self.acquire();
        if self.dead.load(Ordering::Relaxed) {
            self.release();
            return false;
        }
        true
    }

    /// Marks the node and each node below it dead. The caller holds them.
    fn kill(&self) {
        self.dead.store(true, Ordering::Relaxed);
        for slot in self.slots.lock().iter() {
            if let Slot::Child(c) = slot {
                c.kill();
            }
        }
    }

    /// The end of the node.
    fn end(&self) -> usize {
        self.base + slot_size(self.level) * FANOUT
    }

    /// The index of the slot of `addr`. `addr` is in the node.
    fn index(&self, addr: usize) -> usize {
        (addr - self.base) / slot_size(self.level)
    }
}

/// The tree of one address space.
pub struct Tree<S> {
    root: Arc<Node<S>>,
}

impl<S: Clone> Default for Tree<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Clone> Tree<S> {
    /// Makes a tree with no status.
    pub fn new() -> Self {
        let root = Node::new_held(LEVELS, 0, &Slot::Empty);
        root.release();
        Self { root: Arc::new(root) }
    }

    /// Locks the page aligned range `start..end`. The walk goes down to the lowest node that
    /// covers the range, and makes the nodes on the way if they are not there, as a page table
    /// walk makes page table pages. Then it locks each node below that node in the range.
    ///
    /// # Panics
    ///
    /// If the range is empty or goes past [`TREE_END`].
    pub fn lock(&self, start: usize, end: usize) -> RangeLock<S> {
        assert!(start < end && end <= TREE_END, "a bad range for the tree");
        let node = 'walk: loop {
            let mut node = self.root.clone();
            let mut held = false;
            while node.level > 1 {
                let i = node.index(start);
                if i != node.index(end - 1) {
                    break;
                }
                let child = match &node.slots.lock()[i] {
                    Slot::Child(c) => Some(c.clone()),
                    _ => None,
                };
                if let Some(c) = child {
                    if held {
                        node.release();
                        held = false;
                    }
                    node = c;
                    continue;
                }
                // The child is missing. Only the holder of the node makes it.
                if !held {
                    if !node.acquire_live() {
                        continue 'walk;
                    }
                    held = true;
                    continue;
                }
                let next = {
                    let mut slots = node.slots.lock();
                    let base = node.base + i * slot_size(node.level);
                    let c = Arc::new(Node::new_held(node.level - 1, base, &slots[i]));
                    slots[i] = Slot::Child(c.clone());
                    c
                };
                node.release();
                node = next;
            }
            if held || node.acquire_live() {
                break node;
            }
        };
        let mut held = Vec::new();
        held.push(node.clone());
        lock_below(&node, start, end, &mut held, false);
        RangeLock { start, end, held }
    }

    /// Locks the whole tree if no other operation holds a node. Gives `None` if one does.
    pub fn try_lock_all(&self) -> Option<RangeLock<S>> {
        if !self.root.try_acquire() {
            return None;
        }
        let mut held = Vec::new();
        held.push(self.root.clone());
        if !lock_below(&self.root, 0, TREE_END, &mut held, true) {
            drop(RangeLock { start: 0, end: TREE_END, held });
            return None;
        }
        Some(RangeLock { start: 0, end: TREE_END, held })
    }
}

/// Locks each node below `node` that has an address in `start..end`, in the order of the
/// addresses, and adds it to `held`. With `try_only`, it does not wait, and gives `false` if a
/// node is busy.
fn lock_below<S>(
    node: &Arc<Node<S>>,
    start: usize,
    end: usize,
    held: &mut Vec<Arc<Node<S>>>,
    try_only: bool,
) -> bool {
    if node.level == 1 {
        return true;
    }
    let first = node.index(start.max(node.base));
    let last = node.index(end.min(node.end()) - 1);
    let children: Vec<Arc<Node<S>>> = node.slots.lock()[first..=last]
        .iter()
        .filter_map(|s| match s {
            Slot::Child(c) => Some(c.clone()),
            _ => None,
        })
        .collect();
    for child in children {
        if try_only {
            if !child.try_acquire() {
                return false;
            }
        } else {
            child.acquire();
        }
        held.push(child.clone());
        if !lock_below(&child, start, end, held, try_only) {
            return false;
        }
    }
    true
}

/// A locked range of the tree. The guard reads and changes the statuses of the pages in the
/// range. It unlocks the nodes when it is dropped.
pub struct RangeLock<S> {
    start: usize,
    end: usize,
    /// The locked nodes. The first is the top node.
    held: Vec<Arc<Node<S>>>,
}

impl<S> Drop for RangeLock<S> {
    fn drop(&mut self) {
        for node in self.held.iter().rev() {
            node.release();
        }
    }
}

impl<S: Clone> RangeLock<S> {
    /// The range that the guard can read and change. It is the locked range, or all of the top
    /// node if it is a node of the lowest level, because such a node has no node below it.
    pub fn span(&self) -> (usize, usize) {
        let top = &self.held[0];
        if top.level == 1 { (top.base, top.end()) } else { (self.start, self.end) }
    }

    fn check(&self, start: usize, end: usize) {
        let (lo, hi) = self.span();
        assert!(lo <= start && start < end && end <= hi, "the range is not locked");
    }

    /// The status of the page at `addr`.
    ///
    /// # Panics
    ///
    /// If `addr` is not in the span of the guard.
    pub fn get(&self, addr: usize) -> Option<S> {
        self.check(addr, addr + 1);
        let mut node = self.held[0].clone();
        loop {
            let next = match &node.slots.lock()[node.index(addr)] {
                Slot::Empty => return None,
                Slot::Status(s) => return Some(s.clone()),
                Slot::Child(c) => c.clone(),
            };
            node = next;
        }
    }

    /// Sets the status of each page in the page aligned range `start..end`, or makes the pages
    /// empty with `None`. A slot that the range covers loses its nodes below it, as a page table
    /// frees the page table pages of a range that is not mapped now.
    ///
    /// # Panics
    ///
    /// If the range is not page aligned or is not in the span of the guard.
    pub fn set(&mut self, start: usize, end: usize, status: Option<S>) {
        self.check(start, end);
        let page = 1 << PAGE_SHIFT;
        assert!(start.is_multiple_of(page) && end.is_multiple_of(page), "the range is not aligned");
        let fill = match status {
            Some(s) => Slot::Status(s),
            None => Slot::Empty,
        };
        let top = self.held[0].clone();
        set_in(&top, start, end, &fill, &mut self.held);
    }

    /// Gives the runs of pages with a status in `start..end`, in address order. A run is the
    /// largest range of pages that are next to each other and have statuses that `same` joins.
    /// The first status of the run represents it.
    ///
    /// # Panics
    ///
    /// If the range is not in the span of the guard.
    pub fn runs(
        &self,
        start: usize,
        end: usize,
        same: impl Fn(&S, &S) -> bool,
    ) -> Vec<(usize, usize, S)> {
        self.check(start, end);
        let mut out: Vec<(usize, usize, S)> = Vec::new();
        collect(&self.held[0], start, end, &mut |a, b, s: &S| {
            if let Some(last) = out.last_mut()
                && last.1 == a
                && same(&last.2, s)
            {
                last.1 = b;
                return;
            }
            out.push((a, b, s.clone()));
        });
        out
    }

    /// Gives the run of the page at `addr` in the span of the guard, as [`RangeLock::runs`] does.
    /// The status of the first page of the run represents it.
    ///
    /// # Panics
    ///
    /// If `addr` is not in the span of the guard.
    pub fn run_at(&self, addr: usize, same: impl Fn(&S, &S) -> bool) -> Option<(usize, usize, S)> {
        self.check(addr, addr + 1);
        let top = &self.held[0];
        if top.level != 1 {
            let (lo, hi) = self.span();
            return self.runs(lo, hi, same).into_iter().find(|r| r.0 <= addr && addr < r.1);
        }
        // A node of the lowest level has a slot for each page, so the run is a range of slots.
        let slots = top.slots.lock();
        let i = top.index(addr);
        let Slot::Status(s) = &slots[i] else { return None };
        let joins = |j: usize| matches!(&slots[j], Slot::Status(t) if same(s, t));
        let mut first = i;
        while first > 0 && joins(first - 1) {
            first -= 1;
        }
        let mut end = i + 1;
        while end < FANOUT && joins(end) {
            end += 1;
        }
        let Slot::Status(head) = &slots[first] else { return None };
        let page = slot_size(1);
        Some((top.base + first * page, top.base + end * page, head.clone()))
    }

    /// Tells if a page in `start..end` has a status.
    pub fn any(&self, start: usize, end: usize) -> bool {
        self.check(start, end);
        let mut found = false;
        collect(&self.held[0], start, end, &mut |_, _, _: &S| found = true);
        found
    }
}

/// Sets each slot of `node` in `start..end` to `fill`. A slot that the range covers in part gets
/// a child, which starts with the old value of the slot. The new child goes in `held`, so that
/// no walk takes it. The nodes below a covered slot leave the tree, and they are dead.
fn set_in<S: Clone>(
    node: &Arc<Node<S>>,
    start: usize,
    end: usize,
    fill: &Slot<S>,
    held: &mut Vec<Arc<Node<S>>>,
) {
    let size = slot_size(node.level);
    let first = node.index(start.max(node.base));
    let last = node.index(end.min(node.end()) - 1);
    let mut slots = node.slots.lock();
    for i in first..=last {
        let lo = node.base + i * size;
        if start <= lo && lo + size <= end {
            if let Slot::Child(c) = &slots[i] {
                c.kill();
            }
            slots[i] = fill.leaf_copy();
            continue;
        }
        let child = match &slots[i] {
            Slot::Child(c) => c.clone(),
            old => {
                let c = Arc::new(Node::new_held(node.level - 1, lo, old));
                slots[i] = Slot::Child(c.clone());
                held.push(c.clone());
                c
            }
        };
        set_in(&child, start, end, fill, held);
    }
}

/// Calls `f` with each range of `node` in `start..end` that has one status, in address order.
fn collect<S: Clone>(
    node: &Arc<Node<S>>,
    start: usize,
    end: usize,
    f: &mut impl FnMut(usize, usize, &S),
) {
    let size = slot_size(node.level);
    let first = node.index(start.max(node.base));
    let last = node.index(end.min(node.end()) - 1);
    // The children go after the lock of the slots, because `f` can take time.
    let mut items: Vec<(usize, Slot<S>)> = Vec::new();
    {
        let slots = node.slots.lock();
        for (i, slot) in slots[first..=last].iter().enumerate() {
            let item = match slot {
                Slot::Empty => continue,
                Slot::Status(s) => Slot::Status(s.clone()),
                Slot::Child(c) => Slot::Child(c.clone()),
            };
            items.push((node.base + (first + i) * size, item));
        }
    }
    for (lo, item) in items {
        match item {
            Slot::Status(s) => f(lo.max(start), (lo + size).min(end), &s),
            Slot::Child(c) => collect(&c, start, end, f),
            Slot::Empty => {}
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::vec;

    const P: usize = 4096;
    const M2: usize = 2 << 20;
    const G1: usize = 1 << 30;

    fn eq(a: &u32, b: &u32) -> bool {
        a == b
    }

    #[test]
    fn set_and_get() {
        let t: Tree<u32> = Tree::new();
        let mut r = t.lock(0, TREE_END);
        r.set(G1, 3 * G1, Some(7));
        r.set(G1 + 5 * P, G1 + 9 * P, Some(8));
        r.set(G1 + 6 * P, G1 + 7 * P, None);
        assert_eq!(r.get(G1), Some(7));
        assert_eq!(r.get(G1 + 5 * P), Some(8));
        assert_eq!(r.get(G1 + 6 * P), None);
        assert_eq!(r.get(G1 + 7 * P + 100), Some(8));
        assert_eq!(r.get(3 * G1), None);
        assert_eq!(
            r.runs(0, TREE_END, eq),
            vec![
                (G1, G1 + 5 * P, 7),
                (G1 + 5 * P, G1 + 6 * P, 8),
                (G1 + 7 * P, G1 + 9 * P, 8),
                (G1 + 9 * P, 3 * G1, 7)
            ]
        );
        assert!(r.any(G1 + 6 * P, G1 + 8 * P));
        assert!(!r.any(G1 + 6 * P, G1 + 7 * P));
    }

    #[test]
    fn a_covered_slot_drops_its_children() {
        let t: Tree<u32> = Tree::new();
        let mut r = t.lock(0, TREE_END);
        r.set(M2 + P, M2 + 2 * P, Some(1));
        r.set(0, G1, Some(2));
        assert_eq!(r.runs(0, TREE_END, eq), vec![(0, G1, 2)]);
        r.set(0, G1, None);
        assert!(!r.any(0, TREE_END));
    }

    #[test]
    fn a_page_lock_has_the_whole_leaf_node() {
        let t: Tree<u32> = Tree::new();
        t.lock(0, TREE_END).set(0, G1, Some(1));
        let mut r = t.lock(M2 + 3 * P, M2 + 4 * P);
        assert_eq!(r.span(), (M2, 2 * M2));
        assert_eq!(r.get(M2), Some(1));
        r.set(M2, M2 + P, Some(2));
        drop(r);
        let all = t.lock(0, TREE_END);
        assert_eq!(all.runs(0, G1, eq), vec![(0, M2, 1), (M2, M2 + P, 2), (M2 + P, G1, 1)]);
    }

    #[test]
    fn the_run_of_a_page() {
        let t: Tree<u32> = Tree::new();
        let mut all = t.lock(0, TREE_END);
        all.set(M2 + 10 * P, M2 + 20 * P, Some(1));
        all.set(M2 + 20 * P, M2 + 30 * P, Some(2));
        drop(all);
        let r = t.lock(M2 + 25 * P, M2 + 26 * P);
        assert_eq!(r.run_at(M2 + 25 * P, |_, _| true), Some((M2 + 10 * P, M2 + 30 * P, 1)));
        assert_eq!(r.run_at(M2 + 25 * P, eq), Some((M2 + 20 * P, M2 + 30 * P, 2)));
        assert_eq!(r.run_at(M2 + 31 * P, eq), None);
    }

    #[test]
    fn try_lock_all_fails_when_a_node_is_held() {
        let t: Tree<u32> = Tree::new();
        let r = t.lock(5 * M2, 5 * M2 + P);
        assert!(t.try_lock_all().is_none());
        drop(r);
        assert!(t.try_lock_all().is_some());
    }

    #[test]
    fn threads_on_separate_ranges() {
        use std::sync::Arc as StdArc;
        let t: StdArc<Tree<u32>> = StdArc::new(Tree::new());
        let workers: std::vec::Vec<_> = (0..4u32)
            .map(|n| {
                let t = t.clone();
                std::thread::spawn(move || {
                    let base = G1 + n as usize * 4 * M2;
                    for i in 0..200 {
                        let a = base + (i % 64) * P;
                        let mut r = t.lock(a, a + P);
                        let old = r.get(a).unwrap_or(0);
                        r.set(a, a + P, Some(old + 1));
                    }
                })
            })
            .collect();
        // A thread that locks the whole tree at the same time.
        for _ in 0..20 {
            let r = t.lock(0, TREE_END);
            let _ = r.runs(0, TREE_END, eq);
        }
        for w in workers {
            w.join().unwrap();
        }
        let r = t.lock(0, TREE_END);
        for n in 0..4 {
            let base = G1 + n * 4 * M2;
            let total: u32 = (0..64).map(|i| r.get(base + i * P).unwrap_or(0)).sum();
            assert_eq!(total, 200);
        }
    }

    #[test]
    fn a_walk_starts_again_at_a_dead_node() {
        use std::sync::Arc as StdArc;
        let t: StdArc<Tree<u32>> = StdArc::new(Tree::new());
        let x = 7 * M2 + 3 * P;
        let worker = {
            let t = t.clone();
            std::thread::spawn(move || {
                for _ in 0..2000 {
                    let mut r = t.lock(x, x + P);
                    let old = r.get(x).unwrap_or(0);
                    r.set(x, x + P, Some(old + 1));
                }
            })
        };
        // Each round puts the leaf node of `x` out of the tree, with the same status for `x`.
        for _ in 0..2000 {
            let mut r = t.lock(6 * M2, 8 * M2);
            let v = r.get(x);
            r.set(7 * M2, 8 * M2, v);
        }
        worker.join().unwrap();
        assert_eq!(t.lock(x, x + P).get(x), Some(2000));
    }
}

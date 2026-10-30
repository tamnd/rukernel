//! The page table tree of the CortenMM backend.
//!
//! The tree has the shape of the page table of x86-64 and arm64 with 4 levels: each node has 512
//! slots, a slot of the lowest level is one page of 4 KiB, and the root covers 256 TiB. A slot is
//! empty, holds the status of each page in it, or points to a node of the next level. The status
//! of a page tells if the page is mapped and how. Thus the tree is the source of truth for the
//! address space, and there is no tree of areas. spec/24-open-questions.md question 1 is the
//! experiment.
//!
//! CortenMM (SOSP 2025) keeps the status of each page in the page table pages. The statuses of the
//! pages of a node of the lowest level are in the last level page table of the same 2 MiB, in
//! [`Leaves`], and the node has no slots. Thus a change of the pages of one 2 MiB block writes one
//! tree, the page table. The nodes above keep the statuses of their larger slots, which cover
//! 2 MiB or more, and the locks.
//!
//! Each node has its own lock. A [`RangeLock`] locks the lowest node that covers a range, and
//! each node below it in the range. Thus two operations on ranges in different nodes do not wait
//! for each other: a page fault locks one node of the lowest level, which covers 2 MiB. The lock
//! of a node of the lowest level is the lock of the 2 MiB block in [`Leaves`], next to the
//! statuses of the block, as CortenMM locks the page table page that keeps the statuses. Thus a
//! page fault can lock the block with the walk of the page table, and not walk this tree.
//!
//! A lock goes down from the root with no lock, as the RCU walk of CortenMM, to the lowest node
//! that covers the range, and then locks that node and each node below it in the range. Thus an
//! operation does not wait at a node above its range, and a page fault does not wait for a call
//! on another 2 MiB block. A walk locks a node on the way only to make a missing child. A node
//! that a holder removes from the tree is dead, and a walk that locks a dead node starts again.
//!
//! An empty node leaves the tree, as an empty page table page of Linux goes in `free_pgtables`.
//! A `set` that empties a child below the top of its lock removes the child at once. When a lock
//! drops and its top node is empty, it locks the parent and removes the node, and then the parent
//! if it is empty too. The nodes that a walk makes and that stay empty go in the same way.
//!
//! The protocol has no deadlock. An operation waits for a node only when it holds no node, or
//! when it holds an ancestor of the node, so each chain of waits goes down the tree. A node that a
//! holder makes is locked before other operations can see it.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Index, IndexMut};
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

    /// The status of the slot, if it has one.
    fn status(&self) -> Option<&S> {
        match self {
            Slot::Status(s) => Some(s),
            _ => None,
        }
    }
}

/// The statuses of the pages of the nodes of the lowest level, in the last level page tables of
/// the address space. The 2 MiB block of a node of the lowest level has one table.
///
/// A call holds the node of the lowest level of a block, or a node above it and each node below
/// it in the range, when it reads or changes the statuses of the block. A block with no node of
/// the lowest level has no status.
pub trait Leaves<S> {
    /// The status of the page at `addr`.
    fn get(&self, addr: usize) -> Option<S>;

    /// Sets the status of each page in the page aligned range `start..end`, or removes it with
    /// `None`.
    fn set(&self, start: usize, end: usize, status: Option<&S>);

    /// Calls `f` with ranges of pages in `start..end` with one status, in address order. Two
    /// ranges next to each other can have the same status.
    fn runs(&self, start: usize, end: usize, f: impl FnMut(usize, usize, &S));

    /// Gives the run of the page at `addr` in its 2 MiB block: the largest range of pages around
    /// it with statuses that `same` joins, and the status of the first page of the run.
    fn run_at(&self, addr: usize, same: impl Fn(&S, &S) -> bool) -> Option<(usize, usize, S)>;

    /// Tells if no page of the 2 MiB block at `base` has a status.
    fn is_empty(&self, base: usize) -> bool;

    /// Takes the lock of the 2 MiB block at `base`, which is the lock of its node of the lowest
    /// level, and waits while another call holds it.
    fn lock(&self, base: usize);

    /// Takes the lock of the block at `base` if no other call holds it. Gives `false` if one does.
    fn try_lock(&self, base: usize) -> bool;

    /// Releases the lock of the block at `base`.
    fn unlock(&self, base: usize);
}

/// The slots in one chunk of [`Slots`].
const CHUNK: usize = 128;

/// The slots of a node, in chunks of [`CHUNK`] slots. A chunk is 2 KiB, a small allocation of the
/// kernel heap. An allocation of more than 2 KiB maps pages of the heap, and its free sends a TLB
/// shootdown to each CPU. With one allocation of 8 KiB for each node, `fork` and `exit` made and
/// freed about 20 such allocations, and the shootdowns were most of their time.
struct Slots<S>([Vec<Slot<S>>; FANOUT / CHUNK]);

const _: () = assert!(CHUNK * size_of::<Slot<Arc<()>>>() <= 2048);

impl<S> Slots<S> {
    /// Gives the slots in order.
    fn iter(&self) -> impl Iterator<Item = &Slot<S>> {
        self.0.iter().flatten()
    }

    /// Gives the slots in order, to change them.
    fn iter_mut(&mut self) -> impl Iterator<Item = &mut Slot<S>> {
        self.0.iter_mut().flatten()
    }

    /// Gives the slots from `first` to `last`, both included.
    fn range(&self, first: usize, last: usize) -> impl Iterator<Item = &Slot<S>> {
        self.iter().skip(first).take(last + 1 - first)
    }
}

impl<S> Index<usize> for Slots<S> {
    type Output = Slot<S>;
    fn index(&self, i: usize) -> &Slot<S> {
        &self.0[i / CHUNK][i % CHUNK]
    }
}

impl<S> IndexMut<usize> for Slots<S> {
    fn index_mut(&mut self, i: usize) -> &mut Slot<S> {
        &mut self.0[i / CHUNK][i % CHUNK]
    }
}

/// One node of the tree.
struct Node<S> {
    level: u32,
    /// The first address of the node.
    base: usize,
    /// The lock of the node. Only the holder changes `slots`. A node of the lowest level uses the
    /// lock of its block in [`Leaves`], so two nodes of one block, a dead one and a live one, have
    /// one lock.
    busy: AtomicBool,
    /// The node is not in the tree now. Only the holder sets it.
    dead: AtomicBool,
    /// The slots. A walk reads them with no `busy`, so the spin lock gives safe access. It is held
    /// only for a short time.
    slots: SpinLock<Slots<S>>,
}

impl<S: Clone> Node<S> {
    /// Makes a node with each slot a copy of `fill`. The caller holds the new node. A node of the
    /// lowest level has no slots, and its pages get the status of `fill` in `leaves`. Its lock is
    /// the lock of its block, which this takes, or which the caller holds already with `locked`.
    fn new_held(
        level: u32,
        base: usize,
        fill: &Slot<S>,
        leaves: &impl Leaves<S>,
        locked: bool,
    ) -> Self {
        let slots = if level == 1 {
            if !locked {
                leaves.lock(base);
            }
            if let Some(s) = fill.status() {
                leaves.set(base, base + slot_size(2), Some(s));
            }
            Slots(core::array::from_fn(|_| Vec::new()))
        } else {
            Slots(core::array::from_fn(|_| (0..CHUNK).map(|_| fill.leaf_copy()).collect()))
        };
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
    fn acquire(&self, leaves: &impl Leaves<S>) {
        if self.level == 1 {
            return leaves.lock(self.base);
        }
        while self
            .busy
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // The holder can wait for a TLB request of this CPU, for example in `fork`.
            while self.busy.load(Ordering::Relaxed) {
                rk_frame::sync::wait_hint();
            }
        }
    }

    fn try_acquire(&self, leaves: &impl Leaves<S>) -> bool {
        if self.level == 1 {
            return leaves.try_lock(self.base);
        }
        self.busy.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    fn release(&self, leaves: &impl Leaves<S>) {
        if self.level == 1 {
            return leaves.unlock(self.base);
        }
        self.busy.store(false, Ordering::Release);
    }

    /// Locks the node, and gives `false` with no lock if the node is dead.
    fn acquire_live(&self, leaves: &impl Leaves<S>) -> bool {
        self.acquire(leaves);
        if self.dead.load(Ordering::Relaxed) {
            self.release(leaves);
            return false;
        }
        true
    }

    /// Marks the node and each node below it dead, and removes the statuses of the nodes of the
    /// lowest level from `leaves`. The caller holds the nodes.
    fn kill(&self, leaves: &impl Leaves<S>) {
        self.dead.store(true, Ordering::Relaxed);
        if self.level == 1 {
            leaves.set(self.base, self.end(), None);
            return;
        }
        for slot in self.slots.lock().iter() {
            if let Slot::Child(c) = slot {
                c.kill(leaves);
            }
        }
    }

    /// Tells if no slot of the node has a status or a child.
    fn is_empty(&self, leaves: &impl Leaves<S>) -> bool {
        if self.level == 1 {
            return leaves.is_empty(self.base);
        }
        self.slots.lock().iter().all(|s| matches!(s, Slot::Empty))
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
pub struct Tree<S, L> {
    root: Arc<Node<S>>,
    leaves: L,
}

impl<S: Clone, L: Leaves<S>> Tree<S, L> {
    /// Makes a tree with no status. The statuses of the nodes of the lowest level go in `leaves`,
    /// which has no status.
    pub fn new(leaves: L) -> Self {
        let root = Node::new_held(LEVELS, 0, &Slot::Empty, &leaves, false);
        root.release(&leaves);
        Self { root: Arc::new(root), leaves }
    }

    /// The statuses of the nodes of the lowest level.
    pub fn leaves(&self) -> &L {
        &self.leaves
    }

    /// Locks the page aligned range `start..end`. The walk goes down to the lowest node that
    /// covers the range, and makes the nodes on the way if they are not there, as a page table
    /// walk makes page table pages. Then it locks each node below that node in the range.
    ///
    /// # Panics
    ///
    /// If the range is empty or goes past [`TREE_END`].
    pub fn lock(&self, start: usize, end: usize) -> RangeLock<'_, S, L> {
        lock_from(&self.root, &self.leaves, start, end, 1)
    }

    /// Makes a copy of the tree that `all` locks, as `fork` copies the page table. `map` gives
    /// the status of the copy for each status of the tree, or `None` for a page that the copy does
    /// not have. A node of the copy with no status does not stay.
    ///
    /// The statuses of the nodes of the lowest level are not copied here. The caller copies them
    /// to `leaves` first, as `VmSpace::fork_with` copies them with the page table, and the copy
    /// has a node of the lowest level for each block of `leaves` with a status.
    ///
    /// # Panics
    ///
    /// If `all` does not lock the whole tree.
    pub fn fork(
        all: &RangeLock<'_, S, L>,
        mut map: impl FnMut(&S) -> Option<S>,
        leaves: L,
    ) -> Self {
        assert!(all.held[0].level == LEVELS && all.span() == (0, TREE_END), "a fork of a part");
        let root = copy_node(&all.held[0], &mut map, &leaves);
        root.release(&leaves);
        Self { root: Arc::new(root), leaves }
    }

    /// The number of nodes in the tree, for the tests.
    #[cfg(test)]
    fn nodes(&self) -> usize {
        fn count<S>(node: &Node<S>) -> usize {
            let slots = node.slots.lock();
            1 + slots
                .iter()
                .map(|s| if let Slot::Child(c) = s { count(c) } else { 0 })
                .sum::<usize>()
        }
        count(&self.root)
    }

    /// Locks the whole tree if no other operation holds a node. Gives `None` if one does.
    pub fn try_lock_all(&self) -> Option<RangeLock<'_, S, L>> {
        let leaves = &self.leaves;
        if !self.root.try_acquire(leaves) {
            return None;
        }
        let mut held = Vec::new();
        held.push(self.root.clone());
        let ok = lock_below(&self.root, leaves, 0, TREE_END, &mut held, true);
        let lock = RangeLock { start: 0, end: TREE_END, held, root: None, prune: false, leaves };
        ok.then_some(lock)
    }
}

/// Locks the page aligned range `start..end` of the tree of `root`, as [`Tree::lock`]. The walk
/// stops at a node of `top` or a higher level, so the lock holds a node of that level at least.
fn lock_from<'a, S: Clone, L: Leaves<S>>(
    root: &Arc<Node<S>>,
    leaves: &'a L,
    start: usize,
    end: usize,
    top: u32,
) -> RangeLock<'a, S, L> {
    assert!(start < end && end <= TREE_END, "a bad range for the tree");
    // The walk made a node, which can stay empty.
    let mut made = false;
    let node = 'walk: loop {
        let mut node = root.clone();
        let mut held = false;
        while node.level > top {
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
                    node.release(leaves);
                    held = false;
                }
                node = c;
                continue;
            }
            // The child is missing. Only the holder of the node makes it.
            if !held {
                if !node.acquire_live(leaves) {
                    continue 'walk;
                }
                held = true;
                continue;
            }
            let next = {
                let mut slots = node.slots.lock();
                let base = node.base + i * slot_size(node.level);
                let c = Arc::new(Node::new_held(node.level - 1, base, &slots[i], leaves, false));
                slots[i] = Slot::Child(c.clone());
                c
            };
            made = true;
            node.release(leaves);
            node = next;
        }
        if held || node.acquire_live(leaves) {
            break node;
        }
    };
    let mut held = Vec::new();
    held.push(node.clone());
    lock_below(&node, leaves, start, end, &mut held, false);
    RangeLock { start, end, held, root: Some(root.clone()), prune: made, leaves }
}

/// Removes the empty node of `level` at `base` from the tree, and then each node above it that
/// becomes empty, as `free_pgtables` of Linux frees the page table pages of a range with no
/// mapping. The caller holds no node.
fn prune_up<S: Clone, L: Leaves<S>>(
    root: &Arc<Node<S>>,
    leaves: &L,
    mut base: usize,
    mut level: u32,
) {
    while level < LEVELS {
        let end = base + slot_size(level) * FANOUT;
        // The lock holds the parent of the node, and the node if it is there.
        let mut lock = lock_from(root, leaves, base, end, level + 1);
        lock.prune = false;
        let parent = lock.held[0].clone();
        let empty = {
            let mut slots = parent.slots.lock();
            let i = parent.index(base);
            if let Slot::Child(c) = &slots[i] {
                if !c.is_empty(leaves) {
                    return;
                }
                c.kill(leaves);
                slots[i] = Slot::Empty;
            }
            slots.iter().all(|s| matches!(s, Slot::Empty))
        };
        drop(lock);
        if !empty {
            return;
        }
        base = parent.base;
        level = parent.level;
    }
}

/// Makes a copy of `node` and of each node below it, with each status that `map` gives. The copy
/// is held. A child of the copy with no status is not there. A node of the lowest level gets its
/// statuses from `leaves`, which has them already.
fn copy_node<S: Clone>(
    node: &Node<S>,
    map: &mut impl FnMut(&S) -> Option<S>,
    leaves: &impl Leaves<S>,
) -> Node<S> {
    let copy = Node::new_held(node.level, node.base, &Slot::Empty, leaves, false);
    if node.level == 1 {
        return copy;
    }
    {
        let from = node.slots.lock();
        let mut to = copy.slots.lock();
        for (dst, src) in to.iter_mut().zip(from.iter()) {
            *dst = match src {
                Slot::Empty => Slot::Empty,
                Slot::Status(s) => map(s).map_or(Slot::Empty, Slot::Status),
                Slot::Child(c) => {
                    let child = copy_node(c, map, leaves);
                    child.release(leaves);
                    if child.is_empty(leaves) { Slot::Empty } else { Slot::Child(Arc::new(child)) }
                }
            };
        }
    }
    copy
}

/// Locks each node below `node` that has an address in `start..end`, in the order of the
/// addresses, and adds it to `held`. With `try_only`, it does not wait, and gives `false` if a
/// node is busy.
fn lock_below<S>(
    node: &Arc<Node<S>>,
    leaves: &impl Leaves<S>,
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
    let children: Vec<Arc<Node<S>>> = node
        .slots
        .lock()
        .range(first, last)
        .filter_map(|s| match s {
            Slot::Child(c) => Some(c.clone()),
            _ => None,
        })
        .collect();
    for child in children {
        if try_only {
            if !child.try_acquire(leaves) {
                return false;
            }
        } else {
            child.acquire(leaves);
        }
        held.push(child.clone());
        if !lock_below(&child, leaves, start, end, held, try_only) {
            return false;
        }
    }
    true
}

/// A locked range of the tree. The guard reads and changes the statuses of the pages in the
/// range. It unlocks the nodes when it is dropped.
pub struct RangeLock<'a, S: Clone, L: Leaves<S>> {
    start: usize,
    end: usize,
    /// The locked nodes. The first is the top node.
    held: Vec<Arc<Node<S>>>,
    /// The root of the tree, to remove the top node after the unlock if it is empty. It is
    /// `None` for a lock that does not remove nodes.
    root: Option<Arc<Node<S>>>,
    /// The walk made a node, or a `set` made pages empty, so the top node can be empty.
    prune: bool,
    /// The statuses of the nodes of the lowest level.
    leaves: &'a L,
}

impl<S: Clone, L: Leaves<S>> Drop for RangeLock<'_, S, L> {
    fn drop(&mut self) {
        for node in self.held.iter().rev() {
            node.release(self.leaves);
        }
        // `set` removes each empty node below the top node. The top node needs the lock of its
        // parent, so it goes after the unlock.
        let top = &self.held[0];
        if self.prune
            && top.level < LEVELS
            && let Some(root) = &self.root
            && top.is_empty(self.leaves)
        {
            prune_up(root, self.leaves, top.base, top.level);
        }
    }
}

impl<S: Clone, L: Leaves<S>> RangeLock<'_, S, L> {
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
            if node.level == 1 {
                return self.leaves.get(addr);
            }
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
            None => {
                self.prune = true;
                Slot::Empty
            }
        };
        let top = self.held[0].clone();
        set_in(&top, start, end, &fill, &mut self.held, self.leaves);
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
        collect(&self.held[0], self.leaves, start, end, &same, &mut |a, b, s: &S| {
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
        // The statuses of a node of the lowest level are in the last level page table of its
        // block, so the run is a range of entries of that table.
        self.leaves.run_at(addr, same)
    }

    /// Tells if a page in `start..end` has a status.
    pub fn any(&self, start: usize, end: usize) -> bool {
        self.check(start, end);
        let mut found = false;
        let all = &|_: &S, _: &S| true;
        collect(&self.held[0], self.leaves, start, end, all, &mut |_, _, _: &S| found = true);
        found
    }
}

/// Sets each slot of `node` in `start..end` to `fill`. A slot that the range covers in part gets
/// a child, which starts with the old value of the slot. The new child goes in `held`, so that
/// no walk takes it. The nodes below a covered slot leave the tree, and they are dead. The pages
/// of a node of the lowest level get the status of `fill` in `leaves`.
fn set_in<S: Clone>(
    node: &Arc<Node<S>>,
    start: usize,
    end: usize,
    fill: &Slot<S>,
    held: &mut Vec<Arc<Node<S>>>,
    leaves: &impl Leaves<S>,
) {
    if node.level == 1 {
        leaves.set(start.max(node.base), end.min(node.end()), fill.status());
        return;
    }
    let size = slot_size(node.level);
    let first = node.index(start.max(node.base));
    let last = node.index(end.min(node.end()) - 1);
    let mut slots = node.slots.lock();
    for i in first..=last {
        let lo = node.base + i * size;
        if start <= lo && lo + size <= end {
            if let Slot::Child(c) = &slots[i] {
                c.kill(leaves);
            }
            slots[i] = fill.leaf_copy();
            continue;
        }
        let child = match &slots[i] {
            Slot::Child(c) => c.clone(),
            // An empty slot stays empty, with no child.
            Slot::Empty if matches!(fill, Slot::Empty) => continue,
            old => {
                // A node of the lowest level that this lock removed before holds the lock of the
                // block, so the new node takes its place in `held` and its lock.
                let dead = (node.level == 2)
                    .then(|| held.iter().position(|n| n.level == 1 && n.base == lo))
                    .flatten();
                let c = Arc::new(Node::new_held(node.level - 1, lo, old, leaves, dead.is_some()));
                slots[i] = Slot::Child(c.clone());
                match dead {
                    Some(k) => held[k] = c.clone(),
                    None => held.push(c.clone()),
                }
                c
            }
        };
        set_in(&child, start, end, fill, held, leaves);
        // A child with no status leaves the tree. The caller holds it, so no walk uses it.
        if matches!(fill, Slot::Empty) && child.is_empty(leaves) {
            child.kill(leaves);
            slots[i] = Slot::Empty;
        }
    }
}

/// Calls `f` with each range of `node` in `start..end` that has one status, in address order.
/// Slots next to each other with statuses that `same` joins go to `f` as one range, because a
/// node of the lowest level often has the same status in each slot.
fn collect<S: Clone>(
    node: &Arc<Node<S>>,
    leaves: &impl Leaves<S>,
    start: usize,
    end: usize,
    same: &impl Fn(&S, &S) -> bool,
    f: &mut impl FnMut(usize, usize, &S),
) {
    if node.level == 1 {
        leaves.runs(start.max(node.base), end.min(node.end()), f);
        return;
    }
    let size = slot_size(node.level);
    let first = node.index(start.max(node.base));
    let last = node.index(end.min(node.end()) - 1);
    // The children go after the lock of the slots, because `f` can take time. The slots go in
    // batches of `BATCH`, so that the list is a small allocation of the kernel heap (see
    // `Slots`).
    const BATCH: usize = 64;
    let mut items: Vec<(usize, usize, Slot<S>)> = Vec::with_capacity(BATCH);
    let mut next = first;
    while next <= last {
        let to = (next + BATCH - 1).min(last);
        {
            let slots = node.slots.lock();
            for (i, slot) in slots.range(next, to).enumerate() {
                let lo = node.base + (next + i) * size;
                match slot {
                    Slot::Empty => {}
                    Slot::Status(s) => match items.last_mut() {
                        Some((_, hi, Slot::Status(t))) if *hi == lo && same(t, s) => {
                            *hi = lo + size
                        }
                        _ => items.push((lo, lo + size, Slot::Status(s.clone()))),
                    },
                    Slot::Child(c) => items.push((lo, lo + size, Slot::Child(c.clone()))),
                }
            }
        }
        next = to + 1;
        for (lo, hi, item) in items.drain(..) {
            match item {
                Slot::Status(s) => f(lo.max(start), hi.min(end), &s),
                // A child of the lowest level goes to the leaves here and not in a call of
                // `collect`, because the frame of `collect` is large in the debug kernel and
                // `mmap` is deep in the stack.
                Slot::Child(c) if c.level == 1 => {
                    leaves.runs(start.max(c.base), end.min(c.end()), &mut *f)
                }
                Slot::Child(c) => collect(&c, leaves, start, end, same, f),
                Slot::Empty => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::vec;

    const P: usize = 4096;
    const M2: usize = 2 << 20;
    const G1: usize = 1 << 30;

    /// The statuses of the pages of the nodes of the lowest level, one for each page, as the
    /// status tables of the last level page tables keep them, and the blocks that are locked.
    struct Pages(SpinLock<BTreeMap<usize, u32>>, SpinLock<alloc::collections::BTreeSet<usize>>);

    impl Pages {
        fn new() -> Self {
            Self(SpinLock::new(BTreeMap::new()), SpinLock::new(alloc::collections::BTreeSet::new()))
        }

        /// The number of pages with a status.
        fn len(&self) -> usize {
            self.0.lock().len()
        }

        /// A copy with the status that `map` gives for each status, as `VmSpace::fork_with`.
        fn fork(&self, map: impl Fn(u32) -> Option<u32>) -> Self {
            let pages = self.0.lock().iter().filter_map(|(&a, &s)| Some((a, map(s)?))).collect();
            Self(SpinLock::new(pages), SpinLock::new(alloc::collections::BTreeSet::new()))
        }
    }

    impl Leaves<u32> for Pages {
        fn get(&self, addr: usize) -> Option<u32> {
            self.0.lock().get(&(addr & !(P - 1))).copied()
        }

        fn set(&self, start: usize, end: usize, status: Option<&u32>) {
            let mut pages = self.0.lock();
            for a in (start..end).step_by(P) {
                match status {
                    Some(&s) => pages.insert(a, s),
                    None => pages.remove(&a),
                };
            }
        }

        fn runs(&self, start: usize, end: usize, mut f: impl FnMut(usize, usize, &u32)) {
            for (&a, s) in self.0.lock().range(start..end) {
                f(a, a + P, s);
            }
        }

        fn run_at(
            &self,
            addr: usize,
            same: impl Fn(&u32, &u32) -> bool,
        ) -> Option<(usize, usize, u32)> {
            let pages = self.0.lock();
            let (page, block) = (addr & !(P - 1), addr & !(M2 - 1));
            let s = *pages.get(&page)?;
            let joins = |a: usize| pages.get(&a).is_some_and(|t| same(&s, t));
            let mut first = page;
            while first > block && joins(first - P) {
                first -= P;
            }
            let mut end = page + P;
            while end < block + M2 && joins(end) {
                end += P;
            }
            Some((first, end, *pages.get(&first)?))
        }

        fn is_empty(&self, base: usize) -> bool {
            self.0.lock().range(base..base + M2).next().is_none()
        }

        fn lock(&self, base: usize) {
            while !self.try_lock(base) {
                core::hint::spin_loop();
            }
        }

        fn try_lock(&self, base: usize) -> bool {
            self.1.lock().insert(base)
        }

        fn unlock(&self, base: usize) {
            assert!(self.1.lock().remove(&base), "the block is not locked");
        }
    }

    fn tree() -> Tree<u32, Pages> {
        Tree::new(Pages::new())
    }

    fn eq(a: &u32, b: &u32) -> bool {
        a == b
    }

    #[test]
    fn set_and_get() {
        let t = tree();
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
        let t = tree();
        let mut r = t.lock(0, TREE_END);
        r.set(M2 + P, M2 + 2 * P, Some(1));
        r.set(0, G1, Some(2));
        assert_eq!(r.runs(0, TREE_END, eq), vec![(0, G1, 2)]);
        r.set(0, G1, None);
        assert!(!r.any(0, TREE_END));
    }

    #[test]
    fn a_page_lock_has_the_whole_leaf_node() {
        let t = tree();
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
        let t = tree();
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
    fn runs_cross_the_chunks_and_batches() {
        // Each page of one node has its own status, so the walk goes through all chunks of the
        // slots and all batches of `collect`.
        let t = tree();
        let mut r = t.lock(0, TREE_END);
        for i in 0..FANOUT {
            r.set(M2 + i * P, M2 + (i + 1) * P, Some((i % 2) as u32));
        }
        let runs = r.runs(0, TREE_END, eq);
        assert_eq!(runs.len(), FANOUT);
        assert!(
            runs.iter()
                .enumerate()
                .all(|(i, x)| *x == (M2 + i * P, M2 + (i + 1) * P, (i % 2) as u32))
        );
        assert_eq!(r.runs(M2 + 100 * P, M2 + 300 * P, eq).len(), 200);
        assert_eq!(r.run_at(M2 + 200 * P, eq), Some((M2 + 200 * P, M2 + 201 * P, 0)));
    }

    #[test]
    fn empty_nodes_leave_the_tree() {
        let t = tree();
        // A page lock makes the nodes down to the leaf, and the clear of the page removes them.
        let mut r = t.lock(G1 + M2 + P, G1 + M2 + 2 * P);
        r.set(G1 + M2 + P, G1 + M2 + 2 * P, Some(1));
        drop(r);
        assert_eq!(t.nodes(), 4);
        let mut r = t.lock(G1 + M2 + P, G1 + M2 + 2 * P);
        r.set(G1 + M2 + P, G1 + M2 + 2 * P, None);
        drop(r);
        assert_eq!(t.nodes(), 1);
        // A clear of a large range removes the nodes below it, and keeps the nodes in use.
        let mut all = t.lock(0, TREE_END);
        all.set(G1 + P, G1 + 2 * P, Some(1));
        all.set(3 * G1 + P, 3 * G1 + 2 * P, Some(2));
        drop(all);
        assert_eq!(t.nodes(), 6);
        let mut r = t.lock(0, 2 * G1);
        r.set(0, 2 * G1, None);
        drop(r);
        assert_eq!(t.nodes(), 4);
        // The walk of a lock makes the nodes of its range, and the unlock removes them again if
        // they have no status.
        let r = t.lock(5 * G1, 5 * G1 + P);
        assert_eq!(t.nodes(), 6);
        drop(r);
        assert_eq!(t.nodes(), 4);
        assert_eq!(
            t.lock(0, TREE_END).runs(0, TREE_END, eq),
            vec![(3 * G1 + P, 3 * G1 + 2 * P, 2)]
        );
    }

    #[test]
    fn fork_copies_the_statuses() {
        let t = tree();
        let mut all = t.lock(0, TREE_END);
        all.set(G1, G1 + 3 * P, Some(1));
        all.set(G1 + 3 * P, G1 + 5 * P, Some(2));
        all.set(4 * G1, 5 * G1, Some(2));
        let map = |s: u32| (s != 2).then_some(s + 10);
        let child = Tree::fork(&all, |&s| map(s), t.leaves().fork(map));
        drop(all);
        assert_eq!(child.lock(0, TREE_END).runs(0, TREE_END, eq), vec![(G1, G1 + 3 * P, 11)]);
        assert_eq!(child.nodes(), 4);
    }

    #[test]
    fn the_statuses_of_small_pages_are_in_the_leaves() {
        // A map of a few pages writes the leaves, and no slot of a node holds their status.
        let t = tree();
        let mut all = t.lock(0, TREE_END);
        all.set(G1 + P, G1 + 3 * P, Some(1));
        assert_eq!(t.leaves().len(), 2);
        assert_eq!(t.leaves().get(G1 + 2 * P), Some(1));
        // A map of a whole 2 MiB block keeps one status in the slot of the block.
        all.set(G1 + 2 * M2, G1 + 3 * M2, Some(2));
        assert_eq!(t.leaves().len(), 2);
        assert_eq!(all.get(G1 + 2 * M2 + 5 * P), Some(2));
        assert_eq!(
            all.runs(0, TREE_END, eq),
            vec![(G1 + P, G1 + 3 * P, 1), (G1 + 2 * M2, G1 + 3 * M2, 2)]
        );
    }

    #[test]
    fn protect_and_unmap_change_the_leaves() {
        let t = tree();
        let mut all = t.lock(0, TREE_END);
        all.set(M2, M2 + 8 * P, Some(1));
        // `mprotect` of the middle gives the pages a new status.
        all.set(M2 + 2 * P, M2 + 4 * P, Some(2));
        assert_eq!(
            all.runs(0, TREE_END, eq),
            vec![(M2, M2 + 2 * P, 1), (M2 + 2 * P, M2 + 4 * P, 2), (M2 + 4 * P, M2 + 8 * P, 1)]
        );
        assert_eq!(t.leaves().get(M2 + 3 * P), Some(2));
        // `munmap` removes the statuses from the leaves.
        all.set(M2 + P, M2 + 8 * P, None);
        assert_eq!(t.leaves().len(), 1);
        all.set(M2, M2 + P, None);
        assert_eq!(t.leaves().len(), 0);
        drop(all);
        assert_eq!(t.nodes(), 1);
    }

    #[test]
    fn a_covered_slot_removes_its_leaves() {
        // A status for a large range removes the statuses of the pages below it from the leaves.
        let t = tree();
        let mut all = t.lock(0, TREE_END);
        all.set(M2 + P, M2 + 2 * P, Some(1));
        all.set(5 * G1 + P, 5 * G1 + 2 * P, Some(1));
        all.set(0, G1, Some(2));
        assert_eq!(t.leaves().len(), 1);
        assert_eq!(t.leaves().get(5 * G1 + P), Some(1));
        all.set(0, TREE_END, None);
        assert_eq!(t.leaves().len(), 0);
    }

    #[test]
    fn fork_copies_the_leaves() {
        let t = tree();
        let mut all = t.lock(0, TREE_END);
        all.set(M2, M2 + 2 * P, Some(1));
        all.set(M2 + 2 * P, M2 + 3 * P, Some(2));
        all.set(3 * M2 + P, 3 * M2 + 2 * P, Some(2));
        let map = |s: u32| (s == 1).then_some(s + 10);
        let child = Tree::fork(&all, |&s| map(s), t.leaves().fork(map));
        drop(all);
        // The child has a node of the lowest level only for a block with a status.
        assert_eq!(child.nodes(), 4);
        assert_eq!(child.leaves().len(), 2);
        assert_eq!(child.lock(0, TREE_END).runs(0, TREE_END, eq), vec![(M2, M2 + 2 * P, 11)]);
        // The parent keeps its statuses.
        assert_eq!(t.leaves().len(), 4);
    }

    #[test]
    fn a_fault_lock_moves_the_status_to_the_leaves() {
        // A page with a status and no frame: the status is in the slot of a large range. The lock
        // of a fault makes the node of the lowest level, and its pages get the status in the
        // leaves, as a page table walk makes the last level table.
        let t = tree();
        t.lock(0, TREE_END).set(0, G1, Some(7));
        assert_eq!(t.leaves().len(), 0);
        let x = 5 * M2 + 9 * P;
        let r = t.lock(x, x + P);
        assert_eq!(t.leaves().len(), FANOUT);
        assert_eq!(r.get(x), Some(7));
        assert_eq!(r.run_at(x, eq), Some((5 * M2, 6 * M2, 7)));
        drop(r);
        // The node has statuses, so it stays.
        assert_eq!(t.nodes(), 4);
        assert_eq!(t.lock(0, TREE_END).runs(0, TREE_END, eq), vec![(0, G1, 7)]);
    }

    #[test]
    fn try_lock_all_fails_when_a_node_is_held() {
        let t = tree();
        let r = t.lock(5 * M2, 5 * M2 + P);
        assert!(t.try_lock_all().is_none());
        drop(r);
        assert!(t.try_lock_all().is_some());
    }

    #[test]
    fn a_held_block_stops_a_lock_of_its_node() {
        // A page fault holds the block in the leaves and not the node of the tree.
        let t = tree();
        t.lock(0, TREE_END).set(M2, M2 + P, Some(1));
        t.leaves().lock(M2);
        assert!(t.try_lock_all().is_none());
        t.leaves().unlock(M2);
        assert!(t.try_lock_all().is_some());
        assert!(t.leaves().1.lock().is_empty());
    }

    #[test]
    fn a_lock_that_makes_a_block_again_keeps_one_lock() {
        // The second node of the block takes the lock of the first, which the lock holds.
        let t = tree();
        let mut r = t.lock(0, G1);
        r.set(M2 + P, M2 + 2 * P, Some(1));
        r.set(M2, 2 * M2, Some(2));
        r.set(M2 + P, M2 + 2 * P, Some(3));
        drop(r);
        assert!(t.leaves().1.lock().is_empty());
        assert_eq!(
            t.lock(0, G1).runs(0, G1, eq),
            vec![(M2, M2 + P, 2), (M2 + P, M2 + 2 * P, 3), (M2 + 2 * P, 2 * M2, 2)]
        );
    }

    #[test]
    fn threads_on_separate_ranges() {
        use std::sync::Arc as StdArc;
        let t = StdArc::new(tree());
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
        let t = StdArc::new(tree());
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

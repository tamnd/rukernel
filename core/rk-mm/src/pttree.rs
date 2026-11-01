//! The page table tree of the CortenMM backend.
//!
//! The tree has the shape of the page table of x86-64 and arm64 with 4 levels: each node has 512
//! slots, a slot of the lowest level is one page of 4 KiB, and the root covers 256 TiB. A slot is
//! empty, holds the status of each page in it, or points to a node of the next level. The status
//! of a page tells if the page is mapped and how. Thus the tree is the source of truth for the
//! address space, and there is no tree of areas. spec/24-open-questions.md question 1 is the
//! experiment.
//!
//! CortenMM (SOSP 2025) keeps the status of each page in the page table pages. The nodes of this
//! tree are the page table pages of the address space, in [`Table`]: a node of the lowest level is
//! the last level page table of its 2 MiB block, and a node above is the page table page of the
//! same range. Each page table page keeps the statuses of its slots, the lock of its node, and a
//! flag that tells if the node is in the tree now (it is live). A slot of a node points to the
//! node below when that node is live. Thus a change of the statuses writes one tree, the page
//! table, and `fork` and the exit of a process walk one tree.
//!
//! Each node has its own lock. A [`RangeLock`] locks the lowest node that covers a range, and
//! each node below it in the range. Thus two operations on ranges in different nodes do not wait
//! for each other: a page fault locks one node of the lowest level, which covers 2 MiB. Thus a
//! page fault can lock the block with the walk of the page table, and not walk the levels above.
//!
//! A change of the statuses of a range can also change the pages of the range, as `munmap` and
//! `mprotect` do, with [`RangeLock::change`]. The change of the pages of each block is in the same
//! pass and under the same lock as the change of the statuses, as a change of CortenMM writes the
//! metadata and the entries of one page table page together.
//!
//! A lock of a range in one 2 MiB block with a live node takes only the lock of the block and does
//! not walk the tree, as CortenMM starts at the last level page table. Another lock goes down from
//! the root with no lock, as the RCU walk of CortenMM, to the lowest node that covers the range,
//! and then locks that node and each node below it in the range. Thus an operation does not wait
//! at a node above its range, and a page fault does not wait for a call on another 2 MiB block. A
//! walk locks a node on the way only to make a missing child. A node that a holder removes from the
//! tree is not live, and a walk that locks a node that is not live starts again.
//!
//! An empty node leaves the tree, as an empty page table page of Linux goes in `free_pgtables`.
//! A `set` that empties a child below the top of its lock removes the child at once. When a lock
//! drops and its top node is empty, it locks the parent and removes the node, and then the parent
//! if it is empty too. The nodes that a walk makes and that stay empty go in the same way. The page
//! table page of a node that leaves the tree stays, with no status, so its lock stays too.
//!
//! The protocol has no deadlock. An operation waits for a node only when it holds no node, or
//! when it holds an ancestor of the node, so each chain of waits goes down the tree. A node that a
//! holder makes is locked before other operations can see it.

use alloc::vec::Vec;
use core::marker::PhantomData;

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
    Child(Node),
}

impl<S> Slot<S> {
    /// The status of the slot, if it has one.
    fn status(&self) -> Option<&S> {
        match self {
            Slot::Status(s) => Some(s),
            _ => None,
        }
    }
}

/// The page table pages of an address space, which keep the nodes of the tree. The page table
/// page of the node of `level` at `base` keeps the status of each slot of the node, the lock of
/// the node, and the flag that tells if the node is live. A slot has a status only if the node
/// below it is not live.
///
/// A call holds a node, or a node above it and each live node below it in the range, when it
/// reads or changes the statuses of the node or the live flags of its children. A node that is not
/// live has no status and no live child.
pub trait Table<S> {
    /// A change of the pages, as `munmap` or `mprotect` makes it, that goes with a change of
    /// their statuses.
    type Op;

    /// Takes the lock of the node of `level` at `base`, and waits while another call holds it.
    /// The page table page of the node is made if it is not there.
    fn lock(&self, level: u32, base: usize);

    /// Takes the lock of the node of `level` at `base` if no other call holds it. Gives `false`
    /// if one does.
    fn try_lock(&self, level: u32, base: usize) -> bool;

    /// Releases the lock of the node of `level` at `base`.
    fn unlock(&self, level: u32, base: usize);

    /// Takes the lock of the node of the lowest level of the 2 MiB block at `base` as `lock`, but
    /// only if the node is live. Gives `false` with no lock if it is not. A lock in one block uses
    /// it to start at the block.
    fn lock_used(&self, base: usize) -> bool;

    /// Tells if the node of `level` at `base` is live. A walk reads it with no lock.
    fn live(&self, level: u32, base: usize) -> bool;

    /// Marks the node of `level` at `base` live or not live. The caller holds the node and its
    /// parent.
    fn set_live(&self, level: u32, base: usize, live: bool);

    /// Tells if the node of `level` at `base` has no status and no live child.
    fn is_empty(&self, level: u32, base: usize) -> bool;

    /// The status of the slot at `addr` of the node of `level`, which is above the lowest level.
    fn slot(&self, level: u32, addr: usize) -> Option<S>;

    /// Sets the status of each slot of the node of `level` in `start..end`, or removes it with
    /// `None`. The range is in one node above the lowest level, and it is aligned to the slots.
    fn set_slots(&self, level: u32, start: usize, end: usize, status: Option<&S>);

    /// Calls `f` with the index of each slot from `first` to `last` of the node of `level` at
    /// `base`, which is above the lowest level, that is not empty, in order. `f` gets `None` for
    /// a slot that points to a live child, and else the status of the slot. The caller holds the
    /// node, and `f` does not use the table. This default reads each slot with `live` and `slot`.
    fn entries(
        &self,
        level: u32,
        base: usize,
        first: usize,
        last: usize,
        mut f: impl FnMut(usize, Option<&S>),
    ) {
        let size = slot_size(level);
        for i in first..=last {
            let child = base + i * size;
            if self.live(level - 1, child) {
                f(i, None);
            } else if let Some(s) = self.slot(level, child) {
                f(i, Some(&s));
            }
        }
    }

    /// The status of the page at `addr`, which is in a node of the lowest level.
    fn get(&self, addr: usize) -> Option<S>;

    /// Sets the status of each page in the page aligned range `start..end`, or removes it with
    /// `None`, and makes the change `op` to the pages of the range, in one pass. `old` gets the
    /// runs of the old statuses of the range in address order, as `runs` gives them. The range is
    /// in one 2 MiB block.
    fn set(
        &self,
        start: usize,
        end: usize,
        status: Option<&S>,
        op: Option<&mut Self::Op>,
        old: &mut dyn FnMut(usize, usize, &S),
    );

    /// Makes the change `op` to the pages of the page aligned range `start..end`, which have no
    /// status in the nodes of the lowest level: their statuses are in the slots of the nodes
    /// above.
    fn change(&self, start: usize, end: usize, op: &mut Self::Op);

    /// Calls `f` with ranges of pages in `start..end` with one status, in address order. Two
    /// ranges next to each other can have the same status. The range is in nodes of the lowest
    /// level.
    fn runs(&self, start: usize, end: usize, f: impl FnMut(usize, usize, &S));

    /// Gives the run of the page at `addr` in its 2 MiB block: the largest range of pages around
    /// it with statuses that `same` joins, and the status of the first page of the run.
    fn run_at(&self, addr: usize, same: impl Fn(&S, &S) -> bool) -> Option<(usize, usize, S)>;
}

/// One node of the tree: the page table page of `level` at `base` in the [`Table`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Node {
    level: u32,
    /// The first address of the node.
    base: usize,
}

/// The root of the tree. It is always live.
const ROOT: Node = Node { level: LEVELS, base: 0 };

impl Node {
    /// The end of the node.
    fn end(self) -> usize {
        self.base + slot_size(self.level) * FANOUT
    }

    /// The index of the slot of `addr`. `addr` is in the node.
    fn index(self, addr: usize) -> usize {
        (addr - self.base) / slot_size(self.level)
    }

    /// The node below the slot `i`. The node is above the lowest level.
    fn child(self, i: usize) -> Node {
        Node { level: self.level - 1, base: self.base + i * slot_size(self.level) }
    }

    /// What the slot `i` holds. The caller holds the node. The node is above the lowest level.
    fn slot<S>(self, table: &impl Table<S>, i: usize) -> Slot<S> {
        let c = self.child(i);
        if table.live(c.level, c.base) {
            return Slot::Child(c);
        }
        table.slot(self.level, c.base).map_or(Slot::Empty, Slot::Status)
    }

    fn acquire<S>(self, table: &impl Table<S>) {
        table.lock(self.level, self.base);
    }

    fn try_acquire<S>(self, table: &impl Table<S>) -> bool {
        table.try_lock(self.level, self.base)
    }

    fn release<S>(self, table: &impl Table<S>) {
        table.unlock(self.level, self.base);
    }

    /// Locks the node, and gives `false` with no lock if the node is not live.
    fn acquire_live<S>(self, table: &impl Table<S>) -> bool {
        self.acquire(table);
        if !table.live(self.level, self.base) {
            self.release(table);
            return false;
        }
        true
    }

    /// Puts the node in the tree, with each slot set to `fill`. The caller holds the parent. The
    /// node is not live, so it has no status and no live child. This takes the lock of the node,
    /// or the caller holds it already with `locked`. The caller then holds the node.
    fn make_held<S>(self, fill: Option<&S>, table: &impl Table<S>, locked: bool) {
        if !locked {
            self.acquire(table);
        }
        if fill.is_some() {
            if self.level == 1 {
                table.set(self.base, self.end(), fill, None, &mut |_, _, _| {});
            } else {
                table.set_slots(self.level, self.base, self.end(), fill);
            }
        }
        table.set_live(self.level, self.base, true);
    }

    /// Takes the node and each node below it out of the tree, and removes their statuses. The
    /// caller holds the nodes.
    fn kill<S, L: Table<S>>(self, table: &L) {
        self.kill_with(table, None, &mut |_, _, _| {});
    }

    /// Takes the node out of the tree as `kill`, makes the change `op` to the pages of the node
    /// in the same pass, and gives the old statuses of the node to `old`, in address order.
    fn kill_with<S, L: Table<S>>(
        self,
        table: &L,
        mut op: Option<&mut L::Op>,
        old: &mut dyn FnMut(usize, usize, &S),
    ) {
        table.set_live(self.level, self.base, false);
        if self.level == 1 {
            table.set(self.base, self.end(), None, op, old);
            return;
        }
        let size = slot_size(self.level);
        for i in 0..FANOUT {
            let lo = self.base + i * size;
            match self.slot(table, i) {
                Slot::Child(c) => c.kill_with(table, op.as_deref_mut(), old),
                Slot::Status(s) => {
                    old(lo, lo + size, &s);
                    if let Some(op) = op.as_deref_mut() {
                        table.change(lo, lo + size, op);
                    }
                }
                // A page with no status has no frame.
                Slot::Empty => {}
            }
        }
        table.set_slots(self.level, self.base, self.end(), None);
    }

    /// Tells if no slot of the node has a status or a child.
    fn is_empty<S>(self, table: &impl Table<S>) -> bool {
        table.is_empty(self.level, self.base)
    }
}

/// The tree of one address space.
pub struct Tree<S, L> {
    table: L,
    _status: PhantomData<fn() -> S>,
}

impl<S: Clone, L: Table<S>> Tree<S, L> {
    /// Makes the tree of the page table pages of `table`. Each node that is live in `table` is in
    /// the tree, as the copy of `fork` makes them. The root is always in the tree.
    pub fn new(table: L) -> Self {
        ROOT.acquire(&table);
        table.set_live(LEVELS, 0, true);
        ROOT.release(&table);
        Self { table, _status: PhantomData }
    }

    /// The page table pages of the tree.
    pub fn table(&self) -> &L {
        &self.table
    }

    /// Locks the page aligned range `start..end`. The walk goes down to the lowest node that
    /// covers the range, and makes the nodes on the way if they are not there, as a page table
    /// walk makes page table pages. Then it locks each node below that node in the range.
    ///
    /// # Panics
    ///
    /// If the range is empty or goes past [`TREE_END`].
    pub fn lock(&self, start: usize, end: usize) -> RangeLock<'_, S, L> {
        // A range in one 2 MiB block starts at the block, as a change of CortenMM locks the last
        // level page table that it finds with the walk of the page table, and does not walk the
        // tree. A block with a live node needs no walk. A block with no live node needs it.
        let base = start & !(slot_size(2) - 1);
        if start < end && end <= base + slot_size(2) && self.table.lock_used(base) {
            let table = &self.table;
            return RangeLock {
                start,
                end,
                held: Vec::new(),
                block: Some(base),
                can_prune: true,
                prune: false,
                table,
                _status: PhantomData,
            };
        }
        lock_from(&self.table, start, end, 1)
    }

    /// The number of nodes in the tree, for the tests.
    #[cfg(test)]
    fn nodes(&self) -> usize {
        fn count<S>(table: &impl Table<S>, node: Node) -> usize {
            if node.level == 1 {
                return 1;
            }
            let children = (0..FANOUT).map(|i| node.child(i));
            1 + children
                .filter(|c| table.live(c.level, c.base))
                .map(|c| count(table, c))
                .sum::<usize>()
        }
        count(&self.table, ROOT)
    }

    /// Locks the whole tree if no other operation holds a node. Gives `None` if one does.
    pub fn try_lock_all(&self) -> Option<RangeLock<'_, S, L>> {
        let table = &self.table;
        if !ROOT.try_acquire(table) {
            return None;
        }
        let mut held = Vec::new();
        held.push(ROOT);
        let ok = lock_below(ROOT, table, 0, TREE_END, &mut held, true);
        let lock = RangeLock {
            start: 0,
            end: TREE_END,
            held,
            block: None,
            can_prune: false,
            prune: false,
            table,
            _status: PhantomData,
        };
        ok.then_some(lock)
    }
}

/// Locks the page aligned range `start..end` of the tree, as [`Tree::lock`]. The walk stops at a
/// node of `top` or a higher level, so the lock holds a node of that level at least.
fn lock_from<'a, S: Clone, L: Table<S>>(
    table: &'a L,
    start: usize,
    end: usize,
    top: u32,
) -> RangeLock<'a, S, L> {
    assert!(start < end && end <= TREE_END, "a bad range for the tree");
    // The walk made a node, which can stay empty.
    let mut made = false;
    let node = 'walk: loop {
        let mut node = ROOT;
        let mut held = false;
        while node.level > top {
            let i = node.index(start);
            if i != node.index(end - 1) {
                break;
            }
            let c = node.child(i);
            if table.live(c.level, c.base) {
                if held {
                    node.release(table);
                    held = false;
                }
                node = c;
                continue;
            }
            // The child is missing. Only the holder of the node makes it.
            if !held {
                if !node.acquire_live(table) {
                    continue 'walk;
                }
                held = true;
                continue;
            }
            // The child starts with the status of the slot.
            let fill = table.slot(node.level, c.base);
            c.make_held(fill.as_ref(), table, false);
            table.set_slots(node.level, c.base, c.end(), None);
            made = true;
            node.release(table);
            node = c;
        }
        if held || node.acquire_live(table) {
            break node;
        }
    };
    let mut held = Vec::new();
    held.push(node);
    lock_below(node, table, start, end, &mut held, false);
    RangeLock {
        start,
        end,
        held,
        block: None,
        can_prune: true,
        prune: made,
        table,
        _status: PhantomData,
    }
}

/// Removes the empty node of `level` at `base` from the tree, and then each node above it that
/// becomes empty, as `free_pgtables` of Linux frees the page table pages of a range with no
/// mapping. The caller holds no node.
fn prune_up<S: Clone, L: Table<S>>(table: &L, mut base: usize, mut level: u32) {
    while level < LEVELS {
        let end = base + slot_size(level) * FANOUT;
        // The lock holds the parent of the node, and the node if it is live.
        let mut lock = lock_from(table, base, end, level + 1);
        lock.prune = false;
        let parent = lock.held[0];
        let node = Node { level, base };
        if table.live(level, base) {
            if !node.is_empty(table) {
                return;
            }
            node.kill(table);
        }
        let empty = parent.is_empty(table);
        drop(lock);
        if !empty {
            return;
        }
        base = parent.base;
        level = parent.level;
    }
}

/// Locks each live node below `node` that has an address in `start..end`, in the order of the
/// addresses, and adds it to `held`. With `try_only`, it does not wait, and gives `false` if a
/// node is busy.
fn lock_below<S>(
    node: Node,
    table: &impl Table<S>,
    start: usize,
    end: usize,
    held: &mut Vec<Node>,
    try_only: bool,
) -> bool {
    if node.level == 1 {
        return true;
    }
    let first = node.index(start.max(node.base));
    let last = node.index(end.min(node.end()) - 1);
    // The caller holds `node`, so no other call makes or removes its children.
    let mut live = [0u64; FANOUT / 64];
    table.entries(node.level, node.base, first, last, |i, s| {
        if s.is_none() {
            live[i / 64] |= 1 << (i % 64);
        }
    });
    let is_live = |i: &usize| live[i / 64] & (1 << (i % 64)) != 0;
    for child in (first..=last).filter(is_live).map(|i| node.child(i)) {
        if try_only {
            if !child.try_acquire(table) {
                return false;
            }
        } else {
            child.acquire(table);
        }
        held.push(child);
        if !lock_below(child, table, start, end, held, try_only) {
            return false;
        }
    }
    true
}

/// A locked range of the tree. The guard reads and changes the statuses of the pages in the
/// range. It unlocks the nodes when it is dropped.
pub struct RangeLock<'a, S: Clone, L: Table<S>> {
    start: usize,
    end: usize,
    /// The locked nodes. The first is the top node. It is empty for a lock of one block.
    held: Vec<Node>,
    /// The 2 MiB block of a lock that holds only the node of the lowest level of the block. Such
    /// a lock does not walk the tree.
    block: Option<usize>,
    /// The lock can remove empty nodes after the unlock. A lock of the whole tree does not.
    can_prune: bool,
    /// The walk made a node, or a `set` made pages empty, so the top node can be empty.
    prune: bool,
    /// The page table pages.
    table: &'a L,
    _status: PhantomData<fn() -> S>,
}

impl<S: Clone, L: Table<S>> Drop for RangeLock<'_, S, L> {
    fn drop(&mut self) {
        for node in self.held.iter().rev() {
            node.release(self.table);
        }
        if let Some(base) = self.block {
            self.table.unlock(1, base);
        }
        // `set` removes each empty node below the top node. The top node needs the lock of its
        // parent, so it goes after the unlock.
        if !self.can_prune || !self.prune {
            return;
        }
        let (base, level, empty) = match self.block {
            Some(base) => (base, 1, self.table.is_empty(1, base)),
            None => {
                let top = self.held[0];
                (top.base, top.level, top.level < LEVELS && top.is_empty(self.table))
            }
        };
        if empty {
            prune_up(self.table, base, level);
        }
    }
}

impl<S: Clone, L: Table<S>> RangeLock<'_, S, L> {
    /// The range that the guard can read and change. It is the locked range, or all of the top
    /// node if it is a node of the lowest level, because such a node has no node below it.
    pub fn span(&self) -> (usize, usize) {
        if let Some(base) = self.block {
            return (base, base + slot_size(2));
        }
        let top = self.held[0];
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
        if self.block.is_some() {
            return self.table.get(addr);
        }
        let mut node = self.held[0];
        loop {
            if node.level == 1 {
                return self.table.get(addr);
            }
            match node.slot(self.table, node.index(addr)) {
                Slot::Empty => return None,
                Slot::Status(s) => return Some(s),
                Slot::Child(c) => node = c,
            }
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
        self.change(start, end, status, None, |_, _, _| {});
    }

    /// Sets the statuses as `set`, and makes the change `op` to the pages of the range in the same
    /// pass, under the same lock of each 2 MiB block. `old` gets the old statuses of the range in
    /// address order. A run can come in parts, and two runs next to each other can have the same
    /// status.
    ///
    /// # Panics
    ///
    /// As for `set`.
    pub fn change(
        &mut self,
        start: usize,
        end: usize,
        status: Option<S>,
        op: Option<&mut L::Op>,
        mut old: impl FnMut(usize, usize, &S),
    ) {
        self.check(start, end);
        let page = 1 << PAGE_SHIFT;
        assert!(start.is_multiple_of(page) && end.is_multiple_of(page), "the range is not aligned");
        if status.is_none() {
            self.prune = true;
        }
        if self.block.is_some() {
            return self.table.set(start, end, status.as_ref(), op, &mut old);
        }
        let top = self.held[0];
        set_in(top, start, end, status.as_ref(), &mut self.held, self.table, op, &mut old);
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
        let mut f = |a, b, s: &S| {
            if let Some(last) = out.last_mut()
                && last.1 == a
                && same(&last.2, s)
            {
                last.1 = b;
                return;
            }
            out.push((a, b, s.clone()));
        };
        match self.block {
            Some(_) => self.table.runs(start, end, f),
            None => collect(self.held[0], self.table, start, end, &same, &mut f),
        }
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
        if self.block.is_some() {
            return self.table.run_at(addr, same);
        }
        let top = self.held[0];
        if top.level != 1 {
            let (lo, hi) = self.span();
            return self.runs(lo, hi, same).into_iter().find(|r| r.0 <= addr && addr < r.1);
        }
        // The statuses of a node of the lowest level are in the last level page table of its
        // block, so the run is a range of entries of that table.
        self.table.run_at(addr, same)
    }

    /// Tells if a page in `start..end` has a status.
    pub fn any(&self, start: usize, end: usize) -> bool {
        self.check(start, end);
        let mut found = false;
        let all = &|_: &S, _: &S| true;
        let mut f = |_, _, _: &S| found = true;
        match self.block {
            Some(_) => self.table.runs(start, end, f),
            None => collect(self.held[0], self.table, start, end, all, &mut f),
        }
        found
    }
}

/// Sets each slot of `node` in `start..end` to `fill`. A slot that the range covers in part gets
/// a child, which starts with the old value of the slot. The new child goes in `held`, so that
/// no walk takes it. The nodes below a covered slot leave the tree. The pages of a node of the
/// lowest level get the status of `fill`. The pages of the range get the change `op` in the same
/// pass, and `old` gets the old statuses in address order.
#[allow(clippy::too_many_arguments)]
fn set_in<S: Clone, L: Table<S>>(
    node: Node,
    start: usize,
    end: usize,
    fill: Option<&S>,
    held: &mut Vec<Node>,
    table: &L,
    mut op: Option<&mut L::Op>,
    old: &mut dyn FnMut(usize, usize, &S),
) {
    if node.level == 1 {
        table.set(start.max(node.base), end.min(node.end()), fill, op, old);
        return;
    }
    let size = slot_size(node.level);
    let first = node.index(start.max(node.base));
    let last = node.index(end.min(node.end()) - 1);
    for i in first..=last {
        let lo = node.base + i * size;
        if start <= lo && lo + size <= end {
            match node.slot(table, i) {
                Slot::Child(c) => c.kill_with(table, op.as_deref_mut(), old),
                Slot::Status(s) => {
                    old(lo, lo + size, &s);
                    if let Some(op) = op.as_deref_mut() {
                        table.change(lo, lo + size, op);
                    }
                }
                // A page with no status has no frame.
                Slot::Empty => {}
            }
            table.set_slots(node.level, lo, lo + size, fill);
            continue;
        }
        let child = match node.slot(table, i) {
            Slot::Child(c) => c,
            // An empty slot stays empty, with no child.
            Slot::Empty if fill.is_none() => continue,
            prev => {
                // A node that this lock took out of the tree before is still held, so it goes
                // back with that lock.
                let c = node.child(i);
                let locked = held.contains(&c);
                c.make_held(prev.status(), table, locked);
                table.set_slots(node.level, lo, lo + size, None);
                if !locked {
                    held.push(c);
                }
                c
            }
        };
        set_in(child, start, end, fill, held, table, op.as_deref_mut(), old);
        // A child with no status leaves the tree. The caller holds it, so no walk uses it.
        if fill.is_none() && child.is_empty(table) {
            child.kill(table);
        }
    }
}

/// Calls `f` with each range of `node` in `start..end` that has one status, in address order.
/// Slots next to each other with statuses that `same` joins go to `f` as one range, because a
/// node of the lowest level often has the same status in each slot.
fn collect<S: Clone>(
    node: Node,
    table: &impl Table<S>,
    start: usize,
    end: usize,
    same: &impl Fn(&S, &S) -> bool,
    f: &mut impl FnMut(usize, usize, &S),
) {
    if node.level == 1 {
        table.runs(start.max(node.base), end.min(node.end()), f);
        return;
    }
    let size = slot_size(node.level);
    let first = node.index(start.max(node.base));
    let last = node.index(end.min(node.end()) - 1);
    // The slots go in batches of `BATCH`, so that the list is a small allocation of the kernel
    // heap.
    const BATCH: usize = 64;
    let mut items: Vec<(usize, usize, Slot<S>)> = Vec::with_capacity(BATCH);
    let mut next = first;
    while next <= last {
        let to = (next + BATCH - 1).min(last);
        table.entries(node.level, node.base, next, to, |i, s| {
            let lo = node.base + i * size;
            match s {
                None => items.push((lo, lo + size, Slot::Child(node.child(i)))),
                Some(s) => match items.last_mut() {
                    Some((_, hi, Slot::Status(t))) if *hi == lo && same(t, s) => *hi = lo + size,
                    _ => items.push((lo, lo + size, Slot::Status(s.clone()))),
                },
            }
        });
        next = to + 1;
        for (lo, hi, item) in items.drain(..) {
            match item {
                Slot::Status(s) => f(lo.max(start), hi.min(end), &s),
                // A child of the lowest level goes to the table here and not in a call of
                // `collect`, because the frame of `collect` is large in the debug kernel and
                // `mmap` is deep in the stack.
                Slot::Child(c) if c.level == 1 => {
                    table.runs(start.max(c.base), end.min(c.end()), &mut *f)
                }
                Slot::Child(c) => collect(c, table, start, end, same, f),
                Slot::Empty => {}
            }
        }
    }
}
#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::vec;
    use rk_frame::sync::SpinLock;

    const P: usize = 4096;
    const M2: usize = 2 << 20;
    const G1: usize = 1 << 30;

    /// The page table pages of the tests. `pages` has the status of each page of the nodes of the
    /// lowest level, and `slots` the status of each slot of the nodes above, by level and address.
    /// `held` has the locked nodes and `live` the live nodes. `frames` is the pages with a frame,
    /// which the change of the tests removes, as `munmap` does.
    struct Pages {
        pages: SpinLock<BTreeMap<usize, u32>>,
        slots: SpinLock<BTreeMap<(u32, usize), u32>>,
        held: SpinLock<BTreeSet<(u32, usize)>>,
        live: SpinLock<BTreeSet<(u32, usize)>>,
        frames: SpinLock<BTreeSet<usize>>,
    }

    impl Pages {
        fn new() -> Self {
            Self {
                pages: SpinLock::new(BTreeMap::new()),
                slots: SpinLock::new(BTreeMap::new()),
                held: SpinLock::new(BTreeSet::new()),
                live: SpinLock::new(BTreeSet::new()),
                frames: SpinLock::new(BTreeSet::new()),
            }
        }

        /// The number of pages with a status in the nodes of the lowest level.
        fn len(&self) -> usize {
            self.pages.lock().len()
        }

        /// A copy with the status that `map` gives for each status, as `VmSpace::fork_with`. A
        /// node of the copy with no status and no live child is not live.
        fn fork(&self, map: impl Fn(u32) -> Option<u32>) -> Self {
            let copy = Self::new();
            *copy.pages.lock() =
                self.pages.lock().iter().filter_map(|(&a, &s)| Some((a, map(s)?))).collect();
            *copy.slots.lock() =
                self.slots.lock().iter().filter_map(|(&a, &s)| Some((a, map(s)?))).collect();
            *copy.live.lock() = self.live.lock().clone();
            for level in 1..LEVELS {
                let nodes: Vec<(u32, usize)> =
                    copy.live.lock().iter().copied().filter(|n| n.0 == level).collect();
                for (l, base) in nodes {
                    if copy.is_empty(l, base) {
                        copy.live.lock().remove(&(l, base));
                    }
                }
            }
            copy
        }
    }

    impl Table<u32> for Pages {
        /// The number of pages that the change removed.
        type Op = usize;

        fn lock(&self, level: u32, base: usize) {
            while !self.try_lock(level, base) {
                core::hint::spin_loop();
            }
        }

        fn try_lock(&self, level: u32, base: usize) -> bool {
            self.held.lock().insert((level, base))
        }

        fn unlock(&self, level: u32, base: usize) {
            assert!(self.held.lock().remove(&(level, base)), "the node is not locked");
        }

        fn lock_used(&self, base: usize) -> bool {
            self.lock(1, base);
            if self.live(1, base) {
                return true;
            }
            self.unlock(1, base);
            false
        }

        fn live(&self, level: u32, base: usize) -> bool {
            self.live.lock().contains(&(level, base))
        }

        fn set_live(&self, level: u32, base: usize, live: bool) {
            assert!(self.held.lock().contains(&(level, base)), "the node is not locked");
            if live {
                self.live.lock().insert((level, base));
            } else {
                self.live.lock().remove(&(level, base));
            }
        }

        fn is_empty(&self, level: u32, base: usize) -> bool {
            let end = base + slot_size(level) * FANOUT;
            if level == 1 {
                return self.pages.lock().range(base..end).next().is_none();
            }
            self.slots.lock().range((level, base)..(level, end)).next().is_none()
                && self.live.lock().range((level - 1, base)..(level - 1, end)).next().is_none()
        }

        fn slot(&self, level: u32, addr: usize) -> Option<u32> {
            self.slots.lock().get(&(level, addr & !(slot_size(level) - 1))).copied()
        }

        fn set_slots(&self, level: u32, start: usize, end: usize, status: Option<&u32>) {
            let mut slots = self.slots.lock();
            for a in (start..end).step_by(slot_size(level)) {
                match status {
                    Some(&s) => slots.insert((level, a), s),
                    None => slots.remove(&(level, a)),
                };
            }
        }

        fn get(&self, addr: usize) -> Option<u32> {
            self.pages.lock().get(&(addr & !(P - 1))).copied()
        }

        fn set(
            &self,
            start: usize,
            end: usize,
            status: Option<&u32>,
            op: Option<&mut usize>,
            old: &mut dyn FnMut(usize, usize, &u32),
        ) {
            assert_eq!(start & !(M2 - 1), (end - 1) & !(M2 - 1), "a set of more than one block");
            let mut pages = self.pages.lock();
            for a in (start..end).step_by(P) {
                let was = match status {
                    Some(&s) => pages.insert(a, s),
                    None => pages.remove(&a),
                };
                if let Some(was) = was {
                    old(a, a + P, &was);
                }
            }
            if let Some(op) = op {
                self.change(start, end, op);
            }
        }

        fn change(&self, start: usize, end: usize, op: &mut usize) {
            let mut frames = self.frames.lock();
            let gone: Vec<usize> = frames.range(start..end).copied().collect();
            for a in &gone {
                frames.remove(a);
            }
            *op += gone.len();
        }

        fn runs(&self, start: usize, end: usize, mut f: impl FnMut(usize, usize, &u32)) {
            for (&a, s) in self.pages.lock().range(start..end) {
                f(a, a + P, s);
            }
        }

        fn run_at(
            &self,
            addr: usize,
            same: impl Fn(&u32, &u32) -> bool,
        ) -> Option<(usize, usize, u32)> {
            let pages = self.pages.lock();
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
        let child = Tree::new(t.table().fork(map));
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
        assert_eq!(t.table().len(), 2);
        assert_eq!(t.table().get(G1 + 2 * P), Some(1));
        // A map of a whole 2 MiB block keeps one status in the slot of the block.
        all.set(G1 + 2 * M2, G1 + 3 * M2, Some(2));
        assert_eq!(t.table().len(), 2);
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
        assert_eq!(t.table().get(M2 + 3 * P), Some(2));
        // `munmap` removes the statuses from the leaves.
        all.set(M2 + P, M2 + 8 * P, None);
        assert_eq!(t.table().len(), 1);
        all.set(M2, M2 + P, None);
        assert_eq!(t.table().len(), 0);
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
        assert_eq!(t.table().len(), 1);
        assert_eq!(t.table().get(5 * G1 + P), Some(1));
        all.set(0, TREE_END, None);
        assert_eq!(t.table().len(), 0);
    }

    #[test]
    fn fork_copies_the_leaves() {
        let t = tree();
        let mut all = t.lock(0, TREE_END);
        all.set(M2, M2 + 2 * P, Some(1));
        all.set(M2 + 2 * P, M2 + 3 * P, Some(2));
        all.set(3 * M2 + P, 3 * M2 + 2 * P, Some(2));
        let map = |s: u32| (s == 1).then_some(s + 10);
        let child = Tree::new(t.table().fork(map));
        drop(all);
        // The child has a node of the lowest level only for a block with a status.
        assert_eq!(child.nodes(), 4);
        assert_eq!(child.table().len(), 2);
        assert_eq!(child.lock(0, TREE_END).runs(0, TREE_END, eq), vec![(M2, M2 + 2 * P, 11)]);
        // The parent keeps its statuses.
        assert_eq!(t.table().len(), 4);
    }

    #[test]
    fn a_fault_lock_moves_the_status_to_the_leaves() {
        // A page with a status and no frame: the status is in the slot of a large range. The lock
        // of a fault makes the node of the lowest level, and its pages get the status in the
        // leaves, as a page table walk makes the last level table.
        let t = tree();
        t.lock(0, TREE_END).set(0, G1, Some(7));
        assert_eq!(t.table().len(), 0);
        let x = 5 * M2 + 9 * P;
        let r = t.lock(x, x + P);
        assert_eq!(t.table().len(), FANOUT);
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
        t.table().lock(1, M2);
        assert!(t.try_lock_all().is_none());
        t.table().unlock(1, M2);
        assert!(t.try_lock_all().is_some());
        assert!(t.table().held.lock().is_empty());
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
        assert!(t.table().held.lock().is_empty());
        assert_eq!(
            t.lock(0, G1).runs(0, G1, eq),
            vec![(M2, M2 + P, 2), (M2 + P, M2 + 2 * P, 3), (M2 + 2 * P, 2 * M2, 2)]
        );
    }

    #[test]
    fn a_change_makes_the_pages_and_gives_the_old_statuses() {
        // A status in the slot of a 2 MiB block, statuses in the leaves of another block, and a
        // frame in each page of both. The change of `munmap` removes the frames in the same pass.
        let t = tree();
        let mut all = t.lock(0, TREE_END);
        all.set(0, 2 * M2, Some(1));
        all.set(M2 + P, M2 + 3 * P, Some(2));
        t.table().frames.lock().extend((0..2 * M2).step_by(P).chain([5 * M2]));
        let (mut gone, mut old) = (0, Vec::new());
        all.change(P, 2 * M2, None, Some(&mut gone), |a, b, s| old.push((a, b, *s)));
        assert_eq!(gone, 2 * FANOUT - 1);
        let joined: Vec<(usize, usize, u32)> = old.iter().fold(Vec::new(), |mut v, &(a, b, s)| {
            match v.last_mut() {
                Some((_, e, t)) if *e == a && *t == s => *e = b,
                _ => v.push((a, b, s)),
            }
            v
        });
        assert_eq!(joined, vec![(P, M2 + P, 1), (M2 + P, M2 + 3 * P, 2), (M2 + 3 * P, 2 * M2, 1)]);
        assert_eq!(all.runs(0, TREE_END, eq), vec![(0, P, 1)]);
        assert_eq!(*t.table().frames.lock(), [0, 5 * M2].into_iter().collect());
    }

    #[test]
    fn a_lock_in_one_block_starts_at_the_block() {
        let t = tree();
        t.lock(0, TREE_END).set(M2 + P, M2 + 3 * P, Some(1));
        // The block has statuses in the leaves, so the lock holds only the block.
        let mut r = t.lock(M2 + 2 * P, M2 + 4 * P);
        assert_eq!((r.block, r.held.len()), (Some(M2), 0));
        assert_eq!(r.span(), (M2, 2 * M2));
        assert!(t.try_lock_all().is_none());
        assert_eq!(r.runs(M2, 2 * M2, eq), vec![(M2 + P, M2 + 3 * P, 1)]);
        r.set(M2 + 2 * P, M2 + 4 * P, Some(2));
        drop(r);
        assert!(t.table().held.lock().is_empty());
        // A block with no status in the leaves needs the walk.
        let r = t.lock(3 * M2, 3 * M2 + P);
        assert_eq!((r.block, r.held[0].level), (None, 1));
        drop(r);
        // The clear of the last statuses of the block removes its node.
        let mut r = t.lock(M2, 2 * M2);
        assert!(r.block.is_some());
        r.set(M2, 2 * M2, None);
        drop(r);
        assert_eq!(t.nodes(), 1);
        assert!(t.table().held.lock().is_empty());
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

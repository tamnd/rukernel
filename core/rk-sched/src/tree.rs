//! The tree of a run queue: an AVL tree in a vector, keyed by the virtual deadline.
//!
//! Each node keeps the lowest virtual run time of its subtree, as the augmented red-black tree of
//! kernel/sched/fair.c of Linux does with `min_vruntime`. Thus the pick of the eligible task with
//! the earliest deadline goes down one path of the tree and takes O(log n) time. Linux uses a
//! red-black tree. An AVL tree gives the same bound, and its code is short in safe Rust.
//!
//! The nodes are in a vector and refer to each other by index, so the tree needs no unsafe code.
//! A removed node goes to a free list, and the next insert uses it again.

use super::Entity;
use alloc::vec::Vec;

/// The index of no node.
const NIL: u32 = u32::MAX;

/// The order of the tree: the virtual deadline, then the order of arrival.
type Key = (u64, u64);

/// A node of the tree.
#[derive(Debug)]
struct Node<T> {
    /// The task, or `None` for a node in the free list.
    task: Option<T>,
    entity: Entity,
    /// The order of arrival in the queue. Of two tasks with the same deadline, the task that
    /// came first is first in the tree.
    seq: u64,
    left: u32,
    right: u32,
    height: u8,
    /// The lowest pair of virtual run time and order of arrival in the subtree.
    min: (u64, u64),
}

/// A tree of tasks. `T` is the handle of a task.
#[derive(Debug)]
pub(crate) struct Tree<T> {
    nodes: Vec<Node<T>>,
    free: Vec<u32>,
    root: u32,
    len: usize,
}

impl<T> Tree<T> {
    /// Makes an empty tree.
    pub(crate) const fn new() -> Self {
        Self { nodes: Vec::new(), free: Vec::new(), root: NIL, len: 0 }
    }

    /// The number of tasks in the tree.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    fn node(&self, n: u32) -> &Node<T> {
        &self.nodes[n as usize]
    }

    fn node_mut(&mut self, n: u32) -> &mut Node<T> {
        &mut self.nodes[n as usize]
    }

    fn key(&self, n: u32) -> Key {
        let node = self.node(n);
        (node.entity.deadline, node.seq)
    }

    fn height(&self, n: u32) -> u8 {
        if n == NIL { 0 } else { self.node(n).height }
    }

    /// The lowest virtual run time in the subtree of `n`, with its order of arrival.
    fn min(&self, n: u32) -> Option<(u64, u64)> {
        (n != NIL).then(|| self.node(n).min)
    }

    /// The lowest virtual run time of the tree.
    pub(crate) fn min_vruntime(&self) -> Option<u64> {
        self.min(self.root).map(|(v, _)| v)
    }

    /// Computes the height and the minimum of `n` from its children, as the callback of the
    /// augmented tree of Linux does.
    fn update(&mut self, n: u32) {
        let (l, r) = (self.node(n).left, self.node(n).right);
        let height = 1 + self.height(l).max(self.height(r));
        let own = (self.node(n).entity.vruntime, self.node(n).seq);
        let min = [self.min(l), self.min(r)].into_iter().flatten().fold(own, Ord::min);
        let node = self.node_mut(n);
        node.height = height;
        node.min = min;
    }

    fn rotate_right(&mut self, n: u32) -> u32 {
        let l = self.node(n).left;
        self.node_mut(n).left = self.node(l).right;
        self.update(n);
        self.node_mut(l).right = n;
        self.update(l);
        l
    }

    fn rotate_left(&mut self, n: u32) -> u32 {
        let r = self.node(n).right;
        self.node_mut(n).right = self.node(r).left;
        self.update(n);
        self.node_mut(r).left = n;
        self.update(r);
        r
    }

    /// Updates `n` and rotates its subtree if the heights of the children differ by more than
    /// one. Gives the new root of the subtree.
    fn rebalance(&mut self, n: u32) -> u32 {
        self.update(n);
        let (l, r) = (self.node(n).left, self.node(n).right);
        let (hl, hr) = (self.height(l), self.height(r));
        if hl > hr + 1 {
            if self.height(self.node(l).left) < self.height(self.node(l).right) {
                let l = self.rotate_left(l);
                self.node_mut(n).left = l;
            }
            return self.rotate_right(n);
        }
        if hr > hl + 1 {
            if self.height(self.node(r).right) < self.height(self.node(r).left) {
                let r = self.rotate_right(r);
                self.node_mut(n).right = r;
            }
            return self.rotate_left(n);
        }
        n
    }

    fn insert_at(&mut self, root: u32, n: u32) -> u32 {
        if root == NIL {
            return n;
        }
        if self.key(n) < self.key(root) {
            let l = self.insert_at(self.node(root).left, n);
            self.node_mut(root).left = l;
        } else {
            let r = self.insert_at(self.node(root).right, n);
            self.node_mut(root).right = r;
        }
        self.rebalance(root)
    }

    /// Adds a task with the order of arrival `seq`.
    pub(crate) fn insert(&mut self, task: T, entity: Entity, seq: u64) {
        let node = Node {
            task: Some(task),
            entity,
            seq,
            left: NIL,
            right: NIL,
            height: 1,
            min: (entity.vruntime, seq),
        };
        let n = match self.free.pop() {
            Some(n) => {
                *self.node_mut(n) = node;
                n
            }
            None => {
                self.nodes.push(node);
                (self.nodes.len() - 1) as u32
            }
        };
        self.root = self.insert_at(self.root, n);
        self.len += 1;
    }

    /// Removes the first node of the subtree of `root`. Gives the new root of the subtree and the
    /// removed node.
    fn remove_first(&mut self, root: u32) -> (u32, u32) {
        let l = self.node(root).left;
        if l == NIL {
            return (self.node(root).right, root);
        }
        let (l, first) = self.remove_first(l);
        self.node_mut(root).left = l;
        (self.rebalance(root), first)
    }

    /// Removes the node with `key` from the subtree of `root`. Gives the new root of the subtree.
    fn remove_at(&mut self, root: u32, key: Key) -> u32 {
        let (l, r) = (self.node(root).left, self.node(root).right);
        match key.cmp(&self.key(root)) {
            core::cmp::Ordering::Less => {
                let l = self.remove_at(l, key);
                self.node_mut(root).left = l;
                self.rebalance(root)
            }
            core::cmp::Ordering::Greater => {
                let r = self.remove_at(r, key);
                self.node_mut(root).right = r;
                self.rebalance(root)
            }
            core::cmp::Ordering::Equal if l == NIL => r,
            core::cmp::Ordering::Equal if r == NIL => l,
            core::cmp::Ordering::Equal => {
                // The next node takes the place of the removed node.
                let (r, next) = self.remove_first(r);
                let node = self.node_mut(next);
                node.left = l;
                node.right = r;
                self.rebalance(next)
            }
        }
    }

    /// Removes the node `n`, and gives its task and entity.
    fn remove(&mut self, n: u32) -> Option<(T, Entity)> {
        self.root = self.remove_at(self.root, self.key(n));
        self.len -= 1;
        self.free.push(n);
        let node = self.node_mut(n);
        Some((node.task.take()?, node.entity))
    }

    /// The node of the eligible task with the earliest deadline, as `pick_eevdf` of Linux finds
    /// it. `eligible` tells if a virtual run time is eligible. If the subtree of a node has an
    /// eligible task, the minimum of the subtree is eligible. So the search goes to the left
    /// child if its subtree has an eligible task, takes the node if it is eligible, and else goes
    /// to the right child.
    fn find_eligible(&self, eligible: impl Fn(u64) -> bool) -> Option<u32> {
        let mut n = self.root;
        if !self.min(n).is_some_and(|(v, _)| eligible(v)) {
            return None;
        }
        while n != NIL {
            let l = self.node(n).left;
            if self.min(l).is_some_and(|(v, _)| eligible(v)) {
                n = l;
            } else if eligible(self.node(n).entity.vruntime) {
                return Some(n);
            } else {
                n = self.node(n).right;
            }
        }
        None
    }

    /// The node with the lowest virtual run time, and of those the node that came first.
    fn find_lowest(&self) -> Option<u32> {
        let target = self.min(self.root)?;
        let mut n = self.root;
        loop {
            let node = self.node(n);
            if self.min(node.left) == Some(target) {
                n = node.left;
            } else if (node.entity.vruntime, node.seq) == target {
                return Some(n);
            } else {
                n = node.right;
            }
        }
    }

    /// Removes the eligible task with the earliest deadline. If no task is eligible, removes the
    /// task with the lowest virtual run time.
    pub(crate) fn pick(&mut self, eligible: impl Fn(u64) -> bool) -> Option<(T, Entity)> {
        let n = self.find_eligible(eligible).or_else(|| self.find_lowest())?;
        self.remove(n)
    }

    /// Removes the task with the latest deadline for which `ok` gives `true`. The search goes
    /// through the tree from the last node, so it can take O(n) time.
    pub(crate) fn remove_last(
        &mut self,
        mut ok: impl FnMut(&T, &Entity) -> bool,
    ) -> Option<(T, Entity)> {
        let mut stack = Vec::new();
        let mut n = self.root;
        let found = loop {
            while n != NIL {
                stack.push(n);
                n = self.node(n).right;
            }
            let Some(top) = stack.pop() else { break None };
            let node = self.node(top);
            if node.task.as_ref().is_some_and(|t| ok(t, &node.entity)) {
                break Some(top);
            }
            n = node.left;
        };
        self.remove(found?)
    }

    /// Checks the order, the heights and the minimums of the tree, for the tests. Gives the
    /// height of the tree.
    #[cfg(test)]
    pub(crate) fn check(&self) -> u8 {
        fn walk<T>(t: &Tree<T>, n: u32, count: &mut usize) -> u8 {
            if n == NIL {
                return 0;
            }
            *count += 1;
            let node = t.node(n);
            if node.left != NIL {
                assert!(t.key(node.left) < t.key(n));
            }
            if node.right != NIL {
                assert!(t.key(node.right) > t.key(n));
            }
            let (hl, hr) = (walk(t, node.left, count), walk(t, node.right, count));
            assert!(hl.abs_diff(hr) <= 1, "the tree is not balanced");
            assert_eq!(node.height, 1 + hl.max(hr));
            let own = (node.entity.vruntime, node.seq);
            let min =
                [t.min(node.left), t.min(node.right)].into_iter().flatten().fold(own, Ord::min);
            assert_eq!(node.min, min);
            node.height
        }
        let mut count = 0;
        let height = walk(self, self.root, &mut count);
        assert_eq!(count, self.len);
        height
    }
}

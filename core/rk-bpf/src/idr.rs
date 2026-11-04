//! The tables of the IDs of the maps, the programs and the links: `map_idr`, `prog_idr` and
//! `link_idr` in kernel/bpf/syscall.c of Linux.
//!
//! A table keeps a weak reference to each object, so an ID does not keep its object. An object
//! takes its ID out of the table when it is dropped, as `bpf_map_free_id`, `bpf_prog_free_id`
//! and `bpf_link_free_id` of Linux.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use rk_frame::sync::SpinLock;

/// The largest ID, `INT_MAX` of Linux.
pub const ID_MAX: u32 = i32::MAX as u32;

struct Inner<T> {
    /// The objects of the IDs. A reserved ID has a `Weak` that cannot be upgraded.
    ids: BTreeMap<u32, Weak<T>>,
    /// The first ID to try for the next object, as `idr_alloc_cyclic`.
    next: u32,
}

/// A table of IDs, `struct idr` with its spin lock.
pub struct Idr<T> {
    inner: SpinLock<Inner<T>>,
}

impl<T> Idr<T> {
    /// Makes an empty table.
    pub const fn new() -> Self {
        Self { inner: SpinLock::new(Inner { ids: BTreeMap::new(), next: 1 }) }
    }

    /// Reserves a new ID from 1 to `ID_MAX`, as `idr_alloc_cyclic`. The next ID comes after the
    /// last one, and goes back to 1 after `ID_MAX`. `None` tells that all IDs are used.
    pub fn alloc(&self) -> Option<u32> {
        let mut g = self.inner.lock();
        let start = g.next;
        let mut id = start;
        loop {
            if !g.ids.contains_key(&id) {
                g.ids.insert(id, Weak::new());
                g.next = if id == ID_MAX { 1 } else { id + 1 };
                return Some(id);
            }
            id = if id == ID_MAX { 1 } else { id + 1 };
            if id == start {
                return None;
            }
        }
    }

    /// Puts `obj` at the reserved ID `id`, as `idr_replace`. After this the ID finds the
    /// object.
    pub fn publish(&self, id: u32, obj: &Arc<T>) {
        if let Some(slot) = self.inner.lock().ids.get_mut(&id) {
            *slot = Arc::downgrade(obj);
        }
    }

    /// Takes `id` out of the table, as `idr_remove`.
    pub fn remove(&self, id: u32) {
        if id != 0 {
            self.inner.lock().ids.remove(&id);
        }
    }

    /// The object of `id`, as `idr_find` and `inc_not_zero`. An ID that is reserved or of an
    /// object that is dropped now gives `None`.
    pub fn find(&self, id: u32) -> Option<Arc<T>> {
        let weak = self.inner.lock().ids.get(&id)?.clone();
        // Upgrade the reference after the lock is free: the drop of the last reference takes
        // the lock again.
        weak.upgrade()
    }

    /// The first ID after `start` that has an object, as `idr_get_next`.
    pub fn get_next(&self, start: u32) -> Option<u32> {
        let g = self.inner.lock();
        let from = start.checked_add(1)?;
        g.ids.range(from..).find(|(_, w)| w.strong_count() != 0).map(|(&id, _)| id)
    }
}

impl<T> Default for Idr<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_id_finds_its_object_until_the_object_is_dropped() {
        let idr: Idr<u8> = Idr::new();
        let a = idr.alloc().unwrap();
        let b = idr.alloc().unwrap();
        assert_eq!((a, b), (1, 2));
        let obj = Arc::new(7u8);
        assert!(idr.find(a).is_none());
        idr.publish(a, &obj);
        assert_eq!(idr.find(a).as_deref(), Some(&7));
        assert_eq!(idr.get_next(0), Some(1));
        // A reserved ID is not in the list.
        assert_eq!(idr.get_next(1), None);
        drop(obj);
        assert!(idr.find(a).is_none());
        idr.remove(a);
        // The IDs do not start again at the first free ID.
        assert_eq!(idr.alloc(), Some(3));
    }
}

//! The swap entries of the page tables, as `swp_entry_t` of Linux.
//!
//! A page of an address space that went to a swap area has a [`SwapSlot`] in its page table
//! instead of a frame. The `Arc` of the slot counts the page tables that have the entry, as the
//! `swap_map` count of Linux: `fork` copies the entry, and an unmap drops it. The page of the swap
//! area becomes free when the last entry goes. rk-vfs has the swap areas, and it gives the I/O and
//! the free of the pages through the hooks of [`set_swap_ops`].

use super::frame::Frame;
use crate::addr::PAGE_SIZE;
use crate::sync::Once;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// The calls of the swap areas.
#[derive(Clone, Copy)]
pub struct SwapOps {
    /// Gives a free page of a swap area for the memory cgroup, or `None`.
    pub alloc: fn(u32) -> Option<u64>,
    /// Makes the page of the entry free, and takes it from the swap of the memory cgroup.
    pub free: fn(u64, u32),
    /// Writes a page to the entry.
    pub write: fn(u64, &[u8]) -> Result<(), ()>,
    /// Reads the page of the entry.
    pub read: fn(u64, &mut [u8]) -> Result<(), ()>,
    /// Counts a page of the memory cgroup that went to swap (true) or that came back (false).
    pub count: fn(u32, bool),
}

static OPS: Once<SwapOps> = Once::new();

/// Sets the calls of the swap areas.
pub fn set_swap_ops(ops: SwapOps) {
    OPS.call_once(|| ops);
}

/// The pages that went to swap and that came back, as `pswpout` and `pswpin` of
/// `/proc/vmstat`.
static PSWPOUT: AtomicU64 = AtomicU64::new(0);
static PSWPIN: AtomicU64 = AtomicU64::new(0);

/// The pages that went to swap and that came back since the boot, as `pswpout` and `pswpin`.
pub fn swap_counts() -> (u64, u64) {
    (PSWPOUT.load(Ordering::Relaxed), PSWPIN.load(Ordering::Relaxed))
}

/// The swap entries that exist, so that a fault looks for an entry only when there can be one.
static SLOTS: AtomicUsize = AtomicUsize::new(0);

/// Tells if a swap entry exists.
pub fn swap_in_use() -> bool {
    SLOTS.load(Ordering::Acquire) != 0
}

/// A page of a swap area that holds the data of a page of an address space. The page of the area
/// becomes free when the value is dropped.
#[derive(Debug)]
pub struct SwapSlot {
    entry: u64,
    memcg: u32,
}

impl SwapSlot {
    /// Takes a free page of a swap area for the memory cgroup `memcg`, as `folio_alloc_swap` of
    /// Linux. Gives `None` if no area has a free page.
    pub fn alloc(memcg: u32) -> Option<Self> {
        let ops = OPS.get()?;
        let entry = (ops.alloc)(memcg)?;
        SLOTS.fetch_add(1, Ordering::AcqRel);
        Some(Self { entry, memcg })
    }

    /// The swap entry, with the type of the area and the page in it.
    pub fn entry(&self) -> u64 {
        self.entry
    }

    /// Writes the data of `frame` to the page of the area, as `swap_writepage` of Linux.
    ///
    /// # Errors
    ///
    /// Gives `Err` if the disk gives an error.
    pub fn write(&self, frame: &Frame) -> Result<(), ()> {
        let ops = OPS.get().ok_or(())?;
        let mut buf = alloc::vec![0u8; PAGE_SIZE];
        frame.read_bytes(0, &mut buf);
        (ops.write)(self.entry, &buf)?;
        PSWPOUT.fetch_add(1, Ordering::Relaxed);
        (ops.count)(self.memcg, true);
        Ok(())
    }

    /// Reads the page of the area to `frame`, as `swap_read_folio` of Linux.
    ///
    /// # Errors
    ///
    /// Gives `Err` if the disk gives an error.
    pub fn read(&self, frame: &Frame) -> Result<(), ()> {
        let ops = OPS.get().ok_or(())?;
        let mut buf: Vec<u8> = alloc::vec![0u8; PAGE_SIZE];
        (ops.read)(self.entry, &mut buf)?;
        frame.write_bytes(0, &buf);
        PSWPIN.fetch_add(1, Ordering::Relaxed);
        (ops.count)(self.memcg, false);
        Ok(())
    }
}

impl Drop for SwapSlot {
    fn drop(&mut self) {
        if let Some(ops) = OPS.get() {
            (ops.free)(self.entry, self.memcg);
        }
        SLOTS.fetch_sub(1, Ordering::AcqRel);
    }
}

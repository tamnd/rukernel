//! The kernel heap, the global allocator of the kernel.
//!
//! The safe kernel crates use `alloc`: `Box`, `Vec`, `BTreeMap` and `Arc`. This module gives the
//! memory for them. A small object comes from a slab of its size class. A slab is one frame in the
//! direct map, so it costs no virtual address space. A large object gets its own pages in the heap
//! range of the vmalloc area, with a guard page after it.
//!
//! The slab pages stay in the heap after their objects are freed. The pages of a large object go
//! back to the frame allocator, but the virtual addresses are not used again. The heap range is 4
//! TiB, so this is not a problem before the vmalloc allocator of R4 replaces this code.

use super::frame::{alloc_frame_phys, free_frame_phys};
use crate::addr::PAGE_SIZE;
use crate::arch::imp::paging;
use crate::sync::SpinLock;
use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// The size classes of the slabs. Each class is a power of two, so each object is aligned to its
/// size.
const CLASSES: [usize; 8] = [16, 32, 64, 128, 256, 512, 1024, 2048];
const LARGEST_CLASS: usize = CLASSES[CLASSES.len() - 1];

/// The head of the free list of each class. A free object holds the address of the next free
/// object in its first word. The value 0 ends the list.
static FREE: SpinLock<[usize; CLASSES.len()]> = SpinLock::new([0; CLASSES.len()]);

/// The next free address in the heap range.
static NEXT_LARGE: AtomicUsize = AtomicUsize::new(paging::HEAP_START);

/// The bytes that the heap gave and that are not freed yet, with the round up of each size class.
static IN_USE: AtomicU64 = AtomicU64::new(0);

/// The heap counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeapStats {
    /// The bytes in use now.
    pub in_use: u64,
}

/// Gives the heap counters.
pub fn heap_stats() -> HeapStats {
    HeapStats { in_use: IN_USE.load(Ordering::Relaxed) }
}

/// The size class of an object, or `None` for a large object.
fn class(layout: Layout) -> Option<usize> {
    let size = layout.size().max(layout.align());
    CLASSES.iter().position(|&c| c >= size)
}

/// Turns interrupts off while it lives, and then turns them back on if they were on. The heap
/// lock is held with interrupts off, so an interrupt handler can allocate.
struct IrqOff(bool);

impl IrqOff {
    fn new() -> Self {
        let on = crate::irq::enabled();
        crate::irq::disable();
        Self(on)
    }
}

impl Drop for IrqOff {
    fn drop(&mut self) {
        if self.0 {
            crate::irq::enable();
        }
    }
}

fn alloc_small(index: usize) -> *mut u8 {
    let _irq = IrqOff::new();
    let mut free = FREE.lock();
    if free[index] == 0 {
        let Some(phys) = alloc_frame_phys() else { return core::ptr::null_mut() };
        let page = paging::phys_to_virt(phys);
        let size = CLASSES[index];
        // Put the objects of the new slab on the list, the first object at the head.
        for object in (page..page + PAGE_SIZE).step_by(size).rev() {
            // SAFETY: the frame is new, so no other owner has it. The direct map maps it writable
            // at `page`, and `object` is in the frame and aligned to 16 bytes.
            unsafe { (object as *mut usize).write(free[index]) };
            free[index] = object;
        }
    }
    let object = free[index];
    // SAFETY: `object` is on the free list, so it is a free object of this class in a slab, and
    // its first word holds the next free object.
    free[index] = unsafe { (object as *const usize).read() };
    IN_USE.fetch_add(CLASSES[index] as u64, Ordering::Relaxed);
    object as *mut u8
}

fn dealloc_small(ptr: *mut u8, index: usize) {
    let _irq = IrqOff::new();
    let mut free = FREE.lock();
    // SAFETY: the caller gives an object of this class that `alloc_small` gave and that is not
    // in use now, so the heap owns it again and can write its first word.
    unsafe { ptr.cast::<usize>().write(free[index]) };
    free[index] = ptr as usize;
    IN_USE.fetch_sub(CLASSES[index] as u64, Ordering::Relaxed);
}

fn alloc_large(layout: Layout) -> *mut u8 {
    if layout.align() > PAGE_SIZE {
        return core::ptr::null_mut();
    }
    let pages = layout.size().div_ceil(PAGE_SIZE);
    // The page after the object is a guard page, so an overrun is a page fault.
    let start = NEXT_LARGE.fetch_add((pages + 1) * PAGE_SIZE, Ordering::Relaxed);
    if start + (pages + 1) * PAGE_SIZE > paging::HEAP_END {
        return core::ptr::null_mut();
    }
    for i in 0..pages {
        let virt = start + i * PAGE_SIZE;
        let mapped = alloc_frame_phys().map(|phys| (phys, paging::map_page(virt, phys, true)));
        match mapped {
            Some((_, Ok(()))) => {}
            Some((phys, Err(()))) => {
                free_frame_phys(phys);
                unmap_large(start, i);
                return core::ptr::null_mut();
            }
            None => {
                unmap_large(start, i);
                return core::ptr::null_mut();
            }
        }
    }
    IN_USE.fetch_add((pages * PAGE_SIZE) as u64, Ordering::Relaxed);
    start as *mut u8
}

/// Removes the first `pages` pages at `start` and gives their frames back. The other CPUs drop
/// the TLB entries of the range in one request, not one for each page.
fn unmap_large(start: usize, pages: usize) {
    paging::unmap_pages(start, pages, &mut free_frame_phys);
}

/// The global allocator of the kernel.
struct Heap;

// SAFETY: `alloc` gives a block of at least `layout.size()` bytes at an address aligned to
// `layout.align()`, or null. A small block is an object of a size class that is not smaller than
// the size and the alignment. A large block is whole pages. No two live blocks overlap, because a
// block is on no free list and in no other block while it is in use.
unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match class(layout) {
            Some(index) => alloc_small(index),
            None => alloc_large(layout),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        match class(layout) {
            Some(index) => dealloc_small(ptr, index),
            None => {
                let pages = layout.size().div_ceil(PAGE_SIZE);
                unmap_large(ptr as usize, pages);
                IN_USE.fetch_sub((pages * PAGE_SIZE) as u64, Ordering::Relaxed);
            }
        }
    }
}

#[global_allocator]
static HEAP: Heap = Heap;

const _: () = assert!(LARGEST_CLASS < PAGE_SIZE);

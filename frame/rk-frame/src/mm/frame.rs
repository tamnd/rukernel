//! The frame allocator and the owned memory types.

use super::bitmap::FrameBitmap;
use crate::addr::{PAGE_SIZE, PhysAddr, VirtAddr};
use crate::arch::imp::paging;
use crate::boot::{BootInfo, MemoryKind};
use crate::sync::SpinLock;
use core::sync::atomic::{AtomicUsize, Ordering};

/// The allocator manages physical memory below this address. 64 GiB needs a bitmap of 2 MiB.
const MAX_PHYS: u64 = 64 << 30;
const WORDS: usize = (MAX_PHYS / PAGE_SIZE as u64 / 64) as usize;

/// The frames below 1 MiB stay reserved. The firmware and the real mode code use them.
const LOW_RESERVED: u64 = 1 << 20;

static FRAMES: SpinLock<FrameBitmap<WORDS>> = SpinLock::new(FrameBitmap::new());

/// Adds the usable memory of the memory map to the allocator, and reserves the kernel image and
/// the initramfs. The boot CPU calls this one time, before the kernel page tables exist.
pub(crate) fn init(info: &BootInfo, kernel_end_phys: u64) {
    let mut frames = FRAMES.lock();
    for r in info.memory().iter().filter(|r| r.kind == MemoryKind::Usable) {
        // Only whole frames are usable.
        let start = r.start.get().div_ceil(PAGE_SIZE as u64);
        let end = (r.start.get() + r.len) / PAGE_SIZE as u64;
        if end > start {
            frames.add_free(start as usize, end as usize);
        }
    }
    let reserve = |frames: &mut FrameBitmap<WORDS>, start: u64, end: u64| {
        let s = start / PAGE_SIZE as u64;
        let e = end.div_ceil(PAGE_SIZE as u64);
        frames.reserve(s as usize, e as usize);
    };
    reserve(&mut frames, 0, LOW_RESERVED.max(kernel_end_phys));
    if let Some((start, len)) = info.initrd() {
        reserve(&mut frames, start.get(), start.get() + len);
    }
}

/// Takes one frame for a page table, fills it with zeros and gives its physical address. A page
/// table frame of the kernel is never given back.
pub(crate) fn alloc_table_frame() -> Option<u64> {
    let frame = FRAMES.lock().alloc()?;
    let phys = (frame * PAGE_SIZE) as u64;
    let virt = paging::phys_to_virt(phys) as *mut u8;
    // SAFETY: the allocator gave this frame to no other owner, and `phys_to_virt` gives an
    // address where it is mapped and writable.
    unsafe { core::ptr::write_bytes(virt, 0, PAGE_SIZE) };
    Some(phys)
}

/// The number of frames that the allocator manages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameStats {
    /// All frames that the allocator manages.
    pub total: usize,
    /// The frames that are free now.
    pub free: usize,
}

/// Gives the frame counts.
pub fn frame_stats() -> FrameStats {
    let frames = FRAMES.lock();
    FrameStats { total: frames.total(), free: frames.free_count() }
}

/// One physical page of 4 KiB. The value owns the page: no other `Frame` or `Mapping` has the
/// same page. The page goes back to the allocator when the value is dropped.
#[derive(Debug)]
pub struct Frame {
    phys: u64,
}

/// Takes a free frame. The contents of the frame are not defined.
pub fn alloc_frame() -> Option<Frame> {
    let frame = FRAMES.lock().alloc()?;
    Some(Frame { phys: (frame * PAGE_SIZE) as u64 })
}

impl Frame {
    /// The number of 8 byte words in a frame.
    pub const WORDS: usize = PAGE_SIZE / 8;

    /// The physical address of the frame.
    pub fn addr(&self) -> PhysAddr {
        PhysAddr::new(self.phys)
    }

    fn word_ptr(&self, index: usize) -> *mut u64 {
        assert!(index < Self::WORDS, "word {index} is outside the frame");
        (paging::phys_to_virt(self.phys) as *mut u64).wrapping_add(index)
    }

    /// Reads the word `index` of the frame.
    ///
    /// # Panics
    ///
    /// If `index` is not less than `Frame::WORDS`.
    pub fn read_u64(&self, index: usize) -> u64 {
        // SAFETY: this value owns the frame, the direct map maps it, and the index is inside it. A
        // `Mapping` of the frame would own this value, so no other path writes the frame now.
        unsafe { self.word_ptr(index).read_volatile() }
    }

    /// Writes the word `index` of the frame.
    ///
    /// # Panics
    ///
    /// If `index` is not less than `Frame::WORDS`.
    pub fn write_u64(&mut self, index: usize, value: u64) {
        // SAFETY: as for `read_u64`. `&mut self` makes sure that there is one writer.
        unsafe { self.word_ptr(index).write_volatile(value) };
    }

    /// Fills the frame with zeros.
    pub fn zero(&mut self) {
        // SAFETY: as for `write_u64`, for all of the frame.
        unsafe { core::ptr::write_bytes(self.word_ptr(0).cast::<u8>(), 0, PAGE_SIZE) };
    }
}

impl Drop for Frame {
    fn drop(&mut self) {
        FRAMES.lock().free(self.phys as usize / PAGE_SIZE);
    }
}

/// The next free address in the vmalloc range. R0 does not use an address two times.
static NEXT_VMALLOC: AtomicUsize = AtomicUsize::new(paging::VMALLOC_START);

/// A frame that is mapped at a kernel virtual address in the vmalloc range. The mapping is removed
/// when the value is dropped, and then the frame goes back to the allocator.
#[derive(Debug)]
pub struct Mapping {
    virt: usize,
    frame: Option<Frame>,
}

/// Maps a frame at a new kernel virtual address. It gives the frame back if no page table frame
/// is free.
pub fn vmap(frame: Frame) -> Result<Mapping, Frame> {
    // Each mapping has a guard page after it, so an overrun is a page fault.
    let virt = NEXT_VMALLOC.fetch_add(2 * PAGE_SIZE, Ordering::Relaxed);
    if virt >= paging::VMALLOC_END || paging::map_page(virt, frame.phys, true).is_err() {
        return Err(frame);
    }
    Ok(Mapping { virt, frame: Some(frame) })
}

/// Maps one page of device registers at a new kernel virtual address and gives the address. The
/// mapping stays for all of the run time.
#[cfg(target_arch = "x86_64")]
pub(crate) fn vmap_mmio(phys: u64) -> Option<usize> {
    let virt = NEXT_VMALLOC.fetch_add(2 * PAGE_SIZE, Ordering::Relaxed);
    if virt >= paging::VMALLOC_END {
        return None;
    }
    paging::map_mmio_page(virt, phys).ok()?;
    Some(virt)
}

impl Mapping {
    /// The kernel virtual address of the mapping.
    pub fn addr(&self) -> VirtAddr {
        VirtAddr::new(self.virt)
    }

    fn word_ptr(&self, index: usize) -> *mut u64 {
        assert!(index < Frame::WORDS, "word {index} is outside the mapping");
        (self.virt as *mut u64).wrapping_add(index)
    }

    /// Reads the word `index` through the mapping.
    ///
    /// # Panics
    ///
    /// If `index` is not less than `Frame::WORDS`.
    pub fn read_u64(&self, index: usize) -> u64 {
        // SAFETY: this value owns the frame and the virtual address, and the page tables map one
        // to the other while this value exists.
        unsafe { self.word_ptr(index).read_volatile() }
    }

    /// Writes the word `index` through the mapping.
    ///
    /// # Panics
    ///
    /// If `index` is not less than `Frame::WORDS`.
    pub fn write_u64(&mut self, index: usize, value: u64) {
        // SAFETY: as for `read_u64`. `&mut self` makes sure that there is one writer.
        unsafe { self.word_ptr(index).write_volatile(value) };
    }

    /// The frame, read through the direct map.
    pub fn frame(&self) -> &Frame {
        self.frame.as_ref().unwrap_or_else(|| unreachable!())
    }

    /// Removes the mapping and gives back the frame.
    pub fn unmap(mut self) -> Frame {
        paging::unmap_page(self.virt);
        self.frame.take().unwrap_or_else(|| unreachable!())
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        if self.frame.is_some() {
            paging::unmap_page(self.virt);
        }
    }
}

/// What the page tables give for one virtual address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageInfo {
    /// The physical address that the virtual address maps to.
    pub phys: PhysAddr,
    /// A write is allowed.
    pub writable: bool,
    /// An instruction fetch is allowed.
    pub executable: bool,
    /// User mode can use the page.
    pub user: bool,
}

/// Gives the mapping of a kernel virtual address, if the page tables have one.
pub fn query(addr: VirtAddr) -> Option<PageInfo> {
    paging::query(addr.get())
}

/// Gives the physical address of a kernel virtual address, if the page tables map it.
pub fn translate(addr: VirtAddr) -> Option<PhysAddr> {
    query(addr).map(|i| i.phys)
}

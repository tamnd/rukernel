//! The frame allocator and the owned memory types.

use super::bitmap::FrameBitmap;
use crate::addr::{PAGE_SIZE, PhysAddr, VirtAddr};
use crate::arch::imp::{mem, paging};
use crate::boot::{BootInfo, MemoryKind};
use crate::sync::{Once, SpinLock};
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicUsize, Ordering};

/// The allocator manages physical memory below this address. 64 GiB needs a bitmap of 2 MiB.
const MAX_PHYS: u64 = 64 << 30;
const WORDS: usize = (MAX_PHYS / PAGE_SIZE as u64 / 64) as usize;

/// The frames below 1 MiB stay reserved. The firmware and the real mode code use them.
const LOW_RESERVED: u64 = 1 << 20;

static FRAMES: SpinLock<FrameBitmap<WORDS>> = SpinLock::new(FrameBitmap::new());

/// Adds the usable memory of the memory map to the allocator, and reserves the kernel image at the
/// physical addresses `kernel` and the initramfs. The boot CPU calls this one time, before the
/// kernel page tables exist.
pub(crate) fn init(info: &BootInfo, kernel: core::ops::Range<u64>) {
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
    reserve(&mut frames, 0, LOW_RESERVED);
    reserve(&mut frames, kernel.start, kernel.end);
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

/// Takes one frame and gives its physical address. The heap uses this function. It owns the
/// frame until it gives it back with `free_frame_phys`.
pub(crate) fn alloc_frame_phys() -> Option<u64> {
    let frame = FRAMES.lock().alloc()?;
    Some((frame * PAGE_SIZE) as u64)
}

/// Gives back a frame that `alloc_frame_phys` gave.
pub(crate) fn free_frame_phys(phys: u64) {
    FRAMES.lock().free(phys as usize / PAGE_SIZE);
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
    /// The memory cgroup that the page is charged to, or 0.
    memcg: u32,
    /// The frame is a part of a [`HugeRun`] of the pool of huge pages. It goes back to the pool
    /// with the other frames of the run, and not to the allocator.
    pooled: bool,
}

/// The function that removes the charge of a frame from its memory cgroup.
static UNCHARGE: Once<fn(u32)> = Once::new();

/// Sets the function that removes the charge of a frame from its memory cgroup, when a frame with
/// a cgroup goes back to the allocator. Only the first call has an effect.
pub fn set_uncharge_hook(f: fn(u32)) {
    UNCHARGE.call_once(|| f);
}

/// Takes a free frame. The contents of the frame are not defined.
pub fn alloc_frame() -> Option<Frame> {
    let frame = FRAMES.lock().alloc()?;
    Some(Frame { phys: (frame * PAGE_SIZE) as u64, memcg: 0, pooled: false })
}

/// Takes a free frame and fills it with zeros.
pub fn alloc_zeroed_frame() -> Option<Frame> {
    let mut frame = alloc_frame()?;
    frame.zero();
    Some(frame)
}

/// The number of 4 KiB frames in a 2 MiB huge page.
pub const HUGE_FRAMES: usize = 512;

/// Takes `HUGE_FRAMES` zeroed frames in a row. The first frame is 2 MiB aligned, so the frames can
/// be mapped as one huge page. Gives `None` if no such run is free.
pub fn alloc_huge_frames() -> Option<alloc::vec::Vec<Frame>> {
    let first = FRAMES.lock().alloc_run(HUGE_FRAMES.trailing_zeros())?;
    let frames = (first..first + HUGE_FRAMES).map(|f| {
        let mut frame = Frame { phys: (f * PAGE_SIZE) as u64, memcg: 0, pooled: false };
        frame.zero();
        frame
    });
    Some(frames.collect())
}

/// The number of runs of `HUGE_FRAMES` frames below `MAX_PHYS`.
const RUNS: usize = (MAX_PHYS / PAGE_SIZE as u64) as usize / HUGE_FRAMES;

/// The number of frames of each pooled run that are back, by the index of the run. A run goes
/// back to the pool when all its frames are back.
static RETURNED: [AtomicU16; RUNS] = [const { AtomicU16::new(0) }; RUNS];

/// The function that takes a run back into the pool of huge pages.
static HUGE_RETURN: Once<fn(HugeRun)> = Once::new();

/// Sets the function that takes a [`HugeRun`] back when the last frame of its
/// [`HugeRun::into_frames`] is dropped. Only the first call has an effect. Without a function,
/// the run goes back to the allocator.
///
/// The function runs where the last frame is dropped, which can be with locks of the caller held.
/// It must not drop a frame while it holds a lock that the drop of a frame can take.
pub fn set_huge_return_hook(f: fn(HugeRun)) {
    HUGE_RETURN.call_once(|| f);
}

/// A run of `HUGE_FRAMES` frames that is 2 MiB aligned, for the pool of huge pages of hugetlbfs.
/// The run goes back to the allocator when the value is dropped. This is the `struct folio` of a
/// huge page of Linux, in mm/hugetlb.c.
#[derive(Debug)]
pub struct HugeRun {
    /// The number of the first frame.
    first: usize,
}

impl HugeRun {
    /// Takes a free run. The contents of the frames are not defined. Gives `None` if no run is
    /// free.
    pub fn alloc() -> Option<Self> {
        let first = FRAMES.lock().alloc_run(HUGE_FRAMES.trailing_zeros())?;
        Some(Self { first })
    }

    /// The physical address of the first frame.
    pub fn addr(&self) -> PhysAddr {
        PhysAddr::new((self.first * PAGE_SIZE) as u64)
    }

    /// Fills the frames with zeros and gives them. The run comes back through the function of
    /// [`set_huge_return_hook`] when each of the frames is dropped.
    pub fn into_frames(self) -> alloc::vec::Vec<Frame> {
        let first = self.first;
        core::mem::forget(self);
        RETURNED[first / HUGE_FRAMES].store(0, Ordering::Relaxed);
        let frames = (first..first + HUGE_FRAMES).map(|f| {
            let mut frame = Frame { phys: (f * PAGE_SIZE) as u64, memcg: 0, pooled: true };
            frame.zero();
            frame
        });
        frames.collect()
    }
}

impl Drop for HugeRun {
    fn drop(&mut self) {
        let mut frames = FRAMES.lock();
        for f in self.first..self.first + HUGE_FRAMES {
            frames.free(f);
        }
    }
}

impl Frame {
    /// The number of 8 byte words in a frame.
    pub const WORDS: usize = PAGE_SIZE / 8;

    /// Marks the frame as charged to the memory cgroup `memcg`. The charge goes away with the
    /// frame, through the function of `set_uncharge_hook`.
    pub fn set_memcg(&mut self, memcg: u32) {
        self.memcg = memcg;
    }

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

    /// The kernel address of the byte `offset` of the frame, for a copy of `len` bytes.
    fn byte_ptr(&self, offset: usize, len: usize) -> *mut u8 {
        assert!(offset + len <= PAGE_SIZE, "{len} bytes at {offset} are outside the frame");
        (paging::phys_to_virt(self.phys) as *mut u8).wrapping_add(offset)
    }

    /// Copies bytes from the frame at `offset` to `buf`.
    ///
    /// The frame can be mapped in user address spaces, and user code can write it at the same
    /// time. Thus the copy uses the copy of the architecture, which the compiler cannot change,
    /// and no Rust reference to the contents of a frame exists.
    ///
    /// # Panics
    ///
    /// If the bytes are not all in the frame.
    pub fn read_bytes(&self, offset: usize, buf: &mut [u8]) {
        let p = self.byte_ptr(offset, buf.len());
        // SAFETY: the frame is mapped in the direct map, and the bytes are in the frame. `buf` is
        // not in a frame that this copy writes.
        unsafe { mem::copy(buf.as_mut_ptr(), p, buf.len()) };
    }

    /// Writes `new` to the 32 bit word at `offset` if the word has the value `old`, in one atomic
    /// operation, and gives the value that the word had. User code on another CPU can change the
    /// word at the same time, as with a futex.
    ///
    /// # Panics
    ///
    /// If `offset` is not 4 byte aligned or the word is not in the frame.
    pub fn compare_exchange_u32(&self, offset: usize, old: u32, new: u32) -> u32 {
        assert!(offset.is_multiple_of(4), "the word at {offset} is not aligned");
        let p = self.byte_ptr(offset, 4).cast::<u32>();
        // SAFETY: the word is in the frame, which the direct map has, and it is aligned. The frame
        // memory is accessed only with copies and atomic operations, so no access to it is a data
        // race with this atomic operation.
        let word = unsafe { AtomicU32::from_ptr(p) };
        word.compare_exchange(old, new, Ordering::SeqCst, Ordering::SeqCst).unwrap_or_else(|v| v)
    }

    /// Reads the 16 bit word at `offset` in one access, with acquire order. A device can write
    /// the word at the same time, as the index of a virtio ring. A copy of bytes can see half of
    /// a new value.
    ///
    /// # Panics
    ///
    /// If `offset` is not 2 byte aligned or the word is not in the frame.
    pub fn load_u16(&self, offset: usize) -> u16 {
        assert!(offset.is_multiple_of(2), "the word at {offset} is not aligned");
        let p = self.byte_ptr(offset, 2).cast::<u16>();
        // SAFETY: as for `compare_exchange_u32`.
        let word = unsafe { AtomicU16::from_ptr(p) };
        word.load(Ordering::Acquire)
    }

    /// Writes the 16 bit word at `offset` in one access, with release order, so that a device
    /// that reads the word sees the old value or the new value.
    ///
    /// # Panics
    ///
    /// If `offset` is not 2 byte aligned or the word is not in the frame.
    pub fn store_u16(&self, offset: usize, value: u16) {
        assert!(offset.is_multiple_of(2), "the word at {offset} is not aligned");
        let p = self.byte_ptr(offset, 2).cast::<u16>();
        // SAFETY: as for `compare_exchange_u32`.
        let word = unsafe { AtomicU16::from_ptr(p) };
        word.store(value, Ordering::Release);
    }

    /// Copies `buf` to the frame at `offset`. A frame that is shared through an `Arc` is written
    /// through a shared reference, as the memory of a `MAP_SHARED` mapping is.
    ///
    /// # Panics
    ///
    /// If the bytes are not all in the frame.
    pub fn write_bytes(&self, offset: usize, buf: &[u8]) {
        let p = self.byte_ptr(offset, buf.len());
        // SAFETY: as for `read_bytes`. No Rust reference to the contents exists, so the write
        // cannot change a value that safe code holds.
        unsafe { mem::copy(p, buf.as_ptr(), buf.len()) };
    }

    /// Fills `len` bytes at `offset` with zeros.
    ///
    /// # Panics
    ///
    /// If the bytes are not all in the frame.
    pub fn fill_zero(&self, offset: usize, len: usize) {
        let p = self.byte_ptr(offset, len);
        // SAFETY: as for `write_bytes`.
        unsafe { mem::zero(p, len) };
    }

    /// Copies all of `other` to this frame. Copy on write uses this.
    pub fn copy_from(&self, other: &Frame) {
        let (to, from) = (self.byte_ptr(0, PAGE_SIZE), other.byte_ptr(0, PAGE_SIZE));
        if to != from {
            // SAFETY: as for `write_bytes`. Two different frames do not overlap, and a frame is
            // page aligned.
            unsafe { mem::copy_page(to, from) };
        }
    }
}

impl Drop for Frame {
    fn drop(&mut self) {
        if self.memcg != 0
            && let Some(f) = UNCHARGE.get()
        {
            f(self.memcg);
        }
        let frame = self.phys as usize / PAGE_SIZE;
        if self.pooled {
            let first = frame & !(HUGE_FRAMES - 1);
            let back = RETURNED[first / HUGE_FRAMES].fetch_add(1, Ordering::AcqRel) + 1;
            if usize::from(back) == HUGE_FRAMES {
                let run = HugeRun { first };
                if let Some(f) = HUGE_RETURN.get() {
                    f(run);
                }
            }
            return;
        }
        FRAMES.lock().free(frame);
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
    if virt >= paging::HEAP_START || paging::map_page(virt, frame.phys, true).is_err() {
        return Err(frame);
    }
    Ok(Mapping { virt, frame: Some(frame) })
}

/// Maps one page of device registers at a new kernel virtual address and gives the address. The
/// mapping stays for all of the run time.
#[cfg(target_arch = "x86_64")]
pub(crate) fn vmap_mmio(phys: u64) -> Option<usize> {
    vmap_mmio_pages(phys, 1)
}

/// Maps `pages` pages of device registers from `phys` at a new kernel virtual address and gives
/// the address. A guard page comes after the mapping. The mapping stays for all of the run time.
#[cfg(target_arch = "x86_64")]
pub(crate) fn vmap_mmio_pages(phys: u64, pages: usize) -> Option<usize> {
    let size = pages.checked_add(1)?.checked_mul(PAGE_SIZE)?;
    let virt = NEXT_VMALLOC.fetch_add(size, Ordering::Relaxed);
    if virt.checked_add(size)? > paging::HEAP_START {
        return None;
    }
    for i in 0..pages {
        paging::map_mmio_page(virt + i * PAGE_SIZE, phys + (i * PAGE_SIZE) as u64).ok()?;
    }
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

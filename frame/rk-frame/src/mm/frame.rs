//! The frame allocator and the owned memory types.

use super::bitmap::FrameBitmap;
use super::heap::IrqOff;
use super::pcp::CpuList;
use crate::addr::{PAGE_SIZE, PhysAddr, VirtAddr};
use crate::arch::imp::{mem, paging};
use crate::boot::{BootInfo, MemoryKind};
use crate::sync::{Once, SpinLock};
use core::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// The allocator manages physical memory below this address. 64 GiB needs a bitmap of 2 MiB.
const MAX_PHYS: u64 = 64 << 30;
const WORDS: usize = (MAX_PHYS / PAGE_SIZE as u64 / 64) as usize;

/// The frames below 1 MiB stay reserved. The firmware and the real mode code use them.
const LOW_RESERVED: u64 = 1 << 20;

static FRAMES: SpinLock<FrameBitmap<WORDS>> = SpinLock::new(FrameBitmap::new());

/// The free frames of the bitmap, for `frame_stats` with no lock. It changes under the lock.
static BITMAP_FREE: AtomicUsize = AtomicUsize::new(0);
/// The frames that the bitmap manages. It changes under the lock.
static BITMAP_TOTAL: AtomicUsize = AtomicUsize::new(0);

/// The lock of the bitmap. The counts of the bitmap go to `BITMAP_FREE` and `BITMAP_TOTAL` when
/// the guard is dropped.
struct Global(crate::sync::SpinLockGuard<'static, FrameBitmap<WORDS>>);

impl Global {
    fn lock() -> Self {
        Self(FRAMES.lock())
    }
}

impl core::ops::Deref for Global {
    type Target = FrameBitmap<WORDS>;
    fn deref(&self) -> &FrameBitmap<WORDS> {
        &self.0
    }
}

impl core::ops::DerefMut for Global {
    fn deref_mut(&mut self) -> &mut FrameBitmap<WORDS> {
        &mut self.0
    }
}

impl Drop for Global {
    fn drop(&mut self) {
        BITMAP_FREE.store(self.0.free_count(), Ordering::Relaxed);
        BITMAP_TOTAL.store(self.0.total(), Ordering::Relaxed);
    }
}

/// A list of a CPU holds up to this many free frames, as the `high` limit of a per-CPU pageset of
/// Linux.
const PCP_HIGH: usize = 128;
/// A list of a CPU takes or gives back this many frames at a time, as the `batch` of Linux.
const PCP_BATCH: usize = 32;

/// The free frames of one CPU, on their own cache lines.
#[repr(align(64))]
struct CpuFrames {
    list: SpinLock<CpuList<PCP_HIGH>>,
    /// The length of the list, for `frame_stats` with no lock.
    len: AtomicUsize,
}

static PCP: [CpuFrames; crate::cpu::MAX_CPUS] =
    [const { CpuFrames { list: SpinLock::new(CpuList::new()), len: AtomicUsize::new(0) } };
        crate::cpu::MAX_CPUS];

/// Takes one free frame from the list of this CPU, as `rmqueue_pcplist` of Linux. An empty list
/// takes a batch from the bitmap first. If the bitmap has no free frame, the lists of all the CPUs
/// go back to the bitmap and the allocation tries again.
fn take_frame() -> Option<usize> {
    if let Some(frame) = take_local() {
        return Some(frame);
    }
    drain_all();
    Global::lock().alloc()
}

fn take_local() -> Option<usize> {
    let _irq = IrqOff::new();
    let cpu = &PCP[crate::cpu::id()];
    let mut list = cpu.list.lock();
    let mut global = None;
    let frame = list.pop_or_refill(PCP_BATCH, || global.get_or_insert_with(Global::lock).alloc());
    drop(global);
    cpu.len.store(list.len(), Ordering::Relaxed);
    frame
}

/// Puts a free frame on the list of this CPU, as `free_unref_page` of Linux. A full list gives a
/// batch back to the bitmap first.
fn give_frame(frame: usize) {
    let _irq = IrqOff::new();
    let cpu = &PCP[crate::cpu::id()];
    let mut list = cpu.list.lock();
    let mut global = None;
    list.push_or_drain(frame, PCP_BATCH, |f| global.get_or_insert_with(Global::lock).free(f));
    drop(global);
    cpu.len.store(list.len(), Ordering::Relaxed);
}

/// Gives the frames of the lists of all the CPUs back to the bitmap, so that a run of frames can
/// form again, as `drain_all_pages` of Linux.
fn drain_all() {
    let _irq = IrqOff::new();
    for cpu in &PCP {
        if cpu.len.load(Ordering::Relaxed) == 0 {
            continue;
        }
        let mut list = cpu.list.lock();
        let mut global = Global::lock();
        list.drain(|f| global.free(f));
        cpu.len.store(0, Ordering::Relaxed);
    }
}

/// Takes `1 << order` frames in a row from the bitmap with `alloc`. If no run is free, the lists of
/// the CPUs go back to the bitmap and `alloc` tries again.
fn take_run(alloc: impl Fn(&mut FrameBitmap<WORDS>) -> Option<usize>) -> Option<usize> {
    if let Some(first) = alloc(&mut Global::lock()) {
        return Some(first);
    }
    drain_all();
    alloc(&mut Global::lock())
}

/// Adds the usable memory of the memory map to the allocator, and reserves the kernel image at the
/// physical addresses `kernel` and the initramfs. The boot CPU calls this one time, before the
/// kernel page tables exist.
pub(crate) fn init(info: &BootInfo, kernel: core::ops::Range<u64>) {
    let mut frames = Global::lock();
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
    let frame = take_frame()?;
    let phys = (frame * PAGE_SIZE) as u64;
    let virt = paging::phys_to_virt(phys) as *mut u8;
    // SAFETY: the allocator gave this frame to no other owner, and `phys_to_virt` gives an
    // address where it is mapped and writable.
    unsafe { core::ptr::write_bytes(virt, 0, PAGE_SIZE) };
    Some(phys)
}

/// Takes `1 << order` frames in a row, aligned to their size, fills them with zeros and gives the
/// physical address of the first. The tables of a device that reads memory, as the tables of the
/// GICv3 ITS, use this function. They are never given back.
#[cfg(target_arch = "aarch64")]
pub(crate) fn alloc_table_run(order: u32) -> Option<u64> {
    let first = take_run(|frames| frames.alloc_run(order))?;
    let phys = (first * PAGE_SIZE) as u64;
    let virt = paging::phys_to_virt(phys) as *mut u8;
    // SAFETY: the allocator gave these frames to no other owner, and the direct map maps them
    // writable.
    unsafe { core::ptr::write_bytes(virt, 0, PAGE_SIZE << order) };
    Some(phys)
}

/// Takes one frame and gives its physical address. The heap uses this function. It owns the
/// frame until it gives it back with `free_frame_phys`.
pub(crate) fn alloc_frame_phys() -> Option<u64> {
    let frame = take_frame()?;
    Some((frame * PAGE_SIZE) as u64)
}

/// Gives back a frame that `alloc_frame_phys` gave.
pub(crate) fn free_frame_phys(phys: u64) {
    give_frame(phys as usize / PAGE_SIZE);
}

/// Takes `1 << order` frames in a row, where `order` is less than 6, and gives the physical address
/// of the first one. The address is a multiple of the size of the run. The heap uses this
/// function, and gives the frames back with `free_frame_phys`.
pub(crate) fn alloc_run_phys(order: u32) -> Option<u64> {
    let frame = take_run(|frames| frames.alloc_small_run(order))?;
    Some((frame * PAGE_SIZE) as u64)
}

/// The number of frames that the allocator manages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameStats {
    /// All frames that the allocator manages.
    pub total: usize,
    /// The frames that are free now.
    pub free: usize,
}

/// Gives the frame counts. The free frames on the lists of the CPUs count as free, as on Linux.
/// The counts take no lock, so they can be a little old.
pub fn frame_stats() -> FrameStats {
    let lists: usize = PCP.iter().map(|cpu| cpu.len.load(Ordering::Relaxed)).sum();
    let free = BITMAP_FREE.load(Ordering::Relaxed) + lists;
    FrameStats { total: BITMAP_TOTAL.load(Ordering::Relaxed), free }
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
    /// The number of page table entries of the user address spaces that map the frame, as
    /// `_mapcount` of a `struct page` of Linux (mm/rmap.c). See [`Frame::map_count`].
    maps: AtomicU32,
}

/// The frames that hold anonymous memory of a process, one bit for each frame, as `PageAnon` of
/// Linux. `/proc/kpageflags` reads the bit of a page frame number without the `Frame`.
static ANON: [AtomicU64; WORDS] = [const { AtomicU64::new(0) }; WORDS];

/// The frames that KSM merged, one bit for each frame, as `PAGE_MAPPING_KSM` of Linux.
static KSM: [AtomicU64; WORDS] = [const { AtomicU64::new(0) }; WORDS];

/// The word of the bitmap `map` and the bit in it of the frame at the physical address `phys`.
fn mark_bit(map: &'static [AtomicU64; WORDS], phys: u64) -> Option<(&'static AtomicU64, u64)> {
    let frame = usize::try_from(phys / PAGE_SIZE as u64).ok()?;
    Some((map.get(frame / 64)?, 1 << (frame % 64)))
}

/// Tells if the bitmap `map` has the frame at the physical address `phys`.
fn has_mark(map: &'static [AtomicU64; WORDS], phys: u64) -> bool {
    mark_bit(map, phys).is_some_and(|(word, bit)| word.load(Ordering::Relaxed) & bit != 0)
}

/// Tells if the frame at the physical address `phys` holds anonymous memory of a process, for
/// `/proc/kpageflags`. See [`Frame::set_anon`].
pub fn phys_is_anon(phys: PhysAddr) -> bool {
    has_mark(&ANON, phys.get())
}

/// Tells if KSM merged the frame at the physical address `phys`, for `/proc/kpageflags`. See
/// [`Frame::set_ksm`].
pub fn phys_is_ksm(phys: PhysAddr) -> bool {
    has_mark(&KSM, phys.get())
}

/// The kind of a run of `HUGE_FRAMES` frames, for the compound page flags of `/proc/kpageflags`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HugeKind {
    /// A transparent huge page that [`alloc_huge_frames`] gave, as `folio_test_large_rmappable`
    /// of Linux. The first frame that goes back ends the mark, as a split of the folio does.
    Thp,
    /// A huge page of the pool of hugetlbfs that is free in the pool, as `folio_test_hugetlb`.
    HugetlbFree,
    /// A huge page of the pool of hugetlbfs that a mapping or a file uses.
    Hugetlb,
}

/// The kind of each run of `HUGE_FRAMES` frames, by the index of the run: 0 for a run that is not
/// a huge page, or 1 + the index of the [`HugeKind`].
static RUN_KIND: [AtomicU8; RUNS] = [const { AtomicU8::new(0) }; RUNS];

fn set_run_kind(first: usize, kind: Option<HugeKind>) {
    let v = match kind {
        None => 0,
        Some(HugeKind::Thp) => 1,
        Some(HugeKind::HugetlbFree) => 2,
        Some(HugeKind::Hugetlb) => 3,
    };
    if let Some(slot) = RUN_KIND.get(first / HUGE_FRAMES) {
        slot.store(v, Ordering::Relaxed);
    }
}

/// Tells if the frame at the physical address `phys` is a part of a huge page, and of which kind,
/// for `/proc/kpageflags`. The frame at the 2 MiB aligned address is the head of the huge page,
/// and the other frames are its tail.
pub fn phys_huge(phys: PhysAddr) -> Option<HugeKind> {
    let frame = usize::try_from(phys.get() / PAGE_SIZE as u64).ok()?;
    match RUN_KIND.get(frame / HUGE_FRAMES)?.load(Ordering::Relaxed) {
        1 => Some(HugeKind::Thp),
        2 => Some(HugeKind::HugetlbFree),
        3 => Some(HugeKind::Hugetlb),
        _ => None,
    }
}

/// The number of page table entries of the user address spaces that map a frame of each pooled
/// run, by the index of the run. A huge page of hugetlbfs is mapped while the count is not 0, as
/// `folio_mapped` of Linux.
static RUN_MAPS: [AtomicU32; RUNS] = [const { AtomicU32::new(0) }; RUNS];

/// Tells if a page table entry of a user address space maps a frame of the huge page of hugetlbfs
/// that has the frame at the physical address `phys`, for `KPF_MMAP` of `/proc/kpageflags`.
pub fn phys_huge_mapped(phys: PhysAddr) -> bool {
    let Ok(frame) = usize::try_from(phys.get() / PAGE_SIZE as u64) else { return false };
    RUN_MAPS.get(frame / HUGE_FRAMES).is_some_and(|n| n.load(Ordering::Relaxed) != 0)
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
    let frame = take_frame()?;
    Some(Frame::new((frame * PAGE_SIZE) as u64, false))
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
    let first = take_run(|frames| frames.alloc_run(HUGE_FRAMES.trailing_zeros()))?;
    set_run_kind(first, Some(HugeKind::Thp));
    let frames = (first..first + HUGE_FRAMES).map(|f| {
        let mut frame = Frame::new((f * PAGE_SIZE) as u64, false);
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
        let first = take_run(|frames| frames.alloc_run(HUGE_FRAMES.trailing_zeros()))?;
        set_run_kind(first, Some(HugeKind::HugetlbFree));
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
        set_run_kind(first, Some(HugeKind::Hugetlb));
        let frames = (first..first + HUGE_FRAMES).map(|f| {
            let mut frame = Frame::new((f * PAGE_SIZE) as u64, true);
            frame.zero();
            frame
        });
        frames.collect()
    }
}

impl Drop for HugeRun {
    fn drop(&mut self) {
        set_run_kind(self.first, None);
        let mut frames = Global::lock();
        for f in self.first..self.first + HUGE_FRAMES {
            frames.free(f);
        }
    }
}

impl Frame {
    /// The number of 8 byte words in a frame.
    pub const WORDS: usize = PAGE_SIZE / 8;

    fn new(phys: u64, pooled: bool) -> Self {
        Self { phys, memcg: 0, pooled, maps: AtomicU32::new(0) }
    }

    /// The number of page table entries of the user address spaces that map the frame, as
    /// `folio_precise_page_mapcount` of Linux. The page cache of a file and the other holders of
    /// the frame do not count. A huge page that one entry maps counts one for each of its frames.
    pub fn map_count(&self) -> u32 {
        self.maps.load(Ordering::Relaxed)
    }

    /// Adds one page table entry to the map count, as `folio_add_anon_rmap_pte` and
    /// `folio_add_file_rmap_pte` of Linux.
    pub(crate) fn map_get(&self) {
        self.maps.fetch_add(1, Ordering::Relaxed);
        if self.pooled
            && let Some(n) = RUN_MAPS.get(self.phys as usize / PAGE_SIZE / HUGE_FRAMES)
        {
            n.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Removes one page table entry from the map count, as `folio_remove_rmap_pte` of Linux.
    pub(crate) fn map_put(&self) {
        self.maps.fetch_sub(1, Ordering::Relaxed);
        if self.pooled
            && let Some(n) = RUN_MAPS.get(self.phys as usize / PAGE_SIZE / HUGE_FRAMES)
        {
            n.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Marks the frame as charged to the memory cgroup `memcg`. The charge goes away with the
    /// frame, through the function of `set_uncharge_hook`.
    pub fn set_memcg(&mut self, memcg: u32) {
        self.memcg = memcg;
    }

    /// Marks the frame as anonymous memory of a process, as `folio_add_new_anon_rmap` of Linux
    /// sets `PageAnon`. A page of a file or of shared memory does not have the mark. The mark goes
    /// away when the frame goes back.
    pub fn set_anon(&self) {
        if let Some((word, bit)) = mark_bit(&ANON, self.phys) {
            word.fetch_or(bit, Ordering::Relaxed);
        }
    }

    /// Marks the frame as a page that KSM merged, as `folio_set_stable_node` of Linux. The mark
    /// goes away when the frame goes back.
    pub fn set_ksm(&self) {
        if let Some((word, bit)) = mark_bit(&KSM, self.phys) {
            word.fetch_or(bit, Ordering::Relaxed);
        }
    }

    /// Tells if the frame holds anonymous memory of a process. See [`Frame::set_anon`].
    pub fn is_anon(&self) -> bool {
        phys_is_anon(self.addr())
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
        for map in [&ANON, &KSM] {
            if let Some((word, bit)) = mark_bit(map, self.phys) {
                word.fetch_and(!bit, Ordering::Relaxed);
            }
        }
        let frame = self.phys as usize / PAGE_SIZE;
        let first = frame & !(HUGE_FRAMES - 1);
        if self.pooled {
            let back = RETURNED[first / HUGE_FRAMES].fetch_add(1, Ordering::AcqRel) + 1;
            if usize::from(back) == HUGE_FRAMES {
                set_run_kind(first, Some(HugeKind::HugetlbFree));
                let run = HugeRun { first };
                if let Some(f) = HUGE_RETURN.get() {
                    f(run);
                }
            }
            return;
        }
        // The first frame of a transparent huge page that goes back ends the huge page.
        if let Some(slot) = RUN_KIND.get(first / HUGE_FRAMES) {
            let _ = slot.compare_exchange(1, 0, Ordering::Relaxed, Ordering::Relaxed);
        }
        give_frame(frame);
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

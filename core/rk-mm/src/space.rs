//! The address space of a process.
//!
//! An `AddressSpace` has the areas of the process and its page table. A page gets a frame at the
//! first access, in `handle_fault`. A private page that two address spaces share after `fork` is
//! read only in both, and the first write copies it. This is copy on write.

use crate::hugetlb::{HPAGE_SIZE, Subpool};
use crate::softdirty::SoftLock;
use crate::tunables::{self, OVERCOMMIT_NEVER, ThpMode};
use crate::vma::{
    Backing, HugeAdvice, PAGE_SIZE, Prot, Vma, VmaKind, VmaSet, is_page_aligned, page_up,
};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use rk_abi::Errno;
use rk_frame::addr::VirtAddr;
use rk_frame::mm::{Frame, HUGE_FRAMES, alloc_huge_frames, alloc_zeroed_frame, frame_stats};
use rk_frame::sync::SpinLock;
#[cfg(not(feature = "corten"))]
use rk_frame::vm::ForkArea;
use rk_frame::vm::{HUGE_PAGE_SIZE, MapError, PageProt, USER_END, UserFault, VmSpace};

#[cfg(feature = "corten")]
mod corten;
pub(crate) mod hugetlb;
pub(crate) mod ksmd;

/// A file that a process can map. rk-vfs implements it, so rk-mm does not depend on rk-vfs, per
/// spec/23-package-layout.md section 23.2.
pub trait MmFile: Send + Sync {
    /// Gives the frame that holds the page `index` of the file. A write to the frame through a
    /// shared mapping changes the file.
    ///
    /// # Errors
    ///
    /// Gives `ENOMEM` if no frame is free, or an error of the file system.
    fn page(&self, index: u64) -> Result<Arc<Frame>, Errno>;

    /// Tells if [`MmFile::page`] gives the page `index` with no read of the file, for example
    /// because the page is in the page cache. A fault calls `page` for a page that is not ready
    /// with no lock of the address space held, as `filemap_fault` of Linux drops `mmap_lock`
    /// before it waits for the read of a page (`FAULT_FLAG_RETRY`).
    fn ready(&self, _index: u64) -> bool {
        true
    }

    /// The device, the inode number and the path of the file, as `/proc/PID/maps` shows them.
    fn name(&self) -> (u64, u64, Vec<u8>) {
        (0, 0, Vec::new())
    }

    /// Tells if the file keeps the pages that a shared mapping changes, and writes them back. A
    /// page of such a file is read only in a shared mapping until the first write, which calls
    /// [`MmFile::dirty`].
    fn writes_back(&self) -> bool {
        false
    }

    /// Records that a shared mapping changed the page `index`. The page is writable at `map` now,
    /// and the file keeps `map` so that [`WriteMap::mkclean`] makes the page read only again
    /// before a write back, as `folio_mkclean` of Linux.
    fn dirty(&self, _index: u64, _map: WriteMap) {}

    /// Tells if the page `index` of the file is in memory, for `mincore` of a page that has no
    /// frame in the page table, as `mincore_page` in mm/mincore.c of Linux.
    fn cached(&self, _index: u64) -> bool {
        false
    }

    /// Checks that a new map of the file can start, as the `mmap` of the file in Linux.
    /// `remap_file_pages` calls it after it removed the old map, and holds one reference to the
    /// file.
    ///
    /// # Errors
    ///
    /// Gives the error of the file, as `EINVAL` for a removed System V segment.
    fn reopen(&self) -> Result<(), Errno> {
        Ok(())
    }

    /// Writes the changed pages from `first` up to `end` back to the file.
    ///
    /// # Errors
    ///
    /// Gives an error of the file system.
    fn write_back(&self, _first: u64, _end: u64) -> Result<(), Errno> {
        Ok(())
    }

    /// Gives the huge pages of the file if it is a file of hugetlbfs. A mapping of such a file
    /// gets huge pages of 2 MiB.
    fn huge_file(&self) -> Option<&hugetlb::HugeFile> {
        None
    }
}

/// A file in an area.
pub type FileRef = Arc<dyn MmFile>;

/// A page of a shared file mapping that a write fault made writable, as an entry of the reverse
/// map of Linux. A file keeps one for each writer of a dirty page, so the write back finds the
/// mappings with no search of the address spaces.
#[derive(Clone)]
pub struct WriteMap {
    /// The page table of the mapping. The entry does not keep the address space alive.
    vm: Weak<VmSpace>,
    /// The address of the page.
    addr: usize,
}

impl WriteMap {
    /// Makes the page read only if it still maps `frame`, as `page_mkclean_one` of Linux. The next
    /// write to the page is a fault that calls [`MmFile::dirty`] again. Gives `true` if the page
    /// changed.
    pub fn mkclean(&self, frame: &Frame) -> bool {
        self.vm
            .upgrade()
            .is_some_and(|vm| vm.write_protect_frame(VirtAddr::new(self.addr), frame.addr().get()))
    }

    /// Tells if the address space of the mapping is still there.
    pub fn alive(&self) -> bool {
        self.vm.strong_count() > 0
    }

    /// Tells if `self` and `other` are the same page of the same address space.
    pub fn same(&self, other: &Self) -> bool {
        self.addr == other.addr && Weak::ptr_eq(&self.vm, &other.vm)
    }
}

/// Two files are the same if they are the same object, so that two areas of one file can merge.
impl PartialEq for dyn MmFile {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::addr_eq(self, other)
    }
}

impl core::fmt::Debug for dyn MmFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MmFile")
    }
}

/// The memory of a shared anonymous area. Each address space that maps the area after `fork`
/// finds the same frames here, also for a page that no process touched before the `fork`. Linux
/// keeps this memory in a shmem file.
struct SharedAnon {
    pages: SpinLock<BTreeMap<u64, Arc<Frame>>>,
}

impl MmFile for SharedAnon {
    fn page(&self, index: u64) -> Result<Arc<Frame>, Errno> {
        let mut pages = self.pages.lock();
        if let Some(frame) = pages.get(&index) {
            return Ok(frame.clone());
        }
        // Linux keeps this memory in shmem, so the page is not anonymous.
        above_reserve()?;
        let frame = charged(alloc_zeroed_frame(), 0)?;
        pages.insert(index, frame.clone());
        Ok(frame)
    }

    fn name(&self) -> (u64, u64, Vec<u8>) {
        (0, 0, b"/dev/zero (deleted)".to_vec())
    }

    fn cached(&self, index: u64) -> bool {
        self.pages.lock().contains_key(&index)
    }
}

/// The lowest address that `mmap` gives without `MAP_FIXED`. Linux names it `mmap_min_addr`.
pub const MMAP_MIN_ADDR: usize = 0x1_0000;
/// The end of the main stack.
pub const STACK_TOP: usize = USER_END;
/// The size of the main stack area. The `RLIMIT_STACK` default of Linux is 8 MiB.
pub const STACK_SIZE: usize = 8 << 20;
/// The free bytes that an area that grows down keeps to the area below it. Linux names it
/// `stack_guard_gap`, and its default is 256 pages.
pub const STACK_GUARD_GAP: usize = 256 * PAGE_SIZE;
/// The range for `MAP_32BIT`, as in Linux on x86-64.
const LOW32: (usize, usize) = (0x4000_0000, 0x8000_0000);
/// The top of the `mmap` area. Linux puts it a gap of 128 MiB below the stack.
pub const MMAP_TOP: usize = STACK_TOP - (128 << 20);

/// The kind of access that caused a page fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// A read.
    Read,
    /// A write.
    Write,
    /// An instruction fetch.
    Exec,
}

/// The arguments of `mmap` after the system call checks them.
#[derive(Clone, Debug)]
pub struct MmapRequest {
    /// The address hint, or the address for `fixed`.
    pub addr: usize,
    /// The length in bytes. It is not 0.
    pub len: usize,
    /// The access.
    pub prot: Prot,
    /// `MAP_SHARED`.
    pub shared: bool,
    /// `MAP_FIXED`: replace each mapping at the address.
    pub fixed: bool,
    /// `MAP_FIXED_NOREPLACE`: use the address, or fail with `EEXIST`.
    pub noreplace: bool,
    /// `MAP_32BIT`: put the mapping in the range from 1 GiB to 2 GiB, as Linux does on x86-64.
    pub low32: bool,
    /// The area can get write access later. See [`Vma::may_write`].
    pub may_write: bool,
    /// `MAP_LOCKED`: lock the area, as `mlock` does.
    pub locked: bool,
    /// `MAP_POPULATE`: give each page its frame now.
    pub populate: bool,
    /// `MAP_GROWSDOWN`: a fault below the area makes the area larger. See [`Vma::grows_down`].
    pub grows_down: bool,
    /// The file and the page aligned offset, or `None` for anonymous memory.
    pub file: Option<(FileRef, u64)>,
    /// What the area is for.
    pub kind: VmaKind,
    /// `MAP_NORESERVE`: the pages are not in the commit count, but with `vm.overcommit_memory` 2.
    /// A mapping of huge pages does not reserve its pages.
    pub noreserve: bool,
    /// `MAP_HUGETLB`: anonymous memory in huge pages of the hugetlbfs pool. A mapping of a file of
    /// hugetlbfs gets huge pages without the flag.
    pub hugetlb: bool,
}

impl MmapRequest {
    /// An anonymous private mapping at the address that the kernel chooses.
    pub fn anon(len: usize, prot: Prot) -> Self {
        Self {
            addr: 0,
            len,
            prot,
            shared: false,
            fixed: false,
            noreplace: false,
            low32: false,
            may_write: true,
            locked: false,
            populate: false,
            grows_down: false,
            file: None,
            kind: VmaKind::Normal,
            noreserve: false,
            hugetlb: false,
        }
    }
}

/// The flags and the new address of an `mremap` call.
#[derive(Clone, Copy, Debug, Default)]
pub struct Remap {
    /// `MREMAP_MAYMOVE`: the area can move to a new address.
    pub may_move: bool,
    /// `MREMAP_FIXED`: move the area to `new_addr`, and replace each mapping there.
    pub fixed: bool,
    /// `MREMAP_DONTUNMAP`: keep the old area after the move, without its pages.
    pub dont_unmap: bool,
    /// The new address for `fixed`.
    pub new_addr: usize,
}

struct State {
    vmas: VmaSet<FileRef>,
    /// The start of the heap. `brk` cannot go below it.
    brk_start: usize,
    /// The end of the heap.
    brk: usize,
    /// `MCL_FUTURE`: lock each new area.
    lock_future: bool,
    /// The guard pages of `MADV_GUARD_INSTALL`, by address. An access to such a page gives
    /// `SIGSEGV`, as a guard marker in the page table of Linux (mm/madvise.c).
    guards: BTreeSet<usize>,
    /// The write backs of the areas that a change removed. They run after the lock of the areas
    /// drops, so the I/O of the file does not hold the lock.
    write_backs: Vec<WriteBack>,
}

/// A write back of the shared file pages of a part of an area. It runs with no lock of the
/// address space held, as Linux writes back the pages of a mapping without `mmap_lock` (for
/// example `msync` in mm/msync.c drops `mmap_lock` around `vfs_fsync_range`).
struct WriteBack {
    file: FileRef,
    first: u64,
    end: u64,
}

impl WriteBack {
    /// The write back of the shared file pages of `vma` from `start` up to `end`, or `None` if
    /// the area has no such pages there.
    fn of(vma: &Vma<FileRef>, start: usize, end: usize) -> Option<Self> {
        match &vma.backing {
            Backing::File { file, offset } if vma.shared && file.writes_back() => {
                let start = start.max(vma.start);
                let end = end.min(vma.end);
                (start < end).then(|| WriteBack {
                    file: file.clone(),
                    first: file_index(vma, *offset, start),
                    end: file_index(vma, *offset, end),
                })
            }
            _ => None,
        }
    }

    /// Writes the pages back. The caller must not hold the lock of the areas.
    fn run(self) -> Result<(), Errno> {
        self.file.write_back(self.first, self.end)
    }
}

/// The guard of the lock of the areas of the VMA backend for a change. When it drops, it frees
/// the lock and then runs the write backs that the change queued in `State::write_backs`.
#[cfg(not(feature = "corten"))]
struct StateGuard<'a>(Option<rk_frame::sync::WriteGuard<'a, State>>);

#[cfg(not(feature = "corten"))]
impl core::ops::Deref for StateGuard<'_> {
    type Target = State;
    fn deref(&self) -> &State {
        self.0.as_deref().expect("the guard holds the lock until it drops")
    }
}

#[cfg(not(feature = "corten"))]
impl core::ops::DerefMut for StateGuard<'_> {
    fn deref_mut(&mut self) -> &mut State {
        self.0.as_deref_mut().expect("the guard holds the lock until it drops")
    }
}

#[cfg(not(feature = "corten"))]
impl Drop for StateGuard<'_> {
    fn drop(&mut self) {
        let Some(mut st) = self.0.take() else { return };
        let jobs = core::mem::take(&mut st.write_backs);
        drop(st);
        // munmap has no error for a failed write back, as on Linux.
        for job in jobs {
            let _ = job.run();
        }
    }
}

/// A page of a file that a fault read with no lock of the address space held. The fault takes
/// the lock again and maps this frame if the area still maps the same page of the same file.
struct Prepared {
    file: FileRef,
    index: u64,
    frame: Arc<Frame>,
}

/// The lock of the areas. The VMA backend has one read-write lock for the whole address space, as
/// the `mmap_lock` of Linux. The CortenMM backend of the `corten` feature locks the nodes of a page
/// table tree instead, per spec/24-open-questions.md question 1.
#[cfg(not(feature = "corten"))]
type StateLock = VmaLock;
#[cfg(feature = "corten")]
type StateLock = corten::Corten;

/// The number of the fault locks of an address space of the VMA backend.
#[cfg(not(feature = "corten"))]
const FAULT_LOCKS: usize = 16;

/// A fault lock on its own cache line, so two CPUs that take two locks do not share a line.
#[cfg(not(feature = "corten"))]
#[repr(align(64))]
struct FaultLock(SpinLock<()>);

/// The lock of the areas of the VMA backend.
///
/// A page fault reads the areas, as a fault of Linux takes `mmap_lock` for a read, so faults of
/// two threads run at the same time. A change of the areas writes them, and waits for the faults.
/// Two faults in one 2 MiB block take the same fault lock too, so a fault sees the page and maps
/// it in one step, as a fault of Linux holds the lock of the last level table (`pte_lockptr` in
/// include/linux/mm.h). Faults in two blocks take two fault locks, except when the blocks share a
/// lock of the `FAULT_LOCKS` locks. The page table of `VmSpace` has a lock for each block too.
#[cfg(not(feature = "corten"))]
struct VmaLock {
    state: rk_frame::sync::RwLock<State>,
    /// The fault locks. They are on the heap, so the address space stays small on the stack.
    faults: alloc::boxed::Box<[FaultLock]>,
}

#[cfg(not(feature = "corten"))]
impl VmaLock {
    fn new(state: State) -> Self {
        let faults = (0..FAULT_LOCKS).map(|_| FaultLock(SpinLock::new(()))).collect();
        Self { state: rk_frame::sync::RwLock::new(state), faults }
    }

    /// Takes the lock to change the areas. No fault runs while the guard lives. The write backs
    /// that the change queues run after the lock drops.
    fn lock(&self) -> StateGuard<'_> {
        StateGuard(Some(self.state.write()))
    }

    /// Takes the lock to change the areas if no other call holds it.
    fn try_lock(&self) -> Option<rk_frame::sync::WriteGuard<'_, State>> {
        self.state.try_write()
    }

    /// Takes the lock to read the areas. Other readers can hold it at the same time.
    fn read(&self) -> rk_frame::sync::ReadGuard<'_, State> {
        self.state.read()
    }

    /// The fault lock of the 2 MiB block of `addr`.
    fn fault_lock(&self, addr: usize) -> &SpinLock<()> {
        &self.faults[(addr / HUGE_PAGE_SIZE) % FAULT_LOCKS].0
    }
}

/// The address space of one process.
pub struct AddressSpace {
    vm: Arc<VmSpace>,
    state: StateLock,
    /// The soft-dirty state of the pages, as `CONFIG_MEM_SOFT_DIRTY` of Linux. Its lock comes after
    /// the lock of the areas, and no other lock comes after it. The calls take the lock only after
    /// a clear.
    soft: SoftLock,
    /// The memory cgroup that the new anonymous pages are charged to, or 0 for none.
    memcg: AtomicU32,
    /// The data of KSM.
    ksm: ksmd::MmKsm,
    /// The 2 MiB blocks of the private hugetlb areas that have a reservation and no page yet,
    /// with the pages of the mount of hugetlbfs of the file of the area. A child of `fork` does
    /// not get them, as on Linux.
    huge_resv: SpinLock<BTreeMap<usize, Option<Arc<Subpool>>>>,
    /// The largest number of pages with a frame before an unmap, as `hiwater_rss` of Linux.
    hiwater: AtomicUsize,
    /// The top of the `mmap` area, as `mmap_base` of Linux. It is [`MMAP_TOP`] less a random
    /// offset that `execve` sets.
    mmap_top: AtomicUsize,
}

fn map_error(e: MapError) -> Errno {
    match e {
        MapError::BadAddress => Errno::EFAULT,
        MapError::Mapped => Errno::EEXIST,
        MapError::NoMemory => Errno::ENOMEM,
    }
}

/// The page permissions for an area. A private page that is not only in this address space is read
/// only, so a write to it is a fault that copies it. A page of a shared file mapping that writes
/// back is read only until the first write marks it dirty. `exclusive` tells that the page can be
/// writable.
fn page_prot(vma: &Vma<FileRef>, exclusive: bool) -> PageProt {
    let tracked = matches!(&vma.backing, Backing::File { file, .. } if file.writes_back());
    PageProt {
        readable: vma.prot.read,
        writable: vma.prot.write && ((vma.shared && !tracked) || exclusive),
        executable: vma.prot.exec,
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        ksmd::exit(self);
        // The process ended or called execve. Its shared file mappings go back to their files.
        let st = self.state.lock();
        let jobs: Vec<WriteBack> =
            st.vmas.iter().filter_map(|vma| WriteBack::of(vma, vma.start, vma.end)).collect();
        uncharge_commit(accounted(st.vmas.iter()));
        drop(st);
        for job in jobs {
            let _ = job.run();
        }
        let unused = core::mem::take(&mut *self.huge_resv.lock());
        unreserve_blocks(unused.into_values());
    }
}

/// Gives back the reservations of private hugetlb blocks that no page used. A block of a file of
/// hugetlbfs gives its page back to the subpool of the mount too, as `hugetlb_vm_op_close` of
/// Linux.
fn unreserve_blocks(blocks: impl Iterator<Item = Option<Arc<Subpool>>>) {
    let mut anon = 0;
    for subpool in blocks {
        match subpool {
            Some(subpool) => subpool.unreserve(1),
            None => anon += 1,
        }
    }
    hugetlb::unreserve(anon);
}

/// The pages of memory.
fn total_pages() -> usize {
    frame_stats().total
}

/// Adds `len` bytes to the commit count, or gives `ENOMEM` if the overcommit policy does not
/// allow it.
fn charge_commit(len: usize) -> Result<(), Errno> {
    if len == 0 || tunables::charge(len / PAGE_SIZE, total_pages()) {
        Ok(())
    } else {
        Err(Errno::ENOMEM)
    }
}

/// Removes `len` bytes from the commit count.
fn uncharge_commit(len: usize) {
    tunables::uncharge(len / PAGE_SIZE);
}

/// The bytes of the areas that are in the commit count.
fn accounted<'a>(vmas: impl Iterator<Item = &'a Vma<FileRef>>) -> usize {
    vmas.filter(|v| v.account).map(Vma::len).sum()
}

/// Gives a new value for [`Vma::fork_anon`]. It is never 0.
fn next_fork_anon() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Makes the lock of the areas `state` of the page table `vm`. The CortenMM backend keeps the
/// statuses of the small pages in the page table.
#[cfg(feature = "corten")]
#[inline(always)]
fn new_lock(vm: Arc<VmSpace>, state: State) -> StateLock {
    StateLock::new(vm, state)
}

/// Makes the lock of the areas `state`.
#[cfg(not(feature = "corten"))]
#[inline(always)]
fn new_lock(_vm: Arc<VmSpace>, state: State) -> StateLock {
    StateLock::new(state)
}

impl AddressSpace {
    /// Makes an empty address space. Gives `ENOMEM` if no frame is free for the page table.
    pub fn new() -> Result<Self, Errno> {
        Ok(Self::with_vm(Arc::new(VmSpace::new().ok_or(Errno::ENOMEM)?)))
    }

    /// Makes an address space with no areas that uses the page table `vm`.
    fn with_vm(vm: Arc<VmSpace>) -> Self {
        let state = State {
            vmas: VmaSet::new(),
            brk_start: 0,
            brk: 0,
            lock_future: false,
            guards: BTreeSet::new(),
            write_backs: Vec::new(),
        };
        Self::with_state(vm.clone(), new_lock(vm, state))
    }

    /// Makes an address space with the page table `vm` and the areas of `state`.
    fn with_state(vm: Arc<VmSpace>, state: StateLock) -> Self {
        Self {
            vm,
            state,
            soft: SoftLock::new(),
            memcg: AtomicU32::new(0),
            ksm: ksmd::MmKsm::default(),
            huge_resv: SpinLock::new(BTreeMap::new()),
            hiwater: AtomicUsize::new(0),
            mmap_top: AtomicUsize::new(MMAP_TOP),
        }
    }

    /// The top of the `mmap` area.
    pub fn mmap_top(&self) -> usize {
        self.mmap_top.load(Ordering::Relaxed)
    }

    /// Moves the top of the `mmap` area down by `offset` bytes, as `arch_pick_mmap_layout` of
    /// Linux does for a random offset. The offset is rounded down to a page. An offset that is
    /// too large is limited, so that the `mmap` area keeps at least half of its size.
    pub fn set_mmap_offset(&self, offset: usize) {
        let offset = offset.min((MMAP_TOP - MMAP_MIN_ADDR) / 2) & !(PAGE_SIZE - 1);
        self.mmap_top.store(MMAP_TOP - offset, Ordering::Relaxed);
    }

    /// Sets the memory cgroup that the new anonymous pages are charged to. The pages that the
    /// space has keep their charge, as in Linux.
    pub fn set_memcg(&self, memcg: u32) {
        self.memcg.store(memcg, Ordering::Relaxed);
    }

    /// The memory cgroup of the new anonymous pages.
    pub fn memcg(&self) -> u32 {
        self.memcg.load(Ordering::Relaxed)
    }

    /// The page table.
    pub fn vm(&self) -> &VmSpace {
        &self.vm
    }

    /// Loads the page table, so the user code of the process can run.
    pub fn activate(&self) {
        self.vm.activate();
    }

    /// Gives a copy of the areas, in address order.
    pub fn areas(&self) -> Vec<Vma<FileRef>> {
        self.state.lock().vmas.iter().cloned().collect()
    }

    /// Gives a copy of the areas in address order, and the start and the end of the heap, as
    /// `start_brk` and `brk` of Linux. All three come from one lock, so `/proc/PID/maps` can name
    /// the areas of the heap with them.
    pub fn areas_and_heap(&self) -> (Vec<Vma<FileRef>>, usize, usize) {
        let st = self.state.lock();
        (st.vmas.iter().cloned().collect(), st.brk_start, st.brk)
    }

    /// Gives the start of the first area of the kind `kind`, or `None` if there is none. The
    /// signal code of arm64 finds the vDSO with it.
    pub fn find_kind(&self, kind: VmaKind) -> Option<usize> {
        self.state.lock().vmas.iter().find(|v| v.kind == kind).map(|v| v.start)
    }

    /// Gives a copy of the areas in the page aligned range of `addr..addr + len`, in address
    /// order. `madvise` uses it.
    ///
    /// # Errors
    ///
    /// `ENOMEM` if a page of the range is not mapped.
    pub fn areas_in(&self, addr: usize, len: usize) -> Result<Vec<Vma<FileRef>>, Errno> {
        let (start, end) = Self::lock_range(addr, len)?;
        let st = self.state.lock();
        if !st.vmas.covers(start, end) {
            return Err(Errno::ENOMEM);
        }
        Ok(st.vmas.iter().filter(|v| v.end > start && v.start < end).cloned().collect())
    }

    /// Sets the start of the heap. The ELF loader calls it with the end of the program.
    pub fn set_brk_start(&self, addr: usize) {
        let mut st = self.state.lock();
        st.brk_start = addr;
        st.brk = addr;
    }

    /// Makes a mapping and gives its address.
    ///
    /// # Errors
    ///
    /// `EINVAL` for a bad address or length, `EEXIST` for `MAP_FIXED_NOREPLACE` on a mapping, and
    /// `ENOMEM` when no range is free or a fixed range goes past the end of user space.
    pub fn mmap(&self, req: MmapRequest) -> Result<usize, Errno> {
        let hugetlb =
            req.hugetlb || req.file.as_ref().is_some_and(|(f, _)| f.huge_file().is_some());
        let align = if hugetlb { HPAGE_SIZE } else { PAGE_SIZE };
        let len = req.len.checked_next_multiple_of(align).unwrap_or(0);
        let start = self.mmap_area(req)?;
        // A new mapping is soft-dirty, as the flag `VM_SOFTDIRTY` of a new area of Linux.
        self.soft.mapped(start, start.saturating_add(len));
        Ok(start)
    }

    /// `mmap` without the soft-dirty state.
    fn mmap_area(&self, req: MmapRequest) -> Result<usize, Errno> {
        if req.len == 0 {
            return Err(Errno::EINVAL);
        }
        // A mapping of huge pages has a length, an offset and an address that are 2 MiB aligned,
        // as `hugetlb_get_unmapped_area` of Linux.
        let hugetlb =
            req.hugetlb || req.file.as_ref().is_some_and(|(f, _)| f.huge_file().is_some());
        let align = if hugetlb { HPAGE_SIZE } else { PAGE_SIZE };
        let len = req
            .len
            .checked_next_multiple_of(align)
            .filter(|&l| l <= USER_END)
            .ok_or(Errno::ENOMEM)?;
        if let Some((_, offset)) = &req.file
            && !offset.is_multiple_of(align as u64)
        {
            return Err(Errno::EINVAL);
        }
        #[cfg(feature = "corten")]
        if !hugetlb {
            return self.corten_mmap(req, len);
        }
        let mut st = self.state.lock();
        let start = if req.fixed || req.noreplace {
            if !req.addr.is_multiple_of(align) {
                return Err(Errno::EINVAL);
            }
            // As `__get_unmapped_area` of Linux, a range past the end of user space is ENOMEM.
            if req.addr.checked_add(len).is_none_or(|e| e > USER_END) {
                return Err(Errno::ENOMEM);
            }
            if st.vmas.overlaps(req.addr, req.addr + len) {
                if req.noreplace {
                    return Err(Errno::EEXIST);
                }
                self.unmap_locked(&mut st, req.addr, req.addr + len);
            }
            if st.vmas.len() > tunables::max_map_count() {
                return Err(Errno::ENOMEM);
            }
            req.addr
        } else {
            if st.vmas.len() > tunables::max_map_count() {
                return Err(Errno::ENOMEM);
            }
            let (bottom, top) = if req.low32 { LOW32 } else { (MMAP_MIN_ADDR, self.mmap_top()) };
            let hint = if hugetlb {
                req.addr.checked_next_multiple_of(align).unwrap_or(0)
            } else {
                req.addr & !(PAGE_SIZE - 1)
            };
            let hint_ok = hint >= MMAP_MIN_ADDR
                && hint
                    .checked_add(len)
                    .is_some_and(|e| e <= if req.low32 { top } else { USER_END })
                && !st.vmas.overlaps(hint, hint + len);
            let gap = if hugetlb {
                st.vmas.find_gap_aligned(len, align, bottom, top)
            } else {
                st.vmas.find_gap(len, bottom, top)
            };
            if hint_ok { hint } else { gap.ok_or(Errno::ENOMEM)? }
        };
        let no_file = req.file.is_none();
        let mut file = req.file;
        if hugetlb {
            file = self.reserve_huge(&req.prot, req.shared, req.noreserve, file, start, len)?;
        }
        // As `accountable_mapping` of Linux: a private writable area and a shared anonymous area
        // are in the commit count. `MAP_NORESERVE` has no effect with `vm.overcommit_memory` 2.
        // The pages of hugetlbfs are not in the count, as on Linux.
        let account = !hugetlb
            && !(req.noreserve && tunables::overcommit_memory() != OVERCOMMIT_NEVER)
            && if req.shared { no_file } else { req.prot.write };
        if account && let Err(e) = charge_commit(len) {
            self.unreserve_private(start, start + len);
            return Err(e);
        }
        let backing = match file {
            Some((file, offset)) => Backing::File { file, offset },
            None if req.shared => {
                let file: FileRef = Arc::new(SharedAnon { pages: SpinLock::new(BTreeMap::new()) });
                Backing::File { file, offset: 0 }
            }
            None => Backing::Anon,
        };
        let locked = req.locked || st.lock_future;
        st.vmas.insert_merged(Vma {
            start,
            end: start + len,
            prot: req.prot,
            shared: req.shared,
            may_write: req.may_write,
            locked,
            grows_down: req.grows_down,
            mergeable: false,
            huge: HugeAdvice::None,
            account,
            hugetlb,
            dont_fork: false,
            wipe_on_fork: false,
            dont_dump: false,
            fork_anon: 0,
            backing,
            kind: req.kind,
        });
        let populate = req.populate || locked;
        drop(st);
        if populate {
            // A page that cannot get its frame now gets it at the first access, as on Linux.
            let _ = self.populate(start, start + len);
        }
        Ok(start)
    }

    /// Reserves the huge pages of a new hugetlb mapping at `start`, as `hugetlb_reserve_pages`
    /// of Linux, and gives the file of the mapping. A shared mapping reserves the pages of its
    /// file, and a shared anonymous mapping gets a new file. A private mapping reserves its
    /// blocks in the address space. A writable mapping makes its file longer, as on Linux.
    fn reserve_huge(
        &self,
        prot: &Prot,
        shared: bool,
        noreserve: bool,
        file: Option<(FileRef, u64)>,
        start: usize,
        len: usize,
    ) -> Result<Option<(FileRef, u64)>, Errno> {
        let blocks = (len / HPAGE_SIZE) as u64;
        match file {
            None if shared => {
                let name = b"/anon_hugepage (deleted)".to_vec();
                let huge = hugetlb::HugeFile::new(0, 0, name, len as u64);
                if !noreserve {
                    huge.reserve(0, blocks)?;
                }
                let file: FileRef = huge;
                Ok(Some((file, 0)))
            }
            Some((file, offset)) => {
                let huge = file.huge_file().ok_or(Errno::EINVAL)?;
                let first = offset / HPAGE_SIZE as u64;
                if shared && !noreserve {
                    huge.reserve(first, first + blocks)?;
                } else if !shared && !noreserve {
                    self.reserve_private(start, len, huge.subpool())?;
                }
                if prot.write {
                    huge.grow_to(offset + len as u64);
                }
                Ok(Some((file, offset)))
            }
            None => {
                if !noreserve {
                    self.reserve_private(start, len, None)?;
                }
                Ok(None)
            }
        }
    }

    /// Reserves the huge pages of the private hugetlb range `start..start + len`. A private
    /// mapping of a file of hugetlbfs takes the pages from `subpool`, the pages of the mount, so
    /// `size=` limits them, as `hugetlb_reserve_pages` of Linux.
    fn reserve_private(
        &self,
        start: usize,
        len: usize,
        subpool: Option<&Arc<Subpool>>,
    ) -> Result<(), Errno> {
        let blocks = len / HPAGE_SIZE;
        match subpool {
            Some(subpool) => subpool.reserve(blocks as u64)?,
            None => hugetlb::reserve(blocks)?,
        }
        let mut resv = self.huge_resv.lock();
        resv.extend((start..start + len).step_by(HPAGE_SIZE).map(|b| (b, subpool.cloned())));
        Ok(())
    }

    /// Removes the reservations of the private hugetlb blocks in `start..end`.
    fn unreserve_private(&self, start: usize, end: usize) {
        let unused = {
            let mut resv = self.huge_resv.lock();
            let blocks: Vec<usize> = resv.range(start..end).map(|(&b, _)| b).collect();
            blocks.iter().filter_map(|b| resv.remove(b)).collect::<Vec<_>>()
        };
        unreserve_blocks(unused.into_iter());
    }

    /// Tells if `start` or `end` is in a hugetlb area and is not 2 MiB aligned. Such an area
    /// cannot split there, so `munmap` and `mprotect` give `EINVAL`, as `hugetlb_vm_op_split` of
    /// Linux.
    fn splits_huge(st: &State, start: usize, end: usize) -> bool {
        [start, end].into_iter().any(|x| {
            !x.is_multiple_of(HPAGE_SIZE)
                && st.vmas.find(x).is_some_and(|v| v.hugetlb && v.start < x)
        })
    }

    fn unmap_locked(&self, st: &mut State, start: usize, end: usize) {
        Self::remove_guards(st, start, end);
        for vma in st.vmas.remove_range(start, end) {
            if vma.hugetlb && !vma.shared {
                self.unreserve_private(vma.start, vma.end);
            }
            self.unmap_pages(VirtAddr::new(vma.start), VirtAddr::new(vma.end));
            if vma.account {
                uncharge_commit(vma.len());
            }
            // The write back runs after the lock of the areas drops, see `StateGuard`.
            if let Some(job) = WriteBack::of(&vma, vma.start, vma.end) {
                st.write_backs.push(job);
            }
        }
    }

    /// Writes the changed pages of the shared file mappings in `addr..addr + len` back to their
    /// files.
    ///
    /// # Errors
    ///
    /// `EINVAL` if `addr` is not page aligned, `ENOMEM` if a page of the range is not mapped,
    /// `EBUSY` for `invalidate` on a locked area, or an error of the file system.
    pub fn msync(&self, addr: usize, len: usize, invalidate: bool) -> Result<(), Errno> {
        if !is_page_aligned(addr) {
            return Err(Errno::EINVAL);
        }
        let end = page_up(len).and_then(|l| addr.checked_add(l)).ok_or(Errno::ENOMEM)?;
        if end > USER_END {
            return Err(Errno::ENOMEM);
        }
        // The lock of the areas only finds the pages. The write backs run after it drops, as
        // `msync` in mm/msync.c of Linux drops `mmap_lock` around `vfs_fsync_range`. The errors
        // come in the same order as with the write backs under the lock.
        let st = self.state.lock();
        let mut jobs = Vec::new();
        let mut busy = false;
        for vma in st.vmas.iter().filter(|v| v.start < end && addr < v.end) {
            if invalidate && vma.locked {
                busy = true;
                break;
            }
            jobs.extend(WriteBack::of(vma, addr, end));
        }
        let covers = st.vmas.covers(addr, end);
        drop(st);
        // The write back makes the pages read only in each address space that wrote them, so
        // the next write marks them dirty again, as `folio_mkclean` of Linux.
        for job in jobs {
            job.run()?;
        }
        if busy {
            return Err(Errno::EBUSY);
        }
        if !covers {
            return Err(Errno::ENOMEM);
        }
        Ok(())
    }

    /// Removes the mappings in `addr..addr + len`.
    ///
    /// # Errors
    ///
    /// `EINVAL` if `addr` is not page aligned, `len` is 0 or the range is not in the user half.
    /// `ENOMEM` if the range is in the middle of an area and the split makes too many areas.
    #[cfg_attr(feature = "corten", allow(unreachable_code))]
    pub fn munmap(&self, addr: usize, len: usize) -> Result<(), Errno> {
        let end = page_up(len)
            .and_then(|l| addr.checked_add(l))
            .filter(|&e| len != 0 && is_page_aligned(addr) && e <= USER_END)
            .ok_or(Errno::EINVAL)?;
        #[cfg(feature = "corten")]
        return self.corten_munmap(addr, end);
        let mut st = self.state.lock();
        if Self::splits_huge(&st, addr, end) {
            return Err(Errno::EINVAL);
        }
        if st.vmas.len() >= tunables::max_map_count()
            && st.vmas.find(addr).is_some_and(|vma| vma.start < addr && end < vma.end)
        {
            return Err(Errno::ENOMEM);
        }
        self.unmap_locked(&mut st, addr, end);
        Ok(())
    }

    /// Calls `f` with the area at `at`, or `None` if no area has it. The CortenMM backend gives
    /// the part of the area in the 2 MiB block of `at`.
    fn with_area<R>(&self, at: usize, f: impl FnOnce(Option<&Vma<FileRef>>) -> R) -> R {
        #[cfg(feature = "corten")]
        return f(self.corten_area(at).as_ref());
        #[cfg(not(feature = "corten"))]
        f(self.state.lock().vmas.find(at))
    }

    /// Gives a frame to each page of `start..end` that has none. A page of an area that allows a
    /// write gets a frame of its own, so that a later write does not copy it.
    fn populate(&self, start: usize, end: usize) -> Result<(), Errno> {
        let mut at = start;
        while at < end {
            let (access, step) = match self.with_area(at, |v| v.map(|v| (v.prot, v.hugetlb, v.end)))
            {
                Some((prot, _, end)) if !prot.write && !prot.read && !prot.exec => {
                    at = end;
                    continue;
                }
                Some((prot, hugetlb, _)) => {
                    let access = if prot.write { Access::Write } else { Access::Read };
                    // One fault maps the whole huge page of a hugetlb area.
                    let step = if hugetlb { HPAGE_SIZE - at % HPAGE_SIZE } else { PAGE_SIZE };
                    (access, step)
                }
                None => return Err(Errno::ENOMEM),
            };
            self.handle_fault(at, access)?;
            at += step;
        }
        Ok(())
    }

    /// The page aligned range of `addr..addr + len`, as `mlock` and `mincore` use it.
    fn lock_range(addr: usize, len: usize) -> Result<(usize, usize), Errno> {
        let start = addr & !(PAGE_SIZE - 1);
        let end = len
            .checked_add(addr - start)
            .and_then(page_up)
            .and_then(|l| start.checked_add(l))
            .filter(|&e| e <= USER_END)
            .ok_or(Errno::ENOMEM)?;
        Ok((start, end))
    }

    /// Locks or unlocks the areas in `addr..addr + len`. A lock gives each page its frame, but
    /// not with `on_fault`. `limit` is the most locked bytes of the space, `RLIMIT_MEMLOCK`, or
    /// `None` if the caller has `CAP_IPC_LOCK`.
    ///
    /// # Errors
    ///
    /// `ENOMEM` if a page of the range is not mapped, if the lock goes above `limit`, or if no
    /// frame is free.
    pub fn mlock(
        &self,
        addr: usize,
        len: usize,
        lock: bool,
        on_fault: bool,
        limit: Option<usize>,
    ) -> Result<(), Errno> {
        let (start, end) = Self::lock_range(addr, len)?;
        {
            let mut st = self.state.lock();
            if let Some(limit) = limit.filter(|_| lock) {
                // As `do_mlock` of Linux: the pages that are locked already in the range do not
                // count again.
                let locked: usize = st.vmas.iter().filter(|v| v.locked).map(Vma::len).sum();
                let mut want = locked.saturating_add(end - start);
                if want > limit {
                    let again: usize = st
                        .vmas
                        .iter()
                        .filter(|v| v.locked)
                        .map(|v| v.end.min(end).saturating_sub(v.start.max(start)))
                        .sum();
                    want -= again;
                }
                if want > limit {
                    return Err(Errno::ENOMEM);
                }
            }
            if !st.vmas.covers(start, end) {
                return Err(Errno::ENOMEM);
            }
            st.vmas.update_range_merged(start, end, |vma| vma.locked = lock);
        }
        if lock && !on_fault {
            only_enomem(self.populate(start, end))?;
        }
        Ok(())
    }

    /// Locks each area, and with `future` each new area too. A lock gives each page its frame,
    /// but not with `on_fault`. `mlockall` calls it, and `munlockall` calls it with `lock` false.
    /// `limit` is the most locked bytes of the space, `RLIMIT_MEMLOCK`, or `None` if the caller
    /// has `CAP_IPC_LOCK`.
    ///
    /// # Errors
    ///
    /// `ENOMEM` if the areas with `current` are larger than `limit`, or if no frame is free.
    pub fn mlock_all(
        &self,
        lock: bool,
        current: bool,
        future: bool,
        on_fault: bool,
        limit: Option<usize>,
    ) -> Result<(), Errno> {
        let areas: Vec<(usize, usize)> = {
            let mut st = self.state.lock();
            if lock
                && current
                && limit.is_some_and(|l| st.vmas.iter().map(Vma::len).sum::<usize>() > l)
            {
                return Err(Errno::ENOMEM);
            }
            st.lock_future = lock && future;
            if current || !lock {
                st.vmas.update_range_merged(0, USER_END, |vma| vma.locked = lock);
            }
            st.vmas.iter().map(|v| (v.start, v.end)).collect()
        };
        if lock && current && !on_fault {
            for (start, end) in areas {
                only_enomem(self.populate(start, end))?;
            }
        }
        Ok(())
    }

    /// The number of bytes in locked areas, the `VmLck` line of `/proc/PID/status`.
    pub fn locked_bytes(&self) -> usize {
        self.state.lock().vmas.iter().filter(|v| v.locked).map(Vma::len).sum()
    }

    /// The number of pages of the address space that have a frame. It does not allocate, so the
    /// OOM killer can use it when the memory is short.
    pub fn page_count(&self) -> usize {
        self.vm.page_count()
    }

    /// The largest number of pages of the address space that had a frame, as `get_mm_hiwater_rss`
    /// of Linux. The space keeps the count before each unmap of a range, so the pages of an area
    /// that `munmap` or `madvise` removed count.
    pub fn hiwater_pages(&self) -> usize {
        self.hiwater.load(Ordering::Relaxed).max(self.page_count())
    }

    /// Removes the pages in `start..end` from the page table. The count of pages before the
    /// removal goes into the high water mark. The pages lose their soft-dirty state, as the zap
    /// of the page table entries of Linux (`zap_pte_range` in mm/memory.c).
    fn unmap_pages(&self, start: VirtAddr, end: VirtAddr) {
        self.hiwater.fetch_max(self.page_count(), Ordering::Relaxed);
        self.vm.unmap_range(start, end);
        self.soft.unmapped(start.get(), end.get());
    }

    /// The number of pages in `start..end` that have a frame.
    pub fn resident_pages(&self, start: usize, end: usize) -> usize {
        self.vm.pages_in(VirtAddr::new(start), VirtAddr::new(end))
    }

    /// Copies the page at `addr` to `buf` for a core dump, as `get_dump_page` in mm/gup.c of
    /// Linux. A page with a frame gives its bytes, and the permissions of the page have no
    /// effect. A page of a file area with no frame gives the page of the file. Gives `false` for
    /// an anonymous page with no frame, which the dump keeps as a hole, and for a page that the
    /// file cannot give. `buf` has the size of a page.
    pub fn dump_page(&self, addr: usize, buf: &mut [u8]) -> bool {
        let page = addr & !(PAGE_SIZE - 1);
        if let Some((frame, _)) = self.vm.page(VirtAddr::new(page)) {
            frame.read_bytes(0, &mut buf[..PAGE_SIZE]);
            return true;
        }
        // The CortenMM backend locks only the block of the page, and not the whole space for
        // each page of the dump.
        let file = self.with_area(page, |vma| match vma {
            Some(vma @ Vma { backing: Backing::File { file, offset }, hugetlb: false, .. }) => {
                Some((file.clone(), file_index(vma, *offset, page)))
            }
            _ => None,
        });
        let Some(file) = file else { return false };
        match file.0.page(file.1) {
            Ok(frame) => {
                frame.read_bytes(0, &mut buf[..PAGE_SIZE]);
                true
            }
            Err(_) => false,
        }
    }

    /// Gives one byte for each page of `addr..addr + len`: 1 if the page has a frame, else 0. A
    /// page of a file without a frame here is 1 if the file has the page in memory, as
    /// `mincore_unmapped_range` of Linux.
    ///
    /// # Errors
    ///
    /// `EINVAL` if `addr` is not page aligned, and `ENOMEM` if a page of the range is not mapped.
    pub fn mincore(&self, addr: usize, len: usize) -> Result<Vec<u8>, Errno> {
        if !is_page_aligned(addr) {
            return Err(Errno::EINVAL);
        }
        let (start, end) = Self::lock_range(addr, len)?;
        let st = self.state.lock();
        if !st.vmas.covers(start, end) {
            return Err(Errno::ENOMEM);
        }
        let mut out = alloc::vec![0u8; (end - start) / PAGE_SIZE];
        for vma in st.vmas.iter().filter(|v| v.start < end && start < v.end) {
            let Backing::File { file, offset } = &vma.backing else { continue };
            for page in (start.max(vma.start)..end.min(vma.end)).step_by(PAGE_SIZE) {
                if file.cached(file_index(vma, *offset, page)) {
                    out[(page - start) / PAGE_SIZE] = 1;
                }
            }
        }
        drop(st);
        for page in self.vm.mapped_pages(VirtAddr::new(start), VirtAddr::new(end)) {
            out[(page.get() - start) / PAGE_SIZE] = 1;
        }
        Ok(out)
    }

    /// Changes the size of the area at `addr`, and can move it. Gives the new address.
    ///
    /// # Errors
    ///
    /// `EINVAL` for a bad address, length or flag, `EFAULT` if `addr..addr + old_len` is not in
    /// one area, and `ENOMEM` if the area cannot grow and cannot move.
    pub fn mremap(
        &self,
        addr: usize,
        old_len: usize,
        new_len: usize,
        remap: Remap,
    ) -> Result<usize, Errno> {
        if (remap.fixed && !remap.may_move)
            || (remap.dont_unmap && (!remap.may_move || old_len != new_len))
            || !is_page_aligned(addr)
        {
            return Err(Errno::EINVAL);
        }
        let old_len = page_up(old_len).ok_or(Errno::EINVAL)?;
        let new_len = page_up(new_len).filter(|&l| l != 0).ok_or(Errno::EINVAL)?;
        let mut st = self.state.lock();
        // The pages of a hugetlb area do not move.
        if st.vmas.find(addr).is_some_and(|v| v.hugetlb) {
            return Err(Errno::EINVAL);
        }
        if remap.fixed {
            let to = remap.new_addr;
            let to_end = to.checked_add(new_len).filter(|&e| e <= USER_END);
            let Some(to_end) = to_end.filter(|_| is_page_aligned(to)) else {
                return Err(Errno::EINVAL);
            };
            if to < addr.saturating_add(old_len) && addr < to_end {
                return Err(Errno::EINVAL);
            }
            Self::resizable(&st, addr, old_len)?;
            self.unmap_locked(&mut st, to, to_end);
            return self.move_locked(&mut st, addr, old_len, new_len, to, remap.dont_unmap);
        }
        let end = Self::resizable(&st, addr, old_len)?;
        if old_len >= new_len && !remap.dont_unmap {
            self.unmap_locked(&mut st, addr + new_len, addr + old_len);
            return Ok(addr);
        }
        // Grow the area in place if the range after it is free.
        let new_end = addr.checked_add(new_len).filter(|&e| e <= USER_END);
        if let Some(new_end) = new_end.filter(|_| old_len != 0 && !remap.dont_unmap)
            && end == addr + old_len
            && !st.vmas.overlaps(end, new_end)
        {
            if st.vmas.find(addr).is_some_and(|v| v.account) {
                charge_commit(new_len - old_len)?;
            }
            st.vmas.update_range(addr, end, |vma| vma.end = new_end);
            st.vmas.merge_range(addr, new_end);
            self.soft.mapped(end, new_end);
            return Ok(addr);
        }
        if !remap.may_move {
            return Err(Errno::ENOMEM);
        }
        let to = st.vmas.find_gap(new_len, MMAP_MIN_ADDR, self.mmap_top()).ok_or(Errno::ENOMEM)?;
        self.move_locked(&mut st, addr, old_len, new_len, to, remap.dont_unmap)
    }

    /// Examines the old range of `mremap`, and gives the end of its area. An `old_len` of 0
    /// copies a shared area, as Linux does.
    fn resizable(st: &State, addr: usize, old_len: usize) -> Result<usize, Errno> {
        let vma = st.vmas.find(addr).ok_or(Errno::EFAULT)?;
        if old_len == 0 && !vma.shared {
            return Err(Errno::EINVAL);
        }
        if old_len > vma.end - addr {
            return Err(Errno::EFAULT);
        }
        Ok(vma.end)
    }

    /// Moves the pages in `addr..addr + old_len` to `to`, and makes the area at `to` with
    /// `new_len` bytes. The range at `to` is free.
    fn move_locked(
        &self,
        st: &mut State,
        addr: usize,
        old_len: usize,
        new_len: usize,
        to: usize,
        dont_unmap: bool,
    ) -> Result<usize, Errno> {
        // The new area is in the commit count, and the old area stays in it if it stays.
        if st.vmas.find(addr).is_some_and(|v| v.account) {
            let removed = if old_len == 0 || dont_unmap { 0 } else { old_len };
            if new_len > removed {
                charge_commit(new_len - removed)?;
            } else {
                uncharge_commit(removed - new_len);
            }
        }
        let mut vma = match st.vmas.find(addr) {
            Some(v) if old_len == 0 => {
                let mut copy = v.clone();
                if let Backing::File { offset, .. } = &mut copy.backing {
                    *offset += (addr - v.start) as u64;
                }
                copy.start = addr;
                copy
            }
            _ => {
                // The guard pages do not move with the area.
                Self::remove_guards(st, addr, addr + old_len);
                st.vmas.remove_range(addr, addr + old_len).pop().ok_or(Errno::EFAULT)?
            }
        };
        // A writable page of a file that writes back becomes read only, as the file knows the old
        // address only. The next write marks it dirty at the new address.
        let tracked =
            vma.shared && matches!(&vma.backing, Backing::File { file, .. } if file.writes_back());
        for page in self.vm.mapped_pages(VirtAddr::new(addr), VirtAddr::new(addr + old_len)) {
            let Some((frame, mut prot)) = self.vm.page(page) else { continue };
            prot.writable &= !tracked;
            self.vm.unmap(page);
            let off = page.get() - addr;
            if off < new_len {
                self.vm.map(VirtAddr::new(to + off), frame, prot).map_err(map_error)?;
            }
        }
        // The old pages have no entries now, as `move_ptes` of Linux.
        self.soft.unmapped(addr, addr + old_len);
        if dont_unmap {
            st.vmas.insert_merged(Vma { start: addr, end: addr + old_len, ..vma.clone() });
        }
        vma.start = to;
        vma.end = to + new_len;
        st.vmas.insert_merged(vma);
        // The pages that move are soft-dirty, as `move_soft_dirty_pte` of Linux.
        self.soft.mapped(to, to + new_len);
        Ok(to)
    }

    /// Changes the access of the mappings in `addr..addr + len`.
    ///
    /// # Errors
    ///
    /// `EINVAL` if `addr` is not page aligned, `ENOMEM` if a page of the range is not mapped, and
    /// `EACCES` for write access to an area that cannot get it.
    #[cfg_attr(feature = "corten", allow(unreachable_code))]
    pub fn mprotect(&self, addr: usize, len: usize, prot: Prot) -> Result<(), Errno> {
        if !is_page_aligned(addr) {
            return Err(Errno::EINVAL);
        }
        let end = page_up(len).and_then(|l| addr.checked_add(l)).ok_or(Errno::ENOMEM)?;
        if end > USER_END {
            return Err(Errno::ENOMEM);
        }
        #[cfg(feature = "corten")]
        return self.corten_mprotect(addr, end, prot);
        let mut st = self.state.lock();
        if !st.vmas.covers(addr, end) {
            return Err(Errno::ENOMEM);
        }
        if Self::splits_huge(&st, addr, end) {
            return Err(Errno::EINVAL);
        }
        if prot.write && st.vmas.iter().any(|v| v.start < end && addr < v.end && !v.may_write) {
            return Err(Errno::EACCES);
        }
        // A private area that gets write access goes in the commit count, as in Linux.
        if prot.write {
            let more: usize = st
                .vmas
                .iter()
                .filter(|v| v.start < end && addr < v.end && !v.shared && !v.account && !v.hugetlb)
                .map(|v| v.end.min(end) - v.start.max(addr))
                .sum();
            charge_commit(more)?;
        }
        st.vmas.update_range_merged(addr, end, |vma| {
            vma.prot = prot;
            vma.account |= prot.write && !vma.shared && !vma.hugetlb;
        });
        let mut next = 0;
        for page in self.vm.mapped_pages(VirtAddr::new(addr), VirtAddr::new(end)) {
            let a = page.get();
            let Some(vma) = st.vmas.find(a).filter(|_| a >= next) else { continue };
            // A private page that gets write access stays read only, and the next write fault
            // makes it writable if this address space is its only user.
            let new = self.soft_prot(a, page_prot(vma, false));
            // A huge page that is all in the range keeps one entry.
            if a.is_multiple_of(HUGE_PAGE_SIZE)
                && a + HUGE_PAGE_SIZE <= end.min(vma.end)
                && self.vm.protect_huge(page, new)
            {
                next = a + HUGE_PAGE_SIZE;
                continue;
            }
            self.vm.protect(page, new);
        }
        Ok(())
    }

    /// Moves the end of the heap to `addr`, and gives the new end. A bad value gives the old end,
    /// as Linux does.
    #[cfg_attr(feature = "corten", allow(unreachable_code))]
    pub fn brk(&self, addr: usize) -> usize {
        #[cfg(feature = "corten")]
        return self.corten_brk(addr);
        let mut st = self.state.lock();
        let (Some(old_end), Some(new_end)) = (page_up(st.brk), page_up(addr)) else {
            return st.brk;
        };
        if addr < st.brk_start || st.brk_start == 0 || new_end > MMAP_TOP {
            return st.brk;
        }
        if new_end > old_end {
            if st.vmas.overlaps(old_end, new_end) || charge_commit(new_end - old_end).is_err() {
                return st.brk;
            }
            let mut vma = Vma::anon(old_end, new_end, Prot::RW, VmaKind::Heap);
            vma.locked = st.lock_future;
            vma.account = true;
            st.vmas.insert_merged(vma);
            self.soft.mapped(old_end, new_end);
        } else if new_end < old_end {
            self.unmap_locked(&mut st, new_end, old_end);
        }
        st.brk = addr;
        addr
    }

    /// Handles a page fault at `addr`.
    ///
    /// # Errors
    ///
    /// Gives `EFAULT` if no area contains the address or the area does not allow the access. The
    /// kernel then sends `SIGSEGV`. Gives `ENOMEM` if no frame is free. Gives the error of the
    /// file for a page that the file cannot give, such as a page past the end of the file. The
    /// kernel then sends `SIGBUS`.
    pub fn handle_fault(&self, addr: usize, access: Access) -> Result<(), Errno> {
        #[cfg(feature = "corten")]
        return self.corten_fault(addr, access);
        #[cfg(not(feature = "corten"))]
        let mut prepared = None;
        #[cfg(not(feature = "corten"))]
        loop {
            let st = self.state.read();
            let Some(vma) = st.vmas.find(addr) else {
                drop(st);
                // A fault below an area that grows down makes the area larger, up to the size of
                // the main stack, as Linux does with the default `RLIMIT_STACK`. This changes the
                // areas, so it takes the lock for a write, as `expand_stack` of Linux does.
                let mut st = self.state.lock();
                if st.vmas.find(addr).is_none() {
                    self.grow_stack(&mut st, addr)?;
                }
                continue;
            };
            // A guard page gives `SIGSEGV`, as `handle_pte_marker` of Linux.
            if !st.guards.is_empty() && st.guards.contains(&(addr & !(PAGE_SIZE - 1))) {
                return Err(Errno::EFAULT);
            }
            // The read of a page of a file can wait for the disk. It runs with no lock held, and
            // the fault then starts again, as `filemap_fault` of Linux with `FAULT_FLAG_RETRY`.
            if prepared.is_none()
                && let Some((file, index)) = self.read_first(vma, addr, access)
            {
                drop(st);
                let frame = file.page(index)?;
                prepared = Some(Prepared { file, index, frame });
                continue;
            }
            let _block = self.state.fault_lock(addr).lock();
            return self.fault_area(vma, addr, access, prepared.as_ref());
        }
    }

    /// Gives the file and the index of the page that a fault at `addr` in `vma` must read from
    /// the file first, or `None` if the fault does not read the file. The page is not mapped and
    /// the file must read it ([`MmFile::ready`] is `false`).
    fn read_first(
        &self,
        vma: &Vma<FileRef>,
        addr: usize,
        access: Access,
    ) -> Option<(FileRef, u64)> {
        let Backing::File { file, offset } = &vma.backing else { return None };
        let page = addr & !(PAGE_SIZE - 1);
        if vma.hugetlb || !allowed(vma, access) || self.vm.page(VirtAddr::new(page)).is_some() {
            return None;
        }
        let index = file_index(vma, *offset, page);
        (!file.ready(index)).then(|| (file.clone(), index))
    }

    /// Makes the area above `addr` grow down to the page of `addr`. The new pages keep the
    /// soft-dirty state of the area, as `expand_downwards` of Linux keeps `VM_SOFTDIRTY`.
    ///
    /// # Errors
    ///
    /// `EFAULT` if no area grows down to `addr`.
    fn grow_stack(&self, st: &mut State, addr: usize) -> Result<(), Errno> {
        let old = st.vmas.grow_down(addr, STACK_GUARD_GAP, STACK_SIZE).ok_or(Errno::EFAULT)?;
        self.soft.grew(addr & !(PAGE_SIZE - 1), old);
        Ok(())
    }

    /// Handles a page fault at `addr` in `vma`, the area that has the address. The caller holds
    /// the lock of the area, and no other fault in the 2 MiB block of `addr` runs.
    fn fault_area(
        &self,
        vma: &Vma<FileRef>,
        addr: usize,
        access: Access,
        prepared: Option<&Prepared>,
    ) -> Result<(), Errno> {
        self.fault_page(vma, addr, access, prepared)?;
        self.soft.when_tracking(|soft| {
            // A huge page has one soft-dirty state, as the entry of a PMD of Linux.
            let page = VirtAddr::new(addr & !(PAGE_SIZE - 1));
            let (start, end) = if self.vm.is_huge(page) {
                let block = addr & !(HUGE_PAGE_SIZE - 1);
                (block, block + HUGE_PAGE_SIZE)
            } else {
                (page.get(), page.get() + PAGE_SIZE)
            };
            if access == Access::Write {
                soft.wrote(start, end);
            } else if soft.any_clean(start, end) {
                // A read fault can map a writable page. A clean page stays read only, so the
                // first write is a fault that marks it.
                self.vm.write_protect(VirtAddr::new(start), VirtAddr::new(end));
            }
        });
        Ok(())
    }

    /// `fault_area` without the soft-dirty state. `prepared` is a page of the file that the
    /// fault read before with no lock held.
    fn fault_page(
        &self,
        vma: &Vma<FileRef>,
        addr: usize,
        access: Access,
        prepared: Option<&Prepared>,
    ) -> Result<(), Errno> {
        if !allowed(vma, access) {
            return Err(Errno::EFAULT);
        }
        let page = addr & !(PAGE_SIZE - 1);
        let at = VirtAddr::new(page);
        let write = access == Access::Write;
        if vma.hugetlb && self.hugetlb_fault(vma, page, write)? {
            return Ok(());
        }
        // A write to a transparent huge page that is read only after `fork`.
        if write && !vma.shared && !vma.hugetlb && self.thp_cow(vma, page) {
            return Ok(());
        }
        match self.vm.page(at) {
            // The first write to a range of an anonymous area can get a huge page.
            None if write && self.map_huge(vma, page) => Ok(()),
            None => {
                let mut dirty = None;
                let (frame, exclusive) = match &vma.backing {
                    Backing::Anon => (anon_frame(self.memcg())?, true),
                    Backing::File { file, offset } => {
                        let index = file_index(vma, *offset, page);
                        // A file with a page cache has the page now, and gives the frame of the
                        // cache, which a write or a truncate after the read changed. Another
                        // file gives the frame of the read.
                        let frame = match prepared {
                            Some(p) if same_file(&p.file, file) && p.index == index => {
                                if file.ready(index) { file.page(index)? } else { p.frame.clone() }
                            }
                            _ => file.page(index)?,
                        };
                        if vma.shared {
                            if write {
                                dirty = Some((file, index));
                            }
                            (frame, write)
                        } else if !write {
                            (frame, false)
                        } else {
                            (copy_frame(&frame, self.memcg())?, true)
                        }
                    }
                };
                self.vm.map(at, frame, page_prot(vma, exclusive)).map_err(map_error)?;
                // The page is dirty after it is writable, so a write back that runs between the
                // two steps cannot make the page clean and leave it writable.
                if let Some((file, index)) = dirty {
                    file.dirty(index, self.write_map(page));
                }
                Ok(())
            }
            Some((frame, prot)) => {
                if !write || prot.writable {
                    // Another fault mapped the page, or the page allows the access now.
                    return Ok(());
                }
                // The first write to a page of a shared file mapping.
                if vma.shared {
                    drop(frame);
                    self.vm.protect(at, page_prot(vma, true));
                    if let Backing::File { file, offset } = &vma.backing {
                        file.dirty(file_index(vma, *offset, page), self.write_map(page));
                    }
                    return Ok(());
                }
                // A write to a private page that is read only: copy on write. The page table and
                // `frame` hold two references. A third reference is another address space or the
                // page cache.
                if Arc::strong_count(&frame) == 2 && !matches!(vma.backing, Backing::File { .. }) {
                    drop(frame);
                    self.vm.protect(at, page_prot(vma, true));
                    return Ok(());
                }
                let copy = copy_frame(&frame, self.memcg())?;
                drop(frame);
                self.vm.unmap(at);
                self.vm.map(at, copy, page_prot(vma, true)).map_err(map_error)
            }
        }
    }

    /// Handles a fault in a hugetlb area, as `hugetlb_fault` of Linux. Gives `false` if the 2 MiB
    /// range of `page` is not all in the area or has 4 KiB pages after a split, so the fault
    /// takes the path of 4 KiB pages.
    ///
    /// # Errors
    ///
    /// `ENOSPC` if the pool has no page, and `ENXIO` for a page after the end of the file. The
    /// kernel then sends `SIGBUS`.
    fn hugetlb_fault(&self, vma: &Vma<FileRef>, page: usize, write: bool) -> Result<bool, Errno> {
        let block = page & !(HPAGE_SIZE - 1);
        if block < vma.start || block + HPAGE_SIZE > vma.end {
            return Ok(false);
        }
        let at = VirtAddr::new(block);
        if let Some((_, prot)) = self.vm.page(VirtAddr::new(page))
            && (!write || prot.writable)
        {
            return Ok(true);
        }
        // A private page of a file of hugetlbfs takes a page of the mount.
        let subpool = match &vma.backing {
            Backing::File { file, .. } => file.huge_file().and_then(hugetlb::HugeFile::subpool),
            Backing::Anon => None,
        };
        if let Some((frames, _)) = self.vm.huge_block(at) {
            // A write to a page that is read only. The page table and `frames` hold two
            // references to a page that only this address space uses.
            if vma.shared || Arc::strong_count(&frames[0]) == 2 {
                drop(frames);
                return Ok(self.vm.protect_huge(at, page_prot(vma, true)));
            }
            let copy = self.take_huge(block, Some(&frames), subpool)?;
            drop(frames);
            self.unmap_pages(at, VirtAddr::new(block + HPAGE_SIZE));
            self.vm.map_hugetlb(at, copy, page_prot(vma, true)).map_err(map_error)?;
            return Ok(true);
        }
        if self.vm.pages_in(at, VirtAddr::new(block + HPAGE_SIZE)) != 0 {
            return Ok(false);
        }
        let (huge, exclusive) = match &vma.backing {
            Backing::Anon => (self.take_huge(block, None, None)?, true),
            Backing::File { file, offset } => {
                let Some(file) = file.huge_file() else { return Ok(false) };
                let index = (offset + (block - vma.start) as u64) / HPAGE_SIZE as u64;
                if vma.shared {
                    (file.page_at(index)?, true)
                } else if index >= file.size().div_ceil(HPAGE_SIZE as u64) {
                    return Err(Errno::ENXIO);
                } else {
                    // A private mapping reads the page of the file, and a write copies it. A
                    // page that the file does not have is a new private page, as on Linux.
                    match file.lookup(index) {
                        Some(cached) if !write => (cached, false),
                        Some(cached) => (self.take_huge(block, Some(&cached), subpool)?, true),
                        None => (self.take_huge(block, None, subpool)?, true),
                    }
                }
            }
        };
        self.vm.map_hugetlb(at, huge, page_prot(vma, exclusive)).map_err(map_error)?;
        Ok(true)
    }

    /// Takes a huge page for the private hugetlb `block`, with the reservation of the block if it
    /// has one, and copies `from` to it. A block of a mapping of a file of hugetlbfs takes the page
    /// from `subpool`, the pages of the mount of the file.
    fn take_huge(
        &self,
        block: usize,
        from: Option<&[Arc<Frame>]>,
        subpool: Option<&Arc<Subpool>>,
    ) -> Result<hugetlb::HugePage, Errno> {
        let resv = self.huge_resv.lock().remove(&block);
        let reserved = resv.is_some();
        let page = match (subpool, from) {
            (Some(subpool), from) => hugetlb::private_page(subpool, reserved, from),
            (None, Some(from)) => hugetlb::copy_page(from, reserved),
            (None, None) => hugetlb::alloc_page(reserved),
        };
        if page.is_err()
            && let Some(resv) = resv
        {
            self.huge_resv.lock().insert(block, resv);
        }
        // A private huge page is anonymous memory, as `hugetlb_add_new_anon_rmap` of Linux.
        if let Ok(frames) = &page {
            frames.iter().for_each(|f| f.set_anon());
        }
        page
    }

    /// Handles a write to a transparent huge page that is read only, as `do_huge_pmd_wp_page` of
    /// Linux. A page that only this address space uses becomes writable, and else the space gets
    /// a copy of the whole huge page. Gives `false` if there is no such page or no memory for the
    /// copy, so the fault copies one page of 4 KiB and splits the huge page.
    fn thp_cow(&self, vma: &Vma<FileRef>, page: usize) -> bool {
        let block = page & !(HUGE_PAGE_SIZE - 1);
        let at = VirtAddr::new(block);
        let Some((frames, prot)) = self.vm.huge_block(at) else { return false };
        if prot.writable || !matches!(vma.backing, Backing::Anon) {
            return false;
        }
        if frames.iter().all(|f| Arc::strong_count(f) == 2) {
            drop(frames);
            return self.vm.protect_huge(at, page_prot(vma, true));
        }
        let Some(copy) = hugetlb::copy_thp(&frames, self.memcg()) else { return false };
        drop(frames);
        self.unmap_pages(at, VirtAddr::new(block + HUGE_PAGE_SIZE));
        self.vm.map_huge(at, copy, page_prot(vma, true)).is_ok()
    }

    /// Maps a huge page at the 2 MiB range of `page`, if the policy and the area allow it. The
    /// area is private anonymous memory that KSM does not merge, the range is all in the area, and
    /// no page of the range has a frame. Gives `false` if the page needs a 4 KiB frame.
    fn map_huge(&self, vma: &Vma<FileRef>, page: usize) -> bool {
        let allowed = match tunables::thp_enabled() {
            ThpMode::Always => vma.huge != HugeAdvice::NoHuge,
            ThpMode::Madvise => vma.huge == HugeAdvice::Huge,
            ThpMode::Never => false,
        };
        let block = page & !(HUGE_PAGE_SIZE - 1);
        // KSM merges 4 KiB pages, so a mergeable area gets 4 KiB pages, and `ksmd` does not split
        // blocks. A memory cgroup takes the charge of the whole block.
        if !allowed
            || vma.mergeable
            || self.ksm_any()
            || vma.shared
            || !matches!(vma.backing, Backing::Anon)
            || block < vma.start
            || block + HUGE_PAGE_SIZE > vma.end
        {
            return false;
        }
        let range = (VirtAddr::new(block), VirtAddr::new(block + HUGE_PAGE_SIZE));
        if self.vm.pages_in(range.0, range.1) != 0 {
            return false;
        }
        let stats = frame_stats();
        if stats.free < HUGE_FRAMES + tunables::reserve_pages(stats.total) {
            return false;
        }
        let Some(frames) = alloc_huge_frames() else { return false };
        let Some(frames) = charge_block(frames, self.memcg()) else { return false };
        self.vm.map_huge(range.0, frames, page_prot(vma, true)).is_ok()
    }

    /// Sets the advice for huge pages of the areas in `addr..addr + len`, for `MADV_HUGEPAGE`
    /// and `MADV_NOHUGEPAGE`. The pages that the areas have do not change.
    ///
    /// # Errors
    ///
    /// `ENOMEM` if a page of the range is not mapped.
    pub fn set_huge_advice(
        &self,
        addr: usize,
        len: usize,
        advice: HugeAdvice,
    ) -> Result<(), Errno> {
        let (start, end) = Self::lock_range(addr, len)?;
        let mut st = self.state.lock();
        if !st.vmas.covers(start, end) {
            return Err(Errno::ENOMEM);
        }
        st.vmas.update_range_merged(start, end, |vma| vma.huge = advice);
        Ok(())
    }

    /// Removes the frames of the pages in `addr..addr + len`, for `MADV_DONTNEED`. The next
    /// access to a page of anonymous memory gives zeros, and the next access to a page of a file
    /// gives the page of the file again.
    pub fn discard(&self, addr: usize, len: usize) {
        let Ok((start, end)) = Self::lock_range(addr, len) else { return };
        let st = self.state.lock();
        for vma in st.vmas.iter().filter(|v| v.start < end && start < v.end) {
            let (mut from, mut to) = (start.max(vma.start), end.min(vma.end));
            // A hugetlb area loses whole huge pages only, as on Linux.
            if vma.hugetlb {
                from = from.next_multiple_of(HPAGE_SIZE);
                to &= !(HPAGE_SIZE - 1);
            }
            if from < to {
                self.unmap_pages(VirtAddr::new(from), VirtAddr::new(to));
            }
        }
    }

    /// Tells if an area of the space maps a file of hugetlbfs.
    fn maps_huge_file(&self) -> bool {
        let st = self.state.lock();
        st.vmas
            .iter()
            .any(|v| matches!(&v.backing, Backing::File { file, .. } if file.huge_file().is_some()))
    }

    /// Removes the huge pages `first..end` of `file` from the areas that map them, as
    /// `hugetlb_vmdelete_list` of Linux. The areas stay, so a later access after the end of the
    /// file gets `SIGBUS`.
    fn unmap_huge_file(&self, file: &hugetlb::HugeFile, first: u64, end: u64) {
        let hpage = HPAGE_SIZE as u64;
        let st = self.state.lock();
        for vma in st.vmas.iter() {
            let Backing::File { file: f, offset } = &vma.backing else { continue };
            if !f.huge_file().is_some_and(|h| core::ptr::eq(h, file)) {
                continue;
            }
            let lo = first.saturating_mul(hpage).max(*offset);
            let hi = end.saturating_mul(hpage).min(offset + vma.len() as u64);
            if lo < hi {
                let start = vma.start + (lo - offset) as usize;
                let stop = vma.start + (hi - offset) as usize;
                self.unmap_pages(VirtAddr::new(start), VirtAddr::new(stop));
            }
        }
    }

    /// Removes the frames of each private area, for the OOM reaper. A shared area keeps its
    /// frames, because other address spaces can map them. Gives the number of pages that were
    /// mapped before. The call does not allocate, so it works when the memory is short, as
    /// `__oom_reap_task_mm` of Linux.
    pub fn reap(&self) -> usize {
        let st = self.state.lock();
        let before = self.vm.page_count();
        for vma in st.vmas.iter().filter(|v| !v.shared) {
            self.vm.unmap_range(VirtAddr::new(vma.start), VirtAddr::new(vma.end));
        }
        before.saturating_sub(self.vm.page_count())
    }

    /// Makes the address space of a child of `fork`. A shared area maps the same frames. A
    /// private area maps the same frames read only in both address spaces, so the first write in
    /// either one copies the page. A huge page stays a huge page in both.
    ///
    /// # Errors
    ///
    /// Gives `ENOMEM` if no frame is free for a page table.
    pub fn fork(&self) -> Result<Self, Errno> {
        let soft = self.soft.get();
        #[cfg(feature = "corten")]
        let child = self.corten_fork()?;
        #[cfg(not(feature = "corten"))]
        let child = self.vma_fork()?;
        child.soft.set(soft);
        // A file that writes back does not know the pages of the child, so they become read only,
        // and the first write of the child marks them dirty.
        let st = child.state.lock();
        for vma in st.vmas.iter().filter(|v| v.shared) {
            if matches!(&vma.backing, Backing::File { file, .. } if file.writes_back()) {
                child.vm.write_protect(VirtAddr::new(vma.start), VirtAddr::new(vma.end));
            }
        }
        drop(st);
        Ok(child)
    }

    /// The entry of the reverse map for the page at `page` of this address space.
    fn write_map(&self, page: usize) -> WriteMap {
        WriteMap { vm: Arc::downgrade(&self.vm), addr: page }
    }

    /// Takes away the write access of `prot` if the page at `addr` is clean in the soft-dirty
    /// state, so that the next write is a fault that marks it. For a page of a huge page, each
    /// page of the huge page counts.
    fn soft_prot(&self, addr: usize, mut prot: PageProt) -> PageProt {
        if prot.writable {
            self.soft.when_tracking(|soft| {
                let block = addr & !(HUGE_PAGE_SIZE - 1);
                let (start, end) = if self.vm.is_huge(VirtAddr::new(addr)) {
                    (block, block + HUGE_PAGE_SIZE)
                } else {
                    (addr, addr + PAGE_SIZE)
                };
                prot.writable = !soft.any_clean(start, end);
            });
        }
        prot
    }

    /// Makes all the pages of the address space clean in the soft-dirty state, as a write of 4 to
    /// `/proc/PID/clear_refs` of Linux. The pages become read only, so the next write to a page is
    /// a fault that marks it soft-dirty.
    pub fn clear_soft_dirty(&self) {
        let st = self.state.lock();
        let ranges: Vec<(usize, usize)> = st.vmas.iter().map(|v| (v.start, v.end)).collect();
        // The faults hold the lock of the areas, so no fault runs between the two steps.
        self.soft.with(|soft| soft.clear(ranges.iter().copied()));
        for (start, end) in ranges {
            self.vm.write_protect(VirtAddr::new(start), VirtAddr::new(end));
        }
        drop(st);
    }

    /// Tells if the page at `addr` is soft-dirty. `present` tells that the page has a frame. See
    /// [`crate::softdirty::SoftDirty::is_dirty`].
    pub fn soft_dirty(&self, addr: usize, present: bool) -> bool {
        self.soft.is_dirty(addr, present)
    }

    /// Tells if the area `start..end` has the flag `VM_SOFTDIRTY` of Linux, for the line
    /// `VmFlags` of `/proc/PID/smaps`. Before the first clear, each area has it.
    pub fn area_soft_dirty(&self, start: usize, end: usize) -> bool {
        !self.soft.tracking() || self.soft.with(|soft| soft.area_dirty(start, end))
    }

    /// Sets the high water mark of the pages with a frame to the pages that have a frame now, as a
    /// write of 5 to `/proc/PID/clear_refs` of Linux.
    pub fn reset_hiwater(&self) {
        self.hiwater.store(self.page_count(), Ordering::Relaxed);
    }

    /// `fork` of the VMA backend. It copies the list of areas.
    #[cfg(not(feature = "corten"))]
    fn vma_fork(&self) -> Result<Self, Errno> {
        let st = self.state.lock();
        // An area of `MADV_DONTFORK` does not go to the child, and an area of `MADV_WIPEONFORK`
        // goes without its pages, as `dup_mmap` in kernel/fork.c of Linux.
        let copied = |v: &&Vma<FileRef>| !v.dont_fork && !v.wipe_on_fork;
        let areas: Vec<ForkArea> = st
            .vmas
            .iter()
            .filter(copied)
            .map(|v| ForkArea { start: v.start, end: v.end, shared: v.shared })
            .collect();
        let child = Self::with_vm(Arc::new(self.vm.fork(&areas).map_err(map_error)?));
        child.mmap_top.store(self.mmap_top(), Ordering::Relaxed);
        // The private areas of the child go in the commit count. The memory of a shared area is
        // in the count one time.
        charge_commit(accounted(st.vmas.iter().filter(|v| !v.shared && !v.dont_fork)))?;
        // The child does not get the locks of the parent, as on Linux.
        let mut vmas = st.vmas.clone();
        let skipped: Vec<(usize, usize)> =
            st.vmas.iter().filter(|v| v.dont_fork).map(|v| (v.start, v.end)).collect();
        for (start, end) in skipped {
            vmas.remove_range(start, end);
        }
        vmas.update_range(0, USER_END, |vma| {
            vma.locked = false;
            vma.account &= !vma.shared;
            // An area of `MADV_WIPEONFORK` has no pages of the parent, and Linux gives it no
            // `anon_vma` in `dup_mmap`.
            if !vma.shared && !vma.wipe_on_fork {
                vma.fork_anon = next_fork_anon();
            }
        });
        // The guard pages of the areas with their pages go to the child, as the guard markers
        // that `copy_page_range` of Linux copies.
        let guards = if st.guards.is_empty() {
            BTreeSet::new()
        } else {
            let keep = |&&g: &&usize| st.vmas.find(g).is_some_and(|v| copied(&v));
            st.guards.iter().filter(keep).copied().collect()
        };
        *child.state.lock() = State {
            vmas,
            brk_start: st.brk_start,
            brk: st.brk,
            lock_future: false,
            guards,
            write_backs: Vec::new(),
        };
        Ok(child)
    }

    /// Removes the guard pages in `start..end`.
    fn remove_guards(st: &mut State, start: usize, end: usize) {
        if !st.guards.is_empty() {
            let inside: Vec<usize> = st.guards.range(start..end).copied().collect();
            for g in inside {
                st.guards.remove(&g);
            }
        }
    }

    /// Sets the fork advice of the areas in `addr..addr + len`: `MADV_DONTFORK` and
    /// `MADV_DOFORK` with `dont_fork`, `MADV_WIPEONFORK` and `MADV_KEEPONFORK` with `wipe`.
    ///
    /// # Errors
    ///
    /// `ENOMEM` if a page of the range is not mapped.
    pub fn set_fork_advice(
        &self,
        addr: usize,
        len: usize,
        dont_fork: Option<bool>,
        wipe: Option<bool>,
    ) -> Result<(), Errno> {
        let (start, end) = Self::lock_range(addr, len)?;
        let mut st = self.state.lock();
        if !st.vmas.covers(start, end) {
            return Err(Errno::ENOMEM);
        }
        st.vmas.update_range_merged(start, end, |vma| {
            if let Some(on) = dont_fork {
                vma.dont_fork = on;
            }
            if let Some(on) = wipe {
                vma.wipe_on_fork = on;
            }
        });
        Ok(())
    }

    /// Sets the dump advice of the areas in `addr..addr + len`: `MADV_DONTDUMP` with `true` and
    /// `MADV_DODUMP` with `false`, as `madvise_vma_behavior` in mm/madvise.c of Linux. A core
    /// dump does not hold the pages of an area with the advice.
    ///
    /// # Errors
    ///
    /// `ENOMEM` if a page of the range is not mapped.
    pub fn set_dump_advice(&self, addr: usize, len: usize, dont_dump: bool) -> Result<(), Errno> {
        let (start, end) = Self::lock_range(addr, len)?;
        let mut st = self.state.lock();
        if !st.vmas.covers(start, end) {
            return Err(Errno::ENOMEM);
        }
        st.vmas.update_range_merged(start, end, |vma| vma.dont_dump = dont_dump);
        Ok(())
    }

    /// Makes the pages in `addr..addr + len` guard pages, for `MADV_GUARD_INSTALL`, as
    /// `madvise_guard_install` in mm/madvise.c of Linux. The frames of the pages go away, and an
    /// access to a page gives `SIGSEGV` until `MADV_GUARD_REMOVE`.
    ///
    /// # Errors
    ///
    /// `ENOMEM` if a page of the range is not mapped, and `EINVAL` for a locked area or an area
    /// of hugetlbfs.
    pub fn guard_install(&self, addr: usize, len: usize) -> Result<(), Errno> {
        let (start, end) = Self::lock_range(addr, len)?;
        let mut st = self.state.lock();
        if !st.vmas.covers(start, end) {
            return Err(Errno::ENOMEM);
        }
        if st.vmas.iter().any(|v| v.start < end && start < v.end && (v.locked || v.hugetlb)) {
            return Err(Errno::EINVAL);
        }
        self.unmap_pages(VirtAddr::new(start), VirtAddr::new(end));
        st.guards.extend((start..end).step_by(PAGE_SIZE));
        Ok(())
    }

    /// Tells if the page at `addr` is a guard page of `MADV_GUARD_INSTALL`, for `PM_GUARD_REGION`
    /// of `/proc/PID/pagemap`.
    pub fn is_guard(&self, addr: usize) -> bool {
        let page = addr & !(PAGE_SIZE - 1);
        #[cfg(feature = "corten")]
        return self.corten_is_guard(page);
        #[cfg(not(feature = "corten"))]
        {
            let st = self.state.lock();
            !st.guards.is_empty() && st.guards.contains(&page)
        }
    }

    /// Removes the guard pages in `addr..addr + len`, for `MADV_GUARD_REMOVE`. The next access to
    /// a page gives a new page, as `madvise_guard_remove` in mm/madvise.c of Linux.
    ///
    /// # Errors
    ///
    /// `ENOMEM` if a page of the range is not mapped, and `EINVAL` for an area of hugetlbfs.
    pub fn guard_remove(&self, addr: usize, len: usize) -> Result<(), Errno> {
        let (start, end) = Self::lock_range(addr, len)?;
        let mut st = self.state.lock();
        if !st.vmas.covers(start, end) {
            return Err(Errno::ENOMEM);
        }
        if st.vmas.iter().any(|v| v.start < end && start < v.end && v.hugetlb) {
            return Err(Errno::EINVAL);
        }
        Self::remove_guards(&mut st, start, end);
        Ok(())
    }

    /// Copies user memory at `addr` to `buf`. A page that is not there yet gets its frame.
    ///
    /// # Errors
    ///
    /// Gives `EFAULT` if a byte of the range is not in an area that allows a read.
    pub fn read(&self, addr: usize, buf: &mut [u8]) -> Result<(), Errno> {
        let mut done = 0;
        while done < buf.len() {
            match self.vm.read(VirtAddr::new(addr + done), &mut buf[done..]) {
                Ok(()) => return Ok(()),
                Err(UserFault { addr: at, .. }) => {
                    self.fault_in(at, Access::Read)?;
                    done = at - addr;
                }
            }
        }
        Ok(())
    }

    /// Copies `buf` to user memory at `addr`. A page that is read only after `fork` is copied.
    ///
    /// # Errors
    ///
    /// Gives `EFAULT` if a byte of the range is not in an area that allows a write.
    pub fn write(&self, addr: usize, buf: &[u8]) -> Result<(), Errno> {
        let mut done = 0;
        while done < buf.len() {
            match self.vm.write(VirtAddr::new(addr + done), &buf[done..]) {
                Ok(()) => return Ok(()),
                Err(UserFault { addr: at, .. }) => {
                    self.fault_in(at, Access::Write)?;
                    done = at - addr;
                }
            }
        }
        Ok(())
    }

    /// Writes `new` to the aligned 32 bit word at `addr` if the word has the value `old`, in one
    /// atomic operation, and gives the value that the word had. A page that is read only after
    /// `fork` is copied first.
    ///
    /// # Errors
    ///
    /// Gives `EFAULT` if the word is not in an area that allows a write, and `EINVAL` if `addr`
    /// is not aligned.
    pub fn compare_exchange_u32(&self, addr: usize, old: u32, new: u32) -> Result<u32, Errno> {
        if !addr.is_multiple_of(4) {
            return Err(Errno::EINVAL);
        }
        loop {
            match self.vm.compare_exchange_u32(VirtAddr::new(addr), old, new) {
                Ok(value) => return Ok(value),
                Err(UserFault { addr: at, .. }) => self.fault_in(at, Access::Write)?,
            }
        }
    }

    /// Copies `buf` to user memory at `addr`, also to a private page that is read only, such as
    /// the code of the program. The page gets a private copy first, so the file and the other
    /// processes do not see the change. This is the write of `ptrace` with `FOLL_FORCE`.
    ///
    /// # Errors
    ///
    /// Gives `EFAULT` if a byte of the range is not mapped, or is in a shared area that does not
    /// allow a write, and `ENOMEM` if no frame is free for the copy.
    pub fn write_force(&self, addr: usize, buf: &[u8]) -> Result<(), Errno> {
        let mut done = 0;
        while done < buf.len() {
            let at = addr + done;
            let offset = at & (PAGE_SIZE - 1);
            let len = (PAGE_SIZE - offset).min(buf.len() - done);
            let chunk = &buf[done..done + len];
            done += len;
            if self.write(at, chunk).is_ok() {
                continue;
            }
            self.handle_fault(at, Access::Read)?;
            let st = self.state.lock();
            let vma = st.vmas.find(at).ok_or(Errno::EFAULT)?;
            if vma.shared {
                return Err(Errno::EFAULT);
            }
            let page = VirtAddr::new(at & !(PAGE_SIZE - 1));
            let (frame, _) = self.vm.page(page).ok_or(Errno::EFAULT)?;
            let copy = copy_frame(&frame, self.memcg())?;
            drop(frame);
            copy.write_bytes(offset, chunk);
            self.vm.unmap(page);
            self.vm.map(page, copy, page_prot(vma, true)).map_err(map_error)?;
        }
        Ok(())
    }

    /// Fills `len` bytes of user memory at `addr` with zeros.
    ///
    /// # Errors
    ///
    /// As for `write`.
    pub fn fill_zero(&self, addr: usize, len: usize) -> Result<(), Errno> {
        let mut done = 0;
        while done < len {
            match self.vm.fill_zero(VirtAddr::new(addr + done), len - done) {
                Ok(()) => return Ok(()),
                Err(UserFault { addr: at, .. }) => {
                    self.fault_in(at, Access::Write)?;
                    done = at - addr;
                }
            }
        }
        Ok(())
    }

    /// Reads a string that ends with a zero byte, without the zero byte.
    ///
    /// # Errors
    ///
    /// Gives `EFAULT` for a bad address, and `ENAMETOOLONG` if no zero byte is in the first `max`
    /// bytes.
    pub fn read_cstr(&self, addr: usize, max: usize) -> Result<Vec<u8>, Errno> {
        // Most strings are short, as the arguments and the environment of an exec, so the string
        // is read in small chunks and not in a page each time.
        const CHUNK: usize = 128;
        let mut out = Vec::new();
        let mut at = addr;
        let mut chunk = [0u8; CHUNK];
        while out.len() < max {
            // Read up to the end of the page at most, so a string at the end of an area works.
            let n = (PAGE_SIZE - at % PAGE_SIZE).min(max - out.len()).min(CHUNK);
            self.read(at, &mut chunk[..n])?;
            if let Some(zero) = chunk[..n].iter().position(|&b| b == 0) {
                out.extend_from_slice(&chunk[..zero]);
                return Ok(out);
            }
            out.extend_from_slice(&chunk[..n]);
            at += n;
        }
        Err(Errno::ENAMETOOLONG)
    }

    /// Gives the physical address of `addr` if it is in a shared area, else `None`. A futex in a
    /// shared area uses the physical address as its key, so that each address space that maps the
    /// page finds the same futex. A page that is not there yet gets its frame.
    ///
    /// # Errors
    ///
    /// Gives `EFAULT` if `addr` is not in an area that allows a read.
    pub fn shared_phys(&self, addr: usize) -> Result<Option<u64>, Errno> {
        let shared = self.with_area(addr, |v| match v {
            Some(vma) if vma.prot.read => Ok(vma.shared),
            _ => Err(Errno::EFAULT),
        })?;
        if !shared {
            return Ok(None);
        }
        self.fault_in(addr, Access::Read)?;
        let page = VirtAddr::new(addr & !(PAGE_SIZE - 1));
        let (frame, _) = self.vm.page(page).ok_or(Errno::EFAULT)?;
        Ok(Some(frame.addr().get() + (addr & (PAGE_SIZE - 1)) as u64))
    }

    fn fault_in(&self, addr: usize, access: Access) -> Result<(), Errno> {
        let page = VirtAddr::new(addr & !(PAGE_SIZE - 1));
        // A thread on another CPU can change the page after the fault, for example with `fork`,
        // which makes the private pages read only, or with `MADV_DONTNEED`. Then the fault runs
        // again, as the fault of Linux runs again after `fixup_user_fault`.
        for _ in 0..FAULT_TRIES {
            // A copy gives EFAULT also for a page that would be SIGBUS, as on Linux.
            self.handle_fault(addr, access).map_err(|e| match e {
                Errno::ENOMEM => e,
                _ => Errno::EFAULT,
            })?;
            if let Some((_, p)) = self.vm.page(page)
                && (access != Access::Write || p.writable)
            {
                return Ok(());
            }
        }
        Err(Errno::EFAULT)
    }
}

/// The most faults of `fault_in` for one page. A fault on another CPU can change the page after
/// each fault, but not each time.
const FAULT_TRIES: usize = 8;

/// Keeps only the `ENOMEM` error of a populate. A page that has another error, such as a file page
/// past the end of the file, gets the error at its first access, as on Linux.
fn only_enomem(r: Result<(), Errno>) -> Result<(), Errno> {
    match r {
        Err(Errno::ENOMEM) => Err(Errno::ENOMEM),
        _ => Ok(()),
    }
}

/// Tells if `vma` allows `access`.
fn allowed(vma: &Vma<FileRef>, access: Access) -> bool {
    match access {
        Access::Read => vma.prot.read || vma.prot.write || vma.prot.exec,
        Access::Write => vma.prot.write,
        Access::Exec => vma.prot.exec,
    }
}

/// Tells if `a` and `b` are the same file.
fn same_file(a: &FileRef, b: &FileRef) -> bool {
    core::ptr::addr_eq(Arc::as_ptr(a), Arc::as_ptr(b))
}

/// The index in the file of the page at `page` in `vma`, which maps the file from `offset`.
fn file_index(vma: &Vma<FileRef>, offset: u64, page: usize) -> u64 {
    (offset + (page - vma.start) as u64) / PAGE_SIZE as u64
}

/// Writes back the shared file pages of `vma` from `start` up to `end`.
#[cfg(feature = "corten")]
fn write_back(vma: &Vma<FileRef>, start: usize, end: usize) -> Result<(), Errno> {
    WriteBack::of(vma, start, end).map_or(Ok(()), WriteBack::run)
}

/// Charges a page to the memory cgroup `memcg`, and marks `frame` with the charge. A frame that
/// is not there, a frame from the reserve of the kernel ([`crate::USER_RESERVE`]) or a charge
/// past the limit gives `ENOMEM`.
fn charged(frame: Option<Frame>, memcg: u32) -> Result<Arc<Frame>, Errno> {
    let mut frame = frame.ok_or(Errno::ENOMEM)?;
    if rk_frame::mm::frame_stats().free < crate::USER_RESERVE {
        return Err(Errno::ENOMEM);
    }
    if memcg != 0 {
        rk_cgroup::charge_page(memcg).map_err(|_| Errno::ENOMEM)?;
        frame.set_memcg(memcg);
    }
    Ok(Arc::new(frame))
}

/// Charges the run `frames` of a transparent huge page to the memory cgroup `memcg` as one block,
/// and marks each frame with the charge. Gives `None` if the charge passes the limit, so the
/// fault takes a 4 KiB page.
fn charge_block(mut frames: Vec<Frame>, memcg: u32) -> Option<Vec<Arc<Frame>>> {
    if memcg != 0 {
        rk_cgroup::charge_pages(memcg, frames.len()).ok()?;
        for frame in &mut frames {
            frame.set_memcg(memcg);
        }
    }
    // A transparent huge page is anonymous memory.
    frames.iter().for_each(Frame::set_anon);
    Some(frames.into_iter().map(Arc::new).collect())
}

/// Tells if user memory can take a frame now.
fn above_reserve() -> Result<(), Errno> {
    let stats = frame_stats();
    if stats.free > tunables::reserve_pages(stats.total) { Ok(()) } else { Err(Errno::ENOMEM) }
}

/// A new anonymous page with zeros, charged to the memory cgroup `memcg`.
fn anon_frame(memcg: u32) -> Result<Arc<Frame>, Errno> {
    above_reserve()?;
    let frame = charged(alloc_zeroed_frame(), memcg)?;
    frame.set_anon();
    Ok(frame)
}

/// A copy of `from` for copy on write, charged to the memory cgroup `memcg`. The copy is
/// anonymous, also when `from` is a page of a file, as `wp_page_copy` of Linux makes it.
fn copy_frame(from: &Frame, memcg: u32) -> Result<Arc<Frame>, Errno> {
    above_reserve()?;
    let frame = charged(rk_frame::mm::alloc_frame(), memcg)?;
    frame.copy_from(from);
    frame.set_anon();
    Ok(frame)
}

//! The kernel side of KSM: the thread `ksmd`, the access to the page tables for the merge logic
//! of [`crate::ksm`], and the calls of `madvise`, `prctl`, `fork`, `execve` and procfs.
//!
//! The global state has a lock that no task holds while it blocks or yields. A task that holds it
//! takes the lock of an address space only with `try_lock`, because the holder of that lock can
//! block, and a spin on it with the global lock held can stop a system with one CPU.

use super::{AddressSpace, copy_frame, map_error, page_prot};
use crate::ksm::{self, Areas, Found, Hooks, Ksm, MmId, Pages, RUN_MERGE};
use crate::vma::Vma;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use rk_abi::Errno;
use rk_frame::addr::{PAGE_SIZE, VirtAddr};
use rk_frame::mm::{Frame, alloc_zeroed_frame};
use rk_frame::sync::{Once, SpinLock};
use rk_frame::task::{TaskOptions, WaitQueue, should_yield};

/// The KSM data of one address space.
#[derive(Debug, Default)]
pub(super) struct MmKsm {
    /// The number of the address space in KSM, or 0 before its first mergeable area. Linux marks
    /// such an address space with `MMF_VM_MERGEABLE`.
    id: AtomicU64,
    /// `PR_SET_MEMORY_MERGE`: each private area is mergeable. Linux names it `MMF_VM_MERGE_ANY`.
    merge_any: AtomicBool,
}

/// The address spaces in KSM, by number.
struct Spaces {
    map: BTreeMap<MmId, Weak<AddressSpace>>,
}

/// The state of KSM.
struct Global {
    ksm: Ksm<Arc<Frame>>,
    spaces: Spaces,
}

static GLOBAL: SpinLock<Global> =
    SpinLock::new(Global { ksm: Ksm::new(), spaces: Spaces { map: BTreeMap::new() } });

/// The numbers of the address spaces that ended. `Drop` cannot take the global lock, because the
/// last reference can go away while `ksmd` holds it.
static DEAD: SpinLock<Vec<MmId>> = SpinLock::new(Vec::new());

/// The next number of an address space.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// The number of address spaces in KSM.
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

/// A change for `ksmd`: a change of a setting or a new address space.
static EPOCH: AtomicU64 = AtomicU64::new(0);
static WAKE: WaitQueue = WaitQueue::new();
static STARTED: Once<()> = Once::new();

/// The page with zeros that `use_zero_pages` maps.
static ZERO: Once<Option<Arc<Frame>>> = Once::new();

/// Tells if KSM can merge the pages of the area. A shared area and a hugetlb area are never
/// mergeable.
fn eligible(vma: &Vma<super::FileRef>, merge_any: bool) -> bool {
    (vma.mergeable || merge_any) && !vma.shared && !vma.hugetlb
}

impl AddressSpace {
    /// Tells if `PR_SET_MEMORY_MERGE` makes each private area of this address space mergeable.
    pub(super) fn ksm_any(&self) -> bool {
        self.ksm.merge_any.load(Ordering::Relaxed)
    }
}

impl Spaces {
    fn get(&self, mm: MmId) -> Option<Arc<AddressSpace>> {
        self.map.get(&mm).and_then(Weak::upgrade)
    }
}

/// Tells if `vm` maps `frame` at `at`, and if only the page table and `held` other references use
/// the frame.
fn maps_only(vm: &AddressSpace, at: VirtAddr, frame: &Arc<Frame>, held: usize) -> bool {
    match vm.vm.page(at) {
        // The page table, the clone here and `held`.
        Some((f, _)) => Arc::ptr_eq(&f, frame) && Arc::strong_count(&f) == 2 + held,
        None => false,
    }
}

impl Pages for Spaces {
    type Frame = Arc<Frame>;

    fn pages_of(&mut self, mm: MmId) -> Areas {
        let Some(sp) = self.get(mm) else { return Areas::Gone };
        let Some(st) = sp.state.try_lock() else { return Areas::Busy };
        let any = sp.ksm_any();
        let mut pages = Vec::new();
        for vma in st.vmas.iter().filter(|v| eligible(v, any)) {
            // A large area needs a large list. When memory is short, the scan tries again later
            // and the kernel does not panic.
            if !sp.vm.try_mapped_pages(VirtAddr::new(vma.start), VirtAddr::new(vma.end), &mut pages)
            {
                return Areas::Busy;
            }
        }
        drop(st);
        Areas::Pages(pages)
    }

    fn frame(&mut self, mm: MmId, addr: usize) -> Found<Arc<Frame>> {
        let Some(sp) = self.get(mm) else { return Found::None };
        let Some(st) = sp.state.try_lock() else { return Found::Busy };
        let ok = st.vmas.find(addr).is_some_and(|v| eligible(v, sp.ksm_any()));
        drop(st);
        if !ok {
            return Found::None;
        }
        match sp.vm.page(VirtAddr::new(addr)) {
            Some((frame, _)) => {
                let exclusive = Arc::strong_count(&frame) == 2;
                Found::Page { frame, exclusive }
            }
            None => Found::None,
        }
    }

    fn key(&self, frame: &Arc<Frame>) -> u64 {
        frame.addr().get() as u64
    }

    fn checksum(&self, frame: &Arc<Frame>) -> u64 {
        // FNV-1a over the words of the page.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let mut buf = [0u8; CHUNK];
        for off in (0..PAGE_SIZE).step_by(CHUNK) {
            frame.read_bytes(off, &mut buf);
            for w in words(&buf) {
                h = (h ^ w).wrapping_mul(0x0100_0000_01b3);
            }
        }
        h
    }

    fn same_contents(&self, a: &Arc<Frame>, b: &Arc<Frame>) -> bool {
        if Arc::ptr_eq(a, b) {
            return true;
        }
        let (mut x, mut y) = ([0u8; CHUNK], [0u8; CHUNK]);
        (0..PAGE_SIZE).step_by(CHUNK).all(|off| {
            a.read_bytes(off, &mut x);
            b.read_bytes(off, &mut y);
            words(&x).eq(words(&y))
        })
    }

    fn is_zero(&self, frame: &Arc<Frame>) -> bool {
        let mut buf = [0u8; CHUNK];
        (0..PAGE_SIZE).step_by(CHUNK).all(|off| {
            frame.read_bytes(off, &mut buf);
            words(&buf).all(|w| w == 0)
        })
    }

    fn zero_frame(&mut self) -> Option<Arc<Frame>> {
        ZERO.call_once(|| alloc_zeroed_frame().map(Arc::new)).clone()
    }

    fn write_protect(&mut self, mm: MmId, addr: usize, frame: &Arc<Frame>) -> bool {
        let Some(sp) = self.get(mm) else { return false };
        let Some(st) = sp.state.try_lock() else { return false };
        let at = VirtAddr::new(addr);
        let Some(vma) = st.vmas.find(addr) else { return false };
        if !eligible(vma, sp.ksm_any()) || !maps_only(&sp, at, frame, 1) {
            return false;
        }
        // The protect flushes the TLB, so no CPU can write the page after it. A copy to user
        // memory on another CPU can hold the frame from before the protect and write it later,
        // so the count of references is checked again after the protect, as `write_protect_page`
        // of mm/ksm.c of Linux checks the count after `ptep_clear_flush`. The page then stays
        // read only, and a write makes it writable again without a copy.
        sp.vm.protect(at, page_prot(vma, false)) && maps_only(&sp, at, frame, 1)
    }

    fn replace(&mut self, mm: MmId, addr: usize, frame: &Arc<Frame>, kpage: &Arc<Frame>) -> bool {
        let Some(sp) = self.get(mm) else { return false };
        let Some(st) = sp.state.try_lock() else { return false };
        let at = VirtAddr::new(addr);
        let Some(vma) = st.vmas.find(addr) else { return false };
        if !eligible(vma, sp.ksm_any()) || !maps_only(&sp, at, frame, 1) {
            return false;
        }
        let prot = page_prot(vma, false);
        sp.vm.protect(at, prot);
        // A fault can make the page writable after `write_protect`, and a copy to user memory can
        // then hold the frame. Check the count again after the protect, as `write_protect_page`
        // of mm/ksm.c of Linux, so that no write comes after the compare.
        if !maps_only(&sp, at, frame, 1) {
            return false;
        }
        if !self.same_contents(frame, kpage) {
            // The page stays read only. A write to it makes it writable again, without a copy.
            return false;
        }
        // The lock of the address space stops a fault on the page between the two steps.
        sp.vm.unmap(at);
        if sp.vm.map(at, kpage.clone(), prot).is_err() {
            // The page table of the page is there, so this does not occur. Put the page back.
            let _ = sp.vm.map(at, frame.clone(), prot);
            return false;
        }
        // The page is a KSM page now, and `/proc/kpageflags` shows it. The zero page is not.
        if zero_phys() != Some(kpage.addr().get()) {
            kpage.set_ksm();
        }
        true
    }

    fn unshare(&mut self, mm: MmId, addr: usize, kpage: &Arc<Frame>) -> Result<(), Errno> {
        let Some(sp) = self.get(mm) else { return Ok(()) };
        let Some(st) = sp.state.try_lock() else { return Err(Errno::EAGAIN) };
        let at = VirtAddr::new(addr);
        let Some((frame, _)) = sp.vm.page(at) else { return Ok(()) };
        if !Arc::ptr_eq(&frame, kpage) {
            return Ok(());
        }
        let Some(vma) = st.vmas.find(addr) else { return Ok(()) };
        let copy = copy_frame(&frame, sp.memcg())?;
        sp.vm.unmap(at);
        sp.vm.map(at, copy, page_prot(vma, true)).map_err(map_error)
    }
}

/// The physical address of the page of zeros that KSM maps for the empty pages with
/// `use_zero_pages`, as the zero page of Linux, or `None` before KSM made it.
pub fn zero_phys() -> Option<u64> {
    ZERO.get().and_then(|z| z.as_ref()).map(|f| f.addr().get())
}

/// Removes the address spaces that ended.
fn reap(g: &mut Global) {
    let dead = core::mem::take(&mut *DEAD.lock());
    for mm in dead {
        g.ksm.remove_mm(mm);
        if g.spaces.map.remove(&mm).is_some() {
            ACTIVE.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Copies the counters to the files of sysfs.
fn publish(g: &Global) {
    let stats = g.ksm.stats();
    ksm::CONTROL.lock().stats = stats;
}

/// Runs `f` with the global state. `f` gives `EAGAIN` if an address space is busy. Then the task
/// lets the other tasks run and calls `f` again.
fn with_retry(mut f: impl FnMut(&mut Global) -> Result<(), Errno>) -> Result<(), Errno> {
    loop {
        let r = {
            let mut g = GLOBAL.lock();
            reap(&mut g);
            let r = f(&mut g);
            publish(&g);
            r
        };
        match r {
            // The task that holds the lock can wait for a timeout, so sleep for one tick.
            Err(Errno::EAGAIN) => nap(),
            r => return r,
        }
    }
}

/// The size of the parts of a page that the checksum and the compare copy at a time. One copy of
/// many bytes is faster than a call to read each word.
const CHUNK: usize = 1024;

/// The 8 byte words of `buf`.
fn words(buf: &[u8; CHUNK]) -> impl Iterator<Item = u64> + '_ {
    buf.chunks_exact(8)
        .map(|w| u64::from_ne_bytes([w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]]))
}

/// The number of pages that `ksmd` scans with one lock of the global state.
const SCAN_GROUP: usize = 32;

/// Sleeps for one tick. The CPU can then be idle, and the timeouts of the other tasks can end.
fn nap() {
    let deadline = rk_frame::time::ticks() + 1;
    WAKE.wait_until_timeout(deadline, || None::<()>);
}

fn unmerge_all() -> Result<(), Errno> {
    with_retry(|g| g.ksm.unmerge_all(&mut g.spaces))
}

fn wake() {
    EPOCH.fetch_add(1, Ordering::Release);
    WAKE.wake_all();
}

/// Adds `vm` to KSM, and starts `ksmd` the first time.
fn enter(vm: &Arc<AddressSpace>) {
    if vm.ksm.id.load(Ordering::Acquire) != 0 {
        return;
    }
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    if vm.ksm.id.compare_exchange(0, id, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return;
    }
    {
        let mut g = GLOBAL.lock();
        reap(&mut g);
        g.spaces.map.insert(id, Arc::downgrade(vm));
        g.ksm.add_mm(id);
        ACTIVE.fetch_add(1, Ordering::Relaxed);
    }
    STARTED.call_once(|| {
        ksm::set_hooks(Hooks { unmerge_all, wake });
        // A failure leaves KSM without its thread. The pages then do not merge.
        let _ = TaskOptions::new(ksmd).nice(5, false).spawn();
    });
    wake();
}

/// Gives each page of `vm` in `start..end` that maps a KSM page a copy, and forgets them.
fn unmerge(vm: &AddressSpace, start: usize, end: usize) -> Result<(), Errno> {
    let id = vm.ksm.id.load(Ordering::Acquire);
    if id == 0 {
        return Ok(());
    }
    with_retry(|g| g.ksm.unmerge_range(&mut g.spaces, id, start, end))
}

/// Records that the address space ended. `Drop` of [`AddressSpace`] calls it.
pub(super) fn exit(vm: &AddressSpace) {
    let id = vm.ksm.id.load(Ordering::Acquire);
    if id != 0 {
        DEAD.lock().push(id);
        wake();
    }
}

/// `madvise(MADV_MERGEABLE)` and `madvise(MADV_UNMERGEABLE)` for the pages in `start..end`. A
/// shared area and a hugetlb area do not change, as in Linux.
///
/// # Errors
///
/// `ENOMEM` if no frame is free for a copy of a KSM page.
pub fn madvise(vm: &Arc<AddressSpace>, start: usize, end: usize, merge: bool) -> Result<(), Errno> {
    vm.state.lock().vmas.update_range_merged(start, end, |v| {
        if !v.shared && !v.hugetlb {
            v.mergeable = merge;
        }
    });
    if merge {
        enter(vm);
        Ok(())
    } else {
        unmerge(vm, start, end)
    }
}

/// `prctl(PR_SET_MEMORY_MERGE)`. With `on`, each private area of `vm` is mergeable. Without it, no
/// area is mergeable, and each KSM page of `vm` gets a copy.
///
/// # Errors
///
/// `ENOMEM` if no frame is free for a copy of a KSM page.
pub fn set_merge_any(vm: &Arc<AddressSpace>, on: bool) -> Result<(), Errno> {
    if on {
        vm.ksm.merge_any.store(true, Ordering::Relaxed);
        enter(vm);
        return Ok(());
    }
    if !vm.ksm.merge_any.swap(false, Ordering::Relaxed) {
        return Ok(());
    }
    vm.state.lock().vmas.update_range_merged(0, rk_frame::vm::USER_END, |v| v.mergeable = false);
    unmerge(vm, 0, usize::MAX)
}

/// `prctl(PR_GET_MEMORY_MERGE)`.
pub fn merge_any(vm: &AddressSpace) -> bool {
    vm.ksm_any()
}

/// Adds the address space of a child of `fork` to KSM if the parent is in KSM. The child has the
/// areas of the parent with their `mergeable` flags, and keeps `merge_any`, as in Linux.
pub fn fork(parent: &AddressSpace, child: &Arc<AddressSpace>) {
    child.ksm.merge_any.store(parent.ksm_any(), Ordering::Relaxed);
    if parent.ksm.id.load(Ordering::Acquire) != 0 {
        enter(child);
    }
}

/// Keeps `merge_any` in the new address space of `execve`, as Linux does.
pub fn exec(old: &AddressSpace, new: &Arc<AddressSpace>) {
    if old.ksm_any() {
        new.ksm.merge_any.store(true, Ordering::Relaxed);
        enter(new);
    }
}

/// The counters of `vm`.
fn mm_stats(vm: &AddressSpace) -> ksm::MmStats {
    let id = vm.ksm.id.load(Ordering::Acquire);
    if id == 0 {
        return ksm::MmStats::default();
    }
    let mut g = GLOBAL.lock();
    reap(&mut g);
    g.ksm.mm_stats(id)
}

/// The text of `/proc/PID/ksm_stat`.
pub fn stat(vm: &AddressSpace) -> Vec<u8> {
    let mergeable = vm.ksm.id.load(Ordering::Acquire) != 0;
    ksm::stat_text(&mm_stats(vm), vm.ksm_any(), mergeable).into_bytes()
}

/// The text of `/proc/PID/ksm_merging_pages`.
pub fn merging_pages(vm: &AddressSpace) -> Vec<u8> {
    alloc::format!("{}\n", mm_stats(vm).merging_pages).into_bytes()
}

/// The ticks of `ms` milliseconds, at least one.
fn ms_to_ticks(ms: u32) -> u64 {
    (u64::from(ms) * rk_frame::time::HZ).div_ceil(1000).max(1)
}

/// The thread `ksmd`. It scans `pages_to_scan` pages, sleeps `sleep_millisecs`, and does it again
/// while `run` is 1 and an address space has mergeable areas.
fn ksmd() {
    loop {
        WAKE.wait_until(|| {
            let run = ksm::CONTROL.lock().tun.run;
            let work = run == RUN_MERGE && ACTIVE.load(Ordering::Relaxed) > 0;
            (work || !DEAD.lock().is_empty()).then_some(())
        });
        {
            let mut g = GLOBAL.lock();
            reap(&mut g);
            publish(&g);
        }
        let tun = ksm::CONTROL.lock().tun;
        if tun.run != RUN_MERGE || ACTIVE.load(Ordering::Relaxed) == 0 {
            continue;
        }
        let mut left = (tun.pages_to_scan as usize).max(1);
        while left > 0 {
            // A small group of pages for each lock keeps the cost of the lock low.
            let n = left.min(SCAN_GROUP);
            left -= n;
            let ended = {
                let mut guard = GLOBAL.lock();
                let g = &mut *guard;
                // A write of 2 to `run` sets `run` and then unmerges with this lock. Read `run`
                // with the lock, so that no scan adds an item after the unmerge.
                if ksm::CONTROL.lock().tun.run != RUN_MERGE {
                    break;
                }
                reap(g);
                let ended = g.ksm.scan(&mut g.spaces, &tun, n);
                publish(g);
                ended
            };
            if ended {
                break;
            }
            if should_yield() {
                nap();
            }
        }
        // The kernel runs with interrupts off, and the timeouts of the other tasks end only when
        // the CPU is idle. So `ksmd` sleeps for one tick at least, also when `sleep_millisecs` is
        // 0. With a yield only, a task that sleeps would not wake up again.
        let epoch = EPOCH.load(Ordering::Acquire);
        let deadline = rk_frame::time::ticks() + ms_to_ticks(tun.sleep_millisecs);
        WAKE.wait_until_timeout(deadline, || {
            (EPOCH.load(Ordering::Acquire) != epoch).then_some(())
        });
    }
}

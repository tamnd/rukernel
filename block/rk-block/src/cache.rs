//! The page cache: the data of a disk or a file in memory, from mm/filemap.c of Linux.
//!
//! The cache keeps the data in folios of up to `FOLIO_SIZE` bytes. A folio has `FOLIO_PAGES`
//! pages, and each page is up to date or not, and dirty or not. A read of a page that is not up
//! to date reads all such pages of the folio in one batch, so a read of one page also reads the
//! pages near it. A write of a whole page does not read the page.
//!
//! A write makes its pages dirty. The dirty pages go to the store in three cases: `sync` and
//! `write_back` of a range, and a write that puts the dirty data of the cache above
//! `DIRTY_LIMIT`. The write then waits for the write back, as `balance_dirty_pages` of Linux. All
//! the dirty pages go in one batch, thus the block layer merges and sorts them.
//!
//! When the cache holds more than `CACHE_LIMIT` bytes, it drops the clean folios that were used
//! least recently.
//!
//! A new folio is charged to the memory cgroup of the task that makes it, as
//! `mem_cgroup_charge` of Linux, through the functions of `set_memcg_ops`. A charged folio does
//! not count for `CACHE_LIMIT`. The memory cgroup takes it back with `reclaim`, and the charged
//! folios of all caches stay below `MemcgOps::limit`.
//!
//! The lock of the cache is not held while the store does a bio, as Linux does the I/O of the
//! page cache with the folio lock (`PG_locked`) and the writeback flag (`PG_writeback`), and holds
//! the lock of the xarray of the mapping only for a short time. A folio that a read fills is
//! locked: a second read of its pages waits for the first one, and the folio does not go from the
//! cache. The pages that a write back sends are under write back: they become clean when the
//! write back starts, a `write_back` of their range waits for them, and the folio does not go
//! from the cache. A write can change a page under write back, because a bio has its own copy of
//! the data. The page is then dirty again.
//!
//! A read in `without_wait` does not read from the store. If a page that it needs is not up to
//! date, it gives `EAGAIN`, as a read with `IOCB_NOWAIT` in `filemap_read` of Linux.

use crate::{Bio, Op, Result, SECTOR_SIZE};
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use rk_abi::Errno;
use rk_frame::sync::{Once, SpinLock, SpinLockGuard};

/// The size of a page.
pub const PAGE_SIZE: usize = 4096;
/// The number of pages in a folio.
pub const FOLIO_PAGES: usize = 16;
/// The largest size of a folio: 64 KiB.
pub const FOLIO_SIZE: usize = PAGE_SIZE * FOLIO_PAGES;
/// The dirty data above which a write waits for the write back.
pub const DIRTY_LIMIT: usize = 4 << 20;
/// The data above which the cache drops clean folios.
pub const CACHE_LIMIT: usize = 32 << 20;

/// The store under a cache, for example the request queue of a disk. A bio has a sector of
/// the store, from 0 to `size / SECTOR_SIZE`.
pub trait Store: Send + Sync {
    /// The size in bytes. It is a multiple of `SECTOR_SIZE`.
    fn size(&self) -> u64;

    /// Does the bios of `bios` and sets the result of each.
    fn submit(&self, bios: &mut [Bio]);

    /// Makes the data of the completed writes durable.
    ///
    /// # Errors
    ///
    /// Gives the error of the store.
    fn flush(&self) -> Result<()>;

    /// Tells if the store can discard data.
    fn can_discard(&self) -> bool {
        false
    }

    /// Discards the `len` bytes from `offset`. Both are multiples of `SECTOR_SIZE`.
    ///
    /// # Errors
    ///
    /// Gives `EOPNOTSUPP` if the store cannot discard, or the error of the store.
    fn discard(&self, _offset: u64, _len: u64) -> Result<()> {
        Err(Errno::EOPNOTSUPP)
    }
}

/// The functions that charge the page cache to the memory cgroups. The kernel gives them.
#[derive(Clone, Copy, Debug)]
pub struct MemcgOps {
    /// Gives the memory cgroup of the current task, or 0 for none.
    pub current: fn() -> u32,
    /// Charges bytes to a memory cgroup. The cache calls it with its lock, so it does not fail
    /// and does not take pages back.
    pub charge: fn(u32, u64),
    /// Removes a charge of bytes from a memory cgroup.
    pub uncharge: fn(u32, u64),
    /// Takes back the cache of the cgroups over their limit after a charge to a memory cgroup.
    /// The cache calls it without its lock.
    pub balance: fn(u32),
    /// The largest number of bytes in the charged folios of all caches.
    pub limit: usize,
}

/// The functions of [`set_memcg_ops`].
static MEMCG: Once<MemcgOps> = Once::new();

/// The bytes in the charged folios of all caches.
static CHARGED: AtomicUsize = AtomicUsize::new(0);

/// Sets the functions that charge the page cache to the memory cgroups. Only the first call
/// has an effect.
pub fn set_memcg_ops(ops: MemcgOps) {
    MEMCG.call_once(|| ops);
}

/// The bytes that a folio of `len` bytes charges: whole pages.
fn charge_of(len: usize) -> usize {
    len.next_multiple_of(PAGE_SIZE)
}

/// The data of up to `FOLIO_PAGES` pages, from a multiple of `FOLIO_SIZE`.
struct Folio {
    data: Vec<u8>,
    /// The memory cgroup that the folio is charged to, or 0.
    memcg: u32,
    /// A bit for each page that has the data of the store, or newer data.
    uptodate: u16,
    /// A bit for each page that has data that is not in the store.
    dirty: u16,
    /// A read of the store fills the folio now, as `PG_locked` of Linux.
    locked: bool,
    /// A bit for each page that a write back sends to the store now, as `PG_writeback` of Linux.
    writeback: u16,
    /// The time of the last use, for the choice of the folios to drop.
    used: u64,
}

impl Folio {
    /// Tells if the store does a bio of the folio now. The folio must stay in the cache.
    fn busy(&self) -> bool {
        self.locked || self.writeback != 0
    }

    /// The bytes of the pages in `mask`.
    fn bytes(&self, mask: u16) -> usize {
        self.runs(mask).into_iter().flatten().map(|p| self.page(p).len()).sum()
    }

    fn pages(&self) -> usize {
        self.data.len().div_ceil(PAGE_SIZE)
    }

    /// The bytes of the page `p` in `data`.
    fn page(&self, p: usize) -> core::ops::Range<usize> {
        p * PAGE_SIZE..((p + 1) * PAGE_SIZE).min(self.data.len())
    }

    /// The bit of each page that has a byte from `start` to `end` in the folio.
    fn mask(&self, start: usize, end: usize) -> u16 {
        let first = start / PAGE_SIZE;
        let last = end.div_ceil(PAGE_SIZE).min(self.pages());
        (first..last).fold(0, |m, p| m | 1 << p)
    }

    /// The bit of each page that has all its bytes from `start` to `end` in the folio.
    fn covered(&self, start: usize, end: usize) -> u16 {
        (0..self.pages())
            .filter(|&p| self.page(p).start >= start && self.page(p).end <= end)
            .fold(0, |m, p| m | 1 << p)
    }

    /// The runs of pages in `mask`, as ranges of pages.
    fn runs(&self, mask: u16) -> Vec<core::ops::Range<usize>> {
        let mut runs = Vec::new();
        let mut p = 0;
        while p < self.pages() {
            if mask & 1 << p == 0 {
                p += 1;
                continue;
            }
            let start = p;
            while p < self.pages() && mask & 1 << p != 0 {
                p += 1;
            }
            runs.push(start..p);
        }
        runs
    }
}

struct Inner {
    folios: BTreeMap<u64, Folio>,
    /// The number of dirty bytes, page by page.
    dirty: usize,
    /// The number of bytes in the folios.
    cached: usize,
    /// The number of bytes in the charged folios.
    charged: usize,
    /// A folio was charged to a memory cgroup since the last call of `balance`.
    new_charge: bool,
    clock: u64,
}

/// The tasks that read in `without_wait` now, by the number of the task.
static NOWAIT: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());

/// The number of the current task. On the host there are no tasks.
fn task_id() -> u64 {
    #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        rk_frame::task::Task::current().id()
    }
    #[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
    {
        0
    }
}

/// Runs `f`, and each read of a cache in it that must read from the store gives `EAGAIN`. This
/// is the read of `preadv2` with `RWF_NOWAIT`.
pub fn without_wait<R>(f: impl FnOnce() -> R) -> R {
    let id = task_id();
    NOWAIT.lock().push(id);
    let value = f();
    let mut tasks = NOWAIT.lock();
    if let Some(n) = tasks.iter().position(|&t| t == id) {
        tasks.swap_remove(n);
    }
    value
}

/// Tells if the current task reads in `without_wait`.
pub fn no_wait() -> bool {
    let tasks = NOWAIT.lock();
    !tasks.is_empty() && tasks.contains(&task_id())
}

/// The tasks that wait for the end of a bio of a folio, as the folio wait queues of Linux
/// (`folio_wait_bit` in mm/filemap.c). The queue blocks the task on the kernel of x86-64 and
/// aarch64. On the other targets and on the host there are no tasks, so the wait tests the
/// condition again in a loop.
struct FolioWait {
    #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
    queue: rk_frame::task::WaitQueue,
}

impl FolioWait {
    const fn new() -> Self {
        Self {
            #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
            queue: rk_frame::task::WaitQueue::new(),
        }
    }

    /// Blocks the current task until `cond` is true.
    fn wait_until(&self, mut cond: impl FnMut() -> bool) {
        #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
        self.queue.wait_until(|| cond().then_some(()));
        #[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
        while !cond() {
            core::hint::spin_loop();
        }
    }

    /// Wakes each task that waits.
    fn wake_all(&self) {
        #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
        self.queue.wake_all();
    }
}

/// The page cache of one store.
pub struct PageCache<S> {
    store: S,
    inner: SpinLock<Inner>,
    /// The tasks that wait for a folio that is locked or under write back.
    wait: FolioWait,
}

/// The guard of the lock of a cache.
type Guard<'a> = SpinLockGuard<'a, Inner>;

/// One write back: the bios, and the folio and the pages of each bio.
type Batch = (Vec<Bio>, Vec<(u64, u16)>);

impl<S: Store> PageCache<S> {
    /// Makes an empty cache of `store`.
    pub fn new(store: S) -> Self {
        let inner = Inner {
            folios: BTreeMap::new(),
            dirty: 0,
            cached: 0,
            charged: 0,
            new_charge: false,
            clock: 0,
        };
        Self { store, inner: SpinLock::new(inner), wait: FolioWait::new() }
    }

    /// The store under the cache.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The size of the store in bytes.
    pub fn size(&self) -> u64 {
        self.store.size()
    }

    /// The number of dirty bytes, page by page.
    pub fn dirty_bytes(&self) -> usize {
        self.inner.lock().dirty
    }

    /// The number of bytes in the cache.
    pub fn cached_bytes(&self) -> usize {
        self.inner.lock().cached
    }

    /// Gives the folio `index`, with no page up to date if it is new.
    fn folio<'a>(&self, inner: &'a mut Inner, index: u64) -> &'a mut Folio {
        inner.clock += 1;
        let used = inner.clock;
        let size = self.size();
        let folio = inner.folios.entry(index).or_insert_with(|| {
            let start = index * FOLIO_SIZE as u64;
            let len = (size - start).min(FOLIO_SIZE as u64) as usize;
            inner.cached += len;
            let memcg = MEMCG.get().map_or(0, |ops| (ops.current)());
            if memcg != 0
                && let Some(ops) = MEMCG.get()
            {
                (ops.charge)(memcg, charge_of(len) as u64);
                inner.charged += len;
                inner.new_charge = true;
                CHARGED.fetch_add(len, Ordering::Relaxed);
            }
            Folio {
                data: vec![0; len],
                memcg,
                uptodate: 0,
                dirty: 0,
                locked: false,
                writeback: 0,
                used,
            }
        });
        folio.used = used;
        folio
    }

    /// Reads the pages of `mask` of the folio `index` that are not up to date. The lock of the
    /// cache is not held during the read, as `filemap_read_folio` of Linux reads with the folio
    /// locked. A read of the same folio by another task waits for this one. Gives the lock back.
    fn fill<'a>(&'a self, mut inner: Guard<'a>, index: u64, mask: u16) -> Result<Guard<'a>> {
        loop {
            let folio = self.folio(&mut inner, index);
            let missing = mask & !folio.uptodate;
            if missing == 0 {
                return Ok(inner);
            }
            if no_wait() {
                return Err(Errno::EAGAIN);
            }
            if folio.locked {
                // Another read fills the folio, `folio_lock` of Linux.
                drop(inner);
                self.wait_for(|f| !f.locked, index..index + 1);
                inner = self.inner.lock();
                continue;
            }
            folio.locked = true;
            let base = index * (FOLIO_SIZE / SECTOR_SIZE) as u64;
            let runs = folio.runs(missing);
            let mut bios: Vec<Bio> = runs
                .iter()
                .map(|r| {
                    let bytes = folio.page(r.start).start..folio.page(r.end - 1).end;
                    let sector = base + (bytes.start / SECTOR_SIZE) as u64;
                    Bio::new(Op::Read, sector, vec![0; bytes.len()])
                })
                .collect();
            drop(inner);
            self.store.submit(&mut bios);
            inner = self.inner.lock();
            // A locked folio stays in the cache.
            let Some(folio) = inner.folios.get_mut(&index) else { return Err(Errno::EIO) };
            folio.locked = false;
            let mut result = Ok(());
            for (r, bio) in runs.iter().zip(bios) {
                if let Err(e) = bio.result {
                    result = result.and(Err(e));
                    continue;
                }
                let start = folio.page(r.start).start;
                for p in r.clone() {
                    // A write of the whole page during the read has newer data.
                    if folio.uptodate & 1 << p != 0 {
                        continue;
                    }
                    let bytes = folio.page(p);
                    let from = bytes.start - start;
                    folio.data[bytes.clone()].copy_from_slice(&bio.data[from..from + bytes.len()]);
                    folio.uptodate |= 1 << p;
                }
            }
            self.wait.wake_all();
            result?;
        }
    }

    /// Waits until `ready` is true for each folio from `range` in the cache. The caller does not
    /// hold the lock of the cache.
    fn wait_for(&self, ready: impl Fn(&Folio) -> bool, range: core::ops::Range<u64>) {
        self.wait
            .wait_until(|| self.inner.lock().folios.range(range.clone()).all(|(_, f)| ready(f)));
    }

    /// The folio, and the range of bytes in it, of the part of `len` bytes at `offset` that
    /// starts `done` bytes after `offset`.
    fn span(offset: u64, len: usize, done: usize) -> (u64, usize, usize) {
        let at = offset + done as u64;
        let index = at / FOLIO_SIZE as u64;
        let start = (at % FOLIO_SIZE as u64) as usize;
        let n = (FOLIO_SIZE - start).min(len - done);
        (index, start, start + n)
    }

    /// Reads up to `buf.len()` bytes at `offset`. Gives the number of bytes, which is 0 at the
    /// end of the store.
    ///
    /// # Errors
    ///
    /// Gives the error of the store.
    pub fn read(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let size = self.size();
        if offset >= size {
            return Ok(0);
        }
        let len = buf.len().min((size - offset) as usize);
        let mut inner = self.inner.lock();
        let no_wait = no_wait();
        let mut done = 0;
        while done < len {
            let (index, start, end) = Self::span(offset, len, done);
            // A read fills all the folio, as a small readahead. A read that does not wait needs
            // only its own pages.
            let folio = self.folio(&mut inner, index);
            let mask =
                if no_wait { folio.mask(start, end) } else { folio.mask(0, folio.data.len()) };
            inner = self.fill(inner, index, mask)?;
            let folio = self.folio(&mut inner, index);
            buf[done..done + end - start].copy_from_slice(&folio.data[start..end]);
            done += end - start;
        }
        self.shrink(&mut inner);
        let charged = core::mem::take(&mut inner.new_charge);
        drop(inner);
        if charged {
            balance();
        }
        Ok(len)
    }

    /// Writes up to `buf.len()` bytes at `offset` to the cache. Gives the number of bytes. A
    /// write at the end of the store gives `ENOSPC`.
    ///
    /// # Errors
    ///
    /// Gives the error of the store, from the read of a page that the write changes in part, or
    /// from a write back.
    pub fn write(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        let size = self.size();
        if buf.is_empty() {
            return Ok(0);
        }
        if offset >= size {
            return Err(Errno::ENOSPC);
        }
        let len = buf.len().min((size - offset) as usize);
        let mut inner = self.inner.lock();
        let mut done = 0;
        while done < len {
            let (index, start, end) = Self::span(offset, len, done);
            let folio = self.folio(&mut inner, index);
            let all = folio.mask(start, end);
            // A page that the write changes in part must have the other data first.
            let whole = folio.covered(start, end);
            inner = self.fill(inner, index, all & !whole)?;
            let folio = self.folio(&mut inner, index);
            folio.data[start..end].copy_from_slice(&buf[done..done + end - start]);
            let new = all & !folio.dirty;
            folio.uptodate |= all;
            folio.dirty |= all;
            let added = folio.bytes(new);
            inner.dirty += added;
            done += end - start;
        }
        if inner.dirty > DIRTY_LIMIT {
            inner = self.wait_writeback(inner, 0, u64::MAX);
            let batch = Self::collect(&mut inner, 0, u64::MAX);
            let (back, result) = self.send(inner, batch);
            inner = back;
            result?;
        }
        self.shrink(&mut inner);
        let charged = core::mem::take(&mut inner.new_charge);
        drop(inner);
        if charged {
            balance();
        }
        Ok(len)
    }

    /// Waits until no folio from `first` to `end` is under write back, and gives the lock back.
    /// Then a new write back of a page does not run with an older one, and the older data does
    /// not come to the store last, as `folio_wait_writeback` in `write_cache_pages` of Linux.
    fn wait_writeback<'a>(&'a self, mut inner: Guard<'a>, first: u64, end: u64) -> Guard<'a> {
        while inner.folios.range(first..end).any(|(_, f)| f.writeback != 0) {
            drop(inner);
            self.wait_for(|f| f.writeback == 0, first..end);
            inner = self.inner.lock();
        }
        inner
    }

    /// Makes the bios of the dirty pages of the folios from `first` to `end`. The pages become
    /// clean and under write back, as `folio_clear_dirty_for_io` and `folio_start_writeback` of
    /// Linux.
    fn collect(inner: &mut Inner, first: u64, end: u64) -> Batch {
        let mut bios = Vec::new();
        let mut owners = Vec::new();
        let mut clean = 0;
        for (&index, folio) in inner.folios.range_mut(first..end) {
            let base = index * (FOLIO_SIZE / SECTOR_SIZE) as u64;
            for r in folio.runs(folio.dirty) {
                let bytes = folio.page(r.start).start..folio.page(r.end - 1).end;
                let sector = base + (bytes.start / SECTOR_SIZE) as u64;
                bios.push(Bio::new(Op::Write, sector, folio.data[bytes].to_vec()));
                owners.push((index, r.fold(0, |m, p| m | 1 << p)));
            }
            clean += folio.bytes(folio.dirty);
            folio.writeback |= folio.dirty;
            folio.dirty = 0;
        }
        inner.dirty -= clean;
        (bios, owners)
    }

    /// Writes the bios of `batch` with no lock of the cache held, and ends the write back of
    /// their pages, as `folio_end_writeback` of Linux. The pages of a failed bio become dirty
    /// again. Gives the lock back.
    fn send<'a>(&'a self, inner: Guard<'a>, (mut bios, owners): Batch) -> (Guard<'a>, Result<()>) {
        if bios.is_empty() {
            return (inner, Ok(()));
        }
        drop(inner);
        self.store.submit(&mut bios);
        let mut inner = self.inner.lock();
        let mut result = Ok(());
        for (bio, (index, mask)) in bios.iter().zip(owners) {
            if let Err(e) = bio.result {
                result = result.and(Err(e));
            }
            // A folio under write back stays in the cache.
            let Some(folio) = inner.folios.get_mut(&index) else { continue };
            folio.writeback &= !mask;
            if bio.result.is_err() {
                let again = mask & !folio.dirty;
                folio.dirty |= again;
                let added = folio.bytes(again);
                inner.dirty += added;
            }
        }
        self.wait.wake_all();
        (inner, result)
    }

    /// Writes the dirty pages that have a byte from `offset` up to `offset + len` to the store.
    ///
    /// # Errors
    ///
    /// Gives the error of the store.
    pub fn write_back(&self, offset: u64, len: u64) -> Result<()> {
        let first = offset / FOLIO_SIZE as u64;
        let end = offset.saturating_add(len).div_ceil(FOLIO_SIZE as u64);
        let mut inner = self.wait_writeback(self.inner.lock(), first, end);
        let batch = Self::collect(&mut inner, first, end);
        let (inner, result) = self.send(inner, batch);
        drop(inner);
        // A write back of another task can send pages of the range now. The data is in the store
        // only after it ends, as `__filemap_fdatawait_range` of Linux waits for it.
        self.wait_for(|f| f.writeback == 0, first..end);
        result
    }

    /// Writes all the dirty pages to the store, and then makes the data durable.
    ///
    /// # Errors
    ///
    /// Gives the error of the store.
    pub fn sync(&self) -> Result<()> {
        self.write_back(0, u64::MAX)?;
        self.store.flush()
    }

    /// Makes the data that the store has durable, without writing the dirty pages.
    ///
    /// # Errors
    ///
    /// Gives the error of the store.
    pub fn flush(&self) -> Result<()> {
        self.store.flush()
    }

    /// Tells if the store can discard data.
    pub fn can_discard(&self) -> bool {
        self.store.can_discard()
    }

    /// Discards the `len` bytes of the store from `offset`. The folios in the cache stay, so
    /// the caller must not use the data after the discard.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` if `offset` or `len` is not a multiple of `SECTOR_SIZE`, or the error of
    /// the store.
    pub fn discard(&self, offset: u64, len: u64) -> Result<()> {
        let sector = SECTOR_SIZE as u64;
        if !offset.is_multiple_of(sector) || !len.is_multiple_of(sector) {
            return Err(Errno::EINVAL);
        }
        self.store.discard(offset, len)
    }

    /// Drops the folios that have a byte from `offset` up to `offset + len`, after a write that
    /// did not go through the cache. Call `write_back` first, because a dirty page goes too. A
    /// folio that the store reads or writes now goes after the bio, as
    /// `invalidate_inode_pages2_range` of Linux waits for the locked folios.
    pub fn forget(&self, offset: u64, len: u64) {
        let first = offset / FOLIO_SIZE as u64;
        let end = offset.saturating_add(len).div_ceil(FOLIO_SIZE as u64);
        let mut inner = self.inner.lock();
        while inner.folios.range(first..end).any(|(_, f)| f.busy()) {
            drop(inner);
            self.wait_for(|f| !f.busy(), first..end);
            inner = self.inner.lock();
        }
        let gone: Vec<u64> = inner.folios.range(first..end).map(|(i, _)| *i).collect();
        for index in gone {
            Self::drop_folio(&mut inner, index);
        }
    }

    /// Drops the clean folios.
    pub fn drop_clean(&self) {
        let mut inner = self.inner.lock();
        let clean: Vec<u64> = inner
            .folios
            .iter()
            .filter(|(_, f)| f.dirty == 0 && !f.busy())
            .map(|(i, _)| *i)
            .collect();
        for index in clean {
            Self::drop_folio(&mut inner, index);
        }
    }

    /// Drops the clean folios charged to the memory cgroup `memcg` that were used least
    /// recently, until `bytes` bytes of charges are gone. Gives the bytes of the charges that
    /// went. A cache that another task holds now gives nothing, so a reclaim never waits for
    /// a cache.
    pub fn reclaim(&self, memcg: u32, bytes: u64) -> u64 {
        let Some(mut inner) = self.inner.try_lock() else { return 0 };
        let mut clean: Vec<(u64, u64, usize)> = inner
            .folios
            .iter()
            .filter(|(_, f)| f.dirty == 0 && !f.busy() && f.memcg == memcg)
            .map(|(i, f)| (f.used, *i, charge_of(f.data.len())))
            .collect();
        clean.sort_unstable();
        let mut freed = 0;
        for (_, index, len) in clean {
            if freed >= bytes {
                break;
            }
            Self::drop_folio(&mut inner, index);
            freed += len as u64;
        }
        freed
    }

    fn drop_folio(inner: &mut Inner, index: u64) {
        if let Some(folio) = inner.folios.remove(&index) {
            inner.cached -= folio.data.len();
            if folio.memcg != 0 {
                inner.charged -= folio.data.len();
                CHARGED.fetch_sub(folio.data.len(), Ordering::Relaxed);
                if let Some(ops) = MEMCG.get() {
                    (ops.uncharge)(folio.memcg, charge_of(folio.data.len()) as u64);
                }
            }
            let dirty: usize =
                folio.runs(folio.dirty).into_iter().flatten().map(|p| folio.page(p).len()).sum();
            inner.dirty -= dirty;
        }
    }

    /// Drops the clean folios that were used least recently when the folios that are not
    /// charged are above `CACHE_LIMIT`, or the charged folios of all caches are above
    /// `MemcgOps::limit`. It drops folios until the data is an eighth below the limit, so that
    /// the sort of the folios is not done again at each write of a long stream, as the low and
    /// high watermarks of `kswapd` in mm/vmscan.c of Linux.
    fn shrink(&self, inner: &mut Inner) {
        let limit = MEMCG.get().map_or(usize::MAX, |ops| ops.limit);
        let over = |inner: &Inner, cache: usize, charged: usize| {
            inner.cached - inner.charged > cache
                || (inner.charged > 0 && CHARGED.load(Ordering::Relaxed) > charged)
        };
        if !over(inner, CACHE_LIMIT, limit) {
            return;
        }
        let (low_cache, low_charged) = (CACHE_LIMIT - CACHE_LIMIT / 8, limit - limit / 8);
        let mut clean: Vec<(u64, u64)> = inner
            .folios
            .iter()
            .filter(|(_, f)| f.dirty == 0 && !f.busy())
            .map(|(i, f)| (f.used, *i))
            .collect();
        clean.sort_unstable();
        for (_, index) in clean {
            if !over(inner, low_cache, low_charged) {
                break;
            }
            // A charged folio goes only for the limit of the charged folios.
            let charged = inner.folios[&index].memcg != 0;
            if charged == (inner.cached - inner.charged > low_cache) {
                continue;
            }
            Self::drop_folio(inner, index);
        }
    }
}

/// Takes back the cache of the memory cgroup of the current task if it is over its limit. A read
/// or a write calls this only after it charged a new folio, as Linux reclaims in
/// `mem_cgroup_charge` only (mm/memcontrol.c), so a write to folios in the cache does not take
/// the locks of the cgroups.
fn balance() {
    if let Some(ops) = MEMCG.get() {
        let memcg = (ops.current)();
        if memcg != 0 {
            (ops.balance)(memcg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    extern crate std;

    use core::sync::atomic::AtomicBool;
    use std::thread;
    use std::time::Duration;

    /// A store in memory that records the writes.
    struct Ram {
        data: SpinLock<Vec<u8>>,
        writes: SpinLock<Vec<(u64, usize)>>,
        reads: SpinLock<usize>,
        /// A submit waits while this is false.
        open: AtomicBool,
        /// The number of submits that waited for `open`.
        held: AtomicUsize,
    }

    impl Ram {
        /// Holds each submit until `open`.
        fn close(&self) {
            self.open.store(false, Ordering::SeqCst);
        }

        fn open(&self) {
            self.open.store(true, Ordering::SeqCst);
        }

        /// Waits until `n` submits wait for `open`.
        fn wait_held(&self, n: usize) {
            while self.held.load(Ordering::SeqCst) < n {
                thread::yield_now();
            }
        }
    }

    impl Store for Arc<Ram> {
        fn size(&self) -> u64 {
            self.data.lock().len() as u64
        }

        fn submit(&self, bios: &mut [Bio]) {
            if !self.open.load(Ordering::SeqCst) {
                self.held.fetch_add(1, Ordering::SeqCst);
                while !self.open.load(Ordering::SeqCst) {
                    thread::yield_now();
                }
            }
            let mut data = self.data.lock();
            for bio in bios {
                let at = bio.sector as usize * SECTOR_SIZE;
                match bio.op {
                    Op::Read => {
                        *self.reads.lock() += 1;
                        let len = bio.data.len();
                        bio.data.copy_from_slice(&data[at..at + len]);
                    }
                    Op::Write => {
                        self.writes.lock().push((bio.sector, bio.data.len()));
                        data[at..at + bio.data.len()].copy_from_slice(&bio.data);
                    }
                }
            }
        }

        fn flush(&self) -> Result<()> {
            Ok(())
        }
    }

    fn cache(size: usize) -> (Arc<Ram>, PageCache<Arc<Ram>>) {
        let data = (0..size).map(|i| (i / SECTOR_SIZE) as u8).collect();
        let ram = Arc::new(Ram {
            data: SpinLock::new(data),
            writes: SpinLock::new(Vec::new()),
            reads: SpinLock::new(0),
            open: AtomicBool::new(true),
            held: AtomicUsize::new(0),
        });
        (ram.clone(), PageCache::new(ram))
    }

    #[test]
    fn a_write_stays_in_the_cache_until_sync() {
        let (ram, c) = cache(4 * FOLIO_SIZE);
        let buf = vec![0xab; 3 * FOLIO_SIZE];
        assert_eq!(c.write(100, &buf).unwrap(), buf.len());
        assert!(ram.writes.lock().is_empty());
        let mut back = vec![0; buf.len()];
        assert_eq!(c.read(100, &mut back).unwrap(), buf.len());
        assert_eq!(back, buf);
        c.sync().unwrap();
        assert_eq!(c.dirty_bytes(), 0);
        let data = ram.data.lock();
        assert!(data[100..100 + buf.len()].iter().all(|&x| x == 0xab));
        // The bytes before the write in its first page keep their data.
        assert_eq!(data[99], 0);
    }

    #[test]
    fn a_read_fills_the_folio_with_one_bio() {
        let (ram, c) = cache(2 * FOLIO_SIZE);
        let mut buf = [0u8; 10];
        c.read(5 * SECTOR_SIZE as u64, &mut buf).unwrap();
        assert_eq!(buf, [5; 10]);
        c.read(FOLIO_SIZE as u64 - 1, &mut buf[..1]).unwrap();
        assert_eq!(*ram.reads.lock(), 1);
    }

    #[test]
    fn a_write_of_whole_pages_does_not_read() {
        let (ram, c) = cache(FOLIO_SIZE);
        c.write(PAGE_SIZE as u64, &[1; 2 * PAGE_SIZE]).unwrap();
        assert_eq!(*ram.reads.lock(), 0);
        c.write(10, &[2; 10]).unwrap();
        assert_eq!(*ram.reads.lock(), 1);
        c.sync().unwrap();
        // The pages 0, 1 and 2 are one run of dirty pages, thus one bio.
        assert_eq!(*ram.writes.lock(), [(0, 3 * PAGE_SIZE)]);
    }

    #[test]
    fn too_much_dirty_data_goes_to_the_store() {
        let (ram, c) = cache(DIRTY_LIMIT + FOLIO_SIZE);
        c.write(0, &vec![3; DIRTY_LIMIT]).unwrap();
        assert!(ram.writes.lock().is_empty());
        c.write(DIRTY_LIMIT as u64, &[3; PAGE_SIZE]).unwrap();
        assert_eq!(c.dirty_bytes(), 0);
        assert!(ram.data.lock()[..DIRTY_LIMIT + PAGE_SIZE].iter().all(|&x| x == 3));
    }

    #[test]
    fn the_cache_drops_clean_folios() {
        let (_, c) = cache(CACHE_LIMIT + 2 * FOLIO_SIZE);
        let mut buf = vec![0; FOLIO_SIZE];
        for i in 0..(CACHE_LIMIT / FOLIO_SIZE + 2) {
            c.read((i * FOLIO_SIZE) as u64, &mut buf).unwrap();
        }
        assert!(c.cached_bytes() <= CACHE_LIMIT);
        c.drop_clean();
        assert_eq!(c.cached_bytes(), 0);
    }

    #[test]
    fn a_full_cache_drops_folios_down_to_the_low_mark() {
        let (_, c) = cache(CACHE_LIMIT + 2 * FOLIO_SIZE);
        let mut buf = vec![0; FOLIO_SIZE];
        for i in 0..=(CACHE_LIMIT / FOLIO_SIZE) {
            c.read((i * FOLIO_SIZE) as u64, &mut buf).unwrap();
        }
        assert!(c.cached_bytes() <= CACHE_LIMIT - CACHE_LIMIT / 8);
        // The next folios do not make the cache drop folios again.
        let before = c.cached_bytes();
        c.read(CACHE_LIMIT as u64 + FOLIO_SIZE as u64, &mut buf).unwrap();
        assert_eq!(c.cached_bytes(), before + FOLIO_SIZE);
    }

    #[test]
    fn forget_drops_the_data() {
        let (ram, c) = cache(FOLIO_SIZE);
        let mut buf = [0u8; 1];
        c.read(0, &mut buf).unwrap();
        ram.data.lock()[0] = 9;
        c.forget(0, 1);
        c.read(0, &mut buf).unwrap();
        assert_eq!(buf, [9]);
    }

    #[test]
    fn the_last_folio_is_short() {
        let (_, c) = cache(FOLIO_SIZE + 3 * SECTOR_SIZE);
        let mut buf = vec![0; 4 * SECTOR_SIZE];
        assert_eq!(c.read(FOLIO_SIZE as u64, &mut buf).unwrap(), 3 * SECTOR_SIZE);
        assert_eq!(c.write(FOLIO_SIZE as u64 + 3 * SECTOR_SIZE as u64, &buf), Err(Errno::ENOSPC));
        assert_eq!(c.write(FOLIO_SIZE as u64, &buf).unwrap(), 3 * SECTOR_SIZE);
        c.sync().unwrap();
    }

    /// A short time for a thread to reach a wait.
    fn pause() {
        thread::sleep(Duration::from_millis(20));
    }

    #[test]
    fn the_cache_is_not_locked_during_a_read_of_the_store() {
        let (ram, c) = cache(2 * FOLIO_SIZE);
        let c = Arc::new(c);
        ram.close();
        let reader = thread::spawn({
            let c = c.clone();
            move || {
                let mut buf = [0u8; 1];
                c.read(0, &mut buf).unwrap();
                buf[0]
            }
        });
        ram.wait_held(1);
        // A folio that the cache has in full does not need the store.
        c.write(FOLIO_SIZE as u64, &[7; FOLIO_SIZE]).unwrap();
        let mut buf = [0u8; 1];
        c.read(FOLIO_SIZE as u64, &mut buf).unwrap();
        assert_eq!(buf, [7]);
        ram.open();
        assert_eq!(reader.join().unwrap(), 0);
    }

    #[test]
    fn two_reads_of_one_folio_make_one_read_of_the_store() {
        let (ram, c) = cache(FOLIO_SIZE);
        let c = Arc::new(c);
        ram.close();
        let read = |at: u64| {
            let c = c.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 1];
                c.read(at, &mut buf).unwrap();
                buf[0]
            })
        };
        let first = read(0);
        ram.wait_held(1);
        let second = read(SECTOR_SIZE as u64 * 9);
        pause();
        ram.open();
        assert_eq!(first.join().unwrap(), 0);
        assert_eq!(second.join().unwrap(), 9);
        assert_eq!(*ram.reads.lock(), 1);
    }

    #[test]
    fn forget_waits_for_a_read_of_the_store() {
        let (ram, c) = cache(FOLIO_SIZE);
        let c = Arc::new(c);
        ram.close();
        let reader = thread::spawn({
            let c = c.clone();
            move || c.read(0, &mut [0u8; 1]).unwrap()
        });
        ram.wait_held(1);
        let done = Arc::new(AtomicBool::new(false));
        let forget = thread::spawn({
            let (c, done) = (c.clone(), done.clone());
            move || {
                c.forget(0, 1);
                done.store(true, Ordering::SeqCst);
            }
        });
        pause();
        assert!(!done.load(Ordering::SeqCst));
        ram.open();
        reader.join().unwrap();
        forget.join().unwrap();
        assert_eq!(c.cached_bytes(), 0);
    }

    #[test]
    fn a_write_during_a_write_back_stays_dirty() {
        let (ram, c) = cache(FOLIO_SIZE);
        let c = Arc::new(c);
        c.write(0, &[1; PAGE_SIZE]).unwrap();
        ram.close();
        let sync = thread::spawn({
            let c = c.clone();
            move || c.sync().unwrap()
        });
        ram.wait_held(1);
        // The page is clean and under write back. A new write makes it dirty again.
        assert_eq!(c.dirty_bytes(), 0);
        c.write(0, &[2; PAGE_SIZE]).unwrap();
        assert_eq!(c.dirty_bytes(), PAGE_SIZE);
        ram.open();
        sync.join().unwrap();
        assert_eq!(c.dirty_bytes(), PAGE_SIZE);
        c.sync().unwrap();
        assert!(ram.data.lock()[..PAGE_SIZE].iter().all(|&x| x == 2));
    }
}

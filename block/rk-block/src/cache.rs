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
//! A read in `without_wait` does not read from the store. If a page that it needs is not up to
//! date, it gives `EAGAIN`, as a read with `IOCB_NOWAIT` in `filemap_read` of Linux.

use crate::{Bio, Op, Result, SECTOR_SIZE};
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

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

/// The data of up to `FOLIO_PAGES` pages, from a multiple of `FOLIO_SIZE`.
struct Folio {
    data: Vec<u8>,
    /// A bit for each page that has the data of the store, or newer data.
    uptodate: u16,
    /// A bit for each page that has data that is not in the store.
    dirty: u16,
    /// The time of the last use, for the choice of the folios to drop.
    used: u64,
}

impl Folio {
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

/// The page cache of one store.
pub struct PageCache<S> {
    store: S,
    inner: SpinLock<Inner>,
}

/// One write back: the bios, and the folio and the pages of each bio.
type Batch = (Vec<Bio>, Vec<(u64, u16)>);

impl<S: Store> PageCache<S> {
    /// Makes an empty cache of `store`.
    pub fn new(store: S) -> Self {
        let inner = Inner { folios: BTreeMap::new(), dirty: 0, cached: 0, clock: 0 };
        Self { store, inner: SpinLock::new(inner) }
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
            Folio { data: vec![0; len], uptodate: 0, dirty: 0, used }
        });
        folio.used = used;
        folio
    }

    /// Reads the pages of `mask` of the folio `index` that are not up to date.
    fn fill(&self, inner: &mut Inner, index: u64, mask: u16) -> Result<()> {
        let folio = self.folio(inner, index);
        let missing = mask & !folio.uptodate;
        if missing == 0 {
            return Ok(());
        }
        if no_wait() {
            return Err(Errno::EAGAIN);
        }
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
        self.store.submit(&mut bios);
        for (r, bio) in runs.iter().zip(bios) {
            bio.result?;
            let start = folio.page(r.start).start;
            folio.data[start..start + bio.data.len()].copy_from_slice(&bio.data);
            for p in r.clone() {
                folio.uptodate |= 1 << p;
            }
        }
        Ok(())
    }

    /// Calls `f` with each folio, and the range of bytes in it, of `len` bytes at `offset`.
    fn each(
        offset: u64,
        len: usize,
        mut f: impl FnMut(u64, usize, usize, usize) -> Result<()>,
    ) -> Result<()> {
        let mut done = 0;
        while done < len {
            let at = offset + done as u64;
            let index = at / FOLIO_SIZE as u64;
            let start = (at % FOLIO_SIZE as u64) as usize;
            let n = (FOLIO_SIZE - start).min(len - done);
            f(index, start, start + n, done)?;
            done += n;
        }
        Ok(())
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
        Self::each(offset, len, |index, start, end, done| {
            // A read fills all the folio, as a small readahead. A read that does not wait needs
            // only its own pages.
            let folio = self.folio(&mut inner, index);
            let mask =
                if no_wait { folio.mask(start, end) } else { folio.mask(0, folio.data.len()) };
            self.fill(&mut inner, index, mask)?;
            let folio = self.folio(&mut inner, index);
            buf[done..done + end - start].copy_from_slice(&folio.data[start..end]);
            Ok(())
        })?;
        self.shrink(&mut inner);
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
        Self::each(offset, len, |index, start, end, done| {
            let folio = self.folio(&mut inner, index);
            let all = folio.mask(start, end);
            // A page that the write changes in part must have the other data first.
            let whole = folio.covered(start, end);
            self.fill(&mut inner, index, all & !whole)?;
            let folio = self.folio(&mut inner, index);
            folio.data[start..end].copy_from_slice(&buf[done..done + end - start]);
            let new = all & !folio.dirty;
            folio.uptodate |= all;
            folio.dirty |= all;
            let added: usize =
                folio.runs(new).iter().flat_map(Clone::clone).map(|p| folio.page(p).len()).sum();
            inner.dirty += added;
            Ok(())
        })?;
        if inner.dirty > DIRTY_LIMIT {
            let batch = Self::collect(&mut inner, 0, u64::MAX);
            self.send(&mut inner, batch)?;
        }
        self.shrink(&mut inner);
        Ok(len)
    }

    /// Makes the bios of the dirty pages of the folios from `first` to `end`.
    fn collect(inner: &mut Inner, first: u64, end: u64) -> Batch {
        let mut bios = Vec::new();
        let mut owners = Vec::new();
        for (&index, folio) in inner.folios.range(first..end) {
            let base = index * (FOLIO_SIZE / SECTOR_SIZE) as u64;
            for r in folio.runs(folio.dirty) {
                let bytes = folio.page(r.start).start..folio.page(r.end - 1).end;
                let sector = base + (bytes.start / SECTOR_SIZE) as u64;
                bios.push(Bio::new(Op::Write, sector, folio.data[bytes].to_vec()));
                owners.push((index, r.fold(0, |m, p| m | 1 << p)));
            }
        }
        (bios, owners)
    }

    /// Writes the bios of `batch` and makes their pages clean. The pages of a failed bio stay
    /// dirty.
    fn send(&self, inner: &mut Inner, (mut bios, owners): Batch) -> Result<()> {
        self.store.submit(&mut bios);
        let mut result = Ok(());
        for (bio, (index, mask)) in bios.iter().zip(owners) {
            if let Err(e) = bio.result {
                result = result.and(Err(e));
                continue;
            }
            if let Some(folio) = inner.folios.get_mut(&index) {
                folio.dirty &= !mask;
                inner.dirty -= bio.data.len();
            }
        }
        result
    }

    /// Writes the dirty pages that have a byte from `offset` up to `offset + len` to the store.
    ///
    /// # Errors
    ///
    /// Gives the error of the store.
    pub fn write_back(&self, offset: u64, len: u64) -> Result<()> {
        let first = offset / FOLIO_SIZE as u64;
        let end = offset.saturating_add(len).div_ceil(FOLIO_SIZE as u64);
        let mut inner = self.inner.lock();
        let batch = Self::collect(&mut inner, first, end);
        self.send(&mut inner, batch)
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
    /// did not go through the cache. Call `write_back` first, because a dirty page goes too.
    pub fn forget(&self, offset: u64, len: u64) {
        let first = offset / FOLIO_SIZE as u64;
        let end = offset.saturating_add(len).div_ceil(FOLIO_SIZE as u64);
        let mut inner = self.inner.lock();
        let gone: Vec<u64> = inner.folios.range(first..end).map(|(i, _)| *i).collect();
        for index in gone {
            Self::drop_folio(&mut inner, index);
        }
    }

    /// Drops the clean folios.
    pub fn drop_clean(&self) {
        let mut inner = self.inner.lock();
        let clean: Vec<u64> =
            inner.folios.iter().filter(|(_, f)| f.dirty == 0).map(|(i, _)| *i).collect();
        for index in clean {
            Self::drop_folio(&mut inner, index);
        }
    }

    fn drop_folio(inner: &mut Inner, index: u64) {
        if let Some(folio) = inner.folios.remove(&index) {
            inner.cached -= folio.data.len();
            let dirty: usize =
                folio.runs(folio.dirty).into_iter().flatten().map(|p| folio.page(p).len()).sum();
            inner.dirty -= dirty;
        }
    }

    /// Drops the clean folios that were used least recently, until the cache is not above
    /// `CACHE_LIMIT`.
    fn shrink(&self, inner: &mut Inner) {
        if inner.cached <= CACHE_LIMIT {
            return;
        }
        let mut clean: Vec<(u64, u64)> =
            inner.folios.iter().filter(|(_, f)| f.dirty == 0).map(|(i, f)| (f.used, *i)).collect();
        clean.sort_unstable();
        for (_, index) in clean {
            if inner.cached <= CACHE_LIMIT {
                break;
            }
            Self::drop_folio(inner, index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    /// A store in memory that records the writes.
    struct Ram {
        data: SpinLock<Vec<u8>>,
        writes: SpinLock<Vec<(u64, usize)>>,
        reads: SpinLock<usize>,
    }

    impl Store for Arc<Ram> {
        fn size(&self) -> u64 {
            self.data.lock().len() as u64
        }

        fn submit(&self, bios: &mut [Bio]) {
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
}

//! The data of a regular file of tmpfs, in pages of 4096 bytes.
//!
//! A page that the file did not write is a hole. It reads as zeros and has no memory, as in
//! `mm/shmem.c` of Linux. A write far past the end of the file thus takes only the pages that it
//! writes. The bytes of a page past the end of the file are always zeros.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::collections::btree_map::Entry;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_vfs::Result;

/// The size of a page.
pub(crate) const PAGE: u64 = 4096;

/// The count of the pages of one tmpfs, and its limit from the option `size=`.
pub(crate) struct Space {
    /// The pages in use.
    used: AtomicU64,
    /// The largest number of pages. `u64::MAX` is no limit.
    max: AtomicU64,
}

impl Space {
    /// Makes a count with the limit `max` in pages.
    pub(crate) const fn new(max: u64) -> Self {
        Space { used: AtomicU64::new(0), max: AtomicU64::new(max) }
    }

    /// The pages in use.
    pub(crate) fn used(&self) -> u64 {
        self.used.load(Ordering::Acquire)
    }

    /// The limit in pages.
    pub(crate) fn max(&self) -> u64 {
        self.max.load(Ordering::Acquire)
    }

    /// Takes one page from the count, or gives `ENOSPC` at the limit.
    fn take(&self) -> Result<()> {
        let max = self.max();
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < max).then_some(n + 1))
            .map(|_| ())
            .map_err(|_| Errno::ENOSPC)
    }

    /// Gives `n` pages back to the count.
    fn give(&self, n: u64) {
        self.used.fetch_sub(n, Ordering::AcqRel);
    }
}

/// The data of a regular file.
#[derive(Default)]
pub(crate) struct Pages {
    /// The size of the file in bytes.
    len: u64,
    /// The pages that have memory, by index.
    pages: BTreeMap<u64, Box<[u8]>>,
}

impl Pages {
    /// The size of the file in bytes.
    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    /// The number of pages with memory.
    pub(crate) fn count(&self) -> u64 {
        self.pages.len() as u64
    }

    /// Gives the page `index`, and makes it if it has no memory.
    fn page(&mut self, space: &Space, index: u64) -> Result<&mut Box<[u8]>> {
        match self.pages.entry(index) {
            Entry::Occupied(e) => Ok(e.into_mut()),
            Entry::Vacant(e) => {
                space.take()?;
                let mut v = Vec::new();
                if v.try_reserve_exact(PAGE as usize).is_err() {
                    space.give(1);
                    return Err(Errno::ENOSPC);
                }
                v.resize(PAGE as usize, 0);
                Ok(e.insert(v.into_boxed_slice()))
            }
        }
    }

    /// Reads at `offset` into `buf`, and gives the number of bytes. A hole reads as zeros.
    pub(crate) fn read(&self, offset: u64, buf: &mut [u8]) -> usize {
        let n = (buf.len() as u64).min(self.len.saturating_sub(offset)) as usize;
        let mut done = 0;
        while done < n {
            let pos = offset + done as u64;
            let at = (pos % PAGE) as usize;
            let step = (n - done).min(PAGE as usize - at);
            let out = &mut buf[done..done + step];
            match self.pages.get(&(pos / PAGE)) {
                Some(page) => out.copy_from_slice(&page[at..at + step]),
                None => out.fill(0),
            }
            done += step;
        }
        n
    }

    /// Writes `buf` at `offset`, and makes the file larger if the write goes past its end. If a
    /// page cannot get memory, the write stops there, and gives the bytes that it wrote. With no
    /// bytes written, it gives the error.
    pub(crate) fn write(&mut self, space: &Space, offset: u64, buf: &[u8]) -> Result<usize> {
        let mut done = 0;
        while done < buf.len() {
            let pos = offset + done as u64;
            let at = (pos % PAGE) as usize;
            let step = (buf.len() - done).min(PAGE as usize - at);
            match self.page(space, pos / PAGE) {
                Ok(page) => page[at..at + step].copy_from_slice(&buf[done..done + step]),
                Err(e) if done == 0 => return Err(e),
                Err(_) => break,
            }
            done += step;
            self.len = self.len.max(pos + step as u64);
        }
        Ok(done)
    }

    /// Changes the size of the file. A smaller size frees all the pages past the end, also the
    /// pages of `fallocate` with `FALLOC_FL_KEEP_SIZE`, and makes the bytes past the end in the
    /// last page zeros.
    pub(crate) fn set_len(&mut self, space: &Space, size: u64) {
        if size < self.len {
            self.clear(space, size, u64::MAX / PAGE * PAGE);
        }
        self.len = size;
    }

    /// Makes `start..end` a hole: the full pages in it lose their memory, and the other bytes
    /// in it become zeros. The size does not change.
    pub(crate) fn clear(&mut self, space: &Space, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let first = start.div_ceil(PAGE);
        let last = end / PAGE;
        if first < last {
            let gone: Vec<u64> = self.pages.range(first..last).map(|(&i, _)| i).collect();
            for i in &gone {
                self.pages.remove(i);
            }
            space.give(gone.len() as u64);
        }
        // The bytes in the partial pages at the two ends.
        let mut zero = |from: u64, to: u64| {
            if from < to
                && let Some(page) = self.pages.get_mut(&(from / PAGE))
            {
                let at = (from % PAGE) as usize;
                page[at..at + (to - from) as usize].fill(0);
            }
        };
        if first > last {
            zero(start, end);
        } else {
            zero(start, (first * PAGE).min(end));
            zero((last * PAGE).max(start), end);
        }
    }

    /// Gives memory to all the pages in `start..end`, for `fallocate`. The size does not change.
    /// On `ENOSPC`, the pages that it made go away again, as `shmem_fallocate` of Linux.
    pub(crate) fn allocate(&mut self, space: &Space, start: u64, end: u64) -> Result<()> {
        let mut made = Vec::new();
        for index in start / PAGE..end.div_ceil(PAGE) {
            if self.pages.contains_key(&index) {
                continue;
            }
            if let Err(e) = self.page(space, index) {
                for i in &made {
                    self.pages.remove(i);
                }
                space.give(made.len() as u64);
                return Err(e);
            }
            made.push(index);
        }
        Ok(())
    }

    /// Gives the next data at or after `at` if `data`, else the next hole, as `SEEK_DATA` and
    /// `SEEK_HOLE` of `shmem_file_llseek` in Linux. A page with memory is data. The end of the
    /// file is a hole. The caller makes sure that `at` is before the end.
    pub(crate) fn seek(&self, at: u64, data: bool) -> Option<u64> {
        let mut index = at / PAGE;
        if data {
            let (&i, _) = self.pages.range(index..).next()?;
            let pos = (i * PAGE).max(at);
            return (pos < self.len).then_some(pos);
        }
        while self.pages.contains_key(&index) {
            index += 1;
        }
        Some((index * PAGE).max(at).min(self.len))
    }

    /// Frees all the pages, when the file goes away.
    pub(crate) fn free(&mut self, space: &Space) {
        space.give(self.count());
        self.pages.clear();
        self.len = 0;
    }
}

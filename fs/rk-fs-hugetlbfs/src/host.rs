//! A model of `rk_mm::hugetlb::HugeFile` for the tests on the host, which have no pool. A page
//! is a buffer of 2 MiB in the heap.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_mm::hugetlb::{HPAGE_SIZE, Subpool};

const HPAGE: u64 = HPAGE_SIZE as u64;

struct State {
    pages: BTreeMap<u64, Vec<u8>>,
    size: u64,
}

/// The huge pages of one file. The model has no reservations, so each page takes a page of the
/// mount when it is added.
pub struct HugeFile {
    state: SpinLock<State>,
    subpool: Option<Arc<Subpool>>,
}

impl HugeFile {
    /// Makes an empty file of `size` bytes.
    pub fn new(dev: u64, ino: u64, path: Vec<u8>, size: u64) -> Arc<Self> {
        Self::new_in(dev, ino, path, size, None)
    }

    /// Makes an empty file of `size` bytes in the mount with the pages `subpool`.
    pub fn new_in(
        _dev: u64,
        _ino: u64,
        _path: Vec<u8>,
        size: u64,
        subpool: Option<Arc<Subpool>>,
    ) -> Arc<Self> {
        Arc::new(Self { state: SpinLock::new(State { pages: BTreeMap::new(), size }), subpool })
    }

    /// Gives back `n` pages that the file removed to the mount.
    fn release(&self, n: usize) {
        if let Some(subpool) = &self.subpool {
            subpool.release(n as u64);
        }
    }

    /// Sets the path that /proc/PID/maps shows.
    pub fn set_path(&self, _path: Vec<u8>) {}

    /// The size of the file in bytes.
    pub fn size(&self) -> u64 {
        self.state.lock().size
    }

    /// The number of huge pages that the file has.
    pub fn page_count(&self) -> usize {
        self.state.lock().pages.len()
    }

    /// Makes the file at least `size` bytes long.
    pub fn grow_to(&self, size: u64) {
        let mut st = self.state.lock();
        st.size = st.size.max(size);
    }

    /// Changes the size of the file, and drops the pages after the end.
    pub fn set_size(&self, size: u64) {
        let gone = {
            let mut st = self.state.lock();
            st.size = size;
            st.pages.split_off(&size.div_ceil(HPAGE)).len()
        };
        self.release(gone);
    }

    /// Tells if the file has the page `index`.
    pub fn lookup(&self, index: u64) -> Option<()> {
        self.state.lock().pages.contains_key(&index).then_some(())
    }

    /// Gives a page to each index in `first..end`.
    ///
    /// # Errors
    ///
    /// `ENOSPC` if `size=` of the mount does not allow one more page.
    pub fn allocate(&self, first: u64, end: u64) -> Result<(), Errno> {
        let mut st = self.state.lock();
        for i in first..end {
            if st.pages.contains_key(&i) {
                continue;
            }
            if let Some(subpool) = &self.subpool {
                subpool.charge()?;
            }
            st.pages.insert(i, vec![0; HPAGE_SIZE]);
        }
        Ok(())
    }

    /// Removes the pages of `first..end`.
    pub fn punch(&self, first: u64, end: u64) {
        let gone = {
            let mut st = self.state.lock();
            let before = st.pages.len();
            st.pages.retain(|&i, _| i < first || i >= end);
            before - st.pages.len()
        };
        self.release(gone);
    }

    /// Writes zeros to a range of the pages that the file has.
    pub fn zero(&self, offset: u64, len: u64) {
        self.fill(offset, len, 0);
    }

    /// Fills a range of the pages that the file has with `byte`, as a write through a mapping.
    pub fn fill(&self, offset: u64, len: u64, byte: u8) {
        let mut st = self.state.lock();
        for at in offset..offset + len {
            if let Some(p) = st.pages.get_mut(&(at / HPAGE)) {
                p[(at % HPAGE) as usize] = byte;
            }
        }
    }

    /// Copies the bytes at `offset` to `buf`, up to the end of the file.
    pub fn read(&self, offset: u64, buf: &mut [u8]) -> usize {
        let st = self.state.lock();
        let len = usize::try_from(st.size.saturating_sub(offset)).unwrap_or(usize::MAX);
        let len = len.min(buf.len());
        for (i, b) in buf[..len].iter_mut().enumerate() {
            let at = offset + i as u64;
            *b = st.pages.get(&(at / HPAGE)).map_or(0, |p| p[(at % HPAGE) as usize]);
        }
        len
    }
}

impl Drop for HugeFile {
    fn drop(&mut self) {
        let gone = self.state.lock().pages.len();
        self.release(gone);
    }
}

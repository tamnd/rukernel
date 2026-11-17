//! The memory of a map value.
//!
//! A program and the system calls can use one value at the same time, as in Linux. The value is
//! a row of atomic 64-bit words, so each access is safe without a lock. A copy of more than one
//! word is not atomic, as `copy_map_value` of Linux is not.
//!
//! The values of an array map with `BPF_F_MMAPABLE` are in pages that a process can map, as the
//! `vmalloc` memory of `array_map_alloc` in Linux. A process and a program then share the words.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;

/// The size of a page of values.
pub const PAGE_SIZE: usize = 4096;

/// The count of words in a page.
const PAGE_WORDS: usize = PAGE_SIZE / 8;

/// A page of values that a process can map: a frame of memory in the kernel.
#[cfg(target_os = "none")]
pub type Page = rk_frame::mm::Frame;

/// A page of values that a process can map. The host has no frames, so the tests use memory of
/// the heap.
#[cfg(not(target_os = "none"))]
pub struct Page {
    words: [AtomicU64; PAGE_WORDS],
}

#[cfg(not(target_os = "none"))]
impl Page {
    /// The word `index` of the page.
    pub fn atomic_u64(&self, index: usize) -> &AtomicU64 {
        &self.words[index]
    }
}

/// A new page with all bytes zero.
#[cfg(target_os = "none")]
fn new_page() -> Result<Page, Errno> {
    rk_frame::mm::alloc_zeroed_frame().ok_or(Errno::ENOMEM)
}

/// A new page with all bytes zero.
#[cfg(not(target_os = "none"))]
fn new_page() -> Result<Page, Errno> {
    Ok(Page { words: [const { AtomicU64::new(0) }; PAGE_WORDS] })
}

/// The pages that hold `size` bytes, with all bytes zero.
pub fn zeroed_pages(size: usize) -> Result<Arc<[Arc<Page>]>, Errno> {
    let n = size.div_ceil(PAGE_SIZE);
    let mut pages = Vec::new();
    pages.try_reserve_exact(n).map_err(|_| Errno::ENOMEM)?;
    for _ in 0..n {
        pages.push(Arc::new(new_page()?));
    }
    Ok(pages.into())
}

/// The words of a value.
enum Words {
    /// Memory of the heap that only this value has.
    Heap(Box<[AtomicU64]>),
    /// `len` words at the word `first` of shared pages.
    Pages { pages: Arc<[Arc<Page>]>, first: usize, len: usize },
}

/// The memory of one value, with a size that is a multiple of 8 bytes.
pub struct MapValue {
    words: Words,
}

impl MapValue {
    /// A value of `size` bytes rounded up to 8, with all bytes zero.
    pub fn zeroed(size: usize) -> Result<Self, Errno> {
        let n = size.div_ceil(8);
        let mut words = Vec::new();
        words.try_reserve_exact(n).map_err(|_| Errno::ENOMEM)?;
        words.resize_with(n, || AtomicU64::new(0));
        Ok(Self { words: Words::Heap(words.into_boxed_slice()) })
    }

    /// The value of `size` bytes rounded up to 8 at the byte `offset` of `pages`. `offset` is a
    /// multiple of 8, and the bytes are in the pages.
    pub fn in_pages(pages: &Arc<[Arc<Page>]>, offset: usize, size: usize) -> Self {
        let (first, len) = (offset / 8, size.div_ceil(8));
        debug_assert!(offset.is_multiple_of(8) && (first + len) <= pages.len() * PAGE_WORDS);
        Self { words: Words::Pages { pages: pages.clone(), first, len } }
    }

    /// A value with the bytes of `data`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Errno> {
        let v = Self::zeroed(data.len())?;
        v.write(0, data);
        Ok(v)
    }

    /// The size in bytes.
    pub fn len(&self) -> usize {
        self.words() * 8
    }

    /// Tells if the value has no bytes.
    pub fn is_empty(&self) -> bool {
        self.words() == 0
    }

    /// The count of words.
    fn words(&self) -> usize {
        match &self.words {
            Words::Heap(w) => w.len(),
            Words::Pages { len, .. } => *len,
        }
    }

    /// Copies the bytes at `offset` to `buf`. The bytes past the end read as zero.
    pub fn read(&self, offset: usize, buf: &mut [u8]) {
        for (i, b) in buf.iter_mut().enumerate() {
            let at = offset + i;
            *b = match self.word(at / 8) {
                Some(w) => w.load(Ordering::Relaxed).to_le_bytes()[at % 8],
                None => 0,
            };
        }
    }

    /// Copies `data` to the bytes at `offset`. The bytes past the end are not written.
    pub fn write(&self, offset: usize, data: &[u8]) {
        let mut i = 0;
        while i < data.len() {
            let at = offset + i;
            let Some(word) = self.word(at / 8) else { return };
            let first = at % 8;
            let n = (8 - first).min(data.len() - i);
            if n == 8 {
                let mut b = [0u8; 8];
                b.copy_from_slice(&data[i..i + 8]);
                word.store(u64::from_le_bytes(b), Ordering::Relaxed);
            } else {
                let mut mask = [0u8; 8];
                let mut bits = [0u8; 8];
                mask[first..first + n].fill(0xff);
                bits[first..first + n].copy_from_slice(&data[i..i + n]);
                let (mask, bits) = (u64::from_le_bytes(mask), u64::from_le_bytes(bits));
                let _ = word.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |w| {
                    Some((w & !mask) | bits)
                });
            }
            i += n;
        }
    }

    /// The word at the index `index`, for the atomic instructions of a program.
    pub fn word(&self, index: usize) -> Option<&AtomicU64> {
        match &self.words {
            Words::Heap(w) => w.get(index),
            Words::Pages { pages, first, len } => {
                if index >= *len {
                    return None;
                }
                let at = first + index;
                Some(pages.get(at / PAGE_WORDS)?.atomic_u64(at % PAGE_WORDS))
            }
        }
    }

    /// All bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = alloc::vec![0; self.len()];
        self.read(0, &mut v);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_go_in_and_come_out() {
        let v = MapValue::zeroed(13).unwrap();
        assert_eq!(v.len(), 16);
        v.write(3, b"abcdefghij");
        let mut out = [0u8; 16];
        v.read(0, &mut out);
        assert_eq!(&out, b"\0\0\0abcdefghij\0\0\0");
        v.write(14, b"xyz");
        v.read(0, &mut out);
        assert_eq!(&out[13..], b"\0xy");
    }

    #[test]
    fn two_values_in_pages_share_the_words() {
        let pages = zeroed_pages(PAGE_SIZE + 8).unwrap();
        assert_eq!(pages.len(), 2);
        let a = MapValue::in_pages(&pages, PAGE_SIZE - 8, 16);
        let b = MapValue::in_pages(&pages, PAGE_SIZE - 8, 16);
        assert_eq!(a.len(), 16);
        a.write(4, b"abcdefgh");
        let mut out = [0u8; 16];
        b.read(0, &mut out);
        assert_eq!(&out, b"\0\0\0\0abcdefgh\0\0\0\0");
        assert_eq!(pages[1].atomic_u64(0).load(Ordering::Relaxed) & 0xffff_ffff, 0x6867_6665);
        assert!(a.word(2).is_none());
    }
}

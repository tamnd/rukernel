//! The memory of a map value.
//!
//! A program and the system calls can use one value at the same time, as in Linux. The value is
//! a row of atomic 64-bit words, so each access is safe without a lock. A copy of more than one
//! word is not atomic, as `copy_map_value` of Linux is not.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;

/// The memory of one value, with a size that is a multiple of 8 bytes.
pub struct MapValue {
    words: Box<[AtomicU64]>,
}

impl MapValue {
    /// A value of `size` bytes rounded up to 8, with all bytes zero.
    pub fn zeroed(size: usize) -> Result<Self, Errno> {
        let n = size.div_ceil(8);
        let mut words = Vec::new();
        words.try_reserve_exact(n).map_err(|_| Errno::ENOMEM)?;
        words.resize_with(n, || AtomicU64::new(0));
        Ok(Self { words: words.into_boxed_slice() })
    }

    /// A value with the bytes of `data`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Errno> {
        let v = Self::zeroed(data.len())?;
        v.write(0, data);
        Ok(v)
    }

    /// The size in bytes.
    pub fn len(&self) -> usize {
        self.words.len() * 8
    }

    /// Tells if the value has no bytes.
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    /// Copies the bytes at `offset` to `buf`. The bytes past the end read as zero.
    pub fn read(&self, offset: usize, buf: &mut [u8]) {
        for (i, b) in buf.iter_mut().enumerate() {
            let at = offset + i;
            *b = match self.words.get(at / 8) {
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
            let Some(word) = self.words.get(at / 8) else { return };
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
        self.words.get(index)
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
}

//! SHA-1, per FIPS 180-4, as crypto/sha1.c of Linux.

use crate::Hash;
use alloc::boxed::Box;
use alloc::string::String;

/// The first hash.
const H: [u32; 5] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0];

/// The size of a block.
const BLOCK: usize = 64;

/// The state of SHA-1.
#[derive(Clone)]
pub struct Sha1 {
    h: [u32; 5],
    buf: [u8; BLOCK],
    /// The count of bytes of the message so far.
    len: u64,
}

impl Sha1 {
    /// A new SHA-1.
    pub fn new() -> Self {
        Self { h: H, buf: [0; BLOCK], len: 0 }
    }

    fn compress(h: &mut [u32; 5], block: &[u8; BLOCK]) {
        let mut w = [0u32; 80];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = *h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..20 => ((b & c) | (!b & d), 0x5a82_7999),
                20..40 => (b ^ c ^ d, 0x6ed9_eba1),
                40..60 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e);
            let t = t.wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hash for Sha1 {
    fn digest_size(&self) -> usize {
        20
    }

    fn block_size(&self) -> usize {
        BLOCK
    }

    fn name(&self) -> String {
        String::from("sha1")
    }

    fn driver_name(&self) -> String {
        String::from("sha1-generic")
    }

    fn init(&mut self) {
        *self = Self::new();
    }

    fn update(&mut self, mut data: &[u8]) {
        let used = (self.len % BLOCK as u64) as usize;
        self.len = self.len.wrapping_add(data.len() as u64);
        if used > 0 {
            let n = (BLOCK - used).min(data.len());
            self.buf[used..used + n].copy_from_slice(&data[..n]);
            data = &data[n..];
            if used + n < BLOCK {
                return;
            }
            let block = self.buf;
            Self::compress(&mut self.h, &block);
        }
        let (blocks, rest) = data.as_chunks::<BLOCK>();
        for block in blocks {
            Self::compress(&mut self.h, block);
        }
        self.buf[..rest.len()].copy_from_slice(rest);
    }

    fn finish(&mut self, out: &mut [u8]) {
        let bits = self.len.wrapping_mul(8);
        let used = (self.len % BLOCK as u64) as usize;
        let pad = if used < 56 { 56 - used } else { 120 - used };
        let mut tail = [0u8; 72];
        tail[0] = 0x80;
        tail[pad..pad + 8].copy_from_slice(&bits.to_be_bytes());
        self.update(&tail[..pad + 8]);
        for (chunk, word) in out[..20].chunks_mut(4).zip(self.h) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
    }

    fn box_clone(&self) -> Box<dyn Hash> {
        Box::new(self.clone())
    }
}

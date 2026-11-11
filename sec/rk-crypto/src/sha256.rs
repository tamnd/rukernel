//! SHA-224 and SHA-256, per FIPS 180-4, as crypto/sha256.c of Linux.

use crate::Hash;
use alloc::boxed::Box;
use alloc::string::String;

/// The constants of the rounds: the first 32 bits of the fractional parts of the cube roots of
/// the first 64 primes.
#[rustfmt::skip]
const K: [u32; 64] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1,
    0x923f_82a4, 0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
    0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786,
    0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
    0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7, 0xc6e0_0bf3, 0xd5a7_9147,
    0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
    0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
    0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
    0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a,
    0x5b9c_ca4f, 0x682e_6ff3, 0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
    0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
];

/// The first hash of SHA-256: the first 32 bits of the fractional parts of the square roots of
/// the first 8 primes.
#[rustfmt::skip]
const H256: [u32; 8] = [
    0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c,
    0x1f83_d9ab, 0x5be0_cd19,
];

/// The first hash of SHA-224: the second 32 bits of the fractional parts of the square roots of
/// the primes 9 to 16.
#[rustfmt::skip]
const H224: [u32; 8] = [
    0xc105_9ed8, 0x367c_d507, 0x3070_dd17, 0xf70e_5939, 0xffc0_0b31, 0x6858_1511,
    0x64f9_8fa7, 0xbefa_4fa4,
];

/// The size of a block.
const BLOCK: usize = 64;

/// The state of SHA-256 or SHA-224.
#[derive(Clone)]
pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; BLOCK],
    /// The count of bytes of the message so far.
    len: u64,
    /// True for SHA-224.
    short: bool,
}

impl Sha256 {
    /// A new SHA-256.
    pub fn new() -> Self {
        Self { h: H256, buf: [0; BLOCK], len: 0, short: false }
    }

    /// A new SHA-224.
    pub fn new_224() -> Self {
        Self { h: H224, buf: [0; BLOCK], len: 0, short: true }
    }

    /// The digest of `data`, with SHA-256.
    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut s = Self::new();
        s.update(data);
        let mut out = [0; 32];
        s.finish(&mut out);
        out
    }

    fn compress(h: &mut [u32; 8], block: &[u8; BLOCK]) {
        let mut w = [0u32; 64];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hash for Sha256 {
    fn digest_size(&self) -> usize {
        if self.short { 28 } else { 32 }
    }

    fn block_size(&self) -> usize {
        BLOCK
    }

    fn name(&self) -> String {
        String::from(if self.short { "sha224" } else { "sha256" })
    }

    fn driver_name(&self) -> String {
        String::from(if self.short { "sha224-generic" } else { "sha256-generic" })
    }

    fn init(&mut self) {
        *self = if self.short { Self::new_224() } else { Self::new() };
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
        let n = self.digest_size();
        for (i, chunk) in out[..n].chunks_mut(4).enumerate() {
            chunk.copy_from_slice(&self.h[i].to_be_bytes()[..chunk.len()]);
        }
    }

    fn box_clone(&self) -> Box<dyn Hash> {
        Box::new(self.clone())
    }
}

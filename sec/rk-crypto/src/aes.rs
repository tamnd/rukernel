//! AES, per FIPS 197, as crypto/aes_generic.c of Linux.
//!
//! The code uses the tables of 32-bit words of the generic driver of Linux: one table look up
//! for each byte of a round does the substitution and the mix of the columns. The build makes
//! the tables from the S-box. A column of the state is a big endian word, and the first byte of
//! the column is the high byte.

use crate::{BLOCK, Cipher, Result};
use alloc::boxed::Box;
use alloc::string::String;
use rk_abi::Errno;

/// Multiplies `a` by `b` in GF(2^8) with the polynomial of AES.
const fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        a = (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 };
        b >>= 1;
    }
    r
}

/// Makes the S-box: the inverse in GF(2^8) and the affine map of FIPS 197 section 5.1.1.
const fn make_sbox() -> [u8; 256] {
    let mut sbox = [0u8; 256];
    // `p` goes through the powers of the generator 3, and `q` through the powers of its inverse,
    // so `q` is the inverse of `p` at each step.
    let mut p: u8 = 1;
    let mut q: u8 = 1;
    loop {
        p = p ^ (p << 1) ^ if p & 0x80 != 0 { 0x1b } else { 0 };
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        if q & 0x80 != 0 {
            q ^= 0x09;
        }
        let x = q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4);
        sbox[p as usize] = x ^ 0x63;
        if p == 1 {
            break;
        }
    }
    sbox[0] = 0x63;
    sbox
}

const fn invert(sbox: &[u8; 256]) -> [u8; 256] {
    let mut inv = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        inv[sbox[i] as usize] = i as u8;
        i += 1;
    }
    inv
}

/// The table of a round of the encryption for the first byte of a column: the column that the
/// mix of FIPS 197 section 5.1.3 makes from the byte after the S-box.
const fn make_te(sbox: &[u8; 256]) -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let s = sbox[i];
        t[i] = u32::from_be_bytes([mul(s, 2), s, s, mul(s, 3)]);
        i += 1;
    }
    t
}

/// The table of a round of the decryption for the first byte of a column, with the inverse mix
/// of FIPS 197 section 5.3.3.
const fn make_td(inv: &[u8; 256]) -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let s = inv[i];
        t[i] = u32::from_be_bytes([mul(s, 14), mul(s, 9), mul(s, 13), mul(s, 11)]);
        i += 1;
    }
    t
}

const SBOX: [u8; 256] = make_sbox();
const INV_SBOX: [u8; 256] = invert(&SBOX);
const TE: [u32; 256] = make_te(&SBOX);
const TD: [u32; 256] = make_td(&INV_SBOX);

/// The constants of the key expansion, in the high byte.
const RCON: [u32; 10] = [
    0x0100_0000,
    0x0200_0000,
    0x0400_0000,
    0x0800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
    0x1b00_0000,
    0x3600_0000,
];

/// The most words of the round keys: 15 rounds keys of 4 words for AES-256.
const KEY_WORDS: usize = 60;

/// The look up of byte `n` (0 is the high byte) of `w` in `TE` or `TD`, with the rotation of
/// the table for that byte.
fn t(table: &[u32; 256], w: u32, n: u32) -> u32 {
    table[(w >> (24 - 8 * n)) as u8 as usize].rotate_right(8 * n)
}

/// Applies the S-box to each byte of `w`.
fn sub_word(w: u32) -> u32 {
    u32::from_be_bytes(w.to_be_bytes().map(|b| SBOX[b as usize]))
}

/// An AES key: the round keys of the encryption and of the decryption.
#[derive(Clone)]
pub struct Aes {
    enc: [u32; KEY_WORDS],
    dec: [u32; KEY_WORDS],
    /// The count of rounds: 10, 12 or 14. 0 before `set_key`.
    rounds: usize,
}

impl Aes {
    /// AES with no key.
    pub fn new() -> Self {
        Self { enc: [0; KEY_WORDS], dec: [0; KEY_WORDS], rounds: 0 }
    }

    /// True after `set_key`.
    pub fn has_key(&self) -> bool {
        self.rounds != 0
    }
}

impl Default for Aes {
    fn default() -> Self {
        Self::new()
    }
}

impl Cipher for Aes {
    fn name(&self) -> String {
        String::from("aes")
    }

    fn driver_name(&self) -> String {
        String::from("aes-generic")
    }

    fn min_key_size(&self) -> usize {
        16
    }

    fn max_key_size(&self) -> usize {
        32
    }

    /// The key expansion of FIPS 197 section 5.2, and the round keys of the equivalent inverse
    /// cipher of section 5.3.5.
    fn set_key(&mut self, key: &[u8]) -> Result<()> {
        let nk = match key.len() {
            16 | 24 | 32 => key.len() / 4,
            _ => return Err(Errno::EINVAL),
        };
        let rounds = nk + 6;
        let words = 4 * (rounds + 1);
        let mut w = [0u32; KEY_WORDS];
        for (i, k) in key.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*k);
        }
        for i in nk..words {
            let mut temp = w[i - 1];
            if i % nk == 0 {
                temp = sub_word(temp.rotate_left(8)) ^ RCON[i / nk - 1];
            } else if nk > 6 && i % nk == 4 {
                temp = sub_word(temp);
            }
            w[i] = w[i - nk] ^ temp;
        }
        let mut d = [0u32; KEY_WORDS];
        for r in 0..=rounds {
            for j in 0..4 {
                let e = w[4 * (rounds - r) + j];
                d[4 * r + j] = if r == 0 || r == rounds {
                    e
                } else {
                    // The inverse mix of the columns: `TD` of the byte before the S-box.
                    (0..4).fold(0, |acc, n| acc ^ t(&TD, sub_word(e), n))
                };
            }
        }
        self.enc = w;
        self.dec = d;
        self.rounds = rounds;
        Ok(())
    }

    fn encrypt(&self, block: &mut [u8; BLOCK]) {
        let rk = &self.enc;
        let mut s = [0u32; 4];
        for (i, c) in block.as_chunks::<4>().0.iter().enumerate() {
            s[i] = u32::from_be_bytes(*c) ^ rk[i];
        }
        for r in 1..self.rounds {
            s = core::array::from_fn(|i| {
                t(&TE, s[i], 0)
                    ^ t(&TE, s[(i + 1) % 4], 1)
                    ^ t(&TE, s[(i + 2) % 4], 2)
                    ^ t(&TE, s[(i + 3) % 4], 3)
                    ^ rk[4 * r + i]
            });
        }
        let last = 4 * self.rounds;
        for i in 0..4 {
            let b = [
                SBOX[(s[i] >> 24) as usize],
                SBOX[(s[(i + 1) % 4] >> 16) as u8 as usize],
                SBOX[(s[(i + 2) % 4] >> 8) as u8 as usize],
                SBOX[s[(i + 3) % 4] as u8 as usize],
            ];
            let w = u32::from_be_bytes(b) ^ rk[last + i];
            block[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
        }
    }

    fn decrypt(&self, block: &mut [u8; BLOCK]) {
        let rk = &self.dec;
        let mut s = [0u32; 4];
        for (i, c) in block.as_chunks::<4>().0.iter().enumerate() {
            s[i] = u32::from_be_bytes(*c) ^ rk[i];
        }
        for r in 1..self.rounds {
            s = core::array::from_fn(|i| {
                t(&TD, s[i], 0)
                    ^ t(&TD, s[(i + 3) % 4], 1)
                    ^ t(&TD, s[(i + 2) % 4], 2)
                    ^ t(&TD, s[(i + 1) % 4], 3)
                    ^ rk[4 * r + i]
            });
        }
        let last = 4 * self.rounds;
        for i in 0..4 {
            let b = [
                INV_SBOX[(s[i] >> 24) as usize],
                INV_SBOX[(s[(i + 3) % 4] >> 16) as u8 as usize],
                INV_SBOX[(s[(i + 2) % 4] >> 8) as u8 as usize],
                INV_SBOX[s[(i + 1) % 4] as u8 as usize],
            ];
            let w = u32::from_be_bytes(b) ^ rk[last + i];
            block[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
        }
    }

    fn box_clone(&self) -> Box<dyn Cipher> {
        Box::new(self.clone())
    }
}

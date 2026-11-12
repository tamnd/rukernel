//! The templates that make a cipher of any length from a block cipher: `ecb`, `cbc` and `ctr`,
//! as crypto/ecb.c, crypto/cbc.c and crypto/ctr.c of Linux, and `xts` with the ciphertext
//! stealing of IEEE 1619, as crypto/xts.c.

use crate::{BLOCK, Cipher, Result, Skcipher};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use rk_abi::Errno;

/// A mode of a block cipher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Each block alone.
    Ecb,
    /// Cipher block chaining.
    Cbc,
    /// The counter mode, with a big endian counter of 128 bits.
    Ctr,
    /// XTS: the mode of disk encryption of IEEE 1619, with two keys.
    Xts,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Ecb => "ecb",
            Self::Cbc => "cbc",
            Self::Ctr => "ctr",
            Self::Xts => "xts",
        }
    }
}

/// A block cipher in a mode.
pub struct Block {
    mode: Mode,
    cipher: Box<dyn Cipher>,
    /// The cipher of the tweak of XTS, with the second half of the key.
    tweak: Box<dyn Cipher>,
    keyed: bool,
}

impl Block {
    /// The cipher `cipher` in the mode `mode`.
    pub fn new(mode: Mode, cipher: Box<dyn Cipher>) -> Self {
        Self { mode, tweak: cipher.box_clone(), cipher, keyed: false }
    }

    /// Checks the length of the data: a multiple of the block, or for XTS at least one block, as
    /// `xts_init_crypt` of Linux.
    fn check(&self, len: usize) -> Result<()> {
        let ok = match self.mode {
            Mode::Ecb | Mode::Cbc => len.is_multiple_of(BLOCK),
            Mode::Ctr => true,
            Mode::Xts => len >= BLOCK,
        };
        if ok { Ok(()) } else { Err(Errno::EINVAL) }
    }

    fn ctr(&self, iv: &mut [u8], data: &mut [u8]) {
        let mut counter = u128::from_be_bytes(block_of(iv));
        for chunk in data.chunks_mut(BLOCK) {
            let mut ks = counter.to_be_bytes();
            self.cipher.encrypt(&mut ks);
            chunk.iter_mut().zip(ks).for_each(|(b, k)| *b ^= k);
            counter = counter.wrapping_add(1);
        }
        iv.copy_from_slice(&counter.to_be_bytes());
    }

    /// XTS, with the ciphertext stealing of IEEE 1619 section 5.3.2 for a length that is not a
    /// multiple of the block.
    fn xts(&self, iv: &[u8], data: &mut [u8], enc: bool) {
        let mut t = block_of(iv);
        self.tweak.encrypt(&mut t);
        let mut tweak = u128::from_le_bytes(t);
        let tail = data.len() % BLOCK;
        // With a tail, the last full block goes with the tail.
        let full = data.len() / BLOCK - usize::from(tail != 0);
        let (head, rest) = data.split_at_mut(full * BLOCK);
        for chunk in head.as_chunks_mut::<BLOCK>().0 {
            self.xts_block(chunk, tweak, enc);
            tweak = next_tweak(tweak);
        }
        if tail == 0 {
            return;
        }
        let Some((last, part)) = rest.split_first_chunk_mut::<BLOCK>() else {
            return;
        };
        // The encryption uses the tweaks in order. The decryption uses the second tweak for the
        // last full block, then the first one for the block that the stealing makes.
        let (first, second) =
            if enc { (tweak, next_tweak(tweak)) } else { (next_tweak(tweak), tweak) };
        self.xts_block(last, first, enc);
        let mut stolen = *last;
        stolen[..tail].copy_from_slice(part);
        part.copy_from_slice(&last[..tail]);
        self.xts_block(&mut stolen, second, enc);
        *last = stolen;
    }

    fn xts_block(&self, b: &mut [u8; BLOCK], tweak: u128, enc: bool) {
        let t = tweak.to_le_bytes();
        b.iter_mut().zip(t).for_each(|(x, y)| *x ^= y);
        if enc {
            self.cipher.encrypt(b);
        } else {
            self.cipher.decrypt(b);
        }
        b.iter_mut().zip(t).for_each(|(x, y)| *x ^= y);
    }
}

/// The first 16 bytes of `iv`.
fn block_of(iv: &[u8]) -> [u8; BLOCK] {
    let mut b = [0u8; BLOCK];
    b.copy_from_slice(&iv[..BLOCK]);
    b
}

/// Multiplies the tweak by the primitive element of GF(2^128), as `gf128mul_x_ble`.
fn next_tweak(t: u128) -> u128 {
    (t << 1) ^ if t >> 127 != 0 { 0x87 } else { 0 }
}

impl Skcipher for Block {
    fn name(&self) -> String {
        format!("{}({})", self.mode.name(), self.cipher.name())
    }

    fn driver_name(&self) -> String {
        format!("{}({})", self.mode.name(), self.cipher.driver_name())
    }

    fn block_size(&self) -> usize {
        if self.mode == Mode::Ctr { 1 } else { BLOCK }
    }

    fn chunk_size(&self) -> usize {
        BLOCK
    }

    fn iv_size(&self) -> usize {
        if self.mode == Mode::Ecb { 0 } else { BLOCK }
    }

    fn min_key_size(&self) -> usize {
        let n = self.cipher.min_key_size();
        if self.mode == Mode::Xts { 2 * n } else { n }
    }

    fn max_key_size(&self) -> usize {
        let n = self.cipher.max_key_size();
        if self.mode == Mode::Xts { 2 * n } else { n }
    }

    /// A key that fails leaves the cipher with no key, as `crypto_skcipher_setkey` of Linux.
    fn set_key(&mut self, key: &[u8]) -> Result<()> {
        self.keyed = false;
        if key.len() < self.min_key_size() || key.len() > self.max_key_size() {
            return Err(Errno::EINVAL);
        }
        if self.mode == Mode::Xts {
            // `xts_verify_key` of Linux: the two halves have the same size.
            if !key.len().is_multiple_of(2) {
                return Err(Errno::EINVAL);
            }
            let (a, b) = key.split_at(key.len() / 2);
            self.cipher.set_key(a)?;
            self.tweak.set_key(b)?;
        } else {
            self.cipher.set_key(key)?;
        }
        self.keyed = true;
        Ok(())
    }

    fn needs_key(&self) -> bool {
        !self.keyed
    }

    fn encrypt(&self, iv: &mut [u8], data: &mut [u8]) -> Result<()> {
        self.check(data.len())?;
        match self.mode {
            Mode::Ecb => data.as_chunks_mut::<BLOCK>().0.iter_mut().for_each(|b| {
                self.cipher.encrypt(b);
            }),
            Mode::Cbc => {
                let mut prev = block_of(iv);
                for b in data.as_chunks_mut::<BLOCK>().0 {
                    b.iter_mut().zip(prev).for_each(|(x, y)| *x ^= y);
                    self.cipher.encrypt(b);
                    prev = *b;
                }
                iv[..BLOCK].copy_from_slice(&prev);
            }
            Mode::Ctr => self.ctr(iv, data),
            Mode::Xts => self.xts(iv, data, true),
        }
        Ok(())
    }

    fn decrypt(&self, iv: &mut [u8], data: &mut [u8]) -> Result<()> {
        self.check(data.len())?;
        match self.mode {
            Mode::Ecb => data.as_chunks_mut::<BLOCK>().0.iter_mut().for_each(|b| {
                self.cipher.decrypt(b);
            }),
            Mode::Cbc => {
                let mut prev = block_of(iv);
                for b in data.as_chunks_mut::<BLOCK>().0 {
                    let next = *b;
                    self.cipher.decrypt(b);
                    b.iter_mut().zip(prev).for_each(|(x, y)| *x ^= y);
                    prev = next;
                }
                iv[..BLOCK].copy_from_slice(&prev);
            }
            Mode::Ctr => self.ctr(iv, data),
            Mode::Xts => self.xts(iv, data, false),
        }
        Ok(())
    }

    fn box_clone(&self) -> Box<dyn Skcipher> {
        Box::new(Self {
            mode: self.mode,
            cipher: self.cipher.box_clone(),
            tweak: self.tweak.box_clone(),
            keyed: self.keyed,
        })
    }
}

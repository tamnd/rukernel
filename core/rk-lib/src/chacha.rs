//! The ChaCha20 block function and a random number generator on it.
//!
//! The kernel random generator of Linux, drivers/char/random.c, uses ChaCha20 with fast key
//! erasure: each request makes a new key first, so a later look at the state does not show the
//! old output. `ChaChaRng` does the same. The seed comes from the CPU, per
//! spec/05-processes-signals-exec.md.

/// The constant "expand 32-byte k" of ChaCha.
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// Gives the 64 byte block of ChaCha20 for `key`, the block counter `counter` and `nonce`, per
/// RFC 8439 section 2.3.
pub fn block(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [u8; 64] {
    let mut init = [0u32; 16];
    init[..4].copy_from_slice(&SIGMA);
    init[4..12].copy_from_slice(key);
    init[12] = counter;
    init[13..].copy_from_slice(nonce);
    let mut s = init;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for (i, word) in s.iter().enumerate() {
        let v = word.wrapping_add(init[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

/// A random number generator with ChaCha20 and fast key erasure.
#[derive(Clone, Debug)]
pub struct ChaChaRng {
    key: [u32; 8],
    nonce: u64,
}

/// Reads 8 little endian words from 32 bytes.
fn words(bytes: &[u8]) -> [u32; 8] {
    core::array::from_fn(|i| {
        u32::from_le_bytes([bytes[i * 4], bytes[i * 4 + 1], bytes[i * 4 + 2], bytes[i * 4 + 3]])
    })
}

impl ChaChaRng {
    /// Makes a generator from a 32 byte seed.
    pub fn new(seed: [u8; 32]) -> Self {
        Self { key: words(&seed), nonce: 0 }
    }

    /// Mixes `value` into the key, for a new seed from the CPU or from an interrupt time.
    pub fn mix(&mut self, value: u64) {
        self.key[0] ^= value as u32;
        self.key[1] ^= (value >> 32) as u32;
        self.fill(&mut []);
    }

    /// Fills `buf` with random bytes. The first block gives a new key and the key of the output,
    /// so the key changes before the bytes go out.
    pub fn fill(&mut self, buf: &mut [u8]) {
        self.nonce = self.nonce.wrapping_add(1);
        let nonce = [self.nonce as u32, (self.nonce >> 32) as u32, 0];
        let first = block(&self.key, 0, &nonce);
        self.key = words(&first[..32]);
        let out_key = words(&first[32..]);
        for (n, chunk) in buf.chunks_mut(64).enumerate() {
            let b = block(&out_key, n as u32, &nonce);
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8439_block() {
        // RFC 8439 section 2.3.2.
        let key: [u32; 8] = core::array::from_fn(|i| {
            let b = (i * 4) as u32;
            u32::from_le_bytes([b as u8, (b + 1) as u8, (b + 2) as u8, (b + 3) as u8])
        });
        let nonce = [0x0900_0000, 0x4a00_0000, 0];
        let out = block(&key, 1, &nonce);
        assert_eq!(&out[..8], &[0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15]);
        assert_eq!(&out[56..], &[0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e]);
    }

    #[test]
    fn rng_output_changes() {
        let mut rng = ChaChaRng::new([7; 32]);
        let mut a = [0u8; 100];
        let mut b = [0u8; 100];
        rng.fill(&mut a);
        rng.fill(&mut b);
        assert_ne!(a, b);
        assert_ne!(a, [0; 100]);
        let mut again = ChaChaRng::new([7; 32]);
        let mut c = [0u8; 100];
        again.fill(&mut c);
        assert_eq!(a, c);
    }
}

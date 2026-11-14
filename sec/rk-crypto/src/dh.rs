//! Diffie-Hellman, as crypto/dh.c of Linux, and the key derivation function in counter mode of
//! SP800-108, as crypto/kdf_sp800108.c of Linux.

use crate::mpi::Mpi;
use crate::{Hash, Result};
use alloc::vec::Vec;
use rk_abi::Errno;

/// The shortest prime in bits, as `dh_check_params_length` of Linux without FIPS.
const MIN_PRIME_BITS: usize = 1536;

/// Computes `g^key mod p`, as `dh_set_secret` and `dh_compute_value` of Linux with no input.
/// The arguments are big-endian. The result has the size of `p` without its zero bytes at the
/// start, as `crypto_kpp_maxsize`, with zero bytes at the start of the value.
///
/// # Errors
///
/// Gives `EINVAL` if `key` or `g` is longer than `p`, if `p` is 0, or if `p` has fewer than
/// 1536 bits with its zero bytes at the start.
pub fn compute(key: &[u8], p: &[u8], g: &[u8]) -> Result<Vec<u8>> {
    if key.len() > p.len() || g.len() > p.len() || p.iter().all(|&b| b == 0) {
        return Err(Errno::EINVAL);
    }
    if p.len() * 8 < MIN_PRIME_BITS {
        return Err(Errno::EINVAL);
    }
    let p = Mpi::from_be(p);
    let val = Mpi::from_be(g).pow_mod(&Mpi::from_be(key), &p);
    val.to_be_padded(p.byte_len()).ok_or(Errno::EOVERFLOW)
}

/// Fills `out` with the KDF in counter mode of SP800-108, as `crypto_kdf108_ctr_generate` of
/// Linux: each block is the hash of a 32-bit big-endian counter from 1 and `info`.
///
/// # Errors
///
/// Gives `ENOKEY` for a keyed hash without a key, as `crypto_shash_init` of Linux.
pub fn kdf108_ctr(hash: &mut dyn Hash, info: &[u8], out: &mut [u8]) -> Result<()> {
    if hash.needs_key() {
        return Err(Errno::ENOKEY);
    }
    let h = hash.digest_size();
    let mut block = alloc::vec![0u8; h];
    for (i, chunk) in out.chunks_mut(h).enumerate() {
        let counter = (i as u32).wrapping_add(1);
        hash.init();
        hash.update(&counter.to_be_bytes());
        hash.update(info);
        hash.finish(&mut block);
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
    Ok(())
}

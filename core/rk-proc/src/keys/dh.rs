//! `KEYCTL_DH_COMPUTE`, as `security/keys/dh.c` of Linux: the Diffie-Hellman value of three
//! `user` keys, with or without the key derivation function of SP800-108.

use super::{Caller, Kind, Need, READ, lookup};
use alloc::boxed::Box;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_crypto::Hash;

/// The longest output with the KDF, as `KEYCTL_KDF_MAX_OUTPUT_LEN`.
pub const KDF_MAX_OUTPUT: usize = 1024;
/// The longest other information of the KDF, as `KEYCTL_KDF_MAX_OI_LEN`.
pub const KDF_MAX_OTHERINFO: usize = 64;

/// The KDF of `KEYCTL_DH_COMPUTE`: the hash from `alloc_hash` and the other information that
/// follows the shared secret in the input of the KDF.
pub struct Kdf {
    /// The hash, from the name in `struct keyctl_kdf_params`.
    pub hash: Box<dyn Hash>,
    /// The other information of SP800-56A.
    pub otherinfo: Vec<u8>,
}

/// The payload of the `user` key `id`, as `dh_data_from_key`.
///
/// # Errors
///
/// Gives `ENOKEY` if the lookup fails, `EOPNOTSUPP` for a key of another type, or the error of
/// the state of the key.
fn data_from_key(cx: &Caller<'_>, id: i32) -> Result<Vec<u8>, Errno> {
    let r = lookup(cx, id, 0, Need::Perm(READ)).map_err(|_| Errno::ENOKEY)?;
    if r.key.kind != Kind::User {
        return Err(Errno::EOPNOTSUPP);
    }
    r.key.validate(cx.now)?;
    Ok(r.key.state.lock().payload.clone())
}

/// Computes `base^private mod prime` from the payloads of three `user` keys, as
/// `KEYCTL_DH_COMPUTE`. The system call checks the KDF parameters and finds the hash first.
///
/// Without a KDF, gives the size of the value and the value. The value is empty if `buflen` is
/// 0. With a KDF, gives `buflen` bytes of the KDF of the value and the other information.
///
/// # Errors
///
/// Gives the error of the lookup of a key, `EINVAL` for bad parameters, `EOVERFLOW` if the
/// value does not fit in `buflen` bytes, or the error of the KDF.
pub fn dh_compute(
    cx: &Caller<'_>,
    private: i32,
    prime: i32,
    base: i32,
    buflen: usize,
    kdf: Option<Kdf>,
) -> Result<(usize, Vec<u8>), Errno> {
    let p = data_from_key(cx, prime)?;
    let g = data_from_key(cx, base)?;
    let x = data_from_key(cx, private)?;
    let value = rk_crypto::dh::compute(&x, &p, &g)?;
    let Some(mut kdf) = kdf else {
        if buflen == 0 {
            return Ok((value.len(), Vec::new()));
        }
        if value.len() > buflen {
            return Err(Errno::EOVERFLOW);
        }
        return Ok((value.len(), value));
    };
    let mut info = value;
    info.extend_from_slice(&kdf.otherinfo);
    let mut out = alloc::vec![0u8; buflen];
    rk_crypto::dh::kdf108_ctr(kdf.hash.as_mut(), &info, &mut out)?;
    Ok((buflen, out))
}

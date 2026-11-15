//! The operations of `KEYCTL_PKEY_*` on an `asymmetric` key, as `security/keys/keyctl_pkey.c`
//! of Linux.

use super::{Caller, Kind, Need, SEARCH, lookup, random};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_crypto::asym::{Op, Parsed, Query};

/// An `asymmetric` key and the options of the operation, as `struct kernel_pkey_params`.
pub struct Pkey {
    key: Arc<Parsed>,
    /// The encoding: `raw` if the options do not give one.
    encoding: String,
    /// The name of the hash, if the options give one.
    hash: Option<String>,
}

/// Parses the options of an operation, as `keyctl_pkey_params_parse`: `enc=NAME` and
/// `hash=NAME`, with spaces or tabs between them. Gives the encoding and the hash.
///
/// # Errors
///
/// Gives `EINVAL` for an unknown option, an option that is there two times, or an option
/// with no value.
fn parse_info(info: &[u8]) -> Result<(String, Option<String>), Errno> {
    let mut encoding = None;
    let mut hash = None;
    for token in info.split(|&b| b == b' ' || b == b'\t').filter(|t| !t.is_empty()) {
        let (slot, value) = if let Some(v) = token.strip_prefix(b"enc=") {
            (&mut encoding, v)
        } else if let Some(v) = token.strip_prefix(b"hash=") {
            (&mut hash, v)
        } else {
            return Err(Errno::EINVAL);
        };
        if slot.is_some() || value.is_empty() {
            return Err(Errno::EINVAL);
        }
        *slot = Some(String::from_utf8_lossy(value).into_owned());
    }
    Ok((encoding.unwrap_or_else(|| String::from("raw")), hash))
}

/// Finds the key `id` for an operation with the options `info`, as `keyctl_pkey_params_get`.
///
/// # Errors
///
/// Gives `EINVAL` for bad options, the error of the lookup, or `EOPNOTSUPP` for a key that is
/// not an `asymmetric` key.
pub fn pkey_open(cx: &Caller<'_>, id: i32, info: &[u8]) -> Result<Pkey, Errno> {
    let (encoding, hash) = parse_info(info)?;
    let r = lookup(cx, id, 0, Need::Perm(SEARCH))?;
    if r.key.kind != Kind::Asymmetric {
        return Err(Errno::EOPNOTSUPP);
    }
    let key = r.key.state.lock().asym.clone().ok_or(Errno::EINVAL)?;
    Ok(Pkey { key, encoding, hash })
}

impl Pkey {
    /// The operations and the sizes of the key, as `KEYCTL_PKEY_QUERY`.
    ///
    /// # Errors
    ///
    /// Gives the error of [`rk_crypto::asym::PublicKey::query`].
    pub fn query(&self) -> Result<Query, Errno> {
        self.key.key.query(&self.encoding, self.hash.as_deref())
    }

    /// Checks the lengths of an operation against the sizes of the key, as
    /// `keyctl_pkey_params_get_2`. `out_len` is the length of the signature for a check.
    ///
    /// # Errors
    ///
    /// Gives the error of [`Pkey::query`], or `EINVAL` if a length is larger than the size for
    /// the operation.
    pub fn check_lengths(&self, op: Op, in_len: u32, out_len: u32) -> Result<(), Errno> {
        let q = self.query()?;
        let (max_in, max_out) = match op {
            Op::Encrypt => (q.max_dec_size, q.max_enc_size),
            Op::Decrypt => (q.max_enc_size, q.max_dec_size),
            Op::Sign => (q.max_data_size, q.max_sig_size),
            Op::Verify => (q.max_data_size, q.max_sig_size),
        };
        if in_len > u32::from(max_in) || out_len > u32::from(max_out) {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }

    /// Encrypts, decrypts or signs `input` into a buffer of `out_len` bytes, as
    /// `asymmetric_key_eds_op`. The length of the result is the value of the system call.
    ///
    /// # Errors
    ///
    /// Gives the error of [`rk_crypto::asym::PublicKey::eds`].
    pub fn eds(&self, op: Op, input: &[u8], out_len: usize) -> Result<Vec<u8>, Errno> {
        self.key.key.eds(op, &self.encoding, self.hash.as_deref(), input, out_len, &mut random)
    }

    /// Checks the signature `sig` of `digest`, as `asymmetric_key_verify_signature`.
    ///
    /// # Errors
    ///
    /// Gives the error of [`rk_crypto::asym::PublicKey::verify`].
    pub fn verify(&self, digest: &[u8], sig: &[u8]) -> Result<(), Errno> {
        self.key.key.verify(&self.encoding, self.hash.as_deref(), sig, digest)
    }
}

#[cfg(test)]
mod tests {
    use super::parse_info;
    use alloc::string::String;
    use rk_abi::Errno;

    #[test]
    fn info_options() {
        let s = |v: &str| String::from(v);
        assert_eq!(parse_info(b"").unwrap(), (s("raw"), None));
        assert_eq!(
            parse_info(b" enc=pkcs1\thash=sha256 ").unwrap(),
            (s("pkcs1"), Some(s("sha256")))
        );
        assert_eq!(parse_info(b"enc=pkcs1 enc=raw"), Err(Errno::EINVAL));
        assert_eq!(parse_info(b"enc="), Err(Errno::EINVAL));
        assert_eq!(parse_info(b"key=1"), Err(Errno::EINVAL));
    }
}

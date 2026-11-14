//! RSA, as crypto/rsa.c of Linux, and the padding of PKCS#1 v1.5, as crypto/rsa-pkcs1pad.c of
//! Linux.
//!
//! A key comes from the DER of `RSAPublicKey` or `RSAPrivateKey` of RFC 8017. The private key
//! uses `c^d mod n`: the result is the same as with the Chinese remainder theorem of Linux.

use crate::Result;
use crate::asn1::{self, INT, SEQ};
use crate::mpi::Mpi;
use alloc::vec::Vec;
use rk_abi::Errno;

/// The prefix of the `DigestInfo` of a hash, as `rsa_asn1_templates` of Linux.
///
/// Gives `None` for a hash that has no prefix.
pub fn digest_info(hash: &str) -> Option<&'static [u8]> {
    Some(match hash {
        "md5" => &[
            0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
            0x05, 0x00, 0x04, 0x10,
        ],
        "rmd160" => &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x01, 0x05, 0x00, 0x04,
            0x14,
        ],
        "sha3-256" => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x08, 0x05, 0x00, 0x04, 0x20,
        ],
        "sha3-384" => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x09, 0x05, 0x00, 0x04, 0x30,
        ],
        "sha3-512" => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x0a, 0x05, 0x00, 0x04, 0x40,
        ],
        "sha1" => &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ],
        "sha224" => &[
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x04, 0x05, 0x00, 0x04, 0x1c,
        ],
        "sha256" => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        "sha384" => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        "sha512" => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ],
        _ => return None,
    })
}

/// An RSA key, as `struct rsa_mpi_key` of Linux.
#[derive(Clone, Debug)]
pub struct RsaKey {
    n: Mpi,
    e: Mpi,
    d: Option<Mpi>,
    /// The size of the modulus in bytes, as `crypto_akcipher_maxsize`.
    size: usize,
}

/// Reads an `INTEGER` of the key, as `rsa_get_n` and the other functions of `rsa_helper.c`:
/// the content must not be empty, and only `n` can be longer than `n_len`. Gives the value and
/// the length of its content.
fn int(d: &mut asn1::Der<'_>, n_len: Option<usize>) -> Result<(Mpi, usize)> {
    let v = d.expect(INT)?.value;
    if v.is_empty() || n_len.is_some_and(|n| v.len() > n) {
        return Err(Errno::EINVAL);
    }
    Ok((Mpi::from_be(v), v.len()))
}

impl RsaKey {
    /// Reads the DER of `RSAPublicKey`, as `rsa_set_pub_key`.
    ///
    /// # Errors
    ///
    /// Gives `EBADMSG` for bad DER, or `EINVAL` for a bad value or a modulus that does not have
    /// 512, 1024, 1536, 2048, 3072 or 4096 bits.
    pub fn from_public_der(der: &[u8]) -> Result<Self> {
        let seq = asn1::top(der, SEQ)?;
        let mut d = seq.inner();
        let (n, n_raw) = int(&mut d, None)?;
        let (e, _) = int(&mut d, Some(n_raw))?;
        asn1::end(&d)?;
        Self::new(n, e, None)
    }

    /// Reads the DER of `RSAPrivateKey`, as `rsa_set_priv_key`.
    ///
    /// # Errors
    ///
    /// Gives `EBADMSG` for bad DER, or `EINVAL` for a bad value or a modulus that does not have
    /// 512, 1024, 1536, 2048, 3072 or 4096 bits.
    pub fn from_private_der(der: &[u8]) -> Result<Self> {
        let seq = asn1::top(der, SEQ)?;
        let mut d = seq.inner();
        d.expect(INT)?;
        let (n, n_raw) = int(&mut d, None)?;
        let (e, _) = int(&mut d, Some(n_raw))?;
        let (priv_d, _) = int(&mut d, Some(n_raw))?;
        // The primes, the exponents and the coefficient of the Chinese remainder theorem.
        for _ in 0..5 {
            int(&mut d, Some(n_raw))?;
        }
        asn1::end(&d)?;
        Self::new(n, e, Some(priv_d))
    }

    fn new(n: Mpi, e: Mpi, d: Option<Mpi>) -> Result<Self> {
        let size = n.byte_len();
        if !matches!(size * 8, 512 | 1024 | 1536 | 2048 | 3072 | 4096) {
            return Err(Errno::EINVAL);
        }
        Ok(RsaKey { n, e, d, size })
    }

    /// The size of the modulus in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// True for a private key.
    pub fn is_private(&self) -> bool {
        self.d.is_some()
    }

    /// `m^e mod n`, as `_rsa_enc`.
    fn public_op(&self, m: &Mpi) -> Result<Mpi> {
        if *m >= self.n {
            return Err(Errno::EINVAL);
        }
        Ok(m.pow_mod(&self.e, &self.n))
    }

    /// `c^d mod n`, as `_rsa_dec_crt`. A public key gives `EINVAL`, as `rsa_dec`.
    fn private_op(&self, c: &Mpi) -> Result<Mpi> {
        let d = self.d.as_ref().ok_or(Errno::EINVAL)?;
        if *c >= self.n {
            return Err(Errno::EINVAL);
        }
        Ok(c.pow_mod(d, &self.n))
    }

    /// The value `v` in `size` bytes, as `mpi_write_to_sgl` into a buffer of the size of the key.
    fn out(&self, v: &Mpi) -> Result<Vec<u8>> {
        v.to_be_padded(self.size).ok_or(Errno::EOVERFLOW)
    }

    /// Encrypts with no padding, as the `rsa` algorithm: `input^e mod n` in the size of the key.
    ///
    /// # Errors
    ///
    /// Gives `EOVERFLOW` if `out_len` is less than the size of the key, or `EINVAL` if the input
    /// is not less than the modulus.
    pub fn encrypt_raw(&self, input: &[u8], out_len: usize) -> Result<Vec<u8>> {
        if out_len < self.size {
            return Err(Errno::EOVERFLOW);
        }
        self.out(&self.public_op(&Mpi::from_be(input))?)
    }

    /// Decrypts with no padding, as the `rsa` algorithm: `input^d mod n` in the size of the key.
    ///
    /// # Errors
    ///
    /// Gives `EOVERFLOW` if `out_len` is less than the size of the key, or `EINVAL` for a public
    /// key or an input that is not less than the modulus.
    pub fn decrypt_raw(&self, input: &[u8], out_len: usize) -> Result<Vec<u8>> {
        if out_len < self.size {
            return Err(Errno::EOVERFLOW);
        }
        self.out(&self.private_op(&Mpi::from_be(input))?)
    }

    /// Encrypts with the padding of PKCS#1 v1.5, as `pkcs1pad_encrypt`. `random` gives the
    /// random bytes of the padding.
    ///
    /// # Errors
    ///
    /// Gives `EOVERFLOW` if the input is longer than the size of the key less 11 bytes, or if
    /// `out_len` is less than the size of the key.
    pub fn encrypt_pkcs1(
        &self,
        input: &[u8],
        out_len: usize,
        random: &mut dyn FnMut() -> u64,
    ) -> Result<Vec<u8>> {
        let k = self.size;
        if input.len() > k - 11 || out_len < k {
            return Err(Errno::EOVERFLOW);
        }
        let mut em = Vec::with_capacity(k);
        em.push(0x02);
        while em.len() < k - input.len() - 2 {
            em.push((random() % 255) as u8 + 1);
        }
        em.push(0);
        em.extend_from_slice(input);
        self.out(&self.public_op(&Mpi::from_be(&em))?)
    }

    /// Decrypts with the padding of PKCS#1 v1.5, as `pkcs1pad_decrypt`, and gives the message.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` if the input does not have the size of the key, for a public key, or for
    /// a bad padding, and `EOVERFLOW` if the message is longer than `out_len`.
    pub fn decrypt_pkcs1(&self, input: &[u8], out_len: usize) -> Result<Vec<u8>> {
        if input.len() != self.size {
            return Err(Errno::EINVAL);
        }
        let em = self.out(&self.private_op(&Mpi::from_be(input))?)?;
        if em[0] != 0 || em[1] != 0x02 {
            return Err(Errno::EINVAL);
        }
        let em = &em[1..];
        let pos = em.iter().skip(1).position(|&b| b == 0).map(|p| p + 1);
        let pos = match pos {
            Some(p) if p >= 9 => p + 1,
            _ => return Err(Errno::EINVAL),
        };
        if out_len < em.len() - pos {
            return Err(Errno::EOVERFLOW);
        }
        Ok(em[pos..].to_vec())
    }

    /// Signs with the padding of PKCS#1 v1.5, as `pkcs1pad_sign`. `info` is the prefix of the
    /// `DigestInfo`, or `None` if `input` has it.
    ///
    /// # Errors
    ///
    /// Gives `EOVERFLOW` if the input and the prefix are longer than the size of the key less 11
    /// bytes, or if `out_len` is less than the size of the key, and `EINVAL` for a public key.
    pub fn sign_pkcs1(&self, info: Option<&[u8]>, input: &[u8], out_len: usize) -> Result<Vec<u8>> {
        let k = self.size;
        let info = info.unwrap_or_default();
        if input.len() + info.len() > k - 11 || out_len < k {
            return Err(Errno::EOVERFLOW);
        }
        let mut em = Vec::with_capacity(k);
        em.push(0x01);
        em.resize(k - info.len() - input.len() - 2, 0xff);
        em.push(0);
        em.extend_from_slice(info);
        em.extend_from_slice(input);
        self.out(&self.private_op(&Mpi::from_be(&em))?)
    }

    /// Checks a signature with the padding of PKCS#1 v1.5, as `pkcs1pad_verify`. `info` is the
    /// prefix of the `DigestInfo`, or `None` if `digest` has it.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` for an empty digest, a signature that does not have the size of the key or
    /// that is not less than the modulus, `EBADMSG` for a bad padding or prefix, and
    /// `EKEYREJECTED` if the digest is not the same.
    pub fn verify_pkcs1(&self, info: Option<&[u8]>, sig: &[u8], digest: &[u8]) -> Result<()> {
        if digest.is_empty() || sig.len() != self.size {
            return Err(Errno::EINVAL);
        }
        let em = self.out(&self.public_op(&Mpi::from_be(sig))?)?;
        if em[0] != 0 {
            return Err(Errno::EINVAL);
        }
        let em = &em[1..];
        if em[0] != 0x01 {
            return Err(Errno::EBADMSG);
        }
        let pos = em.iter().skip(1).position(|&b| b != 0xff).map_or(em.len(), |p| p + 1);
        if pos < 9 || pos == em.len() || em[pos] != 0 {
            return Err(Errno::EBADMSG);
        }
        let mut rest = &em[pos + 1..];
        if let Some(info) = info {
            rest = rest.strip_prefix(info).ok_or(Errno::EBADMSG)?;
        }
        if rest != digest {
            return Err(Errno::EKEYREJECTED);
        }
        Ok(())
    }
}

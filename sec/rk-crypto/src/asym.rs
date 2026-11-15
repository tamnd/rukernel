//! The data of the `asymmetric` keys, as crypto/asymmetric_keys of Linux: the parsers of X.509
//! certificates and of PKCS#8 private keys, the check of a signature, and the operations of
//! `KEYCTL_PKEY_*` on an RSA key.
//!
//! As Linux, the parsers keep the DER of the RSA key, and an operation reads it again.

use crate::asn1::{
    self, BOOL, BTS, Der, Elem, GEN_TIME, INT, OID, OTS, SEQ, SET, UTC_TIME, cont, oid,
};
use crate::rsa::{RsaKey, digest_info};
use crate::{MAX_ALG_NAME, Result, alloc_hash};
use alloc::vec::Vec;
use rk_abi::Errno;

/// The key can encrypt, as `KEYCTL_SUPPORTS_ENCRYPT`.
pub const SUPPORTS_ENCRYPT: u32 = 0x01;
/// The key can decrypt, as `KEYCTL_SUPPORTS_DECRYPT`.
pub const SUPPORTS_DECRYPT: u32 = 0x02;
/// The key can sign, as `KEYCTL_SUPPORTS_SIGN`.
pub const SUPPORTS_SIGN: u32 = 0x04;
/// The key can check a signature, as `KEYCTL_SUPPORTS_VERIFY`.
pub const SUPPORTS_VERIFY: u32 = 0x08;

/// The bytes of quota of an `asymmetric` key, as the `quotalen` of the parsers.
pub const QUOTA: u32 = 100;

/// A public or private key, as `struct public_key` of Linux.
#[derive(Clone, Debug)]
pub struct PublicKey {
    /// The DER of `RSAPublicKey`, or of `RSAPrivateKey` for a private key.
    pub key: Vec<u8>,
    /// The key is a private key.
    pub is_private: bool,
    /// The name of the format: `X509` or `PKCS8`.
    pub id_type: &'static str,
    /// The name of the algorithm: `rsa`.
    pub algo: &'static str,
}

/// The signature of a certificate, as `struct public_key_signature` of Linux.
#[derive(Clone, Debug)]
pub struct Signature {
    /// The IDs of the key that made the signature: the serial number and the issuer of the
    /// authority key identifier, its key identifier, and the issuer.
    pub auth_ids: [Option<Vec<u8>>; 3],
    /// The signature.
    pub s: Vec<u8>,
    /// The digest of the signed data.
    pub digest: Vec<u8>,
    /// The name of the hash.
    pub hash_algo: &'static str,
    /// The encoding of the signature: `pkcs1`.
    pub encoding: &'static str,
}

/// The data of an `asymmetric` key after its parser, as the payload of Linux.
#[derive(Clone, Debug)]
pub struct Parsed {
    /// The key.
    pub key: PublicKey,
    /// The IDs of the key, as `struct asymmetric_key_ids`: the serial number and the issuer,
    /// the subject key identifier, and the subject. A PKCS#8 key has no IDs.
    pub ids: Option<[Option<Vec<u8>>; 3]>,
    /// The signature of a certificate, if the kernel has its algorithms.
    pub sig: Option<Signature>,
    /// The description that the parser proposes.
    pub desc: Option<Vec<u8>>,
}

/// Parses the payload of a new `asymmetric` key, as `asymmetric_key_preparse`: each parser
/// tries the data while the result is `EBADMSG`.
///
/// # Errors
///
/// Gives `EINVAL` for no data, `EBADMSG` if no parser knows the data, or the error of the
/// parser that knows it.
pub fn parse(data: &[u8]) -> Result<Parsed> {
    if data.is_empty() {
        return Err(Errno::EINVAL);
    }
    match parse_x509(data) {
        Err(Errno::EBADMSG) => parse_pkcs8(data),
        r => r,
    }
}

/// Lower-case hexadecimal, as `bin2hex`.
pub fn hex(data: &[u8]) -> Vec<u8> {
    const D: &[u8; 16] = b"0123456789abcdef";
    data.iter().flat_map(|&b| [D[usize::from(b >> 4)], D[usize::from(b & 15)]]).collect()
}

/// The parts of a name that `x509_extract_name_segment` keeps. The last of each wins.
#[derive(Default)]
struct NameParts<'a> {
    cn: Option<&'a [u8]>,
    o: Option<&'a [u8]>,
    email: Option<&'a [u8]>,
}

/// Reads a `Name` and makes its text, as `x509_fabricate_name`.
fn name(e: &Elem<'_>) -> Result<Vec<u8>> {
    let mut parts = NameParts::default();
    let mut rdns = e.inner();
    while !rdns.is_empty() {
        let mut set = rdns.expect(SET)?.inner();
        while !set.is_empty() {
            let mut ava = set.expect(SEQ)?.inner();
            let id = ava.expect(OID)?.value;
            let value = ava.read()?.value;
            asn1::end(&ava)?;
            let value = (!value.is_empty()).then_some(value);
            match id {
                oid::COMMON_NAME => parts.cn = value,
                oid::ORGANIZATION_NAME => parts.o = value,
                oid::EMAIL_ADDRESS => parts.email = value,
                _ => {}
            }
        }
    }
    let name = match (parts.cn, parts.o) {
        (Some(cn), Some(o)) => {
            if (cn.len() >= o.len() && cn.starts_with(o))
                || (cn.len() >= 7 && o.len() >= 7 && cn[..7] == o[..7])
            {
                cn.to_vec()
            } else {
                let mut n = o.to_vec();
                n.extend_from_slice(b": ");
                n.extend_from_slice(cn);
                n
            }
        }
        (Some(cn), None) => cn.to_vec(),
        (None, Some(o)) => o.to_vec(),
        (None, None) => parts.email.unwrap_or_default().to_vec(),
    };
    // The name is a C string in Linux.
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    Ok(name[..end].to_vec())
}

/// Checks a time of the validity, as `x509_decode_time`.
fn check_time(e: &Elem<'_>) -> Result<()> {
    let v = e.value;
    let digit = |i: usize| -> Result<u32> {
        let d = v[i].wrapping_sub(b'0');
        if d > 9 { Err(Errno::EBADMSG) } else { Ok(u32::from(d)) }
    };
    let dd = |i: usize| -> Result<u32> { Ok(digit(i)? * 10 + digit(i + 1)?) };
    let (year, at) = match e.tag {
        UTC_TIME if v.len() == 13 => {
            let y = dd(0)?;
            (if y >= 50 { y + 1900 } else { y + 2000 }, 2)
        }
        GEN_TIME if v.len() == 15 => {
            let y = dd(0)? * 100 + dd(2)?;
            if (1950..=2049).contains(&y) {
                return Err(Errno::EBADMSG);
            }
            (y, 4)
        }
        _ => return Err(Errno::EBADMSG),
    };
    let (mon, day, hour, min, sec) = (dd(at)?, dd(at + 2)?, dd(at + 4)?, dd(at + 6)?, dd(at + 8)?);
    if v[at + 10] != b'Z' || year < 1970 || !(1..=12).contains(&mon) {
        return Err(Errno::EBADMSG);
    }
    const DAYS: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mon_len = DAYS[mon as usize - 1];
    if mon == 2 && year % 4 == 0 && (year % 100 != 0 || (year / 100) % 4 == 0) {
        mon_len = 29;
    }
    if day < 1 || day > mon_len || hour > 24 || min > 59 || sec > 60 {
        return Err(Errno::EBADMSG);
    }
    Ok(())
}

/// Reads an `AlgorithmIdentifier` and gives its object identifier.
fn algorithm<'a>(d: &mut Der<'a>) -> Result<&'a [u8]> {
    let mut alg = d.expect(SEQ)?.inner();
    let id = alg.expect(OID)?.value;
    if !alg.is_empty() {
        alg.read()?;
    }
    asn1::end(&alg)?;
    Ok(id)
}

/// The hash of an RSA signature algorithm, as `x509_note_sig_algo`.
fn sig_hash(id: &[u8]) -> Result<&'static str> {
    /// The prefix of 2.16.840.1.101.3.4.3, the signature algorithms with SHA-3.
    const SHA3_RSA: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03];
    Ok(match id {
        oid::SHA256_WITH_RSA => "sha256",
        oid::SHA384_WITH_RSA => "sha384",
        oid::SHA512_WITH_RSA => "sha512",
        oid::SHA224_WITH_RSA => "sha224",
        _ => match id.strip_prefix(SHA3_RSA) {
            Some([0x0e]) => "sha3-256",
            Some([0x0f]) => "sha3-384",
            Some([0x10]) => "sha3-512",
            _ => return Err(Errno::ENOPKG),
        },
    })
}

/// The parts of a certificate that the parser keeps, as `struct x509_parse_context`.
#[derive(Default)]
struct Cert<'a> {
    serial: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    subject_name: Vec<u8>,
    key: &'a [u8],
    skid: Option<&'a [u8]>,
    akid: Option<&'a [u8]>,
}

/// Checks an extension and keeps the key identifiers, as `x509_process_extension`.
fn extension<'a>(c: &mut Cert<'a>, id: &[u8], v: &'a [u8]) -> Result<()> {
    match id {
        oid::SUBJECT_KEY_ID => {
            if c.skid.is_some() || v.len() < 3 || v[0] != OTS || usize::from(v[1]) != v.len() - 2 {
                return Err(Errno::EBADMSG);
            }
            c.skid = Some(&v[2..]);
        }
        oid::KEY_USAGE if v.len() < 4 || v[0] != BTS || v[2] >= 8 => {
            return Err(Errno::EBADMSG);
        }
        oid::AUTHORITY_KEY_ID => c.akid = Some(v),
        oid::BASIC_CONSTRAINTS
            if v.len() < 2 || v[0] != SEQ || usize::from(v[1]) != v.len() - 2 =>
        {
            return Err(Errno::EBADMSG);
        }
        _ => {}
    }
    Ok(())
}

/// Reads the authority key identifier, as the `x509_akid` grammar: gives the IDs 0 and 1 of the
/// signature.
fn akid(raw: &[u8], issuer_ids: &mut [Option<Vec<u8>>; 3]) -> Result<()> {
    let mut d = Der::new(raw).expect(SEQ)?.inner();
    if let Some(kid) = d.optional(asn1::cont_prim(0))? {
        issuer_ids[1] = Some(kid.value.to_vec());
    }
    let mut dir_name = None;
    if let Some(names) = d.optional(cont(1))? {
        let mut names = names.inner();
        while !names.is_empty() {
            let gn = names.read()?;
            if gn.tag == cont(4) {
                let mut inner = gn.inner();
                dir_name = Some(inner.expect(SEQ)?.value);
                asn1::end(&inner)?;
            }
        }
    }
    if let Some(serial) = d.optional(asn1::cont_prim(2))?
        && let Some(issuer) = dir_name
    {
        let mut id = serial.value.to_vec();
        id.extend_from_slice(issuer);
        issuer_ids[0] = Some(id);
    }
    asn1::end(&d)
}

/// Parses an X.509 certificate, as `x509_key_preparse`.
///
/// # Errors
///
/// Gives `EMSGSIZE` for more than 64 KiB, `EBADMSG` for bad data, `ENOPKG` for an algorithm that
/// the kernel does not have, `EINVAL` if the two signature algorithms differ, or
/// `EKEYREJECTED` for a bad self-signature.
pub fn parse_x509(data: &[u8]) -> Result<Parsed> {
    let top = asn1::top(data, SEQ)?;
    let mut d = top.inner();
    let tbs = d.expect(SEQ)?;
    let mut c = Cert::default();
    let mut t = tbs.inner();
    t.optional(cont(0))?;
    c.serial = t.expect(INT)?.value;
    let sig_algo = algorithm(&mut t)?;
    let hash_algo = sig_hash(sig_algo)?;
    let issuer = t.expect(SEQ)?;
    c.issuer = issuer.value;
    name(&issuer)?;
    let mut validity = t.expect(SEQ)?.inner();
    check_time(&validity.read()?)?;
    check_time(&validity.read()?)?;
    asn1::end(&validity)?;
    let subject = t.expect(SEQ)?;
    c.subject = subject.value;
    c.subject_name = name(&subject)?;
    let mut spki = t.expect(SEQ)?.inner();
    if algorithm(&mut spki)? != oid::RSA_ENCRYPTION {
        return Err(Errno::ENOPKG);
    }
    let bits = spki.expect(BTS)?.value;
    asn1::end(&spki)?;
    match bits.split_first() {
        Some((0, key)) => c.key = key,
        _ => return Err(Errno::EBADMSG),
    }
    t.optional(asn1::cont_prim(1))?;
    t.optional(asn1::cont_prim(2))?;
    if let Some(ext) = t.optional(cont(3))? {
        let mut outer = ext.inner();
        let mut exts = outer.expect(SEQ)?.inner();
        asn1::end(&outer)?;
        while !exts.is_empty() {
            let mut e = exts.expect(SEQ)?.inner();
            let id = e.expect(OID)?.value;
            e.optional(BOOL)?;
            let v = e.expect(OTS)?.value;
            asn1::end(&e)?;
            extension(&mut c, id, v)?;
        }
    }
    asn1::end(&t)?;
    if algorithm(&mut d)? != sig_algo {
        return Err(Errno::EINVAL);
    }
    let s = match d.expect(BTS)?.value.split_first() {
        Some((0, s)) => s,
        _ => return Err(Errno::EBADMSG),
    };
    asn1::end(&d)?;

    let mut auth_ids: [Option<Vec<u8>>; 3] = [None, None, Some(c.issuer.to_vec())];
    if let Some(raw) = c.akid {
        akid(raw, &mut auth_ids)?;
    }
    let key = PublicKey { key: c.key.to_vec(), is_private: false, id_type: "X509", algo: "rsa" };
    let mut id = c.serial.to_vec();
    id.extend_from_slice(c.issuer);
    let skid = c.skid.map(<[u8]>::to_vec);
    // As `x509_check_for_self_signed`: if the authority key identifier has the two IDs, the two
    // must be those of the certificate.
    let self_issued = c.subject == c.issuer;
    let mut check = self_issued;
    if self_issued && (auth_ids[0].is_some() || auth_ids[1].is_some()) {
        let a = skid.is_some() && skid == auth_ids[1];
        let b = auth_ids[0].as_deref() == Some(&id[..]);
        if !a && !b {
            check = false;
        } else if a != b && auth_ids[0].is_some() && auth_ids[1].is_some() {
            return Err(Errno::EKEYREJECTED);
        }
    }
    // As `x509_get_sig_params`: a hash that the kernel does not have makes the signature
    // unsupported, and the key has no signature.
    let mut sig = match alloc_hash(hash_algo) {
        Ok(mut h) => {
            let mut digest = alloc::vec![0u8; h.digest_size()];
            h.init();
            h.update(tbs.raw);
            h.finish(&mut digest);
            Some(Signature { auth_ids, s: s.to_vec(), digest, hash_algo, encoding: "pkcs1" })
        }
        Err(_) => None,
    };
    if check && let Some(sg) = &sig {
        match verify(&key, sg) {
            Ok(()) => {}
            Err(Errno::ENOPKG) => sig = None,
            Err(e) => return Err(e),
        }
    }
    let mut desc = c.subject_name.clone();
    desc.extend_from_slice(b": ");
    desc.extend_from_slice(&hex(c.skid.unwrap_or(c.serial)));
    Ok(Parsed { key, ids: Some([Some(id), skid, Some(c.subject.to_vec())]), sig, desc: Some(desc) })
}

/// Parses a PKCS#8 private key, as `pkcs8_key_preparse`. The key has no IDs, no signature and
/// no description.
///
/// # Errors
///
/// Gives `EMSGSIZE` for more than 64 KiB, `EBADMSG` for bad data or a version other than 0, or
/// `ENOPKG` for an algorithm other than RSA.
pub fn parse_pkcs8(data: &[u8]) -> Result<Parsed> {
    let mut d = asn1::top(data, SEQ)?.inner();
    if d.expect(INT)?.value != [0] {
        return Err(Errno::EBADMSG);
    }
    if algorithm(&mut d)? != oid::RSA_ENCRYPTION {
        return Err(Errno::ENOPKG);
    }
    let key = d.expect(OTS)?.value;
    d.optional(cont(0))?;
    asn1::end(&d)?;
    let key = PublicKey { key: key.to_vec(), is_private: true, id_type: "PKCS8", algo: "rsa" };
    Ok(Parsed { key, ids: None, sig: None, desc: None })
}

/// An operation of `KEYCTL_PKEY_*`, as `enum kernel_pkey_operation`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Encrypt.
    Encrypt,
    /// Decrypt.
    Decrypt,
    /// Sign.
    Sign,
    /// Check a signature.
    Verify,
}

/// The algorithm of an operation, as `software_key_determine_akcipher`.
struct Alg {
    /// The padding of PKCS#1: `pkcs1pad`, else `rsa` with no padding.
    pkcs1: bool,
    /// The algorithm is a signature algorithm.
    issig: bool,
    /// The prefix of the `DigestInfo` of the hash.
    info: Option<&'static [u8]>,
}

impl PublicKey {
    /// Finds the algorithm of `op` with `encoding` and `hash`, as
    /// `software_key_determine_akcipher` and the allocation of the algorithm.
    fn alg(&self, encoding: &str, hash: Option<&str>, op: Op) -> Result<Alg> {
        if self.algo != "rsa" {
            return Err(Errno::ENOPKG);
        }
        match encoding {
            "pkcs1" => {
                let issig = matches!(op, Op::Sign | Op::Verify);
                let info = match hash {
                    None => None,
                    // `pkcs1pad(rsa,HASH)` must fit in the name of an algorithm.
                    Some(h) if "pkcs1pad(rsa,)".len() + h.len() >= MAX_ALG_NAME => {
                        return Err(Errno::EINVAL);
                    }
                    Some(h) => Some(digest_info(h).ok_or(Errno::ENOENT)?),
                };
                Ok(Alg { pkcs1: true, issig, info })
            }
            "raw" if hash.is_none() => Ok(Alg { pkcs1: false, issig: false, info: None }),
            _ => Err(Errno::EINVAL),
        }
    }

    /// Reads the RSA key, as `crypto_akcipher_set_pub_key` and `crypto_akcipher_set_priv_key`.
    fn rsa(&self) -> Result<RsaKey> {
        if self.is_private {
            RsaKey::from_private_der(&self.key)
        } else {
            RsaKey::from_public_der(&self.key)
        }
    }

    /// The operations and the sizes of the key with `encoding` and `hash`, as
    /// `software_key_query`.
    ///
    /// # Errors
    ///
    /// Gives `ENOPKG` for an algorithm other than RSA, `EINVAL` for a bad encoding, `ENOENT`
    /// for an unknown hash, or the error of the key.
    pub fn query(&self, encoding: &str, hash: Option<&str>) -> Result<Query> {
        let alg = self.alg(encoding, hash, Op::Sign)?;
        let len = self.rsa()?.size();
        let private = |ops: u32, more: u32| if self.is_private { ops | more } else { ops };
        let mut ops = private(SUPPORTS_ENCRYPT, SUPPORTS_DECRYPT);
        if alg.issig {
            ops |= private(SUPPORTS_VERIFY, SUPPORTS_SIGN);
        }
        let max = len as u16;
        Ok(Query {
            supported_ops: ops,
            key_size: len as u32 * 8,
            max_data_size: max,
            max_sig_size: max,
            max_enc_size: max,
            max_dec_size: max,
        })
    }

    /// Encrypts, decrypts or signs `input`, as `software_key_eds_op`. `out_len` is the size of
    /// the buffer of the caller, and `random` gives the random bytes of the padding. The result
    /// has the size that the system call gives.
    ///
    /// # Errors
    ///
    /// Gives `ENOPKG`, `EINVAL` or `ENOENT` for a bad algorithm, the error of the key,
    /// `EINVAL` for an operation that the encoding does not have, or the error of the
    /// operation.
    pub fn eds(
        &self,
        op: Op,
        encoding: &str,
        hash: Option<&str>,
        input: &[u8],
        out_len: usize,
        random: &mut dyn FnMut() -> u64,
    ) -> Result<Vec<u8>> {
        let alg = self.alg(encoding, hash, op)?;
        let rsa = self.rsa()?;
        match (op, alg.issig, alg.pkcs1) {
            (Op::Encrypt, false, true) => rsa.encrypt_pkcs1(input, out_len, random),
            (Op::Encrypt, false, false) => rsa.encrypt_raw(input, out_len),
            (Op::Decrypt, false, true) => rsa.decrypt_pkcs1(input, out_len),
            (Op::Decrypt, false, false) => rsa.decrypt_raw(input, out_len),
            (Op::Sign, true, _) => rsa.sign_pkcs1(alg.info, input, out_len),
            _ => Err(Errno::EINVAL),
        }
    }

    /// Checks the signature `s` of `digest` with `encoding` and `hash`, as
    /// `public_key_verify_signature`.
    ///
    /// # Errors
    ///
    /// Gives `ENOPKG`, `EINVAL` or `ENOENT` for a bad algorithm, `ENOSYS` with no padding, the
    /// error of the key, or the error of the check: `EBADMSG` or `EKEYREJECTED` for a bad
    /// signature.
    pub fn verify(
        &self,
        encoding: &str,
        hash: Option<&str>,
        s: &[u8],
        digest: &[u8],
    ) -> Result<()> {
        let alg = self.alg(encoding, hash, Op::Verify)?;
        let rsa = self.rsa()?;
        if !alg.pkcs1 {
            // The `rsa` algorithm has no operation to check a signature.
            return Err(Errno::ENOSYS);
        }
        rsa.verify_pkcs1(alg.info, s, digest)
    }
}

/// Checks the signature of a certificate with `key`, as `public_key_verify_signature`.
///
/// # Errors
///
/// Gives the error of [`PublicKey::verify`].
pub fn verify(key: &PublicKey, sig: &Signature) -> Result<()> {
    key.verify(sig.encoding, Some(sig.hash_algo), &sig.s, &sig.digest)
}

/// The result of `KEYCTL_PKEY_QUERY`, as `struct kernel_pkey_query`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Query {
    /// The operations of the key: the `SUPPORTS_*` bits.
    pub supported_ops: u32,
    /// The size of the key in bits.
    pub key_size: u32,
    /// The largest data to sign.
    pub max_data_size: u16,
    /// The largest signature.
    pub max_sig_size: u16,
    /// The largest encrypted data.
    pub max_enc_size: u16,
    /// The largest data to encrypt.
    pub max_dec_size: u16,
}

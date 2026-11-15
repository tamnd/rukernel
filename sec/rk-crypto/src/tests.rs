//! The tests of the algorithms with the vectors of crypto/testmgr.h of Linux, as the self tests
//! of testmgr.c.

extern crate std;

use super::*;
use crate::testvec;
use alloc::vec;
use alloc::vec::Vec;

/// A vector of a hash, as `struct hash_testvec`.
pub(crate) struct HashVec {
    pub(crate) key: &'static [u8],
    pub(crate) data: &'static [u8],
    pub(crate) digest: &'static [u8],
}

/// A vector of a cipher, as `struct cipher_testvec`.
pub(crate) struct CipherVec {
    pub(crate) key: &'static [u8],
    pub(crate) iv: &'static [u8],
    pub(crate) iv_out: &'static [u8],
    pub(crate) ptext: &'static [u8],
    pub(crate) ctext: &'static [u8],
}

/// The digest of `data` in pieces of `step` bytes.
fn digest(h: &mut dyn Hash, data: &[u8], step: usize) -> Vec<u8> {
    h.init();
    for piece in data.chunks(step.max(1)) {
        h.update(piece);
    }
    let mut out = vec![0u8; h.digest_size()];
    h.finish(&mut out);
    out
}

fn check_hash(name: &str, vecs: &[HashVec]) {
    let mut h = alloc_hash(name).unwrap();
    assert!(!vecs.is_empty());
    for (i, v) in vecs.iter().enumerate() {
        if !v.key.is_empty() || h.needs_key() {
            h.set_key(v.key).unwrap();
        }
        assert_eq!(h.digest_size(), v.digest.len(), "{name} {i}");
        // In one piece, and in the pieces of the tests of testmgr.c.
        for step in [v.data.len(), 1, 3, 17, 64, 65] {
            assert_eq!(digest(&mut *h, v.data, step), v.digest, "{name} {i} step {step}");
        }
        // A copy of the state in the middle goes on as the original.
        h.init();
        let half = v.data.len() / 2;
        h.update(&v.data[..half]);
        let mut copy = h.box_clone();
        copy.update(&v.data[half..]);
        let mut out = vec![0u8; copy.digest_size()];
        copy.finish(&mut out);
        assert_eq!(out, v.digest, "{name} {i} copy");
    }
}

#[test]
fn sha1() {
    check_hash("sha1", testvec::SHA1);
    check_hash("sha1-generic", testvec::SHA1);
}

#[test]
fn sha224() {
    check_hash("sha224", testvec::SHA224);
}

#[test]
fn sha256() {
    check_hash("sha256", testvec::SHA256);
    check_hash("sha256-generic", testvec::SHA256);
    assert_eq!(&sha256::Sha256::digest(b"abc")[..], testvec::SHA256[1].digest);
}

#[test]
fn sha384() {
    check_hash("sha384", testvec::SHA384);
}

#[test]
fn sha512() {
    check_hash("sha512", testvec::SHA512);
}

#[test]
fn hmac_sha256() {
    check_hash("hmac(sha256)", testvec::HMAC_SHA256);
    check_hash("hmac(sha256-generic)", testvec::HMAC_SHA256);
}

#[test]
fn hash_names() {
    let h = alloc_hash("hmac(sha256-generic)").unwrap();
    assert_eq!(h.name(), "hmac(sha256)");
    assert_eq!(h.driver_name(), "hmac(sha256-generic)");
    assert!(h.needs_key());
    // A hash with no key refuses a key, as `shash_no_setkey`.
    assert_eq!(alloc_hash("sha256").unwrap().set_key(b"k").err(), Some(Errno::ENOSYS));
    // An HMAC of an HMAC is not an algorithm (CVE-2017-17806).
    assert_eq!(alloc_hash("hmac(hmac(sha256))").err(), Some(Errno::ENOENT));
    for bad in ["md4", "sha256(", "hmac(aes)", "hmac(sha256", "cbc(aes)", "", "hmac()"] {
        assert_eq!(alloc_hash(bad).err(), Some(Errno::ENOENT), "{bad}");
    }
}

/// Runs a cipher vector: the encryption and the decryption in one call, and in pieces of
/// `step` blocks that carry the IV from one piece to the next.
fn check_cipher(name: &str, vecs: &[CipherVec], pieces: bool) {
    let mut c = alloc_skcipher(name).unwrap();
    assert!(c.needs_key());
    assert!(!vecs.is_empty());
    for (i, v) in vecs.iter().enumerate() {
        c.set_key(v.key).unwrap();
        assert!(!c.needs_key());
        let mut iv = v.iv.to_vec();
        iv.resize(c.iv_size(), 0);
        let mut data = v.ptext.to_vec();
        c.encrypt(&mut iv, &mut data).unwrap();
        assert_eq!(data, v.ctext, "{name} {i} encrypt");
        if !v.iv_out.is_empty() {
            assert_eq!(iv, v.iv_out, "{name} {i} iv");
        }
        let mut iv = v.iv.to_vec();
        iv.resize(c.iv_size(), 0);
        c.decrypt(&mut iv, &mut data).unwrap();
        assert_eq!(data, v.ptext, "{name} {i} decrypt");
        if !pieces {
            continue;
        }
        for step in [1, 2, 3] {
            let mut iv = v.iv.to_vec();
            let mut data = v.ptext.to_vec();
            for piece in data.chunks_mut(step * BLOCK) {
                c.encrypt(&mut iv, piece).unwrap();
            }
            assert_eq!(data, v.ctext, "{name} {i} step {step}");
        }
    }
}

#[test]
fn aes_ecb() {
    check_cipher("ecb(aes)", testvec::AES, true);
    // The block cipher alone.
    let mut aes = alloc_cipher("aes-generic").unwrap();
    for v in testvec::AES {
        aes.set_key(v.key).unwrap();
        for (p, c) in v.ptext.chunks(BLOCK).zip(v.ctext.chunks(BLOCK)) {
            let mut b: [u8; BLOCK] = p.try_into().unwrap();
            aes.encrypt(&mut b);
            assert_eq!(b, c);
            aes.decrypt(&mut b);
            assert_eq!(b, p);
        }
    }
}

#[test]
fn aes_cbc() {
    check_cipher("cbc(aes)", testvec::AES_CBC, true);
    check_cipher("cbc(aes-generic)", testvec::AES_CBC, false);
}

#[test]
fn aes_ctr() {
    check_cipher("ctr(aes)", testvec::AES_CTR, false);
}

#[test]
fn aes_xts() {
    check_cipher("xts(aes)", testvec::AES_XTS, false);
}

/// XTS with ciphertext stealing: the blocks before the last two are the same as without the
/// tail, and the decryption gives the text back.
#[test]
fn aes_xts_stealing() {
    let mut c = alloc_skcipher("xts(aes)").unwrap();
    let v = &testvec::AES_XTS[3];
    c.set_key(v.key).unwrap();
    for len in [17, 31, 33, 47, 100, 511] {
        let mut data = v.ptext[..len].to_vec();
        let mut iv = v.iv.to_vec();
        c.encrypt(&mut iv, &mut data).unwrap();
        let same = (len / BLOCK - 1) * BLOCK;
        assert_eq!(data[..same], v.ctext[..same], "{len}");
        assert_ne!(data[same..], v.ptext[same..len], "{len}");
        c.decrypt(&mut iv, &mut data).unwrap();
        assert_eq!(data, v.ptext[..len], "{len}");
    }
}

#[test]
fn cipher_errors() {
    let mut c = alloc_skcipher("cbc(aes)").unwrap();
    assert_eq!(c.iv_size(), 16);
    assert_eq!(c.set_key(&[0; 15]).err(), Some(Errno::EINVAL));
    assert_eq!(c.set_key(&[0; 20]).err(), Some(Errno::EINVAL));
    c.set_key(&[0; 16]).unwrap();
    assert!(!c.needs_key());
    // A bad key removes the old key.
    assert_eq!(c.set_key(&[0; 17]).err(), Some(Errno::EINVAL));
    assert!(c.needs_key());
    c.set_key(&[0; 16]).unwrap();
    let mut iv = [0u8; 16];
    // A length that is not a multiple of the block, as af_alg05 of LTP.
    assert_eq!(c.decrypt(&mut iv, &mut [0; 15]).err(), Some(Errno::EINVAL));
    assert_eq!(c.encrypt(&mut iv, &mut [0; 17]).err(), Some(Errno::EINVAL));
    let mut x = alloc_skcipher("xts(aes)").unwrap();
    assert_eq!((x.min_key_size(), x.max_key_size()), (32, 64));
    assert_eq!(x.set_key(&[0; 16]).err(), Some(Errno::EINVAL));
    assert_eq!(x.set_key(&[0; 40]).err(), Some(Errno::EINVAL));
    x.set_key(&[1; 48]).unwrap();
    assert_eq!(x.encrypt(&mut iv, &mut [0; 15]).err(), Some(Errno::EINVAL));
    assert_eq!(x.driver_name(), "xts(aes-generic)");
    assert_eq!(alloc_skcipher("ecb(aes)").unwrap().iv_size(), 0);
    for bad in ["aes", "sha256", "cbc(sha256)", "cbc(cbc(aes))", "xts(aes", "gcm(aes)"] {
        assert_eq!(alloc_skcipher(bad).err(), Some(Errno::ENOENT), "{bad}");
    }
}

/// The bytes of the hex string `s`.
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// The 2048-bit MODP prime of RFC 3526, as LTP keyctl_dh_data.h.
const MODP2048: &str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff";

#[test]
fn mpi_small() {
    use crate::mpi::Mpi;
    let r = Mpi::from_u64(4).pow_mod(&Mpi::from_u64(13), &Mpi::from_u64(497));
    assert_eq!(r, Mpi::from_u64(445));
    // An even modulus takes the slow path.
    let r = Mpi::from_u64(3).pow_mod(&Mpi::from_u64(200), &Mpi::from_u64(1000));
    assert_eq!(r, Mpi::from_u64(1));
    assert_eq!(Mpi::from_u64(7).pow_mod(&Mpi::zero(), &Mpi::from_u64(11)), Mpi::from_u64(1));
    assert_eq!(Mpi::from_u64(7).pow_mod(&Mpi::from_u64(5), &Mpi::from_u64(1)), Mpi::zero());
    let m = Mpi::from_be(&unhex("0000ff01"));
    assert_eq!(m.byte_len(), 2);
    assert_eq!(m.to_be(), vec![0xff, 1]);
    assert_eq!(m.to_be_padded(4).unwrap(), vec![0, 0, 0xff, 1]);
    assert!(m.to_be_padded(1).is_none());
    // A value of more than one limb against a modulus of two limbs.
    let m = Mpi::from_be(&unhex("f123456789abcdef0123456789abcdef"));
    let x = Mpi::from_be(&unhex("0123456789abcdef0123456789abcdef0123456789abcdef"));
    let x2 = x.mul(&x).rem(&m);
    assert_eq!(x.pow_mod(&Mpi::from_u64(2), &m), x2);
    assert_eq!(x.pow_mod(&Mpi::from_u64(3), &m), x2.mul(&x).rem(&m));
}

#[test]
fn dh_ltp_vectors() {
    // The vectors of LTP keyctl25 and keyctl28.
    let p = unhex(MODP2048);
    let x = unhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let g = unhex(
        "dd5d87a6f9df57f13df2c658e501abd72adba34863613bd16769eef955258e3611ee8ec542a426e375c6b4d83b717c97f88504b43acc5df03a4904e88d2619dfb7fb3cda68bc136c468dfedf1c5a5b73046408866fec8949beb587a0a4b6e6c0def5f24405385184a69e9dce4208f363adb0e1ce881863eb8d82d4aead5e1c195047d70d9bdc447bda027684b4351d98503fee1bcf827ffd07501701c7f3912422dd2f42b26cf40adde07d63e235f42f6521402a90dd2cea4a2e177640742d3cac853e96fa494413fee945972b2423a0f51becf28528c9db926002c50ffe2b1a97c978cf488ba29bbb472e7e63282ddd320a15a072d8176075204f7ded293561",
    );
    let z = dh::compute(&x, &p, &g).unwrap();
    let want = "61fc0d4d01cee152340f52b45328aa11d86e92ce8e8f7ba29180f62d999bc7714cbb05efde22bddf6f8dbb00df4efa1c14ea5420acec51cdbdd063fc357bd9ab367f1b67c3b1514e2d190550be1d44515ffe65f8f612ad6cc58496d9c3c9397d8798a78e524d1f26be6214f466cf9a904d28dd29116e510c7b181eac5549ce1defcc6ca20e80d30d24c0776887f8a3050f8daa586bbb6bd076ea875cc33eef19669ec7d44e85df06610b949cd35823a7b1f636af6b4cf18840d45f6e9d1fa73c8bc271ba87cdc29b33cf18ee598ef66c76ccedcc09fee1f8ce5c78b3b9e3f52914aa67d0b5cb7a7ed12e8397f16bfbe4fbebdd18540d4ca765c10c11adea839f";
    assert_eq!(z, unhex(want));
    let mut h = alloc_hash("sha256").unwrap();
    let mut info = z.clone();
    info.extend_from_slice(b"info");
    let mut out = [0u8; 32];
    dh::kdf108_ctr(h.as_mut(), &info, &mut out).unwrap();
    assert_eq!(
        out.to_vec(),
        unhex("bf18e2a730acaed25b76a06a78199970231087afb1815d71efafb3b2c17ac913")
    );
    // More than one block, and a block cut short.
    let mut long = [0u8; 40];
    dh::kdf108_ctr(h.as_mut(), &info, &mut long).unwrap();
    assert_eq!(long[..32], out);
    // The errors of crypto_dh_decode_key and dh_set_params.
    assert_eq!(dh::compute(&p, &x, &g), Err(Errno::EINVAL));
    assert_eq!(dh::compute(&x, &[0; 256], &g), Err(Errno::EINVAL));
    assert_eq!(dh::compute(&x, &p[..128], &x), Err(Errno::EINVAL));
    // A prime with zero bytes at the start gives a shorter result.
    let mut p0 = vec![0u8; 8];
    p0.extend_from_slice(&p);
    assert_eq!(dh::compute(&x, &p0, &g).unwrap(), unhex(want));
}

/// A self-signed certificate of an RSA-2048 key, made with `openssl req -x509 -newkey rsa:2048
/// -subj /O=rukernel/CN=rk-test-key`.
const CERT: &[u8] = include_bytes!("testdata/cert.der");
/// The private key of [`CERT`] in PKCS#8.
const PKCS8: &[u8] = include_bytes!("testdata/key.der");
/// A self-signed certificate with `sha1WithRSAEncryption`.
const CERT_SHA1: &[u8] = include_bytes!("testdata/sha1.der");
/// The signature of `rukernel` with SHA-256, made with `openssl dgst -sha256 -sign`.
const MSG_SIG: &[u8] = include_bytes!("testdata/msg.sig");

fn sha256_of(data: &[u8]) -> Vec<u8> {
    let mut h = alloc_hash("sha256").unwrap();
    digest(h.as_mut(), data, data.len().max(1))
}

#[test]
fn x509_parse() {
    let p = asym::parse(CERT).unwrap();
    assert_eq!(p.key.id_type, "X509");
    assert!(!p.key.is_private);
    let skid = unhex("987d54853a1cfc4027b413c4f4d9914becc3188a");
    let desc = b"rukernel: rk-test-key: 987d54853a1cfc4027b413c4f4d9914becc3188a";
    assert_eq!(p.desc.as_deref(), Some(&desc[..]));
    let ids = p.ids.unwrap();
    assert_eq!(ids[1].as_deref(), Some(&skid[..]));
    let sig = p.sig.unwrap();
    assert_eq!(sig.hash_algo, "sha256");
    assert_eq!(sig.auth_ids[1].as_deref(), Some(&skid[..]));
    assert_eq!(sig.auth_ids[2], ids[2]);
    // The signature of the certificate is good, and a changed signature is not.
    asym::verify(&p.key, &sig).unwrap();
    let mut bad = CERT.to_vec();
    *bad.last_mut().unwrap() ^= 1;
    assert!(asym::parse(&bad).is_err());
    // A changed byte in the issuer and the subject changes the digest.
    let mut bad = CERT.to_vec();
    while let Some(at) = bad.windows(11).position(|w| w == b"rk-test-key") {
        bad[at] = b'R';
    }
    assert_eq!(asym::parse(&bad).unwrap_err(), Errno::EKEYREJECTED);
    // Linux 6.8 has no sha1WithRSAEncryption in x509_note_sig_algo.
    assert_eq!(asym::parse(CERT_SHA1).unwrap_err(), Errno::ENOPKG);
    // No data, bad data, and too much data.
    assert_eq!(asym::parse(b"").unwrap_err(), Errno::EINVAL);
    assert_eq!(asym::parse(b"bogus").unwrap_err(), Errno::EBADMSG);
    assert_eq!(asym::parse(&CERT[..CERT.len() - 1]).unwrap_err(), Errno::EBADMSG);
    assert_eq!(asym::parse(&vec![0x30; 70000]).unwrap_err(), Errno::EMSGSIZE);
    // The bytes after the certificate are not checked.
    let mut more = CERT.to_vec();
    more.extend_from_slice(b"more");
    asym::parse(&more).unwrap();
}

#[test]
fn pkcs8_parse() {
    let p = asym::parse(PKCS8).unwrap();
    assert_eq!(p.key.id_type, "PKCS8");
    assert!(p.key.is_private && p.ids.is_none() && p.sig.is_none() && p.desc.is_none());
    // A version other than 0.
    let mut bad = PKCS8.to_vec();
    let at = bad.windows(3).position(|w| w == [0x02, 0x01, 0x00]).unwrap();
    bad[at + 2] = 1;
    assert_eq!(asym::parse(&bad).unwrap_err(), Errno::EBADMSG);
}

#[test]
fn pkey_ops() {
    use asym::{Op, SUPPORTS_DECRYPT, SUPPORTS_ENCRYPT, SUPPORTS_VERIFY};
    let public = asym::parse(CERT).unwrap().key;
    let private = asym::parse(PKCS8).unwrap().key;
    let mut n = 0u64;
    let mut random = move || {
        n = n.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        n >> 33
    };
    // KEYCTL_PKEY_QUERY, as LTP keyctl29 and keyctl30.
    let q = public.query("pkcs1", None).unwrap();
    assert_eq!(q.supported_ops, SUPPORTS_ENCRYPT | SUPPORTS_VERIFY);
    assert_eq!((q.key_size, q.max_enc_size, q.max_sig_size), (2048, 256, 256));
    let q = private.query("pkcs1", Some("sha256")).unwrap();
    assert_eq!(q.supported_ops, 15);
    assert_eq!(
        private.query("raw", None).unwrap().supported_ops,
        SUPPORTS_ENCRYPT | SUPPORTS_DECRYPT
    );
    assert_eq!(public.query("raw", Some("sha256")).unwrap_err(), Errno::EINVAL);
    assert_eq!(public.query("oaep", None).unwrap_err(), Errno::EINVAL);
    assert_eq!(public.query("pkcs1", Some("md4")).unwrap_err(), Errno::ENOENT);
    // Sign gives the signature of OpenSSL, and the public key checks it.
    let d = sha256_of(b"rukernel");
    let s = private.eds(Op::Sign, "pkcs1", Some("sha256"), &d, 256, &mut random).unwrap();
    assert_eq!(s, MSG_SIG);
    public.verify("pkcs1", Some("sha256"), &s, &d).unwrap();
    assert_eq!(
        public.verify("pkcs1", Some("sha256"), &s, &sha256_of(b"x")),
        Err(Errno::EKEYREJECTED)
    );
    assert_eq!(public.verify("pkcs1", Some("sha1"), &s, &d[..20]), Err(Errno::EBADMSG));
    assert_eq!(public.verify("raw", None, &s, &d), Err(Errno::ENOSYS));
    assert_eq!(
        public.eds(Op::Sign, "pkcs1", Some("sha256"), &d, 256, &mut random),
        Err(Errno::EINVAL)
    );
    // Encrypt and decrypt with the padding of PKCS#1, and with no padding.
    let c = public.eds(Op::Encrypt, "pkcs1", None, b"secret", 256, &mut random).unwrap();
    assert_eq!(c.len(), 256);
    assert_eq!(private.eds(Op::Decrypt, "pkcs1", None, &c, 256, &mut random).unwrap(), b"secret");
    assert_eq!(private.eds(Op::Decrypt, "pkcs1", None, &c, 3, &mut random), Err(Errno::EOVERFLOW));
    assert_eq!(public.eds(Op::Decrypt, "pkcs1", None, &c, 256, &mut random), Err(Errno::EINVAL));
    assert_eq!(
        public.eds(Op::Encrypt, "pkcs1", None, b"x", 255, &mut random),
        Err(Errno::EOVERFLOW)
    );
    assert_eq!(
        public.eds(Op::Encrypt, "pkcs1", None, &[1; 246], 256, &mut random),
        Err(Errno::EOVERFLOW)
    );
    // The hash of `pkcs1pad(rsa,sha256)` does not change the encryption.
    let c = public.eds(Op::Encrypt, "pkcs1", Some("sha256"), b"x", 256, &mut random).unwrap();
    assert_eq!(private.eds(Op::Decrypt, "pkcs1", None, &c, 256, &mut random).unwrap(), b"x");
    let c = public.eds(Op::Encrypt, "raw", None, b"secret", 256, &mut random).unwrap();
    let m = private.eds(Op::Decrypt, "raw", None, &c, 256, &mut random).unwrap();
    assert_eq!((m.len(), &m[250..]), (256, &b"secret"[..]));
    assert_eq!(
        public.eds(Op::Encrypt, "raw", None, &[0xff; 256], 256, &mut random),
        Err(Errno::EINVAL)
    );
}

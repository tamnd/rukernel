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

//! The tests of the sockets of the family `AF_ALG`.

use super::*;
use crate::NoPaths;
use crate::consts::{MSG_MORE, MSG_TRUNC, SOCK_STREAM};
use alloc::vec;
use rk_abi::native::poll::{POLLIN, POLLOUT};

const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// RFC 4231 test case 2: the key "Jefe".
const JEFE: &str = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

fn hex(b: &[u8]) -> alloc::string::String {
    b.iter().map(|x| alloc::format!("{x:02x}")).collect()
}

/// A `struct sockaddr_alg` for the type `kind` and the algorithm `name`.
fn addr(kind: &str, name: &str) -> Vec<u8> {
    let mut a = vec![0u8; NAME_OFFSET + 64];
    a[..2].copy_from_slice(&(AF_ALG as u16).to_ne_bytes());
    a[2..2 + kind.len()].copy_from_slice(kind.as_bytes());
    a[NAME_OFFSET..NAME_OFFSET + name.len()].copy_from_slice(name.as_bytes());
    a
}

fn bound(kind: &str, name: &str) -> Arc<AlgSocket> {
    let s = AlgSocket::new(SOCK_SEQPACKET, 0).unwrap();
    s.bind(&NoPaths, &addr(kind, name)).unwrap();
    s
}

fn send(s: &dyn Socket, data: &[u8], flags: u32) -> Result<usize> {
    let msg = Message { data: data.to_vec(), ..Message::default() };
    s.send(&NoPaths, msg, flags, false)
}

fn digest(s: &dyn Socket) -> alloc::string::String {
    hex(&s.recv(64, 0, false).unwrap().data)
}

#[test]
fn create_and_bind() {
    assert_eq!(AlgSocket::new(SOCK_STREAM, 0).err(), Some(Errno::ESOCKTNOSUPPORT));
    assert_eq!(AlgSocket::new(SOCK_SEQPACKET, 1).err(), Some(Errno::EPROTONOSUPPORT));
    let s = AlgSocket::new(SOCK_SEQPACKET, 0).unwrap();
    assert_eq!(s.get_option(SOL_SOCKET, SO_TYPE).unwrap(), 5i32.to_ne_bytes());
    assert_eq!(s.get_option(SOL_SOCKET, SO_DOMAIN).unwrap(), 38i32.to_ne_bytes());
    assert_eq!(s.get_option(SOL_ALG, ALG_SET_KEY).err(), Some(Errno::EOPNOTSUPP));
    // A socket with no algorithm has no key and no operation socket.
    assert_eq!(s.set_option(SOL_ALG, ALG_SET_KEY, b"k").err(), Some(Errno::ENOPROTOOPT));
    assert_eq!(s.accept(false).err(), Some(Errno::EINVAL));
    assert_eq!(send(&*s, b"x", 0).err(), Some(Errno::EOPNOTSUPP));
    let a = addr("hash", "sha256");
    assert_eq!(s.bind(&NoPaths, &a[..NAME_OFFSET]).err(), Some(Errno::EINVAL));
    let mut bad = a.clone();
    bad[16] = 1;
    assert_eq!(s.bind(&NoPaths, &bad).err(), Some(Errno::EINVAL));
    // `CRYPTO_ALG_KERN_DRIVER_ONLY` is the one flag that the mask can have.
    let mut ok = a.clone();
    ok[20..24].copy_from_slice(&CRYPTO_ALG_KERN_DRIVER_ONLY.to_ne_bytes());
    s.bind(&NoPaths, &ok).unwrap();
    for (kind, name) in [("nope", "sha256"), ("hash", "md2"), ("hash", "cbc(aes)")] {
        assert_eq!(s.bind(&NoPaths, &addr(kind, name)).err(), Some(Errno::ENOENT), "{name}");
    }
    // A driver name and a nested HMAC are not in the allow list.
    for name in ["sha256-generic", "hmac(hmac(sha256))", "hmac(sha256-generic)"] {
        assert_eq!(s.bind(&NoPaths, &addr("hash", name)).err(), Some(Errno::ENOENT), "{name}");
    }
    // The name ends at the last byte of the address.
    let short = &a[..NAME_OFFSET + 5];
    assert_eq!(s.bind(&NoPaths, short).err(), Some(Errno::ENOENT));
    s.bind(&NoPaths, &a[..NAME_OFFSET + 7]).unwrap();
}

#[test]
fn hash_send_recv() {
    let s = bound("hash", "sha256");
    let op = s.accept(false).unwrap();
    // No data gives the digest of no data.
    assert_eq!(digest(&*op), EMPTY);
    assert_eq!(send(&*op, b"abc", 0), Ok(3));
    assert_eq!(digest(&*op), ABC);
    // The receive ended the digest.
    assert_eq!(digest(&*op), EMPTY);
    // Pieces with `MSG_MORE`, and an empty send that ends the digest.
    assert_eq!(send(&*op, b"a", MSG_MORE), Ok(1));
    assert_eq!(send(&*op, b"b", MSG_MORE), Ok(1));
    assert_eq!(send(&*op, b"c", MSG_MORE), Ok(1));
    assert_eq!(send(&*op, b"", 0), Ok(0));
    assert_eq!(digest(&*op), ABC);
    // A receive ends an open digest.
    send(&*op, b"ab", MSG_MORE).unwrap();
    send(&*op, b"c", MSG_MORE).unwrap();
    assert_eq!(digest(&*op), ABC);
    // A send without `MSG_MORE` drops the digest before.
    send(&*op, b"xyz", 0).unwrap();
    send(&*op, b"abc", 0).unwrap();
    assert_eq!(digest(&*op), ABC);
    // A short receive gives the start of the digest.
    send(&*op, b"abc", 0).unwrap();
    let r = op.recv(4, 0, false).unwrap();
    assert_eq!((hex(&r.data), r.len, r.flags), (ABC[..8].into(), 4, MSG_TRUNC));
    // The bound socket cannot change while it has an operation socket.
    assert_eq!(s.bind(&NoPaths, &addr("hash", "sha1")).err(), Some(Errno::EBUSY));
    assert_eq!(s.set_option(SOL_ALG, ALG_SET_KEY, b"k").err(), Some(Errno::EBUSY));
    assert_eq!(op.set_option(SOL_ALG, ALG_SET_KEY, b"k").err(), Some(Errno::EOPNOTSUPP));
    drop(op);
    // A hash with no key refuses a key, as `shash_no_setkey` of Linux.
    assert_eq!(s.set_option(SOL_ALG, ALG_SET_KEY, b"k").err(), Some(Errno::ENOSYS));
    s.bind(&NoPaths, &addr("hash", "sha1")).unwrap();
    let op = s.accept(false).unwrap();
    send(&*op, b"abc", 0).unwrap();
    assert_eq!(digest(&*op), "a9993e364706816aba3e25717850c26c9cd0d89d");
}

#[test]
fn hash_accept_copies_state() {
    let s = bound("hash", "sha256");
    let op = s.accept(false).unwrap();
    send(&*op, b"ab", MSG_MORE).unwrap();
    let copy = op.accept(false).unwrap();
    send(&*op, b"c", 0).unwrap();
    send(&*copy, b"c", 0).unwrap();
    assert_eq!(digest(&*op), ABC);
    assert_eq!(digest(&*copy), ABC);
    // A closed digest is not copied.
    let fresh = op.accept(false).unwrap();
    assert_eq!(digest(&*fresh), EMPTY);
}

#[test]
fn hmac_key() {
    let s = bound("hash", "hmac(sha256)");
    // An operation socket before the key has no key.
    let early = s.accept(false).unwrap();
    assert_eq!(send(&*early, b"x", 0).err(), Some(Errno::ENOKEY));
    assert_eq!(early.recv(32, 0, false).err(), Some(Errno::ENOKEY));
    assert_eq!(early.accept(false).err(), Some(Errno::ENOKEY));
    // The bound socket can take a key while its operation sockets have none.
    s.set_option(SOL_ALG, ALG_SET_KEY, b"Jefe").unwrap();
    send(&*early, b"what do ya want for nothing?", 0).unwrap();
    assert_eq!(digest(&*early), JEFE);
    // Now the operation socket has the key, and the key cannot change.
    assert_eq!(s.set_option(SOL_ALG, ALG_SET_KEY, b"x").err(), Some(Errno::EBUSY));
    let op = s.accept(false).unwrap();
    send(&*op, b"what do ya want for nothing?", 0).unwrap();
    assert_eq!(digest(&*op), JEFE);
    drop((early, op));
    s.set_option(SOL_ALG, ALG_SET_KEY, b"other").unwrap();
    let op = s.accept(false).unwrap();
    send(&*op, b"what do ya want for nothing?", 0).unwrap();
    assert_ne!(digest(&*op), JEFE);
}

/// The key, the IV and the text of NIST SP 800-38A F.2.1, CBC-AES128.
const NIST_KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const NIST_IV: &str = "000102030405060708090a0b0c0d0e0f";
const NIST_PTEXT: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";
const NIST_CTEXT: &str = "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// A send with the control messages of an operation: `op` and, if not empty, the IV.
fn send_op(s: &dyn Socket, data: &[u8], op: u32, iv: &[u8], flags: u32) -> Result<usize> {
    let mut control = vec![(SOL_ALG, ALG_SET_OP, op.to_ne_bytes().to_vec())];
    if !iv.is_empty() {
        let mut v = (iv.len() as u32).to_ne_bytes().to_vec();
        v.extend_from_slice(iv);
        control.push((SOL_ALG, ALG_SET_IV, v));
    }
    let msg = Message { data: data.to_vec(), control, ..Message::default() };
    s.send(&NoPaths, msg, flags, false)
}

fn cipher_op(name: &str, key: &[u8]) -> Arc<dyn Socket> {
    let s = bound("skcipher", name);
    s.set_option(SOL_ALG, ALG_SET_KEY, key).unwrap();
    s.accept(false).unwrap()
}

#[test]
fn skcipher_cbc() {
    let (key, iv) = (unhex(NIST_KEY), unhex(NIST_IV));
    let (ptext, ctext) = (unhex(NIST_PTEXT), unhex(NIST_CTEXT));
    let op = cipher_op("cbc(aes)", &key);
    assert_eq!(send_op(&*op, &ptext, skcipher::ALG_OP_ENCRYPT, &iv, 0), Ok(32));
    // A blocking receive of more than the data would wait for a new send, as Linux, so the
    // receives here ask for the length of the data.
    assert_eq!(op.recv(32, 0, false).unwrap().data, ctext);
    // The operation ended, so a receive waits for a new send.
    assert_eq!(op.recv(64, 0, true).err(), Some(Errno::EAGAIN));
    // A decryption in two sends: the IV of the second block comes from the first block.
    send_op(&*op, &ctext[..16], skcipher::ALG_OP_DECRYPT, &iv, MSG_MORE).unwrap();
    assert_eq!(op.recv(16, 0, false).unwrap().data, ptext[..16]);
    send(&*op, &ctext[16..], 0).unwrap();
    assert_eq!(op.recv(16, 0, false).unwrap().data, ptext[16..]);
    // A receive in pieces that are smaller than the data.
    send_op(&*op, &ptext, skcipher::ALG_OP_ENCRYPT, &iv, 0).unwrap();
    assert_eq!(op.recv(20, 0, false).unwrap().data, ctext[..16]);
    assert_eq!(op.recv(16, 0, false).unwrap().data, ctext[16..]);
    // A send with no control message keeps the operation, and the IV goes on from the last
    // block.
    send(&*op, &ptext, 0).unwrap();
    let mut c = rk_crypto::alloc_skcipher("cbc(aes)").unwrap();
    c.set_key(&key).unwrap();
    let (mut next, mut want) = (ctext[16..].to_vec(), ptext.clone());
    c.encrypt(&mut next, &mut want).unwrap();
    assert_eq!(op.recv(32, 0, false).unwrap().data, want);
}

#[test]
fn skcipher_errors() {
    let (key, iv) = (unhex(NIST_KEY), unhex(NIST_IV));
    let s = bound("skcipher", "cbc(aes)");
    assert_eq!(s.bind(&NoPaths, &addr("skcipher", "cbc(aes-generic)")).err(), Some(Errno::ENOENT));
    assert_eq!(s.bind(&NoPaths, &addr("skcipher", "sha256")).err(), Some(Errno::ENOENT));
    assert_eq!(s.set_option(SOL_ALG, ALG_SET_KEY, &key[..15]).err(), Some(Errno::EINVAL));
    // An operation socket before the key has no key.
    let early = s.accept(false).unwrap();
    assert_eq!(send(&*early, b"x", 0).err(), Some(Errno::ENOKEY));
    s.set_option(SOL_ALG, ALG_SET_KEY, &key).unwrap();
    let op = s.accept(false).unwrap();
    // A receive with no send waits.
    assert_eq!(op.recv(16, 0, true).err(), Some(Errno::EAGAIN));
    assert_eq!(op.accept(false).err(), Some(Errno::EOPNOTSUPP));
    // A bad operation, a bad IV and an unknown control message.
    assert_eq!(send_op(&*op, &[0; 16], 2, &iv, 0).err(), Some(Errno::EINVAL));
    assert_eq!(send_op(&*op, &[0; 16], 1, &iv[..8], 0).err(), Some(Errno::EINVAL));
    let msg = Message {
        data: vec![0; 16],
        control: vec![(SOL_ALG, 9, vec![0; 4])],
        ..Message::default()
    };
    assert_eq!(op.send(&NoPaths, msg, 0, false).err(), Some(Errno::EINVAL));
    // The data of an operation that ended waits for a receive.
    send_op(&*op, &[0; 16], 1, &iv, 0).unwrap();
    assert_eq!(send(&*op, &[0; 16], 0).err(), Some(Errno::EINVAL));
    op.recv(16, 0, false).unwrap();
    // A length that is not a multiple of the block, as af_alg05 of LTP.
    send_op(&*op, &[0; 15], 0, &iv, 0).unwrap();
    assert_eq!(op.recv(16, 0, false).err(), Some(Errno::EINVAL));
    // While more data comes, a receive waits for a full block.
    let op = s.accept(false).unwrap();
    assert_eq!(op.poll() & (POLLIN | POLLOUT), POLLIN | POLLOUT);
    send_op(&*op, &[0; 8], 1, &iv, MSG_MORE).unwrap();
    assert_eq!(op.recv(16, 0, true).err(), Some(Errno::EAGAIN));
    send(&*op, &[0; 8], MSG_MORE).unwrap();
    assert_eq!(op.recv(16, 0, false).unwrap().data.len(), 16);
    // More data comes and the queue is empty: the socket is not readable.
    assert_eq!(op.poll() & (POLLIN | POLLOUT), POLLOUT);
}

#[test]
fn skcipher_xts() {
    let key: Vec<u8> = (0..32).collect();
    let iv = [7u8; 16];
    let op = cipher_op("xts(aes)", &key);
    let mut c = rk_crypto::alloc_skcipher("xts(aes)").unwrap();
    c.set_key(&key).unwrap();
    // Whole blocks, and lengths with ciphertext stealing.
    for len in [16, 17, 32, 100] {
        let data: Vec<u8> = (0..len as u8).collect();
        let mut want = data.clone();
        c.encrypt(&mut iv.clone(), &mut want).unwrap();
        send_op(&*op, &data, skcipher::ALG_OP_ENCRYPT, &iv, 0).unwrap();
        assert_eq!(op.recv(len, 0, false).unwrap().data, want, "{len}");
        send_op(&*op, &want, skcipher::ALG_OP_DECRYPT, &iv, 0).unwrap();
        assert_eq!(op.recv(len, 0, false).unwrap().data, data, "{len}");
    }
}

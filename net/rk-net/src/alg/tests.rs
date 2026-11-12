//! The tests of the sockets of the family `AF_ALG`.

use super::*;
use crate::NoPaths;
use crate::consts::{MSG_MORE, MSG_TRUNC, SOCK_STREAM};
use alloc::vec;

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

//! The sockets of the family `AF_ALG`, as crypto/af_alg.c of Linux.
//!
//! A program makes a socket of the type `SOCK_SEQPACKET` and binds it to an algorithm with a type
//! and a name, for example `hash` and `sha256`. The bound socket holds the algorithm and its key.
//! `setsockopt` with the level `SOL_ALG` and `ALG_SET_KEY` sets the key. `accept` on the bound
//! socket gives an operation socket. The program writes the data to the operation socket and
//! reads the result from it. The module `hash` has the operation sockets of the type `hash`, as
//! crypto/algif_hash.c of Linux.
//!
//! The algorithms come from the crate `rk_crypto`. A program can bind only the algorithms of the
//! allow list of the type, as `af_alg_check_restriction` of Linux with `crypto.af_alg_restrict`
//! at its default value 1. A process with no `CAP_NET_ADMIN` and no `CAP_SYS_ADMIN` can bind
//! only the entries that are for all users. Another name gives `ENOENT`.
//!
//! An operation socket of an algorithm that needs a key and has none is a socket with no key, as
//! the `ops_nokey` of Linux. Its operations give `ENOKEY` until the bound socket has a key. The
//! key of the bound socket cannot change while it has an operation socket with a key.

mod hash;
#[cfg(test)]
mod tests;

use crate::consts::SOCK_SEQPACKET;
use crate::options::Options;
use crate::{Message, PathOps, Received, Socket, next_ino};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use rk_abi::Errno;
use rk_abi::native::socket::{
    SO_ACCEPTCONN, SO_DOMAIN, SO_ERROR, SO_PROTOCOL, SO_TYPE, SOL_SOCKET,
};
use rk_frame::sync::SpinLock;
use rk_vfs::cred::cap;
use rk_vfs::inode::Result;

/// The address family of the sockets of the crypto API.
pub const AF_ALG: u32 = 38;
/// The level of the socket options of `AF_ALG`.
pub const SOL_ALG: u32 = 279;

/// The options of the level `SOL_ALG` and the types of the control messages of `AF_ALG`, from
/// include/uapi/linux/if_alg.h of Linux. The option that sets the key.
pub const ALG_SET_KEY: u32 = 1;
/// The control message that sets the IV.
pub const ALG_SET_IV: u32 = 2;
/// The control message that sets the operation, encrypt or decrypt.
pub const ALG_SET_OP: u32 = 3;
/// The control message that sets the length of the associated data of an AEAD.
pub const ALG_SET_AEAD_ASSOCLEN: u32 = 4;
/// The option that sets the size of the tag of an AEAD.
pub const ALG_SET_AEAD_AUTHSIZE: u32 = 5;
/// The option that sets the entropy of a DRBG for a test.
pub const ALG_SET_DRBG_ENTROPY: u32 = 6;
/// The option that sets the key from a key of the kernel key ring.
pub const ALG_SET_KEY_BY_KEY_SERIAL: u32 = 7;

/// The offset of `salg_name` in `struct sockaddr_alg`.
const NAME_OFFSET: usize = 24;
/// The size of `salg_type`.
const TYPE_LEN: usize = 14;
/// The one flag that `salg_feat` and `salg_mask` can have.
const CRYPTO_ALG_KERN_DRIVER_ONLY: u32 = 0x1000;

/// An allow list: the name of an algorithm, and true if all users can bind it, as
/// `AF_ALG_UNPRIVILEGED`.
type AllowList = &'static [(&'static str, bool)];

/// True if the process can bind all the algorithms of an allow list, as `af_alg_capable`.
fn capable() -> bool {
    let cred = rk_vfs::cred::current();
    cred.ns_capable(rk_vfs::user_ns::init(), cap::NET_ADMIN) || cred.capable(cap::SYS_ADMIN)
}

/// Gives `ENOENT` if the process cannot bind `name`, as `af_alg_check_restriction` of Linux.
fn check_restriction(name: &str, list: AllowList) -> Result<()> {
    match list.iter().find(|(n, _)| *n == name) {
        Some(&(_, all)) if all || capable() => Ok(()),
        _ => Err(Errno::ENOENT),
    }
}

/// The algorithm of a bound socket, as the `private` of a `struct alg_sock` of Linux.
enum Tfm {
    Hash(Box<dyn rk_crypto::Hash>),
}

impl Tfm {
    /// Finds the algorithm `name` of the type `kind`, as the `bind` of a `struct af_alg_type`.
    fn bind(kind: &str, name: &str) -> Result<Self> {
        match kind {
            "hash" => hash::bind(name).map(Self::Hash),
            _ => Err(Errno::ENOENT),
        }
    }

    fn needs_key(&self) -> bool {
        match self {
            Self::Hash(h) => h.needs_key(),
        }
    }

    fn set_key(&mut self, key: &[u8]) -> Result<()> {
        match self {
            Self::Hash(h) => h.set_key(key),
        }
    }
}

/// The state of a bound socket that its operation sockets share.
struct Shared {
    tfm: Option<Tfm>,
    /// The count of operation sockets, as `refcnt`.
    children: usize,
    /// The count of operation sockets with no key, as `nokey_refcnt`.
    nokey: usize,
}

/// The shared state of a bound socket.
struct Bound(SpinLock<Shared>);

/// A new operation socket.
enum Child {
    Hash(Arc<hash::HashSocket>),
}

impl Child {
    fn socket(self) -> Arc<dyn Socket> {
        match self {
            Self::Hash(s) => s,
        }
    }
}

impl Bound {
    /// Makes an operation socket, as `af_alg_accept` of Linux. An algorithm that needs a key
    /// and has none gives a socket with no key.
    fn accept(self: &Arc<Self>) -> Result<Child> {
        let mut s = self.0.lock();
        let Some(tfm) = &s.tfm else {
            return Err(Errno::EINVAL);
        };
        let nokey = tfm.needs_key();
        let child = match tfm {
            Tfm::Hash(h) => Child::Hash(hash::HashSocket::new(self.clone(), h.box_clone(), nokey)),
        };
        s.children += 1;
        if nokey {
            s.nokey += 1;
        }
        Ok(child)
    }

    /// An operation socket goes, as `af_alg_release_parent` of Linux.
    fn release(&self, nokey: bool) {
        let mut s = self.0.lock();
        s.children -= 1;
        if nokey {
            s.nokey -= 1;
        }
    }

    /// An operation socket with no key checks the key of the bound socket, as `hash_check_key`
    /// of Linux. If the bound socket has a key now, `take` gets the algorithm, and the socket
    /// has a key from now on.
    ///
    /// # Errors
    ///
    /// Gives `ENOKEY` if the bound socket has no key.
    fn check_key(&self, take: impl FnOnce(&Tfm)) -> Result<()> {
        let mut s = self.0.lock();
        match &s.tfm {
            Some(tfm) if !tfm.needs_key() => take(tfm),
            _ => return Err(Errno::ENOKEY),
        }
        s.nokey -= 1;
        Ok(())
    }
}

/// Reads an option of the level `SOL_SOCKET` of a socket of the family.
fn get_socket_option(options: &SpinLock<Options>, name: u32) -> Result<Vec<u8>> {
    let int = |v: u32| (v as i32).to_ne_bytes().to_vec();
    Ok(match name {
        SO_TYPE => int(SOCK_SEQPACKET),
        SO_DOMAIN => int(AF_ALG),
        SO_PROTOCOL | SO_ERROR | SO_ACCEPTCONN => int(0),
        _ => options.lock().get(name)?,
    })
}

/// The C string at the start of `bytes`, up to its first zero byte.
fn c_str(bytes: &[u8]) -> &[u8] {
    bytes.split(|&b| b == 0).next().unwrap_or(bytes)
}

/// A socket of the family `AF_ALG` that is not an operation socket, as `alg_proto_ops` of Linux.
pub struct AlgSocket {
    ino: u64,
    bound: Arc<Bound>,
    options: SpinLock<Options>,
}

impl AlgSocket {
    /// Makes a socket, as `alg_create` of Linux.
    ///
    /// # Errors
    ///
    /// Gives `ESOCKTNOSUPPORT` for a type other than `SOCK_SEQPACKET`, and `EPROTONOSUPPORT` for
    /// a protocol other than 0.
    pub fn new(kind: u32, protocol: u64) -> Result<Arc<Self>> {
        if kind != SOCK_SEQPACKET {
            return Err(Errno::ESOCKTNOSUPPORT);
        }
        if protocol as i32 != 0 {
            return Err(Errno::EPROTONOSUPPORT);
        }
        Ok(Arc::new(Self {
            ino: next_ino(),
            bound: Arc::new(Bound(SpinLock::new(Shared { tfm: None, children: 0, nokey: 0 }))),
            options: SpinLock::new(Options::default()),
        }))
    }
}

impl Socket for AlgSocket {
    fn family(&self) -> u32 {
        AF_ALG
    }

    fn kind(&self) -> u32 {
        SOCK_SEQPACKET
    }

    fn ino(&self) -> u64 {
        self.ino
    }

    /// Binds the socket to an algorithm, as `alg_bind` of Linux. The address is a
    /// `struct sockaddr_alg` with at least one byte of `salg_name`.
    fn bind(&self, _paths: &dyn PathOps, addr: &[u8]) -> Result<()> {
        if addr.len() < NAME_OFFSET + 1 {
            return Err(Errno::EINVAL);
        }
        let word = |at: usize| u32::from_ne_bytes(addr[at..at + 4].try_into().unwrap_or_default());
        let (feat, mask) = (word(16), word(20));
        if (feat | mask) & !CRYPTO_ALG_KERN_DRIVER_ONLY != 0 {
            return Err(Errno::EINVAL);
        }
        // The last byte of each field is a zero byte, as Linux writes it.
        let kind = c_str(&addr[2..2 + TYPE_LEN - 1]);
        let name = c_str(&addr[NAME_OFFSET..addr.len() - 1]);
        let kind = core::str::from_utf8(kind).map_err(|_| Errno::ENOENT)?;
        let name = core::str::from_utf8(name).map_err(|_| Errno::ENOENT)?;
        let tfm = Tfm::bind(kind, name)?;
        let mut s = self.bound.0.lock();
        if s.children != 0 {
            return Err(Errno::EBUSY);
        }
        s.tfm = Some(tfm);
        Ok(())
    }

    fn accept(&self, _nonblock: bool) -> Result<Arc<dyn Socket>> {
        Ok(self.bound.accept()?.socket())
    }

    fn send(&self, _: &dyn PathOps, _: Message, _: u32, _: bool) -> Result<usize> {
        Err(Errno::EOPNOTSUPP)
    }

    fn recv(&self, _len: usize, _flags: u32, _nonblock: bool) -> Result<Received> {
        Err(Errno::EOPNOTSUPP)
    }

    fn name(&self) -> Vec<u8> {
        (AF_ALG as u16).to_ne_bytes().to_vec()
    }

    fn get_option(&self, level: u32, name: u32) -> Result<Vec<u8>> {
        if level != SOL_SOCKET {
            return Err(Errno::EOPNOTSUPP);
        }
        get_socket_option(&self.options, name)
    }

    /// Sets an option, as `alg_setsockopt` of Linux. The key cannot change while the socket has
    /// an operation socket with a key.
    fn set_option(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
        if level == SOL_SOCKET {
            return self.options.lock().set(name, value);
        }
        let mut s = self.bound.0.lock();
        if s.children != s.nokey {
            return Err(Errno::EBUSY);
        }
        let Some(tfm) = s.tfm.as_mut() else {
            return Err(Errno::ENOPROTOOPT);
        };
        match (level, name) {
            (SOL_ALG, ALG_SET_KEY) => tfm.set_key(value),
            // The kernel has no keys of the key rings for `ALG_SET_KEY_BY_KEY_SERIAL`, as Linux
            // with no `CONFIG_KEYS`. The types here have no size of a tag and no entropy.
            _ => Err(Errno::ENOPROTOOPT),
        }
    }

    fn poll(&self) -> u32 {
        0
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

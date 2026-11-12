//! The operation sockets of the type `hash`, as crypto/algif_hash.c of Linux.
//!
//! A send adds its data to the digest. A send with `MSG_MORE` keeps the digest open for more
//! data. A send without it ends the digest, and the next send starts a new one. A receive gives
//! the digest and ends it if it is open. A receive with no data before gives the digest of no
//! data. A receive shorter than the digest gives its start, with `MSG_TRUNC`. `accept` on an
//! operation socket gives a new one with a copy of the open digest.

use super::{AF_ALG, AllowList, Bound, Child, Tfm, get_socket_option};
use crate::consts::{MSG_MORE, MSG_TRUNC, SOCK_SEQPACKET};
use crate::options::Options;
use crate::{Message, PathOps, Received, Socket, next_ino};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use rk_abi::Errno;
use rk_abi::native::socket::SOL_SOCKET;
use rk_crypto::Hash;
use rk_frame::sync::SpinLock;
use rk_vfs::inode::Result;

/// The hashes that a program can bind, as `hash_allowlist` of Linux.
const ALLOW: AllowList = &[
    ("cmac(aes)", false),
    ("hmac(md5)", false),
    ("hmac(sha1)", false),
    ("hmac(sha224)", false),
    ("hmac(sha256)", false),
    ("hmac(sha384)", false),
    ("hmac(sha512)", true),
    ("md4", false),
    ("md5", false),
    ("sha1", true),
    ("sha224", false),
    ("sha256", false),
    ("sha384", false),
    ("sha512", false),
];

/// Finds a hash, as `hash_bind` of Linux.
pub(super) fn bind(name: &str) -> Result<Box<dyn Hash>> {
    super::check_restriction(name, ALLOW)?;
    rk_crypto::alloc_hash(name)
}

/// The state of an operation socket, as `struct hash_ctx` of Linux.
struct Ctx {
    hash: Box<dyn Hash>,
    /// The digest is open: the last send had `MSG_MORE`.
    more: bool,
    /// The digest that the last send ended.
    result: Option<Vec<u8>>,
    /// The socket has no key yet.
    nokey: bool,
}

/// An operation socket of the type `hash`.
pub(super) struct HashSocket {
    ino: u64,
    bound: Arc<Bound>,
    ctx: SpinLock<Ctx>,
    options: SpinLock<Options>,
}

impl HashSocket {
    pub(super) fn new(bound: Arc<Bound>, hash: Box<dyn Hash>, nokey: bool) -> Arc<Self> {
        Arc::new(Self {
            ino: next_ino(),
            bound,
            ctx: SpinLock::new(Ctx { hash, more: false, result: None, nokey }),
            options: SpinLock::new(Options::default()),
        })
    }

    /// A socket with no key takes the key of the bound socket, as `hash_check_key` of Linux.
    fn check_key(&self, ctx: &mut Ctx) -> Result<()> {
        if !ctx.nokey {
            return Ok(());
        }
        self.bound.check_key(|tfm| {
            let Tfm::Hash(h) = tfm;
            ctx.hash = h.box_clone();
        })?;
        ctx.nokey = false;
        Ok(())
    }
}

impl Drop for HashSocket {
    fn drop(&mut self) {
        let nokey = self.ctx.lock().nokey;
        self.bound.release(nokey);
    }
}

/// Ends the digest of `ctx` and gives it.
fn finish(ctx: &mut Ctx) -> Vec<u8> {
    let mut out = vec![0u8; ctx.hash.digest_size()];
    ctx.hash.finish(&mut out);
    out
}

impl Socket for HashSocket {
    fn family(&self) -> u32 {
        AF_ALG
    }

    fn kind(&self) -> u32 {
        SOCK_SEQPACKET
    }

    fn ino(&self) -> u64 {
        self.ino
    }

    /// Gives a new operation socket with a copy of the open digest, as `hash_accept` of Linux.
    fn accept(&self, _nonblock: bool) -> Result<Arc<dyn Socket>> {
        let state = {
            let mut ctx = self.ctx.lock();
            self.check_key(&mut ctx)?;
            ctx.more.then(|| ctx.hash.box_clone())
        };
        let Child::Hash(child) = self.bound.accept()?;
        if let Some(hash) = state {
            let mut c = child.ctx.lock();
            c.hash = hash;
            c.more = true;
        }
        Ok(child)
    }

    /// Adds the data to the digest, as `hash_sendmsg` of Linux.
    fn send(&self, _: &dyn PathOps, msg: Message, flags: u32, _: bool) -> Result<usize> {
        let mut ctx = self.ctx.lock();
        self.check_key(&mut ctx)?;
        let more = flags & MSG_MORE != 0;
        let data = &msg.data;
        if !ctx.more {
            // A send that does not go on from an open digest drops the last digest.
            ctx.result = None;
            if data.is_empty() {
                return Ok(0);
            }
            ctx.hash.init();
        }
        ctx.hash.update(data);
        if !more {
            let out = finish(&mut ctx);
            ctx.result = Some(out);
        }
        ctx.more = more;
        Ok(data.len())
    }

    /// Gives the digest, as `hash_recvmsg` of Linux.
    fn recv(&self, len: usize, _flags: u32, _nonblock: bool) -> Result<Received> {
        let mut ctx = self.ctx.lock();
        self.check_key(&mut ctx)?;
        let size = ctx.hash.digest_size();
        let n = len.min(size);
        let result = match ctx.result.take() {
            Some(r) if !ctx.more => r,
            r => {
                if r.is_none() && !ctx.more {
                    ctx.hash.init();
                }
                ctx.more = false;
                finish(&mut ctx)
            }
        };
        let flags = if len < size { MSG_TRUNC } else { 0 };
        Ok(Received { data: result[..n].to_vec(), len: n, flags, ..Received::default() })
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

    fn set_option(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
        if level != SOL_SOCKET {
            return Err(Errno::EOPNOTSUPP);
        }
        self.options.lock().set(name, value)
    }

    fn poll(&self) -> u32 {
        0
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

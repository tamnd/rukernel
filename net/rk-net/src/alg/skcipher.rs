//! The operation sockets of the type `skcipher`, as crypto/algif_skcipher.c of Linux.
//!
//! A send adds data to the queue of the socket. Its control messages of the level `SOL_ALG` set
//! the operation (`ALG_SET_OP`) and the IV (`ALG_SET_IV`). A send with `MSG_MORE` tells that more
//! data comes. A receive encrypts or decrypts the data of the queue and gives the result. While
//! more data comes, a receive takes only full blocks, and the IV of the next receive goes on from
//! the data before, as `CRYPTO_SKCIPHER_REQ_NOTFINAL` of Linux. A receive waits for data if the
//! socket has none yet, or if more data comes and the queue has less than one block. After a
//! receive takes all the data of an operation that ended, the next receive waits for a new send.
//!
//! The queue holds at most the size of the send buffer, as `af_alg_sndbuf` of Linux. A send
//! waits until a receive takes data from a full queue.

use super::{AF_ALG, AllowList, Bound, SOL_ALG, Tfm, get_socket_option};
use super::{ALG_SET_AEAD_ASSOCLEN, ALG_SET_IV, ALG_SET_OP};
use crate::consts::{MSG_DONTWAIT, MSG_MORE, SOCK_SEQPACKET};
use crate::options::{Options, Timeout};
use crate::{Message, PathOps, Received, Socket, next_ino, wait_for};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::poll::{POLLIN, POLLOUT, POLLRDNORM, POLLWRBAND, POLLWRNORM};
use rk_abi::native::socket::SOL_SOCKET;
use rk_crypto::Skcipher;
use rk_frame::addr::PAGE_SIZE;
use rk_frame::sync::SpinLock;
use rk_vfs::inode::Result;
use rk_vfs::wait::{PollTable, WaitQueue};

/// The operation of `ALG_SET_OP` that decrypts.
pub(super) const ALG_OP_DECRYPT: u32 = 0;
/// The operation of `ALG_SET_OP` that encrypts.
pub(super) const ALG_OP_ENCRYPT: u32 = 1;

/// The ciphers that a program can bind, as `skcipher_allowlist` of Linux.
const ALLOW: AllowList = &[
    ("adiantum(xchacha12,aes)", true),
    ("adiantum(xchacha20,aes)", true),
    ("cbc(aes)", false),
    ("cbc(des)", false),
    ("cbc(des3_ede)", false),
    ("cbc(paes)", false),
    ("ctr(aes)", false),
    ("ecb(aes)", false),
    ("ecb(des)", false),
    ("hctr2(aes)", true),
    ("xts(aes)", true),
    ("xts(camellia)", true),
    ("xts(serpent)", true),
    ("xts(twofish)", true),
];

/// Finds a cipher, as `skcipher_bind` of Linux.
pub(super) fn bind(name: &str) -> Result<Box<dyn Skcipher>> {
    super::check_restriction(name, ALLOW)?;
    rk_crypto::alloc_skcipher(name)
}

/// The state of an operation socket, as `struct af_alg_ctx` of Linux.
struct Ctx {
    cipher: Box<dyn Skcipher>,
    /// The data that waits for a receive.
    queue: VecDeque<u8>,
    /// The IV of the next receive.
    iv: Vec<u8>,
    /// A send came.
    init: bool,
    /// The last send had `MSG_MORE`.
    more: bool,
    /// Encrypt, not decrypt.
    enc: bool,
    /// A send waits for space in the queue.
    write: bool,
    /// The socket has no key yet.
    nokey: bool,
}

/// The settings of the control messages of one send, as `struct af_alg_control` of Linux.
#[derive(Default)]
struct Control {
    iv: Option<Vec<u8>>,
    op: u32,
}

/// Reads the control messages of the level `SOL_ALG`, as `af_alg_cmsg_send` of Linux.
fn control(msg: &Message) -> Result<Control> {
    let mut con = Control::default();
    let word = |data: &[u8]| -> Result<u32> {
        let (w, _) = data.split_first_chunk::<4>().ok_or(Errno::EINVAL)?;
        Ok(u32::from_ne_bytes(*w))
    };
    for (level, kind, data) in &msg.control {
        if *level != SOL_ALG {
            continue;
        }
        match *kind {
            ALG_SET_IV => {
                let len = word(data)? as usize;
                let iv = data.get(4..).and_then(|d| d.get(..len)).ok_or(Errno::EINVAL)?;
                con.iv = Some(iv.to_vec());
            }
            ALG_SET_OP => con.op = word(data)?,
            ALG_SET_AEAD_ASSOCLEN => {
                if word(data)? >= 0x8000_0000 {
                    return Err(Errno::EINVAL);
                }
            }
            _ => return Err(Errno::EINVAL),
        }
    }
    Ok(con)
}

/// An operation socket of the type `skcipher`.
pub(super) struct SkcipherSocket {
    ino: u64,
    bound: Arc<Bound>,
    ctx: SpinLock<Ctx>,
    options: SpinLock<Options>,
    wait: Arc<WaitQueue>,
    events: AtomicU64,
}

impl SkcipherSocket {
    pub(super) fn new(bound: Arc<Bound>, cipher: Box<dyn Skcipher>, nokey: bool) -> Arc<Self> {
        let iv = vec![0u8; cipher.iv_size()];
        Arc::new(Self {
            ino: next_ino(),
            bound,
            ctx: SpinLock::new(Ctx {
                cipher,
                queue: VecDeque::new(),
                iv,
                init: false,
                more: false,
                enc: false,
                write: false,
                nokey,
            }),
            options: SpinLock::new(Options::default()),
            wait: Arc::new(WaitQueue::new()),
            events: AtomicU64::new(0),
        })
    }

    /// A socket with no key takes the key of the bound socket, as `skcipher_check_key` of Linux.
    fn check_key(&self) -> Result<()> {
        let mut ctx = self.ctx.lock();
        if !ctx.nokey {
            return Ok(());
        }
        self.bound.check_key(|tfm| {
            if let Tfm::Skcipher(c) = tfm {
                ctx.cipher = c.box_clone();
            }
        })?;
        ctx.nokey = false;
        Ok(())
    }

    /// The free space of the queue, as `af_alg_sndbuf` of Linux.
    fn space(&self, ctx: &Ctx) -> usize {
        let buf = (self.options.lock().sndbuf as usize & !(PAGE_SIZE - 1)).max(PAGE_SIZE);
        buf.saturating_sub(ctx.queue.len())
    }

    /// The size of the receive buffer, as `af_alg_rcvbuf` of Linux with nothing in use.
    fn rcvbuf(&self) -> usize {
        (self.options.lock().rcvbuf as usize & !(PAGE_SIZE - 1)).max(PAGE_SIZE)
    }

    fn wake(&self) {
        self.events.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
    }

    /// Adds data to the queue, as `af_alg_sendmsg` of Linux.
    fn send_data(&self, msg: &Message, flags: u32, nonblock: bool) -> Result<usize> {
        let con = if msg.control.is_empty() && msg.rights.is_empty() && msg.cred.is_none() {
            None
        } else {
            Some(control(msg)?)
        };
        let enc = match con.as_ref().map(|c| c.op) {
            None | Some(ALG_OP_DECRYPT) => false,
            Some(ALG_OP_ENCRYPT) => true,
            Some(_) => return Err(Errno::EINVAL),
        };
        let mut ctx = self.ctx.lock();
        if let Some(iv) = con.as_ref().and_then(|c| c.iv.as_ref())
            && iv.len() != ctx.cipher.iv_size()
        {
            return Err(Errno::EINVAL);
        }
        if ctx.write {
            return Err(Errno::EBUSY);
        }
        // The data of an operation that ended waits for a receive.
        if ctx.init && !ctx.more && !ctx.queue.is_empty() {
            return Err(Errno::EINVAL);
        }
        ctx.init = true;
        if let Some(con) = con {
            ctx.enc = enc;
            if let Some(iv) = con.iv {
                ctx.iv = iv;
            }
        }
        let data = &msg.data;
        let mut copied = 0;
        let mut err = None;
        while copied < data.len() {
            let space = self.space(&ctx);
            if space < PAGE_SIZE {
                // `af_alg_wait_for_wmem` of Linux: wait for a receive.
                if nonblock || flags & MSG_DONTWAIT != 0 {
                    err = Some(Errno::EAGAIN);
                    break;
                }
                ctx.write = true;
                drop(ctx);
                let r = wait_for(&self.wait, Timeout::default(), || {
                    let c = self.ctx.lock();
                    Ok((self.space(&c) >= PAGE_SIZE).then_some(()))
                });
                ctx = self.ctx.lock();
                ctx.write = false;
                if let Err(e) = r {
                    err = Some(e);
                    break;
                }
                continue;
            }
            let n = space.min(data.len() - copied);
            ctx.queue.extend(&data[copied..copied + n]);
            copied += n;
        }
        if err.is_none() {
            ctx.more = flags & MSG_MORE != 0;
        }
        let used = !ctx.queue.is_empty();
        drop(ctx);
        if used {
            self.wake();
        }
        match err {
            Some(e) if copied == 0 => Err(e),
            _ => Ok(copied),
        }
    }

    /// One operation of a receive, as `_skcipher_recvmsg` of Linux. Gives the result, at most
    /// `len` bytes.
    fn recv_once(&self, len: usize, wait: bool) -> Result<Vec<u8>> {
        let mut ctx = self.ctx.lock();
        let bs = ctx.cipher.chunk_size();
        if !ctx.init || (ctx.more && ctx.queue.len() < bs) {
            // `af_alg_wait_for_data` of Linux.
            if !wait {
                return Err(Errno::EAGAIN);
            }
            drop(ctx);
            wait_for(&self.wait, Timeout::default(), || {
                let c = self.ctx.lock();
                Ok((c.init && (!c.more || c.queue.len() >= bs)).then_some(()))
            })?;
            ctx = self.ctx.lock();
        }
        let used = ctx.queue.len();
        let mut n = len.min(used).min(self.rcvbuf());
        // While more data comes, take only full blocks.
        if ctx.more || n < used {
            n -= n % bs;
            if n == 0 {
                return Err(Errno::EINVAL);
            }
        }
        let mut data: Vec<u8> = ctx.queue.drain(..n).collect();
        // `af_alg_pull_tsgl` of Linux: an operation that ended needs a new send.
        if ctx.queue.is_empty() {
            ctx.init = ctx.more;
        }
        let ctx = &mut *ctx;
        if ctx.enc {
            ctx.cipher.encrypt(&mut ctx.iv, &mut data)?;
        } else {
            ctx.cipher.decrypt(&mut ctx.iv, &mut data)?;
        }
        Ok(data)
    }
}

impl Drop for SkcipherSocket {
    fn drop(&mut self) {
        let nokey = self.ctx.lock().nokey;
        self.bound.release(nokey);
    }
}

impl Socket for SkcipherSocket {
    fn family(&self) -> u32 {
        AF_ALG
    }

    fn kind(&self) -> u32 {
        SOCK_SEQPACKET
    }

    fn ino(&self) -> u64 {
        self.ino
    }

    fn send(&self, _: &dyn PathOps, msg: Message, flags: u32, nonblock: bool) -> Result<usize> {
        self.check_key()?;
        self.send_data(&msg, flags, nonblock)
    }

    /// Encrypts or decrypts the data of the queue, as `skcipher_recvmsg` of Linux. The receive
    /// does operations until it has `len` bytes. An error after some data gives the data. As
    /// Linux, a blocking receive of more bytes than the operation has waits for a new send.
    fn recv(&self, len: usize, flags: u32, nonblock: bool) -> Result<Received> {
        self.check_key()?;
        let wait = !nonblock && flags & MSG_DONTWAIT == 0;
        let mut out = Vec::new();
        let mut result = Ok(());
        while out.len() < len {
            match self.recv_once(len - out.len(), wait) {
                Ok(d) if d.is_empty() => break,
                Ok(d) => out.extend_from_slice(&d),
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        self.wake();
        if let Err(e) = result
            && out.is_empty()
        {
            return Err(e);
        }
        let n = out.len();
        Ok(Received { data: out, len: n, ..Received::default() })
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

    /// The events, as `af_alg_poll` of Linux.
    fn poll(&self) -> u32 {
        let ctx = self.ctx.lock();
        let read = if !ctx.more || !ctx.queue.is_empty() { POLLIN | POLLRDNORM } else { 0 };
        let write =
            if self.space(&ctx) >= PAGE_SIZE { POLLOUT | POLLWRNORM | POLLWRBAND } else { 0 };
        read | write
    }

    fn poll_wait(&self, table: &mut PollTable) {
        table.add(&self.wait);
    }

    fn event_count(&self) -> u64 {
        self.events.load(Ordering::Relaxed)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

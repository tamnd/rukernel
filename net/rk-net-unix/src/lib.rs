//! Unix sockets: stream, datagram and seqpacket sockets in one machine, as net/unix/af_unix.c
//! of Linux has them.
//!
//! A socket has a name in the tree (a path), an abstract name (the first byte of the path is 0),
//! or no name. The table `NAMES` finds the socket of a name. A message goes into the receive
//! queue of the peer. The bytes of a message count against the send buffer of the sender until
//! the receiver takes them, as `sk_wmem_alloc` of Linux. Thus a full peer stops the sender.
//!
//! A message can carry files (`SCM_RIGHTS`) and credentials (`SCM_CREDENTIALS`). rukernel does
//! not collect the cycles of sockets that are in flight in their own queues. Linux has a garbage
//! collector for them in net/unix/garbage.c.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use rk_abi::Errno;
use rk_abi::native::poll::{
    POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP, POLLRDNORM, POLLWRBAND, POLLWRNORM,
};
use rk_abi::native::socket::{
    SO_ACCEPTCONN, SO_BINDTODEVICE, SO_COOKIE, SO_DOMAIN, SO_ERROR, SO_PASSCRED, SO_PASSPIDFD,
    SO_PASSSEC, SO_PEEK_OFF, SO_PEERCRED, SO_PEERGROUPS, SO_PEERSEC, SO_PROTOCOL, SO_SNDLOWAT,
    SO_TYPE, SOL_SOCKET,
};
use rk_frame::sync::SpinLock;
use rk_net::consts::{
    AF_UNIX, AF_UNSPEC, MSG_DONTWAIT, MSG_OOB, MSG_PEEK, MSG_TRUNC, MSG_WAITALL, SHUT_RD,
    SHUT_RDWR, SHUT_WR, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET, SOCK_STREAM,
};
use rk_net::{
    Cred, Message, NO_CRED, NodeId, Options, PathOps, Received, Socket, current_cred, wait_for,
};
use rk_vfs::File;
use rk_vfs::inode::Result;
use rk_vfs::wait::{PollTable, WaitQueue};

/// The offset of `sun_path` in `struct sockaddr_un`.
const SUN_PATH: usize = 2;
/// The size of `struct sockaddr_un`.
const SOCKADDR_UN_SIZE: usize = SUN_PATH + 108;
/// The most datagrams in a receive queue, the default of `net.unix.max_dgram_qlen`.
const MAX_DGRAM_QLEN: usize = 10;

/// The name of a bound socket in the table.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    /// A socket file in the tree.
    Path(NodeId),
    /// An abstract name: the ID of the network namespace and the bytes after the first 0. Each
    /// namespace has its own abstract names, as `unix_find_abstract` of Linux, which uses
    /// `sock_net` in the hash.
    Abstract(u32, Vec<u8>),
}

/// The bound sockets.
static NAMES: SpinLock<BTreeMap<Key, Weak<Unix>>> = SpinLock::new(BTreeMap::new());
/// All the sockets, by their inode number, for /proc/net/unix.
static ALL: SpinLock<BTreeMap<u64, Weak<Unix>>> = SpinLock::new(BTreeMap::new());

/// `__SO_ACCEPTCON` of linux/net.h, the flag of a listening socket in /proc/net/unix. The value
/// is written by hand because rk-abigen does not take linux/net.h yet.
const SO_ACCEPTCON: u32 = 1 << 16;
/// `SS_UNCONNECTED` of `enum socket_state` in linux/net.h, written by hand as `SO_ACCEPTCON`.
const SS_UNCONNECTED: u32 = 1;
/// `SS_CONNECTED` of `enum socket_state` in linux/net.h.
const SS_CONNECTED: u32 = 3;

/// Adds /proc/net/unix. The boot code calls this one time.
pub fn init() {
    rk_net::procfs::register("unix", show);
}

/// The text of /proc/net/unix, as `unix_seq_show` of Linux. The address of a socket shows as 0,
/// as Linux shows it with `kernel.kptr_restrict`.
pub fn show() -> String {
    let mut out = String::from("Num       RefCount Protocol Flags    Type St Inode Path\n");
    let all: Vec<Arc<Unix>> = ALL.lock().values().filter_map(Weak::upgrade).collect();
    for u in all {
        let s = u.state.lock();
        if s.closed {
            continue;
        }
        let flags = if s.conn == Conn::Listening { SO_ACCEPTCON } else { 0 };
        let connected = s.conn == Conn::Connected || (u.kind == SOCK_DGRAM && s.peer.is_some());
        let st = if connected { SS_CONNECTED } else { SS_UNCONNECTED };
        out.push_str(&format!(
            "0000000000000000: {:08X} {:08X} {flags:08X} {:04X} {st:02X} {:5}",
            2 + u32::from(connected),
            0,
            u.kind,
            u.ino
        ));
        if let Some(path) = s.addr.as_ref().and_then(|a| a.get(SUN_PATH..)) {
            out.push(' ');
            match path.split_first() {
                // An abstract name starts with `@`, and each 0 in it shows as `@`.
                Some((0, name)) => {
                    out.push('@');
                    out.extend(name.iter().map(|&b| if b == 0 { '@' } else { char::from(b) }));
                }
                _ => {
                    let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
                    out.push_str(&String::from_utf8_lossy(&path[..end]));
                }
            }
        }
        out.push('\n');
    }
    out
}

/// A name from the address of a call.
enum Name {
    /// The path, without the 0 at the end.
    Path(Vec<u8>),
    /// The abstract name, without the first 0.
    Abstract(Vec<u8>),
}

impl Name {
    /// Checks an address as `unix_validate_addr` of Linux, and gives the name.
    fn parse(addr: &[u8]) -> Result<Self> {
        if addr.len() <= SUN_PATH || addr.len() > SOCKADDR_UN_SIZE || family(addr) != AF_UNIX {
            return Err(Errno::EINVAL);
        }
        let path = &addr[SUN_PATH..];
        if path[0] == 0 {
            return Ok(Self::Abstract(path[1..].to_vec()));
        }
        let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
        Ok(Self::Path(path[..end].to_vec()))
    }

    /// The address that `getsockname` gives for the name.
    fn address(&self) -> Vec<u8> {
        let mut addr = (AF_UNIX as u16).to_ne_bytes().to_vec();
        match self {
            Self::Path(p) => {
                addr.extend_from_slice(p);
                addr.push(0);
            }
            Self::Abstract(a) => {
                addr.push(0);
                addr.extend_from_slice(a);
            }
        }
        addr
    }

    /// The key of the name. `net` is the ID of the network namespace of the socket.
    fn key(&self, paths: &dyn PathOps, net: u32) -> Result<Key> {
        match self {
            Self::Path(p) => Ok(Key::Path(paths.find_node(p)?)),
            Self::Abstract(a) => Ok(Key::Abstract(net, a.clone())),
        }
    }
}

/// The family of an address. The caller checked that it has 2 bytes.
fn family(addr: &[u8]) -> u32 {
    u32::from(u16::from_ne_bytes([addr[0], addr[1]]))
}

/// The address of a socket with no name.
fn unnamed() -> Vec<u8> {
    (AF_UNIX as u16).to_ne_bytes().to_vec()
}

/// One message in a receive queue.
struct Packet {
    data: Vec<u8>,
    /// The bytes that a stream receive took.
    read: usize,
    /// The address of the sender.
    from: Option<Vec<u8>>,
    rights: Vec<Arc<File>>,
    /// The credentials of the sender. A message has them if the sender gave them, or if the
    /// sender or the receiver had `SO_PASSCRED` at the send, as in Linux.
    cred: Option<Cred>,
    sender: Weak<Unix>,
}

impl Packet {
    fn rest(&self) -> usize {
        self.data.len() - self.read
    }
}

/// The state of the connection of a stream or seqpacket socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Conn {
    Unconnected,
    Listening,
    Connected,
}

struct State {
    /// The address for `getsockname`.
    addr: Option<Vec<u8>>,
    /// The name in `NAMES`. An accepted socket has the address of the listener, but no key.
    key: Option<Key>,
    conn: Conn,
    /// The peer: the other end of a connection, or the destination of a datagram socket.
    peer: Option<Arc<Unix>>,
    /// The credentials of the peer at the time of the connection, for `SO_PEERCRED`.
    peer_cred: Option<Cred>,
    /// The credentials of a listener at the time of `listen`.
    listen_cred: Option<Cred>,
    backlog: usize,
    /// The connections that `accept` did not take.
    pending: VecDeque<Arc<Unix>>,
    queue: VecDeque<Packet>,
    shut_rd: bool,
    shut_wr: bool,
    /// The file of the socket closed.
    closed: bool,
    /// The error for `SO_ERROR` and the next call.
    error: Option<Errno>,
    passcred: bool,
    passsec: bool,
    passpidfd: bool,
    peek_off: i32,
    options: Options,
}

/// A Unix socket.
pub struct Unix {
    kind: u32,
    ino: u64,
    state: SpinLock<State>,
    /// The tasks that wait for a change of the socket wait here: a receive for a message, a
    /// send for space, `accept` for a connection and `connect` for space in the backlog.
    wait: Arc<WaitQueue>,
    /// The bytes that this socket sent and the receivers did not take.
    inflight: AtomicUsize,
    /// The count of the wakes, for an edge triggered epoll entry.
    events: AtomicU64,
    /// The ID of the network namespace that made the socket, for the abstract names.
    net: u32,
    this: Weak<Unix>,
}

impl Drop for Unix {
    fn drop(&mut self) {
        ALL.lock().remove(&self.ino);
    }
}

/// The counter of the names that `bind` gives to a socket with no name.
static AUTOBIND: AtomicU32 = AtomicU32::new(0);

impl Unix {
    /// Makes a socket of the type `kind`. `SOCK_RAW` is a datagram socket, as in Linux.
    ///
    /// # Errors
    ///
    /// Gives `ESOCKTNOSUPPORT` for a type that Unix sockets do not have.
    pub fn new(kind: u32) -> Result<Arc<Self>> {
        let kind = match kind {
            SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET => kind,
            SOCK_RAW => SOCK_DGRAM,
            _ => return Err(Errno::ESOCKTNOSUPPORT),
        };
        let sock = Arc::new_cyclic(|this| Self {
            kind,
            ino: rk_net::next_ino(),
            state: SpinLock::new(State {
                addr: None,
                key: None,
                conn: Conn::Unconnected,
                peer: None,
                peer_cred: None,
                listen_cred: None,
                backlog: 0,
                pending: VecDeque::new(),
                queue: VecDeque::new(),
                shut_rd: false,
                shut_wr: false,
                closed: false,
                error: None,
                passcred: false,
                passsec: false,
                passpidfd: false,
                peek_off: -1,
                options: Options::default(),
            }),
            wait: Arc::new(WaitQueue::new()),
            inflight: AtomicUsize::new(0),
            events: AtomicU64::new(0),
            net: rk_net::ns::current().id(),
            this: this.clone(),
        });
        ALL.lock().insert(sock.ino, Arc::downgrade(&sock));
        Ok(sock)
    }

    /// Makes two sockets of the type `kind` that are connected, for `socketpair`.
    ///
    /// # Errors
    ///
    /// Gives `ESOCKTNOSUPPORT` for a type that Unix sockets do not have.
    pub fn pair(kind: u32) -> Result<(Arc<Self>, Arc<Self>)> {
        let a = Self::new(kind)?;
        let b = Self::new(kind)?;
        let cred = current_cred();
        for (x, y) in [(&a, &b), (&b, &a)] {
            let mut s = x.state.lock();
            s.peer = Some(y.clone());
            s.peer_cred = Some(cred);
            if kind != SOCK_DGRAM {
                s.conn = Conn::Connected;
            }
        }
        Ok((a, b))
    }

    fn me(&self) -> Arc<Self> {
        // The socket is alive while a caller has a reference to it.
        self.this.upgrade().unwrap_or_else(|| unreachable!())
    }

    fn wake(&self) {
        self.events.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
    }

    fn sndbuf(&self) -> usize {
        self.state.lock().options.sndbuf as usize
    }

    /// Takes the bytes of `n` from the count of the sender, because the receiver took them.
    ///
    /// As `unix_write_space` of Linux, the sender wakes only when at most a quarter of its send
    /// buffer is in use, the same test as POLLOUT. A wake for each read wakes all the writers of
    /// a full socket for each small read, and each writer then finds too little space and sleeps
    /// again. With hackbench, this made each system call cost about 1 ms on TCG.
    fn uncharge(sender: &Weak<Unix>, n: usize) {
        if let Some(sender) = sender.upgrade() {
            let used = sender.inflight.fetch_sub(n, Ordering::Relaxed).saturating_sub(n);
            if used * 4 <= sender.sndbuf() {
                sender.wake();
            }
        }
    }

    /// Finds the socket with the name in `addr`. The type must be the type of this socket. An
    /// abstract name is in the namespace of this socket.
    fn lookup(&self, paths: &dyn PathOps, name: &Name) -> Result<Arc<Unix>> {
        let kind = self.kind;
        let key = name.key(paths, self.net)?;
        let found = NAMES.lock().get(&key).and_then(Weak::upgrade);
        let Some(other) = found else { return Err(Errno::ECONNREFUSED) };
        if other.state.lock().closed {
            return Err(Errno::ECONNREFUSED);
        }
        if other.kind != kind {
            return Err(Errno::EPROTOTYPE);
        }
        Ok(other)
    }

    /// Gives the socket an abstract name of five hex digits, as `unix_autobind` of Linux.
    fn autobind(&self) -> Result<()> {
        let mut s = self.state.lock();
        if s.addr.is_some() {
            return Ok(());
        }
        let mut names = NAMES.lock();
        for _ in 0..=0xfffff {
            let n = AUTOBIND.fetch_add(1, Ordering::Relaxed) & 0xfffff;
            let name = Name::Abstract(format!("{n:05x}").into_bytes());
            let Name::Abstract(a) = &name else { continue };
            let key = Key::Abstract(self.net, a.clone());
            if names.get(&key).and_then(Weak::upgrade).is_some() {
                continue;
            }
            names.insert(key.clone(), self.this.clone());
            s.addr = Some(name.address());
            s.key = Some(key);
            return Ok(());
        }
        Err(Errno::ENOSPC)
    }

    /// Takes the pending error, as `sock_error` of Linux.
    fn take_error(&self) -> Result<()> {
        match self.state.lock().error.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// A datagram socket lost its peer `other`, as `unix_dgram_disconnected` of Linux. The
    /// messages in the queue go away. If `other` has this socket as its peer, it gets
    /// `ECONNRESET`.
    fn dgram_disconnected(&self, other: &Arc<Unix>) {
        let purged: Vec<Packet> = self.state.lock().queue.drain(..).collect();
        for p in &purged {
            Self::uncharge(&p.sender, p.rest());
        }
        drop(purged);
        self.wake();
        let mut o = other.state.lock();
        if !o.closed && o.peer.as_ref().is_some_and(|p| core::ptr::eq(Arc::as_ptr(p), self)) {
            o.error = Some(Errno::ECONNRESET);
            drop(o);
            other.wake();
        }
    }

    /// Closes the socket. An embryo is a connection that `accept` did not take.
    fn close(&self, embryo: bool) {
        let (key, pending, packets, peer) = {
            let mut s = self.state.lock();
            if s.closed {
                return;
            }
            s.closed = true;
            s.shut_rd = true;
            s.shut_wr = true;
            let pending: Vec<Arc<Unix>> = s.pending.drain(..).collect();
            let packets: Vec<Packet> = s.queue.drain(..).collect();
            (s.key.take(), pending, packets, s.peer.take())
        };
        if let Some(key) = key {
            let mut names = NAMES.lock();
            if names.get(&key).is_some_and(|w| core::ptr::eq(w.as_ptr(), self)) {
                names.remove(&key);
            }
        }
        if let Some(peer) = &peer
            && self.kind != SOCK_DGRAM
        {
            let mut p = peer.state.lock();
            p.shut_rd = true;
            p.shut_wr = true;
            if !packets.is_empty() || embryo {
                p.error = Some(Errno::ECONNRESET);
            }
            drop(p);
            peer.wake();
        }
        for p in &packets {
            Self::uncharge(&p.sender, p.rest());
        }
        for e in pending {
            e.close(true);
        }
        drop(packets);
        drop(peer);
        self.wake();
    }

    fn connect_dgram(&self, paths: &dyn PathOps, addr: &[u8]) -> Result<()> {
        if addr.len() < SUN_PATH {
            return Err(Errno::EINVAL);
        }
        if family(addr) == AF_UNSPEC {
            let old = self.state.lock().peer.take();
            if let Some(old) = old {
                self.dgram_disconnected(&old);
            }
            return Ok(());
        }
        let name = Name::parse(addr)?;
        if self.state.lock().passcred {
            self.autobind()?;
        }
        let other = self.lookup(paths, &name)?;
        if !may_send(&other, self) {
            return Err(Errno::EPERM);
        }
        let old = self.state.lock().peer.replace(other.clone());
        if let Some(old) = old
            && !Arc::ptr_eq(&old, &other)
        {
            self.dgram_disconnected(&old);
        }
        Ok(())
    }

    fn connect_stream(&self, paths: &dyn PathOps, addr: &[u8], nonblock: bool) -> Result<()> {
        let name = Name::parse(addr)?;
        let timeout = {
            let s = self.state.lock();
            match s.conn {
                Conn::Connected => return Err(Errno::EISCONN),
                Conn::Listening => return Err(Errno::EINVAL),
                Conn::Unconnected => {}
            }
            (s.passcred, s.options.sndtimeo)
        };
        if timeout.0 {
            self.autobind()?;
        }
        loop {
            let other = self.lookup(paths, &name)?;
            let mut o = other.state.lock();
            if o.conn != Conn::Listening || o.shut_rd {
                return Err(Errno::ECONNREFUSED);
            }
            if o.pending.len() > o.backlog {
                drop(o);
                if nonblock {
                    return Err(Errno::EAGAIN);
                }
                wait_for(&other.wait, timeout.1, || {
                    let o = other.state.lock();
                    let ready =
                        o.closed || o.conn != Conn::Listening || o.pending.len() <= o.backlog;
                    Ok(ready.then_some(()))
                })?;
                continue;
            }
            let mut s = self.state.lock();
            if s.conn != Conn::Unconnected {
                return Err(Errno::EISCONN);
            }
            let server = Self::new(self.kind)?;
            {
                let mut n = server.state.lock();
                n.conn = Conn::Connected;
                n.peer = Some(self.me());
                n.peer_cred = Some(current_cred());
                n.addr = o.addr.clone();
                n.options.sndbuf = o.options.sndbuf;
                n.options.rcvbuf = o.options.rcvbuf;
            }
            s.conn = Conn::Connected;
            s.peer = Some(server.clone());
            s.peer_cred = o.listen_cred;
            o.pending.push_back(server);
            drop(s);
            drop(o);
            other.wake();
            return Ok(());
        }
    }

    /// Tells if a message to `peer` gets the credentials of the sender: `SO_PASSCRED` is set on
    /// this socket or on `peer`.
    fn may_passcred(&self, peer: &Self) -> bool {
        self.state.lock().passcred || peer.state.lock().passcred
    }

    /// The send of a stream socket: the data goes in pieces into the queue of the peer.
    fn send_stream(&self, msg: Message, nonblock: bool) -> Result<usize> {
        let (peer, timeout, from) = {
            let s = self.state.lock();
            if msg.addr.is_some() {
                return Err(if s.conn == Conn::Connected {
                    Errno::EISCONN
                } else {
                    Errno::EOPNOTSUPP
                });
            }
            if s.conn != Conn::Connected {
                return Err(Errno::ENOTCONN);
            }
            if s.shut_wr {
                return Err(Errno::EPIPE);
            }
            let Some(peer) = s.peer.clone() else { return Err(Errno::ENOTCONN) };
            (peer, s.options.sndtimeo, s.addr.clone())
        };
        let cred = msg.cred.or_else(|| self.may_passcred(&peer).then(current_cred));
        let mut rights = Some(msg.rights);
        let data = msg.data;
        let mut sent = 0;
        while sent < data.len() {
            let sndbuf = self.sndbuf();
            let space = wait_for(&self.wait, timeout, || {
                if self.state.lock().shut_wr {
                    return Err(Errno::EPIPE);
                }
                let used = self.inflight.load(Ordering::Relaxed);
                if used < sndbuf {
                    return Ok(Some(sndbuf - used));
                }
                if nonblock { Err(Errno::EAGAIN) } else { Ok(None) }
            });
            let space = match space {
                Ok(space) => space,
                Err(_) if sent > 0 => return Ok(sent),
                Err(e) => return Err(e),
            };
            let n = (data.len() - sent).min(space).min((sndbuf / 2).saturating_sub(64).max(1));
            let mut p = peer.state.lock();
            if p.closed || p.shut_rd {
                drop(p);
                return if sent > 0 { Ok(sent) } else { Err(Errno::EPIPE) };
            }
            p.queue.push_back(Packet {
                data: data[sent..sent + n].to_vec(),
                read: 0,
                from: from.clone(),
                rights: rights.take().unwrap_or_default(),
                cred,
                sender: self.this.clone(),
            });
            drop(p);
            self.inflight.fetch_add(n, Ordering::Relaxed);
            peer.wake();
            sent += n;
        }
        Ok(sent)
    }

    /// The send of a datagram or seqpacket socket: one message.
    fn send_dgram(&self, paths: &dyn PathOps, msg: Message, nonblock: bool) -> Result<usize> {
        self.take_error()?;
        let len = msg.data.len();
        let (passcred, unbound, sndbuf, timeout) = {
            let s = self.state.lock();
            if self.kind == SOCK_SEQPACKET && s.conn != Conn::Connected {
                return Err(Errno::ENOTCONN);
            }
            (s.passcred, s.addr.is_none(), s.options.sndbuf as usize, s.options.sndtimeo)
        };
        if len > sndbuf.saturating_sub(32) {
            return Err(Errno::EMSGSIZE);
        }
        if passcred && unbound && self.kind == SOCK_DGRAM {
            self.autobind()?;
        }
        let other = match &msg.addr {
            Some(addr) if self.kind == SOCK_DGRAM => self.lookup(paths, &Name::parse(addr)?)?,
            _ => match self.state.lock().peer.clone() {
                Some(peer) => peer,
                None => return Err(Errno::ENOTCONN),
            },
        };
        if self.state.lock().shut_wr {
            return Err(Errno::EPIPE);
        }
        // Wait for space in the send buffer, then for space in the queue of the receiver.
        wait_for(&self.wait, timeout, || {
            if self.state.lock().shut_wr {
                return Err(Errno::EPIPE);
            }
            if self.inflight.load(Ordering::Relaxed) < sndbuf {
                return Ok(Some(()));
            }
            if nonblock { Err(Errno::EAGAIN) } else { Ok(None) }
        })?;
        let me = self.me();
        let mut msg = Some(msg);
        wait_for(&other.wait, timeout, || {
            let mut o = other.state.lock();
            if o.closed {
                drop(o);
                if self.kind == SOCK_SEQPACKET {
                    return Err(Errno::EPIPE);
                }
                let mut s = self.state.lock();
                if s.peer.as_ref().is_some_and(|p| Arc::ptr_eq(p, &other)) {
                    s.peer = None;
                    drop(s);
                    self.dgram_disconnected(&other);
                }
                return Err(Errno::ECONNREFUSED);
            }
            if self.kind == SOCK_DGRAM && !may_send_locked(&o, self) {
                return Err(Errno::EPERM);
            }
            if o.shut_rd {
                return Err(Errno::EPIPE);
            }
            let ours = o.peer.as_ref().is_some_and(|p| Arc::ptr_eq(p, &me));
            if !Arc::ptr_eq(&other, &me) && !ours && o.queue.len() > MAX_DGRAM_QLEN {
                return if nonblock { Err(Errno::EAGAIN) } else { Ok(None) };
            }
            let Some(msg) = msg.take() else { return Ok(Some(())) };
            let cred = msg.cred.or_else(|| (passcred || o.passcred).then(current_cred));
            let from = if Arc::ptr_eq(&other, &me) {
                o.addr.clone()
            } else {
                self.state.lock().addr.clone()
            };
            o.queue.push_back(Packet {
                data: msg.data,
                read: 0,
                from,
                rights: msg.rights,
                cred,
                sender: self.this.clone(),
            });
            Ok(Some(()))
        })?;
        self.inflight.fetch_add(len, Ordering::Relaxed);
        other.wake();
        Ok(len)
    }

    /// The receive of a datagram or seqpacket socket: one message.
    fn recv_dgram(&self, len: usize, flags: u32, nonblock: bool) -> Result<Received> {
        let peek = flags & MSG_PEEK != 0;
        let timeout = {
            let s = self.state.lock();
            if self.kind == SOCK_SEQPACKET && s.conn != Conn::Connected {
                return Err(Errno::ENOTCONN);
            }
            s.options.rcvtimeo
        };
        let taken = wait_for(&self.wait, timeout, || {
            let mut s = self.state.lock();
            if let Some(e) = s.error.take() {
                return Err(e);
            }
            let passcred = s.passcred;
            let mut skip = if peek && s.peek_off >= 0 { s.peek_off as usize } else { 0 };
            let mut index = None;
            for (i, p) in s.queue.iter().enumerate() {
                if skip < p.data.len() || (skip == 0 && p.data.is_empty()) {
                    index = Some(i);
                    break;
                }
                skip -= p.data.len();
            }
            if let Some(i) = index {
                let p = &s.queue[i];
                let size = (p.data.len() - skip).min(len);
                let mut r = Received {
                    data: p.data[skip..skip + size].to_vec(),
                    len: p.data.len() - skip,
                    addr: p.from.clone(),
                    rights: Vec::new(),
                    cred: passcred.then(|| p.cred.unwrap_or(NO_CRED)),
                    flags: 0,
                    control: Vec::new(),
                };
                if r.len > size {
                    r.flags |= MSG_TRUNC;
                }
                if peek {
                    r.rights = p.rights.clone();
                    if s.peek_off >= 0 {
                        s.peek_off = s.peek_off.saturating_add(size as i32);
                    }
                    return Ok(Some((r, None)));
                }
                let p = s.queue.remove(i).unwrap_or_else(|| unreachable!());
                if s.peek_off >= 0 {
                    s.peek_off = (s.peek_off - p.data.len() as i32).max(0);
                }
                let mut p = p;
                r.rights = core::mem::take(&mut p.rights);
                return Ok(Some((r, Some(p))));
            }
            if s.shut_rd {
                return Ok(Some((Received::default(), None)));
            }
            if nonblock { Err(Errno::EAGAIN) } else { Ok(None) }
        })?;
        let (r, packet) = taken;
        if let Some(p) = packet {
            Self::uncharge(&p.sender, p.data.len());
            self.wake();
        }
        Ok(r)
    }

    /// The receive of a stream socket: bytes of one or more messages.
    fn recv_stream(&self, len: usize, flags: u32, nonblock: bool) -> Result<Received> {
        let peek = flags & MSG_PEEK != 0;
        let (timeout, lowat) = {
            let s = self.state.lock();
            if s.conn != Conn::Connected {
                return Err(Errno::EINVAL);
            }
            let lowat = s
                .options
                .get(rk_abi::native::socket::SO_RCVLOWAT)
                .ok()
                .and_then(|v| v.first_chunk::<4>().map(|b| i32::from_ne_bytes(*b)))
                .unwrap_or(1)
                .max(1) as usize;
            (s.options.rcvtimeo, lowat)
        };
        // As in `sock_rcvlowat` of Linux, the target is at least one byte. A receive of 0 bytes
        // waits until data is in the queue.
        let target = if flags & MSG_WAITALL != 0 { len } else { lowat.min(len) }.max(1);
        let mut out = Received::default();
        let mut first = true;
        let mut charged: Vec<(Weak<Unix>, usize)> = Vec::new();
        let r = wait_for(&self.wait, timeout, || {
            let mut s = self.state.lock();
            let passcred = s.passcred;
            let mut skip = if peek && s.peek_off >= 0 { s.peek_off as usize } else { 0 };
            let mut stop = false;
            let mut i = 0;
            let mut cred = None;
            // A receive of 0 bytes takes the files of the first message, and leaves its data.
            if len == 0
                && !peek
                && let Some(p) = s.queue.front_mut()
            {
                out.addr = p.from.clone();
                out.cred = passcred.then(|| p.cred.unwrap_or(NO_CRED));
                out.rights = core::mem::take(&mut p.rights);
                return Ok(Some(()));
            }
            while out.data.len() < len && i < s.queue.len() {
                let p = &mut s.queue[i];
                let rest = p.rest();
                if skip >= rest && rest > 0 {
                    skip -= rest;
                    i += 1;
                    continue;
                }
                // Messages of different writers are not joined, as in Linux.
                if !first && passcred && cred != p.cred {
                    stop = true;
                    break;
                }
                if first {
                    first = false;
                    out.addr = p.from.clone();
                    cred = p.cred;
                    out.cred = passcred.then(|| p.cred.unwrap_or(NO_CRED));
                }
                let n = (rest - skip).min(len - out.data.len());
                let start = p.read + skip;
                out.data.extend_from_slice(&p.data[start..start + n]);
                skip = 0;
                let has_rights = !p.rights.is_empty();
                if peek {
                    if has_rights {
                        out.rights = p.rights.clone();
                        stop = true;
                        break;
                    }
                    i += 1;
                    continue;
                }
                p.read += n;
                charged.push((p.sender.clone(), n));
                if has_rights {
                    out.rights = core::mem::take(&mut p.rights);
                }
                if p.rest() == 0 {
                    s.queue.remove(i);
                } else {
                    // The buffer of the caller is full.
                    break;
                }
                if has_rights {
                    stop = true;
                    break;
                }
            }
            let copied = out.data.len();
            if peek && s.peek_off >= 0 {
                s.peek_off = s.peek_off.saturating_add(copied as i32);
            }
            if copied >= target
                || stop
                || (copied > 0 && nonblock)
                || (len == 0 && !s.queue.is_empty())
            {
                return Ok(Some(()));
            }
            if copied == 0
                && let Some(e) = s.error.take()
            {
                return Err(e);
            }
            if s.shut_rd {
                return Ok(Some(()));
            }
            if nonblock {
                return Err(Errno::EAGAIN);
            }
            Ok(None)
        });
        if !peek && !out.data.is_empty() {
            let mut s = self.state.lock();
            if s.peek_off >= 0 {
                s.peek_off = (s.peek_off - out.data.len() as i32).max(0);
            }
        }
        for (sender, n) in &charged {
            Self::uncharge(sender, *n);
        }
        match r {
            Ok(()) => {}
            Err(_) if !out.data.is_empty() => {}
            Err(e) => return Err(e),
        }
        out.len = out.data.len();
        Ok(out)
    }
}

/// Tells if `sender` can send to `other`: `other` has no peer, or `sender` is its peer, as
/// `unix_may_send` of Linux.
fn may_send(other: &Unix, sender: &Unix) -> bool {
    may_send_locked(&other.state.lock(), sender)
}

fn may_send_locked(o: &State, sender: &Unix) -> bool {
    o.peer.as_ref().is_none_or(|p| core::ptr::eq(Arc::as_ptr(p), sender))
}

/// Gives the bytes of an `int` option.
fn int(v: i32) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

impl Socket for Unix {
    fn family(&self) -> u32 {
        AF_UNIX
    }

    fn kind(&self) -> u32 {
        self.kind
    }

    fn ino(&self) -> u64 {
        self.ino
    }

    fn bind(&self, paths: &dyn PathOps, addr: &[u8]) -> Result<()> {
        if addr.len() == SUN_PATH && family(addr) == AF_UNIX {
            if self.state.lock().addr.is_some() {
                return Err(Errno::EINVAL);
            }
            return self.autobind();
        }
        let name = Name::parse(addr)?;
        if self.state.lock().addr.is_some() {
            return Err(Errno::EINVAL);
        }
        let key = match &name {
            Name::Path(p) => Key::Path(paths.make_node(p)?),
            Name::Abstract(a) => Key::Abstract(self.net, a.clone()),
        };
        let mut s = self.state.lock();
        if s.addr.is_some() {
            return Err(Errno::EINVAL);
        }
        let mut names = NAMES.lock();
        if names.get(&key).and_then(Weak::upgrade).is_some() {
            return Err(Errno::EADDRINUSE);
        }
        names.insert(key.clone(), self.this.clone());
        s.addr = Some(name.address());
        s.key = Some(key);
        Ok(())
    }

    fn connect(&self, paths: &dyn PathOps, addr: &[u8], nonblock: bool) -> Result<()> {
        if self.kind == SOCK_DGRAM {
            self.connect_dgram(paths, addr)
        } else {
            self.connect_stream(paths, addr, nonblock)
        }
    }

    fn listen(&self, backlog: u32) -> Result<()> {
        if self.kind == SOCK_DGRAM {
            return Err(Errno::EOPNOTSUPP);
        }
        let mut s = self.state.lock();
        if s.addr.is_none() || s.conn == Conn::Connected {
            return Err(Errno::EINVAL);
        }
        s.backlog = backlog as usize;
        s.conn = Conn::Listening;
        // A listener is its own peer, as `init_peercred` in `unix_listen` of Linux.
        s.listen_cred = Some(current_cred());
        s.peer_cred = s.listen_cred;
        drop(s);
        self.wake();
        Ok(())
    }

    fn accept(&self, nonblock: bool) -> Result<Arc<dyn Socket>> {
        if self.kind == SOCK_DGRAM {
            return Err(Errno::EOPNOTSUPP);
        }
        let timeout = {
            let s = self.state.lock();
            if s.conn != Conn::Listening {
                return Err(Errno::EINVAL);
            }
            s.options.rcvtimeo
        };
        let new = wait_for(&self.wait, timeout, || {
            let mut s = self.state.lock();
            if s.conn != Conn::Listening {
                return Err(Errno::EINVAL);
            }
            if let Some(new) = s.pending.pop_front() {
                // The new socket gets `SO_PASSCRED` of the listener, as `unix_sock_inherit_flags`.
                new.state.lock().passcred = s.passcred;
                return Ok(Some(new));
            }
            if nonblock { Err(Errno::EAGAIN) } else { Ok(None) }
        })?;
        self.wake();
        Ok(new)
    }

    fn send(&self, paths: &dyn PathOps, msg: Message, flags: u32, nonblock: bool) -> Result<usize> {
        let nonblock = nonblock || flags & MSG_DONTWAIT != 0;
        if flags & MSG_OOB != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        if self.kind == SOCK_STREAM {
            self.send_stream(msg, nonblock)
        } else {
            self.send_dgram(paths, msg, nonblock)
        }
    }

    fn recv(&self, len: usize, flags: u32, nonblock: bool) -> Result<Received> {
        let nonblock = nonblock || flags & MSG_DONTWAIT != 0;
        if flags & MSG_OOB != 0 {
            return Err(if self.kind == SOCK_STREAM { Errno::EINVAL } else { Errno::EOPNOTSUPP });
        }
        if self.kind == SOCK_STREAM {
            self.recv_stream(len, flags, nonblock)
        } else {
            self.recv_dgram(len, flags, nonblock)
        }
    }

    fn shutdown(&self, how: u32) -> Result<()> {
        if how > SHUT_RDWR {
            return Err(Errno::EINVAL);
        }
        let rd = how == SHUT_RD || how == SHUT_RDWR;
        let wr = how == SHUT_WR || how == SHUT_RDWR;
        let peer = {
            let mut s = self.state.lock();
            s.shut_rd |= rd;
            s.shut_wr |= wr;
            if self.kind != SOCK_DGRAM && s.conn == Conn::Connected { s.peer.clone() } else { None }
        };
        self.wake();
        if let Some(peer) = peer {
            let mut p = peer.state.lock();
            p.shut_wr |= rd;
            p.shut_rd |= wr;
            drop(p);
            peer.wake();
        }
        Ok(())
    }

    fn name(&self) -> Vec<u8> {
        self.state.lock().addr.clone().unwrap_or_else(unnamed)
    }

    fn peer_name(&self) -> Result<Vec<u8>> {
        let peer = {
            let s = self.state.lock();
            if self.kind != SOCK_DGRAM && s.conn != Conn::Connected {
                return Err(Errno::ENOTCONN);
            }
            s.peer.clone()
        };
        match peer {
            Some(peer) => Ok(peer.name()),
            None if self.kind == SOCK_DGRAM => Err(Errno::ENOTCONN),
            // The peer closed. Linux keeps the address of the peer.
            None => Ok(unnamed()),
        }
    }

    fn get_option(&self, level: u32, name: u32) -> Result<Vec<u8>> {
        if level != SOL_SOCKET {
            return Err(Errno::EOPNOTSUPP);
        }
        let mut s = self.state.lock();
        Ok(match name {
            SO_TYPE => int(self.kind as i32),
            SO_DOMAIN => int(AF_UNIX as i32),
            SO_PROTOCOL => int(0),
            SO_ERROR => int(s.error.take().map_or(0, |e| i32::from(e.get()))),
            SO_ACCEPTCONN => int(i32::from(s.conn == Conn::Listening)),
            SO_PASSCRED => int(i32::from(s.passcred)),
            SO_PASSSEC => int(i32::from(s.passsec)),
            SO_PASSPIDFD => int(i32::from(s.passpidfd)),
            SO_PEEK_OFF => int(s.peek_off),
            SO_SNDLOWAT => int(1),
            SO_COOKIE => self.ino.to_ne_bytes().to_vec(),
            SO_BINDTODEVICE | SO_PEERGROUPS => Vec::new(),
            SO_PEERSEC => return Err(Errno::ENOPROTOOPT),
            SO_PEERCRED => {
                // No peer gives the pid 0 and the IDs -1, as `cred_to_ucred` of Linux.
                let c = s.peer_cred.unwrap_or(Cred { pid: 0, uid: u32::MAX, gid: u32::MAX });
                let mut v = c.pid.to_ne_bytes().to_vec();
                v.extend_from_slice(&c.uid.to_ne_bytes());
                v.extend_from_slice(&c.gid.to_ne_bytes());
                v
            }
            _ => s.options.get(name)?,
        })
    }

    fn set_option(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
        if level != SOL_SOCKET {
            return Err(Errno::EOPNOTSUPP);
        }
        let flag = || -> Result<bool> {
            let Some(v) = value.first_chunk::<4>() else { return Err(Errno::EINVAL) };
            Ok(i32::from_ne_bytes(*v) != 0)
        };
        let mut s = self.state.lock();
        match name {
            SO_PASSCRED => s.passcred = flag()?,
            SO_PASSSEC => s.passsec = flag()?,
            SO_PASSPIDFD => s.passpidfd = flag()?,
            SO_PEEK_OFF => {
                let Some(v) = value.first_chunk::<4>() else { return Err(Errno::EINVAL) };
                s.peek_off = i32::from_ne_bytes(*v);
            }
            SO_BINDTODEVICE => {
                if value.first().is_some_and(|&b| b != 0) {
                    return Err(Errno::ENODEV);
                }
            }
            SO_TYPE | SO_DOMAIN | SO_PROTOCOL | SO_ERROR | SO_ACCEPTCONN | SO_PEERCRED
            | SO_PEERSEC | SO_PEERGROUPS | SO_COOKIE | SO_SNDLOWAT => {
                return Err(Errno::ENOPROTOOPT);
            }
            _ => s.options.set(name, value)?,
        }
        drop(s);
        self.wake();
        Ok(())
    }

    fn event_count(&self) -> u64 {
        self.events.load(Ordering::Relaxed)
    }

    fn poll_wait(&self, table: &mut PollTable) {
        table.add(&self.wait);
        // A datagram socket can write when the queue of its peer has space, as
        // `unix_dgram_poll` of Linux waits on the peer too.
        if self.kind != SOCK_STREAM
            && let Some(peer) = self.state.lock().peer.clone()
        {
            table.add(&peer.wait);
        }
    }

    fn poll(&self) -> u32 {
        let (mut mask, peer, listening) = {
            let s = self.state.lock();
            let mut mask = 0;
            if s.error.is_some() {
                mask |= POLLERR;
            }
            if s.shut_rd && s.shut_wr {
                mask |= POLLHUP;
            }
            if s.shut_rd {
                mask |= POLLRDHUP | POLLIN | POLLRDNORM;
            }
            if !s.queue.is_empty() || !s.pending.is_empty() {
                mask |= POLLIN | POLLRDNORM;
            }
            if self.kind != SOCK_DGRAM && s.conn == Conn::Unconnected {
                mask |= POLLHUP;
            }
            (mask, s.peer.clone(), s.conn == Conn::Listening)
        };
        let sndbuf = self.sndbuf();
        let mut writable = !listening && self.inflight.load(Ordering::Relaxed) * 4 <= sndbuf;
        if writable
            && self.kind != SOCK_STREAM
            && let Some(peer) = peer
            && !core::ptr::eq(Arc::as_ptr(&peer), self)
        {
            let p = peer.state.lock();
            let ours = p.peer.as_ref().is_some_and(|q| core::ptr::eq(Arc::as_ptr(q), self));
            if !ours && p.queue.len() > MAX_DGRAM_QLEN {
                writable = false;
            }
        }
        if writable {
            mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
        }
        mask
    }

    fn readable(&self) -> Result<usize> {
        let s = self.state.lock();
        if s.conn == Conn::Listening {
            return Err(Errno::EINVAL);
        }
        Ok(if self.kind == SOCK_DGRAM {
            s.queue.front().map_or(0, |p| p.data.len())
        } else {
            s.queue.iter().map(Packet::rest).sum()
        })
    }

    fn unsent(&self) -> Result<usize> {
        if self.state.lock().conn == Conn::Listening {
            return Err(Errno::EINVAL);
        }
        Ok(self.inflight.load(Ordering::Relaxed))
    }

    fn release(&self) {
        self.close(false);
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Checks the arguments of `socket` and `socketpair` for a Unix socket, and gives the type.
///
/// # Errors
///
/// Gives `EPROTONOSUPPORT` for a protocol that is not 0 or `PF_UNIX`.
pub fn check_protocol(protocol: u32) -> Result<()> {
    if protocol != 0 && protocol != AF_UNIX {
        return Err(Errno::EPROTONOSUPPORT);
    }
    Ok(())
}

#[cfg(test)]
mod tests;

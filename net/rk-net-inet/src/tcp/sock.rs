//! The TCP sockets and the glue between the state machine of `conn` and IP, as
//! net/ipv4/tcp_ipv4.c, net/ipv6/tcp_ipv6.c, af_inet.c and inet_connection_sock.c of Linux.
//! The addresses are `ip::Ip`, thus one table has the connections of both families, and an
//! `AF_INET6` socket without `IPV6_V6ONLY` takes IPv4 connections too.
//!
//! The table `ESTAB` finds the connection of a segment by its four addresses and ports. It holds
//! a strong reference, so that a connection that the program closed lives until its end, as an
//! orphan of Linux. The table `LISTEN` finds a listening socket by its port. The table `PORTS`
//! has the bound ports.
//!
//! A socket holds its own lock while it changes its connection, and it can then take the lock
//! of a table. The code never takes the lock of a socket while it holds the lock of a table, and
//! it holds no lock while it sends a segment. A received segment does not start a poll.

use super::cc::Algo;
use super::conn::{Config, Conn, DEFAULT_MSS, ProcInfo, State};
use super::seg::{self, ACK, RST, SYN, Seg};
use crate::ip::{self, Ip};
use crate::ipv4::{self, PROTO_TCP};
use crate::ipv6;
use crate::ports::{self, Binding, Ports};
use crate::sockaddr;
use crate::stack::{self, COUNTERS};
use crate::stack6::{self, Out6};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::in6::{IPV6_ADDRFORM, IPV6_TCLASS, IPV6_UNICAST_HOPS, IPV6_V6ONLY};
use rk_abi::native::inet::{IP_TOS, IP_TTL, IPPROTO_IP, IPPROTO_IPV6, IPPROTO_TCP};
use rk_abi::native::poll::{
    POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP, POLLRDNORM, POLLWRBAND, POLLWRNORM,
};
use rk_abi::native::socket::{
    SO_ACCEPTCONN, SO_BINDTODEVICE, SO_COOKIE, SO_DOMAIN, SO_ERROR, SO_KEEPALIVE, SO_LINGER,
    SO_PROTOCOL, SO_RCVBUF, SO_RCVBUFFORCE, SO_REUSEADDR, SO_SNDBUF, SO_SNDBUFFORCE, SO_TYPE,
    SOL_SOCKET,
};
use rk_abi::native::tcp::{
    TCP_CONGESTION, TCP_CORK, TCP_KEEPCNT, TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_MAXSEG, TCP_NODELAY,
    TCP_QUICKACK, TCP_SYNCNT,
};
use rk_frame::sync::SpinLock;
use rk_net::consts::{
    AF_INET, AF_INET6, MSG_DONTWAIT, MSG_ERRQUEUE, MSG_MORE, MSG_OOB, MSG_PEEK, MSG_WAITALL,
    SHUT_RD, SHUT_RDWR, SHUT_WR, SOCK_STREAM,
};
use rk_net::ns::PerNet;
use rk_net::{Message, Options, PathOps, Received, Socket, wait_for};
use rk_vfs::UserMemory;
use rk_vfs::inode::Result;
use rk_vfs::wait::{PollTable, WaitQueue};

/// The four addresses and ports of a connection: the local address and port, then the remote
/// address and port.
type Key = (Ip, u16, Ip, u16);

/// The connections, by their four addresses and ports.
static ESTAB: PerNet<SpinLock<BTreeMap<Key, Arc<Stream>>>> =
    PerNet::new(|| SpinLock::new(BTreeMap::new()));
/// The listening sockets on one port, with their local address and `IPV6_V6ONLY`.
type Listeners = Vec<(Ip, bool, Arc<Stream>)>;

/// The listening sockets, by their port.
static LISTEN: PerNet<SpinLock<BTreeMap<u16, Listeners>>> =
    PerNet::new(|| SpinLock::new(BTreeMap::new()));
/// The bound ports of the TCP sockets.
static PORTS: PerNet<SpinLock<Ports>> = PerNet::new(|| SpinLock::new(Ports::new(ports::EPHEMERAL)));
/// The part of the initial sequence numbers that changes with each connection.
static ISS: AtomicU32 = AtomicU32::new(0x1234_5678);

/// The largest backlog of `listen`, `net.core.somaxconn` of Linux.
const SOMAXCONN: u32 = 4096;
/// The smallest value of `TCP_MAXSEG`, `TCP_MIN_MSS` of Linux.
const MIN_MAXSEG: i32 = 88;
/// The length of the name of `TCP_CONGESTION`, `TCP_CA_NAME_MAX` of Linux.
const CA_NAME_MAX: usize = 16;
/// The bytes of the IPv4 header and the TCP header without options.
const HEADERS: u32 = 40;
/// The bytes of the IPv6 header and the TCP header without options.
const HEADERS6: u32 = 60;

/// A new initial sequence number, as `secure_tcp_seq` of Linux without the hash: a counter and
/// a clock of 4 microseconds.
fn iss() -> u32 {
    let clock = (stack::now_ms() as u32).wrapping_mul(250);
    ISS.fetch_add(64_000, Ordering::Relaxed).wrapping_add(clock)
}

fn int(v: i32) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

fn int_of(value: &[u8]) -> Result<i32> {
    let Some(v) = value.first_chunk::<4>() else { return Err(Errno::EINVAL) };
    Ok(i32::from_ne_bytes(*v))
}

/// The phase of the socket for `connect`, `sock->state` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Unconnected,
    Connecting,
    Connected,
}

/// The state of a listening socket.
struct Listener {
    /// The backlog of `listen`.
    backlog: usize,
    /// The open connections that wait for `accept`.
    queue: VecDeque<Arc<Stream>>,
}

struct Inner {
    /// `AF_INET` or `AF_INET6`.
    family: u32,
    local: Ip,
    port: u16,
    remote: Option<(Ip, u16)>,
    /// The interface of a link local address, from the scope ID, or 0.
    oif: u32,
    /// `IPV6_V6ONLY`.
    v6only: bool,
    /// `IPV6_UNICAST_HOPS`, or `None` for the default.
    hops: Option<u8>,
    /// `IPV6_TCLASS`.
    tclass: u8,
    /// The socket has a binding in `PORTS`.
    bound: bool,
    /// `bind` set the address, `SOCK_BINDADDR_LOCK` of Linux.
    lock_addr: bool,
    /// `bind` set the port, `SOCK_BINDPORT_LOCK` of Linux.
    lock_port: bool,
    /// The connection is in `ESTAB`.
    hashed: bool,
    /// The binding of the closed socket in TIME-WAIT allows `SO_REUSEADDR`.
    tw_reuse: bool,
    conn: Option<Conn>,
    listen: Option<Listener>,
    /// The listening socket of a connection that `accept` did not take yet.
    parent: Option<Weak<Stream>>,
    phase: Phase,
    /// No file has the socket: the program closed it, or `accept` did not take it yet.
    orphan: bool,
    options: Options,
    ttl: Option<u8>,
    tos: u8,
    nodelay: bool,
    cork: bool,
    /// The multicast groups of `MCAST_JOIN_GROUP`: the interface and the group address. A
    /// socket from `accept` does not copy them, as `inet_csk_clone_lock` of Linux.
    mc_groups: Vec<(u32, [u8; 4])>,
    quickack: bool,
    /// `TCP_MAXSEG`, or 0.
    maxseg: u32,
    keepidle: u32,
    keepintvl: u32,
    keepcnt: u32,
    syn_retries: u32,
    algo: Algo,
    shut_rd: bool,
    shut_wr: bool,
    /// The owner, the file system user ID of the creator as `sk_uid` of Linux. A connection of
    /// a listening socket has the owner of the listening socket.
    uid: u32,
    /// The state at the last `collect`, for the counters of /proc/net/snmp.
    counted: State,
}

impl Inner {
    fn new(family: u32) -> Self {
        Self {
            family,
            local: if family == AF_INET6 { ip::ANY } else { ip::V4_ANY },
            port: 0,
            remote: None,
            oif: 0,
            v6only: false,
            hops: None,
            tclass: 0,
            bound: false,
            lock_addr: false,
            lock_port: false,
            hashed: false,
            tw_reuse: false,
            conn: None,
            listen: None,
            parent: None,
            phase: Phase::Unconnected,
            orphan: false,
            options: Options::default(),
            ttl: None,
            tos: 0,
            nodelay: false,
            cork: false,
            mc_groups: Vec::new(),
            quickack: false,
            maxseg: 0,
            keepidle: super::conn::KEEPIDLE,
            keepintvl: super::conn::KEEPINTVL,
            keepcnt: super::conn::KEEPCNT,
            syn_retries: super::conn::SYN_RETRIES,
            algo: Algo::Cubic,
            shut_rd: false,
            shut_wr: false,
            uid: rk_vfs::cred::current().fsuid,
            counted: State::Closed,
        }
    }

    fn reuse(&self) -> bool {
        self.options.get(SO_REUSEADDR).is_ok_and(|v| v != int(0))
    }

    fn keepalive(&self) -> bool {
        self.options.get(SO_KEEPALIVE).is_ok_and(|v| v != int(0))
    }

    fn ttl(&self) -> u8 {
        self.ttl.unwrap_or(ipv4::DEFAULT_TTL)
    }

    /// The wildcard address of the family of the socket.
    fn any(&self) -> Ip {
        if self.family == AF_INET6 { ip::ANY } else { ip::V4_ANY }
    }

    /// The time to live or the hop limit, and the type of service or the traffic class, of a
    /// packet of the connection: an IPv4 connection uses the options of IPv4.
    fn ip_options(&self) -> (u8, u8) {
        match self.remote {
            Some((a, _)) if ip::v4(&a).is_none() => {
                (self.hops.unwrap_or(ipv6::DEFAULT_HOPS), self.tclass)
            }
            _ => (self.ttl(), self.tos),
        }
    }

    /// The parameters of a new connection to `dst`.
    fn config(&self, dst: &Ip) -> Config {
        let headers = if ip::v4(dst).is_some() { HEADERS } else { HEADERS6 };
        // The largest segment fits in the MTU of the route, as `tcp_mtu_to_mss` of Linux.
        let mtu = stack6::path(dst, self.oif)
            .ok()
            .map(|p| p.mtu)
            .filter(|&m| m != 0)
            .unwrap_or(DEFAULT_MSS + headers);
        // A packet has at most 65535 bytes, also on the loopback device with its MTU of 65536.
        let mut mss = mtu.min(ipv4::MAX_LEN as u32).saturating_sub(headers);
        if self.maxseg != 0 {
            mss = mss.min(self.maxseg);
        }
        Config {
            iss: iss(),
            mss,
            rcvbuf: self.options.rcvbuf as usize,
            sndbuf: self.options.sndbuf as usize,
            algo: self.algo,
        }
    }

    /// Gives the options of the socket to the connection.
    fn tune(&mut self, now: u64) {
        let keepalive = self.keepalive();
        let (sndbuf, rcvbuf) = (self.options.sndbuf as usize, self.options.rcvbuf as usize);
        let Some(c) = self.conn.as_mut() else { return };
        c.nodelay = self.nodelay;
        c.cork = self.cork;
        c.keepidle = self.keepidle;
        c.keepintvl = self.keepintvl;
        c.keepcnt = self.keepcnt;
        c.syn_retries = self.syn_retries;
        c.set_buffers(sndbuf, rcvbuf);
        c.set_algo(self.algo);
        if keepalive {
            c.set_keepalive(true, now);
        }
    }

    /// The state of the connection. A socket without one is closed.
    fn state(&self) -> State {
        self.conn.as_ref().map_or(State::Closed, Conn::state)
    }

    fn opening(&self) -> bool {
        matches!(self.state(), State::SynSent | State::SynRcvd)
    }

    /// The side of the peer ended: `RCV_SHUTDOWN` of Linux.
    fn rcv_shut(&self) -> bool {
        self.shut_rd
            || self.conn.as_ref().is_some_and(|c| c.fin_rcvd() || c.state() == State::Closed)
    }

    /// The side of the program ended: `SEND_SHUTDOWN` of Linux.
    fn snd_shut(&self) -> bool {
        self.shut_wr
            || self.conn.as_ref().is_some_and(|c| c.fin_queued() || c.state() == State::Closed)
    }

    fn key(&self) -> Key {
        let (a, p) = self.remote.unwrap_or((self.any(), 0));
        (self.local, self.port, a, p)
    }
}

/// The work that a change of a socket leaves for the time after its lock: the segments to send
/// and the changes of the tables.
struct Tx {
    segs: Vec<Seg>,
    key: Key,
    /// The interface of a link local peer, or 0.
    oif: u32,
    ttl: u8,
    tos: u8,
    /// Remove the connection from `ESTAB`.
    unhash: bool,
    /// Remove the binding from `PORTS`.
    unbind: bool,
    /// Let other sockets with `SO_REUSEADDR` have the port.
    reuse: bool,
}

/// Counts a change of the state of a connection, as `tcp_set_state`, `tcp_done` and
/// `tcp_connect` of Linux.
fn count_change(before: State, after: State) {
    if before == after {
        return;
    }
    let k = &COUNTERS;
    match (before, after) {
        (State::Closed, State::SynSent) => add(&k.tcp_active_opens, 1),
        (State::SynRcvd, a) if a != State::Closed => add(&k.tcp_passive_opens, 1),
        (State::SynSent | State::SynRcvd, State::Closed) => add(&k.tcp_attempt_fails, 1),
        (State::Established | State::CloseWait, State::Closed) => add(&k.tcp_estab_resets, 1),
        _ => {}
    }
}

fn add(c: &AtomicU64, n: u64) {
    c.fetch_add(n, Ordering::Relaxed);
}

/// Sends the segment `seg` of the connection `key` on the interface `oif` or on the route.
fn transmit(key: &Key, oif: u32, ttl: u8, tos: u8, seg: &Seg) {
    add(&COUNTERS.tcp_out_segs, 1);
    if seg.has(RST) {
        add(&COUNTERS.tcp_out_rsts, 1);
    }
    let &(src, sport, dst, dport) = key;
    let bytes = seg.encode(sport, dport, &src, &dst);
    let out = Out6 { src, dst, next: PROTO_TCP, hops: ttl, tclass: tos };
    // A lost segment is like a segment that the network lost: the timers send it again.
    let _ = stack6::output_ip(&out, oif, &bytes);
}

/// The listening socket for a segment to `dst` and `port`. A socket with the address `dst`
/// wins over a wildcard socket, and an IPv4 wildcard wins over `::`, as `compute_score`.
fn listener(port: u16, dst: &Ip) -> Option<Arc<Stream>> {
    let table = LISTEN.lock();
    let list = table.get(&port)?;
    list.iter()
        .find(|(a, _, _)| a == dst)
        .or_else(|| list.iter().find(|(a, _, _)| *a == ip::V4_ANY && ip::v4(dst).is_some()))
        .or_else(|| list.iter().find(|(a, v6only, _)| ip::takes(a, *v6only, dst)))
        .map(|(_, _, s)| s.clone())
}

/// Takes a TCP segment, as `tcp_v4_rcv` and `tcp_v6_rcv` of Linux. `tcp` has the header and
/// the data. An IPv4 packet has IPv4-mapped addresses.
pub(crate) fn input(src: Ip, dst: Ip, tcp: &[u8], broadcast: bool) {
    if broadcast {
        return;
    }
    let Some((sport, dport, seg)) = seg::parse(tcp, &src, &dst) else {
        // A segment shorter than its header goes without a count, as `tcp_v4_rcv` of Linux.
        if tcp.len() >= seg::HLEN {
            add(&COUNTERS.tcp_in_errs, 1);
            if !seg::checksum_ok(tcp, &src, &dst) {
                add(&COUNTERS.tcp_in_csum_errors, 1);
            }
        }
        return;
    };
    add(&COUNTERS.tcp_in_segs, 1);
    let key = (dst, dport, src, sport);
    let found = ESTAB.lock().get(&key).cloned();
    if let Some(sock) = found {
        sock.segment(seg);
        return;
    }
    if let Some(l) = listener(dport, &dst)
        && l.syn(&key, &seg)
    {
        return;
    }
    // No socket: an RST, as `tcp_v4_send_reset`.
    if let Some(rst) = super::conn::reset_for(&seg) {
        transmit(&key, 0, ipv4::DEFAULT_TTL, 0, &rst);
    }
}

/// Runs the timers of the connections. The poll of the stack calls this.
pub(crate) fn tick() {
    let now = stack::now_ms();
    let all: Vec<Arc<Stream>> = {
        let table = ESTAB.lock();
        if table.is_empty() {
            return;
        }
        table.values().cloned().collect()
    };
    for sock in all {
        let tx = {
            let mut s = sock.state.lock();
            let Some(c) = s.conn.as_mut() else { continue };
            if !c.next_timer().is_some_and(|t| t <= now) {
                continue;
            }
            c.tick(now);
            sock.collect(&mut s)
        };
        sock.flush(tx);
    }
}

/// The state numbers of Linux in include/net/tcp_states.h, which is not in the uAPI.
fn linux_state(state: State) -> u8 {
    match state {
        State::Established => 1,
        State::SynSent => 2,
        State::SynRcvd => 3,
        State::FinWait1 => 4,
        State::FinWait2 => 5,
        State::TimeWait => 6,
        State::Closed => 7,
        State::CloseWait => 8,
        State::LastAck => 9,
        State::Closing => 11,
    }
}

/// `TCP_LISTEN` of include/net/tcp_states.h.
pub(crate) const LISTEN_STATE: u8 = 10;

/// A socket of /proc/net/tcp.
pub(crate) struct ProcLine {
    /// The family of the socket.
    pub family: u32,
    /// The local address and port.
    pub local: (Ip, u16),
    /// The remote address and port, or the wildcard and 0.
    pub remote: (Ip, u16),
    /// The state number of Linux.
    pub state: u8,
    /// The owner.
    pub uid: u32,
    /// The inode number of the socket.
    pub ino: u64,
    /// The connections that wait for `accept`, for a listening socket.
    pub accept_queue: u32,
    /// The values of the connection. A listening socket has none.
    pub info: Option<ProcInfo>,
}

/// The sockets of /proc/net/tcp: the listening sockets, then the connections, as the order of
/// `tcp_seq_next` in Linux. A socket that is only bound is not there.
pub(crate) fn proc_lines() -> Vec<ProcLine> {
    let now = stack::now_ms();
    let listening: Vec<Arc<Stream>> =
        LISTEN.lock().values().flatten().map(|(_, _, s)| s.clone()).collect();
    let conns: Vec<Arc<Stream>> = ESTAB.lock().values().cloned().collect();
    let mut out = Vec::new();
    for sock in listening.iter().chain(&conns) {
        let s = sock.state.lock();
        let (state, info) = match (&s.listen, &s.conn) {
            (Some(_), _) => (LISTEN_STATE, None),
            (None, Some(c)) if c.state() != State::Closed => {
                (linux_state(c.state()), Some(c.proc_info(now)))
            }
            _ => continue,
        };
        out.push(ProcLine {
            family: s.family,
            local: (s.local, s.port),
            remote: s.remote.unwrap_or((s.any(), 0)),
            state,
            uid: s.uid,
            ino: sock.ino,
            accept_queue: s.listen.as_ref().map_or(0, |l| l.queue.len() as u32),
            info,
        });
    }
    out
}

/// The connections in the state ESTABLISHED or CLOSE-WAIT, for `CurrEstab` of /proc/net/snmp.
pub(crate) fn curr_estab() -> u64 {
    let conns: Vec<Arc<Stream>> = ESTAB.lock().values().cloned().collect();
    conns
        .iter()
        .filter(|c| matches!(c.state.lock().state(), State::Established | State::CloseWait))
        .count() as u64
}

/// A TCP socket.
pub struct Stream {
    /// `AF_INET` or `AF_INET6`. `IPV6_ADDRFORM` changes an `AF_INET6` socket to `AF_INET`.
    family: AtomicU32,
    ino: u64,
    me: Weak<Stream>,
    state: SpinLock<Inner>,
    wait: Arc<WaitQueue>,
    events: AtomicU64,
}

impl Stream {
    /// Makes a socket.
    pub fn new() -> Arc<Self> {
        Self::with(Inner::new(AF_INET))
    }

    /// Makes an `AF_INET6` socket.
    pub fn new6() -> Arc<Self> {
        Self::with(Inner::new(AF_INET6))
    }

    fn with(inner: Inner) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            family: AtomicU32::new(inner.family),
            ino: rk_net::next_ino(),
            me: me.clone(),
            state: SpinLock::new(inner),
            wait: Arc::new(WaitQueue::new()),
            events: AtomicU64::new(0),
        })
    }

    /// The family of the socket.
    fn af(&self) -> u32 {
        self.family.load(Ordering::Relaxed)
    }

    fn wake(&self) {
        self.events.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
    }

    /// Takes the work of a change of the connection. The caller holds the lock.
    fn collect(&self, s: &mut Inner) -> Tx {
        let segs = s.conn.as_mut().map(Conn::take_output).unwrap_or_default();
        let state = s.state();
        let retransmits = s.conn.as_mut().map_or(0, Conn::take_retransmits);
        add(&COUNTERS.tcp_retrans_segs, u64::from(retransmits));
        count_change(s.counted, state);
        s.counted = state;
        let unhash = state == State::Closed && s.hashed;
        if unhash {
            s.hashed = false;
        }
        let unbind = s.orphan && !s.hashed && s.bound && s.listen.is_none();
        if unbind {
            s.bound = false;
        }
        let reuse = s.orphan && s.bound && !s.tw_reuse && state == State::TimeWait;
        if reuse {
            s.tw_reuse = true;
        }
        let (ttl, tos) = s.ip_options();
        Tx { segs, key: s.key(), oif: s.oif, ttl, tos, unhash, unbind, reuse }
    }

    /// Does the work of `collect` without the lock, and wakes the waiters.
    fn flush(&self, tx: Tx) {
        let port = tx.key.1;
        if tx.reuse {
            PORTS.lock().set_reuse(port, self.ino, true);
        }
        for seg in &tx.segs {
            transmit(&tx.key, tx.oif, tx.ttl, tx.tos, seg);
        }
        if tx.unhash {
            let removed = {
                let mut table = ESTAB.lock();
                if table.get(&tx.key).is_some_and(|s| s.ino == self.ino) {
                    table.remove(&tx.key)
                } else {
                    None
                }
            };
            drop(removed);
        }
        if tx.unbind {
            PORTS.lock().unbind(port, self.ino);
        }
        self.wake();
    }

    /// Takes a segment of the connection.
    fn segment(&self, seg: Seg) {
        let now = stack::now_ms();
        let (tx, parent) = {
            let mut s = self.state.lock();
            let Some(c) = s.conn.as_mut() else { return };
            let before = c.state();
            c.input(seg, now);
            let after = c.state();
            let open = before == State::SynRcvd && after != State::SynRcvd;
            let parent = if open { s.parent.take() } else { None };
            (self.collect(&mut s), parent.map(|p| (p, after == State::Closed)))
        };
        self.flush(tx);
        // The handshake of a passive connection ended: the connection goes to the queue of
        // `accept`, as `tcp_child_process` of Linux.
        if let Some((parent, closed)) = parent
            && !closed
        {
            let me = self.me.upgrade();
            let queued = match (parent.upgrade(), me) {
                (Some(p), Some(me)) => p.enqueue(me),
                _ => false,
            };
            if !queued {
                self.abort_orphan();
            }
        }
    }

    /// Puts an open connection in the queue of `accept`. Gives `false` if the socket does not
    /// listen.
    fn enqueue(&self, child: Arc<Stream>) -> bool {
        {
            let mut s = self.state.lock();
            if s.orphan {
                return false;
            }
            let Some(l) = s.listen.as_mut() else { return false };
            l.queue.push_back(child);
        }
        self.wake();
        true
    }

    /// Ends a connection that no file has, and sends an RST.
    fn abort_orphan(&self) {
        let tx = {
            let mut s = self.state.lock();
            s.orphan = true;
            if let Some(c) = s.conn.as_mut() {
                c.abort();
            }
            self.collect(&mut s)
        };
        self.flush(tx);
    }

    /// Takes a SYN on a listening socket, as `tcp_conn_request` of Linux. Gives `false` if the
    /// segment needs an RST.
    fn syn(&self, key: &Key, seg: &Seg) -> bool {
        if seg.has(RST) {
            return true;
        }
        if seg.has(ACK) {
            return false;
        }
        if !seg.has(SYN) {
            return true;
        }
        let now = stack::now_ms();
        let &(local, port, remote, rport) = key;
        let (child, reuse, v6only) = {
            let s = self.state.lock();
            let Some(l) = &s.listen else { return false };
            // A full queue drops the SYN, and the peer sends it again, as
            // `sk_acceptq_is_full`.
            if s.orphan || l.queue.len() > l.backlog {
                return true;
            }
            let mut c = Inner::new(s.family);
            c.v6only = s.v6only;
            c.hops = s.hops;
            c.tclass = s.tclass;
            c.oif = s.oif;
            c.local = local;
            c.port = port;
            c.remote = Some((remote, rport));
            c.bound = true;
            c.lock_addr = s.lock_addr;
            c.lock_port = s.lock_port;
            c.hashed = true;
            c.parent = Some(self.me.clone());
            c.phase = Phase::Connected;
            c.orphan = true;
            c.options.sndbuf = s.options.sndbuf;
            c.options.rcvbuf = s.options.rcvbuf;
            if s.keepalive() {
                let _ = c.options.set(SO_KEEPALIVE, &int(1));
            }
            c.ttl = s.ttl;
            c.tos = s.tos;
            c.nodelay = s.nodelay;
            c.maxseg = s.maxseg;
            c.keepidle = s.keepidle;
            c.keepintvl = s.keepintvl;
            c.keepcnt = s.keepcnt;
            c.syn_retries = s.syn_retries;
            c.algo = s.algo;
            c.uid = s.uid;
            c.conn = Some(Conn::accept(&c.config(&remote), seg, now));
            c.tune(now);
            (Stream::with(c), s.reuse(), s.v6only)
        };
        {
            let mut table = ESTAB.lock();
            if table.contains_key(key) {
                return true;
            }
            table.insert(*key, child.clone());
        }
        PORTS.lock().add(port, Binding { addr: local, reuse, id: child.ino, v6only });
        let tx = child.collect(&mut child.state.lock());
        child.flush(tx);
        true
    }

    /// Gives the socket a port if it has none, as `inet_autobind` of Linux.
    fn autobind(&self, s: &mut Inner) -> Result<()> {
        if s.port == 0 {
            let b = Binding { addr: s.local, reuse: s.reuse(), id: self.ino, v6only: s.v6only };
            s.port = PORTS.lock().bind(0, b)?;
            s.bound = true;
        }
        Ok(())
    }

    /// Stops the listening of the socket. Gives the connections of the queue, which the caller
    /// ends without the lock.
    fn stop_listen(&self, s: &mut Inner) -> Vec<Arc<Stream>> {
        let Some(l) = s.listen.take() else { return Vec::new() };
        {
            let mut table = LISTEN.lock();
            if let Some(list) = table.get_mut(&s.port) {
                list.retain(|(_, _, sock)| sock.ino != self.ino);
                if list.is_empty() {
                    table.remove(&s.port);
                }
            }
        }
        PORTS.lock().set_reuse(s.port, self.ino, s.reuse());
        l.queue.into_iter().collect()
    }

    /// Waits for the end of the handshake, as `inet_wait_for_connect` of Linux. `first` tells
    /// if this call started the connection.
    fn connect_wait(&self, nonblock: bool, first: bool) -> Result<()> {
        let (opening, timeout) = {
            let s = self.state.lock();
            (s.opening(), s.options.sndtimeo)
        };
        if opening {
            let pending = if first { Errno::EINPROGRESS } else { Errno::EALREADY };
            if nonblock {
                return Err(pending);
            }
            let r =
                wait_for(&self.wait, timeout, || Ok((!self.state.lock().opening()).then_some(())));
            match r {
                Ok(()) => {}
                Err(Errno::EAGAIN) => return Err(pending),
                Err(e) => return Err(e),
            }
        }
        let mut s = self.state.lock();
        if s.state() == State::Closed {
            s.phase = Phase::Unconnected;
            let err = s.conn.as_mut().and_then(Conn::take_error);
            return Err(err.unwrap_or(Errno::ECONNABORTED));
        }
        s.phase = Phase::Connected;
        Ok(())
    }

    /// Ends the connection for `connect` with `AF_UNSPEC`, as `tcp_disconnect` of Linux.
    fn disconnect(&self) {
        let (tx, children) = {
            let mut s = self.state.lock();
            let children = self.stop_listen(&mut s);
            if let Some(c) = s.conn.as_mut() {
                c.abort();
            }
            let tx = self.collect(&mut s);
            s.conn = None;
            s.remote = None;
            s.phase = Phase::Unconnected;
            // The socket keeps only the address and the port that `bind` set, as
            // `tcp_disconnect` and `tcp_set_state` of Linux.
            if !s.lock_addr {
                s.local = s.any();
            }
            if !s.lock_port && s.bound {
                PORTS.lock().unbind(s.port, self.ino);
                s.bound = false;
                s.port = 0;
            }
            s.shut_rd = false;
            s.shut_wr = false;
            (tx, children)
        };
        self.flush(tx);
        for c in children {
            c.abort_orphan();
        }
    }

    /// One step of `send`: gives the bytes that the send queue took.
    fn send_step(s: &mut Inner, data: &[u8], now: u64) -> Result<usize> {
        let shut = s.shut_wr;
        let Some(c) = s.conn.as_mut() else { return Err(Errno::EPIPE) };
        if let Some(e) = c.take_error() {
            return Err(e);
        }
        if shut {
            return Err(Errno::EPIPE);
        }
        match c.state() {
            State::SynSent | State::SynRcvd => Ok(0),
            _ if !c.can_send() => Err(Errno::EPIPE),
            _ => Ok(c.send(data, now)),
        }
    }

    /// Tells if a blocked `send` can go on.
    fn send_ready(s: &Inner) -> bool {
        let Some(c) = &s.conn else { return true };
        c.error().is_some()
            || s.shut_wr
            || (!s.opening() && (!c.can_send() || c.queued() < c.sndbuf()))
    }

    /// One step of `recv`, as the loop of `tcp_recvmsg` of Linux. `first` tells that the call
    /// has no data yet.
    fn recv_step(s: &mut Inner, want: usize, peek: bool, now: u64, first: bool) -> Step {
        if s.listen.is_some() {
            return Step::Err(Errno::ENOTCONN);
        }
        let shut = s.shut_rd;
        let Some(c) = s.conn.as_mut() else {
            return if shut { Step::Eof } else { Step::Err(Errno::ENOTCONN) };
        };
        if c.readable() > 0 {
            return Step::Data(c.recv(want, peek, now));
        }
        if c.fin_rcvd() {
            return Step::Eof;
        }
        if c.error().is_some() {
            // An error after some data ends the call, and the next call gives the error.
            return match first {
                true => Step::Err(c.take_error().unwrap_or(Errno::ECONNRESET)),
                false => Step::Eof,
            };
        }
        if shut || c.state() == State::Closed {
            return Step::Eof;
        }
        Step::Empty
    }

    fn recv_ready(s: &Inner) -> bool {
        let Some(c) = &s.conn else { return true };
        s.listen.is_some() || c.readable() > 0 || c.error().is_some() || s.rcv_shut()
    }
}

/// The result of one step of `recv`.
enum Step {
    Data(Vec<u8>),
    Eof,
    Empty,
    Err(Errno),
}

fn received(data: Vec<u8>) -> Received {
    Received { len: data.len(), data, ..Received::default() }
}

impl Socket for Stream {
    fn family(&self) -> u32 {
        self.af()
    }

    fn kind(&self) -> u32 {
        SOCK_STREAM
    }

    fn protocol(&self) -> u32 {
        IPPROTO_TCP
    }

    fn ino(&self) -> u64 {
        self.ino
    }

    fn bind(&self, _paths: &dyn PathOps, addr: &[u8]) -> Result<()> {
        let (addr, port, scope) = sockaddr::parse_bind_in(self.af(), addr)?;
        let mut s = self.state.lock();
        let mut v6only = s.v6only;
        let mut oif = s.oif;
        match ip::v4(&addr) {
            Some(_) if self.af() == AF_INET6 && s.v6only => return Err(Errno::EINVAL),
            Some(a4) => {
                if a4 != ipv4::ANY && !stack::ROUTES.lock().is_local(a4) {
                    return Err(Errno::EADDRNOTAVAIL);
                }
            }
            None if addr == ip::ANY => {}
            None => {
                if ipv6::needs_scope(&addr) {
                    if scope != 0 {
                        oif = scope;
                    }
                    if oif == 0 {
                        return Err(Errno::EINVAL);
                    }
                }
                let ok = stack6::ROUTES6
                    .lock()
                    .addrs()
                    .iter()
                    .any(|a| a.addr == addr && (!ipv6::needs_scope(&addr) || a.ifindex == oif));
                if !ok {
                    return Err(Errno::EADDRNOTAVAIL);
                }
                // A socket on an IPv6 address takes no IPv4 connections, as `__inet6_bind`.
                v6only = true;
            }
        }
        if s.port != 0 || s.state() != State::Closed {
            return Err(Errno::EINVAL);
        }
        let b = Binding { addr, reuse: s.reuse(), id: self.ino, v6only };
        s.port = PORTS.lock().bind(port, b)?;
        s.bound = true;
        s.lock_addr = !ip::is_any(&addr);
        s.lock_port = port != 0;
        s.local = addr;
        s.v6only = v6only;
        s.oif = oif;
        Ok(())
    }

    fn connect(&self, _paths: &dyn PathOps, addr: &[u8], nonblock: bool) -> Result<()> {
        // An IPv6 socket connects only to `AF_INET6` addresses, as `tcp_v6_connect`.
        if self.af() == AF_INET6
            && addr.first_chunk::<2>().is_some_and(|f| u32::from(u16::from_ne_bytes(*f)) == AF_INET)
        {
            return Err(if addr.len() < sockaddr::RFC2133 {
                Errno::EINVAL
            } else {
                Errno::EAFNOSUPPORT
            });
        }
        let Some((dst, dport, scope)) = sockaddr::parse_connect_in(self.af(), addr)? else {
            self.disconnect();
            return Ok(());
        };
        // A destination of 0.0.0.0 or `::` is the local host, as Linux.
        let dst = match ip::v4(&dst) {
            Some(ipv4::ANY) => ip::mapped(ipv4::LOOPBACK),
            None if dst == ip::ANY => ip::LOOPBACK,
            _ => dst,
        };
        let now = stack::now_ms();
        let tx = {
            let mut s = self.state.lock();
            match s.phase {
                Phase::Connected => return Err(Errno::EISCONN),
                Phase::Connecting => {
                    drop(s);
                    return self.connect_wait(nonblock, false);
                }
                Phase::Unconnected => {}
            }
            if s.listen.is_some() || s.state() != State::Closed {
                return Err(Errno::EISCONN);
            }
            let mapped = ip::v4(&dst).is_some();
            // An IPv6 socket reaches an IPv4 peer only as a dual stack socket.
            let local6 = ip::v4(&s.local).is_none() && s.local != ip::ANY;
            if mapped && (s.v6only || local6) {
                return Err(Errno::ENETUNREACH);
            }
            if !mapped && ip::v4(&s.local).is_some() {
                return Err(Errno::ENETUNREACH);
            }
            if ipv6::needs_scope(&dst) && scope != 0 {
                s.oif = scope;
            }
            let next = stack6::path(&dst, s.oif)?;
            if ip::is_any(&s.local) {
                s.local = next.src;
                if s.bound {
                    PORTS.lock().set_addr(s.port, self.ino, next.src);
                }
            }
            self.autobind(&mut s)?;
            let key = (s.local, s.port, dst, dport);
            {
                let Some(me) = self.me.upgrade() else { return Err(Errno::EBADF) };
                let mut table = ESTAB.lock();
                if table.contains_key(&key) {
                    return Err(Errno::EADDRNOTAVAIL);
                }
                table.insert(key, me);
            }
            s.hashed = true;
            s.remote = Some((dst, dport));
            s.shut_rd = false;
            s.shut_wr = false;
            s.conn = Some(Conn::new(&s.config(&dst)));
            s.tune(now);
            if let Some(c) = s.conn.as_mut() {
                c.connect(now);
            }
            s.phase = Phase::Connecting;
            self.collect(&mut s)
        };
        self.flush(tx);
        stack::poll_now();
        // A connect without a wait gives `EINPROGRESS` also when the handshake on the loopback
        // device is over, as Linux, which takes the SYN-ACK after the call.
        if nonblock {
            return Err(Errno::EINPROGRESS);
        }
        self.connect_wait(false, true)
    }

    fn listen(&self, backlog: u32) -> Result<()> {
        let backlog = backlog.min(SOMAXCONN) as usize;
        let mut s = self.state.lock();
        if let Some(l) = s.listen.as_mut() {
            l.backlog = backlog;
            return Ok(());
        }
        if s.phase != Phase::Unconnected || s.state() != State::Closed {
            return Err(Errno::EINVAL);
        }
        if s.port == 0 {
            self.autobind(&mut s)?;
        } else {
            let b = Binding { addr: s.local, reuse: s.reuse(), id: self.ino, v6only: s.v6only };
            if !PORTS.lock().is_free(s.port, &b) {
                return Err(Errno::EADDRINUSE);
            }
        }
        // No other socket can bind the port of a listening socket, as `inet_bind_conflict`.
        PORTS.lock().set_reuse(s.port, self.ino, false);
        s.conn = None;
        s.listen = Some(Listener { backlog, queue: VecDeque::new() });
        let Some(me) = self.me.upgrade() else { return Err(Errno::EBADF) };
        LISTEN.lock().entry(s.port).or_default().push((s.local, s.v6only, me));
        Ok(())
    }

    fn accept(&self, nonblock: bool) -> Result<Arc<dyn Socket>> {
        stack::poll();
        let timeout = self.state.lock().options.rcvtimeo;
        let child = wait_for(&self.wait, timeout, || {
            let mut s = self.state.lock();
            let Some(l) = s.listen.as_mut() else { return Err(Errno::EINVAL) };
            if let Some(c) = l.queue.pop_front() {
                return Ok(Some(c));
            }
            if nonblock { Err(Errno::EAGAIN) } else { Ok(None) }
        })?;
        let tx = {
            let mut s = child.state.lock();
            s.orphan = false;
            child.collect(&mut s)
        };
        child.flush(tx);
        Ok(child)
    }

    fn send(
        &self,
        _paths: &dyn PathOps,
        msg: Message,
        flags: u32,
        nonblock: bool,
    ) -> Result<usize> {
        if flags & MSG_OOB != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let nonblock = nonblock || flags & MSG_DONTWAIT != 0;
        let data = msg.data;
        let timeout = self.state.lock().options.sndtimeo;
        let mut done = 0;
        loop {
            let now = stack::now_ms();
            let (tx, r) = {
                let mut s = self.state.lock();
                // `MSG_MORE` corks the connection for this send, as `tcp_push` of Linux with
                // `TCP_NAGLE_CORK`. The next send without it sends the data that waits.
                let cork = s.cork || flags & MSG_MORE != 0;
                if let Some(c) = s.conn.as_mut() {
                    c.cork = cork;
                }
                let r = Self::send_step(&mut s, &data[done..], now);
                (self.collect(&mut s), r)
            };
            self.flush(tx);
            // The segments on the loopback device arrive now, as the softirq of Linux.
            stack::poll_now();
            match r {
                Ok(n) => done += n,
                Err(e) if done == 0 => return Err(e),
                Err(_) => return Ok(done),
            }
            if done == data.len() {
                return Ok(done);
            }
            if nonblock {
                return if done > 0 { Ok(done) } else { Err(Errno::EAGAIN) };
            }
            let r = wait_for(&self.wait, timeout, || {
                Ok(Self::send_ready(&self.state.lock()).then_some(()))
            });
            if let Err(e) = r {
                return if done > 0 { Ok(done) } else { Err(e) };
            }
        }
    }

    fn recv(&self, len: usize, flags: u32, nonblock: bool) -> Result<Received> {
        if flags & MSG_OOB != 0 {
            return Err(Errno::EINVAL);
        }
        if flags & MSG_ERRQUEUE != 0 {
            return Err(Errno::EAGAIN);
        }
        if len == 0 {
            return Ok(Received::default());
        }
        stack::poll();
        let nonblock = nonblock || flags & MSG_DONTWAIT != 0;
        let peek = flags & MSG_PEEK != 0;
        let target = if flags & MSG_WAITALL != 0 && !peek { len } else { 1 };
        let timeout = self.state.lock().options.rcvtimeo;
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let now = stack::now_ms();
            let (tx, step) = {
                let mut s = self.state.lock();
                let step = Self::recv_step(&mut s, len - buf.len(), peek, now, buf.is_empty());
                (self.collect(&mut s), step)
            };
            let update = !tx.segs.is_empty();
            self.flush(tx);
            if update {
                stack::poll_now();
            }
            match step {
                Step::Data(d) => {
                    buf.extend_from_slice(&d);
                    if peek || buf.len() >= target {
                        return Ok(received(buf));
                    }
                    continue;
                }
                Step::Eof => return Ok(received(buf)),
                Step::Err(e) if buf.is_empty() => return Err(e),
                Step::Err(_) => return Ok(received(buf)),
                Step::Empty if nonblock => {
                    return if buf.is_empty() { Err(Errno::EAGAIN) } else { Ok(received(buf)) };
                }
                Step::Empty => {}
            }
            let r = wait_for(&self.wait, timeout, || {
                Ok(Self::recv_ready(&self.state.lock()).then_some(()))
            });
            if let Err(e) = r {
                return if buf.is_empty() { Err(e) } else { Ok(received(buf)) };
            }
        }
    }

    fn shutdown(&self, how: u32) -> Result<()> {
        if how > SHUT_RDWR {
            return Err(Errno::EINVAL);
        }
        let rd = how == SHUT_RD || how == SHUT_RDWR;
        let wr = how == SHUT_WR || how == SHUT_RDWR;
        let now = stack::now_ms();
        let (tx, children, r) = {
            let mut s = self.state.lock();
            if s.listen.is_some() {
                // `SHUT_RD` stops a listening socket, as `inet_shutdown` of Linux.
                let children = if rd { self.stop_listen(&mut s) } else { Vec::new() };
                (self.collect(&mut s), children, Ok(()))
            } else {
                s.shut_rd |= rd;
                s.shut_wr |= wr;
                let r = match s.conn.as_mut() {
                    None => Err(Errno::ENOTCONN),
                    Some(c) if c.state() == State::Closed => Err(Errno::ENOTCONN),
                    Some(c) if c.state() == State::SynSent => {
                        c.close(now);
                        s.phase = Phase::Unconnected;
                        Ok(())
                    }
                    Some(c) => {
                        if wr {
                            c.close(now);
                        }
                        Ok(())
                    }
                };
                (self.collect(&mut s), Vec::new(), r)
            }
        };
        self.flush(tx);
        for c in children {
            c.abort_orphan();
        }
        stack::poll_now();
        r
    }

    fn name(&self) -> Vec<u8> {
        let s = self.state.lock();
        let scope = stack6::scope_of(&s.local, s.oif);
        sockaddr::make_in(self.af(), &s.local, s.port, scope)
    }

    fn peer_name(&self) -> Result<Vec<u8>> {
        let s = self.state.lock();
        if s.conn.is_none() || matches!(s.state(), State::Closed | State::SynSent) {
            return Err(Errno::ENOTCONN);
        }
        let (a, p) = s.remote.ok_or(Errno::ENOTCONN)?;
        Ok(sockaddr::make_in(self.af(), &a, p, stack6::scope_of(&a, s.oif)))
    }

    fn get_option(&self, level: u32, name: u32) -> Result<Vec<u8>> {
        let mut s = self.state.lock();
        match level {
            SOL_SOCKET => Ok(match name {
                SO_TYPE => int(SOCK_STREAM as i32),
                SO_DOMAIN => int(self.af() as i32),
                SO_PROTOCOL => int(IPPROTO_TCP as i32),
                SO_ERROR => {
                    let e = s.conn.as_mut().and_then(Conn::take_error);
                    int(e.map_or(0, |e| i32::from(e.get())))
                }
                SO_ACCEPTCONN => int(i32::from(s.listen.is_some())),
                SO_COOKIE => self.ino.to_ne_bytes().to_vec(),
                SO_BINDTODEVICE => Vec::new(),
                _ => s.options.get(name)?,
            }),
            IPPROTO_IP => Ok(match name {
                IP_TTL => int(i32::from(s.ttl())),
                IP_TOS => int(i32::from(s.tos)),
                _ => return Err(Errno::ENOPROTOOPT),
            }),
            IPPROTO_IPV6 if self.af() == AF_INET6 => Ok(match name {
                IPV6_V6ONLY => int(i32::from(s.v6only)),
                IPV6_UNICAST_HOPS => int(i32::from(s.hops.unwrap_or(ipv6::DEFAULT_HOPS))),
                IPV6_TCLASS => int(i32::from(s.tclass)),
                _ => return Err(Errno::ENOPROTOOPT),
            }),
            IPPROTO_TCP => Ok(match name {
                TCP_NODELAY => int(i32::from(s.nodelay)),
                TCP_MAXSEG => {
                    let open = !matches!(s.state(), State::Closed | State::SynSent);
                    let mss = match &s.conn {
                        Some(c) if open => c.mss(),
                        _ if s.maxseg != 0 => s.maxseg,
                        _ => DEFAULT_MSS,
                    };
                    int(mss as i32)
                }
                TCP_CORK => int(i32::from(s.cork)),
                TCP_KEEPIDLE => int(s.keepidle as i32),
                TCP_KEEPINTVL => int(s.keepintvl as i32),
                TCP_KEEPCNT => int(s.keepcnt as i32),
                TCP_SYNCNT => int(s.syn_retries as i32),
                TCP_QUICKACK => int(i32::from(s.quickack)),
                TCP_CONGESTION => {
                    let mut v = s.algo.name().to_vec();
                    v.resize(CA_NAME_MAX, 0);
                    v
                }
                _ => return Err(Errno::ENOPROTOOPT),
            }),
            // An IPv4 socket gives the other levels to `ip_getsockopt` of Linux, which gives
            // `EOPNOTSUPP`. IPv6 gives `ENOPROTOOPT`.
            _ if self.af() == AF_INET6 => Err(Errno::ENOPROTOOPT),
            _ => Err(Errno::EOPNOTSUPP),
        }
    }

    fn set_option(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
        let now = stack::now_ms();
        let tx = {
            let mut s = self.state.lock();
            match level {
                SOL_SOCKET => match name {
                    SO_TYPE | SO_DOMAIN | SO_PROTOCOL | SO_ERROR | SO_ACCEPTCONN | SO_COOKIE => {
                        return Err(Errno::ENOPROTOOPT);
                    }
                    SO_BINDTODEVICE => {
                        if value.first().is_some_and(|&b| b != 0) {
                            return Err(Errno::ENODEV);
                        }
                    }
                    _ => {
                        s.options.set(name, value)?;
                        match name {
                            SO_KEEPALIVE => {
                                let on = s.keepalive();
                                if let Some(c) = s.conn.as_mut() {
                                    c.set_keepalive(on, now);
                                }
                            }
                            SO_SNDBUF | SO_RCVBUF | SO_SNDBUFFORCE | SO_RCVBUFFORCE => {
                                s.tune(now);
                            }
                            _ => {}
                        }
                    }
                },
                IPPROTO_IP if matches!(name, MCAST_JOIN_GROUP | MCAST_LEAVE_GROUP) => {
                    let (index, group) = group_req(value)?;
                    let found = s.mc_groups.iter().position(|&g| g == (index, group));
                    match (name, found) {
                        (MCAST_JOIN_GROUP, Some(_)) => return Err(Errno::EADDRINUSE),
                        (MCAST_JOIN_GROUP, None) => s.mc_groups.push((index, group)),
                        (_, Some(i)) => {
                            s.mc_groups.remove(i);
                        }
                        (_, None) => return Err(Errno::EADDRNOTAVAIL),
                    }
                }
                IPPROTO_IP => {
                    let v = int_of(value)?;
                    match name {
                        IP_TTL => {
                            s.ttl = match v {
                                -1 => None,
                                1..=255 => Some(v as u8),
                                _ => return Err(Errno::EINVAL),
                            };
                        }
                        IP_TOS => s.tos = v as u8,
                        _ => return Err(Errno::ENOPROTOOPT),
                    }
                }
                IPPROTO_IPV6 if self.af() == AF_INET6 => {
                    let v = int_of(value)?;
                    match name {
                        // A bound socket keeps its family, as `do_ipv6_setsockopt`.
                        IPV6_V6ONLY if s.port != 0 => return Err(Errno::EINVAL),
                        // A connection to an IPv4 peer becomes an `AF_INET` socket, as
                        // `do_ipv6_setsockopt` in net/ipv6/ipv6_sockglue.c of Linux.
                        IPV6_ADDRFORM if v != AF_INET as i32 => return Err(Errno::EINVAL),
                        IPV6_ADDRFORM => {
                            if s.state() != State::Established {
                                return Err(Errno::ENOTCONN);
                            }
                            if s.v6only || !s.remote.is_some_and(|(a, _)| ip::v4(&a).is_some()) {
                                return Err(Errno::EADDRNOTAVAIL);
                            }
                            s.family = AF_INET;
                            self.family.store(AF_INET, Ordering::Relaxed);
                        }
                        IPV6_V6ONLY => s.v6only = v != 0,
                        IPV6_UNICAST_HOPS => {
                            s.hops = match v {
                                -1 => None,
                                0..=255 => Some(v as u8),
                                _ => return Err(Errno::EINVAL),
                            };
                        }
                        IPV6_TCLASS => {
                            s.tclass = match v {
                                -1 => 0,
                                0..=255 => v as u8,
                                _ => return Err(Errno::EINVAL),
                            };
                        }
                        _ => return Err(Errno::ENOPROTOOPT),
                    }
                }
                IPPROTO_TCP if name == TCP_CONGESTION => {
                    s.algo = Algo::by_name(value).ok_or(Errno::ENOENT)?;
                    let algo = s.algo;
                    if let Some(c) = s.conn.as_mut() {
                        c.set_algo(algo);
                    }
                }
                IPPROTO_TCP => {
                    let v = int_of(value)?;
                    match name {
                        TCP_NODELAY => s.nodelay = v != 0,
                        TCP_CORK => s.cork = v != 0,
                        TCP_QUICKACK => s.quickack = v != 0,
                        TCP_MAXSEG if v == 0 || (MIN_MAXSEG..=0xffff).contains(&v) => {
                            s.maxseg = v as u32;
                        }
                        TCP_KEEPIDLE if (1..=32767).contains(&v) => s.keepidle = v as u32,
                        TCP_KEEPINTVL if (1..=32767).contains(&v) => s.keepintvl = v as u32,
                        TCP_KEEPCNT if (1..=127).contains(&v) => s.keepcnt = v as u32,
                        TCP_SYNCNT if (1..=127).contains(&v) => s.syn_retries = v as u32,
                        TCP_MAXSEG | TCP_KEEPIDLE | TCP_KEEPINTVL | TCP_KEEPCNT | TCP_SYNCNT => {
                            return Err(Errno::EINVAL);
                        }
                        _ => return Err(Errno::ENOPROTOOPT),
                    }
                    let (nodelay, cork) = (s.nodelay, s.cork);
                    let keep = (s.keepidle, s.keepintvl, s.keepcnt, s.syn_retries);
                    if let Some(c) = s.conn.as_mut() {
                        c.nodelay = nodelay;
                        c.cork = cork;
                        (c.keepidle, c.keepintvl, c.keepcnt, c.syn_retries) = keep;
                        // Data that waited for the end of the cork or of Nagle goes now.
                        c.flush(now);
                    }
                }
                _ => return Err(Errno::ENOPROTOOPT),
            }
            self.collect(&mut s)
        };
        self.flush(tx);
        Ok(())
    }

    fn poll_wait(&self, table: &mut PollTable) {
        table.add(&self.wait);
    }

    fn poll(&self) -> u32 {
        let s = self.state.lock();
        if let Some(l) = &s.listen {
            return if l.queue.is_empty() { 0 } else { POLLIN | POLLRDNORM };
        }
        // As `tcp_poll` of Linux.
        let mut mask = 0;
        let state = s.state();
        let (rcv, snd) = (s.rcv_shut(), s.snd_shut());
        if (rcv && snd) || state == State::Closed {
            mask |= POLLHUP;
        }
        if rcv {
            mask |= POLLIN | POLLRDNORM | POLLRDHUP;
        }
        if !s.opening() {
            if s.conn.as_ref().is_some_and(|c| c.readable() > 0) {
                mask |= POLLIN | POLLRDNORM;
            }
            let writable = s
                .conn
                .as_ref()
                .is_none_or(|c| c.sndbuf().saturating_sub(c.queued()) >= c.queued() / 2);
            if snd || writable {
                mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
            }
        }
        if s.conn.as_ref().is_some_and(|c| c.error().is_some()) {
            mask |= POLLERR;
        }
        mask
    }

    fn event_count(&self) -> u64 {
        self.events.load(Ordering::Relaxed)
    }

    fn readable(&self) -> Result<usize> {
        let s = self.state.lock();
        if s.listen.is_some() {
            return Err(Errno::EINVAL);
        }
        Ok(s.conn.as_ref().map_or(0, Conn::readable))
    }

    fn unsent(&self) -> Result<usize> {
        let s = self.state.lock();
        if s.listen.is_some() {
            return Err(Errno::EINVAL);
        }
        Ok(s.conn.as_ref().map_or(0, Conn::queued))
    }

    fn release(&self) {
        let now = stack::now_ms();
        let (tx, children) = {
            let mut s = self.state.lock();
            s.orphan = true;
            let children = self.stop_listen(&mut s);
            // `SO_LINGER` with a time of 0 ends the connection with an RST.
            let mut linger = int(1);
            linger.extend_from_slice(&0i32.to_ne_bytes());
            let abort = s.options.get(SO_LINGER).is_ok_and(|v| v == linger);
            if let Some(c) = s.conn.as_mut() {
                // Data that the program did not read also gives an RST, as `tcp_close`.
                if abort || c.readable() > 0 {
                    c.abort();
                } else {
                    c.close(now);
                    c.orphan(now);
                }
            }
            (self.collect(&mut s), children)
        };
        self.flush(tx);
        for c in children {
            c.abort_orphan();
        }
        stack::poll_now();
    }

    fn ioctl(&self, cmd: u32, arg: usize, mem: &dyn UserMemory) -> Option<Result<usize>> {
        crate::ioctl::inet_ioctl(cmd, arg, mem)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// `MCAST_JOIN_GROUP` of `<linux/in.h>`.
const MCAST_JOIN_GROUP: u32 = 42;
/// `MCAST_LEAVE_GROUP` of `<linux/in.h>`.
const MCAST_LEAVE_GROUP: u32 = 45;
/// The size of `struct group_req`: the interface, a pad and a `struct sockaddr_storage`.
const GROUP_REQ_SIZE: usize = 136;

/// Reads a `struct group_req` of an IPv4 group: the interface index and the group address, as
/// `ip_mc_join_group` of Linux. Gives `EINVAL` for a short value or an address that is not a
/// multicast IPv4 address.
fn group_req(value: &[u8]) -> Result<(u32, [u8; 4])> {
    if value.len() < GROUP_REQ_SIZE {
        return Err(Errno::EINVAL);
    }
    let index = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
    let family = u16::from_ne_bytes([value[8], value[9]]);
    if u32::from(family) != AF_INET {
        return Err(Errno::EINVAL);
    }
    let group = [value[12], value[13], value[14], value[15]];
    if group[0] & 0xf0 != 0xe0 {
        return Err(Errno::EINVAL);
    }
    Ok((index, group))
}

/// Clears the tables of TCP of a namespace that stops.
pub(crate) fn ns_exit() {
    ESTAB.reset();
    LISTEN.reset();
    PORTS.reset();
}

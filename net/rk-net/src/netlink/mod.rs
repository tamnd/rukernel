//! The netlink sockets of the family `NETLINK_ROUTE`, as net/netlink/af_netlink.c and
//! net/core/rtnetlink.c of Linux.
//!
//! A process sends requests to the kernel on a netlink socket, and the kernel sends back the
//! replies, the acks and the dumps as datagrams. The kernel also sends a copy of each change to
//! the sockets that listen to a multicast group. The families (link, IPv4) give the handlers of
//! the message types with `register`. The handler of a dump gives all of the messages at the
//! start of the dump, and the socket puts them in datagrams of the size that Linux uses. The
//! layout of each message is the layout of Linux, because spec/10 section 10.4 asks for replies
//! that are byte identical.

pub mod link;
pub mod msg;

use crate::consts::{
    AF_NETLINK, MSG_DONTWAIT, MSG_OOB, MSG_PEEK, MSG_TRUNC, SOCK_DGRAM, SOCK_RAW, SOL_NETLINK,
};
use crate::{Message, Options, PathOps, Received, Socket, current_cred, next_ino, wait_for};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::cell::Cell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use msg::{HDRLEN, Header};
use rk_abi::Errno;
use rk_abi::native::netlink::{
    NETLINK_ADD_MEMBERSHIP, NETLINK_BROADCAST_ERROR, NETLINK_CAP_ACK, NETLINK_DROP_MEMBERSHIP,
    NETLINK_EXT_ACK, NETLINK_GET_STRICT_CHK, NETLINK_LIST_MEMBERSHIPS, NETLINK_LISTEN_ALL_NSID,
    NETLINK_NO_ENOBUFS, NETLINK_PKTINFO, NETLINK_ROUTE, NLM_F_ACK, NLM_F_DUMP, NLM_F_DUMP_FILTERED,
    NLM_F_ECHO, NLM_F_MULTI, NLM_F_REQUEST, NLMSG_MIN_TYPE,
};
use rk_abi::native::poll::{POLLERR, POLLIN, POLLOUT, POLLRDNORM, POLLWRBAND, POLLWRNORM};
use rk_abi::native::rtnetlink::{
    RTM_BASE, RTM_GETADDR, RTM_GETNETCONF, RTM_GETROUTE, RTM_MAX, RTNLGRP_IPV4_MROUTE_R,
    RTNLGRP_IPV6_MROUTE_R, RTNLGRP_MAX,
};
use rk_abi::native::socket::{
    SO_ACCEPTCONN, SO_DOMAIN, SO_ERROR, SO_PROTOCOL, SO_TYPE, SOL_SOCKET,
};
use rk_frame::sync::SpinLock;
use rk_vfs::cred::{self, cap};
use rk_vfs::inode::Result;
use rk_vfs::wait::{PollTable, WaitQueue};

/// The size of `struct sockaddr_nl`.
pub const ADDR_LEN: usize = 12;

/// The size of a dump datagram, `NLMSG_GOODSIZE` of Linux: a page less the shared info of a
/// socket buffer.
const GOODSIZE: usize = 3776;

/// The largest dump datagram, `SKB_WITH_OVERHEAD(32768)` of Linux.
const MAX_DUMP: usize = 32768 - 320;

/// The memory that a datagram uses in the receive buffer more than its data, as the
/// `truesize` of a socket buffer of Linux.
const OVERHEAD: usize = 576;

/// The size of the message `NLMSG_DONE`: the header and an `int`.
const DONE_LEN: usize = HDRLEN + 4;

/// The flags of a socket, as `NETLINK_F_*` of Linux.
const F_PKTINFO: u32 = 1 << 0;
const F_BROADCAST_ERROR: u32 = 1 << 1;
const F_NO_ENOBUFS: u32 = 1 << 2;
const F_LISTEN_ALL_NSID: u32 = 1 << 3;
const F_CAP_ACK: u32 = 1 << 4;
const F_EXT_ACK: u32 = 1 << 5;
const F_STRICT_CHK: u32 = 1 << 6;

/// One datagram in the receive queue.
struct Datagram {
    data: Vec<u8>,
    /// The port ID of the sender. The kernel has 0.
    portid: u32,
    /// The multicast group, or 0 for a unicast datagram.
    group: u32,
}

/// A dump that runs.
struct Dump {
    /// The messages that are not yet in a datagram.
    msgs: VecDeque<Vec<u8>>,
    /// The sequence number and the port ID of the request, for `NLMSG_DONE`.
    seq: u32,
    portid: u32,
    /// The status in `NLMSG_DONE`: 0 or an error.
    status: i32,
    /// `NLMSG_DONE` comes in its own datagram after the last messages, as the flag
    /// `RTNL_FLAG_DUMP_SPLIT_NLM_DONE` of Linux.
    split: bool,
    /// The flags that the handler added to each message, as `cb->answer_flags` of Linux.
    answer: u16,
}

struct State {
    /// The groups that the socket listens to. Bit `n` is the group `n + 1`.
    groups: u64,
    /// The socket has a bitmap of groups, as `nlk->groups` of Linux. `NETLINK_LIST_MEMBERSHIPS`
    /// gives nothing without it.
    groups_alloc: bool,
    dst_portid: u32,
    dst_group: u32,
    queue: VecDeque<Datagram>,
    /// The memory of the datagrams in the queue, as `sk_rmem_alloc`.
    rmem: usize,
    error: Option<Errno>,
    dump: Option<Dump>,
    /// The largest size that a receive asked for, as `nlk->max_recvmsg_len`.
    max_recvmsg_len: usize,
    flags: u32,
    options: Options,
}

/// A netlink socket.
pub struct NetlinkSocket {
    me: Weak<NetlinkSocket>,
    ino: u64,
    kind: u32,
    protocol: u32,
    /// The port ID. It is 0 until the socket is bound.
    portid: AtomicU32,
    bound: AtomicBool,
    state: SpinLock<State>,
    wait: Arc<WaitQueue>,
    events: AtomicU64,
}

/// The netlink sockets, for the port IDs and for the multicast groups.
static SOCKETS: SpinLock<Vec<Weak<NetlinkSocket>>> = SpinLock::new(Vec::new());

fn sockets() -> Vec<Arc<NetlinkSocket>> {
    SOCKETS.lock().iter().filter_map(Weak::upgrade).collect()
}

/// Finds the bound socket with the port ID `portid`.
fn lookup(portid: u32) -> Option<Arc<NetlinkSocket>> {
    sockets().into_iter().find(|s| s.bound.load(Ordering::Acquire) && s.portid() == portid)
}

/// Tells if the current process has `CAP_NET_ADMIN`.
fn net_admin() -> bool {
    cred::current().capable(cap::NET_ADMIN)
}

/// The bytes of a `struct sockaddr_nl`.
fn sockaddr(portid: u32, groups: u32) -> Vec<u8> {
    let mut a = Vec::with_capacity(ADDR_LEN);
    a.extend_from_slice(&(AF_NETLINK as u16).to_ne_bytes());
    a.extend_from_slice(&[0, 0]);
    a.extend_from_slice(&portid.to_ne_bytes());
    a.extend_from_slice(&groups.to_ne_bytes());
    a
}

/// Reads a `struct sockaddr_nl`: the family, the port ID and the groups.
fn parse_addr(a: &[u8]) -> Option<(u32, u32, u32)> {
    let a = a.get(..ADDR_LEN)?;
    let family = u32::from(u16::from_ne_bytes([a[0], a[1]]));
    let portid = u32::from_ne_bytes([a[4], a[5], a[6], a[7]]);
    let groups = u32::from_ne_bytes([a[8], a[9], a[10], a[11]]);
    Some((family, portid, groups))
}

/// The bit of the group `group` in `nl_groups`, as `netlink_group_mask` of Linux.
fn group_mask(group: u32) -> u32 {
    if group == 0 { 0 } else { 1u32.checked_shl(group - 1).unwrap_or(0) }
}

/// The first group in `groups`, as `ffs`.
fn first_group(groups: u32) -> u32 {
    if groups == 0 { 0 } else { groups.trailing_zeros() + 1 }
}

/// Checks a multicast group for `bind` and `NETLINK_ADD_MEMBERSHIP`, as `rtnetlink_bind` of
/// Linux.
fn bind_group(group: u32) -> Result<()> {
    if (group == RTNLGRP_IPV4_MROUTE_R || group == RTNLGRP_IPV6_MROUTE_R) && !net_admin() {
        return Err(Errno::EPERM);
    }
    Ok(())
}

impl NetlinkSocket {
    /// Makes a socket, as `netlink_create` of Linux. Only `NETLINK_ROUTE` is here.
    ///
    /// # Errors
    ///
    /// Gives `ESOCKTNOSUPPORT` for a type other than `SOCK_RAW` and `SOCK_DGRAM`, and
    /// `EPROTONOSUPPORT` for another protocol.
    pub fn new(kind: u32, protocol: u32) -> Result<Arc<Self>> {
        if kind != SOCK_RAW && kind != SOCK_DGRAM {
            return Err(Errno::ESOCKTNOSUPPORT);
        }
        if protocol != NETLINK_ROUTE {
            return Err(Errno::EPROTONOSUPPORT);
        }
        let sock = Arc::new_cyclic(|me| Self {
            me: me.clone(),
            ino: next_ino(),
            kind,
            protocol,
            portid: AtomicU32::new(0),
            bound: AtomicBool::new(false),
            state: SpinLock::new(State {
                groups: 0,
                groups_alloc: false,
                dst_portid: 0,
                dst_group: 0,
                queue: VecDeque::new(),
                rmem: 0,
                error: None,
                dump: None,
                max_recvmsg_len: 0,
                flags: 0,
                options: Options::default(),
            }),
            wait: Arc::new(WaitQueue::new()),
            events: AtomicU64::new(0),
        });
        let mut list = SOCKETS.lock();
        list.retain(|w| w.strong_count() > 0);
        list.push(Arc::downgrade(&sock));
        Ok(sock)
    }

    /// The port ID.
    pub fn portid(&self) -> u32 {
        self.portid.load(Ordering::Acquire)
    }

    fn wake(&self) {
        self.events.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
    }

    /// Binds the socket to `portid`, as `netlink_insert` of Linux. Gives `EADDRINUSE` if
    /// another socket has the port ID. A socket that is bound keeps its port ID.
    fn insert(&self, portid: u32) -> Result<()> {
        let list = SOCKETS.lock();
        if self.bound.load(Ordering::Acquire) {
            return Ok(());
        }
        let taken = list.iter().filter_map(Weak::upgrade).any(|s| {
            !core::ptr::eq(&*s, self) && s.bound.load(Ordering::Acquire) && s.portid() == portid
        });
        if taken {
            return Err(Errno::EADDRINUSE);
        }
        self.portid.store(portid, Ordering::Release);
        self.bound.store(true, Ordering::Release);
        Ok(())
    }

    /// Binds the socket to a free port ID, as `netlink_autobind` of Linux: the ID of the
    /// process, or a number below -4096 if another socket has it.
    fn autobind(&self) -> Result<()> {
        static ROVER: AtomicU32 = AtomicU32::new(-4097i32 as u32);
        let pid = current_cred().pid;
        if pid > 0 && self.insert(pid as u32).is_ok() {
            return Ok(());
        }
        loop {
            let id = ROVER.fetch_sub(1, Ordering::Relaxed);
            match self.insert(id) {
                Err(Errno::EADDRINUSE) => continue,
                r => return r,
            }
        }
    }

    /// Puts a datagram in the receive queue, as `__netlink_sendskb` of Linux. A full queue drops
    /// the datagram and sets the error `ENOBUFS`, as `netlink_overrun`. Gives `false` if the
    /// queue was full.
    fn deliver(&self, data: Vec<u8>, portid: u32, group: u32) -> bool {
        let mut s = self.state.lock();
        if s.rmem > s.options.rcvbuf as usize {
            if s.flags & F_NO_ENOBUFS == 0 {
                s.error = Some(Errno::ENOBUFS);
            }
            drop(s);
            self.wake();
            return false;
        }
        s.rmem += data.len() + OVERHEAD;
        s.queue.push_back(Datagram { data, portid, group });
        drop(s);
        self.wake();
        true
    }

    /// Puts a datagram from the kernel (port ID 0, no group) in the receive queue, as
    /// `netlink_sendskb` of Linux. `mq_notify` sends its cookie to the socket of the process
    /// in this way. Gives `false` if the queue was full.
    pub fn send_from_kernel(&self, data: Vec<u8>) -> bool {
        self.deliver(data, 0, 0)
    }

    /// Sends the next datagram of the dump that runs, as `netlink_dump` of Linux. The datagram
    /// has as many messages as fit in `max(NLMSG_GOODSIZE, max_recvmsg_len)` bytes. `NLMSG_DONE`
    /// goes at the end of the last datagram if it fits, else in a datagram of its own.
    fn dump_step(&self, s: &mut State) {
        let size = GOODSIZE.max(s.max_recvmsg_len);
        if s.dump.is_none() {
            return;
        }
        if !s.queue.is_empty() && s.rmem + size + OVERHEAD >= s.options.rcvbuf as usize {
            s.dump = None;
            s.error = Some(Errno::ENOBUFS);
            return;
        }
        let Some(dump) = s.dump.as_mut() else { return };
        let mut buf = Vec::new();
        while let Some(m) = dump.msgs.front() {
            if !buf.is_empty() && buf.len() + m.len() > size {
                break;
            }
            buf.extend_from_slice(m);
            dump.msgs.pop_front();
        }
        let last = dump.msgs.is_empty() && !(dump.split && !buf.is_empty());
        if last && buf.len() + DONE_LEN <= size {
            let mut done = msg::done(dump.seq, dump.portid, dump.status);
            done[6..8].copy_from_slice(&(NLM_F_MULTI as u16 | dump.answer).to_ne_bytes());
            buf.extend_from_slice(&done);
            s.dump = None;
        }
        s.rmem += buf.len() + OVERHEAD;
        s.queue.push_back(Datagram { data: buf, portid: 0, group: 0 });
    }

    /// Runs each message of a request to the kernel, as `netlink_rcv_skb` of Linux. The kernel
    /// sends an ack for a message with `NLM_F_ACK` and for each error.
    fn input(&self, data: &[u8]) {
        let portid = self.portid();
        for m in msg::messages(data) {
            let Some(h) = Header::parse(m) else { break };
            let mut err = 0;
            if h.flags & NLM_F_REQUEST as u16 != 0 && u32::from(h.ty) >= NLMSG_MIN_TYPE {
                match rtnl_rcv(self, h, m) {
                    Ok(Flow::Done) => {}
                    // A dump that starts sends no ack.
                    Ok(Flow::Dump) => continue,
                    Err(e) => err = -i32::from(e.get()),
                }
            }
            if h.flags & NLM_F_ACK as u16 != 0 || err != 0 {
                let cap_ack = self.state.lock().flags & F_CAP_ACK != 0;
                self.deliver(msg::ack(m, err, portid, cap_ack), 0, 0);
            }
        }
    }

    /// Starts a dump with all of its messages, as `netlink_dump_start` of Linux. Gives `EBUSY`
    /// if a dump runs.
    fn start_dump(
        &self,
        h: Header,
        result: Result<Vec<Vec<u8>>>,
        split: bool,
        answer: u16,
    ) -> Result<()> {
        let mut s = self.state.lock();
        if s.dump.is_some() {
            return Err(Errno::EBUSY);
        }
        let (msgs, status) = match result {
            Ok(msgs) => (msgs, 0),
            Err(e) => (Vec::new(), -i32::from(e.get())),
        };
        s.dump = Some(Dump {
            msgs: msgs.into(),
            seq: h.seq,
            portid: self.portid(),
            status,
            split,
            answer,
        });
        self.dump_step(&mut s);
        drop(s);
        self.wake();
        Ok(())
    }

    /// Joins or leaves the group `group`.
    fn set_group(&self, group: u32, on: bool) {
        let mut s = self.state.lock();
        let bit = 1u64 << (group - 1);
        if on {
            s.groups |= bit;
        } else {
            s.groups &= !bit;
        }
    }
}

impl Socket for NetlinkSocket {
    fn family(&self) -> u32 {
        AF_NETLINK
    }

    fn kind(&self) -> u32 {
        self.kind
    }

    fn protocol(&self) -> u32 {
        self.protocol
    }

    fn ino(&self) -> u64 {
        self.ino
    }

    fn bind(&self, _paths: &dyn PathOps, addr: &[u8]) -> Result<()> {
        let Some((family, portid, groups)) = parse_addr(addr) else {
            return Err(Errno::EINVAL);
        };
        if family != AF_NETLINK {
            return Err(Errno::EINVAL);
        }
        if groups != 0 {
            self.state.lock().groups_alloc = true;
        }
        let bound = self.bound.load(Ordering::Acquire);
        if bound && portid != self.portid() {
            return Err(Errno::EINVAL);
        }
        for g in (0..32).filter(|g| groups & (1 << g) != 0) {
            bind_group(g + 1)?;
        }
        if !bound {
            if portid != 0 { self.insert(portid)? } else { self.autobind()? }
        }
        let mut s = self.state.lock();
        if groups == 0 && s.groups as u32 == 0 {
            return Ok(());
        }
        s.groups = (s.groups & !0xffff_ffff) | u64::from(groups);
        Ok(())
    }

    fn connect(&self, _paths: &dyn PathOps, addr: &[u8], _nonblock: bool) -> Result<()> {
        let Some(family) = addr.first_chunk::<2>().map(|f| u32::from(u16::from_ne_bytes(*f)))
        else {
            return Err(Errno::EINVAL);
        };
        if family == 0 {
            let mut s = self.state.lock();
            s.dst_portid = 0;
            s.dst_group = 0;
            return Ok(());
        }
        if family != AF_NETLINK {
            return Err(Errno::EINVAL);
        }
        let Some((_, portid, groups)) = parse_addr(addr) else {
            return Err(Errno::EINVAL);
        };
        if (groups != 0 || portid != 0) && !net_admin() {
            return Err(Errno::EPERM);
        }
        if !self.bound.load(Ordering::Acquire) {
            self.autobind()?;
        }
        let mut s = self.state.lock();
        s.dst_portid = portid;
        s.dst_group = first_group(groups);
        Ok(())
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
        let (dst_portid, dst_group) = match msg.addr.as_deref() {
            Some(a) if !a.is_empty() => {
                let Some((family, portid, groups)) = parse_addr(a) else {
                    return Err(Errno::EINVAL);
                };
                if family != AF_NETLINK {
                    return Err(Errno::EINVAL);
                }
                let group = first_group(groups);
                if (group != 0 || portid != 0) && !net_admin() {
                    return Err(Errno::EPERM);
                }
                (portid, group)
            }
            _ => {
                let s = self.state.lock();
                (s.dst_portid, s.dst_group)
            }
        };
        if !self.bound.load(Ordering::Acquire) {
            self.autobind()?;
        }
        let len = msg.data.len();
        if len + 32 > self.state.lock().options.sndbuf as usize {
            return Err(Errno::EMSGSIZE);
        }
        let portid = self.portid();
        if dst_group != 0 {
            broadcast(Some(self), &msg.data, portid, dst_portid, dst_group);
        }
        if dst_portid == 0 {
            self.input(&msg.data);
            return Ok(len);
        }
        let Some(peer) = lookup(dst_portid) else {
            return Err(Errno::ECONNREFUSED);
        };
        let _ = nonblock;
        if !peer.deliver(msg.data, portid, 0) {
            return Err(Errno::EAGAIN);
        }
        Ok(len)
    }

    fn recv(&self, len: usize, flags: u32, nonblock: bool) -> Result<Received> {
        if flags & MSG_OOB != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let timeout = self.state.lock().options.rcvtimeo;
        let nonblock = nonblock || flags & MSG_DONTWAIT != 0;
        let d = wait_for(&self.wait, timeout, || {
            let mut s = self.state.lock();
            if let Some(e) = s.error.take() {
                return Err(e);
            }
            let d = if flags & MSG_PEEK != 0 {
                s.queue.front().map(|d| Datagram {
                    data: d.data.clone(),
                    portid: d.portid,
                    group: d.group,
                })
            } else {
                let d = s.queue.pop_front();
                if let Some(d) = &d {
                    s.rmem -= (d.data.len() + OVERHEAD).min(s.rmem);
                }
                d
            };
            match d {
                Some(d) => {
                    s.max_recvmsg_len = s.max_recvmsg_len.max(len).min(MAX_DUMP);
                    if s.dump.is_some() && s.rmem <= s.options.rcvbuf as usize / 2 {
                        self.dump_step(&mut s);
                    }
                    Ok(Some(d))
                }
                None if nonblock => Err(Errno::EAGAIN),
                None => Ok(None),
            }
        })?;
        let full = d.data.len();
        let mut data = d.data;
        let mut rflags = 0;
        if len < full {
            data.truncate(len);
            rflags |= MSG_TRUNC;
        }
        Ok(Received {
            data,
            len: full,
            addr: Some(sockaddr(d.portid, group_mask(d.group))),
            flags: rflags,
            ..Received::default()
        })
    }

    fn name(&self) -> Vec<u8> {
        let s = self.state.lock();
        sockaddr(self.portid(), s.groups as u32)
    }

    fn peer_name(&self) -> Result<Vec<u8>> {
        let s = self.state.lock();
        Ok(sockaddr(s.dst_portid, group_mask(s.dst_group)))
    }

    fn get_option(&self, level: u32, name: u32) -> Result<Vec<u8>> {
        let mut s = self.state.lock();
        let int = |v: i32| v.to_ne_bytes().to_vec();
        if level == SOL_SOCKET {
            return Ok(match name {
                SO_TYPE => int(self.kind as i32),
                SO_DOMAIN => int(AF_NETLINK as i32),
                SO_PROTOCOL => int(self.protocol as i32),
                SO_ERROR => int(s.error.take().map_or(0, |e| i32::from(e.get()))),
                SO_ACCEPTCONN => int(0),
                _ => s.options.get(name)?,
            });
        }
        if level != SOL_NETLINK {
            return Err(Errno::ENOPROTOOPT);
        }
        let flag = match name {
            NETLINK_PKTINFO => F_PKTINFO,
            NETLINK_BROADCAST_ERROR => F_BROADCAST_ERROR,
            NETLINK_NO_ENOBUFS => F_NO_ENOBUFS,
            NETLINK_LISTEN_ALL_NSID => F_LISTEN_ALL_NSID,
            NETLINK_CAP_ACK => F_CAP_ACK,
            NETLINK_EXT_ACK => F_EXT_ACK,
            NETLINK_GET_STRICT_CHK => F_STRICT_CHK,
            NETLINK_LIST_MEMBERSHIPS => {
                // The bitmap has `RTNLGRP_MAX` bits, in words of 32 bits.
                if !s.groups_alloc {
                    return Ok(Vec::new());
                }
                let words = RTNLGRP_MAX.div_ceil(32) as usize;
                return Ok((0..words)
                    .flat_map(|w| ((s.groups >> (32 * w)) as u32).to_ne_bytes())
                    .collect());
            }
            _ => return Err(Errno::ENOPROTOOPT),
        };
        Ok(int(i32::from(s.flags & flag != 0)))
    }

    fn set_option(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
        if level == SOL_SOCKET {
            return match name {
                SO_TYPE | SO_DOMAIN | SO_PROTOCOL | SO_ERROR | SO_ACCEPTCONN => {
                    Err(Errno::ENOPROTOOPT)
                }
                _ => self.state.lock().options.set(name, value),
            };
        }
        if level != SOL_NETLINK {
            return Err(Errno::ENOPROTOOPT);
        }
        // A value shorter than an `int` is 0, as Linux reads it.
        let val = value.first_chunk::<4>().map_or(0, |v| u32::from_ne_bytes(*v));
        let flag = match name {
            NETLINK_PKTINFO => F_PKTINFO,
            NETLINK_ADD_MEMBERSHIP | NETLINK_DROP_MEMBERSHIP => {
                self.state.lock().groups_alloc = true;
                if val == 0 || val > RTNLGRP_MAX {
                    return Err(Errno::EINVAL);
                }
                if name == NETLINK_ADD_MEMBERSHIP {
                    bind_group(val)?;
                }
                self.set_group(val, name == NETLINK_ADD_MEMBERSHIP);
                return Ok(());
            }
            NETLINK_BROADCAST_ERROR => F_BROADCAST_ERROR,
            NETLINK_NO_ENOBUFS => F_NO_ENOBUFS,
            NETLINK_LISTEN_ALL_NSID => {
                if !cred::current().capable(cap::NET_BROADCAST) {
                    return Err(Errno::EPERM);
                }
                F_LISTEN_ALL_NSID
            }
            NETLINK_CAP_ACK => F_CAP_ACK,
            NETLINK_EXT_ACK => F_EXT_ACK,
            NETLINK_GET_STRICT_CHK => F_STRICT_CHK,
            _ => return Err(Errno::ENOPROTOOPT),
        };
        let mut s = self.state.lock();
        if val != 0 {
            s.flags |= flag;
        } else {
            s.flags &= !flag;
        }
        Ok(())
    }

    fn poll_wait(&self, table: &mut PollTable) {
        table.add(&self.wait);
    }

    fn poll(&self) -> u32 {
        let s = self.state.lock();
        let mut mask = POLLOUT | POLLWRNORM | POLLWRBAND;
        if s.error.is_some() {
            mask |= POLLERR;
        }
        if !s.queue.is_empty() {
            mask |= POLLIN | POLLRDNORM;
        }
        mask
    }

    fn event_count(&self) -> u64 {
        self.events.load(Ordering::Relaxed)
    }

    fn readable(&self) -> Result<usize> {
        // Linux has no `FIONREAD` for netlink sockets.
        Err(Errno::ENOTTY)
    }

    fn unsent(&self) -> Result<usize> {
        Err(Errno::ENOTTY)
    }

    fn release(&self) {
        let me = self.me.as_ptr();
        SOCKETS.lock().retain(|w| w.strong_count() > 0 && w.as_ptr() != me);
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Sends `data` to each socket in the group `group`, as `netlink_broadcast` of Linux. The
/// sender `from` and the socket with the port ID `exclude` do not get it.
fn broadcast(from: Option<&NetlinkSocket>, data: &[u8], portid: u32, exclude: u32, group: u32) {
    if group == 0 || group > RTNLGRP_MAX {
        return;
    }
    let bit = 1u64 << (group - 1);
    for s in sockets() {
        if from.is_some_and(|f| core::ptr::eq(f, &*s)) || s.portid() == exclude {
            continue;
        }
        if s.state.lock().groups & bit != 0 {
            s.deliver(data.to_vec(), portid, group);
        }
    }
}

/// The process that asked for a change, for the notification of the change.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Origin {
    /// The port ID of the socket of the request.
    pub portid: u32,
    /// The sequence number of the request.
    pub seq: u32,
    /// The request has `NLM_F_ECHO`: the socket of the request gets the notification.
    pub echo: bool,
}

impl Origin {
    /// A change that the kernel makes itself.
    pub const KERNEL: Self = Self { portid: 0, seq: 0, echo: false };
}

/// Sends the notification `msg` to the group `group`, as `rtnl_notify` of Linux. With
/// `NLM_F_ECHO` the socket of the request gets the message as a unicast, and not as a member of
/// the group.
pub fn notify(group: u32, msg: Vec<u8>, origin: Origin) {
    let exclude = if origin.echo { origin.portid } else { 0 };
    broadcast(None, &msg, 0, exclude, group);
    if origin.echo
        && let Some(s) = lookup(origin.portid)
    {
        s.deliver(msg, 0, 0);
    }
}

/// Tells if a socket listens to the group `group`. A family can skip the work of a
/// notification that no socket gets.
pub fn has_listeners(group: u32) -> bool {
    if group == 0 || group > RTNLGRP_MAX {
        return false;
    }
    let bit = 1u64 << (group - 1);
    sockets().iter().any(|s| s.state.lock().groups & bit != 0)
}

/// A request that a handler runs.
pub struct Request<'a> {
    /// The header of the message.
    pub hdr: Header,
    /// The message with its header.
    pub msg: &'a [u8],
    /// The port ID of the socket of the request.
    pub portid: u32,
    /// The socket asked for the strict checks of a dump, `NETLINK_GET_STRICT_CHK`.
    pub strict: bool,
    sock: &'a NetlinkSocket,
    filtered: Cell<bool>,
}

impl Request<'_> {
    /// The data of the message after the header, at most `nlmsg_len`.
    pub fn payload(&self) -> &[u8] {
        let end = (self.hdr.len as usize).min(self.msg.len());
        &self.msg[HDRLEN.min(end)..end]
    }

    /// The fixed header of the family and the attributes after it, as `nlmsg_parse` of Linux.
    /// Gives `EINVAL` if the message is shorter than the fixed header of `len` bytes.
    pub fn parse(&self, len: usize, max: u16) -> Result<(&[u8], msg::Attrs<'_>)> {
        let p = self.payload();
        if p.len() < len {
            return Err(Errno::EINVAL);
        }
        Ok((&p[..len], msg::Attrs::parse(&p[msg::align(len).min(p.len())..], max)))
    }

    /// Sends a reply to the socket of the request, as `rtnl_unicast` of Linux.
    pub fn reply(&self, msg: Vec<u8>) {
        self.sock.deliver(msg, 0, 0);
    }

    /// Tells that a dump has a filter. The `NLMSG_DONE` of the dump then has the flag
    /// `NLM_F_DUMP_FILTERED`, as `cb->answer_flags` of Linux. The handler puts the flag in its
    /// own messages.
    pub fn set_filtered(&self) {
        self.filtered.set(true);
    }

    /// The origin of a change that the request makes, for `notify`.
    pub fn origin(&self) -> Origin {
        Origin {
            portid: self.portid,
            seq: self.hdr.seq,
            echo: self.hdr.flags & NLM_F_ECHO as u16 != 0,
        }
    }
}

/// The handler of a request that changes or gets one object, as `doit` of Linux.
pub type DoIt = fn(&Request<'_>) -> Result<()>;

/// The handler of a dump, as `dumpit` of Linux. It gives all of the messages of the dump.
pub type DumpIt = fn(&Request<'_>) -> Result<Vec<Vec<u8>>>;

#[derive(Clone, Copy)]
enum Dumper {
    /// One handler.
    One(DumpIt),
    /// The handlers of each family in turn, as `rtnl_dump_all` of Linux.
    All,
}

#[derive(Clone, Copy, Default)]
struct Handler {
    doit: Option<DoIt>,
    dumpit: Option<Dumper>,
    split: bool,
}

/// The handlers, by the family and the message type.
static HANDLERS: SpinLock<BTreeMap<(u8, u16), Handler>> = SpinLock::new(BTreeMap::new());

/// Registers the handlers of the message type `ty` of the family `family`, as
/// `rtnl_register_many` of Linux. With `split` the message `NLMSG_DONE` of a dump comes in its
/// own datagram, as `RTNL_FLAG_DUMP_SPLIT_NLM_DONE`.
pub fn register(family: u8, ty: u32, doit: Option<DoIt>, dumpit: Option<DumpIt>, split: bool) {
    HANDLERS
        .lock()
        .insert((family, ty as u16), Handler { doit, dumpit: dumpit.map(Dumper::One), split });
}

/// Registers the handlers of the links and the dumps of all families. The IPv4 stack calls this
/// at boot. A second call does nothing.
pub fn init() {
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.swap(true, Ordering::AcqRel) {
        return;
    }
    {
        let mut h = HANDLERS.lock();
        for ty in [RTM_GETADDR, RTM_GETROUTE, RTM_GETNETCONF] {
            h.insert(
                (0, ty as u16),
                Handler { doit: None, dumpit: Some(Dumper::All), split: false },
            );
        }
    }
    link::init();
}

/// The result of a message to the kernel.
enum Flow {
    /// The handler ran.
    Done,
    /// A dump started. It sends no ack.
    Dump,
}

/// The kind of a message type: new, delete, get or set, as `rtnl_msgtype_kind` of Linux.
const KIND_GET: u16 = 2;

/// Runs one request, as `rtnetlink_rcv_msg` of Linux.
fn rtnl_rcv(sock: &NetlinkSocket, h: Header, m: &[u8]) -> Result<Flow> {
    if u32::from(h.ty) > RTM_MAX {
        return Err(Errno::EOPNOTSUPP);
    }
    let end = (h.len as usize).min(m.len());
    // Each message has at least the family.
    let Some(&family) = m.get(HDRLEN..end).and_then(|p| p.first()) else {
        return Ok(Flow::Done);
    };
    let kind = (h.ty - RTM_BASE as u16) & 3;
    if kind != KIND_GET && !net_admin() {
        return Err(Errno::EPERM);
    }
    let strict = sock.state.lock().flags & F_STRICT_CHK != 0;
    let req =
        Request { hdr: h, msg: m, portid: sock.portid(), strict, sock, filtered: Cell::new(false) };
    let handlers = HANDLERS.lock().clone();
    let find = |f: u8, dump: bool| {
        handlers
            .get(&(f, h.ty))
            .filter(|x| if dump { x.dumpit.is_some() } else { x.doit.is_some() })
    };
    if kind == KIND_GET && h.flags & NLM_F_DUMP as u16 != 0 {
        let Some(handler) = find(family, true).or_else(|| find(0, true)) else {
            return Err(Errno::EOPNOTSUPP);
        };
        let (result, split) = match handler.dumpit {
            Some(Dumper::One(f)) => (f(&req), handler.split),
            _ => (dump_all(&handlers, &req, family, h.ty), true),
        };
        let answer = if req.filtered.get() { NLM_F_DUMP_FILTERED as u16 } else { 0 };
        sock.start_dump(h, result, split, answer)?;
        return Ok(Flow::Dump);
    }
    let Some(doit) = find(family, false).or_else(|| find(0, false)).and_then(|x| x.doit) else {
        return Err(Errno::EOPNOTSUPP);
    };
    doit(&req)?;
    Ok(Flow::Done)
}

/// Runs the dump of each family from `family` on, as `rtnl_dump_all` of Linux. The dump stops
/// at the first error. An error after some messages ends the dump without the error.
fn dump_all(
    handlers: &BTreeMap<(u8, u16), Handler>,
    req: &Request<'_>,
    family: u8,
    ty: u16,
) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for (&(f, t), h) in handlers {
        if t != ty || f < family.max(1) {
            continue;
        }
        let Some(Dumper::One(dumpit)) = h.dumpit else { continue };
        match dumpit(req) {
            Ok(msgs) => out.extend(msgs),
            Err(e) if out.is_empty() => return Err(e),
            Err(_) => break,
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests;

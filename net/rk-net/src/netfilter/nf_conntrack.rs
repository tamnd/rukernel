//! Connection tracking, as net/netfilter/nf_conntrack_core.c, nf_conntrack_proto.c,
//! nf_conntrack_proto_generic.c, nf_conntrack_proto_udp.c, nf_conntrack_proto_icmp.c and
//! nf_conntrack_proto_icmpv6.c of Linux.
//!
//! A connection has two tuples: the tuple of its first packet (`IP_CT_DIR_ORIGINAL`) and the
//! tuple of the answer (`IP_CT_DIR_REPLY`). Each namespace has a table of the tuples of its
//! connections. The hook at `NF_INET_PRE_ROUTING` and `NF_INET_LOCAL_OUT` finds the connection
//! of each packet, or makes a new one, and puts a reference to it and the state of the packet
//! (`IP_CT_NEW`, `IP_CT_ESTABLISHED`, `IP_CT_RELATED` and their replies) on the packet buffer.
//! The hook at `NF_INET_POST_ROUTING` and `NF_INET_LOCAL_IN`, with the last priority, puts a new
//! connection in the table (`__nf_conntrack_confirm`). So a packet that a hook drops makes no
//! connection.
//!
//! The trackers here are the generic one (the addresses only), TCP (in `proto_tcp`), UDP,
//! UDP-Lite, ICMP and ICMPv6. SCTP and DCCP have their ports in the tuple, with the generic
//! timeout. An ICMP
//! error belongs to the connection of the packet in it, as `IP_CT_RELATED`.
//!
//! The hooks are there while a user needs them, as `nf_ct_netns_get` and `nf_ct_netns_put` of
//! Linux. A connection ends at its timeout. The table drops the connections that ended when it
//! adds new ones and when `nf_conntrack_count` is read, in place of the work of `gc_worker`.
//!
//! rukernel puts the fragments of a packet together after `NF_INET_PRE_ROUTING`, not before
//! it as `nf_defrag_ipv4` and `nf_defrag_ipv6` of Linux, so a fragment that comes in gets no
//! connection. The packets that the host sends are whole at the hooks.

use super::{
    NF_ACCEPT, NF_DROP, NF_INET_LOCAL_IN, NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING,
    NF_INET_PRE_ROUTING, NF_IP_PRI_CONNTRACK, NFPROTO_INET, NFPROTO_IPV4, NFPROTO_IPV6, NfHookFn,
    NfHookOps, NfHookState, nf_pktinfo, nf_register_net_hooks, nf_unregister_net_hooks,
};
use crate::buf::NetBuf;
use crate::ns::{self, PerNet};
use crate::sysctl;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::inode::Result;

pub mod nf_conntrack_netlink;
pub mod proto_tcp;

/// The state of a packet of a connection that has seen packets in both directions.
pub const IP_CT_ESTABLISHED: u8 = 0;
/// The state of a packet that belongs to a connection, as an ICMP error.
pub const IP_CT_RELATED: u8 = 1;
/// The state of the packets of a connection that has not seen a reply.
pub const IP_CT_NEW: u8 = 2;
/// The value that the state of a packet in the reply direction adds.
pub const IP_CT_IS_REPLY: u8 = 3;
/// The state of a packet in the reply direction.
pub const IP_CT_ESTABLISHED_REPLY: u8 = IP_CT_ESTABLISHED + IP_CT_IS_REPLY;
/// The state of a related packet in the reply direction.
pub const IP_CT_RELATED_REPLY: u8 = IP_CT_RELATED + IP_CT_IS_REPLY;
/// The count of the states.
pub const IP_CT_NUMBER: u8 = 5;

/// The direction of the first packet of a connection.
pub const IP_CT_DIR_ORIGINAL: usize = 0;
/// The direction of the answer.
pub const IP_CT_DIR_REPLY: usize = 1;

/// The connection is the one that a helper expected.
pub const IPS_EXPECTED: u32 = 1 << 0;
/// The connection has seen a packet in the reply direction.
pub const IPS_SEEN_REPLY: u32 = 1 << 1;
/// The connection stays until its timeout.
pub const IPS_ASSURED: u32 = 1 << 2;
/// The connection is in the table.
pub const IPS_CONFIRMED: u32 = 1 << 3;
/// The source of the connection changes.
pub const IPS_SRC_NAT: u32 = 1 << 4;
/// The destination of the connection changes.
pub const IPS_DST_NAT: u32 = 1 << 5;
/// The sequence numbers change.
pub const IPS_SEQ_ADJUST: u32 = 1 << 6;
/// The source NAT is set up.
pub const IPS_SRC_NAT_DONE: u32 = 1 << 7;
/// The destination NAT is set up.
pub const IPS_DST_NAT_DONE: u32 = 1 << 8;
/// The connection is going away.
pub const IPS_DYING: u32 = 1 << 9;
/// The timeout of the connection does not change.
pub const IPS_FIXED_TIMEOUT: u32 = 1 << 10;
/// The bits of the NAT of a connection.
pub const IPS_NAT_MASK: u32 = IPS_SRC_NAT | IPS_DST_NAT;
/// The bits of the NAT that is set up.
pub const IPS_NAT_DONE_MASK: u32 = IPS_SRC_NAT_DONE | IPS_DST_NAT_DONE;

/// The priority of the hook that puts the new connections in the table, the last one.
pub const NF_IP_PRI_CONNTRACK_CONFIRM: i32 = i32::MAX;

/// The protocol numbers that the trackers know.
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_DCCP: u8 = 33;
const IPPROTO_ICMPV6: u8 = 58;
const IPPROTO_SCTP: u8 = 132;
const IPPROTO_UDPLITE: u8 = 136;

/// The time of a UDP connection with a reply before it gets the timeout of a stream, 2 s.
const UDP_STREAM_DELAY_SECS: u64 = 2;

/// The tuple of one direction of a connection, as `struct nf_conntrack_tuple` of Linux. An IPv4
/// address is in the first 4 bytes of its field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NfConntrackTuple {
    /// The family of the addresses: `NFPROTO_IPV4` or `NFPROTO_IPV6`.
    pub l3num: u8,
    /// The protocol of the transport header.
    pub protonum: u8,
    /// The source address.
    pub src: [u8; 16],
    /// The destination address.
    pub dst: [u8; 16],
    /// The source port, or the ID of an ICMP echo. Zero for the generic tracker.
    pub src_u: u16,
    /// The destination port, or the type of ICMP in the high byte and its code in the low byte.
    pub dst_u: u16,
}

impl NfConntrackTuple {
    /// The type of an ICMP or ICMPv6 tuple.
    pub fn icmp_type(&self) -> u8 {
        (self.dst_u >> 8) as u8
    }

    /// The tuple of the other direction, as `nf_ct_invert_tuple` of Linux. Gives `None` for an
    /// ICMP type that has no answer.
    pub fn invert(&self) -> Option<Self> {
        let dst_u = match self.protonum {
            IPPROTO_ICMP if self.l3num == NFPROTO_IPV4 => {
                u16::from(icmp_invert(self.icmp_type())?) << 8 | (self.dst_u & 0xff)
            }
            IPPROTO_ICMPV6 if self.l3num == NFPROTO_IPV6 => {
                u16::from(icmpv6_invert(self.icmp_type())?) << 8 | (self.dst_u & 0xff)
            }
            _ => self.src_u,
        };
        let src_u = match self.protonum {
            IPPROTO_ICMP | IPPROTO_ICMPV6 => self.src_u,
            _ => self.dst_u,
        };
        Some(Self { src: self.dst, dst: self.src, src_u, dst_u, ..*self })
    }
}

/// The type of the answer to an ICMP request, as `invmap` of `icmp_pkt_to_tuple` of Linux.
fn icmp_invert(t: u8) -> Option<u8> {
    Some(match t {
        8 => 0,   // ICMP_ECHO -> ICMP_ECHOREPLY
        0 => 8,   // ICMP_ECHOREPLY -> ICMP_ECHO
        13 => 14, // ICMP_TIMESTAMP -> ICMP_TIMESTAMPREPLY
        14 => 13,
        15 => 16, // ICMP_INFO_REQUEST -> ICMP_INFO_REPLY
        16 => 15,
        17 => 18, // ICMP_ADDRESS -> ICMP_ADDRESSREPLY
        18 => 17,
        _ => return None,
    })
}

/// The type of the answer to an ICMPv6 request, as `invmap` of nf_conntrack_proto_icmpv6.c.
fn icmpv6_invert(t: u8) -> Option<u8> {
    Some(match t {
        128 => 129, // ICMPV6_ECHO_REQUEST -> ICMPV6_ECHO_REPLY
        129 => 128,
        139 => 140, // ICMPV6_NI_QUERY -> ICMPV6_NI_REPLY
        140 => 139,
        _ => return None,
    })
}

/// The ICMP types that can start a connection, as `valid_new` of `icmp_packet` of Linux.
fn icmp_valid_new(l3num: u8, t: u8) -> bool {
    if l3num == NFPROTO_IPV4 { matches!(t, 8 | 13 | 15 | 17) } else { matches!(t, 128 | 139) }
}

/// Tells if `protonum` is ICMP of the family `l3num`: ICMP for IPv4 or ICMPv6 for IPv6.
fn is_icmp(l3num: u8, protonum: u8) -> bool {
    matches!((l3num, protonum), (NFPROTO_IPV4, IPPROTO_ICMP) | (NFPROTO_IPV6, IPPROTO_ICMPV6))
}

/// The ICMP types of the errors, which carry the start of the packet that made them.
fn icmp_is_error(l3num: u8, t: u8) -> bool {
    if l3num == NFPROTO_IPV4 {
        // Destination unreachable, source quench, redirect, time exceeded, parameter problem.
        matches!(t, 3 | 4 | 5 | 11 | 12)
    } else {
        // The ICMPv6 errors have the types under 128.
        t < 128
    }
}

/// A connection, as `struct nf_conn` of Linux.
pub struct NfConn {
    /// The tuples of the two directions, `IP_CT_DIR_ORIGINAL` and `IP_CT_DIR_REPLY`. NAT
    /// changes the reply tuple of a connection before it goes in the table.
    tuple: SpinLock<[NfConntrackTuple; 2]>,
    /// The `IPS_*` bits.
    status: AtomicU32,
    /// The tick of the timer at which the connection ends.
    timeout: AtomicU64,
    /// The mark of the connection, for the `ct mark` of nf_tables.
    pub mark: AtomicU32,
    /// The ID of the connection, as `nf_ct_get_id` of Linux.
    pub id: u32,
    /// The tick after which a UDP connection with a reply is a stream, as
    /// `ct->proto.udp.stream_ts` of Linux.
    udp_stream_ts: AtomicU64,
    /// The state of a TCP connection, as `ct->proto.tcp` of Linux.
    tcp: SpinLock<proto_tcp::TcpState>,
}

impl NfConn {
    /// The `IPS_*` bits of the connection.
    pub fn status(&self) -> u32 {
        self.status.load(Ordering::Relaxed)
    }

    /// The tuple of the direction `dir`.
    pub fn tuple(&self, dir: usize) -> NfConntrackTuple {
        self.tuple.lock()[dir]
    }

    /// The tuples of the two directions.
    pub fn tuples(&self) -> [NfConntrackTuple; 2] {
        *self.tuple.lock()
    }

    /// Sets the reply tuple of a connection that is not in the table yet, as
    /// `nf_conntrack_alter_reply` of Linux.
    pub(crate) fn alter_reply(&self, reply: NfConntrackTuple) {
        debug_assert!(!self.is_confirmed());
        self.tuple.lock()[IP_CT_DIR_REPLY] = reply;
    }

    pub(crate) fn set_status(&self, bits: u32) -> u32 {
        self.status.fetch_or(bits, Ordering::Relaxed)
    }

    /// Tells if the connection is in the table, as `nf_ct_is_confirmed` of Linux.
    pub fn is_confirmed(&self) -> bool {
        self.status() & IPS_CONFIRMED != 0
    }

    /// The ticks of the timer before the connection ends, as `nf_ct_expires` of Linux.
    pub fn expires(&self) -> u64 {
        self.timeout.load(Ordering::Relaxed).saturating_sub(now())
    }

    fn expired(&self, t: u64) -> bool {
        self.timeout.load(Ordering::Relaxed) <= t
    }

    /// Sets the timeout to `extra` ticks from now, as `nf_ct_refresh` of Linux. A connection
    /// with `IPS_FIXED_TIMEOUT` keeps its timeout.
    pub fn refresh(&self, extra: u64) {
        if self.status() & IPS_FIXED_TIMEOUT == 0 {
            self.timeout.store(now() + extra, Ordering::Relaxed);
        }
    }
}

impl fmt::Debug for NfConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NfConn")
            .field("id", &self.id)
            .field("tuple", &self.tuple(IP_CT_DIR_ORIGINAL))
            .field("status", &self.status())
            .finish()
    }
}

/// The connection of a packet and the state of the packet in it, as `skb->_nfct` of Linux.
#[derive(Clone, Default)]
pub struct NfCt(Option<(Arc<NfConn>, u8)>);

impl NfCt {
    /// The connection and the state, `IP_CT_*`, as `nf_ct_get` of Linux.
    pub fn get(&self) -> Option<(&Arc<NfConn>, u8)> {
        self.0.as_ref().map(|(c, i)| (c, *i))
    }

    /// Sets the connection and the state, as `nf_ct_set` of Linux.
    pub fn set(&mut self, ct: Arc<NfConn>, info: u8) {
        self.0 = Some((ct, info));
    }

    /// Removes the connection, as `nf_reset_ct` of Linux. A packet that goes to another
    /// namespace drops its connection.
    pub fn reset(&mut self) {
        self.0 = None;
    }
}

impl PartialEq for NfCt {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (None, None) => true,
            (Some((a, i)), Some((b, j))) => Arc::ptr_eq(a, b) && i == j,
            _ => false,
        }
    }
}

impl Eq for NfCt {}

impl fmt::Debug for NfCt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some((c, i)) => write!(f, "NfCt({}, {i})", c.id),
            None => f.write_str("NfCt(none)"),
        }
    }
}

/// The ticks of the timer. A unit test sets the time.
#[cfg(not(test))]
fn now() -> u64 {
    crate::options::now()
}

#[cfg(test)]
static TEST_NOW: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
fn now() -> u64 {
    TEST_NOW.load(Ordering::Relaxed)
}

/// A timeout of /proc/sys/net/netfilter in ticks.
fn timeout(name: &str) -> u64 {
    u64::try_from(sysctl::netfilter(name)).unwrap_or(0) * crate::options::hz()
}

/// The tuples of the connections of a namespace, as the table `nf_conntrack_hash` of Linux.
#[derive(Default)]
struct CtTable {
    /// Each tuple of each connection, with the direction of the tuple.
    hash: BTreeMap<NfConntrackTuple, (Arc<NfConn>, usize)>,
    /// The connections that went in since the last walk for the ones that ended.
    inserts: usize,
}

impl CtTable {
    /// The count of the connections.
    fn count(&self) -> usize {
        self.hash.len() / 2
    }

    fn remove(&mut self, ct: &NfConn) {
        ct.set_status(IPS_DYING);
        for t in &ct.tuples() {
            if self.hash.get(t).is_some_and(|(c, _)| core::ptr::eq(&**c, ct)) {
                self.hash.remove(t);
            }
        }
    }

    /// Removes the connections that ended, as `gc_worker` of Linux.
    fn gc(&mut self) {
        let t = now();
        let dead: Vec<Arc<NfConn>> = self
            .hash
            .values()
            .filter(|(c, d)| *d == IP_CT_DIR_ORIGINAL && c.expired(t))
            .map(|(c, _)| c.clone())
            .collect();
        for c in dead {
            self.remove(&c);
        }
        self.inserts = 0;
    }

    /// Finds the connection of `tuple`, as `__nf_conntrack_find_get` of Linux. A connection that
    /// ended goes away.
    fn find(&mut self, tuple: &NfConntrackTuple) -> Option<(Arc<NfConn>, usize)> {
        let (c, d) = self.hash.get(tuple)?.clone();
        if c.expired(now()) {
            self.remove(&c);
            return None;
        }
        Some((c, d))
    }
}

static CT: PerNet<SpinLock<CtTable>> = PerNet::new(|| SpinLock::new(CtTable::default()));

/// The users of the hooks of a namespace for IPv4 and IPv6, with the hooks.
#[derive(Default)]
struct CtUsers {
    users: [u32; 2],
    hooks: [Vec<NfHookOps>; 2],
}

static USERS: PerNet<SpinLock<CtUsers>> = PerNet::new(|| SpinLock::new(CtUsers::default()));

/// The next ID of a connection.
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

/// The count of the connections of the current namespace, `nf_conntrack_count`.
pub fn nf_conntrack_count() -> usize {
    let mut t = CT.lock();
    t.gc();
    t.count()
}

/// Finds the connection of `tuple` in the current namespace, with the direction of the tuple,
/// as `nf_conntrack_find_get` of Linux.
pub fn nf_conntrack_find_get(tuple: &NfConntrackTuple) -> Option<(Arc<NfConn>, usize)> {
    CT.lock().find(tuple)
}

/// Tells if a connection other than `ignored` has the tuple `tuple`, as
/// `nf_conntrack_tuple_taken` of Linux. NAT uses this to find a free tuple.
pub fn nf_conntrack_tuple_taken(tuple: &NfConntrackTuple, ignored: &NfConn) -> bool {
    CT.lock().find(tuple).is_some_and(|(c, _)| !core::ptr::eq(&*c, ignored))
}

/// Gives the tuple of the packet `d` of the family `pf` and the offset of its transport
/// header, as `nf_ct_get_tuple` of Linux. Gives `None` for a fragment and for a header that is
/// too short.
pub fn nf_ct_get_tuple(pf: u8, d: &[u8]) -> Option<(NfConntrackTuple, usize)> {
    let mut t = NfConntrackTuple { l3num: pf, ..NfConntrackTuple::default() };
    match pf {
        NFPROTO_IPV4 => {
            if d.len() < 20 || d[0] >> 4 != 4 {
                return None;
            }
            // A fragment, with the flag "more fragments" or an offset.
            if u16::from_be_bytes([d[6], d[7]]) & 0x3fff != 0 {
                return None;
            }
            t.src[..4].copy_from_slice(&d[12..16]);
            t.dst[..4].copy_from_slice(&d[16..20]);
        }
        NFPROTO_IPV6 => {
            if d.len() < 40 || d[0] >> 4 != 6 {
                return None;
            }
            t.src.copy_from_slice(&d[8..24]);
            t.dst.copy_from_slice(&d[24..40]);
        }
        _ => return None,
    }
    let pkt = nf_pktinfo(pf, d);
    let thoff = pkt.thoff?;
    // A fragment of IPv6 with the offset 0 still has a fragment header.
    if pf == NFPROTO_IPV6 && has_frag_header(d) {
        return None;
    }
    t.protonum = pkt.l4proto;
    let l4 = d.get(thoff..).unwrap_or_default();
    match t.protonum {
        IPPROTO_TCP | IPPROTO_UDP | IPPROTO_UDPLITE | IPPROTO_SCTP | IPPROTO_DCCP => {
            let p = l4.get(..4)?;
            t.src_u = u16::from_be_bytes([p[0], p[1]]);
            t.dst_u = u16::from_be_bytes([p[2], p[3]]);
        }
        IPPROTO_ICMP if pf == NFPROTO_IPV4 => icmp_tuple(&mut t, l4)?,
        IPPROTO_ICMPV6 if pf == NFPROTO_IPV6 => icmp_tuple(&mut t, l4)?,
        _ => {}
    }
    Some((t, thoff))
}

/// The type, the code and the ID of an ICMP header, as `icmp_pkt_to_tuple` of Linux.
fn icmp_tuple(t: &mut NfConntrackTuple, l4: &[u8]) -> Option<()> {
    let h = l4.get(..8)?;
    t.dst_u = u16::from_be_bytes([h[0], h[1]]);
    t.src_u = u16::from_be_bytes([h[4], h[5]]);
    Some(())
}

/// Tells if an IPv6 packet has a fragment header.
fn has_frag_header(d: &[u8]) -> bool {
    let (mut next, mut off) = (d[6], 40);
    loop {
        match next {
            44 => return true,
            0 | 43 | 60 => {
                let Some(h) = d.get(off..off + 2) else { return false };
                next = h[0];
                off += (usize::from(h[1]) + 1) * 8;
            }
            51 => {
                let Some(h) = d.get(off..off + 2) else { return false };
                next = h[0];
                off += (usize::from(h[1]) + 2) * 4;
            }
            _ => return false,
        }
    }
}

/// The first timeout of a new connection of `protonum`.
fn new_timeout(l3num: u8, protonum: u8) -> u64 {
    match protonum {
        IPPROTO_UDP | IPPROTO_UDPLITE => timeout("nf_conntrack_udp_timeout"),
        IPPROTO_ICMP => timeout("nf_conntrack_icmp_timeout"),
        IPPROTO_ICMPV6 if l3num == NFPROTO_IPV6 => timeout("nf_conntrack_icmpv6_timeout"),
        _ => timeout("nf_conntrack_generic_timeout"),
    }
}

/// Makes a connection for `tuple`, out of the table, as `init_conntrack` of Linux. Gives `None`
/// for a tuple with no reply tuple.
fn init_conntrack(tuple: &NfConntrackTuple) -> Option<Arc<NfConn>> {
    let reply = tuple.invert()?;
    let t = now();
    Some(Arc::new(NfConn {
        tuple: SpinLock::new([*tuple, reply]),
        status: AtomicU32::new(0),
        timeout: AtomicU64::new(t + new_timeout(tuple.l3num, tuple.protonum)),
        mark: AtomicU32::new(0),
        id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        udp_stream_ts: AtomicU64::new(t + UDP_STREAM_DELAY_SECS * crate::options::hz()),
        tcp: SpinLock::new(proto_tcp::TcpState::default()),
    }))
}

/// The length of the IP packet `d` from its header, or the bytes that are there.
fn ip_len(pf: u8, d: &[u8]) -> usize {
    let len = match pf {
        NFPROTO_IPV4 => usize::from(u16::from_be_bytes([d[2], d[3]])),
        _ => 40 + usize::from(u16::from_be_bytes([d[4], d[5]])),
    };
    len.min(d.len())
}

/// Removes a connection from the table, as `nf_ct_kill` of Linux. The packets that have it keep
/// it.
pub fn nf_ct_kill(ct: &NfConn) {
    if ct.is_confirmed() {
        CT.lock().remove(ct);
    } else {
        ct.set_status(IPS_DYING);
    }
}

/// The work of the tracker of the protocol for a packet, as `nf_conntrack_handle_packet` of
/// Linux. `d` is the packet and `thoff` the offset of its transport header.
fn handle_packet(ct: &NfConn, ctinfo: u8, d: &[u8], thoff: usize) -> proto_tcp::Verdict {
    use proto_tcp::Verdict;
    let tuple = &ct.tuple(IP_CT_DIR_ORIGINAL);
    let ok = |b: bool| if b { Verdict::Accept } else { Verdict::Invalid };
    match tuple.protonum {
        IPPROTO_TCP => {
            let dir = if ctinfo >= IP_CT_IS_REPLY { IP_CT_DIR_REPLY } else { IP_CT_DIR_ORIGINAL };
            let len = ip_len(tuple.l3num, d).saturating_sub(thoff);
            let l4 = d.get(thoff..).unwrap_or_default();
            proto_tcp::tcp_packet(ct, dir, l4, len, !ct.is_confirmed())
        }
        IPPROTO_UDP | IPPROTO_UDPLITE => {
            // `nf_conntrack_udp_packet`: a connection with a reply that lives for 2 s gets the
            // timeout of a stream and stays.
            if ct.status() & IPS_SEEN_REPLY != 0 {
                let stream = now() > ct.udp_stream_ts.load(Ordering::Relaxed);
                let extra = if stream {
                    timeout("nf_conntrack_udp_timeout_stream")
                } else {
                    timeout("nf_conntrack_udp_timeout")
                };
                ct.refresh(extra);
                if stream {
                    ct.set_status(IPS_ASSURED);
                }
            } else {
                ct.refresh(timeout("nf_conntrack_udp_timeout"));
            }
            ok(true)
        }
        _ if is_icmp(tuple.l3num, tuple.protonum) => {
            // `icmp_packet`: only a request starts a connection.
            if ctinfo == IP_CT_NEW && !icmp_valid_new(tuple.l3num, tuple.icmp_type()) {
                return ok(false);
            }
            ct.refresh(new_timeout(tuple.l3num, tuple.protonum));
            ok(true)
        }
        _ => {
            ct.refresh(timeout("nf_conntrack_generic_timeout"));
            ok(true)
        }
    }
}

/// Finds the connection of the packet in an ICMP error, as `nf_conntrack_inet_error` of Linux.
/// The packet in the error went in the other direction, so the inverse of its tuple finds the
/// connection.
fn icmp_error(pf: u8, l4: &[u8]) -> Option<(Arc<NfConn>, u8)> {
    let inner = l4.get(8..)?;
    let (orig, _) = nf_ct_get_tuple(pf, inner).or_else(|| truncated_tuple(pf, inner))?;
    let (ct, dir) = CT.lock().find(&orig.invert()?)?;
    let info = if dir == IP_CT_DIR_REPLY { IP_CT_RELATED_REPLY } else { IP_CT_RELATED };
    Some((ct, info))
}

/// The tuple of the packet in an ICMP error, which can end after 8 bytes of its transport
/// header, so its IPv4 total length can be more than the bytes that are there.
fn truncated_tuple(pf: u8, inner: &[u8]) -> Option<(NfConntrackTuple, usize)> {
    if pf != NFPROTO_IPV4 || inner.len() < 20 {
        return None;
    }
    let ihl = usize::from(inner[0] & 0xf) * 4;
    let end = (ihl + 8).min(inner.len());
    nf_ct_get_tuple(pf, &inner[..end])
}

/// Finds or makes the connection of a packet and puts it on the packet, as `nf_conntrack_in` of
/// Linux. A packet with a connection already, as a packet that the host sent to itself on the
/// loopback device, keeps it. A packet that the trackers do not know gets no connection, and
/// the `ct state` of nf_tables sees it as invalid.
pub fn nf_conntrack_in(skb: &mut NetBuf, state: &NfHookState) -> u32 {
    if skb.nfct.get().is_some() {
        return NF_ACCEPT;
    }
    let pf = state.pf;
    let Some((tuple, thoff)) = nf_ct_get_tuple(pf, skb.data()) else { return NF_ACCEPT };
    if is_icmp(pf, tuple.protonum) && icmp_is_error(pf, tuple.icmp_type()) {
        if let Some((ct, info)) = icmp_error(pf, skb.data().get(thoff..).unwrap_or_default()) {
            skb.nfct.set(ct, info);
        }
        return NF_ACCEPT;
    }
    // A segment that opens a closed TCP connection again removes it, and the lookup runs
    // again, as `NF_REPEAT` of Linux.
    for _ in 0..2 {
        let found = CT.lock().find(&tuple);
        let (ct, ctinfo) = match found {
            Some((ct, IP_CT_DIR_REPLY)) => (ct, IP_CT_ESTABLISHED_REPLY),
            Some((ct, _)) => {
                let info =
                    if ct.status() & IPS_SEEN_REPLY != 0 { IP_CT_ESTABLISHED } else { IP_CT_NEW };
                (ct, info)
            }
            None => {
                if nf_conntrack_count_full() {
                    return NF_DROP;
                }
                let Some(ct) = init_conntrack(&tuple) else { return NF_ACCEPT };
                (ct, IP_CT_NEW)
            }
        };
        match handle_packet(&ct, ctinfo, skb.data(), thoff) {
            proto_tcp::Verdict::Accept => {}
            proto_tcp::Verdict::Invalid => return NF_ACCEPT,
            proto_tcp::Verdict::Repeat => {
                nf_ct_kill(&ct);
                continue;
            }
            proto_tcp::Verdict::Kill => nf_ct_kill(&ct),
        }
        if ctinfo == IP_CT_ESTABLISHED_REPLY {
            ct.set_status(IPS_SEEN_REPLY);
        }
        skb.nfct.set(ct, ctinfo);
        return NF_ACCEPT;
    }
    NF_ACCEPT
}

/// Tells if the table is full after a walk for the connections that ended, as the check of
/// `nf_conntrack_max` in `__nf_conntrack_alloc` of Linux.
fn nf_conntrack_count_full() -> bool {
    let max = usize::try_from(sysctl::netfilter("nf_conntrack_max")).unwrap_or(0);
    if max == 0 {
        return false;
    }
    let mut t = CT.lock();
    if t.count() < max {
        return false;
    }
    t.gc();
    t.count() >= max
}

/// Puts the new connection of a packet in the table, as `nf_conntrack_confirm` and
/// `__nf_conntrack_confirm` of Linux. When another packet put the same connection in the table
/// first, the packet takes that connection, as `nf_ct_resolve_clash`.
pub fn nf_conntrack_confirm(skb: &mut NetBuf) -> u32 {
    let Some((ct, info)) = skb.nfct.get() else { return NF_ACCEPT };
    if ct.is_confirmed() || info >= IP_CT_IS_REPLY {
        return NF_ACCEPT;
    }
    let ct = ct.clone();
    let mut t = CT.lock();
    if ct.status() & IPS_DYING != 0 {
        return NF_DROP;
    }
    let [orig, reply] = ct.tuples();
    if let Some((old, dir)) = t.find(&orig) {
        drop(t);
        let info = if dir == IP_CT_DIR_REPLY { IP_CT_ESTABLISHED_REPLY } else { info };
        skb.nfct.set(old, info);
        return NF_ACCEPT;
    }
    if t.find(&reply).is_some() {
        return NF_DROP;
    }
    t.inserts += 1;
    if t.inserts >= 64 {
        t.gc();
    }
    // A connection that no rule of NAT changed keeps its tuples, and the rules of NAT do not
    // run for its next packets, as `nf_nat_alloc_null_binding` of Linux.
    ct.set_status(IPS_CONFIRMED | IPS_NAT_DONE_MASK);
    t.hash.insert(orig, (ct.clone(), IP_CT_DIR_ORIGINAL));
    t.hash.insert(reply, (ct, IP_CT_DIR_REPLY));
    NF_ACCEPT
}

/// The hook of `NF_INET_PRE_ROUTING` and `NF_INET_LOCAL_OUT`, as `ipv4_conntrack_in`,
/// `ipv4_conntrack_local` and the hooks of IPv6 of Linux.
struct ConntrackIn;

impl NfHookFn for ConntrackIn {
    fn hook(&self, skb: &mut NetBuf, state: &NfHookState) -> u32 {
        nf_conntrack_in(skb, state)
    }
}

/// The hook of `NF_INET_POST_ROUTING` and `NF_INET_LOCAL_IN`, as `ipv4_confirm` of Linux.
struct ConntrackConfirm;

impl NfHookFn for ConntrackConfirm {
    fn hook(&self, skb: &mut NetBuf, _state: &NfHookState) -> u32 {
        nf_conntrack_confirm(skb)
    }
}

/// The hooks of connection tracking for the family `pf`, as `ipv4_conntrack_ops` of Linux, and
/// the hooks of NAT, as `nf_nat_ipv4_ops`.
fn conntrack_ops(pf: u8) -> Vec<NfHookOps> {
    let input: Arc<dyn NfHookFn> = Arc::new(ConntrackIn);
    let confirm: Arc<dyn NfHookFn> = Arc::new(ConntrackConfirm);
    let op = |hook: &Arc<dyn NfHookFn>, hooknum, priority| NfHookOps {
        hook: hook.clone(),
        pf,
        hooknum,
        priority,
    };
    let mut ops = alloc::vec![
        op(&input, NF_INET_PRE_ROUTING, NF_IP_PRI_CONNTRACK),
        op(&input, NF_INET_LOCAL_OUT, NF_IP_PRI_CONNTRACK),
        op(&confirm, NF_INET_POST_ROUTING, NF_IP_PRI_CONNTRACK_CONFIRM),
        op(&confirm, NF_INET_LOCAL_IN, NF_IP_PRI_CONNTRACK_CONFIRM),
    ];
    ops.extend(super::nf_nat::nf_nat_ops(pf));
    ops
}

fn families(pf: u8) -> &'static [(u8, usize)] {
    match pf {
        NFPROTO_IPV4 => &[(NFPROTO_IPV4, 0)],
        NFPROTO_IPV6 => &[(NFPROTO_IPV6, 1)],
        NFPROTO_INET => &[(NFPROTO_IPV4, 0), (NFPROTO_IPV6, 1)],
        _ => &[],
    }
}

/// Adds a user of connection tracking for the family `pf` in the current namespace, as
/// `nf_ct_netns_get` of Linux. The first user registers the hooks.
///
/// # Errors
///
/// Gives `EINVAL` for a family that is not known, and the error of the registration.
pub fn nf_ct_netns_get(pf: u8) -> Result<()> {
    let fams = families(pf);
    if fams.is_empty() {
        return Err(Errno::EINVAL);
    }
    let mut u = USERS.lock();
    for (i, &(f, at)) in fams.iter().enumerate() {
        if u.users[at] == 0 {
            let ops = conntrack_ops(f);
            if let Err(e) = nf_register_net_hooks(&ops) {
                // The families before this one lose the user again.
                for &(_, back) in &fams[..i] {
                    put_locked(&mut u, back);
                }
                return Err(e);
            }
            u.hooks[at] = ops;
        }
        u.users[at] += 1;
    }
    Ok(())
}

fn put_locked(u: &mut CtUsers, at: usize) {
    if u.users[at] == 0 {
        return;
    }
    u.users[at] -= 1;
    if u.users[at] == 0 {
        nf_unregister_net_hooks(&u.hooks[at]);
        u.hooks[at] = Vec::new();
    }
}

/// Removes a user of connection tracking for the family `pf`, as `nf_ct_netns_put` of Linux.
/// The last user removes the hooks.
pub fn nf_ct_netns_put(pf: u8) {
    let mut u = USERS.lock();
    for &(_, at) in families(pf) {
        put_locked(&mut u, at);
    }
}

/// Tells if the hooks of connection tracking of the family `pf` are there in the current
/// namespace.
pub fn nf_ct_active(pf: u8) -> bool {
    families(pf).iter().all(|&(_, at)| USERS.lock().users[at] != 0)
}

/// Drops the connections and the users of a namespace that stops. The hooks go with the lists
/// of netfilter.
fn ns_exit() {
    CT.reset();
    USERS.reset();
}

/// Registers the work of connection tracking for each namespace. `netfilter::init` calls this.
pub(super) fn init() {
    ns::add_ops(|| {}, ns_exit);
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::netfilter::NF_INET_FORWARD;
    use alloc::vec;

    // The tests set the time, so they run one at a time.
    pub(crate) static SERIAL: SpinLock<()> = SpinLock::new(());

    pub(crate) fn state(hook: u8) -> NfHookState {
        NfHookState { hook, pf: NFPROTO_IPV4, in_dev: 0, out_dev: 0 }
    }

    /// An IPv4 packet of `proto` from `src` to `dst` with the transport header `l4`.
    pub(crate) fn ip4(proto: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> NetBuf {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
        p[9] = proto;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p.extend_from_slice(l4);
        NetBuf::from_slice(&p)
    }

    pub(crate) fn udp(sport: u16, dport: u16) -> Vec<u8> {
        let mut h = vec![0u8; 8];
        h[0..2].copy_from_slice(&sport.to_be_bytes());
        h[2..4].copy_from_slice(&dport.to_be_bytes());
        h
    }

    const A: [u8; 4] = [10, 9, 0, 1];
    const B: [u8; 4] = [10, 9, 0, 2];

    /// Runs the hooks of a packet that goes out and of its answer that comes in.
    fn out(mut skb: NetBuf) -> NetBuf {
        assert_eq!(nf_conntrack_in(&mut skb, &state(NF_INET_LOCAL_OUT)), NF_ACCEPT);
        assert_eq!(nf_conntrack_confirm(&mut skb), NF_ACCEPT);
        skb
    }

    fn info(skb: &NetBuf) -> Option<u8> {
        skb.nfct.get().map(|(_, i)| i)
    }

    pub(crate) fn set_time(t: u64) {
        TEST_NOW.store(t, Ordering::Relaxed);
    }

    /// Sets the time and empties the table, for a test that counts the connections.
    pub(crate) fn fresh(t: u64) {
        set_time(t);
        *CT.lock() = CtTable::default();
    }

    #[test]
    fn a_udp_flow_is_new_then_established_and_ends_at_its_timeout() {
        let _s = SERIAL.lock();
        fresh(1000);
        let hz = crate::options::hz();
        let before = nf_conntrack_count();
        assert_eq!(before, 0);
        let a = out(ip4(IPPROTO_UDP, A, B, &udp(4000, 53)));
        assert_eq!(info(&a), Some(IP_CT_NEW));
        let (ct, _) = a.nfct.get().unwrap();
        assert!(ct.is_confirmed());
        assert_eq!(ct.tuple(IP_CT_DIR_REPLY).src_u, 53);
        assert_eq!(ct.expires(), 30 * hz);
        assert_eq!(nf_conntrack_count(), before + 1);
        // A second packet before the reply is new too.
        assert_eq!(info(&out(ip4(IPPROTO_UDP, A, B, &udp(4000, 53)))), Some(IP_CT_NEW));
        // The reply comes in.
        let mut r = ip4(IPPROTO_UDP, B, A, &udp(53, 4000));
        nf_conntrack_in(&mut r, &state(NF_INET_PRE_ROUTING));
        assert_eq!(info(&r), Some(IP_CT_ESTABLISHED_REPLY));
        assert_eq!(nf_conntrack_confirm(&mut r), NF_ACCEPT);
        assert!(ct.status() & IPS_SEEN_REPLY != 0);
        assert!(ct.status() & IPS_ASSURED == 0);
        assert_eq!(info(&out(ip4(IPPROTO_UDP, A, B, &udp(4000, 53)))), Some(IP_CT_ESTABLISHED));
        // After 2 s the flow is a stream, with the timeout of 120 s.
        set_time(1000 + 3 * hz);
        let _ = out(ip4(IPPROTO_UDP, A, B, &udp(4000, 53)));
        assert!(ct.status() & IPS_ASSURED != 0);
        assert_eq!(ct.expires(), 120 * hz);
        // At the timeout the connection goes, and the next packet is new.
        set_time(1000 + 124 * hz);
        assert_eq!(nf_conntrack_count(), before);
        let b = out(ip4(IPPROTO_UDP, A, B, &udp(4000, 53)));
        assert_eq!(info(&b), Some(IP_CT_NEW));
        assert!(!Arc::ptr_eq(b.nfct.get().unwrap().0, ct));
        set_time(1000 + 200 * hz);
        assert_eq!(nf_conntrack_count(), before);
    }

    #[test]
    fn a_packet_that_a_hook_drops_makes_no_connection() {
        let _s = SERIAL.lock();
        fresh(5000);
        let mut a = ip4(IPPROTO_UDP, A, B, &udp(4001, 9));
        nf_conntrack_in(&mut a, &state(NF_INET_LOCAL_OUT));
        assert_eq!(info(&a), Some(IP_CT_NEW));
        // No confirm: the packet went away before `NF_INET_POST_ROUTING`.
        let t = a.nfct.get().unwrap().0.tuple(IP_CT_DIR_ORIGINAL);
        assert!(nf_conntrack_find_get(&t).is_none());
        // A packet with a connection keeps it, as on the loopback device.
        let ct = a.nfct.clone();
        nf_conntrack_in(&mut a, &state(NF_INET_PRE_ROUTING));
        assert_eq!(a.nfct, ct);
        // A fragment gets no connection.
        let mut f = ip4(IPPROTO_UDP, A, B, &udp(4001, 9));
        f.data_mut()[6] = 0x20;
        nf_conntrack_in(&mut f, &state(NF_INET_FORWARD));
        assert_eq!(info(&f), None);
    }

    #[test]
    fn an_echo_has_a_connection_and_an_icmp_error_is_related() {
        let _s = SERIAL.lock();
        fresh(9000);
        // An echo request and its reply.
        let echo = |t: u8, id: u16| {
            let mut h = vec![t, 0, 0, 0, 0, 0, 0, 1];
            h[4..6].copy_from_slice(&id.to_be_bytes());
            h
        };
        let a = out(ip4(IPPROTO_ICMP, A, B, &echo(8, 77)));
        assert_eq!(info(&a), Some(IP_CT_NEW));
        let mut r = ip4(IPPROTO_ICMP, B, A, &echo(0, 77));
        nf_conntrack_in(&mut r, &state(NF_INET_PRE_ROUTING));
        assert_eq!(info(&r), Some(IP_CT_ESTABLISHED_REPLY));
        // An echo reply with no request is not valid.
        let mut x = ip4(IPPROTO_ICMP, B, A, &echo(0, 78));
        nf_conntrack_in(&mut x, &state(NF_INET_PRE_ROUTING));
        assert_eq!(info(&x), None);
        // A port unreachable for a UDP packet is related to its connection, in the reply
        // direction.
        let u = out(ip4(IPPROTO_UDP, A, B, &udp(4002, 7)));
        let mut err = vec![3, 3, 0, 0, 0, 0, 0, 0];
        err.extend_from_slice(ip4(IPPROTO_UDP, A, B, &udp(4002, 7)).data());
        let mut e = ip4(IPPROTO_ICMP, B, A, &err);
        nf_conntrack_in(&mut e, &state(NF_INET_PRE_ROUTING));
        assert_eq!(info(&e), Some(IP_CT_RELATED_REPLY));
        assert!(Arc::ptr_eq(e.nfct.get().unwrap().0, u.nfct.get().unwrap().0));
        // An error for a packet with no connection has none.
        let mut err = vec![3, 3, 0, 0, 0, 0, 0, 0];
        err.extend_from_slice(ip4(IPPROTO_UDP, A, B, &udp(4003, 7)).data());
        let mut e = ip4(IPPROTO_ICMP, B, A, &err);
        nf_conntrack_in(&mut e, &state(NF_INET_PRE_ROUTING));
        assert_eq!(info(&e), None);
    }

    #[test]
    fn a_full_table_drops_a_new_connection_and_a_clash_takes_the_first() {
        let _s = SERIAL.lock();
        fresh(20_000);
        sysctl::write("netfilter/nf_conntrack_max", b"2").unwrap();
        let _ = out(ip4(IPPROTO_UDP, A, B, &udp(1, 9)));
        let _ = out(ip4(IPPROTO_UDP, A, B, &udp(2, 9)));
        let mut c = ip4(IPPROTO_UDP, A, B, &udp(3, 9));
        assert_eq!(nf_conntrack_in(&mut c, &state(NF_INET_LOCAL_OUT)), NF_DROP);
        // A packet of a connection in the table still goes.
        let _ = out(ip4(IPPROTO_UDP, A, B, &udp(1, 9)));
        // After the timeout there is room again.
        set_time(20_000 + 31 * crate::options::hz());
        let _ = out(ip4(IPPROTO_UDP, A, B, &udp(3, 9)));
        assert_eq!(nf_conntrack_count(), 1);
        sysctl::write("netfilter/nf_conntrack_max", b"4096").unwrap();
        // Two first packets of one flow: the second to the table takes the connection of the
        // first.
        let mut x = ip4(IPPROTO_UDP, A, B, &udp(5, 9));
        let mut y = ip4(IPPROTO_UDP, A, B, &udp(5, 9));
        nf_conntrack_in(&mut x, &state(NF_INET_LOCAL_OUT));
        nf_conntrack_in(&mut y, &state(NF_INET_LOCAL_OUT));
        assert_ne!(x.nfct, y.nfct);
        assert_eq!(nf_conntrack_confirm(&mut x), NF_ACCEPT);
        assert_eq!(nf_conntrack_confirm(&mut y), NF_ACCEPT);
        assert_eq!(x.nfct, y.nfct);
        assert_eq!(nf_conntrack_count(), 2);
    }

    /// A TCP header with no options and `data` bytes of data.
    fn tcp(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, data: usize) -> Vec<u8> {
        let mut h = vec![0u8; 20 + data];
        h[0..2].copy_from_slice(&sport.to_be_bytes());
        h[2..4].copy_from_slice(&dport.to_be_bytes());
        h[4..8].copy_from_slice(&seq.to_be_bytes());
        h[8..12].copy_from_slice(&ack.to_be_bytes());
        h[12] = 5 << 4;
        h[13] = flags;
        h[14..16].copy_from_slice(&65535u16.to_be_bytes());
        h
    }

    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    const FIN: u8 = 0x01;
    const RST: u8 = 0x04;

    /// Runs the hooks of a segment that comes in.
    fn came_in(l4: &[u8]) -> NetBuf {
        let mut skb = ip4(IPPROTO_TCP, B, A, l4);
        nf_conntrack_in(&mut skb, &state(NF_INET_PRE_ROUTING));
        nf_conntrack_confirm(&mut skb);
        skb
    }

    fn tcp_out(l4: &[u8]) -> NetBuf {
        out(ip4(IPPROTO_TCP, A, B, l4))
    }

    #[test]
    fn a_tcp_connection_goes_through_its_states() {
        use proto_tcp::*;
        let _s = SERIAL.lock();
        fresh(50_000);
        let hz = crate::options::hz();
        let syn = tcp_out(&tcp(5000, 80, 100, 0, SYN, 0));
        assert_eq!(info(&syn), Some(IP_CT_NEW));
        let (ct, _) = syn.nfct.get().unwrap();
        let ct = ct.clone();
        assert_eq!(tcp_state(&ct), TCP_CONNTRACK_SYN_SENT);
        assert_eq!(ct.expires(), 120 * hz);
        let sa = came_in(&tcp(80, 5000, 900, 101, SYN | ACK, 0));
        assert_eq!(info(&sa), Some(IP_CT_ESTABLISHED_REPLY));
        assert_eq!(tcp_state(&ct), TCP_CONNTRACK_SYN_RECV);
        let a = tcp_out(&tcp(5000, 80, 101, 901, ACK, 0));
        assert_eq!(info(&a), Some(IP_CT_ESTABLISHED));
        assert_eq!(tcp_state(&ct), TCP_CONNTRACK_ESTABLISHED);
        assert!(ct.status() & IPS_ASSURED != 0);
        assert_eq!(ct.expires(), 432_000 * hz);
        // Data that the other end did not take yet gets the timeout of 300 s.
        let _ = tcp_out(&tcp(5000, 80, 101, 901, ACK, 10));
        assert_eq!(ct.expires(), 300 * hz);
        let _ = came_in(&tcp(80, 5000, 901, 111, ACK, 0));
        assert_eq!(ct.expires(), 432_000 * hz);
        // A segment far out of the window is invalid.
        let bad = came_in(&tcp(80, 5000, 901 + 0x4000_0000, 111, ACK, 0));
        assert_eq!(info(&bad), None);
        assert_eq!(tcp_state(&ct), TCP_CONNTRACK_ESTABLISHED);
        // The close.
        let _ = tcp_out(&tcp(5000, 80, 111, 901, FIN | ACK, 0));
        assert_eq!(tcp_state(&ct), TCP_CONNTRACK_FIN_WAIT);
        let _ = came_in(&tcp(80, 5000, 901, 112, FIN | ACK, 0));
        assert_eq!(tcp_state(&ct), TCP_CONNTRACK_LAST_ACK);
        let _ = tcp_out(&tcp(5000, 80, 112, 902, ACK, 0));
        assert_eq!(tcp_state(&ct), TCP_CONNTRACK_TIME_WAIT);
        assert_eq!(ct.expires(), 120 * hz);
        // A SYN of the same ports opens a new connection.
        let again = tcp_out(&tcp(5000, 80, 5000, 0, SYN, 0));
        assert_eq!(info(&again), Some(IP_CT_NEW));
        assert!(!Arc::ptr_eq(again.nfct.get().unwrap().0, &ct));
        assert!(ct.status() & IPS_DYING != 0);
        assert_eq!(nf_conntrack_count(), 1);
    }

    #[test]
    fn a_rst_for_a_syn_ends_the_connection_and_a_lone_ack_is_picked_up() {
        use proto_tcp::*;
        let _s = SERIAL.lock();
        fresh(60_000);
        let hz = crate::options::hz();
        let syn = tcp_out(&tcp(5001, 81, 100, 0, SYN, 0));
        let ct = syn.nfct.get().unwrap().0.clone();
        let rst = came_in(&tcp(81, 5001, 0, 101, RST | ACK, 0));
        assert_eq!(info(&rst), Some(IP_CT_ESTABLISHED_REPLY));
        assert_eq!(tcp_state(&ct), TCP_CONNTRACK_CLOSE);
        assert_eq!(nf_conntrack_count(), 0);
        // A FIN alone, or a SYN with a FIN, is not valid.
        assert_eq!(info(&tcp_out(&tcp(5002, 81, 1, 0, FIN, 0))), None);
        assert_eq!(info(&tcp_out(&tcp(5002, 81, 1, 0, SYN | FIN, 0))), None);
        // An ACK in the middle of a connection starts one, with a short timeout until the
        // reply.
        let mid = tcp_out(&tcp(5003, 81, 7000, 8000, ACK, 0));
        assert_eq!(info(&mid), Some(IP_CT_NEW));
        let ct = mid.nfct.get().unwrap().0.clone();
        assert_eq!(tcp_state(&ct), TCP_CONNTRACK_ESTABLISHED);
        assert_eq!(ct.expires(), 300 * hz);
        // The reply makes `IPS_SEEN_REPLY`, and the next segment makes the connection assured.
        let _ = came_in(&tcp(81, 5003, 8000, 7000, ACK, 0));
        assert!(ct.status() & IPS_ASSURED == 0);
        let _ = tcp_out(&tcp(5003, 81, 7000, 8000, ACK, 0));
        assert!(ct.status() & IPS_ASSURED != 0);
        assert_eq!(ct.expires(), 432_000 * hz);
        // With `nf_conntrack_tcp_loose` 0 the ACK is not valid.
        sysctl::write("netfilter/nf_conntrack_tcp_loose", b"0").unwrap();
        assert_eq!(info(&tcp_out(&tcp(5004, 81, 7000, 8000, ACK, 0))), None);
        sysctl::write("netfilter/nf_conntrack_tcp_loose", b"1").unwrap();
    }

    #[test]
    fn the_tuple_of_ipv6_and_of_the_generic_tracker() {
        let mut p = vec![0u8; 48];
        p[0] = 0x60;
        p[6] = IPPROTO_UDP;
        p[23] = 1;
        p[39] = 2;
        p[40..42].copy_from_slice(&5000u16.to_be_bytes());
        p[42..44].copy_from_slice(&53u16.to_be_bytes());
        let (t, thoff) = nf_ct_get_tuple(NFPROTO_IPV6, &p).unwrap();
        assert_eq!((t.src_u, t.dst_u, thoff, t.dst[15]), (5000, 53, 40, 2));
        let r = t.invert().unwrap();
        assert_eq!((r.src_u, r.dst_u, r.src[15]), (53, 5000, 2));
        // A fragment header makes no tuple.
        let mut f = vec![0u8; 56];
        f[0] = 0x60;
        f[6] = 44;
        f[40] = IPPROTO_UDP;
        assert!(nf_ct_get_tuple(NFPROTO_IPV6, &f).is_none());
        // GRE has the addresses only.
        let g = ip4(47, A, B, &[1, 2, 3, 4]);
        let (t, _) = nf_ct_get_tuple(NFPROTO_IPV4, g.data()).unwrap();
        assert_eq!((t.protonum, t.src_u, t.dst_u), (47, 0, 0));
        assert_eq!(t.invert().unwrap().src[..4], B);
    }

    #[test]
    fn the_hooks_are_there_while_a_user_needs_them() {
        let _s = SERIAL.lock();
        let h = super::super::hook_count(NFPROTO_IPV6, NF_INET_LOCAL_IN);
        assert!(!nf_ct_active(NFPROTO_IPV6));
        nf_ct_netns_get(NFPROTO_IPV6).unwrap();
        nf_ct_netns_get(NFPROTO_IPV6).unwrap();
        assert!(nf_ct_active(NFPROTO_IPV6));
        // The confirm and the change of the source of NAT.
        assert_eq!(super::super::hook_count(NFPROTO_IPV6, NF_INET_LOCAL_IN), h + 2);
        nf_ct_netns_put(NFPROTO_IPV6);
        assert!(nf_ct_active(NFPROTO_IPV6));
        nf_ct_netns_put(NFPROTO_IPV6);
        assert!(!nf_ct_active(NFPROTO_IPV6));
        assert_eq!(super::super::hook_count(NFPROTO_IPV6, NF_INET_LOCAL_IN), h);
        assert_eq!(nf_ct_netns_get(3), Err(Errno::EINVAL));
    }
}

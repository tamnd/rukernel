//! The multicast groups of IPv6 and the Multicast Listener Discovery of RFC 2710 and RFC 3810,
//! as net/ipv6/mcast.c of Linux.
//!
//! A device is in the solicited node group of each of its addresses, and in the groups that
//! sockets join with `IPV6_JOIN_GROUP`. A group of the sockets has a count of the users. The
//! first user sends a report that the device joins the group, and the last user sends a report
//! that it leaves. A query of MLD gets an answer after a random delay below the largest delay
//! of the query: a report of each group, or of the group of the query. The group of all of the
//! nodes and the groups of the interface scope get no report, as `MAF_NOREPORT` of Linux.
//!
//! The device sends MLDv2 reports. It sends MLDv1 reports after it gets an MLDv1 query, for the
//! time of `mc_v1_seen` of Linux, or when `force_mld_version` is 1.
//!
//! The device does not keep the lists of the sources of MLDv2, and it does not send a report
//! two times as the robustness variable asks.

use crate::checksum;
use crate::ip::{self, Ip};
use crate::ipv6::{self, ALL_NODES, ALL_ROUTERS, HLEN, Header, PROTO_ICMPV6};
use crate::stack::{count, now_ms};
use crate::stack6::{self, COUNTERS6, ROUTES6};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::if_addr::IFA_F_TENTATIVE;
use rk_frame::sync::SpinLock;
use rk_net::buf::{HEADROOM, NetBuf};
use rk_net::dev::{self, LinkKind, NetDevice};
use rk_net::ns::PerNet;
use rk_net::sysctl::{Family, Scope};
use rk_vfs::inode::Result;

/// `ICMPV6_MGM_QUERY`: a query of MLD.
pub(crate) const MLD_QUERY: u8 = 130;
/// `ICMPV6_MGM_REPORT`: an MLDv1 report.
const MLD1_REPORT: u8 = 131;
/// `ICMPV6_MGM_REDUCTION`: an MLDv1 done message.
const MLD1_DONE: u8 = 132;
/// `ICMPV6_MLD2_REPORT`: an MLDv2 report.
const MLD2_REPORT: u8 = 143;
/// The record of a group without sources in an answer to a query.
const MODE_IS_EXCLUDE: u8 = 2;
/// The record of a group that a device leaves.
const CHANGE_TO_INCLUDE: u8 = 3;
/// The record of a group that a device joins.
const CHANGE_TO_EXCLUDE: u8 = 4;
/// The group of the MLDv2 routers, `ff02::16`.
const ALL_MLDV2_ROUTERS: Ip = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16];
/// The hop-by-hop header `NEXTHDR_HOP`.
const NEXT_HOP: u8 = 0;
/// The time that the device stays in the mode of MLDv1 after an MLDv1 query, in milliseconds:
/// the robustness variable 2 times the query interval of 125 s, and the query response
/// interval of 10 s, as `mld_update_qi` and `mld_set_v1_mode` of Linux.
const V1_TIMEOUT_MS: u64 = 2 * 125_000 + 10_000;

/// A group that sockets joined on an interface, and the count of its users.
struct Group {
    ifindex: u32,
    addr: Ip,
    users: u32,
}

/// An answer to a query that waits: the interface, the group or `None` for all of the groups,
/// MLDv1 or MLDv2, and the time to send it in milliseconds.
struct Answer {
    ifindex: u32,
    group: Option<Ip>,
    v1: bool,
    at: u64,
}

/// The groups of the sockets.
static GROUPS: PerNet<SpinLock<Vec<Group>>> = PerNet::new(|| SpinLock::new(Vec::new()));
/// The answers that wait.
static ANSWERS: PerNet<SpinLock<Vec<Answer>>> = PerNet::new(|| SpinLock::new(Vec::new()));
/// The interfaces that got an MLDv1 query, and the end of their MLDv1 mode in milliseconds.
static V1_SEEN: PerNet<SpinLock<BTreeMap<u32, u64>>> =
    PerNet::new(|| SpinLock::new(BTreeMap::new()));

/// A random number below `n`, or 0 if `n` is 0.
pub(crate) fn random_below(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    random_u64() % n
}

/// 64 random bits, from the random seed of the machine and a counter, mixed as splitmix64.
pub(crate) fn random_u64() -> u64 {
    use core::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let mut x = rk_frame::arch::random_seed() ^ n.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// Tells if a device sends reports for the group `a`: not the group of all of the nodes, and
/// not a group of the interface scope or below, as `MAF_NOREPORT` of Linux.
fn reported(a: &Ip) -> bool {
    *a != ALL_NODES && a[1] & 0xf > 1
}

/// Tells if a device can send MLD: a device with a link layer for multicast, or a TUN device.
fn sends_mld(dev: &NetDevice) -> bool {
    matches!(dev.kind(), LinkKind::Ether | LinkKind::Tun) && dev.is_up()
}

/// Tells if a socket of the interface `ifindex` joined the group `addr`.
pub(crate) fn joined(ifindex: u32, addr: &Ip) -> bool {
    GROUPS.lock().iter().any(|g| g.ifindex == ifindex && g.addr == *addr)
}

/// The groups of the interface `ifindex` that get reports: the solicited node groups of its
/// addresses and the groups of the sockets, each one time.
fn groups_of(ifindex: u32) -> Vec<Ip> {
    let mut out: Vec<Ip> =
        ROUTES6.lock().addrs_of(ifindex).map(|a| ipv6::solicited_node(&a.addr)).collect();
    out.extend(GROUPS.lock().iter().filter(|g| g.ifindex == ifindex).map(|g| g.addr));
    out.sort_unstable();
    out.dedup();
    out.retain(reported);
    out
}

/// Tells if the interface sends MLDv1, as `mld_in_v1_mode` of Linux.
fn v1_mode(ifindex: u32) -> bool {
    let conf = |scope| rk_net::sysctl::conf(Family::Ipv6, scope, "force_mld_version");
    match (conf(Scope::All), conf(Scope::Dev(ifindex))) {
        (1, _) | (_, 1) => return true,
        (2, _) | (_, 2) => return false,
        _ => {}
    }
    let mut seen = V1_SEEN.lock();
    match seen.get(&ifindex) {
        Some(&end) if end > now_ms() => true,
        Some(_) => {
            seen.remove(&ifindex);
            false
        }
        None => false,
    }
}

/// Joins the group `addr` on the interface `ifindex` for a socket, as `__ipv6_dev_mc_inc` of
/// Linux. The first user sends a report.
pub(crate) fn join(ifindex: u32, addr: &Ip) {
    {
        let mut g = GROUPS.lock();
        if let Some(x) = g.iter_mut().find(|x| x.ifindex == ifindex && x.addr == *addr) {
            x.users += 1;
            return;
        }
        g.push(Group { ifindex, addr: *addr, users: 1 });
    }
    if let Some(d) = dev::by_index(ifindex) {
        report_change(&d, addr, true);
    }
}

/// Leaves the group `addr` on the interface `ifindex` for a socket, as `__ipv6_dev_mc_dec` of
/// Linux. The last user sends a report.
pub(crate) fn leave(ifindex: u32, addr: &Ip) {
    {
        let mut g = GROUPS.lock();
        let Some(at) = g.iter().position(|x| x.ifindex == ifindex && x.addr == *addr) else {
            return;
        };
        g[at].users -= 1;
        if g[at].users > 0 {
            return;
        }
        g.remove(at);
    }
    // A group that is a solicited node group of an address stays.
    if ROUTES6.lock().addrs_of(ifindex).any(|a| ipv6::solicited_node(&a.addr) == *addr) {
        return;
    }
    if let Some(d) = dev::by_index(ifindex) {
        report_change(&d, addr, false);
    }
}

/// Sends the reports of the groups of the sockets of a device that goes up, as `ipv6_mc_up` of
/// Linux.
pub(crate) fn up(dev: &NetDevice) {
    let ifindex = dev.ifindex();
    let groups: Vec<Ip> =
        GROUPS.lock().iter().filter(|g| g.ifindex == ifindex).map(|g| g.addr).collect();
    for g in &groups {
        report_change(dev, g, true);
    }
}

/// Sends a report that `dev` joins or leaves `group`, as `igmp6_join_group` and
/// `igmp6_leave_group` of Linux.
pub(crate) fn report_change(dev: &NetDevice, group: &Ip, join: bool) {
    if !sends_mld(dev) || !reported(group) {
        return;
    }
    if v1_mode(dev.ifindex()) {
        let (kind, dst) = if join { (MLD1_REPORT, *group) } else { (MLD1_DONE, ALL_ROUTERS) };
        send_v1(dev, kind, dst, group);
    } else {
        let mode = if join { CHANGE_TO_EXCLUDE } else { CHANGE_TO_INCLUDE };
        send_v2(dev, &[(mode, *group)]);
    }
}

/// The largest delay of the answer to the query `msg` in milliseconds, as `mldv2_mrc` of Linux.
pub(crate) fn max_delay(msg: &[u8], v1: bool) -> u64 {
    let code = u64::from(u16::from_be_bytes([msg[4], msg[5]]));
    if v1 || code < 0x8000 {
        return code;
    }
    let mant = code & 0xfff;
    let exp = (code >> 12) & 7;
    (mant | 0x1000) << (exp + 3)
}

/// Takes a query of MLD, as `igmp6_event_query` of Linux. A query from an address that is not
/// link local, or with a bad length, goes away. A general query has the group `::`.
pub(crate) fn query_input(dev: &NetDevice, h: &Header, msg: &[u8]) {
    let v1 = match msg.len() {
        24 => true,
        n if n >= 28 => false,
        _ => return,
    };
    if !ipv6::is_link_local(&h.src) {
        return;
    }
    let ifindex = dev.ifindex();
    let Ok(group) = <Ip>::try_from(&msg[8..24]) else { return };
    let group = if group == ip::ANY {
        // A general query goes to the group of all of the nodes, as RFC 3810 asks.
        if h.dst != ALL_NODES {
            return;
        }
        None
    } else {
        if !ipv6::is_multicast(&group) || h.dst != group {
            return;
        }
        let member = joined(ifindex, &group)
            || ROUTES6.lock().addrs_of(ifindex).any(|a| ipv6::solicited_node(&a.addr) == group);
        if !member || !reported(&group) {
            return;
        }
        Some(group)
    };
    if v1 {
        V1_SEEN.lock().insert(ifindex, now_ms() + V1_TIMEOUT_MS);
    }
    let at = now_ms() + random_below(max_delay(msg, v1));
    let mut answers = ANSWERS.lock();
    // An answer that waits for the same groups keeps the earlier time.
    if let Some(a) = answers.iter_mut().find(|a| a.ifindex == ifindex && a.group == group) {
        a.at = a.at.min(at);
        a.v1 = v1;
        return;
    }
    answers.push(Answer { ifindex, group, v1, at });
}

/// Sends the answers to the queries that are due. The timers of IPv6 call this.
pub(crate) fn tick(now: u64) {
    let due: Vec<Answer> = {
        let mut answers = ANSWERS.lock();
        if answers.is_empty() {
            return;
        }
        let (due, wait) = answers.drain(..).partition(|a| a.at <= now);
        *answers = wait;
        due
    };
    for a in due {
        let Some(d) = dev::by_index(a.ifindex).filter(|d| sends_mld(d)) else { continue };
        let groups = match a.group {
            Some(g) => Vec::from([g]),
            None => groups_of(a.ifindex),
        };
        if a.v1 {
            for g in &groups {
                send_v1(&d, MLD1_REPORT, *g, g);
            }
        } else if !groups.is_empty() {
            let records: Vec<(u8, Ip)> = groups.iter().map(|g| (MODE_IS_EXCLUDE, *g)).collect();
            send_v2(&d, &records);
        }
    }
}

/// Forgets the groups and the answers of an interface that goes away.
pub(crate) fn forget(ifindex: u32) {
    GROUPS.lock().retain(|g| g.ifindex != ifindex);
    ANSWERS.lock().retain(|a| a.ifindex != ifindex);
    V1_SEEN.lock().remove(&ifindex);
}

/// The source of an MLD message: a link local address that is not tentative, or `::` if the
/// device has none yet, as RFC 3590 allows.
fn source(ifindex: u32) -> Ip {
    ROUTES6
        .lock()
        .addrs_of(ifindex)
        .find(|a| ipv6::is_link_local(&a.addr) && a.flags & IFA_F_TENTATIVE == 0)
        .map_or(ip::ANY, |a| a.addr)
}

/// Sends an MLDv1 message of the type `kind` about `group` to `dst`, as `igmp6_send` of Linux.
fn send_v1(dev: &NetDevice, kind: u8, dst: Ip, group: &Ip) {
    let mut msg = Vec::with_capacity(24);
    msg.extend_from_slice(&[kind, 0, 0, 0, 0, 0, 0, 0]);
    msg.extend_from_slice(group);
    send(dev, dst, msg);
}

/// Sends an MLDv2 report with the records `records` of the groups, as `mld_send_report` of
/// Linux.
fn send_v2(dev: &NetDevice, records: &[(u8, Ip)]) {
    // The records of one report fit in the minimum MTU of IPv6.
    for chunk in records.chunks(50) {
        let mut msg = Vec::with_capacity(8 + 20 * chunk.len());
        msg.extend_from_slice(&[MLD2_REPORT, 0, 0, 0, 0, 0]);
        msg.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        for (mode, group) in chunk {
            msg.extend_from_slice(&[*mode, 0, 0, 0]);
            msg.extend_from_slice(group);
        }
        send(dev, ALL_MLDV2_ROUTERS, msg);
    }
}

/// Sends the MLD message `msg` to `dst` with the router alert option and the hop limit 1. The
/// function computes the checksum.
fn send(dev: &NetDevice, dst: Ip, mut msg: Vec<u8>) {
    let src = source(dev.ifindex());
    let sum = checksum::upper(&src, &dst, PROTO_ICMPV6, &msg);
    msg[2..4].copy_from_slice(&sum.to_be_bytes());
    // The hop-by-hop header: the router alert option for MLD, then two bytes of padding.
    let hop = [PROTO_ICMPV6, 0, 5, 2, 0, 0, 1, 0];
    let mut h = Header::new(src, dst, NEXT_HOP, hop.len() + msg.len());
    h.hops = 1;
    let mut buf = NetBuf::new(HEADROOM, HLEN + hop.len() + msg.len());
    buf.extend_from_slice(&h.to_bytes());
    buf.extend_from_slice(&hop);
    buf.extend_from_slice(&msg);
    stack6::count_icmp_out(&msg);
    count(&COUNTERS6.out_requests);
    count(&COUNTERS6.out_mcast);
    // A lost report is like a lost frame. A router asks again with a query.
    let _ = stack6::transmit_mcast(dev, &dst, buf);
}

/// Joins the group `group` for a socket, as `ipv6_sock_mc_join` of Linux. With the interface
/// 0 the route to the group gives the interface. Gives the interface.
///
/// # Errors
///
/// Gives `EINVAL` for an address that is not multicast, and `ENODEV` for an interface that is
/// not there.
pub(crate) fn sock_join(ifindex: u32, group: &Ip) -> Result<u32> {
    if !ipv6::is_multicast(group) {
        return Err(Errno::EINVAL);
    }
    let ifindex = match ifindex {
        0 => stack6::route(group, 0).map_err(|_| Errno::ENODEV)?.ifindex,
        i => i,
    };
    if dev::by_index(ifindex).is_none() {
        return Err(Errno::ENODEV);
    }
    join(ifindex, group);
    Ok(ifindex)
}

/// Clears the groups of a namespace that stops.
pub(crate) fn ns_exit() {
    GROUPS.reset();
    ANSWERS.reset();
    V1_SEEN.reset();
}

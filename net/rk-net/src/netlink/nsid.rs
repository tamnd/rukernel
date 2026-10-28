//! The IDs of the other network namespaces: `RTM_NEWNSID` and `RTM_GETNSID`, as
//! net/core/net_namespace.c of Linux.
//!
//! Each namespace has its own table. The table gives a number, the nsid, to a peer namespace.
//! `ip netns set` gives an nsid, and a link with its other end in a peer namespace gets an nsid
//! when the kernel tells about the link (`IFLA_LINK_NETNSID`).

use super::msg::{Attrs, Builder};
use super::{Request, notify, register};
use crate::ns::{self, NetNs, PerNet};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::rtnetlink::{RTM_GETNSID, RTM_NEWNSID, RTNLGRP_NSID};
use rk_frame::sync::SpinLock;
use rk_vfs::inode::Result;

/// The attributes of the nsid messages, `NETNSA_*` of <linux/net_namespace.h>. rk-abigen does
/// not take this header yet.
const NETNSA_NSID: u32 = 1;
/// The PID of a task in the peer namespace.
const NETNSA_PID: u32 = 2;
/// A file of the peer namespace.
const NETNSA_FD: u32 = 3;
/// The nsid of a namespace that the request asks about.
const NETNSA_TARGET_NSID: u32 = 4;
/// The largest attribute.
const NETNSA_MAX: u16 = 5;
/// The value of `NETNSA_NSID` for a peer with no nsid, `NETNSA_NSID_NOT_ASSIGNED`.
const NOT_ASSIGNED: i32 = -1;
/// The size of `struct rtgenmsg` with its padding.
const RTGEN_LEN: usize = 4;

/// The nsids of the current namespace: the ID of the peer namespace to the nsid, as
/// `netns_ids` of `struct net` in Linux.
static IDS: PerNet<SpinLock<BTreeMap<u32, i32>>> = PerNet::new(|| SpinLock::new(BTreeMap::new()));

pub(super) fn init() {
    register(0, RTM_NEWNSID, Some(newid), None, false);
    register(0, RTM_GETNSID, Some(getid), Some(dump), false);
    ns::add_ops(|| {}, exit);
}

/// Removes a namespace that stops from the tables of the other namespaces, as
/// `unhash_nsid` of Linux.
fn exit() {
    let gone = ns::current().id();
    IDS.reset();
    for index in ns::indices() {
        let _in = ns::enter_index(index);
        IDS.lock().remove(&gone);
    }
}

/// The nsid of `peer` in the current namespace, or `NETNSA_NSID_NOT_ASSIGNED`, as `peernet2id`
/// of Linux.
pub fn peer_id(peer: &NetNs) -> i32 {
    IDS.lock().get(&peer.id()).copied().unwrap_or(NOT_ASSIGNED)
}

/// Gives `peer` an nsid in the current namespace. `want` is the nsid to use, or below 0 for
/// the smallest free nsid. Gives `EEXIST` if the nsid is in use, as `alloc_netid` of Linux.
fn alloc(peer: &NetNs, want: i32) -> Result<i32> {
    let mut ids = IDS.lock();
    if let Some(&id) = ids.get(&peer.id()) {
        return Ok(id);
    }
    let used = |n: i32| ids.values().any(|&v| v == n);
    let id = if want >= 0 {
        if used(want) {
            return Err(Errno::EEXIST);
        }
        want
    } else {
        (0..i32::MAX).find(|&n| !used(n)).ok_or(Errno::ENOSPC)?
    };
    ids.insert(peer.id(), id);
    Ok(id)
}

/// The nsid of `peer`, with a new nsid if it has none, as `peernet2id_alloc` of Linux. Linux
/// also sends `RTM_NEWNSID` for a new nsid. This one does not, because the caller can be in the
/// middle of a message of a link.
pub fn peer_id_alloc(peer: &NetNs) -> i32 {
    alloc(peer, NOT_ASSIGNED).unwrap_or(NOT_ASSIGNED)
}

/// The message of an nsid, as `rtnl_net_fill` of Linux.
fn fill(ty: u32, flags: u16, seq: u32, portid: u32, nsid: i32) -> Vec<u8> {
    let mut b = Builder::new(ty as u16, flags, seq, portid);
    b.fixed(&[0; RTGEN_LEN]);
    b.u32(NETNSA_NSID as u16, nsid as u32);
    b.finish()
}

/// The peer namespace of a request: `NETNSA_PID` or `NETNSA_FD`.
fn peer_of(a: &Attrs<'_>) -> Result<Option<Arc<NetNs>>> {
    if let Some(pid) = a.u32(NETNSA_PID)? {
        return ns::by_pid(pid as i32).map(Some);
    }
    if let Some(fd) = a.u32(NETNSA_FD)? {
        return ns::by_fd(fd as i32).map(Some);
    }
    Ok(None)
}

/// `RTM_NEWNSID`: gives a peer namespace an nsid, as `rtnl_net_newid` of Linux.
fn newid(req: &Request<'_>) -> Result<()> {
    let (_, a) = req.parse(RTGEN_LEN, NETNSA_MAX)?;
    let nsid = a.u32(NETNSA_NSID)?.ok_or(Errno::EINVAL)? as i32;
    let peer = peer_of(&a)?.ok_or(Errno::EINVAL)?;
    if peer_id(&peer) >= 0 {
        return Err(Errno::EEXIST);
    }
    let id = alloc(&peer, nsid)?;
    notify(RTNLGRP_NSID, fill(RTM_NEWNSID, 0, req.hdr.seq, req.portid, id), req.origin());
    Ok(())
}

/// `RTM_GETNSID`: gives the nsid of a peer namespace, as `rtnl_net_getid` of Linux.
fn getid(req: &Request<'_>) -> Result<()> {
    let (_, a) = req.parse(RTGEN_LEN, NETNSA_MAX)?;
    if a.has(NETNSA_TARGET_NSID) {
        return Err(Errno::EOPNOTSUPP);
    }
    let nsid = match peer_of(&a)? {
        Some(peer) => peer_id(&peer),
        None => {
            // A peer by its nsid must exist, as `get_net_ns_by_id` of Linux.
            let want = a.u32(NETNSA_NSID)?.ok_or(Errno::EINVAL)? as i32;
            if !IDS.lock().values().any(|&v| v == want) {
                return Err(Errno::ENOENT);
            }
            want
        }
    };
    req.reply(fill(RTM_NEWNSID, 0, req.hdr.seq, req.portid, nsid));
    Ok(())
}

/// The dump of `RTM_GETNSID`: all nsids of the namespace, as `rtnl_net_dumpid` of Linux.
fn dump(req: &Request<'_>) -> Result<Vec<Vec<u8>>> {
    let mut ids: Vec<i32> = IDS.lock().values().copied().collect();
    ids.sort_unstable();
    let multi = rk_abi::native::netlink::NLM_F_MULTI as u16;
    Ok(ids.into_iter().map(|id| fill(RTM_NEWNSID, multi, req.hdr.seq, req.portid, id)).collect())
}

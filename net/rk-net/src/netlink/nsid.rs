//! The IDs of the other network namespaces: `RTM_NEWNSID` and `RTM_GETNSID`, as
//! net/core/net_namespace.c of Linux.
//!
//! Each namespace has its own table. The table gives a number, the nsid, to a peer namespace.
//! `ip netns set` gives an nsid, and a link with its other end in a peer namespace gets an nsid
//! when the kernel tells about the link (`IFLA_LINK_NETNSID`). Each new nsid goes to the
//! listeners of `RTNLGRP_NSID` of the namespace as `RTM_NEWNSID`, and when the peer namespace
//! stops, its nsid goes as `RTM_DELNSID`.

use super::msg::{Attrs, Builder};
use super::{Origin, Request, has_listeners, notify, register};
use crate::ns::{self, NetNs, PerNet};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::rtnetlink::{RTM_DELNSID, RTM_GETNSID, RTM_NEWNSID, RTNLGRP_NSID};
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
/// The nsid of the target namespace in the namespace of the request, in a reply to a request
/// with `NETNSA_TARGET_NSID`.
const NETNSA_CURRENT_NSID: u32 = 5;
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
/// `unhash_nsid` of Linux. Each namespace that had an nsid for it sends `RTM_DELNSID`.
fn exit() {
    let gone = ns::current().id();
    IDS.reset();
    for index in ns::indices() {
        let _in = ns::enter_index(index);
        let id = IDS.lock().remove(&gone);
        if let Some(id) = id {
            notify_id(RTM_DELNSID, id, 0, Origin::KERNEL);
        }
    }
}

/// Sends a change of an nsid of the current namespace to `RTNLGRP_NSID`, as
/// `rtnl_net_notifyid` of Linux.
fn notify_id(ty: u32, id: i32, seq: u32, origin: Origin) {
    if has_listeners(RTNLGRP_NSID) || origin.echo {
        notify(RTNLGRP_NSID, fill(ty, 0, seq, origin.portid, id, None), origin);
    }
}

/// The nsid of `peer` in the current namespace, or `NETNSA_NSID_NOT_ASSIGNED`, as `peernet2id`
/// of Linux.
pub fn peer_id(peer: &NetNs) -> i32 {
    IDS.lock().get(&peer.id()).copied().unwrap_or(NOT_ASSIGNED)
}

/// Gives `peer` an nsid in the current namespace. `want` is the nsid to use, or below 0 for
/// the smallest free nsid. Gives `EEXIST` if the nsid is in use, as `alloc_netid` of Linux.
/// Gives the nsid, and `true` if it is new.
fn alloc(peer: &NetNs, want: i32) -> Result<(i32, bool)> {
    let mut ids = IDS.lock();
    if let Some(&id) = ids.get(&peer.id()) {
        return Ok((id, false));
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
    Ok((id, true))
}

/// The nsid of `peer`, with a new nsid if it has none, as `peernet2id_alloc` of Linux. A new
/// nsid goes to the listeners as `RTM_NEWNSID`. The caller holds no lock of netlink.
pub fn peer_id_alloc(peer: &NetNs) -> i32 {
    match alloc(peer, NOT_ASSIGNED) {
        Ok((id, true)) => {
            notify_id(RTM_NEWNSID, id, 0, Origin::KERNEL);
            id
        }
        Ok((id, false)) => id,
        Err(_) => NOT_ASSIGNED,
    }
}

/// The message of an nsid, as `rtnl_net_fill` of Linux. `current` is the value of
/// `NETNSA_CURRENT_NSID`, for a request with a target namespace.
fn fill(ty: u32, flags: u16, seq: u32, portid: u32, nsid: i32, current: Option<i32>) -> Vec<u8> {
    let mut b = Builder::new(ty as u16, flags, seq, portid);
    b.fixed(&[0; RTGEN_LEN]);
    b.u32(NETNSA_NSID as u16, nsid as u32);
    if let Some(c) = current {
        b.u32(NETNSA_CURRENT_NSID as u16, c as u32);
    }
    b.finish()
}

/// The peer namespace with the nsid `id` in the current namespace, as `get_net_ns_by_id` of
/// Linux.
fn by_nsid(id: i32) -> Option<Arc<NetNs>> {
    let peer = IDS.lock().iter().find(|&(_, &v)| v == id).map(|(&k, _)| k)?;
    ns::by_id(peer)
}

/// The namespace of `NETNSA_TARGET_NSID`, as `rtnl_get_net_ns_capable` of Linux. Gives
/// `EINVAL` if the current namespace has no peer with the nsid.
fn target_of(a: &Attrs<'_>) -> Result<Option<Arc<NetNs>>> {
    match a.u32(NETNSA_TARGET_NSID)? {
        Some(id) => by_nsid(id as i32).map(Some).ok_or(Errno::EINVAL),
        None => Ok(None),
    }
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
    let (id, _) = alloc(&peer, nsid)?;
    notify_id(RTM_NEWNSID, id, req.hdr.seq, req.origin());
    Ok(())
}

/// `RTM_GETNSID`: gives the nsid of a peer namespace, as `rtnl_net_getid` of Linux. With
/// `NETNSA_TARGET_NSID` the reply gives the nsid of the peer in the target namespace, and the
/// nsid of the peer in the current namespace as `NETNSA_CURRENT_NSID`.
fn getid(req: &Request<'_>) -> Result<()> {
    let (_, a) = req.parse(RTGEN_LEN, NETNSA_MAX)?;
    let peer = match peer_of(&a)? {
        Some(peer) => peer,
        None => {
            // A peer by its nsid must exist, as `get_net_ns_by_id` of Linux.
            let want = a.u32(NETNSA_NSID)?.ok_or(Errno::EINVAL)? as i32;
            by_nsid(want).ok_or(Errno::ENOENT)?
        }
    };
    let target = target_of(&a)?;
    let current = target.as_ref().map(|_| peer_id(&peer));
    let nsid = match &target {
        Some(t) => {
            let _in = ns::enter(t);
            peer_id(&peer)
        }
        None => peer_id(&peer),
    };
    req.reply(fill(RTM_NEWNSID, 0, req.hdr.seq, req.portid, nsid, current));
    Ok(())
}

/// The dump of `RTM_GETNSID`: all nsids of the namespace, as `rtnl_net_dumpid` of Linux. A
/// request with the strict checks can give `NETNSA_TARGET_NSID`, and then the dump has the
/// nsids of the target namespace, each with its nsid in the current namespace.
fn dump(req: &Request<'_>) -> Result<Vec<Vec<u8>>> {
    let mut target = None;
    if req.strict {
        let (_, a) = req.parse(RTGEN_LEN, NETNSA_MAX)?;
        // Only the target is a valid attribute, as `rtnl_valid_dump_net_req` of Linux.
        if (0..=u32::from(NETNSA_MAX)).any(|t| t != NETNSA_TARGET_NSID && a.has(t)) {
            return Err(Errno::EINVAL);
        }
        target = target_of(&a)?;
    }
    let multi = rk_abi::native::netlink::NLM_F_MULTI as u16;
    let Some(target) = target else {
        let mut ids: Vec<i32> = IDS.lock().values().copied().collect();
        ids.sort_unstable();
        return Ok(ids
            .into_iter()
            .map(|id| fill(RTM_NEWNSID, multi, req.hdr.seq, req.portid, id, None))
            .collect());
    };
    let mut peers: Vec<(i32, u32)> = {
        let _in = ns::enter(&target);
        IDS.lock().iter().map(|(&peer, &id)| (id, peer)).collect()
    };
    peers.sort_unstable();
    Ok(peers
        .into_iter()
        .map(|(id, peer)| {
            let current = ns::by_id(peer).map_or(NOT_ASSIGNED, |p| peer_id(&p));
            fill(RTM_NEWNSID, multi, req.hdr.seq, req.portid, id, Some(current))
        })
        .collect())
}

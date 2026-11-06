//! The netlink protocol of netfilter, `NETLINK_NETFILTER`, as net/netfilter/nfnetlink.c of
//! Linux.
//!
//! The high byte of the message type is the subsystem, and the low byte is the message of the
//! subsystem. Each message starts with `struct nfgenmsg`. A program sends the changes of
//! nf_tables in a batch: `NFNL_MSG_BATCH_BEGIN`, the messages, and `NFNL_MSG_BATCH_END`. The
//! kernel runs all of the messages, and then commits all of the changes, or none of them if one
//! message failed. The errors and the acks of the batch come after the commit or the abort, so
//! that the program gets each error one time.

use super::msg::{self, Attrs, HDRLEN, Header};
use super::{Flow, NetlinkSocket, Request, broadcast, listeners, lookup, net_admin};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::Cell;
use rk_abi::Errno;
use rk_abi::native::netlink::{NLM_F_ACK, NLM_F_DUMP, NLM_F_ECHO, NLM_F_REQUEST, NLMSG_MIN_TYPE};
use rk_vfs::inode::Result;

/// The protocol number, `NETLINK_NETFILTER` of <linux/netlink.h>.
pub const NETLINK_NETFILTER: u32 = 12;

// The subsystems, `NFNL_SUBSYS_*` of <linux/netfilter/nfnetlink.h>. rk-abigen does not take
// this header yet, so the values are written by hand.
/// The subsystem ctnetlink, for the connections of conntrack.
pub const NFNL_SUBSYS_CTNETLINK: u8 = 1;
/// The subsystem nf_tables.
pub const NFNL_SUBSYS_NFTABLES: u8 = 10;
/// The number of subsystems, `NFNL_SUBSYS_COUNT`.
const NFNL_SUBSYS_COUNT: u16 = 13;

/// The first message of a batch, `NFNL_MSG_BATCH_BEGIN`.
pub const NFNL_MSG_BATCH_BEGIN: u16 = NLMSG_MIN_TYPE as u16;
/// The last message of a batch, `NFNL_MSG_BATCH_END`.
pub const NFNL_MSG_BATCH_END: u16 = NLMSG_MIN_TYPE as u16 + 1;

/// The attribute of `NFNL_MSG_BATCH_BEGIN` with the generation that the batch expects,
/// `NFNL_BATCH_GENID`.
pub const NFNL_BATCH_GENID: u32 = 1;

/// The version of `struct nfgenmsg`, `NFNETLINK_V0`.
pub const NFNETLINK_V0: u8 = 0;
/// The size of `struct nfgenmsg`.
pub const NFGENMSG_LEN: usize = 4;

/// The group of the changes of nf_tables, `NFNLGRP_NFTABLES`.
pub const NFNLGRP_NFTABLES: u32 = 7;
/// The number of groups, `NFNLGRP_MAX`.
pub(super) const NGROUPS: u32 = 9;

/// The subsystem of a message type, `NFNL_SUBSYS_ID`.
pub const fn nfnl_subsys_id(ty: u16) -> u8 {
    (ty >> 8) as u8
}

/// The message of a message type in its subsystem, `NFNL_MSG_TYPE`.
pub const fn nfnl_msg_type(ty: u16) -> u8 {
    ty as u8
}

/// The header of a message of netfilter, `struct nfgenmsg`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NfGenMsg {
    /// The family, `NFPROTO_*`.
    pub nfgen_family: u8,
    /// The version, `NFNETLINK_V0`.
    pub version: u8,
    /// The ID of a resource, in the byte order of the network. nf_tables puts the low 16 bits of
    /// the generation in it.
    pub res_id: u16,
}

impl NfGenMsg {
    /// Reads the header at the start of `b`.
    fn parse(b: &[u8]) -> Option<Self> {
        let b = b.get(..NFGENMSG_LEN)?;
        Some(Self { nfgen_family: b[0], version: b[1], res_id: u16::from_be_bytes([b[2], b[3]]) })
    }

    /// The bytes of the header.
    pub fn bytes(&self) -> [u8; NFGENMSG_LEN] {
        let r = self.res_id.to_be_bytes();
        [self.nfgen_family, self.version, r[0], r[1]]
    }
}

/// Starts a message of netfilter with its header, as `nfnl_msg_put` of Linux.
pub fn nfnl_msg_put(
    portid: u32,
    seq: u32,
    ty: u16,
    flags: u16,
    family: u8,
    version: u8,
    res_id: u16,
) -> msg::Builder {
    let mut b = msg::Builder::new(ty, flags, seq, portid);
    b.fixed(&NfGenMsg { nfgen_family: family, version, res_id }.bytes());
    b
}

/// A request to a subsystem, as `struct nfnl_info` of Linux.
pub struct NfnlInfo<'a> {
    /// The request, for the replies and the extended ack.
    pub req: &'a Request<'a>,
    /// The header of the message.
    pub nlh: Header,
    /// The header of netfilter.
    pub nfmsg: NfGenMsg,
}

/// A handler of a message, `nfnl_callback.call` of Linux.
pub type NfnlCall = fn(&NfnlInfo<'_>, &Attrs<'_>) -> Result<()>;

/// A handler of a dump. It gives all of the messages of the dump.
pub type NfnlDump = fn(&NfnlInfo<'_>, &Attrs<'_>) -> Result<Vec<Vec<u8>>>;

/// The kind of a handler, `enum nfnl_callback_type` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NfnlCbType {
    /// The message type has no handler.
    Unspec,
    /// The handler does not change the state. It runs out of a batch.
    Rcu,
    /// The handler can change the state. It runs out of a batch.
    Mutex,
    /// The handler changes the state. It runs only in a batch.
    Batch,
}

/// The handler of one message type, `struct nfnl_callback` of Linux.
#[derive(Clone, Copy)]
pub struct NfnlCallback {
    /// The handler of a request for one object, or of a change in a batch.
    pub call: Option<NfnlCall>,
    /// The handler of a dump.
    pub dump: Option<NfnlDump>,
    /// The kind of the handler.
    pub kind: NfnlCbType,
    /// The highest attribute type.
    pub attr_count: u16,
}

/// The changes of a batch, as the `commit` and `abort` functions of `struct
/// nfnetlink_subsystem` of Linux. The subsystem holds its lock until the batch ends.
pub trait NfnlBatch {
    /// Runs one message of the batch. The change is not visible until the commit.
    fn call(&mut self, info: &NfnlInfo<'_>, cb: &NfnlCallback, attrs: &Attrs<'_>) -> Result<()>;
    /// Makes all of the changes visible.
    fn commit(self: Box<Self>, batch: Origin) -> Result<()>;
    /// Drops all of the changes.
    fn abort(self: Box<Self>);
}

/// The sender of a batch: its port ID, the sequence number and `NLM_F_ECHO` of
/// `NFNL_MSG_BATCH_BEGIN`.
pub type Origin = super::Origin;

/// Starts a batch of a subsystem.
pub type NfnlBegin = fn(genid: u32) -> Option<Box<dyn NfnlBatch>>;

/// A subsystem, as `struct nfnetlink_subsystem` of Linux.
pub struct NfnlSubsystem {
    /// The name.
    pub name: &'static str,
    /// The ID.
    pub subsys_id: u8,
    /// The handlers, by the message of the subsystem.
    pub cb: &'static [NfnlCallback],
    /// Starts a batch if the generation is `genid`, or any generation if `genid` is 0, as
    /// `valid_genid` of Linux. Gives `None` if the generation changed.
    pub begin: Option<NfnlBegin>,
}

/// The subsystems.
static SUBSYSTEMS: &[&NfnlSubsystem] = &[
    &crate::netfilter::nf_conntrack::nf_conntrack_netlink::CTNETLINK_SUBSYS,
    &crate::netfilter::nf_tables_api::NF_TABLES_SUBSYS,
];

fn nfnetlink_get_subsys(subsys_id: u16) -> Option<&'static NfnlSubsystem> {
    SUBSYSTEMS.iter().copied().find(|s| u16::from(s.subsys_id) == subsys_id)
}

fn nfnetlink_find_client(ty: u16, ss: &NfnlSubsystem) -> Option<&'static NfnlCallback> {
    let cb_id = usize::from(nfnl_msg_type(ty));
    let cb: &'static [NfnlCallback] = ss.cb;
    cb.get(cb_id)
}

/// Sends `data` to the group `group`, and to `portid` if `echo` is set, as `nfnetlink_send`
/// of Linux.
pub fn nfnetlink_send(data: Vec<u8>, portid: u32, group: u32, echo: bool) {
    let exclude = if echo { portid } else { 0 };
    broadcast(NETLINK_NETFILTER, None, &data, 0, exclude, group, super::Creds::KERNEL);
    if echo && let Some(s) = lookup(NETLINK_NETFILTER, portid) {
        s.deliver(data, 0, 0);
    }
}

/// Tells if a socket listens to the group `group`, as `nfnetlink_has_listeners` of Linux.
pub fn nfnetlink_has_listeners(group: u32) -> bool {
    listeners(NETLINK_NETFILTER, group)
}

/// Checks a group for `bind`, as `nfnetlink_bind` of Linux. A process needs `CAP_NET_ADMIN`
/// to listen, because the protocol does not have `NL_CFG_F_NONROOT_RECV`.
pub(super) fn bind(group: u32) -> Result<()> {
    if group == 0 || group > NGROUPS {
        return Err(Errno::EINVAL);
    }
    if !net_admin() {
        return Err(Errno::EPERM);
    }
    Ok(())
}

/// Runs the datagram `data` as a batch, as `nfnetlink_rcv` of Linux. Gives `false` if the
/// datagram is not a batch: then each message goes to `rcv_msg`.
pub(super) fn rcv(sock: &NetlinkSocket, data: &[u8]) -> bool {
    let Some(nlh) = Header::parse(data) else { return true };
    if (nlh.len as usize) < HDRLEN || data.len() < nlh.len as usize {
        return true;
    }
    if !net_admin() {
        ack(sock, &data[..nlh.len as usize], -i32::from(Errno::EPERM.get()), None);
        return true;
    }
    if nlh.ty != NFNL_MSG_BATCH_BEGIN {
        return false;
    }
    nfnetlink_rcv_skb_batch(sock, data, nlh);
    true
}

/// Sends the ack or the error of the message `m`, as `netlink_ack` of Linux.
fn ack(sock: &NetlinkSocket, m: &[u8], err: i32, ext: Option<msg::ExtAck>) {
    let flags = sock.state.lock().flags;
    let cap_ack = flags & super::F_CAP_ACK != 0;
    let ext = ext.filter(|_| flags & super::F_EXT_ACK != 0);
    sock.deliver(msg::ack_ext(m, err, sock.portid(), cap_ack, ext.as_ref()), 0, 0);
}

/// Reads the first message of a batch, as `nfnetlink_rcv_skb_batch` of Linux.
fn nfnetlink_rcv_skb_batch(sock: &NetlinkSocket, data: &[u8], nlh: Header) {
    let msglen = msg::align(nlh.len as usize).min(data.len());
    if data.len() < HDRLEN + NFGENMSG_LEN {
        return;
    }
    let begin = &data[..nlh.len as usize];
    let Some(nfgenmsg) = NfGenMsg::parse(&begin[HDRLEN..]) else { return };
    let attrs = Attrs::parse(&begin[(HDRLEN + NFGENMSG_LEN).min(begin.len())..], 1);
    let gen_id = match attrs.get(NFNL_BATCH_GENID) {
        Some(d) => match d.first_chunk::<4>() {
            Some(v) => u32::from_be_bytes(*v),
            None => {
                ack(sock, begin, -i32::from(Errno::ERANGE.get()), None);
                return;
            }
        },
        None => 0,
    };
    // An old nft puts the subsystem in the byte order of the host.
    let res_id = if nfgenmsg.res_id == u16::from(NFNL_SUBSYS_NFTABLES).swap_bytes() {
        u16::from(NFNL_SUBSYS_NFTABLES)
    } else {
        nfgenmsg.res_id
    };
    nfnetlink_rcv_batch(sock, &data[msglen..], begin, nlh, res_id, gen_id);
}

/// An entry of the list of the errors of a batch, as `struct nfnl_err` of Linux.
struct NfnlErr<'a> {
    nlh: &'a [u8],
    err: i32,
    ext: msg::ExtAck,
}

/// Runs the messages of a batch for the subsystem `subsys_id`, as `nfnetlink_rcv_batch` of
/// Linux. `begin` is the message `NFNL_MSG_BATCH_BEGIN`.
fn nfnetlink_rcv_batch(
    sock: &NetlinkSocket,
    mut skb: &[u8],
    begin: &[u8],
    nlh: Header,
    subsys_id: u16,
    genid: u32,
) {
    let errno = |e: Errno| -i32::from(e.get());
    if subsys_id >= NFNL_SUBSYS_COUNT {
        return ack(sock, begin, errno(Errno::EINVAL), None);
    }
    let Some(ss) = nfnetlink_get_subsys(subsys_id) else {
        return ack(sock, begin, errno(Errno::EOPNOTSUPP), None);
    };
    let Some(start) = ss.begin else {
        return ack(sock, begin, errno(Errno::EOPNOTSUPP), None);
    };
    let Some(mut batch) = start(genid) else {
        return ack(sock, begin, errno(Errno::ERESTART), None);
    };
    let mut err_list: Vec<NfnlErr<'_>> = Vec::new();
    let mut failure = false;
    let mut done = false;
    while skb.len() >= HDRLEN {
        let Some(h) = Header::parse(skb) else { break };
        let len = h.len as usize;
        if len < HDRLEN || skb.len() < len || len - HDRLEN < NFGENMSG_LEN {
            err_list.clear();
            failure = true;
            break;
        }
        let m = &skb[..len];
        let ext = Cell::new(msg::ExtAck::default());
        let err = 'ack: {
            // Only the requests go to the kernel.
            if h.flags & NLM_F_REQUEST as u16 == 0 {
                break 'ack Err(Errno::EINVAL);
            }
            if h.ty == NFNL_MSG_BATCH_BEGIN {
                // Two starts make a bad batch.
                err_list.clear();
                failure = true;
                break 'ack Ok(true);
            }
            if h.ty == NFNL_MSG_BATCH_END {
                done = true;
                break 'ack Ok(true);
            }
            if u32::from(h.ty) < NLMSG_MIN_TYPE {
                break 'ack Err(Errno::EINVAL);
            }
            // A batch has only the messages of one subsystem.
            if u16::from(nfnl_subsys_id(h.ty)) != subsys_id {
                break 'ack Err(Errno::EINVAL);
            }
            let Some(nc) = nfnetlink_find_client(h.ty, ss) else {
                break 'ack Err(Errno::EINVAL);
            };
            if nc.kind != NfnlCbType::Batch {
                break 'ack Err(Errno::EINVAL);
            }
            let req = Request::new(sock, h, m, &ext);
            let Ok((fixed, attrs)) = req.parse(NFGENMSG_LEN, nc.attr_count) else {
                break 'ack Err(Errno::EINVAL);
            };
            let Some(nfmsg) = NfGenMsg::parse(fixed) else { break 'ack Err(Errno::EINVAL) };
            let info = NfnlInfo { req: &req, nlh: h, nfmsg };
            batch.call(&info, nc, &attrs).map(|()| false)
        };
        let err = match err {
            Ok(true) => break,
            Ok(false) => 0,
            Err(e) => errno(e),
        };
        if h.flags & NLM_F_ACK as u16 != 0 || err != 0 {
            // The errors go after the batch, and the batch does not stop at an error: the
            // program gets all of them, and then the transaction stops.
            err_list.push(NfnlErr { nlh: m, err, ext: ext.get() });
            if err != 0 {
                failure = true;
            }
        }
        skb = &skb[msg::align(len).min(skb.len())..];
    }
    if done && !failure {
        let origin = Origin {
            portid: sock.portid(),
            seq: nlh.seq,
            echo: nlh.flags & NLM_F_ECHO as u16 != 0,
        };
        if let Err(e) = batch.commit(origin) {
            ack(sock, begin, errno(e), None);
        }
    } else {
        batch.abort();
    }
    for e in err_list {
        ack(sock, e.nlh, e.err, Some(e.ext));
    }
}

/// Runs one message that is not in a batch, as `nfnetlink_rcv_msg` of Linux.
pub(super) fn rcv_msg(
    sock: &NetlinkSocket,
    h: Header,
    m: &[u8],
    ext: &Cell<msg::ExtAck>,
) -> Result<Flow> {
    // Each message has at least `struct nfgenmsg`.
    if (h.len as usize) < HDRLEN + NFGENMSG_LEN || m.len() < HDRLEN + NFGENMSG_LEN {
        return Ok(Flow::Done);
    }
    let Some(ss) = nfnetlink_get_subsys(u16::from(nfnl_subsys_id(h.ty))) else {
        return Err(Errno::EINVAL);
    };
    let Some(nc) = nfnetlink_find_client(h.ty, ss) else { return Err(Errno::EINVAL) };
    let req = Request::new(sock, h, m, ext);
    let (fixed, attrs) = req.parse(NFGENMSG_LEN, nc.attr_count)?;
    let Some(nfmsg) = NfGenMsg::parse(fixed) else { return Err(Errno::EINVAL) };
    if !matches!(nc.kind, NfnlCbType::Rcu | NfnlCbType::Mutex) {
        return Err(Errno::EINVAL);
    }
    let info = NfnlInfo { req: &req, nlh: h, nfmsg };
    if h.flags & NLM_F_DUMP as u16 == NLM_F_DUMP as u16
        && let Some(dump) = nc.dump
    {
        let result = dump(&info, &attrs)?;
        sock.start_dump(h, Ok(result), false, 0, ext.get())?;
        return Ok(Flow::Dump);
    }
    let Some(call) = nc.call else { return Err(Errno::EOPNOTSUPP) };
    call(&info, &attrs)?;
    Ok(Flow::Done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::SOCK_RAW;
    use crate::netfilter::NFPROTO_IPV4;
    use crate::netfilter::nf_tables_api::{NFT_MSG_GETTABLE, NFT_MSG_NEWTABLE};
    use crate::netlink::msg::Builder;
    use crate::{Message, NoPaths, Socket, dev};
    use alloc::sync::Arc;
    use rk_abi::native::netlink::{NLM_F_CREATE, NLM_F_EXCL, NLMSG_DONE, NLMSG_ERROR};

    const NFTA_TABLE_NAME: u16 = 1;

    fn socket() -> Arc<NetlinkSocket> {
        dev::init();
        crate::netlink::init();
        NetlinkSocket::new(SOCK_RAW, NETLINK_NETFILTER).unwrap()
    }

    fn nfmsg(ty: u16, flags: u32, seq: u32, family: u8, res_id: u16) -> Builder {
        let mut b = Builder::new(ty, (NLM_F_REQUEST | flags) as u16, seq, 0);
        b.fixed(
            &NfGenMsg { nfgen_family: family, version: NFNETLINK_V0, res_id: res_id.to_be() }
                .bytes(),
        );
        b
    }

    fn batch(seq: u32) -> Builder {
        nfmsg(NFNL_MSG_BATCH_BEGIN, 0, seq, 0, u16::from(NFNL_SUBSYS_NFTABLES))
    }

    fn newtable(seq: u32, name: &str, flags: u32) -> Vec<u8> {
        let ty = (u16::from(NFNL_SUBSYS_NFTABLES) << 8) | u16::from(NFT_MSG_NEWTABLE);
        let mut b = nfmsg(ty, NLM_F_CREATE | NLM_F_ACK | flags, seq, NFPROTO_IPV4, 0);
        b.str(NFTA_TABLE_NAME, name);
        b.finish()
    }

    fn send(s: &NetlinkSocket, data: Vec<u8>) {
        s.send(&NoPaths, Message { data, ..Message::default() }, 0, true).unwrap();
    }

    /// The errors of the acks that the socket has, by sequence number.
    fn acks(s: &NetlinkSocket) -> Vec<(u32, i32)> {
        let mut out = Vec::new();
        while let Ok(r) = s.recv(65536, 0, true) {
            for m in msg::messages(&r.data) {
                let h = Header::parse(m).unwrap();
                if h.ty == NLMSG_ERROR as u16 {
                    let err = i32::from_ne_bytes(m[HDRLEN..HDRLEN + 4].try_into().unwrap());
                    out.push((h.seq, err));
                }
            }
        }
        out
    }

    /// The names of the tables in a dump.
    fn tables(s: &NetlinkSocket) -> Vec<Vec<u8>> {
        let ty = (u16::from(NFNL_SUBSYS_NFTABLES) << 8) | u16::from(NFT_MSG_GETTABLE);
        send(s, nfmsg(ty, NLM_F_DUMP, 9, NFPROTO_IPV4, 0).finish());
        let mut out = Vec::new();
        while let Ok(r) = s.recv(65536, 0, true) {
            let mut done = false;
            for m in msg::messages(&r.data) {
                let h = Header::parse(m).unwrap();
                if h.ty == NLMSG_DONE as u16 {
                    done = true;
                } else if nfnl_msg_type(h.ty) == NFT_MSG_NEWTABLE {
                    let a = Attrs::parse(&m[HDRLEN + NFGENMSG_LEN..], 2);
                    out.push(a.str(u32::from(NFTA_TABLE_NAME)).unwrap().to_vec());
                }
            }
            if done {
                break;
            }
        }
        out
    }

    #[test]
    fn a_batch_commits_its_tables_and_a_batch_with_no_end_aborts() {
        let _serial = crate::TEST_DEVICES.lock();
        let s = socket();
        let mut d = batch(1).finish();
        d.extend(newtable(2, "nfunit", 0));
        d.extend(nfmsg(NFNL_MSG_BATCH_END, 0, 3, 0, u16::from(NFNL_SUBSYS_NFTABLES)).finish());
        send(&s, d);
        assert_eq!(acks(&s), [(2, 0)]);
        assert!(tables(&s).contains(&b"nfunit".to_vec()));

        // The same table again with NLM_F_EXCL gives EEXIST.
        let mut d = batch(4).finish();
        d.extend(newtable(5, "nfunit", NLM_F_EXCL));
        d.extend(nfmsg(NFNL_MSG_BATCH_END, 0, 6, 0, u16::from(NFNL_SUBSYS_NFTABLES)).finish());
        send(&s, d);
        assert_eq!(acks(&s), [(5, -i32::from(Errno::EEXIST.get()))]);

        // A batch with no end makes nothing.
        let mut d = batch(7).finish();
        d.extend(newtable(8, "nfunit2", 0));
        send(&s, d);
        acks(&s);
        assert!(!tables(&s).contains(&b"nfunit2".to_vec()));
    }
}

//! ctnetlink, the subsystem of `NETLINK_NETFILTER` for the connections, as
//! net/netfilter/nf_conntrack_netlink.c of Linux. `conntrack -L` dumps the table, `conntrack -G`
//! gets one connection, `conntrack -D` deletes connections and `conntrack -C` reads the count.
//!
//! The requests here are `IPCTNL_MSG_CT_GET` (a dump or one connection), `IPCTNL_MSG_CT_DELETE`
//! (one connection, or a flush), `IPCTNL_MSG_CT_GET_CTRZERO` and `IPCTNL_MSG_CT_GET_STATS`. A
//! dump and a flush take the filters `CTA_MARK` with `CTA_MARK_MASK` and `CTA_STATUS` with
//! `CTA_STATUS_MASK`, and the family of `struct nfgenmsg`. Only the zone 0 has connections.
//!
//! `IPCTNL_MSG_CT_NEW`, `CTA_FILTER`, the statistics of each CPU, the lists of the dying and the
//! unconfirmed connections, and the events give `EOPNOTSUPP`. The connections have no counters
//! of the packets and the bytes, so `CTA_COUNTERS_*` are not in the messages.

use super::{
    CT, IPPROTO_DCCP, IPPROTO_SCTP, IPPROTO_TCP, IPPROTO_UDP, IPPROTO_UDPLITE, NfConn,
    NfConntrackTuple, is_icmp, nf_ct_kill,
};
use crate::netfilter::{NFPROTO_IPV4, NFPROTO_IPV6, NFPROTO_UNSPEC};
use crate::netlink::msg::{Attrs, Builder};
use crate::netlink::nfnetlink::{
    NFNETLINK_V0, NFNL_SUBSYS_CTNETLINK, NfnlCallback, NfnlCbType, NfnlInfo, NfnlSubsystem,
    nfnl_msg_put,
};
use crate::sysctl;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use rk_abi::Errno;
use rk_abi::native::netlink::{NLA_F_NESTED, NLM_F_MULTI};
use rk_vfs::inode::Result;

// The messages, `enum cntl_msg_types` of <linux/netfilter/nfnetlink_conntrack.h>.
const IPCTNL_MSG_CT_NEW: u8 = 0;
#[cfg(test)]
const IPCTNL_MSG_CT_GET: u8 = 1;
const IPCTNL_MSG_CT_GET_STATS: u8 = 5;

// The attributes of a connection, `enum ctattr_type`.
const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_STATUS: u16 = 3;
const CTA_PROTOINFO: u16 = 4;
const CTA_TIMEOUT: u16 = 7;
const CTA_MARK: u16 = 8;
const CTA_USE: u16 = 11;
const CTA_ID: u16 = 12;
const CTA_ZONE: u16 = 18;
const CTA_MARK_MASK: u16 = 21;
const CTA_FILTER: u16 = 25;
const CTA_STATUS_MASK: u16 = 26;
/// `CTA_MAX`.
const CTA_MAX: u16 = 27;

// The attributes of a tuple, `enum ctattr_tuple`.
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;
const CTA_TUPLE_ZONE: u16 = 3;

// `enum ctattr_ip`.
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;

// `enum ctattr_l4proto`.
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;
const CTA_PROTO_ICMP_ID: u16 = 4;
const CTA_PROTO_ICMP_TYPE: u16 = 5;
const CTA_PROTO_ICMP_CODE: u16 = 6;
const CTA_PROTO_ICMPV6_ID: u16 = 7;
const CTA_PROTO_ICMPV6_TYPE: u16 = 8;
const CTA_PROTO_ICMPV6_CODE: u16 = 9;

// `enum ctattr_protoinfo` and `enum ctattr_protoinfo_tcp`.
const CTA_PROTOINFO_TCP: u16 = 1;
const CTA_PROTOINFO_TCP_STATE: u16 = 1;
const CTA_PROTOINFO_TCP_WSCALE_ORIGINAL: u16 = 2;
const CTA_PROTOINFO_TCP_WSCALE_REPLY: u16 = 3;
const CTA_PROTOINFO_TCP_FLAGS_ORIGINAL: u16 = 4;
const CTA_PROTOINFO_TCP_FLAGS_REPLY: u16 = 5;

// `enum ctattr_stats_global`.
const CTA_STATS_GLOBAL_ENTRIES: u16 = 1;
const CTA_STATS_GLOBAL_MAX_ENTRIES: u16 = 2;

const NESTED: u16 = NLA_F_NESTED as u16;

/// The message type of the subsystem for `msg`, as `nfnl_msg_type` of Linux.
const fn msg_type(msg: u8) -> u16 {
    (NFNL_SUBSYS_CTNETLINK as u16) << 8 | msg as u16
}

/// A request that rukernel does not do.
fn ctnetlink_unsupported(_info: &NfnlInfo<'_>, _cda: &Attrs<'_>) -> Result<()> {
    Err(Errno::EOPNOTSUPP)
}

const UNSUPPORTED: NfnlCallback = NfnlCallback {
    call: Some(ctnetlink_unsupported),
    dump: None,
    kind: NfnlCbType::Rcu,
    attr_count: CTA_MAX,
};

/// The handlers, by `IPCTNL_MSG_CT_*`, as `ctnl_cb` of Linux.
static CTNL_CB: [NfnlCallback; 8] = [
    // IPCTNL_MSG_CT_NEW
    NfnlCallback { kind: NfnlCbType::Mutex, ..UNSUPPORTED },
    // IPCTNL_MSG_CT_GET
    NfnlCallback {
        call: Some(ctnetlink_get_conntrack),
        dump: Some(ctnetlink_dump_table),
        kind: NfnlCbType::Mutex,
        attr_count: CTA_MAX,
    },
    // IPCTNL_MSG_CT_DELETE
    NfnlCallback {
        call: Some(ctnetlink_del_conntrack),
        dump: None,
        kind: NfnlCbType::Mutex,
        attr_count: CTA_MAX,
    },
    // IPCTNL_MSG_CT_GET_CTRZERO: the connections have no counters to zero.
    NfnlCallback {
        call: Some(ctnetlink_get_conntrack),
        dump: Some(ctnetlink_dump_table),
        kind: NfnlCbType::Mutex,
        attr_count: CTA_MAX,
    },
    // IPCTNL_MSG_CT_GET_STATS_CPU
    UNSUPPORTED,
    // IPCTNL_MSG_CT_GET_STATS
    NfnlCallback {
        call: Some(ctnetlink_stat_ct),
        dump: None,
        kind: NfnlCbType::Rcu,
        attr_count: CTA_MAX,
    },
    // IPCTNL_MSG_CT_GET_DYING
    UNSUPPORTED,
    // IPCTNL_MSG_CT_GET_UNCONFIRMED
    UNSUPPORTED,
];

/// The subsystem, `ctnl_subsys` of Linux.
pub static CTNETLINK_SUBSYS: NfnlSubsystem = NfnlSubsystem {
    name: "conntrack",
    subsys_id: NFNL_SUBSYS_CTNETLINK,
    cb: &CTNL_CB,
    begin: None,
};

fn be16(a: &Attrs<'_>, ty: u16) -> Result<Option<u16>> {
    a.get(u32::from(ty))
        .map(|d| d.first_chunk::<2>().map(|v| u16::from_be_bytes(*v)).ok_or(Errno::ERANGE))
        .transpose()
}

fn be32(a: &Attrs<'_>, ty: u16) -> Result<Option<u32>> {
    a.get(u32::from(ty))
        .map(|d| d.first_chunk::<4>().map(|v| u32::from_be_bytes(*v)).ok_or(Errno::ERANGE))
        .transpose()
}

/// Puts the addresses and the protocol of `t`, as `ctnetlink_dump_tuples` of Linux.
fn ctnetlink_dump_tuples(b: &mut Builder, t: &NfConntrackTuple) {
    let ip = b.nest(CTA_TUPLE_IP | NESTED);
    if t.l3num == NFPROTO_IPV4 {
        b.put(CTA_IP_V4_SRC, &t.src[..4]);
        b.put(CTA_IP_V4_DST, &t.dst[..4]);
    } else {
        b.put(CTA_IP_V6_SRC, &t.src);
        b.put(CTA_IP_V6_DST, &t.dst);
    }
    b.end_nest(ip);
    let proto = b.nest(CTA_TUPLE_PROTO | NESTED);
    b.u8(CTA_PROTO_NUM, t.protonum);
    let icmp = match t.l3num {
        NFPROTO_IPV4 => (CTA_PROTO_ICMP_ID, CTA_PROTO_ICMP_TYPE, CTA_PROTO_ICMP_CODE),
        _ => (CTA_PROTO_ICMPV6_ID, CTA_PROTO_ICMPV6_TYPE, CTA_PROTO_ICMPV6_CODE),
    };
    match t.protonum {
        p if is_icmp(t.l3num, p) => {
            b.put(icmp.0, &t.src_u.to_be_bytes());
            b.u8(icmp.1, (t.dst_u >> 8) as u8);
            b.u8(icmp.2, t.dst_u as u8);
        }
        IPPROTO_TCP | IPPROTO_UDP | IPPROTO_UDPLITE | IPPROTO_SCTP | IPPROTO_DCCP => {
            b.put(CTA_PROTO_SRC_PORT, &t.src_u.to_be_bytes());
            b.put(CTA_PROTO_DST_PORT, &t.dst_u.to_be_bytes());
        }
        _ => {}
    }
    b.end_nest(proto);
}

/// The users of a connection, as `refcount_read(&ct->ct_general.use)` of Linux. The table has a
/// reference for each of the two tuples and the caller has one, where Linux counts one for the
/// table.
fn ct_use(ct: &Arc<NfConn>) -> u32 {
    u32::try_from(Arc::strong_count(ct).saturating_sub(2).max(1)).unwrap_or(u32::MAX)
}

/// The message of a connection, as `ctnetlink_fill_info` of Linux. The type of the message is
/// `IPCTNL_MSG_CT_NEW`, with `NLM_F_MULTI` for a socket.
fn ctnetlink_fill_info(portid: u32, seq: u32, ct: &Arc<NfConn>) -> Vec<u8> {
    let [orig, reply] = ct.tuples();
    let flags = if portid != 0 { NLM_F_MULTI as u16 } else { 0 };
    let mut b =
        nfnl_msg_put(portid, seq, msg_type(IPCTNL_MSG_CT_NEW), flags, orig.l3num, NFNETLINK_V0, 0);
    let n = b.nest(CTA_TUPLE_ORIG | NESTED);
    ctnetlink_dump_tuples(&mut b, &orig);
    b.end_nest(n);
    let n = b.nest(CTA_TUPLE_REPLY | NESTED);
    ctnetlink_dump_tuples(&mut b, &reply);
    b.end_nest(n);
    b.put(CTA_STATUS, &ct.status().to_be_bytes());
    b.put(CTA_MARK, &ct.mark.load(Ordering::Relaxed).to_be_bytes());
    b.put(CTA_ID, &ct.id.to_be_bytes());
    b.put(CTA_USE, &ct_use(ct).to_be_bytes());
    let secs = ct.expires() / crate::options::hz();
    b.put(CTA_TIMEOUT, &u32::try_from(secs).unwrap_or(u32::MAX).to_be_bytes());
    if orig.protonum == IPPROTO_TCP {
        // `tcp_to_nlattr`: struct nf_ct_tcp_flags is the flags and a mask of 0.
        let tcp = *ct.tcp.lock();
        let info = b.nest(CTA_PROTOINFO | NESTED);
        let n = b.nest(CTA_PROTOINFO_TCP | NESTED);
        b.u8(CTA_PROTOINFO_TCP_STATE, tcp.state);
        b.u8(CTA_PROTOINFO_TCP_WSCALE_ORIGINAL, tcp.seen[0].td_scale);
        b.u8(CTA_PROTOINFO_TCP_WSCALE_REPLY, tcp.seen[1].td_scale);
        b.put(CTA_PROTOINFO_TCP_FLAGS_ORIGINAL, &[tcp.seen[0].flags, 0]);
        b.put(CTA_PROTOINFO_TCP_FLAGS_REPLY, &[tcp.seen[1].flags, 0]);
        b.end_nest(n);
        b.end_nest(info);
    }
    b.finish()
}

/// Reads the tuple in the attribute `ty` of `cda` for the family `l3num`, as
/// `ctnetlink_parse_tuple` of Linux. Gives `None` for a zone other than 0, which has no
/// connections.
fn ctnetlink_parse_tuple(
    info: &NfnlInfo<'_>,
    cda: &Attrs<'_>,
    ty: u16,
    l3num: u8,
) -> Result<Option<NfConntrackTuple>> {
    let nest = cda.get(u32::from(ty)).ok_or(Errno::EINVAL)?;
    let tb = Attrs::parse(nest, CTA_TUPLE_ZONE);
    let Some(ip) = tb.get(u32::from(CTA_TUPLE_IP)) else {
        return Err(info.req.missing(Some(nest), u32::from(CTA_TUPLE_IP)));
    };
    let Some(proto) = tb.get(u32::from(CTA_TUPLE_PROTO)) else {
        return Err(info.req.missing(Some(nest), u32::from(CTA_TUPLE_PROTO)));
    };
    let mut t = NfConntrackTuple { l3num, ..NfConntrackTuple::default() };
    let ia = Attrs::parse(ip, CTA_IP_V6_DST);
    let (src, dst, len) = match l3num {
        NFPROTO_IPV4 => (CTA_IP_V4_SRC, CTA_IP_V4_DST, 4),
        NFPROTO_IPV6 => (CTA_IP_V6_SRC, CTA_IP_V6_DST, 16),
        _ => return Err(Errno::EOPNOTSUPP),
    };
    for (ty, out) in [(src, &mut t.src), (dst, &mut t.dst)] {
        let a = ia.get(u32::from(ty)).ok_or(Errno::EINVAL)?;
        out[..len].copy_from_slice(a.get(..len).ok_or(Errno::ERANGE)?);
    }
    let pa = Attrs::parse(proto, CTA_PROTO_ICMPV6_CODE);
    t.protonum = pa.u8(u32::from(CTA_PROTO_NUM))?.ok_or(Errno::EINVAL)?;
    match t.protonum {
        p if is_icmp(l3num, p) => {
            let (id, ty, code) = if l3num == NFPROTO_IPV4 {
                (CTA_PROTO_ICMP_ID, CTA_PROTO_ICMP_TYPE, CTA_PROTO_ICMP_CODE)
            } else {
                (CTA_PROTO_ICMPV6_ID, CTA_PROTO_ICMPV6_TYPE, CTA_PROTO_ICMPV6_CODE)
            };
            let ty = pa.u8(u32::from(ty))?.ok_or(Errno::EINVAL)?;
            let code = pa.u8(u32::from(code))?.ok_or(Errno::EINVAL)?;
            t.src_u = be16(&pa, id)?.ok_or(Errno::EINVAL)?;
            t.dst_u = u16::from(ty) << 8 | u16::from(code);
            // `icmp_nlattr_to_tuple`: only the types of a request or a reply.
            t.invert().ok_or(Errno::EINVAL)?;
        }
        IPPROTO_TCP | IPPROTO_UDP | IPPROTO_UDPLITE | IPPROTO_SCTP | IPPROTO_DCCP => {
            t.src_u = be16(&pa, CTA_PROTO_SRC_PORT)?.ok_or(Errno::EINVAL)?;
            t.dst_u = be16(&pa, CTA_PROTO_DST_PORT)?.ok_or(Errno::EINVAL)?;
        }
        _ => {}
    }
    if be16(&tb, CTA_TUPLE_ZONE)?.unwrap_or(0) != 0 {
        return Ok(None);
    }
    Ok(Some(t))
}

/// The filter of a dump or a flush, as `struct ctnetlink_filter` of Linux.
struct CtFilter {
    family: u8,
    mark: (u32, u32),
    status: (u32, u32),
    /// The request has a zone other than 0, so nothing matches.
    none: bool,
}

impl CtFilter {
    /// Reads the filter, as `ctnetlink_alloc_filter` of Linux.
    fn parse(cda: &Attrs<'_>, family: u8) -> Result<Self> {
        if cda.has(u32::from(CTA_FILTER)) {
            return Err(Errno::EOPNOTSUPP);
        }
        // `ctnetlink_filter_parse_mark`.
        let mark = match (be32(cda, CTA_MARK)?, be32(cda, CTA_MARK_MASK)?) {
            (Some(v), mask) => (v, mask.unwrap_or(u32::MAX)),
            (None, Some(_)) => return Err(Errno::EINVAL),
            (None, None) => (0, 0),
        };
        // `ctnetlink_filter_parse_status`.
        let status = match be32(cda, CTA_STATUS)? {
            Some(v) => {
                let mask = be32(cda, CTA_STATUS_MASK)?.unwrap_or(v);
                if mask == 0 {
                    return Err(Errno::EINVAL);
                }
                (v, mask)
            }
            None => (0, 0),
        };
        let none = be16(cda, CTA_ZONE)?.unwrap_or(0) != 0;
        Ok(Self { family, mark, status, none })
    }

    /// Tells if `ct` passes the filter, as `ctnetlink_filter_match` of Linux.
    fn matches(&self, ct: &NfConn) -> bool {
        !self.none
            && (self.family == NFPROTO_UNSPEC || ct.tuple(0).l3num == self.family)
            && ct.mark.load(Ordering::Relaxed) & self.mark.1 == self.mark.0
            && ct.status() & self.status.1 == self.status.0
    }
}

/// The connections of the current namespace that pass `f`, in the order of their tuples.
fn connections(f: &CtFilter) -> Vec<Arc<NfConn>> {
    let mut t = CT.lock();
    t.gc();
    t.hash.values().filter(|(c, d)| *d == 0 && f.matches(c)).map(|(c, _)| c.clone()).collect()
}

/// The dump of the connections, as `ctnetlink_dump_table` of Linux.
fn ctnetlink_dump_table(info: &NfnlInfo<'_>, cda: &Attrs<'_>) -> Result<Vec<Vec<u8>>> {
    let f = CtFilter::parse(cda, info.nfmsg.nfgen_family)?;
    Ok(connections(&f)
        .iter()
        .map(|ct| ctnetlink_fill_info(info.req.portid, info.nlh.seq, ct))
        .collect())
}

/// Finds the connection of the tuple in the request, as the start of `ctnetlink_get_conntrack`
/// and `ctnetlink_del_conntrack` of Linux.
fn find(info: &NfnlInfo<'_>, cda: &Attrs<'_>) -> Result<Arc<NfConn>> {
    let family = info.nfmsg.nfgen_family;
    let ty = if cda.has(u32::from(CTA_TUPLE_ORIG)) { CTA_TUPLE_ORIG } else { CTA_TUPLE_REPLY };
    let tuple = ctnetlink_parse_tuple(info, cda, ty, family)?.ok_or(Errno::ENOENT)?;
    if be16(cda, CTA_ZONE)?.unwrap_or(0) != 0 {
        return Err(Errno::ENOENT);
    }
    let (ct, _) = CT.lock().find(&tuple).ok_or(Errno::ENOENT)?;
    Ok(ct)
}

/// Gives one connection, as `ctnetlink_get_conntrack` of Linux.
fn ctnetlink_get_conntrack(info: &NfnlInfo<'_>, cda: &Attrs<'_>) -> Result<()> {
    if !cda.has(u32::from(CTA_TUPLE_ORIG)) && !cda.has(u32::from(CTA_TUPLE_REPLY)) {
        return Err(Errno::EINVAL);
    }
    let ct = find(info, cda)?;
    info.req.reply(ctnetlink_fill_info(info.req.portid, info.nlh.seq, &ct));
    Ok(())
}

/// Deletes one connection, or all of the connections that pass the filter, as
/// `ctnetlink_del_conntrack` and `ctnetlink_flush_conntrack` of Linux. A flush with the
/// version 0 of `struct nfgenmsg` takes all of the families.
fn ctnetlink_del_conntrack(info: &NfnlInfo<'_>, cda: &Attrs<'_>) -> Result<()> {
    if !cda.has(u32::from(CTA_TUPLE_ORIG)) && !cda.has(u32::from(CTA_TUPLE_REPLY)) {
        let family = if info.nfmsg.version != 0 { info.nfmsg.nfgen_family } else { NFPROTO_UNSPEC };
        let f = CtFilter::parse(cda, family)?;
        for ct in connections(&f) {
            nf_ct_kill(&ct);
        }
        return Ok(());
    }
    let ct = find(info, cda)?;
    if let Some(id) = be32(cda, CTA_ID)?
        && id != ct.id
    {
        return Err(Errno::ENOENT);
    }
    nf_ct_kill(&ct);
    Ok(())
}

/// Gives the count of the connections and the limit, as `ctnetlink_stat_ct` of Linux.
fn ctnetlink_stat_ct(info: &NfnlInfo<'_>, _cda: &Attrs<'_>) -> Result<()> {
    let count = u32::try_from(super::nf_conntrack_count()).unwrap_or(u32::MAX);
    let max = sysctl::netfilter("nf_conntrack_max") as u32;
    let flags = if info.req.portid != 0 { NLM_F_MULTI as u16 } else { 0 };
    let mut b = nfnl_msg_put(
        info.req.portid,
        info.nlh.seq,
        msg_type(IPCTNL_MSG_CT_GET_STATS),
        flags,
        NFPROTO_UNSPEC,
        NFNETLINK_V0,
        0,
    );
    b.put(CTA_STATS_GLOBAL_ENTRIES, &count.to_be_bytes());
    b.put(CTA_STATS_GLOBAL_MAX_ENTRIES, &max.to_be_bytes());
    info.req.reply(b.finish());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::{SERIAL, fresh, ip4, state, udp};
    use super::super::{nf_conntrack_confirm, nf_conntrack_count, nf_conntrack_in};
    use super::*;
    use crate::consts::SOCK_RAW;
    use crate::netfilter::{NF_ACCEPT, NF_INET_LOCAL_OUT};
    use crate::netlink::NetlinkSocket;
    use crate::netlink::msg::{self, HDRLEN, Header};
    use crate::netlink::nfnetlink::{NETLINK_NETFILTER, NFGENMSG_LEN, NfGenMsg};
    use crate::{Message, NoPaths, Socket, dev};
    use rk_abi::native::netlink::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_ERROR};

    const IPCTNL_MSG_CT_DELETE: u8 = 2;
    const A: [u8; 4] = [10, 9, 1, 1];
    const B: [u8; 4] = [10, 9, 1, 2];

    fn request(msg: u8, flags: u32, family: u8, attrs: impl FnOnce(&mut Builder)) -> Vec<u8> {
        let mut b = Builder::new(msg_type(msg), (NLM_F_REQUEST | flags) as u16, 1, 0);
        b.fixed(&NfGenMsg { nfgen_family: family, version: NFNETLINK_V0, res_id: 0 }.bytes());
        attrs(&mut b);
        b.finish()
    }

    /// `CTA_TUPLE_ORIG` of the UDP flow from A port `sport` to B port 53.
    fn orig(sport: u16) -> impl FnOnce(&mut Builder) {
        move |b| {
            let t = NfConntrackTuple {
                l3num: NFPROTO_IPV4,
                protonum: IPPROTO_UDP,
                src: [A[0], A[1], A[2], A[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                dst: [B[0], B[1], B[2], B[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                src_u: sport,
                dst_u: 53,
            };
            let n = b.nest(CTA_TUPLE_ORIG | NESTED);
            ctnetlink_dump_tuples(b, &t);
            b.end_nest(n);
        }
    }

    /// Sends `data` and gives the messages of the replies other than `NLMSG_DONE`, and the
    /// error of the ack, if any.
    fn talk(s: &NetlinkSocket, data: Vec<u8>) -> (Vec<Vec<u8>>, Option<i32>) {
        s.send(&NoPaths, Message { data, ..Message::default() }, 0, true).unwrap();
        let (mut out, mut err) = (Vec::new(), None);
        while let Ok(r) = s.recv(65536, 0, true) {
            for m in msg::messages(&r.data) {
                let h = Header::parse(m).unwrap();
                if h.ty == NLMSG_ERROR as u16 {
                    err = Some(i32::from_ne_bytes(m[HDRLEN..HDRLEN + 4].try_into().unwrap()));
                } else if nfnl_subsys_of(h.ty) {
                    out.push(m.to_vec());
                }
            }
        }
        (out, err)
    }

    fn nfnl_subsys_of(ty: u16) -> bool {
        ty >> 8 == u16::from(NFNL_SUBSYS_CTNETLINK)
    }

    fn attrs(m: &[u8]) -> Attrs<'_> {
        Attrs::parse(&m[HDRLEN + NFGENMSG_LEN..], CTA_MAX)
    }

    fn get32(a: &Attrs<'_>, ty: u16) -> u32 {
        be32(a, ty).unwrap().unwrap()
    }

    const fn err(e: Errno) -> Option<i32> {
        Some(-(e.get() as i32))
    }

    #[test]
    fn ctnetlink_dumps_gets_and_deletes_a_connection() {
        let _s = SERIAL.lock();
        let _d = crate::TEST_DEVICES.lock();
        fresh(4000);
        dev::init();
        crate::netlink::init();
        let mut p = ip4(IPPROTO_UDP, A, B, &udp(4100, 53));
        assert_eq!(nf_conntrack_in(&mut p, &state(NF_INET_LOCAL_OUT)), NF_ACCEPT);
        assert_eq!(nf_conntrack_confirm(&mut p), NF_ACCEPT);
        let (ct, _) = p.nfct.get().unwrap();
        let (ct, id) = (ct.clone(), ct.id);
        drop(p);
        let s = NetlinkSocket::new(SOCK_RAW, NETLINK_NETFILTER).unwrap();

        // The dump has the connection, with its tuples, status, ID and timeout.
        let (d, e) = talk(&s, request(IPCTNL_MSG_CT_GET, NLM_F_DUMP, NFPROTO_IPV4, |_| {}));
        assert_eq!((d.len(), e), (1, None));
        let h = Header::parse(&d[0]).unwrap();
        assert_eq!(h.ty, msg_type(IPCTNL_MSG_CT_NEW));
        assert_eq!(d[0][HDRLEN], NFPROTO_IPV4);
        let a = attrs(&d[0]);
        let t = Attrs::parse(a.get(u32::from(CTA_TUPLE_ORIG)).unwrap(), CTA_TUPLE_ZONE);
        let ip = Attrs::parse(t.get(u32::from(CTA_TUPLE_IP)).unwrap(), CTA_IP_V6_DST);
        assert_eq!(ip.get(u32::from(CTA_IP_V4_SRC)), Some(&A[..]));
        let pr = Attrs::parse(t.get(u32::from(CTA_TUPLE_PROTO)).unwrap(), CTA_PROTO_ICMPV6_CODE);
        assert_eq!(pr.u8(u32::from(CTA_PROTO_NUM)).unwrap(), Some(IPPROTO_UDP));
        assert_eq!(be16(&pr, CTA_PROTO_SRC_PORT).unwrap(), Some(4100));
        let r = Attrs::parse(a.get(u32::from(CTA_TUPLE_REPLY)).unwrap(), CTA_TUPLE_ZONE);
        let pr = Attrs::parse(r.get(u32::from(CTA_TUPLE_PROTO)).unwrap(), CTA_PROTO_ICMPV6_CODE);
        assert_eq!(be16(&pr, CTA_PROTO_DST_PORT).unwrap(), Some(4100));
        assert_eq!(get32(&a, CTA_ID), id);
        assert_eq!(get32(&a, CTA_TIMEOUT), 30);
        // The table and the test have the connection.
        assert_eq!(get32(&a, CTA_USE), 2);
        assert_ne!(get32(&a, CTA_STATUS) & super::super::IPS_CONFIRMED, 0);

        // The filters: an other family, a mark and CTA_FILTER.
        let (d, _) = talk(&s, request(IPCTNL_MSG_CT_GET, NLM_F_DUMP, NFPROTO_IPV6, |_| {}));
        assert!(d.is_empty());
        let mark = |b: &mut Builder| {
            b.put(CTA_MARK, &5u32.to_be_bytes());
        };
        let (d, _) = talk(&s, request(IPCTNL_MSG_CT_GET, NLM_F_DUMP, NFPROTO_IPV4, mark));
        assert!(d.is_empty());
        ct.mark.store(0x15, Ordering::Relaxed);
        let mark = |b: &mut Builder| {
            b.put(CTA_MARK, &5u32.to_be_bytes());
            b.put(CTA_MARK_MASK, &0xfu32.to_be_bytes());
        };
        let (d, _) = talk(&s, request(IPCTNL_MSG_CT_GET, NLM_F_DUMP, NFPROTO_UNSPEC, mark));
        assert_eq!(d.len(), 1);
        let only_mask = |b: &mut Builder| {
            b.put(CTA_MARK_MASK, &0xfu32.to_be_bytes());
        };
        let r = talk(&s, request(IPCTNL_MSG_CT_GET, NLM_F_DUMP, NFPROTO_IPV4, only_mask));
        assert_eq!(r.1, err(Errno::EINVAL));
        let filter = |b: &mut Builder| {
            b.put(CTA_FILTER | NESTED, &[]);
        };
        let r = talk(&s, request(IPCTNL_MSG_CT_GET, NLM_F_DUMP, NFPROTO_IPV4, filter));
        assert_eq!(r.1, err(Errno::EOPNOTSUPP));

        // A get of the tuple, and of a tuple with no connection.
        let (d, e) = talk(&s, request(IPCTNL_MSG_CT_GET, NLM_F_ACK, NFPROTO_IPV4, orig(4100)));
        assert_eq!((d.len(), e), (1, Some(0)));
        assert_eq!(get32(&attrs(&d[0]), CTA_MARK), 0x15);
        let r = talk(&s, request(IPCTNL_MSG_CT_GET, 0, NFPROTO_IPV4, orig(4101)));
        assert_eq!(r, (Vec::new(), err(Errno::ENOENT)));
        let r = talk(&s, request(IPCTNL_MSG_CT_GET, 0, NFPROTO_IPV4, |_| {}));
        assert_eq!(r.1, err(Errno::EINVAL));

        // The count, and the requests that rukernel does not do.
        let (d, _) = talk(&s, request(IPCTNL_MSG_CT_GET_STATS, 0, NFPROTO_UNSPEC, |_| {}));
        assert_eq!(get32(&attrs(&d[0]), CTA_STATS_GLOBAL_ENTRIES), 1);
        assert_eq!(get32(&attrs(&d[0]), CTA_STATS_GLOBAL_MAX_ENTRIES), 4096);
        let r = talk(&s, request(IPCTNL_MSG_CT_NEW, 0, NFPROTO_IPV4, orig(4100)));
        assert_eq!(r.1, err(Errno::EOPNOTSUPP));

        // A delete with an other ID fails, and then the delete takes the connection.
        let wrong = |b: &mut Builder| {
            orig(4100)(b);
            b.put(CTA_ID, &(id + 1).to_be_bytes());
        };
        let r = talk(&s, request(IPCTNL_MSG_CT_DELETE, 0, NFPROTO_IPV4, wrong));
        assert_eq!(r.1, err(Errno::ENOENT));
        let r = talk(&s, request(IPCTNL_MSG_CT_DELETE, NLM_F_ACK, NFPROTO_IPV4, orig(4100)));
        assert_eq!(r, (Vec::new(), Some(0)));
        assert_eq!(nf_conntrack_count(), 0);

        // A flush with the version 0 takes the connections of each family.
        let mut p = ip4(IPPROTO_UDP, A, B, &udp(4102, 53));
        nf_conntrack_in(&mut p, &state(NF_INET_LOCAL_OUT));
        nf_conntrack_confirm(&mut p);
        assert_eq!(nf_conntrack_count(), 1);
        let r = talk(&s, request(IPCTNL_MSG_CT_DELETE, NLM_F_ACK, NFPROTO_IPV6, |_| {}));
        assert_eq!(r, (Vec::new(), Some(0)));
        assert_eq!(nf_conntrack_count(), 0);
    }
}

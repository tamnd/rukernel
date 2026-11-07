//! The xtables extensions in nf_tables, as net/netfilter/nft_compat.c of Linux. `iptables-nft`
//! puts a match or a target of xtables that has no native form in a rule as the expression
//! `match` or `target`, with the name, the revision and the data of the extension. It asks the
//! best revision of an extension with `NFNL_MSG_COMPAT_GET` of the subsystem
//! `NFNL_SUBSYS_NFT_COMPAT`.
//!
//! The extensions here are the matches `state`, `conntrack` (revisions 1, 2 and 3), `comment`,
//! `icmp` and `icmp6`, and the target `REJECT` of IPv4 and IPv6, as xt_state.c, xt_conntrack.c,
//! xt_comment.c, ip_tables.c, ip6_tables.c, ipt_REJECT.c and ip6t_REJECT.c. An other extension
//! gives `ENOENT`, as an extension that Linux cannot load.

use crate::buf::NetBuf;
use crate::netfilter::nf_conntrack::{IP_CT_DIR_ORIGINAL, IP_CT_DIR_REPLY, IP_CT_IS_REPLY};
use crate::netfilter::nf_conntrack::{IPS_DST_NAT, IPS_SRC_NAT, NfConntrackTuple};
use crate::netfilter::nf_reject::{NfReject, nf_send_reject};
use crate::netfilter::nf_tables_api::{NFT_BREAK, NFT_CONTINUE};
use crate::netfilter::{
    NF_DROP, NF_INET_FORWARD, NF_INET_LOCAL_IN, NF_INET_LOCAL_OUT, NFPROTO_ARP, NFPROTO_BRIDGE,
    NFPROTO_INET, NFPROTO_IPV4, NFPROTO_IPV6, NFPROTO_UNSPEC, NfHookState,
};
use crate::netlink::msg::Attrs;
use crate::netlink::nfnetlink::{
    NFNETLINK_V0, NFNL_SUBSYS_NFT_COMPAT, NfnlCallback, NfnlCbType, NfnlInfo, NfnlSubsystem,
    nfnl_msg_put,
};
use alloc::sync::Arc;
use core::cell::Cell;
use rk_abi::Errno;
use rk_abi::native::netlink::NLM_F_MULTI;
use rk_vfs::inode::Result;

// The message and the attributes of the subsystem, <linux/netfilter/nf_tables_compat.h>.
const NFNL_MSG_COMPAT_GET: u8 = 0;
const NFTA_COMPAT_NAME: u16 = 1;
const NFTA_COMPAT_REV: u16 = 2;
const NFTA_COMPAT_TYPE: u16 = 3;
const NFTA_COMPAT_MAX: u16 = 3;
const NFT_COMPAT_NAME_MAX: usize = 32;

// The attributes of the expressions `match` and `target`: `NFTA_MATCH_*` and `NFTA_TARGET_*`
// have the same values.
const NFTA_XT_NAME: u32 = 1;
const NFTA_XT_REV: u32 = 2;
const NFTA_XT_INFO: u32 = 3;
const NFTA_XT_MAX: u16 = 3;

// The attribute `NFTA_RULE_COMPAT` of a rule.
const NFTA_RULE_COMPAT_PROTO: u32 = 1;
const NFTA_RULE_COMPAT_FLAGS: u32 = 2;
const NFT_RULE_COMPAT_F_UNUSED: u32 = 1 << 0;
const NFT_RULE_COMPAT_F_INV: u32 = 1 << 1;
const NFT_RULE_COMPAT_F_MASK: u32 = NFT_RULE_COMPAT_F_INV;

const IPPROTO_ICMP: u16 = 1;
const IPPROTO_TCP: u16 = 6;
const IPPROTO_ICMPV6: u16 = 58;

/// The alignment of the data of an extension, `XT_ALIGN` of a 64-bit kernel.
const fn xt_align(n: usize) -> usize {
    n.div_ceil(8) * 8
}

/// The rule of an extension at its check, as the fields of `struct xt_mtchk_param` and
/// `struct xt_tgchk_param` of Linux.
pub(crate) struct XtCheck {
    /// The protocol of the rule, from `NFTA_RULE_COMPAT_PROTO`, or 0.
    pub proto: u16,
    /// The rule matches the packets that do not have `proto`.
    pub inv: bool,
}

/// A packet for an extension, as `struct xt_action_param` of Linux.
pub(crate) struct XtAction<'a> {
    pub skb: &'a NetBuf,
    pub state: &'a NfHookState,
    /// The offset of the transport header, or `None` for a fragment that is not the first.
    pub thoff: Option<usize>,
    /// The match tells to drop the packet, as `hotdrop`.
    pub hotdrop: Cell<bool>,
}

impl XtAction<'_> {
    /// The `n` bytes of the transport header, as `skb_header_pointer`. A short packet sets
    /// `hotdrop`.
    fn th(&self, n: usize) -> Option<&[u8]> {
        let h = self.thoff.and_then(|o| self.skb.data().get(o..o + n));
        if h.is_none() {
            self.hotdrop.set(true);
        }
        h
    }
}

/// What an extension does with a packet.
#[derive(Clone, Copy, Debug)]
pub(crate) enum XtKind {
    /// A match: it tells if the packet matches.
    Match(fn(&[u8], &XtAction<'_>) -> bool),
    /// A target: it gives the verdict, or `XT_CONTINUE` (`NFT_CONTINUE`).
    Target(fn(&[u8], &XtAction<'_>) -> u32),
}

/// An extension of xtables, as `struct xt_match` and `struct xt_target` of Linux.
#[derive(Debug)]
pub(crate) struct XtExt {
    name: &'static str,
    revision: u8,
    /// The family, or `NFPROTO_UNSPEC` for all.
    family: u8,
    /// The size of the data.
    size: usize,
    /// The table that the extension needs, or `None`.
    table: Option<&'static str>,
    /// The hooks that the extension can be on, or 0 for all.
    hooks: u32,
    /// The protocol that the rule must have, or 0.
    proto: u16,
    /// The extension uses connection tracking, as a call of `nf_ct_netns_get` in its check.
    conntrack: bool,
    /// The check of the data, as `checkentry`.
    check: Option<fn(&[u8], &XtCheck) -> Result<()>>,
    kind: XtKind,
}

impl XtExt {
    fn is_target(&self) -> bool {
        matches!(self.kind, XtKind::Target(_))
    }
}

const fn ext(name: &'static str, revision: u8, family: u8, size: usize, kind: XtKind) -> XtExt {
    XtExt {
        name,
        revision,
        family,
        size,
        table: None,
        hooks: 0,
        proto: 0,
        conntrack: false,
        check: None,
        kind,
    }
}

const REJECT_HOOKS: u32 = 1 << NF_INET_LOCAL_IN | 1 << NF_INET_FORWARD | 1 << NF_INET_LOCAL_OUT;

/// The extensions, as the lists `xt[af].match` and `xt[af].target` of Linux.
static XT_EXTS: [XtExt; 9] = [
    XtExt { conntrack: true, ..ext("state", 0, NFPROTO_UNSPEC, 4, XtKind::Match(state_mt)) },
    XtExt {
        conntrack: true,
        ..ext("conntrack", 1, NFPROTO_UNSPEC, 152, XtKind::Match(conntrack_mt_v1))
    },
    XtExt {
        conntrack: true,
        ..ext("conntrack", 2, NFPROTO_UNSPEC, 156, XtKind::Match(conntrack_mt_v2))
    },
    XtExt {
        conntrack: true,
        ..ext("conntrack", 3, NFPROTO_UNSPEC, 164, XtKind::Match(conntrack_mt_v3))
    },
    ext("comment", 0, NFPROTO_UNSPEC, 256, XtKind::Match(comment_mt)),
    XtExt {
        proto: IPPROTO_ICMP,
        check: Some(icmp_checkentry),
        ..ext("icmp", 0, NFPROTO_IPV4, 4, XtKind::Match(icmp_match))
    },
    XtExt {
        proto: IPPROTO_ICMPV6,
        check: Some(icmp_checkentry),
        ..ext("icmp6", 0, NFPROTO_IPV6, 4, XtKind::Match(icmp6_match))
    },
    XtExt {
        table: Some("filter"),
        hooks: REJECT_HOOKS,
        check: Some(reject_tg_check),
        ..ext("REJECT", 0, NFPROTO_IPV4, 4, XtKind::Target(reject_tg))
    },
    XtExt {
        table: Some("filter"),
        hooks: REJECT_HOOKS,
        check: Some(reject_tg6_check),
        ..ext("REJECT", 0, NFPROTO_IPV6, 4, XtKind::Target(reject_tg6))
    },
];

/// Finds the extension `name` with the revision `rev` for the family `af`, then for all the
/// families, as `xt_find_match` and `xt_find_target` of Linux.
fn xt_find(af: u8, name: &[u8], rev: u8, target: bool) -> Option<&'static XtExt> {
    let find = |f: u8| {
        XT_EXTS.iter().find(|e| {
            e.family == f
                && e.is_target() == target
                && e.name.as_bytes() == name
                && e.revision == rev
        })
    };
    find(af).or_else(|| if af == NFPROTO_UNSPEC { None } else { find(NFPROTO_UNSPEC) })
}

/// The best revision of the extension `name`, as `xt_find_revision` of Linux. Gives `ENOENT`
/// if there is no extension of the name, and `EPROTONOSUPPORT` if there is none with the
/// revision `rev`.
fn xt_find_revision(af: u8, name: &[u8], rev: u8, target: bool) -> Result<u8> {
    let mut best = None;
    let mut have = false;
    for f in [af, NFPROTO_UNSPEC] {
        for e in XT_EXTS.iter() {
            if e.family == f && e.is_target() == target && e.name.as_bytes() == name {
                best = best.max(Some(e.revision));
                have |= e.revision == rev;
            }
        }
        if have || af == NFPROTO_UNSPEC {
            break;
        }
    }
    match best {
        None => Err(Errno::ENOENT),
        Some(_) if !have => Err(Errno::EPROTONOSUPPORT),
        Some(b) => Ok(b),
    }
}

/// A string attribute with the policy `NLA_NUL_STRING` and the length `max`: it must have a
/// NUL byte, and the string must not be longer than `max`.
fn nul_string(d: &[u8], max: usize) -> Result<&[u8]> {
    let n = d.len().min(max + 1);
    let Some(end) = d[..n].iter().position(|&c| c == 0) else { return Err(Errno::EINVAL) };
    let len = if d.last() == Some(&0) { d.len() - 1 } else { d.len() };
    if len > max {
        return Err(Errno::ERANGE);
    }
    Ok(&d[..end])
}

fn be32(a: &Attrs<'_>, ty: u32) -> Result<Option<u32>> {
    a.get(ty)
        .map(|d| d.first_chunk::<4>().map(|v| u32::from_be_bytes(*v)).ok_or(Errno::ERANGE))
        .transpose()
}

/// Reads `NFTA_RULE_COMPAT` of a rule, as `nft_parse_compat` of Linux: the protocol and the
/// inversion of the protocol.
fn nft_parse_compat(attr: &[u8]) -> Result<(u16, bool)> {
    let a = Attrs::parse(attr, 2);
    let (Some(proto), Some(flags)) =
        (be32(&a, NFTA_RULE_COMPAT_PROTO)?, be32(&a, NFTA_RULE_COMPAT_FLAGS)?)
    else {
        return Err(Errno::EINVAL);
    };
    if flags & NFT_RULE_COMPAT_F_UNUSED != 0 || flags & !NFT_RULE_COMPAT_F_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    let proto = u16::try_from(proto).map_err(|_| Errno::EINVAL)?;
    Ok((proto, flags & NFT_RULE_COMPAT_F_INV != 0))
}

/// The expression `match` or `target`: an extension and its data, as the private data of
/// nft_compat.c.
#[derive(Clone, Debug)]
pub(crate) struct NftXt {
    ext: &'static XtExt,
    info: Arc<[u8]>,
}

impl NftXt {
    /// The hooks that the extension can be on, or 0 for all.
    pub(crate) fn hooks(&self) -> u32 {
        self.ext.hooks
    }

    /// Tells if the extension uses connection tracking.
    pub(crate) fn needs_ct(&self) -> bool {
        self.ext.conntrack
    }

    /// Runs the extension on a packet, as `nft_match_eval` and `nft_target_eval_xt` of Linux.
    pub(crate) fn eval(&self, skb: &NetBuf, state: &NfHookState, thoff: Option<usize>) -> u32 {
        let par = XtAction { skb, state, thoff, hotdrop: Cell::new(false) };
        let v = match self.ext.kind {
            XtKind::Match(mt) if mt(&self.info, &par) => NFT_CONTINUE,
            XtKind::Match(_) => NFT_BREAK,
            XtKind::Target(tg) => tg(&self.info, &par),
        };
        if par.hotdrop.get() { NF_DROP } else { v }
    }
}

/// Reads the expression `match` (`target` false) or `target` of a rule of the table `table` of
/// the family `family`, as `nft_match_init` and `nft_target_init` of Linux. `compat` is
/// `NFTA_RULE_COMPAT` of the rule.
pub(crate) fn nft_xt_init(
    target: bool,
    table: &[u8],
    family: u8,
    data: &[u8],
    compat: Option<&[u8]>,
) -> Result<NftXt> {
    let a = Attrs::parse(data, NFTA_XT_MAX);
    let (Some(name), Some(rev), Some(info)) =
        (a.get(NFTA_XT_NAME), be32(&a, NFTA_XT_REV)?, a.get(NFTA_XT_INFO))
    else {
        return Err(Errno::EINVAL);
    };
    let name = nul_string(name, usize::MAX - 1)?;
    let rev = u8::try_from(rev).map_err(|_| Errno::EINVAL)?;
    // nf_tables has the extensions for these families; the other ones give `EOPNOTSUPP` in
    // `nft_match_validate`.
    if !matches!(family, NFPROTO_IPV4 | NFPROTO_IPV6 | NFPROTO_INET | NFPROTO_BRIDGE | NFPROTO_ARP)
    {
        return Err(Errno::EOPNOTSUPP);
    }
    let ext = xt_find(family, name, rev, target).ok_or(Errno::ENOENT)?;
    if ext.size > info.len() || xt_align(ext.size) != xt_align(info.len()) {
        return Err(Errno::EINVAL);
    }
    let (proto, inv) = compat.map(nft_parse_compat).transpose()?.unwrap_or((0, false));
    // The checks of `xt_check_match` and `xt_check_target` of Linux. The hooks are checked
    // with the chain.
    if ext.table.is_some_and(|t| t.as_bytes() != table) {
        return Err(Errno::EINVAL);
    }
    if ext.proto != 0 && (ext.proto != proto || inv) {
        return Err(Errno::EINVAL);
    }
    if let Some(check) = ext.check {
        check(info, &XtCheck { proto, inv })?;
    }
    Ok(NftXt { ext, info: info.into() })
}

/// The handler of `NFNL_MSG_COMPAT_GET`, as `nfnl_compat_get_rcu` of Linux. It gives the best
/// revision of an extension.
fn nfnl_compat_get(info: &NfnlInfo<'_>, tb: &Attrs<'_>) -> Result<()> {
    let (Some(name), Some(rev), Some(ty)) = (
        tb.get(u32::from(NFTA_COMPAT_NAME)),
        be32(tb, u32::from(NFTA_COMPAT_REV))?,
        be32(tb, u32::from(NFTA_COMPAT_TYPE))?,
    ) else {
        return Err(Errno::EINVAL);
    };
    let name = nul_string(name, NFT_COMPAT_NAME_MAX - 1)?;
    let rev = u8::try_from(rev).map_err(|_| Errno::EINVAL)?;
    // xtables reads 1 as a target and all the other values as a match.
    let target = ty == 1;
    let family = info.nfmsg.nfgen_family;
    if !matches!(family, NFPROTO_IPV4 | NFPROTO_IPV6 | NFPROTO_BRIDGE | NFPROTO_ARP) {
        return Err(Errno::EINVAL);
    }
    let best = xt_find_revision(family, name, rev, target)?;
    let flags = if info.req.portid != 0 { NLM_F_MULTI as u16 } else { 0 };
    let mut b = nfnl_msg_put(
        info.req.portid,
        info.nlh.seq,
        u16::from(NFNL_SUBSYS_NFT_COMPAT) << 8 | u16::from(NFNL_MSG_COMPAT_GET),
        flags,
        family,
        NFNETLINK_V0,
        0,
    );
    let mut s = alloc::vec::Vec::from(name);
    s.push(0);
    b.put(NFTA_COMPAT_NAME, &s);
    b.put(NFTA_COMPAT_REV, &u32::from(best).to_be_bytes());
    b.put(NFTA_COMPAT_TYPE, &u32::from(target).to_be_bytes());
    info.req.reply(b.finish());
    Ok(())
}

static NFNL_COMPAT_CB: [NfnlCallback; 1] = [NfnlCallback {
    call: Some(nfnl_compat_get),
    dump: None,
    kind: NfnlCbType::Rcu,
    attr_count: NFTA_COMPAT_MAX,
}];

/// The subsystem `NFNL_SUBSYS_NFT_COMPAT`, as `nfnl_compat_subsys` of Linux.
pub static NFT_COMPAT_SUBSYS: NfnlSubsystem = NfnlSubsystem {
    name: "nft-compat",
    subsys_id: NFNL_SUBSYS_NFT_COMPAT,
    cb: &NFNL_COMPAT_CB,
    begin: None,
};

fn ne16(d: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([d[at], d[at + 1]])
}

fn ne32(d: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]])
}

fn be16(d: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([d[at], d[at + 1]])
}

// xt_state.c. The bit of a state: `XT_STATE_INVALID`, then `XT_STATE_BIT` of each state.
const XT_STATE_INVALID: u32 = 1 << 0;

/// The bit of the state of a packet in a connection, `XT_STATE_BIT`.
fn xt_state_bit(ctinfo: u8) -> u32 {
    1 << (ctinfo % IP_CT_IS_REPLY + 1)
}

fn state_mt(info: &[u8], par: &XtAction<'_>) -> bool {
    let bit = match par.skb.nfct.get() {
        Some((_, ctinfo)) => xt_state_bit(ctinfo),
        None => XT_STATE_INVALID,
    };
    ne32(info, 0) & bit != 0
}

// xt_conntrack.c. The offsets in `struct xt_conntrack_mtinfo1`, 2 and 3.
const CT_ADDRS: usize = 0;
const CT_EXPIRES_MIN: usize = 128;
const CT_EXPIRES_MAX: usize = 132;
const CT_L4PROTO: usize = 136;
const CT_PORTS: usize = 138;
const CT_MATCH_FLAGS: usize = 146;
const CT_INVERT_FLAGS: usize = 148;
const CT_STATE_MASK: usize = 150;
const CT_STATUS_MASK_V2: usize = 152;
const CT_PORTS_HIGH: usize = 154;

const XT_CONNTRACK_STATE: u16 = 1 << 0;
const XT_CONNTRACK_PROTO: u16 = 1 << 1;
const XT_CONNTRACK_ORIGSRC: u16 = 1 << 2;
const XT_CONNTRACK_STATUS: u16 = 1 << 6;
const XT_CONNTRACK_EXPIRES: u16 = 1 << 7;
const XT_CONNTRACK_ORIGSRC_PORT: u16 = 1 << 8;
const XT_CONNTRACK_DIRECTION: u16 = 1 << 12;

const XT_CONNTRACK_STATE_SNAT: u16 = 1 << 6;
const XT_CONNTRACK_STATE_DNAT: u16 = 1 << 7;

fn conntrack_mt_v1(info: &[u8], par: &XtAction<'_>) -> bool {
    conntrack_mt(info, par, u16::from(info[CT_STATE_MASK]), info[CT_STATE_MASK + 1].into(), false)
}

fn conntrack_mt_v2(info: &[u8], par: &XtAction<'_>) -> bool {
    conntrack_mt(info, par, ne16(info, CT_STATE_MASK), ne16(info, CT_STATUS_MASK_V2), false)
}

fn conntrack_mt_v3(info: &[u8], par: &XtAction<'_>) -> bool {
    conntrack_mt(info, par, ne16(info, CT_STATE_MASK), ne16(info, CT_STATUS_MASK_V2), true)
}

/// Compares the address `k` of a tuple with the address and the mask at `at` in the data, as
/// `conntrack_addrcmp` of Linux.
fn conntrack_addrcmp(k: &[u8; 16], info: &[u8], at: usize, family: u8) -> bool {
    let n = match family {
        NFPROTO_IPV4 => 4,
        NFPROTO_IPV6 => 16,
        _ => return false,
    };
    (0..n).all(|i| (k[i] ^ info[at + i]) & info[at + 16 + i] == 0)
}

/// The match `conntrack`, as `conntrack_mt` of Linux. Revision 3 has the ranges of the ports
/// in the order of the host.
fn conntrack_mt(
    info: &[u8],
    par: &XtAction<'_>,
    state_mask: u16,
    status_mask: u16,
    v3: bool,
) -> bool {
    let flags = ne16(info, CT_MATCH_FLAGS);
    let inv = ne16(info, CT_INVERT_FLAGS);
    // The test of `flag`, inverted by the rule, fails.
    let fails = |flag: u16, ok: bool| flags & flag != 0 && ok == (inv & flag != 0);
    let ct = par.skb.nfct.get();
    let mut statebit = match ct {
        Some((_, ctinfo)) => xt_state_bit(ctinfo) as u16,
        None => XT_STATE_INVALID as u16,
    };
    if flags & XT_CONNTRACK_STATE != 0 {
        if let Some((ct, _)) = ct {
            if ct.status() & IPS_SRC_NAT != 0 {
                statebit |= XT_CONNTRACK_STATE_SNAT;
            }
            if ct.status() & IPS_DST_NAT != 0 {
                statebit |= XT_CONNTRACK_STATE_DNAT;
            }
        }
        if fails(XT_CONNTRACK_STATE, state_mask & statebit != 0) {
            return false;
        }
    }
    let Some((ct, ctinfo)) = ct else { return flags & XT_CONNTRACK_STATE != 0 };
    if fails(XT_CONNTRACK_DIRECTION, ctinfo < IP_CT_IS_REPLY) {
        return false;
    }
    let tuples = [ct.tuple(IP_CT_DIR_ORIGINAL), ct.tuple(IP_CT_DIR_REPLY)];
    // ORIGSRC, ORIGDST, REPLSRC and REPLDST.
    for i in 0..4 {
        let t = &tuples[i / 2];
        let addr = if i % 2 == 0 { &t.src } else { &t.dst };
        let ok = conntrack_addrcmp(addr, info, CT_ADDRS + i * 32, par.state.pf);
        if fails(XT_CONNTRACK_ORIGSRC << i, ok) {
            return false;
        }
    }
    if !ct_proto_port_check(info, &tuples, flags, inv, v3) {
        return false;
    }
    if fails(XT_CONNTRACK_STATUS, u32::from(status_mask) & ct.status() != 0) {
        return false;
    }
    if flags & XT_CONNTRACK_EXPIRES != 0 {
        let expires = ct.expires() / crate::options::hz();
        let ok = expires >= u64::from(ne32(info, CT_EXPIRES_MIN))
            && expires <= u64::from(ne32(info, CT_EXPIRES_MAX));
        if fails(XT_CONNTRACK_EXPIRES, ok) {
            return false;
        }
    }
    true
}

/// The checks of the protocol and the ports, as `ct_proto_port_check` and
/// `ct_proto_port_check_v3` of Linux.
fn ct_proto_port_check(
    info: &[u8],
    tuples: &[NfConntrackTuple; 2],
    flags: u16,
    inv: u16,
    v3: bool,
) -> bool {
    let fails = |flag: u16, ok: bool| flags & flag != 0 && ok == (inv & flag != 0);
    if fails(XT_CONNTRACK_PROTO, u16::from(tuples[0].protonum) == ne16(info, CT_L4PROTO)) {
        return false;
    }
    // ORIGSRC_PORT, ORIGDST_PORT, REPLSRC_PORT and REPLDST_PORT. The tuple has the ports in
    // the order of the host.
    for i in 0..4 {
        let t = &tuples[i / 2];
        let port = if i % 2 == 0 { t.src_u } else { t.dst_u };
        let ok = if v3 {
            port >= ne16(info, CT_PORTS + i * 2) && port <= ne16(info, CT_PORTS_HIGH + i * 2)
        } else {
            port == be16(info, CT_PORTS + i * 2)
        };
        if fails(XT_CONNTRACK_ORIGSRC_PORT << i, ok) {
            return false;
        }
    }
    true
}

fn comment_mt(_info: &[u8], _par: &XtAction<'_>) -> bool {
    true
}

// ip_tables.c and ip6_tables.c: `struct ipt_icmp` and `struct ip6t_icmp` are the type, the
// first and the last code, and the flags.
const IPT_ICMP_INV: u8 = 0x01;

fn icmp_checkentry(info: &[u8], _: &XtCheck) -> Result<()> {
    if info[3] & !IPT_ICMP_INV != 0 { Err(Errno::EINVAL) } else { Ok(()) }
}

fn icmp_match(info: &[u8], par: &XtAction<'_>) -> bool {
    // A fragment that is not the first has no header.
    if par.thoff.is_none() {
        return false;
    }
    let Some(h) = par.th(8) else { return false };
    // The type 0xff is any type.
    let ok = info[0] == 0xff || (h[0] == info[0] && h[1] >= info[1] && h[1] <= info[2]);
    ok != (info[3] & IPT_ICMP_INV != 0)
}

fn icmp6_match(info: &[u8], par: &XtAction<'_>) -> bool {
    if par.thoff.is_none() {
        return false;
    }
    let Some(h) = par.th(8) else { return false };
    (h[0] == info[0] && h[1] >= info[1] && h[1] <= info[2]) != (info[3] & IPT_ICMP_INV != 0)
}

// ipt_REJECT.c: `enum ipt_reject_with`.
const IPT_ICMP_ECHOREPLY: u32 = 4;
const IPT_TCP_RESET: u32 = 7;

fn reject_tg_check(info: &[u8], c: &XtCheck) -> Result<()> {
    match ne32(info, 0) {
        IPT_ICMP_ECHOREPLY => Err(Errno::EINVAL),
        IPT_TCP_RESET if c.proto != IPPROTO_TCP || c.inv => Err(Errno::EINVAL),
        _ => Ok(()),
    }
}

fn reject_tg(info: &[u8], par: &XtAction<'_>) -> u32 {
    reject_send(par, reject_how(ne32(info, 0)))
}

/// The answer of `REJECT` for IPv4: the ICMP code of unreachable network, host, protocol and
/// port, then of the prohibited network and host, then the TCP RST, then the filtered packet.
fn reject_how(with: u32) -> Option<NfReject> {
    match with {
        w @ 0..=3 => Some(NfReject::Unreach(w as u8)),
        5 => Some(NfReject::Unreach(9)),
        6 => Some(NfReject::Unreach(10)),
        IPT_TCP_RESET => Some(NfReject::TcpReset),
        8 => Some(NfReject::Unreach(13)),
        _ => None,
    }
}

// ip6t_REJECT.c: `enum ip6t_reject_with`.
const IP6T_ICMP6_ECHOREPLY: u32 = 5;
const IP6T_TCP_RESET: u32 = 6;

fn reject_tg6_check(info: &[u8], c: &XtCheck) -> Result<()> {
    match ne32(info, 0) {
        IP6T_ICMP6_ECHOREPLY => Err(Errno::EINVAL),
        IP6T_TCP_RESET if c.proto != IPPROTO_TCP || c.inv => Err(Errno::EINVAL),
        _ => Ok(()),
    }
}

fn reject_tg6(info: &[u8], par: &XtAction<'_>) -> u32 {
    reject_send(par, reject_how6(ne32(info, 0)))
}

/// The answer of `REJECT` for IPv6: the ICMPv6 code of no route, prohibited, not a neighbour,
/// unreachable address and port, then the TCP RST, then the failed policy and the reject
/// route.
fn reject_how6(with: u32) -> Option<NfReject> {
    match with {
        w @ 0..=4 => Some(NfReject::Unreach(w as u8)),
        IP6T_TCP_RESET => Some(NfReject::TcpReset),
        7 => Some(NfReject::Unreach(5)),
        8 => Some(NfReject::Unreach(6)),
        _ => None,
    }
}

fn reject_send(par: &XtAction<'_>, how: Option<NfReject>) -> u32 {
    if let Some(how) = how {
        let s = par.state;
        nf_send_reject(s.pf, s.hook, s.in_dev, par.skb.data(), how);
    }
    NF_DROP
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::SOCK_RAW;
    use crate::netfilter::nf_conntrack::tests::{SERIAL, fresh, ip4, state, udp};
    use crate::netfilter::nf_conntrack::{nf_conntrack_confirm, nf_conntrack_in};
    use crate::netfilter::{NF_ACCEPT, NF_INET_LOCAL_OUT};
    use crate::netlink::NetlinkSocket;
    use crate::netlink::msg::{self, Builder, HDRLEN, Header};
    use crate::netlink::nfnetlink::{NETLINK_NETFILTER, NFGENMSG_LEN, NfGenMsg};
    use crate::{Message, NoPaths, Socket, dev};
    use alloc::vec;
    use alloc::vec::Vec;
    use rk_abi::native::netlink::{NLM_F_REQUEST, NLMSG_ERROR};

    const A: [u8; 4] = [10, 9, 2, 1];
    const B: [u8; 4] = [10, 9, 2, 2];

    fn attrs(list: &[(u16, &[u8])]) -> Vec<u8> {
        let mut b = Builder::new(0, 0, 0, 0);
        for (ty, d) in list {
            b.put(*ty, d);
        }
        b.finish()[HDRLEN..].to_vec()
    }

    /// The data of the expression `match` or `target` of `name`, revision `rev`.
    fn xt(name: &str, rev: u32, info: &[u8]) -> Vec<u8> {
        let mut n = Vec::from(name.as_bytes());
        n.push(0);
        attrs(&[(1, &n), (2, &rev.to_be_bytes()), (3, info)])
    }

    /// `NFTA_RULE_COMPAT` with the protocol `proto` and the flags `flags`.
    fn compat(proto: u32, flags: u32) -> Vec<u8> {
        attrs(&[(1, &proto.to_be_bytes()), (2, &flags.to_be_bytes())])
    }

    fn init(target: bool, family: u8, data: &[u8], c: Option<&[u8]>) -> Result<NftXt> {
        nft_xt_init(target, b"filter", family, data, c)
    }

    fn run(x: &NftXt, skb: &NetBuf) -> u32 {
        x.eval(skb, &state(NF_INET_LOCAL_OUT), Some(20))
    }

    /// The data of `xt_conntrack_mtinfo3` with the flags, the inverted flags and the state
    /// mask, and the range of the original destination port.
    fn ctinfo3(flags: u16, inv: u16, states: u16, dport: (u16, u16)) -> Vec<u8> {
        let mut d = vec![0u8; xt_align(164)];
        d[CT_PORTS + 2..CT_PORTS + 4].copy_from_slice(&dport.0.to_ne_bytes());
        d[CT_PORTS_HIGH + 2..CT_PORTS_HIGH + 4].copy_from_slice(&dport.1.to_ne_bytes());
        d[CT_MATCH_FLAGS..CT_MATCH_FLAGS + 2].copy_from_slice(&flags.to_ne_bytes());
        d[CT_INVERT_FLAGS..CT_INVERT_FLAGS + 2].copy_from_slice(&inv.to_ne_bytes());
        d[CT_STATE_MASK..CT_STATE_MASK + 2].copy_from_slice(&states.to_ne_bytes());
        d
    }

    #[test]
    fn the_best_revision_and_the_errors_of_the_lookup() {
        let v4 = NFPROTO_IPV4;
        assert_eq!(xt_find_revision(v4, b"conntrack", 1, false), Ok(3));
        assert_eq!(xt_find_revision(v4, b"conntrack", 0, false), Err(Errno::EPROTONOSUPPORT));
        assert_eq!(xt_find_revision(v4, b"nothing", 0, false), Err(Errno::ENOENT));
        assert_eq!(xt_find_revision(v4, b"REJECT", 0, true), Ok(0));
        assert_eq!(xt_find_revision(v4, b"REJECT", 0, false), Err(Errno::ENOENT));
        assert_eq!(xt_find_revision(NFPROTO_IPV6, b"icmp", 0, false), Err(Errno::ENOENT));
        assert_eq!(xt_find_revision(NFPROTO_IPV6, b"state", 0, false), Ok(0));
        assert_eq!(nul_string(b"abc\0", 3), Ok(&b"abc"[..]));
        assert_eq!(nul_string(b"abcd", 3), Err(Errno::EINVAL));
        assert_eq!(nul_string(b"ab\0de", 3), Err(Errno::ERANGE));
    }

    #[test]
    fn the_init_checks_the_extension_and_the_rule() {
        let v4 = NFPROTO_IPV4;
        let reject =
            |with: u32| xt("REJECT", 0, &[with.to_ne_bytes().as_slice(), &[0; 4]].concat());
        let tcp = compat(6, 0);
        // The name, the revision and the data are needed, and the data has the size of the
        // extension.
        assert_eq!(init(false, v4, &attrs(&[]), None).unwrap_err(), Errno::EINVAL);
        assert_eq!(init(false, v4, &xt("nothing", 0, &[0; 8]), None).unwrap_err(), Errno::ENOENT);
        assert_eq!(init(false, v4, &xt("state", 0, &[0; 16]), None).unwrap_err(), Errno::EINVAL);
        assert_eq!(init(false, v4, &xt("state", 0, &[0; 2]), None).unwrap_err(), Errno::EINVAL);
        assert_eq!(init(false, v4, &xt("state", 256, &[0; 8]), None).unwrap_err(), Errno::EINVAL);
        assert!(init(false, v4, &xt("state", 0, &[0; 8]), None).unwrap().needs_ct());
        assert!(init(false, NFPROTO_INET, &xt("state", 0, &[0; 4]), None).is_ok());
        assert_eq!(
            init(false, NFPROTO_INET, &xt("icmp", 0, &[0; 8]), None).unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            init(false, crate::netfilter::NFPROTO_NETDEV, &xt("state", 0, &[0; 8]), None)
                .unwrap_err(),
            Errno::EOPNOTSUPP
        );
        // icmp needs the protocol ICMP, not inverted, and knows only the flag of inversion.
        let icmp = xt("icmp", 0, &[8, 0, 0xff, 0, 0, 0, 0, 0]);
        let c1 = compat(1, 0);
        assert!(init(false, v4, &icmp, Some(&c1)).is_ok());
        assert_eq!(init(false, v4, &icmp, None).unwrap_err(), Errno::EINVAL);
        assert_eq!(init(false, v4, &icmp, Some(&compat(17, 0))).unwrap_err(), Errno::EINVAL);
        let inv = compat(1, NFT_RULE_COMPAT_F_INV);
        assert_eq!(init(false, v4, &icmp, Some(&inv)).unwrap_err(), Errno::EINVAL);
        let bad = xt("icmp", 0, &[8, 0, 0xff, 2, 0, 0, 0, 0]);
        assert_eq!(init(false, v4, &bad, Some(&c1)).unwrap_err(), Errno::EINVAL);
        // The flags of the rule: an unused or unknown flag, and no flags.
        for c in [compat(1, NFT_RULE_COMPAT_F_UNUSED), compat(1, 4), attrs(&[(1, &[0, 0, 0, 1])])] {
            assert_eq!(init(false, v4, &icmp, Some(&c)).unwrap_err(), Errno::EINVAL);
        }
        // REJECT is a target of the table filter. The TCP RST needs the protocol TCP, and the
        // echo reply is not there any more.
        let x = init(true, v4, &reject(IPT_TCP_RESET), Some(&tcp)).unwrap();
        assert_eq!(x.hooks(), REJECT_HOOKS);
        assert_eq!(init(false, v4, &reject(3), None).unwrap_err(), Errno::ENOENT);
        assert_eq!(nft_xt_init(true, b"nat", v4, &reject(3), None).unwrap_err(), Errno::EINVAL);
        assert_eq!(init(true, v4, &reject(IPT_TCP_RESET), None).unwrap_err(), Errno::EINVAL);
        let tinv = compat(6, NFT_RULE_COMPAT_F_INV);
        assert_eq!(init(true, v4, &reject(IPT_TCP_RESET), Some(&tinv)).unwrap_err(), Errno::EINVAL);
        assert_eq!(init(true, v4, &reject(IPT_ICMP_ECHOREPLY), None).unwrap_err(), Errno::EINVAL);
        let v6 = NFPROTO_IPV6;
        assert!(init(true, v6, &reject(IP6T_TCP_RESET), Some(&tcp)).is_ok());
        assert_eq!(init(true, v6, &reject(IP6T_TCP_RESET), None).unwrap_err(), Errno::EINVAL);
        assert_eq!(init(true, v6, &reject(IP6T_ICMP6_ECHOREPLY), None).unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn reject_sends_the_code_of_each_type_and_drops() {
        assert_eq!(reject_how(3), Some(NfReject::Unreach(3)));
        assert_eq!(reject_how(6), Some(NfReject::Unreach(10)));
        assert_eq!(reject_how(IPT_TCP_RESET), Some(NfReject::TcpReset));
        assert_eq!(reject_how(8), Some(NfReject::Unreach(13)));
        assert_eq!(reject_how(IPT_ICMP_ECHOREPLY), None);
        assert_eq!(reject_how6(4), Some(NfReject::Unreach(4)));
        assert_eq!(reject_how6(IP6T_TCP_RESET), Some(NfReject::TcpReset));
        assert_eq!(reject_how6(8), Some(NfReject::Unreach(6)));
        // A type with no answer only drops.
        let x = init(true, NFPROTO_IPV4, &xt("REJECT", 0, &[9, 0, 0, 0, 0, 0, 0, 0]), None);
        let skb = ip4(1, A, B, &[8, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(run(&x.unwrap(), &skb), NF_DROP);
    }

    #[test]
    fn icmp_matches_the_type_and_the_codes() {
        let c = compat(1, 0);
        let m = |info: [u8; 4]| {
            let mut d = info.to_vec();
            d.resize(8, 0);
            init(false, NFPROTO_IPV4, &xt("icmp", 0, &d), Some(&c)).unwrap()
        };
        let echo = ip4(1, A, B, &[8, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(run(&m([8, 0, 0xff, 0]), &echo), NFT_CONTINUE);
        assert_eq!(run(&m([0, 0, 0xff, 0]), &echo), NFT_BREAK);
        assert_eq!(run(&m([0, 0, 0xff, IPT_ICMP_INV]), &echo), NFT_CONTINUE);
        assert_eq!(run(&m([8, 1, 0xff, 0]), &echo), NFT_BREAK);
        assert_eq!(run(&m([0xff, 0, 0, 0]), &echo), NFT_CONTINUE);
        // A short header drops the packet, and a fragment that is not the first does not
        // match.
        let short = ip4(1, A, B, &[8, 0, 0, 0]);
        assert_eq!(run(&m([8, 0, 0xff, 0]), &short), NF_DROP);
        let s = state(NF_INET_LOCAL_OUT);
        assert_eq!(m([8, 0, 0xff, 0]).eval(&echo, &s, None), NFT_BREAK);
        // icmp6 has no type for all the types.
        let c6 = compat(58, 0);
        let x =
            init(false, NFPROTO_IPV6, &xt("icmp6", 0, &[0xff, 0, 0xff, 0, 0, 0, 0, 0]), Some(&c6));
        assert_eq!(run(&x.unwrap(), &echo), NFT_BREAK);
    }

    #[test]
    fn state_and_conntrack_match_the_connection() {
        let _s = SERIAL.lock();
        fresh(5000);
        let v4 = NFPROTO_IPV4;
        let statem = |mask: u32| {
            init(
                false,
                v4,
                &xt("state", 0, &[mask.to_ne_bytes().as_slice(), &[0; 4]].concat()),
                None,
            )
            .unwrap()
        };
        let new = xt_state_bit(crate::netfilter::nf_conntrack::IP_CT_NEW);
        let mut p = ip4(17, A, B, &udp(4000, 9));
        // No connection: the state is invalid.
        assert_eq!(run(&statem(XT_STATE_INVALID), &p), NFT_CONTINUE);
        assert_eq!(run(&statem(new), &p), NFT_BREAK);
        assert_eq!(nf_conntrack_in(&mut p, &state(NF_INET_LOCAL_OUT)), NF_ACCEPT);
        assert_eq!(nf_conntrack_confirm(&mut p), NF_ACCEPT);
        assert_eq!(run(&statem(new), &p), NFT_CONTINUE);
        assert_eq!(run(&statem(XT_STATE_INVALID), &p), NFT_BREAK);
        // conntrack: --ctstate NEW --ctorigdstport 9, then 10:20, then ! 10:20, and the
        // direction.
        let ct = |flags: u16, inv: u16, ports: (u16, u16)| {
            let d = ctinfo3(flags, inv, new as u16, ports);
            init(false, v4, &xt("conntrack", 3, &d), None).unwrap()
        };
        let both = XT_CONNTRACK_STATE | XT_CONNTRACK_ORIGSRC_PORT << 1;
        assert_eq!(run(&ct(both, 0, (9, 9)), &p), NFT_CONTINUE);
        assert_eq!(run(&ct(both, 0, (10, 20)), &p), NFT_BREAK);
        assert_eq!(run(&ct(both, XT_CONNTRACK_ORIGSRC_PORT << 1, (10, 20)), &p), NFT_CONTINUE);
        assert_eq!(run(&ct(both, XT_CONNTRACK_STATE, (9, 9)), &p), NFT_BREAK);
        let dir = XT_CONNTRACK_DIRECTION;
        assert_eq!(run(&ct(dir, 0, (0, 0)), &p), NFT_CONTINUE);
        assert_eq!(run(&ct(dir, dir, (0, 0)), &p), NFT_BREAK);
        // The original source address with a mask of 24 bits, and the protocol UDP in
        // revision 1.
        let mut d = vec![0u8; 152];
        d[0..4].copy_from_slice(&[10, 9, 2, 77]);
        d[16..19].copy_from_slice(&[255; 3]);
        d[CT_L4PROTO..CT_L4PROTO + 2].copy_from_slice(&17u16.to_ne_bytes());
        let f = XT_CONNTRACK_ORIGSRC | XT_CONNTRACK_PROTO;
        d[CT_MATCH_FLAGS..CT_MATCH_FLAGS + 2].copy_from_slice(&f.to_ne_bytes());
        let x = init(false, v4, &xt("conntrack", 1, &d), None).unwrap();
        assert_eq!(run(&x, &p), NFT_CONTINUE);
        d[CT_L4PROTO] = 6;
        let x = init(false, v4, &xt("conntrack", 1, &d), None).unwrap();
        assert_eq!(run(&x, &p), NFT_BREAK);
        // A packet with no connection matches only a rule with a state.
        let q = ip4(17, A, B, &udp(4001, 9));
        assert_eq!(run(&ct(dir, 0, (0, 0)), &q), NFT_BREAK);
        let invalid = ctinfo3(XT_CONNTRACK_STATE, 0, XT_STATE_INVALID as u16, (0, 0));
        let x = init(false, v4, &xt("conntrack", 3, &invalid), None).unwrap();
        assert_eq!(run(&x, &q), NFT_CONTINUE);
        // The comment always matches.
        let x = init(false, v4, &xt("comment", 0, &[0; 256]), None).unwrap();
        assert_eq!(run(&x, &q), NFT_CONTINUE);
        assert_eq!(x.hooks(), 0);
    }

    /// Sends `NFNL_MSG_COMPAT_GET` and gives the reply or the error.
    fn get(
        s: &NetlinkSocket,
        family: u8,
        name: &[u8],
        rev: u32,
        ty: u32,
    ) -> (Option<Vec<u8>>, i32) {
        let t = u16::from(NFNL_SUBSYS_NFT_COMPAT) << 8 | u16::from(NFNL_MSG_COMPAT_GET);
        let mut b = Builder::new(t, NLM_F_REQUEST as u16, 1, 0);
        b.fixed(&NfGenMsg { nfgen_family: family, version: NFNETLINK_V0, res_id: 0 }.bytes());
        b.put(NFTA_COMPAT_NAME, name);
        b.put(NFTA_COMPAT_REV, &rev.to_be_bytes());
        b.put(NFTA_COMPAT_TYPE, &ty.to_be_bytes());
        s.send(&NoPaths, Message { data: b.finish(), ..Message::default() }, 0, true).unwrap();
        let (mut out, mut err) = (None, 0);
        while let Ok(r) = s.recv(65536, 0, true) {
            for m in msg::messages(&r.data) {
                let h = Header::parse(m).unwrap();
                if h.ty == NLMSG_ERROR as u16 {
                    err = i32::from_ne_bytes(m[HDRLEN..HDRLEN + 4].try_into().unwrap());
                } else {
                    assert_eq!(h.ty, t);
                    out = Some(m[HDRLEN + NFGENMSG_LEN..].to_vec());
                }
            }
        }
        (out, err)
    }

    #[test]
    fn compat_get_gives_the_best_revision() {
        let _d = crate::TEST_DEVICES.lock();
        dev::init();
        crate::netlink::init();
        let s = NetlinkSocket::new(SOCK_RAW, NETLINK_NETFILTER).unwrap();
        let (r, e) = get(&s, NFPROTO_IPV4, b"conntrack\0", 1, 0);
        assert_eq!(e, 0);
        let r = r.unwrap();
        let a = Attrs::parse(&r, NFTA_COMPAT_MAX);
        assert_eq!(a.str(u32::from(NFTA_COMPAT_NAME)), Some(&b"conntrack"[..]));
        assert_eq!(be32(&a, u32::from(NFTA_COMPAT_REV)), Ok(Some(3)));
        assert_eq!(be32(&a, u32::from(NFTA_COMPAT_TYPE)), Ok(Some(0)));
        let (r, e) = get(&s, NFPROTO_IPV6, b"REJECT\0", 0, 1);
        assert_eq!(e, 0);
        let a = Attrs::parse(r.as_ref().unwrap(), NFTA_COMPAT_MAX);
        assert_eq!(be32(&a, u32::from(NFTA_COMPAT_TYPE)), Ok(Some(1)));
        let errno = |e: Errno| -(e.get() as i32);
        assert_eq!(get(&s, NFPROTO_IPV4, b"conntrack\0", 9, 0).1, errno(Errno::EPROTONOSUPPORT));
        assert_eq!(get(&s, NFPROTO_IPV4, b"nothing\0", 0, 0).1, errno(Errno::ENOENT));
        assert_eq!(get(&s, NFPROTO_INET, b"state\0", 0, 0).1, errno(Errno::EINVAL));
        assert_eq!(get(&s, NFPROTO_IPV4, b"state", 0, 0).1, errno(Errno::EINVAL));
    }
}

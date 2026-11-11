//! The stateful objects of nf_tables, as the objects of nf_tables_api.c and nft_counter.c,
//! nft_quota.c, nft_limit.c and nft_objref.c of Linux.
//!
//! A table has objects with a name and a type: `counter`, `quota` and `limit`. Two objects of
//! different types can have the same name. A rule uses an object with the expression `objref`:
//! by its name, or by the key of the packet in a map of objects. The copies of a table in a
//! batch share the state of each object, and a packet changes it with no lock on the tables.
//!
//! The same states are the stateful expressions of a set and of its elements, as
//! `nft_set_elem_expr_alloc` of Linux, with `connlimit` of nft_connlimit.c. Each element has
//! its own state: a copy of the expressions of the set, or the ones that it gives.

use super::super::{
    NF_DROP, NFT, NFT_MSG_DELOBJ, NFT_MSG_DESTROYOBJ, NFT_MSG_GETOBJ_RESET, NFT_MSG_NEWOBJ,
    NFT_SET_OBJECT, NFT_SET_TIMEOUT, NFTA_LIST_ELEM, NFTA_SET_ELEM_OBJREF, NftBatch, NftCtx,
    NftData, NftTable, bad, be32, be64, cstr, family_match, nfnl_msg_put, nfnl_msg_type,
    nft_set_lookup_global, nft_table_lookup, nft_type, nla_name, nla_udata,
};
use super::{
    NFT_BREAK, NFTA_COUNTER_BYTES, NFTA_COUNTER_PACKETS, NFTA_EXPR_DATA, NFTA_EXPR_MAX,
    NFTA_EXPR_NAME, NftExpr, NftLimit, NftRegs, nf_tables_expr_parse, nft_limit_eval,
    nft_limit_init, nft_parse_register, nla_raw,
};
use crate::buf::NetBuf;
use crate::netfilter::nf_conntrack::{NfConntrackTuple, nf_conntrack_find_get, nf_ct_get_tuple};
use crate::netfilter::{NFPROTO_IPV4, NFPROTO_IPV6};
use crate::netlink::msg::{self, Attrs, Builder};
use crate::netlink::nfnetlink::{NFNETLINK_V0, NfnlInfo};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::netlink::{NLM_F_EXCL, NLM_F_MULTI, NLM_F_REPLACE};
use rk_frame::sync::SpinLock;
use rk_vfs::inode::Result;

// The attributes of an object, `enum nft_object_attributes`.
const NFTA_OBJ_TABLE: u32 = 1;
const NFTA_OBJ_NAME: u32 = 2;
const NFTA_OBJ_TYPE: u32 = 3;
const NFTA_OBJ_DATA: u32 = 4;
const NFTA_OBJ_USE: u32 = 5;
const NFTA_OBJ_HANDLE: u32 = 6;
const NFTA_OBJ_USERDATA: u32 = 8;
/// The last attribute of an object, `NFTA_OBJ_MAX`.
pub(in super::super) const NFTA_OBJ_MAX: u16 = 8;

// The types of the objects.
const NFT_OBJECT_UNSPEC: u32 = 0;
const NFT_OBJECT_COUNTER: u32 = 1;
const NFT_OBJECT_QUOTA: u32 = 2;
const NFT_OBJECT_LIMIT: u32 = 4;
/// The last type of an object, `NFT_OBJECT_MAX` (`NFT_OBJECT_SYNPROXY`).
pub(in super::super) const NFT_OBJECT_MAX: u32 = 10;

// The attributes of `quota`, `enum nft_quota_attributes`.
const NFTA_QUOTA_BYTES: u32 = 1;
const NFTA_QUOTA_FLAGS: u32 = 2;
const NFTA_QUOTA_CONSUMED: u32 = 4;
const NFT_QUOTA_F_INV: u32 = 1;
const NFT_QUOTA_F_DEPLETED: u32 = 2;

// The attributes of `objref`, `enum nft_objref_attributes`.
const NFTA_OBJREF_IMM_TYPE: u32 = 1;
const NFTA_OBJREF_IMM_NAME: u32 = 2;
const NFTA_OBJREF_SET_SREG: u32 = 3;
pub(super) const NFTA_OBJREF_SET_NAME: u32 = 4;
pub(super) const NFTA_OBJREF_SET_ID: u32 = 5;

/// The state of a `counter` object, as `struct nft_counter` of Linux.
#[derive(Debug, Default)]
pub(crate) struct NftCounter {
    packets: AtomicU64,
    bytes: AtomicU64,
}

/// `quota`, as `struct nft_quota` of Linux: the bytes that the packets can have, and the bytes
/// that they had.
#[derive(Debug)]
pub(crate) struct NftQuota {
    quota: AtomicU64,
    consumed: AtomicU64,
    /// `NFT_QUOTA_F_INV`: the packets match when they are over the quota.
    flags: AtomicU32,
}

// The attributes of `connlimit`, `enum nft_connlimit_attributes`.
const NFTA_CONNLIMIT_COUNT: u32 = 1;
const NFTA_CONNLIMIT_FLAGS: u32 = 2;
const NFT_CONNLIMIT_F_INV: u32 = 1;

/// The most expressions of a set or of an element, `NFT_SET_EXPR_MAX`.
const NFT_SET_EXPR_MAX: usize = 2;

/// `connlimit`, as nft_connlimit.c: the most connections, and the connections that the
/// packets had, as the list of nf_conncount.c of Linux.
pub(crate) struct NftConnlimit {
    limit: u32,
    invert: bool,
    conns: SpinLock<Vec<NfConntrackTuple>>,
}

impl fmt::Debug for NftConnlimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NftConnlimit")
            .field("limit", &self.limit)
            .field("invert", &self.invert)
            .finish()
    }
}

/// Reads a `connlimit`, as `nft_connlimit_do_init` of Linux.
pub(super) fn nft_connlimit_init(data: &[u8]) -> Result<Arc<NftConnlimit>> {
    let a = Attrs::parse(data, 2);
    let Some(limit) = be32(&a, NFTA_CONNLIMIT_COUNT)? else { return Err(Errno::EINVAL) };
    let flags = be32(&a, NFTA_CONNLIMIT_FLAGS)?.unwrap_or(0);
    if flags & !NFT_CONNLIMIT_F_INV != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(Arc::new(NftConnlimit {
        limit,
        invert: flags & NFT_CONNLIMIT_F_INV != 0,
        conns: SpinLock::new(Vec::new()),
    }))
}

/// Counts the connection of the packet, as `nft_connlimit_do_eval` and `nf_conncount_add` of
/// Linux. The list keeps only the connections that connection tracking still has. A packet
/// with no tuple is dropped. A count over the limit ends the rule, or a count that is not over
/// it with `NFT_CONNLIMIT_F_INV`.
pub(super) fn nft_connlimit_eval(c: &NftConnlimit, regs: &mut NftRegs, skb: &NetBuf) {
    let tuple = match skb.nfct.get() {
        Some((ct, _)) => ct.tuple(0),
        None => {
            let d = skb.data();
            let pf =
                if d.first().is_some_and(|v| v >> 4 == 6) { NFPROTO_IPV6 } else { NFPROTO_IPV4 };
            match nf_ct_get_tuple(pf, d) {
                Some((t, _)) => t,
                None => {
                    regs.verdict = NF_DROP;
                    return;
                }
            }
        }
    };
    let count = {
        let mut conns = c.conns.lock();
        conns.retain(|t| *t == tuple || nf_conntrack_find_get(t).is_some());
        if !conns.contains(&tuple) {
            conns.push(tuple);
        }
        conns.len()
    };
    if (count > c.limit as usize) != c.invert {
        regs.verdict = NFT_BREAK;
    }
}

/// The state of an object, or of a stateful expression of a set or of an element. The copies
/// of the object share it.
#[derive(Clone, Debug)]
pub(crate) enum NftObjState {
    Counter(Arc<NftCounter>),
    Quota(Arc<NftQuota>),
    /// A `limit`, with the attributes that made it, for the dump.
    Limit(Arc<NftLimit>, Vec<u8>),
    /// A `connlimit`, only as an expression.
    Connlimit(Arc<NftConnlimit>),
}

impl NftObjState {
    /// The name of the expression of the state.
    pub(crate) fn name(&self) -> &'static [u8] {
        match self {
            NftObjState::Counter(_) => b"counter",
            NftObjState::Quota(_) => b"quota",
            NftObjState::Limit(..) => b"limit",
            NftObjState::Connlimit(_) => b"connlimit",
        }
    }

    /// The state is a `connlimit`, that needs connection tracking.
    pub(crate) fn is_connlimit(&self) -> bool {
        matches!(self, NftObjState::Connlimit(_))
    }

    /// A new state with the values of this one, as `nft_expr_clone` of Linux. A counter and
    /// a quota keep their counts, a limit gets a full bucket, and a `connlimit` an empty list.
    pub(crate) fn fresh(&self) -> NftObjState {
        match self {
            NftObjState::Counter(c) => NftObjState::Counter(Arc::new(NftCounter {
                packets: AtomicU64::new(c.packets.load(Ordering::Relaxed)),
                bytes: AtomicU64::new(c.bytes.load(Ordering::Relaxed)),
            })),
            NftObjState::Quota(q) => NftObjState::Quota(Arc::new(NftQuota {
                quota: AtomicU64::new(q.quota.load(Ordering::Relaxed)),
                consumed: AtomicU64::new(q.consumed.load(Ordering::Relaxed)),
                flags: AtomicU32::new(q.flags.load(Ordering::Relaxed)),
            })),
            NftObjState::Limit(l, data) => match nft_limit_init(data) {
                Ok(n) => NftObjState::Limit(n, data.clone()),
                Err(_) => NftObjState::Limit(l.clone(), data.clone()),
            },
            NftObjState::Connlimit(c) => NftObjState::Connlimit(Arc::new(NftConnlimit {
                limit: c.limit,
                invert: c.invert,
                conns: SpinLock::new(Vec::new()),
            })),
        }
    }
}

/// Reads a stateful expression of the set with the flags `set_flags`, as
/// `nft_set_elem_expr_alloc` of Linux. An expression that is not stateful gives `EOPNOTSUPP`,
/// and `connlimit` in a set with timeouts too: its list has no garbage collection there.
pub(crate) fn nft_set_elem_expr_alloc(
    table: &NftTable,
    set_flags: u32,
    nla: &[u8],
) -> Result<NftObjState> {
    let tb = Attrs::parse(nla, NFTA_EXPR_MAX);
    let Some(name) = tb.str(NFTA_EXPR_NAME) else { return Err(Errno::EINVAL) };
    let name = name.split(|&c| c == 0).next().unwrap_or(name);
    let data = tb.get(NFTA_EXPR_DATA).unwrap_or(&[]);
    match name {
        b"counter" => nft_obj_state_init(NFT_OBJECT_COUNTER, data),
        b"quota" => nft_obj_state_init(NFT_OBJECT_QUOTA, data),
        b"limit" => nft_obj_state_init(NFT_OBJECT_LIMIT, data),
        b"connlimit" => {
            let c = nft_connlimit_init(data)?;
            if set_flags & NFT_SET_TIMEOUT != 0 {
                return Err(Errno::EOPNOTSUPP);
            }
            Ok(NftObjState::Connlimit(c))
        }
        // An expression that Linux knows, but that has no state.
        _ => match nf_tables_expr_parse(table, nla, None) {
            Ok(_) => Err(Errno::EOPNOTSUPP),
            Err(e) => Err(e),
        },
    }
}

/// Reads the expressions of a set, of an element or of `dynset`: one in the attribute
/// `single`, or a list in `list`. The list needs `list_ok`, the flag that allows it, or gives
/// `EINVAL`. `want` is the list of expressions that the set has: the expressions must be of the
/// same types, in the same order, or they give `EOPNOTSUPP`, as `nft_add_set_elem` and
/// `nft_dynset_init` of Linux. A list with more than `NFT_SET_EXPR_MAX` gives `E2BIG`.
pub(crate) fn nft_set_exprs_parse(
    table: &NftTable,
    set_flags: u32,
    a: &Attrs<'_>,
    (single, list): (u32, u32),
    list_ok: bool,
    want: &[NftObjState],
) -> Result<Option<Vec<NftObjState>>> {
    if let Some(e) = a.get(single) {
        let s = nft_set_elem_expr_alloc(table, set_flags, e)?;
        if want.first().is_some_and(|w| w.name() != s.name()) {
            return Err(Errno::EOPNOTSUPP);
        }
        return Ok(Some(alloc::vec![s]));
    }
    let Some(l) = a.get(list) else { return Ok(None) };
    if !list_ok {
        return Err(Errno::EINVAL);
    }
    let mut out = Vec::new();
    for (ty, e) in msg::attrs(l) {
        if out.len() == NFT_SET_EXPR_MAX || (!want.is_empty() && out.len() == want.len()) {
            return Err(Errno::E2BIG);
        }
        if ty != NFTA_LIST_ELEM {
            return Err(Errno::EINVAL);
        }
        let s = nft_set_elem_expr_alloc(table, set_flags, e)?;
        if want.get(out.len()).is_some_and(|w| w.name() != s.name()) {
            return Err(Errno::EOPNOTSUPP);
        }
        out.push(s);
    }
    if !want.is_empty() && want.len() != out.len() {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(Some(out))
}

/// Adds one expression in the attribute `attr`, as `nft_expr_dump` of Linux.
fn nft_state_expr_dump(b: &mut Builder, attr: u16, s: &NftObjState, reset: bool) {
    let nest = b.nest(attr);
    b.put(NFTA_EXPR_NAME as u16, &cstr(s.name()));
    let data = b.nest(NFTA_EXPR_DATA as u16);
    nft_state_dump(s, b, reset, None);
    b.end_nest(data);
    b.end_nest(nest);
}

/// Adds the expressions of a set, of an element or of `dynset`: one in `single`, more in a
/// list in `list`, as `nft_set_elem_expr_dump` of Linux.
pub(crate) fn nft_set_exprs_dump(
    b: &mut Builder,
    (single, list): (u32, u32),
    exprs: &[NftObjState],
    reset: bool,
) {
    match exprs {
        [] => {}
        [s] => nft_state_expr_dump(b, single as u16, s, reset),
        _ => {
            let nest = b.nest(list as u16);
            for s in exprs {
                nft_state_expr_dump(b, NFTA_LIST_ELEM, s, reset);
            }
            b.end_nest(nest);
        }
    }
}

/// Runs the expressions of an element on a packet, as `nft_set_elem_update_expr` of Linux:
/// an expression that ends the rule stops the others.
pub(super) fn nft_set_elem_update_expr(exprs: &[NftObjState], regs: &mut NftRegs, skb: &NetBuf) {
    for s in exprs {
        nft_obj_eval(s, regs, skb);
        if regs.verdict == NFT_BREAK {
            return;
        }
    }
}

/// An object of a table, as `struct nft_object` of Linux.
#[derive(Clone, Debug)]
pub(crate) struct NftObj {
    pub(crate) name: Vec<u8>,
    pub(crate) handle: u64,
    ty: u32,
    udata: Option<Vec<u8>>,
    state: NftObjState,
    /// The quota and the flags of a quota that the batch changes. The commit puts them in the
    /// state, as `nft_obj_commit_update` of Linux.
    update: Option<(u64, u32)>,
}

/// Reads the attributes of a quota, as `nft_quota_do_init` of Linux. Gives the quota, the
/// bytes that the packets had, and the flags.
fn nft_quota_parse(data: &[u8]) -> Result<(u64, u64, u32)> {
    let a = Attrs::parse(data, 4);
    let Some(quota) = be64(&a, NFTA_QUOTA_BYTES)? else { return Err(Errno::EINVAL) };
    if quota > i64::MAX as u64 {
        return Err(Errno::EOVERFLOW);
    }
    let consumed = be64(&a, NFTA_QUOTA_CONSUMED)?.unwrap_or(0);
    if consumed > quota {
        return Err(Errno::EINVAL);
    }
    let flags = be32(&a, NFTA_QUOTA_FLAGS)?.unwrap_or(0);
    if flags & !NFT_QUOTA_F_INV != 0 {
        return Err(Errno::EINVAL);
    }
    Ok((quota, consumed, flags))
}

/// Reads a `quota` expression or object.
pub(super) fn nft_quota_init(data: &[u8]) -> Result<Arc<NftQuota>> {
    let (quota, consumed, flags) = nft_quota_parse(data)?;
    Ok(Arc::new(NftQuota {
        quota: AtomicU64::new(quota),
        consumed: AtomicU64::new(consumed),
        flags: AtomicU32::new(flags),
    }))
}

/// Adds the bytes of the packet to the quota, as `nft_quota_do_eval` of Linux. A packet over
/// the quota ends the rule, or a packet under it with `NFT_QUOTA_F_INV`.
pub(super) fn nft_quota_eval(q: &NftQuota, regs: &mut NftRegs, skb: &NetBuf) {
    let len = skb.len() as u64;
    let consumed = q.consumed.fetch_add(len, Ordering::Relaxed).wrapping_add(len);
    let over = consumed > q.quota.load(Ordering::Relaxed);
    if over != (q.flags.load(Ordering::Relaxed) & NFT_QUOTA_F_INV != 0) {
        regs.verdict = NFT_BREAK;
    }
}

/// Runs an object on a packet, as the `eval` of the types of objects of Linux.
pub(super) fn nft_obj_eval(s: &NftObjState, regs: &mut NftRegs, skb: &NetBuf) {
    match s {
        NftObjState::Counter(c) => {
            c.packets.fetch_add(1, Ordering::Relaxed);
            c.bytes.fetch_add(skb.len() as u64, Ordering::Relaxed);
        }
        NftObjState::Quota(q) => nft_quota_eval(q, regs, skb),
        NftObjState::Limit(l, _) => nft_limit_eval(l, regs, skb),
        NftObjState::Connlimit(c) => nft_connlimit_eval(c, regs, skb),
    }
}

/// Makes the state of an object of the type `ty`, as `nft_obj_init` of Linux. A type that is
/// not here gives `ENOENT`, as a module that Linux cannot load.
fn nft_obj_state_init(ty: u32, data: &[u8]) -> Result<NftObjState> {
    match ty {
        NFT_OBJECT_COUNTER => {
            let a = Attrs::parse(data, 2);
            Ok(NftObjState::Counter(Arc::new(NftCounter {
                packets: AtomicU64::new(be64(&a, NFTA_COUNTER_PACKETS)?.unwrap_or(0)),
                bytes: AtomicU64::new(be64(&a, NFTA_COUNTER_BYTES)?.unwrap_or(0)),
            })))
        }
        NFT_OBJECT_QUOTA => Ok(NftObjState::Quota(nft_quota_init(data)?)),
        NFT_OBJECT_LIMIT => Ok(NftObjState::Limit(nft_limit_init(data)?, data.to_vec())),
        _ => Err(Errno::ENOENT),
    }
}

impl NftObj {
    /// The program of a chain uses this state.
    pub(super) fn state(&self) -> &NftObjState {
        &self.state
    }

    /// Adds the attributes of the state, as the `dump` of the types of objects of Linux.
    fn dump_data(&self, b: &mut Builder, reset: bool) {
        nft_state_dump(&self.state, b, reset, self.update);
    }
}

/// Adds the attributes of a state, as the `dump` of the types of objects and of the stateful
/// expressions of Linux. A reset sets the counter or the bytes of the quota back to 0.
/// `update` is the quota and the flags that a batch gives a quota object.
fn nft_state_dump(s: &NftObjState, b: &mut Builder, reset: bool, update: Option<(u64, u32)>) {
    match s {
        NftObjState::Counter(c) => {
            let bytes = c.bytes.load(Ordering::Relaxed);
            let packets = c.packets.load(Ordering::Relaxed);
            b.put(NFTA_COUNTER_BYTES as u16, &bytes.to_be_bytes())
                .put(NFTA_COUNTER_PACKETS as u16, &packets.to_be_bytes());
            if reset {
                c.bytes.fetch_sub(bytes, Ordering::Relaxed);
                c.packets.fetch_sub(packets, Ordering::Relaxed);
            }
        }
        NftObjState::Quota(q) => {
            let (quota, mut flags) = update
                .unwrap_or((q.quota.load(Ordering::Relaxed), q.flags.load(Ordering::Relaxed)));
            let consumed = q.consumed.load(Ordering::Relaxed);
            let shown = if consumed >= quota {
                flags |= NFT_QUOTA_F_DEPLETED;
                quota
            } else {
                consumed
            };
            b.put(NFTA_QUOTA_BYTES as u16, &quota.to_be_bytes())
                .put(NFTA_QUOTA_CONSUMED as u16, &shown.to_be_bytes())
                .put(NFTA_QUOTA_FLAGS as u16, &flags.to_be_bytes());
            if reset {
                q.consumed.fetch_sub(consumed, Ordering::Relaxed);
            }
        }
        NftObjState::Limit(_, data) => {
            for (ty, v) in nla_raw(data) {
                b.put(ty, v);
            }
        }
        NftObjState::Connlimit(c) => {
            let flags = if c.invert { NFT_CONNLIMIT_F_INV } else { 0 };
            b.put(NFTA_CONNLIMIT_COUNT as u16, &c.limit.to_be_bytes())
                .put(NFTA_CONNLIMIT_FLAGS as u16, &flags.to_be_bytes());
        }
    }
}

impl NftTable {
    /// The number of rules and elements that use the object `handle`, as `obj->use` of Linux.
    pub(crate) fn obj_use(&self, handle: u64) -> u32 {
        let rules = self
            .chains
            .iter()
            .flat_map(|c| c.rules.iter())
            .flat_map(|r| r.parsed.iter())
            .filter(|e| matches!(e, NftExpr::Objref { obj } if *obj == handle))
            .count();
        let elems = self
            .sets
            .iter()
            .flat_map(|s| s.elems.values())
            .filter(|e| e.data == Some(NftData::Obj(handle)))
            .count();
        (rules + elems) as u32
    }

    /// The name of the object `handle`.
    pub(crate) fn obj_name(&self, handle: u64) -> &[u8] {
        self.objs.iter().find(|o| o.handle == handle).map_or(&[], |o| &o.name)
    }
}

/// Finds the object `name` of the type `ty`, as `nft_obj_lookup` of Linux.
fn nft_obj_lookup(table: &NftTable, name: Option<&[u8]>, ty: u32) -> Result<usize> {
    let Some(name) = name else { return Err(Errno::EINVAL) };
    table.objs.iter().position(|o| o.name == name && o.ty == ty).ok_or(Errno::ENOENT)
}

/// Reads an `objref` expression, as `nft_objref_select_ops`, `nft_objref_init` and
/// `nft_objref_map_init` of Linux.
pub(super) fn nft_objref_init(table: &NftTable, data: &[u8]) -> Result<NftExpr> {
    let a = Attrs::parse(data, 5);
    if a.has(NFTA_OBJREF_SET_SREG) && (a.has(NFTA_OBJREF_SET_NAME) || a.has(NFTA_OBJREF_SET_ID)) {
        let name = a.str(NFTA_OBJREF_SET_NAME).map(|n| n.split(|&c| c == 0).next().unwrap_or(n));
        let s = nft_set_lookup_global(table, name, be32(&a, NFTA_OBJREF_SET_ID)?)?;
        let set = &table.sets[s];
        if set.flags & NFT_SET_OBJECT == 0 {
            return Err(Errno::EINVAL);
        }
        let len = set.klen as usize;
        let sreg = nft_parse_register(&a, NFTA_OBJREF_SET_SREG, len)?;
        return Ok(NftExpr::ObjrefMap { set: set.handle, sreg, len });
    }
    let (Some(ty), Some(name)) = (be32(&a, NFTA_OBJREF_IMM_TYPE)?, a.str(NFTA_OBJREF_IMM_NAME))
    else {
        return Err(Errno::EOPNOTSUPP);
    };
    let name = name.split(|&c| c == 0).next().unwrap_or(name);
    let o = nft_obj_lookup(table, Some(name), ty).map_err(|_| Errno::ENOENT)?;
    Ok(NftExpr::Objref { obj: table.objs[o].handle })
}

/// The message of an object, as `nf_tables_fill_obj_info` of Linux.
#[allow(clippy::too_many_arguments)]
fn nf_tables_fill_obj_info(
    portid: u32,
    seq: u32,
    event: u8,
    flags: u16,
    base_seq: u32,
    table: &NftTable,
    obj: &NftObj,
    reset: bool,
) -> Vec<u8> {
    let mut b = nfnl_msg_put(
        portid,
        seq,
        nft_type(event),
        flags,
        table.family,
        NFNETLINK_V0,
        base_seq as u16,
    );
    b.put(NFTA_OBJ_TABLE as u16, &cstr(&table.name))
        .put(NFTA_OBJ_NAME as u16, &cstr(&obj.name))
        .put(NFTA_OBJ_HANDLE as u16, &obj.handle.to_be_bytes());
    if event == NFT_MSG_DELOBJ || event == NFT_MSG_DESTROYOBJ {
        return b.finish();
    }
    b.put(NFTA_OBJ_TYPE as u16, &obj.ty.to_be_bytes())
        .put(NFTA_OBJ_USE as u16, &table.obj_use(obj.handle).to_be_bytes());
    let nest = b.nest(NFTA_OBJ_DATA as u16);
    obj.dump_data(&mut b, reset);
    b.end_nest(nest);
    if let Some(u) = &obj.udata {
        b.put(NFTA_OBJ_USERDATA as u16, u);
    }
    b.finish()
}

/// Gets one object, as `nf_tables_getobj` of Linux. `NFT_MSG_GETOBJ_RESET` also resets it.
pub(in super::super) fn nf_tables_getobj(info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<()> {
    let reset = nfnl_msg_type(info.nlh.ty) == NFT_MSG_GETOBJ_RESET;
    let (Some(name), Some(ty)) = (nla_name(nla, NFTA_OBJ_NAME)?, be32(nla, NFTA_OBJ_TYPE)?) else {
        return Err(Errno::EINVAL);
    };
    let family = info.nfmsg.nfgen_family;
    let nft = NFT.lock();
    let t = nft_table_lookup(&nft.tables, nla_name(nla, NFTA_OBJ_TABLE)?, family, 0)
        .map_err(|e| bad(info, nla, NFTA_OBJ_TABLE, e))?;
    let table = &nft.tables[t];
    let o = nft_obj_lookup(table, Some(name), ty).map_err(|e| bad(info, nla, NFTA_OBJ_NAME, e))?;
    let m = nf_tables_fill_obj_info(
        info.req.portid,
        info.nlh.seq,
        NFT_MSG_NEWOBJ,
        0,
        nft.base_seq,
        table,
        &table.objs[o],
        reset,
    );
    drop(nft);
    info.req.reply(m);
    Ok(())
}

/// The dump of the objects, as `nf_tables_dump_obj` of Linux. `NFTA_OBJ_TABLE` and
/// `NFTA_OBJ_TYPE` limit the dump to one table and one type.
pub(in super::super) fn nf_tables_dump_obj(
    info: &NfnlInfo<'_>,
    nla: &Attrs<'_>,
) -> Result<Vec<Vec<u8>>> {
    let reset = nfnl_msg_type(info.nlh.ty) == NFT_MSG_GETOBJ_RESET;
    let table_name = nla_name(nla, NFTA_OBJ_TABLE)?;
    let ty = be32(nla, NFTA_OBJ_TYPE)?.unwrap_or(NFT_OBJECT_UNSPEC);
    let nft = NFT.lock();
    let family = info.nfmsg.nfgen_family;
    let mut out = Vec::new();
    for t in nft.tables.iter().filter(|t| family_match(family, t)) {
        if table_name.is_some_and(|n| n != t.name) {
            continue;
        }
        for o in t.objs.iter().filter(|o| ty == NFT_OBJECT_UNSPEC || o.ty == ty) {
            out.push(nf_tables_fill_obj_info(
                info.req.portid,
                info.nlh.seq,
                NFT_MSG_NEWOBJ,
                NLM_F_MULTI as u16,
                nft.base_seq,
                t,
                o,
                reset,
            ));
        }
    }
    Ok(out)
}

/// Puts the changes of the quotas of a batch in their state, at the commit.
pub(in super::super) fn nft_obj_commit(tables: &mut [NftTable]) {
    for o in tables.iter_mut().flat_map(|t| t.objs.iter_mut()) {
        if let (Some((quota, flags)), NftObjState::Quota(q)) = (o.update.take(), &o.state) {
            q.quota.store(quota, Ordering::Relaxed);
            q.flags.store(flags, Ordering::Relaxed);
        }
    }
}

impl NftBatch {
    /// The notice of an object, as `nf_tables_obj_notify` of Linux.
    pub(in super::super) fn notify_obj(&mut self, ctx: &NftCtx, event: u8, t: usize, o: usize) {
        let flags = ctx.notify_flags();
        let m = self.want(ctx).then(|| {
            let table = &self.tables[t];
            nf_tables_fill_obj_info(
                ctx.portid,
                ctx.seq,
                event,
                flags,
                self.next_seq,
                table,
                &table.objs[o],
                false,
            )
        });
        self.notify(ctx, m);
    }

    /// Makes an object, as `nf_tables_newobj` of Linux. An object that is there stays as it
    /// is, apart from a quota, that gets the new quota and flags at the commit.
    pub(in super::super) fn nf_tables_newobj(
        &mut self,
        info: &NfnlInfo<'_>,
        nla: &Attrs<'_>,
    ) -> Result<()> {
        let ctx = NftCtx::new(info);
        let (Some(ty), Some(name), Some(data)) =
            (be32(nla, NFTA_OBJ_TYPE)?, nla_name(nla, NFTA_OBJ_NAME)?, nla.get(NFTA_OBJ_DATA))
        else {
            return Err(Errno::EINVAL);
        };
        let t =
            nft_table_lookup(&self.tables, nla_name(nla, NFTA_OBJ_TABLE)?, ctx.family, ctx.portid)
                .map_err(|e| bad(info, nla, NFTA_OBJ_TABLE, e))?;
        if let Ok(o) = nft_obj_lookup(&self.tables[t], Some(name), ty) {
            if ctx.has(NLM_F_EXCL) {
                return Err(bad(info, nla, NFTA_OBJ_NAME, Errno::EEXIST));
            }
            if ctx.has(NLM_F_REPLACE) {
                return Err(Errno::EOPNOTSUPP);
            }
            // Of the types here, only a quota has an update.
            if ty != NFT_OBJECT_QUOTA {
                return Ok(());
            }
            let (quota, _, flags) = nft_quota_parse(data)?;
            self.tables[t].objs[o].update = Some((quota, flags));
            self.notify_obj(&ctx, NFT_MSG_NEWOBJ, t, o);
            return Ok(());
        }
        let state = nft_obj_state_init(ty, data)?;
        let udata = nla_udata(nla, NFTA_OBJ_USERDATA)?;
        let table = &mut self.tables[t];
        let handle = table.alloc_handle();
        table.objs.push(NftObj { name: name.to_vec(), handle, ty, udata, state, update: None });
        let o = table.objs.len() - 1;
        self.notify_obj(&ctx, NFT_MSG_NEWOBJ, t, o);
        Ok(())
    }

    /// Removes an object, by its name or its handle, as `nf_tables_delobj` of Linux. An object
    /// that a rule or an element uses gives `EBUSY`.
    pub(in super::super) fn nf_tables_delobj(
        &mut self,
        info: &NfnlInfo<'_>,
        nla: &Attrs<'_>,
    ) -> Result<()> {
        let ctx = NftCtx::new(info);
        let name = nla_name(nla, NFTA_OBJ_NAME)?;
        let handle = be64(nla, NFTA_OBJ_HANDLE)?;
        let Some(ty) = be32(nla, NFTA_OBJ_TYPE)? else { return Err(Errno::EINVAL) };
        if name.is_none() && handle.is_none() {
            return Err(Errno::EINVAL);
        }
        let t =
            nft_table_lookup(&self.tables, nla_name(nla, NFTA_OBJ_TABLE)?, ctx.family, ctx.portid)
                .map_err(|e| bad(info, nla, NFTA_OBJ_TABLE, e))?;
        let table = &self.tables[t];
        let (r, attr) = match handle {
            Some(h) => (
                table.objs.iter().position(|o| o.handle == h && o.ty == ty).ok_or(Errno::ENOENT),
                NFTA_OBJ_HANDLE,
            ),
            None => (nft_obj_lookup(table, name, ty), NFTA_OBJ_NAME),
        };
        let o = match r {
            Ok(o) => o,
            Err(Errno::ENOENT) if ctx.ty == NFT_MSG_DESTROYOBJ => return Ok(()),
            Err(e) => return Err(bad(info, nla, attr, e)),
        };
        if table.obj_use(table.objs[o].handle) > 0 {
            return Err(bad(info, nla, attr, Errno::EBUSY));
        }
        self.notify_obj(&ctx, NFT_MSG_DELOBJ, t, o);
        self.tables[t].objs.remove(o);
        Ok(())
    }
}

/// Reads `NFTA_SET_ELEM_OBJREF`, the object of an element of a map of objects of the type
/// `ty`.
pub(crate) fn nft_setelem_parse_obj(table: &NftTable, ea: &Attrs<'_>, ty: u32) -> Result<NftData> {
    let o = nft_obj_lookup(table, nla_name(ea, NFTA_SET_ELEM_OBJREF)?, ty)?;
    Ok(NftData::Obj(table.objs[o].handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(ty: u32, v: &[u8]) -> Vec<u8> {
        let mut b = Builder::new(0, 0, 0, 0);
        b.put(ty as u16, v);
        b.finish()[crate::netlink::msg::HDRLEN..].to_vec()
    }

    #[test]
    fn a_quota_needs_its_bytes_and_known_flags() {
        assert_eq!(nft_quota_parse(&[]).unwrap_err(), Errno::EINVAL);
        let mut d = attr(NFTA_QUOTA_BYTES, &100u64.to_be_bytes());
        assert_eq!(nft_quota_parse(&d).unwrap(), (100, 0, 0));
        d.extend(attr(NFTA_QUOTA_FLAGS, &NFT_QUOTA_F_DEPLETED.to_be_bytes()));
        assert_eq!(nft_quota_parse(&d).unwrap_err(), Errno::EINVAL);
        let mut d = attr(NFTA_QUOTA_BYTES, &100u64.to_be_bytes());
        d.extend(attr(NFTA_QUOTA_CONSUMED, &101u64.to_be_bytes()));
        assert_eq!(nft_quota_parse(&d).unwrap_err(), Errno::EINVAL);
    }

    fn table() -> NftTable {
        NftTable {
            name: b"t".to_vec(),
            family: NFPROTO_IPV4,
            flags: 0,
            handle: 1,
            udata: None,
            nlpid: 0,
            chains: Vec::new(),
            sets: Vec::new(),
            objs: Vec::new(),
            flowtables: Vec::new(),
            hgenerator: 1,
        }
    }

    /// An expression with its name and its data, in the attribute `ty`.
    fn expr(ty: u32, name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut e = attr(NFTA_EXPR_NAME, name);
        e.extend(attr(NFTA_EXPR_DATA, data));
        attr(ty, &e)
    }

    #[test]
    fn a_set_takes_only_stateful_expressions_of_the_types_of_the_set() {
        let t = table();
        let counter = || expr(NFTA_LIST_ELEM.into(), b"counter\0", &[]);
        let limit = attr(1, &1u64.to_be_bytes());
        let limit = [limit, attr(2, &1u64.to_be_bytes())].concat();
        let limit = expr(NFTA_LIST_ELEM.into(), b"limit\0", &limit);
        let parse = |l: &[u8], ok: bool, want: &[NftObjState]| {
            let a = attr(2, l);
            nft_set_exprs_parse(&t, 0, &Attrs::parse(&a, 2), (1, 2), ok, want)
        };
        let two = [limit.clone(), counter()].concat();
        let set = parse(&two, true, &[]).unwrap().unwrap();
        assert_eq!(
            set.iter().map(NftObjState::name).collect::<Vec<_>>(),
            [&b"limit"[..], b"counter"]
        );
        // A list needs its flag, has at most two expressions, and has the ones of the set.
        assert_eq!(parse(&two, false, &[]).unwrap_err(), Errno::EINVAL);
        assert_eq!(parse(&[two.clone(), counter()].concat(), true, &[]).unwrap_err(), Errno::E2BIG);
        assert_eq!(parse(&counter(), true, &set).unwrap_err(), Errno::EOPNOTSUPP);
        assert_eq!(parse(&[counter(), limit].concat(), true, &set).unwrap_err(), Errno::EOPNOTSUPP);
        assert_eq!(parse(&two, true, &set).unwrap().unwrap().len(), 2);
        // An expression with no state.
        let imm = expr(NFTA_LIST_ELEM.into(), b"immediate\0", &[]);
        assert!(parse(&imm, true, &[]).is_err());
        // A connlimit has no place in a set with timeouts.
        let c = expr(1, b"connlimit\0", &attr(NFTA_CONNLIMIT_COUNT, &20u32.to_be_bytes()));
        let a = Attrs::parse(&c, 2);
        assert!(nft_set_exprs_parse(&t, 0, &a, (1, 2), false, &[]).is_ok());
        let e = nft_set_exprs_parse(&t, NFT_SET_TIMEOUT, &a, (1, 2), false, &[]);
        assert_eq!(e.unwrap_err(), Errno::EOPNOTSUPP);
    }

    #[test]
    fn a_copy_of_a_state_has_its_own_counts() {
        let c = nft_obj_state_init(
            NFT_OBJECT_COUNTER,
            &attr(NFTA_COUNTER_PACKETS, &9u64.to_be_bytes()),
        )
        .unwrap();
        let copy = c.fresh();
        let (NftObjState::Counter(a), NftObjState::Counter(b)) = (&c, &copy) else { panic!() };
        assert_eq!(b.packets.load(Ordering::Relaxed), 9);
        a.packets.store(1, Ordering::Relaxed);
        assert_eq!(b.packets.load(Ordering::Relaxed), 9);
        let mut b = Builder::new(0, 0, 0, 0);
        nft_set_exprs_dump(&mut b, (1, 2), &[copy], false);
        let d = b.finish()[crate::netlink::msg::HDRLEN..].to_vec();
        let e = Attrs::parse(&d, 2);
        let x = Attrs::parse(e.get(1).unwrap(), NFTA_EXPR_MAX);
        assert_eq!(x.get(NFTA_EXPR_NAME), Some(&b"counter\0"[..]));
    }

    #[test]
    fn an_unknown_type_of_object_gives_enoent() {
        assert_eq!(nft_obj_state_init(3, &[]).unwrap_err(), Errno::ENOENT);
        assert!(matches!(nft_obj_state_init(NFT_OBJECT_COUNTER, &[]), Ok(NftObjState::Counter(_))));
    }

    #[test]
    fn objects_of_two_types_can_have_the_same_name() {
        let obj = |handle, ty| NftObj {
            name: b"c".to_vec(),
            handle,
            ty,
            udata: None,
            state: nft_obj_state_init(ty, &attr(NFTA_QUOTA_BYTES, &100u64.to_be_bytes())).unwrap(),
            update: None,
        };
        let t = NftTable {
            name: b"t".to_vec(),
            family: crate::netfilter::NFPROTO_IPV4,
            flags: 0,
            handle: 1,
            udata: None,
            nlpid: 0,
            chains: Vec::new(),
            sets: Vec::new(),
            objs: alloc::vec![obj(1, NFT_OBJECT_COUNTER), obj(2, NFT_OBJECT_QUOTA)],
            flowtables: Vec::new(),
            hgenerator: 2,
        };
        assert_eq!(nft_obj_lookup(&t, Some(b"c"), NFT_OBJECT_QUOTA), Ok(1));
        assert_eq!(nft_obj_lookup(&t, Some(b"c"), NFT_OBJECT_LIMIT), Err(Errno::ENOENT));
        let mut d = attr(NFTA_OBJREF_IMM_TYPE, &NFT_OBJECT_QUOTA.to_be_bytes());
        d.extend(attr(NFTA_OBJREF_IMM_NAME, b"c\0"));
        assert!(matches!(nft_objref_init(&t, &d), Ok(NftExpr::Objref { obj: 2 })));
        let mut d = attr(NFTA_OBJREF_IMM_TYPE, &NFT_OBJECT_LIMIT.to_be_bytes());
        d.extend(attr(NFTA_OBJREF_IMM_NAME, b"c\0"));
        assert_eq!(nft_objref_init(&t, &d).unwrap_err(), Errno::ENOENT);
        assert_eq!(nft_objref_init(&t, &[]).unwrap_err(), Errno::EOPNOTSUPP);
        assert_eq!(t.obj_use(2), 0);
    }

    #[test]
    fn a_reset_gives_the_counter_and_sets_it_back_to_0() {
        let c = Arc::new(NftCounter::default());
        c.packets.store(12, Ordering::Relaxed);
        c.bytes.store(1433, Ordering::Relaxed);
        let obj = NftObj {
            name: b"c".to_vec(),
            handle: 1,
            ty: NFT_OBJECT_COUNTER,
            udata: None,
            state: NftObjState::Counter(c.clone()),
            update: None,
        };
        let mut b = Builder::new(0, 0, 0, 0);
        obj.dump_data(&mut b, true);
        let m = b.finish();
        let a = Attrs::parse(&m[crate::netlink::msg::HDRLEN..], 2);
        assert_eq!(be64(&a, NFTA_COUNTER_PACKETS).unwrap(), Some(12));
        assert_eq!(be64(&a, NFTA_COUNTER_BYTES).unwrap(), Some(1433));
        assert_eq!(c.packets.load(Ordering::Relaxed), 0);
        assert_eq!(c.bytes.load(Ordering::Relaxed), 0);
    }
}

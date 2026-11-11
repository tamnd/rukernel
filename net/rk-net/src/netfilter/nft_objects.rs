//! The stateful objects of nf_tables, as the objects of nf_tables_api.c and nft_counter.c,
//! nft_quota.c, nft_limit.c and nft_objref.c of Linux.
//!
//! A table has objects with a name and a type: `counter`, `quota` and `limit`. Two objects of
//! different types can have the same name. A rule uses an object with the expression `objref`:
//! by its name, or by the key of the packet in a map of objects. The copies of a table in a
//! batch share the state of each object, and a packet changes it with no lock on the tables.

use super::super::{
    NFT, NFT_MSG_DELOBJ, NFT_MSG_DESTROYOBJ, NFT_MSG_GETOBJ_RESET, NFT_MSG_NEWOBJ, NFT_SET_OBJECT,
    NFTA_SET_ELEM_OBJREF, NftBatch, NftCtx, NftData, NftTable, bad, be32, be64, cstr, family_match,
    nfnl_msg_put, nfnl_msg_type, nft_set_lookup_global, nft_table_lookup, nft_type, nla_name,
    nla_udata,
};
use super::{
    NFT_BREAK, NFTA_COUNTER_BYTES, NFTA_COUNTER_PACKETS, NftExpr, NftLimit, NftRegs,
    nft_limit_eval, nft_limit_init, nft_parse_register, nla_raw,
};
use crate::buf::NetBuf;
use crate::netlink::msg::{Attrs, Builder};
use crate::netlink::nfnetlink::{NFNETLINK_V0, NfnlInfo};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::netlink::{NLM_F_EXCL, NLM_F_MULTI, NLM_F_REPLACE};
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

/// The state of an object. The copies of the object share it.
#[derive(Clone, Debug)]
pub(crate) enum NftObjState {
    Counter(Arc<NftCounter>),
    Quota(Arc<NftQuota>),
    /// A `limit`, with the attributes that made it, for the dump.
    Limit(Arc<NftLimit>, Vec<u8>),
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

    /// Adds the attributes of the state, as the `dump` of the types of objects of Linux. A
    /// reset sets the counter or the bytes of the quota back to 0.
    fn dump_data(&self, b: &mut Builder, reset: bool) {
        match &self.state {
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
                let (quota, mut flags) = self
                    .update
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

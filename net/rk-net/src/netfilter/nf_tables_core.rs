//! The expressions of nf_tables and the packet path of a base chain, as
//! net/netfilter/nf_tables_core.c and the expressions of net/netfilter of Linux.
//!
//! A rule is a list of expressions. The expressions work on the registers: `payload` and
//! `meta` load data of the packet, `immediate` loads a value or sets the verdict, `bitwise`
//! masks a register, `cmp` and `lookup` end the rule when the data does not match, and
//! `counter` counts the packets. The expressions here are `immediate`, `cmp`, `payload`,
//! `meta`, `bitwise`, `counter`, `lookup`, `dynset`, `ct`, `nat`, `masq` and `redir`, and in
//! nft_exprs.rs `byteorder`, `range`, `limit`, `log` and `reject`. Another name gives
//! `ENOENT`, as a module that Linux cannot load.
//!
//! At the commit each base chain gets a program: its rules and the rules of the chains that it
//! can jump to, with the keys of the sets that the rules look up. A packet takes the program
//! of the chain and runs it with no lock on the objects. The elements that `dynset` adds,
//! updates and removes go in a list of the set that the programs share, and the next commit
//! puts them in the set.

use super::{
    DynElem, NF_DROP, NFPROTO_IPV6, NFT_BREAK, NFT_CONTINUE, NFT_DATA_VALUE_MAXLEN,
    NFT_DATA_VERDICT, NFT_GOTO, NFT_JUMP, NFT_RETURN, NFT_SET_ANONYMOUS, NFT_SET_CONSTANT,
    NFT_SET_ELEM_INTERVAL_END, NFT_SET_EVAL, NFT_SET_INTERVAL, NFT_SET_MAP, NFT_SET_OBJECT,
    NFT_SET_TIMEOUT, NFTA_DATA_MAX, NFTA_DATA_VALUE, NFTA_DATA_VERDICT, NftChainType, NftData,
    NftTable, be32, be64, nft_set_lookup_global, nft_verdict_init,
};
use crate::buf::NetBuf;
use crate::netfilter::nf_conntrack::{IP_CT_DIR_ORIGINAL, IP_CT_DIR_REPLY, IP_CT_IS_REPLY};
use crate::netfilter::nf_nat::{
    NF_NAT_MANIP_DST, NF_NAT_MANIP_SRC, NF_NAT_RANGE_MAP_IPS, NF_NAT_RANGE_MASK,
    NF_NAT_RANGE_NETMAP, NF_NAT_RANGE_PROTO_OFFSET, NF_NAT_RANGE_PROTO_SPECIFIED, NfNatRange,
    hook2manip, nf_nat_masquerade, nf_nat_redirect, nf_nat_setup_info,
};
use crate::netfilter::{
    NF_INET_FORWARD, NF_INET_LOCAL_IN, NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING,
    NF_INET_PRE_ROUTING, NFPROTO_INET, NFPROTO_IPV4, NfHookState, NfPktinfo as NftPktinfo,
    nf_pktinfo as nft_pktinfo,
};
use crate::netlink::msg::Attrs;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_abi::Errno;
use rk_vfs::inode::Result;

#[path = "nft_exprs.rs"]
mod nft_exprs;

use self::nft_exprs::{
    NftByteorder, NftLimit, NftLog, NftRange, NftReject, nft_byteorder_eval, nft_byteorder_init,
    nft_limit_eval, nft_limit_init, nft_log_eval, nft_log_init, nft_range_eval, nft_range_init,
    nft_reject_eval, nft_reject_init,
};

// The attributes of an expression, `NFTA_EXPR_*`.
const NFTA_EXPR_NAME: u32 = 1;
const NFTA_EXPR_DATA: u32 = 2;
const NFTA_EXPR_MAX: u16 = 2;

// The registers, `enum nft_registers`. The verdict register and the four registers of 16
// bytes come first, then the 16 registers of 4 bytes on the same bytes.
const NFT_REG_VERDICT: u32 = 0;
const NFT_REG_4: u32 = 4;
const NFT_REG32_00: u32 = 8;
const NFT_REG32_15: u32 = 23;
/// The size of a register of 16 bytes, `NFT_REG_SIZE`.
const NFT_REG_SIZE: usize = 16;
/// The size of a register of 4 bytes, `NFT_REG32_SIZE`.
const NFT_REG32_SIZE: usize = 4;
/// The bytes of the registers with the verdict, `sizeof(struct nft_regs)`.
const NFT_REGS_LEN: usize = NFT_REG_SIZE * 5;

// `NFTA_IMMEDIATE_*`.
const NFTA_IMMEDIATE_DREG: u32 = 1;
const NFTA_IMMEDIATE_DATA: u32 = 2;

// `NFTA_CMP_*` and `enum nft_cmp_ops`.
const NFTA_CMP_SREG: u32 = 1;
const NFTA_CMP_OP: u32 = 2;
const NFTA_CMP_DATA: u32 = 3;
const NFT_CMP_EQ: u32 = 0;
const NFT_CMP_NEQ: u32 = 1;
const NFT_CMP_LT: u32 = 2;
const NFT_CMP_LTE: u32 = 3;
const NFT_CMP_GT: u32 = 4;
const NFT_CMP_GTE: u32 = 5;

// `NFTA_PAYLOAD_*` and `enum nft_payload_bases`.
const NFTA_PAYLOAD_DREG: u32 = 1;
const NFTA_PAYLOAD_BASE: u32 = 2;
const NFTA_PAYLOAD_OFFSET: u32 = 3;
const NFTA_PAYLOAD_LEN: u32 = 4;
const NFTA_PAYLOAD_SREG: u32 = 5;
const NFT_PAYLOAD_LL_HEADER: u32 = 0;
const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;

// `NFTA_META_*` and `enum nft_meta_keys`.
/// The attributes and the keys of `ct`, as nft_ct.c of Linux.
const NFTA_CT_DREG: u32 = 1;
const NFTA_CT_KEY: u32 = 2;
const NFTA_CT_DIRECTION: u32 = 3;
const NFTA_CT_SREG: u32 = 4;
const NFT_CT_STATE: u32 = 0;
const NFT_CT_DIRECTION: u32 = 1;
const NFT_CT_STATUS: u32 = 2;
const NFT_CT_MARK: u32 = 3;
const NFT_CT_EXPIRATION: u32 = 5;
const NFT_CT_L3PROTOCOL: u32 = 7;
const NFT_CT_SRC: u32 = 8;
const NFT_CT_DST: u32 = 9;
const NFT_CT_PROTOCOL: u32 = 10;
const NFT_CT_PROTO_SRC: u32 = 11;
const NFT_CT_PROTO_DST: u32 = 12;
const NFT_CT_SRC_IP: u32 = 19;
const NFT_CT_DST_IP: u32 = 20;
const NFT_CT_SRC_IP6: u32 = 21;
const NFT_CT_DST_IP6: u32 = 22;
const NFT_CT_ID: u32 = 23;

// `NFTA_NAT_*`, `enum nft_nat_types`, `NFTA_MASQ_*` and `NFTA_REDIR_*`.
const NFTA_NAT_TYPE: u32 = 1;
const NFTA_NAT_FAMILY: u32 = 2;
const NFTA_NAT_REG_ADDR_MIN: u32 = 3;
const NFTA_NAT_REG_ADDR_MAX: u32 = 4;
const NFTA_NAT_REG_PROTO_MIN: u32 = 5;
const NFTA_NAT_REG_PROTO_MAX: u32 = 6;
const NFTA_NAT_FLAGS: u32 = 7;
const NFT_NAT_SNAT: u32 = 0;
const NFT_NAT_DNAT: u32 = 1;
const NFTA_MASQ_FLAGS: u32 = 1;
const NFTA_MASQ_REG_PROTO_MIN: u32 = 2;
const NFTA_MASQ_REG_PROTO_MAX: u32 = 3;
const NFTA_REDIR_REG_PROTO_MIN: u32 = 1;
const NFTA_REDIR_REG_PROTO_MAX: u32 = 2;
const NFTA_REDIR_FLAGS: u32 = 3;

/// The bits of `ct state`, as `NF_CT_STATE_INVALID_BIT` and `NF_CT_STATE_BIT` of Linux.
const NF_CT_STATE_INVALID_BIT: u32 = 1 << 0;

const NFTA_META_DREG: u32 = 1;
const NFTA_META_KEY: u32 = 2;
const NFTA_META_SREG: u32 = 3;
const NFT_META_LEN: u32 = 0;
const NFT_META_PROTOCOL: u32 = 1;
const NFT_META_IIF: u32 = 4;
const NFT_META_OIF: u32 = 5;
const NFT_META_NFPROTO: u32 = 15;
const NFT_META_L4PROTO: u32 = 16;

// `NFTA_BITWISE_*` and `enum nft_bitwise_ops`.
const NFTA_BITWISE_SREG: u32 = 1;
const NFTA_BITWISE_DREG: u32 = 2;
const NFTA_BITWISE_LEN: u32 = 3;
const NFTA_BITWISE_MASK: u32 = 4;
const NFTA_BITWISE_XOR: u32 = 5;
const NFTA_BITWISE_OP: u32 = 6;
const NFT_BITWISE_BOOL: u32 = 0;

// `NFTA_COUNTER_*`.
const NFTA_COUNTER_BYTES: u32 = 1;
const NFTA_COUNTER_PACKETS: u32 = 2;

// `NFTA_LOOKUP_*` and `enum nft_lookup_flags`.
const NFTA_LOOKUP_SET: u32 = 1;
const NFTA_LOOKUP_SREG: u32 = 2;
const NFTA_LOOKUP_DREG: u32 = 3;
const NFTA_LOOKUP_SET_ID: u32 = 4;
const NFTA_LOOKUP_FLAGS: u32 = 5;
const NFT_LOOKUP_F_INV: u32 = 1;

// `NFTA_DYNSET_*`, `enum nft_dynset_ops` and `enum nft_dynset_flags`.
const NFTA_DYNSET_SET_NAME: u32 = 1;
const NFTA_DYNSET_SET_ID: u32 = 2;
const NFTA_DYNSET_OP: u32 = 3;
const NFTA_DYNSET_SREG_KEY: u32 = 4;
const NFTA_DYNSET_SREG_DATA: u32 = 5;
const NFTA_DYNSET_TIMEOUT: u32 = 6;
const NFTA_DYNSET_EXPR: u32 = 7;
const NFTA_DYNSET_FLAGS: u32 = 9;
const NFTA_DYNSET_EXPRESSIONS: u32 = 10;
const NFTA_DYNSET_MAX: u16 = 10;
const NFT_DYNSET_OP_UPDATE: u32 = 1;
const NFT_DYNSET_OP_DELETE: u32 = 2;
const NFT_DYNSET_F_INV: u32 = 1;
const NFT_DYNSET_F_EXPR: u32 = 2;

/// The deepest jumps, `NFT_JUMP_STACK_SIZE`.
pub(super) const NFT_JUMP_STACK_SIZE: usize = 16;

/// `ETH_P_IP` and `ETH_P_IPV6`, for `meta protocol`.
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;

/// The data of `immediate`.
#[derive(Clone, Debug)]
pub(super) enum NftImm {
    /// A value for a register.
    Value(Vec<u8>),
    /// A verdict, and the handle of the chain of `NFT_JUMP` and `NFT_GOTO`.
    Verdict { code: u32, chain: Option<u64> },
}

/// An expression of a rule, as `struct nft_expr` with its private data.
#[derive(Clone, Debug)]
pub(super) enum NftExpr {
    /// `immediate`, as nft_immediate.c. `dreg` is a byte offset in the registers.
    Immediate { dreg: usize, data: NftImm },
    /// `cmp`, as nft_cmp.c.
    Cmp { sreg: usize, op: u32, data: Vec<u8> },
    /// `payload`, as nft_payload.c.
    Payload { base: u32, offset: usize, len: usize, dreg: usize },
    /// `meta`, as nft_meta.c.
    Meta { key: u32, dreg: usize },
    /// `bitwise` with `NFT_BITWISE_BOOL`, as nft_bitwise.c.
    Bitwise { sreg: usize, dreg: usize, mask: Vec<u8>, xor: Vec<u8> },
    /// `counter`, as nft_counter.c. The copies of the rule share the counters.
    Counter { packets: Arc<AtomicU64>, bytes: Arc<AtomicU64> },
    /// `lookup` in the set `set` (a handle), as nft_lookup.c. A lookup in a map has `dreg`, the
    /// register that gets the data of the element; a verdict map sets the verdict.
    Lookup { set: u64, sreg: usize, len: usize, invert: bool, dreg: Option<usize> },
    /// `ct` that loads a key of the connection of the packet, as `nft_ct_get_eval`. `dir` is
    /// the direction of the tuple for the keys of a tuple.
    Ct { key: u32, dir: usize, len: usize, dreg: usize },
    /// `ct mark set`, as `nft_ct_set_eval`.
    CtSet { sreg: usize },
    /// `snat` and `dnat`, as nft_nat.c. `addr` and `proto` are the registers of the first and
    /// the last address and port; an address has `alen` bytes.
    Nat {
        mtype: u8,
        family: u8,
        alen: usize,
        addr: Option<(usize, usize)>,
        proto: Option<(usize, usize)>,
        flags: u32,
    },
    /// `masquerade`, as nft_masq.c.
    Masq { flags: u32, proto: Option<(usize, usize)> },
    /// `redirect`, as nft_redir.c.
    Redir { flags: u32, proto: Option<(usize, usize)> },
    /// `byteorder`, as nft_byteorder.c.
    Byteorder(NftByteorder),
    /// `range`, as nft_range.c.
    Range(NftRange),
    /// `limit`, as nft_limit.c. The copies of the rule share the bucket.
    Limit(Arc<NftLimit>),
    /// `log`, as nft_log.c.
    Log(NftLog),
    /// `reject`, as nft_reject.c.
    Reject(NftReject),
    /// `dynset`, as nft_dynset.c.
    Dynset(NftDynset),
}

/// `dynset`: adds the key of a packet to a set, updates the timeout of its element, or removes
/// it, as `struct nft_dynset` of Linux.
#[derive(Clone, Debug)]
pub(super) struct NftDynset {
    /// The handle of the set.
    pub(super) set: u64,
    op: u32,
    sreg_key: usize,
    klen: usize,
    /// The register and the length of the data of a new element of a map.
    sreg_data: Option<(usize, usize)>,
    /// The timeout in milliseconds of the new elements, or 0 for the one of the set.
    timeout: u64,
    invert: bool,
}

/// Reads a `dynset` expression, as `nft_dynset_init` of Linux. The expressions of the
/// elements come later.
fn nft_dynset_init(table: &NftTable, data: &[u8]) -> Result<NftExpr> {
    let a = Attrs::parse(data, NFTA_DYNSET_MAX);
    let name = a.str(NFTA_DYNSET_SET_NAME).map(|n| n.split(|&c| c == 0).next().unwrap_or(n));
    if name.is_none() || !a.has(NFTA_DYNSET_OP) || !a.has(NFTA_DYNSET_SREG_KEY) {
        return Err(Errno::EINVAL);
    }
    let flags = be32(&a, NFTA_DYNSET_FLAGS)?.unwrap_or(0);
    if flags & !(NFT_DYNSET_F_INV | NFT_DYNSET_F_EXPR) != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let s = nft_set_lookup_global(table, name, be32(&a, NFTA_DYNSET_SET_ID)?)?;
    let set = &table.sets[s];
    // The backends of the intervals have no update.
    if set.flags & (NFT_SET_OBJECT | NFT_SET_INTERVAL) != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if set.flags & NFT_SET_CONSTANT != 0 {
        return Err(Errno::EBUSY);
    }
    let op = be32(&a, NFTA_DYNSET_OP)?.unwrap_or(0);
    if op > NFT_DYNSET_OP_DELETE {
        return Err(Errno::EOPNOTSUPP);
    }
    if a.has(NFTA_DYNSET_TIMEOUT) && set.flags & NFT_SET_TIMEOUT == 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let timeout = super::nft_msecs(&a, NFTA_DYNSET_TIMEOUT)?.unwrap_or(0);
    let klen = set.klen as usize;
    let sreg_key = nft_parse_register(&a, NFTA_DYNSET_SREG_KEY, klen)?;
    let sreg_data = if a.has(NFTA_DYNSET_SREG_DATA) {
        if set.flags & NFT_SET_MAP == 0 || set.dtype == NFT_DATA_VERDICT {
            return Err(Errno::EOPNOTSUPP);
        }
        let dlen = set.dlen as usize;
        Some((nft_parse_register(&a, NFTA_DYNSET_SREG_DATA, dlen)?, dlen))
    } else if set.flags & NFT_SET_MAP != 0 {
        return Err(Errno::EINVAL);
    } else {
        None
    };
    if a.has(NFTA_DYNSET_EXPR) || a.has(NFTA_DYNSET_EXPRESSIONS) {
        if set.flags & NFT_SET_EVAL == 0 {
            return Err(Errno::EINVAL);
        }
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(NftExpr::Dynset(NftDynset {
        set: set.handle,
        op,
        sreg_key,
        klen,
        sreg_data,
        timeout,
        invert: flags & NFT_DYNSET_F_INV != 0,
    }))
}

impl NftExpr {
    /// The handle of the chain that the expression jumps to.
    pub(super) fn jump_target(&self) -> Option<u64> {
        match self {
            NftExpr::Immediate { data: NftImm::Verdict { chain, .. }, .. } => *chain,
            _ => None,
        }
    }
}

/// Reads a register for `len` bytes, as `nft_parse_register_load` and
/// `nft_parse_register_store` of Linux. Gives the byte offset of the register.
fn nft_parse_register(a: &Attrs<'_>, ty: u32, len: usize) -> Result<usize> {
    let Some(reg) = be32(a, ty)? else { return Err(Errno::EINVAL) };
    let at = match reg {
        NFT_REG_VERDICT => return Err(Errno::EINVAL),
        1..=NFT_REG_4 => reg as usize * NFT_REG_SIZE,
        NFT_REG32_00..=NFT_REG32_15 => {
            NFT_REG_SIZE + (reg - NFT_REG32_00) as usize * NFT_REG32_SIZE
        }
        _ => return Err(Errno::ERANGE),
    };
    if len == 0 {
        return Err(Errno::EINVAL);
    }
    if at + len > NFT_REGS_LEN {
        return Err(Errno::ERANGE);
    }
    Ok(at)
}

/// Reads a value of at most `NFT_DATA_VALUE_MAXLEN` bytes, as `nft_data_init` with
/// `NFT_DATA_VALUE`.
fn nft_value(nla: &[u8]) -> Result<Vec<u8>> {
    let tb = Attrs::parse(nla, NFTA_DATA_MAX);
    let Some(v) = tb.get(NFTA_DATA_VALUE) else { return Err(Errno::EINVAL) };
    if v.is_empty() {
        return Err(Errno::EINVAL);
    }
    if v.len() > NFT_DATA_VALUE_MAXLEN as usize {
        return Err(Errno::EOVERFLOW);
    }
    Ok(v.to_vec())
}

/// A length in an attribute.
fn len_attr(a: &Attrs<'_>, ty: u32) -> Result<usize> {
    match be32(a, ty)? {
        Some(l) if l > 0 && l as usize <= NFT_REGS_LEN => Ok(l as usize),
        Some(_) => Err(Errno::ERANGE),
        None => Err(Errno::EINVAL),
    }
}

/// Reads an expression of a rule of `table`, as `nf_tables_expr_parse` and the `init` of each
/// expression of Linux.
pub(super) fn nf_tables_expr_parse(table: &NftTable, nla: &[u8]) -> Result<NftExpr> {
    let tb = Attrs::parse(nla, NFTA_EXPR_MAX);
    let Some(name) = tb.str(NFTA_EXPR_NAME) else { return Err(Errno::EINVAL) };
    let name = name.split(|&c| c == 0).next().unwrap_or(name);
    let data = tb.get(NFTA_EXPR_DATA).unwrap_or(&[]);
    match name {
        b"immediate" => {
            let a = Attrs::parse(data, 2);
            let Some(d) = a.get(NFTA_IMMEDIATE_DATA) else { return Err(Errno::EINVAL) };
            if be32(&a, NFTA_IMMEDIATE_DREG)? == Some(NFT_REG_VERDICT) {
                let v = Attrs::parse(d, NFTA_DATA_MAX);
                let Some(v) = v.get(NFTA_DATA_VERDICT) else { return Err(Errno::EINVAL) };
                let NftData::Verdict { code, chain } = nft_verdict_init(table, v)? else {
                    return Err(Errno::EINVAL);
                };
                return Ok(NftExpr::Immediate { dreg: 0, data: NftImm::Verdict { code, chain } });
            }
            let v = nft_value(d)?;
            let dreg = nft_parse_register(&a, NFTA_IMMEDIATE_DREG, v.len())?;
            Ok(NftExpr::Immediate { dreg, data: NftImm::Value(v) })
        }
        b"cmp" => {
            let a = Attrs::parse(data, 3);
            let Some(d) = a.get(NFTA_CMP_DATA) else { return Err(Errno::EINVAL) };
            let v = nft_value(d)?;
            let sreg = nft_parse_register(&a, NFTA_CMP_SREG, v.len())?;
            let op = match be32(&a, NFTA_CMP_OP)? {
                Some(op @ NFT_CMP_EQ..=NFT_CMP_GTE) => op,
                Some(_) => return Err(Errno::EINVAL),
                None => return Err(Errno::EINVAL),
            };
            Ok(NftExpr::Cmp { sreg, op, data: v })
        }
        b"payload" => {
            let a = Attrs::parse(data, 5);
            if a.has(NFTA_PAYLOAD_SREG) {
                // The change of the packet comes later.
                return Err(Errno::EOPNOTSUPP);
            }
            let base = match be32(&a, NFTA_PAYLOAD_BASE)? {
                Some(
                    b @ (NFT_PAYLOAD_LL_HEADER
                    | NFT_PAYLOAD_NETWORK_HEADER
                    | NFT_PAYLOAD_TRANSPORT_HEADER),
                ) => b,
                Some(_) => return Err(Errno::EOPNOTSUPP),
                None => return Err(Errno::EINVAL),
            };
            let Some(offset) = be32(&a, NFTA_PAYLOAD_OFFSET)? else { return Err(Errno::EINVAL) };
            if offset > u32::from(u8::MAX) {
                return Err(Errno::ERANGE);
            }
            let len = len_attr(&a, NFTA_PAYLOAD_LEN)?;
            let dreg = nft_parse_register(&a, NFTA_PAYLOAD_DREG, len)?;
            Ok(NftExpr::Payload { base, offset: offset as usize, len, dreg })
        }
        b"meta" => {
            let a = Attrs::parse(data, 3);
            if a.has(NFTA_META_SREG) {
                return Err(Errno::EOPNOTSUPP);
            }
            let (key, len) = match be32(&a, NFTA_META_KEY)? {
                Some(k @ (NFT_META_LEN | NFT_META_IIF | NFT_META_OIF)) => (k, 4),
                Some(NFT_META_PROTOCOL) => (NFT_META_PROTOCOL, 2),
                Some(k @ (NFT_META_NFPROTO | NFT_META_L4PROTO)) => (k, 1),
                Some(_) => return Err(Errno::EOPNOTSUPP),
                None => return Err(Errno::EINVAL),
            };
            let dreg = nft_parse_register(&a, NFTA_META_DREG, len)?;
            Ok(NftExpr::Meta { key, dreg })
        }
        b"bitwise" => {
            let a = Attrs::parse(data, 7);
            if be32(&a, NFTA_BITWISE_OP)?.unwrap_or(NFT_BITWISE_BOOL) != NFT_BITWISE_BOOL {
                return Err(Errno::EOPNOTSUPP);
            }
            let len = len_attr(&a, NFTA_BITWISE_LEN)?;
            let sreg = nft_parse_register(&a, NFTA_BITWISE_SREG, len)?;
            let dreg = nft_parse_register(&a, NFTA_BITWISE_DREG, len)?;
            let (Some(m), Some(x)) = (a.get(NFTA_BITWISE_MASK), a.get(NFTA_BITWISE_XOR)) else {
                return Err(Errno::EINVAL);
            };
            let (mask, xor) = (nft_value(m)?, nft_value(x)?);
            if mask.len() != len || xor.len() != len {
                return Err(Errno::EINVAL);
            }
            Ok(NftExpr::Bitwise { sreg, dreg, mask, xor })
        }
        b"counter" => {
            let a = Attrs::parse(data, 2);
            let packets = be64(&a, NFTA_COUNTER_PACKETS)?.unwrap_or(0);
            let bytes = be64(&a, NFTA_COUNTER_BYTES)?.unwrap_or(0);
            Ok(NftExpr::Counter {
                packets: Arc::new(AtomicU64::new(packets)),
                bytes: Arc::new(AtomicU64::new(bytes)),
            })
        }
        b"lookup" => {
            let a = Attrs::parse(data, 5);
            let name = a.str(NFTA_LOOKUP_SET).map(|n| n.split(|&c| c == 0).next().unwrap_or(n));
            if name.is_none() {
                return Err(Errno::EINVAL);
            }
            let s = nft_set_lookup_global(table, name, be32(&a, NFTA_LOOKUP_SET_ID)?)?;
            let set = &table.sets[s];
            if set.flags & NFT_SET_OBJECT != 0 {
                // The maps of objects come later.
                return Err(Errno::EOPNOTSUPP);
            }
            let len = set.klen as usize;
            let sreg = nft_parse_register(&a, NFTA_LOOKUP_SREG, len)?;
            let flags = be32(&a, NFTA_LOOKUP_FLAGS)?.unwrap_or(0);
            if flags & !NFT_LOOKUP_F_INV != 0 {
                return Err(Errno::EINVAL);
            }
            let invert = flags & NFT_LOOKUP_F_INV != 0;
            let dreg = match be32(&a, NFTA_LOOKUP_DREG)? {
                Some(_) if invert || set.flags & NFT_SET_MAP == 0 => return Err(Errno::EINVAL),
                // A verdict map stores in the register of the verdict, and only there, as
                // `nft_validate_register_store` of Linux.
                Some(r) if set.dtype == NFT_DATA_VERDICT => {
                    if r != NFT_REG_VERDICT {
                        return Err(Errno::EINVAL);
                    }
                    Some(0)
                }
                Some(NFT_REG_VERDICT) => return Err(Errno::EINVAL),
                Some(_) => Some(nft_parse_register(&a, NFTA_LOOKUP_DREG, set.dlen as usize)?),
                // A lookup of the keys of a map: it makes no sense for an anonymous map, that
                // only the rule uses.
                None if set.flags & (NFT_SET_MAP | NFT_SET_ANONYMOUS)
                    == NFT_SET_MAP | NFT_SET_ANONYMOUS =>
                {
                    return Err(Errno::EINVAL);
                }
                None => None,
            };
            Ok(NftExpr::Lookup { set: set.handle, sreg, len, invert, dreg })
        }
        b"ct" => nft_ct_init(table, data),
        b"nat" => nft_nat_init(table, data),
        b"masq" => nft_masq_init(table, data),
        b"redir" => nft_redir_init(table, data),
        b"byteorder" => Ok(NftExpr::Byteorder(nft_byteorder_init(data)?)),
        b"range" => Ok(NftExpr::Range(nft_range_init(data)?)),
        b"limit" => Ok(NftExpr::Limit(nft_limit_init(data)?)),
        b"log" => Ok(NftExpr::Log(nft_log_init(data)?)),
        b"reject" => Ok(NftExpr::Reject(nft_reject_init(table.family, data)?)),
        b"dynset" => nft_dynset_init(table, data),
        _ => Err(Errno::ENOENT),
    }
}

/// Reads a `ct` expression, as `nft_ct_get_init` and `nft_ct_set_init` of Linux. The keys that
/// need a direction are the ones of a tuple.
fn nft_ct_init(table: &NftTable, data: &[u8]) -> Result<NftExpr> {
    // Connection tracking is for IPv4 and IPv6.
    if !matches!(table.family, NFPROTO_IPV4 | NFPROTO_IPV6 | NFPROTO_INET) {
        return Err(Errno::EOPNOTSUPP);
    }
    let a = Attrs::parse(data, 4);
    let Some(key) = be32(&a, NFTA_CT_KEY)? else { return Err(Errno::EINVAL) };
    let dir = match a.get(NFTA_CT_DIRECTION) {
        None => None,
        Some(&[d]) if usize::from(d) <= 1 => Some(usize::from(d)),
        Some(_) => return Err(Errno::EINVAL),
    };
    if a.has(NFTA_CT_SREG) {
        if a.has(NFTA_CT_DREG) {
            return Err(Errno::EINVAL);
        }
        // The other keys of `nft_ct_set_init` come later.
        if key != NFT_CT_MARK {
            return Err(Errno::EOPNOTSUPP);
        }
        if dir.is_some() {
            return Err(Errno::EINVAL);
        }
        let sreg = nft_parse_register(&a, NFTA_CT_SREG, 4)?;
        return Ok(NftExpr::CtSet { sreg });
    }
    let addr_len = match table.family {
        NFPROTO_IPV4 => 4,
        _ => 16,
    };
    let (len, needs_dir) = match key {
        NFT_CT_DIRECTION => (1, false),
        NFT_CT_STATE | NFT_CT_STATUS | NFT_CT_MARK | NFT_CT_EXPIRATION | NFT_CT_ID => (4, false),
        // For compatibility, Linux takes a direction for these.
        NFT_CT_L3PROTOCOL | NFT_CT_PROTOCOL => (1, dir.is_some()),
        NFT_CT_SRC | NFT_CT_DST => (addr_len, true),
        NFT_CT_SRC_IP | NFT_CT_DST_IP => (4, true),
        NFT_CT_SRC_IP6 | NFT_CT_DST_IP6 => (16, true),
        NFT_CT_PROTO_SRC | NFT_CT_PROTO_DST => (2, true),
        _ => return Err(Errno::EOPNOTSUPP),
    };
    if needs_dir != dir.is_some() {
        return Err(Errno::EINVAL);
    }
    let dreg = nft_parse_register(&a, NFTA_CT_DREG, len)?;
    Ok(NftExpr::Ct { key, dir: dir.unwrap_or(0), len, dreg })
}

/// Reads the registers of the first and the last value of a range. The last is the first if
/// it is not there.
fn nft_range_regs(a: &Attrs<'_>, min: u32, max: u32, len: usize) -> Result<(usize, usize)> {
    let lo = nft_parse_register(a, min, len)?;
    let hi = if a.has(max) { nft_parse_register(a, max, len)? } else { lo };
    Ok((lo, hi))
}

/// The flags of a range that this NAT does.
fn nft_nat_flags(flags: u32) -> Result<u32> {
    if flags & !NF_NAT_RANGE_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & (NF_NAT_RANGE_NETMAP | NF_NAT_RANGE_PROTO_OFFSET) != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(flags)
}

/// Reads a `nat` expression, as `nft_nat_init` of Linux.
fn nft_nat_init(table: &NftTable, data: &[u8]) -> Result<NftExpr> {
    if !matches!(table.family, NFPROTO_IPV4 | NFPROTO_IPV6 | NFPROTO_INET) {
        return Err(Errno::EOPNOTSUPP);
    }
    let a = Attrs::parse(data, 7);
    let Some(ty) = be32(&a, NFTA_NAT_TYPE)? else { return Err(Errno::EINVAL) };
    if !a.has(NFTA_NAT_REG_ADDR_MIN) && !a.has(NFTA_NAT_REG_PROTO_MIN) {
        return Err(Errno::EINVAL);
    }
    let mtype = match ty {
        NFT_NAT_SNAT => NF_NAT_MANIP_SRC,
        NFT_NAT_DNAT => NF_NAT_MANIP_DST,
        _ => return Err(Errno::EOPNOTSUPP),
    };
    let Some(family) = be32(&a, NFTA_NAT_FAMILY)? else { return Err(Errno::EINVAL) };
    if table.family != NFPROTO_INET && u32::from(table.family) != family {
        return Err(Errno::EOPNOTSUPP);
    }
    let alen = match family as u8 {
        NFPROTO_IPV4 if family <= 0xff => 4,
        NFPROTO_IPV6 if family <= 0xff => 16,
        _ if a.has(NFTA_NAT_REG_ADDR_MIN) => return Err(Errno::EAFNOSUPPORT),
        _ => 0,
    };
    let mut flags = 0;
    let addr = if a.has(NFTA_NAT_REG_ADDR_MIN) {
        flags |= NF_NAT_RANGE_MAP_IPS;
        Some(nft_range_regs(&a, NFTA_NAT_REG_ADDR_MIN, NFTA_NAT_REG_ADDR_MAX, alen)?)
    } else {
        None
    };
    let proto = if a.has(NFTA_NAT_REG_PROTO_MIN) {
        flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
        Some(nft_range_regs(&a, NFTA_NAT_REG_PROTO_MIN, NFTA_NAT_REG_PROTO_MAX, 2)?)
    } else {
        None
    };
    flags |= nft_nat_flags(be32(&a, NFTA_NAT_FLAGS)?.unwrap_or(0))?;
    Ok(NftExpr::Nat { mtype, family: family as u8, alen, addr, proto, flags })
}

/// Reads a `masq` expression, as `nft_masq_init` of Linux.
fn nft_masq_init(table: &NftTable, data: &[u8]) -> Result<NftExpr> {
    if !matches!(table.family, NFPROTO_IPV4 | NFPROTO_IPV6 | NFPROTO_INET) {
        return Err(Errno::EOPNOTSUPP);
    }
    let a = Attrs::parse(data, 3);
    let flags = nft_nat_flags(be32(&a, NFTA_MASQ_FLAGS)?.unwrap_or(0))?;
    let proto = if a.has(NFTA_MASQ_REG_PROTO_MIN) {
        Some(nft_range_regs(&a, NFTA_MASQ_REG_PROTO_MIN, NFTA_MASQ_REG_PROTO_MAX, 2)?)
    } else {
        None
    };
    Ok(NftExpr::Masq { flags, proto })
}

/// Reads a `redir` expression, as `nft_redir_init` of Linux. A port range sets
/// `NF_NAT_RANGE_PROTO_SPECIFIED`.
fn nft_redir_init(table: &NftTable, data: &[u8]) -> Result<NftExpr> {
    if !matches!(table.family, NFPROTO_IPV4 | NFPROTO_IPV6 | NFPROTO_INET) {
        return Err(Errno::EOPNOTSUPP);
    }
    let a = Attrs::parse(data, 3);
    let mut flags = nft_nat_flags(be32(&a, NFTA_REDIR_FLAGS)?.unwrap_or(0))?;
    let proto = if a.has(NFTA_REDIR_REG_PROTO_MIN) {
        flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
        Some(nft_range_regs(&a, NFTA_REDIR_REG_PROTO_MIN, NFTA_REDIR_REG_PROTO_MAX, 2)?)
    } else {
        None
    };
    Ok(NftExpr::Redir { flags, proto })
}

/// The hooks of a base chain that can have the expression, and if the chain must have the type
/// `nat`, as the `validate` of nft_nat.c, nft_masq.c and nft_reject.c of Linux. Gives `None`
/// for an expression that any chain can have.
fn nft_expr_hooks(e: &NftExpr) -> Option<(u32, bool)> {
    match e {
        NftExpr::Nat { mtype: NF_NAT_MANIP_SRC, .. } => {
            Some((1 << NF_INET_POST_ROUTING | 1 << NF_INET_LOCAL_IN, true))
        }
        NftExpr::Nat { .. } => Some((1 << NF_INET_PRE_ROUTING | 1 << NF_INET_LOCAL_OUT, true)),
        NftExpr::Masq { .. } => Some((1 << NF_INET_POST_ROUTING, true)),
        NftExpr::Redir { .. } => Some((1 << NF_INET_PRE_ROUTING | 1 << NF_INET_LOCAL_OUT, true)),
        NftExpr::Reject(_) => Some((
            1 << NF_INET_PRE_ROUTING
                | 1 << NF_INET_LOCAL_IN
                | 1 << NF_INET_FORWARD
                | 1 << NF_INET_LOCAL_OUT,
            false,
        )),
        _ => None,
    }
}

/// Checks that an expression of a rule of a base chain of the type `ty` at `hooknum` can be
/// there, as `nft_chain_validate_chaintype` and `nft_chain_validate_hooks` of Linux. A chain
/// that a jump reaches checks this when a packet gets there.
pub(super) fn nft_expr_validate(e: &NftExpr, base: Option<(&NftChainType, u8)>) -> Result<()> {
    match (nft_expr_hooks(e), base) {
        (Some((mask, nat)), Some((ty, hook))) if (nat && !ty.nat) || mask & 1 << hook == 0 => {
            Err(Errno::EOPNOTSUPP)
        }
        _ => Ok(()),
    }
}

/// The range of a `nat` or `masq` expression from the registers.
fn nft_nat_range(
    regs: &NftRegs,
    flags: u32,
    alen: usize,
    addr: Option<(usize, usize)>,
    proto: Option<(usize, usize)>,
) -> NfNatRange {
    let mut r = NfNatRange { flags, ..NfNatRange::default() };
    if let Some((lo, hi)) = addr {
        r.min_addr[..alen].copy_from_slice(&regs.data[lo..lo + alen]);
        r.max_addr[..alen].copy_from_slice(&regs.data[hi..hi + alen]);
    }
    if let Some((lo, hi)) = proto {
        r.min_proto = u16::from_be_bytes([regs.data[lo], regs.data[lo + 1]]);
        r.max_proto = u16::from_be_bytes([regs.data[hi], regs.data[hi + 1]]);
    }
    r
}

/// Loads the key `key` of the connection of `skb`, as `nft_ct_get_eval` of Linux. A packet
/// with no connection has the state invalid and no other key.
fn nft_ct_get(key: u32, dir: usize, len: usize, skb: &NetBuf) -> Option<Vec<u8>> {
    let Some((ct, ctinfo)) = skb.nfct.get() else {
        return (key == NFT_CT_STATE).then(|| NF_CT_STATE_INVALID_BIT.to_ne_bytes().to_vec());
    };
    let u32v = |v: u32| Some(v.to_ne_bytes().to_vec());
    let t = &ct.tuple(dir);
    let v4 = t.l3num == NFPROTO_IPV4;
    match key {
        NFT_CT_STATE => u32v(1 << (u32::from(ctinfo % IP_CT_IS_REPLY) + 1)),
        NFT_CT_DIRECTION => {
            let d = if ctinfo >= IP_CT_IS_REPLY { IP_CT_DIR_REPLY } else { IP_CT_DIR_ORIGINAL };
            Some(alloc::vec![d as u8])
        }
        NFT_CT_STATUS => u32v(ct.status()),
        NFT_CT_MARK => u32v(ct.mark.load(Ordering::Relaxed)),
        NFT_CT_EXPIRATION => {
            let ms = ct.expires().saturating_mul(1000) / crate::options::hz();
            u32v(u32::try_from(ms).unwrap_or(u32::MAX))
        }
        NFT_CT_ID => u32v(ct.id),
        NFT_CT_L3PROTOCOL => Some(alloc::vec![t.l3num]),
        NFT_CT_PROTOCOL => Some(alloc::vec![t.protonum]),
        NFT_CT_SRC => Some(t.src[..len].to_vec()),
        NFT_CT_DST => Some(t.dst[..len].to_vec()),
        NFT_CT_SRC_IP if v4 => Some(t.src[..4].to_vec()),
        NFT_CT_DST_IP if v4 => Some(t.dst[..4].to_vec()),
        NFT_CT_SRC_IP6 if !v4 => Some(t.src.to_vec()),
        NFT_CT_DST_IP6 if !v4 => Some(t.dst.to_vec()),
        // The ports are in the order of the network, as `tuple->src.u.all`.
        NFT_CT_PROTO_SRC => Some(t.src_u.to_be_bytes().to_vec()),
        NFT_CT_PROTO_DST => Some(t.dst_u.to_be_bytes().to_vec()),
        _ => None,
    }
}

/// Tells if a rule has a `ct` expression, so that its table needs connection tracking.
pub(super) fn nft_rule_needs_ct(exprs: &[NftExpr]) -> bool {
    exprs.iter().any(|e| {
        matches!(
            e,
            NftExpr::Ct { .. }
                | NftExpr::CtSet { .. }
                | NftExpr::Nat { .. }
                | NftExpr::Masq { .. }
                | NftExpr::Redir { .. }
        )
    })
}

/// The chains that the expression `e` of `table` can jump to: the chain of a verdict, and the
/// chains of the verdicts of a verdict map.
pub(super) fn nft_expr_targets(table: &NftTable, e: &NftExpr) -> Vec<u64> {
    match e {
        NftExpr::Lookup { set, dreg: Some(_), .. } => table
            .sets
            .iter()
            .filter(|s| s.handle == *set)
            .flat_map(|s| s.elems.values())
            .filter_map(|el| match el.data {
                Some(NftData::Verdict { chain, .. }) => chain,
                _ => None,
            })
            .collect(),
        e => e.jump_target().into_iter().collect(),
    }
}

/// Tells if the chain `target` of `table` can reach the chain `from` with jumps, so that a
/// jump from `from` to `target` makes a loop, as `nf_tables_check_loops` of Linux. A jump
/// stack deeper than `NFT_JUMP_STACK_SIZE` also gives `ELOOP`. The jumps of the verdict maps
/// count.
pub(super) fn nft_check_loops(table: &NftTable, from: u64, target: u64) -> Result<()> {
    fn walk(table: &NftTable, from: u64, at: u64, depth: usize) -> Result<()> {
        if at == from || depth >= NFT_JUMP_STACK_SIZE {
            return Err(Errno::ELOOP);
        }
        let Some(chain) = table.chains.iter().find(|c| c.handle == at) else { return Ok(()) };
        for r in &chain.rules {
            for e in &r.parsed {
                for t in nft_expr_targets(table, e) {
                    walk(table, from, t, depth + 1)?;
                }
            }
        }
        Ok(())
    }
    walk(table, from, target, 1)
}

/// An expression of a program, with the jumps and the sets as indexes in the program.
#[derive(Debug)]
enum ProgExpr {
    Expr(NftExpr),
    Verdict { code: u32, chain: usize },
    Lookup { set: usize, sreg: usize, len: usize, invert: bool, dreg: Option<usize> },
    Dynset { set: usize, d: NftDynset },
}

/// The data of an element of a set in a program.
#[derive(Clone, Debug, Default)]
enum ProgData {
    /// An element of a set, or of a map that the rule looks up with no register.
    #[default]
    None,
    /// The value of an element of a map.
    Value(Vec<u8>),
    /// The verdict of an element of a verdict map, with the chain as an index in the program.
    Verdict { code: u32, chain: usize },
}

/// The elements of a set, for `lookup` and `dynset`.
#[derive(Debug, Default)]
struct ProgSet {
    keys: BTreeMap<Vec<u8>, ProgData>,
    /// The ranges of a set with `NFT_SET_INTERVAL`: the start, the end, if the range has its
    /// end, and the data.
    ranges: Vec<(Vec<u8>, Vec<u8>, bool, ProgData)>,
    /// The catch-all element, for a key that no other element has.
    catchall: Option<ProgData>,
    /// The time in nanoseconds when the elements with a timeout expire, by the start of their
    /// key, and of the catch-all element. Empty for a set with no timeouts.
    expires: BTreeMap<Vec<u8>, u64>,
    catchall_expires: u64,
    /// The timeouts in milliseconds of the elements that have one.
    timeouts: BTreeMap<Vec<u8>, u64>,
    /// The changes of `dynset` since the commit, for a set that `dynset` changes or that has
    /// `NFT_SET_EVAL`.
    dynamic: Option<super::DynElems>,
    /// The size of the set, or 0, the number of its elements at the commit, and its timeout in
    /// milliseconds.
    size: usize,
    count: usize,
    timeout: u64,
}

/// The data of an element of `dynset`.
fn prog_data(e: &super::NftElem) -> ProgData {
    match &e.data {
        Some(NftData::Value(v)) => ProgData::Value(v.clone()),
        _ => ProgData::None,
    }
}

impl ProgSet {
    /// The data of the element of `key`, as the `lookup` of the backends of sets of Linux. An
    /// element that has expired does not match.
    fn find(&self, key: &[u8]) -> Option<ProgData> {
        let now = if self.expires.is_empty() && self.catchall_expires == 0 && self.dynamic.is_none()
        {
            0
        } else {
            super::nft_now_ns()
        };
        let catchall = || {
            self.catchall
                .clone()
                .filter(|_| self.catchall_expires == 0 || now < self.catchall_expires)
        };
        if let Some(d) = &self.dynamic {
            match d.0.lock().elems.get(key) {
                Some(DynElem::Add(e)) if !e.expired(now) => return Some(prog_data(e)),
                Some(&DynElem::Refresh(x)) if now < x => {
                    return self.keys.get(key).cloned().or_else(catchall);
                }
                Some(_) => return catchall(),
                None => {}
            }
        }
        let live = |k: &[u8]| self.expires.get(k).is_none_or(|&t| now < t);
        self.keys
            .get(key)
            .filter(|_| live(key))
            .cloned()
            .or_else(|| {
                self.ranges.iter().find_map(|(s, e, with_end, d)| {
                    let inside = s.as_slice() <= key
                        && (key < e.as_slice() || (*with_end && key == e.as_slice()));
                    (inside && live(s)).then(|| d.clone())
                })
            })
            .or_else(catchall)
    }
}

/// Runs `dynset` on the set `set`, as `nft_dynset_eval` of Linux: adds the key of the
/// registers, updates the expiration of its element, or removes it. A key that is not there
/// and does not fit in the set ends the rule, and with `NFT_DYNSET_F_INV` a key that is there
/// or that fits.
fn nft_dynset_eval(d: &NftDynset, set: &ProgSet, regs: &mut NftRegs) {
    let Some(dy) = &set.dynamic else { return };
    let key = regs.data[d.sreg_key..d.sreg_key + d.klen].to_vec();
    let now = super::nft_now_ns();
    let mut g = dy.0.lock();
    // The timeout of the element of the key, if it is there.
    let committed = || {
        let live = set.expires.get(&key).is_none_or(|&t| now < t);
        (set.keys.contains_key(&key) && live).then(|| set.timeouts.get(&key).copied().unwrap_or(0))
    };
    let present = match g.elems.get(&key) {
        Some(DynElem::Add(e)) => (!e.expired(now)).then_some(e.timeout),
        Some(&DynElem::Refresh(x)) => {
            (now < x).then(|| set.timeouts.get(&key).copied().unwrap_or(0))
        }
        Some(DynElem::Del) => None,
        None => committed(),
    };
    if d.op == NFT_DYNSET_OP_DELETE {
        if present.is_some() {
            g.elems.insert(key, DynElem::Del);
            g.delta -= 1;
        }
        return;
    }
    let ok = match present {
        Some(t) => {
            // An update starts the timeout of the element again.
            if d.op == NFT_DYNSET_OP_UPDATE && t != 0 {
                let t = if d.timeout != 0 { d.timeout } else { t };
                let x = now.saturating_add(t * 1_000_000);
                match g.elems.get_mut(&key) {
                    Some(DynElem::Add(e)) => e.expires = x,
                    _ => {
                        g.elems.insert(key, DynElem::Refresh(x));
                    }
                }
            }
            true
        }
        None if set.size != 0 && set.count as isize + g.delta >= set.size as isize => false,
        None => {
            let timeout = if d.timeout != 0 { d.timeout } else { set.timeout };
            let data = d.sreg_data.map(|(r, l)| NftData::Value(regs.data[r..r + l].to_vec()));
            let elem = super::NftElem {
                key_end: None,
                data,
                flags: 0,
                udata: None,
                timeout,
                expires: if timeout == 0 { 0 } else { now.saturating_add(timeout * 1_000_000) },
            };
            // An element of `dynset` that expired has its place in the count.
            if !matches!(g.elems.get(&key), Some(DynElem::Add(_))) {
                g.delta += 1;
            }
            g.elems.insert(key, DynElem::Add(elem));
            true
        }
    };
    drop(g);
    if ok == d.invert {
        regs.verdict = NFT_BREAK;
    }
}

/// The program of a base chain: the chains that it can reach, the first is the base chain.
#[derive(Debug, Default)]
pub(super) struct NftProg {
    chains: Vec<Vec<Vec<ProgExpr>>>,
    sets: Vec<ProgSet>,
    /// The base chain has the type `nat`.
    nat: bool,
}

impl NftProg {
    /// The number of rules of each chain of the program.
    #[cfg(test)]
    pub(super) fn rules_of_chains(&self) -> Vec<usize> {
        self.chains.iter().map(Vec::len).collect()
    }
}

/// The chains of a program that is made: their indexes, and the chains that still need their
/// rules.
struct ProgChains {
    at: BTreeMap<u64, usize>,
    todo: Vec<u64>,
}

impl ProgChains {
    /// The index of the chain `h` in the program.
    fn index(&mut self, h: u64) -> usize {
        let next = self.at.len();
        *self.at.entry(h).or_insert_with(|| {
            self.todo.push(h);
            next
        })
    }
}

/// The elements of the set `s` of `table`.
fn prog_set(table: &NftTable, s: usize, chains: &mut ProgChains) -> ProgSet {
    let set = &table.sets[s];
    let changed = table
        .chains
        .iter()
        .flat_map(|c| &c.rules)
        .flat_map(|r| &r.parsed)
        .any(|e| matches!(e, NftExpr::Dynset(d) if d.set == set.handle));
    let mut p = ProgSet {
        dynamic: (changed || set.flags & NFT_SET_EVAL != 0).then(|| set.dynamic.clone()),
        size: set.size as usize,
        timeout: set.timeout,
        ..ProgSet::default()
    };
    let now = super::nft_now_ns();
    for (k, e) in set.elems.iter().filter(|(k, e)| e.timeout != 0 && !k.catchall) {
        p.timeouts.insert(k.key.clone(), e.timeout);
    }
    for (k, e) in set.elems.iter().filter(|(_, e)| e.expires != 0) {
        if k.catchall {
            p.catchall_expires = e.expires;
        } else {
            p.expires.insert(k.key.clone(), e.expires);
        }
    }
    let mut data = |e: &super::NftElem| match &e.data {
        Some(NftData::Value(v)) => ProgData::Value(v.clone()),
        Some(NftData::Verdict { code, chain }) => {
            ProgData::Verdict { code: *code, chain: chain.map_or(0, |h| chains.index(h)) }
        }
        None => ProgData::None,
    };
    if set.flags & NFT_SET_INTERVAL != 0 {
        // The elements are in the order of the keys: a start, then the element with
        // `NFT_SET_ELEM_INTERVAL_END` that ends the range. A start with `NFTA_SET_ELEM_KEY_END`
        // is a range with its end. The start has the data of the range.
        let mut start: Option<(&Vec<u8>, ProgData)> = None;
        for (k, e) in set.elems.iter().filter(|(_, e)| !e.expired(now)) {
            if k.catchall {
                p.catchall = Some(data(e));
            } else if k.end || e.flags & NFT_SET_ELEM_INTERVAL_END != 0 {
                if let Some((s, d)) = start.take() {
                    p.ranges.push((s.clone(), k.key.clone(), false, d));
                }
            } else if let Some(end) = &e.key_end {
                p.ranges.push((k.key.clone(), end.clone(), true, data(e)));
                start = None;
            } else {
                start = Some((&k.key, data(e)));
            }
        }
        // A start with no end goes to the last key.
        if let Some((s, d)) = start {
            p.ranges.push((s.clone(), alloc::vec![0xff; s.len()], true, d));
        }
    } else {
        for (k, e) in set.elems.iter().filter(|(_, e)| !e.expired(now)) {
            if k.catchall {
                p.catchall = Some(data(e));
            } else {
                p.keys.insert(k.key.clone(), data(e));
            }
        }
    }
    p.count = p.keys.len();
    p
}

/// Makes the program of the chain `c` of `table`, as the rules of `nf_tables_commit_chain`
/// of Linux.
pub(super) fn nft_prog(table: &NftTable, c: usize) -> NftProg {
    let mut prog = NftProg {
        nat: table.chains[c].base.as_ref().is_some_and(|b| b.ty.nat),
        ..NftProg::default()
    };
    let mut chains = ProgChains { at: BTreeMap::new(), todo: Vec::new() };
    chains.index(table.chains[c].handle);
    let mut set_at: BTreeMap<u64, usize> = BTreeMap::new();
    // The index in the program of the set with the handle `h`.
    let mut set_index = |h: u64, prog: &mut NftProg, chains: &mut ProgChains| {
        *set_at.entry(h).or_insert_with(|| {
            let s = table.sets.iter().position(|s| s.handle == h);
            prog.sets.push(s.map(|s| prog_set(table, s, chains)).unwrap_or_default());
            prog.sets.len() - 1
        })
    };
    while let Some(h) = chains.todo.pop() {
        let Some(chain) = table.chains.iter().find(|ch| ch.handle == h) else { continue };
        let mut rules = Vec::with_capacity(chain.rules.len());
        for r in &chain.rules {
            let mut out = Vec::with_capacity(r.parsed.len());
            for e in &r.parsed {
                out.push(match e {
                    NftExpr::Immediate {
                        data: NftImm::Verdict { code, chain: Some(t) }, ..
                    } => ProgExpr::Verdict { code: *code, chain: chains.index(*t) },
                    NftExpr::Lookup { set, sreg, len, invert, dreg } => ProgExpr::Lookup {
                        set: set_index(*set, &mut prog, &mut chains),
                        sreg: *sreg,
                        len: *len,
                        invert: *invert,
                        dreg: *dreg,
                    },
                    NftExpr::Dynset(d) => ProgExpr::Dynset {
                        set: set_index(d.set, &mut prog, &mut chains),
                        d: d.clone(),
                    },
                    e => ProgExpr::Expr(e.clone()),
                });
            }
            rules.push(out);
        }
        let at = chains.at[&h];
        if at >= prog.chains.len() {
            prog.chains.resize_with(at + 1, Vec::new);
        }
        prog.chains[at] = rules;
    }
    prog
}

/// The registers, as `struct nft_regs` of Linux.
struct NftRegs {
    verdict: u32,
    chain: usize,
    data: [u8; NFT_REGS_LEN],
}

impl NftRegs {
    /// Stores `v` at `at` and clears the rest of the last register of 4 bytes, as the stores
    /// of Linux.
    fn store(&mut self, at: usize, v: &[u8]) {
        let end = at + v.len().div_ceil(NFT_REG32_SIZE) * NFT_REG32_SIZE;
        self.data[at..end].fill(0);
        self.data[at..at + v.len()].copy_from_slice(v);
    }
}

/// Runs an expression.
fn nft_eval(
    e: &ProgExpr,
    prog: &NftProg,
    regs: &mut NftRegs,
    skb: &NetBuf,
    state: &NfHookState,
    pkt: &NftPktinfo,
) {
    match e {
        ProgExpr::Verdict { code, chain } => {
            regs.verdict = *code;
            regs.chain = *chain;
        }
        ProgExpr::Lookup { set, sreg, len, invert, dreg } => {
            let found = prog.sets[*set].find(&regs.data[*sreg..*sreg + *len]);
            if found.is_some() == *invert {
                regs.verdict = NFT_BREAK;
                return;
            }
            match (found, dreg) {
                (Some(ProgData::Value(v)), Some(dreg)) => regs.store(*dreg, &v),
                (Some(ProgData::Verdict { code, chain }), Some(_)) => {
                    regs.verdict = code;
                    regs.chain = chain;
                }
                _ => {}
            }
        }
        ProgExpr::Dynset { set, d } => nft_dynset_eval(d, &prog.sets[*set], regs),
        ProgExpr::Expr(e) => match e {
            NftExpr::Immediate { dreg, data: NftImm::Value(v) } => regs.store(*dreg, v),
            NftExpr::Immediate { data: NftImm::Verdict { code, .. }, .. } => regs.verdict = *code,
            NftExpr::Cmp { sreg, op, data } => {
                let d = regs.data[*sreg..*sreg + data.len()].cmp(data.as_slice());
                let ok = match *op {
                    NFT_CMP_EQ => d.is_eq(),
                    NFT_CMP_NEQ => d.is_ne(),
                    NFT_CMP_LT => d.is_lt(),
                    NFT_CMP_LTE => d.is_le(),
                    NFT_CMP_GT => d.is_gt(),
                    _ => d.is_ge(),
                };
                if !ok {
                    regs.verdict = NFT_BREAK;
                }
            }
            NftExpr::Payload { base, offset, len, dreg } => {
                let d = skb.data();
                let start = match *base {
                    NFT_PAYLOAD_NETWORK_HEADER => Some(0),
                    NFT_PAYLOAD_TRANSPORT_HEADER => pkt.thoff,
                    // The packet has no link layer header at the hooks of IPv4 and IPv6.
                    _ => None,
                };
                match start.and_then(|s| d.get(s + offset..s + offset + len)) {
                    Some(v) => regs.store(*dreg, v),
                    None => regs.verdict = NFT_BREAK,
                }
            }
            NftExpr::Meta { key, dreg } => match *key {
                NFT_META_LEN => regs.store(*dreg, &(skb.len() as u32).to_ne_bytes()),
                NFT_META_PROTOCOL => {
                    let p = if state.pf == NFPROTO_IPV6 { ETH_P_IPV6 } else { ETH_P_IP };
                    regs.store(*dreg, &p.to_be_bytes());
                }
                NFT_META_IIF if state.in_dev != 0 => {
                    regs.store(*dreg, &state.in_dev.to_ne_bytes());
                }
                NFT_META_OIF if state.out_dev != 0 => {
                    regs.store(*dreg, &state.out_dev.to_ne_bytes());
                }
                NFT_META_NFPROTO => regs.store(*dreg, &[state.pf]),
                NFT_META_L4PROTO if pkt.thoff.is_some() => regs.store(*dreg, &[pkt.l4proto]),
                _ => regs.verdict = NFT_BREAK,
            },
            NftExpr::Bitwise { sreg, dreg, mask, xor } => {
                let mut v = [0u8; NFT_REGS_LEN];
                for i in 0..mask.len() {
                    v[i] = (regs.data[sreg + i] & mask[i]) ^ xor[i];
                }
                regs.store(*dreg, &v[..mask.len()]);
            }
            NftExpr::Counter { packets, bytes } => {
                packets.fetch_add(1, Ordering::Relaxed);
                bytes.fetch_add(skb.len() as u64, Ordering::Relaxed);
            }
            NftExpr::Lookup { .. } | NftExpr::Dynset(_) => regs.verdict = NFT_BREAK,
            NftExpr::Ct { key, dir, len, dreg } => match nft_ct_get(*key, *dir, *len, skb) {
                Some(v) => regs.store(*dreg, &v),
                None => regs.verdict = NFT_BREAK,
            },
            NftExpr::CtSet { sreg } => {
                if let Some((ct, _)) = skb.nfct.get() {
                    let r = &regs.data[*sreg..*sreg + 4];
                    let v = u32::from_ne_bytes([r[0], r[1], r[2], r[3]]);
                    if ct.mark.load(Ordering::Relaxed) != v {
                        ct.mark.store(v, Ordering::Relaxed);
                    }
                }
            }
            // A chain that is not of the type `nat`, or a hook of the other change, can reach a
            // rule of NAT only with a jump; the rule does not match there.
            e @ (NftExpr::Nat { .. } | NftExpr::Masq { .. } | NftExpr::Redir { .. })
                if !prog.nat
                    || nft_expr_hooks(e).is_some_and(|(m, _)| m & 1 << state.hook == 0)
                    || skb.nfct.get().is_none() =>
            {
                regs.verdict = NFT_BREAK;
            }
            NftExpr::Nat { mtype, family, alen, addr, proto, flags } => {
                if (*family == NFPROTO_INET || *family == state.pf)
                    && hook2manip(state.hook) == *mtype
                    && let Some((ct, _)) = skb.nfct.get()
                {
                    let r = nft_nat_range(regs, *flags, *alen, *addr, *proto);
                    regs.verdict = nf_nat_setup_info(ct, &r, *mtype);
                }
            }
            NftExpr::Redir { flags, proto } => {
                if let Some((ct, _)) = skb.nfct.get() {
                    let r = nft_nat_range(regs, *flags, 0, None, *proto);
                    regs.verdict = nf_nat_redirect(ct, &r, state, skb.data());
                }
            }
            NftExpr::Masq { flags, proto } => {
                if let Some((ct, _)) = skb.nfct.get() {
                    let r = nft_nat_range(regs, *flags, 0, None, *proto);
                    regs.verdict = nf_nat_masquerade(ct, &r, state, skb.data());
                }
            }
            NftExpr::Byteorder(b) => nft_byteorder_eval(b, regs),
            NftExpr::Range(r) => nft_range_eval(r, regs),
            NftExpr::Limit(l) => nft_limit_eval(l, regs, skb),
            NftExpr::Log(l) => nft_log_eval(l, skb, state),
            // A chain that a jump reaches from a hook with no `reject` does not reject.
            NftExpr::Reject(r) => {
                regs.verdict = if nft_expr_hooks(e).is_some_and(|(m, _)| m & 1 << state.hook == 0) {
                    NFT_BREAK
                } else {
                    nft_reject_eval(r, skb, state)
                };
            }
        },
    }
}

/// Runs the program of a base chain on a packet, as `nft_do_chain` of Linux. Gives the
/// verdict, or `policy` at the end of the base chain.
pub(super) fn nft_do_chain(prog: &NftProg, policy: u32, skb: &NetBuf, state: &NfHookState) -> u32 {
    let pkt = nft_pktinfo(state.pf, skb.data());
    let mut regs = NftRegs { verdict: NFT_CONTINUE, chain: 0, data: [0; NFT_REGS_LEN] };
    let mut stack: Vec<(usize, usize)> = Vec::new();
    let (mut chain, mut rule) = (0usize, 0usize);
    loop {
        let Some(rules) = prog.chains.get(chain) else { return NF_DROP };
        let Some(r) = rules.get(rule) else {
            // The end of a chain: back to the chain of the jump, or the policy.
            match stack.pop() {
                Some((c, n)) => (chain, rule) = (c, n),
                None => return policy,
            }
            continue;
        };
        regs.verdict = NFT_CONTINUE;
        for e in r {
            nft_eval(e, prog, &mut regs, skb, state, &pkt);
            if regs.verdict != NFT_CONTINUE {
                break;
            }
        }
        match regs.verdict {
            NFT_CONTINUE | NFT_BREAK => rule += 1,
            NFT_JUMP => {
                if stack.len() >= NFT_JUMP_STACK_SIZE {
                    return NF_DROP;
                }
                stack.push((chain, rule + 1));
                (chain, rule) = (regs.chain, 0);
            }
            NFT_GOTO => (chain, rule) = (regs.chain, 0),
            NFT_RETURN => match stack.pop() {
                Some((c, n)) => (chain, rule) = (c, n),
                None => return policy,
            },
            // `NF_ACCEPT`, `NF_DROP` with its error, `NF_QUEUE` and the other verdicts of
            // netfilter end the packet path of nf_tables.
            v => return v,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netfilter::{NF_ACCEPT, NF_INET_LOCAL_OUT};
    use alloc::vec;

    const R1: usize = NFT_REG_SIZE;

    fn state(pf: u8) -> NfHookState {
        NfHookState { hook: NF_INET_LOCAL_OUT, pf, in_dev: 0, out_dev: 3 }
    }

    /// An IPv4 UDP packet from 10.0.0.1 to 10.0.0.2 with the destination port `dport`.
    fn udp4(dport: u16) -> NetBuf {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        NetBuf::from_slice(&p)
    }

    fn e(x: NftExpr) -> ProgExpr {
        ProgExpr::Expr(x)
    }

    fn dport(port: u16) -> Vec<ProgExpr> {
        vec![
            e(NftExpr::Payload { base: NFT_PAYLOAD_TRANSPORT_HEADER, offset: 2, len: 2, dreg: R1 }),
            e(NftExpr::Cmp { sreg: R1, op: NFT_CMP_EQ, data: port.to_be_bytes().to_vec() }),
        ]
    }

    fn verdict(code: u32, chain: usize) -> ProgExpr {
        ProgExpr::Verdict { code, chain }
    }

    #[test]
    fn a_rule_drops_the_packets_that_match_and_the_rest_get_the_policy() {
        let mut r = dport(9);
        r.push(verdict(NF_DROP, 0));
        let prog = NftProg { chains: vec![vec![r]], sets: vec![], nat: false };
        let s = state(NFPROTO_IPV4);
        assert_eq!(nft_do_chain(&prog, NF_ACCEPT, &udp4(9), &s), NF_DROP);
        assert_eq!(nft_do_chain(&prog, NF_ACCEPT, &udp4(10), &s), NF_ACCEPT);
    }

    #[test]
    fn a_jump_comes_back_and_a_goto_does_not() {
        // Chain 0 jumps to chain 1, which returns for port 9 and accepts the rest. The next
        // rule of chain 0 drops.
        let c0 = vec![vec![verdict(NFT_JUMP, 1)], vec![verdict(NF_DROP, 0)]];
        let mut ret = dport(9);
        ret.push(verdict(NFT_RETURN, 0));
        let c1 = vec![ret, vec![verdict(NF_ACCEPT, 0)]];
        let prog = NftProg { chains: vec![c0, c1], sets: vec![], nat: false };
        let s = state(NFPROTO_IPV4);
        assert_eq!(nft_do_chain(&prog, NF_ACCEPT, &udp4(9), &s), NF_DROP);
        assert_eq!(nft_do_chain(&prog, NF_DROP, &udp4(10), &s), NF_ACCEPT);
        // A goto to an empty chain ends with the policy of the base chain.
        let c0 = vec![vec![verdict(NFT_GOTO, 1)], vec![verdict(NF_DROP, 0)]];
        let prog = NftProg { chains: vec![c0, vec![]], sets: vec![], nat: false };
        assert_eq!(nft_do_chain(&prog, NF_ACCEPT, &udp4(9), &s), NF_ACCEPT);
    }

    #[test]
    fn ct_reads_the_connection_and_sets_its_mark() {
        use crate::netfilter::nf_conntrack::nf_conntrack_in;
        let s = state(NFPROTO_IPV4);
        // ct state & (new | invalid) != 0: ct mark set 7, drop for port 9.
        let state_is = |bits: u32| {
            vec![
                e(NftExpr::Ct { key: NFT_CT_STATE, dir: 0, len: 4, dreg: R1 }),
                e(NftExpr::Bitwise {
                    sreg: R1,
                    dreg: R1,
                    mask: bits.to_ne_bytes().to_vec(),
                    xor: vec![0; 4],
                }),
                e(NftExpr::Cmp { sreg: R1, op: NFT_CMP_NEQ, data: vec![0; 4] }),
            ]
        };
        let mut r = state_is(1 << 3);
        r.extend([
            e(NftExpr::Ct { key: NFT_CT_SRC, dir: 1, len: 4, dreg: R1 }),
            e(NftExpr::Cmp { sreg: R1, op: NFT_CMP_EQ, data: vec![10, 0, 0, 2] }),
            e(NftExpr::Ct { key: NFT_CT_PROTO_DST, dir: 0, len: 2, dreg: R1 }),
            e(NftExpr::Cmp { sreg: R1, op: NFT_CMP_EQ, data: 9u16.to_be_bytes().to_vec() }),
            e(NftExpr::Immediate { dreg: R1, data: NftImm::Value(7u32.to_ne_bytes().to_vec()) }),
            e(NftExpr::CtSet { sreg: R1 }),
            verdict(NF_DROP, 0),
        ]);
        let mut invalid = state_is(NF_CT_STATE_INVALID_BIT);
        invalid.push(verdict(NF_DROP, 0));
        let prog = NftProg { chains: vec![vec![r, invalid]], sets: vec![], nat: false };
        // No connection: the state is invalid, and the other keys break the rule.
        assert_eq!(nft_do_chain(&prog, NF_ACCEPT, &udp4(9), &s), NF_DROP);
        let mut p = udp4(9);
        p.data_mut()[3] = 28;
        assert_eq!(nf_conntrack_in(&mut p, &s), NF_ACCEPT);
        assert_eq!(nft_do_chain(&prog, NF_ACCEPT, &p, &s), NF_DROP);
        assert_eq!(p.nfct.get().unwrap().0.mark.load(Ordering::Relaxed), 7);
        let mut q = udp4(10);
        nf_conntrack_in(&mut q, &s);
        assert_eq!(nft_do_chain(&prog, NF_ACCEPT, &q, &s), NF_ACCEPT);
        let mut regs = vec![e(NftExpr::Ct { key: NFT_CT_DIRECTION, dir: 0, len: 1, dreg: R1 })];
        regs.extend([
            e(NftExpr::Cmp { sreg: R1, op: NFT_CMP_EQ, data: vec![0] }),
            verdict(NF_DROP, 0),
        ]);
        let prog = NftProg { chains: vec![vec![regs]], sets: vec![], nat: false };
        assert_eq!(nft_do_chain(&prog, NF_ACCEPT, &q, &s), NF_DROP);
    }

    #[test]
    fn meta_bitwise_and_lookup_match_the_packet() {
        let s = state(NFPROTO_IPV4);
        // meta l4proto udp, ip saddr & 255.255.255.0 == 10.0.0.0, oif 3: counter, drop.
        let packets = Arc::new(AtomicU64::new(0));
        let bytes = Arc::new(AtomicU64::new(0));
        let r = vec![
            e(NftExpr::Meta { key: NFT_META_L4PROTO, dreg: R1 }),
            e(NftExpr::Cmp { sreg: R1, op: NFT_CMP_EQ, data: vec![17] }),
            e(NftExpr::Payload { base: NFT_PAYLOAD_NETWORK_HEADER, offset: 12, len: 4, dreg: R1 }),
            e(NftExpr::Bitwise {
                sreg: R1,
                dreg: R1,
                mask: vec![255, 255, 255, 0],
                xor: vec![0; 4],
            }),
            e(NftExpr::Cmp { sreg: R1, op: NFT_CMP_EQ, data: vec![10, 0, 0, 0] }),
            e(NftExpr::Meta { key: NFT_META_OIF, dreg: R1 }),
            e(NftExpr::Cmp { sreg: R1, op: NFT_CMP_EQ, data: 3u32.to_ne_bytes().to_vec() }),
            e(NftExpr::Counter { packets: packets.clone(), bytes: bytes.clone() }),
            verdict(NF_DROP, 0),
        ];
        let prog = NftProg { chains: vec![vec![r]], sets: vec![], nat: false };
        assert_eq!(nft_do_chain(&prog, NF_ACCEPT, &udp4(1), &s), NF_DROP);
        assert_eq!((packets.load(Ordering::Relaxed), bytes.load(Ordering::Relaxed)), (1, 28));

        // udp dport in { 5-9 }, and not in { 7 } with NFT_LOOKUP_F_INV.
        let range = ProgSet {
            ranges: vec![(
                5u16.to_be_bytes().to_vec(),
                9u16.to_be_bytes().to_vec(),
                true,
                ProgData::None,
            )],
            ..ProgSet::default()
        };
        let seven = ProgSet {
            keys: [(7u16.to_be_bytes().to_vec(), ProgData::None)].into(),
            ..ProgSet::default()
        };
        let mut r = dport(0);
        r.pop();
        r.push(ProgExpr::Lookup { set: 0, sreg: R1, len: 2, invert: false, dreg: None });
        r.push(ProgExpr::Lookup { set: 1, sreg: R1, len: 2, invert: true, dreg: None });
        r.push(verdict(NF_DROP, 0));
        let prog = NftProg { chains: vec![vec![r]], sets: vec![range, seven], nat: false };
        let v: Vec<u32> = [4, 5, 7, 9, 10]
            .iter()
            .map(|&p| nft_do_chain(&prog, NF_ACCEPT, &udp4(p), &s))
            .collect();
        assert_eq!(v, [NF_ACCEPT, NF_DROP, NF_ACCEPT, NF_DROP, NF_ACCEPT]);
    }

    #[test]
    fn a_map_loads_the_data_and_a_verdict_map_sets_the_verdict() {
        let s = state(NFPROTO_IPV4);
        const R2: usize = 2 * NFT_REG_SIZE;
        // udp dport map { 7 : 70, 8 : 80 } in R2, R2 == 80: drop.
        let map = ProgSet {
            keys: [
                (7u16.to_be_bytes().to_vec(), ProgData::Value(70u16.to_be_bytes().to_vec())),
                (8u16.to_be_bytes().to_vec(), ProgData::Value(80u16.to_be_bytes().to_vec())),
            ]
            .into(),
            ..ProgSet::default()
        };
        // udp dport vmap { 1-3 : jump c1, 9 : accept, * : goto c2 }.
        let vmap = ProgSet {
            keys: [(9u16.to_be_bytes().to_vec(), ProgData::Verdict { code: NF_ACCEPT, chain: 0 })]
                .into(),
            ranges: vec![(
                1u16.to_be_bytes().to_vec(),
                3u16.to_be_bytes().to_vec(),
                true,
                ProgData::Verdict { code: NFT_JUMP, chain: 1 },
            )],
            catchall: Some(ProgData::Verdict { code: NFT_GOTO, chain: 2 }),
            ..ProgSet::default()
        };
        let mut r0 = dport(0);
        r0.pop();
        r0.push(ProgExpr::Lookup { set: 0, sreg: R1, len: 2, invert: false, dreg: Some(R2) });
        r0.push(e(NftExpr::Cmp { sreg: R2, op: NFT_CMP_EQ, data: 80u16.to_be_bytes().to_vec() }));
        r0.push(verdict(NF_DROP, 0));
        let mut r1 = dport(0);
        r1.pop();
        r1.push(ProgExpr::Lookup { set: 1, sreg: R1, len: 2, invert: false, dreg: Some(0) });
        // c1 drops port 2 and returns, c2 drops all.
        let mut c1 = dport(2);
        c1.push(verdict(NF_DROP, 0));
        let c2 = vec![verdict(NF_DROP, 0)];
        let prog = NftProg {
            chains: vec![vec![r0, r1, vec![verdict(NF_ACCEPT, 0)]], vec![c1], vec![c2]],
            sets: vec![map, vmap],
            nat: false,
        };
        let v: Vec<u32> = [7, 8, 1, 2, 9, 5]
            .iter()
            .map(|&p| nft_do_chain(&prog, NF_ACCEPT, &udp4(p), &s))
            .collect();
        // 7 matches no element of the vmap and takes the catch-all.
        assert_eq!(v, [NF_DROP, NF_DROP, NF_ACCEPT, NF_DROP, NF_ACCEPT, NF_DROP]);
    }

    #[test]
    fn an_element_matches_until_it_expires() {
        use core::sync::atomic::Ordering;
        let k = |p: u16| p.to_be_bytes().to_vec();
        let set = ProgSet {
            keys: [(k(1), ProgData::None), (k(2), ProgData::None)].into(),
            ranges: vec![(k(10), k(20), true, ProgData::None)],
            catchall: Some(ProgData::Value(k(7))),
            expires: [(k(1), 5_000), (k(10), 8_000)].into(),
            catchall_expires: 9_000,
            ..ProgSet::default()
        };
        super::super::NFT_TEST_NS.store(4_999, Ordering::Relaxed);
        assert!(matches!(set.find(&k(1)), Some(ProgData::None)));
        assert!(matches!(set.find(&k(15)), Some(ProgData::None)));
        super::super::NFT_TEST_NS.store(5_000, Ordering::Relaxed);
        // 1 has expired and takes the catch-all; 2 has no timeout.
        assert!(matches!(set.find(&k(1)), Some(ProgData::Value(_))));
        assert!(matches!(set.find(&k(2)), Some(ProgData::None)));
        super::super::NFT_TEST_NS.store(9_000, Ordering::Relaxed);
        assert!(set.find(&k(15)).is_none());
        assert!(matches!(set.find(&k(2)), Some(ProgData::None)));
        // `dynset` adds an element with the timeout of the set, and an update starts the
        // timeout again. The test runs here, as it sets the time too.
        let set = ProgSet { timeout: 3, dynamic: Some(Default::default()), ..ProgSet::default() };
        let add = |op: u32, timeout: u64| NftDynset {
            set: 0,
            op,
            sreg_key: R1,
            klen: 2,
            sreg_data: None,
            timeout,
            invert: false,
        };
        let mut regs = NftRegs { verdict: NFT_CONTINUE, chain: 0, data: [0; NFT_REGS_LEN] };
        regs.data[R1..R1 + 2].copy_from_slice(&k(5));
        super::super::NFT_TEST_NS.store(1_000_000, Ordering::Relaxed);
        nft_dynset_eval(&add(0, 0), &set, &mut regs);
        super::super::NFT_TEST_NS.store(3_999_999, Ordering::Relaxed);
        assert!(set.find(&k(5)).is_some());
        nft_dynset_eval(&add(1, 10), &set, &mut regs);
        super::super::NFT_TEST_NS.store(13_000_000, Ordering::Relaxed);
        assert!(set.find(&k(5)).is_some());
        // An add does not start it again.
        nft_dynset_eval(&add(0, 0), &set, &mut regs);
        super::super::NFT_TEST_NS.store(13_999_999, Ordering::Relaxed);
        assert!(set.find(&k(5)).is_none());
        assert_eq!(regs.verdict, NFT_CONTINUE);
        super::super::NFT_TEST_NS.store(0, Ordering::Relaxed);
    }

    #[test]
    fn dynset_adds_the_key_of_the_packet_and_removes_it() {
        // The first rule removes port 6 from set 0, the next drops the ports in set 0, the next
        // adds port 5 to it, and the last drops port 7, that does not fit in set 1.
        let lookup = |set| ProgExpr::Lookup { set, sreg: R1, len: 2, invert: false, dreg: None };
        let load =
            e(NftExpr::Payload { base: NFT_PAYLOAD_TRANSPORT_HEADER, offset: 2, len: 2, dreg: R1 });
        let dynset = |set, op, invert| ProgExpr::Dynset {
            set,
            d: NftDynset { set: 0, op, sreg_key: R1, klen: 2, sreg_data: None, timeout: 0, invert },
        };
        let mut r0 = vec![load, lookup(0)];
        r0.push(verdict(NF_DROP, 0));
        let mut r1 = dport(5);
        r1.push(dynset(0, 0, false));
        let mut r2 = dport(6);
        r2.push(dynset(0, NFT_DYNSET_OP_DELETE, false));
        let mut r3 = dport(7);
        r3.extend([dynset(1, 0, true), verdict(NF_DROP, 0)]);
        let k = |p: u16| p.to_be_bytes().to_vec();
        let set0 = ProgSet {
            keys: [(k(6), ProgData::None)].into(),
            count: 1,
            dynamic: Some(Default::default()),
            ..ProgSet::default()
        };
        let set1 = ProgSet {
            keys: [(k(9), ProgData::None)].into(),
            size: 1,
            count: 1,
            dynamic: Some(Default::default()),
            ..ProgSet::default()
        };
        let prog =
            NftProg { chains: vec![vec![r2, r0, r1, r3]], sets: vec![set0, set1], nat: false };
        let s = state(NFPROTO_IPV4);
        let v: Vec<u32> =
            [5, 5, 6, 6, 7].iter().map(|&p| nft_do_chain(&prog, NF_ACCEPT, &udp4(p), &s)).collect();
        // 5 is added and dropped the next time; 6 is removed before the lookup.
        assert_eq!(v, [NF_ACCEPT, NF_DROP, NF_ACCEPT, NF_ACCEPT, NF_DROP]);
        let d = prog.sets[0].dynamic.as_ref().unwrap().0.lock();
        assert!(matches!(d.elems.get(&k(5)), Some(DynElem::Add(_))));
        assert!(matches!(d.elems.get(&k(6)), Some(DynElem::Del)));
        assert_eq!(d.delta, 0);
    }

    #[test]
    fn the_transport_header_of_ipv6_is_after_the_extension_headers() {
        let mut p = vec![0u8; 40 + 8 + 8];
        p[0] = 0x60;
        p[6] = 0; // Hop by hop options.
        p[40] = 17;
        p[41] = 0;
        p[50..52].copy_from_slice(&53u16.to_be_bytes());
        let pkt = nft_pktinfo(NFPROTO_IPV6, &p);
        assert_eq!((pkt.thoff, pkt.l4proto), (Some(48), 17));
        // A fragment of IPv4 that is not the first has no transport header.
        let mut b = udp4(9).data().to_vec();
        b[6..8].copy_from_slice(&0x0010u16.to_be_bytes());
        assert_eq!(nft_pktinfo(NFPROTO_IPV4, &b).thoff, None);
    }

    #[test]
    fn a_register_must_hold_the_data() {
        let reg = |r: u32, len: usize| {
            let mut b = crate::netlink::msg::Builder::new(0, 0, 0, 0);
            b.put(1, &r.to_be_bytes());
            let m = b.finish();
            nft_parse_register(&Attrs::parse(&m[crate::netlink::msg::HDRLEN..], 1), 1, len)
        };
        assert_eq!(reg(1, 16), Ok(R1));
        assert_eq!(reg(NFT_REG32_00, 4), Ok(R1));
        assert_eq!(reg(NFT_REG32_15, 4), Ok(NFT_REGS_LEN - 4));
        assert_eq!(reg(NFT_REG32_15, 8), Err(Errno::ERANGE));
        assert_eq!(reg(NFT_REG_VERDICT, 4), Err(Errno::EINVAL));
        assert_eq!(reg(1, 0), Err(Errno::EINVAL));
    }
}

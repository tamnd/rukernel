//! The objects of nf_tables and their netlink messages, as net/netfilter/nf_tables_api.c of
//! Linux.
//!
//! A namespace has tables. A table has chains and sets. A chain has rules, and a base chain
//! has a hook in the IPv4 or IPv6 path with a priority and a policy. A set has elements. A
//! program changes the objects with a batch of `NETLINK_NETFILTER` messages. The batch works on
//! a copy of the objects of the namespace, and the commit puts the copy in place, registers and
//! unregisters the hooks of the base chains, and increments the generation, all in one step. An
//! abort drops the copy. The dumps and the requests for one object read the committed objects.
//!
//! A rule keeps its expressions as the program sent them, for the dumps, and as the parsed
//! expressions of nf_tables_core.rs. At the commit each base chain gets the program of its
//! rules, and a packet runs it.

#[path = "nf_tables_core.rs"]
mod nf_tables_core;

use self::nf_tables_core::{
    NftExpr, NftProg, nf_tables_expr_parse, nft_check_loops, nft_do_chain, nft_prog,
};
use crate::buf::NetBuf;
use crate::netfilter::{
    NF_ACCEPT, NF_DROP, NF_INET_NUMHOOKS, NF_QUEUE, NFPROTO_ARP, NFPROTO_BRIDGE, NFPROTO_INET,
    NFPROTO_IPV4, NFPROTO_IPV6, NFPROTO_NETDEV, NFPROTO_UNSPEC, NfHookFn, NfHookOps, NfHookState,
    nf_register_net_hooks, nf_unregister_net_hook,
};
use crate::netlink::msg::{self, Attrs, Builder};
use crate::netlink::nfnetlink::{
    NFNETLINK_V0, NFNL_SUBSYS_NFTABLES, NFNLGRP_NFTABLES, NfnlBatch, NfnlCallback, NfnlCbType,
    NfnlInfo, NfnlSubsystem, Origin, nfnetlink_has_listeners, nfnetlink_send, nfnl_msg_put,
    nfnl_msg_type,
};
use crate::ns::PerNet;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::netlink::{
    NLM_F_APPEND, NLM_F_CREATE, NLM_F_ECHO, NLM_F_EXCL, NLM_F_MULTI, NLM_F_NONREC, NLM_F_REPLACE,
};
use rk_frame::sync::{SpinLock, SpinLockGuard};
use rk_vfs::inode::Result;

// The messages, `enum nf_tables_msg_types` of <linux/netfilter/nf_tables.h>. rk-abigen does
// not take this header yet, so the values are written by hand.
/// Makes or changes a table.
pub const NFT_MSG_NEWTABLE: u8 = 0;
/// Gets or dumps the tables.
pub const NFT_MSG_GETTABLE: u8 = 1;
/// Deletes a table.
pub const NFT_MSG_DELTABLE: u8 = 2;
/// Makes or changes a chain.
pub const NFT_MSG_NEWCHAIN: u8 = 3;
/// Gets or dumps the chains.
pub const NFT_MSG_GETCHAIN: u8 = 4;
/// Deletes a chain.
pub const NFT_MSG_DELCHAIN: u8 = 5;
/// Adds or replaces a rule.
pub const NFT_MSG_NEWRULE: u8 = 6;
/// Gets or dumps the rules.
pub const NFT_MSG_GETRULE: u8 = 7;
/// Deletes a rule.
pub const NFT_MSG_DELRULE: u8 = 8;
/// Makes a set.
pub const NFT_MSG_NEWSET: u8 = 9;
/// Gets or dumps the sets.
pub const NFT_MSG_GETSET: u8 = 10;
/// Deletes a set.
pub const NFT_MSG_DELSET: u8 = 11;
/// Adds elements to a set.
pub const NFT_MSG_NEWSETELEM: u8 = 12;
/// Gets or dumps the elements of a set.
pub const NFT_MSG_GETSETELEM: u8 = 13;
/// Deletes elements of a set.
pub const NFT_MSG_DELSETELEM: u8 = 14;
/// The notification of a new generation.
pub const NFT_MSG_NEWGEN: u8 = 15;
/// Gets the generation.
pub const NFT_MSG_GETGEN: u8 = 16;
/// Deletes a table, with no error if it is not there.
pub const NFT_MSG_DESTROYTABLE: u8 = 26;
/// Deletes a chain, with no error if it is not there.
pub const NFT_MSG_DESTROYCHAIN: u8 = 27;
/// Deletes a rule, with no error if it is not there.
pub const NFT_MSG_DESTROYRULE: u8 = 28;
/// Deletes a set, with no error if it is not there.
pub const NFT_MSG_DESTROYSET: u8 = 29;
/// Deletes elements, with no error if they are not there.
pub const NFT_MSG_DESTROYSETELEM: u8 = 30;
/// The number of messages, `NFT_MSG_MAX`.
const NFT_MSG_MAX: usize = 34;

/// The longest name of a table, a chain or a set with its NUL byte, `NFT_NAME_MAXLEN`.
const NFT_NAME_MAXLEN: usize = 256;
/// The longest user data, `NFT_USERDATA_MAXLEN`.
const NFT_USERDATA_MAXLEN: usize = 256;
/// The longest name of a chain type, `NFT_MODULE_AUTOLOAD_LIMIT`.
const NFT_MODULE_AUTOLOAD_LIMIT: usize = 64 - "nft-chain-255-".len();

// The attributes of a table, `NFTA_TABLE_*`.
const NFTA_TABLE_NAME: u32 = 1;
const NFTA_TABLE_FLAGS: u32 = 2;
const NFTA_TABLE_USE: u16 = 3;
const NFTA_TABLE_HANDLE: u32 = 4;
const NFTA_TABLE_USERDATA: u32 = 6;
const NFTA_TABLE_OWNER: u16 = 7;
const NFTA_TABLE_MAX: u16 = 7;

// The flags of a table, `enum nft_table_flags`.
/// The table has no hooks.
pub const NFT_TABLE_F_DORMANT: u32 = 0x1;
/// The table goes when the socket of its owner closes.
pub const NFT_TABLE_F_OWNER: u32 = 0x2;
/// The table stays when its owner goes, and has no owner then.
pub const NFT_TABLE_F_PERSIST: u32 = 0x4;
const NFT_TABLE_F_MASK: u32 = NFT_TABLE_F_DORMANT | NFT_TABLE_F_OWNER | NFT_TABLE_F_PERSIST;

// The attributes of a chain, `NFTA_CHAIN_*`.
const NFTA_CHAIN_TABLE: u32 = 1;
const NFTA_CHAIN_HANDLE: u32 = 2;
const NFTA_CHAIN_NAME: u32 = 3;
const NFTA_CHAIN_HOOK: u32 = 4;
const NFTA_CHAIN_POLICY: u32 = 5;
const NFTA_CHAIN_USE: u16 = 6;
const NFTA_CHAIN_TYPE: u32 = 7;
const NFTA_CHAIN_FLAGS: u32 = 10;
const NFTA_CHAIN_ID: u32 = 11;
const NFTA_CHAIN_USERDATA: u32 = 12;
const NFTA_CHAIN_MAX: u16 = 12;

// The flags of a chain, `enum nft_chain_flags`.
/// The chain has a hook.
pub const NFT_CHAIN_BASE: u32 = 1 << 0;
/// The hardware runs the chain.
pub const NFT_CHAIN_HW_OFFLOAD: u32 = 1 << 1;
/// The chain belongs to one rule.
pub const NFT_CHAIN_BINDING: u32 = 1 << 2;
const NFT_CHAIN_FLAGS: u32 = NFT_CHAIN_BASE | NFT_CHAIN_HW_OFFLOAD | NFT_CHAIN_BINDING;

// The attributes of the hook of a base chain, `NFTA_HOOK_*`.
const NFTA_HOOK_HOOKNUM: u32 = 1;
const NFTA_HOOK_PRIORITY: u32 = 2;
const NFTA_HOOK_MAX: u16 = 4;

// The attributes of a rule, `NFTA_RULE_*`.
const NFTA_RULE_TABLE: u32 = 1;
const NFTA_RULE_CHAIN: u32 = 2;
const NFTA_RULE_HANDLE: u32 = 3;
const NFTA_RULE_EXPRESSIONS: u32 = 4;
const NFTA_RULE_POSITION: u32 = 6;
const NFTA_RULE_USERDATA: u32 = 7;
const NFTA_RULE_ID: u32 = 9;
const NFTA_RULE_POSITION_ID: u32 = 10;
const NFTA_RULE_CHAIN_ID: u32 = 11;
const NFTA_RULE_MAX: u16 = 11;

// The attributes of a list, `NFTA_LIST_*`.
const NFTA_LIST_ELEM: u16 = 1;
/// The most expressions in one rule, `NFT_MAX_EXPRS`.
const NFT_MAX_EXPRS: usize = 128;

// The attributes of a set, `NFTA_SET_*`.
const NFTA_SET_TABLE: u32 = 1;
const NFTA_SET_NAME: u32 = 2;
const NFTA_SET_FLAGS: u32 = 3;
const NFTA_SET_KEY_TYPE: u32 = 4;
const NFTA_SET_KEY_LEN: u32 = 5;
const NFTA_SET_DATA_TYPE: u32 = 6;
const NFTA_SET_DATA_LEN: u32 = 7;
const NFTA_SET_POLICY: u32 = 8;
const NFTA_SET_DESC: u32 = 9;
const NFTA_SET_ID: u32 = 10;
const NFTA_SET_TIMEOUT: u32 = 11;
const NFTA_SET_GC_INTERVAL: u32 = 12;
const NFTA_SET_USERDATA: u32 = 13;
const NFTA_SET_OBJ_TYPE: u32 = 15;
const NFTA_SET_HANDLE: u32 = 16;
const NFTA_SET_EXPR: u32 = 17;
const NFTA_SET_EXPRESSIONS: u32 = 18;
const NFTA_SET_MAX: u16 = 18;

// The flags of a set, `enum nft_set_flags`.
/// The set has no name and goes with its rule.
pub const NFT_SET_ANONYMOUS: u32 = 0x1;
/// The elements do not change after the set is made.
pub const NFT_SET_CONSTANT: u32 = 0x2;
/// The elements are ranges.
pub const NFT_SET_INTERVAL: u32 = 0x4;
/// The set is a map, and each element has data.
pub const NFT_SET_MAP: u32 = 0x8;
/// The elements have a timeout.
pub const NFT_SET_TIMEOUT: u32 = 0x10;
/// The packet path adds elements.
pub const NFT_SET_EVAL: u32 = 0x20;
/// The set maps keys to stateful objects.
pub const NFT_SET_OBJECT: u32 = 0x40;
/// The key has more fields.
pub const NFT_SET_CONCAT: u32 = 0x80;
/// The elements have expressions.
pub const NFT_SET_EXPR: u32 = 0x100;

// The policies of a set, `enum nft_set_policies`.
const NFT_SET_POL_PERFORMANCE: u32 = 0;
const NFT_SET_POL_MEMORY: u32 = 1;

// The description of a set, `NFTA_SET_DESC_*` and `NFTA_SET_FIELD_*`.
const NFTA_SET_DESC_SIZE: u32 = 1;
const NFTA_SET_DESC_CONCAT: u32 = 2;
const NFTA_SET_FIELD_LEN: u32 = 1;
/// The most fields of a key, `NFT_REG32_COUNT`.
const NFT_REG32_COUNT: usize = 16;

// The attributes of a list of elements, `NFTA_SET_ELEM_LIST_*`.
const NFTA_SET_ELEM_LIST_TABLE: u32 = 1;
const NFTA_SET_ELEM_LIST_SET: u32 = 2;
const NFTA_SET_ELEM_LIST_ELEMENTS: u32 = 3;
const NFTA_SET_ELEM_LIST_SET_ID: u32 = 4;
const NFTA_SET_ELEM_LIST_MAX: u16 = 4;

// The attributes of an element, `NFTA_SET_ELEM_*`.
const NFTA_SET_ELEM_KEY: u32 = 1;
const NFTA_SET_ELEM_DATA: u32 = 2;
const NFTA_SET_ELEM_FLAGS: u32 = 3;
const NFTA_SET_ELEM_TIMEOUT: u32 = 4;
const NFTA_SET_ELEM_EXPIRATION: u32 = 5;
const NFTA_SET_ELEM_USERDATA: u32 = 6;
const NFTA_SET_ELEM_EXPR: u32 = 7;
const NFTA_SET_ELEM_OBJREF: u32 = 9;
const NFTA_SET_ELEM_KEY_END: u32 = 10;
const NFTA_SET_ELEM_EXPRESSIONS: u32 = 11;
const NFTA_SET_ELEM_MAX: u16 = 11;

// The flags of an element, `enum nft_set_elem_flags`.
/// The element ends a range.
pub const NFT_SET_ELEM_INTERVAL_END: u32 = 0x1;
/// The element matches each key.
pub const NFT_SET_ELEM_CATCHALL: u32 = 0x2;

// The data of an element, `NFTA_DATA_*` and `NFTA_VERDICT_*`.
const NFTA_DATA_VALUE: u32 = 1;
const NFTA_DATA_VERDICT: u32 = 2;
const NFTA_DATA_MAX: u16 = 2;
const NFTA_VERDICT_CODE: u32 = 1;
const NFTA_VERDICT_CHAIN: u32 = 2;
const NFTA_VERDICT_CHAIN_ID: u32 = 3;
const NFTA_VERDICT_MAX: u16 = 3;

// The verdicts of nf_tables, `enum nft_verdicts`.
/// Goes on with the next expression.
pub const NFT_CONTINUE: u32 = -1i32 as u32;
/// Stops the rule and goes on with the next rule.
pub const NFT_BREAK: u32 = -2i32 as u32;
/// Jumps to a chain and comes back.
pub const NFT_JUMP: u32 = -3i32 as u32;
/// Goes to a chain and does not come back.
pub const NFT_GOTO: u32 = -4i32 as u32;
/// Goes back to the chain of the last jump.
pub const NFT_RETURN: u32 = -5i32 as u32;

// The types of data, `enum nft_data_types`.
/// The data is a value.
pub const NFT_DATA_VALUE: u32 = 0;
/// The data is a verdict.
pub const NFT_DATA_VERDICT: u32 = 0xffff_ff00;
const NFT_DATA_RESERVED_MASK: u32 = 0xffff_ff00;
/// The longest value, `NFT_DATA_VALUE_MAXLEN`.
pub const NFT_DATA_VALUE_MAXLEN: u32 = 64;
/// The size of a verdict in a map, `sizeof(struct nft_verdict)`.
const NFT_VERDICT_LEN: u32 = 16;

// The attributes of a generation, `NFTA_GEN_*`.
const NFTA_GEN_ID: u16 = 1;
const NFTA_GEN_PROC_PID: u16 = 2;

/// The message type of the message `event` of nf_tables.
const fn nft_type(event: u8) -> u16 {
    (NFNL_SUBSYS_NFTABLES as u16) << 8 | event as u16
}

/// Tells if nf_tables takes the family, as `nft_supported_family` of Linux.
fn nft_supported_family(family: u8) -> bool {
    matches!(
        family,
        NFPROTO_INET | NFPROTO_IPV4 | NFPROTO_ARP | NFPROTO_NETDEV | NFPROTO_BRIDGE | NFPROTO_IPV6
    )
}

/// A type of base chain, as `struct nft_chain_type` of Linux.
#[derive(Debug, PartialEq, Eq)]
struct NftChainType {
    name: &'static str,
    /// The hooks that the type takes, one bit for each hook.
    hook_mask: u32,
}

/// The type `filter` of the families `ip`, `ip6` and `inet`, as nft_chain_filter.c of Linux.
/// The other families have no hooks here, and the types `nat` and `route` come later.
static NFT_CHAIN_FILTER: NftChainType = NftChainType { name: "filter", hook_mask: 0x1f };

static NFT_CHAIN_TYPES_INET: [&NftChainType; 1] = [&NFT_CHAIN_FILTER];

/// The types of the family `family`, as `chain_type[family]` of Linux.
fn nft_chain_types(family: u8) -> &'static [&'static NftChainType] {
    match family {
        NFPROTO_IPV4 | NFPROTO_IPV6 | NFPROTO_INET => &NFT_CHAIN_TYPES_INET,
        _ => &[],
    }
}

/// The data of an element of a map.
#[derive(Clone, Debug, PartialEq, Eq)]
enum NftData {
    /// A value.
    Value(Vec<u8>),
    /// A verdict, and the handle of the chain of `NFT_JUMP` and `NFT_GOTO`.
    Verdict { code: u32, chain: Option<u64> },
}

/// The key of an element. A catch-all element has no key, and the end of an interval has the
/// key of its end.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ElemKey {
    catchall: bool,
    key: Vec<u8>,
    end: bool,
}

/// An element of a set, as `struct nft_set_ext` of Linux.
#[derive(Clone, Debug)]
struct NftElem {
    key_end: Option<Vec<u8>>,
    data: Option<NftData>,
    flags: u32,
    udata: Option<Vec<u8>>,
}

/// A set, as `struct nft_set` of Linux.
#[derive(Clone, Debug)]
struct NftSet {
    name: Vec<u8>,
    handle: u64,
    flags: u32,
    ktype: u32,
    klen: u32,
    dtype: u32,
    dlen: u32,
    policy: u32,
    size: u32,
    field_len: Vec<u8>,
    udata: Option<Vec<u8>>,
    elems: BTreeMap<ElemKey, NftElem>,
    /// The ID in the batch that made the set, for `NFTA_SET_ELEM_LIST_SET_ID`.
    txn_id: Option<u32>,
}

impl NftSet {
    /// The type of the data of the elements, as `nft_set_datatype` of Linux.
    fn datatype(&self) -> u32 {
        if self.flags & NFT_SET_MAP != 0 { self.dtype } else { NFT_DATA_VALUE }
    }

    /// The number of elements that count for the size of the set.
    fn nelems(&self) -> usize {
        self.elems.keys().filter(|k| !k.catchall).count()
    }
}

/// A rule, as `struct nft_rule` of Linux. It keeps the payload of `NFTA_RULE_EXPRESSIONS`.
#[derive(Clone, Debug)]
struct NftRule {
    handle: u64,
    exprs: Vec<u8>,
    /// The expressions of `exprs`.
    parsed: Vec<NftExpr>,
    udata: Option<Vec<u8>>,
    /// The ID in the batch that made the rule, for `NFTA_RULE_POSITION_ID`.
    txn_id: Option<u32>,
}

/// The hook of a base chain, as `struct nft_base_chain` of Linux.
#[derive(Clone)]
struct NftBaseChain {
    hooknum: u8,
    priority: i32,
    ty: &'static NftChainType,
    policy: u32,
    /// The function in the hook list. It stays the same while the chain lives.
    ops: Arc<NftHookOps>,
}

/// A chain, as `struct nft_chain` of Linux.
#[derive(Clone)]
struct NftChain {
    name: Vec<u8>,
    handle: u64,
    flags: u32,
    udata: Option<Vec<u8>>,
    base: Option<NftBaseChain>,
    rules: Vec<NftRule>,
    /// The ID in the batch that made the chain, for `NFTA_RULE_CHAIN_ID`.
    txn_id: Option<u32>,
}

/// A table, as `struct nft_table` of Linux.
#[derive(Clone)]
struct NftTable {
    name: Vec<u8>,
    family: u8,
    flags: u32,
    handle: u64,
    udata: Option<Vec<u8>>,
    /// The port ID of the owner, as `table->nlpid`.
    nlpid: u32,
    chains: Vec<NftChain>,
    sets: Vec<NftSet>,
    /// The last handle of a chain, a rule or a set, as `table->hgenerator`.
    hgenerator: u64,
}

impl NftTable {
    /// The table has an owner, as `nft_table_has_owner` of Linux.
    fn has_owner(&self) -> bool {
        self.flags & NFT_TABLE_F_OWNER != 0
    }

    /// The number of objects in the table, as `table->use` of Linux.
    fn use_count(&self) -> u32 {
        (self.chains.len() + self.sets.len()) as u32
    }

    /// The number of rules and references of the chain `handle`, as `chain->use` of Linux.
    fn chain_use(&self, handle: u64) -> u32 {
        let rules = self.chains.iter().find(|c| c.handle == handle).map_or(0, |c| c.rules.len());
        let jumps = self
            .chains
            .iter()
            .flat_map(|c| c.rules.iter())
            .flat_map(|r| r.parsed.iter())
            .filter(|e| e.jump_target() == Some(handle))
            .count();
        let refs = self
            .sets
            .iter()
            .flat_map(|s| s.elems.values())
            .filter(
                |e| matches!(e.data, Some(NftData::Verdict { chain: Some(h), .. }) if h == handle),
            )
            .count();
        (rules + refs + jumps) as u32
    }

    /// The set `handle` has a rule that looks it up, as `set->use` of Linux.
    fn set_in_use(&self, handle: u64) -> bool {
        self.chains
            .iter()
            .flat_map(|c| c.rules.iter())
            .flat_map(|r| r.parsed.iter())
            .any(|e| matches!(e, NftExpr::Lookup { set, .. } if *set == handle))
    }

    /// A new handle, as `nf_tables_alloc_handle` of Linux.
    fn alloc_handle(&mut self) -> u64 {
        self.hgenerator += 1;
        self.hgenerator
    }

    fn chain_name(&self, handle: u64) -> &[u8] {
        self.chains.iter().find(|c| c.handle == handle).map_or(&[], |c| &c.name)
    }
}

/// The function of a base chain in the hook list, as `nft_do_chain` of Linux.
pub struct NftHookOps {
    /// The committed policy of the chain. A packet reads it without a lock.
    policy: AtomicU32,
    /// The committed program of the chain. A packet holds the lock only to take a reference.
    prog: SpinLock<Arc<NftProg>>,
}

impl NftHookOps {
    fn new(policy: u32) -> Self {
        Self { policy: AtomicU32::new(policy), prog: SpinLock::new(Arc::new(NftProg::default())) }
    }
}

impl NfHookFn for NftHookOps {
    /// Runs the rules of the chain on `skb`. At the end of the chain the packet gets the
    /// policy of the chain.
    fn hook(&self, skb: &mut NetBuf, state: &NfHookState) -> u32 {
        let prog = self.prog.lock().clone();
        nft_do_chain(&prog, self.policy.load(Ordering::Acquire), skb, state)
    }
}

/// The state of nf_tables in a namespace, as `struct nftables_pernet` of Linux.
struct NftablesPernet {
    /// The generation, as `base_seq`. It is never 0.
    base_seq: u32,
    /// The last handle of a table.
    table_handle: u64,
    tables: Vec<NftTable>,
    /// The hooks in the hook lists of the namespace.
    hooks: Vec<NfHookOps>,
}

impl Default for NftablesPernet {
    fn default() -> Self {
        Self { base_seq: 1, table_handle: 0, tables: Vec::new(), hooks: Vec::new() }
    }
}

static NFT: PerNet<SpinLock<NftablesPernet>> =
    PerNet::new(|| SpinLock::new(NftablesPernet::default()));

/// The handlers of nf_tables, as `nf_tables_cb` of Linux.
static NF_TABLES_CB: [NfnlCallback; NFT_MSG_MAX] = {
    const fn batch(attr_count: u16) -> NfnlCallback {
        NfnlCallback { call: None, dump: None, kind: NfnlCbType::Batch, attr_count }
    }
    const fn rcu(
        call: Option<crate::netlink::nfnetlink::NfnlCall>,
        dump: Option<crate::netlink::nfnetlink::NfnlDump>,
        attr_count: u16,
    ) -> NfnlCallback {
        NfnlCallback { call, dump, kind: NfnlCbType::Rcu, attr_count }
    }
    let none = NfnlCallback { call: None, dump: None, kind: NfnlCbType::Unspec, attr_count: 0 };
    let mut cb = [none; NFT_MSG_MAX];
    cb[NFT_MSG_NEWTABLE as usize] = batch(NFTA_TABLE_MAX);
    cb[NFT_MSG_GETTABLE as usize] =
        rcu(Some(nf_tables_gettable), Some(nf_tables_dump_tables), NFTA_TABLE_MAX);
    cb[NFT_MSG_DELTABLE as usize] = batch(NFTA_TABLE_MAX);
    cb[NFT_MSG_DESTROYTABLE as usize] = batch(NFTA_TABLE_MAX);
    cb[NFT_MSG_NEWCHAIN as usize] = batch(NFTA_CHAIN_MAX);
    cb[NFT_MSG_GETCHAIN as usize] =
        rcu(Some(nf_tables_getchain), Some(nf_tables_dump_chains), NFTA_CHAIN_MAX);
    cb[NFT_MSG_DELCHAIN as usize] = batch(NFTA_CHAIN_MAX);
    cb[NFT_MSG_DESTROYCHAIN as usize] = batch(NFTA_CHAIN_MAX);
    cb[NFT_MSG_NEWRULE as usize] = batch(NFTA_RULE_MAX);
    cb[NFT_MSG_GETRULE as usize] =
        rcu(Some(nf_tables_getrule), Some(nf_tables_dump_rules), NFTA_RULE_MAX);
    cb[NFT_MSG_DELRULE as usize] = batch(NFTA_RULE_MAX);
    cb[NFT_MSG_DESTROYRULE as usize] = batch(NFTA_RULE_MAX);
    cb[NFT_MSG_NEWSET as usize] = batch(NFTA_SET_MAX);
    cb[NFT_MSG_GETSET as usize] =
        rcu(Some(nf_tables_getset), Some(nf_tables_dump_sets), NFTA_SET_MAX);
    cb[NFT_MSG_DELSET as usize] = batch(NFTA_SET_MAX);
    cb[NFT_MSG_DESTROYSET as usize] = batch(NFTA_SET_MAX);
    cb[NFT_MSG_NEWSETELEM as usize] = batch(NFTA_SET_ELEM_LIST_MAX);
    cb[NFT_MSG_GETSETELEM as usize] =
        rcu(Some(nf_tables_getsetelem), Some(nf_tables_dump_set), NFTA_SET_ELEM_LIST_MAX);
    cb[NFT_MSG_DELSETELEM as usize] = batch(NFTA_SET_ELEM_LIST_MAX);
    cb[NFT_MSG_DESTROYSETELEM as usize] = batch(NFTA_SET_ELEM_LIST_MAX);
    cb[NFT_MSG_GETGEN as usize] = rcu(Some(nf_tables_getgen), None, 0);
    cb
};

/// The subsystem nf_tables, as `nf_tables_subsys` of Linux.
pub static NF_TABLES_SUBSYS: NfnlSubsystem = NfnlSubsystem {
    name: "nf_tables",
    subsys_id: NFNL_SUBSYS_NFTABLES,
    cb: &NF_TABLES_CB,
    begin: Some(nf_tables_begin),
};

// The attributes, with the checks of the policies of Linux. A short number gives `ERANGE`, as
// the check of `NLA_U32` and `NLA_BE64`.

fn be32(a: &Attrs<'_>, ty: u32) -> Result<Option<u32>> {
    a.get(ty)
        .map(|d| d.first_chunk::<4>().map(|v| u32::from_be_bytes(*v)).ok_or(Errno::ERANGE))
        .transpose()
}

fn be64(a: &Attrs<'_>, ty: u32) -> Result<Option<u64>> {
    a.get(ty)
        .map(|d| d.first_chunk::<8>().map(|v| u64::from_be_bytes(*v)).ok_or(Errno::ERANGE))
        .transpose()
}

/// A string of at most `max` bytes, as `NLA_STRING` with a length. Gives the bytes up to the
/// first NUL byte.
fn nla_string<'a>(a: &Attrs<'a>, ty: u32, max: usize) -> Result<Option<&'a [u8]>> {
    let Some(d) = a.get(ty) else { return Ok(None) };
    let len = if d.last() == Some(&0) { d.len() - 1 } else { d.len() };
    if len > max {
        return Err(Errno::ERANGE);
    }
    Ok(Some(d.split(|&c| c == 0).next().unwrap_or(d)))
}

/// A name of a table, a chain or a set.
fn nla_name<'a>(a: &Attrs<'a>, ty: u32) -> Result<Option<&'a [u8]>> {
    nla_string(a, ty, NFT_NAME_MAXLEN - 1)
}

/// User data of at most `NFT_USERDATA_MAXLEN` bytes, as `NLA_BINARY`.
fn nla_udata(a: &Attrs<'_>, ty: u32) -> Result<Option<Vec<u8>>> {
    match a.get(ty) {
        Some(d) if d.len() > NFT_USERDATA_MAXLEN => Err(Errno::ERANGE),
        Some(d) => Ok(Some(d.to_vec())),
        None => Ok(None),
    }
}

/// The context of a change, as `struct nft_ctx` of Linux.
#[derive(Clone, Copy)]
struct NftCtx {
    family: u8,
    portid: u32,
    seq: u32,
    flags: u16,
    report: bool,
    ty: u8,
}

impl NftCtx {
    fn new(info: &NfnlInfo<'_>) -> Self {
        Self {
            family: info.nfmsg.nfgen_family,
            portid: info.req.portid,
            seq: info.nlh.seq,
            flags: info.nlh.flags,
            report: info.nlh.flags & NLM_F_ECHO as u16 != 0,
            ty: nfnl_msg_type(info.nlh.ty),
        }
    }

    fn has(&self, flag: u32) -> bool {
        self.flags & flag as u16 != 0
    }

    /// The flags of a notice, `ctx->flags & (NLM_F_CREATE | NLM_F_EXCL)`.
    fn notify_flags(&self) -> u16 {
        self.flags & (NLM_F_CREATE | NLM_F_EXCL) as u16
    }
}

/// Finds the table `name` of `family`, as `nft_table_lookup` of Linux. A table with another
/// owner gives `EPERM` to a request that has a port ID.
fn nft_table_lookup(
    tables: &[NftTable],
    name: Option<&[u8]>,
    family: u8,
    nlpid: u32,
) -> Result<usize> {
    let Some(name) = name else { return Err(Errno::EINVAL) };
    let at =
        tables.iter().position(|t| t.name == name && t.family == family).ok_or(Errno::ENOENT)?;
    let t = &tables[at];
    if t.has_owner() && nlpid != 0 && t.nlpid != nlpid {
        return Err(Errno::EPERM);
    }
    Ok(at)
}

/// Finds the table with the handle `handle`, as `nft_table_lookup_byhandle` of Linux.
fn nft_table_lookup_byhandle(
    tables: &[NftTable],
    handle: u64,
    family: u8,
    nlpid: u32,
) -> Result<usize> {
    let at = tables
        .iter()
        .position(|t| t.handle == handle && t.family == family)
        .ok_or(Errno::ENOENT)?;
    let t = &tables[at];
    if t.has_owner() && nlpid != 0 && t.nlpid != nlpid {
        return Err(Errno::EPERM);
    }
    Ok(at)
}

/// Finds the chain `name`, as `nft_chain_lookup` of Linux.
fn nft_chain_lookup(table: &NftTable, name: Option<&[u8]>) -> Result<usize> {
    let Some(name) = name else { return Err(Errno::EINVAL) };
    table.chains.iter().position(|c| c.name == name).ok_or(Errno::ENOENT)
}

fn nft_chain_lookup_byhandle(table: &NftTable, handle: u64) -> Result<usize> {
    table.chains.iter().position(|c| c.handle == handle).ok_or(Errno::ENOENT)
}

/// Finds a chain that the batch made, as `nft_chain_lookup_byid` of Linux.
fn nft_chain_lookup_byid(table: &NftTable, id: u32) -> Result<usize> {
    table.chains.iter().position(|c| c.txn_id == Some(id)).ok_or(Errno::ENOENT)
}

fn nft_set_lookup(table: &NftTable, name: Option<&[u8]>) -> Result<usize> {
    let Some(name) = name else { return Err(Errno::EINVAL) };
    table.sets.iter().position(|s| s.name == name).ok_or(Errno::ENOENT)
}

/// Finds a set by its name, or by the ID of the batch that made it, as
/// `nft_set_lookup_global` of Linux.
fn nft_set_lookup_global(table: &NftTable, name: Option<&[u8]>, id: Option<u32>) -> Result<usize> {
    match nft_set_lookup(table, name) {
        Err(e) => match id {
            Some(id) => table.sets.iter().position(|s| s.txn_id == Some(id)).ok_or(Errno::ENOENT),
            None => Err(e),
        },
        ok => ok,
    }
}

fn nft_rule_lookup(chain: &NftChain, handle: u64) -> Result<usize> {
    chain.rules.iter().position(|r| r.handle == handle).ok_or(Errno::ENOENT)
}

// The messages of the objects.

fn nf_tables_fill_table_info(
    portid: u32,
    seq: u32,
    event: u8,
    flags: u16,
    base_seq: u32,
    table: &NftTable,
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
    b.put(NFTA_TABLE_NAME as u16, &cstr(&table.name))
        .put(NFTA_TABLE_FLAGS as u16, &(table.flags & NFT_TABLE_F_MASK).to_be_bytes())
        .put(NFTA_TABLE_USE, &table.use_count().to_be_bytes())
        .put(NFTA_TABLE_HANDLE as u16, &table.handle.to_be_bytes());
    if event == NFT_MSG_DELTABLE || event == NFT_MSG_DESTROYTABLE {
        return b.finish();
    }
    if table.has_owner() {
        b.put(NFTA_TABLE_OWNER, &table.nlpid.to_be_bytes());
    }
    if let Some(u) = &table.udata {
        b.put(NFTA_TABLE_USERDATA as u16, u);
    }
    b.finish()
}

fn nf_tables_fill_chain_info(
    portid: u32,
    seq: u32,
    event: u8,
    flags: u16,
    base_seq: u32,
    table: &NftTable,
    chain: &NftChain,
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
    b.put(NFTA_CHAIN_TABLE as u16, &cstr(&table.name))
        .put(NFTA_CHAIN_HANDLE as u16, &chain.handle.to_be_bytes())
        .put(NFTA_CHAIN_NAME as u16, &cstr(&chain.name));
    if event == NFT_MSG_DELCHAIN || event == NFT_MSG_DESTROYCHAIN {
        return b.finish();
    }
    if let Some(base) = &chain.base {
        let nest = b.nest(NFTA_CHAIN_HOOK as u16);
        b.put(NFTA_HOOK_HOOKNUM as u16, &u32::from(base.hooknum).to_be_bytes())
            .put(NFTA_HOOK_PRIORITY as u16, &base.priority.to_be_bytes());
        b.end_nest(nest);
        b.put(NFTA_CHAIN_POLICY as u16, &base.policy.to_be_bytes());
        b.put(NFTA_CHAIN_TYPE as u16, &cstr(base.ty.name.as_bytes()));
    }
    if chain.flags != 0 {
        b.put(NFTA_CHAIN_FLAGS as u16, &chain.flags.to_be_bytes());
    }
    b.put(NFTA_CHAIN_USE, &table.chain_use(chain.handle).to_be_bytes());
    if let Some(u) = &chain.udata {
        b.put(NFTA_CHAIN_USERDATA as u16, u);
    }
    b.finish()
}

#[allow(clippy::too_many_arguments)]
fn nf_tables_fill_rule_info(
    portid: u32,
    seq: u32,
    event: u8,
    flags: u16,
    base_seq: u32,
    table: &NftTable,
    chain: &NftChain,
    rule: &NftRule,
    prev: u64,
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
    b.put(NFTA_RULE_TABLE as u16, &cstr(&table.name))
        .put(NFTA_RULE_CHAIN as u16, &cstr(&chain.name))
        .put(NFTA_RULE_HANDLE as u16, &rule.handle.to_be_bytes());
    if event != NFT_MSG_DELRULE && event != NFT_MSG_DESTROYRULE && prev != 0 {
        b.put(NFTA_RULE_POSITION as u16, &prev.to_be_bytes());
    }
    b.put(NFTA_RULE_EXPRESSIONS as u16, &rule.exprs);
    if let Some(u) = &rule.udata {
        b.put(NFTA_RULE_USERDATA as u16, u);
    }
    b.finish()
}

fn nf_tables_fill_set(
    portid: u32,
    seq: u32,
    event: u8,
    flags: u16,
    base_seq: u32,
    table: &NftTable,
    set: &NftSet,
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
    b.put(NFTA_SET_TABLE as u16, &cstr(&table.name))
        .put(NFTA_SET_NAME as u16, &cstr(&set.name))
        .put(NFTA_SET_HANDLE as u16, &set.handle.to_be_bytes());
    if event == NFT_MSG_DELSET || event == NFT_MSG_DESTROYSET {
        return b.finish();
    }
    if set.flags != 0 {
        b.put(NFTA_SET_FLAGS as u16, &set.flags.to_be_bytes());
    }
    b.put(NFTA_SET_KEY_TYPE as u16, &set.ktype.to_be_bytes())
        .put(NFTA_SET_KEY_LEN as u16, &set.klen.to_be_bytes());
    if set.flags & NFT_SET_MAP != 0 {
        b.put(NFTA_SET_DATA_TYPE as u16, &set.dtype.to_be_bytes())
            .put(NFTA_SET_DATA_LEN as u16, &set.dlen.to_be_bytes());
    }
    if set.policy != NFT_SET_POL_PERFORMANCE {
        b.put(NFTA_SET_POLICY as u16, &set.policy.to_be_bytes());
    }
    if let Some(u) = &set.udata {
        b.put(NFTA_SET_USERDATA as u16, u);
    }
    let nest = b.nest(NFTA_SET_DESC as u16);
    if set.size != 0 {
        b.put(NFTA_SET_DESC_SIZE as u16, &set.size.to_be_bytes());
    }
    if set.field_len.len() > 1 {
        let concat = b.nest(NFTA_SET_DESC_CONCAT as u16);
        for &len in &set.field_len {
            let elem = b.nest(NFTA_LIST_ELEM);
            b.put(NFTA_SET_FIELD_LEN as u16, &u32::from(len).to_be_bytes());
            b.end_nest(elem);
        }
        b.end_nest(concat);
    }
    b.end_nest(nest);
    b.finish()
}

/// Adds the data `data` in the attribute `attr`, as `nft_data_dump` of Linux.
fn nft_data_dump(b: &mut Builder, attr: u32, data: &NftData, table: &NftTable) {
    let nest = b.nest(attr as u16);
    match data {
        NftData::Value(v) => {
            b.put(NFTA_DATA_VALUE as u16, v);
        }
        NftData::Verdict { code, chain } => {
            let v = b.nest(NFTA_DATA_VERDICT as u16);
            b.put(NFTA_VERDICT_CODE as u16, &code.to_be_bytes());
            if let Some(h) = chain {
                b.put(NFTA_VERDICT_CHAIN as u16, &cstr(table.chain_name(*h)));
            }
            b.end_nest(v);
        }
    }
    b.end_nest(nest);
}

/// Adds one element in a list, as `nf_tables_fill_setelem` of Linux.
fn nf_tables_fill_setelem(b: &mut Builder, table: &NftTable, key: &ElemKey, elem: &NftElem) {
    let nest = b.nest(NFTA_LIST_ELEM);
    if !key.catchall {
        nft_data_dump(b, NFTA_SET_ELEM_KEY, &NftData::Value(key.key.clone()), table);
    }
    if let Some(k) = &elem.key_end {
        nft_data_dump(b, NFTA_SET_ELEM_KEY_END, &NftData::Value(k.clone()), table);
    }
    if let Some(d) = &elem.data {
        nft_data_dump(b, NFTA_SET_ELEM_DATA, d, table);
    }
    if elem.flags != 0 {
        b.put(NFTA_SET_ELEM_FLAGS as u16, &elem.flags.to_be_bytes());
    }
    if let Some(u) = &elem.udata {
        b.put(NFTA_SET_ELEM_USERDATA as u16, u);
    }
    b.end_nest(nest);
}

/// A message with the elements `elems` of `set`.
#[allow(clippy::too_many_arguments)]
fn nf_tables_fill_setelem_info(
    portid: u32,
    seq: u32,
    event: u8,
    flags: u16,
    base_seq: u32,
    table: &NftTable,
    set: &NftSet,
    elems: &[(&ElemKey, &NftElem)],
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
    b.put(NFTA_SET_ELEM_LIST_TABLE as u16, &cstr(&table.name))
        .put(NFTA_SET_ELEM_LIST_SET as u16, &cstr(&set.name));
    let nest = b.nest(NFTA_SET_ELEM_LIST_ELEMENTS as u16);
    for (k, e) in elems {
        nf_tables_fill_setelem(&mut b, table, k, e);
    }
    b.end_nest(nest);
    b.finish()
}

/// The message with the generation, as `nf_tables_fill_gen_info` of Linux.
fn nf_tables_fill_gen_info(portid: u32, seq: u32, base_seq: u32) -> Vec<u8> {
    let mut b = nfnl_msg_put(
        portid,
        seq,
        nft_type(NFT_MSG_NEWGEN),
        0,
        NFPROTO_UNSPEC,
        NFNETLINK_V0,
        base_seq as u16,
    );
    b.put(NFTA_GEN_ID, &base_seq.to_be_bytes())
        .put(NFTA_GEN_PROC_PID, &(crate::current_cred().pid as u32).to_be_bytes());
    b.finish()
}

/// A name with its NUL byte.
fn cstr(s: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() + 1);
    v.extend_from_slice(s);
    v.push(0);
    v
}

// The requests that read the committed objects.

fn nf_tables_gettable(info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<()> {
    let nft = NFT.lock();
    let family = info.nfmsg.nfgen_family;
    let name = nla_name(nla, NFTA_TABLE_NAME)?;
    let at = nft_table_lookup(&nft.tables, name, family, 0)
        .map_err(|e| bad(info, nla, NFTA_TABLE_NAME, e))?;
    let m = nf_tables_fill_table_info(
        info.req.portid,
        info.nlh.seq,
        NFT_MSG_NEWTABLE,
        0,
        nft.base_seq,
        &nft.tables[at],
    );
    drop(nft);
    info.req.reply(m);
    Ok(())
}

/// Sets the bad attribute `ty` of the extended ack and gives `e`.
fn bad(info: &NfnlInfo<'_>, nla: &Attrs<'_>, ty: u32, e: Errno) -> Errno {
    if let Some(d) = nla.get(ty) {
        info.req.bad_attr(d);
    }
    e
}

fn family_match(family: u8, table: &NftTable) -> bool {
    family == NFPROTO_UNSPEC || family == table.family
}

fn nf_tables_dump_tables(info: &NfnlInfo<'_>, _nla: &Attrs<'_>) -> Result<Vec<Vec<u8>>> {
    let nft = NFT.lock();
    let family = info.nfmsg.nfgen_family;
    Ok(nft
        .tables
        .iter()
        .filter(|t| family_match(family, t))
        .map(|t| {
            nf_tables_fill_table_info(
                info.req.portid,
                info.nlh.seq,
                NFT_MSG_NEWTABLE,
                NLM_F_MULTI as u16,
                nft.base_seq,
                t,
            )
        })
        .collect())
}

fn nf_tables_getchain(info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<()> {
    let nft = NFT.lock();
    let family = info.nfmsg.nfgen_family;
    let t = nft_table_lookup(&nft.tables, nla_name(nla, NFTA_CHAIN_TABLE)?, family, 0)
        .map_err(|e| bad(info, nla, NFTA_CHAIN_TABLE, e))?;
    let table = &nft.tables[t];
    let c = nft_chain_lookup(table, nla_name(nla, NFTA_CHAIN_NAME)?)
        .map_err(|e| bad(info, nla, NFTA_CHAIN_NAME, e))?;
    let m = nf_tables_fill_chain_info(
        info.req.portid,
        info.nlh.seq,
        NFT_MSG_NEWCHAIN,
        0,
        nft.base_seq,
        table,
        &table.chains[c],
    );
    drop(nft);
    info.req.reply(m);
    Ok(())
}

fn nf_tables_dump_chains(info: &NfnlInfo<'_>, _nla: &Attrs<'_>) -> Result<Vec<Vec<u8>>> {
    let nft = NFT.lock();
    let family = info.nfmsg.nfgen_family;
    let mut out = Vec::new();
    for t in nft.tables.iter().filter(|t| family_match(family, t)) {
        for c in &t.chains {
            out.push(nf_tables_fill_chain_info(
                info.req.portid,
                info.nlh.seq,
                NFT_MSG_NEWCHAIN,
                NLM_F_MULTI as u16,
                nft.base_seq,
                t,
                c,
            ));
        }
    }
    Ok(out)
}

fn nf_tables_getrule(info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<()> {
    let nft = NFT.lock();
    let family = info.nfmsg.nfgen_family;
    let t = nft_table_lookup(&nft.tables, nla_name(nla, NFTA_RULE_TABLE)?, family, 0)
        .map_err(|e| bad(info, nla, NFTA_RULE_TABLE, e))?;
    let table = &nft.tables[t];
    let c = nft_chain_lookup(table, nla_name(nla, NFTA_RULE_CHAIN)?)
        .map_err(|e| bad(info, nla, NFTA_RULE_CHAIN, e))?;
    let chain = &table.chains[c];
    let Some(handle) = be64(nla, NFTA_RULE_HANDLE)? else { return Err(Errno::EINVAL) };
    let r = nft_rule_lookup(chain, handle).map_err(|e| bad(info, nla, NFTA_RULE_HANDLE, e))?;
    let m = nf_tables_fill_rule_info(
        info.req.portid,
        info.nlh.seq,
        NFT_MSG_NEWRULE,
        0,
        nft.base_seq,
        table,
        chain,
        &chain.rules[r],
        0,
    );
    drop(nft);
    info.req.reply(m);
    Ok(())
}

/// The dump of the rules, as `nf_tables_dump_rules` of Linux. `NFTA_RULE_TABLE` and
/// `NFTA_RULE_CHAIN` limit the dump to one table and one chain.
fn nf_tables_dump_rules(info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<Vec<Vec<u8>>> {
    let table_name = nla_name(nla, NFTA_RULE_TABLE)?;
    let chain_name = nla_name(nla, NFTA_RULE_CHAIN)?;
    let nft = NFT.lock();
    let family = info.nfmsg.nfgen_family;
    let mut out = Vec::new();
    for t in nft.tables.iter().filter(|t| family_match(family, t)) {
        if table_name.is_some_and(|n| n != t.name) {
            continue;
        }
        for c in &t.chains {
            if chain_name.is_some_and(|n| n != c.name) {
                continue;
            }
            let mut prev = 0;
            for r in &c.rules {
                out.push(nf_tables_fill_rule_info(
                    info.req.portid,
                    info.nlh.seq,
                    NFT_MSG_NEWRULE,
                    (NLM_F_MULTI | NLM_F_APPEND) as u16,
                    nft.base_seq,
                    t,
                    c,
                    r,
                    prev,
                ));
                prev = r.handle;
            }
        }
    }
    Ok(out)
}

fn nf_tables_getset(info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<()> {
    let family = info.nfmsg.nfgen_family;
    // A request for one set needs a family.
    if family == NFPROTO_UNSPEC {
        return Err(Errno::EAFNOSUPPORT);
    }
    let nft = NFT.lock();
    let t = nft_table_lookup(&nft.tables, nla_name(nla, NFTA_SET_TABLE)?, family, 0)
        .map_err(|e| bad(info, nla, NFTA_SET_TABLE, e))?;
    let table = &nft.tables[t];
    let s = nft_set_lookup(table, nla_name(nla, NFTA_SET_NAME)?)?;
    let m = nf_tables_fill_set(
        info.req.portid,
        info.nlh.seq,
        NFT_MSG_NEWSET,
        0,
        nft.base_seq,
        table,
        &table.sets[s],
    );
    drop(nft);
    info.req.reply(m);
    Ok(())
}

fn nf_tables_dump_sets(info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<Vec<Vec<u8>>> {
    let table_name = nla_name(nla, NFTA_SET_TABLE)?;
    let nft = NFT.lock();
    let family = info.nfmsg.nfgen_family;
    let mut out = Vec::new();
    for t in nft.tables.iter().filter(|t| family_match(family, t)) {
        if table_name.is_some_and(|n| n != t.name) {
            continue;
        }
        for s in &t.sets {
            out.push(nf_tables_fill_set(
                info.req.portid,
                info.nlh.seq,
                NFT_MSG_NEWSET,
                NLM_F_MULTI as u16,
                nft.base_seq,
                t,
                s,
            ));
        }
    }
    Ok(out)
}

/// The size of the elements in one message of a dump, near `NLMSG_GOODSIZE`.
const ELEM_DUMP_SIZE: usize = 3000;

/// The dump of the elements of one set, as `nf_tables_dump_set` of Linux. The elements go in
/// as many messages as they need.
fn nf_tables_dump_set(info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<Vec<Vec<u8>>> {
    let family = info.nfmsg.nfgen_family;
    let nft = NFT.lock();
    let t = nft_table_lookup(&nft.tables, nla_name(nla, NFTA_SET_ELEM_LIST_TABLE)?, family, 0)?;
    let table = &nft.tables[t];
    let s = nft_set_lookup(table, nla_name(nla, NFTA_SET_ELEM_LIST_SET)?)?;
    let set = &table.sets[s];
    let mut out = Vec::new();
    let mut part: Vec<(&ElemKey, &NftElem)> = Vec::new();
    let mut size = 0;
    for (k, e) in &set.elems {
        let len = k.key.len() + e.key_end.as_ref().map_or(0, Vec::len) + 64;
        if !part.is_empty() && size + len > ELEM_DUMP_SIZE {
            out.push(nf_tables_fill_setelem_info(
                info.req.portid,
                info.nlh.seq,
                NFT_MSG_NEWSETELEM,
                NLM_F_MULTI as u16,
                nft.base_seq,
                table,
                set,
                &part,
            ));
            part.clear();
            size = 0;
        }
        part.push((k, e));
        size += len;
    }
    if !part.is_empty() {
        out.push(nf_tables_fill_setelem_info(
            info.req.portid,
            info.nlh.seq,
            NFT_MSG_NEWSETELEM,
            NLM_F_MULTI as u16,
            nft.base_seq,
            table,
            set,
            &part,
        ));
    }
    Ok(out)
}

/// Gets the elements of the list, as `nf_tables_getsetelem` of Linux. Each element comes in a
/// message of its own.
fn nf_tables_getsetelem(info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<()> {
    let family = info.nfmsg.nfgen_family;
    let nft = NFT.lock();
    let t = nft_table_lookup(&nft.tables, nla_name(nla, NFTA_SET_ELEM_LIST_TABLE)?, family, 0)
        .map_err(|e| bad(info, nla, NFTA_SET_ELEM_LIST_TABLE, e))?;
    let table = &nft.tables[t];
    let s = nft_set_lookup(table, nla_name(nla, NFTA_SET_ELEM_LIST_SET)?)
        .map_err(|e| bad(info, nla, NFTA_SET_ELEM_LIST_SET, e))?;
    let set = &table.sets[s];
    let Some(list) = nla.get(NFTA_SET_ELEM_LIST_ELEMENTS) else { return Err(Errno::EINVAL) };
    let mut replies = Vec::new();
    for (_, attr) in msg::attrs(list) {
        let ea = Attrs::parse(attr, NFTA_SET_ELEM_MAX);
        let flags = nft_setelem_parse_flags(set, &ea)?;
        let key =
            nft_setelem_parse_elemkey(set, &ea, flags).inspect_err(|_| info.req.bad_attr(attr))?;
        let Some((k, e)) = set.elems.get_key_value(&key) else {
            info.req.bad_attr(attr);
            return Err(Errno::ENOENT);
        };
        replies.push(nf_tables_fill_setelem_info(
            info.req.portid,
            info.nlh.seq,
            NFT_MSG_NEWSETELEM,
            0,
            nft.base_seq,
            table,
            set,
            &[(k, e)],
        ));
    }
    drop(nft);
    for m in replies {
        info.req.reply(m);
    }
    Ok(())
}

fn nf_tables_getgen(info: &NfnlInfo<'_>, _nla: &Attrs<'_>) -> Result<()> {
    let base_seq = NFT.lock().base_seq;
    info.req.reply(nf_tables_fill_gen_info(info.req.portid, info.nlh.seq, base_seq));
    Ok(())
}

// The elements.

/// Reads the flags of an element, as `nft_setelem_parse_flags` of Linux.
fn nft_setelem_parse_flags(set: &NftSet, ea: &Attrs<'_>) -> Result<u32> {
    let flags = be32(ea, NFTA_SET_ELEM_FLAGS)?.unwrap_or(0);
    if flags & !(NFT_SET_ELEM_INTERVAL_END | NFT_SET_ELEM_CATCHALL) != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if set.flags & NFT_SET_INTERVAL == 0 && flags & NFT_SET_ELEM_INTERVAL_END != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & (NFT_SET_ELEM_INTERVAL_END | NFT_SET_ELEM_CATCHALL)
        == NFT_SET_ELEM_INTERVAL_END | NFT_SET_ELEM_CATCHALL
    {
        return Err(Errno::EINVAL);
    }
    Ok(flags)
}

/// Reads a value of `len` bytes in the attribute `nla`, as `nft_value_init` of Linux.
fn nft_value_init(nla: &[u8], len: u32) -> Result<Vec<u8>> {
    let tb = Attrs::parse(nla, NFTA_DATA_MAX);
    if tb.has(NFTA_DATA_VERDICT) && !tb.has(NFTA_DATA_VALUE) {
        return Err(Errno::EINVAL);
    }
    let Some(v) = tb.get(NFTA_DATA_VALUE) else { return Err(Errno::EINVAL) };
    if v.is_empty() {
        return Err(Errno::EINVAL);
    }
    if v.len() > NFT_DATA_VALUE_MAXLEN as usize {
        return Err(Errno::EOVERFLOW);
    }
    if v.len() != len as usize {
        return Err(Errno::EINVAL);
    }
    Ok(v.to_vec())
}

/// Reads the key of an element, as `nft_setelem_parse_key` of Linux.
fn nft_setelem_parse_elemkey(set: &NftSet, ea: &Attrs<'_>, flags: u32) -> Result<ElemKey> {
    let catchall = flags & NFT_SET_ELEM_CATCHALL != 0;
    let key = match (catchall, ea.get(NFTA_SET_ELEM_KEY)) {
        (true, None) => Vec::new(),
        (false, Some(k)) => nft_value_init(k, set.klen)?,
        _ => return Err(Errno::EINVAL),
    };
    Ok(ElemKey { catchall, key, end: flags & NFT_SET_ELEM_INTERVAL_END != 0 })
}

/// Reads a verdict, as `nft_verdict_init` of Linux. A jump goes to a chain of `table` that is
/// not a base chain.
fn nft_verdict_init(table: &NftTable, nla: &[u8]) -> Result<NftData> {
    let tb = Attrs::parse(nla, NFTA_VERDICT_MAX);
    let Some(code) = be32(&tb, NFTA_VERDICT_CODE)? else { return Err(Errno::EINVAL) };
    let chain = match code {
        NF_ACCEPT | NF_DROP | NF_QUEUE | NFT_CONTINUE | NFT_BREAK | NFT_RETURN => None,
        NFT_JUMP | NFT_GOTO => {
            let at = if let Some(name) = nla_name(&tb, NFTA_VERDICT_CHAIN)? {
                nft_chain_lookup(table, Some(name))?
            } else if let Some(id) = be32(&tb, NFTA_VERDICT_CHAIN_ID)? {
                nft_chain_lookup_byid(table, id)?
            } else {
                return Err(Errno::EINVAL);
            };
            let chain = &table.chains[at];
            if chain.base.is_some() {
                return Err(Errno::EOPNOTSUPP);
            }
            if chain.flags & NFT_CHAIN_BINDING != 0 {
                return Err(Errno::EINVAL);
            }
            Some(chain.handle)
        }
        _ => return Err(Errno::EINVAL),
    };
    Ok(NftData::Verdict { code, chain })
}

/// Reads the data of an element of a map, as `nft_setelem_parse_data` of Linux.
fn nft_setelem_parse_data(table: &NftTable, set: &NftSet, nla: &[u8]) -> Result<NftData> {
    let tb = Attrs::parse(nla, NFTA_DATA_MAX);
    if set.datatype() == NFT_DATA_VERDICT {
        let Some(v) = tb.get(NFTA_DATA_VERDICT) else { return Err(Errno::EINVAL) };
        return nft_verdict_init(table, v);
    }
    nft_value_init(nla, set.dlen).map(NftData::Value)
}

// The batch.

/// A notice for the group `NFNLGRP_NFTABLES` that goes out at the commit.
struct NftNotice {
    msg: Vec<u8>,
    portid: u32,
    report: bool,
}

/// The changes of one batch, as the `commit_list` of Linux. The batch holds the lock of nf_tables
/// of the namespace until it ends, as `commit_mutex`.
struct NftBatch {
    net: SpinLockGuard<'static, NftablesPernet>,
    /// The objects with the changes of the batch.
    tables: Vec<NftTable>,
    table_handle: u64,
    /// The generation after the commit.
    next_seq: u32,
    notices: Vec<NftNotice>,
    /// A socket listens to the group: the batch makes the notices.
    listen: bool,
    /// The batch changed an object.
    changed: bool,
    /// The tables whose flags changed in the batch.
    updated: Vec<u64>,
}

/// Starts a batch, as `nf_tables_valid_genid` of Linux. A batch with a generation that is not
/// the current one gives `None`.
fn nf_tables_begin(genid: u32) -> Option<Box<dyn NfnlBatch>> {
    let net = NFT.get().lock();
    if genid != 0 && genid != net.base_seq {
        return None;
    }
    let mut next_seq = net.base_seq.wrapping_add(1);
    if next_seq == 0 {
        next_seq = 1;
    }
    Some(Box::new(NftBatch {
        tables: net.tables.clone(),
        table_handle: net.table_handle,
        next_seq,
        notices: Vec::new(),
        listen: nfnetlink_has_listeners(NFNLGRP_NFTABLES),
        changed: false,
        updated: Vec::new(),
        net,
    }))
}

impl NftBatch {
    /// Tells if the batch makes the notices of the request `ctx`.
    fn want(&self, ctx: &NftCtx) -> bool {
        ctx.report || self.listen
    }

    /// Keeps a notice for the commit, as `nft_notify_enqueue` of Linux.
    fn notify(&mut self, ctx: &NftCtx, msg: Option<Vec<u8>>) {
        self.changed = true;
        if let Some(msg) = msg {
            self.notices.push(NftNotice { msg, portid: ctx.portid, report: ctx.report });
        }
    }

    fn notify_table(&mut self, ctx: &NftCtx, event: u8, t: usize) {
        let flags = ctx.notify_flags();
        let m = self.want(ctx).then(|| {
            nf_tables_fill_table_info(
                ctx.portid,
                ctx.seq,
                event,
                flags,
                self.next_seq,
                &self.tables[t],
            )
        });
        self.notify(ctx, m);
    }

    fn notify_chain(&mut self, ctx: &NftCtx, event: u8, t: usize, c: usize) {
        let flags = ctx.notify_flags();
        let (portid, s) = (ctx.portid, ctx.seq);
        let m = self.want(ctx).then(|| {
            let table = &self.tables[t];
            nf_tables_fill_chain_info(
                portid,
                s,
                event,
                flags,
                self.next_seq,
                table,
                &table.chains[c],
            )
        });
        self.notify(ctx, m);
    }

    fn notify_set(&mut self, ctx: &NftCtx, event: u8, t: usize, s: usize) {
        let flags = ctx.notify_flags();
        let m = self.want(ctx).then(|| {
            let table = &self.tables[t];
            nf_tables_fill_set(
                ctx.portid,
                ctx.seq,
                event,
                flags,
                self.next_seq,
                table,
                &table.sets[s],
            )
        });
        self.notify(ctx, m);
    }

    /// The notice of a rule, as `nf_tables_rule_notify` of Linux. A new rule that is not the
    /// first or the last one has the handle of the rule before it.
    fn notify_rule(&mut self, ctx: &NftCtx, event: u8, t: usize, c: usize, r: usize) {
        let mut flags = ctx.notify_flags();
        if ctx.has(NLM_F_APPEND | NLM_F_REPLACE) {
            flags |= NLM_F_APPEND as u16;
        }
        let m = self.want(ctx).then(|| {
            let table = &self.tables[t];
            let chain = &table.chains[c];
            let prev = if event == NFT_MSG_NEWRULE && r > 0 && r + 1 < chain.rules.len() {
                chain.rules[r - 1].handle
            } else {
                0
            };
            nf_tables_fill_rule_info(
                ctx.portid,
                ctx.seq,
                event,
                flags,
                self.next_seq,
                table,
                chain,
                &chain.rules[r],
                prev,
            )
        });
        self.notify(ctx, m);
    }

    fn notify_setelem(&mut self, ctx: &NftCtx, event: u8, t: usize, s: usize, key: &ElemKey) {
        let flags = ctx.notify_flags();
        let m = self.want(ctx).then_some(()).and_then(|()| {
            let table = &self.tables[t];
            let set = &table.sets[s];
            let (k, e) = set.elems.get_key_value(key)?;
            Some(nf_tables_fill_setelem_info(
                ctx.portid,
                ctx.seq,
                event,
                flags,
                self.next_seq,
                table,
                set,
                &[(k, e)],
            ))
        });
        self.notify(ctx, m);
    }

    // The tables.

    fn nf_tables_newtable(&mut self, info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<()> {
        let ctx = NftCtx::new(info);
        if !nft_supported_family(ctx.family) {
            return Err(Errno::EOPNOTSUPP);
        }
        let name = nla_name(nla, NFTA_TABLE_NAME)?;
        match nft_table_lookup(&self.tables, name, ctx.family, ctx.portid) {
            Ok(t) => {
                if ctx.has(NLM_F_EXCL) {
                    return Err(bad(info, nla, NFTA_TABLE_NAME, Errno::EEXIST));
                }
                if ctx.has(NLM_F_REPLACE) {
                    return Err(Errno::EOPNOTSUPP);
                }
                return self.nf_tables_updtable(&ctx, nla, t);
            }
            Err(Errno::ENOENT) => {}
            Err(e) => return Err(bad(info, nla, NFTA_TABLE_NAME, e)),
        }
        let Some(name) = name else { return Err(Errno::EINVAL) };
        let flags = be32(nla, NFTA_TABLE_FLAGS)?.unwrap_or(0);
        if flags & !NFT_TABLE_F_MASK != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        self.table_handle += 1;
        self.tables.push(NftTable {
            name: name.to_vec(),
            family: ctx.family,
            flags,
            handle: self.table_handle,
            udata: nla_udata(nla, NFTA_TABLE_USERDATA)?,
            nlpid: if flags & NFT_TABLE_F_OWNER != 0 { ctx.portid } else { 0 },
            chains: Vec::new(),
            sets: Vec::new(),
            hgenerator: 0,
        });
        let t = self.tables.len() - 1;
        self.notify_table(&ctx, NFT_MSG_NEWTABLE, t);
        Ok(())
    }

    /// Changes the flags of a table, as `nf_tables_updtable` of Linux. The hooks of a dormant
    /// table go at the commit.
    fn nf_tables_updtable(&mut self, ctx: &NftCtx, nla: &Attrs<'_>, t: usize) -> Result<()> {
        let Some(flags) = be32(nla, NFTA_TABLE_FLAGS)? else { return Ok(()) };
        if flags & !NFT_TABLE_F_MASK != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let table = &self.tables[t];
        if flags == table.flags {
            return Ok(());
        }
        let orphan = table.flags & (NFT_TABLE_F_OWNER | NFT_TABLE_F_PERSIST) == NFT_TABLE_F_PERSIST;
        if (table.has_owner() && flags & NFT_TABLE_F_OWNER == 0)
            || (flags & NFT_TABLE_F_OWNER != 0 && !orphan)
            || (flags ^ table.flags) & NFT_TABLE_F_PERSIST != 0
        {
            return Err(Errno::EOPNOTSUPP);
        }
        // The dormant state changes one time in a batch.
        if self.updated.contains(&table.handle) {
            return Err(Errno::EINVAL);
        }
        let handle = table.handle;
        self.updated.push(handle);
        let table = &mut self.tables[t];
        if flags & NFT_TABLE_F_OWNER != 0 {
            table.nlpid = ctx.portid;
        }
        table.flags = flags;
        self.notify_table(ctx, NFT_MSG_NEWTABLE, t);
        Ok(())
    }

    fn nf_tables_deltable(&mut self, info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<()> {
        let ctx = NftCtx::new(info);
        let name = nla_name(nla, NFTA_TABLE_NAME)?;
        let handle = be64(nla, NFTA_TABLE_HANDLE)?;
        if name.is_none() && handle.is_none() {
            return self.nft_flush(&ctx, nla);
        }
        let (r, attr) = match handle {
            Some(h) => (
                nft_table_lookup_byhandle(&self.tables, h, ctx.family, ctx.portid),
                NFTA_TABLE_HANDLE,
            ),
            None => (nft_table_lookup(&self.tables, name, ctx.family, ctx.portid), NFTA_TABLE_NAME),
        };
        let t = match r {
            Ok(t) => t,
            Err(Errno::ENOENT) if ctx.ty == NFT_MSG_DESTROYTABLE => return Ok(()),
            Err(e) => return Err(bad(info, nla, attr, e)),
        };
        if ctx.has(NLM_F_NONREC) && self.tables[t].use_count() > 0 {
            return Err(Errno::EBUSY);
        }
        self.nft_flush_table(&ctx, t);
        Ok(())
    }

    /// Removes all of the tables of the family, as `nft_flush` of Linux. A table of another
    /// owner stays.
    fn nft_flush(&mut self, ctx: &NftCtx, nla: &Attrs<'_>) -> Result<()> {
        let name = nla_name(nla, NFTA_TABLE_NAME)?;
        let mut t = 0;
        while t < self.tables.len() {
            let table = &self.tables[t];
            if !family_match(ctx.family, table)
                || (table.has_owner() && table.nlpid != ctx.portid)
                || name.is_some_and(|n| n != table.name)
            {
                t += 1;
                continue;
            }
            let mut c = *ctx;
            c.family = table.family;
            self.nft_flush_table(&c, t);
        }
        Ok(())
    }

    /// Removes a table with its rules, sets and chains, as `nft_flush_table` of Linux.
    fn nft_flush_table(&mut self, ctx: &NftCtx, t: usize) {
        for c in 0..self.tables[t].chains.len() {
            while !self.tables[t].chains[c].rules.is_empty() {
                self.notify_rule(ctx, NFT_MSG_DELRULE, t, c, 0);
                self.tables[t].chains[c].rules.remove(0);
            }
        }
        while !self.tables[t].sets.is_empty() {
            self.notify_set(ctx, NFT_MSG_DELSET, t, 0);
            self.tables[t].sets.remove(0);
        }
        while !self.tables[t].chains.is_empty() {
            self.notify_chain(ctx, NFT_MSG_DELCHAIN, t, 0);
            self.tables[t].chains.remove(0);
        }
        self.notify_table(ctx, NFT_MSG_DELTABLE, t);
        self.tables.remove(t);
    }

    // The chains.

    fn nf_tables_newchain(&mut self, info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<()> {
        let ctx = NftCtx::new(info);
        let t = nft_table_lookup(
            &self.tables,
            nla_name(nla, NFTA_CHAIN_TABLE)?,
            ctx.family,
            ctx.portid,
        )
        .map_err(|e| bad(info, nla, NFTA_CHAIN_TABLE, e))?;
        let table = &self.tables[t];
        let mut attr = NFTA_CHAIN_NAME;
        let chain = if let Some(h) = be64(nla, NFTA_CHAIN_HANDLE)? {
            attr = NFTA_CHAIN_HANDLE;
            Some(
                nft_chain_lookup_byhandle(table, h)
                    .map_err(|e| bad(info, nla, NFTA_CHAIN_HANDLE, e))?,
            )
        } else if let Some(name) = nla_name(nla, NFTA_CHAIN_NAME)? {
            match nft_chain_lookup(table, Some(name)) {
                Ok(c) => Some(c),
                Err(Errno::ENOENT) => None,
                Err(e) => return Err(bad(info, nla, NFTA_CHAIN_NAME, e)),
            }
        } else if !nla.has(NFTA_CHAIN_ID) {
            return Err(Errno::EINVAL);
        } else {
            None
        };
        let mut policy = None;
        if let Some(p) = be32(nla, NFTA_CHAIN_POLICY)? {
            if chain.is_some_and(|c| table.chains[c].base.is_none())
                || (chain.is_none() && !nla.has(NFTA_CHAIN_HOOK))
            {
                return Err(bad(info, nla, NFTA_CHAIN_POLICY, Errno::EOPNOTSUPP));
            }
            if p != NF_DROP && p != NF_ACCEPT {
                return Err(Errno::EINVAL);
            }
            policy = Some(p);
        }
        let mut flags = match (be32(nla, NFTA_CHAIN_FLAGS)?, chain) {
            (Some(f), _) => f,
            (None, Some(c)) => table.chains[c].flags,
            (None, None) => 0,
        };
        if flags & !NFT_CHAIN_FLAGS != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        if let Some(c) = chain {
            let old = &table.chains[c];
            if old.flags & NFT_CHAIN_BINDING != 0 {
                return Err(Errno::EINVAL);
            }
            if ctx.has(NLM_F_EXCL) {
                return Err(bad(info, nla, attr, Errno::EEXIST));
            }
            if ctx.has(NLM_F_REPLACE) {
                return Err(Errno::EOPNOTSUPP);
            }
            flags |= old.flags & NFT_CHAIN_BASE;
            return self.nf_tables_updchain(info, &ctx, nla, t, c, policy, flags);
        }
        self.nf_tables_addchain(info, &ctx, nla, t, policy.unwrap_or(NF_ACCEPT), flags)
    }

    /// Reads the hook of a new base chain, as `nft_chain_parse_hook` of Linux.
    fn nft_chain_parse_hook(
        family: u8,
        nla: &Attrs<'_>,
    ) -> Result<(u8, i32, &'static NftChainType)> {
        let Some(h) = nla.get(NFTA_CHAIN_HOOK) else { return Err(Errno::EINVAL) };
        let ha = Attrs::parse(h, NFTA_HOOK_MAX);
        let (Some(num), Some(prio)) =
            (be32(&ha, NFTA_HOOK_HOOKNUM)?, be32(&ha, NFTA_HOOK_PRIORITY)?)
        else {
            return Err(Errno::EINVAL);
        };
        let types = nft_chain_types(family);
        let Some(&default) = types.first() else { return Err(Errno::EOPNOTSUPP) };
        let ty = match nla_string(nla, NFTA_CHAIN_TYPE, NFT_MODULE_AUTOLOAD_LIMIT)? {
            Some(name) => *types.iter().find(|t| t.name.as_bytes() == name).ok_or(Errno::ENOENT)?,
            None => default,
        };
        if num >= u32::from(NF_INET_NUMHOOKS) || ty.hook_mask & (1 << num) == 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        Ok((num as u8, prio as i32, ty))
    }

    fn nf_tables_addchain(
        &mut self,
        info: &NfnlInfo<'_>,
        ctx: &NftCtx,
        nla: &Attrs<'_>,
        t: usize,
        policy: u32,
        flags: u32,
    ) -> Result<()> {
        static CHAIN_ID: AtomicU64 = AtomicU64::new(0);
        let (base, flags) = if nla.has(NFTA_CHAIN_HOOK) {
            if flags & NFT_CHAIN_BINDING != 0 {
                return Err(Errno::EOPNOTSUPP);
            }
            let (hooknum, priority, ty) = Self::nft_chain_parse_hook(ctx.family, nla)?;
            if flags & NFT_CHAIN_HW_OFFLOAD != 0 {
                return Err(Errno::EOPNOTSUPP);
            }
            let ops = Arc::new(NftHookOps::new(policy));
            (Some(NftBaseChain { hooknum, priority, ty, policy, ops }), flags | NFT_CHAIN_BASE)
        } else {
            if flags & NFT_CHAIN_BASE != 0 {
                return Err(Errno::EINVAL);
            }
            if flags & NFT_CHAIN_HW_OFFLOAD != 0 {
                return Err(Errno::EOPNOTSUPP);
            }
            (None, flags)
        };
        let name = match nla_name(nla, NFTA_CHAIN_NAME)? {
            Some(n) => n.to_vec(),
            None if flags & NFT_CHAIN_BINDING != 0 => {
                format!("__chain{}", CHAIN_ID.fetch_add(1, Ordering::Relaxed) + 1).into_bytes()
            }
            None => return Err(Errno::EINVAL),
        };
        let udata = nla_udata(nla, NFTA_CHAIN_USERDATA)?;
        let txn_id = be32(nla, NFTA_CHAIN_ID)?;
        let table = &mut self.tables[t];
        if table.chains.iter().any(|c| c.name == name) {
            return Err(bad(info, nla, NFTA_CHAIN_NAME, Errno::EEXIST));
        }
        let handle = table.alloc_handle();
        table.chains.push(NftChain { name, handle, flags, udata, base, rules: Vec::new(), txn_id });
        let c = table.chains.len() - 1;
        self.notify_chain(ctx, NFT_MSG_NEWCHAIN, t, c);
        Ok(())
    }

    /// Changes a chain: the policy of a base chain, or the name, as `nf_tables_updchain` of
    /// Linux. The hook of a base chain does not change.
    #[allow(clippy::too_many_arguments)]
    fn nf_tables_updchain(
        &mut self,
        info: &NfnlInfo<'_>,
        ctx: &NftCtx,
        nla: &Attrs<'_>,
        t: usize,
        c: usize,
        policy: Option<u32>,
        flags: u32,
    ) -> Result<()> {
        let table = &self.tables[t];
        let chain = &table.chains[c];
        if let Some(h) = nla.get(NFTA_CHAIN_HOOK) {
            let Some(base) = &chain.base else {
                return Err(bad(info, nla, NFTA_CHAIN_HOOK, Errno::EEXIST));
            };
            let ha = Attrs::parse(h, NFTA_HOOK_MAX);
            if be32(&ha, NFTA_HOOK_HOOKNUM)?.is_some_and(|n| n != u32::from(base.hooknum))
                || be32(&ha, NFTA_HOOK_PRIORITY)?.is_some_and(|p| p as i32 != base.priority)
            {
                return Err(Errno::EOPNOTSUPP);
            }
            if let Some(name) = nla_string(nla, NFTA_CHAIN_TYPE, NFT_MODULE_AUTOLOAD_LIMIT)?
                && name != base.ty.name.as_bytes()
            {
                return Err(bad(info, nla, NFTA_CHAIN_TYPE, Errno::EEXIST));
            }
        }
        if flags != chain.flags {
            return Err(Errno::EOPNOTSUPP);
        }
        let rename = match (nla.has(NFTA_CHAIN_HANDLE), nla_name(nla, NFTA_CHAIN_NAME)?) {
            (true, Some(name)) if name != chain.name => {
                if nft_chain_lookup(table, Some(name)).is_ok() {
                    return Err(bad(info, nla, NFTA_CHAIN_NAME, Errno::EEXIST));
                }
                Some(name.to_vec())
            }
            _ => None,
        };
        let chain = &mut self.tables[t].chains[c];
        if let (Some(p), Some(base)) = (policy, chain.base.as_mut()) {
            base.policy = p;
        }
        if let Some(name) = rename {
            chain.name = name;
        }
        self.notify_chain(ctx, NFT_MSG_NEWCHAIN, t, c);
        Ok(())
    }

    fn nf_tables_delchain(&mut self, info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<()> {
        let ctx = NftCtx::new(info);
        let t = nft_table_lookup(
            &self.tables,
            nla_name(nla, NFTA_CHAIN_TABLE)?,
            ctx.family,
            ctx.portid,
        )
        .map_err(|e| bad(info, nla, NFTA_CHAIN_TABLE, e))?;
        let table = &self.tables[t];
        let (r, attr) = match be64(nla, NFTA_CHAIN_HANDLE)? {
            Some(h) => (nft_chain_lookup_byhandle(table, h), NFTA_CHAIN_HANDLE),
            None => (nft_chain_lookup(table, nla_name(nla, NFTA_CHAIN_NAME)?), NFTA_CHAIN_NAME),
        };
        let c = match r {
            Ok(c) => c,
            Err(Errno::ENOENT) if ctx.ty == NFT_MSG_DESTROYCHAIN => return Ok(()),
            Err(e) => return Err(bad(info, nla, attr, e)),
        };
        let chain = &table.chains[c];
        if chain.flags & NFT_CHAIN_BINDING != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let mut use_count = table.chain_use(chain.handle);
        if ctx.has(NLM_F_NONREC) && use_count > 0 {
            return Err(Errno::EBUSY);
        }
        use_count -= chain.rules.len() as u32;
        // Some elements or rules jump to the chain, so it cannot go with its rules.
        if use_count > 0 {
            return Err(bad(info, nla, attr, Errno::EBUSY));
        }
        while !self.tables[t].chains[c].rules.is_empty() {
            self.notify_rule(&ctx, NFT_MSG_DELRULE, t, c, 0);
            self.tables[t].chains[c].rules.remove(0);
        }
        self.notify_chain(&ctx, NFT_MSG_DELCHAIN, t, c);
        self.tables[t].chains.remove(c);
        Ok(())
    }

    // The rules.

    fn nf_tables_newrule(&mut self, info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<()> {
        let ctx = NftCtx::new(info);
        let t =
            nft_table_lookup(&self.tables, nla_name(nla, NFTA_RULE_TABLE)?, ctx.family, ctx.portid)
                .map_err(|e| bad(info, nla, NFTA_RULE_TABLE, e))?;
        let table = &self.tables[t];
        let c = if let Some(name) = nla_name(nla, NFTA_RULE_CHAIN)? {
            nft_chain_lookup(table, Some(name)).map_err(|e| bad(info, nla, NFTA_RULE_CHAIN, e))?
        } else if let Some(id) = be32(nla, NFTA_RULE_CHAIN_ID)? {
            nft_chain_lookup_byid(table, id).map_err(|e| bad(info, nla, NFTA_RULE_CHAIN_ID, e))?
        } else {
            return Err(Errno::EINVAL);
        };
        let chain = &table.chains[c];
        let mut old = None;
        let handle = if let Some(h) = be64(nla, NFTA_RULE_HANDLE)? {
            let r = nft_rule_lookup(chain, h).map_err(|e| bad(info, nla, NFTA_RULE_HANDLE, e))?;
            if ctx.has(NLM_F_EXCL) {
                return Err(bad(info, nla, NFTA_RULE_HANDLE, Errno::EEXIST));
            }
            if !ctx.has(NLM_F_REPLACE) {
                return Err(Errno::EOPNOTSUPP);
            }
            old = Some(r);
            h
        } else {
            if !ctx.has(NLM_F_CREATE) || ctx.has(NLM_F_REPLACE) {
                return Err(Errno::EINVAL);
            }
            if let Some(pos) = be64(nla, NFTA_RULE_POSITION)? {
                old = Some(
                    nft_rule_lookup(chain, pos)
                        .map_err(|e| bad(info, nla, NFTA_RULE_POSITION, e))?,
                );
            } else if let Some(id) = be32(nla, NFTA_RULE_POSITION_ID)? {
                old = Some(
                    chain
                        .rules
                        .iter()
                        .position(|r| r.txn_id == Some(id))
                        .ok_or_else(|| bad(info, nla, NFTA_RULE_POSITION_ID, Errno::ENOENT))?,
                );
            }
            0
        };
        let exprs = nla.get(NFTA_RULE_EXPRESSIONS).unwrap_or(&[]);
        let mut parsed = Vec::new();
        for (n, (ty, e)) in msg::attrs(exprs).enumerate() {
            if ty != NFTA_LIST_ELEM || n == NFT_MAX_EXPRS {
                return Err(Errno::EINVAL);
            }
            let expr = nf_tables_expr_parse(table, e).inspect_err(|_| info.req.bad_attr(e))?;
            // A jump that comes back to the chain is a loop, as `nft_chain_validate` of Linux.
            if let Some(target) = expr.jump_target() {
                nft_check_loops(table, chain.handle, target)?;
            }
            parsed.push(expr);
        }
        let udata = match nla.get(NFTA_RULE_USERDATA) {
            Some(d) if d.len() > NFT_USERDATA_MAXLEN => return Err(Errno::ERANGE),
            Some(d) if !d.is_empty() => Some(d.to_vec()),
            _ => None,
        };
        let txn_id = be32(nla, NFTA_RULE_ID)?;
        let table = &mut self.tables[t];
        let handle = if handle == 0 { table.alloc_handle() } else { handle };
        let rule = NftRule { handle, exprs: exprs.to_vec(), parsed, udata, txn_id };
        let at = if let (true, Some(o)) = (ctx.has(NLM_F_REPLACE), old) {
            self.notify_rule(&ctx, NFT_MSG_DELRULE, t, c, o);
            self.tables[t].chains[c].rules[o] = rule;
            o
        } else {
            let rules = &mut self.tables[t].chains[c].rules;
            let at = if ctx.has(NLM_F_APPEND) {
                old.map_or(rules.len(), |o| o + 1)
            } else {
                old.unwrap_or(0)
            };
            rules.insert(at, rule);
            at
        };
        self.notify_rule(&ctx, NFT_MSG_NEWRULE, t, c, at);
        Ok(())
    }

    fn nf_tables_delrule(&mut self, info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<()> {
        let ctx = NftCtx::new(info);
        let t =
            nft_table_lookup(&self.tables, nla_name(nla, NFTA_RULE_TABLE)?, ctx.family, ctx.portid)
                .map_err(|e| bad(info, nla, NFTA_RULE_TABLE, e))?;
        let destroy = ctx.ty == NFT_MSG_DESTROYRULE;
        let chain = match nla_name(nla, NFTA_RULE_CHAIN)? {
            Some(name) => match nft_chain_lookup(&self.tables[t], Some(name)) {
                Ok(c) => Some(c),
                Err(Errno::ENOENT) if destroy => return Ok(()),
                Err(e) => return Err(bad(info, nla, NFTA_RULE_CHAIN, e)),
            },
            None => None,
        };
        let Some(c) = chain else {
            for c in 0..self.tables[t].chains.len() {
                if self.tables[t].chains[c].flags & NFT_CHAIN_BINDING == 0 {
                    self.nft_delrule_by_chain(&ctx, t, c);
                }
            }
            return Ok(());
        };
        if self.tables[t].chains[c].flags & NFT_CHAIN_BINDING != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let rules = &self.tables[t].chains[c].rules;
        let r = if let Some(h) = be64(nla, NFTA_RULE_HANDLE)? {
            match nft_rule_lookup(&self.tables[t].chains[c], h) {
                Ok(r) => r,
                Err(Errno::ENOENT) if destroy => return Ok(()),
                Err(e) => return Err(bad(info, nla, NFTA_RULE_HANDLE, e)),
            }
        } else if let Some(id) = be32(nla, NFTA_RULE_ID)? {
            rules
                .iter()
                .position(|r| r.txn_id == Some(id))
                .ok_or_else(|| bad(info, nla, NFTA_RULE_ID, Errno::ENOENT))?
        } else {
            self.nft_delrule_by_chain(&ctx, t, c);
            return Ok(());
        };
        self.notify_rule(&ctx, NFT_MSG_DELRULE, t, c, r);
        self.tables[t].chains[c].rules.remove(r);
        Ok(())
    }

    /// Removes all of the rules of a chain, as `nft_delrule_by_chain` of Linux.
    fn nft_delrule_by_chain(&mut self, ctx: &NftCtx, t: usize, c: usize) {
        while !self.tables[t].chains[c].rules.is_empty() {
            self.notify_rule(ctx, NFT_MSG_DELRULE, t, c, 0);
            self.tables[t].chains[c].rules.remove(0);
        }
    }

    // The sets.

    fn nf_tables_newset(&mut self, info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<()> {
        let ctx = NftCtx::new(info);
        let table_name = nla_name(nla, NFTA_SET_TABLE)?;
        let name = nla_name(nla, NFTA_SET_NAME)?;
        let (Some(_), Some(name), Some(klen), Some(id)) =
            (table_name, name, be32(nla, NFTA_SET_KEY_LEN)?, be32(nla, NFTA_SET_ID)?)
        else {
            return Err(Errno::EINVAL);
        };
        let ktype = be32(nla, NFTA_SET_KEY_TYPE)?.unwrap_or(NFT_DATA_VALUE);
        if ktype & NFT_DATA_RESERVED_MASK == NFT_DATA_RESERVED_MASK {
            return Err(Errno::EINVAL);
        }
        if klen == 0 || klen > NFT_DATA_VALUE_MAXLEN {
            return Err(Errno::EINVAL);
        }
        let flags = be32(nla, NFTA_SET_FLAGS)?.unwrap_or(0);
        let known = NFT_SET_ANONYMOUS
            | NFT_SET_CONSTANT
            | NFT_SET_INTERVAL
            | NFT_SET_TIMEOUT
            | NFT_SET_MAP
            | NFT_SET_EVAL
            | NFT_SET_OBJECT
            | NFT_SET_CONCAT
            | NFT_SET_EXPR;
        if flags & !known != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        // Only one of these works.
        let both = |a: u32, b: u32| flags & (a | b) == a | b;
        if both(NFT_SET_MAP, NFT_SET_OBJECT)
            || both(NFT_SET_EVAL, NFT_SET_OBJECT)
            || flags & (NFT_SET_ANONYMOUS | NFT_SET_TIMEOUT | NFT_SET_EVAL)
                == NFT_SET_ANONYMOUS | NFT_SET_TIMEOUT
            || both(NFT_SET_CONSTANT, NFT_SET_TIMEOUT)
        {
            return Err(Errno::EOPNOTSUPP);
        }
        // The timeouts, the objects and the expressions of the sets come later.
        if flags & (NFT_SET_TIMEOUT | NFT_SET_OBJECT | NFT_SET_EXPR) != 0
            || nla.has(NFTA_SET_EXPR)
            || nla.has(NFTA_SET_EXPRESSIONS)
        {
            return Err(Errno::EOPNOTSUPP);
        }
        let (mut dtype, mut dlen) = (0, 0);
        if let Some(d) = be32(nla, NFTA_SET_DATA_TYPE)? {
            if flags & NFT_SET_MAP == 0 {
                return Err(Errno::EINVAL);
            }
            dtype = d;
            if dtype & NFT_DATA_RESERVED_MASK == NFT_DATA_RESERVED_MASK && dtype != NFT_DATA_VERDICT
            {
                return Err(Errno::EINVAL);
            }
            if dtype != NFT_DATA_VERDICT {
                let Some(l) = be32(nla, NFTA_SET_DATA_LEN)? else { return Err(Errno::EINVAL) };
                if l == 0 || l > NFT_DATA_VALUE_MAXLEN {
                    return Err(Errno::EINVAL);
                }
                dlen = l;
            } else {
                dlen = NFT_VERDICT_LEN;
            }
        } else if flags & NFT_SET_MAP != 0 {
            return Err(Errno::EINVAL);
        }
        if nla.has(NFTA_SET_OBJ_TYPE) || nla.has(NFTA_SET_TIMEOUT) || nla.has(NFTA_SET_GC_INTERVAL)
        {
            return Err(Errno::EINVAL);
        }
        let policy = be32(nla, NFTA_SET_POLICY)?.unwrap_or(NFT_SET_POL_PERFORMANCE);
        if policy != NFT_SET_POL_PERFORMANCE && policy != NFT_SET_POL_MEMORY {
            return Err(Errno::EOPNOTSUPP);
        }
        let (size, field_len) = match nla.get(NFTA_SET_DESC) {
            Some(d) => nf_tables_set_desc_parse(d, klen)?,
            None => (0, Vec::new()),
        };
        let t = nft_table_lookup(&self.tables, table_name, ctx.family, ctx.portid)
            .map_err(|e| bad(info, nla, NFTA_SET_TABLE, e))?;
        let table = &self.tables[t];
        match nft_set_lookup(table, Some(name)) {
            Ok(s) => {
                if ctx.has(NLM_F_EXCL) {
                    return Err(bad(info, nla, NFTA_SET_NAME, Errno::EEXIST));
                }
                if ctx.has(NLM_F_REPLACE) {
                    return Err(Errno::EOPNOTSUPP);
                }
                let set = &table.sets[s];
                if set.flags & NFT_SET_ANONYMOUS != 0 {
                    return Err(Errno::EOPNOTSUPP);
                }
                // A set that is not the same as the old one gives `EEXIST`, as
                // `nft_set_is_same`.
                if set.ktype != ktype
                    || set.dtype != dtype
                    || set.flags != flags
                    || set.klen != klen
                    || set.dlen != dlen
                    || set.field_len != field_len
                {
                    return Err(bad(info, nla, NFTA_SET_NAME, Errno::EEXIST));
                }
                return Ok(());
            }
            Err(Errno::ENOENT) => {}
            Err(e) => return Err(bad(info, nla, NFTA_SET_NAME, e)),
        }
        if !ctx.has(NLM_F_CREATE) {
            return Err(Errno::ENOENT);
        }
        let name = nf_tables_set_alloc_name(table, name)?;
        let udata = nla_udata(nla, NFTA_SET_USERDATA)?;
        let table = &mut self.tables[t];
        let handle = table.alloc_handle();
        table.sets.push(NftSet {
            name,
            handle,
            flags,
            ktype,
            klen,
            dtype,
            dlen,
            policy,
            size,
            field_len,
            udata,
            elems: BTreeMap::new(),
            txn_id: Some(id),
        });
        let s = table.sets.len() - 1;
        self.notify_set(&ctx, NFT_MSG_NEWSET, t, s);
        Ok(())
    }

    fn nf_tables_delset(&mut self, info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<()> {
        let ctx = NftCtx::new(info);
        let t =
            nft_table_lookup(&self.tables, nla_name(nla, NFTA_SET_TABLE)?, ctx.family, ctx.portid)
                .map_err(|e| bad(info, nla, NFTA_SET_TABLE, e))?;
        let table = &self.tables[t];
        let (r, attr) = match be64(nla, NFTA_SET_HANDLE)? {
            Some(h) => (
                table.sets.iter().position(|s| s.handle == h).ok_or(Errno::ENOENT),
                NFTA_SET_HANDLE,
            ),
            None => (nft_set_lookup(table, nla_name(nla, NFTA_SET_NAME)?), NFTA_SET_NAME),
        };
        let s = match r {
            Ok(s) => s,
            Err(Errno::ENOENT) if ctx.ty == NFT_MSG_DESTROYSET => return Ok(()),
            Err(e) => return Err(bad(info, nla, attr, e)),
        };
        if (ctx.has(NLM_F_NONREC) && !table.sets[s].elems.is_empty())
            || table.set_in_use(table.sets[s].handle)
        {
            return Err(bad(info, nla, attr, Errno::EBUSY));
        }
        self.notify_set(&ctx, NFT_MSG_DELSET, t, s);
        self.tables[t].sets.remove(s);
        Ok(())
    }

    // The elements.

    fn nf_tables_newsetelem(&mut self, info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<()> {
        let ctx = NftCtx::new(info);
        let Some(list) = nla.get(NFTA_SET_ELEM_LIST_ELEMENTS) else { return Err(Errno::EINVAL) };
        let t = nft_table_lookup(
            &self.tables,
            nla_name(nla, NFTA_SET_ELEM_LIST_TABLE)?,
            ctx.family,
            ctx.portid,
        )
        .map_err(|e| bad(info, nla, NFTA_SET_ELEM_LIST_TABLE, e))?;
        let s = nft_set_lookup_global(
            &self.tables[t],
            nla_name(nla, NFTA_SET_ELEM_LIST_SET)?,
            be32(nla, NFTA_SET_ELEM_LIST_SET_ID)?,
        )
        .map_err(|e| bad(info, nla, NFTA_SET_ELEM_LIST_SET, e))?;
        for (_, attr) in msg::attrs(list) {
            self.nft_add_set_elem(&ctx, t, s, attr).inspect_err(|_| info.req.bad_attr(attr))?;
        }
        Ok(())
    }

    /// Adds one element, as `nft_add_set_elem` of Linux.
    fn nft_add_set_elem(&mut self, ctx: &NftCtx, t: usize, s: usize, attr: &[u8]) -> Result<()> {
        let table = &self.tables[t];
        let set = &table.sets[s];
        let ea = Attrs::parse(attr, NFTA_SET_ELEM_MAX);
        let flags = nft_setelem_parse_flags(set, &ea)?;
        let key = nft_setelem_parse_elemkey(set, &ea, flags)?;
        let end = flags & NFT_SET_ELEM_INTERVAL_END != 0;
        if set.flags & NFT_SET_MAP != 0 {
            if !ea.has(NFTA_SET_ELEM_DATA) && !end {
                return Err(Errno::EINVAL);
            }
        } else if ea.has(NFTA_SET_ELEM_DATA) {
            return Err(Errno::EINVAL);
        }
        if ea.has(NFTA_SET_ELEM_OBJREF) {
            return Err(Errno::EINVAL);
        }
        let extra = [
            NFTA_SET_ELEM_DATA,
            NFTA_SET_ELEM_TIMEOUT,
            NFTA_SET_ELEM_EXPIRATION,
            NFTA_SET_ELEM_USERDATA,
            NFTA_SET_ELEM_EXPR,
            NFTA_SET_ELEM_KEY_END,
            NFTA_SET_ELEM_EXPRESSIONS,
        ];
        if end && extra.iter().any(|&a| ea.has(a)) {
            return Err(Errno::EINVAL);
        }
        if ea.has(NFTA_SET_ELEM_TIMEOUT) || ea.has(NFTA_SET_ELEM_EXPIRATION) {
            return Err(Errno::EINVAL);
        }
        if ea.has(NFTA_SET_ELEM_EXPR) || ea.has(NFTA_SET_ELEM_EXPRESSIONS) {
            return Err(Errno::EOPNOTSUPP);
        }
        let key_end = match ea.get(NFTA_SET_ELEM_KEY_END) {
            Some(k) => Some(nft_value_init(k, set.klen)?),
            None => None,
        };
        let data = match ea.get(NFTA_SET_ELEM_DATA) {
            Some(d) => Some(nft_setelem_parse_data(table, set, d)?),
            None => None,
        };
        let udata = nla_udata(&ea, NFTA_SET_ELEM_USERDATA)?;
        if let Some(old) = set.elems.get(&key) {
            // An element that is there gives `EBUSY` if its data is not the same, and
            // `EEXIST` with `NLM_F_EXCL`.
            if old.data != data {
                return Err(Errno::EBUSY);
            }
            if ctx.has(NLM_F_EXCL) {
                return Err(Errno::EEXIST);
            }
            return Ok(());
        }
        if !key.catchall && set.size != 0 && set.nelems() >= set.size as usize {
            return Err(Errno::ENFILE);
        }
        let elem = NftElem { key_end, data, flags, udata };
        self.tables[t].sets[s].elems.insert(key.clone(), elem);
        self.notify_setelem(ctx, NFT_MSG_NEWSETELEM, t, s, &key);
        Ok(())
    }

    fn nf_tables_delsetelem(&mut self, info: &NfnlInfo<'_>, nla: &Attrs<'_>) -> Result<()> {
        let ctx = NftCtx::new(info);
        let t = nft_table_lookup(
            &self.tables,
            nla_name(nla, NFTA_SET_ELEM_LIST_TABLE)?,
            ctx.family,
            ctx.portid,
        )
        .map_err(|e| bad(info, nla, NFTA_SET_ELEM_LIST_TABLE, e))?;
        let s = nft_set_lookup(&self.tables[t], nla_name(nla, NFTA_SET_ELEM_LIST_SET)?)
            .map_err(|e| bad(info, nla, NFTA_SET_ELEM_LIST_SET, e))?;
        let Some(list) = nla.get(NFTA_SET_ELEM_LIST_ELEMENTS) else {
            // No list removes all of the elements, as `nft_set_flush`.
            let keys: Vec<ElemKey> = self.tables[t].sets[s].elems.keys().cloned().collect();
            for k in keys {
                self.notify_setelem(&ctx, NFT_MSG_DELSETELEM, t, s, &k);
                self.tables[t].sets[s].elems.remove(&k);
            }
            return Ok(());
        };
        for (_, attr) in msg::attrs(list) {
            match self.nft_del_setelem(&ctx, t, s, attr) {
                Err(Errno::ENOENT) if ctx.ty == NFT_MSG_DESTROYSETELEM => {}
                Err(e) => {
                    info.req.bad_attr(attr);
                    return Err(e);
                }
                Ok(()) => {}
            }
        }
        Ok(())
    }

    /// Removes one element, as `nft_del_setelem` of Linux.
    fn nft_del_setelem(&mut self, ctx: &NftCtx, t: usize, s: usize, attr: &[u8]) -> Result<()> {
        let set = &self.tables[t].sets[s];
        let ea = Attrs::parse(attr, NFTA_SET_ELEM_MAX);
        let flags = nft_setelem_parse_flags(set, &ea)?;
        let key = nft_setelem_parse_elemkey(set, &ea, flags)?;
        if !set.elems.contains_key(&key) {
            return Err(Errno::ENOENT);
        }
        self.notify_setelem(ctx, NFT_MSG_DELSETELEM, t, s, &key);
        self.tables[t].sets[s].elems.remove(&key);
        Ok(())
    }
}

/// Reads the description of a set: the size and the lengths of the fields of a concatenated
/// key, as `nf_tables_set_desc_parse` and `nft_set_desc_concat` of Linux.
fn nf_tables_set_desc_parse(nla: &[u8], klen: u32) -> Result<(u32, Vec<u8>)> {
    let da = Attrs::parse(nla, 2);
    let size = be32(&da, NFTA_SET_DESC_SIZE)?.unwrap_or(0);
    let mut fields = Vec::new();
    if let Some(concat) = da.get(NFTA_SET_DESC_CONCAT) {
        for (ty, f) in msg::attrs(concat) {
            if ty != NFTA_LIST_ELEM {
                return Err(Errno::EINVAL);
            }
            if fields.len() >= NFT_REG32_COUNT {
                return Err(Errno::E2BIG);
            }
            let fa = Attrs::parse(f, 1);
            let Some(len) = be32(&fa, NFTA_SET_FIELD_LEN)? else { return Err(Errno::EINVAL) };
            if len == 0 || len > u32::from(u8::MAX) {
                return Err(Errno::EINVAL);
            }
            fields.push(len as u8);
        }
        let regs: u32 = fields.iter().map(|&l| u32::from(l).div_ceil(4)).sum();
        if regs != klen.div_ceil(4) {
            return Err(Errno::EINVAL);
        }
    }
    Ok((size, fields))
}

/// The name of a new set. A name with `%d` takes the lowest free number, as
/// `nf_tables_set_alloc_name` of Linux.
fn nf_tables_set_alloc_name(table: &NftTable, name: &[u8]) -> Result<Vec<u8>> {
    let Some(p) = name.iter().position(|&c| c == b'%') else {
        return Ok(name.to_vec());
    };
    if name.get(p + 1) != Some(&b'd') || name[p + 2..].contains(&b'%') {
        return Err(Errno::EINVAL);
    }
    const MAX: usize = 8 * 4096;
    let make = |n: usize| {
        let mut v = name[..p].to_vec();
        v.extend_from_slice(format!("{n}").as_bytes());
        v.extend_from_slice(&name[p + 2..]);
        v
    };
    (0..MAX).map(make).find(|v| !table.sets.iter().any(|s| &s.name == v)).ok_or(Errno::EMFILE)
}

/// The hooks of the base chains of the tables that are not dormant.
type WantedHook = (Arc<NftHookOps>, u8, u8, i32, u32, Arc<NftProg>);

fn nft_wanted_hooks(tables: &[NftTable]) -> Vec<WantedHook> {
    let mut out = Vec::new();
    for t in tables.iter().filter(|t| t.flags & NFT_TABLE_F_DORMANT == 0) {
        for (i, c) in t.chains.iter().enumerate() {
            if let Some(b) = &c.base {
                let prog = Arc::new(nft_prog(t, i));
                out.push((b.ops.clone(), t.family, b.hooknum, b.priority, b.policy, prog));
            }
        }
    }
    out
}

/// Puts the hooks of `tables` in the hook lists, and removes the hooks that are not in
/// `tables` any more. The state of each base chain goes to its hook.
fn nft_sync_hooks(net: &mut NftablesPernet, tables: &[NftTable]) -> Result<()> {
    let want = nft_wanted_hooks(tables);
    let same = |ops: &NfHookOps, w: &Arc<NftHookOps>| {
        Arc::as_ptr(&ops.hook).cast::<u8>() == Arc::as_ptr(w).cast::<u8>()
    };
    let new: Vec<NfHookOps> = want
        .iter()
        .filter(|w| !net.hooks.iter().any(|h| same(h, &w.0)))
        .map(|w| NfHookOps { hook: w.0.clone(), pf: w.1, hooknum: w.2, priority: w.3 })
        .collect();
    for w in &want {
        *w.0.prog.lock() = w.5.clone();
        w.0.policy.store(w.4, Ordering::Release);
    }
    nf_register_net_hooks(&new)?;
    let mut hooks = Vec::with_capacity(want.len());
    for h in core::mem::take(&mut net.hooks) {
        if want.iter().any(|w| same(&h, &w.0)) {
            hooks.push(h);
        } else {
            nf_unregister_net_hook(&h);
        }
    }
    hooks.extend(new);
    net.hooks = hooks;
    Ok(())
}

impl NfnlBatch for NftBatch {
    fn call(&mut self, info: &NfnlInfo<'_>, _cb: &NfnlCallback, nla: &Attrs<'_>) -> Result<()> {
        match nfnl_msg_type(info.nlh.ty) {
            NFT_MSG_NEWTABLE => self.nf_tables_newtable(info, nla),
            NFT_MSG_DELTABLE | NFT_MSG_DESTROYTABLE => self.nf_tables_deltable(info, nla),
            NFT_MSG_NEWCHAIN => self.nf_tables_newchain(info, nla),
            NFT_MSG_DELCHAIN | NFT_MSG_DESTROYCHAIN => self.nf_tables_delchain(info, nla),
            NFT_MSG_NEWRULE => self.nf_tables_newrule(info, nla),
            NFT_MSG_DELRULE | NFT_MSG_DESTROYRULE => self.nf_tables_delrule(info, nla),
            NFT_MSG_NEWSET => self.nf_tables_newset(info, nla),
            NFT_MSG_DELSET | NFT_MSG_DESTROYSET => self.nf_tables_delset(info, nla),
            NFT_MSG_NEWSETELEM => self.nf_tables_newsetelem(info, nla),
            NFT_MSG_DELSETELEM | NFT_MSG_DESTROYSETELEM => self.nf_tables_delsetelem(info, nla),
            _ => Err(Errno::EOPNOTSUPP),
        }
    }

    /// Puts the changes in place, as `nf_tables_commit` of Linux. A batch with no change does
    /// not start a new generation.
    fn commit(mut self: Box<Self>, batch: Origin) -> Result<()> {
        if !self.changed {
            return Ok(());
        }
        for t in &mut self.tables {
            for c in &mut t.chains {
                c.txn_id = None;
                for r in &mut c.rules {
                    r.txn_id = None;
                }
            }
            for s in &mut t.sets {
                s.txn_id = None;
            }
        }
        let tables = core::mem::take(&mut self.tables);
        nft_sync_hooks(&mut self.net, &tables)?;
        self.net.tables = tables;
        self.net.table_handle = self.table_handle;
        self.net.base_seq = self.next_seq;
        let base_seq = self.next_seq;
        let NftBatch { net, notices, listen, .. } = *self;
        drop(net);
        for n in notices {
            nfnetlink_send(n.msg, n.portid, NFNLGRP_NFTABLES, n.report);
        }
        // The notice of the new generation, as `nf_tables_gen_notify`.
        if batch.echo || listen {
            let m = nf_tables_fill_gen_info(batch.portid, batch.seq, base_seq);
            nfnetlink_send(m, batch.portid, NFNLGRP_NFTABLES, batch.echo);
        }
        Ok(())
    }

    fn abort(self: Box<Self>) {}
}

/// Removes the tables of the socket `portid` that closes, as `nft_rcv_nl_event` of Linux. A
/// table with `NFT_TABLE_F_PERSIST` stays and has no owner then.
pub fn nft_release_portid(portid: u32) {
    let mut net = NFT.lock();
    if !net.tables.iter().any(|t| t.has_owner() && t.nlpid == portid) {
        return;
    }
    let mut tables = core::mem::take(&mut net.tables);
    tables.retain_mut(|t| {
        if !t.has_owner() || t.nlpid != portid {
            return true;
        }
        if t.flags & NFT_TABLE_F_PERSIST != 0 {
            t.flags &= !NFT_TABLE_F_OWNER;
            t.nlpid = 0;
            return true;
        }
        false
    });
    // Removing hooks does not fail.
    let _ = nft_sync_hooks(&mut net, &tables);
    net.tables = tables;
}

#[cfg(test)]
mod tests {
    use super::*;

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
            hgenerator: 0,
        }
    }

    fn set(name: &[u8]) -> NftSet {
        NftSet {
            name: name.to_vec(),
            handle: 1,
            flags: 0,
            ktype: 0,
            klen: 4,
            dtype: 0,
            dlen: 0,
            policy: 0,
            size: 0,
            field_len: Vec::new(),
            udata: None,
            elems: BTreeMap::new(),
            txn_id: None,
        }
    }

    #[test]
    fn a_set_name_with_a_number_takes_the_lowest_free_one() {
        let mut t = table();
        assert_eq!(nf_tables_set_alloc_name(&t, b"__set%d").unwrap(), b"__set0");
        t.sets.push(set(b"__set0"));
        t.sets.push(set(b"__set2"));
        assert_eq!(nf_tables_set_alloc_name(&t, b"__set%d").unwrap(), b"__set1");
        assert_eq!(nf_tables_set_alloc_name(&t, b"plain").unwrap(), b"plain");
        assert_eq!(nf_tables_set_alloc_name(&t, b"bad%x"), Err(Errno::EINVAL));
        assert_eq!(nf_tables_set_alloc_name(&t, b"%d%d"), Err(Errno::EINVAL));
    }

    #[test]
    fn the_fields_of_a_key_must_fill_the_key() {
        let mut b = Builder::new(0, 0, 0, 0);
        let c = b.nest(NFTA_SET_DESC_CONCAT as u16);
        for len in [4u32, 2] {
            let e = b.nest(NFTA_LIST_ELEM);
            b.put(NFTA_SET_FIELD_LEN as u16, &len.to_be_bytes());
            b.end_nest(e);
        }
        b.end_nest(c);
        let m = b.finish();
        let desc = &m[msg::HDRLEN..];
        assert_eq!(nf_tables_set_desc_parse(desc, 8).unwrap(), (0, alloc::vec![4, 2]));
        assert_eq!(nf_tables_set_desc_parse(desc, 12), Err(Errno::EINVAL));
    }
}

//! The programs of the cgroups, kernel/bpf/cgroup.c of Linux.
//!
//! Each cgroup has a list of programs for each attach type, with the flags of the attach. The
//! effective programs of a cgroup are its programs and the programs of its ancestors, as
//! `compute_effective_progs` of Linux gives them. Linux keeps the effective arrays in each
//! cgroup and computes them again after each change. rukernel computes the array of a cgroup
//! when a hook runs, from the lists of the cgroup and of its ancestors, so a new cgroup needs no
//! hook. The count of the programs of each attach type, as `cgroup_bpf_enabled_key` of Linux,
//! lets a hook stop at once when no cgroup has a program.
//!
//! The caller gives the cgroups through [`CgroupEnv`]: the cgroup of a descriptor, the parent of
//! a cgroup and the ID of a cgroup. The IDs of rukernel cgroups are not used again, so a list
//! stays with its cgroup until [`cgroup_bpf_offline`] takes it away.

use crate::link::{BPF_LINK_INFO_SIZE, BpfLink, BpfLinkOps, link_info, link_type};
use crate::prog::BpfProg;
use crate::uapi::attach_flags::*;
use crate::uapi::attach_type::*;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

/// The result of a cgroup operation.
pub type Result<T> = core::result::Result<T, Errno>;

/// The ID of a cgroup, `CgId` of rk-cgroup.
pub type CgId = u32;

/// What the cgroup programs need of the caller.
pub trait CgroupEnv {
    /// The parent of the cgroup `id`, or `None` for the root.
    fn cgroup_parent(&self, id: CgId) -> Option<CgId>;
    /// The ID of the cgroup that a program sees, `cgroup_id` of Linux: the inode number of its
    /// directory.
    fn cgroup_id(&self, id: CgId) -> u64;
}

/// The attach types of the cgroups that rukernel has, a part of `enum cgroup_bpf_attach_type`
/// of Linux.
#[allow(missing_docs)]
pub mod atype {
    pub const CGROUP_INET_INGRESS: usize = 0;
    pub const CGROUP_INET_EGRESS: usize = 1;
    pub const CGROUP_INET_SOCK_CREATE: usize = 2;
    pub const CGROUP_INET_SOCK_RELEASE: usize = 3;
    pub const CGROUP_INET4_POST_BIND: usize = 4;
    pub const CGROUP_INET6_POST_BIND: usize = 5;
    pub const CGROUP_DEVICE: usize = 6;
    /// The count of the attach types, `MAX_CGROUP_BPF_ATTACH_TYPE`.
    pub const MAX_CGROUP_BPF_ATTACH_TYPE: usize = 7;
}

use atype::*;

/// The attach type of the cgroups of an attach type, `to_cgroup_bpf_attach_type` of Linux. An
/// attach type that rukernel does not have gives `None`.
pub fn to_cgroup_bpf_attach_type(attach_type: u32) -> Option<usize> {
    Some(match attach_type {
        BPF_CGROUP_INET_INGRESS => CGROUP_INET_INGRESS,
        BPF_CGROUP_INET_EGRESS => CGROUP_INET_EGRESS,
        BPF_CGROUP_INET_SOCK_CREATE => CGROUP_INET_SOCK_CREATE,
        BPF_CGROUP_INET_SOCK_RELEASE => CGROUP_INET_SOCK_RELEASE,
        BPF_CGROUP_INET4_POST_BIND => CGROUP_INET4_POST_BIND,
        BPF_CGROUP_INET6_POST_BIND => CGROUP_INET6_POST_BIND,
        BPF_CGROUP_DEVICE => CGROUP_DEVICE,
        _ => return None,
    })
}

/// The most programs in one list, `BPF_CGROUP_MAX_PROGS` of Linux.
pub const BPF_CGROUP_MAX_PROGS: usize = 64;

/// One program of a list, `struct bpf_prog_list` of Linux.
#[derive(Clone)]
struct ProgList {
    /// The program. For a link it is the program of the link.
    prog: Arc<BpfProg>,
    /// The ID of the link, or 0 for a program that `BPF_PROG_ATTACH` attached.
    link: u32,
    /// The flags of the attach.
    flags: u32,
}

/// The programs of a cgroup, `struct cgroup_bpf` of Linux without the effective arrays.
#[derive(Default)]
struct CgroupBpf {
    progs: [Vec<ProgList>; MAX_CGROUP_BPF_ATTACH_TYPE],
    flags: [u32; MAX_CGROUP_BPF_ATTACH_TYPE],
    revisions: [u64; MAX_CGROUP_BPF_ATTACH_TYPE],
}

/// The programs of all cgroups. The lock is `cgroup_mutex` of Linux for the programs.
static CGROUPS: SpinLock<BTreeMap<CgId, CgroupBpf>> = SpinLock::new(BTreeMap::new());

/// The count of the attached programs of each attach type, `cgroup_bpf_enabled_key` of Linux.
static ENABLED: [AtomicU32; MAX_CGROUP_BPF_ATTACH_TYPE] =
    [const { AtomicU32::new(0) }; MAX_CGROUP_BPF_ATTACH_TYPE];

/// Tells if a cgroup has a program of the attach type `atype`, `cgroup_bpf_enabled` of Linux.
pub fn cgroup_bpf_enabled(atype: usize) -> bool {
    ENABLED.get(atype).is_some_and(|n| n.load(Ordering::Relaxed) != 0)
}

/// The cgroup `id` and its ancestors, from `id` to the root.
fn ancestors(env: &dyn CgroupEnv, id: CgId) -> Vec<CgId> {
    let mut out = alloc::vec![id];
    let mut p = id;
    while let Some(q) = env.cgroup_parent(p) {
        out.push(q);
        p = q;
    }
    out
}

/// The flags of `atype` in the cgroup `id`.
fn flags_of(cgroups: &BTreeMap<CgId, CgroupBpf>, id: CgId, atype: usize) -> u32 {
    cgroups.get(&id).map_or(0, |c| c.flags[atype])
}

/// The list of `atype` in the cgroup `id`.
fn list_of(cgroups: &BTreeMap<CgId, CgroupBpf>, id: CgId, atype: usize) -> &[ProgList] {
    cgroups.get(&id).map_or(&[], |c| &c.progs[atype])
}

/// Tells if the ancestors of a cgroup let it have a program, `hierarchy_allows_attach` of Linux.
/// A parent with one program that does not allow the override stops the attach.
fn hierarchy_allows_attach(
    cgroups: &BTreeMap<CgId, CgroupBpf>,
    chain: &[CgId],
    atype: usize,
) -> bool {
    for &p in &chain[1..] {
        let flags = flags_of(cgroups, p, atype);
        if flags & BPF_F_ALLOW_MULTI != 0 {
            return true;
        }
        if list_of(cgroups, p, atype).len() == 1 {
            return flags & BPF_F_ALLOW_OVERRIDE != 0;
        }
    }
    true
}

/// The effective programs of the first cgroup of `chain`, `compute_effective_progs` of Linux.
/// The programs of the cgroup come first, and then the programs of each ancestor with
/// `BPF_F_ALLOW_MULTI`. An ancestor without it adds its programs only if no cgroup below it has
/// one. The programs with `BPF_F_PREORDER` come before all others, the ones of the ancestors
/// first.
fn compute_effective_progs(
    cgroups: &BTreeMap<CgId, CgroupBpf>,
    chain: &[CgId],
    atype: usize,
) -> Vec<Arc<BpfProg>> {
    let mut pre: Vec<Vec<Arc<BpfProg>>> = Vec::new();
    let mut post = Vec::new();
    let mut cnt = 0;
    for &p in chain {
        if cnt > 0 && flags_of(cgroups, p, atype) & BPF_F_ALLOW_MULTI == 0 {
            continue;
        }
        let mut level = Vec::new();
        for pl in list_of(cgroups, p, atype) {
            if pl.flags & BPF_F_PREORDER != 0 {
                level.push(pl.prog.clone());
            } else {
                post.push(pl.prog.clone());
            }
            cnt += 1;
        }
        pre.push(level);
    }
    let mut out: Vec<Arc<BpfProg>> = pre.into_iter().rev().flatten().collect();
    out.extend(post);
    out
}

/// The effective programs of `atype` in the cgroup `id`, for a hook and for
/// `BPF_F_QUERY_EFFECTIVE`.
pub fn cgroup_bpf_effective(env: &dyn CgroupEnv, id: CgId, atype: usize) -> Vec<Arc<BpfProg>> {
    if !cgroup_bpf_enabled(atype) {
        return Vec::new();
    }
    let chain = ancestors(env, id);
    compute_effective_progs(&CGROUPS.lock(), &chain, atype)
}

/// Runs the effective programs of `atype` in the cgroup `id` with `run`, as
/// `bpf_prog_run_array_cg` of Linux. Gives 0 if each program gives 1 in bit 0, and `EPERM`
/// else. `run` gives the return value of a program.
pub fn bpf_prog_run_array_cg(
    env: &dyn CgroupEnv,
    id: CgId,
    atype: usize,
    mut run: impl FnMut(&BpfProg) -> u64,
) -> Result<()> {
    let mut ok = true;
    for prog in cgroup_bpf_effective(env, id, atype) {
        ok &= run(&prog) & 1 != 0;
    }
    if ok { Ok(()) } else { Err(Errno::EPERM) }
}

/// What an attach puts in a list: a program or a link.
enum Attach<'a> {
    Prog(Arc<BpfProg>),
    Link(&'a BpfLink),
}

/// The place for a new program, as `find_attach_entry` of Linux. `Some(i)` replaces the program
/// at `i`.
fn find_attach_entry(
    progs: &[ProgList],
    what: &Attach<'_>,
    replace: Option<&Arc<BpfProg>>,
    allow_multi: bool,
) -> Result<Option<usize>> {
    if !allow_multi {
        return Ok(if progs.is_empty() { None } else { Some(0) });
    }
    for pl in progs {
        match what {
            Attach::Prog(prog)
                if pl.link == 0
                    && Arc::ptr_eq(&pl.prog, prog)
                    && !replace.is_some_and(|r| Arc::ptr_eq(r, prog)) =>
            {
                return Err(Errno::EINVAL);
            }
            Attach::Link(link) if pl.link == link.id() => return Err(Errno::EINVAL),
            _ => {}
        }
    }
    if let Some(replace) = replace {
        return progs
            .iter()
            .position(|pl| pl.link == 0 && Arc::ptr_eq(&pl.prog, replace))
            .map(Some)
            .ok_or(Errno::ENOENT);
    }
    Ok(None)
}

/// The anchor of `BPF_F_BEFORE` and `BPF_F_AFTER`, from `relative_fd` or `relative_id`.
pub enum Anchor {
    /// A program, `bpf_get_anchor_prog` of Linux.
    Prog(Arc<BpfProg>),
    /// A link, `bpf_get_anchor_link` of Linux.
    Link(Arc<BpfLink>),
}

/// Finds the anchor of `relative_fd` or `relative_id`. The arguments are the flags and the
/// descriptor or the ID.
pub type GetAnchor<'a> = &'a dyn Fn(u32, u32) -> Result<Anchor>;

/// The checks of the flags and the anchor of `get_prog_list` of Linux. The call finds the
/// anchor before it locks the lists, because the drop of a link takes the lock.
fn get_anchor_checked(
    is_link_attach: bool,
    flags: u32,
    id_or_fd: u32,
    get_anchor: GetAnchor<'_>,
) -> Result<Option<Anchor>> {
    let is_link = flags & BPF_F_LINK != 0;
    if !is_link && flags & BPF_F_ID == 0 && id_or_fd == 0 {
        return Ok(None);
    }
    // The flags must have one of `BPF_F_BEFORE` and `BPF_F_AFTER`.
    if (flags & BPF_F_BEFORE != 0) == (flags & BPF_F_AFTER != 0) || is_link != is_link_attach {
        return Err(Errno::EINVAL);
    }
    match get_anchor(flags, id_or_fd)? {
        Anchor::Prog(p) if !is_link => Ok(Some(Anchor::Prog(p))),
        Anchor::Link(l) if is_link => Ok(Some(Anchor::Link(l))),
        _ => Err(Errno::EINVAL),
    }
}

/// The index of the new entry in `progs`, as `get_prog_list` and `insert_pl_to_hlist` of Linux.
fn insert_pos(progs: &[ProgList], flags: u32, anchor: Option<&Anchor>) -> Result<usize> {
    let is_before = flags & BPF_F_BEFORE != 0;
    let found = match anchor {
        None => {
            if !progs.is_empty() && is_before && flags & BPF_F_AFTER != 0 {
                return Err(Errno::EINVAL);
            }
            // Without an anchor a program goes first with `BPF_F_BEFORE`, else last.
            return Ok(if is_before { 0 } else { progs.len() });
        }
        Some(Anchor::Prog(p)) => {
            progs.iter().position(|pl| pl.link == 0 && Arc::ptr_eq(&pl.prog, p))
        }
        Some(Anchor::Link(l)) => progs.iter().position(|pl| pl.link == l.id()),
    };
    let i = found.ok_or(Errno::ENOENT)?;
    if (progs[i].flags & BPF_F_PREORDER != 0) != (flags & BPF_F_PREORDER != 0) {
        return Err(Errno::EINVAL);
    }
    Ok(if is_before { i } else { i + 1 })
}

/// The arguments of an attach.
pub struct AttachArgs<'a> {
    /// The cgroup.
    pub cgrp: CgId,
    /// The program for `BPF_PROG_ATTACH`, or `None` for a link.
    pub prog: Option<Arc<BpfProg>>,
    /// The program of `replace_bpf_fd`, with `BPF_F_REPLACE`.
    pub replace_prog: Option<Arc<BpfProg>>,
    /// The link for `BPF_LINK_CREATE`.
    pub link: Option<&'a BpfLink>,
    /// The attach type.
    pub attach_type: u32,
    /// The flags.
    pub flags: u32,
    /// `relative_fd` or `relative_id`.
    pub relative: u32,
    /// Finds the anchor of `relative`.
    pub get_anchor: GetAnchor<'a>,
    /// `expected_revision`, or 0.
    pub revision: u64,
}

/// Attaches a program or a link to a cgroup, `__cgroup_bpf_attach` of Linux.
pub fn cgroup_bpf_attach(env: &dyn CgroupEnv, a: AttachArgs<'_>) -> Result<()> {
    let flags = a.flags;
    let saved_flags = flags & (BPF_F_ALLOW_OVERRIDE | BPF_F_ALLOW_MULTI);
    if (flags & BPF_F_ALLOW_OVERRIDE != 0 && flags & BPF_F_ALLOW_MULTI != 0)
        || (flags & BPF_F_REPLACE != 0 && flags & BPF_F_ALLOW_MULTI == 0)
        || (flags & BPF_F_REPLACE != 0 && flags & (BPF_F_BEFORE | BPF_F_AFTER) != 0)
    {
        return Err(Errno::EINVAL);
    }
    let what = match (&a.prog, a.link) {
        (Some(p), None) => Attach::Prog(p.clone()),
        (None, Some(l)) if a.replace_prog.is_none() => Attach::Link(l),
        _ => return Err(Errno::EINVAL),
    };
    if a.replace_prog.is_some() != (flags & BPF_F_REPLACE != 0) {
        return Err(Errno::EINVAL);
    }
    let new_prog = match &what {
        Attach::Prog(p) => p.clone(),
        Attach::Link(l) => l.prog().ok_or(Errno::ENOLINK)?,
    };
    let atype = to_cgroup_bpf_attach_type(a.attach_type).ok_or(Errno::EINVAL)?;
    let anchor = get_anchor_checked(a.link.is_some(), flags, a.relative, a.get_anchor)?;
    let chain = ancestors(env, a.cgrp);
    let mut cgroups = CGROUPS.lock();
    let cur = cgroups.get(&a.cgrp);
    if a.revision != 0 && a.revision != cur.map_or(0, |c| c.revisions[atype]) {
        return Err(Errno::ESTALE);
    }
    if !hierarchy_allows_attach(&cgroups, &chain, atype) {
        return Err(Errno::EPERM);
    }
    let progs = list_of(&cgroups, a.cgrp, atype);
    if !progs.is_empty() && flags_of(&cgroups, a.cgrp, atype) != saved_flags {
        // An attach without the override on top of one with it, or of several programs on
        // top of one, is not allowed.
        return Err(Errno::EPERM);
    }
    if progs.len() >= BPF_CGROUP_MAX_PROGS {
        return Err(Errno::E2BIG);
    }
    let entry =
        find_attach_entry(progs, &what, a.replace_prog.as_ref(), flags & BPF_F_ALLOW_MULTI != 0)?;
    let pos = match entry {
        Some(_) => None,
        None => Some(insert_pos(progs, flags, anchor.as_ref())?),
    };
    let link = match what {
        Attach::Link(l) => l.id(),
        Attach::Prog(_) => 0,
    };
    let pl = ProgList { prog: new_prog, link, flags };
    let c = cgroups.entry(a.cgrp).or_default();
    match (entry, pos) {
        (Some(i), _) => c.progs[atype][i] = pl,
        (None, Some(i)) => {
            c.progs[atype].insert(i, pl);
            ENABLED[atype].fetch_add(1, Ordering::Relaxed);
        }
        (None, None) => {}
    }
    c.flags[atype] = saved_flags;
    c.revisions[atype] += 1;
    Ok(())
}

/// Detaches a program or a link from a cgroup, `__cgroup_bpf_detach` of Linux. Without
/// `BPF_F_ALLOW_MULTI` the call detaches the only program, and a caller without the program
/// needs `net_admin`.
fn cgroup_bpf_detach_locked(
    cgroups: &mut BTreeMap<CgId, CgroupBpf>,
    cgrp: CgId,
    prog: Option<&Arc<BpfProg>>,
    link: u32,
    atype: usize,
    revision: u64,
    net_admin: bool,
) -> Result<()> {
    let c = cgroups.get_mut(&cgrp);
    let (progs, flags, rev) = match &c {
        Some(c) => (&c.progs[atype][..], c.flags[atype], c.revisions[atype]),
        None => (&[][..], 0, 0),
    };
    if revision != 0 && revision != rev {
        return Err(Errno::ESTALE);
    }
    // `find_detach_entry`.
    let i = if flags & BPF_F_ALLOW_MULTI == 0 {
        let first = progs.first().ok_or(Errno::ENOENT)?;
        let same = link == 0 && prog.is_some_and(|p| Arc::ptr_eq(p, &first.prog));
        let same_link = link != 0 && first.link == link;
        if !same && !same_link && !net_admin {
            return Err(Errno::EPERM);
        }
        0
    } else {
        if prog.is_none() && link == 0 {
            return Err(Errno::EINVAL);
        }
        progs
            .iter()
            .position(|pl| {
                pl.link == link && (link != 0 || prog.is_some_and(|p| Arc::ptr_eq(p, &pl.prog)))
            })
            .ok_or(Errno::ENOENT)?
    };
    let c = c.ok_or(Errno::ENOENT)?;
    c.progs[atype].remove(i);
    c.revisions[atype] += 1;
    if c.progs[atype].is_empty() {
        c.flags[atype] = 0;
    }
    ENABLED[atype].fetch_sub(1, Ordering::Relaxed);
    Ok(())
}

/// `BPF_PROG_DETACH` of a cgroup program, `cgroup_bpf_detach` of Linux. `prog` is the program
/// of `attach_bpf_fd`, or `None` for a bad descriptor.
pub fn cgroup_bpf_detach(
    cgrp: CgId,
    prog: Option<&Arc<BpfProg>>,
    attach_type: u32,
    revision: u64,
    net_admin: bool,
) -> Result<()> {
    let atype = to_cgroup_bpf_attach_type(attach_type).ok_or(Errno::EINVAL)?;
    cgroup_bpf_detach_locked(&mut CGROUPS.lock(), cgrp, prog, 0, atype, revision, net_admin)
}

/// The offsets of the `query` struct of `union bpf_attr`.
#[allow(missing_docs)]
pub mod query {
    pub const TARGET_FD: usize = 0;
    pub const ATTACH_TYPE: usize = 4;
    pub const QUERY_FLAGS: usize = 8;
    pub const ATTACH_FLAGS: usize = 12;
    pub const PROG_IDS: usize = 16;
    pub const PROG_CNT: usize = 24;
    pub const PROG_ATTACH_FLAGS: usize = 32;
    pub const REVISION: usize = 56;
}

/// `BPF_F_QUERY_EFFECTIVE`: the query gives the effective programs.
pub const BPF_F_QUERY_EFFECTIVE: u32 = 1;

/// The result of a query, for `__cgroup_bpf_query` of Linux.
pub struct QueryResult {
    /// `attach_flags`: the flags of the cgroup, or 0 for an effective query.
    pub attach_flags: u32,
    /// `prog_cnt`: the count of the programs.
    pub prog_cnt: u32,
    /// `revision`.
    pub revision: u64,
    /// The IDs of the programs.
    pub prog_ids: Vec<u32>,
    /// The flags of each program, for `prog_attach_flags`.
    pub prog_attach_flags: Vec<u32>,
}

/// The programs of `attach_type` in the cgroup `cgrp`, as `__cgroup_bpf_query` of Linux.
pub fn cgroup_bpf_query(
    env: &dyn CgroupEnv,
    cgrp: CgId,
    attach_type: u32,
    effective: bool,
) -> Result<QueryResult> {
    let atype = to_cgroup_bpf_attach_type(attach_type).ok_or(Errno::EINVAL)?;
    let chain = ancestors(env, cgrp);
    let cgroups = CGROUPS.lock();
    if effective {
        let progs = compute_effective_progs(&cgroups, &chain, atype);
        return Ok(QueryResult {
            attach_flags: 0,
            prog_cnt: progs.len() as u32,
            revision: 0,
            prog_ids: progs.iter().map(|p| p.id).collect(),
            prog_attach_flags: Vec::new(),
        });
    }
    let flags = flags_of(&cgroups, cgrp, atype);
    let progs = list_of(&cgroups, cgrp, atype);
    Ok(QueryResult {
        attach_flags: flags,
        prog_cnt: progs.len() as u32,
        revision: cgroups.get(&cgrp).map_or(0, |c| c.revisions[atype]),
        prog_ids: progs.iter().map(|pl| pl.prog.id).collect(),
        prog_attach_flags: progs.iter().map(|pl| flags | (pl.flags & BPF_F_PREORDER)).collect(),
    })
}

/// Takes the programs of a removed cgroup away, as `cgroup_bpf_offline` and
/// `cgroup_bpf_release` of Linux. The links of the cgroup stay, without a cgroup.
pub fn cgroup_bpf_offline(cgrp: CgId) {
    let Some(c) = CGROUPS.lock().remove(&cgrp) else {
        return;
    };
    for (atype, list) in c.progs.iter().enumerate() {
        ENABLED[atype].fetch_sub(list.len() as u32, Ordering::Relaxed);
    }
}

/// The link of a cgroup, `struct bpf_cgroup_link` of Linux.
pub struct BpfCgroupLink {
    /// The cgroup.
    cgrp: CgId,
    /// The ID of the cgroup for the info of the link.
    cgroup_id: u64,
}

impl BpfCgroupLink {
    /// Tells if the cgroup still has the link. A removed cgroup lets its links go, as
    /// `bpf_cgroup_link_auto_detach` of Linux.
    fn attached(&self, link: &BpfLink) -> Option<usize> {
        let atype = to_cgroup_bpf_attach_type(link.attach_type)?;
        let cgroups = CGROUPS.lock();
        list_of(&cgroups, self.cgrp, atype).iter().any(|pl| pl.link == link.id()).then_some(atype)
    }
}

impl BpfLinkOps for BpfCgroupLink {
    /// `bpf_cgroup_link_release`.
    fn release(&self, link: &BpfLink) {
        let Some(atype) = to_cgroup_bpf_attach_type(link.attach_type) else {
            return;
        };
        let mut cgroups = CGROUPS.lock();
        let _ = cgroup_bpf_detach_locked(&mut cgroups, self.cgrp, None, link.id(), atype, 0, true);
    }

    /// `bpf_cgroup_link_detach`.
    fn detach(&self, link: &BpfLink) -> Result<()> {
        link.release_once();
        Ok(())
    }

    /// `cgroup_bpf_replace` and `__cgroup_bpf_replace`.
    fn update_prog(
        &self,
        link: &BpfLink,
        new: Arc<BpfProg>,
        old: Option<&Arc<BpfProg>>,
    ) -> Result<()> {
        let atype = to_cgroup_bpf_attach_type(link.attach_type).ok_or(Errno::EINVAL)?;
        let mut cgroups = CGROUPS.lock();
        let cur = link.prog().ok_or(Errno::ENOLINK)?;
        let c = cgroups.get_mut(&self.cgrp).ok_or(Errno::ENOLINK)?;
        if old.is_some_and(|o| !Arc::ptr_eq(o, &cur)) {
            return Err(Errno::EPERM);
        }
        if cur.prog_type != new.prog_type {
            return Err(Errno::EINVAL);
        }
        let pl = c.progs[atype].iter_mut().find(|pl| pl.link == link.id()).ok_or(Errno::ENOENT)?;
        pl.prog = new.clone();
        c.revisions[atype] += 1;
        link.set_prog(Some(new));
        Ok(())
    }

    /// `bpf_cgroup_link_fill_link_info`.
    fn fill_link_info(&self, link: &BpfLink, info: &mut [u8; BPF_LINK_INFO_SIZE]) -> Result<()> {
        let id = if self.attached(link).is_some() { self.cgroup_id } else { 0 };
        let u = link_info::UNION;
        info[u..u + 8].copy_from_slice(&id.to_ne_bytes());
        info[u + 8..u + 12].copy_from_slice(&link.attach_type.to_ne_bytes());
        Ok(())
    }

    /// `bpf_cgroup_link_show_fdinfo`.
    fn show_fdinfo(&self, link: &BpfLink, out: &mut String) {
        let id = if self.attached(link).is_some() { self.cgroup_id } else { 0 };
        out.push_str(&format!("cgroup_id:\t{id}\nattach_type:\t{}\n", link.attach_type));
    }
}

/// The flags of `BPF_LINK_CREATE` for a cgroup, `BPF_F_LINK_ATTACH_MASK` of Linux.
pub const BPF_F_LINK_ATTACH_MASK: u32 =
    BPF_F_ID | BPF_F_BEFORE | BPF_F_AFTER | BPF_F_PREORDER | BPF_F_LINK;

/// Makes a link of `prog` in the cgroup `cgrp`, `cgroup_bpf_link_attach` of Linux. `settle`
/// gives the link its ID before the attach.
#[allow(clippy::too_many_arguments)]
pub fn cgroup_bpf_link_attach(
    env: &dyn CgroupEnv,
    cgrp: CgId,
    prog: Arc<BpfProg>,
    attach_type: u32,
    flags: u32,
    relative: u32,
    get_anchor: GetAnchor<'_>,
    revision: u64,
    settle: impl FnOnce(&Arc<BpfLink>) -> Result<u32>,
) -> Result<Arc<BpfLink>> {
    if flags & !BPF_F_LINK_ATTACH_MASK != 0 {
        return Err(Errno::EINVAL);
    }
    let ops = BpfCgroupLink { cgrp, cgroup_id: env.cgroup_id(cgrp) };
    let link =
        Arc::new(BpfLink::new(link_type::BPF_LINK_TYPE_CGROUP, Box::new(ops), prog, attach_type));
    settle(&link)?;
    cgroup_bpf_attach(
        env,
        AttachArgs {
            cgrp,
            prog: None,
            replace_prog: None,
            link: Some(&link),
            attach_type,
            flags: BPF_F_ALLOW_MULTI | flags,
            relative,
            get_anchor,
            revision,
        },
    )?;
    Ok(link)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::bpf_link_settle;

    /// The cgroups `base`, `base + 1` and `base + 2`, each one the child of the one before.
    struct Chain(CgId);

    impl CgroupEnv for Chain {
        fn cgroup_parent(&self, id: CgId) -> Option<CgId> {
            (id > self.0).then(|| id - 1)
        }

        fn cgroup_id(&self, id: CgId) -> u64 {
            u64::from(id) + 100
        }
    }

    fn prog(id: u32) -> Arc<BpfProg> {
        Arc::new(BpfProg {
            prog_type: crate::prog::prog_type::BPF_PROG_TYPE_CGROUP_SKB,
            expected_attach_type: 0,
            insns: Vec::new(),
            used_maps: Vec::new(),
            id,
            name: [0; 16],
            tag: [0; 8],
            gpl_compatible: true,
            verified_insns: 0,
            run_cnt: core::sync::atomic::AtomicU64::new(0),
            load_time: 0,
            uid: 0,
            enforce_expected_attach_type: false,
        })
    }

    fn no_anchor(_flags: u32, _id_or_fd: u32) -> Result<Anchor> {
        Err(Errno::EBADF)
    }

    fn attach(env: &Chain, cgrp: CgId, p: &Arc<BpfProg>, flags: u32) -> Result<()> {
        cgroup_bpf_attach(
            env,
            AttachArgs {
                cgrp,
                prog: Some(p.clone()),
                replace_prog: None,
                link: None,
                attach_type: BPF_CGROUP_INET_EGRESS,
                flags,
                relative: 0,
                get_anchor: &no_anchor,
                revision: 0,
            },
        )
    }

    fn effective(env: &Chain, cgrp: CgId) -> Vec<u32> {
        cgroup_bpf_query(env, cgrp, BPF_CGROUP_INET_EGRESS, true).unwrap().prog_ids
    }

    #[test]
    fn the_effective_programs_follow_the_flags_of_the_ancestors() {
        let env = Chain(1000);
        let (a, b, c) = (prog(9001), prog(9002), prog(9003));
        attach(&env, 1000, &a, BPF_F_ALLOW_MULTI).unwrap();
        attach(&env, 1001, &b, BPF_F_ALLOW_OVERRIDE).unwrap();
        assert_eq!(effective(&env, 1002), [9002, 9001]);
        // A program without the override in 1001 stops the attach in 1002.
        attach(&env, 1001, &b, 0).unwrap_err();
        attach(&env, 1002, &c, 0).unwrap();
        assert_eq!(effective(&env, 1002), [9003, 9001]);
        assert_eq!(attach(&env, 1002, &a, BPF_F_ALLOW_MULTI), Err(Errno::EPERM));
        let q = cgroup_bpf_query(&env, 1001, BPF_CGROUP_INET_EGRESS, false).unwrap();
        assert_eq!((q.attach_flags, q.prog_cnt, q.revision), (BPF_F_ALLOW_OVERRIDE, 1, 1));
        assert_eq!(
            cgroup_bpf_detach(1001, None, BPF_CGROUP_INET_EGRESS, 0, false),
            Err(Errno::EPERM)
        );
        cgroup_bpf_detach(1001, Some(&b), BPF_CGROUP_INET_EGRESS, 0, false).unwrap();
        assert_eq!(effective(&env, 1001), [9001]);
        cgroup_bpf_offline(1002);
        cgroup_bpf_offline(1000);
        assert_eq!(effective(&env, 1002), [] as [u32; 0]);
    }

    #[test]
    fn a_multi_list_rejects_a_program_twice_and_can_replace() {
        let env = Chain(2000);
        let (a, b) = (prog(9011), prog(9012));
        attach(&env, 2000, &a, BPF_F_ALLOW_MULTI).unwrap();
        assert_eq!(attach(&env, 2000, &a, BPF_F_ALLOW_MULTI), Err(Errno::EINVAL));
        assert_eq!(attach(&env, 2000, &b, BPF_F_ALLOW_OVERRIDE), Err(Errno::EPERM));
        assert_eq!(attach(&env, 2000, &b, BPF_F_REPLACE), Err(Errno::EINVAL));
        cgroup_bpf_attach(
            &env,
            AttachArgs {
                cgrp: 2000,
                prog: Some(b.clone()),
                replace_prog: Some(a.clone()),
                link: None,
                attach_type: BPF_CGROUP_INET_EGRESS,
                flags: BPF_F_ALLOW_MULTI | BPF_F_REPLACE,
                relative: 0,
                get_anchor: &no_anchor,
                revision: 1,
            },
        )
        .unwrap();
        assert_eq!(effective(&env, 2000), [9012]);
        let get = |_: u32, _: u32| Ok(Anchor::Prog(b.clone()));
        cgroup_bpf_attach(
            &env,
            AttachArgs {
                cgrp: 2000,
                prog: Some(a.clone()),
                replace_prog: None,
                link: None,
                attach_type: BPF_CGROUP_INET_EGRESS,
                flags: BPF_F_ALLOW_MULTI | BPF_F_BEFORE,
                relative: 5,
                get_anchor: &get,
                revision: 0,
            },
        )
        .unwrap();
        assert_eq!(effective(&env, 2000), [9011, 9012]);
        assert_eq!(
            cgroup_bpf_detach(2000, None, BPF_CGROUP_INET_EGRESS, 0, true),
            Err(Errno::EINVAL)
        );
        cgroup_bpf_detach(2000, Some(&a), BPF_CGROUP_INET_EGRESS, 0, false).unwrap();
        cgroup_bpf_detach(2000, Some(&b), BPF_CGROUP_INET_EGRESS, 0, false).unwrap();
        let q = cgroup_bpf_query(&env, 2000, BPF_CGROUP_INET_EGRESS, false).unwrap();
        assert_eq!((q.attach_flags, q.prog_cnt, q.revision), (0, 0, 5));
    }

    #[test]
    fn a_link_detaches_when_it_is_dropped() {
        let env = Chain(3000);
        let a = prog(9021);
        let link = cgroup_bpf_link_attach(
            &env,
            3000,
            a.clone(),
            BPF_CGROUP_INET_EGRESS,
            0,
            0,
            &no_anchor,
            0,
            bpf_link_settle,
        )
        .unwrap();
        assert_eq!(effective(&env, 3001), [9021]);
        let mut info = [0u8; BPF_LINK_INFO_SIZE];
        link.fill_info(&mut info).unwrap();
        assert_eq!(info[16..24], 3100u64.to_ne_bytes());
        let b = prog(9022);
        link.ops.update_prog(&link, b.clone(), Some(&a)).unwrap();
        assert_eq!(effective(&env, 3000), [9022]);
        assert_eq!(link.ops.update_prog(&link, a.clone(), Some(&a)), Err(Errno::EPERM));
        drop(link);
        assert_eq!(effective(&env, 3000), [] as [u32; 0]);
    }
}

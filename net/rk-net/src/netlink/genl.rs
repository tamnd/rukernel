//! Generic netlink, the protocol `NETLINK_GENERIC`, as net/netlink/genetlink.c of Linux.
//!
//! A family of generic netlink has a name, an ID that the kernel gives at registration, its
//! commands and its multicast groups. The message type of a request is the ID of the family,
//! and the payload starts with `struct genlmsghdr`, which has the command. The family `nlctrl`
//! has the ID `GENL_ID_CTRL`. A program asks it for the ID and the groups of a family by its
//! name, with `CTRL_CMD_GETFAMILY`.

use super::msg::{self, Attrs, Builder, HDRLEN, Header};
use super::policy::{self, Kind, Policy};
use super::{Flow, NetlinkSocket, Request, broadcast, net_admin};
use alloc::vec::Vec;
use core::cell::Cell;
use rk_abi::Errno;
use rk_abi::native::netlink::{
    NETLINK_GENERIC, NLM_F_ACK, NLM_F_DUMP, NLM_F_ECHO, NLM_F_MULTI, NLM_F_REQUEST,
};
use rk_frame::sync::SpinLock;
use rk_vfs::cred::{self, cap};
use rk_vfs::inode::Result;

/// The size of `struct genlmsghdr`, `GENL_HDRLEN`.
pub const GENL_HDRLEN: usize = 4;

// The flags of a command, `GENL_*` of <linux/genetlink.h>. rk-abigen does not take this header
// yet, so the values are written by hand.
/// The command needs `CAP_NET_ADMIN`.
pub const GENL_ADMIN_PERM: u32 = 0x01;
/// The command has a handler for one object.
const GENL_CMD_CAP_DO: u32 = 0x02;
/// The command has a handler for a dump.
const GENL_CMD_CAP_DUMP: u32 = 0x04;
/// The command has a policy.
const GENL_CMD_CAP_HASPOL: u32 = 0x08;
/// The command needs `CAP_NET_ADMIN` in the user namespace of the network namespace.
pub const GENL_UNS_ADMIN_PERM: u32 = 0x10;

// The checks that a command does not do, `GENL_DONT_VALIDATE_*` of include/net/genetlink.h.
/// A request for one object has the liberal checks.
pub const GENL_DONT_VALIDATE_STRICT: u8 = 1 << 0;
/// A dump has no checks of its attributes.
pub const GENL_DONT_VALIDATE_DUMP: u8 = 1 << 1;
/// A dump has the liberal checks.
pub const GENL_DONT_VALIDATE_DUMP_STRICT: u8 = 1 << 2;

/// A group needs `CAP_NET_ADMIN`, `GENL_MCAST_CAP_NET_ADMIN`.
pub const GENL_MCAST_CAP_NET_ADMIN: u8 = 1 << 0;
/// A group needs `CAP_SYS_ADMIN`, `GENL_MCAST_CAP_SYS_ADMIN`.
pub const GENL_MCAST_CAP_SYS_ADMIN: u8 = 1 << 1;

/// The ID of the family `nlctrl` and of its group `notify`, `GENL_ID_CTRL`.
pub const GENL_ID_CTRL: u16 = 0x10;
/// The IDs of two old families that keep their IDs, `GENL_ID_VFS_DQUOT` and `GENL_ID_PMCRAID`.
const GENL_ID_VFS_DQUOT: u16 = GENL_ID_CTRL + 1;
const GENL_ID_PMCRAID: u16 = GENL_ID_CTRL + 2;
/// The first ID that a family gets, `GENL_START_ALLOC`.
const GENL_START_ALLOC: u16 = GENL_ID_CTRL + 3;
/// The last ID, `GENL_MAX_ID`.
const GENL_MAX_ID: u16 = 1023;
/// The size of the name of a family or a group with its NUL byte, `GENL_NAMSIZ`.
const GENL_NAMSIZ: u16 = 16;

/// The number of multicast groups of a socket of the protocol, `mc_groups_longs *
/// BITS_PER_LONG` of Linux.
pub(super) const NGROUPS: u32 = 64;

// The commands of `nlctrl`, `CTRL_CMD_*` of <linux/genetlink.h>.
const CTRL_CMD_NEWFAMILY: u8 = 1;
const CTRL_CMD_GETFAMILY: u8 = 3;

// The attributes of `nlctrl`, `CTRL_ATTR_*`.
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const CTRL_ATTR_VERSION: u16 = 3;
const CTRL_ATTR_HDRSIZE: u16 = 4;
const CTRL_ATTR_MAXATTR: u16 = 5;
const CTRL_ATTR_OPS: u16 = 6;
const CTRL_ATTR_MCAST_GROUPS: u16 = 7;

// The attributes of a command, `CTRL_ATTR_OP_*`.
const CTRL_ATTR_OP_ID: u16 = 1;
const CTRL_ATTR_OP_FLAGS: u16 = 2;

// The attributes of a group, `CTRL_ATTR_MCAST_GRP_*`.
const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;

/// The handler of a request for one object, as `doit` of Linux.
pub type DoIt = fn(&Info<'_>) -> Result<()>;

/// The handler of a dump. It gives all of the messages of the dump.
pub type DumpIt = fn(&Info<'_>) -> Result<Vec<Vec<u8>>>;

/// A command of a family, as `struct genl_ops` of Linux.
pub struct Op {
    /// The command.
    pub cmd: u8,
    /// `GENL_ADMIN_PERM` or `GENL_UNS_ADMIN_PERM`, or 0.
    pub flags: u32,
    /// The `GENL_DONT_VALIDATE_*` flags.
    pub validate: u8,
    /// The policy of the attributes. The type 0 is in the slice.
    pub policy: Option<&'static [Policy]>,
    /// The handler of a request for one object.
    pub doit: Option<DoIt>,
    /// The handler of a dump.
    pub dumpit: Option<DumpIt>,
}

/// A multicast group of a family, as `struct genl_multicast_group` of Linux.
pub struct McGroup {
    /// The name.
    pub name: &'static str,
    /// The `GENL_MCAST_CAP_*` flags.
    pub flags: u8,
}

/// A family, as `struct genl_family` of Linux.
pub struct Family {
    /// The name, at most 15 bytes.
    pub name: &'static str,
    /// The version.
    pub version: u8,
    /// The size of the fixed header of the family after `struct genlmsghdr`.
    pub hdrsize: u32,
    /// The largest attribute type.
    pub maxattr: u32,
    /// The commands from this one on have the strict checks of `struct genlmsghdr` and a
    /// policy that rejects all attributes if they have no policy, `resv_start_op`.
    pub resv_start_op: u8,
    /// The commands.
    pub ops: &'static [Op],
    /// The multicast groups.
    pub mcgrps: &'static [McGroup],
}

/// A family that is registered.
#[derive(Clone, Copy)]
struct Entry {
    id: u16,
    family: &'static Family,
    /// The ID of the first group of the family, `mcgrp_offset`.
    mcgrp_offset: u32,
}

struct Registry {
    /// The families, by their ID.
    families: Vec<Entry>,
    /// The IDs of the groups that are in use. Bit `n` is the group `n`. Linux keeps the groups
    /// 0 and 1, and the groups of the three families with a fixed ID.
    groups: u64,
    /// The last ID that a family got, for the cyclic allocation of `idr_alloc_cyclic`.
    last_id: u16,
}

static REGISTRY: SpinLock<Registry> = SpinLock::new(Registry {
    families: Vec::new(),
    groups: 0x3 | 1 << GENL_ID_CTRL | 1 << GENL_ID_VFS_DQUOT | 1 << GENL_ID_PMCRAID,
    last_id: GENL_START_ALLOC - 1,
});

/// The policy of a command without a policy, `genl_policy_reject_all` of Linux.
static REJECT_ALL: [Policy; 1] = [Policy::of(Kind::Reject)];

impl Registry {
    fn by_id(&self, id: u16) -> Option<Entry> {
        self.families.iter().find(|e| e.id == id).copied()
    }

    fn by_name(&self, name: &[u8]) -> Option<Entry> {
        self.families.iter().find(|e| e.family.name.as_bytes() == name).copied()
    }

    /// The first free IDs for `n` groups, as `genl_allocate_reserve_groups` of Linux.
    fn reserve_groups(&mut self, n: u32) -> Option<u32> {
        let first =
            (0..=NGROUPS - n).find(|&id| (id..id + n).all(|g| self.groups & 1 << g == 0))?;
        for g in first..first + n {
            self.groups |= 1 << g;
        }
        Some(first)
    }
}

/// Registers the family `family`, as `genl_register_family` of Linux. Gives its ID. `nlctrl`
/// gets `GENL_ID_CTRL`, and another family gets the next free ID from `GENL_START_ALLOC` on.
///
/// # Errors
///
/// Gives `EEXIST` if a family has the name, and `ENOSPC` if no ID or group is free.
pub fn register(family: &'static Family) -> Result<u16> {
    let mut r = REGISTRY.lock();
    if r.by_name(family.name.as_bytes()).is_some() {
        return Err(Errno::EEXIST);
    }
    let id = if family.name == "nlctrl" {
        GENL_ID_CTRL
    } else {
        let free = |id: &u16| r.by_id(*id).is_none();
        let id = (r.last_id + 1..=GENL_MAX_ID)
            .find(free)
            .or_else(|| (GENL_START_ALLOC..=r.last_id).find(free))
            .ok_or(Errno::ENOSPC)?;
        r.last_id = id;
        id
    };
    let n = family.mcgrps.len() as u32;
    let mcgrp_offset = if n == 0 {
        0
    } else if id == GENL_ID_CTRL {
        u32::from(GENL_ID_CTRL)
    } else {
        r.reserve_groups(n).ok_or(Errno::ENOSPC)?
    };
    let at = r.families.partition_point(|e| e.id < id);
    r.families.insert(at, Entry { id, family, mcgrp_offset });
    Ok(id)
}

/// The ID of the family `name`, if it is registered.
pub fn family_id(name: &str) -> Option<u16> {
    REGISTRY.lock().by_name(name.as_bytes()).map(|e| e.id)
}

/// The ID of the multicast group `grp` of the family with the ID `id`.
fn group_id(id: u16, grp: usize) -> Option<u32> {
    let e = REGISTRY.lock().by_id(id)?;
    (grp < e.family.mcgrps.len()).then_some(e.mcgrp_offset + grp as u32)
}

/// Sends `msg` to the multicast group `grp` of the family with the ID `id`, as
/// `genlmsg_multicast_netns` of Linux.
pub fn multicast(id: u16, grp: usize, msg: Vec<u8>) {
    if let Some(group) = group_id(id, grp) {
        broadcast(NETLINK_GENERIC, None, &msg, 0, 0, group);
    }
}

/// Tells if a socket listens to the multicast group `grp` of the family with the ID `id`, as
/// `genl_has_listeners` of Linux.
pub fn has_listeners(id: u16, grp: usize) -> bool {
    group_id(id, grp).is_some_and(|g| super::listeners(NETLINK_GENERIC, g))
}

/// Starts a message of the family with the ID `id`, as `genlmsg_put` of Linux: the netlink
/// header and `struct genlmsghdr` with the command `cmd` and the version `version`.
pub fn message(id: u16, version: u8, cmd: u8, flags: u16, seq: u32, portid: u32) -> Builder {
    let mut b = Builder::new(id, flags, seq, portid);
    b.fixed(&[cmd, version, 0, 0]);
    b
}

/// Checks the join of a socket to the group `group`, as `genl_bind` of Linux.
pub(super) fn bind(group: u32) -> Result<()> {
    let r = REGISTRY.lock();
    let Some((e, i)) = r.families.iter().find_map(|e| {
        let i = group.checked_sub(e.mcgrp_offset)? as usize;
        (i < e.family.mcgrps.len()).then_some((e, i))
    }) else {
        return Ok(());
    };
    let flags = e.family.mcgrps[i].flags;
    if flags & GENL_MCAST_CAP_NET_ADMIN != 0 && !net_admin() {
        return Err(Errno::EPERM);
    }
    if flags & GENL_MCAST_CAP_SYS_ADMIN != 0 && !cred::current().capable(cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    Ok(())
}

/// A request to a family, as `struct genl_info` of Linux.
pub struct Info<'a> {
    /// The netlink request.
    pub req: &'a Request<'a>,
    /// The ID of the family.
    pub family: u16,
    /// The command.
    pub cmd: u8,
    /// The version in `struct genlmsghdr`.
    pub version: u8,
    /// The fixed header of the family after `struct genlmsghdr`.
    pub user_hdr: &'a [u8],
    /// The attributes, after the checks of the policy of the command. A command without a
    /// policy has none.
    pub attrs: Attrs<'a>,
}

/// The flags of a command for `nlctrl`, as `ctrl_fill_info` of Linux.
fn op_flags(f: &Family, op: &Op) -> u32 {
    let mut flags = op.flags;
    if op.doit.is_some() {
        flags |= GENL_CMD_CAP_DO;
    }
    if op.dumpit.is_some() {
        flags |= GENL_CMD_CAP_DUMP;
    }
    // A command without its own policy gets the policy that rejects all from
    // `resv_start_op` on. A dump with `GENL_DONT_VALIDATE_DUMP` has no policy.
    let policy = op.policy.is_some() || op.cmd >= f.resv_start_op;
    let do_pol = op.doit.is_some() && policy;
    let dump_pol = op.dumpit.is_some() && policy && op.validate & GENL_DONT_VALIDATE_DUMP == 0;
    if do_pol || dump_pol {
        flags |= GENL_CMD_CAP_HASPOL;
    }
    flags
}

/// The policy of a command, with the policy that rejects all for a command without one from
/// `resv_start_op` on.
fn op_policy(f: &Family, op: &Op) -> Option<&'static [Policy]> {
    op.policy.or((op.cmd >= f.resv_start_op).then_some(&REJECT_ALL[..]))
}

/// Checks `struct genlmsghdr` and the flags of a request, as `genl_header_check` of Linux.
fn header_check(req: &Request<'_>, f: &Family, cmd: u8, reserved: u16) -> Result<()> {
    if cmd < f.resv_start_op {
        return Ok(());
    }
    if reserved != 0 {
        return Err(req.error("genlmsghdr.reserved field is not 0", Errno::EINVAL));
    }
    let mut flags = req.hdr.flags;
    if flags & NLM_F_DUMP as u16 == NLM_F_DUMP as u16 {
        flags &= !(NLM_F_DUMP as u16);
    }
    if flags & !((NLM_F_REQUEST | NLM_F_ACK | NLM_F_ECHO) as u16) != 0 {
        return Err(req.error("ambiguous or reserved bits set in nlmsg_flags", Errno::EINVAL));
    }
    Ok(())
}

/// Runs one request, as `genl_rcv_msg` and `genl_family_rcv_msg` of Linux.
pub(super) fn rcv(
    sock: &NetlinkSocket,
    h: Header,
    m: &[u8],
    ext: &Cell<msg::ExtAck>,
) -> Result<Flow> {
    let Some(e) = REGISTRY.lock().by_id(h.ty) else {
        return Err(Errno::ENOENT);
    };
    let f = e.family;
    let hdrlen = GENL_HDRLEN + f.hdrsize as usize;
    if (h.len as usize) < HDRLEN + hdrlen || m.len() < HDRLEN + hdrlen {
        return Err(Errno::EINVAL);
    }
    let req = Request::new(sock, h, m, ext);
    let (cmd, version) = (m[HDRLEN], m[HDRLEN + 1]);
    let reserved = u16::from_ne_bytes([m[HDRLEN + 2], m[HDRLEN + 3]]);
    header_check(&req, f, cmd, reserved)?;
    let dump = h.flags & NLM_F_DUMP as u16 == NLM_F_DUMP as u16;
    let Some(op) = f
        .ops
        .iter()
        .find(|o| o.cmd == cmd && if dump { o.dumpit.is_some() } else { o.doit.is_some() })
    else {
        return Err(Errno::EOPNOTSUPP);
    };
    if op.flags & (GENL_ADMIN_PERM | GENL_UNS_ADMIN_PERM) != 0 && !net_admin() {
        return Err(Errno::EPERM);
    }
    let (no_policy, liberal) = if dump {
        (
            op.validate & GENL_DONT_VALIDATE_DUMP != 0,
            op.validate & GENL_DONT_VALIDATE_DUMP_STRICT != 0,
        )
    } else {
        (false, op.validate & GENL_DONT_VALIDATE_STRICT != 0)
    };
    let policy = if no_policy { None } else { op_policy(f, op) };
    let attrs = match policy {
        Some(p) => {
            let flags = if liberal { policy::LIBERAL } else { policy::STRICT };
            policy::parse(&req, hdrlen, p, flags)?.1
        }
        None => Attrs::parse(&[], 0),
    };
    let p = req.payload();
    let info =
        Info { req: &req, family: e.id, cmd, version, user_hdr: &p[GENL_HDRLEN..hdrlen], attrs };
    if dump {
        let Some(dumpit) = op.dumpit else { return Err(Errno::EOPNOTSUPP) };
        let result = dumpit(&info);
        let answer = if req.filtered.get() { super::NLM_F_DUMP_FILTERED as u16 } else { 0 };
        sock.start_dump(h, result, false, answer, ext.get())?;
        return Ok(Flow::Dump);
    }
    let Some(doit) = op.doit else { return Err(Errno::EOPNOTSUPP) };
    doit(&info)?;
    Ok(Flow::Done)
}

// The family `nlctrl`.

/// The policy of `CTRL_CMD_GETFAMILY`, `ctrl_policy_family` of Linux.
static CTRL_POLICY_FAMILY: [Policy; 3] =
    [Policy::NONE, Policy::of(Kind::U16), Policy::of(Kind::NulString).len(GENL_NAMSIZ - 1)];

static CTRL_OPS: [Op; 1] = [Op {
    cmd: CTRL_CMD_GETFAMILY,
    flags: 0,
    validate: GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
    policy: Some(&CTRL_POLICY_FAMILY),
    doit: Some(ctrl_getfamily),
    dumpit: Some(ctrl_dumpfamily),
}];

static CTRL_GROUPS: [McGroup; 1] = [McGroup { name: "notify", flags: 0 }];

/// The family `nlctrl`, `genl_ctrl` of Linux.
static CTRL: Family = Family {
    name: "nlctrl",
    version: 2,
    hdrsize: 0,
    maxattr: (CTRL_POLICY_FAMILY.len() - 1) as u32,
    // `CTRL_CMD_GETPOLICY + 1`.
    resv_start_op: 11,
    ops: &CTRL_OPS,
    mcgrps: &CTRL_GROUPS,
};

/// The message that tells about the family `e`, as `ctrl_fill_info` of Linux.
fn ctrl_fill(e: &Entry, portid: u32, seq: u32, flags: u16, cmd: u8) -> Vec<u8> {
    let f = e.family;
    let mut b = message(GENL_ID_CTRL, CTRL.version, cmd, flags, seq, portid);
    b.str(CTRL_ATTR_FAMILY_NAME, f.name)
        .u16(CTRL_ATTR_FAMILY_ID, e.id)
        .u32(CTRL_ATTR_VERSION, u32::from(f.version))
        .u32(CTRL_ATTR_HDRSIZE, f.hdrsize)
        .u32(CTRL_ATTR_MAXATTR, f.maxattr);
    if !f.ops.is_empty() {
        let ops = b.nest(CTRL_ATTR_OPS);
        for (i, op) in f.ops.iter().enumerate() {
            let n = b.nest(i as u16 + 1);
            b.u32(CTRL_ATTR_OP_ID, u32::from(op.cmd)).u32(CTRL_ATTR_OP_FLAGS, op_flags(f, op));
            b.end_nest(n);
        }
        b.end_nest(ops);
    }
    if !f.mcgrps.is_empty() {
        let grps = b.nest(CTRL_ATTR_MCAST_GROUPS);
        for (i, g) in f.mcgrps.iter().enumerate() {
            let n = b.nest(i as u16 + 1);
            b.u32(CTRL_ATTR_MCAST_GRP_ID, e.mcgrp_offset + i as u32)
                .str(CTRL_ATTR_MCAST_GRP_NAME, g.name);
            b.end_nest(n);
        }
        b.end_nest(grps);
    }
    b.finish()
}

/// `CTRL_CMD_GETFAMILY` for one family, by its ID or its name, as `ctrl_getfamily` of Linux.
fn ctrl_getfamily(info: &Info<'_>) -> Result<()> {
    let r = REGISTRY.lock();
    let mut res = None;
    let mut err = Errno::EINVAL;
    if let Some(d) = info.attrs.get(u32::from(CTRL_ATTR_FAMILY_ID)) {
        let id = d.first_chunk::<2>().map_or(0, |b| u16::from_ne_bytes(*b));
        res = r.by_id(id);
        err = Errno::ENOENT;
    }
    if let Some(d) = info.attrs.get(u32::from(CTRL_ATTR_FAMILY_NAME)) {
        // The name ends at its NUL byte, as `strcmp`.
        let name = d.split(|&c| c == 0).next().unwrap_or(&[]);
        res = r.by_name(name);
        err = Errno::ENOENT;
    }
    drop(r);
    let e = res.ok_or(err)?;
    let req = info.req;
    req.reply(ctrl_fill(&e, req.portid, req.hdr.seq, 0, CTRL_CMD_NEWFAMILY));
    Ok(())
}

/// `CTRL_CMD_GETFAMILY` for all families, as `ctrl_dumpfamily` of Linux.
fn ctrl_dumpfamily(info: &Info<'_>) -> Result<Vec<Vec<u8>>> {
    let families = REGISTRY.lock().families.clone();
    let req = info.req;
    Ok(families
        .iter()
        .map(|e| ctrl_fill(e, req.portid, req.hdr.seq, NLM_F_MULTI as u16, CTRL_CMD_NEWFAMILY))
        .collect())
}

/// Registers `nlctrl`. A second call does nothing.
pub(super) fn init() {
    let _ = register(&CTRL);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr<'a>(b: &'a [u8], ty: u16) -> Option<&'a [u8]> {
        msg::attrs(b).find(|&(t, _)| t == ty).map(|(_, d)| d)
    }

    #[test]
    fn nlctrl_message() {
        init();
        let e = REGISTRY.lock().by_id(GENL_ID_CTRL).unwrap();
        let m = ctrl_fill(&e, 7, 9, 0, CTRL_CMD_NEWFAMILY);
        let h = Header::parse(&m).unwrap();
        assert_eq!((h.ty, h.seq, h.pid, h.len as usize), (GENL_ID_CTRL, 9, 7, m.len()));
        assert_eq!(&m[HDRLEN..HDRLEN + 4], &[CTRL_CMD_NEWFAMILY, 2, 0, 0]);
        let a = &m[HDRLEN + GENL_HDRLEN..];
        assert_eq!(attr(a, CTRL_ATTR_FAMILY_NAME), Some(&b"nlctrl\0"[..]));
        assert_eq!(attr(a, CTRL_ATTR_FAMILY_ID), Some(&16u16.to_ne_bytes()[..]));
        assert_eq!(attr(a, CTRL_ATTR_VERSION), Some(&2u32.to_ne_bytes()[..]));
        assert_eq!(attr(a, CTRL_ATTR_MAXATTR), Some(&2u32.to_ne_bytes()[..]));
        let ops = attr(a, CTRL_ATTR_OPS).unwrap();
        let op = attr(ops, 1).unwrap();
        assert_eq!(attr(op, CTRL_ATTR_OP_ID), Some(&3u32.to_ne_bytes()[..]));
        // has-doit, has-dumpit and has-policy.
        assert_eq!(attr(op, CTRL_ATTR_OP_FLAGS), Some(&0xeu32.to_ne_bytes()[..]));
        let grp = attr(attr(a, CTRL_ATTR_MCAST_GROUPS).unwrap(), 1).unwrap();
        assert_eq!(attr(grp, CTRL_ATTR_MCAST_GRP_ID), Some(&16u32.to_ne_bytes()[..]));
        assert_eq!(attr(grp, CTRL_ATTR_MCAST_GRP_NAME), Some(&b"notify\0"[..]));
    }

    #[test]
    fn group_ids() {
        let mut r = Registry { families: Vec::new(), groups: 0x3 | 0x7 << 16, last_id: 18 };
        assert_eq!(r.reserve_groups(1), Some(2));
        assert_eq!(r.reserve_groups(14), Some(19));
        assert_eq!(r.reserve_groups(13), Some(3));
        assert_eq!(r.reserve_groups(1), Some(33));
    }
}

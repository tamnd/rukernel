//! The ethtool interface of the network devices: the generic netlink family `ethtool`, as
//! net/ethtool/netlink.c of Linux, and the ioctl `SIOCETHTOOL`, as net/ethtool/ioctl.c.
//!
//! A request of the family names a device in the nest `ETHTOOL_A_*_HEADER`, by its index or
//! by its name. A get request without `NLM_F_DUMP` gives one reply for that device, and a dump
//! gives one message for each device that has the data. A set request changes the device and
//! sends a notice to the group `monitor`. A list of bits, as the link modes and the features,
//! is a bitset nest, in the compact form (arrays of 32-bit words) or in the verbose form (one
//! nest for each bit, with its index and its name).

use crate::dev::{self, Event, LinkKind, NetDevice};
use crate::features;
use crate::ioctl::{IfReq, net_admin};
use crate::netlink::Request;
use crate::netlink::genl::{self, Family, GENL_UNS_ADMIN_PERM, Info, McGroup, Op};
use crate::netlink::msg::{Attrs, Builder};
use crate::netlink::policy::{self, Check, Kind, Policy};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, Ordering};
use rk_abi::Errno;
use rk_abi::native::netlink::{NLA_F_NESTED, NLA_TYPE_MASK, NLM_F_MULTI};
use rk_vfs::UserMemory;
use rk_vfs::inode::Result;

/// The data of `get_drvinfo` of a driver, as `struct ethtool_drvinfo` of Linux.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DrvInfo {
    /// The name of the driver.
    pub driver: String,
    /// The version of the driver. An empty version gives the release of the kernel.
    pub version: String,
    /// The version of the firmware.
    pub fw_version: String,
    /// The place of the device on its bus.
    pub bus_info: String,
}

/// The link settings of a device, as `struct ethtool_link_ksettings` of Linux. The link modes
/// are bitmaps of `ETHTOOL_LINK_MODE_*_BIT`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkSettings {
    /// The speed in Mb/s, or `SPEED_UNKNOWN`.
    pub speed: u32,
    /// `DUPLEX_HALF`, `DUPLEX_FULL` or `DUPLEX_UNKNOWN`.
    pub duplex: u8,
    /// The connector, `PORT_*`.
    pub port: u8,
    /// The MDIO address of the PHY.
    pub phy_address: u8,
    /// 1 if autonegotiation is on.
    pub autoneg: u8,
    /// The MDIO protocols, `ETH_MDIO_SUPPORTS_*`.
    pub mdio_support: u8,
    /// The MDI or MDI-X state of a twisted pair port.
    pub eth_tp_mdix: u8,
    /// The MDI or MDI-X control of a twisted pair port.
    pub eth_tp_mdix_ctrl: u8,
    /// The transceiver, `XCVR_*`.
    pub transceiver: u8,
    /// The master and slave configuration, or 0 if the device does not support it.
    pub master_slave_cfg: u8,
    /// The master and slave state, or 0 if the device does not support it.
    pub master_slave_state: u8,
    /// The rate matching, `RATE_MATCH_*`.
    pub rate_matching: u8,
    /// The number of lanes.
    pub lanes: u32,
    /// The link modes that the device supports.
    pub supported: u128,
    /// The link modes that the device advertises.
    pub advertising: u128,
    /// The link modes that the link partner advertises.
    pub lp_advertising: u128,
}

/// The sizes of the rings, as `struct ethtool_ringparam` of Linux.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rings {
    /// The largest size of a receive ring.
    pub rx_max: u32,
    /// The size of the receive ring.
    pub rx: u32,
    /// The largest size of a transmit ring.
    pub tx_max: u32,
    /// The size of the transmit ring.
    pub tx: u32,
}

/// The numbers of the channels, as `struct ethtool_channels` of Linux.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Channels {
    /// The largest number of receive channels.
    pub max_rx: u32,
    /// The largest number of transmit channels.
    pub max_tx: u32,
    /// The largest number of other channels.
    pub max_other: u32,
    /// The largest number of combined channels.
    pub max_combined: u32,
    /// The number of receive channels.
    pub rx_count: u32,
    /// The number of transmit channels.
    pub tx_count: u32,
    /// The number of other channels.
    pub other_count: u32,
    /// The number of combined channels.
    pub combined_count: u32,
}

/// An unknown speed, `SPEED_UNKNOWN`.
pub const SPEED_UNKNOWN: u32 = u32::MAX;
/// Half duplex, `DUPLEX_HALF`.
pub const DUPLEX_HALF: u8 = 0;
/// Full duplex, `DUPLEX_FULL`.
pub const DUPLEX_FULL: u8 = 1;
/// An unknown duplex, `DUPLEX_UNKNOWN`.
pub const DUPLEX_UNKNOWN: u8 = 0xff;
/// A twisted pair port, `PORT_TP`.
pub const PORT_TP: u8 = 0;
/// Another port, `PORT_OTHER`.
pub const PORT_OTHER: u8 = 0xff;

/// Checks new link settings of a virtual device and changes its speed and duplex, as
/// `virtnet_set_link_ksettings` of Linux. Only the speed and the duplex can change. The port must
/// stay `PORT_OTHER`, and the other fields must be 0. The advertised link modes do not matter.
///
/// # Errors
///
/// Gives `EINVAL` for a bad speed, a bad duplex or another field that is not 0.
pub fn virtdev_set(s: &LinkSettings, speed: &AtomicU32, duplex: &AtomicU8) -> Result<()> {
    let good_speed = s.speed <= i32::MAX as u32 || s.speed == SPEED_UNKNOWN;
    let good_duplex = matches!(s.duplex, DUPLEX_HALF | DUPLEX_FULL | DUPLEX_UNKNOWN);
    let rest = LinkSettings { speed: 0, duplex: 0, lanes: 0, advertising: 0, ..*s };
    let zero = LinkSettings { port: PORT_OTHER, ..LinkSettings::default() };
    if !good_speed || !good_duplex || rest != zero {
        return Err(Errno::EINVAL);
    }
    speed.store(s.speed, Ordering::Relaxed);
    duplex.store(s.duplex, Ordering::Relaxed);
    Ok(())
}

// The commands of the family, `ETHTOOL_MSG_*` of <linux/ethtool_netlink_generated.h>. The
// requests and the replies have their own numbers.
const MSG_STRSET_GET: u8 = 1;
const MSG_LINKINFO_GET: u8 = 2;
const MSG_LINKINFO_SET: u8 = 3;
const MSG_LINKMODES_GET: u8 = 4;
const MSG_LINKMODES_SET: u8 = 5;
const MSG_LINKSTATE_GET: u8 = 6;
const MSG_DEBUG_GET: u8 = 7;
const MSG_DEBUG_SET: u8 = 8;
const MSG_WOL_GET: u8 = 9;
const MSG_WOL_SET: u8 = 10;
const MSG_FEATURES_GET: u8 = 11;
const MSG_FEATURES_SET: u8 = 12;
const MSG_RINGS_GET: u8 = 15;
const MSG_CHANNELS_GET: u8 = 17;
/// The first command after `ETHTOOL_MSG_MODULE_GET`, for `resv_start_op`.
const MSG_RESV_START: u8 = 36;

const REPLY_LINKINFO_NTF: u8 = 3;
const REPLY_LINKMODES_NTF: u8 = 5;
const REPLY_FEATURES_SET: u8 = 12;
const REPLY_FEATURES_NTF: u8 = 13;
const REPLY_RINGS_GET: u8 = 16;
const REPLY_CHANNELS_GET: u8 = 18;

/// The version of the family, `ETHTOOL_GENL_VERSION`.
const VERSION: u8 = 1;

// The attributes of the header, `ETHTOOL_A_HEADER_*`.
const A_HEADER: u16 = 1;
const A_HEADER_DEV_INDEX: u16 = 1;
const A_HEADER_DEV_NAME: u16 = 2;
const A_HEADER_FLAGS: u32 = 3;
const A_HEADER_PHY_INDEX: u32 = 4;

// The flags of the header, `ETHTOOL_FLAG_*`.
const FLAG_COMPACT_BITSETS: u32 = 1;
const FLAG_OMIT_REPLY: u32 = 2;
const FLAG_STATS: u32 = 4;

// The attributes of a bitset, `ETHTOOL_A_BITSET_*`.
const A_BITSET_NOMASK: u16 = 1;
const A_BITSET_SIZE: u16 = 2;
const A_BITSET_BITS: u16 = 3;
const A_BITSET_VALUE: u16 = 4;
const A_BITSET_MASK: u16 = 5;
const A_BITSET_BITS_BIT: u16 = 1;
const A_BITSET_BIT_INDEX: u16 = 1;
const A_BITSET_BIT_NAME: u16 = 2;
const A_BITSET_BIT_VALUE: u16 = 3;

/// The number of link modes, `__ETHTOOL_LINK_MODE_MASK_NBITS`.
const LINK_MODE_COUNT: u32 = 125;
/// The number of 32-bit words of a link mode bitmap, `__ETHTOOL_LINK_MODE_MASK_NU32`.
const LINK_MODE_NU32: usize = 4;

/// The number of string sets, `ETH_SS_COUNT`.
const SS_COUNT: u32 = 23;
/// The string set of the statistics of the driver, `ETH_SS_STATS`.
const SS_STATS: u32 = 1;

/// The release of the kernel, `init_uts_ns.name.release` of Linux, for the version of
/// `ETHTOOL_GDRVINFO`. It is `UNAME_RELEASE` of rk-syscall, which rk-net does not use.
const UTS_RELEASE: &str = "7.3.0-rukernel";

/// The ID of the family.
static FAMILY_ID: AtomicU16 = AtomicU16::new(0);
/// The sequence number of the last notice, `ethnl_bcast_seq` of Linux.
static BCAST_SEQ: AtomicU32 = AtomicU32::new(0);

// The policies, as net/ethtool/netlink.c and the files of each command of Linux.
static HEADER: [Policy; 4] = [
    Policy::NONE,
    Policy::of(Kind::U32),
    Policy::of(Kind::NulString).len(127),
    Policy::of(Kind::U32).check(Check::Mask((FLAG_COMPACT_BITSETS | FLAG_OMIT_REPLY) as u64)),
];
static HEADER_STATS: [Policy; 4] = [
    Policy::NONE,
    Policy::of(Kind::U32),
    Policy::of(Kind::NulString).len(127),
    Policy::of(Kind::U32)
        .check(Check::Mask((FLAG_COMPACT_BITSETS | FLAG_OMIT_REPLY | FLAG_STATS) as u64)),
];
static HEADER_PHY: [Policy; 5] = [
    Policy::NONE,
    Policy::of(Kind::U32),
    Policy::of(Kind::NulString).len(127),
    Policy::of(Kind::U32).check(Check::Mask((FLAG_COMPACT_BITSETS | FLAG_OMIT_REPLY) as u64)),
    Policy::of(Kind::U32).check(Check::Min(1)),
];
static GET_POLICY: [Policy; 2] = [Policy::NONE, Policy::nest(&HEADER)];
static LINKSTATE_GET_POLICY: [Policy; 2] = [Policy::NONE, Policy::nest(&HEADER_STATS)];
static STRSET_GET_POLICY: [Policy; 4] =
    [Policy::NONE, Policy::nest(&HEADER_PHY), Policy::of(Kind::Nested), Policy::of(Kind::Flag)];
static STRINGSETS_POLICY: [Policy; 2] = [Policy::NONE, Policy::of(Kind::Nested)];
static STRINGSET_POLICY: [Policy; 2] = [Policy::NONE, Policy::of(Kind::U32)];
static LINKINFO_SET_POLICY: [Policy; 6] = [
    Policy::NONE,
    Policy::nest(&HEADER),
    Policy::of(Kind::U8),
    Policy::of(Kind::U8),
    Policy::NONE,
    Policy::of(Kind::U8),
];
static LINKMODES_SET_POLICY: [Policy; 10] = [
    Policy::NONE,
    Policy::nest(&HEADER),
    Policy::of(Kind::U8),
    Policy::of(Kind::Nested),
    Policy::NONE,
    Policy::of(Kind::U32),
    Policy::of(Kind::U8),
    Policy::of(Kind::U8),
    Policy::NONE,
    Policy::of(Kind::U32).check(Check::Range(1, 8)),
];
static DEBUG_SET_POLICY: [Policy; 3] =
    [Policy::NONE, Policy::nest(&HEADER), Policy::of(Kind::Nested)];
static WOL_SET_POLICY: [Policy; 4] = [
    Policy::NONE,
    Policy::nest(&HEADER),
    Policy::of(Kind::Nested),
    Policy::of(Kind::Binary).len(6),
];
static FEATURES_SET_POLICY: [Policy; 4] =
    [Policy::NONE, Policy::nest(&HEADER), Policy::NONE, Policy::of(Kind::Nested)];
static BITSET_POLICY: [Policy; 6] = [
    Policy::NONE,
    Policy::of(Kind::Flag),
    Policy::of(Kind::U32).check(Check::Max(i16::MAX as u64)),
    Policy::of(Kind::Nested),
    Policy::of(Kind::Binary),
    Policy::of(Kind::Binary),
];
static BIT_POLICY: [Policy; 4] =
    [Policy::NONE, Policy::of(Kind::U32), Policy::of(Kind::NulString), Policy::of(Kind::Flag)];

/// A get command, as `ethnl_get_doit`, `ethnl_get_start` and `ethnl_get_dumpit` of Linux.
const fn get_op(cmd: u8, policy: &'static [Policy]) -> Op {
    Op {
        cmd,
        flags: 0,
        validate: 0,
        policy: Some(policy),
        doit: Some(default_doit),
        start: Some(default_start),
        dumpit: Some(default_dumpit),
    }
}

/// A set command. It needs `CAP_NET_ADMIN` in the user namespace of the network namespace.
const fn set_op(cmd: u8, policy: &'static [Policy], doit: genl::DoIt) -> Op {
    Op {
        cmd,
        flags: GENL_UNS_ADMIN_PERM,
        validate: 0,
        policy: Some(policy),
        doit: Some(doit),
        start: None,
        dumpit: None,
    }
}

static OPS: [Op; 14] = [
    get_op(MSG_STRSET_GET, &STRSET_GET_POLICY),
    get_op(MSG_LINKINFO_GET, &GET_POLICY),
    set_op(MSG_LINKINFO_SET, &LINKINFO_SET_POLICY, default_set_doit),
    get_op(MSG_LINKMODES_GET, &GET_POLICY),
    set_op(MSG_LINKMODES_SET, &LINKMODES_SET_POLICY, default_set_doit),
    get_op(MSG_LINKSTATE_GET, &LINKSTATE_GET_POLICY),
    get_op(MSG_DEBUG_GET, &GET_POLICY),
    set_op(MSG_DEBUG_SET, &DEBUG_SET_POLICY, default_set_doit),
    Op { flags: GENL_UNS_ADMIN_PERM, ..get_op(MSG_WOL_GET, &GET_POLICY) },
    set_op(MSG_WOL_SET, &WOL_SET_POLICY, default_set_doit),
    get_op(MSG_FEATURES_GET, &GET_POLICY),
    set_op(MSG_FEATURES_SET, &FEATURES_SET_POLICY, features_set),
    get_op(MSG_RINGS_GET, &GET_POLICY),
    get_op(MSG_CHANNELS_GET, &GET_POLICY),
];

static MCGRPS: [McGroup; 1] = [McGroup { name: "monitor", flags: 0 }];

static FAMILY: Family = Family {
    name: "ethtool",
    version: VERSION,
    hdrsize: 0,
    maxattr: 0,
    resv_start_op: MSG_RESV_START,
    ops: &OPS,
    mcgrps: &MCGRPS,
};

/// Registers the family and its notifier, as `ethnl_init` of Linux.
pub fn init() {
    if let Ok(id) = genl::register(&FAMILY) {
        FAMILY_ID.store(id, Ordering::Relaxed);
        dev::add_notifier(netdev_event);
    }
}

/// Sends the notice of a change of the features, as `ethnl_netdev_event` of Linux.
fn netdev_event(dev: &NetDevice, event: Event) {
    if event == Event::Features {
        notify(dev, REPLY_FEATURES_NTF);
    }
}

/// The data of a request, as `struct ethnl_req_info` of Linux and the fields of
/// `struct strset_req_info`.
#[derive(Default)]
struct ReqInfo<'a> {
    /// The device of the header.
    dev: Option<Arc<NetDevice>>,
    /// `ETHTOOL_A_HEADER_FLAGS`.
    flags: u32,
    /// `ETHTOOL_A_HEADER_PHY_INDEX`.
    phy_index: u32,
    /// The header nest, for the extended ack.
    header: Option<&'a [u8]>,
    /// The string sets of the request, one bit for each ID.
    req_ids: u32,
    /// Only the numbers of the strings.
    counts_only: bool,
}

/// The compact form of the bitsets.
impl ReqInfo<'_> {
    fn compact(&self) -> bool {
        self.flags & FLAG_COMPACT_BITSETS != 0
    }
}

/// Sets the message of the extended ack if there is a request.
fn fail(req: Option<&Request<'_>>, text: &'static str, e: Errno) -> Errno {
    req.map_or(e, |r| r.error(text, e))
}

/// The string up to the first NUL byte.
fn cstr(d: &[u8]) -> &[u8] {
    d.split(|&c| c == 0).next().unwrap_or(d)
}

/// The value of a `u32` attribute that the policy checked.
fn get_u32(d: &[u8]) -> u32 {
    d.first_chunk::<4>().map_or(0, |v| u32::from_ne_bytes(*v))
}

/// The attributes in `b` with their types and flags, as `nla_for_each_attr` of Linux.
fn raw_attrs(mut b: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    core::iter::from_fn(move || {
        if b.len() < 4 {
            return None;
        }
        let len = usize::from(u16::from_ne_bytes([b[0], b[1]]));
        if len < 4 || len > b.len() {
            return None;
        }
        let ty = u16::from_ne_bytes([b[2], b[3]]);
        let data = &b[4..len];
        b = &b[((len + 3) & !3).min(b.len())..];
        Some((ty, data))
    })
}

/// Checks the attributes of a nest with `policy`, as `nla_parse_nested` of Linux. The caller
/// checked the flag `NLA_F_NESTED`.
fn inner<'a>(req: &Request<'_>, data: &'a [u8], policy: &'static [Policy]) -> Result<Attrs<'a>> {
    policy::validate(req, data, policy, policy::STRICT)?;
    Ok(Attrs::parse(data, (policy.len() - 1) as u16))
}

/// Checks the flag `NLA_F_NESTED` of the nest with the type `raw`, and its attributes, as
/// `nla_parse_nested` of Linux.
fn nested<'a>(
    req: &Request<'_>,
    raw: u16,
    data: &'a [u8],
    policy: &'static [Policy],
) -> Result<Attrs<'a>> {
    if u32::from(raw) & NLA_F_NESTED == 0 {
        return Err(req.attr_error("NLA_F_NESTED is missing", data, Errno::EINVAL));
    }
    inner(req, data, policy)
}

/// Finds the device of the header, as `ethnl_parse_header_dev_get` of Linux.
fn parse_header<'a>(
    req: &Request<'_>,
    header: Option<&'a [u8]>,
    require_dev: bool,
) -> Result<ReqInfo<'a>> {
    let Some(h) = header else {
        if !require_dev {
            return Ok(ReqInfo::default());
        }
        return Err(req.error("request header missing", Errno::EINVAL));
    };
    // The policy of the command checked the header.
    let tb = Attrs::parse(h, A_HEADER_PHY_INDEX as u16);
    let flags = tb.get(A_HEADER_FLAGS).map_or(0, get_u32);
    let name = tb.get(u32::from(A_HEADER_DEV_NAME));
    let dev = if let Some(i) = tb.get(u32::from(A_HEADER_DEV_INDEX)) {
        let Some(d) = dev::by_index(get_u32(i)) else {
            return Err(req.attr_error("no device matches ifindex", i, Errno::ENODEV));
        };
        if name.is_some_and(|n| cstr(n) != d.name().as_bytes()) {
            return Err(req.attr_error("ifindex and name do not match", h, Errno::ENODEV));
        }
        Some(d)
    } else if let Some(n) = name {
        let d = core::str::from_utf8(cstr(n)).ok().and_then(dev::by_name);
        let Some(d) = d else {
            return Err(req.attr_error("no device matches name", n, Errno::ENODEV));
        };
        Some(d)
    } else if require_dev {
        return Err(req.attr_error("neither ifindex nor name specified", h, Errno::EINVAL));
    } else {
        None
    };
    let mut phy_index = 0;
    if let Some(p) = tb.get(A_HEADER_PHY_INDEX) {
        if dev.is_none() {
            return Err(req.attr_error("phy_index set without a netdev", h, Errno::EINVAL));
        }
        phy_index = get_u32(p);
    }
    Ok(ReqInfo { dev, flags, phy_index, header: Some(h), ..ReqInfo::default() })
}

/// Adds the header of a reply, as `ethnl_fill_reply_header` of Linux.
fn put_header(b: &mut Builder, dev: Option<&NetDevice>) {
    if let Some(d) = dev {
        let n = b.nest(A_HEADER | NLA_F_NESTED as u16);
        b.u32(A_HEADER_DEV_INDEX, d.ifindex());
        b.str(A_HEADER_DEV_NAME, &d.name());
        b.end_nest(n);
    }
}

/// The function that checks the data of a get command and adds its attributes, as
/// `prepare_data` and `fill_reply` of `struct ethnl_request_ops` of Linux. An error of the
/// first part comes before the header.
type Fill = fn(Option<&Request<'_>>, &ReqInfo<'_>, Option<&NetDevice>, &mut Builder) -> Result<()>;

/// A get command, as `struct ethnl_request_ops` of Linux.
struct GetOps {
    reply_cmd: u8,
    /// A request without a device is good, as for the global string sets.
    allow_nodev_do: bool,
    fill: Fill,
}

/// The get command `cmd`.
fn get_ops(cmd: u8) -> Option<GetOps> {
    let (reply_cmd, fill): (u8, Fill) = match cmd {
        MSG_STRSET_GET => (1, strset_fill),
        MSG_LINKINFO_GET => (2, linkinfo_fill),
        MSG_LINKMODES_GET => (4, linkmodes_fill),
        MSG_LINKSTATE_GET => (6, linkstate_fill),
        MSG_DEBUG_GET => (7, unsupported_fill),
        MSG_WOL_GET => (9, unsupported_fill),
        MSG_FEATURES_GET => (11, features_fill),
        MSG_RINGS_GET => (REPLY_RINGS_GET, rings_fill),
        MSG_CHANNELS_GET => (REPLY_CHANNELS_GET, channels_fill),
        _ => return None,
    };
    Some(GetOps { reply_cmd, allow_nodev_do: cmd == MSG_STRSET_GET, fill })
}

/// Builds one message of the command `cmd` for the device `dev`.
#[allow(clippy::too_many_arguments)]
fn build(
    req: Option<&Request<'_>>,
    fill: Fill,
    cmd: u8,
    ri: &ReqInfo<'_>,
    dev: Option<&NetDevice>,
    flags: u16,
    seq: u32,
    portid: u32,
) -> Result<Vec<u8>> {
    let id = FAMILY_ID.load(Ordering::Relaxed);
    let mut b = genl::message(id, VERSION, cmd, flags, seq, portid);
    fill(req, ri, dev, &mut b)?;
    Ok(b.finish())
}

/// Parses a get request, as `ethnl_default_parse` of Linux.
fn default_parse<'a>(info: &Info<'a>, require_dev: bool) -> Result<ReqInfo<'a>> {
    let mut ri = parse_header(info.req, info.attrs.get(u32::from(A_HEADER)), require_dev)?;
    if info.cmd == MSG_STRSET_GET {
        strset_parse(info.req, &info.attrs, &mut ri)?;
    }
    Ok(ri)
}

/// Answers a get request for one device, as `ethnl_default_doit` of Linux.
fn default_doit(info: &Info<'_>) -> Result<()> {
    let req = info.req;
    let ops = get_ops(info.cmd).ok_or(Errno::EOPNOTSUPP)?;
    if !info.attrs.has(u32::from(A_HEADER)) {
        return Err(req.missing(None, u32::from(A_HEADER)));
    }
    let ri = default_parse(info, !ops.allow_nodev_do)?;
    let m = build(
        Some(req),
        ops.fill,
        ops.reply_cmd,
        &ri,
        ri.dev.as_deref(),
        0,
        req.hdr.seq,
        req.portid,
    )?;
    req.reply(m);
    Ok(())
}

/// Checks a dump request, as `ethnl_default_start` of Linux.
fn default_start(info: &Info<'_>) -> Result<()> {
    get_ops(info.cmd).ok_or(Errno::EOPNOTSUPP)?;
    default_parse(info, false).map(drop)
}

/// Gives one message for each device, as `ethnl_default_dumpit` of Linux. A device without
/// the data has no message. Linux ignores the device of the header.
fn default_dumpit(info: &Info<'_>) -> Result<Vec<Vec<u8>>> {
    let req = info.req;
    let ops = get_ops(info.cmd).ok_or(Errno::EOPNOTSUPP)?;
    let mut ri = default_parse(info, false)?;
    ri.dev = None;
    let mut out = Vec::new();
    for d in dev::devices() {
        let flags = NLM_F_MULTI as u16;
        match build(
            Some(req),
            ops.fill,
            ops.reply_cmd,
            &ri,
            Some(&d),
            flags,
            req.hdr.seq,
            req.portid,
        ) {
            Ok(m) => out.push(m),
            Err(Errno::EOPNOTSUPP) => {}
            // Linux sends the messages so far and ends the dump. The error goes only in a dump
            // without messages.
            Err(e) if out.is_empty() => return Err(e),
            Err(_) => break,
        }
    }
    Ok(out)
}

/// Sends the notice `cmd` of a change of `dev` to the group `monitor`, as
/// `ethnl_default_notify` of Linux.
fn notify(dev: &NetDevice, cmd: u8) {
    let request = match cmd {
        REPLY_LINKINFO_NTF => MSG_LINKINFO_GET,
        REPLY_LINKMODES_NTF => MSG_LINKMODES_GET,
        REPLY_FEATURES_NTF => MSG_FEATURES_GET,
        _ => return,
    };
    let Some(ops) = get_ops(request) else { return };
    let ri = ReqInfo { flags: FLAG_COMPACT_BITSETS, ..ReqInfo::default() };
    let Ok(mut m) = build(None, ops.fill, cmd, &ri, Some(dev), 0, 0, 0) else { return };
    let seq = BCAST_SEQ.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    m[8..12].copy_from_slice(&seq.to_ne_bytes());
    genl::multicast(FAMILY_ID.load(Ordering::Relaxed), 0, m);
}

/// A set command, as the fields `set_validate`, `set` and `set_ntf_cmd` of
/// `struct ethnl_request_ops` of Linux. `validate` gives `false` if there is nothing to do,
/// and `set` gives `true` if the device changed.
struct SetOps {
    validate: fn(&Info<'_>, &NetDevice) -> Result<bool>,
    set: fn(&Info<'_>, &NetDevice) -> Result<bool>,
    ntf_cmd: u8,
}

/// The set command `cmd`.
fn set_ops(cmd: u8) -> Option<SetOps> {
    let unsupported: fn(&Info<'_>, &NetDevice) -> Result<bool> = |_, _| Err(Errno::EOPNOTSUPP);
    match cmd {
        MSG_LINKINFO_SET => Some(SetOps {
            validate: link_set_validate,
            set: linkinfo_set,
            ntf_cmd: REPLY_LINKINFO_NTF,
        }),
        MSG_LINKMODES_SET => Some(SetOps {
            validate: linkmodes_set_validate,
            set: linkmodes_set,
            ntf_cmd: REPLY_LINKMODES_NTF,
        }),
        // No driver has `get_msglevel` or `get_wol`.
        MSG_DEBUG_SET | MSG_WOL_SET => {
            Some(SetOps { validate: unsupported, set: unsupported, ntf_cmd: 0 })
        }
        _ => None,
    }
}

/// Changes a device, as `ethnl_default_set_doit` of Linux.
fn default_set_doit(info: &Info<'_>) -> Result<()> {
    let req = info.req;
    let ops = set_ops(info.cmd).ok_or(Errno::EOPNOTSUPP)?;
    if !info.attrs.has(u32::from(A_HEADER)) {
        return Err(req.missing(None, u32::from(A_HEADER)));
    }
    let ri = default_parse(info, true)?;
    let dev = ri.dev.ok_or(Errno::ENODEV)?;
    if !(ops.validate)(info, &dev)? {
        return Ok(());
    }
    if (ops.set)(info, &dev)? {
        notify(&dev, ops.ntf_cmd);
    }
    Ok(())
}

/// Sets `*v` to the `u8` attribute `ty` if the request has it, as `ethnl_update_u8` of Linux.
fn update_u8(v: &mut u8, attrs: &Attrs<'_>, ty: u32, modified: &mut bool) {
    let Some(&n) = attrs.get(ty).and_then(<[u8]>::first) else { return };
    if *v != n {
        *v = n;
        *modified = true;
    }
}

/// Sets `*v` to the `u32` attribute `ty` if the request has it, as `ethnl_update_u32` of Linux.
fn update_u32(v: &mut u32, attrs: &Attrs<'_>, ty: u32, modified: &mut bool) {
    if let Some(d) = attrs.get(ty) {
        let n = get_u32(d);
        if *v != n {
            *v = n;
            *modified = true;
        }
    }
}

/// A get command that no driver supports, as `debug_prepare_data` without `get_msglevel`.
fn unsupported_fill(
    _: Option<&Request<'_>>,
    _: &ReqInfo<'_>,
    _: Option<&NetDevice>,
    _: &mut Builder,
) -> Result<()> {
    Err(Errno::EOPNOTSUPP)
}

/// The link settings of the driver, as `netif_get_link_ksettings` of Linux.
fn link_settings(req: Option<&Request<'_>>, dev: &NetDevice) -> Result<LinkSettings> {
    dev.driver()
        .link_settings()
        .ok_or_else(|| fail(req, "failed to retrieve link settings", Errno::EOPNOTSUPP))
}

// LINKINFO, as net/ethtool/linkinfo.c of Linux.

fn linkinfo_fill(
    req: Option<&Request<'_>>,
    _: &ReqInfo<'_>,
    dev: Option<&NetDevice>,
    b: &mut Builder,
) -> Result<()> {
    let dev = dev.ok_or(Errno::ENODEV)?;
    let s = link_settings(req, dev)?;
    put_header(b, Some(dev));
    b.u8(2, s.port).u8(3, s.phy_address).u8(4, s.eth_tp_mdix);
    b.u8(5, s.eth_tp_mdix_ctrl).u8(6, s.transceiver);
    Ok(())
}

/// Checks that the driver can get and set the link settings, as
/// `ethnl_set_linkinfo_validate` of Linux.
fn link_set_validate(_: &Info<'_>, dev: &NetDevice) -> Result<bool> {
    let d = dev.driver();
    if d.link_settings().is_none() || !d.has_set_link_settings() {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(true)
}

/// Changes the port, the PHY address and the MDI-X control, as `ethnl_set_linkinfo` of Linux.
fn linkinfo_set(info: &Info<'_>, dev: &NetDevice) -> Result<bool> {
    let req = info.req;
    let mut s = link_settings(Some(req), dev)?;
    let mut modified = false;
    update_u8(&mut s.port, &info.attrs, 2, &mut modified);
    update_u8(&mut s.phy_address, &info.attrs, 3, &mut modified);
    update_u8(&mut s.eth_tp_mdix_ctrl, &info.attrs, 5, &mut modified);
    if !modified {
        return Ok(false);
    }
    dev.driver().set_link_settings(&s).map_err(|e| req.error("link settings update failed", e))?;
    Ok(true)
}

// LINKMODES, as net/ethtool/linkmodes.c of Linux.

const A_LINKMODES_AUTONEG: u32 = 2;
const A_LINKMODES_OURS: u32 = 3;
const A_LINKMODES_SPEED: u32 = 5;
const A_LINKMODES_DUPLEX: u32 = 6;
const A_LINKMODES_MASTER_SLAVE_CFG: u32 = 7;
const A_LINKMODES_LANES: u32 = 9;

/// The link modes without a speed, as the modes of `link_mode_params` of Linux with
/// `SPEED_UNKNOWN`: Autoneg, TP, AUI, MII, FIBRE, BNC, Pause, Asym_Pause, Backplane and the FEC
/// modes.
const SPECIAL_LINK_MODES: u128 = (1 << 6)
    | (1 << 7)
    | (1 << 8)
    | (1 << 9)
    | (1 << 10)
    | (1 << 11)
    | (1 << 13)
    | (1 << 14)
    | (1 << 16)
    | (1 << 49)
    | (1 << 50)
    | (1 << 51)
    | (1 << 74);

fn linkmodes_fill(
    req: Option<&Request<'_>>,
    ri: &ReqInfo<'_>,
    dev: Option<&NetDevice>,
    b: &mut Builder,
) -> Result<()> {
    let dev = dev.ok_or(Errno::ENODEV)?;
    let s = link_settings(req, dev)?;
    let compact = ri.compact();
    put_header(b, Some(dev));
    b.u8(2, s.autoneg);
    put_bitset(b, 3, s.advertising, Some(s.supported), LINK_MODE_COUNT, &LINK_MODES, compact);
    if s.lp_advertising != 0 {
        put_bitset(b, 4, s.lp_advertising, None, LINK_MODE_COUNT, &LINK_MODES, compact);
    }
    b.u32(5, s.speed).u8(6, s.duplex);
    // No driver has `cap_link_lanes_supported`, so the number of lanes is 0 and has no
    // attribute.
    if s.master_slave_cfg != 0 {
        b.u8(7, s.master_slave_cfg);
    }
    if s.master_slave_state != 0 {
        b.u8(8, s.master_slave_state);
    }
    b.u8(10, s.rate_matching);
    Ok(())
}

/// Checks the values of a request, as `ethnl_check_linkmodes` and
/// `ethnl_set_linkmodes_validate` of Linux.
fn linkmodes_set_validate(info: &Info<'_>, dev: &NetDevice) -> Result<bool> {
    let req = info.req;
    if let Some(d) = info.attrs.get(A_LINKMODES_MASTER_SLAVE_CFG) {
        // MASTER_SLAVE_CFG_MASTER_PREFERRED to MASTER_SLAVE_CFG_SLAVE_FORCE.
        if !(2..=5).contains(&d[0]) {
            return Err(req.attr_error("master/slave value is invalid", d, Errno::EOPNOTSUPP));
        }
    }
    let lanes = info.attrs.get(A_LINKMODES_LANES);
    if let Some(d) = lanes.filter(|d| !get_u32(d).is_power_of_two()) {
        return Err(req.attr_error("lanes value is invalid", d, Errno::EINVAL));
    }
    link_set_validate(info, dev)
}

/// Changes the link modes, the speed and the duplex, as `ethnl_set_linkmodes` and
/// `ethnl_update_linkmodes` of Linux.
fn linkmodes_set(info: &Info<'_>, dev: &NetDevice) -> Result<bool> {
    let req = info.req;
    let tb = &info.attrs;
    let mut s = link_settings(Some(req), dev)?;
    let ms_cfg = tb.get(A_LINKMODES_MASTER_SLAVE_CFG);
    if let Some(d) = ms_cfg.filter(|_| s.master_slave_cfg == 0) {
        return Err(req.attr_error(
            "master/slave configuration not supported by device",
            d,
            Errno::EOPNOTSUPP,
        ));
    }
    let mut modified = false;
    let req_speed = tb.has(A_LINKMODES_SPEED);
    let req_lanes = tb.has(A_LINKMODES_LANES);
    let req_duplex = tb.has(A_LINKMODES_DUPLEX);
    update_u8(&mut s.autoneg, tb, A_LINKMODES_AUTONEG, &mut modified);
    if let Some(d) = tb.get(A_LINKMODES_LANES) {
        // No driver has `cap_link_lanes_supported`.
        if s.autoneg == 0 {
            return Err(req.attr_error(
                "lanes configuration not supported by device",
                d,
                Errno::EOPNOTSUPP,
            ));
        }
    } else if s.autoneg == 0 && s.lanes != 0 {
        s.lanes = 0;
        modified = true;
    }
    if let Some(d) = tb.get(A_LINKMODES_OURS) {
        update_bitset(req, &mut s.advertising, LINK_MODE_COUNT, d, &LINK_MODES, &mut modified)?;
    }
    update_u32(&mut s.speed, tb, A_LINKMODES_SPEED, &mut modified);
    update_u32(&mut s.lanes, tb, A_LINKMODES_LANES, &mut modified);
    update_u8(&mut s.duplex, tb, A_LINKMODES_DUPLEX, &mut modified);
    update_u8(&mut s.master_slave_cfg, tb, A_LINKMODES_MASTER_SLAVE_CFG, &mut modified);
    if !tb.has(A_LINKMODES_OURS) && s.autoneg != 0 && (req_speed || req_lanes || req_duplex) {
        // `ethnl_auto_linkmodes` of Linux advertises each supported mode with the speed, the
        // lanes and the duplex of the request, and no other mode with a speed. No driver of
        // rukernel supports a link mode, so no mode with a speed stays.
        let adv = s.advertising & (SPECIAL_LINK_MODES | s.supported);
        if adv != s.advertising {
            s.advertising = adv;
            modified = true;
        }
    }
    if !modified {
        return Ok(false);
    }
    dev.driver().set_link_settings(&s).map_err(|e| req.error("link settings update failed", e))?;
    Ok(true)
}

// LINKSTATE, as net/ethtool/linkstate.c of Linux.

fn linkstate_fill(
    _: Option<&Request<'_>>,
    _: &ReqInfo<'_>,
    dev: Option<&NetDevice>,
    b: &mut Builder,
) -> Result<()> {
    let dev = dev.ok_or(Errno::ENODEV)?;
    put_header(b, Some(dev));
    // `__ethtool_get_link` of Linux: the device is up and has a carrier.
    if dev.driver().has_get_link() {
        b.u8(2, u8::from(dev.is_up() && dev.carrier()));
    }
    Ok(())
}

// RINGS and CHANNELS, as net/ethtool/rings.c and net/ethtool/channels.c of Linux.

fn rings_fill(
    _: Option<&Request<'_>>,
    _: &ReqInfo<'_>,
    dev: Option<&NetDevice>,
    b: &mut Builder,
) -> Result<()> {
    let dev = dev.ok_or(Errno::ENODEV)?;
    let r = dev.driver().rings().ok_or(Errno::EOPNOTSUPP)?;
    put_header(b, Some(dev));
    if r.rx_max != 0 {
        b.u32(2, r.rx_max).u32(6, r.rx);
    }
    if r.tx_max != 0 {
        b.u32(5, r.tx_max).u32(9, r.tx);
    }
    // `ETHTOOL_A_RINGS_TX_PUSH` and `ETHTOOL_A_RINGS_RX_PUSH`.
    b.u8(13, 0).u8(14, 0);
    Ok(())
}

fn channels_fill(
    _: Option<&Request<'_>>,
    _: &ReqInfo<'_>,
    dev: Option<&NetDevice>,
    b: &mut Builder,
) -> Result<()> {
    let dev = dev.ok_or(Errno::ENODEV)?;
    let c = dev.driver().channels().ok_or(Errno::EOPNOTSUPP)?;
    put_header(b, Some(dev));
    for (max_ty, max, count) in [
        (2, c.max_rx, c.rx_count),
        (3, c.max_tx, c.tx_count),
        (4, c.max_other, c.other_count),
        (5, c.max_combined, c.combined_count),
    ] {
        if max != 0 {
            b.u32(max_ty, max).u32(max_ty + 4, count);
        }
    }
    Ok(())
}

// FEATURES, as net/ethtool/features.c of Linux.

fn features_fill(
    _: Option<&Request<'_>>,
    ri: &ReqInfo<'_>,
    dev: Option<&NetDevice>,
    b: &mut Builder,
) -> Result<()> {
    let dev = dev.ok_or(Errno::ENODEV)?;
    let compact = ri.compact();
    let names = &features::NAMES;
    let n = features::COUNT;
    put_header(b, Some(dev));
    put_bitset(b, 2, dev.hw_features().into(), Some(low(n)), n, names, compact);
    put_bitset(b, 3, dev.wanted_features().into(), None, n, names, compact);
    put_bitset(b, 4, dev.features().into(), None, n, names, compact);
    put_bitset(b, 5, features::NEVER_CHANGE.into(), None, n, names, compact);
    Ok(())
}

/// Changes the wanted features, as `ethnl_set_features` of Linux. The reply has the wanted
/// features that the device did not take, and the active features that changed.
fn features_set(info: &Info<'_>) -> Result<()> {
    let req = info.req;
    let Some(wanted) = info.attrs.get(3) else { return Err(Errno::EINVAL) };
    let ri = parse_header(req, info.attrs.get(u32::from(A_HEADER)), true)?;
    let dev = ri.dev.clone().ok_or(Errno::ENODEV)?;
    let old_active = dev.features();
    let old_wanted = dev.wanted_features();
    let (rw, rm) = parse_bitset(req, wanted, features::COUNT, &features::NAMES)?;
    let (rw, rm) = (rw as u64, rm as u64);
    if rm & !features::ETHTOOL_BITS != 0 {
        return Err(req.error("attempt to change non-ethtool features", Errno::EINVAL));
    }
    let req_wanted = (rw & rm) | (old_wanted & !rm);
    if req_wanted != old_wanted {
        dev.set_wanted_features(req_wanted);
    }
    let new_active = dev.features();
    let modified = new_active != old_active;
    if ri.flags & FLAG_OMIT_REPLY == 0 {
        let wanted_diff = (req_wanted ^ new_active) & rm;
        let active_diff = old_active ^ new_active;
        let (names, n, compact) = (&features::NAMES, features::COUNT, ri.compact());
        let id = FAMILY_ID.load(Ordering::Relaxed);
        let mut b = genl::message(id, VERSION, REPLY_FEATURES_SET, 0, req.hdr.seq, req.portid);
        put_header(&mut b, Some(&dev));
        let (w, wm) = ((req_wanted & wanted_diff).into(), Some(wanted_diff.into()));
        put_bitset(&mut b, 3, w, wm, n, names, compact);
        let (a, am) = ((new_active & active_diff).into(), Some(active_diff.into()));
        put_bitset(&mut b, 4, a, am, n, names, compact);
        req.reply(b.finish());
    }
    if modified {
        dev.features_changed();
    }
    Ok(())
}

// Bitsets, as net/ethtool/bitset.c of Linux. A bitset here has at most 128 bits.

/// The low `n` bits.
fn low(n: u32) -> u128 {
    if n >= 128 { u128::MAX } else { (1 << n) - 1 }
}

/// The low `n` bits of the array of 32-bit words `d`.
fn load(d: &[u8], n: u32) -> u128 {
    let v = d
        .as_chunks::<4>()
        .0
        .iter()
        .take(4)
        .enumerate()
        .fold(0u128, |v, (i, w)| v | u128::from(get_u32(w)) << (32 * i));
    v & low(n)
}

/// Tells if a bit from `from` to `to` is set in the array of 32-bit words `d`.
fn any_bit(d: &[u8], from: u32, to: u32) -> bool {
    (from..to).any(|i| {
        let w = d.get(4 * (i / 32) as usize..).map_or(0, get_u32);
        w & (1 << (i % 32)) != 0
    })
}

/// Adds the bitset `ty` with the values `val` and the mask `mask`, as `ethnl_put_bitset32` of
/// Linux. A bitset without a mask is a list.
fn put_bitset(
    b: &mut Builder,
    ty: u16,
    val: u128,
    mask: Option<u128>,
    nbits: u32,
    names: &[&str],
    compact: bool,
) {
    let nest = b.nest(ty | NLA_F_NESTED as u16);
    if mask.is_none() {
        b.put(A_BITSET_NOMASK, &[]);
    }
    b.u32(A_BITSET_SIZE, nbits);
    if compact {
        let words = |v: u128| -> Vec<u8> {
            let v = v & low(nbits);
            (0..nbits.div_ceil(32)).flat_map(|i| ((v >> (32 * i)) as u32).to_ne_bytes()).collect()
        };
        b.put(A_BITSET_VALUE, &words(val));
        if let Some(m) = mask {
            b.put(A_BITSET_MASK, &words(m));
        }
    } else {
        let bits = b.nest(A_BITSET_BITS | NLA_F_NESTED as u16);
        let shown = mask.unwrap_or(val);
        for i in (0..nbits).filter(|&i| shown >> i & 1 != 0) {
            let bit = b.nest(A_BITSET_BITS_BIT | NLA_F_NESTED as u16);
            b.u32(A_BITSET_BIT_INDEX, i);
            b.str(A_BITSET_BIT_NAME, names.get(i as usize).copied().unwrap_or(""));
            if mask.is_some() && val >> i & 1 != 0 {
                b.put(A_BITSET_BIT_VALUE, &[]);
            }
            b.end_nest(bit);
        }
        b.end_nest(bits);
    }
    b.end_nest(nest);
}

/// Parses one bit of a verbose bitset, as `ethnl_parse_bit` of Linux. Gives its index and its
/// value.
fn parse_bit(
    req: &Request<'_>,
    raw: u16,
    entry: &[u8],
    nbits: u32,
    no_mask: bool,
    names: &[&str],
) -> Result<(u32, bool)> {
    let tb = nested(req, raw, entry, &BIT_POLICY)?;
    let name = tb.get(u32::from(A_BITSET_BIT_NAME));
    let idx = if let Some(i) = tb.get(u32::from(A_BITSET_BIT_INDEX)) {
        let idx = get_u32(i);
        if idx >= nbits {
            return Err(req.attr_error("bit index too high", i, Errno::EOPNOTSUPP));
        }
        let want = names.get(idx as usize).map_or(&b""[..], |n| n.as_bytes());
        if name.is_some_and(|n| cstr(n) != want) {
            return Err(req.attr_error("bit index and name mismatch", entry, Errno::EINVAL));
        }
        idx
    } else if let Some(n) = name {
        let found = names.iter().take(nbits as usize).position(|s| s.as_bytes() == cstr(n));
        let Some(idx) = found else {
            return Err(req.attr_error("bit name not found", n, Errno::EOPNOTSUPP));
        };
        idx as u32
    } else {
        let e = Errno::EINVAL;
        return Err(req.attr_error("neither bit index nor name specified", entry, e));
    };
    Ok((idx, no_mask || tb.has(u32::from(A_BITSET_BIT_VALUE))))
}

/// Checks a compact bitset, as `ethnl_compact_sanity_checks` of Linux. Gives its size.
fn compact_sanity(req: &Request<'_>, nest: &[u8], tb: &Attrs<'_>, nbits: u32) -> Result<u32> {
    let e = Errno::EINVAL;
    let no_mask = tb.has(u32::from(A_BITSET_NOMASK));
    let mask = tb.get(u32::from(A_BITSET_MASK));
    if let (true, Some(m)) = (no_mask, mask) {
        return Err(req.attr_error("mask not allowed in list bitset", m, e));
    }
    let Some(size) = tb.get(u32::from(A_BITSET_SIZE)) else {
        return Err(req.attr_error("missing size in compact bitset", nest, e));
    };
    let Some(value) = tb.get(u32::from(A_BITSET_VALUE)) else {
        return Err(req.attr_error("missing value in compact bitset", nest, e));
    };
    if !no_mask && mask.is_none() {
        return Err(req.attr_error("missing mask in compact nonlist bitset", nest, e));
    }
    let size = get_u32(size);
    let bytes = size.div_ceil(32) as usize * 4;
    if value.len() != bytes {
        return Err(req.attr_error("bitset value length does not match size", value, e));
    }
    if let Some(m) = mask.filter(|m| m.len() != bytes) {
        return Err(req.attr_error("bitset mask length does not match size", m, e));
    }
    if size <= nbits {
        return Ok(size);
    }
    let test = if no_mask { value } else { mask.unwrap_or(value) };
    if any_bit(test, nbits, size) {
        return Err(req.attr_error("cannot modify bits past kernel bitset size", test, e));
    }
    Ok(size)
}

/// Changes the bitmap `map` of `nbits` bits with the bitset `attr`, as `ethnl_update_bitset32`
/// of Linux. Sets `*modified` if the bitmap changed.
fn update_bitset(
    req: &Request<'_>,
    map: &mut u128,
    nbits: u32,
    attr: &[u8],
    names: &[&str],
    modified: &mut bool,
) -> Result<()> {
    let tb = inner(req, attr, &BITSET_POLICY)?;
    let no_mask = tb.has(u32::from(A_BITSET_NOMASK));
    let Some(bits) = tb.get(u32::from(A_BITSET_BITS)) else {
        let size = compact_sanity(req, attr, &tb, nbits)?;
        let change = size.min(nbits);
        let value = load(tb.get(u32::from(A_BITSET_VALUE)).unwrap_or(&[]), change);
        let mask = match tb.get(u32::from(A_BITSET_MASK)) {
            Some(m) if !no_mask => load(m, change),
            _ => low(change),
        };
        let mut new = (*map & !mask) | (value & mask);
        if no_mask && change < nbits {
            new &= !(low(nbits) & !low(change));
        }
        if new != *map {
            *map = new;
            *modified = true;
        }
        return Ok(());
    };
    verbose_checks(req, &tb)?;
    let saved = *map;
    if no_mask {
        *map &= !low(nbits);
    }
    for (raw, entry) in raw_attrs(bits) {
        if u32::from(raw) & NLA_TYPE_MASK != u32::from(A_BITSET_BITS_BIT) {
            let text = "only ETHTOOL_A_BITSET_BITS_BIT allowed in ETHTOOL_A_BITSET_BITS";
            return Err(req.attr_error(text, entry, Errno::EINVAL));
        }
        let (idx, val) = parse_bit(req, raw, entry, nbits, no_mask, names)?;
        if (*map >> idx & 1 != 0) != val {
            *map ^= 1 << idx;
            if !no_mask {
                *modified = true;
            }
        }
    }
    if no_mask && (saved ^ *map) & low(nbits) != 0 {
        *modified = true;
    }
    Ok(())
}

/// A verbose bitset has no value and no mask.
fn verbose_checks(req: &Request<'_>, tb: &Attrs<'_>) -> Result<()> {
    if let Some(v) = tb.get(u32::from(A_BITSET_VALUE)) {
        return Err(req.attr_error("value only allowed in compact bitset", v, Errno::EINVAL));
    }
    if let Some(m) = tb.get(u32::from(A_BITSET_MASK)) {
        return Err(req.attr_error("mask only allowed in compact bitset", m, Errno::EINVAL));
    }
    Ok(())
}

/// Gives the values and the mask of the bitset `attr`, as `ethnl_parse_bitset` of Linux.
fn parse_bitset(
    req: &Request<'_>,
    attr: &[u8],
    nbits: u32,
    names: &[&str],
) -> Result<(u128, u128)> {
    let tb = inner(req, attr, &BITSET_POLICY)?;
    let no_mask = tb.has(u32::from(A_BITSET_NOMASK));
    let Some(bits) = tb.get(u32::from(A_BITSET_BITS)) else {
        let size = compact_sanity(req, attr, &tb, nbits)?;
        let change = size.min(nbits);
        let value = load(tb.get(u32::from(A_BITSET_VALUE)).unwrap_or(&[]), change);
        let mask = match tb.get(u32::from(A_BITSET_MASK)) {
            Some(m) if !no_mask => load(m, change),
            _ => low(nbits),
        };
        return Ok((value, mask));
    };
    verbose_checks(req, &tb)?;
    let (mut value, mut mask) = (0, if no_mask { low(nbits) } else { 0 });
    for (raw, entry) in raw_attrs(bits) {
        let (idx, val) = parse_bit(req, raw, entry, nbits, no_mask, names)?;
        if val {
            value |= 1 << idx;
        }
        if !no_mask {
            mask |= 1 << idx;
        }
    }
    Ok((value, mask))
}

// STRSET, as net/ethtool/strset.c of Linux.

/// Parses the string sets of a request, as `strset_parse_request` of Linux.
fn strset_parse(req: &Request<'_>, attrs: &Attrs<'_>, ri: &mut ReqInfo<'_>) -> Result<()> {
    let Some(nest) = attrs.get(2) else { return Ok(()) };
    policy::validate(req, nest, &STRINGSETS_POLICY, policy::STRICT)?;
    ri.counts_only = attrs.has(3);
    for (raw, entry) in raw_attrs(nest) {
        if u32::from(raw) & NLA_TYPE_MASK != 1 {
            return Err(Errno::EINVAL);
        }
        let tb = nested(req, raw, entry, &STRINGSET_POLICY)?;
        let Some(id) = tb.get(1).map(get_u32) else {
            return Err(req.missing(Some(entry), 1));
        };
        if id >= SS_COUNT {
            return Err(req.attr_error("unknown string set id", entry, Errno::EOPNOTSUPP));
        }
        ri.req_ids |= 1 << id;
    }
    Ok(())
}

/// The strings of a string set.
enum Set {
    /// The strings of each device.
    PerDev,
    /// The strings of the kernel.
    Global(&'static [&'static str]),
    /// A set that Linux does not have any more, `ETH_SS_NTUPLE_FILTERS`.
    Gone,
}

/// The string set `id`, as `info_template` of Linux.
fn set(id: u32) -> Set {
    match id {
        0..=2 | 7 => Set::PerDev,
        4 => Set::Global(&features::NAMES),
        5 => Set::Global(&["toeplitz", "xor", "crc32"]),
        6 => Set::Global(&[
            "Unspec",
            "rx-copybreak",
            "tx-copybreak",
            "pfc-prevention-tout",
            "tx-copybreak-buf-size",
        ]),
        8 => Set::Global(&[
            "Unspec",
            "phy-downshift",
            "phy-fast-link-down",
            "phy-energy-detect-power-down",
            "phy-short-cable-preset",
            "phy-lpf-bandwidth",
            "phy-dsp-eq-init-value",
        ]),
        9 => Set::Global(&LINK_MODES),
        10 => Set::Global(&[
            "drv",
            "probe",
            "link",
            "timer",
            "ifdown",
            "ifup",
            "rx_err",
            "tx_err",
            "tx_queued",
            "intr",
            "tx_done",
            "rx_status",
            "pktdata",
            "hw",
            "wol",
        ]),
        11 => Set::Global(&[
            "phy",
            "ucast",
            "mcast",
            "bcast",
            "arp",
            "magic",
            "magicsecure",
            "filter",
        ]),
        12 => Set::Global(&[
            "hardware-transmit",
            "software-transmit",
            "hardware-receive",
            "software-receive",
            "software-system-clock",
            "hardware-legacy-clock",
            "hardware-raw-clock",
            "option-id",
            "sched-transmit",
            "ack-transmit",
            "option-cmsg",
            "option-tsonly",
            "option-stats",
            "option-pktinfo",
            "option-tx-swhw",
            "bind-phc",
            "option-id-tcp",
            "option-rx-filter",
            "tx-completion",
        ]),
        13 => Set::Global(&["off", "on", "onestep-sync", "onestep-p2p"]),
        14 => Set::Global(&[
            "none",
            "all",
            "some",
            "ptpv1-l4-event",
            "ptpv1-l4-sync",
            "ptpv1-l4-delay-req",
            "ptpv2-l4-event",
            "ptpv2-l4-sync",
            "ptpv2-l4-delay-req",
            "ptpv2-l2-event",
            "ptpv2-l2-sync",
            "ptpv2-l2-delay-req",
            "ptpv2-event",
            "ptpv2-sync",
            "ptpv2-delay-req",
            "ntp-all",
        ]),
        15 => Set::Global(&["vxlan", "geneve", "vxlan-gpe"]),
        16 => Set::Global(&["eth-phy", "eth-mac", "eth-ctrl", "rmon", "phydev"]),
        17 => Set::Global(&["SymbolErrorDuringCarrier"]),
        18 => Set::Global(&[
            "FramesTransmittedOK",
            "SingleCollisionFrames",
            "MultipleCollisionFrames",
            "FramesReceivedOK",
            "FrameCheckSequenceErrors",
            "AlignmentErrors",
            "OctetsTransmittedOK",
            "FramesWithDeferredXmissions",
            "LateCollisions",
            "FramesAbortedDueToXSColls",
            "FramesLostDueToIntMACXmitError",
            "CarrierSenseErrors",
            "OctetsReceivedOK",
            "FramesLostDueToIntMACRcvError",
            "MulticastFramesXmittedOK",
            "BroadcastFramesXmittedOK",
            "FramesWithExcessiveDeferral",
            "MulticastFramesReceivedOK",
            "BroadcastFramesReceivedOK",
            "InRangeLengthErrors",
            "OutOfRangeLengthField",
            "FrameTooLongErrors",
        ]),
        19 => Set::Global(&[
            "MACControlFramesTransmitted",
            "MACControlFramesReceived",
            "UnsupportedOpcodesReceived",
        ]),
        20 => Set::Global(&[
            "etherStatsUndersizePkts",
            "etherStatsOversizePkts",
            "etherStatsFragments",
            "etherStatsJabbers",
        ]),
        21 => {
            Set::Global(&["RxFrames", "RxOctets", "RxErrors", "TxFrames", "TxOctets", "TxErrors"])
        }
        22 => Set::Global(&["bonded-phc-index"]),
        _ => Set::Gone,
    }
}

/// Tells if the reply has the string set `id`, as `strset_include` of Linux.
fn strset_include(ri: &ReqInfo<'_>, dev: Option<&NetDevice>, id: u32) -> bool {
    if ri.req_ids != 0 {
        return ri.req_ids & (1 << id) != 0;
    }
    match set(id) {
        Set::Gone => false,
        Set::PerDev => dev.is_some(),
        Set::Global(_) => dev.is_none(),
    }
}

fn strset_fill(
    req: Option<&Request<'_>>,
    ri: &ReqInfo<'_>,
    dev: Option<&NetDevice>,
    b: &mut Builder,
) -> Result<()> {
    // `strset_prepare_data` of Linux.
    if dev.is_none() {
        if (0..SS_COUNT).any(|i| ri.req_ids & (1 << i) != 0 && matches!(set(i), Set::PerDev)) {
            let text = "requested per device strings without dev";
            return Err(fail(req, text, Errno::EINVAL));
        }
    } else if ri.dev.is_some() && ri.phy_index != 0 {
        // No device has a PHY.
        let e = Errno::ENODEV;
        return Err(match (req, ri.header) {
            (Some(r), Some(h)) => r.attr_error("no phy matching phyindex", h, e),
            _ => e,
        });
    }
    put_header(b, dev);
    let sets = b.nest(2 | NLA_F_NESTED as u16);
    for id in (0..SS_COUNT).filter(|&id| strset_include(ri, dev, id)) {
        let stats: Vec<String>;
        let owned: Vec<&str>;
        let names: &[&str] = match set(id) {
            Set::Gone => return Err(Errno::EOPNOTSUPP),
            Set::Global(n) => n,
            Set::PerDev => {
                stats = match dev {
                    Some(d) if id == SS_STATS => d.driver().stat_names(),
                    _ => Vec::new(),
                };
                owned = stats.iter().map(String::as_str).collect();
                &owned
            }
        };
        if names.is_empty() {
            continue;
        }
        let s = b.nest(1 | NLA_F_NESTED as u16);
        b.u32(1, id).u32(2, names.len() as u32);
        if !ri.counts_only {
            let strings = b.nest(3 | NLA_F_NESTED as u16);
            for (i, n) in names.iter().enumerate() {
                let one = b.nest(1 | NLA_F_NESTED as u16);
                b.u32(1, i as u32).str(2, n);
                b.end_nest(one);
            }
            b.end_nest(strings);
        }
        b.end_nest(s);
    }
    b.end_nest(sets);
    Ok(())
}

/// The names of the link modes, `link_mode_names` of Linux.
static LINK_MODES: [&str; LINK_MODE_COUNT as usize] = [
    "10baseT/Half",
    "10baseT/Full",
    "100baseT/Half",
    "100baseT/Full",
    "1000baseT/Half",
    "1000baseT/Full",
    "Autoneg",
    "TP",
    "AUI",
    "MII",
    "FIBRE",
    "BNC",
    "10000baseT/Full",
    "Pause",
    "Asym_Pause",
    "2500baseX/Full",
    "Backplane",
    "1000baseKX/Full",
    "10000baseKX4/Full",
    "10000baseKR/Full",
    "10000baseR_FEC",
    "20000baseMLD2/Full",
    "20000baseKR2/Full",
    "40000baseKR4/Full",
    "40000baseCR4/Full",
    "40000baseSR4/Full",
    "40000baseLR4/Full",
    "56000baseKR4/Full",
    "56000baseCR4/Full",
    "56000baseSR4/Full",
    "56000baseLR4/Full",
    "25000baseCR/Full",
    "25000baseKR/Full",
    "25000baseSR/Full",
    "50000baseCR2/Full",
    "50000baseKR2/Full",
    "100000baseKR4/Full",
    "100000baseSR4/Full",
    "100000baseCR4/Full",
    "100000baseLR4_ER4/Full",
    "50000baseSR2/Full",
    "1000baseX/Full",
    "10000baseCR/Full",
    "10000baseSR/Full",
    "10000baseLR/Full",
    "10000baseLRM/Full",
    "10000baseER/Full",
    "2500baseT/Full",
    "5000baseT/Full",
    "None",
    "RS",
    "BASER",
    "50000baseKR/Full",
    "50000baseSR/Full",
    "50000baseCR/Full",
    "50000baseLR_ER_FR/Full",
    "50000baseDR/Full",
    "100000baseKR2/Full",
    "100000baseSR2/Full",
    "100000baseCR2/Full",
    "100000baseLR2_ER2_FR2/Full",
    "100000baseDR2/Full",
    "200000baseKR4/Full",
    "200000baseSR4/Full",
    "200000baseLR4_ER4_FR4/Full",
    "200000baseDR4/Full",
    "200000baseCR4/Full",
    "100baseT1/Full",
    "1000baseT1/Full",
    "400000baseKR8/Full",
    "400000baseSR8/Full",
    "400000baseLR8_ER8_FR8/Full",
    "400000baseDR8/Full",
    "400000baseCR8/Full",
    "LLRS",
    "100000baseKR/Full",
    "100000baseSR/Full",
    "100000baseLR_ER_FR/Full",
    "100000baseCR/Full",
    "100000baseDR/Full",
    "200000baseKR2/Full",
    "200000baseSR2/Full",
    "200000baseLR2_ER2_FR2/Full",
    "200000baseDR2/Full",
    "200000baseCR2/Full",
    "400000baseKR4/Full",
    "400000baseSR4/Full",
    "400000baseLR4_ER4_FR4/Full",
    "400000baseDR4/Full",
    "400000baseCR4/Full",
    "100baseFX/Half",
    "100baseFX/Full",
    "10baseT1L/Full",
    "800000baseCR8/Full",
    "800000baseKR8/Full",
    "800000baseDR8/Full",
    "800000baseDR8_2/Full",
    "800000baseSR8/Full",
    "800000baseVR8/Full",
    "10baseT1S/Full",
    "10baseT1S/Half",
    "10baseT1S_P2MP/Half",
    "10baseT1BRR/Full",
    "200000baseCR/Full",
    "200000baseKR/Full",
    "200000baseDR/Full",
    "200000baseDR_2/Full",
    "200000baseSR/Full",
    "200000baseVR/Full",
    "400000baseCR2/Full",
    "400000baseKR2/Full",
    "400000baseDR2/Full",
    "400000baseDR2_2/Full",
    "400000baseSR2/Full",
    "400000baseVR2/Full",
    "800000baseCR4/Full",
    "800000baseKR4/Full",
    "800000baseDR4/Full",
    "800000baseDR4_2/Full",
    "800000baseSR4/Full",
    "800000baseVR4/Full",
    "1600000baseCR8/Full",
    "1600000baseKR8/Full",
    "1600000baseDR8/Full",
    "1600000baseDR8_2/Full",
];

// The ioctl `SIOCETHTOOL`, as net/ethtool/ioctl.c of Linux.

const ETHTOOL_GDRVINFO: u32 = 0x03;
const ETHTOOL_GLINK: u32 = 0x0a;
const ETHTOOL_GPERMADDR: u32 = 0x20;
const ETHTOOL_PERQUEUE: u32 = 0x4b;
const ETHTOOL_GLINKSETTINGS: u32 = 0x4c;

/// The commands that do not need `CAP_NET_ADMIN`, as the list of `__dev_ethtool` of Linux.
const UNPRIVILEGED: [u32; 36] = [
    0x01, 0x03, 0x07, 0x0a, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x37, 0x1b, 0x1d, 0x4a, 0x1e, 0x20,
    0x21, 0x23, 0x2b, 0x25, 0x27, 0x29, 0x2d, 0x2e, 0x2f, 0x30, 0x38, 0x46, 0x3a, 0x3c, 0x41, 0x44,
    0x48, 0x4e, 0x4c, 0x50,
];

/// The size of `struct ethtool_drvinfo`.
const DRVINFO_LEN: usize = 196;
/// The size of `struct ethtool_link_settings`.
const LINK_SETTINGS_LEN: usize = 48;

/// Copies `s` into the string field at `at` of 32 bytes, as `strscpy` of Linux.
fn put_str(buf: &mut [u8], at: usize, s: &str) {
    let n = s.len().min(31);
    buf[at..at + n].copy_from_slice(&s.as_bytes()[..n]);
}

/// Runs the command at `ifr_data` of the `struct ifreq` `r`, as `dev_ethtool` of Linux. This
/// has `ETHTOOL_GDRVINFO`, `ETHTOOL_GLINK`, `ETHTOOL_GPERMADDR` and `ETHTOOL_GLINKSETTINGS`.
///
/// # Errors
///
/// Gives `EFAULT` for bad memory, `ENODEV` for a name that no device has, `EPERM` for a
/// change without `CAP_NET_ADMIN`, and `EOPNOTSUPP` for a command that the device or rukernel
/// does not have.
pub fn ioctl(r: &IfReq, mem: &dyn UserMemory) -> Result<usize> {
    let data = u64::from_ne_bytes(r.buf[16..24].try_into().unwrap_or_default()) as usize;
    let read_u32 = |at: usize| -> Result<u32> {
        let mut b = [0; 4];
        mem.read(at, &mut b).map_err(|_| Errno::EFAULT)?;
        Ok(u32::from_ne_bytes(b))
    };
    let write = |at: usize, b: &[u8]| mem.write(at, b).map_err(|_| Errno::EFAULT);
    let cmd = read_u32(data)?;
    let dev = core::str::from_utf8(r.dev_name()).ok().and_then(dev::by_name);
    let dev = dev.ok_or(Errno::ENODEV)?;
    let sub_cmd = if cmd == ETHTOOL_PERQUEUE { read_u32(data + 4)? } else { cmd };
    if !UNPRIVILEGED.contains(&sub_cmd) && !net_admin() {
        return Err(Errno::EPERM);
    }
    let driver = dev.driver();
    match cmd {
        ETHTOOL_GDRVINFO => {
            let mut b = [0u8; DRVINFO_LEN];
            b[0..4].copy_from_slice(&cmd.to_ne_bytes());
            put_str(&mut b, 36, UTS_RELEASE);
            if let Some(i) = driver.drvinfo() {
                put_str(&mut b, 4, &i.driver);
                if !i.version.is_empty() {
                    b[36..68].fill(0);
                    put_str(&mut b, 36, &i.version);
                }
                put_str(&mut b, 68, &i.fw_version);
                put_str(&mut b, 100, &i.bus_info);
                let n = driver.stat_names().len() as u32;
                b[180..184].copy_from_slice(&n.to_ne_bytes());
            } else if let Some(kind) = dev.link_kind() {
                put_str(&mut b, 4, kind);
            } else {
                return Err(Errno::EOPNOTSUPP);
            }
            write(data, &b)?;
        }
        ETHTOOL_GLINK => {
            if !driver.has_get_link() {
                return Err(Errno::EOPNOTSUPP);
            }
            let up = u32::from(dev.is_up() && dev.carrier());
            let mut b = [0u8; 8];
            b[0..4].copy_from_slice(&cmd.to_ne_bytes());
            b[4..8].copy_from_slice(&up.to_ne_bytes());
            write(data, &b)?;
        }
        ETHTOOL_GPERMADDR => {
            let size = read_u32(data + 4)?;
            let len = match dev.kind() {
                LinkKind::Ether | LinkKind::Loopback => 6,
                _ => 0,
            };
            if size < len {
                return Err(Errno::ETOOSMALL);
            }
            let mut b = [0u8; 8];
            b[0..4].copy_from_slice(&cmd.to_ne_bytes());
            b[4..8].copy_from_slice(&len.to_ne_bytes());
            write(data, &b)?;
            write(data + 8, &driver.perm_addr().0[..len as usize])?;
        }
        ETHTOOL_GLINKSETTINGS => {
            let Some(s) = driver.link_settings() else { return Err(Errno::EOPNOTSUPP) };
            let mut base = [0u8; LINK_SETTINGS_LEN];
            mem.read(data, &mut base).map_err(|_| Errno::EFAULT)?;
            if base[15] as i8 != LINK_MODE_NU32 as i8 {
                // The user asks for the number of words: give it as a negative number.
                let mut b = [0u8; LINK_SETTINGS_LEN];
                b[0..4].copy_from_slice(&cmd.to_ne_bytes());
                b[15] = (-(LINK_MODE_NU32 as i8)) as u8;
                write(data, &b)?;
                return Ok(0);
            }
            let mut b = [0u8; LINK_SETTINGS_LEN + 3 * 4 * LINK_MODE_NU32];
            b[0..4].copy_from_slice(&cmd.to_ne_bytes());
            b[4..8].copy_from_slice(&s.speed.to_ne_bytes());
            b[8..15].copy_from_slice(&[
                s.duplex,
                s.port,
                s.phy_address,
                s.autoneg,
                s.mdio_support,
                s.eth_tp_mdix,
                s.eth_tp_mdix_ctrl,
            ]);
            b[15] = LINK_MODE_NU32 as u8;
            b[16] = s.transceiver;
            // The master and slave fields and the rate matching are 0, unsupported.
            for (k, m) in [s.supported, s.advertising, s.lp_advertising].into_iter().enumerate() {
                for w in 0..LINK_MODE_NU32 {
                    let at = LINK_SETTINGS_LEN + (k * LINK_MODE_NU32 + w) * 4;
                    b[at..at + 4].copy_from_slice(&((m >> (32 * w)) as u32).to_ne_bytes());
                }
            }
            write(data, &b)?;
        }
        _ => return Err(Errno::EOPNOTSUPP),
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_mode_names_match_linux() {
        assert_eq!(LINK_MODES[6], "Autoneg");
        assert_eq!(LINK_MODES[74], "LLRS");
        assert!(LINK_MODES.iter().all(|n| !n.is_empty()));
        for i in [6, 7, 8, 9, 10, 11, 13, 14, 16, 49, 50, 51, 74] {
            assert!(!LINK_MODES[i].contains("base"), "{}", LINK_MODES[i]);
        }
    }

    #[test]
    fn bitset_words_load_low_word_first() {
        let d = [1, 0, 0, 0, 2, 0, 0, 0];
        assert_eq!(load(&d, 64), 1 | 2 << 32);
        assert_eq!(load(&d, 33), 1);
        assert_eq!(low(3), 7);
        assert_eq!(low(128), u128::MAX);
        assert!(any_bit(&d, 33, 64));
        assert!(!any_bit(&d, 34, 64));
    }

    #[test]
    fn virtdev_set_takes_only_speed_and_duplex() {
        let (speed, duplex) = (AtomicU32::new(SPEED_UNKNOWN), AtomicU8::new(DUPLEX_UNKNOWN));
        let base = LinkSettings { port: PORT_OTHER, ..LinkSettings::default() };
        let s = LinkSettings { speed: 1000, duplex: DUPLEX_FULL, ..base };
        assert_eq!(virtdev_set(&s, &speed, &duplex), Ok(()));
        assert_eq!((speed.load(Ordering::Relaxed), duplex.load(Ordering::Relaxed)), (1000, 1));
        let bad = LinkSettings { autoneg: 1, ..s };
        assert_eq!(virtdev_set(&bad, &speed, &duplex), Err(Errno::EINVAL));
        let bad = LinkSettings { port: PORT_TP, ..s };
        assert_eq!(virtdev_set(&bad, &speed, &duplex), Err(Errno::EINVAL));
        let bad = LinkSettings { duplex: 2, ..s };
        assert_eq!(virtdev_set(&bad, &speed, &duplex), Err(Errno::EINVAL));
    }
}

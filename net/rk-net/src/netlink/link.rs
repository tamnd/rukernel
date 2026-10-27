//! The messages of the links: `RTM_GETLINK`, `RTM_NEWLINK` and `RTM_SETLINK`, as
//! net/core/rtnetlink.c of Linux.

use super::msg::{Attrs, Builder};
use super::{Origin, Request, notify, register};
use crate::consts::IFNAMSIZ;
use crate::dev::{self, Event, LinkKind, NetDevice};
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::if_link::{
    IFLA_ADDRESS, IFLA_AF_SPEC, IFLA_ALLMULTI, IFLA_ALT_IFNAME, IFLA_BROADCAST, IFLA_CARRIER,
    IFLA_CARRIER_CHANGES, IFLA_CARRIER_DOWN_COUNT, IFLA_CARRIER_UP_COUNT, IFLA_EXT_MASK,
    IFLA_GRO_IPV4_MAX_SIZE, IFLA_GRO_MAX_SIZE, IFLA_GROUP, IFLA_GSO_IPV4_MAX_SIZE,
    IFLA_GSO_MAX_SEGS, IFLA_GSO_MAX_SIZE, IFLA_HEADROOM, IFLA_IFNAME, IFLA_LINKINFO, IFLA_LINKMODE,
    IFLA_MAP, IFLA_MASTER, IFLA_MAX_MTU, IFLA_MAX_PACING_OFFLOAD_HORIZON, IFLA_MIN_MTU, IFLA_MTU,
    IFLA_NETNS_IMMUTABLE, IFLA_NUM_RX_QUEUES, IFLA_NUM_TX_QUEUES, IFLA_NUM_VF, IFLA_OPERSTATE,
    IFLA_PARENT_DEV_BUS_NAME, IFLA_PARENT_DEV_NAME, IFLA_PERM_ADDRESS, IFLA_PROMISCUITY,
    IFLA_PROTINFO, IFLA_PROTO_DOWN, IFLA_QDISC, IFLA_STATS, IFLA_STATS64, IFLA_TAILROOM,
    IFLA_TARGET_NETNSID, IFLA_TSO_MAX_SEGS, IFLA_TSO_MAX_SIZE, IFLA_TXQLEN, IFLA_XDP,
    IFLA_XDP_ATTACHED, XDP_ATTACHED_NONE,
};
use rk_abi::native::netlink::{NLM_F_CREATE, NLM_F_EXCL, NLM_F_MULTI, NLM_F_REPLACE};
use rk_abi::native::rtnetlink::{RTM_GETLINK, RTM_NEWLINK, RTM_SETLINK, RTNLGRP_LINK};
use rk_frame::sync::SpinLock;
use rk_vfs::inode::Result;

/// The size of `struct ifinfomsg`.
pub const IFINFO_LEN: usize = 16;

/// The largest attribute type of a link, `IFLA_MAX` of Linux 7.3.
const IFLA_MAX: u16 = 69;

/// The flags of `IFLA_EXT_MASK`, `RTEXT_FILTER_*` of <linux/rtnetlink.h>. They are macros of
/// shifts that rk-abigen does not read, thus they are here by hand.
const RTEXT_FILTER_VF: u32 = 1 << 0;
const RTEXT_FILTER_SKIP_STATS: u32 = 1 << 3;
const RTEXT_FILTER_NAME_ONLY: u32 = 1 << 8;

/// The largest segment counts and sizes of the offloads, as Linux sets them for a new device:
/// `GSO_MAX_SEGS`, `GSO_LEGACY_MAX_SIZE` and `GSO_MAX_SIZE`.
const GSO_MAX_SEGS: u32 = 65535;
const GSO_LEGACY_MAX_SIZE: u32 = 65536;
const GSO_MAX_SIZE: u32 = 8 * GSO_MAX_SEGS;

/// The function of a family that adds its attributes of a link in `IFLA_AF_SPEC`, as
/// `fill_link_af` of Linux. It gives `false` if it has no data for the device.
pub type AfFill = fn(&NetDevice, &mut Builder) -> bool;

static AF: SpinLock<Vec<(u16, AfFill)>> = SpinLock::new(Vec::new());

/// Registers the attributes of the family `family` in `IFLA_AF_SPEC`, as `rtnl_af_register`
/// of Linux.
pub fn register_af(family: u16, fill: AfFill) {
    AF.lock().push((family, fill));
}

pub(super) fn init() {
    register(0, RTM_GETLINK, Some(getlink), Some(dump), true);
    register(0, RTM_NEWLINK, Some(newlink), None, false);
    register(0, RTM_SETLINK, Some(setlink), None, false);
    dev::add_notifier(event);
}

/// The bytes of `struct ifinfomsg` for a device.
fn ifinfo(dev: &NetDevice, change: u32) -> [u8; IFINFO_LEN] {
    let mut h = [0; IFINFO_LEN];
    h[2..4].copy_from_slice(&dev.kind().arphrd().to_ne_bytes());
    h[4..8].copy_from_slice(&dev.ifindex().to_ne_bytes());
    h[8..12].copy_from_slice(&dev.flags().to_ne_bytes());
    h[12..16].copy_from_slice(&change.to_ne_bytes());
    h
}

/// Builds the message of a link, as `rtnl_fill_ifinfo` of Linux. The attributes are in the
/// order of Linux.
pub fn fill(
    dev: &NetDevice,
    ty: u32,
    portid: u32,
    seq: u32,
    change: u32,
    flags: u32,
    ext: u32,
) -> Vec<u8> {
    let mut b = Builder::new(ty as u16, flags as u16, seq, portid);
    b.fixed(&ifinfo(dev, change));
    b.str(IFLA_IFNAME as u16, &dev.name());
    if ext & RTEXT_FILTER_NAME_ONLY != 0 {
        return b.finish();
    }
    let lo = dev.kind() == LinkKind::Loopback;
    let tso_max_size = if lo { GSO_MAX_SIZE } else { GSO_LEGACY_MAX_SIZE };
    b.u32(IFLA_TXQLEN as u16, dev.txqlen())
        .u8(IFLA_OPERSTATE as u16, dev.operstate())
        .u8(IFLA_LINKMODE as u16, 0)
        .u8(IFLA_NETNS_IMMUTABLE as u16, u8::from(lo))
        .u32(IFLA_MTU as u16, dev.mtu())
        .u32(IFLA_MIN_MTU as u16, dev.min_mtu())
        .u32(IFLA_MAX_MTU as u16, dev.max_mtu())
        .u32(IFLA_GROUP as u16, 0)
        .u32(IFLA_PROMISCUITY as u16, dev.promiscuity())
        .u32(IFLA_ALLMULTI as u16, dev.allmulti())
        .u32(IFLA_NUM_TX_QUEUES as u16, 1)
        .u32(IFLA_GSO_MAX_SEGS as u16, GSO_MAX_SEGS)
        .u32(IFLA_GSO_MAX_SIZE as u16, GSO_LEGACY_MAX_SIZE)
        .u32(IFLA_GRO_MAX_SIZE as u16, GSO_LEGACY_MAX_SIZE)
        .u32(IFLA_GSO_IPV4_MAX_SIZE as u16, GSO_LEGACY_MAX_SIZE)
        .u32(IFLA_GRO_IPV4_MAX_SIZE as u16, GSO_LEGACY_MAX_SIZE)
        .u32(IFLA_TSO_MAX_SIZE as u16, tso_max_size)
        .u32(IFLA_TSO_MAX_SEGS as u16, GSO_MAX_SEGS)
        .uint(IFLA_MAX_PACING_OFFLOAD_HORIZON as u16, 0)
        .u32(IFLA_NUM_RX_QUEUES as u16, 1)
        .u8(IFLA_CARRIER as u16, u8::from(dev.carrier()))
        .u32(IFLA_CARRIER_CHANGES as u16, dev.carrier_up_count())
        .u32(IFLA_CARRIER_UP_COUNT as u16, dev.carrier_up_count())
        .u32(IFLA_CARRIER_DOWN_COUNT as u16, 0)
        .u16(IFLA_HEADROOM as u16, 0)
        .u16(IFLA_TAILROOM as u16, 0)
        .u8(IFLA_PROTO_DOWN as u16, 0)
        .put(IFLA_ADDRESS as u16, &dev.mac().0)
        .put(IFLA_BROADCAST as u16, &dev.broadcast().0);
    if ext & RTEXT_FILTER_SKIP_STATS == 0 {
        let st = dev.stats();
        let mut s64 = [0u64; 25];
        s64[..8].copy_from_slice(&[
            st.rx_packets,
            st.tx_packets,
            st.rx_bytes,
            st.tx_bytes,
            st.rx_errors,
            st.tx_errors,
            st.rx_dropped,
            st.tx_dropped,
        ]);
        let b64: Vec<u8> = s64.iter().flat_map(|v| v.to_ne_bytes()).collect();
        let b32: Vec<u8> = s64[..24].iter().flat_map(|&v| (v as u32).to_ne_bytes()).collect();
        b.put(IFLA_STATS64 as u16, &b64).put(IFLA_STATS as u16, &b32);
    }
    let parent = dev.parent();
    if ext & RTEXT_FILTER_VF != 0 && parent.is_some() {
        b.u32(IFLA_NUM_VF as u16, 0);
    }
    let xdp = b.nest(IFLA_XDP as u16);
    b.u8(IFLA_XDP_ATTACHED as u16, XDP_ATTACHED_NONE as u8);
    b.end_nest(xdp);
    if dev.mac().0 != [0; 6] {
        b.put(IFLA_PERM_ADDRESS as u16, &dev.mac().0);
    }
    b.str(IFLA_QDISC as u16, dev.qdisc());
    let spec = b.nest(IFLA_AF_SPEC as u16);
    let families = AF.lock().clone();
    for (family, f) in families {
        let at = b.nest(family);
        if f(dev, &mut b) {
            b.end_nest(at);
        } else {
            b.truncate(at);
        }
    }
    b.end_nest(spec);
    // `struct rtnl_link_ifmap`: three u64, a u16 and two u8, padded to 32 bytes.
    b.put(IFLA_MAP as u16, &[0; 32]);
    if let Some((name, bus)) = parent {
        b.str(IFLA_PARENT_DEV_NAME as u16, &name);
        b.str(IFLA_PARENT_DEV_BUS_NAME as u16, bus);
    }
    b.finish()
}

/// Checks the attributes of a request against `ifla_policy` of Linux. A name of
/// `IFNAMSIZ` bytes or more without its NUL gives `ERANGE`.
fn check_policy(a: &Attrs<'_>) -> Result<()> {
    for ty in [IFLA_IFNAME, IFLA_ALT_IFNAME] {
        if a.str(ty).is_some_and(|n| n.len() >= IFNAMSIZ) {
            return Err(Errno::ERANGE);
        }
    }
    for ty in [IFLA_MTU, IFLA_TXQLEN, IFLA_EXT_MASK, IFLA_GROUP] {
        a.u32(ty)?;
    }
    for ty in [IFLA_OPERSTATE, IFLA_LINKMODE] {
        a.u8(ty)?;
    }
    Ok(())
}

fn i32_at(b: &[u8], at: usize) -> i32 {
    b.get(at..at + 4).map_or(0, |v| i32::from_ne_bytes([v[0], v[1], v[2], v[3]]))
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    i32_at(b, at) as u32
}

/// Finds the device of a request by the name in `IFLA_IFNAME`, as `rtnl_dev_get` of Linux.
fn by_name(a: &Attrs<'_>) -> Option<Arc<NetDevice>> {
    let name = a.str(IFLA_IFNAME).or_else(|| a.str(IFLA_ALT_IFNAME))?;
    dev::by_name(core::str::from_utf8(name).ok()?)
}

/// `RTM_GETLINK` for one device, as `rtnl_getlink` of Linux.
fn getlink(req: &Request<'_>) -> Result<()> {
    let (h, a) = req.parse(IFINFO_LEN, IFLA_MAX)?;
    if req.strict {
        if h[1] != 0 || u32_at(h, 0) >> 16 != 0 || u32_at(h, 8) != 0 || u32_at(h, 12) != 0 {
            return Err(Errno::EINVAL);
        }
        let allowed = [IFLA_IFNAME, IFLA_ALT_IFNAME, IFLA_EXT_MASK, IFLA_TARGET_NETNSID];
        if super::msg::attrs(&req.payload()[IFINFO_LEN..])
            .any(|(ty, _)| ty > 0 && ty <= IFLA_MAX && !allowed.contains(&u32::from(ty)))
        {
            return Err(Errno::EINVAL);
        }
    }
    check_policy(&a)?;
    let ext = a.u32(IFLA_EXT_MASK)?.unwrap_or(0);
    let index = i32_at(h, 4);
    let dev = if index > 0 {
        dev::by_index(index as u32)
    } else if a.has(IFLA_IFNAME) || a.has(IFLA_ALT_IFNAME) {
        by_name(&a)
    } else {
        return Err(Errno::EINVAL);
    };
    let dev = dev.ok_or(Errno::ENODEV)?;
    req.reply(fill(&dev, RTM_NEWLINK, req.portid, req.hdr.seq, 0, 0, ext));
    Ok(())
}

/// The dump of `RTM_GETLINK`, as `rtnl_dump_ifinfo` of Linux.
fn dump(req: &Request<'_>) -> Result<Vec<Vec<u8>>> {
    let p = req.payload();
    let mut ext = 0;
    if req.strict {
        let (h, a) = req.parse(IFINFO_LEN, IFLA_MAX)?;
        if h[1] != 0 || u32_at(h, 0) >> 16 != 0 || u32_at(h, 8) != 0 || u32_at(h, 12) != 0 {
            return Err(Errno::EINVAL);
        }
        if i32_at(h, 4) != 0 {
            return Err(Errno::EINVAL);
        }
        check_policy(&a)?;
        for (ty, _) in super::msg::attrs(&p[IFINFO_LEN..]) {
            match u32::from(ty) {
                IFLA_EXT_MASK | IFLA_TARGET_NETNSID | IFLA_LINKINFO | IFLA_MASTER => {}
                t if t > u32::from(IFLA_MAX) => {}
                _ => return Err(Errno::EINVAL),
            }
        }
        ext = a.u32(IFLA_EXT_MASK)?.unwrap_or(0);
    } else {
        // An old request has only `struct rtgenmsg` before the attributes.
        let hdrlen = if p.len() < IFINFO_LEN { 1 } else { IFINFO_LEN };
        let a = Attrs::parse(&p[super::msg::align(hdrlen).min(p.len())..], IFLA_MAX);
        if check_policy(&a).is_ok() {
            ext = a.u32(IFLA_EXT_MASK).ok().flatten().unwrap_or(0);
        }
    }
    let flags = NLM_F_MULTI;
    Ok(dev::devices()
        .iter()
        .map(|d| fill(d, RTM_NEWLINK, req.portid, req.hdr.seq, 0, flags, ext))
        .collect())
}

/// Changes a device, as `do_setlink` of Linux: the MTU, the name, the flags and the length of
/// the queue. A change of the hardware address gives `EOPNOTSUPP`.
fn setlink_dev(dev: &NetDevice, h: &[u8], a: &Attrs<'_>) -> Result<()> {
    for ty in [IFLA_ADDRESS, IFLA_BROADCAST] {
        if a.get(ty).is_some_and(|v| v.len() < 6) {
            return Err(Errno::EINVAL);
        }
    }
    if a.has(IFLA_MAP) || a.has(IFLA_ADDRESS) {
        return Err(Errno::EOPNOTSUPP);
    }
    if let Some(mtu) = a.u32(IFLA_MTU)? {
        dev.set_mtu(mtu)?;
    }
    if i32_at(h, 4) > 0
        && let Some(name) = a.str(IFLA_IFNAME)
    {
        dev.set_name(name)?;
    }
    let (flags, change) = (u32_at(h, 8), u32_at(h, 12));
    if flags != 0 || change != 0 {
        let flags = if change != 0 { (flags & change) | (dev.flags() & !change) } else { flags };
        dev.change_flags(flags)?;
    }
    if let Some(len) = a.u32(IFLA_TXQLEN)? {
        dev.set_txqlen(len);
    }
    Ok(())
}

/// `RTM_NEWLINK`, as `rtnl_newlink` of Linux. Only a change of a device is here: a new device of
/// a kind gives `EOPNOTSUPP`.
fn newlink(req: &Request<'_>) -> Result<()> {
    let (h, a) = req.parse(IFINFO_LEN, IFLA_MAX)?;
    check_policy(&a)?;
    let index = i32_at(h, 4);
    let flags = u32::from(req.hdr.flags);
    let (dev, named) = if index > 0 {
        (dev::by_index(index as u32), true)
    } else if index < 0 {
        return Err(Errno::EINVAL);
    } else if a.has(IFLA_IFNAME) || a.has(IFLA_ALT_IFNAME) {
        (by_name(&a), true)
    } else {
        (None, false)
    };
    let Some(dev) = dev else {
        if flags & NLM_F_CREATE == 0 {
            return if named || !a.has(IFLA_GROUP) { Err(Errno::ENODEV) } else { Ok(()) };
        }
        return Err(Errno::EOPNOTSUPP);
    };
    if flags & NLM_F_EXCL != 0 {
        return Err(Errno::EEXIST);
    }
    if flags & NLM_F_REPLACE != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if a.has(IFLA_PROTINFO) {
        return Err(Errno::EOPNOTSUPP);
    }
    setlink_dev(&dev, h, &a)
}

/// `RTM_SETLINK`, as `rtnl_setlink` of Linux.
fn setlink(req: &Request<'_>) -> Result<()> {
    let (h, a) = req.parse(IFINFO_LEN, IFLA_MAX)?;
    check_policy(&a)?;
    let index = i32_at(h, 4);
    let dev = if index > 0 {
        dev::by_index(index as u32)
    } else if a.has(IFLA_IFNAME) || a.has(IFLA_ALT_IFNAME) {
        by_name(&a)
    } else {
        return Err(Errno::EINVAL);
    };
    let dev = dev.ok_or(Errno::ENODEV)?;
    setlink_dev(&dev, h, &a)
}

/// Sends `RTM_NEWLINK` to the group `RTNLGRP_LINK` for a change of a device, as `rtmsg_ifinfo`
/// of Linux.
fn event(dev: &NetDevice, e: Event) {
    let change = match e {
        Event::Flags(c) => c,
        Event::Mtu | Event::Name => 0,
        Event::Up | Event::Down => return,
    };
    if !super::has_listeners(RTNLGRP_LINK) {
        return;
    }
    notify(RTNLGRP_LINK, fill(dev, RTM_NEWLINK, 0, 0, change, 0, 0), Origin::KERNEL);
}

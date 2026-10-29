//! The ioctls of IPv4 sockets, as `inet_ioctl`, `devinet_ioctl`, `ip_rt_ioctl` and `arp_ioctl`
//! of Linux: the addresses of the interfaces, the routes of `route add` and the ARP entries of
//! `arp -s` and `arp -d`. The other socket ioctls go to the
//! calls of the network devices in rk-net.

use crate::fib;
use crate::ipv4::{self, Addr};
use crate::neigh::Nud;
use crate::route::{IfAddr, Match, RTAX_ADVMSS, RTAX_RTT, RTAX_WINDOW, Route};
use crate::stack::ROUTES;
use alloc::string::String;
use rk_abi::Errno;
use rk_abi::native::netlink::{NLM_F_CREATE, NLM_F_REPLACE};
use rk_abi::native::rtnetlink::{
    RT_SCOPE_HOST, RT_SCOPE_LINK, RT_SCOPE_NOWHERE, RT_SCOPE_UNIVERSE, RT_TABLE_MAIN, RTN_UNICAST,
    RTN_UNREACHABLE, RTPROT_BOOT,
};
use rk_abi::native::sockios::{
    SIOCADDRT, SIOCDARP, SIOCDELRT, SIOCGARP, SIOCGIFADDR, SIOCGIFBRDADDR, SIOCGIFDSTADDR,
    SIOCGIFNETMASK, SIOCGIFPFLAGS, SIOCRTMSG, SIOCSARP, SIOCSIFADDR, SIOCSIFBRDADDR,
    SIOCSIFDSTADDR, SIOCSIFFLAGS, SIOCSIFNETMASK, SIOCSIFPFLAGS,
};
use rk_net::consts::{
    AF_INET, ATF_COM, ATF_DONTPUB, ATF_NETMASK, ATF_PERM, ATF_PUBL, IFF_BROADCAST, IFF_POINTOPOINT,
    IFF_UP, IFNAMSIZ, RTF_GATEWAY, RTF_HOST, RTF_IRTT, RTF_MTU, RTF_REJECT, RTF_WINDOW,
};
use rk_net::dev::{self, NetDevice};
use rk_net::ether::MacAddr;
use rk_net::ioctl::{IfReq, net_admin};
use rk_net::netlink::Origin;
use rk_vfs::UserMemory;
use rk_vfs::inode::Result;

/// The size of `struct rtentry` on a 64-bit machine.
const RTENTRY_LEN: usize = 120;
/// The size of `struct arpreq`.
const ARPREQ_LEN: usize = 68;

/// The ioctls of an IPv4 socket. Gives `None` for a call that IPv4 does not take, as
/// `ENOIOCTLCMD`.
pub(crate) fn inet_ioctl(cmd: u32, arg: usize, mem: &dyn UserMemory) -> Option<Result<usize>> {
    Some(match cmd {
        SIOCADDRT | SIOCDELRT => rt_ioctl(cmd, arg, mem).map(|()| 0),
        SIOCRTMSG => Err(Errno::EINVAL),
        SIOCSARP | SIOCDARP | SIOCGARP => arp_ioctl(cmd, arg, mem).map(|()| 0),
        SIOCGIFADDR | SIOCGIFBRDADDR | SIOCGIFNETMASK | SIOCGIFDSTADDR | SIOCGIFPFLAGS => {
            IfReq::read(mem, arg).and_then(|mut r| {
                devinet_ioctl(cmd, &mut r)?;
                r.write(mem, arg)?;
                Ok(0)
            })
        }
        SIOCSIFADDR | SIOCSIFBRDADDR | SIOCSIFNETMASK | SIOCSIFDSTADDR | SIOCSIFPFLAGS
        | SIOCSIFFLAGS => {
            IfReq::read(mem, arg).and_then(|mut r| devinet_ioctl(cmd, &mut r)).map(|()| 0)
        }
        _ => return None,
    })
}

/// The length of the prefix of the class of an address, as `inet_abc_len` of Linux. Gives
/// `None` for a multicast address.
fn abc_len(a: Addr) -> Option<u8> {
    if a[0] == 0 || a == ipv4::BROADCAST {
        return Some(0);
    }
    Some(match a[0] {
        0..=127 => 8,
        128..=191 => 16,
        192..=223 => 24,
        224..=239 => return None,
        _ => 32,
    })
}

/// Tells if `mask` is not a valid netmask for `addr`, as `bad_mask` of Linux: the address has
/// bits after the mask, or the mask has a hole.
fn bad_mask(mask: Addr, addr: Addr) -> bool {
    let (m, a) = (u32::from_be_bytes(mask), u32::from_be_bytes(addr));
    let host = !m;
    a & host != 0 || host & host.wrapping_add(1) != 0
}

/// The length of the prefix of a valid netmask, as `inet_mask_len` of Linux.
fn mask_len(mask: Addr) -> u8 {
    u32::from_be_bytes(mask).leading_ones() as u8
}

/// The interface ioctls of IPv4, as `devinet_ioctl` of Linux. A name as `eth0:1` names the
/// address with that label.
fn devinet_ioctl(cmd: u32, r: &mut IfReq) -> Result<()> {
    let family = r.family();
    let sin = r.addr4();
    let mut try_addr = false;
    match cmd {
        SIOCGIFADDR | SIOCGIFBRDADDR | SIOCGIFDSTADDR | SIOCGIFNETMASK => {
            try_addr = u32::from(family) == AF_INET;
            r.set_addr4(AF_INET as u16, ipv4::ANY);
        }
        SIOCSIFFLAGS => {
            if !net_admin() {
                return Err(Errno::EPERM);
            }
        }
        SIOCSIFADDR | SIOCSIFBRDADDR | SIOCSIFDSTADDR | SIOCSIFNETMASK => {
            if !net_admin() {
                return Err(Errno::EPERM);
            }
            if u32::from(family) != AF_INET {
                return Err(Errno::EINVAL);
            }
        }
        _ => return Err(Errno::EINVAL),
    }
    let d = core::str::from_utf8(r.dev_name()).ok().and_then(dev::by_name).ok_or(Errno::ENODEV)?;
    let name = String::from_utf8_lossy(r.name()).into_owned();
    let ifindex = d.ifindex();
    // The address with the label and the local address of the request, as 4.4BSD, else the
    // first address with the label, as 4.3BSD.
    let ifa = {
        let t = ROUTES.lock();
        let mut it = t.addrs_of(ifindex);
        let by_addr = if try_addr { it.find(|a| a.label == name && a.local == sin) } else { None };
        by_addr.or_else(|| t.addrs_of(ifindex).find(|a| a.label == name)).cloned()
    };
    let colon = r.has_colon();
    let Some(ifa) = ifa else {
        return match cmd {
            SIOCSIFADDR => set_addr(&d, &name, colon, None, sin),
            SIOCSIFFLAGS if !colon => d.change_flags(i32::from(r.short()) as u32),
            _ => Err(Errno::EADDRNOTAVAIL),
        };
    };
    let this = |o: &IfAddr| *o == ifa;
    match cmd {
        SIOCGIFADDR => r.set_addr4(AF_INET as u16, ifa.local),
        SIOCGIFBRDADDR => r.set_addr4(AF_INET as u16, ifa.broadcast),
        SIOCGIFDSTADDR => r.set_addr4(AF_INET as u16, ifa.address),
        SIOCGIFNETMASK => r.set_addr4(AF_INET as u16, ifa.netmask()),
        SIOCSIFFLAGS => {
            if !colon {
                return d.change_flags(i32::from(r.short()) as u32);
            }
            if i32::from(r.short()) as u32 & IFF_UP == 0 {
                fib::del_addr(ifindex, this, Origin::KERNEL)?;
            }
        }
        SIOCSIFADDR => set_addr(&d, &name, colon, Some(ifa), sin)?,
        SIOCSIFBRDADDR => {
            if ifa.broadcast != sin {
                let mut new = fib::del_addr(ifindex, this, Origin::KERNEL)?;
                new.broadcast = sin;
                insert(new)?;
            }
        }
        SIOCSIFDSTADDR => {
            if ifa.address != sin {
                if abc_len(sin).is_none() {
                    return Err(Errno::EINVAL);
                }
                let mut new = fib::del_addr(ifindex, this, Origin::KERNEL)?;
                new.address = sin;
                insert(new)?;
            }
        }
        SIOCSIFNETMASK => {
            if bad_mask(sin, ipv4::ANY) {
                return Err(Errno::EINVAL);
            }
            if ifa.netmask() != sin {
                let old_mask = ifa.mask();
                let mut new = fib::del_addr(ifindex, this, Origin::KERNEL)?;
                new.prefix = mask_len(sin);
                let local = u32::from_be_bytes(new.local);
                // A broadcast address that matches the old mask follows the new mask.
                if d.flags() & IFF_BROADCAST != 0
                    && new.prefix < 31
                    && u32::from_be_bytes(new.broadcast) == local | !old_mask
                {
                    new.broadcast = (local | !u32::from_be_bytes(sin)).to_be_bytes();
                }
                insert(new)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Adds an address again after a change, as `inet_insert_ifa` of Linux. The address 0.0.0.0
/// is not added.
fn insert(a: IfAddr) -> Result<()> {
    if a.local == ipv4::ANY {
        return Ok(());
    }
    fib::add_addr(a, Origin::KERNEL)
}

/// `SIOCSIFADDR`: sets the address of a label, with the netmask and the broadcast address of
/// its class, as `devinet_ioctl` and `inet_set_ifa` of Linux. The address 0.0.0.0 removes the
/// address.
fn set_addr(d: &NetDevice, name: &str, colon: bool, old: Option<IfAddr>, a: Addr) -> Result<()> {
    let Some(class) = abc_len(a) else { return Err(Errno::EINVAL) };
    let mut ifa = match old {
        None => {
            let label = if colon { String::from(name) } else { d.name() };
            IfAddr::new(d.ifindex(), a, 0, &label)
        }
        Some(old) => {
            if old.local == a {
                return Ok(());
            }
            let mut ifa = fib::del_addr(d.ifindex(), |o| *o == old, Origin::KERNEL)?;
            ifa.broadcast = ipv4::ANY;
            ifa.scope = RT_SCOPE_UNIVERSE as u8;
            ifa
        }
    };
    ifa.local = a;
    ifa.address = a;
    if d.flags() & IFF_POINTOPOINT == 0 {
        ifa.prefix = class;
        if d.flags() & IFF_BROADCAST != 0 && class < 31 {
            ifa.broadcast = ifa.default_broadcast();
        }
    } else {
        ifa.prefix = 32;
    }
    ifa.flags = rk_abi::native::if_addr::IFA_F_PERMANENT;
    ifa.valid = crate::route::INFINITY;
    ifa.preferred = crate::route::INFINITY;
    if ipv4::is_loopback(a) {
        ifa.scope = RT_SCOPE_HOST as u8;
    }
    insert(ifa)
}

fn sockaddr_at(b: &[u8], at: usize) -> (u16, Addr) {
    (u16::from_ne_bytes([b[at], b[at + 1]]), [b[at + 4], b[at + 5], b[at + 6], b[at + 7]])
}

/// `SIOCSARP`, `SIOCDARP` and `SIOCGARP`, as `arp_ioctl` in net/ipv4/arp.c of Linux. The stack
/// has no proxy ARP, thus `ATF_PUBL` gives `EOPNOTSUPP`.
fn arp_ioctl(cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<()> {
    if cmd != SIOCGARP && !net_admin() {
        return Err(Errno::EPERM);
    }
    let mut r = [0u8; ARPREQ_LEN];
    mem.read(arg, &mut r).map_err(|_| Errno::EFAULT)?;
    let (pa_family, ip) = sockaddr_at(&r, 0);
    let mut ha_family = u16::from_ne_bytes([r[16], r[17]]);
    let mut flags = u32::from_ne_bytes([r[32], r[33], r[34], r[35]]);
    if u32::from(pa_family) != AF_INET {
        return Err(Errno::EPFNOSUPPORT);
    }
    if flags & ATF_PUBL == 0 && flags & (ATF_NETMASK | ATF_DONTPUB) != 0 {
        return Err(Errno::EINVAL);
    }
    let name = &r[52..52 + IFNAMSIZ - 1];
    let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(name.len())];
    let mut d = None;
    if !name.is_empty() {
        let dv = dev::by_name(&String::from_utf8_lossy(name)).ok_or(Errno::ENODEV)?;
        let ty = dv.kind().arphrd();
        if ha_family == 0 {
            ha_family = ty;
        }
        if flags & ATF_COM != 0 && ha_family != ty {
            return Err(Errno::EINVAL);
        }
        d = Some(dv);
    } else if cmd == SIOCGARP {
        return Err(Errno::ENODEV);
    }
    if flags & ATF_PUBL != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    // Without a device, the route to the address gives it, as `arp_req_dev_by_ip`.
    let d = match d {
        Some(d) => d,
        None => {
            let next = crate::stack::route(ip)?;
            dev::by_index(next.ifindex).ok_or(Errno::EINVAL)?
        }
    };
    match cmd {
        SIOCDARP => {
            if crate::stack::neigh_del(d.ifindex(), ip) {
                Ok(())
            } else {
                Err(Errno::ENXIO)
            }
        }
        SIOCSARP => {
            // `arp_req_set`: a permanent entry has its address.
            if ha_family != d.kind().arphrd() {
                return Err(Errno::EINVAL);
            }
            let nud = if flags & ATF_PERM != 0 {
                flags |= ATF_COM;
                Nud::Permanent
            } else {
                Nud::Stale
            };
            let mac =
                (flags & ATF_COM != 0).then(|| MacAddr(r[18..24].try_into().unwrap_or([0; 6])));
            let create = NLM_F_CREATE | NLM_F_REPLACE;
            crate::stack::neigh_add(&d, ip, mac, nud, create)
        }
        _ => {
            // `arp_req_get`: an entry without `NUD_NOARP` gives its address and flags.
            let n = crate::stack::neighbours()
                .into_iter()
                .find(|n| n.ifindex == d.ifindex() && n.addr == ip && n.state != Nud::Noarp)
                .ok_or(Errno::ENXIO)?;
            let mac = n.mac.unwrap_or(MacAddr::ZERO);
            r[16..18].copy_from_slice(&d.kind().arphrd().to_ne_bytes());
            r[18..24].copy_from_slice(&mac.0);
            let flags = match n.state {
                Nud::Incomplete => 0,
                Nud::Permanent => ATF_PERM | ATF_COM,
                _ => ATF_COM,
            };
            r[32..36].copy_from_slice(&flags.to_ne_bytes());
            let dn = d.name();
            r[52..52 + IFNAMSIZ].fill(0);
            let len = dn.len().min(IFNAMSIZ - 1);
            r[52..52 + len].copy_from_slice(&dn.as_bytes()[..len]);
            mem.write(arg, &r).map_err(|_| Errno::EFAULT)
        }
    }
}

/// `SIOCADDRT` and `SIOCDELRT`, as `ip_rt_ioctl` and `rtentry_to_fib_config` of Linux.
fn rt_ioctl(cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<()> {
    let mut rt = [0u8; RTENTRY_LEN];
    mem.read(arg, &mut rt).map_err(|_| Errno::EFAULT)?;
    if !net_admin() {
        return Err(Errno::EPERM);
    }
    let (dst_family, dst) = sockaddr_at(&rt, 8);
    let (gw_family, gw) = sockaddr_at(&rt, 24);
    let (mask_family, mask) = sockaddr_at(&rt, 40);
    let flags = u32::from(u16::from_ne_bytes([rt[56], rt[57]]));
    let metric = i16::from_ne_bytes([rt[80], rt[81]]);
    let mut dev_ptr = [0u8; 8];
    dev_ptr.copy_from_slice(&rt[88..96]);
    let dev_ptr = u64::from_ne_bytes(dev_ptr) as usize;
    let ulong_at = |at: usize| u64::from_ne_bytes(rt[at..at + 8].try_into().unwrap_or([0; 8]));
    if u32::from(dst_family) != AF_INET {
        return Err(Errno::EAFNOSUPPORT);
    }
    let mut prefix = 32;
    if flags & RTF_HOST == 0 {
        if u32::from(mask_family) != AF_INET && (mask != ipv4::ANY || mask_family != 0) {
            return Err(Errno::EAFNOSUPPORT);
        }
        if bad_mask(mask, dst) {
            return Err(Errno::EINVAL);
        }
        prefix = mask_len(mask);
    }
    let add = cmd == SIOCADDRT;
    let mut r = Route::new(dst, prefix, None, 0);
    r.dst = dst;
    r.protocol = if add { RTPROT_BOOT as u8 } else { 0 };
    if metric != 0 {
        r.priority = (i32::from(metric) - 1) as u32;
    }
    if flags & RTF_REJECT != 0 {
        r.scope = RT_SCOPE_HOST as u8;
        r.kind = RTN_UNREACHABLE as u8;
    } else {
        r.scope = RT_SCOPE_NOWHERE as u8;
        r.kind = RTN_UNICAST as u8;
        if dev_ptr != 0 {
            let mut name = [0u8; IFNAMSIZ - 1];
            mem.read(dev_ptr, &mut name).map_err(|_| Errno::EFAULT)?;
            let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
            let name = String::from_utf8_lossy(&name[..end]).into_owned();
            let base = name.split(':').next().unwrap_or("");
            let d = dev::by_name(base).ok_or(Errno::ENODEV)?;
            r.ifindex = d.ifindex();
            if name.contains(':') {
                let t = ROUTES.lock();
                let a = t.addrs_of(r.ifindex).find(|a| a.label == name).ok_or(Errno::ENODEV)?;
                r.prefsrc = Some(a.local);
            }
        }
        if u32::from(gw_family) == AF_INET && gw != ipv4::ANY {
            r.gateway = Some(gw);
            if flags & RTF_GATEWAY != 0 && ROUTES.lock().addr_type(gw) == RTN_UNICAST {
                r.scope = RT_SCOPE_UNIVERSE as u8;
            }
        }
    }
    r.table = RT_TABLE_MAIN;
    // The metrics of `rt_mtu`, `rt_window` and `rt_irtt`, with the limit of `ip_metrics_convert`
    // on the MSS. Linux keeps the low 32 bits.
    let m = &mut r.metrics;
    if flags & RTF_MTU != 0 {
        m[usize::from(RTAX_ADVMSS - 1)] = (ulong_at(96) as u32).wrapping_sub(40).min(65535 - 40);
    }
    if flags & RTF_WINDOW != 0 {
        m[usize::from(RTAX_WINDOW - 1)] = ulong_at(104) as u32;
    }
    if flags & RTF_IRTT != 0 {
        m[usize::from(RTAX_RTT - 1)] = u32::from(u16::from_ne_bytes([rt[112], rt[113]])) << 3;
    }
    if !add {
        let m = Match {
            table: r.table,
            dst: r.dst,
            prefix: r.prefix,
            tos: 0,
            kind: Some(r.kind),
            scope: (r.scope != RT_SCOPE_NOWHERE as u8).then_some(r.scope),
            protocol: None,
            prefsrc: r.prefsrc,
            gateway: r.gateway,
            ifindex: (r.ifindex != 0).then_some(r.ifindex),
            priority: (r.priority != 0).then_some(r.priority),
        };
        return fib::del_route(&m, Origin::KERNEL);
    }
    if flags & RTF_REJECT == 0 {
        if flags & RTF_GATEWAY != 0 && r.gateway.is_none() {
            return Err(Errno::EINVAL);
        }
        if r.scope == RT_SCOPE_NOWHERE as u8 {
            r.scope = RT_SCOPE_LINK as u8;
        }
    }
    fib::check_route(&mut r)?;
    fib::add_route(r, NLM_F_CREATE, Origin::KERNEL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_and_masks() {
        assert_eq!(abc_len([10, 0, 0, 1]), Some(8));
        assert_eq!(abc_len([172, 16, 0, 1]), Some(16));
        assert_eq!(abc_len([192, 168, 1, 1]), Some(24));
        assert_eq!(abc_len([224, 0, 0, 1]), None);
        assert_eq!(abc_len([0, 0, 0, 0]), Some(0));
        assert!(!bad_mask([255, 255, 255, 0], [10, 0, 2, 0]));
        assert!(bad_mask([255, 255, 255, 0], [10, 0, 2, 1]));
        assert!(bad_mask([255, 0, 255, 0], ipv4::ANY));
        assert!(!bad_mask(ipv4::ANY, ipv4::ANY));
        assert_eq!(mask_len([255, 255, 240, 0]), 20);
    }
}

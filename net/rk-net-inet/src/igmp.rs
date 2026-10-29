//! The IPv4 multicast groups of the devices, as net/ipv4/igmp.c of Linux, and the files
//! /proc/net/igmp, /proc/net/igmp6 and /proc/net/dev_mcast that `ip maddr show` reads.
//!
//! A device that goes up joins the group of all of the hosts, 224.0.0.1, as `ip_mc_up` of
//! Linux, and a device that goes down leaves it, as `ip_mc_down`. A group has a count of its
//! users. The device takes the packets to its groups. Linux sends no report for 224.0.0.1, and
//! this stack sends no IGMP reports for the other groups.

use crate::ip::Ip;
use crate::ipv4::Addr;
use crate::stack6::ROUTES6;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use rk_frame::sync::SpinLock;
use rk_net::dev::{self, Event, NetDevice};
use rk_net::ether::MacAddr;
use rk_net::ns::PerNet;

/// The group of all of the hosts, `IGMP_ALL_HOSTS` of Linux.
pub(crate) const ALL_HOSTS: Addr = [224, 0, 0, 1];

/// A group of an interface and the count of its users, `struct ip_mc_list` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Group {
    /// The interface.
    pub ifindex: u32,
    /// The group.
    pub addr: Addr,
    /// The count of the users.
    pub users: u32,
}

/// The groups of the interfaces. A new group goes at the start, as the list of Linux.
static GROUPS: PerNet<SpinLock<Vec<Group>>> = PerNet::new(|| SpinLock::new(Vec::new()));

/// Joins the group `addr` on the interface `ifindex`, as `ip_mc_inc_group` of Linux.
pub(crate) fn join(ifindex: u32, addr: Addr) {
    let mut g = GROUPS.lock();
    match g.iter_mut().find(|x| x.ifindex == ifindex && x.addr == addr) {
        Some(x) => x.users += 1,
        None => g.insert(0, Group { ifindex, addr, users: 1 }),
    }
}

/// Leaves the group `addr` on the interface `ifindex`, as `ip_mc_dec_group` of Linux. The last
/// user removes the group.
pub(crate) fn leave(ifindex: u32, addr: Addr) {
    let mut g = GROUPS.lock();
    if let Some(at) = g.iter().position(|x| x.ifindex == ifindex && x.addr == addr) {
        g[at].users -= 1;
        if g[at].users == 0 {
            g.remove(at);
        }
    }
}

/// Tells if the interface `ifindex` is in the group `addr`, as `ip_check_mc_rcu` of Linux.
pub(crate) fn joined(ifindex: u32, addr: Addr) -> bool {
    GROUPS.lock().iter().any(|g| g.ifindex == ifindex && g.addr == addr)
}

/// The groups of all of the interfaces.
pub(crate) fn groups() -> Vec<Group> {
    GROUPS.lock().clone()
}

/// Changes the groups of a device that goes up, goes down or goes away, as `ip_mc_up`,
/// `ip_mc_down` and `ip_mc_destroy_dev` of Linux.
pub(crate) fn event(dev: &NetDevice, event: Event) {
    let ifindex = dev.ifindex();
    match event {
        Event::Up => join(ifindex, ALL_HOSTS),
        Event::Down => leave(ifindex, ALL_HOSTS),
        Event::Unregister => GROUPS.lock().retain(|g| g.ifindex != ifindex),
        _ => {}
    }
}

/// Clears the groups of a namespace that stops.
pub(crate) fn ns_exit() {
    GROUPS.reset();
}

/// The text of /proc/net/igmp, as `igmp_mc_seq_show` of Linux: a line for each device with
/// groups, and a line for each group. The group is a number of the byte order of the machine.
/// The device is in the mode of IGMPv3, and no timer runs.
pub(crate) fn show_igmp() -> String {
    let groups = groups();
    let mut out = String::from("Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n");
    for d in dev::devices() {
        let mine: Vec<&Group> = groups.iter().filter(|g| g.ifindex == d.ifindex()).collect();
        if mine.is_empty() {
            continue;
        }
        out.push_str(&format!("{}\t{:<10}: {:5} {:>7}\n", d.ifindex(), d.name(), mine.len(), "V3"));
        for g in mine {
            let addr = u32::from_ne_bytes(g.addr);
            out.push_str(&format!("\t\t\t\t{addr:08X} {:5} 0:00000000\t\t0\n", g.users));
        }
    }
    out
}

/// `MAF_LOADED` of Linux: the device joined the group on the link.
const MAF_LOADED: u32 = 4;
/// `MAF_NOREPORT` of Linux: the device sends no report for the group.
const MAF_NOREPORT: u32 = 8;

/// The IPv6 groups of the device `d`, newest first, with their users and flags: the groups of
/// the sockets and the solicited node groups of the addresses, then `ff02::1` and `ff01::1`,
/// as `ipv6_add_dev` and `addrconf_join_solict` of Linux.
fn groups6(d: &NetDevice) -> Vec<(Ip, u32, u32)> {
    let ifindex = d.ifindex();
    let mut out: Vec<(Ip, u32, u32)> = Vec::new();
    let mut add = |a: Ip, flags: u32| match out.iter_mut().find(|x| x.0 == a) {
        Some(x) => x.1 += 1,
        None => out.push((a, 1, flags)),
    };
    for (a, users) in crate::mcast6::groups(ifindex) {
        for _ in 0..users {
            add(a, MAF_LOADED);
        }
    }
    let addrs: Vec<Ip> = ROUTES6.lock().addrs_of(ifindex).map(|a| a.addr).collect();
    for a in addrs.iter().rev() {
        add(crate::ipv6::solicited_node(a), MAF_LOADED);
    }
    add(crate::ipv6::ALL_NODES, MAF_LOADED | MAF_NOREPORT);
    add(crate::ipv6::ALL_NODES_IF, MAF_NOREPORT);
    out
}

/// The text of /proc/net/igmp6, as `igmp6_mc_seq_show` of Linux: a line for each group of each
/// device that is up, with the address in 32 hex digits. No timer runs.
pub(crate) fn show_igmp6() -> String {
    let mut out = String::new();
    for d in dev::devices().into_iter().filter(|d| d.is_up()) {
        for (a, users, flags) in groups6(&d) {
            let hex: String = a.iter().map(|b| format!("{b:02x}")).collect();
            out.push_str(&format!(
                "{:<4} {:<15} {hex} {users:5} {flags:08X} 0\n",
                d.ifindex(),
                d.name()
            ));
        }
    }
    out
}

/// The text of /proc/net/dev_mcast, as `dev_mc_seq_show` of Linux: the link addresses of each
/// Ethernet device. They are the addresses of `SIOCADDMULTI` and, when the device is up, the
/// addresses of its groups from `ip_eth_mc_map` and `ipv6_eth_mc_map`. The two counts are the
/// users and the global use, which is 1 for an address of `SIOCADDMULTI`. `ip maddr` shows
/// such an address as `static`.
pub(crate) fn show_dev_mcast() -> String {
    let groups = groups();
    let mut out = String::new();
    for d in dev::devices().into_iter().filter(|d| d.kind() == dev::LinkKind::Ether) {
        let mut macs: Vec<(MacAddr, u32, u32)> = Vec::new();
        let mut add = |m: MacAddr, global: u32| match macs.iter_mut().find(|x| x.0 == m) {
            Some(x) => {
                x.1 += 1;
                x.2 |= global;
            }
            None => macs.push((m, 1, global)),
        };
        if d.is_up() {
            for g in groups.iter().filter(|g| g.ifindex == d.ifindex()) {
                let a = g.addr;
                add(MacAddr([0x01, 0x00, 0x5e, a[1] & 0x7f, a[2], a[3]]), 0);
            }
            for (a, _, _) in groups6(&d) {
                add(crate::ipv6::multicast_mac(&a), 0);
            }
        }
        for m in d.mc_list() {
            add(m, 1);
        }
        for (m, users, global) in macs {
            let hex: String = m.0.iter().map(|b| format!("{b:02x}")).collect();
            out.push_str(&format!(
                "{:<4} {:<15} {users:<5} {global:<5} {hex}\n",
                d.ifindex(),
                d.name()
            ));
        }
    }
    out
}

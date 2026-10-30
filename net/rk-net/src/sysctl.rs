//! The network sysctl values, which the proc file system shows under /proc/sys/net, as the
//! tables of net/core/sysctl_net_core.c, net/ipv4/sysctl_net_ipv4.c, net/ipv4/devinet.c,
//! net/ipv6/sysctl_net_ipv6.c, net/ipv6/addrconf.c and net/unix/sysctl_net_unix.c of Linux.
//!
//! Each network namespace has its own values, as `struct netns_ipv4` and `struct netns_ipv6`
//! of Linux. A read or a write uses the namespace of the caller. The values of `conf` are for
//! each device, with `all` and `default`. A new device copies the values of `default`, as
//! `ipv4_devconf_setup` and `ipv6_add_dev` of Linux. A new namespace copies the IPv4 values of
//! `all` and `default` from the first namespace, and the IPv6 values start at the defaults, as
//! `devinet_init_net` and `addrconf_init_net` of Linux with `devconf_inherit_init_net` 0.
//!
//! A protocol reads the values it uses, and `add_hook` tells it of a write.

use crate::dev::{self, Event, NetDevice};
use crate::ns::{self, PerNet};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::inode::Result;

/// An integer sysctl: its name, its default value and its range.
#[derive(Clone, Copy)]
struct Param {
    name: &'static str,
    default: i32,
    min: i32,
    max: i32,
}

const fn p(name: &'static str, default: i32, min: i32, max: i32) -> Param {
    Param { name, default, min, max }
}

const INT_MAX: i32 = i32::MAX;
const INT_MIN: i32 = i32::MIN;

/// The integer values of `net.core`, as `netns_core_table` of Linux.
const CORE: &[Param] = &[
    p("busy_poll", 0, 0, INT_MAX),
    p("busy_read", 0, 0, INT_MAX),
    p("netdev_max_backlog", 1000, INT_MIN, INT_MAX),
    p("optmem_max", 131_072, INT_MIN, INT_MAX),
    p("rmem_default", 212_992, 256, INT_MAX),
    p("rmem_max", 212_992, 256, INT_MAX),
    p("somaxconn", 4096, 0, INT_MAX),
    p("wmem_default", 212_992, 256, INT_MAX),
    p("wmem_max", 212_992, 256, INT_MAX),
];

/// The integer values of `net.ipv4`, as `ipv4_net_table` of Linux.
const IPV4: &[Param] = &[
    p("icmp_echo_ignore_all", 0, 0, 1),
    p("icmp_echo_ignore_broadcasts", 1, 0, 1),
    p("icmp_ignore_bogus_error_responses", 1, 0, 1),
    p("icmp_ratelimit", 1000, 0, INT_MAX),
    p("igmp_max_memberships", 20, INT_MIN, INT_MAX),
    p("igmp_max_msf", 10, INT_MIN, INT_MAX),
    p("ip_default_ttl", 64, 1, 255),
    p("ip_forward", 0, 0, 1),
    p("ip_no_pmtu_disc", 0, INT_MIN, INT_MAX),
    p("ip_nonlocal_bind", 0, 0, 1),
    p("ip_unprivileged_port_start", 1024, 0, 65535),
    p("tcp_ecn", 2, 0, 2),
    p("tcp_fastopen", 1, INT_MIN, INT_MAX),
    p("tcp_fin_timeout", 60, INT_MIN, INT_MAX),
    p("tcp_keepalive_intvl", 75, 1, INT_MAX),
    p("tcp_keepalive_probes", 9, INT_MIN, INT_MAX),
    p("tcp_keepalive_time", 7200, 1, INT_MAX),
    p("tcp_sack", 1, 0, 1),
    p("tcp_syn_retries", 6, 1, 127),
    p("tcp_synack_retries", 5, INT_MIN, INT_MAX),
    p("tcp_timestamps", 1, 0, 2),
    p("tcp_tw_reuse", 2, 0, 2),
    p("tcp_window_scaling", 1, 0, 1),
];

/// The integer values of `net.ipv6`, as `ipv6_table_template` of Linux.
const IPV6: &[Param] = &[
    p("bindv6only", 0, 0, 1),
    p("flowlabel_consistency", 1, 0, 1),
    p("fwmark_reflect", 0, 0, 1),
    p("ip_nonlocal_bind", 0, 0, 1),
    p("mld_max_msf", 64, INT_MIN, INT_MAX),
    p("mld_qrv", 2, 1, INT_MAX),
];

/// The integer values of `net.unix`, as `unix_table` of Linux.
const UNIX: &[Param] = &[p("max_dgram_qlen", 10, INT_MIN, INT_MAX)];

/// The values of `net.ipv4.conf.*`, as `DEVINET_SYSCTL_*` and `ipv4_devconf_dflt` of Linux.
const IPV4_CONF: &[Param] = &[
    p("accept_local", 0, 0, 1),
    p("accept_redirects", 1, 0, 1),
    p("accept_source_route", 1, 0, 1),
    p("arp_accept", 0, 0, 2),
    p("arp_announce", 0, 0, 2),
    p("arp_evict_nocarrier", 1, 0, 1),
    p("arp_filter", 0, 0, 1),
    p("arp_ignore", 0, 0, 8),
    p("arp_notify", 0, 0, 1),
    p("bc_forwarding", 0, 0, 1),
    p("bootp_relay", 0, 0, 1),
    p("disable_policy", 0, 0, 1),
    p("disable_xfrm", 0, 0, 1),
    p("drop_gratuitous_arp", 0, 0, 1),
    p("drop_unicast_in_l2_multicast", 0, 0, 1),
    p("force_igmp_version", 0, 0, 3),
    p("forwarding", 0, 0, 1),
    p("igmpv2_unsolicited_report_interval", 10_000, INT_MIN, INT_MAX),
    p("igmpv3_unsolicited_report_interval", 1000, INT_MIN, INT_MAX),
    p("ignore_routes_with_linkdown", 0, 0, 1),
    p("log_martians", 0, 0, 1),
    p("mc_forwarding", 0, 0, 1),
    p("medium_id", 0, INT_MIN, INT_MAX),
    p("promote_secondaries", 0, 0, 1),
    p("proxy_arp", 0, 0, 1),
    p("proxy_arp_pvlan", 0, 0, 1),
    p("route_localnet", 0, 0, 1),
    p("rp_filter", 0, 0, 2),
    p("secure_redirects", 1, 0, 1),
    p("send_redirects", 1, 0, 1),
    p("shared_media", 1, 0, 1),
    p("src_valid_mark", 0, 0, 1),
    p("tag", 0, INT_MIN, INT_MAX),
];

/// The values of `net.ipv6.conf.*`, as `ipv6_devconf_dflt` and `addrconf_sysctl` of Linux. The
/// value of `mtu` of a device is the MTU of the device.
const IPV6_CONF: &[Param] = &[
    p("accept_dad", 1, INT_MIN, INT_MAX),
    p("accept_ra", 1, INT_MIN, INT_MAX),
    p("accept_ra_defrtr", 1, INT_MIN, INT_MAX),
    p("accept_ra_from_local", 0, INT_MIN, INT_MAX),
    p("accept_ra_min_hop_limit", 1, INT_MIN, INT_MAX),
    p("accept_ra_mtu", 1, INT_MIN, INT_MAX),
    p("accept_ra_pinfo", 1, INT_MIN, INT_MAX),
    p("accept_ra_rt_info_max_plen", 0, INT_MIN, INT_MAX),
    p("accept_ra_rt_info_min_plen", 0, INT_MIN, INT_MAX),
    p("accept_ra_rtr_pref", 1, INT_MIN, INT_MAX),
    p("accept_redirects", 1, INT_MIN, INT_MAX),
    p("accept_source_route", 0, INT_MIN, INT_MAX),
    p("addr_gen_mode", 0, 0, 3),
    p("autoconf", 1, INT_MIN, INT_MAX),
    p("dad_transmits", 1, INT_MIN, INT_MAX),
    p("disable_ipv6", 0, INT_MIN, INT_MAX),
    p("disable_policy", 0, INT_MIN, INT_MAX),
    p("drop_unicast_in_l2_multicast", 0, INT_MIN, INT_MAX),
    p("drop_unsolicited_na", 0, INT_MIN, INT_MAX),
    p("enhanced_dad", 1, INT_MIN, INT_MAX),
    p("force_mld_version", 0, INT_MIN, INT_MAX),
    p("force_tllao", 0, INT_MIN, INT_MAX),
    p("forwarding", 0, INT_MIN, INT_MAX),
    p("hop_limit", 64, 1, 255),
    p("keep_addr_on_down", 0, INT_MIN, INT_MAX),
    p("max_addresses", 16, INT_MIN, INT_MAX),
    p("max_desync_factor", 600, INT_MIN, INT_MAX),
    p("mc_forwarding", 0, INT_MIN, INT_MAX),
    p("mldv1_unsolicited_report_interval", 10_000, INT_MIN, INT_MAX),
    p("mldv2_unsolicited_report_interval", 1000, INT_MIN, INT_MAX),
    p("mtu", 1280, 1280, INT_MAX),
    p("ndisc_notify", 0, INT_MIN, INT_MAX),
    p("ndisc_tclass", 0, 0, 255),
    p("optimistic_dad", 0, INT_MIN, INT_MAX),
    p("proxy_ndp", 0, INT_MIN, INT_MAX),
    p("regen_max_retry", 3, INT_MIN, INT_MAX),
    p("router_probe_interval", 60, INT_MIN, INT_MAX),
    p("router_solicitation_delay", 1, INT_MIN, INT_MAX),
    p("router_solicitation_interval", 4, INT_MIN, INT_MAX),
    p("router_solicitation_max_interval", 3600, INT_MIN, INT_MAX),
    p("router_solicitations", -1, -1, INT_MAX),
    p("seg6_enabled", 0, INT_MIN, INT_MAX),
    p("suppress_frag_ndisc", 1, INT_MIN, INT_MAX),
    p("temp_prefered_lft", 86_400, INT_MIN, INT_MAX),
    p("temp_valid_lft", 604_800, INT_MIN, INT_MAX),
    p("use_optimistic", 0, INT_MIN, INT_MAX),
    p("use_tempaddr", 0, INT_MIN, INT_MAX),
];

/// The values of `all` that are not the values of `default`: `ipv4_devconf` of Linux has no
/// `accept_source_route`, and `ipv6_devconf` has `accept_dad` 0.
const IPV4_ALL: &[(&str, i32)] = &[("accept_source_route", 0)];
const IPV6_ALL: &[(&str, i32)] = &[("accept_dad", 0)];

/// The values of `net.ipv4` that are text, with their default text.
const IPV4_TEXT: &[(&str, &str)] = &[
    ("ip_local_port_range", "32768\t60999"),
    ("tcp_available_congestion_control", "reno cubic"),
    ("tcp_congestion_control", "cubic"),
];

/// The family of the values of a `conf` directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// `net.ipv4.conf`.
    Ipv4,
    /// `net.ipv6.conf`.
    Ipv6,
}

impl Family {
    fn params(self) -> &'static [Param] {
        match self {
            Self::Ipv4 => IPV4_CONF,
            Self::Ipv6 => IPV6_CONF,
        }
    }
}

/// The directory of `conf` that a value is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// `conf/all`.
    All,
    /// `conf/default`, the values of a new device.
    Default,
    /// The directory of the device with the interface index.
    Dev(u32),
}

/// The values of one `conf` directory, for IPv4 and IPv6.
#[derive(Clone)]
struct Conf {
    v4: Vec<i32>,
    v6: Vec<i32>,
}

impl Conf {
    fn new(all: bool) -> Self {
        let make = |params: &[Param], over: &[(&str, i32)]| -> Vec<i32> {
            params
                .iter()
                .map(|p| {
                    let o = over.iter().find(|o| all && o.0 == p.name);
                    o.map_or(p.default, |o| o.1)
                })
                .collect()
        };
        Self { v4: make(IPV4_CONF, IPV4_ALL), v6: make(IPV6_CONF, IPV6_ALL) }
    }

    fn values(&mut self, f: Family) -> &mut Vec<i32> {
        match f {
            Family::Ipv4 => &mut self.v4,
            Family::Ipv6 => &mut self.v6,
        }
    }
}

/// The sysctl values of a namespace.
pub struct Tables {
    core: Vec<i32>,
    ipv4: Vec<i32>,
    ipv6: Vec<i32>,
    unix: Vec<i32>,
    texts: Vec<String>,
    /// `net.ipv4.ping_group_range`.
    ping: (u32, u32),
    /// `net.ipv4.ip_local_reserved_ports`: sorted ranges that do not touch.
    reserved: Vec<(u16, u16)>,
    all: Conf,
    default: Conf,
    devs: BTreeMap<u32, Conf>,
}

impl Tables {
    fn new() -> Self {
        let defaults = |params: &[Param]| params.iter().map(|p| p.default).collect();
        Self {
            core: defaults(CORE),
            ipv4: defaults(IPV4),
            ipv6: defaults(IPV6),
            unix: defaults(UNIX),
            texts: IPV4_TEXT.iter().map(|t| String::from(t.1)).collect(),
            // The empty range `1 0`, as Linux.
            ping: (1, 0),
            reserved: Vec::new(),
            all: Conf::new(true),
            default: Conf::new(false),
            devs: BTreeMap::new(),
        }
    }

    /// The values of `scope`. A device without values gets the values of `default`.
    fn conf(&mut self, scope: Scope) -> &mut Conf {
        match scope {
            Scope::All => &mut self.all,
            Scope::Default => &mut self.default,
            Scope::Dev(i) => {
                let d = self.default.clone();
                self.devs.entry(i).or_insert(d)
            }
        }
    }
}

static TABLES: PerNet<SpinLock<Tables>> = PerNet::new(|| SpinLock::new(Tables::new()));

/// A function that a write of a `conf` value calls, in the namespace of the write. It gets the
/// family, the scope, the name and the new value.
pub type Hook = fn(Family, Scope, &'static str, i32);

static HOOKS: SpinLock<Vec<Hook>> = SpinLock::new(Vec::new());

/// Adds a function that gets each write of a `conf` value, as the `proc_handler` of the values
/// of Linux that change the state of a device.
pub fn add_hook(f: Hook) {
    HOOKS.lock().push(f);
}

/// Copies the IPv4 values of `all` and `default` of the first namespace to a new namespace, as
/// `devinet_init_net` of Linux.
fn ns_init() {
    let (all, default) = {
        let first = TABLES.first().lock();
        (first.all.v4.clone(), first.default.v4.clone())
    };
    let mut t = TABLES.lock();
    t.all.v4 = all;
    t.default.v4 = default;
}

fn ns_exit() {
    TABLES.reset();
}

/// Makes and removes the values of a device, as `inetdev_init` and `ipv6_add_dev` of Linux.
fn event(d: &NetDevice, e: Event) {
    let index = d.ifindex();
    let mut t = TABLES.lock();
    match e {
        Event::Register => {
            let mut c = t.default.clone();
            if let Some(at) = IPV6_CONF.iter().position(|p| p.name == "mtu") {
                c.v6[at] = d.mtu().max(1280) as i32;
            }
            t.devs.insert(index, c);
        }
        Event::Unregister => {
            t.devs.remove(&index);
        }
        _ => {}
    }
}

/// Sets the functions of the namespaces and of the devices. `dev::init` calls this one time.
pub(crate) fn init() {
    ns::add_ops(ns_init, ns_exit);
    dev::add_notifier(event);
}

/// The value `name` of `conf` in the current namespace. Gives 0 for a name that is not there.
pub fn conf(f: Family, scope: Scope, name: &str) -> i32 {
    let Some(at) = f.params().iter().position(|p| p.name == name) else { return 0 };
    TABLES.lock().conf(scope).values(f)[at]
}

/// Sets a `conf` value of the current namespace, as a write of its file, for the kernel
/// itself: `SIOCSARP` with `ATF_PUBL` sets `proxy_arp`, as `arp_req_set_proxy` of Linux.
///
/// # Errors
///
/// Gives `EINVAL` if no value has the name `name`.
pub fn set_conf(f: Family, scope: Scope, name: &str, v: i32) -> Result<()> {
    let at = f.params().iter().position(|p| p.name == name).ok_or(Errno::EINVAL)?;
    conf_write(f, scope, f.params()[at].name, at, v);
    Ok(())
}

/// Tells if IPv6 is off on the device `ifindex`, `net.ipv6.conf.DEV.disable_ipv6`.
pub fn ipv6_disabled(ifindex: u32) -> bool {
    conf(Family::Ipv6, Scope::Dev(ifindex), "disable_ipv6") != 0
}

/// The value `name` of `net.ipv4` in the current namespace. Gives 0 for a name that is not
/// there.
pub fn ipv4(name: &str) -> i32 {
    IPV4.iter().position(|p| p.name == name).map_or(0, |at| TABLES.lock().ipv4[at])
}

/// The value `name` of `net.core` in the current namespace. Gives 0 for a name that is not
/// there.
pub fn core(name: &str) -> i32 {
    CORE.iter().position(|p| p.name == name).map_or(0, |at| TABLES.lock().core[at])
}

/// Tells if `port` is in `net.ipv4.ip_local_reserved_ports` of the current namespace. The
/// search for a free ephemeral port skips these ports, as `inet_is_local_reserved_port` of
/// Linux.
pub fn local_reserved_port(port: u16) -> bool {
    TABLES.lock().reserved.iter().any(|&(lo, hi)| (lo..=hi).contains(&port))
}

/// The text of a list of port ranges, as `proc_do_large_bitmap` of Linux gives it: `a-b` or
/// `a`, with a comma between them.
fn ranges_text(list: &[(u16, u16)]) -> String {
    let parts: Vec<String> = list
        .iter()
        .map(|&(lo, hi)| if lo == hi { format!("{lo}") } else { format!("{lo}-{hi}") })
        .collect();
    parts.join(",")
}

/// Parses a list of port ranges, as the write of `proc_do_large_bitmap` of Linux: `a` or `a-b`
/// with a comma between them, and each port below 65536. Gives the ranges sorted and merged.
fn parse_ranges(data: &[u8]) -> Result<Vec<(u16, u16)>> {
    let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
    let text = text.strip_suffix('\n').unwrap_or(text).trim_start();
    let mut list = Vec::new();
    if text.is_empty() {
        return Ok(list);
    }
    let port = |w: &str| w.parse::<u16>().map_err(|_| Errno::EINVAL);
    for item in text.split(',') {
        let (lo, hi) = match item.split_once('-') {
            Some((a, b)) => (port(a)?, port(b)?),
            None => (port(item)?, port(item)?),
        };
        if lo > hi {
            return Err(Errno::EINVAL);
        }
        list.push((lo, hi));
    }
    list.sort_unstable();
    let mut out: Vec<(u16, u16)> = Vec::new();
    for (lo, hi) in list {
        match out.last_mut() {
            Some(last) if u32::from(lo) <= u32::from(last.1) + 1 => last.1 = last.1.max(hi),
            _ => out.push((lo, hi)),
        }
    }
    Ok(out)
}

/// The default TTL of IPv4, `net.ipv4.ip_default_ttl`.
pub fn default_ttl() -> u8 {
    ipv4("ip_default_ttl").clamp(1, 255) as u8
}

/// The range of the groups that can make an ICMP echo socket, `net.ipv4.ping_group_range`.
pub fn ping_group_range() -> (u32, u32) {
    TABLES.lock().ping
}

/// Sets `net.ipv4.ping_group_range`. A range with `high` below `low` becomes the empty range
/// `1 0`, as `ipv4_ping_group_range` of Linux. A value larger than `i32::MAX` gives `None`.
pub fn set_ping_group_range(low: u32, high: u32) -> Option<()> {
    if low > i32::MAX as u32 || high > i32::MAX as u32 {
        return None;
    }
    TABLES.lock().ping = if high < low { (1, 0) } else { (low, high) };
    Some(())
}

/// Tells if a process with one of the groups `groups` can make an ICMP echo socket.
pub fn ping_group_allowed(groups: impl IntoIterator<Item = u32>) -> bool {
    let (low, high) = ping_group_range();
    groups.into_iter().any(|g| (low..=high).contains(&g))
}

/// An entry of a directory of /proc/sys/net: a directory, or a file that takes a write or not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    /// A directory.
    Dir,
    /// A file. The value tells if it takes a write.
    File(bool),
}

fn names(params: &[Param]) -> impl Iterator<Item = (String, Entry)> + '_ {
    params.iter().map(|p| (String::from(p.name), Entry::File(true)))
}

/// The scope of the directory `name` of `conf`, in the current namespace.
fn scope(name: &str) -> Option<Scope> {
    match name {
        "all" => Some(Scope::All),
        "default" => Some(Scope::Default),
        _ => dev::by_name(name).map(|d| Scope::Dev(d.ifindex())),
    }
}

fn family(name: &str) -> Option<Family> {
    match name {
        "ipv4" => Some(Family::Ipv4),
        "ipv6" => Some(Family::Ipv6),
        _ => None,
    }
}

/// The entries of the directory `path` of /proc/sys/net, in the current namespace. `path` has
/// no `/` at the start or the end, and the empty path is /proc/sys/net. Gives `None` if no
/// directory has the path.
pub fn list(path: &str) -> Option<Vec<(String, Entry)>> {
    let parts: Vec<&str> = if path.is_empty() { Vec::new() } else { path.split('/').collect() };
    let dir = |n: &str| (String::from(n), Entry::Dir);
    let mut out: Vec<(String, Entry)> = match parts[..] {
        [] => ["core", "ipv4", "ipv6", "unix"].into_iter().map(dir).collect(),
        ["core"] => names(CORE).collect(),
        ["unix"] => names(UNIX).collect(),
        ["ipv4"] => {
            let texts = IPV4_TEXT.iter().map(|t| {
                (String::from(t.0), Entry::File(t.0 != "tcp_available_congestion_control"))
            });
            names(IPV4)
                .chain(texts)
                .chain([
                    dir("conf"),
                    (String::from("ping_group_range"), Entry::File(true)),
                    (String::from("ip_local_reserved_ports"), Entry::File(true)),
                ])
                .collect()
        }
        ["ipv6"] => names(IPV6).chain([dir("conf")]).collect(),
        [f, "conf"] => {
            family(f)?;
            let devs = dev::devices().into_iter().map(|d| (d.name(), Entry::Dir));
            [dir("all"), dir("default")].into_iter().chain(devs).collect()
        }
        [f, "conf", s] => {
            let f = family(f)?;
            scope(s)?;
            f.params()
                .iter()
                .map(|p| (String::from(p.name), Entry::File(p.name != "mc_forwarding")))
                .collect()
        }
        _ => return None,
    };
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Some(out)
}

/// The values of a directory other than `conf`, with their parameters.
fn global<'a>(t: &'a mut Tables, dir: &str) -> Option<(&'static [Param], &'a mut Vec<i32>)> {
    Some(match dir {
        "core" => (CORE, &mut t.core),
        "ipv4" => (IPV4, &mut t.ipv4),
        "ipv6" => (IPV6, &mut t.ipv6),
        "unix" => (UNIX, &mut t.unix),
        _ => return None,
    })
}

/// Reads the file `path` of /proc/sys/net in the current namespace. Gives `ENOENT` if no file
/// has the path.
pub fn read(path: &str) -> Result<Vec<u8>> {
    let parts: Vec<&str> = path.split('/').collect();
    // The lookup of a device takes the lock of the devices, so it comes first.
    let dev_scope = match parts[..] {
        [_, "conf", s, _] => Some(scope(s).ok_or(Errno::ENOENT)?),
        _ => None,
    };
    let mut t = TABLES.lock();
    let text = match parts[..] {
        ["ipv4", "ping_group_range"] => format!("{}\t{}", t.ping.0, t.ping.1),
        ["ipv4", "ip_local_reserved_ports"] => ranges_text(&t.reserved),
        ["ipv4", name] if IPV4_TEXT.iter().any(|x| x.0 == name) => {
            let at = IPV4_TEXT.iter().position(|x| x.0 == name).unwrap_or(0);
            t.texts[at].clone()
        }
        [f, "conf", _, name] => {
            let f = family(f).ok_or(Errno::ENOENT)?;
            let at = f.params().iter().position(|p| p.name == name).ok_or(Errno::ENOENT)?;
            let scope = dev_scope.ok_or(Errno::ENOENT)?;
            format!("{}", t.conf(scope).values(f)[at])
        }
        [d, name] => {
            let (params, values) = global(&mut t, d).ok_or(Errno::ENOENT)?;
            let at = params.iter().position(|p| p.name == name).ok_or(Errno::ENOENT)?;
            format!("{}", values[at])
        }
        _ => return Err(Errno::ENOENT),
    };
    Ok(format!("{text}\n").into_bytes())
}

/// Parses one integer, as `proc_dointvec` of Linux.
fn parse(data: &[u8]) -> Result<i32> {
    let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
    text.trim().parse().map_err(|_| Errno::EINVAL)
}

/// Writes the file `path` of /proc/sys/net in the current namespace. Gives `ENOENT` if no file
/// has the path, and `EINVAL` for a value out of the range, as `proc_dointvec_minmax` of Linux.
pub fn write(path: &str, data: &[u8]) -> Result<()> {
    let parts: Vec<&str> = path.split('/').collect();
    match parts[..] {
        ["ipv4", "ping_group_range"] => {
            let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
            let mut words = text.split_ascii_whitespace().map(str::parse::<u32>);
            let (Some(Ok(low)), Some(Ok(high)), None) = (words.next(), words.next(), words.next())
            else {
                return Err(Errno::EINVAL);
            };
            set_ping_group_range(low, high).ok_or(Errno::EINVAL)
        }
        ["ipv4", "ip_local_reserved_ports"] => {
            let list = parse_ranges(data)?;
            TABLES.lock().reserved = list;
            Ok(())
        }
        ["ipv4", "tcp_available_congestion_control"] => Err(Errno::EPERM),
        ["ipv4", name] if IPV4_TEXT.iter().any(|x| x.0 == name) => {
            let at = IPV4_TEXT.iter().position(|x| x.0 == name).unwrap_or(0);
            let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
            let text = text.trim();
            // The kernel has the algorithms of `tcp_available_congestion_control`.
            if name == "tcp_congestion_control" && !matches!(text, "reno" | "cubic") {
                return Err(Errno::ENOENT);
            }
            TABLES.lock().texts[at] = String::from(text);
            Ok(())
        }
        // `ip_forward` sets `forwarding` of `all`, `default` and each device, as
        // `devinet_sysctl_forward` and `inet_forward_change` of Linux.
        ["ipv4", "ip_forward"] => {
            let v = parse(data)?;
            if !(0..=1).contains(&v) {
                return Err(Errno::EINVAL);
            }
            forward_change(Family::Ipv4, v);
            Ok(())
        }
        [f, "conf", s, name] => {
            let f = family(f).ok_or(Errno::ENOENT)?;
            let at = f.params().iter().position(|p| p.name == name).ok_or(Errno::ENOENT)?;
            let scope = scope(s).ok_or(Errno::ENOENT)?;
            let param = &f.params()[at];
            if param.name == "mc_forwarding" {
                return Err(Errno::EPERM);
            }
            let v = parse(data)?;
            if v < param.min || v > param.max {
                return Err(Errno::EINVAL);
            }
            conf_write(f, scope, param.name, at, v);
            Ok(())
        }
        [d, name] => {
            let v = parse(data)?;
            let mut t = TABLES.lock();
            let (params, values) = global(&mut t, d).ok_or(Errno::ENOENT)?;
            let at = params.iter().position(|p| p.name == name).ok_or(Errno::ENOENT)?;
            if v < params[at].min || v > params[at].max {
                return Err(Errno::EINVAL);
            }
            values[at] = v;
            Ok(())
        }
        _ => Err(Errno::ENOENT),
    }
}

/// Sets `forwarding` of `all`, `default` and each device of the current namespace, as
/// `inet_forward_change` and `addrconf_forward_change` of Linux.
fn forward_change(f: Family, v: i32) {
    let at = f.params().iter().position(|p| p.name == "forwarding").unwrap_or(0);
    let devs: Vec<u32> = dev::devices().iter().map(|d| d.ifindex()).collect();
    {
        let mut t = TABLES.lock();
        if f == Family::Ipv4 {
            let fw = IPV4.iter().position(|p| p.name == "ip_forward").unwrap_or(0);
            t.ipv4[fw] = v;
        }
        for s in [Scope::All, Scope::Default].into_iter().chain(devs.iter().map(|&i| Scope::Dev(i)))
        {
            t.conf(s).values(f)[at] = v;
        }
    }
    let hooks = HOOKS.lock().clone();
    for &i in &devs {
        for h in &hooks {
            h(f, Scope::Dev(i), "forwarding", v);
        }
    }
}

/// Writes the value at `at` of `conf`. A write of `all` sets `forwarding` and `disable_ipv6` of
/// each device too, as `addrconf_disable_ipv6` and `addrconf_fixup_forwarding` of Linux. The
/// hooks run for each device that changes.
fn conf_write(f: Family, scope: Scope, name: &'static str, at: usize, v: i32) {
    if scope == Scope::All && name == "forwarding" {
        return forward_change(f, v);
    }
    let all_devs = scope == Scope::All && f == Family::Ipv6 && name == "disable_ipv6";
    let mut changed = Vec::new();
    let devs = if all_devs { dev::devices() } else { Vec::new() };
    {
        let mut t = TABLES.lock();
        t.conf(scope).values(f)[at] = v;
        if all_devs {
            t.conf(Scope::Default).values(f)[at] = v;
            for d in devs {
                let i = d.ifindex();
                let old = core::mem::replace(&mut t.conf(Scope::Dev(i)).values(f)[at], v);
                if old != v {
                    changed.push(Scope::Dev(i));
                }
            }
        } else {
            changed.push(scope);
        }
    }
    let hooks = HOOKS.lock().clone();
    for s in changed {
        for h in &hooks {
            h(f, s, name, v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_files_have_the_values_of_linux() {
        dev::init();
        assert_eq!(read("ipv6/conf/all/disable_ipv6").unwrap(), b"0\n");
        assert_eq!(read("ipv6/conf/all/accept_dad").unwrap(), b"0\n");
        assert_eq!(read("ipv6/conf/default/accept_dad").unwrap(), b"1\n");
        assert_eq!(read("ipv6/conf/lo/mtu").unwrap(), b"65536\n");
        assert_eq!(read("ipv4/ip_default_ttl").unwrap(), b"64\n");
        assert_eq!(read("ipv4/conf/all/tag").unwrap(), b"0\n");
        assert!(read("ipv6/conf/nothing/accept_ra").is_err());
        let conf = list("ipv4/conf").unwrap();
        assert!(conf.iter().any(|(n, _)| n == "lo"));
        assert_eq!(write("ipv4/ip_default_ttl", b"0\n"), Err(Errno::EINVAL));
        write("ipv4/ip_default_ttl", b"65\n").unwrap();
        assert_eq!(default_ttl(), 65);
        write("ipv4/ip_default_ttl", b"64").unwrap();
    }

    #[test]
    fn reserved_ports_take_a_list_of_ranges() {
        // Linux gives an empty line when no port is reserved. libtirpc reads the file and does
        // not bind a server without it.
        assert_eq!(read("ipv4/ip_local_reserved_ports").unwrap(), b"\n");
        write("ipv4/ip_local_reserved_ports", b"50001,40000-40002,40003\n").unwrap();
        assert_eq!(read("ipv4/ip_local_reserved_ports").unwrap(), b"40000-40003,50001\n");
        assert!(local_reserved_port(40002));
        assert!(!local_reserved_port(40004));
        assert_eq!(write("ipv4/ip_local_reserved_ports", b"70000"), Err(Errno::EINVAL));
        assert_eq!(write("ipv4/ip_local_reserved_ports", b"9-8"), Err(Errno::EINVAL));
        write("ipv4/ip_local_reserved_ports", b"\n").unwrap();
        assert!(!local_reserved_port(40002));
        assert!(list("ipv4").unwrap().iter().any(|(n, _)| n == "ip_local_reserved_ports"));
    }

    #[test]
    fn all_sets_each_device() {
        dev::init();
        write("ipv6/conf/all/disable_ipv6", b"1").unwrap();
        assert!(ipv6_disabled(1));
        assert_eq!(read("ipv6/conf/default/disable_ipv6").unwrap(), b"1\n");
        write("ipv6/conf/all/disable_ipv6", b"0").unwrap();
        assert!(!ipv6_disabled(1));
        write("ipv4/ip_forward", b"1").unwrap();
        assert_eq!(read("ipv4/conf/lo/forwarding").unwrap(), b"1\n");
        write("ipv4/conf/all/forwarding", b"0").unwrap();
        assert_eq!(read("ipv4/ip_forward").unwrap(), b"0\n");
    }
}

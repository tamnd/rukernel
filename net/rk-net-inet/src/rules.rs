//! The routing rules of IPv4 and IPv6, as net/core/fib_rules.c, net/ipv4/fib_rules.c and
//! net/ipv6/fib6_rules.c of Linux.
//!
//! A rule selects the packets by their addresses, marks, interfaces and other fields, and
//! tells which table to look in, or makes the lookup fail. A route lookup walks the rules in
//! the order of their priority, and the first rule that gives a route wins. Each family of
//! each namespace has its own list. The list starts with the default rules of Linux: `local`,
//! `main` and `default` for IPv4, and `local` and `main` for IPv6.
//!
//! `ip rule` changes and shows the rules with `RTM_NEWRULE`, `RTM_DELRULE` and `RTM_GETRULE`.

use crate::stack::ROUTES;
use crate::stack6::ROUTES6;
use alloc::string::String;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::netlink::{NLM_F_EXCL, NLM_F_MULTI};
use rk_abi::native::rtnetlink::{
    RT_TABLE_COMPAT, RT_TABLE_DEFAULT, RT_TABLE_LOCAL, RT_TABLE_MAIN, RTM_DELRULE, RTM_GETRULE,
    RTM_NEWRULE, RTNLGRP_IPV4_RULE, RTNLGRP_IPV6_RULE, RTPROT_KERNEL,
};
use rk_net::consts::{AF_INET, AF_INET6, AF_UNSPEC, IFNAMSIZ};
use rk_net::dev::{self, Event, NetDevice};
use rk_net::netlink::msg::{Attrs, Builder, attrs};
use rk_net::netlink::{self, Origin, Request};
use rk_vfs::inode::Result;

// The attributes of a rule, `FRA_*` of <linux/fib_rules.h>. rk-abigen does not take this
// header yet, so the values are written by hand.
/// The destination prefix.
const FRA_DST: u32 = 1;
/// The source prefix.
const FRA_SRC: u32 = 2;
/// The name of the input interface.
const FRA_IIFNAME: u32 = 3;
/// The priority of the target of a `goto` rule.
const FRA_GOTO: u32 = 4;
/// The priority of the rule.
const FRA_PRIORITY: u32 = 6;
/// The firewall mark.
const FRA_FWMARK: u32 = 10;
/// The realm of IPv4.
const FRA_FLOW: u32 = 11;
/// The tunnel ID.
const FRA_TUN_ID: u32 = 12;
/// The interface group that a route must not use.
const FRA_SUPPRESS_IFGROUP: u32 = 13;
/// The longest prefix that a route must not have.
const FRA_SUPPRESS_PREFIXLEN: u32 = 14;
/// The table, for an ID above 255.
const FRA_TABLE: u32 = 15;
/// The mask of the firewall mark.
const FRA_FWMASK: u32 = 16;
/// The name of the output interface.
const FRA_OIFNAME: u32 = 17;
/// The table of the L3 master device.
const FRA_L3MDEV: u32 = 19;
/// The range of user IDs.
const FRA_UID_RANGE: u32 = 20;
/// The protocol that added the rule.
const FRA_PROTOCOL: u32 = 21;
/// The IP protocol.
const FRA_IP_PROTO: u32 = 22;
/// The range of source ports.
const FRA_SPORT_RANGE: u32 = 23;
/// The range of destination ports.
const FRA_DPORT_RANGE: u32 = 24;
/// The full DSCP value.
const FRA_DSCP: u32 = 25;
/// The IPv6 flow label.
const FRA_FLOWLABEL: u32 = 26;
/// The mask of the IPv6 flow label.
const FRA_FLOWLABEL_MASK: u32 = 27;
/// The mask of the source port.
const FRA_SPORT_MASK: u32 = 28;
/// The mask of the destination port.
const FRA_DPORT_MASK: u32 = 29;
/// The mask of the DSCP value.
const FRA_DSCP_MASK: u32 = 30;
/// The last attribute, `FRA_MAX`.
const FRA_MAX: u16 = 30;

/// The action of a rule: look in a table, `FR_ACT_TO_TBL`.
pub const FR_ACT_TO_TBL: u8 = 1;
/// Go to the rule with a priority, `FR_ACT_GOTO`.
pub const FR_ACT_GOTO: u8 = 2;
/// Do nothing, `FR_ACT_NOP`.
pub const FR_ACT_NOP: u8 = 3;
/// Drop the packet without a message, `FR_ACT_BLACKHOLE`.
pub const FR_ACT_BLACKHOLE: u8 = 6;
/// The destination is not reachable, `FR_ACT_UNREACHABLE`.
pub const FR_ACT_UNREACHABLE: u8 = 7;
/// The administrator prohibits the packet, `FR_ACT_PROHIBIT`.
pub const FR_ACT_PROHIBIT: u8 = 8;

/// The flag of a rule that `RTM_DELRULE` cannot remove, `FIB_RULE_PERMANENT`.
const FIB_RULE_PERMANENT: u32 = 1;
/// The flag of a rule that matches the packets that the selector does not match.
const FIB_RULE_INVERT: u32 = 2;
/// The flag of a `goto` rule without its target, in a dump.
const FIB_RULE_UNRESOLVED: u32 = 4;
/// The flag of a rule with an input interface that is not there, in a dump.
const FIB_RULE_IIF_DETACHED: u32 = 8;
/// The flag of a rule with an output interface that is not there, in a dump.
const FIB_RULE_OIF_DETACHED: u32 = 0x10;
/// The flag of an IPv6 rule that matches a lookup without a source address.
const FIB_RULE_FIND_SADDR: u32 = 0x10000;

/// The size of `struct fib_rule_hdr`.
const FRH_LEN: usize = 12;
/// The user ID that is not valid, the end of a range that is not set.
const NO_UID: u32 = u32::MAX;
/// The mask of the IPv6 flow label, `IPV6_FLOWLABEL_MASK`, in the byte order of the network.
const FLOWLABEL_MASK: u32 = u32::from_be(0x000f_ffff);

/// A routing rule, as `struct fib_rule`, `struct fib4_rule` and `struct fib6_rule` of Linux.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// The priority. A lower value comes first.
    pub pref: u32,
    /// The table of the action `FR_ACT_TO_TBL`.
    pub table: u32,
    /// The action, `FR_ACT_*`.
    pub action: u8,
    /// The flags, `FIB_RULE_PERMANENT`, `FIB_RULE_INVERT` and `FIB_RULE_FIND_SADDR`.
    pub flags: u32,
    /// The protocol that added the rule, `RTPROT_*`.
    pub proto: u8,
    /// The name of the input interface, or an empty name.
    pub iifname: String,
    /// The index of the input interface: 0 for no interface, -1 if it is not there.
    pub iifindex: i32,
    /// The name of the output interface, or an empty name.
    pub oifname: String,
    /// The index of the output interface, as `iifindex`.
    pub oifindex: i32,
    /// The firewall mark and its mask.
    pub mark: u32,
    /// The mask of the firewall mark.
    pub mark_mask: u32,
    /// The priority of the target of a `goto` rule.
    pub target: u32,
    /// The tunnel ID, in the byte order of the network.
    pub tun_id: u64,
    /// The table of the L3 master device, 0 or 1.
    pub l3mdev: u8,
    /// The first and the last user ID. `NO_UID` in the range tells that it is not set.
    pub uid: (u32, u32),
    /// The longest prefix of a route that the rule does not take, or -1.
    pub suppress_prefixlen: i32,
    /// The interface group that a route must not use, or -1.
    pub suppress_ifgroup: i32,
    /// The IP protocol, or 0.
    pub ip_proto: u8,
    /// The range of source ports, or `(0, 0)`.
    pub sport: (u16, u16),
    /// The mask of the source port.
    pub sport_mask: u16,
    /// The range of destination ports, or `(0, 0)`.
    pub dport: (u16, u16),
    /// The mask of the destination port.
    pub dport_mask: u16,
    /// The source prefix: the address (the first 4 bytes for IPv4) and its length.
    pub src: [u8; 16],
    /// The length of the source prefix.
    pub src_len: u8,
    /// The destination prefix.
    pub dst: [u8; 16],
    /// The length of the destination prefix.
    pub dst_len: u8,
    /// The DSCP value, the 6 upper bits of the field of the type of service.
    pub dscp: u8,
    /// The mask of the DSCP value.
    pub dscp_mask: u8,
    /// The rule has the full DSCP value of `FRA_DSCP`, and not the type of service.
    pub dscp_full: bool,
    /// The realm of IPv4, `FRA_FLOW`.
    pub flow: u32,
    /// The IPv6 flow label and its mask, in the byte order of the network.
    pub flowlabel: u32,
    /// The mask of the IPv6 flow label.
    pub flowlabel_mask: u32,
}

impl Rule {
    /// An empty rule, as the rule of `fib_nl2rule` before it reads the attributes.
    const fn empty() -> Self {
        Self {
            pref: 0,
            table: 0,
            action: 0,
            flags: 0,
            proto: 0,
            iifname: String::new(),
            iifindex: 0,
            oifname: String::new(),
            oifindex: 0,
            mark: 0,
            mark_mask: 0,
            target: 0,
            tun_id: 0,
            l3mdev: 0,
            uid: (0, NO_UID),
            suppress_prefixlen: -1,
            suppress_ifgroup: -1,
            ip_proto: 0,
            sport: (0, 0),
            sport_mask: 0,
            dport: (0, 0),
            dport_mask: 0,
            src: [0; 16],
            src_len: 0,
            dst: [0; 16],
            dst_len: 0,
            dscp: 0,
            dscp_mask: 0,
            dscp_full: false,
            flow: 0,
            flowlabel: 0,
            flowlabel_mask: 0,
        }
    }

    /// A default rule, as `fib_default_rule_add` of Linux.
    const fn default_rule(pref: u32, table: u32) -> Self {
        let mut r = Self::empty();
        r.action = FR_ACT_TO_TBL;
        r.pref = pref;
        r.table = table;
        r.proto = RTPROT_KERNEL as u8;
        r
    }

    /// Tells if the rule has a range of user IDs, as `uid_range_set` of Linux.
    fn has_uid(&self) -> bool {
        self.uid.0 != NO_UID && self.uid.1 != NO_UID
    }
}

/// The default rules of IPv4, as `fib_default_rules_init` of Linux.
static DEFAULT4: [Rule; 3] = [
    Rule::default_rule(0, RT_TABLE_LOCAL),
    Rule::default_rule(0x7ffe, RT_TABLE_MAIN),
    Rule::default_rule(0x7fff, RT_TABLE_DEFAULT),
];

/// The default rules of IPv6, as `fib6_rules_net_init` of Linux.
static DEFAULT6: [Rule; 2] =
    [Rule::default_rule(0, RT_TABLE_LOCAL), Rule::default_rule(0x7ffe, RT_TABLE_MAIN)];

/// The fields of a packet that a rule looks at, as `struct flowi` of Linux. The addresses of
/// IPv4 are in the first 4 bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flow {
    /// The destination address.
    pub dst: [u8; 16],
    /// The source address, or `None` if the lookup has no source yet.
    pub src: Option<[u8; 16]>,
    /// The input interface. A packet of this host comes from the loopback device.
    pub iif: u32,
    /// The output interface, or 0.
    pub oif: u32,
    /// The firewall mark.
    pub mark: u32,
    /// The user ID of the socket.
    pub uid: u32,
    /// The field of the type of service.
    pub tos: u8,
    /// The IP protocol.
    pub proto: u8,
    /// The source port.
    pub sport: u16,
    /// The destination port.
    pub dport: u16,
    /// The IPv6 flow label, in the byte order of the network.
    pub flowlabel: u32,
}

impl Flow {
    /// A flow to the IPv4 address `dst` through `oif`, from the host.
    pub fn v4(dst: [u8; 4], oif: u32, iif: u32) -> Self {
        let mut d = [0; 16];
        d[..4].copy_from_slice(&dst);
        Self { dst: d, oif, iif, ..Self::default() }
    }

    /// Sets the IPv4 source address.
    pub fn with_src4(mut self, src: [u8; 4]) -> Self {
        let mut s = [0; 16];
        s[..4].copy_from_slice(&src);
        self.src = Some(s);
        self
    }
}

/// The result of the lookup in one table, for `Rules::lookup`.
pub enum Step<T> {
    /// The table has no route, or a route of the type `throw`: the next rule runs.
    Next,
    /// The table has a route. The value is the length of its prefix for the check of
    /// `suppress_prefixlength`, or `None` for a route that gives an error.
    Found(T, Option<u8>),
}

/// Tells if the `bits` first bits of `a` and `b` are the same.
fn same_prefix(a: &[u8], b: &[u8], bits: u8) -> bool {
    let full = usize::from(bits / 8);
    if a[..full] != b[..full] {
        return false;
    }
    let rest = bits % 8;
    rest == 0 || (a[full] ^ b[full]) & (0xffu8 << (8 - rest)) == 0
}

/// Tells if a port matches a range and a mask, as `fib_rule_port_match` of Linux.
fn port_match(range: (u16, u16), mask: u16, port: u16) -> bool {
    if (range.0 ^ port) & mask != 0 {
        return false;
    }
    !(mask == 0 && range_set(range) && !(range.0..=range.1).contains(&port))
}

/// Tells if a range of ports is set, as `fib_rule_port_range_set` of Linux.
fn range_set(r: (u16, u16)) -> bool {
    r.0 != 0 && r.1 != 0
}

/// The rules of one family in one namespace, as `struct fib_rules_ops` of Linux.
pub struct Rules {
    /// The family, `AF_INET` or `AF_INET6`.
    family: u32,
    /// The rules in their order, when `custom` is set.
    list: Vec<Rule>,
    /// The administrator changed the rules. Until then the list is the default rules.
    custom: bool,
}

impl Rules {
    /// The default rules of `family`.
    pub const fn new(family: u32) -> Self {
        Self { family, list: Vec::new(), custom: false }
    }

    /// The rules in their order.
    pub fn list(&self) -> &[Rule] {
        if self.custom {
            &self.list
        } else if self.family == AF_INET6 {
            &DEFAULT6
        } else {
            &DEFAULT4
        }
    }

    /// The list to change.
    fn list_mut(&mut self) -> &mut Vec<Rule> {
        if !self.custom {
            self.list = self.list().to_vec();
            self.custom = true;
        }
        &mut self.list
    }

    /// The size of the addresses of the family.
    fn addr_size(&self) -> usize {
        if self.family == AF_INET6 { 16 } else { 4 }
    }

    /// Tells if the rule `r` takes the flow `fl`, as `fib_rule_match` of Linux.
    fn matches(&self, r: &Rule, fl: &Flow) -> bool {
        let m = self.matches_selector(r, fl);
        if r.flags & FIB_RULE_INVERT != 0 { !m } else { m }
    }

    fn matches_selector(&self, r: &Rule, fl: &Flow) -> bool {
        if r.iifindex != 0 && i64::from(r.iifindex) != i64::from(fl.iif) {
            return false;
        }
        if r.oifindex != 0 && i64::from(r.oifindex) != i64::from(fl.oif) {
            return false;
        }
        if (r.mark ^ fl.mark) & r.mark_mask != 0 {
            return false;
        }
        // The packets of this stack have no tunnel ID, and no device is an L3 master.
        if r.tun_id != 0 || r.l3mdev != 0 {
            return false;
        }
        if fl.uid < r.uid.0 || fl.uid > r.uid.1 {
            return false;
        }
        let n = self.addr_size();
        if !same_prefix(&fl.dst[..n], &r.dst[..n], r.dst_len) {
            return false;
        }
        let dscp = fl.tos >> 2;
        if self.family == AF_INET6 {
            if r.src_len != 0 {
                match fl.src {
                    Some(s) if !same_prefix(&s, &r.src, r.src_len) => return false,
                    None if r.flags & FIB_RULE_FIND_SADDR == 0 => return false,
                    _ => {}
                }
            }
            if (r.dscp ^ dscp) & r.dscp_mask != 0 {
                return false;
            }
            if (r.flowlabel ^ fl.flowlabel) & r.flowlabel_mask != 0 {
                return false;
            }
        } else {
            let src = fl.src.unwrap_or([0; 16]);
            if !same_prefix(&src[..4], &r.src[..4], r.src_len) {
                return false;
            }
            // The type of service compares the 3 bits of `IPTOS_TOS_MASK`, as
            // `fib_dscp_masked_match` of Linux.
            if r.dscp_full && (r.dscp ^ dscp) & r.dscp_mask != 0 {
                return false;
            }
            if !r.dscp_full && r.dscp != 0 && r.dscp != dscp & 0x7 {
                return false;
            }
        }
        if r.ip_proto != 0 && r.ip_proto != fl.proto {
            return false;
        }
        port_match(r.sport, r.sport_mask, fl.sport) && port_match(r.dport, r.dport_mask, fl.dport)
    }

    /// Walks the rules for `fl`, as `fib_rules_lookup` of Linux. `table` looks in one table.
    /// Gives the result and the rule that gave it.
    ///
    /// # Errors
    ///
    /// Gives `ESRCH` if no rule gives a route, and `ENETUNREACH`, `EACCES` or `EINVAL` for a
    /// rule of the type `unreachable`, `prohibit` or `blackhole`.
    pub fn lookup<T>(&self, fl: &Flow, mut table: impl FnMut(u32) -> Step<T>) -> Result<T> {
        let list = self.list();
        let mut i = 0;
        while i < list.len() {
            let r = &list[i];
            i += 1;
            if !self.matches(r, fl) {
                continue;
            }
            match r.action {
                FR_ACT_GOTO => {
                    // The target is the first rule with its priority. A rule without its
                    // target does nothing.
                    if let Some(t) = list.iter().position(|x| x.pref == r.target) {
                        i = t;
                    }
                    continue;
                }
                FR_ACT_NOP => continue,
                FR_ACT_TO_TBL => {}
                FR_ACT_UNREACHABLE => return Err(Errno::ENETUNREACH),
                FR_ACT_PROHIBIT => return Err(Errno::EACCES),
                _ => return Err(Errno::EINVAL),
            }
            match table(r.table) {
                Step::Next => continue,
                Step::Found(v, None) => return Ok(v),
                Step::Found(v, Some(prefix)) => {
                    // A route with a short prefix does not count, as `fib4_rule_suppress`.
                    if i32::from(prefix) <= r.suppress_prefixlen {
                        continue;
                    }
                    return Ok(v);
                }
            }
        }
        Err(Errno::ESRCH)
    }

    /// The priority of a new rule without a priority, as `fib_default_rule_pref` of Linux:
    /// one below the priority of the second rule.
    fn default_pref(&self) -> u32 {
        match self.list().get(1) {
            Some(r) if r.pref != 0 => r.pref - 1,
            _ => 0,
        }
    }

    /// Sets the interface indices of the rules with the name of `dev`, as `attach_rules`.
    fn attach(&mut self, name: &str, ifindex: u32) {
        if !self.custom {
            return;
        }
        for r in &mut self.list {
            if r.iifindex == -1 && r.iifname == name {
                r.iifindex = ifindex as i32;
            }
            if r.oifindex == -1 && r.oifname == name {
                r.oifindex = ifindex as i32;
            }
        }
    }

    /// Marks the rules with the interface `ifindex` as detached, as `detach_rules`.
    fn detach(&mut self, ifindex: u32) {
        if !self.custom {
            return;
        }
        for r in &mut self.list {
            if r.iifindex == ifindex as i32 {
                r.iifindex = -1;
            }
            if r.oifindex == ifindex as i32 {
                r.oifindex = -1;
            }
        }
    }
}

/// Registers the handlers of the rules and the function that takes the changes of the devices.
pub(crate) fn init() {
    netlink::register(AF_UNSPEC as u8, RTM_NEWRULE, Some(newrule), None, false);
    netlink::register(AF_UNSPEC as u8, RTM_DELRULE, Some(delrule), None, false);
    netlink::register(AF_UNSPEC as u8, RTM_GETRULE, None, Some(dump), false);
    dev::add_notifier(event);
}

/// Takes the changes of the devices, as `fib_rules_event` of Linux.
fn event(d: &NetDevice, e: Event) {
    let ifindex = d.ifindex();
    let apply = |f: &dyn Fn(&mut Rules)| {
        f(&mut ROUTES.lock().rules);
        f(&mut ROUTES6.lock().rules);
    };
    match e {
        Event::Register => {
            let name = d.name();
            apply(&|r| r.attach(&name, ifindex));
        }
        Event::Name => {
            let name = d.name();
            apply(&|r| {
                r.detach(ifindex);
                r.attach(&name, ifindex);
            });
        }
        Event::Unregister => apply(&|r| r.detach(ifindex)),
        _ => {}
    }
}

/// Runs `f` on the rules of `family`, or gives `None` for a family without rules, as
/// `lookup_rules_ops` of Linux.
fn with_rules<R>(family: u8, f: impl FnOnce(&mut Rules) -> R) -> Option<R> {
    match u32::from(family) {
        AF_INET => Some(f(&mut ROUTES.lock().rules)),
        AF_INET6 => Some(f(&mut ROUTES6.lock().rules)),
        _ => None,
    }
}

/// The group of the notifications of `family`.
fn group(family: u8) -> u32 {
    if u32::from(family) == AF_INET6 { RTNLGRP_IPV6_RULE } else { RTNLGRP_IPV4_RULE }
}

/// Tells if `r` is a `goto` rule without its target in `list`.
fn unresolved(list: &[Rule], r: &Rule) -> bool {
    r.action == FR_ACT_GOTO && !list.iter().any(|x| x.pref == r.target)
}

/// Builds the message of a rule of `list`, as `fib_nl_fill_rule` of Linux.
fn fill(list: &[Rule], r: &Rule, family: u8, ty: u32, flags: u32, seq: u32, pid: u32) -> Vec<u8> {
    let mut b = Builder::new(ty as u16, flags as u16, seq, pid);
    let mut h = [0u8; FRH_LEN];
    h[0] = family;
    h[4] = if r.table < 256 { r.table as u8 } else { RT_TABLE_COMPAT as u8 };
    h[7] = r.action;
    let mut fl = r.flags;
    if unresolved(list, r) {
        fl |= FIB_RULE_UNRESOLVED;
    }
    if !r.iifname.is_empty() && r.iifindex == -1 {
        fl |= FIB_RULE_IIF_DETACHED;
    }
    if !r.oifname.is_empty() && r.oifindex == -1 {
        fl |= FIB_RULE_OIF_DETACHED;
    }
    let v6 = u32::from(family) == AF_INET6;
    h[1] = r.dst_len;
    h[2] = r.src_len;
    h[3] = if r.dscp_full { 0 } else { r.dscp << 2 };
    h[8..12].copy_from_slice(&fl.to_ne_bytes());
    b.fixed(&h);
    b.u32(FRA_TABLE as u16, r.table);
    b.u32(FRA_SUPPRESS_PREFIXLEN as u16, r.suppress_prefixlen as u32);
    b.u8(FRA_PROTOCOL as u16, r.proto);
    if !r.iifname.is_empty() {
        b.str(FRA_IIFNAME as u16, &r.iifname);
    }
    if !r.oifname.is_empty() {
        b.str(FRA_OIFNAME as u16, &r.oifname);
    }
    if r.pref != 0 {
        b.u32(FRA_PRIORITY as u16, r.pref);
    }
    if r.mark != 0 {
        b.u32(FRA_FWMARK as u16, r.mark);
    }
    if r.mark_mask != 0 || r.mark != 0 {
        b.u32(FRA_FWMASK as u16, r.mark_mask);
    }
    if r.target != 0 {
        b.u32(FRA_GOTO as u16, r.target);
    }
    if r.tun_id != 0 {
        b.put(FRA_TUN_ID as u16, &r.tun_id.to_ne_bytes());
    }
    if r.l3mdev != 0 {
        b.u8(FRA_L3MDEV as u16, r.l3mdev);
    }
    if r.has_uid() {
        let mut u = [0u8; 8];
        u[..4].copy_from_slice(&r.uid.0.to_ne_bytes());
        u[4..].copy_from_slice(&r.uid.1.to_ne_bytes());
        b.put(FRA_UID_RANGE as u16, &u);
    }
    let range = |b: &mut Builder, ty: u32, p: (u16, u16)| {
        let mut v = [0u8; 4];
        v[..2].copy_from_slice(&p.0.to_ne_bytes());
        v[2..].copy_from_slice(&p.1.to_ne_bytes());
        b.put(ty as u16, &v);
    };
    if range_set(r.sport) {
        range(&mut b, FRA_SPORT_RANGE, r.sport);
    }
    if r.sport_mask != 0 {
        b.u16(FRA_SPORT_MASK as u16, r.sport_mask);
    }
    if range_set(r.dport) {
        range(&mut b, FRA_DPORT_RANGE, r.dport);
    }
    if r.dport_mask != 0 {
        b.u16(FRA_DPORT_MASK as u16, r.dport_mask);
    }
    if r.ip_proto != 0 {
        b.u8(FRA_IP_PROTO as u16, r.ip_proto);
    }
    if r.suppress_ifgroup != -1 {
        b.u32(FRA_SUPPRESS_IFGROUP as u16, r.suppress_ifgroup as u32);
    }
    // The part of the family, as `fib4_rule_fill` and `fib6_rule_fill`.
    if r.dscp_full {
        b.u8(FRA_DSCP as u16, r.dscp);
        b.u8(FRA_DSCP_MASK as u16, r.dscp_mask);
    }
    let n = if v6 { 16 } else { 4 };
    if v6 && r.flowlabel_mask != 0 {
        b.u32(FRA_FLOWLABEL as u16, r.flowlabel);
        b.u32(FRA_FLOWLABEL_MASK as u16, r.flowlabel_mask);
    }
    if r.dst_len != 0 {
        b.put(FRA_DST as u16, &r.dst[..n]);
    }
    if r.src_len != 0 {
        b.put(FRA_SRC as u16, &r.src[..n]);
    }
    if !v6 && r.flow != 0 {
        b.u32(FRA_FLOW as u16, r.flow);
    }
    b.finish()
}

/// Sends a change of a rule to the group of its family, as `notify_rule_change` of Linux.
fn notify(m: Vec<u8>, family: u8, origin: Origin) {
    netlink::notify(group(family), m, origin);
}

/// Tells if a change of a rule of `family` goes to a socket.
fn wanted(family: u8, origin: Origin) -> bool {
    netlink::has_listeners(group(family)) || origin.echo
}

/// Checks the attributes of a request against `fib_rule_policy` of Linux, as
/// `nlmsg_parse_deprecated`. Gives the error and the payload of the bad attribute.
fn check_policy(p: &[u8]) -> core::result::Result<(), (Errno, &[u8])> {
    for (ty, d) in attrs(p) {
        let ty = u32::from(ty);
        let min = match ty {
            FRA_IIFNAME | FRA_OIFNAME => {
                let len = d.iter().position(|&c| c == 0).unwrap_or(d.len());
                if len > IFNAMSIZ - 1 {
                    return Err((Errno::ERANGE, d));
                }
                0
            }
            FRA_PRIORITY
            | FRA_FWMARK
            | FRA_FLOW
            | FRA_FWMASK
            | FRA_TABLE
            | FRA_SUPPRESS_PREFIXLEN
            | FRA_SUPPRESS_IFGROUP
            | FRA_GOTO => 4,
            FRA_TUN_ID | FRA_UID_RANGE => 8,
            FRA_L3MDEV | FRA_PROTOCOL | FRA_IP_PROTO => 1,
            FRA_SPORT_RANGE | FRA_DPORT_RANGE => 4,
            // The newer attributes have the strict checks: the exact size.
            FRA_DSCP | FRA_DSCP_MASK => {
                if d.len() != 1 {
                    return Err((Errno::EINVAL, d));
                }
                if d[0] > 0x3f {
                    return Err((if ty == FRA_DSCP { Errno::ERANGE } else { Errno::EINVAL }, d));
                }
                1
            }
            FRA_FLOWLABEL | FRA_FLOWLABEL_MASK => {
                if d.len() != 4 {
                    return Err((Errno::EINVAL, d));
                }
                4
            }
            FRA_SPORT_MASK | FRA_DPORT_MASK => {
                if d.len() != 2 {
                    return Err((Errno::EINVAL, d));
                }
                2
            }
            _ => 0,
        };
        if d.len() < min {
            return Err((Errno::ERANGE, d));
        }
    }
    Ok(())
}

/// Reads a range of ports, as `nla_get_port_range` of Linux.
fn port_range(d: &[u8]) -> Option<(u16, u16)> {
    let s = u16::from_ne_bytes([d[0], d[1]]);
    let e = u16::from_ne_bytes([d[2], d[3]]);
    (s != 0 && e != 0 && e < 0xffff && s <= e).then_some((s, e))
}

/// Reads the mask of a port, as `fib_nl2rule_port_mask` of Linux.
fn port_mask(req: &Request<'_>, d: &[u8], range: (u16, u16)) -> Result<u16> {
    let valid = range.0 != 0 && range.1 != 0 && range.1 < 0xffff && range.0 <= range.1;
    if !valid {
        return Err(req.attr_error(
            "Cannot specify port mask without port value",
            d,
            Errno::EINVAL,
        ));
    }
    if range.0 != range.1 {
        return Err(req.attr_error("Cannot specify port mask for port range", d, Errno::EINVAL));
    }
    let m = u16::from_ne_bytes([d[0], d[1]]);
    if range.0 & !m != 0 {
        return Err(req.attr_error("Invalid port mask", d, Errno::EINVAL));
    }
    Ok(m)
}

/// A request to add or remove a rule, after `fib_nl2rule` and the `configure` of the family.
struct Parsed<'a> {
    family: u8,
    rule: Rule,
    /// The request has `FRA_PRIORITY`.
    user_pref: bool,
    hdr: &'a [u8],
    attrs: Attrs<'a>,
}

fn u32_of(a: &Attrs<'_>, ty: u32) -> Option<u32> {
    a.u32(ty).ok().flatten()
}

fn u8_of(a: &Attrs<'_>, ty: u32) -> Option<u8> {
    a.u8(ty).ok().flatten()
}

/// Reads a request, as the first part of `fib_newrule` and `fib_delrule` of Linux, with
/// `fib_nl2rule`.
fn parse<'a>(req: &'a Request<'a>) -> Result<Parsed<'a>> {
    let p = req.payload();
    if p.len() < FRH_LEN {
        return Err(req.error("Invalid msg length", Errno::EINVAL));
    }
    let family = p[0];
    let size = match u32::from(family) {
        AF_INET => 4,
        AF_INET6 => 16,
        _ => return Err(req.error("Rule family not supported", Errno::EAFNOSUPPORT)),
    };
    let rest = &p[FRH_LEN..];
    if let Err((e, d)) = check_policy(rest) {
        return Err(req.attr_error("Error parsing msg", d, e));
    }
    let h = &p[..FRH_LEN];
    let a = Attrs::parse(rest, FRA_MAX);
    let (dst_len, src_len) = (h[1], h[2]);
    let addr_ok =
        |ty: u32, len: u8| a.get(ty).is_some_and(|d| d.len() == size) && len <= size as u8 * 8;
    if src_len != 0 && !addr_ok(FRA_SRC, src_len) {
        return Err(req.error("Invalid source address", Errno::EINVAL));
    }
    if dst_len != 0 && !addr_ok(FRA_DST, dst_len) {
        return Err(req.error("Invalid dst address", Errno::EINVAL));
    }
    let mut r = Rule::empty();
    let user_pref = a.has(FRA_PRIORITY);
    r.pref = u32_of(&a, FRA_PRIORITY).unwrap_or(0);
    r.proto = u8_of(&a, FRA_PROTOCOL).unwrap_or(0);
    let name = |ty: u32| {
        a.str(ty).map(|s| String::from_utf8_lossy(&s[..s.len().min(IFNAMSIZ - 1)]).into_owned())
    };
    if let Some(n) = name(FRA_IIFNAME) {
        r.iifname = n;
        r.iifindex = -1;
    }
    if let Some(n) = name(FRA_OIFNAME) {
        r.oifname = n;
        r.oifindex = -1;
    }
    if let Some(m) = u32_of(&a, FRA_FWMARK) {
        r.mark = m;
        if m != 0 {
            r.mark_mask = u32::MAX;
        }
    }
    if let Some(m) = u32_of(&a, FRA_FWMASK) {
        r.mark_mask = m;
    }
    if let Some(d) = a.get(FRA_TUN_ID) {
        r.tun_id = u64::from_ne_bytes(d[..8].try_into().unwrap_or([0; 8]));
    }
    if a.has(FRA_L3MDEV) {
        return Err(req.error("l3mdev support is not enabled in kernel", Errno::EINVAL));
    }
    r.action = h[7];
    r.flags = u32::from_ne_bytes([h[8], h[9], h[10], h[11]]);
    r.table = u32_of(&a, FRA_TABLE).unwrap_or(u32::from(h[4]));
    r.suppress_prefixlen = u32_of(&a, FRA_SUPPRESS_PREFIXLEN).map_or(-1, |v| v as i32);
    r.suppress_ifgroup = u32_of(&a, FRA_SUPPRESS_IFGROUP).map_or(-1, |v| v as i32);
    if let Some(t) = u32_of(&a, FRA_GOTO) {
        if r.action != FR_ACT_GOTO {
            return Err(req.error("Unexpected goto", Errno::EINVAL));
        }
        r.target = t;
    } else if r.action == FR_ACT_GOTO {
        return Err(req.error("Missing goto target for action goto", Errno::EINVAL));
    }
    if let Some(d) = a.get(FRA_UID_RANGE) {
        let s = u32::from_ne_bytes([d[0], d[1], d[2], d[3]]);
        let e = u32::from_ne_bytes([d[4], d[5], d[6], d[7]]);
        r.uid = (s, e);
        if !r.has_uid() || s > e {
            return Err(req.error("Invalid uid range", Errno::EINVAL));
        }
    }
    r.ip_proto = u8_of(&a, FRA_IP_PROTO).unwrap_or(0);
    if let Some(d) = a.get(FRA_SPORT_RANGE) {
        r.sport = port_range(d).ok_or_else(|| req.error("Invalid sport range", Errno::EINVAL))?;
        if r.sport.0 == r.sport.1 {
            r.sport_mask = u16::MAX;
        }
    }
    if let Some(d) = a.get(FRA_SPORT_MASK) {
        r.sport_mask = port_mask(req, d, r.sport)?;
    }
    if let Some(d) = a.get(FRA_DPORT_RANGE) {
        r.dport = port_range(d).ok_or_else(|| req.error("Invalid dport range", Errno::EINVAL))?;
        if r.dport.0 == r.dport.1 {
            r.dport_mask = u16::MAX;
        }
    }
    if let Some(d) = a.get(FRA_DPORT_MASK) {
        r.dport_mask = port_mask(req, d, r.dport)?;
    }
    Ok(Parsed { family, rule: r, user_pref, hdr: h, attrs: a })
}

/// Reads the part of the family, as `fib4_rule_configure` and `fib6_rule_configure` of Linux,
/// without the choice of a table.
fn configure(req: &Request<'_>, p: &mut Parsed<'_>) -> Result<()> {
    let (h, a, r) = (p.hdr, &p.attrs, &mut p.rule);
    let v6 = u32::from(p.family) == AF_INET6;
    let tos = h[3];
    if !v6 && (a.has(FRA_FLOWLABEL) || a.has(FRA_FLOWLABEL_MASK)) {
        return Err(req.error("Flow label cannot be specified for IPv4 FIB rules", Errno::EINVAL));
    }
    if tos & 3 != 0 {
        return Err(req.error("Invalid dsfield (tos): ECN bits must be 0", Errno::EINVAL));
    }
    if !v6 && tos & !0x1e != 0 {
        return Err(req.error("Invalid tos", Errno::EINVAL));
    }
    r.dscp = tos >> 2;
    if v6 && tos != 0 {
        r.dscp_mask = 0x3f;
    }
    if let Some(v) = u8_of(a, FRA_DSCP) {
        if r.dscp != 0 {
            return Err(req.error("Cannot specify both TOS and DSCP", Errno::EINVAL));
        }
        r.dscp = v;
        r.dscp_mask = 0x3f;
        r.dscp_full = true;
    }
    if let Some(d) = a.get(FRA_DSCP_MASK) {
        if !r.dscp_full {
            return Err(req.attr_error(
                "Cannot specify DSCP mask without DSCP value",
                d,
                Errno::EINVAL,
            ));
        }
        if r.dscp & !d[0] != 0 {
            return Err(req.attr_error("Invalid DSCP mask", d, Errno::EINVAL));
        }
        r.dscp_mask = d[0];
    }
    if v6 && (a.has(FRA_FLOWLABEL) || a.has(FRA_FLOWLABEL_MASK)) {
        // Linux tells the missing attribute in `NLMSGERR_ATTR_MISS_TYPE`, without a message.
        let (Some(fl), Some(mask)) = (a.get(FRA_FLOWLABEL), a.get(FRA_FLOWLABEL_MASK)) else {
            return Err(Errno::EINVAL);
        };
        let fl = u32::from_ne_bytes([fl[0], fl[1], fl[2], fl[3]]);
        let m = u32::from_ne_bytes([mask[0], mask[1], mask[2], mask[3]]);
        if m & !FLOWLABEL_MASK != 0 {
            return Err(req.attr_error("Invalid flow label mask", mask, Errno::EINVAL));
        }
        if fl & !m != 0 {
            return Err(req.error("Flow label and mask do not match", Errno::EINVAL));
        }
        r.flowlabel = fl;
        r.flowlabel_mask = m;
    }
    if v6 && r.action == FR_ACT_TO_TBL && r.table == 0 {
        return Err(req.error("Invalid table", Errno::EINVAL));
    }
    let n = if v6 { 16 } else { 4 };
    r.src_len = h[2];
    r.dst_len = h[1];
    if r.src_len != 0
        && let Some(s) = a.get(FRA_SRC)
    {
        r.src[..n].copy_from_slice(&s[..n]);
    }
    if r.dst_len != 0
        && let Some(d) = a.get(FRA_DST)
    {
        r.dst[..n].copy_from_slice(&d[..n]);
    }
    if !v6 {
        r.flow = u32_of(a, FRA_FLOW).unwrap_or(0);
    }
    Ok(())
}

/// The part of `fib_nl2rule_locked` of Linux: the default priority, the check of the target
/// of `goto`, and the interfaces.
fn locked(req: &Request<'_>, rules: &Rules, p: &mut Parsed<'_>) -> Result<()> {
    let r = &mut p.rule;
    if !p.user_pref {
        r.pref = rules.default_pref();
    }
    if p.attrs.has(FRA_GOTO) && r.target <= r.pref {
        return Err(req.error("Backward goto not supported", Errno::EINVAL));
    }
    Ok(())
}

/// Sets the indices of the interfaces of `r` from their names. A missing interface keeps -1.
fn resolve(r: &mut Rule) {
    if !r.iifname.is_empty()
        && let Some(d) = dev::by_name(&r.iifname)
    {
        r.iifindex = d.ifindex() as i32;
    }
    if !r.oifname.is_empty()
        && let Some(d) = dev::by_name(&r.oifname)
    {
        r.oifindex = d.ifindex() as i32;
    }
}

/// Tells if the family part of `r` matches the request, as `fib4_rule_compare` and
/// `fib6_rule_compare` of Linux.
fn compare(r: &Rule, family: u8, h: &[u8], a: &Attrs<'_>) -> bool {
    let n = if u32::from(family) == AF_INET6 { 16 } else { 4 };
    let (dst_len, src_len, tos) = (h[1], h[2], h[3]);
    if src_len != 0 && r.src_len != src_len {
        return false;
    }
    if dst_len != 0 && r.dst_len != dst_len {
        return false;
    }
    if tos != 0 && (r.dscp_full || r.dscp << 2 != tos) {
        return false;
    }
    if let Some(v) = u8_of(a, FRA_DSCP)
        && (!r.dscp_full || r.dscp != v)
    {
        return false;
    }
    if let Some(v) = u8_of(a, FRA_DSCP_MASK)
        && (!r.dscp_full || r.dscp_mask != v)
    {
        return false;
    }
    if n == 16 {
        if u32_of(a, FRA_FLOWLABEL).is_some_and(|v| v != r.flowlabel) {
            return false;
        }
        if u32_of(a, FRA_FLOWLABEL_MASK).is_some_and(|v| v != r.flowlabel_mask) {
            return false;
        }
    } else if u32_of(a, FRA_FLOW).is_some_and(|v| v != r.flow) {
        return false;
    }
    if src_len != 0 && a.get(FRA_SRC).is_none_or(|s| s[..n] != r.src[..n]) {
        return false;
    }
    if dst_len != 0 && a.get(FRA_DST).is_none_or(|d| d[..n] != r.dst[..n]) {
        return false;
    }
    true
}

/// Tells if the list has a rule with the same fields as `p`, as `rule_exists` of Linux.
fn exists(rules: &Rules, p: &Parsed<'_>) -> bool {
    let n = &p.rule;
    rules.list().iter().any(|r| {
        r.action == n.action
            && r.table == n.table
            && r.pref == n.pref
            && r.iifname == n.iifname
            && r.oifname == n.oifname
            && r.mark == n.mark
            && r.suppress_ifgroup == n.suppress_ifgroup
            && r.suppress_prefixlen == n.suppress_prefixlen
            && r.mark_mask == n.mark_mask
            && r.tun_id == n.tun_id
            && r.l3mdev == n.l3mdev
            && r.uid == n.uid
            && r.ip_proto == n.ip_proto
            && r.proto == n.proto
            && r.sport == n.sport
            && r.sport_mask == n.sport_mask
            && r.dport == n.dport
            && r.dport_mask == n.dport_mask
            && compare(r, p.family, p.hdr, &p.attrs)
    })
}

/// The index of the first rule that the request selects, as `rule_find` of Linux. A field that
/// the request does not set selects each rule.
fn find(rules: &Rules, p: &Parsed<'_>) -> Option<usize> {
    let n = &p.rule;
    rules.list().iter().position(|r| {
        (n.action == 0 || r.action == n.action)
            && (n.table == 0 || r.table == n.table)
            && (!p.user_pref || r.pref == n.pref)
            && (n.iifname.is_empty() || r.iifname == n.iifname)
            && (n.oifname.is_empty() || r.oifname == n.oifname)
            && (n.mark == 0 || r.mark == n.mark)
            && (n.suppress_ifgroup == -1 || r.suppress_ifgroup == n.suppress_ifgroup)
            && (n.suppress_prefixlen == -1 || r.suppress_prefixlen == n.suppress_prefixlen)
            && (n.mark_mask == 0 || r.mark_mask == n.mark_mask)
            && (n.tun_id == 0 || r.tun_id == n.tun_id)
            && (n.l3mdev == 0 || r.l3mdev == n.l3mdev)
            && (!n.has_uid() || r.uid == n.uid)
            && (n.ip_proto == 0 || r.ip_proto == n.ip_proto)
            && (n.proto == 0 || r.proto == n.proto)
            && (!range_set(n.sport) || r.sport == n.sport)
            && (n.sport_mask == 0 || r.sport_mask == n.sport_mask)
            && (!range_set(n.dport) || r.dport == n.dport)
            && (n.dport_mask == 0 || r.dport_mask == n.dport_mask)
            && compare(r, p.family, p.hdr, &p.attrs)
    })
}

/// `RTM_NEWRULE`, as `fib_newrule` of Linux.
fn newrule(req: &Request<'_>) -> Result<()> {
    let mut p = parse(req)?;
    let family = p.family;
    resolve(&mut p.rule);
    with_rules(family, |rules| -> Result<()> {
        locked(req, rules, &mut p)?;
        if req.hdr.flags & NLM_F_EXCL as u16 != 0 && exists(rules, &p) {
            return Err(Errno::EEXIST);
        }
        Ok(())
    })
    .ok_or(Errno::EAFNOSUPPORT)??;
    configure(req, &mut p)?;
    let mut rule = p.rule;
    // A rule of IPv4 to the table 0 gets a new empty table, as `fib_empty_table` of Linux.
    if u32::from(family) == AF_INET && rule.table == 0 && rule.action == FR_ACT_TO_TBL {
        rule.table = ROUTES.lock().new_table().ok_or(Errno::ENOBUFS)?;
    }
    let origin = req.origin();
    let m = with_rules(family, |rules| {
        let list = rules.list_mut();
        // The new rule goes after the last rule with the same or a lower priority.
        let at = list.iter().position(|r| r.pref > rule.pref).unwrap_or(list.len());
        list.insert(at, rule);
        wanted(family, origin)
            .then(|| fill(list, &list[at], family, RTM_NEWRULE, 0, origin.seq, origin.portid))
    })
    .ok_or(Errno::EAFNOSUPPORT)?;
    if let Some(m) = m {
        notify(m, family, origin);
    }
    Ok(())
}

/// `RTM_DELRULE`, as `fib_delrule` of Linux.
fn delrule(req: &Request<'_>) -> Result<()> {
    let mut p = parse(req)?;
    let family = p.family;
    resolve(&mut p.rule);
    let origin = req.origin();
    let m = with_rules(family, |rules| -> Result<Option<Vec<u8>>> {
        locked(req, rules, &mut p)?;
        let i = find(rules, &p).ok_or(Errno::ENOENT)?;
        if rules.list()[i].flags & FIB_RULE_PERMANENT != 0 {
            return Err(Errno::EPERM);
        }
        let list = rules.list_mut();
        let r = list.remove(i);
        Ok(wanted(family, origin)
            .then(|| fill(list, &r, family, RTM_DELRULE, 0, origin.seq, origin.portid)))
    })
    .ok_or(Errno::EAFNOSUPPORT)??;
    if let Some(m) = m {
        notify(m, family, origin);
    }
    Ok(())
}

/// `RTM_GETRULE` with `NLM_F_DUMP`, as `fib_nl_dumprule` of Linux.
fn dump(req: &Request<'_>) -> Result<Vec<Vec<u8>>> {
    let p = req.payload();
    if req.strict {
        if p.len() < FRH_LEN {
            return Err(req.error("Invalid header for fib rule dump request", Errno::EINVAL));
        }
        if p[1..FRH_LEN].iter().any(|&b| b != 0) {
            return Err(
                req.error("Invalid values in header for fib rule dump request", Errno::EINVAL)
            );
        }
        if p.len() > FRH_LEN {
            return Err(
                req.error("Invalid data after header in fib rule dump request", Errno::EINVAL)
            );
        }
    }
    let family = p.first().copied().unwrap_or(0);
    let families: &[u32] = match u32::from(family) {
        AF_UNSPEC => &[AF_INET, AF_INET6],
        AF_INET => &[AF_INET],
        AF_INET6 => &[AF_INET6],
        _ => return Err(Errno::EAFNOSUPPORT),
    };
    let mut out = Vec::new();
    for &f in families {
        let (seq, pid) = (req.hdr.seq, req.portid);
        with_rules(f as u8, |rules| {
            let list = rules.list();
            for r in list {
                out.push(fill(list, r, f as u8, RTM_NEWRULE, NLM_F_MULTI, seq, pid));
            }
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::{IfAddr, Link, Route, Table};
    use alloc::vec;
    use rk_abi::native::netlink::NLM_F_CREATE;

    fn rule(pref: u32, table: u32) -> Rule {
        Rule { pref, table, action: FR_ACT_TO_TBL, ..Rule::empty() }
    }

    fn add(rules: &mut Rules, r: Rule) {
        let list = rules.list_mut();
        let at = list.iter().position(|x| x.pref > r.pref).unwrap_or(list.len());
        list.insert(at, r);
    }

    /// The tables that the lookup visits, with a route in `found`.
    fn walk(rules: &Rules, fl: &Flow, found: &[(u32, u8)]) -> (Vec<u32>, Result<u32>) {
        let mut seen = Vec::new();
        let res = rules.lookup(fl, |t| {
            seen.push(t);
            match found.iter().find(|f| f.0 == t) {
                Some(&(t, prefix)) => Step::Found(t, Some(prefix)),
                None => Step::Next,
            }
        });
        (seen, res)
    }

    #[test]
    fn the_default_rules_are_those_of_linux() {
        let r4 = Rules::new(AF_INET);
        let got: Vec<(u32, u32)> = r4.list().iter().map(|r| (r.pref, r.table)).collect();
        assert_eq!(got, [(0, RT_TABLE_LOCAL), (0x7ffe, RT_TABLE_MAIN), (0x7fff, RT_TABLE_DEFAULT)]);
        let r6 = Rules::new(AF_INET6);
        let got: Vec<(u32, u32)> = r6.list().iter().map(|r| (r.pref, r.table)).collect();
        assert_eq!(got, [(0, RT_TABLE_LOCAL), (0x7ffe, RT_TABLE_MAIN)]);
        assert!(r4.list().iter().all(|r| r.proto == RTPROT_KERNEL as u8 && !r.has_uid()));
        assert_eq!(r4.default_pref(), 0x7ffd);
        let fl = Flow::v4([8, 8, 8, 8], 0, 1);
        assert_eq!(walk(&r4, &fl, &[]), (vec![255, 254, 253], Err(Errno::ESRCH)));
        assert_eq!(walk(&r4, &fl, &[(254, 0)]), (vec![255, 254], Ok(254)));
    }

    #[test]
    fn a_rule_selects_by_source_mark_and_interface() {
        let mut rules = Rules::new(AF_INET);
        let mut r = rule(100, 100);
        r.src[..4].copy_from_slice(&[10, 1, 0, 0]);
        r.src_len = 16;
        add(&mut rules, r);
        let mut r = rule(200, 200);
        r.mark = 5;
        r.mark_mask = 0xff;
        r.iifindex = 3;
        add(&mut rules, r);
        assert_eq!(rules.default_pref(), 99);
        let found = [(100, 24), (200, 24), (254, 0)];
        let fl = Flow::v4([8, 8, 8, 8], 0, 1);
        assert_eq!(walk(&rules, &fl, &found).1, Ok(254));
        assert_eq!(walk(&rules, &fl.with_src4([10, 1, 2, 3]), &found).1, Ok(100));
        assert_eq!(walk(&rules, &fl.with_src4([10, 2, 2, 3]), &found).1, Ok(254));
        let marked = Flow { mark: 0x105, iif: 3, ..fl };
        assert_eq!(walk(&rules, &marked, &found).1, Ok(200));
        assert_eq!(walk(&rules, &Flow { iif: 1, ..marked }, &found).1, Ok(254));
        // `not` turns the selector round.
        rules.list_mut()[1].flags |= FIB_RULE_INVERT;
        assert_eq!(walk(&rules, &fl.with_src4([10, 2, 2, 3]), &found).1, Ok(100));
    }

    #[test]
    fn goto_nop_suppress_and_the_reject_rules() {
        let mut rules = Rules::new(AF_INET);
        add(&mut rules, Rule { action: FR_ACT_GOTO, target: 300, ..rule(10, 0) });
        add(&mut rules, rule(20, 20));
        add(&mut rules, Rule { action: FR_ACT_NOP, ..rule(300, 0) });
        add(&mut rules, Rule { suppress_prefixlen: 0, ..rule(400, 254) });
        let fl = Flow::v4([8, 8, 8, 8], 0, 1);
        // The goto skips table 20. The default route of main is suppressed at 400.
        let (seen, res) = walk(&rules, &fl, &[(20, 8), (254, 0)]);
        assert_eq!(seen, [255, 254, 254]);
        assert_eq!(res, Ok(254));
        let (seen, res) = walk(&rules, &fl, &[(254, 8)]);
        assert_eq!((seen, res), (vec![255, 254], Ok(254)));
        // A goto without its target does nothing.
        rules.list_mut().retain(|r| r.pref != 300);
        assert_eq!(walk(&rules, &fl, &[(20, 8)]).1, Ok(20));
        for (action, e) in [
            (FR_ACT_UNREACHABLE, Errno::ENETUNREACH),
            (FR_ACT_PROHIBIT, Errno::EACCES),
            (FR_ACT_BLACKHOLE, Errno::EINVAL),
        ] {
            let mut rules = Rules::new(AF_INET);
            add(&mut rules, Rule { action, ..rule(5, 0) });
            assert_eq!(walk(&rules, &fl, &[(254, 0)]).1, Err(e));
        }
    }

    #[test]
    fn ports_and_protocols() {
        let r = Rule { ip_proto: 6, dport: (1000, 2000), ..rule(1, 1) };
        let rules = Rules::new(AF_INET);
        let fl = Flow { proto: 6, dport: 1500, ..Flow::v4([1, 1, 1, 1], 0, 1) };
        assert!(rules.matches(&r, &fl));
        assert!(!rules.matches(&r, &Flow { dport: 2001, ..fl }));
        assert!(!rules.matches(&r, &Flow { proto: 17, ..fl }));
        let masked = Rule { dport: (0x100, 0x100), dport_mask: 0xff00, ..r };
        assert!(rules.matches(&masked, &Flow { dport: 0x1ff, ..fl }));
        assert!(!rules.matches(&masked, &Flow { dport: 0x2ff, ..fl }));
    }

    #[test]
    fn a_policy_route_comes_from_its_table() {
        let mut t = Table::new();
        t.set_loopback(1);
        t.insert_addr(IfAddr::new(2, [10, 0, 2, 15], 24, "eth0")).unwrap();
        t.sync_link(Link { ifindex: 2, up: true, loopback: false });
        t.insert_route(Route::new([0; 4], 0, Some([10, 0, 2, 2]), 2), NLM_F_CREATE).unwrap();
        let other = Route { table: 100, ..Route::new([0; 4], 0, Some([10, 0, 2, 3]), 2) };
        t.insert_route(other, NLM_F_CREATE).unwrap();
        let mut r = rule(1000, 100);
        r.src[..4].copy_from_slice(&[10, 0, 2, 15]);
        r.src_len = 32;
        add(&mut t.rules, r);
        let (n, _) = t.lookup_route([8, 8, 8, 8], 0).unwrap();
        assert_eq!(n.hop, [10, 0, 2, 2]);
        let fl = Flow::v4([8, 8, 8, 8], 0, 1).with_src4([10, 0, 2, 15]);
        let (n, r) = t.lookup_flow(&fl).unwrap();
        assert_eq!((n.hop, r.unwrap().table), ([10, 0, 2, 3], 100));
        // A rule that rejects gives its error, and the error is ENETUNREACH without a route.
        add(&mut t.rules, Rule { action: FR_ACT_PROHIBIT, ..rule(500, 0) });
        assert_eq!(t.lookup([8, 8, 8, 8]), Err(Errno::EACCES));
        t.rules.list_mut().clear();
        assert_eq!(t.lookup([8, 8, 8, 8]), Err(Errno::ENETUNREACH));
    }
}

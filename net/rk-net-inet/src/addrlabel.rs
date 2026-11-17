//! The labels of the IPv6 addresses, the policy table of RFC 6724, as net/ipv6/addrlabel.c of
//! Linux: `RTM_NEWADDRLABEL`, `RTM_DELADDRLABEL` and `RTM_GETADDRLABEL`, which `ip addrlabel`
//! and `networkctl label` use.
//!
//! Each network namespace has its own table, which starts with the default policy of Linux. The
//! selection of a source address does not use the labels yet.

use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::netlink::{NLM_F_MULTI, NLM_F_REPLACE};
use rk_abi::native::rtnetlink::{RTM_DELADDRLABEL, RTM_GETADDRLABEL, RTM_NEWADDRLABEL};
use rk_frame::sync::SpinLock;
use rk_net::consts::AF_INET6;
use rk_net::dev;
use rk_net::netlink::msg::Builder;
use rk_net::netlink::{self, Request};
use rk_net::ns::PerNet;
use rk_vfs::inode::Result;

/// The size of `struct ifaddrlblmsg`.
const IFAL_LEN: usize = 12;
/// The prefix of a label, `IFAL_ADDRESS` of <linux/if_addrlabel.h>.
const IFAL_ADDRESS: u32 = 1;
/// The label, `IFAL_LABEL`.
const IFAL_LABEL: u32 = 2;
/// The last attribute, `IFAL_MAX`.
const IFAL_MAX: u16 = 2;
/// The label of an address that no entry takes, `IPV6_ADDR_LABEL_DEFAULT`. A process cannot
/// add it.
const LABEL_DEFAULT: u32 = 0xffff_ffff;

/// The kinds of address that an entry can need, as the `IPV6_ADDR_*` values that
/// `ip6addrlbl_alloc` of Linux keeps in `addrtype`. 0 is any address.
const MAPPED: u8 = 1;
const COMPAT_V4: u8 = 2;
const LOOPBACK: u8 = 3;

/// An entry of the table, `struct ip6addrlbl_entry` of Linux.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    prefix: [u8; 16],
    prefixlen: u8,
    /// The interface, or 0 for all of them.
    ifindex: u32,
    /// The kind of address that the entry needs, or 0.
    kind: u8,
    label: u32,
}

/// The table of a namespace, `ip6addrlbl_table` of Linux. `seq` counts the adds, and each
/// message has it.
struct Table {
    list: Vec<Entry>,
    seq: u32,
}

/// The default policy, `ip6addrlbl_init_table` of Linux: the prefix, its length and the label.
const DEFAULTS: [([u8; 16], u8, u32); 10] = [
    ([0; 16], 0, 1),
    (prefix(&[0xfc]), 7, 5),
    (prefix(&[0xfe, 0xc0]), 10, 11),
    (prefix(&[0x20, 0x02]), 16, 2),
    (prefix(&[0x3f, 0xfe]), 16, 12),
    (prefix(&[0x20, 0x01]), 32, 6),
    (prefix(&[0x20, 0x01, 0x00, 0x10]), 28, 7),
    (prefix(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]), 96, 4),
    ([0; 16], 96, 3),
    (prefix(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), 128, 0),
];

/// An address that starts with `head`.
const fn prefix(head: &[u8]) -> [u8; 16] {
    let mut a = [0; 16];
    let mut i = 0;
    while i < head.len() {
        a[i] = head[i];
        i += 1;
    }
    a
}

impl Table {
    /// The table of a new namespace, as `ip6addrlbl_net_init` of Linux.
    fn new() -> Self {
        let mut t = Self { list: Vec::new(), seq: 0 };
        for (p, len, label) in DEFAULTS {
            // The defaults are valid and have no duplicates.
            let _ = t.add(p, len, 0, label, false);
        }
        t
    }

    /// Adds an entry, as `ip6addrlbl_alloc` and `__ip6addrlbl_add` of Linux. A longer prefix
    /// comes first, and for one length an entry of an interface comes before an entry for all
    /// of them. Gives `EEXIST` for an entry that is there, without `replace`, and `EINVAL` for
    /// a prefix of the mapped addresses that is longer than 96 bits.
    fn add(&mut self, p: [u8; 16], len: u8, ifindex: u32, label: u32, replace: bool) -> Result<()> {
        let p = mask(p, len);
        let kind = match addr_kind(&p) {
            MAPPED if len > 96 => return Err(Errno::EINVAL),
            MAPPED | COMPAT_V4 if len == 96 => addr_kind(&p),
            LOOPBACK if len == 128 => LOOPBACK,
            _ => 0,
        };
        let new = Entry { prefix: p, prefixlen: len, ifindex, kind, label };
        let mut at = self.list.len();
        for (i, o) in self.list.iter().enumerate() {
            if o.prefixlen == len && o.ifindex == ifindex && o.prefix == p {
                if !replace {
                    return Err(Errno::EEXIST);
                }
                self.list[i] = new;
                self.seq = self.seq.wrapping_add(1);
                return Ok(());
            }
            if (o.prefixlen == len && o.ifindex == 0) || o.prefixlen < len {
                at = i;
                break;
            }
        }
        self.list.insert(at, new);
        self.seq = self.seq.wrapping_add(1);
        Ok(())
    }

    /// Removes an entry, as `__ip6addrlbl_del` of Linux. Gives `ESRCH` if it is not there.
    fn del(&mut self, p: [u8; 16], len: u8, ifindex: u32) -> Result<()> {
        let p = mask(p, len);
        let at = self
            .list
            .iter()
            .position(|o| o.prefixlen == len && o.ifindex == ifindex && o.prefix == p)
            .ok_or(Errno::ESRCH)?;
        self.list.remove(at);
        Ok(())
    }

    /// The first entry that takes the address `a` on the interface `ifindex`, as
    /// `__ipv6_addr_label` of Linux.
    fn lookup(&self, a: &[u8; 16], ifindex: u32) -> Option<&Entry> {
        let kind = addr_kind(a);
        self.list.iter().find(|e| {
            (e.ifindex == 0 || e.ifindex == ifindex)
                && (e.kind == 0 || e.kind == kind)
                && mask(*a, e.prefixlen) == e.prefix
        })
    }
}

/// The tables of the namespaces.
static TABLE: PerNet<SpinLock<Table>> = PerNet::new(|| SpinLock::new(Table::new()));

/// Clears the table of a namespace that stops.
pub(crate) fn ns_exit() {
    TABLE.reset();
}

/// The address `a` with only its first `len` bits, as `ipv6_addr_prefix` of Linux.
fn mask(mut a: [u8; 16], len: u8) -> [u8; 16] {
    let len = usize::from(len.min(128));
    for (i, b) in a.iter_mut().enumerate() {
        let bits = len.saturating_sub(i * 8).min(8);
        *b &= !(0xffu8.checked_shr(bits as u32).unwrap_or(0));
    }
    a
}

/// The kind of the address `a` for the entries, as the parts of `ipv6_addr_type` of Linux that
/// `ip6addrlbl_alloc` keeps: a mapped IPv4 address, an IPv4 compatible address, the loopback
/// address, or 0.
fn addr_kind(a: &[u8; 16]) -> u8 {
    if a[..8] != [0; 8] {
        return 0;
    }
    match (&a[8..12], &a[12..]) {
        ([0, 0, 0, 0], [0, 0, 0, 0]) => 0,
        ([0, 0, 0, 0], [0, 0, 0, 1]) => LOOPBACK,
        ([0, 0, 0, 0], _) => COMPAT_V4,
        ([0, 0, 0xff, 0xff], _) => MAPPED,
        _ => 0,
    }
}

/// The message of an entry, as `ip6addrlbl_fill` of Linux.
fn fill(e: &Entry, seq: u32, portid: u32, msg_seq: u32, flags: u32) -> Vec<u8> {
    let mut b = Builder::new(RTM_NEWADDRLABEL as u16, flags as u16, msg_seq, portid);
    let mut h = [0u8; IFAL_LEN];
    h[0] = AF_INET6 as u8;
    h[2] = e.prefixlen;
    h[4..8].copy_from_slice(&e.ifindex.to_ne_bytes());
    h[8..12].copy_from_slice(&seq.to_ne_bytes());
    b.fixed(&h);
    b.put(IFAL_ADDRESS as u16, &e.prefix).u32(IFAL_LABEL as u16, e.label);
    b.finish()
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4).map_or(0, |v| u32::from_ne_bytes([v[0], v[1], v[2], v[3]]))
}

/// Registers the handlers in rtnetlink. The stack calls this one time at boot.
pub(crate) fn init() {
    let inet6 = AF_INET6 as u8;
    netlink::register(inet6, RTM_NEWADDRLABEL, Some(newdel), None, false);
    netlink::register(inet6, RTM_DELADDRLABEL, Some(newdel), None, false);
    netlink::register(inet6, RTM_GETADDRLABEL, Some(get), Some(dump), false);
}

/// `RTM_NEWADDRLABEL` and `RTM_DELADDRLABEL`, as `ip6addrlbl_newdel` of Linux.
fn newdel(req: &Request<'_>) -> Result<()> {
    let (h, a) = req.parse(IFAL_LEN, IFAL_MAX)?;
    let len = h[2];
    if h[0] != AF_INET6 as u8 || len > 128 {
        return Err(Errno::EINVAL);
    }
    let p = a.addr6(IFAL_ADDRESS).map_err(|_| Errno::EINVAL)?.ok_or(Errno::EINVAL)?;
    let label = a.u32(IFAL_LABEL).map_err(|_| Errno::EINVAL)?.ok_or(Errno::EINVAL)?;
    if label == LABEL_DEFAULT {
        return Err(Errno::EINVAL);
    }
    let ifindex = u32_at(h, 4);
    let mut t = TABLE.get().lock();
    if u32::from(req.hdr.ty) == RTM_NEWADDRLABEL {
        if ifindex != 0 && dev::by_index(ifindex).is_none() {
            return Err(Errno::EINVAL);
        }
        let replace = u32::from(req.hdr.flags) & NLM_F_REPLACE != 0;
        t.add(p, len, ifindex, label, replace)
    } else {
        t.del(p, len, ifindex)
    }
}

/// `RTM_GETADDRLABEL` for one address, as `ip6addrlbl_get` of Linux: the entry that takes it.
fn get(req: &Request<'_>) -> Result<()> {
    let (h, a) = req.parse(IFAL_LEN, IFAL_MAX)?;
    if req.strict {
        if h[1] != 0 || h[3] != 0 || u32_at(h, 8) != 0 {
            return Err(
                req.error("Invalid values in header for addrlabel get request", Errno::EINVAL)
            );
        }
        if a.has(IFAL_LABEL) {
            return Err(req.error("Unsupported attribute in addrlabel get request", Errno::EINVAL));
        }
    }
    if h[0] != AF_INET6 as u8 || h[2] != 128 {
        return Err(Errno::EINVAL);
    }
    let ifindex = u32_at(h, 4);
    if ifindex != 0 && dev::by_index(ifindex).is_none() {
        return Err(Errno::EINVAL);
    }
    let addr = a.addr6(IFAL_ADDRESS).map_err(|_| Errno::EINVAL)?.ok_or(Errno::EINVAL)?;
    let m = {
        let t = TABLE.get().lock();
        let e = t.lookup(&addr, ifindex).ok_or(Errno::ESRCH)?;
        fill(e, t.seq, req.portid, req.hdr.seq, 0)
    };
    req.reply(m);
    Ok(())
}

/// The dump of `RTM_GETADDRLABEL`, as `ip6addrlbl_dump` of Linux.
fn dump(req: &Request<'_>) -> Result<Vec<Vec<u8>>> {
    if req.strict {
        let p = req.payload();
        let h = p.get(..IFAL_LEN).ok_or_else(|| {
            req.error("Invalid header for address label dump request", Errno::EINVAL)
        })?;
        if h[1..4] != [0; 3] || u32_at(h, 4) != 0 || u32_at(h, 8) != 0 {
            return Err(
                req.error("Invalid values in header for address label dump request", Errno::EINVAL)
            );
        }
        if p.len() > IFAL_LEN {
            let text = "Invalid data after header for address label dump request";
            return Err(req.error(text, Errno::EINVAL));
        }
    }
    let t = TABLE.get().lock();
    Ok(t.list.iter().map(|e| fill(e, t.seq, req.portid, req.hdr.seq, NLM_F_MULTI)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(head: &[u8]) -> [u8; 16] {
        prefix(head)
    }

    #[test]
    fn the_default_policy_is_the_one_of_linux() {
        let t = Table::new();
        let got: Vec<_> = t.list.iter().map(|e| (e.prefixlen, e.label)).collect();
        // A longer prefix comes first, and for one length a later entry comes first.
        assert_eq!(
            got,
            [
                (128, 0),
                (96, 3),
                (96, 4),
                (32, 6),
                (28, 7),
                (16, 12),
                (16, 2),
                (10, 11),
                (7, 5),
                (0, 1)
            ]
        );
        assert_eq!(t.seq, 10);
        let label = |x: [u8; 16]| t.lookup(&x, 0).map(|e| e.label);
        // As on Linux, the address :: takes the entry ::/96.
        assert_eq!(label([0; 16]), Some(3));
        let mut lo = [0; 16];
        lo[15] = 1;
        assert_eq!(label(lo), Some(0));
        assert_eq!(label(a(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1])), Some(4));
        assert_eq!(label(a(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1])), Some(3));
        assert_eq!(label(a(&[0x20, 0x01, 0, 0, 0x12])), Some(6));
        assert_eq!(label(a(&[0x20, 0x01, 0x0d, 0xb8])), Some(1));
        assert_eq!(label(a(&[0x20, 0x01, 0x00, 0x10])), Some(7));
        assert_eq!(label(a(&[0xfd, 0x00])), Some(5));
        assert_eq!(label(a(&[0x24, 0x00])), Some(1));
    }

    #[test]
    fn an_entry_takes_an_add_a_replace_and_a_delete() {
        let mut t = Table::new();
        let p = a(&[0x20, 0x01, 0x0d, 0xb8, 0xff]);
        // The prefix loses the bits after its length.
        t.add(p, 32, 0, 100, false).unwrap();
        let e = t.lookup(&a(&[0x20, 0x01, 0x0d, 0xb8, 1]), 0).unwrap();
        assert_eq!((e.prefix, e.label), (a(&[0x20, 0x01, 0x0d, 0xb8]), 100));
        assert_eq!(t.seq, 11);
        assert_eq!(t.add(p, 32, 0, 101, false), Err(Errno::EEXIST));
        t.add(p, 32, 0, 101, true).unwrap();
        assert_eq!(t.lookup(&p, 0).unwrap().label, 101);
        // An entry of an interface comes before an entry for all of them with the same length.
        t.add(p, 32, 3, 102, false).unwrap();
        assert_eq!(t.lookup(&p, 3).unwrap().label, 102);
        assert_eq!(t.lookup(&p, 2).unwrap().label, 101);
        t.del(p, 32, 3).unwrap();
        assert_eq!(t.del(p, 32, 3), Err(Errno::ESRCH));
        assert_eq!(t.lookup(&p, 3).unwrap().label, 101);
        // A mapped prefix longer than 96 bits is not valid.
        let mapped = a(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10]);
        assert_eq!(t.add(mapped, 104, 0, 9, false), Err(Errno::EINVAL));
    }
}

//! The table of the type enforcement rules, as security/selinux/ss/avtab.c of Linux.
//!
//! A rule has a key, the source type, the target type, the class and the kind of the rule, and
//! a value: the permissions of an `allow`, `auditallow` or `dontaudit` rule, the new type of a
//! `type_transition`, `type_member` or `type_change` rule, or the extended permissions of an
//! `allowxperm` rule. The table keeps the rules in the order of their keys, so a search is a
//! binary search. A conditional rule also has its block and its list, true or false.

use crate::policydb::{Error, Policydb, Reader};
use alloc::boxed::Box;
use alloc::vec::Vec;

/// The kinds of the rules, `AVTAB_*` of Linux.
pub mod spec {
    /// `allow`: the permissions that are allowed.
    pub const ALLOWED: u16 = 0x0001;
    /// `auditallow`: the allowed permissions that make an audit record.
    pub const AUDITALLOW: u16 = 0x0002;
    /// The complement of `dontaudit`: the denied permissions that make an audit record.
    pub const AUDITDENY: u16 = 0x0004;
    /// The rules of access vectors.
    pub const AV: u16 = ALLOWED | AUDITALLOW | AUDITDENY;
    /// `type_transition`.
    pub const TRANSITION: u16 = 0x0010;
    /// `type_member`.
    pub const MEMBER: u16 = 0x0020;
    /// `type_change`.
    pub const CHANGE: u16 = 0x0040;
    /// The rules of types.
    pub const TYPE: u16 = TRANSITION | MEMBER | CHANGE;
    /// `allowxperm`.
    pub const XPERMS_ALLOWED: u16 = 0x0100;
    /// `auditallowxperm`.
    pub const XPERMS_AUDITALLOW: u16 = 0x0200;
    /// `dontauditxperm`.
    pub const XPERMS_DONTAUDIT: u16 = 0x0400;
    /// The rules of extended permissions.
    pub const XPERMS: u16 = XPERMS_ALLOWED | XPERMS_AUDITALLOW | XPERMS_DONTAUDIT;
    /// The bit of a conditional rule that is active in the format of the file.
    pub const ENABLED: u16 = 0x8000;
    /// The bit of an active conditional rule in the old format.
    pub(crate) const ENABLED_OLD: u32 = 0x8000_0000;
}

/// The order of the values of a rule in the format before version 20, `spec_order` of Linux.
const SPEC_ORDER: [u16; 6] = [
    spec::ALLOWED,
    spec::AUDITDENY,
    spec::AUDITALLOW,
    spec::TRANSITION,
    spec::CHANGE,
    spec::MEMBER,
];

/// The kinds of the extended permissions, `AVTAB_XPERMS_*` of Linux.
pub mod xperms {
    /// The functions of one driver of `ioctl`.
    pub const IOCTLFUNCTION: u8 = 0x01;
    /// The drivers of `ioctl`.
    pub const IOCTLDRIVER: u8 = 0x02;
    /// The types of the messages of a netlink socket.
    pub const NLMSG: u8 = 0x03;
}

/// The extended permissions of a rule, `struct avtab_extended_perms` of Linux.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Xperms {
    /// The kind, [`xperms::IOCTLFUNCTION`] to [`xperms::NLMSG`].
    pub specified: u8,
    /// The driver, the high byte of the `ioctl` command.
    pub driver: u8,
    /// The 256 bits of the permissions.
    pub perms: [u32; 8],
}

/// A rule.
#[derive(Clone, Debug)]
pub struct Entry {
    /// The source type, the target type, the class and the kind, 16 bits each.
    key: u64,
    /// The permissions or the new type.
    pub data: u32,
    /// For a conditional rule, the number of the block plus 1, shifted left by 1, with the
    /// bit 0 set for the true list. For another rule, 0.
    cond: u32,
    /// The extended permissions.
    pub xperms: Option<Box<Xperms>>,
}

fn key(source: u16, target: u16, class: u16, specified: u16) -> u64 {
    (u64::from(source) << 48)
        | (u64::from(target) << 32)
        | (u64::from(class) << 16)
        | u64::from(specified)
}

impl Entry {
    /// The source type.
    pub fn source(&self) -> u16 {
        (self.key >> 48) as u16
    }

    /// The target type.
    pub fn target(&self) -> u16 {
        (self.key >> 32) as u16
    }

    /// The class.
    pub fn class(&self) -> u16 {
        (self.key >> 16) as u16
    }

    /// The kind of the rule.
    pub fn specified(&self) -> u16 {
        self.key as u16
    }

    /// The conditional block of a conditional rule.
    pub fn cond_node(&self) -> u32 {
        (self.cond >> 1).saturating_sub(1)
    }

    /// The list of a conditional rule: true or false.
    pub fn cond_list(&self) -> bool {
        self.cond & 1 != 0
    }
}

/// A table of rules, `struct avtab` of Linux.
#[derive(Clone, Debug, Default)]
pub struct Avtab {
    entries: Vec<Entry>,
}

impl Avtab {
    /// Reads the rules that are not conditional, as `avtab_read` of Linux. The table cannot be
    /// empty, and two rules cannot have one key, but for extended permissions.
    pub(crate) fn read(r: &mut Reader<'_>, p: &Policydb) -> Result<Self, Error> {
        let n = r.u32()?;
        if n == 0 {
            return Err(Error::Invalid("empty rule table"));
        }
        let mut t = Self { entries: Vec::new() };
        for _ in 0..r.count(n, 12)? {
            for (key, data, xperms) in read_item(r, p, false)? {
                t.entries.push(Entry { key, data, cond: 0, xperms });
            }
        }
        t.sort();
        let dup = t
            .entries
            .windows(2)
            .any(|w| w[0].key == w[1].key && w[0].specified() & spec::XPERMS == 0);
        if dup {
            return Err(Error::Invalid("duplicate rule"));
        }
        Ok(t)
    }

    /// Reads a list of conditional rules, as `cond_read_av_list` of Linux. The list is the
    /// true list or the false list of the block `node`.
    pub(crate) fn read_cond_list(
        &mut self,
        r: &mut Reader<'_>,
        p: &Policydb,
        node: u32,
        list: bool,
    ) -> Result<(), Error> {
        let n = r.u32()?;
        let cond = ((node + 1) << 1) | u32::from(list);
        for _ in 0..r.count(n, 12)? {
            for (key, data, xperms) in read_item(r, p, true)? {
                self.entries.push(Entry { key, data, cond, xperms });
            }
        }
        Ok(())
    }

    /// Puts the rules in the order of their keys. Rules with one key keep their order.
    pub(crate) fn sort(&mut self) {
        self.entries.sort_by_key(|e| e.key);
    }

    /// Checks the conditional rules of types, as `cond_insertf` of Linux: a rule of a type
    /// cannot have the key of a rule that is not conditional, and two rules with one key must
    /// be in the true list and the false list of one block.
    pub(crate) fn check_cond_types(&self, te: &Self) -> Result<(), Error> {
        let mut i = 0;
        while i < self.entries.len() {
            let e = &self.entries[i];
            let same = self.entries[i..].iter().take_while(|x| x.key == e.key).count();
            if e.specified() & spec::TYPE != 0 {
                if te.entries.binary_search_by_key(&e.key, |x| x.key).is_ok() {
                    return Err(Error::Invalid("conditional type rule"));
                }
                let ok = match same {
                    1 => true,
                    2 => {
                        let f = &self.entries[i + 1];
                        e.cond_node() == f.cond_node() && e.cond_list() != f.cond_list()
                    }
                    _ => false,
                };
                if !ok {
                    return Err(Error::Invalid("conditional type rule"));
                }
            }
            i += same;
        }
        Ok(())
    }

    /// The rules with the source type `s`, the target type `t` and the class `c` whose kind
    /// has a bit of `mask`, as `avtab_search_node` and `avtab_search_node_next` of Linux.
    pub fn search(&self, s: u16, t: u16, c: u16, mask: u16) -> impl Iterator<Item = &Entry> {
        let first = key(s, t, c, 0);
        let at = self.entries.partition_point(|e| e.key < first);
        self.entries[at..]
            .iter()
            .take_while(move |e| e.key >> 16 == first >> 16)
            .filter(move |e| e.specified() & mask != 0)
    }

    /// The first rule with the key `s`, `t`, `c` and `specified`.
    pub fn find(&self, s: u32, t: u32, c: u16, specified: u16) -> Option<&Entry> {
        let (Ok(s), Ok(t)) = (u16::try_from(s), u16::try_from(t)) else { return None };
        self.search(s, t, c, specified).find(|e| e.specified() == specified)
    }

    /// All the rules, in the order of their keys.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter()
    }

    /// The number of rules.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Tells if the table has no rule.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A rule that [`read_item`] reads: its key, its value and its extended permissions.
type Item = (u64, u32, Option<Box<Xperms>>);

/// Reads a rule, as `avtab_read_item` of Linux. A rule of the format before version 20 can
/// have more than one kind, and gives one rule for each kind.
fn read_item(r: &mut Reader<'_>, p: &Policydb, conditional: bool) -> Result<Vec<Item>, Error> {
    let valid = |s: u32, t: u32, c: u32| p.type_valid(s) && p.type_valid(t) && p.class_valid(c);
    if p.version < crate::policydb::version::AVTAB {
        let items = r.u32()?;
        if !(5..=8).contains(&items) {
            return Err(Error::Invalid("rule item count"));
        }
        let mut buf = [0u32; 8];
        for v in buf.iter_mut().take(items as usize) {
            *v = r.u32()?;
        }
        let [s, t, c] = [buf[0], buf[1], buf[2]].map(|v| u16::try_from(v).ok());
        let (Some(s), Some(t), Some(c)) = (s, t, c) else {
            return Err(Error::Invalid("rule key"));
        };
        if !valid(s.into(), t.into(), c.into()) {
            return Err(Error::Invalid("rule key"));
        }
        let val = buf[3];
        let enabled = if val & spec::ENABLED_OLD != 0 { spec::ENABLED } else { 0 };
        let kinds = val as u16;
        let (av, ty) = (kinds & spec::AV != 0, kinds & spec::TYPE != 0);
        if !(av || ty) || (av && ty) || kinds & spec::XPERMS != 0 {
            return Err(Error::Invalid("rule kind"));
        }
        let mut out = Vec::new();
        let mut at = 4;
        for kind in SPEC_ORDER {
            if kinds & kind == 0 {
                continue;
            }
            let data =
                *buf.get(at).filter(|_| at < items as usize).ok_or(Error::Invalid("rule items"))?;
            at += 1;
            if kind & spec::TYPE != 0 && !p.simple_type_valid(data) {
                return Err(Error::Invalid("rule type"));
            }
            out.push((key(s, t, c, kind | enabled), data, None));
        }
        if at != items as usize {
            return Err(Error::Invalid("rule items"));
        }
        return Ok(out);
    }
    let [s, t, c, specified] = r.u16s::<4>()?;
    if !valid(s.into(), t.into(), c.into()) {
        return Err(Error::Invalid("rule key"));
    }
    let kind = specified & !spec::ENABLED;
    if kind.count_ones() != 1 || kind & !(spec::AV | spec::TYPE | spec::XPERMS) != 0 {
        return Err(Error::Invalid("rule kind"));
    }
    if kind & spec::XPERMS != 0 {
        if p.version < crate::policydb::version::XPERMS_IOCTL
            || (conditional && p.version < crate::policydb::version::COND_XPERMS)
        {
            return Err(Error::Invalid("extended permissions in this version"));
        }
        let specified = r.u8()?;
        let driver = r.u8()?;
        let perms = r.u32s::<8>()?;
        let x = Box::new(Xperms { specified, driver, perms });
        return Ok(Vec::from([(key(s, t, c, kind), 0, Some(x))]));
    }
    let data = r.u32()?;
    if kind & spec::TYPE != 0 && !p.simple_type_valid(data) {
        return Err(Error::Invalid("rule type"));
    }
    Ok(Vec::from([(key(s, t, c, kind), data, None)]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(keys: &[(u16, u16, u16, u16, u32)]) -> Avtab {
        let mut t = Avtab::default();
        for &(s, tt, c, k, data) in keys {
            t.entries.push(Entry { key: key(s, tt, c, k), data, cond: 0, xperms: None });
        }
        t.sort();
        t
    }

    #[test]
    fn a_search_finds_the_rules_of_a_key() {
        let t = table(&[
            (2, 3, 4, spec::AUDITDENY, 5),
            (2, 3, 4, spec::ALLOWED, 1),
            (2, 3, 5, spec::ALLOWED, 2),
            (1, 3, 4, spec::ALLOWED, 3),
            (2, 3, 4, spec::XPERMS_ALLOWED, 7),
            (2, 3, 4, spec::XPERMS_ALLOWED, 8),
        ]);
        let av: Vec<u32> = t.search(2, 3, 4, spec::AV).map(|e| e.data).collect();
        assert_eq!(av, [1, 5]);
        let x: Vec<u32> = t.search(2, 3, 4, spec::XPERMS).map(|e| e.data).collect();
        assert_eq!(x, [7, 8]);
        assert_eq!(t.find(2, 3, 5, spec::ALLOWED).map(|e| e.data), Some(2));
        assert!(t.find(2, 3, 5, spec::AUDITDENY).is_none());
        assert!(t.find(70_000, 3, 5, spec::ALLOWED).is_none());
        let e = t.entries().next().unwrap();
        assert_eq!((e.source(), e.target(), e.class(), e.specified()), (1, 3, 4, 1));
        assert_eq!(t.len(), 6);
    }

    #[test]
    fn a_conditional_rule_has_its_block_and_list() {
        let e = Entry { key: 0, data: 0, cond: (4 << 1) | 1, xperms: None };
        assert_eq!((e.cond_node(), e.cond_list()), (3, true));
        let e = Entry { key: 0, data: 0, cond: 1 << 1, xperms: None };
        assert_eq!((e.cond_node(), e.cond_list()), (0, false));
    }
}

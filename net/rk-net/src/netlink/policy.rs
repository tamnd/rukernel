//! The policies of the attributes and their checks, as `struct nla_policy` and
//! `__nla_validate_parse` of lib/nlattr.c of Linux, and the description of a policy in the
//! extended ack, as `netlink_policy_dump_write_attr` of net/netlink/policy.c.
//!
//! A family gives a policy for each attribute type of a message. `parse` checks the attributes
//! of a request against the policy, with the same errors and messages as Linux, and gives the
//! attributes by type.

use super::Request;
use super::msg::{ATTR_HDRLEN, Attrs, Builder};
use rk_abi::Errno;
use rk_abi::native::netlink::{NLA_F_NESTED, NLA_TYPE_MASK};
use rk_vfs::inode::Result;

// The attributes of the description of a policy, `NL_POLICY_TYPE_ATTR_*` of
// <linux/netlink.h>. rk-abigen does not take this enum yet, so the values are written by hand.
/// The type of the attribute, `NL_ATTR_TYPE_*`.
const NL_POLICY_TYPE_ATTR_TYPE: u16 = 1;
/// The smallest value of an unsigned integer.
const NL_POLICY_TYPE_ATTR_MIN_VALUE_U: u16 = 4;
/// The largest value of an unsigned integer.
const NL_POLICY_TYPE_ATTR_MAX_VALUE_U: u16 = 5;
/// The smallest length of a string or of binary data.
const NL_POLICY_TYPE_ATTR_MIN_LENGTH: u16 = 6;
/// The largest length of a string or of binary data.
const NL_POLICY_TYPE_ATTR_MAX_LENGTH: u16 = 7;
/// The bits that an integer can have.
const NL_POLICY_TYPE_ATTR_MASK: u16 = 12;

/// The type of an attribute, `NLA_*` of include/net/netlink.h.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// No type: no check, or `Unsupported attribute` in the strict mode.
    Unspec,
    /// The attribute is never valid.
    Reject,
    /// A flag without data.
    Flag,
    /// An 8 bit integer.
    U8,
    /// A 16 bit integer.
    U16,
    /// A 32 bit integer.
    U32,
    /// A 64 bit integer.
    U64,
    /// An unsigned integer of 32 or 64 bits, `NLA_UINT`.
    Uint,
    /// A 16 bit integer in the network byte order.
    Be16,
    /// A 32 bit integer in the network byte order.
    Be32,
    /// A string, with or without a NUL byte at the end.
    String,
    /// A string with a NUL byte.
    NulString,
    /// Binary data.
    Binary,
    /// A nest of attributes.
    Nested,
}

/// The check of the value of an attribute, `NLA_VALIDATE_*`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    /// No check.
    None,
    /// The value is at least this.
    Min(u64),
    /// The value is at most this.
    Max(u64),
    /// The value is in this range.
    Range(u64, u64),
    /// The value has only these bits.
    Mask(u64),
}

/// The policy of one attribute type, as `struct nla_policy` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// The type.
    pub kind: Kind,
    /// The length: the largest length of a string or of binary data, the smallest length of
    /// an attribute without a type, or the largest type of a nest.
    pub len: u16,
    /// The check of the value.
    pub check: Check,
    /// The policy of the attributes in a nest.
    pub nested: Option<&'static [Policy]>,
    /// The message of an attribute of the type `Reject`.
    pub reject: Option<&'static str>,
}

impl Policy {
    /// The policy of a type that the family does not take.
    pub const NONE: Self = Self::of(Kind::Unspec);

    /// A policy of the type `kind` without a check.
    pub const fn of(kind: Kind) -> Self {
        Self { kind, len: 0, check: Check::None, nested: None, reject: None }
    }

    /// Sets the length.
    pub const fn len(mut self, len: u16) -> Self {
        self.len = len;
        self
    }

    /// Sets the check of the value.
    pub const fn check(mut self, check: Check) -> Self {
        self.check = check;
        self
    }

    /// A nest with the policy `p` for its attributes.
    pub const fn nest(p: &'static [Policy]) -> Self {
        let mut s = Self::of(Kind::Nested);
        s.len = (p.len() - 1) as u16;
        s.nested = Some(p);
        s
    }

    /// The exact length of a fixed size type, `nla_attr_len` of Linux.
    const fn exact(&self) -> usize {
        match self.kind {
            Kind::U8 => 1,
            Kind::U16 | Kind::Be16 => 2,
            Kind::U32 | Kind::Be32 => 4,
            Kind::U64 => 8,
            _ => 0,
        }
    }

    /// The largest value of an integer type, for the range of the description.
    const fn type_max(&self) -> u64 {
        match self.kind {
            Kind::U8 => u8::MAX as u64,
            Kind::U16 | Kind::Be16 => u16::MAX as u64,
            Kind::U32 | Kind::Be32 => u32::MAX as u64,
            _ => u64::MAX,
        }
    }

    /// The range of the value, as `nla_get_range_unsigned` of Linux.
    fn range(&self) -> (u64, u64) {
        let max = match self.kind {
            Kind::String | Kind::NulString | Kind::Binary => u64::from(u16::MAX),
            _ => self.type_max(),
        };
        match self.check {
            Check::Min(m) => (m, max),
            Check::Max(m) => (0, m),
            Check::Range(a, b) => (a, b),
            _ => (0, max),
        }
    }

    /// Adds the description of the policy as the nest `ty`, as `netlink_policy_dump_write_attr`
    /// of Linux. A type without a description adds nothing.
    pub fn describe(&self, b: &mut Builder, ty: u16) {
        // `NL_ATTR_TYPE_*` of <linux/netlink.h>.
        let kind: u32 = match self.kind {
            Kind::Flag => 1,
            Kind::U8 => 2,
            Kind::U16 => 3,
            Kind::U32 => 4,
            Kind::U64 => 5,
            Kind::Uint => 17,
            Kind::Binary => 10,
            Kind::String => 11,
            Kind::NulString => 12,
            Kind::Nested => 13,
            Kind::Unspec | Kind::Reject | Kind::Be16 | Kind::Be32 => return,
        };
        let at = b.nest(ty | NLA_F_NESTED as u16);
        match self.kind {
            Kind::U8 | Kind::U16 | Kind::U32 | Kind::U64 | Kind::Uint => {
                if let Check::Mask(m) = self.check {
                    b.put(NL_POLICY_TYPE_ATTR_MASK, &m.to_ne_bytes());
                } else {
                    let (min, max) = self.range();
                    b.put(NL_POLICY_TYPE_ATTR_MIN_VALUE_U, &min.to_ne_bytes());
                    b.put(NL_POLICY_TYPE_ATTR_MAX_VALUE_U, &max.to_ne_bytes());
                }
            }
            Kind::String | Kind::NulString | Kind::Binary => {
                if matches!(self.check, Check::Range(..) | Check::Min(_) | Check::Max(_)) {
                    let (min, max) = self.range();
                    if min != 0 {
                        b.u32(NL_POLICY_TYPE_ATTR_MIN_LENGTH, min as u32);
                    }
                    if max < u64::from(u16::MAX) {
                        b.u32(NL_POLICY_TYPE_ATTR_MAX_LENGTH, max as u32);
                    }
                } else if self.len != 0 {
                    b.u32(NL_POLICY_TYPE_ATTR_MAX_LENGTH, u32::from(self.len));
                }
            }
            _ => {}
        }
        b.u32(NL_POLICY_TYPE_ATTR_TYPE, kind);
        b.end_nest(at);
    }
}

/// The attribute types above the largest type of the policy are an error.
pub const MAXTYPE: u32 = 1;
/// Bytes after the last attribute are an error.
pub const TRAILING: u32 = 2;
/// An attribute of the type `Unspec` is an error.
pub const UNSPEC: u32 = 4;
/// An integer must have the exact length of its type.
pub const STRICT_ATTRS: u32 = 8;
/// A nest must have `NLA_F_NESTED`, and another attribute must not have it.
pub const NESTED: u32 = 16;
/// All of the strict checks, `NL_VALIDATE_STRICT` of Linux.
pub const STRICT: u32 = MAXTYPE | TRAILING | UNSPEC | STRICT_ATTRS | NESTED;
/// The old checks of `nlmsg_parse_deprecated`.
pub const LIBERAL: u32 = 0;

/// The value of an integer attribute, in the byte order of the machine.
fn value(kind: Kind, d: &[u8]) -> u64 {
    match (kind, d.len()) {
        (Kind::U8, _) => u64::from(d[0]),
        (Kind::U16, _) => u64::from(u16::from_ne_bytes([d[0], d[1]])),
        (Kind::Be16, _) => u64::from(u16::from_be_bytes([d[0], d[1]])),
        (Kind::Be32, _) => u64::from(u32::from_be_bytes([d[0], d[1], d[2], d[3]])),
        (Kind::U64, _) | (Kind::Uint, 8) => {
            u64::from_ne_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
        }
        _ => u64::from(u32::from_ne_bytes([d[0], d[1], d[2], d[3]])),
    }
}

/// Checks the attribute with the type field `raw` and the data `d`, as `validate_nla` of Linux.
fn validate_one(
    req: &Request<'_>,
    raw: u16,
    d: &[u8],
    policy: &'static [Policy],
    flags: u32,
) -> Result<()> {
    let ty = usize::from(raw & NLA_TYPE_MASK as u16);
    let Some(pt) = policy.get(ty).filter(|_| ty != 0) else {
        return Ok(());
    };
    let pol_err = |text: &'static str, e: Errno| req.policy_error(text, d, pt, e);
    let exact = pt.exact();
    if exact != 0 && d.len() != exact && flags & STRICT_ATTRS != 0 {
        return Err(pol_err("invalid attribute length", Errno::EINVAL));
    }
    let nested = u32::from(raw) & NLA_F_NESTED != 0;
    if flags & NESTED != 0 {
        if pt.kind == Kind::Nested && !nested {
            return Err(pol_err("NLA_F_NESTED is missing", Errno::EINVAL));
        }
        if pt.kind != Kind::Nested && pt.kind != Kind::Unspec && nested {
            return Err(pol_err("NLA_F_NESTED not expected", Errno::EINVAL));
        }
    }
    let failed = |e: Errno| pol_err("Attribute failed policy validation", e);
    match pt.kind {
        Kind::Reject => {
            return Err(match pt.reject {
                Some(m) => req.attr_error(m, d, Errno::EINVAL),
                None => failed(Errno::EINVAL),
            });
        }
        Kind::Flag => {
            if !d.is_empty() {
                return Err(failed(Errno::ERANGE));
            }
        }
        Kind::Uint => {
            if d.len() != 4 && d.len() != 8 {
                return Err(pol_err("invalid attribute length", Errno::EINVAL));
            }
        }
        Kind::String => {
            if d.is_empty() {
                return Err(failed(Errno::ERANGE));
            }
            let len = if d[d.len() - 1] == 0 { d.len() - 1 } else { d.len() };
            if pt.len != 0 && len > usize::from(pt.len) {
                return Err(failed(Errno::ERANGE));
            }
        }
        Kind::NulString => {
            let n = if pt.len != 0 { d.len().min(usize::from(pt.len) + 1) } else { d.len() };
            if n == 0 || !d[..n].contains(&0) {
                return Err(failed(Errno::EINVAL));
            }
        }
        Kind::Binary => {
            if pt.len != 0 && d.len() > usize::from(pt.len) {
                return Err(failed(Errno::ERANGE));
            }
        }
        Kind::Nested => {
            if d.is_empty() {
                return Ok(());
            }
            if d.len() < ATTR_HDRLEN {
                return Err(failed(Errno::ERANGE));
            }
            if let Some(np) = pt.nested {
                validate(req, d, np, flags)?;
            }
        }
        Kind::Unspec => {
            if flags & UNSPEC != 0 {
                return Err(req.attr_error("Unsupported attribute", d, Errno::EINVAL));
            }
            if d.len() < usize::from(pt.len) {
                return Err(failed(Errno::ERANGE));
            }
        }
        _ => {
            let min = if pt.len != 0 { usize::from(pt.len) } else { exact };
            if d.len() < min {
                return Err(failed(Errno::ERANGE));
            }
        }
    }
    let int = matches!(
        pt.kind,
        Kind::U8 | Kind::U16 | Kind::U32 | Kind::U64 | Kind::Uint | Kind::Be16 | Kind::Be32
    );
    match pt.check {
        Check::None => {}
        Check::Mask(m) => {
            if int && value(pt.kind, d) & !m != 0 {
                return Err(pol_err("reserved bit set", Errno::EINVAL));
            }
        }
        _ => {
            let (min, max) = pt.range();
            let v = if int { value(pt.kind, d) } else { d.len() as u64 };
            if v < min || v > max {
                let text = if pt.kind == Kind::Binary {
                    "binary attribute size out of range"
                } else {
                    "integer out of range"
                };
                return Err(pol_err(text, Errno::ERANGE));
            }
        }
    }
    Ok(())
}

/// Checks the attributes in `b` against `policy`, as `__nla_validate_parse` of Linux. `b`
/// must be a part of the message of `req`, for the offset of a bad attribute. `flags` is
/// `STRICT`, `LIBERAL` or other bits.
///
/// # Errors
///
/// Gives the error of the first bad attribute, and sets the extended ack.
pub fn validate(req: &Request<'_>, b: &[u8], policy: &'static [Policy], flags: u32) -> Result<()> {
    let maxtype = policy.len().saturating_sub(1);
    let mut rest = b;
    while rest.len() >= ATTR_HDRLEN {
        let len = usize::from(u16::from_ne_bytes([rest[0], rest[1]]));
        if len < ATTR_HDRLEN || len > rest.len() {
            break;
        }
        let raw = u16::from_ne_bytes([rest[2], rest[3]]);
        let d = &rest[ATTR_HDRLEN..len];
        let ty = usize::from(raw & NLA_TYPE_MASK as u16);
        if ty == 0 || ty > maxtype {
            if flags & MAXTYPE != 0 {
                return Err(req.attr_error("Unknown attribute type", d, Errno::EINVAL));
            }
        } else {
            validate_one(req, raw, d, policy, flags)?;
        }
        rest = &rest[super::msg::align(len).min(rest.len())..];
    }
    if !rest.is_empty() && flags & TRAILING != 0 {
        return Err(req.error("bytes leftover after parsing attributes", Errno::EINVAL));
    }
    Ok(())
}

/// Checks and parses the attributes of `req` after its fixed header of `hdrlen` bytes, as
/// `nlmsg_parse` (with `STRICT`) or `nlmsg_parse_deprecated` (with `LIBERAL`) of Linux.
///
/// # Errors
///
/// Gives `EINVAL` for a message shorter than the fixed header, and the errors of `validate`.
pub fn parse<'a>(
    req: &'a Request<'a>,
    hdrlen: usize,
    policy: &'static [Policy],
    flags: u32,
) -> Result<(&'a [u8], Attrs<'a>)> {
    let p = req.payload();
    if p.len() < hdrlen {
        return Err(req.error("Invalid header length", Errno::EINVAL));
    }
    let b = &p[super::msg::align(hdrlen).min(p.len())..];
    validate(req, b, policy, flags)?;
    Ok((&p[..hdrlen], Attrs::parse(b, (policy.len() - 1) as u16)))
}

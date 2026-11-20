//! The decisions of the policy, as security/selinux/ss/services.c of Linux.
//!
//! The policy gives a decision for two contexts and a class: the permissions that are allowed
//! and the permissions that make an audit record. It also gives the context of a new object or
//! of a process after an exec. The kernel uses its own values for the classes and the
//! permissions, and a map from each load of a policy turns them into the values of the policy.

use crate::avtab::{Entry, Xperms, spec, xperms};
use crate::classmap::{self, CLASSES};
use crate::policydb::{
    ConstraintExpr, Context, Level, OBJECT_R_VAL, Policydb, Range, cexpr, default,
};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// A decision, `struct av_decision` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AvDecision {
    /// The permissions that are allowed.
    pub allowed: u32,
    /// The allowed permissions that make an audit record.
    pub auditallow: u32,
    /// The denied permissions that make an audit record.
    pub auditdeny: u32,
    /// The number of the policy load that gave the decision.
    pub seqno: u32,
    /// [`PERMISSIVE`] and [`NEVERAUDIT`].
    pub flags: u32,
}

/// The flag of a decision for a permissive domain, `AVD_FLAGS_PERMISSIVE` of Linux.
pub const PERMISSIVE: u32 = 1;

/// The flag of a decision for a domain that makes no audit records, `AVD_FLAGS_NEVERAUDIT`.
pub const NEVERAUDIT: u32 = 2;

impl AvDecision {
    /// A decision that allows nothing and audits each denial, as `avd_init` of Linux.
    pub const fn new(seqno: u32) -> Self {
        Self { allowed: 0, auditallow: 0, auditdeny: u32::MAX, seqno, flags: 0 }
    }
}

/// The base permissions of the extended permissions, `AVC_EXT_*` of Linux.
pub mod ext {
    /// `ioctl`: the driver is the high byte of the command, and the permission its low byte.
    pub const IOCTL: u8 = 1 << 0;
    /// The types of the messages of a netlink socket.
    pub const NLMSG: u8 = 1 << 1;
}

/// The kinds of the rules in an [`XpermsDecision`], `XPERMS_*` of Linux.
pub mod used {
    /// `allowxperm`.
    pub const ALLOWED: u8 = 1;
    /// `auditallowxperm`.
    pub const AUDITALLOW: u8 = 2;
    /// `dontauditxperm`.
    pub const DONTAUDIT: u8 = 4;
}

/// Tells if the bit `perm` of the 256 bits `p` is set, as `security_xperm_test` of Linux.
pub fn xperm_test(p: &[u32; 8], perm: u8) -> bool {
    p[usize::from(perm >> 5)] & (1 << (perm & 0x1f)) != 0
}

/// Sets the bit `perm` of the 256 bits `p`, as `security_xperm_set` of Linux.
pub fn xperm_set(p: &mut [u32; 8], perm: u8) {
    p[usize::from(perm >> 5)] |= 1 << (perm & 0x1f);
}

/// The drivers that have rules of extended permissions for two contexts and a class, as
/// `struct extended_perms` of Linux. A check of an extended permission on a driver that is not
/// in `drivers` is a denial.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExtendedPerms {
    /// The base permissions of the rules, the bits of [`ext`].
    pub base_perms: u8,
    /// True if a rule of extended permissions is there, `len` of Linux.
    pub any: bool,
    /// The drivers, one bit for each.
    pub drivers: [u32; 8],
}

/// The extended permissions of one driver for two contexts and a class, as
/// `struct extended_perms_decision` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XpermsDecision {
    /// The driver.
    pub driver: u8,
    /// The base permission, a bit of [`ext`].
    pub base_perm: u8,
    /// The kinds of the rules that the policy has for the driver, the bits of [`used`].
    pub used: u8,
    /// The allowed permissions.
    pub allowed: [u32; 8],
    /// The permissions that make an audit record when they are allowed.
    pub auditallow: [u32; 8],
    /// The permissions that make no audit record when they are denied.
    pub dontaudit: [u32; 8],
}

impl XpermsDecision {
    /// A decision for `driver` without rules.
    pub const fn new(driver: u8, base_perm: u8) -> Self {
        Self { driver, base_perm, used: 0, allowed: [0; 8], auditallow: [0; 8], dontaudit: [0; 8] }
    }

    /// Tells if the policy has a rule of the kind `which` for the permission `perm`, as
    /// `avc_xperms_has_perm` of Linux.
    pub fn has(&self, perm: u8, which: u8) -> bool {
        let bits = match which {
            used::ALLOWED => &self.allowed,
            used::AUDITALLOW => &self.auditallow,
            _ => &self.dontaudit,
        };
        self.used & which != 0 && xperm_test(bits, perm)
    }
}

/// Adds the driver of the rule `x` of extended permissions to `xp`, as
/// `services_compute_xperms_drivers` of Linux.
fn compute_xperms_drivers(xp: &mut ExtendedPerms, x: &Xperms) {
    match x.specified {
        xperms::IOCTLDRIVER => {
            xp.base_perms |= ext::IOCTL;
            for (d, p) in xp.drivers.iter_mut().zip(x.perms) {
                *d |= p;
            }
        }
        xperms::IOCTLFUNCTION => {
            xp.base_perms |= ext::IOCTL;
            xperm_set(&mut xp.drivers, x.driver);
        }
        xperms::NLMSG => {
            xp.base_perms |= ext::NLMSG;
            xperm_set(&mut xp.drivers, x.driver);
        }
        _ => {}
    }
    xp.any = true;
}

/// Adds the rule `e` of extended permissions to `xpd` if it is for the driver and the base
/// permission of `xpd`, as `services_compute_xperms_decision` of Linux.
fn compute_xperms_decision(xpd: &mut XpermsDecision, e: &Entry) {
    let Some(x) = e.xperms.as_deref() else { return };
    let base = match x.specified {
        xperms::IOCTLFUNCTION => ext::IOCTL,
        xperms::NLMSG => ext::NLMSG,
        xperms::IOCTLDRIVER => {
            if xpd.base_perm != ext::IOCTL || !xperm_test(&x.perms, xpd.driver) {
                return;
            }
            ext::IOCTL
        }
        _ => return,
    };
    if xpd.base_perm != base || (x.specified != xperms::IOCTLDRIVER && xpd.driver != x.driver) {
        return;
    }
    let (which, bits) = match e.specified() & spec::XPERMS {
        spec::XPERMS_ALLOWED => (used::ALLOWED, &mut xpd.allowed),
        spec::XPERMS_AUDITALLOW => (used::AUDITALLOW, &mut xpd.auditallow),
        spec::XPERMS_DONTAUDIT => (used::DONTAUDIT, &mut xpd.dontaudit),
        _ => return,
    };
    xpd.used |= which;
    if x.specified == xperms::IOCTLDRIVER {
        *bits = [u32::MAX; 8];
    } else {
        for (b, p) in bits.iter_mut().zip(x.perms) {
            *b |= p;
        }
    }
}

/// The type of the audit records of the errors of SELinux, `AUDIT_SELINUX_ERR` of Linux.
const SELINUX_ERR: u16 = 1401;

/// Sends an audit record of the type `SELINUX_ERR`.
pub(crate) fn log_err(text: &str) {
    rk_net::netlink::audit::log_lsm(SELINUX_ERR, text);
}

/// Compares two values with the operator `op` of a constraint.
fn compare(op: u32, a: u32, b: u32) -> bool {
    match op {
        cexpr::EQ => a == b,
        cexpr::NEQ => a != b,
        _ => false,
    }
}

/// Compares two levels with the operator `op` of a constraint.
fn compare_levels(op: u32, l1: &Level, l2: &Level) -> bool {
    match op {
        cexpr::EQ => l1 == l2,
        cexpr::NEQ => l1 != l2,
        cexpr::DOM => l1.dom(l2),
        cexpr::DOMBY => l2.dom(l1),
        cexpr::INCOMP => !l1.dom(l2) && !l2.dom(l1),
        _ => false,
    }
}

/// The low level of a range as a range of one level.
fn low(range: &Range) -> Range {
    Range { low: range.low.clone(), high: range.low.clone() }
}

/// The high level of a range as a range of one level.
fn high(range: &Range) -> Range {
    Range { low: range.high.clone(), high: range.high.clone() }
}

/// The greatest lower bound of two ranges, as `mls_context_glblub` of Linux. Two ranges with
/// no common sensitivity have no bound.
fn glblub(r1: &Range, r2: &Range) -> Option<Range> {
    if r1.high.sens < r2.low.sens || r2.high.sens < r1.low.sens {
        return None;
    }
    Some(Range {
        low: Level { sens: r1.low.sens.max(r2.low.sens), cats: r1.low.cats.and(&r2.low.cats) },
        high: Level { sens: r1.high.sens.min(r2.high.sens), cats: r1.high.cats.and(&r2.high.cats) },
    })
}

impl Policydb {
    /// Evaluates a constraint expression for the source context `s`, the target context `t`
    /// and, for a `validatetrans` rule, the old context `x`, as `constraint_expr_eval` of
    /// Linux.
    pub fn constraint_eval(
        &self,
        s: &Context,
        t: &Context,
        x: Option<&Context>,
        expr: &[ConstraintExpr],
    ) -> bool {
        let depth = cexpr::MAXDEPTH as usize;
        let mut stack: Vec<bool> = Vec::with_capacity(depth);
        for e in expr {
            let v = match e.kind {
                cexpr::NOT | cexpr::AND | cexpr::OR => {
                    let Some(a) = stack.pop() else { return false };
                    if e.kind == cexpr::NOT {
                        !a
                    } else {
                        let Some(b) = stack.pop() else { return false };
                        if e.kind == cexpr::AND { a && b } else { a || b }
                    }
                }
                _ if stack.len() == depth => return false,
                cexpr::ATTR => match e.attr {
                    cexpr::USER => compare(e.op, s.user, t.user),
                    cexpr::TYPE => compare(e.op, s.ty, t.ty),
                    cexpr::ROLE => {
                        let dom = |a: u32, b: u32| {
                            self.role(a).is_some_and(|r| r.dominates.get(b.wrapping_sub(1)))
                        };
                        match e.op {
                            cexpr::DOM => dom(s.role, t.role),
                            cexpr::DOMBY => dom(t.role, s.role),
                            cexpr::INCOMP => !dom(s.role, t.role) && !dom(t.role, s.role),
                            op => compare(op, s.role, t.role),
                        }
                    }
                    cexpr::L1L2 => compare_levels(e.op, &s.range.low, &t.range.low),
                    cexpr::L1H2 => compare_levels(e.op, &s.range.low, &t.range.high),
                    cexpr::H1L2 => compare_levels(e.op, &s.range.high, &t.range.low),
                    cexpr::H1H2 => compare_levels(e.op, &s.range.high, &t.range.high),
                    cexpr::L1H1 => compare_levels(e.op, &s.range.low, &s.range.high),
                    cexpr::L2H2 => compare_levels(e.op, &t.range.low, &t.range.high),
                    _ => return false,
                },
                cexpr::NAMES => {
                    let c = if e.attr & cexpr::TARGET != 0 {
                        t
                    } else if e.attr & cexpr::XTARGET != 0 {
                        let Some(x) = x else { return false };
                        x
                    } else {
                        s
                    };
                    let v = if e.attr & cexpr::USER != 0 {
                        c.user
                    } else if e.attr & cexpr::ROLE != 0 {
                        c.role
                    } else if e.attr & cexpr::TYPE != 0 {
                        c.ty
                    } else {
                        return false;
                    };
                    let has = e.names.get(v.wrapping_sub(1));
                    match e.op {
                        cexpr::EQ => has,
                        cexpr::NEQ => !has,
                        _ => return false,
                    }
                }
                _ => return false,
            };
            stack.push(v);
        }
        stack.len() == 1 && stack[0]
    }

    /// Computes the decision of the policy for the contexts `s` and `t` and the class `tclass`
    /// of the policy, as `context_struct_compute_av` of Linux.
    pub fn context_compute_av(&self, s: &Context, t: &Context, tclass: u32) -> AvDecision {
        self.context_compute_av_xperms(s, t, tclass, None)
    }

    /// Computes the decision as [`Self::context_compute_av`], and adds the drivers of the rules
    /// of extended permissions to `xp`, as `context_struct_compute_av` of Linux with `xperms`.
    pub fn context_compute_av_xperms(
        &self,
        s: &Context,
        t: &Context,
        tclass: u32,
        mut xp: Option<&mut ExtendedPerms>,
    ) -> AvDecision {
        let mut avd = AvDecision::new(0);
        let mask = if xp.is_some() { spec::AV | spec::XPERMS } else { spec::AV };
        let (Some(class), Ok(c)) = (self.class(tclass), u16::try_from(tclass)) else {
            rk_frame::println!("SELinux:  Invalid class {tclass}");
            return avd;
        };
        let attrs = |ty: u32| ty.checked_sub(1).and_then(|i| self.type_attr_map.get(i as usize));
        let (Some(sattr), Some(tattr)) = (attrs(s.ty), attrs(t.ty)) else { return avd };
        for i in sattr.iter() {
            for j in tattr.iter() {
                let (Ok(si), Ok(tj)) = (u16::try_from(i + 1), u16::try_from(j + 1)) else {
                    continue;
                };
                for e in self.te.search(si, tj, c, mask) {
                    match e.specified() {
                        spec::ALLOWED => avd.allowed |= e.data,
                        spec::AUDITALLOW => avd.auditallow |= e.data,
                        spec::AUDITDENY => avd.auditdeny &= e.data,
                        _ => {
                            if let (Some(xp), Some(x)) = (xp.as_deref_mut(), e.xperms.as_deref()) {
                                compute_xperms_drivers(xp, x);
                            }
                        }
                    }
                }
                let active = |e: &&Entry| self.cond_active(e.cond_node(), e.cond_list());
                for e in self.te_cond.search(si, tj, c, mask).filter(active) {
                    if e.specified() & spec::ALLOWED != 0 {
                        avd.allowed |= e.data;
                    }
                    if e.specified() & spec::AUDITDENY != 0 {
                        avd.auditdeny &= e.data;
                    }
                    if e.specified() & spec::AUDITALLOW != 0 {
                        avd.auditallow |= e.data;
                    }
                    if let (Some(xp), Some(x)) = (xp.as_deref_mut(), e.xperms.as_deref()) {
                        compute_xperms_drivers(xp, x);
                    }
                }
            }
        }
        for con in &class.constraints {
            if con.perms & avd.allowed != 0 && !self.constraint_eval(s, t, None, &con.expr) {
                avd.allowed &= !con.perms;
            }
        }
        if tclass == self.process_class
            && avd.allowed & self.process_trans_perms != 0
            && s.role != t.role
            && !self.role_allow.contains(&(s.role, t.role))
        {
            avd.allowed &= !self.process_trans_perms;
        }
        self.bounds_av(s, t, tclass, &mut avd);
        avd
    }

    /// Computes the extended permissions of the driver and the base permission of `xpd` for
    /// the contexts `s` and `t` and the class `tclass` of the policy, as the loop of
    /// `security_compute_xperms_decision` of Linux.
    pub fn context_compute_xperms(
        &self,
        s: &Context,
        t: &Context,
        tclass: u32,
        xpd: &mut XpermsDecision,
    ) {
        let Ok(c) = u16::try_from(tclass) else { return };
        let attrs = |ty: u32| ty.checked_sub(1).and_then(|i| self.type_attr_map.get(i as usize));
        let (Some(sattr), Some(tattr)) = (attrs(s.ty), attrs(t.ty)) else { return };
        for i in sattr.iter() {
            for j in tattr.iter() {
                let (Ok(si), Ok(tj)) = (u16::try_from(i + 1), u16::try_from(j + 1)) else {
                    continue;
                };
                for e in self.te.search(si, tj, c, spec::XPERMS) {
                    compute_xperms_decision(xpd, e);
                }
                let active = |e: &&Entry| self.cond_active(e.cond_node(), e.cond_list());
                for e in self.te_cond.search(si, tj, c, spec::XPERMS).filter(active) {
                    compute_xperms_decision(xpd, e);
                }
            }
        }
    }

    /// Removes the permissions that the bounds of the source type do not allow, as
    /// `type_attribute_bounds_av` of Linux, and makes an audit record for them.
    fn bounds_av(&self, s: &Context, t: &Context, tclass: u32, avd: &mut AvDecision) {
        let Some(source) = self.ty(s.ty).filter(|ty| ty.bounds != 0) else { return };
        let lo_s = Context { ty: source.bounds, ..s.clone() };
        let lo_t = match self.ty(t.ty).filter(|ty| ty.bounds != 0) {
            Some(target) => Context { ty: target.bounds, ..t.clone() },
            None => t.clone(),
        };
        let lo = self.context_compute_av(&lo_s, &lo_t, tclass);
        let masked = !lo.allowed & avd.allowed;
        if masked == 0 {
            return;
        }
        avd.allowed &= !masked;
        self.dump_masked_av(s, t, tclass, masked, "bounds");
    }

    /// Makes the audit record of the permissions that a rule removed, as
    /// `security_dump_masked_av` of Linux.
    fn dump_masked_av(&self, s: &Context, t: &Context, tclass: u32, perms: u32, reason: &str) {
        let mut names = String::new();
        for i in (0..32).filter(|i| perms & (1 << i) != 0) {
            if !names.is_empty() {
                names.push(',');
            }
            let name = self.perms(tclass).find(|p| p.value == i + 1);
            names.push_str(name.map_or("????", |p| p.name.as_str()));
        }
        log_err(&format!(
            "op=security_compute_av reason={reason} scontext={} tcontext={} tclass={} perms={names}",
            self.context_to_string(s),
            self.context_to_string(t),
            self.name(crate::policydb::sym::CLASSES, tclass).unwrap_or_default(),
        ));
    }

    /// Computes the context of a new object or of a process after an exec, as
    /// `security_compute_sid` of Linux. `specified` is a kind of type rule, `tclass` is a class
    /// of the policy, `name` is the name of a new file and `sock` tells if the class is a
    /// class of sockets. The new context can be not valid. A range that the policy cannot
    /// compute gives `None`.
    pub fn context_compute_sid(
        &self,
        s: &Context,
        t: &Context,
        tclass: u32,
        specified: u16,
        name: Option<&[u8]>,
        sock: bool,
    ) -> Option<Context> {
        let class = self.class(tclass);
        let process = tclass == self.process_class || sock;
        let user = match specified {
            spec::MEMBER => t.user,
            _ if class.is_some_and(|c| c.default_user == default::TARGET) => t.user,
            _ => s.user,
        };
        let role = match class.map(|c| c.default_role) {
            Some(default::SOURCE) => s.role,
            Some(default::TARGET) => t.role,
            _ if process => s.role,
            _ => OBJECT_R_VAL,
        };
        let rule = u16::try_from(tclass).ok().and_then(|c| {
            let (Ok(st), Ok(tt)) = (u16::try_from(s.ty), u16::try_from(t.ty)) else {
                return None;
            };
            self.te.search(st, tt, c, specified).next().or_else(|| {
                self.te_cond
                    .search(st, tt, c, specified)
                    .find(|e| self.cond_active(e.cond_node(), e.cond_list()))
            })
        });
        let ty = match (rule, class.map(|c| c.default_type)) {
            (Some(rule), _) => rule.data,
            (None, Some(default::SOURCE)) => s.ty,
            (None, Some(default::TARGET)) => t.ty,
            _ if process => s.ty,
            _ => t.ty,
        };
        let mut new = Context { user, role, ty, range: Range::default() };
        if let Some(name) = name.and_then(|n| core::str::from_utf8(n).ok()) {
            let key = (t.ty, tclass, String::from(name));
            if let Some(rules) = self.filename_tr.get(&key)
                && let Some(&(_, otype)) = rules.iter().find(|r| r.0.get(s.ty - 1))
            {
                new.ty = otype;
            }
        }
        if specified & spec::TRANSITION != 0
            && let Some(&r) = self.role_tr.get(&(s.role, t.ty, tclass))
        {
            new.role = r;
        }
        if self.mls {
            new.range = self.compute_range(s, t, tclass, specified, sock)?;
        }
        Some(new)
    }

    /// Computes the range of a new context, as `mls_compute_sid` of Linux.
    fn compute_range(
        &self,
        s: &Context,
        t: &Context,
        tclass: u32,
        specified: u16,
        sock: bool,
    ) -> Option<Range> {
        if specified == spec::TRANSITION {
            if let Some(r) = self.range_tr.get(&(s.ty, t.ty, tclass)) {
                return Some(r.clone());
            }
            match self.class(tclass).map_or(0, |c| c.default_range) {
                default::SOURCE_LOW => return Some(low(&s.range)),
                default::SOURCE_HIGH => return Some(high(&s.range)),
                default::SOURCE_LOW_HIGH => return Some(s.range.clone()),
                default::TARGET_LOW => return Some(low(&t.range)),
                default::TARGET_HIGH => return Some(high(&t.range)),
                default::TARGET_LOW_HIGH => return Some(t.range.clone()),
                default::GLBLUB => return glblub(&s.range, &t.range),
                _ => {}
            }
        }
        match specified {
            spec::TRANSITION | spec::CHANGE if tclass == self.process_class || sock => {
                Some(s.range.clone())
            }
            spec::TRANSITION | spec::CHANGE | spec::MEMBER => Some(low(&s.range)),
            _ => None,
        }
    }
}

/// The values in the policy of a class of the kernel and of its permissions,
/// `struct selinux_mapping` of Linux. A class or a permission that is not in the policy has
/// the value 0.
#[derive(Clone, Debug, Default)]
pub struct Mapping {
    /// The value of the class in the policy.
    pub value: u32,
    /// The bit in the policy of each permission of the kernel.
    pub perms: Vec<u32>,
}

/// Makes the map of the classes and the permissions of the kernel to those of the policy, as
/// `selinux_set_mapping` of Linux. The map has an empty item for the class 0. With
/// `reject_unknown`, a class or a permission that is not in the policy stops the load.
pub fn set_mapping(db: &Policydb) -> Option<Vec<Mapping>> {
    let mut map = Vec::with_capacity(CLASSES.len() + 1);
    map.push(Mapping::default());
    let mut unknown = false;
    for &(name, perms) in &CLASSES {
        let Some(value) = db.class_value(name) else {
            rk_frame::println!("SELinux:  Class {name} not defined in policy.");
            if db.reject_unknown {
                return None;
            }
            unknown = true;
            map.push(Mapping::default());
            continue;
        };
        let mut m = Mapping { value, perms: Vec::with_capacity(perms.len()) };
        for &perm in perms {
            let bit = db.perm_bit(value, perm).unwrap_or(0);
            if bit == 0 {
                rk_frame::println!(
                    "SELinux:  Permission {perm} in class {name} not defined in policy."
                );
                if db.reject_unknown {
                    return None;
                }
                unknown = true;
            }
            m.perms.push(bit);
        }
        map.push(m);
    }
    if unknown {
        let how = if db.allow_unknown { "allowed" } else { "denied" };
        rk_frame::println!("SELinux: the above unknown classes and permissions will be {how}");
    }
    Some(map)
}

/// The value in the policy of the class `tclass` of the kernel, as `unmap_class` of Linux.
pub fn unmap_class(map: &[Mapping], tclass: u16) -> u32 {
    map.get(usize::from(tclass)).map_or(u32::from(tclass), |m| m.value)
}

/// The value for the kernel of the class `value` of the policy, as `map_class` of Linux.
pub fn map_class(map: &[Mapping], value: u32) -> u16 {
    map.iter().skip(1).position(|m| m.value == value).map_or(0, |i| i as u16 + 1)
}

/// Turns the bits of a decision of the policy into the bits of the kernel, as
/// `map_decision` of Linux. A permission that is not in the policy is allowed with
/// `allow_unknown`, and audited without it.
pub fn map_decision(map: &[Mapping], tclass: u16, avd: &mut AvDecision, allow_unknown: bool) {
    let Some(m) = map.get(usize::from(tclass)) else { return };
    let (mut allowed, mut auditallow, mut auditdeny) = (0, 0, 0);
    for (i, &p) in m.perms.iter().enumerate() {
        if avd.allowed & p != 0 || (allow_unknown && p == 0) {
            allowed |= 1 << i;
        }
        if avd.auditallow & p != 0 {
            auditallow |= 1 << i;
        }
        if avd.auditdeny & p != 0 || (!allow_unknown && p == 0) {
            auditdeny |= 1 << i;
        }
    }
    // A request of a permission after the last one is a bug of the kernel, and its denial
    // makes an audit record.
    for i in m.perms.len()..32 {
        auditdeny |= 1 << i;
    }
    avd.allowed = allowed;
    avd.auditallow = auditallow;
    avd.auditdeny = auditdeny;
}

/// Tells if the class of the policy `value` is a class of sockets for the kernel.
pub fn is_socket_value(map: &[Mapping], value: u32) -> bool {
    classmap::is_socket(map_class(map, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policydb::sym;

    fn policy() -> Policydb {
        Policydb::read(include_bytes!("../tests/rk_test.33.bin")).unwrap()
    }

    fn ctx(p: &Policydb, s: &str) -> Context {
        p.string_to_context(s, None).unwrap()
    }

    fn bits(p: &Policydb, class: &str, perms: &[&str]) -> u32 {
        let c = p.class_value(class).unwrap();
        perms.iter().map(|n| p.perm_bit(c, n).unwrap()).fold(0, |a, b| a | b)
    }

    #[test]
    fn the_decisions_follow_the_rules_and_the_constraints() {
        let p = policy();
        let file = p.class_value("file").unwrap();
        let init = ctx(&p, "system_u:system_r:init_t:s0");
        let etc = ctx(&p, "system_u:object_r:etc_t:s0");
        let avd = p.context_compute_av(&init, &etc, file);
        // `write` is in no allow rule, and the constraint of `write` holds for init_t only
        // when the roles are equal.
        assert_eq!(avd.allowed, bits(&p, "file", &["read", "getattr", "open", "execute"]));
        assert_eq!(avd.auditallow, bits(&p, "file", &["write"]));
        assert_eq!(avd.auditdeny, u32::MAX);
        let proc = ctx(&p, "system_u:object_r:proc_t:s0");
        let avd = p.context_compute_av(&init, &proc, file);
        assert_eq!(avd.auditdeny, !bits(&p, "file", &["write"]));
        // The MLS constraint of `read`: init_t is in mlsfilereadtoclr.
        let high = ctx(&p, "system_u:object_r:etc_t:s1");
        let avd = p.context_compute_av(&init, &high, file);
        assert_ne!(avd.allowed & bits(&p, "file", &["read"]), 0);
        let kernel = ctx(&p, "system_u:system_r:kernel_t:s0");
        let avd = p.context_compute_av(&kernel, &high, file);
        assert_eq!(avd.allowed & bits(&p, "file", &["read"]), 0);
        assert_ne!(avd.allowed & bits(&p, "file", &["open"]), 0);
        // The conditional rules follow the booleans.
        let bin = ctx(&p, "system_u:object_r:bin_t:s0");
        let ent = bits(&p, "file", &["execute_no_trans"]);
        assert_ne!(p.context_compute_av(&init, &bin, file).allowed & ent, 0);
        let b = p.bools.iter().flatten().find(|b| b.name == "allow_exec").unwrap();
        b.state.store(false, core::sync::atomic::Ordering::Relaxed);
        p.evaluate_conds();
        let avd = p.context_compute_av(&init, &bin, file);
        assert_eq!(avd.allowed & ent, 0);
        assert_eq!(avd.auditdeny & ent, 0);
    }

    #[test]
    fn the_extended_permissions_follow_the_rules() {
        let p = policy();
        let file = p.class_value("file").unwrap();
        let kernel = ctx(&p, "system_u:system_r:kernel_t:s0");
        let etc = ctx(&p, "system_u:object_r:etc_t:s0");
        // The drivers of the rules of kernel_t and of its attribute domain.
        let mut xp = ExtendedPerms::default();
        let avd = p.context_compute_av_xperms(&kernel, &etc, file, Some(&mut xp));
        assert_ne!(avd.allowed & bits(&p, "file", &["ioctl"]), 0);
        assert!(xp.any && xp.base_perms == ext::IOCTL);
        assert!([0x12, 0x54, 0x89].iter().all(|&d| xperm_test(&xp.drivers, d)));
        assert!(!xperm_test(&xp.drivers, 0x13) && !xperm_test(&xp.drivers, 0x43));
        let decision = |driver, base| {
            let mut xpd = XpermsDecision::new(driver, base);
            p.context_compute_xperms(&kernel, &etc, file, &mut xpd);
            xpd
        };
        // A rule of functions gives its functions, and a rule of drivers gives all of them.
        let xpd = decision(0x54, ext::IOCTL);
        assert_eq!(xpd.used, used::ALLOWED);
        assert!(xpd.has(0x01, used::ALLOWED) && !xpd.has(0x02, used::ALLOWED));
        assert!(!xpd.has(0x01, used::AUDITALLOW) && !xpd.has(0x01, used::DONTAUDIT));
        assert_eq!(decision(0x12, ext::IOCTL).allowed, [u32::MAX; 8]);
        let xpd = decision(0x89, ext::IOCTL);
        assert!(xpd.has(0x10, used::ALLOWED) && !xpd.has(0x11, used::ALLOWED));
        assert!(xpd.has(0x20, used::ALLOWED) && !xpd.has(0x21, used::ALLOWED));
        // Another driver or another base permission has no rules.
        assert_eq!(decision(0x43, ext::IOCTL), XpermsDecision::new(0x43, ext::IOCTL));
        assert_eq!(decision(0x54, ext::NLMSG), XpermsDecision::new(0x54, ext::NLMSG));
        // init_t has only the rule of domain, and dir has no rules of extended permissions.
        let init = ctx(&p, "system_u:system_r:init_t:s0");
        let mut xp = ExtendedPerms::default();
        p.context_compute_av_xperms(&init, &etc, file, Some(&mut xp));
        assert!(xperm_test(&xp.drivers, 0x89) && !xperm_test(&xp.drivers, 0x54));
        let mut xp = ExtendedPerms::default();
        p.context_compute_av_xperms(&kernel, &etc, p.class_value("dir").unwrap(), Some(&mut xp));
        assert_eq!(xp, ExtendedPerms::default());
    }

    #[test]
    fn a_rule_of_drivers_adds_all_its_drivers() {
        let mut xp = ExtendedPerms::default();
        let mut x = Xperms { specified: xperms::IOCTLDRIVER, driver: 0, perms: [0; 8] };
        xperm_set(&mut x.perms, 0x12);
        xperm_set(&mut x.perms, 0xff);
        compute_xperms_drivers(&mut xp, &x);
        assert!(xp.any && xp.base_perms == ext::IOCTL);
        assert_eq!(xp.drivers, x.perms);
        let x = Xperms { specified: xperms::NLMSG, driver: 0x20, perms: [1; 8] };
        compute_xperms_drivers(&mut xp, &x);
        assert_eq!(xp.base_perms, ext::IOCTL | ext::NLMSG);
        assert!(xperm_test(&xp.drivers, 0x20) && !xperm_test(&xp.drivers, 0x00));
    }

    #[test]
    fn a_process_transition_needs_the_roles_and_the_bounds() {
        let p = policy();
        let process = p.class_value("process").unwrap();
        let tr = bits(&p, "process", &["transition"]);
        let kernel = ctx(&p, "system_u:system_r:kernel_t:s0-s1:c0.c2");
        let init = ctx(&p, "system_u:system_r:init_t:s0");
        assert_ne!(p.context_compute_av(&kernel, &init, process).allowed & tr, 0);
        // h1 dom h2 fails from s0 to s0-s1.
        let low = ctx(&p, "system_u:system_r:kernel_t:s0");
        let init_high = ctx(&p, "system_u:system_r:init_t:s0-s1");
        assert_eq!(p.context_compute_av(&low, &init_high, process).allowed & tr, 0);
        // child_t is bounded by unconfined_t, which has no rules for itself.
        let child = Context { ty: p.names[sym::TYPES]["child_t"], ..init.clone() };
        let avd = p.context_compute_av(&child, &child, process);
        assert_eq!(avd.allowed, 0);
    }

    #[test]
    fn a_new_context_follows_the_type_rules() {
        let p = policy();
        let process = p.class_value("process").unwrap();
        let file = p.class_value("file").unwrap();
        let dir = p.class_value("dir").unwrap();
        let text = |c: Option<Context>| p.context_to_string(&c.unwrap());
        let kernel = ctx(&p, "system_u:system_r:kernel_t:s0");
        let exec = ctx(&p, "system_u:object_r:init_exec_t:s0");
        let new = p.context_compute_sid(&kernel, &exec, process, spec::TRANSITION, None, false);
        assert_eq!(text(new), "system_u:user_r:init_t:s0-s1:c0.c2");
        let init = ctx(&p, "system_u:system_r:init_t:s0");
        let tmp = ctx(&p, "system_u:object_r:tmpfs_t:s1");
        let new = p.context_compute_sid(&init, &tmp, file, spec::TRANSITION, None, false);
        assert_eq!(text(new), "system_u:object_r:etc_t:s1");
        let named = Some(&b"named"[..]);
        let new = p.context_compute_sid(&init, &tmp, dir, spec::TRANSITION, named, false);
        assert_eq!(text(new), "system_u:object_r:bin_t:s0");
        let new = p.context_compute_sid(&init, &tmp, dir, spec::TRANSITION, None, false);
        assert_eq!(text(new), "system_u:object_r:tmpfs_t:s0");
        let new = p.context_compute_sid(&init, &tmp, dir, spec::MEMBER, None, false);
        assert_eq!(text(new), "system_u:object_r:tmpfs_t:s0");
        let etc = ctx(&p, "system_u:object_r:etc_t:s0");
        let new = p.context_compute_sid(&init, &etc, file, spec::CHANGE, None, false);
        assert_eq!(text(new), "system_u:object_r:bin_t:s0");
        let new = p.context_compute_sid(&init, &etc, process, spec::CHANGE, None, false);
        assert_eq!(text(new), "system_u:system_r:init_t:s0");
    }

    #[test]
    fn the_map_turns_the_values_of_the_kernel_into_the_values_of_the_policy() {
        let p = policy();
        let map = set_mapping(&p).unwrap();
        assert_eq!(map.len(), CLASSES.len() + 1);
        let file = p.class_value("file").unwrap();
        assert_eq!(unmap_class(&map, classmap::class::FILE), file);
        assert_eq!(map_class(&map, file), classmap::class::FILE);
        assert_eq!(unmap_class(&map, classmap::value("tcp_socket").unwrap()), 0);
        // `watch_mountns` is not in the policy, and the policy denies the unknown permissions.
        let m = &map[usize::from(classmap::class::FILE)];
        assert_eq!(m.perms[1], bits(&p, "file", &["read"]));
        assert_eq!(m.perms[25], 0);
        let mut avd = AvDecision::new(1);
        avd.allowed = bits(&p, "file", &["read", "execute_no_trans"]);
        avd.auditallow = bits(&p, "file", &["read"]);
        avd.auditdeny = !bits(&p, "file", &["read"]);
        map_decision(&map, classmap::class::FILE, &mut avd, false);
        assert_eq!(avd.allowed, (1 << 1) | (1 << 26));
        assert_eq!(avd.auditallow, 1 << 1);
        assert_eq!(avd.auditdeny, !(1 << 1));
        let mut avd = AvDecision::new(1);
        map_decision(&map, classmap::class::FILE, &mut avd, true);
        assert_eq!(avd.allowed, 1 << 25);
        assert_eq!(avd.auditdeny, (!0 << 28) | ((1 << 28) - 1) & !(1 << 25));
    }

    #[test]
    fn the_decisions_of_a_policy_from_an_environment_variable() {
        // The test uses a policy of a distribution, as the targeted policy of Fedora, when
        // RK_SELINUX_POLICY gives its path.
        let Ok(path) = std::env::var("RK_SELINUX_POLICY") else { return };
        let p = Policydb::read(&std::fs::read(path).unwrap()).unwrap();
        let map = set_mapping(&p).unwrap();
        assert_ne!(unmap_class(&map, classmap::value("tcp_socket").unwrap()), 0);
        let file = p.class_value("file").unwrap();
        let process = p.class_value("process").unwrap();
        let httpd = ctx(&p, "system_u:system_r:httpd_t:s0");
        let content = ctx(&p, "system_u:object_r:httpd_sys_content_t:s0");
        let read = bits(&p, "file", &["read", "open", "getattr"]);
        assert_eq!(p.context_compute_av(&httpd, &content, file).allowed & read, read);
        let shadow = ctx(&p, "system_u:object_r:shadow_t:s0");
        let write = bits(&p, "file", &["read", "write"]);
        assert_eq!(p.context_compute_av(&httpd, &shadow, file).allowed & write, 0);
        let init = ctx(&p, "system_u:system_r:init_t:s0");
        let exec = ctx(&p, "system_u:object_r:sshd_exec_t:s0");
        let new = p.context_compute_sid(&init, &exec, process, spec::TRANSITION, None, false);
        let new = p.context_to_string(&new.unwrap());
        assert!(new.starts_with("system_u:system_r:sshd_t:s0"), "{new}");
        std::println!("init_t runs sshd_exec_t as {new}");
    }
}

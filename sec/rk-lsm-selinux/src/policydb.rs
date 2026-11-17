//! The binary policy of SELinux, as security/selinux/ss/policydb.c of Linux.
//!
//! `load_policy` writes the policy that `checkpolicy` or `secilc` made to the file `load` of
//! selinuxfs. [`Policydb::read`] reads it with the checks of `policydb_read` of Linux. The policy
//! has a header, the symbols (the commons, the classes with their permissions and constraints,
//! the roles, the types, the users, the booleans, the sensitivities and the categories), the
//! type enforcement rules ([`crate::avtab`]) with their conditional rules, the role transitions
//! and the allowed role changes, the file name transitions, the contexts of the objects
//! (initial SIDs, file system uses, ports, network interfaces and nodes), the `genfscon` rules,
//! the range transitions and the attributes of each type.
//!
//! The numbers in the file are little endian. A value of a symbol starts at 1. In a bitmap the
//! bit of the value `v` is `v - 1`.

use crate::avtab::Avtab;
use crate::ebitmap::Ebitmap;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

/// The magic number at the start of a policy, `POLICYDB_MAGIC` of Linux. It is also the magic
/// number of selinuxfs.
pub const MAGIC: u32 = 0xf97c_ff8c;

/// The text after the magic number, `POLICYDB_STRING` of Linux.
const STRING: &[u8] = b"SE Linux";

/// The policy versions that the kernel can read. Version 35 adds `neveraudit`.
pub const VERSION_MIN: u32 = 15;
/// The newest policy version, `POLICYDB_VERSION_MAX` of Linux. The file `policyvers` of
/// selinuxfs gives it.
pub const VERSION_MAX: u32 = 35;

/// The policy versions that added a part of the format, `POLICYDB_VERSION_*` of Linux.
pub mod version {
    /// Booleans and conditional rules.
    pub const BOOL: u32 = 16;
    /// MLS and the `validatetrans` rules.
    pub const MLS: u32 = 19;
    /// The new format of the rules.
    pub const AVTAB: u32 = 20;
    /// A class in the range transitions.
    pub const RANGETRANS: u32 = 21;
    /// The policy capabilities.
    pub const POLCAP: u32 = 22;
    /// The permissive types.
    pub const PERMISSIVE: u32 = 23;
    /// The bounds of the users, roles and types.
    pub const BOUNDARY: u32 = 24;
    /// The file name transitions.
    pub const FILENAME_TRANS: u32 = 25;
    /// A class in the role transitions.
    pub const ROLETRANS: u32 = 26;
    /// The default user, role and range of a class.
    pub const NEW_OBJECT_DEFAULTS: u32 = 27;
    /// The default type of a class.
    pub const DEFAULT_TYPE: u32 = 28;
    /// The names in the constraints.
    pub const CONSTRAINT_NAMES: u32 = 29;
    /// The extended permissions of `ioctl`.
    pub const XPERMS_IOCTL: u32 = 30;
    /// The compact format of the file name transitions.
    pub const COMP_FTRANS: u32 = 33;
    /// The extended permissions in the conditional rules.
    pub const COND_XPERMS: u32 = 34;
    /// The types that are never audited.
    pub const NEVERAUDIT: u32 = 35;
}

/// The bits of the configuration word of the header, `POLICYDB_CONFIG_*` of Linux.
const CONFIG_MLS: u32 = 1;
const REJECT_UNKNOWN: u32 = 2;
const ALLOW_UNKNOWN: u32 = 4;

/// The number of symbol tables and of object context lists of a policy version, as
/// `policydb_compat` of Linux.
fn compat(version: u32) -> Option<(u32, u32)> {
    match version {
        15 => Some((5, 6)),
        16 => Some((6, 6)),
        17 | 18 => Some((6, 7)),
        19..=30 => Some((8, 7)),
        31..=VERSION_MAX => Some((8, 9)),
        _ => None,
    }
}

/// The highest number of permissions of a class, `SEL_VEC_MAX` of Linux.
const SEL_VEC_MAX: u32 = 32;

/// The value of the role `object_r`, the role of the files, `OBJECT_R_VAL` of Linux.
pub const OBJECT_R_VAL: u32 = 1;

/// An error of the read of a policy. The load gives `EINVAL` for each one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The policy ends before a part.
    Truncated,
    /// A part has a bad value. The text tells which part.
    Invalid(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated policy"),
            Self::Invalid(what) => write!(f, "invalid {what}"),
        }
    }
}

/// Reads the numbers and the strings of a policy, as `next_entry` and `str_read` of Linux.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader at the start of `data`.
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// The number of bytes after the position.
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// The next `n` bytes.
    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.remaining() {
            return Err(Error::Truncated);
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.bytes(1)?[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn u32s<const N: usize>(&mut self) -> Result<[u32; N], Error> {
        let mut out = [0; N];
        for v in &mut out {
            *v = self.u32()?;
        }
        Ok(out)
    }

    pub(crate) fn u16s<const N: usize>(&mut self) -> Result<[u16; N], Error> {
        let mut out = [0; N];
        for v in &mut out {
            let b = self.bytes(2)?;
            *v = u16::from_le_bytes([b[0], b[1]]);
        }
        Ok(out)
    }

    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        let mut b = [0; 8];
        b.copy_from_slice(self.bytes(8)?);
        Ok(u64::from_le_bytes(b))
    }

    /// A string of `len` bytes without a NUL, as `str_read` of Linux.
    pub(crate) fn string(&mut self, len: u32) -> Result<String, Error> {
        let b = self.bytes(len as usize)?;
        if b.contains(&0) {
            return Err(Error::Invalid("string"));
        }
        String::from_utf8(b.to_vec()).map_err(|_| Error::Invalid("string"))
    }

    /// Checks that `n` items of at least `min` bytes each can be in the rest of the policy, as
    /// `size_check` of Linux. A bad count then cannot make a large allocation.
    pub(crate) fn count(&self, n: u32, min: usize) -> Result<usize, Error> {
        let n = n as usize;
        if n.checked_mul(min).is_none_or(|need| need > self.remaining()) {
            return Err(Error::Truncated);
        }
        Ok(n)
    }
}

/// A level of MLS: a sensitivity and a set of categories, `struct mls_level` of Linux.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Level {
    /// The value of the sensitivity.
    pub sens: u32,
    /// The categories.
    pub cats: Ebitmap,
}

impl Level {
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let sens = r.u32()?;
        Ok(Self { sens, cats: Ebitmap::read(r)? })
    }

    /// Tells if this level dominates `other`, as `mls_level_dom` of Linux.
    pub fn dom(&self, other: &Self) -> bool {
        self.sens >= other.sens && self.cats.contains(&other.cats)
    }
}

/// A range of MLS, from a low level to a high level, `struct mls_range` of Linux.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Range {
    /// The low level.
    pub low: Level,
    /// The high level.
    pub high: Level,
}

impl Range {
    /// Reads a range, as `mls_read_range_helper` of Linux: the number of sensitivities (1 or
    /// 2), the sensitivities, and the categories of each level. With one level the high level
    /// is the low level.
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let items = r.u32()?;
        if items == 0 || items > 2 {
            return Err(Error::Invalid("range"));
        }
        let low_sens = r.u32()?;
        let high_sens = if items > 1 { r.u32()? } else { low_sens };
        let low = Level { sens: low_sens, cats: Ebitmap::read(r)? };
        let high_cats = if items > 1 { Ebitmap::read(r)? } else { low.cats.clone() };
        Ok(Self { low, high: Level { sens: high_sens, cats: high_cats } })
    }

    /// Tells if this range has all of `other`, as `mls_range_contains` of Linux.
    pub fn contains(&self, other: &Self) -> bool {
        other.low.dom(&self.low) && self.high.dom(&other.high)
    }
}

/// A security context: a user, a role, a type and a range, `struct context` of Linux.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Context {
    /// The value of the user.
    pub user: u32,
    /// The value of the role.
    pub role: u32,
    /// The value of the type.
    pub ty: u32,
    /// The MLS range. It is empty in a policy without MLS.
    pub range: Range,
}

/// A permission of a common or of a class: its name and its value, 1 to 32.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Perm {
    /// The name.
    pub name: String,
    /// The value. The bit of the permission is `1 << (value - 1)`.
    pub value: u32,
}

/// Reads the permissions of a common or a class, as `perm_read` of Linux. Each value is from 1
/// to `nprim`, and two permissions cannot have one value. The return has the bits of the values.
fn read_perms(r: &mut Reader<'_>, n: u32, nprim: u32, out: &mut Vec<Perm>) -> Result<u32, Error> {
    let mut claimed = 0u32;
    for _ in 0..r.count(n, 8)? {
        let [len, value] = r.u32s::<2>()?;
        let name = r.string(len)?;
        if value == 0 || value > nprim || value > SEL_VEC_MAX {
            return Err(Error::Invalid("permission value"));
        }
        let bit = 1u32 << (value - 1);
        if claimed & bit != 0 || out.iter().any(|p| p.name == name) {
            return Err(Error::Invalid("duplicate permission"));
        }
        claimed |= bit;
        out.push(Perm { name, value });
    }
    Ok(claimed)
}

/// A common: a set of permissions that classes share, `struct common_datum` of Linux.
#[derive(Clone, Debug)]
pub struct Common {
    /// The name, as `file` or `socket`.
    pub name: String,
    /// The value.
    pub value: u32,
    /// The number of permission values.
    pub nprim: u32,
    /// The permissions.
    pub perms: Vec<Perm>,
}

/// A constraint, or a `validatetrans` rule, of a class, `struct constraint_node` of Linux.
#[derive(Clone, Debug)]
pub struct Constraint {
    /// The permissions that the constraint checks.
    pub perms: u32,
    /// The expression in postfix order.
    pub expr: Vec<ConstraintExpr>,
}

/// The kinds of the nodes of a constraint expression, `CEXPR_*` of Linux.
pub mod cexpr {
    /// The negation of the expression on the top.
    pub const NOT: u32 = 1;
    /// The conjunction of the two expressions on the top.
    pub const AND: u32 = 2;
    /// The disjunction of the two expressions on the top.
    pub const OR: u32 = 3;
    /// A compare of two attributes of the contexts.
    pub const ATTR: u32 = 4;
    /// A compare of an attribute of a context with a set of names.
    pub const NAMES: u32 = 5;
    /// The highest depth of the stack of an expression.
    pub const MAXDEPTH: i32 = 5;

    /// The user.
    pub const USER: u32 = 1;
    /// The role.
    pub const ROLE: u32 = 2;
    /// The type.
    pub const TYPE: u32 = 4;
    /// The target context, with `USER`, `ROLE` or `TYPE`.
    pub const TARGET: u32 = 8;
    /// The third context of a `validatetrans` rule.
    pub const XTARGET: u32 = 16;
    /// The low level of the source and the low level of the target.
    pub const L1L2: u32 = 32;
    /// The low level of the source and the high level of the target.
    pub const L1H2: u32 = 64;
    /// The high level of the source and the low level of the target.
    pub const H1L2: u32 = 128;
    /// The high level of the source and the high level of the target.
    pub const H1H2: u32 = 256;
    /// The low level and the high level of the source.
    pub const L1H1: u32 = 512;
    /// The low level and the high level of the target.
    pub const L2H2: u32 = 1024;

    /// Equal.
    pub const EQ: u32 = 1;
    /// Not equal.
    pub const NEQ: u32 = 2;
    /// Dominates.
    pub const DOM: u32 = 3;
    /// Is dominated by.
    pub const DOMBY: u32 = 4;
    /// Not comparable.
    pub const INCOMP: u32 = 5;
}

/// A node of a constraint expression, `struct constraint_expr` of Linux.
#[derive(Clone, Debug)]
pub struct ConstraintExpr {
    /// The kind of the node, [`cexpr::NOT`] to [`cexpr::NAMES`].
    pub kind: u32,
    /// The attribute of the contexts that the node compares.
    pub attr: u32,
    /// The operator of the compare.
    pub op: u32,
    /// The names of a [`cexpr::NAMES`] node.
    pub names: Ebitmap,
}

/// Reads the constraints of a class, as `read_cons_helper` of Linux. The checks of the depth
/// of the stack make sure that the evaluation cannot fail.
fn read_constraints(
    r: &mut Reader<'_>,
    version: u32,
    n: u32,
    xtarget: bool,
) -> Result<Vec<Constraint>, Error> {
    use cexpr::*;
    let mut out = Vec::new();
    for _ in 0..r.count(n, 8)? {
        let [perms, nexpr] = r.u32s::<2>()?;
        let mut expr = Vec::new();
        let mut depth: i32 = -1;
        for _ in 0..r.count(nexpr, 12)? {
            let [kind, attr, op] = r.u32s::<3>()?;
            let mut names = Ebitmap::new();
            match kind {
                NOT if depth >= 0 => {}
                AND | OR if depth >= 1 => depth -= 1,
                ATTR if depth < MAXDEPTH - 1 => {
                    depth += 1;
                    let ok = match attr {
                        USER | TYPE => op == EQ || op == NEQ,
                        ROLE | L1L2 | L1H2 | H1L2 | H1H2 | L1H1 | L2H2 => {
                            (EQ..=INCOMP).contains(&op)
                        }
                        _ => false,
                    };
                    if !ok {
                        return Err(Error::Invalid("constraint attribute"));
                    }
                }
                NAMES if depth < MAXDEPTH - 1 => {
                    depth += 1;
                    let target = attr & (TARGET | XTARGET);
                    if (!xtarget && attr & XTARGET != 0)
                        || target == TARGET | XTARGET
                        || !matches!(attr & !(TARGET | XTARGET), USER | ROLE | TYPE)
                        || (op != EQ && op != NEQ)
                    {
                        return Err(Error::Invalid("constraint names"));
                    }
                    names = Ebitmap::read(r)?;
                    if version >= crate::policydb::version::CONSTRAINT_NAMES {
                        // The type set of the source policy, for `policydb_write`: the types,
                        // the types that are not in the set, and the flags.
                        Ebitmap::read(r)?;
                        Ebitmap::read(r)?;
                        r.u32()?;
                    }
                }
                _ => return Err(Error::Invalid("constraint expression")),
            }
            expr.push(ConstraintExpr { kind, attr, op, names });
        }
        if depth != 0 {
            return Err(Error::Invalid("constraint depth"));
        }
        out.push(Constraint { perms, expr });
    }
    Ok(out)
}

/// The values of the default rules of a class, `DEFAULT_*` of Linux.
pub mod default {
    /// The value from the source context.
    pub const SOURCE: u32 = 1;
    /// The value from the target context.
    pub const TARGET: u32 = 2;
    /// The low level of the source.
    pub const SOURCE_LOW: u32 = 1;
    /// The high level of the source.
    pub const SOURCE_HIGH: u32 = 2;
    /// The range of the source.
    pub const SOURCE_LOW_HIGH: u32 = 3;
    /// The low level of the target.
    pub const TARGET_LOW: u32 = 4;
    /// The high level of the target.
    pub const TARGET_HIGH: u32 = 5;
    /// The range of the target.
    pub const TARGET_LOW_HIGH: u32 = 6;
    /// The greatest lower bound of the two ranges.
    pub const GLBLUB: u32 = 7;
}

/// A class of objects, `struct class_datum` of Linux.
#[derive(Clone, Debug)]
pub struct Class {
    /// The name, as `file`.
    pub name: String,
    /// The value.
    pub value: u32,
    /// The index of the common in [`Policydb::commons`].
    pub common: Option<usize>,
    /// The number of permission values, with the values of the common.
    pub nprim: u32,
    /// The permissions of the class, without the permissions of the common.
    pub perms: Vec<Perm>,
    /// The constraints.
    pub constraints: Vec<Constraint>,
    /// The `validatetrans` rules.
    pub validatetrans: Vec<Constraint>,
    /// The default rule of the user of a new object.
    pub default_user: u32,
    /// The default rule of the role of a new object.
    pub default_role: u32,
    /// The default rule of the range of a new object.
    pub default_range: u32,
    /// The default rule of the type of a new object.
    pub default_type: u32,
}

/// A role, `struct role_datum` of Linux.
#[derive(Clone, Debug)]
pub struct Role {
    /// The name.
    pub name: String,
    /// The value.
    pub value: u32,
    /// The role that bounds this role, or 0.
    pub bounds: u32,
    /// The roles that this role dominates.
    pub dominates: Ebitmap,
    /// The types that the role can have.
    pub types: Ebitmap,
}

/// A type or an attribute, `struct type_datum` of Linux.
#[derive(Clone, Debug)]
pub struct Type {
    /// The name.
    pub name: String,
    /// The value.
    pub value: u32,
    /// Tells if this is an attribute, a set of types.
    pub attribute: bool,
    /// The type that bounds this type, or 0.
    pub bounds: u32,
}

/// A user, `struct user_datum` of Linux.
#[derive(Clone, Debug)]
pub struct User {
    /// The name.
    pub name: String,
    /// The value.
    pub value: u32,
    /// The user that bounds this user, or 0.
    pub bounds: u32,
    /// The roles of the user.
    pub roles: Ebitmap,
    /// The MLS range of the user.
    pub range: Range,
    /// The default level of the user.
    pub dfltlevel: Level,
}

/// A boolean, `struct cond_bool_datum` of Linux.
#[derive(Debug)]
pub struct Bool {
    /// The name.
    pub name: String,
    /// The value.
    pub value: u32,
    /// The state.
    pub state: AtomicBool,
}

/// A sensitivity, `struct level_datum` of Linux.
#[derive(Clone, Debug)]
pub struct Sens {
    /// The name.
    pub name: String,
    /// The level: the value of the sensitivity and the categories that it can have.
    pub level: Level,
}

/// The kinds of the nodes of a boolean expression, `COND_*` of Linux.
pub mod cond {
    /// The state of a boolean.
    pub const BOOL: u32 = 1;
    /// Not.
    pub const NOT: u32 = 2;
    /// Or.
    pub const OR: u32 = 3;
    /// And.
    pub const AND: u32 = 4;
    /// Exclusive or.
    pub const XOR: u32 = 5;
    /// Equal.
    pub const EQ: u32 = 6;
    /// Not equal.
    pub const NEQ: u32 = 7;
    /// The highest depth of the stack of an expression, `COND_EXPR_MAXDEPTH` of Linux.
    pub const MAXDEPTH: usize = 10;
}

/// A conditional block of rules, `struct cond_node` of Linux. The rules of the true list are
/// active when the expression is true, and the rules of the false list when it is false.
#[derive(Debug)]
pub struct CondNode {
    /// The value of the expression with the states of the booleans.
    pub state: AtomicBool,
    /// The expression in postfix order: the kind of each node and its boolean.
    pub expr: Vec<(u32, u32)>,
}

/// The behaviours of `fs_use` rules, `SECURITY_FS_USE_*` of Linux.
pub mod fs_use {
    /// The labels are in the extended attribute `security.selinux`.
    pub const XATTR: u32 = 1;
    /// A new file gets the label of a type transition from the label of its creator.
    pub const TRANS: u32 = 2;
    /// A file gets the label of the task that made it.
    pub const TASK: u32 = 3;
    /// The labels come from the `genfscon` rules.
    pub const GENFS: u32 = 4;
    /// The file system has no labels.
    pub const NONE: u32 = 5;
    /// The labels come from the `context=` mount option.
    pub const MNTPOINT: u32 = 6;
    /// The file system gives the labels itself.
    pub const NATIVE: u32 = 7;
}

/// The context of an object of the policy, `struct ocontext` of Linux. A rule has one context,
/// and a network interface has two.
#[derive(Clone, Debug)]
pub struct Ocontext<T> {
    /// What the rule is for.
    pub key: T,
    /// The contexts.
    pub context: Context,
    /// The second context of a network interface: the context of its packets.
    pub context2: Option<Context>,
}

/// An `fs_use` rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsUse {
    /// The behaviour, [`fs_use::XATTR`] to [`fs_use::NATIVE`].
    pub behavior: u32,
    /// The name of the file system type.
    pub fstype: String,
}

/// A port rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Port {
    /// The IP protocol.
    pub protocol: u8,
    /// The first port.
    pub low: u16,
    /// The last port.
    pub high: u16,
}

/// The rules of the object contexts of the policy, `ocontexts` of Linux.
#[derive(Clone, Debug, Default)]
pub struct Ocontexts {
    /// The contexts of the initial SIDs.
    pub isid: Vec<Ocontext<u32>>,
    /// The old `fscon` rules, which have no effect.
    pub fs: Vec<Ocontext<String>>,
    /// The ports.
    pub port: Vec<Ocontext<Port>>,
    /// The network interfaces.
    pub netif: Vec<Ocontext<String>>,
    /// The IPv4 nodes: the address and the mask in network order.
    pub node: Vec<Ocontext<(u32, u32)>>,
    /// The `fs_use` rules.
    pub fsuse: Vec<Ocontext<FsUse>>,
    /// The IPv6 nodes: the address and the mask in network order.
    pub node6: Vec<Ocontext<([u32; 4], [u32; 4])>>,
    /// The Infiniband partition keys: the subnet prefix and the first and last key.
    pub ibpkey: Vec<Ocontext<(u64, u16, u16)>>,
    /// The Infiniband end ports: the device and the port.
    pub ibendport: Vec<Ocontext<(String, u8)>>,
}

/// A `genfscon` rule: a path below the root of a file system, a class or 0 for all the
/// classes, and a context.
#[derive(Clone, Debug)]
pub struct GenfsRule {
    /// The path.
    pub path: String,
    /// The policy value of the class, or 0.
    pub sclass: u32,
    /// The context.
    pub context: Context,
}

/// The rules of the type transitions of files with a name, the key of
/// `struct filename_trans_key` of Linux: the type of the directory, the class and the name.
pub type FilenameKey = (u32, u32, String);

/// The policy that the kernel reads from a binary policy, `struct policydb` of Linux.
#[derive(Debug)]
pub struct Policydb {
    /// The version of the format.
    pub version: u32,
    /// Tells if the policy has MLS.
    pub mls: bool,
    /// The kernel refuses the policy if a class or a permission of the kernel is not in it.
    pub reject_unknown: bool,
    /// The kernel allows the classes and the permissions that are not in the policy.
    pub allow_unknown: bool,
    /// The policy capabilities.
    pub policycaps: Ebitmap,
    /// The types whose denials do not fail, `permissive_map` of Linux.
    pub permissive: Ebitmap,
    /// The types whose decisions are never audited.
    pub neveraudit: Ebitmap,
    /// The commons, by value.
    pub commons: Vec<Common>,
    /// The classes, at the index `value - 1`.
    pub classes: Vec<Option<Class>>,
    /// The roles, at the index `value - 1`.
    pub roles: Vec<Option<Role>>,
    /// The types and attributes, at the index `value - 1`.
    pub types: Vec<Option<Type>>,
    /// The users, at the index `value - 1`.
    pub users: Vec<Option<User>>,
    /// The booleans, at the index `value - 1`.
    pub bools: Vec<Option<Bool>>,
    /// The sensitivities, at the index `value - 1`.
    pub sens: Vec<Option<Sens>>,
    /// The names of the categories, at the index `value - 1`.
    pub cats: Vec<Option<String>>,
    /// The values of the names of the symbols. An alias has the value of its type,
    /// sensitivity or category.
    pub names: [BTreeMap<String, u32>; 8],
    /// The type enforcement rules.
    pub te: Avtab,
    /// The conditional blocks of the conditional rules.
    pub cond: Vec<CondNode>,
    /// The conditional rules.
    pub te_cond: Avtab,
    /// The role transitions: the role, the type and the class give the new role.
    pub role_tr: BTreeMap<(u32, u32, u32), u32>,
    /// The allowed role changes.
    pub role_allow: Vec<(u32, u32)>,
    /// The type transitions of files with a name. The list has the source types and the new
    /// type of each rule.
    pub filename_tr: BTreeMap<FilenameKey, Vec<(Ebitmap, u32)>>,
    /// The object contexts.
    pub ocon: Ocontexts,
    /// The `genfscon` rules of each file system type, in the order of the names. The rules of
    /// a type are in the order of the length of the path, the longest first.
    pub genfs: Vec<(String, Vec<GenfsRule>)>,
    /// The range transitions: the source type, the target type and the class give the range.
    pub range_tr: BTreeMap<(u32, u32, u32), Range>,
    /// The attributes of each type, with the type itself, at the index `value - 1`.
    pub type_attr_map: Vec<Ebitmap>,
    /// The value of the class `process`.
    pub process_class: u32,
    /// The bits of the permissions `transition` and `dyntransition` of `process`.
    pub process_trans_perms: u32,
}

/// The indexes of the symbol tables, `SYM_*` of Linux.
pub mod sym {
    /// The commons.
    pub const COMMONS: usize = 0;
    /// The classes.
    pub const CLASSES: usize = 1;
    /// The roles.
    pub const ROLES: usize = 2;
    /// The types.
    pub const TYPES: usize = 3;
    /// The users.
    pub const USERS: usize = 4;
    /// The booleans.
    pub const BOOLS: usize = 5;
    /// The sensitivities.
    pub const LEVELS: usize = 6;
    /// The categories.
    pub const CATS: usize = 7;
}

/// Puts `item` at the index `value - 1` of `table`. The value must be from 1 to the size of
/// the table, and the place must be free.
fn place<T>(table: &mut [Option<T>], value: u32, item: T, what: &'static str) -> Result<(), Error> {
    let slot =
        value.checked_sub(1).and_then(|i| table.get_mut(i as usize)).ok_or(Error::Invalid(what))?;
    if slot.is_some() {
        return Err(Error::Invalid(what));
    }
    *slot = Some(item);
    Ok(())
}

/// Adds a name to a table of names. A name can be there only once.
fn add_name(map: &mut BTreeMap<String, u32>, name: String, value: u32) -> Result<(), Error> {
    if map.insert(name, value).is_some() {
        return Err(Error::Invalid("duplicate symbol"));
    }
    Ok(())
}

fn table<T>(n: u32) -> Vec<Option<T>> {
    let mut v = Vec::new();
    v.resize_with(n as usize, || None);
    v
}

impl Policydb {
    /// Reads a binary policy, as `policydb_read` of Linux.
    ///
    /// # Errors
    ///
    /// An [`Error`] tells the first part of the policy that is bad.
    pub fn read(data: &[u8]) -> Result<Self, Error> {
        let r = &mut Reader::new(data);
        let [magic, len] = r.u32s::<2>()?;
        if magic != MAGIC {
            return Err(Error::Invalid("magic number"));
        }
        if len as usize != STRING.len() || r.bytes(STRING.len())? != STRING {
            return Err(Error::Invalid("policy string"));
        }
        let [version, config, sym_num, ocon_num] = r.u32s::<4>()?;
        if !(VERSION_MIN..=VERSION_MAX).contains(&version) {
            return Err(Error::Invalid("policy version"));
        }
        let mls = config & CONFIG_MLS != 0;
        if mls && version < version::MLS {
            return Err(Error::Invalid("MLS in an old version"));
        }
        if config & (REJECT_UNKNOWN | ALLOW_UNKNOWN) == REJECT_UNKNOWN | ALLOW_UNKNOWN {
            return Err(Error::Invalid("handle unknown"));
        }
        let ebitmap_if = |r: &mut Reader<'_>, v: u32| {
            if version >= v { Ebitmap::read(r) } else { Ok(Ebitmap::new()) }
        };
        let policycaps = ebitmap_if(r, version::POLCAP)?;
        let permissive = ebitmap_if(r, version::PERMISSIVE)?;
        let neveraudit = ebitmap_if(r, version::NEVERAUDIT)?;
        let (syms, ocons) = compat(version).ok_or(Error::Invalid("policy version"))?;
        if (sym_num, ocon_num) != (syms, ocons) {
            return Err(Error::Invalid("table sizes"));
        }
        let mut p = Self {
            version,
            mls,
            reject_unknown: config & REJECT_UNKNOWN != 0,
            allow_unknown: config & ALLOW_UNKNOWN != 0,
            policycaps,
            permissive,
            neveraudit,
            commons: Vec::new(),
            classes: Vec::new(),
            roles: Vec::new(),
            types: Vec::new(),
            users: Vec::new(),
            bools: Vec::new(),
            sens: Vec::new(),
            cats: Vec::new(),
            names: Default::default(),
            te: Avtab::default(),
            cond: Vec::new(),
            te_cond: Avtab::default(),
            role_tr: BTreeMap::new(),
            role_allow: Vec::new(),
            filename_tr: BTreeMap::new(),
            ocon: Ocontexts::default(),
            genfs: Vec::new(),
            range_tr: BTreeMap::new(),
            type_attr_map: Vec::new(),
            process_class: 0,
            process_trans_perms: 0,
        };
        for i in 0..syms as usize {
            let [nprim, nel] = r.u32s::<2>()?;
            let nel = r.count(nel, 16)?;
            p.read_symbols(r, i, nprim, nel)?;
        }
        p.check_symbols()?;
        p.process_class = p.class_value("process").ok_or(Error::Invalid("no process class"))?;
        p.te = Avtab::read(r, &p)?;
        if version >= version::BOOL {
            p.read_cond_list(r)?;
        }
        p.read_role_trans(r)?;
        p.read_filename_trans(r)?;
        let transition = p.perm_bit(p.process_class, "transition");
        let dyntransition = p.perm_bit(p.process_class, "dyntransition");
        match (transition, dyntransition) {
            (Some(t), Some(d)) => p.process_trans_perms = t | d,
            _ => return Err(Error::Invalid("process transition permissions")),
        }
        p.read_ocontexts(r, ocons)?;
        p.read_genfs(r)?;
        if version >= version::MLS {
            p.read_range_trans(r)?;
        }
        let ntypes = p.types.len() as u32;
        for i in 0..ntypes {
            let mut e = ebitmap_if(r, version::AVTAB)?;
            if e.highbit() > 0 && e.iter().last().is_some_and(|b| b >= ntypes) {
                return Err(Error::Invalid("type attribute map"));
            }
            e.set(i, true);
            p.type_attr_map.push(e);
        }
        p.check_bounds()?;
        Ok(p)
    }

    /// Reads the `nel` symbols of the table `i`.
    fn read_symbols(
        &mut self,
        r: &mut Reader<'_>,
        i: usize,
        nprim: u32,
        nel: usize,
    ) -> Result<(), Error> {
        let v = self.version;
        match i {
            sym::COMMONS => {
                for _ in 0..nel {
                    let [len, value, nprim, nel] = r.u32s::<4>()?;
                    if nprim > SEL_VEC_MAX || nel > SEL_VEC_MAX {
                        return Err(Error::Invalid("common permissions"));
                    }
                    let name = r.string(len)?;
                    let mut perms = Vec::new();
                    read_perms(r, nel, nprim, &mut perms)?;
                    add_name(&mut self.names[i], name.clone(), value)?;
                    self.commons.push(Common { name, value, nprim, perms });
                }
            }
            sym::CLASSES => {
                self.classes = table(nprim);
                for _ in 0..nel {
                    let class = self.read_class(r)?;
                    add_name(&mut self.names[i], class.name.clone(), class.value)?;
                    let value = class.value;
                    place(&mut self.classes, value, class, "class value")?;
                }
            }
            sym::ROLES => {
                self.roles = table(nprim);
                let object_r = Role {
                    name: String::from("object_r"),
                    value: OBJECT_R_VAL,
                    bounds: 0,
                    dominates: Ebitmap::new(),
                    types: Ebitmap::new(),
                };
                add_name(&mut self.names[i], object_r.name.clone(), OBJECT_R_VAL)?;
                place(&mut self.roles, OBJECT_R_VAL, object_r, "role value")?;
                for _ in 0..nel {
                    let [len, value] = r.u32s::<2>()?;
                    let bounds = if v >= version::BOUNDARY { r.u32()? } else { 0 };
                    let name = r.string(len)?;
                    let dominates = Ebitmap::read(r)?;
                    let types = Ebitmap::read(r)?;
                    if name == "object_r" {
                        // The role of the objects is always there with the value 1, as
                        // `roles_init` of Linux makes it.
                        if value != OBJECT_R_VAL {
                            return Err(Error::Invalid("object_r value"));
                        }
                        continue;
                    }
                    add_name(&mut self.names[i], name.clone(), value)?;
                    let role = Role { name, value, bounds, dominates, types };
                    place(&mut self.roles, value, role, "role value")?;
                }
            }
            sym::TYPES => {
                self.types = table(nprim);
                for _ in 0..nel {
                    let [len, value, props] = r.u32s::<3>()?;
                    let (primary, attribute, bounds) = if v >= version::BOUNDARY {
                        (props & 1 != 0, props & 2 != 0, r.u32()?)
                    } else {
                        (props != 0, false, 0)
                    };
                    let name = r.string(len)?;
                    add_name(&mut self.names[i], name.clone(), value)?;
                    if primary {
                        let ty = Type { name, value, attribute, bounds };
                        place(&mut self.types, value, ty, "type value")?;
                    }
                }
            }
            sym::USERS => {
                self.users = table(nprim);
                for _ in 0..nel {
                    let [len, value] = r.u32s::<2>()?;
                    let bounds = if v >= version::BOUNDARY { r.u32()? } else { 0 };
                    let name = r.string(len)?;
                    let roles = Ebitmap::read(r)?;
                    let (range, dfltlevel) = if v >= version::MLS {
                        (Range::read(r)?, Level::read(r)?)
                    } else {
                        (Range::default(), Level::default())
                    };
                    add_name(&mut self.names[i], name.clone(), value)?;
                    let user = User { name, value, bounds, roles, range, dfltlevel };
                    place(&mut self.users, value, user, "user value")?;
                }
            }
            sym::BOOLS => {
                self.bools = table(nprim);
                for _ in 0..nel {
                    let [value, state, len] = r.u32s::<3>()?;
                    if state > 1 {
                        return Err(Error::Invalid("boolean state"));
                    }
                    let name = r.string(len)?;
                    add_name(&mut self.names[i], name.clone(), value)?;
                    let b = Bool { name, value, state: AtomicBool::new(state != 0) };
                    place(&mut self.bools, value, b, "boolean value")?;
                }
            }
            sym::LEVELS => {
                self.sens = table(nprim);
                for _ in 0..nel {
                    let [len, isalias] = r.u32s::<2>()?;
                    let name = r.string(len)?;
                    let level = Level::read(r)?;
                    add_name(&mut self.names[i], name.clone(), level.sens)?;
                    if isalias == 0 {
                        let value = level.sens;
                        place(&mut self.sens, value, Sens { name, level }, "sensitivity value")?;
                    }
                }
            }
            _ => {
                self.cats = table(nprim);
                for _ in 0..nel {
                    let [len, value, isalias] = r.u32s::<3>()?;
                    let name = r.string(len)?;
                    add_name(&mut self.names[i], name.clone(), value)?;
                    if isalias == 0 {
                        place(&mut self.cats, value, name, "category value")?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Reads a class, as `class_read` of Linux.
    fn read_class(&self, r: &mut Reader<'_>) -> Result<Class, Error> {
        let [len, len2, value, nprim, nel, ncons] = r.u32s::<6>()?;
        if nel > SEL_VEC_MAX || nprim > SEL_VEC_MAX || value > u32::from(u16::MAX) {
            return Err(Error::Invalid("class"));
        }
        let name = r.string(len)?;
        let common = if len2 > 0 {
            let key = r.string(len2)?;
            let at = self.commons.iter().position(|c| c.name == key);
            let at = at.ok_or(Error::Invalid("class common"))?;
            if nprim < self.commons[at].nprim {
                return Err(Error::Invalid("class common permissions"));
            }
            Some(at)
        } else {
            None
        };
        let mut perms = Vec::new();
        let claimed = read_perms(r, nel, nprim, &mut perms)?;
        let inherited = common.map_or(0, |c| self.commons[c].nprim);
        let mask = |n: u32| if n >= 32 { u32::MAX } else { (1u32 << n) - 1 };
        if claimed != mask(nprim) & !mask(inherited) {
            return Err(Error::Invalid("class permission values"));
        }
        let constraints = read_constraints(r, self.version, ncons, false)?;
        let validatetrans = if self.version >= version::MLS {
            let n = r.u32()?;
            read_constraints(r, self.version, n, true)?
        } else {
            Vec::new()
        };
        let mut class = Class {
            name,
            value,
            common,
            nprim,
            perms,
            constraints,
            validatetrans,
            default_user: 0,
            default_role: 0,
            default_range: 0,
            default_type: 0,
        };
        if self.version >= version::NEW_OBJECT_DEFAULTS {
            let [user, role, range] = r.u32s::<3>()?;
            if user > default::TARGET || role > default::TARGET || range > default::GLBLUB {
                return Err(Error::Invalid("class defaults"));
            }
            (class.default_user, class.default_role, class.default_range) = (user, role, range);
        }
        if self.version >= version::DEFAULT_TYPE {
            let ty = r.u32()?;
            if ty > default::TARGET {
                return Err(Error::Invalid("class default type"));
            }
            class.default_type = ty;
        }
        Ok(class)
    }

    /// Checks that each value of the tables has a symbol, as `policydb_index` of Linux needs.
    fn check_symbols(&self) -> Result<(), Error> {
        let full = self.classes.iter().all(Option::is_some)
            && self.roles.iter().all(Option::is_some)
            && self.users.iter().all(Option::is_some)
            && self.bools.iter().all(Option::is_some);
        if !full {
            return Err(Error::Invalid("symbol without a value"));
        }
        // As Linux, a value of a sensitivity or of a category can have no symbol. A level
        // with such a value is not valid.
        Ok(())
    }

    /// Tells if `t` is the value of a type or an attribute.
    pub(crate) fn type_valid(&self, t: u32) -> bool {
        t >= 1 && t as usize <= self.types.len()
    }

    /// Tells if `t` is the value of a type that is not an attribute, as
    /// `policydb_simpletype_isvalid` of Linux.
    pub(crate) fn simple_type_valid(&self, t: u32) -> bool {
        self.ty(t).is_some_and(|ty| !ty.attribute)
    }

    /// Tells if `c` is the value of a class.
    pub(crate) fn class_valid(&self, c: u32) -> bool {
        c >= 1 && c as usize <= self.classes.len()
    }

    fn role_valid(&self, r: u32) -> bool {
        r >= 1 && r as usize <= self.roles.len()
    }

    /// The type with the value `t`.
    pub fn ty(&self, t: u32) -> Option<&Type> {
        self.types.get(t.checked_sub(1)? as usize)?.as_ref()
    }

    /// Tells if the type `bound` is in the chain of bounds of the type `t`, as the loop of
    /// `security_bounded_transition` of Linux. The load checks that a chain is short and has no
    /// loop.
    pub fn type_bounded_by(&self, t: u32, bound: u32) -> bool {
        let mut t = t;
        while let Some(b) = self.ty(t).map(|ty| ty.bounds).filter(|&b| b != 0) {
            if b == bound {
                return true;
            }
            t = b;
        }
        false
    }

    /// The class with the value `c`.
    pub fn class(&self, c: u32) -> Option<&Class> {
        self.classes.get(c.checked_sub(1)? as usize)?.as_ref()
    }

    /// The role with the value `v`.
    pub fn role(&self, v: u32) -> Option<&Role> {
        self.roles.get(v.checked_sub(1)? as usize)?.as_ref()
    }

    /// The user with the value `v`.
    pub fn user(&self, v: u32) -> Option<&User> {
        self.users.get(v.checked_sub(1)? as usize)?.as_ref()
    }

    /// The value of the class with the name `name`.
    pub fn class_value(&self, name: &str) -> Option<u32> {
        self.names[sym::CLASSES].get(name).copied()
    }

    /// The permissions of the class `c`, with the permissions of its common.
    pub fn perms(&self, c: u32) -> impl Iterator<Item = &Perm> {
        let class = self.class(c);
        let common = class.and_then(|c| c.common).and_then(|i| self.commons.get(i));
        let own = class.map(|c| c.perms.as_slice()).unwrap_or_default();
        common.map(|c| c.perms.as_slice()).unwrap_or_default().iter().chain(own)
    }

    /// The bit of the permission `name` of the class `c`, as `string_to_av_perm` of Linux.
    pub fn perm_bit(&self, c: u32, name: &str) -> Option<u32> {
        self.perms(c).find(|p| p.name == name).map(|p| 1 << (p.value - 1))
    }

    /// Tells if the policy capability `cap` is set.
    pub fn policycap(&self, cap: u32) -> bool {
        self.policycaps.get(cap)
    }

    /// Reads the conditional blocks, as `cond_read_list` of Linux. The state of each block
    /// comes from the states of the booleans.
    fn read_cond_list(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        let n = r.u32()?;
        for i in 0..r.count(n, 8)? {
            let [state, nexpr] = r.u32s::<2>()?;
            let mut expr = Vec::new();
            for _ in 0..r.count(nexpr, 8)? {
                let [kind, b] = r.u32s::<2>()?;
                if kind == 0 || kind > cond::NEQ {
                    return Err(Error::Invalid("conditional expression"));
                }
                if kind == cond::BOOL && (b == 0 || b as usize > self.bools.len()) {
                    return Err(Error::Invalid("conditional boolean"));
                }
                expr.push((kind, b));
            }
            self.cond.push(CondNode { state: AtomicBool::new(state != 0), expr });
            let node = i as u32;
            let mut table = core::mem::take(&mut self.te_cond);
            let res = table
                .read_cond_list(r, self, node, true)
                .and_then(|()| table.read_cond_list(r, self, node, false));
            self.te_cond = table;
            res?;
        }
        self.te_cond.sort();
        self.te_cond.check_cond_types(&self.te)?;
        self.evaluate_conds();
        Ok(())
    }

    /// Evaluates the expression of a conditional block, as `cond_evaluate_expr` of Linux. A
    /// bad expression gives `None`.
    pub fn evaluate(&self, expr: &[(u32, u32)]) -> Option<bool> {
        let mut stack: Vec<bool> = Vec::new();
        for &(kind, b) in expr {
            if kind == cond::BOOL {
                if stack.len() == cond::MAXDEPTH {
                    return None;
                }
                let state = self.bools.get(b.checked_sub(1)? as usize)?.as_ref()?;
                stack.push(state.state.load(Ordering::Relaxed));
                continue;
            }
            let x = stack.pop()?;
            let v = match kind {
                cond::NOT => !x,
                _ => {
                    let y = stack.pop()?;
                    match kind {
                        cond::OR => y || x,
                        cond::AND => y && x,
                        cond::XOR => y ^ x,
                        cond::EQ => y == x,
                        cond::NEQ => y != x,
                        _ => return None,
                    }
                }
            };
            stack.push(v);
        }
        if stack.len() == 1 { stack.pop() } else { None }
    }

    /// Sets the state of each conditional block from the states of the booleans, as
    /// `evaluate_cond_nodes` of Linux. A block with a bad expression has no active rules.
    pub fn evaluate_conds(&self) {
        for node in &self.cond {
            let state = self.evaluate(&node.expr);
            node.state.store(state.unwrap_or(false), Ordering::Relaxed);
        }
    }

    /// Tells if the rule of a conditional block is active.
    pub fn cond_active(&self, node: u32, list: bool) -> bool {
        self.cond.get(node as usize).is_some_and(|n| n.state.load(Ordering::Relaxed) == list)
    }

    /// Reads the role transitions and the allowed role changes.
    fn read_role_trans(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        let n = r.u32()?;
        for _ in 0..r.count(n, 12)? {
            let [role, ty, new_role] = r.u32s::<3>()?;
            let class =
                if self.version >= version::ROLETRANS { r.u32()? } else { self.process_class };
            if !self.role_valid(role)
                || !self.type_valid(ty)
                || !self.class_valid(class)
                || !self.role_valid(new_role)
            {
                return Err(Error::Invalid("role transition"));
            }
            if self.role_tr.insert((role, ty, class), new_role).is_some() {
                return Err(Error::Invalid("duplicate role transition"));
            }
        }
        let n = r.u32()?;
        for _ in 0..r.count(n, 8)? {
            let [role, new_role] = r.u32s::<2>()?;
            if !self.role_valid(role) || !self.role_valid(new_role) {
                return Err(Error::Invalid("role allow"));
            }
            self.role_allow.push((role, new_role));
        }
        Ok(())
    }

    /// Reads the type transitions of files with a name, as `filename_trans_read` of Linux. A
    /// policy before version 33 has one rule for each source type.
    fn read_filename_trans(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        if self.version < version::FILENAME_TRANS {
            return Ok(());
        }
        let n = r.u32()?;
        for _ in 0..r.count(n, 8)? {
            let len = r.u32()?;
            let name = r.string(len)?;
            if self.version < version::COMP_FTRANS {
                let [stype, ttype, class, otype] = r.u32s::<4>()?;
                if !self.type_valid(stype)
                    || !self.type_valid(ttype)
                    || !self.class_valid(class)
                    || !self.simple_type_valid(otype)
                {
                    return Err(Error::Invalid("file name transition"));
                }
                let list = self.filename_tr.entry((ttype, class, name)).or_default();
                // A rule for a source type that has a rule is ignored, as on Linux.
                if list.iter().any(|(s, _)| s.get(stype - 1)) {
                    continue;
                }
                match list.iter_mut().find(|(_, o)| *o == otype) {
                    Some((s, _)) => s.set(stype - 1, true),
                    None => list.push((Ebitmap::from_bits([stype - 1]), otype)),
                }
            } else {
                let [ttype, class, ndatum] = r.u32s::<3>()?;
                if !self.type_valid(ttype) || !self.class_valid(class) || ndatum == 0 {
                    return Err(Error::Invalid("file name transition"));
                }
                let mut list = Vec::new();
                for _ in 0..r.count(ndatum, 16)? {
                    let stypes = Ebitmap::read(r)?;
                    if stypes.iter().last().is_some_and(|b| b as usize >= self.types.len()) {
                        return Err(Error::Invalid("file name transition types"));
                    }
                    let otype = r.u32()?;
                    if !self.simple_type_valid(otype) {
                        return Err(Error::Invalid("file name transition type"));
                    }
                    list.push((stypes, otype));
                }
                if self.filename_tr.insert((ttype, class, name), list).is_some() {
                    return Err(Error::Invalid("duplicate file name transition"));
                }
            }
        }
        Ok(())
    }

    /// Reads a context and checks it, as `context_read_and_validate` of Linux.
    fn read_context(&self, r: &mut Reader<'_>) -> Result<Context, Error> {
        let [user, role, ty] = r.u32s::<3>()?;
        let range = if self.version >= version::MLS { Range::read(r)? } else { Range::default() };
        let c = Context { user, role, ty, range };
        if !self.context_valid(&c) {
            return Err(Error::Invalid("context"));
        }
        Ok(c)
    }

    /// Tells if a level is valid: a sensitivity of the policy with the categories that it
    /// can have, as `mls_level_isvalid` of Linux.
    pub fn level_valid(&self, l: &Level) -> bool {
        let sens = l.sens.checked_sub(1).and_then(|i| self.sens.get(i as usize));
        let Some(Some(sens)) = sens else { return false };
        sens.level.cats.contains(&l.cats)
    }

    /// Tells if a range is valid, as `mls_range_isvalid` of Linux.
    pub fn range_valid(&self, r: &Range) -> bool {
        self.level_valid(&r.low) && self.level_valid(&r.high) && r.high.dom(&r.low)
    }

    /// Tells if a context is valid, as `policydb_context_isvalid` of Linux: the role is a role
    /// of the user, the type is a type of the role, and the range is in the range of the user.
    /// The role `object_r` can have each type.
    pub fn context_valid(&self, c: &Context) -> bool {
        let (Some(role), Some(user)) = (self.role(c.role), self.user(c.user)) else {
            return false;
        };
        if self.ty(c.ty).is_none_or(|t| t.attribute) {
            return false;
        }
        if c.role != OBJECT_R_VAL && (!user.roles.get(c.role - 1) || !role.types.get(c.ty - 1)) {
            return false;
        }
        if !self.mls {
            return true;
        }
        self.range_valid(&c.range) && (c.role == OBJECT_R_VAL || user.range.contains(&c.range))
    }

    /// Reads the object contexts, as `ocontext_read` of Linux.
    fn read_ocontexts(&mut self, r: &mut Reader<'_>, n: u32) -> Result<(), Error> {
        for i in 0..n {
            let nel = r.u32()?;
            for _ in 0..r.count(nel, 8)? {
                match i {
                    0 => {
                        let sid = r.u32()?;
                        let context = self.read_context(r)?;
                        self.ocon.isid.push(Ocontext { key: sid, context, context2: None });
                    }
                    1 | 3 => {
                        let len = r.u32()?;
                        let key = r.string(len)?;
                        let context = self.read_context(r)?;
                        let context2 = Some(self.read_context(r)?);
                        let o = Ocontext { key, context, context2 };
                        if i == 1 { self.ocon.fs.push(o) } else { self.ocon.netif.push(o) }
                    }
                    2 => {
                        let [protocol, low, high] = r.u32s::<3>()?;
                        let (Ok(protocol), Ok(low), Ok(high)) =
                            (u8::try_from(protocol), u16::try_from(low), u16::try_from(high))
                        else {
                            return Err(Error::Invalid("port"));
                        };
                        if low == 0 || low > high {
                            return Err(Error::Invalid("port range"));
                        }
                        let context = self.read_context(r)?;
                        let key = Port { protocol, low, high };
                        self.ocon.port.push(Ocontext { key, context, context2: None });
                    }
                    4 => {
                        let a = u32::from_ne_bytes(r.bytes(4)?.try_into().unwrap_or_default());
                        let m = u32::from_ne_bytes(r.bytes(4)?.try_into().unwrap_or_default());
                        let context = self.read_context(r)?;
                        self.ocon.node.push(Ocontext { key: (a, m), context, context2: None });
                    }
                    5 => {
                        let [behavior, len] = r.u32s::<2>()?;
                        if behavior == fs_use::MNTPOINT || behavior > fs_use::NATIVE {
                            return Err(Error::Invalid("fs_use behavior"));
                        }
                        let fstype = r.string(len)?;
                        let context = self.read_context(r)?;
                        let key = FsUse { behavior, fstype };
                        self.ocon.fsuse.push(Ocontext { key, context, context2: None });
                    }
                    6 => {
                        let mut w = [0u32; 8];
                        for v in &mut w {
                            *v = u32::from_ne_bytes(r.bytes(4)?.try_into().unwrap_or_default());
                        }
                        let key = ([w[0], w[1], w[2], w[3]], [w[4], w[5], w[6], w[7]]);
                        let context = self.read_context(r)?;
                        self.ocon.node6.push(Ocontext { key, context, context2: None });
                    }
                    7 => {
                        let prefix = u64::from_be_bytes(r.bytes(8)?.try_into().unwrap_or_default());
                        let [lo, hi] = r.u32s::<2>()?;
                        let (Ok(lo), Ok(hi)) = (u16::try_from(lo), u16::try_from(hi)) else {
                            return Err(Error::Invalid("ibpkey"));
                        };
                        let context = self.read_context(r)?;
                        let key = (prefix, lo, hi);
                        self.ocon.ibpkey.push(Ocontext { key, context, context2: None });
                    }
                    _ => {
                        let [len, port] = r.u32s::<2>()?;
                        let dev = r.string(len)?;
                        let port = u8::try_from(port).ok().filter(|&p| p != 0);
                        let port = port.ok_or(Error::Invalid("ibendport"))?;
                        let context = self.read_context(r)?;
                        let key = (dev, port);
                        self.ocon.ibendport.push(Ocontext { key, context, context2: None });
                    }
                }
            }
        }
        Ok(())
    }

    /// Reads the `genfscon` rules, as `genfs_read` of Linux. The file system types are kept
    /// in the order of their names, and the rules of a type with the longest path first.
    fn read_genfs(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        let n = r.u32()?;
        for _ in 0..r.count(n, 8)? {
            let len = r.u32()?;
            let fstype = r.string(len)?;
            let at = match self.genfs.binary_search_by(|g| g.0.as_str().cmp(&fstype)) {
                Ok(_) => return Err(Error::Invalid("duplicate genfs type")),
                Err(at) => at,
            };
            let mut rules: Vec<GenfsRule> = Vec::new();
            let nel = r.u32()?;
            for _ in 0..r.count(nel, 8)? {
                let len = r.u32()?;
                let path = r.string(len)?;
                let sclass = r.u32()?;
                if sclass > u32::from(u16::MAX) || (sclass != 0 && !self.class_valid(sclass)) {
                    return Err(Error::Invalid("genfs class"));
                }
                let context = self.read_context(r)?;
                let dup = rules.iter().any(|c| {
                    c.path == path && (c.sclass == 0 || sclass == 0 || c.sclass == sclass)
                });
                if dup {
                    return Err(Error::Invalid("duplicate genfs entry"));
                }
                let at = rules.iter().position(|c| path.len() > c.path.len());
                let rule = GenfsRule { path, sclass, context };
                rules.insert(at.unwrap_or(rules.len()), rule);
            }
            self.genfs.insert(at, (fstype, rules));
        }
        Ok(())
    }

    /// Reads the range transitions, as `range_read` of Linux.
    fn read_range_trans(&mut self, r: &mut Reader<'_>) -> Result<(), Error> {
        let n = r.u32()?;
        for _ in 0..r.count(n, 12)? {
            let [stype, ttype] = r.u32s::<2>()?;
            let class =
                if self.version >= version::RANGETRANS { r.u32()? } else { self.process_class };
            if !self.type_valid(stype) || !self.type_valid(ttype) || !self.class_valid(class) {
                return Err(Error::Invalid("range transition"));
            }
            let range = Range::read(r)?;
            if !self.range_valid(&range) {
                return Err(Error::Invalid("range transition range"));
            }
            if self.range_tr.insert((stype, ttype, class), range).is_some() {
                return Err(Error::Invalid("duplicate range transition"));
            }
        }
        Ok(())
    }

    /// Checks the bounds of the users, the roles and the types, as
    /// `policydb_bounds_sanity_check` of Linux: a bound is a valid value, and a chain of
    /// bounds is short and has no loop.
    fn check_bounds(&self) -> Result<(), Error> {
        if self.version < version::BOUNDARY {
            return Ok(());
        }
        fn chain(start: u32, next: impl Fn(u32) -> Option<u32>) -> bool {
            let mut v = start;
            for _ in 0..4 {
                match next(v) {
                    Some(0) => return true,
                    Some(b) => v = b,
                    None => return false,
                }
            }
            false
        }
        let users =
            self.users.iter().flatten().all(|u| chain(u.value, |v| self.user(v).map(|u| u.bounds)));
        let roles =
            self.roles.iter().flatten().all(|r| chain(r.value, |v| self.role(v).map(|r| r.bounds)));
        let types = self.types.iter().flatten().all(|t| {
            chain(t.value, |v| self.ty(v).filter(|t| !t.attribute).map(|t| t.bounds)) || t.attribute
        });
        if users && roles && types { Ok(()) } else { Err(Error::Invalid("bounds")) }
    }

    /// The name of the symbol with the value `value` in the table `table`.
    pub fn name(&self, table: usize, value: u32) -> Option<&str> {
        let i = value.checked_sub(1)? as usize;
        Some(match table {
            sym::CLASSES => self.classes.get(i)?.as_ref()?.name.as_str(),
            sym::ROLES => self.roles.get(i)?.as_ref()?.name.as_str(),
            sym::TYPES => self.types.get(i)?.as_ref()?.name.as_str(),
            sym::USERS => self.users.get(i)?.as_ref()?.name.as_str(),
            sym::BOOLS => self.bools.get(i)?.as_ref()?.name.as_str(),
            sym::LEVELS => self.sens.get(i)?.as_ref()?.name.as_str(),
            sym::CATS => self.cats.get(i)?.as_ref()?.as_str(),
            _ => self.commons.iter().find(|c| c.value == value)?.name.as_str(),
        })
    }

    /// The number of rules, with the conditional rules.
    pub fn rules(&self) -> usize {
        self.te.len() + self.te_cond.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::avtab::spec;

    const V24: &[u8] = include_bytes!("../tests/rk_test.24.bin");
    const V33: &[u8] = include_bytes!("../tests/rk_test.33.bin");
    const V35: &[u8] = include_bytes!("../tests/rk_test.35.bin");

    fn value(p: &Policydb, table: usize, name: &str) -> u32 {
        *p.names[table].get(name).unwrap()
    }

    fn count<T>(table: &[Option<T>]) -> usize {
        table.iter().flatten().count()
    }

    #[test]
    fn the_test_policy_reads_in_each_version() {
        for (data, v) in [(V24, 24), (V33, 33), (V35, 35)] {
            let p = Policydb::read(data).unwrap();
            assert_eq!(p.version, v);
            assert!(p.mls && !p.reject_unknown && !p.allow_unknown);
            assert_eq!(p.classes.len(), 13);
            assert_eq!(p.class(p.process_class).unwrap().name, "process");
            assert_eq!(p.process_trans_perms, (1 << 1) | (1 << 23));
            assert_eq!(p.name(sym::CLASSES, 1), Some("security"));
            // The types, the attributes and the role object_r.
            assert_eq!(count(&p.types), 18);
            assert_eq!(value(&p, sym::TYPES, "sbin_t"), value(&p, sym::TYPES, "bin_t"));
            assert!(p.ty(value(&p, sym::TYPES, "domain")).unwrap().attribute);
            assert_eq!(p.role(OBJECT_R_VAL).unwrap().name, "object_r");
            assert_eq!(p.roles.len(), 3);
            assert_eq!(p.users.len(), 2);
            assert_eq!(count(&p.sens), 2);
            assert_eq!(value(&p, sym::LEVELS, "s1a"), 2);
            assert_eq!(count(&p.cats), 3);
            assert_eq!(value(&p, sym::CATS, "cx"), 3);
            assert_eq!(p.bools.len(), 2);
            assert_eq!(p.cond.len(), 2);
            assert_eq!(p.ocon.isid.len(), 7);
            assert_eq!(p.ocon.fsuse.len(), 5);
            assert_eq!(p.ocon.port.len(), 2);
            assert_eq!(p.ocon.netif.len(), 1);
            assert_eq!(p.ocon.node.len(), 1);
            assert_eq!(p.ocon.node6.len(), 1);
            assert_eq!(p.range_tr.len(), 1);
            assert_eq!(p.role_tr.len(), 1);
            assert_eq!(p.role_allow.len(), 1);
            assert_eq!(p.filename_tr.len(), usize::from(v >= 25));
        }
    }

    #[test]
    fn the_symbols_have_their_attributes() {
        let p = Policydb::read(V35).unwrap();
        // policycap network_peer_controls, open_perms, extended_socket_class and
        // genfs_seclabel_symlinks.
        assert_eq!(p.policycaps.iter().collect::<Vec<_>>(), [0, 1, 2, 6]);
        let unconfined = value(&p, sym::TYPES, "unconfined_t");
        assert_eq!(p.permissive.iter().collect::<Vec<_>>(), [unconfined]);
        let child = value(&p, sym::TYPES, "child_t");
        assert_eq!(p.ty(child).unwrap().bounds, unconfined);
        assert!(p.type_bounded_by(child, unconfined));
        assert!(!p.type_bounded_by(unconfined, child));
        assert!(!p.type_bounded_by(child, value(&p, sym::TYPES, "kernel_t")));
        let file = p.class_value("file").unwrap();
        let class = p.class(file).unwrap();
        assert_eq!(p.commons[class.common.unwrap()].name, "file");
        assert_eq!(p.perm_bit(file, "ioctl"), Some(1));
        assert_eq!(p.perm_bit(file, "entrypoint"), Some(1 << 26));
        assert_eq!(p.perm_bit(file, "search"), None);
        assert_eq!(class.default_range, default::TARGET_LOW);
        assert_eq!(class.constraints.len(), 2);
        assert_eq!(class.validatetrans.len(), 1);
        let dir = p.class(p.class_value("dir").unwrap()).unwrap();
        assert_eq!(dir.default_type, default::TARGET);
        let process = p.class(p.process_class).unwrap();
        assert_eq!((process.default_user, process.default_role), (1, 1));
        let system_u = p.user(value(&p, sym::USERS, "system_u")).unwrap();
        assert_eq!(system_u.range.low.sens, 1);
        assert_eq!(system_u.range.high.sens, 2);
        assert_eq!(system_u.range.high.cats.iter().collect::<Vec<_>>(), [0, 1, 2]);
        let init = value(&p, sym::TYPES, "init_t");
        let domain = value(&p, sym::TYPES, "domain");
        let attrs: Vec<u32> = p.type_attr_map[init as usize - 1].iter().collect();
        assert!(attrs.contains(&(init - 1)) && attrs.contains(&(domain - 1)));
    }

    #[test]
    fn the_rules_are_there() {
        let p = Policydb::read(V35).unwrap();
        let t = |n| value(&p, sym::TYPES, n);
        let process = p.process_class;
        let file = p.class_value("file").unwrap();
        let rule = p.te.find(t("kernel_t"), t("init_t"), process as u16, spec::ALLOWED);
        assert_eq!(rule.map(|e| e.data), p.perm_bit(process, "transition"));
        let rule = p.te.find(t("kernel_t"), t("init_exec_t"), process as u16, spec::TRANSITION);
        assert_eq!(rule.map(|e| e.data), Some(t("init_t")));
        let rule = p.te.find(t("init_t"), t("proc_t"), file as u16, spec::AUDITDENY);
        assert_eq!(rule.map(|e| e.data), Some(!p.perm_bit(file, "write").unwrap()));
        // checkpolicy can keep the attributes of the rule or give a rule for each type.
        let xperms = p.te.entries().find(|e| e.specified() & spec::XPERMS_ALLOWED != 0);
        let x = xperms.unwrap().xperms.as_ref().unwrap();
        assert_eq!(x.driver, 0x89);
        let n = |b: u32| x.perms[b as usize / 32] & (1 << (b % 32)) != 0;
        assert!(n(0x10) && !n(0x11) && n(0x12) && n(0x20) && !n(0x21));
        // allow_exec is true and secure_mode is false: both blocks are on.
        assert!(p.cond_active(0, true) && p.cond_active(1, true));
        let on = p.te_cond.entries().filter(|e| p.cond_active(e.cond_node(), e.cond_list()));
        assert_eq!(on.count(), 2);
        let tmpfs = t("tmpfs_t");
        let dir = p.class_value("dir").unwrap();
        let named = p.filename_tr.get(&(tmpfs, dir, String::from("named"))).unwrap();
        assert_eq!(named[0].1, t("bin_t"));
        assert!(named[0].0.get(t("init_t") - 1));
        let range = p.range_tr.get(&(t("kernel_t"), t("init_exec_t"), process)).unwrap();
        assert_eq!((range.low.sens, range.high.sens), (1, 2));
    }

    #[test]
    fn the_object_contexts_are_there() {
        let p = Policydb::read(V33).unwrap();
        let t = |n| value(&p, sym::TYPES, n);
        let kernel = p.ocon.isid.iter().find(|o| o.key == 1).unwrap();
        assert_eq!(kernel.context.ty, t("kernel_t"));
        assert_eq!(kernel.context.range.high.sens, 2);
        let devnull = p.ocon.isid.iter().find(|o| o.key == 27).unwrap();
        assert_eq!(devnull.context.ty, t("devnull_t"));
        let uses: Vec<(&str, u32)> =
            p.ocon.fsuse.iter().map(|o| (o.key.fstype.as_str(), o.key.behavior)).collect();
        assert!(uses.contains(&("ext4", fs_use::XATTR)));
        assert!(uses.contains(&("tmpfs", fs_use::TRANS)));
        assert!(uses.contains(&("pipefs", fs_use::TASK)));
        let names: Vec<&str> = p.genfs.iter().map(|g| g.0.as_str()).collect();
        assert_eq!(names, ["proc", "selinuxfs", "sysfs"]);
        let proc: Vec<&str> = p.genfs[0].1.iter().map(|g| g.path.as_str()).collect();
        assert_eq!(proc, ["/kmsg", "/sys", "/"]);
        assert_eq!(p.genfs[0].1[0].sclass, p.class_value("file").unwrap());
        assert_eq!(p.ocon.port[1].key, Port { protocol: 17, low: 1000, high: 2000 });
        assert_eq!(p.ocon.node[0].key.0, u32::from_ne_bytes([127, 0, 0, 1]));
        assert!(p.ocon.netif[0].context2.is_some());
    }

    #[test]
    fn a_bad_policy_is_an_error() {
        assert_eq!(Policydb::read(&[]).unwrap_err(), Error::Truncated);
        let mut bad = V33.to_vec();
        bad[0] ^= 1;
        assert_eq!(Policydb::read(&bad).unwrap_err(), Error::Invalid("magic number"));
        let mut bad = V33.to_vec();
        bad[16..20].copy_from_slice(&36u32.to_le_bytes());
        assert_eq!(Policydb::read(&bad).unwrap_err(), Error::Invalid("policy version"));
        let mut bad = V33.to_vec();
        bad[20..24].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(Policydb::read(&bad).unwrap_err(), Error::Invalid("handle unknown"));
        // Each policy that ends early is an error.
        for len in (0..V33.len()).step_by(7) {
            assert!(Policydb::read(&V33[..len]).is_err(), "{len}");
        }
    }

    #[test]
    fn a_policy_from_an_environment_variable_reads() {
        // The test reads a policy of a distribution, as the targeted policy of Fedora, when
        // RK_SELINUX_POLICY gives its path.
        let Ok(path) = std::env::var("RK_SELINUX_POLICY") else { return };
        let data = std::fs::read(path).unwrap();
        let p = Policydb::read(&data).unwrap();
        assert!(p.types.len() > 1000 && p.rules() > 10_000);
        std::println!(
            "version {} classes {} types {} rules {} bools {}",
            p.version,
            p.classes.len(),
            p.types.len(),
            p.rules(),
            p.bools.len()
        );
    }
}

//! The unpack of a binary policy, as security/apparmor/policy_unpack.c and policy_compat.c of
//! Linux.
//!
//! The policy compiler writes each profile as a stream of typed elements. Each element is a
//! type byte and its data. An element can have a name before it, as the type `NAME` and a
//! text. The kernel looks for the names to find the optional parts.
//!
//! A policy can have more than one profile. The first profile has a header with the version of
//! the format, and each profile can have a header. The versions 5 to 9 are known.

use crate::dfa::{self, Dfa, State};
use crate::policy::Mode;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;

/// The type codes of the elements, `enum aa_code` of Linux.
mod code {
    pub(super) const U8: u8 = 0;
    pub(super) const U32: u8 = 2;
    pub(super) const U64: u8 = 3;
    pub(super) const NAME: u8 = 4;
    pub(super) const STRING: u8 = 5;
    pub(super) const BLOB: u8 = 6;
    pub(super) const STRUCT: u8 = 7;
    pub(super) const STRUCTEND: u8 = 8;
    pub(super) const ARRAY: u8 = 11;
    pub(super) const ARRAYEND: u8 = 12;
}

/// The mask of the version of the format in the version word, `K_ABI_MASK`.
pub const ABI_MASK: u32 = 0x3ff;
/// The version flag that puts each profile in complain mode, `FORCE_COMPLAIN_FLAG`.
const FORCE_COMPLAIN: u32 = 0x800;

/// The classes of the rules of a policy DFA, `AA_CLASS_*` of Linux.
pub mod class {
    /// The file rules.
    pub const FILE: usize = 2;
    /// The capability rules.
    pub const CAP: usize = 3;
    /// The attach rules.
    pub const XMATCH: usize = 11;
    /// The last class, `AA_CLASS_LAST`.
    pub const LAST: usize = 32;
}

/// The permission bits of a file rule, as include/file.h and perms.h of Linux.
pub mod perm {
    /// `AA_MAY_EXEC`.
    pub const EXEC: u32 = 0x1;
    /// `AA_MAY_WRITE`.
    pub const WRITE: u32 = 0x2;
    /// `AA_MAY_READ`.
    pub const READ: u32 = 0x4;
    /// `AA_MAY_APPEND`.
    pub const APPEND: u32 = 0x8;
    /// `AA_MAY_CREATE`.
    pub const CREATE: u32 = 0x10;
    /// `AA_MAY_DELETE`.
    pub const DELETE: u32 = 0x20;
    /// `AA_MAY_OPEN`.
    pub const OPEN: u32 = 0x40;
    /// `AA_MAY_RENAME`.
    pub const RENAME: u32 = 0x80;
    /// `AA_MAY_SETATTR`.
    pub const SETATTR: u32 = 0x100;
    /// `AA_MAY_GETATTR`.
    pub const GETATTR: u32 = 0x200;
    /// `AA_MAY_CHMOD`.
    pub const CHMOD: u32 = 0x1000;
    /// `AA_MAY_CHOWN`.
    pub const CHOWN: u32 = 0x2000;
    /// `AA_MAY_LOCK`, also `AA_LINK_SUBSET`.
    pub const LOCK: u32 = 0x8000;
    /// `AA_EXEC_MMAP`.
    pub const EXEC_MMAP: u32 = 0x1_0000;
    /// `AA_MAY_LINK`.
    pub const LINK: u32 = 0x4_0000;
    /// `AA_MAY_ONEXEC`.
    pub const ONEXEC: u32 = 0x2000_0000;
    /// `AA_MAY_CHANGE_PROFILE`.
    pub const CHANGE_PROFILE: u32 = 0x4000_0000;
    /// `AA_MAY_CHANGEHAT`.
    pub const CHANGEHAT: u32 = 0x8000_0000;
}

/// The bits of the exec index of a permission, `AA_X_*` of Linux.
pub mod x {
    /// The index into the transition table, `AA_X_INDEX_MASK`.
    pub const INDEX_MASK: u32 = 0x00ff_ffff;
    /// The kind of the transition, `AA_X_TYPE_MASK`.
    pub const TYPE_MASK: u32 = 0x0c00_0000;
    /// The profile with the name of the program, `AA_X_NAME`.
    pub const NAME: u32 = 0x0400_0000;
    /// A name of the transition table, `AA_X_TABLE`.
    pub const TABLE: u32 = 0x0800_0000;
    /// The environment is not cleaned, `AA_X_UNSAFE`.
    pub const UNSAFE: u32 = 0x1000_0000;
    /// A child profile, `AA_X_CHILD`.
    pub const CHILD: u32 = 0x2000_0000;
    /// The same profile, `AA_X_INHERIT`.
    pub const INHERIT: u32 = 0x4000_0000;
    /// No profile, `AA_X_UNCONFINED`.
    pub const UNCONFINED: u32 = 0x8000_0000;
}

/// The permissions of an accept state, `struct aa_perms` of Linux.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Perms {
    /// The allowed operations.
    pub allow: u32,
    /// The denied operations.
    pub deny: u32,
    /// The operations allowed in the subtree.
    pub subtree: u32,
    /// The operations allowed on a condition.
    pub cond: u32,
    /// The operations that kill the task.
    pub kill: u32,
    /// The operations in complain mode.
    pub complain: u32,
    /// The operations that ask user space.
    pub prompt: u32,
    /// The operations to log.
    pub audit: u32,
    /// The operations not to log.
    pub quiet: u32,
    /// The operations to hide.
    pub hide: u32,
    /// The exec transition ([`x`]).
    pub xindex: u32,
    /// The index of the tag set.
    pub tag: u32,
    /// The index of the label in the transition table.
    pub label: u32,
}

/// An entry of a table of texts, `struct aa_str_table_ent` of Linux. A multi entry has more
/// than one text, each ending with a 0 byte.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StrEnt {
    /// The bytes with the 0 bytes.
    pub text: Vec<u8>,
    /// The count of the texts.
    pub count: u32,
}

/// The tags of a policy DB, `struct aa_tags_struct` of Linux.
#[derive(Clone, Debug, Default)]
pub struct Tags {
    /// The texts of the tags.
    pub strs: Vec<StrEnt>,
    /// The headers: mask, count, size and index of the texts.
    pub hdrs: Vec<[u32; 4]>,
    /// The sets: a count and the indexes of the headers.
    pub sets: Vec<u32>,
}

/// A policy DB, `struct aa_policydb` of Linux: a DFA, its permissions and the start states.
#[derive(Clone, Debug)]
pub struct Pdb {
    /// The DFA, if there is one.
    pub dfa: Option<Dfa>,
    /// The permission table. The accept table of the DFA has the indexes.
    pub perms: Vec<Perms>,
    /// The start state of each class.
    pub start: [State; class::LAST + 1],
    /// The transition table of the exec rules.
    pub trans: Vec<StrEnt>,
    /// The tags.
    pub tags: Tags,
}

impl Default for Pdb {
    fn default() -> Self {
        Self {
            dfa: None,
            perms: Vec::new(),
            start: [dfa::START; class::LAST + 1],
            trans: Vec::new(),
            tags: Tags::default(),
        }
    }
}

/// The capability rules of a profile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caps {
    /// The allowed capabilities.
    pub allow: u64,
    /// The capabilities to log.
    pub audit: u64,
    /// The capabilities not to log.
    pub quiet: u64,
    /// The capabilities that the policy DB mediates, `extended`.
    pub extended: u64,
}

/// A profile as the unpack gives it, before the load puts it in a namespace.
#[derive(Clone, Debug)]
pub struct Unpacked {
    /// The full name, with `//` between a parent and a child.
    pub name: String,
    /// The namespace of the name, `:NS:NAME`.
    pub ns: Option<String>,
    /// The profile that this profile replaces, `rename`.
    pub rename: Option<String>,
    /// The attach text, `attach`.
    pub attach: Option<String>,
    /// The DFA of the attach.
    pub xmatch: Box<Pdb>,
    /// The length of the attach without the pattern, for the order of the matches.
    pub xmatch_len: u32,
    /// The path that a disconnected path gets, `disconnected`.
    pub disconnected: Option<String>,
    /// The signal of the kill mode.
    pub signal: u32,
    /// The profile is a hat.
    pub hat: bool,
    /// The mode.
    pub mode: Mode,
    /// Each operation is logged.
    pub audit: bool,
    /// The flags of the path names, `path_flags`.
    pub path_flags: u32,
    /// The capability rules.
    pub caps: Caps,
    /// The extended attributes of the attach.
    pub xattrs: Vec<String>,
    /// The mask of the limits and the hard limits.
    pub rlimits: (u32, Vec<u64>),
    /// The rules of the network marks: audit, deny and label.
    pub secmark: Vec<(u8, u8, String)>,
    /// The policy DB of the rules other than the file rules.
    pub policy: Arc<Pdb>,
    /// The policy DB of the file rules. It can be the same as `policy`.
    pub file: Arc<Pdb>,
    /// The key and value data, `data`.
    pub data: Vec<(String, Vec<u8>)>,
    /// The version word of the header of the profile.
    pub version: u32,
}

/// An error of the unpack: the error number, the text for the log and the name of the profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// The error number.
    pub errno: Errno,
    /// The text of the log, `info`.
    pub info: &'static str,
    /// The name of the profile, if the unpack found it.
    pub name: Option<String>,
    /// The offset in the data where the unpack stopped.
    pub pos: usize,
}

/// The read head of the data, `struct aa_ext` of Linux.
struct Ext<'a> {
    data: &'a [u8],
    pos: usize,
    version: u32,
}

impl<'a> Ext<'a> {
    fn inbounds(&self, n: usize) -> bool {
        self.data.len() - self.pos >= n
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if !self.inbounds(n) {
            return None;
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }

    /// Runs `f` and puts the head back if it fails.
    fn try_<T>(&mut self, f: impl FnOnce(&mut Self) -> Option<T>) -> Option<T> {
        let pos = self.pos;
        let r = f(self);
        if r.is_none() {
            self.pos = pos;
        }
        r
    }

    fn le16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }

    fn le32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A chunk with a 16-bit size, `aa_unpack_u16_chunk`.
    fn u16_chunk(&mut self) -> Option<&'a [u8]> {
        self.try_(|e| {
            let n = e.le16()?;
            e.take(usize::from(n))
        })
    }

    /// The type byte `code`, `aa_unpack_X`.
    fn x(&mut self, code: u8) -> bool {
        if self.data.get(self.pos) == Some(&code) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// The type byte `code` after an optional name, which must be `name` if `name` is set,
    /// `aa_unpack_nameX`.
    fn name_x(&mut self, code: u8, name: Option<&str>) -> bool {
        self.try_(|e| {
            if e.x(code::NAME) {
                let tag = e.u16_chunk().unwrap_or(&[]);
                if let Some(name) = name {
                    let end = tag.iter().position(|&b| b == 0)?;
                    if tag.last() != Some(&0) || &tag[..end] != name.as_bytes() {
                        return None;
                    }
                }
            } else if name.is_some() {
                return None;
            }
            e.x(code).then_some(())
        })
        .is_some()
    }

    fn u8(&mut self, name: Option<&str>) -> Option<u8> {
        self.try_(|e| {
            if !e.name_x(code::U8, name) {
                return None;
            }
            e.take(1).map(|b| b[0])
        })
    }

    fn u32(&mut self, name: Option<&str>) -> Option<u32> {
        self.try_(|e| if e.name_x(code::U32, name) { e.le32() } else { None })
    }

    fn u64(&mut self, name: Option<&str>) -> Option<u64> {
        self.try_(|e| {
            if !e.name_x(code::U64, name) {
                return None;
            }
            e.take(8).map(|b| u64::from_le_bytes(b.try_into().unwrap_or([0; 8])))
        })
    }

    /// The start of an array and its count, `aa_unpack_array`.
    fn array(&mut self, name: Option<&str>) -> Option<u16> {
        self.try_(|e| if e.name_x(code::ARRAY, name) { e.le16() } else { None })
    }

    /// A blob with a 32-bit size, `aa_unpack_blob`. An empty blob is not there.
    fn blob(&mut self, name: Option<&str>) -> Option<&'a [u8]> {
        self.try_(|e| {
            if !e.name_x(code::BLOB, name) {
                return None;
            }
            let n = e.le32()? as usize;
            e.take(n).filter(|b| !b.is_empty())
        })
    }

    /// A text that ends with a 0 byte, `aa_unpack_str`. It gives the bytes with the 0 byte.
    fn str_raw(&mut self, name: Option<&str>) -> Option<&'a [u8]> {
        self.try_(|e| {
            if !e.name_x(code::STRING, name) {
                return None;
            }
            e.u16_chunk().filter(|s| s.last() == Some(&0))
        })
    }

    /// A text without its 0 byte.
    fn string(&mut self, name: Option<&str>) -> Option<String> {
        let raw = self.str_raw(name)?;
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        Some(String::from_utf8_lossy(&raw[..end]).into_owned())
    }
}

/// An error of the unpack at the head `e`.
fn fail(e: &Ext<'_>, errno: Errno, info: &'static str) -> Error {
    Error { errno, info, name: None, pos: e.pos }
}

type R<T> = core::result::Result<T, Error>;

/// Checks an entry of a table of texts and gives the count of its texts, as
/// `process_strs_entry` of Linux. In a multi entry, a text `:NS` and the next text are one
/// text `:NS:NAME`.
fn strs_entry(s: &mut [u8], multi: bool) -> Option<u32> {
    let size = s.len();
    if size == 0 || (multi && (size < 2 || s[size - 2] != 0)) {
        return None;
    }
    let end = if multi { size - 2 } else { size - 1 };
    let mut c = 1;
    let mut start = 0;
    for i in 0..end {
        if i == start {
            if s[i] == 0 || s[i].is_ascii_whitespace() || (s[i] == b':' && s[i + 1] == 0) {
                return None;
            }
        } else if s[i] == 0 {
            if s[start] == b':' {
                s[i] = b':';
            } else {
                c += 1;
            }
            start = i + 1;
        }
    }
    Some(c)
}

/// A table of texts, `unpack_strs_table` of Linux. A table that is not there is empty.
fn strs_table(e: &mut Ext<'_>, name: &str, multi: bool) -> R<Vec<StrEnt>> {
    let pos = e.pos;
    let mut table = Vec::new();
    if !e.name_x(code::STRUCT, Some(name)) {
        return Ok(table);
    }
    let mut body = || -> Option<()> {
        let n = e.array(None)?;
        for _ in 0..n {
            let mut text = e.str_raw(None)?.to_vec();
            let count = strs_entry(&mut text, multi)?;
            if !multi && count > 1 {
                return None;
            }
            table.push(StrEnt { text, count });
        }
        (e.name_x(code::ARRAYEND, None) && e.name_x(code::STRUCTEND, None)).then_some(())
    };
    if body().is_none() {
        e.pos = pos;
        return Err(fail(e, Errno::EPROTO, "failed to unpack the string table"));
    }
    Ok(table)
}

/// The tags of a policy DB, `unpack_tags` and `verify_tags` of Linux.
fn tags(e: &mut Ext<'_>) -> R<Tags> {
    let pos = e.pos;
    let mut t = Tags::default();
    if !e.name_x(code::STRUCT, Some("tags")) {
        return Ok(t);
    }
    let bad = |e: &mut Ext<'_>, info| {
        e.pos = pos;
        Err(fail(e, Errno::EPROTO, info))
    };
    if e.u32(Some("version")) != Some(1) {
        return bad(e, "invalid tags version");
    }
    t.strs = strs_table(e, "strs", true)?;
    let hdrs = e.try_(|e| {
        let n = e.array(Some("hdrs"))?;
        let mut h = Vec::new();
        for _ in 0..n {
            h.push([e.u32(None)?, e.u32(None)?, e.u32(None)?, e.u32(None)?]);
        }
        e.name_x(code::ARRAYEND, None).then_some(h)
    });
    let Some(hdrs) = hdrs else { return bad(e, "failed to unpack profile tag.headers") };
    t.hdrs = hdrs;
    let sets = e.try_(|e| {
        let n = e.array(Some("sets"))?;
        let mut s = Vec::new();
        for _ in 0..n {
            s.push(e.u32(None)?);
        }
        e.name_x(code::ARRAYEND, None).then_some(s)
    });
    let Some(sets) = sets else { return bad(e, "failed to unpack profile tag.sets") };
    t.sets = sets;
    if !e.name_x(code::STRUCTEND, None) {
        return bad(e, "failed to unpack profile tags");
    }
    let none = t.sets.is_empty() && t.hdrs.is_empty() && t.strs.is_empty();
    if none {
        return Ok(t);
    }
    if t.sets.is_empty() || t.hdrs.is_empty() || t.strs.is_empty() {
        return bad(e, "failed verification tags partial data present");
    }
    let mut i = 0;
    while i < t.sets.len() {
        let cnt = t.sets[i] as usize;
        if i + cnt >= t.sets.len() {
            return bad(e, "failed verification tagset too large");
        }
        for _ in 0..cnt {
            i += 1;
            if t.sets[i] as usize >= t.hdrs.len() {
                return bad(e, "failed verification tagsets idx out of bounds");
            }
        }
        i += 1;
    }
    for h in &t.hdrs {
        let Some(s) = t.strs.get(h[3] as usize) else {
            return bad(e, "failed verification tags.hdrs idx out of bounds");
        };
        if h[1] != s.count || h[2] as usize != s.text.len() {
            return bad(e, "failed verification tagd.hdrs[idx].count");
        }
    }
    Ok(t)
}

/// The permission table of a policy DB, `unpack_perms_table` of Linux. `None` if it is not
/// there: the permissions are in the accept tables of the DFA.
fn perms_table(e: &mut Ext<'_>) -> R<Option<Vec<Perms>>> {
    let pos = e.pos;
    if !e.name_x(code::STRUCT, Some("perms")) {
        return Ok(None);
    }
    let table = e.try_(|e| {
        let version = e.u32(Some("version"))?;
        let n = e.array(None)?;
        if version != 1 {
            return None;
        }
        let mut t = Vec::new();
        for _ in 0..n {
            let _reserved = e.u32(None)?;
            let mut f = [0u32; 13];
            for v in &mut f {
                *v = e.u32(None)?;
            }
            let [
                allow,
                deny,
                subtree,
                cond,
                kill,
                complain,
                prompt,
                audit,
                quiet,
                hide,
                xindex,
                tag,
                label,
            ] = f;
            t.push(Perms {
                allow,
                deny,
                subtree,
                cond,
                kill,
                complain,
                prompt,
                audit,
                quiet,
                hide,
                xindex,
                tag,
                label,
            });
        }
        (e.name_x(code::ARRAYEND, None) && e.name_x(code::STRUCTEND, None)).then_some(t)
    });
    match table {
        Some(t) => Ok(Some(t)),
        None => {
            e.pos = pos;
            Err(fail(e, Errno::EPROTO, "failed to unpack - perms"))
        }
    }
}

/// The DFA blob `aadfa`, `unpack_dfa` of Linux. The DFA starts at an offset aligned to 8 bytes
/// in the stream.
fn unpack_dfa(e: &mut Ext<'_>, flags: u32) -> R<Option<Dfa>> {
    let Some(blob) = e.blob(Some("aadfa")) else { return Ok(None) };
    let at = e.pos - blob.len();
    let sz = at.wrapping_sub(e.pos & 7);
    let pad = ((sz + 7) & !7) - sz;
    let body = blob.get(pad..).ok_or(fail(e, Errno::EPROTO, "failed to unpack - dfa"))?;
    Dfa::unpack(body, flags).map(Some).map_err(|errno| fail(e, errno, "failed to unpack - dfa"))
}

/// A policy DB, `unpack_pdb` of Linux.
fn unpack_pdb(e: &mut Ext<'_>, required_dfa: bool, required_trans: bool) -> R<Box<Pdb>> {
    let pos = e.pos;
    let r = (|| {
        let mut pdb = Box::new(Pdb { tags: tags(e)?, ..Pdb::default() });
        let perms = perms_table(e)?;
        let flags = if perms.is_some() {
            let v2 = e.u32(Some("permsv")).is_some_and(|v| v > 2);
            dfa::accept_flags(dfa::DATA32, if v2 { dfa::DATA32 } else { 0 })
        } else {
            dfa::accept_flags(dfa::DATA32, dfa::DATA32)
        };
        let has_perms = perms.is_some();
        pdb.perms = perms.unwrap_or_default();
        pdb.dfa = unpack_dfa(e, flags)?;
        match &mut pdb.dfa {
            None if required_dfa => return Err(fail(e, Errno::EPROTO, "missing required dfa")),
            None => {}
            Some(d) => {
                pdb.start[0] = e.u32(Some("start")).unwrap_or(dfa::START);
                pdb.start[class::FILE] = e.u32(Some("dfa_start")).unwrap_or(dfa::START);
                let states = d.states();
                if pdb.start[0] as usize >= states || pdb.start[class::FILE] as usize >= states {
                    return Err(fail(e, Errno::EPROTO, "invalid dfa start state"));
                }
                for i in class::FILE + 1..=class::LAST {
                    pdb.start[i] = d.next(pdb.start[0], i as u8);
                }
                if has_perms && !d.has_accept2() {
                    d.add_accept2();
                }
            }
        }
        // A transition table can be there without a DFA, from an old compiler.
        match strs_table(e, "xtable", false) {
            Ok(t) => pdb.trans = t,
            Err(err) if required_trans => {
                return Err(Error { info: "failed to unpack profile transition table", ..err });
            }
            Err(_) => {}
        }
        if pdb.dfa.is_none() {
            pdb.trans.clear();
        }
        Ok(pdb)
    })();
    if r.is_err() {
        e.pos = pos;
    }
    r
}

/// The old exec index of an accept entry, `dfa_map_xindex` of Linux.
fn map_xindex(mask: u32) -> u32 {
    let old = (mask >> 10) & 0xf;
    let mut index = 0;
    if mask & 0x100 != 0 {
        index |= x::UNSAFE;
    }
    if mask & 0x200 != 0 {
        index |= x::INHERIT;
    }
    if mask & 0x80 != 0 {
        index |= x::UNCONFINED;
    }
    match old {
        0 => {}
        1 => index |= x::UNCONFINED,
        2 => index |= x::NAME,
        3 => index |= x::NAME | x::CHILD,
        _ => index |= x::TABLE | (old - 4),
    }
    index
}

/// The old file permissions, `map_old_perms` of Linux.
fn map_old_perms(old: u32) -> u32 {
    let mut new = old & 0xf;
    if old & perm::READ != 0 {
        new |= perm::GETATTR | perm::OPEN;
    }
    if old & perm::WRITE != 0 {
        new |= perm::SETATTR | perm::CREATE | perm::DELETE | perm::CHMOD | perm::CHOWN | perm::OPEN;
    }
    if old & 0x10 != 0 {
        new |= perm::LINK;
    }
    if old & 0x20 != 0 {
        new |= perm::LOCK;
    }
    if old & 0x40 != 0 {
        new |= perm::EXEC_MMAP;
    }
    new
}

/// The parts of an old accept entry, the macros `dfa_user_*` and `dfa_other_*` of Linux.
struct OldAccept {
    a1: u32,
    a2: u32,
}

impl OldAccept {
    fn user_allow(&self) -> u32 {
        (self.a1 & 0x7f) | (self.a1 & 0x8000_0000)
    }
    fn user_xbits(&self) -> u32 {
        (self.a1 >> 7) & 0x7f
    }
    fn user_audit(&self) -> u32 {
        self.a2 & 0x7f
    }
    fn user_quiet(&self) -> u32 {
        (self.a2 >> 7) & 0x7f
    }
    fn other_allow(&self) -> u32 {
        ((self.a1 >> 14) & 0x7f) | (self.a1 & 0x8000_0000)
    }
    fn other_xbits(&self) -> u32 {
        (self.a1 >> 21) & 0x7f
    }
    fn other_audit(&self) -> u32 {
        (self.a2 >> 14) & 0x7f
    }
    fn other_quiet(&self) -> u32 {
        (self.a2 >> 21) & 0x7f
    }

    /// The file permissions of the owner or of the others, `compute_fperms_user` and
    /// `compute_fperms_other` of Linux.
    fn fperms(&self, other: bool) -> Perms {
        let (allow, audit, quiet, xi) = if other {
            (self.other_allow(), self.other_audit(), self.other_quiet(), (self.a1 >> 14) & 0x3fff)
        } else {
            (self.user_allow(), self.user_audit(), self.user_quiet(), self.a1 & 0x3fff)
        };
        let mut p = Perms {
            allow: map_old_perms(allow) | perm::GETATTR,
            audit: map_old_perms(audit),
            quiet: map_old_perms(quiet),
            xindex: map_xindex(xi),
            ..Perms::default()
        };
        if self.a1 & 0x8000_0000 != 0 {
            p.allow |= perm::CHANGE_PROFILE;
        }
        if self.a1 & 0x4000_0000 != 0 {
            p.allow |= perm::ONEXEC;
        }
        p
    }

    /// The permissions of a rule of the policy DB, `compute_perms_entry` of Linux.
    fn perms(&self, version: u32) -> Perms {
        let map_other = |x: u32| ((x & 0x3) << 8) | ((x & 0x1c) << 18) | ((x & 0x60) << 19);
        let map_xbits = |x: u32| ((x & 0x1) << 7) | ((x & 0x7e) << 9);
        let mut p = Perms {
            allow: self.user_allow() | map_other(self.other_allow()),
            audit: self.user_audit() | map_other(self.other_audit()),
            quiet: self.user_quiet() | map_other(self.other_quiet()),
            ..Perms::default()
        };
        if version & ABI_MASK <= 8 {
            p.allow |= perm::LOCK;
        } else {
            p.allow |= map_xbits(self.user_xbits());
            p.quiet |= map_xbits(self.other_xbits());
        }
        p
    }
}

/// How the permissions of an old DFA are in its accept tables.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Compat {
    /// The attach DFA, `aa_compat_map_xmatch`.
    Xmatch,
    /// The policy DB, `aa_compat_map_policy`.
    Policy(u32),
    /// The file DFA, `aa_compat_map_file`, with an entry for the owner and one for the others.
    File,
}

/// Makes the permission table of a DFA that has its permissions in the accept tables.
fn compat_map(pdb: &mut Pdb, how: Compat) {
    let Some(d) = &mut pdb.dfa else { return };
    let n = d.states();
    let acc = |s: usize| OldAccept {
        a1: d.accept().get(s).copied().unwrap_or(0),
        a2: d.accept2().get(s).copied().unwrap_or(0),
    };
    let mut perms = Vec::with_capacity(if how == Compat::File { 2 * n } else { n });
    for s in 0..n {
        let a = acc(s);
        match how {
            // The file map of Linux does not skip the trap state 0.
            Compat::File => {
                perms.push(a.fperms(false));
                perms.push(a.fperms(true));
            }
            // The other maps give no permissions to the trap state 0.
            _ if s == 0 => perms.push(Perms::default()),
            Compat::Xmatch => perms.push(Perms { allow: a.user_allow(), ..Perms::default() }),
            Compat::Policy(v) => perms.push(a.perms(v)),
        }
    }
    pdb.perms = perms;
    d.remap_accept(if how == Compat::File { 2 } else { 1 });
}

/// The parts of a full name `:NS:NAME` or `:NS://NAME`, `aa_splitn_fqname` of Linux. Gives the
/// name and the namespace.
pub fn split_fqname(fq: &str) -> (Option<&str>, Option<&str>) {
    let name = fq.trim_start();
    let Some(rest) = name.strip_prefix(':') else {
        return ((!name.is_empty()).then_some(name), None);
    };
    let rest = rest.trim_start();
    match rest.split_once(':') {
        Some((ns, after)) => {
            let after = after.strip_prefix("//").unwrap_or(after).trim_start();
            ((!after.is_empty()).then_some(after), (!ns.is_empty()).then_some(ns))
        }
        None => (None, (!rest.is_empty()).then_some(rest)),
    }
}

/// The largest signal that a kill mode can have, `MAXMAPPED_SIG`.
const MAXMAPPED_SIG: u32 = 35;
/// `SIGKILL`.
const SIGKILL: u32 = 9;

/// The default of `path_flags`, `PATH_MEDIATE_DELETED`.
const PATH_MEDIATE_DELETED: u32 = 0x10000;

/// A profile, `unpack_profile` of Linux. The profile is in a box, and each part of the unpack
/// is in its own function, so that the frames on the kernel stack stay small.
fn unpack_profile(e: &mut Ext<'_>) -> R<Box<Unpacked>> {
    let mut name_seen: Option<String> = None;
    let r = profile_body(e, &mut name_seen);
    // The log of a failure has the name of the profile, or `unknown` before the name.
    r.map_err(|err| Error { name: name_seen.or(err.name).or(Some(String::from("unknown"))), ..err })
}

/// The error of the profile unpack at the position of `e`.
fn bad(e: &Ext<'_>, info: &'static str) -> Error {
    fail(e, Errno::EPROTO, info)
}

#[inline(never)]
fn profile_body(e: &mut Ext<'_>, name_seen: &mut Option<String>) -> R<Box<Unpacked>> {
    if !e.name_x(code::STRUCT, Some("profile")) {
        return Err(bad(e, "failed to unpack profile"));
    }
    let full = e.string(None).filter(|s| !s.is_empty());
    let Some(full) = full else { return Err(bad(e, "failed to unpack profile")) };
    *name_seen = Some(full.clone());
    let (name, ns) = split_fqname(&full);
    if ns.is_some() && name.is_none() {
        return Err(bad(e, "empty profile name"));
    }
    let name = String::from(name.unwrap_or(&full));
    *name_seen = Some(name.clone());
    let ns = ns.map(String::from);
    let mut p = Box::new(Unpacked {
        name,
        ns,
        rename: None,
        attach: None,
        xmatch: Box::default(),
        xmatch_len: 0,
        disconnected: None,
        signal: SIGKILL,
        hat: false,
        mode: Mode::Enforce,
        audit: false,
        path_flags: PATH_MEDIATE_DELETED,
        caps: Caps::default(),
        xattrs: Vec::new(),
        rlimits: (0, Vec::new()),
        secmark: Vec::new(),
        policy: Arc::default(),
        file: Arc::default(),
        data: Vec::new(),
        version: e.version,
    });
    body_attach(e, &mut p)?;
    body_flags(e, &mut p)?;
    body_caps(e, &mut p)?;
    body_tables(e, &mut p)?;
    body_pdbs(e, &mut p)?;
    body_data(e, &mut p)?;
    if !e.name_x(code::STRUCTEND, None) {
        return Err(bad(e, "failed to unpack end of profile"));
    }
    Ok(p)
}

/// The names and the attach DFA of a profile.
#[inline(never)]
fn body_attach(e: &mut Ext<'_>, p: &mut Unpacked) -> R<()> {
    p.rename = e.string(Some("rename"));
    p.attach = e.string(Some("attach"));
    p.xmatch = unpack_pdb(e, false, false).map_err(|err| Error { info: "bad xmatch", ..err })?;
    if p.xmatch.dfa.is_some() {
        let Some(len) = e.u32(None) else { return Err(bad(e, "missing xmatch len")) };
        p.xmatch_len = len;
        p.xmatch.start[class::XMATCH] = dfa::START;
        if p.xmatch.perms.is_empty() {
            compat_map(&mut p.xmatch, Compat::Xmatch);
        }
    }
    p.disconnected = e.string(Some("disconnected"));
    p.signal = e.u32(Some("kill")).unwrap_or(SIGKILL);
    if !(1..=MAXMAPPED_SIG).contains(&p.signal) {
        return Err(bad(e, "profile kill.signal invalid value"));
    }
    Ok(())
}

/// The flags, the mode and the path flags of a profile.
#[inline(never)]
fn body_flags(e: &mut Ext<'_>, p: &mut Unpacked) -> R<()> {
    if !e.name_x(code::STRUCT, Some("flags")) {
        return Err(bad(e, "profile missing flags"));
    }
    let flags = e.u32(None);
    let packed_mode = e.u32(None);
    let audit = e.u32(None);
    let (Some(flags), Some(packed_mode), Some(audit)) = (flags, packed_mode, audit) else {
        return Err(bad(e, "failed to unpack profile flags"));
    };
    p.mode = match packed_mode {
        _ if packed_mode == 1 || e.version & FORCE_COMPLAIN != 0 => Mode::Complain,
        0 => Mode::Enforce,
        2 => Mode::Kill,
        3 => Mode::Unconfined,
        4 => Mode::User,
        _ => return Err(bad(e, "failed to unpack profile flags")),
    };
    if !e.name_x(code::STRUCTEND, None) {
        return Err(bad(e, "failed to unpack profile flags"));
    }
    p.hat = flags & 1 != 0;
    p.audit = audit != 0;
    p.path_flags = e.u32(Some("path_flags")).unwrap_or(PATH_MEDIATE_DELETED);
    Ok(())
}

/// The capability rules of a profile.
#[inline(never)]
fn body_caps(e: &mut Ext<'_>, p: &mut Unpacked) -> R<()> {
    let mut low = [0u32; 4];
    for v in &mut low {
        *v = e.u32(None).ok_or_else(|| bad(e, "failed to unpack profile capabilities"))?;
    }
    let mut high = [0u32; 4];
    if e.name_x(code::STRUCT, Some("caps64")) {
        for v in &mut high {
            *v =
                e.u32(None).ok_or_else(|| bad(e, "failed to unpack upper profile capabilities"))?;
        }
        if !e.name_x(code::STRUCTEND, None) {
            return Err(bad(e, "failed to unpack upper profile capabilities"));
        }
    }
    let cap = |i: usize| u64::from(low[i]) | (u64::from(high[i]) << 32);
    p.caps.allow = cap(0);
    p.caps.audit = cap(1);
    p.caps.quiet = cap(2);
    if e.name_x(code::STRUCT, Some("capsx")) {
        let lo = e.u32(None);
        let hi = e.u32(None);
        let (Some(lo), Some(hi), true) = (lo, hi, e.name_x(code::STRUCTEND, None)) else {
            return Err(bad(e, "failed to unpack extended profile capabilities"));
        };
        p.caps.extended = u64::from(lo) | (u64::from(hi) << 32);
    }
    Ok(())
}

/// The tables of the extended attributes, the limits and the network marks of a profile.
#[inline(never)]
fn body_tables(e: &mut Ext<'_>, p: &mut Unpacked) -> R<()> {
    p.xattrs = e
        .try_(|e| {
            let mut out = Vec::new();
            if e.name_x(code::STRUCT, Some("xattrs")) {
                let n = e.array(None)?;
                for _ in 0..n {
                    out.push(e.string(None)?);
                }
                (e.name_x(code::ARRAYEND, None) && e.name_x(code::STRUCTEND, None)).then_some(())?;
            }
            Some(out)
        })
        .ok_or_else(|| bad(e, "failed to unpack profile xattrs"))?;
    p.rlimits = e
        .try_(|e| {
            let mut out = (0, Vec::new());
            if e.name_x(code::STRUCT, Some("rlimits")) {
                out.0 = e.u32(None)?;
                let n = e.array(None)?;
                if n > 16 {
                    return None;
                }
                for _ in 0..n {
                    out.1.push(e.u64(None)?);
                }
                (e.name_x(code::ARRAYEND, None) && e.name_x(code::STRUCTEND, None)).then_some(())?;
            }
            Some(out)
        })
        .ok_or_else(|| bad(e, "failed to unpack profile rlimits"))?;
    p.secmark = e
        .try_(|e| {
            let mut out = Vec::new();
            if e.name_x(code::STRUCT, Some("secmark")) {
                let n = e.array(None)?;
                for _ in 0..n {
                    out.push((e.u8(None)?, e.u8(None)?, e.string(None)?));
                }
                (e.name_x(code::ARRAYEND, None) && e.name_x(code::STRUCTEND, None)).then_some(())?;
            }
            Some(out)
        })
        .ok_or_else(|| bad(e, "failed to unpack profile secmark rules"))?;
    Ok(())
}

/// The policy DB and the file DB of a profile.
#[inline(never)]
fn body_pdbs(e: &mut Ext<'_>, p: &mut Unpacked) -> R<()> {
    if e.name_x(code::STRUCT, Some("policydb")) {
        let mut db = unpack_pdb(e, true, false)
            .map_err(|err| Error { info: "failed to unpack policydb", ..err })?;
        if let Some(d) = &db.dfa {
            let file = d.next(db.start[0], class::FILE as u8);
            if file != dfa::NOMATCH {
                db.start[class::FILE] = file;
            }
        }
        if !e.name_x(code::STRUCTEND, None) {
            return Err(bad(e, "failed to unpack policydb"));
        }
        if db.perms.is_empty() {
            compat_map(&mut db, Compat::Policy(e.version));
        }
        p.policy = Arc::from(db);
    }
    let mut file = unpack_pdb(e, false, true)?;
    if file.dfa.is_some() {
        if file.perms.is_empty() {
            compat_map(&mut file, Compat::File);
        }
        p.file = Arc::from(file);
    } else if p.policy.dfa.is_some() && p.policy.start[class::FILE] != dfa::NOMATCH {
        p.file = p.policy.clone();
    }
    Ok(())
}

/// The key and value data of a profile.
#[inline(never)]
fn body_data(e: &mut Ext<'_>, p: &mut Unpacked) -> R<()> {
    if e.name_x(code::STRUCT, Some("data")) {
        while let Some(key) = e.string(None) {
            let value = e.blob(None).map(<[u8]>::to_vec).unwrap_or_default();
            if p.data.iter().any(|(k, _)| *k == key) {
                return Err(bad(e, "failed to insert data to table"));
            }
            p.data.push((key, value));
        }
        if !e.name_x(code::STRUCTEND, None) {
            return Err(bad(e, "failed to unpack end of key, value data table"));
        }
    }
    Ok(())
}

/// Checks the header of a profile, `verify_header` of Linux. The first profile must have the
/// version. A later header keeps the version and the namespace.
fn verify_header(e: &mut Ext<'_>, required: bool, ns: &mut Option<String>) -> R<()> {
    let bad = |e: &Ext<'_>, info| fail(e, Errno::EPROTONOSUPPORT, info);
    match e.u32(Some("version")) {
        Some(v) => e.version = v,
        None if required => return Err(bad(e, "invalid profile format")),
        None => {}
    }
    let v = e.version & ABI_MASK;
    if !(5..=9).contains(&v) {
        return Err(bad(e, "unsupported interface version"));
    }
    if let Some(name) = e.string(Some("namespace")) {
        if name.is_empty() {
            return Err(bad(e, "invalid namespace name"));
        }
        match ns {
            Some(n) if *n != name => return Err(bad(e, "invalid ns change")),
            Some(_) => {}
            None => *ns = Some(name),
        }
    }
    Ok(())
}

/// Checks the indexes of an accept table, `verify_dfa_accept_index` of Linux.
fn verify_accept(pdb: &Pdb) -> bool {
    let Some(d) = &pdb.dfa else { return true };
    let size = pdb.perms.len();
    d.accept().iter().enumerate().all(|(i, &a)| {
        let owner = d.accept2().get(i).is_some_and(|f| f & dfa::ACCEPT_FLAG_OWNER != 0);
        (a as usize) < size && !(owner && a as usize + 1 >= size)
    })
}

/// Checks the permissions of a policy DB, `verify_perms` of Linux. The transition table loses
/// the entries that no permission uses at its end.
fn verify_perms(pdb: &mut Pdb) -> bool {
    let mut xmax: Option<usize> = None;
    for p in &pdb.perms {
        let bad = p.allow & p.deny != 0
            || p.subtree & !p.allow != 0
            || p.cond & (p.allow | p.deny) != 0
            || p.kill & p.allow != 0
            || p.complain & (p.allow | p.deny) != 0
            || p.prompt & (p.allow | p.deny) != 0
            || p.complain & p.prompt != 0
            || p.hide & p.allow != 0;
        if bad {
            return false;
        }
        if p.xindex & x::TYPE_MASK == x::TABLE {
            let i = (p.xindex & x::INDEX_MASK) as usize;
            if i >= pdb.trans.len() {
                return false;
            }
            xmax = Some(xmax.map_or(i, |m| m.max(i)));
        }
        if p.tag != 0 && p.tag as usize >= pdb.tags.sets.len() {
            return false;
        }
        if p.label != 0 && p.label as usize >= pdb.trans.len() {
            return false;
        }
    }
    match xmax {
        None => pdb.trans.clear(),
        Some(m) => pdb.trans.truncate(m + 1),
    }
    true
}

/// Checks a profile after the unpack, `verify_profile` of Linux.
fn verify_profile(p: &mut Unpacked) -> core::result::Result<(), &'static str> {
    if !verify_accept(&p.file) {
        return Err("Unpack: file Invalid named transition");
    }
    if !verify_accept(&p.policy) {
        return Err("Unpack: policy Invalid named transition");
    }
    let same = Arc::ptr_eq(&p.file, &p.policy);
    let ok = verify_perms(Arc::make_mut(&mut p.policy))
        && (same || verify_perms(Arc::make_mut(&mut p.file)))
        && verify_perms(&mut p.xmatch);
    if same {
        p.file = p.policy.clone();
    }
    if ok { Ok(()) } else { Err("Unpack: Invalid perm index") }
}

/// The result of the unpack of a policy: its profiles, the namespace of the header and the
/// version of the format.
#[derive(Debug)]
pub struct Policy {
    /// The profiles in the order of the data.
    pub profiles: Vec<Box<Unpacked>>,
    /// The namespace of the headers.
    pub ns: Option<String>,
    /// The version of the format, `abi`.
    pub abi: u32,
}

/// Unpacks the profiles of `data`, as `aa_unpack` of Linux.
///
/// # Errors
///
/// Gives an [`Error`] with `EPROTO` for data that is not correct, `EPROTONOSUPPORT` for a
/// version that is not known, and `ENOMEM` if the memory is full.
pub fn unpack(data: &[u8]) -> R<Policy> {
    let mut e = Ext { data, pos: 0, version: 0 };
    let mut ns = None;
    let mut profiles = Vec::new();
    while e.pos < data.len() {
        let first = e.pos == 0;
        verify_header(&mut e, first, &mut ns)?;
        let mut p = unpack_profile(&mut e)?;
        if let Err(info) = verify_profile(&mut p) {
            return Err(Error { errno: Errno::EPROTO, info, name: Some(p.name), pos: e.pos });
        }
        profiles.push(p);
    }
    if profiles.is_empty() {
        return Err(fail(&e, Errno::EPROTONOSUPPORT, "invalid profile format"));
    }
    Ok(Policy { profiles, ns, abi: e.version & ABI_MASK })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A policy of `apparmor_parser` 4.0.1 with the features of this kernel: the profile
    /// `rk_test` for `/usr/bin/rk-test` in complain mode with the hat `hat1`.
    const RK_TEST: &[u8] = include_bytes!("../tests/rk_test.bin");

    #[test]
    fn the_policy_of_the_compiler_unpacks() {
        let p = unpack(RK_TEST).unwrap();
        assert_eq!(p.abi, 7);
        assert_eq!(p.ns, None);
        let names: Vec<&str> = p.profiles.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["rk_test", "rk_test//hat1"]);
        let t = &p.profiles[0];
        assert_eq!(t.mode, Mode::Complain);
        assert!(!t.hat);
        assert!(p.profiles[1].hat);
        // The compiler gives the attach as the DFA of the attach only.
        let allow = |pdb: &Pdb, start: usize, path: &[u8], other: usize| {
            let d = pdb.dfa.as_ref().unwrap();
            let state = d.match_bytes(pdb.start[start], path);
            pdb.perms[d.accept()[state as usize] as usize + other].allow
        };
        assert_ne!(allow(&t.xmatch, class::XMATCH, b"/usr/bin/rk-test", 0), 0);
        assert_eq!(allow(&t.xmatch, class::XMATCH, b"/usr/bin/rk-tes", 0), 0);
        let read = allow(&t.file, class::FILE, b"/etc/hostname", 0);
        assert_eq!(read & (perm::READ | perm::WRITE), perm::READ);
        let other = allow(&t.file, class::FILE, b"/etc/hostname", 1);
        assert_eq!(other & (perm::READ | perm::WRITE), perm::READ);
        let tmp = allow(&t.file, class::FILE, b"/tmp/a/b", 0);
        assert_eq!(tmp & (perm::READ | perm::WRITE), perm::READ | perm::WRITE);
        assert_eq!(allow(&t.file, class::FILE, b"/etc/passwd", 0) & perm::READ, 0);
    }

    /// A small policy: the profile `rk_min` in complain mode, with no rules.
    pub(crate) const RK_MIN: &[u8] = b"\x04\x08\x00version\x00\x02\x07\x00\x00\x00\
        \x04\x08\x00profile\x00\x07\x05\x07\x00rk_min\x00\
        \x04\x06\x00flags\x00\x07\x02\x00\x00\x00\x00\x02\x01\x00\x00\x00\x02\x00\x00\x00\x00\x08\
        \x02\x00\x00\x00\x00\x02\x00\x00\x00\x00\x02\x00\x00\x00\x00\x02\x00\x00\x00\x00\x08";

    #[test]
    fn a_profile_with_no_rules_unpacks() {
        let p = unpack(RK_MIN).unwrap();
        assert_eq!(p.profiles.len(), 1);
        let m = &p.profiles[0];
        assert_eq!((m.name.as_str(), m.mode, m.signal), ("rk_min", Mode::Complain, SIGKILL));
        assert!(m.xmatch.dfa.is_none() && m.file.dfa.is_none() && m.policy.dfa.is_none());
        // Without the end of the profile, the unpack fails with the name of the profile.
        let e = unpack(&RK_MIN[..RK_MIN.len() - 1]).unwrap_err();
        assert_eq!((e.errno, e.info), (Errno::EPROTO, "failed to unpack end of profile"));
        assert_eq!(e.name.as_deref(), Some("rk_min"));
    }

    #[test]
    fn a_policy_that_is_not_correct_fails() {
        assert_eq!(unpack(b"").unwrap_err().errno, Errno::EPROTONOSUPPORT);
        assert_eq!(unpack(b"x").unwrap_err().errno, Errno::EPROTONOSUPPORT);
        let mut cut = RK_TEST.to_vec();
        cut.truncate(RK_TEST.len() / 2);
        assert_eq!(unpack(&cut).unwrap_err().errno, Errno::EPROTO);
        // The version 4 is too old.
        let mut old = RK_TEST.to_vec();
        old[12] = 4;
        assert_eq!(unpack(&old).unwrap_err().info, "unsupported interface version");
    }

    #[test]
    fn the_parts_of_a_name_and_a_table_of_texts() {
        assert_eq!(split_fqname("a//b"), (Some("a//b"), None));
        assert_eq!(split_fqname(":ns:a"), (Some("a"), Some("ns")));
        assert_eq!(split_fqname(":ns://a"), (Some("a"), Some("ns")));
        assert_eq!(split_fqname(":ns"), (None, Some("ns")));
        let mut s = b":ns\0name\0\0".to_vec();
        assert_eq!(strs_entry(&mut s, true), Some(1));
        assert_eq!(s, b":ns:name\0\0");
        assert_eq!(strs_entry(&mut b"a\0b\0\0".to_vec(), true), Some(2));
        assert_eq!(strs_entry(&mut b" a\0".to_vec(), false), None);
        assert_eq!(map_xindex(0x2 << 10), x::NAME);
        assert_eq!(map_xindex(5 << 10), x::TABLE | 1);
        assert_eq!(map_old_perms(perm::READ), perm::READ | perm::GETATTR | perm::OPEN);
    }
}

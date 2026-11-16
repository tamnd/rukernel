//! selinuxfs, the file system of SELinux, as security/selinux/selinuxfs.c of Linux. The init
//! system mounts it on `/sys/fs/selinux`.
//!
//! `load_policy` writes the binary policy to `load`, and `setenforce` writes 0 or 1 to
//! `enforce`. The other files give the state of the module and of the policy. A process
//! writes a request to a transaction file, as `access` or `create`, and reads the answer from
//! the same open file. The directory `avc` gives the state of the access vector cache, and
//! `initial_contexts` the contexts of the initial SIDs. Each change and each request is a
//! check of a permission of the class `security` on the SID `security`, as on Linux. There is
//! one instance: each mount shows the same files. The inode numbers are those of Linux, so
//! that the files keep their numbers from one mount to the next.

use crate::classmap::{class, security};
use crate::sidtab::{INITIAL_NAMES, NUM_INITIAL, sid};
use crate::{avc, deny_unknown, enforcing, policy, policydb, reject_unknown, server};
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use rk_abi::Errno;
use rk_frame::sync::{Once, SpinLock};
use rk_vfs::file::{File, FileOps};
use rk_vfs::fstype::{FsType, MountArgs};
use rk_vfs::inode::{DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, mode};

/// The magic number of selinuxfs, `SELINUX_MAGIC` of `<linux/magic.h>`.
pub const SELINUX_MAGIC: u64 = 0xf97c_ff8c;

/// The type of selinuxfs for `mount -t selinuxfs`.
pub const FS_TYPE: FsType = FsType { name: "selinuxfs", nodev: true, make: mount };

/// The inode number of the directory `avc`. Linux gives the numbers from `SEL_INO_NEXT` (22)
/// in the order of `sel_fill_super`: `booleans` (22), `null` (23), `avc` (24) and its three
/// files, `ss` (28) and its file, `initial_contexts` (30), `class` (31) and
/// `policy_capabilities` (32).
const AVC_DIR_INO: u64 = 24;

/// The inode number of the directory `initial_contexts`.
const INITCON_DIR_INO: u64 = 30;

/// The inode number of the directory `policy_capabilities`.
const POLICYCAP_DIR_INO: u64 = 32;

/// The bit of the inode numbers of the files of `initial_contexts`, `SEL_INITCON_INO_OFFSET`
/// of Linux.
const INITCON_INO_OFFSET: u64 = 0x0100_0000;

/// The bit of the inode numbers of the files of `policy_capabilities`,
/// `SEL_POLICYCAP_INO_OFFSET` of Linux.
const POLICYCAP_INO_OFFSET: u64 = 0x0800_0000;

/// The largest write to a file other than `load`, `PAGE_SIZE` of Linux.
const PAGE_SIZE: usize = 4096;

/// The largest answer of a transaction file, `SIMPLE_TRANSACTION_LIMIT` of Linux.
const TRANSACTION_LIMIT: usize = PAGE_SIZE - 8;

/// The names of the files of the directory `avc`, in the order of Linux.
const AVC_FILES: [&str; 3] = ["cache_threshold", "hash_stats", "cache_stats"];

/// Takes a write of the whole text of a file and gives the number of bytes that it used.
type WriteFn = fn(&[u8]) -> Result<usize>;

/// Takes the request of a transaction file and gives the answer.
type TransactionFn = fn(&[u8]) -> Result<Vec<u8>>;

/// A file of the root.
#[derive(Clone, Copy)]
struct FileDef {
    /// The name.
    name: &'static str,
    /// The inode number, from `enum sel_inos` of Linux.
    ino: u64,
    /// The permission bits.
    perm: u32,
    /// Gives the text of the file, or `None` for a file that a process cannot read.
    read: Option<fn() -> Result<Vec<u8>>>,
    /// Takes a write of the whole text, or `None` for a file that takes no write.
    write: Option<WriteFn>,
    /// Gives the answer of a request, for a transaction file.
    transaction: Option<TransactionFn>,
}

impl FileDef {
    /// A file with a read and a write.
    const fn new(
        name: &'static str,
        ino: u64,
        perm: u32,
        read: Option<fn() -> Result<Vec<u8>>>,
        write: Option<WriteFn>,
    ) -> Self {
        Self { name, ino, perm, read, write, transaction: None }
    }

    /// A transaction file, which all can read and write, as `transaction_ops` of Linux.
    const fn transaction(name: &'static str, ino: u64, op: TransactionFn) -> Self {
        Self { name, ino, perm: 0o666, read: None, write: None, transaction: Some(op) }
    }
}

/// The files of the root, in the order of `selinux_files` of Linux.
const FILES: [FileDef; 14] = [
    FileDef::new("load", 3, 0o600, None, Some(write_load)),
    FileDef::new("enforce", 4, 0o644, Some(read_enforce), Some(write_enforce)),
    FileDef::transaction("context", 5, write_context),
    FileDef::transaction("access", 6, write_access),
    FileDef::transaction("create", 7, write_create),
    FileDef::transaction("relabel", 8, write_relabel),
    FileDef::new("policyvers", 10, 0o444, Some(read_policyvers), None),
    FileDef::new("mls", 12, 0o444, Some(read_mls), None),
    FileDef::transaction("member", 14, write_member),
    FileDef::new("checkreqprot", 15, 0o644, Some(read_checkreqprot), Some(write_checkreqprot)),
    FileDef::new("reject_unknown", 17, 0o444, Some(read_reject), None),
    FileDef::new("deny_unknown", 18, 0o444, Some(read_deny), None),
    FileDef::new("status", 19, 0o444, Some(read_status), None),
    FileDef::new("policy", 20, 0o444, Some(read_policy), None),
];

/// Formats a number as `"%d"`, with no new line, as most files of selinuxfs.
fn number(v: impl core::fmt::Display) -> Result<Vec<u8>> {
    Ok(format!("{v}").into_bytes())
}

fn read_enforce() -> Result<Vec<u8>> {
    number(u8::from(enforcing()))
}

fn read_policyvers() -> Result<Vec<u8>> {
    number(policydb::VERSION_MAX)
}

fn read_mls() -> Result<Vec<u8>> {
    number(u8::from(crate::mls_enabled()))
}

fn read_checkreqprot() -> Result<Vec<u8>> {
    number(0)
}

fn read_reject() -> Result<Vec<u8>> {
    number(u8::from(reject_unknown()))
}

fn read_deny() -> Result<Vec<u8>> {
    number(u8::from(deny_unknown()))
}

fn read_status() -> Result<Vec<u8>> {
    Ok(crate::status().to_vec())
}

/// Gives the binary policy, as `sel_open_policy` of Linux, which fails before the first load.
fn read_policy() -> Result<Vec<u8>> {
    check(security::READ_POLICY)?;
    policy().map(|p| p.data.clone()).ok_or(Errno::EINVAL)
}

/// Checks a permission of the class `security` of the current task on the SID `security`, as
/// the files of selinuxfs of Linux do.
fn check(perm: u32) -> Result<()> {
    avc::has_perm(crate::current_sid(), sid::SECURITY, class::SECURITY, perm, |_| {})
}

/// Loads a policy, as `sel_write_load` of Linux.
fn write_load(data: &[u8]) -> Result<usize> {
    if data.is_empty() {
        return Err(Errno::EINVAL);
    }
    check(security::LOAD_POLICY)?;
    crate::load_policy(data).inspect_err(|_| {
        rk_frame::println!("SELinux: failed to load policy");
    })?;
    Ok(data.len())
}

/// Parses a number as `sscanf("%d")`: spaces, a sign and decimal digits, and the text after
/// the digits does not count.
fn scan_int(data: &[u8]) -> Option<i64> {
    let text = core::str::from_utf8(data).ok()?.trim_start();
    let (neg, text) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let end = text.bytes().position(|b| !b.is_ascii_digit()).unwrap_or(text.len());
    let v: i64 = text[..end].parse().ok()?;
    Some(if neg { -v } else { v })
}

/// Changes the mode, as `sel_write_enforce` of Linux.
fn write_enforce(data: &[u8]) -> Result<usize> {
    if data.len() >= PAGE_SIZE {
        return Err(Errno::ENOMEM);
    }
    let v = scan_int(data).ok_or(Errno::EINVAL)?;
    if (v != 0) != enforcing() {
        check(security::SETENFORCE)?;
    }
    crate::set_enforcing(v != 0);
    Ok(data.len())
}

/// Takes a write to `checkreqprot` and does nothing, as Linux, which no longer supports a
/// change of this value.
fn write_checkreqprot(data: &[u8]) -> Result<usize> {
    static TOLD: AtomicBool = AtomicBool::new(false);
    if !TOLD.swap(true, Ordering::Relaxed) {
        let (pid, comm) = crate::current();
        rk_frame::println!(
            "SELinux: {} ({pid}) wrote to checkreqprot. This is no longer supported.",
            alloc::string::String::from_utf8_lossy(&comm)
        );
    }
    Ok(data.len())
}

/// The words of a request, as `sscanf` with `%s`.
fn words(data: &[u8]) -> Vec<&[u8]> {
    let data = data.split(|&c| c == 0).next().unwrap_or_default();
    data.split(|c| c.is_ascii_whitespace()).filter(|w| !w.is_empty()).collect()
}

/// The SID of a context of a request, as `security_context_str_to_sid` of Linux.
fn str_to_sid(text: &[u8]) -> Result<u32> {
    server::context_to_sid(text, 0, false)
}

/// The class of a request, as `sscanf` with `%hu`.
fn scan_class(word: &[u8]) -> Result<u32> {
    scan_int(word).map(|v| u32::from(v as u16)).ok_or(Errno::EINVAL)
}

/// The answer with the text of the context of `sid` and a NUL, as `sel_write_context` and
/// `sel_write_create` of Linux.
fn context_answer(sid: u32, func: &str) -> Result<Vec<u8>> {
    let mut text = server::sid_to_context(sid)?.into_bytes();
    text.push(0);
    if text.len() > TRANSACTION_LIMIT {
        rk_frame::println!("SELinux: {func}:  context size ({}) exceeds payload max", text.len());
        return Err(Errno::ERANGE);
    }
    Ok(text)
}

/// Computes a decision, as `sel_write_access` of Linux: `scontext tcontext tclass`.
fn write_access(data: &[u8]) -> Result<Vec<u8>> {
    check(security::COMPUTE_AV)?;
    let [s, t, c, ..] = words(data)[..] else { return Err(Errno::EINVAL) };
    let tclass = scan_class(c)?;
    let avd = server::compute_av_user(str_to_sid(s)?, str_to_sid(t)?, tclass);
    let text = format!(
        "{:x} {:x} {:x} {:x} {} {:x}",
        avd.allowed,
        u32::MAX,
        avd.auditallow,
        avd.auditdeny,
        avd.seqno,
        avd.flags
    );
    Ok(text.into_bytes())
}

/// Checks a context and gives its canonical text, as `sel_write_context` of Linux.
fn write_context(data: &[u8]) -> Result<Vec<u8>> {
    check(security::CHECK_CONTEXT)?;
    let sid = server::context_to_sid(data, 0, false)?;
    context_answer(sid, "sel_write_context")
}

/// Decodes the name of a new object of `create`, as `sel_write_create` of Linux: `+` is a
/// space and `%XX` is a byte in hex digits. The name ends at a NUL.
fn decode_name(word: &[u8]) -> Result<Vec<u8>> {
    let hex = |c: Option<&u8>| c.and_then(|&c| (c as char).to_digit(16)).ok_or(Errno::EINVAL);
    let mut out = Vec::new();
    let mut it = word.iter();
    while let Some(&c) = it.next() {
        let c = match c {
            b'+' => b' ',
            b'%' => (hex(it.next())? << 4 | hex(it.next())?) as u8,
            c => c,
        };
        if c == 0 {
            break;
        }
        out.push(c);
    }
    Ok(out)
}

/// Computes the context of a new object, as `sel_write_create` of Linux:
/// `scontext tcontext tclass [name]`.
fn write_create(data: &[u8]) -> Result<Vec<u8>> {
    check(security::COMPUTE_CREATE)?;
    let w = words(data);
    let [s, t, c, ..] = w[..] else { return Err(Errno::EINVAL) };
    let tclass = scan_class(c)?;
    let name = w.get(3).map(|n| decode_name(n)).transpose()?;
    let (ssid, tsid) = (str_to_sid(s)?, str_to_sid(t)?);
    let sid = server::transition_sid_user(ssid, tsid, tclass, name.as_deref())?;
    context_answer(sid, "sel_write_create")
}

/// Computes the context of a relabel, as `sel_write_relabel` of Linux.
fn write_relabel(data: &[u8]) -> Result<Vec<u8>> {
    check(security::COMPUTE_RELABEL)?;
    let [s, t, c, ..] = words(data)[..] else { return Err(Errno::EINVAL) };
    let tclass = scan_class(c)?;
    let sid = server::change_sid(str_to_sid(s)?, str_to_sid(t)?, tclass)?;
    context_answer(sid, "sel_write_relabel")
}

/// Computes the context of a member, as `sel_write_member` of Linux.
fn write_member(data: &[u8]) -> Result<Vec<u8>> {
    check(security::COMPUTE_MEMBER)?;
    let [s, t, c, ..] = words(data)[..] else { return Err(Errno::EINVAL) };
    let tclass = scan_class(c)?;
    let sid = server::member_sid(str_to_sid(s)?, str_to_sid(t)?, tclass)?;
    context_answer(sid, "sel_write_member")
}

/// Gives the value of `avc/cache_threshold`.
fn read_threshold() -> Result<Vec<u8>> {
    number(avc::THRESHOLD.load(Ordering::Relaxed))
}

/// Changes the largest number of decisions in the cache, as `sel_write_avc_cache_threshold`
/// of Linux.
fn write_threshold(data: &[u8]) -> Result<usize> {
    check(security::SETSECPARAM)?;
    if data.len() >= PAGE_SIZE {
        return Err(Errno::ENOMEM);
    }
    let v = scan_int(data).ok_or(Errno::EINVAL)?;
    avc::THRESHOLD.store(v as u32, Ordering::Relaxed);
    Ok(data.len())
}

/// Gives the context of an initial SID with a NUL, as `sel_read_initcon` of Linux.
fn read_initcon(sid: u32) -> Result<Vec<u8>> {
    let mut text = server::sid_to_context(sid)?.into_bytes();
    text.push(0);
    Ok(text)
}

/// The device of selinuxfs.
fn dev() -> u64 {
    static DEV: Once<u64> = Once::new();
    *DEV.call_once(rk_vfs::inode::anon_dev)
}

/// An inode of selinuxfs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Node {
    /// The root.
    Root,
    /// A file of the root, by its index in [`FILES`].
    File(usize),
    /// The directory `avc`.
    AvcDir,
    /// A file of `avc`, by its index in [`AVC_FILES`].
    Avc(usize),
    /// The directory `initial_contexts`.
    InitDir,
    /// A file of `initial_contexts`, by its SID.
    Init(u32),
    /// The directory `policy_capabilities`.
    CapDir,
    /// A file of `policy_capabilities`, by the number of the capability.
    Cap(usize),
}

impl Node {
    /// The inode number.
    fn ino(self) -> u64 {
        match self {
            Self::Root => 1,
            Self::File(i) => FILES[i].ino,
            Self::AvcDir => AVC_DIR_INO,
            Self::Avc(i) => AVC_DIR_INO + 1 + i as u64,
            Self::InitDir => INITCON_DIR_INO,
            Self::Init(sid) => u64::from(sid) | INITCON_INO_OFFSET,
            Self::CapDir => POLICYCAP_DIR_INO,
            Self::Cap(i) => i as u64 | POLICYCAP_INO_OFFSET,
        }
    }

    /// The entries of this directory.
    fn children(self) -> Vec<(&'static str, Self)> {
        match self {
            Self::Root => FILES
                .iter()
                .enumerate()
                .map(|(i, f)| (f.name, Self::File(i)))
                .chain([
                    ("avc", Self::AvcDir),
                    ("initial_contexts", Self::InitDir),
                    ("policy_capabilities", Self::CapDir),
                ])
                .collect(),
            Self::AvcDir => AVC_FILES.iter().enumerate().map(|(i, &n)| (n, Self::Avc(i))).collect(),
            Self::InitDir => (1..=NUM_INITIAL)
                .filter_map(|sid| Some((INITIAL_NAMES[sid as usize]?, Self::Init(sid))))
                .collect(),
            Self::CapDir => {
                crate::POLICYCAP_NAMES.iter().enumerate().map(|(i, &n)| (n, Self::Cap(i))).collect()
            }
            _ => Vec::new(),
        }
    }

    fn is_dir(self) -> bool {
        matches!(self, Self::Root | Self::AvcDir | Self::InitDir | Self::CapDir)
    }

    /// The function of a transaction file.
    fn transaction(self) -> Option<TransactionFn> {
        match self {
            Self::File(i) => FILES[i].transaction,
            _ => None,
        }
    }

    /// The text of this file.
    fn text(self) -> Result<Vec<u8>> {
        match self {
            // A transaction file without an open file has no answer.
            Self::File(i) if FILES[i].transaction.is_some() => Ok(Vec::new()),
            Self::File(i) => FILES[i].read.ok_or(Errno::EINVAL)?(),
            Self::Avc(0) => read_threshold(),
            Self::Avc(1) => Ok(avc::hash_stats().into_bytes()),
            Self::Avc(_) => Ok(avc::cache_stats().into_bytes()),
            Self::Init(sid) => read_initcon(sid),
            Self::Cap(i) => number(u8::from(policy().is_some_and(|p| p.db.policycap(i as u32)))),
            _ => Err(Errno::EISDIR),
        }
    }

    /// Takes the whole write `data` at `offset`. The files of selinuxfs take no partial write.
    fn write(self, offset: u64, data: &[u8]) -> Result<usize> {
        let write = match self {
            Self::File(i) => FILES[i].write.ok_or(Errno::EINVAL)?,
            Self::Avc(0) => write_threshold,
            Self::Avc(_) | Self::Init(_) | Self::Cap(_) => return Err(Errno::EINVAL),
            _ => return Err(Errno::EISDIR),
        };
        if offset != 0 {
            return Err(Errno::EINVAL);
        }
        write(data)
    }
}

/// Copies the part of `text` at `offset` to `buf`.
fn copy_at(text: &[u8], offset: u64, buf: &mut [u8]) -> usize {
    let start = usize::try_from(offset).unwrap_or(usize::MAX).min(text.len());
    let n = buf.len().min(text.len() - start);
    buf[..n].copy_from_slice(&text[start..start + n]);
    n
}

/// An open file of selinuxfs. A write does not move the position, as Linux.
struct SelFile {
    /// The inode.
    node: Node,
    /// The answer of the request of a transaction file, as `simple_transaction_argresp` of
    /// Linux. It is empty after a request that failed.
    answer: SpinLock<Option<Vec<u8>>>,
}

impl SelFile {
    /// Takes the request of a transaction file, as `selinux_transaction_write` and
    /// `simple_transaction_get` of Linux. An open file takes one request.
    fn request(&self, op: TransactionFn, data: &[u8]) -> Result<usize> {
        if data.len() > TRANSACTION_LIMIT - 1 {
            return Err(Errno::EFBIG);
        }
        {
            let mut answer = self.answer.lock();
            if answer.is_some() {
                return Err(Errno::EBUSY);
            }
            *answer = Some(Vec::new());
        }
        let out = op(data)?;
        *self.answer.lock() = Some(out);
        Ok(data.len())
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        match self.node.transaction() {
            Some(op) => self.request(op, buf),
            None => self.node.write(offset, buf),
        }
    }
}

impl FileOps for SelFile {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        let n = self.read_at(file, file.pos(), buf)?;
        file.set_pos(file.pos() + n as u64);
        Ok(n)
    }

    fn read_at(&self, _file: &File, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if self.node.transaction().is_some() {
            let answer = self.answer.lock();
            return Ok(copy_at(answer.as_deref().unwrap_or_default(), offset, buf));
        }
        Ok(copy_at(&self.node.text()?, offset, buf))
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize> {
        self.write_at(file.pos(), buf)
    }

    fn write_at(&self, _file: &File, offset: u64, buf: &[u8]) -> Result<usize> {
        SelFile::write_at(self, offset, buf)
    }

    fn seekable(&self) -> bool {
        true
    }

    fn whole_write(&self) -> bool {
        true
    }
}

impl Inode for Node {
    fn metadata(&self) -> Metadata {
        let (kind, perm, nlink) = match *self {
            Self::Root | Self::AvcDir | Self::InitDir | Self::CapDir => (mode::S_IFDIR, 0o755, 2),
            Self::File(i) => (mode::S_IFREG, FILES[i].perm, 1),
            Self::Avc(0) => (mode::S_IFREG, 0o644, 1),
            Self::Avc(_) | Self::Init(_) | Self::Cap(_) => (mode::S_IFREG, 0o444, 1),
        };
        // `status` has the size of its structure, and `policy` the size of the policy, as
        // the inodes of Linux after an open.
        let size = match *self {
            Self::File(i) if FILES[i].name == "status" => 20,
            Self::File(i) if FILES[i].name == "policy" => {
                policy().map_or(0, |p| p.data.len() as u64)
            }
            _ => 0,
        };
        Metadata {
            dev: dev(),
            ino: self.ino(),
            mode: kind | perm,
            nlink,
            size,
            ..Metadata::default()
        }
    }

    fn set_attr(&self, attr: &SetAttr) -> Result<()> {
        // The truncate of an open with `O_TRUNC` has no effect, as `simple_setattr` of Linux on
        // a file with no pages.
        let truncate = SetAttr { size: attr.size, ..SetAttr::default() };
        if !self.is_dir() && *attr == truncate {
            return Ok(());
        }
        Err(Errno::EPERM)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        Ok(copy_at(&self.text()?, offset, buf))
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        self.write(offset, buf)
    }

    fn open_file(&self, _flags: u32) -> Option<Result<Arc<dyn FileOps>>> {
        if self.is_dir() {
            return None;
        }
        Some(Ok(Arc::new(SelFile { node: *self, answer: SpinLock::new(None) })))
    }

    fn lookup(&self, name: &[u8]) -> Result<InodeRef> {
        if !self.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let node = self.children().into_iter().find(|(n, _)| n.as_bytes() == name);
        Ok(Arc::new(node.ok_or(Errno::ENOENT)?.1))
    }

    fn read_dir(&self, pos: u64) -> Result<Option<(DirEntry, u64)>> {
        if !self.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let entry = match pos {
            0 => DirEntry { ino: self.ino(), kind: FileType::Directory, name: b".".to_vec() },
            1 => DirEntry { ino: 1, kind: FileType::Directory, name: b"..".to_vec() },
            _ => {
                let children = self.children();
                let Some(&(name, node)) =
                    usize::try_from(pos - 2).ok().and_then(|i| children.get(i))
                else {
                    return Ok(None);
                };
                let kind = if node.is_dir() { FileType::Directory } else { FileType::Regular };
                DirEntry { ino: node.ino(), kind, name: name.as_bytes().to_vec() }
            }
        };
        Ok(Some((entry, pos + 1)))
    }

    fn fs_id(&self) -> u64 {
        dev()
    }

    fn fs_magic(&self) -> u64 {
        SELINUX_MAGIC
    }
}

/// Gives the root of selinuxfs. Each mount shows the same files, as `get_tree_single` of Linux.
fn mount(_args: &MountArgs<'_>) -> Result<InodeRef> {
    static ROOT: Once<InodeRef> = Once::new();
    Ok(ROOT.call_once(|| Arc::new(Node::Root)).clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(inode: &InodeRef) -> Result<Vec<u8>> {
        let mut buf = alloc::vec![0u8; 1 << 16];
        let n = inode.read_at(0, &mut buf)?;
        Ok(buf[..n].to_vec())
    }

    fn names(dir: &InodeRef) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut pos = 0;
        while let Some((e, next)) = dir.read_dir(pos).unwrap() {
            out.push(e.name);
            pos = next;
        }
        out
    }

    fn args() -> MountArgs<'static> {
        MountArgs { data: b"", dev: None, read_only: false, lookup: None }
    }

    #[test]
    fn the_root_has_the_files_of_linux() {
        let _guard = crate::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = mount(&args()).unwrap();
        assert_eq!(root.fs_magic(), SELINUX_MAGIC);
        assert!(root.metadata().is_dir());
        let all = names(&root);
        assert_eq!(all.len(), 2 + FILES.len() + 3);
        assert_eq!(&all[2..4], [&b"load"[..], b"enforce"]);
        let load = root.lookup(b"load").unwrap();
        assert_eq!(load.metadata().mode, mode::S_IFREG | 0o600);
        assert_eq!(load.metadata().ino, 3);
        assert_eq!(read(&load), Err(Errno::EINVAL));
        let vers = root.lookup(b"policyvers").unwrap();
        assert_eq!(read(&vers).unwrap(), b"35");
        assert_eq!(vers.write_at(0, b"1"), Err(Errno::EINVAL));
        assert_eq!(root.lookup(b"nothing").err(), Some(Errno::ENOENT));
        let status = root.lookup(b"status").unwrap();
        assert_eq!(status.metadata().size, 20);
        assert_eq!(read(&status).unwrap().len(), 20);
        let check = root.lookup(b"checkreqprot").unwrap();
        assert_eq!(read(&check).unwrap(), b"0");
        let caps = root.lookup(b"policy_capabilities").unwrap();
        assert_eq!(names(&caps).len(), 2 + crate::POLICYCAP_NAMES.len());
        let open_perms = caps.lookup(b"open_perms").unwrap();
        assert_eq!(open_perms.metadata().ino, 1 | POLICYCAP_INO_OFFSET);
        assert_eq!(open_perms.lookup(b"x").err(), Some(Errno::ENOTDIR));
        assert!(root.lookup(b"enforce").unwrap().open_file(0).unwrap().unwrap().whole_write());
        assert_eq!(scan_int(b" -12abc"), Some(-12));
        assert_eq!(scan_int(b"x"), None);
    }

    #[test]
    fn a_load_through_the_file_sets_the_policy() {
        let _guard = crate::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = mount(&args()).unwrap();
        let load = root.lookup(b"load").unwrap();
        assert_eq!(load.write_at(0, b""), Err(Errno::EINVAL));
        assert_eq!(load.write_at(0, b"not a policy"), Err(Errno::EINVAL));
        let data = include_bytes!("../tests/rk_test.33.bin");
        assert_eq!(load.write_at(1, data), Err(Errno::EINVAL));
        assert_eq!(load.write_at(0, data), Ok(data.len()));
        assert_eq!(read(&root.lookup(b"mls").unwrap()).unwrap(), b"1");
        assert_eq!(read(&root.lookup(b"deny_unknown").unwrap()).unwrap(), b"1");
        assert_eq!(read(&root.lookup(b"reject_unknown").unwrap()).unwrap(), b"0");
        let pol = root.lookup(b"policy").unwrap();
        assert!(pol.metadata().size > 0);
        let caps = root.lookup(b"policy_capabilities").unwrap();
        assert_eq!(read(&caps.lookup(b"open_perms").unwrap()).unwrap(), b"1");
        assert_eq!(read(&caps.lookup(b"cgroup_seclabel").unwrap()).unwrap(), b"0");
        let enforce = root.lookup(b"enforce").unwrap();
        assert_eq!(enforce.write_at(0, b"x"), Err(Errno::EINVAL));
        assert_eq!(enforce.write_at(0, &[b'1'; PAGE_SIZE]), Err(Errno::ENOMEM));
        let kernel = root.lookup(b"initial_contexts").unwrap().lookup(b"kernel").unwrap();
        assert_eq!(kernel.metadata().ino, 1 | INITCON_INO_OFFSET);
        assert_eq!(read(&kernel).unwrap(), b"system_u:system_r:kernel_t:s0-s1:c0.c2\0");
        let avc = root.lookup(b"avc").unwrap();
        assert_eq!(names(&avc).len(), 2 + AVC_FILES.len());
        let stats = read(&avc.lookup(b"cache_stats").unwrap()).unwrap();
        assert!(stats.starts_with(b"lookups hits misses allocations reclaims frees\n"));
        let file = SelFile { node: Node::File(2), answer: SpinLock::new(None) };
        assert_eq!(FILES[2].name, "context");
        assert_eq!(file.request(write_context, b"system_u:object_r:sbin_t:s0\0"), Ok(28));
        assert_eq!(file.answer.lock().as_deref(), Some(&b"system_u:object_r:bin_t:s0\0"[..]));
        assert_eq!(file.request(write_context, b"x"), Err(Errno::EBUSY));
        let file = SelFile { node: Node::File(2), answer: SpinLock::new(None) };
        assert_eq!(
            file.request(write_context, b"system_u:object_r:nothing_t:s0"),
            Err(Errno::EINVAL)
        );
        assert_eq!(file.request(write_context, &[b'a'; TRANSACTION_LIMIT]), Err(Errno::EFBIG));
        assert_eq!(decode_name(b"na%6Ded+"), Ok(b"named ".to_vec()));
        assert_eq!(decode_name(b"a%zz"), Err(Errno::EINVAL));
    }
}

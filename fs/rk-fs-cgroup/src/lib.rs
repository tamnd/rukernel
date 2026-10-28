//! cgroup2: the file system of the cgroup hierarchy, for `mount -t cgroup2`.
//!
//! rk-cgroup keeps the hierarchy and the values of the files. This crate shows the hierarchy as
//! directories, and each cgroup has the files of its controllers. `mkdir` makes a cgroup and
//! `rmdir` removes it. A write of `cgroup.procs` moves a process, and the writes of the other
//! files go to rk-cgroup. Each `write` is one command, as in Linux, so the offset has no effect.
//!
//! A mount shows the hierarchy from the root of the cgroup namespace of the process that mounts
//! it. All the mounts show the same cgroups.
//!
//! The delegation of Linux works here: `chown` and `chmod` change the owner and the mode of a
//! directory or a file, and a new cgroup and its files belong to the process that makes it. A
//! write of `cgroup.procs` or `cgroup.threads` checks the credentials and the cgroup namespace of
//! the process that opened the file, as `cgroup_procs_write_permission` of Linux. The mount
//! option `nsdelegate` makes each cgroup namespace a delegation boundary.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
#[path = "kernel.rs"]
mod procs;
#[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
#[path = "host.rs"]
mod procs;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_abi::native::poll::{POLLERR, POLLIN, POLLOUT, POLLPRI, POLLRDNORM, POLLWRNORM};
use rk_cgroup::psi::{Trigger, TriggerState};
use rk_cgroup::{CgId, FILES};
use rk_frame::sync::{Once, SpinLock};
use rk_vfs::cred::{Cred, cap, may};
use rk_vfs::file::{File, FileOps};
use rk_vfs::fstype::{FsType, MountArgs};
use rk_vfs::inode::mode;
use rk_vfs::wait::{PollTable, WaitQueue};
use rk_vfs::{DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, now};

/// The magic number of cgroup2, `CGROUP2_SUPER_MAGIC` of `<linux/magic.h>`.
pub const CGROUP2_MAGIC: u64 = 0x6367_7270;

/// The file system type of cgroup2, for `mount -t cgroup2`.
pub const FS_TYPE: FsType = FsType { name: "cgroup2", nodev: true, make: mount };

/// The block size that `stat` gives for a file.
const BLOCK_SIZE: u32 = 4096;

/// The bits of the inode number below the ID of the cgroup. The number of a directory has 0
/// there, and the number of a file has its place in the list of files plus 1.
const INO_SHIFT: u32 = 8;

/// The key of the owner that a cgroup got from the process that made it, below the inode number
/// of its directory. The files of the cgroup have this owner if `chown` did not change it.
const CREATOR: u64 = (1 << INO_SHIFT) - 1;

const _: () = assert!(FILES.len() < CREATOR as usize);

/// The mount option `nsdelegate`, `CGRP_ROOT_NS_DELEGATE` of Linux: each cgroup namespace is a
/// delegation boundary. All the mounts share it, as all the mounts of cgroup2 of Linux share one
/// root.
static NS_DELEGATE: AtomicBool = AtomicBool::new(false);

/// The waits of `poll` on `cgroup.events` and the other files with events wait here. A change of
/// such a file wakes them.
static EVENTS: WaitQueue = WaitQueue::new();

/// Wakes the waits of `poll` on the files with events. rk-cgroup calls it after a change.
fn wake_events() {
    EVENTS.wake_all();
}

/// The owner and the mode that `chown` and `chmod` gave, and the owner of each cgroup that a
/// process that is not root made, by inode number. Other inodes belong to root.
static ATTRS: SpinLock<BTreeMap<u64, Attr>> = SpinLock::new(BTreeMap::new());

/// The owner and the mode of a directory or a file of cgroup2.
#[derive(Clone, Copy)]
struct Attr {
    uid: u32,
    gid: u32,
    /// The permission bits that `chmod` gave. `None` keeps the bits of the file.
    mode: Option<u32>,
}

/// The files that the root of a cgroup namespace lets a process of the namespace write when the
/// option `nsdelegate` is on, the files with `CFTYPE_NS_DELEGATABLE` in Linux.
const DELEGATABLE: [&str; 3] = ["cgroup.procs", "cgroup.threads", "cgroup.subtree_control"];

/// Makes the root of a mount: the root of the cgroup namespace of the caller. The option
/// `nsdelegate` changes only from the initial cgroup namespace, and each mount from there sets
/// it or clears it, as `apply_cgroup_root_flags` of Linux. cgroup2 takes the other options of
/// Linux, but they have no effect here.
fn mount(args: &MountArgs<'_>) -> Result<InodeRef> {
    rk_cgroup::set_notify(wake_events);
    let (ns, root) = procs::namespace();
    if ns == 0 {
        let on = args.data.split(|&b| b == b',').any(|o| o == b"nsdelegate");
        NS_DELEGATE.store(on, Ordering::Relaxed);
    }
    Ok(Arc::new(Node { id: root, file: None }))
}

/// The credentials and the cgroup namespace of the process that opened a file. The checks of a
/// write use them, as `cgroup_file_open` of Linux keeps them.
struct Access {
    cred: Arc<Cred>,
    /// The cgroup namespace: 0 is the initial namespace.
    ns: u32,
    /// The root cgroup of the namespace.
    root: CgId,
}

impl Access {
    /// The credentials and the cgroup namespace of the caller.
    fn current() -> Self {
        let (ns, root) = procs::namespace();
        Self { cred: rk_vfs::cred::current(), ns, root }
    }

    /// Checks that a write of the file `name` of the cgroup `id` is allowed. With `nsdelegate`, a
    /// process in a cgroup namespace cannot write the files of the root of its namespace, except
    /// the files of [`DELEGATABLE`], as `cgroup_file_write` of Linux.
    fn may_write(&self, id: CgId, name: &str) -> Result<()> {
        if NS_DELEGATE.load(Ordering::Relaxed)
            && self.ns != 0
            && self.root == id
            && !DELEGATABLE.contains(&name)
        {
            return Err(Errno::EPERM);
        }
        Ok(())
    }

    /// Checks a move of a process or a thread from the cgroup `src` to the cgroup `dst`, as
    /// `cgroup_procs_write_permission` of Linux. The process must be able to write
    /// `cgroup.procs` of the nearest common ancestor. With `nsdelegate`, both cgroups must be in
    /// the cgroup namespace of the process.
    fn may_migrate(&self, src: CgId, dst: CgId) -> Result<()> {
        let (common, inside) = rk_cgroup::with(|h| {
            let mut common = src;
            while !h.is_descendant(dst, common) {
                let Some(p) = h.parent(common) else { break };
                common = p;
            }
            (common, h.is_descendant(src, self.root) && h.is_descendant(dst, self.root))
        });
        let meta = Node { id: common, file: Some("cgroup.procs") }.metadata();
        self.cred.permission(&meta, may::WRITE)?;
        if NS_DELEGATE.load(Ordering::Relaxed) && !inside {
            return Err(Errno::ENOENT);
        }
        Ok(())
    }
}

/// The device of cgroup2. All the mounts show the same files, so they have one device.
fn dev() -> u64 {
    static DEV: Once<u64> = Once::new();
    *DEV.call_once(rk_vfs::anon_dev)
}

/// Gives the cgroup of a directory of cgroup2, for `CLONE_INTO_CGROUP`. Gives `None` for
/// another inode, or for a cgroup that was removed.
pub fn cgroup_of(inode: &InodeRef) -> Option<CgId> {
    if inode.fs_magic() != CGROUP2_MAGIC {
        return None;
    }
    let m = inode.metadata();
    if m.mode & mode::S_IFMT != mode::S_IFDIR {
        return None;
    }
    let id = CgId::try_from(m.ino >> INO_SHIFT).ok()?;
    rk_cgroup::with(|h| h.exists(id)).then_some(id)
}

/// The place of the file `name` in the list of files, plus 1. 0 is for the directory.
fn file_index(name: &str) -> u64 {
    FILES.iter().position(|f| f.name == name).unwrap_or(FILES.len()) as u64 + 1
}

/// An inode of cgroup2: the directory of the cgroup `id`, or its file `file`.
#[derive(Clone, Copy)]
struct Node {
    id: CgId,
    file: Option<&'static str>,
}

impl Node {
    /// The inode number of the cgroup `id`, or of its file `file`.
    fn ino(id: CgId, file: Option<&str>) -> u64 {
        u64::from(id) << INO_SHIFT | file.map_or(0, file_index)
    }

    /// Gives an error if the cgroup was removed. A file that is open after `rmdir` gives
    /// `ENODEV`, as in Linux.
    fn live(&self) -> Result<()> {
        if rk_cgroup::with(|h| h.exists(self.id)) { Ok(()) } else { Err(Errno::ENODEV) }
    }

    /// The text of the file `name`.
    fn text(&self, name: &str) -> Result<String> {
        self.live()?;
        match name {
            "cgroup.procs" => Ok(lines(&procs::processes(self.id))),
            "cgroup.threads" => Ok(lines(&procs::threads(self.id))),
            _ => {
                let t = rk_cgroup::now();
                rk_cgroup::with(|h| h.read(self.id, name, t))
            }
        }
    }

    /// Does the write of `data` to the file `name`, with the credentials and the cgroup
    /// namespace `access` of the process that opened the file.
    fn command(&self, name: &str, data: &[u8], access: &Access) -> Result<()> {
        self.live()?;
        access.may_write(self.id, name)?;
        let check = |src: CgId| access.may_migrate(src, self.id);
        match name {
            "cgroup.procs" => procs::move_process(self.id, parse_id(data)?, &check),
            "cgroup.threads" => procs::move_thread(self.id, parse_id(data)?, &check),
            _ if name.ends_with(".pressure") => {
                // A trigger needs an open file, and `OpenFile` makes it. A write through the
                // inode only, without a file, cannot keep a trigger.
                Trigger::parse(data)?;
                Err(Errno::EOPNOTSUPP)
            }
            _ => {
                // A limit or a weight of a device needs a block device with the number, as
                // `blkg_conf_open_bdev` of Linux.
                if matches!(name, "io.max" | "io.weight")
                    && rk_cgroup::io::dev_of_write(data).is_some_and(|d| !procs::block_exists(d))
                {
                    return Err(Errno::ENODEV);
                }
                let t = rk_cgroup::now();
                let effect = rk_cgroup::with(|h| h.write(self.id, name, data, t))?;
                procs::apply(self.id, effect);
                Ok(())
            }
        }
    }

    /// The entries of the directory, without `.` and `..`.
    fn entries(&self) -> Result<Vec<(Vec<u8>, Option<CgId>)>> {
        rk_cgroup::with(|h| {
            if !h.exists(self.id) {
                return Err(Errno::ENOENT);
            }
            let mut out: Vec<(Vec<u8>, Option<CgId>)> =
                h.children(self.id).into_iter().map(|(n, c)| (n, Some(c))).collect();
            out.extend(h.files(self.id).iter().map(|f| (f.name.as_bytes().to_vec(), None)));
            Ok(out)
        })
    }
}

/// The text of a list of IDs: one ID on each line.
fn lines(ids: &[u32]) -> String {
    ids.iter().map(|id| format!("{id}\n")).collect()
}

/// Reads a process or thread ID from a write of `cgroup.procs` or `cgroup.threads`.
fn parse_id(data: &[u8]) -> Result<u32> {
    let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
    text.trim_matches(|c: char| c.is_ascii_whitespace() || c == '\0')
        .parse()
        .map_err(|_| Errno::EINVAL)
}

impl Inode for Node {
    fn metadata(&self) -> Metadata {
        let (kind, perm, nlink) = match self.file {
            None => (mode::S_IFDIR, 0o755, 2),
            Some(name) => {
                let perm =
                    rk_cgroup::with(|h| h.file(self.id, name.as_bytes())).map_or(0o444, |f| f.perm);
                (mode::S_IFREG, perm, 1)
            }
        };
        let ino = Self::ino(self.id, self.file);
        let attr = {
            let attrs = ATTRS.lock();
            attrs.get(&ino).or_else(|| attrs.get(&(Self::ino(self.id, None) | CREATOR))).copied()
        };
        let perm = attr.and_then(|a| a.mode).unwrap_or(perm);
        let t = now();
        Metadata {
            dev: dev(),
            ino,
            mode: kind | perm,
            nlink,
            uid: attr.map_or(0, |a| a.uid),
            gid: attr.map_or(0, |a| a.gid),
            blksize: BLOCK_SIZE,
            atime: t,
            mtime: t,
            ctime: t,
            ..Metadata::default()
        }
    }

    fn set_attr(&self, attr: &SetAttr) -> Result<()> {
        // `O_TRUNC` sets the size to 0, and the files have no size. The times do not change, as
        // the times of the files are the time now.
        if attr.uid.is_none() && attr.gid.is_none() && attr.mode.is_none() {
            return Ok(());
        }
        self.live()?;
        let m = self.metadata();
        let mut attrs = ATTRS.lock();
        let a = attrs.entry(m.ino).or_insert(Attr { uid: m.uid, gid: m.gid, mode: None });
        a.uid = attr.uid.unwrap_or(a.uid);
        a.gid = attr.gid.unwrap_or(a.gid);
        if let Some(perm) = attr.mode {
            a.mode = Some(perm & 0o7777);
        }
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let Some(name) = self.file else { return Err(Errno::EISDIR) };
        let text = self.text(name)?;
        let text = text.as_bytes();
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(text.len());
        let n = buf.len().min(text.len() - start);
        buf[..n].copy_from_slice(&text[start..start + n]);
        Ok(n)
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize> {
        let Some(name) = self.file else { return Err(Errno::EISDIR) };
        self.command(name, buf, &Access::current())?;
        Ok(buf.len())
    }

    fn lookup(&self, name: &[u8]) -> Result<InodeRef> {
        if self.file.is_some() {
            return Err(Errno::ENOTDIR);
        }
        rk_cgroup::with(|h| {
            if let Some(id) = h.lookup(self.id, name) {
                return Ok(Arc::new(Node { id, file: None }) as InodeRef);
            }
            let f = h.file(self.id, name).ok_or(Errno::ENOENT)?;
            Ok(Arc::new(Node { id: self.id, file: Some(f.name) }) as InodeRef)
        })
    }

    fn create(&self, name: &[u8], kind: FileType, _perm: u32, _rdev: u64) -> Result<InodeRef> {
        if self.file.is_some() {
            return Err(Errno::ENOTDIR);
        }
        if kind != FileType::Directory {
            return Err(Errno::EPERM);
        }
        let t = rk_cgroup::now();
        let id = rk_cgroup::with(|h| h.mkdir(self.id, name, t))?;
        // The new directory and its files belong to the caller, as `cgroup_mkdir` of Linux.
        let cred = rk_vfs::cred::current();
        if cred.fsuid != 0 || cred.fsgid != 0 {
            let owner = Attr { uid: cred.fsuid, gid: cred.fsgid, mode: None };
            let dir = Self::ino(id, None);
            let mut attrs = ATTRS.lock();
            attrs.insert(dir, owner);
            attrs.insert(dir | CREATOR, owner);
        }
        Ok(Arc::new(Node { id, file: None }))
    }

    fn symlink(&self, _: &[u8], _: &[u8]) -> Result<InodeRef> {
        Err(Errno::EPERM)
    }

    fn link(&self, _: &[u8], _: &InodeRef) -> Result<()> {
        Err(Errno::EPERM)
    }

    fn unlink(&self, _: &[u8]) -> Result<()> {
        Err(Errno::EPERM)
    }

    fn rmdir(&self, name: &[u8]) -> Result<()> {
        if self.file.is_some() {
            return Err(Errno::ENOTDIR);
        }
        rk_cgroup::with(|h| {
            if h.lookup(self.id, name).is_none() && h.file(self.id, name).is_some() {
                return Err(Errno::ENOTDIR);
            }
            h.rmdir(self.id, name)
        })
        .map(|id| ATTRS.lock().retain(|&ino, _| ino >> INO_SHIFT != u64::from(id)))
    }

    fn rename(&self, _: &[u8], _: &InodeRef, _: &[u8]) -> Result<()> {
        Err(Errno::EPERM)
    }

    fn read_dir(&self, pos: u64) -> Result<Option<(DirEntry, u64)>> {
        if self.file.is_some() {
            return Err(Errno::ENOTDIR);
        }
        let entry = match pos {
            0 => DirEntry {
                ino: Self::ino(self.id, None),
                kind: FileType::Directory,
                name: b".".to_vec(),
            },
            1 => {
                let parent = rk_cgroup::with(|h| h.parent(self.id)).unwrap_or(self.id);
                DirEntry {
                    ino: Self::ino(parent, None),
                    kind: FileType::Directory,
                    name: b"..".to_vec(),
                }
            }
            _ => {
                let entries = self.entries()?;
                let Some((name, child)) = entries.into_iter().nth((pos - 2) as usize) else {
                    return Ok(None);
                };
                match child {
                    Some(id) => {
                        DirEntry { ino: Self::ino(id, None), kind: FileType::Directory, name }
                    }
                    None => {
                        let ino = Self::ino(self.id, core::str::from_utf8(&name).ok());
                        DirEntry { ino, kind: FileType::Regular, name }
                    }
                }
            }
        };
        Ok(Some((entry, pos + 1)))
    }

    fn fs_magic(&self) -> u64 {
        CGROUP2_MAGIC
    }

    fn fs_options(&self) -> Vec<u8> {
        if NS_DELEGATE.load(Ordering::Relaxed) { b",nsdelegate".to_vec() } else { Vec::new() }
    }

    fn open_file(&self, _flags: u32) -> Option<Result<Arc<dyn FileOps>>> {
        self.file?;
        Some(Ok(Arc::new(OpenFile::new(*self))))
    }
}

/// The events of `poll` that a file of cgroup2 always has, `DEFAULT_POLLMASK` of Linux.
const DEFAULT_POLLMASK: u32 = POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM;

/// An open file of cgroup2. It keeps the state of the open file of kernfs: the count of events
/// at the last read, for `poll`, and the trigger of a pressure file. It also keeps the
/// credentials and the cgroup namespace of the process that opened it, for the checks of a write.
struct OpenFile {
    node: Node,
    access: Access,
    /// The count of events of the file at the last read. A file that was not read has 0, so the
    /// first `poll` sees an event, as `kernfs_generic_poll` of Linux.
    seen: AtomicU64,
    /// The trigger of a pressure file, after a write of it.
    trigger: SpinLock<Option<Arc<PsiTrigger>>>,
}

impl OpenFile {
    fn new(node: Node) -> Self {
        Self {
            node,
            access: Access::current(),
            seen: AtomicU64::new(0),
            trigger: SpinLock::new(None),
        }
    }

    /// The name of the file.
    fn name(&self) -> &'static str {
        self.node.file.unwrap_or("")
    }

    /// The count of events of the file now. A file without events has 1, as the open node of
    /// kernfs.
    fn seq(&self) -> u64 {
        let name = self.name();
        rk_cgroup::with(|h| h.event_seq(self.node.id, name)).unwrap_or(1)
    }

    /// Tells if this is a pressure file.
    fn pressure(&self) -> Option<usize> {
        let r = self.name().strip_suffix(".pressure")?;
        rk_cgroup::psi::NAMES.iter().position(|&x| x == r)
    }

    /// Reads the text at `offset`. A read sets the count of events that `poll` compares.
    fn read_text(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let seq = self.seq();
        let text = self.node.text(self.name())?;
        self.seen.store(seq, Ordering::Relaxed);
        let text = text.as_bytes();
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(text.len());
        let n = buf.len().min(text.len() - start);
        buf[..n].copy_from_slice(&text[start..start + n]);
        Ok(n)
    }

    /// Does a write. A write of a pressure file makes the trigger of this open file, as
    /// `cgroup_pressure_write` of Linux.
    fn command(&self, buf: &[u8]) -> Result<usize> {
        let Some(resource) = self.pressure() else {
            self.node.command(self.name(), buf, &self.access)?;
            return Ok(buf.len());
        };
        self.node.live()?;
        self.access.may_write(self.node.id, self.name())?;
        let trigger = Trigger::parse(buf)?;
        // A user without `CAP_SYS_RESOURCE` must use a window that is a multiple of 2 seconds,
        // as `psi_trigger_create` of Linux.
        if !rk_vfs::cred::current().capable(cap::SYS_RESOURCE)
            && trigger.window % (rk_cgroup::psi::PERIOD_NS / 1000) != 0
        {
            return Err(Errno::EINVAL);
        }
        let mut slot = self.trigger.lock();
        if slot.is_some() {
            return Err(Errno::EBUSY);
        }
        *slot = Some(PsiTrigger::start(self.node.id, trigger, resource));
        Ok(buf.len())
    }
}

impl FileOps for OpenFile {
    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize> {
        let pos = file.pos();
        let n = self.read_text(pos, buf)?;
        file.set_pos(pos + n as u64);
        Ok(n)
    }

    fn write(&self, _file: &File, buf: &[u8]) -> Result<usize> {
        self.command(buf)
    }

    fn read_at(&self, _file: &File, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.read_text(offset, buf)
    }

    fn write_at(&self, _file: &File, _offset: u64, buf: &[u8]) -> Result<usize> {
        self.command(buf)
    }

    fn seekable(&self) -> bool {
        true
    }

    fn poll(&self, _file: &File) -> u32 {
        if self.pressure().is_some() {
            // As `psi_trigger_poll` of Linux: a file without a trigger has an error.
            let Some(t) = self.trigger.lock().clone() else {
                return DEFAULT_POLLMASK | POLLERR | POLLPRI;
            };
            t.check();
            return if t.take_event() { DEFAULT_POLLMASK | POLLPRI } else { DEFAULT_POLLMASK };
        }
        if self.seq() == self.seen.load(Ordering::Relaxed) {
            DEFAULT_POLLMASK
        } else {
            DEFAULT_POLLMASK | POLLERR | POLLPRI
        }
    }

    fn pollable(&self) -> bool {
        true
    }

    fn poll_wait(&self, _file: &File, table: &mut PollTable) {
        match &*self.trigger.lock() {
            Some(t) => table.add(&t.wait),
            None => table.add_static(&EVENTS),
        }
    }

    fn event_count(&self) -> u64 {
        match &*self.trigger.lock() {
            Some(t) => t.events.load(Ordering::Relaxed),
            None => self.seq(),
        }
    }
}

/// A trigger of a pressure file: it has an event when the stall time in a window grows over the
/// threshold, as the triggers of `kernel/sched/psi.c` of Linux. A timer checks the stall time ten
/// times in each window.
pub(crate) struct PsiTrigger {
    id: CgId,
    state: SpinLock<TriggerState>,
    /// An event that `poll` did not see yet.
    event: AtomicBool,
    /// The count of events, for an edge triggered epoll entry.
    events: AtomicU64,
    /// The waits of `poll` on the file of the trigger wait here.
    wait: Arc<WaitQueue>,
    timer: Once<procs::TriggerTimer>,
}

impl PsiTrigger {
    /// Makes the trigger `trigger` of the resource `resource` of the cgroup `id`, and starts its
    /// timer.
    fn start(id: CgId, trigger: Trigger, resource: usize) -> Arc<Self> {
        let now = rk_cgroup::now();
        let total = rk_cgroup::with(|h| h.psi_total(id, resource, trigger.full, now));
        let this = Arc::new(Self {
            id,
            state: SpinLock::new(TriggerState::new(trigger, resource, now, total)),
            event: AtomicBool::new(false),
            events: AtomicU64::new(0),
            wait: Arc::new(WaitQueue::new()),
            timer: Once::new(),
        });
        // The timer checks the trigger ten times in each window.
        let period = trigger.window * 100;
        this.timer.call_once(|| procs::start_timer(&this, period));
        this
    }

    /// Checks the stall time, and makes an event if it grew over the threshold. The timer calls
    /// it.
    fn check(&self) {
        let now = rk_cgroup::now();
        let (resource, full) = {
            let s = self.state.lock();
            (s.resource, s.trigger.full)
        };
        let total = rk_cgroup::with(|h| h.psi_total(self.id, resource, full, now));
        if self.state.lock().check(now, total) {
            self.event.store(true, Ordering::Relaxed);
            self.events.fetch_add(1, Ordering::Relaxed);
            self.wait.wake_all();
        }
    }

    /// Takes the event that `poll` did not see yet.
    fn take_event(&self) -> bool {
        self.event.swap(false, Ordering::Relaxed)
    }
}

impl Drop for PsiTrigger {
    fn drop(&mut self) {
        if let Some(timer) = self.timer.get() {
            procs::stop_timer(timer);
        }
    }
}

/// The operations of an open file of `/proc/pressure` for the resource `resource`: the pressure
/// of the system, from the root cgroup, with the triggers of the files of cgroup2.
pub fn system_pressure(resource: usize) -> Option<Arc<dyn FileOps>> {
    let r = *rk_cgroup::psi::NAMES.get(resource)?;
    let file = FILES.iter().find(|f| f.name.strip_suffix(".pressure") == Some(r))?;
    Some(Arc::new(OpenFile::new(Node { id: rk_cgroup::ROOT, file: Some(file.name) })))
}

#[cfg(test)]
mod tests;

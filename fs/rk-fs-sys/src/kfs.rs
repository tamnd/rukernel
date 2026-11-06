//! The small file systems that systemd mounts at boot: debugfs, tracefs, configfs, fusectl and
//! binfmt_misc. Each one has one instance, so each mount shows the same files, as
//! `get_tree_single` of Linux.
//!
//! - debugfs (fs/debugfs) on `/sys/kernel/debug` has the directory `tracing`, which shows the
//!   files of tracefs, as the automount of tracefs in debugfs of Linux. No driver adds files.
//! - tracefs (fs/tracefs, kernel/trace/trace.c) on `/sys/kernel/tracing` has the control files
//!   of the tracer `nop`. The kernel has no other tracer and no trace events, so the buffer stays
//!   empty. `tracing_on`, `current_tracer`, `trace_clock` and `buffer_size_kb` keep a write.
//! - configfs (fs/configfs) on `/sys/kernel/config` is empty, because no subsystem uses it.
//! - fusectl (fs/fuse/control.c) on `/sys/fs/fuse/connections` is empty, because the kernel has
//!   no FUSE connection.
//! - binfmt_misc (fs/binfmt_misc.c) on `/proc/sys/fs/binfmt_misc` has `register`, `status` and a
//!   file for each format of `rk_vfs::binfmt`.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use rk_abi::Errno;
use rk_frame::sync::Once;
use rk_vfs::binfmt;
use rk_vfs::fstype::{FsType, MountArgs};
use rk_vfs::inode::mode;
use rk_vfs::{DirEntry, FileType, Inode, InodeRef, Metadata, Result, SetAttr, now};

/// The type of debugfs, for `mount -t debugfs`.
pub const DEBUGFS: FsType = FsType { name: "debugfs", nodev: true, make: mount_debugfs };
/// The type of tracefs.
pub const TRACEFS: FsType = FsType { name: "tracefs", nodev: true, make: mount_tracefs };
/// The type of configfs.
pub const CONFIGFS: FsType = FsType { name: "configfs", nodev: true, make: mount_configfs };
/// The type of fusectl.
pub const FUSECTL: FsType = FsType { name: "fusectl", nodev: true, make: mount_fusectl };
/// The type of binfmt_misc.
pub const BINFMT_MISC: FsType = FsType { name: "binfmt_misc", nodev: true, make: mount_binfmt };

fn mount_debugfs(_: &MountArgs<'_>) -> Result<InodeRef> {
    Ok(root(&DEBUG))
}

fn mount_tracefs(_: &MountArgs<'_>) -> Result<InodeRef> {
    Ok(root(&TRACE))
}

fn mount_configfs(_: &MountArgs<'_>) -> Result<InodeRef> {
    Ok(root(&CONFIG))
}

fn mount_fusectl(_: &MountArgs<'_>) -> Result<InodeRef> {
    Ok(root(&FUSECTL_FS))
}

fn mount_binfmt(_: &MountArgs<'_>) -> Result<InodeRef> {
    Ok(root(&BINFMT))
}

/// An entry of a directory: a directory or a file, with its permission bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Entry {
    Dir(u32),
    File(u32),
}

/// A file system of this module.
struct Kfs {
    /// The number of the file system, for its device.
    id: usize,
    /// The magic number of `<linux/magic.h>`.
    magic: u64,
    /// The permission bits of the root.
    root: u32,
    /// The entries of the directory at a path, or `None` if no directory has the path.
    list: fn(&str) -> Option<Vec<(&'static str, Entry)>>,
    /// The text of the file at a path.
    read: fn(&str) -> Result<Vec<u8>>,
    /// Takes a write to the file at a path.
    write: fn(&str, &[u8]) -> Result<()>,
}

static DEBUG: Kfs = Kfs {
    id: 0,
    magic: 0x6462_6720,
    root: 0o700,
    list: debug_list,
    read: debug_read,
    write: debug_write,
};
static TRACE: Kfs = Kfs {
    id: 1,
    magic: 0x7472_6163,
    root: 0o700,
    list: trace_list,
    read: trace_read,
    write: trace_write,
};
static CONFIG: Kfs = Kfs {
    id: 2,
    magic: 0x6265_6570,
    root: 0o755,
    list: empty_list,
    read: no_read,
    write: no_write,
};
static FUSECTL_FS: Kfs = Kfs {
    id: 3,
    magic: 0x6573_5543,
    root: 0o755,
    list: empty_list,
    read: no_read,
    write: no_write,
};
static BINFMT: Kfs = Kfs {
    id: 4,
    magic: 0x4249_4e4d,
    root: 0o755,
    list: binfmt_list,
    read: binfmt_read,
    write: binfmt_write,
};

/// The device of the file system with the number `id`.
fn dev(id: usize) -> u64 {
    static DEVS: [Once<u64>; 5] = [const { Once::new() }; 5];
    *DEVS[id].call_once(rk_vfs::anon_dev)
}

/// The inode number of the path `path`: 1 for the root, and a hash of the path for another one.
fn ino(path: &str) -> u64 {
    if path.is_empty() {
        return 1;
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in path.as_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    (h >> 1) | 2
}

fn empty_list(path: &str) -> Option<Vec<(&'static str, Entry)>> {
    path.is_empty().then(Vec::new)
}

fn no_read(_: &str) -> Result<Vec<u8>> {
    Err(Errno::EINVAL)
}

fn no_write(_: &str, _: &[u8]) -> Result<()> {
    Err(Errno::EINVAL)
}

// debugfs: the directory `tracing` is tracefs.

fn debug_list(path: &str) -> Option<Vec<(&'static str, Entry)>> {
    match path {
        "" => Some(Vec::from([("tracing", Entry::Dir(0o700))])),
        "tracing" => trace_list(""),
        _ => trace_list(path.strip_prefix("tracing/")?),
    }
}

fn debug_read(path: &str) -> Result<Vec<u8>> {
    trace_read(path.strip_prefix("tracing/").ok_or(Errno::EINVAL)?)
}

fn debug_write(path: &str, data: &[u8]) -> Result<()> {
    trace_write(path.strip_prefix("tracing/").ok_or(Errno::EINVAL)?, data)
}

// tracefs.

/// The permission bits of a file that takes a write, `TRACE_MODE_WRITE` of Linux.
const WRITE: Entry = Entry::File(0o640);
/// The permission bits of a file that only gives text, `TRACE_MODE_READ` of Linux.
const READ: Entry = Entry::File(0o440);
/// The permission bits of a directory of tracefs, as `tracefs_create_dir` of Linux.
const DIR: Entry = Entry::Dir(0o750);

/// The state of `tracing_on`.
static TRACING_ON: AtomicBool = AtomicBool::new(true);
/// The size of the buffer of each CPU in KiB. Linux has 1408 KiB.
static BUFFER_KB: AtomicU64 = AtomicU64::new(1408);
/// The index of the clock of `trace_clock` in `CLOCKS`.
static CLOCK: AtomicUsize = AtomicUsize::new(0);

/// The clocks of `trace_clock`, as `trace_clocks` of Linux. x86-64 also has the TSC.
const CLOCKS: &[&str] = if cfg!(target_arch = "x86_64") {
    &["local", "global", "counter", "uptime", "perf", "mono", "mono_raw", "boot", "tai", "x86-tsc"]
} else {
    &["local", "global", "counter", "uptime", "perf", "mono", "mono_raw", "boot", "tai"]
};

fn trace_list(path: &str) -> Option<Vec<(&'static str, Entry)>> {
    let out = match path {
        "" => Vec::from([
            ("README", READ),
            ("available_events", READ),
            ("available_tracers", READ),
            ("buffer_size_kb", WRITE),
            ("buffer_total_size_kb", READ),
            ("current_tracer", WRITE),
            ("events", DIR),
            ("instances", DIR),
            ("options", DIR),
            ("set_event", WRITE),
            ("trace", WRITE),
            ("trace_clock", WRITE),
            ("trace_marker", Entry::File(0o220)),
            ("trace_marker_raw", Entry::File(0o220)),
            ("tracing_on", WRITE),
        ]),
        "events" => Vec::from([("enable", WRITE)]),
        "instances" | "options" => Vec::new(),
        _ => return None,
    };
    Some(out)
}

/// The text of `trace` with no entries, as `print_trace_header` and `print_func_help_header_irq`
/// of Linux.
fn trace_text() -> Vec<u8> {
    let cpus = rk_frame::cpu::count();
    format!(
        "# tracer: nop\n#\n# entries-in-buffer/entries-written: 0/0   #P:{cpus}\n#\n\
         #                                _-----=> irqs-off/BH-disabled\n\
         #                               / _----=> need-resched\n\
         #                              | / _---=> hardirq/softirq\n\
         #                              || / _--=> preempt-depth\n\
         #                              ||| / _-=> migrate-disable\n\
         #                              |||| /     delay\n\
         #           TASK-PID     CPU#  |||||  TIMESTAMP  FUNCTION\n\
         #              | |         |   |||||     |         |\n"
    )
    .into_bytes()
}

/// The text of `trace_clock`: the clocks, with the one in use in brackets.
fn clock_text() -> Vec<u8> {
    let now = CLOCK.load(Ordering::Relaxed);
    let names: Vec<String> = CLOCKS
        .iter()
        .enumerate()
        .map(|(i, c)| if i == now { format!("[{c}]") } else { String::from(*c) })
        .collect();
    format!("{}\n", names.join(" ")).into_bytes()
}

const README: &str = "tracing mini-HOWTO:\n\n\
# echo 0 > tracing_on : quick way to disable tracing\n\
# echo 1 > tracing_on : quick way to re-enable tracing\n\n\
 Important files:\n\
  trace\t\t\t- The static contents of the buffer\n\
\t\t\t  To clear the buffer write into this file: echo > trace\n\
  tracing_on\t\t- Enable or disable writing to the ring buffer\n\
  current_tracer\t- function and latency tracers\n\
  available_tracers\t- list of configured tracers for current_tracer\n\
  buffer_size_kb\t- view and modify size of per cpu buffer\n\
  buffer_total_size_kb  - view total size of all cpu buffers\n\n\
  trace_clock\t\t- change the clock used to order events\n\
  trace_marker\t\t- Writes into this file writes into the kernel buffer\n\
  trace_marker_raw\t\t- Writes into this file writes binary data into the kernel buffer\n";

fn trace_read(path: &str) -> Result<Vec<u8>> {
    let kb = BUFFER_KB.load(Ordering::Relaxed);
    let text = match path {
        "README" => Vec::from(README.as_bytes()),
        "available_events" | "set_event" => Vec::new(),
        "available_tracers" | "current_tracer" => b"nop\n".to_vec(),
        "buffer_size_kb" => format!("{kb}\n").into_bytes(),
        "buffer_total_size_kb" => format!("{}\n", kb * rk_frame::cpu::count() as u64).into_bytes(),
        "events/enable" => b"0\n".to_vec(),
        "trace" => trace_text(),
        "trace_clock" => clock_text(),
        "tracing_on" => format!("{}\n", u8::from(TRACING_ON.load(Ordering::Relaxed))).into_bytes(),
        _ => return Err(Errno::EINVAL),
    };
    Ok(text)
}

/// Reads an unsigned number with spaces and a new line around it.
fn number(data: &[u8]) -> Result<u64> {
    let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
    text.trim().parse().map_err(|_| Errno::EINVAL)
}

fn trace_write(path: &str, data: &[u8]) -> Result<()> {
    // A mark goes to a buffer that keeps nothing, and it can have any bytes. With `tracing_on`
    // at 0 the buffer takes no write, and Linux gives `EBADF`.
    if path == "trace_marker" || path == "trace_marker_raw" {
        return if TRACING_ON.load(Ordering::Relaxed) { Ok(()) } else { Err(Errno::EBADF) };
    }
    let word = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?.trim();
    match path {
        "tracing_on" => TRACING_ON.store(number(data)? != 0, Ordering::Relaxed),
        "buffer_size_kb" => match number(data)? {
            0 => return Err(Errno::EINVAL),
            kb => BUFFER_KB.store(kb, Ordering::Relaxed),
        },
        "current_tracer" if word == "nop" => {}
        "trace_clock" => {
            let i = CLOCKS.iter().position(|&c| c == word).ok_or(Errno::EINVAL)?;
            CLOCK.store(i, Ordering::Relaxed);
        }
        // The buffer is empty, so a write that clears it has nothing to do. No event exists, so
        // only a write with no name, or one that turns events off, works.
        "trace" => {}
        "set_event" if word.is_empty() || word.starts_with('!') => {}
        "events/enable" if word == "0" || word == "1" => {}
        _ => return Err(Errno::EINVAL),
    }
    Ok(())
}

// binfmt_misc.

fn binfmt_list(path: &str) -> Option<Vec<(&'static str, Entry)>> {
    if !path.is_empty() {
        return None;
    }
    let mut out = Vec::from([("register", Entry::File(0o200)), ("status", Entry::File(0o644))]);
    // The names of the formats live as long as the list, so they leak only when a format is
    // added. A name is short and the list of formats is small.
    for name in binfmt::names() {
        out.push((intern(name), Entry::File(0o644)));
    }
    Some(out)
}

/// Gives a name that lives for the time of the kernel. The same name gives the same string.
fn intern(name: String) -> &'static str {
    static NAMES: rk_frame::sync::SpinLock<Vec<&'static str>> =
        rk_frame::sync::SpinLock::new(Vec::new());
    let mut names = NAMES.lock();
    if let Some(n) = names.iter().find(|n| **n == name) {
        return n;
    }
    let n: &'static str = alloc::boxed::Box::leak(name.into_boxed_str());
    names.push(n);
    n
}

fn binfmt_read(path: &str) -> Result<Vec<u8>> {
    match path {
        "status" => Ok(binfmt::status().to_vec()),
        "register" => Err(Errno::EINVAL),
        name => binfmt::get(name).map(|f| binfmt::show(&f)).ok_or(Errno::ENOENT),
    }
}

fn binfmt_write(path: &str, data: &[u8]) -> Result<()> {
    match path {
        "register" => binfmt::register(data),
        "status" => binfmt::write_status(data),
        name => binfmt::write_format(name, data),
    }
}

/// The root of the file system `fs`.
fn root(fs: &'static Kfs) -> InodeRef {
    Arc::new(Node { fs, path: String::new(), entry: Entry::Dir(fs.root) })
}

/// An inode of a file system of this module. `path` is the path from the root, without a `/` at
/// the start.
struct Node {
    fs: &'static Kfs,
    path: String,
    entry: Entry,
}

impl Node {
    fn child_path(&self, name: &str) -> String {
        if self.path.is_empty() { String::from(name) } else { format!("{}/{name}", self.path) }
    }

    fn children(&self) -> Result<Vec<(&'static str, Entry)>> {
        match self.entry {
            Entry::Dir(_) => (self.fs.list)(&self.path).ok_or(Errno::ENOENT),
            Entry::File(_) => Err(Errno::ENOTDIR),
        }
    }
}

impl Inode for Node {
    fn metadata(&self) -> Metadata {
        let (kind, perm, nlink) = match self.entry {
            Entry::Dir(perm) => (mode::S_IFDIR, perm, 2),
            Entry::File(perm) => (mode::S_IFREG, perm, 1),
        };
        let t = now();
        Metadata {
            dev: dev(self.fs.id),
            ino: ino(&self.path),
            mode: kind | perm,
            nlink,
            blksize: 4096,
            atime: t,
            mtime: t,
            ctime: t,
            ..Metadata::default()
        }
    }

    fn set_attr(&self, attr: &SetAttr) -> Result<()> {
        // A truncate at open, as `echo > trace`, has no effect.
        if attr.mode.is_some() || attr.uid.is_some() || attr.gid.is_some() {
            return Err(Errno::EPERM);
        }
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if let Entry::Dir(_) = self.entry {
            return Err(Errno::EISDIR);
        }
        let text = (self.fs.read)(&self.path)?;
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(text.len());
        let n = buf.len().min(text.len() - start);
        buf[..n].copy_from_slice(&text[start..start + n]);
        Ok(n)
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize> {
        if let Entry::Dir(_) = self.entry {
            return Err(Errno::EISDIR);
        }
        (self.fs.write)(&self.path, buf)?;
        Ok(buf.len())
    }

    fn lookup(&self, name: &[u8]) -> Result<InodeRef> {
        let name = core::str::from_utf8(name).map_err(|_| Errno::ENOENT)?;
        let (_, entry) =
            self.children()?.into_iter().find(|(n, _)| *n == name).ok_or(Errno::ENOENT)?;
        Ok(Arc::new(Node { fs: self.fs, path: self.child_path(name), entry }))
    }

    fn read_dir(&self, pos: u64) -> Result<Option<(DirEntry, u64)>> {
        let children = self.children()?;
        let entry = match pos {
            0 => DirEntry { ino: ino(&self.path), kind: FileType::Directory, name: b".".to_vec() },
            1 => {
                let up = self.path.rfind('/').map_or("", |i| &self.path[..i]);
                DirEntry { ino: ino(up), kind: FileType::Directory, name: b"..".to_vec() }
            }
            _ => {
                let Some(&(name, e)) = usize::try_from(pos - 2).ok().and_then(|i| children.get(i))
                else {
                    return Ok(None);
                };
                let kind = match e {
                    Entry::Dir(_) => FileType::Directory,
                    Entry::File(_) => FileType::Regular,
                };
                DirEntry { ino: ino(&self.child_path(name)), kind, name: name.as_bytes().to_vec() }
            }
        };
        Ok(Some((entry, pos + 1)))
    }

    fn fs_id(&self) -> u64 {
        dev(self.fs.id)
    }

    fn fs_magic(&self) -> u64 {
        self.fs.magic
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mount(t: FsType) -> InodeRef {
        (t.make)(&MountArgs { data: b"", dev: None, read_only: false, lookup: None }).unwrap()
    }

    fn names(dir: &InodeRef) -> Vec<String> {
        let mut out = Vec::new();
        let mut pos = 2;
        while let Some((e, next)) = dir.read_dir(pos).unwrap() {
            out.push(String::from_utf8(e.name).unwrap());
            pos = next;
        }
        out
    }

    fn read(node: &InodeRef) -> String {
        let mut buf = [0u8; 2048];
        let n = node.read_at(0, &mut buf).unwrap();
        String::from_utf8(buf[..n].to_vec()).unwrap()
    }

    fn walk(root: &InodeRef, path: &str) -> InodeRef {
        path.split('/').fold(root.clone(), |d, n| d.lookup(n.as_bytes()).unwrap())
    }

    #[test]
    fn each_type_has_the_magic_and_the_mode_of_linux() {
        for (t, magic, perm) in [
            (DEBUGFS, 0x6462_6720, 0o700),
            (TRACEFS, 0x7472_6163, 0o700),
            (CONFIGFS, 0x6265_6570, 0o755),
            (FUSECTL, 0x6573_5543, 0o755),
            (BINFMT_MISC, 0x4249_4e4d, 0o755),
        ] {
            let root = mount(t);
            assert_eq!(root.fs_magic(), magic, "{}", t.name);
            assert_eq!(root.metadata().mode, mode::S_IFDIR | perm, "{}", t.name);
            assert_eq!(root.metadata().ino, 1);
        }
        assert!(names(&mount(CONFIGFS)).is_empty());
        assert!(names(&mount(FUSECTL)).is_empty());
        assert_ne!(mount(CONFIGFS).fs_id(), mount(FUSECTL).fs_id());
    }

    #[test]
    fn tracefs_has_the_control_files_of_the_nop_tracer() {
        let root = mount(TRACEFS);
        let all = names(&root);
        for f in ["available_tracers", "current_tracer", "trace", "trace_marker", "tracing_on"] {
            assert!(all.iter().any(|n| n == f), "{f}");
        }
        assert_eq!(read(&walk(&root, "available_tracers")), "nop\n");
        assert!(read(&walk(&root, "trace")).starts_with("# tracer: nop\n#\n# entries-in-buffer"));
        assert!(read(&walk(&root, "trace_clock")).starts_with("[local] global counter"));
        let clock = walk(&root, "trace_clock");
        clock.write_at(0, b"mono\n").unwrap();
        assert!(read(&clock).contains(" [mono] "));
        assert_eq!(clock.write_at(0, b"nothing"), Err(Errno::EINVAL));
        clock.write_at(0, b"local").unwrap();
        let tracer = walk(&root, "current_tracer");
        assert_eq!(tracer.write_at(0, b"function\n"), Err(Errno::EINVAL));
        assert_eq!(tracer.write_at(0, b"nop\n"), Ok(4));
        let marker = walk(&root, "trace_marker");
        assert_eq!(marker.metadata().mode, mode::S_IFREG | 0o220);
        assert_eq!(marker.write_at(0, b"hello"), Ok(5));
        let on = walk(&root, "tracing_on");
        on.write_at(0, b"0\n").unwrap();
        assert_eq!(read(&on), "0\n");
        assert_eq!(marker.write_at(0, b"hello"), Err(Errno::EBADF));
        on.write_at(0, b"1\n").unwrap();
        assert_eq!(read(&walk(&root, "events/enable")), "0\n");
        assert_eq!(walk(&root, "events").metadata().mode, mode::S_IFDIR | 0o750);
        assert_eq!(root.lookup(b"nothing").err(), Some(Errno::ENOENT));
    }

    #[test]
    fn debugfs_shows_tracefs_in_tracing() {
        let root = mount(DEBUGFS);
        assert_eq!(names(&root), ["tracing"]);
        assert_eq!(read(&walk(&root, "tracing/available_tracers")), "nop\n");
        assert_eq!(names(&walk(&root, "tracing")), names(&mount(TRACEFS)));
    }

    #[test]
    fn binfmt_misc_registers_shows_and_removes_a_format() {
        let root = mount(BINFMT_MISC);
        assert_eq!(names(&root), ["register", "status"]);
        assert_eq!(read(&walk(&root, "status")), "enabled\n");
        let register = walk(&root, "register");
        assert_eq!(register.metadata().mode, mode::S_IFREG | 0o200);
        assert_eq!(register.write_at(0, b":kfs:M::RK::/bin/sh:\n"), Ok(21));
        assert_eq!(names(&root), ["register", "status", "kfs"]);
        let f = walk(&root, "kfs");
        assert_eq!(read(&f), "enabled\ninterpreter /bin/sh\nflags: \noffset 0\nmagic 524b\n");
        f.write_at(0, b"-1").unwrap();
        assert_eq!(names(&root), ["register", "status"]);
        assert_eq!(f.read_at(0, &mut [0u8; 8]), Err(Errno::ENOENT));
    }
}

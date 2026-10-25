//! The files of procfs that read the state of the kernel: the root directory, the system files,
//! `/proc/sys` and the directory of each process.

use crate::node::{FindFn, data_file, dead_link, dir, file, join, link, rw_file};
use crate::text::{self, MapLine, MemInfo, SmapsArea, Statm};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::sync::{Once, SpinLock};
use rk_mm::{Backing, VmaKind};
use rk_proc::exec::USER_HZ;
use rk_proc::signal::{NSIG, SIG_IGN};
use rk_proc::{Pid, Process, Thread};
use rk_vfs::{InodeRef, Location, Result};

/// The facts about the kernel that procfs shows, which a higher layer knows.
#[derive(Clone, Debug, Default)]
pub struct KernelInfo {
    /// The release, as `uname -r` gives it.
    pub release: &'static str,
    /// The version, as `uname -v` gives it.
    pub version: &'static str,
    /// The command line of the kernel.
    pub cmdline: String,
}

static INFO: Once<KernelInfo> = Once::new();

/// Gives procfs the facts about the kernel. Only the first call has an effect.
pub fn set_kernel_info(info: KernelInfo) {
    INFO.call_once(|| info);
}

fn info() -> KernelInfo {
    INFO.get().cloned().unwrap_or_default()
}

/// Makes the root directory of procfs.
pub(crate) fn root() -> InodeRef {
    let find: FindFn = Box::new(|name: &[u8]| {
        if let Some(pid) = parse_pid(name) {
            if let Some(p) = rk_proc::find_process(pid) {
                return Ok(process_dir(&p));
            }
            // A thread that is not the leader has a directory too, which `ls` does not show.
            if let Some(t) = rk_proc::find_thread(pid) {
                return Ok(thread_dir(&t, &join(b"/", name), b"/"));
            }
            return Err(Errno::ENOENT);
        }
        root_files().into_iter().find(|(n, _)| n == name).map(|(_, i)| i).ok_or(Errno::ENOENT)
    });
    dir(b"/", b"/", 0o555, root_list, Some(find))
}

fn root_list() -> Result<Vec<(Vec<u8>, InodeRef)>> {
    let mut out = root_files();
    for p in rk_proc::processes() {
        out.push((format!("{}", p.pid()).into_bytes(), process_dir(&p)));
    }
    Ok(out)
}

fn parse_pid(name: &[u8]) -> Option<Pid> {
    if name.first() == Some(&b'0') {
        return None;
    }
    core::str::from_utf8(name).ok()?.parse().ok()
}

fn text_file(path: &[u8], f: fn() -> Vec<u8>) -> InodeRef {
    file(path, move || Ok(f()))
}

fn root_files() -> Vec<(Vec<u8>, InodeRef)> {
    let files: [(&[u8], fn() -> Vec<u8>); 9] = [
        (b"meminfo", || {
            let f = rk_frame::mm::frame_stats();
            let kb = (rk_mm::PAGE_SIZE / 1024) as u64;
            text::meminfo(MemInfo { total: f.total as u64 * kb, free: f.free as u64 * kb })
                .into_bytes()
        }),
        (b"cpuinfo", cpuinfo),
        (b"uptime", || {
            let (s, cs) = uptime();
            format!("{s}.{cs:02} 0.00\n").into_bytes()
        }),
        (b"loadavg", || {
            let all = rk_proc::processes();
            let running = all.iter().filter(|p| p.state_letter() == b'R').count();
            let last = all.iter().map(|p| p.pid()).max().unwrap_or(0);
            format!("0.00 0.00 0.00 {running}/{} {last}\n", all.len()).into_bytes()
        }),
        (b"stat", stat),
        (b"version", || {
            let i = info();
            format!("Linux version {} (rukernel) {}\n", i.release, i.version).into_bytes()
        }),
        (b"cmdline", || format!("{}\n", info().cmdline).into_bytes()),
        (b"filesystems", || {
            let mut out = String::new();
            for t in rk_vfs::fstype::types() {
                out.push_str(if t.nodev { "nodev\t" } else { "\t" });
                out.push_str(t.name);
                out.push('\n');
            }
            out.into_bytes()
        }),
        (b"swaps", || b"Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n".to_vec()),
    ];
    let mut out: Vec<(Vec<u8>, InodeRef)> =
        files.iter().map(|&(name, f)| (name.to_vec(), text_file(&join(b"/", name), f))).collect();
    out.push((b"mounts".to_vec(), link(b"/mounts", 0o777, || Ok(b"self/mounts".to_vec()))));
    out.push((
        b"self".to_vec(),
        link(b"/self", 0o777, || {
            let t = rk_proc::current_thread().ok_or(Errno::ENOENT)?;
            Ok(format!("{}", t.process().pid()).into_bytes())
        }),
    ));
    out.push((
        b"thread-self".to_vec(),
        link(b"/thread-self", 0o777, || {
            let t = rk_proc::current_thread().ok_or(Errno::ENOENT)?;
            Ok(format!("{}/task/{}", t.process().pid(), t.tid()).into_bytes())
        }),
    ));
    out.push((b"sys".to_vec(), sys_dir()));
    out
}

/// The seconds and the hundredths of a second since boot.
fn uptime() -> (u64, u64) {
    let ticks = rk_frame::time::ticks();
    let hz = rk_frame::time::HZ;
    (ticks / hz, ticks % hz * 100 / hz)
}

fn cpuinfo() -> Vec<u8> {
    let n = rk_frame::cpu::count();
    let mut out = String::new();
    for i in 0..n {
        out += &format!(
            "processor\t: {i}\nvendor_id\t: rukernel\nmodel name\t: {} virtual CPU\ncpu MHz\t\t: {}\n\
             physical id\t: 0\nsiblings\t: {n}\ncore id\t\t: {i}\ncpu cores\t: {n}\nflags\t\t:\n\n",
            rk_frame::arch::UNAME_MACHINE,
            rk_frame::time::timer_frequency() / 1_000_000,
        );
    }
    out.into_bytes()
}

fn stat() -> Vec<u8> {
    let all = rk_proc::processes();
    let running = all.iter().filter(|p| p.state_letter() == b'R').count();
    let boot = rk_vfs::now().sec - uptime().0 as i64;
    // The timer does not tick while the kernel runs, so the time that is not user time is idle.
    let hz = rk_frame::time::HZ;
    let total = rk_frame::time::ticks();
    // The kernel counts the user time of all CPUs together, so each CPU line has an equal part.
    let n = rk_frame::cpu::count() as u64;
    let user = rk_proc::user_ticks().min(total * n);
    let line = |user: u64, idle: u64| {
        format!("{} 0 0 {} 0 0 0 0 0 0", user * USER_HZ / hz, idle * USER_HZ / hz)
    };
    let cpus: String =
        (0..n).map(|i| format!("cpu{i} {}\n", line(user / n, total - user / n))).collect();
    format!(
        "cpu  {}\n{cpus}intr 0\nctxt 0\nbtime {boot}\nprocesses {}\n\
         procs_running {running}\nprocs_blocked 0\nsoftirq 0 0 0 0 0 0 0 0 0 0 0\n",
        line(user, total * n - user),
        all.iter().map(|p| p.pid()).max().unwrap_or(0),
    )
    .into_bytes()
}

/// The files of `/proc/sys` and their first values. A write keeps the new text, but the kernel
/// does not use it yet.
const SYSCTLS: &[(&str, &str)] = &[
    ("kernel/hostname", "(none)"),
    ("kernel/ngroups_max", "65536"),
    ("kernel/osrelease", ""),
    ("kernel/ostype", "Linux"),
    ("kernel/overflowgid", "65534"),
    ("kernel/overflowuid", "65534"),
    ("kernel/pid_max", "4194304"),
    ("kernel/tainted", "0"),
    ("kernel/threads-max", ""),
    ("kernel/version", ""),
    ("vm/max_map_count", "65530"),
    ("vm/min_free_kbytes", "1024"),
    ("vm/mmap_min_addr", "65536"),
    ("vm/overcommit_memory", "0"),
    ("vm/overcommit_ratio", "50"),
];

static SYSCTL_VALUES: SpinLock<Vec<(&'static str, Vec<u8>)>> = SpinLock::new(Vec::new());

fn sysctl_read(name: &'static str, default: &'static str) -> Vec<u8> {
    if let Some((_, v)) = SYSCTL_VALUES.lock().iter().find(|(n, _)| *n == name) {
        return v.clone();
    }
    let value = match name {
        "kernel/osrelease" => String::from(info().release),
        "kernel/version" => String::from(info().version),
        "kernel/threads-max" => format!("{}", (rk_frame::mm::frame_stats().total / 32).max(20)),
        _ => String::from(default),
    };
    format!("{value}\n").into_bytes()
}

fn sysctl_write(name: &'static str, data: &[u8]) {
    let mut value = data.to_vec();
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value.pop();
    }
    value.push(b'\n');
    let mut values = SYSCTL_VALUES.lock();
    values.retain(|(n, _)| *n != name);
    values.push((name, value));
}

fn sys_dir() -> InodeRef {
    sys_subdir("")
}

/// The directory `/proc/sys/<prefix>`, with the entries of `SYSCTLS` below it.
fn sys_subdir(prefix: &'static str) -> InodeRef {
    let path = if prefix.is_empty() { String::from("/sys") } else { format!("/sys/{prefix}") };
    let parent = match path.rfind('/') {
        Some(0) => String::from("/"),
        Some(i) => String::from(&path[..i]),
        None => String::from("/"),
    };
    let list_path = path.clone();
    dir(
        path.as_bytes(),
        parent.as_bytes(),
        0o555,
        move || {
            let mut out: Vec<(Vec<u8>, InodeRef)> = Vec::new();
            for &(name, default) in SYSCTLS {
                let rest = if prefix.is_empty() {
                    name
                } else {
                    match name.strip_prefix(prefix).and_then(|r| r.strip_prefix('/')) {
                        Some(r) => r,
                        None => continue,
                    }
                };
                match rest.split_once('/') {
                    Some((sub, _)) => {
                        if !out.iter().any(|(n, _)| n == sub.as_bytes()) {
                            let full = &name[..name.len() - rest.len() + sub.len()];
                            out.push((sub.as_bytes().to_vec(), sys_subdir(full)));
                        }
                    }
                    None => {
                        let fpath = format!("{list_path}/{rest}");
                        let node = rw_file(
                            fpath.as_bytes(),
                            move || Ok(sysctl_read(name, default)),
                            move |data| {
                                sysctl_write(name, data);
                                Ok(())
                            },
                        );
                        out.push((rest.as_bytes().to_vec(), node));
                    }
                }
            }
            Ok(out)
        },
        None,
    )
}

fn alive<T>(w: &Weak<T>) -> Result<Arc<T>> {
    w.upgrade().ok_or(Errno::ESRCH)
}

/// The signals that the process ignores and the signals that have a handler.
fn actions(p: &Process) -> (u64, u64) {
    let (mut ignored, mut caught) = (0, 0);
    for sig in 1..=NSIG {
        let handler = p.action(sig).handler;
        if handler == SIG_IGN {
            ignored |= 1 << (sig - 1);
        } else if handler > SIG_IGN {
            caught |= 1 << (sig - 1);
        }
    }
    (ignored, caught)
}

/// The state letter of one thread.
fn thread_state(t: &Thread) -> u8 {
    let p = t.process();
    if p.is_zombie() {
        return b'Z';
    }
    if t.is_trace_stopped() {
        return b't';
    }
    if p.is_stopped() {
        return b'T';
    }
    match t.task() {
        Some(task) if task.is_blocked() && t.in_killable_wait() => b'D',
        Some(task) if task.is_blocked() => b'S',
        Some(_) => b'R',
        None => b'Z',
    }
}

/// The text of `/proc/PID/syscall`: `running` for a thread that runs, the number, the arguments,
/// the stack pointer and the instruction pointer of a thread that waits in a system call, and -1
/// with the two pointers for a thread that waits outside one.
fn syscall_of(p: &Process, t: Option<&Thread>) -> Vec<u8> {
    let leader = p.threads().into_iter().find(|t| t.tid() == p.pid());
    let Some(thread) = t.or(leader.as_deref()) else { return b"running\n".to_vec() };
    if !thread.task().is_some_and(|task| task.is_blocked()) {
        return b"running\n".to_vec();
    }
    let info = thread.syscall_info();
    let text = if info.nr < 0 {
        format!("-1 {:#x} {:#x}\n", info.sp, info.pc)
    } else {
        let a = info.args;
        format!(
            "{} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}\n",
            info.nr, a[0], a[1], a[2], a[3], a[4], a[5], info.sp, info.pc
        )
    };
    text.into_bytes()
}

fn stat_of(p: &Process, t: Option<&Thread>) -> text::Stat {
    let (ignored, caught) = actions(p);
    let threads = p.threads();
    let leader = threads.iter().find(|t| t.tid() == p.pid()).cloned();
    let vsize = p.vm().map_or(0, |vm| vm.areas().iter().map(|a| (a.end - a.start) as u64).sum());
    let thread = t.or(leader.as_deref());
    text::Stat {
        pid: t.map_or(p.pid(), Thread::tid),
        comm: p.comm(),
        // Linux gives the state of the leader for the process, if the leader is there.
        state: thread.map_or_else(|| p.state_letter(), thread_state),
        ppid: p.ppid(),
        pgid: p.pgid(),
        sid: p.sid(),
        threads: threads.len(),
        // Linux gives the time of the thread in the stat of a thread.
        utime: t.map_or_else(|| p.user_ticks(), Thread::user_ticks) * USER_HZ / rk_frame::time::HZ,
        cutime: p.child_ticks() * USER_HZ / rk_frame::time::HZ,
        start: p.start_tick() * USER_HZ / rk_frame::time::HZ,
        vsize,
        rss: p.vm().map_or(0, |vm| vm.resident_pages(0, rk_frame::vm::USER_END) as u64),
        pending: thread.map_or(0, |t| t.pending().0),
        blocked: thread.map_or(0, |t| t.blocked().0),
        ignored,
        caught,
        exit_signal: p.exit_signal(),
    }
}

/// The sizes of `/proc/PID/statm`, as `task_statm` of Linux gives them.
fn statm_of(p: &Process) -> Statm {
    let mut m = Statm::default();
    let Some(vm) = p.vm() else { return m };
    for a in vm.areas() {
        let pages = ((a.end - a.start) / rk_mm::PAGE_SIZE) as u64;
        let resident = vm.resident_pages(a.start, a.end) as u64;
        let file = matches!(a.backing, Backing::File { .. });
        m.size += pages;
        m.resident += resident;
        if file || a.shared {
            m.shared += resident;
        }
        if file && a.prot.exec {
            m.text += pages;
        }
        if (a.prot.write && !a.shared) || a.kind == VmaKind::Stack {
            m.data += pages;
        }
    }
    m
}

fn status_of(p: &Process, t: Option<&Thread>) -> Vec<u8> {
    let s = stat_of(p, t);
    let threads = p.threads();
    let thread = t.or_else(|| threads.iter().find(|t| t.tid() == p.pid()).map(|t| &**t));
    let umask = p.fs().map_or(0o022, |fs| fs.lock().umask());
    let x = text::Status {
        tid: t.map_or(p.pid(), Thread::tid),
        tracer: thread.map_or(0, Thread::tracer_pid),
        umask,
        shared_pending: p.shared_pending().0,
        locked: p.vm().map_or(0, |vm| vm.locked_bytes() as u64),
        rss: p.vm().map_or(0, |vm| vm.resident_pages(0, rk_frame::vm::USER_END) as u64 * 4096),
    };
    let mut s = s;
    s.pid = p.pid();
    text::status(&s, &x)
}

/// Reads or writes `len` bytes of the memory of the process `w` at `addr`, one page at a time,
/// for `/proc/PID/mem`. `f` gets the address and the range of the buffer for each page. The
/// access stops at the first page that has no mapping, and gives the bytes before it. An access
/// that has no bytes gives `EIO`, as in Linux.
fn mem_access(
    w: &Weak<Process>,
    addr: u64,
    len: usize,
    mut f: impl FnMut(&rk_mm::AddressSpace, usize, core::ops::Range<usize>) -> Result<()>,
) -> Result<usize> {
    let vm = alive(w)?.vm().ok_or(Errno::EIO)?;
    let mut done = 0;
    while done < len {
        let Some(at) = usize::try_from(addr).ok().and_then(|a| a.checked_add(done)) else { break };
        if at >= rk_frame::vm::USER_END {
            break;
        }
        let n = (rk_mm::PAGE_SIZE - at % rk_mm::PAGE_SIZE).min(len - done);
        if f(&vm, at, done..done + n).is_err() {
            break;
        }
        done += n;
    }
    if done == 0 && len != 0 {
        return Err(Errno::EIO);
    }
    Ok(done)
}

fn maps_of(p: &Process) -> Result<Vec<u8>> {
    areas_of(p, false)
}

fn smaps_of(p: &Process) -> Result<Vec<u8>> {
    areas_of(p, true)
}

/// The text of `/proc/PID/maps`, or of `/proc/PID/smaps` with `smaps`.
fn areas_of(p: &Process, smaps: bool) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let Some(vm) = p.vm() else { return Ok(out) };
    for a in vm.areas() {
        let mut line = MapLine {
            start: a.start,
            end: a.end,
            read: a.prot.read,
            write: a.prot.write,
            exec: a.prot.exec,
            shared: a.shared,
            ..MapLine::default()
        };
        if let Backing::File { file, offset } = &a.backing {
            let (dev, ino, path) = file.name();
            line.offset = *offset;
            line.dev = dev;
            line.ino = ino;
            line.name = path;
        }
        match a.kind {
            VmaKind::Heap => line.name = b"[heap]".to_vec(),
            VmaKind::Stack => line.name = b"[stack]".to_vec(),
            VmaKind::Vdso => line.name = b"[vdso]".to_vec(),
            VmaKind::Vvar => line.name = b"[vvar]".to_vec(),
            VmaKind::Normal => {}
        }
        text::map_line(&mut out, &line);
        if smaps {
            let area = SmapsArea {
                size: (a.end - a.start) as u64,
                rss: vm.resident_pages(a.start, a.end) as u64 * 4096,
                anon: matches!(a.backing, Backing::Anon),
                locked: a.locked,
            };
            text::smaps_area(&mut out, &area, &line);
        }
    }
    Ok(out)
}

fn mounts_of(p: &Process) -> Result<Vec<u8>> {
    let fs = p.fs().ok_or(Errno::ESRCH)?.lock().clone();
    let mut out = Vec::new();
    for m in fs.namespace().mounts() {
        let at = Location { mount: m.clone(), dentry: m.root().clone() };
        let Ok(path) = fs.path_of(&at) else { continue };
        let src = m.source();
        text::escape(&mut out, &src.source);
        out.push(b' ');
        text::escape(&mut out, &path);
        out.extend_from_slice(
            format!(" {} {} 0 0\n", src.fstype, text::mount_options(src.flags)).as_bytes(),
        );
    }
    Ok(out)
}

fn mountinfo_of(p: &Process) -> Result<Vec<u8>> {
    let fs = p.fs().ok_or(Errno::ESRCH)?.lock().clone();
    let mut out = Vec::new();
    for m in fs.namespace().mounts() {
        let at = Location { mount: m.clone(), dentry: m.root().clone() };
        let Ok(path) = fs.path_of(&at) else { continue };
        // The path of the root of the mount in its file system. It is not `/` after `MS_BIND`.
        let mut root = Vec::new();
        let mut d = m.root().clone();
        while let Some(up) = d.parent() {
            let mut part = Vec::from(&b"/"[..]);
            part.extend_from_slice(&d.name());
            root.splice(0..0, part);
            d = up;
        }
        if root.is_empty() {
            root.push(b'/');
        }
        let src = m.source();
        let info = text::MountInfo {
            id: m.id(),
            parent: m.mountpoint().map_or(m.id(), |up| up.mount.id()),
            dev: m.root().inode().metadata().dev,
            root: &root,
            path: &path,
            flags: src.flags,
            fstype: src.fstype,
            source: &src.source,
        };
        text::mountinfo(&mut out, &info);
    }
    Ok(out)
}

/// The target of a link in `/proc/PID/fd`.
fn fd_target(file: &rk_vfs::File, fs: Option<&rk_vfs::FsContext>) -> Vec<u8> {
    if let Some(at) = file.location() {
        return fs.and_then(|fs| fs.path_of(at).ok()).unwrap_or_else(|| at.absolute_path());
    }
    match file.metadata() {
        Ok(m) if m.mode & rk_vfs::inode::mode::S_IFMT == rk_vfs::inode::mode::S_IFIFO => {
            format!("pipe:[{}]", m.ino).into_bytes()
        }
        Ok(m) if m.mode & rk_vfs::inode::mode::S_IFMT == rk_vfs::inode::mode::S_IFSOCK => {
            format!("socket:[{}]", m.ino).into_bytes()
        }
        _ => b"anon_inode:[unknown]".to_vec(),
    }
}

fn fd_dir(w: Weak<Process>, base: &[u8]) -> InodeRef {
    let path = join(base, b"fd");
    let me = path.clone();
    dir(
        &path,
        base,
        0o500,
        move || {
            let p = alive(&w)?;
            let files = p.files().ok_or(Errno::ESRCH)?;
            let fs = p.fs().map(|fs| fs.lock().clone());
            let entries: Vec<(i32, Arc<rk_vfs::File>)> =
                files.lock().iter().map(|(fd, e)| (fd, e.file.clone())).collect();
            Ok(entries
                .into_iter()
                .map(|(fd, file)| {
                    let name = format!("{fd}").into_bytes();
                    let target = fd_target(&file, fs.as_ref());
                    let flags = file.flags();
                    let perm = 0o100 * u32::from(flags.readable()) * 4
                        + 0o100 * u32::from(flags.writable()) * 2
                        + 0o100;
                    let path = join(&me, &name);
                    // A socket cannot open again through its link, as `sock_no_open` of Linux.
                    let node = if target.starts_with(b"socket:[") {
                        dead_link(&path, perm, move || Ok(target.clone()), Errno::ENXIO)
                    } else {
                        link(&path, perm, move || Ok(target.clone()))
                    };
                    (name, node)
                })
                .collect())
        },
        None,
    )
}

/// The files of a process directory, from the process `w`. `t` is the thread of a directory in
/// `task`, or `None` for the directory of the process.
fn process_files(
    w: &Weak<Process>,
    t: Option<Weak<Thread>>,
    base: &[u8],
) -> Vec<(Vec<u8>, InodeRef)> {
    let mut out: Vec<(Vec<u8>, InodeRef)> = Vec::new();
    let p_ = w.clone();
    let t_ = t.clone();
    out.push((
        b"stat".to_vec(),
        file(&join(base, b"stat"), move || {
            let p = alive(&p_)?;
            let t = t_.as_ref().map(alive).transpose()?;
            Ok(text::stat(&stat_of(&p, t.as_deref())))
        }),
    ));
    let p_ = w.clone();
    let t_ = t.clone();
    out.push((
        b"status".to_vec(),
        file(&join(base, b"status"), move || {
            let p = alive(&p_)?;
            let t = t_.as_ref().map(alive).transpose()?;
            Ok(status_of(&p, t.as_deref()))
        }),
    ));
    let p_ = w.clone();
    let p2 = w.clone();
    out.push((
        b"comm".to_vec(),
        rw_file(
            &join(base, b"comm"),
            move || {
                let mut c = alive(&p_)?.comm();
                c.push(b'\n');
                Ok(c)
            },
            move |data| {
                let name = data.strip_suffix(b"\n").unwrap_or(data);
                alive(&p2)?.set_comm(name);
                Ok(())
            },
        ),
    ));
    let p_ = w.clone();
    let t_ = t.clone();
    out.push((
        b"syscall".to_vec(),
        file(&join(base, b"syscall"), move || {
            let p = alive(&p_)?;
            let t = t_.as_ref().map(alive).transpose()?;
            Ok(syscall_of(&p, t.as_deref()))
        }),
    ));
    let p_ = w.clone();
    out.push((
        b"cmdline".to_vec(),
        file(&join(base, b"cmdline"), move || Ok(alive(&p_)?.cmdline())),
    ));
    out.push((b"environ".to_vec(), file(&join(base, b"environ"), || Ok(Vec::new()))));
    let p_ = w.clone();
    out.push((b"auxv".to_vec(), file(&join(base, b"auxv"), move || Ok(alive(&p_)?.auxv()))));
    let p_ = w.clone();
    let p2 = w.clone();
    out.push((
        b"mem".to_vec(),
        data_file(
            &join(base, b"mem"),
            0o600,
            move |addr, buf| {
                mem_access(&p_, addr, buf.len(), |vm, at, range| vm.read(at, &mut buf[range]))
            },
            move |addr, buf| {
                mem_access(&p2, addr, buf.len(), |vm, at, range| vm.write_force(at, &buf[range]))
            },
        ),
    ));
    let p_ = w.clone();
    out.push((b"maps".to_vec(), file(&join(base, b"maps"), move || maps_of(&*alive(&p_)?))));
    let p_ = w.clone();
    out.push((b"smaps".to_vec(), file(&join(base, b"smaps"), move || smaps_of(&*alive(&p_)?))));
    let p_ = w.clone();
    out.push((b"mounts".to_vec(), file(&join(base, b"mounts"), move || mounts_of(&*alive(&p_)?))));
    let p_ = w.clone();
    out.push((
        b"mountinfo".to_vec(),
        file(&join(base, b"mountinfo"), move || mountinfo_of(&*alive(&p_)?)),
    ));
    let p_ = w.clone();
    out.push((
        b"statm".to_vec(),
        file(&join(base, b"statm"), move || Ok(text::statm(&statm_of(&*alive(&p_)?)))),
    ));
    let p_ = w.clone();
    let p2 = w.clone();
    out.push((
        b"oom_score_adj".to_vec(),
        rw_file(
            &join(base, b"oom_score_adj"),
            move || Ok(text::number(i64::from(alive(&p_)?.oom_score_adj()))),
            move |data| {
                let v = text::parse_number(data).ok_or(Errno::EINVAL)?;
                if !(-1000..=1000).contains(&v) {
                    return Err(Errno::EINVAL);
                }
                alive(&p2)?.set_oom_score_adj(v as i32);
                Ok(())
            },
        ),
    ));
    out.push((b"oom_score".to_vec(), file(&join(base, b"oom_score"), || Ok(b"0\n".to_vec()))));
    let p_ = w.clone();
    out.push((
        b"exe".to_vec(),
        link(&join(base, b"exe"), 0o777, move || {
            let p = alive(&p_)?;
            let exe = p.exe().ok_or(Errno::ENOENT)?;
            let fs = p.fs().map(|fs| fs.lock().clone());
            Ok(fs.and_then(|fs| fs.path_of(&exe).ok()).unwrap_or_else(|| exe.absolute_path()))
        }),
    ));
    let p_ = w.clone();
    out.push((
        b"cwd".to_vec(),
        link(&join(base, b"cwd"), 0o777, move || {
            let fs = alive(&p_)?.fs().ok_or(Errno::ENOENT)?.lock().clone();
            fs.getcwd()
        }),
    ));
    let p_ = w.clone();
    out.push((
        b"root".to_vec(),
        link(&join(base, b"root"), 0o777, move || {
            let fs = alive(&p_)?.fs().ok_or(Errno::ENOENT)?.lock().clone();
            fs.path_of(fs.root())
        }),
    ));
    out.push((b"fd".to_vec(), fd_dir(w.clone(), base)));
    out
}

fn process_dir(p: &Arc<Process>) -> InodeRef {
    let w = Arc::downgrade(p);
    let base = format!("/{}", p.pid()).into_bytes();
    let list_base = base.clone();
    dir(
        &base,
        b"/",
        0o555,
        move || {
            alive(&w)?;
            let mut out = process_files(&w, None, &list_base);
            out.push((b"task".to_vec(), task_dir(w.clone(), &list_base)));
            Ok(out)
        },
        None,
    )
}

fn task_dir(w: Weak<Process>, base: &[u8]) -> InodeRef {
    let path = join(base, b"task");
    let me = path.clone();
    dir(
        &path,
        base,
        0o555,
        move || {
            let p = alive(&w)?;
            Ok(p.threads()
                .iter()
                .map(|t| {
                    let name = format!("{}", t.tid()).into_bytes();
                    let node = thread_dir(t, &join(&me, &name), &me);
                    (name, node)
                })
                .collect())
        },
        None,
    )
}

fn thread_dir(t: &Arc<Thread>, path: &[u8], parent: &[u8]) -> InodeRef {
    let tw = Arc::downgrade(t);
    let pw = Arc::downgrade(t.process());
    let base = path.to_vec();
    dir(
        path,
        parent,
        0o555,
        move || {
            alive(&tw)?;
            Ok(process_files(&pw, Some(tw.clone()), &base))
        },
        None,
    )
}

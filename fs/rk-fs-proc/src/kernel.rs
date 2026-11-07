//! The files of procfs that read the state of the kernel: the root directory, the system files,
//! `/proc/sys` and the directory of each process.

use crate::node::{
    FindFn, data_file, dead_link, dir, file, join, jump_link, link, ops_file, rw_file, set_gone,
    set_owner,
};
use crate::procmap;
use crate::text::{self, MapLine, MemInfo, SmapsArea, Statm};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use rk_abi::Errno;
use rk_frame::sync::{Once, SpinLock};
use rk_mm::{Backing, FileRef, HugeAdvice, Vma, VmaKind};
use rk_proc::exec::USER_HZ;
use rk_proc::pid_namespace::{self, PidNamespace};
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
    /// Fills a buffer with random bytes, for `kernel.random.boot_id` and `kernel.random.uuid`.
    pub random: Option<fn(&mut [u8])>,
}

static INFO: Once<KernelInfo> = Once::new();

/// Gives procfs the facts about the kernel. Only the first call has an effect.
pub fn set_kernel_info(info: KernelInfo) {
    INFO.call_once(|| info);
}

fn info() -> KernelInfo {
    INFO.get().cloned().unwrap_or_default()
}

/// The PID namespace of a mount of procfs, or `None` for the first namespace.
type PidNs = Option<Arc<PidNamespace>>;

/// Makes the root directory of a mount of procfs. The mount shows the processes of the PID
/// namespace `ns` with their IDs in it, as the `pid_ns` of the superblock of Linux.
pub(crate) fn root(ns: PidNs) -> InodeRef {
    let find_ns = ns.clone();
    let find: FindFn = Box::new(move |name: &[u8]| {
        if let Some(nr) = parse_pid(name) {
            let pid = pid_namespace::find_pid_ns(nr, find_ns.as_ref()).ok_or(Errno::ENOENT)?;
            if let Some(p) = rk_proc::find_process(pid) {
                return Ok(process_dir(&p, &find_ns));
            }
            // A thread that is not the leader has a directory too, which `ls` does not show.
            if let Some(t) = rk_proc::find_thread(pid) {
                return Ok(thread_dir(&t, &join(b"/", name), b"/", &find_ns));
            }
            return Err(Errno::ENOENT);
        }
        root_files(&find_ns)
            .into_iter()
            .find(|(n, _)| n == name)
            .map(|(_, i)| i)
            .ok_or(Errno::ENOENT)
    });
    dir(b"/", b"/", 0o555, move || root_list(&ns), Some(find))
}

/// The text that `show` makes from the block devices, in the order of their numbers.
fn disks(show: fn(&[text::Disk]) -> String) -> Vec<u8> {
    let list: Vec<text::Disk> = rk_vfs::blockdev::block_devices()
        .into_iter()
        .filter_map(|(name, rdev)| {
            let q = rk_vfs::blockdev::block_queue(rdev)?;
            let (major, minor) = (rk_vfs::device::major(rdev), rk_vfs::device::minor(rdev));
            Some(text::Disk { major, minor, name, sectors: q.sectors(), stats: q.stats().fields() })
        })
        .collect();
    show(&list).into_bytes()
}

/// The counts of the memory for `/proc/vmstat`, `/proc/zoneinfo` and `/proc/buddyinfo`.
fn vm_counts() -> text::VmCounts {
    let f = rk_frame::mm::frame_stats();
    let traps = rk_frame::trap::counts();
    let span = rk_frame::mm::frame_span();
    let mut sectors = [0u64; 2];
    for (_, rdev) in rk_vfs::blockdev::block_devices() {
        if let Some(q) = rk_vfs::blockdev::block_queue(rdev) {
            let s = q.stats();
            sectors[0] += s.sectors[0];
            sectors[1] += s.sectors[1];
        }
    }
    let cpus = (0..rk_frame::cpu::count())
        .map(|cpu| {
            let (count, high, batch) = rk_frame::mm::cpu_free_frames(cpu);
            (count as u64, high as u64, batch as u64)
        })
        .collect();
    text::VmCounts {
        total: f.total as u64,
        free: f.free as u64,
        anon_thp: rk_frame::vm::huge_pages_mapped() as u64,
        faults: traps.page_faults + traps.user_page_faults,
        pgpgin: sectors[0] / 2,
        pgpgout: sectors[1] / 2,
        min_free_kbytes: rk_mm::tunables::min_free_kbytes(f.total) as u64,
        span: (span.start as u64, span.end as u64),
        blocks: rk_frame::mm::free_blocks().map(|n| n as u64),
        cpus,
    }
}

/// The entries of the root: the files, and a directory for each process of the namespace `ns`,
/// with its ID in `ns`.
fn root_list(ns: &PidNs) -> Result<Vec<(Vec<u8>, InodeRef)>> {
    let mut out = root_files(ns);
    for p in rk_proc::processes() {
        let nr = pid_namespace::pid_nr_ns(p.pid(), ns.as_ref());
        if nr != 0 {
            out.push((format!("{nr}").into_bytes(), process_dir(&p, ns)));
        }
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

fn root_files(ns: &PidNs) -> Vec<(Vec<u8>, InodeRef)> {
    let files: [(&[u8], fn() -> Vec<u8>); 13] = [
        (b"meminfo", || {
            let f = rk_frame::mm::frame_stats();
            let kb = (rk_mm::PAGE_SIZE / 1024) as u64;
            let swap = rk_vfs::swap::total_pages() * kb;
            let pages = |n: usize| n as u64 * kb;
            text::meminfo(MemInfo {
                total: pages(f.total),
                free: pages(f.free),
                swap,
                commit_limit: pages(rk_mm::tunables::commit_limit(f.total)),
                committed: pages(rk_mm::tunables::committed_pages()),
                anon_huge: rk_frame::vm::huge_pages_mapped() as u64 * 2048,
                hugetlb: rk_mm::hugetlb::counts(),
            })
            .into_bytes()
        }),
        (b"cpuinfo", cpuinfo),
        (b"uptime", || {
            // The time since boot is a time of `CLOCK_BOOTTIME` in the time namespace of the
            // reader, as `uptime_proc_show` of Linux.
            let (s, cs) = match rk_proc::current_thread() {
                Some(t) => {
                    let ns = t
                        .time_ns()
                        .to_ns(rk_proc::timens::CLOCK_BOOTTIME, rk_frame::time::clock_ns());
                    (ns / 1_000_000_000, ns % 1_000_000_000 / 10_000_000)
                }
                None => uptime(),
            };
            format!("{s}.{cs:02} 0.00\n").into_bytes()
        }),
        (b"loadavg", || {
            let all = rk_proc::processes();
            let running = all.iter().filter(|p| p.state_letter() == b'R').count();
            let last = all.iter().map(|p| p.pid()).max().unwrap_or(0);
            format!("0.00 0.00 0.00 {running}/{} {last}\n", all.len()).into_bytes()
        }),
        (b"stat", stat),
        (b"interrupts", || {
            let cpus = rk_frame::cpu::count();
            let tlb: Option<Vec<u64>> = (0..cpus).map(rk_frame::cpu::tlb_shootdowns).collect();
            text::interrupts(cpus, tlb.as_deref()).into_bytes()
        }),
        (b"version", || {
            let i = info();
            format!("Linux version {} (rukernel) {}\n", i.release, i.version).into_bytes()
        }),
        (b"cmdline", || format!("{}\n", info().cmdline).into_bytes()),
        (b"devices", || rk_vfs::device::proc_devices().into_bytes()),
        (b"keys", || {
            rk_proc::current_thread()
                .map_or_else(Vec::new, |t| t.with_keys(rk_proc::keys::keys_text))
        }),
        (b"key-users", rk_proc::keys::key_users_text),
        (b"filesystems", || {
            let mut out = String::new();
            for t in rk_vfs::fstype::types() {
                out.push_str(if t.nodev { "nodev\t" } else { "\t" });
                out.push_str(t.name);
                out.push('\n');
            }
            out.into_bytes()
        }),
        (b"swaps", || {
            let kb = (rk_mm::PAGE_SIZE / 1024) as u64;
            let mut out = String::from(text::SWAPS_HEADER);
            rk_vfs::swap::for_each(|s| {
                out.push_str(&text::swap_line(&s.path, s.partition, s.pages * kb, 0, s.priority));
            });
            out.into_bytes()
        }),
    ];
    let mut out: Vec<(Vec<u8>, InodeRef)> =
        files.iter().map(|&(name, f)| (name.to_vec(), text_file(&join(b"/", name), f))).collect();
    out.push((b"mounts".to_vec(), link(b"/mounts", 0o777, || Ok(b"self/mounts".to_vec()))));
    out.push((b"net".to_vec(), link(b"/net", 0o777, || Ok(b"self/net".to_vec()))));
    // A machine with a device tree has `/proc/device-tree`, as `proc_device_tree_init` of Linux.
    if rk_frame::firmware::device_tree().is_some() {
        out.push((
            b"device-tree".to_vec(),
            link(b"/device-tree", 0o777, || Ok(b"/sys/firmware/devicetree/base".to_vec())),
        ));
    }
    // `self` and `thread-self` give the IDs of the caller in the namespace of the mount, and
    // they do not exist for a caller that the namespace does not see, as `proc_self_get_link`
    // of Linux.
    let self_ns = ns.clone();
    out.push((
        b"self".to_vec(),
        link(b"/self", 0o777, move || {
            let t = rk_proc::current_thread().ok_or(Errno::ENOENT)?;
            let tgid = pid_namespace::pid_nr_ns(t.process().pid(), self_ns.as_ref());
            if tgid == 0 {
                return Err(Errno::ENOENT);
            }
            Ok(format!("{tgid}").into_bytes())
        }),
    ));
    let thread_ns = ns.clone();
    out.push((
        b"thread-self".to_vec(),
        link(b"/thread-self", 0o777, move || {
            let t = rk_proc::current_thread().ok_or(Errno::ENOENT)?;
            let tgid = pid_namespace::pid_nr_ns(t.process().pid(), thread_ns.as_ref());
            let tid = pid_namespace::pid_nr_ns(t.tid(), thread_ns.as_ref());
            if tgid == 0 || tid == 0 {
                return Err(Errno::ENOENT);
            }
            Ok(format!("{tgid}/task/{tid}").into_bytes())
        }),
    ));
    out.push((
        b"kpageflags".to_vec(),
        data_file(b"/kpageflags", 0o400, kpageflags_read, |_, _| Err(Errno::EINVAL)),
    ));
    out.push((b"sys".to_vec(), sys_dir()));
    out.push((b"sysvipc".to_vec(), sysvipc_dir()));
    out.push((b"bus".to_vec(), bus_dir()));
    out.push((
        b"cgroups".to_vec(),
        text_file(b"/cgroups", || rk_cgroup::with(|h| h.proc_cgroups()).into_bytes()),
    ));
    out.push((b"pressure".to_vec(), pressure_dir()));
    out.push((b"diskstats".to_vec(), text_file(b"/diskstats", || disks(text::diskstats))));
    out.push((b"partitions".to_vec(), text_file(b"/partitions", || disks(text::partitions))));
    out.push((
        b"buddyinfo".to_vec(),
        text_file(b"/buddyinfo", || text::buddyinfo(&vm_counts()).into_bytes()),
    ));
    out.push((
        b"vmstat".to_vec(),
        text_file(b"/vmstat", || text::vmstat(&vm_counts()).into_bytes()),
    ));
    out.push((
        b"zoneinfo".to_vec(),
        text_file(b"/zoneinfo", || text::zoneinfo(&vm_counts()).into_bytes()),
    ));
    out
}

/// The directory `/proc/pressure`: the pressure of the CPU, the memory and the I/O of the
/// system, from the root cgroup.
fn pressure_dir() -> InodeRef {
    dir(
        b"/pressure",
        b"/",
        0o555,
        || {
            // An open file keeps a trigger after a write, as the pressure files of cgroup2.
            let files: [(&[u8], usize); 3] = [
                (b"cpu", rk_cgroup::psi::CPU),
                (b"memory", rk_cgroup::psi::MEMORY),
                (b"io", rk_cgroup::psi::IO),
            ];
            Ok(files
                .iter()
                .map(|&(name, r)| {
                    let file = ops_file(
                        &join(b"/pressure", name),
                        0o666,
                        move || Ok(pressure(r)),
                        move || rk_fs_cgroup::system_pressure(r),
                    );
                    (name.to_vec(), file)
                })
                .collect())
        },
        None,
    )
}

/// The text of a file of `/proc/pressure` for the resource `r`.
fn pressure(r: usize) -> Vec<u8> {
    let t = rk_cgroup::now();
    rk_cgroup::with(|h| h.psi_show(rk_cgroup::ROOT, r, t)).unwrap_or_default().into_bytes()
}

/// The text of `/proc/PID/cgroup`: the path of the cgroup of `p` from the root of the cgroup
/// namespace of the caller, as cgroup v2 of Linux shows it.
fn cgroup_of(p: &Process) -> Vec<u8> {
    let ns = rk_proc::current_thread().map_or(0, |t| t.process().cgroup_ns());
    let path = rk_cgroup::with(|h| h.path_from(p.cgroup(), h.namespace_root(ns)));
    let mut out = b"0::".to_vec();
    out.extend_from_slice(&path);
    out.push(b'\n');
    out
}

/// The directory `/proc/PID/ns`: a magic link for each namespace of the process that has a file,
/// as `fs/proc/namespaces.c` of Linux. The link shows `KIND:[INODE]`, and a walk goes to the
/// file of the namespace, which `setns` takes. `t` is the thread of a directory in `task`: each
/// thread has its own network namespace.
fn ns_dir(base: &[u8], w: Weak<Process>, t: Option<Weak<Thread>>) -> InodeRef {
    use rk_vfs::nsfs::{NsInode, NsKind, link_text};
    /// The entries.
    const ENTRIES: [(&[u8], NsKind); 10] = [
        (b"cgroup", NsKind::Cgroup),
        (b"ipc", NsKind::Ipc),
        (b"mnt", NsKind::Mnt),
        (b"net", NsKind::Net),
        (b"pid", NsKind::Pid),
        (b"pid_for_children", NsKind::Pid),
        (b"time", NsKind::Time),
        (b"time_for_children", NsKind::Time),
        (b"user", NsKind::User),
        (b"uts", NsKind::Uts),
    ];
    let path = join(base, b"ns");
    let path_ = path.clone();
    dir(
        &path,
        base,
        0o511,
        move || {
            Ok(ENTRIES
                .iter()
                .map(|&(name, kind)| {
                    let children = name == b"time_for_children";
                    let pid_children = name == b"pid_for_children";
                    let (p_, p_j) = (w.clone(), w.clone());
                    let (t_, t_j) = (t.clone(), t.clone());
                    let link = jump_link(
                        &join(&path_, name),
                        0o777,
                        move || {
                            let p = alive(&p_)?;
                            let id = match (kind, &t_) {
                                (NsKind::Net, Some(t)) => alive(t)?.net_ns().id(),
                                (NsKind::Uts, Some(t)) => alive(t)?.uts_ns().id(),
                                (NsKind::Ipc, Some(t)) => alive(t)?.ipc_ns().id(),
                                (NsKind::Time, _) => time_ns(&p, t_.as_ref(), children)?.id(),
                                (NsKind::User, _) => p.cred().user_ns.id(),
                                (NsKind::Pid, _) if pid_children => {
                                    let ns = pid_ns_for_children(&p, t_.as_ref())?;
                                    rk_proc::pid_namespace::ns_id(ns.as_ref())
                                }
                                _ => rk_proc::ns::ns_id(&p, kind)?,
                            };
                            Ok(link_text(kind, id))
                        },
                        move || {
                            let p = alive(&p_j)?;
                            let node = match kind {
                                // The file keeps the network, UTS or IPC namespace, as on Linux.
                                NsKind::Net => {
                                    let net = match &t_j {
                                        Some(t) => alive(t)?.net_ns(),
                                        None => p.net_ns(),
                                    };
                                    NsInode::with_hold(kind, net.id(), net)
                                }
                                NsKind::Uts => {
                                    let uts = match &t_j {
                                        Some(t) => alive(t)?.uts_ns(),
                                        None => p.uts_ns(),
                                    };
                                    NsInode::with_hold(kind, uts.id(), uts)
                                }
                                NsKind::Ipc => {
                                    let ipc = match &t_j {
                                        Some(t) => alive(t)?.ipc_ns(),
                                        None => p.ipc_ns(),
                                    };
                                    NsInode::with_hold(kind, ipc.id(), ipc)
                                }
                                NsKind::Time => {
                                    let ns = time_ns(&p, t_j.as_ref(), children)?;
                                    NsInode::with_hold(kind, ns.id(), ns)
                                }
                                // The file keeps the user namespace, as on Linux.
                                NsKind::User => {
                                    let ns = p.cred().user_ns.clone();
                                    NsInode::with_hold(kind, ns.id(), ns)
                                }
                                // The file keeps the PID namespace, as on Linux.
                                NsKind::Pid => {
                                    let ns = if pid_children {
                                        pid_ns_for_children(&p, t_j.as_ref())?
                                    } else {
                                        p.pid_ns().cloned()
                                    };
                                    match ns {
                                        Some(ns) => NsInode::with_hold(kind, ns.id(), ns),
                                        None => NsInode::new(kind, 0),
                                    }
                                }
                                _ => NsInode::new(kind, rk_proc::ns::ns_id(&p, kind)?),
                            };
                            Ok(rk_vfs::Location::detached(node))
                        },
                    );
                    (name.to_vec(), owned(&w, link))
                })
                .collect())
        },
        None,
    )
}

/// The PID namespace for the children of the thread `t`, or of `p` without a thread, as
/// `pidns_for_children_get` of Linux. `None` is the first namespace.
///
/// # Errors
///
/// Gives `ENOENT` for a new namespace whose init did not start yet.
fn pid_ns_for_children(
    p: &Process,
    t: Option<&Weak<Thread>>,
) -> Result<Option<Arc<rk_proc::pid_namespace::PidNamespace>>> {
    let ns = match t {
        Some(t) => alive(t)?.pid_ns_for_children(),
        None => p.pid_ns_for_children(),
    };
    if let Some(n) = &ns
        && !rk_proc::pid_namespace::same(ns.as_ref(), p.pid_ns())
        && !n.has_child_reaper()
    {
        return Err(Errno::ENOENT);
    }
    Ok(ns)
}

/// The time namespace of the thread `t`, or of `p` without a thread, or the namespace for its
/// children if `children` is set.
fn time_ns(
    p: &Process,
    t: Option<&Weak<Thread>>,
    children: bool,
) -> Result<Arc<rk_proc::timens::TimeNs>> {
    Ok(match (t, children) {
        (Some(t), false) => alive(t)?.time_ns(),
        (Some(t), true) => alive(t)?.time_ns_for_children(),
        (None, false) => p.time_ns(),
        (None, true) => p.time_ns_for_children(),
    })
}

/// The directory `/proc/bus` with `input/devices`, the input devices and their handlers, as
/// drivers/input/input.c of Linux.
fn bus_dir() -> InodeRef {
    let input = || {
        let devices = || rk_vfs::input::proc_devices().into_bytes();
        let list = alloc::vec![(b"devices".to_vec(), text_file(b"/bus/input/devices", devices))];
        Ok(list)
    };
    dir(
        b"/bus",
        b"/",
        0o555,
        move || {
            Ok(alloc::vec![(b"input".to_vec(), dir(b"/bus/input", b"/bus", 0o555, input, None))])
        },
        None,
    )
}

/// The directory `/proc/sysvipc`, with the System V objects of each kind.
fn sysvipc_dir() -> InodeRef {
    dir(
        b"/sysvipc",
        b"/",
        0o555,
        || {
            Ok(rk_vfs::ipc::SYSVIPC_FILES
                .iter()
                .map(|&name| {
                    let path = join(b"/sysvipc", name.as_bytes());
                    (name.as_bytes().to_vec(), file(&path, move || Ok(rk_vfs::ipc::sysvipc(name))))
                })
                .collect())
        },
        None,
    )
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
    // The time of the boot is the real time less the time since boot in the time namespace of
    // the reader, as `show_stat` of Linux.
    let off = rk_proc::current_thread()
        .map_or(0, |t| t.time_ns().offset(rk_proc::timens::CLOCK_BOOTTIME));
    let boot =
        (rk_frame::time::realtime_offset_ns() as i64).wrapping_sub(off).div_euclid(1_000_000_000);
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
    ("fs/file-max", ""),
    ("fs/nr_open", ""),
    ("fs/inotify/max_queued_events", ""),
    ("fs/inotify/max_user_instances", ""),
    ("fs/inotify/max_user_watches", ""),
    ("fs/fanotify/max_queued_events", ""),
    ("fs/fanotify/max_user_groups", ""),
    ("fs/fanotify/max_user_marks", ""),
    ("fs/lease-break-time", ""),
    ("fs/leases-enable", ""),
    ("fs/pipe-max-size", ""),
    // rukernel does not count the pipe pages of each user, so the limits only keep their text.
    ("fs/pipe-user-pages-hard", "0"),
    ("fs/pipe-user-pages-soft", "16384"),
    ("fs/protected_fifos", ""),
    ("fs/protected_hardlinks", ""),
    ("fs/protected_regular", ""),
    ("fs/protected_symlinks", ""),
    ("fs/suid_dumpable", ""),
    ("kernel/cap_last_cap", ""),
    ("kernel/core_pattern", ""),
    ("kernel/core_uses_pid", ""),
    ("kernel/domainname", ""),
    ("kernel/hostname", ""),
    ("kernel/keys/gc_delay", ""),
    ("kernel/keys/maxbytes", ""),
    ("kernel/keys/maxkeys", ""),
    ("kernel/keys/root_maxbytes", ""),
    ("kernel/keys/root_maxkeys", ""),
    ("kernel/ngroups_max", "65536"),
    ("kernel/ns_last_pid", ""),
    ("kernel/osrelease", ""),
    ("kernel/ostype", "Linux"),
    ("kernel/overflowgid", "65534"),
    ("kernel/overflowuid", "65534"),
    ("kernel/pid_max", "4194304"),
    // The console, default, smallest and boot log levels, as `console_printk` of Linux.
    ("kernel/printk", "4\t4\t1\t7"),
    // The generator is ready at boot, so the entropy count is full, as `input_pool.init_bits`
    // of Linux. The two files only give text.
    ("kernel/random/boot_id", ""),
    ("kernel/random/entropy_avail", "256"),
    ("kernel/random/poolsize", "256"),
    ("kernel/random/uuid", ""),
    ("kernel/sched_rr_timeslice_ms", ""),
    ("kernel/sem", ""),
    ("kernel/sched_rt_period_us", ""),
    ("kernel/sched_rt_runtime_us", ""),
    ("kernel/tainted", "0"),
    ("kernel/threads-max", ""),
    // Who can make BPF maps, which rk-bpf reads.
    ("kernel/unprivileged_bpf_disabled", ""),
    ("kernel/version", ""),
    // Yama, when it is an active module.
    ("kernel/yama/ptrace_scope", ""),
    // The limits of the user namespace of the reader, as kernel/ucount.c of Linux.
    ("user/max_cgroup_namespaces", ""),
    ("user/max_fanotify_groups", ""),
    ("user/max_fanotify_marks", ""),
    ("user/max_inotify_instances", ""),
    ("user/max_inotify_watches", ""),
    ("user/max_ipc_namespaces", ""),
    ("user/max_mnt_namespaces", ""),
    ("user/max_net_namespaces", ""),
    ("user/max_pid_namespaces", ""),
    ("user/max_time_namespaces", ""),
    ("user/max_user_namespaces", ""),
    ("user/max_uts_namespaces", ""),
    ("vm/dirty_background_bytes", "0"),
    ("vm/dirty_background_ratio", "10"),
    ("vm/dirty_bytes", "0"),
    ("vm/dirty_expire_centisecs", "3000"),
    ("vm/dirty_ratio", "20"),
    ("vm/dirty_writeback_centisecs", "500"),
    ("vm/drop_caches", "0"),
    ("vm/hugetlb_shm_group", ""),
    ("vm/max_map_count", ""),
    ("vm/memfd_noexec", ""),
    ("vm/min_free_kbytes", ""),
    ("vm/mmap_min_addr", "65536"),
    ("vm/compact_memory", "0"),
    ("vm/nr_hugepages", ""),
    ("vm/nr_hugepages_mempolicy", ""),
    ("vm/nr_overcommit_hugepages", ""),
    ("vm/overcommit_kbytes", ""),
    ("vm/overcommit_memory", ""),
    ("vm/overcommit_ratio", ""),
    ("vm/panic_on_oom", "0"),
    // The kernel has no inode and dentry caches to shrink, so the value only keeps its text.
    ("vm/vfs_cache_pressure", "100"),
];

/// The sysctls that only give text, with the mode 0444 of Linux.
const READ_ONLY_SYSCTLS: &[&str] = &[
    "kernel/cap_last_cap",
    "kernel/random/boot_id",
    "kernel/random/entropy_avail",
    "kernel/random/poolsize",
    "kernel/random/uuid",
];

/// Makes a random UUID of version 4 in the text form of `%pU` of Linux, as `proc_do_uuid` in
/// drivers/char/random.c.
fn uuid_text(mut uuid: [u8; 16]) -> Vec<u8> {
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    let mut out = String::new();
    for (i, b) in uuid.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out += &format!("{b:02x}");
    }
    out.push('\n');
    out.into_bytes()
}

/// 16 random bytes from the generator of the kernel.
fn random_uuid() -> [u8; 16] {
    let mut uuid = [0; 16];
    if let Some(fill) = info().random {
        fill(&mut uuid);
    }
    uuid
}

/// The ID of this boot, `kernel.random.boot_id`. It is random, and it stays the same until the
/// next boot. journald puts it in each record.
fn boot_id() -> [u8; 16] {
    static ID: Once<[u8; 16]> = Once::new();
    *ID.call_once(random_uuid)
}

static SYSCTL_VALUES: SpinLock<Vec<(&'static str, Vec<u8>)>> = SpinLock::new(Vec::new());

/// The sysctl of `name` that the VFS reads, `fs.protected_*`, `fs.inotify.*` and the lease
/// sysctls, and its largest value.
fn protected(name: &str) -> Option<(&'static AtomicU32, u32)> {
    use rk_vfs::cred::protected::{FIFOS, HARDLINKS, REGULAR, SYMLINKS};
    use rk_vfs::lease::{BREAK_TIME, ENABLE};
    use rk_vfs::notify::inotify::{MAX_QUEUED_EVENTS, MAX_USER_INSTANCES, MAX_USER_WATCHES};
    // The inotify and fanotify limits go from 0 to `INT_MAX`, as `inotify_table` and
    // `fanotify_table` of Linux.
    const INT_MAX: u32 = i32::MAX as u32;
    match name {
        "fs/fanotify/max_queued_events" => {
            Some((&rk_vfs::notify::fanotify::MAX_QUEUED_EVENTS, INT_MAX))
        }
        "fs/inotify/max_queued_events" => Some((&MAX_QUEUED_EVENTS, INT_MAX)),
        "fs/inotify/max_user_instances" => Some((&MAX_USER_INSTANCES, INT_MAX)),
        "fs/inotify/max_user_watches" => Some((&MAX_USER_WATCHES, INT_MAX)),
        // The time in seconds that a lease holder has to give up its lease, and the switch of
        // the leases, as `lease_break_time` and `leases_enable` of fs/locks.c of Linux. Linux
        // takes any `int`, but a negative value has the effect of 0, so rukernel refuses it.
        "fs/lease-break-time" => Some((&BREAK_TIME, INT_MAX)),
        "fs/leases-enable" => Some((&ENABLE, INT_MAX)),
        "fs/protected_fifos" => Some((&FIFOS, 2)),
        "fs/protected_hardlinks" => Some((&HARDLINKS, 1)),
        "fs/protected_regular" => Some((&REGULAR, 2)),
        "fs/protected_symlinks" => Some((&SYMLINKS, 1)),
        _ => None,
    }
}

/// The `kernel.keys.*` sysctl of `name`, which the key service reads, and its smallest value.
fn key_limit(name: &str) -> Option<(&'static AtomicU32, u32)> {
    use rk_proc::keys::{GC_DELAY, MAXBYTES, MAXKEYS, ROOT_MAXBYTES, ROOT_MAXKEYS};
    match name {
        "kernel/keys/gc_delay" => Some((&GC_DELAY, 0)),
        "kernel/keys/maxbytes" => Some((&MAXBYTES, 1)),
        "kernel/keys/maxkeys" => Some((&MAXKEYS, 1)),
        "kernel/keys/root_maxbytes" => Some((&ROOT_MAXBYTES, 1)),
        "kernel/keys/root_maxkeys" => Some((&ROOT_MAXKEYS, 1)),
        _ => None,
    }
}

/// The functions that read and write the `vm.*` sysctl of `name` that the memory manager keeps.
/// The write function gives `None` for a value out of its range.
fn vm_tunable(name: &str) -> Option<(fn() -> usize, fn(usize) -> Option<()>)> {
    use rk_mm::tunables as t;
    fn total() -> usize {
        rk_frame::mm::frame_stats().total
    }
    Some(match name {
        "vm/max_map_count" => (t::max_map_count, |v| Some(t::set_max_map_count(v))),
        "vm/min_free_kbytes" => {
            (|| t::min_free_kbytes(total()), |v| Some(t::set_min_free_kbytes(v)))
        }
        "vm/overcommit_kbytes" => (t::overcommit_kbytes, |v| Some(t::set_overcommit_kbytes(v))),
        "vm/memfd_noexec" => (t::memfd_noexec, t::set_memfd_noexec),
        "vm/overcommit_memory" => (t::overcommit_memory, t::set_overcommit_memory),
        "vm/overcommit_ratio" => (t::overcommit_ratio, |v| Some(t::set_overcommit_ratio(v))),
        "vm/nr_hugepages" | "vm/nr_hugepages_mempolicy" => (
            || {
                let c = rk_mm::hugetlb::counts();
                c.total - c.surplus
            },
            |v| Some(rk_mm::hugetlb::set_nr_hugepages(v)),
        ),
        "vm/hugetlb_shm_group" => (rk_mm::hugetlb::shm_group, rk_mm::hugetlb::set_shm_group),
        "vm/nr_overcommit_hugepages" => (
            || rk_mm::hugetlb::counts().overcommit,
            |v| Some(rk_mm::hugetlb::set_nr_overcommit_hugepages(v)),
        ),
        _ => return None,
    })
}

/// The function that reads the UTS name of the sysctl `name`, for `kernel/hostname` and
/// `kernel/domainname`.
fn uts_name(name: &str) -> Option<fn() -> rk_proc::uts::Field> {
    match name {
        "kernel/hostname" => Some(rk_proc::uts::hostname),
        "kernel/domainname" => Some(rk_proc::uts::domainname),
        _ => None,
    }
}

/// The limit of the `user.max_*` sysctl `name` in the user namespace of the caller, as the
/// `ucount_sysctls` of Linux. In the first namespace, the inotify limits are those of
/// `fs.inotify`, as Linux keeps them in the same place. `fs.fanotify.max_user_groups` and
/// `fs.fanotify.max_user_marks` are the fanotify limits of the first namespace, as
/// `fanotify_table` of Linux.
fn user_limit(name: &str) -> Option<(Arc<rk_vfs::user_ns::UserNs>, rk_vfs::user_ns::UcountKind)> {
    use rk_vfs::user_ns::UcountKind;
    match name {
        "fs/fanotify/max_user_groups" => {
            return Some((rk_vfs::user_ns::init().clone(), UcountKind::FanotifyGroups));
        }
        "fs/fanotify/max_user_marks" => {
            return Some((rk_vfs::user_ns::init().clone(), UcountKind::FanotifyMarks));
        }
        _ => {}
    }
    let kind = UcountKind::by_name(name.strip_prefix("user/")?)?;
    Some((rk_vfs::cred::current().user_ns.clone(), kind))
}

/// The atomic value of the limit `kind` in the first user namespace, if `fs.inotify` keeps it.
fn inotify_alias(
    ns: &rk_vfs::user_ns::UserNs,
    kind: rk_vfs::user_ns::UcountKind,
) -> Option<&'static AtomicU32> {
    use rk_vfs::notify::inotify::{MAX_USER_INSTANCES, MAX_USER_WATCHES};
    use rk_vfs::user_ns::UcountKind;
    match kind {
        _ if !ns.is_init() => None,
        UcountKind::InotifyInstances => Some(&MAX_USER_INSTANCES),
        UcountKind::InotifyWatches => Some(&MAX_USER_WATCHES),
        _ => None,
    }
}

fn sysctl_read(name: &'static str, default: &'static str) -> Vec<u8> {
    if let Some((ns, kind)) = user_limit(name) {
        let v =
            inotify_alias(&ns, kind).map_or_else(|| ns.max(kind), |a| a.load(Ordering::Relaxed));
        return format!("{v}\n").into_bytes();
    }
    if let Some(t) = rk_vfs::ipc::sysctl(name) {
        return format!("{}\n", t.get()).into_bytes();
    }
    if let Some(t) = rk_vfs::ipc::long_sysctl(name) {
        return format!("{}\n", t.get()).into_bytes();
    }
    if name == "fs/pipe-max-size" {
        return format!("{}\n", rk_vfs::pipe::PIPE_MAX_SIZE.load(Ordering::Relaxed)).into_bytes();
    }
    if let Some((v, _)) = protected(name).or_else(|| key_limit(name)) {
        return format!("{}\n", v.load(Ordering::Relaxed)).into_bytes();
    }
    if let Some((get, _)) = vm_tunable(name) {
        return format!("{}\n", get()).into_bytes();
    }
    match name {
        "kernel/random/boot_id" => return uuid_text(boot_id()),
        "kernel/random/uuid" => return uuid_text(random_uuid()),
        "fs/nr_open" => return format!("{}\n", rk_vfs::fdtable::nr_open()).into_bytes(),
        "kernel/ns_last_pid" => return format!("{}\n", rk_proc::last_pid()).into_bytes(),
        "kernel/cap_last_cap" => return format!("{}\n", rk_vfs::cred::cap::LAST).into_bytes(),
        "kernel/yama/ptrace_scope" => {
            return format!("{}\n", rk_proc::yama::ptrace_scope()).into_bytes();
        }
        "kernel/unprivileged_bpf_disabled" => {
            let v = rk_bpf::UNPRIVILEGED_BPF_DISABLED.load(Ordering::Relaxed);
            return format!("{v}\n").into_bytes();
        }
        "kernel/sem" => {
            let [msl, mns, opm, mni] = rk_vfs::ipc::sem_limits();
            return format!("{msl}\t{mns}\t{opm}\t{mni}\n").into_bytes();
        }
        _ => {}
    }
    // The real time values of the scheduler, as kernel/sched/rt.c of Linux.
    match name {
        "kernel/sched_rr_timeslice_ms" => {
            return format!("{}\n", rk_proc::sched::rr_timeslice_ms()).into_bytes();
        }
        "kernel/sched_rt_period_us" => {
            return format!("{}\n", rk_proc::sched::rt_bandwidth().0).into_bytes();
        }
        "kernel/sched_rt_runtime_us" => {
            return format!("{}\n", rk_proc::sched::rt_bandwidth().1).into_bytes();
        }
        _ => {}
    }
    // The core dump settings, which the writer of core files reads.
    match name {
        "kernel/core_pattern" => {
            let mut v = rk_proc::coredump::pattern();
            v.push(b'\n');
            return v;
        }
        "kernel/core_uses_pid" => {
            return format!("{}\n", rk_proc::coredump::uses_pid()).into_bytes();
        }
        "fs/suid_dumpable" => {
            return format!("{}\n", rk_proc::coredump::suid_dumpable()).into_bytes();
        }
        _ => {}
    }
    if let Some(f) = uts_name(name) {
        let mut v = rk_proc::uts::bytes(&f()).to_vec();
        v.push(b'\n');
        return v;
    }
    if let Some((_, v)) = SYSCTL_VALUES.lock().iter().find(|(n, _)| *n == name) {
        return v.clone();
    }
    let value = match name {
        "kernel/osrelease" => String::from(info().release),
        "kernel/version" => String::from(info().version),
        "kernel/threads-max" => format!("{}", (rk_frame::mm::frame_stats().total / 32).max(20)),
        // As `files_maxfiles_init` of Linux: 10 percent of the memory in KiB, and at least 8192.
        "fs/file-max" => format!("{}", (rk_frame::mm::frame_stats().total * 4 / 10).max(8192)),
        _ => String::from(default),
    };
    format!("{value}\n").into_bytes()
}

/// Reads an `int` that a program wrote to a sysctl, as `proc_dointvec` of Linux. The text ends at
/// a NUL byte, and spaces and a new line around the number are accepted. A text that is not a
/// number, or a number out of the range of `int`, gives `EINVAL`.
fn parse_int(data: &[u8]) -> Result<i32> {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let n = text::parse_number(&data[..end]).ok_or(Errno::EINVAL)?;
    i32::try_from(n).map_err(|_| Errno::EINVAL)
}

fn sysctl_write(name: &'static str, data: &[u8]) -> Result<()> {
    // A value from 0 to `INT_MAX`, as `proc_dointvec_minmax` of Linux.
    if let Some((ns, kind)) = user_limit(name) {
        let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
        let n: u32 = text.trim().parse().map_err(|_| Errno::EINVAL)?;
        if n > i32::MAX as u32 {
            return Err(Errno::EINVAL);
        }
        match inotify_alias(&ns, kind) {
            Some(a) => a.store(n, Ordering::Relaxed),
            None => ns.set_max(kind, n),
        }
        return Ok(());
    }
    // The limits of the IPC objects, which the system calls read.
    if let Some(t) = rk_vfs::ipc::sysctl(name) {
        let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
        return t.set(text.trim().parse().map_err(|_| Errno::EINVAL)?);
    }
    if let Some(t) = rk_vfs::ipc::long_sysctl(name) {
        let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
        t.set(text.trim().parse().map_err(|_| Errno::EINVAL)?);
        return Ok(());
    }
    // The size goes up to a power of two count of pages, as `proc_dopipe_max_size` of Linux.
    if name == "fs/pipe-max-size" {
        let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
        let n: u32 = text.trim().parse().map_err(|_| Errno::EINVAL)?;
        let size = rk_vfs::pipe::round_pipe_size(n as usize).ok_or(Errno::EINVAL)?;
        rk_vfs::pipe::PIPE_MAX_SIZE.store(size, Ordering::Relaxed);
        return Ok(());
    }
    // A value out of the range gives `EINVAL`, as `proc_dointvec_minmax` of Linux.
    if let Some((v, max)) = protected(name) {
        let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
        let n: u32 = text.trim().parse().map_err(|_| Errno::EINVAL)?;
        if n > max {
            return Err(Errno::EINVAL);
        }
        v.store(n, Ordering::Relaxed);
        return Ok(());
    }
    // A value from the smallest value to `INT_MAX`, as `proc_dointvec_minmax` of Linux.
    if let Some((v, min)) = key_limit(name) {
        let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
        let n: u32 = text.trim().parse().map_err(|_| Errno::EINVAL)?;
        if n < min || n > i32::MAX as u32 {
            return Err(Errno::EINVAL);
        }
        v.store(n, Ordering::Relaxed);
        return Ok(());
    }
    // Only a process with `CAP_SYS_ADMIN` sets the scope of `memfd_create`, as
    // `pid_mfd_noexec_dointvec_minmax` in kernel/pid_namespace.c of Linux.
    if name == "vm/memfd_noexec" && !rk_vfs::cred::current().capable(rk_vfs::cred::cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    // A value from 0 to `INT_MAX`, as `proc_dointvec_minmax` of Linux.
    if let Some((_, set)) = vm_tunable(name) {
        let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
        let n: usize = text.trim().parse().map_err(|_| Errno::EINVAL)?;
        if n > i32::MAX as usize {
            return Err(Errno::EINVAL);
        }
        return set(n).ok_or(Errno::EINVAL);
    }
    match name {
        // A value from 64 to `INT_MAX` rounded down to 64, as `sysctl_nr_open` in fs/file.c of
        // Linux.
        "fs/nr_open" => {
            let n = usize::try_from(parse_int(data)?).map_err(|_| Errno::EINVAL)?;
            let range = rk_vfs::fdtable::NR_OPEN_MIN..=rk_vfs::fdtable::NR_OPEN_MAX;
            if !range.contains(&n) {
                return Err(Errno::EINVAL);
            }
            rk_vfs::fdtable::NR_OPEN.store(n, Ordering::Relaxed);
            return Ok(());
        }
        // Only a process with `CAP_SYS_ADMIN` or `CAP_CHECKPOINT_RESTORE` sets the next ID, as
        // `pid_ns_ctl_handler` in kernel/pid_namespace.c of Linux.
        "kernel/ns_last_pid" => {
            use rk_vfs::cred::cap;
            let cred = rk_vfs::cred::current();
            if !cred.capable(cap::SYS_ADMIN) && !cred.capable(cap::CHECKPOINT_RESTORE) {
                return Err(Errno::EPERM);
            }
            return rk_proc::set_last_pid(i64::from(parse_int(data)?));
        }
        // `yama_dointvec_minmax` in security/yama/yama_lsm.c of Linux.
        "kernel/yama/ptrace_scope" => {
            return rk_proc::yama::set_ptrace_scope(i64::from(parse_int(data)?));
        }
        // Only a process with `CAP_SYS_ADMIN` writes it, and the value 1 cannot change, as
        // `bpf_unpriv_handler` in kernel/bpf/syscall.c of Linux.
        "kernel/unprivileged_bpf_disabled" => {
            let admin = rk_vfs::cred::current().capable(rk_vfs::cred::cap::SYS_ADMIN);
            if !admin {
                return Err(Errno::EPERM);
            }
            return rk_bpf::bpf_unpriv_handler(i64::from(parse_int(data)?), admin);
        }
        // Up to four `int` values, as `proc_ipc_sem_dointvec` in ipc/ipc_sysctl.c of Linux.
        "kernel/sem" => {
            let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
            let text = core::str::from_utf8(&data[..end]).map_err(|_| Errno::EINVAL)?;
            let values: Vec<i32> = text
                .split_ascii_whitespace()
                .map(|w| w.parse().map_err(|_| Errno::EINVAL))
                .collect::<Result<_>>()?;
            return rk_vfs::ipc::set_sem_limits(&values);
        }
        // An `int` of 0 or more, as `vfs_cache_pressure` in fs/dcache.c of Linux. The text is
        // kept below.
        "vm/vfs_cache_pressure" if parse_int(data)? < 0 => return Err(Errno::EINVAL),
        _ => {}
    }
    // `sched_rr_handler` and `sched_rt_handler` in kernel/sched/rt.c of Linux. A time slice of 0
    // or less sets the default. The checks of the period and the run time are in `rk_proc`.
    match name {
        "kernel/sched_rr_timeslice_ms" => {
            rk_proc::sched::set_rr_timeslice_ms(parse_int(data)?);
            return Ok(());
        }
        "kernel/sched_rt_period_us" => {
            return rk_proc::sched::set_rt_bandwidth(Some(parse_int(data)?), None);
        }
        "kernel/sched_rt_runtime_us" => {
            return rk_proc::sched::set_rt_bandwidth(None, Some(parse_int(data)?));
        }
        _ => {}
    }
    // `core_pattern` is a string of at most 127 bytes, `core_uses_pid` is an `int`, and
    // `suid_dumpable` is 0, 1 or 2, as fs/coredump.c and fs/exec.c of Linux.
    match name {
        "kernel/core_pattern" => return rk_proc::coredump::set_pattern(data),
        "kernel/core_uses_pid" => {
            let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
            rk_proc::coredump::set_uses_pid(text.trim().parse().map_err(|_| Errno::EINVAL)?);
            return Ok(());
        }
        "fs/suid_dumpable" => {
            let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
            let n: u32 = text.trim().parse().map_err(|_| Errno::EINVAL)?;
            return rk_proc::coredump::set_suid_dumpable(n);
        }
        _ => {}
    }
    // A name ends at a newline, and only the first 64 bytes count, as `proc_dostring` of Linux.
    if uts_name(name).is_some() {
        let end = data.iter().position(|&b| b == b'\n' || b == 0).unwrap_or(data.len());
        let text = &data[..end.min(rk_proc::uts::NAME_MAX)];
        if name == "kernel/hostname" {
            rk_proc::uts::set_hostname(text);
        } else {
            rk_proc::uts::set_domainname(text);
        }
        return Ok(());
    }
    // A write to `drop_caches` removes the clean pages of the block devices. The value stays 0.
    // The kernel does not move pages, so a write to `compact_memory` has no work.
    if name == "vm/compact_memory" {
        return Ok(());
    }
    if name == "vm/drop_caches" {
        rk_vfs::blockdev::drop_clean_all();
        return Ok(());
    }
    let mut value = data.to_vec();
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value.pop();
    }
    value.push(b'\n');
    let mut values = SYSCTL_VALUES.lock();
    values.retain(|(n, _)| *n != name);
    values.push((name, value));
    Ok(())
}

/// The directory `net` of a process, with the files that the network stack registers in
/// `rk_net::procfs`. The kernel has one network namespace, so each process shows the same files.
fn net_dir(base: &[u8]) -> InodeRef {
    let path = join(base, b"net");
    let list_path = path.clone();
    let list = move || {
        Ok(rk_net::procfs::files()
            .into_iter()
            .map(|(name, show)| {
                let node =
                    file(&join(&list_path, name.as_bytes()), move || Ok(show().into_bytes()));
                (name.as_bytes().to_vec(), node)
            })
            .collect())
    };
    dir(&path, base, 0o555, list, None)
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
            if prefix.is_empty() {
                out.push((b"net".to_vec(), sys_net_dir(String::new())));
            }
            let ipc = rk_vfs::ipc::SYSCTL_NAMES.iter().map(|&n| (n, ""));
            for (name, default) in SYSCTLS.iter().copied().chain(ipc) {
                // The files of Yama are there only when Yama is active.
                if name.starts_with("kernel/yama/") && !rk_proc::yama::active() {
                    continue;
                }
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
                        let read = move || Ok(sysctl_read(name, default));
                        let node = if READ_ONLY_SYSCTLS.contains(&name) {
                            file(fpath.as_bytes(), read)
                        } else {
                            rw_file(fpath.as_bytes(), read, move |data| sysctl_write(name, data))
                        };
                        out.push((rest.as_bytes().to_vec(), node));
                    }
                }
            }
            Ok(out)
        },
        None,
    )
}

/// The directory `/proc/sys/net/<path>`, with the values of `rk_net::sysctl`. The entries are
/// the ones of the network namespace of the reader, as `net_ctl_header_lookup` of Linux.
fn sys_net_dir(path: String) -> InodeRef {
    let full = if path.is_empty() { String::from("/sys/net") } else { format!("/sys/net/{path}") };
    let parent = String::from(&full[..full.rfind('/').unwrap_or(0)]);
    let list_path = full.clone();
    dir(
        full.as_bytes(),
        parent.as_bytes(),
        0o555,
        move || {
            let entries = rk_net::sysctl::list(&path).ok_or(Errno::ENOENT)?;
            Ok(entries
                .into_iter()
                .map(|(name, kind)| {
                    let sub = if path.is_empty() { name.clone() } else { format!("{path}/{name}") };
                    let fpath = format!("{list_path}/{name}");
                    let node = match kind {
                        rk_net::sysctl::Entry::Dir => sys_net_dir(sub),
                        rk_net::sysctl::Entry::File(true) => {
                            let w = sub.clone();
                            rw_file(
                                fpath.as_bytes(),
                                move || rk_net::sysctl::read(&sub),
                                move |data| rk_net::sysctl::write(&w, data),
                            )
                        }
                        rk_net::sysctl::Entry::File(false) => {
                            file(fpath.as_bytes(), move || rk_net::sysctl::read(&sub))
                        }
                    };
                    (name.into_bytes(), node)
                })
                .collect())
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

/// The values of `/proc/PID/stat`, with the IDs in the PID namespace `ns` of the mount, as
/// `do_task_stat` of Linux. An ID that `ns` does not see is 0.
fn stat_of(p: &Process, t: Option<&Thread>, ns: &PidNs) -> text::Stat {
    let nr = |id: Pid| pid_namespace::pid_nr_ns(id, ns.as_ref());
    let (ignored, caught) = actions(p);
    let threads = p.threads();
    let leader = threads.iter().find(|t| t.tid() == p.pid()).cloned();
    let vsize = p.vm().map_or(0, |vm| vm.areas().iter().map(|a| (a.end - a.start) as u64).sum());
    let thread = t.or(leader.as_deref());
    text::Stat {
        pid: nr(t.map_or(p.pid(), Thread::tid)),
        comm: p.comm(),
        // Linux gives the state of the leader for the process, if the leader is there.
        state: thread.map_or_else(|| p.state_letter(), thread_state),
        ppid: nr(p.ppid()),
        pgid: nr(p.pgid()),
        sid: nr(p.sid()),
        threads: threads.len(),
        // Linux gives the time of the thread in the stat of a thread.
        utime: t.map_or_else(|| p.user_ticks(), Thread::user_ticks) * USER_HZ / rk_frame::time::HZ,
        stime: t.map_or_else(|| p.sys_ticks(), Thread::sys_ticks) * USER_HZ / rk_frame::time::HZ,
        cutime: p.child_ticks() * USER_HZ / rk_frame::time::HZ,
        cstime: p.child_sys_ticks() * USER_HZ / rk_frame::time::HZ,
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

/// The sizes of the kinds of memory of `p`, as `task_mem` and the `vm_stat_account` of Linux:
/// a private area that can be written is data, an area that can run and cannot be written is
/// code. The code of the first such area of a file is the code of the program, and the rest is
/// the code of the libraries.
fn mem_sizes(p: &Process) -> text::MemSizes {
    let mut m = text::MemSizes::default();
    let Some(vm) = p.vm() else { return m };
    let page = rk_mm::PAGE_SIZE as u64;
    let mut exe_file = None;
    for a in vm.areas() {
        let size = (a.end - a.start) as u64;
        let resident = vm.resident_pages(a.start, a.end) as u64 * page;
        let file = match &a.backing {
            Backing::File { file, .. } => {
                let (dev, ino, _) = file.name();
                Some((dev, ino))
            }
            _ => None,
        };
        match (&file, a.shared) {
            (Some(_), _) => m.rss_file += resident,
            (None, true) => m.rss_shmem += resident,
            (None, false) => m.rss_anon += resident,
        }
        if a.kind == VmaKind::Stack {
            m.stack += size;
        } else if a.prot.write && !a.shared {
            m.data += size;
        } else if a.prot.exec && !a.prot.write {
            if exe_file.is_none() && file.is_some() {
                exe_file.clone_from(&file);
            }
            if file.is_some() && file == exe_file {
                m.exe += size;
            } else {
                m.lib += size;
            }
        }
    }
    m
}

/// The text of `/proc/PID/status`, with the IDs in the PID namespace `ns` of the mount, as
/// `proc_pid_status` of Linux.
fn status_of(p: &Process, t: Option<&Thread>, ns: &PidNs) -> Vec<u8> {
    let s = stat_of(p, t, ns);
    let nr = |id: Pid| pid_namespace::pid_nr_ns(id, ns.as_ref());
    let tid = t.map_or(p.pid(), Thread::tid);
    // An ID for each namespace from `ns` down to the namespace of the process.
    let levels = |id: Pid| pid_namespace::numbers(id, p.pid_ns(), ns.as_ref());
    let threads = p.threads();
    let thread = t.or_else(|| threads.iter().find(|t| t.tid() == p.pid()).map(|t| &**t));
    let umask = p.fs().map_or(0o022, |fs| fs.lock().umask());
    let x = text::Status {
        tid: nr(tid),
        tracer: nr(thread.map_or(0, Thread::tracer_pid)),
        umask,
        shared_pending: p.shared_pending().0,
        locked: p.vm().map_or(0, |vm| vm.locked_bytes() as u64),
        rss: p.vm().map_or(0, |vm| vm.resident_pages(0, rk_frame::vm::USER_END) as u64 * 4096),
        mem: mem_sizes(p),
        cred: (*p.cred()).clone(),
        no_new_privs: thread.is_some_and(Thread::no_new_privs),
        ns_ids: [levels(p.pid()), levels(tid), levels(p.pgid()), levels(p.sid())],
    };
    let mut s = s;
    s.pid = nr(p.pid());
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

/// The start and the end of the heap, as `start_brk` and `brk` of Linux.
type Heap = (usize, usize);

/// Tells if the area `a` is a part of the heap, as `vma_is_initial_heap` of Linux: an area with
/// no file that has a part in `start_brk..brk`. Thus a page that `mmap` put in the heap with
/// `MAP_FIXED`, as the guard page of the malloc of musl, also shows `[heap]`.
fn in_heap(a: &Vma<FileRef>, (start, end): Heap) -> bool {
    matches!(a.backing, Backing::Anon) && a.start < end && a.end > start
}

/// The line of `/proc/PID/maps` for the area `a`.
fn map_line_of(a: &Vma<FileRef>, heap: Heap) -> MapLine {
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
        VmaKind::Normal if in_heap(a, heap) => line.name = b"[heap]".to_vec(),
        VmaKind::Normal => {}
    }
    line
}

/// The flags of `area` for the line `VmFlags` of `/proc/PID/smaps`, in the order of
/// `show_smap_vma_flags` of Linux. `soft_dirty` is the flag `VM_SOFTDIRTY`.
///
/// A shared mapping of a file that is not open for writing has `VM_MAYSHARE` (ms) but not
/// `VM_SHARED` (sh) or `VM_MAYWRITE` (mw), as `do_mmap` of Linux. The vDSO has the flags of
/// `_install_special_mapping`, and its data page also has the flags of a mapping of PFNs. The main
/// stack has `VM_GROWSDOWN` as on Linux, but rukernel maps all of it at the exec. It has no
/// `VM_SOFTDIRTY`, as `setup_arg_pages` of Linux removes it.
fn vm_flags(a: &Vma<FileRef>, soft_dirty: bool) -> Vec<&'static str> {
    let vvar = a.kind == VmaKind::Vvar;
    let special = vvar || a.kind == VmaKind::Vdso;
    let flags = [
        (a.prot.read, "rd"),
        (a.prot.write, "wr"),
        (a.prot.exec, "ex"),
        (a.shared && a.may_write, "sh"),
        (true, "mr"),
        (!vvar && (a.may_write || a.kind == VmaKind::Vdso), "mw"),
        (!vvar, "me"),
        (a.shared, "ms"),
        (a.grows_down || a.kind == VmaKind::Stack, "gd"),
        (vvar, "pf"),
        (a.locked, "lo"),
        (vvar, "io"),
        (a.dont_fork, "dc"),
        (special, "de"),
        // Linux counts a shared anonymous area in its shmem file, not with `VM_ACCOUNT`.
        (a.account && !a.shared, "ac"),
        (a.hugetlb, "ht"),
        (a.wipe_on_fork, "wf"),
        (vvar || a.dont_dump, "dd"),
        (soft_dirty && a.kind != VmaKind::Stack, "sd"),
        (a.huge == HugeAdvice::Huge, "hg"),
        (a.huge == HugeAdvice::NoHuge, "nh"),
        (a.mergeable, "mg"),
    ];
    flags.into_iter().filter(|&(on, _)| on).map(|(_, name)| name).collect()
}

/// The text of `/proc/PID/maps`, or of `/proc/PID/smaps` with `smaps`.
fn areas_of(p: &Process, smaps: bool) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let Some(vm) = p.vm() else { return Ok(out) };
    let (areas, start, end) = vm.areas_and_heap();
    for a in areas {
        let line = map_line_of(&a, (start, end));
        text::map_line(&mut out, &line);
        if smaps {
            let area = SmapsArea {
                size: (a.end - a.start) as u64,
                rss: vm.resident_pages(a.start, a.end) as u64 * 4096,
                anon: matches!(a.backing, Backing::Anon),
                locked: a.locked,
                flags: vm_flags(&a, vm.area_soft_dirty(a.start, a.end)),
            };
            text::smaps_area(&mut out, &area);
        }
    }
    Ok(out)
}

/// An open file of `/proc/PID/maps`. It reads the text of its inode, and answers the ioctl
/// `PROCMAP_QUERY`, as `procfs_procmap_ioctl` in fs/proc/task_mmu.c of Linux.
struct MapsFile {
    p: Weak<Process>,
}

impl rk_vfs::file::FileOps for MapsFile {
    fn read(&self, file: &rk_vfs::file::File, buf: &mut [u8]) -> Result<usize> {
        let pos = file.pos();
        let n = file.inode().ok_or(Errno::EINVAL)?.read_at(pos, buf)?;
        file.set_pos(pos + n as u64);
        Ok(n)
    }

    fn read_at(&self, file: &rk_vfs::file::File, offset: u64, buf: &mut [u8]) -> Result<usize> {
        file.inode().ok_or(Errno::EINVAL)?.read_at(offset, buf)
    }

    fn seekable(&self) -> bool {
        true
    }

    fn ioctl(
        &self,
        _file: &rk_vfs::file::File,
        cmd: u32,
        arg: usize,
        mem: &dyn rk_vfs::file::UserMemory,
    ) -> Result<usize> {
        if cmd != procmap::PROCMAP_QUERY {
            return Err(Errno::ENOTTY);
        }
        procmap_query(&*alive(&self.p)?, arg, mem)?;
        Ok(0)
    }
}

/// Does the ioctl `PROCMAP_QUERY` for the structure at `arg`, as `do_procmap_query` of Linux.
fn procmap_query(p: &Process, arg: usize, mem: &dyn rk_vfs::file::UserMemory) -> Result<()> {
    use procmap::{Answer, Area, QUERY_SIZE, Query};
    let mut word = [0u8; 8];
    mem.read(arg, &mut word)?;
    let size = u64::from_ne_bytes(word);
    if size > rk_mm::PAGE_SIZE as u64 {
        return Err(Errno::E2BIG);
    }
    let size = size as usize;
    let mut raw = [0u8; QUERY_SIZE];
    let known = size.min(QUERY_SIZE);
    mem.read(arg, &mut raw[..known])?;
    // A newer structure is good only if its new fields are zero, as `copy_struct_from_user`.
    let mut at = QUERY_SIZE;
    while at < size {
        let n = (size - at).min(word.len());
        mem.read(arg + at, &mut word[..n])?;
        if word[..n].iter().any(|&b| b != 0) {
            return Err(Errno::E2BIG);
        }
        at += n;
    }
    let q = Query::parse(&raw)?;
    let vm = p.vm().ok_or(Errno::ESRCH)?;
    let (areas, start, end) = vm.areas_and_heap();
    let list: Vec<Area> = areas
        .iter()
        .map(|a| {
            let mut flags = 0;
            for (on, bit) in [
                (a.prot.read, procmap::VMA_READABLE),
                (a.prot.write, procmap::VMA_WRITABLE),
                (a.prot.exec, procmap::VMA_EXECUTABLE),
                (a.shared, procmap::VMA_SHARED),
            ] {
                if on {
                    flags |= bit;
                }
            }
            let file = matches!(a.backing, Backing::File { .. })
                && !matches!(a.kind, VmaKind::Vdso | VmaKind::Vvar);
            Area { start: a.start as u64, end: a.end as u64, flags, file }
        })
        .collect();
    let i = procmap::find(&list, &q)?;
    let area = &list[i];
    let line = map_line_of(&areas[i], (start, end));
    let mut answer = Answer {
        start: area.start,
        end: area.end,
        flags: area.flags,
        page_size: if areas[i].hugetlb { rk_mm::hugetlb::HPAGE_SIZE } else { rk_mm::PAGE_SIZE }
            as u64,
        ..Answer::default()
    };
    if area.file {
        answer.offset = line.offset;
        answer.inode = line.ino;
        answer.major = rk_vfs::device::major(line.dev);
        answer.minor = rk_vfs::device::minor(line.dev);
    }
    if q.name_size != 0 && !line.name.is_empty() {
        let len = u32::try_from(line.name.len() + 1).map_err(|_| Errno::ENAMETOOLONG)?;
        if len > q.name_size {
            return Err(Errno::ENAMETOOLONG);
        }
        let mut name = line.name;
        name.push(0);
        mem.write(q.name_addr as usize, &name)?;
        answer.name_size = len;
    }
    let out = procmap::encode(&q, &answer);
    mem.write(arg, &out[..known])
}

/// Reads the entries of `/proc/PID/pagemap` from `offset`, one `u64` for each page, as
/// `pagemap_read` in fs/proc/task_mmu.c of Linux. Only a caller with `CAP_SYS_ADMIN` sees the
/// page frame numbers. Other callers see 0 in their place.
fn pagemap_read(p: &Process, offset: u64, buf: &mut [u8]) -> Result<usize> {
    const ENTRY: usize = 8;
    if offset % ENTRY as u64 != 0 || buf.len() % ENTRY != 0 {
        return Err(Errno::EINVAL);
    }
    let Some(vm) = p.vm() else { return Ok(0) };
    let admin = rk_proc::current_thread()
        .is_some_and(|t| t.process().cred().capable(rk_vfs::cred::cap::SYS_ADMIN));
    let first = offset / ENTRY as u64;
    let areas = vm.area_ranges();
    let zero = rk_mm::ksm::zero_phys();
    let total = buf.len() / ENTRY;
    let mut k = 0;
    while k < total {
        let Some(addr) = usize::try_from(first + k as u64)
            .ok()
            .and_then(|page| page.checked_mul(rk_mm::PAGE_SIZE))
            .filter(|&a| a < rk_frame::vm::USER_END)
        else {
            break;
        };
        // The pages up to the next area are a hole: no frame maps them, they are not guard
        // pages and they have no soft-dirty bit, as `pagemap_pte_hole` of Linux. Their entries
        // are 0, and the read fills them at one time without a walk of the page table, so a read
        // of the large holes is fast.
        let next = areas.partition_point(|&(_, end)| end <= addr);
        let start = areas.get(next).map_or(rk_frame::vm::USER_END, |&(start, _)| start);
        if addr < start {
            let end = start.min(rk_frame::vm::USER_END);
            let n = ((end - addr) / rk_mm::PAGE_SIZE).clamp(1, total - k);
            buf[k * ENTRY..(k + n) * ENTRY].fill(0);
            k += n;
            continue;
        }
        let mut page = procmap::PageFacts::default();
        if let Some((frame, _)) = vm.vm().page(rk_frame::addr::VirtAddr::new(addr)) {
            let phys = frame.addr().get();
            page.present = true;
            page.pfn = admin.then_some(phys / rk_mm::PAGE_SIZE as u64);
            page.zero = zero == Some(phys);
            // A page of a file or of shared memory is not anonymous. A private area of a file
            // maps the page of the file until the first write makes an anonymous copy.
            page.file = !frame.is_anon();
            // The map count of the frame counts the page table entries that map it, and not the
            // page cache or KSM, as `folio_precise_page_mapcount` of Linux.
            page.exclusive = frame.map_count() == 1;
        } else {
            // A guard page has a marker in place of a frame, as `pte_to_pagemap_entry` of Linux.
            page.guard = vm.is_guard(addr);
        }
        page.soft_dirty = vm.soft_dirty(addr, page.present);
        buf[k * ENTRY..(k + 1) * ENTRY]
            .copy_from_slice(&procmap::pagemap_entry(&page).to_ne_bytes());
        k += 1;
    }
    Ok(k * ENTRY)
}

/// Does a write to `/proc/PID/clear_refs`, as `clear_refs_write` in fs/proc/task_mmu.c of Linux.
/// The process keeps no referenced bits, so 1, 2 and 3 do nothing.
fn clear_refs_write(p: &Process, data: &[u8]) -> Result<usize> {
    let what = procmap::parse_clear_refs(data)?;
    if let Some(vm) = p.vm() {
        match what {
            procmap::ClearRefs::Referenced => {}
            procmap::ClearRefs::SoftDirty => vm.clear_soft_dirty(),
            procmap::ClearRefs::Hiwater => vm.reset_hiwater(),
        }
    }
    Ok(data.len())
}

/// The largest page frame number of `/proc/kpageflags`. It gives the address bits of the
/// physical memory that the kernel can have.
const KPAGEFLAGS_PFNS: u64 = 1 << 40;

/// Reads the entries of `/proc/kpageflags` from `offset`, one `u64` for each page frame, as
/// `kpageflags_read` in fs/proc/page.c of Linux. Only the anonymous pages of the processes, the
/// pages of mapped files, the huge pages and the page of zeros of KSM have flags.
fn kpageflags_read(offset: u64, buf: &mut [u8]) -> Result<usize> {
    const ENTRY: usize = 8;
    if offset % ENTRY as u64 != 0 || buf.len() % ENTRY != 0 {
        return Err(Errno::EINVAL);
    }
    let first = offset / ENTRY as u64;
    let zero = rk_mm::ksm::zero_phys();
    let mut done = 0;
    for (i, out) in buf.chunks_exact_mut(ENTRY).enumerate() {
        let pfn = first + i as u64;
        if pfn >= KPAGEFLAGS_PFNS {
            break;
        }
        let phys = pfn * rk_mm::PAGE_SIZE as u64;
        let at = rk_frame::addr::PhysAddr::new(phys);
        let anon = rk_frame::mm::phys_is_anon(at);
        let head = phys.is_multiple_of(rk_frame::vm::HUGE_PAGE_SIZE as u64);
        let huge = rk_frame::mm::phys_huge(at).map(|kind| match kind {
            rk_frame::mm::HugeKind::Thp => (procmap::Compound::Thp, head),
            rk_frame::mm::HugeKind::Hugetlb => (procmap::Compound::Hugetlb, head),
            rk_frame::mm::HugeKind::HugetlbFree => (procmap::Compound::HugetlbFree, head),
        });
        let frame = procmap::FrameFacts {
            zero: zero == Some(phys),
            anon,
            ksm: rk_frame::mm::phys_is_ksm(at),
            file: if anon { None } else { rk_vfs::mapped::frame_dirty(phys) },
            huge,
            huge_mapped: rk_frame::mm::phys_huge_mapped(at),
        };
        out.copy_from_slice(&procmap::page_flags(&frame).to_ne_bytes());
        done += ENTRY;
    }
    Ok(done)
}

/// An open file of `/proc/PID/mounts` or `/proc/PID/mountinfo`. It reads the text of its inode, and has an event of
/// `POLLPRI` and `POLLERR` when the mounts of the name space change, as `mounts_poll` in
/// fs/proc_namespace.c of Linux.
struct MountsFile {
    ns: Arc<rk_vfs::MountNamespace>,
    /// The count of the changes that `poll` saw last.
    seen: AtomicU64,
}

impl MountsFile {
    /// Opens the file for the name space of `p`. The changes before the open have no event.
    fn open(p: &Process) -> Option<Arc<dyn rk_vfs::file::FileOps>> {
        let ns = p.fs()?.lock().namespace().clone();
        Some(Arc::new(Self { seen: AtomicU64::new(ns.event()), ns }))
    }
}

impl rk_vfs::file::FileOps for MountsFile {
    fn read(&self, file: &rk_vfs::file::File, buf: &mut [u8]) -> Result<usize> {
        let pos = file.pos();
        let n = file.inode().ok_or(Errno::EINVAL)?.read_at(pos, buf)?;
        file.set_pos(pos + n as u64);
        Ok(n)
    }

    fn read_at(&self, file: &rk_vfs::file::File, offset: u64, buf: &mut [u8]) -> Result<usize> {
        file.inode().ok_or(Errno::EINVAL)?.read_at(offset, buf)
    }

    fn seekable(&self) -> bool {
        true
    }

    fn poll(&self, _file: &rk_vfs::file::File) -> u32 {
        use rk_abi::native::poll::{POLLERR, POLLIN, POLLPRI, POLLRDNORM};
        let event = self.ns.event();
        if self.seen.swap(event, Ordering::Relaxed) == event {
            POLLIN | POLLRDNORM
        } else {
            POLLIN | POLLRDNORM | POLLERR | POLLPRI
        }
    }

    fn pollable(&self) -> bool {
        true
    }

    fn poll_wait(&self, _file: &rk_vfs::file::File, table: &mut rk_vfs::wait::PollTable) {
        table.add_static(rk_vfs::MountNamespace::poll_queue());
    }

    fn event_count(&self) -> u64 {
        self.ns.event()
    }
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
            format!(" {} {}", src.fstype, text::mount_options(src.flags)).as_bytes(),
        );
        out.extend_from_slice(&m.root().inode().fs_options());
        out.extend_from_slice(b" 0 0\n");
    }
    Ok(out)
}

/// The text of `/proc/PID/mountstats`, as `show_vfsstat` in fs/proc_namespace.c of Linux. No
/// file system adds statistics.
fn mountstats_of(p: &Process) -> Result<Vec<u8>> {
    let fs = p.fs().ok_or(Errno::ESRCH)?.lock().clone();
    let mut out = Vec::new();
    for m in fs.namespace().mounts() {
        let at = Location { mount: m.clone(), dentry: m.root().clone() };
        let Ok(path) = fs.path_of(&at) else { continue };
        let src = m.source();
        out.extend_from_slice(b"device ");
        if src.source.is_empty() {
            out.extend_from_slice(b"no device");
        } else {
            text::escape(&mut out, &src.source);
        }
        out.extend_from_slice(b" mounted on ");
        text::escape(&mut out, &path);
        out.extend_from_slice(b" with fstype ");
        text::escape(&mut out, src.fstype.as_bytes());
        out.push(b'\n');
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
            propagation: m.propagation(),
            options: &m.root().inode().fs_options(),
        };
        text::mountinfo(&mut out, &info);
    }
    Ok(out)
}

/// The target of a link in `/proc/PID/fd`.
fn fd_target(file: &rk_vfs::File, fs: Option<&rk_vfs::FsContext>) -> Vec<u8> {
    /// `PID_FS_MAGIC`: a process file descriptor has the name of `pidfs_dname` of Linux.
    const PID_FS_MAGIC: u64 = 0x5049_4446;
    if let Some(at) = file.location() {
        if at.inode().fs_magic() == PID_FS_MAGIC {
            return b"anon_inode:[pidfd]".to_vec();
        }
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
                    // A walk goes to the open file itself, so a pipe and a file without a name
                    // open again, as the magic links of Linux.
                    let node = if target.starts_with(b"socket:[") {
                        dead_link(&path, perm, move || Ok(target.clone()), Errno::ENXIO)
                    } else if file.location().is_some() || target.starts_with(b"pipe:[") {
                        let file = Arc::downgrade(&file);
                        jump_link(
                            &path,
                            perm,
                            move || Ok(target.clone()),
                            move || {
                                let file = file.upgrade().ok_or(Errno::ENOENT)?;
                                if let Some(at) = file.location() {
                                    return Ok(at.clone());
                                }
                                let inode = rk_vfs::pipe::pipe_inode(&file).ok_or(Errno::ENOENT)?;
                                Ok(rk_vfs::Location::detached(inode))
                            },
                        )
                    } else {
                        link(&path, perm, move || Ok(target.clone()))
                    };
                    (name, owned(&w, node))
                })
                .collect())
        },
        None,
    )
}

/// The text of `/proc/PID/fdinfo/FD`, as `seq_show` in fs/proc/fd.c of Linux.
fn fdinfo_text(p: &Process, fd: i32) -> Result<Vec<u8>> {
    let files = p.files().ok_or(Errno::ESRCH)?;
    let (file, cloexec) = {
        let files = files.lock();
        let entry = files.get(fd).map_err(|_| Errno::ENOENT)?;
        (entry.file.clone(), entry.cloexec)
    };
    let mut flags = file.flags().0;
    if cloexec {
        flags |= rk_abi::native::open::O_CLOEXEC;
    }
    let mnt_id = file.location().map_or(0, |at| at.mount.id());
    let ino = file.metadata().map_or(0, |m| m.ino);
    let mut out =
        format!("pos:\t{}\nflags:\t0{flags:o}\nmnt_id:\t{mnt_id}\nino:\t{ino}\n", file.pos())
            .into_bytes();
    out.extend_from_slice(&file.fdinfo());
    Ok(out)
}

fn fdinfo_dir(w: Weak<Process>, base: &[u8]) -> InodeRef {
    let path = join(base, b"fdinfo");
    let me = path.clone();
    dir(
        &path,
        base,
        0o500,
        move || {
            let p = alive(&w)?;
            let files = p.files().ok_or(Errno::ESRCH)?;
            let fds: Vec<i32> = files.lock().iter().map(|(fd, _)| fd).collect();
            Ok(fds
                .into_iter()
                .map(|fd| {
                    let name = format!("{fd}").into_bytes();
                    let w = w.clone();
                    let node = file(&join(&me, &name), move || fdinfo_text(&*alive(&w)?, fd));
                    (name, node)
                })
                .collect())
        },
        None,
    )
}

/// The thread of `timerslack_ns`: the thread `t`, or the main thread of the process `w`.
fn slack_thread(w: &Weak<Process>, t: &Option<Weak<Thread>>) -> Result<Arc<Thread>> {
    if let Some(t) = t {
        return alive(t);
    }
    let p = alive(w)?;
    let threads = p.threads();
    let main = threads.iter().find(|t| t.tid() == p.pid()).or(threads.first());
    main.cloned().ok_or(Errno::ESRCH)
}

/// The files of `/proc/PID/attr` that all modules share, with their permission bits, as
/// `attr_dir_stuff` of fs/proc/base.c of Linux.
const ATTR_FILES: [(&str, u32); 6] = [
    ("current", 0o666),
    ("prev", 0o444),
    ("exec", 0o666),
    ("fscreate", 0o666),
    ("keycreate", 0o666),
    ("sockcreate", 0o666),
];

/// The files of a module directory in `/proc/PID/attr`, as the `apparmor` directory of Linux.
const ATTR_MODULE_FILES: [(&str, u32); 3] = [("current", 0o666), ("prev", 0o444), ("exec", 0o666)];

/// The thread of an `attr` file: the thread `t`, or the main thread of the process `w`.
fn attr_thread(w: &Weak<Process>, t: &Option<Weak<Thread>>) -> Result<Arc<Thread>> {
    slack_thread(w, t)
}

/// A file of `/proc/PID/attr`, as `proc_pid_attr_read` and `proc_pid_attr_write` of Linux.
/// `lsmid` is the module of a module directory, or 0. Only the task itself can write, and a
/// write must start at the offset 0 and be at most one page.
fn attr_file(
    path: &[u8],
    perm: u32,
    w: &Weak<Process>,
    t: &Option<Weak<Thread>>,
    lsmid: u64,
    name: &'static str,
) -> InodeRef {
    let (p_, t_) = (w.clone(), t.clone());
    let (p2, t2) = (w.clone(), t.clone());
    data_file(
        path,
        perm,
        move |offset, buf| {
            let thread = attr_thread(&p_, &t_)?;
            let cred = thread.process().cred();
            let task = rk_vfs::security::Task {
                pid: thread.tid(),
                cred: &cred,
                security: Some(thread.security()),
            };
            let text = rk_vfs::security::getprocattr(&task, lsmid, name)?;
            let start = usize::try_from(offset).unwrap_or(usize::MAX).min(text.len());
            let n = buf.len().min(text.len() - start);
            buf[..n].copy_from_slice(&text[start..start + n]);
            Ok(n)
        },
        move |offset, data| {
            let thread = attr_thread(&p2, &t2)?;
            let me = rk_proc::current_thread().ok_or(Errno::EACCES)?;
            if !Arc::ptr_eq(&me, &thread) {
                return Err(Errno::EACCES);
            }
            if offset != 0 {
                return Err(Errno::EINVAL);
            }
            let data = &data[..data.len().min(rk_mm::PAGE_SIZE)];
            rk_vfs::security::setprocattr(lsmid, name, data)
        },
    )
}

/// The directory `/proc/PID/attr`: the files that all modules share, and a directory for each
/// active module that has its own files, as `proc_attr_dir_operations` of Linux.
fn attr_dir(base: &[u8], w: Weak<Process>, t: Option<Weak<Thread>>) -> InodeRef {
    let path = join(base, b"attr");
    let path_ = path.clone();
    dir(
        &path,
        base,
        0o555,
        move || {
            let mut out: Vec<(Vec<u8>, InodeRef)> = ATTR_FILES
                .iter()
                .map(|&(name, perm)| {
                    let file = attr_file(&join(&path_, name.as_bytes()), perm, &w, &t, 0, name);
                    (name.as_bytes().to_vec(), file)
                })
                .collect();
            for (lsmid, module) in rk_vfs::security::attr_modules() {
                let mpath = join(&path_, module.as_bytes());
                let mpath_ = mpath.clone();
                let (w_, t_) = (w.clone(), t.clone());
                let mdir = dir(
                    &mpath,
                    &path_,
                    0o555,
                    move || {
                        Ok(ATTR_MODULE_FILES
                            .iter()
                            .map(|&(name, perm)| {
                                let p = join(&mpath_, name.as_bytes());
                                (
                                    name.as_bytes().to_vec(),
                                    attr_file(&p, perm, &w_, &t_, lsmid, name),
                                )
                            })
                            .collect())
                    },
                    None,
                );
                out.push((module.as_bytes().to_vec(), mdir));
            }
            Ok(out)
        },
        None,
    )
}

/// The files of a process directory, from the process `w`. `t` is the thread of a directory in
/// `task`, or `None` for the directory of the process.
/// Copies the part of `text` at `offset` to `buf`, for a read of a file of text.
fn read_text(text: &[u8], offset: u64, buf: &mut [u8]) -> usize {
    let start = usize::try_from(offset).unwrap_or(usize::MAX).min(text.len());
    let n = buf.len().min(text.len() - start);
    buf[..n].copy_from_slice(&text[start..start + n]);
    n
}

/// The files of the user namespace of the process: `uid_map`, `gid_map`, `projid_map` and
/// `setgroups`, as fs/proc/base.c and kernel/user_namespace.c of Linux. The writer is the
/// process that calls `write`.
fn user_ns_files(w: &Weak<Process>, base: &[u8], out: &mut Vec<(Vec<u8>, InodeRef)>) {
    use rk_vfs::user_ns::{self, IdKind};
    let me = rk_vfs::cred::current;
    for (name, kind) in
        [(&b"uid_map"[..], IdKind::Uid), (b"gid_map", IdKind::Gid), (b"projid_map", IdKind::Projid)]
    {
        let (p_, p2) = (w.clone(), w.clone());
        out.push((
            name.to_vec(),
            data_file(
                &join(base, name),
                0o644,
                move |offset, buf| {
                    let ns = alive(&p_)?.cred().user_ns.clone();
                    let text = user_ns::show_map(&ns, kind, &me().user_ns);
                    Ok(read_text(&text, offset, buf))
                },
                move |offset, data| {
                    let ns = alive(&p2)?.cred().user_ns.clone();
                    user_ns::write_map(&ns, kind, &me(), offset, data)?;
                    Ok(data.len())
                },
            ),
        ));
    }
    let (p_, p2) = (w.clone(), w.clone());
    out.push((
        b"setgroups".to_vec(),
        data_file(
            &join(base, b"setgroups"),
            0o644,
            move |offset, buf| {
                let ns = alive(&p_)?.cred().user_ns.clone();
                Ok(read_text(user_ns::show_setgroups(&ns), offset, buf))
            },
            move |offset, data| {
                let ns = alive(&p2)?.cred().user_ns.clone();
                user_ns::write_setgroups(&ns, &me(), offset, data)?;
                Ok(data.len())
            },
        ),
    ));
}

fn process_files(
    w: &Weak<Process>,
    t: Option<Weak<Thread>>,
    base: &[u8],
    ns: &PidNs,
) -> Vec<(Vec<u8>, InodeRef)> {
    let mut out: Vec<(Vec<u8>, InodeRef)> = Vec::new();
    let p_ = w.clone();
    let t_ = t.clone();
    let ns_ = ns.clone();
    out.push((
        b"stat".to_vec(),
        file(&join(base, b"stat"), move || {
            let p = alive(&p_)?;
            let t = t_.as_ref().map(alive).transpose()?;
            Ok(text::stat(&stat_of(&p, t.as_deref(), &ns_)))
        }),
    ));
    let p_ = w.clone();
    let t_ = t.clone();
    let ns_ = ns.clone();
    out.push((
        b"status".to_vec(),
        file(&join(base, b"status"), move || {
            let p = alive(&p_)?;
            let t = t_.as_ref().map(alive).transpose()?;
            Ok(status_of(&p, t.as_deref(), &ns_))
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
    // As `timerslack_ns` in fs/proc/base.c of Linux: the slack of the thread of the directory, or
    // of the main thread. Another process needs `CAP_SYS_NICE` to change it, and 0 sets the
    // default again.
    let p_ = w.clone();
    let t_ = t.clone();
    let p2 = w.clone();
    let t2 = t.clone();
    out.push((
        b"timerslack_ns".to_vec(),
        rw_file(
            &join(base, b"timerslack_ns"),
            move || Ok(alloc::format!("{}\n", slack_thread(&p_, &t_)?.timer_slack()).into_bytes()),
            move |data| {
                let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
                let ns: u64 = text.trim().parse().map_err(|_| Errno::EINVAL)?;
                let thread = slack_thread(&p2, &t2)?;
                let me = rk_proc::current_thread().ok_or(Errno::EPERM)?;
                if !Arc::ptr_eq(me.process(), thread.process())
                    && !me.process().cred().capable(rk_vfs::cred::cap::SYS_NICE)
                {
                    return Err(Errno::EPERM);
                }
                thread.set_timer_slack(ns);
                Ok(())
            },
        ),
    ));
    if t.is_none() {
        // As `timens_offsets` in fs/proc/base.c of Linux: the offsets of the time namespace for
        // the children of the process.
        let p_ = w.clone();
        let p2 = w.clone();
        out.push((
            b"timens_offsets".to_vec(),
            rw_file(
                &join(base, b"timens_offsets"),
                move || {
                    let ns = alive(&p_)?.time_ns_for_children();
                    Ok(rk_proc::timens::show_offsets(&ns).into_bytes())
                },
                move |data| {
                    let ns = alive(&p2)?.time_ns_for_children();
                    let me = rk_proc::current_thread().ok_or(Errno::EPERM)?;
                    let may = me.process().cred().capable(rk_vfs::cred::cap::SYS_TIME);
                    rk_proc::timens::write_offsets(&ns, data, rk_frame::time::clock_ns(), may)
                },
            ),
        ));
    }
    user_ns_files(w, base, &mut out);
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
    let (p_, p2) = (w.clone(), w.clone());
    out.push((
        b"maps".to_vec(),
        ops_file(
            &join(base, b"maps"),
            0o444,
            move || maps_of(&*alive(&p_)?),
            move || Some(Arc::new(MapsFile { p: p2.clone() })),
        ),
    ));
    let p_ = w.clone();
    out.push((
        b"pagemap".to_vec(),
        data_file(
            &join(base, b"pagemap"),
            0o400,
            move |offset, buf| pagemap_read(&*alive(&p_)?, offset, buf),
            |_, _| Err(Errno::EINVAL),
        ),
    ));
    let p_ = w.clone();
    out.push((
        b"clear_refs".to_vec(),
        data_file(
            &join(base, b"clear_refs"),
            0o200,
            |_, _| Err(Errno::EINVAL),
            move |_, data| clear_refs_write(&*alive(&p_)?, data),
        ),
    ));
    let p_ = w.clone();
    out.push((b"smaps".to_vec(), file(&join(base, b"smaps"), move || smaps_of(&*alive(&p_)?))));
    let (p_, p2) = (w.clone(), w.clone());
    out.push((
        b"mounts".to_vec(),
        ops_file(
            &join(base, b"mounts"),
            0o444,
            move || mounts_of(&*alive(&p_)?),
            move || MountsFile::open(&*p2.upgrade()?),
        ),
    ));
    out.push((b"net".to_vec(), net_dir(base)));
    let (p_, p2) = (w.clone(), w.clone());
    out.push((
        b"mountinfo".to_vec(),
        ops_file(
            &join(base, b"mountinfo"),
            0o444,
            move || mountinfo_of(&*alive(&p_)?),
            move || MountsFile::open(&*p2.upgrade()?),
        ),
    ));
    let p_ = w.clone();
    out.push((
        b"statm".to_vec(),
        file(&join(base, b"statm"), move || Ok(text::statm(&statm_of(&*alive(&p_)?)))),
    ));
    let p_ = w.clone();
    out.push((
        b"cgroup".to_vec(),
        file(&join(base, b"cgroup"), move || Ok(cgroup_of(&*alive(&p_)?))),
    ));
    out.push((b"ns".to_vec(), ns_dir(base, w.clone(), t.clone())));
    out.push((b"attr".to_vec(), attr_dir(base, w.clone(), t.clone())));
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
    // As `proc_pid_limits` in fs/proc/base.c of Linux.
    let p_ = w.clone();
    out.push((
        b"limits".to_vec(),
        file(&join(base, b"limits"), move || {
            let p = alive(&p_)?;
            let l: [(u64, u64); 16] = core::array::from_fn(|r| {
                let l = p.limit(r);
                (l.cur, l.max)
            });
            Ok(text::limits(&l).into_bytes())
        }),
    ));
    // As `proc_loginuid_read` and `proc_loginuid_write` in fs/proc/base.c of Linux: only the
    // process itself sets its login UID, and the text has no new line.
    let p_ = w.clone();
    let p2 = w.clone();
    out.push((
        b"loginuid".to_vec(),
        rw_file(
            &join(base, b"loginuid"),
            move || Ok(format!("{}", alive(&p_)?.audit_ids().0).into_bytes()),
            move |data| {
                let p = alive(&p2)?;
                let me = rk_proc::current_thread().ok_or(Errno::EPERM)?;
                if !Arc::ptr_eq(me.process(), &p) {
                    return Err(Errno::EPERM);
                }
                let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
                let uid: u32 = text.trim().parse().map_err(|_| Errno::EINVAL)?;
                p.set_loginuid(uid)
            },
        ),
    ));
    let p_ = w.clone();
    out.push((
        b"sessionid".to_vec(),
        file(&join(base, b"sessionid"), move || {
            Ok(format!("{}", alive(&p_)?.audit_ids().1).into_bytes())
        }),
    ));
    let p_ = w.clone();
    out.push((
        b"personality".to_vec(),
        ops_file(
            &join(base, b"personality"),
            0o400,
            move || Ok(format!("{:08x}\n", alive(&p_)?.personality()).into_bytes()),
            || None,
        ),
    ));
    // The kernel has no symbol names, so the text is `0`, as `proc_pid_wchan` of Linux gives
    // without `kallsyms`.
    out.push((b"wchan".to_vec(), file(&join(base, b"wchan"), || Ok(b"0".to_vec()))));
    // As `proc_pid_schedstat` in fs/proc/base.c of Linux: the CPU time of the thread in ns, the
    // time it waited on a run queue, and the count of its runs. The kernel does not count the
    // last two yet.
    let p_ = w.clone();
    let t_ = t.clone();
    out.push((
        b"schedstat".to_vec(),
        file(&join(base, b"schedstat"), move || {
            let t = slack_thread(&p_, &t_)?;
            let ns = (t.user_ticks() + t.sys_ticks()) * (1_000_000_000 / rk_frame::time::HZ);
            Ok(format!("{ns} 0 0\n").into_bytes())
        }),
    ));
    let p_ = w.clone();
    out.push((
        b"mountstats".to_vec(),
        ops_file(&join(base, b"mountstats"), 0o400, move || mountstats_of(&*alive(&p_)?), || None),
    ));
    // As `proc_coredump_filter_write` in fs/proc/base.c of Linux: the number takes the base of
    // its prefix, and only the bits of the filter stay.
    let p_ = w.clone();
    let p2 = w.clone();
    out.push((
        b"coredump_filter".to_vec(),
        rw_file(
            &join(base, b"coredump_filter"),
            move || Ok(text::coredump_filter(alive(&p_)?.coredump_filter())),
            move |data| {
                let v = text::parse_unsigned(data).ok_or(Errno::EINVAL)?;
                let v = u32::try_from(v).map_err(|_| Errno::ERANGE)?;
                alive(&p2)?.set_coredump_filter(v);
                Ok(())
            },
        ),
    ));
    // The files of KSM are empty for a process without an address space, as in Linux.
    let p_ = w.clone();
    out.push((
        b"ksm_stat".to_vec(),
        file(&join(base, b"ksm_stat"), move || {
            Ok(alive(&p_)?.vm().map(|vm| rk_mm::ksm::stat(&vm)).unwrap_or_default())
        }),
    ));
    let p_ = w.clone();
    out.push((
        b"ksm_merging_pages".to_vec(),
        file(&join(base, b"ksm_merging_pages"), move || {
            Ok(alive(&p_)?.vm().map(|vm| rk_mm::ksm::merging_pages(&vm)).unwrap_or_default())
        }),
    ));
    let p_ = w.clone();
    let p_j = w.clone();
    out.push((
        b"exe".to_vec(),
        // A magic link, as `proc_exe_link` of Linux: a walk goes to the file itself, and
        // `RESOLVE_NO_MAGICLINKS` stops it.
        jump_link(
            &join(base, b"exe"),
            0o777,
            move || {
                let p = alive(&p_)?;
                let exe = p.exe().ok_or(Errno::ENOENT)?;
                let fs = p.fs().map(|fs| fs.lock().clone());
                Ok(fs.and_then(|fs| fs.path_of(&exe).ok()).unwrap_or_else(|| exe.absolute_path()))
            },
            move || alive(&p_j)?.exe().ok_or(Errno::ENOENT),
        ),
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
    out.push((b"fdinfo".to_vec(), fdinfo_dir(w.clone(), base)));
    out.into_iter().map(|(name, node)| (name, owned(w, node))).collect()
}

/// Gives the files of a process the effective user and group of the process, as
/// `task_dump_owner` of Linux. The files of a process that has ended belong to root.
fn owned(w: &Weak<Process>, node: InodeRef) -> InodeRef {
    let w = w.clone();
    set_owner(&node, move || {
        w.upgrade().map_or((0, 0), |p| {
            let cred = p.cred();
            (cred.euid, cred.egid)
        })
    });
    node
}

fn process_dir(p: &Arc<Process>, ns: &PidNs) -> InodeRef {
    let w = Arc::downgrade(p);
    // The inode numbers come from the serial number too, so that a new process with the same PID
    // has new inodes, as in Linux.
    let base = format!("/{}/{}", p.pid(), p.serial()).into_bytes();
    let list_base = base.clone();
    let owner = w.clone();
    let ns = ns.clone();
    let node = dir(
        &base,
        b"/",
        0o555,
        move || {
            alive(&w)?;
            let mut out = process_files(&w, None, &list_base, &ns);
            out.push((b"task".to_vec(), owned(&w, task_dir(w.clone(), &list_base, ns.clone()))));
            Ok(out)
        },
        None,
    );
    // The directory is gone when the process is not in the table of processes: after the wait
    // that reaped it, also when a new process has the PID now, as `pid_revalidate` of Linux.
    let gone = owner.clone();
    set_gone(&node, move || {
        gone.upgrade()
            .is_none_or(|p| rk_proc::find_process(p.pid()).is_none_or(|now| !Arc::ptr_eq(&now, &p)))
    });
    owned(&owner, node)
}

/// The `task` directory of a process, with the ID of each thread in the namespace `ns` of the
/// mount.
fn task_dir(w: Weak<Process>, base: &[u8], ns: PidNs) -> InodeRef {
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
                .filter(|t| pid_namespace::pid_nr_ns(t.tid(), ns.as_ref()) != 0)
                .map(|t| {
                    let name =
                        format!("{}", pid_namespace::pid_nr_ns(t.tid(), ns.as_ref())).into_bytes();
                    let node = thread_dir(t, &join(&me, &name), &me, &ns);
                    (name, owned(&w, node))
                })
                .collect())
        },
        None,
    )
}

fn thread_dir(t: &Arc<Thread>, path: &[u8], parent: &[u8], ns: &PidNs) -> InodeRef {
    let tw = Arc::downgrade(t);
    let pw = Arc::downgrade(t.process());
    let base = path.to_vec();
    let ns = ns.clone();
    dir(
        path,
        parent,
        0o555,
        move || {
            alive(&tw)?;
            Ok(process_files(&pw, Some(tw.clone()), &base, &ns))
        },
        None,
    )
}

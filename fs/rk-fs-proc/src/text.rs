//! The text of the proc files, from plain values. The functions do not read the state of the
//! kernel, so the tests on the host examine them.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;
use rk_abi::native::mount::{
    MS_NOATIME, MS_NODEV, MS_NODIRATIME, MS_NOEXEC, MS_NOSUID, MS_NOSYMFOLLOW, MS_RDONLY,
    MS_RELATIME, MS_SYNCHRONOUS,
};
use rk_vfs::cred::Cred;

/// The memory counts for `/proc/meminfo`, in KiB.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemInfo {
    /// All memory that the kernel manages.
    pub total: u64,
    /// The memory that is free.
    pub free: u64,
    /// The size of the active swap areas. rukernel does not use them yet, so all of it is free.
    pub swap: u64,
    /// The commit limit of `vm.overcommit_memory` 2.
    pub commit_limit: u64,
    /// The memory that the address spaces can write without a new mapping.
    pub committed: u64,
    /// The memory in transparent huge pages.
    pub anon_huge: u64,
    /// The counters of the pool of hugetlbfs, in huge pages.
    pub hugetlb: rk_mm::hugetlb::Counts,
}

/// The text of `/proc/meminfo`. R1 has no page cache, so the other counts are 0.
pub fn meminfo(m: MemInfo) -> String {
    let h = m.hugetlb;
    let rows: [(&str, u64); 26] = [
        ("MemTotal", m.total),
        ("MemFree", m.free),
        ("MemAvailable", m.free),
        ("Buffers", 0),
        ("Cached", 0),
        ("SwapCached", 0),
        ("Active", 0),
        ("Inactive", 0),
        ("SwapTotal", m.swap),
        ("SwapFree", m.swap),
        ("Dirty", 0),
        ("Writeback", 0),
        ("AnonPages", 0),
        ("Mapped", 0),
        ("Shmem", 0),
        ("Slab", 0),
        ("CommitLimit", m.commit_limit),
        ("Committed_AS", m.committed),
        ("VmallocTotal", 34_359_738_367),
        ("AnonHugePages", m.anon_huge),
        ("HugePages_Total", h.total as u64),
        ("HugePages_Free", h.free as u64),
        ("HugePages_Rsvd", h.resv as u64),
        ("HugePages_Surp", h.surplus as u64),
        ("Hugepagesize", rk_mm::hugetlb::HPAGE_KB as u64),
        ("Hugetlb", (h.total * rk_mm::hugetlb::HPAGE_KB) as u64),
    ];
    let mut out = String::new();
    for (name, value) in rows {
        let unit = if name.starts_with("HugePages_") { "" } else { " kB" };
        let _ = writeln!(out, "{:<16}{value:>8}{unit}", format!("{name}:"));
    }
    out
}

/// The first line of `/proc/swaps`.
pub const SWAPS_HEADER: &str = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";

/// A line of `/proc/swaps`, as `swap_show` of Linux. The sizes are in KiB.
pub fn swap_line(path: &[u8], partition: bool, size: u64, used: u64, priority: i32) -> String {
    let mut out = String::new();
    // `seq_file_path` writes a space, a tab, a new line and a backslash in octal.
    for &b in path {
        if matches!(b, b' ' | b'\t' | b'\n' | b'\\') {
            let _ = write!(out, "\\{b:03o}");
        } else {
            out.push(char::from(b));
        }
    }
    let pad = 40usize.saturating_sub(out.len()).max(1);
    let kind = if partition { "partition" } else { "file" };
    let tab = |n: u64| if n < 10_000_000 { "\t" } else { "" };
    let _ =
        writeln!(out, "{:pad$}{kind}\t{size}\t{}{used}\t{}{priority}", "", tab(size), tab(used));
    out
}

/// The options field of a line of `/proc/mounts`, from the mount flags.
pub fn mount_options(flags: u64) -> String {
    let flags = flags as u32;
    let mut out = String::from(if flags & MS_RDONLY != 0 { "ro" } else { "rw" });
    let names = [
        (MS_SYNCHRONOUS, ",sync"),
        (MS_NOSUID, ",nosuid"),
        (MS_NODEV, ",nodev"),
        (MS_NOEXEC, ",noexec"),
        (MS_NOATIME, ",noatime"),
        (MS_NODIRATIME, ",nodiratime"),
        (MS_RELATIME, ",relatime"),
        (MS_NOSYMFOLLOW, ",nosymfollow"),
    ];
    for (bit, name) in names {
        if flags & bit != 0 {
            out.push_str(name);
        }
    }
    out
}

/// The fields of a line of `/proc/PID/mountinfo`.
pub struct MountInfo<'a> {
    /// The mount ID.
    pub id: u64,
    /// The mount ID of the parent mount. The root mount gives its own ID.
    pub parent: u64,
    /// The device of the file system, as `st_dev` gives it.
    pub dev: u64,
    /// The path of the root of the mount in its file system.
    pub root: &'a [u8],
    /// The path of the mount point from the root of the process.
    pub path: &'a [u8],
    /// The mount flags.
    pub flags: u64,
    /// The type of the file system.
    pub fstype: &'a str,
    /// The source of the mount.
    pub source: &'a [u8],
    /// The propagation of the mount.
    pub propagation: rk_vfs::Propagation,
    /// The options of the file system, each with a comma before it.
    pub options: &'a [u8],
}

/// Writes a line of `/proc/PID/mountinfo`, as `show_mountinfo` of Linux does. The optional fields
/// show the peer group of a shared mount, the master of a slave and `unbindable`.
pub fn mountinfo(out: &mut Vec<u8>, m: &MountInfo<'_>) {
    let major = ((m.dev >> 8) & 0xfff) | ((m.dev >> 32) & !0xfff);
    let minor = (m.dev & 0xff) | ((m.dev >> 12) & !0xff);
    out.extend_from_slice(format!("{} {} {major}:{minor} ", m.id, m.parent).as_bytes());
    escape(out, m.root);
    out.push(b' ');
    escape(out, m.path);
    out.extend_from_slice(format!(" {}", mount_options(m.flags)).as_bytes());
    let p = m.propagation;
    if p.group != 0 {
        out.extend_from_slice(format!(" shared:{}", p.group).as_bytes());
    }
    if p.master != 0 {
        out.extend_from_slice(format!(" master:{}", p.master).as_bytes());
    }
    if p.unbindable {
        out.extend_from_slice(b" unbindable");
    }
    out.extend_from_slice(format!(" - {} ", m.fstype).as_bytes());
    escape(out, m.source);
    let ro = if m.flags as u32 & MS_RDONLY != 0 { "ro" } else { "rw" };
    out.extend_from_slice(format!(" {ro}").as_bytes());
    out.extend_from_slice(m.options);
    out.push(b'\n');
}

/// Writes `s` for a field of `/proc/mounts`: a space, a tab, a new line and a backslash become
/// an octal escape, as `mangle` of Linux does.
pub fn escape(out: &mut Vec<u8>, s: &[u8]) {
    for &b in s {
        if matches!(b, b' ' | b'\t' | b'\n' | b'\\') {
            out.extend_from_slice(format!("\\{b:03o}").as_bytes());
        } else {
            out.push(b);
        }
    }
}

/// One area for `/proc/PID/maps`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MapLine {
    /// The first address.
    pub start: usize,
    /// The address after the end.
    pub end: usize,
    /// The `rwx` permissions.
    pub read: bool,
    /// See `read`.
    pub write: bool,
    /// See `read`.
    pub exec: bool,
    /// A shared area shows `s`, a private area `p`.
    pub shared: bool,
    /// The offset in the file.
    pub offset: u64,
    /// The device of the file.
    pub dev: u64,
    /// The inode number of the file.
    pub ino: u64,
    /// The path of the file, or `[heap]`, `[stack]` or empty.
    pub name: Vec<u8>,
}

/// The text of one line of `/proc/PID/maps`. The fields end with a space. A name starts at the
/// byte 73 of the line, as `show_map_vma` of Linux puts it.
pub fn map_line(out: &mut Vec<u8>, m: &MapLine) {
    let flag = |on: bool, c: char| if on { c } else { '-' };
    let head = format!(
        "{:08x}-{:08x} {}{}{}{} {:08x} {:02x}:{:02x} {}",
        m.start,
        m.end,
        flag(m.read, 'r'),
        flag(m.write, 'w'),
        flag(m.exec, 'x'),
        if m.shared { 's' } else { 'p' },
        m.offset,
        rk_vfs::device::major(m.dev),
        rk_vfs::device::minor(m.dev),
        m.ino,
    );
    out.extend_from_slice(head.as_bytes());
    out.push(b' ');
    if !m.name.is_empty() {
        for _ in head.len() + 1..72 {
            out.push(b' ');
        }
        out.push(b' ');
        out.extend_from_slice(&m.name);
    }
    out.push(b'\n');
}

/// The values of one line of `/proc/PID/stat`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    /// The process ID, or the thread ID for `/proc/PID/task/TID/stat`.
    pub pid: u32,
    /// The name of the process.
    pub comm: Vec<u8>,
    /// `R`, `S`, `Z` or another state letter.
    pub state: u8,
    /// The ID of the parent.
    pub ppid: u32,
    /// The process group.
    pub pgid: u32,
    /// The session.
    pub sid: u32,
    /// The number of threads.
    pub threads: usize,
    /// The user CPU time in ticks of `USER_HZ`.
    pub utime: u64,
    /// The system CPU time in ticks of `USER_HZ`.
    pub stime: u64,
    /// The user CPU time of the reaped children in ticks of `USER_HZ`.
    pub cutime: u64,
    /// The system CPU time of the reaped children in ticks of `USER_HZ`.
    pub cstime: u64,
    /// The start time in ticks of `USER_HZ` after boot.
    pub start: u64,
    /// The size of the address space in bytes.
    pub vsize: u64,
    /// The number of pages that have a frame.
    pub rss: u64,
    /// The pending signals.
    pub pending: u64,
    /// The blocked signals.
    pub blocked: u64,
    /// The ignored signals.
    pub ignored: u64,
    /// The signals with a handler.
    pub caught: u64,
    /// The signal that the parent gets at the exit.
    pub exit_signal: u32,
}

/// The text of `/proc/PID/stat`: the 52 fields of `do_task_stat` of Linux. The fields that
/// rukernel does not count yet are 0.
pub fn stat(s: &Stat) -> Vec<u8> {
    let mut out = format!("{} (", s.pid).into_bytes();
    out.extend_from_slice(&s.comm);
    let rest = format!(
        ") {} {} {} {} 0 -1 4194304 0 0 0 0 {} {} {} {} 20 0 {} 0 {} {} {} 18446744073709551615 \
         0 0 0 0 0 {} {} {} {} 0 0 0 {} 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        s.state as char,
        s.ppid,
        s.pgid,
        s.sid,
        s.utime,
        s.stime,
        s.cutime,
        s.cstime,
        s.threads,
        s.start,
        s.vsize,
        s.rss,
        s.pending,
        s.blocked,
        s.ignored,
        s.caught,
        s.exit_signal,
    );
    out.extend_from_slice(rest.as_bytes());
    out
}

/// The values of `/proc/PID/statm`, in pages.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statm {
    /// The size of the address space.
    pub size: u64,
    /// The pages that have a frame.
    pub resident: u64,
    /// The pages that have a frame and that a file or a shared mapping holds.
    pub shared: u64,
    /// The size of the areas of a file that can run.
    pub text: u64,
    /// The size of the private areas that can be written, and of the stack.
    pub data: u64,
}

/// The text of `/proc/PID/statm`. The fields `lib` and `dt` are 0, as in Linux.
pub fn statm(m: &Statm) -> Vec<u8> {
    format!("{} {} {} {} 0 {} 0\n", m.size, m.resident, m.shared, m.text, m.data).into_bytes()
}

/// The word that `/proc/PID/status` shows after the state letter.
pub fn state_name(state: u8) -> &'static str {
    match state {
        b'R' => "R (running)",
        b'S' => "S (sleeping)",
        b'D' => "D (disk sleep)",
        b'T' => "T (stopped)",
        b't' => "t (tracing stop)",
        b'Z' => "Z (zombie)",
        _ => "X (dead)",
    }
}

/// The values of `/proc/PID/status` that `Stat` does not have.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// The thread ID.
    pub tid: u32,
    /// The process ID of the tracer, or 0.
    pub tracer: u32,
    /// The umask.
    pub umask: u32,
    /// The signals that are pending for the process.
    pub shared_pending: u64,
    /// The bytes in locked areas.
    pub locked: u64,
    /// The bytes in pages that have a frame.
    pub rss: u64,
    /// The sizes of the kinds of memory, for the lines `RssAnon` to `VmLib`.
    pub mem: MemSizes,
    /// The credentials of the process.
    pub cred: Cred,
    /// The thread has no_new_privs.
    pub no_new_privs: bool,
}

/// The sizes of the kinds of memory of a process in bytes, as `task_mem` of Linux.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemSizes {
    /// The pages with a frame in private areas without a file.
    pub rss_anon: u64,
    /// The pages with a frame in areas of a file.
    pub rss_file: u64,
    /// The pages with a frame in shared areas without a file.
    pub rss_shmem: u64,
    /// The private areas that can be written, without the stack, `data_vm` of Linux.
    pub data: u64,
    /// The stack, `stack_vm`.
    pub stack: u64,
    /// The code of the program.
    pub exe: u64,
    /// The other areas that can run and cannot be written, as the code of the libraries.
    pub lib: u64,
}

/// The text of `/proc/PID/status`.
pub fn status(s: &Stat, x: &Status) -> Vec<u8> {
    let mut out = Vec::from(&b"Name:\t"[..]);
    out.extend_from_slice(&s.comm);
    let kb = s.vsize / 1024;
    let rss = x.rss / 1024;
    let m = &x.mem;
    let c = &x.cred;
    let groups: Vec<String> = c.groups.iter().map(|g| format!("{g}")).collect();
    let groups = groups.join(" ");
    let text = format!(
        "\nUmask:\t{:04o}\nState:\t{}\nTgid:\t{}\nNgid:\t0\nPid:\t{}\nPPid:\t{}\nTracerPid:\t{}\n\
         Uid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\nFDSize:\t64\nGroups:\t{}\nNStgid:\t{}\nNSpid:\t{}\n\
         NSpgid:\t{}\nNSsid:\t{}\nKthread:\t0\nVmPeak:\t{kb:>8} kB\nVmSize:\t{kb:>8} kB\n\
         VmLck:\t{:>8} kB\nVmPin:\t       0 kB\nVmHWM:\t{rss:>8} kB\nVmRSS:\t{rss:>8} kB\n\
         RssAnon:\t{:>8} kB\nRssFile:\t{:>8} kB\nRssShmem:\t{:>8} kB\nVmData:\t{:>8} kB\n\
         VmStk:\t{:>8} kB\nVmExe:\t{:>8} kB\nVmLib:\t{:>8} kB\nVmPTE:\t       0 kB\n\
         VmSwap:\t       0 kB\nHugetlbPages:\t       0 kB\nCoreDumping:\t0\nTHP_enabled:\t0\n\
         Threads:\t{}\nSigQ:\t0/31\nSigPnd:\t{:016x}\nShdPnd:\t{:016x}\n\
         SigBlk:\t{:016x}\nSigIgn:\t{:016x}\nSigCgt:\t{:016x}\nCapInh:\t{:016x}\n\
         CapPrm:\t{:016x}\nCapEff:\t{:016x}\nCapBnd:\t{:016x}\n\
         CapAmb:\t{:016x}\nNoNewPrivs:\t{}\nSeccomp:\t0\nSeccomp_filters:\t0\n\
         Cpus_allowed:\t1\nCpus_allowed_list:\t0\nMems_allowed:\t1\nMems_allowed_list:\t0\n\
         voluntary_ctxt_switches:\t0\nnonvoluntary_ctxt_switches:\t0\n",
        x.umask,
        state_name(s.state),
        s.pid,
        x.tid,
        s.ppid,
        x.tracer,
        c.uid,
        c.euid,
        c.suid,
        c.fsuid,
        c.gid,
        c.egid,
        c.sgid,
        c.fsgid,
        groups,
        s.pid,
        x.tid,
        s.pgid,
        s.sid,
        x.locked / 1024,
        m.rss_anon / 1024,
        m.rss_file / 1024,
        m.rss_shmem / 1024,
        m.data / 1024,
        m.stack / 1024,
        m.exe / 1024,
        m.lib / 1024,
        s.threads,
        s.pending,
        x.shared_pending,
        s.blocked,
        s.ignored,
        s.caught,
        c.cap_inheritable,
        c.cap_permitted,
        c.cap_effective,
        c.cap_bset,
        c.cap_ambient,
        u8::from(x.no_new_privs),
    );
    out.extend_from_slice(text.as_bytes());
    out
}

/// The values of one area in `/proc/PID/smaps`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SmapsArea {
    /// The size of the area in bytes.
    pub size: u64,
    /// The bytes in pages that have a frame.
    pub rss: u64,
    /// The area is anonymous memory.
    pub anon: bool,
    /// The area is locked.
    pub locked: bool,
}

/// The lines of `/proc/PID/smaps` after the map line of an area, as `show_smap` of Linux gives
/// them. The counts that rukernel does not keep are 0.
pub fn smaps_area(out: &mut Vec<u8>, a: &SmapsArea, m: &MapLine) {
    let kb = |bytes: u64| bytes / 1024;
    let anon = if a.anon { a.rss } else { 0 };
    let locked = if a.locked { a.rss } else { 0 };
    let fields: [(&str, u64); 22] = [
        ("Size", a.size),
        ("KernelPageSize", 4096),
        ("MMUPageSize", 4096),
        ("Rss", a.rss),
        ("Pss", a.rss),
        ("Pss_Dirty", 0),
        ("Shared_Clean", 0),
        ("Shared_Dirty", 0),
        ("Private_Clean", 0),
        ("Private_Dirty", a.rss),
        ("Referenced", a.rss),
        ("Anonymous", anon),
        ("KSM", 0),
        ("LazyFree", 0),
        ("AnonHugePages", 0),
        ("ShmemPmdMapped", 0),
        ("FilePmdMapped", 0),
        ("Shared_Hugetlb", 0),
        ("Private_Hugetlb", 0),
        ("Swap", 0),
        ("SwapPss", 0),
        ("Locked", locked),
    ];
    for (name, value) in fields {
        let name = format!("{name}:");
        out.extend_from_slice(format!("{name:<16}{:>8} kB\n", kb(value)).as_bytes());
    }
    out.extend_from_slice(b"THPeligible:    0\nVmFlags:");
    let flags = [
        (m.read, "rd"),
        (m.write, "wr"),
        (m.exec, "ex"),
        (m.shared, "sh"),
        (true, "mr"),
        (true, "mw"),
        (true, "me"),
        (m.shared, "ms"),
        (a.locked, "lo"),
    ];
    for (on, name) in flags {
        if on {
            out.push(b' ');
            out.extend_from_slice(name.as_bytes());
        }
    }
    out.push(b'\n');
}

/// The text of a number file of `/proc/sys`, with a new line.
pub fn number(n: i64) -> Vec<u8> {
    format!("{n}\n").into_bytes()
}

/// Reads a number that a program wrote to a proc file. Spaces and a new line around it are
/// accepted.
pub fn parse_number(bytes: &[u8]) -> Option<i64> {
    let s = core::str::from_utf8(bytes).ok()?.trim();
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meminfo_has_the_format_of_linux() {
        let m = MemInfo {
            total: 1024,
            free: 512,
            swap: 0,
            commit_limit: 512,
            committed: 100,
            anon_huge: 2048,
            hugetlb: rk_mm::hugetlb::Counts { total: 3, free: 2, ..Default::default() },
        };
        let text = meminfo(m);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 26);
        assert!(text.contains("\nCommitted_AS:        100 kB\n"));
        assert!(text.contains("\nAnonHugePages:      2048 kB\n"));
        assert_eq!(lines[0], "MemTotal:           1024 kB");
        assert_eq!(lines[2], "MemAvailable:        512 kB");
        assert!(text.contains("\nHugePages_Total:       3\nHugePages_Free:        2\n"));
        assert!(text.ends_with("\nHugepagesize:       2048 kB\nHugetlb:            6144 kB\n"));
    }

    #[test]
    fn a_swap_line_has_the_format_of_linux() {
        assert_eq!(
            swap_line(b"/scratch/swap", false, 2044, 0, -2),
            "/scratch/swap                           file\t2044\t\t0\t\t-2\n"
        );
        assert_eq!(
            swap_line(b"/a b", true, 10_000_000, 0, 5),
            "/a\\040b                                 partition\t10000000\t0\t\t5\n"
        );
    }

    #[test]
    fn mount_options_name_the_flags() {
        assert_eq!(mount_options(0), "rw");
        assert_eq!(
            mount_options(u64::from(MS_RDONLY | MS_NOSUID | MS_RELATIME)),
            "ro,nosuid,relatime"
        );
        let mut out = Vec::new();
        escape(&mut out, b"a b\\c");
        assert_eq!(out, b"a\\040b\\134c");
    }

    #[test]
    fn mountinfo_has_the_fields_of_linux() {
        let mut out = Vec::new();
        let m = MountInfo {
            id: 7,
            parent: 1,
            dev: (254 << 8) | 16,
            root: b"/",
            path: b"/mnt",
            flags: u64::from(MS_NOATIME),
            fstype: "ext4",
            source: b"/dev/vdb",
            propagation: rk_vfs::Propagation::default(),
            options: b"",
        };
        mountinfo(&mut out, &m);
        assert_eq!(out, b"7 1 254:16 / /mnt rw,noatime - ext4 /dev/vdb rw\n");
        out.clear();
        let propagation = rk_vfs::Propagation { group: 3, master: 2, unbindable: false };
        mountinfo(&mut out, &MountInfo { propagation, ..m });
        assert_eq!(out, b"7 1 254:16 / /mnt rw,noatime shared:3 master:2 - ext4 /dev/vdb rw\n");
        out.clear();
        mountinfo(&mut out, &MountInfo { options: b",lowerdir=/l", ..m });
        assert_eq!(out, b"7 1 254:16 / /mnt rw,noatime - ext4 /dev/vdb rw,lowerdir=/l\n");
    }

    #[test]
    fn smaps_shows_the_resident_and_locked_bytes() {
        let mut out = Vec::new();
        let area = SmapsArea { size: 8192, rss: 4096, anon: true, locked: true };
        let line = MapLine { read: true, write: true, ..MapLine::default() };
        smaps_area(&mut out, &area, &line);
        let text = core::str::from_utf8(&out).unwrap_or("");
        assert!(text.starts_with("Size:                  8 kB\n"));
        assert!(text.contains("\nRss:                   4 kB\n"));
        assert!(text.contains("\nLocked:                4 kB\n"));
        assert!(text.ends_with("VmFlags: rd wr mr mw me lo\n"));
    }

    #[test]
    fn a_map_line_puts_the_name_in_its_column() {
        let mut out = Vec::new();
        let m =
            MapLine { start: 0x1000, end: 0x3000, read: true, exec: true, ..MapLine::default() };
        map_line(&mut out, &m);
        assert_eq!(out, b"00001000-00003000 r-xp 00000000 00:00 0 \n");
        out.clear();
        map_line(&mut out, &MapLine { name: b"[heap]".to_vec(), write: true, ..m });
        let line = core::str::from_utf8(&out).unwrap();
        assert_eq!(line.find('['), Some(73));
        assert!(line.starts_with("00001000-00003000 rwxp "));
    }

    #[test]
    fn stat_has_52_fields() {
        let s = Stat {
            pid: 7,
            comm: b"a b)".to_vec(),
            state: b'S',
            ppid: 1,
            pgid: 7,
            sid: 1,
            threads: 2,
            utime: 3,
            stime: 6,
            cutime: 4,
            cstime: 8,
            rss: 5,
            exit_signal: 17,
            ..Stat::default()
        };
        let text = String::from_utf8(stat(&s)).unwrap();
        assert!(text.starts_with("7 (a b)) S 1 7 1 "));
        // A parser finds the end of the name at the last ')'.
        let rest = &text[text.rfind(')').unwrap() + 2..];
        let fields: Vec<&str> = rest.split_ascii_whitespace().collect();
        assert_eq!(fields.len() + 2, 52);
        // Fields 14 to 17 are utime, stime, cutime and cstime.
        assert_eq!(fields[11], "3");
        assert_eq!(fields[12], "6");
        assert_eq!(fields[13], "4");
        assert_eq!(fields[14], "8");
        assert_eq!(fields[17], "2");
        // Field 24 is rss.
        assert_eq!(fields[21], "5");
        assert_eq!(fields[35], "17");
    }

    #[test]
    fn status_gives_the_state_and_the_ids() {
        let s = Stat {
            pid: 5,
            comm: b"sh".to_vec(),
            state: b'R',
            ppid: 1,
            threads: 1,
            ..Stat::default()
        };
        let text = String::from_utf8(status(
            &s,
            &Status { tid: 6, tracer: 3, umask: 0o22, ..Status::default() },
        ))
        .unwrap();
        assert!(text.starts_with("Name:\tsh\nUmask:\t0022\nState:\tR (running)\nTgid:\t5\n"));
        assert!(text.contains("\nPid:\t6\nPPid:\t1\nTracerPid:\t3\n"));
        assert!(text.contains("\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nFDSize:\t64\nGroups:\t\n"));
        assert!(text.contains("\nCapEff:\t000001ffffffffff\n"));
        let mem = MemSizes { data: 8192, stack: 4096, ..MemSizes::default() };
        let text =
            String::from_utf8(status(&s, &Status { rss: 4096, mem, ..Status::default() })).unwrap();
        assert!(text.contains("\nVmHWM:\t       4 kB\nVmRSS:\t       4 kB\nRssAnon:\t"));
        assert!(text.contains("\nVmData:\t       8 kB\nVmStk:\t       4 kB\nVmExe:\t"));
        assert!(text.contains("\nVmSwap:\t       0 kB\nHugetlbPages:\t       0 kB\n"));
        let mut cred = Cred::root().setgroups(alloc::vec![20, 10]).unwrap();
        cred = cred.setresuid(1000, 1001, 1002).unwrap();
        let text = String::from_utf8(status(
            &s,
            &Status { cred, no_new_privs: true, ..Status::default() },
        ))
        .unwrap();
        assert!(text.contains("\nUid:\t1000\t1001\t1002\t1001\n"));
        assert!(text.contains("\nGroups:\t10 20\n"));
        assert!(text.contains("\nCapEff:\t0000000000000000\n"));
        assert!(text.contains("\nNoNewPrivs:\t1\n"));
        assert_eq!(state_name(b'Z'), "Z (zombie)");
        assert_eq!(state_name(b't'), "t (tracing stop)");
    }

    #[test]
    fn statm_has_7_fields() {
        let m = Statm { size: 10, resident: 4, shared: 2, text: 3, data: 5 };
        assert_eq!(statm(&m), b"10 4 2 3 0 5 0\n");
    }

    #[test]
    fn numbers_go_both_ways() {
        assert_eq!(number(-3), b"-3\n");
        assert_eq!(parse_number(b" 42\n"), Some(42));
        assert_eq!(parse_number(b"x"), None);
    }
}

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

/// The memory counts for `/proc/meminfo`, in KiB.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemInfo {
    /// All memory that the kernel manages.
    pub total: u64,
    /// The memory that is free.
    pub free: u64,
}

/// The text of `/proc/meminfo`. R1 has no page cache and no swap, so the other counts are 0.
pub fn meminfo(m: MemInfo) -> String {
    let rows: [(&str, u64); 21] = [
        ("MemTotal", m.total),
        ("MemFree", m.free),
        ("MemAvailable", m.free),
        ("Buffers", 0),
        ("Cached", 0),
        ("SwapCached", 0),
        ("Active", 0),
        ("Inactive", 0),
        ("SwapTotal", 0),
        ("SwapFree", 0),
        ("Dirty", 0),
        ("Writeback", 0),
        ("AnonPages", 0),
        ("Mapped", 0),
        ("Shmem", 0),
        ("Slab", 0),
        ("CommitLimit", m.total),
        ("Committed_AS", m.total - m.free),
        ("VmallocTotal", 34_359_738_367),
        ("HugePages_Total", 0),
        ("Hugepagesize", 2048),
    ];
    let mut out = String::new();
    for (name, value) in rows {
        let unit = if name.starts_with("HugePages_") { "" } else { " kB" };
        let _ = writeln!(out, "{:<16}{value:>8}{unit}", format!("{name}:"));
    }
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
    /// The start time in ticks of `USER_HZ` after boot.
    pub start: u64,
    /// The size of the address space in bytes.
    pub vsize: u64,
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
        ") {} {} {} {} 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 {} 0 {} {} 0 18446744073709551615 \
         0 0 0 0 0 {} {} {} {} 0 0 0 {} 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        s.state as char,
        s.ppid,
        s.pgid,
        s.sid,
        s.threads,
        s.start,
        s.vsize,
        s.pending,
        s.blocked,
        s.ignored,
        s.caught,
        s.exit_signal,
    );
    out.extend_from_slice(rest.as_bytes());
    out
}

/// The word that `/proc/PID/status` shows after the state letter.
pub fn state_name(state: u8) -> &'static str {
    match state {
        b'R' => "R (running)",
        b'S' => "S (sleeping)",
        b'D' => "D (disk sleep)",
        b'T' => "T (stopped)",
        b'Z' => "Z (zombie)",
        _ => "X (dead)",
    }
}

/// The values of `/proc/PID/status` that `Stat` does not have.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// The thread ID.
    pub tid: u32,
    /// The umask.
    pub umask: u32,
    /// The signals that are pending for the process.
    pub shared_pending: u64,
    /// The bytes in locked areas.
    pub locked: u64,
    /// The bytes in pages that have a frame.
    pub rss: u64,
}

/// The text of `/proc/PID/status`. Each process runs as root with all capabilities in R1.
pub fn status(s: &Stat, x: &Status) -> Vec<u8> {
    let mut out = Vec::from(&b"Name:\t"[..]);
    out.extend_from_slice(&s.comm);
    let kb = s.vsize / 1024;
    let text = format!(
        "\nUmask:\t{:04o}\nState:\t{}\nTgid:\t{}\nNgid:\t0\nPid:\t{}\nPPid:\t{}\nTracerPid:\t0\n\
         Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nFDSize:\t64\nGroups:\t\nNStgid:\t{}\nNSpid:\t{}\n\
         NSpgid:\t{}\nNSsid:\t{}\nKthread:\t0\nVmPeak:\t{kb:>8} kB\nVmSize:\t{kb:>8} kB\n\
         VmLck:\t{:>8} kB\nVmRSS:\t{:>8} kB\nThreads:\t{}\nSigQ:\t0/31\nSigPnd:\t{:016x}\nShdPnd:\t{:016x}\n\
         SigBlk:\t{:016x}\nSigIgn:\t{:016x}\nSigCgt:\t{:016x}\nCapInh:\t0000000000000000\n\
         CapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n\
         CapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\nSeccomp_filters:\t0\n\
         Cpus_allowed:\t1\nCpus_allowed_list:\t0\nMems_allowed:\t1\nMems_allowed_list:\t0\n\
         voluntary_ctxt_switches:\t0\nnonvoluntary_ctxt_switches:\t0\n",
        x.umask,
        state_name(s.state),
        s.pid,
        x.tid,
        s.ppid,
        s.pid,
        x.tid,
        s.pgid,
        s.sid,
        x.locked / 1024,
        x.rss / 1024,
        s.threads,
        s.pending,
        x.shared_pending,
        s.blocked,
        s.ignored,
        s.caught,
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
        let text = meminfo(MemInfo { total: 1024, free: 512 });
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 21);
        assert_eq!(lines[0], "MemTotal:           1024 kB");
        assert_eq!(lines[2], "MemAvailable:        512 kB");
        assert!(text.contains("\nHugePages_Total:       0\n"));
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
            exit_signal: 17,
            ..Stat::default()
        };
        let text = String::from_utf8(stat(&s)).unwrap();
        assert!(text.starts_with("7 (a b)) S 1 7 1 "));
        // A parser finds the end of the name at the last ')'.
        let rest = &text[text.rfind(')').unwrap() + 2..];
        let fields: Vec<&str> = rest.split_ascii_whitespace().collect();
        assert_eq!(fields.len() + 2, 52);
        assert_eq!(fields[17], "2");
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
        let text =
            String::from_utf8(status(&s, &Status { tid: 6, umask: 0o22, ..Status::default() }))
                .unwrap();
        assert!(text.starts_with("Name:\tsh\nUmask:\t0022\nState:\tR (running)\nTgid:\t5\n"));
        assert!(text.contains("\nPid:\t6\nPPid:\t1\n"));
        assert_eq!(state_name(b'Z'), "Z (zombie)");
    }

    #[test]
    fn numbers_go_both_ways() {
        assert_eq!(number(-3), b"-3\n");
        assert_eq!(parse_number(b" 42\n"), Some(42));
        assert_eq!(parse_number(b"x"), None);
    }
}

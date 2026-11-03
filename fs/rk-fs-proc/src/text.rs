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

/// A block device, for `/proc/diskstats` and `/proc/partitions`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Disk {
    /// The major number of the device.
    pub major: u32,
    /// The minor number of the device.
    pub minor: u32,
    /// The name of the device, as `vda`.
    pub name: String,
    /// The size in sectors of 512 bytes.
    pub sectors: u64,
    /// The 17 counts of `/sys/block/DEV/stat`.
    pub stats: [u64; 17],
}

/// The text of `/proc/diskstats`, as `diskstats_show` of block/genhd.c of Linux: the numbers,
/// the name and the 17 counts of each device.
pub fn diskstats(disks: &[Disk]) -> String {
    let mut out = String::new();
    for d in disks {
        let _ = write!(out, "{:>4} {:>7} {}", d.major, d.minor, d.name);
        for v in d.stats {
            let _ = write!(out, " {v}");
        }
        out.push('\n');
    }
    out
}

/// The text of `/proc/partitions`, as `show_partition` of block/genhd.c of Linux: the size of
/// each device in blocks of 1 KiB. A device with no sectors, as a loop device without a file, is
/// not in the list.
pub fn partitions(disks: &[Disk]) -> String {
    let mut out = String::from("major minor  #blocks  name\n\n");
    for d in disks.iter().filter(|d| d.sectors > 0) {
        let _ = writeln!(out, "{:>4}  {:>7} {:>10} {}", d.major, d.minor, d.sectors >> 1, d.name);
    }
    out
}

/// The names of `/proc/vmstat` in the order of mm/vmstat.c of Linux 6.8 on x86-64: the counts of
/// a zone (12), the NUMA events (6), the counts of a node (46), the two dirty limits and the
/// events.
const VMSTAT_NAMES: &str = "nr_free_pages nr_zone_inactive_anon nr_zone_active_anon nr_zone_inactive_file \
     nr_zone_active_file nr_zone_unevictable nr_zone_write_pending nr_mlock nr_bounce \
     nr_zspages nr_free_cma nr_unaccepted numa_hit numa_miss numa_foreign numa_interleave \
     numa_local numa_other nr_inactive_anon nr_active_anon nr_inactive_file nr_active_file \
     nr_unevictable nr_slab_reclaimable nr_slab_unreclaimable nr_isolated_anon \
     nr_isolated_file workingset_nodes workingset_refault_anon workingset_refault_file \
     workingset_activate_anon workingset_activate_file workingset_restore_anon \
     workingset_restore_file workingset_nodereclaim nr_anon_pages nr_mapped nr_file_pages \
     nr_dirty nr_writeback nr_writeback_temp nr_shmem nr_shmem_hugepages nr_shmem_pmdmapped \
     nr_file_hugepages nr_file_pmdmapped nr_anon_transparent_hugepages nr_vmscan_write \
     nr_vmscan_immediate_reclaim nr_dirtied nr_written nr_throttled_written \
     nr_kernel_misc_reclaimable nr_foll_pin_acquired nr_foll_pin_released nr_kernel_stack \
     nr_page_table_pages nr_sec_page_table_pages nr_swapcached pgpromote_success \
     pgpromote_candidate pgdemote_kswapd pgdemote_direct pgdemote_khugepaged \
     nr_dirty_threshold nr_dirty_background_threshold pgpgin pgpgout pswpin pswpout \
     pgalloc_dma pgalloc_dma32 pgalloc_normal pgalloc_movable pgalloc_device allocstall_dma \
     allocstall_dma32 allocstall_normal allocstall_movable allocstall_device pgskip_dma \
     pgskip_dma32 pgskip_normal pgskip_movable pgskip_device pgfree pgactivate pgdeactivate \
     pglazyfree pgfault pgmajfault pglazyfreed pgrefill pgreuse pgsteal_kswapd \
     pgsteal_direct pgsteal_khugepaged pgscan_kswapd pgscan_direct pgscan_khugepaged \
     pgscan_direct_throttle pgscan_anon pgscan_file pgsteal_anon pgsteal_file \
     zone_reclaim_failed pginodesteal slabs_scanned kswapd_inodesteal \
     kswapd_low_wmark_hit_quickly kswapd_high_wmark_hit_quickly pageoutrun pgrotated \
     drop_pagecache drop_slab oom_kill numa_pte_updates numa_huge_pte_updates \
     numa_hint_faults numa_hint_faults_local numa_pages_migrated pgmigrate_success \
     pgmigrate_fail thp_migration_success thp_migration_fail thp_migration_split \
     compact_migrate_scanned compact_free_scanned compact_isolated compact_stall \
     compact_fail compact_success compact_daemon_wake compact_daemon_migrate_scanned \
     compact_daemon_free_scanned htlb_buddy_alloc_success htlb_buddy_alloc_fail \
     unevictable_pgs_culled unevictable_pgs_scanned unevictable_pgs_rescued \
     unevictable_pgs_mlocked unevictable_pgs_munlocked unevictable_pgs_cleared \
     unevictable_pgs_stranded thp_fault_alloc thp_fault_fallback thp_fault_fallback_charge \
     thp_collapse_alloc thp_collapse_alloc_failed thp_file_alloc thp_file_fallback \
     thp_file_fallback_charge thp_file_mapped thp_split_page thp_split_page_failed \
     thp_deferred_split_page thp_split_pmd thp_scan_exceed_none_pte thp_scan_exceed_swap_pte \
     thp_scan_exceed_share_pte thp_split_pud thp_zero_page_alloc thp_zero_page_alloc_failed \
     thp_swpout thp_swpout_fallback balloon_inflate balloon_deflate balloon_migrate swap_ra \
     swap_ra_hit ksm_swpin_copy cow_ksm zswpin zswpout zswpwb direct_map_level2_splits \
     direct_map_level3_splits nr_unstable";

/// The counts of a zone in `VMSTAT_NAMES`.
const VM_ZONE_ITEMS: usize = 12;

/// The NUMA events after the counts of a zone in `VMSTAT_NAMES`.
const VM_NUMA_ITEMS: usize = 6;

/// The counts of a node after the NUMA events in `VMSTAT_NAMES`.
const VM_NODE_ITEMS: usize = 46;

/// The counts of the memory for `/proc/vmstat`, `/proc/zoneinfo` and `/proc/buddyinfo`, in pages
/// of 4 KiB unless noted. The machine has one node with one zone, `Normal`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VmCounts {
    /// The frames that the allocator manages.
    pub total: u64,
    /// The free frames.
    pub free: u64,
    /// The transparent huge pages that are mapped, in huge pages.
    pub anon_thp: u64,
    /// The page faults since boot.
    pub faults: u64,
    /// The KiB that the block devices read and wrote.
    pub pgpgin: u64,
    /// The KiB that the block devices wrote.
    pub pgpgout: u64,
    /// `vm.min_free_kbytes`.
    pub min_free_kbytes: u64,
    /// The first frame and the end of the frames of the zone.
    pub span: (u64, u64),
    /// The free blocks of each order, from `rk_frame::mm::free_blocks`.
    pub blocks: [u64; 11],
    /// The `count`, `high` and `batch` of the free list of each CPU.
    pub cpus: Vec<(u64, u64, u64)>,
}

/// The value of the count `name` of `/proc/vmstat`. A count that rukernel does not keep is 0.
fn vm_value(c: &VmCounts, name: &str) -> u64 {
    match name {
        "nr_free_pages" => c.free,
        "nr_anon_transparent_hugepages" => c.anon_thp,
        "pgfault" => c.faults,
        "pgpgin" => c.pgpgin,
        "pgpgout" => c.pgpgout,
        // The defaults of vm.dirty_ratio and vm.dirty_background_ratio, 20 and 10 percent of
        // the free memory, as `global_dirty_limits` of Linux.
        "nr_dirty_threshold" => c.free / 5,
        "nr_dirty_background_threshold" => c.free / 10,
        _ => 0,
    }
}

/// The names of `/proc/vmstat` of this architecture. Only x86-64 counts the splits of the direct
/// map.
fn vm_names() -> impl Iterator<Item = &'static str> {
    VMSTAT_NAMES
        .split(' ')
        .filter(|n| cfg!(target_arch = "x86_64") || !n.starts_with("direct_map_"))
}

/// The text of `/proc/vmstat`, as `vmstat_show` of mm/vmstat.c of Linux.
pub fn vmstat(c: &VmCounts) -> String {
    let mut out = String::new();
    for name in vm_names() {
        let _ = writeln!(out, "{name} {}", vm_value(c, name));
    }
    out
}

/// The text of `/proc/buddyinfo`, as `frag_show_print` of mm/vmstat.c of Linux: the free blocks
/// of each order of the zone.
pub fn buddyinfo(c: &VmCounts) -> String {
    let mut out = format!("Node 0, zone {:>8} ", "Normal");
    for n in c.blocks {
        let _ = write!(out, "{n:6} ");
    }
    out.push('\n');
    out
}

/// The watermarks `min`, `low` and `high` of a zone of `managed` pages with `min_free_kbytes`, as
/// `__setup_per_zone_wmarks` of Linux with the default `watermark_scale_factor` of 10.
fn watermarks(managed: u64, min_free_kbytes: u64) -> (u64, u64, u64) {
    let min = min_free_kbytes / 4;
    let step = (min / 4).max(managed * 10 / 10_000);
    (min, min + step, min + 2 * step)
}

/// The text of `/proc/zoneinfo`, as `zoneinfo_show_print` of mm/vmstat.c of Linux: the counts of
/// the node, the size and the counts of the zone, and the free list of each CPU.
pub fn zoneinfo(c: &VmCounts) -> String {
    let mut names = vm_names();
    let zone: Vec<&str> = names.by_ref().take(VM_ZONE_ITEMS).collect();
    let numa: Vec<&str> = names.by_ref().take(VM_NUMA_ITEMS).collect();
    let node: Vec<&str> = names.take(VM_NODE_ITEMS).collect();
    let mut out = format!("Node 0, zone {:>8}\n  per-node stats", "Normal");
    for name in node {
        let _ = write!(out, "\n      {name:<12} {}", vm_value(c, name));
    }
    let (min, low, high) = watermarks(c.total, c.min_free_kbytes);
    let _ = write!(
        out,
        "\n  pages free     {}\n        boost    0\n        min      {min}\n        low      {low}\n        \
         high     {high}\n        spanned  {}\n        present  {}\n        managed  {}\n        \
         cma      0\n        protection: (0, 0, 0, 0, 0)",
        c.free,
        c.span.1 - c.span.0,
        c.total,
        c.total,
    );
    for name in zone.into_iter().chain(numa) {
        let _ = write!(out, "\n      {name:<12} {}", vm_value(c, name));
    }
    out.push_str("\n  pagesets");
    for (cpu, (count, high, batch)) in c.cpus.iter().enumerate() {
        let _ = write!(
            out,
            "\n    cpu: {cpu}\n              count: {count}\n              high:  {high}\n              \
             batch: {batch}\n  vm stats threshold: 0"
        );
    }
    let _ = writeln!(out, "\n  node_unreclaimable:  0\n  start_pfn:           {}", c.span.0);
    out
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
    /// The two letter names of the flags of the area for the line `VmFlags`, in the order of
    /// `show_smap_vma_flags` of Linux.
    pub flags: Vec<&'static str>,
}

/// The lines of `/proc/PID/smaps` after the map line of an area, as `show_smap` of Linux gives
/// them. The counts that rukernel does not keep are 0.
pub fn smaps_area(out: &mut Vec<u8>, a: &SmapsArea) {
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
    // Each flag has a space after it, as `show_smap_vma_flags` of Linux prints "%c%c ".
    out.extend_from_slice(format!("{:<16}{:>8}\nVmFlags: ", "THPeligible:", 0).as_bytes());
    for name in &a.flags {
        out.extend_from_slice(name.as_bytes());
        out.push(b' ');
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

/// Reads an unsigned number in the base of its prefix, as `kstrtoull` of Linux with the base 0:
/// `0x` gives base 16, another leading `0` gives base 8, and the rest is base 10. A `+` and a
/// new line at the end are accepted. Gives `None` for a text that is not a number, and the
/// number can be larger than any `u32`.
pub fn parse_unsigned(bytes: &[u8]) -> Option<u64> {
    let s = core::str::from_utf8(bytes).ok()?;
    let s = s.strip_suffix('\n').unwrap_or(s);
    let s = s.strip_prefix('+').unwrap_or(s);
    let (digits, radix) = if let Some(hex) = s.strip_prefix("0x").or(s.strip_prefix("0X")) {
        (hex, 16)
    } else if s.len() > 1 && s.starts_with('0') {
        (&s[1..], 8)
    } else {
        (s, 10)
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

/// The text of `/proc/PID/coredump_filter`, as `proc_coredump_filter_read` of Linux.
pub fn coredump_filter(value: u32) -> Vec<u8> {
    format!("{value:08x}\n").into_bytes()
}

/// The text of `/proc/interrupts` with the `TLB` line of x86 only, as `show_interrupts` of Linux
/// (fs/proc/interrupts.c, kernel/irq/proc.c) and `arch_show_interrupts`
/// (arch/x86/kernel/irq.c). `tlb` has the count of each CPU, or is `None` if the CPUs drop TLB
/// entries with no interrupt.
pub fn interrupts(cpus: usize, tlb: Option<&[u64]>) -> String {
    let mut out = format!("{:11}", "");
    for c in 0..cpus {
        let _ = write!(out, "CPU{c:<8}");
    }
    out.push('\n');
    if let Some(counts) = tlb {
        out.push_str("TLB: ");
        for n in counts {
            let _ = write!(out, "{n:10} ");
        }
        out.push_str("  TLB shootdowns\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupts_has_the_format_of_linux() {
        assert_eq!(
            interrupts(2, Some(&[0, 1234])),
            "           CPU0       CPU1       \nTLB:          0       1234   TLB shootdowns\n"
        );
        assert_eq!(interrupts(1, None), "           CPU0       \n");
    }

    #[test]
    fn unsigned_numbers_take_the_base_of_their_prefix() {
        assert_eq!(parse_unsigned(b"0x33\n"), Some(0x33));
        assert_eq!(parse_unsigned(b"0X1ff"), Some(0x1ff));
        assert_eq!(parse_unsigned(b"017"), Some(0o17));
        assert_eq!(parse_unsigned(b"51"), Some(51));
        assert_eq!(parse_unsigned(b"+0"), Some(0));
        assert_eq!(parse_unsigned(b"0x"), None);
        assert_eq!(parse_unsigned(b"08"), None);
        assert_eq!(parse_unsigned(b"-1"), None);
        assert_eq!(parse_unsigned(b" 1"), None);
        assert_eq!(coredump_filter(0x33), b"00000033\n");
    }

    #[test]
    fn diskstats_and_partitions_have_the_format_of_linux() {
        let mut stats = [0; 17];
        stats[0] = 120;
        stats[9] = 7;
        let vda = Disk { major: 254, minor: 0, name: String::from("vda"), sectors: 8192, stats };
        let loop0 = Disk { major: 7, minor: 0, name: String::from("loop0"), ..Disk::default() };
        let list = [loop0, vda];
        assert_eq!(
            diskstats(&list),
            "   7       0 loop0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n \
             254       0 vda 120 0 0 0 0 0 0 0 0 7 0 0 0 0 0 0 0\n"
        );
        assert_eq!(
            partitions(&list),
            "major minor  #blocks  name\n\n 254        0       4096 vda\n"
        );
    }

    #[test]
    fn vmstat_zoneinfo_and_buddyinfo_have_the_format_of_linux() {
        let mut blocks = [0; 11];
        blocks[0] = 3;
        blocks[10] = 100;
        let c = VmCounts {
            total: 131_072,
            free: 120_000,
            faults: 42,
            min_free_kbytes: 5792,
            span: (1, 131_040),
            blocks,
            cpus: alloc::vec![(5, 128, 32)],
            ..VmCounts::default()
        };
        let v = vmstat(&c);
        assert_eq!(v.lines().count(), 178);
        assert!(v.starts_with("nr_free_pages 120000\nnr_zone_inactive_anon 0\n"));
        assert!(v.contains("\npgfault 42\n"));
        assert!(v.contains("\nnr_dirty_threshold 24000\nnr_dirty_background_threshold 12000\n"));
        assert!(v.ends_with("\nnr_unstable 0\n"));
        assert_eq!(
            buddyinfo(&c),
            concat!(
                "Node 0, zone   Normal      3      0      0      0      0      0      0      0",
                "      0      0    100 \n"
            )
        );
        let z = zoneinfo(&c);
        assert!(
            z.starts_with("Node 0, zone   Normal\n  per-node stats\n      nr_inactive_anon 0\n")
        );
        assert!(z.contains("\n      nr_mapped    0\n"));
        assert!(
            z.contains("\n  pages free     120000\n        boost    0\n        min      1448\n")
        );
        assert!(z.contains("\n        spanned  131039\n        present  131072\n"));
        assert!(z.contains("\n      nr_free_pages 120000\n"));
        assert!(z.contains("\n    cpu: 0\n              count: 5\n              high:  128\n"));
        assert!(z.ends_with("\n  node_unreclaimable:  0\n  start_pfn:           1\n"));
    }

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
        let flags = alloc::vec!["rd", "wr", "mr", "mw", "me", "lo", "ac"];
        let area = SmapsArea { size: 8192, rss: 4096, anon: true, locked: true, flags };
        smaps_area(&mut out, &area);
        let text = core::str::from_utf8(&out).unwrap_or("");
        assert!(text.starts_with("Size:                  8 kB\n"));
        assert!(text.contains("\nRss:                   4 kB\n"));
        assert!(text.contains("\nLocked:                4 kB\n"));
        assert!(text.contains("\nTHPeligible:           0\n"));
        assert!(text.ends_with("VmFlags: rd wr mr mw me lo ac \n"));
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

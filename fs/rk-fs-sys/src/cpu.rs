//! The directories `/sys/devices/system/cpu` and `/sys/devices/system/node`, as
//! drivers/base/cpu.c, drivers/base/topology.c and drivers/base/node.c of Linux.
//!
//! The machine has one package and one NUMA node, and each CPU is a core with one thread, as
//! `/proc/cpuinfo` tells. A mask is in the format `%*pb` of Linux, and a list in the format
//! `%*pbl`, with the number of CPUs that run as `nr_cpu_ids`.

use crate::Kind;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use rk_frame::cpu::MAX_CPUS;

/// The kernel runs on x86-64. Some files differ from arm64.
const X86: bool = cfg!(target_arch = "x86_64");

/// The files of `cpuN/topology` that each architecture has, from drivers/base/topology.c.
/// x86-64 also has `die_id`, `die_cpus` and `die_cpus_list`.
const TOPOLOGY: [&str; 13] = [
    "cluster_cpus",
    "cluster_cpus_list",
    "cluster_id",
    "core_cpus",
    "core_cpus_list",
    "core_id",
    "core_siblings",
    "core_siblings_list",
    "package_cpus",
    "package_cpus_list",
    "physical_package_id",
    "thread_siblings",
    "thread_siblings_list",
];

/// The mask of the CPUs in `cpus` (a range of numbers below `n`), as `%*pb` with `n` bits: groups
/// of 32 bits in hexadecimal, separated by commas, with the high group first. Only the first
/// group is shorter than 8 digits.
pub(crate) fn mask(n: usize, cpus: core::ops::Range<usize>) -> String {
    let groups = n.div_ceil(32).max(1);
    let mut out = String::new();
    for g in (0..groups).rev() {
        let mut word = 0u32;
        for bit in 0..32 {
            if cpus.contains(&(g * 32 + bit)) {
                word |= 1 << bit;
            }
        }
        if g == groups - 1 {
            let digits = ((n.max(1) - 1) % 32 + 1).div_ceil(4);
            out.push_str(&format!("{word:0digits$x}"));
        } else {
            out.push_str(&format!(",{word:08x}"));
        }
    }
    out.push('\n');
    out
}

/// The list of the CPUs in `cpus`, as `%*pbl`: `0-3`, or `2` for one CPU, or an empty line.
pub(crate) fn list(cpus: core::ops::Range<usize>) -> String {
    match cpus.len() {
        0 => String::from("\n"),
        1 => format!("{}\n", cpus.start),
        _ => format!("{}-{}\n", cpus.start, cpus.end - 1),
    }
}

/// The text of the file `name` of `cpuN/topology` for the CPU `cpu` of `n` CPUs.
fn topology(n: usize, cpu: usize, name: &str) -> Option<String> {
    let one = cpu..cpu + 1;
    Some(match name {
        "core_id" => format!("{cpu}\n"),
        "physical_package_id" | "die_id" => String::from("0\n"),
        // x86-64 shows the ID of the L2 cache, and without one the largest number of 16 bits.
        // On arm64 the device tree of QEMU has a `cpu-map` with one cluster when the machine has
        // more than one CPU. Without it, Linux gives -1 and each CPU is its own cluster.
        "cluster_id" if X86 => String::from("65535\n"),
        "cluster_id" if n > 1 => String::from("0\n"),
        "cluster_id" => String::from("-1\n"),
        "cluster_cpus" if !X86 => mask(n, 0..n),
        "cluster_cpus_list" if !X86 => list(0..n),
        "core_cpus" | "thread_siblings" | "cluster_cpus" => mask(n, one),
        "core_cpus_list" | "thread_siblings_list" | "cluster_cpus_list" => list(one),
        "core_siblings" | "package_cpus" | "die_cpus" => mask(n, 0..n),
        "core_siblings_list" | "package_cpus_list" | "die_cpus_list" => list(0..n),
        _ => return None,
    })
}

/// The number of the directory `cpuN`, if `name` is one of the `n` CPUs.
fn cpu_number(n: usize, name: &str) -> Option<usize> {
    let digits = name.strip_prefix("cpu")?;
    let canonical = !digits.is_empty() && (digits == "0" || !digits.starts_with('0'));
    if !canonical || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok().filter(|&c| c < n)
}

/// A file with `text`.
fn file(name: &str, text: String) -> (String, Kind) {
    (String::from(name), Kind::File(text.into_bytes()))
}

/// The entries of `/sys/devices/system` and of its directories, with `n` CPUs. `rest` is the
/// path below `devices/system`. Gives `None` if no directory has the path.
pub(crate) fn entries(n: usize, rest: &[&str]) -> Option<Vec<(String, Kind)>> {
    let dir = |name: &str| (String::from(name), Kind::Dir);
    let link = |name: &str, to: String| (String::from(name), Kind::Link(to.into_bytes()));
    let all = 0..n;
    Some(match *rest {
        [] => Vec::from([dir("cpu"), dir("node")]),
        ["cpu"] => {
            let mut out: Vec<(String, Kind)> = (0..n).map(|c| dir(&format!("cpu{c}"))).collect();
            out.push(file("isolated", String::from("\n")));
            out.push(file("kernel_max", format!("{}\n", MAX_CPUS - 1)));
            out.push(file("offline", list(n..n)));
            out.push(file("online", list(all.clone())));
            out.push(file("possible", list(all.clone())));
            out.push(file("present", list(all)));
            out.push(file("uevent", String::new()));
            out
        }
        ["cpu", name] => {
            let cpu = cpu_number(n, name)?;
            let mut out = Vec::from([
                link("node0", String::from("../../node/node0")),
                dir("topology"),
                file("uevent", String::new()),
            ]);
            // On x86-64 the boot CPU cannot go offline, so it has no `online` file, as
            // `arch_register_cpu` of Linux. On arm64 with PSCI each CPU has it.
            if cpu != 0 || !X86 {
                out.push(file("online", String::from("1\n")));
            }
            out
        }
        ["cpu", name, "topology"] => {
            let cpu = cpu_number(n, name)?;
            let x86 = ["die_cpus", "die_cpus_list", "die_id"];
            let names = TOPOLOGY.iter().chain(x86.iter().filter(|_| X86));
            names.map(|&f| file(f, topology(n, cpu, f).unwrap_or_default())).collect()
        }
        ["node"] => Vec::from([
            dir("node0"),
            file("has_cpu", list(0..1)),
            file("has_memory", list(0..1)),
            file("has_normal_memory", list(0..1)),
            file("online", list(0..1)),
            file("possible", list(0..1)),
            file("uevent", String::new()),
        ]),
        ["node", "node0"] => {
            let mut out: Vec<(String, Kind)> =
                (0..n).map(|c| link(&format!("cpu{c}"), format!("../../cpu/cpu{c}"))).collect();
            out.push(file("cpulist", list(0..n)));
            out.push(file("cpumap", mask(n, 0..n)));
            out.push(file("distance", String::from("10\n")));
            out.push(file("uevent", String::new()));
            out
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mask_has_the_format_of_linux() {
        assert_eq!(mask(1, 0..1), "1\n");
        assert_eq!(mask(6, 1..2), "02\n");
        assert_eq!(mask(6, 0..6), "3f\n");
        assert_eq!(mask(8, 0..8), "ff\n");
        assert_eq!(mask(32, 0..1), "00000001\n");
        assert_eq!(mask(40, 0..40), "ff,ffffffff\n");
        assert_eq!(mask(64, 63..64), "80000000,00000000\n");
    }

    #[test]
    fn a_list_has_the_format_of_linux() {
        assert_eq!(list(0..1), "0\n");
        assert_eq!(list(0..4), "0-3\n");
        assert_eq!(list(3..4), "3\n");
        assert_eq!(list(4..4), "\n");
    }

    #[test]
    fn each_cpu_has_a_directory_and_a_topology() {
        let names = |rest: &[&str]| -> Vec<String> {
            entries(4, rest).unwrap().into_iter().map(|(n, _)| n).collect()
        };
        assert!(names(&["cpu"]).starts_with(&["cpu0", "cpu1", "cpu2", "cpu3"].map(String::from)));
        assert!(entries(4, &["cpu", "cpu4"]).is_none());
        assert!(entries(4, &["cpu", "cpu01"]).is_none());
        assert_eq!(topology(4, 2, "core_id").unwrap(), "2\n");
        assert_eq!(topology(4, 2, "core_cpus").unwrap(), "4\n");
        assert_eq!(topology(4, 2, "package_cpus_list").unwrap(), "0-3\n");
        assert_eq!(names(&["node", "node0"])[..2], ["cpu0", "cpu1"].map(String::from));
    }
}

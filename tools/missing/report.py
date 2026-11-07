#!/usr/bin/env python3
"""Makes the report of the files under /proc and /sys that an image reads and that rukernel does
not have.

The kernel option `rk.missing=1` makes the kernel log a line `rk.missing: PATH COMM` for each
lookup under /proc and /sys that gives ENOENT. This script reads the boot logs of an image, puts
the paths of the processes, threads and file descriptors in one form, and writes IMAGE.md next to
it with one line for each missing file, the programs that looked for it and the Linux code of the
file.

    RK_CMDLINE=rk.missing=1 RK_BOOT_LOG=1 cargo xtask boot-test alpine > alpine.log
    tools/missing/report.py alpine alpine.log

`--note TEXT` before the image adds a paragraph to the report, for example to tell that the boot
did not end.
"""

import collections
import datetime
import os
import re
import sys

LINUX = "https://github.com/torvalds/linux/blob/v7.3/"

# The Linux code of a missing file: the first pattern that matches the path gives the file.
SOURCES = [
    (r"^/proc/sys/kernel/random/", "drivers/char/random.c"),
    (r"^/proc/sys/kernel/(sem|msg\w*|shm\w*)$", "ipc/ipc_sysctl.c"),
    (r"^/proc/sys/kernel/ns_last_pid$", "kernel/pid_namespace.c"),
    (r"^/proc/sys/kernel/(pid_max|pid_max_min|pid_max_max)$", "kernel/pid.c"),
    (r"^/proc/sys/kernel/(hostname|domainname|osrelease|ostype|version)$", "kernel/utsname_sysctl.c"),
    (r"^/proc/sys/kernel/keys/", "security/keys/sysctl.c"),
    (r"^/proc/sys/kernel/", "kernel/sysctl.c"),
    (r"^/proc/sys/fs/(nr_open|file-max|file-nr)$", "fs/file_table.c"),
    (r"^/proc/sys/fs/binfmt_misc", "fs/binfmt_misc.c"),
    (r"^/proc/sys/fs/inotify/", "fs/notify/inotify/inotify_user.c"),
    (r"^/proc/sys/fs/fanotify/", "fs/notify/fanotify/fanotify_user.c"),
    (r"^/proc/sys/fs/", "fs/proc/proc_sysctl.c"),
    (r"^/proc/sys/vm/vfs_cache_pressure$", "fs/dcache.c"),
    (r"^/proc/sys/vm/memfd_noexec$", "kernel/pid_namespace.c"),
    (r"^/proc/sys/vm/", "mm/vmscan.c"),
    (r"^/proc/sys/net/core/", "net/core/sysctl_net_core.c"),
    (r"^/proc/sys/net/ipv4/", "net/ipv4/sysctl_net_ipv4.c"),
    (r"^/proc/sys/net/ipv6/", "net/ipv6/sysctl_net_ipv6.c"),
    (r"^/proc/sys/net/unix/", "net/unix/sysctl_net_unix.c"),
    (r"^/proc/sys/", "fs/proc/proc_sysctl.c"),
    (r"^/proc/PID/(task/TID/)?(stat|statm|status)$", "fs/proc/array.c"),
    (r"^/proc/PID/(task/TID/)?(maps|smaps|smaps_rollup|pagemap|clear_refs)$", "fs/proc/task_mmu.c"),
    (r"^/proc/PID/(task/TID/)?(fd|fdinfo)", "fs/proc/fd.c"),
    (r"^/proc/PID/(task/TID/)?ns/", "fs/proc/namespaces.c"),
    (r"^/proc/PID/(task/TID/)?net", "net/core/net-procfs.c"),
    (r"^/proc/PID/(task/TID/)?(uid_map|gid_map|projid_map|setgroups)$", "kernel/user_namespace.c"),
    (r"^/proc/PID/(task/TID/)?attr", "security/security.c"),
    (r"^/proc/PID/(task/TID/)?(mounts|mountinfo|mountstats)$", "fs/proc_namespace.c"),
    (r"^/proc/PID/", "fs/proc/base.c"),
    (r"^/proc/(thread-self|self)$", "fs/proc/self.c"),
    (r"^/proc/(vmstat|zoneinfo|buddyinfo|pagetypeinfo)$", "mm/vmstat.c"),
    (r"^/proc/(diskstats|partitions)$", "block/genhd.c"),
    (r"^/proc/(meminfo)$", "fs/proc/meminfo.c"),
    (r"^/proc/(cpuinfo)$", "arch/x86/kernel/cpu/proc.c"),
    (r"^/proc/(kallsyms)$", "kernel/kallsyms.c"),
    (r"^/proc/(modules)$", "kernel/module/procfs.c"),
    (r"^/proc/(kmsg)$", "fs/proc/kmsg.c"),
    (r"^/proc/(consoles)$", "fs/proc/consoles.c"),
    (r"^/proc/(locks)$", "fs/locks.c"),
    (r"^/proc/(misc)$", "drivers/char/misc.c"),
    (r"^/proc/(slabinfo)$", "mm/slab_common.c"),
    (r"^/proc/(softirqs)$", "fs/proc/softirqs.c"),
    (r"^/proc/(timer_list)$", "kernel/time/timer_list.c"),
    (r"^/proc/(sched_debug)$", "kernel/sched/debug.c"),
    (r"^/proc/(schedstat)$", "kernel/sched/stats.c"),
    (r"^/proc/(crypto)$", "crypto/proc.c"),
    (r"^/proc/(kcore)$", "fs/proc/kcore.c"),
    (r"^/proc/(bus|tty|driver|fs|irq|scsi|acpi)(/|$)", "fs/proc/root.c"),
    (r"^/proc/", "fs/proc/root.c"),
    (r"^/sys/devices/system/cpu", "drivers/base/cpu.c"),
    (r"^/sys/devices/system/node", "drivers/base/node.c"),
    (r"^/sys/devices/system/memory", "drivers/base/memory.c"),
    (r"^/sys/devices/pci", "drivers/pci/pci-sysfs.c"),
    (r"^/sys/devices/platform", "drivers/base/platform.c"),
    (r"^/sys/devices/virtual/dmi", "drivers/firmware/dmi-id.c"),
    (r"^/sys/class/dmi", "drivers/firmware/dmi-id.c"),
    (r"^/sys/class/net", "net/core/net-sysfs.c"),
    (r"^/sys/class/tpm", "drivers/char/tpm/tpm-sysfs.c"),
    (r"^/sys/class/", "drivers/base/class.c"),
    (r"^/sys/(block|dev/block)/[^/]+/(queue/)", "block/blk-sysfs.c"),
    (r"^/sys/(block|dev/block)", "block/genhd.c"),
    (r"^/sys/dev/char", "drivers/base/core.c"),
    (r"^/sys/bus/", "drivers/base/bus.c"),
    (r"^/sys/module", "kernel/params.c"),
    (r"^/sys/firmware/devicetree", "drivers/of/kobj.c"),
    (r"^/sys/firmware/efi", "drivers/firmware/efi/efi.c"),
    (r"^/sys/firmware/acpi", "drivers/acpi/sysfs.c"),
    (r"^/sys/firmware", "drivers/firmware/"),
    (r"^/sys/kernel/debug", "fs/debugfs/inode.c"),
    (r"^/sys/kernel/tracing", "fs/tracefs/inode.c"),
    (r"^/sys/kernel/config", "fs/configfs/mount.c"),
    (r"^/sys/kernel/security", "security/inode.c"),
    (r"^/sys/kernel/mm/transparent_hugepage", "mm/huge_memory.c"),
    (r"^/sys/kernel/mm/hugepages", "mm/hugetlb_sysfs.c"),
    (r"^/sys/kernel/", "kernel/ksysfs.c"),
    (r"^/sys/fs/fuse", "fs/fuse/control.c"),
    (r"^/sys/fs/selinux", "security/selinux/selinuxfs.c"),
    (r"^/sys/fs/bpf", "kernel/bpf/inode.c"),
    (r"^/sys/fs/pstore", "fs/pstore/inode.c"),
    (r"^/sys/fs/cgroup", "kernel/cgroup/cgroup.c"),
    (r"^/sys/fs/", "fs/sysfs/mount.c"),
    (r"^/sys/power", "kernel/power/main.c"),
    (r"^/sys/", "fs/sysfs/"),
]

LINE = re.compile(r"rk\.missing: (/\S*) ?(.*)$")


def normal(path):
    """Gives the path in the form of the report, or None for a name that is missing on Linux
    too: a process, a thread or a file descriptor that is not there now. A procfs or a sysfs that
    is mounted at another path, as /run/systemd/mount-rootfs/proc for a sandbox of systemd, gives
    the path under /proc or /sys."""
    if not re.match(r"/(proc|sys)(/|$)", path):
        path = re.sub(r"^/\S*?(?=/(proc|sys)/)", "", path)
    path = re.sub(r"^/proc/\d+(?=/|$)", "/proc/PID", path)
    path = re.sub(r"/task/\d+(?=/|$)", "/task/TID", path)
    path = re.sub(r"/(fd|fdinfo)/\d+$", r"/\1/FD", path)
    path = re.sub(r"^/sys/devices/system/cpu/cpu\d+", "/sys/devices/system/cpu/cpuN", path)
    path = re.sub(r"^/sys/devices/system/node/node\d+", "/sys/devices/system/node/nodeN", path)
    if re.fullmatch(r"/proc/PID(/task/TID)?|/proc/PID(/task/TID)?/(fd|fdinfo)/FD", path):
        return None
    return path


def source(path):
    for pattern, file in SOURCES:
        if re.search(pattern, path):
            return file
    return None


def main():
    args = sys.argv[1:]
    note = None
    if args[:1] == ["--note"] and len(args) > 1:
        note, args = args[1], args[2:]
    if len(args) < 2:
        sys.exit("usage: report.py [--note TEXT] IMAGE LOG...")
    image = args[0]
    found = collections.OrderedDict()
    for log in args[1:]:
        with open(log, errors="replace") as f:
            for line in f:
                m = LINE.search(line.rstrip("\r\n"))
                if not m:
                    continue
                path = normal(m.group(1))
                if path is None:
                    continue
                comm = m.group(2).strip() or "kernel"
                entry = found.setdefault(path, [0, collections.Counter()])
                entry[0] += 1
                entry[1][comm] += 1
    out = [
        f"# The missing files of {image}",
        "",
        f"The files under /proc and /sys that the `{image}` boot test looks for and that rukernel "
        "does not have, from a boot with `rk.missing=1`. `report.py` made this file "
        f"on {datetime.date.today().isoformat()}. PID, TID and FD stand for a number, and cpuN for "
        "the number of a CPU.",
        "",
    ]
    if note:
        out += [note, ""]
    count = "1 file is" if len(found) == 1 else f"{len(found)} files are"
    out += [
        f"{count} missing.",
        "",
        "| File | Programs | Lookups | Linux |",
        "| --- | --- | --- | --- |",
    ]
    for path in sorted(found):
        count, comms = found[path]
        progs = ", ".join(f"`{c}`" for c, _ in comms.most_common())
        src = source(path)
        link = f"[{src}]({LINUX}{src})" if src else ""
        out.append(f"| `{path}` | {progs} | {count} | {link} |")
    dest = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{image}.md")
    with open(dest, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"{dest}: {len(found)} files")


if __name__ == "__main__":
    main()

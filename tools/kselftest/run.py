#!/usr/bin/env python3
"""Runs kselftest programs on rukernel or on a Linux reference kernel under QEMU, and makes the
table of the results.

Usage: tools/kselftest/run.py --kernel FILE --tests DIR --busybox FILE --log FILE [options] TEST...
       tools/kselftest/run.py --report LOG...

DIR of --tests is the output directory of tools/kselftest/build.sh. A TEST is the name of a
program in DIR, for example test_memcontrol. The script makes an initramfs with BusyBox, the
programs and an init script, and boots the kernel once in QEMU. The init script mounts cgroup2 on
/sys/fs/cgroup with the options of systemd, and runs the programs one after the other, each with
a time limit. The serial output goes to the file of --log. Each program gives these lines:

    ks-start: TEST
    ks-out: LINE           (the output of the program)
    ks-result: TEST CODE   (the exit code, or `timeout`)

--linux is for a Linux reference kernel, as /boot/vmlinuz of the host. The kernel command line
then has `panic=-1`, so that QEMU stops when init ends.

--report reads the logs, and writes a Markdown table with the result of each test case of the
programs (the `ok` and `not ok` lines of the kselftest output) for each log. The name of a column
is the kernel of the log: `Linux VERSION` for a Linux kernel, else `rukernel`, with `arm64` after
it for an arm64 log. Two logs of the same kernel get the number of the log after the name.
"""

import argparse
import importlib.util
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
# The cpio writer of tools/ltp/run.py.
_spec = importlib.util.spec_from_file_location("ltp_run", os.path.join(HERE, "..", "ltp", "run.py"))
ltp_run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ltp_run)

# The script that runs as init. /tests has a test on each line: the program and its time limit in
# seconds, with a tab between them. systemd mounts cgroup2 with `nsdelegate` and
# `memory_recursiveprot`, and test_memcontrol reads the second option from /proc/mounts.
INIT = r"""#!/bin/busybox sh
/bin/busybox mkdir -p /usr/bin /usr/sbin /sbin
/bin/busybox --install -s
export PATH=/bin:/sbin:/usr/bin:/usr/sbin TMPDIR=/tmp
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs dev /dev 2>/dev/null
mkdir -p /dev/shm /tmp
mount -t tmpfs shm /dev/shm
mount -t tmpfs tmp /tmp
mount -t cgroup2 -o @OPTS@ cgroup2 /sys/fs/cgroup
# test_memcg_sock connects to a TCP server on the loopback interface.
ip link set lo up
echo "ks-kernel: $(uname -r)"
echo "ks-arch: $(uname -m)"
echo "ks-controllers: $(cat /sys/fs/cgroup/cgroup.controllers)"
cd /kselftest
while IFS='	' read -r t limit; do
    echo "ks-start: $t"
    timeout -s KILL $limit ./$t > /tmp/out 2>&1
    code=$?
    sed 's/^/ks-out: /' /tmp/out
    [ $code = 137 ] && code=timeout
    printf '\nks-result: %s %s\n' "$t" "$code"
done < /tests
echo "ks-done"
"""

# The time limit of a program in seconds. test_memcontrol and test_cpu are long under QEMU
# without KVM.
LIMITS = {"test_memcontrol": 1800, "test_cpu": 1800}
DEFAULT_LIMIT = 900


def boot(a):
    with open(a.busybox, "rb") as f:
        busybox = f.read()
    init = INIT.replace("@OPTS@", a.mount_options)
    lst = "".join(f"{t}\t{LIMITS.get(t, DEFAULT_LIMIT)}\n" for t in a.tests)
    entries = [(".", 0o040755, b"")]
    entries += [(d, 0o040755, b"") for d in ("bin", "tmp", "proc", "sys", "dev", "kselftest")]
    for t in a.tests:
        with open(os.path.join(a.tests_dir, t), "rb") as f:
            entries.append((f"kselftest/{t}", 0o100755, f.read()))
    entries += [
        ("bin/busybox", 0o100755, busybox),
        ("bin/sh", 0o120777, b"busybox"),
        ("init", 0o100755, init.encode()),
        ("tests", 0o100644, lst.encode()),
        ("etc", 0o040755, b""),
        ("etc/passwd", 0o100644, b"root:x:0:0:root:/:/bin/sh\nnobody:x:65534:65534::/:/bin/false\n"),
        ("etc/group", 0o100644, b"root:x:0:\nnogroup:x:65534:\n"),
    ]
    with tempfile.NamedTemporaryFile(suffix=".cpio", delete=False) as f:
        f.write(ltp_run.cpio(entries))
        initrd = f.name
    if a.arch == "aarch64":
        kernel = ltp_run.arm64_image(a.kernel, initrd + ".Image")
        cmd = [
            "qemu-system-aarch64", "-machine", "virt,gic-version=3", "-cpu", "cortex-a72",
            "-accel", "tcg", "-global", "virtio-mmio.force-legacy=false",
        ]
        console = "ttyAMA0"
    else:
        kernel = a.kernel
        cmd = ["qemu-system-x86_64", "-machine", "q35", "-accel", "tcg", "-cpu", "max",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-nic", "none"]
        console = "ttyS0"
    append = f"console={console} rk.test=init rdinit=/init"
    if a.linux:
        append += " panic=-1"
    cmd += [
        "-m", a.memory, "-smp", str(a.smp), "-display", "none", "-serial", "stdio",
        "-no-reboot", "-monitor", "none", "-kernel", kernel, "-initrd", initrd, "-append", append,
    ]
    limit = sum(LIMITS.get(t, DEFAULT_LIMIT) for t in a.tests) + 600
    try:
        with open(a.log, "wb") as log:
            subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                           timeout=limit)
    except subprocess.TimeoutExpired:
        with open(a.log, "ab") as log:
            log.write(b"\nks-hang\n")
    finally:
        os.remove(initrd)
        if kernel != a.kernel:
            os.remove(kernel)


# A line of the kselftest output with the result of one test case.
CASE = re.compile(r"^(not ok|ok) \d+ (?:# (SKIP|XFAIL) ?)?(.*?)(?: # (SKIP|XFAIL).*)?$")


def read_log(path):
    """Gives the kernel name of a log, and the results: [(program, case, result)], with the
    result of a program that did not end as the case `(end)`."""
    kernel, arch, results, current = "rukernel", "", [], None
    with open(path, errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if line.startswith("ks-kernel: ") and "rukernel" not in line:
                v = line.split(": ", 1)[1].strip()
                kernel = f"Linux {v}"
            elif line.startswith("ks-arch: "):
                arch = line.split(": ", 1)[1].strip()
            elif line.startswith("ks-start: "):
                current = line.split(": ", 1)[1].strip()
            elif line.startswith("ks-out: ") and current:
                m = CASE.match(line[len("ks-out: "):])
                if m:
                    skip = m.group(2) or m.group(4)
                    result = "skip" if skip == "SKIP" else "pass" if m.group(1) == "ok" else "fail"
                    results.append((current, m.group(3).strip(), result))
            elif "ks-result: " in line:
                prog, code = line.split("ks-result: ", 1)[1].split()[:2]
                if code == "timeout":
                    results.append((prog, "(end)", "timeout"))
                current = None
        if current:
            results.append((current, "(end)", "hang"))
    if arch == "aarch64":
        kernel += " arm64"
    return kernel, results


def report(logs):
    columns, rows = [], {}
    for path in logs:
        kernel, results = read_log(path)
        # Two logs of the same kernel get the number of the log in their column name.
        if kernel in columns:
            kernel = f"{kernel} ({len(columns) + 1})"
        columns.append(kernel)
        for prog, case, result in results:
            rows.setdefault((prog, case), {})[kernel] = result
    out = ["| Program | Test case | " + " | ".join(columns) + " |",
           "| --- | --- |" + " --- |" * len(columns)]
    for (prog, case), by in rows.items():
        out.append(f"| {prog} | {case} | " + " | ".join(by.get(c, "-") for c in columns) + " |")
    for c in columns:
        count = {}
        for by in rows.values():
            if c in by:
                count[by[c]] = count.get(by[c], 0) + 1
        out.append("")
        out.append(f"{c}: " + ", ".join(f"{n} {r}" for r, n in sorted(count.items())) + ".")
    print("\n".join(out))


def main():
    p = argparse.ArgumentParser(description="Runs kselftest programs under QEMU.")
    p.add_argument("--kernel", help="the kernel ELF file, or a Linux bzImage")
    p.add_argument("--arch", choices=["x86_64", "aarch64"], default="x86_64")
    p.add_argument("--tests", dest="tests_dir", help="the output directory of build.sh")
    p.add_argument("--busybox", help="a static BusyBox program")
    p.add_argument("--log", help="the file of the serial output")
    p.add_argument("--linux", action="store_true", help="the kernel is a Linux reference kernel")
    p.add_argument("--memory", default="1G")
    p.add_argument("--smp", type=int, default=2)
    p.add_argument("--mount-options", default="nsdelegate,memory_recursiveprot",
                   help="the options of the cgroup2 mount")
    p.add_argument("--report", action="store_true", help="make the table from the logs")
    p.add_argument("tests", nargs="+")
    a = p.parse_args()
    if a.report:
        report(a.tests)
        return
    if not (a.kernel and a.tests_dir and a.busybox and a.log):
        sys.exit("run.py: --kernel, --tests, --busybox and --log are needed")
    a.kernel = os.path.abspath(a.kernel)
    boot(a)


if __name__ == "__main__":
    main()

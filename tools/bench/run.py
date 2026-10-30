#!/usr/bin/env python3
"""Runs the benchmarks of bench.c on rukernel and on Linux under QEMU, and writes the table.

Usage: tools/bench/run.py --rukernel FILE --linux FILE [--cc CC] [--arch aarch64] [options]

The script compiles bench.c as a static program with CC (or takes --bench), and puts it in an
initramfs as /init. Then it boots each kernel one time in QEMU with the same machine (CPU count,
memory, accelerator and CPU model) and the same initramfs. The program runs each benchmark one time
as a warm-up and then --runs times, and prints one line for each run. The script keeps the serial
output of each kernel in OUT/KERNEL.log and writes the table to --table. With --reuse, it does not
boot and makes the table from these logs.

With --arch aarch64, the two kernels are arm64 kernels on the QEMU `virt` machine. --rukernel is
then the kernel ELF file or its `Image`, and --linux is a Linux arm64 `Image`. CC must make arm64
programs.

The value of a run is the time of one operation, or a throughput for the stream benchmarks. The
table gives the median of the runs and the interquartile range (IQR) as a percentage of the median.
The ratio is the median time on rukernel divided by the median time on Linux, or the throughput on
Linux divided by the throughput on rukernel. Thus a ratio of 1.00 is equal and a ratio above 1.00
tells that rukernel is slower. A row with a ratio above 2.00 is red.
"""

import argparse
import datetime
import importlib.util
import os
import platform
import select
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

# The benchmarks in the order of the table: the class, the name in bench.c, the unit, True if a
# higher value is better, and the description.
BENCHES = [
    ("entry", "getpid", "ns", False, "`getpid` through `syscall(2)`"),
    ("entry", "null", "ns", False, "null system call (`getppid`, as LMbench)"),
    ("entry", "read_zero", "ns", False, "`read` of 1 byte from /dev/zero"),
    ("entry", "pipe_rw", "ns", False, "pipe `write` and `read` of 1 byte, one process"),
    ("sched", "ctxsw", "ns", False, "pipe ping-pong between two processes, one round trip"),
    ("sched", "yield", "ns", False, "`sched_yield` with no other task"),
    ("sched", "thread", "us", False, "`pthread_create` and `pthread_join`"),
    ("mem", "fault", "ns", False, "write fault on a new anonymous page"),
    ("mem", "mmap", "ns", False, "`mmap` and `munmap` of 64 KiB anonymous memory"),
    ("mem", "fork", "us", False, "`fork`, `_exit` and `waitpid` of a small process"),
    ("mem", "fork_big", "us", False, "the same with 128 MiB of written private memory"),
    ("mem", "fault_mt", "ns", False, "`fault` in one thread per CPU at the same time, wall time"),
    ("mem", "mmap_mt", "ns", False, "`mmap` in one thread per CPU at the same time, wall time"),
    ("mem", "cow", "ns", False, "write fault that copies a 4 KiB page that a child of fork maps"),
    ("net", "tcp_rr", "us", False, "TCP round trip of 1 byte on loopback"),
    ("net", "tcp_stream", "MB/s", True, "TCP throughput on loopback, writes of 64 KiB"),
    ("net", "udp_rr", "us", False, "UDP round trip of 1 byte on loopback"),
    ("net", "udp_stream", "MB/s", True, "UDP throughput on loopback, datagrams of 1 KiB"),
]

RED = 2.0


def cpio(entries):
    """Gives a cpio archive in the newc format. Each entry is (name, mode, data)."""
    out = bytearray()
    for ino, (name, mode, data) in enumerate(entries + [("TRAILER!!!", 0, b"")], 1):
        name = name.encode() + b"\0"
        fields = [ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
        out += b"070701" + b"".join(b"%08x" % f for f in fields) + name
        out += b"\0" * (-len(out) % 4) + data
        out += b"\0" * (-len(out) % 4)
    return bytes(out)


def accel(a):
    """Gives the accelerator and the CPU model. Both kernels use the same. KVM needs a host of the
    same architecture. Without KVM, an arm64 guest has the CPU of the arm64 boot tests."""
    host = {"arm64": "aarch64", "amd64": "x86_64"}.get(platform.machine(), platform.machine())
    if host == a.arch and os.access("/dev/kvm", os.R_OK | os.W_OK):
        return ["-accel", "kvm", "-cpu", "host"]
    return ["-accel", "tcg", "-cpu", a.cpu or ("cortex-a72" if a.arch == "aarch64" else "max")]


def qemu_binary(a):
    """Gives the QEMU program, from the directory --qemu or RK_QEMU, or from PATH."""
    name = f"qemu-system-{a.arch}"
    return os.path.join(a.qemu, name) if a.qemu else name


def machine(a):
    """Gives the machine options of QEMU. The arm64 kernel of rukernel uses the GICv3."""
    if a.arch == "aarch64":
        return ["-machine", "virt,gic-version=3"]
    return ["-machine", "q35"]


def qemu_command(a, kernel, initrd, cmdline):
    cmd = [qemu_binary(a)] + machine(a) + [
        "-m", a.memory, "-smp", str(a.smp),
        "-display", "none", "-serial", "stdio", "-no-reboot", "-monitor", "none",
        "-kernel", kernel, "-initrd", initrd, "-append", cmdline,
    ]
    if a.arch == "x86_64":
        cmd += ["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
    return cmd + accel(a)


def arm64_image(kernel, path):
    """Writes the arm64 `Image` of the rukernel ELF file to `path`, with the function of the LTP
    runner. Gives `path`, or `kernel` if it is an `Image` already."""
    spec = importlib.util.spec_from_file_location("ltp_run", os.path.join(HERE, "../ltp/run.py"))
    ltp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ltp)
    return ltp.arm64_image(kernel, path)


def parse(path):
    """Gives the values of each benchmark in the serial output in the file `path`."""
    values = {}
    with open(path, "rb") as f:
        for raw in f:
            line = raw.decode(errors="replace").strip()
            if line.startswith("bench: "):
                _, bench, value = line.split()
                values.setdefault(bench, []).append(float(value))
    return values


def boot(a, name, kernel, initrd, cmdline):
    """Boots the kernel and gives the values of each benchmark. The serial output goes to
    OUT/NAME.log. QEMU stops at "bench-done", at the time limit, or when the guest stops."""
    cmd = qemu_command(a, kernel, initrd, cmdline)
    values = {}
    print(f"{name}: {' '.join(cmd)}", flush=True)
    start = time.monotonic()
    with open(os.path.join(a.out, f"{name}.log"), "wb") as log:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL)
        buf = b""
        done = False
        while not done:
            if time.monotonic() - start > a.timeout:
                log.write(b"\nrun.py: time limit\n")
                break
            r, _, _ = select.select([p.stdout], [], [], 5)
            if not r:
                continue
            chunk = os.read(p.stdout.fileno(), 65536)
            if not chunk:
                break
            log.write(chunk)
            log.flush()
            buf += chunk
            *lines, buf = buf.split(b"\n")
            for raw in lines:
                line = raw.decode(errors="replace").strip()
                if line.startswith("bench: "):
                    _, bench, value = line.split()
                    values.setdefault(bench, []).append(float(value))
                elif line.startswith("bench-start: "):
                    print(f"{name}: {line}", flush=True)
                elif line == "bench-done":
                    done = True
        p.kill()
        p.wait()
    print(f"{name}: {int(time.monotonic() - start)} s", flush=True)
    return values


def summary(vals):
    """Gives the median and the IQR as a percentage of the median."""
    med = statistics.median(vals)
    if len(vals) < 4 or med == 0:
        return med, 0.0
    q = statistics.quantiles(vals, n=4)
    return med, 100.0 * (q[2] - q[0]) / med


def fmt(v):
    return f"{v:.0f}" if v >= 100 else f"{v:.1f}" if v >= 10 else f"{v:.2f}"


def host_info():
    model = "unknown CPU"
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    model = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    return f"{model}, {os.cpu_count()} CPUs, Linux {platform.release()}"


def qemu_version(a):
    out = subprocess.run([qemu_binary(a), "--version"], capture_output=True, text=True)
    return out.stdout.splitlines()[0] if out.stdout else "unknown"


def commit():
    out = subprocess.run(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"],
                         capture_output=True, text=True)
    return out.stdout.strip() or "unknown"


def table(a, linux, rk):
    """Gives the text of results.md."""
    acc = " ".join(accel(a))
    target = f"{a.arch}-unknown-none"
    arch_opt = " --arch aarch64" if a.arch == "aarch64" else ""
    lines = [
        "# rukernel-bench: the first table",
        "",
        "This file is generated by `tools/bench/run.py` from the serial logs of the run. A copy "
        f"of the logs is in `{logs_dir(a)}`. Do not edit this file. Run the script again to make "
        "a new table.",
        "",
        f"- Date: {a.date}",
        f"- rukernel commit: {a.commit} (release build of the `rukernel` package)",
        f"- Linux: `{os.path.basename(a.linux)}` ({a.linux_note})",
        f"- Host: {a.host}",
        f"- QEMU: {qemu_version(a)}, `{' '.join(machine(a))} -m {a.memory} -smp {a.smp} {acc}`, "
        "the same "
        "for both kernels",
        f"- Userland: one static musl program (`tools/bench/bench.c`) as /init in the same "
        "initramfs for both kernels",
        f"- Linux command line: `{a.linux_cmdline}`",
        f"- rukernel command line: `{a.rk_cmdline}`",
        f"- Runs: {a.runs} runs for each benchmark after one warm-up run, scale {a.scale}",
        "",
        "These are QEMU numbers, not native numbers. "
        + ("Without KVM, QEMU emulates each instruction (TCG). " if "tcg" in acc else "")
        + "The cost of an emulated instruction is not the cost on hardware. Privileged "
        "instructions, page table changes, TLB flushes and device access cost much more than on "
        "hardware, so the ratio can be different on hardware. Use the table to find the large "
        "differences, not to compare small ones. The run does not obey all the rules of "
        "spec/19-rukernel-bench.md: it is one machine, in a VM, with no Mann-Whitney test, with "
        f"one Linux build ({a.linux_note}), and with no check of the mitigations. Linux runs "
        "with `mitigations=off` because rukernel has no mitigations yet. "
        + ("On arm64, Linux also runs with `kpti=0`, because it turns on KPTI for KASLR on a "
           "CPU with no E0PD, and `mitigations=off` does not stop this. rukernel has no KPTI. "
           if a.arch == "aarch64" else "")
        + "Under TCG, Linux is "
        "very slow on the rows that change page tables or switch tasks (`ctxsw`, `thread`, "
        "`fault`, `mmap`, `fork`). The cause is not known yet. Thus a green row in this group "
        "does not show that rukernel is faster on hardware.",
        "",
        "Each value is the median of the runs. The value in parentheses is the interquartile "
        "range as a percentage of the median. The ratio is the time on rukernel divided by the "
        "time on Linux. For the throughput rows (MB/s), it is the throughput on Linux divided by "
        f"the throughput on rukernel. Thus 1.00 is equal and a higher ratio is slower. A ratio "
        f"above {RED:.2f} is a red row, marked **red**. A benchmark that did not run is red too.",
        "",
        "| Class | Benchmark | Description | Unit | Linux | rukernel | Ratio | Mark |",
        "|---|---|---|---|---|---|---|---|",
    ]
    reds = []
    for cls, name, unit, higher, desc in BENCHES:
        if not a.only_set or name in a.only_set:
            lv, rv = linux.get(name), rk.get(name)
            lc = "did not run" if not lv else "%s (%.0f%%)" % (fmt(summary(lv)[0]), summary(lv)[1])
            rc = "did not run" if not rv else "%s (%.0f%%)" % (fmt(summary(rv)[0]), summary(rv)[1])
            if lv and rv:
                lm, rm = summary(lv)[0], summary(rv)[0]
                ratio = (lm / rm if rm else float("inf")) if higher else rm / lm
                rc_ratio = f"{ratio:.2f}"
                red = ratio > RED
            else:
                rc_ratio, red = "-", True
            if red:
                reds.append(name)
            mark = "**red**" if red else ""
            lines.append(f"| {cls} | `{name}` | {desc} | {unit} | {lc} | {rc} | {rc_ratio} | "
                         f"{mark} |")
    lines += ["", f"Red rows: {', '.join(f'`{r}`' for r in reds) if reds else 'none'}.", ""]
    lines += [
        "To make this table again on a host with QEMU and a C compiler for static musl programs:",
        "",
        "```",
        f"cargo build --release --package rukernel --target {target}",
        f"tools/bench/run.py{arch_opt} --rukernel target/{target}/release/rukernel \\",
        f"    --linux {a.linux} --cc {a.cc or 'musl-gcc'} --runs {a.runs}{extra_options(a)}",
        "```",
        "",
    ]
    return "\n".join(lines)


def logs_dir(a):
    """Gives the directory of the logs for the table, relative to the source tree if it is in it."""
    rel = os.path.relpath(a.out, ROOT)
    return a.out if rel.startswith("..") else rel


def extra_options(a):
    """Gives the options of the run that change the machine or the file of the table."""
    out = ""
    if a.qemu:
        out += f" --qemu {a.qemu}"
    if a.cpu:
        out += f" --cpu {a.cpu}"
    if os.path.abspath(a.table) != os.path.join(HERE, "results.md"):
        out += f" --table {os.path.relpath(a.table, ROOT)}"
    return out


def initramfs(a):
    """Compiles bench.c if --bench is not given, and gives the path of the initramfs."""
    prog = a.bench
    if not prog:
        if not a.cc:
            sys.exit("give --cc or --bench")
        prog = os.path.join(a.out, "bench")
        cmd = a.cc.split() + ["-O2", "-static", "-o", prog, os.path.join(HERE, "bench.c"),
                              "-lpthread"]
        subprocess.run(cmd, check=True)
    with open(prog, "rb") as f:
        data = f.read()
    entries = [(".", 0o040755, b"")]
    entries += [(d, 0o040755, b"") for d in ("dev", "proc", "tmp")]
    entries += [("init", 0o100755, data)]
    initrd = os.path.join(a.out, "initrd.cpio")
    with open(initrd, "wb") as f:
        f.write(cpio(entries))
    return initrd


def main():
    p = argparse.ArgumentParser(description="Runs the benchmarks on rukernel and Linux in QEMU.")
    p.add_argument("--rukernel", required=True, help="the rukernel ELF file (a release build)")
    p.add_argument("--linux", required=True, help="the Linux bzImage, or the arm64 Image")
    p.add_argument("--arch", choices=["x86_64", "aarch64"], default="x86_64",
                   help="the architecture of the kernels and of the QEMU machine")
    p.add_argument("--linux-note", default="the kernel of the host distribution",
                   help="a note on the Linux kernel for the table")
    p.add_argument("--cc", help="a C compiler for static musl programs, for example musl-gcc")
    p.add_argument("--bench", help="a static bench program, in place of --cc")
    p.add_argument("--out", default="out", help="the directory of the logs and the initramfs")
    p.add_argument("--table", default=os.path.join(HERE, "results.md"),
                   help="the file of the table")
    p.add_argument("--runs", type=int, default=10)
    p.add_argument("--scale", type=int, default=100,
                   help="the size of a run in percent of the default size")
    p.add_argument("--smp", type=int, default=1)
    p.add_argument("--memory", default="1G")
    p.add_argument("--qemu", default=os.environ.get("RK_QEMU"),
                   help="the directory of the QEMU programs (default: RK_QEMU, or PATH)")
    p.add_argument("--cpu", help="the CPU model without KVM (default: max, or cortex-a72 on "
                   "arm64), for example max,-x2apic")
    p.add_argument("--timeout", type=int, default=3600, help="the time limit of a boot in seconds")
    p.add_argument("--commit", help="the rukernel commit for the table (default: git HEAD)")
    p.add_argument("--reuse", action="store_true", help="do not boot, and make the table from "
                   "the logs in --out of an earlier run with the same options, on the same host")
    p.add_argument("--reuse-linux", action="store_true", help="boot only rukernel, and take the "
                   "Linux values from the log in --out of an earlier run with the same options")
    p.add_argument("--date", help="the date of the run for the table (default: today)")
    p.add_argument("--only", help="run only these benchmarks, with a comma between them")
    a = p.parse_args()
    a.out = os.path.abspath(a.out)
    os.makedirs(a.out, exist_ok=True)

    a.only_set = set(a.only.split(",")) if a.only else set()
    args = f"-- {a.runs} {a.scale}" + "".join(f" {n}" for n in sorted(a.only_set))
    console = "ttyAMA0" if a.arch == "aarch64" else "ttyS0"
    # On arm64, Linux turns on KPTI for KASLR if the CPU has no E0PD, and mitigations=off does not
    # stop this. QEMU without KVM then flushes all its TLB at each kernel entry and exit, because
    # the trampoline changes the ASID in TTBR1_EL1. rukernel has no KPTI, so kpti=0 turns it off.
    kpti = " kpti=0" if a.arch == "aarch64" else ""
    a.linux_cmdline = (f"console={console} rdinit=/init mitigations=off{kpti} quiet panic=-1 "
                       f"{args}")
    a.rk_cmdline = f"console={console} rk.test=init rdinit=/init {args}"
    a.date = a.date or datetime.date.today().isoformat()
    a.commit = a.commit or commit()
    a.host = host_info()

    if a.reuse:
        linux = parse(os.path.join(a.out, "linux.log"))
        rk = parse(os.path.join(a.out, "rukernel.log"))
    else:
        initrd = initramfs(a)
        if a.reuse_linux:
            linux = parse(os.path.join(a.out, "linux.log"))
        else:
            linux = boot(a, "linux", a.linux, initrd, a.linux_cmdline)
        kernel = a.rukernel
        if a.arch == "aarch64":
            kernel = arm64_image(kernel, os.path.join(a.out, "Image"))
        rk = boot(a, "rukernel", kernel, initrd, a.rk_cmdline)
    text = table(a, linux, rk)
    with open(a.table, "w") as f:
        f.write(text)
    print(text)


if __name__ == "__main__":
    main()

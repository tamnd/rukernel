#!/usr/bin/env python3
"""Runs the maps and smaps diff of rukernel and Linux under QEMU, and writes the result.

Usage: tools/mapsdiff/run.py --linux BZIMAGE --kernel NAME=ELF [--kernel NAME=ELF ...]
           --cc CC --rootfs NAME=TARBALL [--rootfs NAME=TARBALL ...] --out DIR

For each root file system (the Alpine and Debian images of the boot tests), the script makes an
initramfs with the files of the image, the static program mapsdump.c and an /init that runs
`mapsdump --cases` and then each ELF program of the image (with --version) and a list of commands
under `mapsdump`. mapsdump prints /proc/PID/maps and /proc/PID/smaps of each program at its exit
stop. The script boots Linux and each rukernel kernel with each initramfs, one time, with the same
machine, and keeps the serial output in DIR/ROOTFS-KERNEL.log.

Then it compares:
- each pair of rukernel kernels (for example the VMA backend and `corten`), byte for byte;
- Linux and each rukernel kernel, after a normalization: the addresses become the size of each area
  and the gap to the area before it, and the device and inode numbers go. For smaps, the values
  that depend on the fault-around of Linux (Rss, Pss and the clean and dirty counts) go.

The Linux comparison has three parts: maps, smaps without VmFlags, and the VmFlags lines. It
skips ProtectionKey (rukernel has no protection keys) and [vsyscall], and it does not compare the
size and the place of [vvar], [vdso] and [stack]. smaps and VmFlags of a program are compared only
if its maps are the same, so the sum of a row with them can be less than the programs.

The diffs are in DIR/diff-*.txt, and the summary in DIR/summary.md.
"""

import argparse
import concurrent.futures
import difflib
import os
import re
import select
import subprocess
import sys
import tarfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))

# Programs that do not run with --version: they stop the machine, or change it.
SKIP = {
    "halt", "poweroff", "reboot", "shutdown", "init", "telinit", "killall5", "kill", "pkill",
    "swapoff", "swapon", "sulogin", "agetty", "getty", "login", "su", "nologin", "pivot_root",
    "switch_root", "ctrlaltdel", "chroot", "unshare", "nsenter", "setsid", "nohup", "timeout",
    "env", "nice", "ionice", "taskset", "chrt", "setpriv", "runuser", "start-stop-daemon",
    "yes", "sleep", "tail", "watch", "top", "script", "more", "less", "pager", "wall", "mesg",
    "debconf-communicate", "dpkg-preconfigure", "faillog", "lastlog",
}

# Commands that run real work, for each image. Each is (name, argv).
COMMANDS = {
    "alpine": [
        ("sh-true", ["/bin/busybox", "sh", "-c", "true"]),
        ("ls-l", ["/bin/busybox", "ls", "-l", "/"]),
        ("sort", ["/bin/busybox", "sort", "/etc/passwd"]),
        ("awk", ["/bin/busybox", "awk", "-F:", "{print $1}", "/etc/passwd"]),
        ("sed", ["/bin/busybox", "sed", "s/root/toor/", "/etc/passwd"]),
        ("find", ["/bin/busybox", "find", "/etc"]),
        ("tar", ["/bin/busybox", "tar", "cf", "/tmp/etc.tar", "/etc"]),
        ("gzip", ["/bin/busybox", "gzip", "-k", "/tmp/etc.tar"]),
        ("md5sum", ["/bin/busybox", "md5sum", "/bin/busybox"]),
        ("apk-info", ["/sbin/apk", "info", "--no-network"]),
        ("ld-list", ["/lib/ld-musl-x86_64.so.1", "--list", "/bin/busybox"]),
        ("scanelf", ["/usr/bin/scanelf", "-R", "/lib"]),
        ("getconf", ["/usr/bin/getconf", "PAGESIZE"]),
        ("ssl-client", ["/usr/bin/ssl_client"]),
    ],
    "debian": [
        ("bash-c", ["/usr/bin/bash", "-c", "for i in 1 2 3; do echo $i; done"]),
        ("ls-l", ["/usr/bin/ls", "-lR", "/etc"]),
        ("sort", ["/usr/bin/sort", "/etc/passwd"]),
        ("sed", ["/usr/bin/sed", "s/root/toor/", "/etc/passwd"]),
        ("grep", ["/usr/bin/grep", "-r", "root", "/etc"]),
        ("find", ["/usr/bin/find", "/usr/lib", "-name", "*.so*"]),
        ("tar", ["/usr/bin/tar", "cf", "/tmp/etc.tar", "/etc"]),
        ("gzip", ["/usr/bin/gzip", "-k", "/tmp/etc.tar"]),
        ("sha256sum", ["/usr/bin/sha256sum", "/usr/bin/bash"]),
        ("perl", ["/usr/bin/perl", "-e", "my %h; $h{$_}=1 for 1..10000; print scalar keys %h"]),
        ("dpkg-l", ["/usr/bin/dpkg", "-l"]),
        ("apt-cache", ["/usr/bin/apt-cache", "stats"]),
        ("ld-list", ["/lib64/ld-linux-x86-64.so.2", "--list", "/usr/bin/bash"]),
        ("awk", ["/usr/bin/awk", "-F:", "{print $1}", "/etc/passwd"]),
    ],
}


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


def rootfs_entries(path):
    """Gives the cpio entries of the image and its ELF programs."""
    entries, programs, data = [], [], {}
    with tarfile.open(path) as tar:
        members = tar.getmembers()
        for m in members:
            if m.isfile():
                data[m.name] = tar.extractfile(m).read()
        for m in members:
            name = m.name.lstrip("./")
            if not name or name.split("/")[0] in ("dev", "proc", "sys"):
                continue
            perm = m.mode & 0o7777
            if m.isdir():
                entries.append((name, 0o040000 | perm, b""))
            elif m.issym():
                entries.append((name, 0o120000 | 0o777, m.linkname.encode()))
            elif m.islnk():
                entries.append((name, 0o100000 | perm, data.get(m.linkname, b"")))
            elif m.isfile():
                body = data[m.name]
                entries.append((name, 0o100000 | perm, body))
                top = os.path.dirname(name)
                if (body[:4] == b"\x7fELF" and perm & 0o111 and
                        top in ("bin", "usr/bin", "sbin", "usr/sbin") and
                        os.path.basename(name) not in SKIP and not m.islnk()):
                    programs.append(name)
    return entries, sorted(set(programs))


def quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def initramfs(a, rootfs, tarball, mapsdump):
    entries, programs = rootfs_entries(tarball)
    lines = ["#!/bin/sh", "/mapsdump --setup", "/mapsdump --cases"]
    for name, argv in COMMANDS.get(rootfs, []):
        lines.append(" ".join(["/mapsdump", quote("cmd-" + name)] + [quote(x) for x in argv]))
    for prog in programs:
        lines.append(f"/mapsdump {quote('ver-' + prog)} {quote('/' + prog)} --version")
    lines.append("echo mapsdiff: done")
    names = {e[0] for e in entries}
    for d in ("dev", "proc", "tmp", "sys"):
        if d not in names:
            entries.append((d, 0o040755, b""))
    entries.append(("mapsdump", 0o100755, mapsdump))
    entries.append(("init", 0o100755, ("\n".join(lines) + "\n").encode()))
    path = os.path.join(a.out, f"{rootfs}.cpio")
    with open(path, "wb") as f:
        f.write(cpio(entries))
    return path, len(programs) + len(COMMANDS.get(rootfs, []))


def boot(a, log_path, kernel, initrd, cmdline):
    """Boots the kernel, and keeps the serial output in log_path. Stops at "mapsdiff: done"."""
    cmd = ["qemu-system-x86_64", "-machine", "q35", "-m", a.memory, "-smp", str(a.smp),
           "-display", "none", "-serial", "stdio", "-no-reboot", "-monitor", "none",
           "-kernel", kernel, "-initrd", initrd, "-append", cmdline,
           "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-accel", "tcg", "-cpu", "max"]
    print(" ".join(cmd), flush=True)
    start = time.monotonic()
    with open(log_path, "wb") as log:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL)
        tail = b""
        while True:
            if time.monotonic() - start > a.timeout:
                print(f"{log_path}: time limit", flush=True)
                break
            r, _, _ = select.select([p.stdout], [], [], 5)
            if not r:
                if p.poll() is not None:
                    break
                continue
            chunk = os.read(p.stdout.fileno(), 65536)
            if not chunk:
                break
            log.write(chunk)
            tail = (tail + chunk)[-64:]
            if b"mapsdiff: done" in tail:
                break
        p.kill()
        p.wait()
    print(f"{log_path}: {time.monotonic() - start:.0f} s", flush=True)


def parse(path):
    """Gives {name: (maps lines, smaps lines)} from a serial log."""
    out, cur, maps, smaps = {}, None, [], []
    with open(path, "rb") as f:
        for raw in f:
            line = raw.decode(errors="replace").rstrip("\r\n")
            i = line.find("mapsdiff: ")
            if i >= 0 and cur is None and line[i:].startswith("mapsdiff: begin "):
                cur, maps, smaps = line[i + 16:].strip(), [], []
            elif cur is not None and line.startswith("mapsdiff: end "):
                out[cur] = (maps, smaps)
                cur = None
            elif cur is not None and line.startswith("M "):
                maps.append(line[2:])
            elif cur is not None and line.startswith("S "):
                smaps.append(line[2:])
    return out


AREA = re.compile(r"^([0-9a-f]+)-([0-9a-f]+) (\S+) ([0-9a-f]+) (\S+) (\d+)\s*(.*)$")
# The smaps values that depend on the fault-around and the page cache of the kernel.
RESIDENT = {"Rss", "Pss", "Pss_Dirty", "Pss_Anon", "Pss_File", "Pss_Shmem", "Shared_Clean",
            "Shared_Dirty", "Private_Clean", "Private_Dirty", "Referenced", "Anonymous",
            "LazyFree"}


# The special areas. Their size and place are a choice of each kernel: the stack of rukernel is
# 8 MiB at the start, and the vDSO of each kernel has its own size. rukernel has no [vsyscall].
SPECIAL = {"[vvar]", "[vvar_vclock]", "[vdso]", "[stack]"}


def norm_areas(lines, smaps):
    """Gives the normalized lines. Each item is (kind, line), where kind is "area", "flags" or
    "value"."""
    out, prev_end, prev_special, skip = [], None, False, False
    for line in lines:
        m = AREA.match(line)
        if m:
            name = m.group(7)
            if name == "[vsyscall]":
                prev_special = True
                skip = True
                continue
            skip = False
            start, end = int(m.group(1), 16), int(m.group(2), 16)
            if prev_end is None:
                gap = "first"
            elif prev_special or name in SPECIAL:
                gap = "?"
            else:
                gap = f"+{(start - prev_end) // 4096}p" if start - prev_end < 1 << 30 else "far"
            size = "?" if name in SPECIAL else f"{(end - start) // 4096}p"
            offset = m.group(4) if name and not name.startswith("[") else "0"
            out.append(("area", f"{gap} {size} {m.group(3)} {offset} {name}"))
            prev_end, prev_special = end, name in SPECIAL
            continue
        if not smaps or skip:
            continue
        key = line.split(":")[0]
        if key == "ProtectionKey" or (prev_special and key in ("Size", "KernelPageSize",
                                                                 "MMUPageSize")):
            continue
        if key == "VmFlags":
            out.append(("flags", re.sub(r"\s+", " ", line).strip()))
        elif key in RESIDENT:
            out.append(("value", key + ":"))
        else:
            out.append(("value", re.sub(r"\s+", " ", line).strip()))
    return out


def views(lines, kind, normalize):
    """Gives the lines of one kind of comparison: "maps", "smaps" (no VmFlags) or "vmflags"."""
    if not normalize:
        return lines
    smaps = kind != "maps"
    items = norm_areas(lines, smaps)
    if kind == "smaps":
        return [x for k, x in items if k != "flags"]
    if kind == "vmflags":
        return [x for k, x in items if k != "value"]
    return [x for _, x in items]


KINDS = (("maps", 0), ("smaps", 1), ("vmflags", 1))


def compare(a, logs, left, right, normalize, label):
    """Compares the programs of two logs. Gives {kind: (same, different)} and the missing names,
    and writes the diff of each kind."""
    result, missing = {}, []
    names = sorted(set(logs[left]) | set(logs[right]))
    missing = [n for n in names if n not in logs[left] or n not in logs[right]]
    kinds = KINDS if normalize else KINDS[:2]
    maps_diff = set()
    for kind, i in kinds:
        same, diff, text = 0, [], []
        for name in names:
            if name in missing:
                continue
            if kind != "maps" and normalize and name in maps_diff:
                # The maps differ, and the diff of maps has it.
                continue
            x = views(logs[left][name][i], kind, normalize)
            y = views(logs[right][name][i], kind, normalize)
            if x == y:
                same += 1
                continue
            diff.append(name)
            text += list(difflib.unified_diff(x, y, f"{left} {name} {kind}",
                                              f"{right} {name} {kind}", lineterm="", n=2))
        with open(os.path.join(a.out, f"diff-{label}-{kind}.txt"), "w") as f:
            f.write("\n".join(text) + "\n")
        result[kind] = (same, diff)
        if kind == "maps":
            maps_diff = set(diff)
    return result, missing


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--linux", help="the Linux bzImage")
    p.add_argument("--kernel", action="append", default=[], help="NAME=ELF of a rukernel kernel")
    p.add_argument("--rootfs", action="append", default=[], help="NAME=TARBALL of an image")
    p.add_argument("--cc", help="a C compiler for static musl programs")
    p.add_argument("--out", default="out")
    p.add_argument("--smp", type=int, default=1)
    p.add_argument("--memory", default="1G")
    p.add_argument("--jobs", type=int, default=1, help="the number of QEMU runs at the same time")
    p.add_argument("--timeout", type=int, default=7200)
    p.add_argument("--reuse", action="store_true", help="do not boot, compare the logs in --out")
    a = p.parse_args()
    a.out = os.path.abspath(a.out)
    os.makedirs(a.out, exist_ok=True)
    kernels = dict(k.split("=", 1) for k in a.kernel)
    if a.linux:
        kernels = {"linux": a.linux, **kernels}
    rootfs = dict(r.split("=", 1) for r in a.rootfs)

    counts = {}
    if not a.reuse:
        mapsdump_path = os.path.join(a.out, "mapsdump")
        subprocess.run(a.cc.split() + ["-O2", "-static", "-o", mapsdump_path,
                                       os.path.join(HERE, "mapsdump.c")], check=True)
        with open(mapsdump_path, "rb") as f:
            mapsdump = f.read()
        runs = []
        for r, tarball in rootfs.items():
            initrd, counts[r] = initramfs(a, r, tarball, mapsdump)
            for k, kernel in kernels.items():
                cmdline = "console=ttyS0 rdinit=/init panic=-1 quiet"
                cmdline += " nokaslr" if k == "linux" else " rk.test=init"
                runs.append((a, os.path.join(a.out, f"{r}-{k}.log"), kernel, initrd, cmdline))
        with concurrent.futures.ThreadPoolExecutor(a.jobs) as pool:
            list(pool.map(lambda x: boot(*x), runs))

    summary = ["| Image | Left | Right | Normalized | File | Same | Different | Missing |",
               "|---|---|---|---|---|---|---|---|"]
    details = []
    for r in rootfs:
        logs = {k: parse(os.path.join(a.out, f"{r}-{k}.log")) for k in kernels}
        names = list(kernels)
        pairs = [(x, y, False) for i, x in enumerate(names) for y in names[i + 1:]
                 if "linux" not in (x, y)]
        pairs += [("linux", y, True) for y in names if y != "linux" and "linux" in names]
        for left, right, normalize in pairs:
            label = f"{r}-{left}-{right}"
            result, missing = compare(a, logs, left, right, normalize, label)
            for kind, (same, diff) in result.items():
                summary.append(f"| {r} | {left} | {right} | {'yes' if normalize else 'no'} "
                               f"| {kind} | {same} | {len(diff)} | {len(missing)} |")
                if diff:
                    details.append(f"- {label} {kind}: " + ", ".join(diff))
            if missing:
                details.append(f"- {label} missing: " + ", ".join(missing))
    text = "\n".join(summary + [""] + details) + "\n"
    with open(os.path.join(a.out, "summary.md"), "w") as f:
        f.write(text)
    print(text)


if __name__ == "__main__":
    sys.exit(main())

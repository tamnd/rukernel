#!/usr/bin/env python3
"""Runs LTP runtest files on rukernel under QEMU, in batches.

Usage: tools/ltp/run.py --kernel FILE --ltp DIR --busybox FILE [options] GROUP...

GROUP is the name of a runtest file of LTP, as `syscalls` or `mm`. `net` is each runtest/net.*
file. DIR of --ltp is the LTP tree of `tools/ltp/build.sh --full`, as LTP installs it in /opt/ltp.

The script makes an ext4 image of the LTP tree, and splits the tests of each runtest file in
batches. Each batch boots the kernel in QEMU. The initramfs has BusyBox, the list of the tests and
an init script. The script mounts the image on /ltp and runs the tests one after the other. Each
test runs in its own session with a time limit. When the time is over, the script kills all the
processes of the session, so one test that hangs does not stop the batch. The disk /dev/vda is
for the tests that need a block device (LTP_DEV).

The serial output of a batch goes to OUT/RUNTEST-NNN/log. Each test gives these lines:

    ltp-start: TAG
    ltp-out: LINE          (the last lines of the output of a test that does not pass)
    ltp-result: TAG RESULT

RESULT is the exit code of the test, `timeout`, or `missing` when the program of the test is not
in the tree. When the kernel stops (a panic) or hangs during a test, this script writes the result
`panic` or `hang` for the test in the log, and boots again with the next test. report.py reads
these lines.

At most --jobs batches run at the same time. A batch with the file `done` in its directory does
not run again, unless --force is given. report.py takes the newest result of each test, so a
second run with --only and --first 101 runs some tests again and keeps the other results. Without KVM, QEMU uses TCG, and a batch is slow.
"""

import argparse
import concurrent.futures
import os
import select
import shutil
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))

# The time limits in seconds of the tests that run longer than --timeout by design, when it is
# smaller. setsockopt11 repeats its check for up to 300 s (.runtime = 300), and a busy host does
# not complete the 64 rounds in that time.
LIMITS = {"setsockopt11": 420}

# The script that runs as init. It reads the tests from /tests, one test on each line: the tag,
# the time limit of the test in seconds and the command, with a tab between them.
INIT = r"""#!/bin/busybox sh
/bin/busybox mkdir -p /usr/bin /usr/sbin /sbin
/bin/busybox --install -s
export PATH=/ltp/testcases/bin:/ltp/bin:/bin:/sbin:/usr/bin:/usr/sbin
export LTPROOT=/ltp TMPDIR=/tmp LTP_TIMEOUT_MUL=@MUL@ KCONFIG_PATH=/etc/kconfig LTP_DEV=/dev/vda
mkdir -p /proc /sys /dev /tmp /ltp
mount -t proc proc /proc
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts 2>/dev/null
mount -t tmpfs shm /dev/shm
mount -t tmpfs tmp /tmp
[ -e /dev/fd ] || ln -s /proc/self/fd /dev/fd
# systemd mounts cgroup2 with nsdelegate, and the cgroup tests of LTP use the mount that they find.
mount -t cgroup2 -o nsdelegate cgroup2 /sys/fs/cgroup 2>/dev/null
# The tests of IPv6 and the sockets send to ::1 and 127.0.0.1, as on a system where lo is up.
ip link set lo up 2>/dev/null
# The drivers that are in the kernel, for tst_require_drivers. rukernel has no modules.
m=/lib/modules/$(uname -r)
mkdir -p $m /var/run/netns
printf "kernel/drivers/net/veth.ko\nkernel/drivers/net/dummy.ko\n" > $m/modules.builtin
: > $m/modules.dep
if ! mount -t ext4 -o ro /dev/vdb /ltp; then
    echo "ltp-error: cannot mount the LTP image"
    exit 1
fi
echo "ltp-ready"
while IFS='	' read -r tag limit cmd; do
    echo "ltp-start: $tag"
    set -- $cmd
    if [ "${1#*=}" = "$1" ] && ! command -v "$1" >/dev/null 2>&1; then
        echo "ltp-result: $tag missing"
        continue
    fi
    rm -f /run-timeout
    cd /tmp
    setsid sh -c "$cmd" </dev/null >/run-out 2>&1 &
    pid=$!
    (
        trap 'kill $s 2>/dev/null; exit 0' TERM
        sleep $limit & s=$!
        wait $s
        echo > /run-timeout
        kill -KILL -$pid 2>/dev/null
    ) &
    dog=$!
    wait $pid
    code=$?
    # A test that stops early can leave the strict overcommit policy with a limit of 0, and then
    # this shell cannot fork. The shell writes the defaults back without a fork.
    echo 0 > /proc/sys/vm/overcommit_memory
    echo 50 > /proc/sys/vm/overcommit_ratio
    kill $dog 2>/dev/null
    wait $dog 2>/dev/null
    # The processes that the test left behind.
    kill -KILL -$pid 2>/dev/null
    cd /
    [ -e /run-timeout ] && code=timeout
    case $code in
    0) ;;
    32) tail -n 20 /run-out | sed 's/^/ltp-out: /' ;;
    *) tail -n 60 /run-out | sed 's/^/ltp-out: /' ;;
    esac
    # The output can end without a new line.
    printf '\nltp-result: %s %s\n' "$tag" "$code"
    rm -rf /tmp/* /dev/shm/* 2>/dev/null
done < /tests
echo "ltp-done"
"""


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


def runtests(ltp, groups):
    """Gives the tests of the groups: a list of (runtest file, tag, command)."""
    names = []
    for g in groups:
        if g == "net":
            names += sorted(n for n in os.listdir(os.path.join(ltp, "runtest")) if n.startswith("net."))
        else:
            names.append(g)
    tests = []
    for name in names:
        with open(os.path.join(ltp, "runtest", name)) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    tests.append((name, parts[0], parts[1]))
    return tests


def make_image(ltp, path):
    """Makes the ext4 image of the LTP tree, if it is not there or is older than the tree."""
    stamp = os.path.join(ltp, "Version")
    if os.path.exists(path) and os.path.getmtime(path) >= os.path.getmtime(stamp):
        return
    size = sum(
        os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(ltp) for f in fs
        if not os.path.islink(os.path.join(d, f))
    )
    mib = size * 3 // 2 // (1 << 20) + 128
    tmp = path + ".new"
    subprocess.run(["truncate", "-s", f"{mib}M", tmp], check=True)
    subprocess.run(["mkfs.ext4", "-q", "-F", "-L", "ltp", "-d", ltp, tmp], check=True)
    os.replace(tmp, path)


class Batch:
    """A batch of tests that runs in one directory, with as many boots as it needs."""

    def __init__(self, a, name, tests):
        self.a = a
        self.name = name
        self.tests = tests
        self.dir = os.path.join(a.out, name)

    def limit(self, tag):
        """Gives the time limit of the test `tag` in seconds."""
        return max(self.a.timeout, LIMITS.get(tag, 0))

    def initramfs(self, tests):
        with open(self.a.busybox, "rb") as f:
            busybox = f.read()
        with open(os.path.join(HERE, "kconfig"), "rb") as f:
            kconfig = f.read()
        init = INIT.replace("@MUL@", str(self.a.mul))
        lst = "".join(f"{tag}\t{self.limit(tag)}\t{cmd}\n" for _, tag, cmd in tests)
        entries = [(".", 0o040755, b"")]
        entries += [(d, 0o040755, b"") for d in ("bin", "etc", "tmp", "proc", "sys", "dev", "ltp")]
        if self.a.ip:
            # The `ip` of iproute2 is in /bin, before the applet of BusyBox in /sbin.
            with open(self.a.ip, "rb") as f:
                entries.append(("bin/ip", 0o100755, f.read()))
        entries += [
            ("bin/busybox", 0o100755, busybox),
            ("bin/sh", 0o120777, b"busybox"),
            ("init", 0o100755, init.encode()),
            ("tests", 0o100644, lst.encode()),
            ("etc/kconfig", 0o100644, kconfig),
            ("etc/passwd", 0o100644,
             b"root:x:0:0:root:/:/bin/sh\nbin:x:1:1:bin:/bin:/bin/false\n"
             b"daemon:x:2:2:daemon:/sbin:/bin/false\nnobody:x:65534:65534:nobody:/:/bin/false\n"),
            ("etc/group", 0o100644,
             b"root:x:0:\nbin:x:1:\ndaemon:x:2:\nusers:x:100:\nnogroup:x:65534:\n"),
            ("etc/hosts", 0o100644, b"127.0.0.1 localhost\n::1 localhost\n"),
            # getaddrinfo_01 looks up the echo service, as in the netbase files of a distribution.
            ("etc/services", 0o100644, b"echo\t7/tcp\necho\t7/udp\n"),
        ]
        path = os.path.join(self.dir, "initrd.cpio")
        with open(path, "wb") as f:
            f.write(cpio(entries))
        return path

    def boot(self, tests, log):
        """Boots once with the tests. Gives the tags with a result, the tag of the test that ran
        when the boot stopped (or None), and the way that the boot stopped."""
        initrd = self.initramfs(tests)
        disk = os.path.join(self.dir, "dev.img")
        with open(disk, "wb") as f:
            f.truncate(512 << 20)
        cmd = [
            "qemu-system-x86_64", "-machine", "q35", "-m", self.a.memory, "-smp", str(self.a.smp),
            "-display", "none", "-serial", "stdio", "-no-reboot", "-monitor", "none",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
            "-kernel", self.a.kernel, "-initrd", initrd,
            "-append", "console=ttyS0 rk.test=init rdinit=/init",
            "-drive", f"if=none,id=dev,format=raw,cache=unsafe,file={disk}",
            "-device", "virtio-blk-pci,drive=dev",
            "-drive", f"if=none,id=ltp,format=raw,readonly=on,file={self.a.image}",
            "-device", "virtio-blk-pci,drive=ltp",
        ]
        if os.access("/dev/kvm", os.R_OK | os.W_OK):
            cmd += ["-accel", "kvm", "-cpu", "host"]
        else:
            cmd += ["-accel", "tcg", "-cpu", "max"]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        done, current, how = set(), None, "exit"
        # The time of the last start of a test, or of the boot.
        since = time.monotonic()
        limit = self.a.boot_timeout
        buf = b""
        while True:
            r, _, _ = select.select([p.stdout], [], [], 5)
            if r:
                chunk = os.read(p.stdout.fileno(), 65536)
                if not chunk:
                    break
                log.write(chunk)
                log.flush()
                buf += chunk
                *lines, buf = buf.split(b"\n")
                for raw in lines:
                    line = raw.decode(errors="replace").strip()
                    # The output of a test can end without a new line, so a mark can come
                    # after other text on the same line.
                    if "ltp-start: " in line:
                        current = line.split("ltp-start: ", 1)[1].strip()
                        since, limit = time.monotonic(), self.limit(current) + 120
                    elif "ltp-result: " in line:
                        done.add(line.split("ltp-result: ", 1)[1].split()[0])
                        current = None
                        since, limit = time.monotonic(), self.a.timeout + 120
                    elif "kernel panic" in line and not line.startswith("ltp-"):
                        how = "panic"
            elif time.monotonic() - since > limit:
                how = "hang"
                p.kill()
                break
        p.wait()
        os.remove(disk)
        os.remove(initrd)
        return done, current, how

    def run(self):
        if os.path.exists(os.path.join(self.dir, "done")) and not self.a.force:
            return f"{self.name}: done before"
        shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir)
        with open(os.path.join(self.dir, "tests"), "w") as f:
            f.write("".join(f"{tag}\t{cmd}\n" for _, tag, cmd in self.tests))
        start = time.monotonic()
        left = list(self.tests)
        boots = 0
        with open(os.path.join(self.dir, "log"), "ab") as log:
            while left:
                boots += 1
                log.write(f"ltp-boot: {boots}\n".encode())
                log.flush()
                done, current, how = self.boot(left, log)
                if current is None and not done:
                    # The kernel did not reach the first test. The tests cannot run.
                    for _, tag, _ in left:
                        log.write(f"\nltp-result: {tag} noboot\n".encode())
                    break
                rest = [t for t in left if t[1] not in done]
                if current is not None:
                    log.write(f"\nltp-result: {current} {how}\n".encode())
                    rest = [t for t in rest if t[1] != current]
                elif rest and how == "exit":
                    # The init script stopped before the end of the list.
                    log.write(f"\nltp-result: {rest[0][1]} crash\n".encode())
                    rest = rest[1:]
                left = rest
        with open(os.path.join(self.dir, "done"), "w") as f:
            f.write(f"{int(time.monotonic() - start)} s, {boots} boots\n")
        return f"{self.name}: {len(self.tests)} tests, {boots} boots, {int(time.monotonic() - start)} s"


def main():
    p = argparse.ArgumentParser(description="Runs LTP runtest files on rukernel under QEMU.")
    p.add_argument("--kernel", required=True, help="the kernel ELF file")
    p.add_argument("--ltp", required=True, help="the LTP tree of build.sh --full")
    p.add_argument("--busybox", required=True, help="a static BusyBox program")
    p.add_argument("--out", default="runs", help="the directory of the batches")
    p.add_argument("--image", help="the ext4 image of the LTP tree (OUT/ltp.img)")
    p.add_argument("--ip", help="a static `ip` program of iproute2, for the tests of the network "
                   "that need veth and netns")
    p.add_argument("--batch", type=int, default=60, help="the number of tests in a batch")
    p.add_argument("--jobs", type=int, default=2, help="the number of QEMU at the same time")
    p.add_argument("--timeout", type=int, default=240, help="the time limit of a test in seconds")
    p.add_argument("--boot-timeout", type=int, default=300, help="the time limit of a boot")
    p.add_argument("--mul", default="4", help="LTP_TIMEOUT_MUL")
    p.add_argument("--memory", default="1G")
    p.add_argument("--smp", type=int, default=1)
    p.add_argument("--only", help="run only these tags, with a comma between them, or @FILE with "
                   "a tag on each line")
    p.add_argument("--first", type=int, default=1, help="the number of the first batch of each "
                   "runtest file, for example 101 for a second run that keeps the logs of the first")
    p.add_argument("--force", action="store_true", help="run the batches that are done again")
    p.add_argument("groups", nargs="+")
    a = p.parse_args()
    a.out = os.path.abspath(a.out)
    a.kernel = os.path.abspath(a.kernel)
    a.busybox = os.path.abspath(a.busybox)
    a.ip = a.ip and os.path.abspath(a.ip)
    os.makedirs(a.out, exist_ok=True)
    a.image = os.path.abspath(a.image or os.path.join(a.out, "ltp.img"))
    make_image(a.ltp, a.image)

    tests = runtests(a.ltp, a.groups)
    if a.only:
        if a.only.startswith("@"):
            with open(a.only[1:]) as f:
                only = set(f.read().split())
        else:
            only = set(a.only.split(","))
        tests = [t for t in tests if t[1] in only]
    batches = []
    by_file = {}
    for t in tests:
        by_file.setdefault(t[0], []).append(t)
    for name, ts in by_file.items():
        for i in range(0, len(ts), a.batch):
            batches.append(Batch(a, f"{name}-{i // a.batch + a.first:03}", ts[i:i + a.batch]))
    print(f"ltp: {len(tests)} tests in {len(batches)} batches", file=sys.stderr)
    lock = threading.Lock()
    with concurrent.futures.ThreadPoolExecutor(a.jobs) as pool:
        for msg in pool.map(lambda b: b.run(), batches):
            with lock:
                print(msg, file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()

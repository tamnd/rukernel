#!/usr/bin/env python3
"""Runs tests/shell of the nftables project on rukernel or on a Linux reference kernel under QEMU.

Usage: tools/nftables/run.py --kernel FILE --root DIR [options] [TEST...]

DIR of --root is the root file system of `tools/nftables/build.sh` (OUT_DIR/root). A TEST is a
test file or a directory under tests/shell, for example testcases/sets. Without a TEST, all the
tests of testcases run.

The script splits the tests in batches. Each batch boots the kernel in QEMU, with the root file
system, the list of the tests and an init script as the initramfs. The script runs the tests one
after the other. Each test is one run of `run-tests.sh` of nftables, which runs the test in its
own network and mount namespace, and gives its result. A test has a time limit. When the time is
over, the script kills all the processes of the test, so one test that hangs does not stop the
batch.

The serial output of a batch goes to OUT/NAME-NNN/log. Each test gives these lines:

    nft-start: TEST
    nft-out: LINE          (the last lines of the output of a test that does not pass)
    nft-result: TEST RESULT

RESULT is `ok`, `skipped`, `failed`, `dump-fail` (the rule set after the test is not the same as
the dump file of the test), `chk-dump`, `tainted`, `timeout`, or `error` when run-tests.sh gave
no result. When the kernel stops (a panic) or hangs during a test, this script writes the result
`panic` or `hang` for the test, and boots again with the next test. report.py reads these lines.

--linux-modules DIR is for a Linux reference kernel that has nf_tables as modules, as the kernel
of a distribution. DIR is /lib/modules/VERSION of that kernel. The script puts the modules of
the network, the libraries and the crypto code of DIR, and the drivers of drivers/net, in the
initramfs without their zstd compression. Init runs depmod, and modprobe of kmod loads a module
when the kernel asks for it.

--arch aarch64 runs an arm64 kernel and the arm64 root file system (`build.sh --arch aarch64`) on
the QEMU `virt` machine. --kernel is then the kernel ELF file or its `Image`.
"""

import argparse
import concurrent.futures
import importlib.util
import os
import select
import stat
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
# The cpio writer and the arm64 Image of tools/ltp/run.py.
_spec = importlib.util.spec_from_file_location("ltp_run", os.path.join(HERE, "..", "ltp", "run.py"))
ltp_run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ltp_run)
cpio, arm64_image = ltp_run.cpio, ltp_run.arm64_image

# The script that runs as init. It reads the tests from /tests, one test on each line: the test
# and its time limit in seconds, with a tab between them.
INIT = r"""#!/bin/sh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
mkdir -p /dev/pts /dev/shm /run /tmp
mount -t devpts devpts /dev/pts 2>/dev/null
mount -t tmpfs shm /dev/shm
mount -t tmpfs tmp /tmp
mount -t tmpfs run /run
[ -e /dev/fd ] || ln -s /proc/self/fd /dev/fd
# The tests read rule sets from /dev/stdin, as udev makes it on a distribution.
[ -e /dev/stdin ] || ln -s /proc/self/fd/0 /dev/stdin
[ -e /dev/stdout ] || ln -s /proc/self/fd/1 /dev/stdout
[ -e /dev/stderr ] || ln -s /proc/self/fd/2 /dev/stderr
mkdir -p /run/netns
ip link set lo up 2>/dev/null
m=/lib/modules/$(uname -r)
if [ -d $m/kernel ]; then
    depmod -a
    modprobe nf_tables
fi
echo "nft-ready"
cd /nftables/tests/shell
# The tests run one after the other, so run-tests.sh does not shuffle them. With one job it does
# not unload the modules after each test.
export NFT=/usr/sbin/nft NFT_TEST_SHUFFLE_TESTS=n NFT_TEST_JOBS=1 TERM=dumb
have=
while IFS='	' read -r test limit; do
    echo "nft-start: $test"
    rm -f /run-timeout /run-pid
    (
        trap 'kill $s 2>/dev/null; exit 0' TERM
        sleep $limit & s=$!
        wait $s
        echo > /run-timeout
        read p < /run-pid && kill -KILL -$p 2>/dev/null
    ) &
    dog=$!
    # The test runs in its own session, which has the number of its shell.
    env $have setsid sh -c "echo \$\$ > /run-pid; exec ./run-tests.sh -v $test" </dev/null >/run-out 2>&1
    pid=
    read pid < /run-pid 2>/dev/null
    kill $dog 2>/dev/null
    wait $dog 2>/dev/null
    [ -n "$pid" ] && kill -KILL -$pid 2>/dev/null
    # The result is the last status in brackets, as "[OK]" or "[DUMP FAIL]", without the colors.
    sed 's/\x1b\[[0-9;]*[A-Za-z]//g' /run-out > /run-plain
    status=$(sed -n 's/^[IW]: \[\([A-Z ]*\)\].*/\1/p' /run-plain | grep -v EXECUTING | tail -n 1)
    status=$(echo $status | tr 'A-Z ' 'a-z-')
    [ -n "$status" ] || status=error
    [ -e /run-timeout ] && status=timeout
    case $status in
    ok|skipped) ;;
    *) grep -v '^I: conf: \|^I: info: \|^$' /run-plain | tail -n 40 | sed 's/^/nft-out: /' ;;
    esac
    # The probes of the features of the first run are the same for the next runs.
    [ -n "$have" ] || have=$(sed -n 's/^I: conf: \(NFT_TEST_HAVE_[A-Za-z0-9_]*=[yn]\)$/\1/p' /run-plain | tr '\n' ' ')
    printf '\nnft-result: %s %s\n' "$test" "$status"
    rm -rf /tmp/* 2>/dev/null
done < /tests
echo "nft-done"
if [ -d $m/kernel ]; then
    poweroff -f
fi
"""

# The directories of /lib/modules/VERSION that --linux-modules puts in the initramfs.
MODULE_DIRS = ("kernel/net", "kernel/lib", "kernel/crypto", "kernel/arch/x86/crypto")


def tree(root, prefix=""):
    """Gives the cpio entries of the directories, files and symbolic links under `root`, with
    their modes and with the paths relative to `root` under `prefix`."""
    entries = []
    for d, dirs, files in os.walk(root):
        dirs.sort()
        rel = os.path.normpath(os.path.join(prefix, os.path.relpath(d, root)))
        if rel != ".":
            entries.append((rel, stat.S_IFDIR | 0o755, b""))
        for name in sorted(files) + sorted(n for n in dirs if os.path.islink(os.path.join(d, n))):
            path = os.path.join(d, name)
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode):
                data = os.readlink(path).encode()
            elif stat.S_ISREG(st.st_mode):
                with open(path, "rb") as f:
                    data = f.read()
            else:
                continue
            entries.append((os.path.normpath(os.path.join(rel, name)), st.st_mode, data))
    return entries


def modules(src, version):
    """Gives the cpio entries of the modules of --linux-modules, without the zstd compression."""
    entries = []
    base = f"lib/modules/{version}"
    seen = set()

    def mkdirs(rel):
        parts = rel.split("/")
        for i in range(1, len(parts) + 1):
            p = "/".join(parts[:i])
            if p not in seen:
                seen.add(p)
                entries.append((p, stat.S_IFDIR | 0o755, b""))

    def add(path):
        rel = os.path.relpath(path, src)
        data = open(path, "rb").read() if not path.endswith(".zst") else subprocess.run(
            ["zstd", "-dcq", path], check=True, stdout=subprocess.PIPE).stdout
        rel = rel.removesuffix(".zst")
        mkdirs(f"{base}/{os.path.dirname(rel)}")
        entries.append((f"{base}/{rel}", stat.S_IFREG | 0o644, data))

    for sub in MODULE_DIRS:
        for d, dirs, files in os.walk(os.path.join(src, sub)):
            dirs.sort()
            for name in sorted(files):
                add(os.path.join(d, name))
    net = os.path.join(src, "kernel/drivers/net")
    for name in sorted(os.listdir(net)):
        if os.path.isfile(os.path.join(net, name)):
            add(os.path.join(net, name))
    for name in ("modules.builtin", "modules.builtin.modinfo", "modules.order"):
        if os.path.exists(os.path.join(src, name)):
            add(os.path.join(src, name))
    return entries


def find_tests(root, args):
    """Gives the test files of `args` under tests/shell, as run-tests.sh finds them: the
    executable files, in the order of their names."""
    shell = os.path.join(root, "nftables/tests/shell")
    tests = []
    for a in args or ["testcases"]:
        path = os.path.join(shell, a)
        if os.path.isfile(path):
            tests.append(os.path.normpath(a))
            continue
        if not os.path.isdir(path):
            sys.exit(f"run.py: no test {a}")
        for d, dirs, files in os.walk(path):
            for name in files:
                p = os.path.join(d, name)
                if os.access(p, os.X_OK):
                    tests.append(os.path.relpath(p, shell))
    return sorted(set(tests))


class Batch:
    """A batch of tests that runs in one directory, with as many boots as it needs."""

    def __init__(self, a, name, tests, base):
        self.a = a
        self.name = name
        self.tests = tests
        self.base = base
        self.dir = os.path.join(a.out, name)

    def boot(self, tests, log):
        """Boots once with the tests. Gives the tests with a result, the test that ran when the
        boot stopped (or None), and the way that the boot stopped."""
        lst = "".join(f"{t}\t{self.a.timeout}\n" for t in tests)
        initrd = os.path.join(self.dir, "initrd.cpio")
        with open(initrd, "wb") as f:
            f.write(cpio(self.base + [
                ("init", 0o100755, INIT.encode()),
                ("tests", 0o100644, lst.encode()),
            ]))
        if self.a.arch == "aarch64":
            cmd = [
                "qemu-system-aarch64", "-machine", "virt,gic-version=3", "-cpu", "cortex-a72",
                "-accel", "tcg", "-global", "virtio-mmio.force-legacy=false",
            ]
            console = "ttyAMA0"
        else:
            cmd = [
                "qemu-system-x86_64", "-machine", "q35",
                "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
            ]
            if os.access("/dev/kvm", os.R_OK | os.W_OK):
                cmd += ["-accel", "kvm", "-cpu", "host"]
            else:
                cmd += ["-accel", "tcg", "-cpu", "max"]
            console = "ttyS0"
        append = f"console={console} rdinit=/init"
        if self.a.linux_modules:
            # A panic of Linux reboots at once, and -no-reboot then stops QEMU.
            append += " panic=-1 quiet"
        else:
            append += " rk.test=init"
        cmd += [
            "-m", self.a.memory, "-smp", str(self.a.smp),
            "-display", "none", "-serial", "stdio", "-no-reboot", "-monitor", "none",
            # The tests make their own interfaces, veth and dummy, so the machine has no NIC.
            "-nic", "none",
            "-kernel", self.a.kernel, "-initrd", initrd, "-append", append,
        ]
        for d in self.a.bios_dir or []:
            cmd += ["-L", d]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL)
        done, current, how = set(), None, "exit"
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
                    if "nft-start: " in line:
                        current = line.split("nft-start: ", 1)[1].strip()
                        since, limit = time.monotonic(), self.a.timeout + 120
                    elif "nft-result: " in line:
                        done.add(line.split("nft-result: ", 1)[1].split()[0])
                        current = None
                        since, limit = time.monotonic(), self.a.timeout + 120
                    elif line == "nft-done":
                        since, limit = time.monotonic(), 30
                    elif "kernel panic" in line.lower() and not line.startswith("nft-"):
                        how = "panic"
            elif time.monotonic() - since > limit:
                if current is not None:
                    how = "hang"
                p.kill()
                break
        p.wait()
        os.remove(initrd)
        return done, current, how

    def run(self):
        if os.path.exists(os.path.join(self.dir, "done")) and not self.a.force:
            return f"{self.name}: done before"
        os.makedirs(self.dir, exist_ok=True)
        with open(os.path.join(self.dir, "tests"), "w") as f:
            f.write("".join(f"{t}\n" for t in self.tests))
        start = time.monotonic()
        left = list(self.tests)
        boots = 0
        with open(os.path.join(self.dir, "log"), "wb") as log:
            while left:
                boots += 1
                log.write(f"nft-boot: {boots}\n".encode())
                log.flush()
                done, current, how = self.boot(left, log)
                if current is None and not done:
                    # The kernel did not reach the first test. The tests cannot run.
                    for t in left:
                        log.write(f"\nnft-result: {t} noboot\n".encode())
                    break
                rest = [t for t in left if t not in done]
                if current is not None:
                    log.write(f"\nnft-result: {current} {how}\n".encode())
                    rest = [t for t in rest if t != current]
                elif rest:
                    # The init script stopped before the end of the list.
                    log.write(f"\nnft-result: {rest[0]} crash\n".encode())
                    rest = rest[1:]
                left = rest
        secs = int(time.monotonic() - start)
        with open(os.path.join(self.dir, "done"), "w") as f:
            f.write(f"{secs} s, {boots} boots\n")
        return f"{self.name}: {len(self.tests)} tests, {boots} boots, {secs} s"


def main():
    p = argparse.ArgumentParser(description="Runs tests/shell of nftables under QEMU.")
    p.add_argument("--kernel", required=True, help="the kernel ELF file, a bzImage or an arm64 Image")
    p.add_argument("--arch", choices=["x86_64", "aarch64"], default="x86_64")
    p.add_argument("--root", required=True, help="the root file system of build.sh (OUT_DIR/root)")
    p.add_argument("--linux-modules", help="/lib/modules/VERSION of a Linux reference kernel")
    p.add_argument("--out", default="runs", help="the directory of the batches")
    p.add_argument("--name", help="the name of the batches, `rk` or `ref` by default")
    p.add_argument("--batch", type=int, default=100, help="the number of tests in a batch")
    p.add_argument("--jobs", type=int, default=2, help="the number of QEMU at the same time")
    p.add_argument("--timeout", type=int, default=300, help="the time limit of a test in seconds")
    p.add_argument("--boot-timeout", type=int, default=300, help="the time limit of a boot")
    p.add_argument("--memory", default="1G")
    p.add_argument("--smp", type=int, default=1)
    p.add_argument("--bios-dir", action="append", help="a directory of the firmware files of "
                   "QEMU (-L), for a QEMU that is not in its install directory")
    p.add_argument("--force", action="store_true", help="run the batches that are done again")
    p.add_argument("tests", nargs="*")
    a = p.parse_args()
    a.out = os.path.abspath(a.out)
    a.kernel = os.path.abspath(a.kernel)
    os.makedirs(a.out, exist_ok=True)
    if a.arch == "aarch64":
        a.kernel = arm64_image(a.kernel, os.path.join(a.out, "Image"))
    name = a.name or ("ref" if a.linux_modules else "rk")
    base = [(".", stat.S_IFDIR | 0o755, b"")] + tree(a.root)
    if a.linux_modules:
        src = os.path.abspath(a.linux_modules)
        base += modules(src, os.path.basename(src))
    tests = find_tests(a.root, a.tests)
    batches = [Batch(a, f"{name}-{i // a.batch + 1:03}", tests[i:i + a.batch], base)
               for i in range(0, len(tests), a.batch)]
    print(f"nft: {len(tests)} tests in {len(batches)} batches", file=sys.stderr)
    lock = threading.Lock()
    with concurrent.futures.ThreadPoolExecutor(a.jobs) as pool:
        for msg in pool.map(lambda b: b.run(), batches):
            with lock:
                print(msg, file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()

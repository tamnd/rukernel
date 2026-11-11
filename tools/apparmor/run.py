#!/usr/bin/env python3
"""Loads the AppArmor profiles of Ubuntu and runs the AppArmor regression tests on rukernel or on
a Linux reference kernel under QEMU.

Usage: tools/apparmor/run.py --kernel FILE --root DIR [options] [TEST...]

DIR of --root is the root file system of `tools/apparmor/build.sh` (OUT_DIR/root). A TEST is the
name of a test of tests/regression/apparmor without `.sh`, for example `changehat`, or
`profiles`. Without a TEST, `profiles` and all the tests of OUT_DIR/root/apparmor/TESTS run.

`profiles` is the test of the profiles of Ubuntu. It loads /etc/apparmor.d with
`apparmor_parser -r -K`, lists the profiles with `aa-status`, and removes them again. It passes
when the parser gives 0, `aa-status` gives 0, and `aa-status` and
/sys/kernel/security/apparmor/profiles give the same number of profiles.

Each other test is one run of `VERBOSE=1 bash TEST.sh` in tests/regression/apparmor, as
`make tests` runs it. With --complain (the default), the tests load their profiles with
`apparmor_parser -C`, so all the profiles are in complain mode. --enforce loads them as the tests
give them.

The script splits the tests in batches. Each batch boots the kernel in QEMU, with the root file
system, the list of the tests and an init script as the initramfs. The init script runs the tests
one after the other. A test has a time limit. When the time is over, the script kills all the
processes of the test, so one test that hangs does not stop the batch.

The serial output of a batch goes to OUT/NAME-NNN/log. Each test gives these lines:

    aa-start: TEST
    aa-out: LINE           (the output of the test)
    aa-result: TEST RESULT

RESULT is `pass` (the test gives 0), `skip` (the test gives 0 and says that it skips its checks,
because the kernel or the parser does not have a feature), `fail` (the test gives an other code),
or `timeout`. After a `timeout` the script boots again for the next tests, because a task
that hangs in the kernel can hold a lock that the next tests need. When the kernel stops (a panic) or hangs during a test, this script writes the
result `panic` or `hang` for the test, and boots again with the next test. report.py reads these
lines.

--linux is for a Linux reference kernel, for example the kernel of the distribution of the host.
The kernel must have AppArmor built in.

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


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, "..", path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# The arm64 Image of tools/ltp/run.py.
arm64_image = _load("ltp_run", "ltp/run.py").arm64_image

TESTS_DIR = "apparmor/tests/regression/apparmor"

# The script that runs as init. It reads the tests from /tests, one test on each line: the test
# and its time limit in seconds, with a tab between them.
INIT = r"""#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys 2>/dev/null
mount -t securityfs securityfs /sys/kernel/security 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
mkdir -p /dev/pts /dev/shm /run /tmp
mount -t devpts devpts /dev/pts 2>/dev/null
mount -t tmpfs shm /dev/shm
mount -t tmpfs tmp /tmp
mount -t tmpfs run /run
[ -e /dev/fd ] || ln -s /proc/self/fd /dev/fd
[ -e /dev/stdin ] || ln -s /proc/self/fd/0 /dev/stdin
[ -e /dev/stdout ] || ln -s /proc/self/fd/1 /dev/stdout
[ -e /dev/stderr ] || ln -s /proc/self/fd/2 /dev/stderr
ip link set lo up 2>/dev/null
echo "aa-ready: $(uname -r) $(cat /sys/kernel/security/lsm 2>/dev/null)"
cd /apparmor/tests/regression/apparmor
# The tests read the arguments of the parser from uservars.inc. -C loads each profile in
# complain mode.
if [ -e /complain ]; then
    sed -i 's/^parser_args="\(.*\)"$/parser_args="\1 -C"/' uservars.inc
fi
while IFS='	' read -r test limit; do
    echo "aa-start: $test"
    rm -f /run-timeout /run-pid
    (
        trap 'kill $s 2>/dev/null; exit 0' TERM
        sleep $limit & s=$!
        wait $s
        echo > /run-timeout
        read p < /run-pid && kill -KILL -$p 2>/dev/null
    ) &
    dog=$!
    if [ "$test" = profiles ]; then
        cmd=/profiles
    else
        cmd="env VERBOSE=1 bash $test.sh"
    fi
    # The test runs in its own session, which has the number of its shell. Its output goes
    # to the console at once, so the output before a hang is there too.
    setsid -w bash -c "echo \$\$ > /run-pid; exec $cmd" </dev/null 2>&1 | tee /run-out |
        sed -u 's/^/aa-out: /'
    rc=${PIPESTATUS[0]}
    pid=
    read pid < /run-pid 2>/dev/null
    kill $dog 2>/dev/null
    wait $dog 2>/dev/null
    [ -n "$pid" ] && kill -KILL -$pid 2>/dev/null
    if [ -e /run-timeout ]; then
        status=timeout
    elif [ $rc -ne 0 ]; then
        status=fail
    elif grep -q 'Skipping tests\|Skipping test' /run-out; then
        status=skip
    else
        status=pass
    fi
    printf '\naa-result: %s %s\n' "$test" "$status"
    # A test that fails can leave its profiles. The next test starts with no profiles.
    sed 's/ ([a-z]*)$//' /sys/kernel/security/apparmor/profiles 2>/dev/null | while read -r p; do
        printf '%s' "$p" > /sys/kernel/security/apparmor/.remove 2>/dev/null
    done
    rm -rf /tmp/* /tmp/.[!.]* 2>/dev/null
done < /tests
echo "aa-done"
"""

# The test `profiles`: the load of the profiles of Ubuntu, as apparmor.service, and aa-status.
PROFILES = r"""#!/bin/bash
fs=/sys/kernel/security/apparmor
apparmor_parser -r -K /etc/apparmor.d
parser=$?
echo "parser: $parser"
loaded=$(wc -l < $fs/profiles)
echo "profiles: $loaded"
sort $fs/profiles | sed 's/^/profile: /'
aa-status
status=$?
echo "aa-status: $status"
listed=$(aa-status --profiled)
echo "aa-status --profiled: $listed"
echo "aa-status --enforced: $(aa-status --enforced)"
echo "aa-status --complaining: $(aa-status --complaining)"
sed 's/ ([a-z]*)$//' $fs/profiles | while read -r p; do
    printf '%s' "$p" > $fs/.remove 2>/dev/null
done
echo "profiles after the remove: $(wc -l < $fs/profiles)"
[ $parser -eq 0 ] && [ $status -eq 0 ] && [ "$loaded" -gt 0 ] && [ "$listed" = "$loaded" ]
"""


def tree(root):
    """Gives the cpio entries of the directories, files and symbolic links under `root`, with
    their modes and with the paths relative to `root`, as tools/nftables/run.py. An entry is
    (name, mode, data, link). The files with more than one link have the same `link`, and only
    the first of them has the data. The coreutils of Ubuntu 26.04 is one program of 11 MB with
    a hard link for each command, and it checks that the name of the link is the command."""
    entries, links = [], {}
    for d, dirs, files in os.walk(root):
        dirs.sort()
        rel = os.path.normpath(os.path.relpath(d, root))
        if rel != ".":
            entries.append((rel, stat.S_IFDIR | 0o755, b"", None))
        for name in sorted(files) + sorted(n for n in dirs if os.path.islink(os.path.join(d, n))):
            path = os.path.join(d, name)
            at = os.path.normpath(os.path.join(rel, name))
            st = os.lstat(path)
            link = None
            if stat.S_ISLNK(st.st_mode):
                data = os.readlink(path).encode()
            elif stat.S_ISREG(st.st_mode):
                if st.st_nlink > 1:
                    link = (st.st_dev, st.st_ino)
                    if link in links:
                        links[link] += 1
                        entries.append((at, st.st_mode, b"", link))
                        continue
                    links[link] = 1
                with open(path, "rb") as f:
                    data = f.read()
            else:
                continue
            entries.append((at, st.st_mode, data, link))
    return entries


def cpio(entries):
    """Gives a cpio archive in the newc format, as tools/ltp/run.py, with the hard links of
    tree(): the entries of a link have the same inode number and the number of links."""
    count, inos = {}, {}
    for e in entries:
        if e[3] is not None:
            count[e[3]] = count.get(e[3], 0) + 1
    out = bytearray()
    for n, (name, mode, data, link) in enumerate(entries + [("TRAILER!!!", 0, b"", None)], 1):
        ino = inos.setdefault(link, n) if link is not None else n
        nlink = count[link] if link is not None else 1
        name = name.encode() + b"\0"
        fields = [ino, mode, 0, 0, nlink, 0, len(data), 0, 0, 0, 0, len(name), 0]
        out += b"070701" + b"".join(b"%08x" % f for f in fields) + name
        out += b"\0" * (-len(out) % 4) + data
        out += b"\0" * (-len(out) % 4)
    return bytes(out)


def find_tests(root, args):
    """Gives the tests of `args`, or `profiles` and the tests of `make tests` of build.sh."""
    if args:
        for t in args:
            if t != "profiles" and not os.path.isfile(os.path.join(root, TESTS_DIR, t + ".sh")):
                sys.exit(f"run.py: no test {t}")
        return list(args)
    with open(os.path.join(root, "apparmor/TESTS")) as f:
        return ["profiles"] + [t.strip() for t in f if t.strip()]


class Batch:
    """A batch of tests that runs in one directory, with as many boots as it needs."""

    def __init__(self, a, name, tests, base):
        self.a = a
        self.name = name
        self.tests = tests
        self.base = base
        self.dir = os.path.join(a.out, name)

    def limit(self, test):
        """The time limit of `test` in seconds."""
        return self.a.profiles_timeout if test == "profiles" else self.a.timeout

    def boot(self, tests, log):
        """Boots once with the tests. Gives the tests with a result, the test that ran when the
        boot stopped (or None), and the way that the boot stopped."""
        lst = "".join(f"{t}\t{self.limit(t)}\n" for t in tests)
        extra = [("init", 0o100755, INIT.encode(), None),
                 ("profiles", 0o100755, PROFILES.encode(), None),
                 ("tests", 0o100644, lst.encode(), None)]
        if not self.a.enforce:
            extra.append(("complain", 0o100644, b"", None))
        initrd = os.path.join(self.dir, "initrd.cpio")
        with open(initrd, "wb") as f:
            f.write(cpio(self.base + extra))
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
        if self.a.linux:
            # A panic of Linux reboots at once, and -no-reboot then stops QEMU. `quiet` keeps
            # the audit records of AppArmor out of the console. Under QEMU with no KVM and a
            # busy host, the check of the timer of the IO-APIC can fail and panic, so
            # `no_timer_check` skips it.
            append += " panic=-1 quiet no_timer_check apparmor=1 security=apparmor"
        else:
            append += " rk.test=init apparmor=1"
        if self.a.append:
            append += " " + self.a.append
        cmd += [
            "-m", self.a.memory, "-smp", str(self.a.smp),
            "-display", "none", "-serial", "stdio", "-no-reboot", "-monitor", "none",
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
                    if how == "restart":
                        break
                    line = raw.decode(errors="replace").strip()
                    if line.startswith("aa-out: "):
                        continue
                    if "aa-start: " in line:
                        current = line.split("aa-start: ", 1)[1].strip()
                        since, limit = time.monotonic(), self.limit(current) + 120
                    elif "aa-result: " in line:
                        test, status = (line.split("aa-result: ", 1)[1].split() + [""])[:2]
                        done.add(test)
                        current = None
                        since, limit = time.monotonic(), self.a.timeout + 120
                        if status == "timeout" and test != tests[-1]:
                            # A task of the test can stay in the kernel with a lock, as the
                            # learning profile of change_hat of Linux 6.8 in complain mode.
                            # The next tests then hang too. Boot again for them.
                            how = "restart"
                            p.kill()
                            break
                    elif line == "aa-done":
                        since, limit = time.monotonic(), 30
                    elif "kernel panic" in line.lower() and current is not None:
                        how = "panic"
                    elif "blocked for more than" in line and current is not None:
                        # A task of the test hangs in the kernel, as the learning profile of
                        # change_hat of Linux 6.8 in complain mode, which waits for a lock
                        # that its caller holds. The test cannot end.
                        how = "hang"
                        p.kill()
                        break
                if how in ("restart", "hang"):
                    break
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
        boots = noboots = 0
        with open(os.path.join(self.dir, "log"), "wb") as log:
            while left:
                boots += 1
                log.write(f"aa-boot: {boots}\n".encode())
                log.flush()
                done, current, how = self.boot(left, log)
                if current is None and not done:
                    # The kernel did not reach the first test. Try 3 times, then the tests
                    # cannot run.
                    noboots += 1
                    if noboots < 3:
                        continue
                    for t in left:
                        log.write(f"\naa-result: {t} noboot\n".encode())
                    break
                noboots = 0
                rest = [t for t in left if t not in done]
                if current is not None:
                    log.write(f"\naa-result: {current} {how}\n".encode())
                    rest = [t for t in rest if t != current]
                elif rest and how != "restart":
                    # The init script stopped before the end of the list.
                    log.write(f"\naa-result: {rest[0]} crash\n".encode())
                    rest = rest[1:]
                left = rest
        secs = int(time.monotonic() - start)
        with open(os.path.join(self.dir, "done"), "w") as f:
            f.write(f"{secs} s, {boots} boots\n")
        return f"{self.name}: {len(self.tests)} tests, {boots} boots, {secs} s"


def main():
    p = argparse.ArgumentParser(description="Runs the AppArmor regression tests under QEMU.")
    p.add_argument("--kernel", required=True, help="the kernel ELF file, a bzImage or an arm64 Image")
    p.add_argument("--arch", choices=["x86_64", "aarch64"], default="x86_64")
    p.add_argument("--root", required=True, help="the root file system of build.sh (OUT_DIR/root)")
    p.add_argument("--linux", action="store_true", help="the kernel is a Linux reference kernel")
    p.add_argument("--enforce", action="store_true", help="load the profiles of the tests as "
                   "they are, not in complain mode")
    p.add_argument("--out", default="runs", help="the directory of the batches")
    p.add_argument("--name", help="the name of the batches, `rk` or `ref` by default")
    p.add_argument("--batch", type=int, default=100, help="the number of tests in a batch")
    p.add_argument("--jobs", type=int, default=2, help="the number of QEMU at the same time")
    p.add_argument("--timeout", type=int, default=600, help="the time limit of a test in seconds")
    p.add_argument("--profiles-timeout", type=int, default=3600, help="the time limit of the "
                   "test `profiles` in seconds: the parser compiles about 160 profiles")
    p.add_argument("--boot-timeout", type=int, default=900, help="the time limit of a boot")
    p.add_argument("--append", help="more arguments for the command line of the kernel")
    p.add_argument("--memory", default="2G")
    p.add_argument("--smp", type=int, default=2)
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
    name = a.name or ("ref" if a.linux else "rk")
    base = [(".", stat.S_IFDIR | 0o755, b"", None)] + tree(a.root)
    tests = find_tests(a.root, a.tests)
    batches = [Batch(a, f"{name}-{i // a.batch + 1:03}", tests[i:i + a.batch], base)
               for i in range(0, len(tests), a.batch)]
    print(f"aa: {len(tests)} tests in {len(batches)} batches", file=sys.stderr)
    lock = threading.Lock()
    with concurrent.futures.ThreadPoolExecutor(a.jobs) as pool:
        for msg in pool.map(lambda b: b.run(), batches):
            with lock:
                print(msg, file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Runs the network tests of systemd on rukernel or on a Linux reference kernel under QEMU.

The tests are test/test-network/systemd-networkd-tests.py (the TEST-85-NETWORK integration test
of systemd) and the TEST-75-RESOLVED integration test. They come from the package systemd-tests
of the tree of tools/systemd/build.sh. networkd.md in this directory tells how to make the tree
and has the results.

Usage:
  nettest.py cpio --tree TARBALL --out CPIO [--modules DIR]
  nettest.py run --kernel KERNEL --initrd CPIO --log LOG [--arch ARCH] [--linux]
                 [--classes A,B] [--t75] [--t75-skip X,Y] [--journal N] [--timeout S]
                 [--mem M] [--qemu-dir D] [--icount]
  nettest.py report [-v] [--col NAME=LOG,...] [--diff] [LOG...]

`cpio` writes an initramfs of the tree, with an init script that boots systemd. The service
rk-nettest of the tree runs the tests of the kernel command line, prints the output on the
console and stops the machine. --modules DIR adds the network modules of a Linux kernel from
DIR, /lib/modules/VERSION of that kernel. The modules of a kernel package of the tree also stay.

`run` boots KERNEL with QEMU and writes the console to LOG. --classes gives the test classes of
systemd-networkd-tests.py, `all` for all of them. --t75 runs TEST-75-RESOLVED. TEST-75 stops at
its first test case that fails, so --t75-skip gives the test cases to skip for a second run.
--linux is for a Linux kernel: the command line has no options of rukernel. On arm64, KERNEL is
an arm64 `Image`. --qemu-dir is the directory of a QEMU that is not installed.
--icount makes the clock of the guest count the instructions.

`report` gives the result of each test from the logs of `run`. --col gives markdown tables
with one column for each kernel, and --diff keeps only the tests with different results.
"""

import argparse
import gzip
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import time

# The parts of the module tree of a Linux kernel that the tests can load. The other modules
# (hardware drivers, sound, file systems) only make the initramfs larger.
MODULE_DIRS = (
    "kernel/net/",
    "kernel/lib/",
    "kernel/crypto/",
    "kernel/arch/x86/crypto/",
    "kernel/arch/arm64/crypto/",
    "kernel/drivers/net/",
    "kernel/drivers/virtio/",
    "kernel/drivers/block/virtio_blk",
)

# The parts of drivers/net that are hardware drivers.
MODULE_SKIP = (
    "kernel/drivers/net/ethernet/",
    "kernel/drivers/net/wireless/",
    "kernel/drivers/net/usb/",
    "kernel/drivers/net/can/",
    "kernel/drivers/net/wwan/",
    "kernel/drivers/net/ieee802154/",
    "kernel/drivers/net/hamradio/",
    "kernel/drivers/net/fddi/",
    "kernel/drivers/net/hyperv/",
    "kernel/drivers/net/xen-netback/",
    "kernel/drivers/net/vmxnet3/",
    "kernel/drivers/net/arcnet/",
    "kernel/drivers/net/plip/",
    "kernel/net/wireless/",
    "kernel/net/mac80211/",
    "kernel/net/bluetooth/",
)

# The files of the tree that the tests do not use. The kernel and the device trees of a kernel
# package of the tree are not necessary, because QEMU loads the kernel.
TREE_SKIP = re.compile(
    r"^(usr/share/(doc|man|info|locale|i18n|zoneinfo-icu)/|boot/|usr/lib/linux-image-[^/]+/|"
    r"var/cache/|var/lib/apt/lists/)"
)

INIT = r"""#!/bin/sh
set -e
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
rm -f /.dockerenv
mods=/usr/lib/modules/$(uname -r)
if [ -d "$mods" ]; then
    depmod -a
else
    # rukernel has no loadable modules and no /proc/modules, as Linux without CONFIG_MODULES.
    # modules.builtin names the drivers that are in the kernel, so `modprobe` of one of them
    # succeeds. The test script runs lsmod to see if a module is loaded, and here lsmod gives the
    # empty list of Linux.
    mkdir -p "$mods" /usr/local/sbin
    printf "%s\n" kernel/drivers/net/veth.ko kernel/drivers/net/dummy.ko kernel/drivers/net/tun.ko \
        kernel/net/dns_resolver/dns_resolver.ko kernel/net/netfilter/nf_tables.ko \
        kernel/net/ipv4/netfilter/ip_tables.ko kernel/net/ipv6/netfilter/ip6_tables.ko \
        > "$mods/modules.builtin"
    : > "$mods/modules.order"
    depmod -a
    cat > /usr/local/sbin/lsmod << 'END'
#!/bin/sh
[ -e /proc/modules ] || { echo "Module                  Size  Used by"; exit 0; }
exec /usr/sbin/lsmod "$@"
END
    chmod 755 /usr/local/sbin/lsmod
fi
# Under QEMU without KVM on a busy host, a unit can need more than the 90 s of the default to
# start. The tests do not use the default timeouts.
mkdir -p /etc/systemd/system.conf.d
printf "[Manager]\nDefaultTimeoutStartSec=900\nDefaultTimeoutStopSec=300\n" \
    > /etc/systemd/system.conf.d/rk-nettest.conf
cat > /etc/systemd/system/rk-nettest.service << 'END'
[Unit]
Description=The systemd network tests of rukernel
After=multi-user.target

[Service]
Type=simple
# Under QEMU without KVM on a busy host, a D-Bus call such as `systemctl daemon-reload` can take
# more than the 25 s of the default.
Environment=SYSTEMD_BUS_TIMEOUT=600
ExecStart=/usr/local/bin/rk-nettest
StandardOutput=tty
StandardError=tty
TTYPath=/dev/console
END
mkdir -p /etc/systemd/system/multi-user.target.wants /usr/local/bin /usr/lib/tests
ln -sf ../rk-nettest.service /etc/systemd/system/multi-user.target.wants/rk-nettest.service
# The services of the test servers start only when the tests start them.
for unit in knot isc-dhcp-server isc-dhcp-server6 radvd; do
    rm -f /etc/systemd/system/multi-user.target.wants/$unit.service /etc/rc?.d/S??$unit
done
# The image of the integration tests of systemd has the user 4711 and test-ndisc-send in
# /usr/lib/tests.
id testuser > /dev/null 2>&1 || useradd -m -u 4711 -U testuser
ndisc=/usr/lib/systemd/tests/unit-tests/manual/test-ndisc-send
[ ! -e $ndisc ] || ln -sf $ndisc /usr/lib/tests/test-ndisc-send
cat > /usr/local/bin/rk-nettest << 'END'
#!/bin/bash
state=$(systemctl is-system-running --wait)
echo "rk-nettest: state $state"
echo "rk-nettest: kernel $(uname -r)"
classes=
t75=
t75skip=
journal=
for word in $(cat /proc/cmdline); do
    case $word in
    rk.nwd=*) classes=${word#rk.nwd=} ;;
    rk.t75=*) t75=${word#rk.t75=} ;;
    rk.t75skip=*) t75skip=${word#rk.t75skip=} ;;
    rk.journal=*) journal=${word#rk.journal=} ;;
    esac
done
data=/usr/lib/systemd/tests/testdata
for unit in $(systemctl list-units --failed --no-legend --plain | awk '{print $1}'); do
    echo "rk-nettest: failed unit $unit"
done
# The test script makes a dummy link when it starts. Show if the kernel can do that.
{
    modprobe dummy && echo "modprobe dummy ok"
    ip link add rkprobe0 type dummy && ip link del rkprobe0 && echo "dummy link ok"
} 2>&1 | sed 's/^/rk-nettest: probe: /'
if [ "$classes" = all ]; then
    classes=$(sed -n 's/^class \([A-Za-z0-9]*\)(unittest.TestCase.*/\1/p' \
        $data/test-network/systemd-networkd-tests.py | tr '\n' ,)
fi
if [ -n "$journal" ]; then
    # With rk.journal, the journal of networkd and udevd comes at once, and each 30 s the state
    # and the system call of each thread of networkd and udevd, to see where they wait.
    journalctl -b -f --no-pager -o short-monotonic -u systemd-networkd -u systemd-udevd |
        sed -u "s/^/rk-nettest: live: /" &
    # The log of dnsmasq, the DHCP server of the tests, comes at once too.
    tail -n 0 -F /run/networkd-ci/test-dnsmasq.log 2>/dev/null | sed -u "s/^/rk-nettest: dnsmasq: /" &
    while sleep 30; do
        for p in $(pgrep -x systemd-network) $(pgrep -x "systemd-udevd|udevadm"); do
            for t in /proc/$p/task/*; do
                echo "$p ${t##*/} $(cut -d' ' -f3 $t/stat) $(cat $t/syscall)"
            done
        done 2>&1 | sed "s/^/rk-nettest: watch: $(cut -d' ' -f1 /proc/loadavg) /"
    done &
fi
for class in ${classes//,/ }; do
    echo "rk-nettest: class $class: start"
    SYSTEMD_PAGER= python3 -u $data/test-network/systemd-networkd-tests.py --no-journal $class 2>&1 |
        sed -u "s/^/rk-nettest: $class: /"
    echo "rk-nettest: class $class: exit ${PIPESTATUS[0]}"
    # rk.journal=N prints the last N lines of the journal of networkd and udevd.
    [ -z "$journal" ] || journalctl -b --no-pager -o short-monotonic -u systemd-networkd \
        -u systemd-udevd | tail -n "$journal" | sed "s/^/rk-nettest: journal: /"
done
if [ -n "$t75" ]; then
    echo "rk-nettest: TEST-75-RESOLVED: start"
    rm -f /testok /failed /skipped
    systemd-run --wait --pipe --unit=TEST-75-RESOLVED.service -p Type=oneshot \
        -p MemoryAccounting=no -E SYSTEMD_PAGER= -E "TEST_SKIP_TESTCASES=${t75skip//,/ }" \
        $data/units/TEST-75-RESOLVED.sh 2>&1 | sed -u 's/^/rk-nettest: TEST-75-RESOLVED: /'
    status=${PIPESTATUS[0]}
    [ ! -e /testok ] || echo "rk-nettest: TEST-75-RESOLVED: testok"
    [ ! -e /skipped ] || sed 's/^/rk-nettest: TEST-75-RESOLVED: skipped: /' /skipped
    echo "rk-nettest: TEST-75-RESOLVED: exit $status"
    # rk.journal=N prints the last N lines of the journal of resolved after a failure.
    if [ -n "$journal" ] && [ "$status" != 0 ]; then
        journalctl -b --no-pager -o short-monotonic -u systemd-resolved | tail -n "$journal" \
            > /tmp/rk-journal.txt 2>&1
        sed "s/^/rk-nettest: journal: /" /tmp/rk-journal.txt
    fi
fi
echo "rk-nettest: done"
systemctl poweroff
END
chmod 755 /usr/local/bin/rk-nettest
exec /usr/lib/systemd/systemd
"""


class Cpio:
    """Writes a newc cpio archive to a file."""

    def __init__(self, out):
        self.out = out
        self.ino = 1

    def add(self, name, mode, data=b"", uid=0, gid=0, mtime=0, ino=None, nlink=1):
        if ino is None:
            ino = self.ino
            self.ino += 1
        name = name.encode() + b"\0"
        fields = (ino, mode, uid, gid, nlink, int(mtime), len(data), 0, 0, 0, 0, len(name), 0)
        head = b"070701" + b"".join(b"%08x" % f for f in fields)
        self.out.write(head + name + b"\0" * (-(len(head) + len(name)) % 4))
        self.out.write(data + b"\0" * (-len(data) % 4))

    def finish(self):
        self.add("TRAILER!!!", 0)


def module_wanted(rel):
    """Tells if the cpio has the file `rel` of a module tree, a path after lib/modules/VERSION/."""
    if not rel.startswith("kernel/"):
        return True
    # The directories above a wanted directory stay. An initramfs does not make them.
    if any(d.startswith(rel.rstrip("/") + "/") for d in MODULE_DIRS):
        return True
    return rel.startswith(MODULE_DIRS) and not rel.startswith(MODULE_SKIP)


def tree_wanted(name):
    if TREE_SKIP.match(name):
        return False
    m = re.match(r"^(usr/)?lib/modules/[^/]+/(.*)$", name)
    return m is None or module_wanted(m.group(2))


def cmd_cpio(a):
    # The first pass finds the files that have hard links. The first entry of a group has the
    # data, and the others have the same inode number and no data, as Linux and rk-vfs read them.
    links = {}
    with tarfile.open(a.tree, "r:gz") as t:
        for m in t:
            if m.islnk():
                links.setdefault(m.linkname.removeprefix("./"), []).append(m.name)
    with open(a.out, "wb") as f, tarfile.open(a.tree, "r|gz") as t:
        w = Cpio(f)
        w.add(".", 0o040755)
        inos = {}
        for m in t:
            name = m.name.removeprefix("./").rstrip("/") if m.name not in (".", "./") else ""
            if not name or not tree_wanted(name):
                continue
            perm = m.mode & 0o7777
            if m.isdir():
                w.add(name, 0o040000 | perm, uid=m.uid, gid=m.gid, mtime=m.mtime)
            elif m.issym():
                w.add(name, 0o120000 | 0o777, m.linkname.encode(), m.uid, m.gid, m.mtime)
            elif m.islnk():
                target = m.linkname.removeprefix("./")
                if target in inos:
                    ino, nlink = inos[target]
                    w.add(name, 0o100000 | perm, b"", m.uid, m.gid, m.mtime, ino, nlink)
            elif m.isreg():
                data = t.extractfile(m).read()
                if name in links:
                    ino = w.ino
                    w.ino += 1
                    nlink = len(links[name]) + 1
                    inos[name] = (ino, nlink)
                    w.add(name, 0o100000 | perm, data, m.uid, m.gid, m.mtime, ino, nlink)
                else:
                    w.add(name, 0o100000 | perm, data, m.uid, m.gid, m.mtime)
            elif m.ischr() or m.isblk() or m.isfifo():
                pass
        if a.modules:
            src = os.path.abspath(a.modules)
            base = "usr/lib/modules/" + os.path.basename(src)
            # A tree without a kernel has no usr/lib/modules, and the archive must make it first.
            w.add("usr/lib/modules", 0o040755)
            w.add(base, 0o040755)
            for root, dirs, files in os.walk(src):
                dirs.sort()
                rel = os.path.relpath(root, src)
                rel = "" if rel == "." else rel + "/"
                if rel and not module_wanted(rel):
                    dirs[:] = []
                    continue
                if rel:
                    w.add(f"{base}/{rel}".rstrip("/"), 0o040755)
                for fn in sorted(files):
                    if not module_wanted(rel + fn) or (not rel and fn.startswith("modules.") and
                                                       fn not in ("modules.builtin",
                                                                  "modules.builtin.modinfo",
                                                                  "modules.order")):
                        continue
                    with open(os.path.join(root, fn), "rb") as src_file:
                        w.add(f"{base}/{rel}{fn}", 0o100644, src_file.read())
        w.add("init", 0o100755, INIT.encode())
        w.finish()
    print(f"cpio: {a.out}: {os.path.getsize(a.out) >> 20} MiB")


def qemu_command(a, cmdline):
    if a.arch == "x86_64":
        console = "ttyS0"
        prog = "qemu-system-x86_64"
        machine = ["-machine", "q35", "-cpu", "max"]
        nic = "virtio-net-pci,netdev=n0"
    else:
        console = "ttyAMA0"
        prog = "qemu-system-aarch64"
        machine = ["-M", "virt,gic-version=3,its=on", "-cpu", "cortex-a72",
                   "-global", "virtio-mmio.force-legacy=false"]
        nic = "virtio-net-device,netdev=n0"
    env = dict(os.environ)
    extra = []
    if a.qemu_dir:
        prog = os.path.join(a.qemu_dir, prog)
        env["LD_LIBRARY_PATH"] = os.path.join(a.qemu_dir, "lib")
        env["QEMU_MODULE_DIR"] = os.path.join(a.qemu_dir, "qemu")
        extra = ["-L", os.path.join(a.qemu_dir, "share/qemu"),
                 "-L", os.path.join(a.qemu_dir, "share/seabios")]
        nic += ",romfile="
    cmd = [prog, *machine, *extra, "-m", a.mem, "-smp", "1", "-display", "none",
           "-serial", "stdio", "-monitor", "none", "-no-reboot", "-accel", "tcg",
           "-kernel", a.kernel, "-initrd", a.initrd, "-append", f"console={console} {cmdline}",
           "-netdev", "user,id=n0", "-device", nic]
    if a.arch == "x86_64":
        cmd += ["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
    # With --icount, the clock of the guest counts the instructions, as in the systemd boot test
    # of xtask. The load of the host then does not change the time that the guest sees, but TCG
    # is much slower.
    if a.icount:
        cmd += ["-icount", "shift=0,sleep=off"]
    return cmd, env


def cmd_run(a):
    words = ["rdinit=/init", "systemd.firstboot=no"]
    if not a.linux:
        words.insert(0, "rk.test=init")
    if a.classes:
        words.append(f"rk.nwd={a.classes}")
    if a.t75:
        words.append("rk.t75=1")
    if a.t75_skip:
        words.append(f"rk.t75skip={a.t75_skip}")
    if a.journal:
        words.append(f"rk.journal={a.journal}")
    # The init of the current script replaces the init of the cpio. Linux and rk-vfs read
    # concatenated archives, and a later entry replaces an earlier one.
    initrd = a.log + ".initrd"
    with open(initrd, "wb") as out, open(a.initrd, "rb") as base:
        shutil.copyfileobj(base, out, 1 << 20)
        w = Cpio(out)
        w.add("init", 0o100755, INIT.encode())
        w.finish()
    a.initrd = initrd
    cmd, env = qemu_command(a, " ".join(words))
    start = time.time()
    with open(a.log, "wb") as log:
        log.write(("rk-nettest-run: " + " ".join(cmd) + "\n").encode())
        log.flush()
        p = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL, stdout=log,
                             stderr=subprocess.STDOUT)
        timer = threading.Timer(a.timeout, p.kill)
        timer.start()
        status = p.wait()
        timer.cancel()
        end = f"rk-nettest-run: exit {status} after {int(time.time() - start)} s\n"
        log.write(end.encode())
    os.unlink(initrd)
    print(end, end="")


# The states of the result lines of unittest, as `test_x (__main__.Class.test_x) ... ok`.
STATES = {"ok": "pass", "FAIL": "fail", "ERROR": "error", "expected failure": "xfail",
          "unexpected success": "xpass"}


def parse(path):
    """Gives the results of a log: {test: state}, and the classes that did not end."""
    results = {}
    started, ended = set(), set()
    pending = {}
    with open(path, errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            m = re.match(r"^rk-nettest: class ([\w.]+): (start|exit)", line)
            if m:
                (started if m.group(2) == "start" else ended).add(m.group(1))
                continue
            # The prefix is the argument of the run: a class, or a class and a test.
            m = re.match(r"^rk-nettest: ([\w.]+): (test_\w+) \(__main__\.(\w+)\.\w+\)(.*)$", line)
            if m:
                arg, test, cls, rest = m.groups()
                key = f"{cls}.{test}"
                state = rest.rsplit("... ", 1)[-1].strip() if "... " in rest else ""
                if state.startswith("skipped"):
                    results[key] = "skip"
                elif state in STATES:
                    results[key] = STATES[state]
                else:
                    pending[arg] = key
                continue
            # A test with subtests has no state on its line. The summary of the class has a
            # line for each subtest that failed, as `FAIL: test_x (__main__.Class.test_x) (a=1)`.
            m = re.match(r"^rk-nettest: [\w.]+: (FAIL|ERROR): (test_\w+) \(__main__\.(\w+)\.", line)
            if m:
                key = f"{m.group(3)}.{m.group(2)}"
                old, state = results.get(key), STATES[m.group(1)]
                if old in (None, "pass", "fail"):
                    results[key] = "error" if "error" in (old, state) else state
                continue
            m = re.match(
                r"^rk-nettest: ([\w.]+): "
                r"(ok|FAIL|ERROR|expected failure|unexpected success|skipped.*)$",
                line,
            )
            if m and m.group(1) in pending:
                state = m.group(2)
                state = "skip" if state.startswith("skipped") else STATES[state]
                results[pending.pop(m.group(1))] = state
            m = re.match(r"^rk-nettest: TEST-75-RESOLVED: (testok|exit \d+)", line)
            if m:
                results.setdefault("TEST-75-RESOLVED", "pass" if m.group(1) == "testok" else "fail")
            m = re.match(
                r"^rk-nettest: TEST-75-RESOLVED: \++ : '\+\+\+ (testcase_\w+) (BEGIN|END)", line
            )
            if m:
                state = "fail" if m.group(2) == "BEGIN" else "pass"
                results[f"TEST-75-RESOLVED.{m.group(1)}"] = state
    for cls, key in pending.items():
        results[key] = "timeout" if cls not in ended else "fail"
    return results, started - ended


def merge(paths):
    """Merges the results of the logs of one kernel. A later log wins."""
    results = {}
    for path in paths:
        results.update(parse(path)[0])
    return results


def cmd_report(a):
    if not a.col:
        for path in a.logs:
            results, unfinished = parse(path)
            counts = {}
            for state in results.values():
                counts[state] = counts.get(state, 0) + 1
            print(f"{path}: {counts}" + (f" unfinished {sorted(unfinished)}" if unfinished else ""))
            if a.verbose:
                for key in sorted(results):
                    print(f"{key} {results[key]}")
        return
    # Markdown tables: one column for each kernel. A column is NAME=LOG[,LOG...].
    cols = []
    for col in a.col:
        name, logs = col.split("=", 1)
        cols.append((name, merge(logs.split(","))))
    keys = sorted(set().union(*(r.keys() for _, r in cols)))
    classes = sorted({k.split(".")[0] for k in keys if "." in k})
    print("| Class | " + " | ".join(f"{n} pass" for n, _ in cols) + " | Tests |")
    print("|---|" + "---|" * (len(cols) + 1))
    for cls in classes + ["All"]:
        # The key TEST-75-RESOLVED is the result of the whole test, not a test case.
        ks = [k for k in keys if "." in k and (cls == "All" or k.split(".")[0] == cls)]
        cells = [str(sum(1 for k in ks if r.get(k) == "pass")) for _, r in cols]
        print(f"| {cls} | " + " | ".join(cells) + f" | {len(ks)} |")
    print()
    print("| Test | " + " | ".join(n for n, _ in cols) + " |")
    print("|---|" + "---|" * len(cols))
    for k in keys:
        states = [r.get(k, "not run") for _, r in cols]
        if a.diff and len(set(states)) == 1:
            continue
        print(f"| {k} | " + " | ".join(states) + " |")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("cpio")
    c.add_argument("--tree", required=True)
    c.add_argument("--out", required=True)
    c.add_argument("--modules")
    r = sub.add_parser("run")
    r.add_argument("--kernel", required=True)
    r.add_argument("--initrd", required=True)
    r.add_argument("--log", required=True)
    r.add_argument("--arch", default="x86_64", choices=("x86_64", "aarch64"))
    r.add_argument("--linux", action="store_true")
    r.add_argument("--classes")
    r.add_argument("--t75", action="store_true")
    r.add_argument("--t75-skip")
    r.add_argument(
        "--journal",
        type=int,
        help="print the last N lines of the journal of networkd and udevd after each class",
    )
    r.add_argument("--timeout", type=int, default=6 * 3600)
    r.add_argument("--mem", default="2G")
    r.add_argument("--qemu-dir")
    r.add_argument("--icount", action="store_true")
    s = sub.add_parser("report")
    s.add_argument("logs", nargs="*")
    s.add_argument("-v", "--verbose", action="store_true")
    s.add_argument(
        "--col", action="append", help="NAME=LOG[,LOG...]: a column of the markdown tables"
    )
    s.add_argument("--diff", action="store_true", help="list only the tests with different results")
    a = p.parse_args()
    {"cpio": cmd_cpio, "run": cmd_run, "report": cmd_report}[a.cmd](a)


if __name__ == "__main__":
    main()

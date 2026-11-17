#!/usr/bin/env python3
"""Runs integration tests of systemd (test/units/TEST-*.sh) on rukernel or on a Linux reference
kernel under QEMU, and makes the table of the results.

Usage: tools/systemd/integration.py --tree FILE --kernel FILE --busybox FILE --out DIR [options] TEST...
       tools/systemd/integration.py --report LOG...

FILE of --tree is a tarball of tools/systemd/build.sh of Debian, with these packages in
RK_SYSTEMD_PACKAGES:

    systemd-tests systemd-oomd stress-ng systemd-container dbus-user-session libpam-systemd
    iproute2 iputils-ping strace attr util-linux procps socat ncat

systemd-tests has the tests in /usr/lib/systemd/tests/testdata/units. A TEST is the name of a
test, for example TEST-07-PID1. For each test, the script makes an ext4 image of the tree in DIR
with mkfs.ext4 (as root, or in fakeroot), and boots the kernel once in QEMU with the image as the
root file system. TEST-55-OOMD makes a swap file on the root file system, and Linux cannot swap
to a file of the tmpfs of an initramfs, so the root is a disk for each test. The initramfs has
BusyBox only: its init mounts /dev/vda, and starts systemd on it with switch_root. The serial
output goes to DIR/TEST.log.

The script sets up the test as test/integration-test-wrapper.py of systemd does for a test in a
VM that is not interactive:

  - The kernel command line has `systemd.unit=TEST.service`, and the other options of the
    wrapper. The init of the initramfs sets SYSTEMD_UNIT_PATH, as rukernel does not give the
    words of the kernel command line with `=` to init in its environment.
  - The drop-in of the test unit has `SuccessAction=exit`, `FailureAction=exit` and
    `StandardOutput=journal+console`, and emergency.target stops the machine.
  - The image has the user `testuser` with the UID 4711 and the drop-ins of user@.service, as the
    image of mkosi of systemd, and for TEST-55-OOMD the drop-in of init.scope of
    test/integration-tests/TEST-55-OOMD.
  - The journal is volatile.

With --modules, the image also has the modules of a Linux kernel, so that the reference kernel
can load modules such as veth, as the image of mkosi does. rukernel has no modules.

An `ExecStopPost=` command of the test unit writes the result to the console:

    rk-it: result TEST SERVICE_RESULT EXIT_CODE EXIT_STATUS testok|no-testok

test-control.sh of systemd stops a test at the first subtest or test case that fails. The image
has a test-control.sh that runs all of them, and fails at the end if one failed, so that one boot
gives the result of each one. TEST_MATCH_SUBTEST and TEST_MATCH_TESTCASE of test-control.sh come
from --match-subtest and --match-testcase.

The test passes if the test made /testok and the service result is `success`, or the service
stopped with SIGTERM. After it makes /testok, the test runs `systemctl --no-block exit 123`, and
the stop of the system can stop the service with SIGTERM before it exits. The test is skipped if
the exit status is 77. The results of the subtests and the test cases of test-control.sh come
from the trace of bash on the console. A subtest or a test case that starts and does not end is a
failure.

--report reads the logs, and writes a Markdown table of the results.
"""

import argparse
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
# The cpio writer and the arm64 Image of tools/ltp/run.py.
_spec = importlib.util.spec_from_file_location("ltp_run", os.path.join(HERE, "..", "ltp", "run.py"))
ltp_run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ltp_run)

TESTDATA = "/usr/lib/systemd/tests/testdata"

# The init of the initramfs. It mounts the root disk and starts systemd on it.
INIT = r"""#!/bin/busybox sh
/bin/busybox mkdir -p /usr/bin /usr/sbin /sbin /newroot
/bin/busybox --install -s
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs dev /dev
echo "rk-it: kernel $(uname -r)"
if ! mount -t ext4 /dev/vda /newroot; then
    echo "rk-it: cannot mount /dev/vda"
    exit 1
fi
umount /dev /sys /proc
export SYSTEMD_UNIT_PATH=@UNIT_PATH@
exec switch_root /newroot /usr/lib/systemd/systemd
"""

# The options of the kernel command line from integration-test-wrapper.py.
CMDLINE = (
    "systemd.hostname=H systemd.unit={test}.service "
    "systemd.mask=systemd-networkd-wait-online.service systemd.mask=serial-getty@.service "
    "systemd.show_status=error systemd.crash_shell=0 systemd.crash_action=poweroff loglevel=6"
)

DROPIN = """\
[Service]
StandardOutput=journal+console
ExecStopPost=/usr/local/bin/rk-it-result {test}

[Unit]
SuccessAction=exit
SuccessActionExitStatus=123
FailureAction=exit
"""

# As EMERGENCY_EXIT_SERVICE and EMERGENCY_EXIT_DROPIN of integration-test-wrapper.py.
EMERGENCY_EXIT = """\
[Unit]
DefaultDependencies=no
Conflicts=shutdown.target
Conflicts=rescue.service
Before=shutdown.target
Before=rescue.service
FailureAction=exit

[Service]
ExecStart=false
"""

# Writes the result of the test unit, and the last warnings of the journal if the test failed.
RESULT = r"""#!/bin/sh
ok=no-testok
[ -e /testok ] && ok=testok
{
echo "rk-it: result $1 $SERVICE_RESULT $EXIT_CODE $EXIT_STATUS $ok"
if [ "$ok" = no-testok ]; then
    journalctl -b -q --no-pager -o short-monotonic -p warning | tail -n 80 | sed 's/^/rk-it: log: /'
fi
} > /dev/console 2>&1
"""

# The functions to add at the end of test-control.sh. They replace run_subtests and run_testcases
# of test-control.sh, which stop at the first subtest or test case that fails. These run all of
# them, and fail at the end if one failed, so that one boot gives the result of each one.
CONTROL = r"""
# rk-it: run all the subtests and test cases.
run_subtests() {
    local subtests=("${0%.sh}".*.sh) subtest failed=0
    for subtest in "${subtests[@]}"; do
        if [[ -n "${TEST_MATCH_SUBTEST:-}" ]] && ! [[ "$subtest" =~ $TEST_MATCH_SUBTEST ]]; then
            continue
        fi
        for skip in ${TEST_SKIP_SUBTESTS:-}; do
            if [[ "$subtest" =~ $skip ]]; then
                echo "Skipping $subtest (matching '$skip')"
                continue 2
            fi
        done
        : "--- $subtest BEGIN ---"
        SECONDS=0
        if ! "./$subtest"; then
            echo "Subtest $subtest failed"
            failed=1
            continue
        fi
        : "--- $subtest END (${SECONDS}s) ---"
    done
    return $failed
}

run_testcases() {
    local testcase testcases failed=0
    mapfile -t testcases < <(declare -F | awk '$3 ~ /^testcase_/ {print $3;}')
    for testcase in "${testcases[@]}"; do
        if [[ -n "${TEST_MATCH_TESTCASE:-}" ]] && ! [[ "$testcase" =~ $TEST_MATCH_TESTCASE ]]; then
            continue
        fi
        for skip in ${TEST_SKIP_TESTCASES:-}; do
            if [[ "$testcase" =~ $skip ]]; then
                continue 2
            fi
        done
        : "+++ $testcase BEGIN +++"
        # In the background, so that `set -e` stays on in the subshell.
        ("$testcase") &
        if ! wait $!; then
            echo "Testcase $testcase failed"
            failed=1
            continue
        fi
        : "+++ $testcase END +++"
    done
    return $failed
}
"""

# The drop-in of init.scope of test/integration-tests/TEST-55-OOMD in systemd. TEST-55-OOMD.sh
# checks that memory.high of init.scope is not `max`.
INIT_SCOPE = """\
[Scope]
MemoryHigh=infinity
StartupMemoryHigh=10G
"""

# Makes the image. It runs as root or in fakeroot, so that the files of the tree keep their
# owners.
IMAGE = r"""set -eu
root=$1 tree=$2 stage=$3 img=$4 size=$5 modules=${6:-}
rm -rf "$root"
mkdir "$root"
tar -xzf "$tree" -C "$root"
rm -f "$root/.dockerenv"
cp -R "$stage/files/." "$root/"
(cd "$stage/files" && find . -print) | (cd "$root" && xargs chown -h 0:0)
for f in "$stage"/append/*; do
    name=$(basename "$f" | tr + /)
    cat "$f" >> "$root/$name"
done
if [ -n "$modules" ]; then
    mkdir -p "$root/usr/lib/modules"
    cp -R "$modules" "$root/usr/lib/modules/"
    chown -R -h 0:0 "$root/usr/lib/modules"
fi
mkdir -p "$root/home/testuser"
chown 4711:4711 "$root/home/testuser"
chmod 700 "$root/home/testuser"
rm -f "$img"
truncate -s "$size" "$img"
mkfs.ext4 -q -F -L rkroot -d "$root" "$img"
rm -rf "$root"
"""


def stage(a, test, d):
    """Writes the files to add to the tree in d/files, and the lines to add to files of the tree
    in d/append, with `+` for `/` in the names."""
    dropin = DROPIN.format(test=test)
    for var, value in (("TEST_MATCH_SUBTEST", a.match_subtest),
                       ("TEST_MATCH_TESTCASE", a.match_testcase)):
        if value:
            # systemd reads C escapes and specifiers in Environment=, so a backslash, a quote
            # and a percent sign of the pattern need an escape.
            value = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
            dropin += f'\n[Service]\nEnvironment="{var}={value}"\n'
    files = {
        f"etc/systemd/system/{test}.service.d/50-rk-it.conf": dropin,
        "etc/systemd/system/emergency-exit.service": EMERGENCY_EXIT,
        "etc/systemd/system/emergency.target.d/50-rk-it.conf": "[Unit]\nWants=emergency-exit.service\n",
        "etc/systemd/journald.conf.d/50-rk-it.conf": "[Journal]\nStorage=volatile\n",
        "usr/local/bin/rk-it-result": RESULT,
        "etc/hostname": "H\n",
        # As mkosi/mkosi.extra of systemd: the user manager of TEST-55-OOMD finds the test units
        # with SYSTEMD_UNIT_PATH.
        "usr/lib/systemd/system/user@.service.d/99-SYSTEMD_UNIT_PATH.conf":
            "[Service]\nPassEnvironment=SYSTEMD_UNIT_PATH\n",
        "usr/lib/systemd/system/user@.service.d/fdstore.conf":
            "[Service]\nFileDescriptorStoreMax=20\nFileDescriptorStorePreserve=yes\n",
    }
    if test == "TEST-55-OOMD":
        files["etc/systemd/system/init.scope.d/50-rk-it.conf"] = INIT_SCOPE
    for name, text in files.items():
        path = os.path.join(d, "files", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
        os.chmod(path, 0o755 if "/bin/" in name else 0o644)
    append = {
        "etc/passwd": "testuser:x:4711:4711:Test User:/home/testuser:/bin/bash\n",
        "etc/group": "testuser:x:4711:\n",
        "etc/shadow": "testuser:!:20000::::::\n",
        "etc/gshadow": "testuser:!::\n",
        TESTDATA.lstrip("/") + "/units/test-control.sh": CONTROL,
    }
    os.makedirs(os.path.join(d, "append"))
    for name, text in append.items():
        with open(os.path.join(d, "append", name.replace("/", "+")), "w") as f:
            f.write(text)


def make_image(a, test, img):
    with tempfile.TemporaryDirectory(dir=a.out) as d:
        stage(a, test, d)
        script = os.path.join(d, "image.sh")
        with open(script, "w") as f:
            f.write(IMAGE)
        cmd = ["sh", script, os.path.join(d, "root"), a.tree, d, img, a.disk_size, a.modules]
        if os.geteuid() != 0:
            cmd = ["fakeroot"] + cmd
        subprocess.run(cmd, check=True)


def initramfs(a, test, path):
    with open(a.busybox, "rb") as f:
        busybox = f.read()
    unit_path = f"{TESTDATA}/{test}.units:{TESTDATA}/units:"
    entries = [(".", 0o040755, b"")]
    entries += [(d, 0o040755, b"") for d in ("bin", "proc", "sys", "dev", "newroot")]
    entries += [
        ("bin/busybox", 0o100755, busybox),
        ("bin/sh", 0o120777, b"busybox"),
        ("init", 0o100755, INIT.replace("@UNIT_PATH@", unit_path).encode()),
    ]
    with open(path, "wb") as f:
        f.write(ltp_run.cpio(entries))


def boot(a, test):
    img = os.path.join(a.out, f"{test}{a.tag}.img")
    log = os.path.join(a.out, f"{test}{a.tag}.log")
    initrd = os.path.join(a.out, f"{test}{a.tag}.cpio")
    make_image(a, test, img)
    initramfs(a, test, initrd)
    kernel = a.kernel
    if a.arch == "aarch64":
        kernel = ltp_run.arm64_image(a.kernel, initrd + ".Image")
        cmd = ["qemu-system-aarch64", "-machine", "virt,gic-version=3", "-cpu", "cortex-a72",
               "-accel", "tcg", "-global", "virtio-mmio.force-legacy=false"]
        console = "ttyAMA0"
    else:
        cmd = ["qemu-system-x86_64", "-machine", "q35", "-accel", "tcg", "-cpu", "max",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
        console = "ttyS0"
    append = f"console={console} rk.test=init rdinit=/init " + CMDLINE.format(test=test)
    if a.linux:
        # Linux checks the timer of the IO-APIC at boot, and the check can fail under TCG when the
        # host is busy.
        append += " panic=-1 no_timer_check"
    if a.append:
        append += " " + a.append
    cmd += [
        "-m", a.memory, "-smp", str(a.smp), "-display", "none", "-serial", "stdio",
        "-no-reboot", "-monitor", "none", "-nic", "none",
        "-kernel", kernel, "-initrd", initrd, "-append", append,
        "-drive", f"if=none,id=root,format=raw,cache=unsafe,file={img}",
        "-device", "virtio-blk-pci,drive=root",
    ]
    start = time.monotonic()
    try:
        with open(log, "wb") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                           timeout=a.timeout)
    except subprocess.TimeoutExpired:
        with open(log, "ab") as f:
            f.write(b"\nrk-it: timeout\n")
    with open(log, "ab") as f:
        f.write(f"\nrk-it: time {int(time.monotonic() - start)} s\n".encode())
    os.remove(initrd)
    if kernel != a.kernel:
        os.remove(kernel)
    if not a.keep:
        os.remove(img)
    name, results = read_log(log)
    print(f"{test}: {name}: {results[test]['result']}")


# The lines of test-control.sh in the output of the test on the console, after the name of the
# process: the trace of bash (`set -x`), and the lines that it writes.
MARKS = [
    (re.compile(r"\+ : '--- (\S+) BEGIN ---'"), "subtest", "start"),
    (re.compile(r"\+ : '--- (\S+) END "), "subtest", "pass"),
    (re.compile(r"\]: Subtest (\S+) failed\s*$"), "subtest", "fail"),
    (re.compile(r"\]: Skipping (\S+) \(matching"), "subtest", "skip"),
    (re.compile(r"\+ : '\+\+\+ (\S+) BEGIN \+\+\+'"), "testcase", "start"),
    (re.compile(r"\+ : '\+\+\+ (\S+) END \+\+\+'"), "testcase", "pass"),
    (re.compile(r"\]: Testcase (\S+) failed\s*$"), "testcase", "fail"),
]


def read_log(path):
    """Gives the kernel name of a log, and for each test its result and its subtests and test
    cases. The journal is volatile and can lose the start of a long test, so the subtests and the
    test cases come from the console."""
    kernel, tests, subtest, subs = "rukernel", {}, None, {}
    with open(path, errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            for mark, kind, result in MARKS:
                m = mark.search(line)
                if not m:
                    continue
                name = m.group(1)
                if kind == "subtest":
                    # /usr/lib/.../TEST-07-PID1.exec-context.sh is exec-context.
                    name = os.path.basename(name).split(".", 1)[-1].removesuffix(".sh")
                    if result == "start":
                        subtest = name
                elif subtest:
                    name = f"{subtest} {name}"
                subs[name] = result
                break
            if "rk-it: " not in line:
                continue
            words = line.split("rk-it: ", 1)[1].split()
            if not words:
                continue
            if words[0] == "kernel" and len(words) > 1 and "rukernel" not in words[1]:
                kernel = f"Linux {words[1]}"
            elif words[0] == "result" and len(words) >= 6:
                service, status, ok = words[2], words[4], words[5]
                if status == "77":
                    result = "skip"
                elif ok == "testok" and (service == "success" or status == "TERM"):
                    result = "pass"
                else:
                    result = f"fail ({service}, {status})"
                tests[words[1]] = {"result": result}
    name = os.path.basename(path).split(".")[0]
    entry = tests.setdefault(name, {"result": "no result (timeout or crash)"})
    entry["subtests"] = subs
    return kernel, tests


def report(logs):
    columns, rows = [], {}
    for path in logs:
        kernel, tests = read_log(path)
        if kernel not in columns:
            columns.append(kernel)
        for test, r in tests.items():
            rows.setdefault((test, ""), {})[kernel] = r["result"]
            for sub, res in r["subtests"].items():
                if res == "start":
                    res = "fail"
                rows.setdefault((test, sub), {})[kernel] = res
    out = ["| Test | Subtest or test case | " + " | ".join(columns) + " |",
           "| --- | --- |" + " --- |" * len(columns)]
    for (test, sub), by in sorted(rows.items()):
        out.append(f"| {test} | {sub or '(all)'} | " + " | ".join(by.get(c, "-") for c in columns) + " |")
    print("\n".join(out))


def main():
    p = argparse.ArgumentParser(description="Runs integration tests of systemd under QEMU.")
    p.add_argument("--tree", help="the tarball of tools/systemd/build.sh")
    p.add_argument("--kernel", help="the kernel ELF file, or a Linux bzImage or Image")
    p.add_argument("--busybox", help="a static BusyBox program for the initramfs")
    p.add_argument("--out", help="the directory of the images and the logs")
    p.add_argument("--arch", choices=["x86_64", "aarch64"], default="x86_64")
    p.add_argument("--linux", action="store_true", help="the kernel is a Linux reference kernel")
    p.add_argument("--memory", default="2G")
    p.add_argument("--smp", type=int, default=2)
    p.add_argument("--disk-size", default="3G")
    p.add_argument("--timeout", type=int, default=3600, help="the time limit of a boot in seconds")
    p.add_argument("--modules", default="",
                   help="a directory of modules of the kernel, as /lib/modules/VERSION, to copy to "
                   "the image")
    p.add_argument("--keep", action="store_true", help="keep the images")
    p.add_argument("--append", default="",
                   help="more parameters for the kernel command line, as systemd.log_level=debug")
    p.add_argument("--match-subtest", help="run only the subtests that match, as TEST_MATCH_SUBTEST")
    p.add_argument("--match-testcase",
                   help="run only the test cases that match, as TEST_MATCH_TESTCASE")
    p.add_argument("--tag", default="", help="a text to add to the names of the logs")
    p.add_argument("--report", action="store_true", help="make the table from the logs")
    p.add_argument("tests", nargs="+")
    a = p.parse_args()
    if a.report:
        report(a.tests)
        return
    if not (a.tree and a.kernel and a.busybox and a.out):
        sys.exit("integration: --tree, --kernel, --busybox and --out are needed")
    for tool in ("mkfs.ext4", "fakeroot" if os.geteuid() else "tar"):
        if not shutil.which(tool):
            sys.exit(f"integration: {tool} is not there")
    a.kernel, a.tree, a.busybox = map(os.path.abspath, (a.kernel, a.tree, a.busybox))
    if a.modules:
        a.modules = os.path.abspath(a.modules)
    os.makedirs(a.out, exist_ok=True)
    a.out = os.path.abspath(a.out)
    for test in a.tests:
        boot(a, test)


if __name__ == "__main__":
    main()

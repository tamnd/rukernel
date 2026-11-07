#!/usr/bin/env python3
"""Makes the report of tests/shell of nftables from the logs of the runs of run.py.

Usage: tools/nftables/report.py --logs DIR [--out FILE]

DIR of --logs has one directory for each batch of run.py, and each batch directory has the file
`log`, the serial output of the virtual machine. The name of a batch gives the kernel:

- `ref-NNN`: the Linux reference kernel.
- `rk-NNN`: rukernel on x86_64.
- `rk-arm64-NNN`: rukernel on arm64.

The script keeps the newest result of each test for each kernel. It writes the report to FILE,
by default report.md next to the script: the number of the tests that pass for each directory of
testcases, the tests that pass on Linux and not on rukernel, and the result of each test. Do not
change the report by hand, because the next run of the script writes it again.
"""

import argparse
import datetime
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
TEST_URL = "https://git.netfilter.org/nftables/tree/tests/shell/{}?h=v{}"
RESULT = re.compile(r"nft-result: (\S+) (\S+)")
OUT = re.compile(r"nft-out: (.*)")
KERNELS = ("ref", "rk", "rk-arm64")
TITLES = {"ref": "Linux", "rk": "rukernel x86_64", "rk-arm64": "rukernel arm64"}
# The words of the results of run.py in the report.
WORDS = {
    "ok": "pass", "skipped": "skip", "failed": "fail", "dump-fail": "dump differs",
    "chk-dump": "no dump", "tainted": "tainted", "timeout": "timeout", "error": "error",
    "panic": "panic", "hang": "hang", "crash": "crash", "noboot": "no boot",
}


def version():
    """Gives the nftables version of build.sh."""
    with open(os.path.join(HERE, "build.sh")) as f:
        return re.search(r"^NFTABLES=(\S+)$", f.read(), re.M).group(1)


def kernel_of(name):
    """Gives the kernel of a batch from its name, or None."""
    m = re.match(r"^(.*)-\d+$", name)
    return m.group(1) if m and m.group(1) in KERNELS else None


def note_of(lines):
    """Gives a short note from the last lines of the output of a test that does not pass: the
    first error of nft or of the test, or else the last line."""
    skip = ("I: ", "W: [", "mount: /run:")
    lines = [s.strip() for s in lines if s.strip() and not s.startswith(skip)]
    pick = next((s for s in lines if "Error:" in s or s.startswith("E: ")),
                lines[-1] if lines else "")
    # The name of a temporary file of run-tests.sh changes at each run.
    pick = re.sub(r"/tmp/nft-test\.[^/ ]+/[^/ ]+/", "", pick).replace("|", "\\|")
    return pick if len(pick) <= 100 else pick[:97] + "..."


def read_logs(logs):
    """Gives, for each kernel, the newest result of each test: (time, result, note)."""
    results = {k: {} for k in KERNELS}
    for name in sorted(os.listdir(logs)):
        path = os.path.join(logs, name, "log")
        kernel = kernel_of(name)
        if kernel is None or not os.path.isfile(path):
            continue
        when = os.path.getmtime(path)
        out = []
        with open(path, errors="replace") as f:
            for raw in f:
                line = raw.replace("\r", "").rstrip("\n")
                m = OUT.search(line)
                if m:
                    out.append(m.group(1))
                    continue
                m = RESULT.search(line)
                if not m:
                    continue
                test, res = m.groups()
                note = "" if res in ("ok", "skipped") else note_of(out)
                out = []
                old = results[kernel].get(test)
                if old is None or old[0] <= when:
                    results[kernel][test] = (when, WORDS.get(res, res), note)
    return results


def cell(r, test):
    return r[test][1] if test in r else ""


def main():
    p = argparse.ArgumentParser(description="Makes the report of tests/shell of nftables.")
    p.add_argument("--logs", required=True)
    p.add_argument("--out", default=os.path.join(HERE, "report.md"))
    a = p.parse_args()
    ver = version()
    res = read_logs(a.logs)
    ref, rk, a64 = res["ref"], res["rk"], res["rk-arm64"]
    tests = sorted(set(ref) | set(rk) | set(a64))
    dirs = sorted({t.split("/")[1] for t in tests})
    when = max((v[0] for r in res.values() for v in r.values()), default=0)
    day = datetime.date.fromtimestamp(when).isoformat() if when else "never"

    def link(t):
        return f"[{t.removeprefix('testcases/')}]({TEST_URL.format(t, ver)})"

    def passes(r, ts):
        return sum(1 for t in ts if t in r and r[t][1] == "pass")

    o = ["# nftables tests/shell results", "",
         "report.py makes this file from the logs of the runs of run.py. Do not change it by hand.",
         "",
         f"These are the results of the tests of tests/shell of nftables {ver}, with `nft` "
         f"{ver} of Alpine. The README in this directory tells how the tests run. The Linux "
         "column is the result on the reference kernel. A test that passes on Linux and does not "
         "pass on rukernel is work that remains. A skip is a test that needs a feature that the "
         "kernel or `nft` does not have, as run-tests.sh finds it.", "",
         f"## Status at {day}", "",
         "| Directory | Tests | Pass on Linux | Pass on rukernel x86_64 | Pass on both | "
         "Pass on rukernel arm64 |",
         "| --- | --- | --- | --- | --- | --- |"]
    for d in dirs + [None]:
        ts = [t for t in tests if d is None or t.split("/")[1] == d]
        both = sum(1 for t in ts if cell(ref, t) == "pass" and cell(rk, t) == "pass")
        ran = sum(1 for t in ts if t in a64)
        arm = ("no run" if not ran else str(passes(a64, ts)) if ran == len(ts)
               else f"{passes(a64, ts)} of {ran} that ran")
        o.append(f"| {d or 'all'} | {len(ts)} | {passes(ref, ts)} | {passes(rk, ts)} | {both} | "
                 f"{arm} |")
    o += ["", "## Work that remains", "",
          "These tests pass on Linux and do not pass on rukernel x86_64.", ""]
    todo = [t for t in tests if cell(ref, t) == "pass" and cell(rk, t) != "pass"]
    if not todo:
        o.append("None.")
    for d in dirs:
        ts = [t for t in todo if t.split("/")[1] == d]
        if ts:
            o.append(f"- {d}: {len(ts)}: " + ", ".join(link(t) for t in ts) + ".")
    o += ["", "## Each test", "",
          "| Test | Linux | rukernel x86_64 | rukernel arm64 | Note |",
          "| --- | --- | --- | --- | --- |"]
    for t in tests:
        note = rk[t][2] if t in rk and rk[t][2] else (ref[t][2] if t in ref else "")
        o.append(f"| {link(t)} | {cell(ref, t)} | {cell(rk, t)} | {cell(a64, t)} | {note} |")
    with open(a.out, "w") as f:
        f.write("\n".join(o) + "\n")


if __name__ == "__main__":
    main()

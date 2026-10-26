#!/usr/bin/env python3
"""Makes the fstests result tables from the logs of the test runs.

Usage: tools/fstests/report.py --logs DIR --tests DIR [--list FILE ...] [--out DIR]

DIR of --logs has one directory for each run, and each run directory has the file `log`, the
serial output of the virtual machine. A run with a name that starts with `ref-` or `oref-` ran
on the Linux reference kernel. Each other run ran on rukernel. The script keeps the newest result
of each test from each kernel.

DIR of --tests is the `tests` directory of fstests. The script reads the description and the
groups of each test from the head of the test file.

Each --list file has test names, one or more on each line. The tables show these tests also if
no run has a result for them.

The script reads notes.txt next to it. Each line has a test name, a tab and a note. The note
shows in the table of the test.

The script writes ext4.md and overlay.md in the directory of --out, by default the directory of
the script.
"""

import argparse
import datetime
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RESULT = re.compile(r"^fstests: ((?:generic|ext4|overlay|shared)/\d+)\s+(.*)$")


def status_of(text):
    """Gives the status and the reason of one result line of `check`."""
    text = text.strip()
    if re.match(r"^\d+s", text):
        return "pass", ""
    if text.startswith("[not run]"):
        return "not run", text[len("[not run]"):].strip()
    if text.startswith("[expunged]"):
        return "not run", "expunged"
    if "inconsistent" in text:
        return "fail", "fsck finds an error"
    if "[failed" in text:
        return "fail", "the test stops with an error"
    return "fail", "the output is not the expected output"


def read_logs(logs):
    """Gives the newest result of each test for rukernel and for the reference kernel."""
    rk, ref = {}, {}
    for name in sorted(os.listdir(logs)):
        path = os.path.join(logs, name, "log")
        if not os.path.isfile(path):
            continue
        when = os.path.getmtime(path)
        results = ref if name.startswith(("ref-", "oref-")) else rk
        with open(path, errors="replace") as f:
            for line in f:
                m = RESULT.match(line.rstrip())
                if not m:
                    continue
                test, text = m.groups()
                status, reason = status_of(text)
                old = results.get(test)
                if old is None or old[0] <= when:
                    results[test] = (when, status, reason)
    return rk, ref


def describe(tests, name):
    """Gives the description and the groups of a test from its file."""
    path = os.path.join(tests, name)
    if not os.path.isfile(path):
        return "", ""
    with open(path, errors="replace") as f:
        lines = f.read().split("\n")
    words, started = [], False
    for line in lines:
        if line.startswith("# FS QA Test"):
            started = True
            continue
        if not started:
            continue
        if not line.startswith("#"):
            break
        text = line[1:].strip()
        if text.startswith(("Copyright", "SPDX")):
            continue
        if not text:
            if words:
                break
            continue
        words.append(text)
    groups = ""
    for line in lines:
        m = re.match(r"^_begin_fstest\s+(.*)", line)
        if m:
            groups = m.group(1).strip()
            break
    return clean(" ".join(words)), groups


def clean(text, limit=160):
    """Makes a description fit in one cell of a table."""
    text = text.replace("|", "/").replace("\u2014", ",").replace("\u2013", "-")
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[:limit].rsplit(" ", 1)[0].rstrip(",.;:") + " ..."
    return text


def read_notes():
    notes = {}
    path = os.path.join(HERE, "notes.txt")
    if os.path.isfile(path):
        with open(path) as f:
            for line in f:
                if line.startswith("#") or "\t" not in line:
                    continue
                test, note = line.rstrip("\n").split("\t", 1)
                notes[test.strip()] = note.strip()
    return notes


def day(when):
    return datetime.date.fromtimestamp(when).isoformat() if when else "-"


def write_table(path, title, intro, names, rk, ref, tests, notes):
    rows = []
    count = {"pass": 0, "fail": 0, "not run": 0, "no result": 0}
    for name in names:
        desc, _ = describe(tests, name)
        when, status, reason = rk.get(name, (0, "no result", ""))
        _, ref_status, _ = ref.get(name, (0, "no result", ""))
        count[status] += 1
        note = notes.get(name) or clean(reason, 90)
        rows.append(f"| {name} | {desc} | {ref_status} | {status} | {day(when)} | {note} |")
    with open(path, "w") as f:
        f.write(f"# {title}\n\n")
        f.write(intro + "\n\n")
        total = len(names)
        f.write(
            f"rukernel: {count['pass']} pass, {count['fail']} fail, {count['not run']} not run, "
            f"and {count['no result']} have no result, of {total} tests.\n\n"
        )
        f.write("| Test | What the test checks | Linux | rukernel | Last run | Note |\n")
        f.write("| --- | --- | --- | --- | --- | --- |\n")
        f.write("\n".join(rows) + "\n")


def main():
    p = argparse.ArgumentParser(description="Makes the fstests result tables.")
    p.add_argument("--logs", required=True)
    p.add_argument("--tests", required=True)
    p.add_argument("--list", action="append", default=[])
    p.add_argument("--out", default=HERE)
    a = p.parse_args()

    rk, ref = read_logs(a.logs)
    names = set(rk) | set(ref)
    for path in a.list:
        with open(path) as f:
            for line in f:
                if not line.startswith("#"):
                    names.update(line.split())
    notes = read_notes()

    def key(n):
        suite, num = n.split("/")
        return suite, int(num)

    ext4 = sorted((n for n in names if n.split("/")[0] in ("generic", "ext4")), key=key)
    overlay = sorted((n for n in names if n.startswith("overlay/")), key=key)
    write_table(
        os.path.join(a.out, "ext4.md"),
        "fstests results on ext4",
        "These are the results of the generic and ext4 tests of fstests on ext4. The Linux column "
        "is the result on the reference kernel, and the rukernel column is the newest result on "
        "rukernel. The README in this directory tells how the tests run.",
        ext4, rk, ref, a.tests, notes,
    )
    write_table(
        os.path.join(a.out, "overlay.md"),
        "fstests results on overlayfs",
        "These are the results of the overlay tests of fstests. The lower and the upper "
        "directories are on ext4. The README in this directory tells how the tests run.",
        overlay, rk, ref, a.tests, notes,
    )
    print(f"ext4: {len(ext4)} tests, overlay: {len(overlay)} tests", file=sys.stderr)


if __name__ == "__main__":
    main()

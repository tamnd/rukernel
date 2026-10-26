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

The script reads linux.txt next to it, the Linux code that each test checks. Each test links to
its file in fstests, and to that Linux code. The fstests tag comes from build.sh, and the Linux
version comes from tools/rk-abigen, the version of the reference kernel. If the Linux tarball of
rk-abigen is in its cache, the script stops when a path of linux.txt is not in it.

The script writes ext4.md and overlay.md in the directory of --out, by default the directory of
the script. It also writes the status and the work that remains in README.md of that directory,
between the lines `<!-- report: begin -->` and `<!-- report: end -->`. Do not change the text
between these lines by hand, because the next run of the script writes it again.
"""

import argparse
import datetime
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
FSTESTS_URL = "https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/{}?h={}"
LINUX_URL = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/{}?h=v{}"
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


def version(path, pattern):
    """Gives the first group of `pattern` in the file `path` of the repository."""
    with open(os.path.join(ROOT, path)) as f:
        m = re.search(pattern, f.read(), re.M)
    if not m:
        sys.exit(f"no version in {path}")
    return m.group(1)


def linux_paths(linux):
    """Gives the paths of the Linux tarball in the cache of rk-abigen, or None if it is not there."""
    cache = os.environ.get("RK_ABIGEN_CACHE") or os.path.expanduser("~/.cache/rk-abigen")
    tarball = os.path.join(cache, f"linux-{linux}.tar.xz")
    listing = os.path.join(cache, f"linux-{linux}.paths")
    if not os.path.isfile(listing):
        if not os.path.isfile(tarball):
            return None
        out = subprocess.run(["tar", "-tJf", tarball], check=True, capture_output=True, text=True)
        with open(listing, "w") as f:
            f.write(out.stdout)
    prefix = f"linux-{linux}/"
    with open(listing) as f:
        return {line.rstrip("\n").removeprefix(prefix) for line in f}


def read_code(linux):
    """Reads linux.txt: the Linux paths for each key, and the order of the keys."""
    code = {}
    with open(os.path.join(HERE, "linux.txt")) as f:
        for line in f:
            if line.startswith("#") or "\t" not in line:
                continue
            key, paths = line.rstrip("\n").split("\t", 1)
            code[key.strip()] = paths.split()
    known = linux_paths(linux)
    if known is None:
        print("the Linux tarball is not in the cache, so the paths are not checked", file=sys.stderr)
    else:
        for paths in code.values():
            for path in paths:
                if path not in known:
                    sys.exit(f"linux.txt: {path} is not in Linux {linux}")
    return code


def code_of(code, name, cause, groups):
    """Gives the Linux paths of a test: from its name, its cause, its groups or its suite."""
    if name in code:
        return code[name]
    for key, paths in code.items():
        if key.startswith("cause:") and key[len("cause:"):].lower() in cause.lower():
            return paths
    for key, paths in code.items():
        if key.startswith("group:") and key[len("group:"):] in groups:
            return paths
    return code.get("suite:" + name.split("/")[0], [])


def links(paths, linux):
    return ", ".join(f"[{p}]({LINUX_URL.format(p, linux)})" for p in paths)


def day(when):
    return datetime.date.fromtimestamp(when).isoformat() if when else "-"


def results(names, rk, ref, notes, tests, code):
    """Gives a row for each test: the name, the date, the rukernel status, the Linux status, the
    cause, the description and the Linux paths."""
    rows = []
    for name in names:
        when, status, reason = rk.get(name, (0, "no result", ""))
        ref_status = ref.get(name, (0, "no result", ""))[1]
        cause = notes.get(name) or (clean(reason, 90) if reason else "")
        desc, groups = describe(tests, name)
        paths = code_of(code, name, cause or reason, groups.split())
        rows.append((name, when, status, ref_status, cause, desc, paths))
    return rows


def write_table(path, title, intro, rows, tag, linux):
    count = {"pass": 0, "fail": 0, "not run": 0, "no result": 0}
    lines = []
    for name, when, status, ref_status, cause, desc, paths in rows:
        count[status] += 1
        test = f"[{name}]({FSTESTS_URL.format(name, tag)})"
        lines.append(
            f"| {test} | {desc} | {links(paths, linux)} | {ref_status} | {status} | {day(when)} "
            f"| {cause} |"
        )
    with open(path, "w") as f:
        f.write(f"# {title}\n\n")
        f.write("report.py makes this file from the logs of the runs. Do not change it by hand.\n\n")
        f.write(intro + "\n\n")
        f.write(
            f"The tests are from fstests {tag}. The Linux column is the result on Linux {linux}, "
            f"the reference kernel, and the Linux code column links to the code of Linux {linux} "
            "that the test checks.\n\n"
        )
        f.write(
            f"rukernel: {count['pass']} pass, {count['fail']} fail, {count['not run']} not run, "
            f"and {count['no result']} have no result, of {len(rows)} tests.\n\n"
        )
        f.write("| Test | What the test checks | Linux code | Linux | rukernel | Last run | Note |\n")
        f.write("| --- | --- | --- | --- | --- | --- | --- |\n")
        f.write("\n".join(lines) + "\n")


def names_of(tests):
    """Writes a list of test names as an English list."""
    if len(tests) == 1:
        return tests[0]
    return ", ".join(tests[:-1]) + " and " + tests[-1]


def remaining(rows, tag, linux):
    """Gives the lines of the work that remains: the tests that pass on Linux and do not pass on
    rukernel, in groups by the cause, with the Linux code of each group."""
    groups = {}
    for name, _, status, ref_status, cause, _, paths in rows:
        if status == "pass" or ref_status != "pass":
            continue
        if status == "no result":
            key = "No result yet"
        elif cause:
            key = f"{status.capitalize()}: {cause}"
        else:
            key = f"{status.capitalize()}: no reason in the log"
        groups.setdefault(key, []).append((name, paths))
    order = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    lines = []
    for key, tests in order:
        names = names_of([f"[{n}]({FSTESTS_URL.format(n, tag)})" for n, _ in tests])
        line = f"- {key.rstrip('.?!')}. {len(tests)}: {names}."
        if key != "No result yet":
            seen = []
            for _, paths in tests:
                seen += [p for p in paths if p not in seen]
            line += f" Linux code: {links(seen[:3], linux)}."
        lines.append(line)
    return lines


def write_readme(path, suites, newest, tag, linux):
    """Writes the status and the work that remains between the marks of README.md."""
    begin, end = "<!-- report: begin -->", "<!-- report: end -->"
    with open(path) as f:
        text = f.read()
    if begin not in text or end not in text:
        sys.exit(f"{path} has no report marks")
    out = [begin, "", f"## Status at {day(newest)}", ""]
    out.append(
        "| Suite | Tests | Pass on Linux | Pass on rukernel | Pass on both | Fail on rukernel "
        "| Not run on rukernel | No result |"
    )
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for title, rows in suites:
        c = lambda f: sum(1 for r in rows if f(r))
        out.append(
            f"| {title} | {len(rows)} | {c(lambda r: r[3] == 'pass')} "
            f"| {c(lambda r: r[2] == 'pass')} | {c(lambda r: r[2] == r[3] == 'pass')} "
            f"| {c(lambda r: r[2] == 'fail')} | {c(lambda r: r[2] == 'not run')} "
            f"| {c(lambda r: r[2] == 'no result')} |"
        )
    out += [
        "",
        "The rukernel column of a table has the newest result of each test, and the Last run "
        "column of the table gives its date. A change after that date can change the result.",
        "",
        "## Work that remains",
        "",
        "These are the tests that pass on Linux and do not pass on rukernel, in groups by the "
        "cause. The cause is the note in notes.txt, or else the reason in the log. Each group "
        f"links to the code of Linux {linux} that its tests check.",
    ]
    for title, rows in suites:
        out += ["", f"### {title}", ""]
        out += remaining(rows, tag, linux) or ["- None."]
    out += ["", end]
    head, rest = text.split(begin, 1)
    tail = rest.split(end, 1)[1]
    with open(path, "w") as f:
        f.write(head + "\n".join(out) + tail)


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
    tag = version("tools/fstests/build.sh", r"^FSTESTS_TAG=(\S+)")
    linux = version("tools/rk-abigen/src/main.rs", r'^const LINUX_VERSION: &str = "([^"]+)";')
    code = read_code(linux)

    def key(n):
        suite, num = n.split("/")
        return suite, int(num)

    ext4 = sorted((n for n in names if n.split("/")[0] in ("generic", "ext4")), key=key)
    overlay = sorted((n for n in names if n.startswith("overlay/")), key=key)
    ext4_rows = results(ext4, rk, ref, notes, a.tests, code)
    overlay_rows = results(overlay, rk, ref, notes, a.tests, code)
    write_table(
        os.path.join(a.out, "ext4.md"),
        "fstests results on ext4",
        "These are the results of the generic and ext4 tests of fstests on ext4. The rukernel "
        "column is the newest result on rukernel. The README in this directory tells how the tests "
        "run.",
        ext4_rows,
        tag,
        linux,
    )
    write_table(
        os.path.join(a.out, "overlay.md"),
        "fstests results on overlayfs",
        "These are the results of the overlay tests of fstests. The lower and the upper "
        "directories are on ext4. The README in this directory tells how the tests run.",
        overlay_rows,
        tag,
        linux,
    )
    newest = max([v[0] for v in rk.values()] + [0])
    write_readme(
        os.path.join(a.out, "README.md"), [("ext4", ext4_rows), ("overlay", overlay_rows)], newest, tag, linux
    )
    print(f"ext4: {len(ext4)} tests, overlay: {len(overlay)} tests", file=sys.stderr)


if __name__ == "__main__":
    main()

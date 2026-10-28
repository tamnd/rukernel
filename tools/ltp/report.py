#!/usr/bin/env python3
"""Makes the LTP result tables from the logs of the runs of run.py.

Usage: tools/ltp/report.py --logs DIR --src DIR [--notbuilt FILE] [--out DIR] [--arch ARCH]

DIR of --logs has one directory for each batch of run.py, with the name RUNTEST-NNN. Each batch
directory has the file `log`, the serial output of the virtual machine, and the file `tests`, the
tests of the batch. The script keeps the newest result of each test.

DIR of --src has the sources of the LTP tests (the testcases directory of LTP), from src.tar.gz
of `build.sh --full`. The script finds the source of each test, and reads the first sentence of
its description. Each test links to its source in LTP at the tag of build.sh.

The --notbuilt file of `build.sh --full` has the tests that did not build with musl.

The script reads notes.txt next to it. Each line has a test name, a tab and a note. The note shows
in the table of the test, and gives the cause of the test in the work that remains.

The script reads linux.txt next to it, the Linux code that each test checks. A key is a test name,
or the directory of the source of the test in LTP, as kernel/syscalls/fork. The Linux version
comes from tools/rk-abigen. If the Linux tarball of rk-abigen is in its cache, the script stops
when a path of linux.txt is not in it.

The script writes syscalls.md, mm.md, sched.md, net.md and pty.md in the directory of --out, by
default the directory of the script. It also writes the status and the work that remains in
README.md of that directory, between the lines `<!-- report: begin -->` and `<!-- report: end -->`.

--arch aarch64 is for the logs of `run.py --arch aarch64`. The script then writes GROUP-aarch64.md
for each group with results, as syscalls-aarch64.md, and does not change README.md.
"""

import argparse
import datetime
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
LTP_URL = "https://github.com/linux-test-project/ltp/blob/{}/testcases/{}"
LINUX_URL = "https://github.com/torvalds/linux/blob/v{}/{}"
GROUPS = ["syscalls", "mm", "sched", "net", "pty"]
TITLES = {
    "syscalls": "LTP syscalls results",
    "mm": "LTP mm results",
    "sched": "LTP sched results",
    "net": "LTP net results",
    "pty": "LTP pty results",
}

# The status of each result of run.py. A code is the exit code of the test. LTP gives 32 (TCONF)
# when a test does not apply, and an OR of 1 (TFAIL), 2 (TBROK) and 4 (TWARN) when it fails.
STATUS = {
    "missing": "not built",
    "timeout": "timeout",
    "panic": "panic",
    "hang": "hang",
    "crash": "crash",
    "noboot": "no boot",
}
ORDER = ["pass", "fail", "does not apply", "timeout", "panic", "hang", "crash", "not built",
         "no boot", "no result"]


def group_of(runtest):
    return "net" if runtest.startswith("net.") else runtest


def status_of(result):
    """Gives the status and the code text of one result of run.py."""
    if result in STATUS:
        return STATUS[result], ""
    if result == "0":
        return "pass", ""
    if result == "32":
        return "does not apply", ""
    try:
        code = int(result)
    except ValueError:
        return "fail", result
    if code > 128:
        return "fail", f"signal {code - 128}"
    return "fail", f"exit {code}"


# A line of the output that tells the reason of a result. LTP prefixes it with the file and line.
# The names of some errno values, for the old tests that print the number.
ERRNO = {1: "EPERM", 2: "ENOENT", 9: "EBADF", 12: "ENOMEM", 13: "EACCES", 14: "EFAULT",
         19: "ENODEV", 22: "EINVAL", 25: "ENOTTY", 38: "ENOSYS", 95: "EOPNOTSUPP"}
REASON = re.compile(r"(?:^|\s)(TFAIL|TBROK|TCONF|TWARN)\s*:?\s*(.*)")


def reason_of(status, lines):
    """Gives the reason of a result: the first line with TFAIL, TBROK, TCONF or TWARN, in this
    order, or only TCONF for a test that does not apply."""
    # A test that gives TCONF and TWARN exits with 36, and the TCONF line tells the reason.
    want = ("TCONF",) if status == "does not apply" else ("TFAIL", "TBROK", "TCONF", "TWARN")
    for kind in want:
        for line in lines:
            m = REASON.search(line)
            if m and m.group(1) == kind:
                text = m.group(2)
                if "unsuitable kernel config" in text:
                    # The lines before give the options that the test needs.
                    names = []
                    for other in lines:
                        c = re.search(r"Constraint '!?(CONFIG_\w+)", other)
                        if c and c.group(1) not in names:
                            names.append(c.group(1))
                    if names:
                        text = "Needs " + ", ".join(names)
                e = re.search(r"errno=(\d+)", text)
                if e and int(e.group(1)) in ERRNO:
                    text = text.replace(e.group(0), ERRNO[int(e.group(1))])
                return clean(f"{kind}: {text}", 120)
    if status == "does not apply":
        return ""
    for line in reversed(lines):
        if line.strip() and "Summary" not in line and not re.match(r"^\s*(passed|failed|broken|skipped|warnings)\s", line):
            return clean(line, 120)
    return ""


def read_logs(logs):
    """Gives the newest result of each test: (runtest, tag) -> (when, status, code, reason), and
    the commands of the tests: (runtest, tag) -> command."""
    results, tests = {}, {}
    for name in sorted(os.listdir(logs)):
        m = re.match(r"^(.+)-\d+$", name)
        path = os.path.join(logs, name, "log")
        if not m or not os.path.isfile(path):
            continue
        runtest = m.group(1)
        lst = os.path.join(logs, name, "tests")
        if os.path.isfile(lst):
            with open(lst) as f:
                for line in f:
                    if "\t" in line:
                        tag, cmd = line.rstrip("\n").split("\t", 1)
                        tests[(runtest, tag)] = cmd
        when = os.path.getmtime(path)
        out = []
        with open(path, errors="replace") as f:
            for line in f:
                line = line.rstrip("\r\n")
                if line.startswith("ltp-start: "):
                    out = []
                elif line.startswith("ltp-out: "):
                    out.append(line[len("ltp-out: "):])
                elif "ltp-result: " in line:
                    parts = line.split("ltp-result: ", 1)[1].split()
                    if len(parts) < 2:
                        continue
                    tag, result = parts[0], parts[1]
                    status, code = status_of(result)
                    key = (runtest, tag)
                    old = results.get(key)
                    if old is None or old[0] <= when:
                        results[key] = (when, status, code, reason_of(status, out))
                    out = []
    return results, tests


def read_notbuilt(path):
    notbuilt = set()
    if path and os.path.isfile(path):
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    notbuilt.add((parts[0], parts[1]))
    return notbuilt


def index_sources(src):
    """Gives the paths of the sources under testcases, by the name of the program."""
    index = {}
    for d, _, files in os.walk(src):
        for f in files:
            base, ext = os.path.splitext(f)
            if ext not in (".c", ".sh", ""):
                continue
            rel = os.path.relpath(os.path.join(d, f), src)
            index.setdefault(base, []).append(rel)
            if ext == ".sh":
                index.setdefault(f, []).append(rel)
    return index


GROUP_DIRS = {
    "syscalls": "kernel/syscalls/",
    "mm": "kernel/mem/",
    "sched": "kernel/sched/",
    "net": "network/",
    "pty": "kernel/pty/",
}


def source_of(index, group, program):
    """Gives the path of the source of a program, relative to testcases, or None."""
    names = [program]
    for suffix in ("_64", "_16"):
        if program.endswith(suffix):
            names.append(program[: -len(suffix)])
    for name in names:
        paths = index.get(name)
        if not paths:
            continue
        want = GROUP_DIRS[group]
        return sorted(paths, key=lambda p: (not p.startswith(want), not p.endswith(".c"), p))[0]
    return None


def describe(src, path):
    """Gives the first sentence of the description of a test, from its source."""
    if path is None:
        return ""
    try:
        with open(os.path.join(src, path), errors="replace") as f:
            text = f.read(16384)
    except OSError:
        return ""
    lines = text.split("\n")
    words = []
    # The doc comment of new LTP tests starts with "/*\", and older ones have [Description].
    start = None
    for i, line in enumerate(lines):
        s = line.strip()
        if s == "/*\\" or "[Description]" in s or re.match(r"^\*?\s*DESCRIPTION\s*:?\s*$", s.strip("* ")):
            start = i + 1
            break
        if s.startswith("# DESCRIPTION") or s.startswith("# Description"):
            start = i + 1
            break
    if start is None:
        return first_paragraph(lines)
    for line in lines[start:start + 40]:
        s = line.strip()
        if s.startswith("*/"):
            break
        s = s.lstrip("*#").strip()
        if s.startswith("[") and s.endswith("]"):
            if words:
                break
            continue
        if not s:
            if words:
                break
            continue
        if s.startswith(("Copyright", "SPDX", "@")):
            continue
        words.append(s)
        joined = " ".join(words)
        if re.search(r"[a-z)]\.(\s|$)", joined):
            break
    text = " ".join(words)
    m = re.search(r"^(.*?[a-z)\]])\.(\s|$)", text)
    if m:
        text = m.group(1) + "."
    return clean(text, 160)


# The words of a paragraph about the authors of a test, and not about the test.
AUTHORS = re.compile(r"Copyright|SPDX|Author|AUTHOR|Porting|Ported|written by|Written by|@|\(c\)|"
                     r"All Rights Reserved|History|HISTORY|Modified|Rewrote|Rewritten|Converted|"
                     r"free software|GNU|WARRANTY|License|LICENSE|later version|Foundation|MERCHANTABILITY")


def first_paragraph(lines):
    """Gives the first sentence of the first comment that is not about the authors, for a test
    without a description section."""
    paragraphs, words, inside = [], [], False
    for line in lines[:80]:
        s = line.strip()
        oneline = False
        if not inside:
            if s.startswith("/*"):
                inside = True
                # In a box of one-line comments, only an empty line ends a paragraph.
                oneline = s.endswith("*/")
                s = s[2:].strip()
            elif s.startswith("#") and not s.startswith(("#!", "#include", "#define", "#if")):
                s = s.lstrip("#").strip()
                if s:
                    words.append(s)
                elif words:
                    paragraphs.append(words)
                    words = []
                continue
            elif s.startswith("#!"):
                continue
            elif s.startswith(("#include", "#define")) or (s and not s.startswith("//")):
                # Only the comments at the head of the file describe the test.
                break
            else:
                continue
        end = "*/" in s
        s = re.sub(r"^[\s*]+", "", s.split("*/")[0]).strip()
        if s:
            words.append(s)
        elif words:
            paragraphs.append(words)
            words = []
        if end:
            inside = False
            if words and not oneline:
                paragraphs.append(words)
                words = []
    if words:
        paragraphs.append(words)
    for words in paragraphs:
        text = re.sub(r"^Description\s*:\s*", "", " ".join(words))
        if AUTHORS.search(text) or len(text) < 12 or re.match(r"^(File|Test Name)\s*:", text):
            continue
        m = re.search(r"^(.*?[a-z)\]])\.(\s|$)", text)
        return clean(m.group(1) + "." if m else text, 160)
    return ""


def clean(text, limit=160):
    """Makes a text fit in one cell of a table."""
    text = text.replace("|", "/").replace("—", ",").replace("–", "-")
    text = text.replace("<", "&lt;").replace(">", "&gt;").replace("`", "'")
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
    """Reads linux.txt: the Linux paths for each key."""
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


def code_of(code, tag, path):
    """Gives the Linux paths of a test: from its name, or from the directory of its source."""
    if tag in code:
        return code[tag]
    if path:
        d = os.path.dirname(path)
        while d:
            if d in code:
                return code[d]
            d = os.path.dirname(d)
    return []


def links(paths, linux):
    return ", ".join(f"[{p}]({LINUX_URL.format(linux, p)})" for p in paths)


def day(when):
    return datetime.date.fromtimestamp(when).isoformat() if when else "-"


def rows_of(keys, results, tests, notbuilt, notes, src, index, code):
    """Gives a row for each test: a dict with the runtest file, the tag, the date, the status, the
    note, the reason, the description, the source and the Linux paths."""
    rows = []
    for runtest, tag in keys:
        when, status, codetext, reason = results.get((runtest, tag), (0, "no result", "", ""))
        if status == "no result" and (runtest, tag) in notbuilt:
            status = "not built"
        cmd = tests.get((runtest, tag), "")
        program = cmd.split()[0] if cmd else tag
        path = source_of(index, group_of(runtest), program)
        note = notes.get(tag) or notes.get(f"{runtest}:{tag}") or ""
        rows.append({
            "runtest": runtest,
            "tag": tag,
            "when": when,
            "status": status,
            "code": codetext,
            "reason": reason,
            "note": note,
            "desc": describe(src, path),
            "path": path,
            "linux": code_of(code, tag, path),
        })
    return rows


def test_link(row, tag):
    if row["path"]:
        return f"[{row['tag']}]({LTP_URL.format(tag, row['path'])})"
    return row["tag"]


def result_text(row):
    if row["status"] == "fail" and row["code"]:
        return f"fail ({row['code']})"
    return row["status"]


def write_table(path, group, rows, tag, linux, arch="x86_64"):
    count = {s: 0 for s in ORDER}
    for r in rows:
        count[r["status"]] += 1
    net = group == "net"
    lines = []
    for r in rows:
        note = r["note"] or r["reason"]
        first = f"| {r['runtest']} " if net else ""
        lines.append(
            f"{first}| {test_link(r, tag)} | {r['desc']} | {links(r['linux'], linux)} "
            f"| {result_text(r)} | {day(r['when'])} | {note} |"
        )
    parts = [f"{count[s]} {s}" for s in ORDER if count[s]]
    with open(path, "w") as f:
        on = " on arm64" if arch == "aarch64" else ""
        f.write(f"# {TITLES[group]}{on}\n\n")
        f.write("report.py makes this file from the logs of the runs. Do not change it by hand.\n\n")
        if net:
            f.write(
                f"These are the results of the tests of the runtest/net.* files of LTP {tag} on "
                "rukernel. The README in this directory tells how the tests run.\n\n"
            )
        else:
            f.write(
                f"These are the results of the tests of runtest/{group} of LTP {tag} on rukernel"
                f"{on}. The README in this directory tells how the tests run.\n\n"
            )
        f.write(
            f"The Linux code column links to the code of Linux {linux} that the test checks. The "
            "note is the note in notes.txt, or else the first TFAIL, TBROK or TCONF line of the "
            "output.\n\n"
        )
        f.write(f"rukernel: {', '.join(parts)}, of {len(rows)} tests.\n\n")
        head = "| Runtest " if net else ""
        f.write(f"{head}| Test | What the test checks | Linux code | rukernel | Last run | Note |\n")
        f.write(("| --- " if net else "") + "| --- | --- | --- | --- | --- | --- |\n")
        f.write("\n".join(lines) + "\n")


def names_of(tests):
    """Writes a list of test names as an English list."""
    if len(tests) == 1:
        return tests[0]
    return ", ".join(tests[:-1]) + " and " + tests[-1]


# The rules that give the cause of a result from its reason, when notes.txt has no note. Each rule
# is a pattern of the reason and the cause. The first rule that matches gives the cause.
CAUSES = [
    (r"__NR_(\w+) not supported", "The system call {} is missing"),
    (r"syscall\((\w+)\) .*not supported", "The system call {} is missing"),
    (r"16-bit version of", "The 16-bit ID system calls are not on x86-64"),
    (r"This arch .* is not supported|Test only supports|only supported on|not supported on this arch",
     "The test is for another architecture"),
    (r"socket\(2, .*EAFNOSUPPORT", "AF_INET sockets are missing"),
    (r"socket\(10, .*EAFNOSUPPORT", "AF_INET6 sockets are missing"),
    (r"EAFNOSUPPORT", "An address family of sockets is missing"),
    (r"Needs (CONFIG_[\w, ]+)", "Needs {}"),
    (r"Couldn't find '([\w.\-]+)' in \$PATH", "Needs the command {}"),
    (r"(mkfs\.\w+|modprobe|useradd|ip/ifconfig|tst_loader\.sh)\b.*(?:fail|not found|non-zero)",
     "The command {} fails"),
    (r"Failed to run cmd: ([\w.\-]+)", "The command {} fails"),
    (r"Failed to find module", "Needs kernel modules"),
    # The net tests look for the veth driver in /lib/modules, and the message has no new line.
    (r"(\w+) driver not avail", "Needs the {} driver"),
    (r"type (veth) .*failed", "Needs the {} driver"),
    (r"modules\.dep|modules\.builtin", "Needs a kernel driver, for example veth"),
    (r"KSM configuration", "Needs CONFIG_KSM"),
    (r"huge pages|hugetlbfs", "Needs huge pages"),
    (r"tmpfs|TMPDIR", "The test does not run on tmpfs, the file system of TMPDIR"),
    (r"The (\w+) filesystem is not supported", "Needs the file system {}"),
    (r"No required filesystems", "Needs a file system that rukernel does not have"),
    (r"(\w+) is not supported by the test", "Needs a file system other than {}"),
    (r"controller required|cgroup", "Needs a cgroup v2 controller"),
    (r"fanotify", "fanotify is missing"),
    (r"perf_event", "perf_event_open is missing"),
    (r"NUMA|node", "Needs NUMA"),
    (r"at least (\d+) CPUs", "Needs {} CPUs"),
    (r"SwapFree|free space", "Needs more swap or disk space"),
    (r"non-POSIX|time_high fields|xfs/xqm\.h|getcontext|profil\(\)|sethostid is undefined|"
     r"__NR_mmap2 is not defined", "The C library (musl) does not have a feature of the test"),
    (r"Failed to acquire device", "Needs a loop device"),
    (r"Test killed by (SIG\w+)", "The test gets {}"),
    (r"Test killed!", "The test does not stop in the LTP time limit"),
    (r"tst_checkpoint_wait.*ETIMEDOUT", "A wait for a checkpoint of the test times out"),
    (r"alloc passed, expected to fail", "The overcommit limits of memory are missing"),
    (r"(\w+)(?:\(\))? (?:is )?not (?:supported|implemented)", "{} is not supported"),
    (r"doesn't support (\w+)", "{} is not supported"),
    (r"Test device stat file", "Needs the stat file of the test device in /sys/block"),
    (r"(/proc/[\w/.\-]+)", "Needs {}"),
    (r"(/sys/[\w/.\-]+)", "Needs {}"),
    (r"(CONFIG_\w+)", "Needs {}"),
    (r"needs? root|Test needs to be run as root", "Needs root"),
    (r"succ?e+d|(?<!failed) unexpectedly|returned 0 \(expected -1\)|"
     r"returned unexpected value 0|shouldn't be executed|expected return value=-1, got 0|returned with 0",
     "A call that must fail succeeds"),
    (r".*\b(E[A-Z0-9]{3,})\b", "Unexpected {}"),
]

# The names of the LTP functions that call a system call, and the system call.
CALLS = {"tst_clock_settime": "clock_settime", "persona": "personality", "stime": "settimeofday"}


def cause_of(row):
    """Gives the cause of a test that does not pass: its note, or a cause from its reason."""
    if row["note"]:
        return row["note"]
    reason = row["reason"]
    if row["status"] in ("timeout", "panic", "hang", "crash", "not built", "no boot", "no result"):
        return {
            "timeout": "The test does not stop in its time",
            "panic": "The kernel panics",
            "hang": "The kernel hangs",
            "crash": "The init script stops",
            "not built": "The test does not build with musl",
            "no boot": "The kernel does not boot",
            "no result": "No result yet",
        }[row["status"]]
    if "ENOSYS" in reason:
        # The system call is the function before the error, or else the directory of the test.
        m = re.search(r"(\w+)\([^()]*\)[^()]*ENOSYS", reason)
        name = m.group(1) if m else None
        if name is None and (row.get("path") or "").startswith("kernel/syscalls/"):
            name = row["path"].split("/")[2]
        if name:
            return f"The system call {CALLS.get(name, name)} gives ENOSYS"
        return "A system call gives ENOSYS"
    for pattern, text in CAUSES:
        m = re.search(pattern, reason)
        if m:
            groups = [g for g in m.groups() if g] if m.groups() else []
            return text.format(*groups) if groups else text
    return "No reason in the log" if not reason else "Other reasons"


def remaining(rows, tag, linux, limit=12):
    """Gives the lines of the work that remains: the tests that do not pass, in groups by the
    cause, with the Linux code of each group."""
    groups = {}
    for r in rows:
        if r["status"] == "pass":
            continue
        key = f"{r['status'].capitalize()}: {cause_of(r)}"
        groups.setdefault(key, []).append(r)
    order = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    lines = []
    for key, tests in order:
        shown = [test_link(r, tag) for r in tests[:limit]]
        if len(tests) > limit:
            shown.append(f"{len(tests) - limit} more")
        line = f"- {key.rstrip('.?!')}. {len(tests)}: {names_of(shown)}."
        seen = []
        for r in tests:
            seen += [p for p in r["linux"] if p not in seen]
        if seen:
            line += f" Linux code: {links(seen[:3], linux)}."
        lines.append(line)
    return lines


def write_readme(path, groups, newest, tag, linux):
    """Writes the status and the work that remains between the marks of README.md."""
    begin, end = "<!-- report: begin -->", "<!-- report: end -->"
    with open(path) as f:
        text = f.read()
    if begin not in text or end not in text:
        sys.exit(f"{path} has no report marks")
    shown = ["pass", "fail", "does not apply", "timeout", "panic", "hang", "not built", "no result"]
    out = [begin, "", f"## Status at {day(newest)}", ""]
    out.append("| Group | Tests | " + " | ".join(s.capitalize() for s in shown) + " |")
    out.append("| --- " * (len(shown) + 2) + "|")
    for group, rows in groups:
        c = {s: 0 for s in ORDER}
        for r in rows:
            c[r["status"]] += 1
        c["hang"] += c["crash"]
        c["no result"] += c["no boot"]
        out.append(
            f"| [{group}]({group}.md) | {len(rows)} | " + " | ".join(str(c[s]) for s in shown) + " |"
        )
    out += [
        "",
        "The table of a group has the newest result of each test, and the Last run column of the "
        "table gives its date. A change after that date can change the result. The hang column "
        "also counts the tests after which the init script stopped.",
        "",
        "## Work that remains",
        "",
        "These are the tests that do not pass, in groups by the cause. The cause is the note in "
        "notes.txt, or else a cause that report.py finds in the first TFAIL, TBROK or TCONF line "
        f"of the output. Each group links to the code of Linux {linux} that its tests check.",
    ]
    for group, rows in groups:
        out += ["", f"### {group}", ""]
        out += remaining(rows, tag, linux) or ["- None."]
    out += ["", end]
    head, rest = text.split(begin, 1)
    tail = rest.split(end, 1)[1]
    with open(path, "w") as f:
        f.write(head + "\n".join(out) + tail)


def main():
    p = argparse.ArgumentParser(description="Makes the LTP result tables.")
    p.add_argument("--logs", required=True)
    p.add_argument("--src", required=True, help="the testcases directory of the LTP source")
    p.add_argument("--notbuilt")
    p.add_argument("--out", default=HERE)
    p.add_argument("--arch", choices=["x86_64", "aarch64"], default="x86_64",
                   help="the architecture of the runs of run.py")
    a = p.parse_args()

    results, tests = read_logs(a.logs)
    notbuilt = read_notbuilt(a.notbuilt)
    notes = read_notes()
    tag = version("tools/ltp/build.sh", r"^LTP_TAG=(\S+)")
    linux = version("tools/rk-abigen/src/main.rs", r'^const LINUX_VERSION: &str = "([^"]+)";')
    code = read_code(linux)
    index = index_sources(a.src)

    # The order of the tests in a table is the order of the runtest files.
    keys = list(dict.fromkeys(list(tests) + list(results) + sorted(notbuilt)))
    out = []
    suffix = "-aarch64" if a.arch == "aarch64" else ""
    for group in GROUPS:
        # The arm64 runs are for some groups only, so a group without results has no file.
        if a.arch == "aarch64" and not any(group_of(k[0]) == group for k in results):
            continue
        gkeys = [k for k in keys if group_of(k[0]) == group]
        rows = rows_of(gkeys, results, tests, notbuilt, notes, a.src, index, code)
        write_table(os.path.join(a.out, f"{group}{suffix}.md"), group, rows, tag, linux, a.arch)
        out.append((group, rows))
        print(f"{group}: {len(rows)} tests", file=sys.stderr)
    if a.arch == "aarch64":
        return
    newest = max([v[0] for v in results.values()] + [0])
    write_readme(os.path.join(a.out, "README.md"), out, newest, tag, linux)


if __name__ == "__main__":
    main()

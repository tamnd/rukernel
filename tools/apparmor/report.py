#!/usr/bin/env python3
"""Makes report.md from the logs of tools/apparmor/run.py.

Usage: tools/apparmor/report.py --logs DIR [--out FILE]

DIR has the batch directories of run.py, NAME-NNN/log. NAME is the kernel: `ref`, `rk` or an
other name of --name. The report has the newest result of each test for each kernel, and the
number of checks of each test that give `ok` and that give an error. The section of the load
and the attach compares the tests of LOAD_ATTACH with the reference.
"""

import argparse
import os
import re
import sys

# The tests that check the load of the profiles and the attach of a profile to a task: at exec,
# with aa-exec, with change_hat, with change_profile and with change_onexec, and the
# introspection of the label. These tests make the exit of the complain mode in #540.
LOAD_ATTACH = [
    "profiles", "aa_exec", "aa_policy_cache", "at_secure", "changehat", "changehat_fork",
    "changehat_misc", "changeprofile", "complain", "environ", "exec", "exec_qual", "i18n",
    "introspect", "longpath", "onexec",
]

OK = re.compile(r"^(ok \((pass|fail|signal\d*)\)|x(pass|fail|signal\d*)): ")
ERROR = re.compile(r"^(Error|Fatal Error|Alert): ")
# The temporary directory of a test has a random name.
TMP = re.compile(r"/tmp/sdtest\.[^/ ]*")


class Result:
    def __init__(self, status, out):
        self.status = status
        self.out = out
        self.checks = {TMP.sub("/tmp/sdtest.X", line) for line in out if OK.match(line)}
        self.ok = sum(1 for line in out if OK.match(line))
        self.errors = [line for line in out if ERROR.match(line)]


def read_logs(logs):
    """Gives {kernel: {test: Result}} and {kernel: the aa-ready line}, with the newest result of
    each test."""
    results, ready = {}, {}
    for d in sorted(os.listdir(logs)):
        m = re.fullmatch(r"(.+)-(\d{3})", d)
        path = os.path.join(logs, d, "log")
        if not m or not os.path.exists(path):
            continue
        kernel = m.group(1)
        res = results.setdefault(kernel, {})
        out = []
        with open(path, "rb") as f:
            for raw in f:
                line = raw.decode(errors="replace").rstrip("\r\n")
                at = line.find("aa-")
                if at < 0:
                    continue
                line = line[at:]
                if line.startswith("aa-ready: "):
                    ready.setdefault(kernel, line[len("aa-ready: "):].strip())
                elif line.startswith("aa-start: "):
                    out = []
                elif line.startswith("aa-out: "):
                    out.append(line[len("aa-out: "):])
                elif line.startswith("aa-result: "):
                    parts = line[len("aa-result: "):].split()
                    if len(parts) == 2:
                        res[parts[0]] = Result(parts[1], out)
                    out = []
    return results, ready


def cell(r):
    if r is None:
        return ""
    if r.status in ("pass", "skip"):
        return r.status if not r.ok else f"{r.status}, {r.ok} ok"
    text = r.status
    if r.ok or r.errors:
        text += f", {r.ok} ok, {len(r.errors)} errors"
    return text


def profiles_section(results, kernels):
    lines = ["## The profiles of Ubuntu", ""]
    lines.append("The test `profiles` loads /etc/apparmor.d with `apparmor_parser -r -K` and lists "
                 "the profiles with `aa-status`.")
    lines.append("")
    lines.append("| Kernel | Result | Parser | Profiles | aa-status | Enforce | Complain |")
    lines.append("|---|---|---|---|---|---|---|")
    names = {}
    for k in kernels:
        r = results[k].get("profiles")
        if r is None:
            continue
        val = {}
        for line in r.out:
            for key in ("parser", "profiles", "aa-status", "aa-status --enforced",
                        "aa-status --complaining"):
                if line.startswith(key + ": "):
                    val[key] = line[len(key) + 2:].strip()
        names[k] = {line[len("profile: "):] for line in r.out if line.startswith("profile: ")}
        lines.append(f"| {k} | {r.status} | {val.get('parser', '')} | {val.get('profiles', '')} | "
                     f"{val.get('aa-status', '')} | {val.get('aa-status --enforced', '')} | "
                     f"{val.get('aa-status --complaining', '')} |")
    lines.append("")
    if "ref" in names:
        for k in kernels:
            if k == "ref" or k not in names:
                continue
            only_ref = sorted(names["ref"] - names[k])
            only_k = sorted(names[k] - names["ref"])
            if not only_ref and not only_k:
                lines.append(f"{k} has the same profiles and modes as the reference.")
            else:
                lines.append(f"The profiles of the reference that {k} does not have: "
                             f"{', '.join(only_ref) or 'none'}. The profiles of {k} that the "
                             f"reference does not have: {', '.join(only_k) or 'none'}.")
            lines.append("")
    return lines


def main():
    p = argparse.ArgumentParser(description="Makes the report of the AppArmor tests.")
    p.add_argument("--logs", required=True, help="the directory of the batches of run.py")
    p.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                 "report.md"))
    a = p.parse_args()
    results, ready = read_logs(a.logs)
    if not results:
        sys.exit("report.py: no logs")
    kernels = sorted(results, key=lambda k: (k != "ref", k))
    tests = sorted({t for r in results.values() for t in r} - {"profiles"})
    lines = ["# The AppArmor tests", ""]
    lines.append("This file is made by `tools/apparmor/report.py`. See README.md.")
    lines.append("")
    for k in kernels:
        lines.append(f"- {k}: {ready.get(k, 'no boot')}")
    lines.append("")
    lines += profiles_section(results, kernels)

    lines += ["## The load and the attach", ""]
    lines.append("In complain mode, a check that expects a denial gets no denial, so some tests "
                 "fail on the reference too. Thus the pass set has two parts: the tests that "
                 "pass on the reference, and the checks (the lines `ok`) of the reference in "
                 "each test.")
    lines.append("")
    others = [k for k in kernels if k != "ref"]
    if "ref" in results:
        ref = results["ref"]
        want = [t for t in LOAD_ATTACH if ref.get(t) and ref[t].status == "pass"]
        checks = sum(len(ref[t].checks) for t in LOAD_ATTACH if ref.get(t))
        lines.append(f"The reference passes {len(want)} of the {len(LOAD_ATTACH)} tests of the "
                     f"load and the attach: {', '.join(want) or 'none'}. These tests have "
                     f"{checks} checks that pass on the reference.")
        lines.append("")
        for k in others:
            miss = [t for t in want if not results[k].get(t) or results[k][t].status != "pass"]
            lost = []
            for t in LOAD_ATTACH:
                if ref.get(t):
                    got = results[k][t].checks if results[k].get(t) else set()
                    lost += [f"{t}: {c}" for c in sorted(ref[t].checks - got)]
            if not miss and not lost:
                lines.append(f"- {k}: all of these tests and checks pass. {k} reaches the pass "
                             f"set of the reference.")
                continue
            if miss:
                lines.append(f"- {k}: {len(want) - len(miss)} of these tests pass. Not yet: "
                             f"{', '.join(miss)}.")
            else:
                lines.append(f"- {k}: all of these tests pass.")
            if lost:
                lines.append(f"- {k}: {checks - len(lost)} of the checks pass. Not yet:")
                lines += [f"  - `{c[:200]}`" for c in lost]
        lines.append("")
    lines.append("| Test | " + " | ".join(kernels) + " |")
    lines.append("|---|" + "---|" * len(kernels))
    for t in LOAD_ATTACH:
        lines.append(f"| {t} | " + " | ".join(cell(results[k].get(t)) for k in kernels) + " |")
    lines.append("")

    lines += ["## All the tests", ""]
    count = {k: {} for k in kernels}
    for k in kernels:
        for t in tests:
            r = results[k].get(t)
            if r:
                count[k][r.status] = count[k].get(r.status, 0) + 1
    for k in kernels:
        lines.append(f"- {k}: " + ", ".join(f"{n} {s}" for s, n in sorted(count[k].items())))
    lines.append("")
    lines.append("| Test | " + " | ".join(kernels) + " |")
    lines.append("|---|" + "---|" * len(kernels))
    for t in tests:
        lines.append(f"| {t} | " + " | ".join(cell(results[k].get(t)) for k in kernels) + " |")
    lines.append("")

    lines += ["## The first error of each test that does not pass", ""]
    for k in kernels:
        for t in tests:
            r = results[k].get(t)
            if r and r.status not in ("pass", "skip"):
                why = r.errors[0] if r.errors else (r.out[-1] if r.out else "no output")
                lines.append(f"- {k}, {t}: `{why[:200]}`")
    lines.append("")
    with open(a.out, "w") as f:
        f.write("\n".join(lines))
    print(f"report.py: {a.out}", file=sys.stderr)


if __name__ == "__main__":
    main()

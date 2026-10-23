# Tracking upstream

Linux releases every nine or ten weeks: 63 days per cycle through 2026 (document 01.1). Each release brings about 15,000 to 19,000 commits. Of those, a few hundred touch the user visible interface: new system calls (472 `fchroot` in 7.3), new flags on old ones (four new `clone3` flags in 7.1), new io_uring opcodes, new netlink attributes, new sysfs files, changed procfs fields, new Landlock ABI versions, removed file systems. A kernel that claims "compatible with the latest Linux" has to absorb that delta every cycle, indefinitely. Done by hand it would consume the project. This document describes the pipeline that makes it routine.

## 17.1 The cadence

**The reference moves on the tag.** When Linus tags a release (v7.4 is expected around mid December 2026), the pipeline runs within hours:

1. **Day 0:** `rk-abigen` regenerates the ABI from the new tree (document 04.3) and writes `ABI-CHANGES-7.3-7.4.md`. `rukernel-compat` runs its whole suite against the new reference, and the first report, "what 7.4 changed that we do not yet do", exists the day 7.4 is tagged (document 18.9).
2. **Day 0 to 7:** the generated tables are merged. New system call numbers appear in the dispatch table returning `ENOSYS` and counted in `/sys/kernel/rukernel/abi/enosys`. New constants, structures and flags are in `rk-abi`, so a flag the kernel does not yet handle is rejected with the reference's error for an unknown flag (usually `EINVAL`), never silently ignored.
3. **Day 7 to 63:** each item in `ABI-CHANGES` becomes an issue, labelled by subsystem and by the size estimate the classifier gives (section 17.3). The gate in document 02.5: by the next upstream tag, every item is implemented or carries an issue that says why not yet.
4. **Merge window watch:** during each two week merge window, the pipeline runs against Linus's tree daily. By the time an `-rc1` exists, the changes are known, and by `-rc7` most of them are implemented. This is how the 63 day gate is met in practice: work starts at the merge window, not at the release.

**Stable releases** (7.3.1, 7.3.2 and so on) rarely change the ABI, but sometimes do: a behaviour fix that programs notice, a security fix that tightens a check. The pipeline runs on each stable tag and diffs the behaviour tests, not just the headers. A stable release that changes observable behaviour produces a `behaviour.toml` entry (document 04.6) keyed to that stable version.

**Longterm.** The newest longterm (6.18 now, likely 7.4 for 2026) is a second reference, selectable at boot with `rukernel.abi=6.18`. Enterprise and embedded users run longterm kernels, and some software checks for exact versions. Behaviour that differs between releases is keyed in `behaviour.toml`, so one rukernel binary presents either release faithfully. Older longterms are not references. Programs built for them run on the current ABI, because Linux's ABI is backward compatible, which is the "never break user space" rule.

## 17.2 What changes, by kind

`ABI-CHANGES-<from>-<to>.md` groups the delta by kind, because each kind has a different cost:

| Kind | Source | Typical count per release | Handling |
|---|---|---|---|
| New system call | the syscall tables | 0 to 3 | generated stub at day 0, implementation by hand |
| New flag or field on an existing call | uAPI header diff, BTF signature diff | 10 to 40 | generated constant at day 0; behaviour by hand, often small |
| New ioctl | `_IOC` decoding diff | 20 to 100, mostly in drivers | only those for subsystems or drivers we have |
| New netlink attribute or message | YNL spec diff | 20 to 80 | mostly generated: parse and dump code comes from the spec; semantics by hand |
| New io_uring opcode or flag | `io_uring.h` diff | 0 to 4 | by hand |
| New BPF helper, kfunc, map or program type | `bpf.h`, `BTF_ID_FLAGS` sets | 5 to 30 | by hand, with the verifier tests from kselftest |
| New or changed sysfs file | `Documentation/ABI` diff, booted reference walk | 30 to 150 | generators per subsystem, by hand |
| New or changed procfs field | booted reference walk | 2 to 10 | by hand, test from the walk |
| New tracepoint or changed format | `/sys/kernel/tracing/events` walk | 10 to 50 | by hand where we have the subsystem |
| Removed interface | all of the above | a few | kept only if the claimed ABI is older (`behaviour.toml`) |
| Behaviour change with no interface change | LTP and kselftest diffs between releases, the changelog's "user visible" commits | 5 to 20 | found by the differential, fixed by hand |

The last row is the hard one. There is no header diff for "`MOVE_MOUNT_BENEATH` now works on the root". Three sources find these:

- **Changed tests.** A new or changed kselftest or LTP test is almost always the test for a behaviour change. Each one becomes a case run against both references.
- **The differential.** Tests that pass on 7.3 and fail on 7.4, or the reverse, show the change directly.
- **Commit classification.** Every mainline commit that touches `include/uapi`, `Documentation/ABI`, `fs/proc`, `kernel/sys.c` or the system call entry points, or that carries a `Fixes:` tag against an ABI visible commit, is classified (section 17.3) and listed.

## 17.3 Machine assistance, with the harness as judge

The volume (about 18,000 commits per release) is the problem LLM based tools are now good at triaging. The research is recent and specific:

- KernelGPT (ASPLOS 2025) generated syzkaller descriptions from kernel source.
- KNighter (SOSP 2025) generated checkers.
- AutoDriver (2025) ported drivers across API changes.
- OSFoundry (August 2026) writes system code against a persistent specification.
- K-Repro reproduces kernel bugs from patches.

The pipeline uses them in three bounded roles:

1. **Classification.** For each commit in the release, decide whether it changes user visible behaviour and, if so, which rukernel subsystem owns the change. The output is a draft of `ABI-CHANGES`, reviewed by a person. A misclassification is caught later by the differential, so the cost of a classifier error is delay, not a compatibility bug.
2. **Test synthesis.** For each behaviour change, draft a differential test case (a small C or Rust program, or a syzkaller program) that distinguishes old from new behaviour, and run it on both references. A test that does not distinguish them is discarded automatically. This is KernelGPT's insight applied to compatibility: the oracle (two real kernels) validates the machine's output, so the machine's error rate does not matter much.
3. **Implementation drafts.** For the routine kinds (a new flag that gates an existing path, a new sysfs attribute, a new netlink attribute), draft the rukernel change against the generated ABI and the Linux commit. The draft must pass the synthesized test and the full compat suite for that subsystem, and is reviewed like any other pull request. The unsafe rule (document 03.1) means a machine drafted change cannot introduce memory unsafety outside `rk-frame`, and changes to `rk-frame` are never drafted by machine.

The rule that governs all three: **a machine output enters the tree only through the harness.** The differential against real Linux is the judge, and its verdict does not depend on who wrote the code.

## 17.4 What `uname` says

Programs check the kernel version, sometimes for good reasons (feature detection where probing is impossible) and sometimes for bad ones (refusing to run on an "unsupported" kernel). rukernel reports:

- **`uname -s`:** `Linux`. Programs branch on it, and rukernel is Linux from their point of view.
- **`uname -r`:** the claimed release with a suffix, for example `7.3.0-rk1.2.0`. Version checks that parse major, minor and patch see the release whose ABI we implement. The suffix identifies rukernel to people and to tools that care, the same way distributions append `-generic` or `.fc43.x86_64`. With `rukernel.abi=6.18`, the release reads `6.18.0-rk1.2.0`.
- **`uname -v`:** the build string, which begins `#1 SMP PREEMPT_LAZY rukernel` and then gives the build date, in the format Linux uses.
- **`/proc/version`:** Linux's format, with `rukernel` and the compiler (`rustc 1.xx`) where Linux names GCC or Clang.
- **`/sys/kernel/rukernel/`:** the version, the commit, the claimed ABI, the ENOSYS counters, the driver host status (document 12.5), and the persona registrations (document 16.2).

**The rule:** the reported release is the one whose ABI is fully implemented. rukernel does not claim 7.4 until the 7.4 delta is closed, or listed with issues at the gate in document 02.5. Before that it reports 7.3. "It says 7.4, so it has `foo`" must be true for every `foo` a program could reasonably probe by version. Otherwise version based feature detection breaks, and version reporting is itself part of the ABI.

## 17.5 Upstream relations

rukernel is a separate kernel, but not a separate community from Linux's on the things that matter to both:

- **Bugs in Linux** found by the differential (behaviour that contradicts documentation, a race the harness exposes on the reference side, an undocumented ABI quirk) are reported upstream with the reproducer.
- **Documentation fixes** for `Documentation/ABI` and the man pages, where reimplementation exposes gaps, are sent to the maintainers. A second implementation is the best documentation review there is.
- **Shared tests.** Improvements to kselftest, LTP and the gVisor suite that come from rukernel's harness are contributed upstream, under those projects' licences.
- **Interfaces that start in rukernel and might belong in Linux**, `rk-nt` being the obvious candidate (document 16.3), are proposed upstream before they ship as stable. An interface that only rukernel has is a future compatibility burden.

## 17.6 What happens if Linux changes direction

The ABI is stable by Linux's own rule, so the risk is not breakage. The risk is growth in directions that are expensive to follow: a new subsystem as large as io_uring, or a new BPF program type that exposes deep scheduler internals. The response is the same as for any other gap. It is listed, prioritized by the corpus (does real software use it yet?), and reported honestly in the coverage numbers. "Compatible with Linux 7.x" is a statement with a number attached, and that number can go down when Linux adds something large. The release notes say so.

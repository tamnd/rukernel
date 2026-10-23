# The goal

"100% compatible with Linux, at Linux's speed, running every binary" is a slogan until each word has a measurement. This document gives each axis its measurement, its gate at 1.0, and what does not count.

## 2.1 Axis one: ABI compatibility

**The claim.** A program built for Linux, distributed as a binary, behaves on rukernel exactly as it does on the pinned Linux release, for every program in the corpus and for every interface the corpus does not reach but the ABI defines.

**What "the ABI" means here** is defined in document 04.1 and is wider than the system call table:

- System calls, with their numbers, argument layouts, flags, return values, errno values, and blocking and restart behaviour.
- ioctls, netlink families and messages, socket options, `fcntl` and `prctl` commands.
- The contents and formats of procfs, sysfs, debugfs where tools rely on it, and devtmpfs nodes.
- The vDSO, the auxiliary vector, the ELF loading rules, signal frames, the initial stack layout.
- The on disk formats of every file system we support, so that disks move between Linux and rukernel.
- Observable timing contracts that programs rely on: `CLOCK_MONOTONIC` never going backwards, `epoll` wake ordering, futex fairness as far as glibc depends on it.

**The numbers at 1.0:**

| Part | Gate |
|---|---|
| System calls in the pinned release (x86-64, arm64, riscv64) | 100% implemented, none returning `ENOSYS` except the ones Linux itself returns `ENOSYS` for in the reference configuration |
| Subsystem independent ioctls (tty, block, loop, fs, `FIONREAD` family, seccomp, userfaultfd, perf, KVM, DRM core, input, evdev, uinput, ntsync, vfio) | 100% |
| Netlink families with YNL specs, plus rtnetlink, nf_tables, genetlink control, audit, uevent, sock_diag | 100% of the families; messages and attributes 100% of those reachable by the corpus, with the rest enumerated |
| Device ioctls | 100% for each driver rukernel has |
| procfs and sysfs | 100% of paths and formats the reference exposes under the corpus, in the same configuration |
| gVisor syscall suite, LTP, kselftest | the same pass set as the reference, with every exception listed and justified (document 18.5) |
| Distribution images (Debian, Ubuntu, Fedora, Arch, Alpine, NixOS) | boot to multi-user, pass their own smoke tests |
| Container images (the top 200 on Docker Hub, by digest) | each image's entrypoint runs and passes its health check under Docker, Podman and Kubernetes (containerd + runc and crun) |

**How it is measured.** The five levels of document 18:

- L1: generated ABI equality, meaning tables, layouts and constants.
- L2: system call suites.
- L3: subsystem suites (fstests, blktests, kselftest net and bpf, CRIU).
- L4: distribution and container corpus.
- L5: real world scenarios (games, IDEs, databases, browsers, build farms).

Each is differential against real Linux in an identical VM, so the oracle is never our reading of a man page.

**What does not count:**

- Passing a test by special casing it.
- Matching on one architecture only.
- A program that runs but produces different output.
- A program that runs only with a rukernel specific flag.

## 2.2 Axis two: performance parity

**The claim.** For each workload class, rukernel's median is within the class gate of Linux's median, on the same hardware, with the same mitigations, compared against the better of Linux's distribution and tuned configurations.

The classes and gates are in document 19.1: kernel entry 5%, scheduling 5% on throughput and 10% on p99, memory 10%, scalability "no worse past 8 CPUs", storage 5%, file system metadata 10%, networking 5% on throughput and 10% on p99, applications 5%.

**Why per class.** A geometric mean over classes lets a kernel be 30% slower at `fork` and 10% faster at `getpid` and call itself equal. Users do not run a geometric mean.

**Why "better of the two" configurations.** If rukernel beats the distribution configuration only because the distribution leaves something off, we have measured Fedora's choices, not our kernel.

**What does not count:**

- Disabling mitigations on one side.
- Comparing across machines or days.
- Reporting the best run.
- Benchmarks chosen after the results were known.

The reporting rules in document 19.8 apply to every public number.

**Where rukernel may be faster**, and why that does not offset anything elsewhere: a Rust kernel can skip some of Linux's defensive checks because the type system already proved them (bounds checks on internal structures are elided where indices are typed), and it avoids some indirect calls through static dispatch. Document 21 estimates these at a few percent on specific paths. They are reported but never netted against losses.

## 2.3 Axis three: programs from other systems

**Windows.** The claim: rukernel runs the Windows programs that the same pinned Wine and Proton builds run on Linux 7.3, at the same success rate and at the same or better frame rate and frame time distribution. The measurement is the L5 game list: the 300 most played Steam titles that are rated Gold or better on ProtonDB and use no kernel anti cheat, plus a list of desktop applications (Office 2016, Photoshop CS6, Notepad++, 7-Zip, Steam itself, Visual Studio Build Tools). Each runs on both kernels, with frame time traces from MangoHud.

**macOS.** The claim at 1.0 is tier D1 only, as defined in document 16.4: command line Mach-O binaries for x86-64 and arm64 run unmodified against a Darwin user land built from Apple's open source and Darling. The measurement is a corpus of Homebrew bottles and Apple's open source command line tools, each with its own test suite, run on rukernel and on a Mac running the same version of macOS.

**Cross ISA.** x86-64 Linux binaries on arm64 rukernel through FEX and Box64, with the same success rate as on arm64 Linux and the TSO prctl where the hardware supports it.

**What does not count:**

- Programs that need a Windows kernel driver or a macOS kernel extension. These are listed and excluded by rule, not by test result.
- Closed Apple frameworks. They are not shipped or loaded.

## 2.4 Axis four: safety

The claim: a memory safety or data race bug in rukernel can exist only in `rk-frame`, the audited leaf crates, or the compiler.

**The measures:**

| Measure | Gate at 1.0 |
|---|---|
| Lines containing `unsafe` outside `rk-frame` and the 23.3 list | 0, enforced by the build |
| Lines of code in `rk-frame` | under 25,000 |
| `rk-frame` public API functions with a Verus specification | 100% |
| `rk-frame` functions with a completed proof | the page table, frame allocator, RCU, and lock primitives at 1.0; the rest by R12 (document 22) |
| KASAN class findings from syzkaller in safe crates | 0 (a finding is a bug in `rk-frame` or the toolchain, triaged as such) |
| Kernel panics from syzkaller per CPU-day | at most Linux's rate on the same descriptions, falling every release |

Safety is not only memory safety. A logic bug that leaks a capability, mishandles a credential or breaks namespace isolation is as bad as a use after free. Document 13 covers how the type system helps there (credentials as capabilities that cannot be forged, namespaces as typed handles), and document 20 covers the testing.

## 2.5 Axis five: tracking upstream

The claim: rukernel follows mainline, not a frozen version.

| Measure | Gate |
|---|---|
| ABI regenerated after a mainline tag | within 7 days |
| `ABI-CHANGES-<from>-<to>.md` published | with the regeneration |
| Compat run against the new reference | from day one |
| Every new system call, flag, ioctl and pseudo file implemented or listed with an issue | within one release cycle (about 63 days) |
| Longterm reference supported | the current newest longterm (6.18 now), selectable with `rukernel.abi=6.18` |

Document 17 has the pipeline.

## 2.6 What 100% is not

The number is 100% of the defined interface, with the exceptions listed and argued. It is not a claim that every Linux kernel behaviour is reproduced:

- **Loadable modules.** Linux `.ko` files do not load (document 12.6). Their functionality is built in where we support it.
- **Hardware coverage.** We drive the hardware in document 12's list. Linux drives far more.
- **Kernel internal interfaces.** These are out of scope by definition. That covers `kallsyms` addresses, `/proc/kcore` contents and the exact text of debug messages, except where a tool depends on them, which document 18.5 settles case by case.
- **Bugs.** Where Linux's behaviour is a bug that programs depend on, we match it. Where it is a bug nothing depends on, and Linux has since fixed it, we follow the fix. Both are recorded.
- **Timing.** Races in programs that happen to win on Linux and lose on rukernel are found by the differential and investigated. A program that is correct only by Linux's accidents of timing is reported upstream to the program, and we do not promise to match the accident.

## 2.7 The order of the axes

When axes conflict, compatibility wins over performance, performance wins over elegance, and safety is not traded at all. A faster path that needs new `unsafe` outside `rk-frame` is not taken. A path that needs new `unsafe` inside `rk-frame` is taken only with a proof obligation and a benchmark that justifies it.

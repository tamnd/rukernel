# rukernel-compat: the compatibility harness

`github.com/tamnd/rukernel-compat` holds everything rukernel is tested against that somebody else wrote: the test suites, the corpora of real programs and images, the licenses they come with, and the harness that runs them against a real Linux and against rukernel and compares the two. It is built on the same rules as `rucc-compat`, and where a rule here looks pedantic it is because the rucc harness already found out what happens without it.

The kernel repository holds the kernel and nothing else. Keeping them apart is what stops a clone of the kernel from being a clone of LTP, glibc, fstests and a terabyte of container images, and it is what lets the harness be pointed at another kernel, Asterinas, gVisor, the FreeBSD linuxulator, on the same day and with the same scoring, which is how we find out whether a number is about us or about the test.

## 18.1 The one rule

**The oracle is a real Linux, not the man page.** A man page describes what the authors think the kernel does. The kernel does what it does, programs depend on that, and "compatible" means the second thing. Every comparison in this repository is a differential against a pinned Linux kernel running in the same VM shape on the same machine, and a case whose answer we cannot get from a real Linux is not compared.

The pinned reference is the latest stable of the newest mainline release (7.3, tagged 18 October 2026, and its 7.3.y stables as they appear; document 17 for how it moves), built from a kernel.org tarball checked by hash, with the configuration named in the run: `defconfig` plus the test fragment, or a distribution config copied unchanged out of the distribution's package (Fedora, Debian, Ubuntu, Arch), exactly as `rucc-kernel` pins them. A second reference, the newest longterm (6.18.y, supported to December 2028), runs the same cases so that "differs from 7.3" and "differs from what most machines in the world run" are separately visible.

## 18.2 The differential

`rkc run <suite>` boots the reference and rukernel in the same QEMU/KVM machine shape (same vCPU count, same memory, same virtio devices, same kernel command line options where they mean the same thing, same initramfs and the same root image by hash), runs the suite in each, and compares outcomes case by case.

Before either kernel runs, the harness makes them agree about everything a difference must not come from:

- **The clock.** Both guests boot with the same `CLOCK_REALTIME` seed from the harness and a paravirtual clock. Tests that print time are normalized only through a registered rule, never by a blanket regex.
- **The machine.** CPUID is pinned by passing the same `-cpu` model to QEMU, not `host`, because glibc picks `memcpy` implementations from CPUID, and a different `memcpy` turns into different `/proc/self/maps` and different timing.
- **The identity.** `uname -r` is a persona, exactly as `rucc` claims a `__GNUC__`. rukernel reports `7.3.0-rukernel` and the major and minor it reports are the ABI level it claims to implement. Programs gate on `uname` (glibc's `--enable-kernel` floor, Docker, systemd's `REQUIRED_KERNEL`), so a kernel that claims 7.3 must behave as 7.3 and the harness checks that the claim and the behaviour move together (17.4).
- **The randomness.** Both kernels boot with `nokaslr`-equivalent and a fixed `getrandom` seed for the comparison runs, and with real entropy for the soak runs, which are judged by outcome only.

### Outcomes, not a pass rate

Each case lands in exactly one row: `same`, `differs`, `crash` (the rukernel guest panicked, oopsed, or hung past the watchdog), `timeout`, `reference-fails` (the reference does not pass it either, so we have nothing to say), and `not-run` (a prerequisite is missing, with the missing thing named). A summary never adds `differs` to `crash`. A kernel that is wrong and a kernel that is unfinished are different news, and a summary that adds them together hides the one that matters.

### The trace differential

For cases that pass on both sides by exit status but might still differ, `rkc run --trace` records every system call on both sides and compares the sequences. On Linux the recorder is an eBPF program on the `raw_syscalls` tracepoints that writes number, arguments, return value and the bytes behind pointer arguments the syscall table marks as `out`. On rukernel it is the kernel's own `ktrace`, which writes the same record format from the syscall dispatcher. Neither side uses ptrace, because ptrace perturbs signal and scheduling behaviour and because rukernel's ptrace is itself under test.

A trace difference is reported as the first divergent syscall with the twenty before it. Most divergences are a different `errno`, a different struct layout in an output buffer, or a different ordering of directory entries, and all three are bugs on our side unless the reference is nondeterministic there. Known nondeterminism (readdir order on tmpfs is not one of them; Linux tmpfs order is deterministic and programs depend on it) is registered per syscall in `trace-rules.toml` with the reason.

## 18.3 The suites

Every suite is fetched by hash, unpacked into a cache, and never committed. A manifest per suite names the version, the license, how a case is judged, and the exclusions.

| Suite | What it is | Why it is here | How a case is judged |
|---|---|---|---|
| gVisor syscall tests (`test/syscalls`) | ~250 gtest binaries, thousands of cases, written to pass on native Linux | The closest thing to an executable Linux ABI spec that exists; gVisor wrote it because it had exactly our problem | gtest result per case |
| LTP | ~4,000 tests across syscalls, mm, fs, net, containers, controllers, Open POSIX | Breadth, and the corner cases kernel maintainers already found | LTP result codes, `TCONF` is `not-run` with its message |
| kselftest | `tools/testing/selftests` from the pinned tree, per collection | Written by the people who wrote each feature, updated in lockstep with the feature | TAP per program |
| fstests (xfstests) | the generic and per-filesystem groups | The only credible oracle for filesystem semantics | fstests result, `_notrun` is `not-run` |
| blktests | block layer, NVMe, loop, nbd, zoned | Block and NVMe passthrough uAPI | result per case |
| libc suites | glibc `make check`, musl `libc-test`, bionic tests | A libc test is a test of the kernel underneath it as much as of the libc | per test |
| language runtimes | Go `syscall`, `os`, `net`, `runtime` tests; Rust `std` tests; CPython `test` package; Node.js `test/parallel`; OpenJDK jtreg `java/nio`, `java/net`, `java/lang/ProcessBuilder` | Runtimes exercise epoll, signals, futexes, `clone3`, `pidfd`, `io_uring` and `/proc` in exactly the way real programs do | per test |
| CRIU `zdtm` | checkpoint and restore of hundreds of process shapes | CRIU reads nearly every corner of `/proc` and every piece of task state; if CRIU can dump a rukernel process, `/proc` is right | per test |
| runc, crun, containerd, podman integration suites | OCI runtime tests | namespaces, cgroup v2, mount API, seccomp, idmapped mounts | per test |
| systemd test suite and `TEST-*` integration tests | the init system's own tests | systemd uses nearly every modern interface: pidfd, cgroup v2, BPF (cgroup programs, LSM BPF), mount API, fanotify, namespaces, `name_to_handle_at` | per test |
| syzkaller | coverage guided fuzzing from syzkaller's syscall descriptions | Finds crashes; the descriptions double as a machine readable ABI inventory (document 04) | crash or no crash; reproducer kept |

The gVisor suite is first because it is designed for exactly this: each test runs on native Linux in gVisor's own CI, so a failure on rukernel is unambiguous. LTP is second because of breadth. kselftest is the one that moves with every release, and it is the main input to document 17's upstream tracking: a new kselftest collection in 7.4 is the first concrete statement of what 7.4 added.

KUnit is deliberately not in the table. KUnit tests are kernel internal: they call kernel functions, not system calls, so they test Linux's implementation, not its interface. Where a KUnit test encodes an interface fact (the `printk` format specifiers, the time conversion tables, the `bitmap` parse format behind `/proc` and `/sys` cpu lists) the fact is ported into a rukernel unit test and linked from the manifest, and the port is checked against the KUnit source on every pin bump.

## 18.4 The levels

Compatibility is reported at five levels with their own denominators, because "passes 92% of LTP" and "boots Fedora" are claims about different things and one number cannot carry both.

**L1, the static floor.** A static busybox and a static Go binary run as PID 1 and complete a scripted session: shell, `ps`, `mount`, `ip`, `wget` against the harness. Denominator: the scripted steps.

**L2, the syscall level.** The gVisor syscall suite, LTP `syscalls`, and kselftest collections for the core (`clone3`, `pidfd`, `futex`, `rseq`, `mm`, `mount_setattr`, `filesystems`, `exec`, `timens`, `signal`, `seccomp`, `landlock`, `io_uring` via liburing's tests). Denominator: cases the reference passes. Reported per syscall family against the inventory from document 04, so a reader can see that `epoll` is at 100% and `fanotify` is at 40% rather than both being averaged into 85%.

**L3, the subsystem level.** fstests on ext4, xfs, btrfs, tmpfs and overlayfs; blktests; LTP `net`, `containers`, `controllers`, `mm`; the netlink and nftables selftests; the BPF selftests (`test_progs`, `test_verifier`). Denominator: cases the reference passes on the same configuration.

**L4, the distribution level.** Unmodified distribution images boot to a login and pass a scripted session and their own smoke tests: Debian 13, Fedora 44 and 46, Ubuntu 26.04 LTS, Alpine edge, Arch, NixOS. Then the top 200 images on Docker Hub by pull count run their own `HEALTHCHECK` or a scripted smoke per image under podman and under Docker on rukernel. Denominator: images, each green or red with the first failure named.

**L5, the application level.** The programs that are hard because they use everything: Chromium and Firefox with their sandboxes on (seccomp-bpf, user namespaces, `memfd`, `pidfd`), the JVM with its signal based safepoints, PostgreSQL with `huge_pages=on` and `io_uring`, QEMU with `/dev/kvm`, Firecracker, Docker in Docker, Kubernetes (kind) bringing up a cluster, Steam with Proton running a pinned set of games, `perf` and `bpftrace` against rukernel's own tracepoints, CRIU dumping and restoring a running PostgreSQL. Each is a named scripted scenario. Denominator: scenarios.

A release says its number at every level. A release that moves L2 up and L4 down says so in the same sentence.

## 18.5 Exclusions, settled cases and the register

Every manifest carries the cases that do not pass yet as `[[exclude]]` entries, and every one names the issue in `tamnd/rukernel` that will take it off the list. A manifest with an exclusion that names no issue does not load. A whole run fails on a stale entry: a case that now passes while its exclusion is still listed, or an exclusion naming a case the suite does not have. That is what stops the list from becoming the place a regression goes to be quiet.

An exclusion carries the outcome it covers. An entry for `crash` does not cover a case that now runs and `differs`; the run fails and somebody updates the entry, because a crash turning into a wrong answer is progress worth seeing and a wrong answer turning into a crash is a regression worth seeing.

`[[settled]]` is the other kind: a behaviour where rukernel has decided it will differ from Linux on purpose and no issue will ever close it. Each names the section of this specification where the decision is argued. There are deliberately few. The candidates known today:

- `/proc/kallsyms`, `/proc/kcore`, `/sys/kernel/debug` contents: rukernel exports its own symbols, not Linux's, so a test that greps for a Linux function name is settled (document 11 explains why `kprobe` attach by Linux function name is mapped through an alias table where it can be and refused where it cannot).
- `init_module` and `finit_module` with a Linux `.ko`: refused with `ENOEXEC` (document 12.6).
- Anything that reads `/dev/mem` or `/dev/port` for real hardware state.
- `uname -v` build strings, `/proc/version` compiler string.

`[[untrustworthy]]` is the third kind, borrowed directly from rucc-compat's `screen`: a test the reference itself passes only by accident. LTP and kselftest both contain tests that race, that depend on the host's CPU count, or that pass on Linux because of timing. The harness runs every case on the reference five times before it is allowed to grade rukernel, and a case that does not give the same answer five times is written down here with what it did, rather than silently failing on rukernel some nights.

## 18.6 The image corpus

L4 and L5 need real programs, and real programs come as distribution images and container images. The corpus is a list of references by digest (`docker.io/library/postgres@sha256:...`, Fedora `Cloud-Base` qcow2 by its published checksum), a license tier for each, and the scenario that exercises it. Nothing is committed; `rkc fetch` pulls into the cache and verifies the digest.

The corpus is refreshed on a schedule rather than continuously. A refresh is a pull request that changes digests, and its CI run is the moment a new upstream image version shows up as a regression, which keeps "our kernel broke" and "the image changed" in different commits.

## 18.7 The ABI coverage report

`rkc coverage` joins three things: the inventory from document 04 (every syscall, every ioctl command, every netlink message type, every `/proc` and `/sys` file, every `prctl` and `fcntl` command, every socket option, every `io_uring` opcode, every BPF helper and program type), the coverage rukernel's `ktrace` recorded during a sweep, and the outcomes. It prints, per entry, whether rukernel implements it, whether anything in the corpus reached it, and whether everything that reached it got the same answer.

The useful output is the two lists at the bottom. **Implemented and never reached** is code nothing tests, which is where dead or wrong entries collect. **Reached and not implemented** is the priority list for the next milestone, ordered by how many distinct programs in the corpus hit it. That second list is what decides what gets built next. It replaces opinion with a count, which matters for a surface this large.

## 18.8 Running it

```
cargo build --release
./target/release/rkc list
./target/release/rkc fetch gvisor-syscalls ltp
./target/release/rkc run gvisor-syscalls --kernel ../rukernel/target/x86_64/rukernel.efi --reference 7.3 --report
./target/release/rkc run ltp --unit syscalls --trace --jobs 8
./target/release/rkc image docker-top200 --runtime podman
./target/release/rkc coverage results/*.cov --report
```

`--jobs` defaults to half the host's CPUs, for the reason rucc-compat gives: timeouts are judged on a wall clock and an oversubscribed host turns slowness into failure. Results come back in case order whatever the setting, because a report whose rows move between runs cannot be diffed.

## 18.9 CI

Per pull request to rukernel: L1 in full, the gVisor suite and LTP `syscalls` on x86-64 under KVM, the kselftest core collections, and the trace differential on a fixed sample of 300 cases. Budget: 25 minutes.

Nightly: everything at L2 and L3 on x86-64 and arm64, L4 for the distribution images, syzkaller for eight CPU hours with any new crash filed automatically with its reproducer, and the coverage union.

Weekly: L4 container corpus and L5 scenarios, and the second reference (the longterm kernel).

On each upstream release (document 17): the whole thing against the new reference before the reference pin is moved, so the first report after a release is "what 7.4 changed that we do not yet do", and it exists the day 7.4 is tagged.

## 18.10 House style

Plain English, one paragraph per line, no em or en dashes, no horizontal rules, enforced by `scripts/style.sh` as in the other repositories. Apache-2.0 for the harness; every fetched suite under its own license and never stored here.

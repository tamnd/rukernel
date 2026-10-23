# rukernel-bench: the performance harness

`github.com/tamnd/rukernel-bench` measures rukernel against Linux on the same machine, with the same userland, the same configuration intent and the same workload, and publishes every number including the ones we lose. It follows `rucc-bench`, `rupg-bench` and `rudb-bench`: reporting rules first, workloads second, because a benchmark number without its methodology is marketing, and the project's claim on the performance axis (document 02) is only as credible as its honesty about the losses.

## 19.1 What "same performance as Linux" means

Document 02 states the claim as a number per workload class, not as one geometric mean, because a kernel is several different machines glued together and a geometric mean over them hides exactly the regression a user will hit. The classes:

| Class | Representative | Gate at 1.0 |
|---|---|---|
| Kernel entry | `getpid`, `clock_gettime` (vDSO), `read` of 1 byte from `/dev/zero`, `futex` wake with no waiter | within 5% of Linux, same mitigations |
| Scheduling | context switch via pipe ping-pong, `hackbench`, `schbench` p99 wakeup latency, `perf bench sched messaging` | within 5% on throughput, within 10% on p99 |
| Memory | page fault (anon, file, THP), `mmap`/`munmap` churn, `fork` of a 1 GiB process, `madvise(DONTNEED)` | within 10% |
| Scalability | `will-it-scale` (all testcases, threads and processes, 1 to N CPUs) | no testcase scales worse than Linux past 8 CPUs |
| Storage | `fio` 4k random read/write and 128k sequential via `io_uring` and `libaio`, on NVMe and virtio-blk; fstests runtime | within 5% IOPS and p99 on the same device |
| Filesystem metadata | `fs_mark`, `dbench`, `git status` on a large tree, kernel untar and `make -j` | within 10% |
| Networking | `netperf`/`neper` TCP_RR and TCP_STREAM, `sockperf` UDP latency, `iperf3`, loopback and virtio-net and a real 100 GbE NIC | within 5% throughput, within 10% p99 |
| Applications | nginx + `wrk`, Redis/Valkey + `memtier`, PostgreSQL `pgbench` TPC-B and read only, MySQL `sysbench` OLTP, memcached, SQLite `speedtest1`, kernel build | within 5% |

"Within 5%" means the median of rukernel is no more than 5% worse than the median of Linux, and the Mann-Whitney U test at p < 0.01 cannot reject "not worse than 5%". Better than Linux is reported as better; it is not the goal and does not offset a loss elsewhere.

The gate is per workload, and a release whose table has a red row says which row in the release notes.

## 19.2 The comparison, stated exactly

**Linux** is the same pinned stable as the compat reference (document 18.1), built from kernel.org by hash with the configuration named in the run. Two configurations are always run, because they answer different questions:

- **distro**: the Fedora configuration for that release, unchanged. This is what users run and the honest comparison for "can I replace my kernel".
- **tuned**: the distro configuration with the options a performance team would set for the workload (`PREEMPT_LAZY` or `PREEMPT_NONE` as appropriate, `HZ=1000`, transparent huge pages `always` for the memory class, the right I/O scheduler). rukernel is compared against the better of the two and says so.

**Mitigations** are matched, not disabled. Both kernels run with the CPU vulnerability mitigations the CPU needs (retpoline or eIBRS, IBPB on context switch where Linux does it, the same `spectre_v2` and `retbleed` mode), and `/sys/devices/system/cpu/vulnerabilities/*` must read the same on both, which the harness checks before it measures anything. A run with `mitigations=off` is a separate, labelled series. A syscall latency comparison where one side has mitigations and the other does not is the single most common dishonest kernel benchmark, and this rule exists to make it impossible here.

**Other rows.** Asterinas (the closest prior art, a Rust framekernel with a Linux ABI), gVisor with the systrap platform (as the floor a user-space Linux ABI pays), and FreeBSD with the linuxulator for the application class. They run where they can run the workload, and "does not run" is a row, not an omission.

**Userland** is byte identical: the same root image by hash, the same glibc, the same binaries, the same `sysctl` values where both kernels accept them (and a listed difference where rukernel does not).

## 19.3 Machines

Never compare across machines, and never compare against a number from a different day on the same machine without rerunning the baseline. The reference fleet, named in `machines.toml` with CPU, microcode, BIOS settings, memory, NIC and disk:

- x86-64 server: 2-socket AMD EPYC (Zen 5) and 1-socket Intel Xeon (Granite Rapids), bare metal, NVMe, 100 GbE.
- arm64 server: Ampere or Graviton class bare metal.
- arm64 laptop: Apple M-series under Asahi, for the desktop scenarios.
- VM: the same workloads under KVM on the x86 server, because most kernels in 2026 run as guests and the virtio path is the one most users see.

Bare metal and VM numbers are separate series.

## 19.4 Methodology

Pinned CPU frequency with boost disabled where the platform allows; isolated measurement cores; the harness process on a separate core; SMT state recorded and fixed; the same NUMA placement on both kernels, enforced by the harness with `numactl` and checked in `/proc/self/status`.

Ten runs minimum per cell, more when the measured coefficient of variation is above 2%. Median and IQR reported, never a minimum, never a single run. Warm-up runs discarded and counted. Every run records the kernel's own counters before and after (context switches, page faults, interrupts per CPU, softirqs) from `/proc`, which on rukernel doubles as a check that those counters mean the same thing.

Latency is reported as a distribution: p50, p99, p99.9 and max, from HDR histograms, with coordinated omission corrected in the open loop generators (`wrk2`, `memtier --rate`).

Hardware counters alongside time: instructions, cycles, IPC, LLC misses, iTLB and dTLB misses, branch misses, per run, from `perf stat` on Linux and from rukernel's `perf_event_open` implementation, which must count the same events (if it does not, that is a compat bug filed against document 11 before it is a benchmark result). Instructions in kernel mode per operation is the most diagnostic single number a kernel benchmark produces, and it is in every row.

## 19.5 Attribution

A number that says "slower" without saying where is not actionable. Every nightly cell also records:

- a `perf record` profile of both kernels for the workload at a fixed sampling rate, kept for 90 days, symbolized against each kernel's own symbols;
- for the entry class, a cycle breakdown of the syscall path (entry, dispatch, work, exit, mitigations) from rukernel's built in path timers, which compile to nothing in release builds and to `rdtsc` pairs in the `bench` profile;
- lock contention from rukernel's lock statistics, which are always on at a cost the entry class benchmark itself bounds.

The comparison report pairs the two profiles by function role through a hand maintained map (`linux:__schedule` with `rukernel:sched::switch`), so a 7% loss on `hackbench` arrives as "4 points in wakeup, 3 points in the runqueue lock".

## 19.6 Workload definitions

Each workload is a directory with a `bench.toml`: the binary and its version by hash, the command, the parameters swept, the metric and its direction, and the gate. Parameters are swept, not chosen: `will-it-scale` at 1, 2, 4, 8, 16, 32, 64 and all CPUs; `fio` at queue depths 1, 4, 32, 128 and 1, 4, 16 jobs. A kernel tuned for one point of a sweep and bad at the rest is a common result and the sweep is what shows it.

The suites drawn from, not reinvented: LMbench 3 (latency and bandwidth primitives), `will-it-scale`, Intel's `lkp-tests` job definitions, Mel Gorman's MMTests configurations (the suite SUSE uses for scheduler and mm regressions), `perf bench`, `schbench`, `hackbench`, `fio`, `neper`, `netperf`, `sockperf`, and the Phoronix Test Suite profiles for the application class where their versions can be pinned.

## 19.7 Regression gates

Every nightly writes one row per cell: kernel commit, reference version, machine, workload, parameters, metric, median, IQR, n. The gate on a pull request is computed from that cell's own measured noise over the last 30 nightlies, not a global percentage, because a cell with 0.3% noise and one with 5% need different thresholds and one global threshold makes one of them useless. A move outside the gate blocks the merge unless the pull request states the trade ("costs 2% on `getpid` and closes a speculative execution gap" is an acceptable and obviously correct trade).

The rule that matters most: **a performance change ships with the number that justifies it.** An optimization that does not move a benchmark in this harness is complexity without evidence, and in a kernel complexity is where the bugs live.

## 19.8 Reporting rules

These apply to the README, release notes, the dashboard and any talk or post.

1. State the comparison exactly: which Linux, which config, which mitigations, which machine, bare metal or VM.
2. Report the distribution, not the best run.
3. Report the whole table, including the losses, in the same table as the wins.
4. State what did not run and why.
5. Never compare across machines.
6. Every public number is reproducible by a command: `rkb run --suite entry --machine epyc-z5 --compare linux-7.3:distro`.
7. Never call a result "Linux performance" unless every class in 19.1 is green. "Within 5% of Linux on storage and networking, 12% behind on fork" is a sentence we are allowed to write. "Linux-class performance" is not, until it is true.

## 19.9 House style

Same as the other repositories: plain English, one paragraph per line, no em or en dashes, charts drawn deterministically from committed data, Apache-2.0.

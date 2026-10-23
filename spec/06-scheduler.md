# The scheduler

The scheduler is the subsystem where "compatible" and "same performance" are the same requirement. No program calls the CFS or EEVDF algorithm by name. Every program's latency and throughput depend on it, and a growing number of programs (games under Proton, audio servers, databases, `systemd` slices, Kubernetes) are tuned against its specific behaviour. So the policy is: **implement the Linux scheduling classes with the Linux algorithms, and measure equivalence**, and spend the novelty budget elsewhere.

## 6.1 Classes

Linux's class hierarchy is ABI because `sched_setattr` names the policies and because the order of precedence between them is observable. rukernel implements the same stack, in the same priority order:

1. **stop**: per CPU, highest, for migration and `stop_machine`. Internal.
2. **deadline** (`SCHED_DEADLINE`): EDF with constant bandwidth server, admission control on `sched_setattr`, `SCHED_FLAG_RECLAIM` (GRUB), `SCHED_FLAG_DL_OVERRUN`, and the deadline server that Linux added in 6.12 to give the fair class a guaranteed share against RT starvation.
3. **rt** (`SCHED_FIFO`, `SCHED_RR`): 100 static priorities, per CPU runqueues with push and pull balancing, RT throttling through `sched_rt_runtime_us` (now realized by the fair deadline server), priority inheritance through rt-mutexes.
4. **fair** (`SCHED_NORMAL`, `SCHED_BATCH`, `SCHED_IDLE`): EEVDF (6.6), section 6.2.
5. **ext** (`SCHED_EXT`): sched_ext (6.12), section 6.4. Placed where Linux places it, with the same fallback to fair on error or watchdog expiry.
6. **idle**: per CPU idle task and the cpuidle governors.

## 6.2 The fair class: EEVDF

Linux replaced CFS's pick logic with EEVDF in 6.6 and removed the remaining CFS heuristics over the following releases. rukernel implements EEVDF as specified by Stoica and Abdel-Wahab and as refined in Linux: virtual runtime, lag, eligibility (`vruntime <= avg_vruntime`), virtual deadline `vd = ve + r/w`, the augmented red-black tree keyed on deadline with the min-vruntime augmentation for O(log n) eligible pick, lag preservation across sleep with the decay rule, `sched_attr.sched_runtime` as the request size (the latency hint userspace can set per task since 6.12), and placement of waking tasks.

Weights come from the same 40 entry `sched_prio_to_weight` table, so `nice` means exactly what it means on Linux. A program that sets nice 19 for a background job and measures its share is checking a number, and that number must match.

**Group scheduling** (cgroup v2 `cpu.weight`, `cpu.max` bandwidth, `cpu.idle`, `cpu.uclamp.*`) uses hierarchical runqueues with per CPU group entities as in Linux, because the alternative (flattened weight computation) gives different shares under contention, and Kubernetes and systemd slices are configured against Linux's behaviour.

**Load tracking** is PELT (per entity load tracking) with the same 32 ms half life, because PELT signals drive load balancing, schedutil frequency selection, energy aware scheduling and uclamp, and every one of those has observable effects. `/proc/<pid>/sched` exports the same fields.

## 6.3 SMP: load balancing and topology

Scheduling domains built from the topology (SMT, cluster, MC/LLC, die, NUMA levels with distances from ACPI SLIT and SRAT or the device tree), with the same balancing intervals and imbalance calculations as Linux's `find_busiest_group` family, idle balancing, nohz idle balancing, wake affine logic, `select_idle_sibling` for LLC local wakeups, and NUMA balancing (task placement and page migration driven by NUMA hinting faults, document 07.7).

Topology is exposed exactly as Linux exposes it: `/sys/devices/system/cpu/cpu*/topology/*`, `/sys/devices/system/node`, `/proc/cpuinfo`, and the `sched_getaffinity` masks. hwloc, the JVM, Go's runtime, databases and `numactl` read these, and a wrong topology is a performance bug that looks like a compatibility pass.

**Energy aware scheduling** for asymmetric systems (Arm big.LITTLE and DynamIQ, Intel hybrid with P and E cores, Apple M-series under Asahi) uses the energy model and capacity awareness, with `schedutil` as the cpufreq governor. Intel's hybrid systems additionally need ITMT and the hardware feedback interface (HFI) or Thread Director hints, which Linux consumes. This matters for laptops, which is where desktop users will first try rukernel.

## 6.4 sched_ext

sched_ext lets user space load a scheduler as a set of BPF programs implementing `struct sched_ext_ops` callbacks (`select_cpu`, `enqueue`, `dispatch`, `running`, `stopping`, and the rest), with dispatch queues (DSQs) and kfuncs. Since 6.12 it is part of mainline, and the `scx` project ships production schedulers (`scx_lavd` for gaming on the Steam Deck, `scx_rusty`, `scx_bpfland`, `scx_layered` used at Meta) that people run today.

rukernel implements sched_ext as a host for BPF programs exactly as Linux does, which means:

- the `struct_ops` attach mechanism and the `sched_ext_ops` layout from BTF (document 11);
- every sched_ext kfunc (`scx_bpf_dsq_insert`, `scx_bpf_dsq_move_to_local`, `scx_bpf_kick_cpu`, `scx_bpf_create_dsq`, the cpumask and idle CPU kfuncs, and the rest) with Linux's names, signatures and semantics, discoverable through rukernel's BTF so libbpf's CO-RE relocation works;
- the watchdog, the `SCX_OPS_*` flags, the error exit path that returns all tasks to the fair class, and `/sys/kernel/sched_ext/*`;
- compatibility with the `scx` user space loaders unmodified.

Linux keeps extending it, and each extension is part of the target: the deadline server covers sched_ext tasks since 7.0, topological CPU IDs arrived in 7.2, and 7.3 completed **sub-schedulers**, where a root BPF scheduler delegates cgroup subtrees to child schedulers with revocable CPU grants. A 7.3 compatible kernel must host that hierarchy.

This is the most important single choice in this document, for two reasons. First, sched_ext schedulers are now part of what users run: SteamOS ships `scx_lavd`, CachyOS offers several, and a kernel that cannot load them is not compatible with those systems. Second, it gives rukernel a policy escape hatch that costs nothing in compatibility. Any scheduling experiment can be done as a sched_ext program loaded on both Linux and rukernel, compared directly in `rukernel-bench`, and promoted into the built in fair class only if it wins on both.

## 6.5 Preemption models

`PREEMPT_LAZY` (6.13) is the default, as described in document 03.4, and `PREEMPT_FULL` is selectable at boot with `preempt=`. Linux 7.0 removed `PREEMPT_NONE` and `PREEMPT_VOLUNTARY` on most architectures, leaving exactly these two, which simplifies our matrix: `preempt=none` and `preempt=voluntary` are accepted and mapped to lazy, as Linux 7.x does, so old kernel command lines still boot. `PREEMPT_RT` is a build profile; with it, `/sys/kernel/realtime` reads 1 and cyclictest latency on the reference machines is a `rukernel-bench` gate.

## 6.6 Recent upstream mechanisms we implement

These are recent enough that a reimplementation could miss them and old enough that programs or distributions now rely on them:

- **Proxy execution**: a mutex owner runs on the waiter's scheduling context so that a high priority waiter's time is spent unblocking it. The first parts were merged in 6.17 behind `CONFIG_SCHED_PROXY_EXEC`, and donor migration across CPUs in 7.2. We implement it on `Mutex` and `RwSem` as upstream does, in the same stages.
- **Cache aware scheduling** (7.2): wakeup and balancing prefer keeping tasks that share data in one LLC.
- **Group scheduling modes** (7.3): the single cgroup runqueue and the `concur` default. The mode switch lives in debugfs and is not stable ABI, so we implement the default behaviour and track the knob without promising it.
- **The fair deadline server** (6.12), mentioned above.
- **Delayed dequeue** for sleeping tasks with negative lag (6.12), which EEVDF needs for correct lag accounting.
- **Per task latency hints** through `sched_attr.sched_runtime` on fair tasks.
- **Core scheduling** (`PR_SCHED_CORE`) for SMT side channel isolation, which ChromeOS and some cloud providers use.
- **Time slice extension** for user space lock holders (7.0): a thread marks itself in its `rseq` area as being in a critical section, the scheduler grants a short extension instead of preempting, and the thread gives the time back with `rseq_slice_yield` (syscall 471).
- **cgroup v2 `cpu.idle`** and `SCHED_IDLE` semantics, used by systemd for background slices.

## 6.7 Timers, ticks and idle

Tickless idle (`NO_HZ_IDLE`) by default and full tickless (`NO_HZ_FULL` with `nohz_full=` and `isolcpus=`) for latency sensitive deployments; hrtimers on a per CPU timer wheel and red-black tree split as in Linux (the timer wheel for coarse timeouts, hrtimers for precise ones), timer slack (`PR_SET_TIMERSLACK` and `/proc/<pid>/timerslack_ns`), and timer migration to non idle CPUs. cpuidle with the `menu` and `teo` governors, `intel_idle` and ACPI `_CST`, and `/dev/cpu_dma_latency` and PM QoS for programs that request low wakeup latency (audio, trading systems).

## 6.8 What is exported

`/proc/schedstat` (version 17 format), `/proc/<pid>/sched`, `/proc/<pid>/schedstat`, `/proc/pressure/{cpu,memory,io,irq}` (PSI, used by systemd-oomd, Android's lmkd and Facebook's oomd, including PSI triggers through `poll`), `/sys/kernel/debug/sched/*` where tools read it, the `sched:*` tracepoints with Linux's field names and formats (`perf sched`, `bpftrace` scripts and `scx` tooling depend on them), and `sched_getattr` reporting exactly what was set.

## 6.9 How equivalence is measured

The scheduler has no oracle that says "correct". It has distributions. `rukernel-bench`'s scheduling class (document 19.1) runs `hackbench`, `schbench`, `perf bench sched`, `cyclictest`, the MMTests scheduler configurations and the application set on both kernels, and the scheduler is accepted when the distributions match within the gates. Beyond the benchmarks, two specific checks:

- **Share fidelity**: a test matrix of CPU hogs at different nice values, cgroup weights and bandwidth limits, measuring each task's share over 60 seconds on both kernels. Shares must match within 1 percentage point.
- **Wakeup placement fidelity**: a trace differential on `sched_wakeup` and `sched_switch` events for a fixed workload, comparing the distribution of CPU choices (same LLC, same core, idle sibling) rather than exact decisions, since exact decisions depend on timing.

The kSTEP work at OSDI 2026, which drives the Linux scheduler deterministically to reproduce scheduler bugs, suggests a stronger third check: replay the same deterministic event sequence through both schedulers' pick logic in a user space harness and compare decisions exactly. Because `rk-sched`'s policy code is safe Rust with no hardware dependencies, it compiles as a normal user space library, and this harness is cheap to build. Document 20.5 describes it.

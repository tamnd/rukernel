# Verification and testing

The framekernel design (document 03) reduces the soundness of the whole kernel to the soundness of `rk-frame`'s public interface plus the compiler. This document is about making that reduction pay:

- prove `rk-frame` correct where proofs are practical,
- test everything else so that its logic matches Linux,
- and make the tests deterministic enough that a failure is a fact, not a flake.

Compatibility testing against Linux is document 18. This document covers correctness of the kernel itself.

## 20.1 The layers of assurance

| Layer | Applies to | Tool | Gate |
|---|---|---|---|
| Type system | everything | `rustc`, `#![forbid(unsafe_code)]` outside `rk-frame` | build fails |
| Proof | `rk-frame` core | Verus | proof checks in CI |
| Model checking | lock free and concurrent algorithms | loom, shuttle, and GenMC under LKMM | every interleaving up to the bound |
| UB detection | all `unsafe` code, in host unit tests | Miri, with Tree Borrows | clean |
| Fuzzing | system call surface | syzkaller | no new crash class per release |
| Sanitizers | whole kernel builds | KASAN-equivalent shadow in `rk-frame`, KCSAN-style data race detection, UBSAN for arithmetic | clean on the CI corpus |
| Unit and integration tests | every crate | `cargo test` on host, KUnit-style in-kernel tests | pass |
| Differential | the ABI | `rukernel-compat` | document 18 |

## 20.2 Proving `rk-frame` with Verus

Verus became practical for this job between 2024 and 2026:

- Verus itself was published at SOSP 2024.
- VeriSMo and Anvil won OSDI 2024 Best Paper awards.
- Atmosphere verified a whole Rust microkernel at a proof to code ratio of 3.3 to 1 in under 2.5 person years (SOSP 2025).
- Asterinas's `vostd` proved OSTD's page table and synchronization code and found real bugs.
- CortenMM verified a scalable memory manager and won SOSP 2025's Best Paper award.

rukernel starts from this body of work instead of retrofitting proofs later.

**What gets proved, in order:**

1. **The frame allocator.** Frames are never handed out twice, freed frames were allocated, metadata type `M` is fixed for a frame's lifetime, and per CPU caches conserve frames.
2. **Page tables.** The `VmSpace` interface maps, unmaps and protects exactly the ranges asked for. Kernel mappings are never reachable from user page tables. A frame mapped into a user space is reference counted for every mapping. TLB shootdown completes before a frame is reused. This is the property whose violation is a use after free through stale TLB entries, the most dangerous bug class in any kernel's mm.
3. **User memory access.** `UserPtr` copies touch only user addresses, faults are recovered, and the SMAP or PAN window is closed on every exit path.
4. **Locks and RCU.** Mutual exclusion for the spin lock and its IRQ variants. Grace period correctness for RCU: a callback runs only after every reader that could see the old pointer has exited. Preemption guard nesting.
5. **DMA and IOMMU.** A `DmaBuffer` is mapped only for its device. Unmapping invalidates the IOTLB before the frames are reused.
6. **Context switch and trap entry.** These are proved by specification and review rather than in Verus, because they are assembly. Their contracts (callee saved registers preserved, stack switched, FPU state owned by exactly one task) are stated in Verus and assumed. The assumption is listed in the trusted base.

**What is trusted and not proved:**

- `rustc` and LLVM.
- The assembly in entry and context switch.
- The hardware's behaviour as described in its manuals.
- The Verus tool.
- The specifications themselves.

The specifications are reviewed by people. Mistakes in them are the main residual risk, which is why they are kept short and why the differential tests also exercise `rk-frame` through the whole kernel.

**Proof effort and automation.** At Atmosphere's ratio, `rk-frame`'s roughly 25,000 lines would need around 80,000 lines of proof. That is a lot, and it is the reason the proof plan is staged across milestones (document 22: items 1 to 4 by R8, all by R12). KVerus generated 21% of CortenMM's proof code (arXiv 2605.03822), and VeruSAGE studies agent driven proof search. Machine assisted proof writing is used without restriction, because the proof checker is the judge: an incorrect proof does not check.

**CortenMM specifically.** CortenMM argues for making the page table itself the source of truth for an address space, with per page table node locking, instead of a separate VMA tree. That makes its proofs tractable and its scalability better. Linux's user visible behaviour around VMAs (`/proc/<pid>/maps`, `mremap` semantics, VMA merging rules that show up in `smaps`, the `mmap` placement algorithm) still has to be reproduced exactly. Document 07.5 takes CortenMM as a research experiment at R4. Whether it becomes the design is open question one in document 24.

## 20.3 Concurrency testing

Concurrency bugs are the class most likely to survive both the type system and testing. Rust prevents data races but not race conditions, deadlocks or ordering bugs in lock free code.

- **loom and shuttle** run every lock free structure in `rk-frame` and the safe crates (the RCU core, the per CPU caches, the seqlocks, the io_uring ring indices, the futex hash, the wait queues) under exhaustive or randomized interleavings on the host, in `cargo test`.
- **GenMC** checks the same algorithms under LKMM, the memory model rukernel targets (document 03.5), for the barrier placements loom cannot reason about, such as address and control dependencies.
- **The lock level check** (document 03.5) catches lock order inversions at compile time where levels are static. A lockdep style runtime validator catches them in debug builds where they are not.
- **The data race detector**, a KCSAN equivalent, samples memory accesses in `rk-frame`'s raw primitives at runtime in CI builds, to find races in the one place they are possible.

## 20.4 Fuzzing

**syzkaller** is the primary fuzzer, for three reasons. It understands the Linux system call surface through its descriptions, about 4,000 system call variants. Its descriptions apply unchanged to rukernel, because the ABI is the same. And the same corpus runs on Linux, so crashes can be compared.

- **Coverage:** rukernel exports KCOV-compatible coverage (`/sys/kernel/debug/kcov` with the same ioctls), so syzkaller's coverage guidance works without modification.
- **Scale:** a syz-manager instance runs continuously on the CI fleet, 64 VMs at a time. Nightly CI adds 8 CPU hours on the newest commit (document 18.9).
- **Triage:** crashes are deduplicated by the first rukernel frame. Each is filed with its reproducer and bisected automatically, as syzbot does. Linux's syzbot has 1,334 to 1,582 open bugs at the time of writing (document 01.1). The goal is a much smaller number, and a falling one.
- **Descriptions from KernelGPT style synthesis** (document 17.3) for interfaces syzkaller describes poorly, especially new ones in each release.

**Other fuzzers:**

- File system image fuzzing: mutated ext4, xfs, btrfs, squashfs and erofs images mounted in a loop. Document 08.7 argues that typed parsing removes the crash class. The fuzzer checks the argument.
- An AML interpreter fuzzer over firmware tables (document 15.4).
- A BPF program fuzzer that compares verifier verdicts against Linux (document 11.2).
- netlink message fuzzers driven by the YNL specs.
- `cargo fuzz` harnesses on every parser crate, in host builds.

## 20.5 The scheduler replay harness

Scheduler behaviour is hard to test because it is a function of timing. kSTEP (OSDI 2026) showed that Linux's scheduler bugs can be found deterministically by driving the scheduler from a controlled event sequence. rukernel builds that in from the start.

`rk-sched` is written so that its policy core (EEVDF, the load balancer, wakeup placement, bandwidth control, and the sched_ext core) is a pure state machine. Its inputs are an event stream: task creation, wakeup, block, tick, CPU hotplug, affinity change, cgroup weight change, migration request. Its outputs are decisions. The kernel feeds it real events. The replay harness feeds it recorded or generated ones on the host, with no hardware and no timing. That enables:

- **Property tests:** fairness bounds (lag stays within EEVDF's bounds), work conservation (no CPU idles while another has runnable tasks, beyond the balancing interval), bandwidth limits respected, and no starvation under sched_ext watchdog conditions.
- **Differential tests against Linux:** the same event trace, recorded on Linux through the `sched_*` tracepoints, is replayed into rukernel's core. The decisions are compared. Exact match is not expected, because placement heuristics have legitimate freedom. Fairness metrics, latency distributions and migration counts are compared within tolerances. A divergence in those is a finding.
- **Regression reproduction:** a field report with a `perf sched record` trace becomes a deterministic test case.

The same pattern, a pure core fed by an event stream, is used for the memory reclaim policy (MGLRU generations and aging) and for TCP congestion control, where it makes Linux's own packetdrill tests runnable without a network.

## 20.6 Testing in kernel and on host

- **Host tests.** Most crates compile for the host target as well as the kernel target, with `rk-frame` replaced by a host implementation (`rk-frame-host`) that simulates frames, page tables and CPUs in user space. This is where the bulk of unit tests, all loom tests and all Miri runs happen. It is fast, debuggable and parallel.
- **In kernel tests.** A KUnit compatible framework runs tests inside a booted rukernel and reports in KTAP format, the same format as Linux's KUnit, so the same CI parsers read both. Linux's KUnit tests for user visible behaviour (the `printf` format tests, the `bitmap`, `list` and `string` helpers, the time conversion tests) are ported where they test semantics rukernel shares.
- **Boot tests.** Every pull request boots rukernel on x86-64 and arm64 under QEMU, with and without KVM, to a minimal init that runs a smoke test and powers off. Budget: 2 minutes.

## 20.7 Debuggability

A kernel nobody can debug will not be adopted, however correct it is.

- **gdb** through QEMU's gdbstub and kgdb over serial, with full Rust debug info and pretty printers for the core types.
- **Oops output in Linux's format**: registers, the call trace with symbol and offset, the taint flags, and the `Code:` line. Tools that parse oopses (the kernel's `decode_stacktrace.sh`, abrt, distribution crash reporters) work, and so does the ordinary panic path (document 03.6).
- **ftrace-compatible tracing** in tracefs: the function tracer, the function graph tracer and the event tracers, as far as tools use them. perf, trace-cmd and bpftrace work against them (document 11.4).
- **`ktrace`**, rukernel's always available system call tracer, used by the trace differential (document 18.2), with output convertible to `strace` format.
- **`rkcrash`**, for vmcore analysis (document 15.3).

## 20.8 What "tested" means at a release

A release is cut when all of these hold:

- the proof suite checks;
- host tests, loom, Miri and in kernel tests pass on every architecture;
- the syzkaller instance has run at least 1,000 CPU hours on the release candidate with no unresolved crash;
- the fuzzers listed in 20.4 have run their release budget;
- the compat levels (document 18.4) are at or above the previous release's on every level;
- the bench table (document 19) has no red row the release notes do not name.

# The performance model

Document 19 says how performance is measured. This document says why rukernel can reach Linux's numbers and where it is at risk. Each fast path gets a budget, built from what Linux spends today and from what Rust adds or removes. A benchmark result that misses a budget is then a specific question, not a mystery.

## 21.1 Principles

1. **Same algorithms where they are observable or proven.** EEVDF, per VMA locks, RCU path walk, blk-mq, NAPI, GRO, MGLRU and sheaves are the product of decades of tuning against real workloads. rukernel uses them. Novelty is spent on safety and structure, not on second guessing Linux's performance work.
2. **No dynamic dispatch on hot paths where the set is closed.** Linux's operation tables (`file_operations`, `inode_operations`, `proto_ops`) are indirect calls. After Spectre v2 these cost either a retpoline (about 20 to 30 cycles extra) or an eIBRS predicted call, and Linux has spent years adding static calls and `INDIRECT_CALL_*` wrappers to avoid them. In Rust, where the set of implementations is known at build time (all built in, document 03.7), dispatch can be an `enum` match or a monomorphized generic. That is a direct branch the predictor handles well and the compiler can inline.
3. **No locks or allocations rukernel adds that Linux does not have.** A safe abstraction that needs an `Arc` clone, a lock or a heap allocation on a path where Linux does none is a performance bug, even if it is easier to prove correct. `rk-frame`'s job is to provide zero cost safe abstractions for those paths: borrowed RCU references, per CPU access under a preemption guard, and slab allocated objects with typed handles.
4. **Bounds checks are paid where Linux has none, and measured.** Rust checks array and slice indices. On hot paths the indices are usually proven in range by construction (an iterator, a typed index whose constructor checks once), and LLVM removes the check. Where it cannot, the check is a predictable branch costing about one cycle. The bench profile's instruction counts (document 19.4) show where checks survive, and the hot ones are restructured.
5. **Measure before optimizing, and keep the number.** Document 19.7: a performance change ships with the benchmark that justifies it.

## 21.2 The system call path

**Linux's cost.** A null system call (`getpid` through `syscall(2)`, avoiding glibc caching) costs about 70 to 110 ns on recent x86 with eIBRS and no KPTI. It costs several times that with KPTI or with the heavier Retbleed and SRSO mitigations (document 01.7). Most of the time is the `syscall` and `sysret` transition and the mitigation work at entry and exit. The C dispatch and `getpid` itself are a few nanoseconds.

**rukernel's path:**

1. The entry stub in `rk-frame`: assembly, the same instruction sequence as Linux's for the same mitigation set, FRED where available.
2. Build the `TrapFrame`.
3. Dispatch through the generated table, a bounds checked index into an array of function pointers. This is the one indirect call, and it goes through the same retpoline or eIBRS as Linux's, because Linux also uses an array of pointers. Linux has since moved to a `switch` statement on x86 to avoid the indirect call under some mitigations. We do the same, generated as a `match`.
4. Argument decoding: typed, with no work for scalars, and `UserPtr` construction for pointers, which is a range check.
5. The handler.
6. Exit work: signals, the reschedule flag, and the ptrace, seccomp and audit flags, checked with one load and branch on a combined flags word as Linux does.
7. The exit stub.

**Budget:** the same as Linux within 5% (document 19.1). The only extra work rukernel does is the `UserPtr` range check, which Linux also does in `access_ok`. The risk is the exit work check if the flags are not packed the same way, and the bench profile's per stage timers (document 19.5) are there to catch it.

**The vDSO** is user space code, compiled from Rust to the same instruction sequence (`rdtscp` or `rdtsc` with the seqcount loop). The 17 ns `clock_gettime` is matched by construction.

## 21.3 Context switch and wakeup

**Linux's cost:** about 1.2 to 1.5 µs per round trip for a pipe ping pong on one core, including two system calls, two wakeups and two context switches (document 01.7). The context switch itself (register save, stack switch, CR3 write with PCID, FPU state handled lazily on return to user) is a few hundred nanoseconds. The rest is the wakeup path (runqueue lock, enqueue, EEVDF placement, preemption check) and the pipe's own locking.

**rukernel:** the same structure. The risk is in the runqueue lock and the scheduler's data structures. Linux's EEVDF uses an augmented red black tree keyed on virtual deadline, with the minimum eligible time cached. Our implementation uses the same augmented tree, intrusive and allocation free, which is one of the places `rk-sched` needs a small audited leaf crate for intrusive collections (document 23.3). Without it, an `Arc` per scheduler entity would cost reference count traffic on every enqueue.

**Budget:** within 5% on `perf bench sched pipe` and `hackbench`, and within 10% on `schbench` p99 wakeup latency.

## 21.4 Page faults and memory

**Linux's cost:** an anonymous page fault on a fresh page costs about 1 to 2 µs on recent hardware. That is dominated by zeroing the 4 KiB page (about 100 to 200 ns with `rep stosb`), the page allocation from the per CPU lists, the per VMA lock, the page table update, and the exception entry and exit. With mTHP, a 64 KiB fault does 16 pages of work for one exception.

**rukernel:** the same steps. The per VMA lock is an `RwSem` in the VMA. The folio comes from per CPU frame caches, with sheaves (document 07.3) for the metadata. The page table update goes through `rk-frame`'s `VmSpace` cursor, which is the verified part. The cursor API is designed so that a fault does one walk, not one walk per check. Asterinas's measurements show its equivalent path matching Linux on LMbench's fault microbenchmarks.

**`fork`** of a large process is dominated by copying page tables and marking pages copy on write. Linux has optimized it heavily (batching, folio granularity, the per VMA lock). It is the memory benchmark with the most risk, because the verified cursor has to support batch operations to match. Budget: within 10%.

**Scalability** (`will-it-scale` page_fault, mmap and brk tests at high thread counts) depends on avoiding shared cache lines: no global counters on the fault path, per CPU RSS counters folded lazily, and the per VMA lock instead of the address space lock. This is the CortenMM question again: its per page table node locking scales better than per VMA locks on some patterns, at the cost of fidelity questions (document 24).

## 21.5 The VFS fast path

**Linux's cost:** `stat` on a cached path of five components costs about 300 to 600 ns, nearly all in RCU path walk: hash lookups per component, permission checks per component, the seqcount checks, and no locks and no reference counts unless it has to fall back.

**rukernel:** RCU walk with borrowed dentries bounded by the RCU guard's lifetime (document 08.1). The permission check per component is the same `generic_permission` logic, with the credential borrowed, not cloned. The risk is in the fallback rate: if the RCU walk falls back to ref walk more often than Linux's (because of a seqcount bumped too eagerly, say), `stat` heavy workloads (`git status`, `make` on a large tree, package managers) slow down a lot. The bench profile counts fallbacks, and so does Linux's with a tracepoint, so the rates can be compared directly.

**Budget:** within 10% on file system metadata (document 19.1), with `git status` on a large repository and a kernel build as the headline numbers.

## 21.6 Storage

**Linux's cost:** on an NVMe 4 KiB random read through io_uring with polling at queue depth 1, total kernel overhead is about 1 µs. A third of that is io_uring submission and completion, a third the block layer and NVMe command build, and a third DMA mapping and the IOMMU (document 09.6). At high queue depth the cost per I/O falls with batching: plugging, one doorbell per batch, and completion batching.

**rukernel:** the same layers with the same batching. The risks are:

- the SQE copy out (document 09.3), which is one cache line and noise in practice;
- `DmaBuffer` ownership tracking, which must compile to nothing beyond the mapping call;
- and the async executor for requests that cannot complete inline, which must not allocate.

**Budget:** within 5% on IOPS and p99.

## 21.7 Networking

**Linux's cost:** a loopback TCP_RR round trip costs about 5 µs. It is dominated by two socket wakeups (sleep and wake, scheduler), the TCP state machine on both sides, and softirq processing. Copies are negligible at small sizes. Bulk TCP over 100 GbE is dominated by per packet costs amortized by GRO and TSO, and by the copy to user, which zero copy receive removes.

**rukernel:** the same structure: NAPI, GRO, TSO, TSQ and softirq batching. The stack's async internals (document 10.3) are for protocol timers and connection setup, not for the per packet data path, which is ordinary synchronous code called from NAPI poll.

**Budget:** within 5% on throughput and within 10% on p99.

## 21.8 Where rukernel can be faster, and why it does not count

- **Fewer indirect calls**, from static dispatch (21.1, point 2). This is worth a few percent on system call heavy and VFS heavy workloads under retpoline mitigations, and less under eIBRS.
- **Fewer defensive checks.** Linux validates many internal invariants at runtime (`BUG_ON`, `WARN_ON`, refcount saturation checks) that the type system proves. A cycle here and there.
- **No KASAN or KCSAN cost in production.** That cost is equal on both sides, since neither ships with them, so this is not an advantage. It is here only to note that it is not one.

Document 02.2 is clear that being faster on one row does not offset being slower on another. These are reported as they fall.

## 21.9 Where rukernel is at risk

Ranked by how likely each is to produce a red row in document 19:

1. **`fork` and `munmap` of large address spaces**, if the verified page table cursor does not batch as well as Linux's hand tuned loops (21.4).
2. **RCU walk fallback rates** in the VFS (21.5).
3. **The BPF shadow structures** for CO-RE (document 11.4). These add stores on credential, comm and cgroup changes, and some of those are on fork and exec.
4. **Lock contention** at high CPU counts, in places where Rust's ownership model pushed the design toward a coarser lock than Linux uses. The lock statistics (document 19.5) find these.
5. **Code size and instruction cache pressure** from monomorphization, if generics are instantiated freely. Kernel text size is tracked per release. Linux's x86 `vmlinux` text is about 20 to 30 MB for a distribution configuration. rukernel's budget is to stay at or below it for an equivalent feature set.
6. **Compiler differences.** `rustc` and LLVM against GCC (which distributions use to build Linux) or Clang (Android, ChromeOS). Linux built with Clang with ThinLTO is within noise of GCC on most workloads. Kernel code is not much affected by compiler differences, and the bench harness can compare against a Clang built Linux to separate compiler effects from kernel effects.

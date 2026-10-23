# Open questions

These are the decisions the spec has not settled, ranked by how much of the design depends on each answer. Each entry gives the question, the options, what would decide it, and when it has to be decided. A question leaves this list when its decision is recorded in the relevant document and in the settled decisions of document 00.

## 1. CortenMM or VMAs as the source of truth for address spaces

**The question.** Should an address space be a VMA tree with page tables underneath, as Linux does, or should the page table be the source of truth with per node locking, as CortenMM (SOSP 2025) does?

**For CortenMM:**

- Its proofs are much more tractable, and the address space core is the most important thing to verify (document 20.2, item 2).
- It scales better on some `will-it-scale` patterns.

**For VMAs:**

- Linux's VMA behaviour is user visible in many places: `/proc/<pid>/maps` and `smaps`, merge and split rules, `mremap` semantics, `mmap` placement, `madvise` on ranges, and `MAP_FIXED_NOREPLACE` errors.
- Reproducing that exactly on top of a structure that has no VMAs means keeping a shadow VMA view. The shadow view may cost back the scalability gain.

**What decides it.** The R4 experiment (document 22) on two counts:

- the `will-it-scale` and `fork` numbers against the VMA design;
- whether the `maps` and `smaps` differential over the L4 corpus is byte identical.

If both pass, CortenMM wins. If fidelity needs a shadow structure that loses the scalability gain, VMAs win and the proofs are done the harder way.

**Deadline:** end of R4.

## 2. Build on OSTD or write `rk-frame`

**The question.** Asterinas's OSTD is the closest existing thing to `rk-frame`: a framekernel's unsafe base, MPL-2.0, partly verified by `vostd`. Should rukernel start from it rather than write its own?

**For OSTD:**

- Years of work and proofs already exist.
- It brings a community.

**Against OSTD:**

- Its interfaces are shaped for Asterinas: async free stackful tasks with its own scheduler hooks, and its own frame metadata scheme.
- rukernel needs LKMM semantics, `PREEMPT_LAZY`, the lock level system, text poking for the BPF JIT and static keys, the VMX/SVM core, and FRED. Some of these change OSTD's core interfaces.
- MPL-2.0 is compatible with GPL-2.0-only in a combined work, but contributions would be split across licences.

**What decides it.** A prototype in R0:

- port `rk-mm`'s fault path and `rk-sched`'s context switch onto OSTD;
- list every interface change needed;
- ask Asterinas whether they would accept those changes upstream.

If they would, rukernel builds on OSTD and contributes back. If not, `rk-frame` is written from scratch with OSTD's proofs as a guide.

**Deadline:** end of R0.

## 3. Kernel unwinding and panic strategy

**The question.** The kernel builds with `panic = "abort"` and no unwinding (document 03.6). Should some subsystems instead use unwinding, catching a Rust panic at a boundary and returning `-EIO` instead of oopsing?

Unwinding would let a buggy file system or driver fail one request instead of killing the machine. That is the Linux behaviour of `BUG` in a file system turning into an oops that kills one process, plus a bit more. It costs code size, needs unwind tables (`gimli`), and requires every lock and RCU guard to be unwind safe.

**What decides it.** A measurement of text size and fault path cost with unwinding enabled for `rk-fs-*` and `rk-drv-*` only, plus a review of how often panics happen in practice in the syzkaller corpus.

**Deadline:** R3, before the first disk file system ships.

## 4. Speculative frame references for GUP-fast

**The question.** Linux's lockless `get_user_pages_fast` walks user page tables without locks and takes speculative references on folios that may be freed concurrently, relying on RCU table freeing and on `folio_try_get` failing on a zero count. Can that be expressed with `rk-frame`'s typed frame handles, and can it be verified?

GUP-fast is on the path of direct I/O, io_uring fixed buffers, RDMA, vhost and futexes, so a slower locked walk shows up in storage and network benchmarks.

**The options:**

- a verified speculative reference API in `rk-frame` (preferred);
- a locked walk with the per VMA lock and accepting the cost;
- pinning registered buffers ahead of time, which is what io_uring fixed buffers do anyway, and accepting the cost only on unregistered paths.

**Deadline:** R3, measured with `fio` direct I/O.

## 5. BTF shadows for sched_ext

**The question.** sched_ext schedulers (`scx_lavd`, `scx_rusty`, `scx_bpfland`, `scx_layered`) read `task_struct`, `rq` and cgroup fields through CO-RE. The shadow structure approach (document 11.4) works for tracing programs, which read a few fields. sched_ext schedulers read many fields on every scheduling decision, and some of those fields (`p->se.sum_exec_runtime`, `p->scx.dsq_vtime`, `p->nr_cpus_allowed`, the CPU masks) change on hot paths.

**The options:**

- keep shadows up to date on every change, which costs stores on the scheduler's hottest paths;
- lay out rukernel's own task and runqueue structures so that the fields sched_ext reads sit at BTF described offsets, so the shadow is the real structure for those fields;
- support sched_ext only through the kfunc interface and the `scx_*` helpers, which most schedulers mostly use, and treat direct field reads as unsupported.

**What decides it.** A survey of field accesses across the scx repository's schedulers, and a measurement of option 1 on `schbench`.

**Deadline:** R7, before sched_ext work begins in R8.

## 6. How far macOS goes, and on what hardware

**The question.** D1 (command line programs, document 16.4) is committed for R9. D2 (daemons and XPC) is R11. Should D3, GUI applications with AppKit and Metal, ever be a goal?

**Against D3:**

- macOS frameworks are not open source, and redistributing them is not allowed.
- Darling's GUI work shows how large the framework surface is.
- Metal on non-Apple GPUs is a translation layer of its own.

**For D3:**

- On Apple Silicon running Asahi, with the user's own macOS installation on the same disk, the user's licensed frameworks could be loaded from their own volume. That is legally and technically a different situation from redistributing them.

**What decides it.** Legal review of the "frameworks from the user's own macOS volume" model, plus an estimate of the remaining kernel surface (IOKit user clients, IOSurface, the window server's Mach interfaces).

**Deadline:** after 1.0. Nothing before R11 depends on it.

## 7. ZFS

**The question.** OpenZFS is CDDL licensed and ships as an out of tree Linux module. rukernel cannot load `.ko` files (document 12.6). Users who run ZFS root (Ubuntu offers it, and TrueNAS and Proxmox use it) cannot move without it.

**The options:**

- a clean room Rust implementation of the ZFS on disk format, which is documented and stable, with the same `zfs` and `zpool` ioctl interface as OpenZFS's `/dev/zfs`;
- running OpenZFS in the Linux driver host (document 12.5), which is awkward because ZFS is not a device driver and needs deep VFS integration;
- declaring ZFS out of scope and saying so.

**What decides it.** Demand measured from the L4 corpus users, and whether the CDDL to GPL boundary question can be avoided entirely by the clean room route.

**Deadline:** none before 1.0. The scope section of document 00 lists ZFS as not planned until this is answered.

## 8. More architectures

**The question.** Should loongarch64, ppc64le or s390x become supported targets?

Each is a real Linux user base:

- loongarch64 in China;
- ppc64le in IBM Power servers and some HPC sites;
- s390x on mainframes, where Linux workloads are significant.

Each costs an `rk-frame` port (traps, page tables, atomics, the memory model mapping), a backend for the BPF JIT, ABI generation (cheap, since `rk-abigen` already handles per architecture tables), and CI hardware.

**What decides it.** A maintainer with access to the hardware, and a funded use case. The architecture independent code is meant to need nothing, and the first port beyond riscv64 will test that claim.

**Deadline:** none. Not before R8.

## 9. The nftables JIT

**The question.** Linux interprets nf_tables bytecode. Compiling rulesets to native code, or to BPF, has been proposed upstream several times and not merged. Should rukernel compile them?

It would help large rulesets (Kubernetes clusters with thousands of services, if they use the nftables mode of kube-proxy). It adds a second code generator to audit, and it changes nothing visible.

**What decides it.** A measurement at R5 of the interpreter on kube-proxy rulesets at 10,000 services against Linux. If the interpreter is already at parity, nothing is done.

**Deadline:** R10.

## 10. The `rk-nt` interface

**The question.** Is there an in kernel NT primitive set (objects, handles, waits, APCs) that Wine would use and that measurably beats ntsync plus futexes? If so, what is its shape? Document 16.3 commits to building it only if it wins, and to proposing it upstream first.

**What decides it.** Profiles of the L5 Proton scenarios at R6, showing where Wine spends time in system calls that an NT primitive would remove. Then a prototype, and a conversation with the Wine developers before any ABI is frozen.

**Deadline:** R11.

## 11. Stable Rust features the kernel wants

**The question.** The spec commits to stable Rust only (document 03.9). Several unstable features would simplify the kernel:

- `arbitrary_self_types`, for smart pointer receivers on `Arc` and RCU references;
- `allocator_api`, for fallible allocation in standard collections;
- `asm_goto`, for static keys without a runtime branch;
- some `core::intrinsics`.

Rust for Linux has driven several of these toward stabilization. Some stabilized in 2025 and 2026, and some have not.

**The options:**

- wait for stabilization;
- work around each one (custom collections with fallible allocation, a jump label implementation using `asm!` with a data table);
- allow a pinned nightly toolchain for the kernel only.

**The current answer** is to work around each one and stay on stable. The cost of each workaround is tracked, and this question is revisited every Rust release.

**Deadline:** continuous.

## 12. Governance and naming the release

**The questions.**

- Who decides when an ABI release is claimed (document 17.4)?
- How are behaviours in the settled register (document 18.5) agreed?
- Does a foundation hold the trademark?

These matter less early, and more once distributions ship rukernel.

**What decides it.** The first distribution that wants to ship rukernel as an option.

**Deadline:** before 1.0.

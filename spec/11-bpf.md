# BPF

BPF is the part of the Linux ABI that most resists reimplementation, because a BPF program is code written against the kernel, not just against its system calls. It names kernel functions as kfuncs, reads kernel structures through BTF, attaches to kernel functions as kprobes and fentry points, and relies on a verifier whose exact acceptance boundary is observable: a program Linux accepts that we reject is a compatibility failure. In 2026 BPF is load bearing infrastructure everywhere: in systemd, Cilium, Falco, Tetragon, bpftrace, the sched_ext schedulers, the HID quirk programs, Android's networking and the observability agents of every cloud. A kernel without it cannot run a modern distribution well.

## 11.1 Scope

The `bpf(2)` system call with all its commands (about 41 in `enum bpf_cmd` in v7.3), every map type, every program type and attach type in the pinned release, BPF links, BPF tokens for delegated use from user namespaces (6.9), signed programs (6.18, `signature` and `keyring_id` in `bpf_attr`), arenas (`BPF_MAP_TYPE_ARENA`), struct_ops, the 7.2 "common attributes", and `bpffs`.

What makes that list tractable is to divide it into three layers with different compatibility arguments.

## 11.2 Layer one: the instruction set, the verifier and the JIT

The **instruction set** is specified by RFC 9669, published in 2024 as an IETF standard, plus Linux's extensions since. It is small and exactly defined, and conformance is testable with the IETF conformance suite and Linux's `test_verifier` and `test_progs` in kselftest.

The **verifier** is the hard part. Linux's verifier is about 25,000 lines of C. It performs abstract interpretation with range tracking (tnum and the signed and unsigned 32 and 64 bit bounds), pointer type tracking, reference tracking for acquired objects, state pruning, loop bounding, precision backtracking, and the type checks driven by BTF. Its acceptance boundary is not specified anywhere except in its code, and programs in the wild are tuned to it. A program that passes on Linux because of a particular pruning heuristic, and fails on a more conservative verifier, is a real failure.

So rukernel's verifier is a port of Linux's algorithm, written in safe Rust and structured to be testable, not a new design. The test is differential: every program in the corpus is loaded on both kernels with the verifier log at level 2, and the accept or reject outcome must match. The corpus is kselftest's `test_progs` and `test_verifier`, the programs shipped by Cilium, systemd, bpftrace's standard tools, libbpf-tools, Falco, Tetragon, the scx schedulers, and the KernelGPT and syzkaller generated programs. The instruction counts in the log differ, and that is allowed. Accept or reject is not.

"Prove It to the Kernel" (SOSP 2025) and the formal verification work on Linux's range analysis (Agni, CAV 2023) show that the verifier's abstract domains can be verified. That is the plan in document 20 for the range tracking core.

The **JIT** compiles verified programs to x86-64, arm64 and riscv64. Linux's JITs are straightforward single pass translators with constant blinding. Ours are the same design, written in Rust, with the emitted code going into executable memory through `rk-frame`'s text poking interface (W^X enforced: write through a temporary alias, then flip). The interpreter exists for debugging and for the `bpf_jit_enable=0` setting. Trampolines for fentry, fexit and struct_ops are generated the same way.

## 11.3 Layer two: maps, helpers and kfuncs

**Maps:** hash, array, per CPU variants, LRU, LPM trie, ring buffer, user ring buffer, bloom filter, stack trace, cgroup storage, sk, inode and task storage, devmap, cpumap, xskmap, sockmap, sockhash, reuseport array, queue, stack, struct_ops, arena, and the 7.2 resizable hash. Each is a data structure with a defined interface, and porting them is ordinary work.

**Helpers** are the stable function interface: about 210 numbered helpers, each with a fixed signature in `include/uapi/linux/bpf.h`. Implementing them is ordinary work too, generated from the uAPI's helper documentation comment, which is machine readable.

**kfuncs** are where it gets interesting. A kfunc is a kernel function exposed to BPF by name and BTF type, with no stability promise in Linux. In practice programs depend on them (`bpf_task_acquire`, `bpf_cgroup_from_id`, `bpf_obj_new`, `bpf_rcu_read_lock`, `bpf_dynptr_*`, `bpf_iter_*`, `bpf_arena_alloc_pages`, the `scx_bpf_*` set for sched_ext, `bpf_xdp_metadata_*`, `bpf_crypto_*`). rukernel exports the same kfunc names with the same BTF signatures and the same semantics. Each one is implemented over rukernel's equivalent structure, and the kfunc table is generated from Linux's `BTF_ID_FLAGS` sets in the pinned tree, so a new kfunc in a release shows up as a gap in `ABI-CHANGES`.

## 11.4 Layer three: BTF, CO-RE and the kernel's own types

This is the layer a reimplementation could get wrong in principle, not only in detail.

A CO-RE program (compile once, run everywhere, which is how essentially all modern BPF tools ship) carries relocations that say "field `pid` of `struct task_struct`", resolved at load time by libbpf against the running kernel's BTF in `/sys/kernel/btf/vmlinux`. The program then reads that field with a direct load at the computed offset, through `bpf_probe_read_kernel` or through a BTF typed pointer.

rukernel does not have a `struct task_struct`. Its task is a Rust struct with a different layout and different fields.

There are three possible answers. We take the third:

1. **Refuse CO-RE programs.** That rules out most of the observability ecosystem. Rejected.
2. **Lay out rukernel's structures exactly like Linux's.** That freezes our internals to Linux's, and they change every release. Rejected.
3. **Publish a synthetic `vmlinux` BTF that describes Linux's types, and back it with shadow structures.** For each kernel type that BPF programs actually read, rukernel maintains a shadow object with Linux's layout, updated where the real object changes. Typed pointers handed to BPF, such as the `task_struct *` in a tracepoint context, are pointers to the shadow. This is the design.

**What gets a shadow is decided by measurement.** The corpus of BPF programs (section 11.2) is scanned for the CO-RE relocations it uses. In practice that is a few hundred fields across a few dozen types: `task_struct`, `mm_struct`, `file`, `inode`, `dentry`, `sk_buff`, `sock`, `cgroup`, `cred`, `nsproxy`, `pid`, `bio`, `request`, `net_device` and `vm_area_struct`. Most of the fields are identity, credentials, comm and a few counters.

**How shadows are kept current.** Each shadow field is updated at the point where rukernel's real state changes, through a `#[bpf_shadow]` attribute on the field that generates the update. The cost is a few stores on paths like credential change and comm change. For `task_struct` the shadow is allocated with the task, so a pointer to it is a stable address, as BPF expects.

**Fields that are not shadowed** are present in the BTF so CO-RE relocation succeeds, and they read as zero. The coverage report lists them, and the load can optionally fail if a program reads one: `bpf.strict_shadow=1`, a setting tools can probe.

**fentry, fexit and kprobes** are attached by Linux function name. rukernel maintains a map from Linux function names to rukernel functions with an equivalent role and arguments, generated where possible and hand maintained otherwise (`tcp_v4_connect`, `vfs_read`, `do_sys_openat2`, `__x64_sys_*`, `finish_task_switch`, `sched_switch` tracepoint and so on). This is the same map document 19.5 uses to compare profiles. A kprobe on a function name with no mapping fails as it would on a Linux kernel without that symbol, which tools handle because function names change in Linux too.

**Tracepoints** are a much easier case. They are named, have documented formats in `/sys/kernel/tracing/events/*/format`, and are what well written tools prefer. rukernel emits the same tracepoints with the same format files at the equivalent points: `sched_switch`, `sched_wakeup`, `sys_enter` and `sys_exit`, `block_rq_*`, `net_dev_*`, `tcp_*`, `kmem_*`, `page_fault_*`, `irq_*` and the `syscalls:*` set.

This design costs memory and some work on hot paths. It is the price of running Linux's observability tools unmodified, and the benchmarks measure it. Whether it holds up for sched_ext schedulers, which read scheduler internals heavily, is an open question in document 24.

## 11.5 sched_ext

sched_ext is how scheduling policy is now developed in Linux (document 06.4). Its interface is a struct_ops of about 30 callbacks plus the `scx_bpf_*` kfuncs, with dispatch queues as the central abstraction. rukernel implements it on its own scheduler core with the same semantics. That includes the 7.3 sub scheduler hierarchy, the watchdog that ejects a stalled scheduler back to the fair class, and `/sys/kernel/sched_ext/*`. The scx schedulers (`scx_rusty`, `scx_lavd`, `scx_bpfland`, `scx_layered`, `scx_flash`) are L3 tests. Their performance on rukernel against Linux, for the same scheduler, is a bench row.

## 11.6 Security of BPF

- Unprivileged BPF is disabled by default (`kernel.unprivileged_bpf_disabled=2`, as most distributions ship).
- BPF tokens allow delegation into containers.
- Signed programs are verified against the kernel keyring, as Linux does since 6.18.
- The LSM hooks for BPF are present, and BPF LSM (`BPF_PROG_TYPE_LSM`) attaches to rukernel's LSM hook points by Linux hook name (document 13).
- Spectre hardening is the same as Linux's: speculative bounds checks and constant blinding in the JIT.

The verifier is the attack surface. Being in safe Rust means a verifier logic bug can admit an unsafe program, but the verifier cannot itself be corrupted.

## 11.7 Order of work

1. Classic BPF for seccomp and socket filters (R2).
2. The eBPF interpreter, maps and helpers for networking and cgroups, which systemd needs (R5).
3. JIT, BTF and CO-RE with shadows for the tracing tools (R7).
4. sched_ext and struct_ops (R8).
5. Arena, tokens and signing as each is reached by the corpus.

Document 22 has the milestones.

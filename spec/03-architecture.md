# Architecture

This document fixes the shape of the kernel: what is trusted, what is not, how the pieces talk, how they run concurrently, and how failure is represented. Every later document assumes it. The decisions here are the ones that are most expensive to change after the first year, so each one says what it costs and what the alternative would have cost.

## 3.1 The shape: a framekernel

rukernel is a **framekernel**, the architecture Asterinas named and demonstrated (Peng et al., USENIX ATC 2025): one address space and one privilege level like a monolithic kernel, so a system call is a function call and a page fault is a function call and nothing is copied between components; but the right to write `unsafe` Rust is confined to one small crate, `rk-frame`, and every other crate in the kernel is compiled with `#![forbid(unsafe_code)]`.

The rule is mechanical and enforced by the build (document 23): a crate outside `rk-frame` and the short list of audited leaf crates in 23.3 that contains the token `unsafe` does not compile. Soundness of the whole kernel then reduces to soundness of `rk-frame`'s public API, which is the thing document 20 verifies.

Why this and not the alternatives:

**Not a microkernel.** A microkernel pays an IPC on every crossing between the file system, the block layer, the network stack and the driver. seL4's IPC is the fastest in the world and it is still a few hundred cycles plus the cache and TLB footprint of a second address space, multiplied by every `read()`. Document 02's performance axis says within 5% of Linux on `read`, `fio` and `TCP_RR`, and that is not reachable with a crossing on the data path. Fuchsia's Starnix runs the Linux ABI on top of Zircon and its published numbers are the evidence (document 01).

**Not a monolithic kernel in unsafe Rust.** Rewriting Linux's design in Rust with `unsafe` wherever it is convenient gets Linux's performance and Linux's bug classes, which is the worst trade available: all the cost of a rewrite and none of the reason for one. The Rust-for-Linux experience is that the abstractions are where the value is, and a framekernel is that experience taken to its end.

**Not a library OS or unikernel.** Unikraft, OSv and ArceOS get very good numbers by dropping the user/kernel boundary and running one application. Document 02 requires running every Linux program, including the ones that `fork`, `ptrace` each other, and sandbox themselves with seccomp. That needs real processes.

The cost of the framekernel is that the safe services cannot be fault isolated from each other at run time: a logic bug in the ext4 code can still corrupt ext4, and a deadlock in the network stack still hangs the network stack. What it removes is the memory safety class (use after free, out of bounds, uninitialized reads, races on plain memory), which is the largest single class in syzbot's open report list and in the kernel CVE stream since the kernel became its own CNA in 2024, and it does so at zero run time cost on the data path.

## 3.2 The trusted core, `rk-frame`

`rk-frame` is everything that must touch hardware or raw memory, and nothing else. Its budget is **25,000 lines** at 1.0. A pull request that grows it past that budget has to argue for the budget in the same pull request. Asterinas's OSTD is about 15,000 lines doing a similar job for fewer architectures, so this is a ceiling rather than a target.

What it provides, as safe APIs:

- **Boot and CPU bring up**: entry from UEFI, Multiboot2 (for QEMU direct boot), the Linux x86 boot protocol (so GRUB, systemd-boot and `kexec` can load us as if we were a bzImage), and the arm64 and RISC-V Linux image headers. Per CPU areas, SMP bring up, CPU feature detection.
- **Physical memory**: the frame allocator (a buddy allocator with per CPU caches, document 07), typed frames `Frame<M>` whose metadata type `M` is fixed at allocation, and `Segment` for physically contiguous ranges.
- **Virtual memory**: page table construction and walking for each architecture, TLB shootdown, the kernel's direct map, and `VmSpace`, the user address space object that the safe `rk-mm` crate drives without ever seeing a page table entry.
- **User memory access**: `UserPtr<T>`, `UserSlice` and `UserReader`/`UserWriter`. These are the only way to touch user memory. They do SMAP/PAN toggling, exception table based fault recovery, and they cannot be dereferenced, only copied through. TOCTOU is handled by construction: a value read from user memory is a kernel copy, and reading it twice is two reads.
- **Traps and interrupts**: the trap entry and exit, the system call entry for each architecture's instruction, the exception vectors, the interrupt controller drivers (x2APIC and IOAPIC, GICv3 and GICv4, RISC-V AIA and PLIC), IPIs, and the `TrapFrame` the safe dispatcher receives.
- **Context switch**: saving and restoring register state, FPU and vector state (XSAVE with the compacted format, SVE and SME on arm64, the RISC-V V extension), and the per task kernel stack.
- **Synchronization primitives**: raw spin locks, the `Preempt` and `IrqGuard` disable guards, atomics wrappers with the memory orderings the Linux memory model needs, and the RCU grace period machinery (3.5).
- **Timers and clocks**: TSC, the arm generic timer, the RISC-V timer, HPET and the paravirtual clocks, calibration, and the vDSO data page writer.
- **I/O**: MMIO and port I/O as typed regions, DMA mapping with IOMMU (VT-d, AMD-Vi, SMMUv3) so that a driver gets a `DmaBuffer` and never a physical address, and PCI configuration space access.
- **Per CPU variables** as a type, `PerCpu<T>`, whose access requires a preemption guard.
- **Hardware virtualization**: VMX and SVM on x86 and VHE on arm64, with VMCS and VMCB handling, VM entry and exit and their speculation barriers, and the EPT and NPT page tables. This is about 5,000 lines of the budget. KVM's emulator, interrupt controllers and uAPI above it are safe (document 14.4).
- **Text poking**: writing code into executable memory for the BPF JIT, static keys and alternatives, through a temporary writable alias, so W^X holds at every instant (document 11.2).

What it does not provide: anything with policy. No scheduler policy (it provides `switch_to`, the scheduler crate decides whom to switch to), no page replacement, no file system, no sockets.

## 3.3 The safe services

Everything else is safe Rust in crates layered strictly (document 23 has the full tree and the layer rule):

```
userland
  ----------------------------------------------- syscall boundary
rk-abi        generated: numbers, structs, flags, ioctl codes, errno (document 04)
rk-syscall    the dispatcher and the per syscall entry functions
  rk-proc     tasks, threads, process groups, sessions, credentials, signals, ptrace, exec
  rk-sched    EEVDF fair class, RT, deadline, idle, sched_ext host (document 06)
  rk-mm       address spaces, VMAs, faults, page cache, reclaim, swap, memcg (document 07)
  rk-vfs      dentries, inodes, mounts, the mount API, file descriptors, locks, notify (08)
  rk-fs-*     ext4, xfs, btrfs, tmpfs, proc, sys, cgroup, devtmpfs, overlay, fuse, 9p, virtiofs
  rk-block    blk-mq, the I/O schedulers, the page cache's block side (09)
  rk-uring    io_uring (09)
  rk-net      sockets, TCP/IP, netlink, netfilter, the qdisc layer (10)
  rk-bpf      the verifier, the JITs, maps, BTF, program attach points (11)
  rk-sec      capabilities, LSM hooks, seccomp, landlock, SELinux and AppArmor (13)
  rk-ns       namespaces and cgroup v2 controllers (14)
  rk-kvm      the /dev/kvm uAPI on VMX, SVM, arm64 VHE (14)
  rk-drv-*    drivers (12)
  rk-persona  foreign personalities (16)
rk-lib        safe collections, maple tree, xarray, radix and interval trees, bitmaps
rk-frame      the trusted core
```

A service may depend on `rk-lib`, `rk-frame` and services below it in the order the layer file lists, and never on a service above it. Upward calls go through traits registered at boot (the VFS calls into file systems through `FileSystem`, `Inode` and `File` traits; the block layer calls drivers through `BlockDevice`). This is how Linux does it with function pointer tables (`file_operations`, `inode_operations`), and the dispatch cost is the same: one indirect call. A Rust trait object is a vtable pointer and a data pointer, which is exactly `struct file`'s `f_op` and `private_data`.

## 3.4 The execution model

**A task is a kernel thread with its own kernel stack**, as in Linux. A system call runs on the calling task's kernel stack, blocks by sleeping on a wait queue, and is interrupted by a signal by being woken with a pending signal and returning `ERESTARTSYS` or `EINTR` up the call chain.

We considered and rejected async Rust as the primary model, where a system call is a future and a blocked call is a suspended future with no stack. It saves memory (no 16 KiB stack per thread) and Asterinas and several research kernels have explored it. It was rejected for three reasons:

1. Linux's interruption semantics are defined in terms of a blocked call unwinding with `-ERESTARTSYS` and being restarted, transparently or not depending on `SA_RESTART` and the specific syscall's restart block (`nanosleep` restarts with the remaining time, `futex` with the original timeout, `poll` with a recomputed one). Expressing that through `Future` cancellation is possible and every attempt we found was harder to get right than the stack model.
2. Deep call chains (VFS into ext4 into the page cache into the block layer into a driver, with a page fault in the middle on `copy_to_user`) would make every function in them `async`, which colors the whole kernel and makes every lock a question of whether it may be held across an `.await`.
3. Performance: a stackful switch is a few dozen cycles of register save and restore; a deep future's poll chain re-enters every level on every wake.

Async is used where it fits: inside `rk-net` for timers and protocol state machines, and inside `rk-uring` for the internal worker that completes requests that cannot complete inline. Both are leaf uses with an executor that runs on ordinary kernel threads.

**Preemption** is full preemption by default with the lazy preemption model Linux adopted (`PREEMPT_LAZY`, merged in 6.13): a fair class task is preempted at the next tick or return to user rather than immediately, and RT and deadline tasks preempt immediately. `PREEMPT_RT` semantics (spin locks become sleeping locks with priority inheritance, threaded interrupts) are a build configuration, not a fork, because the lock types are already ours and changing what `SpinLock` means under a feature flag is exactly what Linux did over twenty years.

**Interrupts** run on a per CPU interrupt stack, do the minimum, and defer to threaded handlers or softirq equivalents. The softirq model is kept (network receive and transmit, timers, tasklets for drivers that expect them, RCU callbacks) because `/proc/softirqs` is ABI, `ksoftirqd` appears in `ps`, and network performance depends on exactly the batching that softirqs give.

## 3.5 Concurrency primitives

Locks are types and their ordering is checked.

- `SpinLock<T>`, `Mutex<T>`, `RwLock<T>`, `RwSem<T>`, `SeqLock<T>`, `Rcu<T>`, `PerCpu<T>`, `Atomic*`. Each guard is a value whose lifetime is the critical section.
- **Context is in the type system.** A function that may sleep takes a `&Sleepable` token; interrupt context never has one, and holding a `SpinLockGuard` borrows the token mutably so it cannot be passed on. "Sleeping while atomic", one of Linux's most common bug reports, is a compile error.
- **Lock classes and ordering.** Each lock is declared with a class (`lock_class!(VFS_INODE_LOCK, level = 30)`), and acquiring a lower level while holding a higher one is a compile error where the levels are static and a lockdep style runtime check in debug builds where they are not (two inodes of the same class, ordered by address as Linux does in `lock_two_nondirectories`).
- **RCU** is a real tree RCU with quiescent state tracking per CPU, expedited grace periods, and `call_rcu` and `synchronize_rcu`. In Rust, an `RcuReadGuard` gives `&T` with a lifetime bounded by the read side critical section, which makes the classic RCU bug (keeping a pointer past `rcu_read_unlock`) a borrow check error. Dentry lookup, the routing table, the PID table, file descriptor tables and the module of every hot path that Linux makes lockless with RCU are lockless here for the same reason.
- **The memory model** is the Linux kernel memory model (LKMM), not the C++ model, because user programs and drivers depend on its guarantees around `READ_ONCE`, `WRITE_ONCE`, address and control dependencies, and the full barriers on value returning atomics. `rk-frame` provides `read_once`, `write_once`, `smp_mb` and the acquire and release forms, implemented with inline assembly where Rust's atomics are stronger or weaker than LKMM requires.

## 3.6 Errors and failure

**Every fallible kernel function returns `Result<T, Errno>`.** `Errno` is the Linux errno space (`rk-abi` generates it) plus the internal restart codes (`ERESTARTSYS`, `ERESTARTNOINTR`, `ERESTARTNOHAND`, `ERESTART_RESTARTBLOCK`) that never reach user space. The `?` operator does what `if (err) goto out;` does in Linux, and `Drop` does what the `out:` label does, which removes the most common C kernel bug class after memory safety: the error path that leaks or double frees.

**Allocation is fallible everywhere.** No `Box::new`, no `Vec::push` that aborts. `rk-lib` provides collections whose growth returns `Result`, and Clippy is configured to deny the infallible APIs. Linux returns `ENOMEM` from deep inside syscalls and programs handle it; a kernel that panics instead is not compatible.

**Panics are bugs, and a panic stops the machine.** The kernel builds with `panic = "abort"` and does not unwind. The panic handler prints the message and the location on the console and halts. Under QEMU it exits with a failure status, so a boot test that panics fails. This was open question 3 of document 24, and it was decided in R3:

- The targets `x86_64-unknown-none`, `aarch64-unknown-none` and `riscv64gc-unknown-none-elf` use the `abort` panic strategy, and their `core` and `alloc` come compiled with it. Unwinding needs `-Zbuild-std` to compile them again, and a `no_std` crate also needs the `eh_personality` lang item. Both are unstable, and the kernel uses stable Rust only (document 00). So we cannot build unwinding for `rk-fs-*` and `rk-drv-*` on the pinned toolchain, and we cannot measure its text size and cost there.
- The error rules make a panic rare. Each fallible function returns `Result`, Clippy warns on `unwrap`, `expect` and `panic!` outside the tests, and a file system checks each value that it reads from the disk and gives `EUCLEAN` or `EIO` for a bad value. The ext4 and XFS drivers do this, so a damaged image fails one request and does not stop the machine.
- Each boot test run stops on a panic, so each passing run of the boot tests, fstests, LTP and gVisor had no panic.

A panic in interrupt context or with a spin lock held must halt in each design, so the cost of abort is only on the panics in process context. We will open the question again if `build-std` and `eh_personality` become stable, with the measurement that document 24 asks for. Until then, a Rust panic does not print an oops in the format of document 20.

## 3.7 No Linux modules, but every module

Linux distributions expect modules: `udev` loads drivers by modalias, `systemd-modules-load` loads a list, Docker runs `modprobe overlay` and `modprobe br_netfilter`, and dozens of programs check `/proc/modules` or `/sys/module/<name>`.

rukernel does not load Linux `.ko` files (document 12.6 explains why it cannot). Everything is built in. To make that invisible, the build emits `modules.builtin` and `modules.builtin.modinfo` in the formats `kmod` reads, naming every rukernel component by the Linux module name it replaces, with its aliases. `modprobe overlay` then finds `overlay` in `modules.builtin` and succeeds without loading anything, which is what Linux's own `modprobe` does for a built in module. `/sys/module/<name>/parameters` exposes the parameters each component accepts under the Linux name. A program that asks whether `br_netfilter` is loaded gets yes, because the functionality it is asking about is present.

rukernel's own loadable modules, Rust crates compiled against a specific kernel build and signed, are a post 1.0 feature. They are for rukernel drivers, not for Linux binaries.

## 3.8 Configuration

Linux has about 20,000 Kconfig symbols. A user program can see only a few hundred of their effects, and those are what we implement. rukernel's configuration is Cargo features grouped into profiles (`server`, `desktop`, `embedded`, `rt`, `debug`), and the build generates a `/proc/config.gz` that answers the questions programs actually ask (`CONFIG_BPF_SYSCALL=y`, `CONFIG_USER_NS=y`, `CONFIG_CGROUP_BPF=y`, `CONFIG_SECCOMP_FILTER=y`, `CONFIG_IKCONFIG_PROC=y`) with the values that describe what rukernel actually does. Docker's `check-config.sh`, systemd and many container tools read this file to decide what to use, so it is ABI in practice and is tested as such: the generated file is diffed against the reference's file for the same profile in every compat run, and every difference is either an option that changes nothing visible or a registered gap.

## 3.9 Toolchain

Stable Rust pinned in `rust-toolchain.toml`, with the short list of unstable features the kernel needs behind one gate and tracked against stabilization, as Rust for Linux tracks its own list. Targets are `x86_64-unknown-none`, `aarch64-unknown-none-softfloat` and `riscv64gc-unknown-none-elf` with custom target JSON only where those cannot express what we need (the red zone, the code model, floating point in the kernel). The kernel is built with `cargo xtask build`, which produces an EFI application, a bzImage compatible image, and the arm64 and RISC-V `Image` formats, plus the vDSO, which is built with the same Rust toolchain as a `no_std` shared object.

There is no C in the kernel at 1.0. The one optional exception is the driver host in document 12.5, which hosts unmodified Linux driver source compiled by rucc or GCC inside a sandbox, and which is off in every default profile.

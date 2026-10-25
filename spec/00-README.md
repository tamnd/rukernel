# rukernel: a Linux compatible kernel in Rust

rukernel is a new operating system kernel written in Rust. It runs every Linux user space binary unmodified, at Linux speed, by implementing the Linux kernel's user visible interface exactly: the system calls, the ioctls, `/proc` and `/sys`, netlink, the vDSO, the ELF loader, the signal frames. It tracks mainline. Today that is Linux 7.3, tagged on 18 October 2026, and each new mainline release becomes the target within one release cycle.

Through that same interface it also runs unmodified Windows programs and unmodified macOS command line programs. They run in the way they already run on Linux, through Wine, Proton and a Darwin user land, with a small number of kernel primitives that make those layers faster and more faithful than they can be on Linux. No program is recompiled, patched or repackaged to run on rukernel. That is the whole point.

There are three repositories, after `tamnd/rucc`, `tamnd/rucc-compat` and `tamnd/rucc-bench`:

- `tamnd/rukernel`: the kernel.
- `tamnd/rukernel-compat`: the harness that measures compatibility against a real, pinned Linux kernel, differentially, in identical virtual machines (document 18).
- `tamnd/rukernel-bench`: the harness that measures performance against the same Linux on the same machine and publishes every number, including the ones we lose (document 19).

This directory is the specification. It is written to be argued with. Every goal in it is stated so that a measurement can show it false.

## The one thing that changed this year

Three things that were each open questions in 2024 have become facts, and together they make this project an engineering problem rather than a research bet.

First, the framekernel design has been shown to work at Linux speed. Asterinas, a Rust kernel with a Linux ABI, keeps all `unsafe` code in one small framework (about 14% of the code base) and the rest in safe Rust. Its USENIX ATC 2025 paper reports throughput relative to Linux of 1.08 on LMbench, 1.17 on Nginx, 1.31 on Redis and 0.85 on SQLite. By October 2026 it runs 240+ system calls, namespaces and cgroups (0.18), and DRM and AArch64 (0.19). Its memory manager, CortenMM, won the SOSP 2025 Best Paper award with machine checked concurrency proofs.

Second, verifying kernel Rust has become practical. Verus (SOSP 2024), VeriSMo and Anvil (both OSDI 2024 Best Papers), Atmosphere (SOSP 2025) and Asterinas's own `vostd` proofs show that the unsafe core of a kernel can be proved sound with a few person years of effort, not decades. KVerus generated 21% of CortenMM's proof code automatically.

Third, Rust in Linux itself stopped being experimental in 7.0, in April 2026. Binder, Nova, Tyr and rnull are in mainline. The question is no longer whether Rust can express a kernel. It is whether a kernel written in Rust from the start can be the whole kernel, at the same speed, with the same interface.

## The goal, falsifiably

Five axes, each with a number (document 02 has the detail):

1. **ABI compatibility.** All of these are implemented with Linux's exact semantics: 100% of the system calls in the pinned Linux release, 100% of the subsystem independent ioctls and netlink families, and 100% of the procfs and sysfs files that a corpus of distribution images, container images and real applications touches. For every driver rukernel has, 100% of that driver's device ioctls are implemented too. Measured at five levels, L1 to L5, by `rukernel-compat` against the real kernel (document 18).
2. **Performance parity.** The median result on each benchmark class is within 5% of Linux (10% for memory and file system metadata), on the same hardware, with the same mitigations, against both the distribution and the tuned Linux configuration. Every class is reported, and a red row is a red row (document 19).
3. **Foreign programs.** Windows: the same success rate and speed as the same Proton build on Linux 7.3, across the L5 game and application list. macOS: command line Mach-O binaries from Homebrew and the Apple open source tools, at tier D1 (document 16).
4. **Safety.** No `unsafe` outside `rk-frame` and a short list of audited leaf crates. The unsafe budget is 25,000 lines. The public interface of `rk-frame` is verified with Verus (document 20). Memory corruption bugs found by syzkaller in safe crates: zero, by construction. A finding there is a bug in `rk-frame` or the compiler.
5. **Upstream tracking.** The ABI for each new mainline release is regenerated within one week of the tag. The full compat suite runs against the new reference from day one, and every gap is closed or listed within one release cycle, about 63 days (document 17).

## Why Rust, said once

The reason is not fashion. Most of Linux's serious bugs found by syzbot, and a large share of the CVEs the kernel CNA has assigned since 2024, are memory safety and concurrency errors in C. Use after free, out of bounds access, data races, refcount leaks and sleeping in atomic context are compile errors in a Rust kernel built the way document 03 describes. Rust is also the only memory safe language with the control over layout, inline assembly, atomics and allocation failure a kernel needs, and it has no runtime. Rust for Linux has spent five years proving every one of those properties inside Linux itself.

## Settled decisions

These are decided and the rest of the spec builds on them. Reopening one needs a measurement.

- **Framekernel, not microkernel, not monolithic C.** One address space and one privilege level, like Linux, for Linux's speed. All `unsafe` lives in `rk-frame`, and every other crate is `#![forbid(unsafe_code)]` (document 03).
- **The ABI is data.** System call tables, struct layouts, ioctl numbers, netlink specs and the documented sysfs are generated from the pinned Linux tree by `rk-abigen`, never typed by hand (document 04).
- **Stackful kernel threads, not async.** This keeps blocking semantics, signal interruption and `ERESTARTSYS` exactly as Linux has them. Async is used only inside the network stack and io_uring, where it is the natural shape (document 03.4).
- **No Linux modules, but every module name.** rukernel never loads a `.ko`. It is all built in, and `modules.builtin` makes `modprobe` succeed for every component we have (documents 03.7, 12.6).
- **Personalities in user land first.** Windows through unmodified Wine and Proton, macOS through a Darwin user land. The kernel adds primitives only where measurement shows a win (document 16).
- **Differential testing against real Linux is the oracle.** The test is not the man page or the standard. It is a real kernel in an identical VM. Where Linux's behaviour is the bug, we match it and record it (document 18).
- **Stable Rust only.** No nightly features in the shipped kernel. The minimum toolchain moves with Rust's six weekly releases (document 03.9).
- **Panics abort.** The kernel does not unwind, and a panic stops the machine. A file system or a driver gives an error for bad data and does not panic. Unwinding needs unstable features, so it waits for them (document 03.6, open question 3).
- **No GUP fast yet.** Direct I/O copies through a kernel buffer. Zero copy pins frames under the per VMA lock, and io_uring fixed buffers pin at registration. A speculative frame reference waits for a red benchmark row on hardware (document 07.13, open question 4).
- **Licences.** The kernel is GPL-2.0-only, the same as Linux. That makes reading Linux's source and porting its algorithms a question of engineering, not of law, and keeps open the option of code flowing in both directions. `rukernel-compat` and `rukernel-bench` are Apache-2.0, like the rucc harnesses. Personality user land components carry their upstream licences (LGPL for Wine, APSL and others for Darwin).

## The documents

| Doc | Subject |
|---|---|
| 00 | This file |
| 01 | The 2026 landscape: Linux 7.x, Rust kernels, Linux ABI reimplementations, papers, foreign personalities, performance baselines, with sources |
| 02 | The goal, axis by axis, with the measurement for each |
| 03 | Architecture: the framekernel, `rk-frame`, crate layering, execution model, concurrency, errors, modules, config, toolchain |
| 04 | The ABI surface and `rk-abigen` |
| 05 | Processes, credentials, exec, signals, ptrace, futexes, namespaces, rseq |
| 06 | The scheduler: EEVDF, sched_ext, preemption, proxy execution |
| 07 | Memory: frames, folios, slab and sheaves, VMAs, faults, THP, NUMA, reclaim, swap, memcg |
| 08 | The VFS and file systems |
| 09 | The block layer and io_uring |
| 10 | Networking |
| 11 | BPF |
| 12 | Drivers, GPUs, the optional Linux driver host, and why `.ko` cannot load |
| 13 | Security: LSMs, seccomp, Landlock, mitigations, CFI |
| 14 | Containers and KVM: cgroup v2, namespaces, the KVM uAPI, guest_memfd |
| 15 | Boot and platforms: x86-64, arm64, riscv64, firmware, IOMMU |
| 16 | Foreign personalities: Windows, macOS, cross ISA |
| 17 | Tracking upstream |
| 18 | `rukernel-compat` |
| 19 | `rukernel-bench` |
| 20 | Verification and testing |
| 21 | The performance model |
| 22 | Milestones R0 to R12 |
| 23 | Repository and crate layout |
| 24 | Open questions, ranked |

## What this is not

- **Not a Linux fork, and not a translation of Linux to Rust.** No C file in Linux is mechanically converted. The algorithms are Linux's where Linux's behaviour is observable, and the code is new.
- **Not a module loader for Linux drivers.** A `.ko` is compiled against one kernel's internal structures, and rukernel does not have them (document 12.6).
- **Not a research microkernel.** Every design choice that costs Linux compatibility or Linux speed loses, however elegant it is.
- **Not a Windows or macOS kernel.** Programs that need a Windows kernel driver (kernel anti cheat, hardware drivers, endpoint security) or a macOS kernel extension, IOKit driver or system extension cannot run, and we say so.
- **Not a way around Apple's licences.** Apple's closed frameworks may not run off Apple hardware, and rukernel does not ship or load them (document 16).

## Honesty about scope

Linux is about 38 million lines of C and headers, maintained by over 3,000 developers each release. Most of that is drivers. rukernel does not try to replace Linux's driver coverage. It targets the machines where kernels actually run in 2026: virtual machines (virtio), cloud instances, common server hardware (NVMe, the major NIC families), and a short list of laptops and GPUs. A machine whose hardware we do not drive is out of scope until it is not, and the list is published (document 12). Out of tree file systems are the same: ZFS is not planned until open question 7 in document 24 is answered.

The ABI is large but finite and generated. The work it describes is large but not unbounded: around 370 system calls on x86-64, a few hundred ioctl families that matter, netlink families described in YAML, and pseudo files the corpus enumerates. The rest of the work is making each of those as fast as Linux, and that is what the milestones in document 22 are organized around. Each milestone ends at a point where the project is useful even if it stops there.

## The name

ru for Rust and for the rucc family, kernel because that is what it is. `uname -s` says `Linux`, because programs check it, and `uname -r` says the release we claim (document 17.4). `/proc/version` says rukernel.

# The 2026 landscape

This is what was true on 23 October 2026, with a source for each claim. It is the evidence the other documents stand on. Where a fact could not be confirmed it says so, and no design decision rests on an unconfirmed fact. Counts marked "(tree)" were taken by us from the v7.3 tarball (`cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.3.tar.xz`) or from git.kernel.org at the named tag.

## 01.1 Linux, the target

**Releases.** 6.18 on 30 November 2025, 6.19 on 8 February 2026, 7.0 on 12 April, 7.1 on 14 June, 7.2 on 16 August, and 7.3 on 18 October 2026. Each cycle took 63 days. 7.3 set records: 18,765 non merge commits from 3,021 developers, 807 of them first time contributors. The 7.4 merge window opened on 19 October. Sources: https://kernelnewbies.org/LinuxVersions, https://lwn.net/Articles/1101143/, https://www.heise.de/en/news/Linux-kernel-7-3-is-here-with-fixes-across-the-board-11492855.html

**kernel.org on 23 October 2026.** Mainline 7.3. Stable 7.2.12. Longterm 6.18.58, 6.12.114, 6.6.160, 6.1.190, 5.15.223 and 5.10.272. 6.18 is the newest longterm kernel, supported to December 2028. No 2026 longterm has been announced. 7.4, the last release of the year, is the likely choice, but that is an inference from past practice. Ubuntu 26.10 ships 7.3. Sources: https://www.kernel.org/, https://www.kernel.org/category/releases.html

**System calls (tree).** The highest number is 472, `fchroot`, added in 7.3, on x86-64, i386 and the generic table. 471 `rseq_slice_yield` came in 7.0, 470 `listns` in 6.19 and 469 `file_setattr` in 6.18. 7.1 and 7.2 added no system calls. x86-64 in v7.3 has 370 implemented 64 bit and common entries, 16 reserved numbers with no entry point, and 36 x32 entries at 512 to 547. The generic table has 324 numbers with an entry point. There are about 790 `SYSCALL_DEFINEn` sites. Sources: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/arch/x86/entry/syscalls/syscall_64.tbl?h=v7.3, https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/scripts/syscall.tbl?h=v7.3

**`fchroot` and failfs.** `fchroot` takes a directory descriptor. The special `FD_FAILFS_ROOT` moves the caller into failfs, where every operation fails. 7.3 also added a `syscall_user_dispatch` sysctl. Sources: https://lwn.net/Articles/1089244/, https://docs.kernel.org/next/filesystems/failfs.html

**ABI changes by release, 7.0 to 7.3.**

- **7.0:**
  - `OPEN_TREE_NAMESPACE`.
  - `statmount` accepts a descriptor, including for detached mounts.
  - The rseq time slice extension.
  - Deprecation of BSD `acct(2)` begins.
  - A 64 bit vDSO `clock_getres`.
  - The preemption models cut to `PREEMPT_LAZY` and `PREEMPT_FULL` on most architectures.
  - nullfs, file systems opting in to leases, and XFS self healing.
  - Rust no longer experimental.
  - Sources: https://kernelnewbies.org/Linux_7.0, https://lwn.net/Articles/1057769/
- **7.1:**
  - clone3 gains `CLONE_AUTOREAP`, `CLONE_NNP`, `CLONE_PIDFD_AUTOKILL` and `CLONE_EMPTY_MNTNS`.
  - `FSMOUNT_NAMESPACE` and `UNSHARE_EMPTY_MNTNS`.
  - `MOVE_MOUNT_BENEATH` on the root.
  - `pidfd_info.coredump_code`.
  - `sched_getattr` reports runtime and deadline for deadline tasks.
  - `user.*` xattrs on sockets.
  - 64 bit `i_ino`.
  - A new NTFS driver, FRED on by default, an hrtimer core rewrite, and guest_memfd with userfaultfd.
  - Source: https://kernelnewbies.org/Linux_7.1
- **7.2:**
  - `O_EMPTYPATH` and `OPENAT2_REGULAR`.
  - bpf common attributes, and fanotify pidfds.
  - procfs `subset=pid` relaxed, and a robust futex unlock race fixed.
  - Scheduling: cache aware scheduling and proxy execution donor migration.
  - Memory: khugepaged mTHP collapse, and MGLRU gains of up to about 30% on MongoDB/YCSB.
  - Zoned XFS no longer experimental.
  - Sources: https://kernelnewbies.org/Linux_7.2, https://lwn.net/Articles/1088991/, https://www.phoronix.com/news/Linux-7.2-Scheduler
- **7.3:**
  - `binfmt_misc` handlers decided by BPF, and `PT_INTERP` substitution.
  - `UFFDIO_REGISTER_MODE_RWP`, and `RWF_DONTCACHE` on block devices.
  - Landlock `RESTRICT_SELF_NO_NEW_PRIVS`.
  - Kernel threads in their own nullfs, and PID 1 with its own `fs_struct`.
  - sched_ext sub-schedulers complete, and group scheduling modes.
  - File systems: EFS and FreeVxFS removed, the btrfs v1 free space cache removed, overlayfs idmapped mounts, and ntfs3 alternate data streams.
  - Sources: https://kernelnewbies.org/Linux_7.3, https://lwn.net/Articles/1089791/, https://www.phoronix.com/news/Linux-7.3-sched-ext. The KernelNewbies 7.3 page contained a block of instructions aimed at AI readers. It was ignored, and every fact here is cross checked against another source.

**io_uring (tree).**

- v7.3 has 65 `IORING_OP_*` opcodes, up from 63 in v6.18.
- 6.19 added `NOP128`, `URING_CMD128`, `SETUP_SQE_MIXED` and `REGISTER_ZCRX_CTRL`.
- 7.0 added `REGISTER_BPF_FILTER`, the cBPF filter that lets sandboxes restrict io_uring per operation, and `SETUP_SQ_REWIND`.
- 7.1 added `TIMEOUT_IMMEDIATE_ARG`, split the uAPI into `linux/io_uring/*.h`, and added a BPF struct_ops event loop.
- 7.2 added zcrx completion notifications.
- 7.3 gave FUSE over io_uring buffer pools and zero copy.
- Source: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/uapi/linux/io_uring.h?h=v7.3

**BPF.**

- Signed programs landed in 6.18, with `signature` and `keyring_id` in `bpf_attr`.
- 7.0 added SELinux control over BPF tokens.
- 7.2 added a resizable hash map, sleepable tracepoint programs and stack arguments.
- 7.3 added global per CPU data, `__arena` kfunc arguments and signed metadata integrity.
- `enum bpf_cmd` has about 41 entries (tree).
- The Hornet LSM is still out of tree.
- Sources: https://www.phoronix.com/news/Linux-6.18-BPF-Signed-Deferred, https://lwn.net/Articles/1089791/

**Memory management.**

- Slab sheaves landed in 6.18 and replaced per CPU partial slabs in 7.0.
- guest_memfd `mmap` came in 6.18. In place private and shared conversion is still in progress.
- Memdescs are prototype work. Matthew Wilcox calls the 8 byte descriptor "a distant goal".
- The swap table rework ran from 7.0 to 7.3.
- A series making per VMA locks unconditional was queued in linux-next in September 2026.
- Sources: https://www.phoronix.com/news/Linux-6.18-Slab-Sheaves, https://lwn.net/Articles/1074950/, https://lwn.net/Articles/1078539/, https://www.phoronix.com/news/Linux-6.18-KVM

**File systems.** bcachefs was removed in 6.18 and now ships as a DKMS module. Source: https://ostechnix.com/bcachefs-external-dkms-module-linux-kernel/

**Other primitives the personalities need (tree).** `drivers/misc/ntsync.c` defines 14 `NTSYNC_IOC_*` ioctls. The Landlock ABI version is 11, with UDP bind and connect, `FS_RESOLVE_UNIX`, scopes, `RESTRICT_SELF_TSYNC` and logging. The futex2 system calls are 449 and 454 to 456.

**Rust in Linux (tree).**

- 496 `.rs` files, about 192,000 lines.
- Drivers: Android binder, nova-core and nova DRM, Tyr (Arm Mali), rnull, rcpufreq_dt, two PHY drivers, pwm_th1520 and drm_panic_qr.
- No Asahi AGX driver (about 21,000 lines, upstreaming started in 2026) and no Rust NVMe driver in mainline.
- s390 gained Rust in 7.2 and PowerPC in 7.3.
- CVE-2025-68260, a race in rust_binder, is reported as the first CVE in mainline Rust.
- A patch for 7.4 deletes the C binder driver. It is pending.
- Sources: https://lwn.net/Articles/1078068/, https://asahilinux.org/2026/02/progress-report-6-19/, https://www.collabora.com/news-and-blog/blog/2026/10/21/upstreaming-tyr-rust-drm-and-the-linux-kernel/, https://www.phoronix.com/news/Google-Binder-C-Goodbye

**Size of the target (tree).**

- About 95,965 files: 26.7M raw lines of `.c` and 11.0M of `.h`.
- `include/uapi`: 952 files, about 221,000 lines.
- 2,522 `_IO*` ioctl definitions in the generic and x86 uAPI headers, 4,348 tree wide.
- `Documentation/ABI`: 6,460 `What:` entries, 6,268 of them under `/sys`.
- About 22,000 Kconfig symbols.
- 135 kselftest directories, about 330 KUnit suites and about 4,100 KUnit cases.
- No published count exists of the procfs and sysfs files on a typical running system, which is why document 04 generates one.

**Conformance oracles.**

- LTP 20260930 (1 October 2026, 3,000+ tests): https://github.com/linux-test-project/ltp/releases
- syzbot upstream on 23 October: between 1,334 and 1,582 open bugs (the page shows both), 7,571 fixed and 223 missing backports: https://syzkaller.appspot.com/upstream
- KernelCI: about 1.8 million tests per week from 15 to 18 labs: https://ratatoskr.run/kernelci/2026/08/17385552
- gVisor's `test/syscalls` runs against both native Linux and gVisor, and is the nearest thing to a public system call conformance suite: https://github.com/google/gvisor/blob/master/test/syscalls/README.md

## 01.2 Rust kernels

**Asterinas** is the closest prior art, and document 03 adopts its central idea.

- The ATC 2025 paper is "Asterinas: A Linux ABI-Compatible, Rust-Based Framekernel OS with a Small and Sound TCB" (Peng, Tian et al.): https://www.usenix.org/conference/atc25/presentation/peng-yuke and https://arxiv.org/abs/2506.03876
- All `unsafe` code is in OSTD, which is about 14% of the code.
- At paper time it had 210+ system calls, ext2, exFAT, OverlayFS, RamFS, procfs and sysfs, TCP, UDP, Unix and netlink sockets, and virtio and USB, on x86-64 and RISC-V, in over 100,000 lines of Rust.
- Throughput relative to Linux: LMbench 1.08, Nginx 1.17, Redis 1.31, SQLite 0.85.
- Now 240+ system calls and an experimental "Asterinas NixOS": https://github.com/asterinas/asterinas
- 0.18 (June 2026) added namespaces, cgroups, virtio-fs and vsock, aimed at being the Kata Containers guest: https://asterinas.github.io/2026/06/04/announcing-asterinas-0.18.0.html
- 0.19 (13 October 2026) added DRM, AArch64, a device model, and a first self hosted build: https://github.com/asterinas/asterinas/issues/3479
- Daily Kata 3.28 builds use Asterinas as the guest kernel: https://github.com/asterinas/kata-containers/releases/tag/3.28.0-20261022-asterinas
- `vostd` holds Verus proofs of OSTD's memory management and synchronization, and they found real undefined behaviour, deadlocks and overflows: https://github.com/asterinas/vostd
- CortenMM, its memory manager, won the SOSP 2025 Best Paper award: https://sigops.org/s/conferences/sosp/2025/accepted.html

What Asterinas has not shown is the rest of the gap to Linux: full system call coverage, io_uring, BPF, real hardware, Linux class file systems, and parity across all workload classes rather than a selection. That gap is this project.

**Other Rust kernels:**

- **Theseus** (OSDI 2020): intralingual design, a single address space, not a Linux ABI: https://www.usenix.org/system/files/osdi20-boos.pdf
- **RedLeaf** (OSDI 2020): isolation domains from language safety alone, with drivers that match DPDK and SPDK: https://mars-research.github.io/doc/2020-osdi-redleaf.pdf
- **Atmosphere** (SOSP 2025): a Verus verified L4 style microkernel with 6,000 lines of executable code, a proof ratio of 3.32 to 1, under 2.5 person years, and verification in under 20 seconds: https://dl.acm.org/doi/10.1145/3731569.3764821, https://mars-research.github.io/projects/atmo/
- **Tock** (SOSP 2025, "From Research to Securing 10 Million Computers") and **TickTock** (SOSP 2025, Flux verified isolation): https://dl.acm.org/doi/10.1145/3731569.3764828, https://dl.acm.org/doi/10.1145/3731569.3764856
- **Redox**: a microkernel with POSIX source compatibility, not a Linux binary ABI.
- **Maestro**: 135 of 437 system calls, unstable: https://blog.lenot.re/a/introduction
- **Kerla**: unmaintained: https://github.com/nuta/kerla
- **Moss** (late 2025): an async first kernel where system calls are `async fn` and the compiler prevents holding a spinlock across `.await`. It has 109 system calls, AArch64 only, and runs an Arch Linux ARM user land: https://github.com/hexagonal-sun/moss-kernel
- **StarryOS** on ArceOS: claims most Linux system calls, with no performance data: https://github.com/rcore-os/tgoskits/issues/2202
- **Hermit**: a unikernel with no binary ABI.
- **rust-sel4** 5.0: Rust for seL4 user space only.
- **Hyperlight**: micro VMs with no guest kernel, 1 to 2 ms cold start.
- Rust in Windows: `win32kbase_rs.sys`, about 36,000 lines, which had an out of bounds bug in 2025: https://hunterworks.software/teardowns/rust-in-windows-11
- Ferrocene 26.08 is a qualified Rust toolchain. 26.02 certified 5,169 `core` functions: https://ferrous-systems.com/blog/ferrocene-26-08-0/

The lesson from Moss is the strongest argument for an async kernel we have seen, and document 03.4 explains why we still do not use one. Linux's blocking, signal interruption and restart semantics map directly onto stackful threads, and the per task stack costs about 16 KiB, which no one has shown to matter at Linux's scale.

## 01.3 Verification

- Verus (SOSP 2024) verifies 3 to 61 times faster than earlier tools: https://dl.acm.org/doi/10.1145/3694715.3695952
- VeriSMo (OSDI 2024 Best Paper) is a Verus verified SEV-SNP security module that matches C performance: https://www.usenix.org/conference/osdi24/presentation/zhou
- Anvil (OSDI 2024 Best Paper) proves liveness of Kubernetes controllers: https://www.usenix.org/conference/osdi24/presentation/sun-xudong
- jwmalloc (OSDI 2026) is a verified allocator, checked with bounded model checking under weak memory.
- At OSDI 2026, neuro symbolic proof generation automated Isabelle proofs for seL4: https://www.usenix.org/conference/osdi26/technical-sessions
- KVerus generated 21% of CortenMM's proofs: https://arxiv.org/abs/2605.03822
- VeruSAGE studies agent based verification: https://arxiv.org/abs/2512.18436

Document 20 builds on this. Verifying a framekernel's unsafe core with Verus is no longer novel. It is what a careful project now does.

## 01.4 Linux ABI reimplementations, and what broke them

- **gVisor:**
  - A Go user space kernel, with systrap (seccomp `SECCOMP_RET_TRAP`) as the default platform.
  - 290 of 352 amd64 system calls are full or partial, and 253 of 295 on arm64.
  - io_uring is off by default.
  - `/proc` and `/sys` are incomplete.
  - Cgroups inside the sandbox do not enforce limits.
  - Netfilter is partial.
  - Sources: https://gvisor.dev/docs/user_guide/compatibility/linux/amd64/, https://gvisor.dev/docs/user_guide/compatibility/
- **WSL1:**
  - Pico processes translated Linux calls to NT. Microsoft replaced it with a real Linux kernel in WSL2 for "file system performance and full system call compatibility".
  - Tar unpacking became up to 20 times faster.
  - The causes were VFS semantic mismatch, slow metadata, no FUSE, and no namespaces or cgroups.
  - Source: https://learn.microsoft.com/en-us/windows/wsl/compare-versions
- **FreeBSD linuxulator:**
  - No cgroups, namespaces or systemd. The default user land is Rocky 9.
  - Its sibling, LinuxKPI, runs Linux DRM drivers.
  - Sources: https://docs.freebsd.org/en/articles/linux-emulation/, https://cdaemon.com/posts/pwS7dVqV
- **illumos LX brand:**
  - Emulates proc, cgroup and sysfs, has no modules, and has never been upstreamed. It runs systemd Debian zones in 2026.
  - Sources: https://man.omnios.org/man7/lx, https://it-notes.dragas.net/2026/09/28/smartos-the-illumos-way-of-thinking-about-servers/
- **Fuchsia Starnix:**
  - A Rust user space Linux kernel on Zircon that aims for bug for bug compatibility.
  - Restricted mode (RFC-0261), AArch32 (RFC-0264), a `UserAddress` type for user pointers, `track_stub!` for gaps.
  - Sources: https://fuchsia.dev/fuchsia-src/concepts/starnix/kernel, https://fuchsia.dev/fuchsia-src/contribute/governance/rfcs/0261_fast_and_efficient_user_space_kernel_emulation
- **Unikraft:** binary compatibility through an ELF loader and a system call shim: https://unikraft.org/docs/concepts/compatibility
- **Gramine:** about 170 of about 360 system calls: https://gramine.readthedocs.io/en/v1.8/devel/features.html
- **Junction** (NSDI 2024): a kernel bypass library OS with its own Linux system call layer: https://www.usenix.org/conference/nsdi24/presentation/fried
- **Loupe** (ASPLOS 2024):
  - 40 to 60% of the system calls an application references can be stubbed or faked, and static analysis overestimates by 2 to 5 times.
  - Faking futex breaks Redis.
  - Stubbing `prlimit64` cut Redis's memory use by 30%, a reminder that stubs change behaviour.
  - Sources: https://arxiv.org/abs/2309.15996, https://github.com/unikraft/loupe

**The recurring failures** across gVisor, WSL1, LX and the linuxulator are the same list every time:

- `/proc` and `/sys` contents.
- cgroups and namespaces.
- ptrace and CRIU.
- netfilter.
- FUSE.
- File system semantics: case, permissions, symlinks, metadata speed.
- Kernel modules.

None of them failed on the system call table itself. That is why rukernel generates its pseudo file manifests from a booted reference (document 04), treats containers as first class targets (document 14), and puts the trace differential (document 18) on every pull request. Loupe tells us what order to build things in. It does not tell us we may stop. The goal is all of the ABI, because the programs we have not traced are the ones users will run.

## 01.5 Research directions we use, 2024 to 2026

- **LLM assisted kernel work:**
  - KernelGPT (ASPLOS 2025) synthesizes syzkaller descriptions and found 24 bugs and 11 CVEs: https://github.com/ise-uiuc/KernelGPT
  - KNighter (SOSP 2025) synthesizes static checkers.
  - OSFoundry (arXiv, August 2026) is an agent harness writing code against a persistent specification. It generated SpecOS, which passes 70 of 70 functional tests: https://arxiv.org/abs/2609.25018
  - AutoDriver and DriveBench port drivers across API changes at 56.4% compile success: https://arxiv.org/abs/2511.18924
  - K-Repro reproduces n-day bugs: https://arxiv.org/abs/2602.07287
  - ECO (OSDI 2026) is an optimizer deployed at Google.
  - Document 17 uses these for upstream tracking, always behind the compat harness.
- **Scheduling:**
  - sched_ext (6.12).
  - PeeR (OSDI 2026): preemptible eBPF on sched_ext.
  - kSTEP (OSDI 2026): deterministic testing of Linux scheduler bugs, which document 20.5 adapts.
  - Xkernel (OSDI 2026): live tuning of kernel constants: https://arxiv.org/abs/2512.12530
- **Memory:**
  - CortenMM (SOSP 2025).
  - Scalable address spaces with a concurrent interval skiplist (SOSP 2025).
  - cache_ext (SOSP 2025): eBPF page cache policies.
  - MEMTIS (SOSP 2023): https://github.com/cosmoss-jigu/memtis
  - TPP (ASPLOS 2023): https://arxiv.org/abs/2206.02878
  - The OSDI 2026 CXL and tiering papers: MAC, LiteSwitch, NEMO.
- **Storage:**
  - BypassD (ASPLOS 2024): 42% lower 4 KiB latency than Linux, with IOMMU mediated user space access: https://dl.acm.org/doi/10.1145/3617232.3624854
  - Aeolia and GoFS (SOSP 2025).
  - DeLFS, Oxbow and Declarative IO (OSDI 2026).
- **Networking:** Rakaia (OSDI 2026, in kernel RPC scheduling), SBB (user interrupts), Sepia (DDIO and page colouring).
- **BPF:** "Prove It to the Kernel" (verifier precision, SOSP 2025), eBPF misbehaviour detection (SOSP 2025), vBPF (OSDI 2026).
- **Isolation:**
  - μFork (SOSP 2025): fork in a single address space on CHERI: https://arxiv.org/abs/2509.09439
  - CHERIoT RTOS (SOSP 2025).
  - Ichnaea (MPK) and Mohabi (SFI) at OSDI 2026.
- **Driver reuse:** DD/OS (OSDI 2004), FreeBSD LinuxKPI, and μUSB (OSDI 2026), which derives a minimal driver from traces of the full one. They inform document 12.5.
- **Syscall interposition pitfalls:** K23 (Middleware 2025): https://dl.acm.org/doi/10.1145/3721462.3770772

## 01.6 Foreign personalities

**Windows.**

- Wine 11.0 (13 January 2026):
  - The new WoW64 design is complete. One loader runs 32 bit PE code thunked to 64 bit Unix libraries, so no 32 bit host libraries are needed.
  - It uses ntsync, follows modern NT system call numbering, and uses userfaultfd for write watches.
  - Sources: https://www.winehq.org/news/2026011301, https://www.heise.de/en/news/Wine-11-0-uncorks-New-WoW64-architecture-is-complete-11140791.html
- ntsync (Linux 6.14): Dirt 3 went from 110 to 861 fps against plain Wine, with smaller gains against fsync: https://www.gamingonlinux.com/2025/01/ntsync-for-proton-wine-now-in-linux-kernel-6-14-that-should-make-many-steamos-users-happy/
- Proton 11.0-1 came on 7 July 2026, and 11.0-2 is current: https://www.techtimes.com/articles/319940/20260708/proton-11-stable-fixes-ea-desktop-regression-brings-18-new-linux-games.htm
- ProtonDB derived data: 88% of Steam games are Silver or better and 83% Gold or better. About 3% of the top 1000 are blocked, almost all by kernel anti cheat: https://www.tomshardware.com/software/linux/nearly-90-percent-of-windows-games-now-run-on-linux-latest-data-shows-as-windows-10-dies-gaming-on-linux-is-more-viable-than-ever
- AreWeAntiCheatYet: about 55% of about 1,166 anti cheat titles are broken: https://github.com/FinnHering/AreWeAntiCheatYet
- VKD3D-Proton 3.0 (November 2025): https://github.com/HansKristian-Work/vkd3d-proton/releases/tag/v3.0
- Hangover 11 pairs Wine with FEX or Box64 on arm64: https://www.phoronix.com/news/Hangover-11.0-Released
- NT system call numbers change between Windows builds, and the stable boundary is the DLL surface: https://j00ru.vexillium.org/syscalls/nt/64/
- WSL1 is the counter example: Microsoft controlled both sides and still gave up on emulating one kernel's semantics inside another.

**macOS.**

- Darling v0.1.20260608 uses darlingserver, a user space kernel server built partly from XNU source. It replaced a Linux kernel module that was "too unstable". Mach traps use negative numbers. Command line tools work, and graphical programs are basic and experimental. Sources: https://github.com/darlinghq/darling/releases, https://docs.darlinghq.org/internals/darlingserver/index.html, https://docs.darlinghq.org/internals/basics/system-call-emulation.html
- PureDarwin boots open Darwin to a shell: https://www.puredarwin.org/handbook/roadmap.html
- Apple's licences:
  - The Xcode and SDK agreement says "AUTHORIZED ONLY FOR EXECUTION ON AN APPLE-BRANDED PRODUCT RUNNING MACOS": https://www.apple.com/legal/sla/docs/xcode.pdf
  - The macOS 27 licence: https://www.apple.com/legal/sla/docs/macOS27.pdf
- Rosetta 2 is fully supported through macOS 27. macOS 28 keeps a reduced form for older games: https://developer.apple.com/news/?id=w5ngl9k2
- Third party arm64e binaries are expected from macOS 26 on. This rests on an Apple forum statement and is partly unverified. They need pointer authentication with Apple's key ABI: https://clang.llvm.org/docs/PointerAuthentication.html
- Asahi Linux has M3 support in its installer without GPU acceleration, as of September 2026. M4 and M5 are in bring up: https://asahilinux.org/2026/08/progress-report-7-2/

**Cross ISA.**

- FEX 2610, with monthly releases and a JIT disk cache since 2609: https://fex-emu.com/FEX-2608/
- Box64 0.4.4, with DynaCache by default: https://box86.org/2026/08/new-box64-v0-4-4-release/
- Rosetta for Linux VMs uses a per thread `ACTLR.TSOEN` toggle through a prctl: https://developer.apple.com/documentation/virtualization/accelerating-the-performance-of-rosetta
- Microsoft Prism emulates AVX and AVX2 since October 2025.

**Historical personalities:**

- Linux `personality(2)` and iBCS.
- `binfmt_misc`.
- FreeBSD's alternate sysent tables.
- Solaris branded zones: http://parallels.nsu.ru/~dkolbin/brandz.html
- The NT subsystems: csrss, OS/2, POSIX, Interix, then WSL1: https://brianreiter.org/2010/08/24/the-sad-history-of-the-microsoft-posix-subsystem/
- XNU's dual Mach and BSD tables.

The lesson of NT's history, that GUI personalities move into the kernel under performance pressure (win32k in NT 4.0), is why document 16 leaves room for `rk-nt` and `rk-mach` but requires a measured win first.

## 01.7 Performance baselines

- **`getpid` round trip:**
  - About 107 ns with eIBRS and no KPTI: https://www.freecodecamp.org/news/how-a-system-call-actually-works-in-linux/
  - 166 ns on a Threadripper 2950X with 6.8: https://arxiv.org/pdf/2608.26871
  - 76 to 620 ns depending on mitigations: https://gms.tf/on-the-costs-of-syscalls.html
- **vDSO `clock_gettime`:** about 17 ns.
- **Context switch:** lmbench `lat_ctx` is about 1.2 to 1.5 µs pinned, about 3.1 µs across cores, and about 7.9 µs under full load: https://www.sobyte.net/post/2022-06/ctx-switch/
- **Page faults:** per VMA locks doubled fault handling performance in 6.4 and reached nearly three times by 6.6: https://lwn.net/Articles/937943/
- **io_uring against epoll:** naive io_uring ties or loses. The wins come from multishot receive, provided buffer rings, batching and zero copy: https://github.com/axboe/liburing/issues/536
- **gVisor:** third party figures put its overhead at 10 to 30% on I/O and 2.2 times or worse on simple system calls: https://northflank.com/blog/what-is-gvisor

These are the floor document 21 builds its budget from. They also show how much mitigations matter: the spread in `getpid` cost across mitigation settings is larger than any plausible difference between two well written kernels. That is why document 19 matches mitigations before it measures anything.

## 01.8 What follows for rukernel

1. The framekernel is proven at Linux speed on a subset. The open question is coverage, and coverage is mostly a matter of generation and testing, which documents 04 and 18 address.
2. Compatibility projects die on pseudo files, containers, ptrace, netfilter and file system semantics, not on system calls. Those are first class in this spec.
3. Foreign personalities are mostly user land problems that a near perfect Linux ABI solves for free. Kernel work is limited to a few primitives, and two of them (ntsync and futex_waitv) are already in Linux.
4. Verifying the unsafe core is practical in 2026 and should be done from the start, not retrofitted.
5. Linux moves every 63 days with about 18,000 commits. Tracking it has to be a pipeline, not a project (document 17).

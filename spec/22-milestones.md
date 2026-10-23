# Milestones

Thirteen milestones, R0 to R12. Each one has an exit criterion a script can check. Each one also ends at a sane stopping point: if the project stopped there, what exists would still be useful to someone. The order follows the corpus. Things real programs need first come first, and the tests that judge each milestone come from document 18 and document 19.

1.0 is R10. R11 and R12 come after 1.0.

## R0: The skeleton

**Contents:**

- `rk-frame` boots on x86-64 under QEMU through the Linux boot protocol and UEFI.
- Serial console, the frame allocator, kernel page tables, traps and interrupts, one CPU.
- `rk-abigen` generates the system call tables, struct layouts and constants from v7.3 for x86-64, arm64 and riscv64.
- `rukernel-compat` L1 runs.
- The repository layout of document 23, the unsafe rule enforced in the build, and CI with boot tests.

**Exit:** `rkc l1 --reference 7.3` passes for x86-64. Every system call number resolves to a stub returning `ENOSYS`. CI enforces `#![forbid(unsafe_code)]` outside `rk-frame`.

**If we stop here:** a generated, versioned, machine readable Linux ABI with a differ, which is useful on its own to gVisor, Starnix, Asterinas and anyone else reimplementing Linux.

## R1: A static binary runs

**Contents:**

- Processes and threads.
- ELF loading for static and static PIE binaries.
- `mmap` and anonymous memory.
- tmpfs as root from an initramfs.
- Pipes, basic signals, `wait`, and the console tty.
- The vDSO.

**Exit:**

- A static BusyBox boots to a shell under QEMU.
- The gVisor syscall suite runs, and its pass rate is reported.
- LTP's `syscalls` group runs, and its pass rate is reported.

**If we stop here:** a teaching kernel with a real ABI.

## R2: glibc, dynamically

**Contents:**

- The dynamic loader path (`PT_INTERP`, the auxv in full).
- Futexes and robust lists.
- `clone3` and pthreads.
- Full signal semantics with restart.
- ptrace for gdb and strace.
- seccomp with classic BPF.
- epoll, eventfd, timerfd and signalfd.
- `/proc` per process files.
- Unix sockets.
- SMP with a first EEVDF.

**Exit:**

- Alpine and Debian minimal root file systems (in tmpfs) boot to a shell with `init=/bin/sh`.
- gdb and strace work on a program.
- gVisor suite pass rate at or above 80%.

**If we stop here:** a Linux compatible runtime for single machine, CLI workloads.

## R3: Storage

**Contents:**

- virtio-blk.
- The block layer with mq-deadline.
- The page cache with large folios and writeback.
- ext4 read and write with the journal.
- xfs read.
- overlayfs.
- devtmpfs and sysfs.
- The mount API.

**Exit:**

- Debian boots from an ext4 disk image to a login prompt.
- fstests' `quick` group passes on ext4 at the same pass set as the reference.
- `e2fsck` is clean after every test.

**If we stop here:** a kernel for VM appliances with a persistent disk.

## R4: Memory, scheduling and networking at depth

**Contents:**

- **Memory:** per VMA locks, THP and mTHP, MGLRU, swap and zswap, NUMA policies, userfaultfd, memfd and seals, and KSM.
- **The CortenMM experiment:** an alternative `rk-mm` backend with per page table node locking, measured against the VMA design on `will-it-scale` and checked for fidelity against `/proc/<pid>/maps` and `smaps` (document 07.5).
- **Scheduling:** the full EEVDF and the load balancer, cgroup v2 cpu and memory, and PSI.
- **Networking:** virtio-net, TCP and UDP with CUBIC and BBR, rtnetlink, and `/proc/net`.
- **arm64:** brought up to tier 1.

**Exit:**

- On x86-64 and arm64, LTP `syscalls`, `mm`, `sched` and `net` reach the reference's pass set apart from listed exceptions.
- The first `rukernel-bench` table is published for the entry, scheduling, memory and networking classes. Red rows are allowed at this milestone, and the table lists them.
- A decision on CortenMM is recorded (document 24, question 1).

**If we stop here:** a credible server kernel for network services in VMs.

## R5: A distribution, with systemd

**Contents:**

- systemd as PID 1, with everything it needs:
  - cgroup v2 with all controllers, all namespaces and pidfds;
  - the eBPF interpreter, maps and cgroup programs;
  - netlink families for `networkd`, `resolved` and `udevd`;
  - uevents, the keyring, `fanotify` and `inotify`;
  - AppArmor and SELinux in permissive then enforcing mode;
  - the TPM driver.
- nftables.
- The rest of `/sys` and `/proc` for the corpus.

**Exit:**

- L4 distribution images boot to multi user and pass their smoke tests on both tier 1 architectures: Debian 13, Ubuntu 26.04 and 26.10, Fedora 44, Arch, Alpine 3.22 and NixOS 26.05.
- systemd's own integration tests (`TEST-*`) reach the reference's pass set apart from listed exceptions.

**If we stop here:** a drop in kernel for distributions in VMs.

## R6: Containers, KVM guests, and Windows programs

**Contents:**

- **Containers:** Docker, Podman, containerd and Kubernetes conformance; CRIU; runc, crun and youki.
- **KVM:** the KVM host on x86-64 (VMX and SVM, without nested virtualization).
- **Graphics:** virtio-gpu with Venus, DRM and KMS core.
- **The Windows persona** (document 16.3): ntsync, futex_waitv, syscall user dispatch, uffd write protect, and casefold tmpfs and ext4.
- **io_uring:** the 65 opcodes.

**Exit:**

- Kubernetes conformance passes on a three node cluster of rukernel nodes.
- CRIU `zdtm` passes at the reference's pass set.
- QEMU on a rukernel host boots the L4 Linux images and Windows 11.
- The first L5 Proton list runs under Venus with success rates and frame times compared to Linux 7.3 on the same host.
- liburing's test suite passes at the reference's pass set.

**If we stop here:** a kernel for container hosts and cloud VMs, and a Linux compatible base for games in a VM.

## R7: Observability and the rest of BPF

**Contents:**

- **BPF:** the JIT for all three architectures, BTF, CO-RE with shadow structures (document 11.4), fentry, fexit, kprobes and tracepoints, the ring buffer, and BPF LSM.
- **perf:** `perf_event_open` with hardware counters, sampling and call graphs.
- **Tracing:** ftrace compatible tracefs.
- kexec and kdump.

**Exit:**

- kselftest `bpf` (`test_progs`, `test_verifier`) reaches the reference's pass set apart from listed exceptions.
- The verifier verdict differential over the BPF corpus agrees on 100% of programs.
- bpftrace, libbpf-tools, Cilium, Falco and Tetragon run their own test suites.
- `perf` and `rr` pass their test suites.

**If we stop here:** a kernel operators can observe and debug with the tools they already use.

## R8: Bare metal servers and performance parity

**Contents:**

- **Real hardware:** NVMe on PCIe; ice, mlx5 and bnxt_en; AHCI and xHCI; ACPI in full; IOMMU strict and lazy; cpufreq and cpuidle.
- **Scheduling and kernel bypass:** sched_ext with sub schedulers, XDP and AF_XDP, devmem and zcrx on mlx5.
- **riscv64** at tier 2.
- **Verified core:** Verus proofs of the frame allocator, page tables, user memory access, and locks and RCU (document 20.2, items 1 to 4).

**Exit:**

- On the bare metal reference fleet (document 19.3), every server class row of the bench table is green at the 1.0 gates.
- The proofs for items 1 to 4 check.

**If we stop here:** a production server kernel for the supported hardware, which is the core of the project's value.

## R9: macOS command line programs, and arm64 parity

**Contents:**

- **`rk-mach`:** Mach ports and IPC, kqueue with Mach port filters, the workqueue, ulock and psynch, the shared region, and the commpage.
- **A Darwin user land** from Apple's open source and Darling, with the D1 corpus (document 16.4).
- **Cross ISA:** FEX and Box64 personas with the TSO prctl on Apple Silicon.
- **arm64:** server bench parity.

**Exit:**

- The D1 corpus passes its test suites at the target rate against a Mac running the same macOS version.
- x86-64 Linux programs run on arm64 rukernel through FEX at the same success rate as on arm64 Linux.
- arm64 bench rows are green.

**If we stop here:** the first kernel that runs Linux, Windows and macOS command line programs side by side, unmodified.

## R10: The desktop and 1.0

**Contents:**

- **GPUs:** xe and amdgpu (RDNA 2 and later) with KMS, render and display.
- **Laptop support** (document 12.7): Wi-Fi, Bluetooth, SOF audio, webcams through libcamera, suspend and resume, and battery.
- **The reference laptops:** Framework 13 AMD, ThinkPad X1 Carbon, and Apple M1 and M2 under Asahi.
- **Networking and storage:** NVMe over TCP and RDMA, and an nftables JIT if measurement asks for one.
- **Containers:** cgroup v1 read paths for old containers.
- **The Linux driver host** (document 12.5) as an opt in.
- **Upstream tracking:** the 63 day gate met for two consecutive upstream releases.

**Exit, which is the 1.0 definition:** all five axes of document 02 are at their 1.0 gates:

- ABI coverage 100% with the register of exceptions published;
- the bench table green on every class on the reference fleet;
- the Windows L5 list at parity with Linux on bare metal GPUs;
- macOS D1;
- the safety measures;
- the upstream gate met.

**If we stop here:** 1.0.

## R11: Beyond Linux's own primitives

**Contents:**

- **`rk-nt`** (document 16.3): in kernel NT object, handle and wait primitives for Wine. It ships only if it shows a measured win on the L5 Proton scenarios, and only after being offered upstream to Wine and Linux.
- **macOS D2:** daemons and XPC services, launchd semantics.
- **Hardware and file systems:** nova for NVIDIA, Mali and AGX GPU drivers, f2fs, NFS server and ksmbd.
- **Confidential computing:** SEV-SNP and TDX host support.

**Exit:** each item has its own L5 scenario at parity or better.

## R12: The verified kernel

**Contents:**

- Verus proofs for the rest of `rk-frame`: DMA and IOMMU, per CPU, timers, and the remaining interfaces.
- The BPF verifier's range analysis verified.
- The scheduler replay harness's properties (document 20.5) proved for the EEVDF core rather than only tested.

**Exit:** every public function in `rk-frame` has a checked proof against its specification, and the trusted base list (document 20.2) contains only the compiler, the assembly, the hardware and Verus.

## How long

The spec does not promise dates, because the dominant uncertainty is people, not technology. For scale:

- Asterinas reached its ATC 2025 state (210+ system calls, Linux class performance on a selection of workloads) in about three years with a team of a few dozen people.
- Starnix reached Android compatibility in a similar period with a larger team.
- R0 to R5 is roughly that scope.
- R6 to R10 is several times more. It is mostly driver work and the long tail of the ABI, which is where generation (document 04), the harness (document 18) and machine assistance under the harness (document 17.3) are meant to change the arithmetic.

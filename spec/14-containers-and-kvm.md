# Containers and KVM

Most Linux kernels in production in 2026 run containers, and many of them run virtual machines too. Both are interfaces where the earlier Linux reimplementations failed, as document 01.4 lists. For containers the reason is that cgroups and namespaces cut across every subsystem. For KVM the reason is that it is a second ABI, between the kernel and a VMM, with its own large surface. rukernel treats both as first class from R5.

## 14.1 Namespaces

All eight namespace types with Linux's semantics:

- **mount** (document 08.3)
- **UTS**
- **IPC:** System V IPC and POSIX message queues
- **PID:** nested, with `/proc` per namespace, `NS_LAST_PID`, `ns_last_pid`, and PID 1 signal semantics
- **network** (document 10.8)
- **user** (document 13.1)
- **cgroup**
- **time:** `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` offsets, and the vDSO page per time namespace

The interfaces are `clone`, `clone3` (with the 7.1 flags), `unshare`, `setns` (including by pidfd with multiple flags at once), and the `nsfs` file handles in `/proc/<pid>/ns/*`. Namespace files support `NS_GET_USERNS`, `NS_GET_PARENT`, `NS_GET_NSTYPE`, `NS_GET_OWNER_UID`, `NS_GET_MNTNS_ID` and the 6.x mount namespace ID ioctls, plus `listns` (6.19, number 470), which lists namespaces by type and owner.

In the kernel, a task's namespaces are an `Arc<NsProxy>` of typed handles. Every lookup that depends on a namespace takes the handle explicitly: a PID lookup takes `&PidNs`, a route lookup takes `&NetNs`. "Looked up in the initial namespace by mistake" is the cause of a long list of Linux container escapes, and here it is a missing argument, caught at compile time.

## 14.2 cgroup v2

cgroup v2 is the interface. systemd requires it, every container runtime uses it, and since 2024 the major distributions have dropped v1 by default. cgroup v1 is supported for the controllers and file names old container images still read: the read paths only, mounted in hybrid layout when asked, post 1.0.

The controllers:

| Controller | Interface files | Notes |
|---|---|---|
| cpu | `cpu.weight`, `cpu.weight.nice`, `cpu.max`, `cpu.max.burst`, `cpu.idle`, `cpu.uclamp.*`, `cpu.stat`, `cpu.pressure` | hierarchical EEVDF weights and bandwidth control (document 06) |
| cpuset | `cpuset.cpus`, `cpuset.mems`, `.effective`, `cpuset.cpus.partition`, `cpuset.cpus.exclusive` | partitions for isolated CPUs |
| memory | `memory.current`, `min`, `low`, `high`, `max`, `peak` (writable since 6.12), `swap.*`, `zswap.*`, `oom.group`, `memory.stat` with every key, `memory.events`, `memory.reclaim`, `memory.pressure`, `memory.numa_stat` | document 07.11 |
| io | `io.max`, `io.weight`, `io.latency`, `io.cost.qos` and `io.cost.model`, `io.stat`, `io.pressure` | iocost and iolatency as Linux implements them |
| pids | `pids.max`, `pids.current`, `pids.peak`, `pids.events` | |
| rdma, hugetlb, misc, dmem | as Linux | `dmem` (6.14) is the device memory controller for GPUs |
| freezer | `cgroup.freeze`, `cgroup.events` | |
| perf_event | implicit in v2 | |

Plus the core files: `cgroup.procs`, `cgroup.threads`, `cgroup.type` (threaded mode), `cgroup.subtree_control`, `cgroup.controllers`, `cgroup.max.depth`, `cgroup.max.descendants`, `cgroup.stat`, `cgroup.kill`, `cgroup.pressure`, and the `nsdelegate`, `memory_recursiveprot`, `memory_hugetlb_accounting` and `pids_localevents` mount options.

**PSI** (pressure stall information) in `/proc/pressure/*` and per cgroup, with poll triggers. systemd-oomd and Android's lmkd depend on its exact semantics, and `rukernel-compat` tests it with a load generator against both kernels.

**BPF on cgroups.** The cgroup BPF attach points (`cgroup_skb`, `sock`, `sock_addr`, `sockopt`, `sysctl`, `device`, `getsockopt`), which systemd uses for `IPAddressDeny`, `DeviceAllow` and socket binding restrictions (document 11).

## 14.3 The container stack as test

The L4 and L5 corpus (document 18.6) includes the full stack:

- **Runtimes:** runc, crun and youki, with their own integration tests run on both kernels. These exercise every namespace, cgroup, seccomp, mount and capability edge.
- **Engines:** Docker, Podman (rootless, with pasta networking and fuse-overlayfs or native overlay with idmapped mounts), and containerd with nerdctl.
- **Kubernetes:** a full conformance run (the Sonobuoy certified conformance suite) on a three node kind or kubeadm cluster with rukernel nodes. The CNI matrix is Cilium (eBPF), Calico (nftables and eBPF modes) and Flannel. kube-proxy runs in nftables and IPVS modes.
- **systemd's nspawn and portable services**, and LXC and Incus system containers.
- **CRIU:** checkpoint and restore of containers through its `zdtm` test suite. It is the most exhaustive single test of ABI fidelity there is, because CRIU must reconstruct every piece of kernel state from user space.
- **Sandboxed runtimes:** gVisor itself running on rukernel (its systrap platform uses seccomp and shared memory, a good stress test), Kata Containers with rukernel as both host and guest kernel, and Firecracker.

Asterinas 0.18's focus on Kata guests (document 01.2) shows that the guest kernel role is a sensible early target. It needs only virtio and a narrow device set, yet it carries real container workloads.

## 14.4 KVM

rukernel is a KVM host. This matters for two reasons. Cloud and developer machines run VMs: QEMU, Firecracker, Cloud Hypervisor, crosvm, libvirt, GNOME Boxes, Android's emulator, and Kata. And the compat harness itself runs Linux and rukernel in VMs, so a rukernel host running the harness is the ultimate self test.

The KVM uAPI is a large, well specified ioctl interface on `/dev/kvm`, VM file descriptors and vCPU file descriptors:

- capability negotiation (`KVM_CHECK_EXTENSION` with about 240 capabilities in v7.3),
- memory slots with dirty logging (bitmap and dirty ring),
- `KVM_RUN` with the shared `kvm_run` structure and every exit reason,
- register and MSR access, CPUID setting,
- the in kernel interrupt controllers (IOAPIC, PIC and LAPIC on x86; vGIC v3 and v4 on arm64; AIA on RISC-V),
- irqfd, ioeventfd and IRQ routing,
- the PIT and kvmclock, Hyper-V enlightenments (for Windows guests), and Xen emulation (for Xen guests on KVM, used by some clouds),
- nested virtualization,
- the stats file descriptors (binary stats), and `/sys/kernel/debug/kvm`.

**guest_memfd** (6.8, with `mmap` in 6.18 and userfaultfd in 7.1) is the memory model for confidential VMs and for VMMs that want guest memory not mapped into the host. Confidential computing comes after the base:

- AMD SEV-SNP host support,
- Intel TDX host support,
- Arm CCA when the hardware is common,
- and, on the guest side, rukernel booting as an SNP or TDX guest (document 15.6).

**Implementation.** The architecture specific core is VMX, SVM and their VMCS and VMCB handling, the EPT and NPT page tables, and VM entry and exit with their speculation barriers. It lives in `rk-frame`, because it is the definition of unsafe hardware interaction, and it is about 5,000 lines of the `rk-frame` budget (document 03.2). Everything above it is safe Rust: the instruction emulator for MMIO exits, the interrupt controllers, CPUID policy, the memory slot management and the uAPI. Linux's KVM is around 150,000 lines in x86 alone, much of it emulator and nested virtualization. The split puts most of that in safe code.

The tests are kselftest's `kvm` directory (over 100 tests), `kvm-unit-tests` from the upstream project, QEMU's own test suite, and booting the L4 guest image set (Linux distributions, FreeBSD, and Windows 11 with Hyper-V enlightenments and virtio-win drivers) under QEMU on a rukernel host. Performance targets are in document 19: VM exit round trip, boot time of a Firecracker microVM, and the virtio-net and virtio-blk paths with vhost.

**vhost.** vhost-net, vhost-vsock, vhost-scsi and vhost-user (through the VMM), and VFIO with IOMMUFD (6.x) for device passthrough, including mediated devices and SR-IOV virtual functions.

# The ABI surface, as data

"100% compatible with Linux" is a claim about an interface, and the interface has to be written down before the claim can be checked. Linux does not write it down in one place. It is spread over syscall tables, uAPI headers, a few thousand ioctl definitions, YAML netlink specifications, `Documentation/ABI`, the procfs and sysfs implementations themselves, BTF, and behaviour that is written down nowhere. This document defines the inventory, how it is generated from a pinned Linux tree on every release, and how the rest of the kernel consumes it.

The principle: **the ABI is data generated from upstream, never hand typed.** A hand typed struct layout is a bug waiting for an architecture, and a hand maintained syscall list is out of date on the day 7.4 is tagged.

## 4.1 What counts as the ABI

Everything a user space program can observe or depend on without loading kernel code:

1. **System calls**: numbers per architecture, argument types, return conventions, and the compat (32 bit) entry points.
2. **uAPI types**: every struct, union, enum, flag and constant under `include/uapi` and `arch/*/include/uapi`, with their layout on each ABI (x86-64, x32, i386 compat, arm64, arm32 compat, riscv64).
3. **ioctls**: every command number, its direction and size, and the struct it carries, per device type.
4. **netlink**: every family (rtnetlink, generic netlink families, nftables, audit, connector, uevent, sock_diag, xfrm), every message type, attribute and nesting.
5. **Pseudo file systems**: every file under `/proc`, `/sys`, `/sys/fs/cgroup`, `/sys/kernel/tracing`, `/sys/fs/bpf`, `/dev`, with its format, permissions and write semantics.
6. **Signals and the signal frame**: `siginfo_t` per signal and code, the `ucontext` layout per architecture, the restorer contract, alternate stacks, and the FPU and vector state layout inside the frame (XSAVE on x86, the `sigcontext` extension records on arm64).
7. **The process start contract**: ELF loading, the auxiliary vector, the initial stack layout, `AT_*` values, the vDSO's exported symbols and versions, and the `PT_GNU_STACK`, `PT_GNU_PROPERTY` (IBT and SHSTK, BTI) handling.
8. **BPF**: program types, attach types, helper IDs and signatures, kfuncs exposed through BTF, map types, the instruction set and the verifier's acceptance behaviour (document 11).
9. **io_uring**: opcodes, SQE and CQE layouts, setup flags, registration opcodes, and the ring memory layout.
10. **`prctl`, `fcntl`, `setsockopt`/`getsockopt`, `ptrace` requests, `keyctl` commands, `perf_event_open` attribute layout and event encodings, `arch_prctl`, `seccomp` operations, `bpf` commands, `madvise` advice values**: the multiplexed calls whose real surface is their command space.
11. **Behaviour**: errno choice, ordering (directory entries, `/proc` listings, `epoll` ready list), what is atomic, what is interruptible, limits (`PATH_MAX`, `ARG_MAX` as derived from `RLIMIT_STACK`, `pipe` capacity), and the exact text of the files people parse.

The last item is the one that cannot be generated, and it is most of the work. Documents 05 through 14 own it per subsystem, and document 18's differential is how it is checked.

## 4.2 The sources, per category

| Category | Upstream source | Machine readable? |
|---|---|---|
| Syscall numbers | `arch/x86/entry/syscalls/syscall_64.tbl` and `syscall_32.tbl`; `scripts/syscall.tbl` (the generic table used by arm64, riscv and the newer ports since 6.11) | yes, a table |
| Syscall signatures | `SYSCALL_DEFINEn` and `COMPAT_SYSCALL_DEFINEn` in the tree; `include/linux/syscalls.h` | parseable from source; also present in BTF as `__se_sys_*` and `__do_sys_*` |
| uAPI types | `include/uapi/**`, `arch/*/include/uapi/**`, exported by `make headers_install` | headers; layouts confirmed from BTF and from compiling probes |
| ioctl numbers | `_IO`, `_IOR`, `_IOW`, `_IOWR` macros in uAPI headers | yes after preprocessing; the four fields decode directly |
| netlink | `Documentation/netlink/specs/*.yaml` (the YNL specs), plus rtnetlink and nftables headers | YNL specs are fully machine readable, but they do not cover every family yet |
| sysfs | `Documentation/ABI/{stable,testing,obsolete,removed}` | semi structured text (`What:`, `Date:`, `Contact:`, `Description:`) |
| procfs | `fs/proc/*.c`, `Documentation/filesystems/proc.rst` | no; formats are `seq_printf` calls |
| BPF | `include/uapi/linux/bpf.h` (helper list with signatures in comments, parsed by `scripts/bpf_doc.py`), kfunc BTF tags | yes, via `bpf_doc.py` and BTF |
| io_uring | `include/uapi/linux/io_uring.h` | yes |
| syscall semantics, approximately | syzkaller `sys/linux/*.txt` descriptions | yes, a typed DSL covering syscalls, ioctls, netlink and resources |
| tracepoints | `include/trace/events/*.h` | the format files under `tracefs/events/*/format` are generated from these |

Two sources deserve a note. **syzkaller's descriptions** are the most complete typed description of the Linux ABI anywhere, maintained by people fuzzing it daily, and they cover what the uAPI headers do not say: which argument is a file descriptor of which kind, which buffer is input and which output, which values are flags and which are enums. We consume them both as an ABI cross check and as the input to fuzzing rukernel. **BTF** (`/sys/kernel/btf/vmlinux` of the pinned reference kernel built with `CONFIG_DEBUG_INFO_BTF`) is the ground truth for struct layout as the compiler actually laid it out, including padding, so every generated Rust type is checked against it.

## 4.3 The generator, `rk-abigen`

`rk-abigen` lives in the rukernel repository under `tools/` and runs on a pinned Linux tree. It is not part of the kernel build: its output is committed, so building the kernel never needs a Linux tree, and every change to the ABI shows up as a reviewable diff in `rk-abi`.

Pipeline:

1. **Fetch** the pinned tarball by hash; run `make headers_install ARCH=<a>` for each supported ABI into a scratch sysroot.
2. **Tables**: parse the syscall tables into `syscalls.toml`, one entry per (ABI, number) with the entry point name and ABI tag (`common`, `64`, `x32`, `i386`).
3. **Signatures**: build the reference kernel with BTF and read `__se_sys_*` prototypes from it; cross check against `SYSCALL_DEFINE` parsing. Each argument gets a kind from syzkaller where syzkaller has one (`fd[sock]`, `ptr[in, sockaddr]`, `flags[open_flags]`).
4. **Types**: run `bindgen` over the installed headers once per ABI with layout tests on, then reduce the output into `rk-abi` modules that are `#[repr(C)]`, derive `FromBytes`, `IntoBytes` and `KnownLayout` (the `zerocopy` traits, so copying from user memory is safe without `unsafe`), and carry a layout assertion per field against BTF.
5. **Constants and flags**: preprocessor driven extraction of every `#define` in uAPI that evaluates to an integer, grouped into typed `bitflags` and enums by the prefixes the headers use (`O_*`, `MAP_*`, `CLONE_*`, `SOCK_*`), with the grouping table hand maintained because the headers do not say which constants belong together.
6. **ioctls**: every `_IOC` definition decoded into (type, nr, dir, size) and joined with the struct it names, emitted as `ioctls.toml` and as a Rust enum per device family.
7. **netlink**: the YNL YAML specs converted into Rust message and attribute types with parsers and emitters, plus hand written specs, in the same YAML format, for the families YNL does not cover yet. Those are upstreamable, and sending them upstream is a goal: every family we describe is one less that the next reimplementer has to.
8. **sysfs and procfs manifests**: `Documentation/ABI` parsed into `sysfs.toml`; procfs entries enumerated from the reference by walking `/proc` in a booted reference VM with a representative workload, recording every path, mode, and a sample of its content. That last step is the honest one: the authoritative list of `/proc` files is the list a real kernel shows.
9. **Diff**: compare the new output against the committed output and write `ABI-CHANGES-<from>-<to>.md`: syscalls added, structs grown, flags added, ioctls added, netlink attributes added, sysfs entries added, removed and moved between stability levels. Document 17 is the process that consumes this file.

## 4.4 How the kernel consumes it

`rk-abi` is a generated crate with no logic. `rk-syscall` holds a dispatch table built at compile time from `syscalls.toml` and a trait per entry:

```rust
#[syscall(abi = "common", nr = 435, name = "clone3")]
fn clone3(cx: &mut SyscallCx, args: UserPtr<CloneArgs>, size: usize) -> SysResult<Pid>;
```

The `syscall` attribute checks at build time that the number, name and argument types match `syscalls.toml` for every ABI the entry exists in, generates the compat entry where the ABI needs one (struct layout conversion for i386 and arm32 compat is generated from the two layouts in `rk-abi`, not written by hand), and generates the `ktrace` record writer (document 18.2) from the argument kinds.

An entry that `syscalls.toml` lists and that has no implementation returns `ENOSYS`, logs once per process name with `pr_info_ratelimited` in Linux's format, and is counted in `/sys/kernel/rukernel/abi/enosys`, so "what is missing" is a file a user can read on a running system. glibc and most runtimes handle `ENOSYS` by falling back (to `clone` from `clone3`, to `stat` from `statx`, to `epoll_wait` from `epoll_pwait2`), and that fallback is often what lets an early rukernel run real programs at all. It is also why the compat harness grades on behaviour rather than on "did it return `ENOSYS`": a kernel at the 6.6 level of `statmount` support and one at the 7.3 level can both run a program that falls back, and only the trace differential tells them apart.

## 4.5 Size of the surface

Order of magnitude, from the 7.x tree (document 01 has the exact counts for the pinned version):

- The highest system call number in 7.3 is 472 (`fchroot`) on x86-64, i386 and the generic table alike. The x86-64 table has 370 implemented 64 bit and common entries, 16 reserved numbers with no entry point, and 36 x32 entries at 512 to 547; the generic table has 324 numbers with an entry point. Recent releases add zero to two each: 6.19 added `listns` (470), 7.0 `rseq_slice_yield` (471), 7.1 and 7.2 none, 7.3 `fchroot` (472). About 790 `SYSCALL_DEFINEn` sites exist in the tree once compat and arch variants are counted.
- `include/uapi` is 952 files and about 221,000 lines, plus 457 architecture uAPI headers (49 of them x86). That is tens of thousands of constants and several thousand structs.
- 2,522 `_IO`/`_IOR`/`_IOW`/`_IOWR` definitions in the generic and x86 uAPI headers and 4,348 across the whole tree, a lower bound since many legacy ioctls are bare numbers, most of which belong to drivers nobody will ever run against rukernel (a specific SCSI HBA's management interface), and a few hundred that matter for everything (TTY, block, loop, `FIONREAD`, `SIOC*`, DRM core, KVM, V4L2 core, input, evdev, `TUN`, `NS_GET_*`, `PIDFD_*`, `FS_IOC_*`, `BTRFS_IOC_*`).
- A few dozen netlink families with a few thousand attributes.
- Several hundred `/proc` file shapes per process and system wide. `Documentation/ABI` has 6,460 `What:` entries, 6,268 of them under `/sys`, which covers only documented sysfs; a running machine exposes many thousands more attributes, most of them per device.

The tractable reading of "100%" is therefore: **100% of the syscalls, 100% of the subsystem independent ioctls, 100% of the netlink families and pseudo files that the corpus in document 18 reaches, and 100% of the device ioctls for the device classes rukernel has drivers for.** A device ioctl for hardware we have no driver for is not part of the surface any program on rukernel can reach. That definition is falsifiable and it grows with the corpus, which is the right direction for it to grow.

## 4.6 Versioned behaviour

Linux sometimes changes behaviour without changing the interface: a new flag accepted, an `EINVAL` that becomes success, a `/proc` field appended. rukernel implements the behaviour of the version it claims. Where a behaviour changed between the longterm and the latest release and programs are known to care (an appended field in `/proc/<pid>/status`, the `EINVAL` to `EOPNOTSUPP` changes in a few file system calls), the behaviour is keyed on the claimed version, so a rukernel booted with `rukernel.abi=6.18` behaves as 6.18 does on those points and reports `6.18` in `uname`. This is a small, explicit table (`behaviour.toml`), not a general mechanism, and every entry has a test that fails on the wrong version.

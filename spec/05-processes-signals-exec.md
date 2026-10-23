# Processes, threads, signals and exec

This is the part of the ABI that every program touches in its first millisecond and that the most programs depend on in the most subtle ways. A wrong `errno` from `openat` breaks one program. A wrong signal mask across `execve` or a `vfork` that is not really `vfork` breaks a shell, and then everything that runs under it.

## 5.1 The task model

One `Task` per Linux thread, as in Linux. A process is a thread group: the tasks that share a `tgid`, a signal handler table and the process wide signal queue. Everything a task may share is a separately reference counted object, and `clone` flags pick which ones are shared and which are copied:

| Object | Shared by | Linux flag |
|---|---|---|
| `AddressSpace` (`rk-mm`) | threads, `vfork` children | `CLONE_VM` |
| `FdTable` | threads, `CLONE_FILES` children | `CLONE_FILES` |
| `FsContext` (root, cwd, umask) | threads | `CLONE_FS` |
| `SigHandlers` | threads | `CLONE_SIGHAND` |
| `Namespaces` (an `nsproxy`) | everything not created with a `CLONE_NEW*` flag | `CLONE_NEW*` |
| `Credentials` | copy on write, replaced atomically with RCU | none (always per task, shared by reference until changed) |
| `IoContext` | `CLONE_IO` | `CLONE_IO` |
| `SysvSem` undo list | `CLONE_SYSVSEM` | `CLONE_SYSVSEM` |

This is not a design choice. The sharing structure *is* the ABI, since programs combine flags in ways the man page never anticipated (`CLONE_VM` without `CLONE_THREAD` for Go's old runtime and for `posix_spawn`, `CLONE_FILES` without `CLONE_VM` for some sandboxes, `CLONE_PARENT` for `systemd-nspawn`). The objects are Rust `Arc`s with the same sharing relationships as Linux's `struct mm_struct`, `files_struct`, `fs_struct`, `sighand_struct` and `nsproxy`.

**`clone3`** is the primary entry point, and `clone`, `fork` and `vfork` are wrappers over it, as in Linux. All `clone3` features are supported: `CLONE_PIDFD`, `CLONE_INTO_CGROUP`, `set_tid` for CRIU, `CLONE_CLEAR_SIGHAND`, the 7.1 additions `CLONE_AUTOREAP` (the child is reaped without a `wait`), `CLONE_NNP` (the child starts with `no_new_privs`), `CLONE_PIDFD_AUTOKILL` (closing the last pidfd kills the child) and `CLONE_EMPTY_MNTNS` (a new, empty mount namespace), and the `size` versioning rule (unknown trailing bytes must be zero, otherwise `E2BIG`).

**`vfork`** really suspends the parent until the child execs or exits, and the child really runs on the parent's address space. Shells and `posix_spawn` implementations depend on both properties, and an implementation that turns `vfork` into `fork` is slow and breaks programs that write to memory in the child on purpose.

**PIDs** come from a per namespace IDR equivalent (an xarray keyed by number), allocated cyclically from `ns_last_pid` with the wrap at `pid_max`, as programs and CRIU expect. A `Pid` object outlives its task while a pidfd or `/proc/<pid>` handle refers to it, which is what makes pidfds race free.

## 5.2 Credentials

UIDs, GIDs, supplementary groups, the five capability sets (permitted, effective, inheritable, bounding, ambient), securebits, `no_new_privs`, the keyrings, and the LSM security blobs. Credentials are immutable once published; `setuid` builds a new `Credentials` and swaps it in with RCU, as Linux's `commit_creds` does. The rules for `setresuid` and friends, the capability transformation on `execve` (including the file capability `security.capability` xattr with versions 2 and 3, the latter carrying a root UID for user namespaces), and the `SECBIT_*` behaviour are all ABI and are tested against the reference by LTP's `cap_*` and `setuid*` tests and by `libcap`'s test suite.

Credentials are translated through the user namespace hierarchy on every boundary crossing (5.9), and the in kernel representation is always the `kuid_t` style global ID, never a namespace relative one.

## 5.3 Exec

`execve` and `execveat` (including `AT_EMPTY_PATH` on an `O_PATH` descriptor and `AT_EXECVE_CHECK` from 6.14 for script interpreters that want the kernel's verdict):

1. **Resolve and open** the file with the exec permission check, `noexec` mount check, and LSM hooks.
2. **Recognize the format**: ELF, `#!` scripts (with the 256 byte line limit Linux has used since 5.1 and its exact argument splitting: one optional argument, not split on spaces), the persona formats from document 16, then `binfmt_misc` entries, which are full fidelity (magic and extension matching, `F` fix binary, `C` credentials, `O` open binary, `P` preserve argv0), including the 7.3 additions: handlers backed by a BPF program that decides the match, and `PT_INTERP` substitution.
3. **Point of no return**: flush the old address space, de-thread (kill the other threads of the group, make this task the group leader and take over the leader's PID, which is the behaviour `exec` from a non-leader thread relies on), close `O_CLOEXEC` descriptors, reset handled signals to default, keep ignored ones and the mask, unshare the files table if shared.
4. **Load ELF**: `PT_LOAD` segments with the exact page alignment and `p_align` behaviour (including large `p_align` for 2 MiB alignment that Linux honours since 5.10 for THP friendly text), `PT_INTERP`, `PT_GNU_STACK` for executable stack, `PT_GNU_PROPERTY` for x86 IBT and SHSTK and arm64 BTI, `PT_GNU_RELRO` left to `ld.so`, ET_DYN placement with `ELF_ET_DYN_BASE` and the ASLR offsets per architecture with the same entropy bits (`mmap_rnd_bits`) so that tools that assume a layout keep working.
5. **Build the stack**: argv, envp, the auxiliary vector with every `AT_*` entry Linux supplies (`AT_SYSINFO_EHDR`, `AT_HWCAP` through `AT_HWCAP4`, `AT_PLATFORM`, `AT_RANDOM`, `AT_SECURE`, `AT_EXECFN`, `AT_MINSIGSTKSZ`, `AT_RSEQ_FEATURE_SIZE`, `AT_RSEQ_ALIGN`, `AT_PAGESZ`, `AT_CLKTCK`, `AT_PHDR`, `AT_BASE`, `AT_ENTRY`, `AT_UID` and friends), in Linux's order, with the 16 byte alignment rule. `AT_HWCAP` values on arm64 and RISC-V are generated from the same CPU feature probing that produces `/proc/cpuinfo`, so the two always agree.
6. **Map the vDSO** (5.4) and set up `rseq` state to unregistered.

`ARG_MAX` is derived as in Linux: a quarter of `RLIMIT_STACK`, with the 32 page floor and the `MAX_ARG_STRLEN` per string limit, because build systems with very long command lines probe the real limit.

## 5.4 The vDSO

Built as a `no_std` Rust shared object with the same symbol names and versions as Linux's (`__vdso_clock_gettime`, `__vdso_gettimeofday`, `__vdso_time`, `__vdso_clock_getres`, `__vdso_getcpu`, `__vdso_getrandom` from 6.11, on x86-64 versioned `LINUX_2.6`; `__kernel_*` on arm64 versioned `LINUX_2.6.39`), reading a data page layout that is ours. glibc and musl look up the symbols by name and version only, so the data page layout is private, which lets us use one layout across architectures.

`getrandom` in the vDSO uses the `vgetrandom_alloc` state protocol from 6.11 so that glibc 2.41 and later get the fast path. Time uses the same seqcount protocol as Linux, with the time namespace offset page mapped over the data page for tasks in a non root time namespace.

The vDSO is mapped where Linux maps it, and `[vdso]` and `[vvar]` appear in `/proc/<pid>/maps` with those names, since several runtimes (Go, the JVM, sanitizers) parse maps to find them.

## 5.5 Exit, wait and pidfd

`exit` and `exit_group`, zombie reaping, reparenting to the nearest subreaper (`PR_SET_CHILD_SUBREAPER`) or the namespace's init, `SIGCHLD` with `SA_NOCLDWAIT` and `SA_NOCLDSTOP` semantics, `wait4`, `waitid` with `P_PIDFD`, `WNOWAIT`, `WEXITED`, `WSTOPPED`, `WCONTINUED`, `__WALL` and `__WCLONE`.

pidfds in full, including `pidfd_info.coredump_code` (7.1) and fanotify reporting pidfds (7.2): `pidfd_open` (with `PIDFD_NONBLOCK` and `PIDFD_THREAD`), `pidfd_send_signal`, `pidfd_getfd`, `process_mrelease`, polling for exit, `waitid(P_PIDFD)`, and the `PIDFD_GET_*_NAMESPACE` and `PIDFD_GET_INFO` ioctls. pidfds are backed by `pidfs` as in Linux since 6.9, so `fstat` on a pidfd returns a stable inode number per process that systemd uses to identify processes across PID reuse. Getting pidfd behaviour exactly right matters disproportionately because systemd, `dbus-broker`, and every modern service manager use pidfds as the identity of a process.

## 5.6 Signals

Signals are where reimplementations go to die, so the specification is the reference's behaviour checked case by case. The structure:

- Per task pending queue, per process shared pending queue, the blocked mask, the handler table, real time signals queued with their `siginfo` and standard signals coalesced.
- **Delivery target selection** for process directed signals: the main thread if it does not block the signal, otherwise any thread that does not, with Linux's preference order (`complete_signal`'s logic: the thread that is `wants_signal`, starting from the last one chosen, round robin).
- **Group stop and continue**, `SIGSTOP`, `SIGTSTP`, `SIGTTIN`, `SIGTTOU` with job control and orphaned process group rules, and the interaction with ptrace stops.
- **Fatal signal fast path**: a fatal unhandled signal kills the whole group and wakes every task from interruptible and killable sleeps.
- **The signal frame** per architecture, bit exact: `rt_sigframe` with `siginfo_t`, `ucontext_t`, the FPU state and on x86-64 the full XSAVE area in Linux's format with the `fpx_sw_bytes` magic and the `xstate_size` that glibc reads; on arm64 the `sigcontext` with its chain of `_aarch64_ctx` records (`FPSIMD_MAGIC`, `ESR_MAGIC`, `SVE_MAGIC`, `ZA_MAGIC`, `ZT_MAGIC`, `TPIDR2_MAGIC`, `FPMR_MAGIC`, `POE_MAGIC`, `GCS_MAGIC`, `EXTRA_MAGIC`). Debuggers, JITs, Wine, and sanitizers read and modify these frames and rely on the layout.
- **`sigaltstack`** with `SS_AUTODISARM` and the `AT_MINSIGSTKSZ` contract for AMX and SVE sized state.
- **Shadow stacks** (x86 SHSTK, arm64 GCS) with the signal token protocol, enabled through `arch_prctl(ARCH_SHSTK_ENABLE)` and `prctl(PR_SET_SHADOW_STACK_STATUS)` by glibc when the binary is marked.
- **`signalfd`**, `rt_sigtimedwait`, `rt_sigqueueinfo` and `rt_tgsigqueueinfo` with the permission rules on `si_code`, `pidfd_send_signal`.
- **Syscall restart**: the `ERESTART*` codes, `SA_RESTART`, and restart blocks for `nanosleep`, `clock_nanosleep`, `futex` and `poll`.
- **`PR_SET_SYSCALL_USER_DISPATCH`** (needed by Wine, document 16), seccomp's `SECCOMP_RET_TRAP` raising `SIGSYS` with the syscall details in `siginfo`, and `SIGSEGV` and `SIGBUS` `si_code` values that match Linux for each fault type, including `SEGV_PKUERR`, `SEGV_CPERR` for control protection faults and `BUS_MCEERR_AR` for memory errors.

The test oracle for this section is the gVisor syscall suite's `sigaction`, `sigaltstack`, `sigprocmask`, `sigtimedwait`, `sigiret`, `exceptions`, `fault` and `sigstop` tests, LTP's signal tests, and a dedicated differential corpus of signal frame dumps per architecture.

## 5.7 ptrace

ptrace is required by `gdb`, `strace`, `lldb`, `rr`, CRIU, Wine's debugger, sandboxes and every crash reporter. Full implementation: `PTRACE_SEIZE` and `PTRACE_INTERRUPT`, `PTRACE_LISTEN`, the event stops (`PTRACE_O_TRACECLONE`, `TRACEEXEC`, `TRACEEXIT`, `TRACESECCOMP`, `TRACESYSGOOD`, `EXITKILL`), `PTRACE_GETREGSET` and `SETREGSET` for every regset Linux exposes per architecture (`NT_PRSTATUS`, `NT_PRFPREG`, `NT_X86_XSTATE`, `NT_ARM_SVE`, `NT_ARM_ZA`, `NT_ARM_TLS`, `NT_ARM_PAC_MASK` and the rest), `PTRACE_GET_SYSCALL_INFO`, `PTRACE_SET_SYSCALL_INFO` (6.16), `PTRACE_GET_RSEQ_CONFIGURATION`, `PTRACE_GETSIGMASK` and `SETSIGMASK`, `PTRACE_PEEKSIGINFO`, and hardware breakpoints and watchpoints through the debug registers and `perf_event`. The Yama `ptrace_scope` rules are implemented in `rk-sec`.

`rr` is the acid test: it depends on deterministic counting of retired conditional branches through `perf_event_open`, on precise ptrace stop semantics, and on `PTRACE_O_EXITKILL`. rr's own test suite is an L5 scenario.

## 5.8 Futexes and user space synchronization

The futex is the most performance critical synchronization primitive on Linux, and glibc's mutexes, condition variables and `pthread_join`, Go's runtime, Rust's `std::sync`, and the JVM all sit on it.

- `futex` with `FUTEX_WAIT`, `WAKE`, `REQUEUE`, `CMP_REQUEUE`, `WAKE_OP`, `WAIT_BITSET`, `WAKE_BITSET`, the PI operations (`LOCK_PI`, `LOCK_PI2`, `UNLOCK_PI`, `TRYLOCK_PI`, `WAIT_REQUEUE_PI`, `CMP_REQUEUE_PI`) with the priority inheritance chain walked by `rk-sched`, `FUTEX_PRIVATE_FLAG` and `FUTEX_CLOCK_REALTIME`.
- The `futex2` calls: `futex_waitv` (5.16), and `futex_wake`, `futex_wait` and `futex_requeue` (6.7) with size and NUMA flags.
- Robust futex lists (`set_robust_list`), walked on exit, including the `FUTEX_OWNER_DIED` protocol.
- The hash: per process private futex hash (Linux moved to a per process hash in 6.16 with `PR_FUTEX_HASH` to set its size) and a global hash for shared futexes keyed on (inode, offset) or (mm, address).
- **ntsync** (`/dev/ntsync`, 6.14) as a character device in `rk-proc`, sharing the wait queue machinery, for the Windows persona.

## 5.9 Namespaces

All eight: mount, PID, network, IPC, UTS, user, cgroup, time. Created by `clone3`, `unshare`, entered by `setns` with either a namespace file descriptor or a pidfd plus a flags mask (the 5.8 extension that enters several at once atomically). Inspected through `/proc/<pid>/ns/*`, `ioctl(NS_GET_USERNS, NS_GET_PARENT, NS_GET_NSTYPE, NS_GET_OWNER_UID)`, and the 6.x namespace ID and `listns` facilities as they land upstream.

User namespaces are the hard one because they reach into everything: ID mapping on every credential check, `uid_map` and `gid_map` write rules (including the `setgroups` deny gate), capability scoping to the owning namespace for each resource type, `CAP_SETFCAP` and file capability v3, idmapped mounts (`mount_setattr` with `MOUNT_ATTR_IDMAP`) translating on every inode operation. They are also the one rootless containers, browsers' sandboxes and Flatpak need, so they cannot be postponed. Section 14.2 has the containers side.

## 5.10 rseq, time slice extension and scheduling hints

`rseq` registration and the critical section abort protocol on preemption, signal delivery and migration, with the extended `rseq` area fields (`node_id`, `mm_cid`) that glibc and tcmalloc use, and the feature size and alignment advertised in the auxiliary vector. glibc registers `rseq` for every thread by default, so a kernel without it is a kernel whose every `sched_getcpu` is slower and whose tcmalloc falls back to a slow path.

The time slice extension facility (7.0), where a thread holding a user space lock asks the scheduler for a short grace period before preemption and returns it with `rseq_slice_yield`, uses the same `rseq` area (document 06.6).

`fchroot` (7.3) changes root to a directory file descriptor, and its special value `FD_FAILFS_ROOT` moves the caller into failfs, where every path operation fails; it is the cleanest way for a sandbox to drop file system access, and it is cheap for us because it is a property of `FsContext`.

## 5.11 Resource limits and accounting

`prlimit64` with every `RLIMIT_*`, `getrusage` with `RUSAGE_SELF`, `CHILDREN`, `THREAD`, `times`, the per task and per thread group CPU clocks (`CLOCK_PROCESS_CPUTIME_ID`, `CLOCK_THREAD_CPUTIME_ID`, and the clock IDs derived from PIDs), POSIX CPU timers, the taskstats netlink family and delay accounting, `/proc/<pid>/stat`, `statm`, `status`, `io`, `sched` and `schedstat` with field order and formatting identical to the reference.

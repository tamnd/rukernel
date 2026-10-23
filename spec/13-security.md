# Security

Security in rukernel has two parts that are easy to confuse. The first is the Linux security model: users, capabilities, LSMs, seccomp, Landlock, keyrings, integrity. Programs and administrators configure it, so it is ABI and must behave exactly like Linux's. The second is the kernel's own resistance to attack: memory safety, hardening and speculative execution mitigations. There rukernel aims to be better than Linux, because that is the reason to write it in Rust.

## 13.1 Credentials and capabilities

- **Credentials** are Linux's: real, effective, saved and filesystem UIDs and GIDs, supplementary groups, the five capability sets (permitted, effective, inheritable, bounding, ambient), securebits, `no_new_privs`, and the per LSM security blobs. They are immutable once published and replaced by copy on write (`prepare_creds` and `commit_creds` in Linux).
- **In Rust,** a credential is an `Arc<Cred>`, and a permission check takes a `&Cred` and returns a `Result<CapProof, Errno>`. Functions that perform a privileged action require the proof as an argument. Calling `set_hostname` without first passing `ns_capable(CAP_SYS_ADMIN)` on the right user namespace is then a type error, not a code review finding. This is the most direct security win from the type system. Linux's long history of missing capability checks, and of checks against the wrong namespace, is a class of bug a proof token removes.
- **User namespaces** with the ID mapping semantics, `/proc/<pid>/uid_map`, `gid_map` and `setgroups`, the unprivileged creation sysctls distributions set (`kernel.unprivileged_userns_clone` on Debian, and the AppArmor user namespace restriction on Ubuntu), and capability scoping per namespace (document 14).

## 13.2 LSMs

The LSM framework with its hook points at the same places as Linux's (about 250 hooks in v7.3), stacking per the 6.x model with the `lsm=` boot parameter, and the LSM system calls `lsm_get_self_attr`, `lsm_set_self_attr` and `lsm_list_modules` (6.8).

The modules:

| LSM | Why | Scope |
|---|---|---|
| capability | always | full |
| Yama | ptrace scope on every distribution | full |
| SELinux | Fedora, RHEL, Android | full: policy loading through selinuxfs, the AVC, labelling on every file system with xattrs, `context=` mounts, the netlink and network controls, MLS and MCS, and BPF token controls (7.0); the reference policy and Fedora's targeted policy load and enforce identically |
| AppArmor | Ubuntu, Debian, SUSE | full: profiles through securityfs, the policy compiler's binary format, `change_profile`, and the user namespace mediation Ubuntu enables |
| Landlock | unprivileged sandboxing (Chromium, systemd, Firefox's helpers, Rust tooling) | full, ABI version 11 (section 13.4) |
| BPF LSM | systemd's `RestrictFileSystems`, Tetragon, KRSI style policies | full, attaching by Linux hook name (document 11) |
| lockdown | secure boot | full |
| IPE | integrity policy, used with dm-verity images | full |
| loadpin, safesetid, Smack, TOMOYO | rarely used | post 1.0, listed |

SELinux and AppArmor are large: their policy engines, labelling and per object hooks. They are ported from Linux's implementation and tested with their upstream test suites (`selinux-testsuite` and AppArmor's regression tests) on both kernels. A policy decision that differs between the two kernels is a security bug of the first severity, not a compatibility bug.

## 13.3 seccomp

- seccomp strict and filter modes, classic BPF filters, `SECCOMP_RET_*` actions including `USER_NOTIF` with `SECCOMP_IOCTL_NOTIF_ADDFD`, `SECCOMP_FILTER_FLAG_TSYNC`, `NEW_LISTENER`, `WAIT_KILLABLE_RECV` and `SPEC_ALLOW`, the per architecture audit values, and `/proc/<pid>/status` Seccomp fields.
- Filters are interpreted, or compiled by the same JIT as eBPF.
- Every container runtime installs a seccomp profile, and Chromium and Firefox each install several, so seccomp is on the hot path of system calls for a large share of real workloads. The entry path benchmark (document 19.1) has a row with Docker's default profile installed.
- Syscall User Dispatch (`PR_SET_SYSCALL_USER_DISPATCH`) is implemented with the selector byte semantics, plus the 7.3 sysctl. Wine uses it to run Windows programs that issue system calls directly (document 16.3).

## 13.4 Landlock

Landlock is the unprivileged sandboxing interface that programs now adopt on their own: the `landlock_create_ruleset`, `landlock_add_rule` and `landlock_restrict_self` system calls, with ABI version 11 in v7.3. The rule types are file system access rights (including `REFER`, `TRUNCATE`, `IOCTL_DEV` and `FS_RESOLVE_UNIX`), network rules for TCP and UDP bind and connect, scopes for abstract Unix sockets and signals, `RESTRICT_SELF_TSYNC`, logging flags, and `RESTRICT_SELF_NO_NEW_PRIVS` (7.3).

Programs probe the ABI version and use what they find, so we report exactly the reference's version for the claimed release. Under `rukernel.abi=6.18` that is the version Linux 6.18 reports.

## 13.5 Integrity, keys and crypto

- **Keyrings** with the `add_key`, `request_key` and `keyctl` interfaces, user, logon, big_key, trusted, encrypted and asymmetric key types, and the system and platform keyrings populated from the firmware's secure boot databases.
- **IMA and EVM:** measurement into the TPM, appraisal and the policy language.
- **TPM 2.0** through `/dev/tpm0` and `/dev/tpmrm0`, with the TPM driver for CRB, TIS and firmware TPMs. systemd's measured boot and disk unlocking use these.
- **fs-verity**, and **dm-verity** with root hash signatures.
- **The crypto API** as user space sees it through `AF_ALG`, and what kernel users need: dm-crypt, fscrypt, IPsec, kTLS, WireGuard, and the hash and checksum functions. The implementations are Rust, with the architecture specific fast paths (AES-NI, VAES, SHA extensions, the ARMv8 crypto extensions) as audited `unsafe` leaf crates using `core::arch` intrinsics (document 23.3). The FIPS 140-3 self tests and mode follow Linux's, so distributions that need FIPS can enable it.

## 13.6 The kernel's own hardening

Rust covers spatial and temporal memory safety in safe code. The rest of a modern hardening posture is still needed, because `rk-frame` and the compiler are trusted and because speculative execution ignores language semantics.

**Control flow:**

- **Forward edges:** kCFI, which `rustc` supports through `-Zsanitizer=kcfi` in the form Linux uses and which is stabilizing, or FineIBT on Intel CPUs with CET IBT, matching Linux's choice per CPU.
- **Backward edges:** shadow stacks. CET supervisor shadow stacks on x86 where available, and the Arm GCS and PAC return address signing on arm64.
- **Indirect calls** are rarer than in Linux to begin with, because static dispatch through generics replaces many of Linux's operation tables. Where there are trait objects, they are CFI checked.

**Memory layout:**

- KASLR for text and the direct map, and per boot randomized `kmalloc` caches (the `RANDOM_KMALLOC_CACHES` idea).
- Slab freelist hardening.
- `init_on_alloc` by default and `init_on_free` as an option.
- W^X for all kernel memory.
- Read only after init for configuration.
- Stack canaries in `rk-frame`, and stack depth checks.
- Guard pages on kernel stacks (virtually mapped stacks, as Linux).
- SMEP, SMAP, UMIP and PAN, PXN on arm64.
- Memory tagging (Arm MTE) for the kernel heap as an option on hardware that has it.

**Speculative execution:** every mitigation Linux applies for the CPU it runs on, decided the same way, reported in `/sys/devices/system/cpu/vulnerabilities/*` with the same strings, and controlled by the same boot parameters (`mitigations=`, `spectre_v2=`, `retbleed=` and the rest):

- retpolines or eIBRS, IBPB on context switch, RSB filling, and BHI clearing,
- untrained return thunks for Retbleed and SRSO,
- VERW buffer clearing for MDS, TAA, MMIO stale data, RFDS and the 2025 and 2026 transient scheduler attack disclosures,
- KPTI for Meltdown affected parts, and L1TF and ITS mitigations.

The x86 entry code that applies these lives in `rk-frame` (document 03.2), and is the only place mitigations touch the system call path. Document 19.2 requires that both kernels report identical vulnerability files before any benchmark runs, because otherwise the comparison is meaningless.

## 13.7 Audit

The audit subsystem through `NETLINK_AUDIT`: rules, watches, the system call audit context, the record formats `auditd` and `ausearch` parse, and the SELinux and AppArmor records. Government and enterprise distributions need audit to be certified, and its record formats are tested differentially like any other netlink output.

## 13.8 What the claim is

rukernel's security claim is limited and checkable:

1. The memory safety and data race classes are absent outside `rk-frame` and the audited leaf crates.
2. `rk-frame` is verified for the properties document 20 lists.
3. The Linux security model is reproduced exactly.
4. The hardening posture is at least Linux's.

The claim is not that rukernel has no vulnerabilities. Logic bugs in permission checks, namespace confusion, information leaks through uninitialized padding (prevented by `zerocopy`'s `IntoBytes`, which refuses types with padding) and side channels remain possible, and syzkaller, the differential policy tests and a public security process will find them. The kernel CNA model applies: a CVE for every fixed security bug, published with the fix.

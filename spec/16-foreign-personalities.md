# Foreign personalities: Windows and macOS binaries

The goal statement says rukernel runs every program binary from Linux, macOS and Windows without modifying anything. This document says how, and it says exactly where that sentence stops being true. The Linux part is the rest of this specification. The macOS and Windows parts are mostly a user space problem that other people have spent twenty years on. The kernel's job is to be the best possible host for that user space, and to move a small number of primitives into the kernel where moving them is worth it.

The verified landscape behind every claim here is in document 01, section 01.6. The short version: Wine 11 (January 2026) and Proton 11 (July 2026) run roughly 85 to 90% of Steam's catalogue at "Silver or better" on Linux. Darling, after more than a decade, runs command line macOS programs and only simple GUI programs. Microsoft built a Linux personality inside NT (WSL1) and abandoned it for a VM (WSL2) because of the semantic long tail. Those three facts set the plan.

## 16.1 The principle: personalities live at the stable boundary

Every operating system has one boundary its vendor promises not to break, and it is almost never the system call table.

- **Linux** promises the system call ABI. "We do not break user space" is about syscalls, and statically linked binaries from 2005 still run. So the Linux personality is a syscall personality, and that is the rest of this specification.
- **Windows** promises the exported DLL surface: `ntdll`, `kernel32`, `user32` and the rest. NT system call numbers are renumbered between Windows builds (j00ru's tables show it build by build), and `win32k` numbers move even more. A Windows personality implemented as an NT syscall table would chase a target that Microsoft deliberately moves.
- **macOS** promises `libSystem` (`libsystem_kernel.dylib` and friends). Go stopped issuing raw system calls on macOS and moved to libSystem for this reason. XNU's `syscalls.master` and the Mach trap table are open source, and they change between releases.

So the Windows and macOS personalities are implemented where those vendors' compatibility promises are: in reimplemented system libraries running in user space, on top of the Linux personality. The kernel adds primitives under them where performance or semantics require it. This is the Wine model, and it is the right one. It is also why "without modifying anything" is achievable for the binary: the program's own code is untouched, and what it links against at run time is ours.

## 16.2 How a foreign binary starts

The user types `./setup.exe` or `./SomeTool` (a Mach-O) or double clicks it. Nothing else changes.

rukernel's `execve` recognizes the format before any `binfmt_misc` lookup: PE/COFF by the `MZ` and `PE\0\0` signatures, Mach-O by its magic numbers (`0xfeedfacf`, and the fat `0xcafebabe` with a fat header shape that is distinguishable from a Java class file), ELF of a foreign ISA by `e_machine`. For each format, a **persona** is registered at boot from `/etc/rukernel/personas.d/*.toml`. A persona names the loader (an ELF program that becomes the process image, the way `ld.so` is named by `PT_INTERP`), the persona's root (`/usr/lib/rukernel/win`, `/usr/lib/rukernel/darwin`), and flags.

This is `binfmt_misc` with three differences. It is registered by default, so it works on a fresh install with no `systemd-binfmt` configuration. It records the persona on the task (`/proc/<pid>/persona`, and inherited across `fork` and reset on a native `exec`), which the Mach and NT primitives below use to decide what a process may call. And it is visible to `binfmt_misc` users: `/proc/sys/fs/binfmt_misc/` lists the personas as entries, so a user who registers their own Wine or FEX handler there overrides ours in the way they would expect on Linux. Linux 7.3 added `binfmt_misc` handlers whose match is decided by a BPF program, plus `PT_INTERP` substitution. Both are part of the Linux personality anyway (document 05.3). They are also exactly the mechanism a persona needs to tell a Java class file from a fat Mach-O, or a .NET assembly from a native PE. So a persona is implemented as a built in, pre-registered BPF backed `binfmt_misc` handler, not as a separate mechanism.

## 16.3 Windows

### 16.3.1 The user space: Wine, unmodified, pinned

The Windows persona is a pinned upstream Wine build (11.x stable) with DXVK and VKD3D-Proton for Direct3D, packaged as `rukernel-win`, and with Proton as the alternative persona for games through Steam. We do not fork Wine. Every Wine bug we find goes upstream, because a fork of Wine is the single largest maintenance liability this project could take on.

Wine 11's architecture fits this well. Its new WoW64 mode is complete: 32 bit PE code thunks into 64 bit Unix libraries inside one loader, as Windows itself does. A 64 bit Linux personality is therefore enough to run 32 bit Windows programs, without the i386 compat syscall layer and without 32 bit host libraries.

### 16.3.2 What the kernel must provide

Everything Wine needs is Linux ABI, and some of it is recent Linux ABI that a reimplementation could easily treat as optional. It is not optional for this persona:

| Primitive | Why Wine needs it | Document |
|---|---|---|
| `/dev/ntsync` (Linux 6.14) | NT mutexes, semaphores, events and `NtWaitForMultipleObjects` wait-any and wait-all in the kernel instead of round trips to `wineserver`. On by default in Proton 11. Figura's benchmarks showed large gains over plain Wine; against `fsync` the gain is smaller and is mostly correctness | 05.8 |
| `futex_waitv` (5.16) | the `fsync` fallback path when ntsync is not available | 05.8 |
| `PR_SET_SYSCALL_USER_DISPATCH` (5.11) | programs that issue the `syscall` instruction directly (DRM, anti-cheat, some launchers) are routed to Wine's handler by `SIGSYS` | 05.6 |
| userfaultfd with write protect | Wine 11 uses it for `GetWriteWatch` tracking; without it Wine falls back to `mprotect` and signals, which is much slower | 07.9 |
| `arch_prctl` and FSGSBASE | the TEB lives at `%gs` on x86-64 | 05.3 |
| fast, correct signal delivery with full XSAVE state | SEH exceptions are delivered as signals and rebuilt into `CONTEXT` records; Wine reads and writes the AVX and AVX-512 state in the frame | 05.6 |
| `memfd_create`, `mmap` with `MAP_FIXED_NOREPLACE`, large reservations at low addresses | PE images must load at their preferred base, and 32 bit WoW64 needs the low 4 GiB | 07 |
| DRM/KMS, a GPU driver Mesa can drive, and Vulkan | DXVK and VKD3D-Proton translate Direct3D to Vulkan; the whole graphics path is Linux user space plus the DRM uAPI | 12.4 |
| `inotify`, `epoll`, `eventfd`, `timerfd`, `pidfd` | `ReadDirectoryChangesW`, the message loop, waitable timers | 08, 05 |
| case folding on ext4 and tmpfs (`casefold`, `+F` directories) | Windows path semantics without Wine's user space case search | 08.6 |

That table is the Windows persona's kernel contract, and every row is tested in the compat harness by Wine's own test suite (`make test` in a pinned Wine tree runs about 300 DLL test modules) and by the Proton scenarios at L5.

### 16.3.3 Where the kernel goes beyond Linux: `rk-nt`

Linux took one step toward NT semantics with ntsync. The next steps are clear from where Wine spends its time: `wineserver` is a single threaded process that owns the NT object namespace, the handle tables, process and thread state, and the message queues, and every one of those operations is a socket round trip.

`rk-nt` is an optional rukernel device, `/dev/rk-nt`, that implements in the kernel the parts of `wineserver` that are on hot paths:

- **the object namespace and handle tables**: `\BaseNamedObjects`, directories, symbolic links, handle inheritance and `DuplicateHandle` across processes;
- **the wait engine** extended from ntsync with APC delivery and alertable waits;
- **sections and views** for shared memory between Windows processes.

It is an extension of the ntsync interface, designed with the Wine developers, and offered upstream to both Wine and Linux. If they take it, it stops being rukernel specific, and that is the outcome we want. If they do not, Wine without `rk-nt` still runs, since Wine detects the device and falls back to `wineserver`. This is a post 1.0 item (document 22, R11) and is gated on a measured win on the L5 Proton scenarios.

### 16.3.4 What will not run, ever

Anything that needs a Windows **kernel** driver: kernel mode anti-cheat (Vanguard, and the kernel components of EasyAntiCheat and BattlEye where the developer has not enabled their Proton runtime), hardware drivers shipped as `.sys`, file system filter drivers, antivirus and EDR products, most VPN clients, and some DRM. Loading a Windows `.sys` requires an NT kernel, a different project (ReactOS has been at it since 1996 and is alpha). AreWeAntiCheatYet tracks about 1,166 anti cheat games and lists roughly 55% as broken on Linux. That number is the honest ceiling for this category, and it is set by publishers rather than by kernels.

### 16.3.5 The claim

"rukernel runs the Windows programs Proton and Wine run on Linux, at the same success rate, at the same speed or faster." That is a falsifiable claim measured by running the same Proton build on Linux 7.3 and on rukernel against the L5 game list, with the fps and frame time distribution captured by MangoHud on both sides.

## 16.4 macOS

### 16.4.1 The situation

macOS compatibility is much harder than Windows compatibility for three reasons, and none of them is the kernel.

1. **The frameworks are closed and the license forbids running them elsewhere.** The Xcode and Apple SDKs Agreement authorizes execution only on Apple branded hardware running macOS, and the macOS license says the same of the OS. AppKit, Foundation's closed parts, CoreGraphics, CoreText, CoreAnimation, Metal, SwiftUI and Security cannot be copied off a Mac and used. A macOS persona must reimplement every framework a program links, clean room, which is Wine's task again but against a much larger and faster moving API surface, with no equivalent of Microsoft's decades of backward compatibility discipline.
2. **The kernel interface is richer than a syscall table.** macOS user space is built on Mach: ports and rights, `mach_msg` with out of line memory and port descriptors, MIG generated RPC, exception ports instead of signals for crash handling, vouchers and importance donation, `launchd` as the bootstrap server, XPC on top of all of it, `kqueue` with `EVFILT_MACHPORT`, the `pthread` workqueue that sizes libdispatch's thread pool in the kernel according to QoS, `ulock` and `psynch` for locks, the shared region for the dyld shared cache, and the commpage.
3. **Apple Silicon and arm64e.** Apple ships its own binaries as arm64e (pointer authentication), and third party arm64e becomes generally supported with macOS 26. Running arm64e code needs PAC keys managed per process with Apple's key and discriminator conventions, preserved through signal and exception frames.

Darling's history matters here. Darling started with a Linux kernel module for Mach IPC. It replaced the module with `darlingserver`, a user space server that embeds parts of XNU and serves Mach traps over RPC, because the module was too hard to keep stable against a moving Linux kernel. That second reason does not apply to us. We own the kernel, the Mach primitives can be first class kernel objects written in safe Rust, and no out of tree module chases an upstream that does not care about it.

### 16.4.2 The kernel part: `rk-mach`

`rk-mach` is the macOS persona's kernel component. It is available only to tasks with the `darwin` persona, and it implements:

- **Mach IPC**: port name spaces per task, send, receive, send-once and dead names, port sets, `mach_msg` and `mach_msg2` with inline, out of line memory (copy on write) and port descriptors, no-senders and dead-name notifications, and message trailers with audit tokens.
- **Tasks and threads as Mach objects**: `task_self`, `thread_self`, `task_threads`, `thread_get_state` and `thread_set_state`, suspend and resume, exception ports and exception delivery (`EXC_BAD_ACCESS` and the rest, raised from the same trap path that raises `SIGSEGV` for Linux tasks).
- **Mach VM**: `mach_vm_allocate`, `mach_vm_map`, `mach_vm_protect`, memory entries, and `mach_vm_region`, implemented over `rk-mm`'s VMAs.
- **BSD syscalls**: XNU's `syscalls.master` table, implemented on top of the same VFS, process and socket code the Linux persona uses. Most BSD calls map directly onto Linux semantics (`open`, `read`, `mmap`). The rest are thin (`getattrlist`, `getdirentries64`, `proc_info`, `csops`, `__pthread_kill`).
- **kqueue and kevent** including `EVFILT_MACHPORT`, `EVFILT_USER`, and `kevent_qos` and `kevent_id` for libdispatch workloops.
- **The workqueue**: `bsdthread_register` and `workq_kernreturn`, with the kernel creating and parking threads by QoS class, driven by `rk-sched` as a scheduling class.
- **ulock and psynch**: `__ulock_wait2` and `__ulock_wake` over the futex machinery, and the `psynch_*` calls for pthread mutexes, condition variables and rwlocks.
- **The shared region** and the **commpage**.
- **The syscall entry**: on x86-64, the class encoding in `rax` (Mach, Unix, machdep); on arm64, `svc #0x80` with negative numbers for Mach traps. The persona flag on the task selects the Darwin dispatch table on entry. This is the only place the persona touches the hot path, and it is one predictable branch.

Estimated size: 30,000 to 40,000 lines of Rust, all of it safe, all of it in one crate that is compiled only when the `darwin` persona feature is on.

### 16.4.3 The user space part

The Darwin user space is assembled from what can legally be assembled:

- **Apple's open source**, under the APSL and other permissive licenses: `dyld`, `libdispatch`, `libpthread`, `Libc`, `libmalloc`, `CoreFoundation` (the open CF-lite), `objc4`, `libclosure`, parts of `Security`, `launchd`'s open pieces, `xnu`'s headers. These are the foundations, and they are real Apple code.
- **Darling's reimplementations** of the closed frameworks, contributed to rather than forked, under the same rule as Wine.
- **Our own `libsystem_kernel.dylib`**, built from XNU's open source system call stubs, which call into `rk-mach` directly rather than into a server.

### 16.4.4 Tiers, honestly

| Tier | What | Expected at 1.0 |
|---|---|---|
| D1 | Unix programs built for macOS: command line tools in C, C++, Rust, Go, Swift on Foundation only, Homebrew bottles, Python and Node built for macOS, compilers | yes, x86-64 and arm64 (non arm64e). This is Darling's working set today and the kernel side makes it faster and more robust |
| D2 | programs using XPC services, `launchd` agents, Keychain through Security, FSEvents | partially; depends on the reimplemented services |
| D3 | simple AppKit GUI programs | research. Darling's GUI support is "basic experimental", built on Cocotron's AppKit and an early Metal over Vulkan layer |
| D4 | large GUI applications (Xcode, Final Cut, Logic, Adobe, Office), Metal heavy software, anything with a System Extension or a kext | no. The closed framework surface is the obstacle, and reimplementing it is a larger project than rukernel |
| D5 | arm64e binaries | only on hardware with FEAT_PAuth, and only when Apple's PAC ABI is documented well enough to reproduce; research |

The macOS claim at 1.0 is therefore D1: "unmodified command line Mach-O binaries for x86-64 and arm64 run on rukernel." That claim is narrower than the goal statement, and it is the one that can be measured: a corpus of Homebrew bottles and their own test suites, run on a Mac and on rukernel, compared by output.

Running macOS's own frameworks on a Mac, under rukernel booted through Asahi's boot chain on Apple hardware, is a different question. It is closer to legal on paper but still needs a real macOS install on the same machine. It is noted as open question in document 24 and is not on the roadmap.

x86-64 Mach-O on arm64 is not worth building toward. Apple's Rosetta 2 is fully supported only through macOS 27, and macOS 28 keeps a reduced form for older games. The x86-64 macOS ecosystem is being retired by its own vendor.

## 16.5 Other ISAs

"Every program" includes the x86-64 binary on an arm64 machine, which is the common case for a laptop in 2026. Translation is user space work and the best translators are already Linux programs: FEX-Emu (monthly releases, Valve funded, used for the Steam Frame) and Box64 (0.4.x, with DynaCache on by default since 0.4.4). Both are registered as personas for foreign `e_machine` values. For Windows on arm64 the Hangover build of Wine pairs Wine's WoW64 thunks with FEX or Box64.

The kernel's job is to make translation fast and correct:

- **Hardware TSO.** Apple M-series cores have a per thread total store order mode (`ACTLR_EL1.TSOEN`) that removes the memory barriers a translator must otherwise insert for x86's memory model. Asahi exposes it to FEX through a `prctl`. rukernel exposes the same `prctl` with the same semantics, saves and restores the bit on context switch, and also implements it on any future arm64 core with an architected TSO feature.
- **Fast signals and `sigreturn`**, since translators implement x86 exceptions, self modifying code detection and guest signals with host signals.
- **`mmap` placement control** for translators that need a 47 bit x86 address space inside a 48 or 52 bit arm64 one.
- **The x86-64 compat syscall surface is not needed**: FEX and Box64 translate guest syscalls to host syscalls themselves.

## 16.6 What "without modifying anything" means, precisely

- The program's binary is never modified, patched, rewritten or re-signed.
- The program is started the way it is started on its home system: by path, by double click in a file manager, by Steam.
- The program runs against libraries we ship, and for Windows and macOS those are reimplementations. That is how it has to be: the original libraries cannot legally be shipped, and for Windows they would also need an NT kernel.
- The success rate is published per persona and tier, measured by the compat harness, and it is never rounded into the Linux number.

## 16.7 Effort and ordering

Windows first, because it is cheap. The persona is mostly the Linux ABI done well plus ntsync, the payoff is the largest catalogue of desktop software in existence, and Proton is the most demanding real world test of the Linux personality available. Wine's test suite and the Proton scenarios join the compat harness at R6 (document 22).

macOS D1 second, at R9, because `rk-mach` is real kernel work (Mach IPC semantics are subtle, especially rights accounting and notification ordering) and because its user is narrower.

`rk-nt` and the macOS GUI tiers are post 1.0 and are justified only by measurement and demand.

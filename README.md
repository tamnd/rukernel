# rukernel

rukernel is an operating system kernel in Rust. It has the same user interface as Linux 7.3. A program that runs on Linux runs on rukernel with no change. The target speed is the speed of Linux on the same machine.

The project is at milestone R0. The design is complete and is in [`spec/`](spec/). The kernel boots on x86-64 under QEMU through PVH, the Linux boot protocol or UEFI and prints the memory map. It does not run programs yet.

## The goal

The goal has five axes. Each axis has a number that a test can measure. [`spec/02-the-goal.md`](spec/02-the-goal.md) gives the gates.

1. **ABI.** rukernel implements each system call, ioctl, netlink family, procfs file and sysfs file of Linux 7.3 that real programs use. A test runs each program on rukernel and on Linux in identical virtual machines and compares the results.
2. **Speed.** Each benchmark class is within its gate of Linux 7.3 on the same machine. The gates are 5% to 10%, by class.
3. **Foreign programs.** Windows programs run through unmodified Wine and Proton. macOS command line programs run through a Darwin user land.
4. **Safety.** All `unsafe` code is in one crate, `rk-frame`, with a budget of 25,000 lines. All other crates forbid `unsafe` code. Verus proofs cover the core of `rk-frame`.
5. **Upstream.** rukernel implements each new Linux release in 63 days or less.

## The design

- **Framekernel.** The kernel has one address space and one privilege level, as Linux has. Only `rk-frame` can contain `unsafe` code. The build fails if another crate contains `unsafe` code.
- **The ABI is data.** A tool, `rk-abigen`, reads the Linux source tree and generates the system call tables, structure layouts, constants and ioctl numbers. No person types these values.
- **Linux is the oracle.** The tests do not compare rukernel with a man page. They compare rukernel with a real Linux kernel. If Linux has a bug that programs see, rukernel has the same bug, and the register records it.
- **No Linux modules.** rukernel does not load `.ko` files. All parts are built in. `modprobe` succeeds for each part that rukernel has.
- **Stable Rust only.** The kernel builds with a stable Rust toolchain. The toolchain version is in [`rust-toolchain.toml`](rust-toolchain.toml).

## The three repositories

| Repository | Contents | License |
|---|---|---|
| [tamnd/rukernel](https://github.com/tamnd/rukernel) | The kernel, the ABI generator and the design | GPL-2.0-only |
| [tamnd/rukernel-compat](https://github.com/tamnd/rukernel-compat) | The differential test harness, `rkc` | Apache-2.0 |
| [tamnd/rukernel-bench](https://github.com/tamnd/rukernel-bench) | The benchmark harness, `rkb` | Apache-2.0 |

## Build and test

You need `rustup`. The toolchain file installs the correct Rust version and the three bare metal targets.

```
cargo xtask ci
```

This command runs the same checks as the CI gate. The cheapest checks run first.

| Command | What it checks |
|---|---|
| `cargo xtask unsafe` | Each crate root has `#![forbid(unsafe_code)]`, except the crates in `xtask/unsafe-allowed.txt` |
| `cargo xtask layers` | Each crate depends only on crates in its layer or a lower layer, as `xtask/layers.txt` gives |
| `cargo xtask style` | The prose has no em dashes, no en dashes and no horizontal rules |
| `cargo xtask targets` | The kernel crates build for `x86_64-unknown-none`, `aarch64-unknown-none` and `riscv64gc-unknown-none-elf` |
| `cargo xtask boot-test` | The kernel boots in QEMU on x86-64 and each self test passes, and the bzImage boots through the Linux boot protocol and UEFI |

## Boot the kernel

You need `qemu-system-x86_64`. This command builds the kernel and boots it in QEMU. The serial console is on the terminal. The arguments become the kernel command line.

```
cargo xtask qemu rk.test=boot
```

QEMU loads the ELF image directly through the PVH entry note. The build also writes a bzImage next to the ELF image, in `target/x86_64-unknown-none/debug/bzImage`. A loader of the Linux boot protocol, such as QEMU with `-kernel` or GRUB with `linux`, can boot it. The bzImage is also an EFI application, so UEFI firmware can start it directly. The boot test boots the bzImage with the BIOS of QEMU and with OVMF. It finds OVMF in the usual package paths, or `RK_OVMF` gives the path.

The `init` and `tty` boot tests run the C programs in `tests/user`. The build compiles them with `musl-gcc` or `zig cc`, or with the command in `RK_USER_CC`. The `busybox` boot test runs the BusyBox shell as init. The shell runs a pipeline, and `^C` stops a job in the foreground. The first run downloads a static BusyBox from busybox.net and checks its SHA-256. `RK_BUSYBOX` gives the path of a different BusyBox. To use the shell yourself, run this command:

```
cargo xtask qemu console=ttyS0 rdinit=/bin/sh -- -i
```

The `ltp` boot test runs tests of the Linux Test Project. `tools/ltp/build.sh` builds them as static musl programs in an Alpine container, and needs docker. The test runs each test in `tools/ltp/tests.txt`. It finds the programs in `target/ltp`, or in the directory that `RK_LTP` gives. To run only some boot tests, give their names:

```
tools/ltp/build.sh target/ltp
cargo xtask boot-test ltp
```

The `kselftest` boot test runs tests from the selftests of Linux. `tools/kselftest/build.sh` builds them as static glibc programs in a Debian container, and needs docker. Now the test runs the `seccomp_bpf` test. It finds the programs in `target/kselftest`, or in the directory that `RK_KSELFTEST` gives:

```
tools/kselftest/build.sh target/kselftest
cargo xtask boot-test kselftest
```

The `gvisor` boot test runs the Unix socket tests of the gVisor system call suite. `tools/gvisor/build.sh` builds them as static glibc programs in a Debian container, without bazel, and needs docker. The build is faster on an x86-64 host, because an arm64 host runs the compiler in an emulator. The test finds the programs in `target/gvisor`, or in the directory that `RK_GVISOR` gives:

```
tools/gvisor/build.sh target/gvisor
cargo xtask boot-test gvisor
```

The `fstests` boot test runs fstests on ext4. `tools/fstests/build.sh` builds fstests and a Debian root file system for it in a container, and needs docker. The test runs each test in `tools/fstests/tests.txt`, with a test disk and a scratch disk. `RK_FSTESTS_TESTS` gives other tests for a run by hand. The test finds the root file system in `target/fstests`, or in the directory that `RK_FSTESTS` gives:

```
tools/fstests/build.sh target/fstests
cargo xtask boot-test fstests
```

The `alpine` and `debian` boot tests run programs that use a dynamic loader. The `alpine` test uses the Alpine mini root file system, with musl. The `debian` test uses the Debian trixie slim root file system, with glibc. Its script runs bash, coreutils, dpkg, apt and perl, and then `tests/user/nptl.c`, a pthread test that the build compiles with glibc. The build uses `cc` on an x86-64 Linux host, or `zig cc -target x86_64-linux-gnu`, or the command in `RK_GLIBC_CC`. The first run downloads each root file system and checks its SHA-256. `RK_ALPINE` and `RK_DEBIAN` give the path of a different file.

The `alpine` test runs `ps`, `top` and `pgrep` of BusyBox on a `sleep` process and checks the values that they show. The test also runs strace, gdb and procps-ng if `tools/debug/build.sh` installed them. The script needs docker. It installs gdb, strace and procps-ng from Alpine, and builds a small C program with debug information. strace traces a shell pipeline with `-f`, and gdb sets a breakpoint in the program and steps it. `ps`, `top`, `pgrep` and `pidof` of procps-ng show the `sleep` process. The test finds the tools in `target/debug-tools`, or in the directory that `RK_DEBUG_TOOLS` gives:

```sh
tools/debug/build.sh target/debug-tools
cargo xtask boot-test alpine
```

## Repository layout

| Path | Contents |
|---|---|
| `spec/` | The design, in 25 documents |
| `kernel/rukernel/` | The kernel binary and its linker script |
| `frame/rk-frame/` | The only crate that can contain `unsafe` code |
| `core/rk-abi/` | The typed Linux ABI: error numbers now, generated tables later |
| `core/rk-lib/` | Safe helpers that all kernel crates use |
| `core/rk-sched/` | The scheduler: the fair class with EEVDF |
| `core/rk-mm/` | The memory manager: areas, page faults, copy on write, `mmap` and `brk` |
| `fs/rk-vfs/` | The virtual file system: inodes, dentries, mounts, path walks, open files and the cpio reader |
| `fs/rk-fs-proc/` | procfs, the files of `/proc` that give the state of the kernel and of each process |
| `fs/rk-fs-sys/` | sysfs, the files of `/sys` that show the devices of the kernel |
| `fs/rk-fs-tmpfs/` | tmpfs, the file system in memory that holds the initramfs |
| `net/rk-net/` | The socket layer: the socket operations, the socket files and the common socket options |
| `net/rk-net-unix/` | Unix sockets: stream, datagram and seqpacket sockets with path and abstract names |
| `core/rk-proc/` | Processes and threads: process IDs, `fork`, `execve`, `exit` and `wait4` |
| `core/rk-syscall/` | The system call table and the system calls of R1 |
| `drv/rk-drv-mem/` | The memory devices: `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random` and `/dev/urandom` |
| `drv/rk-drv-tty/` | The console tty on the serial port |
| `tests/user/` | The C test programs that run in user mode |
| `xtask/` | The build checks |

[`spec/23-package-layout.md`](spec/23-package-layout.md) gives the full crate tree. The crates come into the tree as the milestones need them.

## Milestones

Each milestone has an exit criterion that a script can check. Each milestone also stops at a useful point. [`spec/22-milestones.md`](spec/22-milestones.md) gives the details. Each milestone has a [tracking issue](https://github.com/tamnd/rukernel/issues?q=label%3Akind%2Fmilestone).

| Milestone | Result |
|---|---|
| R0 | The skeleton. `rk-frame` boots on x86-64 under QEMU. The generated ABI exists. |
| R1 | A static BusyBox boots to a shell. |
| R2 | glibc programs run with dynamic linking. gdb and strace work. |
| R3 | Debian boots from an ext4 disk. |
| R4 | Memory, scheduling and networking at depth. arm64 is tier 1. |
| R5 | Distributions boot with systemd. |
| R6 | Containers, KVM and Windows programs. |
| R7 | The BPF JIT, BTF, perf and tracing. |
| R8 | Bare metal servers at Linux speed. riscv64 is tier 2. |
| R9 | macOS command line programs. arm64 is at Linux speed. |
| R10 | The desktop. This is 1.0. |
| R11 | Primitives that Linux does not have, for Wine. |
| R12 | Proofs for all of `rk-frame`. |

## What rukernel is not

- rukernel is not a Linux fork. It is not a translation of Linux from C to Rust. The code is new.
- rukernel does not load Linux drivers. A `.ko` file uses the internal structures of one Linux build, and rukernel does not have them.
- rukernel is not a Windows kernel or a macOS kernel. A program that needs a Windows kernel driver or a macOS kernel extension does not run.
- rukernel does not ship Apple frameworks and does not load them.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Report security problems as [SECURITY.md](SECURITY.md) tells you.

## License

The kernel is under the GNU General Public License, version 2 only. Refer to [LICENSE](LICENSE). This is the license of Linux. Thus a developer can read the Linux source and use its algorithms in rukernel. The harness repositories are under the Apache License 2.0.

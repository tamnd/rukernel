# rukernel-bench (first version)

This directory has the first version of rukernel-bench, the harness that compares the performance of rukernel and Linux. [spec/19-rukernel-bench.md](../../spec/19-rukernel-bench.md) gives the rules, and [spec/23-package-layout.md](../../spec/23-package-layout.md) section 23.5 gives the layout. The harness will move to its own repository, `tamnd/rukernel-bench`, later. Until then, it is small and it stays here.

- `bench.c` has the workloads. It is one static C program with a function for each benchmark.
- `run.py` compiles `bench.c`, boots rukernel and Linux in QEMU with the same initramfs, and writes the table.
- `results.md` is the table that `run.py` made. Do not edit it.
- `logs` has the serial output of the two kernels in the run of `results.md`. `run.py --reuse --out tools/bench/logs` makes the table again from them.

## The benchmarks

The table has four classes of spec/19-rukernel-bench.md section 19.1.

| Class | Benchmark | What it measures |
|---|---|---|
| entry | `getpid` | `syscall(SYS_getpid)` in a loop |
| entry | `null` | `syscall(SYS_getppid)` in a loop, the null system call of LMbench |
| entry | `read_zero` | `read` of 1 byte from /dev/zero |
| entry | `pipe_rw` | `write` of 1 byte to a pipe and `read` of it, in one process |
| sched | `ctxsw` | a round trip of 1 byte between two processes over two pipes |
| sched | `yield` | `sched_yield` with no other task |
| sched | `thread` | `pthread_create` and `pthread_join` of a thread that returns at once |
| mem | `fault` | the write fault on a new anonymous page |
| mem | `mmap` | `mmap` and `munmap` of 64 KiB anonymous memory |
| mem | `fork` | `fork`, `_exit` of the child and `waitpid` |
| mem | `fork_big` | the same in a process with 128 MiB of written private memory |
| mem | `fault_mt` | `fault` in one thread per CPU at the same time, as page_fault1 of will-it-scale. The value is the wall time over the faults of all threads |
| mem | `mmap_mt` | `mmap` and `munmap` of 64 KiB in one thread per CPU at the same time, as mmap1 of will-it-scale |
| mem | `cow` | the write fault that copies a private page of 4 KiB that a child of `fork` also maps. The time of the page copy is a part of it |
| net | `tcp_rr` | a round trip of 1 byte over TCP on loopback between two processes |
| net | `tcp_stream` | the throughput of one TCP connection on loopback |
| net | `udp_rr` | a round trip of 1 byte over UDP on loopback between two processes |
| net | `udp_stream` | the throughput of datagrams of 1 KiB over UDP on loopback, as the receiver counts them |

`udp_stream` depends much on the scheduler. With 1 CPU, the sender and the receiver share the CPU. Since the EEVDF wakeup preemption of #408 (2bcd83e), the receiver that a datagram wakes takes the CPU from the sender at once, as in Linux, so the two tasks switch about one time for each datagram. Before, the sender ran until the next tick, and the receiver then read the datagrams in a batch. This is the cause of the drop of the row from 16.8 MB/s (f4a973a) to 4.73 MB/s (212e8b2 with #401) in results.md (#442). A `git bisect` on server2 found 2bcd83e: 4.00 MB/s, and 18.0 MB/s at the commit before it (d94bb6d). At fa7f8e5, the row gives 5.29 MB/s, and 21.0 MB/s with the wakeup preemption turned off. Linux gives 5.50 MB/s in the same run. Thus the network code did not become slower, and the new value is the one to compare with Linux.

## How it runs

`run.py` compiles `bench.c` as a static musl program and puts it as `/init` in an initramfs. It boots each kernel one time in QEMU, with the same machine: the same CPU count, memory, accelerator and CPU model. As init, the program mounts /proc and /dev, brings up `lo`, and runs each benchmark one time as a warm-up and then `--runs` times. Each run prints one line on the serial console. `run.py` reads the lines, and writes the median of each benchmark, the interquartile range, and the ratio of rukernel to Linux to `results.md`. A row where rukernel is more than 2 times slower than Linux is red. The serial output of each kernel stays in `OUT/linux.log` and `OUT/rukernel.log`.

Build the release kernel first. On a host with QEMU and a compiler for static musl programs:

```
cargo build --release --package rukernel --target x86_64-unknown-none
tools/bench/run.py --rukernel target/x86_64-unknown-none/release/rukernel \
    --linux /boot/vmlinuz-VERSION --cc musl-gcc --runs 10 --out /tmp/bench
```

`--arch aarch64` runs arm64 kernels on the `virt` machine of `qemu-system-aarch64` with a GICv3, and the console is `ttyAMA0`. Without KVM on an arm64 host, the CPU is `cortex-a72`, as in the arm64 boot tests. `--rukernel` is then the arm64 ELF file of rukernel, which `run.py` changes into an `Image`, and `--linux` is a Linux arm64 `Image`, for example the uncompressed `vmlinuz` of the arm64 kernel package of Ubuntu. `--cc` must make static arm64 programs. `results-aarch64.md` has the arm64 table, with the logs in `logs-aarch64`.

`linux-arm64.sh DIR` builds a Linux arm64 `Image` for the Linux column. It downloads the Linux release that tools/rk-abigen uses (7.3), checks its SHA-256, and builds the `Image` of `defconfig` with `aarch64-linux-gnu-gcc`, or with clang and ld.lld (`LLVM=1`) if that compiler is not there. The build runs with `nice -n 19` and 3 jobs, and `JOBS` changes the number of jobs. The `Image` is `DIR/build/arch/arm64/boot/Image`. On server2 (6 CPUs, load average 15 to 17), the build took about 75 minutes, the `Image` is 50 MiB, and DIR takes 3.6 GiB.

```
tools/bench/linux-arm64.sh ~/rk-linux-arm64
cargo build --release --package rukernel --target aarch64-unknown-none
tools/bench/run.py --arch aarch64 --rukernel target/aarch64-unknown-none/release/rukernel \
    --linux ~/rk-linux-arm64/build/arch/arm64/boot/Image --cc aarch64-linux-musl-gcc \
    --out tools/bench/logs-aarch64 --table tools/bench/results-aarch64.md
```

In the first arm64 table (#442), `tcp_stream` is red: 25.7 MB/s on rukernel and 57.5 MB/s on Linux, a ratio of 2.23. Linux is 7 times slower than rukernel on the entry rows (`getpid` 39482 ns on Linux and 5694 ns on rukernel), and the cause is not known yet.

The arm64 `fork` copy of #401, with `run.py --arch aarch64` on server2 (QEMU 8.2.2 with TCG, `cortex-a72`, `-smp 1`, load average 6 to 7), rukernel only, because the host had no Linux arm64 `Image` then. The medians of 2 boots of 5 runs each (#442):

| Benchmark | 212e8b2 (before #401) | fa7f8e5 (#401) |
|---|---|---|
| `fork` (us) | 856, 817 | 629, 665 |
| `fork_big` (us) | 7724, 7745 | 2920, 2799 |
| `cow` (ns) | 20966, 21334 | 19293, 17496 |
| `fault` (ns) | 5884, 5876 | 5702, 5434 |
| `mmap` (ns) | 33273, 27315 | 22569, 22296 |

`fork` is 1.3 times faster and `fork_big` 2.7 times faster. `fork_big` also gains from the one entry for each huge page of #401.

`--cc` takes a command with arguments, for example `"zig cc -target x86_64-linux-musl"`. `--bench FILE` uses a program that is already compiled. `--only getpid,fork` runs only some benchmarks. `--reuse` makes the table again from the logs of an earlier run, with no boot. `--reuse-linux` boots only rukernel and takes the Linux values from the earlier log, so two rukernel builds can use the same Linux run. `--smp` and `--memory` change the machine for both kernels. `run.py --help` gives all the options.

`--qemu DIR` uses the QEMU programs in DIR, and the default is the directory in `RK_QEMU`, or `PATH`. `--cpu MODEL` gives the CPU model without KVM, for example `max,-x2apic`.

## The x2APIC

`apic.rs` uses the x2APIC when CPUID gives it. QEMU 8.2.2 with TCG has no x2APIC, so the boot tests and `results.md` use the xAPIC. QEMU 9.2.4 with TCG gives the x2APIC with `-cpu max`. With it, the kernel writes `x2apic enabled` in the boot log, and the `init` boot test checks that the kernel uses the x2APIC if and only if CPUID gives it (#442). On server2 with QEMU 9.2.4 (`RK_QEMU`), the boot tests `init`, `smp` (4 CPUs, with IPIs), `busybox`, `mm`, `task`, `blk` and `inet` pass in x2APIC mode. They found no bug.

`results-x2apic.md` is the table of a run with QEMU 9.2.4 and `-cpu max`, with the logs in `logs-x2apic`. rukernel uses the x2APIC in it. Linux does not, because it uses the x2APIC only with interrupt remapping, and the machine has no IOMMU. Its boot log gives "x2apic: IRQ remapping doesn't support X2APIC mode". The host was busy (load average 13 to 17), so the values are less stable than in `results.md`.

The table below compares the modes on rukernel alone. Each value is the median of 10 runs in one boot, for 3 boots with `-cpu max` (x2APIC) and 3 boots with `-cpu max,-x2apic` (xAPIC) on QEMU 9.2.4, one after the other on server2. The ratio is the median of the x2APIC boots divided by the median of the xAPIC boots, and the inverse for the MB/s rows, so a ratio above 1.00 tells that the x2APIC is slower. All ratios are between 0.82 and 1.13, and the interquartile range of a boot is often 10% to 30%. Thus the mode makes no difference that this harness can see under TCG. With `-smp 1`, the APIC writes in these benchmarks are the EOI of the timer, 250 times each second, so this result is as expected. A difference can show with KVM, where each APIC access is an exit of the VM, and the MMIO exit of an xAPIC access costs more than the MSR exit of an x2APIC access.

| Benchmark | x2APIC | xAPIC | Ratio |
|---|---|---|---|
| `getpid` (ns) | 1733, 1410, 1376 | 1838, 1711, 1312 | 0.82 |
| `null` (ns) | 2178, 1653, 1646 | 2121, 1465, 1198 | 1.13 |
| `read_zero` (ns) | 3189, 3071, 3243 | 2772, 2956, 3090 | 1.08 |
| `pipe_rw` (ns) | 9293, 7881, 7319 | 7897, 7882, 7142 | 1.00 |
| `ctxsw` (ns) | 178603, 150924, 148926 | 152883, 160340, 145623 | 0.99 |
| `yield` (ns) | 1779, 1862, 1557 | 1768, 2037, 1818 | 0.98 |
| `thread` (us) | 374, 379, 359 | 350, 371, 297 | 1.07 |
| `fault` (ns) | 5745, 5122, 6038 | 5039, 5859, 5416 | 1.06 |
| `mmap` (ns) | 13673, 12328, 12261 | 12129, 12723, 12140 | 1.02 |
| `fork` (us) | 775, 725, 652 | 689, 664, 683 | 1.06 |
| `fork_big` (us) | 5348, 4562, 4588 | 4715, 4821, 5010 | 0.95 |
| `fault_mt` (ns) | 10701, 10011, 10016 | 7676, 8933, 10148 | 1.12 |
| `mmap_mt` (ns) | 12007, 9289, 10467 | 9109, 9995, 12158 | 1.05 |
| `cow` (ns) | 17467, 16071, 15747 | 17676, 18434, 17691 | 0.91 |
| `tcp_rr` (us) | 381, 312, 325 | 319, 341, 334 | 0.97 |
| `tcp_stream` (MB/s) | 16.6, 18.9, 17.5 | 18.7, 20.4, 18.5 | 1.07 |
| `udp_rr` (us) | 370, 320, 318 | 333, 315, 344 | 0.96 |
| `udp_stream` (MB/s) | 3.70, 4.05, 4.26 | 4.08, 3.99, 3.95 | 0.99 |

To build the same QEMU in a home directory, with no system packages, take the release tarball from download.qemu.org and run `configure --prefix=DIR/install --target-list=x86_64-softmmu,aarch64-softmmu --without-default-features --disable-docs --enable-fdt=internal --enable-slirp --enable-tcg`, then `make` and `make install`. The build needs glib, pixman, meson and ninja. Meson downloads dtc and libslirp. Then set `RK_QEMU=DIR/install/bin`.

## Limits

The numbers come from QEMU, not from hardware. Without KVM, QEMU emulates each instruction (TCG), and privileged instructions, page table changes and device access cost much more than on hardware. Use the table to find large differences. Under TCG, Linux is very slow on the benchmarks that change page tables or switch tasks, and the cause is not known yet. Thus a green row there does not show that rukernel is faster on hardware. The first version does not obey all the rules of spec/19-rukernel-bench.md: it runs on one machine, in a VM, without the Mann-Whitney test, with the distribution kernel of the host and not a pinned Linux build, and without the check of the mitigations. Linux runs with `mitigations=off`, because rukernel has no mitigations yet.

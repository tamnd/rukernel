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

`--arch aarch64` runs arm64 kernels on the `virt` machine of `qemu-system-aarch64` with a GICv3, and the console is `ttyAMA0`. Without KVM on an arm64 host, the CPU is `cortex-a72`, as in the arm64 boot tests. `--rukernel` is then the arm64 ELF file of rukernel, which `run.py` changes into an `Image`, and `--linux` is a Linux arm64 `Image`, for example the uncompressed `vmlinuz` of the arm64 kernel package of Ubuntu. `--cc` must make static arm64 programs. `results-aarch64.md` has the arm64 table.

```
cargo build --release --package rukernel --target aarch64-unknown-none
tools/bench/run.py --arch aarch64 --rukernel target/aarch64-unknown-none/release/rukernel \
    --linux Image --cc aarch64-linux-musl-gcc --only cow --table tools/bench/results-aarch64.md
```

The arm64 `fork` copy of #401, with `run.py --arch aarch64` on server2 (QEMU 8.2.2 with TCG, `cortex-a72`, `-smp 1`, load average 6 to 7), rukernel only, because the host has no Linux arm64 `Image`. The medians of 2 boots of 5 runs each (#442):

| Benchmark | 212e8b2 (before #401) | fa7f8e5 (#401) |
|---|---|---|
| `fork` (us) | 856, 817 | 629, 665 |
| `fork_big` (us) | 7724, 7745 | 2920, 2799 |
| `cow` (ns) | 20966, 21334 | 19293, 17496 |
| `fault` (ns) | 5884, 5876 | 5702, 5434 |
| `mmap` (ns) | 33273, 27315 | 22569, 22296 |

`fork` is 1.3 times faster and `fork_big` 2.7 times faster. `fork_big` also gains from the one entry for each huge page of #401.

`--cc` takes a command with arguments, for example `"zig cc -target x86_64-linux-musl"`. `--bench FILE` uses a program that is already compiled. `--only getpid,fork` runs only some benchmarks. `--reuse` makes the table again from the logs of an earlier run, with no boot. `--reuse-linux` boots only rukernel and takes the Linux values from the earlier log, so two rukernel builds can use the same Linux run. `--smp` and `--memory` change the machine for both kernels. `run.py --help` gives all the options.

## Limits

The numbers come from QEMU, not from hardware. Without KVM, QEMU emulates each instruction (TCG), and privileged instructions, page table changes and device access cost much more than on hardware. Use the table to find large differences. Under TCG, Linux is very slow on the benchmarks that change page tables or switch tasks, and the cause is not known yet. Thus a green row there does not show that rukernel is faster on hardware. The first version does not obey all the rules of spec/19-rukernel-bench.md: it runs on one machine, in a VM, without the Mann-Whitney test, with the distribution kernel of the host and not a pinned Linux build, and without the check of the mitigations. Linux runs with `mitigations=off`, because rukernel has no mitigations yet.

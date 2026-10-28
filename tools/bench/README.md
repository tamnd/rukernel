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
| net | `tcp_rr` | a round trip of 1 byte over TCP on loopback between two processes |
| net | `tcp_stream` | the throughput of one TCP connection on loopback |
| net | `udp_rr` | a round trip of 1 byte over UDP on loopback between two processes |
| net | `udp_stream` | the throughput of datagrams of 1 KiB over UDP on loopback, as the receiver counts them |

## How it runs

`run.py` compiles `bench.c` as a static musl program and puts it as `/init` in an initramfs. It boots each kernel one time in QEMU, with the same machine: the same CPU count, memory, accelerator and CPU model. As init, the program mounts /proc and /dev, brings up `lo`, and runs each benchmark one time as a warm-up and then `--runs` times. Each run prints one line on the serial console. `run.py` reads the lines, and writes the median of each benchmark, the interquartile range, and the ratio of rukernel to Linux to `results.md`. A row where rukernel is more than 2 times slower than Linux is red. The serial output of each kernel stays in `OUT/linux.log` and `OUT/rukernel.log`.

Build the release kernel first. On a host with QEMU and a compiler for static musl programs:

```
cargo build --release --package rukernel --target x86_64-unknown-none
tools/bench/run.py --rukernel target/x86_64-unknown-none/release/rukernel \
    --linux /boot/vmlinuz-VERSION --cc musl-gcc --runs 10 --out /tmp/bench
```

`--cc` takes a command with arguments, for example `"zig cc -target x86_64-linux-musl"`. `--bench FILE` uses a program that is already compiled. `--only getpid,fork` runs only some benchmarks. `--reuse` makes the table again from the logs of an earlier run, with no boot. `--smp` and `--memory` change the machine for both kernels. `run.py --help` gives all the options.

## Limits

The numbers come from QEMU, not from hardware. Without KVM, QEMU emulates each instruction (TCG), and privileged instructions, page table changes and device access cost much more than on hardware. Use the table to find large differences. Under TCG, Linux is very slow on the benchmarks that change page tables or switch tasks, and the cause is not known yet. Thus a green row there does not show that rukernel is faster on hardware. The first version does not obey all the rules of spec/19-rukernel-bench.md: it runs on one machine, in a VM, without the Mann-Whitney test, with the distribution kernel of the host and not a pinned Linux build, and without the check of the mitigations. Linux runs with `mitigations=off`, because rukernel has no mitigations yet.

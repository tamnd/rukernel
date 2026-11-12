# kselftest test_verifier on rukernel

This file gives the result of bpf/test_verifier of the Linux selftests on rukernel, for the verifier of issue #537. tools/kselftest/build.sh builds test_verifier from Linux v6.17 with a static libbpf, and `cargo xtask boot-test kselftest` runs it as root in the initramfs of the test.

## Scope

Each test of test_verifier has a program, a program type, and the result and the verifier message of Linux. A test passes when rukernel accepts or refuses the program as Linux does, and gives the same message. For a test that Linux accepts, test_verifier also runs the program with `BPF_PROG_TEST_RUN`, and the return value must be the value of the test.

The verifier of rukernel is for the program types of issue #537: `SOCKET_FILTER`, `CGROUP_SKB`, `CGROUP_SOCK`, `CGROUP_SOCK_ADDR` and `CGROUP_DEVICE`. build.sh adds a check to test_verifier that skips the tests of the other program types, with the message `SKIP (program type N)`.

## Result

Run of 2026-11-11, rukernel debug build, x86-64, QEMU TCG with one CPU:

```
Summary: 281 PASSED, 510 SKIPPED, 0 FAILED
```

All 281 tests of the five program types that run give the result of Linux. The first run, before the fixes of the verifier PR, gave 259 PASSED and 22 FAILED.

The skipped tests:

| Count | Reason |
| --- | --- |
| 264 | The unprivileged run (`#N/u`) of each test. The kernel has `kernel.unprivileged_bpf_disabled=2`, so test_verifier runs only as root (`#N/p`). |
| 237 | `SKIP (program type N)`: the program types that issue #537 does not cover. These are 122 tests of `SCHED_CLS` (3), 28 of `TRACEPOINT` (5), 25 of `XDP` (6), 25 of `SK_LOOKUP` (30), 18 of `SK_SKB` (14), 6 of `TRACING` (26), 4 of `PERF_EVENT` (7), 2 of `SCHED_ACT` (4), and 1 each of `KPROBE` (2), `LWT_OUT` (11), `SOCK_OPS` (13), `CGROUP_SYSCTL` (23), `CGROUP_SOCKOPT` (25), `EXT` (28) and `LSM` (29). |
| 6 | `SKIP (requires BPF JIT)`: the inline of `bpf_loop`. rukernel has no JIT before R7. |
| 3 | `SKIP (unsupported map type 4)`: `BPF_MAP_TYPE_PERF_EVENT_ARRAY` is not in issue #537. |

## Notes

- rukernel cannot load bpf_testmod.ko. build.sh changes test_verifier so that it runs on without the module. No test of the five program types fails without the module.
- The verifier prunes a path when its state is equal to a state that it saw before at the same jump target, as `is_state_visited` of Linux. A path that comes back to an equal state is a loop that does not end, and the verifier gives "infinite loop detected at insn N". A loop that changes its state goes on to the limit of 1000000 instructions and gives "BPF program is too large".
- The registers and the stack of a verifier state are on the heap. A debug build of the kernel keeps many copies of a state on the stack, and the 32 KiB kernel stack overflowed with large states.

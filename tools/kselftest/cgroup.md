# kselftest cgroup results

This file gives the results of the cgroup tests of the Linux selftests on rukernel and on the Linux reference kernel, for issue #536. tools/kselftest/build.sh builds test_core, test_cpuset, test_freezer, test_kill, test_memcontrol and test_cpu from Linux v6.17 as static programs.

## How the tests run

tools/kselftest/run.py boots a kernel in QEMU without KVM, with 2 CPUs and 1 GiB of memory. The initramfs has BusyBox, the programs and an init script. The init script mounts cgroup2 on /sys/fs/cgroup with `nsdelegate,memory_recursiveprot`, as systemd does, and runs the programs one after the other. The files of the tests are on the tmpfs of the initramfs. There is no swap.

```sh
tools/kselftest/build.sh out/ks
python3 tools/kselftest/run.py --kernel target/x86_64-unknown-none/release/rukernel \
    --tests out/ks --busybox busybox --log ks-rk.log \
    test_core test_cpuset test_freezer test_kill test_memcontrol test_cpu
python3 tools/kselftest/run.py --linux --kernel /boot/vmlinuz-6.8.0-147-generic \
    --tests out/ks --busybox busybox --log ks-linux.log \
    test_core test_cpuset test_freezer test_kill test_memcontrol test_cpu
python3 tools/kselftest/run.py --report ks-linux.log ks-rk.log
```

For arm64, add `--arch aarch64`, and give arm64 programs and an arm64 BusyBox.

The `kselftest` boot test of `cargo xtask boot-test` runs the same programs. The boot test uses 1 CPU and 512 MiB of memory. A program passes there if it exits with 1 and each test case that fails is in the list `known` of the script: the test cases below that fail on Linux too, and test_cgfreezer_migrate, which has a race (see the notes).

## Controllers

`cgroup.controllers` of the root cgroup is `cpuset cpu io memory hugetlb pids rdma misc` on rukernel, on x86_64 and on arm64. This is the same list as on Linux 6.8.0-147-generic.

## Results

The runs of the table used Linux 6.8.0-147-generic on x86_64 and rukernel on x86_64 and arm64, on server2 with a load average of 12 to 19. The rukernel logs ran test_cpu three times, and the table gives the last run. The pass set of rukernel is the same as the pass set of Linux on x86_64. The only other difference is test_memcg_current_peak, which skips on Linux and fails on rukernel. On arm64, test_cgfreezer_migrate fails in this run (see the notes).

| Program | Test case | Linux 6.8.0-147-generic | rukernel | rukernel arm64 |
| --- | --- | --- | --- | --- |
| test_core | test_cgcore_internal_process_constraint | pass | pass | pass |
| test_core | test_cgcore_top_down_constraint_enable | pass | pass | pass |
| test_core | test_cgcore_top_down_constraint_disable | pass | pass | pass |
| test_core | test_cgcore_no_internal_process_constraint_on_threads | pass | pass | pass |
| test_core | test_cgcore_parent_becomes_threaded | pass | pass | pass |
| test_core | test_cgcore_invalid_domain | pass | pass | pass |
| test_core | test_cgcore_populated | pass | pass | pass |
| test_core | test_cgcore_proc_migration | pass | pass | pass |
| test_core | test_cgcore_thread_migration | pass | pass | pass |
| test_core | test_cgcore_destroy | pass | pass | pass |
| test_core | test_cgcore_lesser_euid_open | pass | pass | pass |
| test_core | test_cgcore_lesser_ns_open | pass | pass | pass |
| test_cpuset | test_cpuset_perms_object_allow | pass | pass | pass |
| test_cpuset | test_cpuset_perms_object_deny | pass | pass | pass |
| test_cpuset | test_cpuset_perms_subtree | pass | pass | pass |
| test_freezer | test_cgfreezer_simple | pass | pass | pass |
| test_freezer | test_cgfreezer_tree | pass | pass | pass |
| test_freezer | test_cgfreezer_forkbomb | pass | pass | pass |
| test_freezer | test_cgfreezer_mkdir | pass | pass | pass |
| test_freezer | test_cgfreezer_rmdir | pass | pass | pass |
| test_freezer | test_cgfreezer_migrate | pass | pass | fail |
| test_freezer | test_cgfreezer_ptrace | pass | pass | pass |
| test_freezer | test_cgfreezer_stopped | pass | pass | pass |
| test_freezer | test_cgfreezer_ptraced | pass | pass | pass |
| test_freezer | test_cgfreezer_vfork | pass | pass | pass |
| test_kill | test_cgkill_simple | pass | pass | pass |
| test_kill | test_cgkill_tree | pass | pass | pass |
| test_kill | test_cgkill_forkbomb | pass | pass | pass |
| test_memcontrol | test_memcg_subtree_control | pass | pass | pass |
| test_memcontrol | test_memcg_current_peak | skip | fail | fail |
| test_memcontrol | test_memcg_min | fail | fail | fail |
| test_memcontrol | test_memcg_low | fail | fail | fail |
| test_memcontrol | test_memcg_high | fail | fail | fail |
| test_memcontrol | test_memcg_high_sync | pass | pass | pass |
| test_memcontrol | test_memcg_max | fail | fail | fail |
| test_memcontrol | test_memcg_reclaim | fail | fail | fail |
| test_memcontrol | test_memcg_oom_events | pass | pass | pass |
| test_memcontrol | test_memcg_swap_max_peak | skip | skip | skip |
| test_memcontrol | test_memcg_sock | fail | fail | fail |
| test_memcontrol | test_memcg_oom_group_leaf_events | pass | pass | pass |
| test_memcontrol | test_memcg_oom_group_parent_events | pass | pass | pass |
| test_memcontrol | test_memcg_oom_group_score_events | pass | pass | pass |
| test_cpu | test_cpucg_subtree_control | pass | pass | pass |
| test_cpu | test_cpucg_stats | fail | fail | fail |
| test_cpu | test_cpucg_nice | skip | skip | skip |
| test_cpu | test_cpucg_weight_overprovisioned | fail | fail | pass |
| test_cpu | test_cpucg_weight_underprovisioned | skip | skip | skip |
| test_cpu | test_cpucg_nested_weight_overprovisioned | pass | pass | pass |
| test_cpu | test_cpucg_nested_weight_underprovisioned | skip | skip | skip |
| test_cpu | test_cpucg_max | fail | fail | fail |
| test_cpu | test_cpucg_max_nested | fail | fail | fail |

Linux 6.8.0-147-generic: 10 fail, 36 pass, 5 skip.

rukernel: 11 fail, 36 pass, 4 skip.

rukernel arm64: 11 fail, 36 pass, 4 skip.

## Test cases that fail or skip on Linux

These test cases do not pass on Linux 6.8 in the same runner, so they are not in the pass set of the reference.

| Test case | Linux | rukernel | Reason |
| --- | --- | --- | --- |
| test_memcg_current_peak | skip | fail | The test writes `memory.peak` to reset it, and Linux 6.8 does not have this write (it came in Linux 6.12), so the test skips. rukernel has the write, and the test goes on. It then reads 50 MiB of a file of the tmpfs, and expects that the read charges 50 MiB of page cache. A read of a hole of a tmpfs file gives the zero page and does not charge, on Linux too. |
| test_memcg_min, test_memcg_low, test_memcg_high, test_memcg_max, test_memcg_reclaim | fail | fail | These tests expect that the kernel reclaims page cache from the cgroup. The page cache of the tests is on tmpfs and there is no swap, so Linux cannot reclaim it. rukernel does not reclaim page cache from a cgroup. |
| test_memcg_sock | fail | fail | The test expects the `sock` counter of `memory.stat` to go up while a TCP connection on the loopback interface sends data, and to go back to 0 after it. |
| test_cpucg_stats, test_cpucg_max, test_cpucg_max_nested | fail | fail | The tests compare `usage_usec` of `cpu.stat` with an expected CPU time, with a small margin. Under QEMU without KVM the values are not in the margin, on Linux too. |
| test_cpucg_weight_overprovisioned | fail | fail or pass | The test compares the CPU time of three cgroups with weights 50, 100 and 150. On rukernel it passed in 1 of 3 runs on x86_64 and in 3 of 3 runs on arm64. |
| test_cpucg_nice | skip | skip | `cpu.stat` has no `nice_usec` on Linux 6.8 and on rukernel. |
| test_cpucg_weight_underprovisioned, test_cpucg_nested_weight_underprovisioned | skip | skip | The tests need 4 CPUs or more, and the runner gives 2. |
| test_memcg_swap_max_peak | skip | skip | There is no swap. |

## Notes

test_cpucg_nested_weight_overprovisioned compares the CPU time of nested cgroups. Before #536 it failed on rukernel for two reasons. The weight of a thread did not include the weights of the other entities at each level of the tree, and the load balance of rk-sched moved tasks to make the number of tasks equal, not the weights. Now each thread gets the part of the weight of its cgroup that Linux gives it, and a busy CPU compares the sum of the weights of the tasks, as `migrate_load` of Linux. The test passes in each run on x86_64 and arm64.

test_cgfreezer_migrate fails on arm64 under QEMU without KVM on rukernel and on Linux 7.3, and the result changes with the number of CPUs. The test freezes a cgroup B, moves a process into it, and waits for an inotify event of `cgroup.events` to see that B is frozen. The test never reads the inotify file descriptor, so the file descriptor stays readable after the first event, and the 10 checks of the wait loop do not wait. The loop also does not stop when a check succeeds. Thus the test passes only if B is frozen at the first check, before the moved process stops. Linux has the same race, but it sends the event from a workqueue and at most once in 10 ms. In two runs of test_freezer at each number of CPUs, the results were:

| CPUs | rukernel arm64 | Linux 7.3 arm64 |
| --- | --- | --- |
| 1 | pass, pass | - |
| 2 | pass, pass | fail, fail |
| 4 | fail, fail | pass, pass |

In one of these rukernel runs with 2 CPUs, test_cgfreezer_mkdir failed. On Linux 7.3 with 4 CPUs, test_cgfreezer_ptrace failed once, and the kernel crashed in the other run after the freezer tests. On x86_64, test_freezer passes on both kernels.

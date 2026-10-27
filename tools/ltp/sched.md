# LTP sched results

report.py makes this file from the logs of the runs. Do not change it by hand.

These are the results of the tests of runtest/sched of LTP 20260930 on rukernel. The README in this directory tells how the tests run.

The Linux code column links to the code of Linux 7.3 that the test checks. The note is the note in notes.txt, or else the first TFAIL, TBROK or TCONF line of the output.

rukernel: 4 pass, 3 fail, 3 does not apply, 3 hang, 1 not built, of 14 tests.

| Test | What the test checks | Linux code | rukernel | Last run | Note |
| --- | --- | --- | --- | --- | --- |
| [pth_str01](https://github.com/linux-test-project/ltp/blob/20260930/testcases/kernel/sched/pthreads/pth_str01.c) | TODO: proper output | [kernel/sched/core.c](https://github.com/torvalds/linux/blob/v7.3/kernel/sched/core.c), [kernel/futex/](https://github.com/torvalds/linux/blob/v7.3/kernel/futex/) | pass | 2026-10-27 |  |
| [pth_str02](https://github.com/linux-test-project/ltp/blob/20260930/testcases/kernel/sched/pthreads/pth_str02.c) |  | [kernel/sched/core.c](https://github.com/torvalds/linux/blob/v7.3/kernel/sched/core.c), [kernel/futex/](https://github.com/torvalds/linux/blob/v7.3/kernel/futex/) | pass | 2026-10-27 |  |
| [pth_str03](https://github.com/linux-test-project/ltp/blob/20260930/testcases/kernel/sched/pthreads/pth_str03.c) | TODO: proper output | [kernel/sched/core.c](https://github.com/torvalds/linux/blob/v7.3/kernel/sched/core.c), [kernel/futex/](https://github.com/torvalds/linux/blob/v7.3/kernel/futex/) | pass | 2026-10-27 |  |
| [time-schedule01](https://github.com/linux-test-project/ltp/blob/20260930/testcases/kernel/sched/tool/time-schedule.c) | time-schedule.c | [kernel/sched/core.c](https://github.com/torvalds/linux/blob/v7.3/kernel/sched/core.c) | fail (exit 1) | 2026-10-27 | Error changing to RT class Function not implemented |
| [trace_sched01](https://github.com/linux-test-project/ltp/blob/20260930/testcases/kernel/sched/tool/trace_sched.c) | This utility spawns N tasks, each task sets its priority by making a system call to the scheduler. | [kernel/sched/core.c](https://github.com/torvalds/linux/blob/v7.3/kernel/sched/core.c) | fail (signal 127) | 2026-10-27 | thread [0] - process exited with exit code -1 |
| [cfs_bandwidth01](https://github.com/linux-test-project/ltp/blob/20260930/testcases/kernel/sched/cfs-scheduler/cfs_bandwidth01.c) | Creates a multi-level CGroup hierarchy with the cpu controller enabled. | [kernel/sched/fair.c](https://github.com/torvalds/linux/blob/v7.3/kernel/sched/fair.c) | does not apply | 2026-10-27 | TCONF: Needs CONFIG_CFS_BANDWIDTH |
| [hackbench01](https://github.com/linux-test-project/ltp/blob/20260930/testcases/kernel/sched/cfs-scheduler/hackbench.c) | hackbench tests the Linux scheduler. | [kernel/sched/fair.c](https://github.com/torvalds/linux/blob/v7.3/kernel/sched/fair.c) | hang | 2026-10-27 |  |
| [hackbench02](https://github.com/linux-test-project/ltp/blob/20260930/testcases/kernel/sched/cfs-scheduler/hackbench.c) | hackbench tests the Linux scheduler. | [kernel/sched/fair.c](https://github.com/torvalds/linux/blob/v7.3/kernel/sched/fair.c) | hang | 2026-10-27 |  |
| [starvation](https://github.com/linux-test-project/ltp/blob/20260930/testcases/kernel/sched/cfs-scheduler/starvation.c) | Thread starvation test. | [kernel/sched/fair.c](https://github.com/torvalds/linux/blob/v7.3/kernel/sched/fair.c) | hang | 2026-10-27 |  |
| [proc_sched_rt01](https://github.com/linux-test-project/ltp/blob/20260930/testcases/kernel/sched/sysctl/proc_sched_rt01.c) | Sanity tests for the /proc/sys/kernel/sched_r* files. | [kernel/sched/core.c](https://github.com/torvalds/linux/blob/v7.3/kernel/sched/core.c) | does not apply | 2026-10-27 | TCONF: Needs CONFIG_SYSCTL |
| [sched_cli_serv](https://github.com/linux-test-project/ltp/blob/20260930/testcases/kernel/sched/clisrv/run_sched_cliserv.sh) |  | [kernel/sched/core.c](https://github.com/torvalds/linux/blob/v7.3/kernel/sched/core.c) | fail (exit 1) | 2026-10-27 | + exit 1 |
| [sched_stress](https://github.com/linux-test-project/ltp/blob/20260930/testcases/kernel/sched/sched_stress/sched_stress.sh) | FILE : sched_stress | [kernel/sched/core.c](https://github.com/torvalds/linux/blob/v7.3/kernel/sched/core.c) | pass | 2026-10-27 |  |
| [autogroup01](https://github.com/linux-test-project/ltp/blob/20260930/testcases/kernel/sched/autogroup/autogroup01.c) | This is a regression test about the race in autogroup, this test can crash the buggy kernel, and the bug has been fixed in: | [kernel/sched/autogroup.c](https://github.com/torvalds/linux/blob/v7.3/kernel/sched/autogroup.c) | does not apply | 2026-10-27 | TCONF: autogroup not supported |
| [sched_football](https://github.com/linux-test-project/ltp/blob/20260930/testcases/realtime/func/sched_football/sched_football.c) | Scheduler test that uses a football analogy. |  | not built | 2026-10-27 |  |

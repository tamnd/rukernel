# The missing files of alpine

The files under /proc and /sys that the `alpine` boot test looks for and that rukernel does not have, from a boot with `rk.missing=1`. `report.py` made this file on 2026-11-02. PID, TID and FD stand for a number, and cpuN for the number of a CPU.

1 file is missing.

| File | Programs | Lookups | Linux |
| --- | --- | --- | --- |
| `/proc/sys/vm/memfd_noexec` | `apk` | 1 | [kernel/pid_namespace.c](https://github.com/torvalds/linux/blob/v7.3/kernel/pid_namespace.c) |

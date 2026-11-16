# systemd integration test results

This file gives the results of three integration tests of systemd on rukernel and on the Linux reference kernel, for issue #536: TEST-07-PID1, TEST-19-CGROUP and TEST-55-OOMD.

## How the tests run

tools/systemd/integration.py runs the tests. Its help text tells how it sets up a test, as test/integration-test-wrapper.py of systemd does for a test in a virtual machine. The tree is Debian 13 with systemd 257.13, from tools/systemd/build.sh with the packages of the help text:

```sh
RK_SYSTEMD_PACKAGES="systemd-tests systemd-oomd stress-ng systemd-container dbus-user-session \
    libpam-systemd iproute2 iputils-ping strace attr util-linux procps socat ncat" \
    tools/systemd/build.sh sd-tree.tar.gz
python3 tools/systemd/integration.py --tree sd-tree.tar.gz \
    --kernel target/x86_64-unknown-none/release/rukernel --busybox busybox --memory 1G \
    --out it-rk TEST-07-PID1 TEST-19-CGROUP TEST-55-OOMD
python3 tools/systemd/integration.py --linux --modules /lib/modules/6.8.0-147-generic \
    --tree sd-tree.tar.gz --kernel /boot/vmlinuz-6.8.0-147-generic --busybox busybox \
    --memory 1G --out it-linux TEST-07-PID1 TEST-19-CGROUP TEST-55-OOMD
python3 tools/systemd/integration.py --report it-linux/*.log it-rk/*.log
```

`--append systemd.log_level=debug` adds parameters to the command line of the kernel, and `--match-subtest` and `--match-testcase` run a part of a test. For arm64, add `--arch aarch64`, and give an arm64 tree (`tools/systemd/build.sh FILE arm64`) and an arm64 BusyBox.

Each test boots once in QEMU without KVM, with 2 CPUs and 1 GiB of memory. The test-control.sh of the image runs each subtest and each test case, and does not stop at the first failure, so one boot gives the result of each one.

## Results

The runs are from 2026-11-16, with rukernel 0.5.34 and the changes of #536, and with QEMU without KVM.

- x86_64: rukernel and Linux 6.8.0-147-generic ran on server1, one machine at a time. The load average was between 0.2 and 9 during the runs of rukernel.
- arm64: rukernel ran on server2, with a load average between 20 and 42 from other jobs. TEST-07-PID1 is from the last build. TEST-19-CGROUP and TEST-55-OOMD are from an earlier build, rukernel 0.5.30 with the earlier changes of #536. There is no arm64 run of Linux, because the arm64 reference kernel has no PSI, which TEST-55-OOMD needs, and a run of TEST-07-PID1 takes more than 3 hours on that host.

### x86_64

| Test | Subtest or test case | Linux 6.8.0-147-generic | rukernel |
| --- | --- | --- | --- |
| TEST-07-PID1 | (all) | fail (exit-code, 1) | fail (exit-code, 1) |
| TEST-07-PID1 | DeferReactivation | pass | pass |
| TEST-07-PID1 | aux-scope | pass | pass |
| TEST-07-PID1 | exec-context | pass | fail |
| TEST-07-PID1 | exec-deserialization | fail | pass |
| TEST-07-PID1 | exec-deserialization testcase_added_after | pass | pass |
| TEST-07-PID1 | exec-deserialization testcase_added_before | pass | pass |
| TEST-07-PID1 | exec-deserialization testcase_interleaved | pass | pass |
| TEST-07-PID1 | exec-deserialization testcase_issue_6533 | pass | pass |
| TEST-07-PID1 | exec-deserialization testcase_no_change | pass | pass |
| TEST-07-PID1 | exec-deserialization testcase_removal | fail | pass |
| TEST-07-PID1 | exec-deserialization testcase_swapped | fail | pass |
| TEST-07-PID1 | exec-timestamps | pass | pass |
| TEST-07-PID1 | issue-14566 | pass | pass |
| TEST-07-PID1 | issue-16115 | pass | pass |
| TEST-07-PID1 | issue-1981 | pass | pass |
| TEST-07-PID1 | issue-2467 | pass | pass |
| TEST-07-PID1 | issue-27953 | pass | pass |
| TEST-07-PID1 | issue-30412 | pass | pass |
| TEST-07-PID1 | issue-3166 | pass | pass |
| TEST-07-PID1 | issue-3171 | pass | pass |
| TEST-07-PID1 | issue-31752 | pass | pass |
| TEST-07-PID1 | issue-33672 | pass | pass |
| TEST-07-PID1 | issue-34104 | pass | pass |
| TEST-07-PID1 | issue-38320 | pass | pass |
| TEST-07-PID1 | issue-40916 | pass | pass |
| TEST-07-PID1 | main-PID-change | pass | pass |
| TEST-07-PID1 | mask | pass | pass |
| TEST-07-PID1 | mount-invalid-chars | pass | pass |
| TEST-07-PID1 | mqueue-ownership | pass | pass |
| TEST-07-PID1 | poll-limit | pass | pass |
| TEST-07-PID1 | pr-31351 | pass | pass |
| TEST-07-PID1 | private-network | pass | pass |
| TEST-07-PID1 | private-pids | skip | skip |
| TEST-07-PID1 | private-users | pass | pass |
| TEST-07-PID1 | protect-control-groups | pass | pass |
| TEST-07-PID1 | protect-control-groups testcase_basic_no | pass | pass |
| TEST-07-PID1 | protect-control-groups testcase_basic_private | pass | pass |
| TEST-07-PID1 | protect-control-groups testcase_basic_strict | pass | pass |
| TEST-07-PID1 | protect-control-groups testcase_basic_yes | pass | pass |
| TEST-07-PID1 | socket-pass-fds | pass | pass |
| TEST-07-PID1 | type-exec-parallel | pass | pass |
| TEST-07-PID1 | working-directory | pass | pass |
| TEST-19-CGROUP | (all) | pass | pass |
| TEST-19-CGROUP | ExitType-cgroup | pass | pass |
| TEST-19-CGROUP | IPAddressAllow-Deny | pass | pass |
| TEST-19-CGROUP | abort-on-cgroup-creation-failure | pass | pass |
| TEST-19-CGROUP | cleanup-slice | pass | pass |
| TEST-19-CGROUP | delegate | pass | pass |
| TEST-19-CGROUP | delegate testcase_attributes | pass | pass |
| TEST-19-CGROUP | delegate testcase_controllers | pass | pass |
| TEST-19-CGROUP | delegate testcase_scope_unpriv_delegation | pass | pass |
| TEST-19-CGROUP | delegate testcase_subgroup | pass | pass |
| TEST-19-CGROUP | keyed-properties | pass | pass |
| TEST-19-CGROUP | keyed-properties testcase_iodevice_dbus | pass | pass |
| TEST-19-CGROUP | keyed-properties testcase_iodevice_unitfile | pass | pass |
| TEST-19-CGROUP | tasks-max-scale | pass | pass |
| TEST-19-CGROUP | tasks-max-scale testcase_tasks_max_scale_serialize | pass | pass |
| TEST-55-OOMD | (all) | pass | fail (exit-code, 1) |
| TEST-55-OOMD | testcase_basic_system | pass | pass |
| TEST-55-OOMD | testcase_basic_user | pass | pass |
| TEST-55-OOMD | testcase_duration_analyze | pass | pass |
| TEST-55-OOMD | testcase_duration_override | pass | pass |
| TEST-55-OOMD | testcase_preference_avoid | pass | fail |

### arm64

| Test | Subtest or test case | rukernel |
| --- | --- | --- |
| TEST-07-PID1 | (all) | fail (exit-code, 1) |
| TEST-07-PID1 | DeferReactivation | pass |
| TEST-07-PID1 | aux-scope | pass |
| TEST-07-PID1 | exec-context | fail |
| TEST-07-PID1 | exec-deserialization | pass |
| TEST-07-PID1 | exec-deserialization testcase_added_after | pass |
| TEST-07-PID1 | exec-deserialization testcase_added_before | pass |
| TEST-07-PID1 | exec-deserialization testcase_interleaved | pass |
| TEST-07-PID1 | exec-deserialization testcase_issue_6533 | pass |
| TEST-07-PID1 | exec-deserialization testcase_no_change | pass |
| TEST-07-PID1 | exec-deserialization testcase_removal | pass |
| TEST-07-PID1 | exec-deserialization testcase_swapped | pass |
| TEST-07-PID1 | exec-timestamps | pass |
| TEST-07-PID1 | issue-14566 | pass |
| TEST-07-PID1 | issue-16115 | pass |
| TEST-07-PID1 | issue-1981 | pass |
| TEST-07-PID1 | issue-2467 | pass |
| TEST-07-PID1 | issue-27953 | pass |
| TEST-07-PID1 | issue-30412 | pass |
| TEST-07-PID1 | issue-3166 | pass |
| TEST-07-PID1 | issue-3171 | pass |
| TEST-07-PID1 | issue-31752 | pass |
| TEST-07-PID1 | issue-33672 | pass |
| TEST-07-PID1 | issue-34104 | pass |
| TEST-07-PID1 | issue-38320 | pass |
| TEST-07-PID1 | issue-40916 | pass |
| TEST-07-PID1 | main-PID-change | pass |
| TEST-07-PID1 | mask | pass |
| TEST-07-PID1 | mount-invalid-chars | pass |
| TEST-07-PID1 | mqueue-ownership | pass |
| TEST-07-PID1 | poll-limit | pass |
| TEST-07-PID1 | pr-31351 | pass |
| TEST-07-PID1 | private-network | pass |
| TEST-07-PID1 | private-pids | skip |
| TEST-07-PID1 | private-users | pass |
| TEST-07-PID1 | protect-control-groups | pass |
| TEST-07-PID1 | protect-control-groups testcase_basic_no | pass |
| TEST-07-PID1 | protect-control-groups testcase_basic_private | pass |
| TEST-07-PID1 | protect-control-groups testcase_basic_strict | pass |
| TEST-07-PID1 | protect-control-groups testcase_basic_yes | pass |
| TEST-07-PID1 | socket-pass-fds | pass |
| TEST-07-PID1 | type-exec-parallel | fail |
| TEST-07-PID1 | working-directory | pass |
| TEST-19-CGROUP | (all) | pass |
| TEST-19-CGROUP | ExitType-cgroup | pass |
| TEST-19-CGROUP | IPAddressAllow-Deny | pass |
| TEST-19-CGROUP | abort-on-cgroup-creation-failure | pass |
| TEST-19-CGROUP | cleanup-slice | pass |
| TEST-19-CGROUP | delegate | pass |
| TEST-19-CGROUP | delegate testcase_attributes | pass |
| TEST-19-CGROUP | delegate testcase_controllers | pass |
| TEST-19-CGROUP | delegate testcase_scope_unpriv_delegation | pass |
| TEST-19-CGROUP | delegate testcase_subgroup | pass |
| TEST-19-CGROUP | keyed-properties | pass |
| TEST-19-CGROUP | keyed-properties testcase_iodevice_dbus | pass |
| TEST-19-CGROUP | keyed-properties testcase_iodevice_unitfile | pass |
| TEST-19-CGROUP | tasks-max-scale | pass |
| TEST-19-CGROUP | tasks-max-scale testcase_tasks_max_scale_serialize | pass |
| TEST-55-OOMD | (all) | fail (exit-code, 1) |
| TEST-55-OOMD | testcase_basic_system | pass |
| TEST-55-OOMD | testcase_basic_user | pass |
| TEST-55-OOMD | testcase_duration_analyze | pass |
| TEST-55-OOMD | testcase_duration_override | pass |
| TEST-55-OOMD | testcase_preference_avoid | fail |

### Differences and exceptions

- TEST-07-PID1 exec-context fails on rukernel at `SocketBindAllow=` and `SocketBindDeny=`. systemd loads the BPF program `sd_bind4` (82 instructions, with two loops of 128 rounds), and the verifier of rukernel stops at the limit of 1000000 instructions with "BPF program is too large". The verifier prunes a path only when a kept state is equal in all registers, and it keeps at most 16 states for each instruction. Linux 6.8 also prunes when the registers that are different are not read again (liveness) or are scalars that are not precise. So systemd turns off `bpf-socket-bind`, the bind is not refused, and `ncat` runs until `timeout` stops it with 124. The same run shows that `restrict_ifaces_bpf` does not load, because `mmap` of an array map with `BPF_F_MMAPABLE` gives `ENODEV`. This subtest does not use `RestrictNetworkInterfaces=`. Both are open work for the eBPF verifier and maps. The earlier part of exec-context, which checks `DevicePolicy=strict` with `access(2)`, now passes.
- TEST-07-PID1 exec-deserialization and DeferReactivation depend on the time between two jobs. Under TCG they fail on some runs of both kernels. In these runs Linux failed testcase_removal and testcase_swapped, and rukernel passed them.
- TEST-07-PID1 private-pids is skipped on both kernels.
- TEST-07-PID1 type-exec-parallel failed on arm64 with "Failed to start transient service unit: Connection timed out" from `systemd-run`. The test starts 20 services at the same time, and the D-Bus call took more than its time limit at a load of 40. It passes on x86_64.
- TEST-55-OOMD testcase_basic_system failed in the first x86_64 run of rukernel. At that time other jobs used all the memory of the host except 100 MB, and systemd-journald stopped with a watchdog error. The table has the second run, where it passed.
- TEST-55-OOMD testcase_preference_avoid and the other cases that wait for a kill by systemd-oomd need memory pressure from reclaim. rukernel has no reclaim of anonymous memory and no swap, so `pgscan` stays 0 and systemd-oomd does not kill. This is #752.
- An arm64 run of an earlier build stopped once at `systemctl daemon-reload` in TEST-07-PID1 and once in TEST-55-OOMD. Two debug runs and the last run of TEST-07-PID1 did not stop there.

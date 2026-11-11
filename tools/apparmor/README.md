# apparmor

This directory has the files that load the AppArmor profiles of Ubuntu 26.04 and run the AppArmor regression tests (tests/regression/apparmor of the AppArmor project) on rukernel in complain mode, and the record of the results (#540).

- `build.sh` builds the root file system of the tests in an Ubuntu 26.04 container: `apparmor_parser`, `aa-status` and the profiles of the apparmor package of Ubuntu, and tests/regression/apparmor of the source package with the same version, built with `make USE_SYSTEM=1`.
- `run.py` runs the tests on rukernel, or on a Linux reference kernel, under QEMU, in batches.
- `report.py` makes `report.md` from the logs of the runs.
- `report.md` has the result of each test on Linux and on rukernel.

## How the tests run

`run.py` makes an initramfs from the root file system of `build.sh`, with the list of the tests of a batch and an init script. The coreutils of Ubuntu 26.04 is one program with a hard link for each command, and the program checks its name. Thus the initramfs keeps the hard links. Each batch boots the kernel in QEMU with `apparmor=1`. The init script mounts securityfs and runs the tests one after the other.

The first test is `profiles`. It loads all the profiles of /etc/apparmor.d with `apparmor_parser -r -K`, as apparmor.service does at boot, and lists them with `aa-status`. It passes when the parser and `aa-status` give 0 and `aa-status` lists all the profiles that the kernel has. The output has the list of the profiles with their modes, so the report can compare the profiles of rukernel with the profiles of the reference.

Each other test is one run of `VERBOSE=1 bash TEST.sh` in tests/regression/apparmor, as `make tests` runs it. The init script adds `-C` to the arguments of the parser in uservars.inc, so each test loads its profiles in complain mode. `--enforce` loads them in enforce mode. In verbose mode, each check of a test gives a line `ok (pass): ...` or an error. A test has a time limit of 600 seconds (3600 seconds for `profiles`). When the time is over, the script kills all the processes of the test, and `run.py` boots again for the next tests, because a task that hangs in the kernel can hold a lock that the next tests need. When the kernel does not reach the init script, `run.py` tries 3 times. When the kernel panics or hangs during a test, `run.py` records the result of the test and boots again with the next test. At most 2 batches run at the same time. After each test the init script removes the profiles that are left.

```sh
tools/apparmor/build.sh ~/rkaa
cargo build --release --package rukernel --target x86_64-unknown-none
tools/apparmor/run.py --kernel target/x86_64-unknown-none/release/rukernel --root ~/rkaa/root \
    --out ~/rkaa/runs
```

A test after the options runs only that test, for example `changehat` or `profiles`. A batch that is done does not run again, unless `--force` is given. To run a test again, use a different `--out`, and put the batch directory next to the others with a new number: the report keeps the newest result of each test.

The reference kernel is a Linux kernel with AppArmor built in, as the kernel of a distribution. `--linux` adds `apparmor=1 security=apparmor` to the command line, and `no_timer_check`, because the check of the timer of the IO-APIC can fail under QEMU with no KVM and panic. The batches of a run with `--linux` have the name `ref`. The reference of `report.md` is Linux 6.8.0-147-generic of Ubuntu 24.04:

```sh
tools/apparmor/run.py --linux --kernel /boot/vmlinuz-$(uname -r) --root ~/rkaa/root --out ~/rkaa/runs
```

`--arch aarch64` runs the arm64 kernel on the QEMU `virt` machine, with the root file system of `build.sh --arch aarch64`. Give `--name rk-arm64`, so that the report has the results in the arm64 column. `--bios-dir DIR` gives a directory of the firmware files of QEMU, when QEMU is not in its usual place. `--append` adds arguments to the command line of the kernel.

The results are:

- pass: the test gives 0.
- skip: the test gives 0 and says that it skips its checks, because the kernel or the parser does not have a feature.
- fail: the test gives a different code.
- timeout: the test did not stop in its time limit.
- panic, hang: the kernel panicked, or stopped to give output, during the test.
- exit: QEMU stopped during the test with no panic.
- noboot: the kernel did not start the init script.

In complain mode, the kernel allows what a profile does not allow, and logs it. Thus a check that expects a denial fails, also on Linux. The exit of item 3 of #540 compares the tests of the load and the attach (`LOAD_ATTACH` in `report.py`) with the reference: each of these tests that passes on the reference must pass, and each check of these tests that passes on the reference must pass.

## The runs of report.md

The runs of `report.md` were on a server with no KVM, 11 GB of memory and a load of about 30 from other jobs. Thus QEMU used TCG, and a test was slow: one `apparmor_parser` run took up to 200 seconds. The runs used `--timeout 3600`, `--memory 1G` and `--jobs 2`. Some tests still did not stop in the time limit, on the two kernels. When the memory of the server was full, the OOM killer of the server stopped QEMU, and the test has the result `exit`. A test with `exit`, `hang` or `timeout` ran again with `--jobs 1` where it was necessary. The runs again of `at_secure`, `environ` and `onexec` used `--timeout 10800` and `--memory 768M`, because `at_secure` took 2 to 5 hours.

The report has no arm64 column. On the server, the arm64 root file system of `build.sh --arch aarch64` does not build, because tar of Ubuntu 26.04 gets `ENOSYS` under the qemu-user emulation of the server. The arm64 kernel runs the `apparmor` boot test of rukernel instead.

## How to make the report again

```sh
tools/apparmor/report.py --logs ~/rkaa/runs
```

The report has the newest result of each test for each kernel.

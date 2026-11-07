# nftables

This directory has the files that run tests/shell of the nftables project on rukernel, and the record of the results (#542).

- `build.sh` builds the root file system of the tests in an Alpine container: `nft` of the nftables package of Alpine, the programs that the tests use, and tests/shell of the nftables release with the same version.
- `run.py` runs the tests on rukernel, or on a Linux reference kernel, under QEMU, in batches.
- `report.py` makes `report.md` from the logs of the runs.
- `report.md` has the result of each test on Linux and on rukernel.

## How the tests run

`run.py` makes an initramfs from the root file system of `build.sh`, with the list of the tests of a batch and an init script. Each batch boots the kernel in QEMU. The init script runs the tests one after the other. Each test is one run of `run-tests.sh` of nftables with that test, so `run-tests.sh` runs the test in its own network and mount namespace, and gives the result. The probes of the features of `run-tests.sh` in the first run give the `NFT_TEST_HAVE_*` variables of the next runs. Each test has a time limit of 300 seconds. When the time is over, the script kills all the processes of the test. When the kernel panics or hangs during a test, `run.py` records the result of the test and boots again with the next test. At most 2 batches run at the same time.

```sh
tools/nftables/build.sh ~/rknft
cargo build --release --package rukernel --target x86_64-unknown-none
tools/nftables/run.py --kernel target/x86_64-unknown-none/release/rukernel --root ~/rknft/root \
    --out ~/rknft/runs
```

A test or a directory of tests after the options runs only these tests, for example `testcases/sets`. A batch that is done does not run again, unless `--force` is given. Under QEMU with no KVM, some tests need more than 300 seconds. Run them again with a larger `--timeout` and a different `--out`, and put the batch directory next to the others with a new number: the report keeps the newest result of each test.

The reference kernel is a Linux kernel with nf_tables as modules, as the kernel of a distribution. `--linux-modules` gives the modules of that kernel. `run.py` puts the modules of the network, the libraries and the crypto code, and the drivers of drivers/net, in the initramfs without their zstd compression. The init script runs `depmod`, and `modprobe` of kmod loads a module when the kernel asks for it. The batches of a run with `--linux-modules` have the name `ref`. The reference of `report.md` is Linux 6.8.0-147-generic of Ubuntu 24.04:

```sh
tools/nftables/run.py --kernel /boot/vmlinuz-$(uname -r) --linux-modules /lib/modules/$(uname -r) \
    --root ~/rknft/root --out ~/rknft/runs
```

`--arch aarch64` runs the arm64 kernel on the QEMU `virt` machine, with the root file system of `build.sh --arch aarch64`. Give `--name rk-arm64`, so that the report has the results in the arm64 column. `--bios-dir DIR` gives a directory of the firmware files of QEMU, when QEMU is not in its usual place.

The results are:

- pass: the test gives 0.
- skip: the test gives 77, because the kernel or `nft` does not have a feature that the test needs.
- fail: the test gives a different code.
- dump differs: the rule set after the test is not the same as the dump file of the test.
- timeout: the test did not stop in its time limit.
- panic, hang: the kernel panicked, or stopped to give output, during the test.

## How to make the report again

```sh
tools/nftables/report.py --logs ~/rknft/runs
```

The report has the newest result of each test for each kernel.

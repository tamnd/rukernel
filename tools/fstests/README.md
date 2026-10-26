# fstests

This directory has the files that run fstests on rukernel, and the record of the results.

- `build.sh` builds fstests and a Debian root file system that runs it.
- `tests.txt` has the tests that `cargo xtask boot-test fstests` runs.
- `ext4.md` has the result of each generic and ext4 test on ext4.
- `overlay.md` has the result of each overlay test.
- `notes.txt` has a note for some tests: the missing feature, or the pull request that fixed the test.
- `report.py` makes `ext4.md` and `overlay.md` from the logs of the runs.

## How the tests run

Each run boots the kernel in QEMU with the root file system of `build.sh` as the initramfs. The virtual machine has two virtio disks of 2 GiB, and init makes ext4 on both. The test device is `/dev/vda` on `/test`, and the scratch device is `/dev/vdb` on `/scratch`. Then init runs `./check` with the tests of the run.

The same root file system also boots on a Linux reference kernel. The Linux column of the tables is the result on that kernel. A test that passes on Linux and does not pass on rukernel is work that remains. A test that does not run on Linux is not a goal.

The tests come from the quick group of fstests, in batches. The ext4 tables have 347 tests, and the overlay table has 93 tests.

## Status at 2026-10-26

| Suite | Tests | Pass on Linux | Pass on rukernel | Pass on both | Fail on rukernel | Not run on rukernel | No result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ext4 | 347 | 312 | 212 | 207 | 26 | 97 | 12 |
| overlay | 93 | 61 | 23 | 22 | 14 | 56 | 0 |

The rukernel column of a table has the newest result of each test. Some results are from the batch runs of 2026-10-25, and the changes after that day can change them. The next full run makes the tables new.

## Work that remains

These are the tests that pass on Linux and do not pass on rukernel, in groups by the cause.

### ext4 tests that fail

- generic/256: a full disk leaked the blocks of a write when the extent tree needed a new block. The fix is in progress.
- generic/213, generic/228, generic/260, generic/263, generic/288, generic/294, generic/306, generic/371, generic/394, generic/409, generic/499, generic/511, generic/641, generic/079, generic/087, generic/126, generic/130, ext4/042: the result is from 2026-10-25. Each one needs a new run, and then a fix if it still fails.
- ext4/003: needs bigalloc.
- ext4/023: needs htree directories.
- ext4/308 and generic/018: need `EXT4_IOC_MOVE_EXT`.
- generic/569: needs a reverse map, to write protect the pages of a mapped swap file.
- generic/633: needs io_uring.

### ext4 tests that do not run

- Shutdown of the file system (`EXT4_IOC_SHUTDOWN`): 14 tests, for example generic/417, generic/468 and generic/474.
- ext4 encryption: 9 tests, for example generic/395 and generic/580.
- The fsgqa user cannot run commands: 6 tests, generic/680 and generic/683 to generic/687. This result is from before the credential work. It needs a new run.
- Loop devices: ext4/032, ext4/052 and generic/361.
- `O_TMPFILE`: generic/004, generic/389 and generic/531.
- NFS export, the file handles: generic/426, generic/467 and generic/477.
- fsmap: ext4/027 and ext4/028.
- The libaio engine of fio: generic/095 and generic/366.
- User namespaces and `/proc/PID/uid_map`: generic/317 and generic/318.
- Freeze of the file system: generic/491 and generic/738.
- `mount_setattr`: generic/644 and generic/689.
- Transparent huge pages: generic/759 and generic/760.
- One test for each of these: bigalloc with meta_bg, ea_inode, clearing the extent flag, filename wipe, the journal checkpoint ioctl, `/dev/kmsg`, `fiemap -a`, the file system label, the creation time of an inode, FITRIM, casefold, the `fs.protected_symlinks` and `fs.protected_regular` sysctls, `chattr +x`, delayed allocation, io_uring and ACLs on generic/697.
- No result yet: generic/037, generic/042, generic/050, generic/052, generic/062, generic/067, generic/069, generic/070, generic/071, generic/075, generic/076 and generic/078.

### overlay tests

- The `index` feature: 18 tests, for example overlay/018 and overlay/033.
- The `redirect_dir` feature: 5 tests, for example overlay/017 and overlay/049.
- The `uuid` feature: overlay/081.
- The `lowerdir+` and `datadir+` options: overlay/086.
- `unshare` is not in the root file system: overlay/020.
- 14 tests fail: overlay/004, overlay/012, overlay/022, overlay/023, overlay/024, overlay/026, overlay/028, overlay/035, overlay/038, overlay/066, overlay/075, overlay/078, overlay/083 and overlay/084. overlay/066 also fails on Linux.

## How to make the tables again

Copy the run directories, each with its `log` file, to one directory. The name of a run on the reference kernel starts with `ref-` or `oref-`. Then run the script with the `tests` directory of fstests:

```sh
tools/fstests/report.py --logs RUNS --tests FSTESTS/tests --list BATCH_FILE
```

A `--list` file adds the tests that have no result yet. Write a new line in `notes.txt` when a pull request fixes a test, or when a test needs a feature that rukernel does not have. Then change the status section of this file.

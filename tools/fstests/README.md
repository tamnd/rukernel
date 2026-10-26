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

<!-- report: begin -->

## Status at 2026-10-26

| Suite | Tests | Pass on Linux | Pass on rukernel | Pass on both | Fail on rukernel | Not run on rukernel | No result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ext4 | 347 | 312 | 212 | 207 | 26 | 97 | 12 |
| overlay | 93 | 61 | 23 | 22 | 14 | 56 | 0 |

The rukernel column of a table has the newest result of each test, and the Last run column of the table gives its date. A change after that date can change the result.

## Work that remains

These are the tests that pass on Linux and do not pass on rukernel, in groups by the cause. The cause is the note in notes.txt, or else the reason in the log.

### ext4

- Fail: the output is not the expected output. 14: ext4/042, generic/079, generic/087, generic/126, generic/130, generic/228, generic/288, generic/294, generic/306, generic/371, generic/394, generic/409, generic/499 and generic/511.
- Not run: ext4 does not support shutdown. 14: ext4/051, generic/417, generic/468, generic/474, generic/505, generic/507, generic/508, generic/530, generic/536, generic/599, generic/635, generic/646, generic/737 and generic/794.
- No result yet. 12: generic/037, generic/042, generic/050, generic/052, generic/062, generic/067, generic/069, generic/070, generic/071, generic/075, generic/076 and generic/078.
- Not run: kernel is unaware of ext4 encryption feature, or mkfs options are not compatible with . 9: generic/395, generic/396, generic/580, generic/581, generic/582, generic/592, generic/602, generic/621 and generic/739.
- Not run: fsgqa cannot execute commands. 6: generic/680, generic/683, generic/684, generic/685, generic/686 and generic/687.
- Fail: the test stops with an error. 3: generic/260, generic/263 and generic/641.
- Not run: O_TMPFILE is not supported. 3: generic/004, generic/389 and generic/531.
- Not run: This test requires loopback device support. 3: ext4/032, ext4/052 and generic/361.
- Not run: ext4 does not support NFS export. 3: generic/426, generic/467 and generic/477.
- Fail: Needs EXT4_IOC_MOVE_EXT, the online defragmentation of ext4. 2: ext4/308 and generic/018.
- Not run: This test requires procfs uid_map support. 2: generic/317 and generic/318.
- Not run: ext4 does not support freezing. 2: generic/491 and generic/738.
- Not run: fio engine libaio not available. 2: generic/095 and generic/366.
- Not run: kernel does not support mount_setattr syscall. 2: generic/644 and generic/689.
- Not run: system doesn't support transparent hugepages. 2: generic/759 and generic/760.
- Not run: xfs_io fsmap support is missing. 2: ext4/027 and ext4/028.
- Fail: A full disk leaked the blocks of a write when the extent tree needed a new block. The fix is in progress. 1: generic/256.
- Fail: A write to a mapped swap file must give SIGBUS. This needs a reverse map to write protect the pages. 1: generic/569.
- Fail: Needs bigalloc, the clusters of more than one block. 1: ext4/003.
- Fail: Needs htree directories. 1: ext4/023.
- Fail: Needs io_uring. 1: generic/633.
- Fail: fsck finds an error. 1: generic/213.
- Not run: ACLs not supported by this filesystem type: ext4. 1: generic/697.
- Not run: Clearing extent flag not supported, old chattr and/or kernel. 1: ext4/005.
- Not run: FSTRIM not supported. 1: generic/537.
- Not run: Kernel doesn't support the ext4 feature(s): bigalloc,meta_bg,^resize_inode. 1: ext4/025.
- Not run: Kernel doesn't support the ext4 feature(s): ea_inode. 1: ext4/026.
- Not run: Test requires writable /dev/kmsg. 1: generic/402.
- Not run: ext4 does not support casefold feature. 1: generic/556.
- Not run: filename wipe not supported. 1: ext4/048.
- Not run: fs.protected_regular sysctl unavailable. 1: generic/598.
- Not run: fs.protected_symlinks sysctl unavailable. 1: generic/597.
- Not run: inode creation time not supported by this filesystem. 1: generic/528.
- Not run: journal checkpoint ioctl not present on device. 1: ext4/050.
- Not run: kernel does not support IO_URING. 1: generic/678.
- Not run: test requires delayed allocation buffered writes. 1: generic/614.
- Not run: xfs_io chattr +x failed (old kernel/wrong fs?). 1: generic/607.
- Not run: xfs_io fiemap -a failed (old kernel/wrong fs/bad args?). 1: generic/425.
- Not run: xfs_io label failed (old kernel/wrong fs?). 1: generic/492.
- Not run: xfs_io shutdown failed (old kernel/wrong fs?). 1: generic/623.

### overlay

- Not run: overlay feature 'index' cannot be enabled on /scratch. 18: overlay/018, overlay/033, overlay/034, overlay/036, overlay/037, overlay/042, overlay/047, overlay/048, overlay/050, overlay/051, overlay/052, overlay/053, overlay/054, overlay/055, overlay/068, overlay/069, overlay/073 and overlay/074.
- Fail: the output is not the expected output. 13: overlay/004, overlay/012, overlay/022, overlay/023, overlay/024, overlay/026, overlay/028, overlay/035, overlay/038, overlay/075, overlay/078, overlay/083 and overlay/084.
- Not run: overlay feature 'redirect_dir' cannot be enabled on /scratch. 5: overlay/017, overlay/049, overlay/057, overlay/079 and overlay/085.
- Not run: overlay feature 'uuid' cannot be enabled on /scratch. 1: overlay/081.
- Not run: overlay lowerdir+,datadir+ not supported on /scratch. 1: overlay/086.
- Not run: unshare : command not found, should be in util-linux. 1: overlay/020.

<!-- report: end -->

## How to make the tables again

`update.sh` copies the logs of the runs from the test server and runs `report.py`. The script writes `ext4.md`, `overlay.md` and the status and work sections of this file, so do not change these by hand:

```sh
tools/fstests/update.sh
```

The test server is `server2` by default. Set `RK_FSTESTS_HOST` to use a different server, and `RK_FSTESTS_DIR` to use a different directory on it. The script also copies the `tests` directory of fstests and the batch lists from that server.

`report.py` can also run on logs that are on this computer. The name of a run on the reference kernel starts with `ref-` or `oref-`:

```sh
tools/fstests/report.py --logs RUNS --tests FSTESTS/tests --list BATCH_FILE
```

A `--list` file adds the tests that have no result yet. Write a new line in `notes.txt` when a pull request fixes a test, or when a test needs a feature that rukernel does not have. The note then shows in the tables and gives the group of the test in the work that remains.

# fstests

This directory has the files that run fstests on rukernel, and the record of the results.

- `build.sh` builds fstests and a Debian root file system that runs it.
- `tests.txt` has the tests that `cargo xtask boot-test fstests` runs.
- `ext4.md` has the result of each generic and ext4 test on ext4.
- `overlay.md` has the result of each overlay test.
- `notes.txt` has a note for some tests: the missing feature, or the pull request that fixed the test.
- `linux.txt` has the Linux code that each test checks, as paths in the Linux tree. A key is a test, a part of the cause, a group of fstests or a suite.
- `report.py` makes `ext4.md` and `overlay.md` from the logs of the runs.

## How the tests run

Each run boots the kernel in QEMU with the root file system of `build.sh` as the initramfs. The virtual machine has two virtio disks of 2 GiB, and init makes ext4 on both. The test device is `/dev/vda` on `/test`, and the scratch device is `/dev/vdb` on `/scratch`. Then init runs `./check` with the tests of the run.

The same root file system also boots on a Linux reference kernel. The Linux column of the tables is the result on that kernel. A test that passes on Linux and does not pass on rukernel is work that remains. A test that does not run on Linux is not a goal.

The tests come from the quick group of fstests, in batches. The ext4 tables have 347 tests, and the overlay table has 93 tests.

<!-- report: begin -->

## Status at 2026-10-27

| Suite | Tests | Pass on Linux | Pass on rukernel | Pass on both | Fail on rukernel | Not run on rukernel | No result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ext4 | 369 | 312 | 285 | 275 | 11 | 73 | 0 |
| overlay | 93 | 61 | 52 | 51 | 1 | 40 | 0 |

The rukernel column of a table has the newest result of each test, and the Last run column of the table gives its date. A change after that date can change the result.

## Work that remains

These are the tests that pass on Linux and do not pass on rukernel, in groups by the cause. The cause is the note in notes.txt, or else the reason in the log. Each group links to the code of Linux 7.3 that its tests check.

### ext4

- Not run: kernel is unaware of ext4 encryption feature, or mkfs options are not compatible with . 9: [generic/395](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/395?h=v2026.10.15), [generic/396](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/396?h=v2026.10.15), [generic/580](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/580?h=v2026.10.15), [generic/581](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/581?h=v2026.10.15), [generic/582](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/582?h=v2026.10.15), [generic/592](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/592?h=v2026.10.15), [generic/602](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/602?h=v2026.10.15), [generic/621](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/621?h=v2026.10.15) and [generic/739](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/739?h=v2026.10.15). Linux code: [fs/crypto/](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/crypto/?h=v7.3), [fs/ext4/crypto.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/ext4/crypto.c?h=v7.3).
- Not run: Passes since #271. 3: [generic/426](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/426?h=v2026.10.15), [generic/467](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/467?h=v2026.10.15) and [generic/477](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/477?h=v2026.10.15). Linux code: [fs/exportfs/expfs.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/exportfs/expfs.c?h=v7.3), [fs/fhandle.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/fhandle.c?h=v7.3).
- Fail: Passes since #275. 2: [ext4/308](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/ext4/308?h=v2026.10.15) and [generic/018](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/018?h=v2026.10.15). Linux code: [fs/ext4/move_extent.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/ext4/move_extent.c?h=v7.3).
- Not run: Passes since #273. 2: [ext4/005](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/ext4/005?h=v2026.10.15) and [ext4/048](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/ext4/048?h=v2026.10.15). Linux code: [fs/ext4/inode.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/ext4/inode.c?h=v7.3), [fs/namei.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/namei.c?h=v7.3), [fs/ext4/namei.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/ext4/namei.c?h=v7.3).
- Not run: Passes since #276. 2: [ext4/027](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/ext4/027?h=v2026.10.15) and [ext4/028](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/ext4/028?h=v2026.10.15). Linux code: [fs/ext4/fsmap.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/ext4/fsmap.c?h=v7.3).
- Not run: This test requires procfs uid_map support. 2: [generic/317](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/317?h=v2026.10.15) and [generic/318](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/318?h=v2026.10.15). Linux code: [kernel/user_namespace.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/user_namespace.c?h=v7.3).
- Not run: idmapped mounts not support by ext4. 2: [generic/644](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/644?h=v2026.10.15) and [generic/689](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/689?h=v2026.10.15). Linux code: [fs/mnt_idmapping.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/mnt_idmapping.c?h=v7.3), [fs/namespace.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/namespace.c?h=v7.3).
- Not run: system doesn't support transparent hugepages. 2: [generic/759](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/759?h=v2026.10.15) and [generic/760](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/760?h=v2026.10.15). Linux code: [mm/huge_memory.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/huge_memory.c?h=v7.3).
- Fail: A write to a mapped swap file must give SIGBUS. This needs a reverse map to write protect the pages. 1: [generic/569](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/569?h=v2026.10.15). Linux code: [mm/swapfile.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/swapfile.c?h=v7.3), [mm/rmap.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/rmap.c?h=v7.3).
- Fail: An extend does not zero the tail of the last page (#311). 1: [generic/794](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/794?h=v2026.10.15). Linux code: [fs/ext4/ioctl.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/ext4/ioctl.c?h=v7.3).
- Fail: Needs BLKROSET on the block device (#309). 1: [generic/050](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/050?h=v2026.10.15). Linux code: [fs/ext4/ioctl.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/ext4/ioctl.c?h=v7.3).
- Fail: Needs io_uring. 1: [generic/633](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/633?h=v2026.10.15). Linux code: [io_uring/](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/io_uring/?h=v7.3), [fs/ext4/inode.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/ext4/inode.c?h=v7.3).
- Fail: Passes since #274. 1: [generic/641](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/641?h=v2026.10.15). Linux code: [mm/swapfile.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/swapfile.c?h=v7.3).
- Fail: Passes since #285. 1: [generic/130](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/130?h=v2026.10.15). Linux code: [fs/ext4/](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/ext4/?h=v7.3).
- Fail: The orphan list is not processed after a shutdown (#310). 1: [generic/417](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/417?h=v2026.10.15). Linux code: [fs/ext4/ioctl.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/ext4/ioctl.c?h=v7.3).
- Fail: The size update of an O_SYNC direct write is not in the journal (#310). 1: [generic/737](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/737?h=v2026.10.15). Linux code: [fs/ext4/ioctl.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/ext4/ioctl.c?h=v7.3).
- Not run: Passes since #277. 1: [ext4/052](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/ext4/052?h=v2026.10.15). Linux code: [fs/namei.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/namei.c?h=v7.3), [fs/ext4/namei.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/ext4/namei.c?h=v7.3).
- Not run: Passes since #280. 1: [ext4/025](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/ext4/025?h=v2026.10.15). Linux code: [fs/ext4/](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/ext4/?h=v7.3).
- Not run: The test hangs (#308). 1: [generic/507](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/507?h=v2026.10.15). Linux code: [fs/ext4/ioctl.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/ext4/ioctl.c?h=v7.3).
- Not run: ext4 does not support casefold feature. 1: [generic/556](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/556?h=v2026.10.15). Linux code: [fs/unicode/](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/unicode/?h=v7.3), [fs/ext4/namei.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/ext4/namei.c?h=v7.3).
- Not run: kernel does not support IO_URING. 1: [generic/678](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/generic/678?h=v2026.10.15). Linux code: [io_uring/](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/io_uring/?h=v7.3).

### overlay

- Not run: Needs nfs_export (#306). 9: [overlay/050](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/overlay/050?h=v2026.10.15), [overlay/051](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/overlay/051?h=v2026.10.15), [overlay/052](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/overlay/052?h=v2026.10.15), [overlay/053](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/overlay/053?h=v2026.10.15), [overlay/054](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/overlay/054?h=v2026.10.15), [overlay/055](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/overlay/055?h=v2026.10.15), [overlay/068](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/overlay/068?h=v2026.10.15), [overlay/069](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/overlay/069?h=v2026.10.15) and [overlay/074](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/overlay/074?h=v2026.10.15). Linux code: [fs/exportfs/expfs.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/exportfs/expfs.c?h=v7.3), [fs/fhandle.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/fhandle.c?h=v7.3).
- Not run: unshare : command not found, should be in util-linux. 1: [overlay/020](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/tree/tests/overlay/020?h=v2026.10.15). Linux code: [fs/overlayfs/copy_up.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/overlayfs/copy_up.c?h=v7.3).

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

Each test links to its file in fstests at the tag of `build.sh`. Each test and each group of the work that remains also links to the code of the reference kernel, Linux 7.3, from `linux.txt`. The version comes from `tools/rk-abigen`. If the Linux tarball of `rk-abigen` is in its cache, `report.py` stops when a path of `linux.txt` is not in that version, so a new version cannot leave a broken link. When a test links to the wrong code, change `linux.txt`.

A `--list` file adds the tests that have no result yet. Write a new line in `notes.txt` when a pull request fixes a test, or when a test needs a feature that rukernel does not have. The note then shows in the tables and gives the group of the test in the work that remains.

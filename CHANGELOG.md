# Changelog

This file records each release. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The version numbers follow [Semantic Versioning](https://semver.org/).

## Unreleased

### Fixed

- A second mount of a block device that has a mounted file system of the same type now gives the same file system, as the super blocks of Linux. Before this change, each mount read the disk again, and the two mounts did not see the changes of the other. A mount that would change the read only state of the file system gives `EBUSY`, as Linux.

## [0.3.15] - 2026-10-26

### Added

- The semaphores of System V: `semget`, `semop`, `semtimedop` and `semctl`. `semop` does all its operations or none of them, and waits until a change of the set lets them go on. A signal stops the wait with `EINTR`. An operation with `SEM_UNDO` records the opposite change, and the kernel does it when the process ends. The t_ofd_locks program of generic/478 uses these calls, and generic/478 now passes.
- `renameat2` with `RENAME_EXCHANGE` on tmpfs and ext4. The two names exchange their files, which can have different types. A directory that moves to the other parent gets a new `..`, and the link counts of the parents change. A file system without the flag gives `EINVAL`, as Linux. generic/025 passes.
- `swapon` and `swapoff`. `swapon` reads the header of `mkswap` and makes sure that each page of a swap file has a block on the disk, as Linux. A file with holes gives `EINVAL`. While a file is an active swap area, a write, a truncate, a `fallocate`, a `copy_file_range` and a shared writable mapping of the file give `ETXTBSY`. `/proc/swaps`, `/proc/meminfo` and `sysinfo` show the active areas. rukernel does not move pages to a swap area yet.

### Fixed

- A link of `/proc/PID/fd` is now a magic link, as Linux. A walk that follows it goes to the open file and does not read the target as a path. An open through the link of a pipe gives a new end of the same pipe, and an open through the link of a file without a name gives the file. Before this change, bash could not use `<(...)` and `>(...)`, because the open of `/dev/fd/63` gave `ENOENT`.
- ext4 keeps the inode before each orphan in memory, as Linux. Before this change, the close of an open file without links walked the list of orphans from its head, so a process that closed many such files used time that grew as the square of their count.
- `copy_file_range` checks the types of the files before their modes, as `generic_file_rw_checks` of Linux. A copy to a device or a fifo that is open with `O_APPEND` now gives `EINVAL`, not `EBADF`. generic/434 passes.
- The descriptor table of a process now follows its soft `RLIMIT_NOFILE`, as Linux. Before this change, a process could not open more than 1024 files after a higher `setrlimit`. `poll` and `select` also use the soft limit. generic/488 passes.

## [0.3.14] - 2026-10-26

### Added

- `preadv`, `pwritev`, `preadv2` and `pwritev2`. An offset of -1 for `preadv2` and `pwritev2` uses the position of the file. `RWF_APPEND` writes at the end, and `RWF_DSYNC` and `RWF_SYNC` sync the file after the write. `RWF_ATOMIC` and `RWF_DONTCACHE` give `EOPNOTSUPP`, because no file system of rukernel has them. fsx uses these calls, so generic/091, generic/263 and generic/469 now pass.
- ext4 makes the extra fields of an inode larger when it changes the inode and the inode has less than `s_want_extra_isize`, as Linux. The attributes that then do not fit in the inode move to its attribute block. If the block has no room, the driver tries `s_min_extra_isize`, and else the inode keeps its size. A new inode gets the size that `ext4_clamp_want_extra_isize` gives. ext4/022 passes.

### Fixed

- A file mapping now sees a `write`, a truncate and a `fallocate` of the file at once, and a `read` sees the changes of a shared mapping, as the page cache of Linux gives. Before this change, a mapping kept its old copy of a page until the last mapping went. generic/428 passes.
- An ext4 mount no longer frees a reserved inode, an inode past the end, or an inode that is not in use when `s_last_orphan` points to it. As Linux, such an inode ends the list of orphans and stays as it is. ext4/038 passes.

## [0.3.13] - 2026-10-26

### Added

- ext4 grows a mounted file system with `EXT4_IOC_RESIZE_FS`, which resize2fs uses for an online resize. The last group gets the new blocks up to its end, and each new group gets its bitmaps and its inode table after its copy of the superblock and of the descriptors. The resize inode maps the reserved descriptor blocks of each new group with a copy. The descriptors of the new groups must fit in the blocks of descriptors that the disk has.
- A mount claims its block device. An `O_EXCL` open of a mounted block device gives `EBUSY`, and a mount of a device that a file has open with `O_EXCL` gives `EBUSY`, as Linux. e2fsprogs use this to find that a disk is mounted.
- ext4 mounts a disk with `meta_bg`, which mkfs uses when the group descriptors do not fit after the superblock, for example with `-g 256`. Each meta block group keeps its block of descriptors in its first group, and the bitmap of a new group and `statfs` count those blocks. ext4/058 passes.
- ext4 writes and truncates the files that have a block map, as ext2 and ext3 keep them. A write to a hole gets new blocks and the indirect blocks that the map needs, and a truncate frees the blocks past the size and the indirect blocks that then map nothing. A disk without the `extents` feature mounts for read and write, and its new files have a block map. ext4/044 passes.

## [0.3.12] - 2026-10-26

### Added

- The files `dirty_ratio`, `dirty_background_ratio`, `dirty_bytes`, `dirty_background_bytes`, `dirty_expire_centisecs` and `dirty_writeback_centisecs` in `/proc/sys/vm`. They keep the value that a program writes, but the writeback does not use them yet. generic/460 needs them.
- The `FS_IOC_GOINGDOWN` ioctl on ext4, as `EXT4_IOC_SHUTDOWN` of Linux. After it, a change, a read of the data of a file and `fsync` give `EIO`, and nothing goes to the disk again. The unmount leaves the journal, so the next mount replays it as after a crash. `LOGFLUSH` and the default flags first make the changes durable, and `NOLOGFLUSH` loses the changes since the last commit. The fstests that need `_require_scratch_shutdown` can run now.
- `chattr +e` and `chattr -e` on ext4. `+e` moves a file or a directory from a block map to an extent tree, and the tree uses the indirect blocks of the map first. `-e` moves a file to a block map, as Linux, only if the tree has at most one extent that has data and fits in the 12 direct blocks. ext4/005 needs it.
- The ext4 mount options `minixdf` and `bsddf`. With `minixdf`, `statfs` counts the blocks of the metadata and of the journal in the count of blocks, as Linux. ext4/042 checks it.
- The `EXT4_IOC_CHECKPOINT` ioctl. It writes the transactions of the journal to their places and empties the journal. With `EXT4_IOC_CHECKPOINT_FLAG_ZEROOUT` it then writes zeros to the blocks of the log. `EXT4_IOC_CHECKPOINT_FLAG_DISCARD` gives `EOPNOTSUPP`, as the disk does not discard. ext4/050 checks it.
- Each process has credentials: the real, effective, saved and file system user and group IDs, the supplementary groups, and the five capability sets with the securebits. A fork copies them. init is root with all the capabilities.
- `setuid`, `setgid`, `setreuid`, `setregid`, `setresuid`, `setresgid`, `setfsuid`, `setfsgid` and `setgroups` change the credentials with the rules of Linux. A process that leaves root loses its capabilities, unless it set `PR_SET_KEEPCAPS`. `getgroups` gives the groups.
- `capset` changes the capability sets. The `prctl` options `PR_CAPBSET_READ`, `PR_CAPBSET_DROP`, `PR_GET_KEEPCAPS`, `PR_SET_KEEPCAPS`, `PR_GET_SECUREBITS`, `PR_SET_SECUREBITS` and `PR_CAP_AMBIENT` work.
- An `execve` of a set-user-ID or set-group-ID file changes the effective ID, and an `execve` computes the new capability sets as Linux does for a file without file capabilities. The bits have no effect on a `nosuid` mount, with no_new_privs, or under a tracer. The auxiliary vector gives the IDs and `AT_SECURE`.
- `/proc/PID/status` shows the IDs, the groups, the capability sets and the no_new_privs bit.
- The VFS checks the permission bits with the credentials of the process, as `generic_permission` of Linux. A walk needs the search permission on each directory. `open`, `access`, `faccessat2`, `truncate`, `chdir`, `fchdir` and `execve` check the access to the file. A create, a link, a remove and a rename need the write and search permissions on the directory. `CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH` skip the checks.
- In a sticky directory, only the owner of a file, the owner of the directory or a process with `CAP_FOWNER` can remove or rename the file.
- A new file gets the file system user ID of the process as its owner. Its group is the group of the process, or the group of the directory if the directory is set-group-ID. A new directory in a set-group-ID directory is set-group-ID too.
- `mknod` of a character or block device needs `CAP_MKNOD`. `O_NOATIME` needs the owner of the file or `CAP_FOWNER`.
- `chmod`, `chown` and `utimensat` check the owner rules of Linux. Only the owner or a process with `CAP_FOWNER` can change the mode or set a time that is not now. Only a process with `CAP_CHOWN` can give a file to another user, and the owner can only give it to a group that it is in. To set both times to now, the process must be the owner or be able to write the file.
- `chmod` clears the set-group-ID bit if the process is not in the group of the file and has no `CAP_FSETID`. `chown` of a file that is not a directory clears the set-user-ID bit, and the set-group-ID bit if the group can run the file.
- A write, a truncate or an `fallocate` of a regular file by a process without `CAP_FSETID` clears the set-user-ID bit, and the set-group-ID bit if the group can run the file.
- The `trusted.` extended attributes need `CAP_SYS_ADMIN`, and `listxattr` hides them from other processes. A `user.` attribute needs the read or the write permission on the file, and in a sticky directory only the owner can change one.
- `kill`, `tkill`, `tgkill`, `rt_sigqueueinfo` and `rt_tgsigqueueinfo` need the same user as the target or `CAP_KILL`, as `check_kill_permission` of Linux. A process can always send `SIGCONT` in its session. `kill` of a group or of all processes skips the processes that the caller cannot signal.
- `PTRACE_ATTACH` and `PTRACE_SEIZE` need the same IDs as the target and its permitted capabilities, or `CAP_SYS_PTRACE`. `PTRACE_O_SUSPEND_SECCOMP` needs `CAP_SYS_ADMIN`.
- `prlimit64` and `setrlimit` need `CAP_SYS_RESOURCE` to raise a hard limit, and `prlimit64` on another process needs the same IDs. `setpriority` needs `CAP_SYS_NICE` to change a process of another user or to go below the nice value that `RLIMIT_NICE` allows. `PRIO_USER` selects the processes of the user.
- `mount`, `umount2`, `fsopen`, `fspick`, `fsmount`, `move_mount` and `open_tree` with `OPEN_TREE_CLONE` need `CAP_SYS_ADMIN`. The `syslog` actions other than the full read and the size need `CAP_SYSLOG` or `CAP_SYS_ADMIN`.
- POSIX ACLs in the `system.posix_acl_access` and `system.posix_acl_default` extended attributes. The permission check uses the named user and group entries and the mask, as Linux. A set of the access ACL changes the mode, and `chmod` changes the ACL. A new file or directory gets the default ACL of its directory in place of the umask, and a new directory also gets it as its default ACL. Only the owner or a process with `CAP_FOWNER` can set an ACL. ext4 keeps the ACLs in the format of Linux on the disk.

### Fixed

- An ext4 disk with a block size larger than 4096 does not mount and gives `EINVAL`, as Linux on a page size of 4096. Before, the mount gave `EROFS`, so `mount` tried again read-only, and generic/466 could not write to the disk.
- `lseek` with `SEEK_DATA` and `SEEK_HOLE` finds the holes of a file from its extents, on ext4 and on an overlay over ext4. An unwritten extent is a hole. Before, all the file was data, and generic/448 did not run.
- `sync_file_range` is a system call. It checks its arguments like Linux and syncs all the file when a flag is set. Before, it gave ENOSYS, and generic/285 stopped at its eighth test.

## [0.3.11] - 2026-10-25

### Added

- The `FS_IOC_FSGETXATTR` and `FS_IOC_FSSETXATTR` ioctls. They give and change the inode flags as the `FS_XFLAG_*` flags, as `xfs_io` uses them. A project id other than 0 gives `EOPNOTSUPP`, and an extent size hint gives `EINVAL`.
- The `FIBMAP` and `FIGETBSZ` ioctls. `FIBMAP` gives the block of the disk of a block of a file on ext4, and 0 for a hole. generic/519 needs it.
- `statx` gives the compressed, immutable, append-only and nodump attributes in `stx_attributes`, from the inode flags. generic/424 checks them.

### Fixed

- `utimensat` with a time that is not the time now gives `EPERM` on an append-only file, as Linux. generic/079 checks it.

## [0.3.10] - 2026-10-25

### Added

- The `FS_IOC_GETFLAGS` and `FS_IOC_SETFLAGS` ioctls, as `lsattr` and `chattr` use them. ext4 keeps the flags in the inode, and tmpfs keeps the immutable, append-only, nodump and noatime flags. overlayfs copies the file up before it sets the flags. An immutable file refuses a write, a truncate, a change of its attributes or extended attributes, a link and an unlink, and an immutable directory refuses a new entry. An append-only file accepts only an open with `O_APPEND`, and `fcntl` cannot clear `O_APPEND` on it.
- `FALLOC_FL_COLLAPSE_RANGE` and `FALLOC_FL_INSERT_RANGE` on ext4. A collapse frees the blocks of the range and moves the blocks after it down. An insert moves the blocks after the offset up and leaves a hole. The offset and the length must be multiples of the block size. Many fstests need `fcollapse` or `finsert` of xfs_io, and did not run before.

## [0.3.9] - 2026-10-25

### Added

- Advisory file locks. `fcntl` takes POSIX record locks (`F_GETLK`, `F_SETLK`, `F_SETLKW`) and open file description locks (`F_OFD_GETLK`, `F_OFD_SETLK`, `F_OFD_SETLKW`), and the new `flock(2)` call locks a full file. A POSIX lock belongs to the descriptor table, and a close of any descriptor of the file releases it. An OFD lock and a `flock` lock belong to the open file, and go away when its last descriptor closes. `F_SETLKW` finds a wait that never ends and gives `EDEADLK`. Before, each lock command gave 0 and did nothing.
- `fallocate(2)`. ext4 gives new blocks as extents that are not initialized, so they read as zeros. `FALLOC_FL_KEEP_SIZE`, `FALLOC_FL_PUNCH_HOLE` and `FALLOC_FL_ZERO_RANGE` work on ext4 and tmpfs, and overlayfs passes the call to the upper file. The other modes give `EOPNOTSUPP`. Many fstests need `falloc`, `fpunch` or `fzero` of xfs_io, and did not run before.
- The `FS_IOC_FIEMAP` ioctl. ext4 gives the extents of a file, and marks the extents that are not initialized as unwritten. A file with a block map gives each run of blocks as one extent. overlayfs passes the call to the real file. Only `FIEMAP_FLAG_SYNC` is accepted. Many fstests use `fiemap` of xfs_io, and did not run before.
- `/proc/sys/vm/drop_caches`. A write removes the clean pages of the block devices from the cache. The file reads as 0.

### Fixed

- On ext4, a truncate to the same size frees the blocks past the end of the file that `fallocate` gave with `FALLOC_FL_KEEP_SIZE`, as Linux. generic/092 checks it.

## [0.3.8] - 2026-10-25

### Added

- `syslog(2)` and a kernel log. The text of the kernel goes to a ring of 64 KiB, and each line starts with the level and the time since boot, as on Linux. `dmesg` reads it with `syslog(2)`. The actions that change the console log level do nothing.
- The `fstests` boot test makes `/dev/fd` and an ext4 file system on the scratch disk, so the overlay tests can run with `RK_FSTESTS_TESTS="-overlay ..."`.
- `membarrier(2)`, with the global, the private and the `SYNC_CORE` commands, their registrations, and `MEMBARRIER_CMD_GET_REGISTRATIONS`. Each command interrupts each other CPU. liburcu needs it, and mkfs.xfs uses liburcu.
- XFS, in the new crate `rk-fs-xfs`. The driver can only read. It reads the inodes, the extent lists and the extent trees, the short form directories and the data blocks of the larger directories, and the symbolic links, of version 4 and version 5 file systems. A read and write mount gives `EROFS`. The log is not replayed. tools/debug/build.sh adds xfsprogs, and the alpine boot test makes an XFS file system from a tree with `mkfs.xfs -p`, and compares the files with the tree.
- The `fstests` boot test shows the output of `check` while the tests run. `RK_FSTESTS_TIMEOUT` gives a shorter time limit, and `RK_FSTESTS_WATCH` shows the state and the system call of each process each minute after a time, to find a test that hangs.

### Fixed

- `lseek` takes `SEEK_DATA` and `SEEK_HOLE`, with the generic rules of Linux: all the file is data, and the end of the file is the only hole. mkfs.xfs uses them to copy the files of a tree.
- A block device takes `BLKALIGNOFF`, `BLKGETDISKSEQ`, `BLKBSZGET` and `BLKBSZSET`. libblkid needs all its topology ioctls, and without them mkfs.xfs found a sector size of 0. mkfs.xfs sets the block size of the device before it writes.
- The boot tests of a root file system can take 300 seconds. The alpine test took more than 120 seconds on a busy host.
- `splice` and `sendfile` into a pipe write only the data that fits in the pipe, as Linux. Before, a copy that was larger than the free space waited for a reader, and fsstress hung when it spliced a file into its own pipe. This stopped generic/013 and overlay/019.

## [0.3.7] - 2026-10-25

### Added

- Extended attributes: `setxattr`, `getxattr`, `listxattr` and `removexattr`, with the `l` and `f` forms. The `Inode` trait gets `get_xattr`, `set_xattr`, `list_xattr` and `remove_xattr`, and tmpfs keeps the attributes in memory. The calls take the `user.`, `trusted.` and `security.` namespaces, and check the names, the sizes and the flags as Linux. A `user.` attribute is only for a regular file, a directory or a socket, as Linux 6.17.
- Named FIFOs. An open of a FIFO for read or for write waits until the other end opens, and `O_RDWR` does not wait. An open for write with `O_NONBLOCK` and no reader gives `ENXIO`. All opens of one FIFO share one pipe.
- overlayfs, in the new crate `rk-fs-overlay`. A mount joins the lower directories of `lowerdir=` and the upper directory of `upperdir=`. The first change of a lower file copies it up, a removal makes a whiteout, and a new directory over a removed one is opaque. A mount without `upperdir=` is read only. A rename of a lower directory gives `EXDEV`, as Linux without `redirect_dir`. `MountArgs` gets `lookup`, so a file system type can find the paths of its options.
- ext4 keeps extended attributes, in the inode and in one block, in the format of Linux. A change writes all the attributes again: the attributes that fit stay in the inode and the others go to the block. A block that other inodes share is copied before a change. The removal of the last attribute in a block or of the file frees the block. The `user.`, `trusted.`, `security.` and `system.` namespaces are supported. The alpine boot test sets attributes on the test disk and checks them with `debugfs` and `e2fsck`.
- tools/ltp/build.sh builds the LTP tests of the xattr calls, `sendfile`, `splice`, `copy_file_range` and `posix_fadvise`. 55 of them pass and go in tools/ltp/tests.txt.

## [0.3.6] - 2026-10-25

### Added

- `sendfile`, `splice`, `copy_file_range` and `fadvise64`. The copy calls copy through a buffer in the kernel. `splice` needs a pipe on one side, as Linux. `fadvise64` checks its arguments and does nothing else. GNU grep uses `splice` to empty a pipe into `/dev/null`, and it failed with `ENOSYS` in fstests before this change.
- A read updates the access time of a file, and `getdents64` updates the access time of a directory, with the rules of Linux. A mount is relatime by default, and `noatime`, `nodiratime`, `strictatime`, a read only mount and `O_NOATIME` change the update. A remount without an atime flag keeps the atime flags of the mount. The `Inode` trait gets `set_atime`, which does not change the change time.
- sysfs, in the new crate `rk-fs-sys`. It shows each device in `/sys/devices/virtual/CLASS/NAME` with the files `dev` and `uevent`, and a block device also has `size`, `ro` and `removable`. `/sys/class`, `/sys/block` and `/sys/dev` have links to these directories, as on Linux. BusyBox `mdev -s` makes the device files from it.
- tools/debug/build.sh installs eudev. The alpine boot test checks the output of `udevadm info` for the test disk.
- devtmpfs. Each mount shows one tmpfs that has a device file for each device of the kernel.
- The kernel keeps a list of its devices with their names and classes in `rk_vfs::device`. A block device goes in the list when its driver adds it. The kernel makes `/dev` of the initramfs, devtmpfs and sysfs from this list.
- The `fstests` boot test prints the diff and the end of the full log of each test that fails.

### Fixed

- `rk-fs-ext4` added the blocks of the extent tree to `i_blocks` again each time it wrote the tree, so `e2fsck` found a wrong `i_blocks` after generic/013 of fstests.

## [0.3.5] - 2026-10-25

### Added

- The `fstests` boot test runs fstests on ext4. tools/fstests/build.sh builds fstests and a Debian root file system for it in a container, and tools/fstests/tests.txt gives the tests that the boot test runs. The test makes ext4 on a test disk and gives a second disk as the scratch disk. The boot test runs only when target/fstests or `RK_FSTESTS` has the root file system.
- `/proc/PID/mountinfo`, with the fields of Linux. fstests and `findmnt` read it.
- `statfs` and `fstatfs` give the block and inode counts of an ext4 file system, and the mount flags of the path as the `ST_*` flags. The `Inode` trait gets `fs_stat` for the counts.
- The new mount API: `fsopen`, `fsconfig`, `fsmount`, `fspick`, `move_mount` and `open_tree`. A file system context is a file that keeps the options of `fsconfig`. `fsmount` and `open_tree` with `OPEN_TREE_CLONE` give a mount that is not attached, and `move_mount` attaches it. `move_mount` also moves an attached mount, and puts a mount below another mount with `MOVE_MOUNT_BENEATH`. `mount` with `MS_MOVE` moves a mount. The 14 LTP tests of these calls pass.
- The `ltp` boot test gives the tests a disk in `LTP_DEV`, for the tests that need a device.
- rk-abigen generates the flags of the new mount API, and the values of an `enum` of the uAPI, as `FSCONFIG_SET_FLAG`.
- A fault of the kernel prints a call trace: the addresses in the kernel code that are on the stack, as the `?` entries of Linux.
- `RK_BOOT_LOG` tells `cargo xtask boot-test` to print the full log of a test that passes.
- The kernel reads the real time clock of the CMOS memory at boot on x86-64, as `mc146818_get_time` of Linux. `CLOCK_REALTIME`, `CLOCK_REALTIME_COARSE`, `CLOCK_TAI`, `gettimeofday`, `time`, the vDSO and the file times count from that time. Before this change, the real time started at 1970 at boot.
- An absolute time of a real time clock in `clock_nanosleep`, `timer_settime`, `timerfd_settime` and `futex` changes to the time since boot. `FUTEX_LOCK_PI` uses `CLOCK_REALTIME`, and `FUTEX_WAIT_BITSET` and `FUTEX_LOCK_PI2` use it with `FUTEX_CLOCK_REALTIME`, as Linux.

### Fixed

- `e2fsck` reported the orphan list of an ext4 disk as corrupt after generic/001 of fstests. The deletion time of a freed inode was a few seconds after 1970, smaller than the inode count, so e2fsck read it as a link of the orphan list.
- A chain of symbolic links caused a stack overflow of the kernel in fstests. The path walk called itself for each link, and 40 links used more than the 32 KiB of the kernel stack in a debug build. The walk is now a loop.

## [0.3.4] - 2026-10-25

### Added

- `rk-fs-ext4` replays the jbd2 journal at mount, as `jbd2_journal_recover` of Linux. It supports the revoke records, 64 bit block numbers, and the checksums of `CSUM_V2` and `CSUM_V3`. A transaction with a bad commit block ends the log, and a copy with a bad checksum is not written. A read only mount also replays the journal. Then the driver marks the journal empty and clears `needs_recovery`.
- `rk-fs-ext4` writes the jbd2 journal. The metadata blocks of each change go to the log in one transaction, with the descriptor, revoke and commit blocks and the checksums of `CSUM_V2` and `CSUM_V3`. When the transaction is durable, the blocks go to their places. The data of regular files does not go to the log, as `data=writeback`. A mount sets `needs_recovery`, and an unmount does a checkpoint, marks the log empty, and clears `needs_recovery`. After a crash, the next mount replays the log, so the disk stays consistent.
- `rk-fs-ext4` collects the changes in one transaction for up to 5 seconds, or until the transaction is a quarter of the log, as the `commit=5` default of Linux. `fsync`, `sync`, `syncfs` and unmount commit at once. A block that a change frees is not used again before the commit.
- `rk-fs-ext4` keeps the list of orphans in `s_last_orphan`, as Linux. An inode that loses its last link while a process uses it goes on the list in the same change. A read and write mount frees the orphans that a crash left.
- The `Inode` trait gets `sync`, which `fsync`, `fdatasync`, `sync` and `syncfs` call.
- The `Disk` trait of `rk-fs-ext4` gets `write_back` and `flush`, and `DiskCache` gets `flush`, so a file system can make a write durable before the next one.
- The `alpine` boot test copies the ext4 disk while it is mounted read and write, and checks that `e2fsck` replays the journal of the copy and finds no error. The test disk uses `cache=unsafe` in QEMU, because a flush on the host is slow and the disk is new for each run.
- tools/debug/build.sh adds e2fsprogs-extra, which has debugfs, dumpe2fs and tune2fs. The `alpine` boot test writes a transaction with debugfs, mounts the disk, and checks that the kernel replayed it.

## [0.3.3] - 2026-10-25

### Added

- The new crate `rk-fs-ext4` mounts ext4, ext3 and ext2 read only. It reads the superblock, the group descriptors, the inode tables, the extent trees, the block maps and the directories through the page cache of the disk. A change gives `EROFS`. The driver does not replay the journal yet, and it does not check the checksums.
- `mount` gives the device number and the `MS_RDONLY` flag to a file system that needs a block device. It gives `ENOTBLK` if the source is not a block device.
- The extended attribute calls. No file system keeps extended attributes yet, so a list is empty, a read or a removal gives `ENODATA`, and a change gives `EOPNOTSUPP`.
- tools/debug/build.sh adds e2fsprogs. The `alpine` boot test makes an ext4 file system with `mkfs.ext4 -d` on a second disk, mounts it read only, and compares the tree with `diff -r`.
- `rk-fs-ext4` writes ext4. It creates, writes, truncates, links, renames and removes files, directories, symbolic links and device files. It allocates blocks and inodes from the bitmaps, makes the bitmaps of the groups with `BLOCK_UNINIT` and `INODE_UNINIT`, builds the extent trees again, and writes the checksums of `metadata_csum` and `uninit_bg`. An inode without a link stays until its last user closes it. The driver does not write the journal yet, so a crash can leave errors that fsck must repair. A disk with a feature that the driver cannot change, with a journal to replay, or with blocks larger than 4 KiB mounts read only.
- The `alpine` boot test mounts the ext4 disk read and write, changes files and directories, and then checks the disk with `e2fsck -fn`.

### Fixed

- `lchown` changes the symbolic link and not its target.

## [0.3.2] - 2026-10-25

### Added

- The new crate `rk-block` holds the block layer. Each disk has a request queue. The queue merges the bios that touch, and the mq-deadline scheduler sorts the requests by sector and sends them in batches, with a deadline of 500 ms for a read and 5 s for a write.
- Each queue starts with the mq-deadline scheduler. The other scheduler is `none`. A file in `/sys/block` to change the scheduler comes with sysfs.
- The asynchronous I/O calls `io_setup`, `io_destroy`, `io_submit`, `io_cancel`, `io_getevents` and `io_pgetevents`. `io_submit` supports `IOCB_CMD_PREAD`, `IOCB_CMD_PWRITE`, `IOCB_CMD_PREADV`, `IOCB_CMD_PWRITEV`, `IOCB_CMD_FSYNC` and `IOCB_CMD_FDSYNC`, and `IOCB_FLAG_RESFD`. The reads and the writes of one block device in a call go to the block layer as one batch.
- The shared memory of System V: `shmget`, `shmat`, `shmdt` and `shmctl` with `IPC_STAT`, `IPC_SET`, `IPC_RMID`, `IPC_INFO`, `SHM_INFO`, `SHM_STAT`, `SHM_LOCK` and `SHM_UNLOCK`.
- tools/debug/build.sh adds fio. The `alpine` boot test runs fio with libaio and `--verify=crc32c` on a virtio-blk disk.
- The page cache in `rk-block`. It keeps the data in folios of up to 64 KiB, and each page of a folio is up to date or dirty on its own. A read fills all of its folio in one batch. A write of a whole page does not read the page. The dirty pages go to the disk on `sync`, `syncfs`, `fsync`, `BLKFLSBUF`, and when the dirty data is above 4 MiB. When the cache holds more than 32 MiB, it drops the clean folios that were used least recently.
- A block device file reads and writes through the page cache. A file with `O_DIRECT` goes to the request queue, and it first writes the dirty pages of its range to the disk.
- `sync` and `syncfs` write the dirty pages of each disk.
- The `blk` boot test writes 512 KiB through the page cache, calls `sync`, and then checks the data on the host.

## [0.3.1] - 2026-10-25

### Added

- A virtio-blk driver in the new crate `rk-drv-virtio`. It uses the modern virtio PCI transport and one split virtqueue, and it waits for each request in a loop. Each disk is a block device `/dev/vda`, `/dev/vdb` and so on, with the major number 254.
- rk-frame finds the PCI devices through the configuration ports, and maps the memory BARs of a device.
- A block device file supports `read`, `write`, `pread`, `pwrite`, `lseek` with `SEEK_END`, and the `ioctl` calls `BLKGETSIZE`, `BLKGETSIZE64`, `BLKSSZGET`, `BLKPBSZGET`, `BLKIOMIN`, `BLKIOOPT`, `BLKROGET` and `BLKFLSBUF`.
- `fsync` and `fdatasync` send a flush to the disk of a block device file.
- The `blk` boot test starts QEMU with a disk of 1 MiB, reads and writes the disk in the guest, and then checks the data on the host.

## [0.3.0] - 2026-10-25

### Added

- The `gvisor` boot test runs 20 Unix socket test programs of the gVisor test suite. `tools/gvisor/build.sh` builds them in Docker without Bazel, and `RK_GVISOR` sets their directory. A few tests need user namespaces, network namespaces, PID namespaces or capabilities, and the boot test does not run them until R5.
- `setsockopt` and `getsockopt` accept `SO_NO_CHECK`.
- The network device calls of `ioctl`, as `SIOCGIFINDEX`, give `ENODEV` on a socket, because there is no network device yet.

### Changed

- `fork` does not write protect a page again when it is read only already. A process that forks many times is much faster.

### Fixed

- A Unix socket message gets the credentials of the sender only when the sender gives them, or when the sender or the receiver has `SO_PASSCRED`, as in Linux. A message without credentials gives the pid 0 and the IDs 65534 to a receiver with `SO_PASSCRED`. A stream receive does not join the data of messages with different credentials.
- A socket from `accept` gets `SO_PASSCRED` of the listener. `SO_PEERCRED` gives the credentials of the caller after `listen`, and the pid 0 and the IDs -1 before a connection.
- A stream receive of 0 bytes waits for data, or gives `EAGAIN` without a wait. If data is there, it takes the files of the first message and leaves the data.
- `recvmmsg` stops when its time out is over after a message, and writes the time that is left, as Linux does.
- An edge triggered epoll entry on a Unix socket sees each new message, also when the socket is readable already.
- An open of a socket through `/proc/PID/fd` gives `ENXIO`, as in Linux.

## [0.2.6] - 2026-10-24

### Added

- `/proc/PID/stat` gives the resident set size, and `/proc/PID/statm` gives the resident, shared, text and data sizes. The `cpu` lines of `/proc/stat` give the user time and the idle time.
- The `alpine` boot test checks the values that `ps`, `top` and `pgrep` of BusyBox show. With the tools of `tools/debug/build.sh`, it also checks `ps`, `top`, `pgrep` and `pidof` of procps-ng.
- The scheduler uses EEVDF, as Linux does. Each task gets a share of the CPU from its weight, and the task with the earliest virtual deadline runs first. The time of the scheduler comes from the TSC.
- `getpriority`, `setpriority`, `sched_setscheduler`, `sched_getscheduler`, `sched_setparam`, `sched_getparam`, `sched_setattr`, `sched_getattr`, `sched_get_priority_max`, `sched_get_priority_min`, `sched_rr_get_interval`, `sched_setaffinity`, `sched_getaffinity` and `getcpu`. The nice value sets the weight of the thread. A real time policy and `SCHED_DEADLINE` give the largest weight, and `SCHED_IDLE` gives the smallest weight.
- `clock_gettime` and `clock_getres` accept the CPU clocks of `clock_getcpuclockid` and `pthread_getcpuclockid`.
- The ltp boot test runs 31 more tests, most of them for the scheduling calls. `tools/ltp/build.sh` builds the getpriority, setpriority and nice tests.
- The kernel starts each CPU that the ACPI MADT gives, up to 64 CPUs. User code runs on all CPUs at the same time. Kernel code runs on one CPU at a time, under one big kernel lock, as in Linux 2.0. All CPUs use one queue of the scheduler, and a CPU with no task waits in its idle task. The CPUs send interrupts to each other to drop TLB entries and to wake an idle CPU.
- `sched_getaffinity`, `getcpu`, `__vdso_getcpu`, `/proc/cpuinfo` and `/proc/stat` give each CPU that runs. The GDT of each CPU has the CPU number in the limit of the segment 0x7b, as in Linux.
- The `smp` boot test runs init with 8 CPUs. Init checks the CPU count and runs a hackbench load of 80 processes that send messages through socket pairs. `RK_SMP` sets the CPU count of `cargo xtask qemu` and of the other boot tests.

### Changed

- The clocks of the system calls and of the vDSO change between two ticks. They add the time of the time stamp counter since the last tick. A time out of 0 in `poll`, `select` and `epoll_wait` does not wait for the next tick.
- The kernel copies the frames of user pages with `rep movsb`, not one byte at a time. A copy on write of a page is about 30 times faster under QEMU.

### Fixed

- The futex calls change the futex word with an atomic compare and exchange, because user code on another CPU can change the word at the same time.
- The kernel finds the ACPI RSDP in the BIOS area when the PVH loader does not give it.
- `timer_settime` and `timer_delete` discard the pending signal of the old setting of the timer, as Linux 6.13 does. `timer_getoverrun` gives the overrun count of the last signal that a thread took, and not of the last signal that the timer sent.
- `tools/ltp/build.sh` makes the LTP archives again after a crash of the compiler, so a failed build does not leave an archive without some objects.
- The `alpine` boot test can copy the debug tools on macOS. A file of the tree now replaces a BusyBox link of the root file system.

## [0.2.5] (2026-10-24)

This release is the fifth part of milestone R2. It adds epoll, event files, timer files and signal files. The ltp boot test runs 50 more tests, and all of them pass.

### Added

- `epoll_create`, `epoll_create1`, `epoll_ctl`, `epoll_wait`, `epoll_pwait` and `epoll_pwait2`. An entry can be level triggered or edge triggered, and it accepts `EPOLLONESHOT` and `EPOLLEXCLUSIVE`. An epoll file can watch another epoll file, and `epoll_ctl` refuses a loop and a chain of more than 5 files.
- `eventfd` and `eventfd2`, with `EFD_SEMAPHORE`.
- `timerfd_create`, `timerfd_settime` and `timerfd_gettime`, with `TFD_TIMER_ABSTIME` and the `TFD_IOC_SET_TICKS` ioctl.
- `signalfd` and `signalfd4`. A read gives each pending signal of the set as a `struct signalfd_siginfo`.
- `fcntl` accepts `F_GETPIPE_SZ` and `F_SETPIPE_SZ`.
- The ltp boot test runs 50 more tests for epoll, event files, timer files and signal files.

## [0.2.4] (2026-10-24)

This release is the fourth part of milestone R2. It adds process file descriptors, `seccomp` with classic BPF and user notifications, `memfd_create`, and Unix sockets. The new `kselftest` boot test runs the `seccomp_bpf` test of Linux, and all the tests that apply pass.

### Added

- `pidfd_open`, `pidfd_send_signal` and `pidfd_getfd`. `poll` of a process file descriptor gives `POLLIN` when the process ended. `clone` and `clone3` accept `CLONE_PIDFD`, and `waitid` accepts `P_PIDFD`.
- `kcmp` for `KCMP_FILE`, `KCMP_VM`, `KCMP_FILES`, `KCMP_FS` and `KCMP_SIGHAND`.
- `capget` and `capset`. All processes run as root, thus `capget` gives all the capabilities in the effective and permitted sets.
- init checks the process file descriptors, `kcmp` and `capget`.
- `seccomp` with filters of classic BPF, and the strict mode. A filter gives the action `SECCOMP_RET_KILL_PROCESS`, `KILL_THREAD`, `TRAP`, `ERRNO`, `TRACE`, `LOG` or `ALLOW`. A child of `fork` or `clone` gets the filters of its parent, and `execve` keeps them.
- `seccomp` accepts `SECCOMP_SET_MODE_STRICT`, `SECCOMP_SET_MODE_FILTER`, `SECCOMP_GET_ACTION_AVAIL` and `SECCOMP_GET_NOTIF_SIZES`. `prctl` accepts `PR_GET_SECCOMP`, `PR_SET_SECCOMP`, `PR_SET_NO_NEW_PRIVS` and `PR_GET_NO_NEW_PRIVS`.
- `ptrace` accepts `PTRACE_SECCOMP_GET_FILTER`, `PTRACE_SECCOMP_GET_METADATA` and `PTRACE_O_SUSPEND_SECCOMP`. A tracer with `PTRACE_O_TRACESECCOMP` gets the stop `PTRACE_EVENT_SECCOMP`.
- init checks `seccomp`.
- The listener of `seccomp` notifications. `SECCOMP_FILTER_FLAG_NEW_LISTENER` gives a file descriptor, and `SECCOMP_RET_USER_NOTIF` stops the thread until the supervisor sends a reply. The supervisor uses `SECCOMP_IOCTL_NOTIF_RECV`, `SEND`, `ID_VALID`, `ADDFD` and `SET_FLAGS`. `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` makes the wait killable after the supervisor receives the notification.
- `SECCOMP_FILTER_FLAG_TSYNC` and `SECCOMP_FILTER_FLAG_TSYNC_ESRCH` put the filter on all the threads of the process.
- `memfd_create`. A memfd is a regular file in a private tmpfs, with no name in the tree.
- `unshare` for `CLONE_FILES`, `CLONE_FS` and `CLONE_SYSVSEM`. The flags of the name spaces give `EINVAL`, because rukernel has no name spaces yet.
- `/proc/PID/syscall`. The state of a thread in `/proc/PID/stat` is `D` while it waits for a killable event.
- init checks `memfd_create` and `unshare`.
- Unix sockets of the types `SOCK_STREAM`, `SOCK_DGRAM` and `SOCK_SEQPACKET`. A socket can have a path name, an abstract name or no name. The new crates are `rk-net` (the socket layer) and `rk-net-unix` (the Unix family).
- `socket`, `socketpair`, `bind`, `listen`, `accept`, `accept4`, `connect`, `getsockname`, `getpeername`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `sendmmsg`, `recvmmsg`, `shutdown`, `getsockopt` and `setsockopt`.
- A message can carry files with `SCM_RIGHTS` and credentials with `SCM_CREDENTIALS`. `SO_PEERCRED` gives the credentials of the peer, and `SO_PASSCRED` gives the credentials of the sender with each message.
- `/proc/PID/fd` shows a socket as `socket:[INODE]`.
- init checks Unix sockets.
- The `kselftest` boot test runs the `seccomp_bpf` test of the Linux selftests. `tools/kselftest/build.sh` builds the test as a static glibc program. 99 tests pass, and 3 tests skip because rukernel has no PID name spaces.

### Fixed

- The signal information of a stop of `ptrace` that is not a signal now has the ID of the tracee in `si_pid`, as in Linux. Before, `si_pid` was 0, because the kernel wrote the code of the stop with the layout of a fault.

## [0.2.3] (2026-10-24)

This release is the third part of milestone R2. It adds `ptrace`, `process_vm_readv` and `process_vm_writev`, and the procfs files that debuggers read. gdb and strace from Alpine run on rukernel. The `ltp` boot test runs 191 LTP tests.

### Added

- `ptrace`. A tracer attaches with `PTRACE_TRACEME`, `PTRACE_ATTACH` or `PTRACE_SEIZE`, and gets the stops of its tracees with `wait4` and `waitid`. A tracee stops at a signal, at the group stop, at `PTRACE_INTERRUPT`, at the entry to a system call and the return from it, and at the events `PTRACE_EVENT_FORK`, `VFORK`, `CLONE`, `EXEC`, `VFORK_DONE` and `EXIT`. `PTRACE_LISTEN` keeps a tracee in the group stop.
- The tracer reads and writes the memory of the tracee with `PTRACE_PEEKDATA` and `PTRACE_POKEDATA`. A write to a read-only page of the program, for a breakpoint, makes a private copy of the page.
- The tracer reads and writes the registers with `PTRACE_GETREGS`, `PTRACE_SETREGS`, `PTRACE_GETFPREGS`, `PTRACE_SETFPREGS`, `PTRACE_GETREGSET`, `PTRACE_SETREGSET`, `PTRACE_PEEKUSER` and `PTRACE_POKEUSER`. A change of `orig_rax` at the entry to a system call changes the system call, and -1 skips it. The kernel keeps the debug registers that the tracer writes, but it does not load them into the CPU.
- `PTRACE_SINGLESTEP`, `PTRACE_GETSIGINFO`, `PTRACE_SETSIGINFO`, `PTRACE_GETEVENTMSG`, `PTRACE_SETOPTIONS`, `PTRACE_GET_SYSCALL_INFO`, `PTRACE_KILL` and `PTRACE_DETACH`.
- `process_vm_readv` and `process_vm_writev`.
- `wait4` accepts `__WALL` and `__WCLONE`, and `waitid` gives `CLD_TRAPPED` for a stop of a tracee.
- `/proc/PID/mem` reads and writes the memory of a process. `/proc/PID/auxv` gives the auxiliary vector. `/proc/PID/status` gives `TracerPid`, and a stopped tracee has the state `t`.
- The `alpine` boot test runs strace and gdb, if `tools/debug/build.sh` installed them. strace traces a shell pipeline with `-f`, and gdb sets a breakpoint in a program and steps it.
- init checks `ptrace` and `process_vm_readv`.
- The `ltp` boot test runs 191 tests. The new tests are 8 `ptrace` tests.

### Fixed

- The exit signal of init is now `SIGCHLD`, as in Linux. Before, it was 0.
- `PTRACE_LISTEN` after `PTRACE_INTERRUPT` or `SIGCONT` now makes the tracee stop again at once, as in Linux. Before, the tracee stayed in the stop, and strace did not continue.
- A stop of `PTRACE_INTERRUPT` in a stopped process now gives the stop signal, as in Linux.

## [0.2.2] (2026-10-24)

This release is the second part of milestone R2. It adds stop and continue, `waitid`, `restart_syscall` and the CPU time of each thread and process. The `ltp` boot test runs 183 LTP tests.

### Added

- CPU time for each thread and process. The timer ticks that come while a thread runs user code are its user time. The kernel runs with interrupts off, so the system time is 0. The time of the threads that ended stays in the process, and a wait adds the time of the child to its parent.
- `CLOCK_PROCESS_CPUTIME_ID` and `CLOCK_THREAD_CPUTIME_ID` give the CPU time. Before, they gave the time since boot.
- A POSIX timer on `CLOCK_PROCESS_CPUTIME_ID` or `CLOCK_THREAD_CPUTIME_ID`, and the interval timers `ITIMER_VIRTUAL` and `ITIMER_PROF`, count the CPU time. A thread checks these timers when it comes back to the kernel from user code. Before, they counted the time since they started.
- `getrusage`, `times`, `wait4` and `waitid` give the user time of the process, the thread or the children. `/proc/PID/stat` gives `utime` and `cutime`.
- init checks the CPU clocks, `ITIMER_VIRTUAL`, `getrusage`, `times`, `wait4` and `/proc/self/stat`.
- The `ltp` boot test runs 183 tests. The new test is `clock_gettime01`.
- Stop and continue. `SIGSTOP`, `SIGTSTP`, `SIGTTIN` and `SIGTTOU` with the default action stop all threads of the process, and `SIGCONT` starts them again. A stop signal discards a pending `SIGCONT`, and `SIGCONT` discards the pending stop signals, as in Linux. `SIGKILL` ends a stopped process. init does not stop.
- The parent gets `SIGCHLD` with `CLD_STOPPED` or `CLD_CONTINUED` when a child stops or continues, unless its action has `SA_NOCLDSTOP`. `wait4` gives a stopped child with `WUNTRACED` and a continued child with `WCONTINUED`. Each stop and each continue is given one time.
- `waitid` with `P_ALL`, `P_PID` and `P_PGID`, and the options `WEXITED`, `WSTOPPED`, `WCONTINUED`, `WNOHANG` and `WNOWAIT`. `WNOWAIT` keeps the child in a state that the next wait can take. `P_PIDFD` gives `EBADF`, because the kernel does not have pidfd yet.
- `restart_syscall`. A relative `nanosleep` or `clock_nanosleep` that a stop or a signal without a handler stops continues with the time that remains, as in Linux.
- `/proc/PID/stat` and `/proc/PID/status` show the state `T` for a stopped process.
- init checks stop and continue, `waitid`, `WNOWAIT` and `restart_syscall`.
- The `ltp` boot test runs 182 tests. The new tests are 10 `waitid` tests and 15 tests of `nanosleep`, `clock_gettime`, `gettimeofday`, `sigaction`, `rt_sigaction`, `sigprocmask`, `rt_sigprocmask` and `sigaltstack`.

### Fixed

- `SA_RESETHAND` now changes only the handler to `SIG_DFL`. The flags, the mask and the restorer stay, as in Linux.
- The parent of a process that a signal ends with a core dump now gets `CLD_DUMPED` in `SIGCHLD`.
- `tools/ltp/build.sh` did not run, because the strip command had quotes in the quoted script.

## [0.2.1] (2026-10-24)

This release is the first part of milestone R2. It adds robust futexes and priority inheritance futexes, `clone3`, `rt_sigtimedwait`, `rt_sigqueueinfo`, the interval timers and the POSIX timers. Programs of Alpine and Debian run with their dynamic loaders. The `ltp` boot test runs 157 LTP tests.

### Added

- Robust futex lists. `set_robust_list` keeps the head of the list of the thread, and `get_robust_list` gives it. When a thread exits or calls `execve`, the kernel walks the list. It marks each futex that the thread holds with `FUTEX_OWNER_DIED` and wakes one waiter, as Linux does. A robust mutex of a dead thread or process then gives `EOWNERDEAD`.
- The priority inheritance operations of `futex`: `FUTEX_LOCK_PI`, `FUTEX_LOCK_PI2`, `FUTEX_TRYLOCK_PI` and `FUTEX_UNLOCK_PI`. `FUTEX_UNLOCK_PI` gives the lock to the first waiter. The kernel does not change the priority of the owner, because the scheduler has no priorities yet.
- `tests/user/nptl.c`, a pthread test that the `debian` boot test compiles with glibc and runs. It follows the nptl tests of glibc. It checks normal, error check, recursive, robust and priority inheritance mutexes, condition variables with each clock, `pthread_cancel`, barriers, read and write locks, semaphores and thread local variables.
- The `alpine` boot test. It runs the Alpine mini root file system, and its script runs programs that use the dynamic loader of musl, such as `apk`.
- The `debian` boot test. It runs the Debian trixie slim root file system, and its script runs programs that use the dynamic loader of glibc: bash, coreutils, `dpkg-query`, `apt-get` and perl. The kernel needed no change for them.
- init checks robust mutexes and priority inheritance mutexes of musl.
- `clone3`. It checks `struct clone_args` as Linux does: a struct that is too short gives `EINVAL`, and a larger struct with a field that is not 0 gives `E2BIG`. The new thread starts at the top of the stack that `stack` and `stack_size` give. `CLONE_CLEAR_SIGHAND` puts each handler back to the default action. glibc now makes its threads with `clone3`. `CLONE_PIDFD`, `CLONE_INTO_CGROUP` and `set_tid` give `EINVAL`, because the kernel does not have them yet.
- init and `rk-nptl` start 1000 threads that wait on a barrier, and then join them. `rk-nptl` also checks the `Threads` line of `/proc/self/status`.
- `rt_sigtimedwait`. It takes a pending signal of the set, and a signal of the set wakes the thread while it waits, as if the thread did not block it. The action of the signal does not apply, so the wait can take a signal that would end the process. A time of 0 gives `EAGAIN` at once if no signal is pending.
- `rt_sigqueueinfo` and `rt_tgsigqueueinfo`. The signal keeps the `si_value` of the sender. A program can send a signal with a code of the kernel or of `kill` only to itself, as Linux tells.
- init checks `sigwaitinfo`, `sigtimedwait`, `sigqueue` and the order of real time signals.
- `alarm`, `setitimer` and `getitimer`. `alarm` and `ITIMER_REAL` use the same timer, as in Linux. The kernel does not count CPU time yet, so `ITIMER_VIRTUAL` and `ITIMER_PROF` count the time since they started. `execve` keeps the interval timers.
- The POSIX timers: `timer_create`, `timer_settime`, `timer_gettime`, `timer_getoverrun` and `timer_delete`. A timer can send its signal to the process, to one thread with `SIGEV_THREAD_ID`, or no signal with `SIGEV_NONE`. A timer has one signal in the queue at most. When the timer fires again before the program takes the signal, the overrun count of the signal increases. `execve` deletes the POSIX timers, and a child of `fork` has no timers.
- A kernel task fires the timers. It waits until the earliest deadline and then sends the signals, so the timer interrupt takes no lock.
- init checks `alarm`, the interval timers and the POSIX timers.
- The `ltp` boot test runs 118 tests. The new tests are the 18 futex tests.
- The `ltp` boot test runs 157 tests. The new tests are 39 signal and timer tests: `alarm`, the interval timers, the POSIX timers, `kill`, `tgkill`, `signal`, `pause`, `sigsuspend`, `sigpending`, `rt_sigtimedwait` and `rt_sigqueueinfo`.
- `tools/ltp/kconfig` tells LTP the kernel options of rukernel through `KCONFIG_PATH`. A test that needs a kernel option that rukernel does not have now stops with `TCONF`, and a test that only reads the options can run.

### Fixed

- `/proc/PID/stat` gives the state of the leader thread, as Linux does. Before, it gave `R` if any thread of the process could run.
- `futex` with `FUTEX_CLOCK_REALTIME` gives `ENOSYS` for each operation other than `FUTEX_WAIT_BITSET` and `FUTEX_LOCK_PI2`, as Linux does.

### Changed

- The `ltp` boot test sets `LTP_TIMEOUT_MUL=4`, because QEMU without KVM is slow.
- `tools/ltp/build.sh` removes the symbols from the LTP tests. Each test is 5 times smaller, so the initramfs of the `ltp` boot test fits in the memory of the guest. The script also builds the `waitid` tests.

## [0.2.0] (2026-10-24)

This release completes milestone R1. A static program runs: the kernel has processes and threads, ELF loading, `mmap` with the lock calls and `MAP_GROWSDOWN`, tmpfs from an initramfs, pipes, signals, the console tty and the vDSO. The `ltp` boot test runs 100 LTP tests. The OSTD item #8 moves to R2.

### Added

- `mlock`, `mlock2` with `MLOCK_ONFAULT`, `munlock`, `mlockall` with `MCL_CURRENT`, `MCL_FUTURE` and `MCL_ONFAULT`, and `munlockall`. A lock gives each page of the range its frame. The kernel has no swap, so a locked page and an unlocked page stay in memory the same way. The kernel does not enforce `RLIMIT_MEMLOCK` yet.
- `mmap` with `MAP_LOCKED` and `MAP_POPULATE`. `MAP_POPULATE` gives each page its frame before `mmap` returns.
- `mincore`. It gives 1 for each page that has a frame.
- `msync` with `MS_INVALIDATE` gives `EBUSY` for a locked area, as Linux does.
- `madvise` checks its arguments as Linux does. An unknown advice gives `EINVAL`, and so do `MADV_MERGEABLE` and `MADV_UNMERGEABLE`, because there is no KSM. A range with a page that is not mapped gives `ENOMEM`. `MADV_DONTNEED` and `MADV_REMOVE` on a locked area, `MADV_REMOVE` on a private area, and `MADV_FREE` and `MADV_WIPEONFORK` on an area that is shared or that maps a file give `EINVAL`. `MADV_FREE` gives zero pages again, as `MADV_DONTNEED` does.
- The `VmLck` and `VmRSS` lines of `/proc/PID/status`, and `/proc/PID/smaps` with the size, the resident bytes, the anonymous bytes and the locked bytes of each area.
- `mmap` with `MAP_GROWSDOWN`. A fault below the area makes the area larger, up to 8 MiB. The area keeps a gap of 256 pages to the area below it, as the `stack_guard_gap` of Linux does. A fault in the gap sends `SIGSEGV`.
- The vDSO. The build script of rk-frame compiles `vdso/x86_64.rs` with rustc and links it to a shared object with the name `linux-vdso.so.1`. It has `__vdso_clock_gettime`, `__vdso_clock_getres`, `__vdso_gettimeofday`, `__vdso_time` and `__vdso_getcpu` with the version `LINUX_2.6`, as on Linux. A clock that the vDSO does not give goes to the system call.
- The data page of the vDSO. The timer interrupt writes the tick count to it, so the time in the vDSO is the same as the time of the system calls. `execve` maps the data page and the vDSO, and gives the address of the vDSO in `AT_SYSINFO_EHDR`. `/proc/PID/maps` names them `[vvar]` and `[vdso]`. musl now reads the time through the vDSO.
- init finds the functions of the vDSO in its symbols and calls them. The time of the vDSO agrees with the system call.
- The `ltp` boot test runs 100 tests. The new tests are of `mlock`, `munlock`, `mincore`, `madvise`, `msync` and `MAP_GROWSDOWN`.

## [0.1.4] (2026-10-24)

This release continues milestone R1. The kernel now has procfs, `vfork`, resource limits, `msync`, `mremap` and a larger LTP boot test.

### Added

- The `busybox` boot test. The initramfs has a static BusyBox from busybox.net, and the boot test checks its SHA-256. The BusyBox shell runs as init. It runs the pipeline `echo one two | tr a-z A-Z | cat`, then a job in the foreground, and `^C` stops the job. `RK_BUSYBOX` gives the path of a different BusyBox.
- The `ltp` boot test. `tools/ltp/build.sh` builds a pinned release of the Linux Test Project as static musl programs, and the boot test runs the tests in `tools/ltp/tests.txt` under the BusyBox shell. CI keeps the programs in its cache.
- `cargo xtask boot-test` accepts the names of the boot tests to run.
- `futex` with `FUTEX_WAIT`, `FUTEX_WAKE`, `FUTEX_WAIT_BITSET`, `FUTEX_WAKE_BITSET`, `FUTEX_REQUEUE`, `FUTEX_CMP_REQUEUE` and `FUTEX_WAKE_OP`, with a timeout and with `FUTEX_PRIVATE_FLAG`. The key of a futex in a shared area is the physical address, so processes that share the page find the same futex. When a thread ends, the kernel clears its `clear_child_tid` word and wakes a waiter, so `pthread_join` works.
- `mount` and `umount2`. `mount` makes a new file system of a registered type, makes a bind mount, and accepts `MS_REMOUNT` and the propagation flags. R1 has one mount name space, so a change of the propagation type has no effect. The VFS keeps the source, the type and the flags of each mount, but it does not enforce the flags yet. `umount2` accepts `MNT_FORCE`, `MNT_DETACH`, `MNT_EXPIRE` and `UMOUNT_NOFOLLOW`.
- A list of file system types in rk-vfs. The kernel registers tmpfs at boot. The tmpfs option `mode=` gives the permission bits of the root.
- procfs in the new crate rk-fs-proc. The kernel registers it as the type `proc`. The root has `meminfo`, `cpuinfo`, `uptime`, `loadavg`, `stat`, `version`, `cmdline`, `filesystems`, `swaps`, `mounts`, `self`, `thread-self` and a directory for each process. A process directory has `stat`, `status`, `cmdline`, `comm`, `environ`, `maps`, `mounts`, `statm`, `oom_score_adj`, `oom_score`, the links `exe`, `cwd` and `root`, `fd` and `task`. `/proc/sys/kernel` and `/proc/sys/vm` have the values that the LTP library reads. A write to them keeps the value, but the kernel does not use it yet.
- Each process keeps its command line, the file of its program, the tick of its start and its `oom_score_adj`.
- The `ltp` boot test mounts procfs on `/proc` and a tmpfs on `/dev/shm`. `RK_LTP_TESTS` gives other tests for a run by hand.
- `clone` with `CLONE_PARENT`. The child gets the parent and the exit signal of the caller.
- The `ltp` boot test runs 84 tests of `fork`, `clone`, `exit`, `wait`, `waitpid`, `wait4`, `getpid`, `gettid`, `brk`, `mmap`, `mprotect`, `munmap`, `mremap`, `msync`, `getrlimit` and `setrlimit`.
- Resource limits for each process. `prlimit64` reads and changes them, and `fork` copies them. A new soft limit above the hard limit gives `EINVAL`, and a hard limit of `RLIMIT_NOFILE` above 1048576 gives `EPERM`. The kernel does not enforce the limits yet.
- The status of a process that a signal ends with a core dump has the core dump bit when `RLIMIT_CORE` is not 0. The kernel does not write a core file.
- `mmap` with `MAP_32BIT` puts the mapping between 1 GiB and 2 GiB, as Linux does on x86-64.
- `mmap` of `/dev/zero` makes anonymous memory, as Linux does.
- An address space has 65530 areas at most, the default `vm.max_map_count` of Linux. `mmap` gives `ENOMEM` at the limit, and so does a `munmap` that cuts an area in two.
- `mprotect` gives `EACCES` for write access to a shared mapping of a file that is not open for writing.
- `msync`. A write through a shared file mapping marks the page dirty. `msync`, `munmap` and the end of the address space write the dirty pages back to the file, up to the end of the file. A `read` or `write` of the file does not see the pages of a mapping before the write back. The page cache of R2 removes this limit.
- `mremap` with `MREMAP_MAYMOVE`, `MREMAP_FIXED` and `MREMAP_DONTUNMAP`. An area grows in place when the range after it is free, or moves with its pages. An old length of 0 copies a shared area, as Linux does.
- A fault on a page of a file mapping past the end of the file sends `SIGBUS` with `BUS_ADRERR`, as Linux does.
- `tools/ltp/build.sh` builds the LTP tests of more system calls, for the next tests of R1.
- The `mount` group of constants from `<linux/mount.h>` in rk-abi.
- `AddressSpace::shared_phys` in rk-mm gives the physical address of a shared page.
- init mounts procfs and reads `/proc/meminfo`, `/proc/self/stat`, `/proc/self/status`, `/proc/self/maps`, `/proc/mounts` and `/proc/sys/kernel/pid_max`.
- init examines `pthread_create` and `pthread_join`, a mutex that four threads use, a condition variable, `pthread_kill`, the `futex` errors and timeout, `exit` with a second thread, and `execve` with a second thread.

### Fixed

- `mmap` looks up the descriptor before it examines the other arguments, so a closed descriptor gives `EBADF` as on Linux. `MAP_SHARED_VALIDATE` accepts only the flags of the Linux mask `LEGACY_MAP_MASK`.
- `vfork` and `clone` with `CLONE_VFORK` make the parent wait until the child calls `execve` or ends. The child uses the memory of the parent until then, as on Linux. Before, the child got a copy of the memory and the parent continued at once.
- A shared anonymous mapping keeps its pages in a shared object, so a page that the parent did not touch before `fork` is shared too. Before, the parent and the child each got a different page at the first access. `/proc/PID/maps` shows the area as `/dev/zero (deleted)`, as Linux does.
- `statfs` examines the file system of its path, and `statfs` and `fstatfs` give the magic number of that file system. Before, `statfs` examined the root and did not read the path.
- `execve` ends the other threads of the process and waits until they are gone, as `de_thread` of Linux does. Before, the other threads continued in the new program.
- The `heap` self test accepts a new page table for the block of 1 MiB. The page tables of the heap range stay after the block is freed, so a larger initramfs made the test fail.

## [0.1.3] (2026-10-24)

This release continues milestone R1. The kernel now has signals with handlers, a console that blocks, pipes, `poll` and `select`.

### Added

- A bottom half in rk-frame. An interrupt handler takes no lock, so the work that the interrupt starts runs later, in the idle loop of the scheduler and after an interrupt in user mode. `add_bottom_half` adds the function of a driver. `WaitQueue::wait_until_timeout` waits with a timeout, and the bottom half wakes the task when the timeout is over.
- `rk_vfs::WaitQueue` and `rk_vfs::wait::interrupted`, the waits of the file operations. A wait that a signal stops gives `ERESTARTSYS`.
- The restart numbers of the kernel in rk-abi: `ERESTARTSYS`, `ERESTARTNOINTR`, `ERESTARTNOHAND` and `ERESTART_RESTARTBLOCK`. A system call that gives one of them starts again.
- The words after `--` on the command line are the arguments of init, as in Linux.
- The new `tty` boot test. The boot test types a line and `^C` on the serial port. init reads the line, and `^C` stops a child that runs in user mode in the foreground process group.
- Signals. The new `rk_proc::signal` module has the signal sets, the actions, the default actions, the pending queue and `siginfo`. Each process has an action table and a shared queue, and each thread has a mask, a private queue and an alternate stack. A real time signal can be in the queue more than one time.
- The signal delivery. Before a thread goes back to user mode, the kernel takes the next signal that the thread does not block. For a handler, the kernel writes the `rt_sigframe` of the x86-64 ABI with the registers, the FPU state and `siginfo`, and `rt_sigreturn` reads them back. The flags `SA_SIGINFO`, `SA_RESTART`, `SA_NODEFER`, `SA_RESETHAND`, `SA_ONSTACK` and `SA_NOCLDWAIT` work.
- The system calls `rt_sigaction`, `rt_sigprocmask`, `rt_sigpending`, `rt_sigsuspend`, `pause`, `sigaltstack` and `rt_sigreturn`. `tkill` and `tgkill` send a signal to one thread.
- A process sends its exit signal to its parent when it ends. If the parent ignores `SIGCHLD`, the kernel reaps the child at once.
- `FpuState::as_bytes`, `FpuState::from_bytes` and `UserContext::set_fpu` in rk-frame.
- init examines a handler, a blocked signal, `SIGCHLD`, `SIGTERM`, `sigsuspend`, a signal that stops `nanosleep`, the address of `SIGSEGV` and the alternate stack.
- Pipes. The new `rk_vfs::pipe` module has a buffer of 64 KiB with a read end and a write end, as fs/pipe.c of Linux has them. A write of up to `PIPE_BUF` bytes is atomic. A read gives end of file when each write end is closed, and a write with no read end gives `EPIPE` and sends `SIGPIPE`. The system calls `pipe` and `pipe2` make a pipe, with `O_CLOEXEC` and `O_NONBLOCK`.
- The system calls `poll`, `ppoll`, `select` and `pselect6`. A wait scans the files, and waits on the new poll queue of rk-vfs until a file has a new event, a signal comes or the time is over. `ppoll` and `pselect6` set the signal mask for the time of the call.
- init examines a pipe between a parent and a child that runs `execve`, end of file, `O_NONBLOCK`, `poll`, `select` with a timeout and `SIGPIPE`.

### Changed

- The console reads the serial port in the bottom half. A reader blocks on a wait queue, and `^C` stops a program that does not read. `nanosleep` blocks with a timeout and does not poll.
- An exception in user mode sends its signal to the thread, with the fault address in `siginfo`. A handler can catch it. Before, the exception always ended the process.
- `kill` puts the signal in the queue of the process. Before, a signal always did its default action.
- `clone` keeps the exit signal of the low byte of its flags. `execve` sets each handler back to the default action.

## [0.1.2] (2026-10-24)

This release continues milestone R1. The kernel now runs a static program from the initramfs as the first process.

### Added

- rk-abi has six new groups of constants: `stat` for the mode bits and `statx`, `ioctls` for the terminal and file `ioctl` commands, `termbits` for `struct termios`, `auxv` for the auxiliary vector, `elf` for the ELF headers and `random` for `getrandom`. rk-abigen generates them from the uAPI headers, as it does for the other groups.
- The rk-mm crate. An `AddressSpace` keeps the areas of a user process as Linux keeps its `vm_area_struct` list, and it has `mmap`, `munmap`, `mprotect` and `brk`. A page gets a frame at the first access. `handle_fault` gives a zero page for anonymous memory and asks the `MmFile` of the area for a file page. `fork` makes the private pages read only in the parent and the child, and the first write to such a page copies it. The new `fault` boot test runs a user program that gets its pages through page faults, and then examines fork, copy on write, `munmap`, `mprotect` and `brk`.
- The rk-vfs crate, the virtual file system. A file system gives `Inode` objects. The VFS keeps the dentries, the mounts of a `MountNamespace` and the open files, walks paths with symbolic links and mount points, and does the name operations: `open`, `mkdir`, `mknod`, `symlink`, `link`, `unlink`, `rmdir`, `rename` and `readlink`. `FdTable` is the descriptor table of a process. `cpio::unpack` reads an initramfs in the newc format.
- The rk-fs-tmpfs crate, a file system in memory. The kernel makes a tmpfs as the root file system and unpacks the initramfs into it. `BootInfo::initrd_bytes` gives the bytes of the initramfs, and the direct map now always includes it. The new `initramfs` boot test reads a file, a symbolic link and a hard link from the initramfs that `cargo xtask` makes.
- The EFI stub gets the initramfs from the firmware through the `LoadFile2` protocol, as the EFI stub of Linux does. Then a UEFI boot also gives the initramfs to the kernel.
- The rk-proc crate. A `Process` has a process ID, a parent, a process group, a session, an address space, a descriptor table and its threads. `fork` copies a process, `exec` loads a static ELF or a static PIE with its stack, auxiliary vector and arguments, and `wait` gives the status of a child that ended, as `wait4` does.
- The rk-syscall crate. It has the system call table and the first system calls: the file calls, `mmap`, `munmap`, `mprotect`, `brk`, `clone`, `fork`, `vfork`, `execve`, `exit`, `wait4`, `kill`, the process group calls, the clocks, `nanosleep`, `uname`, `prlimit64`, `sysinfo` and `getrandom`. A file mapping copies the pages of the file at the first fault.
- The rk-drv-mem crate, with `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random` and `/dev/urandom`. The random devices use ChaCha20 from the new `rk_lib::chacha` module, with a seed from `rk_frame::arch::random_seed`.
- The rk-drv-tty crate, a tty on the serial console with a line discipline, `termios`, the job control `ioctl` commands and the signals of the control characters.
- The kernel runs `/init` from the initramfs, or the program of `rdinit=`, as the first process. If init cannot start or it ends, the kernel stops with the message of Linux. The kernel makes `/dev` and its device nodes before init starts.
- The new `init` boot test runs a static C program as `/init`. The program examines the process calls, memory, files, devices, `fork`, `wait4`, `execve` of a static PIE and the clock. `cargo xtask` compiles the programs in `tests/user` with `musl-gcc` or `zig cc`. CI installs `musl-tools`.
- `rk_frame::console::write_bytes`, `rk_frame::console::try_read_byte` and `rk_proc::kill_group`.
- `clippy.toml` lets the tests use `unwrap`, `expect` and `panic`.

### Changed

- `PageProt` has a `readable` field. A page with no access stays in the `VmSpace`, but the page table has no entry for it, as for `PROT_NONE`.

## [0.1.1] (2026-10-23)

This release starts milestone R1. A user process can now have its own address space, and the kernel can run more than one task.

### Added

- Kernel tasks in `rk_frame::task`. A task has a kernel stack of 32 KiB on the heap, with an unmapped page before and after it. `TaskOptions::spawn` makes a task, `yield_now` lets the next task run, `exit` ends the task, and a `WaitQueue` blocks a task until a condition is true. `should_yield` tells a task that runs user code that its time slice of 4 ticks is over. The new `task` boot test runs three tasks in turns and a task that waits in a wait queue.
- The rk-sched crate. It gives rk-frame a round robin scheduler through `inject_scheduler`.
- `rk_frame::vm::VmSpace`, the page table of one user address space. The user half belongs to the address space, and the kernel half is the same in each address space. The address space owns its frames through `Arc<Frame>`, so two address spaces can map the same frame. `read`, `write` and `fill_zero` copy user memory through a software walk, and give a `UserFault` at the first page that is not mapped or not writable. The new `vm` boot test runs a program in two address spaces and examines that each program reads its own data.
- `Frame::read_bytes`, `Frame::write_bytes`, `Frame::fill_zero`, `Frame::copy_from` and `mm::alloc_zeroed_frame`.
- Each `UserContext` keeps the x87 and SSE state and the FS base of its thread. rk-frame turns on SSE at boot, loads the state with `fxrstor64` before the entry to user mode and saves it with `fxsave64` after the exit. `set_fs_base` gives the value for `arch_prctl(ARCH_SET_FS)`. The `syscall` boot test runs two user programs that use SSE registers in turns and examines that each keeps its values.

### Removed

- `rk_frame::user::map_page`. It put user pages in the kernel page table. A user page is now in a `VmSpace`.

## [0.1.0] (2026-10-23)

This release completes milestone R0, the skeleton. `rkc l1 --reference 7.3` passes for x86-64, each system call number gives `ENOSYS`, and CI enforces the unsafe rule.

### Added

- The kernel heap. rk-frame gives the global allocator, so the safe crates can use `Box`, `Vec`, `BTreeMap` and `Arc`. A small object comes from a slab of 16 to 2048 bytes in the direct map. A large object gets its own pages with a guard page after it. The new `heap` boot test examines it.
- A CI job runs `rkc l1 --reference 7.3` of rukernel-compat on each pull request. It compares the generated ABI of each architecture with the uAPI headers that the Linux 7.3 build installs. The job is part of the `ci` check.

## [0.0.4] (2026-10-23)

### Added

- The Linux boot protocol on x86-64. `cargo xtask boot-test` writes a bzImage next to the ELF image. The real mode setup code gets the E820 memory map from the BIOS and goes to the 32 bit entry. The 64 bit entry is 0x200 bytes after it. The kernel reads the command line, the memory map, the initramfs and the ACPI RSDP from `boot_params`.
- The EFI stub. The bzImage has a PE/COFF header, so UEFI firmware can start it as an EFI application. The stub copies the kernel to 1 MiB, reads the command line from the load options and the ACPI RSDP from the configuration table, calls ExitBootServices and goes to the 64 bit entry. The kernel reads the EFI memory map from `boot_params`.
- The `boot` and `mm` boot tests also run with the bzImage, with the BIOS of QEMU and with OVMF. CI installs OVMF.

### Changed

- `BootInfo::push_region` merges an entry with the last entry when the two are adjacent and have the same kind.
- `cargo xtask unsafe` reads a budget for each crate in `xtask/unsafe-allowed.txt` and needs an audit section in `frame/AUDITED.md` for each crate in the list.

## [0.0.3] (2026-10-23)

### Added

- `rk-abigen`, the ABI generator, in `tools/rk-abigen`. `rk-abigen fetch` downloads the Linux 7.3 tarball and checks its SHA-256. `rk-abigen generate` writes the system call tables of x86-64, arm64 and riscv64 into `abi/7.3/` as TOML and into `rk-abi` as Rust.
- `rk_abi::x86_64::syscalls`, `rk_abi::aarch64::syscalls` and `rk_abi::riscv64::syscalls` give the number of each system call and a table of names. `rk_abi::native` is the module of the target.
- `cargo xtask abi` and a CI job run the generator again and fail if the output is not in the tree.
- `rk-abigen` generates the uAPI constants of each architecture: the error numbers, the flags of `open`, `fcntl`, the `*at` calls, `mmap`, `clone`, `sigaction`, `wait4`, `futex` and `poll`, and the clock IDs. It installs the uAPI headers as `make headers_install` does, and clang compiles a probe for each target, as asm-offsets does in Linux. The values are in `abi/7.3/<arch>/constants.toml` and in modules such as `rk_abi::x86_64::open`.
- `rk-abigen` generates the uAPI structures of each architecture, for example `struct stat`, `struct statx`, `struct clone_args`, `struct epoll_event` and `struct new_utsname`. clang gives the layout of each structure. The Rust structures are `#[repr(C)]`, have a field for each padding gap, derive the zerocopy traits and have a compile time check of each offset. They are in `rk_abi::<arch>::types` and in `abi/7.3/<arch>/types.toml`.
- `rk-abi` depends on `zerocopy` 0.8, so that a structure can be copied from user memory with no `unsafe` code.
- User mode on x86-64. `rk_frame::user::UserContext::execute` runs user code until a system call, an exception or an interrupt, and gives the reason. The `syscall` instruction goes to the kernel through LSTAR. The return to user mode is always `iretq`. The TSS has an entry stack for traps from user mode.
- `rk_frame::user::map_page` maps a frame in the user half of the address space.
- The system call table of the kernel. Each number gives `-ENOSYS` in R0.
- The `syscall` boot test. A user program makes each system call number of x86-64 and checks that each one gives `-ENOSYS`.

### Changed

- rk-abigen now generates the `Errno` constants from `<asm/errno.h>`. `Errno` has all the error numbers of Linux, from `EPERM` (1) to `EHWPOISON` (133), and the hand-written list is gone.

### Fixed

- The boot tests use KVM only when the runner can open `/dev/kvm`. Otherwise QEMU uses TCG.
- The license check allows GPL-2.0-only for the crates of this workspace, because they are published now.

## [0.0.2] (2026-10-23)

### Added

- Traps on x86-64. The GDT has the Linux selectors. The TSS has separate stacks for a double fault, an NMI and a machine check. The IDT sends all 256 vectors to one trap handler. An unhandled kernel exception prints an Oops message with the registers and panics.
- An exception table, as in Linux. `rk_frame::trap::probe_read_u64` reads an address and gives an error on a fault, with no panic.
- The `trap` boot test.
- The release workflow publishes `rk-abi`, `rk-frame`, `rk-lib` and `rukernel` to crates.io. The publish script obeys the crates.io rate limits.
- A frame allocator. It is a bitmap of the usable memory in the memory map. `rk_frame::mm::Frame` owns one physical page and gives it back when it is dropped.
- The kernel page tables, with the Linux layout: the direct map at `0xffff888000000000`, the vmalloc range at `0xffffc90000000000` and the kernel image at `0xffffffff80000000`. Text is read only and executable, rodata is read only, and data and bss are writable and not executable. The boot identity map is gone after this step.
- `rk_frame::mm::vmap` maps a frame in the vmalloc range with a guard page after it. `rk_frame::mm::query` and `translate` walk the page tables.
- The `mm` boot test.
- The local APIC in x2APIC mode, or in xAPIC mode when the CPU has no x2APIC. The legacy PIC is masked. The APIC timer is measured against the PIT and interrupts 250 times each second on vector `0xec`, as in Linux.
- `rk_frame::irq` turns interrupts on and off, and `rk_frame::time` gives the tick count and the timer frequency.
- The `timer` boot test.

### Fixed

- The PVH entry clears the bss before the first Rust code runs.

## [0.0.1] (2026-10-23)

### Added

- The design, in `spec/`.
- The workspace skeleton: `rk-frame`, `rk-abi`, `rk-lib` and `xtask`.
- The unsafe rule, the layer rule and the prose rules, as `cargo xtask` checks.
- The CI gate, the security workflows and the release workflow.
- The kernel binary, `rukernel`. It boots on x86-64 under QEMU through the PVH entry, prints the boot log on the serial port and reads the memory map.
- `cargo xtask qemu` and `cargo xtask boot-test`, and a CI job that runs the boot tests.

[0.3.15]: https://github.com/tamnd/rukernel/releases/tag/v0.3.15
[0.3.14]: https://github.com/tamnd/rukernel/releases/tag/v0.3.14
[0.3.13]: https://github.com/tamnd/rukernel/releases/tag/v0.3.13
[0.3.12]: https://github.com/tamnd/rukernel/releases/tag/v0.3.12
[0.3.11]: https://github.com/tamnd/rukernel/releases/tag/v0.3.11
[0.3.10]: https://github.com/tamnd/rukernel/releases/tag/v0.3.10
[0.3.9]: https://github.com/tamnd/rukernel/releases/tag/v0.3.9
[0.3.8]: https://github.com/tamnd/rukernel/releases/tag/v0.3.8
[0.3.7]: https://github.com/tamnd/rukernel/releases/tag/v0.3.7
[0.3.6]: https://github.com/tamnd/rukernel/releases/tag/v0.3.6
[0.3.5]: https://github.com/tamnd/rukernel/releases/tag/v0.3.5
[0.3.4]: https://github.com/tamnd/rukernel/releases/tag/v0.3.4
[0.3.3]: https://github.com/tamnd/rukernel/releases/tag/v0.3.3
[0.3.2]: https://github.com/tamnd/rukernel/releases/tag/v0.3.2
[0.3.1]: https://github.com/tamnd/rukernel/releases/tag/v0.3.1
[0.3.0]: https://github.com/tamnd/rukernel/releases/tag/v0.3.0
[0.2.6]: https://github.com/tamnd/rukernel/releases/tag/v0.2.6
[0.2.5]: https://github.com/tamnd/rukernel/releases/tag/v0.2.5
[0.2.4]: https://github.com/tamnd/rukernel/releases/tag/v0.2.4
[0.2.3]: https://github.com/tamnd/rukernel/releases/tag/v0.2.3
[0.2.2]: https://github.com/tamnd/rukernel/releases/tag/v0.2.2
[0.2.1]: https://github.com/tamnd/rukernel/releases/tag/v0.2.1
[0.2.0]: https://github.com/tamnd/rukernel/releases/tag/v0.2.0
[0.1.4]: https://github.com/tamnd/rukernel/releases/tag/v0.1.4
[0.1.3]: https://github.com/tamnd/rukernel/releases/tag/v0.1.3
[0.1.2]: https://github.com/tamnd/rukernel/releases/tag/v0.1.2
[0.1.1]: https://github.com/tamnd/rukernel/releases/tag/v0.1.1
[0.1.0]: https://github.com/tamnd/rukernel/releases/tag/v0.1.0
[0.0.4]: https://github.com/tamnd/rukernel/releases/tag/v0.0.4
[0.0.3]: https://github.com/tamnd/rukernel/releases/tag/v0.0.3
[0.0.2]: https://github.com/tamnd/rukernel/releases/tag/v0.0.2
[0.0.1]: https://github.com/tamnd/rukernel/releases/tag/v0.0.1

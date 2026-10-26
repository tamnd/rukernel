# fstests results on ext4

These are the results of the generic and ext4 tests of fstests on ext4. The Linux column is the result on the reference kernel, and the rukernel column is the newest result on rukernel. The README in this directory tells how the tests run.

rukernel: 212 pass, 26 fail, 97 not run, and 12 have no result, of 347 tests.

| Test | What the test checks | Linux | rukernel | Last run | Note |
| --- | --- | --- | --- | --- | --- |
| ext4/001 | Test fallocate FALLOC_FL_ZERO_RANGE | pass | pass | 2026-10-25 |  |
| ext4/003 | Regression test for commit: b5b6077 ext4: fix wrong assert in ext4_mb_normalize_request() This testcase checks whether this bug has been fixed. | pass | fail | 2026-10-25 | Needs bigalloc, the clusters of more than one block. |
| ext4/005 | Test corruption issue in converting file with a hole at the beginning to non-extent based format | pass | not run | 2026-10-25 | Clearing extent flag not supported, old chattr and/or kernel? |
| ext4/020 | Test partial blocksize defrag integrity issue. | pass | pass | 2026-10-25 |  |
| ext4/021 | Regression test for commit: 688f869 ext4: Initialize fsync transaction ids in ext4_new_inode() | pass | pass | 2026-10-25 |  |
| ext4/022 | Test extending of i_extra_isize code | pass | pass | 2026-10-26 |  |
| ext4/023 | Ensure that the populate helpers actually /can/ populate a ext4 filesystem with all types of metadata and create an image of the metadata. Check that fsck is ... | pass | fail | 2026-10-25 | Needs htree directories. |
| ext4/024 | Regression test for 0d06863f903a ("ext4: don't BUG when truncating encrypted inodes on the orphan list"). | no result | not run | 2026-10-25 | kernel is unaware of ext4 encryption feature, or mkfs options are not compatible with ... |
| ext4/025 | Regression test for commit: 3a4b77c ("ext4: validate s_first_meta_bg at mount time"). | pass | not run | 2026-10-25 | Kernel doesn't support the ext4 feature(s): bigalloc,meta_bg,^resize_inode |
| ext4/026 | Test for ea_inode feature in ext4. Without ea_inode feature, an extended attribute in ext4 cannot be larger than the fs block size. ea_inode feature allows ... | pass | not run | 2026-10-25 | Kernel doesn't support the ext4 feature(s): ea_inode |
| ext4/027 | Check that getfsmap reports the BG metadata we're expecting. | pass | not run | 2026-10-25 | xfs_io fsmap support is missing |
| ext4/028 | Populate filesystem, check that fsmap -n10000 matches fsmap -n1. | pass | not run | 2026-10-25 | xfs_io fsmap support is missing |
| ext4/032 | Ext4 online resize tests of small and crucial resizes with bigalloc feature. | pass | not run | 2026-10-25 | This test requires loopback device support |
| ext4/033 | Test s_inodes_count overflow for huge filesystems. This bug was fixed by commit 4f2f76f75143 ("ext4: Forbid overflowing inode count when resizing".) | no result | not run | 2026-10-25 | This test requires dm zero support |
| ext4/035 |  | pass | pass | 2026-10-25 |  |
| ext4/036 | Test truncate orphan inodes when mounting ext4 ext4 used to hit WARNING, this commit fixed the issue | pass | pass | 2026-10-25 |  |
| ext4/037 | Test mount a needs_recovery partition with noload option. ext4 used to Oops until part of this commit: | pass | pass | 2026-10-25 |  |
| ext4/038 | Regression test for commit: c9eb13a ext4: fix hang when processing corrupted orphaned inode list | pass | pass | 2026-10-26 |  |
| ext4/042 | Test overhead & df output for extN filesystems | pass | fail | 2026-10-25 | the output is not the expected output |
| ext4/043 | Test file timestamps are only precise to seconds with 128-byte inodes." | pass | pass | 2026-10-25 |  |
| ext4/044 | Test file timestamps are precise to nanoseconds with 256-byte inodes | pass | pass | 2026-10-25 |  |
| ext4/048 | Test wiping of ext4_dir_entry2 data upon file removal, conversion to htree, and splitting of htree nodes | pass | not run | 2026-10-25 | filename wipe not supported |
| ext4/049 | Regression test for kernel commit a149d2a5cabb (ext4: fix check to prevent false positive report of incorrect used inodes) | pass | pass | 2026-10-25 |  |
| ext4/050 | Test checkpoint and zeroout of journal via ioctl EXT4_IOC_CHECKPOINT | pass | not run | 2026-10-25 | journal checkpoint ioctl not present on device |
| ext4/051 | Test that tune2fs doesn't fail after ext4 shutdown Regression test for kernel commit: 4274f516d4bc ext4: recalucate superblock checksum after updating free ... | pass | not run | 2026-10-25 | ext4 does not support shutdown |
| ext4/052 | Test ext4's large_dir feature | pass | not run | 2026-10-25 | This test requires loopback device support |
| ext4/054 | Regression test for kernel commit: 1. 0f2f87d51aebc (ext4: prevent partial update of the extent blocks) 2. 9c6e071913792 (ext4: check for inconsistent extents ... | pass | pass | 2026-10-25 |  |
| ext4/056 |  | pass | pass | 2026-10-25 |  |
| ext4/058 | Set 256 blocks in a block group, then inject I/O pressure, it will trigger off kernel BUG in ext4_mb_mark_diskspace_used | pass | pass | 2026-10-25 |  |
| ext4/059 | A regression test for b55c3cd102a6 ("ext4: add reserved GDT blocks check"). Make sure there's not kernel crash, if resize an ext4 which resize_inode feature is ... | pass | pass | 2026-10-25 |  |
| ext4/271 |  | pass | pass | 2026-10-25 |  |
| ext4/306 | Test that blocks are available to non-extent files after a resize2fs Regression test for commit: c5c72d8 ext4: fix online resizing for ext3-compat file systems | pass | pass | 2026-10-25 |  |
| ext4/308 |  | pass | fail | 2026-10-25 | Needs EXT4_IOC_MOVE_EXT, the online defragmentation of ext4. |
| generic/001 | Random file copier to produce chains of identical files so the head and the tail can be diff'd at the end of each iteration. | no result | pass | 2026-10-26 |  |
| generic/003 | Tests the noatime, relatime, strictatime and nodiratime mount options. There is an extra check for Btrfs to ensure that the access time is never updated on ... | pass | pass | 2026-10-25 |  |
| generic/004 | Test O_TMPFILE opens, and linking them back into the namespace. | pass | not run | 2026-10-25 | O_TMPFILE is not supported |
| generic/008 | Makes calls to fallocate zero range and checks tossed ranges | pass | pass | 2026-10-25 |  |
| generic/009 | Test fallocate FALLOC_FL_ZERO_RANGE | pass | pass | 2026-10-25 |  |
| generic/012 | Multi collapse range tests This testcase is one of the 4 testcases which tries to test various corner cases for fcollapse range functionality over different ... | pass | pass | 2026-10-25 |  |
| generic/015 | check out-of-space behaviour | pass | pass | 2026-10-26 |  |
| generic/016 | Delayed allocation multi collapse range tests This testcase is one of the 4 testcases which tries to test various corner cases for fcollapse range ... | pass | pass | 2026-10-25 |  |
| generic/018 | Basic defragmentation sanity tests | pass | fail | 2026-10-26 | Needs EXT4_IOC_MOVE_EXT, the online defragmentation of ext4. |
| generic/020 | extended attributes | pass | pass | 2026-10-25 |  |
| generic/021 | Standard collapse range tests This testcase is one of the 4 testcases which tries to test various corner cases for fcollapse range functionality over different ... | pass | pass | 2026-10-25 |  |
| generic/022 | Delayed allocation collapse range tests This testcase is one of the 4 testcases which tries to test various corner cases for fcollapse range functionality over ... | pass | pass | 2026-10-25 |  |
| generic/023 | Check renameat2 syscall without flags | pass | pass | 2026-10-26 |  |
| generic/024 | Check renameat2 syscall with RENAME_NOREPLACE flag | pass | pass | 2026-10-26 |  |
| generic/025 | Check renameat2 syscall with RENAME_EXCHANGE flag | pass | pass | 2026-10-26 |  |
| generic/026 | Test out ACL count limits | no result | not run | 2026-10-26 | ext4 does not define maximum ACL count |
| generic/028 | The following commit introduced a race condition that causes getcwd(2) to return "/" instead of correct path | pass | pass | 2026-10-25 |  |
| generic/029 | Test mapped writes against truncate down/up to ensure we get the data correctly written. This can expose data corruption bugs on filesystems where the block ... | pass | pass | 2026-10-25 |  |
| generic/030 | Test mapped writes against remap+truncate down/up to ensure we get the data correctly written. This can expose data corruption bugs on filesystems where the ... | pass | pass | 2026-10-25 |  |
| generic/031 | Test non-aligned writes against fcollapse to ensure that partial pages are correctly written and aren't left behind causing invalidation or data corruption ... | pass | pass | 2026-10-25 |  |
| generic/032 | This test implements a data corruption scenario on XFS filesystems with sub-page sized blocks and unwritten extents. Inode lock contention during writeback of ... | fail | pass | 2026-10-25 |  |
| generic/033 | This test stresses indirect block reservation for delayed allocation extents. XFS reserves extra blocks for deferred allocation of delalloc extents. These ... | pass | pass | 2026-10-25 |  |
| generic/035 | Check overwriting rename system call | pass | pass | 2026-10-25 |  |
| generic/037 |  | pass | no result | - |  |
| generic/042 | Test stale data exposure via writeback using various file allocation modification commands. The presumption is that such commands result in partial writeback ... | pass | no result | - |  |
| generic/050 | Check out various mount/remount/unmount scenarious on a read-only blockdev. | pass | no result | - |  |
| generic/052 | To test log replay by shutdown of file system This is the first simple initial test to ensure that the goingdown ioctl is working and recovery of create ... | pass | no result | - |  |
| generic/053 | xfs_repair breaks acls | pass | pass | 2026-10-26 |  |
| generic/058 | Standard insert range tests This testcase is one of the 4 testcases which tries to test various corner cases for finsert range functionality over different ... | pass | pass | 2026-10-25 |  |
| generic/060 | Delayed allocation insert range tests This testcase is one of the 4 testcases which tries to test various corner cases for finsert range functionality over ... | pass | pass | 2026-10-25 |  |
| generic/061 | Multi insert range tests This testcase is one of the 4 testcases which tries to test various corner cases for finsert range functionality over different type ... | pass | pass | 2026-10-25 |  |
| generic/062 | Exercises the getfattr/setfattr tools Derived from tests originally written by Andreas Gruenbacher for ext2 | pass | no result | - |  |
| generic/063 | Delayed allocation multi insert range tests This testcase is one of the 4 testcases which tries to test various corner cases for finsert range functionality ... | pass | pass | 2026-10-25 |  |
| generic/064 | Test multiple fallocate insert/collapse range calls on same file. Call insert range on alternate blocks multiple times until the file is left with 50 extents ... | pass | pass | 2026-10-25 |  |
| generic/067 | Some random mount/umount corner case tests | pass | no result | - |  |
| generic/069 | Test out writes with O_APPEND flag sets. | pass | no result | - |  |
| generic/070 | fsstress incarnation testing extended attributes writes | pass | no result | - |  |
| generic/071 | Test extent pre-allocation (using fallocate) into a region that already has a pre-allocated extent that ends beyond the file's size. Verify that if the fs is ... | pass | no result | - |  |
| generic/075 | fsx (non-AIO variant) | pass | no result | - |  |
| generic/076 | Test blockdev reads in parallel with filesystem reads/writes | pass | no result | - |  |
| generic/078 | Check renameat2 syscall with RENAME_WHITEOUT flag | pass | no result | - |  |
| generic/079 | Run the t_immutable test program for immutable/append-only files. | pass | fail | 2026-10-25 | the output is not the expected output |
| generic/080 | Verify that mtime is updated when writing to mmap-ed pages | pass | pass | 2026-10-25 |  |
| generic/084 | Test hardlink to unlinked file. | pass | pass | 2026-10-25 |  |
| generic/086 | This test excercises the problem with unwritten and delayed extents in ext4 extent status tree where we might in some cases lose a block worth of data. Even ... | pass | pass | 2026-10-25 |  |
| generic/087 |  | pass | fail | 2026-10-25 | the output is not the expected output |
| generic/088 | test out CAP_DAC_OVERRIDE and CAP_DAC_SEARCH code in xfs_iaccess(ip,mode,cr) | pass | pass | 2026-10-25 |  |
| generic/091 | fsx exercising direct IO -- sub-block sizes and concurrent buffered IO | pass | pass | 2026-10-26 |  |
| generic/092 | fallocate/truncate tests with FALLOC_FL_KEEP_SIZE option. Verify if the disk space is released after truncating a file to i_size after writing to a portion of ... | pass | pass | 2026-10-25 |  |
| generic/094 | Run the fiemap (file extent mapping) tester with preallocation enabled | pass | pass | 2026-10-25 |  |
| generic/095 | Concurrent mixed I/O (buffer I/O, aiodio, mmap, splice) on the same files | pass | not run | 2026-10-25 | fio engine libaio not available |
| generic/096 | Exercise the situation that cause ext4 to BUG_ON() when we use zero range to zero a range which starts within the isize but ends past the isize but still in ... | pass | pass | 2026-10-25 |  |
| generic/097 | simple attr tests for EAs: - set - get - list - remove Basic testing. | pass | pass | 2026-10-25 |  |
| generic/098 |  | pass | pass | 2026-10-25 |  |
| generic/099 | Test out ACLs. | pass | pass | 2026-10-26 |  |
| generic/103 |  | pass | pass | 2026-10-25 |  |
| generic/105 | Test fix of bug: 930290 - xfs directory with no exec perm in ACL denies access and breaks CAPP evaluation which pulls out an earlier mod | pass | pass | 2026-10-26 |  |
| generic/112 | fsx (AIO variant, based on 075) | pass | pass | 2026-10-25 |  |
| generic/113 | aio-stress | pass | pass | 2026-10-25 |  |
| generic/114 | Test races while extending past EOF via sub-block AIO writes | pass | pass | 2026-10-25 |  |
| generic/117 | Attempt to cause filesystem corruption with serial fsstresses doing extended attributes writes - pv 940655 | pass | pass | 2026-10-25 |  |
| generic/120 | Test noatime mount option. | pass | pass | 2026-10-25 |  |
| generic/123 |  | pass | pass | 2026-10-26 |  |
| generic/124 |  | pass | pass | 2026-10-25 |  |
| generic/126 |  | pass | fail | 2026-10-25 | the output is not the expected output |
| generic/128 |  | no result | pass | 2026-10-26 | Passes since #214. Before, /dev/null had the mode 0644 and a user could not write to it. |
| generic/129 |  | pass | pass | 2026-10-25 |  |
| generic/130 |  | pass | fail | 2026-10-26 | the output is not the expected output |
| generic/131 |  | fail | fail | 2026-10-26 | the test stops with an error |
| generic/135 |  | pass | pass | 2026-10-26 |  |
| generic/141 |  | pass | pass | 2026-10-26 |  |
| generic/169 |  | pass | pass | 2026-10-26 |  |
| generic/184 | check mknod makes working nodes. | pass | pass | 2026-10-26 |  |
| generic/193 | Test permission checks in ->setattr | pass | pass | 2026-10-26 |  |
| generic/198 | Test that aio+dio into holes does completion at the proper offsets See also https://bugzilla.redhat.com/show_bug.cgi?id=217098 | pass | pass | 2026-10-26 |  |
| generic/207 | Run aio-dio-extend-stat - test race in dio aio completion | pass | pass | 2026-10-26 |  |
| generic/210 | Run aio-dio-subblock-eof-read - test AIO read of last block of DIO file | pass | pass | 2026-10-26 |  |
| generic/211 | Test that overwriting a file with mmap when the filesystem has no more space available for data allocation works. The motivation here is to check that NOCOW ... | pass | pass | 2026-10-26 |  |
| generic/212 | Run aio-io-setup-with-nonwritable-context-pointer - Test what happens when a non-writable context pointer is passed to io_setup | pass | pass | 2026-10-26 |  |
| generic/213 | Check some unwritten extent boundary conditions, fallocate version. | pass | fail | 2026-10-26 | fsck finds an error |
| generic/214 | Basic unwritten extent sanity checks | pass | pass | 2026-10-26 |  |
| generic/215 | Test out c/mtime updates after mapped writes. | pass | pass | 2026-10-26 |  |
| generic/219 | Simple quota accounting test for direct/buffered/mmap IO. | no result | not run | 2026-10-26 | Quota user tools not installed |
| generic/221 | Check ctime updates when calling futimens without UTIME_OMIT for the mtime entry. | pass | pass | 2026-10-26 |  |
| generic/225 | Run the fiemap (file extent mapping) tester | pass | pass | 2026-10-26 |  |
| generic/228 | Check if fallocate respects RLIMIT_FSIZE | pass | fail | 2026-10-26 | the output is not the expected output |
| generic/230 | Simple quota enforcement test. | no result | not run | 2026-10-26 | Quota user tools not installed |
| generic/235 | Test whether quota gets properly reenabled after remount read-write | no result | not run | 2026-10-26 | Quota user tools not installed |
| generic/236 | Check ctime updated or not if file linked See also http://marc.info/?l=linux-btrfs&m=127434439020230&w=2 | pass | pass | 2026-10-26 |  |
| generic/237 | Check user B can setfacl a file which belongs to user A See also http://marc.info/?l=linux-btrfs&m=127434445620298&w=2 | pass | pass | 2026-10-26 |  |
| generic/240 | Test that non-block-aligned aio+dio into holes does not leave zero'd out portions of the file | pass | pass | 2026-10-26 |  |
| generic/245 | Check that directory renames onto non-empty targets fail | pass | pass | 2026-10-26 |  |
| generic/246 | Check that truncation after failed writes does not zero too much data. | pass | pass | 2026-10-26 |  |
| generic/247 | Test for race between direct I/O and mmap | pass | pass | 2026-10-26 |  |
| generic/248 | Test for pwrite hang problem when writing from mmaped buffer of the same page | pass | pass | 2026-10-26 |  |
| generic/249 | simple splice(2) test. | pass | pass | 2026-10-26 |  |
| generic/250 | Create an unwritten extent, set up dm-error, try a DIO write, then make sure we can't read back old disk contents. | fail | not run | 2026-10-26 | This test requires dm error support |
| generic/252 | Create an unwritten extent, set up dm-error, try an AIO DIO write, then make sure we can't read back old disk contents. | fail | not run | 2026-10-26 | This test requires dm error support |
| generic/255 | Test Generic fallocate hole punching | pass | pass | 2026-10-26 |  |
| generic/256 | Test Full File System Hole Punching | pass | fail | 2026-10-26 | A full disk leaked the blocks of a write when the extent tree needed a new block. The fix is in progress. |
| generic/257 |  | pass | pass | 2026-10-26 |  |
| generic/258 | Test timestamps prior to epoch On 64-bit, ext2/3/4 was sign-extending when read from disk See also commit 4d7bf11d649c72621ca31b8ea12b9c94af380e63 | pass | pass | 2026-10-26 |  |
| generic/260 | Purpose of this test is to check FITRIM argument handling to make sure that the argument processing is right and that it does not overflow. | pass | fail | 2026-10-26 | the test stops with an error |
| generic/263 | fsx exercising direct IO vs sub-block buffered I/O | pass | fail | 2026-10-26 | the test stops with an error |
| generic/277 | Check if ctime update caused by chattr is written to disk | pass | pass | 2026-10-26 |  |
| generic/285 | SEEK_DATA/SEEK_HOLE sanity tests. | no result | pass | 2026-10-25 |  |
| generic/286 | SEEK_DATA/SEEK_HOLE copy tests. | pass | pass | 2026-10-26 |  |
| generic/288 | This check the FITRIM argument handling in the corner case where length is smaller than block size or zero. | pass | fail | 2026-10-26 | the output is not the expected output |
| generic/294 | Tests for EEXIST (not EROFS) for inode creations, if we ask to create an already-existing entity on an RO filesystem | pass | fail | 2026-10-26 | the output is not the expected output |
| generic/305 | Ensure that quota charges us for reflinking a file and that we're not charged for buffered copy on write. | no result | not run | 2026-10-26 | Reflink not supported by scratch filesystem type: ext4 |
| generic/306 | Test RW open of a device on a RO fs | pass | fail | 2026-10-26 | the output is not the expected output |
| generic/307 | Check if ctime is updated and written to disk after setfacl | pass | pass | 2026-10-26 |  |
| generic/308 | Regression test for commit: f17722f ext4: Fix max file size and logical block counting of extent format file | pass | pass | 2026-10-26 |  |
| generic/309 | Test directory mtime and ctime are updated when moving a file onto an existing file in the directory | pass | pass | 2026-10-26 |  |
| generic/313 | Check ctime and mtime are updated on truncate(2) and ftruncate(2) | pass | pass | 2026-10-26 |  |
| generic/314 | Test SGID inheritance on subdirectories | pass | pass | 2026-10-26 |  |
| generic/315 | fallocate/truncate tests with FALLOC_FL_KEEP_SIZE option. Verify if the disk space is released after truncating a file back to the old smaller size. Before ... | pass | pass | 2026-10-26 |  |
| generic/316 | Test Generic fallocate hole punching w/o unwritten extent | pass | pass | 2026-10-26 |  |
| generic/317 | Check uid/gid to/from disk with a user namespace. A new file will be created from inside a userns. We check that the uid/gid is correct from both inside the ... | pass | not run | 2026-10-26 | This test requires procfs uid_map support. |
| generic/318 | Check get/set ACLs to/from disk with a user namespace. A new file will be created and ACLs set on it from both inside a userns and from init_user_ns. We check ... | pass | not run | 2026-10-26 | This test requires procfs uid_map support. |
| generic/319 | Regression test to make sure a directory inherits the default ACL from its parent directory. This test was motivated by an issue reported by a btrfs user. That ... | pass | pass | 2026-10-26 |  |
| generic/324 | Sanity check for defrag utility. | pass | pass | 2026-10-26 |  |
| generic/326 | Ensure that quota charges us for reflinking a file and that we're not charged for directio copy on write. | no result | not run | 2026-10-26 | Reflink not supported by scratch filesystem type: ext4 |
| generic/327 | Ensure that we can't go over the hard block limit when reflinking. | no result | not run | 2026-10-26 | Reflink not supported by scratch filesystem type: ext4 |
| generic/328 | Ensure that we can't go over the hard block limit when CoWing a file. | no result | not run | 2026-10-26 | Reflink not supported by scratch filesystem type: ext4 |
| generic/337 |  | pass | pass | 2026-10-26 |  |
| generic/338 | Test I/O on dm error device. | fail | not run | 2026-10-26 | This test requires dm error support |
| generic/346 |  | pass | pass | 2026-10-26 |  |
| generic/355 | Test clear of suid/sgid on direct write. | pass | pass | 2026-10-26 |  |
| generic/360 | Test symlink to very long path, check symlink file contains correct path. | pass | pass | 2026-10-26 |  |
| generic/361 | Test remount on I/O errors. | pass | not run | 2026-10-26 | This test requires loopback device support |
| generic/362 | Test that doing a direct IO append write to a file when the input buffer was not yet faulted in, does not result in an incorrect file size. | pass | pass | 2026-10-26 |  |
| generic/364 | Test that a program that has 2 threads using the same file descriptor and concurrently doing direct IO writes and fsync doesn't trigger any crash or deadlock. | pass | pass | 2026-10-26 |  |
| generic/366 | Test if mixed direct read, direct write and buffered write on the same file will hang the filesystem. | pass | not run | 2026-10-26 | fio engine libaio not available |
| generic/371 | Run write(2) and fallocate(2) in parallel and the total needed data space for these operations don't exceed whole fs free data space, to see whether we will ... | pass | fail | 2026-10-26 | the output is not the expected output |
| generic/375 | Check if SGID is cleared upon chmod / setfacl when the owner is not in the owning group. | pass | pass | 2026-10-26 |  |
| generic/377 |  | pass | pass | 2026-10-26 |  |
| generic/378 | Simple permission check on hard links. | pass | pass | 2026-10-26 |  |
| generic/381 | Test xfs_quota when user or names beginning with digits. For example, create a 'limit' for a user or group named '12345678-abcd', then query this user and ... | no result | not run | 2026-10-26 | Quota user tools not installed |
| generic/382 | When default quota is set, all different quota types inherits the same default value, include group quota. So if a user quota limit larger than the default ... | no result | not run | 2026-10-26 | Quota user tools not installed |
| generic/389 | Test if O_TMPFILE files inherit POSIX Default ACLs when they are linked into the namespace. | pass | not run | 2026-10-26 | O_TMPFILE is not supported |
| generic/391 | Test two threads doing non-overlapping direct I/O in the same extents. Motivated by a bug in Btrfs' direct I/O get_block function which would lead to spurious ... | pass | pass | 2026-10-26 |  |
| generic/392 | Test inode's metadata after fsync or fdatasync calls. In the case of fsync, filesystem should recover all the inode metadata, while recovering for fdatasync it ... | pass | pass | 2026-10-26 |  |
| generic/393 | Test some small truncations to check inline_data and its cached data are truncated correctly at the same time. | pass | pass | 2026-10-26 |  |
| generic/394 | Make sure fs honors file size resource limit. | pass | fail | 2026-10-26 | the output is not the expected output |
| generic/395 | Test setting and getting encryption policies. | pass | not run | 2026-10-26 | kernel is unaware of ext4 encryption feature, or mkfs options are not compatible with ... |
| generic/396 | Test that FS_IOC_SET_ENCRYPTION_POLICY correctly validates the fscrypt_policy structure that userspace passes to it. | pass | not run | 2026-10-26 | kernel is unaware of ext4 encryption feature, or mkfs options are not compatible with ... |
| generic/401 |  | pass | pass | 2026-10-26 |  |
| generic/402 | Test to verify filesystem timestamps for supported ranges. | pass | not run | 2026-10-26 | Test requires writable /dev/kmsg. |
| generic/403 | Test racing getxattr requests against large xattr add and remove loop. This reproduces a bug on XFS where a getxattr of an existing attribute spuriously ... | pass | pass | 2026-10-26 |  |
| generic/404 | Regression test which targets two nasty ext4 bugs in a logic which shifts extents: | pass | pass | 2026-10-26 |  |
| generic/406 | If a larger dio write (size >= 128M) got splitted, the assertion in endio would complain (CONFIG_BTRFS_ASSERT is required). | pass | pass | 2026-10-26 |  |
| generic/409 | Test mount shared subtrees, verify the bind semantics: | pass | fail | 2026-10-26 | the output is not the expected output |
| generic/410 | Test mount shared subtrees, verify the state transition when use: --make-shared --make-slave --make-private --make-unbindable | pass | pass | 2026-10-26 |  |
| generic/411 | This test cover linux commit 7ae8fd0, kernel two mnt_group_id == 0 (no peer)vfsmount as peers. It case kernel dereference a NULL address. | pass | pass | 2026-10-26 |  |
| generic/412 |  | pass | pass | 2026-10-25 |  |
| generic/417 | Test orphan inode / unlinked list processing on RO mount & RW transition | pass | not run | 2026-10-25 | ext4 does not support shutdown |
| generic/420 | Verify fallocate(mode=FALLOC_FL_KEEP_SIZE/FALLOC_FL_PUNCH_HOLE) does not alter the file size. | pass | pass | 2026-10-25 |  |
| generic/422 | Test that a filesystem's implementation of the stat(2) system call reports correct values for the number of blocks allocated for a file when there are delayed ... | pass | pass | 2026-10-25 |  |
| generic/423 | Test the statx system call | pass | pass | 2026-10-25 |  |
| generic/424 | Test the statx stx_attribute flags that can be set with chattr | pass | pass | 2026-10-25 |  |
| generic/425 | Check that FIEMAP produces some output when we require an external block to hold extended attributes. | pass | not run | 2026-10-25 | xfs_io fiemap -a failed (old kernel/wrong fs/bad args?) |
| generic/426 | Check stale handles pointing to unlinked files and non-stale handles pointing to linked files | pass | not run | 2026-10-25 | ext4 does not support NFS export |
| generic/427 | Try to trigger a race of free eofblocks and file extending dio writes. A known bug of XFS has been fixed by "e4229d6 xfs: fix eofblocks race with file ... | pass | pass | 2026-10-26 |  |
| generic/428 | This is a regression test for kernel patch: dax: fix data corruption due to stale mmap reads created by Ross Zwisler <ross.zwisler@linux.intel.com> | pass | pass | 2026-10-25 |  |
| generic/430 | Tests vfs_copy_file_range(): - Copy a file - Copy beginning of original to new file - Copy middle of original to a new file - Copy end of original to new file ... | pass | pass | 2026-10-25 |  |
| generic/431 | Tests vfs_copy_file_range(): - Copy a small file - Small copies from various points in the original file | pass | pass | 2026-10-25 |  |
| generic/432 | Tests vfs_copy_file_range(): - Copy a file - Use copy to swap data at beginning and end - Use copy to swap data in the middle - Use copy to simultaneously ... | pass | pass | 2026-10-25 |  |
| generic/433 | Tests vfs_copy_file_range(): - Copy a small file - Use copy to swap data at beginning and end - Use copy to swap data in the middle - Use copy to swap data in ... | pass | pass | 2026-10-25 |  |
| generic/434 | Tests vfs_copy_file_range() error checking | pass | pass | 2026-10-26 |  |
| generic/436 | More SEEK_DATA/SEEK_HOLE sanity tests. | pass | pass | 2026-10-26 |  |
| generic/437 | This is a regression test for kernel patches: mm: avoid spurious 'bad pmd' warning messages dax: Fix race between colliding PMD & PTE entries created by Ross ... | pass | pass | 2026-10-25 |  |
| generic/439 | Test that if we punch a hole in a file, with either a range that goes beyond the file's size or covers a file range that is already a hole, and that if after ... | pass | pass | 2026-10-25 |  |
| generic/441 | Open a file several times, write to it, fsync on all fds and make sure that they all return 0. Change the device to start throwing errors. Write again on all ... | fail | not run | 2026-10-25 | This test requires dm error support |
| generic/443 | Takes page fault while writev is iterating over the vectors in the IOV | pass | pass | 2026-10-25 |  |
| generic/444 | Check if SGID is inherited when creating a subdirectory when the owner is not in the owning group and directory has default ACLs. | pass | pass | 2026-10-26 |  |
| generic/445 | Another SEEK_DATA/SEEK_HOLE sanity test. | pass | pass | 2026-10-26 |  |
| generic/446 | Regression test for commit: 04197b3 ("xfs: don't BUG() on mixed direct and mapped I/O") | pass | pass | 2026-10-25 |  |
| generic/448 | Check what happens when SEEK_HOLE/SEEK_DATA are fed negative offsets. | pass | pass | 2026-10-26 |  |
| generic/449 | Fill the device and set as many extended attributes to a file as possible. Then call setfacl on it and, if this fails for lack of space, test that the ... | pass | pass | 2026-10-26 |  |
| generic/450 | Test read around EOF. If the file offset is at or past the end of file, no bytes are read, and read() returns zero. There was a bug, when DIO read offset is ... | pass | pass | 2026-10-25 |  |
| generic/451 | Test data integrity when mixing buffered reads and asynchronous direct writes a file. | pass | pass | 2026-10-25 |  |
| generic/452 | This is a regression test for kernel patch: commit fd96b8da68d3 ("ext4: fix fault handling when mounted with -o dax,ro") created by Ross Zwisler ... | pass | pass | 2026-10-25 |  |
| generic/453 | Create a directory with multiple filenames that all appear the same (in unicode, anyway) but point to different inodes. In theory all Linux filesystems should ... | pass | pass | 2026-10-25 |  |
| generic/454 | Create xattrs with multiple keys that all appear the same (in unicode, anyway) but point to different values. In theory all Linux filesystems should allow this ... | pass | pass | 2026-10-25 |  |
| generic/460 | Test that XFS reserves reasonable indirect blocks for delalloc and speculative allocation, and doesn't cause any fdblocks corruption. | pass | pass | 2026-10-26 |  |
| generic/462 | This is a regression test for kernel commit ef947b2 x86, mm: fix gup_pte_range() vs DAX mappings created by Jeffrey Moyer <jmoyer@redhat.com> | no result | not run | 2026-10-26 | /dev/vdb ext4 does not support -o dax |
| generic/465 | Test i_size is updated properly under dio read/write | pass | pass | 2026-10-25 |  |
| generic/466 | Check that high-offset reads and writes work. | pass | pass | 2026-10-26 |  |
| generic/467 | Check open by file handle. This is a variant of test generic/426 that tests with less files and more use cases: - open directory by file handle - verify ... | pass | not run | 2026-10-25 | ext4 does not support NFS export |
| generic/468 | This testcase is a fallocate variant of generic/392, it expands to test block preallocation functionality of fallocate. In this case, we are trying to execute ... | pass | not run | 2026-10-25 | ext4 does not support shutdown |
| generic/469 | Test that mmap read doesn't see non-zero data past EOF on truncate down. | pass | pass | 2026-10-26 |  |
| generic/471 | Test that if names are added to a directory after an opendir(3) call and before a rewinddir(3) call, future readdir(3) calls will return the names. This is ... | pass | pass | 2026-10-25 |  |
| generic/472 | Test various swapfile activation oddities. | pass | pass | 2026-10-26 |  |
| generic/473 | Test for the new ranged query functionality in xfs_io's fiemap command. This tests various combinations of hole + data layout being printed. Also the test used ... | no result | pass | 2026-10-25 |  |
| generic/474 | Inspired by syncfs bug of overlayfs which does not sync dirty inodes in underlying filesystem. | pass | not run | 2026-10-25 | ext4 does not support shutdown |
| generic/477 | Check open by file handle after cycle mount. | pass | not run | 2026-10-25 | ext4 does not support NFS export |
| generic/478 | Test OFD lock. fcntl F_OFD_SETLK to set lock, then F_OFD_GETLK to verify we are being given correct advice by kernel. | pass | pass | 2026-10-26 |  |
| generic/484 | Open a file and write to it and fsync. Then, flip the data device to throw errors, write to it again and do an fdatasync. Then open an O_RDONLY fd on the same ... | fail | not run | 2026-10-25 | This test requires dm error support |
| generic/485 | Regression test for: 349fa7d6e193 ("ext4: prevent right-shifting extents beyond EXT_MAX_BLOCKS") 7d83fb14258b ("xfs: prevent creating negative-sized file via ... | pass | pass | 2026-10-25 |  |
| generic/486 | Ensure that we can XATTR_REPLACE a tiny attr into a large attr. Kanda Motohiro <kanda.motohiro@gmail.com> reports that XATTR_REPLACE'ing a single-byte attr ... | pass | pass | 2026-10-25 |  |
| generic/488 | Test having many file descriptors referring to deleted files open. Regression test for patch "Btrfs: fix ENOSPC caused by orphan items reservations". | pass | pass | 2026-10-26 |  |
| generic/490 | Check that SEEK_DATA works properly for offsets in the middle of large holes. This was broken for ext4 with indirect-block based files and this test checks for ... | pass | pass | 2026-10-26 |  |
| generic/491 | Test first read with freeze right after mount. | pass | not run | 2026-10-25 | ext4 does not support freezing |
| generic/492 | Test the online filesystem label set/get ioctls | pass | not run | 2026-10-25 | xfs_io label failed (old kernel/wrong fs?) |
| generic/494 | Test truncation/hole punching of an active swapfile. | pass | pass | 2026-10-26 |  |
| generic/495 | Test invalid swap file (with holes) | pass | pass | 2026-10-26 |  |
| generic/496 | Test various swapfile activation oddities on filesystems that support fallocated swapfiles (for given fs ext4/xfs) | pass | pass | 2026-10-26 |  |
| generic/497 | Test various swapfile activation oddities, having used fcollapse to create discontiguous ranges in the file. | pass | pass | 2026-10-26 |  |
| generic/499 | Test a specific sequence of fsx operations that causes an mmap read past eof to return nonzero contents. | pass | fail | 2026-10-25 | the output is not the expected output |
| generic/503 | This is a regression test for kernel patch: ext4: handle layout changes to pinned DAX mapping | pass | pass | 2026-10-25 |  |
| generic/505 | This testcase is trying to test recovery flow of generic filesystem, w/ below steps, once uid or gid changes, after we fsync that file, we can expect that ... | pass | not run | 2026-10-25 | ext4 does not support shutdown |
| generic/507 | This testcase is trying to test recovery flow of generic filesystem, w/ below steps, once i_flags changes, after we fsync that file, we can expect that i_flags ... | pass | not run | 2026-10-25 | ext4 does not support shutdown |
| generic/508 | This testcase is trying to test recovery flow of generic filesystem, it needs creation time support on specified filesystem. With below steps, once the file is ... | pass | not run | 2026-10-25 | ext4 does not support shutdown |
| generic/511 | Test a specific sequence of fsx operations that causes an mmap read past eof to return nonzero contents. | pass | fail | 2026-10-25 | the output is not the expected output |
| generic/514 | Ensure that file size resource limits are respected when reflinking. | no result | not run | 2026-10-26 | Reflink not supported by scratch filesystem type: ext4 |
| generic/519 | Verify if there's physical address overlap returned by FIBMAP, cover: 79b3dbe4adb3 fs: fix iomap_bmap position calculation | pass | pass | 2026-10-25 |  |
| generic/523 | Check that xattrs can have slashes in their name. | pass | pass | 2026-10-25 |  |
| generic/524 | Test XFS page writeback code for races with the cached file mapping. XFS caches the file -> block mapping for a full extent once it is initially looked up. The ... | pass | pass | 2026-10-26 |  |
| generic/528 | Check that statx btime (aka creation time) is plausibly close to when we created a file. A bug caught during code review of xfs patches revealed that there ... | pass | not run | 2026-10-25 | inode creation time not supported by this filesystem |
| generic/529 | Regression test for a bug where XFS corrupts memory if the listxattr buffer is a particularly well crafted size on a filesystem that supports posix acls. | pass | pass | 2026-10-26 |  |
| generic/530 | Stress test creating a lot of unlinked O_TMPFILE files and recovering them after a crash, checking that we don't blow up the filesystem. This is sort of a ... | pass | not run | 2026-10-25 | ext4 does not support shutdown |
| generic/531 | Stress test creating a lot of unlinked O_TMPFILE files and closing them all at once, checking that we don't blow up the filesystem. This is sort of a ... | pass | not run | 2026-10-25 | O_TMPFILE is not supported |
| generic/532 | Regression test for a bug where XFS fails to set statx attributes_mask but sets attribute flags anyway, which is fixed by commit 1b9598c8fb99 ("xfs: fix ... | pass | pass | 2026-10-25 |  |
| generic/533 | Simple attr smoke tests for user EAs, dereived from generic/097. | pass | pass | 2026-10-25 |  |
| generic/536 | Test a some write patterns for stale data exposure after a crash. XFS is historically susceptible to this problem in the window between delalloc to physical ... | pass | not run | 2026-10-25 | ext4 does not support shutdown |
| generic/537 | Ensure that we can't call fstrim on filesystems mounted norecovery, because FSTRIM implementations use free space metadata to drive the discard requests and we ... | pass | not run | 2026-10-25 | FSTRIM not supported |
| generic/538 | Non-block-aligned direct AIO write test with an initial truncate i_size. | pass | pass | 2026-10-25 |  |
| generic/539 | Check that SEEK_HOLE can find a punched hole. | pass | pass | 2026-10-26 |  |
| generic/545 | Check that we can't set the FS_APPEND_FL and FS_IMMUTABLE_FL inode flags without capbility CAP_LINUX_IMMUTABLE | no result | not run | 2026-10-25 | capsh utility required, skipped this test |
| generic/553 | Check that we cannot copy_file_range() to an immutable file | pass | pass | 2026-10-25 |  |
| generic/554 | Check that we cannot copy_file_range() to a swapfile | pass | pass | 2026-10-26 |  |
| generic/556 | Test the basic functionality of filesystems with case-insensitive support. | pass | not run | 2026-10-25 | ext4 does not support casefold feature |
| generic/566 | Regression test for chgrp returning to userspace with ILOCK held after a hard quota error. This causes the filesystem to hang if kernel is not patched. | no result | not run | 2026-10-26 | Quota user tools not installed |
| generic/567 | Test mapped writes against punch-hole to ensure we get the data correctly written. This can expose data corruption bugs on filesystems where the block size is ... | pass | pass | 2026-10-25 |  |
| generic/568 | Test that fallocating an unaligned range allocates all blocks touched by that range | pass | pass | 2026-10-25 |  |
| generic/569 | Check that we can't modify a file that's an active swap file. | pass | fail | 2026-10-26 | A write to a mapped swap file must give SIGBUS. This needs a reverse map to write protect the pages. |
| generic/571 |  | fail | not run | 2026-10-25 | Require fcntl setlease support |
| generic/573 | Test access controls on the fs-verity ioctls. FS_IOC_MEASURE_VERITY is allowed on any file, whereas FS_IOC_ENABLE_VERITY requires write access. | no result | not run | 2026-10-26 | fsverity utility required, skipped this test |
| generic/578 | Make sure that we can handle multiple mmap writers to the same file. | no result | not run | 2026-10-25 | Reflink not supported by test filesystem type: ext4 |
| generic/580 | Basic test of the fscrypt filesystem-level encryption keyring and v2 encryption policies. | pass | not run | 2026-10-25 | kernel is unaware of ext4 encryption feature, or mkfs options are not compatible with ... |
| generic/581 | Test non-root use of the fscrypt filesystem-level encryption keyring and v2 encryption policies. | pass | not run | 2026-10-26 | kernel is unaware of ext4 encryption feature, or mkfs options are not compatible with ... |
| generic/582 | Verify ciphertext for v2 encryption policies that use AES-256-XTS to encrypt file contents and AES-256-CTS-CBC to encrypt file names. | pass | not run | 2026-10-25 | kernel is unaware of ext4 encryption feature, or mkfs options are not compatible with ... |
| generic/583 | Verify ciphertext for v2 encryption policies that use AES-128-CBC-ESSIV to encrypt file contents and AES-128-CTS-CBC to encrypt file names. | not run | not run | 2026-10-25 | kernel is unaware of ext4 encryption feature, or mkfs options are not compatible with ... |
| generic/584 | Verify ciphertext for v2 encryption policies that use Adiantum to encrypt file contents and file names. | not run | not run | 2026-10-25 | kernel is unaware of ext4 encryption feature, or mkfs options are not compatible with ... |
| generic/586 | Race an appending aio dio write to the second block of a file while simultaneously fallocating to the first block. Make sure that we end up with a two-block ... | pass | pass | 2026-10-25 |  |
| generic/587 | Regression test to ensure that dquots are attached to the inode when we're performing unwritten extent conversion after a directio write and the extent mapping ... | no result | not run | 2026-10-26 | Quota user tools not installed |
| generic/591 | Test using splice() to read from pipes. | pass | pass | 2026-10-25 |  |
| generic/592 | Verify ciphertext for v2 encryption policies that use the IV_INO_LBLK_64 flag and use AES-256-XTS to encrypt file contents and AES-256-CTS-CBC to encrypt file ... | pass | not run | 2026-10-25 | kernel is unaware of ext4 encryption feature, or mkfs options are not compatible with ... |
| generic/597 | Test protected_symlink and protected_hardlink sysctls | pass | not run | 2026-10-26 | fs.protected_symlinks sysctl unavailable |
| generic/598 | Test protected_regular and protected_fifos sysctls | pass | not run | 2026-10-25 | fs.protected_regular sysctl unavailable |
| generic/599 | Test data integrity for ro remount. | pass | not run | 2026-10-25 | ext4 does not support shutdown |
| generic/602 | Verify ciphertext for v2 encryption policies that use the IV_INO_LBLK_32 flag and use AES-256-XTS to encrypt file contents and AES-256-CTS-CBC to encrypt file ... | pass | not run | 2026-10-25 | kernel is unaware of ext4 encryption feature, or mkfs options are not compatible with ... |
| generic/604 | Evicting dirty inodes can take a long time during umount. Check that a new mount racing with such a delayed umount succeeds. | pass | pass | 2026-10-25 |  |
| generic/607 | Verify the inheritance behavior of FS_XFLAG_DAX flag in various combinations. 1) New files and directories automatically inherit FS_XFLAG_DAX from their parent ... | pass | not run | 2026-10-25 | xfs_io chattr +x failed (old kernel/wrong fs?) |
| generic/609 | iomap can call generic_write_sync() if we're O_DSYNC, so write a basic test to exercise O_DSYNC so any unsuspecting file systems will get lockdep warnings if ... | pass | pass | 2026-10-25 |  |
| generic/610 | Test a fallocate() zero range operation against a large file range for which there are many small extents allocated. Verify the operation does not fail and the ... | pass | pass | 2026-10-25 |  |
| generic/611 | Verify that metadata won't get corrupted when extended attribute name of size one is set. | pass | pass | 2026-10-25 |  |
| generic/614 | Test that after doing a memory mapped write to an empty file, a call to stat(2) reports a non-zero number of used blocks. | pass | not run | 2026-10-25 | test requires delayed allocation buffered writes |
| generic/615 | Test that if we keep overwriting an entire file, either with buffered writes or direct IO writes, the number of used blocks reported by stat(2) is never zero ... | pass | pass | 2026-10-26 |  |
| generic/618 | Verify that forkoff can be returned as 0 properly if it isn't able to fit inline for XFS. However, this test is fs-neutral and can be done quickly so leave it ... | pass | pass | 2026-10-26 |  |
| generic/621 | Test for a race condition where a duplicate filename could be created in an encrypted directory while the directory's encryption key was being added ... | pass | not run | 2026-10-26 | kernel is unaware of ext4 encryption feature, or mkfs options are not compatible with ... |
| generic/623 | Test a write fault scenario on a shutdown fs. | pass | not run | 2026-10-26 | xfs_io shutdown failed (old kernel/wrong fs?) |
| generic/626 | Test RENAME_WHITEOUT on filesystem without space to create one more inodes. This is a regression test for kernel commit: 6b4b8e6b4ad8 ("ext4: ext4: fix bug for ... | pass | pass | 2026-10-26 |  |
| generic/629 | Make sure that copy_file_range forces the log out if we open the file with O_SYNC or set FS_XFLAG_SYNC on the file. We test that it actually forced the log by ... | fail | not run | 2026-10-26 | This test requires dm error support |
| generic/632 | Regression test to verify that creating a series of detached mounts, attaching them to the filesystem, and unmounting them does not trigger an integer overflow ... | pass | pass | 2026-10-26 |  |
| generic/633 | Test that idmapped mounts behave correctly. | pass | fail | 2026-10-26 | Needs io_uring. |
| generic/634 | Make sure we can store and retrieve timestamps on the extremes of the date ranges supported by userspace, and the common places where overflows can happen. | pass | pass | 2026-10-26 |  |
| generic/635 | Make sure we can store and retrieve timestamps on the extremes of the date ranges supported by userspace, and the common places where overflows can happen ... | pass | not run | 2026-10-26 | ext4 does not support shutdown |
| generic/636 | Test invalid swap files. Empty swap file (only swap header) | pass | pass | 2026-10-26 |  |
| generic/637 |  | pass | pass | 2026-10-26 |  |
| generic/638 | This case mmaps several pages of a file, alloc pages, copy data with pages overlapping, e.g: +-----------------------+ / (copy) / / V ... | pass | pass | 2026-10-26 |  |
| generic/639 | Open a file and write a little data to it. Unmount (to clean out the cache) and then mount again. Then write some data to it beyond the EOF and ensure the ... | pass | pass | 2026-10-26 |  |
| generic/641 | Test small swapfile which doesn't contain even a single page-aligned contiguous range of blocks. This case covered commit 5808fecc5723 ("iomap: Fix negative ... | pass | fail | 2026-10-26 | the test stops with an error |
| generic/644 | Test that fscaps on idmapped mounts behave correctly. | pass | not run | 2026-10-26 | kernel does not support mount_setattr syscall |
| generic/646 | Testcase for kernel commit: 50d25484bebe xfs: sync lazy sb accounting on quiesce of read-only mounts | pass | not run | 2026-10-26 | ext4 does not support shutdown |
| generic/647 | Trigger page faults in the same file during read and write | pass | pass | 2026-10-26 |  |
| generic/676 | Test that filesystem properly handles seeking in directory both to valid and invalid positions. | pass | pass | 2026-10-26 |  |
| generic/678 | Test doing a read, with io_uring, over a file range that includes multiple extents. The read operation triggers page faults when accessing all pages of the ... | pass | not run | 2026-10-26 | kernel does not support IO_URING |
| generic/679 | Test that if we call fallocate against a file range that has a mix of holes and written extents, the fallocate succeeds if the filesystem has enough free space ... | pass | pass | 2026-10-26 |  |
| generic/680 | Test for the Dirty Pipe vulnerability (CVE-2022-0847) caused by an uninitialized "pipe_buffer.flags" variable, which fixed by: 9d2231c5d74e ("lib/iov_iter ... | pass | not run | 2026-10-26 | fsgqa cannot execute commands. |
| generic/683 | Functional test for dropping suid and sgid bits as part of a fallocate. | pass | not run | 2026-10-26 | fsgqa cannot execute commands. |
| generic/684 | Functional test for dropping suid and sgid bits as part of a fpunch. | pass | not run | 2026-10-26 | fsgqa cannot execute commands. |
| generic/685 | Functional test for dropping suid and sgid bits as part of a fzero. | pass | not run | 2026-10-26 | fsgqa cannot execute commands. |
| generic/686 | Functional test for dropping suid and sgid bits as part of a finsert. | pass | not run | 2026-10-26 | fsgqa cannot execute commands. |
| generic/687 | Functional test for dropping suid and sgid bits as part of a fcollapse. | pass | not run | 2026-10-26 | fsgqa cannot execute commands. |
| generic/689 | Test that setting POSIX ACLs in userns-mountable filesystems works. | pass | not run | 2026-10-26 | kernel does not support mount_setattr syscall |
| generic/693 | Verify ciphertext for v2 encryption policies that use AES-256-XTS to encrypt file contents and AES-256-HCTR2 to encrypt file names. | not run | not run | 2026-10-26 | kernel is unaware of ext4 encryption feature, or mkfs options are not compatible with ... |
| generic/696 | Test S_ISGID stripping whether works correctly when call process uses umask(S_IXGRP). | pass | pass | 2026-10-26 | Passes since #212. |
| generic/697 | Test S_ISGID stripping whether works correctly when call process uses posix acl. | pass | not run | 2026-10-26 | ACLs not supported by this filesystem type: ext4 |
| generic/706 | Test that seeking for data on a 1 byte file works correctly, the returned offset should be 0 if the start offset is 0. | pass | pass | 2026-10-26 |  |
| generic/708 | Test iomap direct_io partial writes. | pass | pass | 2026-10-26 |  |
| generic/728 | Test a bug where the NFS client wasn't sending a post-op GETATTR to the server after setting an xattr, resulting in `stat` reporting a stale ctime. | pass | pass | 2026-10-26 |  |
| generic/729 | Trigger page faults in the same file during read and write | pass | pass | 2026-10-26 |  |
| generic/732 | Mount the same export to different mount points and move (rename) files among those mount points. This simple test recently unveils an ancient nfsd bug that is ... | pass | pass | 2026-10-26 |  |
| generic/735 | Append writes to a file with logical block numbers close to 0xffffffff and observe if a kernel crash is caused by ext4_lblk_t overflow triggering BUG_ON at ... | pass | pass | 2026-10-26 |  |
| generic/736 | Test that on a fairly large directory if we keep renaming files while holding the directory open and doing readdir(3) calls, we don't end up in an infinite ... | pass | pass | 2026-10-26 |  |
| generic/737 | Integrity test for O_SYNC with buff-io, dio, aio-dio with sudden shutdown. Based on a testcase reported by Gao Xiang <hsiangkao@linux.alibaba.com> | pass | not run | 2026-10-26 | ext4 does not support shutdown |
| generic/738 | Test possible deadlock of umount and reclaim memory when there are EOF blocks in files. | pass | not run | 2026-10-26 | ext4 does not support freezing |
| generic/739 | Verify the on-disk format of encrypted files that use a crypto data unit size that differs from the filesystem block size. This tests the functionality that ... | pass | not run | 2026-10-26 | kernel is unaware of ext4 encryption feature, or mkfs options are not compatible with ... |
| generic/742 | Test fiemap into an mmaped buffer of the same file | pass | pass | 2026-10-26 |  |
| generic/748 | Repeatedly prealloc beyond i_size, set an xattr, direct write into the prealloc while extending i_size, then fdatasync. This is a regression test for a Btrfs ... | pass | pass | 2026-10-26 |  |
| generic/749 | As per POSIX NOTES mmap(2) maps multiples of the system page size, but if the data mapped is not multiples of the page size the remaining bytes are zeroed out ... | pass | pass | 2026-10-26 |  |
| generic/755 | Create a file, stat it and then unlink it. Does the ctime of the target inode change? | pass | pass | 2026-10-26 |  |
| generic/758 | Test mapped writes against zero-range to ensure we get the data correctly written. This can expose data corruption bugs on filesystems where the block size is ... | pass | pass | 2026-10-26 |  |
| generic/759 | fsx exercising reads/writes from userspace buffers backed by hugepages | pass | not run | 2026-10-26 | system doesn't support transparent hugepages |
| generic/760 | fsx exercising direct IO reads/writes from userspace buffers backed by hugepages | pass | not run | 2026-10-26 | system doesn't support transparent hugepages |
| generic/761 | Making sure direct IO (O_DIRECT) writes won't cause any data checksum mismatch, even if the contents of the buffer changes during writeback. | pass | pass | 2026-10-26 |  |
| generic/763 | test zero-byte writes | pass | pass | 2026-10-26 |  |
| generic/794 | Test that extending a file past a non-block-aligned EOF correctly zero-fills the gap [old_EOF, block_boundary), and that this zeroing persists through a ... | pass | not run | 2026-10-26 | ext4 does not support shutdown |
| generic/796 | Test an i_size expanding fallocate into a range beyond current i_size that already has a preallocated extent, with an unmount and mount after each fallocate to ... | pass | pass | 2026-10-26 |  |
| generic/797 | Test writing into a file range containing prealloc extents beyond the current i_size, with an unmount and mount after fallocate and the write, to verify that ... | pass | pass | 2026-10-26 |  |
| generic/799 | Check that fstat(2) returns the correct hard link count for a regular file. | pass | pass | 2026-10-26 |  |
| generic/806 | Test replacing a xattr's value with a larger value. | pass | pass | 2026-10-26 |  |

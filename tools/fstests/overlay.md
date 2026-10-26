# fstests results on overlayfs

These are the results of the overlay tests of fstests. The lower and the upper directories are on ext4. The README in this directory tells how the tests run.

rukernel: 23 pass, 14 fail, 56 not run, and 0 have no result, of 93 tests.

| Test | What the test checks | Linux | rukernel | Last run | Note |
| --- | --- | --- | --- | --- | --- |
| overlay/001 | Test copy up files from lower dir that are <, =, > 4G in size. | not run | not run | 2026-10-26 | This test requires at least 8GB free on /scratch to run |
| overlay/002 | Test that calling fsync against a file using the merged directory does not result in a crash nor fails unexpectedly. | pass | pass | 2026-10-26 |  |
| overlay/003 | Test overlayfs basic whiteout. | pass | pass | 2026-10-26 |  |
| overlay/004 | Test file copy up on overlayfs by changing mode bits. | pass | fail | 2026-10-26 | the output is not the expected output |
| overlay/005 | Memleak in overlayfs copy-up error handling path leads to panic when unmount the underlying fs. Kernel commit ab79efab0 fixed this issue. | not run | not run | 2026-10-26 | This test requires loopback device support |
| overlay/006 | Test visible whiteout issue after renaming file from lowerdir to a dir in upperdir. | pass | pass | 2026-10-26 |  |
| overlay/007 | Test getcwd() failure after unsuccessful rmdir | pass | pass | 2026-10-26 |  |
| overlay/008 | Create file/dir over whiteout by another user, uid/gid of the file/dir should be current fsuid/fsgid, not the mounter's. | pass | pass | 2026-10-26 |  |
| overlay/009 | dentry leak for default_permissions mount option | pass | pass | 2026-10-26 |  |
| overlay/010 | Remove dir which contains whiteout from lower dir. | pass | pass | 2026-10-26 |  |
| overlay/011 | test overlay private xattr on overlayfs with multiple lower dirs, all the lower layers except the lowest one should honor overlay private xattr ... | pass | pass | 2026-10-26 |  |
| overlay/012 | The upper dentry may become stale before we remove it from overlay, e.g. file was removed from upperdir directly, which triggered warning/oops in ... | pass | fail | 2026-10-26 | the output is not the expected output |
| overlay/014 | Test copy-up of lowerdir with opaque xattr set. | pass | pass | 2026-10-26 |  |
| overlay/015 | SGID bit inheritance over whiteout. | pass | pass | 2026-10-26 |  |
| overlay/016 |  | pass | pass | 2026-10-26 |  |
| overlay/017 |  | pass | not run | 2026-10-26 | overlay feature 'redirect_dir' cannot be enabled on /scratch |
| overlay/018 |  | pass | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/020 | Reproducer from kernel commit 3fe6e52 ovl: override creds with the ones from the superblock mounter Testing ovl copyup/namespace/cred issue. | pass | not run | 2026-10-26 | unshare : command not found, should be in util-linux |
| overlay/021 | Test concurrent copy up | not run | not run | 2026-10-26 | This test requires at least 3GB free on /scratch to run |
| overlay/022 | Regression test for kernel commit: 76bc8e2 ovl: disallow overlayfs as upperdir | pass | fail | 2026-10-26 | the output is not the expected output |
| overlay/023 | The "work" directory in an overlyfs workdir should not inherit ACL attrs from workdir. Kernel commits below fix it. c11b9fdd6a61 ovl: remove posix_acl_default ... | pass | fail | 2026-10-26 | the output is not the expected output |
| overlay/024 | "work" directory under workdir should be cleaned up well on overlayfs startup, or overlayfs will be mounted read-only. Kernel commit below fixes it ... | pass | fail | 2026-10-26 | the output is not the expected output |
| overlay/025 | Overlayfs failed to get posix acls if lower or upper fs is tmpfs. Kernel commit below fixed it. 5201dc449e4b ovl: use cached acl on underlying layer | pass | pass | 2026-10-26 |  |
| overlay/026 | Overlayfs should only filter out xattr starting with "trusted.overlay.", not "trusted.overlay". | pass | fail | 2026-10-26 | the output is not the expected output |
| overlay/027 | If underlying upper file is immutable, it should stays untouchable in the overlayfs mount. | pass | pass | 2026-10-26 |  |
| overlay/028 | When file in lower dir is locked and it's been copied up, make sure the lock is working in overlayfs. | pass | fail | 2026-10-26 | the output is not the expected output |
| overlay/029 | There are dirs/files in lower dir and upper dir before mounting overlayfs. After mounting, use dir in overlayfs mountpoint as lowerdir to mount another ... | pass | pass | 2026-10-26 |  |
| overlay/030 | Run the t_immutable test program for immutable/append-only files and directories in an overlayfs upper directory. | pass | pass | 2026-10-26 |  |
| overlay/031 | The unmerged and origined directories may contain invalid whiteouts when we change underlaying dir (e.g. clean up lowerdir) and remount overlay. This may lead ... | pass | pass | 2026-10-26 |  |
| overlay/032 | Test concurrent copy up of lower hardlinks. | not run | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/033 | Test nlink accounting of overlay hardlinks. | pass | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/034 | Test overlay nlink when adding lower hardlinks. | pass | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/035 | Test cases that force read-only mount | pass | fail | 2026-10-26 | the output is not the expected output |
| overlay/036 | Test mount error cases with exclusive directories | pass | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/037 | Test mount error cases with option index=on | pass | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/038 |  | pass | fail | 2026-10-26 | the output is not the expected output |
| overlay/039 | Test access time update issue for directories in upper layer. | pass | pass | 2026-10-26 |  |
| overlay/040 | chattr with [iap..] attributes open file for read-only and invoke ioctl(). If we chattr a lower file in overlay, it will get the lower file but not trigger ... | pass | pass | 2026-10-26 |  |
| overlay/041 |  | not run | not run | 2026-10-26 | overlay feature 'xino' cannot be enabled on /scratch |
| overlay/042 | Test creating lower hardlinks for copied up files. | pass | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/043 |  | not run | not run | 2026-10-26 | overlay feature 'redirect_dir' cannot be enabled on /scratch |
| overlay/044 |  | not run | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/045 | Test fsck.overlay how to deal with whiteouts in overlayfs. | not run | not run | 2026-10-26 | fsck.overlay utility required, skipped this test |
| overlay/046 | Test fsck.overlay how to deal with redirect xattr in overlayfs. | not run | not run | 2026-10-26 | fsck.overlay utility required, skipped this test |
| overlay/047 |  | pass | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/048 | Test nlink accounting of overlay hardlinks with offline modifications. | pass | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/049 | Test multiple redirects to the same lower dir. | pass | not run | 2026-10-26 | overlay feature 'redirect_dir' cannot be enabled on /scratch |
| overlay/050 | Test encode/decode overlay file handles | pass | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/051 | Test encode/decode overlay file handles for non-samefs. | pass | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/052 | Test encode/decode overlay file handles with renames | pass | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/053 | Test encode/decode of non-samefs overlay file handles with renames | pass | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/054 | Test encode/decode overlay file handle of dir with non-indexed ancestor | pass | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/055 | Test overlay file handle of dir with ancestor under lower redirect | pass | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/056 | Test fsck.overlay how to deal with impure xattr in overlayfs. | not run | not run | 2026-10-26 | fsck.overlay utility required, skipped this test |
| overlay/057 | Test absolute redirect is followed even if ancestor is opaque | pass | not run | 2026-10-26 | overlay feature 'redirect_dir' cannot be enabled on /scratch |
| overlay/058 | Test decoding overlay file handles with warm/cold dentry cache | fail | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/059 | Test multiple origin references to the same lower file. | fail | not run | 2026-10-26 | overlay feature 'redirect_dir' cannot be enabled on /scratch |
| overlay/060 | Test metadata only copy up functionality. | fail | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/062 | Test file handle decode with multi lower layers on same fs | fail | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/063 | Create dir over cached negative dentry, but whiteout removed from upper | fail | pass | 2026-10-26 |  |
| overlay/064 | Make sure CAP_SETUID is not cleared over file copy up. | fail | not run | 2026-10-26 | setcap utility required, skipped this test |
| overlay/065 | Test mount error cases with overlapping layers | fail | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/066 | Test overlayfs copy-up function for variant sparse files. | fail | fail | 2026-10-26 | the output is not the expected output |
| overlay/067 |  | fail | not run | 2026-10-26 | overlay feature 'xino' cannot be enabled on /scratch |
| overlay/068 | Test encode/decode of nested overlay file handles | pass | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/069 | Test encode/decode of nested overlay file handles | pass | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/070 |  | not run | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/071 |  | not run | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/072 | Test overlay nlink when adding upper hardlinks. | pass | pass | 2026-10-26 |  |
| overlay/073 | Test whiteout inode sharing functionality. | pass | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/074 | Test two overlayfs file handle bugs: 1. Failure to query file handle size Fixed by kernel commit 144da23beab8: ovl: return required buffer size for file handles | pass | not run | 2026-10-26 | overlay feature 'index' cannot be enabled on /scratch |
| overlay/075 | Run the t_immutable test program for immutable/append-only files and directories that exist in overlayfs lower layer. | pass | fail | 2026-10-26 | the output is not the expected output |
| overlay/076 | Support for chattr on overlayfs directories was added in kernel v5.10 by commit 61536bed2149 ("ovl: support [S/G]ETFLAGS and FS[S/G]ETXATTR ioctls for ... | pass | pass | 2026-10-26 |  |
| overlay/077 | Test invalidate of readdir cache | pass | pass | 2026-10-26 |  |
| overlay/078 | Test copy up of lower file attributes. | pass | fail | 2026-10-26 | the output is not the expected output |
| overlay/079 | Test data-only layers functionality. | pass | not run | 2026-10-26 | overlay feature 'redirect_dir' cannot be enabled on /scratch |
| overlay/080 | Test fs-verity functionallity | not run | not run | 2026-10-26 | overlay feature 'redirect_dir' cannot be enabled on /scratch |
| overlay/081 |  | pass | not run | 2026-10-26 | overlay feature 'uuid' cannot be enabled on /scratch |
| overlay/082 | Test for a regression in copy up of symlink that has the noatime inode attribute. | pass | pass | 2026-10-26 |  |
| overlay/083 | Test regressions in parsing and display of special chars in mount options. | pass | fail | 2026-10-26 | the output is not the expected output |
| overlay/084 | Test advanded nesting functionallity | pass | fail | 2026-10-26 | the output is not the expected output |
| overlay/085 | Test data-only layers functionality. This is a variant of test overlay/079 with lowerdir+,datadir+ mount options | pass | not run | 2026-10-26 | overlay feature 'redirect_dir' cannot be enabled on /scratch |
| overlay/086 | Test lowerdir+,datadir+ mount option restrictions. | pass | not run | 2026-10-26 | overlay lowerdir+,datadir+ not supported on /scratch |
| overlay/087 | This is a variant of test xfs/546 for overlayfs with and without the "volatile" mount option. It only works over xfs underlying fs. | not run | not run | 2026-10-26 | base fs ext4 has unknown behavior with syncfs after shutdown |
| overlay/088 | Test data-only layers functionality. This is a variant of test overlay/085 with userxattr and without redirect_dir/metacopy options | not run | not run | 2026-10-26 | overlay feature 'redirect_dir' cannot be enabled on /scratch |
| overlay/089 | Test fs-verity functionallity This is a variant of test overlay/080 with userxattr and without redirect_dir/metacopy options | not run | not run | 2026-10-26 | overlay feature 'redirect_dir' cannot be enabled on /scratch |
| overlay/100 | Run unionmount testsuite to verify correctness with single lower layer on same fs as upper | not run | not run | 2026-10-26 | unionmount testsuite required. |
| overlay/101 | Run unionmount testsuite to verify correctness with single lower layer not on same fs as upper | not run | not run | 2026-10-26 | unionmount testsuite required. |
| overlay/102 | Run unionmount testsuite to verify correctness with single lower layer not on same fs as upper with xino enabled | not run | not run | 2026-10-26 | unionmount testsuite required. |
| overlay/110 | Run unionmount testsuite on a nested overlay filesystem with single lower overlay layer, whose layers are on same fs | not run | not run | 2026-10-26 | unionmount testsuite required. |
| overlay/111 | Run unionmount testsuite on a nested overlay filesystem with single lower overlay layer, whose layers are on same fs with xino enabled (xino overflow not ... | not run | not run | 2026-10-26 | unionmount testsuite required. |
| overlay/112 | Run unionmount testsuite on a nested overlay filesystem with single lower overlay layer, whose layers are not on same fs | not run | not run | 2026-10-26 | unionmount testsuite required. |
| overlay/113 | Run unionmount testsuite on a nested overlay filesystem with single lower overlay layer, whose layers are not on same fs with xino enabled (expected xino ... | not run | not run | 2026-10-26 | unionmount testsuite required. |

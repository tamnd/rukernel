# The VFS and file systems

The VFS is the largest single body of ABI in the kernel after the system call table itself, because "everything is a file" means `/proc`, `/sys`, `/dev`, cgroups, BPF pins, tracing and the namespace handles are all served by it. Its fast path (path lookup, `stat`, `open`, `read` of cached data) is also the path that dominates build systems, package managers and container startup, so it carries the performance claim as much as the scheduler does.

## 8.1 The object model

The objects are Linux's, because their lifetimes and sharing are observable: `SuperBlock`, `Inode`, `Dentry`, `Mount` (a `vfsmount` in a mount namespace's tree), `File` (an open file description with its offset, flags and credentials), and the per process `FdTable`. File systems implement traits (`FileSystemType`, `SuperOps`, `InodeOps`, `FileOps`, `AddressSpaceOps`, `DentryOps`) that correspond one to one with Linux's operation tables, which keeps the porting of semantics from each Linux file system straightforward to review against its source.

**The dentry cache** is a hash of (parent, name) with RCU lookup, negative dentries, and the LRU and shrinker integration. **Path walk** has two modes as in Linux: RCU walk, which takes no locks and no references and falls back to ref walk on any conflict (a seqcount change on a dentry or mount), and ref walk. Linux's RCU walk is the reason `stat` on a deep path costs a few hundred nanoseconds, and matching it is a requirement, not an optimization. In Rust, the RCU walk is a function that holds an `RcuReadGuard` and returns borrowed dentries whose lifetime is tied to it, and the fallback is the `Err` branch.

**Lookup semantics** that programs depend on: `openat2` with `RESOLVE_BENEATH`, `RESOLVE_IN_ROOT`, `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS`, `RESOLVE_NO_XDEV` and `RESOLVE_CACHED`; the 40 symlink nesting limit; magic links in `/proc/<pid>/fd` and `/proc/<pid>/exe` and their permission rules; `O_PATH` descriptors; the 7.2 additions `O_EMPTYPATH` (reopen through a descriptor without a path) and `OPENAT2_REGULAR`; trailing slash rules; `..` across mount points and chroots; case folding lookups on `casefold` directories (ext4, tmpfs, f2fs) with the Unicode version the file system records.

## 8.2 The calls

Every file and directory system call, including the ones added in the last three years that a reimplementation can easily miss: `statx` with every mask bit (`STATX_MNT_ID_UNIQUE`, `STATX_DIOALIGN`, `STATX_DIO_READ_ALIGN`, `STATX_SUBVOL`, `STATX_WRITE_ATOMIC`), `cachestat` (6.5), `fchmodat2` (6.6), the `*xattrat` family (6.13), `file_getattr` and `file_setattr` (6.17), `name_to_handle_at` and `open_by_handle_at` with `AT_HANDLE_FID`, `AT_HANDLE_MNT_ID_UNIQUE` and connectable handles, `copy_file_range`, `splice`, `tee`, `vmsplice`, `sendfile`, `fallocate` with every mode (punch hole, collapse range, insert range, zero range, unshare, `FALLOC_FL_WRITE_ZEROES`), `preadv2` and `pwritev2` with `RWF_HIPRI`, `RWF_DSYNC`, `RWF_SYNC`, `RWF_NOWAIT`, `RWF_APPEND`, `RWF_NOAPPEND`, `RWF_ATOMIC` and `RWF_DONTCACHE` (uncached buffered I/O from 6.14, extended to block devices in 7.3), and `fchroot` (7.3).

**File locking**: POSIX record locks with their per process semantics (the "close any descriptor drops all locks" rule), open file description locks (`F_OFD_*`), `flock`, leases and delegations (since 7.0 file systems opt in to leases; we match which ones do), and mandatory locking refused as Linux refuses it.

**Notification**: `inotify` with every event and the queue overflow behaviour, `fanotify` with every class and report mode (`FAN_REPORT_FID`, `FAN_REPORT_DFID_NAME`, `FAN_REPORT_TARGET_FID`, `FAN_REPORT_PIDFD`, the pre-content events from 6.14 used by HSM tools, and mount notifications from 6.15), and `dnotify` for the programs that still use it.

## 8.3 Mounts and the mount API

The new mount API in full (`fsopen`, `fsconfig`, `fsmount`, `fspick`, `move_mount`, `open_tree`, `mount_setattr`), the old `mount(2)` translated onto it, and the newer pieces systemd and container runtimes now depend on: `statmount` and `listmount` (6.8, with `statmount` accepting a descriptor for detached mounts since 7.0), `open_tree_attr` (6.15), `OPEN_TREE_NAMESPACE` (7.0), `FSMOUNT_NAMESPACE` and `UNSHARE_EMPTY_MNTNS` (7.1), `MOVE_MOUNT_BENEATH` (6.5, working on the root since 7.1 so the root can be replaced without `pivot_root`), mount propagation (shared, slave, private, unbindable, peer groups and `/proc/<pid>/mountinfo` with its optional fields in the exact format), idmapped mounts, `nosymfollow`, detached mount trees, and unique 64 bit mount IDs.

Kernel threads run in their own `nullfs` root and PID 1 has its own `fs_struct` since 7.3. These are internal, but they show through `/proc/<pid>/root` of kernel threads, so we match them.

## 8.4 The page cache and buffered I/O

Per inode `AddressSpace` with an xarray of folios, large folios wherever the file system supports them (document 07.6), readahead with the same window algorithm (sequential detection, async readahead marker, `fadvise` and `madvise` hints, `readahead(2)`, the per device `read_ahead_kb`), writeback with per BDI dirty throttling (`balance_dirty_pages` and its proportional limits are what make `dd` to a slow USB stick not freeze a desktop, and what `vm.dirty_ratio` tunes), `sync_file_range`, `fsync`, `syncfs`, and the `errseq` writeback error reporting that makes `fsync` report errors exactly once per descriptor, which PostgreSQL relies on after the 2018 fsync incident.

**Direct I/O** through the iomap layer design: alignment rules per `STATX_DIOALIGN`, the coherency rules with the page cache, and atomic writes (`RWF_ATOMIC`, 6.11 onward) for databases.

## 8.5 Pseudo file systems

These are ABI in their contents, not only their interfaces, and they are the single most cited cause of compatibility failures across gVisor, WSL1, the illumos LX brand and the FreeBSD linuxulator (document 01.4).

- **procfs**: every per process file (`stat`, `status`, `maps`, `smaps`, `smaps_rollup`, `pagemap`, `fd`, `fdinfo` with per type fields for eventfd, epoll, inotify, fanotify, timerfd, signalfd, pidfd, io_uring and BPF, `mountinfo`, `cgroup`, `ns`, `environ`, `cmdline` with its rewriting semantics, `auxv`, `limits`, `oom_*`, `sched`, `io`, `wchan`, `stack`, `syscall`, `personality`, `timens_offsets`, `attr/*`, `task/<tid>/*`, `ksm_*`, `seccomp` in `status`) and every system file that programs read (`cpuinfo` per architecture, `meminfo`, `vmstat`, `zoneinfo`, `stat`, `loadavg`, `uptime`, `version`, `filesystems`, `mounts`, `partitions`, `diskstats`, `interrupts`, `softirqs`, `pressure/*`, `net/*`, `sys/*` as the sysctl tree, `self`, `thread-self`, `kallsyms` per the settled entry in document 18.5, `config.gz` per 03.8, `modules`, `devices`, `cgroups`, `locks`, `swaps`, `buddyinfo`, `slabinfo`), and the mount options (`hidepid=`, `subset=pid` with its 7.2 relaxation, `gid=`).
- **sysfs**: the device model's view (`/sys/devices`, `/sys/bus`, `/sys/class`, `/sys/block`, `/sys/dev`), `/sys/kernel` (including `mm`, `security`, `tracing`, `btf`, `debug`), `/sys/fs`, `/sys/module` (per document 03.7), `/sys/firmware` (ACPI tables, DMI, EFI variables through `efivarfs`, device tree), `/sys/power`, and uevents through netlink with the same `ACTION`, `DEVPATH`, `SUBSYSTEM` and `MODALIAS` strings so `udev` and `mdev` work unmodified.
- **devtmpfs** with the standard nodes and their major and minor numbers (`/dev/null` is 1:3 on every Linux and some programs check), **devpts** with the multi instance semantics containers need, **tmpfs** with `huge=`, `noswap`, quotas (6.6), case folding, `size=` and `nr_inodes=`, and `memfd` and SysV shm on it, **cgroup2fs** (document 14), **bpffs** (document 11), **tracefs** and **debugfs** to the extent tools use them, **securityfs**, **configfs**, **efivarfs**, **pidfs**, **nsfs**, **pipefs** and **sockfs** as anonymous internal file systems with the right `fstat` behaviour, **binfmt_misc**, **hugetlbfs**, **mqueue**, **fusectl**, and **nullfs** (7.0).

Every file in these trees is produced by a generator registered against a path, and the compat harness's procfs and sysfs manifests (document 04.3, step 8) are the oracle: for each path, the reference's mode, owner and a content sample under a fixed workload. A file that exists on the reference and not on rukernel is a finding, and so is one that exists only on rukernel.

## 8.6 Disk file systems

The order is set by what real installations boot from and what containers and databases sit on:

| File system | Why | Scope at 1.0 |
|---|---|---|
| ext4 | the default on Debian and Ubuntu, and the most common root file system in the world | read and write, journal (jbd2) with every mode, extents, `metadata_csum`, `orphan_file`, `casefold`, `encrypt` (fscrypt), `verity`, quotas, large folios, `fast_commit`; fsck compatible on disk |
| xfs | the default on RHEL, Fedora Server and many databases; zoned XFS is no longer experimental since 7.2 | read and write, v5 format, reflink, `bigtime`, `nrext64`, realtime and zoned devices post 1.0, online repair post 1.0 |
| btrfs | the default on Fedora Workstation and openSUSE | read and write, subvolumes, snapshots, send and receive, compression (zstd, lzo, zlib), checksums, RAID 0, 1, 10 and DUP; RAID 5 and 6 refused as unsafe, as upstream recommends against them; the free space tree only (7.3 removed the v1 cache) |
| tmpfs, ramfs | everything | full |
| overlayfs | every container image | full, including idmapped layers (7.3), `redirect_dir`, `metacopy`, `index`, volatile and data only layers |
| vfat, exfat | EFI system partitions and removable media | full |
| ntfs | dual boot machines and external disks; a new in kernel NTFS driver merged in 7.1 alongside ntfs3, which gained alternate data streams in 7.3 | read and write, the subset ntfs3 supports |
| iso9660, udf | installers and optical media | read |
| squashfs, erofs | live images, snaps, Android, container lazy pulls | read, with every compressor and erofs's fscache and file backed modes |
| f2fs | Android and some SSD setups | post 1.0 |
| fuse | every user space file system, `sshfs`, `rclone`, Flatpak's portals, AppImage | full, including passthrough (6.9) and FUSE over io_uring (6.14, with buffer pools and zero copy in 7.3) |
| 9p, virtiofs | VM shared folders (QEMU, crosvm, Kata) | full |
| NFS client (v3, v4.2), SMB3 client | enterprise and home networks | client only at 1.0; NFS server (knfsd) and ksmbd post 1.0 |

bcachefs was removed from mainline in 6.18 and is out of scope. EFS and FreeVxFS were removed in 7.3 and are out of scope too.

**On disk compatibility is absolute.** A rukernel ext4, xfs or btrfs must be mountable by Linux and checkable by the upstream `e2fsck`, `xfs_repair` and `btrfs check` after any sequence of operations, and the other way round. The test is fstests run on rukernel with the upstream fsck run after every test, plus a cross mount differential: create on one kernel, mount and verify on the other, for a generated corpus of operations, in both directions.

## 8.7 How a file system gets written

The disk file systems are the largest volume of code in the kernel after drivers, and the on disk formats are specified mostly by their Linux implementations. Each one is written from the format documentation (ext4's `Documentation/filesystems/ext4`, the XFS on disk format book, the btrfs documentation) and from reading the Linux implementation. The kernel's GPL-2.0 license (document 00) means that reading the Linux source and expressing the same algorithm in Rust is not a licensing question. The engineering question is whether a translation keeps Linux's behaviour, and fstests answers that.

The design rule inside each file system is that **all on disk structures are parsed through typed, bounds checked views** (`zerocopy` layouts generated from the format definitions), never through pointer casts. A corrupted or malicious image then produces `EFSCORRUPTED`, not a kernel memory error. Linux's file systems are one of syzbot's largest sources of crashes, almost all of them from crafted images, and this rule removes the class rather than the instances.

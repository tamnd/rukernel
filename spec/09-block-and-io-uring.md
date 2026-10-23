# The block layer and io_uring

Storage is where a kernel's overhead is most visible. An NVMe drive in 2026 does several million 4 KiB IOPS at around 10 µs of device latency, so a kernel that spends 2 µs per I/O has lost a fifth of the device. Linux spent the last decade on this (blk-mq, polled I/O, io_uring, passthrough), and matching it is the storage class gate in document 19.1.

## 9.1 blk-mq

The block layer is multi queue in the Linux sense:

- Per CPU software staging queues mapped onto hardware dispatch queues.
- A tag set per device, shared or per queue.
- Requests allocated from the tag space so no allocation happens on the I/O path.
- Plugging per task, so a burst of I/O becomes one doorbell.
- Merging in the plug and in the scheduler.
- Completion on the submitting CPU, or a CPU sharing its cache, through IPI or softirq, as `rq_affinity` selects.

The user visible parts are ABI:

- Per queue sysfs: `/sys/block/<dev>/queue/*`, which is about 40 files including `scheduler`, `nr_requests`, `rotational`, `logical_block_size`, `physical_block_size`, `max_sectors_kb`, `io_poll`, `io_poll_delay`, `write_cache`, `zoned`, `nr_zones`, `atomic_write_*`, `dma_alignment` and `rq_affinity`.
- `/sys/block/<dev>/stat` and `/proc/diskstats` with their exact field order.
- The block ioctls (`BLKGETSIZE64`, `BLKSSZGET`, `BLKDISCARD`, `BLKSECDISCARD`, `BLKZEROOUT`, `BLKPG`, `BLKRRPART`, `BLKREPORTZONE` and the other zone ioctls, `BLKGETDISKSEQ`, `BLKPBSZGET`, `BLKIOMIN`, `BLKIOOPT`, `BLKFLSBUF`).
- The partition scanning rules (MBR, GPT, and the others Linux enables by default).
- `/dev/disk/by-*` through uevents for udev.

**I/O schedulers:** `none`, `mq-deadline`, `kyber` and `bfq`, selectable per device through sysfs. A distribution's udev rules set the scheduler by device type, and those rules must find the names they expect.

**Stacking:**

- device-mapper with the targets distributions use: linear, striped, crypt (LUKS through `cryptsetup`), thin provisioning, snapshot, verity (for verified boot images), integrity, mirror and raid through dm-raid, zero, error, delay and flakey (fstests uses the last three).
- md RAID 0, 1, 4, 5, 6 and 10 with the same superblock formats.
- loop with `LOOP_CONFIGURE` and direct I/O.
- `ublk` for user space block devices.
- nbd, zram and brd.

**Polled I/O.** Polled queues configured per driver (`poll_queues` for NVMe), polled completions driven by io_uring with `IORING_SETUP_IOPOLL`, and hybrid polling. This is how the lowest latency numbers in Linux are produced, and it is in the storage class benchmark.

**Zoned block devices.** ZNS NVMe and SMR drives, with zone append, the zone ioctls and the `zonefs` file system. Zoned XFS became stable in 7.2.

**Integrity and inline crypto.** T10 PI and NVMe protection information, the `blk-crypto` framework for inline encryption hardware, and fscrypt's use of it.

## 9.2 NVMe

The NVMe driver is the most important real hardware driver in the project after virtio. Its scope:

- **Transport:** PCIe at 1.0. NVMe over TCP and over RDMA, the fabrics hosts, follow at R10 (document 22).
- **Queues:** one I/O queue pair per CPU, with interrupt vectors spread across CPUs.
- **Command paths:** SGL and PRP construction, Host Memory Buffer, APST power states, multipath (native NVMe multipath with ANA), namespaces and namespace management, and `nvme-cli` passthrough through `NVME_IOCTL_ADMIN_CMD`, `NVME_IOCTL_IO_CMD` and the 64 bit variants.
- **Character devices:** the generic `/dev/ngXnY` devices and the io_uring `uring_cmd` passthrough that SPDK class users rely on.

The driver is written in safe Rust over `rk-frame`'s DMA, MMIO and interrupt abstractions. Every descriptor the device reads is built through typed views. The device's completion queue entries are read through a volatile typed view with the phase bit check, which is the one place a bad device could confuse a driver. The IOMMU is on by default (document 15.5), so a misbehaving device cannot write outside its mappings.

Rust for Linux carried an NVMe driver out of tree for years (rnvme) and its performance was within noise of the C driver on the published runs. That is evidence that the language costs nothing here. We do not reuse its code, because it is written against Linux's internal Rust bindings.

## 9.3 io_uring

io_uring is a second system call interface. It is growing faster than the classic one, and it is the most demanding single subsystem for compatibility and for performance. v7.3 defines 65 opcodes (document 01.1), the register operations, the setup flags, the provided buffer rings, the zero copy receive (zcrx) interface, multishot operations, linked and drained SQEs, fixed files and buffers, `uring_cmd` for drivers, `IORING_SETUP_SQPOLL`, `IORING_SETUP_DEFER_TASKRUN`, `IORING_SETUP_SINGLE_ISSUER`, `IORING_SETUP_NO_SQARRAY`, mixed SQE sizes (6.19), `IORING_SETUP_SQ_REWIND` (7.0), message rings between rings, futex wait and wake operations, waitid, `IORING_OP_BIND` and `LISTEN`, `IORING_OP_PIPE`, epoll waits, and the cBPF operation filter from 7.0 (`IORING_REGISTER_BPF_FILTER`).

**Design.** The ring memory is shared with user space, so `rk-frame` provides one typed abstraction for it: a `SharedRing<T>` whose head and tail are atomics with the right orderings, and whose entries are read through `zerocopy` views that copy each SQE out before validating it. The copy closes the time of check to time of use class of bugs that hit Linux's io_uring several times. It costs one 64 or 128 byte copy per SQE, which is in L1 and does not show in the benchmark.

**Execution.** Each operation is tried inline with `IOCB_NOWAIT` semantics first. That is Linux's model, and it is why io_uring is fast on cached data. On `EAGAIN`, file operations that support it arm a poll and retry from the wakeup (task work). The rest go to the io-wq worker pool, which is bounded and accounted to the submitter's cgroup.

This is the one place outside the network stack where rukernel uses async Rust. An io_uring request is a state machine with a natural `Future` shape (submit, maybe poll, complete, maybe re-arm for multishot), and an executor per ring, running in task work and in io-wq, polls them. The executor is small, has no allocation on the hot path (futures are stored in the request slot, sized at build time), and never blocks. File operations reached from io_uring are the same functions the classic system calls use, called with a non blocking context token. Code that can sleep cannot be called from there, because it requires `&Sleepable` (document 03.5).

**Registered resources.** Fixed files, fixed buffers, and the provided buffer ring. Registered buffers are pinned through `rk-frame`'s pin interface and accounted to `RLIMIT_MEMLOCK` and the memcg, as in Linux.

**Zero copy.**

- Send zero copy (`IORING_OP_SEND_ZC`, `SENDMSG_ZC`) with its notification CQEs.
- Zero copy receive (zcrx) through the NIC's header split and page pool, with the refill ring.
- Splice based copies between pipes, files and sockets.

zcrx depends on driver support, and lands with the first NIC driver that has header split (document 12.3).

**Security.** io_uring has been a frequent source of Linux CVEs, enough that Google disabled it in ChromeOS and on its production servers, and Android allows it only for some processes. rukernel supports:

- `io_uring_disabled` (the 0, 1 and 2 sysctl).
- `io_uring_group`.
- seccomp's inability to see SQEs, documented as on Linux.
- The 7.0 cBPF filter, which is the right tool for sandboxes.
- LSM hooks for `uring_cmd`, `override_creds` and `sqpoll`.

The design claim is that rukernel's io_uring does not carry the classes of bug Linux's has had (use after free on request lifetimes, races between cancellation and completion, missing reference counts on files), because request ownership is linear in the type system. We test that claim with syzkaller's io_uring descriptions, not by assertion.

**The compatibility suites:**

- liburing's test suite, which is about 350 tests, run on both kernels.
- kselftest's io_uring tests.
- Applications using it: PostgreSQL 18 (`io_method=io_uring`), RocksDB, ScyllaDB, QEMU (`aio=io_uring`), Tokio's io-uring runtime, `fio`, Samba's `vfs_io_uring`, and systemd.

## 9.4 Asynchronous I/O, the older interfaces

`io_setup`, `io_submit`, `io_getevents`, `io_pgetevents`, `io_cancel` and `io_destroy` (Linux AIO, still used by databases and QEMU), with its user visible ring header in the mapping that libaio reads directly. POSIX AIO is in glibc, on threads.

## 9.5 Direct and uncached I/O

The `O_DIRECT` path from user buffer to device, with no copy, through the pin interface. `RWF_DONTCACHE` (6.14 for files, 7.3 for block devices): buffered I/O that drops the pages once written back. Atomic writes through `RWF_ATOMIC` with the device's limits from `statx`.

## 9.6 Performance targets

From document 19.1: within 5% IOPS and p99 on 4 KiB random reads and writes and 128 KiB sequential, through both io_uring and libaio, at queue depths from 1 to 128, on NVMe and virtio-blk.

The analysis in document 21 says where the time goes on Linux's 4 KiB polled read:

- About 1 µs in total kernel overhead at queue depth 1.
- Of that, about a third is io_uring submission and completion.
- A third is the block layer and NVMe command construction.
- A third is the DMA mapping and IOMMU work.

The IOMMU third is shared with Linux's own costs and is the same on both kernels when both use the same IOMMU mode, which document 19.2 requires.

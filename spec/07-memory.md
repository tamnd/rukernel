# Memory management

Memory management is where Linux has had the most performance engineering since 2020 (folios, multi size THP, the maple tree, per VMA locks, MGLRU, the new slab sheaves), and so it is where a reimplementation is most likely to fall behind on performance while passing every functional test. It is also where the safest Rust design and the fastest design pull hardest against each other, and where the strongest recent research result applies directly: CortenMM (SOSP 2025, best paper), Asterinas's memory manager, which is both faster than Linux's on the scalability benchmarks it reports and carries concurrency proofs.

## 7.1 Physical memory

**Zones and nodes**: per NUMA node `pg_data_t` equivalents with `DMA`, `DMA32`, `NORMAL` and `MOVABLE` zones, and `ZONE_DEVICE` for persistent memory and device private memory. Watermarks (`min`, `low`, `high`, the `watermark_scale_factor` and boost), `/proc/zoneinfo`, `/proc/buddyinfo`, `/proc/pagetypeinfo` and `/sys/devices/system/node/node*/meminfo` with Linux's formats.

**The buddy allocator** with migrate types (unmovable, movable, reclaimable, CMA, highatomic, isolate), per CPU page lists for order 0 and the small orders Linux caches (since 5.13 the per CPU lists hold orders up to `PAGE_ALLOC_COSTLY_ORDER` and the THP order), compaction (both direct and `kcompactd`), and fragmentation avoidance. This is `rk-frame`'s frame allocator; the policy (watermarks, compaction triggers, migrate type fallback order) is in safe `rk-mm` and drives it through a narrow API.

**Memory hotplug** for VMs (virtio-mem, ACPI hotplug, balloon), because cloud guests resize memory and Kubernetes nodes expect it.

## 7.2 Folios and page metadata

Linux spent 2021 to 2025 converting from `struct page` to `struct folio` (a power of two, physically contiguous, naturally aligned group of pages managed as one) and is now moving toward memdescs, where each kind of memory user has its own descriptor and `struct page` shrinks toward a pointer. As of 7.3 that is still prototype work: experiments have shrunk `struct page` to 32 bytes, `CONFIG_MEMDESC` is proposed, and the 8 byte descriptor is in Matthew Wilcox's words a distant goal. rukernel starts at the end of that road.

Every frame has a typed metadata slot (`Frame<M>` in document 03.2) whose type is fixed at allocation: `FolioMeta` for anonymous and file memory, `SlabMeta` for slab pages, `PageTableMeta` for page table pages, `FrameBufMeta` for networking buffers. A folio is a typed handle to a head frame with its order. There is no union of everything, and so no class of bug where code reads slab metadata from a page cache page. This is the design memdescs are aiming at and that Asterinas's OSTD already uses. The cost Linux is trying to remove (64 bytes of `struct page` per 4 KiB frame, 1.6% of memory) is avoided from the start: the per frame metadata is 16 bytes with type specific descriptors allocated per folio.

## 7.3 The slab allocator

Kernel objects come from typed slab caches (`KmemCache<T>`), with `kmalloc` size classes for untyped buffers. The design follows SLUB as Linux has it in 2026: per CPU slabs with lockless fast paths, partial lists per node, and the **sheaves** per CPU array caches that Linux merged in 6.18 and made universal in 7.0, where they replaced the per CPU partial slabs, with batched `kfree_rcu` through sheaves. Slab merging is off by default for hardening; `kmalloc` random caches (`RANDOM_KMALLOC_CACHES`) and freelist pointer hardening are on, because these are memory safety mitigations that cost little and our unsafe core still has bugs we have not found.

`/proc/slabinfo` and `/sys/kernel/slab/*` are produced with Linux's cache names for the caches that exist in both (`dentry`, `inode_cache`, `task_struct`, `kmalloc-64`, `skbuff_head_cache` and so on), since monitoring tools (`slabtop`, node exporters) key on the names.

## 7.4 Address spaces and VMAs

The user address space is a set of VMAs in a **maple tree** (Linux since 6.1), an RCU safe B-tree variant designed for ranges, which gives lockless lookup of the VMA covering a fault address. rukernel implements the maple tree in `rk-lib` in safe Rust with RCU read guards. The interface `rk-mm` uses is the same one Linux uses (find, store range, iterate), so Linux's maple tree test suite (`lib/test_maple_tree.c`, which encodes the expected behaviour of a few thousand range operations) can be ported as tests.

**Locking**: per VMA locks (Linux 6.4 onward) so that page faults do not take the address space lock in the common case, with `mmap_lock` as a reader writer semaphore for structural changes. CortenMM argues for going further, replacing the VMA tree as the source of truth with the page table itself plus per page table page locking, and reports better scalability than Linux on `mmap`, fault and `munmap` heavy multithreaded benchmarks with a proof of correctness. That design is a candidate, not a decision: the open question (document 24) is whether it reproduces every observable Linux VMA behaviour (`/proc/<pid>/maps` and `smaps` granularity, VMA merging rules that programs observe through maps, `mremap` semantics, `MAP_GROWSDOWN` stack guard gaps). The experiment is scheduled at R4 (document 22), and the result is written down whichever way it goes.

**The calls**: `mmap` with every flag (`MAP_FIXED`, `MAP_FIXED_NOREPLACE`, `MAP_POPULATE`, `MAP_NORESERVE`, `MAP_HUGETLB` with size encoding, `MAP_SHARED_VALIDATE`, `MAP_SYNC`, `MAP_UNINITIALIZED` refused, `MAP_32BIT`, `MAP_STACK`, `MAP_DROPPABLE` from 6.11), `munmap`, `mremap` (`MREMAP_MAYMOVE`, `MREMAP_FIXED`, `MREMAP_DONTUNMAP`), `mprotect` and `pkey_mprotect`, `madvise` with all advice values (`MADV_DONTNEED`, `FREE`, `COLD`, `PAGEOUT`, `POPULATE_READ`, `POPULATE_WRITE`, `COLLAPSE`, `GUARD_INSTALL` and `GUARD_REMOVE` from 6.13, `HUGEPAGE`, `NOHUGEPAGE`, `WIPEONFORK`, `KEEPONFORK`, `DONTDUMP`, `MERGEABLE`), `process_madvise`, `mlock2`, `mlockall` with `MCL_ONFAULT`, `msync`, `mincore`, `mseal` (6.10, used by glibc and Chrome to seal mappings), `membarrier` with every command (the JVM, .NET and liburcu need the private expedited and `RSEQ` forms), `brk`, `remap_file_pages` emulation, `process_vm_readv` and `writev`, and memory protection keys on x86 and arm64 POE.

**`/proc/<pid>/maps`, `smaps`, `smaps_rollup`, `pagemap`, `numa_maps`, `status` memory fields, and the `PROCMAP_QUERY` ioctl (6.11)** are produced to the reference format exactly. Profilers, sanitizers, garbage collectors, CRIU and container runtimes parse them; `pagemap` bits (soft dirty, exclusive, file or shared, swapped, present, the PFN masked for unprivileged readers) are ABI that CRIU depends on, and the `PAGEMAP_SCAN` ioctl (6.7) is what Wine and CRIU use for fast dirty tracking.

## 7.5 Page faults

Anonymous faults with zero page sharing, copy on write with the `PageAnonExclusive` rules (the 2022 rework that fixed the long standing GUP versus COW bugs; programs using `O_DIRECT` and `vmsplice` on forked memory depend on its semantics), file faults through the page cache with fault around, `userfaultfd` (missing, write protect, minor, `UFFDIO_MOVE` from 6.8, `UFFDIO_POISON`, the `/dev/userfaultfd` device and the unprivileged sysctl), `MAP_SHARED` anonymous memory through shmem, and the fault path's interaction with signals (`SIGBUS` on truncated files, `SIGSEGV` with the right `si_code`).

The fault path is the hottest path in the memory class benchmarks, and the target is Linux's instruction count for a minor anonymous fault: the lookup under a per VMA lock or RCU, folio allocation from the per CPU list, zeroing, PTE install, all without touching the address space lock.

## 7.6 Huge pages

Three mechanisms, all of which programs use:

- **hugetlbfs** with `MAP_HUGETLB`, `SHM_HUGETLB`, `memfd_create(MFD_HUGETLB)`, per size pools under `/sys/kernel/mm/hugepages`, surplus pages, reservation accounting, and the cgroup hugetlb controller. Databases and DPDK use it, and its accounting rules are notoriously specific.
- **Transparent huge pages** (PMD sized) for anonymous, shmem and tmpfs memory, and file backed text on file systems with large folio support, with `khugepaged`, the `always`, `madvise` and `never` modes, `MADV_COLLAPSE`, and per process `PR_SET_THP_DISABLE`.
- **Multi size THP (mTHP)** from 6.8: anonymous folios of intermediate orders (16 KiB, 64 KiB, and so on) controlled under `/sys/kernel/mm/transparent_hugepage/hugepages-*kB/`, and since 7.2 collapsed into by `khugepaged` as well as allocated at fault time. This matters most on arm64 with contiguous PTE (`contpte`) mappings, where 64 KiB folios give most of the TLB benefit of 2 MiB pages without the internal fragmentation. Swap out and in of large folios without splitting, as Linux does since 6.10 and 6.12.

Large folios in the page cache for every file system that supports them (ext4 since 6.16 for regular files, xfs, btrfs, tmpfs), which is one of the largest single throughput wins Linux has made for buffered I/O.

## 7.7 NUMA and memory tiering

Memory policies (`mbind`, `set_mempolicy`, `get_mempolicy`, `set_mempolicy_home_node`, `MPOL_PREFERRED_MANY`, weighted interleave from 6.9 with `/sys/kernel/mm/mempolicy/weighted_interleave`), `move_pages`, `migrate_pages`, automatic NUMA balancing with hinting faults, and memory tiering for CXL attached memory: demotion on reclaim from fast to slow tiers and promotion of hot pages (the TPP design, mostly upstream since 5.18), with the tier sysfs interface. The research on top of that (Memtis, and the CXL tiering papers at SOSP 2025 and OSDI 2026, document 01) is a policy space, not ABI, so it fits behind the same interfaces and is a candidate for experimentation once the baseline matches Linux.

## 7.8 Reclaim

**MGLRU** (multi generational LRU, 6.1) as the default page replacement policy, with the classic active and inactive lists available as the alternative, because distributions differ in which they enable and the behaviour under pressure differs measurably. `kswapd` per node, direct reclaim, the shrinker interface for kernel caches (dentries, inodes, the slab caches that register), workingset detection with shadow entries for refault distance, `vm.swappiness`, `vm.vfs_cache_pressure`, `vm.min_free_kbytes`, `vm.watermark_scale_factor`, `drop_caches`, `/proc/vmstat` with every counter name Linux has (monitoring keys on them), and the OOM killer with `oom_score_adj`, `oom_score`, the cgroup aware group kill (`memory.oom.group`), and the exact selection heuristic, since container platforms depend on which process gets killed.

`cache_ext` (SOSP 2025), page cache policies as eBPF programs, is the sched_ext analogue for reclaim. If it merges upstream we implement it in the same way as sched_ext (document 06.4); until then it is a research option.

## 7.9 Swap and compression

Swap devices and files with priorities, `swapon` and `swapoff` flags, discard, swap cache, readahead, `zswap` (compressed cache in front of swap, with the zsmalloc allocator) and `zram` block devices, because Fedora, ChromeOS and Android configure zram swap by default and a kernel without it changes memory behaviour on those systems visibly. Large folio swap as mentioned in 7.6.

## 7.10 Memory cgroup

cgroup v2 `memory.*` in full: `current`, `min`, `low`, `high` with throttling, `max`, `peak` (resettable since 6.12), `swap.current`, `swap.max`, `swap.high`, `zswap.current`, `zswap.max`, `zswap.writeback`, `events`, `events.local`, `stat` (every field, in order), `numa_stat`, `pressure`, `oom.group`, `reclaim` (proactive reclaim), and per cgroup kernel memory accounting (slab objects charged to the allocating cgroup). Container runtimes and Kubernetes' kubelet read `memory.stat` field by field to make eviction decisions, so field names and semantics are compared against the reference in the compat harness under load.

## 7.11 Shared memory and file backed anonymous memory

`memfd_create` with `MFD_CLOEXEC`, `MFD_ALLOW_SEALING`, `MFD_HUGETLB`, `MFD_NOEXEC_SEAL` and `MFD_EXEC` (6.3) and the `vm.memfd_noexec` sysctl; file seals (`F_SEAL_SEAL`, `SHRINK`, `GROW`, `WRITE`, `FUTURE_WRITE`, `EXEC`); `memfd_secret` (5.14); System V shared memory, POSIX shared memory on tmpfs; and `guest_memfd` for KVM (document 14.4).

## 7.12 What the safe design buys and costs here

Buys: the page table walker, frame allocator and TLB shootdown are in `rk-frame` and verified (document 20); everything above them (VMAs, faults, reclaim, cgroups, policies) is safe Rust where a use after free on a folio or a VMA is a compile error. Linux's mm subsystem has a long tail of exactly those bugs, found by syzbot every week.

Costs: Linux's mm uses tricks Rust's ownership model resists, especially `struct page` reference counts manipulated speculatively by GUP fast and by RCU readers (`folio_try_get` on a folio that may be freed and reallocated under you). These are implemented once in `rk-frame` as a small set of primitives (`FrameRef::try_get_rcu`) with their proofs, and the safe layers use them. Whether that small set is enough for everything Linux does with speculative references is the second open question in document 24, and GUP fast is the test case.

## 7.13 GUP fast: the decision for R3

This was open question 4 of document 24, and it was decided in R3. The kernel has no GUP now. A direct read or write copies between the user buffer and a kernel buffer, and the block layer uses the kernel buffer. The copy walks the user page tables with no lock, as `copy_from_user` does, and a fault goes to the fault path. This takes no reference on a user frame, so it needs no speculative reference and no proof for one.

We measured with fio on the alpine boot test, with the `psync` engine on a virtio-blk disk under QEMU with no KVM:

| Job | Direct I/O | Through the page cache |
|---|---|---|
| Sequential read, 128 KiB | 160 IOPS, 20.1 MiB/s | 184 IOPS, 23.1 MiB/s |
| Sequential write, 128 KiB | 147 IOPS, 18.4 MiB/s | 203 IOPS, 25.5 MiB/s |
| Random read, 4 KiB | 397 IOPS | 1462 IOPS |
| Random write, 4 KiB | 423 IOPS | 1875 IOPS |

A direct request of 4 KiB takes about 2.5 ms, and the device takes almost all of it. A copy of 4 KiB takes some microseconds, so the copy is less than 1% of the time. Without KVM, the three options of the question cannot show a difference.

The decision:

1. Until zero copy direct I/O comes, the kernel copies, as above.
2. Zero copy direct I/O pins the user frames with a walk under the per VMA lock (option 2). The per VMA locks come in R4.
3. io_uring fixed buffers pin their frames when the program registers them (option 3), so their requests do not walk the page tables.
4. The speculative reference API in `rk-frame` (option 1) is not built until `rukernel-bench` shows the locked walk as a red row on hardware with KVM or on bare metal (R8). Then we measure the three options with fio direct I/O again, and the question opens again with those numbers.

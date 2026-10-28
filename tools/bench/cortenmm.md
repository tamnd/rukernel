# The CortenMM experiment

This file has the results of the CortenMM experiment (#323, spec/24-open-questions.md question 1). It compares the VMA backend of rk-mm with a second backend in the CortenMM style. In the second backend, a tree with the shape of the page table is the source of truth, and each node of the tree has its own lock.

## The backend

The `corten` feature of rk-mm selects the backend. The `corten` feature of the `rukernel` package turns it on, and `RK_KERNEL_FEATURES=corten cargo xtask boot-test` boots it. The default kernel keeps the VMA backend, and its code does not change.

- `core/rk-mm/src/pttree.rs` is the tree. It has 4 levels of 512 slots, as the page table of x86-64. A slot is empty, holds one status for each page in it, or points to a child node. Each node has its own lock. A lock of a range goes down from the root with no lock, as the RCU walk of CortenMM, to the lowest node that covers the range. Then it locks that node and each node below it in the range. A walk locks a node on the way only to make a missing child. A node that a holder removes is dead, and a walk that locks a dead node starts again. The module has 7 unit tests.
- `core/rk-mm/src/space/corten.rs` connects the tree to `VmSpace`. The status of a page is the area (`Vma`) that maps it, so a run of pages with the same status is one area. The areas of `/proc/PID/maps` come from the statuses. Two runs merge as Linux `vma_merge` merges them.
- A page fault, `mmap` (not hugetlb), `munmap`, `mprotect` and `brk` lock only the nodes of their range. The other calls (`fork`, `mremap`, `mlock`, `madvise`, KSM, the `/proc` views and more) are rare. They lock the whole tree, make the list of areas from the statuses, run the code of the VMA backend on it, and write the changes back to the tree.

## The big kernel lock

rk-frame has a big kernel lock (`KERNEL_LOCK` in `frame/rk-frame/src/task.rs`). Only one CPU runs kernel code at a time. Thus two page faults on different CPUs do not run at the same time in rukernel today, with either backend. The per node locks cannot give more parallel work. They only add cost. The multithreaded rows below measure this cost, not the scaling of the design. The scaling claim of CortenMM can be tested only after the big kernel lock goes.

## Setup

- Host: server3, AMD EPYC, 8 CPUs, Linux 6.8.0-147. QEMU 8.2.2 with TCG (no KVM), `-smp 4 -m 1G`.
- Other users ran work on the host at the same time. The load average was between 6 and 33. Thus the numbers have much noise: the interquartile range is often 40 to 200 percent of the median. Use only the large differences.
- Kernels: release builds of base 926bdf9 with this change, one with the default features and one with `--features corten`. The same initramfs (`tools/bench/bench.c`) for both.
- `fault_mt` and `mmap_mt` are new. They run `fault` and `mmap` in one thread for each CPU at the same time and give the wall time for each operation.

## Results

The A/B runs boot the two kernels one after the other, 3 times each (VMA, CortenMM, VMA, and so on), so that the load of the host is about the same for the two. Each run has 5 runs for each row. The table gives the median and the lowest of the 3 medians of each kernel. The ratio is CortenMM divided by VMA, on the medians, so a ratio above 1.00 means that CortenMM is slower. The load average was between 5.6 and 10.8. Linux (from the first run, with no change in the guest) is for scale. Times in ns, `fork` in us.

| Benchmark | Linux | VMA median | VMA lowest | CortenMM median | CortenMM lowest | Ratio |
|---|---|---|---|---|---|---|
| `fault` | 68988 | 20876 | 14858 | 23093 | 12418 | 1.11 |
| `mmap` | 138668 | 2089924 | 1836711 | 2549708 | 2109395 | 1.22 |
| `fork` (us) | 18950 | 12584 | 12272 | 47884 | 40186 | 3.81 |
| `fault_mt` | 36598 | 508198 | 475312 | 632812 | 484726 | 1.25 |
| `mmap_mt` | 324066 | 2542919 | 1717426 | 1388392 | 935000 | 0.55 |

The medians of each run:

| Benchmark | VMA 1 | VMA 2 | VMA 3 | CortenMM 1 | CortenMM 2 | CortenMM 3 |
|---|---|---|---|---|---|---|
| `fault` | 20876 | 47327 | 14858 | 35155 | 23093 | 12418 |
| `mmap` | 2089924 | 4769463 | 1836711 | 2549708 | 2109395 | 2831908 |
| `fork` (us) | 18842 | 12272 | 12584 | 47884 | 40186 | 85349 |
| `fault_mt` | 1634628 | 475312 | 508198 | 977937 | 484726 | 632812 |
| `mmap_mt` | 2542919 | 2667957 | 1717426 | 1993656 | 1388392 | 935000 |

Only `fork` is clearly different: CortenMM is 3 to 4 times slower, because `fork` locks the whole tree, builds the list of areas, and builds the tree of the child. For `fault`, `mmap` and `fault_mt`, the runs of the two kernels overlap, so the difference is not larger than the noise. `mmap_mt` is faster on CortenMM in all 3 pairs, but the interquartile range of this row is 75 to 190 percent, and the earlier runs below gave the opposite result. Thus the A/B does not show a gain from the per node locks. This agrees with the big kernel lock: the per node locks cannot let two calls run at the same time.

The first runs, with 5 runs for each row, under a load average up to 33. Version 1 of the tree locked the nodes hand over hand from the root. Version 2 is the current tree. Medians in ns, fork rows in us.

| Benchmark | Linux | VMA | Corten v1 | Corten v2 |
|---|---|---|---|---|
| `fault` | 68988 | 32848 | 12277 | 18914 |
| `mmap` | 138668 | 1076676 | 1801248 | 4314412 |
| `fork` (us) | 18950 | 10247 | 76088 | 149426 |
| `fork_big` (us) | 86383 | 220619 | 616463 | 694186 |
| `fault_mt` | 36598 | 513951 | 3071313 | 2133297 |
| `mmap_mt` | 324066 | 1284312 | 2637000 | 8677729 |

## Fidelity of maps and smaps

A test program made the same address space on Linux and on the two backends, and printed `/proc/self/maps` and `/proc/self/smaps`. The program made these areas: anonymous areas next to each other, an area with a part made read only by `mprotect` and then made writable again, a shared anonymous area with a hole, two mappings of one file at offsets that follow each other, the heap after `brk`, and the same after `fork` in the child.

Only two results are different:

| Case | Linux | VMA | Corten |
|---|---|---|---|
| `mprotect` of the middle to read only, then back to read and write | 1 area | 3 areas | 1 area |
| One file mapped in two calls at offsets that follow each other, next to each other | 1 area | 2 areas | 1 area |

In both cases the CortenMM backend shows the same areas as Linux, and the VMA backend does not merge. `smaps` is different in the same way. All the other areas, and the maps of the child after `fork`, are the same on the two backends. The binary has no name on either backend (Linux shows `/init`). The areas come from the statuses, so the CortenMM backend needs no shadow structure to make these files.

## Boot tests

With `RK_KERNEL_FEATURES=corten` on server3 (load average below 1.5), each test with the ELF kernel, the bzImage and UEFI:

| Test | Result |
|---|---|
| `mm` | pass |
| `vm` | pass |
| `fault` | pass |
| `busybox` | pass |
| `init` | pass in 10 of 12 boots |

There is no `fork` boot test. The `mm`, `vm`, `init` and `busybox` tests use `fork` many times. The two `init` failures were the same check, "the threads run again" (`tests/user/init.c`, `test_stop`). It waits 50 ms after `SIGCONT` and checks that a thread of the child changed a counter in shared memory. The default kernel passed the same test in 3 of 3 boots at the same time. Under a high load, the first version of the tree failed other timing checks of `init`, and the default kernel failed timing checks of `init` too. The cause is not known. The tree changes no page table entry when it writes back the statuses, so the shared page stays shared. The `smp` test (8 CPUs) times out at the test with 1000 threads on both backends under TCG.

## Gaps

- The backend still has shared locks: `meta` (the heap), and `va`, the set of reserved ranges that `mmap` uses to find a free range. The page table of rk-frame also has one lock. Thus the per node locks do not remove all the shared locks, even without the big kernel lock. `mmap` and `munmap` are slower, because they change both `va` and the tree.
- The rare calls lock the whole tree and build the list of areas. `fork` is much slower because of this.
- The tree is a separate structure, not the page table pages. CortenMM keeps the status in the page table. Thus each change writes two trees.
- `max_map_count` is approximate. The backend counts the merged ranges of `va`, not the areas.
- The `munmap` of the middle of an area does not return `ENOMEM` when the split goes above `max_map_count`.
- A node that becomes empty stays in the tree until the address space goes.
- When a slot of a lower level must hold more than one status, the slot becomes a node of 512 slots, and each slot holds a copy of the `Arc` of the status.

## Follow up

- Remove the big kernel lock, and give the page table of rk-frame a lock for each node. Then run `fault_mt` and `mmap_mt` again, on hardware or with KVM.
- Keep the status in the page table pages, as CortenMM does, and remove the separate tree.
- Make `fork` walk the tree with no list of areas.
- Make the VMA backend merge areas after `mprotect` and for file mappings that follow each other, as Linux does. This is a fidelity bug of the default backend.
- Run the `maps` and `smaps` differential over the full L4 corpus.
- Find the cause of the `init` failure "the threads run again" with the `corten` feature.

## Recommendation for question 1

Keep the VMAs as the source of truth for now, and decide again after the big kernel lock goes.

- Scalability: not shown. With the big kernel lock, only one CPU runs kernel code at a time, so the per node locks cannot give scaling. `fault_mt` and `mmap_mt` show no clear gain, and `fork` is 3 to 4 times slower. The test of document 22 cannot pass or fail until the kernel runs page faults on more than one CPU at the same time.
- Fidelity: passes, and is better than the VMA backend. The CortenMM backend makes `maps` and `smaps` from the statuses with no shadow structure, and in the two cases that differ it shows the same areas as Linux. This removes the main argument for VMAs in question 1 (the cost of a shadow view). The differential ran on a small set of cases, not the full L4 corpus.

Thus question 1 stays open. Do the follow up items above in this order: the big kernel lock, the page table locks of rk-frame, and the statuses in the page table pages. Then run `fault_mt`, `mmap_mt` and will-it-scale on hardware or with KVM. Until then, the default backend gets the merge rules of Linux, and the `corten` feature stays as the experiment.

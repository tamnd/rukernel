# The CortenMM experiment

This file has the results of the CortenMM experiment (#323, spec/24-open-questions.md question 1). It compares the VMA backend of rk-mm with a second backend in the CortenMM style. In the second backend, a tree with the shape of the page table is the source of truth, and each node of the tree has its own lock.

## The backend

The `corten` feature of rk-mm selects the backend. The `corten` feature of the `rukernel` package turns it on, and `RK_KERNEL_FEATURES=corten cargo xtask boot-test` boots it. The default kernel keeps the VMA backend, and its code does not change.

- `core/rk-mm/src/pttree.rs` is the tree. It has 4 levels of 512 slots, as the page table of x86-64. A slot is empty, holds one status for each page in it, or points to a child node. Each node has its own lock. A lock of a range goes down from the root with no lock, as the RCU walk of CortenMM, to the lowest node that covers the range. Then it locks that node and each node below it in the range. A walk locks a node on the way only to make a missing child. A node that a holder removes is dead, and a walk that locks a dead node starts again. The module has 7 unit tests.
- `core/rk-mm/src/space/corten.rs` connects the tree to `VmSpace`. The status of a page is the area (`Vma`) that maps it, so a run of pages with the same status is one area. The areas of `/proc/PID/maps` come from the statuses. Two runs merge as Linux `vma_merge` merges them.
- A page fault, `mmap` (not hugetlb), `munmap`, `mprotect` and `brk` lock only the nodes of their range. Since #405, `fork` copies the tree with one walk. The other calls (`mremap`, `mlock`, `madvise`, KSM, the `/proc` views and more) are rare. They lock the whole tree, make the list of areas from the statuses, run the code of the VMA backend on it, and write the changes back to the tree.

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

Only `fork` is clearly different: CortenMM is 3 to 4 times slower, because `fork` locks the whole tree, builds the list of areas, and builds the tree of the child. The section on `fork` after #405 below finds the true cause, the allocations of the kernel heap, and gives the new numbers. For `fault`, `mmap` and `fault_mt`, the runs of the two kernels overlap, so the difference is not larger than the noise. `mmap_mt` is faster on CortenMM in all 3 pairs, but the interquartile range of this row is 75 to 190 percent, and the earlier runs below gave the opposite result. Thus the A/B does not show a gain from the per node locks. This agrees with the big kernel lock: the per node locks cannot let two calls run at the same time.

The first runs, with 5 runs for each row, under a load average up to 33. Version 1 of the tree locked the nodes hand over hand from the root. Version 2 is the current tree. Medians in ns, fork rows in us.

| Benchmark | Linux | VMA | Corten v1 | Corten v2 |
|---|---|---|---|---|
| `fault` | 68988 | 32848 | 12277 | 18914 |
| `mmap` | 138668 | 1076676 | 1801248 | 4314412 |
| `fork` (us) | 18950 | 10247 | 76088 | 149426 |
| `fork_big` (us) | 86383 | 220619 | 616463 | 694186 |
| `fault_mt` | 36598 | 513951 | 3071313 | 2133297 |
| `mmap_mt` | 324066 | 1284312 | 2637000 | 8677729 |

## `fork` after #405

In #405, `fork` walks the tree once: it copies the statuses into the tree of the child (`Tree::fork`) and builds no list of areas. This alone did not make `fork` faster. A profile with counters in the kernel found the cause: each node of the tree was one allocation of 8 KiB (512 slots of 16 bytes), and the walk of the tree copied the slots of a node into a list of up to 12 KiB. The kernel heap maps pages for an allocation of more than 2 KiB, and the free of such an allocation sends a TLB shootdown to each CPU. A `fork` and the exit of the child made about 20 of these allocations (2 with the VMA backend), and the shootdowns took most of the time. Now the slots of a node are in 4 chunks of 2 KiB, the walk reads them in batches of 64 and joins the slots with the same status, and `fork` keeps the last copy of a status.

A/B on server2 (QEMU with TCG, `-smp 4 -m 1G`, load average 2 to 4), with the same method as above: VMA, CortenMM, VMA, and so on, 3 times, 5 runs each. Medians in us.

| Benchmark | VMA median | VMA lowest | CortenMM median | CortenMM lowest | Ratio |
|---|---|---|---|---|---|
| `fork` | 5400 | 5187 | 7612 | 6893 | 1.41 |
| `fork_big` | 26700 | 26673 | 42753 | 41684 | 1.60 |

Before the change of the heap allocations, at the same base and under a load average of 11 to 22, the ratios were 1.58 for `fork` and 12.7 for `fork_big` (12495 and 19788 us; 42411 and 536624 us). The cost that is left grows with the memory that the process touched. A page fault locks the node of the lowest level of its 2 MiB block, so the walk makes that node, with 512 copies of the status. For the 128 MiB of `fork_big`, the tree has 64 such nodes, and `fork` and the exit of the child walk 32768 slots: in a profile, the walk of the statuses took 2.6 ms, the copy of the tree 3.7 ms and the exit 5.5 ms, of about 55 ms. The copy of the page table (`VmSpace::fork`, about 12 ms) is the same on the two backends. When the statuses go into the page table pages, the walk of the statuses and the walk of the page table are one walk.

The kernel heap is a cost for the VMA backend too: the 2 large allocations of each `fork` and exit (on both backends) took about 2.5 ms of a `fork` of 7 ms in a profile, because of the shootdown at the free.

## Fidelity of maps and smaps

A test program made the same address space on Linux and on the two backends, and printed `/proc/self/maps` and `/proc/self/smaps`. The program made these areas: anonymous areas next to each other, an area with a part made read only by `mprotect` and then made writable again, a shared anonymous area with a hole, two mappings of one file at offsets that follow each other, the heap after `brk`, and the same after `fork` in the child.

Only two results are different:

| Case | Linux | VMA | Corten |
|---|---|---|---|
| `mprotect` of the middle to read only, then back to read and write | 1 area | 3 areas | 1 area |
| One file mapped in two calls at offsets that follow each other, next to each other | 1 area | 2 areas | 1 area |

In both cases the CortenMM backend shows the same areas as Linux, and the VMA backend did not merge. Since #405 the VMA backend merges as `vma_merge` of Linux, and it shows 1 area in both cases too. `smaps` was different in the same way. All the other areas, and the maps of the child after `fork`, are the same on the two backends. The binary has no name on either backend (Linux shows `/init`). The areas come from the statuses, so the CortenMM backend needs no shadow structure to make these files.

## Boot tests

With `RK_KERNEL_FEATURES=corten` on server3 (load average below 1.5), each test with the ELF kernel, the bzImage and UEFI:

| Test | Result |
|---|---|
| `mm` | pass |
| `vm` | pass |
| `fault` | pass |
| `busybox` | pass |
| `init` | pass in 10 of 12 boots (before #405), pass in 12 of 12 boots (#405, server2) |

There is no `fork` boot test. The `mm`, `vm`, `init` and `busybox` tests use `fork` many times. The two `init` failures were the same check, "the threads run again" (`tests/user/init.c`, `test_stop`). It waits 50 ms after `SIGCONT` and checks that a thread of the child changed a counter in shared memory. The default kernel passed the same test in 3 of 3 boots at the same time. Under a high load, the first version of the tree failed other timing checks of `init`, and the default kernel failed timing checks of `init` too. In #405 the check passed in 18 of 18 boots at the base and in 12 of 12 boots with the changes of #405, on server2 under a load average of 8 to 18. 600 extra rounds of stop and continue (also on the code of #323, and with the CPU of QEMU shared with 2 busy loops) found no round in which the thread did not run in 50 ms, and the code of `wait_until`, `wake` and the continue of a group has no lost wake. Thus the only cause found is the fixed sleep of 50 ms on a busy host. Since #405 the check waits up to 2 s for the change, and it prints the time if the wait is longer than 50 ms. The tree changes no page table entry when it writes back the statuses, so the shared page stays shared. The `smp` test (8 CPUs) times out at the test with 1000 threads on both backends under TCG.

## Gaps

- The backend still has shared locks: `meta` (the heap), and `va`, the set of reserved ranges that `mmap` uses to find a free range. The page table of rk-frame also has one lock. Thus the per node locks do not remove all the shared locks, even without the big kernel lock. `mmap` and `munmap` are slower, because they change both `va` and the tree.
- The rare calls other than `fork` lock the whole tree and build the list of areas. Since #405, `fork` walks the tree once and builds no list of areas.
- The tree is a separate structure, not the page table pages. CortenMM keeps the status in the page table. Thus each change writes two trees, and `fork` and `exit` walk two trees. A page fault makes a node of the lowest level for its 2 MiB block, so the size of the tree grows with the memory that the process touched.
- When a slot of a lower level must hold more than one status, the slot becomes a node of 512 slots, and each slot holds a copy of the `Arc` of the status.

## Follow up

- Remove the big kernel lock, and give the page table of rk-frame a lock for each node, as spec/25-removing-the-big-kernel-lock.md gives. Then run `fault_mt` and `mmap_mt` again, on hardware or with KVM.
- Keep the status in the page table pages, as CortenMM does, and remove the separate tree.
- Run the `maps` and `smaps` differential over the full L4 corpus.
- Make the free of a large allocation of the kernel heap cheaper (for example a cache of freed ranges, or memory from the direct map for allocations of one page), so that it does not send a TLB shootdown each time. This is about a third of the time of `fork` on both backends.

## Recommendation for question 1

Keep the VMAs as the source of truth for now, and decide again after the big kernel lock goes.

- Scalability: not shown. With the big kernel lock, only one CPU runs kernel code at a time, so the per node locks cannot give scaling. `fault_mt` and `mmap_mt` show no clear gain, and `fork` was 3 to 4 times slower (1.4 times since #405). The test of document 22 cannot pass or fail until the kernel runs page faults on more than one CPU at the same time.
- Fidelity: passes, and is better than the VMA backend. The CortenMM backend makes `maps` and `smaps` from the statuses with no shadow structure, and in the two cases that differ it shows the same areas as Linux. This removes the main argument for VMAs in question 1 (the cost of a shadow view). The differential ran on a small set of cases, not the full L4 corpus.

Thus question 1 stays open. Do the follow up items above in this order: the big kernel lock, the page table locks of rk-frame, and the statuses in the page table pages. Then run `fault_mt`, `mmap_mt` and will-it-scale on hardware or with KVM. Until then, the default backend gets the merge rules of Linux, and the `corten` feature stays as the experiment.

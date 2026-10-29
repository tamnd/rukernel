# Removing the big kernel lock

This document is the design for the removal of the big kernel lock (`KERNEL_LOCK` in frame/rk-frame/src/task.rs). It is the first follow up item of tools/bench/cortenmm.md and of issue #405. The scaling test of open question 1 (document 24) cannot pass or fail while the lock exists, because only one CPU runs kernel code at a time. This document does not change code. It gives the state that the lock protects now, the order of the steps, the lock for each node of the page table, and the risks.

## 1. What the lock does now

A CPU takes the lock when it comes back from user mode (`UserContext::execute_timed` in frame/rk-frame/src/user.rs), when a secondary CPU starts (`run_secondary`), and when the idle loop wakes from `irq::wait`. A CPU releases the lock when it enters user mode and before the idle loop waits for an interrupt. The kernel runs with interrupts off and has no preemption in the kernel. Thus, with the lock, kernel code on one CPU runs as on a machine with one CPU: a call runs from its start to its next block with no other kernel code at the same time. A wait for the lock does the TLB requests of the other CPUs (`smp::poll`), because the CPU that holds the lock can wait for them.

The lock protects these items now. Some of them have their own `SpinLock`, but the code is correct only because no other CPU runs kernel code between two of these locks.

1. The switch of tasks. The SAFETY comment of `schedule` says that no other CPU switches, because the CPU holds the kernel lock. `Task::state` goes from `BLOCKED` to `RUNNABLE` in `wake`, and `schedule` reads it, puts the task back and switches. Without the lock, a CPU can take a task from a run queue while its stack is still in use on the CPU that blocked it.
2. The wait queues. `WaitQueue::wait_until` sets `BLOCKED`, adds the task to the queue and tests the condition again. `wake` can come from another CPU at any point of this sequence. The current code handles a wake between the test and the block, but the handoff of the stack (item 1) is still open.
3. The idle mask. The idle loop sets its bit in `IDLE_MASK` before it releases the lock, so a `kick` from a CPU that holds the lock sees the bit. Without the lock, the order of the bit, the test of the queue and `irq::wait` must make sure that no wake is lost.
4. The bottom half. `run_bottom_half` runs the expired timers and the functions of `add_bottom_half` with the lock. These functions (network receive, block completion, the timer wheel) assume that no system call runs at the same time.
5. The page table of a process. `VmSpace` in frame/rk-frame/src/vm.rs has one `SpinLock<Inner>` with the root, the map of pages and the map of huge pages. The lock is correct, but it is one lock for the whole address space, and a TLB shootdown waits with the lock held.
6. The state of the higher crates. The core crates have more than 50 global statics, and many structures have more than one lock. Much code reads a value under one lock and changes another value under a second lock, with the kernel lock as the only guard between them: for example the process tree, the signal state of a process and its threads, the file table, the dentry cache, the socket tables and the cgroup counters. No lock order is written down for these locks, because with the kernel lock no two CPUs take them at the same time.
7. The time of a thread. The user and system time of a thread and the tick sampling of #396 assume that one CPU changes the counters of a task.

## 2. The order of the steps

Each step keeps the kernel lock until the last one. Each step is a separate change that passes the full boot tests with `RK_SMP=4` and `RK_SMP=8`.

1. **Lock levels.** Add the lock levels of document 03 to `SpinLock` (the `IrqGuard` and the levels that `frame/rk-frame/src/sync.rs` says come with SMP). A debug build checks the order of the levels at each lock. Run all boot tests with the check on, and fix each report. This step finds the code that depends on the kernel lock for its lock order, before the kernel lock goes.
2. **A wait for a spin lock does the TLB requests.** A CPU that spins on a `SpinLock` with interrupts off calls `smp::poll`, as `kernel_lock` does now. Without this, CPU A can hold a lock and wait for a TLB request, while CPU B waits for the same lock with interrupts off. This is a deadlock.
3. **The scheduler.** Give each run queue its own lock, and give `Task` an `on_cpu` flag, as Linux does. `schedule` sets the flag of the next task and clears the flag of the previous task after `switch`. Another CPU does not run a task while its flag is set. `wake` takes the lock of the run queue of the target CPU. Then the SAFETY comment of `schedule` depends on `on_cpu`, not on the kernel lock. Make the idle loop set its bit in `IDLE_MASK`, test the queue again, and then wait, so that a wake from another CPU is not lost.
4. **The page table of rk-frame.** Give each page table page a lock, as section 3 says. `fork` and `exit` lock the whole tree. Move the TLB shootdown out of the lock: change the entries, release the lock, then send the request and free the frames after it.
5. **The fault path.** Let a page fault run without the kernel lock. The fault path takes the lock of the node of its 2 MiB block in the CortenMM tree (`corten` feature) or the lock of the area in the VMA backend, then the lock of the page table page. The fault is the first path without the kernel lock, because it is the most frequent call and the per node locks of #323 make it safe. The fault path takes the kernel lock again if it must call code that is not converted, for example the read of a page of a file system.
6. **System calls one group at a time.** Add a flag to each entry of the system call table that tells if the call needs the kernel lock. Start with the calls that touch only the current task (`getpid`, `gettid`, `clock_gettime`, `sched_yield`), then the memory calls (`mmap`, `munmap`, `mprotect`, `brk`, `madvise`), then futex, then pipes and sockets. Each group gets a lock order and a stress test with 4 and 8 CPUs.
7. **The bottom half.** Run the bottom half on the CPU that took the interrupt, without the kernel lock, after each of its functions has its own lock.
8. **Remove the kernel lock.** When no call and no bottom half takes the kernel lock, remove it, `LOCK_WAITERS` and the wake in `kernel_unlock`.

## 3. The lock for each page table page

CortenMM locks the page table pages of a range, from the top to the bottom, and keeps the status of each page in a page of metadata next to the page table page. rukernel does the same in two parts.

1. Each page table page gets a frame of metadata with a spin lock and the count of the entries in use. The lock of a range is the lock of the lowest page that covers the range, as `Tree::lock` in core/rk-mm/src/pttree.rs does now. A walk takes the locks from the top to the bottom, and it does not hold the lock of a parent while it waits for a child, except when it makes or removes the child. Two ranges in different pages do not wait for each other.
2. The status of each page (the `Status` of the CortenMM backend) moves from `pttree::Tree` into the metadata of the page table page. Then the tree of statuses and the page table are one tree, and a change writes one tree, not two. This is item 2 of #405. The pages map (`Inner::pages`) of `VmSpace` goes away. The reference to each frame comes from the page table entry and the metadata of the frame.

`fork` locks the whole tree of the parent, copies it with one walk (as `Tree::fork` copies the statuses), and makes the entries of the private pages read only in the parent and the child. An empty page table page leaves the tree when its last entry goes, as an empty node of `pttree::Tree` leaves it now.

## 4. Risks

- **Hidden lock orders.** Code that takes two locks in different orders is correct now, because only one CPU runs it. Step 1 finds these orders only on the paths that the tests run. Rare paths (error paths, OOM, ptrace, cgroup migration) can deadlock later. Mitigation: the lock level check in each debug build, and syzkaller runs with 8 CPUs.
- **Check then act.** Code that reads a value, drops the lock and changes the value later is a race without the kernel lock. Examples are the count of `max_map_count`, the free search of `mmap`, the pid allocator and the reference counts of mounts. Each must hold one lock for the check and the change, or use an atomic operation.
- **The TLB and freed frames.** A frame must not go back to the allocator until each CPU dropped its TLB entry. With the kernel lock, the shootdown and the free run in order. Without it, a fault on another CPU can map the frame again before the shootdown ends. The frames go to a list that the shootdown frees at its end, as `tlb_gather` of Linux does.
- **Lost wakes.** The handoff of a task between CPUs (`on_cpu`) and the idle mask are the most subtle parts. A lost wake hangs a task, and a double run of a task corrupts its stack. Mitigation: a model of `wait_until`, `wake` and `schedule` in Verus or loom before step 3, and the 1000 thread test of the `smp` boot test with KVM.
- **Interrupts and bottom halves.** The interrupt handlers take no lock now. A bottom half without the kernel lock can run at the same time as a system call that changes the same data, for example the receive queue of a socket.
- **Performance under TCG.** Without the kernel lock, more CPUs spin on spin locks. On a busy host, a spin uses a CPU of the host, as #396 found for the kernel lock. The spin locks need the same short spin and wait for an interrupt as `kernel_lock` has now.
- **Tests that depend on timing.** Some boot tests sleep for a fixed time and expect a change, for example "the threads run again" of `init` before #405. With more CPUs and less serial kernel code, the timing changes. These tests must wait for the change with a long timeout, not test it after a fixed sleep.

## 5. Status after #405

The kernel lock is off by default. The `big-lock` feature of rukernel (`rk-frame/big-lock`) keeps it for a comparison. The steps of section 2 were done in this form:

- Step 2 is done. `SpinLock::lock` and `Once::call_once` call `sync::wait_hint`, which does the TLB requests (`smp::poll`). The shootdown has a SeqCst fence before it reads the active tables of the other CPUs, and `paging::activate` changes the active table with a SeqCst swap.
- Step 3 is done. `Task` has `on_cpu`, and the states `SLEEPING`, `ASLEEP` and `WAKING`. `wake` never waits: a task that did not switch yet runs on, and a task whose CPU did not save its registers yet goes to a queue in `finish_switch`. A yield to a CPU that the affinity mask does not allow also goes to a queue in `finish_switch`. The load balancer of rk-sched skips a task with `on_cpu`. The idle loop sets its bit in `IDLE_MASK` and tests `Scheduler::has_queued` before it waits. The global `EXITED_TASK` is now the per-CPU `prev`.
- Step 5 is done for the VMA backend: `VmSpace.inner` is the lock of each address space, and `AddressSpace.state` is the lock of the areas. Each page fault of one address space takes these two locks, so faults of different processes run at the same time. Faults of one process do not.
- Step 7 is done in part. The functions of `add_bottom_half` run on one CPU at a time (`BOTTOM_HALF_BUSY`), as a tasklet of Linux. The timers of `wait_until_timeout` run on each CPU.
- Steps 1, 4 and 6 are not done. There is no lock level check. The races that an audit of the higher crates found and that the tests can hit are fixed (see CHANGELOG.md). The others are below.

The work that stays:

- The lock for each page table page of section 3. `VmSpace` in frame/rk-frame/src/vm.rs has one lock for each address space.
- The global locks: the heap (`FREE` in frame/rk-frame/src/mm/heap.rs), the frame allocator (`FRAMES` in frame/rk-frame/src/mm/frame.rs) and the cgroup tree (`HIERARCHY` in core/rk-cgroup/src/lib.rs, which `charge` and `psi` of rk-sched take at each switch of a task in a cgroup).
- Spin locks held across file I/O: `AddressSpace::handle_fault` calls `FilePages::page` under the state lock, and `unmap_locked`, `msync` and `Drop` of core/rk-mm/src/space.rs call `write_back` under it. ksmd can drop an address space under `GLOBAL` (core/rk-mm/src/space/ksmd.rs).
- Check then act in rk-proc: the stop of a group against `SIGCONT` (`stop_group`), the zombie and the reparent in `exit_thread`, the last thread test in `run` of core/rk-syscall/src/run.rs, `set_task` after the spawn in `start_thread`, and `FUTEX_CMP_REQUEUE`, which compares the word outside the lock of the table.
- Check then act in the file systems: the `pending` map of rk-fs-ext4 (`Fs::write`, `Fs::read`), `open` with `O_CREAT` against a create on another CPU (rk-vfs fs.rs), `O_APPEND` writes from two files, the dentry cache (`Dentry::add_child`), `rename` without a rename lock, and `rmdir` and `move_entry` of rk-fs-tmpfs.

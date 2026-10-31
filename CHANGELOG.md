# Changelog

This file records each release. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The version numbers follow [Semantic Versioning](https://semver.org/).

## Unreleased

### Fixed

- `/proc/PID/maps` names each area with no file in the range of `brk` `[heap]`, as `vma_is_initial_heap` of Linux (#405). Before, only the area that `brk` made had the name, and the guard page that the `malloc` of musl maps in the heap with `MAP_FIXED` had no name.
- The top of the `mmap` area of a program with a random layout is below the stack by the gap of `mmap_base` in mm/util.c of Linux: the stack size, `stack_guard_gap` and the largest random offset of the stack (`STACK_RND_MASK`, 1 GiB on arm64 and 16 GiB on x86-64), and then by the random offset of `arch_mmap_rnd`. Before, the gap was only 128 MiB. On arm64 the random offset is at most 1 GiB, so LTP hugemmap24 failed when its heap was less than 260 MiB below the end of the user space, in 1 of 20 runs (#435).
- `/proc/PID/maps` shows ` (deleted)` after the path of a mapped file with no link, as a memfd or a file that `unlink` removed (#405). Before, it showed only the path.
- With the `corten` backend, a page fault does not walk the tree of statuses when the status table of the 2 MiB block has the status of the page (#405). The lock of the lowest tree node is now a flag next to the status table, so the fault takes only this flag. An `mmap` or `mprotect` reads the statuses next to the range from the locked range, and does not walk the tree a second time. A core dump finds the area of a page with no frame with a lock of the block of the page only. Before, it locked the whole space and made each area for each such page, so each core dump of the `smp` boot test took 36 to 65 s on a busy host, and the test went past its limit of 600 s. Now a dump takes about 2 s, and the test takes about 300 s.
- tools/bench/run.py gives Linux `kpti=0` on arm64, because Linux turns on KPTI for KASLR on the `cortex-a72` and `mitigations=off` does not stop this (#465). QEMU without KVM then flushes all its TLB at each kernel entry and exit, and the entry rows of Linux were about 7 times slower than rukernel. With `kpti=0`, `getpid` gives 4310 ns on Linux and 5891 ns on rukernel.
- The init check "a stall polls POLLPRI on the trigger" gives the child that the cgroup throttles no end, and waits up to 10 s for the event (#468). Before, the child stopped after 1 s of wall time, and in 1 of 9 smp runs on a busy host the stall did not get to the threshold of 50 ms.
- A POSIX timer that is set again or deleted leaves no signal of its old setting pending (#468). `timer_settime` and `timer_delete` discarded the pending signal first and then changed the timer, and the timer task sent the signal after it released the lock of the timer. A timer that fired between these steps left a signal of the old setting. In 1 of 15 `smp` runs on a busy host, this signal took the place of the signal of the next timer in the init test, and the signal that stayed pending ended init when the test unblocked it.

## [0.4.19] - 2026-10-30

### Fixed

- tools/ltp/run.py gives hackbench02 480 s, because its 8 M messages took up to 223 s under QEMU without KVM, near the limit of 240 s (#504).
- `munmap` and the other removals of a range of pages do one TLB flush for the range, and not one for each 4 KiB page, as the `mmu_gather` of Linux (#468). The frames go after the flush. The `munmap` of the `fault_mt` bench on 4 CPUs sent about 6170 shootdowns in each round, and Linux sends about 9. A range of one page keeps the flush of one entry. The `smp` boot test examines that a `munmap` of 2048 pages with threads on the other CPUs sends almost no shootdown.

## [0.4.18] - 2026-10-30

### Fixed

- The `tcp_stream` row of tools/bench on arm64 is about 3 times faster, and it is not red now (#465). TCP copies the data of its queues with one copy of memory for each part of the queue, and not one byte at a time. The checksum adds aligned 64-bit words, and `NetBuf::extend_from_slice` does not write zeros first. The arm64 kernel has its own `memcpy` and `memset` that copy 16 bytes with each `ldp` and `stp`. The `memcpy` of compiler_builtins does a copy that is not aligned one byte at a time because the target has `strict-align`, and x86-64 uses `rep movsb`. In three runs on a busy host with QEMU TCG, the row gave 18.6 to 19.3 MB/s before and gives 43.4 to 68.2 MB/s now. Linux gives 57.5 MB/s.
- A create or a lookup in a directory removes the cached names that no one uses only when the cache is twice the size that stayed after the last removal, and not at each insert (#475). Before, each insert examined each name in use, and the events of a fanotify group keep the names of their files in use, so the creates of fanotify05 of LTP took a time for each file that the queue held. init examines a directory with 600 open files and 600 closed files.
- tools/ltp/run.py gives fork13 720 s, because the test forks for 600 s (`.runtime = 600`), and gives hackbench01 900 s, because its 20 M messages took 554 s under QEMU without KVM (#475).
- The child cache of an overlay directory removes the nodes that no one uses only when its size doubles, and not on each insert, as the dentry cache after #505 (#504). Many nodes in use made each lookup in the directory slow.
- The check "cpu.max limits a busy loop" of `init` has 3 tries, and each try uses the change of the counters of `cpu.stat` (#504). On a busy host, the time that QEMU does not run the guest counts as CPU time of the busy loop, so one try could go above the limit of 500 ms. A try that fails prints the time and the count of throttles.
- The arm64 `smp` boot test passes the checks "page faults of one file on each CPU read the right data" and "aio on each CPU while two threads destroy the context" (#504). The test runs init with the argument "only", so the general checks do not make /tmp, and the initramfs does not have it. The two checks could not make their files in /tmp and failed before they started. init now makes /tmp at the start of the `smp` checks. The kernel had no fault here.

## [0.4.17] - 2026-10-30

### Added

- init examines that `sendmsg` with a bad `msg_control` and `recvmmsg` with a bad vector give `EFAULT`, as net/socket.c of Linux (#496). sendmsg01 and recvmmsg01 of LTP get SIGSEGV in the wrappers of musl before the call, and tools/ltp/notes.txt tells this. tools/ltp/notes.txt also tells that fallocate06 needs a device of 1 GiB, which the runner does not give. madvise08, splice07, futex_waitv02 and futex_waitv03 pass, and futex_waitv02 goes back in the ltp boot test.
- `SO_BUSY_POLL`, as `sk_setsockopt` in net/core/sock.c of Linux (#491). A negative value gives `EINVAL`, and `getsockopt` gives the value. A new socket takes `net.core.busy_read`. The devices have no busy poll, so the value does not change a receive. busy_poll02 and busy_poll03 of LTP use it.
- `IP_PKTINFO`, `IP_RECVTTL` and `IP_RECVTOS` for UDP, raw and ICMP echo sockets, as `ip_cmsg_recv_offset` in net/ipv4/ip_sockglue.c of Linux (#491). A receive gives the control messages in the order of Linux. `ipi_spec_dst` is the destination of a unicast packet, else an address of the device, as `fib_compute_spec_dst`. dnsmasq needs `IP_PKTINFO` for its DHCP socket.
- `SO_ATTACH_FILTER`, `SO_DETACH_FILTER` and `SO_LOCK_FILTER` for packet sockets, as `sk_attach_filter` in net/core/filter.c and `packet_rcv` in net/packet/af_packet.c of Linux (#491). The new module rk-net filter checks a program of classic BPF as `bpf_check_classic` and runs it on each frame. The return value cuts the frame, and 0 drops it. `SO_DETACH_FILTER` without a filter gives `ENOENT`. tcpdump, dhcpd and dhclient need the filters.
- The error queue of `IP_RECVERR` and `IPV6_RECVERR` for UDP and ICMP echo sockets, as `ip_icmp_error` and `ip_recv_error` in net/ipv4/ip_sockglue.c and `ipv6_icmp_error` and `ipv6_recv_error` in net/ipv6/datagram.c of Linux (#491). `recvmsg` with `MSG_ERRQUEUE` gives the data of the datagram that failed, its destination, the control messages of the ICMP packet and a `struct sock_extended_err` with the offender. `poll` gives `POLLERR` while the queue has an error. Before, `MSG_ERRQUEUE` always gave `EAGAIN`, and tracepath found no hops.
- `net.ipv4.ip_local_reserved_ports`, as `proc_do_large_bitmap` in kernel/sysctl.c and `inet_is_local_reserved_port` of Linux (#491). The file takes a list of ports and ranges, and the search for a free ephemeral port skips them. A bind to a reserved port by its number still works. Before, the file was not there, so `__binddynport` of libtirpc failed and the RPC servers of LTP did not start.
- `setsockopt(IPV6_PKTINFO)` with a `struct in6_pktinfo`, as `do_ipv6_setsockopt` in net/ipv6/ipv6_sockglue.c of Linux (#491). A shorter value gives `EINVAL`, and the interface must be the device of `SO_BINDTODEVICE` if the socket has one. UDP sends on this interface when no other interface is set, as `udpv6_sendmsg`. Before, the option gave `ENOPROTOOPT`, and `ping -6 -I` of iputils stopped.
- `IPV6_PKTINFO` in the control messages of `sendmsg` for UDP, raw and ICMP echo sockets of IPv6, as `ip6_datagram_send_ctl` in net/ipv6/datagram.c of Linux (#491). The interface index sets the interface of the packet, and the address sets the source. A short message, an index that is not the interface of the destination, or a source that is not local gives `EINVAL`, and an interface that is not there gives `ENODEV`. Before, the kernel skipped the control messages of the levels other than `SOL_SOCKET`, so the DHCPv6 server of ISC sent its replies to a link local address on the wrong interface.
- tools/ltp/build-tools.sh copies netstat, traceroute, ss, ethtool, tcpdump, tracepath, the ping of iputils, ps, dhcpd, dhclient, dnsmasq, rpcbind and rpcinfo with their libraries from Alpine Linux, and `run.py --tools` puts them in the initramfs (#491). The script writes /etc/rpc and run.py writes the rpcbind entries of /etc/services, and the init script starts rpcbind. dhclient-script runs the ip of iproute2, and small scripts put the options of ping and tracepath before the address for the getopt of musl. tools/ltp/build.sh builds libtirpc without GSS-API, so that the RPC and TI-RPC tests of LTP link.
- In the `corten` backend, the status of each 4 KiB page is in a status table next to its last level page table in `VmSpace`, under the lock of the table, as CortenMM keeps the metadata of each page next to the page table page (#405). The page table tree keeps only the statuses of ranges of 2 MiB or more. `fork` copies the statuses in the same walk as the page table. The `vm` boot test examines the status table.

### Fixed

- A new user page on x86-64 does not send a TLB shootdown to the other CPUs, as `set_pte_at` in `finish_fault` and `do_anonymous_page` of Linux (mm/memory.c) (#468). A CPU keeps no TLB entry for an entry that is not present. Before, each page fault of a new page waited until each other CPU of the address space did the interrupt. 8192 page faults on 4 CPUs sent 6171 shootdowns, and now they send 12. Without KVM on a busy host, one `par_file_run` took up to 6 minutes, so the `smp` boot test sometimes went past its timeout of 600 seconds. `/proc/interrupts` has the `TLB` line of Linux, and the `smp` test checks it.
- The bzImage and UEFI runs of the `init` boot test have the time limit of the first run, 300 s, and not 120 s (#468). They run the same checks, which take about 120 s on a busy host, so they timed out when the first run passed.

## [0.4.16] - 2026-10-30

### Added

- The `smp` boot test checks the POSIX message queues, aio and KSM on 4 CPUs at the same time (#468). Threads send and receive on one queue while another thread unlinks it, and threads open and unlink one name at the same time. Threads submit and reap aio on one context while two threads destroy it, and one thread waits in `io_getevents`. Threads write to pages with stores and with `read` while `ksmd` merges them.
- The page faults, `mmap`, `munmap` and `brk` of one process do not share a lock for the heap, the reserved ranges or the soft-dirty state (#405). In the `corten` backend, a call that changes the page table tree adds the change to a log with one part for each group of CPUs, and only a `mmap` that searches for a free range takes the lock of the reserved ranges and applies the log first, as `vm_unmapped_area` of Linux searches with `mmap_lock` held. Only `brk` locks the heap fields, `MCL_FUTURE` is a flag, and a fault locks the guard pages only when the process has one. In both backends, the soft-dirty state takes its lock only after a write of 4 to /proc/PID/clear_refs.
- IPv4 forwarding, as net/ipv4/ip_forward.c and `ip_error` in net/ipv4/route.c of Linux (#458). With `forwarding` on for the input device, a packet for another host goes to the next hop of the route. The TTL goes down by one. A TTL of one gives ICMP time exceeded. A packet bigger than the MTU of the output device gives ICMP fragmentation needed if it has DF, else it is fragmented. A packet that goes out on the input device gives an ICMP redirect, with the rate limit of `ip_rt_send_redirect`. A route error gives ICMP network unreachable, host unreachable or packet filtered. /proc/net/snmp shows `Forwarding`, `ForwDatagrams` and `FragFails`.
- IPv6 forwarding, as net/ipv6/ip6_output.c of Linux (#458). With `all.forwarding` on, a packet for another host goes to the next hop. The hop limit goes down by one. A hop limit of one gives ICMPv6 time exceeded, and a packet bigger than the MTU gives ICMPv6 packet too big. Redirects, proxy NDP and the `forwarding` of each device are not done.
- Proxy ARP, as `arp_fwd_proxy` and `arp_process` in net/ipv4/arp.c of Linux (#458). The router replies to an ARP request for an address that it routes through another device when `proxy_arp` is on, or when a proxy entry matches. `RTM_NEWNEIGH`, `RTM_DELNEIGH` and the dump with `NTF_PROXY` add, remove and show the IPv4 proxy entries, as `pneigh_create` and `pneigh_delete` in net/core/neighbour.c. `SIOCSARP` and `SIOCDARP` with `ATF_PUBL` do the same, as `arp_req_set_public`. /proc/net/arp shows the proxy entries.
- The `netns` boot test checks forwarding through a router namespace with IPv4 and IPv6, ICMP time exceeded, fragmentation needed and fragmentation, and proxy ARP with `proxy_arp` and with `arp -s pub` (#458).
- The `smp` boot test checks processes and file systems on 4 CPUs at the same time (#468). Children end on each CPU while their own children end and a thread of init waits for them. A process group gets `SIGKILL` while its members fork. One CPU sends `SIGSTOP` and `SIGCONT` to a process that runs on another CPU. Threads open and close descriptors while another thread does `dup2` on them. Threads link, rename and unlink the same names, two threads rename two directories into each other, and one thread removes a directory while the others make files in it.

### Fixed

- `io_submit` takes the slots of its events before it does the requests, as `get_reqs_available` in fs/aio.c of Linux (#468). Before, two calls on two CPUs could put more events in a context than `io_setup` allowed. `io_destroy` removes the context in one step, so a second call gives `EINVAL`, wakes the tasks in `io_getevents`, and waits for the calls of `io_submit` in progress, as `kill_ioctx`. Before, a task in `io_getevents` waited until its timeout. `io_setup` does the map and the write to user memory without the spin lock of the contexts, and the contexts of two processes with the same ID do not replace each other.
- `mq_open` with `O_CREAT` and without `O_EXCL` opens the queue that another call made at the same time, and does not give `EEXIST` (#468). `mq_unlink` removes only the queue that it checked, so it cannot remove a new queue with the same name that another call made. The kernel sends the signal or the cookie of `mq_notify` without the lock of the queue, and compares the process of a registration and not its PID, as the `struct pid` of `notify_owner` in ipc/mqueue.c of Linux.
- KSM checks the count of references of a page after it makes the page read only, as `write_protect_page` in mm/ksm.c of Linux (#468). Before, a copy to user memory on another CPU that held the frame from before the protect could write it after the compare, and the write was lost or went to the KSM page.
- `fork` and the exit of a process hold a new lock of the tree of the processes for a write, and a signal to a process group or to all processes holds it for a read, as `tasklist_lock` in kernel/fork.c, kernel/exit.c and kernel/signal.c of Linux (#468). `fork` gives `ERESTARTNOINTR` if a signal came to the parent, as `copy_process` does. Before, a child that a member of a group made during `kill(-pgid, SIGKILL)` did not get the signal. Also, a child that ended while its parent ended could stay a zombie that init did not see, and a child of `CLONE_PARENT` could go in the list of a parent that ended. init now gets the exit signal of each zombie that it gets from a parent that ends, as `reparent_leader` does. `setpgid` and `setsid` hold the lock while they check and change the group.
- A `SIGCONT` cancels a stop signal that a thread took from its queue but did not apply yet, as `JOBCTL_STOP_DEQUEUED` in kernel/signal.c of Linux (#468). Before, a process could stop after the `SIGCONT` that came after the `SIGSTOP`, and stay stopped.
- Each directory has a lock that a create, a link, an unlink, a rmdir and a rename hold while they look up the names, check them and change them, as `i_rwsem` in fs/namei.c of Linux (#468). A rename between two directories also holds one rename lock, as `s_vfs_rename_mutex`. Before, two calls on two CPUs could lose a name or a link count in tmpfs, make two directories that are in each other, or remove a directory after a file was made in it. A removed directory takes no new name and gives `ENOENT`, as `S_DEAD`. A rename onto a directory above the source gives `ENOTEMPTY`, as `lock_rename` does.
- A lookup that does not find a name in the dentry cache adds the inode that the file system gave only if no create, unlink or rename changed the cache of the directory in the meantime, as fs/dcache.c of Linux (#468). Before, a lookup at the same time as an unlink could keep the removed name in the cache, and two lookups could make two dentries for one name.
- `io_cancel` reads the key of the request first, then checks it, then finds the context, as fs/aio.c of Linux (#341). A bad address of the request gives `EFAULT` before `EINVAL` for a bad context. The LTP tests io_cancel01 and io_cancel02 pass.
- An aio read or write on a file that cannot seek, such as a pipe or a socket, works as a stream and does not use the offset, as `aio_read` and `aio_write` in fs/aio.c of Linux (#341). `RWF_NOWAIT` on such a file gives `EAGAIN` in the event if the call must wait. A write to a pipe or a socket with `RWF_NOWAIT` from `pwritev2` does not wait, as `pipe_write` in fs/pipe.c. An aio request that a signal stops gives `EINTR` in the event. The LTP test io_submit04 passes.
- /proc/sys/kernel/sched_rr_timeslice_ms, sched_rt_period_us and sched_rt_runtime_us can be written, as `sched_rr_handler` and `sched_rt_handler` in kernel/sched/rt.c of Linux (#341). A time slice of 0 or less sets the default of 100 ms. A period below 1 gives `EINVAL`. A runtime below -1 or above the period gives `EINVAL`. `sched_rr_get_interval` gives the new time slice for `SCHED_RR`, rounded up to a tick. The LTP test proc_sched_rt01 passes.
- The loop devices accept `LOOP_SET_STATUS` and `LOOP_GET_STATUS` with the old `struct loop_info`, as `loop_set_status_old` and `loop_get_status_old` in drivers/block/loop.c of Linux (#341). Before, LTP got `ENOTTY` after `LOOP_SET_FD`, did not detach the device, and the file system of the file stayed busy, so swapon04 got `EBUSY` from `umount`.
- `recvmmsg` measures its timeout with the time stamp counter (#122). The clock of `uptime_ns` stops at the end of a tick until the interrupt of the next tick comes, and a system call runs with interrupts off. Thus a call that started after a tick was due saw no time pass after the first message, and with a short timeout it waited for a second message forever. This stopped the gVisor test `RecvmmsgTimeoutAfterRecv` in socket_unix_pair_test, with little CPU use.
- `accept` on a Unix socket that waits for a connection gives `EINVAL` after a `shutdown` of the listener, as `unix_accept` in net/unix/af_unix.c of Linux (#122). Before, the `shutdown` woke the task, but the task slept again and waited forever.
- `connect` on a Unix stream socket that waits for space in the backlog of the listener gives `ECONNREFUSED` after a `shutdown` of the listener, as `unix_wait_for_peer` of Linux (#122). Before, the task slept again and waited forever.

## [0.4.15] - 2026-10-29

### Added

- UTS namespaces, as kernel/utsname.c of Linux (#481). `clone` and `unshare` with `CLONE_NEWUTS` give the thread a new namespace with a copy of the host name and the NIS domain name, and `uname`, `sethostname`, `setdomainname` and /proc/sys/kernel use the namespace of the caller. It needs `CAP_SYS_ADMIN`.
- IPC namespaces, as ipc/namespace.c of Linux (#481). `clone` and `unshare` with `CLONE_NEWIPC` give the thread a new namespace with no shared memory segments, message queues, semaphore sets or POSIX message queues. The objects of a namespace go when its last thread leaves it. `CLONE_NEWIPC` with `CLONE_SYSVSEM` in `clone` gives `EINVAL`, and `unshare` with `CLONE_NEWIPC` or `CLONE_SYSVSEM` does the semaphore undo changes, as `exit_sem`.
- `setns` joins a UTS or an IPC namespace through a file of /proc/PID/ns or through a pidfd (#481). An open file of the namespace keeps it. setns02 of LTP passes.
- /proc/sys/fs/lease-break-time and /proc/sys/fs/leases-enable, as fs/locks.c of Linux (#481). A write keeps the value, so fcntl33 gives TCONF without a TWARN. fcntl33 skips tmpfs by design.
- Lease breaks, as `__break_lease` in fs/locks.c of Linux (#481). Each inode has a list of leases. An `open` for a write and a `truncate` break all the leases of the file, and an `open` for a read breaks the write leases. The holder gets `SIGIO` or the signal of `F_SETSIG`, and the caller waits until the holder downgrades or removes the lease with `F_SETLEASE`, or for /proc/sys/fs/lease-break-time seconds. With `O_NONBLOCK` the `open` gives `EWOULDBLOCK`. `F_GETLEASE` gives the type that the lease has after the break. A new lease makes the process the owner of the file for the signal. With /proc/sys/fs/leases-enable at 0, `F_SETLEASE` gives `EINVAL`. fcntl33 passes with its directory on ext2.
- ELF core dumps, as fs/coredump.c and fs/binfmt_elf.c of Linux (#475). A signal with a core dump action writes an `ET_CORE` file with a `PT_NOTE` and a `PT_LOAD` for each area. The notes are `NT_PRSTATUS` and `NT_PRFPREG` for each thread, `NT_PRPSINFO`, `NT_SIGINFO`, `NT_AUXV` and `NT_FILE`. The other threads stop and give their registers before the dump. The content of each area follows /proc/PID/coredump_filter and `MADV_DONTDUMP`. `RLIMIT_CORE` cuts the file, and a limit below one page gives no dump. The status of `wait` has `WCOREDUMP` only when the kernel opened the file. x86-64 and arm64 use the same code. madvise08, coredump02, abort01, kill11, setrlimit01 and waitid10 of LTP pass, and the `ltp` boot test runs all of them except coredump02. tools/ltp/kconfig has `CONFIG_COREDUMP`.
- /proc/sys/kernel/core_pattern with `%%`, `%p`, `%P`, `%i`, `%I`, `%u`, `%g`, `%d`, `%s`, `%t`, `%h`, `%e`, `%E`, `%f`, `%c` and `%C`, and /proc/sys/kernel/core_uses_pid, as `format_corename` in fs/coredump.c of Linux (#475). A pattern that starts with `|` or `@` gives no dump, because the kernel has no usermode helper. Thus the pipe part of coredump01 of LTP fails.
- `madvise` with `MADV_DONTDUMP` and `MADV_DODUMP` sets and clears `VM_DONTDUMP` on the areas (#475).
- `PR_SET_DUMPABLE`, `PR_GET_DUMPABLE` and /proc/sys/fs/suid_dumpable, as kernel/sys.c and fs/exec.c of Linux (#475). `execve` of a file that the caller cannot read, or with a set-user-ID or set-group-ID change, and a change of the effective or file system IDs set the flag to fs.suid_dumpable. With the value 2 the core file must have an absolute path and is written as root.
- The `inet` boot test checks that a socket of DCCP or SCTP gives the error of Linux without these modules (`ESOCKTNOSUPPORT` or `EPROTONOSUPPORT`, as `inet_create` in net/ipv4/af_inet.c), so that the LTP tests dccp01 and sctp01 give TCONF for them (#458). tools/ltp/notes.txt gives the cause of the LTP tests of the network that still fail because the BusyBox tools do not have an option, or because they run longer than the time limit.
- Mapped packet rings for `AF_PACKET`, as net/packet/af_packet.c of Linux (#475). `PACKET_VERSION` takes `TPACKET_V1`, `TPACKET_V2` and `TPACKET_V3`, and `PACKET_RX_RING` and `PACKET_TX_RING` take a `struct tpacket_req` or a `struct tpacket_req3` with the checks of `packet_set_ring`. A shared `mmap` of the socket maps the receive ring and then the transmit ring. A received frame goes to the frame at the head of the ring with its header and its `struct sockaddr_ll`, and gets `TP_STATUS_USER`. A `TPACKET_V3` ring puts the frames in blocks, and a kernel task gives a block with frames to the program after `tp_retire_blk_tov` milliseconds. `poll` waits for a frame or a block that the program owns. A `send` on a socket with a transmit ring sends each frame with `TP_STATUS_SEND_REQUEST`. setsockopt02 of LTP passes. setsockopt06, setsockopt07, setsockopt09 and sendto03 still give TCONF, because they need user namespaces.
- `PACKET_STATISTICS`, `PACKET_HDRLEN`, `PACKET_RESERVE`, `PACKET_LOSS` and `PACKET_TIMESTAMP` for packet sockets, as `packet_setsockopt` and `packet_getsockopt` of Linux (#475). `getsockopt` reads the value first for `PACKET_HDRLEN`.

### Fixed

- A signal with a core dump action stops the process from a thread of the process, after it is queued, as `complete_signal` in kernel/signal.c of Linux (#475). Before, the sender stopped the process at once.
- `F_SETLEASE` with `F_WRLCK` gives `EAGAIN` when another file has the inode open for a read, and `F_SETLEASE` with `F_UNLCK` gives `EAGAIN` when the file has no lease, as `check_conflicting_open` and `generic_delete_lease` in fs/locks.c of Linux (#481). A lease conflicts with the leases of other files, and goes away when its file closes. fcntl32 passes with its directory on ext2.
- `splice` gives `EINVAL` for a file that has no `splice_read` or `splice_write` of Linux, as a directory, an eventfd, an epoll, a signalfd, a timerfd, a pidfd or an inotify file, before it waits for the pipe (#481). This is `warn_unsupported` in fs/splice.c. splice07 of LTP waited for the empty pipe until the runner stopped it, and it passes now.
- `setsockopt` with `IPV6_CHECKSUM` at the level `SOL_RAW` on a raw ICMPv6 socket sets the offset of the checksum, as `do_rawv6_setsockopt` in net/ipv6/raw.c of Linux (#458). The level `IPPROTO_IPV6` still gives `EINVAL` for ICMPv6, and an odd offset gives `EINVAL`. Before, both levels gave `EINVAL`, so `traceroute6 -I` of BusyBox stopped and LTP traceroute601 failed.

## [0.4.14] - 2026-10-29

### Added

- The page table of a process has a lock for each 2 MiB block, as the split page table locks of Linux (`pte_lockptr` in include/linux/mm.h), and a new upper table goes in with a compare and swap, as `pmd_install` in mm/memory.c (#468). Page faults in two blocks of one process do not wait for each other. The areas of the VMA backend have a read-write lock, as `mmap_lock`, and a fault takes it for a read.
- The frame allocator and the heap keep a list of free frames and of free objects for each CPU, as the per-CPU pagesets of mm/page_alloc.c (#468). A list takes and gives back a batch of 32 frames or 16 objects under the global lock. An allocation that finds no free frame or no free run takes back the lists of all the CPUs first.
- `futex_waitv`, as `sys_futex_waitv` in kernel/futex/syscalls.c of Linux (#475). A thread waits on up to 128 futexes of 32 bits, private or shared, with an absolute timeout of `CLOCK_MONOTONIC` or `CLOCK_REALTIME`, and gets the index of the futex that a wake woke. `FUTEX2_NUMA` gives `EINVAL`. Before, the call gave `ENOSYS`, futex_waitv02 and futex_waitv03 stopped with TCONF while their thread still used the memory that the cleanup freed, and the thread got `EFAULT` or SIGSEGV.
- /proc/PID/coredump_filter, as fs/proc/base.c of Linux (#475). The default is `00000033`, a write takes a number in the base of its prefix and keeps the 9 bits of the filter, and a child of `fork` gets the value of its parent. madvise08 now reads the file, but it still stops with TBROK because rukernel writes no core dump.
- Each cgroup keeps its memory and pids charges in atomic counters, as `page_counter` of Linux (mm/page_counter.c) and `pids_try_charge` (kernel/cgroup/pids.c) (#468). A charge adds to each counter from the cgroup to the root, and a counter at its limit takes the charge back from the counters below it. A charge, an uncharge, the CPU time, the PSI state and the fork and exit of a task do not take the lock of the cgroup tree. The lock is only for a change of the tree, a move of a task, a change of `cgroup.events` and a removed cgroup that goes after its last charge.
- The page cache of a block device does not hold its lock while the device reads or writes, as the folio lock and the writeback flag of Linux (mm/filemap.c) (#468). A second read of a folio that a read fills waits for it and does not read the device again. A page that a write back sends is clean during the write, and a write to it makes it dirty again. `forget` waits for the bios of its folios, and the shrink of the cache does not drop them.

### Fixed

- After a `fork`, a private area that the child got does not merge with a new area next to it, as `is_mergeable_anon_vma` in mm/vma.c of Linux, because its `anon_vma` chain is not singular (#475). The pieces of one such area still merge again after an `mprotect` and back. LTP vma01 failed since the area merge of #405.
- /proc/PID/ns has no `user` link, as Linux without `CONFIG_USER_NS`, because rukernel cannot make a user namespace (#475). `NS_GET_USERNS` gives `EPERM` and `setns` of a pidfd with `CLONE_NEWUSER` gives `EINVAL`, as on that Linux. getxattr05 found the link and then got `EINVAL` from `unshare(CLONE_NEWUSER)`. ioctl_ns04 now gives TBROK, as on that Linux, because its setup reports TCONF and does not stop the test.
- `PACKET_VERSION` of `AF_PACKET` sockets takes `TPACKET_V1` and `getsockopt` gives it (#475). `TPACKET_V2` and `TPACKET_V3` give `EINVAL`, because there are no mapped rings yet, so setsockopt02 reports TCONF and not `ENOPROTOOPT`.
- A page fault of a file mapping reads the file without the lock of the address space, and tries the fault again with the page, as `filemap_fault` of Linux with `FAULT_FLAG_RETRY` (mm/filemap.c) (#468). `munmap`, `mremap`, `brk`, `msync` and the end of an address space write the shared file pages back after they drop the lock. Before, a fault or an unmap on one CPU stopped the faults of the other threads of the process during the file I/O.
- Two reads of one page of a mapped file on two CPUs give the same page, and a read that runs during a write or a truncate of the file reads the page again, with a count of the changes of the file (#468). Before, the read that came last could put old data over the page of the first one.

## [0.4.13] - 2026-10-29

### Added

- The CPUs run system calls, page faults and the scheduler at the same time, without the big kernel lock (#405). A task has an `on_cpu` flag, as Linux has, and a wake of a task that did not switch yet puts it in a queue after the switch. A CPU that waits for a spin lock does the TLB requests of the other CPUs. The `big-lock` feature of rukernel keeps the old lock for a comparison.
- The `blk` boot test has a second disk with ext2, which xtask makes with mkfs.ext2. Init writes 50 MB to a file on it in chunks of 1 MiB, and 4 MB in chunks of 1 KiB in a memory cgroup, as memcontrol03 of LTP. It calls fsync, checks the data and prints the times (#446).
- The IPv4 multicast socket options `IP_MULTICAST_IF`, `IP_ADD_MEMBERSHIP`, `IP_DROP_MEMBERSHIP`, `MCAST_JOIN_GROUP`, `MCAST_LEAVE_GROUP` and `IP_MULTICAST_ALL` for UDP and raw sockets, as net/ipv4/ip_sockglue.c and net/ipv4/igmp.c of Linux (#458). A membership joins the group on the device, and a socket gets the multicast datagrams of its groups. With `IP_MULTICAST_LOOP`, the host also gets the multicast packets that it sends.
- `IP_BIND_ADDRESS_NO_PORT` for UDP and TCP sockets: `bind` to the port 0 sets only the address, and `connect` gives the port, as `__inet_bind` of Linux (#458).
- A change of a neighbour entry of IPv4 or IPv6 sends `RTM_NEWNEIGH` or `RTM_DELNEIGH` to `RTNLGRP_NEIGH`, as `neigh_update_notify` and `__neigh_notify` of Linux (#458). Thus `ip monitor neigh` shows the changes.

### Fixed

- A `FUTEX_WAIT` on one CPU does not lose a `FUTEX_WAKE` from another CPU: the waiter is in the queue before the read of the word, as in kernel/futex/waitwake.c (#405). `FUTEX_LOCK_PI` and `FUTEX_UNLOCK_PI` change the word with a compare and exchange that they do again on failure.
- `rt_sigaction` with `SIG_IGN` and `wait4` in two threads of one process do not wait for each other, because `set_action` takes the list of threads before the lock of the signals (#405).
- A thread that `clone` makes while another thread starts `exit_group` is killed, so the exit of the group does not wait for it (#405).
- Two Unix sockets with `SO_PASSCRED` that send to each other on two CPUs do not wait for each other, and the count of the bytes in flight does not wrap when the receiver takes the data before the count goes up (#405).
- A `read` into a page that a `fork` on another CPU makes read only faults the page in again and does not give `EFAULT` (#405).
- A write to an ext2 or ext3 file with a block map finds the blocks in runs, as `ext2_get_blocks` in fs/ext2/inode.c of Linux, and each run goes to the page cache in one call. A small write reads and writes only the entries of the map and the bytes of the bitmap that it uses, not whole blocks. With all the changes of #446 in this list, the release kernel under QEMU without KVM writes 50 MB in chunks of 1 KiB in a memory cgroup, as memcontrol03 and memcontrol04 of LTP, in about 5.0 s, not 7.4 to 9.5 s. In chunks of 1 MiB the write takes 1.3 to 1.5 s, not 2.3 to 3.1 s (#446).
- virtio-blk sends up to 512 KiB in one request, the largest request of the block queue, not 64 KiB, as `seg_max` in drivers/block/virtio_blk.c of Linux (#446).
- The page cache drops clean folios until it is an eighth below its limit, as the watermarks of kswapd in mm/vmscan.c of Linux. Before, each read and each write over the limit sorted all the clean folios to drop one folio (#446).
- A read or a write of the page cache checks the limit of the memory cgroup only after it charged a new folio, as `mem_cgroup_charge` of Linux. Before, each call took the lock of the cgroups (#446).
- `IP_MULTICAST_TTL`, `IP_MULTICAST_LOOP` and the other number options of `IPPROTO_IP` take a value of one byte, as `do_ip_setsockopt` of Linux. They gave `EINVAL` (#458).
- `poll`, `select` and `epoll_wait` on an IPv4, IPv6, packet or netlink socket wake at a new event of the socket. Before, the wrapper of the network namespace did not add the queue of the socket, so a wait without a timeout did not end, and a wait with a timeout ended only at the timeout. recvmsg01 of LTP passes (#470).

## [0.4.12] - 2026-10-29

### Added

- The `inet` boot test makes a veth pair with RTM_NEWLINK and `VETH_INFO_PEER`, with the peer in another network namespace. It checks `IFLA_LINK`, the carrier, /proc/net/dev and /sys/class/net, sends a UDP datagram across the pair, and deletes the pair (#454).
- Each queue of a virtio-pci device gets its own MSI-X vector, and the configuration gets one more, as `vp_find_vqs_msix` of Linux (#450). This works on arm64 through the GICv3 ITS, with an event ID for each vector, and on x86-64. If the function does not have enough vectors, the device uses one shared vector, and then its INTx pin.
- The PCI scan on arm64 assigns the I/O BARs from the I/O window of the host and opens the I/O window of each bridge over the I/O BARs behind it, as `pbus_size_io` and `pci_setup_bridge_io` of Linux (#450). A driver can map an I/O BAR with `map_io_bar`. The arm64 boot test `blk` with INTx behind a `pcie-root-port` uses a transitional device and reads its legacy registers through the I/O BAR.
- `SO_BINDTODEVICE` and `SO_BINDTOIFINDEX` for TCP, UDP, ping and raw sockets of IPv4 and IPv6, with getsockopt, as `sock_bindtoindex` in net/core/sock.c of Linux. A bound socket takes only the packets of its device and sends on it. An empty name removes the device. A change of the device needs `CAP_NET_RAW` (#458).
- `RTM_DELNEIGH`, and `NLM_F_CREATE`, `NLM_F_EXCL` and `NLM_F_REPLACE` for `RTM_NEWNEIGH`, with the `NUD_PERMANENT`, `NUD_NOARP`, `NUD_REACHABLE` and `NUD_STALE` states, as `neigh_add` and `neigh_delete` in net/core/neighbour.c. `ip neigh add`, `ip neigh replace` and `ip neigh del` work (#458).
- The `SIOCSARP`, `SIOCGARP` and `SIOCDARP` ioctls, as `arp_ioctl` in net/ipv4/arp.c, for `arp -s` and `arp -d`. /proc/net/arp gives the flags 0x6 for a permanent entry (#458).
- /proc/net/igmp, /proc/net/igmp6 and /proc/net/dev_mcast in the format of Linux, for `ip maddr show`. `SIOCADDMULTI` and `SIOCDELMULTI` keep a list of link addresses for each device, as `dev_mc_add_global` of Linux, so `ip maddr add` and `ip maddr del` work (#458).
- A device that goes up joins 224.0.0.1, as `ip_mc_up` in net/ipv4/igmp.c. It answers a ping to the group when `net.ipv4.icmp_echo_ignore_broadcasts` is 0 (#458).
- The `inet` boot test checks large pings, `IP_PMTUDISC_DO`, `SO_BINDTODEVICE`, a ping to 224.0.0.1, the multicast files, `RTM_NEWNEIGH`, `RTM_DELNEIGH` and the ARP ioctls over the veth pair. The `netns` test sends large pings with IPv4 and IPv6 (#458).
- The kernel writes `x2apic enabled` in the boot log when it puts the local APIC in x2APIC mode, as `x2apic_enable` of Linux. The `init` boot test checks that the kernel uses the x2APIC if and only if CPUID gives it (#442).
- `RK_QEMU` gives the directory of the QEMU programs of `cargo xtask qemu` and the boot tests, and `RK_QEMU_CPU` gives the x86-64 CPU model without KVM. `tools/bench/run.py` has `--qemu` and `--cpu` (#442). With QEMU 9.2.4, which gives the x2APIC under TCG, the boot tests `init`, `smp`, `busybox`, `mm`, `task`, `blk` and `inet` pass in x2APIC mode, and the bench shows no difference between the two modes. tools/bench/README.md gives the numbers and results-x2apic.md has the table.
- `tools/bench/linux-arm64.sh` builds a Linux 7.3 arm64 `Image` with `defconfig`, from the tarball that tools/rk-abigen uses. tools/bench/results-aarch64.md is the first arm64 table with a Linux column. `tcp_stream` is red in it, with 25.7 MB/s on rukernel and 57.5 MB/s on Linux (#442).

### Fixed

- `tools/ltp/build-ip.sh` builds `ip` with `SHARED_LIBS=n`. The static `ip` did not find the veth link kind, so `ip link add ... type veth peer name ...` failed with "Garbage instead of arguments" and the LTP net tests did not start (#454).
- /sys/class/net/NAME/iflink of a veth device gives the index of the other end, as `veth_get_iflink` of Linux (#454).
- `populated` of `cgroup.events` changes at once on the path from the cgroup up to the first cgroup whose value does not change, as `cgroup_update_populated` of Linux (#446). Before, the exit of the last task of a cgroup made `refresh_events` go over each cgroup. In the init boot test, the stop of 100 processes, each in its own leaf of a tree of 1110 cgroups, takes 1070 ms, not 7508 ms. A read of a cgroup file counts the dying cgroups only for `cgroup.stat`.
- tools/ltp/run.py gives cgroup_fj_stress_memory_10_3_each a limit of 600 s, and runs memcontrol03 and memcontrol04 each in their own boot, so the cgroups that they leave do not change the later tests (#446). tools/ltp/notes.txt gives the cause of the `EBUSY` and the segfault in the cleanup of memcontrol04.
- IPv4 and IPv6 packets that are larger than the MTU go in fragments, as `ip_do_fragment` in net/ipv4/ip_output.c and `ip6_fragment` in net/ipv6/ip6_output.c, and the fragments that come in are put together again, as net/ipv4/ip_fragment.c and net/ipv6/reassembly.c. Before, `ping -s 2048` and `ping -s 4064` over a veth pair failed. `IP_PMTUDISC_DO`, `IP_PMTUDISC_PROBE` and `IPV6_DONTFRAG` still give `EMSGSIZE` (#458).
- The boot job of CI compiles the x86-64 user programs with `zig cc -target x86_64-linux-musl` in `RK_USER_CC` (#450). The musl-gcc of Ubuntu 24.04 has no Linux uAPI headers, and its musl 1.2.4 has no `statx`, so tests/user/init.c did not compile.
- The documentation of `compat::RESIZE_INODE` in rk-fs-ext4 links to `RESIZE_INO` with a path, so `cargo doc` with `-D warnings` passes in CI (#450).
- tools/ltp/build.sh builds the LTP directories mq_notify, mq_timedreceive, mq_timedsend, mq_unlink, msgctl, msgget, msgrcv, msgsnd and shmget (#450). tools/ltp/tests.txt has their tests since #342, so the `ltp` boot test stopped with "No such file or directory" in CI.
- The boot job of CI gives the runner user access to /dev/kvm with a udev rule, so QEMU runs with KVM and the `ltp` boot test ends in its time limit (#450). tools/ltp/tests.txt no longer has clock_gettime04, eventfd06, futex_waitv02, kill11, sendfile07_64 and splice07, which fail in the last full LTP run.
- The `ltp` boot test mounts sysfs before the tests, so madvise02 finds /sys/kernel/mm/ksm and does not expect `EINVAL` for `MADV_MERGEABLE` (#450).

## [0.4.11] - 2026-10-29

### Added

- MSI-X on arm64 through the GICv3 ITS, as drivers/irqchip/irq-gic-v3-its.c of Linux (#424). The kernel finds the ITS and the `msi-map` of the PCI host in the device tree, turns on the LPIs of each redistributor and maps each MSI-X vector to an LPI with `MAPD` and `MAPTI`. The virtio-pci devices on the QEMU `virt` machine use MSI-X when the machine has an ITS, and INTx when it has none.
- PCI bridges and the buses after bus 0 on arm64, as `pci_scan_bridge` of Linux (#424). The scan gives the bus numbers and the memory windows of each bridge, and the INTx pin of a device behind a bridge goes through the swizzle of each bridge. The arm64 boot tests run `blk` and `inet` with virtio-pci on bus 0 and behind a `pcie-root-port`.
- tools/ltp/syscalls-aarch64.md, the baseline of the LTP syscalls group on the arm64 kernel (#424). `report.py --arch aarch64` and `RK_LTP_ARCH=aarch64 tools/ltp/update.sh` make it from the runs of `run.py --arch aarch64`.
- A TUN device takes `IFF_MULTI_QUEUE`, `TUNSETQUEUE` with `IFF_ATTACH_QUEUE` and `IFF_DETACH_QUEUE`, and `TUNSETIFINDEX`, as tun.c of Linux (#429). Up to 256 files are queues of one device, and a hash of the flow picks the queue of a packet. A detached queue gives `EBADFD` and `POLLERR`.
- The IPv6 stack answers MLD queries of version 1 and 2 after a random delay, and `IPV6_JOIN_GROUP`, `IPV6_LEAVE_GROUP`, `MCAST_JOIN_GROUP` and `MCAST_LEAVE_GROUP` send MLD reports, as mcast.c of Linux (#429). After an MLDv1 query, or with `force_mld_version` 1, the stack sends MLDv1 reports and done messages.
- A TUN device gets a link local address with a random interface identifier when it goes up, as addrconf.c of Linux (#429).
- Optimistic duplicate address detection, as RFC 4429 and addrconf.c of Linux (#429). With `optimistic_dad`, the link local and SLAAC addresses are optimistic, and a program can add an optimistic address. An optimistic address is a source address after the preferred ones, or before them with `use_optimistic`. The first probe of an address that is not optimistic comes after a random delay of up to `router_solicitation_delay`.
- `/proc/PID/pagemap` gives `PM_GUARD_REGION` (bit 58) and `PM_SWAP` for a guard page of `MADV_GUARD_INSTALL`, as task_mmu.c of Linux (#444).
- The line disciplines `N_SLIP` and `N_SLCAN` for `TIOCSETD` on a pseudo terminal slave, as slip.c and slcan-core.c of Linux (#433). Each makes a network device, `slN` or `slcanN`, and `SIOCGIFNAME` on the slave gives its name. A write to the master gives frames to the device, and a frame that the device sends goes to the master. A hang up of the slave or of the master removes the device. A packet socket that is bound to a device that goes down gets `ENETDOWN`, as `packet_notifier` of Linux.

### Fixed

- `/proc/PID/pagemap` gives `PM_MMAP_EXCLUSIVE` from the map count of the frame, not from the reference count, as task_mmu.c of Linux (#444). A page that two mappings of a shared file map is not exclusive.
- An unmap clears the soft-dirty state of its pages, and the pages of stack growth keep the soft-dirty state of the area, as Linux (#444).
- `/proc/kpageflags` gives `KPF_MMAP` for a hugetlb page only while a process maps it, as fs/proc/page.c of Linux (#444).
- `TIOCSPGRP` from a process in a background group of the terminal sends `SIGTTOU` to the group and starts again after the signal, as `tty_check_change` of Linux (#433). A process that blocks or ignores `SIGTTOU` sets the group. A process in an orphaned group gets `ENOTTY`.

## [0.4.10] - 2026-10-29

### Added

- The console takes `TIOCVHANGUP`, as `tty_vhangup` of Linux (#433). It needs `CAP_SYS_ADMIN`. The open files of the console hang up, the console has no session after it, and the session leader gets `SIGHUP` and `SIGCONT`. A new open of the console works.
- The console takes `TIOCSCTTY` and `TIOCNOTTY` with the rules of `tiocsctty` and `tiocnotty` of Linux, and an open of /dev/ttyS0 without `O_NOCTTY` makes the console the controlling terminal of a session leader without one (#433). An open of /dev/console never does.
- `statfs` on devpts gives `DEVPTS_SUPER_MAGIC` (0x1cd1) (#433).
- The kernel heap gives an object of up to 4 pages from the direct map, as `kmalloc_large` of Linux, so its allocation and its free change no page table and send no TLB shootdown (#401). Up to 8 freed objects of up to 16 pages, as the kernel stacks, stay mapped for the next allocation of the same size, as `cached_stacks` of Linux. On QEMU TCG with 4 CPUs, `mmap` and `munmap` of 64 KiB goes from 594 us to 19 us, `fork` from 4.9 ms to 3.2 ms and `pthread_create` and `pthread_join` from 5.2 ms to 3.0 ms (tools/bench/cortenmm.md).
- `VmSpace` keeps one entry for each huge page and not one for each of its 512 pages, so `fork` and the exit of a process do not walk them (#401). `fork_big` (128 MiB of written private memory) goes from 26 ms to 9 ms on the default backend and from 146 ms to 19 ms with the `corten` feature, on a base before #405.
- The release profile uses thin LTO (#401). On QEMU TCG with 1 CPU, `getpid` goes from 2419 ns to 1679 ns, `read` of /dev/zero from 4528 ns to 2758 ns and `sched_yield` from 2639 ns to 1860 ns. A clean release build takes 68 s and not 71 s, and a rebuild after a change in rk-frame takes 49 s and not 41 s. Fat LTO was faster again on some rows (`getpid` 1319 ns), but its clean build took 119 s and its rebuild 96 s.
- On arm64, the `fork` copy of the page tables finds the last level table once for each 2 MiB, and makes no TLB flush for the new address space (#401). The permission change of the pages of the parent makes one TLB invalidation of all user pages, not one for each page.
- The write back of a shared file mapping makes the mappings of each page read only, as `folio_mkclean` of Linux (#430). The next write to a page is a fault that marks the page dirty again. This replaces the `Written` state of a page.
- `/proc/kpageflags` finds the file of a page from its frame through a map of the frames of the page caches (#430). It does not search the mapped files of each process.
- `/proc/kpageflags` gives `KPF_COMPOUND_HEAD`, `KPF_COMPOUND_TAIL`, `KPF_HUGE`, `KPF_THP`, `KPF_KSM` and `KPF_ZERO_PAGE`, as `stable_page_flags` of Linux (#430). A private hugetlb page has `KPF_ANON`.
- `/proc/PID/pagemap` gives `PM_MMAP_EXCLUSIVE` (bit 56) and `PM_SOFT_DIRTY` (bit 55) (#430). A write of 4 to the new file `/proc/PID/clear_refs` makes all the pages of the process clean, and the next write to a page makes it soft-dirty again.
- The signal actions of a process (2 KiB) are in a box of their own, so that `Process` with the counts of its `Arc` is 968 bytes and fits the slab class of 1024 bytes of the kernel heap (#442). It was 3008 bytes, a large object of one page. The build checks the size.
- tools/bench/cortenmm.md has the `fork` A/B with the changes of both #405 and #401 (#442). CortenMM is 1.9 times slower than VMA in `fork` (4484 and 2367 us) and 3.0 times slower in `fork_big` (22640 and 7467 us). The walk of the statuses is the cost that is left.
- tools/bench/README.md gives the cause of the drop of `udp_stream` from 16.8 MB/s to 4.73 MB/s (#442): the EEVDF wakeup preemption of #408 lets the receiver take the CPU at each datagram, as in Linux. A bisect found 2bcd83e. Without the wakeup preemption the base gives 21.0 MB/s, and with it 5.29 MB/s, and Linux 5.50 MB/s. The README also has the numbers of the arm64 `fork` copy of #401: `fork` from 0.84 to 0.65 ms and `fork_big` from 7.7 to 2.9 ms on QEMU TCG.

### Fixed

- An open of /dev/tty without a controlling terminal gives `ENXIO`, as `tty_open_current_tty` of Linux (#433). It opened the console before.
- A hang up of a pseudo terminal slave with `TIOCVHANGUP` and the close of the master send `SIGHUP` and `SIGCONT` to the session leader, as `tty_signal_session_leader` of Linux (#433). The close of the master also takes the session from the slave.
- `TIOCSPGRP` checks the session, as `tiocspgrp` of Linux (#433). A terminal that is not the controlling terminal of the caller gives `ENOTTY`, a group that no process has gives `ESRCH`, and a group of another session gives `EPERM`.
- `TIOCNOTTY` from a process that is not the session leader drops the controlling terminal of the process, as `proc_clear_tty` of Linux (#433). It did nothing before. A child of `fork` keeps this state, and `setsid` clears it.
- `TIOCGPGRP` and `TIOCGSID` on the console give `ENOTTY` when the console is not the controlling terminal of the caller, as `tiocgpgrp` and `tiocgsid` of Linux (#433).
- `mknod`, `mkdir`, `symlink`, `link`, `unlink`, `rmdir` and `rename` in devpts give `EPERM`, and `O_TMPFILE` gives `EOPNOTSUPP`, as Linux (#433).
- The status table of tools/ltp/README.md has the pty group (#433).
- `TIOCGPTPEER` on a master from a bind mount of /dev/pts/ptmx on /dev/ptmx finds the devpts mount, as `devpts_mntget` of Linux (#433). It failed before.
- `KPF_SWAPBACKED` is bit 14 in `/proc/kpageflags`, as in Linux (#430). It was bit 23.
- The KSM zero frame has no `PM_FILE` bit in `/proc/PID/pagemap`, as the zero page of Linux (#430).
- An exec maps each page of an ELF segment that has only file data from the shared pages of the file, as Linux maps the page cache, and a write copies the page (#423). Before, each exec read and copied each page of the program again. Under QEMU without KVM, fork and exec of BusyBox is about 2 to 4 times faster, and the phases of cgroup_fj_stress that run many commands are about 3 times faster. Eleven of the twelve cgroup_fj_stress tests for cpuset, cpu and memory with 2_9 and 10_3 now end in 99 to 218 s, in the 240 s limit of the runner.
- The fault of an ELF page that the file data does not fill writes the data once and sets only the rest of the page to zero, and `execve` reads its strings in chunks of 128 bytes, not in a zeroed page for each string (#423).
- tools/ltp/notes.txt gives the causes of the TWARN of cgroup_fj_function_cpuset, of memcg_test_3, and of memcontrol03 and memcontrol04, with the results of Linux 6.8 in the same runner (#423).

## [0.4.9] - 2026-10-29

### Added

- TUN and TAP devices on /dev/net/tun, as drivers/net/tun.c of Linux (#410). `ioctl` has `TUNSETIFF`, `TUNGETIFF`, `TUNGETFEATURES`, `TUNSETPERSIST`, `TUNSETOWNER`, `TUNSETGROUP`, `TUNSETLINK`, `TUNSETOFFLOAD`, `TUNSETTXFILTER`, `TUNGETSNDBUF`, `TUNSETSNDBUF`, the `vnet` header commands and `TUNSETCARRIER`. The files read and write packets with the `tun_pi` header and the `virtio_net_hdr` header.
- `AF_PACKET` sockets get the frames that a device receives and, for `ETH_P_ALL`, the frames that it sends, with `sockaddr_ll`, `MSG_PEEK`, `MSG_TRUNC`, `poll` and `PACKET_ADD_MEMBERSHIP` (#410).
- rtnetlink sends `RTM_NEWNSID` and `RTM_DELNSID` to the `RTNLGRP_NSID` group, and `RTM_GETNSID` takes `NETNSA_TARGET_NSID` and gives `NETNSA_CURRENT_NSID` (#410).
- IPv6 duplicate address detection, as net/ipv6/addrconf.c of Linux (#410). A new address is `tentative` until the probes end, and a conflict marks it `dadfailed`. The interface sends an MLDv2 report when it joins the solicited node group of an address.
- tools/ltp/build-ip.sh builds a static iproute2 `ip` for the LTP image (#410).
- devtmpfs and /sys/class make the nodes of devices with a directory in the name, as /dev/net/tun (#410).
- /proc/kpageflags gives `KPF_ANON`, `KPF_SWAPBACKED`, `KPF_UPTODATE`, `KPF_LRU` and `KPF_MMAP` for the anonymous pages of the processes, as fs/proc/page.c of Linux (#421). Each frame of anonymous memory has a mark, as `PageAnon` of Linux.
- `ioctl` `TIOCGPTPEER` on the master of a pseudo terminal opens the slave and gives a new file descriptor, as `ptm_open_peer` of Linux (#413). The flags of the open come from the argument, and the slave of another file gives `EIO`.
- A pseudo terminal can be the controlling terminal of a session (#413). `TIOCSCTTY` makes the slave the controlling terminal of a session leader, as `tiocsctty` of Linux, and with the argument 1 and `CAP_SYS_ADMIN` it takes the slave from another session. `TIOCNOTTY` ends it. An open of a slave without `O_NOCTTY` by a session leader without a controlling terminal makes the slave its controlling terminal. `/dev/tty` opens the slave, and the exit of the session leader sends `SIGHUP` to the foreground process group. `TIOCGSID` and `TIOCGPGRP` on a slave give `ENOTTY` to a process of another session.
- `ioctl` `TIOCVHANGUP` hangs up a pseudo terminal, as `tty_vhangup` of Linux (#413). It needs `CAP_SYS_ADMIN`. After the hang up a read gives 0, a write and an ioctl give `EIO`, and a poll gives `POLLHUP` and `POLLERR`. LTP pty04 now gets to the line disciplines, which rukernel does not have.
- Each mount of devpts is a new instance with its own slaves and numbers, as `get_tree_nodev` in fs/devpts/inode.c of Linux (#413). devpts takes the options `newinstance`, `mode`, `ptmxmode`, `uid`, `gid` and `max`, and an unknown option gives `EINVAL`. /dev/ptmx uses the instance on /dev/pts, and the `ptmx` file of devpts uses its own instance.
- IPv6 processes the routing header on receive, as `ipv6_rthdr_rcv` of net/ipv6/exthdrs.c of Linux (#413). A segment routing header (type 4) goes to the next segment of the list when `seg6_enabled` is on, and a header with no segments left that holds an IPv4 or IPv6 packet gives the inner packet. A bad header gives an ICMPv6 parameter problem, and a hop limit of 1 gives an ICMPv6 time exceeded. rukernel does not forward, so a packet for another address is dropped.
- The LTP tools record the results of the pty group (#413).
- The `mmap` area of a program has a random top, as `arch_mmap_rnd` of Linux. `execve` moves the top down by a random number of pages: up to 2^28 pages on x86-64 and up to 2^18 pages on arm64, the defaults of `mmap_rnd_bits`. A process with `ADDR_NO_RANDOMIZE` in its personality keeps the fixed top. LTP hugemmap24 passes (#415).
- tools/bench has the benchmark `cow`: a write fault that copies a 4 KiB page that a child of `fork` maps. tools/bench/run.py takes `--arch aarch64` and runs the arm64 kernels of rukernel and Linux on the QEMU `virt` machine (#415).
- With the `corten` feature, `fork` copies the tree of statuses with one walk and does not build the list of areas, as `dup_mmap` of Linux copies the areas (#405).
- spec/25-removing-the-big-kernel-lock.md gives the design for the removal of the big kernel lock: the state that it protects, the order of the steps, a lock for each page table page, and the risks (#405).

### Fixed

- /proc/net/unix shows only the sockets of the network name space of the reader (#410).
- The file bit of /proc/PID/pagemap comes from the page itself, as fs/proc/task_mmu.c of Linux (#421). A page of a private file mapping has the bit until the first write makes an anonymous copy, also when the mapping can be written.
- The page cache of a mapped file keeps the clean or dirty state of each page, and /proc/kpageflags and `msync` use it in place of the sets of dirty and clean pages of the file (#421). A write back makes the pages clean when no shared mapping can write the file.
- tools/ltp/run.py records the LTP tree of an image in `IMAGE.tree`, and stops when `--image` and `--ltp` do not agree (#421). It does not make a shared image again from another tree.
- A read of the master of a pseudo terminal before the first open of the slave gives `EIO`, as Linux (#413). It waited before.
- A regular file on a mount of type ext2 does not take `RWF_NOWAIT`, and `preadv2` and `pwritev2` with it give `EOPNOTSUPP`, as Linux, where fs/ext2/file.c does not set `FMODE_NOWAIT` (#417). LTP preadv203 and preadv203_64 then give TCONF on ext2, as on Linux.
- The task switch and the system call are faster. The walk of the pressure counts up the cgroup tree does not allocate, and the x86_64 clock multiplies and shifts instead of a division of 128 bits (#417).
- The LTP runner gives starvation 1800 s, because the test can run for 650 s to 1150 s under QEMU without KVM by design (#417).
- A private mapping of a file of hugetlbfs is charged to the subpool of the mount, as `hugetlb_reserve_pages` and `alloc_hugetlb_folio` of Linux. The `size=` limit of the mount applies to it, so `mmap` gives `ENOMEM` when the reservation does not fit, and a fault of a `MAP_NORESERVE` mapping over the limit gives `SIGBUS`. A page gives its charge back when it is freed, and a reservation without a page gives it back at `munmap` or at exit (#415).
- The LTP build links `brk` and `sbrk` functions that call the kernel, because the functions of musl give `ENOMEM`. LTP hugemmap07 no longer gives TBROK, and sbrk01, mmapstress02, mmapstress03, mmapstress05 and mmapstress08 pass (#415).
- The address space merges areas as `vma_merge` of Linux (#405). After an `mprotect`, `mlock`, `madvise` or `mremap` gives an area the same flags as its neighbour, the two areas are one area again, and two file mappings at offsets that follow each other are one area. Before, /proc/PID/maps showed 3 areas after an `mprotect` of the middle of an area and back.
- With the `corten` feature, an empty node of the tree of statuses leaves the tree (#405). Before, `munmap` left the empty nodes.
- With the `corten` feature, `fork` and `exit` are about as fast as with the default backend (#405). Before, each node of the tree of statuses was one allocation of 8 KiB, and the walk of the tree made a list of up to 512 slots. Each allocation of the kernel heap of more than 2 KiB maps pages, and its free sends a TLB shootdown to each CPU. A `fork` and the `exit` of the child made about 20 of these, and the shootdowns took most of the time. Now the slots of a node are in chunks of 2 KiB and the walk reads them in batches of 64.
- With the `corten` feature, the `max_map_count` check counts the areas exactly, and `munmap` of the middle of an area gives `ENOMEM` when the split goes over `max_map_count`, as `do_vmi_align_munmap` of Linux (#405).
- The `init` check "the threads run again" waits up to 2 s for the counter to change, not a fixed 50 ms, and prints the wait when it is 50 ms or more (#405). The check failed in 2 of 12 boots with the `corten` feature at #323. The check passed in 40 boots at this base and with the code of #323, also on a busy host, and 600 extra rounds of stop and continue found no lost wake and no lost shared page. Thus the fixed sleep is the only cause left.

## [0.4.8] - 2026-10-28

### Added

- The Unix 98 pseudo terminals: /dev/ptmx and the file system devpts, as drivers/tty/pty.c and fs/devpts/inode.c of Linux (#403). `ioctl` has `TIOCGPTN`, `TIOCSPTLCK`, `TIOCGPTLCK`, `TIOCPKT`, `TIOCGPKT`, `TIOCGETD`, `TIOCSETD` (only `N_TTY`) and the terminal commands (`TCGETS`, `TCGETA`, `TCSETS*`, `TCSETA*`, `TIOCGWINSZ`, `TIOCSWINSZ`, `FIONREAD` and others) on both sides of the pair. musl `openpty` works, and LTP ioctl01 passes.
- `setsockopt` with `IPV6_ADDRFORM` changes a connected UDP socket of `AF_INET6` with an IPv4 peer into an `AF_INET` socket, as net/ipv6/ipv6_sockglue.c of Linux (#403).
- EEVDF wakeup preemption, as `check_preempt_wakeup_fair` of Linux with `RUN_TO_PARITY` (#408). A task that wakes, or a new task, takes the CPU from the current task when the current task is not eligible or has used its slice, and the wakeup has an earlier deadline. A wakeup for another CPU sends a reschedule IPI to that CPU.
- /proc/PID/pagemap gives the present bit, the file bit and, for a caller with `CAP_SYS_ADMIN`, the page frame number of each page, as fs/proc/task_mmu.c of Linux (#387). LTP mmap12 passes.
- /proc/kpageflags gives `KPF_UPTODATE`, `KPF_LRU`, `KPF_MMAP` and `KPF_DIRTY` for the pages of mapped files (#387). `msync` of a shared file mapping makes the pages clean, and LTP msync04 uses this.
- The ioctl `PROCMAP_QUERY` of /proc/PID/maps finds the area at an address or the next area, with the filters of the flags and the name of the area, as `do_procmap_query` of Linux (#387).
- `statmount` gives `STATMOUNT_MNT_NS_ID` and takes `mnt_ns_id` to look at the mounts of another mount name space (#387).
- Threaded cgroups, as the thread mode of kernel/cgroup/cgroup.c of Linux (#384). A write of `threaded` to `cgroup.type` makes a threaded cgroup, and `cgroup.type` shows `domain`, `domain threaded`, `domain invalid` or `threaded`. A write to `cgroup.threads` moves one thread inside a threaded subtree, and only the cpu, cpuset and pids controllers work in a threaded cgroup. A read of `cgroup.procs` of a threaded cgroup gives `EOPNOTSUPP`, and the other errors follow Linux.
- The page cache is charged to the memory cgroup of the task that reads or writes it, and `memory.stat` shows it as `file` (#384). A charge past `memory.max` first drops clean page cache of the cgroup, and `memory.min` and `memory.low` protect the cache of a cgroup from this reclaim, as `mem_cgroup_calculate_protection` of Linux. A reclaim that goes below `memory.low` counts a `low` event.
- `io.weight` shares the time of a device between the cgroups that use it, as the iocost controller of Linux does in proportion to the weights (#384). `io.stat` counts discards as `dbytes` and `dios`.
- An OOM reaper (#384). After an OOM kill, the kernel frees the private pages of the victim at once, and the OOM killer does not wait for the exit of the victim.
- A write of `memory.high`, `io.max` or `cpu.max` wakes the threads that wait for the old limit (#384).
- tools/ltp/build.sh installs the tests and scripts of the directories that have subdirectories, as memcontrol01 to memcontrol04 and cgroup_lib.sh (#384).
- On x86-64, the virtio PCI devices interrupt through MSI-X, so the drivers do not poll (#399). Each device gets one vector from 0x40, the message goes to the local APIC of the CPU that waits, and the handler masks the entry of the MSI-X table until the driver takes the interrupt. A device without MSI-X is polled as before.
- The receive path of virtio-net runs from the interrupt on x86-64 too (#399). The MSI-X message stops the user code or wakes an idle CPU, and the bottom half that reads the receive queue runs after it.
- tools/ltp/run.py has `--arch aarch64`, which runs the tests on the arm64 kernel on the `virt` machine of QEMU (#399). tools/ltp/build.sh has `--arch aarch64`, and `LTP_TESTDIRS` builds only some directories of tests. The full build strips the tree before it copies the tree out of the container, so it needs 5 times less free space.
- The boot job of CI builds the arm64 BusyBox with tools/busybox/build.sh, keeps it in the cache, and gives it to `boot-test aarch64` in `RK_BUSYBOX_AARCH64` (#399).

### Fixed

- The IPv6 datagram sockets put the routing header of `IPV6_RTHDR` in the packets that they send, as `ipv6_push_nfrag_opts` of Linux (#403). The packet goes to the first address of the route, and the UDP checksum uses the final destination.
- tools/ltp gives setsockopt11 a limit of 420 seconds, because the test runs for 300 seconds (#403).
- `size=` of a hugetlbfs mount limits the pages that a page fault adds, as the subpool of Linux (#392). Before, only `fallocate` checked it. A fault past the limit gives `SIGBUS`, and a shared mapping whose reservations go past the limit gives `ENOMEM`. `statfs` counts the reservations as used blocks, as on Linux.
- The reservations of `min_size=` of a hugetlbfs mount count one time (#392). A reservation or a page of a file takes one of the reservations of the mount first, and the mount reserves its pages again when the files give them back. Before, a mapping reserved new pages in the pool in addition to the ones of the mount.
- On x86-64 with KVM or on hardware, the removal of a huge page drops only the TLB entry of the huge page (#392). Under QEMU without KVM, which the kernel finds with the hypervisor leaf of CPUID, it still drops all the TLB entries of user pages.
- On arm64, the copy of a page for copy on write moves 128 bytes in each step of the loop with the SIMD registers (#392).
- A new kernel log record wakes the readers of /dev/kmsg that wait in `poll` or `read`, as `wake_up_klogd` of Linux (#408). A bottom half wakes the wait queue, so `printk` does not take the lock of the queue.
- `preadv2` and `pwritev2` with `RWF_NOWAIT` on a tmpfs file give `EOPNOTSUPP`, as Linux, where tmpfs does not set `FMODE_NOWAIT` (#408).
- The free of a large kernel heap block sends one TLB shootdown for the range, not one for each page (#408).
- The unit tests of the key service that walk all the keys no longer run at the same time as the tests that expect a key to go with its last reference. A walk holds each key for a short time, so `keyring_read_sizes` and `quota_and_drop` failed now and then (#407).
- The kernel counts the system CPU time of each thread from the time on the CPU outside user mode (#387). `times`, `getrusage`, `wait4` and /proc/PID/stat give it, and LTP times03 passes.
- `ru_maxrss` is the high-water mark of the resident pages (#387). Before, an `munmap` made it smaller.
- exec maps the aligned segments of an ELF file as private mappings of the file, so /proc/PID/maps shows the path of the executable (#387).
- tools/ltp runs each test in the foreground of the init shell, and the shell of the test forks the command, so the test does not keep the ignored `SIGQUIT` of BusyBox ash as PID 1 (#387). LTP kill11 passes now. Before, its child ignored `SIGQUIT` and the test hung.
- A read of a cgroupfs directory no longer skips entries when an `rmdir` happens between two reads (#384). Each entry keeps its place in the listing (a file by its index, a child cgroup by its ID), so `find -depth -exec rmdir` removes a whole tree. Before, the LTP cgroup_fj tests left their directory behind (`EBUSY`).
- A fork, an exit, `mkdir` and `rmdir` no longer make the kernel compute `cgroup.events` again for each cgroup (#384). The kernel computes the events again only when a cgroup gets its first task or loses its last one, or while a cgroup is frozen. Before, these calls got slower with each cgroup, and the creation of 10000 cgroups took more than 20 minutes under QEMU without KVM. Now it takes about 5 minutes.
- The timer of a pressure trigger starts on its own clock (#399). Before, it started at the time of the counter, which can be ahead of the clock of the timers when ticks are late, so on a busy host the timer did not fire during the stall and the arm64 init check "a stall polls POLLPRI on the trigger" failed.
- A key is dead when its last reference goes, as in Linux (#419). The walks of `/proc/keys`, the find of a session keyring by name and the garbage collector hold the data of each key but no reference to it. Before, a walk kept a key alive for a short time after its last link went, and a lookup by serial could still find it. The test lock of the walks is gone.

## [0.4.7] - 2026-10-28

### Added

- PCI on arm64 through the generic ECAM host of the device tree (#380). The frame assigns the memory BARs from the windows of `ranges`, as `pci_assign_unassigned_resources` of Linux, and finds the INTx line of each device in `interrupt-map`. virtio-blk and virtio-net work on virtio-pci on QEMU `virt`, and the arm64 `blk` and `inet` boot tests also run with virtio-pci.
- Device interrupts on arm64 (#380). The GIC turns on the SPI of each virtio device, from the device tree or from `interrupt-map`. A request of virtio-blk waits with `wfi` for the interrupt, and the interrupt of virtio-net wakes an idle CPU.
- tools/busybox/build.sh builds a static arm64 BusyBox in an arm64 Alpine container, for `RK_BUSYBOX_AARCH64` and the arm64 `busybox` boot test (#380).
- `remap_file_pages`, as mm/mmap.c of Linux (#385). It maps the pages of a shared file map again at a new offset, with a new `mmap` with `MAP_FIXED` over the range.
- `madvise` with `MADV_GUARD_INSTALL` and `MADV_GUARD_REMOVE`, as mm/madvise.c of Linux (#385). An access to a guard page gives `SIGSEGV`, and `fork` keeps the guard pages.
- `madvise` with `MADV_DONTFORK`, `MADV_DOFORK`, `MADV_WIPEONFORK` and `MADV_KEEPONFORK` change `fork` (#385). The child of `fork` does not get a `MADV_DONTFORK` area, and gets a `MADV_WIPEONFORK` area with zero pages.
- `fcntl` with `F_SETFL` turns `O_ASYNC` on and off, and a pipe sends `SIGIO` or the signal of `F_SETSIG` to the owner when it has data or space, as `kill_fasync` of Linux (#385).
- `setsockopt` with `IPV6_ADDRFORM` changes a TCP connection of an `AF_INET6` socket to an IPv4 peer into an `AF_INET` socket, as net/ipv6/ipv6_sockglue.c of Linux (#385).
- `setsockopt` with `IPV6_RTHDR` on an IPv6 datagram socket checks and keeps a routing header of type 2 or 4, and `UDP_CORK` collects the sends in one datagram (#385).
- The `ioctl` commands `RNDGETENTCNT`, `RNDADDTOENTCNT`, `RNDADDENTROPY`, `RNDZAPENTCNT`, `RNDCLEARPOOL` and `RNDRESEEDCRNG` of /dev/random and /dev/urandom, and the sysctls `kernel.random.entropy_avail` and `kernel.random.poolsize` (#385).
- The block device `ioctl` commands `BLKRAGET`, `BLKRASET`, `BLKFRAGET` and `BLKFRASET`, and the directory /sys/block/DEV/queue (#385).
- `poll` on /proc/PID/mounts gives `POLLERR | POLLPRI` after a mount or an unmount in the namespace, as `mounts_poll` of Linux (#385).
- The CortenMM experiment, an address space backend of rk-mm behind the `corten` feature (#323). The status of each page is in a tree with the shape of the page table, and each node of the tree has its own lock. A page fault, `mmap`, `munmap`, `mprotect` and `brk` lock only the nodes of their range, and the other calls lock the whole tree. The default kernel keeps the VMA backend. `RK_KERNEL_FEATURES=corten cargo xtask boot-test` boots the new backend. The benchmarks `fault_mt` and `mmap_mt` of tools/bench run the page fault and `mmap` in one thread per CPU, and `run.py --reuse-linux` boots only rukernel. tools/bench/cortenmm.md has the results.
- Each namespace has its own /proc/sys/net, as on Linux (#390). It has the per-namespace sysctls of net.core, net.ipv4, net.ipv6 and net.unix, and the files of net.ipv4.conf and net.ipv6.conf for all, default and each device, with `disable_ipv6`, `accept_dad`, `accept_ra` and `forwarding`. `disable_ipv6` removes the IPv6 addresses of a device, and `ip_default_ttl` and `icmp_echo_ignore_all` change the IPv4 stack.
- The `dummy` network device, for `ip link add NAME type dummy` (#390).
- Packet sockets of the family `AF_PACKET`, for `SOCK_RAW` and `SOCK_DGRAM` (#390). They send frames and give the ioctls of the devices. They do not receive frames yet.
- `RTM_NEWNSID` and `RTM_GETNSID`, and `IFLA_LINK_NETNSID` for a veth pair with its ends in two namespaces (#390).

### Fixed

- On arm64, `mem::copy` and `mem::zero` move 16 bytes with each instruction, not 1 byte (#380). They copy user pages and clear frames, so the arm64 boot tests run faster.
- On x86-64, a system call returns to user mode with `sysretq` when the registers allow it, as on Linux (#394). The return after an interrupt, an exception or a signal frame still uses `iretq`.
- On x86-64, the kernel keeps the FS base and the CR4.TSD bit of each CPU in a cache and writes them only when they change (#394).
- On x86-64, the FPU state is saved only when the user code used the FPU, with CR0.TS and the `#NM` trap, as the old lazy FPU of Linux (#394). The CPU registers keep the state of the thread that ran last, so a thread that runs again on the same CPU does not load it. CR0.TS is set only when the registers hold the state of the thread that runs, so the LazyFP attack (CVE-2018-3665) cannot read the state of another thread.
- The return to user mode checks one flag for the signal work, as `TIF_SIGPENDING` of Linux, and one flag for a traced thread, so a system call without a signal takes no signal lock and no ptrace lock (#394).
- The return to user mode checks the cgroup freezer, `memory.high` and the CPU and I/O limits only when a cgroup has such a limit (#394).
- The system call path loads the address space and checks for a reschedule without a reference count change, and records the system call information under one lock (#394).
- `sched_yield` returns at once when no other task can run on the CPU (#394). The `yield` benchmark goes from 5.55 to 0.62 times Linux.
- `fork` copies the page tables one last level table at a time, with one TLB flush for each area that becomes read only, and copies the page map of the parent in one pass (#394). The `fork_big` benchmark goes from 78.6 ms to 17.7 ms in tools/bench/results.md. Copy on write, the transparent huge pages and the hugetlb pages work as before.
- `statx` gives `STATX_ATTR_COMPRESSED` and the other attributes in `stx_attributes_mask` only when the file system keeps them, and gives `STATX_DIOALIGN` for a block device (#385).
- `open` for write and `truncate` of a program that runs give `ETXTBSY`, and `execve` of a file that is open for write gives `ETXTBSY`, as `deny_write_access` of Linux (#385).
- `connect` with `AF_UNSPEC` on a TCP socket frees the port and the address that `bind` did not set, as `tcp_disconnect` of Linux (#385).
- `mincore` marks a page of a shared map as resident when the page is in the page cache, also when the process did not touch it (#385).
- The user CPU time of a thread does not count the wait for the kernel lock and the bottom half of an interrupt, and one run of user code counts at most one tick, as the tick sampling of Linux (#396). Before, the time when the host did not run the virtual CPU was user time, so on a busy host a sleep added CPU time and `ITIMER_VIRTUAL` fired too early.
- A CPU that waits for the kernel lock spins 64 times and then waits for an interrupt, and the CPU that releases the lock wakes it (#396). Before, the waiting CPUs used the CPUs of the host, and the CPU that held the lock ran slowly. hackbench on 4 CPUs on a busy TCG host goes from 235 s to 70 s.
- A read of a Unix socket wakes the writers only when at most a quarter of the send buffer is in use, as `unix_write_space` of Linux (#396). Before, each read woke each writer, and hackbench on 2 CPUs took 95 s, now 36 s.
- The `smp` boot test runs with 4 CPUs, not 8, and the boot tests of init have a limit of 300 s, not 120 s (#396). The `smp` test has a limit of 600 s. On a busy host, the `smp` test took 322 s with 8 CPUs.
- The init check of a file lock of another process waits for the child through a pipe, not for a fixed time, so it passes on a busy host (#396).
- `setns` and `unshare` of the network namespace change the calling thread only, not the whole process, as on Linux (#390).
- A sysfs mount shows the network devices of the namespace that mounted it, as on Linux (#390). A new namespace can mount sysfs again on /sys.
- Each network namespace has its own abstract Unix socket names (#390).

## [0.4.6] - 2026-10-28

### Added

- Network namespaces and veth, as net/core/net_namespace.c and drivers/net/veth.c of Linux (#372). `unshare(CLONE_NEWNET)` and `clone` with `CLONE_NEWNET` put the process in a new namespace with its own devices and loopback device, IPv4 and IPv6 routes and addresses, neighbours, ports, sockets, counters, rtnetlink sockets, and view of /proc/net and /sys/class/net. A socket stays in the namespace where it was made. The link /proc/PID/ns/net gives `net:[INODE]` and opens a file of nsfs, and `setns` takes this file or a pidfd with `CLONE_NEWNET`. The file keeps the namespace, so `ip netns add` and `ip netns exec` work. `ip link add NAME type veth peer name PEER` makes a pair, and `ip link set DEV netns PID` and `IFLA_NET_NS_FD` move a device to another namespace. When a namespace ends, its veth devices go and its other devices go back to the first namespace. The new boot test `netns` pings over IPv4 and IPv6 between two namespaces through a veth pair. The threads of a process share one network namespace.
- hugetlbfs, as fs/hugetlbfs and mm/hugetlb.c of Linux (#371). `mount -t hugetlbfs` makes a file system whose files keep their data in huge pages of 2 MiB from a pool, with the options `mode`, `uid`, `gid`, `size`, `min_size`, `nr_inodes` and `pagesize`. A mapping of a file, `mmap` with `MAP_HUGETLB`, `shmget` with `SHM_HUGETLB` and `memfd_create` with `MFD_HUGETLB` get huge pages from the pool. A mapping reserves its pages, so a later fault does not fail, unless it has `MAP_NORESERVE` or `SHM_NORESERVE`. `ftruncate`, `read` and `fallocate` with `FALLOC_FL_PUNCH_HOLE` and `FALLOC_FL_KEEP_SIZE` work on the files, and a truncate or a hole removes the pages from each process that maps them, so a later access gives `SIGBUS`. `cachestat` on a file of hugetlbfs gives `EOPNOTSUPP`. `vm.nr_hugepages`, `vm.nr_overcommit_hugepages`, `vm.hugetlb_shm_group` and the files of /sys/kernel/mm/hugepages/hugepages-2048kB set and show the pool, and /proc/meminfo has the `HugePages_*`, `Hugepagesize` and `Hugetlb` lines.
- `shmget` checks `kernel.shmall` against the pages of all the segments, and takes `SHM_HUGETLB` (#371).
- The first rukernel-bench table, in tools/bench (#327). `bench.c` has benchmarks of the entry, sched, mem and net classes, and `run.py` boots rukernel and Linux in QEMU with the same machine and the same static musl initramfs, and writes the median, the interquartile range and the ratio of each benchmark to `results.md`. A row where rukernel is more than 2 times slower than Linux is red. The harness moves to the repository `tamnd/rukernel-bench` later.
- `preadv2` with the offset -1 takes `RWF_NOWAIT` (#375). A pipe, a socket or a character device with no data gives `EAGAIN`, and a file gives `EAGAIN` when its page is not in the page cache, as `IOCB_NOWAIT` of Linux.

### Changed

- kmsg, signalfd, the seccomp listener, AIO contexts, pidfds and the cgroup event and PSI files have their own poll wait queues, and the global `POLL_WAIT` queue is gone (#375). A wake of one file no longer wakes each task in `poll`, `select` and `epoll_wait`.

### Fixed

- `fork` keeps the transparent huge pages and the hugetlb pages of a process as whole blocks (#371). Both processes map the block read only, and the first write copies the whole block if a huge page is free. Before, `fork` split each block into 4 KiB pages.
- A transparent huge page in a memory cgroup charges the whole block to the cgroup (#371). Before, a process in a memory cgroup got only 4 KiB pages.
- `mmap` with `MAP_FIXED` of a range past the end of user space gives `ENOMEM`, as on Linux (#371). Before, it gave `EINVAL`.
- On x86-64, the removal of a huge page drops all the TLB entries of user pages of the process (#371). Under QEMU without KVM, one `invlpg` let the process run old code from a huge page that was gone.
- The user CPU time of a thread comes from the time stamp counter around the user code, not from the timer ticks that come at the entry to user mode (#375). The kernel runs with interrupts off, so a tick that fell due in the kernel or in the wake from a sleep counted as user time. On a busy host a sleep added CPU time and `ITIMER_VIRTUAL` fired early.
- The timer checks and the relatime check of the init boot test do not assume a fast host (#375). The `timer_gettime` check uses a long timer, the check of the timer signal takes a `SIGALRM` that is still pending, the child of the nanosleep check sends its signal until the parent stops it, and the relatime check waits for the clock to move after `futimens`.

## [0.4.5] - 2026-10-28

### Added

- The cgroup v2 freezer and the notification of cgroup events, as kernel/cgroup/freezer.c of Linux (#366). A write of 1 to `cgroup.freeze` stops each thread of the cgroup and of its descendants at its next return to user mode, and a new child cgroup of a frozen cgroup is frozen too. `cgroup.events` tells `frozen 1` when each thread waits, and `poll` of `cgroup.events` and `cgroup.freeze` gives `POLLPRI` and `POLLERR` when a value changes after the last read.
- PSI triggers, as kernel/sched/psi.c of Linux (#366). A write of `some|full STALL WINDOW` (in microseconds) to a `*.pressure` file or to a /proc/pressure file makes a trigger for the open file. A timer checks the stall time in each window, and `poll` gives `POLLPRI` when the stall time is more than the threshold. A second trigger on the same file gives `EBUSY`, a file without a trigger polls `POLLERR`, and a process without `CAP_SYS_RESOURCE` must use a window that is a multiple of 2 seconds.
- `setns` for cgroup name spaces and the link /proc/PID/ns/cgroup (#366). The link gives `cgroup:[INODE]` and opens a file of the name space file system (`NSFS_MAGIC`). `setns` takes this file or a pidfd with `CLONE_NEWCGROUP` and needs `CAP_SYS_ADMIN`. The other name space types give `EINVAL`.
- `memory.high` throttles a cgroup, as `mem_cgroup_handle_over_high` of Linux (#366). A task that charges pages past `memory.high` waits at its next return to user mode for a time that grows with the square of the overage (at most 2 seconds), and the wait counts as a memory stall in PSI. `memory.events` counts `high`.
- `memory.oom.group` (#366). An OOM kill in a cgroup with `memory.oom.group` 1 kills each process of the highest such cgroup, and `memory.events` counts `oom_group_kill`.
- The cgroup v2 io controller, as block/blk-cgroup.c and block/blk-throttle.c of Linux (#366). `io.stat` counts the bytes and the bios of each block device for a cgroup and its descendants. `io.max` limits `rbps`, `wbps`, `riops` and `wiops` of a device, and a task over a limit waits at its next return to user mode. The wait counts as an I/O stall in PSI. `io.weight` keeps its values but has no effect yet. A device that does not exist gives `ENODEV`.
- Delegation of cgroups, as kernel/cgroup/cgroup.c of Linux (#366). `chown` and `chmod` change the owner and the mode of a cgroup directory or file, and a new cgroup belongs to the fsuid and the fsgid of its creator. A write to `cgroup.procs` or `cgroup.threads` uses the credentials of the open, and the opener must be able to write `cgroup.procs` of the common ancestor (else `EACCES`). The `nsdelegate` mount option makes cgroup name spaces a delegation boundary: a move out of the name space gives `ENOENT`, and a write to the files of the name space root gives `EPERM`.
- tools/ltp/run.py mounts cgroup2 with `nsdelegate` at /sys/fs/cgroup (#366).
- More `fcntl` commands (#378): `F_SETLEASE` and `F_GETLEASE`, `F_GETOWN_EX` and `F_SETOWN_EX` (a `SIGIO` owner of type `F_OWNER_TID` gets the signal on its thread), `F_CREATED_QUERY`, and `F_ADD_SEALS` and `F_GET_SEALS` for files of `memfd_create` with `MFD_ALLOW_SEALING`, as mm/memfd.c of Linux. tmpfs checks the seals on a write, a size change, a `fallocate` and a mode change, and `F_SEAL_WRITE` gives `EBUSY` while a shared writable mapping of the file is there.
- tmpfs keeps the data of a file in pages, and a page that the file did not write is a hole with no memory, as mm/shmem.c of Linux (#378). A write far past the end takes only the pages that it writes, `FALLOC_FL_PUNCH_HOLE` frees the full pages, `st_blocks` counts the pages, and `SEEK_DATA` and `SEEK_HOLE` find the holes. The mount options `size=` and `nr_blocks=` limit the data and `statfs` shows the limit. Before, a write at 4 GiB tried to get 4 GiB of memory and gave `ENOSPC` (LTP open12, openat02, fallocate04, fallocate05 and lseek11).
- `pipe2(O_DIRECT)` makes a pipe that writes packets, as Linux (#378).
- A TCP socket takes `MCAST_JOIN_GROUP` and `MCAST_LEAVE_GROUP`, and UDP sends with `MSG_MORE` add to one datagram until a send without it, as Linux (#378).
- The links ipc, mnt, pid, pid_for_children, time, time_for_children, user and uts in /proc/PID/ns, as fs/proc/namespaces.c of Linux (#377). `setns` takes these files and a pidfd with the flags of these types. A join of a mount name space needs `CAP_SYS_ADMIN` and `CAP_SYS_CHROOT`, and a join of the other types needs `CAP_SYS_ADMIN`. The user name space of the caller gives `EINVAL`.
- The `ioctl` commands of the name space files, as fs/nsfs.c of Linux (#377): `NS_GET_USERNS`, `NS_GET_PARENT`, `NS_GET_NSTYPE`, `NS_GET_OWNER_UID`, `NS_GET_MNTNS_ID` and the four commands that change a PID between name spaces.
- `personality`, `reboot`, `ioperm`, `iopl`, `tee` and `vmsplice` (#377). `personality` keeps the persona and `UNAME26` changes the release of `uname`. `reboot` checks the magic numbers and `CAP_SYS_BOOT`, and `LINUX_REBOOT_CMD_CAD_ON` and `CAD_OFF` work. `ioperm` and `iopl` do the checks of Linux and keep the level, but the kernel does not give port access.
- `prctl` commands (#377): `PR_SET_PDEATHSIG` and `PR_GET_PDEATHSIG`, `PR_SET_TSC` and `PR_GET_TSC` (x86, with `CR4.TSD`), `PR_SET_TIMERSLACK` and `PR_GET_TIMERSLACK`, `PR_SET_THP_DISABLE` and `PR_GET_THP_DISABLE`, and `PR_GET_SPECULATION_CTRL` and `PR_SET_SPECULATION_CTRL`.
- The file /proc/PID/timerslack_ns (#377). A write for another process needs `CAP_SYS_NICE`.
- `RLIMIT_CPU` (#377). A process gets `SIGXCPU` at the soft limit and each second after it, and `SIGKILL` at the hard limit, as kernel/time/posix-cpu-timers.c of Linux.
- `RLIMIT_SIGPENDING` (#377). A real-time signal that is not from `kill` gives `EAGAIN` when the user has that many signals in the queues.
- `ARCH_GET_CPUID` and `ARCH_SET_CPUID` of `arch_prctl` (#377). CPUID is always on, so `ARCH_SET_CPUID` gives `ENODEV`.
- `ru_maxrss` of `getrusage` (#377). The kernel keeps the largest resident set of a process at `execve` and at the exit, and a wait adds the value of the child to its parent.
- The sysctl files fs.pipe-max-size, fs.pipe-user-pages-hard, fs.pipe-user-pages-soft and kernel.core_pattern, and 64-bit values for kernel.shmmax and kernel.shmall (#377). `fcntl(F_SETPIPE_SZ)` takes fs.pipe-max-size as its limit without `CAP_SYS_RESOURCE`.
- `KCMP_IO` and `KCMP_SYSVSEM` of `kcmp` (#377).

### Changed

- The OOM killer of the system waits for a victim that is still on its way out before it kills another process, as Linux does for a task with `TIF_MEMDIE` (#366). A page of a process cannot take the last 256 free frames, so the kernel keeps memory for its heap and for the OOM killer. The OOM killer measures a process without a list of its pages.

### Fixed

- Errors of the file, mount and socket calls now follow Linux (#378). An `O_PATH` file gives `EBADF` to the calls that need an open file. `mount` gives `ENOENT` for a symbolic link as the target, `EINVAL` for no type or no source, and `EBUSY` for the same file system on the same place. `umount2` gives `EINVAL` for a path that is not a mount, `EBUSY` for a mount with open files, and `EAGAIN` for the first `MNT_EXPIRE`. `link` makes its checks in the order of Linux. A mount with `MS_NODEV` stops the opens of devices, `MS_NOEXEC` stops `execve`, and `MS_NOSYMFOLLOW` stops symbolic links. `fsync` and `fdatasync` give `EINVAL` for a pipe, a socket and a character device. `copy_file_range` gives `EFBIG` at the largest file size, and `FICLONE` and `FICLONERANGE` give `EOPNOTSUPP`. `socket` gives `EAFNOSUPPORT` and `EINVAL` for a bad family or type, `socketpair` gives `EOPNOTSUPP` for a family that is not `AF_UNIX`, `getsockopt` gives `EOPNOTSUPP` or `ENOPROTOOPT` for an unknown option as Linux, `sendmsg` gives `EMSGSIZE` for too many buffers, and `connect` to a UNIX socket file without write permission gives `EACCES`. The LTP tests of the files, mounts and sockets groups of the issue pass now, and `tools/ltp/notes.txt` gives the reason for each test that musl or BusyBox stops.
- `pidfd_send_signal` takes a /proc/PID directory, and checks the permission to send the signal (#377).
- `pidfd_getfd`, `get_robust_list` for another process, `process_vm_readv` and `process_vm_writev` need the permission of `ptrace` (#377).
- `sched_setaffinity` of another process needs the same user or `CAP_SYS_NICE` (#377).
- `setpgid` of a child that ran `execve` gives `EACCES` (#377).
- `execve` with an empty argument list gives the program an empty `argv[0]`, as fs/exec.c of Linux (#377).
- The overrun count of a POSIX timer stops at `INT_MAX`, and a `CLOCK_REALTIME` timer with an absolute time before boot counts the intervals before boot (#377).
- An event file that AIO writes stops at `UINT64_MAX`, and `poll` then gives `POLLERR`, as `eventfd_signal_mask` of Linux (#377).
- `clock_nanosleep` on `CLOCK_THREAD_CPUTIME_ID` gives `EOPNOTSUPP` (#377).
- `waitid(P_PIDFD)` on a pidfd with `O_NONBLOCK` gives `EAGAIN` when the child did not change (#377).
- A `clone` that fails after it made the child, for example with a bad address for `CLONE_PIDFD`, ends the child, so no child stays that never runs (#377).
- `seccomp(SECCOMP_SET_MODE_FILTER)` without `CAP_SYS_ADMIN` and without no_new_privs gives `EACCES` (#377).
- `poll`, `select` and `pselect` with `STICKY_TIMEOUTS` in the persona do not change the timeout (#377).

## [0.4.4] - 2026-10-28

### Added

- Kernel Samepage Merging, as mm/ksm.c of Linux (#364). `madvise(MADV_MERGEABLE)` and `prctl(PR_SET_MEMORY_MERGE)` make the private anonymous pages of a process mergeable, and `MADV_UNMERGEABLE` and `PR_SET_MEMORY_MERGE` with 0 make them private again. The kernel thread `ksmd` scans the mergeable pages and maps each group of pages with the same contents to one read only page, and a write to that page copies it. The files of /sys/kernel/mm/ksm show the counters and change the settings (`run`, `pages_to_scan`, `sleep_millisecs`, `max_page_sharing`, `merge_across_nodes`, `use_zero_pages`, `smart_scan`), and /proc/PID/ksm_stat and /proc/PID/ksm_merging_pages show the counters of a process. `tools/ltp/kconfig` now sets `CONFIG_KSM`.
- IPv6, as net/ipv6 of Linux (#369). `AF_INET6` gives UDP, TCP, raw and ICMPv6 ping sockets on the IPv4 code of rk-net-inet, which now keeps IPv4 addresses as IPv4-mapped IPv6 addresses. A socket without `IPV6_V6ONLY` takes IPv4 packets too. The sockets have `IPV6_V6ONLY`, `IPV6_UNICAST_HOPS`, `IPV6_MULTICAST_HOPS`, `IPV6_TCLASS`, `IPV6_CHECKSUM` and `ICMP6_FILTER`. lo gets `::1`, and an Ethernet device gets a link local address from its MAC address when it goes up. Neighbour discovery resolves the next hop, router solicitations and router advertisements give a default route and a SLAAC address, and the kernel answers echo requests. The IPv6 route table and the addresses work through `RTM_NEWADDR`, `RTM_DELADDR`, `RTM_GETADDR`, `RTM_NEWROUTE`, `RTM_DELROUTE` and `RTM_GETROUTE` of `AF_INET6`, so `ip -6 addr` and `ip -6 route` work. The new files /proc/net/if_inet6, ipv6_route, snmp6, tcp6, udp6, raw6 and icmp6 have the format of Linux. `IPV6_RECVPKTINFO`, `IPV6_RECVHOPLIMIT`, `IPV6_RECVTCLASS` and the RFC 2292 forms give control messages to recvmsg. A raw socket can bind again, as on Linux. The new boot test `inet6` checks IPv6 on lo and on the user network of QEMU with BusyBox. The LTP runner brings up lo and adds /etc/services.
- Transparent huge pages for anonymous memory (#365). A write fault in a private anonymous area that covers an aligned 2 MiB block maps the block with one PMD entry (a level 2 block on aarch64). `/sys/kernel/mm/transparent_hugepage/enabled` (`always`, `madvise` or `never`) and `madvise(MADV_HUGEPAGE)` and `madvise(MADV_NOHUGEPAGE)` choose the areas. A partial `mprotect`, `munmap`, `mremap` or `MADV_DONTNEED` splits the block into 4 KiB pages, with a page table that the map put aside, so the split never fails. An area that KSM can merge gets 4 KiB pages, so `ksmd` does not split blocks. `/sys/kernel/mm/transparent_hugepage` also has `defrag`, `hpage_pmd_size`, `use_zero_page` and `shmem_enabled`, and /proc/meminfo has `AnonHugePages`. `tools/ltp/kconfig` now sets `CONFIG_TRANSPARENT_HUGEPAGE`.
- The overcommit policy (#365). `vm.overcommit_memory`, `vm.overcommit_ratio` and `vm.overcommit_kbytes` work as in Linux. The private writable mappings, the shared anonymous mappings and the heap add to the commit count, and the `CommitLimit` and `Committed_AS` lines of /proc/meminfo show the limit and the count. `MAP_NORESERVE` skips the count, except in mode 2.
- `vm.max_map_count` and `vm.min_free_kbytes` (#365). `mmap` and a `munmap` that splits an area give `ENOMEM` past the map count limit. A page for user memory is not given when the free memory is at the `min_free_kbytes` reserve, and a fault that then has no memory starts the OOM killer of the system, which kills the process with the most pages. `vm.panic_on_oom` and `vm.nr_hugepages` are there, with the value 0.
- The arm64 vDSO (#348). User programs get `AT_SYSINFO_EHDR` and the symbols `__kernel_clock_gettime`, `__kernel_gettimeofday`, `__kernel_clock_getres` and `__kernel_rt_sigreturn`, version `LINUX_2.6.39`. The time calls read the virtual counter, which `CNTKCTL_EL1` now lets EL0 read. A signal handler without `SA_RESTORER` returns through `__kernel_rt_sigreturn`, as on Linux. The x86-64 and arm64 vDSOs share the time code.
- virtio-mmio on arm64 (#348). The kernel finds the `virtio,mmio` nodes in the device tree and drives the modern (version 2) virtio-blk and virtio-net devices on them. The virtio driver now has a transport layer for PCI and MMIO.
- The arm64 boot tests `blk`, `inet` and `busybox` (#348). `busybox` needs an arm64 BusyBox from `RK_BUSYBOX_AARCH64`. The vDSO checks of `init` now run on arm64.
- GICv3 on arm64 (#348). The kernel finds the distributor and the redistributors in the device tree, and uses the system registers of the CPU interface for the timer and the SGIs between CPUs. The arm64 boot tests now run on a GICv3, and the `boot` test also runs on a GICv2.
- CI builds the arm64 user programs with `zig cc` (#348), so the arm64 tests `init`, `smp`, `blk` and `inet` run in CI.
- `RK_AARCH64_TESTS` selects some of the arm64 boot tests, for a run by hand (#348).
- The argument `only` of tests/user/init.c (#348). With it, init runs only the checks of the next argument. The arm64 tests `smp`, `blk` and `inet` use it, so the `smp` test is much faster.

### Fixed

- Each file has its own poll wait queue, as `poll_wait` and `wait_queue_head_t` of Linux (#360). `poll`, `select` and `epoll` wait on the queues of their files, so an event on a pipe, a socket, an eventfd, a timerfd, a message queue, inotify, fanotify, a TTY or an epoll file wakes only the tasks that poll that file. Before, each event woke all the tasks that polled any file, so hackbench took O(N²) time.
- `preadv2` with `RWF_NOWAIT` gives `EAGAIN` when the data is not in the page cache of the block device, as `filemap_read` of Linux (#360). Before, the read waited for the disk.
- `mmap` and `brk` join a new private anonymous area to an area next to it that has the same attributes, as `vma_merge` of Linux (#360). `fork` copies each area, so a process with many such areas, as fork14 makes, forked slowly.
- `madvise(MADV_DONTNEED)` and `MADV_FREE` now remove the pages from the address space, so the next touch gets a new zero page, as in Linux (#365). Before, they wrote zeros into the pages, which failed in a read-only area.
- A read of a proc file at an offset that is not 0 now uses the text of the last read at offset 0, as the `seq_file` buffer of Linux (#365). Before, each read made the full text again, so a read of `/proc/PID/maps` with thousands of areas in small parts took a time that grew as the square of the size. The LTP test max_map_count passes now.
- The init script of `tools/ltp/run.py` writes the default overcommit policy back after each test (#365). A test that stopped with the strict policy and a limit of 0 left a shell that could not fork, which stopped the boot.
- A process in a memory cgroup that is below its limit, on a system that is out of memory, now starts the OOM killer of the system (#365). Before, the kernel ran out of its own heap and panicked in the LTP test oom03.
- The search for a free range in `mmap` now starts below the last free range that it found, so a process that makes many mappings does not take time that grows as the square of the count (#365).
- The OOM killer counted the pages of a process with a list of all its pages, `ksmd` listed the pages of a mergeable area in the same way, and `munmap` and `MADV_DONTNEED` kept the frames of the full range in a list. For a process of 2 GiB the list needs 4 MiB of kernel heap, so the kernel panicked when memory was short (LTP oom03). The count now uses no memory, `ksmd` tries the area again later when the list does not fit, and `munmap` frees the frames in batches of 512 (#365).
- The virtio driver read and wrote the index of a ring one byte at a time on arm64, so the device could see half of a new index (#348). The device then stopped the queue. The driver now reads and writes the index in one 16 bit access.
- The bottom half did not poll the network devices on arm64, so a received frame waited until the next send (#348). A TCP connection with the host then stopped.

## [0.4.3] - 2026-10-27

### Added

- The socket tables /proc/net/tcp, /proc/net/udp, /proc/net/raw, /proc/net/icmp and /proc/net/unix, and /proc/net/netstat, in the format of Linux (#355). The lines have the state, the queues, the timer, the uid and the inode of each socket.
- Real ICMP, TCP and IP counters in /proc/net/snmp (#355): the `Icmp` and `IcmpMsg` lines, `ActiveOpens`, `PassiveOpens`, `AttemptFails`, `EstabResets`, `CurrEstab`, `InSegs`, `OutSegs`, `RetransSegs`, `InErrs`, `OutRsts` and `InCsumErrors` of TCP, `OutDatagrams` and `InCsumErrors` of UDP, and `InDelivers` and `InUnknownProtos` of IP.
- The directory /sys/class/net with a link for each interface to /sys/devices/virtual/net/NAME, which has `address`, `mtu`, `flags`, `operstate`, `carrier`, `ifindex`, `type`, the other attribute files of Linux and the `statistics` directory (#355).
- `RTM_GETROUTE` for one destination, as `inet_rtm_getroute` of Linux, so `ip route get` works (#355). The reply has the source address, the gateway, the output interface and the uid, and `RTM_F_FIB_MATCH` gives the route of the table.
- Route metrics (#355): `SIOCADDRT` keeps the MTU, the window and the initial RTT of `route add ... mss window irtt`, `RTM_NEWROUTE` keeps `RTA_METRICS`, and /proc/net/route and the rtnetlink messages show them.
- The lines `VmData`, `VmStk`, `VmExe`, `VmLib`, `VmPTE`, `VmSwap`, `VmPin`, `VmHWM`, `RssAnon`, `RssFile`, `RssShmem`, `HugetlbPages`, `CoreDumping` and `THP_enabled` in /proc/PID/status (#355).
- `pivot_root` (#357). It moves the root mount of the mount name space of the caller to `put_old` and makes `new_root` the root, with the checks and the errors of fs/namespace.c of Linux. The root and the current directory of each process with the old root move to the new root.
- `listmount` and `statmount` (#357). `listmount` gives the IDs of the child mounts of a mount in order, from an ID or in reverse with `LISTMOUNT_REVERSE`. `statmount` gives `struct statmount` with the basic data, the superblock data, the mount point, the root, the file system type and the mount options, as fs/namespace.c of Linux.
- fanotify on the fsnotify layer (#357). `fanotify_init` makes a group of the classes `FAN_CLASS_NOTIF`, `FAN_CLASS_CONTENT` and `FAN_CLASS_PRE_CONTENT`, with `FAN_CLOEXEC`, `FAN_NONBLOCK`, `FAN_UNLIMITED_QUEUE`, `FAN_UNLIMITED_MARKS`, `FAN_REPORT_TID` and `FAN_REPORT_FD_ERROR`. `fanotify_mark` adds, removes and flushes the marks on an inode, a mount and a file system, with the ignore masks of `FAN_MARK_IGNORED_MASK` and `FAN_MARK_IGNORE`, `FAN_MARK_IGNORED_SURV_MODIFY`, `FAN_MARK_ONLYDIR` and `FAN_MARK_DONT_FOLLOW`. A group gets the events of open files (access, modify, open, open for exec and close) and the permission events `FAN_OPEN_PERM`, `FAN_OPEN_EXEC_PERM` and `FAN_ACCESS_PERM`. A read gives `struct fanotify_event_metadata` with a new descriptor of the file, the queue merges the events of the same file and takes one `FAN_Q_OVERFLOW` event when it is full, and a write of `struct fanotify_response` allows or denies the operation that waits. The groups that report a file handle are not supported yet.
- dnotify (#357). `fcntl(F_NOTIFY)` with the `DN_*` events and `DN_MULTISHOT` sends a signal to the owner of the directory file for each change in the directory, as fs/notify/dnotify/dnotify.c of Linux. `F_SETSIG` sets the signal, and a real time signal has `si_fd` and `si_band`. `F_SETOWN`, `F_GETOWN` and `F_GETSIG` also work now.
- The key service of Linux security/keys (#352). `add_key`, `request_key` and `keyctl` work with the `user`, `logon` and `keyring` types and the thread, process, session, user and user session keyrings. The keys have reference counts, permissions, possession, timeouts, revocation, invalidation, the restriction that rejects all links, and the quotas of each user. `request_key` has no upcall: it makes a negative key and gives `ENOKEY`. The `keyctl` operations give the errors of Linux in the order of Linux, and the operations of request key authorization give `EPERM`. /proc/keys, /proc/key-users and /proc/sys/kernel/keys/* show the keys and the limits. `tools/ltp/kconfig` now sets `CONFIG_KEYS`.
- cgroup v2 and PSI (#350). The new crate rk-cgroup keeps the hierarchy, and the new crate rk-fs-cgroup is the `cgroup2` file system with `mkdir`, `rmdir` and the files `cgroup.procs`, `cgroup.threads`, `cgroup.controllers`, `cgroup.subtree_control`, `cgroup.events`, `cgroup.type`, `cgroup.max.depth`, `cgroup.max.descendants`, `cgroup.stat`, `cgroup.freeze` and `cgroup.kill`, with the rule of no internal processes. The pids controller limits `fork` and `clone` with `EAGAIN`. The cpu controller changes the weight of the tasks with `cpu.weight` and throttles a cgroup that uses its `cpu.max` quota, and `cpu.stat` counts the use and the throttles. The memory controller charges the anonymous and copy-on-write pages, and a fault past `memory.max` starts the OOM killer of the cgroup. The cpuset controller limits the CPUs of the threads. `/proc/pressure/{cpu,memory,io}` and the `*.pressure` files show the PSI averages over 10, 60 and 300 seconds. `/proc/PID/cgroup`, `/proc/cgroups`, `clone3` with `CLONE_INTO_CGROUP` and `CLONE_NEWCGROUP` work too.

### Fixed

- The boot tests `init` and `netcfg` failed at times on a busy host after #346, because `sleep` and the time limits now follow wall time (#355). The `netcfg` test waits up to 10 s for its servers, and the CPU time checks of `init` wait up to 20 s.
- `RTF_MTU` had the value of `RTF_MODIFIED` (0x20). It is now 0x40, as in linux/route.h (#355).
- `umount` of `/` or of another path with mounts on its last place gave `EBUSY`. It now removes the last mount on the place, as `LOOKUP_MOUNTPOINT` of Linux (#357).
- The x86_64 timer interrupt now counts each tick period that passed since the last tick, as `tick_do_update_jiffies64` of Linux (#346). The local APIC keeps only one pending timer interrupt, so a kernel path that ran longer than one tick with interrupts off lost ticks. The clock and all timeouts then ran slow, and the `sleep` watchdog of `tools/ltp/run.py` did not stop the test in time.
- The x86_64 boot code now measures the time stamp counter against the PIT 8 times and keeps the shortest measure, as `pit_hpet_ptimer_calibrate_cpu` of Linux (#346). Before, one measure under QEMU without KVM on a busy host gave 4.5 times the true frequency. The clock then ran at a fifth of the true speed, so hackbench02 and shm_test01 of LTP stopped the guest past the time limit of `run.py`.

## [0.4.2] - 2026-10-27

### Added

- The clock can now be set (#344). `clock_settime` and `settimeofday` (and so `stime` of the C library) set `CLOCK_REALTIME` with `CAP_SYS_TIME`, and the vDSO sees the new time. An absolute `CLOCK_REALTIME` timer, `clock_nanosleep` and timerfd move with the clock, and a timerfd with `TFD_TIMER_CANCEL_ON_SET` gives `ECANCELED`. `adjtimex` and `clock_adjtime` keep the NTP state of kernel/time/ntp.c (offset, frequency, status, time constant, TAI offset, `ADJ_SETOFFSET`), but the state does not change the speed of the clock yet. `settimeofday` keeps the time zone for `gettimeofday`. rk-abigen now extracts `<linux/timex.h>` and `<linux/keyctl.h>`.
- `sethostname` and `setdomainname` with `CAP_SYS_ADMIN` (#344). `uname`, /proc/sys/kernel/hostname and /proc/sys/kernel/domainname show the same names, and the names are `(none)` at boot, as in Linux.
- System V message queues and POSIX message queues (#342). `msgget`, `msgsnd`, `msgrcv` and `msgctl` follow ipc/msg.c of Linux, with `MSG_COPY`, `MSG_EXCEPT`, `MSG_NOERROR`, `IPC_NOWAIT`, `IPC_INFO`, `MSG_INFO`, `MSG_STAT` and `MSG_STAT_ANY`. `/proc/sys/kernel` has `msgmax`, `msgmnb`, `msgmni` and the `*_next_id` files of the three IPC types, and `/proc/sysvipc` has `msg`, `sem` and `shm`. `mq_open`, `mq_unlink`, `mq_timedsend`, `mq_timedreceive`, `mq_notify` and `mq_getsetattr` follow ipc/mqueue.c, on the new `mqueue` file system, with `poll` on a queue and the limits in `/proc/sys/fs/mqueue`. `mq_notify` sends a signal for `SIGEV_SIGNAL`. For `SIGEV_THREAD`, a minimal `AF_NETLINK` socket gives the cookie to the thread of musl. The pure queues are in `rk_vfs::ipc`, with host tests. A new descriptor with `RLIMIT_NOFILE` at 0 now gives `EMFILE`, not `EINVAL`.
- `AF_NETLINK` sockets with `NETLINK_ROUTE` (#345). rtnetlink has `RTM_GETLINK` and `RTM_NEWLINK` (up and down, MTU, name), `RTM_GETADDR`, `RTM_NEWADDR` and `RTM_DELADDR` for IPv4, `RTM_GETROUTE`, `RTM_NEWROUTE` and `RTM_DELROUTE`, and `RTM_GETNEIGH`. A dump gives multipart datagrams that end with `NLMSG_DONE`, and a request with `NLM_F_ACK` gets an `NLMSG_ERROR` ack. The attributes `IFLA_*`, `IFA_*`, `RTA_*` and `NDA_*` have the layout and the order of Linux. A socket can join the groups `RTNLGRP_LINK`, `RTNLGRP_IPV4_IFADDR` and `RTNLGRP_IPV4_ROUTE` through `nl_groups` or `NETLINK_ADD_MEMBERSHIP`, and it gets a notification for each change. The route table now has the tables `local` and `main` of Linux, with the `local` and `broadcast` routes of each address, and it checks a new route as `fib_create_info`. rk-abigen now extracts the constants of `<linux/netlink.h>`, `<linux/rtnetlink.h>`, `<linux/if_link.h>`, `<linux/if_addr.h>` and `<linux/neighbour.h>`.
- The interface ioctls on each socket (#345): `SIOCGIFCONF`, `SIOCGIFFLAGS`, `SIOCSIFFLAGS`, `SIOCGIFADDR`, `SIOCSIFADDR`, `SIOCGIFNETMASK`, `SIOCSIFNETMASK`, `SIOCGIFBRDADDR`, `SIOCGIFMTU`, `SIOCSIFMTU`, `SIOCGIFHWADDR`, `SIOCGIFINDEX`, `SIOCGIFNAME`, `SIOCADDRT` and `SIOCDELRT`, with the checks and the errors of `devinet_ioctl` and `ip_rt_ioctl` of Linux. An alias such as `eth0:1` is a label of an address. The calls that make a change need `CAP_NET_ADMIN`.
- The files /proc/net/dev, /proc/net/route, /proc/net/arp and /proc/net/snmp in the format of Linux (#345). /proc/net is a link to /proc/self/net. The new boot test `netcfg` sets up `eth0` without `ip=` with the BusyBox commands `ip link`, `ip addr`, `ip route`, `ifconfig` and `route`, pings the gateway and reads the files of /proc/net.
- inotify and a small fsnotify layer in rk-vfs (#343). The layer keeps the marks of each inode, and the hooks in the VFS send the events of create, unlink, rmdir, rename with a cookie, open, close for write and for read, modify, attrib, access, xattr, delete self, move self and unmount. fanotify and dnotify can use the same hooks later. `inotify_init`, `inotify_init1` with `IN_NONBLOCK` and `IN_CLOEXEC`, `inotify_add_watch` with `IN_ONLYDIR`, `IN_DONT_FOLLOW`, `IN_EXCL_UNLINK`, `IN_MASK_ADD`, `IN_MASK_CREATE` and `IN_ONESHOT`, and `inotify_rm_watch` with `IN_IGNORED` work as on Linux. The queue merges an event with the same last event and takes one `IN_Q_OVERFLOW` event when it is full. The descriptor works with `read`, `FIONREAD`, poll and epoll. The sysctls `fs.inotify.max_queued_events`, `max_user_instances` and `max_user_watches` set the limits, and `/proc/PID/fdinfo` shows the watches. The queue has tests on the host.
- `chroot` with `CAP_SYS_CHROOT`, `close_range` with `CLOSE_RANGE_CLOEXEC` and `CLOSE_RANGE_UNSHARE`, and `fchmodat2` with `AT_SYMLINK_NOFOLLOW` and `AT_EMPTY_PATH` (#343). `/proc/PID/fdinfo/FD` shows the position, the flags, the mount ID and the inode of a descriptor.
- `execveat` with a directory descriptor, `AT_EMPTY_PATH` and `AT_SYMLINK_NOFOLLOW`, `openat2` with `struct open_how` and the flags `RESOLVE_NO_XDEV`, `RESOLVE_NO_MAGICLINKS`, `RESOLVE_NO_SYMLINKS`, `RESOLVE_BENEATH`, `RESOLVE_IN_ROOT` and `RESOLVE_CACHED`, and `cachestat` (#343).

### Fixed

- Permission and argument checks that LTP showed as missing (#344): `RLIMIT_MEMLOCK` (8 MiB by default) for `mlock`, `mlock2` and `mlockall` without `CAP_IPC_LOCK`, the checks of `sched_setscheduler` and `sched_setparam` for a process without `CAP_SYS_NICE`, `EINVAL` for unknown flags of `statx`, and `readlinkat` with an empty path.

## [0.4.1] - 2026-10-27

### Added

- TCP in rk-net-inet (#337). A pure state machine has the states of RFC 9293, the retransmission timer of RFC 6298, Nagle, delayed ACK, keepalive, TIME_WAIT, the window scale option and the MSS option. Congestion control is CUBIC with slow start and fast recovery, in its own module with tests of its growth. The socket layer gives the errors of Linux (`ECONNREFUSED`, `ETIMEDOUT`, `ECONNRESET`, `EPIPE` with `SIGPIPE`, `EINPROGRESS` with `SO_ERROR`, `EAGAIN`), `SO_REUSEADDR`, `SO_LINGER` with a zero time, `TCP_NODELAY`, `TCP_CORK`, `TCP_MAXSEG`, the keepalive options and `TCP_CONGESTION`, `MSG_PEEK`, `MSG_WAITALL` and `MSG_DONTWAIT`, `shutdown`, the listen backlog, `accept` and `accept4`, and the readiness of poll and epoll. The boot test `inet` moves 1 MiB in each direction over `lo` between two processes, and 1 MiB in each direction with a TCP server that xtask starts on the host.
- A virtio-net driver and the network device layer (#328). The driver negotiates `VIRTIO_NET_F_MAC`, `VIRTIO_NET_F_STATUS` and `VIRTIO_F_VERSION_1`, reads the MAC address, and keeps a receive queue and a transmit queue of 64 buffers each. rk-net has the packet buffer `NetBuf` with headroom for the headers, the network devices with a name, an interface index, the MAC address, the MTU, the flags and the statistics of Linux, and the loopback device `lo` with the interface index 1. A virtio-net device gets the name `eth0`, `eth1` and so on, and the kernel prints its name and its MAC address at boot. The drivers poll and do not use interrupts yet. The boot test `net` sends an ARP request to the gateway of the user network of QEMU and receives the reply. rk-abigen now extracts the constants of `<linux/if_ether.h>`.
- The kernel boots on arm64 to the console on the QEMU `virt` machine. The image is a Linux arm64 `Image`, which QEMU `-kernel`, U-Boot `booti` and GRUB load. The boot code drops from EL2 to EL1, turns the MMU on with the kernel at `KERNEL_BASE` and a direct map, and reads the memory, the command line and the initrd from the device tree. The exception vectors print an oops for an unexpected exception. The PL011 UART is the console, and the virtual timer gives the tick through a GICv2. `cargo xtask boot-test aarch64` runs the `boot`, `trap`, `mm`, `heap` and `timer` self tests on `qemu-system-aarch64 -M virt` (#329).
- IPv4, ICMP and UDP in the new crate rk-net-inet (#333). The stack has a neighbour table with ARP (requests each second, three tries, a queue of 8 packets for each address, a reachable time of 30 s, and replies for the local addresses), IPv4 input and output with the header checksum, a TTL of 64 and the flag DF, a route table with the connected routes and a default gateway, and the echo replies and the port unreachable errors of ICMP. The stack drops the fragments and counts them, and a packet larger than the MTU gives `EMSGSIZE`. `socket(AF_INET, ...)` now gives UDP sockets, ICMP echo sockets (`SOCK_DGRAM` with `IPPROTO_ICMP`, for a group in the new sysctl `net.ipv4.ping_group_range`) and raw sockets (with `CAP_NET_RAW`), with `bind`, `connect`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `getsockname`, `getpeername`, poll and epoll, `SO_REUSEADDR`, `SO_RCVBUF`, `SO_BROADCAST`, `IP_TTL`, `IP_TOS`, `IP_RECVERR`, `IP_HDRINCL` and `ICMP_FILTER`. A port of 0 gives an ephemeral port from 32768 to 60999. The errors are `EADDRINUSE`, `EADDRNOTAVAIL`, `ENETUNREACH`, `EDESTADDRREQ`, `EACCES` for a port below 1024 without `CAP_NET_BIND_SERVICE` and for a broadcast without `SO_BROADCAST`, and `ECONNREFUSED` on a connected socket after an ICMP port unreachable error. The kernel sets `lo` up with 127.0.0.1/8, and it configures `eth0` from `ip=<client>:<server>:<gateway>:<netmask>` on the command line. A bottom half polls the devices, and a send polls too, so a datagram on `lo` arrives before the send returns. The new boot test `inet` pings 10.0.2.2, asks the DNS server 10.0.2.3 of QEMU, and sends datagrams over `lo`. rk-abigen now extracts the constants of `<linux/in.h>`.
- The fair class of rk-sched now has a run queue for each CPU. Each queue keeps its tasks in an AVL tree keyed by the virtual deadline, with the lowest virtual run time of each subtree, so the EEVDF pick takes O(log n) time, as `pick_eevdf` of Linux. Before, one queue for all CPUs found the next task with a scan. A task that wakes goes to an idle CPU or to the CPU where it ran last, and keeps its lag on the new queue. A CPU that becomes idle pulls a task from the busiest queue, and a busy CPU evens out the queues every 4 ms. The scheduler now obeys the CPU mask of `sched_setaffinity`: a thread moves to a CPU of the mask, and a new thread gets the mask of its parent (#330).
- `tools/ltp` measures rukernel against the LTP groups `syscalls`, `mm`, `sched` and `net` (#321). `build.sh --full` builds the groups with musl and records the tests that do not build. `run.py` boots the kernel in QEMU with batches of tests. It kills a test that runs for more than its time limit, and boots the kernel again after a panic or a hang. `report.py` and `update.sh` make `README.md`, with the number of tests that pass in each group and the causes of the failures, and a file with the result of each test for each group. The `ltp` boot test does not change.
- arm64 runs tasks, user mode and system calls (#335). The kernel switches tasks with the callee saved registers and d8 to d15. User programs run at EL0 with their own TTBR0 tables and enter the kernel with `svc`, with the rk-abi numbers of arm64. An abort at EL0 goes to the fault handler of rk-mm. Signals use the arm64 `rt_sigframe` with the `fpsimd_context` record, and `rt_sigreturn` restores it. The boot CPU starts the other CPUs with PSCI `CPU_ON`, and each CPU has its own data, its GIC CPU interface and SGIs for the interrupts between CPUs. ptrace on arm64 has the `NT_PRSTATUS` and `NT_ARM_SYSTEM_CALL` register sets, and seccomp uses `AUDIT_ARCH_AARCH64`. The syscall table keeps the old x86-64 calls such as `open` and `fork` out of the arm64 build. `cargo xtask boot-test aarch64` runs the user tests `init` and `smp` when `RK_USER_CC_AARCH64` or `aarch64-linux-musl-gcc` gives an aarch64 musl compiler.

## [0.4.0] - 2026-10-27

### Fixed

- A read only mount of ext4 now frees the orphan inodes that a crash left, as `ext4_orphan_cleanup` of Linux. Before, the orphans stayed until a read write mount. A read only mount of ext4 now also opens the journal, so a remount can make the file system writable, as Linux. Before, the remount gave `EROFS`. A write to a file with `O_SYNC` or `O_DSYNC`, or to an inode with the flag `S_SYNC`, now puts the data and the new size in the journal before it returns, as `generic_write_sync` of Linux. This applies to `write`, `pwrite`, `writev`, `pwritev2` and the writes of AIO, also with `O_DIRECT`. generic/417 and generic/737 now pass (#310).

## [0.3.22] - 2026-10-27

### Added

- `BLKROSET` makes a block device read only or writable again, as `blkdev_roset` of Linux. A write to a read only device gives `EPERM`. A read and write mount of a read only device gives `EACCES`, as `setup_bdev_super` of Linux, so `mount(8)` mounts it read only. A remount to read and write of a read only device gives `EACCES`. ext4 gives `EROFS` for a journal to replay on a read only device. The mount options `norecovery` and `noload` of ext4 leave the journal, and a read only mount then reads the disk as it is. generic/050 now passes.
- `renameat2` with `RENAME_WHITEOUT` works on ext4 and tmpfs. The rename puts a whiteout, a character device with the device number 0:0, at the old name in the same change, as `ext4_whiteout_for_rename` and `shmem_whiteout` of Linux. The flag needs `CAP_MKNOD`. Other file systems give `EINVAL`.
- The VFS enforces the read only flag of each mount, as `mnt_want_write` of Linux. A create, a link, a remove, a rename, an open for a write, a truncate, a change of the attributes, of the extended attributes or of the inode flags on a read only mount gives `EROFS`. A read only bind mount does not change its source. A remount to read only gives `EBUSY` when a file on the mount is open for a write. tmpfs supports a `ro` mount and a remount to read only and back, as `shmem_reconfigure` of Linux. xfs stays read only.
- The `redirect_dir` feature of overlayfs, as `ovl_set_redirect` and `ovl_lookup` of Linux. With `redirect_dir=on`, a rename of a directory of a lower layer sets the attribute `overlay.redirect` of the upper directory to the old name, or to the old path for a move to another directory, and a lookup follows the redirect to the lower directories. An absolute redirect starts the lookup again at the roots of the layers, also below an opaque directory. `redirect_dir=follow`, the default, follows redirects but does not make them, and `redirect_dir=nofollow` gives `EPERM` for a redirect. A new directory in a merged directory is opaque with the feature. overlay/017, overlay/049 and overlay/057 now pass.
- The `metacopy` feature of overlayfs, as Linux. With `metacopy=on`, a change of the attributes of a regular file copies up only the attributes and sets `overlay.metacopy`. The first change of the data copies the data and removes the attribute. A metacopy file finds its data below it, or in a data-only layer through an absolute redirect. A copy up sets `overlay.origin` to the file handle of the lower file and marks the parent with `overlay.impure`, so a file keeps its inode number after a new mount, and `getdents64` gives the same inode numbers as `stat`. overlay/079 and overlay/085 now pass.
- The data-only lower layers of overlayfs, with `lowerdir=a::b` or with the options `lowerdir+=` and `datadir+=`, as fs/overlayfs/params.c of Linux. The values of `lowerdir+=` and `datadir+=` have no escapes, and `/proc/PID/mountinfo` shows them in the same form. `lowerdir+=` after `lowerdir=` or after `datadir+=` gives `EINVAL`. overlay/086 now passes.
- The `uuid` option of overlayfs, as `ovl_init_uuid_xattr` of Linux. A new overlay gets a uuid in the attribute `overlay.uuid` of the upper root, and `statfs` gives an `f_fsid` from it. An old overlay and `uuid=null` give the `f_fsid` of the upper file system. overlay/081 now passes.
- The `index` feature of overlayfs, as fs/overlayfs/namei.c of Linux. With `index=on`, a copy up of a lower hard link puts the upper file in the directory `index` of the work directory, with the file handle of the lower inode in hexadecimal as its name, and links it to the upper directory. The other lower hard links then show the same file, with the inode number of the lower inode. The attribute `overlay.nlink` keeps the count of the links of the overlay file, and the removal of the last name removes the entry. A mount checks that the index is for its layers, else it gives `ESTALE`, and removes the orphan entries and the temporary files. An upper or work directory that another mount uses gives `EBUSY` with the index. The whiteouts of a mount are links to one whiteout in the work directory, as `ovl_whiteout` of Linux. overlay/018, 033, 034, 036, 037, 042, 047, 048 and 073 now pass.
- The `nfs_export` feature of overlayfs, as fs/overlayfs/export.c of Linux. With `nfs_export=on`, `name_to_handle_at` gives a file handle in the format `ovl_fb` of Linux, with the file handle of the lower inode, or of the upper inode for a file that is only in the upper layer. `open_by_handle_at` finds the file from the handle, also after a new mount and for a file that is not in the cache. The feature needs the index. Each copy up of a lower file puts an entry in the index, also for a directory, and the removal of the last name of a file puts a whiteout at its entry. A mount puts a whiteout at each orphan entry. The feature turns `index` on and `metacopy` off when the options do not set them. overlay/050, 051, 052, 053, 054, 055, 068, 069 and 074 now pass.

### Fixed

- When a file grows, the bytes past the old end of the file in its last block become zeros. An append write, a truncate up and a `fallocate` that changes the size do this on the disk of ext4, as `ext4_block_zero_eof` of Linux. The VFS makes these bytes zeros in the pages of a mapping, as `pagecache_isize_extended` of Linux, so tmpfs and the other file systems also get it. Before, old data past the end of the file could show in the file. generic/794 now passes (#311).
- tools/fstests/build.sh stops when fio in the root file system has no libaio engine or when the `unshare` command is missing. The root file system has both. generic/095 and generic/366 now pass. overlay/020 is still not run because rukernel does not have user and PID namespaces yet.
- POSIX ACLs now follow fs/posix_acl.c of Linux in more places (#293). The ext4 mount options `acl` and `noacl` turn the ACLs on and off. Without ACLs, a file system ignores the default ACL of a directory, the umask applies to each new file, `getxattr` and `setxattr` of an ACL give `EOPNOTSUPP`, and `listxattr` does not show the ACLs. The removal of an ACL that a file does not have is not an error. `XATTR_CREATE` and `XATTR_REPLACE` do not apply to an ACL. A default ACL on a file that is not a directory gives `EACCES` before the check of the owner, and an invalid ACL gives `EPERM` to a process that does not own the file. ext4 gives no ACL for an ACL on the disk with no entries, and `EINVAL` for a damaged ACL. overlayfs gives `EOPNOTSUPP` for a change of an ACL if the upper layer has no ACLs, and a copy up to such a layer does not copy the ACLs.
- overlayfs keeps the nodes that are not in use, as the unused dentries of Linux. A lookup of the name gives the same node again, with the same inodes of the layers, until a removal through the mount or an eviction. A mount keeps 4096 unused nodes at most and evicts the oldest first. An unlink or a rmdir checks that the upper directory still has the upper file of the node, as `ovl_remove_upper` of Linux, and gives `ESTALE` after a change of the upper directory that is not through the mount. overlay/012 now passes.
- The file system and IPC permission checks now follow Linux in more places. `shmget`, `shmat`, `shmctl`, `semget`, `semop` and `semctl` now examine the mode of the object, as `ipcperms` of Linux. `IPC_SET` and `IPC_RMID` need the owner, the creator or `CAP_SYS_ADMIN`. `SHM_LOCK` and `SHM_UNLOCK` need the owner, the creator or `CAP_IPC_LOCK`. `utimensat` with times that are not both the time now needs the owner. An open with `O_TRUNC` clears the set-ID bits. `truncate` gives `EINVAL` for a file that is not regular. `rename` examines the permissions before the types of the files, as Linux. The exec of a traced process keeps the set-ID bits if the tracer has `CAP_SYS_PTRACE` (#292).
- `statfs` gives the `f_fsid` of the file system. Before, it gave the device of the inode, so a directory of overlayfs had the device of the overlay and not of the upper file system.
- The credentials of a process now follow Linux in more places. A new file in a directory without the set-group-ID bit keeps its set-group-ID bit, as `mode_strip_sgid` of Linux. A `setresuid` or `setresgid` that changes no ID keeps the file system ID. `setgroups` and `PR_CAPBSET_DROP` give `EPERM` before the checks of their arguments. `SO_PEERCRED` and `SCM_CREDENTIALS` give the effective user and group IDs of the sender, and a sender can only give the IDs and the pid that `scm_check_creds` of Linux allows. `kill`, `tkill`, `tgkill`, `pidfd_send_signal`, `SIGCHLD` and `waitid` give the real user ID of the sender or of the child in `si_uid`. A new shared memory segment or semaphore set gets the effective IDs of the caller as its owner and creator.
- An upper directory of overlayfs without lower directories loses the attribute `overlay.impure` when a read of its entries finds no name with the inode number of a lower inode, as `ovl_dir_read_impure` of Linux. overlay/038 now passes.

## [0.3.21] - 2026-10-27

### Added

- The `ea_inode` feature of ext4, as fs/ext4/xattr.c of Linux. A value of an extended attribute that is larger than a block less 56 bytes, or that does not fit in the inode and the attribute block, goes to the data of an inode of its own, so a value can have up to 64 KiB. The value inode has `EXT4_EA_INODE_FL`, the hash of the value in its access time and the count of its references in its change time and `i_version`. The count of blocks of the file also counts the blocks of its values, as Linux. A value that does not change keeps its inode, and the last reference frees the inode. ext4/026 now passes.
- Delayed allocation of buffered writes on ext4, as `delalloc` of Linux. A write to a hole of a file with an extent tree keeps its data in memory and keeps free blocks for it. The blocks are allocated at `fsync`, `sync`, a freeze, the unmount, or when the kept data is too large. `stat` counts the kept blocks, `statfs` does not give them as free, and `FS_IOC_FIEMAP` gives them with `FIEMAP_EXTENT_DELALLOC`. A truncate drops the kept blocks past the size, and `fallocate` and `EXT4_IOC_MOVE_EXT` first write back the data. The mount option `nodelalloc` turns it off. generic/614 now passes.
- The online resize of ext4 now grows the group descriptors past their blocks, as Linux. A new descriptor block takes the next reserved block of the resize inode, as `add_new_gdb`. When no reserved block is left, the file system changes to `meta_bg`, as `ext4_convert_meta_bg`, and each new meta block group keeps its descriptor block in its first group. With checksums of the descriptors the new inode tables are not zeroed, as Linux. sysfs now has `/sys/fs/ext4/features/meta_bg_resize`, which `resize2fs` reads before it grows a mounted file system past its reserved blocks. ext4/032 now passes.

### Fixed

- A remount with `MS_RDONLY` and without `MS_BIND`, or `FSCONFIG_CMD_RECONFIGURE`, now makes an ext4 file system read only, as Linux. Before the change, all the changes go to their places on the disk and the journal becomes empty. A remount without `MS_RDONLY` makes the file system writable again. Before, a remount changed only the flags of the mount, and a new file on a read only remount did not give `EROFS`. An open for a write of a file on a read only file system gives `EROFS`. generic/294 and generic/306 now pass.
- The work directory of overlayfs, as `ovl_workdir_create` of Linux. A mount with an upper directory removes an old `work` directory in the work directory and makes a new one with the mode 0 and no ACL. If it cannot, for example because the work directory is immutable, the mount is read only, and a remount for writes gives `EROFS`, as for a mount without an upper directory. An upper directory on overlayfs gives `EINVAL`. A remount now calls the file system, so that overlayfs can refuse it. overlay/022, overlay/023, overlay/024 and overlay/035 now pass.
- overlayfs escapes its extended attributes, as Linux. A user attribute with the prefix `trusted.overlay.` goes to the layer as `trusted.overlay.overlay.`, so an overlay can be a layer of another overlay, and a list does not show the attributes of overlayfs. The option `userxattr` changes the prefix to `user.overlay.`. A directory with `overlay.opaque` set to `x` can have whiteouts that are empty regular files with `overlay.whiteout`. The mount ignores unknown options such as `index=off`. overlay/026 and overlay/084 now pass.
- A copy up of overlayfs keeps the inode flags, as `ovl_copy_fileattr` of Linux. The upper file gets the sync and noatime flags. The immutable and append-only flags go to the attribute `overlay.protattr`, so the mount can still change the upper file, and the VFS still enforces the flags on the overlay file. overlay/075 and overlay/078 now pass.
- A copy up of overlayfs keeps the device and the inode number of a file, so a lock on the file stays the same lock. overlay/028 now passes.
- The options of overlayfs can have a comma and a colon with a backslash before them, as `ovl_parse_param_split_lowerdirs` of Linux. `/proc/PID/mountinfo` and `/proc/mounts` show the options of overlayfs, with octal escapes for the special characters, as `ovl_show_options` of Linux. overlay/083 now passes.

## [0.3.20] - 2026-10-27

### Added

- `name_to_handle_at` and `open_by_handle_at` on ext4 and tmpfs, as Linux. An ext4 handle has the inode number and the generation, as `FILEID_INO32_GEN`, so it stays valid after a rename and after a new mount. An open by handle needs `CAP_DAC_READ_SEARCH`, and a handle of a removed inode gives `ESTALE`. `statx` now gives the mount ID in `stx_mnt_id`. generic/426, generic/467 and generic/477 now pass.
- `EXT4_IOC_MOVE_EXT` on ext4, as `ext4_move_extents` of Linux. The ioctl swaps the blocks of a file with the blocks of a donor file for online defragmentation. The data of the file stays the same and goes to the blocks of the donor, and the donor gets the old blocks. If the blocks of both files have no data, only the extents swap. A hole in either file stays. `fallocate` on ext4 now takes a free run of all the blocks after a short free run at the goal, as the mballoc of Linux. ext4/308 and generic/018 now pass.
- `FS_IOC_GETFSMAP` on ext4, as Linux. The ioctl gives the map of the space of the file system: the superblocks, the group descriptors, the bitmaps and the inode tables with their special owners, the runs of free blocks, and the other blocks with an unknown owner. The keys select a range, and a call can continue after the last record of the call before. ext4/027 and ext4/028 now pass.
- The `dir_nlink` rule of ext4, as Linux. An indexed directory with more than 65000 subdirectories has a link count of 1, and keeps it after `rmdir` and rename. Without `dir_nlink`, or without an index, `mkdir` gives `EMLINK` at 65000 links. ext4/052 now passes.
- The `bigalloc` and `meta_bg` features of ext4 for read and write, as Linux. With `bigalloc` a bit of the block bitmap is a cluster of blocks, a file gets full clusters, a new block uses the cluster of its neighbors in the same logical cluster, and a cluster becomes free only when no block of the file uses it. Collapse and insert need full clusters, and `statfs` counts the metadata in clusters. A mount gives `EINVAL` when `first_meta_bg` is past the descriptor blocks. ext4/003 and ext4/025 now pass.

### Fixed

- ext4/005 now passes. `FS_IOC_SETFLAGS` without `EXT4_EXTENTS_FL` already moves a file from an extent tree to a block map, as Linux, and a new unit test checks that a write to a hole at the start of the file after the move gets a new block and does not touch the data after it.
- `pwrite64`, `pwritev` and `pwritev2` on a file with `O_APPEND` write at the end of the file and not at the offset, as Linux. `RWF_NOAPPEND` of `pwritev2` cancels `O_APPEND` for one write. generic/130 now passes.
- ext4 writes zeros over a removed directory entry, as `ext4_generic_delete_entry` of Linux, so the name of a removed file does not stay on the disk. A first record in a block keeps its record length. A new unit test also checks that the change of a directory to an index and the split of a leaf leave no old names, as `make_indexed_dir` and `do_split` of Linux. ext4/048 now passes.
- `swapon` of a regular file now counts only the pages of the disk that the file fully holds, as `iomap_swapfile_activate` of Linux, and gives `EINVAL` for a file without one such page. Before this change, a small file on ext4 with blocks of 1024 bytes and no aligned page on the disk became an active area. generic/641 now passes.
- The x86-64 kernel now runs at physical address 16 MiB, as `CONFIG_PHYSICAL_START` of Linux, and not at 1 MiB. The debug kernel ended after 8 MiB, where OVMF keeps its data, so the EFI stub could not allocate the pages of the kernel and the UEFI boot failed. The 32 bit and the 64 bit entries of the bzImage move the image from 1 MiB to 16 MiB. OVMF also keeps data at 16 MiB, so the EFI stub takes only the free pages there and moves the kernel there after `ExitBootServices`, when that memory is free. The frame allocator still uses the memory below 16 MiB.

## [0.3.19] - 2026-10-27

### Added

- `statx` gives the creation time of a file in `stx_btime` with `STATX_BTIME` on ext4, tmpfs and XFS, as Linux. An ext4 inode without room for the time and an XFS inode before version 3 do not have it. generic/528 now passes.
- `FS_IOC_GETFSLABEL` and `FS_IOC_SETFSLABEL` on ext4, as Linux. They read and change the label of a mounted file system. The new label goes to the disk at once, so `blkid` sees it while the file system is mounted. A label longer than 16 bytes gives `EINVAL`, and a change needs `CAP_SYS_ADMIN`. generic/492 now passes.
- The DAX flag of ext4, as Linux. `FS_IOC_FSGETXATTR` and `FS_IOC_FSSETXATTR` show and change it as `FS_XFLAG_DAX`, and `FS_IOC_SETFLAGS` changes it as `FS_DAX_FL`. A new inode gets the inherited flags of its directory, as `__ext4_new_inode` of Linux, so a new file in a directory with the DAX flag also has the flag. The kernel does not use direct access, so the flag changes nothing else. generic/607 now passes.
- `FIFREEZE` and `FITHAW` on ext4, as Linux. A freeze writes all the changes to their places on the disk and empties the journal, so the disk is clean. A change after the freeze waits for the thaw, and a read does not change the access time. The caller needs `CAP_SYS_ADMIN`. generic/491 and generic/738 now pass.
- `FS_IOC_FIEMAP` with `FIEMAP_FLAG_XATTR` on ext4, as Linux. The ioctl gives the area of the extended attributes in the inode, with `FIEMAP_EXTENT_DATA_INLINE` and `FIEMAP_EXTENT_NOT_ALIGNED`, or else the attribute block of the inode. generic/425 now passes.
- `/dev/kmsg`, as Linux. A write puts one record in the kernel log, with the level and the facility of a `<N>` at the start, or the level 4 and the facility `LOG_USER` without it. A read gives one record as `prio,seq,usec,-;text`, and `lseek` with `SEEK_SET`, `SEEK_DATA` and `SEEK_END` moves to the first record, the first record after the last clear and the end. `dmesg` shows the records. ext4 now keeps a time out of the range of an inode as the nearest time in the range, as Linux, so a time after the year 2446 becomes the last second of 2446. generic/402 now passes.
- ext4 directories with a hash index (`dir_index`, `EXT4_INDEX_FL`), as Linux. A lookup in an indexed directory uses the index, with the legacy, half MD4 and TEA hashes, their unsigned variants and the hash seed of the superblock. A new entry goes into the correct leaf block. A full leaf splits in two, and the index gets a new level when it is full, up to the limit of Linux. When the first block of a directory is full and the file system has `dir_index`, the directory gets an index. Remove and rename keep the index correct, and the index blocks have their checksums with `metadata_csum`. `readdir` reads the blocks in order. ext4/023, generic/001, generic/002, generic/005, generic/006, generic/011 and generic/013 pass, and e2fsck finds no error after each test.
- The loop device, as drivers/block/loop.c of Linux. A loop device is a block device that reads and writes a file at an offset, up to a size limit. `/dev/loop-control` takes `LOOP_CTL_GET_FREE`, `LOOP_CTL_ADD` and `LOOP_CTL_REMOVE`, and the kernel makes and removes the device files in `/dev`. The boot makes `loop0` to `loop7`. Each `/dev/loopN` takes `LOOP_SET_FD`, `LOOP_CONFIGURE`, `LOOP_CLR_FD`, `LOOP_SET_STATUS64`, `LOOP_GET_STATUS64`, `LOOP_SET_CAPACITY`, `LOOP_SET_DIRECT_IO` and `LOOP_SET_BLOCK_SIZE`. A device with `LO_FLAGS_AUTOCLEAR` lets its file go at the last close, so `losetup -d` and `mount -o loop` work. sysfs has the `loop` directory of a device with a file, for example `/sys/block/loop0/loop/backing_file`, and `/proc/devices` shows the major numbers. generic/361 now passes.

## [0.3.18] - 2026-10-27

### Added

- The sysctls `fs.protected_symlinks`, `fs.protected_hardlinks`, `fs.protected_regular` and `fs.protected_fifos`, as Linux. With them, the path walk does not follow a symbolic link of another user in a sticky directory that all can write, `link` gives `EPERM` for a file that the process does not own and cannot read and write, and `open` with `O_CREAT` gives `EACCES` for a file or a FIFO of another user in a sticky directory. Each one is 0 by default, as Linux. generic/597 and generic/598 now pass.
- `mount_setattr`, as Linux. The call sets and clears the flags of a mount (`MOUNT_ATTR_RDONLY`, `MOUNT_ATTR_NOSUID`, `MOUNT_ATTR_NODEV`, `MOUNT_ATTR_NOEXEC`, the atime value, `MOUNT_ATTR_NODIRATIME` and `MOUNT_ATTR_NOSYMFOLLOW`) and changes its propagation. With `AT_RECURSIVE`, it also changes the mounts under the mount. The mount can be a detached mount of `fsmount` or `open_tree`. rukernel has no user namespaces yet, so `MOUNT_ATTR_IDMAP` gives `EINVAL` and the kernel cannot make an idmapped mount. generic/644, generic/689, generic/698 and generic/699 now find the call, but they do not run because they need idmapped mounts.
- `FITRIM` on ext4, as Linux. The call discards the runs of free blocks in a range that have at least the length that the caller gives, and gives the bytes of the runs. A block that a change freed before the last commit stays, because the journal can still need it. The call needs `CAP_SYS_ADMIN`, and a disk that cannot discard gives `EOPNOTSUPP`. The virtio-blk driver now uses the discard command of the device, and the block layer passes a discard from a file system to the driver.
- `O_TMPFILE` on ext4 and tmpfs, as Linux. `open` with `O_TMPFILE` makes a regular file without a name in a directory, and `linkat` with `AT_EMPTY_PATH` or with a link of `/proc/self/fd` gives the file a name. A file of `O_TMPFILE` with `O_EXCL` gets no name. On ext4 the file is on the list of orphans until its first link, so a crash does not keep it. The sysctl `fs.file-max` now shows 10 percent of the memory in KiB, as Linux. generic/004, generic/389 and generic/531 now pass.

### Fixed

- A write, a truncate or a `fallocate` of a regular file by a process that is not in the group of the file now clears the set-group-ID bit, as `file_remove_privs` of Linux. Before this change, the bit stayed when the group could not run the file. generic/683, generic/684, generic/685, generic/686 and generic/687 now pass.

## [0.3.17] - 2026-10-26

### Added

- `RLIMIT_FSIZE`, the largest file that a process can write, as Linux. A write to a regular file is short at the limit, and a write at or after the limit sends `SIGXFSZ` and gives `EFBIG`. `truncate`, `ftruncate` and `fallocate` without `FALLOC_FL_KEEP_SIZE` that make a file larger than the limit also send `SIGXFSZ` and give `EFBIG`. generic/228 and generic/394 now pass.

### Fixed

- The device files that the kernel makes in `/dev` now have the mode of the device list, as devtmpfs of Linux gives. Before this change, the umask of init removed the write bits of the group and of the other users, so a user that is not root could not write to `/dev/null`.
- The files in `/proc/PID` now belong to the effective user and group of the process, as Linux. Before this change, root owned each file, so a process that is not root could not read its own `/proc/self/fd`.
- A write or a `fallocate` of an ext4 file that takes the last free blocks no longer loses its blocks when the extent tree needs a new block. Before this change, the call gave `ENOSPC` after it marked the data blocks as used, and the extent tree did not point to them, so fsck found an error. Now the call gives back its last blocks until the tree fits, and a write is short. generic/256 now passes.
- An ext4 allocation that finds no free block now commits the journal and tries again, as ext4 of Linux. Before this change, the blocks that a change freed stayed busy until the next commit, so a write after a truncate could give `ENOSPC` on a disk with free blocks. generic/213 now passes.

## [0.3.16] - 2026-10-26

### Added

- The propagation of mounts, as the shared subtrees of Linux. `mount` with `MS_SHARED`, `MS_SLAVE`, `MS_PRIVATE` or `MS_UNBINDABLE` changes the propagation of a mount, and `MS_REC` changes the mounts under it too. A mount or an unmount under a shared mount occurs on each peer of the mount and on each slave of the peer group. A bind mount of a shared mount is a peer of the source, and a bind mount of an unbindable mount gives `EINVAL`. `/proc/PID/mountinfo` shows the `shared:`, `master:` and `unbindable` fields.
- Mount name spaces. `unshare` and `clone` with `CLONE_NEWNS` give the process a copy of each mount, as `copy_mnt_ns` of Linux. A copy of a shared mount is a peer of the mount, so a mount under it shows in both name spaces. The flag needs `CAP_SYS_ADMIN`, and `clone` gives `EINVAL` if it also has `CLONE_FS`.

### Fixed

- A second mount of a block device that has a mounted file system of the same type now gives the same file system, as the super blocks of Linux. Before this change, each mount read the disk again, and the two mounts did not see the changes of the other. A mount that would change the read only state of the file system gives `EBUSY`, as Linux.
- A new file that a process makes in a set-group-ID directory now loses the set-group-ID bit before the umask, as `vfs_prepare_mode` of Linux. Before this change, a umask that removed the execute bit of the group kept the set-group-ID bit on a file that the process could not make set-group-ID. This applies to `open`, `mkdir` and `mknod`.
- `clone` with `CLONE_NEWUSER`, `CLONE_NEWPID`, `CLONE_NEWNET` or another namespace type that rukernel does not have now gives `EINVAL`, as `unshare` does. Before this change, `clone` ignored these flags, and a program could not see that the new namespace was not there.

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

[0.4.19]: https://github.com/tamnd/rukernel/releases/tag/v0.4.19
[0.4.18]: https://github.com/tamnd/rukernel/releases/tag/v0.4.18
[0.4.17]: https://github.com/tamnd/rukernel/releases/tag/v0.4.17
[0.4.16]: https://github.com/tamnd/rukernel/releases/tag/v0.4.16
[0.4.15]: https://github.com/tamnd/rukernel/releases/tag/v0.4.15
[0.4.14]: https://github.com/tamnd/rukernel/releases/tag/v0.4.14
[0.4.13]: https://github.com/tamnd/rukernel/releases/tag/v0.4.13
[0.4.12]: https://github.com/tamnd/rukernel/releases/tag/v0.4.12
[0.4.11]: https://github.com/tamnd/rukernel/releases/tag/v0.4.11
[0.4.10]: https://github.com/tamnd/rukernel/releases/tag/v0.4.10
[0.4.9]: https://github.com/tamnd/rukernel/releases/tag/v0.4.9
[0.4.8]: https://github.com/tamnd/rukernel/releases/tag/v0.4.8
[0.4.7]: https://github.com/tamnd/rukernel/releases/tag/v0.4.7
[0.4.6]: https://github.com/tamnd/rukernel/releases/tag/v0.4.6
[0.4.5]: https://github.com/tamnd/rukernel/releases/tag/v0.4.5
[0.4.4]: https://github.com/tamnd/rukernel/releases/tag/v0.4.4
[0.4.3]: https://github.com/tamnd/rukernel/releases/tag/v0.4.3
[0.4.2]: https://github.com/tamnd/rukernel/releases/tag/v0.4.2
[0.4.1]: https://github.com/tamnd/rukernel/releases/tag/v0.4.1
[0.4.0]: https://github.com/tamnd/rukernel/releases/tag/v0.4.0
[0.3.22]: https://github.com/tamnd/rukernel/releases/tag/v0.3.22
[0.3.21]: https://github.com/tamnd/rukernel/releases/tag/v0.3.21
[0.3.20]: https://github.com/tamnd/rukernel/releases/tag/v0.3.20
[0.3.19]: https://github.com/tamnd/rukernel/releases/tag/v0.3.19
[0.3.18]: https://github.com/tamnd/rukernel/releases/tag/v0.3.18
[0.3.17]: https://github.com/tamnd/rukernel/releases/tag/v0.3.17
[0.3.16]: https://github.com/tamnd/rukernel/releases/tag/v0.3.16
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

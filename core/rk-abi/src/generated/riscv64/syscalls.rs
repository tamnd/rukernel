// rk-abigen generated this file from Linux 7.3, from scripts/syscall.tbl.
// Do not edit it. Change rk-abigen and run it again.

//! The system call numbers of riscv64 in Linux.
//!
//! The table uses the lines of the ABIs common, 64, riscv, rlimit, memfd_secret.

/// The highest system call number plus one.
pub const NR_SYSCALLS: usize = 473;
/// The number of `io_setup`.
pub const IO_SETUP: u32 = 0;
/// The number of `io_destroy`.
pub const IO_DESTROY: u32 = 1;
/// The number of `io_submit`.
pub const IO_SUBMIT: u32 = 2;
/// The number of `io_cancel`.
pub const IO_CANCEL: u32 = 3;
/// The number of `io_getevents`.
pub const IO_GETEVENTS: u32 = 4;
/// The number of `setxattr`.
pub const SETXATTR: u32 = 5;
/// The number of `lsetxattr`.
pub const LSETXATTR: u32 = 6;
/// The number of `fsetxattr`.
pub const FSETXATTR: u32 = 7;
/// The number of `getxattr`.
pub const GETXATTR: u32 = 8;
/// The number of `lgetxattr`.
pub const LGETXATTR: u32 = 9;
/// The number of `fgetxattr`.
pub const FGETXATTR: u32 = 10;
/// The number of `listxattr`.
pub const LISTXATTR: u32 = 11;
/// The number of `llistxattr`.
pub const LLISTXATTR: u32 = 12;
/// The number of `flistxattr`.
pub const FLISTXATTR: u32 = 13;
/// The number of `removexattr`.
pub const REMOVEXATTR: u32 = 14;
/// The number of `lremovexattr`.
pub const LREMOVEXATTR: u32 = 15;
/// The number of `fremovexattr`.
pub const FREMOVEXATTR: u32 = 16;
/// The number of `getcwd`.
pub const GETCWD: u32 = 17;
/// The number of `lookup_dcookie`.
pub const LOOKUP_DCOOKIE: u32 = 18;
/// The number of `eventfd2`.
pub const EVENTFD2: u32 = 19;
/// The number of `epoll_create1`.
pub const EPOLL_CREATE1: u32 = 20;
/// The number of `epoll_ctl`.
pub const EPOLL_CTL: u32 = 21;
/// The number of `epoll_pwait`.
pub const EPOLL_PWAIT: u32 = 22;
/// The number of `dup`.
pub const DUP: u32 = 23;
/// The number of `dup3`.
pub const DUP3: u32 = 24;
/// The number of `fcntl`.
pub const FCNTL: u32 = 25;
/// The number of `inotify_init1`.
pub const INOTIFY_INIT1: u32 = 26;
/// The number of `inotify_add_watch`.
pub const INOTIFY_ADD_WATCH: u32 = 27;
/// The number of `inotify_rm_watch`.
pub const INOTIFY_RM_WATCH: u32 = 28;
/// The number of `ioctl`.
pub const IOCTL: u32 = 29;
/// The number of `ioprio_set`.
pub const IOPRIO_SET: u32 = 30;
/// The number of `ioprio_get`.
pub const IOPRIO_GET: u32 = 31;
/// The number of `flock`.
pub const FLOCK: u32 = 32;
/// The number of `mknodat`.
pub const MKNODAT: u32 = 33;
/// The number of `mkdirat`.
pub const MKDIRAT: u32 = 34;
/// The number of `unlinkat`.
pub const UNLINKAT: u32 = 35;
/// The number of `symlinkat`.
pub const SYMLINKAT: u32 = 36;
/// The number of `linkat`.
pub const LINKAT: u32 = 37;
/// The number of `umount2`.
pub const UMOUNT2: u32 = 39;
/// The number of `mount`.
pub const MOUNT: u32 = 40;
/// The number of `pivot_root`.
pub const PIVOT_ROOT: u32 = 41;
/// The number of `nfsservctl`.
pub const NFSSERVCTL: u32 = 42;
/// The number of `statfs`.
pub const STATFS: u32 = 43;
/// The number of `fstatfs`.
pub const FSTATFS: u32 = 44;
/// The number of `truncate`.
pub const TRUNCATE: u32 = 45;
/// The number of `ftruncate`.
pub const FTRUNCATE: u32 = 46;
/// The number of `fallocate`.
pub const FALLOCATE: u32 = 47;
/// The number of `faccessat`.
pub const FACCESSAT: u32 = 48;
/// The number of `chdir`.
pub const CHDIR: u32 = 49;
/// The number of `fchdir`.
pub const FCHDIR: u32 = 50;
/// The number of `chroot`.
pub const CHROOT: u32 = 51;
/// The number of `fchmod`.
pub const FCHMOD: u32 = 52;
/// The number of `fchmodat`.
pub const FCHMODAT: u32 = 53;
/// The number of `fchownat`.
pub const FCHOWNAT: u32 = 54;
/// The number of `fchown`.
pub const FCHOWN: u32 = 55;
/// The number of `openat`.
pub const OPENAT: u32 = 56;
/// The number of `close`.
pub const CLOSE: u32 = 57;
/// The number of `vhangup`.
pub const VHANGUP: u32 = 58;
/// The number of `pipe2`.
pub const PIPE2: u32 = 59;
/// The number of `quotactl`.
pub const QUOTACTL: u32 = 60;
/// The number of `getdents64`.
pub const GETDENTS64: u32 = 61;
/// The number of `lseek`.
pub const LSEEK: u32 = 62;
/// The number of `read`.
pub const READ: u32 = 63;
/// The number of `write`.
pub const WRITE: u32 = 64;
/// The number of `readv`.
pub const READV: u32 = 65;
/// The number of `writev`.
pub const WRITEV: u32 = 66;
/// The number of `pread64`.
pub const PREAD64: u32 = 67;
/// The number of `pwrite64`.
pub const PWRITE64: u32 = 68;
/// The number of `preadv`.
pub const PREADV: u32 = 69;
/// The number of `pwritev`.
pub const PWRITEV: u32 = 70;
/// The number of `sendfile`.
pub const SENDFILE: u32 = 71;
/// The number of `pselect6`.
pub const PSELECT6: u32 = 72;
/// The number of `ppoll`.
pub const PPOLL: u32 = 73;
/// The number of `signalfd4`.
pub const SIGNALFD4: u32 = 74;
/// The number of `vmsplice`.
pub const VMSPLICE: u32 = 75;
/// The number of `splice`.
pub const SPLICE: u32 = 76;
/// The number of `tee`.
pub const TEE: u32 = 77;
/// The number of `readlinkat`.
pub const READLINKAT: u32 = 78;
/// The number of `newfstatat`.
pub const NEWFSTATAT: u32 = 79;
/// The number of `fstat`.
pub const FSTAT: u32 = 80;
/// The number of `sync`.
pub const SYNC: u32 = 81;
/// The number of `fsync`.
pub const FSYNC: u32 = 82;
/// The number of `fdatasync`.
pub const FDATASYNC: u32 = 83;
/// The number of `sync_file_range`.
pub const SYNC_FILE_RANGE: u32 = 84;
/// The number of `timerfd_create`.
pub const TIMERFD_CREATE: u32 = 85;
/// The number of `timerfd_settime`.
pub const TIMERFD_SETTIME: u32 = 86;
/// The number of `timerfd_gettime`.
pub const TIMERFD_GETTIME: u32 = 87;
/// The number of `utimensat`.
pub const UTIMENSAT: u32 = 88;
/// The number of `acct`.
pub const ACCT: u32 = 89;
/// The number of `capget`.
pub const CAPGET: u32 = 90;
/// The number of `capset`.
pub const CAPSET: u32 = 91;
/// The number of `personality`.
pub const PERSONALITY: u32 = 92;
/// The number of `exit`.
pub const EXIT: u32 = 93;
/// The number of `exit_group`.
pub const EXIT_GROUP: u32 = 94;
/// The number of `waitid`.
pub const WAITID: u32 = 95;
/// The number of `set_tid_address`.
pub const SET_TID_ADDRESS: u32 = 96;
/// The number of `unshare`.
pub const UNSHARE: u32 = 97;
/// The number of `futex`.
pub const FUTEX: u32 = 98;
/// The number of `set_robust_list`.
pub const SET_ROBUST_LIST: u32 = 99;
/// The number of `get_robust_list`.
pub const GET_ROBUST_LIST: u32 = 100;
/// The number of `nanosleep`.
pub const NANOSLEEP: u32 = 101;
/// The number of `getitimer`.
pub const GETITIMER: u32 = 102;
/// The number of `setitimer`.
pub const SETITIMER: u32 = 103;
/// The number of `kexec_load`.
pub const KEXEC_LOAD: u32 = 104;
/// The number of `init_module`.
pub const INIT_MODULE: u32 = 105;
/// The number of `delete_module`.
pub const DELETE_MODULE: u32 = 106;
/// The number of `timer_create`.
pub const TIMER_CREATE: u32 = 107;
/// The number of `timer_gettime`.
pub const TIMER_GETTIME: u32 = 108;
/// The number of `timer_getoverrun`.
pub const TIMER_GETOVERRUN: u32 = 109;
/// The number of `timer_settime`.
pub const TIMER_SETTIME: u32 = 110;
/// The number of `timer_delete`.
pub const TIMER_DELETE: u32 = 111;
/// The number of `clock_settime`.
pub const CLOCK_SETTIME: u32 = 112;
/// The number of `clock_gettime`.
pub const CLOCK_GETTIME: u32 = 113;
/// The number of `clock_getres`.
pub const CLOCK_GETRES: u32 = 114;
/// The number of `clock_nanosleep`.
pub const CLOCK_NANOSLEEP: u32 = 115;
/// The number of `syslog`.
pub const SYSLOG: u32 = 116;
/// The number of `ptrace`.
pub const PTRACE: u32 = 117;
/// The number of `sched_setparam`.
pub const SCHED_SETPARAM: u32 = 118;
/// The number of `sched_setscheduler`.
pub const SCHED_SETSCHEDULER: u32 = 119;
/// The number of `sched_getscheduler`.
pub const SCHED_GETSCHEDULER: u32 = 120;
/// The number of `sched_getparam`.
pub const SCHED_GETPARAM: u32 = 121;
/// The number of `sched_setaffinity`.
pub const SCHED_SETAFFINITY: u32 = 122;
/// The number of `sched_getaffinity`.
pub const SCHED_GETAFFINITY: u32 = 123;
/// The number of `sched_yield`.
pub const SCHED_YIELD: u32 = 124;
/// The number of `sched_get_priority_max`.
pub const SCHED_GET_PRIORITY_MAX: u32 = 125;
/// The number of `sched_get_priority_min`.
pub const SCHED_GET_PRIORITY_MIN: u32 = 126;
/// The number of `sched_rr_get_interval`.
pub const SCHED_RR_GET_INTERVAL: u32 = 127;
/// The number of `restart_syscall`.
pub const RESTART_SYSCALL: u32 = 128;
/// The number of `kill`.
pub const KILL: u32 = 129;
/// The number of `tkill`.
pub const TKILL: u32 = 130;
/// The number of `tgkill`.
pub const TGKILL: u32 = 131;
/// The number of `sigaltstack`.
pub const SIGALTSTACK: u32 = 132;
/// The number of `rt_sigsuspend`.
pub const RT_SIGSUSPEND: u32 = 133;
/// The number of `rt_sigaction`.
pub const RT_SIGACTION: u32 = 134;
/// The number of `rt_sigprocmask`.
pub const RT_SIGPROCMASK: u32 = 135;
/// The number of `rt_sigpending`.
pub const RT_SIGPENDING: u32 = 136;
/// The number of `rt_sigtimedwait`.
pub const RT_SIGTIMEDWAIT: u32 = 137;
/// The number of `rt_sigqueueinfo`.
pub const RT_SIGQUEUEINFO: u32 = 138;
/// The number of `rt_sigreturn`.
pub const RT_SIGRETURN: u32 = 139;
/// The number of `setpriority`.
pub const SETPRIORITY: u32 = 140;
/// The number of `getpriority`.
pub const GETPRIORITY: u32 = 141;
/// The number of `reboot`.
pub const REBOOT: u32 = 142;
/// The number of `setregid`.
pub const SETREGID: u32 = 143;
/// The number of `setgid`.
pub const SETGID: u32 = 144;
/// The number of `setreuid`.
pub const SETREUID: u32 = 145;
/// The number of `setuid`.
pub const SETUID: u32 = 146;
/// The number of `setresuid`.
pub const SETRESUID: u32 = 147;
/// The number of `getresuid`.
pub const GETRESUID: u32 = 148;
/// The number of `setresgid`.
pub const SETRESGID: u32 = 149;
/// The number of `getresgid`.
pub const GETRESGID: u32 = 150;
/// The number of `setfsuid`.
pub const SETFSUID: u32 = 151;
/// The number of `setfsgid`.
pub const SETFSGID: u32 = 152;
/// The number of `times`.
pub const TIMES: u32 = 153;
/// The number of `setpgid`.
pub const SETPGID: u32 = 154;
/// The number of `getpgid`.
pub const GETPGID: u32 = 155;
/// The number of `getsid`.
pub const GETSID: u32 = 156;
/// The number of `setsid`.
pub const SETSID: u32 = 157;
/// The number of `getgroups`.
pub const GETGROUPS: u32 = 158;
/// The number of `setgroups`.
pub const SETGROUPS: u32 = 159;
/// The number of `uname`.
pub const UNAME: u32 = 160;
/// The number of `sethostname`.
pub const SETHOSTNAME: u32 = 161;
/// The number of `setdomainname`.
pub const SETDOMAINNAME: u32 = 162;
/// The number of `getrlimit`.
pub const GETRLIMIT: u32 = 163;
/// The number of `setrlimit`.
pub const SETRLIMIT: u32 = 164;
/// The number of `getrusage`.
pub const GETRUSAGE: u32 = 165;
/// The number of `umask`.
pub const UMASK: u32 = 166;
/// The number of `prctl`.
pub const PRCTL: u32 = 167;
/// The number of `getcpu`.
pub const GETCPU: u32 = 168;
/// The number of `gettimeofday`.
pub const GETTIMEOFDAY: u32 = 169;
/// The number of `settimeofday`.
pub const SETTIMEOFDAY: u32 = 170;
/// The number of `adjtimex`.
pub const ADJTIMEX: u32 = 171;
/// The number of `getpid`.
pub const GETPID: u32 = 172;
/// The number of `getppid`.
pub const GETPPID: u32 = 173;
/// The number of `getuid`.
pub const GETUID: u32 = 174;
/// The number of `geteuid`.
pub const GETEUID: u32 = 175;
/// The number of `getgid`.
pub const GETGID: u32 = 176;
/// The number of `getegid`.
pub const GETEGID: u32 = 177;
/// The number of `gettid`.
pub const GETTID: u32 = 178;
/// The number of `sysinfo`.
pub const SYSINFO: u32 = 179;
/// The number of `mq_open`.
pub const MQ_OPEN: u32 = 180;
/// The number of `mq_unlink`.
pub const MQ_UNLINK: u32 = 181;
/// The number of `mq_timedsend`.
pub const MQ_TIMEDSEND: u32 = 182;
/// The number of `mq_timedreceive`.
pub const MQ_TIMEDRECEIVE: u32 = 183;
/// The number of `mq_notify`.
pub const MQ_NOTIFY: u32 = 184;
/// The number of `mq_getsetattr`.
pub const MQ_GETSETATTR: u32 = 185;
/// The number of `msgget`.
pub const MSGGET: u32 = 186;
/// The number of `msgctl`.
pub const MSGCTL: u32 = 187;
/// The number of `msgrcv`.
pub const MSGRCV: u32 = 188;
/// The number of `msgsnd`.
pub const MSGSND: u32 = 189;
/// The number of `semget`.
pub const SEMGET: u32 = 190;
/// The number of `semctl`.
pub const SEMCTL: u32 = 191;
/// The number of `semtimedop`.
pub const SEMTIMEDOP: u32 = 192;
/// The number of `semop`.
pub const SEMOP: u32 = 193;
/// The number of `shmget`.
pub const SHMGET: u32 = 194;
/// The number of `shmctl`.
pub const SHMCTL: u32 = 195;
/// The number of `shmat`.
pub const SHMAT: u32 = 196;
/// The number of `shmdt`.
pub const SHMDT: u32 = 197;
/// The number of `socket`.
pub const SOCKET: u32 = 198;
/// The number of `socketpair`.
pub const SOCKETPAIR: u32 = 199;
/// The number of `bind`.
pub const BIND: u32 = 200;
/// The number of `listen`.
pub const LISTEN: u32 = 201;
/// The number of `accept`.
pub const ACCEPT: u32 = 202;
/// The number of `connect`.
pub const CONNECT: u32 = 203;
/// The number of `getsockname`.
pub const GETSOCKNAME: u32 = 204;
/// The number of `getpeername`.
pub const GETPEERNAME: u32 = 205;
/// The number of `sendto`.
pub const SENDTO: u32 = 206;
/// The number of `recvfrom`.
pub const RECVFROM: u32 = 207;
/// The number of `setsockopt`.
pub const SETSOCKOPT: u32 = 208;
/// The number of `getsockopt`.
pub const GETSOCKOPT: u32 = 209;
/// The number of `shutdown`.
pub const SHUTDOWN: u32 = 210;
/// The number of `sendmsg`.
pub const SENDMSG: u32 = 211;
/// The number of `recvmsg`.
pub const RECVMSG: u32 = 212;
/// The number of `readahead`.
pub const READAHEAD: u32 = 213;
/// The number of `brk`.
pub const BRK: u32 = 214;
/// The number of `munmap`.
pub const MUNMAP: u32 = 215;
/// The number of `mremap`.
pub const MREMAP: u32 = 216;
/// The number of `add_key`.
pub const ADD_KEY: u32 = 217;
/// The number of `request_key`.
pub const REQUEST_KEY: u32 = 218;
/// The number of `keyctl`.
pub const KEYCTL: u32 = 219;
/// The number of `clone`.
pub const CLONE: u32 = 220;
/// The number of `execve`.
pub const EXECVE: u32 = 221;
/// The number of `mmap`.
pub const MMAP: u32 = 222;
/// The number of `fadvise64`.
pub const FADVISE64: u32 = 223;
/// The number of `swapon`.
pub const SWAPON: u32 = 224;
/// The number of `swapoff`.
pub const SWAPOFF: u32 = 225;
/// The number of `mprotect`.
pub const MPROTECT: u32 = 226;
/// The number of `msync`.
pub const MSYNC: u32 = 227;
/// The number of `mlock`.
pub const MLOCK: u32 = 228;
/// The number of `munlock`.
pub const MUNLOCK: u32 = 229;
/// The number of `mlockall`.
pub const MLOCKALL: u32 = 230;
/// The number of `munlockall`.
pub const MUNLOCKALL: u32 = 231;
/// The number of `mincore`.
pub const MINCORE: u32 = 232;
/// The number of `madvise`.
pub const MADVISE: u32 = 233;
/// The number of `remap_file_pages`.
pub const REMAP_FILE_PAGES: u32 = 234;
/// The number of `mbind`.
pub const MBIND: u32 = 235;
/// The number of `get_mempolicy`.
pub const GET_MEMPOLICY: u32 = 236;
/// The number of `set_mempolicy`.
pub const SET_MEMPOLICY: u32 = 237;
/// The number of `migrate_pages`.
pub const MIGRATE_PAGES: u32 = 238;
/// The number of `move_pages`.
pub const MOVE_PAGES: u32 = 239;
/// The number of `rt_tgsigqueueinfo`.
pub const RT_TGSIGQUEUEINFO: u32 = 240;
/// The number of `perf_event_open`.
pub const PERF_EVENT_OPEN: u32 = 241;
/// The number of `accept4`.
pub const ACCEPT4: u32 = 242;
/// The number of `recvmmsg`.
pub const RECVMMSG: u32 = 243;
/// The number of `riscv_hwprobe`.
pub const RISCV_HWPROBE: u32 = 258;
/// The number of `riscv_flush_icache`.
pub const RISCV_FLUSH_ICACHE: u32 = 259;
/// The number of `wait4`.
pub const WAIT4: u32 = 260;
/// The number of `prlimit64`.
pub const PRLIMIT64: u32 = 261;
/// The number of `fanotify_init`.
pub const FANOTIFY_INIT: u32 = 262;
/// The number of `fanotify_mark`.
pub const FANOTIFY_MARK: u32 = 263;
/// The number of `name_to_handle_at`.
pub const NAME_TO_HANDLE_AT: u32 = 264;
/// The number of `open_by_handle_at`.
pub const OPEN_BY_HANDLE_AT: u32 = 265;
/// The number of `clock_adjtime`.
pub const CLOCK_ADJTIME: u32 = 266;
/// The number of `syncfs`.
pub const SYNCFS: u32 = 267;
/// The number of `setns`.
pub const SETNS: u32 = 268;
/// The number of `sendmmsg`.
pub const SENDMMSG: u32 = 269;
/// The number of `process_vm_readv`.
pub const PROCESS_VM_READV: u32 = 270;
/// The number of `process_vm_writev`.
pub const PROCESS_VM_WRITEV: u32 = 271;
/// The number of `kcmp`.
pub const KCMP: u32 = 272;
/// The number of `finit_module`.
pub const FINIT_MODULE: u32 = 273;
/// The number of `sched_setattr`.
pub const SCHED_SETATTR: u32 = 274;
/// The number of `sched_getattr`.
pub const SCHED_GETATTR: u32 = 275;
/// The number of `renameat2`.
pub const RENAMEAT2: u32 = 276;
/// The number of `seccomp`.
pub const SECCOMP: u32 = 277;
/// The number of `getrandom`.
pub const GETRANDOM: u32 = 278;
/// The number of `memfd_create`.
pub const MEMFD_CREATE: u32 = 279;
/// The number of `bpf`.
pub const BPF: u32 = 280;
/// The number of `execveat`.
pub const EXECVEAT: u32 = 281;
/// The number of `userfaultfd`.
pub const USERFAULTFD: u32 = 282;
/// The number of `membarrier`.
pub const MEMBARRIER: u32 = 283;
/// The number of `mlock2`.
pub const MLOCK2: u32 = 284;
/// The number of `copy_file_range`.
pub const COPY_FILE_RANGE: u32 = 285;
/// The number of `preadv2`.
pub const PREADV2: u32 = 286;
/// The number of `pwritev2`.
pub const PWRITEV2: u32 = 287;
/// The number of `pkey_mprotect`.
pub const PKEY_MPROTECT: u32 = 288;
/// The number of `pkey_alloc`.
pub const PKEY_ALLOC: u32 = 289;
/// The number of `pkey_free`.
pub const PKEY_FREE: u32 = 290;
/// The number of `statx`.
pub const STATX: u32 = 291;
/// The number of `io_pgetevents`.
pub const IO_PGETEVENTS: u32 = 292;
/// The number of `rseq`.
pub const RSEQ: u32 = 293;
/// The number of `kexec_file_load`.
pub const KEXEC_FILE_LOAD: u32 = 294;
/// The number of `pidfd_send_signal`.
pub const PIDFD_SEND_SIGNAL: u32 = 424;
/// The number of `io_uring_setup`.
pub const IO_URING_SETUP: u32 = 425;
/// The number of `io_uring_enter`.
pub const IO_URING_ENTER: u32 = 426;
/// The number of `io_uring_register`.
pub const IO_URING_REGISTER: u32 = 427;
/// The number of `open_tree`.
pub const OPEN_TREE: u32 = 428;
/// The number of `move_mount`.
pub const MOVE_MOUNT: u32 = 429;
/// The number of `fsopen`.
pub const FSOPEN: u32 = 430;
/// The number of `fsconfig`.
pub const FSCONFIG: u32 = 431;
/// The number of `fsmount`.
pub const FSMOUNT: u32 = 432;
/// The number of `fspick`.
pub const FSPICK: u32 = 433;
/// The number of `pidfd_open`.
pub const PIDFD_OPEN: u32 = 434;
/// The number of `clone3`.
pub const CLONE3: u32 = 435;
/// The number of `close_range`.
pub const CLOSE_RANGE: u32 = 436;
/// The number of `openat2`.
pub const OPENAT2: u32 = 437;
/// The number of `pidfd_getfd`.
pub const PIDFD_GETFD: u32 = 438;
/// The number of `faccessat2`.
pub const FACCESSAT2: u32 = 439;
/// The number of `process_madvise`.
pub const PROCESS_MADVISE: u32 = 440;
/// The number of `epoll_pwait2`.
pub const EPOLL_PWAIT2: u32 = 441;
/// The number of `mount_setattr`.
pub const MOUNT_SETATTR: u32 = 442;
/// The number of `quotactl_fd`.
pub const QUOTACTL_FD: u32 = 443;
/// The number of `landlock_create_ruleset`.
pub const LANDLOCK_CREATE_RULESET: u32 = 444;
/// The number of `landlock_add_rule`.
pub const LANDLOCK_ADD_RULE: u32 = 445;
/// The number of `landlock_restrict_self`.
pub const LANDLOCK_RESTRICT_SELF: u32 = 446;
/// The number of `memfd_secret`.
pub const MEMFD_SECRET: u32 = 447;
/// The number of `process_mrelease`.
pub const PROCESS_MRELEASE: u32 = 448;
/// The number of `futex_waitv`.
pub const FUTEX_WAITV: u32 = 449;
/// The number of `set_mempolicy_home_node`.
pub const SET_MEMPOLICY_HOME_NODE: u32 = 450;
/// The number of `cachestat`.
pub const CACHESTAT: u32 = 451;
/// The number of `fchmodat2`.
pub const FCHMODAT2: u32 = 452;
/// The number of `map_shadow_stack`.
pub const MAP_SHADOW_STACK: u32 = 453;
/// The number of `futex_wake`.
pub const FUTEX_WAKE: u32 = 454;
/// The number of `futex_wait`.
pub const FUTEX_WAIT: u32 = 455;
/// The number of `futex_requeue`.
pub const FUTEX_REQUEUE: u32 = 456;
/// The number of `statmount`.
pub const STATMOUNT: u32 = 457;
/// The number of `listmount`.
pub const LISTMOUNT: u32 = 458;
/// The number of `lsm_get_self_attr`.
pub const LSM_GET_SELF_ATTR: u32 = 459;
/// The number of `lsm_set_self_attr`.
pub const LSM_SET_SELF_ATTR: u32 = 460;
/// The number of `lsm_list_modules`.
pub const LSM_LIST_MODULES: u32 = 461;
/// The number of `mseal`.
pub const MSEAL: u32 = 462;
/// The number of `setxattrat`.
pub const SETXATTRAT: u32 = 463;
/// The number of `getxattrat`.
pub const GETXATTRAT: u32 = 464;
/// The number of `listxattrat`.
pub const LISTXATTRAT: u32 = 465;
/// The number of `removexattrat`.
pub const REMOVEXATTRAT: u32 = 466;
/// The number of `open_tree_attr`.
pub const OPEN_TREE_ATTR: u32 = 467;
/// The number of `file_getattr`.
pub const FILE_GETATTR: u32 = 468;
/// The number of `file_setattr`.
pub const FILE_SETATTR: u32 = 469;
/// The number of `listns`.
pub const LISTNS: u32 = 470;
/// The number of `rseq_slice_yield`.
pub const RSEQ_SLICE_YIELD: u32 = 471;
/// The number of `fchroot`.
pub const FCHROOT: u32 = 472;

/// The name of each system call number. A number with no entry point in Linux is `None`.
pub static SYSCALLS: [Option<&str>; NR_SYSCALLS] = [
    Some("io_setup"),                // 0
    Some("io_destroy"),              // 1
    Some("io_submit"),               // 2
    Some("io_cancel"),               // 3
    Some("io_getevents"),            // 4
    Some("setxattr"),                // 5
    Some("lsetxattr"),               // 6
    Some("fsetxattr"),               // 7
    Some("getxattr"),                // 8
    Some("lgetxattr"),               // 9
    Some("fgetxattr"),               // 10
    Some("listxattr"),               // 11
    Some("llistxattr"),              // 12
    Some("flistxattr"),              // 13
    Some("removexattr"),             // 14
    Some("lremovexattr"),            // 15
    Some("fremovexattr"),            // 16
    Some("getcwd"),                  // 17
    Some("lookup_dcookie"),          // 18
    Some("eventfd2"),                // 19
    Some("epoll_create1"),           // 20
    Some("epoll_ctl"),               // 21
    Some("epoll_pwait"),             // 22
    Some("dup"),                     // 23
    Some("dup3"),                    // 24
    Some("fcntl"),                   // 25
    Some("inotify_init1"),           // 26
    Some("inotify_add_watch"),       // 27
    Some("inotify_rm_watch"),        // 28
    Some("ioctl"),                   // 29
    Some("ioprio_set"),              // 30
    Some("ioprio_get"),              // 31
    Some("flock"),                   // 32
    Some("mknodat"),                 // 33
    Some("mkdirat"),                 // 34
    Some("unlinkat"),                // 35
    Some("symlinkat"),               // 36
    Some("linkat"),                  // 37
    None,                            // 38
    Some("umount2"),                 // 39
    Some("mount"),                   // 40
    Some("pivot_root"),              // 41
    Some("nfsservctl"),              // 42
    Some("statfs"),                  // 43
    Some("fstatfs"),                 // 44
    Some("truncate"),                // 45
    Some("ftruncate"),               // 46
    Some("fallocate"),               // 47
    Some("faccessat"),               // 48
    Some("chdir"),                   // 49
    Some("fchdir"),                  // 50
    Some("chroot"),                  // 51
    Some("fchmod"),                  // 52
    Some("fchmodat"),                // 53
    Some("fchownat"),                // 54
    Some("fchown"),                  // 55
    Some("openat"),                  // 56
    Some("close"),                   // 57
    Some("vhangup"),                 // 58
    Some("pipe2"),                   // 59
    Some("quotactl"),                // 60
    Some("getdents64"),              // 61
    Some("lseek"),                   // 62
    Some("read"),                    // 63
    Some("write"),                   // 64
    Some("readv"),                   // 65
    Some("writev"),                  // 66
    Some("pread64"),                 // 67
    Some("pwrite64"),                // 68
    Some("preadv"),                  // 69
    Some("pwritev"),                 // 70
    Some("sendfile"),                // 71
    Some("pselect6"),                // 72
    Some("ppoll"),                   // 73
    Some("signalfd4"),               // 74
    Some("vmsplice"),                // 75
    Some("splice"),                  // 76
    Some("tee"),                     // 77
    Some("readlinkat"),              // 78
    Some("newfstatat"),              // 79
    Some("fstat"),                   // 80
    Some("sync"),                    // 81
    Some("fsync"),                   // 82
    Some("fdatasync"),               // 83
    Some("sync_file_range"),         // 84
    Some("timerfd_create"),          // 85
    Some("timerfd_settime"),         // 86
    Some("timerfd_gettime"),         // 87
    Some("utimensat"),               // 88
    Some("acct"),                    // 89
    Some("capget"),                  // 90
    Some("capset"),                  // 91
    Some("personality"),             // 92
    Some("exit"),                    // 93
    Some("exit_group"),              // 94
    Some("waitid"),                  // 95
    Some("set_tid_address"),         // 96
    Some("unshare"),                 // 97
    Some("futex"),                   // 98
    Some("set_robust_list"),         // 99
    Some("get_robust_list"),         // 100
    Some("nanosleep"),               // 101
    Some("getitimer"),               // 102
    Some("setitimer"),               // 103
    Some("kexec_load"),              // 104
    Some("init_module"),             // 105
    Some("delete_module"),           // 106
    Some("timer_create"),            // 107
    Some("timer_gettime"),           // 108
    Some("timer_getoverrun"),        // 109
    Some("timer_settime"),           // 110
    Some("timer_delete"),            // 111
    Some("clock_settime"),           // 112
    Some("clock_gettime"),           // 113
    Some("clock_getres"),            // 114
    Some("clock_nanosleep"),         // 115
    Some("syslog"),                  // 116
    Some("ptrace"),                  // 117
    Some("sched_setparam"),          // 118
    Some("sched_setscheduler"),      // 119
    Some("sched_getscheduler"),      // 120
    Some("sched_getparam"),          // 121
    Some("sched_setaffinity"),       // 122
    Some("sched_getaffinity"),       // 123
    Some("sched_yield"),             // 124
    Some("sched_get_priority_max"),  // 125
    Some("sched_get_priority_min"),  // 126
    Some("sched_rr_get_interval"),   // 127
    Some("restart_syscall"),         // 128
    Some("kill"),                    // 129
    Some("tkill"),                   // 130
    Some("tgkill"),                  // 131
    Some("sigaltstack"),             // 132
    Some("rt_sigsuspend"),           // 133
    Some("rt_sigaction"),            // 134
    Some("rt_sigprocmask"),          // 135
    Some("rt_sigpending"),           // 136
    Some("rt_sigtimedwait"),         // 137
    Some("rt_sigqueueinfo"),         // 138
    Some("rt_sigreturn"),            // 139
    Some("setpriority"),             // 140
    Some("getpriority"),             // 141
    Some("reboot"),                  // 142
    Some("setregid"),                // 143
    Some("setgid"),                  // 144
    Some("setreuid"),                // 145
    Some("setuid"),                  // 146
    Some("setresuid"),               // 147
    Some("getresuid"),               // 148
    Some("setresgid"),               // 149
    Some("getresgid"),               // 150
    Some("setfsuid"),                // 151
    Some("setfsgid"),                // 152
    Some("times"),                   // 153
    Some("setpgid"),                 // 154
    Some("getpgid"),                 // 155
    Some("getsid"),                  // 156
    Some("setsid"),                  // 157
    Some("getgroups"),               // 158
    Some("setgroups"),               // 159
    Some("uname"),                   // 160
    Some("sethostname"),             // 161
    Some("setdomainname"),           // 162
    Some("getrlimit"),               // 163
    Some("setrlimit"),               // 164
    Some("getrusage"),               // 165
    Some("umask"),                   // 166
    Some("prctl"),                   // 167
    Some("getcpu"),                  // 168
    Some("gettimeofday"),            // 169
    Some("settimeofday"),            // 170
    Some("adjtimex"),                // 171
    Some("getpid"),                  // 172
    Some("getppid"),                 // 173
    Some("getuid"),                  // 174
    Some("geteuid"),                 // 175
    Some("getgid"),                  // 176
    Some("getegid"),                 // 177
    Some("gettid"),                  // 178
    Some("sysinfo"),                 // 179
    Some("mq_open"),                 // 180
    Some("mq_unlink"),               // 181
    Some("mq_timedsend"),            // 182
    Some("mq_timedreceive"),         // 183
    Some("mq_notify"),               // 184
    Some("mq_getsetattr"),           // 185
    Some("msgget"),                  // 186
    Some("msgctl"),                  // 187
    Some("msgrcv"),                  // 188
    Some("msgsnd"),                  // 189
    Some("semget"),                  // 190
    Some("semctl"),                  // 191
    Some("semtimedop"),              // 192
    Some("semop"),                   // 193
    Some("shmget"),                  // 194
    Some("shmctl"),                  // 195
    Some("shmat"),                   // 196
    Some("shmdt"),                   // 197
    Some("socket"),                  // 198
    Some("socketpair"),              // 199
    Some("bind"),                    // 200
    Some("listen"),                  // 201
    Some("accept"),                  // 202
    Some("connect"),                 // 203
    Some("getsockname"),             // 204
    Some("getpeername"),             // 205
    Some("sendto"),                  // 206
    Some("recvfrom"),                // 207
    Some("setsockopt"),              // 208
    Some("getsockopt"),              // 209
    Some("shutdown"),                // 210
    Some("sendmsg"),                 // 211
    Some("recvmsg"),                 // 212
    Some("readahead"),               // 213
    Some("brk"),                     // 214
    Some("munmap"),                  // 215
    Some("mremap"),                  // 216
    Some("add_key"),                 // 217
    Some("request_key"),             // 218
    Some("keyctl"),                  // 219
    Some("clone"),                   // 220
    Some("execve"),                  // 221
    Some("mmap"),                    // 222
    Some("fadvise64"),               // 223
    Some("swapon"),                  // 224
    Some("swapoff"),                 // 225
    Some("mprotect"),                // 226
    Some("msync"),                   // 227
    Some("mlock"),                   // 228
    Some("munlock"),                 // 229
    Some("mlockall"),                // 230
    Some("munlockall"),              // 231
    Some("mincore"),                 // 232
    Some("madvise"),                 // 233
    Some("remap_file_pages"),        // 234
    Some("mbind"),                   // 235
    Some("get_mempolicy"),           // 236
    Some("set_mempolicy"),           // 237
    Some("migrate_pages"),           // 238
    Some("move_pages"),              // 239
    Some("rt_tgsigqueueinfo"),       // 240
    Some("perf_event_open"),         // 241
    Some("accept4"),                 // 242
    Some("recvmmsg"),                // 243
    None,                            // 244
    None,                            // 245
    None,                            // 246
    None,                            // 247
    None,                            // 248
    None,                            // 249
    None,                            // 250
    None,                            // 251
    None,                            // 252
    None,                            // 253
    None,                            // 254
    None,                            // 255
    None,                            // 256
    None,                            // 257
    Some("riscv_hwprobe"),           // 258
    Some("riscv_flush_icache"),      // 259
    Some("wait4"),                   // 260
    Some("prlimit64"),               // 261
    Some("fanotify_init"),           // 262
    Some("fanotify_mark"),           // 263
    Some("name_to_handle_at"),       // 264
    Some("open_by_handle_at"),       // 265
    Some("clock_adjtime"),           // 266
    Some("syncfs"),                  // 267
    Some("setns"),                   // 268
    Some("sendmmsg"),                // 269
    Some("process_vm_readv"),        // 270
    Some("process_vm_writev"),       // 271
    Some("kcmp"),                    // 272
    Some("finit_module"),            // 273
    Some("sched_setattr"),           // 274
    Some("sched_getattr"),           // 275
    Some("renameat2"),               // 276
    Some("seccomp"),                 // 277
    Some("getrandom"),               // 278
    Some("memfd_create"),            // 279
    Some("bpf"),                     // 280
    Some("execveat"),                // 281
    Some("userfaultfd"),             // 282
    Some("membarrier"),              // 283
    Some("mlock2"),                  // 284
    Some("copy_file_range"),         // 285
    Some("preadv2"),                 // 286
    Some("pwritev2"),                // 287
    Some("pkey_mprotect"),           // 288
    Some("pkey_alloc"),              // 289
    Some("pkey_free"),               // 290
    Some("statx"),                   // 291
    Some("io_pgetevents"),           // 292
    Some("rseq"),                    // 293
    Some("kexec_file_load"),         // 294
    None,                            // 295
    None,                            // 296
    None,                            // 297
    None,                            // 298
    None,                            // 299
    None,                            // 300
    None,                            // 301
    None,                            // 302
    None,                            // 303
    None,                            // 304
    None,                            // 305
    None,                            // 306
    None,                            // 307
    None,                            // 308
    None,                            // 309
    None,                            // 310
    None,                            // 311
    None,                            // 312
    None,                            // 313
    None,                            // 314
    None,                            // 315
    None,                            // 316
    None,                            // 317
    None,                            // 318
    None,                            // 319
    None,                            // 320
    None,                            // 321
    None,                            // 322
    None,                            // 323
    None,                            // 324
    None,                            // 325
    None,                            // 326
    None,                            // 327
    None,                            // 328
    None,                            // 329
    None,                            // 330
    None,                            // 331
    None,                            // 332
    None,                            // 333
    None,                            // 334
    None,                            // 335
    None,                            // 336
    None,                            // 337
    None,                            // 338
    None,                            // 339
    None,                            // 340
    None,                            // 341
    None,                            // 342
    None,                            // 343
    None,                            // 344
    None,                            // 345
    None,                            // 346
    None,                            // 347
    None,                            // 348
    None,                            // 349
    None,                            // 350
    None,                            // 351
    None,                            // 352
    None,                            // 353
    None,                            // 354
    None,                            // 355
    None,                            // 356
    None,                            // 357
    None,                            // 358
    None,                            // 359
    None,                            // 360
    None,                            // 361
    None,                            // 362
    None,                            // 363
    None,                            // 364
    None,                            // 365
    None,                            // 366
    None,                            // 367
    None,                            // 368
    None,                            // 369
    None,                            // 370
    None,                            // 371
    None,                            // 372
    None,                            // 373
    None,                            // 374
    None,                            // 375
    None,                            // 376
    None,                            // 377
    None,                            // 378
    None,                            // 379
    None,                            // 380
    None,                            // 381
    None,                            // 382
    None,                            // 383
    None,                            // 384
    None,                            // 385
    None,                            // 386
    None,                            // 387
    None,                            // 388
    None,                            // 389
    None,                            // 390
    None,                            // 391
    None,                            // 392
    None,                            // 393
    None,                            // 394
    None,                            // 395
    None,                            // 396
    None,                            // 397
    None,                            // 398
    None,                            // 399
    None,                            // 400
    None,                            // 401
    None,                            // 402
    None,                            // 403
    None,                            // 404
    None,                            // 405
    None,                            // 406
    None,                            // 407
    None,                            // 408
    None,                            // 409
    None,                            // 410
    None,                            // 411
    None,                            // 412
    None,                            // 413
    None,                            // 414
    None,                            // 415
    None,                            // 416
    None,                            // 417
    None,                            // 418
    None,                            // 419
    None,                            // 420
    None,                            // 421
    None,                            // 422
    None,                            // 423
    Some("pidfd_send_signal"),       // 424
    Some("io_uring_setup"),          // 425
    Some("io_uring_enter"),          // 426
    Some("io_uring_register"),       // 427
    Some("open_tree"),               // 428
    Some("move_mount"),              // 429
    Some("fsopen"),                  // 430
    Some("fsconfig"),                // 431
    Some("fsmount"),                 // 432
    Some("fspick"),                  // 433
    Some("pidfd_open"),              // 434
    Some("clone3"),                  // 435
    Some("close_range"),             // 436
    Some("openat2"),                 // 437
    Some("pidfd_getfd"),             // 438
    Some("faccessat2"),              // 439
    Some("process_madvise"),         // 440
    Some("epoll_pwait2"),            // 441
    Some("mount_setattr"),           // 442
    Some("quotactl_fd"),             // 443
    Some("landlock_create_ruleset"), // 444
    Some("landlock_add_rule"),       // 445
    Some("landlock_restrict_self"),  // 446
    Some("memfd_secret"),            // 447
    Some("process_mrelease"),        // 448
    Some("futex_waitv"),             // 449
    Some("set_mempolicy_home_node"), // 450
    Some("cachestat"),               // 451
    Some("fchmodat2"),               // 452
    Some("map_shadow_stack"),        // 453
    Some("futex_wake"),              // 454
    Some("futex_wait"),              // 455
    Some("futex_requeue"),           // 456
    Some("statmount"),               // 457
    Some("listmount"),               // 458
    Some("lsm_get_self_attr"),       // 459
    Some("lsm_set_self_attr"),       // 460
    Some("lsm_list_modules"),        // 461
    Some("mseal"),                   // 462
    Some("setxattrat"),              // 463
    Some("getxattrat"),              // 464
    Some("listxattrat"),             // 465
    Some("removexattrat"),           // 466
    Some("open_tree_attr"),          // 467
    Some("file_getattr"),            // 468
    Some("file_setattr"),            // 469
    Some("listns"),                  // 470
    Some("rseq_slice_yield"),        // 471
    Some("fchroot"),                 // 472
];

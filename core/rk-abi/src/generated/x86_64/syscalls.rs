// rk-abigen generated this file from Linux 7.3, from arch/x86/entry/syscalls/syscall_64.tbl.
// Do not edit it. Change rk-abigen and run it again.

//! The system call numbers of x86_64 in Linux.
//!
//! The table uses the lines of the ABIs common, 64.

/// The highest system call number plus one.
pub const NR_SYSCALLS: usize = 473;
/// The number of `read`.
pub const READ: u32 = 0;
/// The number of `write`.
pub const WRITE: u32 = 1;
/// The number of `open`.
pub const OPEN: u32 = 2;
/// The number of `close`.
pub const CLOSE: u32 = 3;
/// The number of `stat`.
pub const STAT: u32 = 4;
/// The number of `fstat`.
pub const FSTAT: u32 = 5;
/// The number of `lstat`.
pub const LSTAT: u32 = 6;
/// The number of `poll`.
pub const POLL: u32 = 7;
/// The number of `lseek`.
pub const LSEEK: u32 = 8;
/// The number of `mmap`.
pub const MMAP: u32 = 9;
/// The number of `mprotect`.
pub const MPROTECT: u32 = 10;
/// The number of `munmap`.
pub const MUNMAP: u32 = 11;
/// The number of `brk`.
pub const BRK: u32 = 12;
/// The number of `rt_sigaction`.
pub const RT_SIGACTION: u32 = 13;
/// The number of `rt_sigprocmask`.
pub const RT_SIGPROCMASK: u32 = 14;
/// The number of `rt_sigreturn`.
pub const RT_SIGRETURN: u32 = 15;
/// The number of `ioctl`.
pub const IOCTL: u32 = 16;
/// The number of `pread64`.
pub const PREAD64: u32 = 17;
/// The number of `pwrite64`.
pub const PWRITE64: u32 = 18;
/// The number of `readv`.
pub const READV: u32 = 19;
/// The number of `writev`.
pub const WRITEV: u32 = 20;
/// The number of `access`.
pub const ACCESS: u32 = 21;
/// The number of `pipe`.
pub const PIPE: u32 = 22;
/// The number of `select`.
pub const SELECT: u32 = 23;
/// The number of `sched_yield`.
pub const SCHED_YIELD: u32 = 24;
/// The number of `mremap`.
pub const MREMAP: u32 = 25;
/// The number of `msync`.
pub const MSYNC: u32 = 26;
/// The number of `mincore`.
pub const MINCORE: u32 = 27;
/// The number of `madvise`.
pub const MADVISE: u32 = 28;
/// The number of `shmget`.
pub const SHMGET: u32 = 29;
/// The number of `shmat`.
pub const SHMAT: u32 = 30;
/// The number of `shmctl`.
pub const SHMCTL: u32 = 31;
/// The number of `dup`.
pub const DUP: u32 = 32;
/// The number of `dup2`.
pub const DUP2: u32 = 33;
/// The number of `pause`.
pub const PAUSE: u32 = 34;
/// The number of `nanosleep`.
pub const NANOSLEEP: u32 = 35;
/// The number of `getitimer`.
pub const GETITIMER: u32 = 36;
/// The number of `alarm`.
pub const ALARM: u32 = 37;
/// The number of `setitimer`.
pub const SETITIMER: u32 = 38;
/// The number of `getpid`.
pub const GETPID: u32 = 39;
/// The number of `sendfile`.
pub const SENDFILE: u32 = 40;
/// The number of `socket`.
pub const SOCKET: u32 = 41;
/// The number of `connect`.
pub const CONNECT: u32 = 42;
/// The number of `accept`.
pub const ACCEPT: u32 = 43;
/// The number of `sendto`.
pub const SENDTO: u32 = 44;
/// The number of `recvfrom`.
pub const RECVFROM: u32 = 45;
/// The number of `sendmsg`.
pub const SENDMSG: u32 = 46;
/// The number of `recvmsg`.
pub const RECVMSG: u32 = 47;
/// The number of `shutdown`.
pub const SHUTDOWN: u32 = 48;
/// The number of `bind`.
pub const BIND: u32 = 49;
/// The number of `listen`.
pub const LISTEN: u32 = 50;
/// The number of `getsockname`.
pub const GETSOCKNAME: u32 = 51;
/// The number of `getpeername`.
pub const GETPEERNAME: u32 = 52;
/// The number of `socketpair`.
pub const SOCKETPAIR: u32 = 53;
/// The number of `setsockopt`.
pub const SETSOCKOPT: u32 = 54;
/// The number of `getsockopt`.
pub const GETSOCKOPT: u32 = 55;
/// The number of `clone`.
pub const CLONE: u32 = 56;
/// The number of `fork`.
pub const FORK: u32 = 57;
/// The number of `vfork`.
pub const VFORK: u32 = 58;
/// The number of `execve`.
pub const EXECVE: u32 = 59;
/// The number of `exit`.
pub const EXIT: u32 = 60;
/// The number of `wait4`.
pub const WAIT4: u32 = 61;
/// The number of `kill`.
pub const KILL: u32 = 62;
/// The number of `uname`.
pub const UNAME: u32 = 63;
/// The number of `semget`.
pub const SEMGET: u32 = 64;
/// The number of `semop`.
pub const SEMOP: u32 = 65;
/// The number of `semctl`.
pub const SEMCTL: u32 = 66;
/// The number of `shmdt`.
pub const SHMDT: u32 = 67;
/// The number of `msgget`.
pub const MSGGET: u32 = 68;
/// The number of `msgsnd`.
pub const MSGSND: u32 = 69;
/// The number of `msgrcv`.
pub const MSGRCV: u32 = 70;
/// The number of `msgctl`.
pub const MSGCTL: u32 = 71;
/// The number of `fcntl`.
pub const FCNTL: u32 = 72;
/// The number of `flock`.
pub const FLOCK: u32 = 73;
/// The number of `fsync`.
pub const FSYNC: u32 = 74;
/// The number of `fdatasync`.
pub const FDATASYNC: u32 = 75;
/// The number of `truncate`.
pub const TRUNCATE: u32 = 76;
/// The number of `ftruncate`.
pub const FTRUNCATE: u32 = 77;
/// The number of `getdents`.
pub const GETDENTS: u32 = 78;
/// The number of `getcwd`.
pub const GETCWD: u32 = 79;
/// The number of `chdir`.
pub const CHDIR: u32 = 80;
/// The number of `fchdir`.
pub const FCHDIR: u32 = 81;
/// The number of `rename`.
pub const RENAME: u32 = 82;
/// The number of `mkdir`.
pub const MKDIR: u32 = 83;
/// The number of `rmdir`.
pub const RMDIR: u32 = 84;
/// The number of `creat`.
pub const CREAT: u32 = 85;
/// The number of `link`.
pub const LINK: u32 = 86;
/// The number of `unlink`.
pub const UNLINK: u32 = 87;
/// The number of `symlink`.
pub const SYMLINK: u32 = 88;
/// The number of `readlink`.
pub const READLINK: u32 = 89;
/// The number of `chmod`.
pub const CHMOD: u32 = 90;
/// The number of `fchmod`.
pub const FCHMOD: u32 = 91;
/// The number of `chown`.
pub const CHOWN: u32 = 92;
/// The number of `fchown`.
pub const FCHOWN: u32 = 93;
/// The number of `lchown`.
pub const LCHOWN: u32 = 94;
/// The number of `umask`.
pub const UMASK: u32 = 95;
/// The number of `gettimeofday`.
pub const GETTIMEOFDAY: u32 = 96;
/// The number of `getrlimit`.
pub const GETRLIMIT: u32 = 97;
/// The number of `getrusage`.
pub const GETRUSAGE: u32 = 98;
/// The number of `sysinfo`.
pub const SYSINFO: u32 = 99;
/// The number of `times`.
pub const TIMES: u32 = 100;
/// The number of `ptrace`.
pub const PTRACE: u32 = 101;
/// The number of `getuid`.
pub const GETUID: u32 = 102;
/// The number of `syslog`.
pub const SYSLOG: u32 = 103;
/// The number of `getgid`.
pub const GETGID: u32 = 104;
/// The number of `setuid`.
pub const SETUID: u32 = 105;
/// The number of `setgid`.
pub const SETGID: u32 = 106;
/// The number of `geteuid`.
pub const GETEUID: u32 = 107;
/// The number of `getegid`.
pub const GETEGID: u32 = 108;
/// The number of `setpgid`.
pub const SETPGID: u32 = 109;
/// The number of `getppid`.
pub const GETPPID: u32 = 110;
/// The number of `getpgrp`.
pub const GETPGRP: u32 = 111;
/// The number of `setsid`.
pub const SETSID: u32 = 112;
/// The number of `setreuid`.
pub const SETREUID: u32 = 113;
/// The number of `setregid`.
pub const SETREGID: u32 = 114;
/// The number of `getgroups`.
pub const GETGROUPS: u32 = 115;
/// The number of `setgroups`.
pub const SETGROUPS: u32 = 116;
/// The number of `setresuid`.
pub const SETRESUID: u32 = 117;
/// The number of `getresuid`.
pub const GETRESUID: u32 = 118;
/// The number of `setresgid`.
pub const SETRESGID: u32 = 119;
/// The number of `getresgid`.
pub const GETRESGID: u32 = 120;
/// The number of `getpgid`.
pub const GETPGID: u32 = 121;
/// The number of `setfsuid`.
pub const SETFSUID: u32 = 122;
/// The number of `setfsgid`.
pub const SETFSGID: u32 = 123;
/// The number of `getsid`.
pub const GETSID: u32 = 124;
/// The number of `capget`.
pub const CAPGET: u32 = 125;
/// The number of `capset`.
pub const CAPSET: u32 = 126;
/// The number of `rt_sigpending`.
pub const RT_SIGPENDING: u32 = 127;
/// The number of `rt_sigtimedwait`.
pub const RT_SIGTIMEDWAIT: u32 = 128;
/// The number of `rt_sigqueueinfo`.
pub const RT_SIGQUEUEINFO: u32 = 129;
/// The number of `rt_sigsuspend`.
pub const RT_SIGSUSPEND: u32 = 130;
/// The number of `sigaltstack`.
pub const SIGALTSTACK: u32 = 131;
/// The number of `utime`.
pub const UTIME: u32 = 132;
/// The number of `mknod`.
pub const MKNOD: u32 = 133;
/// The number of `uselib`. Linux has no entry point for this number.
pub const USELIB: u32 = 134;
/// The number of `personality`.
pub const PERSONALITY: u32 = 135;
/// The number of `ustat`.
pub const USTAT: u32 = 136;
/// The number of `statfs`.
pub const STATFS: u32 = 137;
/// The number of `fstatfs`.
pub const FSTATFS: u32 = 138;
/// The number of `sysfs`.
pub const SYSFS: u32 = 139;
/// The number of `getpriority`.
pub const GETPRIORITY: u32 = 140;
/// The number of `setpriority`.
pub const SETPRIORITY: u32 = 141;
/// The number of `sched_setparam`.
pub const SCHED_SETPARAM: u32 = 142;
/// The number of `sched_getparam`.
pub const SCHED_GETPARAM: u32 = 143;
/// The number of `sched_setscheduler`.
pub const SCHED_SETSCHEDULER: u32 = 144;
/// The number of `sched_getscheduler`.
pub const SCHED_GETSCHEDULER: u32 = 145;
/// The number of `sched_get_priority_max`.
pub const SCHED_GET_PRIORITY_MAX: u32 = 146;
/// The number of `sched_get_priority_min`.
pub const SCHED_GET_PRIORITY_MIN: u32 = 147;
/// The number of `sched_rr_get_interval`.
pub const SCHED_RR_GET_INTERVAL: u32 = 148;
/// The number of `mlock`.
pub const MLOCK: u32 = 149;
/// The number of `munlock`.
pub const MUNLOCK: u32 = 150;
/// The number of `mlockall`.
pub const MLOCKALL: u32 = 151;
/// The number of `munlockall`.
pub const MUNLOCKALL: u32 = 152;
/// The number of `vhangup`.
pub const VHANGUP: u32 = 153;
/// The number of `modify_ldt`.
pub const MODIFY_LDT: u32 = 154;
/// The number of `pivot_root`.
pub const PIVOT_ROOT: u32 = 155;
/// The number of `_sysctl`.
pub const _SYSCTL: u32 = 156;
/// The number of `prctl`.
pub const PRCTL: u32 = 157;
/// The number of `arch_prctl`.
pub const ARCH_PRCTL: u32 = 158;
/// The number of `adjtimex`.
pub const ADJTIMEX: u32 = 159;
/// The number of `setrlimit`.
pub const SETRLIMIT: u32 = 160;
/// The number of `chroot`.
pub const CHROOT: u32 = 161;
/// The number of `sync`.
pub const SYNC: u32 = 162;
/// The number of `acct`.
pub const ACCT: u32 = 163;
/// The number of `settimeofday`.
pub const SETTIMEOFDAY: u32 = 164;
/// The number of `mount`.
pub const MOUNT: u32 = 165;
/// The number of `umount2`.
pub const UMOUNT2: u32 = 166;
/// The number of `swapon`.
pub const SWAPON: u32 = 167;
/// The number of `swapoff`.
pub const SWAPOFF: u32 = 168;
/// The number of `reboot`.
pub const REBOOT: u32 = 169;
/// The number of `sethostname`.
pub const SETHOSTNAME: u32 = 170;
/// The number of `setdomainname`.
pub const SETDOMAINNAME: u32 = 171;
/// The number of `iopl`.
pub const IOPL: u32 = 172;
/// The number of `ioperm`.
pub const IOPERM: u32 = 173;
/// The number of `create_module`. Linux has no entry point for this number.
pub const CREATE_MODULE: u32 = 174;
/// The number of `init_module`.
pub const INIT_MODULE: u32 = 175;
/// The number of `delete_module`.
pub const DELETE_MODULE: u32 = 176;
/// The number of `get_kernel_syms`. Linux has no entry point for this number.
pub const GET_KERNEL_SYMS: u32 = 177;
/// The number of `query_module`. Linux has no entry point for this number.
pub const QUERY_MODULE: u32 = 178;
/// The number of `quotactl`.
pub const QUOTACTL: u32 = 179;
/// The number of `nfsservctl`. Linux has no entry point for this number.
pub const NFSSERVCTL: u32 = 180;
/// The number of `getpmsg`. Linux has no entry point for this number.
pub const GETPMSG: u32 = 181;
/// The number of `putpmsg`. Linux has no entry point for this number.
pub const PUTPMSG: u32 = 182;
/// The number of `afs_syscall`. Linux has no entry point for this number.
pub const AFS_SYSCALL: u32 = 183;
/// The number of `tuxcall`. Linux has no entry point for this number.
pub const TUXCALL: u32 = 184;
/// The number of `security`. Linux has no entry point for this number.
pub const SECURITY: u32 = 185;
/// The number of `gettid`.
pub const GETTID: u32 = 186;
/// The number of `readahead`.
pub const READAHEAD: u32 = 187;
/// The number of `setxattr`.
pub const SETXATTR: u32 = 188;
/// The number of `lsetxattr`.
pub const LSETXATTR: u32 = 189;
/// The number of `fsetxattr`.
pub const FSETXATTR: u32 = 190;
/// The number of `getxattr`.
pub const GETXATTR: u32 = 191;
/// The number of `lgetxattr`.
pub const LGETXATTR: u32 = 192;
/// The number of `fgetxattr`.
pub const FGETXATTR: u32 = 193;
/// The number of `listxattr`.
pub const LISTXATTR: u32 = 194;
/// The number of `llistxattr`.
pub const LLISTXATTR: u32 = 195;
/// The number of `flistxattr`.
pub const FLISTXATTR: u32 = 196;
/// The number of `removexattr`.
pub const REMOVEXATTR: u32 = 197;
/// The number of `lremovexattr`.
pub const LREMOVEXATTR: u32 = 198;
/// The number of `fremovexattr`.
pub const FREMOVEXATTR: u32 = 199;
/// The number of `tkill`.
pub const TKILL: u32 = 200;
/// The number of `time`.
pub const TIME: u32 = 201;
/// The number of `futex`.
pub const FUTEX: u32 = 202;
/// The number of `sched_setaffinity`.
pub const SCHED_SETAFFINITY: u32 = 203;
/// The number of `sched_getaffinity`.
pub const SCHED_GETAFFINITY: u32 = 204;
/// The number of `set_thread_area`. Linux has no entry point for this number.
pub const SET_THREAD_AREA: u32 = 205;
/// The number of `io_setup`.
pub const IO_SETUP: u32 = 206;
/// The number of `io_destroy`.
pub const IO_DESTROY: u32 = 207;
/// The number of `io_getevents`.
pub const IO_GETEVENTS: u32 = 208;
/// The number of `io_submit`.
pub const IO_SUBMIT: u32 = 209;
/// The number of `io_cancel`.
pub const IO_CANCEL: u32 = 210;
/// The number of `get_thread_area`. Linux has no entry point for this number.
pub const GET_THREAD_AREA: u32 = 211;
/// The number of `lookup_dcookie`. Linux has no entry point for this number.
pub const LOOKUP_DCOOKIE: u32 = 212;
/// The number of `epoll_create`.
pub const EPOLL_CREATE: u32 = 213;
/// The number of `epoll_ctl_old`. Linux has no entry point for this number.
pub const EPOLL_CTL_OLD: u32 = 214;
/// The number of `epoll_wait_old`. Linux has no entry point for this number.
pub const EPOLL_WAIT_OLD: u32 = 215;
/// The number of `remap_file_pages`.
pub const REMAP_FILE_PAGES: u32 = 216;
/// The number of `getdents64`.
pub const GETDENTS64: u32 = 217;
/// The number of `set_tid_address`.
pub const SET_TID_ADDRESS: u32 = 218;
/// The number of `restart_syscall`.
pub const RESTART_SYSCALL: u32 = 219;
/// The number of `semtimedop`.
pub const SEMTIMEDOP: u32 = 220;
/// The number of `fadvise64`.
pub const FADVISE64: u32 = 221;
/// The number of `timer_create`.
pub const TIMER_CREATE: u32 = 222;
/// The number of `timer_settime`.
pub const TIMER_SETTIME: u32 = 223;
/// The number of `timer_gettime`.
pub const TIMER_GETTIME: u32 = 224;
/// The number of `timer_getoverrun`.
pub const TIMER_GETOVERRUN: u32 = 225;
/// The number of `timer_delete`.
pub const TIMER_DELETE: u32 = 226;
/// The number of `clock_settime`.
pub const CLOCK_SETTIME: u32 = 227;
/// The number of `clock_gettime`.
pub const CLOCK_GETTIME: u32 = 228;
/// The number of `clock_getres`.
pub const CLOCK_GETRES: u32 = 229;
/// The number of `clock_nanosleep`.
pub const CLOCK_NANOSLEEP: u32 = 230;
/// The number of `exit_group`.
pub const EXIT_GROUP: u32 = 231;
/// The number of `epoll_wait`.
pub const EPOLL_WAIT: u32 = 232;
/// The number of `epoll_ctl`.
pub const EPOLL_CTL: u32 = 233;
/// The number of `tgkill`.
pub const TGKILL: u32 = 234;
/// The number of `utimes`.
pub const UTIMES: u32 = 235;
/// The number of `vserver`. Linux has no entry point for this number.
pub const VSERVER: u32 = 236;
/// The number of `mbind`.
pub const MBIND: u32 = 237;
/// The number of `set_mempolicy`.
pub const SET_MEMPOLICY: u32 = 238;
/// The number of `get_mempolicy`.
pub const GET_MEMPOLICY: u32 = 239;
/// The number of `mq_open`.
pub const MQ_OPEN: u32 = 240;
/// The number of `mq_unlink`.
pub const MQ_UNLINK: u32 = 241;
/// The number of `mq_timedsend`.
pub const MQ_TIMEDSEND: u32 = 242;
/// The number of `mq_timedreceive`.
pub const MQ_TIMEDRECEIVE: u32 = 243;
/// The number of `mq_notify`.
pub const MQ_NOTIFY: u32 = 244;
/// The number of `mq_getsetattr`.
pub const MQ_GETSETATTR: u32 = 245;
/// The number of `kexec_load`.
pub const KEXEC_LOAD: u32 = 246;
/// The number of `waitid`.
pub const WAITID: u32 = 247;
/// The number of `add_key`.
pub const ADD_KEY: u32 = 248;
/// The number of `request_key`.
pub const REQUEST_KEY: u32 = 249;
/// The number of `keyctl`.
pub const KEYCTL: u32 = 250;
/// The number of `ioprio_set`.
pub const IOPRIO_SET: u32 = 251;
/// The number of `ioprio_get`.
pub const IOPRIO_GET: u32 = 252;
/// The number of `inotify_init`.
pub const INOTIFY_INIT: u32 = 253;
/// The number of `inotify_add_watch`.
pub const INOTIFY_ADD_WATCH: u32 = 254;
/// The number of `inotify_rm_watch`.
pub const INOTIFY_RM_WATCH: u32 = 255;
/// The number of `migrate_pages`.
pub const MIGRATE_PAGES: u32 = 256;
/// The number of `openat`.
pub const OPENAT: u32 = 257;
/// The number of `mkdirat`.
pub const MKDIRAT: u32 = 258;
/// The number of `mknodat`.
pub const MKNODAT: u32 = 259;
/// The number of `fchownat`.
pub const FCHOWNAT: u32 = 260;
/// The number of `futimesat`.
pub const FUTIMESAT: u32 = 261;
/// The number of `newfstatat`.
pub const NEWFSTATAT: u32 = 262;
/// The number of `unlinkat`.
pub const UNLINKAT: u32 = 263;
/// The number of `renameat`.
pub const RENAMEAT: u32 = 264;
/// The number of `linkat`.
pub const LINKAT: u32 = 265;
/// The number of `symlinkat`.
pub const SYMLINKAT: u32 = 266;
/// The number of `readlinkat`.
pub const READLINKAT: u32 = 267;
/// The number of `fchmodat`.
pub const FCHMODAT: u32 = 268;
/// The number of `faccessat`.
pub const FACCESSAT: u32 = 269;
/// The number of `pselect6`.
pub const PSELECT6: u32 = 270;
/// The number of `ppoll`.
pub const PPOLL: u32 = 271;
/// The number of `unshare`.
pub const UNSHARE: u32 = 272;
/// The number of `set_robust_list`.
pub const SET_ROBUST_LIST: u32 = 273;
/// The number of `get_robust_list`.
pub const GET_ROBUST_LIST: u32 = 274;
/// The number of `splice`.
pub const SPLICE: u32 = 275;
/// The number of `tee`.
pub const TEE: u32 = 276;
/// The number of `sync_file_range`.
pub const SYNC_FILE_RANGE: u32 = 277;
/// The number of `vmsplice`.
pub const VMSPLICE: u32 = 278;
/// The number of `move_pages`.
pub const MOVE_PAGES: u32 = 279;
/// The number of `utimensat`.
pub const UTIMENSAT: u32 = 280;
/// The number of `epoll_pwait`.
pub const EPOLL_PWAIT: u32 = 281;
/// The number of `signalfd`.
pub const SIGNALFD: u32 = 282;
/// The number of `timerfd_create`.
pub const TIMERFD_CREATE: u32 = 283;
/// The number of `eventfd`.
pub const EVENTFD: u32 = 284;
/// The number of `fallocate`.
pub const FALLOCATE: u32 = 285;
/// The number of `timerfd_settime`.
pub const TIMERFD_SETTIME: u32 = 286;
/// The number of `timerfd_gettime`.
pub const TIMERFD_GETTIME: u32 = 287;
/// The number of `accept4`.
pub const ACCEPT4: u32 = 288;
/// The number of `signalfd4`.
pub const SIGNALFD4: u32 = 289;
/// The number of `eventfd2`.
pub const EVENTFD2: u32 = 290;
/// The number of `epoll_create1`.
pub const EPOLL_CREATE1: u32 = 291;
/// The number of `dup3`.
pub const DUP3: u32 = 292;
/// The number of `pipe2`.
pub const PIPE2: u32 = 293;
/// The number of `inotify_init1`.
pub const INOTIFY_INIT1: u32 = 294;
/// The number of `preadv`.
pub const PREADV: u32 = 295;
/// The number of `pwritev`.
pub const PWRITEV: u32 = 296;
/// The number of `rt_tgsigqueueinfo`.
pub const RT_TGSIGQUEUEINFO: u32 = 297;
/// The number of `perf_event_open`.
pub const PERF_EVENT_OPEN: u32 = 298;
/// The number of `recvmmsg`.
pub const RECVMMSG: u32 = 299;
/// The number of `fanotify_init`.
pub const FANOTIFY_INIT: u32 = 300;
/// The number of `fanotify_mark`.
pub const FANOTIFY_MARK: u32 = 301;
/// The number of `prlimit64`.
pub const PRLIMIT64: u32 = 302;
/// The number of `name_to_handle_at`.
pub const NAME_TO_HANDLE_AT: u32 = 303;
/// The number of `open_by_handle_at`.
pub const OPEN_BY_HANDLE_AT: u32 = 304;
/// The number of `clock_adjtime`.
pub const CLOCK_ADJTIME: u32 = 305;
/// The number of `syncfs`.
pub const SYNCFS: u32 = 306;
/// The number of `sendmmsg`.
pub const SENDMMSG: u32 = 307;
/// The number of `setns`.
pub const SETNS: u32 = 308;
/// The number of `getcpu`.
pub const GETCPU: u32 = 309;
/// The number of `process_vm_readv`.
pub const PROCESS_VM_READV: u32 = 310;
/// The number of `process_vm_writev`.
pub const PROCESS_VM_WRITEV: u32 = 311;
/// The number of `kcmp`.
pub const KCMP: u32 = 312;
/// The number of `finit_module`.
pub const FINIT_MODULE: u32 = 313;
/// The number of `sched_setattr`.
pub const SCHED_SETATTR: u32 = 314;
/// The number of `sched_getattr`.
pub const SCHED_GETATTR: u32 = 315;
/// The number of `renameat2`.
pub const RENAMEAT2: u32 = 316;
/// The number of `seccomp`.
pub const SECCOMP: u32 = 317;
/// The number of `getrandom`.
pub const GETRANDOM: u32 = 318;
/// The number of `memfd_create`.
pub const MEMFD_CREATE: u32 = 319;
/// The number of `kexec_file_load`.
pub const KEXEC_FILE_LOAD: u32 = 320;
/// The number of `bpf`.
pub const BPF: u32 = 321;
/// The number of `execveat`.
pub const EXECVEAT: u32 = 322;
/// The number of `userfaultfd`.
pub const USERFAULTFD: u32 = 323;
/// The number of `membarrier`.
pub const MEMBARRIER: u32 = 324;
/// The number of `mlock2`.
pub const MLOCK2: u32 = 325;
/// The number of `copy_file_range`.
pub const COPY_FILE_RANGE: u32 = 326;
/// The number of `preadv2`.
pub const PREADV2: u32 = 327;
/// The number of `pwritev2`.
pub const PWRITEV2: u32 = 328;
/// The number of `pkey_mprotect`.
pub const PKEY_MPROTECT: u32 = 329;
/// The number of `pkey_alloc`.
pub const PKEY_ALLOC: u32 = 330;
/// The number of `pkey_free`.
pub const PKEY_FREE: u32 = 331;
/// The number of `statx`.
pub const STATX: u32 = 332;
/// The number of `io_pgetevents`.
pub const IO_PGETEVENTS: u32 = 333;
/// The number of `rseq`.
pub const RSEQ: u32 = 334;
/// The number of `uretprobe`.
pub const URETPROBE: u32 = 335;
/// The number of `uprobe`.
pub const UPROBE: u32 = 336;
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
    Some("read"),                    // 0
    Some("write"),                   // 1
    Some("open"),                    // 2
    Some("close"),                   // 3
    Some("stat"),                    // 4
    Some("fstat"),                   // 5
    Some("lstat"),                   // 6
    Some("poll"),                    // 7
    Some("lseek"),                   // 8
    Some("mmap"),                    // 9
    Some("mprotect"),                // 10
    Some("munmap"),                  // 11
    Some("brk"),                     // 12
    Some("rt_sigaction"),            // 13
    Some("rt_sigprocmask"),          // 14
    Some("rt_sigreturn"),            // 15
    Some("ioctl"),                   // 16
    Some("pread64"),                 // 17
    Some("pwrite64"),                // 18
    Some("readv"),                   // 19
    Some("writev"),                  // 20
    Some("access"),                  // 21
    Some("pipe"),                    // 22
    Some("select"),                  // 23
    Some("sched_yield"),             // 24
    Some("mremap"),                  // 25
    Some("msync"),                   // 26
    Some("mincore"),                 // 27
    Some("madvise"),                 // 28
    Some("shmget"),                  // 29
    Some("shmat"),                   // 30
    Some("shmctl"),                  // 31
    Some("dup"),                     // 32
    Some("dup2"),                    // 33
    Some("pause"),                   // 34
    Some("nanosleep"),               // 35
    Some("getitimer"),               // 36
    Some("alarm"),                   // 37
    Some("setitimer"),               // 38
    Some("getpid"),                  // 39
    Some("sendfile"),                // 40
    Some("socket"),                  // 41
    Some("connect"),                 // 42
    Some("accept"),                  // 43
    Some("sendto"),                  // 44
    Some("recvfrom"),                // 45
    Some("sendmsg"),                 // 46
    Some("recvmsg"),                 // 47
    Some("shutdown"),                // 48
    Some("bind"),                    // 49
    Some("listen"),                  // 50
    Some("getsockname"),             // 51
    Some("getpeername"),             // 52
    Some("socketpair"),              // 53
    Some("setsockopt"),              // 54
    Some("getsockopt"),              // 55
    Some("clone"),                   // 56
    Some("fork"),                    // 57
    Some("vfork"),                   // 58
    Some("execve"),                  // 59
    Some("exit"),                    // 60
    Some("wait4"),                   // 61
    Some("kill"),                    // 62
    Some("uname"),                   // 63
    Some("semget"),                  // 64
    Some("semop"),                   // 65
    Some("semctl"),                  // 66
    Some("shmdt"),                   // 67
    Some("msgget"),                  // 68
    Some("msgsnd"),                  // 69
    Some("msgrcv"),                  // 70
    Some("msgctl"),                  // 71
    Some("fcntl"),                   // 72
    Some("flock"),                   // 73
    Some("fsync"),                   // 74
    Some("fdatasync"),               // 75
    Some("truncate"),                // 76
    Some("ftruncate"),               // 77
    Some("getdents"),                // 78
    Some("getcwd"),                  // 79
    Some("chdir"),                   // 80
    Some("fchdir"),                  // 81
    Some("rename"),                  // 82
    Some("mkdir"),                   // 83
    Some("rmdir"),                   // 84
    Some("creat"),                   // 85
    Some("link"),                    // 86
    Some("unlink"),                  // 87
    Some("symlink"),                 // 88
    Some("readlink"),                // 89
    Some("chmod"),                   // 90
    Some("fchmod"),                  // 91
    Some("chown"),                   // 92
    Some("fchown"),                  // 93
    Some("lchown"),                  // 94
    Some("umask"),                   // 95
    Some("gettimeofday"),            // 96
    Some("getrlimit"),               // 97
    Some("getrusage"),               // 98
    Some("sysinfo"),                 // 99
    Some("times"),                   // 100
    Some("ptrace"),                  // 101
    Some("getuid"),                  // 102
    Some("syslog"),                  // 103
    Some("getgid"),                  // 104
    Some("setuid"),                  // 105
    Some("setgid"),                  // 106
    Some("geteuid"),                 // 107
    Some("getegid"),                 // 108
    Some("setpgid"),                 // 109
    Some("getppid"),                 // 110
    Some("getpgrp"),                 // 111
    Some("setsid"),                  // 112
    Some("setreuid"),                // 113
    Some("setregid"),                // 114
    Some("getgroups"),               // 115
    Some("setgroups"),               // 116
    Some("setresuid"),               // 117
    Some("getresuid"),               // 118
    Some("setresgid"),               // 119
    Some("getresgid"),               // 120
    Some("getpgid"),                 // 121
    Some("setfsuid"),                // 122
    Some("setfsgid"),                // 123
    Some("getsid"),                  // 124
    Some("capget"),                  // 125
    Some("capset"),                  // 126
    Some("rt_sigpending"),           // 127
    Some("rt_sigtimedwait"),         // 128
    Some("rt_sigqueueinfo"),         // 129
    Some("rt_sigsuspend"),           // 130
    Some("sigaltstack"),             // 131
    Some("utime"),                   // 132
    Some("mknod"),                   // 133
    None,                            // 134
    Some("personality"),             // 135
    Some("ustat"),                   // 136
    Some("statfs"),                  // 137
    Some("fstatfs"),                 // 138
    Some("sysfs"),                   // 139
    Some("getpriority"),             // 140
    Some("setpriority"),             // 141
    Some("sched_setparam"),          // 142
    Some("sched_getparam"),          // 143
    Some("sched_setscheduler"),      // 144
    Some("sched_getscheduler"),      // 145
    Some("sched_get_priority_max"),  // 146
    Some("sched_get_priority_min"),  // 147
    Some("sched_rr_get_interval"),   // 148
    Some("mlock"),                   // 149
    Some("munlock"),                 // 150
    Some("mlockall"),                // 151
    Some("munlockall"),              // 152
    Some("vhangup"),                 // 153
    Some("modify_ldt"),              // 154
    Some("pivot_root"),              // 155
    Some("_sysctl"),                 // 156
    Some("prctl"),                   // 157
    Some("arch_prctl"),              // 158
    Some("adjtimex"),                // 159
    Some("setrlimit"),               // 160
    Some("chroot"),                  // 161
    Some("sync"),                    // 162
    Some("acct"),                    // 163
    Some("settimeofday"),            // 164
    Some("mount"),                   // 165
    Some("umount2"),                 // 166
    Some("swapon"),                  // 167
    Some("swapoff"),                 // 168
    Some("reboot"),                  // 169
    Some("sethostname"),             // 170
    Some("setdomainname"),           // 171
    Some("iopl"),                    // 172
    Some("ioperm"),                  // 173
    None,                            // 174
    Some("init_module"),             // 175
    Some("delete_module"),           // 176
    None,                            // 177
    None,                            // 178
    Some("quotactl"),                // 179
    None,                            // 180
    None,                            // 181
    None,                            // 182
    None,                            // 183
    None,                            // 184
    None,                            // 185
    Some("gettid"),                  // 186
    Some("readahead"),               // 187
    Some("setxattr"),                // 188
    Some("lsetxattr"),               // 189
    Some("fsetxattr"),               // 190
    Some("getxattr"),                // 191
    Some("lgetxattr"),               // 192
    Some("fgetxattr"),               // 193
    Some("listxattr"),               // 194
    Some("llistxattr"),              // 195
    Some("flistxattr"),              // 196
    Some("removexattr"),             // 197
    Some("lremovexattr"),            // 198
    Some("fremovexattr"),            // 199
    Some("tkill"),                   // 200
    Some("time"),                    // 201
    Some("futex"),                   // 202
    Some("sched_setaffinity"),       // 203
    Some("sched_getaffinity"),       // 204
    None,                            // 205
    Some("io_setup"),                // 206
    Some("io_destroy"),              // 207
    Some("io_getevents"),            // 208
    Some("io_submit"),               // 209
    Some("io_cancel"),               // 210
    None,                            // 211
    None,                            // 212
    Some("epoll_create"),            // 213
    None,                            // 214
    None,                            // 215
    Some("remap_file_pages"),        // 216
    Some("getdents64"),              // 217
    Some("set_tid_address"),         // 218
    Some("restart_syscall"),         // 219
    Some("semtimedop"),              // 220
    Some("fadvise64"),               // 221
    Some("timer_create"),            // 222
    Some("timer_settime"),           // 223
    Some("timer_gettime"),           // 224
    Some("timer_getoverrun"),        // 225
    Some("timer_delete"),            // 226
    Some("clock_settime"),           // 227
    Some("clock_gettime"),           // 228
    Some("clock_getres"),            // 229
    Some("clock_nanosleep"),         // 230
    Some("exit_group"),              // 231
    Some("epoll_wait"),              // 232
    Some("epoll_ctl"),               // 233
    Some("tgkill"),                  // 234
    Some("utimes"),                  // 235
    None,                            // 236
    Some("mbind"),                   // 237
    Some("set_mempolicy"),           // 238
    Some("get_mempolicy"),           // 239
    Some("mq_open"),                 // 240
    Some("mq_unlink"),               // 241
    Some("mq_timedsend"),            // 242
    Some("mq_timedreceive"),         // 243
    Some("mq_notify"),               // 244
    Some("mq_getsetattr"),           // 245
    Some("kexec_load"),              // 246
    Some("waitid"),                  // 247
    Some("add_key"),                 // 248
    Some("request_key"),             // 249
    Some("keyctl"),                  // 250
    Some("ioprio_set"),              // 251
    Some("ioprio_get"),              // 252
    Some("inotify_init"),            // 253
    Some("inotify_add_watch"),       // 254
    Some("inotify_rm_watch"),        // 255
    Some("migrate_pages"),           // 256
    Some("openat"),                  // 257
    Some("mkdirat"),                 // 258
    Some("mknodat"),                 // 259
    Some("fchownat"),                // 260
    Some("futimesat"),               // 261
    Some("newfstatat"),              // 262
    Some("unlinkat"),                // 263
    Some("renameat"),                // 264
    Some("linkat"),                  // 265
    Some("symlinkat"),               // 266
    Some("readlinkat"),              // 267
    Some("fchmodat"),                // 268
    Some("faccessat"),               // 269
    Some("pselect6"),                // 270
    Some("ppoll"),                   // 271
    Some("unshare"),                 // 272
    Some("set_robust_list"),         // 273
    Some("get_robust_list"),         // 274
    Some("splice"),                  // 275
    Some("tee"),                     // 276
    Some("sync_file_range"),         // 277
    Some("vmsplice"),                // 278
    Some("move_pages"),              // 279
    Some("utimensat"),               // 280
    Some("epoll_pwait"),             // 281
    Some("signalfd"),                // 282
    Some("timerfd_create"),          // 283
    Some("eventfd"),                 // 284
    Some("fallocate"),               // 285
    Some("timerfd_settime"),         // 286
    Some("timerfd_gettime"),         // 287
    Some("accept4"),                 // 288
    Some("signalfd4"),               // 289
    Some("eventfd2"),                // 290
    Some("epoll_create1"),           // 291
    Some("dup3"),                    // 292
    Some("pipe2"),                   // 293
    Some("inotify_init1"),           // 294
    Some("preadv"),                  // 295
    Some("pwritev"),                 // 296
    Some("rt_tgsigqueueinfo"),       // 297
    Some("perf_event_open"),         // 298
    Some("recvmmsg"),                // 299
    Some("fanotify_init"),           // 300
    Some("fanotify_mark"),           // 301
    Some("prlimit64"),               // 302
    Some("name_to_handle_at"),       // 303
    Some("open_by_handle_at"),       // 304
    Some("clock_adjtime"),           // 305
    Some("syncfs"),                  // 306
    Some("sendmmsg"),                // 307
    Some("setns"),                   // 308
    Some("getcpu"),                  // 309
    Some("process_vm_readv"),        // 310
    Some("process_vm_writev"),       // 311
    Some("kcmp"),                    // 312
    Some("finit_module"),            // 313
    Some("sched_setattr"),           // 314
    Some("sched_getattr"),           // 315
    Some("renameat2"),               // 316
    Some("seccomp"),                 // 317
    Some("getrandom"),               // 318
    Some("memfd_create"),            // 319
    Some("kexec_file_load"),         // 320
    Some("bpf"),                     // 321
    Some("execveat"),                // 322
    Some("userfaultfd"),             // 323
    Some("membarrier"),              // 324
    Some("mlock2"),                  // 325
    Some("copy_file_range"),         // 326
    Some("preadv2"),                 // 327
    Some("pwritev2"),                // 328
    Some("pkey_mprotect"),           // 329
    Some("pkey_alloc"),              // 330
    Some("pkey_free"),               // 331
    Some("statx"),                   // 332
    Some("io_pgetevents"),           // 333
    Some("rseq"),                    // 334
    Some("uretprobe"),               // 335
    Some("uprobe"),                  // 336
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

// rk-abigen generated this file from Linux 7.3, from the uAPI headers.
// Do not edit it. Change rk-abigen and run it again.

//! The uAPI structures of riscv64.
//!
//! The field names are the names of Linux. The fields `_padN` are the
//! padding bytes of the C structure.

#![allow(missing_docs)]

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// `struct stat` from `<asm/stat.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub __pad1: u64,
    pub st_size: i64,
    pub st_blksize: i32,
    pub __pad2: i32,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: u64,
    pub st_mtime: i64,
    pub st_mtime_nsec: u64,
    pub st_ctime: i64,
    pub st_ctime_nsec: u64,
    pub __unused4: u32,
    pub __unused5: u32,
}

const _: () = {
    assert!(size_of::<Stat>() == 128);
    assert!(align_of::<Stat>() == 8);
    assert!(core::mem::offset_of!(Stat, st_dev) == 0);
    assert!(core::mem::offset_of!(Stat, st_ino) == 8);
    assert!(core::mem::offset_of!(Stat, st_mode) == 16);
    assert!(core::mem::offset_of!(Stat, st_nlink) == 20);
    assert!(core::mem::offset_of!(Stat, st_uid) == 24);
    assert!(core::mem::offset_of!(Stat, st_gid) == 28);
    assert!(core::mem::offset_of!(Stat, st_rdev) == 32);
    assert!(core::mem::offset_of!(Stat, __pad1) == 40);
    assert!(core::mem::offset_of!(Stat, st_size) == 48);
    assert!(core::mem::offset_of!(Stat, st_blksize) == 56);
    assert!(core::mem::offset_of!(Stat, __pad2) == 60);
    assert!(core::mem::offset_of!(Stat, st_blocks) == 64);
    assert!(core::mem::offset_of!(Stat, st_atime) == 72);
    assert!(core::mem::offset_of!(Stat, st_atime_nsec) == 80);
    assert!(core::mem::offset_of!(Stat, st_mtime) == 88);
    assert!(core::mem::offset_of!(Stat, st_mtime_nsec) == 96);
    assert!(core::mem::offset_of!(Stat, st_ctime) == 104);
    assert!(core::mem::offset_of!(Stat, st_ctime_nsec) == 112);
    assert!(core::mem::offset_of!(Stat, __unused4) == 120);
    assert!(core::mem::offset_of!(Stat, __unused5) == 124);
};

/// `__kernel_fsid_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct KernelFsidT {
    pub val: [i32; 2],
}

const _: () = {
    assert!(size_of::<KernelFsidT>() == 8);
    assert!(align_of::<KernelFsidT>() == 4);
    assert!(core::mem::offset_of!(KernelFsidT, val) == 0);
};

/// `struct statfs` from `<asm/statfs.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Statfs {
    pub f_type: i64,
    pub f_bsize: i64,
    pub f_blocks: i64,
    pub f_bfree: i64,
    pub f_bavail: i64,
    pub f_files: i64,
    pub f_ffree: i64,
    pub f_fsid: KernelFsidT,
    pub f_namelen: i64,
    pub f_frsize: i64,
    pub f_flags: i64,
    pub f_spare: [i64; 4],
}

const _: () = {
    assert!(size_of::<Statfs>() == 120);
    assert!(align_of::<Statfs>() == 8);
    assert!(core::mem::offset_of!(Statfs, f_type) == 0);
    assert!(core::mem::offset_of!(Statfs, f_bsize) == 8);
    assert!(core::mem::offset_of!(Statfs, f_blocks) == 16);
    assert!(core::mem::offset_of!(Statfs, f_bfree) == 24);
    assert!(core::mem::offset_of!(Statfs, f_bavail) == 32);
    assert!(core::mem::offset_of!(Statfs, f_files) == 40);
    assert!(core::mem::offset_of!(Statfs, f_ffree) == 48);
    assert!(core::mem::offset_of!(Statfs, f_fsid) == 56);
    assert!(core::mem::offset_of!(Statfs, f_namelen) == 64);
    assert!(core::mem::offset_of!(Statfs, f_frsize) == 72);
    assert!(core::mem::offset_of!(Statfs, f_flags) == 80);
    assert!(core::mem::offset_of!(Statfs, f_spare) == 88);
};

/// `struct statx_timestamp`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct StatxTimestamp {
    pub tv_sec: i64,
    pub tv_nsec: u32,
    pub __reserved: i32,
}

const _: () = {
    assert!(size_of::<StatxTimestamp>() == 16);
    assert!(align_of::<StatxTimestamp>() == 8);
    assert!(core::mem::offset_of!(StatxTimestamp, tv_sec) == 0);
    assert!(core::mem::offset_of!(StatxTimestamp, tv_nsec) == 8);
    assert!(core::mem::offset_of!(StatxTimestamp, __reserved) == 12);
};

/// `struct statx` from `<linux/stat.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Statx {
    pub stx_mask: u32,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    pub __spare0: [u16; 1],
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_attributes_mask: u64,
    pub stx_atime: StatxTimestamp,
    pub stx_btime: StatxTimestamp,
    pub stx_ctime: StatxTimestamp,
    pub stx_mtime: StatxTimestamp,
    pub stx_rdev_major: u32,
    pub stx_rdev_minor: u32,
    pub stx_dev_major: u32,
    pub stx_dev_minor: u32,
    pub stx_mnt_id: u64,
    pub stx_dio_mem_align: u32,
    pub stx_dio_offset_align: u32,
    pub stx_subvol: u64,
    pub stx_atomic_write_unit_min: u32,
    pub stx_atomic_write_unit_max: u32,
    pub stx_atomic_write_segments_max: u32,
    pub stx_dio_read_offset_align: u32,
    pub stx_atomic_write_unit_max_opt: u32,
    pub __spare2: [u32; 1],
    pub __spare3: [u64; 8],
}

const _: () = {
    assert!(size_of::<Statx>() == 256);
    assert!(align_of::<Statx>() == 8);
    assert!(core::mem::offset_of!(Statx, stx_mask) == 0);
    assert!(core::mem::offset_of!(Statx, stx_blksize) == 4);
    assert!(core::mem::offset_of!(Statx, stx_attributes) == 8);
    assert!(core::mem::offset_of!(Statx, stx_nlink) == 16);
    assert!(core::mem::offset_of!(Statx, stx_uid) == 20);
    assert!(core::mem::offset_of!(Statx, stx_gid) == 24);
    assert!(core::mem::offset_of!(Statx, stx_mode) == 28);
    assert!(core::mem::offset_of!(Statx, __spare0) == 30);
    assert!(core::mem::offset_of!(Statx, stx_ino) == 32);
    assert!(core::mem::offset_of!(Statx, stx_size) == 40);
    assert!(core::mem::offset_of!(Statx, stx_blocks) == 48);
    assert!(core::mem::offset_of!(Statx, stx_attributes_mask) == 56);
    assert!(core::mem::offset_of!(Statx, stx_atime) == 64);
    assert!(core::mem::offset_of!(Statx, stx_btime) == 80);
    assert!(core::mem::offset_of!(Statx, stx_ctime) == 96);
    assert!(core::mem::offset_of!(Statx, stx_mtime) == 112);
    assert!(core::mem::offset_of!(Statx, stx_rdev_major) == 128);
    assert!(core::mem::offset_of!(Statx, stx_rdev_minor) == 132);
    assert!(core::mem::offset_of!(Statx, stx_dev_major) == 136);
    assert!(core::mem::offset_of!(Statx, stx_dev_minor) == 140);
    assert!(core::mem::offset_of!(Statx, stx_mnt_id) == 144);
    assert!(core::mem::offset_of!(Statx, stx_dio_mem_align) == 152);
    assert!(core::mem::offset_of!(Statx, stx_dio_offset_align) == 156);
    assert!(core::mem::offset_of!(Statx, stx_subvol) == 160);
    assert!(core::mem::offset_of!(Statx, stx_atomic_write_unit_min) == 168);
    assert!(core::mem::offset_of!(Statx, stx_atomic_write_unit_max) == 172);
    assert!(core::mem::offset_of!(Statx, stx_atomic_write_segments_max) == 176);
    assert!(core::mem::offset_of!(Statx, stx_dio_read_offset_align) == 180);
    assert!(core::mem::offset_of!(Statx, stx_atomic_write_unit_max_opt) == 184);
    assert!(core::mem::offset_of!(Statx, __spare2) == 188);
    assert!(core::mem::offset_of!(Statx, __spare3) == 192);
};

/// `struct __kernel_timespec` from `<linux/time_types.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct KernelTimespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

const _: () = {
    assert!(size_of::<KernelTimespec>() == 16);
    assert!(align_of::<KernelTimespec>() == 8);
    assert!(core::mem::offset_of!(KernelTimespec, tv_sec) == 0);
    assert!(core::mem::offset_of!(KernelTimespec, tv_nsec) == 8);
};

/// `struct __kernel_itimerspec` from `<linux/time_types.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct KernelItimerspec {
    pub it_interval: KernelTimespec,
    pub it_value: KernelTimespec,
}

const _: () = {
    assert!(size_of::<KernelItimerspec>() == 32);
    assert!(align_of::<KernelItimerspec>() == 8);
    assert!(core::mem::offset_of!(KernelItimerspec, it_interval) == 0);
    assert!(core::mem::offset_of!(KernelItimerspec, it_value) == 16);
};

/// `struct __kernel_old_timeval` from `<linux/time_types.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct KernelOldTimeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

const _: () = {
    assert!(size_of::<KernelOldTimeval>() == 16);
    assert!(align_of::<KernelOldTimeval>() == 8);
    assert!(core::mem::offset_of!(KernelOldTimeval, tv_sec) == 0);
    assert!(core::mem::offset_of!(KernelOldTimeval, tv_usec) == 8);
};

/// `struct __kernel_old_itimerval` from `<linux/time_types.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct KernelOldItimerval {
    pub it_interval: KernelOldTimeval,
    pub it_value: KernelOldTimeval,
}

const _: () = {
    assert!(size_of::<KernelOldItimerval>() == 32);
    assert!(align_of::<KernelOldItimerval>() == 8);
    assert!(core::mem::offset_of!(KernelOldItimerval, it_interval) == 0);
    assert!(core::mem::offset_of!(KernelOldItimerval, it_value) == 16);
};

/// `struct __kernel_timex_timeval`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct KernelTimexTimeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

const _: () = {
    assert!(size_of::<KernelTimexTimeval>() == 16);
    assert!(align_of::<KernelTimexTimeval>() == 8);
    assert!(core::mem::offset_of!(KernelTimexTimeval, tv_sec) == 0);
    assert!(core::mem::offset_of!(KernelTimexTimeval, tv_usec) == 8);
};

/// `struct __kernel_timex` from `<linux/timex.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct KernelTimex {
    pub modes: u32,
    _pad0: [u8; 4],
    pub offset: i64,
    pub freq: i64,
    pub maxerror: i64,
    pub esterror: i64,
    pub status: i32,
    _pad1: [u8; 4],
    pub constant: i64,
    pub precision: i64,
    pub tolerance: i64,
    pub time: KernelTimexTimeval,
    pub tick: i64,
    pub ppsfreq: i64,
    pub jitter: i64,
    pub shift: i32,
    _pad2: [u8; 4],
    pub stabil: i64,
    pub jitcnt: i64,
    pub calcnt: i64,
    pub errcnt: i64,
    pub stbcnt: i64,
    pub tai: i32,
    _pad3: [u8; 44],
}

const _: () = {
    assert!(size_of::<KernelTimex>() == 208);
    assert!(align_of::<KernelTimex>() == 8);
    assert!(core::mem::offset_of!(KernelTimex, modes) == 0);
    assert!(core::mem::offset_of!(KernelTimex, offset) == 8);
    assert!(core::mem::offset_of!(KernelTimex, freq) == 16);
    assert!(core::mem::offset_of!(KernelTimex, maxerror) == 24);
    assert!(core::mem::offset_of!(KernelTimex, esterror) == 32);
    assert!(core::mem::offset_of!(KernelTimex, status) == 40);
    assert!(core::mem::offset_of!(KernelTimex, constant) == 48);
    assert!(core::mem::offset_of!(KernelTimex, precision) == 56);
    assert!(core::mem::offset_of!(KernelTimex, tolerance) == 64);
    assert!(core::mem::offset_of!(KernelTimex, time) == 72);
    assert!(core::mem::offset_of!(KernelTimex, tick) == 88);
    assert!(core::mem::offset_of!(KernelTimex, ppsfreq) == 96);
    assert!(core::mem::offset_of!(KernelTimex, jitter) == 104);
    assert!(core::mem::offset_of!(KernelTimex, shift) == 112);
    assert!(core::mem::offset_of!(KernelTimex, stabil) == 120);
    assert!(core::mem::offset_of!(KernelTimex, jitcnt) == 128);
    assert!(core::mem::offset_of!(KernelTimex, calcnt) == 136);
    assert!(core::mem::offset_of!(KernelTimex, errcnt) == 144);
    assert!(core::mem::offset_of!(KernelTimex, stbcnt) == 152);
    assert!(core::mem::offset_of!(KernelTimex, tai) == 160);
};

/// `struct iovec` from `<linux/uio.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Iovec {
    pub iov_base: u64,
    pub iov_len: u64,
}

const _: () = {
    assert!(size_of::<Iovec>() == 16);
    assert!(align_of::<Iovec>() == 8);
    assert!(core::mem::offset_of!(Iovec, iov_base) == 0);
    assert!(core::mem::offset_of!(Iovec, iov_len) == 8);
};

/// `struct new_utsname` from `<linux/utsname.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct NewUtsname {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
    pub domainname: [u8; 65],
}

const _: () = {
    assert!(size_of::<NewUtsname>() == 390);
    assert!(align_of::<NewUtsname>() == 1);
    assert!(core::mem::offset_of!(NewUtsname, sysname) == 0);
    assert!(core::mem::offset_of!(NewUtsname, nodename) == 65);
    assert!(core::mem::offset_of!(NewUtsname, release) == 130);
    assert!(core::mem::offset_of!(NewUtsname, version) == 195);
    assert!(core::mem::offset_of!(NewUtsname, machine) == 260);
    assert!(core::mem::offset_of!(NewUtsname, domainname) == 325);
};

/// `struct rlimit` from `<linux/resource.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Rlimit {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

const _: () = {
    assert!(size_of::<Rlimit>() == 16);
    assert!(align_of::<Rlimit>() == 8);
    assert!(core::mem::offset_of!(Rlimit, rlim_cur) == 0);
    assert!(core::mem::offset_of!(Rlimit, rlim_max) == 8);
};

/// `struct rlimit64` from `<linux/resource.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Rlimit64 {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

const _: () = {
    assert!(size_of::<Rlimit64>() == 16);
    assert!(align_of::<Rlimit64>() == 8);
    assert!(core::mem::offset_of!(Rlimit64, rlim_cur) == 0);
    assert!(core::mem::offset_of!(Rlimit64, rlim_max) == 8);
};

/// `struct rusage` from `<linux/resource.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Rusage {
    pub ru_utime: KernelOldTimeval,
    pub ru_stime: KernelOldTimeval,
    pub ru_maxrss: i64,
    pub ru_ixrss: i64,
    pub ru_idrss: i64,
    pub ru_isrss: i64,
    pub ru_minflt: i64,
    pub ru_majflt: i64,
    pub ru_nswap: i64,
    pub ru_inblock: i64,
    pub ru_oublock: i64,
    pub ru_msgsnd: i64,
    pub ru_msgrcv: i64,
    pub ru_nsignals: i64,
    pub ru_nvcsw: i64,
    pub ru_nivcsw: i64,
}

const _: () = {
    assert!(size_of::<Rusage>() == 144);
    assert!(align_of::<Rusage>() == 8);
    assert!(core::mem::offset_of!(Rusage, ru_utime) == 0);
    assert!(core::mem::offset_of!(Rusage, ru_stime) == 16);
    assert!(core::mem::offset_of!(Rusage, ru_maxrss) == 32);
    assert!(core::mem::offset_of!(Rusage, ru_ixrss) == 40);
    assert!(core::mem::offset_of!(Rusage, ru_idrss) == 48);
    assert!(core::mem::offset_of!(Rusage, ru_isrss) == 56);
    assert!(core::mem::offset_of!(Rusage, ru_minflt) == 64);
    assert!(core::mem::offset_of!(Rusage, ru_majflt) == 72);
    assert!(core::mem::offset_of!(Rusage, ru_nswap) == 80);
    assert!(core::mem::offset_of!(Rusage, ru_inblock) == 88);
    assert!(core::mem::offset_of!(Rusage, ru_oublock) == 96);
    assert!(core::mem::offset_of!(Rusage, ru_msgsnd) == 104);
    assert!(core::mem::offset_of!(Rusage, ru_msgrcv) == 112);
    assert!(core::mem::offset_of!(Rusage, ru_nsignals) == 120);
    assert!(core::mem::offset_of!(Rusage, ru_nvcsw) == 128);
    assert!(core::mem::offset_of!(Rusage, ru_nivcsw) == 136);
};

/// `struct pollfd` from `<asm/poll.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Pollfd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

const _: () = {
    assert!(size_of::<Pollfd>() == 8);
    assert!(align_of::<Pollfd>() == 4);
    assert!(core::mem::offset_of!(Pollfd, fd) == 0);
    assert!(core::mem::offset_of!(Pollfd, events) == 4);
    assert!(core::mem::offset_of!(Pollfd, revents) == 6);
};

/// `struct clone_args` from `<linux/sched.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct CloneArgs {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,
}

const _: () = {
    assert!(size_of::<CloneArgs>() == 88);
    assert!(align_of::<CloneArgs>() == 8);
    assert!(core::mem::offset_of!(CloneArgs, flags) == 0);
    assert!(core::mem::offset_of!(CloneArgs, pidfd) == 8);
    assert!(core::mem::offset_of!(CloneArgs, child_tid) == 16);
    assert!(core::mem::offset_of!(CloneArgs, parent_tid) == 24);
    assert!(core::mem::offset_of!(CloneArgs, exit_signal) == 32);
    assert!(core::mem::offset_of!(CloneArgs, stack) == 40);
    assert!(core::mem::offset_of!(CloneArgs, stack_size) == 48);
    assert!(core::mem::offset_of!(CloneArgs, tls) == 56);
    assert!(core::mem::offset_of!(CloneArgs, set_tid) == 64);
    assert!(core::mem::offset_of!(CloneArgs, set_tid_size) == 72);
    assert!(core::mem::offset_of!(CloneArgs, cgroup) == 80);
};

/// `struct sched_attr` from `<linux/sched/types.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct SchedAttr {
    pub size: u32,
    pub sched_policy: u32,
    pub sched_flags: u64,
    pub sched_nice: i32,
    pub sched_priority: u32,
    pub sched_runtime: u64,
    pub sched_deadline: u64,
    pub sched_period: u64,
    pub sched_util_min: u32,
    pub sched_util_max: u32,
}

const _: () = {
    assert!(size_of::<SchedAttr>() == 56);
    assert!(align_of::<SchedAttr>() == 8);
    assert!(core::mem::offset_of!(SchedAttr, size) == 0);
    assert!(core::mem::offset_of!(SchedAttr, sched_policy) == 4);
    assert!(core::mem::offset_of!(SchedAttr, sched_flags) == 8);
    assert!(core::mem::offset_of!(SchedAttr, sched_nice) == 16);
    assert!(core::mem::offset_of!(SchedAttr, sched_priority) == 20);
    assert!(core::mem::offset_of!(SchedAttr, sched_runtime) == 24);
    assert!(core::mem::offset_of!(SchedAttr, sched_deadline) == 32);
    assert!(core::mem::offset_of!(SchedAttr, sched_period) == 40);
    assert!(core::mem::offset_of!(SchedAttr, sched_util_min) == 48);
    assert!(core::mem::offset_of!(SchedAttr, sched_util_max) == 52);
};

/// `struct epoll_event` from `<linux/eventpoll.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct EpollEvent {
    pub events: u32,
    _pad0: [u8; 4],
    pub data: u64,
}

const _: () = {
    assert!(size_of::<EpollEvent>() == 16);
    assert!(align_of::<EpollEvent>() == 8);
    assert!(core::mem::offset_of!(EpollEvent, events) == 0);
    assert!(core::mem::offset_of!(EpollEvent, data) == 8);
};

/// `struct signalfd_siginfo` from `<linux/signalfd.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct SignalfdSiginfo {
    pub ssi_signo: u32,
    pub ssi_errno: i32,
    pub ssi_code: i32,
    pub ssi_pid: u32,
    pub ssi_uid: u32,
    pub ssi_fd: i32,
    pub ssi_tid: u32,
    pub ssi_band: u32,
    pub ssi_overrun: u32,
    pub ssi_trapno: u32,
    pub ssi_status: i32,
    pub ssi_int: i32,
    pub ssi_ptr: u64,
    pub ssi_utime: u64,
    pub ssi_stime: u64,
    pub ssi_addr: u64,
    pub ssi_addr_lsb: u16,
    pub __pad2: u16,
    pub ssi_syscall: i32,
    pub ssi_call_addr: u64,
    pub ssi_arch: u32,
    pub __pad: [u8; 28],
}

const _: () = {
    assert!(size_of::<SignalfdSiginfo>() == 128);
    assert!(align_of::<SignalfdSiginfo>() == 8);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_signo) == 0);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_errno) == 4);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_code) == 8);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_pid) == 12);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_uid) == 16);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_fd) == 20);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_tid) == 24);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_band) == 28);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_overrun) == 32);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_trapno) == 36);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_status) == 40);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_int) == 44);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_ptr) == 48);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_utime) == 56);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_stime) == 64);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_addr) == 72);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_addr_lsb) == 80);
    assert!(core::mem::offset_of!(SignalfdSiginfo, __pad2) == 82);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_syscall) == 84);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_call_addr) == 88);
    assert!(core::mem::offset_of!(SignalfdSiginfo, ssi_arch) == 96);
    assert!(core::mem::offset_of!(SignalfdSiginfo, __pad) == 100);
};

/// `struct robust_list` from `<linux/futex.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct RobustList {
    pub next: u64,
}

const _: () = {
    assert!(size_of::<RobustList>() == 8);
    assert!(align_of::<RobustList>() == 8);
    assert!(core::mem::offset_of!(RobustList, next) == 0);
};

/// `struct robust_list_head` from `<linux/futex.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct RobustListHead {
    pub list: RobustList,
    pub futex_offset: i64,
    pub list_op_pending: u64,
}

const _: () = {
    assert!(size_of::<RobustListHead>() == 24);
    assert!(align_of::<RobustListHead>() == 8);
    assert!(core::mem::offset_of!(RobustListHead, list) == 0);
    assert!(core::mem::offset_of!(RobustListHead, futex_offset) == 8);
    assert!(core::mem::offset_of!(RobustListHead, list_op_pending) == 16);
};

/// `struct futex_waitv` from `<linux/futex.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct FutexWaitv {
    pub val: u64,
    pub uaddr: u64,
    pub flags: u32,
    pub __reserved: u32,
}

const _: () = {
    assert!(size_of::<FutexWaitv>() == 24);
    assert!(align_of::<FutexWaitv>() == 8);
    assert!(core::mem::offset_of!(FutexWaitv, val) == 0);
    assert!(core::mem::offset_of!(FutexWaitv, uaddr) == 8);
    assert!(core::mem::offset_of!(FutexWaitv, flags) == 16);
    assert!(core::mem::offset_of!(FutexWaitv, __reserved) == 20);
};

/// `struct open_how` from `<linux/openat2.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct OpenHow {
    pub flags: u64,
    pub mode: u64,
    pub resolve: u64,
}

const _: () = {
    assert!(size_of::<OpenHow>() == 24);
    assert!(align_of::<OpenHow>() == 8);
    assert!(core::mem::offset_of!(OpenHow, flags) == 0);
    assert!(core::mem::offset_of!(OpenHow, mode) == 8);
    assert!(core::mem::offset_of!(OpenHow, resolve) == 16);
};

/// `struct sysinfo` from `<linux/sysinfo.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Sysinfo {
    pub uptime: i64,
    pub loads: [u64; 3],
    pub totalram: u64,
    pub freeram: u64,
    pub sharedram: u64,
    pub bufferram: u64,
    pub totalswap: u64,
    pub freeswap: u64,
    pub procs: u16,
    pub pad: u16,
    _pad0: [u8; 4],
    pub totalhigh: u64,
    pub freehigh: u64,
    pub mem_unit: u32,
    pub _f: [u8; 0],
    _pad1: [u8; 4],
}

const _: () = {
    assert!(size_of::<Sysinfo>() == 112);
    assert!(align_of::<Sysinfo>() == 8);
    assert!(core::mem::offset_of!(Sysinfo, uptime) == 0);
    assert!(core::mem::offset_of!(Sysinfo, loads) == 8);
    assert!(core::mem::offset_of!(Sysinfo, totalram) == 32);
    assert!(core::mem::offset_of!(Sysinfo, freeram) == 40);
    assert!(core::mem::offset_of!(Sysinfo, sharedram) == 48);
    assert!(core::mem::offset_of!(Sysinfo, bufferram) == 56);
    assert!(core::mem::offset_of!(Sysinfo, totalswap) == 64);
    assert!(core::mem::offset_of!(Sysinfo, freeswap) == 72);
    assert!(core::mem::offset_of!(Sysinfo, procs) == 80);
    assert!(core::mem::offset_of!(Sysinfo, pad) == 82);
    assert!(core::mem::offset_of!(Sysinfo, totalhigh) == 88);
    assert!(core::mem::offset_of!(Sysinfo, freehigh) == 96);
    assert!(core::mem::offset_of!(Sysinfo, mem_unit) == 104);
    assert!(core::mem::offset_of!(Sysinfo, _f) == 108);
};

/// `struct sigaltstack` from `<asm/signal.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Sigaltstack {
    pub ss_sp: u64,
    pub ss_flags: i32,
    _pad0: [u8; 4],
    pub ss_size: u64,
}

const _: () = {
    assert!(size_of::<Sigaltstack>() == 24);
    assert!(align_of::<Sigaltstack>() == 8);
    assert!(core::mem::offset_of!(Sigaltstack, ss_sp) == 0);
    assert!(core::mem::offset_of!(Sigaltstack, ss_flags) == 8);
    assert!(core::mem::offset_of!(Sigaltstack, ss_size) == 16);
};

/// `struct __user_cap_header_struct` from `<linux/capability.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct UserCapHeaderStruct {
    pub version: u32,
    pub pid: i32,
}

const _: () = {
    assert!(size_of::<UserCapHeaderStruct>() == 8);
    assert!(align_of::<UserCapHeaderStruct>() == 4);
    assert!(core::mem::offset_of!(UserCapHeaderStruct, version) == 0);
    assert!(core::mem::offset_of!(UserCapHeaderStruct, pid) == 4);
};

/// `struct __user_cap_data_struct` from `<linux/capability.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct UserCapDataStruct {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

const _: () = {
    assert!(size_of::<UserCapDataStruct>() == 12);
    assert!(align_of::<UserCapDataStruct>() == 4);
    assert!(core::mem::offset_of!(UserCapDataStruct, effective) == 0);
    assert!(core::mem::offset_of!(UserCapDataStruct, permitted) == 4);
    assert!(core::mem::offset_of!(UserCapDataStruct, inheritable) == 8);
};

/// `struct termios` from `<asm/termbits.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; 19],
}

const _: () = {
    assert!(size_of::<Termios>() == 36);
    assert!(align_of::<Termios>() == 4);
    assert!(core::mem::offset_of!(Termios, c_iflag) == 0);
    assert!(core::mem::offset_of!(Termios, c_oflag) == 4);
    assert!(core::mem::offset_of!(Termios, c_cflag) == 8);
    assert!(core::mem::offset_of!(Termios, c_lflag) == 12);
    assert!(core::mem::offset_of!(Termios, c_line) == 16);
    assert!(core::mem::offset_of!(Termios, c_cc) == 17);
};

/// `struct termios2` from `<asm/termbits.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Termios2 {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; 19],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

const _: () = {
    assert!(size_of::<Termios2>() == 44);
    assert!(align_of::<Termios2>() == 4);
    assert!(core::mem::offset_of!(Termios2, c_iflag) == 0);
    assert!(core::mem::offset_of!(Termios2, c_oflag) == 4);
    assert!(core::mem::offset_of!(Termios2, c_cflag) == 8);
    assert!(core::mem::offset_of!(Termios2, c_lflag) == 12);
    assert!(core::mem::offset_of!(Termios2, c_line) == 16);
    assert!(core::mem::offset_of!(Termios2, c_cc) == 17);
    assert!(core::mem::offset_of!(Termios2, c_ispeed) == 36);
    assert!(core::mem::offset_of!(Termios2, c_ospeed) == 40);
};

/// `struct winsize` from `<asm/termios.h>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

const _: () = {
    assert!(size_of::<Winsize>() == 8);
    assert!(align_of::<Winsize>() == 2);
    assert!(core::mem::offset_of!(Winsize, ws_row) == 0);
    assert!(core::mem::offset_of!(Winsize, ws_col) == 2);
    assert!(core::mem::offset_of!(Winsize, ws_xpixel) == 4);
    assert!(core::mem::offset_of!(Winsize, ws_ypixel) == 6);
};

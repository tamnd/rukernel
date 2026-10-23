// rk-abigen generated this file from Linux 7.3, from <linux/sched.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The flags of `clone` and `clone3`, and the scheduler policies.

/// `SCHED_NORMAL` from `<linux/sched.h>`.
pub const SCHED_NORMAL: u64 = 0;
/// `SCHED_FIFO` from `<linux/sched.h>`.
pub const SCHED_FIFO: u64 = 1;
/// `SCHED_FLAG_RESET_ON_FORK` from `<linux/sched.h>`.
pub const SCHED_FLAG_RESET_ON_FORK: u64 = 1;
/// `SCHED_GETATTR_FLAG_DL_DYNAMIC` from `<linux/sched.h>`.
pub const SCHED_GETATTR_FLAG_DL_DYNAMIC: u64 = 1;
/// `SCHED_FLAG_RECLAIM` from `<linux/sched.h>`.
pub const SCHED_FLAG_RECLAIM: u64 = 2;
/// `SCHED_RR` from `<linux/sched.h>`.
pub const SCHED_RR: u64 = 2;
/// `SCHED_BATCH` from `<linux/sched.h>`.
pub const SCHED_BATCH: u64 = 3;
/// `SCHED_FLAG_DL_OVERRUN` from `<linux/sched.h>`.
pub const SCHED_FLAG_DL_OVERRUN: u64 = 4;
/// `SCHED_IDLE` from `<linux/sched.h>`.
pub const SCHED_IDLE: u64 = 5;
/// `SCHED_DEADLINE` from `<linux/sched.h>`.
pub const SCHED_DEADLINE: u64 = 6;
/// `SCHED_EXT` from `<linux/sched.h>`.
pub const SCHED_EXT: u64 = 7;
/// `SCHED_FLAG_KEEP_POLICY` from `<linux/sched.h>`.
pub const SCHED_FLAG_KEEP_POLICY: u64 = 8;
/// `SCHED_FLAG_KEEP_PARAMS` from `<linux/sched.h>`.
pub const SCHED_FLAG_KEEP_PARAMS: u64 = 16;
/// `SCHED_FLAG_KEEP_ALL` from `<linux/sched.h>`.
pub const SCHED_FLAG_KEEP_ALL: u64 = 24;
/// `SCHED_FLAG_UTIL_CLAMP_MIN` from `<linux/sched.h>`.
pub const SCHED_FLAG_UTIL_CLAMP_MIN: u64 = 32;
/// Sizeof first published struct.
pub const CLONE_ARGS_SIZE_VER0: u64 = 64;
/// `SCHED_FLAG_UTIL_CLAMP_MAX` from `<linux/sched.h>`.
pub const SCHED_FLAG_UTIL_CLAMP_MAX: u64 = 64;
/// Sizeof second published struct.
pub const CLONE_ARGS_SIZE_VER1: u64 = 80;
/// Sizeof third published struct.
pub const CLONE_ARGS_SIZE_VER2: u64 = 88;
/// `SCHED_FLAG_UTIL_CLAMP` from `<linux/sched.h>`.
pub const SCHED_FLAG_UTIL_CLAMP: u64 = 96;
/// `SCHED_FLAG_ALL` from `<linux/sched.h>`.
pub const SCHED_FLAG_ALL: u64 = 127;
/// New time namespace.
pub const CLONE_NEWTIME: u64 = 128;
/// Signal mask to be sent at exit.
pub const CSIGNAL: u64 = 255;
/// Set if VM shared between processes.
pub const CLONE_VM: u64 = 0x100;
/// Set if fs info shared between processes.
pub const CLONE_FS: u64 = 0x200;
/// Set if open files shared between processes.
pub const CLONE_FILES: u64 = 0x400;
/// Set if signal handlers and blocked signals shared.
pub const CLONE_SIGHAND: u64 = 0x800;
/// Set if a pidfd should be placed in parent.
pub const CLONE_PIDFD: u64 = 0x1000;
/// Set if we want to let tracing continue on the child too.
pub const CLONE_PTRACE: u64 = 0x2000;
/// Set if the parent wants the child to wake it up on mm\_release.
pub const CLONE_VFORK: u64 = 0x4000;
/// Set if we want to have the same parent as the cloner.
pub const CLONE_PARENT: u64 = 0x8000;
/// Same thread group?
pub const CLONE_THREAD: u64 = 0x1_0000;
/// New mount namespace group.
pub const CLONE_NEWNS: u64 = 0x2_0000;
/// Share system V SEM\_UNDO semantics.
pub const CLONE_SYSVSEM: u64 = 0x4_0000;
/// Create a new TLS for the child.
pub const CLONE_SETTLS: u64 = 0x8_0000;
/// Set the TID in the parent.
pub const CLONE_PARENT_SETTID: u64 = 0x10_0000;
/// Clear the TID in the child.
pub const CLONE_CHILD_CLEARTID: u64 = 0x20_0000;
/// Unused, ignored.
pub const CLONE_DETACHED: u64 = 0x40_0000;
/// Set if the tracing process can't force CLONE\_PTRACE on this clone.
pub const CLONE_UNTRACED: u64 = 0x80_0000;
/// Set the TID in the child.
pub const CLONE_CHILD_SETTID: u64 = 0x100_0000;
/// New cgroup namespace.
pub const CLONE_NEWCGROUP: u64 = 0x200_0000;
/// New utsname namespace.
pub const CLONE_NEWUTS: u64 = 0x400_0000;
/// New ipc namespace.
pub const CLONE_NEWIPC: u64 = 0x800_0000;
/// New user namespace.
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
/// New pid namespace.
pub const CLONE_NEWPID: u64 = 0x2000_0000;
/// New network namespace.
pub const CLONE_NEWNET: u64 = 0x4000_0000;
/// `SCHED_RESET_ON_FORK` from `<linux/sched.h>`.
pub const SCHED_RESET_ON_FORK: u64 = 0x4000_0000;
/// Clone io context.
pub const CLONE_IO: u64 = 0x8000_0000;
/// Clear any signal handler and reset to SIG\_DFL.
pub const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;
/// Clone into a specific cgroup given the right permissions.
pub const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;
/// Auto-reap child on exit.
pub const CLONE_AUTOREAP: u64 = 0x4_0000_0000;
/// Set no\_new\_privs on child.
pub const CLONE_NNP: u64 = 0x8_0000_0000;
/// Kill child when clone pidfd closes.
pub const CLONE_PIDFD_AUTOKILL: u64 = 0x10_0000_0000;
/// Create an empty mount namespace.
pub const CLONE_EMPTY_MNTNS: u64 = 0x20_0000_0000;

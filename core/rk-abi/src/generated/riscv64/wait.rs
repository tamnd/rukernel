// rk-abigen generated this file from Linux 7.3, from <linux/wait.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The flags and the ID types of `wait4` and `waitid`.

/// `P_ALL` from `<linux/wait.h>`.
pub const P_ALL: u32 = 0;
/// `P_PID` from `<linux/wait.h>`.
pub const P_PID: u32 = 1;
/// `WNOHANG` from `<linux/wait.h>`.
pub const WNOHANG: u32 = 1;
/// `P_PGID` from `<linux/wait.h>`.
pub const P_PGID: u32 = 2;
/// The same value as `WUNTRACED`.
pub const WSTOPPED: u32 = 2;
/// `WUNTRACED` from `<linux/wait.h>`.
pub const WUNTRACED: u32 = 2;
/// `P_PIDFD` from `<linux/wait.h>`.
pub const P_PIDFD: u32 = 3;
/// `WEXITED` from `<linux/wait.h>`.
pub const WEXITED: u32 = 4;
/// `WCONTINUED` from `<linux/wait.h>`.
pub const WCONTINUED: u32 = 8;
/// Don't reap, just poll status.
pub const WNOWAIT: u32 = 0x100_0000;

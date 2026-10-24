// rk-abigen generated this file from Linux 7.3, from <linux/timerfd.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The flags of `timerfd_create` and `timerfd_settime`, and the `ioctl` of a timer file.

/// `TFD_TIMER_ABSTIME` from `<linux/timerfd.h>`.
pub const TFD_TIMER_ABSTIME: u32 = 1;
/// `TFD_TIMER_CANCEL_ON_SET` from `<linux/timerfd.h>`.
pub const TFD_TIMER_CANCEL_ON_SET: u32 = 2;
/// `TFD_NONBLOCK` from `<linux/timerfd.h>`.
pub const TFD_NONBLOCK: u32 = 0x800;
/// `TFD_CLOEXEC` from `<linux/timerfd.h>`.
pub const TFD_CLOEXEC: u32 = 0x8_0000;
/// `TFD_IOC_SET_TICKS` from `<linux/timerfd.h>`.
pub const TFD_IOC_SET_TICKS: u32 = 0x4008_5400;

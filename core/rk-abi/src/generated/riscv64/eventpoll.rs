// rk-abigen generated this file from Linux 7.3, from <linux/eventpoll.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The operations of `epoll_ctl` and the events and flags of an epoll entry.

/// `EPOLLIN` from `<linux/eventpoll.h>`.
pub const EPOLLIN: u32 = 1;
/// `EPOLL_CTL_ADD` from `<linux/eventpoll.h>`.
pub const EPOLL_CTL_ADD: u32 = 1;
/// `EPOLLPRI` from `<linux/eventpoll.h>`.
pub const EPOLLPRI: u32 = 2;
/// `EPOLL_CTL_DEL` from `<linux/eventpoll.h>`.
pub const EPOLL_CTL_DEL: u32 = 2;
/// `EPOLL_CTL_MOD` from `<linux/eventpoll.h>`.
pub const EPOLL_CTL_MOD: u32 = 3;
/// `EPOLLOUT` from `<linux/eventpoll.h>`.
pub const EPOLLOUT: u32 = 4;
/// `EPOLLERR` from `<linux/eventpoll.h>`.
pub const EPOLLERR: u32 = 8;
/// `EPOLLHUP` from `<linux/eventpoll.h>`.
pub const EPOLLHUP: u32 = 16;
/// `EPOLLNVAL` from `<linux/eventpoll.h>`.
pub const EPOLLNVAL: u32 = 32;
/// `EPOLLRDNORM` from `<linux/eventpoll.h>`.
pub const EPOLLRDNORM: u32 = 64;
/// `EPOLLRDBAND` from `<linux/eventpoll.h>`.
pub const EPOLLRDBAND: u32 = 128;
/// `EPOLL_IOC_TYPE` from `<linux/eventpoll.h>`.
pub const EPOLL_IOC_TYPE: u32 = 138;
/// `EPOLLWRNORM` from `<linux/eventpoll.h>`.
pub const EPOLLWRNORM: u32 = 0x100;
/// `EPOLLWRBAND` from `<linux/eventpoll.h>`.
pub const EPOLLWRBAND: u32 = 0x200;
/// `EPOLLMSG` from `<linux/eventpoll.h>`.
pub const EPOLLMSG: u32 = 0x400;
/// `EPOLLRDHUP` from `<linux/eventpoll.h>`.
pub const EPOLLRDHUP: u32 = 0x2000;
/// `EPOLL_CLOEXEC` from `<linux/eventpoll.h>`.
pub const EPOLL_CLOEXEC: u32 = 0x8_0000;
/// `EPOLL_URING_WAKE` from `<linux/eventpoll.h>`.
pub const EPOLL_URING_WAKE: u32 = 0x800_0000;
/// `EPOLLEXCLUSIVE` from `<linux/eventpoll.h>`.
pub const EPOLLEXCLUSIVE: u32 = 0x1000_0000;
/// `EPOLLWAKEUP` from `<linux/eventpoll.h>`.
pub const EPOLLWAKEUP: u32 = 0x2000_0000;
/// `EPOLLONESHOT` from `<linux/eventpoll.h>`.
pub const EPOLLONESHOT: u32 = 0x4000_0000;
/// `EPOLLET` from `<linux/eventpoll.h>`.
pub const EPOLLET: u32 = 0x8000_0000;

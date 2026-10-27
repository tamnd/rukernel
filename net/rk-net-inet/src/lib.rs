//! The IPv4 stack: ARP neighbours, IPv4, the routes, ICMP, TCP, and the UDP, ICMP echo and raw
//! sockets, as net/ipv4 of Linux.
//!
//! The pure parts are in their own modules, so that the host tests can run them: the checksum,
//! the headers, the neighbour table, the route table, the port table and the parser of `ip=`.
//! The module `stack` has the global tables and the paths of the packets, `socket` has the
//! datagram sockets, and `tcp` has TCP.
//!
//! The drivers do not use interrupts yet. A bottom half of the kernel calls `poll`, which takes
//! the received frames of each device and runs the timers of the neighbour table. The bottom half
//! runs in the idle loop and after each interrupt in user mode, thus at least at each tick of the
//! timer when a process runs. The poll also runs the timers of TCP. A send also calls `poll`, so
//! that a packet on the loopback device arrives before the send returns, as on Linux.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod checksum;
pub mod config;
pub mod fib;
mod ioctl;
pub mod ipv4;
pub mod neigh;
pub mod ports;
mod procfs;
pub mod route;
mod rtnl;
pub mod sockaddr;
mod socket;
mod stack;
pub mod tcp;

pub use socket::{Dgram, Proto, classify, new_socket};
pub use stack::{COUNTERS, Counters, poll, receive};
pub use tcp::Stream;

use alloc::string::String;
use rk_abi::Errno;
use rk_abi::native::netlink::NLM_F_CREATE;
use rk_net::consts::AF_INET;
use rk_net::dev::{self, Event, LinkKind};
use rk_vfs::inode::Result;

/// Registers the parts of IPv4 in rtnetlink and in the ioctls of the devices, sets up the
/// loopback device with `127.0.0.1/8` and starts the poll of the devices. The kernel calls this
/// one time, after the drivers.
pub fn init() {
    rk_net::netlink::init();
    rtnl::init();
    procfs::init();
    rk_net::netlink::link::register_af(AF_INET as u16, fib::fill_link_af);
    rk_net::ioctl::set_ifconf(fib::ifconf);
    dev::add_notifier(fib::event);
    if let Some(lo) = dev::by_name("lo") {
        if lo.is_up() {
            fib::event(&lo, Event::Up);
        } else {
            lo.set_up(true);
        }
    }
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    rk_frame::task::add_bottom_half(poll);
}

/// Configures an Ethernet device from the value of `ip=` on the kernel command line, as
/// net/ipv4/ipconfig.c of Linux: the address with the netmask and the broadcast address, and
/// the default route. Gives the name of the device.
///
/// # Errors
///
/// Gives `EINVAL` for a value that is not valid or not static, `ENODEV` if the device is not
/// there, and the errors of the address and the route.
pub fn configure(value: &str) -> Result<String> {
    let c = config::parse(value).map_err(|_| Errno::EINVAL)?;
    let dev = match &c.device {
        Some(name) => dev::by_name(name),
        None => dev::devices().into_iter().find(|d| d.kind() == LinkKind::Ether),
    }
    .ok_or(Errno::ENODEV)?;
    dev.set_up(true);
    fib::set_addr(dev.ifindex(), c.addr, c.prefix)?;
    if let Some(gw) = c.gateway {
        let mut r = route::Route::new(ipv4::ANY, 0, Some(gw), dev.ifindex());
        fib::check_route(&mut r)?;
        fib::add_route(r, NLM_F_CREATE, rk_net::netlink::Origin::KERNEL)?;
    }
    Ok(dev.name())
}

#[cfg(test)]
mod tests;

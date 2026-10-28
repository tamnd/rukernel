//! The IPv4 and IPv6 stack: ARP neighbours, IPv4, the routes, ICMP, TCP, and the UDP, ICMP echo
//! and raw sockets, as net/ipv4 of Linux, and IPv6 with neighbour discovery, the addresses and
//! the routes of IPv6, and ICMPv6, as net/ipv6 of Linux.
//!
//! The pure parts are in their own modules, so that the host tests can run them: the checksum,
//! the headers, the neighbour table, the route table, the port table and the parser of `ip=`.
//! The module `stack` has the global tables and the paths of the packets, `socket` has the
//! datagram sockets, and `tcp` has TCP. The sockets of both families share the code: they keep
//! IPv4 addresses as IPv4-mapped IPv6 addresses (`ip`). The module `stack6` has the paths of the
//! IPv6 packets, neighbour discovery and ICMPv6, `route6` has the addresses and the routes of
//! IPv6, and `addrconf` gives the devices their addresses and has the rtnetlink messages of
//! `AF_INET6`.
//!
//! The drivers poll, and on arm64 a device interrupt only wakes an idle CPU. A bottom half of the
//! kernel calls `poll`, which takes the received frames of each device and runs the timers of the
//! neighbour table. The bottom half runs in the idle loop and after each interrupt in user mode,
//! thus at least at each tick of the timer when a process runs. The poll also runs the timers of
//! TCP. A send also calls `poll`, so that a packet on the loopback device arrives before the send
//! returns, as on Linux.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod addrconf;
pub mod checksum;
pub mod config;
pub mod fib;
mod ioctl;
pub mod ip;
pub mod ipv4;
pub mod ipv6;
pub mod neigh;
pub mod ports;
mod procfs;
pub mod route;
pub mod route6;
mod rtnl;
pub mod sockaddr;
mod socket;
mod stack;
mod stack6;
pub mod tcp;

pub use socket::{Dgram, Proto, classify, classify6, new_socket, new_socket6};
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
    addrconf::init();
    procfs::init();
    rk_net::netlink::link::register_af(AF_INET as u16, fib::fill_link_af);
    rk_net::ioctl::set_ifconf(fib::ifconf);
    dev::add_notifier(fib::event);
    dev::add_notifier(addrconf::event);
    rk_net::sysctl::add_hook(addrconf::sysctl_hook);
    rk_net::ns::add_ops(ns_init, ns_exit);
    if let Some(lo) = dev::by_name("lo") {
        if lo.is_up() {
            fib::event(&lo, Event::Up);
            addrconf::event(&lo, Event::Up);
        } else {
            lo.set_up(true);
        }
    }
    #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
    rk_frame::task::add_bottom_half(poll);
}

/// Makes the parts of IPv4 and IPv6 of a new namespace. The tables come at the first use, and
/// the loopback device gets its addresses when it goes up.
fn ns_init() {}

/// Clears the tables of a namespace that stops, as the `exit` of the `pernet_operations` of
/// IPv4 and IPv6 in Linux.
fn ns_exit() {
    tcp::ns_exit();
    stack6::ns_exit();
    stack::ns_exit();
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

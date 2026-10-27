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
pub mod ipv4;
pub mod neigh;
pub mod ports;
pub mod route;
pub mod sockaddr;
mod socket;
mod stack;
pub mod tcp;

pub use socket::{Dgram, Proto, classify, new_socket};
pub use stack::{COUNTERS, Counters, add_addr, add_route, poll, receive};
pub use tcp::Stream;

use alloc::string::String;
use rk_abi::Errno;
use rk_net::dev::{self, LinkKind};
use rk_vfs::inode::Result;

/// Sets up the loopback device with `127.0.0.1/8` and starts the poll of the devices. The kernel
/// calls this one time, after the drivers.
pub fn init() {
    if let Some(lo) = dev::by_name("lo") {
        lo.set_up(true);
        // The loopback device and a valid prefix cannot fail.
        let _ = add_addr(lo.ifindex(), ipv4::LOOPBACK, 8);
    }
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    rk_frame::task::add_bottom_half(poll);
}

/// Configures an Ethernet device from the value of `ip=` on the kernel command line: the
/// address, the connected route and the default route. Gives the name of the device.
///
/// # Errors
///
/// Gives `EINVAL` for a value that is not valid or not static, and `ENODEV` if the device is
/// not there.
pub fn configure(value: &str) -> Result<String> {
    let c = config::parse(value).map_err(|_| Errno::EINVAL)?;
    let dev = match &c.device {
        Some(name) => dev::by_name(name),
        None => dev::devices().into_iter().find(|d| d.kind() == LinkKind::Ether),
    }
    .ok_or(Errno::ENODEV)?;
    dev.set_up(true);
    add_addr(dev.ifindex(), c.addr, c.prefix)?;
    if let Some(gw) = c.gateway {
        add_route(ipv4::ANY, 0, Some(gw), dev.ifindex())?;
    }
    Ok(String::from(dev.name()))
}

#[cfg(test)]
mod tests;

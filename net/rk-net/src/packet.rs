//! The packet sockets of the family `AF_PACKET`, as net/packet/af_packet.c of Linux.
//!
//! A packet socket sends whole link frames on one device. It also gives the ioctls of the
//! devices, for example `SIOCGIFINDEX`, as each socket of Linux does. Programs such as
//! `tst_ns_ifmove` of LTP make one only for these ioctls.
//!
//! This socket does not get the frames that the devices receive yet: a receive waits until its
//! timeout or a signal.

use crate::buf::NetBuf;
use crate::consts::{MSG_DONTWAIT, MSG_OOB, SOCK_DGRAM, SOCK_RAW};
use crate::dev;
use crate::ether::{EthHeader, HLEN, MacAddr};
use crate::options::Options;
use crate::{Message, PathOps, Received, Socket, next_ino, wait_for};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU32, Ordering};
use rk_abi::Errno;
use rk_abi::native::poll::{POLLOUT, POLLWRBAND, POLLWRNORM};
use rk_abi::native::socket::{
    SO_ACCEPTCONN, SO_DOMAIN, SO_ERROR, SO_PROTOCOL, SO_TYPE, SOL_SOCKET,
};
use rk_frame::sync::SpinLock;
use rk_vfs::inode::Result;
use rk_vfs::wait::WaitQueue;

/// The family of the packet sockets, `AF_PACKET` of <linux/socket.h>.
pub const AF_PACKET: u32 = 17;

/// The size of `struct sockaddr_ll` of <linux/if_packet.h>.
const SOCKADDR_LL: usize = 20;

/// A packet socket.
pub struct PacketSocket {
    ino: u64,
    kind: u32,
    /// The protocol in network byte order, as the caller gave it.
    protocol: AtomicU32,
    /// The device of `bind`, or 0 for all devices.
    ifindex: AtomicU32,
    options: SpinLock<Options>,
    wait: WaitQueue,
}

impl PacketSocket {
    /// Makes a packet socket, as `packet_create` of Linux. The caller checks `CAP_NET_RAW`.
    ///
    /// # Errors
    ///
    /// Gives `ESOCKTNOSUPPORT` for a type that is not `SOCK_RAW` or `SOCK_DGRAM`.
    pub fn new(kind: u32, protocol: u32) -> Result<Arc<Self>> {
        if kind != SOCK_RAW && kind != SOCK_DGRAM {
            return Err(Errno::ESOCKTNOSUPPORT);
        }
        Ok(Arc::new(Self {
            ino: next_ino(),
            kind,
            protocol: AtomicU32::new(protocol & 0xffff),
            ifindex: AtomicU32::new(0),
            options: SpinLock::new(Options::default()),
            wait: WaitQueue::new(),
        }))
    }
}

/// The fields of a `struct sockaddr_ll`: the protocol, the interface index and the address.
fn parse_addr(addr: &[u8]) -> Result<(u16, u32, MacAddr)> {
    if addr.len() < SOCKADDR_LL {
        return Err(Errno::EINVAL);
    }
    if u32::from(u16::from_ne_bytes([addr[0], addr[1]])) != AF_PACKET {
        return Err(Errno::EINVAL);
    }
    let protocol = u16::from_ne_bytes([addr[2], addr[3]]);
    let ifindex = u32::from_ne_bytes([addr[4], addr[5], addr[6], addr[7]]);
    let mut mac = [0; 6];
    mac.copy_from_slice(&addr[12..18]);
    Ok((protocol, ifindex, MacAddr(mac)))
}

impl Socket for PacketSocket {
    fn family(&self) -> u32 {
        AF_PACKET
    }

    fn kind(&self) -> u32 {
        self.kind
    }

    fn protocol(&self) -> u32 {
        self.protocol.load(Ordering::Relaxed)
    }

    fn ino(&self) -> u64 {
        self.ino
    }

    /// Binds the socket to one device, as `packet_bind` of Linux. Index 0 means all devices.
    fn bind(&self, _paths: &dyn PathOps, addr: &[u8]) -> Result<()> {
        let (protocol, ifindex, _) = parse_addr(addr)?;
        if ifindex != 0 && dev::by_index(ifindex).is_none() {
            return Err(Errno::ENODEV);
        }
        if protocol != 0 {
            self.protocol.store(u32::from(protocol), Ordering::Relaxed);
        }
        self.ifindex.store(ifindex, Ordering::Relaxed);
        Ok(())
    }

    /// Sends one frame, as `packet_snd` of Linux. A `SOCK_RAW` socket gives the whole frame. A
    /// `SOCK_DGRAM` socket gives the payload, and the kernel adds the link header.
    fn send(
        &self,
        _paths: &dyn PathOps,
        msg: Message,
        flags: u32,
        _nonblock: bool,
    ) -> Result<usize> {
        if flags & MSG_OOB != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let (protocol, ifindex, dst) = match msg.addr.as_deref() {
            Some(a) if !a.is_empty() => parse_addr(a)?,
            _ => (self.protocol() as u16, self.ifindex.load(Ordering::Relaxed), MacAddr::BROADCAST),
        };
        // No device gives `ENXIO`, as Linux.
        let dev = dev::by_index(ifindex).ok_or(Errno::ENXIO)?;
        let len = msg.data.len();
        let mut frame = NetBuf::new(HLEN, len);
        frame.put(len).copy_from_slice(&msg.data);
        if self.kind == SOCK_DGRAM {
            let h = EthHeader { dst, src: dev.mac(), ethertype: u16::from_be(protocol) };
            h.push(&mut frame);
        } else if len < HLEN {
            return Err(Errno::EINVAL);
        }
        dev.transmit(frame)?;
        Ok(len)
    }

    fn recv(&self, _len: usize, flags: u32, nonblock: bool) -> Result<Received> {
        if flags & MSG_OOB != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let nonblock = nonblock || flags & MSG_DONTWAIT != 0;
        let timeout = self.options.lock().rcvtimeo;
        wait_for(&self.wait, timeout, || if nonblock { Err(Errno::EAGAIN) } else { Ok(None) })
    }

    /// Gives the `struct sockaddr_ll` of the socket, as `packet_getname` of Linux.
    fn name(&self) -> Vec<u8> {
        let ifindex = self.ifindex.load(Ordering::Relaxed);
        let mut a = [0u8; SOCKADDR_LL];
        a[..2].copy_from_slice(&(AF_PACKET as u16).to_ne_bytes());
        a[2..4].copy_from_slice(&(self.protocol() as u16).to_ne_bytes());
        a[4..8].copy_from_slice(&ifindex.to_ne_bytes());
        if let Some(d) = dev::by_index(ifindex) {
            a[8..10].copy_from_slice(&d.kind().arphrd().to_ne_bytes());
            a[11] = 6;
            a[12..18].copy_from_slice(&d.mac().0);
        }
        a.to_vec()
    }

    fn get_option(&self, level: u32, name: u32) -> Result<Vec<u8>> {
        if level != SOL_SOCKET {
            return Err(Errno::ENOPROTOOPT);
        }
        let int = |v: u32| (v as i32).to_ne_bytes().to_vec();
        Ok(match name {
            SO_TYPE => int(self.kind),
            SO_DOMAIN => int(AF_PACKET),
            SO_PROTOCOL => int(self.protocol()),
            SO_ERROR | SO_ACCEPTCONN => int(0),
            _ => self.options.lock().get(name)?,
        })
    }

    fn set_option(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
        if level != SOL_SOCKET {
            return Err(Errno::ENOPROTOOPT);
        }
        match name {
            SO_TYPE | SO_DOMAIN | SO_PROTOCOL | SO_ERROR | SO_ACCEPTCONN => Err(Errno::ENOPROTOOPT),
            _ => self.options.lock().set(name, value),
        }
    }

    fn poll(&self) -> u32 {
        POLLOUT | POLLWRNORM | POLLWRBAND
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

//! The ioctls of the network devices that each socket shares, as `dev_ioctl` and `dev_ifconf` of
//! net/core/dev_ioctl.c of Linux.
//!
//! A call takes a `struct ifreq`: the name of the device, then a union of the value. A family
//! can take a call first with `Socket::ioctl`, as the IPv4 family does with the addresses. The
//! calls that it does not take come here.

use crate::consts::AF_UNSPEC;
use crate::dev::{self, LinkKind, NetDevice};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::sockios::{
    SIOCADDMULTI, SIOCBONDCHANGEACTIVE, SIOCBONDENSLAVE, SIOCBONDINFOQUERY, SIOCBONDRELEASE,
    SIOCBONDSETHWADDR, SIOCBONDSLAVEINFOQUERY, SIOCDELMULTI, SIOCDEVPRIVATE, SIOCETHTOOL,
    SIOCGHWTSTAMP, SIOCGIFFLAGS, SIOCGIFHWADDR, SIOCGIFINDEX, SIOCGIFMAP, SIOCGIFMEM,
    SIOCGIFMETRIC, SIOCGIFMTU, SIOCGIFNAME, SIOCGIFSLAVE, SIOCGIFTXQLEN, SIOCGMIIPHY, SIOCGMIIREG,
    SIOCSHWTSTAMP, SIOCSIFFLAGS, SIOCSIFHWADDR, SIOCSIFHWBROADCAST, SIOCSIFLINK, SIOCSIFMAP,
    SIOCSIFMEM, SIOCSIFMETRIC, SIOCSIFMTU, SIOCSIFNAME, SIOCSIFSLAVE, SIOCSIFTXQLEN, SIOCSMIIREG,
    SIOCWANDEV,
};
use rk_frame::sync::SpinLock;
use rk_vfs::UserMemory;
use rk_vfs::cred::{self, cap};
use rk_vfs::inode::Result;

/// The size of `struct ifreq` on a 64-bit machine.
pub const IFREQ_LEN: usize = 40;
/// The size of `struct ifconf` on a 64-bit machine.
const IFCONF_LEN: usize = 16;
/// The offset of the union in `struct ifreq`.
const DATA: usize = 16;
/// The type of the socket ioctls, `SOCK_IOC_TYPE` of Linux.
const SOCK_IOC_TYPE: u32 = 0x89;

/// Tells if `cmd` is a socket ioctl, as `is_socket_ioctl_cmd` of Linux.
pub fn is_socket_cmd(cmd: u32) -> bool {
    (cmd >> 8) & 0xff == SOCK_IOC_TYPE
}

/// Tells if the current process has `CAP_NET_ADMIN`.
pub fn net_admin() -> bool {
    cred::current().capable(cap::NET_ADMIN)
}

/// A `struct ifreq` in kernel memory.
#[derive(Clone)]
pub struct IfReq {
    /// The bytes of the structure.
    pub buf: [u8; IFREQ_LEN],
}

impl IfReq {
    /// Reads the structure at `arg`, as `get_user_ifreq` of Linux. The name always ends with a
    /// zero.
    ///
    /// # Errors
    ///
    /// Gives `EFAULT` if the memory is not there.
    pub fn read(mem: &dyn UserMemory, arg: usize) -> Result<Self> {
        let mut buf = [0; IFREQ_LEN];
        mem.read(arg, &mut buf).map_err(|_| Errno::EFAULT)?;
        buf[crate::consts::IFNAMSIZ - 1] = 0;
        Ok(Self { buf })
    }

    /// Writes the structure back at `arg`, as `put_user_ifreq` of Linux.
    ///
    /// # Errors
    ///
    /// Gives `EFAULT` if the memory is not there.
    pub fn write(&self, mem: &dyn UserMemory, arg: usize) -> Result<()> {
        mem.write(arg, &self.buf).map_err(|_| Errno::EFAULT)
    }

    /// The name, without the zero at the end.
    pub fn name(&self) -> &[u8] {
        let end = self.buf[..crate::consts::IFNAMSIZ].iter().position(|&b| b == 0).unwrap_or(0);
        &self.buf[..end]
    }

    /// The name of the device: the name up to a colon. A name as `eth0:1` names an alias of
    /// the addresses of `eth0`.
    pub fn dev_name(&self) -> &[u8] {
        let name = self.name();
        let end = name.iter().position(|&b| b == b':').unwrap_or(name.len());
        &name[..end]
    }

    /// Tells if the name has a colon.
    pub fn has_colon(&self) -> bool {
        self.name().contains(&b':')
    }

    /// Sets the name.
    pub fn set_name(&mut self, name: &str) {
        let n = name.len().min(crate::consts::IFNAMSIZ - 1);
        self.buf[..n].copy_from_slice(&name.as_bytes()[..n]);
        self.buf[n] = 0;
    }

    /// The `int` of the union, as `ifr_ifindex` and `ifr_mtu`.
    pub fn int(&self) -> i32 {
        i32::from_ne_bytes([self.buf[16], self.buf[17], self.buf[18], self.buf[19]])
    }

    /// Sets the `int` of the union.
    pub fn set_int(&mut self, v: i32) {
        self.buf[DATA..DATA + 4].copy_from_slice(&v.to_ne_bytes());
    }

    /// The `short` of the union, `ifr_flags`.
    pub fn short(&self) -> i16 {
        i16::from_ne_bytes([self.buf[16], self.buf[17]])
    }

    /// Sets the `short` of the union.
    pub fn set_short(&mut self, v: i16) {
        self.buf[DATA..DATA + 2].copy_from_slice(&v.to_ne_bytes());
    }

    /// The family of the `struct sockaddr` of the union.
    pub fn family(&self) -> u16 {
        u16::from_ne_bytes([self.buf[16], self.buf[17]])
    }

    /// The IPv4 address of the `struct sockaddr_in` of the union.
    pub fn addr4(&self) -> [u8; 4] {
        [self.buf[20], self.buf[21], self.buf[22], self.buf[23]]
    }

    /// Sets the union to a `struct sockaddr_in` with the address `a` and the port 0.
    pub fn set_addr4(&mut self, family: u16, a: [u8; 4]) {
        self.buf[DATA..DATA + 16].fill(0);
        self.buf[DATA..DATA + 2].copy_from_slice(&family.to_ne_bytes());
        self.buf[20..24].copy_from_slice(&a);
    }

    /// The second name of the union, `ifr_newname`.
    pub fn new_name(&self) -> &[u8] {
        let raw = &self.buf[DATA..DATA + crate::consts::IFNAMSIZ - 1];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        &raw[..end]
    }
}

/// The function that gives the IPv4 addresses of a device for `SIOCGIFCONF`: the label and the
/// address of each.
pub type IfconfFn = fn(ifindex: u32) -> Vec<(String, [u8; 4])>;

static IFCONF: SpinLock<Option<IfconfFn>> = SpinLock::new(None);

/// Sets the function that gives the IPv4 addresses for `SIOCGIFCONF`. The IPv4 stack calls this
/// at boot.
pub fn set_ifconf(f: IfconfFn) {
    *IFCONF.lock() = Some(f);
}

/// `SIOCGIFCONF`: writes a `struct ifreq` for each IPv4 address of each device, as
/// `dev_ifconf` and `inet_gifconf` of Linux. A null buffer gives the size that the list needs.
///
/// # Errors
///
/// Gives `EFAULT` if the memory is not there.
pub fn ifconf(arg: usize, mem: &dyn UserMemory) -> Result<usize> {
    let mut ifc = [0u8; IFCONF_LEN];
    mem.read(arg, &mut ifc).map_err(|_| Errno::EFAULT)?;
    let len = i32::from_ne_bytes([ifc[0], ifc[1], ifc[2], ifc[3]]);
    let mut ptr = [0u8; 8];
    ptr.copy_from_slice(&ifc[8..16]);
    let pos = usize::try_from(u64::from_ne_bytes(ptr)).unwrap_or(usize::MAX);
    let addrs = *IFCONF.lock();
    let size = IFREQ_LEN as i32;
    let mut total: i32 = 0;
    for d in dev::devices() {
        let list = addrs.map(|f| f(d.ifindex())).unwrap_or_default();
        let mut left = len.wrapping_sub(total);
        let mut done: i32 = 0;
        for (label, a) in list {
            if pos == 0 {
                done += size;
                continue;
            }
            if left < size {
                break;
            }
            let mut r = IfReq { buf: [0; IFREQ_LEN] };
            r.set_name(&label);
            r.set_addr4(crate::consts::AF_INET as u16, a);
            let at = pos + (total + done) as usize;
            mem.write(at, &r.buf).map_err(|_| Errno::EFAULT)?;
            left -= size;
            done += size;
        }
        total += done;
    }
    mem.write(arg, &total.to_ne_bytes()).map_err(|_| Errno::EFAULT)?;
    Ok(0)
}

/// Finds the device of the name in `r`.
fn find(r: &IfReq) -> Result<Arc<NetDevice>> {
    core::str::from_utf8(r.dev_name()).ok().and_then(dev::by_name).ok_or(Errno::ENODEV)
}

/// The ioctls of the network devices, as `dev_ioctl` of Linux. The socket file calls this for a
/// socket ioctl that the family does not take.
///
/// # Errors
///
/// Gives the error of Linux for each call: `ENODEV` for a name that no device has, `EPERM`
/// for a change without `CAP_NET_ADMIN`, and `ENOTTY` for an unknown call.
pub fn dev_ioctl(cmd: u32, arg: usize, mem: &dyn UserMemory) -> Result<usize> {
    let mut r = IfReq::read(mem, arg)?;
    let copyout = match cmd {
        SIOCGIFNAME => {
            let d = u32::try_from(r.int()).ok().and_then(dev::by_index).ok_or(Errno::ENODEV)?;
            r.set_name(&d.name());
            true
        }
        SIOCGIFHWADDR => {
            let d = find(&r)?;
            r.buf[DATA..DATA + 2].copy_from_slice(&d.kind().arphrd().to_ne_bytes());
            r.buf[DATA + 2..DATA + 8].copy_from_slice(&d.mac().0);
            true
        }
        SIOCGIFFLAGS | SIOCGIFMETRIC | SIOCGIFMTU | SIOCGIFSLAVE | SIOCGIFMAP | SIOCGIFINDEX
        | SIOCGIFTXQLEN => {
            let d = find(&r)?;
            match cmd {
                // The `short` holds the low 16 bits, as Linux does it.
                SIOCGIFFLAGS => r.set_short(d.flags() as u16 as i16),
                SIOCGIFMETRIC => r.set_int(0),
                SIOCGIFMTU => r.set_int(d.mtu() as i32),
                SIOCGIFSLAVE => return Err(Errno::EINVAL),
                // The drivers have no memory window, port or interrupt to show.
                SIOCGIFMAP => r.buf[DATA..DATA + 21].fill(0),
                SIOCGIFINDEX => r.set_int(d.ifindex() as i32),
                _ => r.set_int(d.txqlen() as i32),
            }
            true
        }
        SIOCETHTOOL => {
            find(&r)?;
            return Err(Errno::EOPNOTSUPP);
        }
        SIOCGMIIPHY | SIOCGMIIREG | SIOCSIFNAME => {
            if !net_admin() {
                return Err(Errno::EPERM);
            }
            let d = find(&r)?;
            if cmd == SIOCSIFNAME {
                let new = r.new_name().to_vec();
                if d.name().as_bytes() != new.as_slice() {
                    d.set_name(&new)?;
                }
            } else {
                // The drivers have no MII registers, as a driver without `ndo_eth_ioctl`.
                return Err(Errno::EOPNOTSUPP);
            }
            true
        }
        SIOCSIFMAP
        | SIOCSIFTXQLEN
        | SIOCSIFFLAGS
        | SIOCSIFMETRIC
        | SIOCSIFMTU
        | SIOCSIFHWADDR
        | SIOCSIFSLAVE
        | SIOCADDMULTI
        | SIOCDELMULTI
        | SIOCSIFHWBROADCAST
        | SIOCSMIIREG
        | SIOCBONDENSLAVE
        | SIOCBONDRELEASE
        | SIOCBONDSETHWADDR
        | SIOCBONDCHANGEACTIVE
        | SIOCSHWTSTAMP
        | SIOCBONDSLAVEINFOQUERY
        | SIOCBONDINFOQUERY => {
            let query = matches!(cmd, SIOCBONDSLAVEINFOQUERY | SIOCBONDINFOQUERY);
            if !query && !net_admin() {
                return Err(Errno::EPERM);
            }
            set(&*find(&r)?, cmd, &r)?;
            false
        }
        SIOCGIFMEM | SIOCSIFMEM | SIOCSIFLINK => return Err(Errno::ENOTTY),
        SIOCWANDEV | SIOCGHWTSTAMP => {
            find(&r)?;
            return Err(Errno::EOPNOTSUPP);
        }
        c if (SIOCDEVPRIVATE..=SIOCDEVPRIVATE + 15).contains(&c) => {
            find(&r)?;
            return Err(Errno::EOPNOTSUPP);
        }
        _ => return Err(Errno::ENOTTY),
    };
    if copyout {
        r.write(mem, arg)?;
    }
    Ok(0)
}

/// The calls that change a device, as `dev_ifsioc` of Linux.
fn set(d: &NetDevice, cmd: u32, r: &IfReq) -> Result<()> {
    match cmd {
        // `ifr_flags` is a `short`, and Linux extends its sign.
        SIOCSIFFLAGS => d.change_flags(i32::from(r.short()) as u32),
        SIOCSIFMTU => d.set_mtu(u32::try_from(r.int()).map_err(|_| Errno::EINVAL)?),
        SIOCSIFTXQLEN => {
            d.set_txqlen(u32::try_from(r.int()).map_err(|_| Errno::EINVAL)?);
            Ok(())
        }
        SIOCSIFHWBROADCAST => {
            if r.family() != d.kind().arphrd() {
                return Err(Errno::EINVAL);
            }
            // The devices keep the broadcast address of their kind.
            Err(Errno::EOPNOTSUPP)
        }
        SIOCADDMULTI | SIOCDELMULTI => {
            // The loopback device has no receive filter. The Ethernet devices take all of the
            // multicast frames, so the list of addresses has no effect.
            if d.kind() == LinkKind::Loopback || u32::from(r.family()) != AF_UNSPEC {
                return Err(Errno::EINVAL);
            }
            Ok(())
        }
        // The drivers cannot change the hardware address and have no MII registers, time
        // stamps, configuration or bonding, as drivers without the operations in Linux.
        SIOCSIFMETRIC
        | SIOCSIFHWADDR
        | SIOCSIFMAP
        | SIOCSMIIREG
        | SIOCSHWTSTAMP
        | SIOCBONDENSLAVE
        | SIOCBONDRELEASE
        | SIOCBONDSETHWADDR
        | SIOCBONDCHANGEACTIVE
        | SIOCBONDSLAVEINFOQUERY
        | SIOCBONDINFOQUERY => Err(Errno::EOPNOTSUPP),
        _ => Err(Errno::EINVAL),
    }
}

//! The parameter `ip=` of the kernel command line, as Documentation/admin-guide/nfs/nfsroot.rst
//! and net/ipv4/ipconfig.c of Linux:
//!
//! `ip=<client-ip>:<server-ip>:<gw-ip>:<netmask>:<hostname>:<device>:<autoconf>`
//!
//! Only the static form is here. The automatic forms (`dhcp`, `bootp`, `rarp`) need a client of
//! those protocols, and the parser gives `Err` for them.

use crate::ipv4::{self, Addr};
use alloc::string::String;

/// A static configuration of one interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpConfig {
    /// The address of the interface.
    pub addr: Addr,
    /// The length of the prefix of the subnet.
    pub prefix: u8,
    /// The default gateway.
    pub gateway: Option<Addr>,
    /// The name of the device, or `None` for the first Ethernet device.
    pub device: Option<String>,
    /// The host name.
    pub hostname: Option<String>,
}

/// The reasons that `parse` does not give a configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The value is `off` or `none`: no configuration.
    Off,
    /// The value asks for an automatic protocol, which the kernel does not have.
    Auto,
    /// The value is not valid.
    Invalid,
}

/// Reads a dotted IPv4 address, as `in_aton` of Linux but strict.
pub fn parse_addr(s: &str) -> Option<Addr> {
    let mut a = [0u8; 4];
    let mut parts = s.split('.');
    for b in &mut a {
        *b = parts.next()?.parse().ok()?;
    }
    parts.next().is_none().then_some(a)
}

/// The prefix length of a netmask. Gives `None` if the ones are not contiguous.
pub fn mask_to_prefix(mask: Addr) -> Option<u8> {
    let m = u32::from_be_bytes(mask);
    let prefix = m.leading_ones() as u8;
    (ipv4::mask(prefix) == m).then_some(prefix)
}

/// The prefix of the class of `a`, for an empty netmask, as `ic_defaults` of Linux.
fn class_prefix(a: Addr) -> u8 {
    match a[0] {
        0..=127 => 8,
        128..=191 => 16,
        _ => 24,
    }
}

/// Reads the value of `ip=`.
///
/// # Errors
///
/// Gives `Error::Off` for `off` or `none`, `Error::Auto` for an automatic protocol, and
/// `Error::Invalid` for a value without a valid client address.
pub fn parse(value: &str) -> Result<IpConfig, Error> {
    match value {
        "off" | "none" => return Err(Error::Off),
        "on" | "any" | "dhcp" | "bootp" | "rarp" | "both" => return Err(Error::Auto),
        _ => {}
    }
    let mut f = value.split(':');
    let mut field = || f.next().filter(|s| !s.is_empty());
    let addr = field().and_then(parse_addr).ok_or(Error::Invalid)?;
    let _server = field();
    let gateway = match field() {
        Some(g) => Some(parse_addr(g).ok_or(Error::Invalid)?),
        None => None,
    };
    let prefix = match field() {
        Some(m) => mask_to_prefix(parse_addr(m).ok_or(Error::Invalid)?).ok_or(Error::Invalid)?,
        None => class_prefix(addr),
    };
    let hostname = field().map(String::from);
    let device = field().map(String::from);
    match field() {
        None | Some("off" | "none") => {}
        Some(_) => return Err(Error::Auto),
    }
    Ok(IpConfig { addr, prefix, gateway, device, hostname })
}

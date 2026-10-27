//! The format of the netlink messages and of their attributes, as include/net/netlink.h and
//! lib/nlattr.c of Linux.
//!
//! A message has a header of 16 bytes, a fixed header of its family, and a list of attributes.
//! Each attribute has a header of 4 bytes, and the message pads each attribute to 4 bytes. All
//! the numbers are in the byte order of the machine.

use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::netlink::{NLA_TYPE_MASK, NLM_F_CAPPED, NLM_F_MULTI, NLMSG_DONE, NLMSG_ERROR};
use rk_vfs::inode::Result;

/// The size of the header of a message, `NLMSG_HDRLEN`.
pub const HDRLEN: usize = 16;
/// The size of the header of an attribute, `NLA_HDRLEN`.
pub const ATTR_HDRLEN: usize = 4;

/// Rounds `n` up to 4 bytes, as `NLMSG_ALIGN` and `NLA_ALIGN`.
pub const fn align(n: usize) -> usize {
    (n + 3) & !3
}

/// The header of a message, `struct nlmsghdr`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// The length of the message with the header.
    pub len: u32,
    /// The type.
    pub ty: u16,
    /// The flags `NLM_F_*`.
    pub flags: u16,
    /// The sequence number.
    pub seq: u32,
    /// The port ID of the sender.
    pub pid: u32,
}

impl Header {
    /// Reads the header at the start of `b`, or gives `None` if `b` is too short.
    pub fn parse(b: &[u8]) -> Option<Self> {
        let b = b.get(..HDRLEN)?;
        Some(Self {
            len: u32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
            ty: u16::from_ne_bytes([b[4], b[5]]),
            flags: u16::from_ne_bytes([b[6], b[7]]),
            seq: u32::from_ne_bytes([b[8], b[9], b[10], b[11]]),
            pid: u32::from_ne_bytes([b[12], b[13], b[14], b[15]]),
        })
    }

    /// The bytes of the header.
    pub fn bytes(&self) -> [u8; HDRLEN] {
        let mut b = [0; HDRLEN];
        b[0..4].copy_from_slice(&self.len.to_ne_bytes());
        b[4..6].copy_from_slice(&self.ty.to_ne_bytes());
        b[6..8].copy_from_slice(&self.flags.to_ne_bytes());
        b[8..12].copy_from_slice(&self.seq.to_ne_bytes());
        b[12..16].copy_from_slice(&self.pid.to_ne_bytes());
        b
    }
}

/// Builds one message, as `nlmsg_put`, the `nla_put_*` functions and `nlmsg_end` of Linux.
pub struct Builder {
    buf: Vec<u8>,
}

impl Builder {
    /// Starts a message with the header fields.
    pub fn new(ty: u16, flags: u16, seq: u32, pid: u32) -> Self {
        let h = Header { len: 0, ty, flags, seq, pid };
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&h.bytes());
        Self { buf }
    }

    /// Adds the fixed header of the family, padded to 4 bytes.
    pub fn fixed(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self.pad();
        self
    }

    fn pad(&mut self) {
        self.buf.resize(align(self.buf.len()), 0);
    }

    /// Adds an attribute, as `nla_put`.
    pub fn put(&mut self, ty: u16, data: &[u8]) -> &mut Self {
        let len = (ATTR_HDRLEN + data.len()) as u16;
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.pad();
        self
    }

    /// Adds an attribute with a `u8`.
    pub fn u8(&mut self, ty: u16, v: u8) -> &mut Self {
        self.put(ty, &[v])
    }

    /// Adds an attribute with a `u16`.
    pub fn u16(&mut self, ty: u16, v: u16) -> &mut Self {
        self.put(ty, &v.to_ne_bytes())
    }

    /// Adds an attribute with a `u32`.
    pub fn u32(&mut self, ty: u16, v: u32) -> &mut Self {
        self.put(ty, &v.to_ne_bytes())
    }

    /// Adds an attribute with a `u32` or a `u64`, as `nla_put_uint`: 4 bytes if the value fits.
    pub fn uint(&mut self, ty: u16, v: u64) -> &mut Self {
        match u32::try_from(v) {
            Ok(v) => self.u32(ty, v),
            Err(_) => self.put(ty, &v.to_ne_bytes()),
        }
    }

    /// Adds an attribute with a string and its NUL byte, as `nla_put_string`.
    pub fn str(&mut self, ty: u16, s: &str) -> &mut Self {
        let len = (ATTR_HDRLEN + s.len() + 1) as u16;
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
        self.pad();
        self
    }

    /// Starts a nested attribute, as `nla_nest_start`. Gives the offset for `end_nest`.
    pub fn nest(&mut self, ty: u16) -> usize {
        let at = self.buf.len();
        self.put(ty, &[]);
        at
    }

    /// Ends the nested attribute that starts at `at`, as `nla_nest_end`.
    pub fn end_nest(&mut self, at: usize) -> &mut Self {
        let len = (self.buf.len() - at) as u16;
        self.buf[at..at + 2].copy_from_slice(&len.to_ne_bytes());
        self
    }

    /// Removes the bytes from `at` on, as `nlmsg_trim` and `nla_nest_cancel` of Linux.
    pub fn truncate(&mut self, at: usize) -> &mut Self {
        self.buf.truncate(at.max(HDRLEN));
        self
    }

    /// The size of the message so far.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Tells if the message has only its header. This is never true.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Sets the length in the header and gives the message.
    pub fn finish(mut self) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

/// The attributes in `b`, as `nla_for_each_attr`. Each item is the type without the flags and
/// the payload. The walk stops at an attribute that does not fit, as `nla_ok`.
pub fn attrs(b: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut rest = b;
    core::iter::from_fn(move || {
        if rest.len() < ATTR_HDRLEN {
            return None;
        }
        let len = u16::from_ne_bytes([rest[0], rest[1]]) as usize;
        let ty = u16::from_ne_bytes([rest[2], rest[3]]);
        if len < ATTR_HDRLEN || len > rest.len() {
            return None;
        }
        let data = &rest[ATTR_HDRLEN..len];
        rest = &rest[align(len).min(rest.len())..];
        Some((ty & NLA_TYPE_MASK as u16, data))
    })
}

/// The attributes of a message, indexed by type, as `nla_parse` of Linux: the last attribute of
/// a type wins, and the types above `max` are not kept.
pub struct Attrs<'a> {
    slots: Vec<Option<&'a [u8]>>,
}

impl<'a> Attrs<'a> {
    /// Parses the attributes in `b` with the types up to `max`.
    pub fn parse(b: &'a [u8], max: u16) -> Self {
        let mut slots = alloc::vec![None; usize::from(max) + 1];
        for (ty, data) in attrs(b) {
            if let Some(slot) = slots.get_mut(usize::from(ty)) {
                *slot = Some(data);
            }
        }
        Self { slots }
    }

    /// The payload of the attribute `ty`.
    pub fn get(&self, ty: u32) -> Option<&'a [u8]> {
        self.slots.get(ty as usize).copied().flatten()
    }

    /// Tells if the message has the attribute `ty`.
    pub fn has(&self, ty: u32) -> bool {
        self.get(ty).is_some()
    }

    /// The attribute `ty` as a `u8`. A short payload gives `ERANGE`, as the policy check of
    /// Linux for `NLA_U8`.
    pub fn u8(&self, ty: u32) -> Result<Option<u8>> {
        self.get(ty).map(|d| d.first().copied().ok_or(Errno::ERANGE)).transpose()
    }

    /// The attribute `ty` as a `u32`.
    pub fn u32(&self, ty: u32) -> Result<Option<u32>> {
        self.get(ty)
            .map(|d| match d.first_chunk::<4>() {
                Some(v) => Ok(u32::from_ne_bytes(*v)),
                None => Err(Errno::ERANGE),
            })
            .transpose()
    }

    /// The attribute `ty` as an IPv4 address.
    pub fn addr4(&self, ty: u32) -> Result<Option<[u8; 4]>> {
        self.get(ty).map(|d| d.first_chunk::<4>().copied().ok_or(Errno::ERANGE)).transpose()
    }

    /// The attribute `ty` as a string: the bytes up to the first NUL byte.
    pub fn str(&self, ty: u32) -> Option<&'a [u8]> {
        self.get(ty).map(|d| d.split(|&c| c == 0).next().unwrap_or(d))
    }
}

/// Builds the error message or the ack for the request `req`, as `netlink_ack` of Linux. An
/// error has a copy of the whole request, unless the socket asked for `NETLINK_CAP_ACK`. An ack
/// and a capped error have only the header of the request and the flag `NLM_F_CAPPED`.
pub fn ack(req: &[u8], err: i32, portid: u32, cap_ack: bool) -> Vec<u8> {
    let h = Header::parse(req).unwrap_or_default();
    let full = err != 0 && !cap_ack;
    let copy = if full { (h.len as usize).min(req.len()) } else { HDRLEN };
    let flags = if full { 0 } else { NLM_F_CAPPED as u16 };
    let mut b = Builder::new(NLMSG_ERROR as u16, flags, h.seq, portid);
    let mut payload = Vec::with_capacity(4 + copy);
    payload.extend_from_slice(&err.to_ne_bytes());
    payload.extend_from_slice(&req[..copy]);
    b.fixed(&payload);
    b.finish()
}

/// Builds the message at the end of a dump, as `netlink_dump_done` of Linux.
pub fn done(seq: u32, portid: u32, status: i32) -> Vec<u8> {
    let mut b = Builder::new(NLMSG_DONE as u16, NLM_F_MULTI as u16, seq, portid);
    b.fixed(&status.to_ne_bytes());
    b.finish()
}

/// The messages in a buffer that a process sent, as `netlink_rcv_skb` of Linux walks them. Each
/// item is one message with its header. The walk stops at a message with a bad length.
pub fn messages(b: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = b;
    core::iter::from_fn(move || {
        let h = Header::parse(rest)?;
        let len = h.len as usize;
        if len < HDRLEN || len > rest.len() {
            return None;
        }
        let msg = &rest[..len];
        rest = &rest[align(len).min(rest.len())..];
        Some(msg)
    })
}

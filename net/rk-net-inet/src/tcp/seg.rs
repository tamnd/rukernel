//! The TCP header of RFC 9293 with the options MSS and window scale, the arithmetic of the
//! sequence numbers, and the checksum, as `struct tcphdr` and `tcp_parse_options` of Linux.

use crate::checksum;
use crate::ipv4::{Addr, PROTO_TCP};
use alloc::vec::Vec;

/// The length of a header without options.
pub const HLEN: usize = 20;

/// The flag FIN: the sender has no more data.
pub const FIN: u8 = 0x01;
/// The flag SYN: synchronize the sequence numbers.
pub const SYN: u8 = 0x02;
/// The flag RST: reset the connection.
pub const RST: u8 = 0x04;
/// The flag PSH: push the data to the reader.
pub const PSH: u8 = 0x08;
/// The flag ACK: the acknowledgment field is valid.
pub const ACK: u8 = 0x10;
/// The flag URG: the urgent pointer is valid.
pub const URG: u8 = 0x20;

/// The option "end of the list".
const OPT_EOL: u8 = 0;
/// The option "no operation".
const OPT_NOP: u8 = 1;
/// The option "maximum segment size".
const OPT_MSS: u8 = 2;
/// The option "window scale" of RFC 7323.
const OPT_WSCALE: u8 = 3;

/// The largest shift of the window scale option, as RFC 7323.
pub const MAX_WSCALE: u8 = 14;

/// Tells if the sequence number `a` is before `b`, modulo 2^32, as `before` of Linux.
pub fn lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Tells if `a` is before `b` or equal to it.
pub fn le(a: u32, b: u32) -> bool {
    !lt(b, a)
}

/// Tells if `a` is after `b`, as `after` of Linux.
pub fn gt(a: u32, b: u32) -> bool {
    lt(b, a)
}

/// Tells if `a` is after `b` or equal to it.
pub fn ge(a: u32, b: u32) -> bool {
    !lt(a, b)
}

/// A segment without the ports: the part that the state machine of a connection reads and
/// writes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Seg {
    /// The sequence number of the first byte, or of the SYN.
    pub seq: u32,
    /// The next sequence number that the sender expects, if the flags have `ACK`.
    pub ack: u32,
    /// The flags.
    pub flags: u8,
    /// The window field, before the scale.
    pub wnd: u16,
    /// The option MSS. Only a SYN has it.
    pub mss: Option<u16>,
    /// The option window scale. Only a SYN has it.
    pub wscale: Option<u8>,
    /// The data.
    pub data: Vec<u8>,
}

impl Seg {
    /// Tells if the segment has all of the flags `f`.
    pub fn has(&self, f: u8) -> bool {
        self.flags & f == f
    }

    /// The length in sequence numbers: the data, and one for SYN and one for FIN.
    pub fn len(&self) -> u32 {
        self.data.len() as u32 + u32::from(self.has(SYN)) + u32::from(self.has(FIN))
    }

    /// Tells if the segment has no sequence numbers.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The bytes of the segment with the ports `sport` and `dport` and the checksum for the
    /// addresses `src` and `dst`.
    pub fn encode(&self, sport: u16, dport: u16, src: Addr, dst: Addr) -> Vec<u8> {
        let mut opts = Vec::new();
        if let Some(mss) = self.mss {
            opts.extend_from_slice(&[OPT_MSS, 4]);
            opts.extend_from_slice(&mss.to_be_bytes());
        }
        if let Some(ws) = self.wscale {
            opts.extend_from_slice(&[OPT_NOP, OPT_WSCALE, 3, ws]);
        }
        let hlen = HLEN + opts.len();
        let mut b = Vec::with_capacity(hlen + self.data.len());
        b.extend_from_slice(&sport.to_be_bytes());
        b.extend_from_slice(&dport.to_be_bytes());
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(&self.ack.to_be_bytes());
        b.push(((hlen / 4) as u8) << 4);
        b.push(self.flags);
        b.extend_from_slice(&self.wnd.to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0]);
        b.extend_from_slice(&opts);
        b.extend_from_slice(&self.data);
        let len = u16::try_from(b.len()).unwrap_or(u16::MAX);
        let sum = checksum::fold(checksum::add(checksum::pseudo(src, dst, PROTO_TCP, len), &b));
        b[16..18].copy_from_slice(&sum.to_be_bytes());
        b
    }
}

/// Reads the segment `tcp` (the header and the data) from `src` to `dst`, as `tcp_v4_rcv` of
/// Linux. Gives the source port, the destination port and the segment, or `None` for a short
/// segment, a bad offset or a bad checksum.
pub fn parse(tcp: &[u8], src: Addr, dst: Addr) -> Option<(u16, u16, Seg)> {
    let h = tcp.get(..HLEN)?;
    let len = u16::try_from(tcp.len()).ok()?;
    if checksum::fold(checksum::add(checksum::pseudo(src, dst, PROTO_TCP, len), tcp)) != 0 {
        return None;
    }
    let off = usize::from(h[12] >> 4) * 4;
    if off < HLEN || off > tcp.len() {
        return None;
    }
    let mut seg = Seg {
        seq: u32::from_be_bytes([h[4], h[5], h[6], h[7]]),
        ack: u32::from_be_bytes([h[8], h[9], h[10], h[11]]),
        flags: h[13],
        wnd: u16::from_be_bytes([h[14], h[15]]),
        mss: None,
        wscale: None,
        data: tcp[off..].to_vec(),
    };
    if seg.has(SYN) {
        options(&tcp[HLEN..off], &mut seg);
    }
    Some((u16::from_be_bytes([h[0], h[1]]), u16::from_be_bytes([h[2], h[3]]), seg))
}

/// Reads the options of a SYN. An option that is not known or not valid is skipped.
fn options(mut o: &[u8], seg: &mut Seg) {
    while let Some((&kind, rest)) = o.split_first() {
        match kind {
            OPT_EOL => return,
            OPT_NOP => o = rest,
            _ => {
                let Some(&len) = rest.first() else { return };
                let len = usize::from(len);
                if len < 2 || len > o.len() {
                    return;
                }
                let body = &o[2..len];
                match (kind, body) {
                    (OPT_MSS, &[a, b]) => seg.mss = Some(u16::from_be_bytes([a, b])),
                    (OPT_WSCALE, &[s]) => seg.wscale = Some(s.min(MAX_WSCALE)),
                    _ => {}
                }
                o = &o[len..];
            }
        }
    }
}

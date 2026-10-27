//! The header of virtio-net, from section 5.1.6 of the virtio 1.2 specification. Each buffer of
//! the receive queue and of the transmit queue starts with it. All fields are little endian.

/// The length of the header. With `F_VERSION_1` the header always has the field `num_buffers`.
pub(crate) const LEN: usize = 12;

/// The header of one packet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NetHdr {
    pub(crate) flags: u8,
    pub(crate) gso_type: u8,
    pub(crate) hdr_len: u16,
    pub(crate) gso_size: u16,
    pub(crate) csum_start: u16,
    pub(crate) csum_offset: u16,
    /// The number of buffers of a received packet. It is 1 without `F_MRG_RXBUF`.
    pub(crate) num_buffers: u16,
}

impl NetHdr {
    /// Reads the header at the start of `b`. Gives `None` if `b` is too short.
    pub(crate) fn parse(b: &[u8]) -> Option<Self> {
        let b = b.get(..LEN)?;
        let le16 = |at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
        Some(Self {
            flags: b[0],
            gso_type: b[1],
            hdr_len: le16(2),
            gso_size: le16(4),
            csum_start: le16(6),
            csum_offset: le16(8),
            num_buffers: le16(10),
        })
    }

    /// The bytes of the header.
    pub(crate) fn to_bytes(self) -> [u8; LEN] {
        let mut b = [0; LEN];
        b[0] = self.flags;
        b[1] = self.gso_type;
        for (at, v) in [
            (2, self.hdr_len),
            (4, self.gso_size),
            (6, self.csum_start),
            (8, self.csum_offset),
            (10, self.num_buffers),
        ] {
            b[at..at + 2].copy_from_slice(&v.to_le_bytes());
        }
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_for_a_plain_packet_is_zeros() {
        // No checksum offload and no segmentation offload, `VIRTIO_NET_HDR_GSO_NONE`.
        assert_eq!(NetHdr::default().to_bytes(), [0; LEN]);
    }

    #[test]
    fn the_header_is_little_endian() {
        let b = [1, 3, 0x36, 0, 0xa8, 0x05, 0x22, 0, 0x10, 0, 1, 0];
        let h = NetHdr::parse(&b).unwrap();
        assert_eq!(
            h,
            NetHdr {
                flags: 1,
                gso_type: 3,
                hdr_len: 54,
                gso_size: 1448,
                csum_start: 34,
                csum_offset: 16,
                num_buffers: 1
            }
        );
        assert_eq!(h.to_bytes(), b);
        assert_eq!(NetHdr::parse(&b[..11]), None);
    }
}

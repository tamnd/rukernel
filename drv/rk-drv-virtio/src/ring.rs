//! The layout of a split virtqueue, from section 2.7 of the virtio 1.2 specification. All fields
//! are little endian.

/// The descriptor continues in the field `next`.
pub(crate) const DESC_F_NEXT: u16 = 1;
/// The device writes the buffer of the descriptor.
pub(crate) const DESC_F_WRITE: u16 = 2;

/// The largest queue that fits the descriptor table in one frame.
pub(crate) const MAX_QUEUE_SIZE: u16 = 256;

/// The bytes of one entry of the descriptor table.
pub(crate) fn descriptor(addr: u64, len: u32, flags: u16, next: u16) -> [u8; 16] {
    let mut d = [0u8; 16];
    d[0..8].copy_from_slice(&addr.to_le_bytes());
    d[8..12].copy_from_slice(&len.to_le_bytes());
    d[12..14].copy_from_slice(&flags.to_le_bytes());
    d[14..16].copy_from_slice(&next.to_le_bytes());
    d
}

/// The offset of the descriptor `index` in the descriptor table.
pub(crate) fn descriptor_offset(index: u16) -> usize {
    usize::from(index) * 16
}

/// The offset of the field `idx` of the available ring and of the used ring.
pub(crate) const IDX_OFFSET: usize = 2;

/// The offset of the entry for `idx` in the available ring of a queue of `size` entries.
pub(crate) fn avail_entry_offset(idx: u16, size: u16) -> usize {
    4 + usize::from(idx % size) * 2
}

/// The offset of the entry for `idx` in the used ring of a queue of `size` entries.
pub(crate) fn used_entry_offset(idx: u16, size: u16) -> usize {
    4 + usize::from(idx % size) * 8
}

/// Gives the queue size to use: the largest power of two that the device and one frame allow.
pub(crate) fn queue_size(device_max: u16) -> u16 {
    let max = device_max.min(MAX_QUEUE_SIZE);
    if max == 0 { 0 } else { 1 << (15 - max.leading_zeros()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_descriptor_is_little_endian() {
        let d = descriptor(0x1122_3344_5566_7788, 0x200, DESC_F_NEXT | DESC_F_WRITE, 5);
        assert_eq!(d, [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0, 2, 0, 0, 3, 0, 5, 0]);
    }

    #[test]
    fn the_rings_wrap_at_the_queue_size() {
        assert_eq!(avail_entry_offset(0, 128), 4);
        assert_eq!(avail_entry_offset(129, 128), 6);
        assert_eq!(used_entry_offset(130, 128), 20);
        assert_eq!(descriptor_offset(255), 4080);
    }

    #[test]
    fn the_queue_fits_in_one_frame() {
        assert_eq!(queue_size(1024), 256);
        assert_eq!(queue_size(256), 256);
        assert_eq!(queue_size(200), 128);
        assert_eq!(queue_size(1), 1);
        assert_eq!(queue_size(0), 0);
    }
}

//! The layout of a split virtqueue, from section 2.7 of the virtio 1.2 specification. All fields
//! are little endian.

use alloc::vec;
use alloc::vec::Vec;

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

/// Reads an entry of the used ring: the first descriptor of the chain and the number of bytes
/// that the device wrote.
pub(crate) fn parse_used_entry(e: [u8; 8]) -> (u32, u32) {
    (u32::from_le_bytes([e[0], e[1], e[2], e[3]]), u32::from_le_bytes([e[4], e[5], e[6], e[7]]))
}

/// The descriptors of a queue, and which of them the device has. A driver that keeps many
/// buffers in a queue takes a free descriptor for each buffer, and gives it back when the device
/// is done. The check of `give_back` stops a bad device from making the driver use a buffer
/// again while the device still has it.
pub(crate) struct Slots {
    free: Vec<u16>,
    busy: Vec<bool>,
}

impl Slots {
    /// Makes `size` free descriptors.
    pub(crate) fn new(size: u16) -> Self {
        Self { free: (0..size).rev().collect(), busy: vec![false; usize::from(size)] }
    }

    /// Takes a free descriptor for the device, or gives `None` if the device has all of them.
    pub(crate) fn take(&mut self) -> Option<u16> {
        let id = self.free.pop()?;
        self.busy[usize::from(id)] = true;
        Some(id)
    }

    /// Gives back the descriptor `id` that the device used. Gives `false` and does nothing if
    /// the device does not have that descriptor.
    pub(crate) fn give_back(&mut self, id: u32) -> bool {
        let Some(busy) = usize::try_from(id).ok().and_then(|i| self.busy.get_mut(i)) else {
            return false;
        };
        if !*busy {
            return false;
        }
        *busy = false;
        self.free.push(id as u16);
        true
    }

    /// The number of descriptors that the device has.
    #[cfg(test)]
    pub(crate) fn in_flight(&self) -> usize {
        self.busy.len() - self.free.len()
    }
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
    fn a_used_entry_gives_the_id_and_the_length() {
        assert_eq!(parse_used_entry([3, 0, 0, 0, 0x2a, 0x05, 0, 0]), (3, 1322));
        assert_eq!(parse_used_entry([0, 0, 1, 0, 0, 0, 0, 0]), (0x1_0000, 0));
    }

    #[test]
    fn slots_take_back_only_what_the_device_has() {
        let mut s = Slots::new(3);
        assert_eq!((s.take(), s.take()), (Some(0), Some(1)));
        assert_eq!(s.in_flight(), 2);
        // The device gives back a descriptor that it does not have, one past the queue, and one
        // with a large ID.
        assert!(!s.give_back(2) && !s.give_back(3) && !s.give_back(0x1_0000));
        assert!(s.give_back(1));
        assert!(!s.give_back(1));
        assert_eq!((s.take(), s.take(), s.take()), (Some(1), Some(2), None));
        assert_eq!(s.in_flight(), 3);
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

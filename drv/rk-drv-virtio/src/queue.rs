//! A split virtqueue. `run` does one request at a time and waits for it. The other functions
//! let a driver keep many buffers in the queue and take them back without a wait.

use crate::pci::{QueueAddrs, Transport};
use crate::ring;
use core::sync::atomic::{Ordering, fence};
use rk_frame::mm::{Frame, alloc_zeroed_frame};

/// One buffer of a request: the physical address, the length, and if the device writes it.
#[derive(Clone, Copy)]
pub(crate) struct Buffer {
    pub(crate) addr: u64,
    pub(crate) len: u32,
    pub(crate) device_writes: bool,
}

/// A queue that the device uses. The frames of the queue stay while the device can read them.
/// The driver resets the device before it drops a queue, and no driver does this yet, so a
/// queue is never dropped.
pub(crate) struct Queue {
    index: u16,
    size: u16,
    notify_at: usize,
    desc: Frame,
    avail: Frame,
    used: Frame,
    /// The next value of the field `idx` of the available ring.
    avail_idx: u16,
    /// The value of the field `idx` of the used ring after the last request.
    used_idx: u16,
}

fn read_u16(frame: &Frame, offset: usize) -> u16 {
    let mut b = [0u8; 2];
    frame.read_bytes(offset, &mut b);
    u16::from_le_bytes(b)
}

impl Queue {
    /// Makes the queue `index` and gives it to the device.
    pub(crate) fn new(t: &Transport, index: u16) -> Option<Self> {
        let size = ring::queue_size(t.queue_max(index));
        if size == 0 {
            return None;
        }
        let (desc, avail, used) =
            (alloc_zeroed_frame()?, alloc_zeroed_frame()?, alloc_zeroed_frame()?);
        let addrs = QueueAddrs {
            desc: desc.addr().get(),
            avail: avail.addr().get(),
            used: used.addr().get(),
        };
        let notify_at = t.enable_queue(index, size, &addrs)?;
        Some(Self { index, size, notify_at, desc, avail, used, avail_idx: 0, used_idx: 0 })
    }

    /// The most buffers in one request.
    pub(crate) fn max_buffers(&self) -> usize {
        usize::from(self.size)
    }

    /// The number of descriptors.
    pub(crate) fn size(&self) -> u16 {
        self.size
    }

    /// Writes the descriptor `id` for the buffer `b`. If `next` is `Some`, the chain continues
    /// at that descriptor.
    pub(crate) fn set_descriptor(&mut self, id: u16, b: Buffer, next: Option<u16>) {
        let mut flags = if b.device_writes { ring::DESC_F_WRITE } else { 0 };
        if next.is_some() {
            flags |= ring::DESC_F_NEXT;
        }
        let d = ring::descriptor(b.addr, b.len, flags, next.unwrap_or(0));
        self.desc.write_bytes(ring::descriptor_offset(id), &d);
    }

    /// Puts the chain that starts at the descriptor `id` in the available ring. The device sees
    /// it after the next `kick`.
    pub(crate) fn push_avail(&mut self, id: u16) {
        self.avail
            .write_bytes(ring::avail_entry_offset(self.avail_idx, self.size), &id.to_le_bytes());
        self.avail_idx = self.avail_idx.wrapping_add(1);
    }

    /// Gives the new entries of the available ring to the device and tells the device.
    pub(crate) fn kick(&mut self, t: &Transport) {
        // The device must see the descriptors and the entries before the new index.
        fence(Ordering::SeqCst);
        self.avail.write_bytes(ring::IDX_OFFSET, &self.avail_idx.to_le_bytes());
        fence(Ordering::SeqCst);
        t.notify(self.notify_at, self.index);
    }

    /// Takes the next entry of the used ring, if the device put one there. Gives the first
    /// descriptor of the chain and the number of bytes that the device wrote.
    pub(crate) fn pop_used(&mut self) -> Option<(u32, u32)> {
        if read_u16(&self.used, ring::IDX_OFFSET) == self.used_idx {
            return None;
        }
        // The driver reads the entry and the buffers only after it sees the new index.
        fence(Ordering::SeqCst);
        let mut entry = [0u8; 8];
        self.used.read_bytes(ring::used_entry_offset(self.used_idx, self.size), &mut entry);
        self.used_idx = self.used_idx.wrapping_add(1);
        Some(ring::parse_used_entry(entry))
    }

    /// Gives the buffers of one request to the device and waits until the device is done.
    /// Gives the number of bytes that the device wrote.
    ///
    /// # Panics
    ///
    /// If `buffers` is empty or has more than `max_buffers` entries.
    pub(crate) fn run(&mut self, t: &Transport, buffers: &[Buffer]) -> u32 {
        assert!(!buffers.is_empty() && buffers.len() <= self.max_buffers(), "bad request");
        // One request at a time, so the chain always starts at descriptor 0.
        for (i, b) in buffers.iter().enumerate() {
            let i = i as u16;
            let next = (usize::from(i) + 1 < buffers.len()).then_some(i + 1);
            self.set_descriptor(i, *b, next);
        }
        self.push_avail(0);
        self.kick(t);
        loop {
            if let Some((_, len)) = self.pop_used() {
                return len;
            }
            core::hint::spin_loop();
        }
    }
}

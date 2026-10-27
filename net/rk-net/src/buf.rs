//! The buffer of one packet, as `struct sk_buff` of Linux in spirit, per spec/10-networking.md
//! section 10.3.
//!
//! A buffer has one contiguous area with three parts: the headroom, the data and the tailroom.
//! Each layer on the transmit path puts its header in the headroom with `push`, so a TCP segment
//! gets its TCP, IPv4 and Ethernet headers without a copy of the payload. Each layer on the
//! receive path removes its header with `pull`. The page fragments, the shared info with the GSO
//! data and the clones of the design come later. They add to this type and do not change the
//! operations here.

use alloc::vec;
use alloc::vec::Vec;

/// The headroom of a new buffer for a packet that the kernel sends. It holds an Ethernet header,
/// an IPv4 header and a TCP header with all options, as `MAX_HEADER` and `MAX_TCP_HEADER` of
/// Linux.
pub const HEADROOM: usize = 128;

/// The buffer of one packet.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetBuf {
    /// All of the area: the headroom, the data and the tailroom.
    area: Vec<u8>,
    /// The start of the data in `area`.
    head: usize,
    /// The end of the data in `area`.
    tail: usize,
    /// The interface index of the device that received the packet, or 0.
    pub ifindex: u32,
    /// The protocol ID of the link header, for example `ETH_P_IP`, or 0 if it is not known.
    pub protocol: u16,
}

impl NetBuf {
    /// Makes an empty buffer with `headroom` bytes before the data and `capacity` bytes for the
    /// data.
    pub fn new(headroom: usize, capacity: usize) -> Self {
        Self {
            area: vec![0; headroom + capacity],
            head: headroom,
            tail: headroom,
            ifindex: 0,
            protocol: 0,
        }
    }

    /// Makes a buffer with a copy of `data` and no headroom. A driver uses this for a received
    /// frame.
    pub fn from_slice(data: &[u8]) -> Self {
        Self { area: data.to_vec(), head: 0, tail: data.len(), ifindex: 0, protocol: 0 }
    }

    /// Makes a buffer with `len` bytes of data with the value zero and no headroom. A driver
    /// copies a received frame into the data.
    pub fn zeroed(len: usize) -> Self {
        Self { area: vec![0; len], head: 0, tail: len, ifindex: 0, protocol: 0 }
    }

    /// The number of bytes of data.
    pub fn len(&self) -> usize {
        self.tail - self.head
    }

    /// Tells if the buffer has no data.
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// The data.
    pub fn data(&self) -> &[u8] {
        &self.area[self.head..self.tail]
    }

    /// The data, to change it.
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.area[self.head..self.tail]
    }

    /// The number of free bytes before the data.
    pub fn headroom(&self) -> usize {
        self.head
    }

    /// The number of free bytes after the data.
    pub fn tailroom(&self) -> usize {
        self.area.len() - self.tail
    }

    /// Adds `len` bytes at the start of the data and gives them, as `skb_push` of Linux. The
    /// bytes have the old contents of the headroom. If the headroom is too small, the buffer gets
    /// a larger area, with a copy of the data. Linux stops with a panic in this case.
    pub fn push(&mut self, len: usize) -> &mut [u8] {
        if len > self.head {
            let room = len + HEADROOM;
            let mut area = vec![0; room + self.len() + self.tailroom()];
            area[room..room + self.len()].copy_from_slice(self.data());
            self.tail = room + self.len();
            self.head = room;
            self.area = area;
        }
        self.head -= len;
        &mut self.area[self.head..self.head + len]
    }

    /// Removes `len` bytes at the start of the data and gives them, as `skb_pull` of Linux.
    /// Gives `None` and does not change the buffer if the data is shorter than `len`.
    pub fn pull(&mut self, len: usize) -> Option<&[u8]> {
        if len > self.len() {
            return None;
        }
        self.head += len;
        Some(&self.area[self.head - len..self.head])
    }

    /// Adds `len` bytes with the value zero at the end of the data and gives them, as `skb_put`
    /// of Linux. The area grows if the tailroom is too small.
    pub fn put(&mut self, len: usize) -> &mut [u8] {
        let end = self.tail + len;
        if end > self.area.len() {
            self.area.resize(end, 0);
        } else {
            self.area[self.tail..end].fill(0);
        }
        self.tail = end;
        &mut self.area[end - len..end]
    }

    /// Adds a copy of `bytes` at the end of the data.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.put(bytes.len()).copy_from_slice(bytes);
    }

    /// Removes the data after the first `len` bytes, as `skb_trim` of Linux. A receive path uses
    /// this to remove the padding after a packet. Does nothing if the data is not longer than
    /// `len`.
    pub fn trim(&mut self, len: usize) {
        if len < self.len() {
            self.tail = self.head + len;
        }
    }
}

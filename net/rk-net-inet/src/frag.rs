//! The fragments of IPv4 and IPv6: the queues of the reassembly, as net/ipv4/inet_fragment.c,
//! net/ipv4/ip_fragment.c and net/ipv6/reassembly.c of Linux, and the split of a packet that is
//! larger than the MTU, as `ip_do_fragment` in net/ipv4/ip_output.c and `ip6_fragment` in
//! net/ipv6/ip6_output.c.
//!
//! A queue has a key: the addresses, the identification and, for IPv4, the protocol. It keeps
//! the parts by their offset. The first part also gives the header of the packet. When the last
//! part came and no hole is left, the queue gives the packet. A part that overlaps another part
//! drops the queue, as `inet_frag_queue_insert` of Linux (RFC 5722). A queue that is not full
//! after `TIMEOUT_MS` goes away.
//!
//! The table does not touch the devices. The caller gives the time in milliseconds. Thus the host
//! tests can run the table.

use alloc::vec::Vec;

/// The time that a queue waits for its parts, `ipfrag_time` of Linux (30 seconds).
pub const TIMEOUT_MS: u64 = 30_000;
/// The most queues of one table. Linux limits the memory with `ipfrag_high_thresh`.
pub const MAX_QUEUES: usize = 64;
/// The most bytes in all of the queues of one table, `ipfrag_high_thresh` of Linux (4 MiB).
pub const MAX_BYTES: usize = 4 << 20;
/// The largest packet after the reassembly, without its header.
pub const MAX_DATA: usize = 65535;

/// A queue of the parts of one packet, `struct inet_frag_queue` of Linux.
struct Queue<K> {
    key: K,
    /// The header of the first part, from `add`.
    head: Option<Vec<u8>>,
    /// The parts by their offset. They do not overlap.
    parts: Vec<(usize, Vec<u8>)>,
    /// The length of the data, when the last part came.
    len: Option<usize>,
    /// The bytes in the parts, `meat` of Linux.
    meat: usize,
    /// The time when the queue goes away.
    expires: u64,
}

/// The result of `Reasm::add`.
#[derive(Debug, PartialEq, Eq)]
pub enum Add {
    /// The queue waits for more parts.
    Wait,
    /// The packet is complete: the header of the first part and all of the data.
    Done(Vec<u8>, Vec<u8>),
    /// The part is not correct, and the queue went away. Count a reassembly failure.
    Fail,
}

/// The queues of the reassembly. `K` is the key of a queue.
pub struct Reasm<K> {
    queues: Vec<Queue<K>>,
    /// The bytes in all of the queues.
    bytes: usize,
}

impl<K: PartialEq> Default for Reasm<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: PartialEq> Reasm<K> {
    /// An empty table.
    pub const fn new() -> Self {
        Self { queues: Vec::new(), bytes: 0 }
    }

    /// The count of queues.
    pub fn len(&self) -> usize {
        self.queues.len()
    }

    /// Tells if the table has no queues.
    pub fn is_empty(&self) -> bool {
        self.queues.is_empty()
    }

    /// Adds a part at the byte `offset` of the data, as `ip_frag_queue` and `ip6_frag_queue` of
    /// Linux. `more` is the flag "more fragments", and `head` is the header of the packet, which
    /// the queue keeps from the part at the offset 0.
    pub fn add(
        &mut self,
        key: K,
        offset: usize,
        more: bool,
        head: &[u8],
        data: &[u8],
        now: u64,
    ) -> Add {
        let end = offset + data.len();
        // Each part but the last has a length that is a multiple of 8.
        if end > MAX_DATA || (more && !data.len().is_multiple_of(8)) || (more && data.is_empty()) {
            self.remove(&key);
            return Add::Fail;
        }
        let at = match self.queues.iter().position(|q| q.key == key) {
            Some(at) => at,
            None => {
                if self.queues.len() >= MAX_QUEUES || self.bytes + data.len() > MAX_BYTES {
                    return Add::Fail;
                }
                self.queues.push(Queue {
                    key,
                    head: None,
                    parts: Vec::new(),
                    len: None,
                    meat: 0,
                    expires: now + TIMEOUT_MS,
                });
                self.queues.len() - 1
            }
        };
        let q = &mut self.queues[at];
        let bad = if more {
            q.len.is_some_and(|l| end > l)
        } else {
            // The last part gives the length. A second last part must agree, and no part can
            // be after it.
            q.len.is_some_and(|l| l != end) || q.parts.iter().any(|(o, p)| o + p.len() > end)
        };
        // A copy of a part that the queue has is not an overlap, as `inet_frag_queue_insert`.
        let same = q.parts.iter().any(|(o, p)| *o == offset && p.as_slice() == data);
        let overlap = q.parts.iter().any(|(o, p)| offset < o + p.len() && *o < end);
        if bad || (overlap && !same) {
            let q = self.queues.swap_remove(at);
            self.bytes -= q.meat;
            return Add::Fail;
        }
        if same {
            return Add::Wait;
        }
        if !more {
            q.len = Some(end);
        }
        if offset == 0 {
            q.head = Some(head.to_vec());
        }
        let i = q.parts.partition_point(|(o, _)| *o < offset);
        q.parts.insert(i, (offset, data.to_vec()));
        q.meat += data.len();
        self.bytes += data.len();
        if q.len != Some(q.meat) || q.head.is_none() {
            return Add::Wait;
        }
        let q = self.queues.swap_remove(at);
        self.bytes -= q.meat;
        let mut out = Vec::with_capacity(q.meat);
        for (_, p) in q.parts {
            out.extend_from_slice(&p);
        }
        Add::Done(q.head.unwrap_or_default(), out)
    }

    /// Removes the queue of `key`.
    fn remove(&mut self, key: &K) {
        if let Some(at) = self.queues.iter().position(|q| q.key == *key) {
            let q = self.queues.swap_remove(at);
            self.bytes -= q.meat;
        }
    }

    /// Removes the queues that waited too long, as `ip_expire` of Linux. Gives the count of
    /// them.
    pub fn expire(&mut self, now: u64) -> usize {
        let before = self.queues.len();
        let mut freed = 0;
        self.queues.retain(|q| {
            let keep = q.expires > now;
            if !keep {
                freed += q.meat;
            }
            keep
        });
        self.bytes -= freed;
        before - self.queues.len()
    }
}

/// The parts of `len` bytes of data for a link with `room` bytes after the header, as
/// `ip_do_fragment` of Linux: each part but the last has a length that is a multiple of 8.
/// Gives the offset and the length of each part.
pub fn split(len: usize, room: usize) -> Vec<(usize, usize)> {
    let size = (room & !7).max(8);
    let mut parts = Vec::new();
    let mut offset = 0;
    while offset < len || parts.is_empty() {
        let n = size.min(len - offset);
        parts.push((offset, n));
        offset += n;
    }
    parts
}

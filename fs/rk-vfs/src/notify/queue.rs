//! The event queue of a notification group, as fs/notify/notification.c of Linux.
//!
//! The queue keeps the events in their order. A new event that is the same as the last event in
//! the queue merges with it, as `inotify_merge` of Linux. When the queue holds its maximum number
//! of events, it takes one overflow event and drops the new events until a read takes events, as
//! `fsnotify_insert_event` of Linux. The overflow event counts as one event of the queue.
//!
//! The module has no locks and no state of the kernel, so the tests on the host examine it.

use super::mask;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// The size of `struct inotify_event` without the name.
pub const EVENT_SIZE: usize = 16;

/// One event of the queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// The watch descriptor, or -1 for the overflow event.
    pub wd: i32,
    /// The bits of the event.
    pub mask: u32,
    /// The cookie that joins the two events of a rename, or 0.
    pub cookie: u32,
    /// The name of the child in the watched directory, or empty.
    pub name: Vec<u8>,
}

impl Event {
    /// The overflow event, as `inotify_init` of Linux makes it.
    pub fn overflow() -> Self {
        Self { wd: -1, mask: mask::Q_OVERFLOW, cookie: 0, name: Vec::new() }
    }

    /// The length of the name with its zero bytes, a multiple of the size of the event, as
    /// `round_event_name_len` of Linux. An event without a name has no name bytes.
    pub fn name_len(&self) -> usize {
        if self.name.is_empty() { 0 } else { (self.name.len() + 1).next_multiple_of(EVENT_SIZE) }
    }

    /// The number of bytes that a read gives for the event.
    pub fn size(&self) -> usize {
        EVENT_SIZE + self.name_len()
    }

    /// Adds the bytes of `struct inotify_event` and of the name to `out`, as
    /// `copy_event_to_user` of Linux.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let len = self.name_len();
        out.extend_from_slice(&self.wd.to_ne_bytes());
        out.extend_from_slice(&self.mask.to_ne_bytes());
        out.extend_from_slice(&self.cookie.to_ne_bytes());
        out.extend_from_slice(&(len as u32).to_ne_bytes());
        out.extend_from_slice(&self.name);
        out.resize(out.len() + len.saturating_sub(self.name.len()), 0);
    }
}

/// What `Queue::push` did with an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Added {
    /// The event is at the end of the queue.
    Queued,
    /// The event is the same as the last event, so the queue did not change.
    Merged,
    /// The queue was full and took the overflow event.
    Overflow,
    /// The queue was full and has the overflow event, so the event is lost.
    Dropped,
}

/// The events of one group.
#[derive(Debug)]
pub struct Queue {
    events: VecDeque<Event>,
    max: usize,
    /// The overflow event is in the queue.
    overflow: bool,
    /// The bytes that a read of all the events gives, for `FIONREAD`.
    bytes: usize,
}

impl Queue {
    /// Makes an empty queue that holds `max` events, as `max_queued_events`.
    pub fn new(max: usize) -> Self {
        Self { events: VecDeque::new(), max, overflow: false, bytes: 0 }
    }

    /// Adds `event` to the end of the queue. If `merge` is true, an event that is the same as
    /// the last event merges with it. `IN_IGNORED` does not merge, as Linux.
    pub fn push(&mut self, event: Event, merge: bool) -> Added {
        if self.events.len() >= self.max {
            if self.overflow {
                return Added::Dropped;
            }
            self.overflow = true;
            self.add(Event::overflow());
            return Added::Overflow;
        }
        if merge && self.events.back() == Some(&event) {
            return Added::Merged;
        }
        self.add(event);
        Added::Queued
    }

    fn add(&mut self, event: Event) {
        self.bytes += event.size();
        self.events.push_back(event);
    }

    /// Takes the first event if it fits in `room` bytes. Gives `Err(())` if there is an event
    /// that does not fit, as `get_one_event` of Linux.
    #[allow(clippy::result_unit_err)]
    pub fn pop(&mut self, room: usize) -> Result<Option<Event>, ()> {
        let Some(first) = self.events.front() else { return Ok(None) };
        if first.size() > room {
            return Err(());
        }
        let event = self.events.pop_front();
        if let Some(e) = &event {
            self.bytes -= e.size();
            if e.wd == -1 && e.mask == mask::Q_OVERFLOW {
                self.overflow = false;
            }
        }
        Ok(event)
    }

    /// Tells if the queue has no event.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// The number of events, with the overflow event.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// The bytes that a read of all the events gives, as `FIONREAD` of Linux.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Removes all the events.
    pub fn clear(&mut self) {
        self.events.clear();
        self.overflow = false;
        self.bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(wd: i32, mask: u32, name: &[u8]) -> Event {
        Event { wd, mask, cookie: 0, name: name.to_vec() }
    }

    #[test]
    fn the_same_event_as_the_last_one_merges() {
        let mut q = Queue::new(16);
        assert_eq!(q.push(ev(1, mask::MODIFY, b""), true), Added::Queued);
        assert_eq!(q.push(ev(1, mask::MODIFY, b""), true), Added::Merged);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn an_event_merges_only_with_the_last_one() {
        let mut q = Queue::new(16);
        q.push(ev(1, mask::MODIFY, b""), true);
        q.push(ev(1, mask::ACCESS, b""), true);
        assert_eq!(q.push(ev(1, mask::MODIFY, b""), true), Added::Queued);
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn events_with_other_names_wds_or_cookies_do_not_merge() {
        let mut q = Queue::new(16);
        q.push(ev(1, mask::CREATE, b"a"), true);
        assert_eq!(q.push(ev(1, mask::CREATE, b"b"), true), Added::Queued);
        assert_eq!(q.push(ev(2, mask::CREATE, b"b"), true), Added::Queued);
        let mut moved = ev(2, mask::CREATE, b"b");
        moved.cookie = 7;
        assert_eq!(q.push(moved, true), Added::Queued);
    }

    #[test]
    fn an_event_without_merge_is_always_queued() {
        let mut q = Queue::new(16);
        q.push(ev(1, mask::IGNORED, b""), false);
        assert_eq!(q.push(ev(1, mask::IGNORED, b""), false), Added::Queued);
    }

    #[test]
    fn a_full_queue_takes_one_overflow_event_at_its_end() {
        let mut q = Queue::new(2);
        q.push(ev(1, mask::OPEN, b""), true);
        q.push(ev(1, mask::ACCESS, b""), true);
        assert_eq!(q.push(ev(1, mask::MODIFY, b""), true), Added::Overflow);
        assert_eq!(q.push(ev(1, mask::ATTRIB, b""), true), Added::Dropped);
        assert_eq!(q.len(), 3);
        q.pop(1024).unwrap();
        q.pop(1024).unwrap();
        assert_eq!(q.pop(1024).unwrap(), Some(Event::overflow()));
        assert_eq!(q.push(ev(1, mask::ATTRIB, b""), true), Added::Queued);
    }

    #[test]
    fn the_overflow_event_stays_one_after_a_read_of_other_events() {
        let mut q = Queue::new(1);
        q.push(ev(1, mask::OPEN, b""), true);
        assert_eq!(q.push(ev(1, mask::ACCESS, b""), true), Added::Overflow);
        q.pop(1024).unwrap();
        // The overflow event is the one event of the queue, and the queue is full.
        assert_eq!(q.push(ev(1, mask::ACCESS, b""), true), Added::Dropped);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn the_name_is_padded_to_the_event_size_with_a_zero_byte() {
        assert_eq!(ev(1, mask::CREATE, b"").size(), 16);
        assert_eq!(ev(1, mask::CREATE, b"abc").size(), 32);
        assert_eq!(ev(1, mask::CREATE, &[b'x'; 15]).size(), 32);
        assert_eq!(ev(1, mask::CREATE, &[b'x'; 16]).size(), 48);
        let mut out = Vec::new();
        let mut e = ev(3, mask::CREATE, b"abc");
        e.cookie = 9;
        e.encode(&mut out);
        assert_eq!(out.len(), 32);
        assert_eq!(&out[0..4], &3i32.to_ne_bytes());
        assert_eq!(&out[4..8], &mask::CREATE.to_ne_bytes());
        assert_eq!(&out[8..12], &9u32.to_ne_bytes());
        assert_eq!(&out[12..16], &16u32.to_ne_bytes());
        assert_eq!(&out[16..19], b"abc");
        assert!(out[19..].iter().all(|&b| b == 0));
    }

    #[test]
    fn a_pop_needs_room_for_the_first_event_and_the_bytes_follow() {
        let mut q = Queue::new(16);
        q.push(ev(1, mask::CREATE, b"name"), true);
        q.push(ev(1, mask::OPEN, b""), true);
        assert_eq!(q.bytes(), 48);
        assert_eq!(q.pop(31), Err(()));
        assert_eq!(q.pop(32).unwrap().map(|e| e.wd), Some(1));
        assert_eq!(q.bytes(), 16);
        assert!(q.pop(16).unwrap().is_some());
        assert!(q.is_empty());
        assert_eq!(q.pop(16), Ok(None));
    }
}

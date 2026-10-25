//! The mq-deadline scheduler, from block/mq-deadline.c of Linux.
//!
//! The scheduler keeps the reads and the writes in two lists that are sorted by sector, and in two
//! lists in the order of arrival. Each request gets a deadline when it arrives: 500 ms for a read
//! and 5 s for a write. The scheduler sends a batch of up to `FIFO_BATCH` requests in sector order
//! in one direction. Then it selects the direction again. Reads go first, but writes go after
//! `WRITES_STARVED` batches of reads. A batch starts at the oldest request if its deadline is
//! past, and else at the next sector after the last request in that direction.
//!
//! A new request merges with a request that ends at its first sector (a back merge) or that
//! starts at its end (a front merge), if the result is not larger than `max_sectors`.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

/// The time from arrival to the deadline of a read, in nanoseconds.
pub const READ_EXPIRE_NS: u64 = 500_000_000;
/// The time from arrival to the deadline of a write, in nanoseconds.
pub const WRITE_EXPIRE_NS: u64 = 5_000_000_000;
/// The largest number of requests in one batch.
pub const FIFO_BATCH: u32 = 16;
/// The number of read batches before the writes go, if writes wait.
pub const WRITES_STARVED: u32 = 2;

/// The direction of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// A read.
    Read = 0,
    /// A write.
    Write = 1,
}

/// A request: a range of sectors in one direction, and the bios that it has, in sector order.
#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    /// The direction.
    pub dir: Dir,
    /// The first sector.
    pub sector: u64,
    /// The number of sectors.
    pub sectors: u64,
    /// The indexes of the bios in the batch.
    pub bios: Vec<usize>,
}

/// A request in the scheduler, with its deadline.
struct Entry {
    rq: Request,
    expires: u64,
}

/// The requests of one direction.
#[derive(Default)]
struct Lists {
    /// The requests by first sector. The second part of the key is the arrival number, so that
    /// two requests can start at one sector.
    sorted: BTreeMap<(u64, u64), Entry>,
    /// The arrival numbers in the order of arrival.
    fifo: VecDeque<u64>,
    /// The first sector of each request by arrival number.
    starts: BTreeMap<u64, u64>,
    /// The sector after the last request that the scheduler sent.
    next: u64,
}

impl Lists {
    fn remove(&mut self, seq: u64) -> Option<Entry> {
        let start = self.starts.remove(&seq)?;
        self.sorted.remove(&(start, seq))
    }

    /// Joins the request after the request `key` to it, if the first ends where the second
    /// starts and the result is not larger than `max`. The result keeps the earlier deadline.
    fn join_next(&mut self, key: (u64, u64), max: u64) {
        let Some(e) = self.sorted.get(&key) else { return };
        let end = e.rq.sector + e.rq.sectors;
        let Some((&next, n)) = self.sorted.range((end, 0)..).next() else { return };
        if next.0 != end || e.rq.sectors + n.rq.sectors > max {
            return;
        }
        let Some(n) = self.sorted.remove(&next) else { return };
        self.starts.remove(&next.1);
        let Some(e) = self.sorted.get_mut(&key) else { return };
        e.rq.sectors += n.rq.sectors;
        e.rq.bios.extend(n.rq.bios);
        e.expires = e.expires.min(n.expires);
    }

    /// The deadline of the request `seq`.
    fn expires(&self, seq: u64) -> u64 {
        self.starts.get(&seq).and_then(|s| self.sorted.get(&(*s, seq))).map_or(0, |e| e.expires)
    }

    /// The arrival number of the oldest request. It drops the numbers of the requests that left.
    fn oldest(&mut self) -> Option<u64> {
        while let Some(&seq) = self.fifo.front() {
            if self.starts.contains_key(&seq) {
                return Some(seq);
            }
            self.fifo.pop_front();
        }
        None
    }

    /// The arrival number of the first request at or after `self.next`.
    fn after_next(&self) -> Option<u64> {
        self.sorted.range((self.next, 0)..).next().map(|(&(_, seq), _)| seq)
    }
}

/// The state of the scheduler.
pub struct Deadline {
    lists: [Lists; 2],
    max_sectors: u64,
    seq: u64,
    /// The direction of the batch that runs, and the count of its requests.
    batch: Option<(Dir, u32)>,
    /// The read batches since the last write batch.
    starved: u32,
}

impl Deadline {
    /// Makes an empty scheduler that merges requests up to `max_sectors` sectors.
    pub fn new(max_sectors: u64) -> Self {
        Self {
            lists: [Lists::default(), Lists::default()],
            max_sectors,
            seq: 0,
            batch: None,
            starved: 0,
        }
    }

    /// Tells if there is no request.
    pub fn is_empty(&self) -> bool {
        self.lists.iter().all(|l| l.sorted.is_empty())
    }

    /// Adds the bio `bio` at `now`. Gives `true` if it merged with a request.
    pub fn insert(&mut self, dir: Dir, sector: u64, sectors: u64, bio: usize, now: u64) -> bool {
        let max = self.max_sectors;
        let l = &mut self.lists[dir as usize];
        let end = sector + sectors;
        // A back merge: the request before ends at `sector`.
        if let Some((&key, e)) = l.sorted.range_mut(..(sector, 0)).next_back()
            && e.rq.sector + e.rq.sectors == sector
            && e.rq.sectors + sectors <= max
        {
            e.rq.sectors += sectors;
            e.rq.bios.push(bio);
            l.join_next(key, max);
            return true;
        }
        // A front merge: the request after starts at `end`.
        if let Some((&(start, seq), e)) = l.sorted.range((end, 0)..).next()
            && start == end
            && e.rq.sectors + sectors <= max
            && let Some(mut e) = l.sorted.remove(&(start, seq))
        {
            e.rq.sector = sector;
            e.rq.sectors += sectors;
            e.rq.bios.insert(0, bio);
            l.sorted.insert((sector, seq), e);
            l.starts.insert(seq, sector);
            if let Some((&before, _)) = l.sorted.range(..(sector, 0)).next_back() {
                l.join_next(before, max);
            }
            return true;
        }
        let seq = self.seq;
        self.seq += 1;
        let expires = now + if dir == Dir::Read { READ_EXPIRE_NS } else { WRITE_EXPIRE_NS };
        let rq = Request { dir, sector, sectors, bios: alloc::vec![bio] };
        l.sorted.insert((sector, seq), Entry { rq, expires });
        l.fifo.push_back(seq);
        l.starts.insert(seq, sector);
        false
    }

    /// Takes the next request to send to the device at `now`.
    pub fn dispatch(&mut self, now: u64) -> Option<Request> {
        if let Some((dir, count)) = self.batch
            && count < FIFO_BATCH
            && let Some(seq) = self.lists[dir as usize].after_next()
        {
            self.batch = Some((dir, count + 1));
            return self.take(dir, seq);
        }
        let reads = !self.lists[Dir::Read as usize].sorted.is_empty();
        let writes = !self.lists[Dir::Write as usize].sorted.is_empty();
        let dir = match (reads, writes) {
            (true, true) if self.starved >= WRITES_STARVED => Dir::Write,
            (true, _) => Dir::Read,
            (false, true) => Dir::Write,
            (false, false) => {
                self.batch = None;
                return None;
            }
        };
        if dir == Dir::Write {
            self.starved = 0;
        } else if writes {
            self.starved += 1;
        }
        let l = &mut self.lists[dir as usize];
        let oldest = l.oldest()?;
        let expired = l.expires(oldest) <= now;
        let seq = match l.after_next() {
            Some(seq) if !expired => seq,
            _ => oldest,
        };
        self.batch = Some((dir, 1));
        self.take(dir, seq)
    }

    fn take(&mut self, dir: Dir, seq: u64) -> Option<Request> {
        let l = &mut self.lists[dir as usize];
        let e = l.remove(seq)?;
        l.next = e.rq.sector + e.rq.sectors;
        Some(e.rq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order(d: &mut Deadline, now: u64) -> Vec<(Dir, u64, u64)> {
        let mut out = Vec::new();
        while let Some(rq) = d.dispatch(now) {
            out.push((rq.dir, rq.sector, rq.sectors));
        }
        out
    }

    #[test]
    fn near_requests_merge() {
        let mut d = Deadline::new(64);
        assert!(!d.insert(Dir::Read, 8, 8, 0, 0));
        assert!(d.insert(Dir::Read, 16, 8, 1, 0));
        assert!(d.insert(Dir::Read, 0, 8, 2, 0));
        // A write does not merge with a read.
        assert!(!d.insert(Dir::Write, 24, 8, 3, 0));
        let rq = d.dispatch(0).unwrap();
        assert_eq!(
            rq,
            Request { dir: Dir::Read, sector: 0, sectors: 24, bios: alloc::vec![2, 0, 1] }
        );
    }

    #[test]
    fn a_merge_does_not_make_a_request_too_large() {
        let mut d = Deadline::new(16);
        d.insert(Dir::Write, 0, 8, 0, 0);
        assert!(d.insert(Dir::Write, 8, 8, 1, 0));
        assert!(!d.insert(Dir::Write, 16, 8, 2, 0));
        assert_eq!(order(&mut d, 0), [(Dir::Write, 0, 16), (Dir::Write, 16, 8)]);
    }

    #[test]
    fn a_batch_goes_in_sector_order() {
        let mut d = Deadline::new(8);
        for (i, s) in [40, 10, 30, 20].into_iter().enumerate() {
            d.insert(Dir::Read, s, 1, i, 0);
        }
        let sectors: Vec<u64> = order(&mut d, 0).into_iter().map(|r| r.1).collect();
        // The first request is the oldest, and then the batch goes up from there.
        assert_eq!(sectors, [10, 20, 30, 40]);
    }

    #[test]
    fn an_expired_request_goes_first() {
        let mut d = Deadline::new(8);
        d.insert(Dir::Read, 100, 1, 0, 0);
        d.insert(Dir::Read, 5, 1, 1, READ_EXPIRE_NS);
        // At the start, the oldest request is at 100, and no request is after it.
        assert_eq!(d.dispatch(READ_EXPIRE_NS).unwrap().sector, 100);
        d.insert(Dir::Read, 200, 1, 2, READ_EXPIRE_NS);
        // The batch continues at 200, after 100.
        assert_eq!(d.dispatch(READ_EXPIRE_NS).unwrap().sector, 200);
        assert_eq!(d.dispatch(READ_EXPIRE_NS).unwrap().sector, 5);
    }

    #[test]
    fn writes_go_after_two_read_batches() {
        let mut d = Deadline::new(1);
        d.insert(Dir::Write, 1000, 1, 0, 0);
        for i in 0..(FIFO_BATCH as u64 * 3) {
            d.insert(Dir::Read, i * 2, 1, 1, 0);
        }
        let dirs: Vec<Dir> = order(&mut d, 0).into_iter().map(|r| r.0).collect();
        let first_write = dirs.iter().position(|&d| d == Dir::Write).unwrap();
        assert_eq!(first_write, 2 * FIFO_BATCH as usize);
    }
}

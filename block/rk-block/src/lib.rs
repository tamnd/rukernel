//! The block layer of rukernel.
//!
//! A driver gives a `BlockDevice`, which reads and writes whole sectors of 512 bytes. The block
//! layer puts a `Queue` in front of each device. A caller gives the queue a batch of bios, and the
//! queue is the plug of Linux for that batch: the bios go into the scheduler, near bios merge into
//! one request, and then the scheduler sends the requests to the device in its order.
//!
//! The drivers do each request before they return, so the queue sends all the requests of a batch
//! before `submit` returns. The schedulers are `mq-deadline`, the default, and `none`. The module
//! `cache` has the page cache, which can be over a queue.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod cache;
pub mod deadline;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use deadline::{Deadline, Dir, Request};
use rk_abi::Errno;
use rk_frame::sync::{Once, SpinLock};

/// The result of the block layer.
pub type Result<T> = core::result::Result<T, Errno>;

/// The size of a sector, the unit of the block layer.
pub const SECTOR_SIZE: usize = 512;

/// The largest request after merges, in sectors: 512 KiB.
pub const MAX_SECTORS: u64 = 1024;

/// The driver of a block device.
pub trait BlockDevice: Send + Sync {
    /// The number of sectors.
    fn sectors(&self) -> u64;

    /// Tells if the device does not accept writes.
    fn read_only(&self) -> bool {
        false
    }

    /// Reads the sectors from `sector` to `buf`. The length of `buf` is a multiple of
    /// `SECTOR_SIZE`, and the sectors are on the device.
    fn read(&self, sector: u64, buf: &mut [u8]) -> Result<()>;

    /// Writes `buf` to the sectors from `sector`, with the same rules as `read`.
    fn write(&self, sector: u64, buf: &[u8]) -> Result<()>;

    /// Makes the data of the completed writes durable.
    fn flush(&self) -> Result<()> {
        Ok(())
    }

    /// Tells if the device can discard sectors.
    fn can_discard(&self) -> bool {
        false
    }

    /// Tells the device that the `count` sectors from `sector` have no data that is in use.
    fn discard(&self, _sector: u64, _count: u64) -> Result<()> {
        Err(Errno::EOPNOTSUPP)
    }
}

/// The operation of a bio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// The device writes the data to memory.
    Read,
    /// The device reads the data from memory.
    Write,
}

/// One read or write of whole sectors. For a write, `data` has the data. For a read, the queue
/// fills `data`. The length of `data` is a multiple of `SECTOR_SIZE` and is not 0.
#[derive(Debug)]
pub struct Bio {
    /// The operation.
    pub op: Op,
    /// The first sector.
    pub sector: u64,
    /// The data of the sectors.
    pub data: Vec<u8>,
    /// The result, after `submit`.
    pub result: Result<()>,
}

impl Bio {
    /// Makes a bio. The result is `Ok` until the queue does the bio.
    pub fn new(op: Op, sector: u64, data: Vec<u8>) -> Self {
        Self { op, sector, data, result: Ok(()) }
    }

    fn sectors(&self) -> u64 {
        (self.data.len() / SECTOR_SIZE) as u64
    }
}

/// The hook that charges the I/O of a queue to the task that submits it, for the io controller
/// of cgroup v2. It gets the device, `true` for a write, the bytes and the count of bios.
pub type AccountFn = fn(dev: u64, write: bool, bytes: u64, ios: u64);

/// The hook of [`set_account`].
static ACCOUNT: Once<AccountFn> = Once::new();

/// Sets the hook that charges each submitted batch of bios, as `blk_cgroup_bio_start` of Linux.
/// Only the first call has an effect.
pub fn set_account(f: AccountFn) {
    ACCOUNT.call_once(|| f);
}

/// The I/O scheduler of a queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheduler {
    /// The requests go in the order of arrival, without merges.
    None,
    /// The scheduler of the module `deadline`.
    MqDeadline,
}

impl Scheduler {
    /// The name in `/sys/block/DEV/queue/scheduler`.
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MqDeadline => "mq-deadline",
        }
    }

    /// The scheduler with the name `name`.
    pub fn from_name(name: &str) -> Option<Self> {
        [Self::None, Self::MqDeadline].into_iter().find(|s| s.name() == name)
    }
}

/// The counts of a disk, as in `/proc/diskstats`. Index 0 is for reads and index 1 for writes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// The requests that the device did.
    pub ios: [u64; 2],
    /// The bios that merged with another bio into one request.
    pub merges: [u64; 2],
    /// The sectors that the device read and wrote.
    pub sectors: [u64; 2],
    /// The flush commands.
    pub flushes: u64,
}

/// The requests that wait in a queue.
enum Pending {
    None(VecDeque<Request>),
    Deadline(Deadline),
}

/// The request queue of one device.
pub struct Queue {
    device: Arc<dyn BlockDevice>,
    pending: SpinLock<Pending>,
    stats: SpinLock<Stats>,
    /// `BLKROSET` made the device read only, as `bd_read_only` of Linux.
    read_only: AtomicBool,
    /// The device number, for the charges of the io controller.
    dev: AtomicU64,
}

impl Queue {
    /// Makes the queue of `device` with the scheduler `mq-deadline`.
    pub fn new(device: Arc<dyn BlockDevice>) -> Self {
        Self {
            device,
            pending: SpinLock::new(Pending::Deadline(Deadline::new(MAX_SECTORS))),
            stats: SpinLock::new(Stats::default()),
            read_only: AtomicBool::new(false),
            dev: AtomicU64::new(0),
        }
    }

    /// Sets the device number of the queue. The charges of the io controller use it.
    pub fn set_dev(&self, dev: u64) {
        self.dev.store(dev, Ordering::Relaxed);
    }

    /// The number of sectors of the device.
    pub fn sectors(&self) -> u64 {
        self.device.sectors()
    }

    /// Tells if the device does not accept writes: the driver can only read it, or `BLKROSET`
    /// made it read only, as `bdev_read_only` of Linux.
    pub fn read_only(&self) -> bool {
        self.device.read_only() || self.read_only.load(Ordering::Relaxed)
    }

    /// Makes the device read only or writable again, for `BLKROSET`. A device that the driver
    /// can only read stays read only.
    pub fn set_read_only(&self, read_only: bool) {
        self.read_only.store(read_only, Ordering::Relaxed);
    }

    /// The counts of the device.
    pub fn stats(&self) -> Stats {
        *self.stats.lock()
    }

    /// The scheduler of the queue.
    pub fn scheduler(&self) -> Scheduler {
        match *self.pending.lock() {
            Pending::None(_) => Scheduler::None,
            Pending::Deadline(_) => Scheduler::MqDeadline,
        }
    }

    /// Changes the scheduler. No request waits between two calls of `submit`, so nothing moves.
    pub fn set_scheduler(&self, s: Scheduler) {
        *self.pending.lock() = match s {
            Scheduler::None => Pending::None(VecDeque::new()),
            Scheduler::MqDeadline => Pending::Deadline(Deadline::new(MAX_SECTORS)),
        };
    }

    /// Does the bios of `bios` and sets the result of each. A bio past the end of the device
    /// gets `EIO`, and a write to a read only device gets `EPERM`.
    pub fn submit(&self, bios: &mut [Bio]) {
        let sectors = self.sectors();
        let now = now();
        let mut pending = self.pending.lock();
        for (i, bio) in bios.iter_mut().enumerate() {
            let n = bio.sectors();
            if n == 0 || !bio.data.len().is_multiple_of(SECTOR_SIZE) {
                bio.result = Err(Errno::EINVAL);
                continue;
            }
            if bio.sector.checked_add(n).is_none_or(|end| end > sectors) {
                bio.result = Err(Errno::EIO);
                continue;
            }
            if bio.op == Op::Write && self.read_only() {
                bio.result = Err(Errno::EPERM);
                continue;
            }
            let dir = if bio.op == Op::Read { Dir::Read } else { Dir::Write };
            match &mut *pending {
                Pending::None(fifo) => {
                    fifo.push_back(Request { dir, sector: bio.sector, sectors: n, bios: vec![i] });
                }
                Pending::Deadline(d) => {
                    d.insert(dir, bio.sector, n, i, now);
                }
            }
        }
        let mut stats = self.stats.lock();
        // The bytes and the bios of each direction, for the io controller.
        let mut charge = [(0u64, 0u64); 2];
        loop {
            let rq = match &mut *pending {
                Pending::None(fifo) => fifo.pop_front(),
                Pending::Deadline(d) => d.dispatch(now),
            };
            let Some(rq) = rq else { break };
            stats.ios[rq.dir as usize] += 1;
            stats.merges[rq.dir as usize] += rq.bios.len() as u64 - 1;
            stats.sectors[rq.dir as usize] += rq.sectors;
            let c = &mut charge[rq.dir as usize];
            c.0 += rq.sectors * SECTOR_SIZE as u64;
            c.1 += rq.bios.len() as u64;
            self.run(&rq, bios);
        }
        drop(stats);
        drop(pending);
        if let Some(account) = ACCOUNT.get() {
            let dev = self.dev.load(Ordering::Relaxed);
            for (dir, &(bytes, ios)) in charge.iter().enumerate() {
                if ios > 0 {
                    account(dev, dir == Dir::Write as usize, bytes, ios);
                }
            }
        }
    }

    /// Sends the request `rq` to the device, and sets the results of its bios.
    fn run(&self, rq: &Request, bios: &mut [Bio]) {
        let result = if let [one] = rq.bios[..] {
            let bio = &mut bios[one];
            match rq.dir {
                Dir::Read => self.device.read(rq.sector, &mut bio.data),
                Dir::Write => self.device.write(rq.sector, &bio.data),
            }
        } else {
            let mut buf = vec![0u8; rq.sectors as usize * SECTOR_SIZE];
            match rq.dir {
                Dir::Read => {
                    let r = self.device.read(rq.sector, &mut buf);
                    if r.is_ok() {
                        let mut at = 0;
                        for &i in &rq.bios {
                            let len = bios[i].data.len();
                            bios[i].data.copy_from_slice(&buf[at..at + len]);
                            at += len;
                        }
                    }
                    r
                }
                Dir::Write => {
                    let mut at = 0;
                    for &i in &rq.bios {
                        let data = &bios[i].data;
                        buf[at..at + data.len()].copy_from_slice(data);
                        at += data.len();
                    }
                    self.device.write(rq.sector, &buf)
                }
            }
        };
        for &i in &rq.bios {
            bios[i].result = result;
        }
    }

    /// Reads the sectors from `sector` to `buf`.
    ///
    /// # Errors
    ///
    /// Gives the error of the device, or `EIO` for sectors past the end.
    pub fn read(&self, sector: u64, buf: &mut [u8]) -> Result<()> {
        let mut bio = [Bio::new(Op::Read, sector, vec![0u8; buf.len()])];
        self.submit(&mut bio);
        let [bio] = bio;
        bio.result?;
        buf.copy_from_slice(&bio.data);
        Ok(())
    }

    /// Writes `buf` to the sectors from `sector`.
    ///
    /// # Errors
    ///
    /// Gives the error of the device, `EIO` for sectors past the end, or `EPERM` for a read only
    /// device.
    pub fn write(&self, sector: u64, buf: &[u8]) -> Result<()> {
        let mut bio = [Bio::new(Op::Write, sector, buf.to_vec())];
        self.submit(&mut bio);
        let [bio] = bio;
        bio.result
    }

    /// Makes the data of the completed writes durable.
    ///
    /// # Errors
    ///
    /// Gives the error of the device.
    pub fn flush(&self) -> Result<()> {
        self.stats.lock().flushes += 1;
        self.device.flush()
    }

    /// Tells if the device can discard sectors.
    pub fn can_discard(&self) -> bool {
        self.device.can_discard()
    }

    /// Discards the `count` sectors from `sector`.
    ///
    /// # Errors
    ///
    /// Gives `EOPNOTSUPP` if the device cannot discard, `EIO` for sectors past the end, or
    /// `EPERM` for a read only device.
    pub fn discard(&self, sector: u64, count: u64) -> Result<()> {
        if self.read_only() {
            return Err(Errno::EPERM);
        }
        if sector.checked_add(count).is_none_or(|e| e > self.sectors()) {
            return Err(Errno::EIO);
        }
        self.device.discard(sector, count)
    }
}

impl cache::Store for Arc<Queue> {
    fn size(&self) -> u64 {
        self.sectors() * SECTOR_SIZE as u64
    }

    fn submit(&self, bios: &mut [Bio]) {
        Queue::submit(self, bios);
    }

    fn flush(&self) -> Result<()> {
        Queue::flush(self)
    }

    fn can_discard(&self) -> bool {
        Queue::can_discard(self)
    }

    fn discard(&self, offset: u64, len: u64) -> Result<()> {
        Queue::discard(self, offset / SECTOR_SIZE as u64, len / SECTOR_SIZE as u64)
    }
}

/// The time for the deadlines, in nanoseconds since boot. On the host there is no clock.
fn now() -> u64 {
    #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        rk_frame::time::clock_ns()
    }
    #[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A device in memory that records the requests.
    struct Ram {
        data: SpinLock<Vec<u8>>,
        requests: SpinLock<Vec<(bool, u64, usize)>>,
    }

    impl BlockDevice for Ram {
        fn sectors(&self) -> u64 {
            (self.data.lock().len() / SECTOR_SIZE) as u64
        }

        fn read(&self, sector: u64, buf: &mut [u8]) -> Result<()> {
            self.requests.lock().push((false, sector, buf.len()));
            let at = sector as usize * SECTOR_SIZE;
            buf.copy_from_slice(&self.data.lock()[at..at + buf.len()]);
            Ok(())
        }

        fn write(&self, sector: u64, buf: &[u8]) -> Result<()> {
            self.requests.lock().push((true, sector, buf.len()));
            let at = sector as usize * SECTOR_SIZE;
            self.data.lock()[at..at + buf.len()].copy_from_slice(buf);
            Ok(())
        }
    }

    fn queue() -> (Arc<Ram>, Queue) {
        let data = (0..64 * SECTOR_SIZE).map(|i| (i / SECTOR_SIZE) as u8).collect();
        let ram = Arc::new(Ram { data: SpinLock::new(data), requests: SpinLock::new(Vec::new()) });
        (ram.clone(), Queue::new(ram))
    }

    #[test]
    fn a_read_only_queue_refuses_writes_until_it_is_writable() {
        let (ram, q) = queue();
        q.set_read_only(true);
        assert!(q.read_only());
        let mut bios = [Bio::new(Op::Write, 1, vec![0xaa; SECTOR_SIZE])];
        q.submit(&mut bios);
        assert_eq!(bios[0].result, Err(Errno::EPERM));
        assert!(ram.requests.lock().is_empty());
        q.set_read_only(false);
        q.submit(&mut bios);
        assert_eq!(bios[0].result, Ok(()));
    }

    #[test]
    fn near_bios_go_as_one_request() {
        let (ram, q) = queue();
        let mut bios: Vec<Bio> =
            [3u64, 1, 2].into_iter().map(|s| Bio::new(Op::Read, s, vec![0; SECTOR_SIZE])).collect();
        q.submit(&mut bios);
        assert_eq!(*ram.requests.lock(), [(false, 1, 3 * SECTOR_SIZE)]);
        for b in &bios {
            assert_eq!(b.result, Ok(()));
            assert!(b.data.iter().all(|&x| u64::from(x) == b.sector));
        }
        assert_eq!(q.stats().merges, [2, 0]);
        assert_eq!(q.stats().ios, [1, 0]);
    }

    #[test]
    fn merged_writes_keep_the_data_of_each_bio() {
        let (ram, q) = queue();
        let mut bios = [
            Bio::new(Op::Write, 11, vec![0xbb; SECTOR_SIZE]),
            Bio::new(Op::Write, 10, vec![0xaa; SECTOR_SIZE]),
        ];
        q.submit(&mut bios);
        assert_eq!(*ram.requests.lock(), [(true, 10, 2 * SECTOR_SIZE)]);
        let data = ram.data.lock();
        assert!(data[10 * SECTOR_SIZE..11 * SECTOR_SIZE].iter().all(|&x| x == 0xaa));
        assert!(data[11 * SECTOR_SIZE..12 * SECTOR_SIZE].iter().all(|&x| x == 0xbb));
    }

    #[test]
    fn the_none_scheduler_keeps_the_order() {
        let (ram, q) = queue();
        q.set_scheduler(Scheduler::from_name("none").unwrap());
        let mut bios = [
            Bio::new(Op::Read, 5, vec![0; SECTOR_SIZE]),
            Bio::new(Op::Read, 4, vec![0; SECTOR_SIZE]),
        ];
        q.submit(&mut bios);
        assert_eq!(*ram.requests.lock(), [(false, 5, SECTOR_SIZE), (false, 4, SECTOR_SIZE)]);
        assert_eq!(q.scheduler().name(), "none");
    }

    #[test]
    fn a_bio_past_the_end_fails() {
        let (_, q) = queue();
        let mut bios = [
            Bio::new(Op::Read, 63, vec![0; 2 * SECTOR_SIZE]),
            Bio::new(Op::Read, 0, vec![0; 100]),
            Bio::new(Op::Write, 0, vec![1; SECTOR_SIZE]),
        ];
        q.submit(&mut bios);
        assert_eq!(bios[0].result, Err(Errno::EIO));
        assert_eq!(bios[1].result, Err(Errno::EINVAL));
        assert_eq!(bios[2].result, Ok(()));
    }
}

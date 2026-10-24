//! virtio-blk, from section 5.2 of the virtio 1.2 specification.

use crate::pci::{Transport, status};
use crate::queue::{Buffer, Queue};
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::addr::PAGE_SIZE;
use rk_frame::mm::{Frame, alloc_zeroed_frame};
use rk_frame::pci::PciDevice;
use rk_frame::sync::SpinLock;
use rk_vfs::blockdev::{BlockDevice, SECTOR_SIZE, register_block};
use rk_vfs::device::makedev;
use rk_vfs::inode::Result;

/// The device ID of a transitional virtio-blk device and of a modern one.
const DEVICE_TRANSITIONAL: u16 = 0x1001;
const DEVICE_MODERN: u16 = 0x1042;

/// The device does not take writes.
const F_RO: u64 = 1 << 5;
/// The device has the flush command.
const F_FLUSH: u64 = 1 << 9;

/// The request types.
const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;

/// The status that the device writes for a request that it did.
const S_OK: u8 = 0;

/// The data frames of one request. A larger read or write is done as more requests.
const DATA_FRAMES: usize = 16;
const SECTORS_PER_FRAME: usize = PAGE_SIZE / SECTOR_SIZE;

/// Tells if the PCI function is a virtio-blk device.
pub(crate) fn is_blk(dev: &PciDevice) -> bool {
    matches!(dev.device_id(), DEVICE_TRANSITIONAL | DEVICE_MODERN)
}

/// Starts the driver for the disk number `index`, and gives the name of the disk.
pub(crate) fn probe(dev: &PciDevice, index: u32) -> Option<String> {
    if index >= 26 {
        return None;
    }
    let t = Transport::new(dev)?;
    let Some(features) = t.negotiate(F_RO | F_FLUSH) else {
        t.fail();
        return None;
    };
    let Some(queue) = Queue::new(&t, 0) else {
        t.fail();
        return None;
    };
    // The header, the status byte and the data of a request.
    let req = alloc_zeroed_frame()?;
    let data = (0..DATA_FRAMES).map(|_| alloc_zeroed_frame()).collect::<Option<Vec<_>>>()?;
    let sectors = t.device_u64(0);
    t.add_status(status::DRIVER_OK);
    let disk = VirtioBlk {
        sectors,
        read_only: features & F_RO != 0,
        flush: features & F_FLUSH != 0,
        state: SpinLock::new(State { t, queue, req, data }),
    };
    let name = format!("vd{}", char::from(b'a' + index as u8));
    register_block(makedev(crate::VIRTBLK_MAJOR, index * 16), &name, Arc::new(disk));
    Some(name)
}

struct State {
    t: Transport,
    queue: Queue,
    req: Frame,
    data: Vec<Frame>,
}

/// A virtio-blk disk.
struct VirtioBlk {
    sectors: u64,
    read_only: bool,
    flush: bool,
    state: SpinLock<State>,
}

/// The offset of the status byte in the request frame, after the header of 16 bytes.
const STATUS_OFFSET: usize = 16;

impl State {
    /// Runs one request of `frames` data frames. The data is already in the frames for a write.
    fn request(&mut self, kind: u32, sector: u64, frames: usize, len: usize) -> Result<()> {
        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&kind.to_le_bytes());
        header[8..16].copy_from_slice(&sector.to_le_bytes());
        self.req.write_bytes(0, &header);
        self.req.write_bytes(STATUS_OFFSET, &[0xff]);
        let req = self.req.addr().get();
        let mut buffers = Vec::with_capacity(frames + 2);
        buffers.push(Buffer { addr: req, len: 16, device_writes: false });
        let mut left = len;
        for f in &self.data[..frames] {
            let n = left.min(PAGE_SIZE);
            buffers.push(Buffer {
                addr: f.addr().get(),
                len: n as u32,
                device_writes: kind == T_IN,
            });
            left -= n;
        }
        buffers.push(Buffer { addr: req + STATUS_OFFSET as u64, len: 1, device_writes: true });
        if buffers.len() > self.queue.max_buffers() {
            return Err(Errno::EIO);
        }
        self.queue.run(&self.t, &buffers);
        let mut s = [0u8];
        self.req.read_bytes(STATUS_OFFSET, &mut s);
        if s[0] == S_OK { Ok(()) } else { Err(Errno::EIO) }
    }
}

impl VirtioBlk {
    fn check(&self, sector: u64, len: usize) -> Result<()> {
        let count = (len / SECTOR_SIZE) as u64;
        if !len.is_multiple_of(SECTOR_SIZE)
            || sector.checked_add(count).is_none_or(|e| e > self.sectors)
        {
            return Err(Errno::EIO);
        }
        Ok(())
    }
}

impl BlockDevice for VirtioBlk {
    fn sectors(&self) -> u64 {
        self.sectors
    }

    fn read_only(&self) -> bool {
        self.read_only
    }

    fn read(&self, sector: u64, buf: &mut [u8]) -> Result<()> {
        self.check(sector, buf.len())?;
        let mut st = self.state.lock();
        let mut sector = sector;
        for chunk in buf.chunks_mut(DATA_FRAMES * PAGE_SIZE) {
            let frames = chunk.len().div_ceil(PAGE_SIZE);
            st.request(T_IN, sector, frames, chunk.len())?;
            for (part, f) in chunk.chunks_mut(PAGE_SIZE).zip(&st.data) {
                f.read_bytes(0, part);
            }
            sector += (chunk.len() / SECTOR_SIZE) as u64;
        }
        Ok(())
    }

    fn write(&self, sector: u64, buf: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(Errno::EPERM);
        }
        self.check(sector, buf.len())?;
        let mut st = self.state.lock();
        let mut sector = sector;
        for chunk in buf.chunks(DATA_FRAMES * PAGE_SIZE) {
            for (part, f) in chunk.chunks(PAGE_SIZE).zip(&st.data) {
                f.write_bytes(0, part);
            }
            let frames = chunk.len().div_ceil(PAGE_SIZE);
            st.request(T_OUT, sector, frames, chunk.len())?;
            sector += (chunk.len() / SECTOR_SIZE) as u64;
        }
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        if !self.flush {
            return Ok(());
        }
        self.state.lock().request(T_FLUSH, 0, 0, 0)
    }
}

// A frame holds a whole number of sectors.
const _: () = assert!(SECTORS_PER_FRAME * SECTOR_SIZE == PAGE_SIZE);

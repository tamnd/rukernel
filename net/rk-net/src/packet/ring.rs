//! The mapped rings of a packet socket, as `packet_set_ring`, `tpacket_rcv`, `tpacket_snd` and the
//! block code (`prb_*`) of net/packet/af_packet.c of Linux.
//!
//! A ring is `tp_block_nr` blocks of `tp_block_size` bytes. The blocks are pages that a `mmap` of
//! the socket maps shared: first the pages of the receive ring, then the pages of the transmit
//! ring.
//!
//! With `TPACKET_V1` and `TPACKET_V2`, a block has `tp_block_size / tp_frame_size` frames, and a
//! frame does not cross the end of its block. A frame starts with a header (`struct tpacket_hdr`
//! or `struct tpacket2_hdr`), and its status word tells which side owns the frame. The kernel
//! fills the frame at the head of the receive ring if its status is `TP_STATUS_KERNEL`, and then
//! sets `TP_STATUS_USER`. The program sets the status back to `TP_STATUS_KERNEL` when it is done
//! with the frame. When the frame at the head is not free, the kernel drops the packet. On the
//! transmit ring, the program sets `TP_STATUS_SEND_REQUEST`, and a `send` sends each such frame
//! from the head and sets `TP_STATUS_AVAILABLE`.
//!
//! With `TPACKET_V3`, a receive block starts with a `struct tpacket_block_desc`. The kernel puts
//! the packets one after the other in the open block, each with a `struct tpacket3_hdr`. The
//! kernel gives the whole block to the program (`TP_STATUS_USER`) when the next packet does not
//! fit, or when the block has packets and was open for `tp_retire_blk_tov` milliseconds. If the
//! next block still belongs to the program, the queue freezes and the kernel drops the packets
//! until the program gives the block back.

use super::SOCKADDR_LL;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use rk_abi::Errno;
use rk_frame::addr::PAGE_SIZE;
use rk_vfs::inode::Result;

/// The ring formats of <linux/if_packet.h>.
pub(super) const TPACKET_V1: i32 = 0;
pub(super) const TPACKET_V2: i32 = 1;
pub(super) const TPACKET_V3: i32 = 2;

/// The alignment of the frames and of the parts of a frame, `TPACKET_ALIGNMENT`.
const TPACKET_ALIGNMENT: usize = 16;

/// The status bits of a receive frame or block, `TP_STATUS_*` of <linux/if_packet.h>.
pub(super) const TP_STATUS_KERNEL: u32 = 0;
pub(super) const TP_STATUS_USER: u32 = 1;
const TP_STATUS_LOSING: u32 = 1 << 2;
pub(super) const TP_STATUS_BLK_TMO: u32 = 1 << 5;
pub(super) const TP_STATUS_TS_SOFTWARE: u32 = 1 << 29;

/// The status values of a transmit frame.
pub(super) const TP_STATUS_AVAILABLE: u32 = 0;
pub(super) const TP_STATUS_SEND_REQUEST: u32 = 1;
const TP_STATUS_SENDING: u32 = 2;
pub(super) const TP_STATUS_WRONG_FORMAT: u32 = 1 << 2;

/// The size of `struct tpacket_block_desc` with its alignment, `BLK_HDR_LEN`.
const BLK_HDR_LEN: usize = 48;

/// The time that a block of `TPACKET_V3` stays open when `tp_retire_blk_tov` is 0, in
/// milliseconds, `DEFAULT_PRB_RETIRE_TOV`. Linux uses it when the device does not give its link
/// speed.
const DEFAULT_RETIRE_TOV: u64 = 8;

/// Rounds `x` up to `TPACKET_ALIGNMENT`, as `TPACKET_ALIGN`.
const fn tpacket_align(x: usize) -> usize {
    (x + TPACKET_ALIGNMENT - 1) & !(TPACKET_ALIGNMENT - 1)
}

/// Rounds `x` up to 8 bytes, as `ALIGN(x, 8)` in `BLK_PLUS_PRIV` and `TOTAL_PKT_LEN_INCL_ALIGN`.
const fn align8(x: usize) -> usize {
    (x + 7) & !7
}

/// The size of the frame header of `version` on a 64 bit machine: `struct tpacket_hdr`,
/// `struct tpacket2_hdr` or `struct tpacket3_hdr`. `PACKET_HDRLEN` gives it.
pub(super) fn header_size(version: i32) -> Option<usize> {
    match version {
        TPACKET_V1 | TPACKET_V2 => Some(32),
        TPACKET_V3 => Some(48),
        _ => None,
    }
}

/// The header and the `struct sockaddr_ll` of a frame of `version`: `TPACKET_HDRLEN`,
/// `TPACKET2_HDRLEN` or `TPACKET3_HDRLEN`, the `tp_hdrlen` of Linux.
fn tp_hdrlen(version: i32) -> usize {
    tpacket_align(header_size(version).unwrap_or(32)) + SOCKADDR_LL
}

/// A page of a ring. The kernel and the program share it through the mapping.
#[cfg(target_os = "none")]
pub(super) type Page = Arc<rk_frame::mm::Frame>;

/// A page of a ring on the host, where the tests run and the frame allocator has no frames.
#[cfg(not(target_os = "none"))]
pub(super) type Page = Arc<HostPage>;

/// A page of memory on the host, with the operations of a `Frame` that a ring uses.
#[cfg(not(target_os = "none"))]
pub(super) struct HostPage(rk_frame::sync::SpinLock<Vec<u8>>);

#[cfg(not(target_os = "none"))]
impl HostPage {
    fn read_bytes(&self, offset: usize, buf: &mut [u8]) {
        buf.copy_from_slice(&self.0.lock()[offset..offset + buf.len()]);
    }

    fn write_bytes(&self, offset: usize, buf: &[u8]) {
        self.0.lock()[offset..offset + buf.len()].copy_from_slice(buf);
    }

    fn compare_exchange_u32(&self, offset: usize, old: u32, new: u32) -> u32 {
        let mut page = self.0.lock();
        let word: [u8; 4] = page[offset..offset + 4].try_into().unwrap_or_default();
        let value = u32::from_ne_bytes(word);
        if value == old {
            page[offset..offset + 4].copy_from_slice(&new.to_ne_bytes());
        }
        value
    }
}

/// Makes a page of zeros.
#[cfg(target_os = "none")]
fn new_page() -> Option<Page> {
    rk_frame::mm::alloc_zeroed_frame().map(Arc::new)
}

#[cfg(not(target_os = "none"))]
fn new_page() -> Option<Page> {
    Some(Arc::new(HostPage(rk_frame::sync::SpinLock::new(alloc::vec![0; PAGE_SIZE]))))
}

/// Tells if `pages` more pages can be taken. A ring takes no more than the free memory, so a
/// large request gives `ENOMEM` and does not take the memory of the other parts of the system.
#[cfg(target_os = "none")]
fn pages_free(pages: usize) -> bool {
    pages <= rk_frame::mm::frame_stats().free
}

#[cfg(not(target_os = "none"))]
fn pages_free(pages: usize) -> bool {
    pages <= 4096
}

/// The real time as seconds and nanoseconds, for the time stamps of the frames.
fn real_time() -> (u32, u32) {
    #[cfg(target_os = "none")]
    let ns = rk_frame::time::realtime_ns();
    #[cfg(not(target_os = "none"))]
    let ns = 0u64;
    ((ns / 1_000_000_000) as u32, (ns % 1_000_000_000) as u32)
}

/// The fields of `struct tpacket_req3`. A `struct tpacket_req` has the first four.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Req {
    block_size: u32,
    block_nr: u32,
    frame_size: u32,
    frame_nr: u32,
    retire_blk_tov: u32,
    sizeof_priv: u32,
    feature_req_word: u32,
}

impl Req {
    /// Reads the request of `PACKET_RX_RING` or `PACKET_TX_RING` for `version`. `TPACKET_V3`
    /// takes a `struct tpacket_req3`, and the other versions a `struct tpacket_req`.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` if `value` is too short, as `packet_setsockopt` of Linux.
    pub(super) fn parse(version: i32, value: &[u8]) -> Result<Self> {
        let words = if version == TPACKET_V3 { 7 } else { 4 };
        if value.len() < words * 4 {
            return Err(Errno::EINVAL);
        }
        let mut w = [0u32; 7];
        for (i, word) in w.iter_mut().take(words).enumerate() {
            let b = &value[i * 4..i * 4 + 4];
            *word = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]);
        }
        Ok(Self {
            block_size: w[0],
            block_nr: w[1],
            frame_size: w[2],
            frame_nr: w[3],
            retire_blk_tov: w[4],
            sizeof_priv: w[5],
            feature_req_word: w[6],
        })
    }

    /// Tells if the request removes the ring: no blocks.
    pub(super) fn removes(&self) -> bool {
        self.block_nr == 0
    }

    /// Checks a request that removes the ring. It must have no frames, as `packet_set_ring`.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` if the request has frames.
    pub(super) fn check_remove(&self) -> Result<()> {
        if self.frame_nr != 0 { Err(Errno::EINVAL) } else { Ok(()) }
    }
}

/// The counts of `PACKET_STATISTICS`, as `struct tpacket_stats_v3`.
#[derive(Default)]
pub(super) struct Stats {
    /// The packets that the socket took.
    pub(super) packets: AtomicU32,
    /// The packets that the socket dropped, `tp_drops`.
    pub(super) drops: AtomicU32,
    /// The times that the queue of a `TPACKET_V3` ring froze, `tp_freeze_q_cnt`.
    pub(super) freeze: AtomicU32,
}

impl Stats {
    /// Gives the counts and sets them to 0, as `packet_getsockopt` of Linux. `tp_packets` also
    /// counts the dropped packets. `TPACKET_V3` gives a `struct tpacket_stats_v3`, and the other
    /// versions a `struct tpacket_stats`.
    pub(super) fn take(&self, version: i32) -> Vec<u8> {
        let drops = self.drops.swap(0, Ordering::Relaxed);
        let packets = self.packets.swap(0, Ordering::Relaxed).wrapping_add(drops);
        let freeze = self.freeze.swap(0, Ordering::Relaxed);
        let mut v = Vec::with_capacity(12);
        v.extend_from_slice(&packets.to_ne_bytes());
        v.extend_from_slice(&drops.to_ne_bytes());
        if version == TPACKET_V3 {
            v.extend_from_slice(&freeze.to_ne_bytes());
        }
        v
    }
}

/// A frame of a transmit ring: the offset and the packet, or the offset and the error.
pub(super) type SendFrame = core::result::Result<(usize, Vec<u8>), (usize, Errno)>;

/// A received packet for a ring.
pub(super) struct Packet<'a> {
    /// The data that the socket gets: the link header and the payload for `SOCK_RAW`, else the
    /// payload.
    pub(super) data: &'a [u8],
    /// The size of the packet before the filter cut it, `tp_len` of Linux.
    pub(super) len: usize,
    /// The size of the link header at the start of `data`.
    pub(super) maclen: usize,
    /// The socket is `SOCK_DGRAM`.
    pub(super) dgram: bool,
    /// The `struct sockaddr_ll` of the sender.
    pub(super) addr: &'a [u8; SOCKADDR_LL],
}

/// The state of the blocks of a `TPACKET_V3` receive ring, `struct tpacket_kbdq_core` of Linux.
struct Blocks {
    /// The block that takes the packets now, `kactive_blk_num`.
    active: usize,
    /// The active block at the last start of the timer, `last_kactive_blk_num`.
    last_active: usize,
    /// The offset of the first packet in a block: the descriptor and the private area,
    /// `BLK_PLUS_PRIV(tp_sizeof_priv)`.
    first: usize,
    /// The largest packet with its header, `max_frame_len`.
    max_frame_len: usize,
    /// The sequence number of the next block that opens, `knxt_seq_num`.
    seq: u64,
    /// The offset in the active block of the next packet, `nxt_offset`.
    next: usize,
    /// The offset in the active block of the last packet, `prev`.
    prev: usize,
    /// The packets and the bytes in the active block, `BLOCK_NUM_PKTS` and `BLOCK_LEN`.
    count: u32,
    len: usize,
    /// The time of the last packet in the active block.
    last_ts: (u32, u32),
    /// The next block was still the program's, so the queue is frozen,
    /// `reset_pending_on_curr_blk`.
    frozen: bool,
    /// The time that a block stays open, in ticks.
    tov: u64,
    /// The tick at which the timer runs, as the retire timer of Linux.
    deadline: u64,
}

/// A ring of a packet socket, `struct packet_ring_buffer` of Linux.
pub(super) struct Ring {
    pages: Vec<Page>,
    version: i32,
    /// `tp_hdrlen` and `tp_reserve` when the ring was made. Neither can change while the ring
    /// exists.
    hdrlen: usize,
    reserve: usize,
    block_size: usize,
    block_nr: usize,
    frame_size: usize,
    frames_per_block: usize,
    /// The last frame, `frame_max`.
    frame_max: usize,
    /// The next frame of the program or the kernel, `head`.
    head: usize,
    /// The block state of a `TPACKET_V3` receive ring.
    blocks: Option<Blocks>,
}

impl Ring {
    /// Makes a ring for `req`, as `packet_set_ring` of Linux. `now` is the tick count, and `hz`
    /// the ticks in a second.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` for a block size that is not a multiple of the page size, a frame size that
    /// is too small or not aligned to `TPACKET_ALIGNMENT`, a frame count that is not the blocks
    /// times the frames in a block, or a private area of `TPACKET_V3` that does not fit. Gives
    /// `ENOMEM` if there is not sufficient memory.
    pub(super) fn new(
        version: i32,
        reserve: u32,
        req: &Req,
        tx: bool,
        now: u64,
        hz: u64,
    ) -> Result<Self> {
        let hdrlen = tp_hdrlen(version);
        if req.block_size as i32 <= 0 || !(req.block_size as usize).is_multiple_of(PAGE_SIZE) {
            return Err(Errno::EINVAL);
        }
        let min_frame = hdrlen as u64 + u64::from(reserve);
        let first = BLK_HDR_LEN as u64 + u64::from(req.sizeof_priv).next_multiple_of(8);
        if version == TPACKET_V3 && u64::from(req.block_size) < first + min_frame {
            return Err(Errno::EINVAL);
        }
        if u64::from(req.frame_size) < min_frame
            || !(req.frame_size as usize).is_multiple_of(TPACKET_ALIGNMENT)
        {
            return Err(Errno::EINVAL);
        }
        let frames_per_block = req.block_size / req.frame_size;
        if frames_per_block == 0
            || frames_per_block > u32::MAX / req.block_nr
            || frames_per_block * req.block_nr != req.frame_nr
        {
            return Err(Errno::EINVAL);
        }
        // Linux makes no blocks for a transmit ring of `TPACKET_V3`, so the fields of the blocks
        // must be 0.
        if version == TPACKET_V3
            && tx
            && (req.retire_blk_tov != 0 || req.sizeof_priv != 0 || req.feature_req_word != 0)
        {
            return Err(Errno::EINVAL);
        }
        let block_size = req.block_size as usize;
        let block_nr = req.block_nr as usize;
        let count = (block_size / PAGE_SIZE).checked_mul(block_nr).ok_or(Errno::ENOMEM)?;
        if !pages_free(count) {
            return Err(Errno::ENOMEM);
        }
        let mut pages = Vec::new();
        pages.try_reserve_exact(count).map_err(|_| Errno::ENOMEM)?;
        for _ in 0..count {
            pages.push(new_page().ok_or(Errno::ENOMEM)?);
        }
        let mut ring = Self {
            pages,
            version,
            hdrlen,
            reserve: reserve as usize,
            block_size,
            block_nr,
            frame_size: req.frame_size as usize,
            frames_per_block: frames_per_block as usize,
            frame_max: req.frame_nr as usize - 1,
            head: 0,
            blocks: None,
        };
        if version == TPACKET_V3 && !tx {
            // As `init_prb_bdqc` and `prb_open_block` of Linux.
            let ms = match req.retire_blk_tov {
                0 => DEFAULT_RETIRE_TOV,
                t => u64::from(t),
            };
            let first = first as usize;
            ring.blocks = Some(Blocks {
                active: 0,
                last_active: 0,
                first,
                max_frame_len: block_size - first,
                seq: 1,
                next: first,
                prev: first,
                count: 0,
                len: first,
                last_ts: (0, 0),
                frozen: false,
                tov: (ms * hz).div_ceil(1000).max(1),
                deadline: 0,
            });
            ring.open_block(now);
        }
        Ok(ring)
    }

    /// The pages of the ring, in the order of the mapping.
    pub(super) fn pages(&self) -> &[Page] {
        &self.pages
    }

    /// Copies the bytes of the ring at `offset` to `buf`. A copy can cross pages.
    pub(super) fn read(&self, offset: usize, buf: &mut [u8]) {
        let mut done = 0;
        while done < buf.len() {
            let at = offset + done;
            let n = (PAGE_SIZE - at % PAGE_SIZE).min(buf.len() - done);
            let Some(page) = self.pages.get(at / PAGE_SIZE) else { return };
            page.read_bytes(at % PAGE_SIZE, &mut buf[done..done + n]);
            done += n;
        }
    }

    /// Copies `buf` to the ring at `offset`.
    pub(super) fn write(&self, offset: usize, buf: &[u8]) {
        let mut done = 0;
        while done < buf.len() {
            let at = offset + done;
            let n = (PAGE_SIZE - at % PAGE_SIZE).min(buf.len() - done);
            let Some(page) = self.pages.get(at / PAGE_SIZE) else { return };
            page.write_bytes(at % PAGE_SIZE, &buf[done..done + n]);
            done += n;
        }
    }

    fn put16(&self, offset: usize, v: u16) {
        self.write(offset, &v.to_ne_bytes());
    }

    fn put32(&self, offset: usize, v: u32) {
        self.write(offset, &v.to_ne_bytes());
    }

    /// Reads the 32 bit word at `offset`.
    pub(super) fn get32(&self, offset: usize) -> u32 {
        let mut b = [0; 4];
        self.read(offset, &mut b);
        u32::from_ne_bytes(b)
    }

    /// Reads the status word at `offset` in one access. The program can write it at the same
    /// time.
    pub(super) fn status(&self, offset: usize) -> u32 {
        self.pages
            .get(offset / PAGE_SIZE)
            .map_or(u32::MAX, |p| p.compare_exchange_u32(offset % PAGE_SIZE, 0, 0))
    }

    /// Writes the status word at `offset` in one access, after the other writes of the frame,
    /// as `__packet_set_status` of Linux.
    pub(super) fn set_status(&self, offset: usize, status: u32) {
        let Some(page) = self.pages.get(offset / PAGE_SIZE) else { return };
        let at = offset % PAGE_SIZE;
        let mut old = page.compare_exchange_u32(at, 0, 0);
        loop {
            match page.compare_exchange_u32(at, old, status) {
                v if v == old => return,
                v => old = v,
            }
        }
    }

    /// The offset of the frame `index`, as `packet_lookup_frame` of Linux.
    pub(super) fn frame_at(&self, index: usize) -> usize {
        let block = index / self.frames_per_block;
        block * self.block_size + (index % self.frames_per_block) * self.frame_size
    }

    /// The offset of the frame at the head.
    pub(super) fn head_frame(&self) -> usize {
        self.frame_at(self.head)
    }

    /// Moves the head to the next frame, as `packet_increment_head` of Linux.
    pub(super) fn advance(&mut self) {
        self.head = if self.head == self.frame_max { 0 } else { self.head + 1 };
    }

    /// Tells if the program has a frame or a block to read, as `packet_previous_rx_frame` in
    /// `packet_poll` of Linux: the frame or block before the head is not the kernel's.
    pub(super) fn readable(&self) -> bool {
        match &self.blocks {
            Some(b) => {
                let prev = if b.active == 0 { self.block_nr - 1 } else { b.active - 1 };
                self.status(prev * self.block_size + 8) != TP_STATUS_KERNEL
            }
            None => {
                let prev = if self.head == 0 { self.frame_max } else { self.head - 1 };
                self.status(self.frame_at(prev)) != TP_STATUS_KERNEL
            }
        }
    }

    /// The offsets of the link header and of the network header in a frame for `p`, as
    /// `tpacket_rcv` of Linux. A `SOCK_DGRAM` socket gets no link header.
    fn offsets(&self, p: &Packet<'_>) -> (usize, usize) {
        if p.dgram {
            let off = tpacket_align(self.hdrlen) + 16 + self.reserve;
            (off, off)
        } else {
            let net = tpacket_align(self.hdrlen + p.maclen.max(16)) + self.reserve;
            (net - p.maclen, net)
        }
    }

    /// Puts a received packet in the ring, as `tpacket_rcv` of Linux. Gives `true` if the ring
    /// took it, and `false` if the ring has no free frame.
    pub(super) fn receive(&mut self, p: &Packet<'_>, stats: &Stats, now: u64) -> bool {
        let (mut macoff, netoff) = self.offsets(p);
        if netoff > usize::from(u16::MAX) {
            return false;
        }
        let mut snaplen = p.data.len();
        let mut status = TP_STATUS_USER | TP_STATUS_TS_SOFTWARE;
        if stats.drops.load(Ordering::Relaxed) != 0 {
            status |= TP_STATUS_LOSING;
        }
        let (sec, nsec) = real_time();
        let at = if let Some(max) = self.blocks.as_ref().map(|b| b.max_frame_len) {
            if macoff + snaplen > max {
                if max >= macoff {
                    snaplen = max - macoff;
                } else {
                    snaplen = 0;
                    macoff = max;
                }
            }
            let Some(at) = self.place(macoff + snaplen, stats, now) else { return false };
            // `struct tpacket3_hdr`. `place` wrote `tp_next_offset`.
            self.put32(at + 4, sec);
            self.put32(at + 8, nsec);
            self.put32(at + 12, snaplen as u32);
            self.put32(at + 16, p.len as u32);
            self.put32(at + 20, status);
            self.put16(at + 24, macoff as u16);
            self.put16(at + 26, netoff as u16);
            self.write(at + 28, &[0; 20]);
            if let Some(b) = self.blocks.as_mut() {
                b.last_ts = (sec, nsec);
            }
            at
        } else {
            if macoff + snaplen > self.frame_size {
                snaplen = self.frame_size.saturating_sub(macoff);
            }
            let at = self.head_frame();
            if self.status(at) != TP_STATUS_KERNEL {
                return false;
            }
            if self.version == TPACKET_V1 {
                // `struct tpacket_hdr`: the status is a `long`, and the time has microseconds.
                self.put32(at + 4, 0);
                self.put32(at + 8, p.len as u32);
                self.put32(at + 12, snaplen as u32);
                self.put16(at + 16, macoff as u16);
                self.put16(at + 18, netoff as u16);
                self.put32(at + 20, sec);
                self.put32(at + 24, nsec / 1000);
            } else {
                // `struct tpacket2_hdr`.
                self.put32(at + 4, p.len as u32);
                self.put32(at + 8, snaplen as u32);
                self.put16(at + 12, macoff as u16);
                self.put16(at + 14, netoff as u16);
                self.put32(at + 16, sec);
                self.put32(at + 20, nsec);
                self.write(at + 24, &[0; 8]);
            }
            at
        };
        let hdr = header_size(self.version).unwrap_or(32);
        self.write(at + tpacket_align(hdr), p.addr);
        self.write(at + macoff, &p.data[..snaplen]);
        stats.packets.fetch_add(1, Ordering::Relaxed);
        if self.blocks.is_none() {
            self.advance();
            self.set_status(at, status);
        }
        true
    }

    /// The offset of the descriptor of the block `n`.
    fn block_at(&self, n: usize) -> usize {
        n * self.block_size
    }

    /// Opens the active block for new packets, as `prb_open_block` of Linux. This also thaws the
    /// queue and starts the timer again.
    fn open_block(&mut self, now: u64) {
        let Some(b) = self.blocks.as_mut() else { return };
        let base = b.active * self.block_size;
        let seq = b.seq;
        b.seq += 1;
        b.count = 0;
        b.len = b.first;
        b.next = b.first;
        b.prev = b.first;
        b.frozen = false;
        b.deadline = now + b.tov;
        b.last_active = b.active;
        let first = b.first as u32;
        let (sec, nsec) = real_time();
        // `struct tpacket_block_desc` with `struct tpacket_hdr_v1`.
        self.put32(base, TPACKET_V3 as u32);
        self.put32(base + 4, BLK_HDR_LEN as u32);
        self.put32(base + 12, 0);
        self.put32(base + 16, first);
        self.put32(base + 20, first);
        self.write(base + 24, &seq.to_ne_bytes());
        self.put32(base + 32, sec);
        self.put32(base + 36, nsec);
    }

    /// Finds the place of a packet of `len` bytes with its header in a block, as
    /// `__packet_lookup_frame_in_block` of Linux. Gives the offset in the ring, or `None` if the
    /// queue is frozen.
    fn place(&mut self, len: usize, stats: &Stats, now: u64) -> Option<usize> {
        let b = self.blocks.as_ref()?;
        if b.frozen {
            if self.status(self.block_at(b.active) + 8) & TP_STATUS_USER != 0 {
                return None;
            }
            self.open_block(now);
        }
        let size = align8(len);
        let b = self.blocks.as_ref()?;
        let curr = if b.next + size < self.block_size {
            b.next
        } else {
            self.retire(0, stats);
            self.dispatch(stats, now)?
        };
        let b = self.blocks.as_mut()?;
        b.prev = curr;
        b.next = curr + size;
        b.len += size;
        b.count += 1;
        let (base, count, blen) = (b.active * self.block_size, b.count, b.len as u32);
        // As `prb_fill_curr_block` of Linux.
        self.put32(base + curr, size as u32);
        self.put32(base + 12, count);
        self.put32(base + 20, blen);
        Some(base + curr)
    }

    /// Closes the active block if it is the kernel's, gives it to the program, and makes the next
    /// block active, as `prb_retire_current_block` and `prb_close_block` of Linux.
    fn retire(&mut self, status: u32, stats: &Stats) {
        let Some(b) = self.blocks.as_ref() else { return };
        let base = self.block_at(b.active);
        if self.status(base + 8) != TP_STATUS_KERNEL {
            return;
        }
        let mut status = TP_STATUS_USER | status;
        if stats.drops.load(Ordering::Relaxed) != 0 {
            status |= TP_STATUS_LOSING;
        }
        let (sec, nsec) = if b.count != 0 { b.last_ts } else { real_time() };
        self.put32(base + b.prev, 0);
        self.put32(base + 40, sec);
        self.put32(base + 44, nsec);
        self.set_status(base + 8, status);
        let nr = self.block_nr;
        if let Some(b) = self.blocks.as_mut() {
            b.active = (b.active + 1) % nr;
        }
    }

    /// Opens the active block if the program gave it back, else freezes the queue, as
    /// `prb_dispatch_next_block` of Linux. Gives the offset in the block of the first packet.
    fn dispatch(&mut self, stats: &Stats, now: u64) -> Option<usize> {
        let b = self.blocks.as_mut()?;
        if self.pages.is_empty() {
            return None;
        }
        let base = b.active * self.block_size;
        let page = &self.pages[base / PAGE_SIZE];
        if page.compare_exchange_u32(base % PAGE_SIZE + 8, 0, 0) & TP_STATUS_USER != 0 {
            b.frozen = true;
            stats.freeze.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        self.open_block(now);
        self.blocks.as_ref().map(|b| b.next)
    }

    /// The tick at which the retire timer of a `TPACKET_V3` receive ring runs.
    pub(super) fn deadline(&self) -> Option<u64> {
        self.blocks.as_ref().map(|b| b.deadline)
    }

    /// Runs the retire timer if its time came, as `prb_retire_rx_blk_timer_expired` of Linux. A
    /// block with packets that stayed active for the whole time goes to the program with
    /// `TP_STATUS_BLK_TMO`. Gives `true` if a block went to the program.
    pub(super) fn expire(&mut self, stats: &Stats, now: u64) -> bool {
        let Some(b) = self.blocks.as_ref() else { return false };
        if now < b.deadline {
            return false;
        }
        let mut done = false;
        if b.last_active == b.active {
            if !b.frozen {
                if b.count != 0 {
                    self.retire(TP_STATUS_BLK_TMO, stats);
                    done = true;
                    if self.dispatch(stats, now).is_some() {
                        return true;
                    }
                }
            } else if self.status(self.block_at(b.active) + 8) & TP_STATUS_USER == 0 {
                // The program gave the block back while the link was idle.
                self.open_block(now);
                return false;
            }
        }
        if let Some(b) = self.blocks.as_mut() {
            b.deadline = now + b.tov;
            b.last_active = b.active;
        }
        done
    }

    /// Takes the frame at the head of a transmit ring if the program asks to send it, as
    /// `packet_current_frame` and `tpacket_parse_header` of Linux. `max` is the largest packet.
    /// Gives the offset of the frame and the packet, or `None` if the frame is not ready. The
    /// frame is `TP_STATUS_SENDING` after this.
    ///
    /// # Errors
    ///
    /// Gives the offset of the frame with `EINVAL` for a `TPACKET_V3` frame with a next offset,
    /// or with `EMSGSIZE` for a packet that is larger than `max`.
    pub(super) fn take_send(&self, max: usize) -> Option<SendFrame> {
        let at = self.head_frame();
        if self.status(at) != TP_STATUS_SEND_REQUEST {
            return None;
        }
        let len = match self.version {
            TPACKET_V3 => {
                if self.get32(at) != 0 {
                    return Some(Err((at, Errno::EINVAL)));
                }
                self.get32(at + 16)
            }
            TPACKET_V2 => self.get32(at + 4),
            _ => self.get32(at + 8),
        } as usize;
        // The data comes after the header, at `tp_hdrlen - sizeof(struct sockaddr_ll)`.
        let off = self.hdrlen - SOCKADDR_LL;
        if len > max || len > self.frame_size - off {
            return Some(Err((at, Errno::EMSGSIZE)));
        }
        let mut data = alloc::vec![0; len];
        self.read(at + off, &mut data);
        self.set_status(at, TP_STATUS_SENDING);
        Some(Ok((at, data)))
    }

    /// The largest packet that a frame of a transmit ring holds.
    pub(super) fn send_max(&self) -> usize {
        self.frame_size - (self.hdrlen - SOCKADDR_LL)
    }
}

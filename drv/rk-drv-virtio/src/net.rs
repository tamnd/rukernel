//! virtio-net, from section 5.1 of the virtio 1.2 specification.
//!
//! The device has one receive queue and one transmit queue. Each buffer is one frame with the
//! header of virtio-net and then the Ethernet frame. The driver keeps all of the receive buffers
//! in the receive queue, and gives each buffer back to the device after it copies the frame out.
//! The driver does not use interrupts: `poll` reads the used ring of the receive queue, and
//! `transmit` takes back the sent buffers from the used ring of the transmit queue.

use crate::net_hdr::{self, NetHdr};
use crate::queue::{Buffer, Queue};
use crate::ring::Slots;
use crate::transport::{Transport, status};
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_frame::addr::PAGE_SIZE;
use rk_frame::mm::{Frame, alloc_zeroed_frame};
use rk_frame::sync::SpinLock;
use rk_net::buf::NetBuf;
use rk_net::dev::{LinkKind, NetDevice, NetDriver, register};
use rk_net::ether::MacAddr;
use rk_vfs::inode::Result;

/// The device has a MAC address in its configuration.
const F_MAC: u64 = 1 << 5;
/// The device has the status of the link in its configuration.
const F_STATUS: u64 = 1 << 16;

/// The offsets of the fields `mac` and `status` in the device configuration.
const CONFIG_MAC: usize = 0;
const CONFIG_STATUS: usize = 6;
/// The bit of the field `status` for a link that is up.
const S_LINK_UP: u16 = 1;

/// The queue numbers.
const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;

/// The most buffers in each queue.
const MAX_BUFFERS: u16 = 64;
/// The length of a buffer: one frame, which holds the header and the largest Ethernet frame.
const BUF_LEN: usize = PAGE_SIZE;

/// One queue and its buffers. The buffer of the descriptor `id` is `bufs[id]`.
struct Ring {
    queue: Queue,
    bufs: Vec<Frame>,
    slots: Slots,
}

impl Ring {
    /// Makes the queue `index` with a buffer for each descriptor, at most `MAX_BUFFERS`.
    fn new(t: &Transport, index: u16, device_writes: bool) -> Option<Self> {
        let mut queue = Queue::new(t, index)?;
        let n = queue.size().min(MAX_BUFFERS);
        let bufs = (0..n).map(|_| alloc_zeroed_frame()).collect::<Option<Vec<_>>>()?;
        // A buffer of the transmit queue gets its length when the driver sends a frame.
        if device_writes {
            for (id, f) in (0..n).zip(&bufs) {
                let b = Buffer { addr: f.addr().get(), len: BUF_LEN as u32, device_writes };
                queue.set_descriptor(id, b, None);
            }
        }
        Some(Self { queue, bufs, slots: Slots::new(n) })
    }
}

/// Starts the driver for the network device number `index` on the transport `t`, and registers
/// the device. `bus` is the number of the device among all virtio devices, as the name `virtioN`
/// of Linux.
pub(crate) fn probe(t: Transport, index: u32, bus: u32) -> Option<Arc<NetDevice>> {
    let Some(features) = t.negotiate(F_MAC | F_STATUS) else {
        t.fail();
        return None;
    };
    let (Some(mut rx), Some(tx)) = (Ring::new(&t, RX_QUEUE, true), Ring::new(&t, TX_QUEUE, false))
    else {
        t.fail();
        return None;
    };
    let mac = if features & F_MAC != 0 {
        MacAddr(core::array::from_fn(|k| t.device_u8(CONFIG_MAC + k)))
    } else {
        // A locally administered address. Linux takes a random one.
        MacAddr([0x02, 0, 0, 0, (index >> 8) as u8, index as u8])
    };
    t.add_status(status::DRIVER_OK);
    while let Some(id) = rx.slots.take() {
        rx.queue.push_avail(id);
    }
    rx.queue.kick(&t);
    let driver = VirtioNet {
        mac,
        bus,
        status: features & F_STATUS != 0,
        t,
        rx: SpinLock::new(rx),
        tx: SpinLock::new(tx),
    };
    register(Arc::new(driver)).ok()
}

/// A virtio-net device.
struct VirtioNet {
    mac: MacAddr,
    /// The number of the device on the virtio bus.
    bus: u32,
    /// The device has the status of the link.
    status: bool,
    t: Transport,
    rx: SpinLock<Ring>,
    tx: SpinLock<Ring>,
}

impl NetDriver for VirtioNet {
    fn kind(&self) -> LinkKind {
        LinkKind::Ether
    }

    fn mac(&self) -> MacAddr {
        self.mac
    }

    fn parent(&self) -> Option<(String, &'static str)> {
        Some((format!("virtio{}", self.bus), "virtio"))
    }

    fn link_up(&self) -> bool {
        !self.status || self.t.device_u16(CONFIG_STATUS) & S_LINK_UP != 0
    }

    fn transmit(&self, frame: NetBuf) -> Result<()> {
        let len = net_hdr::LEN + frame.len();
        if len > BUF_LEN {
            return Err(Errno::EMSGSIZE);
        }
        let mut tx = self.tx.lock();
        while let Some((id, _)) = tx.queue.pop_used() {
            tx.slots.give_back(id);
        }
        let Some(id) = tx.slots.take() else {
            return Err(Errno::ENOBUFS);
        };
        let buf = &tx.bufs[usize::from(id)];
        buf.write_bytes(0, &NetHdr::default().to_bytes());
        buf.write_bytes(net_hdr::LEN, frame.data());
        let b = Buffer { addr: buf.addr().get(), len: len as u32, device_writes: false };
        tx.queue.set_descriptor(id, b, None);
        tx.queue.push_avail(id);
        tx.queue.kick(&self.t);
        Ok(())
    }

    fn poll(&self, budget: usize, deliver: &mut dyn FnMut(NetBuf)) -> usize {
        let mut frames = Vec::new();
        {
            let mut rx = self.rx.lock();
            let mut posted = false;
            while frames.len() < budget {
                let Some((id, len)) = rx.queue.pop_used() else { break };
                // A bad device can give a descriptor that it does not have. The driver skips it.
                if !rx.slots.give_back(id) {
                    continue;
                }
                let len = (len as usize).min(BUF_LEN);
                let buf = &rx.bufs[id as usize];
                let mut hdr = [0; net_hdr::LEN];
                buf.read_bytes(0, &mut hdr);
                // Without `F_MRG_RXBUF` the device puts each frame in one buffer.
                let one = NetHdr::parse(&hdr).is_some_and(|h| h.num_buffers <= 1);
                if one && len > net_hdr::LEN {
                    let mut frame = NetBuf::zeroed(len - net_hdr::LEN);
                    buf.read_bytes(net_hdr::LEN, frame.data_mut());
                    frames.push(frame);
                }
                // The descriptor of each buffer does not change, so the buffer goes back as it is.
                if let Some(id) = rx.slots.take() {
                    rx.queue.push_avail(id);
                    posted = true;
                }
            }
            if posted {
                rx.queue.kick(&self.t);
            }
        }
        // The lock is not held while `deliver` runs, so `deliver` can send a reply.
        let n = frames.len();
        frames.into_iter().for_each(deliver);
        n
    }
}

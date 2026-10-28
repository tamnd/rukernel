//! The line disciplines that make a network device: SLIP, as drivers/net/slip/slip.c of Linux,
//! and the serial line CAN, as drivers/net/can/slcan/slcan-core.c of Linux.
//!
//! `TIOCSETD` with `N_SLIP` or `N_SLCAN` on a terminal makes a network device, `slN` or
//! `slcanN`. The bytes that the terminal receives make the frames that the device receives. A
//! frame that the device sends goes to the terminal as bytes. The device goes away when the
//! terminal gets another line discipline or a hang up.
//!
//! SLIP puts `END` after each frame, and `END` before it too, as RFC 1055. It changes `END` and
//! `ESC` in the data to `ESC ESC_END` and `ESC ESC_ESC`. The serial line CAN sends each CAN frame
//! as one line of text, for example `t0018112233445566778899\r`: the command, the identifier in
//! hexadecimal, the length and the data in hexadecimal.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use rk_abi::Errno;
use rk_abi::native::if_ether::{ETH_P_CAN, ETH_P_IP};
use rk_frame::sync::SpinLock;
use rk_net::buf::NetBuf;
use rk_net::consts::{ARPHRD_CAN, ARPHRD_SLIP, IFF_MULTICAST, IFF_NOARP, IFF_POINTOPOINT};
use rk_net::dev::{self, LinkKind, NetDevice, NetDriver};
use rk_net::ether::{EthHeader, HLEN, MacAddr};
use rk_vfs::cred::{self, cap};
use rk_vfs::inode::Result;

/// The line discipline of a terminal, `N_TTY` of <linux/tty.h>.
pub const N_TTY: i32 = 0;
/// The SLIP line discipline.
pub const N_SLIP: i32 = 1;
/// The serial line CAN line discipline.
pub const N_SLCAN: i32 = 17;
/// The number of line disciplines, `NR_LDISCS`. A larger number gives `EINVAL`.
pub const NR_LDISCS: i32 = 31;

/// The bytes of SLIP, as slip.h of Linux: the end of a frame, and the escape.
const END: u8 = 0o300;
const ESC: u8 = 0o333;
/// `ESC ESC_END` is an `END` in the data, and `ESC ESC_ESC` is an `ESC`.
const ESC_END: u8 = 0o334;
const ESC_ESC: u8 = 0o335;

/// The MTU of a new SLIP device, `SL_MTU` of Linux.
const SL_MTU: u32 = 296;
/// The smallest and the largest MTU of a SLIP device, as `sl_setup` of Linux.
const SL_MIN_MTU: u32 = 68;
const SL_MAX_MTU: u32 = 65534;
/// The length of the queue of a new device, as `sl_setup` and `slc_setup` of Linux.
const TX_QUEUE_LEN: u32 = 10;
/// The most SLIP devices and serial line CAN devices, the defaults of `slip_maxdev` and
/// `maxdev` of Linux.
const SL_MAXDEV: u32 = 256;
const SLC_MAXDEV: u32 = 10;

/// The size of `struct can_frame`, `CAN_MTU` of Linux. It is the MTU of a CAN device.
pub const CAN_MTU: usize = 16;
/// The most data bytes of a CAN frame, `CAN_MAX_DLEN`.
const CAN_MAX_DLEN: usize = 8;
/// The flags of `can_id`: an extended identifier, and a remote request.
const CAN_EFF_FLAG: u32 = 0x8000_0000;
const CAN_RTR_FLAG: u32 = 0x4000_0000;
/// The bits of a standard and of an extended identifier.
const CAN_SFF_MASK: u32 = 0x7ff;
const CAN_EFF_MASK: u32 = 0x1fff_ffff;
/// The largest line of the serial line CAN, `SLCAN_MTU` of Linux: the size of
/// `"T1111222281122334455667788EA5F\r"` with its NUL, and one more byte.
const SLCAN_MTU: usize = 33;

/// The protocol of a line discipline that makes a network device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    /// `N_SLIP`.
    Slip,
    /// `N_SLCAN`.
    Slcan,
}

impl Proto {
    /// The protocol of the line discipline `n`, or `None` for another line discipline.
    pub fn from_ldisc(n: i32) -> Option<Self> {
        match n {
            N_SLIP => Some(Self::Slip),
            N_SLCAN => Some(Self::Slcan),
            _ => None,
        }
    }

    /// The number of the line discipline.
    pub fn ldisc(self) -> i32 {
        match self {
            Self::Slip => N_SLIP,
            Self::Slcan => N_SLCAN,
        }
    }
}

/// Puts the SLIP frame of `data` in `out`, as `slip_esc` of Linux: `END`, the data with `END`
/// and `ESC` changed, and `END`.
pub fn slip_encode(data: &[u8], out: &mut Vec<u8>) {
    out.push(END);
    for &b in data {
        match b {
            END => out.extend_from_slice(&[ESC, ESC_END]),
            ESC => out.extend_from_slice(&[ESC, ESC_ESC]),
            b => out.push(b),
        }
    }
    out.push(END);
}

/// The state of the receive side of a line, as the `rbuff`, `rcount` and the flags `SLF_ESCAPE`
/// and `SLF_ERROR` of Linux.
#[derive(Default)]
pub struct LineRx {
    buf: Vec<u8>,
    escape: bool,
    error: bool,
}

impl LineRx {
    /// Takes the byte `b` of SLIP, as `slip_unesc` of Linux. A frame holds at most `limit`
    /// bytes, else the frame has an error and goes away. Gives the frame that `END` completes.
    /// A frame of 2 bytes or less goes away.
    pub fn slip(&mut self, b: u8, limit: usize) -> Option<Vec<u8>> {
        let s = match b {
            END => {
                let error = core::mem::take(&mut self.error);
                self.escape = false;
                let frame = core::mem::take(&mut self.buf);
                return (!error && frame.len() > 2).then_some(frame);
            }
            ESC => {
                self.escape = true;
                return None;
            }
            ESC_ESC if core::mem::take(&mut self.escape) => ESC,
            ESC_END if core::mem::take(&mut self.escape) => END,
            b => b,
        };
        self.put(s, limit);
        None
    }

    /// Takes the byte `b` of the serial line CAN, as `slcan_unesc` of Linux. A carriage return
    /// or a bell ends a line. Gives the line that it ends, if it has more than 4 bytes.
    pub fn slcan(&mut self, b: u8) -> Option<Vec<u8>> {
        if b == b'\r' || b == 0x07 {
            let error = core::mem::take(&mut self.error);
            let line = core::mem::take(&mut self.buf);
            return (!error && line.len() > 4).then_some(line);
        }
        self.put(b, SLCAN_MTU);
        None
    }

    /// Puts one byte in the frame. A full frame gets an error, as `rx_over_errors` of Linux.
    fn put(&mut self, b: u8, limit: usize) {
        if self.error {
            return;
        }
        if self.buf.len() < limit {
            self.buf.push(b);
        } else {
            self.error = true;
        }
    }

    /// Clears the frame, as a flush of the input.
    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

/// The value of the hexadecimal digit `c`, as `hex_to_bin` of Linux.
fn hex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

/// The number of the hexadecimal text `s`, as `kstrtou32` with base 16 of Linux. It can start
/// with `0x`.
fn hex_u32(s: &[u8]) -> Option<u32> {
    let s = match s {
        [b'0', b'x' | b'X', rest @ ..] => rest,
        s => s,
    };
    if s.is_empty() {
        return None;
    }
    s.iter().try_fold(0u32, |n, &c| n.checked_mul(16)?.checked_add(u32::from(hex(c)?)))
}

/// The `struct can_frame` of the line `line` of the serial line CAN, as `slc_bump` of Linux.
/// Gives `None` for a bad line. The padding bytes are zero.
pub fn slcan_decode(line: &[u8]) -> Option<[u8; CAN_MTU]> {
    let (&cmd, rest) = line.split_first()?;
    let (mut id, id_len) = match cmd {
        b't' => (0, 3),
        b'r' => (CAN_RTR_FLAG, 3),
        b'T' => (CAN_EFF_FLAG, 8),
        b'R' => (CAN_EFF_FLAG | CAN_RTR_FLAG, 8),
        _ => return None,
    };
    id |= hex_u32(rest.get(..id_len)?)?;
    let rest = &rest[id_len..];
    let len = match rest.first()? {
        c @ b'0'..=b'8' => usize::from(c - b'0'),
        _ => return None,
    };
    let mut frame = [0u8; CAN_MTU];
    frame[..4].copy_from_slice(&id.to_ne_bytes());
    frame[4] = len as u8;
    // A remote request has a length, but no data.
    if id & CAN_RTR_FLAG == 0 {
        let data = rest.get(1..1 + 2 * len)?;
        for (i, pair) in data.chunks(2).enumerate() {
            frame[8 + i] = hex(pair[0])? << 4 | hex(pair[1])?;
        }
    }
    Some(frame)
}

/// Puts the line of the `struct can_frame` `frame` in `out`, as `slc_encaps` of Linux. The
/// command is lowercase for a standard identifier, and the hexadecimal digits are uppercase.
/// Gives `false` for a bad frame, as `can_dropped_invalid_skb` of Linux.
pub fn slcan_encode(frame: &[u8], out: &mut Vec<u8>) -> bool {
    if frame.len() != CAN_MTU || usize::from(frame[4]) > CAN_MAX_DLEN {
        return false;
    }
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let id = u32::from_ne_bytes([frame[0], frame[1], frame[2], frame[3]]);
    let len = usize::from(frame[4]);
    let rtr = id & CAN_RTR_FLAG != 0;
    let (cmd, id, digits) = if id & CAN_EFF_FLAG != 0 {
        (if rtr { b'R' } else { b'T' }, id & CAN_EFF_MASK, 8)
    } else {
        (if rtr { b'r' } else { b't' }, id & CAN_SFF_MASK, 3)
    };
    out.push(cmd);
    for i in (0..digits).rev() {
        out.push(DIGITS[(id >> (4 * i) & 0xf) as usize]);
    }
    out.push(b'0' + len as u8);
    if !rtr {
        for &b in &frame[8..8 + len] {
            out.extend_from_slice(&[DIGITS[usize::from(b >> 4)], DIGITS[usize::from(b & 0xf)]]);
        }
    }
    out.push(b'\r');
    true
}

/// The terminal of a line, which takes the bytes of the frames that the device sends.
pub trait LineOut: Send + Sync {
    /// Writes `data` to the terminal, as `tty->ops->write` of Linux. Gives `ENOBUFS` if the
    /// terminal has no room, and the frame goes away.
    fn write_line(&self, data: &[u8]) -> Result<()>;
}

/// The network device of a terminal line, as `struct slip` and `struct slcan` of Linux.
pub struct NetLine {
    proto: Proto,
    out: Weak<dyn LineOut>,
    rx: SpinLock<LineRx>,
    /// The frames that the terminal received, for the poll of the device.
    input: SpinLock<VecDeque<NetBuf>>,
    dev: SpinLock<Weak<NetDevice>>,
    /// The line discipline is closed. The device sends and receives nothing.
    closed: AtomicBool,
}

impl NetLine {
    /// Opens the line discipline `proto` on the terminal `out`, as `slip_open` and
    /// `slcan_open` of Linux. The new device gets the name `slN` or `slcanN` with the lowest
    /// free `N`.
    ///
    /// # Errors
    ///
    /// Gives `EPERM` without `CAP_NET_ADMIN`, and `ENFILE` if each name is in use.
    pub fn open(proto: Proto, out: Weak<dyn LineOut>) -> Result<Arc<Self>> {
        if !cred::current().capable(cap::NET_ADMIN) {
            return Err(Errno::EPERM);
        }
        let line = Arc::new(Self {
            proto,
            out,
            rx: SpinLock::new(LineRx::default()),
            input: SpinLock::new(VecDeque::new()),
            dev: SpinLock::new(Weak::new()),
            closed: AtomicBool::new(false),
        });
        let (prefix, max) = match proto {
            Proto::Slip => ("sl", SL_MAXDEV),
            Proto::Slcan => ("slcan", SLC_MAXDEV),
        };
        for n in 0..max {
            let name: String = format!("{prefix}{n}");
            match dev::register_named(line.clone(), Some(name.as_bytes())) {
                Ok(d) => {
                    d.set_txqlen(TX_QUEUE_LEN);
                    *line.dev.lock() = Arc::downgrade(&d);
                    return Ok(line);
                }
                Err(e) if e == Errno::EEXIST => {}
                Err(e) => return Err(e),
            }
        }
        Err(Errno::ENFILE)
    }

    /// The line discipline of the line.
    pub fn ldisc(&self) -> i32 {
        self.proto.ldisc()
    }

    /// The name of the device.
    pub fn name(&self) -> String {
        self.dev.lock().upgrade().map(|d| d.name()).unwrap_or_default()
    }

    /// Takes the bytes that the terminal received, as `slip_receive_buf` and
    /// `slcan_receive_buf` of Linux. A device that is down drops them. Gives `true` if a new
    /// frame waits for the poll of the device. The caller then calls `rk_net::dev::kick_rx`.
    pub fn receive(&self, data: &[u8]) -> bool {
        let Some(dev) = self.dev.lock().upgrade() else { return false };
        if self.closed.load(Ordering::Relaxed) || !dev.is_up() {
            return false;
        }
        // The buffer of SLIP has twice the MTU, at least 1152 bytes, as `sl_alloc_bufs`.
        let limit = (dev.mtu() as usize * 2).max(1152);
        let mut rx = self.rx.lock();
        let mut frames = Vec::new();
        for &b in data {
            let done = match self.proto {
                Proto::Slip => rx.slip(b, limit),
                Proto::Slcan => rx.slcan(b).and_then(|l| slcan_decode(&l).map(|f| f.to_vec())),
            };
            frames.extend(done);
        }
        drop(rx);
        if frames.is_empty() {
            return false;
        }
        let ethertype = match self.proto {
            Proto::Slip => ETH_P_IP as u16,
            Proto::Slcan => ETH_P_CAN as u16,
        };
        let mut input = self.input.lock();
        for f in frames {
            let mut buf = NetBuf::new(HLEN, f.len());
            buf.put(f.len()).copy_from_slice(&f);
            EthHeader { dst: MacAddr::ZERO, src: MacAddr::ZERO, ethertype }.push(&mut buf);
            input.push_back(buf);
        }
        true
    }

    /// Clears the frame that the line receives, as a flush of the input.
    pub fn flush(&self) {
        self.rx.lock().clear();
    }

    /// Closes the line discipline and removes the device, as `slip_close` and `slcan_close`
    /// of Linux. The packet sockets of the device get `ENETDOWN`.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::Relaxed) {
            return;
        }
        self.input.lock().clear();
        if let Some(d) = self.dev.lock().upgrade() {
            dev::unregister(&d);
        }
    }
}

impl NetDriver for NetLine {
    /// SLIP has `ARPHRD_SLIP` and the flags of `sl_setup`. The serial line CAN has `ARPHRD_CAN`
    /// and `IFF_NOARP`, as `slc_setup`.
    fn kind(&self) -> LinkKind {
        match self.proto {
            Proto::Slip => LinkKind::Line {
                arphrd: ARPHRD_SLIP,
                flags: IFF_NOARP | IFF_POINTOPOINT | IFF_MULTICAST,
            },
            Proto::Slcan => LinkKind::Line { arphrd: ARPHRD_CAN, flags: IFF_NOARP },
        }
    }

    fn mac(&self) -> MacAddr {
        MacAddr::ZERO
    }

    fn mtu(&self) -> u32 {
        match self.proto {
            Proto::Slip => SL_MTU,
            Proto::Slcan => CAN_MTU as u32,
        }
    }

    fn max_mtu(&self) -> u32 {
        match self.proto {
            Proto::Slip => SL_MAX_MTU,
            Proto::Slcan => CAN_MTU as u32,
        }
    }

    fn min_mtu(&self) -> u32 {
        match self.proto {
            Proto::Slip => SL_MIN_MTU,
            Proto::Slcan => CAN_MTU as u32,
        }
    }

    fn link_up(&self) -> bool {
        !self.closed.load(Ordering::Relaxed)
    }

    /// Sends one frame on the terminal, as `sl_xmit` and `slc_xmit` of Linux. A closed line
    /// drops it. The serial line CAN drops a frame that is not a CAN frame.
    fn transmit(&self, frame: NetBuf) -> Result<()> {
        if self.closed.load(Ordering::Relaxed) || frame.len() < HLEN {
            return Ok(());
        }
        let Some(out) = self.out.upgrade() else { return Ok(()) };
        let data = frame.data();
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        let data = &data[HLEN..];
        let mut bytes = Vec::with_capacity(data.len() + 2);
        match self.proto {
            Proto::Slip => slip_encode(data, &mut bytes),
            Proto::Slcan => {
                if u32::from(ethertype) != ETH_P_CAN || !slcan_encode(data, &mut bytes) {
                    return Ok(());
                }
            }
        }
        out.write_line(&bytes)
    }

    fn poll(&self, budget: usize, deliver: &mut dyn FnMut(NetBuf)) -> usize {
        let mut n = 0;
        while n < budget {
            // The lock is not held while `deliver` runs, so `deliver` can send on the device.
            let Some(frame) = self.input.lock().pop_front() else { break };
            deliver(frame);
            n += 1;
        }
        n
    }
}

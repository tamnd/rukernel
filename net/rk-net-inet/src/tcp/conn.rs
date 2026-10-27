//! The state machine of one TCP connection, the transmission control block of RFC 9293, as
//! net/ipv4/tcp_input.c, tcp_output.c and tcp_timer.c of Linux.
//!
//! A connection does no I/O. The caller gives it the received segments, the data of the
//! program and the time in milliseconds, and takes the segments to send from `take_output`. The
//! segments have no ports and no addresses. The caller calls `tick` at the time of
//! `next_timer`. So the host tests drive a connection with segments in and segments out.
//!
//! The connection has:
//! - the states and the checks of RFC 9293 section 3.10, with the checks of RST, SYN and ACK of
//!   RFC 5961,
//! - the retransmission timer of RFC 6298 with Karn's rule, the persist timer and keepalive,
//! - the fast retransmit and the fast recovery of RFC 5681 and NewReno of RFC 6582, with the
//!   limited transmit of RFC 3042,
//! - the algorithm of Nagle, the delayed ACK, and the avoidance of the silly window syndrome
//!   of RFC 1122 for the sender and the receiver,
//! - the window scale of RFC 7323 and the option MSS.
//!
//! It has no timestamps, no SACK, no urgent data and no ECN.

use super::cc::{Algo, Cc};
use super::seg::{self, ACK, FIN, PSH, RST, SYN, Seg, ge, gt, le, lt};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use rk_abi::Errno;

/// The state of a connection, RFC 9293 section 3.3.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// No connection.
    Closed,
    /// A SYN went out, and the connection waits for the SYN of the peer.
    SynSent,
    /// A SYN came and a SYN went out, and the connection waits for the ACK of its SYN.
    SynRcvd,
    /// The connection is open.
    Established,
    /// The program closed its side, and the FIN waits for its ACK.
    FinWait1,
    /// The peer acknowledged the FIN, and the connection waits for the FIN of the peer.
    FinWait2,
    /// The peer closed its side.
    CloseWait,
    /// Both sides sent a FIN at the same time, and the FIN waits for its ACK.
    Closing,
    /// The peer closed first, then the program, and the FIN waits for its ACK.
    LastAck,
    /// Both sides closed. The connection waits so that old segments die.
    TimeWait,
}

/// The MSS of a peer without the option MSS, RFC 9293 section 3.7.1.
pub const DEFAULT_MSS: u32 = 536;
/// The smallest MSS that the connection takes from a peer, `TCP_MIN_SND_MSS` of Linux plus the
/// options.
const MIN_MSS: u32 = 88;
/// The window scale that the connection asks for. Linux computes it from the largest receive
/// buffer and gets 7 for the default sysctls.
pub const WSCALE: u8 = 7;
/// The first retransmission timeout, `TCP_TIMEOUT_INIT` of Linux and RFC 6298.
pub const RTO_INIT: u32 = 1000;
/// The smallest retransmission timeout, `TCP_RTO_MIN` of Linux.
pub const RTO_MIN: u32 = 200;
/// The largest retransmission timeout, `TCP_RTO_MAX` of Linux.
pub const RTO_MAX: u32 = 120_000;
/// The time of the delayed ACK, `TCP_DELACK_MIN` of Linux.
pub const DELACK: u64 = 40;
/// The segments that get a quick ACK at the start of a connection, `TCP_MAX_QUICKACKS`.
const QUICKACKS: u32 = 16;
/// The time in TIME-WAIT, `TCP_TIMEWAIT_LEN` of Linux. It is also the time in FIN-WAIT-2 of a
/// closed socket, `net.ipv4.tcp_fin_timeout`.
pub const TIME_WAIT: u64 = 60_000;
/// The retransmissions of a SYN, `net.ipv4.tcp_syn_retries`.
pub const SYN_RETRIES: u32 = 6;
/// The retransmissions of a SYN-ACK, `net.ipv4.tcp_synack_retries`.
const SYNACK_RETRIES: u32 = 5;
/// The retransmissions of data, `net.ipv4.tcp_retries2`.
const RETRIES: u32 = 15;
/// The duplicate ACKs that start a fast retransmit, `net.ipv4.tcp_reordering`.
const DUPACK_THRESHOLD: u32 = 3;
/// The default idle time before keepalive probes, in seconds, `TCP_KEEPALIVE_TIME`.
pub const KEEPIDLE: u32 = 7200;
/// The default time between keepalive probes, in seconds, `TCP_KEEPALIVE_INTVL`.
pub const KEEPINTVL: u32 = 75;
/// The default number of keepalive probes, `TCP_KEEPALIVE_PROBES`.
pub const KEEPCNT: u32 = 9;

/// The parameters of a new connection.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// The initial sequence number.
    pub iss: u32,
    /// The largest segment that the path takes: the MTU less 40, or `TCP_MAXSEG`.
    pub mss: u32,
    /// The bytes that the receive queue holds. The window is half of it, as Linux with the
    /// default `net.ipv4.tcp_adv_win_scale`.
    pub rcvbuf: usize,
    /// The bytes that the send queue holds.
    pub sndbuf: usize,
    /// The algorithm of the congestion control.
    pub algo: Algo,
}

/// A TCP connection.
#[derive(Debug)]
pub struct Conn {
    state: State,
    /// The connection came from a listening socket.
    passive: bool,

    /// The initial send sequence number.
    iss: u32,
    /// The oldest sequence number that the peer did not acknowledge.
    snd_una: u32,
    /// The next sequence number to send.
    snd_nxt: u32,
    /// The highest sequence number that went out. `snd_nxt` goes back after a timeout.
    snd_max: u32,
    /// The window of the peer in bytes, after the scale.
    snd_wnd: u32,
    /// The largest window of the peer, for the avoidance of the silly window syndrome.
    max_snd_wnd: u32,
    /// The sequence number of the segment of the last window update.
    snd_wl1: u32,
    /// The acknowledgment number of the segment of the last window update.
    snd_wl2: u32,
    /// The shift of the window of the peer.
    snd_wscale: u8,
    /// The shift of the window that this side sends.
    rcv_wscale: u8,
    /// The data from `snd_una` on: the data in flight, then the data not sent yet.
    sndq: VecDeque<u8>,
    /// The size of the send queue.
    sndbuf: usize,
    /// The program closed its side: a FIN follows the data.
    fin_queued: bool,
    /// The sequence number of the FIN, once the connection is open.
    fin_at: Option<u32>,
    /// The largest segment to send.
    mss: u32,
    /// The largest segment that the path takes.
    mss_limit: u32,

    /// The initial receive sequence number.
    irs: u32,
    /// The next sequence number that this side expects.
    rcv_nxt: u32,
    /// The right edge of the window that this side sent. It never goes back.
    rcv_adv: u32,
    /// The data in order that the program did not read.
    rcvq: VecDeque<u8>,
    /// The size of the receive queue.
    rcvbuf: usize,
    /// The data after a hole, by sequence number.
    ooo: Vec<(u32, Vec<u8>)>,
    /// The sequence number of a FIN after a hole.
    ooo_fin: Option<u32>,
    /// The FIN of the peer came, in order.
    fin_rcvd: bool,
    /// The largest segment that came, as `rcv_mss` of Linux.
    rcv_mss: u32,

    /// The smoothed round trip time in 1/8 milliseconds, or 0 before the first sample.
    srtt: u32,
    /// The variation of the round trip time in 1/4 milliseconds.
    rttvar: u32,
    /// The retransmission timeout from the samples, before the backoff.
    rto_base: u32,
    /// The exponent of the backoff.
    backoff: u32,
    /// The segment that measures the round trip: the sequence number after its end and the
    /// time it went out.
    rtt_seq: Option<(u32, u64)>,
    /// The retransmissions since the last ACK of new data.
    retries: u32,
    /// The window probes and keepalive probes without an answer.
    probes: u32,

    /// The time of the retransmission timer.
    rto_at: Option<u64>,
    /// The time of the persist timer.
    persist_at: Option<u64>,
    /// The time of the delayed ACK.
    delack_at: Option<u64>,
    /// The time of the keepalive timer.
    keep_at: Option<u64>,
    /// The end of TIME-WAIT or of FIN-WAIT-2.
    wait_at: Option<u64>,

    /// The congestion control.
    cc: Cc,
    /// The duplicate ACKs in a row.
    dupacks: u32,
    /// The connection is in a fast recovery.
    recovery: bool,
    /// The value of `snd_max` at the start of the last recovery or timeout, RFC 6582.
    recover: u32,
    /// The acknowledged bytes that do not make a full segment yet.
    acked_carry: u32,
    /// The window of the congestion control stopped the last send.
    cwnd_limited: bool,

    /// An ACK must go out now.
    ack_now: bool,
    /// The bytes that came since the last ACK.
    unacked: u32,
    /// The segments that get a quick ACK.
    quick: u32,

    /// `TCP_NODELAY`: no algorithm of Nagle.
    pub nodelay: bool,
    /// `TCP_CORK`: send only full segments.
    pub cork: bool,
    /// `SO_KEEPALIVE`.
    keepalive: bool,
    /// `TCP_KEEPIDLE` in seconds.
    pub keepidle: u32,
    /// `TCP_KEEPINTVL` in seconds.
    pub keepintvl: u32,
    /// `TCP_KEEPCNT`.
    pub keepcnt: u32,
    /// `TCP_SYNCNT`.
    pub syn_retries: u32,
    /// The program closed the socket, so no one reads.
    orphan: bool,
    /// The connection was open one time.
    was_open: bool,
    /// The error for the program, `sk_err` of Linux.
    error: Option<Errno>,
    /// The segments to send.
    out: Vec<Seg>,
}

/// The segment that answers `seg` when no connection takes it, as `tcp_v4_send_reset` of
/// Linux. An RST gets no answer.
pub fn reset_for(seg: &Seg) -> Option<Seg> {
    if seg.has(RST) {
        return None;
    }
    Some(if seg.has(ACK) {
        Seg { seq: seg.ack, flags: RST, ..Seg::default() }
    } else {
        Seg { seq: 0, ack: seg.seq.wrapping_add(seg.len()), flags: RST | ACK, ..Seg::default() }
    })
}

impl Conn {
    /// A closed connection.
    pub fn new(cfg: &Config) -> Self {
        let mss = cfg.mss.max(MIN_MSS);
        Self {
            state: State::Closed,
            passive: false,
            iss: cfg.iss,
            snd_una: cfg.iss,
            snd_nxt: cfg.iss,
            snd_max: cfg.iss,
            snd_wnd: 0,
            max_snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            snd_wscale: 0,
            rcv_wscale: 0,
            sndq: VecDeque::new(),
            sndbuf: cfg.sndbuf,
            fin_queued: false,
            fin_at: None,
            mss: mss.min(DEFAULT_MSS),
            mss_limit: mss,
            irs: 0,
            rcv_nxt: 0,
            rcv_adv: 0,
            rcvq: VecDeque::new(),
            rcvbuf: cfg.rcvbuf,
            ooo: Vec::new(),
            ooo_fin: None,
            fin_rcvd: false,
            rcv_mss: DEFAULT_MSS,
            srtt: 0,
            rttvar: 0,
            rto_base: RTO_INIT,
            backoff: 0,
            rtt_seq: None,
            retries: 0,
            probes: 0,
            rto_at: None,
            persist_at: None,
            delack_at: None,
            keep_at: None,
            wait_at: None,
            cc: Cc::new(cfg.algo),
            dupacks: 0,
            recovery: false,
            recover: cfg.iss,
            acked_carry: 0,
            cwnd_limited: false,
            ack_now: false,
            unacked: 0,
            quick: QUICKACKS,
            nodelay: false,
            cork: false,
            keepalive: false,
            keepidle: KEEPIDLE,
            keepintvl: KEEPINTVL,
            keepcnt: KEEPCNT,
            syn_retries: SYN_RETRIES,
            orphan: false,
            was_open: false,
            error: None,
            out: Vec::new(),
        }
    }

    /// Opens a connection: sends a SYN, as `tcp_connect` of Linux.
    pub fn connect(&mut self, now: u64) {
        self.state = State::SynSent;
        self.snd_nxt = self.iss.wrapping_add(1);
        self.snd_max = self.snd_nxt;
        self.send_syn(false);
        self.rtt_seq = Some((self.snd_nxt, now));
        self.rto_at = Some(now + u64::from(self.rto()));
    }

    /// Makes a connection for the SYN `syn` that came to a listening socket, and sends a
    /// SYN-ACK, as `tcp_conn_request` of Linux.
    pub fn accept(cfg: &Config, syn: &Seg, now: u64) -> Self {
        let mut c = Self::new(cfg);
        c.passive = true;
        c.state = State::SynRcvd;
        c.syn_options(syn);
        c.irs = syn.seq;
        c.rcv_nxt = syn.seq.wrapping_add(1);
        c.snd_wnd = u32::from(syn.wnd);
        c.max_snd_wnd = c.snd_wnd;
        c.snd_nxt = c.iss.wrapping_add(1);
        c.snd_max = c.snd_nxt;
        c.send_syn(true);
        c.rtt_seq = Some((c.snd_nxt, now));
        c.rto_at = Some(now + u64::from(c.rto()));
        c
    }

    /// Reads the options of the SYN of the peer.
    fn syn_options(&mut self, syn: &Seg) {
        if let Some(ws) = syn.wscale {
            self.snd_wscale = ws.min(seg::MAX_WSCALE);
            self.rcv_wscale = WSCALE;
        } else {
            self.snd_wscale = 0;
            self.rcv_wscale = 0;
        }
        let peer = syn.mss.map_or(DEFAULT_MSS, u32::from).max(MIN_MSS);
        self.mss = peer.min(self.mss_limit);
    }

    /// The state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Tells if the connection came from a listening socket.
    pub fn passive(&self) -> bool {
        self.passive
    }

    /// Tells if the connection was open one time.
    pub fn was_open(&self) -> bool {
        self.was_open
    }

    /// Tells if the FIN of the peer came: the program reads the end of the data.
    pub fn fin_rcvd(&self) -> bool {
        self.fin_rcvd
    }

    /// Tells if the program closed its side.
    pub fn fin_queued(&self) -> bool {
        self.fin_queued
    }

    /// The error for the program, without a change.
    pub fn error(&self) -> Option<Errno> {
        self.error
    }

    /// Takes the error for the program.
    pub fn take_error(&mut self) -> Option<Errno> {
        self.error.take()
    }

    /// The largest segment to send.
    pub fn mss(&self) -> u32 {
        self.mss
    }

    /// The congestion control.
    pub fn cc(&self) -> &Cc {
        &self.cc
    }

    /// Changes the algorithm of the congestion control.
    pub fn set_algo(&mut self, algo: Algo) {
        self.cc.set_algo(algo);
    }

    /// The smoothed round trip time in milliseconds.
    pub fn srtt(&self) -> u32 {
        self.srtt >> 3
    }

    /// The bytes that the program can read.
    pub fn readable(&self) -> usize {
        self.rcvq.len()
    }

    /// The bytes in the send queue: the data in flight and the data not sent yet.
    pub fn queued(&self) -> usize {
        self.sndq.len()
    }

    /// The bytes not sent yet, for `SIOCOUTQNSD`.
    pub fn unsent(&self) -> usize {
        self.sndq.len() - self.sent_bytes()
    }

    /// The size of the send queue.
    pub fn sndbuf(&self) -> usize {
        self.sndbuf
    }

    /// Changes the size of the send queue and of the receive queue.
    pub fn set_buffers(&mut self, sndbuf: usize, rcvbuf: usize) {
        self.sndbuf = sndbuf;
        self.rcvbuf = rcvbuf;
    }

    /// Tells if the program can add data: the connection is open and the program did not close
    /// its side.
    pub fn can_send(&self) -> bool {
        matches!(self.state, State::Established | State::CloseWait) && !self.fin_queued
    }

    /// Tells if the connection can take data from the peer.
    fn can_receive(&self) -> bool {
        matches!(self.state, State::Established | State::FinWait1 | State::FinWait2)
    }

    /// Sets `SO_KEEPALIVE`.
    pub fn set_keepalive(&mut self, on: bool, now: u64) {
        self.keepalive = on;
        self.probes = 0;
        self.keep_at = on.then(|| now + u64::from(self.keepidle) * 1000);
    }

    /// The retransmission timeout with the backoff.
    fn rto(&self) -> u32 {
        let rto = u64::from(self.rto_base) << self.backoff.min(16);
        rto.min(u64::from(RTO_MAX)) as u32
    }

    /// The time of the next timer, if a timer runs.
    pub fn next_timer(&self) -> Option<u64> {
        [self.rto_at, self.persist_at, self.delack_at, self.keep_at, self.wait_at]
            .into_iter()
            .flatten()
            .min()
    }

    /// Sends the data that waits, after a change of `nodelay` or `cork`.
    pub fn flush(&mut self, now: u64) {
        self.output(now);
    }

    /// Takes the segments to send.
    pub fn take_output(&mut self) -> Vec<Seg> {
        core::mem::take(&mut self.out)
    }

    /// The window to send, after the receiver side of the avoidance of the silly window
    /// syndrome: the window opens only by a full segment or by half of the buffer, as
    /// `__tcp_select_window` of Linux.
    fn wnd_candidate(&self) -> u32 {
        let space = (self.rcvbuf / 2) as u32;
        let free = space.saturating_sub(self.rcvq.len() as u32);
        let cur = self.rcv_wnd();
        if free > cur && free - cur >= self.rcv_mss.min(space / 2).max(1) { free } else { cur }
    }

    /// The window that this side sent and that is left.
    fn rcv_wnd(&self) -> u32 {
        if lt(self.rcv_adv, self.rcv_nxt) { 0 } else { self.rcv_adv.wrapping_sub(self.rcv_nxt) }
    }

    /// The value of the window field of a segment that is not a SYN. The right edge does not go
    /// back.
    fn window_field(&mut self) -> u16 {
        let ws = self.rcv_wscale;
        let cur = self.rcv_wnd();
        let mut wnd = (self.wnd_candidate().min(0xffff << ws) >> ws) << ws;
        if wnd < cur {
            // The window does not shrink: the field rounds the window up, as
            // `tcp_select_window` of Linux.
            wnd = cur.div_ceil(1 << ws) << ws;
        }
        let field = (wnd >> ws).min(0xffff);
        let edge = self.rcv_nxt.wrapping_add(field << ws);
        if gt(edge, self.rcv_adv) {
            self.rcv_adv = edge;
        }
        field as u16
    }

    /// Adds a segment to the output. A segment with ACK has the acknowledgment number and the
    /// window, and so it ends the wait of a delayed ACK.
    fn push(&mut self, mut s: Seg) {
        if s.has(ACK) {
            s.ack = self.rcv_nxt;
            if s.has(SYN) {
                let space = (self.rcvbuf / 2).min(0xffff) as u32;
                self.rcv_adv = self.rcv_nxt.wrapping_add(space);
                s.wnd = space as u16;
            } else {
                s.wnd = self.window_field();
            }
            self.ack_now = false;
            self.delack_at = None;
            self.unacked = 0;
        }
        self.out.push(s);
    }

    /// Sends the SYN, or the SYN-ACK if `ack`.
    fn send_syn(&mut self, ack: bool) {
        let ws = if ack { (self.rcv_wscale != 0).then_some(WSCALE) } else { Some(WSCALE) };
        let s = Seg {
            seq: self.iss,
            flags: if ack { SYN | ACK } else { SYN },
            wnd: (self.rcvbuf / 2).min(0xffff) as u16,
            mss: Some(self.mss_limit.min(0xffff) as u16),
            wscale: ws,
            ..Seg::default()
        };
        self.push(s);
    }

    /// Sends a segment with only an ACK.
    fn send_ack(&mut self) {
        self.push(Seg { seq: self.snd_nxt, flags: ACK, ..Seg::default() });
    }

    /// Sends an RST for the sequence number `seq`, without an ACK.
    fn send_rst(&mut self, seq: u32) {
        self.out.push(Seg { seq, flags: RST, ..Seg::default() });
    }

    /// Ends the connection with the error `err`, as `tcp_done_with_error` of Linux.
    fn done(&mut self, err: Option<Errno>) {
        if err.is_some() {
            self.error = err;
        }
        self.state = State::Closed;
        self.sndq.clear();
        self.ooo.clear();
        self.rto_at = None;
        self.persist_at = None;
        self.delack_at = None;
        self.keep_at = None;
        self.wait_at = None;
        self.ack_now = false;
    }

    /// Takes data from the program, as `tcp_sendmsg`. Gives the bytes that the send queue took.
    pub fn send(&mut self, data: &[u8], now: u64) -> usize {
        if !self.can_send() {
            return 0;
        }
        let n = data.len().min(self.sndbuf.saturating_sub(self.sndq.len()));
        self.sndq.extend(&data[..n]);
        self.output(now);
        n
    }

    /// Gives at most `len` bytes of the received data, as `tcp_recvmsg`. With `peek`, the data
    /// stays. A read that opens the window a lot sends a window update, as `tcp_cleanup_rbuf`.
    pub fn recv(&mut self, len: usize, peek: bool, now: u64) -> Vec<u8> {
        let n = len.min(self.rcvq.len());
        let data: Vec<u8> = if peek {
            self.rcvq.iter().take(n).copied().collect()
        } else {
            self.rcvq.drain(..n).collect()
        };
        if !peek && n > 0 && self.can_receive() {
            let cur = self.rcv_wnd();
            let space = (self.rcvbuf / 2) as u32;
            if 2 * cur <= space {
                let new = self.wnd_candidate();
                if new > cur && new >= 2 * cur {
                    self.ack_now = true;
                }
            }
            self.output(now);
        }
        data
    }

    /// Closes the side of the program: a FIN follows the data, as `tcp_close_state` and
    /// `tcp_send_fin`. In SYN-SENT the connection ends at once.
    pub fn close(&mut self, now: u64) {
        match self.state {
            State::SynSent => self.done(None),
            State::SynRcvd => self.fin_queued = true,
            State::Established => {
                self.queue_fin();
                self.state = State::FinWait1;
            }
            State::CloseWait => {
                self.queue_fin();
                self.state = State::LastAck;
            }
            _ => {}
        }
        self.output(now);
    }

    /// Puts the FIN after the data in the send queue.
    fn queue_fin(&mut self) {
        self.fin_queued = true;
        // The send queue starts after the SYN, also before the peer acknowledges the SYN.
        let start = if lt(self.snd_una, self.iss.wrapping_add(1)) {
            self.iss.wrapping_add(1)
        } else {
            self.snd_una
        };
        self.fin_at = Some(start.wrapping_add(self.sndq.len() as u32));
    }

    /// Marks that the program closed the socket. A connection in FIN-WAIT-2 then ends after
    /// `TIME_WAIT`, as `tcp_close` with `net.ipv4.tcp_fin_timeout`.
    pub fn orphan(&mut self, now: u64) {
        self.orphan = true;
        if self.state == State::FinWait2 {
            self.wait_at = Some(now + TIME_WAIT);
        }
    }

    /// Ends the connection at once and sends an RST if the peer knows the connection, as
    /// `tcp_disconnect` and `tcp_send_active_reset`.
    pub fn abort(&mut self) {
        if matches!(
            self.state,
            State::SynRcvd
                | State::Established
                | State::FinWait1
                | State::FinWait2
                | State::CloseWait
        ) {
            let seq = self.snd_nxt;
            self.push(Seg { seq, flags: RST | ACK, ..Seg::default() });
        }
        self.done(None);
    }

    /// The bytes of the send queue that went out.
    fn sent_bytes(&self) -> usize {
        (self.snd_nxt.wrapping_sub(self.snd_una) as usize).min(self.sndq.len())
    }

    /// The sequence number of the FIN, if the program closed its side.
    fn fin_seq(&self) -> Option<u32> {
        self.fin_at
    }

    /// Tells if the peer acknowledged the FIN.
    fn fin_acked(&self) -> bool {
        self.fin_seq().is_some_and(|f| gt(self.snd_una, f))
    }

    /// Makes a segment of `len` bytes of the send queue from the offset `off`, with a FIN if
    /// `fin`.
    fn data_seg(&self, seq: u32, off: usize, len: usize, fin: bool) -> Seg {
        let data: Vec<u8> = self.sndq.range(off..off + len).copied().collect();
        let mut flags = ACK;
        if fin {
            flags |= FIN;
        }
        if len > 0 && off + len == self.sndq.len() {
            flags |= PSH;
        }
        Seg { seq, flags, data, ..Seg::default() }
    }

    /// Sends the data that the windows allow and the algorithm of Nagle lets go, then a FIN and
    /// the ACK that waits, as `tcp_write_xmit` of Linux.
    fn output(&mut self, now: u64) {
        let sending = matches!(
            self.state,
            State::Established
                | State::CloseWait
                | State::FinWait1
                | State::Closing
                | State::LastAck
        );
        if sending {
            self.write(now);
        }
        if self.ack_now && self.state != State::Closed && self.state != State::SynSent {
            self.send_ack();
        }
    }

    fn write(&mut self, now: u64) {
        self.cwnd_limited = false;
        loop {
            let off = self.sent_bytes();
            let unsent = self.sndq.len() - off;
            let fin_due = self.fin_seq().is_some_and(|f| le(self.snd_nxt, f));
            if unsent == 0 && !fin_due {
                break;
            }
            // Limited transmit: each of the first two duplicate ACKs lets a new segment go.
            let extra = if self.recovery { 0 } else { self.dupacks.min(2) };
            let cwnd = (self.cc.cwnd + extra).saturating_mul(self.mss);
            let wnd = self.snd_wnd.min(cwnd);
            let flight = self.snd_nxt.wrapping_sub(self.snd_una);
            let usable = wnd.saturating_sub(flight) as usize;
            let len = unsent.min(usable).min(self.mss as usize);
            if unsent > 0 {
                if len == 0 {
                    self.cwnd_limited = cwnd <= self.snd_wnd;
                    break;
                }
                let last = len == unsent;
                let idle = self.snd_max == self.snd_una || self.snd_nxt == self.snd_una;
                let full = len == self.mss as usize;
                let nagle_ok = last && !self.cork && (self.nodelay || idle);
                let sws_ok = self.max_snd_wnd > 0 && len >= (self.max_snd_wnd / 2) as usize;
                if !full && !nagle_ok && !sws_ok {
                    break;
                }
            }
            let fin = fin_due && len == unsent;
            let seq = self.snd_nxt;
            let s = self.data_seg(seq, off, len, fin);
            let new = self.snd_nxt == self.snd_max;
            self.snd_nxt = seq.wrapping_add(len as u32 + u32::from(fin));
            if gt(self.snd_nxt, self.snd_max) {
                self.snd_max = self.snd_nxt;
            }
            if new && self.rtt_seq.is_none() {
                self.rtt_seq = Some((self.snd_nxt, now));
            }
            if self.rto_at.is_none() {
                self.rto_at = Some(now + u64::from(self.rto()));
            }
            self.persist_at = None;
            self.push(s);
            if fin {
                break;
            }
        }
        // The persist timer runs when the peer has a zero window and nothing is in flight.
        let stalled = self.snd_wnd == 0 && self.unsent() > 0 && self.snd_max == self.snd_una;
        if stalled && self.rto_at.is_none() && self.persist_at.is_none() {
            self.persist_at = Some(now + u64::from(self.rto()));
        }
        if self.snd_wnd > 0 {
            self.persist_at = None;
        }
    }

    /// Sends the oldest segment that the peer did not acknowledge again.
    fn retransmit(&mut self, now: u64) {
        let len = self.sndq.len().min(self.mss as usize);
        let fin = self.fin_seq().is_some_and(|f| gt(self.snd_max, f)) && len == self.sndq.len();
        if len == 0 && !fin {
            return;
        }
        let s = self.data_seg(self.snd_una, 0, len, fin);
        let end = self.snd_una.wrapping_add(len as u32 + u32::from(fin));
        if lt(self.snd_nxt, end) {
            self.snd_nxt = end;
        }
        // Karn's rule: a retransmitted segment gives no sample.
        self.rtt_seq = None;
        self.rto_at = Some(now + u64::from(self.rto()));
        self.push(s);
    }

    /// Takes a sample of the round trip time, as RFC 6298 section 2 and `tcp_rtt_estimator`.
    fn rtt_sample(&mut self, rtt: u32) {
        let rtt = rtt.max(1);
        if self.srtt == 0 {
            self.srtt = rtt << 3;
            self.rttvar = (rtt << 1).max(1);
        } else {
            let srtt = self.srtt >> 3;
            let err = rtt.abs_diff(srtt);
            // rttvar = 3/4 rttvar + 1/4 |err|, srtt = 7/8 srtt + 1/8 rtt.
            self.rttvar = self.rttvar - (self.rttvar >> 2) + err;
            self.srtt = self.srtt - (self.srtt >> 3) + rtt;
        }
        // RTO = SRTT + max(4 RTTVAR, RTO_MIN), as Linux, which takes RTO_MIN in place of the
        // clock granularity.
        let rto = (self.srtt >> 3) + self.rttvar.max(RTO_MIN);
        self.rto_base = rto.clamp(RTO_MIN, RTO_MAX);
        self.cc.rtt_sample(rtt);
    }

    /// The timers, as `tcp_write_timer`, `tcp_delack_timer` and `tcp_keepalive_timer`.
    pub fn tick(&mut self, now: u64) {
        let due = |t: Option<u64>| t.is_some_and(|t| t <= now);
        if due(self.wait_at) {
            self.done(None);
            return;
        }
        if due(self.delack_at) {
            self.delack_at = None;
            self.ack_now = true;
        }
        if due(self.rto_at) {
            self.rto_at = None;
            self.on_rto(now);
        }
        if due(self.persist_at) {
            self.persist_at = None;
            self.probe(now);
        }
        if due(self.keep_at) {
            self.keep_at = None;
            self.keepalive_probe(now);
        }
        if self.state != State::Closed {
            self.output(now);
        }
    }

    /// The retransmission timer expired.
    fn on_rto(&mut self, now: u64) {
        match self.state {
            State::SynSent | State::SynRcvd => {
                let max =
                    if self.state == State::SynSent { self.syn_retries } else { SYNACK_RETRIES };
                if self.retries >= max {
                    self.done(Some(Errno::ETIMEDOUT));
                    return;
                }
                self.retries += 1;
                self.backoff += 1;
                self.rtt_seq = None;
                self.send_syn(self.state == State::SynRcvd);
                self.rto_at = Some(now + u64::from(self.rto()));
            }
            State::Established
            | State::CloseWait
            | State::FinWait1
            | State::Closing
            | State::LastAck => {
                if self.snd_una == self.snd_max {
                    return;
                }
                if self.retries >= RETRIES {
                    self.done(Some(Errno::ETIMEDOUT));
                    return;
                }
                self.cc.on_rto(self.retries == 0);
                self.retries += 1;
                self.backoff += 1;
                self.recovery = false;
                self.dupacks = 0;
                self.recover = self.snd_max;
                self.snd_nxt = self.snd_una;
                self.retransmit(now);
            }
            _ => {}
        }
    }

    /// The persist timer expired: sends a window probe, as `tcp_probe_timer`. The probe is a
    /// segment with an old sequence number and no data, as Linux sends, so the peer answers it
    /// with an ACK and its window.
    fn probe(&mut self, now: u64) {
        if self.snd_wnd != 0 || self.unsent() == 0 || !self.can_probe() {
            return;
        }
        if self.probes >= RETRIES {
            self.done(Some(Errno::ETIMEDOUT));
            return;
        }
        self.probes += 1;
        self.backoff += 1;
        let seq = self.snd_una.wrapping_sub(1);
        self.push(Seg { seq, flags: ACK, ..Seg::default() });
        self.persist_at = Some(now + u64::from(self.rto()));
    }

    fn can_probe(&self) -> bool {
        matches!(
            self.state,
            State::Established
                | State::CloseWait
                | State::FinWait1
                | State::Closing
                | State::LastAck
        )
    }

    /// The keepalive timer expired.
    fn keepalive_probe(&mut self, now: u64) {
        if !self.keepalive {
            return;
        }
        let idle_state =
            matches!(self.state, State::Established | State::CloseWait | State::FinWait2);
        if !idle_state || self.snd_una != self.snd_max || !self.sndq.is_empty() {
            self.keep_at = Some(now + u64::from(self.keepidle) * 1000);
            return;
        }
        if self.probes >= self.keepcnt {
            self.abort();
            self.error = Some(Errno::ETIMEDOUT);
            return;
        }
        self.probes += 1;
        let seq = self.snd_una.wrapping_sub(1);
        self.push(Seg { seq, flags: ACK, ..Seg::default() });
        self.keep_at = Some(now + u64::from(self.keepintvl) * 1000);
    }

    /// Takes a segment from the peer, as `tcp_rcv_state_process` of Linux and RFC 9293 section
    /// 3.10.7.
    pub fn input(&mut self, s: Seg, now: u64) {
        match self.state {
            State::Closed => return,
            State::SynSent => {
                self.input_syn_sent(s, now);
                self.output(now);
                return;
            }
            _ => {}
        }
        self.input_sync(s, now);
        self.output(now);
    }

    /// RFC 9293 section 3.10.7.3: a segment in SYN-SENT.
    fn input_syn_sent(&mut self, s: Seg, now: u64) {
        if s.has(ACK) && (le(s.ack, self.iss) || gt(s.ack, self.snd_max)) {
            if !s.has(RST) {
                self.send_rst(s.ack);
            }
            return;
        }
        if s.has(RST) {
            if s.has(ACK) {
                self.done(Some(Errno::ECONNREFUSED));
            }
            return;
        }
        if !s.has(SYN) {
            return;
        }
        self.syn_options(&s);
        self.irs = s.seq;
        self.rcv_nxt = s.seq.wrapping_add(1);
        if s.has(ACK) {
            // The window of a SYN has no scale, RFC 7323 section 2.2.
            self.snd_una = s.ack;
            self.snd_wnd = u32::from(s.wnd);
            self.max_snd_wnd = self.snd_wnd;
            self.snd_wl1 = s.seq;
            self.snd_wl2 = s.ack;
            if let Some((_, t)) = self.rtt_seq.take() {
                self.rtt_sample(now.saturating_sub(t) as u32);
            }
            self.rto_at = None;
            self.retries = 0;
            self.backoff = 0;
            self.open(now);
            self.ack_now = true;
        } else {
            // A simultaneous open: the SYN-ACK goes out with the same sequence number.
            self.state = State::SynRcvd;
            self.snd_wnd = u32::from(s.wnd);
            self.max_snd_wnd = self.snd_wnd;
            self.send_syn(true);
        }
    }

    /// Enters ESTABLISHED, or FIN-WAIT-1 if the program closed its side in SYN-RECEIVED.
    fn open(&mut self, now: u64) {
        self.was_open = true;
        self.state = if self.fin_queued {
            self.queue_fin();
            State::FinWait1
        } else {
            State::Established
        };
        if self.keepalive {
            self.keep_at = Some(now + u64::from(self.keepidle) * 1000);
        }
    }

    /// The acceptability test of RFC 9293 section 3.10.7.4, as `tcp_sequence` of Linux: some
    /// part of the segment is in the window, or the segment is empty and at the left edge.
    fn acceptable(&self, s: &Seg) -> bool {
        let end = s.seq.wrapping_add(s.len());
        ge(end, self.rcv_nxt) && le(s.seq, self.rcv_nxt.wrapping_add(self.rcv_wnd()))
    }

    /// A segment in a state after SYN-SENT.
    fn input_sync(&mut self, mut s: Seg, now: u64) {
        let had_fin = s.has(FIN);
        // First: the sequence number.
        if !self.acceptable(&s) {
            if !s.has(RST) {
                self.ack_now = true;
            }
            return;
        }
        if self.keepalive {
            self.keep_at = Some(now + u64::from(self.keepidle) * 1000);
        }
        // Second: RST, RFC 5961 section 3.2. Only the exact sequence number resets the
        // connection; another one in the window gets a challenge ACK.
        if s.has(RST) {
            if s.seq == self.rcv_nxt {
                let err = match self.state {
                    State::SynRcvd if self.passive => None,
                    State::CloseWait => Some(Errno::EPIPE),
                    State::Closing | State::LastAck | State::TimeWait => None,
                    _ => Some(Errno::ECONNRESET),
                };
                self.done(err);
            } else {
                self.ack_now = true;
            }
            return;
        }
        // Fourth: SYN, RFC 5961 section 4. The SYN-ACK of a simultaneous open passes, as
        // `tcp_validate_incoming` of Linux. A passive connection sends its SYN-ACK again for a
        // SYN again.
        if s.has(SYN) {
            let simultaneous = self.state == State::SynRcvd
                && s.has(ACK)
                && s.seq.wrapping_add(1) == self.rcv_nxt
                && s.ack == self.snd_nxt;
            if !simultaneous {
                if self.state == State::SynRcvd && self.passive && s.seq == self.irs {
                    self.send_syn(true);
                } else {
                    self.ack_now = true;
                }
                return;
            }
        }
        // Trim the part before `rcv_nxt` and the part after the window.
        let old = lt(s.seq, self.rcv_nxt) && !s.is_empty();
        if lt(s.seq, self.rcv_nxt) {
            let mut skip = self.rcv_nxt.wrapping_sub(s.seq);
            if s.has(SYN) {
                s.flags &= !SYN;
                s.seq = s.seq.wrapping_add(1);
                skip -= 1;
            }
            let n = (skip as usize).min(s.data.len());
            s.data.drain(..n);
            s.seq = s.seq.wrapping_add(n as u32);
            if skip as usize > n {
                s.flags &= !FIN;
            }
        }
        let room = self.rcv_wnd().wrapping_sub(s.seq.wrapping_sub(self.rcv_nxt)) as usize;
        if s.data.len() > room {
            // The data after the window goes, and the ACK tells the window, as the drop of
            // `tcp_data_queue` for a zero window.
            s.data.truncate(room);
            s.flags &= !FIN;
            self.ack_now = true;
        }
        if old {
            // A retransmission of data that came: the peer lost the ACK.
            self.ack_now = true;
        }
        if self.state == State::TimeWait && had_fin {
            self.wait_at = Some(now + TIME_WAIT);
        }
        // Fifth: ACK.
        if !s.has(ACK) {
            return;
        }
        if self.state == State::SynRcvd {
            if gt(s.ack, self.snd_una) && le(s.ack, self.snd_max) {
                self.snd_wnd = u32::from(s.wnd) << self.snd_wscale;
                self.max_snd_wnd = self.max_snd_wnd.max(self.snd_wnd);
                self.snd_wl1 = s.seq;
                self.snd_wl2 = s.ack;
                self.open(now);
            } else {
                self.send_rst(s.ack);
                return;
            }
        }
        if !self.ack(&s, now) {
            return;
        }
        match self.state {
            State::FinWait1 if self.fin_acked() => {
                self.state = State::FinWait2;
                self.rto_at = None;
                if self.orphan {
                    self.wait_at = Some(now + TIME_WAIT);
                }
            }
            State::Closing if self.fin_acked() => self.time_wait(now),
            State::LastAck if self.fin_acked() => {
                self.done(None);
                return;
            }
            _ => {}
        }
        // Seventh: the data. Eighth: FIN.
        let fin = s.has(FIN);
        let fin_seq = s.seq.wrapping_add(s.data.len() as u32);
        if !s.data.is_empty() && self.can_receive() {
            self.data(s.seq, s.data, now);
        }
        if fin {
            self.fin(fin_seq, now);
        }
    }

    /// Takes the ACK field, as `tcp_ack`. Gives false if the segment must go.
    fn ack(&mut self, s: &Seg, now: u64) -> bool {
        if gt(s.ack, self.snd_max) {
            // An ACK of data that did not go out.
            self.ack_now = true;
            return false;
        }
        let wnd = u32::from(s.wnd) << self.snd_wscale;
        if gt(s.ack, self.snd_una) {
            let acked = s.ack.wrapping_sub(self.snd_una);
            let flight = self.snd_max.wrapping_sub(self.snd_una);
            let n = (acked as usize).min(self.sndq.len());
            self.sndq.drain(..n);
            self.snd_una = s.ack;
            if lt(self.snd_nxt, self.snd_una) {
                self.snd_nxt = self.snd_una;
            }
            self.retries = 0;
            self.backoff = 0;
            self.probes = 0;
            if let Some((end, t)) = self.rtt_seq
                && ge(s.ack, end)
            {
                self.rtt_seq = None;
                self.rtt_sample(now.saturating_sub(t) as u32);
            }
            self.rto_at = (self.snd_una != self.snd_max).then(|| now + u64::from(self.rto()));
            self.new_ack(acked, flight, now);
        } else if s.ack == self.snd_una
            && s.data.is_empty()
            && !s.has(SYN)
            && !s.has(FIN)
            && wnd == self.snd_wnd
            && self.snd_max != self.snd_una
        {
            self.dupack(now);
        }
        // The window update, RFC 9293 section 3.10.7.4.
        if lt(self.snd_wl1, s.seq) || (self.snd_wl1 == s.seq && le(self.snd_wl2, s.ack)) {
            self.snd_wnd = wnd;
            self.max_snd_wnd = self.max_snd_wnd.max(wnd);
            self.snd_wl1 = s.seq;
            self.snd_wl2 = s.ack;
        }
        if self.snd_wnd > 0 && self.persist_at.is_some() {
            self.persist_at = None;
            self.backoff = 0;
        }
        true
    }

    /// An ACK of new data: the end of a recovery, or the growth of the window.
    fn new_ack(&mut self, acked: u32, flight: u32, now: u64) {
        let total = self.acked_carry + acked;
        let pkts = total / self.mss;
        self.acked_carry = total % self.mss;
        if self.recovery {
            if ge(self.snd_una, self.recover) {
                // A full ACK ends the recovery, RFC 6582 section 3.2 step 3.
                self.recovery = false;
                self.dupacks = 0;
                self.cc.cwnd = self.cc.ssthresh;
            } else {
                // A partial ACK: the next hole goes again, and the window deflates.
                self.retransmit(now);
                self.cc.cwnd = self.cc.cwnd.saturating_sub(pkts).max(1) + 1;
            }
            return;
        }
        self.dupacks = 0;
        let limited = self.cwnd_limited
            || (self.cc.in_slow_start()
                && u64::from(flight) * 2 >= u64::from(self.cc.cwnd) * u64::from(self.mss));
        if limited {
            self.cc.on_ack(pkts, now);
        }
    }

    /// A duplicate ACK: a fast retransmit at the third, RFC 5681 section 3.2 and RFC 6582.
    fn dupack(&mut self, now: u64) {
        if self.recovery {
            // Each duplicate ACK tells that a segment left the network.
            self.cc.cwnd += 1;
            return;
        }
        self.dupacks += 1;
        if self.dupacks == DUPACK_THRESHOLD && ge(self.snd_una, self.recover) {
            self.cc.on_loss();
            self.cc.cwnd = self.cc.ssthresh + DUPACK_THRESHOLD;
            self.recovery = true;
            self.recover = self.snd_max;
            self.retransmit(now);
        }
    }

    /// Takes data at `seq`, as `tcp_data_queue`.
    fn data(&mut self, seq: u32, data: Vec<u8>, now: u64) {
        let len = data.len() as u32;
        self.rcv_mss = self.rcv_mss.max(len.min(self.mss_limit));
        if seq != self.rcv_nxt {
            // Data after a hole waits, and a duplicate ACK goes out at once.
            let pos = self.ooo.iter().position(|(s, _)| gt(*s, seq)).unwrap_or(self.ooo.len());
            self.ooo.insert(pos, (seq, data));
            self.ack_now = true;
            return;
        }
        self.rcvq.extend(&data);
        self.rcv_nxt = self.rcv_nxt.wrapping_add(len);
        self.unacked += len;
        if !self.ooo.is_empty() {
            self.merge();
            // The ACK of a filled hole goes out at once, RFC 5681 section 4.2.
            self.ack_now = true;
        }
        self.check_ooo_fin(now);
        if self.quick > 0 {
            self.quick -= 1;
            self.ack_now = true;
        } else if self.unacked > self.rcv_mss {
            self.ack_now = true;
        } else if self.delack_at.is_none() {
            self.delack_at = Some(now + DELACK);
        }
    }

    /// Moves the data after a hole that is now in order to the receive queue.
    fn merge(&mut self) {
        while let Some((seq, _)) = self.ooo.first() {
            if gt(*seq, self.rcv_nxt) {
                break;
            }
            let (seq, data) = self.ooo.remove(0);
            let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
            if skip < data.len() {
                self.rcvq.extend(&data[skip..]);
                let n = (data.len() - skip) as u32;
                self.rcv_nxt = self.rcv_nxt.wrapping_add(n);
                self.unacked += n;
            }
        }
    }

    /// Takes a FIN at `seq`, as `tcp_fin`.
    fn fin(&mut self, seq: u32, now: u64) {
        if seq != self.rcv_nxt {
            if gt(seq, self.rcv_nxt) && self.can_receive() {
                self.ooo_fin = Some(seq);
                self.ack_now = true;
            }
            return;
        }
        if self.fin_rcvd {
            self.ack_now = true;
            return;
        }
        self.fin_rcvd = true;
        self.ooo_fin = None;
        self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        self.ack_now = true;
        match self.state {
            State::SynRcvd | State::Established => self.state = State::CloseWait,
            State::FinWait1 => {
                if self.fin_acked() {
                    self.time_wait(now);
                } else {
                    self.state = State::Closing;
                }
            }
            State::FinWait2 => self.time_wait(now),
            _ => {}
        }
    }

    /// Enters TIME-WAIT.
    fn time_wait(&mut self, now: u64) {
        self.state = State::TimeWait;
        self.rto_at = None;
        self.persist_at = None;
        self.keep_at = None;
        self.wait_at = Some(now + TIME_WAIT);
    }

    /// Takes a FIN that waited after a hole, once the hole is filled.
    fn check_ooo_fin(&mut self, now: u64) {
        if self.ooo_fin == Some(self.rcv_nxt) {
            let seq = self.rcv_nxt;
            self.fin(seq, now);
        }
    }
}

#[cfg(test)]
mod tests;

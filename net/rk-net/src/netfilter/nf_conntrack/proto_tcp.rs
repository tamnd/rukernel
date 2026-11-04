//! The tracker of TCP, as net/netfilter/nf_conntrack_proto_tcp.c of Linux.
//!
//! A connection has one of the states of `enum tcp_conntrack`. The flags of each segment
//! (SYN, SYN and ACK, FIN, ACK, RST) and its direction pick the next state from the table
//! `tcp_conntracks`. The tracker follows the sequence numbers and the windows of the two ends
//! (`tcp_in_window`, from "Real Stateful TCP Packet Filtering in IP Filter" of Guido van
//! Rooij), so a segment out of the window is invalid, unless `nf_conntrack_tcp_be_liberal` is
//! set. Each state has its timeout of /proc/sys/net/netfilter.

use super::{IP_CT_DIR_ORIGINAL, IP_CT_DIR_REPLY, IPS_ASSURED, IPS_SEEN_REPLY, NfConn, timeout};
use crate::sysctl;

/// The states of a TCP connection, as `enum tcp_conntrack` of Linux.
pub const TCP_CONNTRACK_NONE: u8 = 0;
/// The first SYN went out.
pub const TCP_CONNTRACK_SYN_SENT: u8 = 1;
/// The SYN and ACK came back.
pub const TCP_CONNTRACK_SYN_RECV: u8 = 2;
/// The three-way handshake is done.
pub const TCP_CONNTRACK_ESTABLISHED: u8 = 3;
/// One end sent a FIN.
pub const TCP_CONNTRACK_FIN_WAIT: u8 = 4;
/// The other end took the FIN.
pub const TCP_CONNTRACK_CLOSE_WAIT: u8 = 5;
/// Both ends sent a FIN.
pub const TCP_CONNTRACK_LAST_ACK: u8 = 6;
/// The last ACK went out.
pub const TCP_CONNTRACK_TIME_WAIT: u8 = 7;
/// A RST closed the connection.
pub const TCP_CONNTRACK_CLOSE: u8 = 8;
/// Both ends sent a SYN, a simultaneous open.
pub const TCP_CONNTRACK_SYN_SENT2: u8 = 9;
/// The count of the states. In the table it is an invalid segment.
pub const TCP_CONNTRACK_MAX: u8 = 10;
/// A segment that the table ignores.
const TCP_CONNTRACK_IGNORE: u8 = 11;

const NO: u8 = TCP_CONNTRACK_NONE;
const SS: u8 = TCP_CONNTRACK_SYN_SENT;
const SR: u8 = TCP_CONNTRACK_SYN_RECV;
const ES: u8 = TCP_CONNTRACK_ESTABLISHED;
const FW: u8 = TCP_CONNTRACK_FIN_WAIT;
const CW: u8 = TCP_CONNTRACK_CLOSE_WAIT;
const LA: u8 = TCP_CONNTRACK_LAST_ACK;
const TW: u8 = TCP_CONNTRACK_TIME_WAIT;
const CL: u8 = TCP_CONNTRACK_CLOSE;
const S2: u8 = TCP_CONNTRACK_SYN_SENT2;
const IV: u8 = TCP_CONNTRACK_MAX;
const IG: u8 = TCP_CONNTRACK_IGNORE;

/// The names of the states, as `tcp_conntrack_names` of Linux.
pub const TCP_CONNTRACK_NAMES: [&str; 10] = [
    "NONE",
    "SYN_SENT",
    "SYN_RECV",
    "ESTABLISHED",
    "FIN_WAIT",
    "CLOSE_WAIT",
    "LAST_ACK",
    "TIME_WAIT",
    "CLOSE",
    "SYN_SENT2",
];

/// The indexes of the flags of a segment in the table, as `enum tcp_bit_set` of Linux.
const TCP_SYN_SET: u8 = 0;
const TCP_SYNACK_SET: u8 = 1;
const TCP_FIN_SET: u8 = 2;
const TCP_ACK_SET: u8 = 3;
const TCP_RST_SET: u8 = 4;
const TCP_NONE_SET: u8 = 5;

/// The next state for the direction, the flags and the state, as `tcp_conntracks` of Linux.
#[rustfmt::skip]
const TCP_CONNTRACKS: [[[u8; 10]; 6]; 2] = [
    // The original direction.
    [
        //  NO  SS  SR  ES  FW  CW  LA  TW  CL  S2
        [SS, SS, IG, IG, IG, IG, IG, SS, SS, S2], // syn
        [IV, IV, SR, IV, IV, IV, IV, IV, IV, SR], // synack
        [IV, IV, FW, FW, LA, LA, LA, TW, CL, IV], // fin
        [ES, IV, ES, ES, CW, CW, TW, TW, CL, IV], // ack
        [IV, CL, CL, CL, CL, CL, CL, CL, CL, CL], // rst
        [IV, IV, IV, IV, IV, IV, IV, IV, IV, IV], // none
    ],
    // The reply direction.
    [
        //  NO  SS  SR  ES  FW  CW  LA  TW  CL  S2
        [IV, S2, IV, IV, IV, IV, IV, SS, IV, S2], // syn
        [IV, SR, IG, IG, IG, IG, IG, IG, IG, SR], // synack
        [IV, IV, FW, FW, LA, LA, LA, TW, CL, IV], // fin
        [IV, IG, SR, ES, CW, CW, TW, TW, CL, IG], // ack
        [IV, CL, CL, CL, CL, CL, CL, CL, CL, CL], // rst
        [IV, IV, IV, IV, IV, IV, IV, IV, IV, IV], // none
    ],
];

/// The timeouts of the states in /proc/sys/net/netfilter. SYN_SENT2 has the one of SYN_SENT.
const STATE_TIMEOUTS: [&str; 10] = [
    "nf_conntrack_tcp_timeout_close",
    "nf_conntrack_tcp_timeout_syn_sent",
    "nf_conntrack_tcp_timeout_syn_recv",
    "nf_conntrack_tcp_timeout_established",
    "nf_conntrack_tcp_timeout_fin_wait",
    "nf_conntrack_tcp_timeout_close_wait",
    "nf_conntrack_tcp_timeout_last_ack",
    "nf_conntrack_tcp_timeout_time_wait",
    "nf_conntrack_tcp_timeout_close",
    "nf_conntrack_tcp_timeout_syn_sent",
];

/// The flags of a TCP header.
const TH_FIN: u8 = 0x01;
const TH_SYN: u8 = 0x02;
const TH_RST: u8 = 0x04;
const TH_PSH: u8 = 0x08;
const TH_ACK: u8 = 0x10;
const TH_URG: u8 = 0x20;
const TH_ECE: u8 = 0x40;
const TH_CWR: u8 = 0x80;

/// The flags of an end, as `IP_CT_TCP_FLAG_*` of Linux.
const IP_CT_TCP_FLAG_WINDOW_SCALE: u8 = 0x01;
const IP_CT_TCP_FLAG_SACK_PERM: u8 = 0x02;
const IP_CT_TCP_FLAG_CLOSE_INIT: u8 = 0x04;
const IP_CT_TCP_FLAG_BE_LIBERAL: u8 = 0x08;
const IP_CT_TCP_FLAG_DATA_UNACKNOWLEDGED: u8 = 0x10;
const IP_CT_TCP_FLAG_MAXACK_SET: u8 = 0x20;

/// The flag of `last_flags` for a simultaneous open, as `IP_CT_TCP_SIMULTANEOUS_OPEN`.
const IP_CT_TCP_SIMULTANEOUS_OPEN: u8 = 0x04;

/// The smallest window of an ACK under the lower bound, as `MAXACKWINCONST` of Linux.
const MAXACKWINCONST: u32 = 66000;

/// The largest window scale, as `TCP_MAX_WSCALE` of Linux.
const TCP_MAX_WSCALE: u8 = 14;

/// The view of one end of the connection, as `struct ip_ct_tcp_state` of Linux.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpEnd {
    /// The highest end of the sequence numbers that the end sent.
    pub td_end: u32,
    /// The highest end of the window that the other end gave to this end.
    pub td_maxend: u32,
    /// The largest window of this end.
    pub td_maxwin: u32,
    /// The highest ACK of this end.
    pub td_maxack: u32,
    /// The window scale of this end.
    pub td_scale: u8,
    /// The `IP_CT_TCP_FLAG_*` bits.
    pub flags: u8,
}

/// The TCP part of a connection, as `struct ip_ct_tcp` of Linux.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpState {
    /// The two ends, by direction.
    pub seen: [TcpEnd; 2],
    /// The state, `TCP_CONNTRACK_*`.
    pub state: u8,
    last_dir: usize,
    retrans: u8,
    last_index: u8,
    last_seq: u32,
    last_ack: u32,
    last_end: u32,
    last_win: u16,
    last_flags: u8,
    last_wscale: u8,
}

/// The fields of a TCP header and the length of the segment.
struct Th<'a> {
    seq: u32,
    ack_seq: u32,
    window: u16,
    flags: u8,
    /// The options.
    opts: &'a [u8],
    /// The bytes of data after the header.
    len: u32,
}

impl Th<'_> {
    fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }

    /// The sequence number after the segment, as `segment_seq_plus_len` of Linux.
    fn end(&self) -> u32 {
        self.seq
            .wrapping_add(self.len)
            .wrapping_add(u32::from(self.has(TH_SYN)))
            .wrapping_add(u32::from(self.has(TH_FIN)))
    }

    /// The index of the flags in the table, as `get_conntrack_index` of Linux.
    fn index(&self) -> u8 {
        if self.has(TH_RST) {
            TCP_RST_SET
        } else if self.has(TH_SYN) {
            if self.has(TH_ACK) { TCP_SYNACK_SET } else { TCP_SYN_SET }
        } else if self.has(TH_FIN) {
            TCP_FIN_SET
        } else if self.has(TH_ACK) {
            TCP_ACK_SET
        } else {
            TCP_NONE_SET
        }
    }
}

/// Parses the TCP header at `l4`, with `len` bytes of segment. Gives `None` for a header that
/// is too short, as `tcp_error` of Linux.
fn parse(l4: &[u8], len: usize) -> Option<Th<'_>> {
    let h = l4.get(..20)?;
    let doff = usize::from(h[12] >> 4) * 4;
    if doff < 20 || doff > len {
        return None;
    }
    let opts = l4.get(20..doff)?;
    Some(Th {
        seq: u32::from_be_bytes([h[4], h[5], h[6], h[7]]),
        ack_seq: u32::from_be_bytes([h[8], h[9], h[10], h[11]]),
        flags: h[13],
        window: u16::from_be_bytes([h[14], h[15]]),
        opts,
        len: u32::try_from(len - doff).ok()?,
    })
}

/// Tells if the flags of a segment are a valid set, as `tcp_valid_flags` of Linux.
fn valid_flags(flags: u8) -> bool {
    let f = flags & !(TH_ECE | TH_CWR | TH_PSH);
    matches!(
        f,
        TH_SYN
            | 0x22 // SYN | URG
            | 0x12 // SYN | ACK
            | TH_RST
            | 0x14 // RST | ACK
            | 0x11 // FIN | ACK
            | 0x31 // FIN | ACK | URG
            | TH_ACK
            | 0x30 // ACK | URG
    ) && (f & TH_URG == 0 || f & (TH_SYN | TH_ACK) != 0)
}

/// Walks the options of a header and gives each kind and its data.
fn options(opts: &[u8], mut f: impl FnMut(u8, &[u8])) {
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => return,
            1 => i += 1,
            kind => {
                let Some(&l) = opts.get(i + 1) else { return };
                let l = usize::from(l);
                if l < 2 || i + l > opts.len() {
                    return;
                }
                f(kind, &opts[i + 2..i + l]);
                i += l;
            }
        }
    }
}

/// Reads the window scale and SACK permitted options of a SYN, as `tcp_options` of Linux.
fn tcp_options(th: &Th<'_>, end: &mut TcpEnd) {
    end.td_scale = 0;
    end.flags &= !(IP_CT_TCP_FLAG_WINDOW_SCALE | IP_CT_TCP_FLAG_SACK_PERM);
    options(th.opts, |kind, data| match (kind, data.len()) {
        (4, 0) => end.flags |= IP_CT_TCP_FLAG_SACK_PERM,
        (3, 1) => {
            end.td_scale = data[0].min(TCP_MAX_WSCALE);
            end.flags |= IP_CT_TCP_FLAG_WINDOW_SCALE;
        }
        _ => {}
    });
}

/// The highest right edge of the SACK blocks of a header, as `tcp_sack` of Linux.
fn tcp_sack(th: &Th<'_>, sack: &mut u32) {
    options(th.opts, |kind, data| {
        if kind == 5 && data.len() % 8 == 0 {
            for b in data.as_chunks::<8>().0 {
                let right = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
                if after(right, *sack) {
                    *sack = right;
                }
            }
        }
    });
}

/// `before` of Linux: `a` is before `b` in the sequence space.
fn before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn after(a: u32, b: u32) -> bool {
    before(b, a)
}

/// The result of `tcp_in_window`, as `enum nf_ct_tcp_action` of Linux.
#[derive(Debug, PartialEq, Eq)]
enum Window {
    Accept,
    Invalid,
    Ignore,
}

/// The result of the tracker for a segment.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// The segment belongs to the connection.
    Accept,
    /// The segment is not valid, so it gets no connection.
    Invalid,
    /// The segment opens a connection again, so the old one goes and the lookup runs again.
    Repeat,
    /// The connection goes, and the segment keeps it.
    Kill,
}

fn liberal(sender: &TcpEnd, ret: Window) -> Window {
    if sender.flags & IP_CT_TCP_FLAG_BE_LIBERAL != 0
        || sysctl::netfilter("nf_conntrack_tcp_be_liberal") != 0
    {
        Window::Accept
    } else {
        ret
    }
}

fn maxackwindow(e: &TcpEnd) -> u32 {
    e.td_maxwin.max(MAXACKWINCONST)
}

/// Makes the view of the end of the first SYN, as `tcp_new` of Linux. Gives `false` for a
/// segment that does not start a connection.
fn tcp_new(s: &mut TcpState, th: &Th<'_>) -> bool {
    let new_state = TCP_CONNTRACKS[0][usize::from(th.index())][usize::from(NO)];
    if new_state >= TCP_CONNTRACK_MAX {
        return false;
    }
    *s = TcpState::default();
    let e = &mut s.seen[0];
    e.td_end = th.end();
    e.td_maxwin = u32::from(th.window).max(1);
    if new_state == TCP_CONNTRACK_SYN_SENT {
        e.td_maxend = e.td_end;
        tcp_options(th, e);
    } else if sysctl::netfilter("nf_conntrack_tcp_loose") == 0 {
        // The tracker does not take a connection in the middle.
        return false;
    } else {
        // The history of the connection is lost, so the tracker takes the window of the
        // segment, with SACK and no window check.
        e.td_maxend = e.td_end.wrapping_add(e.td_maxwin);
        let f = IP_CT_TCP_FLAG_SACK_PERM | IP_CT_TCP_FLAG_BE_LIBERAL;
        s.seen[0].flags = f;
        s.seen[1].flags = f;
    }
    s.last_index = TCP_NONE_SET;
    true
}

/// Sets the view of the end that sends a SYN or a SYN and ACK, as `tcp_init_sender` of Linux.
fn init_sender(s: &mut TcpState, dir: usize, th: &Th<'_>, end: u32, win: u32) {
    let [a, b] = &mut s.seen;
    let (sender, receiver) = if dir == 0 { (a, b) } else { (b, a) };
    sender.td_end = end;
    sender.td_maxend = end;
    sender.td_maxwin = win.max(1);
    tcp_options(th, sender);
    // RFC 7323: both ends must send the window scale option to scale the windows.
    if sender.flags & IP_CT_TCP_FLAG_WINDOW_SCALE == 0
        || receiver.flags & IP_CT_TCP_FLAG_WINDOW_SCALE == 0
    {
        sender.td_scale = 0;
        receiver.td_scale = 0;
    }
}

/// Checks the sequence and the ACK numbers of a segment against the windows, and moves the
/// windows, as `tcp_in_window` of Linux.
fn tcp_in_window(s: &mut TcpState, dir: usize, index: u8, th: &Th<'_>) -> Window {
    let mut ack = th.ack_seq;
    let mut sack = ack;
    let win_raw = th.window;
    let mut win = u32::from(win_raw);
    let mut seq = th.seq;
    let mut end = th.end();
    let state = s.state;
    if s.seen[1 - dir].flags & IP_CT_TCP_FLAG_SACK_PERM != 0 {
        tcp_sack(th, &mut sack);
    }
    if s.seen[dir].td_maxwin == 0 {
        if th.has(TH_SYN) {
            // A SYN and ACK for a SYN, or a SYN of the reply direction in a simultaneous open.
            init_sender(s, dir, th, end, win);
            if !th.has(TH_ACK) {
                return Window::Accept;
            }
        } else {
            // A segment in the middle of a connection.
            let [a, b] = &mut s.seen;
            let (sender, receiver) = if dir == 0 { (a, b) } else { (b, a) };
            sender.td_end = end;
            let swin = win << sender.td_scale;
            sender.td_maxwin = swin.max(1);
            sender.td_maxend = end.wrapping_add(sender.td_maxwin);
            if receiver.td_maxwin == 0 {
                receiver.td_end = sack;
                receiver.td_maxend = sack;
            } else if sack == receiver.td_end.wrapping_add(1) {
                // The answer to a keepalive.
                receiver.td_end = receiver.td_end.wrapping_add(1);
            }
        }
    } else if th.has(TH_SYN)
        && after(end, s.seen[dir].td_end)
        && (state == TCP_CONNTRACK_SYN_SENT || state == TCP_CONNTRACK_SYN_RECV)
    {
        // RFC 793: a TCP that starts again uses higher sequence numbers.
        init_sender(s, dir, th, end, win);
        if dir == IP_CT_DIR_REPLY && !th.has(TH_ACK) {
            return Window::Accept;
        }
    }

    let [a, b] = &mut s.seen;
    let (sender, receiver) = if dir == 0 { (a, b) } else { (b, a) };
    if !th.has(TH_ACK) || (th.has(TH_RST) && ack == 0) {
        // No ACK, or the ACK 0 of a RST of a broken stack.
        ack = receiver.td_end;
        sack = ack;
    }
    if th.has(TH_RST) && seq == 0 && state == TCP_CONNTRACK_SYN_SENT {
        // A RST for a SYN.
        seq = sender.td_end;
        end = seq;
    }

    let mut seq_ok = before(seq, sender.td_maxend.wrapping_add(1));
    if !seq_ok {
        let overshot = end.wrapping_sub(sender.td_maxend).wrapping_add(1);
        let ack_ok =
            after(sack, receiver.td_end.wrapping_sub(maxackwindow(sender)).wrapping_sub(1));
        let in_recv_win = receiver.td_maxwin != 0
            && after(end, sender.td_end.wrapping_sub(receiver.td_maxwin).wrapping_sub(1));
        // Some stacks send more than the window of the receiver.
        if in_recv_win
            && ack_ok
            && overshot <= receiver.td_maxwin
            && before(sack, receiver.td_end.wrapping_add(1))
        {
            seq_ok = true;
        }
        if !seq_ok {
            // The sequence number is over the window of the receiver.
            return liberal(sender, Window::Invalid);
        }
    }
    if !before(sack, receiver.td_end.wrapping_add(1)) {
        // The ACK is for data that the tracker did not see.
        if liberal(sender, Window::Invalid) == Window::Invalid {
            return Window::Invalid;
        }
    }
    let in_recv_win = receiver.td_maxwin == 0
        || after(end, sender.td_end.wrapping_sub(receiver.td_maxwin).wrapping_sub(1));
    if !in_recv_win {
        // The receiver took this data already: a retransmission.
        if liberal(sender, Window::Ignore) == Window::Ignore {
            return Window::Ignore;
        }
    }
    if !after(sack, receiver.td_end.wrapping_sub(maxackwindow(sender)).wrapping_sub(1))
        && liberal(sender, Window::Ignore) == Window::Ignore
    {
        // An ACK under the lower bound, which came late.
        return Window::Ignore;
    }

    // RFC 7323: the window of a segment without SYN is scaled.
    if !th.has(TH_SYN) {
        win <<= sender.td_scale;
    }
    let swin = win.wrapping_add(sack.wrapping_sub(ack));
    if sender.td_maxwin < swin {
        sender.td_maxwin = swin;
    }
    if after(end, sender.td_end) {
        sender.td_end = end;
        sender.flags |= IP_CT_TCP_FLAG_DATA_UNACKNOWLEDGED;
    }
    if th.has(TH_ACK) {
        if sender.flags & IP_CT_TCP_FLAG_MAXACK_SET == 0 {
            sender.td_maxack = ack;
            sender.flags |= IP_CT_TCP_FLAG_MAXACK_SET;
        } else if after(ack, sender.td_maxack) {
            sender.td_maxack = ack;
        }
    }
    if receiver.td_maxwin != 0 && after(end, sender.td_maxend) {
        receiver.td_maxwin = receiver.td_maxwin.wrapping_add(end.wrapping_sub(sender.td_maxend));
    }
    if after(sack.wrapping_add(win), receiver.td_maxend.wrapping_sub(1)) {
        receiver.td_maxend = sack.wrapping_add(win);
        if win == 0 {
            receiver.td_maxend = receiver.td_maxend.wrapping_add(1);
        }
    }
    if ack == receiver.td_end {
        receiver.flags &= !IP_CT_TCP_FLAG_DATA_UNACKNOWLEDGED;
    }

    // A retransmission of the same ACK.
    if index == TCP_ACK_SET {
        if s.last_dir == dir
            && s.last_seq == seq
            && s.last_ack == ack
            && s.last_end == end
            && s.last_win == win_raw
        {
            s.retrans = s.retrans.saturating_add(1);
        } else {
            s.last_dir = dir;
            s.last_seq = seq;
            s.last_ack = ack;
            s.last_end = end;
            s.last_win = win_raw;
            s.retrans = 0;
        }
    }
    Window::Accept
}

/// Keeps the segment that the table ignores, so that a later segment can use it, as the case
/// `TCP_CONNTRACK_IGNORE` of `nf_conntrack_tcp_packet` of Linux.
fn note_ignored(s: &mut TcpState, dir: usize, index: u8, th: &Th<'_>) {
    s.last_index = index;
    s.last_dir = dir;
    s.last_seq = th.seq;
    s.last_end = th.end();
    s.last_win = th.window;
    // A SYN of the original direction: the ends can be in sync while the tracker is not. The
    // tracker keeps the options of the SYN, and a SYN and ACK for it puts the tracker in sync.
    if index == TCP_SYN_SET && dir == IP_CT_DIR_ORIGINAL {
        let mut e = TcpEnd::default();
        tcp_options(th, &mut e);
        s.last_flags = e.flags & (IP_CT_TCP_FLAG_WINDOW_SCALE | IP_CT_TCP_FLAG_SACK_PERM);
        s.last_wscale = e.td_scale;
    }
}

/// The work of the tracker for a segment, as `nf_conntrack_tcp_packet` of Linux. `l4` is the
/// TCP header and the data after it, `len` bytes of segment. `new` tells that the connection
/// is not in the table yet.
pub(super) fn tcp_packet(ct: &NfConn, dir: usize, l4: &[u8], len: usize, new: bool) -> Verdict {
    let Some(th) = parse(l4, len) else { return Verdict::Invalid };
    if !valid_flags(th.flags) {
        return Verdict::Invalid;
    }
    let mut guard = ct.tcp.lock();
    let s = &mut *guard;
    if new && !tcp_new(s, &th) {
        return Verdict::Invalid;
    }
    let mut old_state = s.state;
    let index = th.index();
    let mut new_state = TCP_CONNTRACKS[dir][usize::from(index)][usize::from(old_state)];
    let mut check_window = true;
    match new_state {
        TCP_CONNTRACK_SYN_SENT | IG => {
            let mut ignore = new_state == IG;
            if new_state == TCP_CONNTRACK_SYN_SENT && old_state >= TCP_CONNTRACK_TIME_WAIT {
                // A SYN after the close opens the connection again, as RFC 1122 for
                // TIME-WAIT.
                let flags = s.seen[dir].flags | s.seen[1 - dir].flags;
                if flags & IP_CT_TCP_FLAG_CLOSE_INIT != 0
                    || (s.last_dir == dir && s.last_index == TCP_RST_SET)
                {
                    return Verdict::Repeat;
                }
                ignore = true;
            }
            if ignore {
                if index == TCP_SYNACK_SET
                    && s.last_index == TCP_SYN_SET
                    && s.last_dir != dir
                    && th.ack_seq == s.last_end
                {
                    // The SYN and ACK is for a SYN that the table ignored: the connection
                    // starts again from that SYN.
                    old_state = TCP_CONNTRACK_SYN_SENT;
                    new_state = TCP_CONNTRACK_SYN_RECV;
                    let o = &mut s.seen[s.last_dir];
                    o.td_end = s.last_end;
                    o.td_maxend = s.last_end;
                    o.td_maxwin = u32::from(s.last_win).max(1);
                    o.td_scale = s.last_wscale;
                    o.flags =
                        s.last_flags & (IP_CT_TCP_FLAG_WINDOW_SCALE | IP_CT_TCP_FLAG_SACK_PERM);
                    s.seen[dir] = TcpEnd::default();
                } else {
                    note_ignored(s, dir, index, &th);
                    return Verdict::Accept;
                }
            }
        }
        IV => return Verdict::Invalid,
        TCP_CONNTRACK_SYN_SENT2 => s.last_flags |= IP_CT_TCP_SIMULTANEOUS_OPEN,
        TCP_CONNTRACK_SYN_RECV => {
            if dir == IP_CT_DIR_REPLY
                && index == TCP_ACK_SET
                && s.last_flags & IP_CT_TCP_SIMULTANEOUS_OPEN != 0
            {
                new_state = TCP_CONNTRACK_ESTABLISHED;
            }
        }
        TCP_CONNTRACK_CLOSE if index == TCP_RST_SET => {
            let other = s.seen[1 - dir];
            if other.flags & IP_CT_TCP_FLAG_MAXACK_SET != 0 {
                // An ACK of the other end gives the sequence number that the RST must have.
                if before(th.seq, other.td_maxack)
                    && sysctl::netfilter("nf_conntrack_tcp_ignore_invalid_rst") == 0
                {
                    return Verdict::Invalid;
                }
                let established =
                    old_state == TCP_CONNTRACK_ESTABLISHED && ct.status() & IPS_ASSURED != 0;
                let train =
                    s.last_index == TCP_ACK_SET && s.last_dir == dir && th.seq == s.last_end;
                if established && th.seq != other.td_maxack && !train {
                    // A RST that is in the window but not at its start: the stack sends a
                    // challenge ACK, as RFC 5961, and the connection stays.
                    note_ignored(s, dir, index, &th);
                    return Verdict::Accept;
                }
            }
            // A RST for a SYN or an ACK that the tracker let through as out of sync.
            let after_sync = (ct.status() & IPS_SEEN_REPLY != 0 && s.last_index == TCP_SYN_SET)
                || (ct.status() & IPS_ASSURED == 0 && s.last_index == TCP_ACK_SET);
            if after_sync && th.ack_seq == s.last_end {
                check_window = false;
            }
        }
        _ => {}
    }

    if check_window {
        match tcp_in_window(s, dir, index, &th) {
            Window::Accept => {}
            Window::Ignore => return Verdict::Accept,
            Window::Invalid => return Verdict::Invalid,
        }
    }
    s.last_index = index;
    s.last_dir = dir;
    s.state = new_state;
    if old_state != new_state && new_state == TCP_CONNTRACK_FIN_WAIT {
        s.seen[dir].flags |= IP_CT_TCP_FLAG_CLOSE_INIT;
    }

    let t = |st: u8| timeout(STATE_TIMEOUTS[usize::from(st)]);
    let retrans = timeout("nf_conntrack_tcp_timeout_max_retrans");
    let unack = timeout("nf_conntrack_tcp_timeout_unacknowledged");
    let max_retrans =
        u8::try_from(sysctl::netfilter("nf_conntrack_tcp_max_retrans")).unwrap_or(u8::MAX);
    let unacked = (s.seen[0].flags | s.seen[1].flags) & IP_CT_TCP_FLAG_DATA_UNACKNOWLEDGED != 0;
    let mut extra = if s.retrans >= max_retrans && t(new_state) > retrans {
        retrans
    } else if index == TCP_RST_SET {
        t(TCP_CONNTRACK_CLOSE)
    } else if unacked && t(new_state) > unack {
        unack
    } else if s.last_win == 0 && t(new_state) > retrans {
        retrans
    } else {
        t(new_state)
    };
    drop(guard);

    // The core sets `IPS_SEEN_REPLY` after the tracker, so the first reply sees it clear.
    if ct.status() & IPS_SEEN_REPLY == 0 {
        // A connection whose only reply is a RST goes at once.
        if th.has(TH_RST) {
            return Verdict::Kill;
        }
        // A connection in the middle with no reply does not get the long timeout.
        if new_state == TCP_CONNTRACK_ESTABLISHED && extra > unack {
            extra = unack;
        }
    } else if ct.status() & IPS_ASSURED == 0
        && (old_state == TCP_CONNTRACK_SYN_RECV || old_state == TCP_CONNTRACK_ESTABLISHED)
        && new_state == TCP_CONNTRACK_ESTABLISHED
    {
        // A valid ACK after the handshake, or an answer for a connection in the middle.
        ct.set_status(IPS_ASSURED);
    }
    ct.refresh(extra);
    Verdict::Accept
}

/// The state of the TCP connection `ct`, `TCP_CONNTRACK_*`.
pub fn tcp_state(ct: &NfConn) -> u8 {
    ct.tcp.lock().state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flags_and_the_sequence_space() {
        assert!(valid_flags(TH_SYN));
        assert!(valid_flags(TH_SYN | TH_ACK | TH_ECE));
        assert!(valid_flags(TH_FIN | TH_ACK | TH_PSH));
        assert!(!valid_flags(TH_SYN | TH_FIN));
        assert!(!valid_flags(TH_FIN));
        assert!(!valid_flags(0));
        assert!(before(0xffff_fff0, 0x10));
        assert!(after(0x10, 0xffff_fff0));
        let mut sack = 100;
        let opts = [1, 1, 5, 10, 0, 0, 0, 1, 0, 0, 0, 200];
        tcp_sack(&Th { seq: 0, ack_seq: 0, window: 0, flags: 0, opts: &opts, len: 0 }, &mut sack);
        assert_eq!(sack, 200);
        let mut e = TcpEnd::default();
        let opts = [2, 4, 5, 0xb4, 4, 2, 3, 3, 15];
        tcp_options(&Th { seq: 0, ack_seq: 0, window: 0, flags: 0, opts: &opts, len: 0 }, &mut e);
        assert_eq!(e.td_scale, 14);
        assert_eq!(e.flags, IP_CT_TCP_FLAG_WINDOW_SCALE | IP_CT_TCP_FLAG_SACK_PERM);
    }
}

//! The cases of RFC 9293 on two connections that a test wires together.

use super::*;
use alloc::vec;
use alloc::vec::Vec;

const MSS: u32 = 1024;

fn cfg(iss: u32) -> Config {
    Config { iss, mss: MSS, rcvbuf: 20_480, sndbuf: 100_000, algo: Algo::Cubic }
}

/// Moves the output of `from` to `to`, and gives the number of segments.
fn deliver(from: &mut Conn, to: &mut Conn, now: u64) -> usize {
    let out = from.take_output();
    let n = out.len();
    for s in out {
        to.input(s, now);
    }
    n
}

/// Moves the segments both ways until no segment is left.
fn settle(a: &mut Conn, b: &mut Conn, now: u64) {
    for _ in 0..1000 {
        if deliver(a, b, now) + deliver(b, a, now) == 0 {
            return;
        }
    }
    panic!("no end");
}

/// Two open connections: `a` opened, `b` came from a listening socket.
fn pair() -> (Conn, Conn) {
    let mut a = Conn::new(&cfg(1000));
    a.connect(0);
    let syn = a.take_output().remove(0);
    let mut b = Conn::accept(&cfg(5000), &syn, 0);
    settle(&mut a, &mut b, 0);
    assert_eq!(a.state(), State::Established);
    assert_eq!(b.state(), State::Established);
    // One byte each way, so that each side knows the scaled window of the other.
    a.send(b"a", 0);
    deliver(&mut a, &mut b, 0);
    assert_eq!(read_all(&mut b, 0), b"a");
    b.send(b"b", 0);
    settle(&mut a, &mut b, 0);
    assert_eq!(read_all(&mut a, 0), b"b");
    (a, b)
}

/// Reads all the data of `c`.
fn read_all(c: &mut Conn, now: u64) -> Vec<u8> {
    c.recv(usize::MAX, false, now)
}

#[test]
fn handshake() {
    let mut a = Conn::new(&cfg(1000));
    a.connect(0);
    assert_eq!(a.state(), State::SynSent);
    let syn = a.take_output();
    assert_eq!(syn.len(), 1);
    let syn = &syn[0];
    assert_eq!((syn.seq, syn.flags), (1000, SYN));
    assert_eq!((syn.mss, syn.wscale), (Some(MSS as u16), Some(WSCALE)));
    assert_eq!(syn.wnd, 10_240);

    let mut b = Conn::accept(&cfg(5000), syn, 0);
    assert_eq!(b.state(), State::SynRcvd);
    let synack = b.take_output();
    assert_eq!(synack.len(), 1);
    assert_eq!((synack[0].seq, synack[0].ack, synack[0].flags), (5000, 1001, SYN | ACK));
    assert_eq!(synack[0].wscale, Some(WSCALE));

    a.input(synack[0].clone(), 10);
    assert_eq!(a.state(), State::Established);
    assert_eq!(a.srtt(), 10);
    let ack = a.take_output();
    assert_eq!(ack.len(), 1);
    assert_eq!((ack[0].seq, ack[0].ack, ack[0].flags), (1001, 5001, ACK));
    // The window has the scale: 10240 >> 7.
    assert_eq!(ack[0].wnd, 80);
    b.input(ack[0].clone(), 10);
    assert_eq!(b.state(), State::Established);
    assert!(b.take_output().is_empty());
}

#[test]
fn no_window_scale_without_the_option() {
    let mut b =
        Conn::accept(&cfg(5000), &Seg { seq: 7, flags: SYN, wnd: 3000, ..Seg::default() }, 0);
    let synack = b.take_output().remove(0);
    assert_eq!(synack.wscale, None);
    // A peer without the option MSS has 536.
    assert_eq!(b.mss(), DEFAULT_MSS);
    b.input(Seg { seq: 8, ack: 5001, flags: ACK, wnd: 3000, ..Seg::default() }, 0);
    assert_eq!(b.state(), State::Established);
    b.nodelay = true;
    assert_eq!(b.send(&[0; 10], 0), 10);
    let s = b.take_output().remove(0);
    assert_eq!(s.wnd, 10_240);
}

#[test]
fn simultaneous_open() {
    let mut a = Conn::new(&cfg(1000));
    let mut b = Conn::new(&cfg(5000));
    a.connect(0);
    b.connect(0);
    let sa = a.take_output();
    let sb = b.take_output();
    for s in sb {
        a.input(s, 0);
    }
    for s in sa {
        b.input(s, 0);
    }
    assert_eq!(a.state(), State::SynRcvd);
    assert_eq!(b.state(), State::SynRcvd);
    let sa = a.take_output();
    assert_eq!((sa[0].seq, sa[0].ack, sa[0].flags), (1000, 5001, SYN | ACK));
    let sb = b.take_output();
    for s in sb {
        a.input(s, 0);
    }
    for s in sa {
        b.input(s, 0);
    }
    assert_eq!(a.state(), State::Established);
    assert_eq!(b.state(), State::Established);
    settle(&mut a, &mut b, 0);
    a.nodelay = true;
    a.send(b"hi", 0);
    settle(&mut a, &mut b, 0);
    assert_eq!(read_all(&mut b, 0), b"hi");
}

#[test]
fn data_both_ways_through_small_windows() {
    let (mut a, mut b) = pair();
    let data: Vec<u8> = (0..200_000u32).map(|i| (i * 7 + i / 251) as u8).collect();
    let back: Vec<u8> = data.iter().rev().copied().collect();
    let (mut sent_a, mut sent_b) = (0, 0);
    let (mut got_a, mut got_b) = (Vec::new(), Vec::new());
    let mut now = 0;
    while got_b.len() < data.len() || got_a.len() < back.len() {
        sent_a += a.send(&data[sent_a..], now);
        sent_b += b.send(&back[sent_b..], now);
        settle(&mut a, &mut b, now);
        got_b.extend(b.recv(3000, false, now));
        got_a.extend(a.recv(7000, false, now));
        settle(&mut a, &mut b, now);
        now += 1;
        if let Some(t) = a.next_timer().into_iter().chain(b.next_timer()).min()
            && t <= now
        {
            a.tick(now);
            b.tick(now);
        }
        assert!(now < 100_000, "stuck at {} and {}", got_b.len(), got_a.len());
    }
    assert!(got_b == data);
    assert!(got_a == back);
}

#[test]
fn close_from_one_side() {
    let (mut a, mut b) = pair();
    a.nodelay = true;
    a.send(b"end", 0);
    a.close(0);
    assert_eq!(a.state(), State::FinWait1);
    let out = a.take_output();
    assert_eq!(out.len(), 2);
    assert!(out[0].has(ACK | PSH));
    assert!(out[1].has(FIN | ACK));
    for s in out {
        b.input(s, 0);
    }
    assert_eq!(b.state(), State::CloseWait);
    assert!(b.fin_rcvd());
    assert_eq!(read_all(&mut b, 0), b"end");
    deliver(&mut b, &mut a, 0);
    assert_eq!(a.state(), State::FinWait2);
    // The other side can still send.
    b.nodelay = true;
    b.send(b"reply", 0);
    deliver(&mut b, &mut a, 0);
    assert_eq!(read_all(&mut a, 0), b"reply");
    b.close(0);
    assert_eq!(b.state(), State::LastAck);
    deliver(&mut b, &mut a, 0);
    assert_eq!(a.state(), State::TimeWait);
    deliver(&mut a, &mut b, 0);
    assert_eq!(b.state(), State::Closed);
    assert_eq!(b.error(), None);
    assert_eq!(a.next_timer(), Some(TIME_WAIT));
    a.tick(TIME_WAIT);
    assert_eq!(a.state(), State::Closed);
    assert_eq!(a.error(), None);
}

#[test]
fn simultaneous_close() {
    let (mut a, mut b) = pair();
    a.close(0);
    b.close(0);
    let fa = a.take_output();
    let fb = b.take_output();
    for s in fb {
        a.input(s, 0);
    }
    for s in fa {
        b.input(s, 0);
    }
    assert_eq!(a.state(), State::Closing);
    assert_eq!(b.state(), State::Closing);
    settle(&mut a, &mut b, 0);
    assert_eq!(a.state(), State::TimeWait);
    assert_eq!(b.state(), State::TimeWait);
}

#[test]
fn time_wait_acknowledges_a_fin_again() {
    let (mut a, mut b) = pair();
    a.close(0);
    settle(&mut a, &mut b, 0);
    b.close(0);
    let fin = b.take_output().remove(0);
    a.input(fin.clone(), 0);
    assert_eq!(a.state(), State::TimeWait);
    a.take_output();
    // The ACK was lost, and the FIN comes again later.
    a.input(fin, 1000);
    let ack = a.take_output();
    assert_eq!(ack.len(), 1);
    assert_eq!(ack[0].ack, fin_ack(&b));
    assert_eq!(a.next_timer(), Some(1000 + TIME_WAIT));
}

fn fin_ack(c: &Conn) -> u32 {
    c.snd_max
}

#[test]
fn reset_in_syn_sent() {
    let mut a = Conn::new(&cfg(1000));
    a.connect(0);
    a.take_output();
    // An RST without ACK, or with a bad ACK, does nothing.
    a.input(Seg { seq: 0, flags: RST, ..Seg::default() }, 0);
    a.input(Seg { seq: 0, ack: 999, flags: RST | ACK, ..Seg::default() }, 0);
    assert_eq!(a.state(), State::SynSent);
    a.input(Seg { seq: 0, ack: 1001, flags: RST | ACK, ..Seg::default() }, 0);
    assert_eq!(a.state(), State::Closed);
    assert_eq!(a.take_error(), Some(Errno::ECONNREFUSED));
}

#[test]
fn bad_ack_in_syn_sent_gets_a_reset() {
    let mut a = Conn::new(&cfg(1000));
    a.connect(0);
    a.take_output();
    a.input(Seg { seq: 77, ack: 5, flags: SYN | ACK, ..Seg::default() }, 0);
    assert_eq!(a.state(), State::SynSent);
    let out = a.take_output();
    assert_eq!((out[0].seq, out[0].flags), (5, RST));
}

#[test]
fn reset_in_syn_received() {
    let mut b = Conn::accept(&cfg(5000), &Seg { seq: 7, flags: SYN, ..Seg::default() }, 0);
    b.take_output();
    b.input(Seg { seq: 8, flags: RST, ..Seg::default() }, 0);
    assert_eq!(b.state(), State::Closed);
    assert_eq!(b.error(), None);
}

#[test]
fn syn_again_in_syn_received_gets_the_syn_ack_again() {
    let syn = Seg { seq: 7, flags: SYN, ..Seg::default() };
    let mut b = Conn::accept(&cfg(5000), &syn, 0);
    b.take_output();
    b.input(syn, 0);
    let out = b.take_output();
    assert_eq!((out[0].seq, out[0].flags), (5000, SYN | ACK));
}

/// Brings `a` and `b` to the state of `a` given by `steps`, and sends an RST to `a`.
fn reset_after(steps: impl FnOnce(&mut Conn, &mut Conn)) -> (State, Option<Errno>) {
    let (mut a, mut b) = pair();
    steps(&mut a, &mut b);
    let before = a.state();
    a.input(Seg { seq: a.rcv_nxt, flags: RST, ..Seg::default() }, 0);
    assert_eq!(a.state(), State::Closed);
    (before, a.take_error())
}

#[test]
fn reset_in_each_synchronized_state() {
    assert_eq!(reset_after(|_, _| {}), (State::Established, Some(Errno::ECONNRESET)));
    let close_wait = |a: &mut Conn, b: &mut Conn| {
        b.close(0);
        deliver(b, a, 0);
    };
    assert_eq!(reset_after(close_wait), (State::CloseWait, Some(Errno::EPIPE)));
    let fin_wait1 = |a: &mut Conn, _: &mut Conn| a.close(0);
    assert_eq!(reset_after(fin_wait1), (State::FinWait1, Some(Errno::ECONNRESET)));
    let fin_wait2 = |a: &mut Conn, b: &mut Conn| {
        a.close(0);
        settle(a, b, 0);
    };
    assert_eq!(reset_after(fin_wait2), (State::FinWait2, Some(Errno::ECONNRESET)));
    let last_ack = |a: &mut Conn, b: &mut Conn| {
        b.close(0);
        deliver(b, a, 0);
        a.close(0);
    };
    assert_eq!(reset_after(last_ack), (State::LastAck, None));
    let closing = |a: &mut Conn, b: &mut Conn| {
        a.close(0);
        b.close(0);
        a.take_output();
        deliver(b, a, 0);
    };
    assert_eq!(reset_after(closing), (State::Closing, None));
    let time_wait = |a: &mut Conn, b: &mut Conn| {
        a.close(0);
        settle(a, b, 0);
        b.close(0);
        deliver(b, a, 0);
    };
    assert_eq!(reset_after(time_wait), (State::TimeWait, None));
}

#[test]
fn reset_in_the_window_gets_a_challenge_ack() {
    let (mut a, _b) = pair();
    let rcv_nxt = a.rcv_nxt;
    a.input(Seg { seq: rcv_nxt + 100, flags: RST, ..Seg::default() }, 0);
    assert_eq!(a.state(), State::Established);
    let out = a.take_output();
    assert_eq!(out.len(), 1);
    assert_eq!((out[0].flags, out[0].ack), (ACK, rcv_nxt));
    // An RST out of the window gets nothing.
    a.input(Seg { seq: rcv_nxt + 1_000_000, flags: RST, ..Seg::default() }, 0);
    assert_eq!(a.state(), State::Established);
    assert!(a.take_output().is_empty());
}

#[test]
fn syn_in_established_gets_a_challenge_ack() {
    let (mut a, _b) = pair();
    let rcv_nxt = a.rcv_nxt;
    a.input(Seg { seq: rcv_nxt, flags: SYN, ..Seg::default() }, 0);
    assert_eq!(a.state(), State::Established);
    let out = a.take_output();
    assert_eq!((out[0].flags, out[0].ack), (ACK, rcv_nxt));
}

#[test]
fn reply_to_a_segment_without_a_connection() {
    let r = reset_for(&Seg { seq: 10, ack: 99, flags: ACK, ..Seg::default() });
    assert_eq!(r, Some(Seg { seq: 99, flags: RST, ..Seg::default() }));
    let r = reset_for(&Seg { seq: 10, flags: SYN, ..Seg::default() });
    assert_eq!(r, Some(Seg { seq: 0, ack: 11, flags: RST | ACK, ..Seg::default() }));
    assert_eq!(reset_for(&Seg { flags: RST, ..Seg::default() }), None);
}

#[test]
fn retransmission_with_backoff() {
    let (mut a, mut b) = pair();
    a.nodelay = true;
    a.send(b"x", 0);
    deliver(&mut a, &mut b, 50);
    deliver(&mut b, &mut a, 50);
    // RTO = SRTT + max(4 RTTVAR, 200).
    let rto = a.rto();
    assert_eq!(rto, a.srtt() + (a.rttvar).max(RTO_MIN));
    let rto = u64::from(rto);
    a.send(b"lost", 1000);
    let lost = a.take_output();
    assert_eq!(a.next_timer(), Some(1000 + rto));
    a.tick(1000 + rto);
    let again = a.take_output();
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].seq, lost[0].seq);
    assert_eq!(again[0].data, b"lost");
    assert_eq!(a.cc().cwnd, 1);
    // The second timeout is twice as long.
    let t = 1000 + 3 * rto;
    assert_eq!(a.next_timer(), Some(t));
    a.tick(t);
    for s in a.take_output() {
        b.input(s, t + 10);
    }
    assert_eq!(read_all(&mut b, t + 10), b"xlost");
    deliver(&mut b, &mut a, t + 20);
    assert_eq!(a.next_timer(), None);
    // The ACK of new data ends the backoff, and the retransmitted segment gave no sample.
    assert_eq!(u64::from(a.rto()), rto);
}

#[test]
fn too_many_retransmissions_give_etimedout() {
    let (mut a, _b) = pair();
    a.nodelay = true;
    a.send(b"void", 0);
    let mut n = 0;
    while let Some(t) = a.next_timer() {
        a.tick(t);
        a.take_output();
        n += 1;
        assert!(n < 100);
    }
    assert_eq!(n, 16);
    assert_eq!(a.state(), State::Closed);
    assert_eq!(a.take_error(), Some(Errno::ETIMEDOUT));
}

#[test]
fn syn_retries() {
    let mut a = Conn::new(&cfg(1000));
    a.connect(0);
    a.take_output();
    let mut times = Vec::new();
    while let Some(t) = a.next_timer() {
        a.tick(t);
        let out = a.take_output();
        if !out.is_empty() {
            assert_eq!(out[0].flags, SYN);
        }
        times.push(t);
    }
    // 1, 2, 4, 8, 16, 32 seconds between the SYNs, then 64 seconds for the last one.
    assert_eq!(times, [1000, 3000, 7000, 15_000, 31_000, 63_000, 127_000]);
    assert_eq!(a.take_error(), Some(Errno::ETIMEDOUT));
}

#[test]
fn out_of_order_data() {
    let (mut a, mut b) = pair();
    a.nodelay = true;
    a.send(&[1; 1000], 0);
    a.send(&[2; 1000], 0);
    a.send(&[3; 500], 0);
    let segs = a.take_output();
    assert_eq!(segs.len(), 3);
    let start = segs[0].seq;
    b.input(segs[2].clone(), 0);
    let dup = b.take_output();
    assert_eq!(dup.len(), 1);
    assert_eq!(dup[0].ack, start);
    b.input(segs[1].clone(), 0);
    assert_eq!(b.take_output()[0].ack, start);
    assert_eq!(b.readable(), 0);
    b.input(segs[0].clone(), 0);
    let ack = b.take_output();
    assert_eq!(ack[0].ack, start + 2500);
    let got = read_all(&mut b, 0);
    assert_eq!(got.len(), 2500);
    assert!(got[..1000].iter().all(|&x| x == 1));
    assert!(got[1000..2000].iter().all(|&x| x == 2));
    assert!(got[2000..].iter().all(|&x| x == 3));
}

#[test]
fn fin_after_a_hole() {
    let (mut a, mut b) = pair();
    a.nodelay = true;
    a.send(b"abc", 0);
    a.close(0);
    let segs = a.take_output();
    assert!(segs[1].has(FIN));
    b.input(segs[1].clone(), 0);
    assert_eq!(b.state(), State::Established);
    b.input(segs[0].clone(), 0);
    assert_eq!(b.state(), State::CloseWait);
    assert_eq!(read_all(&mut b, 0), b"abc");
}

#[test]
fn duplicate_data_gets_an_ack() {
    let (mut a, mut b) = pair();
    a.nodelay = true;
    a.send(b"once", 0);
    let s = a.take_output().remove(0);
    b.input(s.clone(), 0);
    b.take_output();
    b.input(s, 0);
    let out = b.take_output();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].ack, b.rcv_nxt);
    assert_eq!(read_all(&mut b, 0), b"once");
}

#[test]
fn fast_retransmit_and_recovery() {
    let (mut a, mut b) = pair();
    a.nodelay = true;
    a.send(&[9; 6000], 0);
    let segs = a.take_output();
    assert_eq!(segs.len(), 6);
    let cwnd = a.cc().cwnd;
    for s in &segs[1..] {
        b.input(s.clone(), 1);
    }
    let dups = b.take_output();
    assert_eq!(dups.len(), 5);
    assert!(dups.iter().all(|d| d.ack == segs[0].seq));
    for (i, d) in dups.into_iter().enumerate() {
        a.input(d, 2);
        let out = a.take_output();
        if i == 2 {
            // The third duplicate ACK: the lost segment goes again.
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].seq, segs[0].seq);
            assert_eq!(a.cc().ssthresh, cwnd * 717 / 1024);
            assert_eq!(a.cc().cwnd, a.cc().ssthresh + 3);
        } else {
            assert!(out.iter().all(|s| s.seq != segs[0].seq));
        }
    }
    assert!(a.recovery);
    b.input(segs[0].clone(), 3);
    deliver(&mut b, &mut a, 4);
    assert!(!a.recovery);
    assert_eq!(a.cc().cwnd, a.cc().ssthresh);
    assert_eq!(read_all(&mut b, 5).len(), 6000);
}

#[test]
fn partial_ack_sends_the_next_hole() {
    let (mut a, mut b) = pair();
    a.nodelay = true;
    a.send(&[9; 6000], 0);
    let segs = a.take_output();
    // Segments 0 and 2 are lost.
    for i in [1, 3, 4, 5] {
        b.input(segs[i].clone(), 1);
    }
    deliver(&mut b, &mut a, 2);
    assert!(a.recovery);
    a.take_output();
    b.input(segs[0].clone(), 3);
    let partial = b.take_output();
    assert_eq!(partial[0].ack, segs[2].seq);
    a.input(partial[0].clone(), 4);
    let out = a.take_output();
    assert_eq!(out[0].seq, segs[2].seq);
    assert!(a.recovery);
    b.input(out[0].clone(), 5);
    deliver(&mut b, &mut a, 6);
    assert!(!a.recovery);
    assert_eq!(read_all(&mut b, 7).len(), 6000);
}

#[test]
fn zero_window_and_probes() {
    let (mut a, mut b) = pair();
    a.nodelay = true;
    // The window of `b` is 10000 bytes. It does not read.
    a.send(&[5; 15_000], 0);
    settle(&mut a, &mut b, 0);
    assert_eq!(b.readable(), 10_240);
    assert_eq!(a.snd_wnd, 0);
    assert_eq!(a.unsent(), 4760);
    let rto = u64::from(a.rto());
    let t = a.next_timer().expect("persist timer");
    assert_eq!(t, rto);
    a.tick(t);
    let probe = a.take_output();
    assert_eq!(probe.len(), 1);
    assert_eq!(probe[0].seq, a.snd_una - 1);
    assert!(probe[0].data.is_empty());
    b.input(probe[0].clone(), t);
    let reply = b.take_output();
    assert_eq!(reply.len(), 1);
    assert_eq!(reply[0].wnd, 0);
    a.input(reply[0].clone(), t);
    // The next probe waits twice as long.
    assert_eq!(a.next_timer(), Some(t + 2 * rto));
    // A read opens the window, and `b` tells it at once.
    assert_eq!(b.recv(6000, false, t).len(), 6000);
    let update = b.take_output();
    assert_eq!(update.len(), 1);
    assert!(update[0].wnd > 0);
    a.input(update[0].clone(), t);
    settle(&mut a, &mut b, t);
    assert_eq!(a.unsent(), 0);
    assert_eq!(b.readable(), 9000);
}

#[test]
fn data_into_a_zero_window_goes() {
    let (mut a, mut b) = pair();
    a.nodelay = true;
    a.send(&[5; 10_240], 0);
    settle(&mut a, &mut b, 0);
    let s = Seg { seq: b.rcv_nxt, ack: b.snd_nxt, flags: ACK, data: vec![1; 10], ..Seg::default() };
    b.input(s, 0);
    assert_eq!(b.readable(), 10_240);
    let out = b.take_output();
    assert_eq!(out.len(), 1);
    assert_eq!((out[0].ack, out[0].wnd), (b.rcv_nxt, 0));
}

#[test]
fn nagle_holds_small_segments() {
    let (mut a, mut b) = pair();
    a.send(b"one", 0);
    assert_eq!(a.take_output().len(), 1);
    a.send(b"two", 0);
    assert!(a.take_output().is_empty());
    // The ACK of the first segment lets the second go.
    a.input(Seg { seq: a.rcv_nxt, ack: a.snd_nxt, flags: ACK, wnd: 100, ..Seg::default() }, 1);
    let out = a.take_output();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].data, b"two");
    let _ = &mut b;
    // With TCP_NODELAY each write goes at once.
    a.nodelay = true;
    a.send(b"3", 2);
    a.send(b"4", 2);
    assert_eq!(a.take_output().len(), 2);
}

#[test]
fn cork_holds_partial_segments() {
    let (mut a, _b) = pair();
    a.nodelay = true;
    a.cork = true;
    a.send(&[0; 1500], 0);
    let out = a.take_output();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].data.len(), MSS as usize);
}

#[test]
fn delayed_ack() {
    let (mut a, mut b) = pair();
    a.nodelay = true;
    b.quick = 0;
    a.send(b"small", 0);
    deliver(&mut a, &mut b, 0);
    assert!(b.take_output().is_empty());
    assert_eq!(b.next_timer(), Some(DELACK));
    b.tick(DELACK);
    let ack = b.take_output();
    assert_eq!(ack.len(), 1);
    assert_eq!(ack[0].ack, a.snd_nxt);
    // Two full segments get an ACK at once.
    a.send(&[0; 2000], 100);
    deliver(&mut a, &mut b, 100);
    assert_eq!(b.take_output().len(), 1);
}

#[test]
fn keepalive_probes_then_reset() {
    let (mut a, _b) = pair();
    a.keepidle = 10;
    a.keepintvl = 2;
    a.keepcnt = 3;
    a.set_keepalive(true, 0);
    let mut probes = 0;
    while let Some(t) = a.next_timer() {
        a.tick(t);
        for s in a.take_output() {
            if s.has(RST) {
                assert_eq!(t, 16_000);
            } else {
                assert_eq!(s.seq, a.snd_una - 1);
                probes += 1;
            }
        }
    }
    assert_eq!(probes, 3);
    assert_eq!(a.take_error(), Some(Errno::ETIMEDOUT));
}

#[test]
fn abort_sends_a_reset() {
    let (mut a, mut b) = pair();
    a.abort();
    assert_eq!(a.state(), State::Closed);
    deliver(&mut a, &mut b, 0);
    assert_eq!(b.state(), State::Closed);
    assert_eq!(b.take_error(), Some(Errno::ECONNRESET));
}

#[test]
fn close_in_syn_received_sends_the_fin_after_the_handshake() {
    let mut a = Conn::new(&cfg(1000));
    a.connect(0);
    let syn = a.take_output().remove(0);
    let mut b = Conn::accept(&cfg(5000), &syn, 0);
    b.close(0);
    assert_eq!(b.state(), State::SynRcvd);
    settle(&mut a, &mut b, 0);
    assert_eq!(a.state(), State::CloseWait);
    assert_eq!(b.state(), State::FinWait2);
}

#[test]
fn ack_of_unsent_data_is_dropped() {
    let (mut a, _b) = pair();
    let s =
        Seg { seq: a.rcv_nxt, ack: a.snd_nxt + 50, flags: ACK, data: vec![1], ..Seg::default() };
    a.input(s, 0);
    assert_eq!(a.readable(), 0);
    assert_eq!(a.take_output().len(), 1);
}

#[test]
fn sequence_numbers_wrap() {
    let mut a = Conn::new(&cfg(u32::MAX - 10));
    a.connect(0);
    let syn = a.take_output().remove(0);
    let mut b = Conn::accept(&cfg(u32::MAX - 3000), &syn, 0);
    settle(&mut a, &mut b, 0);
    a.nodelay = true;
    b.nodelay = true;
    a.send(&[1; 5000], 0);
    b.send(&[2; 5000], 0);
    settle(&mut a, &mut b, 0);
    assert_eq!(read_all(&mut b, 0), vec![1; 5000]);
    assert_eq!(read_all(&mut a, 0), vec![2; 5000]);
}

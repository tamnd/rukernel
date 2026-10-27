//! The congestion control: Reno of RFC 5681 and CUBIC of RFC 9438, as net/ipv4/tcp_cong.c and
//! net/ipv4/tcp_cubic.c of Linux.
//!
//! The window is in segments, as `snd_cwnd` of Linux, and the math is in integers with the
//! constants of Linux. The time is in milliseconds. CUBIC has no HyStart yet, so its slow start
//! ends only at a loss or at `ssthresh`.

/// The `ssthresh` of a new connection, `TCP_INFINITE_SSTHRESH` of Linux.
pub const INFINITE_SSTHRESH: u32 = 0x7fff_ffff;
/// The window of a new connection, `TCP_INIT_CWND` of Linux and RFC 6928.
pub const INIT_CWND: u32 = 10;
/// The largest window, in place of `snd_cwnd_clamp`.
const CWND_CLAMP: u32 = 1 << 20;

/// The algorithm of the congestion control, the option `TCP_CONGESTION`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algo {
    /// Reno: one segment more for each round trip.
    Reno,
    /// CUBIC, the default of Linux.
    Cubic,
}

impl Algo {
    /// The name of the algorithm, as `TCP_CONGESTION` gives it.
    pub fn name(self) -> &'static [u8] {
        match self {
            Self::Reno => b"reno",
            Self::Cubic => b"cubic",
        }
    }

    /// The algorithm with the name `name`. The name ends at the first zero byte.
    pub fn by_name(name: &[u8]) -> Option<Self> {
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        match &name[..end] {
            b"reno" => Some(Self::Reno),
            b"cubic" => Some(Self::Cubic),
            _ => None,
        }
    }
}

/// The scale of `BETA`, `BICTCP_BETA_SCALE`.
const BETA_SCALE: u32 = 1024;
/// The decrease of the window at a loss, 717/1024 or about 0.7.
const BETA: u32 = 717;
/// The scale of the time of the cubic function: 2^10 units each second, `BICTCP_HZ`.
const CUBIC_HZ: u32 = 10;
/// `bic_scale * 10`, `cube_rtt_scale` of Linux. With the scales it gives C = 0.4.
const CUBE_RTT_SCALE: u64 = 410;
/// `cube_factor` of Linux: `2^(10 + 3 * BICTCP_HZ) / cube_rtt_scale`.
const CUBE_FACTOR: u64 = (1 << (10 + 3 * CUBIC_HZ)) / CUBE_RTT_SCALE;
/// `beta_scale` of Linux, for the Reno-friendly region: `8 * (1024 + 717) / 3 / (1024 - 717)`.
const FRIENDLY_SCALE: u32 = 8 * (BETA_SCALE + BETA) / 3 / (BETA_SCALE - BETA);

/// The state of CUBIC, `struct bictcp` of Linux.
#[derive(Clone, Copy, Debug, Default)]
struct Cubic {
    /// The window grows by one segment after `cnt` acknowledged segments.
    cnt: u32,
    /// The window before the last loss, W_max.
    last_max_cwnd: u32,
    /// The window at the last update.
    last_cwnd: u32,
    /// The time of the last update.
    last_time: u64,
    /// The origin of the cubic function.
    origin: u32,
    /// The time from the start of the epoch to the origin, K, in units of 1/1024 second.
    k: u32,
    /// The smallest round trip time, in milliseconds.
    delay_min: u32,
    /// The start of the epoch, or `None` before the first update after a loss.
    epoch_start: Option<u64>,
    /// The acknowledged segments in the epoch, for the Reno-friendly window.
    ack_cnt: u32,
    /// The window that Reno would have, W_est.
    tcp_cwnd: u32,
}

/// The integer cube root of `a`.
fn cbrt(a: u64) -> u32 {
    let (mut lo, mut hi) = (0u64, 2_642_245u64);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if mid * mid * mid <= a {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo as u32
}

impl Cubic {
    /// Computes `cnt` from the window `cwnd`, as `bictcp_update` of Linux.
    fn update(&mut self, cwnd: u32, acked: u32, now: u64) {
        self.ack_cnt += acked;
        if self.last_cwnd == cwnd && now.saturating_sub(self.last_time) <= 1000 / 32 {
            return;
        }
        // The cubic part changes at most one time for each moment.
        if self.epoch_start.is_none() || now != self.last_time {
            self.last_cwnd = cwnd;
            self.last_time = now;
            let start = match self.epoch_start {
                Some(s) => s,
                None => {
                    self.ack_cnt = acked;
                    self.tcp_cwnd = cwnd;
                    if self.last_max_cwnd <= cwnd {
                        self.k = 0;
                        self.origin = cwnd;
                    } else {
                        self.k = cbrt(CUBE_FACTOR * u64::from(self.last_max_cwnd - cwnd));
                        self.origin = self.last_max_cwnd;
                    }
                    self.epoch_start = Some(now);
                    now
                }
            };
            // The time since the start of the epoch, one round trip ahead, in 1/1024 second.
            let t = ((now - start + u64::from(self.delay_min)) << CUBIC_HZ) / 1000;
            let k = u64::from(self.k);
            let offs = t.abs_diff(k);
            let delta = (CUBE_RTT_SCALE * offs * offs * offs) >> (10 + 3 * CUBIC_HZ);
            let delta = u32::try_from(delta).unwrap_or(u32::MAX);
            let target = if t < k {
                self.origin.saturating_sub(delta)
            } else {
                self.origin.saturating_add(delta)
            };
            self.cnt = if target > cwnd { cwnd / (target - cwnd) } else { 100 * cwnd };
            // The first epoch, without a loss, grows at least as fast as slow start would.
            if self.last_max_cwnd == 0 && self.cnt > 20 {
                self.cnt = 20;
            }
        }
        // The Reno-friendly region: the window grows at least as fast as Reno with the same
        // decrease would make it grow.
        let delta = (cwnd * FRIENDLY_SCALE) >> 3;
        if delta > 0 {
            while self.ack_cnt > delta {
                self.ack_cnt -= delta;
                self.tcp_cwnd += 1;
            }
        }
        if self.tcp_cwnd > cwnd {
            let max_cnt = cwnd / (self.tcp_cwnd - cwnd);
            self.cnt = self.cnt.min(max_cnt);
        }
        self.cnt = self.cnt.max(2);
    }

    /// The `ssthresh` after a loss, as `cubic_recalc_ssthresh` of Linux, with fast convergence.
    fn ssthresh(&mut self, cwnd: u32) -> u32 {
        self.epoch_start = None;
        self.last_max_cwnd = if cwnd < self.last_max_cwnd {
            (cwnd * (BETA_SCALE + BETA)) / (2 * BETA_SCALE)
        } else {
            cwnd
        };
        ((cwnd * BETA) / BETA_SCALE).max(2)
    }
}

/// The congestion control of one connection.
#[derive(Clone, Debug)]
pub struct Cc {
    algo: Algo,
    /// The congestion window in segments.
    pub cwnd: u32,
    /// The slow start threshold in segments.
    pub ssthresh: u32,
    /// The acknowledged segments since the last increase in congestion avoidance.
    cwnd_cnt: u32,
    cubic: Cubic,
}

impl Cc {
    /// The state of a new connection.
    pub fn new(algo: Algo) -> Self {
        Self {
            algo,
            cwnd: INIT_CWND,
            ssthresh: INFINITE_SSTHRESH,
            cwnd_cnt: 0,
            cubic: Cubic::default(),
        }
    }

    /// The algorithm.
    pub fn algo(&self) -> Algo {
        self.algo
    }

    /// Changes the algorithm, as `tcp_set_congestion_control`. The window stays.
    pub fn set_algo(&mut self, algo: Algo) {
        self.algo = algo;
        self.cubic = Cubic::default();
    }

    /// Tells if the window is below `ssthresh`.
    pub fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// Takes a sample of the round trip time, as `cubic_acked`.
    pub fn rtt_sample(&mut self, rtt_ms: u32) {
        let rtt = rtt_ms.max(1);
        if self.cubic.delay_min == 0 || rtt < self.cubic.delay_min {
            self.cubic.delay_min = rtt;
        }
    }

    /// Slow start, as `tcp_slow_start`: one segment more for each acknowledged segment, up to
    /// `ssthresh`. Gives the acknowledged segments that are left.
    fn slow_start(&mut self, acked: u32) -> u32 {
        let cwnd = self.cwnd.saturating_add(acked).min(self.ssthresh);
        let left = acked - (cwnd - self.cwnd);
        self.cwnd = cwnd.min(CWND_CLAMP);
        left
    }

    /// The additive increase, as `tcp_cong_avoid_ai`: one segment more after `w` acknowledged
    /// segments.
    fn avoid_ai(&mut self, w: u32, acked: u32) {
        let w = w.max(1);
        if self.cwnd_cnt >= w {
            self.cwnd_cnt = 0;
            self.cwnd += 1;
        }
        self.cwnd_cnt += acked;
        if self.cwnd_cnt >= w {
            let delta = self.cwnd_cnt / w;
            self.cwnd_cnt -= delta * w;
            self.cwnd += delta;
        }
        self.cwnd = self.cwnd.min(CWND_CLAMP);
    }

    /// Grows the window for `acked` acknowledged segments at the time `now`, as `cong_avoid`.
    /// The caller calls this only if the window limits the sender, and not in a recovery.
    pub fn on_ack(&mut self, acked: u32, now: u64) {
        let mut acked = acked;
        if acked == 0 {
            return;
        }
        if self.in_slow_start() {
            acked = self.slow_start(acked);
            if acked == 0 {
                return;
            }
        }
        match self.algo {
            Algo::Reno => self.avoid_ai(self.cwnd, acked),
            Algo::Cubic => {
                self.cubic.update(self.cwnd, acked, now);
                self.avoid_ai(self.cubic.cnt, acked);
            }
        }
    }

    /// Computes the new `ssthresh` at a loss, as the `ssthresh` operation, and sets it.
    pub fn on_loss(&mut self) -> u32 {
        self.ssthresh = match self.algo {
            Algo::Reno => (self.cwnd >> 1).max(2),
            Algo::Cubic => self.cubic.ssthresh(self.cwnd),
        };
        self.cwnd_cnt = 0;
        self.ssthresh
    }

    /// Starts again at one segment after a retransmission timeout, as `tcp_enter_loss`. If
    /// `first` is false, the timeout is a repeated one and `ssthresh` stays.
    pub fn on_rto(&mut self, first: bool) {
        if first {
            self.on_loss();
        }
        self.cwnd = 1;
        self.cwnd_cnt = 0;
        // CUBIC starts again from nothing in the state `TCP_CA_Loss`, as `cubic_state`.
        if self.algo == Algo::Cubic {
            self.cubic = Cubic { delay_min: self.cubic.delay_min, ..Cubic::default() };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Runs `rounds` round trips of `rtt` milliseconds from the time `now`. Each round trip
    /// acknowledges the full window, one segment for each ACK. Gives the window at the end of
    /// each round trip.
    fn run(cc: &mut Cc, now: &mut u64, rtt: u64, rounds: usize) -> Vec<u32> {
        let mut out = Vec::new();
        for _ in 0..rounds {
            let n = cc.cwnd;
            for i in 0..n {
                cc.on_ack(1, *now + rtt * u64::from(i) / u64::from(n));
            }
            *now += rtt;
            out.push(cc.cwnd);
        }
        out
    }

    #[test]
    fn cube_root() {
        assert_eq!(cbrt(0), 0);
        assert_eq!(cbrt(1), 1);
        assert_eq!(cbrt(26), 2);
        assert_eq!(cbrt(27), 3);
        assert_eq!(cbrt(1 << 63), 1 << 21);
        assert_eq!(cbrt(u64::MAX), 2_642_245);
    }

    #[test]
    fn names() {
        assert_eq!(Algo::by_name(b"cubic\0\0"), Some(Algo::Cubic));
        assert_eq!(Algo::by_name(b"reno"), Some(Algo::Reno));
        assert_eq!(Algo::by_name(b"bbr"), None);
        assert_eq!(Algo::Cubic.name(), b"cubic");
    }

    #[test]
    fn slow_start_doubles_each_round_trip() {
        for algo in [Algo::Reno, Algo::Cubic] {
            let mut cc = Cc::new(algo);
            let mut now = 0;
            assert_eq!(run(&mut cc, &mut now, 100, 3), [20, 40, 80]);
        }
    }

    #[test]
    fn slow_start_stops_at_ssthresh() {
        let mut cc = Cc::new(Algo::Reno);
        cc.ssthresh = 15;
        cc.on_ack(10, 0);
        assert_eq!(cc.cwnd, 15);
        assert!(!cc.in_slow_start());
    }

    #[test]
    fn reno_adds_one_segment_each_round_trip() {
        let mut cc = Cc::new(Algo::Reno);
        cc.cwnd = 20;
        cc.ssthresh = 20;
        let mut now = 0;
        assert_eq!(run(&mut cc, &mut now, 100, 4), [21, 22, 23, 24]);
    }

    #[test]
    fn reno_halves_at_a_loss() {
        let mut cc = Cc::new(Algo::Reno);
        cc.cwnd = 40;
        assert_eq!(cc.on_loss(), 20);
        cc.cwnd = 3;
        assert_eq!(cc.on_loss(), 2);
        cc.on_rto(true);
        assert_eq!((cc.cwnd, cc.ssthresh), (1, 2));
    }

    #[test]
    fn cubic_decreases_to_seven_tenths() {
        let mut cc = Cc::new(Algo::Cubic);
        cc.cwnd = 100;
        assert_eq!(cc.on_loss(), 70);
        assert_eq!(cc.cubic.last_max_cwnd, 100);
        // A second loss below W_max releases bandwidth: fast convergence.
        cc.cwnd = 90;
        assert_eq!(cc.on_loss(), 63);
        assert_eq!(cc.cubic.last_max_cwnd, 90 * 1741 / 2048);
    }

    #[test]
    fn cubic_window_is_concave_then_convex() {
        let mut cc = Cc::new(Algo::Cubic);
        cc.rtt_sample(100);
        cc.cwnd = 100;
        cc.on_loss();
        cc.cwnd = cc.ssthresh;
        let mut now = 10_000;
        let w = run(&mut cc, &mut now, 100, 80);
        // K is the cube root of (100 - 70) / 0.4, about 4.2 seconds, or 42 round trips. The
        // curve has W_max there.
        let k = cbrt(CUBE_FACTOR * 30);
        assert!((4250..=4350).contains(&k), "K = {k}");
        assert!(w[0] > 70 && w[0] < 78, "{w:?}");
        assert!((95..=102).contains(&w[40]), "{w:?}");
        // Concave: the growth slows near W_max.
        assert!(w[10] - w[0] > w[40] - w[30], "{w:?}");
        // Convex: the growth is faster again after W_max.
        assert!(w[79] - w[69] > w[50] - w[40], "{w:?}");
        assert!(w[79] > 110, "{w:?}");
        // The window never goes down without a loss.
        assert!(w.windows(2).all(|p| p[0] <= p[1]), "{w:?}");
    }

    #[test]
    fn cubic_follows_reno_on_a_short_path() {
        // On a path with a short round trip, the cubic curve grows slowly in time, and the
        // window follows the Reno-friendly line: about 0.53 segments each round trip.
        let mut cc = Cc::new(Algo::Cubic);
        cc.rtt_sample(1);
        cc.cwnd = 1000;
        cc.on_loss();
        cc.cwnd = cc.ssthresh;
        let start = cc.cwnd;
        let mut now = 0;
        let w = run(&mut cc, &mut now, 1, 100);
        let grown = w[99] - start;
        assert!((40..=70).contains(&grown), "grew {grown}");
    }

    #[test]
    fn cubic_starts_again_after_a_timeout() {
        let mut cc = Cc::new(Algo::Cubic);
        cc.cwnd = 50;
        cc.on_rto(true);
        assert_eq!((cc.cwnd, cc.ssthresh), (1, 35));
        cc.cwnd = 4;
        cc.on_rto(false);
        assert_eq!((cc.cwnd, cc.ssthresh), (1, 35));
    }
}

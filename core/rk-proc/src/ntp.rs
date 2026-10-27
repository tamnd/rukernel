//! The state of the NTP clock model, for `adjtimex` and `clock_adjtime`.
//!
//! This is the model of kernel/time/ntp.c of Linux. The kernel keeps the values that a time
//! daemon sets, and gives them back. The values do not change the speed of the clock yet, and
//! the phase offset does not decay, so a read gives the last value that a call set. The code is
//! pure, so the tests on the host examine it.

use rk_abi::Errno;
use rk_abi::native::timex::{
    ADJ_ESTERROR, ADJ_FREQUENCY, ADJ_MAXERROR, ADJ_MICRO, ADJ_NANO, ADJ_OFFSET, ADJ_SETOFFSET,
    ADJ_STATUS, ADJ_TAI, ADJ_TICK, ADJ_TIMECONST, STA_CLOCKERR, STA_NANO, STA_PLL, STA_PPSERROR,
    STA_PPSFREQ, STA_PPSJITTER, STA_PPSSIGNAL, STA_PPSTIME, STA_PPSWANDER, STA_RONLY, STA_UNSYNC,
    TIME_ERROR, TIME_OK,
};
use rk_abi::native::types::KernelTimex;

/// The mode bit of the old `adjtime` call. It is in include/linux/timex.h of the kernel only.
const ADJ_ADJTIME: u32 = 0x8000;
/// The mode bit that makes `ADJ_OFFSET_SINGLESHOT` only read the old value.
const ADJ_OFFSET_READONLY: u32 = 0x2000;

/// The ticks of the user each second, `USER_HZ`.
const USER_HZ: i64 = 100;
const NSEC_PER_USEC: i64 = 1000;
const USEC_PER_SEC: i64 = 1_000_000;
const NSEC_PER_SEC: i64 = 1_000_000_000;
/// The largest phase offset in nanoseconds, `MAXPHASE`.
const MAXPHASE: i64 = 500_000_000;
/// The largest frequency offset in nanoseconds each second, `MAXFREQ`.
const MAXFREQ: i64 = 500_000;
/// The largest time constant of the PLL, `MAXTC`.
const MAXTC: i64 = 10;
/// The largest offset of TAI to UTC in seconds, `MAX_TAI_OFFSET`.
const MAX_TAI_OFFSET: i64 = 100_000;
const NTP_SCALE_SHIFT: u32 = 32;
const SHIFT_USEC: u32 = 16;
/// The scale of the frequency of `struct timex`, parts per million times 2^16, to the internal
/// frequency, nanoseconds times 2^32.
const PPM_SCALE: i64 = NSEC_PER_USEC << (NTP_SCALE_SHIFT - SHIFT_USEC);
const PPM_SCALE_INV_SHIFT: u32 = 19;
const PPM_SCALE_INV: i64 = (1 << (PPM_SCALE_INV_SHIFT + NTP_SCALE_SHIFT)) / PPM_SCALE + 1;
const MAXFREQ_SCALED: i64 = MAXFREQ << NTP_SCALE_SHIFT;
/// The largest error estimate in microseconds, `NTP_PHASE_LIMIT`.
pub const NTP_PHASE_LIMIT: i64 = (MAXPHASE / NSEC_PER_USEC) << 5;

/// The state of the NTP clock model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ntp {
    /// The clock state, `TIME_OK` or a leap second state.
    state: i32,
    /// The status bits, `STA_*`.
    status: i32,
    /// The phase offset in nanoseconds.
    offset: i64,
    /// The frequency offset, in nanoseconds times 2^32 each second.
    freq: i64,
    /// The largest error in microseconds.
    maxerror: i64,
    /// The estimated error in microseconds.
    esterror: i64,
    /// The time constant of the PLL.
    constant: i64,
    /// The microseconds of one tick of the user.
    tick: i64,
    /// The offset of TAI to UTC in seconds.
    tai: i32,
    /// The rest of the old `adjtime` call, in microseconds.
    adjust: i64,
}

impl Default for Ntp {
    fn default() -> Self {
        Self::new()
    }
}

/// Divides a signed value by `2^s`, with the rounding of `shift_right` of Linux.
fn shift_right(x: i64, s: u32) -> i64 {
    if x < 0 { -((-x) >> s) } else { x >> s }
}

/// Tells if the status bits show that the clock is not synchronized, as `is_error_status` of
/// Linux does.
fn is_error_status(status: u32) -> bool {
    status & (STA_UNSYNC | STA_CLOCKERR) != 0
        || (status & (STA_PPSFREQ | STA_PPSTIME) != 0 && status & STA_PPSSIGNAL == 0)
        || status & (STA_PPSTIME | STA_PPSJITTER) == STA_PPSTIME | STA_PPSJITTER
        || (status & STA_PPSFREQ != 0 && status & (STA_PPSWANDER | STA_PPSERROR) != 0)
}

/// Checks the request `tx` before a change, as `timekeeping_validate_timex` of Linux does.
/// `capable` tells if the caller has `CAP_SYS_TIME`.
pub fn validate(tx: &KernelTimex, capable: bool) -> Result<(), Errno> {
    let modes = tx.modes;
    if modes & ADJ_ADJTIME != 0 {
        // In the kernel, `ADJ_OFFSET_SINGLESHOT` is the bit 0x0001, so `ADJ_ADJTIME` alone,
        // with no offset, is not valid.
        if modes & ADJ_OFFSET == 0 {
            return Err(Errno::EINVAL);
        }
        if modes & ADJ_OFFSET_READONLY == 0 && !capable {
            return Err(Errno::EPERM);
        }
    } else {
        if modes != 0 && !capable {
            return Err(Errno::EPERM);
        }
        // A tick that is more than 10 percent wrong is not a real clock.
        if modes & ADJ_TICK != 0 && !(900_000 / USER_HZ..=1_100_000 / USER_HZ).contains(&tx.tick) {
            return Err(Errno::EINVAL);
        }
    }
    if modes & ADJ_SETOFFSET != 0 {
        if !capable {
            return Err(Errno::EPERM);
        }
        let limit = if modes & ADJ_NANO != 0 { NSEC_PER_SEC } else { USEC_PER_SEC };
        if !(0..limit).contains(&tx.time.tv_usec) {
            return Err(Errno::EINVAL);
        }
    }
    if modes & ADJ_FREQUENCY != 0
        && !(i64::MIN / PPM_SCALE..=i64::MAX / PPM_SCALE).contains(&tx.freq)
    {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// The time step of `ADJ_SETOFFSET` in nanoseconds, or `None` if the request has no step.
pub fn set_offset_ns(tx: &KernelTimex) -> Option<i64> {
    if tx.modes & ADJ_SETOFFSET == 0 {
        return None;
    }
    let nsec = if tx.modes & ADJ_NANO != 0 { tx.time.tv_usec } else { tx.time.tv_usec * 1000 };
    Some(tx.time.tv_sec.saturating_mul(NSEC_PER_SEC).saturating_add(nsec))
}

impl Ntp {
    /// The state at boot: the clock is not synchronized.
    pub const fn new() -> Self {
        Self {
            state: TIME_OK as i32,
            status: STA_UNSYNC as i32,
            offset: 0,
            freq: 0,
            maxerror: NTP_PHASE_LIMIT,
            esterror: NTP_PHASE_LIMIT,
            constant: 2,
            tick: USEC_PER_SEC / USER_HZ,
            tai: 0,
            adjust: 0,
        }
    }

    /// Does the changes of the request `tx`, which `validate` accepted, and writes the state back
    /// to `tx`, as `__do_adjtimex` of Linux does. `now_ns` is the real time in nanoseconds after
    /// a time step. Gives the clock state, or `TIME_ERROR` if the clock is not synchronized.
    pub fn adjtimex(&mut self, tx: &mut KernelTimex, now_ns: u64) -> i32 {
        if tx.modes & ADJ_ADJTIME != 0 {
            let old = self.adjust;
            if tx.modes & ADJ_OFFSET_READONLY == 0 {
                self.adjust = tx.offset;
            }
            tx.offset = old;
        } else {
            if tx.modes != 0 {
                self.change(tx);
            }
            tx.offset = self.offset;
            if self.status as u32 & STA_NANO == 0 {
                // Linux divides the low 32 bits without the sign.
                tx.offset = i64::from(tx.offset as u32) / NSEC_PER_USEC;
            }
        }
        let result =
            if is_error_status(self.status as u32) { TIME_ERROR as i32 } else { self.state };
        tx.freq = shift_right((self.freq >> PPM_SCALE_INV_SHIFT) * PPM_SCALE_INV, NTP_SCALE_SHIFT);
        tx.maxerror = self.maxerror;
        tx.esterror = self.esterror;
        tx.status = self.status;
        tx.constant = self.constant;
        tx.precision = 1;
        tx.tolerance = MAXFREQ_SCALED / PPM_SCALE;
        tx.tick = self.tick;
        tx.tai = self.tai;
        tx.ppsfreq = 0;
        tx.jitter = 0;
        tx.shift = 0;
        tx.stabil = 0;
        tx.jitcnt = 0;
        tx.calcnt = 0;
        tx.errcnt = 0;
        tx.stbcnt = 0;
        let now = now_ns as i64;
        tx.time.tv_sec = now / NSEC_PER_SEC;
        tx.time.tv_usec = now % NSEC_PER_SEC;
        if self.status as u32 & STA_NANO == 0 {
            tx.time.tv_usec /= NSEC_PER_USEC;
        }
        result
    }

    /// Does the mode bits of `tx`, as `process_adjtimex_modes` of Linux does.
    fn change(&mut self, tx: &KernelTimex) {
        let modes = tx.modes;
        if modes & ADJ_STATUS != 0 {
            // A clock that stops the PLL is not synchronized.
            if self.status as u32 & STA_PLL != 0 && tx.status as u32 & STA_PLL == 0 {
                self.state = TIME_OK as i32;
                self.status = STA_UNSYNC as i32;
            }
            self.status &= STA_RONLY as i32;
            self.status |= tx.status & !(STA_RONLY as i32);
        }
        if modes & ADJ_NANO != 0 {
            self.status |= STA_NANO as i32;
        }
        if modes & ADJ_MICRO != 0 {
            self.status &= !(STA_NANO as i32);
        }
        if modes & ADJ_FREQUENCY != 0 {
            self.freq = (tx.freq * PPM_SCALE).clamp(-MAXFREQ_SCALED, MAXFREQ_SCALED);
        }
        if modes & ADJ_MAXERROR != 0 {
            self.maxerror = tx.maxerror.clamp(0, NTP_PHASE_LIMIT);
        }
        if modes & ADJ_ESTERROR != 0 {
            self.esterror = tx.esterror.clamp(0, NTP_PHASE_LIMIT);
        }
        if modes & ADJ_TIMECONST != 0 {
            self.constant = tx.constant.clamp(0, MAXTC);
            if self.status as u32 & STA_NANO == 0 {
                self.constant += 4;
            }
            self.constant = self.constant.clamp(0, MAXTC);
        }
        if modes & ADJ_TAI != 0 && (0..=MAX_TAI_OFFSET).contains(&tx.constant) {
            self.tai = tx.constant as i32;
        }
        // The kernel keeps a phase offset only while the PLL is on.
        if modes & ADJ_OFFSET != 0 && self.status as u32 & STA_PLL != 0 {
            self.offset = if self.status as u32 & STA_NANO != 0 {
                tx.offset.clamp(-MAXPHASE, MAXPHASE)
            } else {
                tx.offset.clamp(-MAXPHASE / NSEC_PER_USEC, MAXPHASE / NSEC_PER_USEC) * NSEC_PER_USEC
            };
        }
        if modes & ADJ_TICK != 0 {
            self.tick = tx.tick;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rk_abi::native::timex::{ADJ_OFFSET_SINGLESHOT, ADJ_OFFSET_SS_READ};
    use zerocopy::FromZeros;

    fn timex(modes: u32) -> KernelTimex {
        let mut tx = KernelTimex::new_zeroed();
        tx.modes = modes;
        tx
    }

    #[test]
    fn a_read_gives_the_boot_state() {
        let mut ntp = Ntp::new();
        let mut tx = timex(0);
        assert_eq!(validate(&tx, false), Ok(()));
        assert_eq!(ntp.adjtimex(&mut tx, 1_500_000_000), TIME_ERROR as i32);
        assert_eq!(tx.status, STA_UNSYNC as i32);
        assert_eq!(tx.maxerror, NTP_PHASE_LIMIT);
        assert_eq!(tx.constant, 2);
        assert_eq!(tx.tick, 10_000);
        assert_eq!(tx.tolerance, 32_768_000);
        assert_eq!(tx.precision, 1);
        assert_eq!((tx.time.tv_sec, tx.time.tv_usec), (1, 500_000));
    }

    #[test]
    fn a_change_needs_the_capability() {
        assert_eq!(validate(&timex(ADJ_MAXERROR), false), Err(Errno::EPERM));
        assert_eq!(validate(&timex(ADJ_OFFSET_SS_READ), false), Ok(()));
        assert_eq!(validate(&timex(ADJ_OFFSET_SINGLESHOT), false), Err(Errno::EPERM));
        assert_eq!(validate(&timex(ADJ_OFFSET_SINGLESHOT), true), Ok(()));
        assert_eq!(validate(&timex(ADJ_ADJTIME), true), Err(Errno::EINVAL));
    }

    #[test]
    fn the_tick_has_limits() {
        let mut tx = timex(ADJ_TICK);
        tx.tick = 8999;
        assert_eq!(validate(&tx, true), Err(Errno::EINVAL));
        tx.tick = 11001;
        assert_eq!(validate(&tx, true), Err(Errno::EINVAL));
        tx.tick = 11000;
        assert_eq!(validate(&tx, true), Ok(()));
    }

    #[test]
    fn a_set_value_comes_back() {
        let mut ntp = Ntp::new();
        let mut tx = timex(ADJ_FREQUENCY | ADJ_MAXERROR | ADJ_ESTERROR | ADJ_TIMECONST | ADJ_TICK);
        tx.freq = 100;
        tx.maxerror = 200;
        tx.esterror = 300;
        tx.constant = 3;
        tx.tick = 10_100;
        ntp.adjtimex(&mut tx, 0);
        let mut get = timex(0);
        ntp.adjtimex(&mut get, 0);
        assert_eq!((get.freq, get.maxerror, get.esterror), (100, 200, 300));
        assert_eq!((get.constant, get.tick), (7, 10_100));
        assert_eq!(get.freq, tx.freq);
    }

    #[test]
    fn the_frequency_has_a_limit() {
        let mut ntp = Ntp::new();
        let mut tx = timex(ADJ_FREQUENCY);
        tx.freq = 1 << 30;
        ntp.adjtimex(&mut tx, 0);
        assert_eq!(tx.freq, 500 << 16);
        tx.freq = i64::MAX;
        assert_eq!(validate(&tx, true), Err(Errno::EINVAL));
    }

    #[test]
    fn the_offset_needs_the_pll() {
        let mut ntp = Ntp::new();
        let mut tx = timex(ADJ_OFFSET);
        tx.offset = 1000;
        ntp.adjtimex(&mut tx, 0);
        assert_eq!(tx.offset, 0);
        let mut tx = timex(ADJ_STATUS);
        tx.status = STA_PLL as i32;
        assert_eq!(ntp.adjtimex(&mut tx, 0), TIME_OK as i32);
        let mut tx = timex(ADJ_OFFSET);
        tx.offset = 1000;
        ntp.adjtimex(&mut tx, 0);
        assert_eq!(tx.offset, 1000);
    }

    #[test]
    fn the_single_shot_gives_the_old_value() {
        let mut ntp = Ntp::new();
        let mut tx = timex(ADJ_OFFSET_SINGLESHOT);
        tx.offset = 42;
        ntp.adjtimex(&mut tx, 0);
        assert_eq!(tx.offset, 0);
        let mut tx = timex(ADJ_OFFSET_SS_READ);
        ntp.adjtimex(&mut tx, 0);
        assert_eq!(tx.offset, 42);
    }

    #[test]
    fn a_time_step_is_checked() {
        let mut tx = timex(ADJ_SETOFFSET);
        tx.time.tv_sec = -1;
        tx.time.tv_usec = 1_000_000;
        assert_eq!(validate(&tx, true), Err(Errno::EINVAL));
        tx.time.tv_usec = 500_000;
        assert_eq!(validate(&tx, true), Ok(()));
        assert_eq!(set_offset_ns(&tx), Some(-500_000_000));
        assert_eq!(validate(&tx, false), Err(Errno::EPERM));
    }
}

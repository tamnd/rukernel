// rk-abigen generated this file from Linux 7.3, from <linux/timex.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The modes, the status bits and the clock states of `adjtimex` and `clock_adjtime`.

/// Clock synchronized, no leap second.
pub const TIME_OK: u32 = 0;
/// Time offset.
pub const ADJ_OFFSET: u32 = 1;
/// Enable PLL updates (rw).
pub const STA_PLL: u32 = 1;
/// Insert leap second.
pub const TIME_INS: u32 = 1;
/// Frequency offset.
pub const ADJ_FREQUENCY: u32 = 2;
/// Enable PPS freq discipline (rw).
pub const STA_PPSFREQ: u32 = 2;
/// Delete leap second.
pub const TIME_DEL: u32 = 2;
/// Leap second in progress.
pub const TIME_OOP: u32 = 3;
/// Maximum time error.
pub const ADJ_MAXERROR: u32 = 4;
/// Enable PPS time discipline (rw).
pub const STA_PPSTIME: u32 = 4;
/// Leap second has occurred.
pub const TIME_WAIT: u32 = 4;
/// Bw compat.
pub const TIME_BAD: u32 = 5;
/// Clock not synchronized.
pub const TIME_ERROR: u32 = 5;
/// Estimated time error.
pub const ADJ_ESTERROR: u32 = 8;
/// Select frequency-lock mode (rw).
pub const STA_FLL: u32 = 8;
/// Clock status.
pub const ADJ_STATUS: u32 = 16;
/// Insert leap (rw).
pub const STA_INS: u32 = 16;
/// Pll time constant.
pub const ADJ_TIMECONST: u32 = 32;
/// Delete leap (rw).
pub const STA_DEL: u32 = 32;
/// Clock unsynchronized (rw).
pub const STA_UNSYNC: u32 = 64;
/// Set TAI offset.
pub const ADJ_TAI: u32 = 128;
/// Hold frequency (rw).
pub const STA_FREQHOLD: u32 = 128;
/// Add 'time' to current time.
pub const ADJ_SETOFFSET: u32 = 0x100;
/// PPS signal present (ro).
pub const STA_PPSSIGNAL: u32 = 0x100;
/// PPS signal jitter exceeded (ro).
pub const STA_PPSJITTER: u32 = 0x200;
/// PPS signal wander exceeded (ro).
pub const STA_PPSWANDER: u32 = 0x400;
/// PPS signal calibration error (ro).
pub const STA_PPSERROR: u32 = 0x800;
/// Select microsecond resolution.
pub const ADJ_MICRO: u32 = 0x1000;
/// Clock hardware fault (ro).
pub const STA_CLOCKERR: u32 = 0x1000;
/// Select nanosecond resolution.
pub const ADJ_NANO: u32 = 0x2000;
/// Resolution (0 = us, 1 = ns) (ro).
pub const STA_NANO: u32 = 0x2000;
/// Tick value.
pub const ADJ_TICK: u32 = 0x4000;
/// Mode (0 = PLL, 1 = FLL) (ro).
pub const STA_MODE: u32 = 0x4000;
/// Clock source (0 = A, 1 = B) (ro).
pub const STA_CLK: u32 = 0x8000;
/// Old-fashioned adjtime.
pub const ADJ_OFFSET_SINGLESHOT: u32 = 0x8001;
/// Read-only adjtime.
pub const ADJ_OFFSET_SS_READ: u32 = 0xa001;
/// `STA_RONLY` from `<linux/timex.h>`.
pub const STA_RONLY: u32 = 0xff00;

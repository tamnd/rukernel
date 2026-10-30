//! The scheduling values of a thread: the policy, the priority, the nice value and the CPUs that
//! the thread can use. `sched_setattr` and the other calls of kernel/sched/syscalls.c of Linux
//! change them.

use core::sync::atomic::{AtomicI32, Ordering};
use rk_abi::Errno;
use rk_abi::native::sched::{SCHED_DEADLINE, SCHED_FIFO, SCHED_IDLE, SCHED_RR};
use rk_frame::sync::SpinLock;
#[cfg(target_os = "none")]
use rk_frame::time::HZ;

/// The timer ticks in a second of the kernel, for the unit tests on the host.
#[cfg(not(target_os = "none"))]
const HZ: u64 = 250;

/// The scheduling values of a thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedParams {
    /// The policy: `SCHED_NORMAL`, `SCHED_FIFO` and the others.
    pub policy: u32,
    /// The real time priority, from 1 to 99 for `SCHED_FIFO` and `SCHED_RR`, else 0.
    pub priority: u32,
    /// The nice value, from -20 to 19.
    pub nice: i32,
    /// A child of `fork` gets the default policy and a nice value that is not negative.
    pub reset_on_fork: bool,
    /// The run time of `SCHED_DEADLINE` in each period, in nanoseconds.
    pub runtime: u64,
    /// The relative deadline of `SCHED_DEADLINE`, in nanoseconds.
    pub deadline: u64,
    /// The period of `SCHED_DEADLINE`, in nanoseconds.
    pub period: u64,
    /// The CPUs that the thread can use, one bit for each CPU.
    pub affinity: u64,
}

impl Default for SchedParams {
    fn default() -> Self {
        Self {
            policy: 0,
            priority: 0,
            nice: 0,
            reset_on_fork: false,
            runtime: 0,
            deadline: 0,
            period: 0,
            affinity: u64::MAX,
        }
    }
}

impl SchedParams {
    /// Tells if the policy is a real time policy.
    pub fn is_rt(&self) -> bool {
        matches!(u64::from(self.policy), SCHED_FIFO | SCHED_RR)
    }

    /// Tells if the policy is `SCHED_DEADLINE`.
    pub fn is_deadline(&self) -> bool {
        u64::from(self.policy) == SCHED_DEADLINE
    }

    /// The values of a new thread, as `sched_fork` of Linux makes them.
    pub fn forked(&self) -> Self {
        let mut p = *self;
        if p.reset_on_fork {
            if p.is_rt() || p.is_deadline() {
                p = Self { affinity: p.affinity, ..Self::default() };
            } else if p.nice < 0 {
                p.nice = 0;
            }
            p.reset_on_fork = false;
        }
        p
    }

    /// The nice value and the idle flag that the scheduler uses for the share of the CPU.
    /// rukernel has only the fair class, so a real time thread and a deadline thread get the
    /// largest share.
    pub fn share(&self) -> (i32, bool) {
        if self.is_rt() || self.is_deadline() {
            (-20, false)
        } else {
            (self.nice, u64::from(self.policy) == SCHED_IDLE)
        }
    }
}

/// The default time slice of `SCHED_RR` in milliseconds, as `RR_TIMESLICE` of Linux.
pub const RR_TIMESLICE_MS: i32 = 100;

/// The value of /proc/sys/kernel/sched_rr_timeslice_ms, as `sysctl_sched_rr_timeslice` of Linux.
static RR_TIMESLICE: AtomicI32 = AtomicI32::new(RR_TIMESLICE_MS);

/// The real time period and run time in microseconds, as `sysctl_sched_rt_period` and
/// `sysctl_sched_rt_runtime` of Linux. A run time of -1 means no limit.
static RT_BANDWIDTH: SpinLock<(i32, i32)> = SpinLock::new((1_000_000, 950_000));

/// The value of /proc/sys/kernel/sched_rr_timeslice_ms.
pub fn rr_timeslice_ms() -> i32 {
    RR_TIMESLICE.load(Ordering::Relaxed)
}

/// Sets /proc/sys/kernel/sched_rr_timeslice_ms. A value of 0 or less sets the default, as
/// `sched_rr_handler` in kernel/sched/rt.c of Linux.
pub fn set_rr_timeslice_ms(ms: i32) {
    RR_TIMESLICE.store(if ms <= 0 { RR_TIMESLICE_MS } else { ms }, Ordering::Relaxed);
}

/// The time slice of `SCHED_RR` in nanoseconds. Linux keeps it in timer ticks and rounds the
/// milliseconds up (`msecs_to_jiffies`), and `sched_rr_get_interval` gives this time.
pub fn rr_timeslice_ns() -> u64 {
    let tick_ns = 1_000_000_000 / HZ;
    let ns = rr_timeslice_ms().max(1) as u64 * 1_000_000;
    ns.div_ceil(tick_ns) * tick_ns
}

/// The values of /proc/sys/kernel/sched_rt_period_us and sched_rt_runtime_us.
pub fn rt_bandwidth() -> (i32, i32) {
    *RT_BANDWIDTH.lock()
}

/// Sets the real time period or run time in microseconds, as `sched_rt_handler` in
/// kernel/sched/rt.c of Linux. The period goes from 1 to `INT_MAX`, and the run time goes from -1
/// to `INT_MAX`. A run time other than -1 that is more than the period gives `EINVAL`, and the
/// values do not change.
pub fn set_rt_bandwidth(period: Option<i32>, runtime: Option<i32>) -> Result<(), Errno> {
    let mut bw = RT_BANDWIDTH.lock();
    let new = (period.unwrap_or(bw.0), runtime.unwrap_or(bw.1));
    if new.0 < 1 || new.1 < -1 || (new.1 != -1 && new.1 > new.0) {
        return Err(Errno::EINVAL);
    }
    *bw = new;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rr_time_slice_resets_to_the_default_and_rounds_up_to_a_tick() {
        set_rr_timeslice_ms(-1);
        assert_eq!(rr_timeslice_ms(), RR_TIMESLICE_MS);
        assert_eq!(rr_timeslice_ns(), 100_000_000);
        let tick_ns = 1_000_000_000 / HZ;
        set_rr_timeslice_ms(1);
        assert_eq!(rr_timeslice_ms(), 1);
        assert_eq!(rr_timeslice_ns(), tick_ns.max(1_000_000).div_ceil(tick_ns) * tick_ns);
        set_rr_timeslice_ms(0);
        assert_eq!(rr_timeslice_ms(), RR_TIMESLICE_MS);
    }

    #[test]
    fn the_rt_bandwidth_rejects_bad_values() {
        assert_eq!(set_rt_bandwidth(Some(0), None), Err(Errno::EINVAL));
        assert_eq!(set_rt_bandwidth(Some(-1), None), Err(Errno::EINVAL));
        assert_eq!(set_rt_bandwidth(None, Some(-2)), Err(Errno::EINVAL));
        let (period, _) = rt_bandwidth();
        assert_eq!(set_rt_bandwidth(None, Some(period + 1)), Err(Errno::EINVAL));
        assert_eq!(set_rt_bandwidth(None, Some(-1)), Ok(()));
        assert_eq!(rt_bandwidth(), (period, -1));
        // A period below the run time gives `EINVAL`.
        assert_eq!(set_rt_bandwidth(None, Some(period)), Ok(()));
        assert_eq!(set_rt_bandwidth(Some(period - 1), None), Err(Errno::EINVAL));
        assert_eq!(set_rt_bandwidth(Some(period), Some(950_000)), Ok(()));
    }
}

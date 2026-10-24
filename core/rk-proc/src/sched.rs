//! The scheduling values of a thread: the policy, the priority, the nice value and the CPUs that
//! the thread can use. `sched_setattr` and the other calls of kernel/sched/syscalls.c of Linux
//! change them.

use rk_abi::native::sched::{SCHED_DEADLINE, SCHED_FIFO, SCHED_IDLE, SCHED_RR};

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
            affinity: 1,
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

//! The timers of a process: the interval timers of `setitimer` and `alarm`, and the POSIX timers
//! of `timer_create`.
//!
//! A timer sends a signal when its time is over, and again after each interval if it has one.
//! One kernel task fires the timers. It waits until the earliest deadline and then sends the
//! signals, so the timer interrupt does not take the locks of the signal queues. The times are in
//! nanoseconds since boot, and a timer fires at the first tick at or after its time.

use crate::process::{Process, Thread};
use crate::signal::SigInfo;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU64, Ordering};
use rk_frame::sync::{Once, SpinLock};
use rk_frame::task::{TaskOptions, WaitQueue};
use rk_frame::time::{HZ, ticks};

const NSEC_PER_SEC: u64 = 1_000_000_000;
const TICK_NS: u64 = NSEC_PER_SEC / HZ;

/// The interval timers of `setitimer`: `ITIMER_REAL`, `ITIMER_VIRTUAL` and `ITIMER_PROF`.
pub const NR_ITIMERS: usize = 3;

/// The most POSIX timers of one process.
const MAX_TIMERS: usize = 4096;

/// The nanoseconds since boot, from the timer tick.
pub fn now_ns() -> u64 {
    ticks().saturating_mul(TICK_NS)
}

/// Where a timer sends its signal.
pub enum Target {
    /// Any thread of the process takes the signal.
    Process(Weak<Process>),
    /// This thread takes the signal, for `SIGEV_THREAD_ID`.
    Thread(Weak<Thread>),
    /// The timer sends no signal, for `SIGEV_NONE`.
    None,
}

#[derive(Debug, Default)]
struct TimerState {
    /// The time when the timer fires, or 0 if the timer is off.
    expires: u64,
    /// The time between two signals, or 0 for one signal.
    interval: u64,
    /// The key of the timer in the queue of the timer task, while the timer is on.
    key: Option<(u64, u64)>,
    /// The overrun count of the last signal, for `timer_getoverrun`.
    overrun: i32,
}

/// A timer.
pub struct Timer {
    target: Target,
    /// The signal that the timer sends. The timer sets the time fields of the `siginfo`.
    info: SigInfo,
    state: SpinLock<TimerState>,
}

impl core::fmt::Debug for Timer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Timer").field("info", &self.info).finish_non_exhaustive()
    }
}

impl Timer {
    /// Makes a timer that is off. It sends `info` to `target`.
    pub fn new(target: Target, info: SigInfo) -> Arc<Self> {
        Arc::new(Self { target, info, state: SpinLock::new(TimerState::default()) })
    }

    /// Sets the timer to fire at `expires` and then after each `interval`. An `expires` of 0
    /// turns the timer off. Gives the remaining time and the interval before the change.
    pub fn arm(self: &Arc<Self>, expires: u64, interval: u64) -> (u64, u64) {
        let mut s = self.state.lock();
        let old = s.remaining();
        if let Some(key) = s.key.take() {
            QUEUE.lock().remove(&key);
        }
        s.expires = expires;
        s.interval = if expires == 0 { 0 } else { interval };
        if expires != 0 {
            let key = (expires, NEXT_KEY.fetch_add(1, Ordering::Relaxed));
            s.key = Some(key);
            QUEUE.lock().insert(key, self.clone());
            start();
            EPOCH.fetch_add(1, Ordering::Release);
            WAKE.wake_all();
        }
        old
    }

    /// Gives the remaining time and the interval.
    pub fn get(&self) -> (u64, u64) {
        self.state.lock().remaining()
    }

    /// The overrun count of the last signal.
    pub fn overrun(&self) -> i32 {
        self.state.lock().overrun
    }

    /// Fires the timer at `now`: it sends the signal, and puts the timer back in the queue if it
    /// has an interval.
    fn fire(self: &Arc<Self>, key: (u64, u64), now: u64) {
        let missed = {
            let mut s = self.state.lock();
            if s.key != Some(key) {
                return;
            }
            s.key = None;
            let mut missed = 0;
            if s.interval == 0 {
                s.expires = 0;
            } else {
                missed = (now - s.expires) / s.interval;
                s.expires += (missed + 1) * s.interval;
                let key = (s.expires, NEXT_KEY.fetch_add(1, Ordering::Relaxed));
                s.key = Some(key);
                QUEUE.lock().insert(key, self.clone());
            }
            missed
        };
        let mut info = self.info;
        info.uid = u32::try_from(missed).unwrap_or(i32::MAX as u32);
        let overrun = match &self.target {
            Target::Process(p) => {
                p.upgrade().and_then(|p| crate::process::send_timer_signal(&p, None, info))
            }
            Target::Thread(t) => t
                .upgrade()
                .and_then(|t| crate::process::send_timer_signal(t.process(), Some(&t), info)),
            Target::None => None,
        };
        if let Some(overrun) = overrun {
            self.state.lock().overrun = overrun;
        }
    }
}

impl TimerState {
    fn remaining(&self) -> (u64, u64) {
        if self.expires == 0 {
            return (0, self.interval);
        }
        // A timer that is over but did not fire yet gives 1 microsecond, as Linux does.
        (self.expires.saturating_sub(now_ns()).max(1000), self.interval)
    }
}

/// The timers of one process.
#[derive(Debug, Default)]
pub struct Timers {
    itimers: [Option<Arc<Timer>>; NR_ITIMERS],
    posix: BTreeMap<i32, Arc<Timer>>,
}

impl Timers {
    /// Turns off each timer, for the exit of the process. With `posix_only`, the interval
    /// timers stay, as `execve` keeps them.
    pub fn clear(&mut self, posix_only: bool) {
        for t in core::mem::take(&mut self.posix).into_values() {
            t.arm(0, 0);
        }
        if !posix_only {
            for t in self.itimers.iter_mut().filter_map(Option::take) {
                t.arm(0, 0);
            }
        }
    }

    /// The interval timer `which`. `make` makes it the first time.
    pub fn itimer(&mut self, which: usize, make: impl FnOnce() -> Arc<Timer>) -> Arc<Timer> {
        self.itimers[which].get_or_insert_with(make).clone()
    }

    /// Adds a POSIX timer with the lowest free ID. `make` makes the timer from its ID. Gives
    /// `None` if the process has too many timers.
    pub fn add(&mut self, make: impl FnOnce(i32) -> Arc<Timer>) -> Option<i32> {
        if self.posix.len() >= MAX_TIMERS {
            return None;
        }
        let id = (0..).find(|id| !self.posix.contains_key(id))?;
        self.posix.insert(id, make(id));
        Some(id)
    }

    /// The POSIX timer `id`.
    pub fn get(&self, id: i32) -> Option<Arc<Timer>> {
        self.posix.get(&id).cloned()
    }

    /// Removes the POSIX timer `id` and turns it off. Gives `false` if there is no such timer.
    pub fn remove(&mut self, id: i32) -> bool {
        self.posix.remove(&id).map(|t| t.arm(0, 0)).is_some()
    }
}

/// The timers that are on, by the time when they fire and a number that makes each key unique.
static QUEUE: SpinLock<BTreeMap<(u64, u64), Arc<Timer>>> = SpinLock::new(BTreeMap::new());
static NEXT_KEY: AtomicU64 = AtomicU64::new(0);
/// The count of changes to the queue. The timer task waits until it changes or a deadline comes.
static EPOCH: AtomicU64 = AtomicU64::new(0);
static WAKE: WaitQueue = WaitQueue::new();
static STARTED: Once<()> = Once::new();

/// Starts the timer task the first time that a timer is on.
fn start() {
    STARTED.call_once(|| {
        let _ = TaskOptions::new(run).spawn();
    });
}

/// The timer task.
fn run() {
    loop {
        let epoch = EPOCH.load(Ordering::Acquire);
        let now = now_ns();
        let expired = {
            let mut q = QUEUE.lock();
            let later = q.split_off(&(now + 1, 0));
            core::mem::replace(&mut *q, later)
        };
        for (key, timer) in expired {
            timer.fire(key, now);
        }
        let next = QUEUE.lock().keys().next().map(|k| k.0.div_ceil(TICK_NS));
        let changed = || (EPOCH.load(Ordering::Acquire) != epoch).then_some(());
        match next {
            Some(deadline) => {
                WAKE.wait_until_timeout(deadline, changed);
            }
            None => WAKE.wait_until(changed),
        }
    }
}

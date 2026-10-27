//! Pressure stall information: the time that tasks wait for the CPU, for memory and for I/O.
//!
//! Each cgroup has a `Psi` for the tasks in its subtree. The root has the tasks of the system, and
//! `/proc/pressure` shows it. A resource has two states. `some` is true while one task or more
//! waits for the resource. `full` is true while all the tasks that are not idle wait for it. The
//! totals are the time in each state. The averages over 10, 60 and 300 seconds come from the
//! totals each 2 seconds, with the fixed point exponential decay of `kernel/sched/psi.c` of Linux.
//!
//! Linux keeps the counts for each CPU. This module keeps one count for the group, so on a
//! machine with more than one CPU, `some` for the CPU is true while more tasks can run than run.

use alloc::format;
use alloc::string::String;

/// The CPU resource.
pub const CPU: usize = 0;
/// The memory resource.
pub const MEMORY: usize = 1;
/// The I/O resource.
pub const IO: usize = 2;

/// The names of the resources, as the files `/proc/pressure/NAME` and `NAME.pressure` use them.
pub const NAMES: [&str; 3] = ["cpu", "memory", "io"];

/// One in the fixed point format of the averages: `FIXED_1` of Linux.
pub const FIXED_1: u64 = 1 << 11;

/// The decay of each average in one period: `1 / exp(2s / 10s)`, `1 / exp(2s / 60s)` and
/// `1 / exp(2s / 300s)` in fixed point, as `EXP_10s`, `EXP_60s` and `EXP_300s` of Linux.
pub const EXP: [u64; 3] = [1677, 1981, 2034];

/// The time between two updates of the averages in nanoseconds: `PSI_FREQ` of Linux.
pub const PERIOD_NS: u64 = 2_000_000_000;

/// The smallest window of a trigger in microseconds, as Linux.
pub const WINDOW_MIN_US: u64 = 500_000;
/// The largest window of a trigger in microseconds, as Linux.
pub const WINDOW_MAX_US: u64 = 10_000_000;

/// The counts of the tasks that the states come from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// The tasks that can run: the tasks that run and the tasks in a run queue.
    pub runnable: u32,
    /// The tasks that run on a CPU now.
    pub oncpu: u32,
    /// The tasks that wait for memory, as `TSK_MEMSTALL` of Linux.
    pub memstall: u32,
    /// The tasks that wait for I/O.
    pub iowait: u32,
}

impl Counts {
    /// The state of each resource now: `[some, full]` for each one. A group without the
    /// controller of the CPU has no `full` for the CPU at the root, as Linux.
    fn states(&self, root: bool) -> [[bool; 2]; 3] {
        let waiting = self.runnable.saturating_sub(self.oncpu);
        let nonidle = self.runnable + self.iowait;
        let cpu_some = waiting > 0;
        let cpu_full = !root && cpu_some && self.oncpu == 0;
        let mem_some = self.memstall > 0;
        let mem_full = mem_some && self.memstall >= nonidle;
        let io_some = self.iowait > 0;
        let io_full = io_some && self.runnable == 0;
        [[cpu_some, cpu_full], [mem_some, mem_full], [io_some, io_full]]
    }
}

/// The pressure of one group.
#[derive(Clone, Debug)]
pub struct Psi {
    counts: Counts,
    /// The group is the root. The root has no `full` line for the CPU with a value.
    root: bool,
    /// The states since `changed`.
    states: [[bool; 2]; 3],
    /// The time of the last change of the counts, in nanoseconds.
    changed: u64,
    /// The time in each state, in nanoseconds.
    total: [[u64; 2]; 3],
    /// The totals at the last update of the averages.
    avg_total: [[u64; 2]; 3],
    /// The time of the last update of the averages.
    avg_last: u64,
    /// The time of the next update of the averages.
    avg_next: u64,
    /// The averages over 10, 60 and 300 seconds, in fixed point percent.
    avg: [[[u64; 3]; 2]; 3],
}

/// Gives `load * exp + active * (1 - exp)` in fixed point, as `calc_load` of Linux.
pub fn calc_load(load: u64, exp: u64, active: u64) -> u64 {
    let mut new = load * exp + active * (FIXED_1 - exp);
    if active >= load {
        new += FIXED_1 - 1;
    }
    new / FIXED_1
}

/// Gives `calc_load` with `active` 0 for `n` periods, as `calc_load_n` of Linux. Only the
/// decay of the old value is left.
fn calc_load_n(load: u64, exp: u64, n: u64) -> u64 {
    // `exp ^ n` in fixed point. `n` is small in practice, and the value goes to 0 fast.
    let mut factor = FIXED_1;
    for _ in 0..n.min(64) {
        factor = factor * exp / FIXED_1;
        if factor == 0 {
            break;
        }
    }
    load * factor / FIXED_1
}

/// Formats a fixed point percent with two decimals, as `LOAD_INT` and `LOAD_FRAC` of Linux.
pub fn format_pct(v: u64) -> String {
    let int = v >> 11;
    let frac = ((v & (FIXED_1 - 1)) * 100) >> 11;
    format!("{int}.{frac:02}")
}

impl Psi {
    /// Makes the pressure of a group that has no tasks, at the time `now` in nanoseconds.
    pub fn new(now: u64, root: bool) -> Self {
        Self {
            counts: Counts::default(),
            root,
            states: [[false; 2]; 3],
            changed: now,
            total: [[0; 2]; 3],
            avg_total: [[0; 2]; 3],
            avg_last: now,
            avg_next: now + PERIOD_NS,
            avg: [[[0; 3]; 2]; 3],
        }
    }

    /// The counts of the tasks now.
    pub fn counts(&self) -> Counts {
        self.counts
    }

    /// Adds the time since the last change to the totals of the states that were true.
    fn advance(&mut self, now: u64) {
        let d = now.saturating_sub(self.changed);
        for (total, state) in self.total.iter_mut().zip(self.states) {
            for (t, s) in total.iter_mut().zip(state) {
                if s {
                    *t += d;
                }
            }
        }
        self.changed = self.changed.max(now);
    }

    /// Changes the counts with `f` at the time `now`.
    pub fn change(&mut self, now: u64, f: impl FnOnce(&mut Counts)) {
        self.advance(now);
        self.update_averages(now);
        f(&mut self.counts);
        self.states = self.counts.states(self.root);
    }

    /// Updates the averages if a period ended, as `update_averages` of Linux.
    pub fn update_averages(&mut self, now: u64) {
        if now < self.avg_next {
            return;
        }
        self.advance(now);
        let missed = (now - self.avg_next) / PERIOD_NS;
        let period = now - self.avg_last;
        self.avg_last = now;
        self.avg_next += (missed + 1) * PERIOD_NS;
        for r in 0..3 {
            for s in 0..2 {
                let sample = (self.total[r][s] - self.avg_total[r][s]).min(period);
                self.avg_total[r][s] = self.total[r][s];
                let pct = (sample * 100).checked_div(period).map_or(0, |v| v * FIXED_1);
                for (a, &exp) in self.avg[r][s].iter_mut().zip(&EXP) {
                    if missed > 0 {
                        *a = calc_load_n(*a, exp, missed);
                    }
                    *a = calc_load(*a, exp, pct);
                }
            }
        }
    }

    /// The total time in the state `full` (`full` true) or `some` of the resource, in
    /// nanoseconds, up to `now`.
    pub fn total(&mut self, now: u64, resource: usize, full: bool) -> u64 {
        self.advance(now);
        self.total[resource][usize::from(full)]
    }

    /// The text of `/proc/pressure/NAME` for the resource at the time `now`.
    pub fn show(&mut self, now: u64, resource: usize) -> String {
        self.advance(now);
        self.update_averages(now);
        let mut out = String::new();
        for (s, name) in ["some", "full"].iter().enumerate() {
            // Linux shows zeros for `full` of the CPU at the root.
            let zero = resource == CPU && s == 1 && self.root;
            let avg = if zero { [0; 3] } else { self.avg[resource][s] };
            let total = if zero { 0 } else { self.total[resource][s] / 1000 };
            out.push_str(&format!(
                "{name} avg10={} avg60={} avg300={} total={total}\n",
                format_pct(avg[0]),
                format_pct(avg[1]),
                format_pct(avg[2]),
            ));
        }
        out
    }
}

/// A trigger of a pressure file: the group must stall `threshold` microseconds in a window of
/// `window` microseconds, as `psi_trigger_create` of Linux parses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Trigger {
    /// The state: `full` is true for `full`, false for `some`.
    pub full: bool,
    /// The stall time in microseconds.
    pub threshold: u64,
    /// The time of the window in microseconds.
    pub window: u64,
}

impl Trigger {
    /// Parses `some THRESHOLD WINDOW` or `full THRESHOLD WINDOW`.
    ///
    /// # Errors
    ///
    /// Gives `EINVAL` for another text, a window out of range or a threshold larger than the
    /// window.
    pub fn parse(text: &[u8]) -> Result<Self, rk_abi::Errno> {
        let text = core::str::from_utf8(text).map_err(|_| rk_abi::Errno::EINVAL)?;
        let mut words = text.trim_end_matches(['\n', '\0']).split_ascii_whitespace();
        let full = match words.next() {
            Some("some") => false,
            Some("full") => true,
            _ => return Err(rk_abi::Errno::EINVAL),
        };
        let mut num = || words.next().and_then(|w| w.parse::<u64>().ok());
        let (Some(threshold), Some(window)) = (num(), num()) else {
            return Err(rk_abi::Errno::EINVAL);
        };
        if !(WINDOW_MIN_US..=WINDOW_MAX_US).contains(&window) || threshold == 0 {
            return Err(rk_abi::Errno::EINVAL);
        }
        if threshold > window {
            return Err(rk_abi::Errno::EINVAL);
        }
        Ok(Self { full, threshold, window })
    }
}

/// The state of a trigger that a file keeps: the window that runs now and the last event.
#[derive(Clone, Copy, Debug)]
pub struct TriggerState {
    /// The trigger.
    pub trigger: Trigger,
    /// The resource.
    pub resource: usize,
    /// The start of the window, in nanoseconds.
    pub start: u64,
    /// The total stall time at the start of the window, in nanoseconds.
    pub start_total: u64,
    /// The time of the last event, in nanoseconds, or `None` before the first event.
    pub last_event: Option<u64>,
}

impl TriggerState {
    /// Starts a trigger at the time `now`, with the total `total` of its state.
    pub fn new(trigger: Trigger, resource: usize, now: u64, total: u64) -> Self {
        Self { trigger, resource, start: now, start_total: total, last_event: None }
    }

    /// Tells if the trigger has an event at the time `now`, with the total `total` of its state.
    /// The stall time in the window grows over the threshold for the event, and a trigger has
    /// at most one event in each window, as Linux.
    pub fn check(&mut self, now: u64, total: u64) -> bool {
        let window = self.trigger.window * 1000;
        if now.saturating_sub(self.start) >= window {
            self.start = now;
            self.start_total = total;
        }
        let growth = total.saturating_sub(self.start_total);
        if growth < self.trigger.threshold * 1000 {
            return false;
        }
        if self.last_event.is_some_and(|t| now.saturating_sub(t) < window) {
            return false;
        }
        self.last_event = Some(now);
        true
    }
}

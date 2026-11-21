//! The calculation of the time from a free running counter, as the clocksource of Linux.
//!
//! The clock is the counter since boot, times `mult`, shifted right by `SHIFT`, as
//! `clocksource_cyc2ns` of Linux. The tick count, the `jiffies` value, is the clock divided by the
//! time of one tick, so it does not lose a tick when a timer interrupt comes late. The next tick
//! interrupt is at an absolute counter value, the start of the next tick, as a clockevent device
//! in oneshot mode of Linux. The arm64 timer uses this module with the virtual counter.

/// The shift of the multiplier.
pub(crate) const SHIFT: u32 = 32;

/// The multiplier for a counter of `freq` Hz: the nanoseconds of one cycle, times 2^`SHIFT`. It is
/// 0 if `freq` is 0.
pub(crate) fn mult(freq: u64) -> u64 {
    if freq == 0 {
        return 0;
    }
    ((1_000_000_000u128 << SHIFT) / u128::from(freq)) as u64
}

/// The nanoseconds of `cycles` of the counter.
pub(crate) fn cycles_to_ns(cycles: u64, mult: u64) -> u64 {
    ((u128::from(cycles) * u128::from(mult)) >> SHIFT) as u64
}

/// The least cycles of the counter that `cycles_to_ns` gives `ns` or more for. It gives
/// `u64::MAX` if `mult` is 0 or the value is too large.
pub(crate) fn ns_to_cycles(ns: u64, mult: u64) -> u64 {
    if mult == 0 {
        return u64::MAX;
    }
    u64::try_from((u128::from(ns) << SHIFT).div_ceil(u128::from(mult))).unwrap_or(u64::MAX)
}

/// The cycles since boot of the start of the tick after the tick at `cycles`, for ticks of
/// `tick_ns` nanoseconds. The timer interrupt arms the timer at this value. If the interrupt comes
/// late, the next interrupt is still at the start of a tick, after the current time, so the time
/// of the ticks does not drift and late ticks do not come in a row.
pub(crate) fn next_tick(cycles: u64, mult: u64, tick_ns: u64) -> u64 {
    let next = (cycles_to_ns(cycles, mult) / tick_ns).saturating_add(1);
    ns_to_cycles(next.saturating_mul(tick_ns), mult)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The frequency of the virtual counter of QEMU `virt` before QEMU 9, and of many boards.
    const QEMU_HZ: u64 = 62_500_000;
    /// The frequency of the counter of some arm64 boards. The time of one cycle is not a whole
    /// number of nanoseconds.
    const ODD_HZ: u64 = 19_200_000;
    const TICK_NS: u64 = 4_000_000;

    /// The tick count at `cycles`, as the arm64 timer calculates it.
    fn ticks(cycles: u64, mult: u64) -> u64 {
        cycles_to_ns(cycles, mult) / TICK_NS
    }

    #[test]
    fn clock_follows_the_counter() {
        let m = mult(QEMU_HZ);
        assert_eq!(m, 16 << SHIFT);
        assert_eq!(cycles_to_ns(0, m), 0);
        assert_eq!(cycles_to_ns(QEMU_HZ, m), 1_000_000_000);
        assert_eq!(cycles_to_ns(186 * QEMU_HZ, m), 186_000_000_000);
        assert_eq!(mult(0), 0);
        assert_eq!(cycles_to_ns(QEMU_HZ, 0), 0);
    }

    /// The case of #813: the interrupts come only about 32 times each second, not 250 times. The
    /// clock and the tick count must follow the counter, and must not count the interrupts.
    #[test]
    fn clock_follows_the_counter_when_ticks_are_missed() {
        for freq in [QEMU_HZ, ODD_HZ, 24_000_000, 1_000_000_000] {
            let m = mult(freq);
            let mut cycles = 0;
            let mut interrupts = 0u64;
            let mut last_clock = 0;
            let mut last_ticks = 0;
            // Each interrupt comes late, by a varied time of up to 40 ticks.
            for i in 0..5000u64 {
                let deadline = next_tick(cycles, m, TICK_NS);
                assert!(deadline > cycles);
                let late = freq / 250 * (i * 7919 % 40) + i % 977;
                cycles = deadline + late;
                interrupts += 1;
                let clock = cycles_to_ns(cycles, m);
                assert!(clock >= last_clock);
                let t = ticks(cycles, m);
                assert!(t >= last_ticks + 1, "a tick interrupt adds at least one tick");
                last_clock = clock;
                last_ticks = t;
            }
            let real = (u128::from(cycles) * 1_000_000_000 / u128::from(freq)) as u64;
            // The clock is the time of the counter, with an error of less than 1 us.
            assert!(real - last_clock < 1000, "{freq} Hz: {real} {last_clock}");
            assert_eq!(last_ticks, last_clock / TICK_NS);
            // The interrupts are much fewer than the ticks.
            assert!(interrupts * 10 < last_ticks);
        }
    }

    /// A deadline in ticks is not before the time of the clock: at the interrupt of the tick
    /// `next_tick` gives, the clock is at the start of that tick, and one cycle before it the
    /// clock is in the tick before.
    #[test]
    fn next_tick_is_the_start_of_a_tick() {
        for freq in [QEMU_HZ, ODD_HZ, 24_000_000, 1_000_000_000, 32_768] {
            let m = mult(freq);
            for start in [0, 1, 12_345, freq / 250 - 1, freq / 250, 3 * freq, 86_400 * freq] {
                let next = next_tick(start, m, TICK_NS);
                let t = ticks(start, m);
                assert_eq!(ticks(next, m), t + 1, "{freq} Hz at {start}");
                assert_eq!(ticks(next - 1, m), t, "{freq} Hz at {start}");
                assert!(cycles_to_ns(next, m) >= (t + 1) * TICK_NS);
            }
        }
    }

    #[test]
    fn ns_to_cycles_is_the_inverse() {
        for freq in [QEMU_HZ, ODD_HZ, 1_000_000_000] {
            let m = mult(freq);
            for ns in [0, 1, 999, TICK_NS, 1_000_000_000, 7 * 86_400 * 1_000_000_000] {
                let c = ns_to_cycles(ns, m);
                assert!(cycles_to_ns(c, m) >= ns);
                if c > 0 {
                    assert!(cycles_to_ns(c - 1, m) < ns);
                }
            }
        }
        assert_eq!(ns_to_cycles(1, 0), u64::MAX);
    }
}

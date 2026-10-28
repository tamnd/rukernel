use super::*;
use alloc::vec::Vec;

fn entity(vruntime: u64, deadline: u64) -> Entity {
    Entity { vruntime, deadline, ..Entity::default() }
}

#[test]
fn weights_match_linux() {
    assert_eq!(weight_of(0), NICE_0_WEIGHT);
    assert_eq!(weight_of(-20), 88761);
    assert_eq!(weight_of(19), 15);
    assert_eq!(weight_of(25), 15);
    assert_eq!(weight_of(-1), 1277);
}

#[test]
fn the_earliest_eligible_deadline_runs_first() {
    let mut q = Eevdf::new();
    q.push('a', entity(0, 30));
    q.push('b', entity(0, 10));
    // `c` has the earliest deadline, but it ran more than the average, so it is not eligible.
    q.push('c', entity(90, 5));
    assert_eq!(q.avg_vruntime(None), 30);
    assert_eq!(q.pick(None).map(|(t, _)| t), Some('b'));
    assert_eq!(q.pick(None).map(|(t, _)| t), Some('a'));
    assert_eq!(q.pick(None).map(|(t, _)| t), Some('c'));
    assert!(q.pick(None).is_none());
}

#[test]
fn a_charge_moves_the_deadline_after_a_slice() {
    let mut e = Entity { deadline: BASE_SLICE, ..Entity::default() };
    assert!(!e.charge(BASE_SLICE / 2));
    assert_eq!(e.vruntime, BASE_SLICE / 2);
    assert!(e.charge(BASE_SLICE / 2));
    assert_eq!(e.deadline, 2 * BASE_SLICE);
    // A task with twice the weight gets half the virtual time for the same run time.
    let mut heavy = Entity { weight: 2 * NICE_0_WEIGHT, ..Entity::default() };
    heavy.charge(1000);
    assert_eq!(heavy.vruntime, 500);
}

/// Runs `tasks` for `steps` slices of 1 ms on one CPU, and gives the run time of each task.
fn run(weights: &[u64], steps: usize) -> Vec<u64> {
    let mut q = Eevdf::new();
    for (i, &weight) in weights.iter().enumerate() {
        let mut e = Entity { weight, ..Entity::default() };
        q.place(&mut e, None, true);
        q.push(i, e);
    }
    let mut ran = alloc::vec![0; weights.len()];
    for _ in 0..steps {
        let (i, mut e) = q.pick(None).expect("a task");
        e.charge(1_000_000);
        ran[i] += 1;
        q.push(i, e);
    }
    ran
}

#[test]
fn equal_tasks_share_the_cpu() {
    let ran = run(&[NICE_0_WEIGHT; 3], 300);
    assert!(ran.iter().all(|&r| r == 100), "{ran:?}");
}

#[test]
fn the_share_follows_the_weight() {
    // nice 0 against nice 5: the weights are 1024 and 335, so the shares are 75 and 25 percent.
    let ran = run(&[weight_of(0), weight_of(5)], 1000);
    assert!((740..=770).contains(&ran[0]), "{ran:?}");
}

#[test]
fn a_task_that_wakes_gets_back_its_lag() {
    let mut q = Eevdf::new();
    q.push('a', entity(1000, 4000));
    q.push('b', entity(3000, 6000));
    let mut sleeper = entity(1000, 4000);
    q.save_lag(&mut sleeper, 4_000_000);
    assert_eq!(sleeper.lag, 1000);
    q.place(&mut sleeper, None, false);
    // The lag grows by the weight of the queue with the task over the weight of the queue.
    assert_eq!(sleeper.vruntime, 2000 - 1500);
    assert_eq!(sleeper.lag, 0);
    assert_eq!(sleeper.deadline, sleeper.vruntime + BASE_SLICE);
}

#[test]
fn a_new_task_starts_at_the_average() {
    let mut q = Eevdf::new();
    q.push('a', entity(1000, 4000));
    q.push('b', entity(3000, 6000));
    let mut e = Entity::default();
    q.place(&mut e, None, true);
    assert_eq!(e.vruntime, 2000);
    assert_eq!(e.deadline, 2000 + BASE_SLICE / 2);
}

#[test]
fn the_minimum_does_not_go_back() {
    let mut q: Eevdf<char> = Eevdf::new();
    q.update_min(Some(&entity(500, 0)));
    q.update_min(Some(&entity(100, 0)));
    assert_eq!(q.avg_vruntime(None), 500);
}

/// The queue of the first version, which scans its tasks for the pick. The tests compare the
/// tree with it.
struct Scan<T> {
    tasks: Vec<(T, Entity, u64)>,
    min_vruntime: u64,
    key: i128,
    load: i128,
    lowest: Option<u64>,
    seq: u64,
}

impl<T> Scan<T> {
    fn new() -> Self {
        Self { tasks: Vec::new(), min_vruntime: 0, key: 0, load: 0, lowest: None, seq: 0 }
    }

    fn key_of(&self, e: &Entity) -> i128 {
        i128::from(e.weight) * (i128::from(e.vruntime) - i128::from(self.min_vruntime))
    }

    fn sums(&self, curr: Option<&Entity>) -> (i128, i128) {
        match curr {
            Some(c) => (self.key + self.key_of(c), self.load + i128::from(c.weight)),
            None => (self.key, self.load),
        }
    }

    fn avg_vruntime(&self, curr: Option<&Entity>) -> u64 {
        let (key, load) = self.sums(curr);
        if load == 0 {
            return self.min_vruntime;
        }
        (i128::from(self.min_vruntime) + key.div_euclid(load)).max(0) as u64
    }

    fn advance_min(&mut self, v: u64) {
        if v > self.min_vruntime {
            self.key -= self.load * i128::from(v - self.min_vruntime);
            self.min_vruntime = v;
        }
    }

    fn update_min(&mut self, curr: Option<&Entity>) {
        let lowest = match (self.lowest, curr.map(|e| e.vruntime)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if let Some(lowest) = lowest {
            self.advance_min(lowest);
        }
    }

    fn push(&mut self, task: T, e: Entity) {
        self.key += self.key_of(&e);
        self.load += i128::from(e.weight);
        self.lowest = Some(self.lowest.map_or(e.vruntime, |l| l.min(e.vruntime)));
        self.tasks.push((task, e, self.seq));
        self.seq += 1;
    }

    fn pick(&mut self, curr: Option<&Entity>) -> Option<(T, Entity)> {
        let (key, load) = self.sums(curr);
        let limit = (load > 0).then(|| i128::from(self.min_vruntime) + key.div_euclid(load));
        let mut best: Option<usize> = None;
        let mut lowest: Option<usize> = None;
        for (i, (_, e, seq)) in self.tasks.iter().enumerate() {
            let order = |j: usize| self.tasks[j].2;
            if lowest.is_none_or(|l| (e.vruntime, *seq) < (self.tasks[l].1.vruntime, order(l))) {
                lowest = Some(i);
            }
            if limit.is_some_and(|l| i128::from(e.vruntime) > l) {
                continue;
            }
            if best.is_none_or(|b| (e.deadline, *seq) < (self.tasks[b].1.deadline, order(b))) {
                best = Some(i);
            }
        }
        let best = best.or(lowest)?;
        let low = self.tasks[lowest?].1.vruntime;
        let (task, e, _) = self.tasks.swap_remove(best);
        self.key -= self.key_of(&e);
        self.load -= i128::from(e.weight);
        self.advance_min(low);
        self.lowest = if self.tasks.is_empty() { None } else { Some(low) };
        Some((task, e))
    }
}

/// A small random number generator for the tests: xorshift64.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A random entity near the virtual time `base`. The small ranges make equal deadlines and equal
/// virtual run times frequent, so the order of arrival decides often.
fn random_entity(rng: &mut Rng, base: u64) -> Entity {
    let vruntime = base + rng.below(40);
    Entity {
        vruntime,
        deadline: vruntime + rng.below(30),
        weight: weight_of(rng.below(40) as i32 - 20),
        lag: 0,
    }
}

#[test]
fn the_tree_picks_as_the_scan() {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    for round in 0..200 {
        let mut tree = Eevdf::new();
        let mut scan = Scan::new();
        let mut id = 0u32;
        let size = 1 + rng.below(if round % 10 == 0 { 300 } else { 40 });
        for _ in 0..size {
            let e = random_entity(&mut rng, 0);
            tree.push(id, e);
            scan.push(id, e);
            id += 1;
        }
        for _ in 0..4 * size {
            let base = tree.avg_vruntime(None);
            let curr = (rng.below(3) == 0).then(|| random_entity(&mut rng, base));
            match rng.below(5) {
                0 | 1 => {
                    let e = random_entity(&mut rng, base.saturating_sub(20));
                    tree.push(id, e);
                    scan.push(id, e);
                    id += 1;
                }
                2 => {
                    tree.update_min(curr.as_ref());
                    scan.update_min(curr.as_ref());
                }
                _ => {
                    let a = tree.pick(curr.as_ref());
                    let b = scan.pick(curr.as_ref());
                    assert_eq!(a, b, "round {round}");
                    // The task runs, and goes back to the queue.
                    if let Some((t, mut e)) = a.filter(|_| rng.below(4) != 0) {
                        e.charge(rng.below(4_000_000));
                        tree.push(t, e);
                        scan.push(t, e);
                    }
                }
            }
            assert_eq!(tree.len(), scan.tasks.len());
            assert_eq!(tree.avg_vruntime(curr.as_ref()), scan.avg_vruntime(curr.as_ref()));
            tree.check();
        }
        while let Some(a) = tree.pick(None) {
            assert_eq!(Some(a), scan.pick(None));
        }
        assert!(scan.pick(None).is_none());
    }
}

#[test]
fn the_tree_stays_balanced() {
    let mut q = Eevdf::new();
    // Deadlines in order are the worst case for a tree that does not balance.
    for i in 0..4096u64 {
        q.push(i, entity(i, i));
    }
    // An AVL tree of n nodes has a height of at most 1.44 log2(n).
    assert!(q.check() <= 18, "height {}", q.check());
    for _ in 0..2048 {
        q.pick(None);
    }
    assert!(q.check() <= 17);
    assert_eq!(q.len(), 2048);
}

#[test]
fn a_task_that_is_not_eligible_runs_if_no_task_is() {
    let mut q = Eevdf::new();
    q.push('a', entity(1000, 5000));
    q.push('b', entity(1000, 4000));
    // The task that runs is far behind, so the average is below each task of the queue.
    let curr = Entity { weight: 100 * NICE_0_WEIGHT, ..entity(0, 0) };
    assert!(q.avg_vruntime(Some(&curr)) < 1000);
    // Then the task with the lowest virtual run time, of those the first, runs.
    assert_eq!(q.pick(Some(&curr)).map(|(t, _)| t), Some('a'));
}

#[test]
fn a_stolen_task_keeps_its_lag_on_the_other_queue() {
    let mut src = Eevdf::new();
    src.push('a', entity(1000, 4000));
    src.push('b', entity(3000, 6000));
    src.push('c', entity(2000, 9000));
    // The average of the source is 2000. `c` has the latest deadline, but the test does not let
    // it move, so `b` moves. Its lag is negative, because it ran more than the average.
    let (t, mut e) = src.steal(None, 4_000_000, |&t| t != 'c').expect("a task");
    assert_eq!((t, e.lag), ('b', -1000));
    src.push(t, entity(3000, 6000));
    let (t, e2) = src.steal(None, 4_000_000, |&t| t == 'a').expect("a task");
    assert_eq!((t, e2.lag), ('a', 1000));
    assert_eq!(src.len(), 2);
    assert_eq!(src.avg_vruntime(None), 2500);
    // The other queue has its own virtual time. The task gets its lag back there, made larger
    // by the weight of the queue with the task over the weight of the queue.
    let mut dst = Eevdf::new();
    dst.push('x', entity(50_000, 60_000));
    e = e2;
    dst.place(&mut e, None, false);
    assert_eq!(e.vruntime, 50_000 - 2000);
    // A task that no test allows stays.
    assert!(src.steal(None, 4_000_000, |_| false).is_none());
    assert_eq!(src.len(), 2);
}

#[test]
fn a_task_that_wakes_goes_to_an_idle_cpu() {
    use balance::{Load, select_cpu};
    let busy = Load { queued: 1, running: true };
    let idle = Load::default();
    // The CPU that wakes the task is idle: the task runs there.
    assert_eq!(select_cpu(2, 1, u64::MAX, &[busy, idle, idle, busy], false), 1);
    // The CPU that wakes the task is busy and the last CPU is idle: the task goes back to it.
    assert_eq!(select_cpu(2, 0, u64::MAX, &[busy, idle, idle, busy], false), 2);
    // Else the idle CPU with the lowest number.
    assert_eq!(select_cpu(3, 0, u64::MAX, &[busy, busy, idle, busy], false), 2);
    // No CPU is idle: a task that wakes stays on its last CPU, and a new task goes to the CPU
    // with the fewest tasks.
    let one = Load { queued: 0, running: true };
    assert_eq!(select_cpu(0, 0, u64::MAX, &[busy, one, busy], false), 0);
    assert_eq!(select_cpu(0, 0, u64::MAX, &[busy, one, busy], true), 1);
}

#[test]
fn the_choice_of_a_cpu_follows_the_affinity_mask() {
    use balance::{Load, select_cpu};
    let busy = Load { queued: 2, running: true };
    let idle = Load::default();
    // CPU 1 is idle, but the mask has only CPUs 2 and 3.
    assert_eq!(select_cpu(0, 0, 0b1100, &[busy, idle, busy, busy], false), 2);
    assert_eq!(select_cpu(0, 0, 0b1000, &[busy, idle, idle, busy], false), 3);
    // A mask with no CPU that runs gives the last CPU.
    assert_eq!(select_cpu(1, 0, 0b1_0000, &[busy, busy], false), 1);
}

#[test]
fn an_idle_cpu_pulls_from_the_busiest_queue() {
    use balance::{Load, busiest};
    let load = |queued, running| Load { queued, running };
    let loads = [load(0, false), load(1, true), load(3, true), load(2, true)];
    assert_eq!(busiest(0, &loads, 0), Some(2));
    // The balancer skips a CPU that has no task that can move.
    assert_eq!(busiest(0, &loads, 1 << 2), Some(3));
    assert_eq!(busiest(0, &loads, 1 << 2 | 1 << 3), Some(1));
    // An idle CPU takes the task of a CPU that did not wake up yet.
    assert_eq!(busiest(0, &[load(0, false), load(1, false)], 0), Some(1));
    // A CPU that runs a task does not take the task of a CPU that did not wake up yet.
    assert_eq!(busiest(0, &[load(0, true), load(1, false)], 0), None);
}

#[test]
fn the_periodic_balance_evens_out_the_queues() {
    use balance::{Load, busiest};
    let load = |queued, running| Load { queued, running };
    // A move of one task from 2 tasks to 1 task does not make the loads more equal.
    assert_eq!(busiest(0, &[load(0, true), load(1, true)], 0), None);
    assert_eq!(busiest(0, &[load(0, true), load(2, true)], 0), Some(1));
    // Repeated balances end with loads that differ by at most one.
    let mut loads = [load(0, true), load(7, true), load(0, true), load(1, true)];
    for _ in 0..20 {
        for this in 0..loads.len() {
            if let Some(src) = busiest(this, &loads, 0) {
                loads[src].queued -= 1;
                loads[this].queued += 1;
            }
        }
    }
    let nr: Vec<usize> = loads.iter().map(Load::nr).collect();
    assert_eq!(nr.iter().sum::<usize>(), 12);
    assert!(nr.iter().all(|&n| n == 3), "{nr:?}");
}

#[test]
fn a_task_that_wakes_runs_when_the_current_task_reaches_parity() {
    // The current task ran alone, so it is at the average and keeps the CPU to the end of its
    // slice: a task that wakes with no lag does not stop it.
    let mut q = Eevdf::new();
    let curr = entity(10_000_000, 10_000_000 + BASE_SLICE);
    let mut woken = Entity { lag: 0, ..Entity::default() };
    q.place(&mut woken, Some(&curr), false);
    q.push('w', woken);
    assert!(!q.wakeup_preempt(&curr, &woken));
    // A task that slept with lag is before the average, so the current task is not eligible
    // now and the task that wakes takes the CPU.
    let mut q = Eevdf::new();
    let mut woken = Entity { lag: 1_000_000, ..Entity::default() };
    q.place(&mut woken, Some(&curr), false);
    q.push('w', woken);
    assert!(q.wakeup_preempt(&curr, &woken));
}

#[test]
fn a_task_that_wakes_waits_when_it_is_not_eligible() {
    // The task that wakes ran more than the average before it slept, so it waits, also when the
    // current task is past the average because a heavy task waits in the queue.
    let mut q = Eevdf::new();
    q.push('a', Entity { weight: 10 * NICE_0_WEIGHT, ..entity(0, BASE_SLICE) });
    let curr = entity(2_000_000, 2_000_000 + BASE_SLICE);
    let mut woken = Entity { lag: -3_000_000, ..Entity::default() };
    q.place(&mut woken, Some(&curr), false);
    q.push('w', woken);
    assert!(q.avg_vruntime(Some(&curr)) < curr.vruntime);
    assert!(!q.wakeup_preempt(&curr, &woken));
}

#[test]
fn a_task_that_wakes_runs_when_the_current_task_used_its_slice() {
    let mut q = Eevdf::new();
    let curr = entity(BASE_SLICE, BASE_SLICE);
    let mut woken = Entity { lag: 0, ..Entity::default() };
    q.place(&mut woken, Some(&curr), false);
    // The current task is at the average and its deadline is over, so it has no protection, but
    // its deadline is earlier than the deadline of the task that wakes.
    q.push('w', woken);
    assert!(!q.wakeup_preempt(&curr, &woken));
    let early = Entity { deadline: BASE_SLICE - 1, ..woken };
    assert!(q.wakeup_preempt(&curr, &early));
}

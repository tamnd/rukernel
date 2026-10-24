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

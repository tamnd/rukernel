use super::psi::{self, Psi, Trigger, TriggerState};
use super::*;

const SEC: u64 = 1_000_000_000;

fn names(h: &Hierarchy, id: CgId) -> Vec<&'static str> {
    h.files(id).into_iter().map(|f| f.name).collect()
}

#[test]
fn mkdir_and_rmdir_follow_the_rules() {
    let mut h = Hierarchy::new(0, 0b11);
    let a = h.mkdir(ROOT, b"a", 0).unwrap();
    let b = h.mkdir(a, b"b", 0).unwrap();
    assert_eq!(h.mkdir(ROOT, b"a", 0), Err(Errno::EEXIST));
    assert_eq!(h.path(b), b"/a/b");
    assert_eq!(h.path(ROOT), b"/");
    assert_eq!(h.lookup(ROOT, b"a"), Some(a));
    assert_eq!(h.rmdir(ROOT, b"a"), Err(Errno::EBUSY));
    h.add_process(b);
    assert!(h.populated(a));
    assert_eq!(h.rmdir(a, b"b"), Err(Errno::EBUSY));
    h.remove_process(b);
    assert!(!h.populated(a));
    assert_eq!(h.rmdir(a, b"b"), Ok(b));
    assert!(!h.exists(b));
    assert_eq!(h.rmdir(ROOT, b"a"), Ok(a));
    assert_eq!(h.rmdir(ROOT, b"a"), Err(Errno::ENOENT));
    // An ID is not used again.
    assert!(h.mkdir(ROOT, b"a", 0).unwrap() > b);
}

#[test]
fn the_limits_of_the_hierarchy_hold() {
    let mut h = Hierarchy::new(0, 1);
    let a = h.mkdir(ROOT, b"a", 0).unwrap();
    h.write(a, "cgroup.max.depth", b"1\n", 0).unwrap();
    h.write(a, "cgroup.max.descendants", b"2\n", 0).unwrap();
    let b = h.mkdir(a, b"b", 0).unwrap();
    assert_eq!(h.mkdir(b, b"c", 0), Err(Errno::EAGAIN));
    h.mkdir(a, b"c", 0).unwrap();
    assert_eq!(h.mkdir(a, b"d", 0), Err(Errno::EAGAIN));
    assert_eq!(h.read(a, "cgroup.max.depth", 0).unwrap(), "1\n");
    assert_eq!(h.read(ROOT, "cgroup.max.depth", 0).unwrap(), "max\n");
    assert_eq!(h.read(a, "cgroup.stat", 0).unwrap(), "nr_descendants 2\nnr_dying_descendants 0\n");
    assert_eq!(
        h.read(ROOT, "cgroup.stat", 0).unwrap(),
        "nr_descendants 3\nnr_dying_descendants 0\n"
    );
}

#[test]
fn subtree_control_gives_the_controllers_to_the_children() {
    let mut h = Hierarchy::new(0, 1);
    let a = h.mkdir(ROOT, b"a", 0).unwrap();
    assert_eq!(h.read(ROOT, "cgroup.controllers", 0).unwrap(), "cpuset cpu io memory pids\n");
    assert_eq!(h.read(a, "cgroup.controllers", 0).unwrap(), "\n");
    assert!(!names(&h, a).contains(&"pids.max"));
    h.write(ROOT, "cgroup.subtree_control", b"+pids +memory", 0).unwrap();
    assert_eq!(h.read(ROOT, "cgroup.subtree_control", 0).unwrap(), "memory pids\n");
    assert_eq!(h.read(a, "cgroup.controllers", 0).unwrap(), "memory pids\n");
    assert!(names(&h, a).contains(&"pids.max"));
    assert!(names(&h, a).contains(&"memory.max"));
    assert!(!names(&h, a).contains(&"cpu.max"));
    assert!(!names(&h, ROOT).contains(&"pids.max"));
    assert!(!names(&h, ROOT).contains(&"cgroup.events"));
    // A child can give only what it has.
    assert_eq!(h.write(a, "cgroup.subtree_control", b"+cpu", 0), Err(Errno::ENOENT));
    assert_eq!(h.write(a, "cgroup.subtree_control", b"+nothing", 0), Err(Errno::EINVAL));
    h.write(a, "cgroup.subtree_control", b"+pids", 0).unwrap();
    // The parent cannot take back what a child gives on.
    assert_eq!(h.write(ROOT, "cgroup.subtree_control", b"-pids", 0), Err(Errno::EBUSY));
    h.write(ROOT, "cgroup.subtree_control", b"-memory", 0).unwrap();
    assert_eq!(h.read(a, "cgroup.controllers", 0).unwrap(), "pids\n");
}

#[test]
fn a_cgroup_with_processes_has_no_controllers_for_children() {
    let mut h = Hierarchy::new(0, 1);
    h.write(ROOT, "cgroup.subtree_control", b"+pids", 0).unwrap();
    let a = h.mkdir(ROOT, b"a", 0).unwrap();
    let b = h.mkdir(a, b"b", 0).unwrap();
    h.add_process(a);
    assert_eq!(h.write(a, "cgroup.subtree_control", b"+pids", 0), Err(Errno::EBUSY));
    h.migrate(a, b, 1).unwrap();
    h.write(a, "cgroup.subtree_control", b"+pids", 0).unwrap();
    assert_eq!(h.can_attach(a), Err(Errno::EBUSY));
    assert_eq!(h.migrate(b, a, 1), Err(Errno::EBUSY));
    // The root can have both.
    assert_eq!(h.can_attach(ROOT), Ok(()));
}

#[test]
fn pids_max_refuses_a_fork() {
    let mut h = Hierarchy::new(0, 1);
    h.write(ROOT, "cgroup.subtree_control", b"+pids", 0).unwrap();
    let a = h.mkdir(ROOT, b"a", 0).unwrap();
    h.write(a, "pids.max", b"2\n", 0).unwrap();
    let b = h.mkdir(a, b"b", 0).unwrap();
    h.charge_pids(b, 1).unwrap();
    h.charge_pids(a, 1).unwrap();
    assert_eq!(h.charge_pids(b, 1), Err(Errno::EAGAIN));
    assert_eq!(h.read(a, "pids.current", 0).unwrap(), "2\n");
    assert_eq!(h.read(a, "pids.events", 0).unwrap(), "max 1\n");
    assert_eq!(h.read(a, "pids.max", 0).unwrap(), "2\n");
    h.uncharge_pids(b, 1);
    h.charge_pids(b, 1).unwrap();
    assert_eq!(h.read(a, "pids.peak", 0).unwrap(), "2\n");
    assert_eq!(h.pids(ROOT), 2);
    assert_eq!(h.write(a, "pids.max", b"many", 0), Err(Errno::EINVAL));
    h.write(a, "pids.max", b"max", 0).unwrap();
    h.charge_pids(b, 5).unwrap();
}

#[test]
fn memory_max_refuses_a_charge_and_counts_the_events() {
    let mut h = Hierarchy::new(0, 1);
    h.write(ROOT, "cgroup.subtree_control", b"+memory", 0).unwrap();
    let a = h.mkdir(ROOT, b"a", 0).unwrap();
    h.write(a, "memory.max", b"8K", 0).unwrap();
    h.write(a, "memory.high", b"4096", 0).unwrap();
    assert_eq!(h.read(a, "memory.max", 0).unwrap(), "8192\n");
    h.charge_memory(a, PAGE_SIZE).unwrap();
    h.charge_memory(a, PAGE_SIZE).unwrap();
    assert_eq!(h.charge_memory(a, PAGE_SIZE), Err(a));
    h.count_oom(a);
    h.count_oom_kill(a);
    assert_eq!(h.read(a, "memory.current", 0).unwrap(), "8192\n");
    assert_eq!(
        h.read(a, "memory.events", 0).unwrap(),
        "low 0\nhigh 1\nmax 1\noom 1\noom_kill 1\noom_group_kill 0\n"
    );
    assert!(h.read(a, "memory.stat", 0).unwrap().starts_with("anon 8192\n"));
    h.write(a, "memory.max", b"4096", 0).map(|e| assert_eq!(e, Effect::MemoryOver)).unwrap();
    assert_eq!(h.memory_over(a), PAGE_SIZE);
    h.uncharge_memory(a, PAGE_SIZE);
    assert_eq!(h.memory_over(a), 0);
    assert_eq!(h.read(a, "memory.peak", 0).unwrap(), "8192\n");
    assert_eq!(parse_bytes(b"1M\n"), Ok(1 << 20));
    assert_eq!(parse_bytes(b"4097"), Ok(4096));
    assert_eq!(parse_bytes(b"max"), Ok(MAX));
    assert_eq!(parse_bytes(b"x"), Err(Errno::EINVAL));
}

#[test]
fn a_removed_cgroup_stays_while_it_has_charges() {
    let mut h = Hierarchy::new(0, 1);
    let a = h.mkdir(ROOT, b"a", 0).unwrap();
    h.charge_memory(a, PAGE_SIZE).unwrap();
    h.rmdir(ROOT, b"a").unwrap();
    assert!(!h.exists(a));
    assert_eq!(
        h.read(ROOT, "cgroup.stat", 0).unwrap(),
        "nr_descendants 0\nnr_dying_descendants 1\n"
    );
    h.uncharge_memory(a, PAGE_SIZE);
    assert_eq!(
        h.read(ROOT, "cgroup.stat", 0).unwrap(),
        "nr_descendants 0\nnr_dying_descendants 0\n"
    );
    assert_eq!(h.memory(ROOT).unwrap().current, 0);
}

#[test]
fn cpu_max_throttles_a_cgroup_for_the_rest_of_the_period() {
    let mut h = Hierarchy::new(0, 1);
    h.write(ROOT, "cgroup.subtree_control", b"+cpu", 0).unwrap();
    let a = h.mkdir(ROOT, b"a", 0).unwrap();
    assert_eq!(h.read(a, "cpu.max", 0).unwrap(), "max 100000\n");
    h.write(a, "cpu.max", b"20000 100000", 0).unwrap();
    assert_eq!(h.read(a, "cpu.max", 0).unwrap(), "20000 100000\n");
    let ms = 1_000_000;
    h.charge_cpu(a, 10 * ms, 10 * ms);
    assert_eq!(h.throttled_until(a, 10 * ms), None);
    h.charge_cpu(a, 10 * ms, 20 * ms);
    assert_eq!(h.throttled_until(a, 20 * ms), Some(100 * ms));
    assert_eq!(h.throttled_until(a, 100 * ms), None);
    let stat = h.read(a, "cpu.stat", 100 * ms).unwrap();
    assert!(stat.starts_with("usage_usec 20000\n"), "{stat}");
    assert!(stat.contains("nr_periods 1\nnr_throttled 1\nthrottled_usec 80000\n"), "{stat}");
    // The root has the usage of the subtree and no quota.
    assert!(h.read(ROOT, "cpu.stat", 0).unwrap().starts_with("usage_usec 20000\n"));
    assert!(!h.read(ROOT, "cpu.stat", 0).unwrap().contains("nr_periods"));
    assert_eq!(h.write(a, "cpu.max", b"500 100000", 0), Err(Errno::EINVAL));
    assert_eq!(h.write(a, "cpu.max", b"max 10", 0), Err(Errno::EINVAL));
    h.write(a, "cpu.max", b"max", 0).unwrap();
    h.charge_cpu(a, SEC, 2 * SEC);
    assert_eq!(h.throttled_until(a, 2 * SEC), None);
}

#[test]
fn cpu_weight_scales_the_threads_of_a_group() {
    let mut h = Hierarchy::new(0, 1);
    let a = h.mkdir(ROOT, b"a", 0).unwrap();
    h.charge_pids(a, 2).unwrap();
    // Without the controller the threads count as threads of the root.
    assert_eq!(h.weight_factor(a), WEIGHT_UNIT);
    h.write(ROOT, "cgroup.subtree_control", b"+cpu", 0).unwrap();
    assert_eq!(h.weight_factor(a), WEIGHT_UNIT / 2);
    h.write(a, "cpu.weight", b"200", 0).unwrap();
    assert_eq!(h.weight_factor(a), WEIGHT_UNIT);
    assert_eq!(h.write(a, "cpu.weight", b"0", 0), Err(Errno::ERANGE));
    assert_eq!(h.write(a, "cpu.weight", b"10001", 0), Err(Errno::ERANGE));
    h.write(a, "cpu.weight.nice", b"0", 0).unwrap();
    assert_eq!(h.read(a, "cpu.weight", 0).unwrap(), "100\n");
    h.write(a, "cpu.weight.nice", b"-20", 0).unwrap();
    assert_eq!(h.read(a, "cpu.weight.nice", 0).unwrap(), "-20\n");
    // The threads of the root keep their weight, and do not share the weight of the root.
    h.charge_pids(ROOT, 1000).unwrap();
    assert_eq!(h.weight_factor(ROOT), WEIGHT_UNIT);
    h.write(a, "cpu.weight", b"200", 0).unwrap();
    assert_eq!(h.weight_factor(a), WEIGHT_UNIT);
}

#[test]
fn cpuset_limits_the_cpus() {
    let mut h = Hierarchy::new(0, 0b1111);
    h.write(ROOT, "cgroup.subtree_control", b"+cpuset", 0).unwrap();
    let a = h.mkdir(ROOT, b"a", 0).unwrap();
    assert_eq!(h.read(a, "cpuset.cpus", 0).unwrap(), "\n");
    assert_eq!(h.read(a, "cpuset.cpus.effective", 0).unwrap(), "0-3\n");
    assert_eq!(h.write(a, "cpuset.cpus", b"1,3\n", 0), Ok(Effect::Cpuset));
    assert_eq!(h.effective_cpus(a), 0b1010);
    assert_eq!(h.read(a, "cpuset.cpus", 0).unwrap(), "1,3\n");
    assert_eq!(h.read(a, "cpuset.mems.effective", 0).unwrap(), "0\n");
    assert_eq!(h.write(a, "cpuset.mems", b"1", 0), Err(Errno::EINVAL));
    assert_eq!(parse_list(b"0-2,5"), Ok(0b100111));
    assert_eq!(show_list(0b100111), "0-2,5\n");
    assert_eq!(parse_list(b"3-1"), Err(Errno::EINVAL));
}

#[test]
fn freeze_and_kill_tell_the_caller() {
    let mut h = Hierarchy::new(0, 1);
    let a = h.mkdir(ROOT, b"a", 0).unwrap();
    let b = h.mkdir(a, b"b", 0).unwrap();
    assert_eq!(h.write(a, "cgroup.freeze", b"1", 0), Ok(Effect::Freeze));
    assert!(h.frozen(b));
    assert_eq!(h.read(b, "cgroup.events", 0).unwrap(), "populated 0\nfrozen 1\n");
    assert_eq!(h.read(b, "cgroup.freeze", 0).unwrap(), "0\n");
    assert_eq!(h.write(a, "cgroup.freeze", b"2", 0), Err(Errno::ERANGE));
    assert_eq!(h.write(a, "cgroup.kill", b"1", 0), Ok(Effect::Kill));
    assert_eq!(h.write(ROOT, "cgroup.kill", b"1", 0), Err(Errno::ENOENT));
    assert_eq!(h.write(a, "cgroup.type", b"threaded", 0), Err(Errno::EOPNOTSUPP));
    assert_eq!(h.write(a, "cgroup.stat", b"1", 0), Err(Errno::EACCES));
}

#[test]
fn paths_in_a_namespace_are_relative() {
    let mut h = Hierarchy::new(0, 1);
    let a = h.mkdir(ROOT, b"a", 0).unwrap();
    let b = h.mkdir(a, b"b", 0).unwrap();
    let c = h.mkdir(ROOT, b"c", 0).unwrap();
    let ns = h.new_namespace(a);
    assert_eq!(h.namespace_root(ns), a);
    assert_eq!(h.namespace_root(0), ROOT);
    assert_eq!(h.path_from(b, a), b"/b");
    assert_eq!(h.path_from(a, a), b"/");
    assert_eq!(h.path_from(c, a), b"/../c");
    assert_eq!(h.path_from(ROOT, b), b"/../..");
    assert!(h.is_descendant(b, a));
    assert!(!h.is_descendant(c, a));
}

#[test]
fn proc_cgroups_lists_the_controllers() {
    let mut h = Hierarchy::new(0, 1);
    h.mkdir(ROOT, b"a", 0).unwrap();
    let text = h.proc_cgroups();
    assert!(text.starts_with("#subsys_name\thierarchy\tnum_cgroups\tenabled\n"));
    assert!(text.contains("memory\t0\t2\t1\n"));
}

#[test]
fn pressure_averages_follow_linux() {
    let mut p = Psi::new(0, false);
    // One task waits for the CPU all the time.
    p.change(0, |c| {
        c.runnable = 2;
        c.oncpu = 1;
    });
    let text = p.show(2 * SEC, psi::CPU);
    // One period at 100 percent: 100 * (1 - EXP_10s / FIXED_1) = 18.11.
    assert!(text.starts_with("some avg10=18.11 avg60=3.27 avg300=0.68 total=2000000\n"), "{text}");
    assert!(text.contains("full avg10=0.00"), "{text}");
    p.change(2 * SEC, |c| c.oncpu = 0);
    let text = p.show(4 * SEC, psi::CPU);
    assert!(text.contains("full avg10=18.11"), "{text}");
    assert_eq!(p.total(4 * SEC, psi::CPU, false), 4 * SEC);
    // No stall for a long time: the averages decay.
    p.change(4 * SEC, |c| c.runnable = 0);
    let text = p.show(100 * SEC, psi::CPU);
    assert!(text.starts_with("some avg10=0.00"), "{text}");
    // The root has no full line for the CPU.
    let mut root = Psi::new(0, true);
    root.change(0, |c| c.runnable = 1);
    assert!(
        root.show(2 * SEC, psi::CPU).contains("full avg10=0.00 avg60=0.00 avg300=0.00 total=0")
    );
    assert_eq!(psi::format_pct(psi::FIXED_1 * 5 / 2), "2.50");
}

#[test]
fn memory_stalls_are_some_or_full() {
    let mut p = Psi::new(0, false);
    p.change(0, |c| {
        c.runnable = 2;
        c.memstall = 1;
    });
    assert_eq!(p.total(SEC, psi::MEMORY, false), SEC);
    assert_eq!(p.total(SEC, psi::MEMORY, true), 0);
    p.change(SEC, |c| c.runnable = 1);
    assert_eq!(p.total(2 * SEC, psi::MEMORY, true), SEC);
}

#[test]
fn the_group_pressure_has_the_tasks_of_the_subtree() {
    let mut h = Hierarchy::new(0, 1);
    let a = h.mkdir(ROOT, b"a", 0).unwrap();
    h.psi_change(a, 0, |c| c.runnable += 2);
    assert_eq!(h.psi_counts(ROOT).runnable, 2);
    assert_eq!(h.psi_total(a, psi::CPU, false, SEC), SEC);
    assert!(h.read(a, "cpu.pressure", SEC).unwrap().starts_with("some avg10="));
    assert!(h.read(ROOT, "io.pressure", SEC).unwrap().contains("total=0"));
}

#[test]
fn a_trigger_fires_once_in_a_window() {
    let t = Trigger::parse(b"some 150000 1000000").unwrap();
    assert_eq!(t, Trigger { full: false, threshold: 150_000, window: 1_000_000 });
    assert_eq!(Trigger::parse(b"some 150000 100"), Err(Errno::EINVAL));
    assert_eq!(Trigger::parse(b"many 1 1000000"), Err(Errno::EINVAL));
    assert_eq!(Trigger::parse(b"full 2000000 1000000"), Err(Errno::EINVAL));
    let mut s = TriggerState::new(t, psi::CPU, 0, 0);
    assert!(!s.check(SEC / 10, 100_000_000));
    assert!(s.check(SEC / 5, 160_000_000));
    assert!(!s.check(SEC / 2, 300_000_000));
    // A new window.
    assert!(!s.check(SEC + SEC / 2, 310_000_000));
    assert!(s.check(SEC + SEC / 2 + 1, 500_000_000));
}

#[test]
fn a_cgroup_is_frozen_when_each_thread_waits() {
    let mut h = Hierarchy::new(0, 1);
    let a = h.mkdir(ROOT, b"a", 0).unwrap();
    let b = h.mkdir(a, b"b", 0).unwrap();
    h.add_process(b);
    h.charge_pids(b, 2).unwrap();
    let seq = h.event_seq(a, "cgroup.events").unwrap();
    assert_eq!(h.read(a, "cgroup.events", 0).unwrap(), "populated 1\nfrozen 0\n");
    h.write(a, "cgroup.freeze", b"1", 0).unwrap();
    assert!(h.frozen(b));
    // The threads of `b` did not stop yet.
    assert_eq!(h.read(a, "cgroup.events", 0).unwrap(), "populated 1\nfrozen 0\n");
    h.thread_frozen(b, true);
    assert_eq!(h.read(b, "cgroup.events", 0).unwrap(), "populated 1\nfrozen 0\n");
    h.thread_frozen(b, true);
    assert_eq!(h.read(b, "cgroup.events", 0).unwrap(), "populated 1\nfrozen 1\n");
    assert_eq!(h.read(a, "cgroup.events", 0).unwrap(), "populated 1\nfrozen 1\n");
    assert!(h.event_seq(a, "cgroup.events").unwrap() > seq);
    assert!(h.take_notify());
    assert!(!h.take_notify());
    // A thaw makes the cgroups not frozen at once.
    h.write(a, "cgroup.freeze", b"0", 0).unwrap();
    assert!(!h.frozen(b));
    assert_eq!(h.read(a, "cgroup.events", 0).unwrap(), "populated 1\nfrozen 0\n");
    assert_eq!(h.event_seq(a, "cgroup.procs"), None);
}

#[test]
fn memory_high_makes_a_delay_that_grows_with_the_use() {
    let mut h = Hierarchy::new(0, 1);
    h.write(ROOT, "cgroup.subtree_control", b"+memory", 0).unwrap();
    let a = h.mkdir(ROOT, b"a", 0).unwrap();
    h.write(a, "memory.high", b"1M", 0).unwrap();
    h.charge_memory(a, 1 << 20).unwrap();
    assert_eq!(h.high_delay(a), 0);
    // A small part over the limit gives no wait.
    h.charge_memory(a, PAGE_SIZE).unwrap();
    assert_eq!(h.high_delay(a), 0);
    // Twice the limit gives the longest wait.
    h.charge_memory(a, (1 << 20) - PAGE_SIZE).unwrap();
    assert_eq!(h.high_delay(a), HIGH_DELAY_MAX);
    // The wait is for the pages that the cgroup charged since the last wait.
    assert_eq!(h.high_delay(a), 0);
    h.charge_memory(a, PAGE_SIZE).unwrap();
    assert_eq!(h.high_delay(a), HIGH_DELAY_MAX / HIGH_BATCH);
    let events = h.read(a, "memory.events", 0).unwrap();
    assert!(events.starts_with("low 0\nhigh "), "{events}");
}

#[test]
fn memory_oom_group_gives_the_highest_group() {
    let mut h = Hierarchy::new(0, 1);
    h.write(ROOT, "cgroup.subtree_control", b"+memory", 0).unwrap();
    let a = h.mkdir(ROOT, b"a", 0).unwrap();
    h.write(a, "cgroup.subtree_control", b"+memory", 0).unwrap();
    let b = h.mkdir(a, b"b", 0).unwrap();
    assert_eq!(h.oom_group(b, ROOT), None);
    h.write(b, "memory.oom.group", b"1", 0).unwrap();
    assert_eq!(h.oom_group(b, ROOT), Some(b));
    h.write(a, "memory.oom.group", b"1", 0).unwrap();
    assert_eq!(h.oom_group(b, ROOT), Some(a));
    // A group above the cgroup of the OOM does not count.
    assert_eq!(h.oom_group(b, b), Some(b));
    h.count_oom_group_kill(a);
    assert!(h.read(a, "memory.events", 0).unwrap().ends_with("oom_group_kill 1\n"));
}

#[test]
fn io_stat_counts_the_subtree_and_io_max_gives_a_delay() {
    let mut h = Hierarchy::new(0, 0b1);
    h.write(ROOT, "cgroup.subtree_control", b"+io", 0).unwrap();
    let a = h.mkdir(ROOT, b"a", 0).unwrap();
    let dev = io::makedev(253, 0);
    assert_eq!(io::parse_dev("253:0"), Ok(dev));
    assert_eq!(h.charge_io(a, dev, false, 4096, 1, 0), 0);
    assert_eq!(h.charge_io(a, dev, true, 8192, 2, 0), 0);
    let line = "253:0 rbytes=4096 wbytes=8192 rios=1 wios=2 dbytes=0 dios=0\n";
    assert_eq!(h.read(a, "io.stat", 0).unwrap(), line);
    assert_eq!(h.read(ROOT, "io.stat", 0).unwrap(), line);
    assert!(!names(&h, ROOT).contains(&"io.max"));

    h.write(a, "io.max", b"253:0 wbps=1048576 riops=10", 0).unwrap();
    assert_eq!(h.read(a, "io.max", 0).unwrap(), "253:0 rbps=max wbps=1048576 riops=10 wiops=max\n");
    // 1 MiB at 1 MiB/s takes a second, and the next MiB waits one more second.
    assert_eq!(h.charge_io(a, dev, true, 1 << 20, 1, SEC), SEC);
    assert_eq!(h.charge_io(a, dev, true, 1 << 20, 1, SEC), 2 * SEC);
    // A read of 1 bio at 10 IOPS takes 100 ms.
    assert_eq!(h.charge_io(a, dev, false, 512, 1, SEC), SEC / 10);
    assert_eq!(h.write(a, "io.max", b"253:0 wbps=0", 0), Err(Errno::ERANGE));
    assert_eq!(h.write(a, "io.max", b"253:0 xbps=1", 0), Err(Errno::EINVAL));
    h.write(a, "io.max", b"253:0 wbps=max riops=max", 0).unwrap();
    assert_eq!(h.read(a, "io.max", 0).unwrap(), "");
    assert_eq!(h.charge_io(a, dev, true, 1 << 20, 1, SEC), 0);

    assert_eq!(h.read(a, "io.weight", 0).unwrap(), "default 100\n");
    h.write(a, "io.weight", b"default 200", 0).unwrap();
    h.write(a, "io.weight", b"253:0 50", 0).unwrap();
    assert_eq!(h.read(a, "io.weight", 0).unwrap(), "default 200\n253:0 50\n");
    h.write(a, "io.weight", b"253:0 default", 0).unwrap();
    h.write(a, "io.weight", b"300", 0).unwrap();
    assert_eq!(h.read(a, "io.weight", 0).unwrap(), "default 300\n");
    assert_eq!(h.write(a, "io.weight", b"0", 0), Err(Errno::EINVAL));
}

//! The counts of the memory reclaim for `/proc/vmstat`, as the `PGSCAN_*` and `PGSTEAL_*` events
//! of mm/vmscan.c of Linux. The counts are in pages.

use core::sync::atomic::{AtomicU64, Ordering};

/// The task that takes pages back, as `reclaimer_offset` and `cgroup_reclaim` of mm/vmscan.c of
/// Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reclaimer {
    /// The reclaim in the background, when the free memory is low: `kswapd` of Linux.
    Kswapd,
    /// The reclaim of the task that needs memory when the memory of the system is short.
    Direct,
    /// The reclaim of the task that needs memory for a cgroup at its `memory.high` or its
    /// `memory.max`. Linux counts it in the cgroup as a direct reclaim, but not in the counts of
    /// the system for the reclaimer.
    Cgroup,
}

/// The counts of the reclaim since boot, in pages.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReclaimCounts {
    /// `pgscan_kswapd` and `pgscan_direct`: the pages that the reclaim of the system looked at.
    pub scan: [u64; 2],
    /// `pgsteal_kswapd` and `pgsteal_direct`: the pages that the reclaim of the system freed.
    pub steal: [u64; 2],
    /// `pgscan_anon` and `pgscan_file`: the pages that each reclaim looked at.
    pub scan_kind: [u64; 2],
    /// `pgsteal_anon` and `pgsteal_file`: the pages that each reclaim freed.
    pub steal_kind: [u64; 2],
}

static SCAN: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static STEAL: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static SCAN_KIND: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static STEAL_KIND: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// Counts a reclaim of `who` that looked at `scanned` pages and freed `stolen` of them, of
/// anonymous memory if `anon`, else of the page cache. As `shrink_inactive_list` of Linux, the
/// reclaim of a cgroup does not count in `pgscan_direct` and `pgsteal_direct`.
pub fn count_reclaim(who: Reclaimer, anon: bool, scanned: u64, stolen: u64) {
    let i = match who {
        Reclaimer::Kswapd => Some(0),
        Reclaimer::Direct => Some(1),
        Reclaimer::Cgroup => None,
    };
    if let Some(i) = i {
        SCAN[i].fetch_add(scanned, Ordering::Relaxed);
        STEAL[i].fetch_add(stolen, Ordering::Relaxed);
    }
    let k = usize::from(!anon);
    SCAN_KIND[k].fetch_add(scanned, Ordering::Relaxed);
    STEAL_KIND[k].fetch_add(stolen, Ordering::Relaxed);
}

/// The counts of the reclaim since boot.
pub fn reclaim_counts() -> ReclaimCounts {
    let ld = |a: &[AtomicU64; 2]| [a[0].load(Ordering::Relaxed), a[1].load(Ordering::Relaxed)];
    ReclaimCounts {
        scan: ld(&SCAN),
        steal: ld(&STEAL),
        scan_kind: ld(&SCAN_KIND),
        steal_kind: ld(&STEAL_KIND),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reclaim_of_a_cgroup_counts_only_by_kind() {
        let before = reclaim_counts();
        count_reclaim(Reclaimer::Cgroup, false, 8, 5);
        count_reclaim(Reclaimer::Kswapd, false, 4, 4);
        count_reclaim(Reclaimer::Direct, true, 2, 1);
        let after = reclaim_counts();
        let diff = |a: [u64; 2], b: [u64; 2]| [a[0] - b[0], a[1] - b[1]];
        assert_eq!(diff(after.scan, before.scan), [4, 2]);
        assert_eq!(diff(after.steal, before.steal), [4, 1]);
        assert_eq!(diff(after.scan_kind, before.scan_kind), [2, 12]);
        assert_eq!(diff(after.steal_kind, before.steal_kind), [1, 9]);
    }
}

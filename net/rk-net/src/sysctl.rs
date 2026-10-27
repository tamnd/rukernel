//! The network sysctl values that more than one crate uses. The proc file system shows them
//! under /proc/sys/net, and the protocols read them.

use core::sync::atomic::{AtomicU32, Ordering};

/// The lowest group of `net.ipv4.ping_group_range`.
static PING_GROUP_LOW: AtomicU32 = AtomicU32::new(1);
/// The highest group of `net.ipv4.ping_group_range`.
static PING_GROUP_HIGH: AtomicU32 = AtomicU32::new(0);

/// The range of the groups that can make an ICMP echo socket, `net.ipv4.ping_group_range`. The
/// default `1 0` is an empty range, as on Linux.
pub fn ping_group_range() -> (u32, u32) {
    (PING_GROUP_LOW.load(Ordering::Relaxed), PING_GROUP_HIGH.load(Ordering::Relaxed))
}

/// Sets `net.ipv4.ping_group_range`. A range with `high` below `low` becomes the empty range
/// `1 0`, as `ipv4_ping_group_range` of Linux. The values are the group IDs of the kernel, and
/// a value larger than `i32::MAX` gives `None`.
pub fn set_ping_group_range(low: u32, high: u32) -> Option<()> {
    if low > i32::MAX as u32 || high > i32::MAX as u32 {
        return None;
    }
    let (low, high) = if high < low { (1, 0) } else { (low, high) };
    PING_GROUP_LOW.store(low, Ordering::Relaxed);
    PING_GROUP_HIGH.store(high, Ordering::Relaxed);
    Some(())
}

/// Tells if a process with one of the groups `groups` can make an ICMP echo socket.
pub fn ping_group_allowed(groups: impl IntoIterator<Item = u32>) -> bool {
    let (low, high) = ping_group_range();
    groups.into_iter().any(|g| (low..=high).contains(&g))
}

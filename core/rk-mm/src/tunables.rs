//! The tunables of the memory manager: the policy for transparent huge pages, the overcommit
//! policy and the limits in /proc/sys/vm. procfs and sysfs read and write them, and the address
//! spaces use them.
//!
//! The commit count is the number of pages that the address spaces can write without a new
//! mapping. Linux names it `vm_committed_as`, and /proc/meminfo shows it as `Committed_AS`. A
//! private writable mapping, a shared anonymous mapping, the heap and the stack add their pages to
//! it, as the areas with `VM_ACCOUNT` of Linux. `vm.overcommit_memory` tells if a new mapping can
//! make it larger than the memory.

use crate::vma::PAGE_SIZE;
use alloc::string::String;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

/// The size of a page in KiB.
const PAGE_KB: usize = PAGE_SIZE / 1024;

/// The names of the values of `/sys/kernel/mm/transparent_hugepage/enabled`, in the order of
/// [`ThpMode`].
pub const THP_ENABLED_NAMES: &[&str] = &["always", "madvise", "never"];

/// The names of the values of `/sys/kernel/mm/transparent_hugepage/defrag`. The kernel does not
/// move pages to make huge pages, so the value only changes what the file shows.
pub const THP_DEFRAG_NAMES: &[&str] = &["always", "defer", "defer+madvise", "madvise", "never"];

/// When an anonymous area gets huge pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThpMode {
    /// Each area, but not an area with `MADV_NOHUGEPAGE`. This is the default of Linux.
    Always,
    /// Only an area with `MADV_HUGEPAGE`.
    Madvise,
    /// No area.
    Never,
}

static THP_ENABLED: AtomicU8 = AtomicU8::new(0);
static THP_DEFRAG: AtomicU8 = AtomicU8::new(3);

/// `vm.overcommit_memory` 0: a mapping fails only if it is larger than the memory and the swap.
pub const OVERCOMMIT_GUESS: usize = 0;
/// `vm.overcommit_memory` 1: a mapping never fails because of its size.
pub const OVERCOMMIT_ALWAYS: usize = 1;
/// `vm.overcommit_memory` 2: the commit count stays at or below the commit limit.
pub const OVERCOMMIT_NEVER: usize = 2;

/// The default of `vm.max_map_count`, as in Linux.
pub const DEFAULT_MAX_MAP_COUNT: usize = 65530;

static OVERCOMMIT_MEMORY: AtomicUsize = AtomicUsize::new(OVERCOMMIT_GUESS);
static OVERCOMMIT_RATIO: AtomicUsize = AtomicUsize::new(50);
static OVERCOMMIT_KBYTES: AtomicUsize = AtomicUsize::new(0);
static MAX_MAP_COUNT: AtomicUsize = AtomicUsize::new(DEFAULT_MAX_MAP_COUNT);
/// The value of `vm.min_free_kbytes`, or 0 before a write, for the default of the memory size.
static MIN_FREE_KBYTES: AtomicUsize = AtomicUsize::new(0);
static COMMITTED: AtomicUsize = AtomicUsize::new(0);
static SWAP_PAGES: AtomicUsize = AtomicUsize::new(0);

/// The policy for huge pages, `/sys/kernel/mm/transparent_hugepage/enabled`.
pub fn thp_enabled() -> ThpMode {
    match THP_ENABLED.load(Ordering::Relaxed) {
        0 => ThpMode::Always,
        1 => ThpMode::Madvise,
        _ => ThpMode::Never,
    }
}

/// Gives a sysfs file of a choice, such as `always [madvise] never`, with the current value in
/// brackets.
fn show_choice(names: &[&str], current: usize) -> String {
    let mut out = String::new();
    for (i, name) in names.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        if i == current {
            out.push('[');
            out.push_str(name);
            out.push(']');
        } else {
            out.push_str(name);
        }
    }
    out.push('\n');
    out
}

/// Finds the index of a value that a write to a sysfs file of a choice gives. A new line or
/// spaces at the ends are allowed.
fn parse_choice(names: &[&str], text: &[u8]) -> Option<usize> {
    let text = core::str::from_utf8(text).ok()?.trim();
    names.iter().position(|&n| n == text)
}

/// The text of `/sys/kernel/mm/transparent_hugepage/enabled`.
pub fn show_thp_enabled() -> String {
    show_choice(THP_ENABLED_NAMES, THP_ENABLED.load(Ordering::Relaxed).into())
}

/// The text of `/sys/kernel/mm/transparent_hugepage/defrag`.
pub fn show_thp_defrag() -> String {
    show_choice(THP_DEFRAG_NAMES, THP_DEFRAG.load(Ordering::Relaxed).into())
}

/// Writes `/sys/kernel/mm/transparent_hugepage/enabled`. Gives `None` for an unknown value.
pub fn set_thp_enabled(text: &[u8]) -> Option<()> {
    let i = parse_choice(THP_ENABLED_NAMES, text)?;
    THP_ENABLED.store(i as u8, Ordering::Relaxed);
    Some(())
}

/// Writes `/sys/kernel/mm/transparent_hugepage/defrag`. Gives `None` for an unknown value.
pub fn set_thp_defrag(text: &[u8]) -> Option<()> {
    let i = parse_choice(THP_DEFRAG_NAMES, text)?;
    THP_DEFRAG.store(i as u8, Ordering::Relaxed);
    Some(())
}

/// `vm.overcommit_memory`.
pub fn overcommit_memory() -> usize {
    OVERCOMMIT_MEMORY.load(Ordering::Relaxed)
}

/// Sets `vm.overcommit_memory`. Gives `None` for a value that is not 0, 1 or 2.
pub fn set_overcommit_memory(value: usize) -> Option<()> {
    (value <= OVERCOMMIT_NEVER).then(|| OVERCOMMIT_MEMORY.store(value, Ordering::Relaxed))
}

/// `vm.overcommit_ratio`, the percent of the memory in the commit limit.
pub fn overcommit_ratio() -> usize {
    OVERCOMMIT_RATIO.load(Ordering::Relaxed)
}

/// Sets `vm.overcommit_ratio`. As in Linux, `vm.overcommit_kbytes` becomes 0.
pub fn set_overcommit_ratio(value: usize) {
    OVERCOMMIT_RATIO.store(value, Ordering::Relaxed);
    OVERCOMMIT_KBYTES.store(0, Ordering::Relaxed);
}

/// `vm.overcommit_kbytes`, the commit limit without the swap, or 0 to use the ratio.
pub fn overcommit_kbytes() -> usize {
    OVERCOMMIT_KBYTES.load(Ordering::Relaxed)
}

/// Sets `vm.overcommit_kbytes`. As in Linux, `vm.overcommit_ratio` becomes 0.
pub fn set_overcommit_kbytes(value: usize) {
    OVERCOMMIT_KBYTES.store(value, Ordering::Relaxed);
    OVERCOMMIT_RATIO.store(0, Ordering::Relaxed);
}

/// `vm.max_map_count`, the most areas of an address space. As in Linux, a new area fails when the
/// count is above the limit, so an address space can get one area more than the limit.
pub fn max_map_count() -> usize {
    MAX_MAP_COUNT.load(Ordering::Relaxed)
}

/// Sets `vm.max_map_count`.
pub fn set_max_map_count(value: usize) {
    MAX_MAP_COUNT.store(value, Ordering::Relaxed);
}

/// The default of `vm.min_free_kbytes` for `total` pages of memory: the square root of 16 times
/// the memory in KiB, from 128 KiB to 256 MiB, as `calculate_min_free_kbytes` of Linux.
pub fn default_min_free_kbytes(total: usize) -> usize {
    (total.saturating_mul(PAGE_KB * 16)).isqrt().clamp(128, 262_144)
}

/// `vm.min_free_kbytes` for `total` pages of memory. An allocation for user memory fails when it
/// would make the free memory less than this.
pub fn min_free_kbytes(total: usize) -> usize {
    match MIN_FREE_KBYTES.load(Ordering::Relaxed) {
        0 => default_min_free_kbytes(total),
        v => v,
    }
}

/// The pages of `vm.min_free_kbytes` for `total` pages of memory. User memory does not take a
/// page when the free pages are at or below this count.
pub fn reserve_pages(total: usize) -> usize {
    min_free_kbytes(total) / PAGE_KB
}

/// Sets `vm.min_free_kbytes`.
pub fn set_min_free_kbytes(value: usize) {
    MIN_FREE_KBYTES.store(value.max(1), Ordering::Relaxed);
}

/// Sets the number of swap pages, after `swapon` or `swapoff`.
pub fn set_swap_pages(pages: usize) {
    SWAP_PAGES.store(pages, Ordering::Relaxed);
}

/// The commit count in pages, `Committed_AS`.
pub fn committed_pages() -> usize {
    COMMITTED.load(Ordering::Relaxed)
}

/// The commit limit in pages for `total` pages of memory, `CommitLimit`: the memory times the
/// ratio, or `vm.overcommit_kbytes`, and the swap.
pub fn commit_limit(total: usize) -> usize {
    let swap = SWAP_PAGES.load(Ordering::Relaxed);
    match overcommit_kbytes() {
        0 => total / 100 * overcommit_ratio() + total % 100 * overcommit_ratio() / 100 + swap,
        kb => kb / PAGE_KB + swap,
    }
}

/// Tells if a mapping of `pages` pages is allowed, as `__vm_enough_memory` of Linux. `committed`
/// is the commit count with the new pages, `total` and `swap` are the pages of memory and swap,
/// and `limit` is the commit limit.
pub fn enough_memory(
    mode: usize,
    pages: usize,
    committed: usize,
    total: usize,
    swap: usize,
    limit: usize,
) -> bool {
    match mode {
        OVERCOMMIT_ALWAYS => true,
        OVERCOMMIT_GUESS => pages <= total.saturating_add(swap),
        _ => committed <= limit,
    }
}

/// Adds `pages` to the commit count if the overcommit policy allows it. `total` is the pages of
/// memory. Gives `false` and changes nothing if the policy does not allow it.
pub fn charge(pages: usize, total: usize) -> bool {
    let committed = COMMITTED.fetch_add(pages, Ordering::Relaxed).saturating_add(pages);
    let swap = SWAP_PAGES.load(Ordering::Relaxed);
    let ok = enough_memory(overcommit_memory(), pages, committed, total, swap, commit_limit(total));
    if !ok {
        uncharge(pages);
    }
    ok
}

/// Removes `pages` from the commit count.
pub fn uncharge(pages: usize) {
    let _ = COMMITTED
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| Some(c.saturating_sub(pages)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_choice_shows_the_current_value_in_brackets() {
        assert_eq!(show_choice(THP_ENABLED_NAMES, 1), "always [madvise] never\n");
        assert_eq!(parse_choice(THP_ENABLED_NAMES, b"never\n"), Some(2));
        assert_eq!(parse_choice(THP_ENABLED_NAMES, b"sometimes"), None);
    }

    #[test]
    fn the_overcommit_modes() {
        // Guess: only a mapping larger than the memory and the swap fails.
        assert!(enough_memory(0, 100, 10_000, 100, 0, 50));
        assert!(!enough_memory(0, 101, 0, 100, 0, 50));
        // Always: each mapping is allowed.
        assert!(enough_memory(1, 1000, 10_000, 100, 0, 50));
        // Never: the commit count stays at or below the limit.
        assert!(enough_memory(2, 10, 50, 100, 0, 50));
        assert!(!enough_memory(2, 10, 51, 100, 0, 50));
    }

    #[test]
    fn the_default_min_free_kbytes_follows_linux() {
        // 1 GiB of memory gives 4096 KiB, and the value has limits at both ends.
        assert_eq!(default_min_free_kbytes(262_144), 4096);
        assert_eq!(default_min_free_kbytes(16), 128);
        assert_eq!(default_min_free_kbytes(usize::MAX / 2), 262_144);
    }
}

//! The pool of huge pages of hugetlbfs, as mm/hugetlb.c of Linux.
//!
//! The pool has huge pages of 2 MiB that only hugetlbfs, `MAP_HUGETLB`, `SHM_HUGETLB` and
//! `memfd_create(MFD_HUGETLB)` use. `vm.nr_hugepages` sets the number of persistent pages. With
//! `vm.nr_overcommit_hugepages`, the pool can take surplus pages from the allocator when it has no
//! free page, and gives them back when they are free again.
//!
//! A mapping reserves its pages when it is made, so a later page fault does not fail. A
//! reservation is a free page that only the mapping can take. The counters are the lines
//! `HugePages_Total`, `HugePages_Free`, `HugePages_Rsvd` and `HugePages_Surp` of /proc/meminfo,
//! and the files of /sys/kernel/mm/hugepages/hugepages-2048kB.
//!
//! [`Pool`] is a pure type, so the tests on the host examine the counters. The kernel keeps one
//! pool of `rk_frame::mm::HugeRun` values.

use alloc::vec::Vec;

#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub use crate::space::hugetlb::{
    HugeFile, HugePage, alloc_page, copy_page, counts, reserve, set_nr_hugepages,
    set_nr_overcommit_hugepages, track, unreserve,
};

/// The size of a huge page of hugetlbfs.
pub const HPAGE_SIZE: usize = 2 << 20;

/// The size of a huge page in KiB, as the `Hugepagesize` line of /proc/meminfo shows it.
pub const HPAGE_KB: usize = HPAGE_SIZE / 1024;

/// The name of the directory of the huge page size in /sys/kernel/mm/hugepages.
pub const HPAGE_DIR: &str = "hugepages-2048kB";

/// The counters of the pool, as `struct hstate` of Linux has them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// All the pages of the pool, persistent and surplus. `nr_huge_pages`.
    pub total: usize,
    /// The pages that no mapping uses. `free_huge_pages`.
    pub free: usize,
    /// The free pages that mappings reserved. `resv_huge_pages`.
    pub resv: usize,
    /// The pages above the persistent count. `surplus_huge_pages`.
    pub surplus: usize,
    /// The most surplus pages. `nr_overcommit_huge_pages`.
    pub overcommit: usize,
}

/// The pool of huge pages. `P` is one huge page. The functions that remove pages from the pool
/// give them to the caller, which drops them after it releases the lock of the pool.
#[derive(Debug)]
pub struct Pool<P> {
    free: Vec<P>,
    total: usize,
    resv: usize,
    surplus: usize,
    overcommit: usize,
}

impl<P> Default for Pool<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P> Pool<P> {
    /// Makes an empty pool.
    pub const fn new() -> Self {
        Self { free: Vec::new(), total: 0, resv: 0, surplus: 0, overcommit: 0 }
    }

    /// The counters.
    pub fn counts(&self) -> Counts {
        Counts {
            total: self.total,
            free: self.free.len(),
            resv: self.resv,
            surplus: self.surplus,
            overcommit: self.overcommit,
        }
    }

    /// The pages that are not surplus pages.
    fn persistent(&self) -> usize {
        self.total - self.surplus
    }

    /// Sets the persistent pages to `count`, as `set_max_huge_pages` of Linux. `alloc` gives a
    /// new page, or `None` when no memory is free. The pool cannot free a page in use or a
    /// reserved page, so such pages become surplus pages. Gives the pages to free.
    pub fn set_persistent(&mut self, count: usize, mut alloc: impl FnMut() -> Option<P>) -> Vec<P> {
        // A surplus page becomes a persistent page first.
        while self.surplus > 0 && count > self.persistent() {
            self.surplus -= 1;
        }
        while count > self.persistent() {
            let Some(page) = alloc() else { break };
            self.free.push(page);
            self.total += 1;
        }
        // The pages in use and the reserved pages stay.
        let min = count.max(self.resv + self.total - self.free.len());
        let mut gone = Vec::new();
        while min < self.persistent() {
            let Some(page) = self.free.pop() else { break };
            gone.push(page);
            self.total -= 1;
        }
        while count < self.persistent() {
            self.surplus += 1;
        }
        gone
    }

    /// Sets the most surplus pages, `vm.nr_overcommit_hugepages`.
    pub fn set_overcommit(&mut self, count: usize) {
        self.overcommit = count;
    }

    /// Takes a surplus page from `alloc`, if the overcommit allows one more.
    fn surplus_page(&mut self, alloc: &mut impl FnMut() -> Option<P>) -> Option<P> {
        if self.surplus >= self.overcommit {
            return None;
        }
        let page = alloc()?;
        self.total += 1;
        self.surplus += 1;
        Some(page)
    }

    /// Reserves `n` pages, as `hugetlb_acct_memory` of Linux. If the free pages that are not
    /// reserved are not enough, the pool takes surplus pages. Gives `false` and changes nothing if
    /// the pages are not there, with the surplus pages that it took to free. Else gives `true` and
    /// an empty list.
    pub fn reserve(&mut self, n: usize, mut alloc: impl FnMut() -> Option<P>) -> (bool, Vec<P>) {
        let need = (self.resv + n).saturating_sub(self.free.len());
        let mut more = Vec::new();
        while more.len() < need {
            match self.surplus_page(&mut alloc) {
                Some(page) => more.push(page),
                None => {
                    self.total -= more.len();
                    self.surplus -= more.len();
                    return (false, more);
                }
            }
        }
        self.free.append(&mut more);
        self.resv += n;
        (true, more)
    }

    /// Removes `n` reservations that no page used, as `return_unused_surplus_pages` of Linux.
    /// Free surplus pages leave the pool. Gives the pages to free.
    pub fn unreserve(&mut self, n: usize) -> Vec<P> {
        let n = n.min(self.resv);
        self.resv -= n;
        let mut gone = Vec::new();
        while gone.len() < n && self.surplus > 0 && self.free.len() > self.resv {
            let Some(page) = self.free.pop() else { break };
            gone.push(page);
            self.total -= 1;
            self.surplus -= 1;
        }
        gone
    }

    /// Takes a page for a page fault, as `alloc_hugetlb_folio` of Linux. `reserved` tells that the
    /// caller has a reservation, which the page uses. A caller without one can only take a free
    /// page that is not reserved, or a surplus page.
    pub fn take(&mut self, reserved: bool, mut alloc: impl FnMut() -> Option<P>) -> Option<P> {
        let reserved = reserved && self.resv > 0;
        if reserved || self.free.len() > self.resv {
            let page = self.free.pop()?;
            if reserved {
                self.resv -= 1;
            }
            return Some(page);
        }
        self.surplus_page(&mut alloc)
    }

    /// Takes back a page that is free again, as `free_huge_folio` of Linux. A surplus page leaves
    /// the pool, and the function gives it to free.
    pub fn give_back(&mut self, page: P) -> Option<P> {
        if self.surplus > 0 {
            self.total -= 1;
            self.surplus -= 1;
            return Some(page);
        }
        self.free.push(page);
        None
    }
}

/// The counters of the pool. The host has no pool, so they are all 0 there.
#[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
pub fn counts() -> Counts {
    Counts::default()
}

/// Sets `vm.nr_hugepages`. The host has no pool, so this has no effect there.
#[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
pub fn set_nr_hugepages(_count: usize) {}

/// Sets `vm.nr_overcommit_hugepages`. The host has no pool, so this has no effect there.
#[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
pub fn set_nr_overcommit_hugepages(_count: usize) {}

/// Reserves huge pages. The host has no pool, so each reservation works there.
///
/// # Errors
///
/// None on the host.
#[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
pub fn reserve(_n: usize) -> Result<(), rk_abi::Errno> {
    Ok(())
}

/// Removes reservations. The host has no pool, so this has no effect there.
#[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
pub fn unreserve(_n: usize) {}

static SHM_GROUP: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// `vm.hugetlb_shm_group`: the group whose members can make a `SHM_HUGETLB` segment without
/// `CAP_IPC_LOCK`.
pub fn shm_group() -> usize {
    SHM_GROUP.load(core::sync::atomic::Ordering::Relaxed) as usize
}

/// Sets `vm.hugetlb_shm_group`. Gives `None` for a value that is not a group ID.
pub fn set_shm_group(gid: usize) -> Option<()> {
    let gid = u32::try_from(gid).ok()?;
    SHM_GROUP.store(gid, core::sync::atomic::Ordering::Relaxed);
    Some(())
}

/// The names of the files of /sys/kernel/mm/hugepages/hugepages-2048kB, and if a write can
/// change them.
pub const SYSFS_FILES: [(&str, bool); 6] = [
    ("free_hugepages", false),
    ("nr_hugepages", true),
    ("nr_hugepages_mempolicy", true),
    ("nr_overcommit_hugepages", true),
    ("resv_hugepages", false),
    ("surplus_hugepages", false),
];

/// The text of the file `name` of /sys/kernel/mm/hugepages/hugepages-2048kB for the counters
/// `c`, or `None` for a file that is not there.
pub fn show(c: &Counts, name: &str) -> Option<alloc::string::String> {
    let value = match name {
        "free_hugepages" => c.free,
        // As `nr_hugepages_show` of Linux, the file has all the pages with the surplus pages. The
        // sysctl `vm.nr_hugepages` has only the persistent pages.
        "nr_hugepages" | "nr_hugepages_mempolicy" => c.total,
        "nr_overcommit_hugepages" => c.overcommit,
        "resv_hugepages" => c.resv,
        "surplus_hugepages" => c.surplus,
        _ => return None,
    };
    Some(alloc::format!("{value}\n"))
}

/// Writes the file `name` of /sys/kernel/mm/hugepages/hugepages-2048kB, or the sysctl of the
/// same name.
///
/// # Errors
///
/// `EINVAL` for a text that is not a count, and `EACCES` for a file that a write cannot change.
pub fn store(name: &str, text: &[u8]) -> Result<(), rk_abi::Errno> {
    let count = parse_count(text).ok_or(rk_abi::Errno::EINVAL)?;
    match name {
        "nr_hugepages" | "nr_hugepages_mempolicy" => set_nr_hugepages(count),
        "nr_overcommit_hugepages" => set_nr_overcommit_hugepages(count),
        _ => return Err(rk_abi::Errno::EACCES),
    }
    Ok(())
}

/// Reads a count that a write to a file of the pool gives, such as `vm.nr_hugepages`. A new line
/// or spaces at the ends are allowed.
pub fn parse_count(text: &[u8]) -> Option<usize> {
    core::str::from_utf8(text).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An allocator with `n` pages.
    fn memory(n: &mut usize) -> impl FnMut() -> Option<()> + '_ {
        move || {
            if *n == 0 {
                return None;
            }
            *n -= 1;
            Some(())
        }
    }

    #[test]
    fn nr_hugepages_grows_and_shrinks_the_pool() {
        let mut pool = Pool::new();
        let mut mem = 10;
        assert!(pool.set_persistent(4, memory(&mut mem)).is_empty());
        assert_eq!(pool.counts(), Counts { total: 4, free: 4, ..Counts::default() });
        assert_eq!(pool.set_persistent(1, memory(&mut mem)).len(), 3);
        assert_eq!(pool.counts().total, 1);
        // The memory has 6 pages more, so the pool gets only 7 pages.
        pool.set_persistent(20, memory(&mut mem));
        assert_eq!(pool.counts().total, 7);
    }

    #[test]
    fn a_page_in_use_becomes_a_surplus_page() {
        let mut pool = Pool::new();
        let mut mem = 10;
        pool.set_persistent(2, memory(&mut mem));
        let page = pool.take(false, memory(&mut mem));
        assert!(page.is_some());
        assert_eq!(pool.set_persistent(0, memory(&mut mem)).len(), 1);
        assert_eq!(pool.counts(), Counts { total: 1, free: 0, surplus: 1, ..Counts::default() });
        // The surplus page leaves the pool when it is free.
        assert!(pool.give_back(()).is_some());
        assert_eq!(pool.counts(), Counts::default());
    }

    #[test]
    fn a_reservation_keeps_a_page_for_its_mapping() {
        let mut pool = Pool::new();
        let mut mem = 10;
        pool.set_persistent(2, memory(&mut mem));
        assert!(pool.reserve(2, memory(&mut mem)).0);
        assert!(!pool.reserve(1, memory(&mut mem)).0);
        assert_eq!(pool.counts().resv, 2);
        // A fault without a reservation finds no page.
        assert!(pool.take(false, memory(&mut mem)).is_none());
        assert!(pool.take(true, memory(&mut mem)).is_some());
        assert_eq!(pool.counts(), Counts { total: 2, free: 1, resv: 1, ..Counts::default() });
        assert!(pool.unreserve(1).is_empty());
        assert_eq!(pool.counts().resv, 0);
        // The persistent pages cannot go below the pages in use.
        pool.set_persistent(0, memory(&mut mem));
        assert_eq!(pool.counts(), Counts { total: 1, free: 0, surplus: 1, ..Counts::default() });
    }

    #[test]
    fn the_overcommit_gives_surplus_pages() {
        let mut pool = Pool::new();
        let mut mem = 10;
        pool.set_overcommit(2);
        assert!(pool.reserve(2, memory(&mut mem)).0);
        assert_eq!(pool.counts(), Counts { total: 2, free: 2, resv: 2, surplus: 2, overcommit: 2 });
        assert!(!pool.reserve(1, memory(&mut mem)).0);
        assert_eq!(pool.unreserve(2).len(), 2);
        assert_eq!(pool.counts(), Counts { overcommit: 2, ..Counts::default() });
        // A fault takes a surplus page too.
        assert!(pool.take(false, memory(&mut mem)).is_some());
        assert_eq!(pool.counts().surplus, 1);
        // A larger persistent count makes the surplus page persistent.
        pool.set_persistent(1, memory(&mut mem));
        let want = Counts { total: 1, surplus: 0, overcommit: 2, ..Counts::default() };
        assert_eq!(pool.counts(), want);
    }

    #[test]
    fn counts_parse_as_the_files_of_linux() {
        assert_eq!(parse_count(b"128\n"), Some(128));
        assert_eq!(parse_count(b"-1"), None);
        let c = Counts { total: 3, free: 2, resv: 1, surplus: 1, overcommit: 4 };
        assert_eq!(show(&c, "nr_hugepages").as_deref(), Some("3\n"));
        assert_eq!(show(&c, "surplus_hugepages").as_deref(), Some("1\n"));
        assert_eq!(store("free_hugepages", b"1"), Err(rk_abi::Errno::EACCES));
        assert_eq!(store("nr_hugepages", b"x"), Err(rk_abi::Errno::EINVAL));
    }
}
